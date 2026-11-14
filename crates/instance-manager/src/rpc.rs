//! Manager side of the controller protocol (`manager.sock`). Only same-UID peers that speak the
//! same protocol and build are served.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use vpn_domain::{
    ApiError, AppId, AssignmentSource, Blocklist, BlocklistId, BlocklistRefreshState,
    BlocklistSource, BlocklistView, Capability, DnsProfile, EgressMode, ErrorCode, ForwardBinding,
    ForwardBindingId, GatewaySpec, InstanceId, NamedRef, OP_INSTANCE_EMERGENCY_STOP, Phase,
    ProviderAccount, RuntimeProfile, SecurityProfile, SshHost, Text, TransportProfile,
    TransportProfileId, TransportRef, TransportSettings, UnbanResult, WgKey, tr,
};
use vpn_ipc::control::{
    BootstrapGrantWire, CONTROL_MAX_FRAME, CONTROL_PROTOCOL, Call, ClientMsg, EgressWire, Entity,
    EntityKind, Event, Lifecycle, Reply, SecretMetaWire, ServerMsg, SystemInfo,
};
use vpn_ipc::frame::{FrameWriter, split};
use vpn_ipc::{SecretBytes, identity};
use vpn_store::{Begin, Store, StoreError};
use zeroize::Zeroizing;

use crate::performance::Performance;
use crate::policy::Proposal;
use crate::ssh::SshProjector;
use crate::{Manager, ManagerEvent};

/// Most operations one listing returns.
const MAX_OPERATIONS_LISTED: u32 = 200;
/// After a client stops sending, how long replies already on their way may still go out.
const REPLY_FLUSH: Duration = Duration::from_secs(1);

/// Test-only faults of this module's connections, per thread (a current-thread runtime runs the
/// server and the test on one thread; tests on other threads are not affected).
#[cfg(test)]
pub(crate) mod hooks {
    use std::cell::Cell;
    use std::time::Duration;

    thread_local! {
        /// The next reply write fails, as a host out of buffer space (`ENOBUFS`) makes it.
        pub(crate) static FAIL_NEXT_WRITE: Cell<bool> = const { Cell::new(false) };
        /// New connections are not served while set (a wedged server).
        pub(crate) static STALL: Cell<bool> = const { Cell::new(false) };
        /// Every reply waits this long first (a slow manager).
        pub(crate) static DELAY: Cell<Duration> = const { Cell::new(Duration::ZERO) };
    }
}

/// Static facts the manager reports in `System`, and the optional SSH Manager and Performance
/// Manager.
#[derive(Clone)]
pub struct SystemFacts {
    pub capabilities: Vec<Capability>,
    pub ssh: Option<Arc<SshProjector>>,
    pub performance: Option<Arc<Performance>>,
}

fn performance_of(facts: &SystemFacts) -> Result<&Arc<Performance>, ApiError> {
    facts.performance.as_ref().ok_or_else(|| {
        ApiError::new(
            ErrorCode::UnsupportedCapability,
            tr!(
                "This manager does not have Performance Manager enabled",
                "這個 manager 沒有啟用 Performance Manager",
                "この manager では Performance Manager が有効になっていません"
            ),
        )
    })
}

/// Re-render the SSH projection after a change it depends on (best effort: a failure is kept
/// and reported by `SshStatus`).
async fn ssh_changed(facts: &SystemFacts, store: &Store) {
    if let Some(ssh) = &facts.ssh
        && let Err(e) = ssh.apply(store).await
    {
        tracing::warn!(error = %e.en, "SSH projection not written");
    }
}

fn ssh_of(facts: &SystemFacts) -> Result<&SshProjector, ApiError> {
    facts.ssh.as_deref().ok_or_else(|| {
        ApiError::new(
            ErrorCode::UnsupportedCapability,
            tr!(
                "This manager does not have SSH Manager enabled",
                "這個 manager 沒有啟用 SSH Manager",
                "この manager では SSH Manager が有効になっていません"
            ),
        )
    })
}

pub async fn serve(
    listener: UnixListener,
    manager: Arc<Manager>,
    store: Arc<Store>,
    facts: SystemFacts,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let me = vpn_platform::process::current_uid();
        // The kernel's word on who connected: the Performance Manager samples that process
        // (pid + start time) while the connection lives.
        let pid = match stream.peer_cred() {
            Ok(c) if c.uid() == me => c.pid().and_then(|p| u32::try_from(p).ok()),
            _ => {
                tracing::warn!("refused manager connection from another user");
                continue;
            }
        };
        let (m, s, f) = (manager.clone(), store.clone(), facts.clone());
        tokio::spawn(async move {
            if let Err(e) = connection(stream, pid, m, s, f).await {
                tracing::debug!(error = %e, "control connection ended");
            }
        });
    }
}

async fn connection(
    stream: UnixStream,
    peer_pid: Option<u32>,
    manager: Arc<Manager>,
    store: Arc<Store>,
    facts: SystemFacts,
) -> std::io::Result<()> {
    #[cfg(test)]
    while hooks::STALL.with(std::cell::Cell::get) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (mut rx, mut tx) = split(stream, CONTROL_MAX_FRAME);
    match rx.recv::<ClientMsg>().await? {
        Some((ClientMsg::Hello { protocol, build_id }, _))
            if protocol == CONTROL_PROTOCOL && build_id == identity::build_id() => {}
        Some((ClientMsg::Hello { build_id, .. }, _)) => {
            tracing::warn!(%build_id, manager = identity::build_id(), "refused controller of a different build");
            return Ok(());
        }
        _ => return Ok(()),
    }
    // Held until the connection ends.
    let _sampled = match (&facts.performance, peer_pid) {
        (Some(p), Some(pid)) => p.controller_connected(pid),
        _ => None,
    };
    tx.send(
        &ServerMsg::Hello {
            protocol: CONTROL_PROTOCOL,
            build_id: identity::build_id().to_string(),
            installation_id: store.installation_id(),
        },
        &[],
    )
    .await?;

    let (out_tx, mut out_rx) = mpsc::channel::<ServerMsg>(256);
    let writing = async move {
        while let Some(msg) = out_rx.recv().await {
            write(&mut tx, &msg).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::pin!(writing);
    // One connection, both directions. A reply that cannot be written (the host out of
    // buffers, the client gone) ends the reading too: a connection that keeps taking calls it
    // can no longer answer is one the controller cannot tell is dead.
    let read = tokio::select! {
        read = read_calls(&mut rx, &out_tx, &manager, &store, &facts) => read,
        written = &mut writing => {
            tracing::warn!(error = ?written.err(), "a reply could not be written: closing the control connection");
            return Ok(());
        }
    };
    // The client stopped sending (or broke the protocol): replies already on their way get a
    // moment, then the connection closes as a whole.
    drop(out_tx);
    let _ = tokio::time::timeout(REPLY_FLUSH, &mut writing).await;
    read
}

/// One reply out, through the test-only faults in tests.
async fn write(tx: &mut FrameWriter, msg: &ServerMsg) -> std::io::Result<()> {
    #[cfg(test)]
    {
        if hooks::FAIL_NEXT_WRITE.with(|f| f.replace(false)) {
            return Err(std::io::Error::from_raw_os_error(libc::ENOBUFS));
        }
        let delay = hooks::DELAY.with(std::cell::Cell::get);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
    tx.send(msg, &[]).await
}

/// Read and dispatch the client's calls and subscriptions until it stops sending.
async fn read_calls(
    rx: &mut vpn_ipc::frame::FrameReader,
    out_tx: &mpsc::Sender<ServerMsg>,
    manager: &Arc<Manager>,
    store: &Arc<Store>,
    facts: &SystemFacts,
) -> std::io::Result<()> {
    while let Some((msg, _)) = rx.recv::<ClientMsg>().await? {
        match msg {
            ClientMsg::Call { id, call } => {
                let (m, s, f, out) = (
                    manager.clone(),
                    store.clone(),
                    facts.clone(),
                    out_tx.clone(),
                );
                tokio::spawn(async move {
                    let result = dispatch(call, &m, &s, &f).await;
                    let _ = out.send(ServerMsg::Reply { id, result }).await;
                });
            }
            ClientMsg::Subscribe => {
                let mut events = manager.subscribe();
                let out = out_tx.clone();
                tokio::spawn(async move {
                    loop {
                        let ev = match events.recv().await {
                            Ok(ManagerEvent::Status(s)) => Event::Status(s),
                            Ok(ManagerEvent::Sample {
                                instance_id,
                                generation,
                                sample,
                            }) => Event::Sample {
                                instance_id,
                                generation,
                                sample,
                            },
                            Ok(ManagerEvent::AppStatus(s)) => Event::AppStatus(s),
                            Ok(ManagerEvent::ForwardStatus(s)) => Event::ForwardStatus(s),
                            Ok(ManagerEvent::SshDownloadStatus(s)) => Event::SshDownloadStatus(s),
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(_) => break,
                        };
                        if out.try_send(ServerMsg::Event(ev)).is_err() && out.is_closed() {
                            break;
                        }
                    }
                });
            }
            ClientMsg::Hello { .. } => break,
        }
    }
    Ok(())
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "a `Result::map_err` adapter: it takes the error by value"
)]
fn api(e: StoreError) -> ApiError {
    e.to_api()
}

fn secret_wire(m: vpn_store::SecretMeta) -> SecretMetaWire {
    SecretMetaWire {
        secret_ref: m.secret_ref,
        kind: m.kind,
        label: m.label,
        public_fingerprint: m.public_fingerprint,
        created_at: m.created_at,
    }
}

async fn list(store: &Store, kind: EntityKind) -> Result<Vec<Entity>, StoreError> {
    Ok(match kind {
        EntityKind::Profile => store
            .list()
            .await?
            .into_iter()
            .map(Entity::Profile)
            .collect(),
        EntityKind::Dns => store.list().await?.into_iter().map(Entity::Dns).collect(),
        EntityKind::Security => store
            .list()
            .await?
            .into_iter()
            .map(Entity::Security)
            .collect(),
        EntityKind::Transport => store
            .list()
            .await?
            .into_iter()
            .map(Entity::Transport)
            .collect(),
        EntityKind::Instance => store
            .list()
            .await?
            .into_iter()
            .map(Entity::Instance)
            .collect(),
        EntityKind::Gateway => store
            .list()
            .await?
            .into_iter()
            .map(Entity::Gateway)
            .collect(),
        EntityKind::App => store.list().await?.into_iter().map(Entity::App).collect(),
        EntityKind::Forward => store
            .list()
            .await?
            .into_iter()
            .map(Entity::Forward)
            .collect(),
        EntityKind::SshHost => store
            .list()
            .await?
            .into_iter()
            .map(Entity::SshHost)
            .collect(),
        EntityKind::ProviderAccount => store
            .list()
            .await?
            .into_iter()
            .map(Entity::ProviderAccount)
            .collect(),
    })
}

async fn get(store: &Store, kind: EntityKind, id: String) -> Result<Option<Entity>, StoreError> {
    Ok(match kind {
        EntityKind::Profile => store.get(id).await?.map(Entity::Profile),
        EntityKind::Dns => store.get(id).await?.map(Entity::Dns),
        EntityKind::Security => store.get(id).await?.map(Entity::Security),
        EntityKind::Transport => store.get(id).await?.map(Entity::Transport),
        EntityKind::Instance => store.get(id).await?.map(Entity::Instance),
        EntityKind::Gateway => store.get(id).await?.map(Entity::Gateway),
        EntityKind::App => store.get(id).await?.map(Entity::App),
        EntityKind::Forward => store.get(id).await?.map(Entity::Forward),
        EntityKind::SshHost => store.get(id).await?.map(Entity::SshHost),
        EntityKind::ProviderAccount => store.get(id).await?.map(Entity::ProviderAccount),
    })
}

fn blocklist_view_of(
    b: Blocklist,
    refresh: &HashMap<BlocklistId, BlocklistRefreshState>,
    users: &HashMap<BlocklistId, Vec<NamedRef>>,
) -> BlocklistView {
    // Refresh state belongs to URL sources only (a list switched to upload keeps none).
    let refresh = match b.source {
        BlocklistSource::Url { .. } => refresh.get(&b.id).cloned(),
        BlocklistSource::Upload => None,
    };
    let next_refresh_at = vpn_domain::blocklist::next_refresh_due(
        &b,
        refresh.as_ref().map(|r| (r.attempted_at, r.ok)),
    );
    BlocklistView {
        stale: refresh.as_ref().is_some_and(|r| !r.ok),
        refresh,
        next_refresh_at,
        used_by: users.get(&b.id).cloned().unwrap_or_default(),
        builtin: b
            .builtin
            .as_deref()
            .and_then(vpn_domain::builtin_blocklists::builtin)
            .map(Into::into),
        default_policy: b.builtin.is_some() && b.enabled,
        awaiting_content: b.awaiting_content(),
        // Whether the Provider egress can carry a download is the controller's to say.
        waiting: None,
        blocklist: b,
    }
}

async fn blocklist_views(store: &Store) -> Result<Vec<BlocklistView>, ApiError> {
    let lists: Vec<Blocklist> = store.list().await.map_err(api)?;
    let refresh = store.blocklist_refresh_states().await.map_err(api)?;
    let users = store.blocklist_users().await.map_err(api)?;
    Ok(lists
        .into_iter()
        .map(|b| blocklist_view_of(b, &refresh, &users))
        .collect())
}

async fn blocklist_view(store: &Store, id: BlocklistId) -> Result<BlocklistView, ApiError> {
    let list: Blocklist = store
        .get(id.to_string())
        .await
        .map_err(api)?
        .ok_or_else(|| {
            ApiError::not_found(tr!("the IP blocklist", "IP 封鎖清單", "IP ブロックリスト"))
        })?;
    let refresh = store.blocklist_refresh_states().await.map_err(api)?;
    let users = store.blocklist_users().await.map_err(api)?;
    Ok(blocklist_view_of(list, &refresh, &users))
}

/// Refuse a save that would make a blocklist cover an address a connection needs.
async fn check_policy(
    manager: &Manager,
    store: &Store,
    proposal: Proposal<'_>,
) -> Result<(), ApiError> {
    crate::policy::check(store, &manager.running_policies(), proposal).await
}

fn egress_reply(view: crate::egress::EgressView) -> Reply {
    Reply::ProviderEgress(Box::new(EgressWire {
        egress: view.egress,
        bootstrap: view.grant.map(|g| BootstrapGrantWire {
            connector: g.connector,
            expires_at: g.expires_at,
            run: g.run,
            kind: g.kind,
        }),
        run: view.run,
        recovery: view.recovery,
    }))
}

/// The answer to every call while the manager stops everything to exit. Nothing of the call is
/// done or recorded; an emergency stop says so plainly, because its latch is exactly what the
/// user may think was set.
fn closing_refusal(call: &Call) -> ApiError {
    let emergency = match call {
        Call::Lifecycle(_, Lifecycle::Emergency) => true,
        Call::BeginOperation { kind, .. } => kind == OP_INSTANCE_EMERGENCY_STOP,
        _ => false,
    };
    ApiError::new(
        ErrorCode::Unavailable,
        // A stop keeps the intents: what was running starts again with the next manager.
        if emergency {
            tr!(
                "The emergency stop was not recorded: the manager is stopping (the connection stops with it, but the next manager start restores it as it was set). If you still want this connection locked after the manager restarts, press emergency stop again",
                "急停沒有記錄：manager 正在停止（連線會隨之停止，但 manager 下次啟動時會依原本的設定恢復）。manager 重新啟動後，若仍要鎖定這條連線，請再按一次急停",
                "緊急停止は記録されていません。manager が停止中です（接続も一緒に停止しますが、次に manager が起動すると元の設定どおりに復元されます）。manager の再起動後もこの接続をロックしたい場合は、もう一度緊急停止を押してください"
            )
        } else {
            tr!(
                "The manager is stopping; please wait. This operation was neither run nor recorded",
                "manager 正在停止，請稍候；這個操作沒有執行，也沒有記錄",
                "manager が停止中です。しばらくお待ちください。この操作は実行も記録もされていません"
            )
        },
    )
}

/// The answer to `Call::System`.
fn system_info(store: &Store, manager: &Manager, facts: &SystemFacts) -> Reply {
    let me = vpn_platform::resources::sample_self();
    Reply::System(Box::new(SystemInfo {
        installation_id: store.installation_id(),
        manager_build: identity::build_id().to_string(),
        sqlite_version: Store::sqlite_version().to_string(),
        capabilities: facts.capabilities.clone(),
        logical_cpus: vpn_platform::resources::logical_cpus(),
        manager_rss_bytes: me.rss_bytes,
        manager_cpu_ns: me.cpu_ns,
        metrics_recording: Some(crate::metrics::recording(store, manager.metrics())),
    }))
}

async fn dispatch(
    call: Call,
    manager: &Manager,
    store: &Store,
    facts: &SystemFacts,
) -> Result<Reply, ApiError> {
    if manager.is_closing() {
        return Err(closing_refusal(&call));
    }
    match call {
        Call::System => Ok(system_info(store, manager, facts)),
        Call::List(kind) => list(store, kind).await.map(Reply::Entities).map_err(api),
        Call::Get(kind, id) => get(store, kind, id).await.map_err(api)?.map_or_else(
            || {
                Err(ApiError::not_found(tr!(
                    "the requested data",
                    "指定的資料",
                    "指定されたデータ"
                )))
            },
            |e| Ok(Reply::Entity(Box::new(e))),
        ),
        Call::Create(entity) => create_call(entity, manager, store, facts).await,
        Call::Update {
            entity,
            expected_revision,
        } => update_call(entity, expected_revision, manager, store, facts).await,
        call @ (Call::Delete { .. } | Call::DeleteInstance { .. }) => {
            delete_call(call, manager, store, facts).await
        }
        call @ (Call::ProviderRoute(..)
        | Call::ProviderEgress
        | Call::ProviderBinding
        | Call::PutProviderEgress { .. }
        | Call::BootstrapGrant { .. }
        | Call::BootstrapRevoke
        | Call::Rebootstrap { .. }
        | Call::RebootstrapCancel
        | Call::BootstrapLatest) => egress_call(call, manager, store).await,
        call @ (Call::BootstrapClaimChild { .. }
        | Call::BootstrapReleaseChild { .. }
        | Call::BootstrapRenewChild { .. }
        | Call::BootstrapCreateChild { .. }
        | Call::BootstrapResumeChild { .. }
        | Call::BootstrapSeal { .. }
        | Call::BootstrapAbandon { .. }) => bootstrap_child_call(call, manager, store).await,
        call @ (Call::SshStatus
        | Call::SshInclude
        | Call::SshOverwrite
        | Call::SshApply
        | Call::InstanceStatus(..)
        | Call::InstanceStatuses
        | Call::Lifecycle(..)
        | Call::BeginOperation { .. }
        | Call::FinishOperation { .. }
        | Call::Operation(..)
        | Call::OperationByKey(..)
        | Call::Operations { .. }) => lifecycle_call(call, manager, store, facts).await,
        call @ (Call::PutSecret { .. }
        | Call::GenerateKey { .. }
        | Call::Secrets
        | Call::DeleteSecret(..)
        | Call::LeaseSecret(..)
        | Call::KeyedFingerprint(..)
        | Call::Settings
        | Call::PutSettings { .. }
        | Call::MetricsSeries { .. }
        | Call::MetricsStatus
        | Call::FreePort { .. }) => secrets_call(call, manager, store).await,
        call @ (Call::CreateApp { .. }
        | Call::UpdateApp { .. }
        | Call::DeleteApp { .. }
        | Call::AppStatus(..)
        | Call::AppStatuses
        | Call::AppAction { .. }
        | Call::AppProcesses(..)
        | Call::ForwardStatus(..)
        | Call::ForwardStatuses
        | Call::AppLog { .. }
        | Call::CheckExecutable { .. }) => apps_call(call, manager, store).await,
        call @ (Call::Blocklists
        | Call::Blocklist(..)
        | Call::PutBlocklist { .. }
        | Call::DeleteBlocklist { .. }
        | Call::BuiltinBlocklists
        | Call::RestoreBuiltinBlocklist { .. }
        | Call::BlocklistRefreshed { .. }
        | Call::Bans(..)
        | Call::Unban(..)) => blocklists_call(call, manager, store).await,
        call @ (Call::Diagnostics
        | Call::RecoveryInspect
        | Call::RecoveryReconcile { .. }
        | Call::Performance(..)
        | Call::SshDownload(..)) => system_call(call, manager, store, facts).await,
    }
}

/// The diagnostics, recovery, performance and SSH download calls.
async fn system_call(
    call: Call,
    manager: &Manager,
    store: &Store,
    facts: &SystemFacts,
) -> Result<Reply, ApiError> {
    match call {
        Call::Diagnostics => Ok(Reply::Diagnostics(Box::new(
            crate::system::report(manager, store, facts).await,
        ))),
        Call::RecoveryInspect => Ok(Reply::Recovery(Box::new(
            crate::recovery::inspect(manager, store, ssh_dir(facts))
                .await
                .report(),
        ))),
        Call::RecoveryReconcile { only } => Ok(Reply::Reconciled(Box::new(
            crate::recovery::reconcile(manager, store, ssh_dir(facts), only).await,
        ))),
        Call::Performance(c) => Ok(Reply::Performance(Box::new(
            performance_of(facts)?.call(c).await?,
        ))),
        Call::SshDownload(c) => {
            let downloads = manager.ssh_downloads().ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Unavailable,
                    tr!(
                        "The SSH download component is not running; check the service log",
                        "SSH 下載元件沒有啟動，請查看服務紀錄",
                        "SSH ダウンロードのコンポーネントが起動していません。サービスのログを確認してください"
                    ),
                )
            })?;
            Ok(Reply::SshDownload(Box::new(downloads.call(c).await?)))
        }
        // `dispatch` routes only the calls above here.
        _ => Err(ApiError::internal()),
    }
}

/// A transport profile about to be stored: what its ranges name must exist and be fixed
/// profiles, and a profile an automatic one names must itself stay fixed. Checked against the
/// stored profiles, under the policy lock, so no save in between can undo it.
async fn check_transport(store: &Store, proposed: &TransportProfile) -> Result<(), ApiError> {
    let invalid = |message: Text| ApiError::new(ErrorCode::ValidationFailed, message);
    let mut all: Vec<TransportProfile> = store.list().await.map_err(api)?;
    all.retain(|p| p.id != proposed.id);
    if matches!(proposed.settings, TransportSettings::Auto { .. })
        && let Some(user) = all.iter().find(|p| names_transport(p, proposed.id))
    {
        let name = &user.name;
        return Err(invalid(tr!(
            "A range of the automatic transport profile “{name}” uses this profile, so it must stay fixed",
            "自動傳輸設定「{name}」的區間選用了這個設定，它必須維持固定的設定",
            "自動トランスポート設定「{name}」の範囲がこの設定を使っているため、固定の設定のままにする必要があります"
        )));
    }
    all.push(proposed.clone());
    vpn_domain::resolve_transport(&TransportRef::Profile { id: proposed.id }, &all)
        .map(|_| ())
        .map_err(|e| invalid(e.message()))
}

/// Whether a range of the automatic profile `p` names the stored profile `id`.
fn names_transport(p: &TransportProfile, id: TransportProfileId) -> bool {
    match &p.settings {
        TransportSettings::Fixed { .. } => false,
        TransportSettings::Auto { bands } => bands
            .iter()
            .any(|b| b.profile == TransportRef::Profile { id }),
    }
}

/// A `Create` call: the entity, stored.
async fn create_call(
    entity: Entity,
    manager: &Manager,
    store: &Store,
    facts: &SystemFacts,
) -> Result<Reply, ApiError> {
    let created = match entity {
        Entity::Profile(e) => Entity::Profile(store.create(e).await.map_err(api)?),
        Entity::Dns(e) => Entity::Dns(store.create(e).await.map_err(api)?),
        Entity::Security(e) => {
            let _policy = manager.policy_lock().await;
            check_policy(manager, store, Proposal::Security(&e)).await?;
            Entity::Security(store.create(e).await.map_err(api)?)
        }
        Entity::Transport(e) => {
            let _policy = manager.policy_lock().await;
            check_transport(store, &e).await?;
            Entity::Transport(store.create(e).await.map_err(api)?)
        }
        Entity::Instance(e) => {
            let _policy = manager.policy_lock().await;
            check_policy(manager, store, Proposal::Instance(&e)).await?;
            let e = store.create_instance(e).await.map_err(api)?;
            manager.instance_created(e.id);
            Entity::Instance(e)
        }
        Entity::Gateway(e) => {
            crate::ports::check_gateway(manager, &e).await?;
            let e = store.create(e).await.map_err(api)?;
            manager.gateways_changed(e.instance_id).await;
            Entity::Gateway(e)
        }
        Entity::App(e) => Entity::App(manager.apps().create(e, None).await?),
        Entity::Forward(mut e) => {
            // Entered by hand: never verified by a provider.
            e.assignment_source = AssignmentSource::Manual;
            manager.check_forward(&e).await?;
            let e = store.create(e).await.map_err(api)?;
            manager.forwards_changed(e.instance_id).await;
            Entity::Forward(e)
        }
        Entity::SshHost(e) => {
            let e = store.create(e).await.map_err(api)?;
            ssh_changed(facts, store).await;
            Entity::SshHost(e)
        }
        Entity::ProviderAccount(e) => Entity::ProviderAccount(store.create(e).await.map_err(api)?),
    };
    Ok(Reply::Entity(Box::new(created)))
}

/// An `Update` call of `entity` at revision `r`.
async fn update_call(
    entity: Entity,
    r: u64,
    manager: &Manager,
    store: &Store,
    facts: &SystemFacts,
) -> Result<Reply, ApiError> {
    // What a blocklist covers or what a connection needs changes with these: checked and
    // written under the policy lock.
    let _policy = match &entity {
        Entity::Security(_)
        | Entity::Instance(_)
        | Entity::Profile(_)
        | Entity::Dns(_)
        | Entity::Transport(_) => Some(manager.policy_lock().await),
        _ => None,
    };
    match &entity {
        Entity::Security(s) => check_policy(manager, store, Proposal::Security(s)).await?,
        Entity::Instance(i) => check_policy(manager, store, Proposal::Instance(i)).await?,
        Entity::Profile(p) => check_policy(manager, store, Proposal::Profile(p)).await?,
        Entity::Dns(d) => check_policy(manager, store, Proposal::Dns(d)).await?,
        Entity::Transport(t) => check_transport(store, t).await?,
        _ => {}
    }
    let updated = match entity {
        Entity::Profile(e) => Entity::Profile(store.update(e, r).await.map_err(api)?),
        Entity::Dns(e) => Entity::Dns(store.update(e, r).await.map_err(api)?),
        Entity::Security(e) => Entity::Security(store.update(e, r).await.map_err(api)?),
        Entity::Transport(e) => Entity::Transport(store.update(e, r).await.map_err(api)?),
        Entity::Instance(e) => Entity::Instance(store.update(e, r).await.map_err(api)?),
        Entity::Gateway(e) => {
            app_gateway_unchanged(manager, store, &e).await?;
            crate::ports::check_gateway(manager, &e).await?;
            let e = store.update(e, r).await.map_err(api)?;
            manager.gateways_changed(e.instance_id).await;
            // A new port changes the ProxyCommand of the SSH hosts that use it.
            ssh_changed(facts, store).await;
            Entity::Gateway(e)
        }
        Entity::App(e) => Entity::App(manager.apps().update(e, r, None).await?),
        Entity::Forward(mut e) => {
            let current: ForwardBinding = store
                .get(e.id.to_string())
                .await
                .map_err(api)?
                .ok_or_else(|| {
                    ApiError::not_found(tr!("the port forward", "轉發", "ポート転送"))
                })?;
            if current.instance_id != e.instance_id {
                return Err(ApiError::new(
                    ErrorCode::ValidationFailed,
                    tr!(
                        "A port forward cannot move to another connection; delete it and create it again on that connection",
                        "轉發不能移到另一條連線；請刪除後在那條連線重建",
                        "ポート転送は別の接続に移せません。削除してから、その接続で作り直してください"
                    ),
                ));
            }
            e.assignment_source = AssignmentSource::Manual;
            manager.check_forward(&e).await?;
            let e = store.update(e, r).await.map_err(api)?;
            manager.forwards_changed(e.instance_id).await;
            Entity::Forward(e)
        }
        Entity::SshHost(e) => {
            let e = store.update(e, r).await.map_err(api)?;
            ssh_changed(facts, store).await;
            Entity::SshHost(e)
        }
        Entity::ProviderAccount(e) => {
            Entity::ProviderAccount(store.update(e, r).await.map_err(api)?)
        }
    };
    // What a start resolves: a blocked one may be able to start now. A transport profile also
    // applies to the running connections that use it, at once.
    if matches!(
        updated,
        Entity::Instance(_)
            | Entity::Profile(_)
            | Entity::Dns(_)
            | Entity::Security(_)
            | Entity::Transport(_)
    ) {
        manager.config_changed();
    }
    // Its blocklists apply to running connections at once.
    if matches!(updated, Entity::Security(_)) {
        manager.policy_changed();
    }
    Ok(Reply::Entity(Box::new(updated)))
}

/// An entity id in a call that does not parse.
fn invalid_id() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidRequest,
        tr!("Invalid id", "id 無效", "id が無効です"),
    )
}

/// An Instance is deleted only once it is stopped (or failed).
fn instance_running() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidState,
        tr!(
            "The Instance is still running or recovering; stop it first",
            "Instance 仍在執行或恢復中，請先停止",
            "Instance はまだ実行中か復旧中です。先に停止してください"
        ),
    )
}

/// A `Delete` or `DeleteInstance` call.
async fn delete_call(
    call: Call,
    manager: &Manager,
    store: &Store,
    facts: &SystemFacts,
) -> Result<Reply, ApiError> {
    match call {
        Call::Delete {
            kind,
            id,
            expected_revision: r,
        } => {
            match kind {
                EntityKind::Profile => store.delete::<RuntimeProfile>(id, r).await,
                EntityKind::Dns => store.delete::<DnsProfile>(id, r).await,
                EntityKind::Security => store.delete::<SecurityProfile>(id, r).await,
                EntityKind::Transport => store.delete::<TransportProfile>(id, r).await,
                EntityKind::Instance => {
                    let iid: InstanceId = id.parse().map_err(|_| invalid_id())?;
                    let status = manager.status(iid).await?;
                    if !matches!(status.phase, Phase::Stopped | Phase::Failed) {
                        return Err(instance_running());
                    }
                    let res = store.delete_instance(iid, r).await;
                    if res.is_ok() {
                        manager.instance_removed(iid).await;
                    }
                    res
                }
                EntityKind::Gateway => {
                    let g: Option<GatewaySpec> = store.get(id.clone()).await.map_err(api)?;
                    let res = store.delete::<GatewaySpec>(id, r).await;
                    if res.is_ok()
                        && let Some(g) = g
                    {
                        manager.gateways_changed(g.instance_id).await;
                    }
                    res
                }
                EntityKind::App => {
                    let app: AppId = id.parse().map_err(|_| invalid_id())?;
                    manager.apps().delete(app, r).await?;
                    Ok(())
                }
                EntityKind::Forward => {
                    let fid: ForwardBindingId = id.parse().map_err(|_| invalid_id())?;
                    let f: Option<ForwardBinding> = store.get(id).await.map_err(api)?;
                    let res = store.delete_forward(fid, r).await;
                    if res.is_ok()
                        && let Some(f) = f
                    {
                        manager.forwards_changed(f.instance_id).await;
                    }
                    res
                }
                EntityKind::SshHost => {
                    let res = store.delete::<SshHost>(id, r).await;
                    if res.is_ok() {
                        ssh_changed(facts, store).await;
                    }
                    res
                }
                EntityKind::ProviderAccount => store.delete::<ProviderAccount>(id, r).await,
            }
            .map_err(api)?;
            Ok(Reply::Unit)
        }
        Call::DeleteInstance {
            id,
            expected_revision,
            gateways,
        } => {
            let status = manager.status(id).await?;
            if !matches!(status.phase, Phase::Stopped | Phase::Failed) {
                return Err(instance_running());
            }
            store
                .delete_instance_with_gateways(id, expected_revision, gateways)
                .await
                .map_err(api)?;
            manager.instance_removed(id).await;
            Ok(Reply::Unit)
        }
        // `dispatch` routes only the calls above here.
        _ => Err(ApiError::internal()),
    }
}

/// The Provider egress calls, the grant and the latest run.
async fn egress_call(call: Call, manager: &Manager, store: &Store) -> Result<Reply, ApiError> {
    match call {
        Call::ProviderRoute(id) => {
            let (generation, connector) = manager.provider_route(id).await?;
            Ok(Reply::ProviderRoute {
                generation,
                connector,
            })
        }
        Call::ProviderEgress => Ok(egress_reply(manager.provider_egress().await?)),
        Call::ProviderBinding => Ok(egress_reply(manager.provider_binding().await?)),
        Call::PutProviderEgress {
            desired_mode,
            selected_instance_id,
            expected_revision,
        } => {
            // A chosen Instance (or turning egress off) ends the direct exception: the active
            // run ends in the same Store transaction, its grant closes here.
            let ends = selected_instance_id.is_some() || desired_mode == EgressMode::Disabled;
            let decision = manager.bootstrap().decide().await;
            store
                .put_provider_egress(desired_mode, selected_instance_id, expected_revision)
                .await
                .map_err(api)?;
            manager.binding_changed(ends);
            drop(decision);
            Ok(egress_reply(manager.provider_egress().await?))
        }
        Call::BootstrapGrant { operation } => {
            manager.bootstrap().grant(operation).await?;
            Ok(egress_reply(manager.provider_egress().await?))
        }
        Call::BootstrapRevoke => Ok(egress_reply(manager.end_initial_bootstrap().await?)),
        Call::Rebootstrap {
            expected_revision,
            operation,
        } => Ok(egress_reply(
            manager.rebootstrap(expected_revision, operation).await?,
        )),
        Call::RebootstrapCancel => Ok(egress_reply(manager.cancel_rebootstrap().await?)),
        Call::BootstrapLatest => Ok(Reply::BootstrapRun(
            store
                .latest_bootstrap()
                .await
                .map_err(api)?
                .map(|r| Box::new(r.view())),
        )),
        // `dispatch` routes only the calls above here.
        _ => Err(ApiError::internal()),
    }
}

/// The calls about a bootstrap run's connection.
async fn bootstrap_child_call(
    call: Call,
    manager: &Manager,
    store: &Store,
) -> Result<Reply, ApiError> {
    match call {
        Call::BootstrapClaimChild { operation } => Ok(Reply::BootstrapClaim(
            manager.bootstrap_claim(operation).await?,
        )),
        Call::BootstrapReleaseChild { run, operation } => {
            store
                .release_bootstrap_child(run, operation)
                .await
                .map_err(api)?;
            Ok(Reply::Unit)
        }
        // No decision is taken: it only extends a reservation this request still holds.
        Call::BootstrapRenewChild { run, operation } => {
            store
                .renew_bootstrap_child(run, operation)
                .await
                .map_err(api)?;
            Ok(Reply::Unit)
        }
        Call::BootstrapCreateChild {
            run,
            operation,
            instance,
            gateway,
        } => {
            let _policy = manager.policy_lock().await;
            check_policy(manager, store, Proposal::Instance(&instance)).await?;
            if let Some(g) = &gateway {
                crate::ports::check_gateway(manager, g).await?;
            }
            let (instance, gateway) = manager
                .bootstrap_create_child(run, operation, instance, gateway)
                .await?;
            Ok(Reply::BootstrapChild {
                instance: Box::new(instance),
                gateway,
            })
        }
        Call::BootstrapResumeChild { run } => {
            manager.bootstrap_resume(run).await?;
            Ok(Reply::Unit)
        }
        Call::BootstrapSeal {
            run,
            instance,
            generation,
        } => Ok(egress_reply(
            manager.bootstrap_seal(run, instance, generation).await?,
        )),
        Call::BootstrapAbandon {
            run,
            reason_code,
            reason,
        } => Ok(egress_reply(
            manager.bootstrap_abandon(run, reason_code, reason).await?,
        )),
        // `dispatch` routes only the calls above here.
        _ => Err(ApiError::internal()),
    }
}

/// The SSH projection, lifecycle and operation calls.
async fn lifecycle_call(
    call: Call,
    manager: &Manager,
    store: &Store,
    facts: &SystemFacts,
) -> Result<Reply, ApiError> {
    match call {
        Call::SshStatus => Ok(Reply::SshStatus(Box::new(
            ssh_of(facts)?.status(store).await,
        ))),
        Call::SshInclude | Call::SshOverwrite | Call::SshApply => {
            let ssh = ssh_of(facts)?;
            let backup = match call {
                Call::SshInclude => ssh.include(store).await?,
                Call::SshOverwrite => ssh.overwrite(store).await?,
                _ => {
                    ssh.apply(store)
                        .await
                        .map_err(|e| ApiError::new(ErrorCode::InvalidState, e))?;
                    None
                }
            };
            Ok(Reply::SshAction {
                status: Box::new(ssh.status(store).await),
                backup,
            })
        }
        Call::InstanceStatus(id) => Ok(Reply::Status(Box::new(manager.status(id).await?))),
        Call::InstanceStatuses => Ok(Reply::Statuses(manager.statuses().await)),
        Call::Lifecycle(id, op) => match op {
            Lifecycle::Start => Ok(Reply::Status(Box::new(manager.start_instance(id).await?))),
            Lifecycle::Restart => Ok(Reply::Status(Box::new(manager.restart_instance(id).await?))),
            Lifecycle::ClearEmergency => {
                Ok(Reply::Status(Box::new(manager.clear_emergency(id).await?)))
            }
            Lifecycle::Stop | Lifecycle::Emergency => {
                let o = manager
                    .stop_instance(id, op == Lifecycle::Emergency)
                    .await?;
                Ok(Reply::Stopped {
                    sealed: o.sealed,
                    durable: o.durable,
                })
            }
        },
        Call::BeginOperation {
            kind,
            target_id,
            idempotency_key,
            fingerprint,
        } => match store
            .begin_operation(kind, target_id, idempotency_key, fingerprint)
            .await
            .map_err(api)?
        {
            Begin::New(operation) => Ok(Reply::Begin {
                operation,
                existing: false,
            }),
            Begin::Existing(operation) => Ok(Reply::Begin {
                operation,
                existing: true,
            }),
        },
        Call::FinishOperation {
            id,
            status,
            error,
            result_refs,
        } => {
            store
                .finish_operation(id, status, error, result_refs)
                .await
                .map_err(api)?;
            Ok(Reply::Unit)
        }
        Call::Operation(id) => Ok(Reply::Operation(store.operation(id).await.map_err(api)?)),
        Call::OperationByKey(k) => Ok(Reply::Operation(
            store.operation_by_key(k).await.map_err(api)?,
        )),
        Call::Operations { limit } => Ok(Reply::Operations(
            store
                .recent_operations(limit.clamp(1, MAX_OPERATIONS_LISTED) as usize)
                .await
                .map_err(api)?,
        )),
        // `dispatch` routes only the calls above here.
        _ => Err(ApiError::internal()),
    }
}

/// The secret, settings, metrics and free-port calls.
async fn secrets_call(call: Call, manager: &Manager, store: &Store) -> Result<Reply, ApiError> {
    match call {
        Call::PutSecret {
            kind,
            label,
            plaintext,
            public_fingerprint,
        } => {
            let pt = Zeroizing::new(plaintext.expose().to_vec());
            let meta = store
                .put_secret(kind, label, pt, public_fingerprint)
                .await
                .map_err(api)?;
            Ok(Reply::Secret(secret_wire(meta)))
        }
        Call::GenerateKey { label } => {
            let private = vpn_tunnel::keys::generate_private();
            let public = WgKey(vpn_tunnel::keys::public_from_private(&private));
            let meta = store
                .put_secret(
                    "wireguard_private_key".into(),
                    label,
                    Zeroizing::new(private.to_vec()),
                    Some(crate::resolve::key_fingerprint(&public)),
                )
                .await
                .map_err(api)?;
            Ok(Reply::GeneratedKey {
                secret: secret_wire(meta),
                public_key: public,
            })
        }
        Call::Secrets => Ok(Reply::Secrets(
            store
                .secrets()
                .await
                .map_err(api)?
                .into_iter()
                .map(secret_wire)
                .collect(),
        )),
        Call::DeleteSecret(r) => {
            store.delete_secret(r).await.map_err(api)?;
            Ok(Reply::Unit)
        }
        Call::LeaseSecret(r) => {
            let pt = store.open_secret(r).await.map_err(api)?;
            Ok(Reply::SecretBytes(SecretBytes::new(pt.to_vec())))
        }
        Call::KeyedFingerprint(data) => Ok(Reply::Fingerprint(store.keyed_fingerprint(&data))),
        Call::Settings => Ok(Reply::Settings(store.settings().await.map_err(api)?)),
        Call::PutSettings {
            settings,
            expected_revision,
        } => Ok(Reply::Settings(
            store
                .put_settings(settings, expected_revision)
                .await
                .map_err(api)?,
        )),
        Call::MetricsSeries { scope, range } => Ok(Reply::MetricsSeries(Box::new(
            crate::metrics::series(store, scope, range).await?,
        ))),
        Call::MetricsStatus => Ok(Reply::MetricsStatus(Box::new(
            crate::metrics::status(store, manager.metrics()).await?,
        ))),
        Call::FreePort { from } => Ok(Reply::FreePort(crate::ports::free(store, from).await?)),
        // `dispatch` routes only the calls above here.
        _ => Err(ApiError::internal()),
    }
}

/// The App and port-forward calls.
async fn apps_call(call: Call, manager: &Manager, store: &Store) -> Result<Reply, ApiError> {
    match call {
        Call::CreateApp {
            spec,
            expected_sha256,
        } => Ok(Reply::Entity(Box::new(Entity::App(
            manager.apps().create(spec, expected_sha256).await?,
        )))),
        Call::UpdateApp {
            spec,
            expected_revision,
            expected_sha256,
        } => Ok(Reply::Entity(Box::new(Entity::App(
            manager
                .apps()
                .update(spec, expected_revision, expected_sha256)
                .await?,
        )))),
        Call::DeleteApp {
            id,
            expected_revision,
        } => {
            manager.apps().delete(id, expected_revision).await?;
            Ok(Reply::Unit)
        }
        Call::AppStatus(id) => Ok(Reply::AppStatus(Box::new(manager.apps().status(id).await?))),
        Call::AppStatuses => Ok(Reply::AppStatuses(manager.apps().statuses())),
        Call::AppAction { id, action, sha256 } => Ok(Reply::AppStatus(Box::new(
            manager.apps().action(manager, id, action, sha256).await?,
        ))),
        Call::AppProcesses(id) => Ok(Reply::AppProcesses(Box::new(
            manager.apps().processes(id).await?,
        ))),
        Call::ForwardStatus(id) => {
            let binding: ForwardBinding = store
                .get(id.to_string())
                .await
                .map_err(api)?
                .ok_or_else(|| {
                    ApiError::not_found(tr!("the port forward", "轉發", "ポート転送"))
                })?;
            Ok(Reply::ForwardStatus(Box::new(
                manager.forward_status(&binding).await?,
            )))
        }
        Call::ForwardStatuses => Ok(Reply::ForwardStatuses(manager.forward_statuses().await)),
        Call::AppLog { id, lines } => Ok(Reply::AppLog(Box::new(
            manager.apps().log(id, lines).await?,
        ))),
        Call::CheckExecutable { path } => Ok(Reply::ExecutableCheck(Box::new(
            manager.apps().check_executable(path).await?,
        ))),
        // `dispatch` routes only the calls above here.
        _ => Err(ApiError::internal()),
    }
}

/// The blocklist and ban calls.
async fn blocklists_call(call: Call, manager: &Manager, store: &Store) -> Result<Reply, ApiError> {
    match call {
        Call::Blocklists => Ok(Reply::Blocklists(blocklist_views(store).await?)),
        Call::Blocklist(id) => Ok(Reply::Blocklist(Box::new(blocklist_view(store, id).await?))),
        Call::PutBlocklist {
            list,
            expected_revision,
            set,
        } => {
            let list = *list;
            let id = list.id;
            {
                let _policy = manager.policy_lock().await;
                match (expected_revision, set) {
                    (None, Some(set)) => {
                        // A new list is not used by any security profile yet.
                        store.create_blocklist(list, set).await.map_err(api)?;
                    }
                    (None, None) => {
                        return Err(ApiError::new(
                            ErrorCode::InvalidRequest,
                            tr!(
                                "A new IP blocklist needs content",
                                "新的 IP 封鎖清單需要內容",
                                "新しい IP ブロックリストには内容が必要です"
                            ),
                        ));
                    }
                    (Some(r), set) => {
                        // New content, or a list enabled again, may cover an address a
                        // connection needs (through a profile, or the default policy).
                        check_policy(
                            manager,
                            store,
                            Proposal::Blocklist {
                                list: &list,
                                set: set.as_ref(),
                            },
                        )
                        .await?;
                        store.update_blocklist(list, r, set).await.map_err(api)?;
                    }
                }
            }
            if expected_revision.is_some() {
                // Running connections that use it get the new content (or name) at once, and a
                // start that waited for it (its list covered a needed address) tries again.
                manager.policy_changed();
                manager.config_changed();
            }
            Ok(Reply::Blocklist(Box::new(blocklist_view(store, id).await?)))
        }
        Call::DeleteBlocklist {
            id,
            expected_revision,
        } => {
            store
                .delete_blocklist(id, expected_revision)
                .await
                .map_err(api)?;
            // A built-in list leaves the default policy: running connections without a security
            // profile drop it at once, and a start it blocked may go ahead.
            manager.policy_changed();
            manager.config_changed();
            Ok(Reply::Unit)
        }
        Call::BuiltinBlocklists => Ok(Reply::BuiltinBlocklists(
            store.builtin_blocklists().await.map_err(api)?,
        )),
        Call::RestoreBuiltinBlocklist { key } => {
            let list = {
                let _policy = manager.policy_lock().await;
                store.restore_builtin_blocklist(key).await.map_err(api)?
            };
            // Back in the default policy: a list that came back with content (a user's list of
            // the same URL, adopted) applies to running connections at once, without a new
            // generation.
            manager.policy_changed();
            manager.config_changed();
            Ok(Reply::Blocklist(Box::new(
                blocklist_view(store, list.id).await?,
            )))
        }
        Call::BlocklistRefreshed { id, ok, message } => {
            store
                .record_blocklist_refresh(id, ok, message)
                .await
                .map_err(api)?;
            Ok(Reply::Blocklist(Box::new(blocklist_view(store, id).await?)))
        }
        Call::Bans(instance) => Ok(Reply::Bans(store.bans(instance).await.map_err(api)?)),
        Call::Unban(id) => {
            let ban = store.delete_ban(id).await.map_err(api)?.ok_or_else(|| {
                ApiError::not_found(tr!(
                    "this ban (it may have expired or been lifted)",
                    "這筆封鎖紀錄（可能已到期或已解除）",
                    "このブロック記録（期限切れか、すでに解除された可能性があります）"
                ))
            })?;
            let worker = manager.unban(ban.instance_id, ban.source).await;
            Ok(Reply::Unbanned(Box::new(UnbanResult { ban, worker })))
        }
        // `dispatch` routes only the calls above here.
        _ => Err(ApiError::internal()),
    }
}

/// A running App points at its Gateway's port with the variables (or Seatbelt profile) of the
/// Gateway's kind: while one runs, the Gateway keeps its port, kind and listener.
async fn app_gateway_unchanged(
    manager: &Manager,
    store: &Store,
    next: &GatewaySpec,
) -> Result<(), ApiError> {
    let Some(app) = manager.apps().gateway_in_use(next.id) else {
        return Ok(());
    };
    let current: Option<GatewaySpec> = store.get(next.id.to_string()).await.map_err(api)?;
    let changes = current.is_none_or(|c| {
        c.port != next.port
            || c.kind != next.kind
            || !next.enabled
            || c.instance_id != next.instance_id
    });
    if changes {
        return Err(ApiError::new(
            ErrorCode::InUse,
            tr!(
                "The managed app “{app}” is using this Gateway: stop it before changing the port or protocol or turning the Gateway off",
                "受管 App「{app}」正在使用這個代理埠：請先停止它，再變更埠號、協定或停用",
                "管理対象アプリ「{app}」がこのゲートウェイを使用しています。ポート番号やプロトコルを変更したり無効にしたりする前に、先にアプリを停止してください"
            ),
        ));
    }
    Ok(())
}

fn ssh_dir(facts: &SystemFacts) -> Option<&std::path::Path> {
    facts.ssh.as_deref().map(SshProjector::ssh_dir)
}
