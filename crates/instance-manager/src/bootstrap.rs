//! The direct exception for Provider operations (architecture §7).
//!
//! It covers the first setup's one-time
//! bootstrap and, after the egress became unusable for good, a manual rebootstrap. Each run is a
//! row of the Store's `bootstrap_journal`; the grant itself — a relay socket the controller may
//! reach a fixed allowlist of provider origins through, for at most ten minutes — lives only in
//! this process. The controller never dials: the manager resolves, connects and relays, and holds
//! every stream, so expiry, cancellation, the seal or this process ending cut them all at once.
//! A restarted manager has no grant; it records that before it serves anything
//! ([`Bootstrap::recover`]).
//!
//! A run builds at most one connection (its child). Once the child is ready and its exit answered
//! through it, the seal runs in three steps, each durable before the next: the Store records the
//! seal intent, this process closes the grant, the Store commits the latch, the binding and the end
//! of the run in one transaction. A crash after the intent never reopens direct access: the next
//! start commits it forward.
//!
//! Same request line as an Instance connector (`vpn_ipc::relay`, version 2): a single-use nonce
//! and the route it is meant for, here the bootstrap grant. A reused nonce or a line meant for
//! an Instance connector is refused before anything is resolved. Answered with
//! `{"ok":true,"peer":…,"epochs":…}` or `{"ok":false,"code":…,"message":…}` before the relay.
//! Each grant is its own connector epoch; its network epoch stays 0 (the path is the host's).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use vpn_domain::validation::{is_private, is_special};
use vpn_domain::{
    ApiError, BOOTSTRAP_ALLOWLIST, BootstrapKind, ErrorCode, InstanceId, OperationId,
    ProviderEgress, Text, Timestamp, tr,
};
use vpn_ipc::relay::{Admission, LINE_MAX, RelayAnswer as Reply, RelayFamily as Fam, RelayRoute};
use vpn_store::{BootstrapRow, GrantEnd, Store, StoreError};
use vpn_sync::Mutex;

use crate::remove_file_if_present;

/// How long one grant stays open.
pub const GRANT_TTL: Duration = Duration::from_mins(10);
/// How long a run's new connection may take to connect and have its exit verified before it is
/// no longer made the egress.
pub const PROMOTE_WAIT: Duration = Duration::from_secs(120);
const MAX_STREAMS: usize = 8;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Resolving and connecting together.
const CONNECT_BUDGET: Duration = Duration::from_secs(10);
const MAX_ATTEMPTS: usize = 4;
/// The direct path is the host network, which reports no epochs of its own.
const NETWORK_EPOCH: u64 = 0;

fn refuse(code: &'static str, message: Text) -> Reply {
    Reply::refuse(code, message)
}

/// Where a grant may connect.
#[derive(Clone)]
struct Policy {
    allow: Arc<Vec<(String, u16)>>,
    /// Refuse addresses that are not public (always on outside tests).
    public_only: bool,
}

struct Grant {
    path: PathBuf,
    expires_at: Timestamp,
    cancel: CancellationToken,
    run: String,
    id: String,
    kind: BootstrapKind,
}

impl Drop for Grant {
    fn drop(&mut self) {
        self.cancel.cancel();
        remove_file_if_present(&self.path);
    }
}

/// The grant open right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveGrant {
    /// The relay socket.
    pub connector: String,
    pub expires_at: Timestamp,
    /// The run it belongs to.
    pub run: String,
    pub kind: BootstrapKind,
}

pub struct Bootstrap {
    run_dir: PathBuf,
    store: Arc<Store>,
    policy: Policy,
    grant: Mutex<Option<Grant>>,
    /// How long a grant stays open ([`GRANT_TTL`]; shorter in tests).
    ttl: Duration,
    /// Held across every decision about direct access: opening (with its eligibility check),
    /// claiming the run's connection, the seal, ending a run.
    decisions: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bootstrap")
            .field("run_dir", &self.run_dir)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

fn grant_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "a `Result::map_err` adapter: it takes the error by value"
)]
fn api(e: StoreError) -> ApiError {
    e.to_api()
}

impl Bootstrap {
    /// `run`: the private runtime directory the relay sockets are created in.
    pub fn new(run: PathBuf, store: Arc<Store>) -> Self {
        Self::with_policy(
            run,
            store,
            BOOTSTRAP_ALLOWLIST
                .iter()
                .map(|(h, p)| (h.to_string(), *p))
                .collect(),
            true,
        )
    }

    fn with_policy(
        run: PathBuf,
        store: Arc<Store>,
        allow: Vec<(String, u16)>,
        public_only: bool,
    ) -> Self {
        Self {
            run_dir: run,
            store,
            policy: Policy {
                allow: Arc::new(allow),
                public_only,
            },
            grant: Mutex::new(None),
            ttl: GRANT_TTL,
            decisions: tokio::sync::Mutex::new(()),
        }
    }

    /// Serialise a decision about direct access with every other one.
    pub(crate) async fn decide(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.decisions.lock().await
    }

    /// The open grant, if any.
    pub fn active(&self) -> Option<ActiveGrant> {
        let mut grant = self.grant.lock();
        if grant
            .as_ref()
            .is_some_and(|g| g.cancel.is_cancelled() || g.expires_at <= Timestamp::now())
        {
            *grant = None;
        }
        grant.as_ref().map(|g| ActiveGrant {
            connector: g.path.display().to_string(),
            expires_at: g.expires_at,
            run: g.run.clone(),
            kind: g.kind,
        })
    }

    /// At manager start, before any call is served: the previous process's grants are gone.
    /// Records that, ends overdue promotions, and commits an interrupted seal forward.
    ///
    /// # Errors
    ///
    /// A Store error when the bootstrap journal cannot be read or updated.
    pub async fn recover(&self) -> Result<Vec<BootstrapRow>, StoreError> {
        let _d = self.decide().await;
        let changed = self.store.recover_bootstrap().await?;
        for r in &changed {
            tracing::info!(run = %r.id, stage = ?r.stage, "provider bootstrap run recovered");
        }
        Ok(changed)
    }

    /// Open the first setup's grant, or return the open one. Only while the bootstrap is unused,
    /// Provider egress is on and no egress Instance is chosen.
    ///
    /// # Errors
    ///
    /// `BootstrapInProgress` while a rebootstrap grant is open; the eligibility refusal when the
    /// bootstrap is used, Provider egress is off or an egress Instance is chosen; a Store or
    /// socket failure while opening the grant.
    pub async fn grant(&self, operation: Option<OperationId>) -> Result<ActiveGrant, ApiError> {
        let _d = self.decide().await;
        if let Some(open) = self.active() {
            return if open.kind == BootstrapKind::Initial {
                Ok(open)
            } else {
                Err(ApiError::new(
                    ErrorCode::BootstrapInProgress,
                    tr!(
                        "A direct reconnection is in progress; only one direct connection can be open at a time",
                        "重新直連正在進行；一次只能有一個直連",
                        "再度の直接接続が進行中です。直接接続は一度に 1 つだけです"
                    ),
                ))
            };
        }
        let id = grant_id();
        let expires_at = Timestamp::now().plus(self.ttl);
        let row = self
            .store
            .open_initial_bootstrap(id.clone(), expires_at, operation)
            .await
            .map_err(api)?;
        self.open_socket(row.id, id, BootstrapKind::Initial, expires_at)
            .await
    }

    /// Open a rebootstrap run and its grant. The caller holds [`Self::decide`] and has checked
    /// eligibility under it.
    pub(crate) async fn open_rebootstrap(
        &self,
        expected_revision: u64,
        operation: Option<OperationId>,
    ) -> Result<ActiveGrant, ApiError> {
        if self.active().is_some() {
            return Err(ApiError::new(
                ErrorCode::BootstrapInProgress,
                tr!(
                    "A direct connection is already open; only one can be open at a time",
                    "已有開放中的直連；一次只能有一個",
                    "開いている直接接続がすでにあります。一度に 1 つだけです"
                ),
            ));
        }
        let id = grant_id();
        let expires_at = Timestamp::now().plus(self.ttl);
        let row = self
            .store
            .open_rebootstrap(id.clone(), expires_at, operation, expected_revision)
            .await
            .map_err(api)?;
        self.open_socket(row.id, id, BootstrapKind::Rebootstrap, expires_at)
            .await
    }

    /// Bind the relay socket of grant `id` (already on record for `run`) and serve it until it
    /// expires or is revoked. A socket that cannot be made ends the grant on record too.
    async fn open_socket(
        &self,
        run: String,
        id: String,
        kind: BootstrapKind,
        expires_at: Timestamp,
    ) -> Result<ActiveGrant, ApiError> {
        let path = self
            .run_dir
            .join(format!("b-{:016x}.sock", rand::random::<u64>()));
        let listener = match bind_private(&path) {
            Ok(l) => l,
            Err(e) => {
                if let Err(closing) = self
                    .store
                    .close_bootstrap_grant(
                        run,
                        id,
                        GrantEnd::Expired,
                        "GRANT_FAILED".into(),
                        tr!(
                            "Could not open the direct connection channel",
                            "無法建立直連通道",
                            "直接接続のチャネルを開けませんでした"
                        ),
                    )
                    .await
                {
                    tracing::warn!(error = %closing, "failed bootstrap grant not closed on record");
                }
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    tr!(
                        "Could not open the direct connection channel: {e}",
                        "無法建立直連通道：{e}",
                        "直接接続のチャネルを開けませんでした：{e}"
                    ),
                ));
            }
        };
        let cancel = CancellationToken::new();
        tokio::spawn(accept_loop(
            listener,
            cancel.clone(),
            self.policy.clone(),
            path.clone(),
        ));
        // Expiry closes every stream and records the end; a grant revoked earlier ends here too.
        let expiry = cancel.clone();
        let store = self.store.clone();
        let (r, g, ttl) = (run.clone(), id.clone(), self.ttl);
        tokio::spawn(async move {
            let expired = tokio::select! {
                () = expiry.cancelled() => false,
                () = tokio::time::sleep(ttl) => true,
            };
            expiry.cancel();
            if expired
                && let Err(e) = store
                    .close_bootstrap_grant(
                        r,
                        g,
                        GrantEnd::Expired,
                        "GRANT_EXPIRED".into(),
                        tr!(
                            "The direct connection grant expired (10 minutes)",
                            "直連授權已到期（10 分鐘）",
                            "直接接続の許可が期限切れになりました（10 分）"
                        ),
                    )
                    .await
            {
                tracing::warn!(error = %e, "expiry of the provider bootstrap grant not recorded");
            }
        });
        tracing::info!(?kind, "provider bootstrap grant opened");
        let out = ActiveGrant {
            connector: path.display().to_string(),
            expires_at,
            run: run.clone(),
            kind,
        };
        *self.grant.lock() = Some(Grant {
            path,
            expires_at,
            cancel,
            run,
            id,
            kind,
        });
        Ok(out)
    }

    /// Close the grant now (every stream on it is cut). Memory only: returns the run and grant
    /// it belonged to, for the caller to record.
    pub fn revoke(&self) -> Option<(String, String)> {
        let g = self.grant.lock().take()?;
        tracing::info!(kind = ?g.kind, "provider bootstrap grant closed");
        Some((g.run.clone(), g.id.clone()))
    }

    /// Close the grant of `run` (if it holds the open one) and record it ended with `end`.
    pub(crate) async fn close(
        &self,
        run: &str,
        end: GrantEnd,
        code: &str,
        reason: impl Into<Text>,
    ) -> Result<(), ApiError> {
        let closed = {
            let mut slot = self.grant.lock();
            if slot.as_ref().is_some_and(|g| g.run == run) {
                slot.take()
            } else {
                None
            }
        };
        let Some(g) = closed else {
            return Ok(());
        };
        tracing::info!(kind = ?g.kind, "provider bootstrap grant closed");
        let (run, id) = (g.run.clone(), g.id.clone());
        drop(g);
        self.store
            .close_bootstrap_grant(run, id, end, code.into(), reason.into())
            .await
            .map_err(api)?;
        Ok(())
    }

    /// `DELETE /v1/provider-egress/bootstrap`: end the first setup's grant now. A connection it
    /// built keeps waiting to become the egress (it needs no direct access).
    ///
    /// # Errors
    ///
    /// `InvalidState` when the open grant is a rebootstrap; a Store error recording the end.
    pub async fn end_initial(&self) -> Result<(), ApiError> {
        let _d = self.decide().await;
        let Some(open) = self.active() else {
            return Ok(());
        };
        if open.kind != BootstrapKind::Initial {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                tr!(
                    "The open grant is a direct reconnection; use “Cancel the direct reconnection”",
                    "開放中的是重新直連；請用「取消重新直連」",
                    "開いているのは再度の直接接続です。「再度の直接接続をキャンセル」を使ってください"
                ),
            ));
        }
        self.close(
            &open.run,
            GrantEnd::Cancelled,
            "GRANT_ENDED",
            tr!(
                "The direct connection was ended",
                "已結束直連",
                "直接接続を終了しました"
            ),
        )
        .await
    }

    // --- The seal, step by step (the manager runs all three; tests stop between them) -------

    /// Step 1: the durable intent. From here on no crash reopens direct access.
    pub(crate) async fn seal_intent(
        &self,
        run: &str,
        child: InstanceId,
    ) -> Result<BootstrapRow, ApiError> {
        self.store
            .seal_bootstrap_intent(run.to_string(), child)
            .await
            .map_err(api)
    }

    /// Close the grant here if `run` holds it (memory only; the caller records the end).
    pub(crate) fn close_run(&self, run: &str) -> bool {
        let closed = {
            let mut slot = self.grant.lock();
            if slot.as_ref().is_some_and(|g| g.run == run) {
                slot.take()
            } else {
                None
            }
        };
        closed.is_some_and(|g| {
            tracing::info!(kind = ?g.kind, "provider bootstrap grant closed");
            true
        })
    }

    /// Close `grant` here if it is still the open one — not a grant opened since, for the same run
    /// or another (memory only; the caller records the end).
    pub(crate) fn close_grant(&self, grant: &ActiveGrant) -> bool {
        let closed = {
            let mut slot = self.grant.lock();
            if slot
                .as_ref()
                .is_some_and(|g| g.run == grant.run && g.path == Path::new(&grant.connector))
            {
                slot.take()
            } else {
                None
            }
        };
        closed.is_some_and(|g| {
            tracing::info!(kind = ?g.kind, "provider bootstrap grant closed");
            true
        })
    }

    /// Step 2: close the run's grant here (every direct stream is cut). Returns when: the
    /// evidence the commit records.
    pub(crate) fn seal_revoke(&self, run: &str) -> Timestamp {
        self.close_run(run);
        Timestamp::now()
    }

    /// Step 3: the latch, the binding and the end of the run, in one Store transaction.
    pub(crate) async fn seal_commit(
        &self,
        run: &str,
        revoked_at: Timestamp,
    ) -> Result<(ProviderEgress, BootstrapRow), ApiError> {
        self.store
            .seal_bootstrap_commit(run.to_string(), revoked_at)
            .await
            .map_err(api)
    }
}

fn bind_private(path: &Path) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

async fn accept_loop(
    listener: UnixListener,
    cancel: CancellationToken,
    policy: Policy,
    path: PathBuf,
) {
    let slots = Arc::new(Semaphore::new(MAX_STREAMS));
    // One admission per grant: its own nonces and connector epoch.
    let admission = Arc::new(Admission::new(RelayRoute::Bootstrap));
    let me = vpn_platform::process::current_uid();
    loop {
        let accepted = tokio::select! {
            () = cancel.cancelled() => break,
            r = listener.accept() => r,
        };
        let Ok((stream, _)) = accepted else { continue };
        if !stream.peer_cred().is_ok_and(|c| c.uid() == me) {
            continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            let busy = tr!(
                "Too many connections at once",
                "同時連線過多",
                "同時接続が多すぎます"
            );
            tokio::spawn(answer(stream, refuse("BUSY", busy)));
            continue;
        };
        let (cancel, policy, admission) = (cancel.clone(), policy.clone(), admission.clone());
        tokio::spawn(async move {
            tokio::select! {
                () = cancel.cancelled() => {}
                () = serve(stream, &policy, &admission) => {}
            }
            drop(permit);
        });
    }
    remove_file_if_present(&path);
}

/// Best effort: a client that left gets nothing.
async fn answer(mut stream: UnixStream, reply: Reply) {
    if let Err(e) = stream.write_all(&reply.to_bytes()).await {
        tracing::trace!(error = %e, "bootstrap client not answered");
    }
}

async fn serve(stream: UnixStream, policy: &Policy, admission: &Admission) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let read = tokio::time::timeout(
        REQUEST_TIMEOUT,
        (&mut reader).take(LINE_MAX as u64).read_line(&mut line),
    )
    .await;
    let mut stream = reader.into_inner();
    let epochs = admission.epochs(NETWORK_EPOCH);
    if !matches!(read, Ok(Ok(n)) if n > 0 && line.ends_with('\n')) {
        return answer(
            stream,
            refuse(
                "BAD_REQUEST",
                tr!(
                    "The request is malformed",
                    "請求格式錯誤",
                    "リクエストの形式が正しくありません"
                ),
            )
            .with_epochs(epochs),
        )
        .await;
    }
    let request = match admission.admit(line.trim_end(), NETWORK_EPOCH) {
        Ok(r) => r,
        Err(reply) => return answer(stream, reply).await,
    };
    let host = request.host.to_ascii_lowercase();
    if !policy
        .allow
        .iter()
        .any(|(h, p)| *h == host && *p == request.port)
    {
        return answer(
            stream,
            refuse(
                "DENIED",
                tr!(
                    "This destination is not on the list of providers the first direct connection may reach",
                    "這個目的地不在首次直連允許的供應商清單",
                    "この宛先は、初回の直接接続で許可されたプロバイダーの一覧にありません"
                ),
            )
            .with_epochs(epochs),
        )
        .await;
    }
    let upstream = match tokio::time::timeout(
        CONNECT_BUDGET,
        dial(&host, request.port, request.family, policy),
    )
    .await
    {
        Ok(Ok(u)) => u,
        Ok(Err(reply)) => return answer(stream, reply.with_epochs(epochs)).await,
        Err(_) => {
            let timed_out = tr!(
                "The direct connection timed out",
                "直連逾時",
                "直接接続がタイムアウトしました"
            );
            return answer(stream, refuse("TIMED_OUT", timed_out).with_epochs(epochs)).await;
        }
    };
    let (mut tcp, peer) = upstream;
    let ok = Reply::connected(peer, epochs);
    if stream.write_all(&ok.to_bytes()).await.is_err() {
        return;
    }
    // The relay ends when either side closes (or breaks) its connection.
    if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await {
        tracing::debug!(error = %e, "direct connection relay ended with an error");
    }
}

/// Resolve with the host's resolver (only allowlisted names reach here), keep the requested
/// family only, and connect to the first address that answers.
async fn dial(
    host: &str,
    port: u16,
    family: Fam,
    policy: &Policy,
) -> Result<(TcpStream, SocketAddr), Reply> {
    let want_v4 = family == Fam::V4;
    let candidates: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) if ip.is_ipv4() == want_v4 => vec![ip],
        Ok(_) => {
            return Err(refuse(
                "FAMILY_MISMATCH",
                tr!(
                    "The address does not match the requested IP version",
                    "位址與要求的 IP 版本不符",
                    "アドレスが要求された IP バージョンと一致しません"
                ),
            ));
        }
        Err(_) => match tokio::net::lookup_host((host, port)).await {
            Ok(found) => found
                .map(|a| a.ip().to_canonical())
                .filter(|ip| ip.is_ipv4() == want_v4)
                .collect(),
            Err(e) => {
                return Err(refuse(
                    "RESOLVE",
                    tr!(
                        "Cannot resolve the name: {e}",
                        "無法解析名稱：{e}",
                        "名前解決できません：{e}"
                    ),
                ));
            }
        },
    };
    let candidates: Vec<IpAddr> = candidates
        .into_iter()
        // A resolver answer pointing into the LAN is never followed.
        .filter(|ip| !policy.public_only || !(is_special(*ip) || is_private(*ip)))
        .take(MAX_ATTEMPTS)
        .collect();
    if candidates.is_empty() {
        return Err(refuse(
            "RESOLVE",
            tr!(
                "The name has no public address of this IP version",
                "名稱沒有這個 IP 版本的公開位址",
                "この名前には、この IP バージョンの公開アドレスがありません"
            ),
        ));
    }
    let mut last = refuse(
        "CONNECT",
        tr!("Cannot connect", "無法連線", "接続できません"),
    );
    for ip in candidates {
        let dst = SocketAddr::new(ip, port);
        match TcpStream::connect(dst).await {
            Ok(s) => {
                // Only latency: the connection works without it.
                if let Err(e) = s.set_nodelay(true) {
                    tracing::debug!(error = %e, "TCP_NODELAY not set on a direct connection");
                }
                return Ok((s, dst));
            }
            Err(e) => {
                let kind = e.kind();
                last = refuse(
                    "CONNECT",
                    tr!(
                        "Cannot connect: {kind}",
                        "無法連線：{kind}",
                        "接続できません：{kind}"
                    ),
                );
            }
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::str::FromStr;

    use tokio::net::TcpListener;
    use vpn_store::ChildClaim;

    use super::*;
    use vpn_domain::{
        BootstrapStage, EgressMode, EntityMeta, InstanceLimits, InstancePurpose, InstanceSpec,
        InterfaceSpec, PeerSpec, ProfileId, ProfileSource, ProviderAccount, ProviderAccountId,
        ProviderKind, RuntimeProfile, WgKey,
    };

    fn master() -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new([5u8; 32])
    }

    fn open_store() -> (tempfile::TempDir, Arc<Store>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &master(), 1).unwrap();
        (dir, Arc::new(store))
    }

    fn reopen(dir: &Path) -> Arc<Store> {
        Arc::new(Store::open(dir, &master(), 1).unwrap())
    }

    /// `b` goes (its grant and relay socket with it) and every task it started lets go of the
    /// Store: `store` is the last holder afterwards.
    async fn release(b: Bootstrap, store: &Arc<Store>) {
        drop(b);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while Arc::strong_count(store) > 1 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the Store is still held"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The process ends: nothing of it holds the Store when the next "process" opens it.
    async fn process_ends(b: Bootstrap, store: Arc<Store>) {
        release(b, &store).await;
        drop(store);
    }

    /// A version-2 line for the bootstrap grant, with a fresh nonce.
    fn line(host: &str, port: u16, family: Fam) -> String {
        let l = vpn_ipc::relay::RelayLine::new(host, port, family, RelayRoute::Bootstrap);
        String::from_utf8(l.to_bytes()).unwrap()
    }

    async fn request(path: &str, line: &str) -> (String, UnixStream) {
        let mut s = UnixStream::connect(path).await.unwrap();
        s.write_all(line.as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        let mut byte = [0u8; 1];
        while s.read_exact(&mut byte).await.is_ok() && byte[0] != b'\n' {
            reply.push(byte[0]);
        }
        (String::from_utf8(reply).unwrap(), s)
    }

    fn meta() -> EntityMeta {
        EntityMeta {
            revision: 1,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        }
    }

    async fn profile(store: &Store) -> RuntimeProfile {
        let key = store
            .put_secret(
                "wireguard_private_key".into(),
                None,
                zeroize::Zeroizing::new(vec![1; 32]),
                None,
            )
            .await
            .unwrap();
        let wg = WgKey::from_str("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=").unwrap();
        store
            .create(RuntimeProfile {
                id: ProfileId::new(),
                meta: meta(),
                name: "lab".into(),
                provider: ProviderKind::Mullvad,
                source: ProfileSource::Imported,
                interface: InterfaceSpec {
                    private_key: key.secret_ref,
                    public_key: wg,
                    addresses: vec!["10.99.0.2/32".parse().unwrap()],
                    dns: vec!["10.64.0.1".parse().unwrap()],
                    mtu: 1420,
                },
                peer: PeerSpec {
                    public_key: wg,
                    preshared_key: None,
                    endpoint: "198.51.100.7:51820".parse().unwrap(),
                    allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                    persistent_keepalive: None,
                },
                location: None,
                expires_at: None,
            })
            .await
            .unwrap()
    }

    fn spec(profile_id: ProfileId) -> InstanceSpec {
        InstanceSpec {
            id: InstanceId::new(),
            meta: meta(),
            name: "new egress".into(),
            profile_id,
            dns_profile_id: None,
            security_profile_id: None,
            purpose: InstancePurpose::General,
            limits: InstanceLimits::default(),
            strict: false,
            transport: vpn_domain::TransportRef::default(),
        }
    }

    /// The run's one connection, built as the manager does for a connect request.
    async fn child(store: &Store) -> InstanceId {
        let op = OperationId::new();
        let ChildClaim::Reserved(run) = store.claim_bootstrap_child(op).await.unwrap() else {
            panic!("no reservation");
        };
        let p = profile(store).await;
        let (i, _, _) = store
            .create_bootstrap_child(
                run.id,
                op,
                spec(p.id),
                None,
                Timestamp::now().plus(PROMOTE_WAIT),
            )
            .await
            .unwrap();
        i.id
    }

    #[tokio::test]
    async fn a_nonce_is_good_once_and_only_lines_for_the_grant_pass() {
        let (dir, store) = open_store();
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let _held = s;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                });
            }
        });
        let b = Bootstrap::with_policy(
            dir.path().to_path_buf(),
            store,
            vec![("127.0.0.1".into(), port)],
            false,
        );
        let path = b.grant(None).await.unwrap().connector;
        let once = line("127.0.0.1", port, Fam::V4);
        let (reply, _s) = request(&path, &once).await;
        assert!(reply.contains("\"ok\":true"), "{reply}");
        assert!(reply.contains("\"epochs\""), "{reply}");
        let (reply, _) = request(&path, &once).await;
        assert!(reply.contains("NONCE_REUSED"), "{reply}");
        // A line meant for an Instance connector reaches nothing here.
        let other = vpn_ipc::relay::RelayLine::new(
            "127.0.0.1",
            port,
            Fam::V4,
            RelayRoute::Instance {
                instance_id: InstanceId::new(),
                generation: 1,
            },
        );
        let (reply, _) = request(&path, &String::from_utf8(other.to_bytes()).unwrap()).await;
        assert!(reply.contains("WRONG_ROUTE"), "{reply}");
        // The old line without nonce and route is refused.
        let v1 = format!("{{\"v\":1,\"host\":\"127.0.0.1\",\"port\":{port},\"family\":\"v4\"}}\n");
        let (reply, _) = request(&path, &v1).await;
        assert!(reply.contains("BAD_VERSION"), "{reply}");
    }

    #[tokio::test]
    async fn relays_only_allowlisted_destinations_of_the_requested_family() {
        let (dir, store) = open_store();
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });
        let b = Bootstrap::with_policy(
            dir.path().to_path_buf(),
            store,
            vec![("127.0.0.1".into(), port)],
            false,
        );
        let open = b.grant(None).await.unwrap();
        // Idempotent while open.
        assert_eq!(b.grant(None).await.unwrap(), open);
        let path = open.connector;

        let (reply, _) = request(&path, &line("127.0.0.2", port, Fam::V4)).await;
        assert!(reply.contains("DENIED"), "{reply}");
        let (reply, _) = request(&path, &line("127.0.0.1", port, Fam::V6)).await;
        assert!(reply.contains("FAMILY_MISMATCH"), "{reply}");
        let (reply, mut s) = request(&path, &line("127.0.0.1", port, Fam::V4)).await;
        assert!(reply.contains("\"ok\":true"), "{reply}");
        s.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
    }

    #[tokio::test]
    async fn revoking_cuts_open_streams_and_removes_the_socket() {
        let (dir, store) = open_store();
        let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = held.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Accept and keep the connection open.
            let (_s, _) = held.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let b = Bootstrap::with_policy(
            dir.path().to_path_buf(),
            store.clone(),
            vec![("127.0.0.1".into(), port)],
            false,
        );
        let path = b.grant(None).await.unwrap().connector;
        let (reply, mut s) = request(&path, &line("127.0.0.1", port, Fam::V4)).await;
        assert!(reply.contains("\"ok\":true"), "{reply}");
        b.end_initial().await.unwrap();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("the stream is cut");
        assert_matches!(n, Ok(0) | Err(_));
        assert!(!Path::new(&path).exists());
        assert!(b.active().is_none());
        // Recorded: the run ended with its grant.
        let run = store.latest_bootstrap().await.unwrap().unwrap();
        assert_eq!(run.stage, BootstrapStage::Cancelled);
        assert_eq!(run.grant_id, None);
    }

    #[tokio::test]
    async fn no_grant_once_used_up_or_when_an_egress_is_chosen() {
        let (dir, store) = open_store();
        let b = Bootstrap::new(dir.path().to_path_buf(), store.clone());
        b.grant(None).await.unwrap();
        let i = child(&store).await;
        let run = store.latest_bootstrap().await.unwrap().unwrap();
        b.seal_intent(&run.id, i).await.unwrap();
        let at = b.seal_revoke(&run.id);
        let (used, sealed) = b.seal_commit(&run.id, at).await.unwrap();
        assert!(used.bootstrap_consumed);
        assert_eq!(used.selected_instance_id, Some(i));
        assert_eq!(sealed.stage, BootstrapStage::Sealed);
        assert!(b.active().is_none(), "sealing closes the grant");
        let e = b.grant(None).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::BootstrapAlreadyConsumed);

        let (dir, store) = open_store();
        let b = Bootstrap::new(dir.path().to_path_buf(), store.clone());
        store
            .put_provider_egress(EgressMode::Disabled, None, 1)
            .await
            .unwrap();
        assert!(b.grant(None).await.is_err());
    }

    /// AC-73: once the bootstrap is used, nothing gives direct access back by itself: neither
    /// deleting the egress Instance (after switching away from it) or the provider account, nor
    /// writing the database behind the manager's back.
    #[tokio::test]
    async fn after_the_latch_nothing_restores_direct_access() {
        let (dir, store) = open_store();
        let b = Bootstrap::new(dir.path().to_path_buf(), store.clone());
        b.grant(None).await.unwrap();
        let i = child(&store).await;
        let run = store.latest_bootstrap().await.unwrap().unwrap();
        b.seal_intent(&run.id, i).await.unwrap();
        let at = b.seal_revoke(&run.id);
        b.seal_commit(&run.id, at).await.unwrap();
        let credential = store
            .put_secret(
                "provider_credential".into(),
                None,
                zeroize::Zeroizing::new(b"SYNTHETIC".to_vec()),
                None,
            )
            .await
            .unwrap();
        let account = store
            .create(ProviderAccount {
                id: ProviderAccountId::new(),
                meta: meta(),
                provider: ProviderKind::Mullvad,
                label: "main".into(),
                credential_ref: credential.secret_ref,
                expires_at: None,
                observed_at: None,
            })
            .await
            .unwrap();
        let used = |e: ApiError| assert_eq!(e.code, ErrorCode::BootstrapAlreadyConsumed, "{e:?}");
        // Switch away (no egress chosen), stop and delete the Instance, delete the account.
        let e = store.provider_egress().await.unwrap();
        store
            .put_provider_egress(EgressMode::ViaInstance, None, e.revision)
            .await
            .unwrap();
        used(b.grant(None).await.unwrap_err());
        store
            .change_intent(i, vpn_store::IntentChange::Stop)
            .await
            .unwrap();
        store.delete_instance(i, 1).await.unwrap();
        used(b.grant(None).await.unwrap_err());
        store
            .delete::<ProviderAccount>(account.id.to_string(), 1)
            .await
            .unwrap();
        used(b.grant(None).await.unwrap_err());
        // Behind the manager's back: the latch does not go back, the singleton is not deleted.
        {
            let c = rusqlite::Connection::open(dir.path().join("control.sqlite")).unwrap();
            assert!(
                c.execute("UPDATE provider_egress SET bootstrap_consumed = 0", [])
                    .is_err()
            );
            assert!(c.execute("DELETE FROM provider_egress", []).is_err());
        }
    }

    /// Where a seal can be interrupted (the process dies right after this point).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Crash {
        /// The exit check passed; nothing of the seal is written.
        BeforeIntent,
        AfterIntent,
        /// The grant is closed; the Store commit has not run.
        AfterRevoke,
        AfterCommit,
    }

    /// AC-72: a crash at every point of the seal, for the first setup and for a rebootstrap.
    /// Every interrupted state ends with no direct access after the restart, and once the intent
    /// exists, never with direct access again: the next start commits the seal forward.
    #[tokio::test]
    async fn a_crash_at_any_point_of_the_seal_never_reopens_direct_access() {
        for kind in [BootstrapKind::Initial, BootstrapKind::Rebootstrap] {
            for crash in [
                Crash::BeforeIntent,
                Crash::AfterIntent,
                Crash::AfterRevoke,
                Crash::AfterCommit,
            ] {
                let what = format!("{kind:?} / {crash:?}");
                let (dir, store) = open_store();
                let b = Bootstrap::new(dir.path().to_path_buf(), store.clone());
                if kind == BootstrapKind::Rebootstrap {
                    // An earlier egress, now dead; the first setup used up long ago.
                    let p = profile(&store).await;
                    let dead = store.create_instance(spec(p.id)).await.unwrap();
                    store.consume_bootstrap().await.unwrap();
                    let e = store.provider_egress().await.unwrap();
                    let e = store
                        .put_provider_egress(EgressMode::ViaInstance, Some(dead.id), e.revision)
                        .await
                        .unwrap();
                    let _d = b.decide().await;
                    b.open_rebootstrap(e.revision, None).await.unwrap();
                } else {
                    b.grant(None).await.unwrap();
                }
                let open = b.active().unwrap();
                let i = child(&store).await;
                let run = store.latest_bootstrap().await.unwrap().unwrap();
                if crash >= Crash::AfterIntent {
                    b.seal_intent(&run.id, i).await.unwrap();
                }
                if crash >= Crash::AfterRevoke {
                    let at = b.seal_revoke(&run.id);
                    assert!(b.active().is_none(), "{what}: revoked");
                    if crash >= Crash::AfterCommit {
                        b.seal_commit(&run.id, at).await.unwrap();
                    }
                }
                // The process dies: its grant and relay socket go with it.
                process_ends(b, store).await;
                assert!(
                    UnixStream::connect(&open.connector).await.is_err(),
                    "{what}: the relay socket outlived the process"
                );

                let store = reopen(dir.path());
                let b = Bootstrap::new(dir.path().to_path_buf(), store.clone());
                b.recover().await.unwrap();
                assert!(
                    b.active().is_none(),
                    "{what}: direct access after the restart"
                );
                let run = store.bootstrap_run(run.id.clone()).await.unwrap().unwrap();
                assert_eq!(run.grant_id, None, "{what}");
                let egress = store.provider_egress().await.unwrap();
                if crash == Crash::BeforeIntent {
                    // Nothing was sealed: the connection still waits (no direct access); for
                    // the first setup only the user may reopen, and it keeps the connection.
                    assert_eq!(run.stage, BootstrapStage::InstanceRequested, "{what}");
                    assert_eq!(run.child_instance_id, Some(i), "{what}");
                    assert_eq!(
                        egress.bootstrap_consumed,
                        kind == BootstrapKind::Rebootstrap
                    );
                } else {
                    assert_eq!(run.stage, BootstrapStage::Sealed, "{what}");
                    assert!(egress.bootstrap_consumed, "{what}");
                    assert_eq!(egress.selected_instance_id, Some(i), "{what}");
                    assert_eq!(egress.desired_mode, EgressMode::ViaInstance, "{what}");
                    assert_eq!(
                        run.reason_code.is_some(),
                        crash < Crash::AfterCommit,
                        "{what}: a seal finished at start says so"
                    );
                    let e = b.grant(None).await.unwrap_err();
                    assert_matches!(
                        e.code,
                        ErrorCode::BootstrapAlreadyConsumed | ErrorCode::InvalidState,
                        "{what}: {e:?}"
                    );
                    assert!(b.active().is_none(), "{what}");
                }
                // The run's connection is the only one: no second connection was made.
                let all: Vec<InstanceSpec> = store.list().await.unwrap();
                assert_eq!(all.iter().filter(|s| s.id == i).count(), 1, "{what}");
            }
        }
    }

    /// AC-84: a rebootstrap grant ends when the user cancels it, when it expires, and with the
    /// process — and the latch stays set throughout.
    #[tokio::test]
    async fn a_rebootstrap_grant_is_revoked_by_cancel_expiry_and_crash() {
        async fn open(boot: &Bootstrap) -> ActiveGrant {
            let egress = boot.store.provider_egress().await.unwrap();
            let _d = boot.decide().await;
            boot.open_rebootstrap(egress.revision, None).await.unwrap()
        }
        let (dir, store) = open_store();
        let prof = profile(&store).await;
        let dead = store.create_instance(spec(prof.id)).await.unwrap();
        store.consume_bootstrap().await.unwrap();
        let egress = store.provider_egress().await.unwrap();
        store
            .put_provider_egress(EgressMode::ViaInstance, Some(dead.id), egress.revision)
            .await
            .unwrap();
        // Cancel.
        let boot = Bootstrap::new(dir.path().to_path_buf(), store.clone());
        let grant = open(&boot).await;
        assert!(store.provider_egress().await.unwrap().bootstrap_consumed);
        boot.close(&grant.run, GrantEnd::Cancelled, "CANCELLED", "取消")
            .await
            .unwrap();
        assert!(boot.active().is_none());
        assert!(UnixStream::connect(&grant.connector).await.is_err());
        let row = store
            .bootstrap_run(grant.run.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.stage, BootstrapStage::Cancelled);
        assert!(store.provider_egress().await.unwrap().bootstrap_consumed);

        // Expiry (a short grant for the test).
        release(boot, &store).await;
        let mut boot = Bootstrap::new(dir.path().to_path_buf(), store.clone());
        boot.ttl = Duration::from_millis(200);
        let grant = open(&boot).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let row = store
                .bootstrap_run(grant.run.clone())
                .await
                .unwrap()
                .unwrap();
            if row.stage == BootstrapStage::Expired {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "never expired");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(boot.active().is_none());
        assert!(UnixStream::connect(&grant.connector).await.is_err());
        assert!(store.provider_egress().await.unwrap().bootstrap_consumed);

        // Crash.
        release(boot, &store).await;
        let boot = Bootstrap::new(dir.path().to_path_buf(), store.clone());
        let grant = open(&boot).await;
        process_ends(boot, store).await;
        let store = reopen(dir.path());
        let boot = Bootstrap::new(dir.path().to_path_buf(), store.clone());
        boot.recover().await.unwrap();
        assert!(boot.active().is_none());
        let row = store
            .bootstrap_run(grant.run.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.stage, BootstrapStage::Expired);
        assert_eq!(row.reason_code.as_deref(), Some("MANAGER_RESTARTED"));
        assert!(store.provider_egress().await.unwrap().bootstrap_consumed);
        assert!(UnixStream::connect(&grant.connector).await.is_err());
    }
}
