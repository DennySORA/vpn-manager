//! Controller <-> manager protocol over `manager.sock` (same-UID peers only).
//!
//! The controller holds no durable truth: every persistent read/write (the "Store helper") and
//! every lifecycle intent goes through these closed, typed calls. Calls are multiplexed by id on
//! one connection; a second connection may `Subscribe` to events.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use vpn_domain::{
    ApiError, AppAction, AppId, AppLog, AppProcesses, AppSpec, AppStatus, Ban, BanId, Blocklist,
    BlocklistId, BlocklistView, BootstrapKind, BootstrapRun, BuiltinBlocklistState, Capability,
    DnsProfile, EgressMode, EgressRecovery, ErrorCode, ExecutableCheck, ForwardBinding,
    ForwardBindingId, ForwardStatus, GatewayId, GatewaySpec, InstallationId, InstanceId,
    InstanceSpec, InstanceStatus, ManagerReport, MetricsRange, MetricsScope, MetricsSeries,
    MetricsStatus, Operation, OperationId, OperationStatus, PerformanceOverview, PerformanceScope,
    PerformanceSeriesSet, ProfileId, ProviderAccount, ProviderEgress, ReconcileResult,
    RecoveryReport, RuntimeProfile, SecretRef, SecurityProfile, Settings, SshDownloadStatus,
    SshHost, SshStatus, Text, Timestamp, TransportProfile, UnbanResult, WgKey, tr,
};
use vpn_sync::Mutex;

use vpn_domain::ipset::IpRangeSet;

use crate::frame::split;
use crate::identity;
use crate::secret::SecretBytes;
use crate::worker::WorkerStatus;

pub const CONTROL_PROTOCOL: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityKind {
    Profile,
    Dns,
    Security,
    Transport,
    Instance,
    Gateway,
    App,
    Forward,
    SshHost,
    ProviderAccount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Entity {
    Profile(RuntimeProfile),
    Dns(DnsProfile),
    Security(SecurityProfile),
    Transport(TransportProfile),
    Instance(InstanceSpec),
    Gateway(GatewaySpec),
    App(AppSpec),
    Forward(ForwardBinding),
    SshHost(SshHost),
    ProviderAccount(ProviderAccount),
}

impl Entity {
    #[must_use]
    pub const fn kind(&self) -> EntityKind {
        match self {
            Self::Profile(_) => EntityKind::Profile,
            Self::Dns(_) => EntityKind::Dns,
            Self::Security(_) => EntityKind::Security,
            Self::Transport(_) => EntityKind::Transport,
            Self::Instance(_) => EntityKind::Instance,
            Self::Gateway(_) => EntityKind::Gateway,
            Self::App(_) => EntityKind::App,
            Self::Forward(_) => EntityKind::Forward,
            Self::SshHost(_) => EntityKind::SshHost,
            Self::ProviderAccount(_) => EntityKind::ProviderAccount,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lifecycle {
    Start,
    Stop,
    Emergency,
    ClearEmergency,
    Restart,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetaWire {
    pub secret_ref: SecretRef,
    pub kind: String,
    pub label: Option<String>,
    pub public_fingerprint: Option<String>,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub installation_id: InstallationId,
    pub manager_build: String,
    pub sqlite_version: String,
    pub capabilities: Vec<Capability>,
    pub logical_cpus: u32,
    pub manager_rss_bytes: Option<u64>,
    pub manager_cpu_ns: u64,
    /// Whether metric samples are being stored (absent from a manager of an older build).
    #[serde(default)]
    pub metrics_recording: Option<vpn_domain::MetricsRecording>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Call {
    System,
    List(EntityKind),
    Get(EntityKind, String),
    Create(Entity),
    Update {
        entity: Entity,
        expected_revision: u64,
    },
    Delete {
        kind: EntityKind,
        id: String,
        expected_revision: u64,
    },
    /// Delete a stopped Instance and exactly these Gateways of it, all or nothing.
    DeleteInstance {
        id: InstanceId,
        expected_revision: u64,
        gateways: Vec<GatewayId>,
    },
    InstanceStatus(InstanceId),
    InstanceStatuses,
    Lifecycle(InstanceId, Lifecycle),
    BeginOperation {
        kind: String,
        target_id: Option<String>,
        idempotency_key: Option<String>,
        fingerprint: Option<String>,
    },
    FinishOperation {
        id: OperationId,
        status: OperationStatus,
        error: Option<ApiError>,
        result_refs: Vec<String>,
    },
    Operation(OperationId),
    OperationByKey(String),
    /// The newest operations, newest first (at most `limit`, capped by the manager).
    Operations {
        limit: u32,
    },
    PutSecret {
        kind: String,
        label: Option<String>,
        plaintext: SecretBytes,
        public_fingerprint: Option<String>,
    },
    /// Generate a `WireGuard` key pair inside the manager; only the public key leaves.
    GenerateKey {
        label: Option<String>,
    },
    Secrets,
    DeleteSecret(SecretRef),
    /// Short-lived plaintext lease for a Provider job (the caller zeroizes after use).
    LeaseSecret(SecretRef),
    KeyedFingerprint(Vec<u8>),
    /// The private connector of an Instance's current generation (Provider egress).
    ProviderRoute(InstanceId),
    /// The global Provider egress binding, the open bootstrap grant if any, the run of the
    /// direct exception, and whether the selected egress needs recovery.
    ProviderEgress,
    /// The same without the recovery assessment (what a route needs, read per provider request).
    ProviderBinding,
    /// Change the binding (compare-and-set). Choosing an Instance closes any bootstrap grant.
    PutProviderEgress {
        desired_mode: EgressMode,
        selected_instance_id: Option<InstanceId>,
        expected_revision: u64,
    },
    /// Open the one-time direct bootstrap of the first setup (or return the open grant).
    /// `operation`: the request opening it, recorded with the run.
    BootstrapGrant {
        operation: Option<OperationId>,
    },
    /// Close the first setup's grant now; every stream on it is cut. A connection it built keeps
    /// waiting to become the egress.
    BootstrapRevoke,
    /// Open a manual rebootstrap: a ten-minute direct grant for the recovery operations only.
    /// The manager checks eligibility (under the lock that decides all direct access) and the
    /// egress revision the user saw.
    Rebootstrap {
        expected_revision: u64,
        operation: Option<OperationId>,
    },
    /// Cancel the active rebootstrap: its grant closes and its connection (if built) is not
    /// promoted.
    RebootstrapCancel,
    /// The active run of the direct exception, else the latest (a Store read only).
    BootstrapLatest,
    /// Claim the active run's one connection for the connect request `operation`, before any
    /// provider request is made.
    BootstrapClaimChild {
        operation: OperationId,
    },
    /// The connect request gave up before building the run's connection.
    BootstrapReleaseChild {
        run: String,
        operation: OperationId,
    },
    /// The connect request is still building the run's connection: its reservation runs from
    /// now again (only while it still holds it with nothing built; a late renewal changes
    /// nothing).
    BootstrapRenewChild {
        run: String,
        operation: OperationId,
    },
    /// Create the run's connection: its Instance (intent `running`), its Gateway and the run's
    /// record of it, in one Store transaction; the actor starts it.
    BootstrapCreateChild {
        run: String,
        operation: OperationId,
        instance: InstanceSpec,
        gateway: Option<GatewaySpec>,
    },
    /// The run's connection exists: start it again and wait for it anew.
    BootstrapResumeChild {
        run: String,
    },
    /// The run's connection is ready with `generation` and its exit answered through it: write
    /// the seal intent, close direct access, then commit the latch and the binding.
    BootstrapSeal {
        run: String,
        instance: InstanceId,
        generation: u64,
    },
    /// The run's connection did not become the egress (deadline, failure, stop, exit check).
    BootstrapAbandon {
        run: String,
        reason_code: String,
        reason: Text,
    },
    /// SSH Manager: the files as they are now.
    SshStatus,
    /// Put the `Include` line first in `~/.ssh/config` (after a backup).
    SshInclude,
    /// Replace a hand-modified `vpn-manager.conf` with the generated one (after a backup).
    SshOverwrite,
    /// Write `vpn-manager.conf` now (unless it was modified by hand).
    SshApply,
    Settings,
    PutSettings {
        settings: Settings,
        expected_revision: u64,
    },
    /// Persisted metrics of a scope (every Instance, one Instance or one Gateway) over a fixed
    /// range ending now (the manager picks the point spacing).
    MetricsSeries {
        scope: MetricsScope,
        range: MetricsRange,
    },
    /// Retention, space, gaps and collector state of the persisted metrics.
    MetricsStatus,
    /// The first loopback port from `from` on that no Gateway uses and nothing holds right now
    /// (the manager test-binds it: it owns the listeners, the controller never binds).
    FreePort {
        from: u16,
    },
    /// Create a managed App; the manager approves its executable (`expected_sha256`: the digest
    /// the user saw, refused when the file now differs).
    CreateApp {
        spec: AppSpec,
        expected_sha256: Option<String>,
    },
    /// Update a managed App; a changed executable path is approved like on create, an unchanged
    /// one keeps its approval.
    UpdateApp {
        spec: AppSpec,
        expected_revision: u64,
        expected_sha256: Option<String>,
    },
    /// Delete a managed App that runs nothing.
    DeleteApp {
        id: AppId,
        expected_revision: u64,
    },
    AppStatus(AppId),
    AppStatuses,
    AppAction {
        id: AppId,
        action: AppAction,
        sha256: Option<String>,
    },
    AppProcesses(AppId),
    /// A port forward's status (its connection's actor answers).
    ForwardStatus(ForwardBindingId),
    /// Every port forward's status.
    ForwardStatuses,
    /// The newest `lines` lines of the App's own output.
    AppLog {
        id: AppId,
        lines: u32,
    },
    /// Whether a path can be approved as an App's executable, and what would run.
    CheckExecutable {
        path: String,
    },
    /// Every IP blocklist with its refresh state and users.
    Blocklists,
    Blocklist(BlocklistId),
    /// Create (`expected_revision: None`) or update a blocklist; `set` is its new content. Saving
    /// content that covers an address a connection using it needs is refused (`POLICY_CONFLICT`);
    /// running connections get the new overlay at once.
    PutBlocklist {
        list: Box<Blocklist>,
        expected_revision: Option<u64>,
        set: Option<IpRangeSet>,
    },
    DeleteBlocklist {
        id: BlocklistId,
        expected_revision: u64,
    },
    /// Record a refresh attempt of a URL blocklist (a failure marks it stale).
    BlocklistRefreshed {
        id: BlocklistId,
        ok: bool,
        message: Option<Text>,
    },
    /// The built-in catalogue: each entry's list, or when the user deleted it.
    BuiltinBlocklists,
    /// Create a built-in list the user deleted again (it waits for its first download).
    RestoreBuiltinBlocklist {
        key: String,
    },
    /// Active bans, of one Instance or of all.
    Bans(Option<InstanceId>),
    /// Lift a ban, on the running worker too.
    Unban(BanId),
    // --- System maintenance: diagnostics, recovery ------------------------------------------
    /// What the manager reports about itself for the diagnostics report.
    Diagnostics,
    /// Resources the manager owns and what a crash left behind (no side effects).
    RecoveryInspect,
    /// Clean what is verifiably ours and stale; with `only`, just those (confirmed) item ids.
    RecoveryReconcile {
        only: Option<Vec<String>>,
    },
    /// Performance Manager (`/v1/performance/*`).
    Performance(PerfCall),
    /// SSH download (`/v1/ssh-downloads*`).
    SshDownload(crate::ssh_download::SshDownloadCall),
}

/// An open bootstrap grant: the manager's relay socket, when it closes, and the run it belongs to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapGrantWire {
    pub connector: String,
    pub expires_at: Timestamp,
    pub run: String,
    pub kind: BootstrapKind,
}

/// The global Provider egress binding as the manager answers for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressWire {
    pub egress: ProviderEgress,
    /// The open grant, if any.
    pub bootstrap: Option<BootstrapGrantWire>,
    /// The active run of the direct exception, else the latest.
    pub run: Option<BootstrapRun>,
    /// Set while the selected egress does not work.
    pub recovery: Option<EgressRecovery>,
}

/// What a connect request gets from the active run of the direct exception.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChildClaimWire {
    /// An ordinary connection (no run builds one now).
    None,
    /// This request builds the run's one connection.
    Reserved { run: String },
    /// The run has its connection already: it is used again.
    Existing {
        run: String,
        instance: InstanceId,
        profile: Option<ProfileId>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Reply {
    Unit,
    System(Box<SystemInfo>),
    Entity(Box<Entity>),
    Entities(Vec<Entity>),
    Status(Box<InstanceStatus>),
    Statuses(Vec<InstanceStatus>),
    Stopped {
        sealed: bool,
        durable: bool,
    },
    Begin {
        operation: Operation,
        existing: bool,
    },
    Operation(Option<Operation>),
    Operations(Vec<Operation>),
    Secret(SecretMetaWire),
    GeneratedKey {
        secret: SecretMetaWire,
        public_key: WgKey,
    },
    Secrets(Vec<SecretMetaWire>),
    SecretBytes(SecretBytes),
    Fingerprint(String),
    Settings(Settings),
    SshStatus(Box<SshStatus>),
    SshAction {
        status: Box<SshStatus>,
        backup: Option<String>,
    },
    ProviderRoute {
        generation: u64,
        connector: String,
    },
    ProviderEgress(Box<EgressWire>),
    BootstrapClaim(ChildClaimWire),
    BootstrapRun(Option<Box<BootstrapRun>>),
    BootstrapChild {
        instance: Box<InstanceSpec>,
        gateway: Option<GatewaySpec>,
    },
    MetricsSeries(Box<MetricsSeries>),
    MetricsStatus(Box<MetricsStatus>),
    FreePort(u16),
    AppStatus(Box<AppStatus>),
    AppStatuses(Vec<AppStatus>),
    AppProcesses(Box<AppProcesses>),
    AppLog(Box<AppLog>),
    ForwardStatus(Box<ForwardStatus>),
    ForwardStatuses(Vec<ForwardStatus>),
    ExecutableCheck(Box<ExecutableCheck>),
    Blocklists(Vec<BlocklistView>),
    Blocklist(Box<BlocklistView>),
    BuiltinBlocklists(Vec<BuiltinBlocklistState>),
    Bans(Vec<Ban>),
    Unbanned(Box<UnbanResult>),
    Diagnostics(Box<ManagerReport>),
    Recovery(Box<RecoveryReport>),
    Reconciled(Box<ReconcileResult>),
    Performance(Box<PerfReply>),
    SshDownload(Box<crate::ssh_download::SshDownloadReply>),
}

/// Performance Manager calls: the passive analysis, which never generates traffic.
#[derive(Debug, Serialize, Deserialize)]
pub enum PerfCall {
    /// The passive analysis.
    Summary,
    /// A series set of one scope over a fixed range ending now.
    Series {
        scope: PerformanceScope,
        range: MetricsRange,
    },
}

// One reply per frame, built, serialized and dropped: boxing would only add allocations.
#[expect(
    clippy::large_enum_variant,
    reason = "a message is built, sent and dropped once; it is never stored in bulk, so boxing a variant saves nothing"
)]
#[derive(Debug, Serialize, Deserialize)]
pub enum PerfReply {
    Summary(PerformanceOverview),
    Series(PerformanceSeriesSet),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    Status(Box<InstanceStatus>),
    Sample {
        instance_id: InstanceId,
        generation: u64,
        sample: Box<WorkerStatus>,
    },
    AppStatus(Box<AppStatus>),
    ForwardStatus(Box<ForwardStatus>),
    /// An SSH download job's status (at most one per job and second).
    SshDownloadStatus(Box<SshDownloadStatus>),
}

// A wire message: built, framed and dropped; boxing `Call` would only add an allocation.
#[expect(
    clippy::large_enum_variant,
    reason = "a message is built, sent and dropped once; it is never stored in bulk, so boxing a variant saves nothing"
)]
#[derive(Debug, Serialize, Deserialize)]
pub enum ClientMsg {
    Hello { protocol: u32, build_id: String },
    Call { id: u64, call: Call },
    Subscribe,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ServerMsg {
    Hello {
        protocol: u32,
        build_id: String,
        installation_id: InstallationId,
    },
    Reply {
        id: u64,
        result: Result<Reply, ApiError>,
    },
    Event(Event),
}

/// The largest control frame: a blocklist's content (up to 200,000 IPv6 ranges, 6.4 MB, base64
/// inside JSON) rides on `PutBlocklist`. Everything else is far smaller.
pub const CONTROL_MAX_FRAME: usize = 12 * 1024 * 1024;

/// How long a call waits for its reply.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// A call waiting for its reply.
struct Waiter {
    reply: oneshot::Sender<Result<Reply, ApiError>>,
    /// Its frame went (at least partly) to the socket: from then on the manager may have run
    /// it, and a lost reply is an unknown outcome rather than "not executed".
    sent: bool,
}

#[derive(Default)]
struct Calls {
    waiting: HashMap<u64, Waiter>,
    /// The connection is gone: no new call may wait for a reply on it.
    closed: bool,
}

/// Shows how many calls wait, not their replies.
impl std::fmt::Debug for Calls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Calls")
            .field("waiting", &self.waiting.len())
            .field("closed", &self.closed)
            .finish()
    }
}

type Pending = Arc<Mutex<Calls>>;

/// Client used by the controller. Cheap to clone; reconnect by creating a new one.
#[derive(Debug, Clone)]
pub struct ControlClient {
    out: mpsc::Sender<ClientMsg>,
    pending: Pending,
    next: Arc<AtomicU64>,
    /// `true` once the connection is gone, in either direction.
    lost: watch::Receiver<bool>,
    /// Ends the connection when the caller gives up on it.
    shut: Arc<Notify>,
    pub installation_id: InstallationId,
    pub manager_build: String,
}

/// The call was never handed to the manager.
fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::Unavailable,
        tr!(
            "The core service (manager) is not connected",
            "核心服務（manager）未連線",
            "コアサービス（manager）に接続されていません"
        ),
    )
}

/// The call was sent but its reply was lost with the connection: it may have run.
fn outcome_unknown() -> ApiError {
    ApiError::new(
        ErrorCode::OutcomeUnknown,
        tr!(
            "The connection to the core service (manager) broke after the request was sent, so whether it ran is unknown; look up the operation, and do not resend it with a new Idempotency-Key",
            "請求送出後與核心服務（manager）的連線中斷，無法確認是否已執行；請查詢 operation，不要換新的 Idempotency-Key 重送",
            "リクエストの送信後にコアサービス（manager）との接続が切れたため、実行されたかどうか確認できません。operation を確認し、新しい Idempotency-Key で再送しないでください"
        ),
    )
}

async fn handshake(
    path: &Path,
) -> std::io::Result<(
    crate::FrameReader,
    crate::FrameWriter,
    InstallationId,
    String,
)> {
    let stream = UnixStream::connect(path).await?;
    let (mut rx, mut tx) = split(stream, CONTROL_MAX_FRAME);
    tx.send(
        &ClientMsg::Hello {
            protocol: CONTROL_PROTOCOL,
            build_id: identity::build_id().to_string(),
        },
        &[],
    )
    .await?;
    match tokio::time::timeout(Duration::from_secs(5), rx.recv::<ServerMsg>()).await {
        Ok(Ok(Some((
            ServerMsg::Hello {
                protocol,
                build_id,
                installation_id,
            },
            _,
        )))) if protocol == CONTROL_PROTOCOL => Ok((rx, tx, installation_id, build_id)),
        Ok(Ok(Some(_))) => Err(std::io::Error::other("unexpected manager reply")),
        Ok(Ok(None)) => Err(std::io::Error::other(
            "manager closed the connection (protocol or build mismatch)",
        )),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::other("manager did not answer")),
    }
}

impl ControlClient {
    /// Connect to the manager's control socket at `path` and complete the handshake.
    ///
    /// # Errors
    ///
    /// The connect or handshake I/O error; a manager that answers anything but a matching
    /// `Hello`, closes the connection (protocol or build mismatch) or does not answer in 5 s.
    pub async fn connect(path: &Path) -> std::io::Result<Self> {
        let (mut rx, mut tx, installation_id, manager_build) = handshake(path).await?;
        let pending: Pending = Arc::new(Mutex::new(Calls::default()));
        let (out_tx, mut out_rx) = mpsc::channel::<ClientMsg>(256);
        let (lost_tx, lost) = watch::channel(false);
        let shut = Arc::new(Notify::new());
        let p = pending.clone();
        let close = shut.clone();
        tokio::spawn(async move {
            let writing = async {
                while let Some(msg) = out_rx.recv().await {
                    // Marked before the first byte goes out: a frame cut short is never run by
                    // the manager, but one that went out whole may be, and we cannot tell them
                    // apart.
                    if let ClientMsg::Call { id, .. } = &msg
                        && let Some(waiter) = p.lock().waiting.get_mut(id)
                    {
                        waiter.sent = true;
                    }
                    if tx.send(&msg, &[]).await.is_err() {
                        break;
                    }
                }
            };
            let reading = async {
                while let Ok(Some((msg, _))) = rx.recv::<ServerMsg>().await {
                    if let ServerMsg::Reply { id, result } = msg
                        && let Some(waiter) = p.lock().waiting.remove(&id)
                    {
                        #[expect(
                            clippy::let_underscore_must_use,
                            reason = "it fails only when the caller stopped waiting (timed out, or its request was dropped) and dropped the receiver; the reply then has nowhere to go"
                        )]
                        let _ = waiter.reply.send(result);
                    }
                }
            };
            // Whichever direction ends first ends the connection: a failed write never leaves
            // the reading waiting for replies to calls that did not go out (nor the manager
            // reading from a client that can no longer send), and a reading that ended never
            // leaves calls going out that cannot be answered.
            tokio::select! {
                () = writing => {}
                () = reading => {}
                () = close.notified() => {}
            }
            // Connection lost: fail every waiter. A call that was sent may have run.
            {
                let mut calls = p.lock();
                calls.closed = true;
                for (_, waiter) in calls.waiting.drain() {
                    let lost = if waiter.sent {
                        outcome_unknown()
                    } else {
                        unavailable()
                    };
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "it fails only when the caller stopped waiting (timed out, or its request was dropped), which then needs no failure"
                    )]
                    let _ = waiter.reply.send(Err(lost));
                }
            }
            // Both halves close here, so the manager sees the whole connection go.
            drop((rx, tx, out_rx));
            #[expect(
                clippy::let_underscore_must_use,
                reason = "it fails only when every client handle is gone, and then nobody is left to tell that the connection ended"
            )]
            let _ = lost_tx.send(true);
        });
        Ok(Self {
            out: out_tx,
            pending,
            next: Arc::new(AtomicU64::new(1)),
            lost,
            shut,
            installation_id,
            manager_build,
        })
    }

    #[must_use]
    pub fn is_connected(&self) -> bool {
        !self.out.is_closed() && !self.pending.lock().closed && !*self.lost.borrow()
    }

    /// End the connection now (its user gave up on it): calls still waiting on it fail at once
    /// (`OutcomeUnknown` once sent), and the manager sees it close.
    pub fn close(&self) {
        self.shut.notify_one();
    }

    /// Resolves once the connection is gone: its writing failed, its reading ended (the
    /// manager closed it, or stopped writing to it) or it was closed. A new connection is then
    /// needed.
    pub async fn closed(&self) {
        let mut lost = self.lost.clone();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "either way the connection is gone: it reported so, or its task ended and dropped the sender"
        )]
        let _ = lost.wait_for(|gone| *gone).await;
    }

    /// Run one call. `Unavailable` only when the call never reached the connection; once it
    /// was sent, a lost connection is `OutcomeUnknown` and no answer in time is `Timeout`.
    ///
    /// # Errors
    ///
    /// The manager's own error reply, or `Unavailable`, `OutcomeUnknown` or `Timeout` as above.
    pub async fn call(&self, call: Call) -> Result<Reply, ApiError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut calls = self.pending.lock();
            if calls.closed {
                return Err(unavailable());
            }
            calls.waiting.insert(
                id,
                Waiter {
                    reply: tx,
                    sent: false,
                },
            );
        }
        if self.out.send(ClientMsg::Call { id, call }).await.is_err() {
            self.pending.lock().waiting.remove(&id);
            return Err(unavailable());
        }
        match tokio::time::timeout(CALL_TIMEOUT, rx).await {
            Ok(Ok(r)) => r,
            // Dropped without an answer after the writer took it: it may have been sent.
            Ok(Err(_)) => Err(outcome_unknown()),
            Err(_) => {
                self.pending.lock().waiting.remove(&id);
                Err(ApiError::new(
                    ErrorCode::Timeout,
                    tr!(
                        "The core service took too long to answer",
                        "核心服務回應逾時",
                        "コアサービスの応答がタイムアウトしました"
                    ),
                ))
            }
        }
    }

    /// Open a separate connection streaming events. Ends when the manager goes away.
    ///
    /// # Errors
    ///
    /// The connect or handshake errors of [`Self::connect`], or a failure sending the
    /// subscription.
    pub async fn subscribe(path: &Path) -> std::io::Result<mpsc::Receiver<Event>> {
        let (mut rx, mut tx, _, _) = handshake(path).await?;
        tx.send(&ClientMsg::Subscribe, &[]).await?;
        let (ev_tx, ev_rx) = mpsc::channel(512);
        tokio::spawn(async move {
            let _keep = tx;
            loop {
                tokio::select! {
                    msg = rx.recv::<ServerMsg>() => match msg {
                        Ok(Some((ServerMsg::Event(ev), _))) => {
                            // Slow consumers lose samples rather than stalling the manager.
                            if ev_tx.try_send(ev).is_err() && ev_tx.is_closed() {
                                break;
                            }
                        }
                        _ => break,
                    },
                    // Nobody listens any more: the connection closes now, not at the next event.
                    () = ev_tx.closed() => break,
                }
            }
        });
        Ok(ev_rx)
    }
}

/// Unexpected reply shape (programming error between matching builds).
#[must_use]
pub fn wrong_reply() -> ApiError {
    ApiError::internal()
}
