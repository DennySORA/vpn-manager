//! One actor per Instance: the single owner of that Instance's lifecycle.
//!
//! The payload gate opens only through [`Actor::activate`], and only when the same generation
//! has reported a completed handshake and a successful DNS probe *and* the durable intent still
//! says running with the same intent revision *and* no user stop is held in memory. Faults never
//! change intent; they schedule a new generation with backoff. Stop and emergency tighten first
//! and reap the worker; the durable latch is written concurrently by the Manager.
//!
//! The actor also owns its connection's port forwards: it hands their bindings to each worker,
//! checks their target Apps (`crate::forwards`) on every App event and periodically, and grants
//! or revokes the leases that let the worker listen.

use std::collections::HashMap;
use std::net::{IpAddr, TcpListener};
use std::ops::ControlFlow;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngExt;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use vpn_domain::{
    ApiError, AppSpec, AppliedBlocklist, Ban, BanId, BandwidthCaps, Counter, DesiredState,
    DnsStatus, Enforcement, ErrorCode, Fault, ForwardBinding, ForwardBindingId, ForwardCounters,
    ForwardLease, ForwardState, ForwardStatus, ForwardTarget, GatewayId, GatewayRuntime,
    GatewaySpec, GatewayState, Health, InstanceId, InstanceIntent, InstanceLimits, InstanceSpec,
    InstanceStatus, KernelTcpLimits, LimitKind, Persistence, Phase, PolicyStatus, ProviderKind,
    RecoveryStatus, RunningInfo, RuntimeProfile, SecurityProfile, SecurityProfileId, Text,
    Timestamp, TransportStatus, TunnelStatus, UnbanEffect, tr,
};
use vpn_ipc::worker::{
    BanReport, ForwardLeaseWire, ForwardSpecWire, ForwardStatusWire, FromWorker, GateWire,
    GatewaySpecWire, OverlayWire, StrictWire, ToWorker, TransportStatusWire, TransportWire,
    WorkerConfig, WorkerStatus,
};
use vpn_platform::limits::{Group, Leaf};
use vpn_platform::listener::{RejectReason, bind_loopback, reject_loop};
use vpn_platform::sandbox::{SandboxLease, SandboxProcess, SpawnSpec, WorkerEntry};
use vpn_store::{BanAdded, StoreError};

use crate::forwards::{Evidence, NotReady, Verified};
use crate::hold::Hold;
use crate::policy::RunningPolicy;
use crate::resolve::{ResolveError, resolve};
use crate::sandbox::{self as strict_sandbox};
use crate::worker::{SpawnError, WorkerEvent, WorkerHandle, spawn};
use crate::{Changes, Ctx, ManagerEvent};

/// Unban requests one generation may have waiting for its worker's answer.
const MAX_PENDING_UNBANS: usize = 256;
/// Longest reason a worker may attach to a ban.
const MAX_BAN_REASON: usize = 200;
/// Longest a ban may last (the settings allow 7 days).
const MAX_BAN_SECS: u32 = 604_800;

/// How long a generation has to verify (handshake and DNS probe), at least; one whose transport
/// gives the handshake longer gets that much more ([`Live::start_timeout`]).
const START_TIMEOUT: Duration = Duration::from_secs(30);
/// What a generation needs besides its handshake to verify: the DNS probe and the activation.
const START_AFTER_HANDSHAKE: Duration = Duration::from_secs(15);
/// Port forwards are re-checked at least this often while the connection runs (App events and
/// the App watcher's passes, every 2 s, check them sooner).
const FORWARD_CHECK: Duration = Duration::from_secs(5);
/// A forward's status is published at least this often while its counters move.
const FORWARD_PUBLISH: Duration = Duration::from_secs(2);
/// Reachability evidence is written to disk at most this often per forward and protocol.
const EVIDENCE_WRITE: Duration = Duration::from_secs(60);
/// Why a Mullvad connection carries no forwards.
fn mullvad_no_forwards() -> Text {
    tr!(
        "Mullvad no longer offers port forwarding; the port forwards of this connection stay off",
        "Mullvad 已停止提供 port forwarding；這條連線的轉發不會啟用",
        "Mullvad はポート転送の提供を終了しました。この接続のポート転送は有効になりません"
    )
}
const DEGRADED_RECYCLE: Duration = Duration::from_secs(90);
const BACKOFF_SECS: [u64; 6] = [1, 2, 4, 8, 16, 30];

pub enum ActorCmd {
    /// Re-read the durable intent and act on it. `user` clears a deterministic failure.
    Reconcile {
        user: bool,
    },
    /// Tighten and stop the worker now (the intent latch is written by the Manager).
    Stop {
        emergency: bool,
        reply: oneshot::Sender<()>,
    },
    Inspect(oneshot::Sender<InstanceStatus>),
    /// The private connector of the current generation, only while Ready with the gate open.
    Route(oneshot::Sender<Option<(u64, String)>>),
    /// Gateways of this Instance changed (applies to held listeners when not running).
    GatewaysChanged,
    /// The port this Instance holds a listener on for a Gateway, if any.
    HeldPort(GatewayId, oneshot::Sender<Option<u16>>),
    /// Every listener held, with its port and whether a worker serves it (diagnostics).
    Listeners(oneshot::Sender<Vec<(GatewayId, u16, GatewayState)>>),
    /// Instance deleted: stop everything and release every held port.
    Remove(oneshot::Sender<()>),
    /// Manager shutting down: stop the worker, keep intents for the next start.
    Shutdown(oneshot::Sender<()>),
    /// Start a process in the Instance's strict sandbox (built if needed).
    SandboxSpawn(
        Box<SpawnSpec>,
        oneshot::Sender<Result<SandboxProcess, ApiError>>,
    ),
    /// Lift the auto-ban of `source` on the running worker; answered once it confirms.
    Unban {
        source: IpAddr,
        reply: oneshot::Sender<UnbanEffect>,
    },
    /// Port forwards of this Instance were saved or deleted.
    ForwardsChanged,
    /// One forward's status (`None`: not a forward of this Instance).
    ForwardStatus(ForwardBindingId, oneshot::Sender<Option<ForwardStatus>>),
    /// The status of every forward of this Instance.
    ForwardStatuses(oneshot::Sender<Vec<ForwardStatus>>),
}

/// A lease the running worker holds for one forward.
#[derive(Debug, Clone)]
struct Granted {
    id: u64,
    verified: Verified,
    /// When the lease was granted.
    at: Timestamp,
}

/// One forward as the running worker has it.
struct LiveForward {
    wire: ForwardSpecWire,
    lease: Option<Granted>,
    /// What the worker last reported about it.
    report: Option<ForwardStatusWire>,
}

/// What the actor keeps about one forward across generations.
#[derive(Default)]
struct ForwardRt {
    /// The last check of its target.
    check: Option<Result<Verified, NotReady>>,
    checked_at: Option<Timestamp>,
    /// Arrivals from outside: what is known, and what is on disk.
    evidence: Evidence,
    written: Evidence,
    written_at: Option<Instant>,
    /// The status last published, and when.
    published: Option<ForwardStatus>,
    published_at: Option<Instant>,
}

struct Held {
    port: u16,
    listener: TcpListener,
    reject: Option<CancellationToken>,
}

impl Held {
    /// Refuse every connection explicitly until the listener is handed to a worker.
    fn reject(&mut self, reason: RejectReason) {
        if let Some(c) = self.reject.take() {
            c.cancel();
        }
        let Ok(l) = self.listener.try_clone() else {
            return;
        };
        let token = CancellationToken::new();
        tokio::spawn(reject_loop(l, reason, token.clone()));
        self.reject = Some(token);
    }
}

/// What a probe report says about the connection's DNS.
struct ProbeDns {
    /// Why the probe failed, server by server.
    error: Option<Text>,
    /// The `WireGuard` profile's resolvers stand in: why the profile's servers failed.
    fallback: Option<Text>,
    /// Names fail (`on_failure: fail`): why the profile's servers failed.
    interrupted: Option<Text>,
}

struct Live {
    handle: WorkerHandle,
    /// Private connector socket of this generation (removed when the worker ends).
    connector: String,
    /// Gateways this worker serves, as handed to it.
    served: HashMap<GatewayId, GatewaySpecWire>,
    generation: u64,
    intent_revision: u64,
    permit: Option<u64>,
    tunnel_up: bool,
    probe_ok: bool,
    ready: bool,
    started: Instant,
    degraded_since: Option<Instant>,
    /// The security profile whose blocklists this generation follows (its base rules are fixed
    /// as started), and the revision it started with.
    security_id: Option<SecurityProfileId>,
    security_revision: Option<u64>,
    /// Limit of active bans of this generation.
    max_bans: u32,
    /// The overlay sent last.
    overlay: SentOverlay,
    /// Unban requests waiting for the worker's answer.
    unbans: Vec<(IpAddr, oneshot::Sender<UnbanEffect>)>,
    /// The bandwidth caps sent last (in `Configure` or `SetBandwidth`).
    bandwidth: BandwidthCaps,
    /// The transport sent last (in `Configure` or `SetTransport`).
    transport: TransportWire,
    /// Strict mode: the kernel's TCP buffer limits in the sandbox, once raised for `transport`.
    kernel_limits: Option<KernelTcpLimits>,
    /// The worker's cgroup, and whether the worker was confirmed inside it.
    cgroup: Option<(Leaf, bool)>,
    /// Port forwards handed to this worker, and the lease each holds.
    forwards: HashMap<ForwardBindingId, LiveForward>,
    /// Why this generation carries no forwards at all (its provider cannot forward ports, or
    /// its strict plane has no inbound path yet), with the code shown.
    forwards_blocked: Option<(&'static str, Text)>,
}

impl Live {
    /// How long this generation has to verify: its transport's handshake timeout and what
    /// follows the handshake, and never less than [`START_TIMEOUT`].
    fn start_timeout(&self) -> Duration {
        let handshake = u64::from(self.transport.transport.health.handshake_timeout_secs);
        START_TIMEOUT.max(Duration::from_secs(handshake) + START_AFTER_HANDSHAKE)
    }

    /// What the worker's report says its transport does, in the terms of the profile sent to
    /// it; `None` for a report that still describes an earlier transport.
    fn transport_status(&self, report: &TransportStatusWire) -> Option<TransportStatus> {
        if report.serial != self.transport.serial {
            return None;
        }
        let transport = &self.transport.transport;
        let band = transport.bands.get(usize::try_from(report.band).ok()?)?;
        // `TransportStatus::profile` and `band` are still `String`s in vpn-domain.
        Some(TransportStatus {
            profile: transport.name.clone(),
            automatic: transport.automatic,
            band: band.name.clone(),
            flow: band.flow,
            rtt_ms: report
                .rtt_us
                .map(|us| u32::try_from(us / 1000).unwrap_or(u32::MAX)),
            buffers_grown: u32::try_from(report.buffers_grown).unwrap_or(u32::MAX),
            growth_refused: u32::try_from(report.growth_refused).unwrap_or(u32::MAX),
            kernel_limits: self.kernel_limits,
            congestion: report.congestion.clone(),
        })
    }
}

/// An overlay as sent to the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SentOverlay {
    revision: u64,
    digest: String,
    lists: Vec<AppliedBlocklist>,
}

/// Why a start waits instead of retrying on a timer: a deterministic problem that only the user
/// or a change of what it depends on can resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Blocked {
    /// The configuration cannot start (no DNS, invalid or missing profile...): retried when an
    /// Instance or a `WireGuard`, DNS or security profile is saved.
    Config,
    /// The `WireGuard` key is leased to another Instance that may run: retried as well when an
    /// Instance gives up its key.
    Identity,
}

pub struct Actor {
    id: InstanceId,
    ctx: Arc<Ctx>,
    /// The user's stop, set by the Manager before this actor sees the command.
    hold: Arc<Hold>,
    status: InstanceStatus,
    live: Option<Live>,
    retry_at: Option<tokio::time::Instant>,
    attempt: u32,
    /// A deterministic problem: no timed retry; the user's Start, or a change of what it waits
    /// for (see [`Blocked`]), tries again.
    blocked: Option<Blocked>,
    held: HashMap<GatewayId, Held>,
    /// Gateways whose port could not be bound (e.g. taken by another program), with the reason.
    /// Each fails alone: reported on its own and retried with back-off while the Instance runs
    /// without it.
    failed: HashMap<GatewayId, Text>,
    gateway_retry_at: Option<tokio::time::Instant>,
    gateway_attempt: u32,
    last_key: Option<String>,
    /// What the running generation was started with ([`crate::inputs`]).
    running_inputs: Option<crate::inputs::WorkerInputs>,
    last_sample_emit: Option<Instant>,
    /// The last overlay sent to any generation: a new generation with the same lists and content
    /// keeps its revision instead of taking a new one.
    last_overlay: Option<SentOverlay>,
    /// Linux strict mode: the Instance's sandbox, kept across generations.
    sandbox: Option<SandboxLease>,
    /// Epoch of the last sandbox (a new one gets a higher epoch).
    sandbox_epoch: u64,
    /// This Instance's port forwards as stored.
    bindings: Vec<ForwardBinding>,
    forward_rt: HashMap<ForwardBindingId, ForwardRt>,
}

/// This user's holders of each of `ports` (`(port, udp)`; none for a port when the host's
/// sockets cannot be read) and the network namespace of each of `apps` (pids), from one look at
/// the host on a blocking thread.
async fn scan_holders(
    ports: Vec<(u16, bool)>,
    apps: Vec<u32>,
) -> (
    HashMap<(u16, bool), Vec<vpn_platform::apps::proc::Holder>>,
    HashMap<u32, Option<u64>>,
) {
    if ports.is_empty() {
        return (HashMap::new(), HashMap::new());
    }
    tokio::task::spawn_blocking(move || {
        let namespaces = apps
            .into_iter()
            .map(|pid| (pid, vpn_platform::apps::proc::net_namespace(pid)))
            .collect();
        let holders = vpn_platform::apps::proc::holders(&ports)
            .map_or_default(|found| ports.into_iter().zip(found).collect());
        (holders, namespaces)
    })
    .await
    .unwrap_or_default()
}

/// What the actor's loop listens on besides its own worker and deadlines.
struct Sources {
    commands: mpsc::Receiver<ActorCmd>,
    /// Saved configuration ([`Changes`]).
    changes: tokio::sync::watch::Receiver<Changes>,
    /// An App started, stopped or was looked at again.
    apps: tokio::sync::watch::Receiver<u64>,
    forward_tick: tokio::time::Interval,
}

/// What the actor's loop woke up for ([`Actor::next_wake`]).
enum Wake {
    /// `None`: the manager let the actor go.
    Command(Option<ActorCmd>),
    HolderGone,
    Changes,
    /// `None`: the worker's connection closed.
    Worker(Option<WorkerEvent>),
    StartTimeout,
    DegradedTooLong,
    Retry,
    GatewayRetry,
    Forwards,
}

/// Why a sandbox could not be prepared for a start.
enum SandboxFailure {
    /// The host does not allow it: wait for a configuration change.
    Blocked(Fault),
    /// Possibly temporary: retry with back-off.
    Retry(Fault),
}

/// What a strict worker gets: the namespaces it joins, the descriptors after its Gateway
/// listeners, and their description.
struct StrictStart {
    entry: WorkerEntry,
    fds: Vec<OwnedFd>,
    wire: StrictWire,
}

/// The overlay a generation starts with, and its status before the worker applies it.
fn overlay_status(
    revision: u64,
    resolved: &crate::resolve::Resolved,
) -> (SentOverlay, PolicyStatus) {
    let sent = SentOverlay {
        revision,
        digest: resolved.overlay.digest.clone(),
        lists: resolved.overlay.applied(),
    };
    let policy_status = PolicyStatus {
        revision,
        digest: sent.digest.clone(),
        blocklists: sent.lists.clone(),
        v4_ranges: u32::try_from(resolved.overlay.set.v4_ranges().len()).unwrap_or(u32::MAX),
        v6_ranges: u32::try_from(resolved.overlay.set.v6_ranges().len()).unwrap_or(u32::MAX),
        applied_revision: None,
        applied_digest: None,
        applied_at: None,
        error: None,
    };
    (sent, policy_status)
}

/// A worker's forwards before any of them is leased.
fn live_forwards(wires: Vec<ForwardSpecWire>) -> HashMap<ForwardBindingId, LiveForward> {
    wires
        .into_iter()
        .map(|wire| {
            (
                wire.id,
                LiveForward {
                    wire,
                    lease: None,
                    report: None,
                },
            )
        })
        .collect()
}

/// The tunnel's status before its first handshake.
fn tunnel_status(profile: &RuntimeProfile) -> TunnelStatus {
    TunnelStatus {
        endpoint: profile.peer.endpoint.to_string(),
        last_handshake_at: None,
        wg_rx_bytes: Counter(0),
        wg_tx_bytes: Counter(0),
        ipv6: profile
            .interface
            .addresses
            .iter()
            .any(ipnetwork::IpNetwork::is_ipv6),
    }
}

fn fault(code: &str, message: impl Into<Text>) -> Fault {
    Fault {
        code: code.into(),
        message: message.into(),
        at: Timestamp::now(),
    }
}

/// Fault code of an Instance held closed because a stop asked for before this manager started
/// is not on disk (phase `recovery_required`).
pub const STOP_NOT_CONFIRMED: &str = "STOP_NOT_CONFIRMED";

/// What the user is told about a stop carried over unconfirmed, and how to end it.
fn unconfirmed_fault(emergency: bool) -> Fault {
    fault(
        STOP_NOT_CONFIRMED,
        if emergency {
            tr!(
                "When the core service (manager) last ended, the emergency stop of this connection was not on disk yet, so your last decision cannot be confirmed and the connection stays blocked. To keep the emergency stop, confirm it again; to restore the connection, release the emergency stop and then start it.",
                "核心服務（manager）上次結束時，這條連線的急停還沒寫入磁碟，無法確認你最後的決定，所以一直保持封鎖。要維持急停，請再確認一次急停；要恢復連線，請先解除急停再啟動。",
                "前回コアサービス（manager）が終了したとき、この接続の緊急停止はまだディスクに書き込まれていなかったため、最後の判断を確認できず、ブロックしたままにしています。緊急停止を続ける場合はもう一度緊急停止を確認し、接続を戻す場合は緊急停止を解除してから開始してください。"
            )
        } else {
            tr!(
                "When the core service (manager) last ended, the stop of this connection was not on disk yet, so your last decision cannot be confirmed and the connection stays blocked. To keep it stopped, confirm the stop again; to restore the connection, start it.",
                "核心服務（manager）上次結束時，這條連線的停止還沒寫入磁碟，無法確認你最後的決定，所以一直保持封鎖。要維持停止，請再確認一次停止；要恢復連線，請啟動它。",
                "前回コアサービス（manager）が終了したとき、この接続の停止はまだディスクに書き込まれていなかったため、最後の判断を確認できず、ブロックしたままにしています。停止を続ける場合はもう一度停止を確認し、接続を戻す場合は開始してください。"
            )
        },
    )
}

fn listener_error(g: &GatewaySpec, e: &std::io::Error) -> Text {
    let (name, port) = (&g.name, g.port);
    tr!(
        "The Gateway “{name}” cannot use 127.0.0.1:{port} ({e}); it is retried automatically",
        "Gateway「{name}」無法使用 127.0.0.1:{port}（{e}），稍後自動重試",
        "ゲートウェイ「{name}」は 127.0.0.1:{port} を使用できません（{e}）。しばらくすると自動で再試行します"
    )
}

/// Why a forward cannot listen while its connection runs no generation, by the connection's
/// phase: the code and the reason.
fn not_running(phase: Phase) -> (&'static str, Text) {
    match phase {
        Phase::Reconnecting => (
            "CONNECTION_RECONNECTING",
            tr!(
                "The connection is reconnecting",
                "連線正在重新連線",
                "接続は再接続中です"
            ),
        ),
        Phase::Failed => (
            "CONNECTION_FAILED",
            tr!(
                "The connection cannot start",
                "連線無法啟動",
                "接続を開始できません"
            ),
        ),
        Phase::RecoveryRequired => (
            "CONNECTION_RECOVERY",
            tr!(
                "The connection needs a manual decision and stays blocked until then",
                "連線需人工確認，確認前保持封鎖",
                "接続には手動での確認が必要で、確認まではブロックしたままです"
            ),
        ),
        _ => (
            "CONNECTION_STOPPED",
            tr!(
                "The connection is not running",
                "連線未執行",
                "接続は実行されていません"
            ),
        ),
    }
}

/// The latest blocklist overlay was not applied and the previous one stays enforced: `why`.
fn kept_overlay(why: impl Into<Text>) -> Text {
    tr!(
        "The latest IP blocklist was not applied (the previous version stays): {why}",
        "最新的 IP 封鎖清單未套用（沿用先前的版本）：{why}",
        "最新の IP ブロックリストは適用されていません（以前のバージョンを使い続けます）：{why}";
        why = why
    )
}

/// What a worker is told about a Gateway (compared to detect changes while it runs).
const fn wire_of(g: &GatewaySpec) -> GatewaySpecWire {
    GatewaySpecWire {
        id: g.id,
        kind: g.kind,
        port: g.port,
        udp: g.udp,
        max_connections: g.max_connections,
    }
}

/// What is known of a generation the moment its worker is configured: the revisions it runs
/// (its `WireGuard` profile's, then its DNS and security profiles') and its process.
fn started_info(generation: u64, pid: u32, revisions: crate::resolve::Revisions) -> RunningInfo {
    RunningInfo {
        generation,
        profile_revision: revisions.profile,
        dns_profile_revision: revisions.dns,
        security_profile_revision: revisions.security,
        started_at: Timestamp::now(),
        ready_at: None,
        pid: Some(pid),
        pending_changes: Vec::new(),
        policy: None,
        resources: None,
        bandwidth: None,
        // Known once the worker's first report says what its transport does.
        transport: None,
    }
}

/// The transport a generation starts with, as its worker's `Configure` carries it.
const fn first_transport(transport: vpn_domain::ResolvedTransport) -> TransportWire {
    TransportWire {
        serial: 1,
        transport,
    }
}

/// The bandwidth caps of a connection's limits.
const fn caps_of(l: &InstanceLimits) -> BandwidthCaps {
    BandwidthCaps {
        download_bps: l.download_bps,
        upload_bps: l.upload_bps,
    }
}

/// Jittered back-off: 1/2/4/8/16/30 s, plus a 60 s cool-down every 5 attempts.
fn backoff(attempt: u32) -> Duration {
    let idx = (attempt as usize).min(BACKOFF_SECS.len() - 1);
    let base = BACKOFF_SECS[idx] * 1000;
    let mut delay_ms = rand::rng().random_range(base / 2..=base);
    if attempt > 0 && attempt.is_multiple_of(5) {
        delay_ms += 60_000;
    }
    Duration::from_millis(delay_ms)
}

impl Actor {
    pub fn new(id: InstanceId, ctx: Arc<Ctx>, hold: Arc<Hold>) -> Self {
        let status = InstanceStatus {
            instance_id: id,
            spec_revision: 0,
            intent: InstanceIntent {
                desired: DesiredState::Stopped,
                manual_stop: false,
                emergency_latched: false,
                intent_revision: 0,
                persistence: Persistence::Durable,
            },
            phase: Phase::Stopped,
            enforcement: Enforcement::Blocked,
            health: Health::Unknown,
            running: None,
            tunnel: None,
            dns: None,
            gateways: Vec::new(),
            recovery: RecoveryStatus {
                attempt: 0,
                next_retry_at: None,
                last_fault: None,
                unreachable_attempts: 0,
            },
            observed_at: Timestamp::now(),
            sandbox: None,
        };
        Self {
            id,
            ctx,
            hold,
            status,
            live: None,
            retry_at: None,
            attempt: 0,
            blocked: None,
            held: HashMap::new(),
            failed: HashMap::new(),
            gateway_retry_at: None,
            gateway_attempt: 0,
            last_key: None,
            running_inputs: None,
            last_sample_emit: None,
            last_overlay: None,
            sandbox: None,
            sandbox_epoch: 0,
            bindings: Vec::new(),
            forward_rt: HashMap::new(),
        }
    }

    /// Take over a sandbox a previous manager left (its identity already proven).
    pub fn adopt(&mut self, lease: SandboxLease) {
        self.sandbox_epoch = lease.identity().epoch;
        self.hold_sandbox(lease);
    }

    /// Hold `lease` as this Instance's sandbox; managed Apps can start in it from now on.
    fn hold_sandbox(&mut self, lease: SandboxLease) {
        self.ctx.strict_apps.register(&self.ctx, self.id, &lease);
        self.sandbox = Some(lease);
    }

    /// Let go of the sandbox (to tear it down, or to leave it for the next manager); no App
    /// starts in it any more.
    fn release_sandbox(&mut self) -> Option<SandboxLease> {
        self.ctx.strict_apps.unregister(self.id);
        self.sandbox.take()
    }

    /// Handle one command; `Break` when the actor ends with it.
    async fn on_command(&mut self, cmd: ActorCmd) -> ControlFlow<()> {
        match cmd {
            ActorCmd::Reconcile { user } => {
                if user {
                    self.blocked = None;
                    self.attempt = 0;
                    self.retry_at = None;
                }
                self.refresh_intent().await;
                self.reconcile().await;
            }
            ActorCmd::Stop { emergency, reply } => {
                self.stop_worker(
                    emergency,
                    if emergency {
                        "EMERGENCY_STOP"
                    } else {
                        "STOPPED"
                    },
                )
                .await;
                self.retry_at = None;
                self.refresh_intent().await;
                self.settle_stopped();
                let _ = reply.send(());
            }
            ActorCmd::Inspect(reply) => {
                let _ = reply.send(self.snapshot());
            }
            ActorCmd::Route(reply) => {
                let route = self.live.as_ref().and_then(|l| {
                    (self.status.phase == Phase::Ready && l.permit.is_some())
                        .then(|| (l.generation, l.connector.clone()))
                });
                let _ = reply.send(route);
            }
            ActorCmd::GatewaysChanged => {
                if self.live.is_none() {
                    if let Err(f) = self.sync_listeners(None).await {
                        self.status.recovery.last_fault = Some(f);
                    }
                    self.emit();
                } else {
                    self.apply_gateways_live().await;
                }
            }
            ActorCmd::HeldPort(id, reply) => {
                let _ = reply.send(self.held.get(&id).map(|h| h.port));
            }
            ActorCmd::Listeners(reply) => {
                let _ = reply.send(self.listeners());
            }
            ActorCmd::Remove(reply) => {
                self.stop_worker(false, "REMOVED").await;
                for (_, h) in self.held.drain() {
                    if let Some(c) = h.reject {
                        c.cancel();
                    }
                }
                // The connection is gone: so are its sandbox and its Apps.
                self.teardown_sandbox("REMOVED").await;
                self.ctx.strict_apps.forget(self.id);
                let _ = reply.send(());
                return ControlFlow::Break(());
            }
            ActorCmd::Shutdown(reply) => {
                self.stop_worker(false, "MANAGER_SHUTDOWN").await;
                // The sandbox stays, closed, for the next manager to adopt (its
                // holder gives up `ORPHAN_GRACE` after this process exits if none comes).
                let _ = self.release_sandbox();
                let _ = reply.send(());
                return ControlFlow::Break(());
            }
            ActorCmd::SandboxSpawn(spec, reply) => {
                let result = self.sandbox_spawn(*spec).await;
                self.emit();
                let _ = reply.send(result);
            }
            ActorCmd::Unban { source, reply } => self.unban(source, reply).await,
            ActorCmd::ForwardsChanged => self.forwards_changed().await,
            ActorCmd::ForwardStatus(id, reply) => {
                let status = self
                    .bindings
                    .iter()
                    .find(|b| b.id == id)
                    .map(|b| self.forward_status(b));
                let _ = reply.send(status);
            }
            ActorCmd::ForwardStatuses(reply) => {
                let all = self
                    .bindings
                    .iter()
                    .map(|b| self.forward_status(b))
                    .collect();
                let _ = reply.send(all);
            }
        }
        ControlFlow::Continue(())
    }

    /// The stored configuration, a key release or a policy changed since `before`.
    async fn on_changes(&mut self, before: Changes, now: Changes) {
        let config = now.config != before.config;
        let released = now.released != before.released;
        let policy = now.policy != before.policy;
        if policy {
            self.refresh_overlay().await;
        }
        if config {
            self.refresh_pending().await;
            self.refresh_bandwidth().await;
            self.refresh_transport().await;
            self.drop_unwanted_sandbox().await;
            self.keep_sandbox_ready().await;
        }
        self.retry_blocked(config, released).await;
    }

    pub async fn run(mut self, rx: mpsc::Receiver<ActorCmd>) {
        let changes = self.ctx.changes.subscribe();
        let mut seen = *changes.borrow();
        let apps = self.ctx.apps.changes();
        let mut forward_tick = tokio::time::interval(FORWARD_CHECK);
        forward_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        self.reload_bindings().await;
        self.refresh_intent().await;
        if let Err(f) = self.sync_listeners(None).await {
            self.status.recovery.last_fault = Some(f);
        }
        self.reconcile().await;
        self.keep_sandbox_ready().await;
        let mut sources = Sources {
            commands: rx,
            changes,
            apps,
            forward_tick,
        };
        loop {
            match self.next_wake(&mut sources).await {
                Wake::Command(None) => break,
                Wake::Command(Some(cmd)) => {
                    if self.on_command(cmd).await.is_break() {
                        return;
                    }
                }
                Wake::HolderGone => self.on_holder_gone().await,
                Wake::Changes => {
                    let now = *sources.changes.borrow_and_update();
                    let before = std::mem::replace(&mut seen, now);
                    self.on_changes(before, now).await;
                }
                Wake::Worker(event) => {
                    self.on_worker_event(event.unwrap_or(WorkerEvent::Closed))
                        .await;
                }
                Wake::Retry => {
                    self.retry_at = None;
                    self.refresh_intent().await;
                    self.reconcile().await;
                }
                Wake::GatewayRetry => {
                    self.gateway_retry_at = None;
                    self.retry_gateways().await;
                }
                Wake::StartTimeout => {
                    let secs = self
                        .live
                        .as_ref()
                        .map_or(START_TIMEOUT, Live::start_timeout)
                        .as_secs();
                    self.fail_generation(fault(
                        "START_TIMEOUT",
                        tr!(
                            "The connection was not verified within {secs} seconds (handshake or DNS)",
                            "連線在 {secs} 秒內未完成驗證（握手或 DNS）",
                            "接続は {secs} 秒以内に検証を完了しませんでした（ハンドシェイクまたは DNS）"
                        ),
                    ))
                    .await;
                }
                Wake::DegradedTooLong => {
                    self.fail_generation(fault(
                        "DEGRADED_TOO_LONG",
                        tr!(
                            "The connection stayed unstable; rebuilding it",
                            "連線持續不穩，重新建立",
                            "接続が不安定な状態が続いたため、作り直します"
                        ),
                    ))
                    .await;
                }
                Wake::Forwards => self.check_forwards().await,
            }
        }
    }

    /// Wait for the next thing the loop acts on. They are looked at in this order, so what is
    /// ready first in it wins: commands (a queued Stop is handled before a worker event that
    /// would lead to opening the gate), the sandbox holder's exit, saved configuration, the
    /// worker's events and the connection's own deadlines, and only then the port forward
    /// checks — they scan the host's sockets, and a round of them that is always due again must
    /// not keep a worker's report or a deadline waiting.
    async fn next_wake(&mut self, sources: &mut Sources) -> Wake {
        let start_deadline = self
            .live
            .as_ref()
            .filter(|l| !l.ready)
            .map(|l| tokio::time::Instant::from_std(l.started + l.start_timeout()));
        let degraded_deadline = self
            .live
            .as_ref()
            .and_then(|l| l.degraded_since)
            .map(|t| tokio::time::Instant::from_std(t + DEGRADED_RECYCLE));
        let has_forwards = !self.bindings.is_empty();
        let checking = self.live.is_some() && self.bindings.iter().any(|b| b.enabled);
        let at = |deadline: Option<tokio::time::Instant>| async move {
            match deadline {
                Some(t) => tokio::time::sleep_until(t).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            cmd = sources.commands.recv() => Wake::Command(cmd),
            () = async {
                match self.sandbox.as_ref() {
                    Some(lease) => lease.holder_gone().await,
                    None => std::future::pending().await,
                }
            } => Wake::HolderGone,
            Ok(()) = sources.changes.changed() => Wake::Changes,
            event = async {
                match self.live.as_mut() {
                    Some(l) => l.handle.events.recv().await,
                    None => std::future::pending().await,
                }
            } => Wake::Worker(event),
            () = at(start_deadline) => Wake::StartTimeout,
            () = at(degraded_deadline) => Wake::DegradedTooLong,
            () = at(self.retry_at) => Wake::Retry,
            () = at(self.gateway_retry_at) => Wake::GatewayRetry,
            Ok(()) = sources.apps.changed(), if has_forwards => {
                // An App started, stopped or was looked at again: its forwards follow.
                sources.apps.borrow_and_update();
                Wake::Forwards
            }
            _ = sources.forward_tick.tick(), if checking => Wake::Forwards,
        }
    }

    async fn refresh_intent(&mut self) {
        match self.ctx.store.intent(self.id).await {
            Ok(row) => {
                let mut intent = InstanceIntent {
                    desired: row.desired,
                    manual_stop: row.manual_stop,
                    emergency_latched: row.emergency_latched,
                    intent_revision: row.intent_revision,
                    persistence: Persistence::Durable,
                };
                let held = self.hold.get();
                if held.stopped && !held.durable {
                    // The user's stop is in force; its latch is not on disk yet (retrying).
                    intent.desired = DesiredState::Stopped;
                    intent.manual_stop = true;
                    intent.emergency_latched |= held.emergency;
                    intent.persistence = Persistence::Pending;
                }
                self.status.intent = intent;
            }
            Err(e) => {
                tracing::warn!(instance = %self.id, error = %e, "could not read intent");
                self.status.intent.persistence = Persistence::Unavailable;
            }
        }
    }

    fn wants_running(&self) -> bool {
        let i = &self.status.intent;
        i.desired == DesiredState::Running
            && !i.manual_stop
            && !i.emergency_latched
            && i.persistence == Persistence::Durable
            && !self.hold.stopped()
    }

    async fn reconcile(&mut self) {
        if !self.wants_running() {
            if self.live.is_some() {
                self.stop_worker(false, "INTENT_STOPPED").await;
            }
            self.retry_at = None;
            self.settle_stopped();
            return;
        }
        if self.live.is_some() || self.blocked.is_some() || self.retry_at.is_some() {
            return;
        }
        self.start_generation().await;
    }

    /// Configuration was saved: which of it the running generation does not run yet.
    async fn refresh_pending(&mut self) {
        let Some(started) = &self.running_inputs else {
            return;
        };
        let Some(now) = crate::inputs::current(&self.ctx.store, self.id).await else {
            return;
        };
        let pending = started.pending(&now);
        if let Some(running) = self.status.running.as_mut()
            && running.pending_changes != pending
        {
            running.pending_changes = pending;
            self.status.observed_at = Timestamp::now();
            self.emit();
        }
    }

    /// The connection was saved: new bandwidth caps apply to the running worker at once (they
    /// are not part of what a restart applies). The status shows them once the worker confirms.
    async fn refresh_bandwidth(&mut self) {
        let Some(sent) = self.live.as_ref().map(|l| l.bandwidth) else {
            return;
        };
        let spec: InstanceSpec = match self.ctx.store.get(self.id.to_string()).await {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(instance = %self.id, error = %e, "connection not read; bandwidth caps kept");
                return;
            }
        };
        let want = caps_of(&spec.limits);
        if want == sent {
            return;
        }
        let Some(live) = self.live.as_mut() else {
            return;
        };
        // A worker that is gone sends Closed; the next generation starts with the saved caps.
        if live
            .handle
            .send(&ToWorker::SetBandwidth(want))
            .await
            .is_ok()
        {
            live.bandwidth = want;
            tracing::info!(instance = %self.id, "bandwidth caps sent to the running worker");
        }
    }

    /// A connection or a transport profile was saved: the transport the connection resolves to
    /// now applies to the running worker at once, to the flows it opens from then on (it is not
    /// part of what a restart applies). The status shows it once the worker reports it.
    async fn refresh_transport(&mut self) {
        let Some(sent) = self.live.as_ref().map(|l| l.transport.clone()) else {
            return;
        };
        let spec: InstanceSpec = match self.ctx.store.get(self.id.to_string()).await {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(instance = %self.id, error = %e, "connection not read; transport kept");
                return;
            }
        };
        let want = match crate::resolve::transport(&self.ctx.store, &spec).await {
            Ok(t) => t,
            Err(e) => {
                // The running worker keeps what it has; the next start says why it cannot.
                tracing::warn!(instance = %self.id, error = ?e, "transport not resolved; the running one is kept");
                return;
            }
        };
        if want == sent.transport {
            return;
        }
        let next = TransportWire {
            serial: sent.serial + 1,
            transport: want,
        };
        let Some(live) = self.live.as_mut() else {
            return;
        };
        // A worker that is gone sends Closed; the next generation starts with the saved one.
        if live
            .handle
            .send(&ToWorker::SetTransport(Box::new(next.clone())))
            .await
            .is_ok()
        {
            tracing::info!(instance = %self.id, profile = %next.transport.name.en, "transport sent to the running worker");
            live.transport = next;
            self.tune_sandbox().await;
        }
    }

    /// Strict mode: the kernel sizes the buffers of the sandbox's TCP sockets itself (the
    /// worker's and the Apps'), up to limits of its own. The transport raises them to twice the
    /// largest sizes any of its ranges allows — the kernel counts its bookkeeping in a buffer,
    /// about as much as the data — and never lowers them: a small profile leaves the kernel's
    /// limits as they are.
    async fn tune_sandbox(&mut self) {
        let (Some(live), Some(sandbox)) = (self.live.as_mut(), self.sandbox.as_ref()) else {
            return;
        };
        let (receive_kib, send_kib) = live.transport.transport.tcp_ceilings_kib();
        let bytes = |kib: u32| u64::from(kib) * 1024 * 2;
        let kib = |bytes: u64| u32::try_from(bytes / 1024).unwrap_or(u32::MAX);
        match sandbox
            .raise_tcp_limits(bytes(receive_kib), bytes(send_kib))
            .await
        {
            Ok(Some((receive, send))) => {
                live.kernel_limits = Some(KernelTcpLimits {
                    recv_kib: kib(receive),
                    send_kib: kib(send),
                });
            }
            // A holder of an earlier version: the kernel's own limits stand until the sandbox
            // is built anew.
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(instance = %self.id, error = %e, "kernel TCP buffer limits of the sandbox not raised");
            }
        }
    }

    /// Something a blocked start may wait for changed (`config`: configuration was saved;
    /// `released`: an Instance gave up its key): try again, once. Only while the user wants the
    /// Instance running: a stopped one stays stopped and keeps its block until the user starts
    /// it, and a stop or the emergency latch is never overridden.
    async fn retry_blocked(&mut self, config: bool, released: bool) {
        let due = match self.blocked {
            Some(Blocked::Config) => config,
            Some(Blocked::Identity) => config || released,
            None => false,
        };
        if !due {
            return;
        }
        self.refresh_intent().await;
        if !self.wants_running() {
            return;
        }
        self.blocked = None;
        self.reconcile().await;
    }

    /// What the next generation runs with (its spec revision is recorded); `None` when it cannot
    /// start now (blocked, or a retry is scheduled).
    async fn resolve_for_start(&mut self) -> Option<crate::resolve::Resolved> {
        match resolve(&self.ctx.store, self.id).await {
            Ok(r) => {
                self.status.spec_revision = r.spec.meta.revision;
                Some(r)
            }
            Err(ResolveError::Deterministic { code, message }) => {
                self.blocked = Some(Blocked::Config);
                self.status.recovery.last_fault = Some(fault(code, message));
                self.set_phase(Phase::Failed);
                None
            }
            Err(ResolveError::Transient(e)) => {
                self.schedule_retry(fault("STORE_UNAVAILABLE", e.to_api().message));
                None
            }
        }
    }

    /// The overlay revision of the next generation: the same lists with the same content keep
    /// their revision across generations. `None` when a retry is scheduled.
    async fn overlay_revision_for(&mut self, resolved: &crate::resolve::Resolved) -> Option<u64> {
        match &self.last_overlay {
            Some(last) if resolved.overlay.same_as(&last.lists, &last.digest) => {
                Some(last.revision)
            }
            _ => match self.ctx.store.next_policy_revision().await {
                Ok(r) => Some(r),
                Err(e) => {
                    self.schedule_retry(fault("STORE_UNAVAILABLE", e.to_api().message));
                    None
                }
            },
        }
    }

    /// Reserve the next generation (and the key's lease) in the Store; `None` when it cannot
    /// start now (blocked, stopped meanwhile, or a retry is scheduled).
    async fn reserve(&mut self, resolved: &crate::resolve::Resolved) -> Option<u64> {
        match self
            .ctx
            .store
            .reserve_generation(
                self.id,
                self.status.intent.intent_revision,
                resolved.key_fingerprint.clone(),
            )
            .await
        {
            Ok(g) => Some(g),
            Err(StoreError::IdentityInUse) => {
                self.blocked = Some(Blocked::Identity);
                self.status.recovery.last_fault = Some(fault(
                    "IDENTITY_IN_USE",
                    tr!(
                        "This WireGuard key is in use by another Instance; one key serves one connection at a time, and this is retried automatically once that Instance stops or is deleted",
                        "這把 WireGuard 金鑰正被另一個 Instance 使用；同一把金鑰同時只能有一個連線，該 Instance 停止或刪除後會自動再試",
                        "この WireGuard 鍵は別の Instance が使用しています。1 つの鍵で同時に使える接続は 1 つだけです。その Instance が停止または削除されると自動で再試行します"
                    ),
                ));
                self.set_phase(Phase::Failed);
                None
            }
            Err(StoreError::RevisionConflict { .. } | StoreError::InvalidState(_)) => {
                // The intent changed under us (e.g. a Stop raced this attempt): re-read and act.
                self.refresh_intent().await;
                if self.wants_running() {
                    self.schedule_retry(fault(
                        "INTENT_CHANGED",
                        tr!(
                            "The desired state changed; trying again",
                            "意圖已更新，重新嘗試",
                            "目標の状態が更新されたため、再試行します"
                        ),
                    ));
                } else {
                    self.settle_stopped();
                }
                None
            }
            Err(e) => {
                self.schedule_retry(fault("STORE_UNAVAILABLE", e.to_api().message));
                None
            }
        }
    }

    /// Strict mode's sandbox for the next generation (`Some(None)` without strict mode, whose
    /// sandbox is torn down); `None` when it cannot start now (blocked, or a retry is scheduled).
    async fn strict_for_start(
        &mut self,
        resolved: &crate::resolve::Resolved,
    ) -> Option<Option<StrictStart>> {
        if !resolved.worker.strict {
            self.teardown_sandbox("STRICT_OFF").await;
            return Some(None);
        }
        match self.prepare_strict(&resolved.profile).await {
            Ok(s) => Some(Some(s)),
            Err(SandboxFailure::Blocked(f)) => {
                self.blocked = Some(Blocked::Config);
                self.status.recovery.last_fault = Some(f);
                self.set_phase(Phase::Failed);
                None
            }
            Err(SandboxFailure::Retry(f)) => {
                self.schedule_retry(f);
                None
            }
        }
    }

    /// The held listeners of `gateways`, duplicated for the worker (each stops refusing first);
    /// `None` when one cannot be duplicated (a retry is scheduled).
    fn hand_over_listeners(&mut self, gateways: &[GatewaySpecWire]) -> Option<Vec<OwnedFd>> {
        let mut fds: Vec<OwnedFd> = Vec::new();
        for g in gateways {
            let Some(h) = self.held.get_mut(&g.id) else {
                continue;
            };
            if let Some(c) = h.reject.take() {
                c.cancel();
            }
            match h.listener.try_clone() {
                Ok(l) => fds.push(OwnedFd::from(l)),
                Err(e) => {
                    self.schedule_retry(fault("LISTENER_DUP", e.to_string()));
                    self.restart_reject_loops(RejectReason::Reconnecting);
                    return None;
                }
            }
        }
        Some(fds)
    }

    /// The worker did not start: its cgroup goes, the listeners refuse again, and a retry is
    /// scheduled.
    fn spawn_failed(&mut self, leaf: Option<&Leaf>, e: &SpawnError) {
        if let Some(l) = leaf
            && let Err(err) = l.remove()
        {
            tracing::warn!(instance = %self.id, cgroup = l.rel(), error = %err, "worker cgroup not removed");
        }
        self.restart_reject_loops(RejectReason::Reconnecting);
        let f = match e {
            SpawnError::Refused { code, message } => fault(code, message.clone()),
            other => fault("WORKER_START", other.text()),
        };
        self.schedule_retry(f);
    }

    /// Start the worker in its own cgroup (Linux, delegated; it joins it before its first
    /// instruction). `None` when it did not start (a retry is scheduled).
    async fn spawn_in_cgroup(
        &mut self,
        generation: u64,
        config: WorkerConfig,
        fds: Vec<OwnedFd>,
        entry: Option<vpn_platform::sandbox::WorkerEntry>,
        limits: &vpn_domain::InstanceLimits,
    ) -> Option<(
        WorkerHandle,
        Option<(Leaf, bool)>,
        vpn_domain::ResourceStatus,
    )> {
        // Its own cgroup (Linux, delegated): the worker joins it before its first instruction.
        let leaf_name = format!("{}-{generation}", self.id);
        let tree = crate::limits::worker_tree(limits);
        let (leaf, no_leaf) = match self.ctx.resources.create(Group::Workers, &leaf_name, &tree) {
            Ok(l) => (Some(l), None),
            Err(reason) => (None, Some(reason)),
        };
        // Shared: a recovery removing lock files waits until this worker holds its key lock.
        let spawned = {
            let _gate = self.ctx.spawn_gate.read().await;
            spawn(
                &self.ctx.exe,
                config,
                &fds,
                entry.as_ref(),
                &self.ctx.inventory,
                leaf.as_ref().map(Leaf::procs_fd),
            )
            .await
        };
        let handle = match spawned {
            Ok(h) => h,
            Err(e) => {
                self.spawn_failed(leaf.as_ref(), &e);
                return None;
            }
        };
        drop(fds);
        let cgroup = leaf.map(|l| {
            let placed = l.contains(handle.pid);
            if !placed {
                tracing::warn!(instance = %self.id, cgroup = l.rel(), "worker is not in its cgroup");
            }
            (l, placed)
        });
        let resources = match &cgroup {
            Some((l, placed)) => crate::limits::in_leaf(l, *placed),
            None => crate::limits::without_cgroup(&self.ctx.resources, no_leaf.as_ref()),
        };
        Some((handle, cgroup, resources))
    }

    /// The connector socket of `generation`.
    fn connector_path(&self, generation: u64) -> String {
        let short: String = self.id.to_string().chars().take(8).collect();
        self.ctx
            .paths
            .connector_socket(&short, generation)
            .to_string_lossy()
            .into_owned()
    }

    /// The worker's configuration for `generation`.
    fn worker_config(
        &self,
        generation: u64,
        parts: crate::resolve::WorkerConfigParts,
        key_fingerprint: &str,
        connector: &str,
        strict: Option<StrictWire>,
        forwards: Vec<ForwardSpecWire>,
    ) -> WorkerConfig {
        WorkerConfig {
            instance_id: self.id,
            generation,
            tunnel: parts.tunnel,
            dns: parts.dns,
            policy: parts.policy,
            gateways: parts.gateways,
            limits: parts.limits,
            transport: first_transport(parts.transport),
            key_lock_path: self
                .ctx
                .paths
                .key_lock(key_fingerprint)
                .to_string_lossy()
                .into_owned(),
            connector_path: Some(connector.to_owned()),
            gateway_key: self
                .ctx
                .gateway_key
                .as_ref()
                .map(|k| vpn_ipc::SecretBytes::new(k.to_vec())),
            strict,
            forwards,
        }
    }

    /// The key the next generation reserved; a different one than before released this
    /// Instance's lease on its previous key.
    fn note_key(&mut self, key_fingerprint: &str) {
        if self
            .last_key
            .as_deref()
            .is_some_and(|k| k != key_fingerprint)
        {
            self.ctx.key_released();
        }
        self.last_key = Some(key_fingerprint.to_owned());
    }

    /// Port forwards ride along with a generation; none listens before its App is verified and
    /// leased. A provider without port forwarding gets none, and the reason.
    async fn forwards_for(
        &mut self,
        profile: &RuntimeProfile,
    ) -> (Option<(&'static str, Text)>, Vec<ForwardSpecWire>) {
        self.reload_bindings().await;
        let forwards_blocked = (profile.provider == ProviderKind::Mullvad)
            .then(|| ("PROVIDER_UNSUPPORTED", mullvad_no_forwards()));
        let forward_wires = if forwards_blocked.is_none() {
            self.forward_wires()
        } else {
            Vec::new()
        };
        (forwards_blocked, forward_wires)
    }

    /// What the rest of the manager reads about the started generation: its policy for save
    /// checks, its overlay, its inputs and its tunnel.
    fn record_generation(
        &mut self,
        instance_name: &str,
        needs: &[crate::policy::Need],
        inputs: &crate::inputs::WorkerInputs,
        profile: &RuntimeProfile,
        security_id: Option<SecurityProfileId>,
        sent: &SentOverlay,
    ) {
        self.ctx.running.lock().insert(
            self.id,
            RunningPolicy {
                instance_name: instance_name.to_owned(),
                security_id,
                needs: needs.to_vec(),
            },
        );
        self.last_overlay = Some(sent.clone());
        self.running_inputs = Some(inputs.clone());
        self.status.tunnel = Some(tunnel_status(profile));
    }

    /// The worker's parts with its overlay, serving only the Gateways whose port is held.
    fn worker_parts(
        &self,
        mut parts: crate::resolve::WorkerConfigParts,
        overlay: OverlayWire,
    ) -> crate::resolve::WorkerConfigParts {
        parts.policy.overlay = Some(overlay);
        parts.gateways.retain(|g| self.held.contains_key(&g.id));
        parts
    }

    async fn start_generation(&mut self) {
        self.set_phase(Phase::Starting);
        let Some(mut resolved) = self.resolve_for_start().await else {
            return;
        };
        let Some(overlay_revision) = self.overlay_revision_for(&resolved).await else {
            return;
        };
        let Some(generation) = self.reserve(&resolved).await else {
            return;
        };
        self.note_key(&resolved.key_fingerprint);

        if let Err(f) = self.sync_listeners(Some(&resolved.gateways)).await {
            self.schedule_retry(f);
            return;
        }
        // Strict mode: the worker runs in the Instance's sandbox (kept from an earlier
        // generation when it is intact and still fits the profile).
        let Some(strict) = self.strict_for_start(&resolved).await else {
            return;
        };
        // The blocklist overlay travels in Configure: in force before the gate can open.
        let (sent, policy_status) = overlay_status(overlay_revision, &resolved);
        drop(std::mem::take(&mut resolved.overlay.lists));
        // Hand the held listeners to the worker: stop refusing on them first. A Gateway whose
        // port is taken stays out of this generation; it is reported and retried on its own.
        let overlay = OverlayWire {
            revision: overlay_revision,
            digest: sent.digest.clone(),
            set: std::mem::take(&mut resolved.overlay.set),
        };
        let revisions = resolved.revisions();
        let parts = self.worker_parts(resolved.worker, overlay);
        let Some(mut fds) = self.hand_over_listeners(&parts.gateways) else {
            return;
        };

        let served: HashMap<_, _> = parts.gateways.iter().map(|g| (g.id, g.clone())).collect();
        let bandwidth = caps_of(&parts.limits);
        let transport = first_transport(parts.transport.clone());
        let parts_limits = parts.limits.clone();
        let (forwards_blocked, forward_wires) = self.forwards_for(&resolved.profile).await;
        let connector = self.connector_path(generation);
        let config = self.worker_config(
            generation,
            parts,
            &resolved.key_fingerprint,
            &connector,
            strict.as_ref().map(|s| s.wire.clone()),
            forward_wires.clone(),
        );
        let entry = strict.map(|s| {
            fds.extend(s.fds);
            s.entry
        });
        let Some((handle, cgroup, resources)) = self
            .spawn_in_cgroup(generation, config, fds, entry, &parts_limits)
            .await
        else {
            return;
        };
        let security_id = resolved.security.as_ref().map(|s| s.id);
        self.status.running = Some(RunningInfo {
            policy: Some(policy_status),
            resources: Some(resources),
            // Installed during Configure, which the worker answered.
            bandwidth: Some(bandwidth),
            ..started_info(generation, handle.pid, revisions)
        });
        self.record_generation(
            &resolved.spec.name,
            &resolved.needs,
            &resolved.inputs,
            &resolved.profile,
            security_id,
            &sent,
        );
        let live = Live {
            handle,
            connector,
            served,
            generation,
            intent_revision: self.status.intent.intent_revision,
            permit: None,
            tunnel_up: false,
            probe_ok: false,
            ready: false,
            started: Instant::now(),
            degraded_since: None,
            security_id,
            security_revision: revisions.security,
            max_bans: vpn_domain::effective_auto_ban(resolved.security.as_ref()).max_bans,
            overlay: sent,
            unbans: Vec::new(),
            bandwidth,
            transport,
            kernel_limits: None,
            cgroup,
            forwards: live_forwards(forward_wires),
            forwards_blocked,
        };
        self.go_live(live).await;
    }

    /// Tell the configured worker to start: the generation is live and connecting.
    async fn go_live(&mut self, mut live: Live) {
        if live.handle.send(&ToWorker::Start).await.is_err() {
            self.live = Some(live);
            self.fail_generation(fault(
                "WORKER_EXITED",
                tr!(
                    "The worker exited while starting",
                    "worker 在啟動時結束",
                    "worker が起動中に終了しました"
                ),
            ))
            .await;
            return;
        }
        live.started = Instant::now();
        self.live = Some(live);
        self.tune_sandbox().await;
        self.set_phase(Phase::Connecting);
    }

    /// A DNS probe's verdict from the worker: the connection's DNS status, and readiness.
    /// `ok`: the tunnel answered (readiness and liveness evidence) — with `dns.interrupted` that
    /// is its fresh `WireGuard` session, not a resolved name, so DNS is not healthy then.
    async fn on_probe(&mut self, ok: bool, inconclusive: bool, dns: ProbeDns) {
        let before = self.status.dns.as_ref();
        if inconclusive {
            // The probe did not run (local limit): no verdict on the tunnel either way.
            self.status.dns = Some(DnsStatus {
                healthy: before.and_then(|d| d.healthy),
                last_probe_at: Some(Timestamp::now()),
                last_error: dns.error,
                fallback: before.and_then(|d| d.fallback.clone()),
                interrupted: before.and_then(|d| d.interrupted.clone()),
            });
            self.emit();
            return;
        }
        self.log_probe(before, ok, &dns);
        self.status.dns = Some(DnsStatus {
            healthy: Some(ok && dns.interrupted.is_none()),
            last_probe_at: Some(Timestamp::now()),
            last_error: dns.error,
            fallback: dns.fallback,
            interrupted: dns.interrupted,
        });
        if ok {
            if let Some(l) = self.live.as_mut() {
                l.probe_ok = true;
            }
            self.maybe_activate().await;
        } else {
            self.emit();
        }
    }

    /// A probe's verdict in the log, once per change (probes repeat every few seconds): the
    /// fallback, the interruption and a failure at warn with the reason server by server, the way
    /// back at info.
    fn log_probe(&self, before: Option<&DnsStatus>, ok: bool, dns: &ProbeDns) {
        let id = &self.id;
        let was_fallback = before.and_then(|d| d.fallback.as_ref());
        let was_interrupted = before.and_then(|d| d.interrupted.as_ref());
        let was_error = before.and_then(|d| d.last_error.as_ref());
        if let Some(why) = dns.fallback.as_ref().filter(|w| was_fallback != Some(*w)) {
            tracing::warn!(
                instance = %id,
                reason = %why.en,
                "DNS profile failing: the WireGuard profile's resolvers stand in"
            );
        }
        if let Some(why) = dns
            .interrupted
            .as_ref()
            .filter(|w| was_interrupted != Some(*w))
        {
            tracing::warn!(
                instance = %id,
                reason = %why.en,
                "DNS profile failing: names fail until one of its servers answers (on_failure: fail)"
            );
        }
        if !ok {
            if let Some(why) = dns.error.as_ref().filter(|w| was_error != Some(*w)) {
                tracing::warn!(instance = %id, reason = %why.en, "the DNS health probe failed");
            }
        } else if dns.fallback.is_none() && dns.interrupted.is_none() {
            if was_fallback.is_some() || was_interrupted.is_some() {
                tracing::info!(instance = %id, "the DNS profile's servers answer again");
            } else if before.and_then(|d| d.healthy) == Some(false) {
                tracing::info!(instance = %id, "the DNS health probe passes again");
            }
        }
    }

    /// The worker opened the gate for `permit`: Ready, if that is the current permit.
    async fn on_ready(&mut self, permit: u64) {
        let matches = self.live.as_ref().is_some_and(|l| l.permit == Some(permit));
        if matches {
            if let Some(l) = self.live.as_mut() {
                l.ready = true;
                l.degraded_since = None;
            }
            self.attempt = 0;
            self.status.recovery.unreachable_attempts = 0;
            if let Some(r) = self.status.running.as_mut() {
                r.ready_at.get_or_insert_with(Timestamp::now);
            }
            self.status.health = Health::Healthy;
            self.status.recovery.next_retry_at = None;
            // Ready means the worker confirmed the gate is open for this permit.
            self.status.enforcement = Enforcement::TunnelOnly;
            self.set_phase(Phase::Ready);
            // Forwards whose App is verified may listen now.
            self.check_forwards().await;
        }
    }

    /// A strict worker's SOCKS5 UDP association needs a relay socket on the host's loopback.
    async fn on_relay_request(&mut self, id: u64, client_ip: IpAddr) {
        // A strict worker's SOCKS5 UDP association needs a relay socket on the host's
        // loopback; only a loopback address is ever bound.
        let Some(live) = self.live.as_mut() else {
            return;
        };
        let sent = match strict_sandbox::relay_socket(client_ip) {
            Ok(socket) => {
                live.handle
                    .send_with_fds(&ToWorker::Relay { id }, &[socket.as_fd()])
                    .await
            }
            Err(e) => {
                live.handle
                    .send(&ToWorker::RelayFailed {
                        id,
                        message: e.to_string(),
                    })
                    .await
            }
        };
        if sent.is_err() {
            tracing::debug!(instance = %self.id, "relay socket not delivered");
        }
    }

    /// The worker lifted a ban: answer the unbans waiting for it.
    fn on_unbanned(&mut self, source: IpAddr) {
        // Banned or not (it may have just expired): the worker does not ban it now.
        if let Some(live) = self.live.as_mut() {
            let source = vpn_domain::validation::ban_scope(source);
            let (done, waiting): (Vec<_>, Vec<_>) =
                live.unbans.drain(..).partition(|(s, _)| *s == source);
            live.unbans = waiting;
            for (_, reply) in done {
                let _ = reply.send(UnbanEffect::Applied);
            }
        }
    }

    async fn on_worker_event(&mut self, ev: WorkerEvent) {
        let msg = match ev {
            WorkerEvent::Msg(m) => m,
            WorkerEvent::Closed => {
                self.fail_generation(fault(
                    "WORKER_EXITED",
                    tr!(
                        "The VPN worker process exited",
                        "VPN worker 程序結束",
                        "VPN worker プロセスが終了しました"
                    ),
                ))
                .await;
                return;
            }
        };
        match msg {
            FromWorker::TunnelUp { endpoint } => {
                if let Some(l) = self.live.as_mut() {
                    l.tunnel_up = true;
                }
                if let Some(t) = self.status.tunnel.as_mut() {
                    t.endpoint = endpoint.to_string();
                    t.last_handshake_at = Some(Timestamp::now());
                }
                self.set_phase(Phase::Verifying);
                self.maybe_activate().await;
            }
            FromWorker::Probe {
                ok,
                latency_ms: _,
                error,
                inconclusive,
                fallback,
                interrupted,
            } => {
                let dns = ProbeDns {
                    error,
                    fallback,
                    interrupted,
                };
                self.on_probe(ok, inconclusive, dns).await;
            }
            FromWorker::Ready { permit } => self.on_ready(permit).await,
            FromWorker::Status(s) => self.on_sample(*s),
            FromWorker::Degraded { code, message } => {
                if let Some(l) = self.live.as_mut() {
                    l.degraded_since.get_or_insert_with(Instant::now);
                }
                self.status.health = Health::Degraded;
                self.status.recovery.last_fault = Some(fault(&code, message));
                self.set_phase(Phase::Degraded);
            }
            FromWorker::Recovered => {
                // Probes pass again; open only with fresh evidence and an unchanged intent.
                if let Some(l) = self.live.as_mut() {
                    l.probe_ok = true;
                    l.degraded_since = None;
                    l.ready = false;
                    l.permit = None;
                }
                self.maybe_activate().await;
            }
            FromWorker::Fatal { code, message } => {
                self.fail_generation(fault(&code, message)).await;
            }
            FromWorker::RelayRequest { id, client_ip } => {
                self.on_relay_request(id, client_ip).await;
            }
            FromWorker::OverlayApplied { revision, digest } => {
                self.on_overlay_applied(revision, digest).await;
            }
            FromWorker::OverlayRejected { revision, reason } => {
                self.on_overlay_rejected(revision, reason);
            }
            FromWorker::Banned(report) => self.on_banned(report).await,
            FromWorker::BandwidthApplied(caps) => {
                if let Some(r) = self.status.running.as_mut() {
                    r.bandwidth = Some(caps);
                }
                self.status.observed_at = Timestamp::now();
                self.emit();
            }
            FromWorker::Unbanned { source, found: _ } => self.on_unbanned(source),
            FromWorker::Stopped
            | FromWorker::Pong { .. }
            | FromWorker::Configured
            | FromWorker::Hello { .. } => {}
        }
    }

    fn policy_status_mut(&mut self) -> Option<&mut PolicyStatus> {
        self.status.running.as_mut().and_then(|r| r.policy.as_mut())
    }

    /// The worker installed an overlay. Only the one sent last counts; a different digest for it
    /// means the worker enforces something else than intended: never trusted, rebuilt.
    async fn on_overlay_applied(&mut self, revision: u64, digest: String) {
        let Some(sent) = self.live.as_ref().map(|l| l.overlay.clone()) else {
            return;
        };
        if revision < sent.revision {
            // An earlier overlay; the one sent since is on its way.
            return;
        }
        if revision != sent.revision || digest != sent.digest {
            self.fail_generation(fault(
                "OVERLAY_MISMATCH",
                tr!(
                    "The worker reported an IP blocklist other than the one sent; rebuilding the connection",
                    "worker 回報套用的 IP 封鎖清單與送出的不同，重新建立連線",
                    "worker が適用を報告した IP ブロックリストが送ったものと異なるため、接続を作り直します"
                ),
            ))
            .await;
            return;
        }
        if let Some(p) = self.policy_status_mut() {
            p.applied_revision = Some(revision);
            p.applied_digest = Some(digest);
            p.applied_at = Some(Timestamp::now());
            p.error = None;
        }
        self.status.observed_at = Timestamp::now();
        self.emit();
    }

    /// The worker kept its previous overlay.
    fn on_overlay_rejected(&mut self, revision: u64, reason: impl Into<Text>) {
        let sent = self.live.as_ref().map(|l| l.overlay.revision);
        if sent != Some(revision) {
            return;
        }
        let reason: Text = reason.into();
        tracing::warn!(instance = %self.id, revision, reason = %reason.en, "overlay not applied by the worker");
        if let Some(p) = self.policy_status_mut() {
            p.error = Some(kept_overlay(reason));
        }
        self.status.observed_at = Timestamp::now();
        self.emit();
    }

    /// The security profile the running generation follows (`Some(None)`: the default policy);
    /// `None` when it is gone or cannot be read (the enforced overlay is kept).
    async fn running_security(
        &self,
        security_id: Option<SecurityProfileId>,
    ) -> Option<Option<SecurityProfile>> {
        let Some(id) = security_id else {
            return Some(None);
        };
        match self.ctx.store.get(id.to_string()).await {
            Ok(Some(s)) => Some(Some(s)),
            // Deleted after the Instance switched away from it: keep what is enforced.
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(instance = %self.id, error = %e, "security profile not read; overlay kept");
                None
            }
        }
    }

    /// The latest overlay was not applied (the previous one stays): say why.
    fn overlay_not_applied(&mut self, message: &Text) {
        if let Some(p) = self.policy_status_mut() {
            p.error = Some(message.clone());
        }
        self.emit();
    }

    /// A blocklist or a security profile's list selection was saved: compile this generation's
    /// overlay again and send it when it changed. The base rules stay as started.
    async fn refresh_overlay(&mut self) {
        let Some(live) = self.live.as_ref() else {
            return;
        };
        let (security_id, previous) = (live.security_id, live.overlay.clone());
        let Some(security) = self.running_security(security_id).await else {
            return;
        };
        let needs = self
            .ctx
            .running
            .lock()
            .get(&self.id)
            .map_or_default(|r| r.needs.clone());
        let compiled =
            match crate::policy::compile(&self.ctx.store, security.as_ref(), &needs).await {
                Ok(c) => c,
                Err(e) => {
                    self.overlay_not_applied(&kept_overlay(e.message()));
                    return;
                }
            };
        if let Some((list, need)) = compiled.conflict(&needs) {
            // Saves are checked against running generations, so this only follows an older
            // overlay; never drop the user's rule silently.
            let (list, ip) = (&list.name, need.ip);
            let message = tr!(
                "The latest IP blocklist was not applied: “{list}” contains {ip} ({what}), which this connection needs",
                "最新的 IP 封鎖清單未套用：「{list}」包含這條連線需要的 {ip}（{what}）",
                "最新の IP ブロックリストは適用されていません。「{list}」に、この接続が必要とする {ip}（{what}）が含まれています";
                what = need.kind.label()
            );
            self.overlay_not_applied(&message);
            return;
        }
        let lists = compiled.applied();
        if compiled.same_as(&previous.lists, &previous.digest) {
            // Same content; names may have changed.
            if let Some(p) = self.policy_status_mut() {
                p.blocklists = lists;
            }
            return;
        }
        let revision = match self.ctx.store.next_policy_revision().await {
            Ok(r) => r,
            Err(e) => {
                self.overlay_not_applied(&kept_overlay(e.to_api().message));
                return;
            }
        };
        let sent = SentOverlay {
            revision,
            digest: compiled.digest.clone(),
            lists: lists.clone(),
        };
        let (v4, v6) = (
            u32::try_from(compiled.set.v4_ranges().len()).unwrap_or(u32::MAX),
            u32::try_from(compiled.set.v6_ranges().len()).unwrap_or(u32::MAX),
        );
        let wire = ToWorker::SetOverlay(Box::new(OverlayWire {
            revision,
            digest: compiled.digest.clone(),
            set: compiled.set,
        }));
        let Some(live) = self.live.as_mut() else {
            return;
        };
        if live.handle.send(&wire).await.is_err() {
            // The worker is gone; its Closed event follows and the next generation compiles
            // the overlay afresh.
            return;
        }
        drop(wire);
        tracing::info!(instance = %self.id, revision, "blocklist overlay sent");
        live.overlay = sent.clone();
        self.last_overlay = Some(sent);
        if let Some(p) = self.policy_status_mut() {
            p.revision = revision;
            p.digest = compiled.digest;
            p.blocklists = lists;
            p.v4_ranges = v4;
            p.v6_ranges = v6;
            p.error = None;
        }
        self.status.observed_at = Timestamp::now();
        self.emit();
    }

    /// The worker's auto-ban engine banned a source: keep it (an Instance holds at most its
    /// `max_bans` active bans) so a new generation carries it over and the user can lift it.
    async fn on_banned(&self, report: BanReport) {
        let Some(live) = self.live.as_ref() else {
            return;
        };
        // An IPv4 address, or an IPv6 /64.
        let source = vpn_domain::validation::ban_scope(report.source);
        if !vpn_store::ban_source_ok(source) || report.ban_secs == 0 {
            tracing::warn!(instance = %self.id, "worker reported an invalid ban; ignored");
            return;
        }
        let now = Timestamp::now();
        let ban = Ban {
            id: BanId::new(),
            instance_id: self.id,
            source,
            reason: report
                .reason
                .map(|_, reason| reason.chars().take(MAX_BAN_REASON).collect()),
            security_profile_id: live.security_id,
            security_profile_revision: live.security_revision,
            policy_revision: report.policy_revision,
            generation: live.generation,
            created_at: now,
            expires_at: now.plus(Duration::from_secs(u64::from(
                report.ban_secs.min(MAX_BAN_SECS),
            ))),
        };
        // Addresses never appear in logs.
        match self.ctx.store.add_ban(ban, live.max_bans).await {
            Ok(BanAdded::New(_)) => tracing::info!(instance = %self.id, "auto-ban recorded"),
            Ok(BanAdded::Renewed(_)) => tracing::info!(instance = %self.id, "auto-ban renewed"),
            Ok(BanAdded::Full) => {
                tracing::warn!(instance = %self.id, "auto-ban not recorded: the ban limit is reached");
            }
            Err(e) => tracing::warn!(instance = %self.id, error = %e, "auto-ban not recorded"),
        }
    }

    /// Lift a ban on the running worker; the answer waits for its confirmation.
    async fn unban(&mut self, source: IpAddr, reply: oneshot::Sender<UnbanEffect>) {
        let Some(live) = self.live.as_mut() else {
            let _ = reply.send(UnbanEffect::NotRunning);
            return;
        };
        if live.unbans.len() >= MAX_PENDING_UNBANS {
            let _ = reply.send(UnbanEffect::Unconfirmed);
            return;
        }
        let source = vpn_domain::validation::ban_scope(source);
        if live.handle.send(&ToWorker::Unban { source }).await.is_ok() {
            live.unbans.push((source, reply));
        } else {
            let _ = reply.send(UnbanEffect::NotRunning);
        }
    }

    /// A generation ends: nothing of it is enforced any more.
    fn forget_live(&self, live: &mut Live) {
        for (_, reply) in live.unbans.drain(..) {
            let _ = reply.send(UnbanEffect::NotRunning);
        }
        self.ctx.running.lock().remove(&self.id);
    }

    /// The only place the payload gate is opened.
    async fn maybe_activate(&mut self) {
        let Some(live) = self.live.as_ref() else {
            return;
        };
        if !(live.tunnel_up && live.probe_ok) || live.permit.is_some() {
            return;
        }
        let expected = live.intent_revision;
        // Re-read the durable intent right before opening: a Stop that raced us wins, also
        // while it still waits in the mailbox and its latch is not on disk (the hold).
        self.refresh_intent().await;
        if !self.wants_running() || self.status.intent.intent_revision != expected {
            let held = self.hold.get();
            let (emergency, reason) = match (held.stopped, held.emergency) {
                (true, true) => (true, "EMERGENCY_STOP"),
                (true, false) => (false, "STOPPED"),
                _ => (false, "INTENT_CHANGED"),
            };
            self.stop_worker(emergency, reason).await;
            self.reconcile().await;
            return;
        }
        let permit: u64 = rand::rng().random();
        let Some(live) = self.live.as_mut() else {
            return;
        };
        live.permit = Some(permit);
        if live
            .handle
            .send(&ToWorker::Activate { permit })
            .await
            .is_err()
        {
            self.fail_generation(fault(
                "WORKER_EXITED",
                tr!(
                    "The worker exited before the connection opened",
                    "worker 在開通前結束",
                    "worker が接続の開通前に終了しました"
                ),
            ))
            .await;
        }
    }

    fn on_sample(&mut self, s: WorkerStatus) {
        if let Some(t) = self.status.tunnel.as_mut() {
            t.wg_rx_bytes = Counter(s.wg_rx_bytes);
            t.wg_tx_bytes = Counter(s.wg_tx_bytes);
            t.last_handshake_at = s
                .last_handshake_ms_ago
                .map(|ms| Timestamp(Timestamp::now().0 - Duration::from_millis(ms)));
            if let Some(ep) = s.endpoint {
                t.endpoint = ep.to_string();
            }
        }
        let serving = matches!(s.gate, Some(GateWire::Open));
        self.status.enforcement = match s.gate {
            Some(GateWire::Open) => Enforcement::TunnelOnly,
            Some(_) => Enforcement::Blocked,
            None => Enforcement::Unknown,
        };
        self.status.gateways = self
            .held
            .keys()
            .map(|id| {
                let g = s.gateways.iter().find(|g| g.id == Some(*id));
                GatewayRuntime {
                    gateway_id: *id,
                    state: if serving {
                        GatewayState::Serving
                    } else {
                        GatewayState::Blocked
                    },
                    active_tcp: g.map_or(0, |g| u32::try_from(g.tcp_active).unwrap_or(u32::MAX)),
                    active_udp: g.map_or(0, |g| u32::try_from(g.udp_active).unwrap_or(u32::MAX)),
                    error: None,
                }
            })
            .collect();
        if let (Some(live), Some(running), Some(report)) = (
            self.live.as_ref(),
            self.status.running.as_mut(),
            s.transport.as_ref(),
        ) && let Some(now) = live.transport_status(report)
        {
            running.transport = Some(now);
        }
        self.status.observed_at = Timestamp::now();
        self.on_forward_reports(&s.forwards);
        let generation = s.generation;
        // Persisted in the background: never waits for the Store.
        self.ctx.metrics.offer(self.id, &s);
        let _ = self.ctx.events.send(ManagerEvent::Sample {
            instance_id: self.id,
            generation,
            sample: Box::new(s),
        });
        // Status snapshots at most once per 2 s from samples alone.
        let due = self
            .last_sample_emit
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(2));
        if due {
            self.last_sample_emit = Some(Instant::now());
            // Memory in use and OOM kills of the worker's cgroup, at the same pace.
            if let Some((leaf, true)) = self.live.as_ref().and_then(|l| l.cgroup.as_ref())
                && let Some(r) = self.status.running.as_mut()
            {
                r.resources = Some(crate::limits::in_leaf(leaf, true));
            }
            self.emit();
        }
    }

    /// The reaped worker's cgroup goes. Returns its memory limit (MiB) when the kernel killed the
    /// worker for exceeding it.
    fn release_cgroup(&self, cgroup: Option<(Leaf, bool)>) -> Option<u64> {
        let (leaf, _) = cgroup?;
        let oom = leaf.oom_kills().unwrap_or(0) > 0;
        let limit = leaf.enforced(LimitKind::Memory);
        if let Err(e) = leaf.remove() {
            tracing::warn!(instance = %self.id, cgroup = leaf.rel(), error = %e, "worker cgroup not removed");
        }
        oom.then(|| limit.unwrap_or(0) / (1024 * 1024))
    }

    /// Tear the current generation down and schedule the next attempt.
    async fn fail_generation(&mut self, mut f: Fault) {
        // The peer never answered this attempt: its endpoint failed (not a passing outage of a
        // tunnel that was up). Counted until the connection is ready again or stopped.
        let unreachable = f.code == "HANDSHAKE_FAILED"
            || (f.code == "START_TIMEOUT" && self.live.as_ref().is_some_and(|l| !l.tunnel_up));
        if unreachable {
            self.status.recovery.unreachable_attempts =
                self.status.recovery.unreachable_attempts.saturating_add(1);
        }
        if let Some(mut live) = self.live.take() {
            self.forget_live(&mut live);
            live.handle.kill().await;
            if let Some(mib) = self.release_cgroup(live.cgroup.take())
                && f.code == "WORKER_EXITED"
            {
                f = fault(
                    "WORKER_OOM_KILLED",
                    tr!(
                        "The VPN worker used more memory than its limit ({mib} MiB) and the system ended it; it is rebuilt automatically. If this happens often, raise “Connection buffer” in the connection settings",
                        "VPN worker 使用的記憶體超過上限（{mib} MiB），已被系統結束；會自動重新建立。若經常發生，可在連線設定調高「連線緩衝」",
                        "VPN worker のメモリ使用量が上限（{mib} MiB）を超えたため、システムが終了させました。自動で作り直します。頻繁に起こる場合は、接続設定の「接続バッファー」を引き上げてください"
                    ),
                );
            }
            // A worker that died without its own cleanup leaves its generation's connector
            // socket behind; nobody else uses that path.
            let _ = std::fs::remove_file(&live.connector);
            self.publish_forwards(true);
        }
        self.restart_reject_loops(RejectReason::Reconnecting);
        self.status.health = Health::Unhealthy;
        self.refresh_intent().await;
        if self.wants_running() {
            self.schedule_retry(f);
        } else {
            self.status.recovery.last_fault = Some(f);
            self.settle_stopped();
        }
    }

    async fn stop_worker(&mut self, emergency: bool, reason: &str) {
        if let Some(mut live) = self.live.take() {
            self.forget_live(&mut live);
            let tighten = if emergency {
                ToWorker::Seal {
                    reason: reason.into(),
                }
            } else {
                ToWorker::Tighten {
                    reason: reason.into(),
                }
            };
            let _ = live.handle.send(&tighten).await;
            let _ = live
                .handle
                .send(&ToWorker::ResetPayload {
                    reason: reason.into(),
                })
                .await;
            let grace = if emergency {
                Duration::ZERO
            } else {
                Duration::from_millis(500)
            };
            tracing::info!(instance = %self.id, generation = live.generation, reason, "stopping worker");
            live.handle.stop(grace).await;
            // The process is reaped: its descriptors (and key lock) are gone, its cgroup empty.
            self.release_cgroup(live.cgroup.take());
            let _ = std::fs::remove_file(&live.connector);
            self.publish_forwards(true);
        }
        // No worker of this Instance is left (reaped above, or none during a back-off): its
        // identity leases go, whichever key they name. Should this write fail, the lease of a
        // stopped Instance still blocks no other one (`Store::reserve_generation`).
        if let Err(e) = self.ctx.store.release_identities(self.id).await {
            tracing::warn!(instance = %self.id, error = %e, "identity lease release deferred");
        }
        self.status.enforcement = Enforcement::Blocked;
        self.status.health = Health::Unknown;
        self.status.running = None;
        self.running_inputs = None;
        self.status.dns = None;
        self.restart_reject_loops(RejectReason::Stopped);
    }

    /// The sandbox for this start, and what the worker needs to serve it.
    async fn prepare_strict(
        &mut self,
        profile: &RuntimeProfile,
    ) -> Result<StrictStart, SandboxFailure> {
        self.ensure_sandbox(profile).await?;
        let retry = |e: std::io::Error| {
            SandboxFailure::Retry(fault("SANDBOX_START", Text::of_io_error(&e)))
        };
        let Some(lease) = self.sandbox.as_ref() else {
            return Err(SandboxFailure::Retry(fault(
                "SANDBOX_START",
                tr!(
                    "The sandbox is unavailable",
                    "sandbox 無法使用",
                    "サンドボックスを利用できません"
                ),
            )));
        };
        // The WireGuard socket is made here, in the host's network namespace, pinned to the
        // endpoint; the worker could not make one there.
        let underlay =
            vpn_platform::sandbox::underlay_socket(profile.peer.endpoint).map_err(retry)?;
        let fds = vec![
            lease.tun().map_err(retry)?,
            underlay,
            lease.dns_udp().map_err(retry)?,
            lease.dns_tcp().map_err(retry)?,
        ];
        Ok(StrictStart {
            entry: lease.worker_entry().map_err(retry)?,
            fds,
            wire: StrictWire {
                tun_name: lease.identity().tun_name.clone(),
                sandbox_epoch: lease.identity().epoch,
            },
        })
    }

    /// Keep the sandbox if it is intact and fits the profile; otherwise tear it down (Apps
    /// first) and build a new one with a higher epoch.
    async fn ensure_sandbox(&mut self, profile: &RuntimeProfile) -> Result<(), SandboxFailure> {
        if let Some(lease) = self.sandbox.as_ref() {
            let problem = if !strict_sandbox::fits(lease, profile) {
                Some("PROFILE_CHANGED")
            } else if let Err(e) = lease.check().await {
                tracing::warn!(instance = %self.id, error = %e, "sandbox not intact");
                Some("NOT_INTACT")
            } else {
                None
            };
            match problem {
                None => return Ok(()),
                Some(reason) => self.teardown_sandbox(reason).await,
            }
        }
        // Shared: a recovery never meets a sandbox half-built, and nothing is built while it
        // tears a leftover down.
        let ctx = self.ctx.clone();
        let _gate = ctx.spawn_gate.read().await;
        if let Some(lease) = strict_sandbox::leftover(&self.ctx, self.id).await {
            if strict_sandbox::fits(&lease, profile) && lease.check().await.is_ok() {
                self.adopt(lease);
                return Ok(());
            }
            let grace = strict_sandbox::teardown_grace(&self.ctx, &self.id.to_string()).await;
            lease.teardown(grace).await;
        }
        // A stopping manager builds none: what ended the old one (a signal to the whole service,
        // say) ends this process too, and the new one would be left behind with no manager.
        if self.ctx.is_closing() {
            return Err(SandboxFailure::Retry(fault(
                "MANAGER_STOPPING",
                tr!(
                    "The core service is stopping and builds no more strict isolation sandboxes",
                    "核心服務正在停止，不再建立嚴格隔離 sandbox",
                    "コアサービスが停止中のため、厳格な分離のサンドボックスはこれ以上作成しません"
                ),
            )));
        }
        self.sandbox_epoch = strict_sandbox::next_epoch(self.sandbox_epoch);
        let spec = strict_sandbox::spec(&self.ctx, self.id, self.sandbox_epoch, profile);
        let failure = match SandboxLease::create(&self.ctx.exe, spec).await {
            Ok(lease) => {
                self.hold_sandbox(lease);
                return Ok(());
            }
            Err(e) if e.is_blocked() => SandboxFailure::Blocked(fault(
                "SANDBOX_BLOCKED",
                tr!(
                    "Could not build the strict isolation sandbox: {e}",
                    "無法建立嚴格隔離 sandbox：{e}",
                    "厳格な分離のサンドボックスを作成できませんでした：{e}";
                    e = e.text()
                ),
            )),
            Err(e) => SandboxFailure::Retry(fault("SANDBOX_START", e.text())),
        };
        let (SandboxFailure::Blocked(f) | SandboxFailure::Retry(f)) = &failure;
        self.ctx.strict_apps.failed(self.id, f.message.clone());
        Err(failure)
    }

    /// The sandbox's holder exited: its Apps went with it and nothing can start in it any
    /// more, though a worker in it would go on carrying traffic. The lease is let go at once
    /// (no App is sent into a dead sandbox), and a new sandbox with a higher epoch follows: with
    /// the connection's next generation when a worker ran in it, right away otherwise.
    async fn on_holder_gone(&mut self) {
        let epoch = self.sandbox.as_ref().map(|l| l.identity().epoch);
        tracing::warn!(instance = %self.id, ?epoch, "sandbox holder exited");
        if self.live.is_some() {
            self.fail_generation(fault(
                "SANDBOX_LOST",
                tr!(
                    "The holder process of the strict isolation sandbox ended unexpectedly (the system ended it, or it crashed); the connection and the sandbox are rebuilt",
                    "嚴格隔離 sandbox 的 holder 程序意外結束（被系統結束或當掉），連線與 sandbox 重新建立",
                    "厳格な分離のサンドボックスの holder プロセスが予期せず終了しました（システムによる終了かクラッシュ）。接続とサンドボックスを作り直します"
                ),
            ))
            .await;
        }
        self.teardown_sandbox("HOLDER_GONE").await;
        self.keep_sandbox_ready().await;
        self.emit();
    }

    /// A strict connection keeps its sandbox while it does not run as well — closed: its Apps
    /// can start in it and stay offline until the connection runs. Builds it when missing.
    async fn keep_sandbox_ready(&mut self) {
        if self.sandbox.is_some() || self.live.is_some() {
            return;
        }
        let Ok(Some(spec)) = self
            .ctx
            .store
            .get::<InstanceSpec>(self.id.to_string())
            .await
        else {
            return;
        };
        if !spec.strict {
            return;
        }
        let Ok(Some(profile)) = self
            .ctx
            .store
            .get::<RuntimeProfile>(spec.profile_id.to_string())
            .await
        else {
            self.ctx.strict_apps.failed(
                self.id,
                tr!(
                    "The WireGuard profile of this connection was not found",
                    "找不到這條連線的 WireGuard 設定",
                    "この接続の WireGuard 設定が見つかりません"
                ),
            );
            return;
        };
        match self.ensure_sandbox(&profile).await {
            Ok(()) => self.emit(),
            Err(SandboxFailure::Blocked(f) | SandboxFailure::Retry(f)) => {
                tracing::warn!(instance = %self.id, code = %f.code, "sandbox not prepared");
            }
        }
    }

    /// Tear the sandbox down: its Apps get SIGTERM and up to the longest stop grace among them,
    /// then whatever is left is killed with it. Never while a worker runs in it.
    async fn teardown_sandbox(&mut self, reason: &str) {
        if let Some(lease) = self.release_sandbox() {
            let grace = strict_sandbox::teardown_grace(&self.ctx, &self.id.to_string()).await;
            tracing::info!(
                instance = %self.id,
                epoch = lease.identity().epoch,
                reason,
                grace_secs = grace.as_secs(),
                "tearing the sandbox down"
            );
            lease.teardown(grace).await;
        }
    }

    /// The connection left strict mode while no worker runs: its sandbox goes now rather than
    /// at the next start.
    async fn drop_unwanted_sandbox(&mut self) {
        if self.sandbox.is_none() || self.live.is_some() {
            return;
        }
        if let Ok(Some(spec)) = self
            .ctx
            .store
            .get::<InstanceSpec>(self.id.to_string())
            .await
            && !spec.strict
        {
            self.teardown_sandbox("STRICT_OFF").await;
            self.emit();
        }
    }

    /// Start a process in the sandbox, building it for the stored configuration if there is
    /// none yet (its Apps are then offline until the connection runs).
    async fn sandbox_spawn(&mut self, spec: SpawnSpec) -> Result<SandboxProcess, ApiError> {
        if self.sandbox.is_none() {
            let instance: InstanceSpec = self
                .ctx
                .store
                .get(self.id.to_string())
                .await
                .map_err(|e| e.to_api())?
                .ok_or_else(|| ApiError::not_found("Instance"))?;
            if !instance.strict {
                return Err(ApiError::new(
                    ErrorCode::InvalidState,
                    tr!(
                        "This connection does not have strict isolation turned on",
                        "這個連線沒有啟用嚴格隔離",
                        "この接続では厳格な分離が有効になっていません"
                    ),
                ));
            }
            let profile: RuntimeProfile = self
                .ctx
                .store
                .get(instance.profile_id.to_string())
                .await
                .map_err(|e| e.to_api())?
                .ok_or_else(|| {
                    ApiError::not_found(tr!(
                        "the WireGuard profile",
                        "WireGuard 設定",
                        "WireGuard 設定"
                    ))
                })?;
            match self.ensure_sandbox(&profile).await {
                Ok(()) => {}
                Err(SandboxFailure::Blocked(f)) => {
                    return Err(ApiError::new(ErrorCode::UnsupportedCapability, f.message));
                }
                Err(SandboxFailure::Retry(f)) => {
                    return Err(ApiError::new(ErrorCode::Unavailable, f.message));
                }
            }
        }
        let Some(lease) = self.sandbox.as_ref() else {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                tr!(
                    "The sandbox is unavailable",
                    "sandbox 無法使用",
                    "サンドボックスを利用できません"
                ),
            ));
        };
        lease.spawn(spec).await.map_err(|e| {
            if e.is_blocked() {
                ApiError::new(ErrorCode::UnsupportedCapability, e.text())
            } else {
                ApiError::new(
                    ErrorCode::InvalidRequest,
                    tr!(
                        "Could not start in the sandbox: {e}",
                        "無法在 sandbox 內啟動：{e}",
                        "サンドボックス内で起動できませんでした：{e}";
                        e = e.text()
                    ),
                )
            }
        })
    }

    fn schedule_retry(&mut self, f: Fault) {
        let delay = backoff(self.attempt);
        self.attempt += 1;
        self.retry_at = Some(tokio::time::Instant::now() + delay);
        self.status.recovery.attempt = self.attempt;
        self.status.recovery.next_retry_at = Some(Timestamp::now().plus(delay));
        self.status.recovery.last_fault = Some(f);
        self.status.running = None;
        self.running_inputs = None;
        self.set_phase(Phase::Reconnecting);
    }

    /// Bind listeners for `wanted` gateways (or the stored enabled set when `None`), release
    /// listeners of gateways that are gone or moved. A port that cannot be bound fails only its
    /// own Gateway: it is reported on that Gateway and retried with back-off; the others (and the
    /// Instance) go ahead. Errs only when the stored set cannot be read.
    async fn sync_listeners(&mut self, wanted: Option<&[GatewaySpec]>) -> Result<(), Fault> {
        let owned;
        let wanted: &[GatewaySpec] = if let Some(w) = wanted {
            w
        } else {
            owned = self
                .ctx
                .store
                .list::<GatewaySpec>()
                .await
                .map_err(|e| fault("STORE_UNAVAILABLE", e.to_api().message))?
                .into_iter()
                .filter(|g| g.instance_id == self.id && g.enabled)
                .collect::<Vec<_>>();
            &owned
        };
        self.held.retain(|id, h| {
            let keep = wanted.iter().any(|g| g.id == *id && g.port == h.port);
            if !keep && let Some(c) = h.reject.take() {
                c.cancel();
            }
            keep
        });
        self.failed
            .retain(|id, _| wanted.iter().any(|g| g.id == *id));
        for g in wanted {
            if self.held.contains_key(&g.id) {
                continue;
            }
            match bind_loopback(g.port) {
                Ok(listener) => {
                    self.failed.remove(&g.id);
                    self.held.insert(
                        g.id,
                        Held {
                            port: g.port,
                            listener,
                            reject: None,
                        },
                    );
                }
                Err(e) => {
                    tracing::warn!(instance = %self.id, gateway = %g.id, port = g.port, error = %e, "gateway port unavailable");
                    self.failed.insert(g.id, listener_error(g, &e));
                }
            }
        }
        if self.failed.is_empty() {
            self.gateway_retry_at = None;
            self.gateway_attempt = 0;
        } else if self.gateway_retry_at.is_none() {
            self.schedule_gateway_retry();
        }
        if self.live.is_none() {
            let reason = if self.wants_running() {
                RejectReason::Reconnecting
            } else {
                RejectReason::Stopped
            };
            self.restart_reject_loops(reason);
        }
        Ok(())
    }

    fn schedule_gateway_retry(&mut self) {
        let delay = backoff(self.gateway_attempt);
        self.gateway_attempt += 1;
        self.gateway_retry_at = Some(tokio::time::Instant::now() + delay);
    }

    /// Retry the Gateways whose port could not be bound, with their current stored settings.
    /// One that binds is served at once: handed to the running worker, or refused explicitly
    /// while there is none.
    async fn retry_gateways(&mut self) {
        let stored = match self.ctx.store.list::<GatewaySpec>().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(instance = %self.id, error = %e, "could not re-read gateways");
                self.schedule_gateway_retry();
                return;
            }
        };
        let ids: Vec<GatewayId> = self.failed.keys().copied().collect();
        for id in ids {
            // Deleted, disabled or moved away meanwhile: nothing left to retry.
            let Some(spec) = stored
                .iter()
                .find(|g| g.id == id && g.instance_id == self.id && g.enabled)
                .cloned()
            else {
                self.failed.remove(&id);
                continue;
            };
            match bind_loopback(spec.port) {
                Ok(listener) => {
                    self.failed.remove(&id);
                    self.serve_gateway(spec, listener).await;
                }
                Err(e) => {
                    self.failed.insert(id, listener_error(&spec, &e));
                }
            }
        }
        if self.failed.is_empty() {
            self.gateway_attempt = 0;
        } else {
            self.schedule_gateway_retry();
        }
        self.emit();
    }

    /// Serve a Gateway whose listener was bound after its generation started.
    async fn serve_gateway(&mut self, spec: GatewaySpec, listener: TcpListener) {
        let mut held = Held {
            port: spec.port,
            listener,
            reject: None,
        };
        match self.live.as_mut() {
            Some(live) => {
                let dup = match held.listener.try_clone() {
                    Ok(dup) => OwnedFd::from(dup),
                    Err(e) => {
                        self.failed.insert(spec.id, listener_error(&spec, &e));
                        return;
                    }
                };
                let wire = wire_of(&spec);
                let add = ToWorker::AddGateway(wire.clone());
                // If the worker is gone its Closed event follows, and the reject loops restart
                // on every held listener, this one included.
                if live
                    .handle
                    .send_with_fds(&add, &[dup.as_fd()])
                    .await
                    .is_ok()
                {
                    live.served.insert(spec.id, wire);
                    tracing::info!(instance = %self.id, gateway = %spec.id, "gateway added to the running worker");
                }
            }
            None => held.reject(if self.wants_running() {
                RejectReason::Reconnecting
            } else {
                RejectReason::Stopped
            }),
        }
        self.held.insert(spec.id, held);
    }

    /// Apply stored Gateway changes to the running worker at once: a deleted or disabled Gateway
    /// stops (listener closed, its connections end), a new or enabled one is bound and handed
    /// over, and a changed one is replaced (a new port frees the old one).
    async fn apply_gateways_live(&mut self) {
        let stored = match self.ctx.store.list::<GatewaySpec>().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(instance = %self.id, error = %e, "could not re-read gateways");
                return;
            }
        };
        let desired: HashMap<GatewayId, GatewaySpec> = stored
            .into_iter()
            .filter(|g| g.instance_id == self.id && g.enabled)
            .map(|g| (g.id, g))
            .collect();
        let Some(live) = self.live.as_mut() else {
            return;
        };
        let mut release = Vec::new();
        let outdated: Vec<GatewayId> = live
            .served
            .iter()
            .filter(|(id, wire)| desired.get(id).is_none_or(|g| wire_of(g) != **wire))
            .map(|(id, _)| *id)
            .collect();
        for id in outdated {
            let _ = live.handle.send(&ToWorker::RemoveGateway { id }).await;
            let port = live.served.remove(&id).map(|w| w.port);
            // Keep the listener only when the same port is handed over again below.
            if desired.get(&id).map(|g| g.port) != port {
                release.push(id);
            }
        }
        for id in release {
            if let Some(h) = self.held.remove(&id)
                && let Some(c) = h.reject
            {
                c.cancel();
            }
        }
        self.failed.retain(|id, _| desired.contains_key(id));
        for (id, g) in desired {
            let served = self
                .live
                .as_ref()
                .is_some_and(|l| l.served.contains_key(&id));
            if served || self.failed.contains_key(&id) {
                continue;
            }
            match self.held.remove(&id) {
                Some(h) => {
                    if let Some(c) = h.reject {
                        c.cancel();
                    }
                    self.serve_gateway(g, h.listener).await;
                }
                None => match bind_loopback(g.port) {
                    Ok(listener) => self.serve_gateway(g, listener).await,
                    Err(e) => {
                        tracing::warn!(instance = %self.id, gateway = %id, port = g.port, error = %e, "gateway port unavailable");
                        self.failed.insert(id, listener_error(&g, &e));
                    }
                },
            }
        }
        if !self.failed.is_empty() && self.gateway_retry_at.is_none() {
            self.schedule_gateway_retry();
        }
        self.emit();
    }

    fn restart_reject_loops(&mut self, reason: RejectReason) {
        for h in self.held.values_mut() {
            h.reject(reason);
        }
    }

    fn set_phase(&mut self, phase: Phase) {
        self.status.phase = phase;
        if !matches!(phase, Phase::Ready | Phase::Degraded) {
            self.status.enforcement = Enforcement::Blocked;
        }
        if matches!(phase, Phase::Stopped | Phase::RecoveryRequired) {
            self.status.recovery.next_retry_at = None;
            self.status.recovery.attempt = 0;
            self.status.recovery.unreachable_attempts = 0;
            self.attempt = 0;
        }
        self.status.observed_at = Timestamp::now();
        self.emit();
    }

    /// The Instance does not run: stopped — or, while it holds a stop carried over from before
    /// this manager started that nothing on disk confirms, closed in `recovery_required` until
    /// the user decides (the reason and the way out in its fault).
    fn settle_stopped(&mut self) {
        let held = self.hold.get();
        let shown = self
            .status
            .recovery
            .last_fault
            .as_ref()
            .is_some_and(|f| f.code == STOP_NOT_CONFIRMED);
        if held.unconfirmed {
            if !shown || self.status.phase != Phase::RecoveryRequired {
                self.status.recovery.last_fault = Some(unconfirmed_fault(held.emergency));
            }
            self.set_phase(Phase::RecoveryRequired);
        } else {
            if shown {
                // Decided: the user's stop, start or clearing is in force now.
                self.status.recovery.last_fault = None;
            }
            self.set_phase(Phase::Stopped);
        }
    }

    /// Held listeners: served by a ready worker, or refusing connections.
    fn listeners(&self) -> Vec<(GatewayId, u16, GatewayState)> {
        self.held
            .iter()
            .map(|(id, h)| {
                let serving = self
                    .live
                    .as_ref()
                    .is_some_and(|l| l.ready && l.served.contains_key(id));
                let state = if serving {
                    GatewayState::Serving
                } else {
                    GatewayState::Blocked
                };
                (*id, h.port, state)
            })
            .collect()
    }

    fn snapshot(&self) -> InstanceStatus {
        let mut s = self.status.clone();
        if s.gateways.is_empty() || self.live.is_none() {
            s.gateways = self
                .held
                .keys()
                .map(|id| GatewayRuntime {
                    gateway_id: *id,
                    state: if self.live.as_ref().is_some_and(|l| l.ready) {
                        GatewayState::Serving
                    } else {
                        GatewayState::Blocked
                    },
                    active_tcp: 0,
                    active_udp: 0,
                    error: None,
                })
                .collect();
        }
        // Gateways whose port could not be bound are reported on their own.
        s.gateways
            .extend(self.failed.iter().map(|(id, error)| GatewayRuntime {
                gateway_id: *id,
                state: GatewayState::Failed,
                active_tcp: 0,
                active_udp: 0,
                error: Some(error.clone()),
            }));
        s.sandbox = self.sandbox.as_ref().map(strict_sandbox::status);
        s
    }

    fn emit(&self) {
        let _ = self
            .ctx
            .events
            .send(ManagerEvent::Status(Box::new(self.snapshot())));
    }
}

// -------------------------------------------------------------------------------------------
// Port forwards
// -------------------------------------------------------------------------------------------

impl Actor {
    /// Read this Instance's forwards (and the evidence kept for them) from the Store.
    async fn reload_bindings(&mut self) {
        let bindings: Vec<ForwardBinding> = match self.ctx.store.list::<ForwardBinding>().await {
            Ok(all) => all
                .into_iter()
                .filter(|b| b.instance_id == self.id)
                .collect(),
            Err(e) => {
                tracing::warn!(instance = %self.id, error = %e, "port forwards not read");
                return;
            }
        };
        let evidence = self.ctx.store.forward_evidence().await.unwrap_or_default();
        self.forward_rt
            .retain(|id, _| bindings.iter().any(|b| b.id == *id));
        for b in &bindings {
            let rt = self.forward_rt.entry(b.id).or_default();
            // Evidence counts for the connection and tunnel port it was seen on.
            let stored = |udp: bool| {
                evidence
                    .iter()
                    .find(|e| {
                        e.binding_id == b.id
                            && e.udp == udp
                            && e.instance_id == b.instance_id
                            && e.tunnel_port == b.tunnel_port
                    })
                    .map(|e| e.observed_at)
            };
            let (tcp, udp) = (stored(false), stored(true));
            let moved = rt
                .published
                .as_ref()
                .is_some_and(|p| p.instance_id != b.instance_id)
                || self
                    .bindings
                    .iter()
                    .any(|old| old.id == b.id && old.tunnel_port != b.tunnel_port);
            if moved {
                rt.evidence = Evidence::default();
                rt.written = Evidence::default();
            }
            rt.evidence.merge(tcp, udp);
            rt.written.merge(tcp, udp);
        }
        self.bindings = bindings;
    }

    /// The enabled forwards as the worker runs them.
    fn forward_wires(&self) -> Vec<ForwardSpecWire> {
        self.bindings
            .iter()
            .filter(|b| b.enabled)
            .map(|b| ForwardSpecWire {
                id: b.id,
                protocol: b.protocol,
                tunnel_port: b.tunnel_port,
                max_connections: b.max_connections,
                // A change restarts the forward like any other: its connections end, and the
                // new ones get (or lose) the header from their first byte.
                proxy_protocol: b.proxy_protocol,
                // Likewise: the UDP flows end, and from then on the packet filter (or the relay)
                // carries the forward's UDP.
                udp_direct: b.udp_direct,
            })
            .collect()
    }

    /// A forward was saved or deleted: the running worker gets the new set at once (a changed
    /// forward loses its lease and starts over), then every target is checked again.
    async fn forwards_changed(&mut self) {
        self.reload_bindings().await;
        let wanted: HashMap<ForwardBindingId, ForwardSpecWire> = self
            .forward_wires()
            .into_iter()
            .map(|w| (w.id, w))
            .collect();
        if let Some(live) = self.live.as_mut()
            && live.forwards_blocked.is_none()
        {
            let outdated: Vec<(ForwardBindingId, Option<u64>)> = live
                .forwards
                .iter()
                .filter(|(id, f)| wanted.get(id) != Some(&f.wire))
                .map(|(id, f)| (*id, f.lease.as_ref().map(|g| g.id)))
                .collect();
            let added = wanted.keys().any(|id| !live.forwards.contains_key(id));
            for (binding, lease) in &outdated {
                if let Some(lease_id) = lease {
                    let _ = live
                        .handle
                        .send(&ToWorker::RevokeForward {
                            binding: *binding,
                            lease_id: *lease_id,
                        })
                        .await;
                }
                live.forwards.remove(binding);
            }
            if added || !outdated.is_empty() {
                for (id, wire) in &wanted {
                    live.forwards.entry(*id).or_insert_with(|| LiveForward {
                        wire: wire.clone(),
                        lease: None,
                        report: None,
                    });
                }
                let set = ToWorker::SetForwards(wanted.values().cloned().collect());
                if live.handle.send(&set).await.is_ok() {
                    tracing::info!(instance = %self.id, forwards = wanted.len(), "port forwards sent to the running worker");
                }
            }
        }
        self.check_forwards().await;
        self.publish_forwards(true);
    }

    /// Check every enabled forward's target, then grant or revoke leases to match. The host's
    /// sockets are looked at once for all the forwards that need it, not once per forward and
    /// protocol.
    async fn check_forwards(&mut self) {
        /// What one enabled forward's check goes by.
        struct Check {
            binding: ForwardBinding,
            app: Option<AppSpec>,
            view: crate::apps::TargetView,
            /// Whether this user's holders of the target port are needed: TCP, UDP.
            scan: [bool; 2],
        }
        if self.bindings.is_empty() {
            return;
        }
        let now = Instant::now();
        let enabled: Vec<ForwardBinding> = self
            .bindings
            .iter()
            .filter(|b| b.enabled)
            .cloned()
            .collect();
        let mut checks = Vec::with_capacity(enabled.len());
        for binding in enabled {
            let app: Option<AppSpec> =
                match self.ctx.store.get(binding.target_app_id.to_string()).await {
                    Ok(a) => a,
                    // Cannot tell: keep what the last check found.
                    Err(_) => continue,
                };
            let view = self.ctx.apps.target(binding.target_app_id);
            let needs = |udp: bool| {
                let carried = if udp {
                    binding.protocol.udp()
                } else {
                    binding.protocol.tcp()
                };
                let direct = udp && binding.udp_direct;
                carried && crate::forwards::needs_holders(&view, binding.target_port, udp, direct)
            };
            let scan = [needs(false), needs(true)];
            checks.push(Check {
                binding,
                app,
                view,
                scan,
            });
        }
        let mut ports: Vec<(u16, bool)> = checks
            .iter()
            .flat_map(|c| {
                [false, true]
                    .into_iter()
                    .filter(|udp| c.scan[usize::from(*udp)])
                    .map(|udp| (c.binding.target_port, udp))
            })
            .collect();
        ports.sort_unstable();
        ports.dedup();
        let apps: Vec<u32> = checks
            .iter()
            .filter(|c| c.scan.contains(&true))
            .filter_map(|c| match &c.view {
                crate::apps::TargetView::Running { pid, .. } => Some(*pid),
                _ => None,
            })
            .collect();
        let (holders, namespaces) = scan_holders(ports, apps).await;
        for check in checks {
            // Read from the App's own view: a strict App's sockets are its sandbox's.
            let netns = match &check.view {
                crate::apps::TargetView::Running { pid, .. } => {
                    namespaces.get(pid).copied().flatten()
                }
                _ => None,
            };
            let port = check.binding.target_port;
            let held = |udp: bool| {
                check.scan[usize::from(udp)]
                    .then(|| holders.get(&(port, udp)))
                    .flatten()
                    .map(|found| crate::forwards::same_namespace(found.clone(), netns))
            };
            let (tcp_holders, udp_holders) = (held(false), held(true));
            let result = crate::forwards::verify(&crate::forwards::Facts {
                binding: &check.binding,
                app: check.app.as_ref(),
                view: &check.view,
                tcp_holders: tcp_holders.as_deref(),
                udp_holders: udp_holders.as_deref(),
                now,
            });
            let rt = self.forward_rt.entry(check.binding.id).or_default();
            if let (Some(Ok(_)), Err(e)) = (&rt.check, &result) {
                tracing::info!(instance = %self.id, forward = %check.binding.id, code = e.code, "port forward target no longer verified");
            }
            rt.check = Some(result);
            rt.checked_at = Some(Timestamp::now());
        }
        self.apply_leases().await;
        self.publish_forwards(false);
    }

    /// Grant a lease to every forward of the running worker whose target is verified (once the
    /// generation was activated), replace one whose target moved, revoke the others.
    async fn apply_leases(&mut self) {
        enum Step {
            Grant(Verified),
            Revoke(u64),
        }
        let Some(live) = self.live.as_mut() else {
            return;
        };
        if live.forwards_blocked.is_some() {
            return;
        }
        let mut steps = Vec::new();
        for (id, f) in &live.forwards {
            let check = self.forward_rt.get(id).and_then(|rt| rt.check.as_ref());
            match (check, &f.lease) {
                (Some(Ok(v)), Some(g))
                    if g.verified.run_id == v.run_id
                        && g.verified.tcp == v.tcp
                        && g.verified.udp == v.udp => {}
                // Not activated yet (or re-activating after a tunnel problem): a lease it holds
                // stays, a new one waits.
                (Some(Ok(v)), _) if live.ready => steps.push((*id, Step::Grant(v.clone()))),
                (Some(Ok(_)), _) | (_, None) => {}
                (_, Some(g)) => steps.push((*id, Step::Revoke(g.id))),
            }
        }
        for (id, step) in steps {
            match step {
                Step::Grant(verified) => {
                    let lease_id: u64 = rand::rng().random();
                    // UDP straight into the sandbox connects to nothing: the App's own socket
                    // takes it, so the worker gets no address for it.
                    let direct = live.forwards.get(&id).is_some_and(|f| f.wire.udp_direct);
                    let wire = ForwardLeaseWire {
                        binding: id,
                        lease_id,
                        tcp: verified.tcp,
                        udp: verified.udp.filter(|_| !direct),
                    };
                    if live
                        .handle
                        .send(&ToWorker::GrantForward(wire))
                        .await
                        .is_err()
                    {
                        // The worker is gone; its Closed event follows.
                        return;
                    }
                    tracing::info!(instance = %self.id, forward = %id, "port forward lease granted");
                    if let Some(f) = live.forwards.get_mut(&id) {
                        f.lease = Some(Granted {
                            id: lease_id,
                            verified,
                            at: Timestamp::now(),
                        });
                    }
                }
                Step::Revoke(lease_id) => {
                    let _ = live
                        .handle
                        .send(&ToWorker::RevokeForward {
                            binding: id,
                            lease_id,
                        })
                        .await;
                    tracing::info!(instance = %self.id, forward = %id, "port forward lease revoked");
                    if let Some(f) = live.forwards.get_mut(&id) {
                        f.lease = None;
                    }
                }
            }
        }
    }

    /// The worker's per-forward report: counters, and arrivals from outside (kept, and written
    /// to disk at most once a minute per forward and protocol).
    fn on_forward_reports(&mut self, reports: &[ForwardStatusWire]) {
        let Some(live) = self.live.as_mut() else {
            return;
        };
        let now = Timestamp::now();
        let ago = |ms: Option<u64>| ms.map(|ms| Timestamp(now.0 - Duration::from_millis(ms)));
        for r in reports {
            let Some(id) = r.id else { continue };
            let Some(f) = live.forwards.get_mut(&id) else {
                continue;
            };
            f.report = Some(r.clone());
            let Some(b) = self.bindings.iter().find(|b| b.id == id) else {
                continue;
            };
            let rt = self.forward_rt.entry(id).or_default();
            rt.evidence
                .merge(ago(r.external_tcp_ms_ago), ago(r.external_udp_ms_ago));
            let due = rt.written_at.is_none_or(|t| t.elapsed() >= EVIDENCE_WRITE);
            let newer =
                |known: Option<Timestamp>, written: Option<Timestamp>| match (known, written) {
                    (Some(k), Some(w)) => k.0 > w.0,
                    (Some(_), None) => true,
                    _ => false,
                };
            let first = rt.written.tcp.is_none() && rt.evidence.tcp.is_some()
                || rt.written.udp.is_none() && rt.evidence.udp.is_some();
            if (due || first)
                && (newer(rt.evidence.tcp, rt.written.tcp)
                    || newer(rt.evidence.udp, rt.written.udp))
            {
                rt.written_at = Some(Instant::now());
                for (udp, at, written) in [
                    (false, rt.evidence.tcp, rt.written.tcp),
                    (true, rt.evidence.udp, rt.written.udp),
                ] {
                    let Some(at) = at.filter(|a| written.is_none_or(|w| a.0 > w.0)) else {
                        continue;
                    };
                    let store = self.ctx.store.clone();
                    let row = vpn_store::ForwardEvidence {
                        binding_id: id,
                        udp,
                        instance_id: b.instance_id,
                        tunnel_port: b.tunnel_port,
                        observed_at: at,
                    };
                    tokio::spawn(async move {
                        if let Err(e) = store.record_forward_evidence(row).await {
                            tracing::warn!(error = %e, "forward reachability evidence not written");
                        }
                    });
                }
                rt.written = rt.evidence;
            }
        }
        self.publish_forwards(false);
    }

    /// What a forward shows now.
    fn forward_status(&self, b: &ForwardBinding) -> ForwardStatus {
        let rt = self.forward_rt.get(&b.id);
        let live = self.live.as_ref();
        let lf = live.and_then(|l| l.forwards.get(&b.id));
        let lease = lf.and_then(|f| f.lease.as_ref());
        let report = lf.and_then(|f| f.report.as_ref());
        let (state, code, reason) = self.forward_state_of(b, rt, lf);
        let listening = state == ForwardState::Listening;
        ForwardStatus {
            binding_id: b.id,
            instance_id: b.instance_id,
            state,
            reason_code: (!listening && state != ForwardState::Disabled).then(|| code.to_string()),
            reason: (!listening && state != ForwardState::Disabled).then_some(reason),
            target: lease.map(|g| ForwardTarget {
                app_id: b.target_app_id,
                pid: Some(g.verified.pid),
                tcp_address: g.verified.tcp.map(|a| a.to_string()),
                udp_address: g.verified.udp.map(|a| a.to_string()),
                wildcard: g.verified.wildcard,
                verified_at: rt.and_then(|r| r.checked_at).unwrap_or(g.at),
            }),
            lease: lease.zip(live).map(|(g, l)| ForwardLease {
                lease_id: format!("{:016x}", g.id),
                generation: l.generation,
                granted_at: g.at,
            }),
            counters: report.zip(live).map(|(r, l)| ForwardCounters {
                generation: l.generation,
                accepted: Counter(r.accepted),
                active_tcp: u32::try_from(r.tcp_active).unwrap_or(u32::MAX),
                active_udp: u32::try_from(r.udp_active).unwrap_or(u32::MAX),
                refused_invalid: Counter(r.refused_invalid),
                refused_blocklisted: Counter(r.refused_blocklisted),
                refused_banned: Counter(r.refused_banned),
                refused_rate_limited: Counter(r.refused_rate_limited),
                refused_limit: Counter(r.refused_limit),
                refused_closed: Counter(r.refused_closed),
                target_failed: Counter(r.target_failed),
                bytes_in: Counter(r.bytes_in),
                bytes_out: Counter(r.bytes_out),
                udp_dropped: Counter(r.udp_dropped),
            }),
            reachability: rt.map_or_default(|r| r.evidence).reachability(b.protocol),
            observed_at: Timestamp::now(),
        }
    }

    /// The forward's state, why, in the order the states are listed: disabled, the
    /// connection, the target, then the worker listening.
    fn forward_state_of(
        &self,
        b: &ForwardBinding,
        rt: Option<&ForwardRt>,
        lf: Option<&LiveForward>,
    ) -> (ForwardState, &'static str, Text) {
        use ForwardState::{ConnectionNotReady, Disabled, Listening, TargetMissing};
        let listen_pending = || {
            tr!(
                "Starting to listen",
                "正在開始監聽",
                "待ち受けを開始しています"
            )
        };
        if !b.enabled {
            return (Disabled, "DISABLED", tr!("Turned off", "已停用", "無効"));
        }
        let Some(live) = self.live.as_ref() else {
            let (code, why) = not_running(self.status.phase);
            return (ConnectionNotReady, code, why);
        };
        if let Some((code, why)) = &live.forwards_blocked {
            return (ConnectionNotReady, code, why.clone());
        }
        if !live.ready {
            return (
                ConnectionNotReady,
                "CONNECTION_NOT_READY",
                tr!(
                    "The connection is being set up and carries no traffic yet",
                    "連線正在建立，尚未開放流量",
                    "接続を確立中で、まだトラフィックを通していません"
                ),
            );
        }
        match rt.and_then(|r| r.check.as_ref()) {
            None => {
                return (
                    TargetMissing,
                    "APP_NOT_CHECKED",
                    tr!(
                        "Checking the target app",
                        "正在確認目標 App",
                        "対象アプリを確認しています"
                    ),
                );
            }
            Some(Err(e)) => return (e.state, e.code, e.reason.clone()),
            Some(Ok(_)) => {}
        }
        let Some(f) = lf else {
            return (
                ConnectionNotReady,
                "LISTEN_PENDING",
                tr!(
                    "The running connection has not loaded this port forward yet",
                    "執行中的連線尚未載入這個轉發",
                    "実行中の接続はまだこのポート転送を読み込んでいません"
                ),
            );
        };
        let Some(g) = &f.lease else {
            return (
                ConnectionNotReady,
                "LISTEN_PENDING",
                tr!(
                    "Starting the port forward",
                    "正在開始轉發",
                    "ポート転送を開始しています"
                ),
            );
        };
        if self.status.phase == Phase::Degraded {
            return (
                ConnectionNotReady,
                "CONNECTION_DEGRADED",
                tr!(
                    "The connection is unstable for now: new inbound connections are paused (existing ones stay)",
                    "連線暫時不穩：暫停接受新的連入（既有連線保留）",
                    "接続が一時的に不安定です。新しい着信の受け付けを一時停止しています（既存の接続は維持します）"
                ),
            );
        }
        let Some(r) = f.report.as_ref().filter(|r| r.lease_id == Some(g.id)) else {
            return (ConnectionNotReady, "LISTEN_PENDING", listen_pending());
        };
        if let Some(e) = &r.error {
            return (ConnectionNotReady, "TUNNEL_PORT_UNAVAILABLE", e.clone());
        }
        let tcp_ok = !b.protocol.tcp() || r.tcp_listening;
        let udp_ok = !b.protocol.udp() || r.udp_listening;
        if !(tcp_ok && udp_ok) {
            return (ConnectionNotReady, "LISTEN_PENDING", listen_pending());
        }
        (Listening, "LISTENING", Text::default())
    }

    /// Publish the forwards whose status changed (state, reason, lease, target, evidence) at
    /// once, and the others' counters at most every [`FORWARD_PUBLISH`]; `force` publishes all.
    fn publish_forwards(&mut self, force: bool) {
        let statuses: Vec<ForwardStatus> = self
            .bindings
            .iter()
            .map(|b| self.forward_status(b))
            .collect();
        for status in statuses {
            let rt = self.forward_rt.entry(status.binding_id).or_default();
            let significant = rt.published.as_ref().is_none_or(|p| {
                p.state != status.state
                    || p.reason != status.reason
                    || p.lease != status.lease
                    || p.target.as_ref().map(|t| (&t.tcp_address, &t.udp_address))
                        != status
                            .target
                            .as_ref()
                            .map(|t| (&t.tcp_address, &t.udp_address))
                    || p.reachability != status.reachability
                    || p.counters.is_some() != status.counters.is_some()
            });
            let counters_moved = rt
                .published
                .as_ref()
                .is_some_and(|p| p.counters != status.counters);
            let due = rt
                .published_at
                .is_none_or(|t| t.elapsed() >= FORWARD_PUBLISH);
            if force || significant || (counters_moved && due) {
                rt.published = Some(status.clone());
                rt.published_at = Some(Instant::now());
                let _ = self
                    .ctx
                    .events
                    .send(ManagerEvent::ForwardStatus(Box::new(status)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use tokio::sync::broadcast;
    use vpn_platform::paths::Paths;
    use vpn_store::{IntentChange, Store};
    use zeroize::Zeroizing;

    use super::*;
    use vpn_domain::{
        EntityMeta, InstancePurpose, InterfaceSpec, PeerSpec, ProfileId, ProfileSource, WgKey,
    };

    /// A stored, stopped Instance whose intent is then set running, and a context for its actor.
    async fn running_on_disk(dir: &std::path::Path) -> (InstanceId, Arc<Ctx>) {
        let paths = Paths::under(dir);
        paths.ensure().unwrap();
        let store = Arc::new(Store::open(&paths.state, &Zeroizing::new([9u8; 32]), 1).unwrap());
        let key = store
            .put_secret("k".into(), None, Zeroizing::new(vec![1; 32]), None)
            .await
            .unwrap();
        let wg = WgKey::from_str("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=").unwrap();
        let meta = EntityMeta {
            revision: 1,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        };
        let profile = store
            .create(RuntimeProfile {
                id: ProfileId::new(),
                meta: meta.clone(),
                name: "lab".into(),
                provider: ProviderKind::Generic,
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
            .unwrap();
        let spec = store
            .create_instance(InstanceSpec {
                id: InstanceId::new(),
                meta,
                name: "work".into(),
                profile_id: profile.id,
                dns_profile_id: None,
                security_profile_id: None,
                purpose: InstancePurpose::General,
                limits: InstanceLimits::default(),
                strict: false,
                transport: vpn_domain::TransportRef::default(),
            })
            .await
            .unwrap();
        store
            .change_intent(spec.id, IntentChange::Start)
            .await
            .unwrap();
        let ctx = Arc::new(Ctx {
            apps: crate::apps::Apps::new(
                store.clone(),
                paths.clone(),
                broadcast::channel(16).0,
                Arc::new(vpn_platform::limits::ResourceControl::none("test")),
            ),
            store,
            exe: dir.join("no-such-vpnd"),
            inventory: crate::inventory::Inventory::new(paths.worker_records()),
            stops: Arc::new(crate::stops::PendingStops::new(&paths.state)),
            paths,
            events: broadcast::channel(16).0,
            gateway_key: None,
            metrics: crate::metrics::MetricsCollector::new(),
            changes: tokio::sync::watch::Sender::new(crate::Changes::default()),
            running: vpn_sync::Mutex::new(HashMap::new()),
            spawn_gate: tokio::sync::RwLock::new(()),
            resources: Arc::new(vpn_platform::limits::ResourceControl::none("test")),
            strict_apps: crate::sandbox::StrictApps::new(
                dir.join("no-such-vpnd"),
                std::sync::Weak::new(),
            ),
            closing: std::sync::atomic::AtomicBool::new(false),
        });
        (spec.id, ctx)
    }

    #[tokio::test]
    async fn a_held_stop_beats_a_running_intent_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        // The intent on disk says running: the user's stop is held, its latch not written yet.
        let (id, ctx) = running_on_disk(dir.path()).await;
        let hold = Arc::new(Hold::default());
        hold.stop(false);
        let mut actor = Actor::new(id, ctx, hold.clone());

        actor.refresh_intent().await;
        assert_eq!(actor.status.intent.desired, DesiredState::Stopped);
        assert_eq!(actor.status.intent.persistence, Persistence::Pending);
        assert!(!actor.wants_running());
        // A reconcile (e.g. the one that follows a failed latch) does not restart it.
        actor.reconcile().await;
        assert_eq!(actor.status.phase, Phase::Stopped);
        assert!(actor.live.is_none() && actor.retry_at.is_none());

        // A durable Start requested after the stop lifts the hold.
        hold.started(hold.get().epoch);
        actor.refresh_intent().await;
        assert_eq!(actor.status.intent.persistence, Persistence::Durable);
        assert!(actor.wants_running());

        // Attempts whose peer never answered are counted (and only those), until the connection
        // is ready again or stopped: that, not a passing outage, is an endpoint that failed.
        actor
            .fail_generation(fault("HANDSHAKE_FAILED", "對端沒有回應"))
            .await;
        assert_eq!(actor.status.recovery.unreachable_attempts, 1);
        actor
            .fail_generation(fault("WORKER_EXITED", "worker 結束"))
            .await;
        assert_eq!(actor.status.recovery.unreachable_attempts, 1);
        actor
            .fail_generation(fault("HANDSHAKE_FAILED", "對端沒有回應"))
            .await;
        assert_eq!(actor.status.recovery.unreachable_attempts, 2);
        assert_eq!(actor.status.phase, Phase::Reconnecting);
        actor.set_phase(Phase::Stopped);
        assert_eq!(actor.status.recovery.unreachable_attempts, 0);
    }

    #[tokio::test]
    async fn a_stop_carried_over_unconfirmed_holds_the_instance_for_the_user() {
        let dir = tempfile::tempdir().unwrap();
        let (id, ctx) = running_on_disk(dir.path()).await;
        let hold = Arc::new(Hold::unconfirmed(true));
        let mut actor = Actor::new(id, ctx, hold.clone());
        actor.refresh_intent().await;
        actor.reconcile().await;
        let s = actor.snapshot();
        assert_eq!(s.phase, Phase::RecoveryRequired);
        assert_eq!(s.enforcement, Enforcement::Blocked);
        assert!(s.intent.emergency_latched && s.intent.desired == DesiredState::Stopped);
        let f = s.recovery.last_fault.clone().unwrap();
        assert_eq!(f.code, STOP_NOT_CONFIRMED);
        assert!(f.message.zh_tw.contains("解除急停"), "{}", f.message.zh_tw);
        assert!(actor.live.is_none() && actor.retry_at.is_none());
        // Reconciling again (any command) keeps it, with the time it was first observed.
        actor.reconcile().await;
        assert_eq!(actor.snapshot().recovery.last_fault, Some(f));

        // The user stops it: an ordinary stop from then on, and the reason goes.
        hold.stop(false);
        actor.reconcile().await;
        let s = actor.snapshot();
        assert_eq!(s.phase, Phase::Stopped);
        assert!(s.recovery.last_fault.is_none());
    }
}
