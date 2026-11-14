//! Runtime state as observed by the Instance Manager. Status is never inferred: unknown stays
//! unknown and is never rendered as "protected".

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::common::{Counter, Revision, Timestamp};
use crate::ids::{
    AppId, BanId, BlocklistId, ForwardBindingId, GatewayId, InstallationId, InstanceId,
    OperationId, SecurityProfileId,
};
use crate::metrics::MetricsRecording;
use crate::text::Text;
use crate::transport::FlowSettings;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum DesiredState {
    Running,
    Stopped,
}

/// Whether the latest intent is safely on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Persistence {
    Durable,
    /// Applied in memory; the durable write has not completed yet (retrying).
    Pending,
    Unavailable,
}

/// Durable user intent. Faults never change it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct InstanceIntent {
    pub desired: DesiredState,
    pub manual_stop: bool,
    pub emergency_latched: bool,
    #[ts(type = "number")]
    pub intent_revision: Revision,
    pub persistence: Persistence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Phase {
    Stopped,
    Starting,
    Connecting,
    Verifying,
    Ready,
    /// Tunnel temporarily unhealthy: new payload refused, retrying within the same generation.
    Degraded,
    /// Waiting for the next recovery attempt; payload blocked.
    Reconnecting,
    Stopping,
    /// Stopped by a deterministic problem that needs a configuration change or user action.
    Failed,
    /// Ownership or intent cannot be proven; payload stays blocked until the user decides.
    RecoveryRequired,
}

/// What the data plane currently enforces for payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Enforcement {
    /// Payload refused (no worker, gate closed or tightened).
    Blocked,
    /// Payload admitted and can only leave through the tunnel.
    TunnelOnly,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Health {
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Fault {
    pub code: String,
    pub message: Text,
    pub at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RecoveryStatus {
    pub attempt: u32,
    pub next_retry_at: Option<Timestamp>,
    pub last_fault: Option<Fault>,
    /// Consecutive start attempts whose `WireGuard` peer never answered (no handshake), since the
    /// connection was last ready or stopped: its endpoint failed every time, not a passing
    /// outage of an established tunnel.
    #[serde(default)]
    pub unreachable_attempts: u32,
}

/// A piece of configuration an Instance runs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ConfigPart {
    /// The connection itself: which profiles it uses, its limits.
    Instance,
    /// Its `WireGuard` profile.
    Profile,
    Dns,
    Security,
}

/// Revisions a running generation was started with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RunningInfo {
    #[ts(type = "number")]
    pub generation: u64,
    #[ts(type = "number")]
    pub profile_revision: Revision,
    #[ts(type = "number | null")]
    pub dns_profile_revision: Option<Revision>,
    #[ts(type = "number | null")]
    pub security_profile_revision: Option<Revision>,
    pub started_at: Timestamp,
    pub ready_at: Option<Timestamp>,
    pub pid: Option<u32>,
    /// Saved changes this generation does not run yet; a restart applies them. Only what the
    /// worker uses counts — renaming, a location or an expiry date does not.
    pub pending_changes: Vec<ConfigPart>,
    /// The blocklist overlay of this generation (applies without a restart).
    pub policy: Option<PolicyStatus>,
    /// How the OS confines the worker process (its cgroup limits, or why there are none).
    #[serde(default)]
    pub resources: Option<ResourceStatus>,
    /// The bandwidth caps the worker confirmed it enforces; null until it confirmed them.
    #[serde(default)]
    pub bandwidth: Option<BandwidthCaps>,
    /// The transport the worker reports it applies to the flows it opens; null until it
    /// reported.
    #[serde(default)]
    pub transport: Option<TransportStatus>,
}

/// The transport a running connection applies to the flows it opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TransportStatus {
    /// Name of the profile in force.
    pub profile: Text,
    pub automatic: bool,
    /// Name of the fixed profile whose values new flows take now: the range of an automatic
    /// profile the connection is in, or the profile itself.
    pub band: Text,
    /// The values new flows take now.
    pub flow: FlowSettings,
    /// The round trip measured through the tunnel, milliseconds; null while nothing was
    /// measured.
    pub rtt_ms: Option<u32>,
    /// TCP buffers enlarged because their connection used them, since this generation started.
    pub buffers_grown: u32,
    /// Enlargements not made because the buffer budget had no room for them.
    pub growth_refused: u32,
    /// Strict mode: the kernel's TCP buffer limits in the sandbox after the profile raised
    /// them; null on the userspace stack, and when they could not be set.
    pub kernel_limits: Option<KernelTcpLimits>,
    /// The congestion control the connection's own TCP connections really run (`flow` holds
    /// the one asked for); null in strict mode until the connection opened one of its own.
    #[serde(default)]
    pub congestion: Option<CongestionStatus>,
}

/// The congestion control in use on a connection's own TCP connections.
///
/// Those are its Gateways' outbound connections, DNS and probes. A strict App's own sockets are
/// not among them: they run whatever the sandbox's network namespace has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CongestionStatus {
    /// The kernel's name of it in strict mode (`cubic`, `bbr`, …), the userspace stack's
    /// otherwise.
    pub in_use: String,
    /// Why it is not the one asked for; null when it is.
    pub fallback: Option<CongestionFallback>,
}

/// Why a connection does not run the congestion control its transport profile asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum CongestionFallback {
    /// The userspace TCP stack has no BBR: it runs Cubic.
    UserspaceStack,
    /// The kernel did not give it to this unprivileged process (the module is not loaded, or it
    /// is not in `net.ipv4.tcp_allowed_congestion_control`): the sandbox's own setting runs.
    KernelRefused,
}

/// The largest buffers the kernel gives one TCP socket, KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct KernelTcpLimits {
    pub recv_kib: u32,
    pub send_kib: u32,
}

/// Bandwidth caps (bits per second; null = no cap).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BandwidthCaps {
    #[ts(type = "number | null")]
    pub download_bps: Option<u64>,
    #[ts(type = "number | null")]
    pub upload_bps: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum LimitKind {
    Memory,
    Cpu,
    Processes,
    OpenFiles,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum LimitMechanism {
    /// Linux cgroup v2: the whole process tree together.
    Cgroup,
    /// `setrlimit`: each process on its own.
    Rlimit,
}

/// A limit in force, as read back from the OS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EnforcedLimit {
    pub kind: LimitKind,
    pub mechanism: LimitMechanism,
    /// Bytes (memory), percent of one core (cpu), a count (processes, open files).
    #[ts(type = "number")]
    pub value: u64,
    /// What else to know about it (e.g. that swap is not limited on this host).
    pub note: Option<Text>,
}

/// A limit that is not in force, and why (the platform, this host, or a failure).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UnenforcedLimit {
    pub kind: LimitKind,
    pub reason: Text,
}

/// How the OS confines one process tree: a connection's worker or an App's run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ResourceStatus {
    /// Its cgroup below VPN Manager's delegated cgroup (`workers/<id>-<generation>`,
    /// `apps/<id>`); null without one.
    pub cgroup: Option<String>,
    pub enforced: Vec<EnforcedLimit>,
    pub unenforced: Vec<UnenforcedLimit>,
    /// Memory the cgroup uses (`memory.current`) at `observed_at`; null without a cgroup.
    #[ts(type = "number | null")]
    pub memory_bytes: Option<u64>,
    /// Processes the kernel killed for exceeding the memory limit (`memory.events` `oom_kill`).
    #[ts(type = "number | null")]
    pub oom_kills: Option<u64>,
    pub observed_at: Timestamp,
}

/// One blocklist of a connection's overlay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AppliedBlocklist {
    pub id: BlocklistId,
    pub name: String,
    pub content_sha256: String,
}

/// The live part of a running connection's security policy: the union of its security profile's
/// blocklists, compiled into one deny overlay with its own monotonic revision.
///
/// Saving a blocklist or attaching/detaching one changes it without a restart; the base rules
/// (private ranges, ports, allow rules, auto-ban settings) stay as the generation started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PolicyStatus {
    /// The overlay this generation should enforce (`enforcement_policy_revision`).
    #[ts(type = "number")]
    pub revision: u64,
    /// SHA-256 of the overlay's compiled ranges.
    pub digest: String,
    pub blocklists: Vec<AppliedBlocklist>,
    pub v4_ranges: u32,
    pub v6_ranges: u32,
    /// What the worker confirmed it enforces, by its own digest of what it installed; `None`
    /// until it answers.
    #[ts(type = "number | null")]
    pub applied_revision: Option<u64>,
    pub applied_digest: Option<String>,
    pub applied_at: Option<Timestamp>,
    /// Why the latest saved blocklists are not enforced (the previous overlay stays).
    pub error: Option<Text>,
}

/// A source address the auto-ban engine of a running connection banned (inbound through a port
/// forward). Removed when it expires or is lifted; lifting it never lifts a blocklist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Ban {
    pub id: BanId,
    pub instance_id: InstanceId,
    /// What is banned: an IPv4 address, or an IPv6 /64 (held as its first address, written
    /// `network/64`).
    #[ts(type = "string")]
    #[serde(with = "ban_source")]
    pub source: std::net::IpAddr,
    pub reason: Text,
    pub security_profile_id: Option<SecurityProfileId>,
    #[ts(type = "number | null")]
    pub security_profile_revision: Option<Revision>,
    /// The overlay revision in force when the source was banned.
    #[ts(type = "number")]
    pub policy_revision: u64,
    #[ts(type = "number")]
    pub generation: u64,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

/// [`Ban::source`] as text: [`ban_label`](crate::validation::ban_label) out; in, a bare address
/// (taken as its ban scope) or an IPv6 `network/64`.
mod ban_source {
    use std::net::IpAddr;

    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    use crate::validation::{BAN_V6_PREFIX, ban_label, ban_scope};

    pub fn serialize<S: Serializer>(source: &IpAddr, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&ban_label(*source))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<IpAddr, D::Error> {
        let text = std::borrow::Cow::<str>::deserialize(d)?;
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (&*text, None),
        };
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| D::Error::custom("not a ban source"))?;
        match prefix {
            Some(p) if !(ip.is_ipv6() && p == BAN_V6_PREFIX.to_string()) => {
                Err(D::Error::custom("not a ban source"))
            }
            _ => Ok(ban_scope(ip)),
        }
    }
}

/// What lifting a ban did to the running connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum UnbanEffect {
    /// The running worker confirmed it no longer bans the address.
    Applied,
    /// The connection is not running: nothing enforces the ban any more.
    NotRunning,
    /// Removed from the store; the running worker did not confirm in time.
    Unconfirmed,
}

/// `DELETE /v1/bans/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UnbanResult {
    pub ban: Ban,
    pub worker: UnbanEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TunnelStatus {
    pub endpoint: String,
    pub last_handshake_at: Option<Timestamp>,
    /// `WireGuard` datagram bytes (underlay), not application payload.
    pub wg_rx_bytes: Counter,
    pub wg_tx_bytes: Counter,
    pub ipv6: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DnsStatus {
    /// The latest probe got an answer from the connection's DNS: `false` while it is
    /// `interrupted` too.
    pub healthy: Option<bool>,
    pub last_probe_at: Option<Timestamp>,
    /// Why the latest probe failed, server by server.
    pub last_error: Option<Text>,
    /// Every server of the connection's DNS profile failed and the `WireGuard` profile's own
    /// resolvers answer meanwhile (still through the tunnel): why the profile's servers failed.
    #[serde(default)]
    pub fallback: Option<Text>,
    /// Every server of the connection's DNS profile failed and the profile asks nothing else
    /// (`on_failure: fail`): names do not resolve until one answers again, while the tunnel
    /// itself is up. Why the profile's servers failed.
    #[serde(default)]
    pub interrupted: Option<Text>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum GatewayState {
    /// Accepting and forwarding through the tunnel.
    Serving,
    /// Listener held; connections are refused with an explanation.
    Blocked,
    /// Not started (disabled or Instance stopped).
    Inactive,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct GatewayRuntime {
    pub gateway_id: GatewayId,
    pub state: GatewayState,
    pub active_tcp: u32,
    pub active_udp: u32,
    pub error: Option<Text>,
}

/// The rootless sandbox of a strict Instance (Linux). It outlives worker generations: while no
/// worker runs, its Apps are offline, never routed elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SandboxStatus {
    /// When this sandbox was built (Unix milliseconds); a rebuilt sandbox always gets a higher
    /// epoch than the one it replaces.
    #[ts(type = "number")]
    pub epoch: u64,
    /// Host pid of the sandbox's holder (pid 1 of its pid namespace).
    pub holder_pid: u32,
    /// The TUN device inside the sandbox, its only interface besides `lo`.
    pub tun_name: String,
    /// Tunnel addresses on that device, with prefix lengths.
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct InstanceStatus {
    pub instance_id: InstanceId,
    #[ts(type = "number")]
    pub spec_revision: Revision,
    pub intent: InstanceIntent,
    pub phase: Phase,
    pub enforcement: Enforcement,
    pub health: Health,
    pub running: Option<RunningInfo>,
    pub tunnel: Option<TunnelStatus>,
    pub dns: Option<DnsStatus>,
    pub gateways: Vec<GatewayRuntime>,
    pub recovery: RecoveryStatus,
    pub observed_at: Timestamp,
    /// Linux strict mode: the Instance's sandbox, while one exists.
    #[serde(default)]
    #[ts(optional)]
    pub sandbox: Option<SandboxStatus>,
}

// ---------------------------------------------------------------------------------------------
// Managed Apps
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum AppRunState {
    Stopped,
    Starting,
    Running,
    Stopping,
    /// Did not start, exited on its own with an error, or could not be confirmed stopped.
    Failed,
}

/// How the App's root process ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AppExit {
    /// Exit code of a normal exit.
    pub code: Option<i32>,
    /// Signal that ended it.
    pub signal: Option<i32>,
    pub at: Timestamp,
}

/// A listening TCP socket of the App's process tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AppListener {
    pub pid: u32,
    /// `address:port` as bound, e.g. `127.0.0.1:8080` or `0.0.0.0:8080`.
    pub address: String,
    /// Bound to a loopback address only (not reachable from other hosts).
    pub loopback: bool,
}

/// What the manager observes about one App. Runtime facts are never guessed: `None` means not
/// measured (or not measurable on this host).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AppStatus {
    pub app_id: AppId,
    /// The user's intent (Start → running, Stop → stopped). Faults never change it.
    pub desired: DesiredState,
    /// Whether that intent is on disk.
    pub intent_persistence: Persistence,
    pub state: AppRunState,
    /// Spec revision the current (or last) run was started with.
    #[ts(type = "number | null")]
    pub run_revision: Option<Revision>,
    pub pid: Option<u32>,
    pub started_at: Option<Timestamp>,
    pub last_exit: Option<AppExit>,
    /// Why the App is not running as wanted, or why it was stopped.
    pub last_error: Option<Fault>,
    /// Isolation actually applied to the running process (`None` while nothing runs).
    pub isolation: Option<crate::config::AppIsolation>,
    pub gateway_id: Option<GatewayId>,
    pub gateway_port: Option<u16>,
    /// Processes in the tree right now.
    pub process_count: Option<u32>,
    /// Listening TCP sockets of the tree (checked every 2 s while it runs).
    pub listeners: Option<Vec<AppListener>>,
    /// Seatbelt denials logged for this run (`enforced_proxy`, counted from the system log).
    #[ts(type = "number | null")]
    pub sandbox_denials: Option<u64>,
    /// How the OS confines the running tree (its limits in force, or why one is not).
    #[serde(default)]
    pub resources: Option<ResourceStatus>,
    /// Each local access port of the App (`strict_netns`), as the manager holds it; also while
    /// the App does not run.
    #[serde(default)]
    pub access: Vec<AppAccessStatus>,
    pub observed_at: Timestamp,
}

/// What a local access port does right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum AccessState {
    /// VPN Manager cannot take the host port (another program holds it, or the address is not
    /// available); retried in the background.
    Unavailable,
    /// Held; the App does not run: every connection is refused (an HTTP client is told why).
    AppStopped,
    /// Held; the App runs, but was started before this port was added: restart it to open it.
    RestartNeeded,
    /// Held: admitted connections are relayed to the App.
    Serving,
}

/// One local access port of an App.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AppAccessStatus {
    pub app_port: u16,
    pub host_port: u16,
    pub bind: crate::config::AccessBind,
    pub state: AccessState,
    /// VPN Manager holds the host's listener (`127.0.0.1` or `0.0.0.0`, `host_port`).
    pub listening: bool,
    /// The App's process tree listens on `app_port` in its sandbox, as of the last check (every
    /// 2 s); `None` while it does not run or before the first check.
    pub app_listening: Option<bool>,
    /// Connections relayed to the App since the manager started.
    #[ts(type = "number")]
    pub accepted: u64,
    /// Connections refused since the manager started: another user's program, a host outside
    /// the allowed networks, or the App not running.
    #[ts(type = "number")]
    pub refused: u64,
    /// The latest refusal: who, and why.
    pub last_refused: Option<Fault>,
    /// Why the port does not work, until it works again: the host port cannot be taken, or the
    /// App did not accept a relayed connection.
    pub last_error: Option<Fault>,
}

/// One process of an App's tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AppProcess {
    pub pid: u32,
    pub ppid: u32,
    pub started_at: Timestamp,
    /// Executable name as the OS reports it (may be shortened).
    pub name: String,
    /// User + system CPU time.
    #[ts(type = "number | null")]
    pub cpu_ms: Option<u64>,
    #[ts(type = "number | null")]
    pub rss_bytes: Option<u64>,
}

/// `GET /v1/apps/{id}/processes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AppProcesses {
    pub app_id: AppId,
    /// Root first, then descendants; empty while nothing runs.
    pub processes: Vec<AppProcess>,
    /// The tree has more processes than listed.
    pub truncated: bool,
    pub observed_at: Timestamp,
}

/// `GET /v1/apps/{id}/log`: the newest lines of the App's own stdout/stderr.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AppLog {
    pub app_id: AppId,
    pub lines: Vec<String>,
    /// Older lines exist that are not included.
    pub truncated: bool,
    pub observed_at: Timestamp,
}

// ---------------------------------------------------------------------------------------------
// Port forwards
// ---------------------------------------------------------------------------------------------

/// Where a port forward stands, in the order it is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ForwardState {
    /// Turned off by the user.
    Disabled,
    /// Its connection is not running, not open for payload yet (or any more), or has not
    /// started listening on the tunnel port.
    ConnectionNotReady,
    /// The target App is not running, or nothing of it holds the target port.
    TargetMissing,
    /// The target port is held by something that is not the App's process tree, or the App
    /// cannot receive this protocol.
    TargetNotOwned,
    /// The worker listens on the tunnel port and connects inbound traffic to the App.
    Listening,
}

/// The target as the manager verified it: the App's run and the loopback address(es) the worker
/// connects to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardTarget {
    pub app_id: AppId,
    /// Root process of the App's run.
    pub pid: Option<u32>,
    /// Address the worker connects TCP to (`127.0.0.1:port` or `[::1]:port`).
    pub tcp_address: Option<String>,
    pub udp_address: Option<String>,
    /// The App's tree holds the port on a wildcard address (also reachable from other hosts).
    pub wildcard: bool,
    pub verified_at: Timestamp,
}

/// The revocable grant the worker holds for the current generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardLease {
    /// Hex; new for every grant.
    pub lease_id: String,
    #[ts(type = "number")]
    pub generation: u64,
    pub granted_at: Timestamp,
}

/// What a forward did in the current generation (cumulative; `null` in the status while no
/// worker reports — never zeros).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardCounters {
    #[ts(type = "number")]
    pub generation: u64,
    /// Inbound TCP connections and UDP flows connected to the App.
    pub accepted: Counter,
    pub active_tcp: u32,
    pub active_udp: u32,
    pub refused_invalid: Counter,
    pub refused_blocklisted: Counter,
    pub refused_banned: Counter,
    pub refused_rate_limited: Counter,
    pub refused_limit: Counter,
    /// Arrived while the connection was not open for payload or the lease was ending.
    pub refused_closed: Counter,
    /// The App did not accept a connection.
    pub target_failed: Counter,
    /// Remote → App, and App → remote.
    pub bytes_in: Counter,
    pub bytes_out: Counter,
    pub udp_dropped: Counter,
}

/// Whether the forward has been seen working from outside.
///
/// `observed` only once an inbound connection (TCP) or flow (UDP) actually arrived from a source
/// outside the tunnel's own and private networks; a source inside them, or a lab test, never
/// counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Reachability {
    Unverified,
    Observed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardReachability {
    pub state: Reachability,
    /// Latest arrival from outside, per protocol (kept across restarts while the forward's
    /// connection and tunnel port stay the same).
    pub tcp_observed_at: Option<Timestamp>,
    pub udp_observed_at: Option<Timestamp>,
}

/// What the manager observes about one port forward. Runtime facts are never guessed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ForwardStatus {
    pub binding_id: ForwardBindingId,
    pub instance_id: InstanceId,
    pub state: ForwardState,
    /// Machine code of why it is not listening (e.g. `APP_NOT_RUNNING`).
    pub reason_code: Option<String>,
    /// Why it is not listening, in words.
    pub reason: Option<Text>,
    pub target: Option<ForwardTarget>,
    pub lease: Option<ForwardLease>,
    pub counters: Option<ForwardCounters>,
    pub reachability: ForwardReachability,
    pub observed_at: Timestamp,
}

// ---------------------------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum OperationStatus {
    Accepted,
    Running,
    Succeeded,
    Failed,
    /// The effect may or may not have happened; reconcile before any retry.
    Unknown,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Operation {
    pub id: OperationId,
    pub kind: String,
    pub target_id: Option<String>,
    pub status: OperationStatus,
    pub error: Option<crate::error::ApiError>,
    /// Ids of entities this operation produced.
    pub result_refs: Vec<String>,
    /// False while the operation exists only in memory (store unavailable).
    pub durable: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

/// Operation kind of a user Stop of an Instance. The controller records it; a manager start
/// reads it back to find stops whose latch may never have reached the disk.
pub const OP_INSTANCE_STOP: &str = "instance.stop";
/// Operation kind of an emergency stop of an Instance (see [`OP_INSTANCE_STOP`]).
pub const OP_INSTANCE_EMERGENCY_STOP: &str = "instance.emergency_stop";

// ---------------------------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum CapabilityState {
    Supported,
    Unsupported,
    /// Implemented but not proven on this host.
    Unverified,
    /// Requires something this host or account does not have.
    Blocked,
    /// Works with a documented weaker guarantee.
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Capability {
    pub name: String,
    pub state: CapabilityState,
    pub reason: Option<Text>,
}

fn loopback_text() -> String {
    "127.0.0.1".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SystemStatus {
    pub version: String,
    pub build_id: String,
    pub os: String,
    /// Port of the web UI and API: an installation parameter (`vpn-installer upgrade --port`), not
    /// a setting.
    pub controller_port: u16,
    /// Address the web UI and API listen on: `127.0.0.1` unless installed with
    /// `--listen-address` (also an installation parameter).
    #[serde(default = "loopback_text")]
    pub controller_listen: String,
    /// Networks other hosts may use the web UI and API from (`--allow-client`, CIDR); empty
    /// when only this host may.
    #[serde(default)]
    pub controller_allow_clients: Vec<String>,
    /// This host's own addresses other hosts can reach it at (not loopback or link-local), for
    /// the addresses shown to the user.
    #[serde(default)]
    pub host_addresses: Vec<String>,
    /// The one directory holding everything VPN Manager keeps: programs, data, the vault key and
    /// `logs/`.
    pub data_dir: Option<String>,
    /// `None` while the manager is unreachable.
    pub installation_id: Option<InstallationId>,
    pub manager_connected: bool,
    pub store: StoreHealth,
    pub instances_running: u32,
    pub instances_total: u32,
    pub capabilities: Vec<Capability>,
    /// Whether this host's clock is synchronized (NTP or the like), as its kernel says; `None`
    /// where that cannot be told (not Linux).
    #[serde(default)]
    pub clock_synchronized: Option<bool>,
    /// The controller's time as it answers: the browser compares the server's timestamps with
    /// the server's own time from it, never with its own clock.
    pub observed_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct StoreHealth {
    pub control_ok: bool,
    /// The manager answers and its metric samples are written (false while they fail, see
    /// `metrics_recording`; overwriting the oldest data on a full disk still stores them).
    pub metrics_ok: bool,
    /// Whether metric samples are being stored; `None` while the manager is unreachable.
    #[serde(default)]
    pub metrics_recording: Option<MetricsRecording>,
    pub keystore: CapabilityState,
    pub sqlite_version: String,
}
