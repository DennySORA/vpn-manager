//! System maintenance contract: the diagnostics report and recovery (resources VPN Manager owns
//! and what a crash left behind).
//!
//! Nothing here carries a secret, a destination (endpoint, SSH host name, proxied address) or an
//! account number: a diagnostics report is meant to be shared. Unknown values are `null` with a
//! reason, never `0`.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::api::{SshFileState, SshIncludeState};
use crate::common::Timestamp;
use crate::ids::{AppId, GatewayId, InstallationId, InstanceId, OperationId};
use crate::status::{AppRunState, Capability, GatewayState, Phase};
use crate::text::Text;

// ---------------------------------------------------------------------------------------------
// Diagnostics (`GET /v1/system/diagnostics`)
// ---------------------------------------------------------------------------------------------

/// Format version of [`DiagnosticReport`]. 2: the manager no longer reports backups or restore
/// copies, nor whether a process runs as a benchmark test environment.
pub const DIAGNOSTICS_SCHEMA: u32 = 2;

/// SHA-256 of a program file as it is on disk (or, for a running program, the file it was
/// started from).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BinaryDigest {
    pub path: String,
    pub sha256: Option<String>,
    #[ts(type = "number | null")]
    pub size_bytes: Option<u64>,
    /// Why there is no digest (missing file, unreadable).
    pub error: Option<Text>,
}

/// One long-running VPN Manager process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProcessReport {
    /// `controller` or `manager`.
    pub role: String,
    pub pid: u32,
    pub version: String,
    pub build_id: String,
    /// Git revision the binary was built from (`nogit` outside a checkout).
    pub git_rev: String,
    pub binary: BinaryDigest,
    /// Process start time as the OS records it; null when the OS did not say.
    pub started_at: Option<Timestamp>,
    #[ts(type = "number | null")]
    pub uptime_secs: Option<u64>,
    #[ts(type = "number | null")]
    pub rss_bytes: Option<u64>,
    /// User + system CPU time used so far.
    #[ts(type = "number")]
    pub cpu_ms: u64,
}

/// Write queue of one database: a full normal queue answers `STORE_BUSY` at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct QueueHealth {
    pub depth: u32,
    pub capacity: u32,
    /// Stop and emergency latches; never refused for depth.
    pub priority_depth: u32,
    /// Writes refused with `STORE_BUSY` since the manager started.
    #[ts(type = "number")]
    pub busy_refusals: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DatabaseReport {
    /// `control` or `metrics`.
    pub name: String,
    pub path: String,
    #[ts(type = "number | null")]
    pub size_bytes: Option<u64>,
    #[ts(type = "number | null")]
    pub wal_bytes: Option<u64>,
    /// `PRAGMA user_version`; null when it could not be read.
    #[ts(type = "number | null")]
    pub schema_version: Option<i64>,
    /// The newest schema this build reads and writes.
    #[ts(type = "number")]
    pub supported_version: i64,
    /// `PRAGMA quick_check`: true only for an `ok` answer, null when it did not run.
    pub quick_check_ok: Option<bool>,
    /// The answer (`ok`, the first problems found) or why it did not run.
    pub quick_check: Text,
    pub queue: QueueHealth,
}

/// Whether the data directory's volume has room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum DiskSpaceState {
    Normal,
    /// Below the threshold (or a metrics write found the disk full): the metrics database stops
    /// growing and overwrites its oldest data.
    Low,
    /// The free space could not be read.
    Unknown,
}

/// A database's reserve file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ReserveState {
    /// Allocated: a write of its database that finds the disk full gets its room.
    Held,
    /// Given back to a write that found the disk full; allocated again once there is room.
    Released,
    /// Not allocated (the volume has had no room for it).
    Missing,
}

/// Free space of the data directory and what VPN Manager does about it.
///
/// Below the threshold the metrics database stops growing: it keeps recording by overwriting its
/// oldest data (each pruned span a `disk_low` gap). Control data and secrets are never deleted;
/// a reserve per database keeps room for its writes on a full disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DiskReport {
    pub path: String,
    pub state: DiskSpaceState,
    #[ts(type = "number | null")]
    pub free_bytes: Option<u64>,
    #[ts(type = "number | null")]
    pub total_bytes: Option<u64>,
    /// `min(512 MiB, 5 %)` of the volume.
    #[ts(type = "number | null")]
    pub low_threshold_bytes: Option<u64>,
    pub low_since: Option<Timestamp>,
    /// When a metrics write last found the disk full.
    pub metrics_full_at: Option<Timestamp>,
    /// Metric samples not stored at all: the disk was full even after overwriting the oldest
    /// data (since the manager started).
    #[ts(type = "number")]
    pub samples_skipped: u64,
    /// Metrics rows deleted early (overwritten) to make room for new ones (since the manager
    /// started).
    #[ts(type = "number")]
    pub rows_pruned: u64,
    /// The control database's reserve, and the size of each reserve.
    pub reserve: ReserveState,
    #[ts(type = "number")]
    pub reserve_bytes: u64,
    pub reserve_released_at: Option<Timestamp>,
    /// The metrics database's reserve (its WAL and a checkpoint on a full disk).
    #[serde(default = "missing_reserve")]
    pub metrics_reserve: ReserveState,
    #[serde(default)]
    pub metrics_reserve_released_at: Option<Timestamp>,
    /// Why something could not be read or done.
    pub error: Option<Text>,
}

const fn missing_reserve() -> ReserveState {
    ReserveState::Missing
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum VaultKeyState {
    /// `vault.key` on disk is the key the Store's secrets are sealed with.
    Matches,
    /// Another key: the next manager start will be refused.
    Mismatch,
    Missing,
    /// Wrong owner, mode or length: the next start will be refused.
    Unsafe,
    Unreadable,
}

/// `vault.key` on disk compared with the Store's key check (the key itself is never shown).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct VaultKeyReport {
    pub state: VaultKeyState,
    pub detail: Option<Text>,
}

/// The manager's metrics ingress since it started (worker samples on their way to the Store).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsIngressReport {
    pub queued_now: u32,
    #[ts(type = "number")]
    pub accepted: u64,
    #[ts(type = "number")]
    pub written: u64,
    #[ts(type = "number")]
    pub duplicates: u64,
    #[ts(type = "number")]
    pub stale: u64,
    /// Samples dropped unwritten (queue full); recorded as gaps.
    #[ts(type = "number")]
    pub dropped: u64,
    #[ts(type = "number")]
    pub write_failures: u64,
}

/// A file VPN Manager keeps, by size only (contents are never reported).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FileReport {
    pub name: String,
    pub path: String,
    /// Null when the file does not exist.
    #[ts(type = "number | null")]
    pub size_bytes: Option<u64>,
}

/// A worker process of the manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WorkerResource {
    pub instance_id: InstanceId,
    #[ts(type = "number")]
    pub generation: u64,
    pub pid: u32,
    /// Process start time as the OS reports it; null when the OS did not say.
    pub process_started_at: Option<Timestamp>,
    /// The Instance's phase; null when its actor did not answer in time.
    pub phase: Option<Phase>,
}

/// A loopback listener the manager holds for a Gateway (across generations).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ListenerResource {
    pub instance_id: InstanceId,
    pub gateway_id: GatewayId,
    pub port: u16,
    pub state: GatewayState,
}

/// A per-key lock file (`locks/key-<fingerprint>.lock`). The fingerprint is a hash of a public
/// key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LockResource {
    pub file: String,
    /// Some process holds the lock; null when it could not be tested.
    pub held: Option<bool>,
    /// The live worker of ours that uses this key.
    pub used_by: Option<InstanceId>,
}

/// A private connector socket of one Instance generation (`c-<id>-<generation>.sock`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SocketResource {
    pub file: String,
    /// It belongs to a live worker of ours.
    pub live: bool,
    pub used_by: Option<InstanceId>,
}

/// The strict-mode sandbox (Linux) the manager holds for an Instance across worker generations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SandboxResource {
    pub instance_id: InstanceId,
    #[ts(type = "number")]
    pub epoch: u64,
    /// The holder process (pid 1 of the sandbox's pid namespace), as the host numbers it.
    pub holder_pid: u32,
    /// Its rendezvous socket (`sb-<instance>.sock`).
    pub file: String,
}

/// The process tree of one managed App the manager supervises (its root: pid and start time).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AppResource {
    pub app_id: AppId,
    pub pid: u32,
    /// Start of the root process; null when it was not recorded.
    pub process_started_at: Option<Timestamp>,
    pub state: AppRunState,
    /// Processes in the tree at the last check; null before the first one.
    pub process_count: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct OwnedResources {
    pub workers: Vec<WorkerResource>,
    pub listeners: Vec<ListenerResource>,
    pub key_locks: Vec<LockResource>,
    pub connector_sockets: Vec<SocketResource>,
    #[serde(default)]
    pub sandboxes: Vec<SandboxResource>,
    /// Managed Apps' process trees.
    #[serde(default)]
    pub apps: Vec<AppResource>,
    /// Connections that did not answer in time: their listeners are missing from `listeners`
    /// (not known, not none).
    #[serde(default)]
    pub unanswered: Vec<InstanceId>,
}

/// The SSH Manager projection, without any host, alias or address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SshProjectionReport {
    pub available: bool,
    pub include: SshIncludeState,
    pub file: SshFileState,
    pub pending: bool,
    /// Null when the stored hosts could not be read (`hosts_error` says why).
    pub hosts: Option<u32>,
    pub hosts_error: Option<Text>,
    pub last_error: Option<Text>,
}

/// A place an inspection could not look at, and why: what it found is not the whole picture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ScanGap {
    /// What could not be checked, in words.
    pub what: Text,
    pub path: Option<String>,
    pub reason: Text,
}

/// Instances by phase, as the manager observes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PhaseCount {
    pub phase: Phase,
    pub count: u32,
}

/// What the manager reports about itself (`Call::Diagnostics`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ManagerReport {
    pub process: ProcessReport,
    /// The `vpnctl` installed next to `vpnd`.
    pub vpnctl: BinaryDigest,
    pub installation_id: InstallationId,
    pub data_dir: String,
    pub run_dir: String,
    pub sqlite_version: String,
    pub databases: Vec<DatabaseReport>,
    pub vault_key: VaultKeyReport,
    /// Key files and other state files, by size.
    pub files: Vec<FileReport>,
    pub logs: Vec<FileReport>,
    /// Why the log directory could not be read (then `logs` is not the whole list).
    pub logs_error: Option<Text>,
    pub metrics_ingress: MetricsIngressReport,
    pub instances: Vec<PhaseCount>,
    pub resources: OwnedResources,
    /// Anomalies a recovery would look at (see `GET /v1/recovery`).
    pub recovery_items: u32,
    /// Where that inspection could not look (then `recovery_items` may be incomplete).
    pub recovery_gaps: Vec<ScanGap>,
    pub ssh: Option<SshProjectionReport>,
    /// The data directory's free space (absent from a manager that does not report it).
    #[serde(default)]
    pub disk: Option<DiskReport>,
    pub observed_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum CheckStatus {
    Ok,
    Warning,
    Failed,
    /// Could not be determined (never shown as ok).
    Unknown,
}

/// One conclusion drawn from the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DiagnosticCheck {
    pub id: String,
    pub status: CheckStatus,
    pub message: Text,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ComponentVersions {
    pub gotatun: String,
    pub smoltcp: String,
    /// Linked SQLite (from the manager; null while it is unreachable).
    pub sqlite: Option<String>,
}

/// `GET /v1/system/diagnostics`: versions, binaries, Store health, owned resources and checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DiagnosticReport {
    pub schema_version: u32,
    /// Always true: secrets, destinations and account numbers are never part of it.
    pub redacted: bool,
    pub generated_at: Timestamp,
    pub os: String,
    pub arch: String,
    pub components: ComponentVersions,
    pub checks: Vec<DiagnosticCheck>,
    pub controller: ProcessReport,
    /// Null while the manager is unreachable (`manager_error` says why).
    pub manager: Option<ManagerReport>,
    pub manager_error: Option<Text>,
    pub capabilities: Vec<Capability>,
    /// Why `capabilities` could not be read (then it is empty, not "none").
    pub capabilities_error: Option<Text>,
}

// ---------------------------------------------------------------------------------------------
// Recovery (`GET /v1/recovery`, `POST /v1/recovery/reconcile`)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum RecoveryKind {
    /// A worker of ours whose manager is gone (pid, start time and program match our record).
    OrphanWorker,
    /// A strict-mode sandbox (Linux) of this installation that no manager holds: left by a
    /// crash, or by a teardown that did not finish. Its holder proves installation, user, boot
    /// and start time; cleaning it ends its Apps first.
    OrphanSandbox,
    /// A worker record whose process is gone, or whose pid now belongs to another program.
    StaleWorkerRecord,
    /// A key lock file nobody holds, for a key no profile uses any more.
    StaleKeyLock,
    /// A key lock held by a process that is not one of our live workers (not touched).
    ForeignKeyLock,
    /// A connector, relay or sandbox rendezvous socket nobody listens on.
    StaleSocket,
    /// A socket of ours someone listens on that is neither one of our live workers nor a sandbox
    /// that proves it is ours (not touched).
    ForeignSocket,
    /// A half-written temporary file of an atomic write whose writer is gone.
    TempFile,
    /// A managed App's process tree an earlier manager left running that could not be confirmed
    /// ended (its run record proves it ours: root pid with its start time).
    AppLeftover,
}

/// One owned resource or leftover found by an inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RecoveryItem {
    /// Stable while the same thing is found (kind, path or process identity).
    pub id: String,
    pub kind: RecoveryKind,
    pub title: Text,
    /// What was found and why it is (or is not) provably ours.
    pub detail: Text,
    pub path: Option<String>,
    pub pid: Option<u32>,
    pub instance_id: Option<InstanceId>,
    /// A reconcile cleans it (it is verifiably ours and stale).
    pub cleanable: bool,
    /// What a reconcile does to it; null when it is left alone.
    pub action: Option<Text>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RecoveryReport {
    pub observed_at: Timestamp,
    pub items: Vec<RecoveryItem>,
    pub resources: OwnedResources,
    /// Where the inspection could not look: no item there does not mean nothing is there.
    pub gaps: Vec<ScanGap>,
}

/// `POST /v1/recovery/reconcile`. `items`: the ids the user confirmed; only those still found
/// and cleanable are cleaned. Omitted: everything cleanable now.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct ReconcileInput {
    #[serde(default)]
    pub items: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ReconcileOutcome {
    Done,
    /// Left alone (gone meanwhile, no longer provably ours, or not confirmed).
    Skipped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ReconcileAction {
    pub item_id: String,
    /// Null for a confirmed item that was no longer found.
    pub kind: Option<RecoveryKind>,
    pub title: Text,
    pub outcome: ReconcileOutcome,
    pub detail: Text,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ReconcileResult {
    pub operation_id: Option<OperationId>,
    pub observed_at: Timestamp,
    pub actions: Vec<ReconcileAction>,
    /// What an inspection right after finds.
    pub remaining: Vec<RecoveryItem>,
}
