//! Performance Manager contract: the passive analysis of the running product (`GET
//! /v1/performance/summary`, `/series`).
//!
//! Adapted from `PERFORMANCE_MANAGER.md`; the differences are listed in docs/architecture.md §9.
//!
//! Honesty rules the types carry: a value that is not known is `null` with a reason code, never
//! `0`; every number says whether it is a measurement or derived from measurements; a target is
//! never shown as an actual value.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::common::{Counter, Timestamp};
use crate::ids::{GatewayId, InstanceId};
use crate::metrics::{MetricsGap, MetricsRange};
use crate::status::Phase;
use crate::text::Text;

/// Reason codes of unknown or qualified values. The UI explains each in words; logs and the API
/// carry only the code.
pub mod reason {
    /// Nothing has been measured for this value yet.
    pub const NOT_MEASURED: &str = "NOT_MEASURED";
    /// Fewer than two continuous samples in the window: no rate can be formed.
    pub const INSUFFICIENT_SAMPLES: &str = "INSUFFICIENT_SAMPLES";
    /// The Instance has no running worker.
    pub const INSTANCE_NOT_RUNNING: &str = "INSTANCE_NOT_RUNNING";
    /// A new generation (worker process) started inside the window.
    pub const NEW_GENERATION: &str = "NEW_GENERATION";
    /// A cumulative counter went backwards or a clock did not advance.
    pub const COUNTER_RESET: &str = "COUNTER_RESET";
    /// Two samples are further apart than max(5 s, 2.5 × the sample interval).
    pub const LONG_INTERVAL: &str = "LONG_INTERVAL";
    /// The quantile falls in the last (+∞) bucket: no upper bound exists.
    pub const OVERFLOW_BUCKET: &str = "OVERFLOW_BUCKET";
    /// No latency was recorded in the window.
    pub const NO_LATENCY_SAMPLES: &str = "NO_LATENCY_SAMPLES";
    /// The process or platform does not report this value.
    pub const NOT_REPORTED: &str = "NOT_REPORTED";
    /// The value has no meaning at this scope (e.g. `WireGuard` bytes of one proxy port).
    pub const NOT_APPLICABLE: &str = "NOT_APPLICABLE";
    /// The host is not the spec's reference environment (8 logical CPUs, 16 GiB RAM, ...).
    pub const NOT_REFERENCE_ENVIRONMENT: &str = "NOT_REFERENCE_ENVIRONMENT";
    /// The value only applies while no data flows are open.
    pub const NOT_IDLE: &str = "NOT_IDLE";
}

// ---------------------------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------------------------

/// Where a number comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ObservationSource {
    /// Read directly (a counter, a gauge).
    Measurement,
    /// Computed from measurements (a rate, a quantile, a ratio).
    Derived,
}

/// A number with its provenance. `value: null` always comes with a `reason_code`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NumericObservation {
    pub value: Option<f64>,
    pub reason_code: Option<String>,
    pub source: ObservationSource,
}

impl NumericObservation {
    #[must_use]
    pub const fn known(value: f64, source: ObservationSource) -> Self {
        Self {
            value: Some(value),
            reason_code: None,
            source,
        }
    }

    #[must_use]
    pub fn unknown(reason: &str, source: ObservationSource) -> Self {
        Self {
            value: None,
            reason_code: Some(reason.into()),
            source,
        }
    }

    /// `Ok` is known; `Err` carries the reason it is not.
    #[must_use]
    pub fn from_result(r: Result<f64, &str>, source: ObservationSource) -> Self {
        match r {
            Ok(v) => Self::known(v, source),
            Err(reason) => Self::unknown(reason, source),
        }
    }
}

/// A byte count with its provenance (u64 as a decimal string).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ByteObservation {
    pub value: Option<Counter>,
    pub reason_code: Option<String>,
    pub source: ObservationSource,
}

impl ByteObservation {
    #[must_use]
    pub const fn known(value: u64, source: ObservationSource) -> Self {
        Self {
            value: Some(Counter(value)),
            reason_code: None,
            source,
        }
    }

    #[must_use]
    pub fn unknown(reason: &str, source: ObservationSource) -> Self {
        Self {
            value: None,
            reason_code: Some(reason.into()),
            source,
        }
    }

    #[must_use]
    pub fn from_result(r: Result<u64, &str>, source: ObservationSource) -> Self {
        match r {
            Ok(v) => Self::known(v, source),
            Err(reason) => Self::unknown(reason, source),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Latency
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum LatencyKind {
    /// Gateway: from a client's request to the tunnel connection being established.
    ProxyConnect,
    DnsResolution,
}

/// Quantiles over a window, from merged bucket counts (never averaged per-second quantiles).
///
/// The counts are of the product's fixed latency buckets ([`crate::LATENCY_BUCKETS_US`], version
/// [`crate::LATENCY_HISTOGRAM_VERSION`]) the workers record in.
///
/// A quantile is the upper bound of the first bucket whose cumulative count reaches `ceil(q ×
/// count)`, and `*_lower_us` is that bucket's lower bound: the true value lies in between. In the
/// +∞ bucket the upper bound is null (`OVERFLOW_BUCKET`). Timeouts are counted apart and are never
/// a latency.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LatencySummary {
    pub kind: LatencyKind,
    /// `latency-us-v1`: histograms of different versions are never merged.
    pub histogram_version: String,
    /// Always `bucket_upper_bound`.
    pub quantile_method: String,
    pub count: Counter,
    pub timeout_count: Counter,
    /// Observations in the +∞ bucket.
    pub overflow_count: Counter,
    pub p50_us: Option<Counter>,
    pub p95_us: Option<Counter>,
    pub p99_us: Option<Counter>,
    pub p50_lower_us: Option<Counter>,
    pub p95_lower_us: Option<Counter>,
    pub p99_lower_us: Option<Counter>,
    /// Upper bound of the highest non-empty bucket; null when that is the +∞ bucket.
    pub max_bucket_upper_us: Option<Counter>,
    /// Share of the window covered by continuous samples.
    pub coverage_ratio: f64,
    pub reason_code: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Processes and passive analysis
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ProcessRole {
    Manager,
    Controller,
    /// One Instance worker (per generation).
    Worker,
}

impl ProcessRole {
    pub const ALL: [Self; 3] = [Self::Manager, Self::Controller, Self::Worker];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manager => "manager",
            Self::Controller => "controller",
            Self::Worker => "worker",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "manager" => Self::Manager,
            "controller" => Self::Controller,
            "worker" => Self::Worker,
            _ => return None,
        })
    }
}

/// One process as last sampled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProcessUsage {
    pub role: ProcessRole,
    /// `pid:<pid>/start:<µs since epoch>`: a reused pid is another process.
    pub process_identity: String,
    pub pid: u32,
    pub started_at: Option<Timestamp>,
    pub instance_id: Option<InstanceId>,
    #[ts(type = "number | null")]
    pub generation: Option<u64>,
    /// CPU time over the last sample interval, percent of one logical CPU (may exceed 100).
    pub cpu_core_pct: NumericObservation,
    pub rss_bytes: ByteObservation,
    pub fd_count: Option<u32>,
    pub observed_at: Option<Timestamp>,
}

/// CPU and memory of one role, or of the whole product (`role: null`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RoleUsage {
    pub role: Option<ProcessRole>,
    pub processes: u32,
    /// Sum over the processes, percent of one logical CPU (100 = one core fully used).
    pub cpu_core_pct: NumericObservation,
    /// `cpu_core_pct / logical CPUs`: share of the whole host, not a power percentage.
    pub cpu_host_pct: NumericObservation,
    /// Sum of resident memory. Pages shared between processes count once per process, so the
    /// sum can exceed what the processes really use together.
    pub rss_bytes: ByteObservation,
    /// Largest such sum in the summary window (sampled, not a true high-water mark).
    pub sampled_peak_rss_bytes: ByteObservation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SystemPerformance {
    pub logical_cpu_count: u32,
    pub host_boot_id: Option<String>,
    /// How often processes are sampled.
    pub sample_interval_secs: u32,
    /// Manager + controllers + workers.
    pub product: RoleUsage,
    pub roles: Vec<RoleUsage>,
    pub processes: Vec<ProcessUsage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum PerformanceScopeKind {
    System,
    Component,
    Instance,
    Gateway,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PerformanceScope {
    pub kind: PerformanceScopeKind,
    /// Null for `system`; the Instance or Gateway id, or the component name.
    pub entity_id: Option<String>,
}

impl PerformanceScope {
    #[must_use]
    pub const fn system() -> Self {
        Self {
            kind: PerformanceScopeKind::System,
            entity_id: None,
        }
    }

    #[must_use]
    pub fn instance(id: InstanceId) -> Self {
        Self {
            kind: PerformanceScopeKind::Instance,
            entity_id: Some(id.to_string()),
        }
    }

    #[must_use]
    pub fn gateway(id: GatewayId) -> Self {
        Self {
            kind: PerformanceScopeKind::Gateway,
            entity_id: Some(id.to_string()),
        }
    }
}

/// Passive figures of one scope over a window ending at `window_end`.
///
/// Payload is client-visible stream bytes (no SOCKS/HTTP handshakes); `WireGuard` bytes are
/// datagram bytes without outer IP/UDP headers; the two are never added. Upload = client →
/// destination.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PerformanceSummary {
    pub scope: PerformanceScope,
    pub observed_at: Timestamp,
    pub window_start: Timestamp,
    pub window_end: Timestamp,
    /// Share of the window covered by continuous samples.
    pub coverage_ratio: f64,
    pub missing_duration_ms: Counter,
    /// Client flows the Gateways serve (TCP connections and UDP associations).
    pub active_data_flows: Option<u32>,
    /// Health probes in flight.
    pub active_probe_flows: Option<u32>,
    /// Tunnel flows that are neither: name resolution for clients, Provider traffic.
    pub active_control_flows: Option<u32>,
    pub latencies: Vec<LatencySummary>,
    pub reason_code: Option<String>,
    pub payload_upload_bps: NumericObservation,
    pub payload_download_bps: NumericObservation,
    pub wireguard_tx_bps: NumericObservation,
    pub wireguard_rx_bps: NumericObservation,
    pub cpu_core_pct: NumericObservation,
    pub cpu_host_pct: NumericObservation,
    pub rss_bytes: ByteObservation,
    pub sampled_peak_rss_bytes: ByteObservation,
}

/// Data flows by protocol (null while unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FlowSplit {
    pub tcp: Option<u32>,
    pub udp: Option<u32>,
}

/// An Instance's admission limits and what they allow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct InstanceCapacity {
    pub max_tcp_flows: u32,
    pub max_udp_flows: u32,
    pub memory_mib: u32,
    /// Buffer memory a new tunnel TCP connection reserves, bytes: the opening sizes of the
    /// connection's transport profile (a buffer that grows later takes more, from the part of
    /// the budget new connections do not need).
    pub tcp_flow_bytes: Counter,
    /// Proxied TCP connections the limits allow at once: the smaller of the TCP flow limit and
    /// what the socket-buffer budget holds at `tcp_flow_bytes` each, after the share kept for
    /// DNS and health probes.
    pub tcp_capacity: u32,
    /// The buffer budget, not the flow limit, is what binds.
    pub tcp_capacity_by_memory: bool,
    /// Socket-buffer memory reserved right now (worker report).
    pub memory_reserved_bytes: Option<Counter>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct GatewayPerformance {
    pub gateway_id: GatewayId,
    pub name: String,
    pub port: u16,
    pub max_connections: u32,
    pub udp: bool,
    pub summary: PerformanceSummary,
    pub data_flows: FlowSplit,
    /// Client connections refused at admission during the latency window (counter delta).
    pub admission_rejected: Option<Counter>,
    pub udp_dropped: Option<Counter>,
    pub connect_timeouts: Option<Counter>,
    /// Connects through the tunnel that failed in the latency window: refused, unreachable, the
    /// name not found.
    pub connect_failures: Option<Counter>,
    /// Of `connect_failures`, the connects whose name does not exist (NXDOMAIN) or has no usable
    /// address.
    pub connect_not_found: Option<Counter>,
}

/// How a measured value compares with an engineering target. `basis` says why the target exists;
/// the target is never an actual value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Verdict {
    Pass,
    Fail,
    NotEvaluated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum CriterionUnit {
    Percent,
    Count,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum CriterionOp {
    Lt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum CriterionBasis {
    /// A proposed engineering budget of the spec (§7); not a measurement.
    ProposedBudget,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PerformanceCriterion {
    pub metric: String,
    pub unit: CriterionUnit,
    pub op: CriterionOp,
    pub target: f64,
    pub observed: Option<f64>,
    pub verdict: Verdict,
    pub basis: CriterionBasis,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct InstancePerformance {
    pub instance_id: InstanceId,
    pub name: String,
    pub phase: Phase,
    #[ts(type = "number | null")]
    pub generation: Option<u64>,
    pub summary: PerformanceSummary,
    pub data_flows: FlowSplit,
    pub admission_rejected: Option<Counter>,
    /// Underlay datagrams the pinned socket refused (wrong peer address) in the window.
    pub underlay_blocked: Option<Counter>,
    pub capacity: InstanceCapacity,
    pub gateways: Vec<GatewayPerformance>,
    /// The spec's idle-CPU target (< 0.5 % of one core per Instance without data flows), judged
    /// only in its reference environment.
    pub idle_cpu: PerformanceCriterion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum HintKind {
    /// Flows at or above 80 % of a proxy port's or connection's limit.
    FlowLimit,
    /// The socket-buffer budget, not the flow count, limits the connection.
    MemoryBudget,
    /// A worker uses at least 90 % of one core.
    WorkerCpu,
    /// Connections were refused at admission in the window.
    AdmissionRejections,
    /// Connects through the tunnel timed out in the window.
    ConnectTimeouts,
    /// Connects through the tunnel failed (refused, unreachable) in the window; names not found
    /// are `ConnectNotFound`.
    ConnectFailures,
    /// Connects named a host that does not exist (NXDOMAIN) or has no usable address in the
    /// window: a name problem (often one a DNS blocklist refuses), not a network fault.
    ConnectNotFound,
    /// The pinned underlay refused datagrams in the window.
    UnderlayBlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum HintSeverity {
    Info,
    Warning,
}

/// A bottleneck *reading* of the numbers (推論), never a measured cause.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BottleneckHint {
    pub kind: HintKind,
    pub scope: PerformanceScope,
    pub severity: HintSeverity,
    /// Always `inference`.
    pub basis: String,
    pub observed: f64,
    pub threshold: f64,
    pub unit: CriterionUnit,
    pub message: Text,
}

/// The spec's 5/10/500 reference work set (a scale definition, never a live value) next to what
/// exists now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ReferenceWorkSet {
    pub instances: u32,
    pub gateways: u32,
    pub data_flows: u32,
    pub gateways_per_instance: u32,
    pub flows_per_gateway: u32,
    /// Live: connections that are ready.
    pub ready_instances: u32,
    /// Live: proxy ports that serve.
    pub serving_gateways: u32,
    /// Live: client flows (null while unknown).
    pub active_data_flows: Option<u32>,
    /// Live: ready connections with at least `gateways_per_instance` proxy ports serving.
    pub eligible_instances: u32,
}

/// `GET /v1/performance/summary`: the passive analysis, refreshed every few seconds from
/// in-memory windows. Generates no traffic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PerformanceOverview {
    pub observed_at: Timestamp,
    /// When the manager began collecting (windows are shorter before that).
    pub collecting_since: Timestamp,
    /// Rates cover the last `rate_window_secs`.
    pub rate_window_secs: u32,
    /// Latency quantiles, coverage and counter deltas cover the last `latency_window_secs`.
    pub latency_window_secs: u32,
    pub system: SystemPerformance,
    pub instances: Vec<InstancePerformance>,
    /// Proxy ports beyond the per-answer limit, left out of `instances[].gateways` (their
    /// Instances' totals still include them).
    pub omitted_gateways: u32,
    pub hints: Vec<BottleneckHint>,
    pub reference: ReferenceWorkSet,
}

/// Proxy ports detailed in one summary at most (keeps the answer within one IPC frame).
pub const SUMMARY_MAX_GATEWAYS: usize = 256;

// ---------------------------------------------------------------------------------------------
// Series
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum PerformanceMetric {
    PayloadUploadBps,
    PayloadDownloadBps,
    WireguardTxBps,
    WireguardRxBps,
    CpuCorePct,
    CpuHostPct,
    RssBytes,
    ActiveDataFlows,
    /// All tunnel flows of a worker (data and control), as its netstack counts them.
    ActiveTunnelFlows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum PerformanceUnit {
    BitPerSecond,
    Percent,
    Bytes,
    Count,
}

/// One column of a series set; `values[i]` belongs to `timestamps[i]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PerformanceSeries {
    pub metric: PerformanceMetric,
    /// The role of a per-role column; null for the scope as a whole.
    pub role: Option<ProcessRole>,
    pub unit: PerformanceUnit,
    pub values: Vec<Option<f64>>,
    /// Share of the range with a value.
    pub coverage_ratio: f64,
    pub reason_code: Option<String>,
}

/// `GET /v1/performance/series?scope=…&range=…`: aligned columns over `[from_ms, to_ms)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PerformanceSeriesSet {
    pub scope: PerformanceScope,
    pub range: MetricsRange,
    pub resolution_secs: u32,
    #[ts(type = "number")]
    pub from_ms: i64,
    #[ts(type = "number")]
    pub to_ms: i64,
    #[ts(type = "Array<number>")]
    pub timestamps: Vec<i64>,
    pub series: Vec<PerformanceSeries>,
    pub gaps: Vec<MetricsGap>,
    pub gaps_truncated: bool,
    /// Where the points come from and what they leave out (reason codes).
    pub notes: Vec<String>,
}

/// Series notes.
pub mod series_note {
    /// Process CPU and memory are sampled every 5 s and kept 24 h raw, 30 days per minute.
    pub const PROCESS_SAMPLES: &str = "PROCESS_SAMPLES_5S";
    /// The Instance and proxy-port figures are the metrics service's persisted series of that
    /// scope.
    pub const INSTANCE_METRICS: &str = "INSTANCE_METRICS";
    /// Summed resident memory counts shared pages once per process.
    pub const RSS_SUM_COUNTS_SHARED_PAGES: &str = "RSS_SUM_COUNTS_SHARED_PAGES";
}
