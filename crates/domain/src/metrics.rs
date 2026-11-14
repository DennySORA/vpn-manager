//! Persisted metrics: `GET /v1/metrics/series?range=…&scope=…` and `GET /v1/metrics/status`.
//!
//! A series query names one of a few fixed ranges ending now and a scope (every Instance, one
//! Instance or one Gateway); the server picks the point spacing (1 s or 5 s from the raw samples,
//! 1 min or 1 h rollups) so a series stays far below [`METRICS_MAX_POINTS`]. The answer is a set
//! of aligned columns: `timestamps[i]` belongs to the `i`-th value of every column. A value that
//! is not known is `null`, never `0`, and `gaps` says why.
//!
//! Latency comes from fixed-bucket histograms ([`LATENCY_HISTOGRAM_VERSION`]): a quantile is the
//! upper bound of the first bucket whose cumulative count reaches `ceil(q × count)` over the
//! merged bucket deltas of its window (never an average of per-second quantiles). It is `null`
//! when the window holds no observation or the quantile falls in the last (+∞) bucket; timeouts
//! are counted beside it and are never a latency value.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;

use crate::common::Timestamp;
use crate::ids::{GatewayId, InstanceId};
use crate::text::Text;
use crate::tr;

/// Most points one series may hold.
pub const METRICS_MAX_POINTS: usize = 10_000;

/// Most gap spans one series answer carries (`gaps_truncated` beyond).
pub const METRICS_MAX_GAPS: usize = 2_000;

/// Most Instances, and most Gateways, one series answer lists with their totals (the scope's
/// own values still include every one).
pub const METRICS_MAX_LISTED: usize = 128;

/// Version tag of every latency histogram: fixed bucket upper bounds in microseconds
/// ([`LATENCY_BUCKETS_US`]). Histograms of different versions are never merged.
pub const LATENCY_HISTOGRAM_VERSION: &str = "latency-us-v1";

/// Upper bounds (µs, inclusive) of the latency buckets of [`LATENCY_HISTOGRAM_VERSION`]; the
/// last bucket is +∞ (`u64::MAX`).
pub const LATENCY_BUCKETS_US: [u64; 16] = [
    500,
    1_000,
    2_000,
    5_000,
    10_000,
    20_000,
    50_000,
    100_000,
    200_000,
    500_000,
    1_000_000,
    2_000_000,
    5_000_000,
    10_000_000,
    30_000_000,
    u64::MAX,
];

/// Buckets per latency histogram.
pub const LATENCY_BUCKET_COUNT: usize = LATENCY_BUCKETS_US.len();

/// How latency quantiles are stated: the upper bound of the bucket that holds them.
pub const LATENCY_QUANTILE_BASIS: &str = "bucket_upper_bound";

/// Time window of a metrics query, ending at the moment it is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[ts(export)]
pub enum MetricsRange {
    #[serde(rename = "15m")]
    Last15m,
    #[serde(rename = "1h")]
    Last1h,
    #[serde(rename = "6h")]
    Last6h,
    #[serde(rename = "24h")]
    Last24h,
    #[serde(rename = "7d")]
    Last7d,
    #[serde(rename = "30d")]
    Last30d,
}

impl MetricsRange {
    pub const ALL: [Self; 6] = [
        Self::Last15m,
        Self::Last1h,
        Self::Last6h,
        Self::Last24h,
        Self::Last7d,
        Self::Last30d,
    ];

    /// Query-string form (`15m`, `1h`, `6h`, `24h`, `7d`, `30d`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Last15m => "15m",
            Self::Last1h => "1h",
            Self::Last6h => "6h",
            Self::Last24h => "24h",
            Self::Last7d => "7d",
            Self::Last30d => "30d",
        }
    }

    #[must_use]
    pub const fn duration_ms(self) -> i64 {
        const MIN: i64 = 60_000;
        match self {
            Self::Last15m => 15 * MIN,
            Self::Last1h => 60 * MIN,
            Self::Last6h => 6 * 60 * MIN,
            Self::Last24h => 24 * 60 * MIN,
            Self::Last7d => 7 * 24 * 60 * MIN,
            Self::Last30d => 30 * 24 * 60 * MIN,
        }
    }
}

impl fmt::Display for MetricsRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("range must be 15m, 1h, 6h, 24h, 7d or 30d")]
pub struct UnknownMetricsRange;

/// What to tell the user.
impl From<UnknownMetricsRange> for Text {
    fn from(_: UnknownMetricsRange) -> Self {
        tr!(
            "range must be 15m, 1h, 6h, 24h, 7d or 30d",
            "range 必須是 15m、1h、6h、24h、7d 或 30d",
            "range は 15m、1h、6h、24h、7d、30d のいずれかにしてください"
        )
    }
}

impl FromStr for MetricsRange {
    type Err = UnknownMetricsRange;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|r| r.as_str() == s.trim())
            .ok_or(UnknownMetricsRange)
    }
}

/// What a metrics query covers: `all` (every Instance, summed), `instance:<id>` or
/// `gateway:<id>` (one Gateway's own traffic, connections and connect latency).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TS)]
#[ts(export, type = "string")]
pub enum MetricsScope {
    All,
    Instance(InstanceId),
    Gateway(GatewayId),
}

impl fmt::Display for MetricsScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("all"),
            Self::Instance(id) => write!(f, "instance:{id}"),
            Self::Gateway(id) => write!(f, "gateway:{id}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("scope must be all, instance:<id> or gateway:<id>")]
pub struct UnknownMetricsScope;

/// What to tell the user.
impl From<UnknownMetricsScope> for Text {
    fn from(_: UnknownMetricsScope) -> Self {
        tr!(
            "scope must be all, instance:<id> or gateway:<id>",
            "scope 必須是 all、instance:<id> 或 gateway:<id>",
            "scope は all、instance:<id>、gateway:<id> のいずれかにしてください"
        )
    }
}

impl FromStr for MetricsScope {
    type Err = UnknownMetricsScope;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s == "all" {
            return Ok(Self::All);
        }
        match s.split_once(':') {
            Some(("instance", id)) => id
                .parse()
                .map(MetricsScope::Instance)
                .map_err(|_| UnknownMetricsScope),
            Some(("gateway", id)) => id
                .parse()
                .map(MetricsScope::Gateway)
                .map_err(|_| UnknownMetricsScope),
            _ => Err(UnknownMetricsScope),
        }
    }
}

impl Serialize for MetricsScope {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MetricsScope {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Why values are unknown in part of a series. Unknown is shown as a gap, never as zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum MetricsGapReason {
    /// No samples: the Instance was not running, or nothing was recorded for that time.
    Missing,
    /// Two samples are further apart than max(5 s, 2.5 × sample interval), on the worker's clock
    /// or by arrival (the worker's clock stands still while the host sleeps): no rate across
    /// them.
    LongInterval,
    /// A cumulative counter went backwards or the worker clock did not advance.
    CounterReset,
    /// A new generation (worker process) started; its counters begin again at zero.
    NewGeneration,
    /// Samples were dropped before they were stored (collector queue full, Store busy).
    Dropped,
    /// Data was deleted early to keep the metrics database within its disk quota.
    Quota,
    /// The data directory's volume was low on space: samples were not stored, or the oldest
    /// data was deleted early to free space.
    DiskLow,
    /// The worker did not report this value (e.g. resident memory on this platform).
    Unavailable,
}

/// A span in which some or all values are unknown, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsGap {
    /// Start, inclusive (unix milliseconds).
    #[ts(type = "number")]
    pub from_ms: i64,
    /// End, exclusive (unix milliseconds).
    #[ts(type = "number")]
    pub to_ms: i64,
    pub reason: MetricsGapReason,
}

/// The histogram behind the latency columns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LatencyBasis {
    /// [`LATENCY_HISTOGRAM_VERSION`].
    pub histogram: String,
    /// [`LATENCY_QUANTILE_BASIS`]: a quantile is the upper bound of the bucket holding it.
    pub quantile: String,
    /// Finite bucket upper bounds (µs, ascending); one more bucket above the last is +∞.
    #[ts(type = "Array<number>")]
    pub bucket_upper_bounds_us: Vec<u64>,
}

impl Default for LatencyBasis {
    fn default() -> Self {
        Self {
            histogram: LATENCY_HISTOGRAM_VERSION.into(),
            quantile: LATENCY_QUANTILE_BASIS.into(),
            bucket_upper_bounds_us: LATENCY_BUCKETS_US[..LATENCY_BUCKET_COUNT - 1].to_vec(),
        }
    }
}

/// Totals of one scope (or one Instance, one Gateway) over the range of a series answer.
///
/// Bytes are counter deltas over continuous sample intervals only (never across a reset or a new
/// generation), so time without samples adds nothing and lowers `covered_ms` instead. A value is
/// `null` when nothing in the range could measure it. Latency quantiles follow the module rules:
/// with `connect_count` `null` nothing was measured, with `0` no connect completed, and with a
/// positive count a `null` quantile lies in the +∞ bucket (over 30 s).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsTotals {
    /// Length of the range (`to_ms − from_ms`).
    #[ts(type = "number")]
    pub range_ms: i64,
    /// Time covered by continuous samples. For `scope=all`: time in which at least one Instance
    /// reported (per point, the best-covered Instance; a lower bound of the union).
    #[ts(type = "number")]
    pub covered_ms: i64,
    /// Time the payload gate was open (traffic admitted) within the covered time. `null` when
    /// part of the covered time has no recorded gate state, and for `scope=all`.
    #[ts(type = "number | null")]
    pub serving_ms: Option<i64>,
    /// Payload received (bytes): client-visible by the Gateways, plus what the port forwards
    /// relayed to the Apps and the Apps of a strict sandbox (`sandbox_rx_bytes`, the forwards
    /// included there).
    #[ts(type = "number | null")]
    pub payload_rx_bytes: Option<u64>,
    /// Payload sent (bytes), the same way.
    #[ts(type = "number | null")]
    pub payload_tx_bytes: Option<u64>,
    /// `WireGuard` UDP datagram bytes received (bytes; `null` for a Gateway).
    #[ts(type = "number | null")]
    pub wg_rx_bytes: Option<u64>,
    #[ts(type = "number | null")]
    pub wg_tx_bytes: Option<u64>,
    /// Highest point of `payload_rx_bps` in the range (bit/s, averaged over one point).
    pub peak_payload_rx_bps: Option<f64>,
    pub peak_payload_tx_bps: Option<f64>,
    /// Strict mode: of the payload, what the sandbox's Apps received — the TCP segment and UDP
    /// payload of their own flows as it crossed the sandbox's TUN device, retransmissions
    /// included, plus what the port forwards delivered to them (bytes; data from before
    /// 2026-11-07 left the forwards out). `null` when nothing in the range had a sandbox (a
    /// connection without strict isolation, a Gateway, data from before this was counted):
    /// there was nothing to count, not 0.
    #[serde(default)]
    #[ts(type = "number | null")]
    pub sandbox_rx_bytes: Option<u64>,
    /// What the sandbox's Apps sent (bytes), the same way.
    #[serde(default)]
    #[ts(type = "number | null")]
    pub sandbox_tx_bytes: Option<u64>,
    /// Highest point of `sandbox_rx_bps` and `sandbox_tx_bps` in the range.
    #[serde(default)]
    pub peak_sandbox_rx_bps: Option<f64>,
    #[serde(default)]
    pub peak_sandbox_tx_bps: Option<f64>,
    /// Of the payload, what the Gateways relayed for SSH sessions (「SSH 代理」: TCP connections
    /// to port 22, or marked as SSH by `vpnctl ssh-proxy`), received and sent (bytes). `null`
    /// when it was not recorded in the range (data from before 2026-11-07): not 0.
    #[serde(default)]
    #[ts(type = "number | null")]
    pub ssh_rx_bytes: Option<u64>,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub ssh_tx_bytes: Option<u64>,
    /// Of the payload, what the Gateways relayed for VPN Manager's own SSH downloads (「SSH
    /// 下載」), never also in `ssh_*` (bytes; `null` the same way).
    #[serde(default)]
    #[ts(type = "number | null")]
    pub ssh_pull_rx_bytes: Option<u64>,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub ssh_pull_tx_bytes: Option<u64>,
    /// Highest point of `ssh_rx_bps`, `ssh_tx_bps`, `ssh_pull_rx_bps` and `ssh_pull_tx_bps`.
    #[serde(default)]
    pub peak_ssh_rx_bps: Option<f64>,
    #[serde(default)]
    pub peak_ssh_tx_bps: Option<f64>,
    #[serde(default)]
    pub peak_ssh_pull_rx_bps: Option<f64>,
    #[serde(default)]
    pub peak_ssh_pull_tx_bps: Option<f64>,
    /// Highest point of the payload without its SSH parts (`payload − ssh − ssh_pull`, where
    /// they are known): for a Gateway, its ordinary proxy traffic.
    #[serde(default)]
    pub peak_non_ssh_rx_bps: Option<f64>,
    #[serde(default)]
    pub peak_non_ssh_tx_bps: Option<f64>,
    /// DNS lookups (each call of the resolver), failed lookups and lookups answered from cache
    /// (`null` for a Gateway).
    #[ts(type = "number | null")]
    pub dns_queries: Option<u64>,
    #[ts(type = "number | null")]
    pub dns_failures: Option<u64>,
    #[ts(type = "number | null")]
    pub dns_cache_hits: Option<u64>,
    /// Proxy connects that reached the destination (each one is a latency observation).
    #[ts(type = "number | null")]
    pub connect_count: Option<u64>,
    /// Proxy connects that ran out of time (not latency observations).
    #[ts(type = "number | null")]
    pub connect_timeouts: Option<u64>,
    /// Proxy connects that failed otherwise: refused, unreachable, name not resolved.
    #[ts(type = "number | null")]
    pub connect_failures: Option<u64>,
    /// Of `connect_failures`, the connects whose name does not exist (NXDOMAIN) or has no usable
    /// address. `null` also when some of those failures were recorded before this was counted.
    #[ts(type = "number | null")]
    pub connect_not_found: Option<u64>,
    /// Requests the Gateway itself refused: destination policy, closed gate, connection limits.
    #[ts(type = "number | null")]
    pub connect_rejected: Option<u64>,
    #[ts(type = "number | null")]
    pub connect_p50_us: Option<u64>,
    #[ts(type = "number | null")]
    pub connect_p95_us: Option<u64>,
    #[ts(type = "number | null")]
    pub connect_p99_us: Option<u64>,
    /// DNS lookups answered by an upstream server through the tunnel (latency observations;
    /// cache hits are not among them). `null` for a Gateway.
    #[ts(type = "number | null")]
    pub dns_upstream_count: Option<u64>,
    /// DNS lookups whose deadline passed.
    #[ts(type = "number | null")]
    pub dns_timeouts: Option<u64>,
    #[ts(type = "number | null")]
    pub dns_p50_us: Option<u64>,
    #[ts(type = "number | null")]
    pub dns_p95_us: Option<u64>,
    #[ts(type = "number | null")]
    pub dns_p99_us: Option<u64>,
}

/// Totals of one Instance within a series answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct InstanceMetricsTotals {
    pub instance_id: InstanceId,
    pub totals: MetricsTotals,
}

/// Totals of one Gateway within a series answer (its own traffic, connections and latency).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct GatewayMetricsTotals {
    pub gateway_id: GatewayId,
    /// The Instance the Gateway belonged to while these samples were taken.
    pub instance_id: InstanceId,
    pub totals: MetricsTotals,
}

/// `GET /v1/metrics/series`: aligned columns over `[from_ms, to_ms)`.
///
/// Every point stands for the window `[timestamps[i], timestamps[i] + resolution_secs)` (the
/// last one ends at `to_ms`). Rates are bits per second (bytes × 8, decimal units) over the time
/// samples covered in the window; gauges (flows, memory) are time-weighted means; per-second
/// rates and counts of `scope=all` are sums over the Instances that reported, the cache-hit
/// ratio is total hits over total lookups and latency merges the histograms. Count columns
/// (`connect_*`, `dns_upstream_count`, `dns_timeouts`) attribute each sample interval to the
/// window in which it ended. A Gateway scope has no `WireGuard`, DNS or resource columns: those
/// are `null` throughout (not applicable).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsSeries {
    pub scope: MetricsScope,
    pub range: MetricsRange,
    /// Seconds per point: 1 or 5 (from raw samples), 60 or 3600 (rollups).
    pub resolution_secs: u32,
    #[ts(type = "number")]
    pub from_ms: i64,
    #[ts(type = "number")]
    pub to_ms: i64,
    /// Point times, ascending (unix milliseconds).
    #[ts(type = "Array<number>")]
    pub timestamps: Vec<i64>,
    /// How many Instances (Gateways, for a Gateway scope) reported in each point.
    pub reporting: Vec<u32>,
    /// Payload received (bit/s): client-visible by the Gateways, plus what the port forwards
    /// relayed and the Apps of a strict sandbox.
    pub payload_rx_bps: Vec<Option<f64>>,
    /// Payload sent (bit/s), the same way.
    pub payload_tx_bps: Vec<Option<f64>>,
    /// Strict mode: the sandbox's Apps' part of `payload_rx_bps` (bit/s), the connections
    /// forwarded to them included; `null` where no connection of the scope had a sandbox (always
    /// for a Gateway scope).
    #[serde(default)]
    pub sandbox_rx_bps: Vec<Option<f64>>,
    /// The sandbox's Apps' part of `payload_tx_bps` (bit/s).
    #[serde(default)]
    pub sandbox_tx_bps: Vec<Option<f64>>,
    /// The SSH sessions' part of `payload_rx_bps` and `payload_tx_bps` (bit/s, 「SSH 代理」);
    /// `null` where it was not recorded.
    #[serde(default)]
    pub ssh_rx_bps: Vec<Option<f64>>,
    #[serde(default)]
    pub ssh_tx_bps: Vec<Option<f64>>,
    /// VPN Manager's own SSH downloads' part (bit/s, 「SSH 下載」).
    #[serde(default)]
    pub ssh_pull_rx_bps: Vec<Option<f64>>,
    #[serde(default)]
    pub ssh_pull_tx_bps: Vec<Option<f64>>,
    /// `WireGuard` UDP datagram bytes received (bit/s, without outer IP/UDP headers).
    pub wg_rx_bps: Vec<Option<f64>>,
    /// `WireGuard` UDP datagram bytes sent (bit/s).
    pub wg_tx_bps: Vec<Option<f64>>,
    /// Active TCP flows (gauge): every TCP flow through the tunnel, DNS and management ones
    /// included; for a Gateway scope its own client connections.
    pub active_tcp: Vec<Option<f64>>,
    /// Active UDP flows (gauge): every UDP flow through the tunnel; for a Gateway scope its UDP
    /// associations.
    pub active_udp: Vec<Option<f64>>,
    /// DNS lookups per second.
    pub dns_queries_per_sec: Vec<Option<f64>>,
    /// Failed DNS lookups per second.
    pub dns_failures_per_sec: Vec<Option<f64>>,
    /// Share of DNS lookups answered from cache, 0–1 (`null` without lookups).
    pub dns_cache_hit_ratio: Vec<Option<f64>>,
    /// Proxy connects that reached the destination in the window.
    #[ts(type = "Array<number | null>")]
    pub connect_count: Vec<Option<u64>>,
    #[ts(type = "Array<number | null>")]
    pub connect_timeouts: Vec<Option<u64>>,
    #[ts(type = "Array<number | null>")]
    pub connect_failures: Vec<Option<u64>>,
    /// Of `connect_failures`, the names that do not exist or have no usable address.
    #[ts(type = "Array<number | null>")]
    pub connect_not_found: Vec<Option<u64>>,
    #[ts(type = "Array<number | null>")]
    pub connect_rejected: Vec<Option<u64>>,
    /// Proxy connect latency quantiles (µs, bucket upper bounds).
    #[ts(type = "Array<number | null>")]
    pub connect_p50_us: Vec<Option<u64>>,
    #[ts(type = "Array<number | null>")]
    pub connect_p95_us: Vec<Option<u64>>,
    #[ts(type = "Array<number | null>")]
    pub connect_p99_us: Vec<Option<u64>>,
    /// DNS lookups answered from upstream in the window (latency observations).
    #[ts(type = "Array<number | null>")]
    pub dns_upstream_count: Vec<Option<u64>>,
    #[ts(type = "Array<number | null>")]
    pub dns_timeouts: Vec<Option<u64>>,
    /// DNS resolution latency quantiles (µs, bucket upper bounds; cache hits excluded).
    #[ts(type = "Array<number | null>")]
    pub dns_p50_us: Vec<Option<u64>>,
    #[ts(type = "Array<number | null>")]
    pub dns_p95_us: Vec<Option<u64>>,
    #[ts(type = "Array<number | null>")]
    pub dns_p99_us: Vec<Option<u64>>,
    /// Worker CPU time as a percentage of one core (summed for `scope=all`).
    pub cpu_core_pct: Vec<Option<f64>>,
    /// Worker resident memory (bytes; summed for `scope=all`, shared pages counted per worker).
    pub rss_bytes: Vec<Option<f64>>,
    /// Why values are `null`, as merged spans in ascending order.
    pub gaps: Vec<MetricsGap>,
    /// More gaps existed than one answer carries; the `null` values remain authoritative.
    pub gaps_truncated: bool,
    /// Starts of the windows in which a new worker generation began (a restart; counters begin
    /// again at zero), ascending, at the answer's resolution.
    #[ts(type = "Array<number>")]
    pub restarts: Vec<i64>,
    pub latency: LatencyBasis,
    /// The whole scope over the range.
    pub totals: MetricsTotals,
    /// Each Instance in the scope that has data in the range.
    pub instances: Vec<InstanceMetricsTotals>,
    /// Each Gateway in the scope that has data in the range.
    pub gateways: Vec<GatewayMetricsTotals>,
    /// More Instances or Gateways had data than one answer lists ([`METRICS_MAX_LISTED`] of
    /// each, in the order they first reported); the scope's values still include them all.
    pub entities_truncated: bool,
}

impl MetricsSeries {
    /// A series without points.
    #[must_use]
    pub fn empty(
        scope: MetricsScope,
        range: MetricsRange,
        resolution_secs: u32,
        from_ms: i64,
        to_ms: i64,
    ) -> Self {
        Self {
            scope,
            range,
            resolution_secs,
            from_ms,
            to_ms,
            timestamps: Vec::new(),
            reporting: Vec::new(),
            payload_rx_bps: Vec::new(),
            payload_tx_bps: Vec::new(),
            sandbox_rx_bps: Vec::new(),
            ssh_rx_bps: Vec::new(),
            ssh_tx_bps: Vec::new(),
            ssh_pull_rx_bps: Vec::new(),
            ssh_pull_tx_bps: Vec::new(),
            sandbox_tx_bps: Vec::new(),
            wg_rx_bps: Vec::new(),
            wg_tx_bps: Vec::new(),
            active_tcp: Vec::new(),
            active_udp: Vec::new(),
            dns_queries_per_sec: Vec::new(),
            dns_failures_per_sec: Vec::new(),
            dns_cache_hit_ratio: Vec::new(),
            connect_count: Vec::new(),
            connect_timeouts: Vec::new(),
            connect_failures: Vec::new(),
            connect_not_found: Vec::new(),
            connect_rejected: Vec::new(),
            connect_p50_us: Vec::new(),
            connect_p95_us: Vec::new(),
            connect_p99_us: Vec::new(),
            dns_upstream_count: Vec::new(),
            dns_timeouts: Vec::new(),
            dns_p50_us: Vec::new(),
            dns_p95_us: Vec::new(),
            dns_p99_us: Vec::new(),
            cpu_core_pct: Vec::new(),
            rss_bytes: Vec::new(),
            gaps: Vec::new(),
            gaps_truncated: false,
            restarts: Vec::new(),
            latency: LatencyBasis::default(),
            totals: MetricsTotals {
                range_ms: to_ms - from_ms,
                ..Default::default()
            },
            instances: Vec::new(),
            gateways: Vec::new(),
            entities_truncated: false,
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.timestamps.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.timestamps.is_empty()
    }
}

/// Retention of each stored resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsRetention {
    /// Raw (per-second) samples: Settings `metrics_retention_raw_hours`.
    pub raw_hours: u32,
    /// 1-minute rollups.
    pub minute_days: u32,
    /// 1-hour rollups.
    pub hour_days: u32,
}

/// A time per stored resolution (unix ms); `null` where there is none.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsTierTimes {
    #[ts(type = "number | null")]
    pub raw_ms: Option<i64>,
    #[ts(type = "number | null")]
    pub minute_ms: Option<i64>,
    #[ts(type = "number | null")]
    pub hour_ms: Option<i64>,
}

/// What made data unknown during the last 24 hours, for one reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsGapSummary {
    pub reason: MetricsGapReason,
    /// How often it happened (spans for `dropped`; breaks between samples for
    /// `new_generation`, `counter_reset` and `long_interval`; for rollup minutes written before
    /// this was counted, each minute that had one counts once).
    #[ts(type = "number")]
    pub events: u64,
    /// Time affected, where it is measured (`dropped`, `long_interval`); `null` otherwise or
    /// when part of it was not recorded.
    #[ts(type = "number | null")]
    pub duration_ms: Option<i64>,
    /// When it last happened (unix ms).
    #[ts(type = "number | null")]
    pub last_ms: Option<i64>,
}

/// The last run of a background metrics task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsTaskRun {
    pub at: Timestamp,
    pub ok: bool,
    /// Why it failed (public message), when it did.
    pub error: Option<Text>,
}

/// The last retention and quota run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsRetentionRun {
    pub run: MetricsTaskRun,
    /// Rows past their retention that were deleted.
    #[ts(type = "number")]
    pub expired_rows: u64,
    /// Rows deleted early to stay within the quota (recorded as `quota` gaps).
    #[ts(type = "number")]
    pub quota_rows: u64,
}

/// The collector's ingress since the manager started (`dropped` rows never reached the disk;
/// they are recorded as `dropped` gaps).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsCollectorStatus {
    pub since: Timestamp,
    /// Samples waiting to be written now, and the queue's capacity.
    pub queued: u32,
    pub capacity: u32,
    #[ts(type = "number")]
    pub written: u64,
    #[ts(type = "number")]
    pub dropped: u64,
    /// Samples ignored because one of the same worker clock (or a newer generation) was taken.
    #[ts(type = "number")]
    pub duplicates: u64,
    #[ts(type = "number")]
    pub stale: u64,
    /// Batch writes that failed and were retried.
    #[ts(type = "number")]
    pub write_failures: u64,
}

/// Whether the manager stores metric samples now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum MetricsRecordingState {
    /// Samples are stored (or none arrive: no connection runs).
    Recording,
    /// The data directory's volume is low on space or full: samples are still stored, the
    /// metrics database no longer grows and overwrites its oldest data to make room (each
    /// pruned span a `disk_low` gap) until the volume has room again.
    Overwriting,
    /// Samples cannot be written (`error` says why): they wait in the collector's bounded queue,
    /// the oldest dropped, and the write is retried.
    Failing,
}

/// The manager's metric recording right now (`GET /v1/system/status`, `store.metrics_recording`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsRecording {
    pub state: MetricsRecordingState,
    /// Since when it is overwriting or failing.
    pub since: Option<Timestamp>,
    /// The data directory's free space, and the free space from which the metrics database may
    /// grow again.
    #[ts(type = "number | null")]
    pub free_bytes: Option<u64>,
    #[ts(type = "number | null")]
    pub resume_bytes: Option<u64>,
    /// While overwriting: rows deleted early to make room, and samples not stored at all (the
    /// disk was full even then), since space ran low.
    #[ts(type = "number")]
    pub overwritten_rows: u64,
    #[ts(type = "number")]
    pub lost_samples: u64,
    /// While failing: why the last write failed (public message).
    pub error: Option<Text>,
}

/// `GET /v1/metrics/status`: what is kept, how much space it uses and what went missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetricsStatus {
    /// Workers report one sample per this many milliseconds.
    pub sample_interval_ms: u32,
    pub retention: MetricsRetention,
    /// Disk quota of the metrics database (Settings `metrics_quota_mib`).
    #[ts(type = "number")]
    pub quota_bytes: u64,
    /// Bytes of the database in use (free pages excluded).
    #[ts(type = "number")]
    pub used_bytes: u64,
    /// Size of the database file.
    #[ts(type = "number")]
    pub file_bytes: u64,
    /// In-use bytes exceed the quota (only data that is never pruned early remains).
    pub over_quota: bool,
    /// Oldest data kept per resolution.
    pub oldest: MetricsTierTimes,
    /// Where the quota deleted data early, per resolution: nothing before this time is kept.
    pub pruned_before: MetricsTierTimes,
    /// Rollups are complete up to here (unix ms; the newest minutes are recomputed).
    #[ts(type = "number | null")]
    pub rollup_until_ms: Option<i64>,
    /// Why data was unknown in the last 24 hours, by reason (only reasons that occurred).
    pub gaps_24h: Vec<MetricsGapSummary>,
    pub last_rollup: Option<MetricsTaskRun>,
    pub last_retention: Option<MetricsRetentionRun>,
    pub collector: MetricsCollectorStatus,
    pub observed_at: Timestamp,
}
