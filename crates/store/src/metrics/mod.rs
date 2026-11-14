//! Metrics persistence (`metrics.sqlite`): per-second raw samples of every Instance and of each
//! of its Gateways, 1-minute and 1-hour rollups, explicit gaps, retention and a disk quota. Only
//! counters, gauges and latency histograms are stored: no destinations, names or secrets.
//!
//! How samples relate and fold into buckets is in [`rollup`]; how a range becomes points on a
//! time grid, combined over Instances, is in [`series`]; latency histograms in [`hist`]. A value
//! that cannot be known is `null` with a reason, never zero.
//!
//! Storage is plain rows (no compression codec): raw samples clustered by (series, time), one
//! wide row per rollup bucket, histograms as compact blobs.

mod hist;
mod rollup;
mod series;

use std::collections::HashMap;

use rusqlite::{Connection, OptionalExtension, Row as SqlRow, params};
use vpn_domain::{
    GatewayId, GatewayMetricsTotals, InstanceId, InstanceMetricsTotals, METRICS_MAX_LISTED,
    METRICS_MAX_POINTS, MetricsGapReason, MetricsGapSummary, MetricsRange, MetricsScope,
    MetricsSeries, MetricsTierTimes, Settings,
};

pub use hist::Hist;
pub use rollup::{ConnectCounters, SshBytes};

use rollup::{
    Breaks, Bucket, Gauge, InstBucket, InstRow, Row, ceil_to, floor_to, fold_buckets, rollup_rows,
};
use series::{Grid, Logged, Point, bucket_points, combine, fill, raw_points, totals};

use crate::Store;
use crate::error::StoreError;
use crate::num::{i64_to_f64, u64_to_f64};

/// Workers report one sample per second.
pub const SAMPLE_INTERVAL_MS: u64 = 1_000;
/// Longest interval one rate may span: `max(5 s, 2.5 × sample interval)`.
pub const MAX_GAP_MS: u64 = max_gap_ms(SAMPLE_INTERVAL_MS);
pub const MINUTE_MS: i64 = 60_000;
pub const HOUR_MS: i64 = 60 * MINUTE_MS;
const DAY_MS: i64 = 24 * HOUR_MS;
/// Retention of the rollups (raw retention comes from Settings).
pub const MINUTE_RETENTION_MS: i64 = 30 * DAY_MS;
pub const HOUR_RETENTION_MS: i64 = 180 * DAY_MS;
/// Minute buckets this recent are recomputed by every rollup run, which absorbs samples the
/// collector stored late (its bounded queue holds a few minutes at most).
pub const LOOKBACK_MS: i64 = 10 * MINUTE_MS;
/// Most raw time one rollup run folds while catching up, so it never holds the writer long.
const MAX_SPAN_MS: i64 = 6 * HOUR_MS;
/// Points a range answered from raw samples aims for (the grid step grows to stay below):
/// a reply of every column stays well inside one control frame.
const RAW_POINTS: i64 = 900;
/// Raw rows one answer may read (series × seconds of the range); beyond, minute rollups answer.
const MAX_RAW_ROWS: i64 = 300_000;
/// Rollup buckets of the last hours are never pruned for the quota: the hour rollups are
/// recomputed from them.
const QUOTA_PROTECT_BUCKETS_MS: i64 = 2 * HOUR_MS;
const QUOTA_STEPS: usize = 16;
/// Free pages worth returning to the file system (4 KiB pages: 8 MiB).
const RELEASE_MIN_PAGES: i64 = 2_048;
/// While space is low the metrics database keeps at least this many free pages in its file, and
/// makes [`RING_FREE_PAGES`] when it has fewer: new rows go into them, the file does not grow.
pub const RING_MIN_FREE: i64 = 128;
pub const RING_FREE_PAGES: i64 = 512;
const ROLLUP_KEY: &str = "rollup_until_ms";

/// Gap scopes in `metric_gaps`: samples never stored (all resolutions) or one tier pruned.
const SCOPE_SAMPLES: &str = "samples";

pub const fn max_gap_ms(sample_interval_ms: u64) -> u64 {
    let scaled = sample_interval_ms * 5 / 2;
    if scaled > 5_000 { scaled } else { 5_000 }
}

/// One worker sample as stored: cumulative counters exactly as reported, plus gauges, and the
/// same for each of its Gateways.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricSample {
    pub instance_id: InstanceId,
    /// Manager wall clock when the sample arrived (unix ms): its place on the time axis.
    pub at_ms: i64,
    pub generation: u64,
    /// Counter epoch within the generation: changes when a counter's lineage broke (e.g. a
    /// Gateway's counters left the payload sum). Rates never span two epochs.
    pub epoch: u32,
    /// Worker monotonic milliseconds: rates use only differences of this clock.
    pub mono_ms: u64,
    /// Payload bytes: client-visible ones summed over the Gateways, plus what the port forwards
    /// relayed and (strict mode) the sandbox's Apps' (`sandbox_rx`, `sandbox_tx`, forwards
    /// included there).
    pub payload_rx: u64,
    pub payload_tx: u64,
    /// `WireGuard` UDP datagram bytes (no outer IP/UDP headers).
    pub wg_rx: u64,
    pub wg_tx: u64,
    /// Decrypted / pre-encryption IP packet bytes (not additive with the `WireGuard` bytes).
    pub tunnel_rx: u64,
    pub tunnel_tx: u64,
    pub dns_queries: u64,
    pub dns_failures: u64,
    pub dns_cache_hits: u64,
    /// Gauge: active TCP flows.
    pub active_tcp: u64,
    /// Gauge: active UDP associations.
    pub active_udp: u64,
    /// Counter: worker CPU time (`None` when the platform does not report it).
    pub cpu_ns: Option<u64>,
    /// Gauge: worker resident memory.
    pub rss_bytes: Option<u64>,
    /// The payload gate was open (traffic admitted) when the sample was taken.
    pub gate_open: Option<bool>,
    /// Proxy-connect counters summed over the Gateways (`None` when one is not usable).
    pub connect: Option<ConnectCounters>,
    /// DNS resolution latency of lookups answered from upstream.
    pub dns_latency: Option<Hist>,
    pub gateways: Vec<GatewaySample>,
    /// Strict mode: the transport payload of the sandbox's Apps (remote → Apps, Apps →
    /// remote) — their own flows and the connections forwarded to them — already part of the
    /// payload. Both `None` when the worker has no sandbox: nothing to count, never 0.
    pub sandbox_rx: Option<u64>,
    pub sandbox_tx: Option<u64>,
    /// What the Gateways relayed for SSH sessions and SSH downloads, summed over them (already
    /// part of the payload); `None` when not recorded.
    pub ssh: Option<SshBytes>,
}

/// One Gateway's part of a worker sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewaySample {
    pub gateway_id: GatewayId,
    /// Counter epoch of this Gateway within the generation: a new one each time it starts
    /// serving again (its counters restart).
    pub epoch: u32,
    pub payload_rx: u64,
    pub payload_tx: u64,
    pub active_tcp: u64,
    pub active_udp: u64,
    pub serving: bool,
    pub connect: Option<ConnectCounters>,
    /// What it relayed for SSH sessions and SSH downloads (part of its payload); `None` when not
    /// recorded.
    pub ssh: Option<SshBytes>,
}

/// What [`Store::metrics_append`] did with a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appended {
    /// The samples are stored.
    Stored,
    /// The disk is full even after overwriting the oldest data: the samples were not stored,
    /// their span is a `disk_low` gap (when even that fits).
    Skipped,
}

/// The span of an Instance's samples a batch did not store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SkippedSpan {
    instance_id: InstanceId,
    from_ms: i64,
    to_ms: i64,
    samples: u64,
}

/// Each Instance's span of `samples`.
fn spans_of(samples: &[MetricSample]) -> Vec<SkippedSpan> {
    let mut spans: Vec<SkippedSpan> = Vec::new();
    for s in samples {
        match spans.iter_mut().find(|x| x.instance_id == s.instance_id) {
            Some(x) => {
                x.from_ms = x.from_ms.min(s.at_ms);
                x.to_ms = x.to_ms.max(s.at_ms);
                x.samples += 1;
            }
            None => spans.push(SkippedSpan {
                instance_id: s.instance_id,
                from_ms: s.at_ms,
                to_ms: s.at_ms,
                samples: 1,
            }),
        }
    }
    spans
}

/// A span the collector knows is incomplete because it dropped samples before storing them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedSpan {
    pub instance_id: InstanceId,
    /// First and last dropped sample (unix ms, inclusive).
    pub from_ms: i64,
    pub to_ms: i64,
    /// How many were dropped (for logs; the stored gap keeps only the span).
    pub samples: u64,
}

/// Retention and quota from Settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsPolicy {
    pub raw_retention_ms: i64,
    pub quota_bytes: u64,
}

impl MetricsPolicy {
    /// Raw retention 1 h … 7 d, quota at least 16 MiB: the API refuses values outside its
    /// ranges; the clamp keeps rows stored by earlier versions in bounds.
    #[must_use]
    pub fn from_settings(s: &Settings) -> Self {
        let hours = i64::from(s.metrics_retention_raw_hours.clamp(1, 7 * 24));
        Self {
            raw_retention_ms: hours * HOUR_MS,
            quota_bytes: u64::from(s.metrics_quota_mib.max(16)) * 1_048_576,
        }
    }
}

impl Default for MetricsPolicy {
    fn default() -> Self {
        Self::from_settings(&Settings::default())
    }
}

/// A stored resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Raw samples.
    Second,
    Minute,
    Hour,
}

impl Resolution {
    pub const fn step_ms(self) -> i64 {
        match self {
            Self::Second => SAMPLE_INTERVAL_MS.cast_signed(),
            Self::Minute => MINUTE_MS,
            Self::Hour => HOUR_MS,
        }
    }

    pub const fn retention_ms(self, raw_retention_ms: i64) -> i64 {
        match self {
            Self::Second => raw_retention_ms,
            Self::Minute => MINUTE_RETENTION_MS,
            Self::Hour => HOUR_RETENTION_MS,
        }
    }

    const fn scope(self) -> &'static str {
        match self {
            Self::Second => "raw",
            Self::Minute => "minute",
            Self::Hour => "hour",
        }
    }
}

/// How a range is answered: the stored resolution read, and the grid step of its points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    pub resolution: Resolution,
    pub step_ms: i64,
}

/// Raw samples on a 1/2/5/10/15/30 s grid while the range is raw-retained and short enough;
/// otherwise the finest rollup that stays within [`METRICS_MAX_POINTS`] and its retention.
pub fn plan(range_ms: i64, raw_retention_ms: i64) -> Plan {
    if range_ms <= raw_retention_ms && range_ms <= HOUR_MS {
        let step_ms = [1, 2, 5, 10, 15, 30]
            .into_iter()
            .map(|s| s * 1_000)
            .find(|step| range_ms / step <= RAW_POINTS)
            .unwrap_or(30_000);
        return Plan {
            resolution: Resolution::Second,
            step_ms,
        };
    }
    let resolution = [Resolution::Minute, Resolution::Hour]
        .into_iter()
        .find(|r| {
            range_ms / r.step_ms() <= i64::try_from(METRICS_MAX_POINTS).unwrap_or(i64::MAX)
                && range_ms <= r.retention_ms(raw_retention_ms)
        })
        .unwrap_or(Resolution::Hour);
    Plan {
        resolution,
        step_ms: resolution.step_ms(),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RollupReport {
    pub minute_buckets: usize,
    pub hour_buckets: usize,
    /// Rollups are complete up to here (unix ms); the last minutes are recomputed next time.
    pub until_ms: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionReport {
    pub raw_deleted: usize,
    pub buckets_deleted: usize,
    /// Rows deleted early for the disk quota (recorded as `quota` gaps).
    pub quota_deleted: usize,
    pub used_bytes: u64,
    /// Still above the quota (only the newest data, which is never pruned, remains).
    pub over_quota: bool,
}

/// What the metrics database holds right now (the Store's part of `GET /v1/metrics/status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsStoreStatus {
    /// Bytes of pages in use, and of the whole file.
    pub used_bytes: u64,
    pub file_bytes: u64,
    pub oldest: MetricsTierTimes,
    /// Where the quota deleted data early, per resolution.
    pub pruned_before: MetricsTierTimes,
    pub rollup_until_ms: Option<i64>,
    /// Why data was unknown during the 24 hours before now, by reason.
    pub gaps_24h: Vec<MetricsGapSummary>,
}

// ---------------------------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------------------------

/// v2: per-second samples, wide rollup buckets and an index for explicit gaps. The v1 chunk and
/// rollup tables stay as they are (unused).
pub const METRICS_V2: &str = r"
CREATE TABLE metric_series (
    id          INTEGER PRIMARY KEY,
    instance_id TEXT    NOT NULL UNIQUE
);

-- One row per worker sample. Counters are cumulative u64 stored bit for bit (two's complement):
-- every comparison and difference happens in Rust.
CREATE TABLE metric_samples (
    series         INTEGER NOT NULL,
    at_ms          INTEGER NOT NULL,
    generation     INTEGER NOT NULL,
    epoch          INTEGER NOT NULL,
    mono_ms        INTEGER NOT NULL,
    payload_rx     INTEGER NOT NULL,
    payload_tx     INTEGER NOT NULL,
    wg_rx          INTEGER NOT NULL,
    wg_tx          INTEGER NOT NULL,
    tunnel_rx      INTEGER NOT NULL,
    tunnel_tx      INTEGER NOT NULL,
    dns_queries    INTEGER NOT NULL,
    dns_failures   INTEGER NOT NULL,
    dns_cache_hits INTEGER NOT NULL,
    active_tcp     INTEGER NOT NULL,
    active_udp     INTEGER NOT NULL,
    cpu_ns         INTEGER,
    rss_bytes      INTEGER,
    PRIMARY KEY (series, at_ms, generation, mono_ms)
) WITHOUT ROWID;

-- Rollup buckets: counter deltas with the time they cover (`*_ms`); gauges as min, max and
-- sum(value × ms) over ms. Time not covered is unknown (bucket length − covered), never zero.
CREATE TABLE metric_buckets (
    series         INTEGER NOT NULL,
    resolution_ms  INTEGER NOT NULL CHECK (resolution_ms IN (60000, 3600000)),
    bucket_ms      INTEGER NOT NULL,
    samples        INTEGER NOT NULL,
    breaks         INTEGER NOT NULL,
    payload_rx     INTEGER NOT NULL,
    payload_tx     INTEGER NOT NULL,
    payload_ms     INTEGER NOT NULL,
    wg_rx          INTEGER NOT NULL,
    wg_tx          INTEGER NOT NULL,
    wg_ms          INTEGER NOT NULL,
    tunnel_rx      INTEGER NOT NULL,
    tunnel_tx      INTEGER NOT NULL,
    tunnel_ms      INTEGER NOT NULL,
    dns_queries    INTEGER NOT NULL,
    dns_failures   INTEGER NOT NULL,
    dns_cache_hits INTEGER NOT NULL,
    dns_ms         INTEGER NOT NULL,
    cpu_ns         INTEGER NOT NULL,
    cpu_ms         INTEGER NOT NULL,
    tcp_min        REAL,
    tcp_max        REAL,
    tcp_sum        REAL    NOT NULL,
    tcp_ms         INTEGER NOT NULL,
    udp_min        REAL,
    udp_max        REAL,
    udp_sum        REAL    NOT NULL,
    udp_ms         INTEGER NOT NULL,
    rss_min        REAL,
    rss_max        REAL,
    rss_sum        REAL    NOT NULL,
    rss_ms         INTEGER NOT NULL,
    PRIMARY KEY (series, resolution_ms, bucket_ms)
) WITHOUT ROWID;

-- metric_gaps (v1) records what the data cannot show: scope 'samples' (never stored: every
-- resolution) or the pruned tier ('raw', 'minute', 'hour'); reason 'dropped' or 'quota'.
CREATE INDEX metric_gaps_entity ON metric_gaps (entity_id, end_ms);
";

/// v3: the payload gate, proxy-connect outcomes and latency histograms (`latency-us-v1` blobs)
/// per sample and bucket; per-Gateway samples and rollups (`gateway_series`, `gateway_samples`,
/// `gateway_buckets`). Rows written before v3 keep NULL in the new columns: unknown, never 0.
pub const METRICS_V3: &str = r"
ALTER TABLE metric_samples ADD COLUMN gate_open     INTEGER;
ALTER TABLE metric_samples ADD COLUMN conn_hist     BLOB;
ALTER TABLE metric_samples ADD COLUMN conn_failed   INTEGER;
ALTER TABLE metric_samples ADD COLUMN conn_rejected INTEGER;
ALTER TABLE metric_samples ADD COLUMN dns_hist      BLOB;

ALTER TABLE metric_buckets ADD COLUMN link_ms       INTEGER;
ALTER TABLE metric_buckets ADD COLUMN gate_ms       INTEGER;
ALTER TABLE metric_buckets ADD COLUMN open_ms       INTEGER;
ALTER TABLE metric_buckets ADD COLUMN gen_breaks    INTEGER;
ALTER TABLE metric_buckets ADD COLUMN reset_breaks  INTEGER;
ALTER TABLE metric_buckets ADD COLUMN long_breaks   INTEGER;
ALTER TABLE metric_buckets ADD COLUMN long_ms       INTEGER;
ALTER TABLE metric_buckets ADD COLUMN conn_hist     BLOB;
ALTER TABLE metric_buckets ADD COLUMN conn_failed   INTEGER;
ALTER TABLE metric_buckets ADD COLUMN conn_rejected INTEGER;
ALTER TABLE metric_buckets ADD COLUMN conn_ms       INTEGER;
ALTER TABLE metric_buckets ADD COLUMN dns_hist      BLOB;
ALTER TABLE metric_buckets ADD COLUMN dns_hist_ms   INTEGER;

-- One series per Gateway of an Instance (a Gateway moved to another Instance starts another).
CREATE TABLE gateway_series (
    id          INTEGER PRIMARY KEY,
    instance_id TEXT NOT NULL,
    gateway_id  TEXT NOT NULL,
    UNIQUE (instance_id, gateway_id)
);
CREATE INDEX gateway_series_gateway ON gateway_series (gateway_id);

-- A Gateway's part of each worker sample: written in the same transaction as its Instance's
-- row, so the Instance's gaps (drops, quota) are the Gateway's too.
CREATE TABLE gateway_samples (
    gseries       INTEGER NOT NULL,
    at_ms         INTEGER NOT NULL,
    generation    INTEGER NOT NULL,
    epoch         INTEGER NOT NULL,
    mono_ms       INTEGER NOT NULL,
    payload_rx    INTEGER NOT NULL,
    payload_tx    INTEGER NOT NULL,
    active_tcp    INTEGER NOT NULL,
    active_udp    INTEGER NOT NULL,
    serving       INTEGER NOT NULL,
    conn_hist     BLOB,
    conn_failed   INTEGER,
    conn_rejected INTEGER,
    PRIMARY KEY (gseries, at_ms, generation, mono_ms)
) WITHOUT ROWID;

CREATE TABLE gateway_buckets (
    gseries       INTEGER NOT NULL,
    resolution_ms INTEGER NOT NULL CHECK (resolution_ms IN (60000, 3600000)),
    bucket_ms     INTEGER NOT NULL,
    samples       INTEGER NOT NULL,
    breaks        INTEGER NOT NULL,
    gen_breaks    INTEGER NOT NULL,
    reset_breaks  INTEGER NOT NULL,
    long_breaks   INTEGER NOT NULL,
    long_ms       INTEGER NOT NULL,
    link_ms       INTEGER NOT NULL,
    gate_ms       INTEGER NOT NULL,
    open_ms       INTEGER NOT NULL,
    payload_rx    INTEGER NOT NULL,
    payload_tx    INTEGER NOT NULL,
    payload_ms    INTEGER NOT NULL,
    tcp_min       REAL,
    tcp_max       REAL,
    tcp_sum       REAL    NOT NULL,
    tcp_ms        INTEGER NOT NULL,
    udp_min       REAL,
    udp_max       REAL,
    udp_sum       REAL    NOT NULL,
    udp_ms        INTEGER NOT NULL,
    conn_hist     BLOB    NOT NULL,
    conn_failed   INTEGER NOT NULL,
    conn_rejected INTEGER NOT NULL,
    conn_ms       INTEGER NOT NULL,
    PRIMARY KEY (gseries, resolution_ms, bucket_ms)
) WITHOUT ROWID;
";

/// v5: of the failed proxy connects (`conn_failed`), those whose name had no address. Rows
/// written before v5 keep NULL: unknown, never 0.
pub const METRICS_V5: &str = r"
ALTER TABLE metric_samples  ADD COLUMN conn_not_found INTEGER;
ALTER TABLE metric_buckets  ADD COLUMN conn_not_found INTEGER;
ALTER TABLE gateway_samples ADD COLUMN conn_not_found INTEGER;
ALTER TABLE gateway_buckets ADD COLUMN conn_not_found INTEGER;
";

/// v7: the payload of a strict sandbox's Apps, per sample and per bucket (`sandbox_ms` is the
/// time the bucket's counts cover). NULL where there was no sandbox, and in rows written before
/// v7: unknown, never 0.
pub const METRICS_V7: &str = r"
ALTER TABLE metric_samples ADD COLUMN sandbox_rx INTEGER;
ALTER TABLE metric_samples ADD COLUMN sandbox_tx INTEGER;
ALTER TABLE metric_buckets ADD COLUMN sandbox_rx INTEGER;
ALTER TABLE metric_buckets ADD COLUMN sandbox_tx INTEGER;
ALTER TABLE metric_buckets ADD COLUMN sandbox_ms INTEGER;
";

/// v8: what the Gateways relayed for SSH sessions (`ssh_rx`, `ssh_tx`: 「SSH 代理」) and VPN
/// Manager's own SSH downloads (`ssh_pull_rx`, `ssh_pull_tx`: 「SSH 下載」), part of the payload,
/// per sample and per bucket of an Instance (summed over its Gateways) and of each Gateway
/// (`ssh_ms` is the time a bucket's counts cover). NULL in rows written before v8: unknown,
/// never 0.
pub const METRICS_V8: &str = r"
ALTER TABLE metric_samples  ADD COLUMN ssh_rx      INTEGER;
ALTER TABLE metric_samples  ADD COLUMN ssh_tx      INTEGER;
ALTER TABLE metric_samples  ADD COLUMN ssh_pull_rx INTEGER;
ALTER TABLE metric_samples  ADD COLUMN ssh_pull_tx INTEGER;
ALTER TABLE metric_buckets  ADD COLUMN ssh_rx      INTEGER;
ALTER TABLE metric_buckets  ADD COLUMN ssh_tx      INTEGER;
ALTER TABLE metric_buckets  ADD COLUMN ssh_pull_rx INTEGER;
ALTER TABLE metric_buckets  ADD COLUMN ssh_pull_tx INTEGER;
ALTER TABLE metric_buckets  ADD COLUMN ssh_ms      INTEGER;
ALTER TABLE gateway_samples ADD COLUMN ssh_rx      INTEGER;
ALTER TABLE gateway_samples ADD COLUMN ssh_tx      INTEGER;
ALTER TABLE gateway_samples ADD COLUMN ssh_pull_rx INTEGER;
ALTER TABLE gateway_samples ADD COLUMN ssh_pull_tx INTEGER;
ALTER TABLE gateway_buckets ADD COLUMN ssh_rx      INTEGER;
ALTER TABLE gateway_buckets ADD COLUMN ssh_tx      INTEGER;
ALTER TABLE gateway_buckets ADD COLUMN ssh_pull_rx INTEGER;
ALTER TABLE gateway_buckets ADD COLUMN ssh_pull_tx INTEGER;
ALTER TABLE gateway_buckets ADD COLUMN ssh_ms      INTEGER;
";

/// Migrate the metrics database (writer connection, before readers open) and make deleted pages
/// returnable to the file system: incremental auto-vacuum is set on a new file, and an existing
/// file is converted while it is still small.
pub fn open_metrics(conn: &mut Connection) -> Result<(), StoreError> {
    let tables: i64 = conn.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
    if tables == 0 {
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    }
    crate::schema::migrate_metrics(conn)?;
    if auto_vacuum(conn)? != 2 && page_bytes(conn)?.0 < 8 * 1_048_576 {
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
        conn.execute_batch("VACUUM")?;
    }
    Ok(())
}

fn auto_vacuum(c: &Connection) -> Result<i64, StoreError> {
    Ok(c.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?)
}

/// (bytes of the file, bytes in use).
fn page_bytes(c: &Connection) -> Result<(u64, u64), StoreError> {
    let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let free: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    let size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok((
        (pages.max(0) * size.max(0)).cast_unsigned(),
        ((pages - free).max(0) * size.max(0)).cast_unsigned(),
    ))
}

// ---------------------------------------------------------------------------------------------
// Store API
// ---------------------------------------------------------------------------------------------

impl Store {
    /// Store a batch of samples (with their Gateways' parts) and the spans the collector
    /// dropped, in one transaction. Fails fast with `Busy` when the metrics write queue is full
    /// (the caller keeps its batch). A sample already stored is ignored.
    ///
    /// While the data directory's volume is low on space the oldest data makes room first
    /// ([`ring_room`]): the batch is stored and the file does not grow. Only when the disk is full
    /// even then (`SQLITE_FULL` after the room made, [`Store::open_with_space`]) is the batch
    /// given up — its span a `disk_low` gap — and it counts as handled ([`Appended::Skipped`]) so
    /// the collector neither retries nor grows.
    ///
    /// # Errors
    ///
    /// `Busy` when the metrics write queue is full, `Closed` once the store has shut down, and
    /// `Sqlite` or `Encoding` when the transaction fails.
    pub async fn metrics_append(
        &self,
        samples: Vec<MetricSample>,
        dropped: Vec<DroppedSpan>,
    ) -> Result<Appended, StoreError> {
        if samples.is_empty() && dropped.is_empty() {
            return Ok(Appended::Stored);
        }
        let spans = spans_of(&samples);
        let kept = dropped.clone();
        match self
            .ring_write(move |c| append(c, &samples, &dropped))
            .await
        {
            Ok(()) => Ok(Appended::Stored),
            Err(e) if e.is_disk_full() => {
                self.disk.skipped(spans.iter().map(|s| s.samples).sum());
                // Not even the gap may fit: the span then stays unknown ("no data"), never zero.
                let _ = self
                    .metrics
                    .write(move |c| record_unstored(c, &spans, &kept))
                    .await;
                Ok(Appended::Skipped)
            }
            Err(e) => Err(e),
        }
    }

    /// A metrics write (`f` may run twice: [`Db::write`](crate::db::Db::write)). While space is
    /// low the oldest data first makes room in the file ([`ring_room`]), so that `f` reuses pages
    /// instead of growing it.
    pub(crate) async fn ring_write<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T, StoreError> + Clone + Send + 'static,
    ) -> Result<T, StoreError> {
        let low = self.disk.low(false);
        let disk = self.disk.clone();
        self.metrics
            .write(move |c| {
                if low {
                    match ring_room(c, vpn_domain::Timestamp::now().unix_millis()) {
                        Ok(rows) => disk.pruned(rows as u64),
                        Err(e) if e.is_disk_full() => return Err(e),
                        Err(e) => {
                            tracing::warn!(error = %e, "metrics: no room made in the file yet");
                        }
                    }
                }
                f(c)
            })
            .await
    }

    /// Fold raw samples into 1-minute buckets and those into 1-hour buckets, for Instances and
    /// Gateways (recent buckets are recomputed, catching up is bounded per run).
    ///
    /// # Errors
    ///
    /// `Busy` when the metrics write queue is full, `Closed` once the store has shut down, and
    /// `Sqlite` or `Encoding` when the transaction fails.
    pub async fn metrics_rollup(&self, now_ms: i64) -> Result<RollupReport, StoreError> {
        self.ring_write(move |c| rollup(c, now_ms)).await
    }

    /// Delete what is past retention, then enforce the disk quota oldest data first (raw
    /// samples, then minute, then hour buckets), recording each pruned span as a `quota` gap.
    /// Free pages go back to the volume, except while space is low: then they stay in the file
    /// for the next rows.
    ///
    /// # Errors
    ///
    /// `Busy` when the metrics write queue is full, `Closed` once the store has shut down, and
    /// `Sqlite` or `Encoding` when the transaction fails.
    pub async fn metrics_retain(
        &self,
        policy: MetricsPolicy,
        now_ms: i64,
    ) -> Result<RetentionReport, StoreError> {
        let keep_pages = self.disk.low(false);
        self.metrics
            .write(move |c| retain(c, policy, now_ms, keep_pages))
            .await
    }

    /// The series of `scope` over `range` ending at `now_ms` (see [`plan`] for the points).
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the metrics read
    /// fails.
    pub async fn metrics_series(
        &self,
        scope: MetricsScope,
        range: MetricsRange,
        now_ms: i64,
        raw_retention_ms: i64,
    ) -> Result<MetricsSeries, StoreError> {
        self.metrics
            .read(move |c| query_series(c, scope, range, now_ms, raw_retention_ms))
            .await
    }

    /// Space, oldest data, quota cuts and the last 24 hours' gaps of the metrics database.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the metrics read
    /// fails.
    pub async fn metrics_status(&self, now_ms: i64) -> Result<MetricsStoreStatus, StoreError> {
        self.metrics.read(move |c| query_status(c, now_ms)).await
    }
}

// ---------------------------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------------------------

/// u64 counters travel bit for bit through SQLite's signed INTEGER.
const fn enc(v: u64) -> i64 {
    v.cast_signed()
}

const fn dec(v: i64) -> u64 {
    v.cast_unsigned()
}

/// `?first, ?first+1, …` for `n` parameters.
fn placeholders(first: usize, n: usize) -> String {
    (first..first + n)
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The stored form of a sample's connect counters: histogram, failed, rejected, names not found.
type ConnColumns = (Option<Vec<u8>>, Option<i64>, Option<i64>, Option<i64>);

fn conn_columns(c: Option<&ConnectCounters>) -> ConnColumns {
    c.map_or((None, None, None, None), |c| {
        (
            Some(c.latency.encode()),
            Some(enc(c.failures)),
            Some(enc(c.rejected)),
            c.not_found.map(enc),
        )
    })
}

/// Connect counters back from their columns: unknown unless the histogram, failures and
/// rejections are present and the histogram decodes. A missing count of names not found (a row
/// written before v5) leaves only that count unknown.
fn conn_of(
    hist: Option<Vec<u8>>,
    failed: Option<i64>,
    rejected: Option<i64>,
    not_found: Option<i64>,
) -> Option<ConnectCounters> {
    Some(ConnectCounters {
        latency: Hist::decode(&hist?)?,
        failures: dec(failed?),
        not_found: not_found.map(dec),
        rejected: dec(rejected?),
    })
}

/// A bucket's count of names not found. NULL (a bucket written before v5) is unknown unless the
/// bucket covers no connect time: then nothing was counted, like its failures.
fn bucket_not_found(stored: Option<i64>, connect_ms: u64) -> Option<u64> {
    if connect_ms == 0 {
        Some(0)
    } else {
        stored.map(dec)
    }
}

fn ensure_series(c: &Connection, id: InstanceId) -> Result<i64, StoreError> {
    let key = id.to_string();
    c.execute(
        "INSERT OR IGNORE INTO metric_series (instance_id) VALUES (?1)",
        params![key],
    )?;
    Ok(c.query_row(
        "SELECT id FROM metric_series WHERE instance_id = ?1",
        params![key],
        |r| r.get(0),
    )?)
}

fn ensure_gateway_series(
    c: &Connection,
    instance: InstanceId,
    gateway: GatewayId,
) -> Result<i64, StoreError> {
    let (i, g) = (instance.to_string(), gateway.to_string());
    c.execute(
        "INSERT OR IGNORE INTO gateway_series (instance_id, gateway_id) VALUES (?1, ?2)",
        params![i, g],
    )?;
    Ok(c.query_row(
        "SELECT id FROM gateway_series WHERE instance_id = ?1 AND gateway_id = ?2",
        params![i, g],
        |r| r.get(0),
    )?)
}

fn series_id(c: &Connection, id: InstanceId) -> Result<Option<i64>, StoreError> {
    Ok(c.query_row(
        "SELECT id FROM metric_series WHERE instance_id = ?1",
        params![id.to_string()],
        |r| r.get(0),
    )
    .optional()?)
}

fn all_series(c: &Connection) -> Result<Vec<(i64, InstanceId)>, StoreError> {
    let mut stmt = c.prepare("SELECT id, instance_id FROM metric_series ORDER BY id")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (id, text) = row?;
        // A row that is not an Instance id was not written by us: leave it alone.
        if let Ok(instance) = text.parse() {
            out.push((id, instance));
        }
    }
    Ok(out)
}

/// One Gateway series.
#[derive(Debug, Clone, Copy)]
struct GatewaySeries {
    id: i64,
    instance_id: InstanceId,
    gateway_id: GatewayId,
}

/// Gateway series, all of them or those of one Instance or one Gateway.
fn gateway_series(c: &Connection, scope: MetricsScope) -> Result<Vec<GatewaySeries>, StoreError> {
    let (sql, arg) = match scope {
        MetricsScope::All => (
            "SELECT id, instance_id, gateway_id FROM gateway_series WHERE ?1 IS NULL ORDER BY id",
            None,
        ),
        MetricsScope::Instance(i) => (
            "SELECT id, instance_id, gateway_id FROM gateway_series WHERE instance_id = ?1 ORDER BY id",
            Some(i.to_string()),
        ),
        MetricsScope::Gateway(g) => (
            "SELECT id, instance_id, gateway_id FROM gateway_series WHERE gateway_id = ?1 ORDER BY id",
            Some(g.to_string()),
        ),
    };
    let mut stmt = c.prepare_cached(sql)?;
    let rows = stmt.query_map(params![arg], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, instance, gateway) = row?;
        if let (Ok(instance_id), Ok(gateway_id)) = (instance.parse(), gateway.parse()) {
            out.push(GatewaySeries {
                id,
                instance_id,
                gateway_id,
            });
        }
    }
    Ok(out)
}

fn meta_i64(c: &Connection, key: &str) -> Result<Option<i64>, StoreError> {
    let v: Option<String> = c
        .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(v.and_then(|v| v.parse().ok()))
}

fn set_meta_i64(c: &Connection, key: &str, v: i64) -> Result<(), StoreError> {
    c.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, v.to_string()],
    )?;
    Ok(())
}

fn record_gap(
    c: &Connection,
    scope: &str,
    instance: InstanceId,
    span: (i64, i64),
    reason: MetricsGapReason,
) -> Result<(), StoreError> {
    let reason_text = match reason {
        MetricsGapReason::Quota => "quota",
        MetricsGapReason::DiskLow => "disk_low",
        _ => "dropped",
    };
    let entity = instance.to_string();
    let last: Option<(i64, i64, i64)> = c
        .query_row(
            "SELECT id, start_ms, end_ms FROM metric_gaps
              WHERE entity_id = ?1 AND scope = ?2 AND reason = ?3
              ORDER BY end_ms DESC LIMIT 1",
            params![entity, scope, reason_text],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    // Pruning (for the quota or for space) removes everything older than its cut: one span per
    // tier says so. Samples not stored merge while they are contiguous.
    let pruning = scope != SCOPE_SAMPLES
        && matches!(reason, MetricsGapReason::Quota | MetricsGapReason::DiskLow);
    let merge = last.filter(|&(_, start, end)| {
        pruning
            || (span.0 <= end + MAX_GAP_MS.cast_signed()
                && span.1 >= start - MAX_GAP_MS.cast_signed())
    });
    match merge {
        Some((id, _, _)) => c.execute(
            "UPDATE metric_gaps SET start_ms = min(start_ms, ?2), end_ms = max(end_ms, ?3) WHERE id = ?1",
            params![id, span.0, span.1],
        )?,
        None => c.execute(
            "INSERT INTO metric_gaps (scope, entity_id, start_ms, end_ms, reason) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![scope, entity, span.0, span.1, reason_text],
        )?,
    };
    Ok(())
}

fn load_logged(
    c: &Connection,
    instance: InstanceId,
    resolution: Resolution,
    from: i64,
    to: i64,
) -> Result<Vec<Logged>, StoreError> {
    let mut stmt = c.prepare_cached(
        "SELECT start_ms, end_ms, reason FROM metric_gaps
          WHERE entity_id = ?1 AND end_ms >= ?2 AND start_ms <= ?3 AND scope IN (?4, ?5)
          ORDER BY start_ms",
    )?;
    let rows = stmt.query_map(
        params![
            instance.to_string(),
            from,
            to,
            SCOPE_SAMPLES,
            resolution.scope()
        ],
        |r| {
            Ok(Logged {
                start: r.get(0)?,
                end: r.get(1)?,
                reason: match r.get::<_, String>(2)?.as_str() {
                    "quota" => MetricsGapReason::Quota,
                    "disk_low" => MetricsGapReason::DiskLow,
                    _ => MetricsGapReason::Dropped,
                },
            })
        },
    )?;
    Ok(rows.collect::<Result<_, _>>()?)
}

const SAMPLE_COLUMNS: &str = "at_ms, generation, epoch, mono_ms, payload_rx, payload_tx, wg_rx, \
     wg_tx, tunnel_rx, tunnel_tx, dns_queries, dns_failures, dns_cache_hits, active_tcp, \
     active_udp, cpu_ns, rss_bytes, gate_open, conn_hist, conn_failed, conn_rejected, dns_hist, \
     conn_not_found, sandbox_rx, sandbox_tx, ssh_rx, ssh_tx, ssh_pull_rx, ssh_pull_tx";
const SAMPLE_COUNT: usize = 29;

const GATEWAY_SAMPLE_COLUMNS: &str = "at_ms, generation, epoch, mono_ms, payload_rx, payload_tx, \
     active_tcp, active_udp, serving, conn_hist, conn_failed, conn_rejected, conn_not_found, \
     ssh_rx, ssh_tx, ssh_pull_rx, ssh_pull_tx";
const GATEWAY_SAMPLE_COUNT: usize = 17;

/// The SSH counts of a sample row from its four columns starting at `i`: all four, or not
/// recorded.
fn ssh_of(r: &SqlRow<'_>, i: usize) -> rusqlite::Result<Option<SshBytes>> {
    Ok(
        match (
            r.get::<_, Option<i64>>(i)?,
            r.get::<_, Option<i64>>(i + 1)?,
            r.get::<_, Option<i64>>(i + 2)?,
            r.get::<_, Option<i64>>(i + 3)?,
        ) {
            (Some(rx), Some(tx), Some(pull_rx), Some(pull_tx)) => Some(SshBytes {
                rx: dec(rx),
                tx: dec(tx),
                pull_rx: dec(pull_rx),
                pull_tx: dec(pull_tx),
            }),
            _ => None,
        },
    )
}

/// The four SSH columns of a sample (NULL when not recorded).
fn ssh_columns(ssh: Option<&SshBytes>) -> [Option<i64>; 4] {
    ssh.map_or([None; 4], |b| {
        [
            Some(enc(b.rx)),
            Some(enc(b.tx)),
            Some(enc(b.pull_rx)),
            Some(enc(b.pull_tx)),
        ]
    })
}

/// A bucket's SSH counts and the time they cover from its five columns starting at `i` (written
/// before v8: no time covered, unknown).
fn bucket_ssh(r: &SqlRow<'_>, i: usize) -> rusqlite::Result<(SshBytes, u64)> {
    let ms = r.get::<_, Option<i64>>(i + 4)?.map_or(0, dec);
    if ms == 0 {
        return Ok((SshBytes::default(), 0));
    }
    let v =
        |k: usize| -> rusqlite::Result<u64> { Ok(r.get::<_, Option<i64>>(i + k)?.map_or(0, dec)) };
    Ok((
        SshBytes {
            rx: v(0)?,
            tx: v(1)?,
            pull_rx: v(2)?,
            pull_tx: v(3)?,
        },
        ms,
    ))
}

/// An Instance's rows in `[from, to)`, time-ordered.
fn load_rows(c: &Connection, series: i64, from: i64, to: i64) -> Result<Vec<Row>, StoreError> {
    let mut stmt = c.prepare_cached(&format!(
        "SELECT {SAMPLE_COLUMNS} FROM metric_samples
          WHERE series = ?1 AND at_ms >= ?2 AND at_ms < ?3
          ORDER BY at_ms, generation, mono_ms"
    ))?;
    let rows = stmt.query_map(params![series, from, to], |r| {
        Ok(Row {
            at_ms: r.get(0)?,
            generation: dec(r.get(1)?),
            epoch: r.get(2)?,
            mono_ms: dec(r.get(3)?),
            payload_rx: dec(r.get(4)?),
            payload_tx: dec(r.get(5)?),
            tcp: dec(r.get(13)?),
            udp: dec(r.get(14)?),
            open: r.get::<_, Option<i64>>(17)?.map(|v| v != 0),
            connect: conn_of(r.get(18)?, r.get(19)?, r.get(20)?, r.get(22)?),
            ssh: ssh_of(r, 25)?,
            inst: Some(InstRow {
                wg_rx: dec(r.get(6)?),
                wg_tx: dec(r.get(7)?),
                tunnel_rx: dec(r.get(8)?),
                tunnel_tx: dec(r.get(9)?),
                dns_queries: dec(r.get(10)?),
                dns_failures: dec(r.get(11)?),
                dns_cache_hits: dec(r.get(12)?),
                cpu_ns: r.get::<_, Option<i64>>(15)?.map(dec),
                rss_bytes: r.get::<_, Option<i64>>(16)?.map(dec),
                dns_latency: r
                    .get::<_, Option<Vec<u8>>>(21)?
                    .and_then(|b| Hist::decode(&b)),
                sandbox: match (r.get::<_, Option<i64>>(23)?, r.get::<_, Option<i64>>(24)?) {
                    (Some(rx), Some(tx)) => Some((dec(rx), dec(tx))),
                    _ => None,
                },
            }),
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// A Gateway's rows in `[from, to)`, time-ordered.
fn load_gateway_rows(
    c: &Connection,
    gseries: i64,
    from: i64,
    to: i64,
) -> Result<Vec<Row>, StoreError> {
    let mut stmt = c.prepare_cached(&format!(
        "SELECT {GATEWAY_SAMPLE_COLUMNS} FROM gateway_samples
          WHERE gseries = ?1 AND at_ms >= ?2 AND at_ms < ?3
          ORDER BY at_ms, generation, mono_ms"
    ))?;
    let rows = stmt.query_map(params![gseries, from, to], |r| {
        Ok(Row {
            at_ms: r.get(0)?,
            generation: dec(r.get(1)?),
            epoch: r.get(2)?,
            mono_ms: dec(r.get(3)?),
            payload_rx: dec(r.get(4)?),
            payload_tx: dec(r.get(5)?),
            tcp: dec(r.get(6)?),
            udp: dec(r.get(7)?),
            open: Some(r.get::<_, i64>(8)? != 0),
            connect: conn_of(r.get(9)?, r.get(10)?, r.get(11)?, r.get(12)?),
            ssh: ssh_of(r, 13)?,
            inst: None,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn append(
    c: &mut Connection,
    samples: &[MetricSample],
    dropped: &[DroppedSpan],
) -> Result<(), StoreError> {
    let tx = c.transaction()?;
    {
        let mut ids: HashMap<InstanceId, i64> = HashMap::new();
        let mut gateway_ids: HashMap<(InstanceId, GatewayId), i64> = HashMap::new();
        let mut insert = tx.prepare_cached(&format!(
            "INSERT OR IGNORE INTO metric_samples (series, {SAMPLE_COLUMNS}) VALUES ({})",
            placeholders(1, SAMPLE_COUNT + 1)
        ))?;
        let mut insert_gateway = tx.prepare_cached(&format!(
            "INSERT OR IGNORE INTO gateway_samples (gseries, {GATEWAY_SAMPLE_COLUMNS}) VALUES ({})",
            placeholders(1, GATEWAY_SAMPLE_COUNT + 1)
        ))?;
        for s in samples {
            let series = if let Some(id) = ids.get(&s.instance_id) {
                *id
            } else {
                let id = ensure_series(&tx, s.instance_id)?;
                ids.insert(s.instance_id, id);
                id
            };
            let (conn_hist, conn_failed, conn_rejected, conn_not_found) =
                conn_columns(s.connect.as_ref());
            let [ssh_rx, ssh_tx, ssh_pull_rx, ssh_pull_tx] = ssh_columns(s.ssh.as_ref());
            insert.execute(params![
                series,
                s.at_ms,
                enc(s.generation),
                s.epoch,
                enc(s.mono_ms),
                enc(s.payload_rx),
                enc(s.payload_tx),
                enc(s.wg_rx),
                enc(s.wg_tx),
                enc(s.tunnel_rx),
                enc(s.tunnel_tx),
                enc(s.dns_queries),
                enc(s.dns_failures),
                enc(s.dns_cache_hits),
                enc(s.active_tcp),
                enc(s.active_udp),
                s.cpu_ns.map(enc),
                s.rss_bytes.map(enc),
                s.gate_open.map(i64::from),
                conn_hist,
                conn_failed,
                conn_rejected,
                s.dns_latency.map(|h| h.encode()),
                conn_not_found,
                s.sandbox_rx.zip(s.sandbox_tx).map(|(rx, _)| enc(rx)),
                s.sandbox_rx.zip(s.sandbox_tx).map(|(_, tx)| enc(tx)),
                ssh_rx,
                ssh_tx,
                ssh_pull_rx,
                ssh_pull_tx,
            ])?;
            for g in &s.gateways {
                let key = (s.instance_id, g.gateway_id);
                let gseries = if let Some(id) = gateway_ids.get(&key) {
                    *id
                } else {
                    let id = ensure_gateway_series(&tx, key.0, key.1)?;
                    gateway_ids.insert(key, id);
                    id
                };
                put_gateway_sample(&mut insert_gateway, gseries, s, g)?;
            }
        }
        for d in dropped {
            record_gap(
                &tx,
                SCOPE_SAMPLES,
                d.instance_id,
                (d.from_ms, d.to_ms),
                MetricsGapReason::Dropped,
            )?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// One Gateway's part of sample `s` (`insert`: the prepared `gateway_samples` insert).
fn put_gateway_sample(
    insert: &mut rusqlite::CachedStatement<'_>,
    gseries: i64,
    s: &MetricSample,
    g: &GatewaySample,
) -> Result<(), StoreError> {
    let (conn_hist, conn_failed, conn_rejected, conn_not_found) = conn_columns(g.connect.as_ref());
    let [ssh_rx, ssh_tx, ssh_pull_rx, ssh_pull_tx] = ssh_columns(g.ssh.as_ref());
    insert.execute(params![
        gseries,
        s.at_ms,
        enc(s.generation),
        g.epoch,
        enc(s.mono_ms),
        enc(g.payload_rx),
        enc(g.payload_tx),
        enc(g.active_tcp),
        enc(g.active_udp),
        i64::from(g.serving),
        conn_hist,
        conn_failed,
        conn_rejected,
        conn_not_found,
        ssh_rx,
        ssh_tx,
        ssh_pull_rx,
        ssh_pull_tx,
    ])?;
    Ok(())
}

/// The disk is full even after making room: record the samples not stored and the collector's
/// drops as gaps.
fn record_unstored(
    c: &mut Connection,
    spans: &[SkippedSpan],
    dropped: &[DroppedSpan],
) -> Result<(), StoreError> {
    let tx = c.transaction()?;
    for s in spans {
        record_gap(
            &tx,
            SCOPE_SAMPLES,
            s.instance_id,
            (s.from_ms, s.to_ms),
            MetricsGapReason::DiskLow,
        )?;
    }
    for d in dropped {
        record_gap(
            &tx,
            SCOPE_SAMPLES,
            d.instance_id,
            (d.from_ms, d.to_ms),
            MetricsGapReason::Dropped,
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn pragma_i64(c: &Connection, name: &str) -> Result<i64, StoreError> {
    Ok(c.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))?)
}

/// Space is low: when fewer than [`RING_MIN_FREE`] pages of the file are free, delete the oldest
/// data until [`RING_FREE_PAGES`] are — raw samples already in the rollups first, then minute,
/// then hour buckets (never what the quota never prunes either), then the oldest process
/// samples; each pruned span is a `disk_low` gap of its tier. The pages stay in the file: the next
/// rows reuse them, so writes need no new disk space. Returns the rows deleted.
///
/// # Errors
///
/// `Sqlite` when a page count cannot be read or a deletion fails (`SQLITE_FULL` too: a deletion
/// writes its pages to the WAL).
pub fn ring_room(c: &mut Connection, now_ms: i64) -> Result<usize, StoreError> {
    make_ring(c, now_ms, RING_MIN_FREE)
}

/// A write just found the file full: the pages that were free did not hold it, however many they
/// were (a rollup catching up needs more than [`RING_MIN_FREE`]). Make the whole ring again —
/// [`RING_FREE_PAGES`] free pages, never more — before the write runs once more, as [`ring_room`]
/// does when the ring runs short. Returns the rows deleted.
///
/// # Errors
///
/// As [`ring_room`].
pub fn ring_room_when_full(c: &mut Connection, now_ms: i64) -> Result<usize, StoreError> {
    make_ring(c, now_ms, RING_FREE_PAGES)
}

/// Delete the oldest data until [`RING_FREE_PAGES`] pages of the file are free, unless
/// `content_with` already are.
fn make_ring(c: &mut Connection, now_ms: i64, content_with: i64) -> Result<usize, StoreError> {
    let free = pragma_i64(c, "freelist_count")?;
    if free >= content_with {
        return Ok(0);
    }
    let want = ((RING_FREE_PAGES - free) * pragma_i64(c, "page_size")?).cast_unsigned();
    let target = page_bytes(c)?.1.saturating_sub(want);
    let series = all_series(c)?;
    let gateways = gateway_series(c, MetricsScope::All)?;
    let rolled = rolled_up_before(c)?;
    let mut deleted = enforce_quota(
        c,
        &series,
        &gateways,
        target,
        now_ms,
        rolled,
        MetricsGapReason::DiskLow,
    )?;
    if page_bytes(c)?.1 > target {
        deleted += crate::resources::prune_oldest(c, target, now_ms)?;
    }
    if deleted > 0 {
        tracing::warn!(
            rows = deleted,
            "disk space low: overwrote the oldest metrics to make room for new ones"
        );
    }
    Ok(deleted)
}

/// The disk was full: checkpoint the WAL completely and wait (briefly) for readers to leave it,
/// so that the next write starts it over in the blocks it already has. True when it did.
pub fn restart_wal(c: &Connection) -> bool {
    c.query_row("PRAGMA wal_checkpoint(RESTART)", [], |r| r.get::<_, i64>(0))
        .is_ok_and(|busy| busy == 0)
}

const BUCKET_COLUMNS: &str = "bucket_ms, samples, breaks, payload_rx, payload_tx, payload_ms, \
     wg_rx, wg_tx, wg_ms, tunnel_rx, tunnel_tx, tunnel_ms, dns_queries, dns_failures, \
     dns_cache_hits, dns_ms, cpu_ns, cpu_ms, tcp_min, tcp_max, tcp_sum, tcp_ms, udp_min, udp_max, \
     udp_sum, udp_ms, rss_min, rss_max, rss_sum, rss_ms, link_ms, gate_ms, open_ms, gen_breaks, \
     reset_breaks, long_breaks, long_ms, conn_hist, conn_failed, conn_rejected, conn_ms, dns_hist, \
     dns_hist_ms, conn_not_found, sandbox_rx, sandbox_tx, sandbox_ms, ssh_rx, ssh_tx, ssh_pull_rx, \
     ssh_pull_tx, ssh_ms";
const BUCKET_COUNT: usize = 52;

const GATEWAY_BUCKET_COLUMNS: &str = "bucket_ms, samples, breaks, gen_breaks, reset_breaks, \
     long_breaks, long_ms, link_ms, gate_ms, open_ms, payload_rx, payload_tx, payload_ms, \
     tcp_min, tcp_max, tcp_sum, tcp_ms, udp_min, udp_max, udp_sum, udp_ms, conn_hist, \
     conn_failed, conn_rejected, conn_ms, conn_not_found, ssh_rx, ssh_tx, ssh_pull_rx, \
     ssh_pull_tx, ssh_ms";
const GATEWAY_BUCKET_COUNT: usize = 31;

fn put_bucket(c: &Connection, series: i64, step: i64, b: &Bucket) -> Result<(), StoreError> {
    let mut stmt = c.prepare_cached(&format!(
        "INSERT OR REPLACE INTO metric_buckets (series, resolution_ms, {BUCKET_COLUMNS})
         VALUES ({})",
        placeholders(1, BUCKET_COUNT + 2)
    ))?;
    let i = b.inst.clone().unwrap_or_default();
    let d = b.detail.unwrap_or_default();
    stmt.execute(params![
        series,
        step,
        b.bucket_ms,
        enc(b.samples),
        b.breaks,
        enc(b.payload_rx),
        enc(b.payload_tx),
        enc(b.payload_ms),
        enc(i.wg_rx),
        enc(i.wg_tx),
        enc(i.wg_ms),
        enc(i.tunnel_rx),
        enc(i.tunnel_tx),
        enc(i.tunnel_ms),
        enc(i.dns_queries),
        enc(i.dns_failures),
        enc(i.dns_cache_hits),
        enc(i.dns_ms),
        enc(i.cpu_ns),
        enc(i.cpu_ms),
        b.tcp.min,
        b.tcp.max,
        b.tcp.sum,
        enc(b.tcp.weight_ms),
        b.udp.min,
        b.udp.max,
        b.udp.sum,
        enc(b.udp.weight_ms),
        i.rss.min,
        i.rss.max,
        i.rss.sum,
        enc(i.rss.weight_ms),
        enc(b.link_ms),
        enc(b.gate_ms),
        enc(b.open_ms),
        // Counts the bucket was built without stay unknown.
        b.detail.map(|_| enc(d.generation)),
        b.detail.map(|_| enc(d.reset)),
        b.detail.map(|_| enc(d.long)),
        b.detail.map(|_| enc(d.long_ms)),
        b.connect.latency.encode(),
        enc(b.connect.failures),
        enc(b.connect.rejected),
        enc(b.connect_ms),
        i.dns_latency.encode(),
        enc(i.dns_latency_ms),
        b.connect.not_found.map(enc),
        enc(i.sandbox_rx),
        enc(i.sandbox_tx),
        enc(i.sandbox_ms),
        enc(b.ssh.rx),
        enc(b.ssh.tx),
        enc(b.ssh.pull_rx),
        enc(b.ssh.pull_tx),
        enc(b.ssh_ms),
    ])?;
    Ok(())
}

fn put_gateway_bucket(
    c: &Connection,
    gseries: i64,
    step: i64,
    b: &Bucket,
) -> Result<(), StoreError> {
    let mut stmt = c.prepare_cached(&format!(
        "INSERT OR REPLACE INTO gateway_buckets (gseries, resolution_ms, {GATEWAY_BUCKET_COLUMNS})
         VALUES ({})",
        placeholders(1, GATEWAY_BUCKET_COUNT + 2)
    ))?;
    let d = b.detail.unwrap_or_default();
    stmt.execute(params![
        gseries,
        step,
        b.bucket_ms,
        enc(b.samples),
        b.breaks,
        enc(d.generation),
        enc(d.reset),
        enc(d.long),
        enc(d.long_ms),
        enc(b.link_ms),
        enc(b.gate_ms),
        enc(b.open_ms),
        enc(b.payload_rx),
        enc(b.payload_tx),
        enc(b.payload_ms),
        b.tcp.min,
        b.tcp.max,
        b.tcp.sum,
        enc(b.tcp.weight_ms),
        b.udp.min,
        b.udp.max,
        b.udp.sum,
        enc(b.udp.weight_ms),
        b.connect.latency.encode(),
        enc(b.connect.failures),
        enc(b.connect.rejected),
        enc(b.connect_ms),
        b.connect.not_found.map(enc),
        enc(b.ssh.rx),
        enc(b.ssh.tx),
        enc(b.ssh.pull_rx),
        enc(b.ssh.pull_tx),
        enc(b.ssh_ms),
    ])?;
    Ok(())
}

fn gauge(r: &SqlRow<'_>, i: usize) -> rusqlite::Result<Gauge> {
    Ok(Gauge {
        min: r.get(i)?,
        max: r.get(i + 1)?,
        sum: r.get(i + 2)?,
        weight_ms: dec(r.get(i + 3)?),
    })
}

/// Break counts, unknown when the bucket was written before they were counted.
fn breaks_of(r: &SqlRow<'_>, i: usize) -> rusqlite::Result<Option<Breaks>> {
    let get = |k: usize| r.get::<_, Option<i64>>(i + k);
    Ok(match (get(0)?, get(1)?, get(2)?, get(3)?) {
        (Some(generation), Some(reset), Some(long), Some(long_ms)) => Some(Breaks {
            generation: dec(generation),
            reset: dec(reset),
            long: dec(long),
            long_ms: dec(long_ms),
        }),
        _ => None,
    })
}

/// A stored histogram and the time it covers; zero coverage when it is not stored or damaged.
fn hist_of(blob: Option<Vec<u8>>, ms: Option<i64>) -> (Hist, u64) {
    blob.and_then(|b| Hist::decode(&b))
        .map_or_else(|| (Hist::default(), 0), |h| (h, ms.map_or(0, dec)))
}

fn load_buckets(
    c: &Connection,
    series: i64,
    step: i64,
    from: i64,
    to: i64,
) -> Result<Vec<Bucket>, StoreError> {
    let mut stmt = c.prepare_cached(&format!(
        "SELECT {BUCKET_COLUMNS} FROM metric_buckets
          WHERE series = ?1 AND resolution_ms = ?2 AND bucket_ms >= ?3 AND bucket_ms < ?4
          ORDER BY bucket_ms"
    ))?;
    let rows = stmt.query_map(params![series, step, from, to], |r| {
        let inst = InstBucket {
            wg_rx: dec(r.get(6)?),
            wg_tx: dec(r.get(7)?),
            wg_ms: dec(r.get(8)?),
            tunnel_rx: dec(r.get(9)?),
            tunnel_tx: dec(r.get(10)?),
            tunnel_ms: dec(r.get(11)?),
            dns_queries: dec(r.get(12)?),
            dns_failures: dec(r.get(13)?),
            dns_cache_hits: dec(r.get(14)?),
            dns_ms: dec(r.get(15)?),
            cpu_ns: dec(r.get(16)?),
            cpu_ms: dec(r.get(17)?),
            rss: gauge(r, 26)?,
            dns_latency: Hist::default(),
            dns_latency_ms: 0,
            // A bucket written before v7 covers no sandbox time: unknown, never 0.
            sandbox_rx: r.get::<_, Option<i64>>(44)?.map_or(0, dec),
            sandbox_tx: r.get::<_, Option<i64>>(45)?.map_or(0, dec),
            sandbox_ms: r.get::<_, Option<i64>>(46)?.map_or(0, dec),
        };
        let payload_ms = dec(r.get(5)?);
        // Before v3 the continuous time was not stored: every counter group's covered time is
        // part of it, so the longest is a lower bound.
        let link_ms = r.get::<_, Option<i64>>(30)?.map_or_else(
            || {
                payload_ms
                    .max(inst.wg_ms)
                    .max(inst.tunnel_ms)
                    .max(inst.dns_ms)
            },
            dec,
        );
        let (conn, conn_ms) = hist_of(r.get(37)?, r.get(40)?);
        let (dns_latency, dns_latency_ms) = hist_of(r.get(41)?, r.get(42)?);
        let connect_known = conn_ms > 0;
        let (ssh, ssh_ms) = bucket_ssh(r, 47)?;
        Ok(Bucket {
            bucket_ms: r.get(0)?,
            samples: dec(r.get(1)?),
            breaks: r.get(2)?,
            detail: breaks_of(r, 33)?,
            link_ms,
            gate_ms: r.get::<_, Option<i64>>(31)?.map_or(0, dec),
            open_ms: r.get::<_, Option<i64>>(32)?.map_or(0, dec),
            payload_rx: dec(r.get(3)?),
            payload_tx: dec(r.get(4)?),
            payload_ms,
            tcp: gauge(r, 18)?,
            udp: gauge(r, 22)?,
            connect: ConnectCounters {
                latency: conn,
                failures: if connect_known {
                    r.get::<_, Option<i64>>(38)?.map_or(0, dec)
                } else {
                    0
                },
                not_found: bucket_not_found(r.get(43)?, conn_ms),
                rejected: if connect_known {
                    r.get::<_, Option<i64>>(39)?.map_or(0, dec)
                } else {
                    0
                },
            },
            connect_ms: conn_ms,
            ssh,
            ssh_ms,
            inst: Some(InstBucket {
                dns_latency,
                dns_latency_ms,
                ..inst
            }),
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn load_gateway_buckets(
    c: &Connection,
    gseries: i64,
    step: i64,
    from: i64,
    to: i64,
) -> Result<Vec<Bucket>, StoreError> {
    let mut stmt = c.prepare_cached(&format!(
        "SELECT {GATEWAY_BUCKET_COLUMNS} FROM gateway_buckets
          WHERE gseries = ?1 AND resolution_ms = ?2 AND bucket_ms >= ?3 AND bucket_ms < ?4
          ORDER BY bucket_ms"
    ))?;
    let rows = stmt.query_map(params![gseries, step, from, to], |r| {
        let (latency, connect_ms) = hist_of(r.get(21)?, r.get(24)?);
        let (ssh, ssh_ms) = bucket_ssh(r, 26)?;
        Ok(Bucket {
            bucket_ms: r.get(0)?,
            samples: dec(r.get(1)?),
            breaks: r.get(2)?,
            detail: breaks_of(r, 3)?,
            link_ms: dec(r.get(7)?),
            gate_ms: dec(r.get(8)?),
            open_ms: dec(r.get(9)?),
            payload_rx: dec(r.get(10)?),
            payload_tx: dec(r.get(11)?),
            payload_ms: dec(r.get(12)?),
            tcp: gauge(r, 13)?,
            udp: gauge(r, 17)?,
            connect: ConnectCounters {
                latency,
                failures: dec(r.get(22)?),
                not_found: bucket_not_found(r.get(25)?, connect_ms),
                rejected: dec(r.get(23)?),
            },
            connect_ms,
            ssh,
            ssh_ms,
            inst: None,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn rollup(c: &mut Connection, now_ms: i64) -> Result<RollupReport, StoreError> {
    let tx = c.transaction()?;
    let series = all_series(&tx)?;
    let gateways = gateway_series(&tx, MetricsScope::All)?;
    let recent = floor_to(now_ms, MINUTE_MS) - LOOKBACK_MS;
    let lo = match meta_i64(&tx, ROLLUP_KEY)? {
        Some(w) if w >= recent => recent,
        watermark => {
            // Catching up (first run, downtime, a backlog): continue at the oldest sample not
            // folded yet, skipping time without samples. Gateway rows are written with their
            // Instance's, so the Instances' oldest sample is theirs too.
            let base = watermark.unwrap_or(i64::MIN);
            let mut first: Option<i64> = None;
            for (id, _) in &series {
                let t: Option<i64> = tx.query_row(
                    "SELECT min(at_ms) FROM metric_samples WHERE series = ?1 AND at_ms >= ?2",
                    params![id, base],
                    |r| r.get(0),
                )?;
                first = match (first, t) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
            }
            first.map_or(recent, |t| floor_to(t, MINUTE_MS).min(recent))
        }
    };
    let hi = (lo + MAX_SPAN_MS).min(floor_to(now_ms, MINUTE_MS) + MINUTE_MS);
    let mut report = RollupReport {
        until_ms: hi,
        ..Default::default()
    };
    let (hour_lo, hour_hi) = (floor_to(lo, HOUR_MS), ceil_to(hi, HOUR_MS));
    for (id, _) in &series {
        let from = predecessor_ms(&tx, "metric_samples", "series", *id, lo)?;
        let raw = load_rows(&tx, *id, from, hi)?;
        if !raw.iter().any(|s| s.at_ms >= lo) {
            continue;
        }
        let minutes = rollup_rows(&raw, lo, hi, MINUTE_MS, true);
        for b in &minutes {
            put_bucket(&tx, *id, MINUTE_MS, b)?;
        }
        report.minute_buckets += minutes.len();
        // Hour buckets are recomputed from every stored minute of each hour touched.
        let stored = load_buckets(&tx, *id, MINUTE_MS, hour_lo, hour_hi)?;
        let hours = fold_buckets(&stored, HOUR_MS, true);
        for b in &hours {
            put_bucket(&tx, *id, HOUR_MS, b)?;
        }
        report.hour_buckets += hours.len();
    }
    for g in &gateways {
        let from = predecessor_ms(&tx, "gateway_samples", "gseries", g.id, lo)?;
        let raw = load_gateway_rows(&tx, g.id, from, hi)?;
        if !raw.iter().any(|s| s.at_ms >= lo) {
            continue;
        }
        let minutes = rollup_rows(&raw, lo, hi, MINUTE_MS, false);
        for b in &minutes {
            put_gateway_bucket(&tx, g.id, MINUTE_MS, b)?;
        }
        report.minute_buckets += minutes.len();
        let stored = load_gateway_buckets(&tx, g.id, MINUTE_MS, hour_lo, hour_hi)?;
        let hours = fold_buckets(&stored, HOUR_MS, false);
        for b in &hours {
            put_gateway_bucket(&tx, g.id, HOUR_MS, b)?;
        }
        report.hour_buckets += hours.len();
    }
    set_meta_i64(&tx, ROLLUP_KEY, hi)?;
    tx.commit()?;
    Ok(report)
}

/// Raw samples older than this are folded into rollups that will not be recomputed: they may
/// go. The next run starts at most `LOOKBACK_MS` (plus the minute in progress) before the
/// watermark, and a continuous predecessor is at most `MAX_GAP_MS` further back; one more minute
/// of margin. (An older predecessor only tells of a break, and is read while it is kept.)
fn rolled_up_before(c: &Connection) -> Result<Option<i64>, StoreError> {
    Ok(
        meta_i64(c, ROLLUP_KEY)?
            .map(|w| w - LOOKBACK_MS - 2 * MINUTE_MS - MAX_GAP_MS.cast_signed()),
    )
}

/// Where to start reading a series' rows for `[lo, …)`: at its last row before `lo`, however old,
/// so the first row in range is linked to its predecessor like any other and a restart or a long
/// interval at the start of a rollup run or a range is not lost. `lo` when there is none.
fn predecessor_ms(
    c: &Connection,
    table: &str,
    key: &str,
    id: i64,
    lo: i64,
) -> Result<i64, StoreError> {
    let t: Option<i64> = c
        .prepare_cached(&format!(
            "SELECT max(at_ms) FROM {table} WHERE {key} = ?1 AND at_ms < ?2"
        ))?
        .query_row(params![id, lo], |r| r.get(0))?;
    Ok(t.unwrap_or(lo))
}

/// Rows read from a predecessor on, or none when none of them is at or after `from`: a
/// predecessor alone says nothing about the range.
fn in_range(rows: Vec<Row>, from: i64) -> Vec<Row> {
    if rows.iter().any(|r| r.at_ms >= from) {
        rows
    } else {
        Vec::new()
    }
}

/// Delete one tier's rows older than `before`: of the Instance series given and of every
/// Gateway (their rows go with their Instance's).
fn delete_tier(
    c: &Connection,
    step: Option<i64>,
    series: &[(i64, InstanceId)],
    gateways: &[GatewaySeries],
    before: i64,
) -> Result<usize, StoreError> {
    let mut deleted = 0;
    for (id, _) in series {
        deleted += match step {
            None => c.execute(
                "DELETE FROM metric_samples WHERE series = ?1 AND at_ms < ?2",
                params![id, before],
            )?,
            Some(step) => c.execute(
                "DELETE FROM metric_buckets WHERE series = ?1 AND resolution_ms = ?2 AND bucket_ms < ?3",
                params![id, step, before],
            )?,
        };
    }
    for g in gateways {
        deleted += match step {
            None => c.execute(
                "DELETE FROM gateway_samples WHERE gseries = ?1 AND at_ms < ?2",
                params![g.id, before],
            )?,
            Some(step) => c.execute(
                "DELETE FROM gateway_buckets WHERE gseries = ?1 AND resolution_ms = ?2 AND bucket_ms < ?3",
                params![g.id, step, before],
            )?,
        };
    }
    Ok(deleted)
}

fn retain(
    c: &mut Connection,
    policy: MetricsPolicy,
    now_ms: i64,
    keep_pages: bool,
) -> Result<RetentionReport, StoreError> {
    let mut report = RetentionReport::default();
    let series = all_series(c)?;
    let gateways = gateway_series(c, MetricsScope::All)?;
    let rolled = rolled_up_before(c)?;
    {
        let tx = c.transaction()?;
        if let Some(rolled) = rolled {
            let raw_cut = (now_ms - policy.raw_retention_ms).min(rolled);
            report.raw_deleted += delete_tier(&tx, None, &series, &gateways, raw_cut)?;
        }
        for (step, keep) in [
            (MINUTE_MS, MINUTE_RETENTION_MS),
            (HOUR_MS, HOUR_RETENTION_MS),
        ] {
            report.buckets_deleted +=
                delete_tier(&tx, Some(step), &series, &gateways, now_ms - keep)?;
        }
        tx.execute(
            "DELETE FROM metric_gaps
              WHERE end_ms < ?1
                 OR (scope = 'raw' AND end_ms < ?2)
                 OR (scope = 'minute' AND end_ms < ?3)",
            params![
                now_ms - HOUR_RETENTION_MS,
                now_ms - policy.raw_retention_ms,
                now_ms - MINUTE_RETENTION_MS
            ],
        )?;
        tx.execute(
            "DELETE FROM metric_series
              WHERE NOT EXISTS (SELECT 1 FROM metric_samples s WHERE s.series = metric_series.id)
                AND NOT EXISTS (SELECT 1 FROM metric_buckets b WHERE b.series = metric_series.id)",
            [],
        )?;
        tx.execute(
            "DELETE FROM gateway_series
              WHERE NOT EXISTS (SELECT 1 FROM gateway_samples s WHERE s.gseries = gateway_series.id)
                AND NOT EXISTS (SELECT 1 FROM gateway_buckets b WHERE b.gseries = gateway_series.id)",
            [],
        )?;
        tx.commit()?;
    }
    let series = all_series(c)?;
    let gateways = gateway_series(c, MetricsScope::All)?;
    report.quota_deleted = enforce_quota(
        c,
        &series,
        &gateways,
        policy.quota_bytes,
        now_ms,
        rolled,
        MetricsGapReason::Quota,
    )?;
    if !keep_pages {
        release_free_pages(c, RELEASE_MIN_PAGES)?;
    }
    let used = page_bytes(c)?.1;
    report.used_bytes = used;
    report.over_quota = used > policy.quota_bytes;
    Ok(report)
}

/// Return free pages to the file system (incremental auto-vacuum only) once at least
/// `min_pages` are free, so the file follows the quota down. True when pages were released.
fn release_free_pages(c: &Connection, min_pages: i64) -> Result<bool, StoreError> {
    let free: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    if free < min_pages.max(1) || auto_vacuum(c)? != 2 {
        return Ok(false);
    }
    // The pragma yields a row per page it frees: step it to the end.
    let mut stmt = c.prepare("PRAGMA incremental_vacuum")?;
    let mut rows = stmt.query([])?;
    while rows.next()?.is_some() {}
    Ok(true)
}

/// One prunable tier for the quota.
struct Tier {
    resolution: Resolution,
    /// `None` = raw samples; otherwise the bucket resolution.
    step: Option<i64>,
    /// Nothing at or after this time is pruned.
    protect: i64,
}

impl Tier {
    /// Oldest and newest time of an Instance series in this tier before `before`.
    fn span(
        &self,
        c: &Connection,
        series: i64,
        before: i64,
    ) -> Result<(Option<i64>, Option<i64>), StoreError> {
        let row = |r: &SqlRow<'_>| Ok((r.get(0)?, r.get(1)?));
        Ok(match self.step {
            None => c.query_row(
                "SELECT min(at_ms), max(at_ms) FROM metric_samples WHERE series = ?1 AND at_ms < ?2",
                params![series, before],
                row,
            )?,
            Some(step) => c.query_row(
                "SELECT min(bucket_ms), max(bucket_ms) FROM metric_buckets
                  WHERE series = ?1 AND resolution_ms = ?2 AND bucket_ms < ?3",
                params![series, step, before],
                row,
            )?,
        })
    }
}

/// Delete the oldest data until the file's used pages fit `quota`: raw samples already in the
/// rollups first, then minute buckets, then hour buckets, Gateways' rows together with their
/// Instance's. Each pruned span becomes a gap of its tier with `reason` (`quota`, or
/// `disk_low` when pruned for space). Returns the rows deleted.
fn enforce_quota(
    c: &mut Connection,
    series: &[(i64, InstanceId)],
    gateways: &[GatewaySeries],
    quota: u64,
    now_ms: i64,
    rolled: Option<i64>,
    reason: MetricsGapReason,
) -> Result<usize, StoreError> {
    let tiers = [
        Tier {
            resolution: Resolution::Second,
            step: None,
            protect: rolled.unwrap_or(i64::MIN),
        },
        Tier {
            resolution: Resolution::Minute,
            step: Some(MINUTE_MS),
            protect: now_ms - QUOTA_PROTECT_BUCKETS_MS,
        },
        Tier {
            resolution: Resolution::Hour,
            step: Some(HOUR_MS),
            protect: now_ms - QUOTA_PROTECT_BUCKETS_MS,
        },
    ];
    let mut deleted = 0;
    for tier in &tiers {
        for _ in 0..QUOTA_STEPS {
            let used = page_bytes(c)?.1;
            if used <= quota {
                return Ok(deleted);
            }
            // The oldest and newest prunable times of this tier, over every series.
            let mut span: Option<(i64, i64)> = None;
            for (id, _) in series {
                if let (Some(lo), Some(hi)) = tier.span(c, *id, tier.protect)? {
                    span = Some(span.map_or((lo, hi), |(a, b)| (a.min(lo), b.max(hi))));
                }
            }
            let Some((oldest, newest)) = span else {
                break;
            };
            // Prune the share of the tier's time span that matches the excess (at least a
            // minute), oldest first.
            let excess = u64_to_f64(used - quota) / u64_to_f64(used);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "a share (at most 1) of a time span in ms, rounded up: within i64"
            )]
            let step = (i64_to_f64(newest - oldest) * excess).ceil() as i64;
            let cut = (oldest + step.max(MINUTE_MS)).min(tier.protect);
            let tx = c.transaction()?;
            for (id, instance) in series {
                let Some(first) = tier.span(&tx, *id, cut)?.0 else {
                    continue;
                };
                record_gap(
                    &tx,
                    tier.resolution.scope(),
                    *instance,
                    (first, cut),
                    reason,
                )?;
            }
            deleted += delete_tier(&tx, tier.step, series, gateways, cut)?;
            tx.commit()?;
        }
    }
    Ok(deleted)
}

fn has_raw(
    c: &Connection,
    table: &str,
    key: &str,
    id: i64,
    from: i64,
    to: i64,
) -> Result<bool, StoreError> {
    Ok(c.query_row(
        &format!(
            "SELECT EXISTS (SELECT 1 FROM {table} WHERE {key} = ?1 AND at_ms >= ?2 AND at_ms < ?3)"
        ),
        params![id, from, to],
        |r| r.get(0),
    )?)
}

fn has_buckets(
    c: &Connection,
    gseries: i64,
    step: i64,
    from: i64,
    to: i64,
) -> Result<bool, StoreError> {
    Ok(c.query_row(
        "SELECT EXISTS (SELECT 1 FROM gateway_buckets
          WHERE gseries = ?1 AND resolution_ms = ?2 AND bucket_ms >= ?3 AND bucket_ms < ?4)",
        params![gseries, step, from, to],
        |r| r.get(0),
    )?)
}

/// The plan of a series answer: [`plan`], with raw seconds traded for minutes when they would
/// read more than [`MAX_RAW_ROWS`] rows over every series with data.
fn bounded_plan(
    tx: &Connection,
    instances: &[(i64, InstanceId)],
    gateways: &[GatewaySeries],
    range: MetricsRange,
    now_ms: i64,
    raw_retention_ms: i64,
) -> Result<Plan, StoreError> {
    let start = now_ms - range.duration_ms();
    let mut plan = plan(range.duration_ms(), raw_retention_ms);
    if plan.resolution == Resolution::Second {
        // Bound the raw rows one answer reads: every series with data, one row per second.
        let lookback = start - MAX_GAP_MS.cast_signed();
        let mut reporting = 0i64;
        for (id, _) in instances {
            reporting += i64::from(has_raw(
                tx,
                "metric_samples",
                "series",
                *id,
                lookback,
                now_ms,
            )?);
        }
        for g in gateways {
            reporting += i64::from(has_raw(
                tx,
                "gateway_samples",
                "gseries",
                g.id,
                lookback,
                now_ms,
            )?);
        }
        if reporting * (range.duration_ms() / 1_000) > MAX_RAW_ROWS {
            plan = Plan {
                resolution: Resolution::Minute,
                step_ms: MINUTE_MS,
            };
        }
    }
    Ok(plan)
}

/// One Instance series' raw rows (with the row before the grid) or its buckets, as `raw` says.
fn instance_data(
    tx: &Connection,
    id: i64,
    raw: bool,
    grid: &Grid,
) -> Result<(Vec<Row>, Vec<Bucket>), StoreError> {
    if raw {
        let from = predecessor_ms(tx, "metric_samples", "series", id, grid.from)?;
        Ok((
            in_range(load_rows(tx, id, from, grid.to)?, grid.from),
            Vec::new(),
        ))
    } else {
        Ok((
            Vec::new(),
            load_buckets(tx, id, grid.step, grid.from, grid.to)?,
        ))
    }
}

/// [`instance_data`] for a Gateway series.
fn gateway_data(
    tx: &Connection,
    id: i64,
    raw: bool,
    grid: &Grid,
) -> Result<(Vec<Row>, Vec<Bucket>), StoreError> {
    if raw {
        let from = predecessor_ms(tx, "gateway_samples", "gseries", id, grid.from)?;
        Ok((
            in_range(load_gateway_rows(tx, id, from, grid.to)?, grid.from),
            Vec::new(),
        ))
    } else {
        Ok((
            Vec::new(),
            load_gateway_buckets(tx, id, grid.step, grid.from, grid.to)?,
        ))
    }
}

/// Whether any of the Gateway series `rest` (not listed) has data on the grid.
fn any_unlisted(
    tx: &Connection,
    rest: &[GatewaySeries],
    raw: bool,
    grid: &Grid,
) -> Result<bool, StoreError> {
    let mut truncated = false;
    for g in rest {
        truncated |= if raw {
            has_raw(tx, "gateway_samples", "gseries", g.id, grid.from, grid.to)?
        } else {
            has_buckets(tx, g.id, grid.step, grid.from, grid.to)?
        };
    }
    Ok(truncated)
}

fn query_series(
    c: &Connection,
    scope: MetricsScope,
    range: MetricsRange,
    now_ms: i64,
    raw_retention_ms: i64,
) -> Result<MetricsSeries, StoreError> {
    // One snapshot for every read below.
    let tx = c.unchecked_transaction()?;
    let instances: Vec<(i64, InstanceId)> = match scope {
        MetricsScope::All => all_series(&tx)?,
        MetricsScope::Instance(id) => series_id(&tx, id)?.map(|s| (s, id)).into_iter().collect(),
        MetricsScope::Gateway(_) => Vec::new(),
    };
    let gateways = gateway_series(&tx, scope)?;
    let start = now_ms - range.duration_ms();
    let plan = bounded_plan(&tx, &instances, &gateways, range, now_ms, raw_retention_ms)?;
    let grid = Grid {
        from: floor_to(start, plan.step_ms),
        to: now_ms,
        step: plan.step_ms,
    };
    let span = grid.to - grid.from;
    let mut out = MetricsSeries::empty(
        scope,
        range,
        u32::try_from(plan.step_ms / 1_000).unwrap_or(u32::MAX),
        grid.from,
        grid.to,
    );
    let mut logged_of: HashMap<InstanceId, Vec<Logged>> = HashMap::new();
    let mut logged = |tx: &Connection, instance: InstanceId| -> Result<Vec<Logged>, StoreError> {
        if let Some(l) = logged_of.get(&instance) {
            return Ok(l.clone());
        }
        let l = load_logged(
            tx,
            instance,
            plan.resolution,
            grid.from - MAX_GAP_MS.cast_signed(),
            grid.to,
        )?;
        logged_of.insert(instance, l.clone());
        Ok(l)
    };
    // Points of one series, or `None` when it has nothing in the range.
    let points = |rows: Vec<Row>, buckets: Vec<Bucket>, logged: &[Logged]| -> Option<Vec<Point>> {
        match plan.resolution {
            Resolution::Second => (!rows.is_empty()).then(|| raw_points(&rows, logged, &grid)),
            _ => (!buckets.is_empty()).then(|| bucket_points(&buckets, logged, &grid)),
        }
    };
    let raw = plan.resolution == Resolution::Second;
    let mut scope_points: Vec<Vec<Point>> = Vec::new();
    for (id, instance) in &instances {
        let l = logged(&tx, *instance)?;
        let (rows, buckets) = instance_data(&tx, *id, raw, &grid)?;
        if let Some(p) = points(rows, buckets, &l) {
            if out.instances.len() < METRICS_MAX_LISTED {
                out.instances.push(InstanceMetricsTotals {
                    instance_id: *instance,
                    totals: totals(&p, span, true),
                });
            } else {
                out.entities_truncated = true;
            }
            scope_points.push(p);
        }
    }
    for (n, g) in gateways.iter().enumerate() {
        // Listed Gateways are bounded; one Gateway's scope reads all of its lineages.
        if out.gateways.len() == METRICS_MAX_LISTED && !matches!(scope, MetricsScope::Gateway(_)) {
            out.entities_truncated |= any_unlisted(&tx, &gateways[n..], raw, &grid)?;
            break;
        }
        let l = logged(&tx, g.instance_id)?;
        let (rows, buckets) = gateway_data(&tx, g.id, raw, &grid)?;
        if let Some(p) = points(rows, buckets, &l) {
            out.gateways.push(GatewayMetricsTotals {
                gateway_id: g.gateway_id,
                instance_id: g.instance_id,
                totals: totals(&p, span, true),
            });
            if matches!(scope, MetricsScope::Gateway(_)) {
                scope_points.push(p);
            }
        }
    }
    let combined = combine(&scope_points, grid.len());
    let (instance_level, serving) = match scope {
        MetricsScope::All => (true, false),
        MetricsScope::Instance(_) => (true, true),
        MetricsScope::Gateway(_) => (false, true),
    };
    out.totals = totals(&combined, span, serving);
    fill(&mut out, &grid, &combined, instance_level);
    Ok(out)
}

/// The oldest raw sample and minute and hour bucket over every series.
fn oldest_times(
    tx: &Connection,
    series: &[(i64, InstanceId)],
) -> Result<MetricsTierTimes, StoreError> {
    let min_of = |sql: &str, extra: Option<i64>| -> Result<Option<i64>, StoreError> {
        let mut oldest: Option<i64> = None;
        let mut stmt = tx.prepare_cached(sql)?;
        for (id, _) in series {
            let t: Option<i64> = match extra {
                Some(step) => stmt.query_row(params![id, step], |r| r.get(0))?,
                None => stmt.query_row(params![id], |r| r.get(0))?,
            };
            oldest = match (oldest, t) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        Ok(oldest)
    };
    let buckets_sql =
        "SELECT min(bucket_ms) FROM metric_buckets WHERE series = ?1 AND resolution_ms = ?2";
    Ok(MetricsTierTimes {
        raw_ms: min_of(
            "SELECT min(at_ms) FROM metric_samples WHERE series = ?1",
            None,
        )?,
        minute_ms: min_of(buckets_sql, Some(MINUTE_MS))?,
        hour_ms: min_of(buckets_sql, Some(HOUR_MS))?,
    })
}

/// `(pruned_before, quota_cut, space_cut)` of [`early_cuts`].
type EarlyCuts = (MetricsTierTimes, Option<i64>, Option<i64>);

/// Where data was deleted early (for the quota or for space), and the raw cut of each.
fn early_cuts(tx: &Connection) -> Result<EarlyCuts, StoreError> {
    let mut pruned_before = MetricsTierTimes::default();
    let (mut quota_cut, mut space_cut) = (None::<i64>, None::<i64>);
    let mut stmt = tx.prepare(
        "SELECT scope, reason, max(end_ms) FROM metric_gaps
          WHERE reason IN ('quota', 'disk_low') AND scope != ?1 GROUP BY scope, reason",
    )?;
    let rows = stmt.query_map(params![SCOPE_SAMPLES], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    let later = |t: &mut Option<i64>, end: i64| *t = Some(t.map_or(end, |x| x.max(end)));
    for row in rows {
        let (scope, reason, end) = row?;
        match scope.as_str() {
            "raw" => {
                later(&mut pruned_before.raw_ms, end);
                if reason == "quota" {
                    later(&mut quota_cut, end);
                } else {
                    later(&mut space_cut, end);
                }
            }
            "minute" => later(&mut pruned_before.minute_ms, end),
            "hour" => later(&mut pruned_before.hour_ms, end),
            _ => {}
        }
    }
    Ok((pruned_before, quota_cut, space_cut))
}

/// Samples never stored since `since` for `reason` (dropped by the collector, or not stored
/// while space was low): `(events, duration_ms, last_ms)`.
fn unstored(
    tx: &Connection,
    reason: &str,
    since: i64,
    now_ms: i64,
) -> Result<(u64, i64, Option<i64>), StoreError> {
    let mut stmt = tx.prepare_cached(
        "SELECT start_ms, end_ms FROM metric_gaps
          WHERE scope = ?1 AND reason = ?2 AND end_ms >= ?3",
    )?;
    let rows = stmt.query_map(params![SCOPE_SAMPLES, reason, since], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
    })?;
    let (mut events, mut duration, mut last) = (0u64, 0i64, None::<i64>);
    for row in rows {
        let (start, end) = row?;
        events += 1;
        // A span names its first and last sample: each stands for one interval.
        duration += (end.min(now_ms) - start.max(since)).max(0) + SAMPLE_INTERVAL_MS.cast_signed();
        last = Some(last.map_or(end, |l| l.max(end)));
    }
    Ok((events, duration, last))
}

/// Per break kind the count and the last minute, and the long breaks' total time.
type BreakCounts = ([(u64, Option<i64>); 3], Option<i64>);

/// Breaks between samples since `since`, from the minute rollups: per kind (new generation,
/// counter reset, long interval) the count and the last minute, and the long breaks' total
/// time (`None` when a minute rolled up before it was counted had one).
fn break_counts(
    tx: &Connection,
    series: &[(i64, InstanceId)],
    since: i64,
) -> Result<BreakCounts, StoreError> {
    let mut counts = [(0u64, None::<i64>); 3];
    let mut long_ms = Some(0i64);
    let mut stmt = tx.prepare_cached(
        "SELECT bucket_ms, breaks, gen_breaks, reset_breaks, long_breaks, long_ms
           FROM metric_buckets WHERE series = ?1 AND resolution_ms = ?2 AND bucket_ms >= ?3",
    )?;
    for (id, _) in series {
        let rows = stmt.query_map(params![id, MINUTE_MS, floor_to(since, MINUTE_MS)], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, u32>(1)?, breaks_of(r, 2)?))
        })?;
        for row in rows {
            let (at, flags, detail) = row?;
            // Counted breaks, or for minutes rolled up before they were counted, one per
            // kind the minute had.
            let n = detail.map_or_else(
                || {
                    [
                        u64::from(flags & rollup::BREAK_GENERATION != 0),
                        u64::from(flags & rollup::BREAK_RESET != 0),
                        u64::from(flags & rollup::BREAK_LONG != 0),
                    ]
                },
                |d| [d.generation, d.reset, d.long],
            );
            for (count, k) in counts.iter_mut().zip(n) {
                if k > 0 {
                    count.0 += k;
                    count.1 = Some(count.1.map_or(at, |l: i64| l.max(at)));
                }
            }
            long_ms = match (long_ms, detail) {
                (Some(total), Some(d)) => Some(total + d.long_ms.cast_signed()),
                (_, None) if n[2] > 0 => None,
                (total, _) => total,
            };
        }
    }
    Ok((counts, long_ms))
}

fn query_status(c: &Connection, now_ms: i64) -> Result<MetricsStoreStatus, StoreError> {
    let tx = c.unchecked_transaction()?;
    let (file_bytes, used_bytes) = page_bytes(&tx)?;
    let series = all_series(&tx)?;
    let oldest = oldest_times(&tx, &series)?;
    let (pruned_before, quota_cut, space_cut) = early_cuts(&tx)?;
    let since = now_ms - DAY_MS;
    let mut gaps = Vec::new();
    let (events, duration, last) = unstored(&tx, "dropped", since, now_ms)?;
    if events > 0 {
        gaps.push(MetricsGapSummary {
            reason: MetricsGapReason::Dropped,
            events,
            duration_ms: Some(duration),
            last_ms: last,
        });
    }
    if let Some(cut) = quota_cut.filter(|cut| *cut > since) {
        gaps.push(MetricsGapSummary {
            reason: MetricsGapReason::Quota,
            events: 1,
            duration_ms: Some(cut - since),
            last_ms: Some(cut),
        });
    }
    // Low space: the samples not stored and the raw data pruned early, as one reason.
    let (mut events, mut duration, mut last) = unstored(&tx, "disk_low", since, now_ms)?;
    if let Some(cut) = space_cut.filter(|cut| *cut > since) {
        events += 1;
        duration += cut - since;
        last = Some(last.map_or(cut, |l| l.max(cut)));
    }
    if events > 0 {
        gaps.push(MetricsGapSummary {
            reason: MetricsGapReason::DiskLow,
            events,
            duration_ms: Some(duration),
            last_ms: last,
        });
    }
    let (counts, long_ms) = break_counts(&tx, &series, since)?;
    for ((events, last), reason) in counts.into_iter().zip([
        MetricsGapReason::NewGeneration,
        MetricsGapReason::CounterReset,
        MetricsGapReason::LongInterval,
    ]) {
        if events > 0 {
            gaps.push(MetricsGapSummary {
                reason,
                events,
                duration_ms: (reason == MetricsGapReason::LongInterval)
                    .then_some(long_ms)
                    .flatten(),
                last_ms: last,
            });
        }
    }
    Ok(MetricsStoreStatus {
        used_bytes,
        file_bytes,
        oldest,
        pruned_before,
        rollup_until_ms: meta_i64(&tx, ROLLUP_KEY)?,
        gaps_24h: gaps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pragma(c: &Connection, name: &str) -> i64 {
        c.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn a_v1_metrics_database_is_upgraded_and_switched_to_incremental_vacuum() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Connection::open(dir.path().join("metrics.sqlite")).unwrap();
        c.pragma_update(None, "journal_mode", "WAL").unwrap();
        // What v1 left behind (the tables v2 builds on), without auto-vacuum.
        c.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
             CREATE TABLE metric_gaps (id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL,
                 entity_id TEXT, start_ms INTEGER NOT NULL, end_ms INTEGER NOT NULL,
                 reason TEXT NOT NULL);
             PRAGMA user_version = 1;",
        )
        .unwrap();
        assert_eq!(pragma(&c, "auto_vacuum"), 0);
        open_metrics(&mut c).unwrap();
        assert_eq!(pragma(&c, "user_version"), crate::schema::METRICS_VERSION);
        assert_eq!(pragma(&c, "auto_vacuum"), 2, "incremental");
        let n: i64 = c
            .query_row("SELECT count(*) FROM gateway_samples", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }
}
