//! Series behind `GET /v1/performance/series`: aligned columns over a fixed range ending now.
//!
//! - `system`: CPU (percent of one core, and of the host for the product) and resident memory per
//!   role and for the product, from the persisted process samples (5 s ticks up to 6 h, per-role
//!   minute rollups for 24 h, hours folded from minutes beyond).
//! - `instance`, `gateway`: the metrics service's persisted series of that scope (payload and
//!   `WireGuard` rates, flows; an Instance's worker CPU and memory).
//!
//! A value that is not known is `null` and its span is listed in `gaps` with the reason; a point
//! with every value `null` is inserted after a long silence so no line bridges it.

use std::collections::{BTreeMap, BTreeSet};

use vpn_domain::{
    MetricsGap, MetricsGapReason, MetricsRange, MetricsSeries, PerformanceMetric, PerformanceScope,
    PerformanceScopeKind, PerformanceSeries, PerformanceSeriesSet, PerformanceUnit, ProcessRole,
    reason, series_note,
};

use crate::formula;

/// One role at one 5-s tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickValue {
    pub at_ms: i64,
    /// CPU-time delta since the previous tick and the wall time it covers.
    pub cpu: Option<(u64, u64)>,
    pub rss_bytes: Option<u64>,
}

/// One role in one bucket (minute or folded).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct BucketValue {
    pub bucket_ms: i64,
    pub cpu_ns: u64,
    pub cpu_ms: u64,
    pub rss_sum: f64,
    pub rss_ms: u64,
}

impl BucketValue {
    fn merge(&mut self, o: &Self) {
        self.cpu_ns = self.cpu_ns.saturating_add(o.cpu_ns);
        self.cpu_ms += o.cpu_ms;
        self.rss_sum += o.rss_sum;
        self.rss_ms += o.rss_ms;
    }

    fn cpu_pct(&self) -> Option<f64> {
        (self.cpu_ms > 0)
            .then(|| formula::cpu_core_pct(self.cpu_ns, self.cpu_ms))
            .flatten()
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "a duration in ms as a divisor; f64 is exact far beyond real durations"
    )]
    fn rss(&self) -> Option<f64> {
        (self.rss_ms > 0).then(|| (self.rss_sum / self.rss_ms as f64).round())
    }
}

/// Per-role process data of a range.
#[derive(Debug, Clone, PartialEq)]
pub enum RoleInput {
    Ticks(BTreeMap<ProcessRole, Vec<TickValue>>),
    Buckets(BTreeMap<ProcessRole, Vec<BucketValue>>),
}

/// Resolution of a system-scope range: 5-s ticks while they fit, minutes up to a day, hours.
#[must_use]
pub const fn system_resolution(range: MetricsRange) -> u32 {
    match range {
        MetricsRange::Last15m | MetricsRange::Last1h | MetricsRange::Last6h => 5,
        MetricsRange::Last24h => 60,
        MetricsRange::Last7d | MetricsRange::Last30d => 3_600,
    }
}

/// One role's (CPU %, RSS bytes) at one point.
type Cell = (Option<f64>, Option<f64>);

const TICK_MS: i64 = 5_000;
const TICK_MAX_GAP_MS: i64 = 12_500;
const MAX_GAPS: usize = 2_000;

struct Gaps {
    list: Vec<MetricsGap>,
    truncated: bool,
}

impl Gaps {
    const fn new() -> Self {
        Self {
            list: Vec::new(),
            truncated: false,
        }
    }

    fn add(&mut self, from_ms: i64, to_ms: i64, reason: MetricsGapReason) {
        if to_ms <= from_ms {
            return;
        }
        if let Some(g) = self
            .list
            .iter_mut()
            .rev()
            .take(4)
            .find(|g| g.reason == reason && from_ms <= g.to_ms && to_ms >= g.from_ms)
        {
            g.from_ms = g.from_ms.min(from_ms);
            g.to_ms = g.to_ms.max(to_ms);
            return;
        }
        if self.list.len() >= MAX_GAPS {
            self.truncated = true;
            return;
        }
        self.list.push(MetricsGap {
            from_ms,
            to_ms,
            reason,
        });
    }

    fn finish(mut self) -> (Vec<MetricsGap>, bool) {
        self.list.sort_by_key(|g| (g.from_ms, g.to_ms));
        (self.list, self.truncated)
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "point counts of one series; f64 is exact far beyond any range's points"
)]
fn column(
    metric: PerformanceMetric,
    role: Option<ProcessRole>,
    unit: PerformanceUnit,
    values: Vec<Option<f64>>,
    range_points: usize,
) -> PerformanceSeries {
    let known = values.iter().filter(|v| v.is_some()).count();
    let coverage = if range_points == 0 {
        0.0
    } else {
        (known as f64 / range_points as f64).min(1.0)
    };
    PerformanceSeries {
        metric,
        role,
        unit,
        reason_code: (known == 0).then(|| reason::NOT_MEASURED.to_string()),
        values,
        coverage_ratio: formula::round(coverage, 4),
    }
}

/// The point times, per-role columns, resolution and expected point count of a range.
type Columns = (Vec<i64>, BTreeMap<ProcessRole, Vec<Cell>>, u32, usize);

/// One role's cell at one 5-s tick.
#[expect(
    clippy::cast_precision_loss,
    reason = "a byte count shown as a series value; f64 is exact far beyond real memory sizes"
)]
fn tick_cell(v: &TickValue) -> Cell {
    (
        v.cpu
            .and_then(|(d, dt)| formula::cpu_core_pct(d, dt))
            .map(|v| formula::round(v, 2)),
        v.rss_bytes.map(|r| r as f64),
    )
}

/// The columns of a range kept as 5-s ticks: a null point after each long silence.
fn tick_columns(
    by_role: &BTreeMap<ProcessRole, Vec<TickValue>>,
    range: MetricsRange,
    from: i64,
    now_ms: i64,
    gaps: &mut Gaps,
) -> Columns {
    let grid: BTreeSet<i64> = by_role
        .values()
        .flatten()
        .map(|t| t.at_ms)
        .filter(|t| (from..now_ms).contains(t))
        .collect();
    // Insert a null point after each silence longer than the gap limit.
    let mut ts: Vec<i64> = Vec::new();
    let mut prev: Option<i64> = None;
    for t in &grid {
        match prev {
            Some(p) if t - p > TICK_MAX_GAP_MS => {
                ts.push(p + TICK_MS);
                gaps.add(p + 1, *t, MetricsGapReason::Missing);
            }
            None if t - from > TICK_MAX_GAP_MS => {
                gaps.add(from, *t, MetricsGapReason::Missing);
            }
            _ => {}
        }
        ts.push(*t);
        prev = Some(*t);
    }
    match prev {
        Some(p) if now_ms - p > TICK_MAX_GAP_MS => {
            gaps.add(p + 1, now_ms, MetricsGapReason::Missing);
        }
        None => gaps.add(from, now_ms, MetricsGapReason::Missing),
        _ => {}
    }
    let mut per_role: BTreeMap<ProcessRole, Vec<Cell>> = BTreeMap::new();
    for (role, ticks) in by_role {
        let at: BTreeMap<i64, &TickValue> = ticks.iter().map(|t| (t.at_ms, t)).collect();
        let col = ts
            .iter()
            .map(|t| at.get(t).map_or((None, None), |v| tick_cell(v)))
            .collect();
        // A tick of the role without a CPU value: a process just started or its counter
        // did not continue.
        let mut last: Option<i64> = None;
        for t in ticks.iter().filter(|t| (from..now_ms).contains(&t.at_ms)) {
            if t.cpu.is_none() {
                gaps.add(
                    last.map_or(t.at_ms - TICK_MS, |l| l + 1),
                    t.at_ms + 1,
                    MetricsGapReason::NewGeneration,
                );
            }
            last = Some(t.at_ms);
        }
        per_role.insert(*role, col);
    }
    let expected = usize::try_from(range.duration_ms() / TICK_MS).unwrap_or(usize::MAX);
    (ts, per_role, 5u32, expected)
}

/// The columns of a range kept as buckets, folded to the range's resolution.
fn bucket_columns(
    by_role: &BTreeMap<ProcessRole, Vec<BucketValue>>,
    range: MetricsRange,
    from: i64,
    now_ms: i64,
    gaps: &mut Gaps,
) -> Columns {
    let step: i64 = i64::from(system_resolution(range)) * 1_000;
    let start = from.div_euclid(step) * step;
    let ts: Vec<i64> = std::iter::successors(Some(start), |t| Some(t + step))
        .take_while(|t| *t < now_ms)
        .collect();
    let mut per_role = BTreeMap::new();
    for (role, buckets) in by_role {
        let mut folded: BTreeMap<i64, BucketValue> = BTreeMap::new();
        for b in buckets {
            let k = b.bucket_ms.div_euclid(step) * step;
            folded
                .entry(k)
                .or_insert_with(|| BucketValue {
                    bucket_ms: k,
                    ..Default::default()
                })
                .merge(b);
        }
        let col: Vec<Cell> = ts
            .iter()
            .map(|t| {
                folded.get(t).map_or((None, None), |b| {
                    (b.cpu_pct().map(|v| formula::round(v, 2)), b.rss())
                })
            })
            .collect();
        per_role.insert(*role, col);
    }
    for (i, t) in ts.iter().enumerate() {
        let any = per_role
            .values()
            .any(|col| col[i].0.is_some() || col[i].1.is_some());
        if !any {
            gaps.add(
                (*t).max(from),
                (t + step).min(now_ms),
                MetricsGapReason::Missing,
            );
        }
    }
    let expected = ts.len();
    (ts, per_role, system_resolution(range), expected)
}

/// The system-scope series set: per-role and product CPU and memory.
#[must_use]
pub fn system_series(
    range: MetricsRange,
    now_ms: i64,
    logical_cpus: u32,
    input: &RoleInput,
    store_gaps: &[(i64, i64, MetricsGapReason)],
) -> PerformanceSeriesSet {
    let from = now_ms - range.duration_ms();
    let mut gaps = Gaps::new();
    for (a, b, r) in store_gaps {
        gaps.add((*a).max(from), (*b).min(now_ms), *r);
    }
    let (timestamps, per_role, resolution_secs, expected) = match input {
        RoleInput::Ticks(by_role) => tick_columns(by_role, range, from, now_ms, &mut gaps),
        RoleInput::Buckets(by_role) => bucket_columns(by_role, range, from, now_ms, &mut gaps),
    };

    // The product: every role present at a point must have a value, else it is unknown.
    let product = |pick: fn(&Cell) -> Option<f64>| -> Vec<Option<f64>> {
        (0..timestamps.len())
            .map(|i| {
                let present: Vec<Option<f64>> = per_role
                    .values()
                    .map(|col| col[i])
                    .filter(|v| v.0.is_some() || v.1.is_some())
                    .map(|v| pick(&v))
                    .collect();
                if present.is_empty() || present.iter().any(Option::is_none) {
                    None
                } else {
                    Some(formula::round(present.iter().flatten().sum(), 2))
                }
            })
            .collect()
    };
    let product_cpu = product(|v| v.0);
    let product_host: Vec<Option<f64>> = product_cpu
        .iter()
        .map(|v| {
            v.and_then(|c| formula::cpu_host_pct(c, logical_cpus))
                .map(|v| formula::round(v, 2))
        })
        .collect();
    let product_rss = product(|v| v.1);
    let mut series = vec![
        column(
            PerformanceMetric::CpuCorePct,
            None,
            PerformanceUnit::Percent,
            product_cpu,
            expected,
        ),
        column(
            PerformanceMetric::CpuHostPct,
            None,
            PerformanceUnit::Percent,
            product_host,
            expected,
        ),
        column(
            PerformanceMetric::RssBytes,
            None,
            PerformanceUnit::Bytes,
            product_rss,
            expected,
        ),
    ];
    for (role, col) in &per_role {
        series.push(column(
            PerformanceMetric::CpuCorePct,
            Some(*role),
            PerformanceUnit::Percent,
            col.iter().map(|v| v.0).collect(),
            expected,
        ));
        series.push(column(
            PerformanceMetric::RssBytes,
            Some(*role),
            PerformanceUnit::Bytes,
            col.iter().map(|v| v.1).collect(),
            expected,
        ));
    }
    let (gaps, truncated) = gaps.finish();
    PerformanceSeriesSet {
        scope: PerformanceScope::system(),
        range,
        resolution_secs,
        from_ms: from,
        to_ms: now_ms,
        timestamps,
        series,
        gaps,
        gaps_truncated: truncated,
        notes: vec![
            series_note::PROCESS_SAMPLES.into(),
            series_note::RSS_SUM_COUNTS_SHARED_PAGES.into(),
        ],
    }
}

/// The Instance- or Gateway-scope set from the metrics service's own persisted series of that scope.
///
/// The series are `instance:<id>` or `gateway:<id>`: payload and `WireGuard` rates and flows, and
/// for an Instance its worker's CPU and memory. Nothing is recomputed here; a gap stays a gap.
#[must_use]
pub fn store_series(
    scope: PerformanceScope,
    m: &MetricsSeries,
    logical_cpus: u32,
) -> PerformanceSeriesSet {
    let expected = if m.resolution_secs == 0 {
        m.timestamps.len()
    } else {
        usize::try_from(((m.to_ms - m.from_ms) / (i64::from(m.resolution_secs) * 1_000)).max(1))
            .unwrap_or(usize::MAX)
    };
    let col = |metric, unit, values: Vec<Option<f64>>| column(metric, None, unit, values, expected);
    let gateway = scope.kind == PerformanceScopeKind::Gateway;
    let mut series = vec![
        col(
            PerformanceMetric::PayloadUploadBps,
            PerformanceUnit::BitPerSecond,
            m.payload_tx_bps.clone(),
        ),
        col(
            PerformanceMetric::PayloadDownloadBps,
            PerformanceUnit::BitPerSecond,
            m.payload_rx_bps.clone(),
        ),
    ];
    if gateway {
        // A Gateway's own client connections (UDP associations keep one each).
        series.push(col(
            PerformanceMetric::ActiveDataFlows,
            PerformanceUnit::Count,
            m.active_tcp.clone(),
        ));
    } else {
        let flows: Vec<Option<f64>> = m
            .active_tcp
            .iter()
            .zip(&m.active_udp)
            .map(|(t, u)| match (t, u) {
                (Some(t), Some(u)) => Some(t + u),
                _ => None,
            })
            .collect();
        let host: Vec<Option<f64>> = m
            .cpu_core_pct
            .iter()
            .map(|v| {
                v.and_then(|c| formula::cpu_host_pct(c, logical_cpus))
                    .map(|v| formula::round(v, 2))
            })
            .collect();
        series.extend([
            col(
                PerformanceMetric::WireguardTxBps,
                PerformanceUnit::BitPerSecond,
                m.wg_tx_bps.clone(),
            ),
            col(
                PerformanceMetric::WireguardRxBps,
                PerformanceUnit::BitPerSecond,
                m.wg_rx_bps.clone(),
            ),
            col(
                PerformanceMetric::CpuCorePct,
                PerformanceUnit::Percent,
                m.cpu_core_pct.clone(),
            ),
            col(
                PerformanceMetric::CpuHostPct,
                PerformanceUnit::Percent,
                host,
            ),
            col(
                PerformanceMetric::RssBytes,
                PerformanceUnit::Bytes,
                m.rss_bytes.clone(),
            ),
            col(
                PerformanceMetric::ActiveTunnelFlows,
                PerformanceUnit::Count,
                flows,
            ),
        ]);
    }
    PerformanceSeriesSet {
        scope,
        range: m.range,
        resolution_secs: m.resolution_secs,
        from_ms: m.from_ms,
        to_ms: m.to_ms,
        timestamps: m.timestamps.clone(),
        series,
        gaps: m.gaps.clone(),
        gaps_truncated: m.gaps_truncated,
        notes: vec![series_note::INSTANCE_METRICS.into()],
    }
}
