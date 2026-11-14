//! Series on a time grid: one point per window `[from + i·step, from + (i+1)·step)` (the last
//! one ends at `to`), computed per series (one Instance, or one Gateway of an Instance) and
//! then combined for the scope.
//!
//! From raw samples, each continuous interval spreads its rate (worker clock) and its bytes over
//! the windows its wall-clock span overlaps, in proportion to the overlap; a gauge observation
//! weighs the interval it ends (one nominal sample interval when it starts a run). Arrival
//! jitter therefore never leaves a window empty while the samples are continuous. Counts that
//! cannot be split (latency histograms, connect outcomes) belong to the window in which their
//! interval ended, and a window that only continuous intervals ending elsewhere cover has a
//! known count of zero. From rollups, a point is its bucket.
//!
//! Combining series (`scope=all`) sums the known values per point; ratios are recomputed from
//! the summed parts and histograms are merged, never averaged. A point is unknown only when no
//! series knows it, and its gap reason is the most specific reason any series has.

use crate::num::{i64_to_f64, u64_to_f64};
use vpn_domain::{METRICS_MAX_GAPS, MetricsGap, MetricsGapReason, MetricsSeries, MetricsTotals};

use super::hist::{Hist, Quantile};
use super::rollup::{
    BREAK_GENERATION, Bucket, ConnectCounters, Link, Row, bps, cpu_pct, link, round2,
};
use super::{MAX_GAP_MS, SAMPLE_INTERVAL_MS};

/// A gap the data itself cannot show (dropped by the collector, pruned for the quota): the
/// first and last affected sample time, inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Logged {
    pub start: i64,
    pub end: i64,
    pub reason: MetricsGapReason,
}

fn logged_reason(logged: &[Logged], from: i64, to: i64) -> Option<MetricsGapReason> {
    logged
        .iter()
        .filter(|g| g.start <= to && g.end >= from)
        .map(|g| g.reason)
        .max_by_key(|r| priority(*r))
}

/// How specific a reason is: a point several series are missing for different reasons shows
/// the most specific one.
const fn priority(r: MetricsGapReason) -> u8 {
    use MetricsGapReason::{
        CounterReset, DiskLow, Dropped, LongInterval, Missing, NewGeneration, Quota, Unavailable,
    };
    match r {
        DiskLow => 7,
        Quota => 6,
        Dropped => 5,
        CounterReset => 4,
        NewGeneration => 3,
        LongInterval => 2,
        Missing => 1,
        Unavailable => 0,
    }
}

const fn stronger(a: Option<MetricsGapReason>, b: MetricsGapReason) -> MetricsGapReason {
    match a {
        Some(a) if priority(a) >= priority(b) => a,
        _ => b,
    }
}

/// The windows of a series answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grid {
    pub from: i64,
    pub to: i64,
    pub step: i64,
}

impl Grid {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a positive window count, bounded by the points of one answer"
    )]
    pub(crate) const fn len(&self) -> usize {
        if self.to <= self.from {
            return 0;
        }
        ((self.to - self.from + self.step - 1) / self.step) as usize
    }

    #[expect(
        clippy::cast_possible_wrap,
        reason = "a window index, bounded by the points of one answer"
    )]
    pub(crate) const fn start(&self, i: usize) -> i64 {
        self.from + i as i64 * self.step
    }

    pub(crate) fn end(&self, i: usize) -> i64 {
        (self.start(i) + self.step).min(self.to)
    }

    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "`t` is inside the grid, so the index is non-negative and bounded by its windows"
    )]
    pub(crate) fn slot(&self, t: i64) -> Option<usize> {
        (self.from..self.to)
            .contains(&t)
            .then(|| ((t - self.from) / self.step) as usize)
    }

    /// Windows overlapping `[a, b)`, with the overlap in milliseconds.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "`lo < hi` lie inside the grid, so the indices are non-negative and bounded"
    )]
    fn overlaps(&self, a: i64, b: i64) -> impl Iterator<Item = (usize, i64)> + '_ {
        let (lo, hi) = (a.max(self.from), b.min(self.to));
        let range = if lo < hi {
            ((lo - self.from) / self.step) as usize..((hi - 1 - self.from) / self.step) as usize + 1
        } else {
            0..0
        };
        range.map(move |i| (i, hi.min(self.end(i)) - lo.max(self.start(i))))
    }
}

/// One series' values in one window. `None` is unknown.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Point {
    /// Series that observed anything in the window (0 or 1; summed when combined).
    pub reporting: u32,
    /// Time of continuous intervals in the window (the best-covered series when combined).
    pub covered_ms: f64,
    /// Covered time whose gate state is recorded, and of it the time the gate was open.
    pub gate_ms: f64,
    pub open_ms: f64,
    pub payload_rx_bps: Option<f64>,
    pub payload_tx_bps: Option<f64>,
    pub payload_rx_bytes: Option<f64>,
    pub payload_tx_bytes: Option<f64>,
    pub wg_rx_bps: Option<f64>,
    pub wg_tx_bps: Option<f64>,
    pub wg_rx_bytes: Option<f64>,
    pub wg_tx_bytes: Option<f64>,
    /// The strict sandbox's Apps' part of the payload; `None` without a sandbox.
    pub sandbox_rx_bps: Option<f64>,
    pub sandbox_tx_bps: Option<f64>,
    pub sandbox_rx_bytes: Option<f64>,
    pub sandbox_tx_bytes: Option<f64>,
    /// The SSH sessions' part of the payload (「SSH 代理」); `None` where not recorded.
    pub ssh_rx_bps: Option<f64>,
    pub ssh_tx_bps: Option<f64>,
    pub ssh_rx_bytes: Option<f64>,
    pub ssh_tx_bytes: Option<f64>,
    /// VPN Manager's own SSH downloads' part of the payload (「SSH 下載」).
    pub pull_rx_bps: Option<f64>,
    pub pull_tx_bps: Option<f64>,
    pub pull_rx_bytes: Option<f64>,
    pub pull_tx_bytes: Option<f64>,
    pub tcp: Option<f64>,
    pub udp: Option<f64>,
    pub dns_qps: Option<f64>,
    pub dns_fps: Option<f64>,
    /// DNS lookups, failures and cache hits in the window.
    pub dns_queries: Option<f64>,
    pub dns_failures: Option<f64>,
    pub dns_hits: Option<f64>,
    pub cpu_pct: Option<f64>,
    pub rss: Option<f64>,
    pub connect: Option<ConnectCounters>,
    pub dns_latency: Option<Hist>,
    /// Why the rates are unknown here; `None` while they are known or not due yet.
    pub reason: Option<MetricsGapReason>,
    /// Observed here without its CPU or memory reading.
    pub unavailable: bool,
    /// A new worker generation started in this window.
    pub restart: bool,
}

/// Σ value × ms and Σ ms: a time-weighted mean.
#[derive(Debug, Clone, Copy, Default)]
struct Wsum {
    sum: f64,
    ms: f64,
}

impl Wsum {
    fn add(&mut self, v: f64, ms: f64) {
        self.sum = v.mul_add(ms, self.sum);
        self.ms += ms;
    }

    fn mean(&self) -> Option<f64> {
        (self.ms > 0.0).then(|| self.sum / self.ms)
    }
}

/// A byte counter pair: rates weighted by time, and the bytes themselves.
#[derive(Debug, Clone, Copy, Default)]
struct Flow {
    rx: Wsum,
    tx: Wsum,
    rx_bytes: f64,
    tx_bytes: f64,
}

impl Flow {
    fn add(&mut self, delta: (u64, u64), dt_ms: f64, overlap_ms: f64, share: f64) {
        self.rx
            .add(u64_to_f64(delta.0) * 8_000.0 / dt_ms, overlap_ms);
        self.tx
            .add(u64_to_f64(delta.1) * 8_000.0 / dt_ms, overlap_ms);
        self.rx_bytes = u64_to_f64(delta.0).mul_add(share, self.rx_bytes);
        self.tx_bytes = u64_to_f64(delta.1).mul_add(share, self.tx_bytes);
    }

    fn known(&self) -> bool {
        self.rx.ms > 0.0
    }
}

#[derive(Debug, Clone, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent per-window flags of an accumulator, not a state machine"
)]
struct Acc {
    observed: bool,
    covered: f64,
    gate: f64,
    open: f64,
    payload: Flow,
    wg: Flow,
    sandbox: Flow,
    ssh: Flow,
    pull: Flow,
    tcp: Wsum,
    udp: Wsum,
    rss: Wsum,
    cpu: Wsum,
    dns_qps: Wsum,
    dns_fps: Wsum,
    dns_queries: f64,
    dns_failures: f64,
    dns_hits: f64,
    connect: Option<ConnectCounters>,
    connect_unknown: bool,
    dns_latency: Option<Hist>,
    dns_latency_unknown: bool,
    reason: Option<MetricsGapReason>,
    rss_missing: bool,
    cpu_missing: bool,
    restart: bool,
}

fn pair(new: (u64, u64), old: (u64, u64)) -> Option<(u64, u64)> {
    Some((new.0.checked_sub(old.0)?, new.1.checked_sub(old.1)?))
}

/// Points of one series from its raw rows (time-ordered; they may start with the last row
/// before the grid, so the first window has its rate or its break).
pub fn raw_points(rows: &[Row], logged: &[Logged], grid: &Grid) -> Vec<Point> {
    use MetricsGapReason::{Missing, NewGeneration};
    let sample = SAMPLE_INTERVAL_MS.cast_signed();
    let mut acc = vec![Acc::default(); grid.len()];
    let mark = |acc: &mut [Acc], a: i64, b: i64, reason: MetricsGapReason| {
        for (i, _) in grid.overlaps(a, b) {
            acc[i].reason = Some(stronger(acc[i].reason, reason));
        }
    };
    let mut prev: Option<&Row> = None;
    for cur in rows {
        if cur.at_ms >= grid.to {
            break;
        }
        match prev.map(|p| (p, link(p, cur))) {
            Some((p, Link::Continuous { dt_ms })) => interval(&mut acc, grid, p, cur, dt_ms),
            Some((p, Link::Break(reason))) => {
                gauges(&mut acc, grid, cur);
                if reason == NewGeneration
                    && let Some(k) = grid.slot(cur.at_ms)
                {
                    acc[k].restart = true;
                }
                if reason == NewGeneration
                    && cur.at_ms - p.at_ms > MAX_GAP_MS.cast_signed() + sample
                {
                    // Long silence, then a new worker: not running in between, and the first
                    // sample of the new generation has no rate yet.
                    mark(&mut acc, p.at_ms, cur.at_ms - sample, Missing);
                    mark(&mut acc, cur.at_ms - sample, cur.at_ms + 1, NewGeneration);
                } else {
                    mark(&mut acc, p.at_ms, cur.at_ms + 1, reason);
                }
            }
            None => {
                gauges(&mut acc, grid, cur);
                mark(&mut acc, grid.from, cur.at_ms + 1, Missing);
            }
        }
        prev = Some(cur);
    }
    // After the last sample: silent for longer than a sample may take is missing; less is not
    // due yet.
    match prev {
        None => mark(&mut acc, grid.from, grid.to, Missing),
        Some(last) if grid.to - last.at_ms > MAX_GAP_MS.cast_signed() => {
            mark(&mut acc, last.at_ms + 1, grid.to, Missing);
        }
        Some(_) => {}
    }
    // A sample that never reached the disk stood for the interval ending at it.
    for g in logged {
        mark(&mut acc, g.start - sample, g.end + 1, g.reason);
    }
    let instance = rows.first().is_some_and(|r| r.inst.is_some());
    acc.iter().map(|a| finish(a, instance)).collect()
}

/// Account the continuous interval `p → cur`.
fn interval(acc: &mut [Acc], grid: &Grid, prev: &Row, cur: &Row, dt_ms: u64) {
    let dt = u64_to_f64(dt_ms);
    // Two samples arriving within the same millisecond still span one.
    let (lo, hi) = (prev.at_ms.min(cur.at_ms - 1), cur.at_ms);
    let wall = i64_to_f64(hi - lo);
    let payload = pair(
        (cur.payload_rx, cur.payload_tx),
        (prev.payload_rx, prev.payload_tx),
    );
    let inst = cur.inst.as_ref().zip(prev.inst.as_ref());
    let wg = inst.and_then(|(c, o)| pair((c.wg_rx, c.wg_tx), (o.wg_rx, o.wg_tx)));
    let sandbox = inst.and_then(|(c, o)| pair(c.sandbox?, o.sandbox?));
    let ssh = cur
        .ssh
        .as_ref()
        .zip(prev.ssh.as_ref())
        .and_then(|(c, o)| c.since(o));
    let dns = inst.and_then(|(c, o)| {
        Some((
            c.dns_queries.checked_sub(o.dns_queries)?,
            c.dns_failures.checked_sub(o.dns_failures)?,
            c.dns_cache_hits.checked_sub(o.dns_cache_hits)?,
        ))
    });
    let cpu = inst
        .and_then(|(c, o)| c.cpu_ns?.checked_sub(o.cpu_ns?))
        .and_then(|d| cpu_pct(d, dt_ms));
    let connect = cur
        .connect
        .as_ref()
        .zip(prev.connect.as_ref())
        .and_then(|(c, o)| c.since(o));
    let dns_latency = inst.and_then(|(c, o)| {
        c.dns_latency
            .as_ref()
            .zip(o.dns_latency.as_ref())
            .and_then(|(c, o)| c.since(o))
    });
    for (i, overlap) in grid.overlaps(lo, hi) {
        let o = i64_to_f64(overlap);
        let share = o / wall;
        let s = &mut acc[i];
        s.observed = true;
        s.covered += o;
        if let Some(open) = cur.open {
            s.gate += o;
            if open {
                s.open += o;
            }
        }
        if let Some(d) = payload {
            s.payload.add(d, dt, o, share);
        }
        if let Some(d) = wg {
            s.wg.add(d, dt, o, share);
        }
        if let Some(d) = sandbox {
            s.sandbox.add(d, dt, o, share);
        }
        if let Some(d) = ssh {
            s.ssh.add((d.rx, d.tx), dt, o, share);
            s.pull.add((d.pull_rx, d.pull_tx), dt, o, share);
        }
        s.tcp.add(u64_to_f64(cur.tcp), o);
        s.udp.add(u64_to_f64(cur.udp), o);
        if let Some((c, _)) = inst {
            match c.rss_bytes {
                Some(v) => s.rss.add(u64_to_f64(v), o),
                None => s.rss_missing = true,
            }
            s.cpu_missing |= c.cpu_ns.is_none();
            if dns_latency.is_none() {
                s.dns_latency_unknown = true;
            }
        }
        if let Some(pct) = cpu {
            s.cpu.add(pct, o);
        }
        if let Some((q, f, h)) = dns {
            s.dns_qps.add(u64_to_f64(q) * 1_000.0 / dt, o);
            s.dns_fps.add(u64_to_f64(f) * 1_000.0 / dt, o);
            s.dns_queries = u64_to_f64(q).mul_add(share, s.dns_queries);
            s.dns_failures = u64_to_f64(f).mul_add(share, s.dns_failures);
            s.dns_hits = u64_to_f64(h).mul_add(share, s.dns_hits);
        }
        if connect.is_none() {
            s.connect_unknown = true;
        }
    }
    // Counts that cannot be split belong to the window in which the interval ended.
    if let Some(k) = grid.slot(hi) {
        let s = &mut acc[k];
        if let Some(d) = connect {
            s.connect.get_or_insert_default().add(&d);
        }
        if let Some(d) = dns_latency {
            s.dns_latency.get_or_insert_default().add(&d);
        }
    }
}

/// A sample without a continuous interval before it: its gauges weigh one sample interval.
fn gauges(acc: &mut [Acc], grid: &Grid, cur: &Row) {
    for (i, overlap) in grid.overlaps(cur.at_ms - SAMPLE_INTERVAL_MS.cast_signed(), cur.at_ms) {
        let o = i64_to_f64(overlap);
        let s = &mut acc[i];
        s.observed = true;
        s.tcp.add(u64_to_f64(cur.tcp), o);
        s.udp.add(u64_to_f64(cur.udp), o);
        if let Some(c) = &cur.inst {
            match c.rss_bytes {
                Some(v) => s.rss.add(u64_to_f64(v), o),
                None => s.rss_missing = true,
            }
            s.cpu_missing |= c.cpu_ns.is_none();
        }
    }
}

fn finish(s: &Acc, instance: bool) -> Point {
    let flow_bps = |w: &Wsum| w.mean().map(f64::round);
    let dns_known = s.dns_qps.ms > 0.0;
    // A window that continuous intervals cover, none of whose counts is unknown, saw zero of
    // what no interval ending in it brought.
    let zero_if_covered = |unknown: bool| s.covered > 0.0 && !unknown;
    Point {
        reporting: u32::from(s.observed),
        covered_ms: s.covered,
        gate_ms: s.gate,
        open_ms: s.open,
        payload_rx_bps: flow_bps(&s.payload.rx),
        payload_tx_bps: flow_bps(&s.payload.tx),
        payload_rx_bytes: s.payload.known().then_some(s.payload.rx_bytes),
        payload_tx_bytes: s.payload.known().then_some(s.payload.tx_bytes),
        wg_rx_bps: flow_bps(&s.wg.rx),
        wg_tx_bps: flow_bps(&s.wg.tx),
        wg_rx_bytes: s.wg.known().then_some(s.wg.rx_bytes),
        wg_tx_bytes: s.wg.known().then_some(s.wg.tx_bytes),
        sandbox_rx_bps: flow_bps(&s.sandbox.rx),
        sandbox_tx_bps: flow_bps(&s.sandbox.tx),
        sandbox_rx_bytes: s.sandbox.known().then_some(s.sandbox.rx_bytes),
        sandbox_tx_bytes: s.sandbox.known().then_some(s.sandbox.tx_bytes),
        ssh_rx_bps: flow_bps(&s.ssh.rx),
        ssh_tx_bps: flow_bps(&s.ssh.tx),
        ssh_rx_bytes: s.ssh.known().then_some(s.ssh.rx_bytes),
        ssh_tx_bytes: s.ssh.known().then_some(s.ssh.tx_bytes),
        pull_rx_bps: flow_bps(&s.pull.rx),
        pull_tx_bps: flow_bps(&s.pull.tx),
        pull_rx_bytes: s.pull.known().then_some(s.pull.rx_bytes),
        pull_tx_bytes: s.pull.known().then_some(s.pull.tx_bytes),
        tcp: s.tcp.mean(),
        udp: s.udp.mean(),
        dns_qps: s.dns_qps.mean(),
        dns_fps: s.dns_fps.mean(),
        dns_queries: dns_known.then_some(s.dns_queries),
        dns_failures: dns_known.then_some(s.dns_failures),
        dns_hits: dns_known.then_some(s.dns_hits),
        cpu_pct: s.cpu.mean(),
        rss: s.rss.mean(),
        connect: s
            .connect
            .or_else(|| zero_if_covered(s.connect_unknown).then(ConnectCounters::default)),
        dns_latency: if instance {
            s.dns_latency
                .or_else(|| zero_if_covered(s.dns_latency_unknown).then(Hist::default))
        } else {
            None
        },
        reason: s.reason,
        unavailable: instance && s.observed && (s.rss_missing || s.cpu_missing),
        restart: s.restart,
    }
}

/// Points of one series from its rollup buckets (time-ordered, on the grid's step).
pub fn bucket_points(buckets: &[Bucket], logged: &[Logged], grid: &Grid) -> Vec<Point> {
    let n = grid.len();
    let mut out: Vec<Point> = Vec::with_capacity(n);
    let mut it = buckets.iter().peekable();
    for i in 0..n {
        let t = grid.start(i);
        while it.next_if(|b| b.bucket_ms < t).is_some() {}
        let logged_here = logged_reason(logged, t, t + grid.step - 1);
        let point = match it.next_if(|b| b.bucket_ms == t) {
            Some(b) if b.samples > 0 => {
                let mut p = point_of(b);
                if p.payload_rx_bps.is_none() {
                    p.reason = Some(logged_here.unwrap_or_else(|| b.break_reason()));
                }
                p
            }
            _ => {
                // The window holding `to` may not be rolled up yet while the series runs.
                let pending = i + 1 == n && out.last().is_some_and(|p| p.reporting > 0);
                Point {
                    reason: (!pending).then(|| logged_here.unwrap_or(MetricsGapReason::Missing)),
                    ..Point::default()
                }
            }
        };
        out.push(point);
    }
    out
}

fn point_of(b: &Bucket) -> Point {
    let known = |ms: u64, v: u64| (ms > 0).then_some(u64_to_f64(v));
    let mut p = Point {
        reporting: 1,
        covered_ms: u64_to_f64(b.link_ms),
        gate_ms: u64_to_f64(b.gate_ms),
        open_ms: u64_to_f64(b.open_ms),
        payload_rx_bps: bps(b.payload_rx, b.payload_ms),
        payload_tx_bps: bps(b.payload_tx, b.payload_ms),
        payload_rx_bytes: known(b.payload_ms, b.payload_rx),
        payload_tx_bytes: known(b.payload_ms, b.payload_tx),
        tcp: b.tcp.mean(),
        udp: b.udp.mean(),
        connect: (b.connect_ms > 0).then_some(b.connect),
        ssh_rx_bps: bps(b.ssh.rx, b.ssh_ms),
        ssh_tx_bps: bps(b.ssh.tx, b.ssh_ms),
        ssh_rx_bytes: known(b.ssh_ms, b.ssh.rx),
        ssh_tx_bytes: known(b.ssh_ms, b.ssh.tx),
        pull_rx_bps: bps(b.ssh.pull_rx, b.ssh_ms),
        pull_tx_bps: bps(b.ssh.pull_tx, b.ssh_ms),
        pull_rx_bytes: known(b.ssh_ms, b.ssh.pull_rx),
        pull_tx_bytes: known(b.ssh_ms, b.ssh.pull_tx),
        restart: b.breaks & BREAK_GENERATION != 0,
        ..Point::default()
    };
    if let Some(i) = &b.inst {
        p.wg_rx_bps = bps(i.wg_rx, i.wg_ms);
        p.wg_tx_bps = bps(i.wg_tx, i.wg_ms);
        p.wg_rx_bytes = known(i.wg_ms, i.wg_rx);
        p.wg_tx_bytes = known(i.wg_ms, i.wg_tx);
        p.sandbox_rx_bps = bps(i.sandbox_rx, i.sandbox_ms);
        p.sandbox_tx_bps = bps(i.sandbox_tx, i.sandbox_ms);
        p.sandbox_rx_bytes = known(i.sandbox_ms, i.sandbox_rx);
        p.sandbox_tx_bytes = known(i.sandbox_ms, i.sandbox_tx);
        p.dns_qps =
            (i.dns_ms > 0).then(|| u64_to_f64(i.dns_queries) * 1_000.0 / u64_to_f64(i.dns_ms));
        p.dns_fps =
            (i.dns_ms > 0).then(|| u64_to_f64(i.dns_failures) * 1_000.0 / u64_to_f64(i.dns_ms));
        p.dns_queries = known(i.dns_ms, i.dns_queries);
        p.dns_failures = known(i.dns_ms, i.dns_failures);
        p.dns_hits = known(i.dns_ms, i.dns_cache_hits);
        p.cpu_pct = cpu_pct(i.cpu_ns, i.cpu_ms);
        p.rss = i.rss.mean();
        p.dns_latency = (i.dns_latency_ms > 0).then_some(i.dns_latency);
        p.unavailable = (i.cpu_ms == 0 && b.link_ms > 0) || i.rss.weight_ms == 0;
    }
    p
}

fn osum(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a + b),
        (a, b) => a.or(b),
    }
}

fn omax(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

fn merge_connect(a: &mut Option<ConnectCounters>, b: Option<&ConnectCounters>) {
    if let Some(b) = b {
        a.get_or_insert_default().add(b);
    }
}

fn merge_hist(a: &mut Option<Hist>, b: Option<&Hist>) {
    if let Some(b) = b {
        a.get_or_insert_default().add(b);
    }
}

/// Combine series point by point: known values are summed, histograms merged.
pub fn combine(series: &[Vec<Point>], n: usize) -> Vec<Point> {
    if series.is_empty() {
        return (0..n)
            .map(|_| Point {
                reason: Some(MetricsGapReason::Missing),
                ..Point::default()
            })
            .collect();
    }
    (0..n)
        .map(|i| {
            let mut out = Point::default();
            // A series whose sample for this window is not due yet: the window is not final,
            // whatever the others say.
            let mut pending = false;
            for p in series.iter().filter_map(|s| s.get(i)) {
                pending |= p.reporting == 0 && p.reason.is_none();
                out.reporting += p.reporting;
                out.covered_ms = out.covered_ms.max(p.covered_ms);
                out.gate_ms += p.gate_ms;
                out.open_ms += p.open_ms;
                out.payload_rx_bps = osum(out.payload_rx_bps, p.payload_rx_bps);
                out.payload_tx_bps = osum(out.payload_tx_bps, p.payload_tx_bps);
                out.payload_rx_bytes = osum(out.payload_rx_bytes, p.payload_rx_bytes);
                out.payload_tx_bytes = osum(out.payload_tx_bytes, p.payload_tx_bytes);
                out.wg_rx_bps = osum(out.wg_rx_bps, p.wg_rx_bps);
                out.wg_tx_bps = osum(out.wg_tx_bps, p.wg_tx_bps);
                out.wg_rx_bytes = osum(out.wg_rx_bytes, p.wg_rx_bytes);
                out.wg_tx_bytes = osum(out.wg_tx_bytes, p.wg_tx_bytes);
                out.sandbox_rx_bps = osum(out.sandbox_rx_bps, p.sandbox_rx_bps);
                out.sandbox_tx_bps = osum(out.sandbox_tx_bps, p.sandbox_tx_bps);
                out.sandbox_rx_bytes = osum(out.sandbox_rx_bytes, p.sandbox_rx_bytes);
                out.sandbox_tx_bytes = osum(out.sandbox_tx_bytes, p.sandbox_tx_bytes);
                out.ssh_rx_bps = osum(out.ssh_rx_bps, p.ssh_rx_bps);
                out.ssh_tx_bps = osum(out.ssh_tx_bps, p.ssh_tx_bps);
                out.ssh_rx_bytes = osum(out.ssh_rx_bytes, p.ssh_rx_bytes);
                out.ssh_tx_bytes = osum(out.ssh_tx_bytes, p.ssh_tx_bytes);
                out.pull_rx_bps = osum(out.pull_rx_bps, p.pull_rx_bps);
                out.pull_tx_bps = osum(out.pull_tx_bps, p.pull_tx_bps);
                out.pull_rx_bytes = osum(out.pull_rx_bytes, p.pull_rx_bytes);
                out.pull_tx_bytes = osum(out.pull_tx_bytes, p.pull_tx_bytes);
                out.tcp = osum(out.tcp, p.tcp);
                out.udp = osum(out.udp, p.udp);
                out.dns_qps = osum(out.dns_qps, p.dns_qps);
                out.dns_fps = osum(out.dns_fps, p.dns_fps);
                out.dns_queries = osum(out.dns_queries, p.dns_queries);
                out.dns_failures = osum(out.dns_failures, p.dns_failures);
                out.dns_hits = osum(out.dns_hits, p.dns_hits);
                out.cpu_pct = osum(out.cpu_pct, p.cpu_pct);
                out.rss = osum(out.rss, p.rss);
                merge_connect(&mut out.connect, p.connect.as_ref());
                merge_hist(&mut out.dns_latency, p.dns_latency.as_ref());
                if let Some(r) = p.reason {
                    out.reason = Some(stronger(out.reason, r));
                }
                out.unavailable |= p.unavailable;
                out.restart |= p.restart;
            }
            if pending {
                out.reason = None;
            }
            out
        })
        .collect()
}

/// Totals over a series' (or a combination's) points. `serving` says whether gate time adds
/// up to availability: one Instance or one Gateway, not a sum over Instances.
/// A byte total, rounded and clamped at zero (`as` saturates beyond `u64`).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a rounded, non-negative byte total; `as` saturates, as intended"
)]
const fn round_u64(v: f64) -> u64 {
    v.round().max(0.0) as u64
}

/// A time in ms, rounded (`as` saturates beyond `i64`).
#[expect(
    clippy::cast_possible_truncation,
    reason = "a rounded time in ms, far within i64; `as` saturates, as intended"
)]
const fn round_i64(v: f64) -> i64 {
    v.round() as i64
}

/// The counts of a point that totals sum, in the order [`totals`] reads them.
const fn counts(p: &Point) -> [Option<f64>; 13] {
    [
        p.payload_rx_bytes,
        p.payload_tx_bytes,
        p.wg_rx_bytes,
        p.wg_tx_bytes,
        p.dns_queries,
        p.dns_failures,
        p.dns_hits,
        p.sandbox_rx_bytes,
        p.sandbox_tx_bytes,
        p.ssh_rx_bytes,
        p.ssh_tx_bytes,
        p.pull_rx_bytes,
        p.pull_tx_bytes,
    ]
}

/// A point's SSH sessions ↓↑, SSH downloads ↓↑, and its payload without either ↓↑ (where they
/// are known: the rest of what the scope carried).
fn ssh_rates(p: &Point) -> [Option<f64>; 6] {
    let rest = |all: Option<f64>, ssh: Option<f64>, pull: Option<f64>| {
        Some((all? - ssh? - pull?).max(0.0))
    };
    [
        p.ssh_rx_bps,
        p.ssh_tx_bps,
        p.pull_rx_bps,
        p.pull_tx_bps,
        rest(p.payload_rx_bps, p.ssh_rx_bps, p.pull_rx_bps),
        rest(p.payload_tx_bps, p.ssh_tx_bps, p.pull_tx_bps),
    ]
}

pub fn totals(points: &[Point], range_ms: i64, serving: bool) -> MetricsTotals {
    let (mut covered, mut gate, mut open) = (0.0, 0.0, 0.0);
    let mut sums: [Option<f64>; 13] = [None; 13];
    let (mut peak_rx, mut peak_tx) = (None, None);
    let (mut peak_sandbox_rx, mut peak_sandbox_tx) = (None, None);
    let mut peaks: [Option<f64>; 6] = [None; 6];
    let mut connect: Option<ConnectCounters> = None;
    let mut dns_latency: Option<Hist> = None;
    for p in points {
        covered += p.covered_ms;
        gate += p.gate_ms;
        open += p.open_ms;
        for (sum, v) in sums.iter_mut().zip(counts(p)) {
            *sum = osum(*sum, v);
        }
        for (peak, v) in peaks.iter_mut().zip(ssh_rates(p)) {
            *peak = omax(*peak, v);
        }
        peak_rx = omax(peak_rx, p.payload_rx_bps);
        peak_tx = omax(peak_tx, p.payload_tx_bps);
        peak_sandbox_rx = omax(peak_sandbox_rx, p.sandbox_rx_bps);
        peak_sandbox_tx = omax(peak_sandbox_tx, p.sandbox_tx_bps);
        merge_connect(&mut connect, p.connect.as_ref());
        merge_hist(&mut dns_latency, p.dns_latency.as_ref());
    }
    let int = |v: Option<f64>| v.map(round_u64);
    let [
        payload_rx,
        payload_tx,
        wg_rx,
        wg_tx,
        dns_q,
        dns_f,
        dns_h,
        sandbox_rx,
        sandbox_tx,
        ssh_rx,
        ssh_tx,
        pull_rx,
        pull_tx,
    ] = sums;
    let [
        peak_ssh_rx,
        peak_ssh_tx,
        peak_pull_rx,
        peak_pull_tx,
        peak_rest_rx,
        peak_rest_tx,
    ] = peaks;
    let latency = connect.as_ref().map(|c| &c.latency);
    MetricsTotals {
        range_ms,
        covered_ms: round_i64(covered),
        // Availability needs the gate state of all covered time.
        serving_ms: (serving && covered > 0.0 && gate + 0.5 >= covered).then(|| round_i64(open)),
        payload_rx_bytes: int(payload_rx),
        payload_tx_bytes: int(payload_tx),
        wg_rx_bytes: int(wg_rx),
        wg_tx_bytes: int(wg_tx),
        peak_payload_rx_bps: peak_rx,
        peak_payload_tx_bps: peak_tx,
        sandbox_rx_bytes: int(sandbox_rx),
        sandbox_tx_bytes: int(sandbox_tx),
        peak_sandbox_rx_bps: peak_sandbox_rx,
        peak_sandbox_tx_bps: peak_sandbox_tx,
        ssh_rx_bytes: int(ssh_rx),
        ssh_tx_bytes: int(ssh_tx),
        ssh_pull_rx_bytes: int(pull_rx),
        ssh_pull_tx_bytes: int(pull_tx),
        peak_ssh_rx_bps: peak_ssh_rx,
        peak_ssh_tx_bps: peak_ssh_tx,
        peak_ssh_pull_rx_bps: peak_pull_rx,
        peak_ssh_pull_tx_bps: peak_pull_tx,
        peak_non_ssh_rx_bps: peak_rest_rx,
        peak_non_ssh_tx_bps: peak_rest_tx,
        dns_queries: int(dns_q),
        dns_failures: int(dns_f),
        dns_cache_hits: int(dns_h),
        connect_count: latency.map(Hist::count),
        connect_timeouts: latency.map(|h| h.timeouts),
        connect_failures: connect.map(|c| c.failures),
        connect_not_found: connect.and_then(|c| c.not_found),
        connect_rejected: connect.map(|c| c.rejected),
        connect_p50_us: latency.and_then(|h| h.quantile(Quantile::P50)),
        connect_p95_us: latency.and_then(|h| h.quantile(Quantile::P95)),
        connect_p99_us: latency.and_then(|h| h.quantile(Quantile::P99)),
        dns_upstream_count: dns_latency.map(|h| h.count()),
        dns_timeouts: dns_latency.map(|h| h.timeouts),
        dns_p50_us: dns_latency.and_then(|h| h.quantile(Quantile::P50)),
        dns_p95_us: dns_latency.and_then(|h| h.quantile(Quantile::P95)),
        dns_p99_us: dns_latency.and_then(|h| h.quantile(Quantile::P99)),
    }
}

/// Collects gap spans, merging a span into a recent one of the same reason it touches or
/// overlaps.
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
            .find(|g| g.reason == reason)
            && from_ms <= g.to_ms
            && to_ms >= g.from_ms
        {
            g.from_ms = g.from_ms.min(from_ms);
            g.to_ms = g.to_ms.max(to_ms);
            return;
        }
        if self.list.len() >= METRICS_MAX_GAPS {
            self.truncated = true;
            return;
        }
        self.list.push(MetricsGap {
            from_ms,
            to_ms,
            reason,
        });
    }
}

fn round3(v: f64) -> f64 {
    (v * 1_000.0).round() / 1_000.0
}

/// Write the combined points into the series' columns and gaps. `instance_level`: the scope
/// has `WireGuard`, DNS and resource measures (not a Gateway).
pub fn fill(out: &mut MetricsSeries, grid: &Grid, points: &[Point], instance_level: bool) {
    use MetricsGapReason::{CounterReset, Unavailable};
    let mut gaps = Gaps::new();
    for (i, p) in points.iter().enumerate() {
        let (from, to) = (grid.start(i), grid.end(i));
        out.timestamps.push(from);
        out.reporting.push(p.reporting);
        out.payload_rx_bps.push(p.payload_rx_bps);
        out.payload_tx_bps.push(p.payload_tx_bps);
        out.wg_rx_bps.push(p.wg_rx_bps);
        out.wg_tx_bps.push(p.wg_tx_bps);
        out.sandbox_rx_bps.push(p.sandbox_rx_bps);
        out.sandbox_tx_bps.push(p.sandbox_tx_bps);
        out.ssh_rx_bps.push(p.ssh_rx_bps);
        out.ssh_tx_bps.push(p.ssh_tx_bps);
        out.ssh_pull_rx_bps.push(p.pull_rx_bps);
        out.ssh_pull_tx_bps.push(p.pull_tx_bps);
        out.active_tcp.push(p.tcp.map(round2));
        out.active_udp.push(p.udp.map(round2));
        out.dns_queries_per_sec.push(p.dns_qps.map(round3));
        out.dns_failures_per_sec.push(p.dns_fps.map(round3));
        out.dns_cache_hit_ratio
            .push(match (p.dns_hits, p.dns_queries) {
                (Some(h), Some(q)) if q > 0.0 => {
                    Some(((h / q).clamp(0.0, 1.0) * 10_000.0).round() / 10_000.0)
                }
                _ => None,
            });
        let c = p.connect.as_ref();
        out.connect_count.push(c.map(|c| c.latency.count()));
        out.connect_timeouts.push(c.map(|c| c.latency.timeouts));
        out.connect_failures.push(c.map(|c| c.failures));
        out.connect_not_found.push(c.and_then(|c| c.not_found));
        out.connect_rejected.push(c.map(|c| c.rejected));
        out.connect_p50_us
            .push(c.and_then(|c| c.latency.quantile(Quantile::P50)));
        out.connect_p95_us
            .push(c.and_then(|c| c.latency.quantile(Quantile::P95)));
        out.connect_p99_us
            .push(c.and_then(|c| c.latency.quantile(Quantile::P99)));
        let d = p.dns_latency.as_ref();
        out.dns_upstream_count.push(d.map(Hist::count));
        out.dns_timeouts.push(d.map(|h| h.timeouts));
        out.dns_p50_us
            .push(d.and_then(|h| h.quantile(Quantile::P50)));
        out.dns_p95_us
            .push(d.and_then(|h| h.quantile(Quantile::P95)));
        out.dns_p99_us
            .push(d.and_then(|h| h.quantile(Quantile::P99)));
        out.cpu_core_pct.push(p.cpu_pct.map(round2));
        out.rss_bytes.push(p.rss.map(f64::round));
        if p.restart {
            out.restarts.push(from);
        }

        if p.payload_rx_bps.is_none() {
            // Covered time without a payload rate: that counter went backwards.
            let reason = p
                .reason
                .or_else(|| (p.covered_ms > 0.0).then_some(CounterReset));
            if let Some(reason) = reason {
                gaps.add(from, to, reason);
            }
        } else if instance_level && p.wg_rx_bps.is_none() {
            gaps.add(from, to, CounterReset);
        }
        if instance_level && p.unavailable {
            gaps.add(from, to, Unavailable);
        }
    }
    gaps.list.sort_by_key(|g| (g.from_ms, g.to_ms));
    out.gaps = gaps.list;
    out.gaps_truncated = gaps.truncated;
}
