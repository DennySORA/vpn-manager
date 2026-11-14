//! Passive analysis: in-memory windows of worker and process samples, and their summary figures.
//!
//! The manager keeps every worker's per-second samples and every process's resource samples, and
//! derives the summary figures from them. It never generates traffic; it only reads what the data
//! path already counts.
//!
//! Each Instance keeps every sample of the last [`TAIL_MS`] (for rates over [`RATE_WINDOW_MS`])
//! and a checkpoint about every [`CHECKPOINT_EVERY_MS`] for [`LATENCY_WINDOW_MS`] (latency
//! quantiles, coverage and counter deltas), so memory stays bounded however many Gateways run.
//! Two samples are continuous only within one generation, with the worker clock advancing by at
//! most `max(5 s, 2.5 × interval)` and no counter going backwards; nothing is computed across a
//! break, and the time it covers is reported as missing.

use std::collections::{BTreeMap, VecDeque};

use vpn_domain::{
    BottleneckHint, ByteObservation, Counter, CriterionBasis, CriterionOp, CriterionUnit,
    FlowSplit, GatewayId, GatewayPerformance, HintKind, HintSeverity, InstanceCapacity, InstanceId,
    InstanceLimits, InstancePerformance, LATENCY_BUCKETS_US, LatencyKind, LatencySummary,
    NumericObservation, ObservationSource, PerformanceCriterion, PerformanceScope,
    PerformanceSummary, Phase, ProcessRole, ProcessUsage, ReferenceWorkSet, RoleUsage,
    SystemPerformance, Text, Timestamp, Verdict, reason, tr,
};

use crate::formula::{self, max_gap_ms};
use crate::histogram::Histogram;

/// Workers report every second.
pub const SAMPLE_INTERVAL_MS: u64 = 1_000;
/// Rates (payload, `WireGuard`, CPU) cover this much of the most recent continuous samples.
pub const RATE_WINDOW_MS: u64 = 5_000;
/// Latency quantiles, coverage and counter deltas cover this window.
pub const LATENCY_WINDOW_MS: u64 = 300_000;
/// Every sample is kept this long.
pub const TAIL_MS: u64 = 15_000;
/// Checkpoints for the latency window are taken this often.
pub const CHECKPOINT_EVERY_MS: i64 = 5_000;
/// Hint thresholds (`PERFORMANCE_MANAGER.md` bottleneck hints; inference only).
pub const FLOW_LIMIT_SHARE: f64 = 0.8;
pub const WORKER_CPU_CORE_PCT: f64 = 90.0;
/// The spec's idle-CPU budget per Instance (percent of one core).
pub const IDLE_CPU_BUDGET_PCT: f64 = 0.5;

/// One Gateway's counters in a worker sample (cumulative within the generation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayPoint {
    pub id: GatewayId,
    pub payload_rx: u64,
    pub payload_tx: u64,
    /// Client TCP connections served, UDP associations' control connections included.
    pub tcp_active: u64,
    pub udp_active: u64,
    pub tcp_rejected: u64,
    pub udp_dropped: u64,
    /// Proxy-connect latency, timeouts included.
    pub connect: Histogram,
    /// Connects through the tunnel that failed (cumulative).
    pub connect_failures: u64,
    /// Of them, the connects whose name had no address (cumulative).
    pub connect_not_found: u64,
}

/// One worker sample as kept in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerPoint {
    /// Manager wall clock when it arrived (its place on the time axis).
    pub at_ms: i64,
    pub generation: u64,
    /// Worker clock: rates use only its differences.
    pub mono_ms: u64,
    pub wg_rx: u64,
    pub wg_tx: u64,
    pub admission_rejected: u64,
    pub underlay_blocked: u64,
    pub memory_reserved: u64,
    pub tunnel_tcp: u64,
    pub tunnel_udp: u64,
    /// Control-class tunnel flows (DNS lookups and health probes), when reported.
    pub control_flows: Option<u64>,
    pub probe_flows: Option<u64>,
    pub connector_flows: Option<u64>,
    pub cpu_ns: Option<u64>,
    pub rss_bytes: Option<u64>,
    /// Upstream DNS resolution latency (cache hits excluded), when the worker reports it.
    pub dns: Option<Histogram>,
    pub gateways: Vec<GatewayPoint>,
    /// The connection's payload that no Gateway relayed `(rx, tx)`, cumulative: what its port
    /// forwards relayed and, in strict mode, the sandbox's Apps' own flows. Part of the
    /// connection's payload, not of any Gateway's; it never leaves the sum within a generation.
    pub apps: (u64, u64),
}

impl WorkerPoint {
    fn gateway(&self, id: GatewayId) -> Option<&GatewayPoint> {
        self.gateways.iter().find(|g| g.id == id)
    }
}

/// Why two samples are not continuous.
const fn link(prev: &WorkerPoint, cur: &WorkerPoint) -> Result<u64, &'static str> {
    if prev.generation != cur.generation {
        return Err(reason::NEW_GENERATION);
    }
    if cur.mono_ms <= prev.mono_ms {
        return Err(reason::COUNTER_RESET);
    }
    let dt = cur.mono_ms - prev.mono_ms;
    if dt > max_gap_ms(SAMPLE_INTERVAL_MS) {
        return Err(reason::LONG_INTERVAL);
    }
    Ok(dt)
}

#[derive(Debug, Clone)]
struct Checkpoint {
    point: WorkerPoint,
    /// Every sample from the previous checkpoint to this one was continuous.
    continuous: bool,
}

/// The in-memory window of one Instance.
#[derive(Debug, Default)]
pub struct InstanceWindow {
    tail: VecDeque<WorkerPoint>,
    /// Why the newest sample does not continue the one before it, if it does not.
    tail_break: Option<&'static str>,
    checkpoints: VecDeque<Checkpoint>,
    since_checkpoint_ok: bool,
}

impl InstanceWindow {
    /// Take a sample. Duplicates and samples older than one already taken are ignored (`false`).
    pub fn push(&mut self, p: WorkerPoint) -> bool {
        let link_result = match self.tail.back() {
            Some(prev) if p.generation < prev.generation => return false,
            Some(prev) if p.generation == prev.generation && p.mono_ms <= prev.mono_ms => {
                return false;
            }
            Some(prev) => link(prev, &p),
            None => Err(reason::INSUFFICIENT_SAMPLES),
        };
        let broke = link_result.is_err();
        self.tail_break = link_result.err();
        if broke {
            // Nothing before this sample continues into it.
            self.tail.clear();
        }
        let due = match self.checkpoints.back() {
            None => true,
            Some(_) if broke => true,
            Some(last) => p.at_ms - last.point.at_ms >= CHECKPOINT_EVERY_MS,
        };
        if due {
            let continuous = !broke && self.since_checkpoint_ok && !self.checkpoints.is_empty();
            self.checkpoints.push_back(Checkpoint {
                point: p.clone(),
                continuous,
            });
            self.since_checkpoint_ok = true;
        }
        self.tail.push_back(p);
        let newest = self.tail.back().map_or(0, |p| p.at_ms);
        while self.tail.len() > 2
            && self
                .tail
                .front()
                .is_some_and(|f| newest - f.at_ms > TAIL_MS.cast_signed())
        {
            self.tail.pop_front();
        }
        // Keep one checkpoint before the window start: the first interval needs its start.
        while self.checkpoints.len() > 2
            && self.checkpoints.get(1).is_some_and(|c| {
                newest - c.point.at_ms > LATENCY_WINDOW_MS.cast_signed() + CHECKPOINT_EVERY_MS
            })
        {
            self.checkpoints.pop_front();
        }
        true
    }

    #[must_use]
    pub fn latest(&self) -> Option<&WorkerPoint> {
        self.tail.back()
    }

    /// Continuous intervals (start, end) ending inside `[from, now]`, oldest first: consecutive
    /// checkpoints, then the last checkpoint to the newest sample.
    fn intervals(&self, from: i64) -> Vec<(&WorkerPoint, &WorkerPoint)> {
        let mut out = Vec::new();
        let mut prev: Option<&Checkpoint> = None;
        for c in &self.checkpoints {
            if let Some(p) = prev
                && c.continuous
                && c.point.at_ms > from
            {
                out.push((&p.point, &c.point));
            }
            prev = Some(c);
        }
        if let (Some(last), Some(newest)) = (self.checkpoints.back(), self.tail.back())
            && newest.at_ms > last.point.at_ms
            && newest.at_ms > from
        {
            // The tail holds every sample since the last checkpoint when it is continuous.
            let tail_from_checkpoint = self
                .tail
                .front()
                .is_some_and(|f| f.at_ms <= last.point.at_ms);
            if tail_from_checkpoint && self.since_checkpoint_ok {
                out.push((&last.point, newest));
            }
        }
        out
    }

    /// The samples of the most recent continuous span of up to [`RATE_WINDOW_MS`] (worker
    /// clock), oldest first, at least two. Rates sum the deltas of every consecutive pair, so a
    /// counter that went backwards anywhere inside the span is caught.
    fn rate_points(&self, now_ms: i64) -> Result<Vec<&WorkerPoint>, &'static str> {
        let newest = self.tail.back().ok_or(reason::NOT_MEASURED)?;
        if now_ms - newest.at_ms > max_gap_ms(SAMPLE_INTERVAL_MS).cast_signed() {
            return Err(reason::LONG_INTERVAL);
        }
        let mut out = vec![newest];
        for p in self.tail.iter().rev().skip(1) {
            out.push(p);
            if newest.mono_ms.saturating_sub(p.mono_ms) >= RATE_WINDOW_MS {
                break;
            }
        }
        if out.len() < 2 {
            return Err(self.tail_break.unwrap_or(reason::INSUFFICIENT_SAMPLES));
        }
        out.reverse();
        Ok(out)
    }
}

/// Sum of a per-pair counter delta over consecutive samples; the first pair that cannot give one
/// (a reset) decides the reason.
fn pairwise(
    points: &[&WorkerPoint],
    f: impl Fn(&WorkerPoint, &WorkerPoint) -> Result<u64, &'static str>,
) -> Result<u64, &'static str> {
    let mut total = 0u64;
    for pair in points.windows(2) {
        total = total.saturating_add(f(pair[0], pair[1])?);
    }
    Ok(total)
}

/// Worker-clock time from the first to the last sample.
const fn elapsed(points: &[&WorkerPoint]) -> u64 {
    match (points.first(), points.last()) {
        (Some(a), Some(b)) => b.mono_ms.saturating_sub(a.mono_ms),
        _ => 0,
    }
}

/// What the analysis needs to know about an Instance besides its samples.
#[derive(Debug, Clone)]
pub struct InstanceMeta {
    pub id: InstanceId,
    pub name: String,
    pub phase: Phase,
    pub generation: Option<u64>,
    pub limits: InstanceLimits,
    /// Buffer memory a new tunnel TCP connection reserves: the opening sizes of the
    /// connection's transport profile.
    pub tcp_flow_bytes: u64,
    pub gateways: Vec<GatewayMeta>,
}

#[derive(Debug, Clone)]
pub struct GatewayMeta {
    pub id: GatewayId,
    pub name: String,
    pub port: u16,
    pub max_connections: u32,
    pub udp: bool,
}

/// The host as the analysis sees it.
#[derive(Debug, Clone, Copy)]
pub struct HostMeta {
    pub logical_cpus: u32,
    /// The spec's reference environment (8 logical CPUs, 16 GiB): only there is the idle-CPU
    /// budget judged.
    pub reference_environment: bool,
}

const CONTROL_FLOWS: u32 = 16;
const CONTROL_MEMORY: u64 = 8 * 1024 * 1024;

/// Proxied TCP connections the limits allow at once when each reserves `flow_bytes`.
///
/// Mirrors `tcpCapacity` of the web UI and the netstack's admission: payload stops short of the
/// share kept for control flows.
#[must_use]
pub fn tcp_capacity(limits: &InstanceLimits, flow_bytes: u64) -> (u32, bool) {
    let budget = u64::from(limits.memory_mib) * 1024 * 1024;
    let reserved_memory = CONTROL_MEMORY.min(budget / 4);
    let reserved_flows = CONTROL_FLOWS.min(limits.max_tcp_flows / 4);
    let by_flows = limits.max_tcp_flows - reserved_flows;
    let by_memory =
        u32::try_from((budget - reserved_memory) / flow_bytes.max(1)).unwrap_or(u32::MAX);
    (by_flows.min(by_memory), by_memory < by_flows)
}

fn ms_ts(ms: i64) -> Timestamp {
    Timestamp::from_unix_millis(ms).unwrap_or_else(Timestamp::now)
}

fn num(r: Result<f64, &str>) -> NumericObservation {
    NumericObservation::from_result(r.map(|v| formula::round(v, 2)), ObservationSource::Derived)
}

fn not_applicable() -> NumericObservation {
    NumericObservation::unknown(reason::NOT_APPLICABLE, ObservationSource::Derived)
}

fn bytes_not_applicable() -> ByteObservation {
    ByteObservation::unknown(reason::NOT_APPLICABLE, ObservationSource::Measurement)
}

/// Window bounds, covered time and the continuous intervals of one Instance.
struct WindowCover<'a> {
    from: i64,
    now: i64,
    covered_ms: u64,
    requested_ms: u64,
    intervals: Vec<(&'a WorkerPoint, &'a WorkerPoint)>,
}

/// The window is always the whole window: before the manager collected for that long, the time
/// before it is missing, not assumed idle.
fn cover(w: &InstanceWindow, now_ms: i64) -> WindowCover<'_> {
    let from = now_ms - LATENCY_WINDOW_MS.cast_signed();
    let intervals = w.intervals(from);
    let covered: i64 = intervals
        .iter()
        .map(|(a, b)| (b.at_ms.min(now_ms) - a.at_ms.max(from)).max(0))
        .sum();
    WindowCover {
        from,
        now: now_ms,
        covered_ms: covered.max(0).cast_unsigned(),
        requested_ms: LATENCY_WINDOW_MS,
        intervals,
    }
}

/// Counter delta summed over continuous intervals; `None` without any.
fn sum_deltas(
    intervals: &[(&WorkerPoint, &WorkerPoint)],
    f: impl Fn(&WorkerPoint) -> Option<u64>,
) -> Option<u64> {
    let mut total: Option<u64> = None;
    for (a, b) in intervals {
        if let (Some(x), Some(y)) = (f(a), f(b))
            && let Some(d) = formula::delta(y, x)
        {
            total = Some(total.unwrap_or(0).saturating_add(d));
        }
    }
    total
}

fn latency_over(
    intervals: &[(&WorkerPoint, &WorkerPoint)],
    gateways: &[GatewayId],
) -> Option<Histogram> {
    let mut merged: Option<Histogram> = None;
    for (a, b) in intervals {
        for id in gateways {
            let (Some(ga), Some(gb)) = (a.gateway(*id), b.gateway(*id)) else {
                continue;
            };
            if let Some(d) = gb.connect.delta(&ga.connect) {
                match merged.as_mut() {
                    Some(m) => m.merge(&d),
                    None => merged = Some(d),
                }
            }
        }
    }
    merged
}

/// DNS resolution latency over the window's intervals (`None`: not reported).
fn dns_over(intervals: &[(&WorkerPoint, &WorkerPoint)]) -> Option<Histogram> {
    let mut merged: Option<Histogram> = None;
    let mut reported = false;
    for (a, b) in intervals {
        let (Some(da), Some(db)) = (&a.dns, &b.dns) else {
            continue;
        };
        reported = true;
        if let Some(d) = db.delta(da) {
            match merged.as_mut() {
                Some(m) => m.merge(&d),
                None => merged = Some(d),
            }
        }
    }
    if reported {
        Some(merged.unwrap_or_else(|| Histogram::empty(&LATENCY_BUCKETS_US)))
    } else {
        None
    }
}

/// Payload bytes (rx, tx) between two consecutive samples, of one Gateway or of the whole
/// connection (its Gateways and its Apps' part: port forwards and a strict sandbox's Apps).
fn payload_pair(
    o: &WorkerPoint,
    n: &WorkerPoint,
    only: Option<GatewayId>,
) -> Result<(u64, u64), &'static str> {
    // A Gateway that left the sample takes its bytes with it: the sum is not comparable.
    if only.is_none() && o.gateways.iter().any(|g| n.gateway(g.id).is_none()) {
        return Err(reason::COUNTER_RESET);
    }
    let mut rx = 0u64;
    let mut tx = 0u64;
    let mut any = false;
    for g in &n.gateways {
        if only.is_some_and(|id| id != g.id) {
            continue;
        }
        any = true;
        // A Gateway added between the two samples started its counters at zero.
        let (prx, ptx) = o
            .gateway(g.id)
            .map_or((0, 0), |p| (p.payload_rx, p.payload_tx));
        rx = rx.saturating_add(formula::delta(g.payload_rx, prx).ok_or(reason::COUNTER_RESET)?);
        tx = tx.saturating_add(formula::delta(g.payload_tx, ptx).ok_or(reason::COUNTER_RESET)?);
    }
    if !any && only.is_some() {
        return Err(reason::NOT_MEASURED);
    }
    if only.is_none() {
        let ((orx, otx), (nrx, ntx)) = (o.apps, n.apps);
        rx = rx.saturating_add(formula::delta(nrx, orx).ok_or(reason::COUNTER_RESET)?);
        tx = tx.saturating_add(formula::delta(ntx, otx).ok_or(reason::COUNTER_RESET)?);
    }
    Ok((rx, tx))
}

/// (upload, download) bit/s over the span: upload = client → destination (tx).
fn payload_rates(
    points: &[&WorkerPoint],
    only: Option<GatewayId>,
) -> Result<(f64, f64), &'static str> {
    let rx = pairwise(points, |o, n| payload_pair(o, n, only).map(|(rx, _)| rx))?;
    let tx = pairwise(points, |o, n| payload_pair(o, n, only).map(|(_, tx)| tx))?;
    let dt = elapsed(points);
    Ok((
        formula::rate_bps(tx, dt).ok_or(reason::INSUFFICIENT_SAMPLES)?,
        formula::rate_bps(rx, dt).ok_or(reason::INSUFFICIENT_SAMPLES)?,
    ))
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "flow counts stay below the Instance's u32 flow limits; kept as the worker reports them"
)]
fn flows_of(p: &WorkerPoint, only: Option<GatewayId>) -> (u32, FlowSplit) {
    let mut tcp = 0u64;
    let mut udp = 0u64;
    for g in p
        .gateways
        .iter()
        .filter(|g| only.is_none_or(|id| id == g.id))
    {
        // Each UDP association holds one client TCP control connection.
        tcp += g.tcp_active.saturating_sub(g.udp_active);
        udp += g.udp_active;
    }
    let total = tcp + udp;
    (
        total as u32,
        FlowSplit {
            tcp: Some(tcp as u32),
            udp: Some(udp as u32),
        },
    )
}

/// Payload upload and download rates over a span, of one Gateway (`only`) or the whole worker.
fn payload_observations(
    span: Result<&[&WorkerPoint], &'static str>,
    only: Option<GatewayId>,
) -> (NumericObservation, NumericObservation) {
    match span.and_then(|pts| payload_rates(pts, only)) {
        Ok((up, down)) => (num(Ok(up)), num(Ok(down))),
        Err(r) => (num(Err(r)), num(Err(r))),
    }
}

/// The rate in bits per second of a byte counter over a continuous span of samples.
fn counter_rate(
    pts: &[&WorkerPoint],
    counter: fn(&WorkerPoint) -> u64,
) -> Result<f64, &'static str> {
    let bytes = pairwise(pts, |old, new| {
        formula::delta(counter(new), counter(old)).ok_or(reason::COUNTER_RESET)
    })?;
    formula::rate_bps(bytes, elapsed(pts)).ok_or(reason::INSUFFICIENT_SAMPLES)
}

/// The DNS resolution latency over the window; without any, the reason it is unknown.
fn dns_summary(
    cover: &WindowCover<'_>,
    coverage_ratio: f64,
    not_running: &impl Fn(&'static str) -> &'static str,
) -> LatencySummary {
    dns_over(&cover.intervals).map_or_else(
        || {
            let mut summary = Histogram::empty(&LATENCY_BUCKETS_US)
                .summary(LatencyKind::DnsResolution, coverage_ratio);
            summary.reason_code = Some(not_running(reason::NOT_REPORTED).into());
            summary
        },
        |h| h.summary(LatencyKind::DnsResolution, coverage_ratio),
    )
}

/// An Instance's configured limits, the TCP capacity they give and the memory reserved last.
fn instance_capacity(meta: &InstanceMeta, latest: Option<&WorkerPoint>) -> InstanceCapacity {
    let (capacity, by_memory) = tcp_capacity(&meta.limits, meta.tcp_flow_bytes);
    InstanceCapacity {
        max_tcp_flows: meta.limits.max_tcp_flows,
        max_udp_flows: meta.limits.max_udp_flows,
        memory_mib: meta.limits.memory_mib,
        tcp_flow_bytes: Counter(meta.tcp_flow_bytes),
        tcp_capacity: capacity,
        tcp_capacity_by_memory: by_memory,
        memory_reserved_bytes: latest.map(|p| Counter(p.memory_reserved)),
    }
}

/// CPU of a worker over a continuous span of its samples, percent of one core.
fn worker_cpu_pct(pts: &[&WorkerPoint]) -> Result<f64, &'static str> {
    let used = pairwise(pts, |old, new| {
        let (now, before) = (
            new.cpu_ns.ok_or(reason::NOT_REPORTED)?,
            old.cpu_ns.ok_or(reason::NOT_REPORTED)?,
        );
        formula::delta(now, before).ok_or(reason::COUNTER_RESET)
    })?;
    formula::cpu_core_pct(used, elapsed(pts)).ok_or(reason::INSUFFICIENT_SAMPLES)
}

/// The latest RSS of a worker and the highest one sampled over the window.
fn rss_observations(
    cover: &WindowCover<'_>,
    latest: Option<&WorkerPoint>,
    not_running: &impl Fn(&'static str) -> &'static str,
) -> (ByteObservation, ByteObservation) {
    let rss = latest.map_or_else(
        || {
            ByteObservation::unknown(
                not_running(reason::NOT_MEASURED),
                ObservationSource::Measurement,
            )
        },
        |p| {
            ByteObservation::from_result(
                p.rss_bytes.ok_or(reason::NOT_REPORTED),
                ObservationSource::Measurement,
            )
        },
    );
    let peak = cover
        .intervals
        .iter()
        .flat_map(|(old, new)| [old.rss_bytes, new.rss_bytes])
        .chain(latest.map(|p| p.rss_bytes))
        .flatten()
        .max();
    let peak = ByteObservation::from_result(
        peak.ok_or_else(|| not_running(reason::NOT_MEASURED)),
        ObservationSource::Measurement,
    );
    (rss, peak)
}

/// The probe flows and the control flows (without the probes, with the connectors) a worker
/// reported last.
#[expect(
    clippy::cast_possible_truncation,
    reason = "flow counts stay below the Instance's u32 flow limits; kept as the worker reports them"
)]
fn probe_and_control_flows(latest: Option<&WorkerPoint>) -> (Option<u32>, Option<u32>) {
    let probe = latest.and_then(|p| p.probe_flows).map(|v| v as u32);
    let control = latest.and_then(|p| {
        let control = p.control_flows?;
        let probes = p.probe_flows.unwrap_or(0);
        Some((control.saturating_sub(probes) + p.connector_flows.unwrap_or(0)) as u32)
    });
    (probe, control)
}

/// Analyze one Instance. `window` is `None` for an Instance never sampled since the manager
/// started.
pub fn analyze_instance(
    meta: &InstanceMeta,
    window: Option<&InstanceWindow>,
    host: HostMeta,
    now_ms: i64,
) -> InstancePerformance {
    let empty = InstanceWindow::default();
    let w = window.unwrap_or(&empty);
    let running = meta.generation.is_some();
    // Samples of another generation than the one running now are history, not "now".
    let latest = w
        .latest()
        .filter(|p| Some(p.generation) == meta.generation)
        .filter(|p| now_ms - p.at_ms <= max_gap_ms(SAMPLE_INTERVAL_MS).cast_signed());
    let c = cover(w, now_ms);
    let (coverage_ratio, missing) = formula::coverage(c.covered_ms, c.requested_ms);
    let not_running = |r: &'static str| {
        if running {
            r
        } else {
            reason::INSTANCE_NOT_RUNNING
        }
    };

    let span: Result<Vec<&WorkerPoint>, &'static str> = w
        .rate_points(now_ms)
        .and_then(|points| {
            if points.last().map(|n| n.generation) == meta.generation {
                Ok(points)
            } else {
                Err(reason::NEW_GENERATION)
            }
        })
        .map_err(not_running);
    let span = span.as_deref().map_err(|r| *r);
    let (payload_up, payload_down) = payload_observations(span, None);
    let wg =
        |counter: fn(&WorkerPoint) -> u64| num(span.and_then(|pts| counter_rate(pts, counter)));
    let cpu = span.and_then(worker_cpu_pct);
    let (rss, peak) = rss_observations(&c, latest, &not_running);

    let gateway_ids: Vec<GatewayId> = meta.gateways.iter().map(|g| g.id).collect();
    let latency = latency_over(&c.intervals, &gateway_ids)
        .unwrap_or_else(|| Histogram::empty(&LATENCY_BUCKETS_US))
        .summary(LatencyKind::ProxyConnect, coverage_ratio);
    let dns = dns_summary(&c, coverage_ratio, &not_running);

    let (data, split) = latest.map_or(
        (
            None,
            FlowSplit {
                tcp: None,
                udp: None,
            },
        ),
        |p| {
            let (total, split) = flows_of(p, None);
            (Some(total), split)
        },
    );
    let (probe, control) = probe_and_control_flows(latest);

    let summary = PerformanceSummary {
        scope: PerformanceScope::instance(meta.id),
        observed_at: ms_ts(now_ms),
        window_start: ms_ts(c.from),
        window_end: ms_ts(c.now),
        coverage_ratio,
        missing_duration_ms: Counter(missing),
        active_data_flows: data,
        active_probe_flows: probe,
        active_control_flows: control,
        latencies: vec![latency, dns],
        reason_code: (!running).then(|| reason::INSTANCE_NOT_RUNNING.to_string()),
        payload_upload_bps: payload_up,
        payload_download_bps: payload_down,
        wireguard_tx_bps: wg(|p| p.wg_tx),
        wireguard_rx_bps: wg(|p| p.wg_rx),
        cpu_core_pct: num(cpu),
        cpu_host_pct: num(cpu
            .and_then(|c| formula::cpu_host_pct(c, host.logical_cpus).ok_or(reason::NOT_REPORTED))),
        rss_bytes: rss,
        sampled_peak_rss_bytes: peak,
    };

    let gateways = meta
        .gateways
        .iter()
        .map(|g| analyze_gateway(meta, g, &c, coverage_ratio, missing, latest, span, now_ms))
        .collect();

    let idle_cpu = idle_cpu_criterion(host, data, summary.cpu_core_pct.value);
    InstancePerformance {
        instance_id: meta.id,
        name: meta.name.clone(),
        phase: meta.phase,
        generation: meta.generation,
        data_flows: split,
        admission_rejected: sum_deltas(&c.intervals, |p| Some(p.admission_rejected)).map(Counter),
        underlay_blocked: sum_deltas(&c.intervals, |p| Some(p.underlay_blocked)).map(Counter),
        capacity: instance_capacity(meta, latest),
        gateways,
        idle_cpu,
        summary,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the parts of one Instance analysis a Gateway's figures are cut from"
)]
fn analyze_gateway(
    meta: &InstanceMeta,
    g: &GatewayMeta,
    cover: &WindowCover<'_>,
    coverage_ratio: f64,
    missing: u64,
    latest: Option<&WorkerPoint>,
    span: Result<&[&WorkerPoint], &'static str>,
    now_ms: i64,
) -> GatewayPerformance {
    let running = meta.generation.is_some();
    let in_latest = latest.and_then(|p| p.gateway(g.id));
    let (up, down) = payload_observations(span, Some(g.id));
    let latency = latency_over(&cover.intervals, &[g.id])
        .unwrap_or_else(|| Histogram::empty(&LATENCY_BUCKETS_US))
        .summary(LatencyKind::ProxyConnect, coverage_ratio);
    let (data, split) = match (latest, in_latest) {
        (Some(p), Some(_)) => {
            let (total, split) = flows_of(p, Some(g.id));
            (Some(total), split)
        }
        _ => (
            None,
            FlowSplit {
                tcp: None,
                udp: None,
            },
        ),
    };
    let gw = |f: fn(&GatewayPoint) -> u64| {
        sum_deltas(&cover.intervals, |p| p.gateway(g.id).map(f)).map(Counter)
    };
    GatewayPerformance {
        gateway_id: g.id,
        name: g.name.clone(),
        port: g.port,
        max_connections: g.max_connections,
        udp: g.udp,
        summary: PerformanceSummary {
            scope: PerformanceScope::gateway(g.id),
            observed_at: ms_ts(now_ms),
            window_start: ms_ts(cover.from),
            window_end: ms_ts(cover.now),
            coverage_ratio,
            missing_duration_ms: Counter(missing),
            active_data_flows: data,
            // Probes and control flows belong to the Instance, not to one proxy port.
            active_probe_flows: None,
            active_control_flows: None,
            latencies: vec![latency],
            reason_code: if !running {
                Some(reason::INSTANCE_NOT_RUNNING.into())
            } else if in_latest.is_none() {
                Some(reason::NOT_MEASURED.into())
            } else {
                None
            },
            payload_upload_bps: up,
            payload_download_bps: down,
            wireguard_tx_bps: not_applicable(),
            wireguard_rx_bps: not_applicable(),
            cpu_core_pct: not_applicable(),
            cpu_host_pct: not_applicable(),
            rss_bytes: bytes_not_applicable(),
            sampled_peak_rss_bytes: bytes_not_applicable(),
        },
        data_flows: split,
        admission_rejected: gw(|p| p.tcp_rejected),
        udp_dropped: gw(|p| p.udp_dropped),
        connect_timeouts: gw(|p| p.connect.timeouts),
        connect_failures: gw(|p| p.connect_failures),
        connect_not_found: gw(|p| p.connect_not_found),
    }
}

/// The spec's idle-CPU target (< 0.5 % of one core per Instance, no data flows), judged only in
/// its reference environment; anywhere else it is shown as a target, `not_evaluated`.
fn idle_cpu_criterion(
    host: HostMeta,
    data_flows: Option<u32>,
    cpu_core_pct: Option<f64>,
) -> PerformanceCriterion {
    let idle = data_flows == Some(0);
    let (verdict, reason_code) = match (cpu_core_pct, idle) {
        (None, _) => (Verdict::NotEvaluated, Some(reason::NOT_MEASURED)),
        (Some(_), false) => (Verdict::NotEvaluated, Some(reason::NOT_IDLE)),
        (Some(_), true) if !host.reference_environment => (
            Verdict::NotEvaluated,
            Some(reason::NOT_REFERENCE_ENVIRONMENT),
        ),
        (Some(v), true) if v < IDLE_CPU_BUDGET_PCT => (Verdict::Pass, None),
        (Some(_), true) => (Verdict::Fail, None),
    };
    PerformanceCriterion {
        metric: "idle_cpu_core_pct".into(),
        unit: CriterionUnit::Percent,
        op: CriterionOp::Lt,
        target: IDLE_CPU_BUDGET_PCT,
        observed: if idle { cpu_core_pct } else { None },
        verdict,
        basis: CriterionBasis::ProposedBudget,
        reason_code: reason_code.map(Into::into),
    }
}

/// Bottleneck readings (推論) of the analyzed Instances. Each is labelled `inference`: a hint
/// reads the numbers, it is not a measured cause.
#[must_use]
pub fn hints(instances: &[InstancePerformance]) -> Vec<BottleneckHint> {
    let mut out = Vec::new();
    let mut push = |kind, scope, severity, observed: f64, threshold: f64, unit, message: Text| {
        out.push(BottleneckHint {
            kind,
            scope,
            severity,
            basis: "inference".into(),
            observed: formula::round(observed, 2),
            threshold,
            unit,
            message,
        });
    };
    for i in instances {
        instance_hints(i, &mut push);
        for g in &i.gateways {
            gateway_hints(g, &mut push);
        }
    }
    out
}

/// Adds one hint: kind, scope, severity, observed value, threshold, unit and message.
type PushHint<'a> =
    dyn FnMut(HintKind, PerformanceScope, HintSeverity, f64, f64, CriterionUnit, Text) + 'a;

/// The hints of one Instance as a whole (its Gateways have their own).
#[expect(
    clippy::cast_precision_loss,
    reason = "event counts shown as a hint's observed value; f64 is exact far beyond real counts"
)]
fn instance_hints(i: &InstancePerformance, push: &mut PushHint<'_>) {
    let scope = PerformanceScope::instance(i.instance_id);
    let name = &i.name;
    if let Some(data) = i.summary.active_data_flows
        && i.capacity.tcp_capacity > 0
    {
        let share = f64::from(data) / f64::from(i.capacity.tcp_capacity);
        let pct = share * 100.0;
        if share >= FLOW_LIMIT_SHARE {
            if i.capacity.tcp_capacity_by_memory {
                let mib = i.capacity.memory_mib;
                push(
                    HintKind::MemoryBudget,
                    scope.clone(),
                    HintSeverity::Warning,
                    pct,
                    FLOW_LIMIT_SHARE * 100.0,
                    CriterionUnit::Percent,
                    tr!(
                        "“{name}” has reached {pct:.0}% of its TCP capacity; the limit comes from the connection buffer budget ({mib} MiB), not from the connection limit",
                        "「{name}」的連線數已達 TCP 容量的 {pct:.0}%，限制來自連線緩衝預算（{mib} MiB），不是連線數上限",
                        "「{name}」の接続数が TCP 容量の {pct:.0}% に達しています。制限は接続数の上限ではなく、接続バッファーの予算（{mib} MiB）によるものです"
                    ),
                );
            } else {
                push(
                    HintKind::FlowLimit,
                    scope.clone(),
                    HintSeverity::Warning,
                    pct,
                    FLOW_LIMIT_SHARE * 100.0,
                    CriterionUnit::Percent,
                    tr!(
                        "“{name}” has reached {pct:.0}% of its TCP connection limit",
                        "「{name}」的連線數已達 TCP 連線上限的 {pct:.0}%",
                        "「{name}」の接続数が TCP 接続数の上限の {pct:.0}% に達しています"
                    ),
                );
            }
        }
    }
    if let Some(cpu) = i.summary.cpu_core_pct.value
        && cpu >= WORKER_CPU_CORE_PCT
    {
        push(
            HintKind::WorkerCpu,
            scope.clone(),
            HintSeverity::Warning,
            cpu,
            WORKER_CPU_CORE_PCT,
            CriterionUnit::Percent,
            tr!(
                "The worker of “{name}” uses {cpu:.0}% of one CPU core, which may be what limits the rate",
                "「{name}」的 worker 用了一個 CPU 核心的 {cpu:.0}%，可能是速率的瓶頸",
                "「{name}」の worker が CPU コア 1 つの {cpu:.0}% を使っています。速度のボトルネックになっている可能性があります"
            ),
        );
    }
    if let Some(n) = i.admission_rejected.filter(|n| n.0 > 0) {
        let n = n.0;
        push(
            HintKind::AdmissionRejections,
            scope.clone(),
            HintSeverity::Warning,
            n as f64,
            0.0,
            CriterionUnit::Count,
            tr!(
                "New connections “{name}” refused in the last 5 minutes (limit or gate): {n}",
                "「{name}」在最近 5 分鐘拒絕了 {n} 次新連線（上限或閘門）",
                "「{name}」は直近 5 分間に新しい接続を {n} 回拒否しました（上限またはゲート）"
            ),
        );
    }
    if let Some(n) = i.underlay_blocked.filter(|n| n.0 > 0) {
        let n = n.0;
        push(
            HintKind::UnderlayBlocked,
            scope,
            HintSeverity::Info,
            n as f64,
            0.0,
            CriterionUnit::Count,
            tr!(
                "Packets the WireGuard endpoint of “{name}” blocked because they did not come from the configured peer: {n}",
                "「{name}」的 WireGuard 端點擋下了 {n} 個不是來自設定對端的封包",
                "「{name}」の WireGuard エンドポイントが、設定されたピア以外からのパケットを {n} 個ブロックしました"
            ),
        );
    }
}

/// The hints of one Gateway (proxy port).
#[expect(
    clippy::cast_precision_loss,
    reason = "event counts shown as a hint's observed value; f64 is exact far beyond real counts"
)]
fn gateway_hints(g: &GatewayPerformance, push: &mut PushHint<'_>) {
    let gscope = PerformanceScope::gateway(g.gateway_id);
    let port = g.port;
    if let Some(data) = g.summary.active_data_flows
        && g.max_connections > 0
    {
        let share = f64::from(data) / f64::from(g.max_connections);
        if share >= FLOW_LIMIT_SHARE {
            let (max, pct) = (g.max_connections, share * 100.0);
            push(
                HintKind::FlowLimit,
                gscope.clone(),
                HintSeverity::Warning,
                pct,
                FLOW_LIMIT_SHARE * 100.0,
                CriterionUnit::Percent,
                tr!(
                    "Gateway :{port} has reached {pct:.0}% of its limit of {max} connections",
                    "代理埠 :{port} 的連線數已達上限 {max} 的 {pct:.0}%",
                    "ゲートウェイ :{port} の接続数が上限 {max} の {pct:.0}% に達しています"
                ),
            );
        }
    }
    if let Some(n) = g.admission_rejected.filter(|n| n.0 > 0) {
        let n = n.0;
        push(
            HintKind::AdmissionRejections,
            gscope.clone(),
            HintSeverity::Warning,
            n as f64,
            0.0,
            CriterionUnit::Count,
            tr!(
                "Connections Gateway :{port} refused in the last 5 minutes: {n}",
                "代理埠 :{port} 在最近 5 分鐘拒絕了 {n} 個連線",
                "ゲートウェイ :{port} は直近 5 分間に {n} 件の接続を拒否しました"
            ),
        );
    }
    if let Some(n) = g.connect_timeouts.filter(|n| n.0 > 0) {
        let n = n.0;
        push(
            HintKind::ConnectTimeouts,
            gscope.clone(),
            HintSeverity::Warning,
            n as f64,
            0.0,
            CriterionUnit::Count,
            tr!(
                "Connections through the tunnel that timed out at Gateway :{port} in the last 5 minutes: {n}",
                "代理埠 :{port} 在最近 5 分鐘有 {n} 次經 tunnel 連線逾時",
                "ゲートウェイ :{port} では直近 5 分間にトンネル経由の接続が {n} 回タイムアウトしました"
            ),
        );
    }
    // A name that does not exist is not a network fault: it is read apart from the other
    // failures it is counted among.
    let not_found = g.connect_not_found.map_or(0, |n| n.0);
    let failed = g
        .connect_failures
        .map_or(0, |n| n.0)
        .saturating_sub(not_found);
    if failed > 0 {
        push(
            HintKind::ConnectFailures,
            gscope.clone(),
            HintSeverity::Info,
            failed as f64,
            0.0,
            CriterionUnit::Count,
            tr!(
                "Connections through the tunnel that failed at Gateway :{port} in the last 5 minutes (refused by the destination or unreachable): {failed}",
                "代理埠 :{port} 在最近 5 分鐘有 {failed} 次經 tunnel 連線失敗（目的地拒絕或無法到達）",
                "ゲートウェイ :{port} では直近 5 分間にトンネル経由の接続が {failed} 回失敗しました（宛先が拒否したか、到達できません）"
            ),
        );
    }
    if not_found > 0 {
        push(
            HintKind::ConnectNotFound,
            gscope,
            HintSeverity::Info,
            not_found as f64,
            0.0,
            CriterionUnit::Count,
            tr!(
                "Names that did not exist at Gateway :{port} in the last 5 minutes: {not_found} (DNS has no such name; common for ad or tracking domains blocked by DNS, and for names valid only on the local network)",
                "代理埠 :{port} 在最近 5 分鐘有 {not_found} 次名稱不存在（DNS 沒有這個名稱，常見於被 DNS 封鎖的廣告／追蹤網域或只在區域網路有效的名稱）",
                "ゲートウェイ :{port} では直近 5 分間に、存在しない名前が {not_found} 回ありました（DNS にその名前がありません。DNS でブロックされた広告・トラッキングのドメインや、LAN 内でだけ有効な名前によくあります）"
            ),
        );
    }
}

/// What existed against the 5/10/500 reference work set.
#[must_use]
pub fn reference(instances: &[InstancePerformance]) -> ReferenceWorkSet {
    let ready: Vec<&InstancePerformance> = instances
        .iter()
        .filter(|i| i.phase == Phase::Ready)
        .collect();
    let serving = |i: &InstancePerformance| {
        let serving = i
            .gateways
            .iter()
            .filter(|g| g.summary.active_data_flows.is_some())
            .count();
        u32::try_from(serving).unwrap_or(u32::MAX)
    };
    let data: Option<u32> = ready
        .iter()
        .map(|i| i.summary.active_data_flows)
        .try_fold(0u32, |acc, v| v.map(|v| acc + v));
    ReferenceWorkSet {
        instances: 5,
        gateways: 10,
        data_flows: 500,
        gateways_per_instance: 2,
        flows_per_gateway: 50,
        ready_instances: u32::try_from(ready.len()).unwrap_or(u32::MAX),
        serving_gateways: ready.iter().map(|i| serving(i)).sum(),
        active_data_flows: if ready.is_empty() { None } else { data },
        eligible_instances: u32::try_from(ready.iter().filter(|i| serving(i) >= 2).count())
            .unwrap_or(u32::MAX),
    }
}

// ---------------------------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------------------------

/// One resource observation of one process, taken at a sampler tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessPoint {
    pub at_ms: i64,
    /// The process's own monotonic clock (or the sampler's, for processes sampled by pid).
    pub mono_ms: u64,
    pub cpu_ns: Option<u64>,
    pub rss_bytes: Option<u64>,
    pub fd_count: Option<u32>,
}

/// The in-memory window of one process identity.
#[derive(Debug, Clone)]
pub struct ProcessWindow {
    pub role: ProcessRole,
    pub identity: String,
    pub pid: u32,
    pub started_unix_us: Option<u64>,
    pub instance_id: Option<InstanceId>,
    pub generation: Option<u64>,
    pub points: VecDeque<ProcessPoint>,
}

impl ProcessWindow {
    #[must_use]
    pub const fn new(
        role: ProcessRole,
        identity: String,
        pid: u32,
        started_unix_us: Option<u64>,
        instance_id: Option<InstanceId>,
        generation: Option<u64>,
    ) -> Self {
        Self {
            role,
            identity,
            pid,
            started_unix_us,
            instance_id,
            generation,
            points: VecDeque::new(),
        }
    }

    /// Add a point; out-of-order points are ignored. Keeps the latency window.
    pub fn push(&mut self, p: ProcessPoint) {
        if self.points.back().is_some_and(|b| p.mono_ms <= b.mono_ms) {
            return;
        }
        self.points.push_back(p);
        while self
            .points
            .front()
            .is_some_and(|f| p.at_ms - f.at_ms > LATENCY_WINDOW_MS.cast_signed())
        {
            self.points.pop_front();
        }
    }

    #[must_use]
    pub fn latest(&self) -> Option<&ProcessPoint> {
        self.points.back()
    }

    /// CPU over the most recent continuous span of up to [`RATE_WINDOW_MS`].
    ///
    /// # Errors
    ///
    /// The reason code of an unknown value: no sample (`NOT_MEASURED`), a latest sample too old
    /// (`LONG_INTERVAL`), no earlier sample in the span (`INSUFFICIENT_SAMPLES`), a sample without
    /// CPU time (`NOT_REPORTED`) or a CPU counter that went backwards (`COUNTER_RESET`).
    pub fn cpu_core_pct(&self, now_ms: i64, interval_ms: u64) -> Result<f64, &'static str> {
        let newest = self.points.back().ok_or(reason::NOT_MEASURED)?;
        if now_ms - newest.at_ms > max_gap_ms(interval_ms).cast_signed() {
            return Err(reason::LONG_INTERVAL);
        }
        let mut oldest: Option<&ProcessPoint> = None;
        let mut next = newest;
        for p in self.points.iter().rev().skip(1) {
            if next.mono_ms.saturating_sub(p.mono_ms) > max_gap_ms(interval_ms) {
                break;
            }
            oldest = Some(p);
            next = p;
            if newest.mono_ms.saturating_sub(p.mono_ms) >= RATE_WINDOW_MS {
                break;
            }
        }
        let oldest = oldest.ok_or(reason::INSUFFICIENT_SAMPLES)?;
        let (now, before) = (
            newest.cpu_ns.ok_or(reason::NOT_REPORTED)?,
            oldest.cpu_ns.ok_or(reason::NOT_REPORTED)?,
        );
        let used = formula::delta(now, before).ok_or(reason::COUNTER_RESET)?;
        formula::cpu_core_pct(used, newest.mono_ms - oldest.mono_ms)
            .ok_or(reason::INSUFFICIENT_SAMPLES)
    }
}

/// Usage of a set of processes: summed CPU of those that have a value (a caveat when some do
/// not), summed latest RSS, and the largest such sum over the window's sampler ticks.
fn role_usage(
    role: Option<ProcessRole>,
    windows: &[&ProcessWindow],
    now_ms: i64,
    interval_ms: u64,
    logical_cpus: u32,
) -> RoleUsage {
    let fresh: Vec<&&ProcessWindow> = windows
        .iter()
        .filter(|w| {
            w.latest()
                .is_some_and(|p| now_ms - p.at_ms <= max_gap_ms(interval_ms).cast_signed())
        })
        .collect();
    let cpus: Vec<Result<f64, &str>> = fresh
        .iter()
        .map(|w| w.cpu_core_pct(now_ms, interval_ms))
        .collect();
    let known: Vec<f64> = cpus
        .iter()
        .filter_map(|r| r.as_ref().ok().copied())
        .collect();
    let cpu = if known.is_empty() {
        NumericObservation::unknown(
            cpus.iter()
                .find_map(|r| r.as_ref().err().copied())
                .unwrap_or(reason::NOT_MEASURED),
            ObservationSource::Derived,
        )
    } else {
        let sum: f64 = known.iter().sum();
        NumericObservation {
            value: Some(formula::round(sum, 2)),
            reason_code: (known.len() < cpus.len()).then(|| "PARTIAL".to_string()),
            source: ObservationSource::Derived,
        }
    };
    let host = NumericObservation {
        value: cpu
            .value
            .and_then(|v| formula::cpu_host_pct(v, logical_cpus))
            .map(|v| formula::round(v, 2)),
        reason_code: cpu.reason_code.clone(),
        source: ObservationSource::Derived,
    };
    let rss_known: Vec<u64> = fresh
        .iter()
        .filter_map(|w| w.latest().and_then(|p| p.rss_bytes))
        .collect();
    let rss = if rss_known.is_empty() {
        ByteObservation::unknown(reason::NOT_MEASURED, ObservationSource::Measurement)
    } else {
        ByteObservation {
            value: Some(Counter(rss_known.iter().sum())),
            reason_code: (rss_known.len() < fresh.len()).then(|| "PARTIAL".to_string()),
            source: ObservationSource::Measurement,
        }
    };
    // Sum per sampler tick (all processes are sampled at the same ticks), then the peak.
    let mut per_tick: BTreeMap<i64, u64> = BTreeMap::new();
    for w in windows {
        for p in &w.points {
            if let Some(r) = p.rss_bytes {
                *per_tick.entry(p.at_ms).or_default() += r;
            }
        }
    }
    let peak = per_tick.values().copied().max();
    RoleUsage {
        role,
        processes: u32::try_from(fresh.len()).unwrap_or(u32::MAX),
        cpu_core_pct: cpu,
        cpu_host_pct: host,
        rss_bytes: rss,
        sampled_peak_rss_bytes: ByteObservation::from_result(
            peak.ok_or(reason::NOT_MEASURED),
            ObservationSource::Measurement,
        ),
    }
}

/// The system part of the summary from the process windows.
#[must_use]
pub fn analyze_processes(
    windows: &[ProcessWindow],
    now_ms: i64,
    interval_ms: u64,
    logical_cpus: u32,
    host_boot_id: Option<String>,
) -> SystemPerformance {
    let all: Vec<&ProcessWindow> = windows.iter().collect();
    let roles = ProcessRole::ALL
        .into_iter()
        .map(|role| {
            let ws: Vec<&ProcessWindow> = all.iter().copied().filter(|w| w.role == role).collect();
            role_usage(Some(role), &ws, now_ms, interval_ms, logical_cpus)
        })
        .collect();
    let mut processes: Vec<ProcessUsage> = all
        .iter()
        .filter(|w| {
            w.latest()
                .is_some_and(|p| now_ms - p.at_ms <= max_gap_ms(interval_ms).cast_signed())
        })
        .map(|w| {
            let latest = w.latest();
            ProcessUsage {
                role: w.role,
                process_identity: w.identity.clone(),
                pid: w.pid,
                started_at: w
                    .started_unix_us
                    .and_then(|us| Timestamp::from_unix_millis((us / 1_000).cast_signed())),
                instance_id: w.instance_id,
                generation: w.generation,
                cpu_core_pct: num(w.cpu_core_pct(now_ms, interval_ms)),
                rss_bytes: ByteObservation::from_result(
                    latest.and_then(|p| p.rss_bytes).ok_or(reason::NOT_REPORTED),
                    ObservationSource::Measurement,
                ),
                fd_count: latest.and_then(|p| p.fd_count),
                observed_at: latest.and_then(|p| Timestamp::from_unix_millis(p.at_ms)),
            }
        })
        .collect();
    processes.sort_by(|a, b| a.role.cmp(&b.role).then(a.pid.cmp(&b.pid)));
    SystemPerformance {
        logical_cpu_count: logical_cpus,
        host_boot_id,
        sample_interval_secs: u32::try_from(interval_ms / 1_000).unwrap_or(u32::MAX),
        product: role_usage(None, &all, now_ms, interval_ms, logical_cpus),
        roles,
        processes,
    }
}
