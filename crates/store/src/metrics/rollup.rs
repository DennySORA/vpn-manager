//! The math shared by rollups and series: how one stored sample relates to the one before it,
//! and how samples fold into 1-minute and 1-hour buckets.
//!
//! Rates follow `rate = (counter_new − counter_old) / ((mono_new − mono_old) / 1000)` between
//! consecutive samples of one generation and counter epoch, and only when the worker clock
//! advanced by at most `max(5 s, 2.5 × sample interval)` and the counter did not go backwards.
//! Anything else breaks the series: the rate is unknown, never zero. Buckets keep counter deltas
//! together with the time they cover, and gauges as min / max / time-weighted mean, so time
//! without samples is never averaged in as zero. An interval belongs to the bucket of the sample
//! that ends it.

use crate::num::u64_to_f64;
use vpn_domain::MetricsGapReason;

use super::hist::Hist;
use super::{MAX_GAP_MS, SAMPLE_INTERVAL_MS};

/// Bit flags of a bucket: why its samples did not all form continuous intervals.
pub const BREAK_GENERATION: u32 = 1;
pub const BREAK_RESET: u32 = 2;
pub const BREAK_LONG: u32 = 4;

/// Proxy-connect counters of a sample.
///
/// They are the latency histogram (with the timeouts in it), the connects that failed otherwise
/// and the requests the Gateway refused. They share one lineage
/// and are compared together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectCounters {
    pub latency: Hist,
    pub failures: u64,
    /// Subset of `failures`: the name had no address. `None` when not recorded (written before
    /// metrics v5); a difference or sum with an unrecorded side is unrecorded too, so the count
    /// always covers exactly the failures beside it.
    pub not_found: Option<u64>,
    pub rejected: u64,
}

/// Nothing counted yet: every count known and zero (what sums start from).
impl Default for ConnectCounters {
    fn default() -> Self {
        Self {
            latency: Hist::default(),
            failures: 0,
            not_found: Some(0),
            rejected: 0,
        }
    }
}

impl ConnectCounters {
    /// What happened since an older reading, or `None` if anything went backwards.
    pub(crate) fn since(&self, older: &Self) -> Option<Self> {
        Some(Self {
            latency: self.latency.since(&older.latency)?,
            failures: self.failures.checked_sub(older.failures)?,
            not_found: match (self.not_found, older.not_found) {
                (Some(new), Some(old)) => Some(new.checked_sub(old)?),
                _ => None,
            },
            rejected: self.rejected.checked_sub(older.rejected)?,
        })
    }

    /// Merge another reading or window (the collector sums its Gateways' readings).
    pub fn add(&mut self, other: &Self) {
        self.latency.add(&other.latency);
        self.failures = self.failures.saturating_add(other.failures);
        self.not_found = self
            .not_found
            .zip(other.not_found)
            .map(|(a, b)| a.saturating_add(b));
        self.rejected = self.rejected.saturating_add(other.rejected);
    }
}

/// What a sample's Gateways relayed for SSH, already part of its payload.
///
/// SSH sessions (「SSH 代理」: `rx`, `tx`) and VPN Manager's own SSH downloads (「SSH 下載」:
/// `pull_rx`, `pull_tx`), never one in the other. Cumulative counters in a sample; what a
/// bucket's continuous intervals relayed in a bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SshBytes {
    pub rx: u64,
    pub tx: u64,
    pub pull_rx: u64,
    pub pull_tx: u64,
}

impl SshBytes {
    /// What was relayed since an older reading, or `None` if a counter went backwards.
    pub(crate) fn since(&self, older: &Self) -> Option<Self> {
        Some(Self {
            rx: self.rx.checked_sub(older.rx)?,
            tx: self.tx.checked_sub(older.tx)?,
            pull_rx: self.pull_rx.checked_sub(older.pull_rx)?,
            pull_tx: self.pull_tx.checked_sub(older.pull_tx)?,
        })
    }

    /// Add another reading or window (the collector sums its Gateways' readings).
    pub const fn add(&mut self, other: &Self) {
        self.rx = self.rx.saturating_add(other.rx);
        self.tx = self.tx.saturating_add(other.tx);
        self.pull_rx = self.pull_rx.saturating_add(other.pull_rx);
        self.pull_tx = self.pull_tx.saturating_add(other.pull_tx);
    }
}

/// One stored sample of a series (an Instance, or one Gateway of an Instance) as rollups and
/// series read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Manager wall clock when the sample arrived (unix ms): its place on the time axis.
    pub at_ms: i64,
    pub generation: u64,
    pub epoch: u32,
    /// Worker monotonic milliseconds: rates use only differences of this clock.
    pub mono_ms: u64,
    pub payload_rx: u64,
    pub payload_tx: u64,
    pub tcp: u64,
    pub udp: u64,
    /// Payload gate open (`None`: not recorded, e.g. a sample written before v3).
    pub open: Option<bool>,
    pub connect: Option<ConnectCounters>,
    /// The SSH part of the payload; `None` when not recorded (written before metrics v8).
    pub ssh: Option<SshBytes>,
    /// Instance-only measures; `None` in a Gateway row.
    pub inst: Option<InstRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstRow {
    pub wg_rx: u64,
    pub wg_tx: u64,
    pub tunnel_rx: u64,
    pub tunnel_tx: u64,
    pub dns_queries: u64,
    pub dns_failures: u64,
    pub dns_cache_hits: u64,
    pub cpu_ns: Option<u64>,
    pub rss_bytes: Option<u64>,
    pub dns_latency: Option<Hist>,
    /// Strict mode: the sandbox's Apps' payload `(rx, tx)`, part of the payload; `None` without
    /// a sandbox (or written before metrics v7).
    pub sandbox: Option<(u64, u64)>,
}

/// How a sample relates to the one before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// Same generation and epoch, the worker clock advanced by `dt_ms` within the limit, and the
    /// samples arrived within the limit of each other.
    Continuous {
        dt_ms: u64,
    },
    Break(MetricsGapReason),
}

pub const fn link(prev: &Row, cur: &Row) -> Link {
    if prev.generation != cur.generation {
        return Link::Break(MetricsGapReason::NewGeneration);
    }
    if prev.epoch != cur.epoch || cur.mono_ms <= prev.mono_ms {
        return Link::Break(MetricsGapReason::CounterReset);
    }
    let dt_ms = cur.mono_ms - prev.mono_ms;
    // The worker's clock stands still while the host sleeps; arrival times do not. Samples
    // further apart on either clock were not taken at the sampling pace, and nothing is known
    // about the time between them.
    if dt_ms > MAX_GAP_MS || cur.at_ms - prev.at_ms > MAX_GAP_MS.cast_signed() {
        return Link::Break(MetricsGapReason::LongInterval);
    }
    Link::Continuous { dt_ms }
}

/// Bits per second for `delta` bytes over `ms` milliseconds.
pub fn bps(delta: u64, ms: u64) -> Option<f64> {
    (ms > 0).then(|| (u64_to_f64(delta) * 8_000.0 / u64_to_f64(ms)).round())
}

/// CPU time over wall time, percent of one core.
pub fn cpu_pct(cpu_ns: u64, ms: u64) -> Option<f64> {
    (ms > 0).then(|| round2(u64_to_f64(cpu_ns) / (u64_to_f64(ms) * 10_000.0)))
}

pub fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

pub const fn floor_to(t: i64, step: i64) -> i64 {
    t.div_euclid(step) * step
}

pub const fn ceil_to(t: i64, step: i64) -> i64 {
    floor_to(t.saturating_add(step - 1), step)
}

/// A gauge over a bucket: each observation weighs the time it stands for.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Gauge {
    pub min: Option<f64>,
    pub max: Option<f64>,
    /// Σ value × ms.
    pub sum: f64,
    pub weight_ms: u64,
}

impl Gauge {
    pub(crate) fn observe(&mut self, v: f64, weight_ms: u64) {
        self.min = Some(self.min.map_or(v, |m| m.min(v)));
        self.max = Some(self.max.map_or(v, |m| m.max(v)));
        self.sum = v.mul_add(u64_to_f64(weight_ms), self.sum);
        self.weight_ms += weight_ms;
    }

    fn merge(&mut self, o: &Self) {
        self.min = match (self.min, o.min) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.max = match (self.max, o.max) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        self.sum += o.sum;
        self.weight_ms += o.weight_ms;
    }

    /// Time-weighted mean.
    pub(crate) fn mean(&self) -> Option<f64> {
        (self.weight_ms > 0).then(|| self.sum / u64_to_f64(self.weight_ms))
    }
}

/// How often each kind of break happened in a bucket (`long_ms`: the wall time the long
/// intervals spanned).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Breaks {
    pub generation: u64,
    pub reset: u64,
    pub long: u64,
    pub long_ms: u64,
}

/// One rollup bucket. Counter deltas come only from continuous intervals and each `*_ms` is the
/// time they cover; `link_ms` is the time of all continuous intervals.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Bucket {
    #[expect(
        clippy::struct_field_names,
        reason = "named after its SQL column `bucket_ms`, like the rest of the rollup code"
    )]
    pub bucket_ms: i64,
    pub samples: u64,
    pub breaks: u32,
    /// `None` for buckets written before breaks were counted (only `breaks` is known).
    pub detail: Option<Breaks>,
    pub link_ms: u64,
    /// Continuous time whose gate state is recorded, and of it the time the gate was open.
    pub gate_ms: u64,
    pub open_ms: u64,
    pub payload_rx: u64,
    pub payload_tx: u64,
    pub payload_ms: u64,
    pub tcp: Gauge,
    pub udp: Gauge,
    pub connect: ConnectCounters,
    pub connect_ms: u64,
    /// The SSH part of the payload and the time it covers (0: not recorded).
    pub ssh: SshBytes,
    pub ssh_ms: u64,
    /// Instance-only measures; `None` in a Gateway bucket.
    pub inst: Option<InstBucket>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct InstBucket {
    pub wg_rx: u64,
    pub wg_tx: u64,
    pub wg_ms: u64,
    pub tunnel_rx: u64,
    pub tunnel_tx: u64,
    pub tunnel_ms: u64,
    pub dns_queries: u64,
    pub dns_failures: u64,
    pub dns_cache_hits: u64,
    pub dns_ms: u64,
    pub cpu_ns: u64,
    pub cpu_ms: u64,
    pub rss: Gauge,
    pub dns_latency: Hist,
    pub dns_latency_ms: u64,
    /// The sandbox's Apps' payload and the time it covers (0 without a sandbox).
    pub sandbox_rx: u64,
    pub sandbox_tx: u64,
    pub sandbox_ms: u64,
}

/// Add one counter pair over `dt`; false (nothing added) when either counter went backwards.
const fn add_pair(
    (sum_rx, sum_tx, sum_ms): (&mut u64, &mut u64, &mut u64),
    new: (u64, u64),
    old: (u64, u64),
    dt_ms: u64,
) -> bool {
    match (new.0.checked_sub(old.0), new.1.checked_sub(old.1)) {
        (Some(a), Some(b)) => {
            *sum_rx = sum_rx.saturating_add(a);
            *sum_tx = sum_tx.saturating_add(b);
            *sum_ms += dt_ms;
            true
        }
        _ => false,
    }
}

impl InstBucket {
    /// Account the interval `old → new` of `dt_ms`; false when a counter went backwards.
    fn add(&mut self, new: &InstRow, old: &InstRow, dt_ms: u64) -> bool {
        let mut ok = add_pair(
            (&mut self.wg_rx, &mut self.wg_tx, &mut self.wg_ms),
            (new.wg_rx, new.wg_tx),
            (old.wg_rx, old.wg_tx),
            dt_ms,
        );
        ok &= add_pair(
            (
                &mut self.tunnel_rx,
                &mut self.tunnel_tx,
                &mut self.tunnel_ms,
            ),
            (new.tunnel_rx, new.tunnel_tx),
            (old.tunnel_rx, old.tunnel_tx),
            dt_ms,
        );
        match (
            new.dns_queries.checked_sub(old.dns_queries),
            new.dns_failures.checked_sub(old.dns_failures),
            new.dns_cache_hits.checked_sub(old.dns_cache_hits),
        ) {
            (Some(q), Some(f), Some(h)) => {
                self.dns_queries = self.dns_queries.saturating_add(q);
                self.dns_failures = self.dns_failures.saturating_add(f);
                self.dns_cache_hits = self.dns_cache_hits.saturating_add(h);
                self.dns_ms += dt_ms;
            }
            _ => ok = false,
        }
        // A reading the platform does not give is unavailable, not a reset.
        if let (Some(a), Some(b)) = (new.cpu_ns, old.cpu_ns) {
            match a.checked_sub(b) {
                Some(d) => {
                    self.cpu_ns = self.cpu_ns.saturating_add(d);
                    self.cpu_ms += dt_ms;
                }
                None => ok = false,
            }
        }
        if let (Some(a), Some(b)) = (&new.dns_latency, &old.dns_latency) {
            match a.since(b) {
                Some(d) => {
                    self.dns_latency.add(&d);
                    self.dns_latency_ms += dt_ms;
                }
                None => ok = false,
            }
        }
        // Without a sandbox on either side there is nothing to count: not a reset.
        if let (Some(a), Some(b)) = (new.sandbox, old.sandbox) {
            ok &= add_pair(
                (
                    &mut self.sandbox_rx,
                    &mut self.sandbox_tx,
                    &mut self.sandbox_ms,
                ),
                a,
                b,
                dt_ms,
            );
        }
        ok
    }

    fn merge(&mut self, o: &Self) {
        let sum = |a: &mut u64, b: u64| *a = a.saturating_add(b);
        sum(&mut self.wg_rx, o.wg_rx);
        sum(&mut self.wg_tx, o.wg_tx);
        sum(&mut self.wg_ms, o.wg_ms);
        sum(&mut self.tunnel_rx, o.tunnel_rx);
        sum(&mut self.tunnel_tx, o.tunnel_tx);
        sum(&mut self.tunnel_ms, o.tunnel_ms);
        sum(&mut self.dns_queries, o.dns_queries);
        sum(&mut self.dns_failures, o.dns_failures);
        sum(&mut self.dns_cache_hits, o.dns_cache_hits);
        sum(&mut self.dns_ms, o.dns_ms);
        sum(&mut self.cpu_ns, o.cpu_ns);
        sum(&mut self.cpu_ms, o.cpu_ms);
        self.rss.merge(&o.rss);
        self.dns_latency.add(&o.dns_latency);
        sum(&mut self.dns_latency_ms, o.dns_latency_ms);
        sum(&mut self.sandbox_rx, o.sandbox_rx);
        sum(&mut self.sandbox_tx, o.sandbox_tx);
        sum(&mut self.sandbox_ms, o.sandbox_ms);
    }
}

impl Bucket {
    pub(crate) fn starting(bucket_ms: i64, instance: bool) -> Self {
        Self {
            bucket_ms,
            detail: Some(Breaks::default()),
            inst: instance.then(InstBucket::default),
            ..Default::default()
        }
    }

    /// Account `cur` (its interval since `prev`, and its gauges).
    pub(crate) fn add(&mut self, prev: Option<&Row>, cur: &Row) {
        self.samples += 1;
        // A gauge observation stands for the interval it ends, or one nominal sample interval
        // when it starts a run (nothing continuous before it).
        let weight = match prev.map(|p| (p, link(p, cur))) {
            Some((p, Link::Continuous { dt_ms })) => {
                self.link_ms += dt_ms;
                let mut ok = add_pair(
                    (
                        &mut self.payload_rx,
                        &mut self.payload_tx,
                        &mut self.payload_ms,
                    ),
                    (cur.payload_rx, cur.payload_tx),
                    (p.payload_rx, p.payload_tx),
                    dt_ms,
                );
                if let Some(open) = cur.open {
                    self.gate_ms += dt_ms;
                    if open {
                        self.open_ms += dt_ms;
                    }
                }
                if let (Some(a), Some(b)) = (&cur.connect, &p.connect) {
                    match a.since(b) {
                        Some(d) => {
                            self.connect.add(&d);
                            self.connect_ms += dt_ms;
                        }
                        None => ok = false,
                    }
                }
                // A row without SSH counts (written before metrics v8) leaves them unknown: not a
                // reset.
                if let (Some(a), Some(b)) = (&cur.ssh, &p.ssh) {
                    match a.since(b) {
                        Some(d) => {
                            self.ssh.add(&d);
                            self.ssh_ms += dt_ms;
                        }
                        None => ok = false,
                    }
                }
                if let (Some(bucket), Some(a), Some(b)) =
                    (self.inst.as_mut(), cur.inst.as_ref(), p.inst.as_ref())
                {
                    ok &= bucket.add(a, b, dt_ms);
                }
                if !ok {
                    self.breaks |= BREAK_RESET;
                    if let Some(d) = self.detail.as_mut() {
                        d.reset += 1;
                    }
                }
                dt_ms
            }
            Some((p, Link::Break(reason))) => {
                let detail = self.detail.as_mut();
                match reason {
                    MetricsGapReason::NewGeneration => {
                        self.breaks |= BREAK_GENERATION;
                        if let Some(d) = detail {
                            d.generation += 1;
                        }
                    }
                    MetricsGapReason::LongInterval => {
                        self.breaks |= BREAK_LONG;
                        if let Some(d) = detail {
                            d.long += 1;
                            d.long_ms += (cur.at_ms - p.at_ms).max(0).cast_unsigned();
                        }
                    }
                    _ => {
                        self.breaks |= BREAK_RESET;
                        if let Some(d) = detail {
                            d.reset += 1;
                        }
                    }
                }
                SAMPLE_INTERVAL_MS
            }
            None => SAMPLE_INTERVAL_MS,
        };
        self.tcp.observe(u64_to_f64(cur.tcp), weight);
        self.udp.observe(u64_to_f64(cur.udp), weight);
        if let (Some(bucket), Some(rss)) = (
            self.inst.as_mut(),
            cur.inst.as_ref().and_then(|i| i.rss_bytes),
        ) {
            bucket.rss.observe(u64_to_f64(rss), weight);
        }
    }

    pub(crate) fn merge(&mut self, o: &Self) {
        let sum = |a: &mut u64, b: u64| *a = a.saturating_add(b);
        self.samples += o.samples;
        self.breaks |= o.breaks;
        self.detail = match (self.detail, o.detail) {
            (Some(a), Some(b)) => Some(Breaks {
                generation: a.generation + b.generation,
                reset: a.reset + b.reset,
                long: a.long + b.long,
                long_ms: a.long_ms + b.long_ms,
            }),
            _ => None,
        };
        sum(&mut self.link_ms, o.link_ms);
        sum(&mut self.gate_ms, o.gate_ms);
        sum(&mut self.open_ms, o.open_ms);
        sum(&mut self.payload_rx, o.payload_rx);
        sum(&mut self.payload_tx, o.payload_tx);
        sum(&mut self.payload_ms, o.payload_ms);
        self.tcp.merge(&o.tcp);
        self.udp.merge(&o.udp);
        self.connect.add(&o.connect);
        sum(&mut self.connect_ms, o.connect_ms);
        self.ssh.add(&o.ssh);
        sum(&mut self.ssh_ms, o.ssh_ms);
        match (self.inst.as_mut(), o.inst.as_ref()) {
            (Some(a), Some(b)) => a.merge(b),
            (None, Some(b)) => self.inst = Some(b.clone()),
            _ => {}
        }
    }

    /// Why the rates of a bucket without covered time are unknown.
    pub(crate) const fn break_reason(&self) -> MetricsGapReason {
        if self.breaks & BREAK_GENERATION != 0 {
            MetricsGapReason::NewGeneration
        } else if self.breaks & BREAK_RESET != 0 {
            MetricsGapReason::CounterReset
        } else if self.breaks & BREAK_LONG != 0 {
            MetricsGapReason::LongInterval
        } else {
            MetricsGapReason::Missing
        }
    }
}

/// Fold time-ordered rows into `step` buckets for rows in `[lo, hi)`; rows before `lo` only
/// serve as predecessors. Only buckets with rows are returned.
pub fn rollup_rows(rows: &[Row], lo: i64, hi: i64, step: i64, instance: bool) -> Vec<Bucket> {
    let mut out: Vec<Bucket> = Vec::new();
    let mut prev: Option<&Row> = None;
    for cur in rows {
        if (lo..hi).contains(&cur.at_ms) {
            let start = floor_to(cur.at_ms, step);
            if out.last().is_none_or(|b| b.bucket_ms != start) {
                out.push(Bucket::starting(start, instance));
            }
            if let Some(b) = out.last_mut() {
                b.add(prev, cur);
            }
        }
        prev = Some(cur);
    }
    out
}

/// Fold time-ordered buckets into coarser `step` buckets (minute → hour).
pub fn fold_buckets(buckets: &[Bucket], step: i64, instance: bool) -> Vec<Bucket> {
    let mut out: Vec<Bucket> = Vec::new();
    for b in buckets {
        let start = floor_to(b.bucket_ms, step);
        if out.last().is_none_or(|o| o.bucket_ms != start) {
            out.push(Bucket::starting(start, instance));
        }
        if let Some(o) = out.last_mut() {
            o.merge(b);
        }
    }
    out
}
