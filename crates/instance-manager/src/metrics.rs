//! Metrics Collector: persists the per-second worker samples without ever making the actor (or
//! the data plane behind it) wait for SQLite.
//!
//! [`MetricsCollector::offer`] runs on the actor when a sample arrives. Under a short lock it
//! drops duplicates and out-of-order samples (per Instance: generation, then worker clock),
//! turns the sample into a fixed-shape row (the Instance's counters, gauges and latency
//! histograms, and each Gateway's part) and appends it to a bounded queue; a full queue drops
//! its oldest row and remembers the dropped span as a gap. Nothing in it awaits.
//!
//! An Instance's payload is what its Gateways carried plus, in strict mode, what the Apps of its
//! sandbox carried (counted by the sandbox's TUN filter, which leaves out the worker's own flows,
//! so nothing is counted twice); the sandbox's part is kept beside it.
//!
//! A writer task stores the queue every second, one transaction per batch; a failed write
//! (`STORE_BUSY`, I/O) puts the rows back, still bounded, and retries with back-off — whatever
//! fails, it never stops. On a full disk the Store keeps recording by overwriting the oldest data
//! (`vpn_store::disk`). A second task folds rollups every few seconds and applies retention and
//! the disk quota every few minutes; the collector remembers how their last runs went, and
//! [`recording`] says whether samples are being stored. Queries read the Store directly with a
//! deadline.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vpn_domain::{
    ApiError, ErrorCode, GatewayId, GatewaySpec, InstanceId, InstanceSpec, MetricsCollectorStatus,
    MetricsRange, MetricsRecording, MetricsRecordingState, MetricsRetention, MetricsRetentionRun,
    MetricsScope, MetricsSeries, MetricsStatus, MetricsTaskRun, Text, Timestamp, tr,
};
use vpn_ipc::worker::{GateWire, GatewayStatusWire, WorkerStatus};
use vpn_store::{
    Appended, ConnectCounters, DroppedSpan, GatewaySample, HOUR_RETENTION_MS, Hist,
    MINUTE_RETENTION_MS, MetricSample, MetricsPolicy, SAMPLE_INTERVAL_MS, SshBytes, Store,
    StoreError,
};
use vpn_sync::Mutex;

/// Rows held while the Store is slow or busy.
///
/// A row is about 0.5 KiB plus about 0.25 KiB per Gateway (at most [`MAX_GATEWAYS_PER_SAMPLE`]), so a full queue stays within a few MiB, below
/// the 8 MiB ingress budget.
pub const QUEUE_CAPACITY: usize = 256;
/// Gateways one sample may carry: an Instance has at most 32; a worker reporting more is cut
/// short rather than growing the queue.
const MAX_GATEWAYS_PER_SAMPLE: usize = 64;
/// Dropped spans remembered until written; beyond, drops are only counted.
const MAX_DROPPED_SPANS: usize = 64;
/// Drops this close to the previous one of the same Instance extend its span.
const DROP_MERGE_MS: i64 = 5_000;
const FLUSH_EVERY: Duration = Duration::from_secs(1);
const FLUSH_BACKOFF_MAX: Duration = Duration::from_secs(30);
const ROLLUP_EVERY: Duration = Duration::from_secs(10);
const RETAIN_EVERY: Duration = Duration::from_secs(300);
/// Longest a metrics query may take.
pub const QUERY_DEADLINE: Duration = Duration::from_secs(3);
/// How long writes must have failed before the recording counts as failing.
const FAILING_AFTER_MS: i64 = 5_000;

/// What [`MetricsCollector::offer`] did with a sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    Queued,
    /// Queued; the oldest queued row was dropped to make room (recorded as a gap).
    QueuedDroppedOldest,
    /// Not newer on the worker clock than a sample already taken from this generation.
    Duplicate,
    /// From a generation older than one already seen.
    Stale,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CollectorStats {
    pub queued: u64,
    pub written: u64,
    pub duplicates: u64,
    pub stale: u64,
    /// Rows dropped unwritten (queue full).
    pub dropped: u64,
    pub write_failures: u64,
}

/// Per-Instance ordering state and the counter epochs of the generation.
struct Lineage {
    generation: u64,
    monotonic_ms: u64,
    /// Epoch of the payload and connect sums over the Gateways.
    epoch: u32,
    /// Gateways in the last sample (sorted), each with its own counter epoch.
    gateways: Vec<(GatewayId, u32)>,
    /// The next Gateway epoch of this generation.
    next_gateway_epoch: u32,
}

impl Lineage {
    const fn new(generation: u64, monotonic_ms: u64) -> Self {
        Self {
            generation,
            monotonic_ms,
            epoch: 0,
            gateways: Vec::new(),
            next_gateway_epoch: 0,
        }
    }

    /// Epochs for the Gateways of a new sample (sorted ids): a Gateway that was serving in the
    /// previous sample keeps its epoch; one (re)starting gets a new one, as its counters began
    /// again.
    fn gateway_epochs(&mut self, ids: &[GatewayId]) -> Vec<(GatewayId, u32)> {
        let next = ids
            .iter()
            .map(|id| {
                if let Ok(i) = self.gateways.binary_search_by_key(id, |(g, _)| *g) {
                    (*id, self.gateways[i].1)
                } else {
                    let epoch = self.next_gateway_epoch;
                    self.next_gateway_epoch = self.next_gateway_epoch.wrapping_add(1);
                    (*id, epoch)
                }
            })
            .collect::<Vec<_>>();
        self.gateways.clone_from(&next);
        next
    }
}

/// Writes have been failing since `since`; `error` is the last one's public message.
#[derive(Debug, Clone)]
struct Failing {
    since: Timestamp,
    error: Text,
}

#[derive(Default)]
struct Ingress {
    queue: VecDeque<MetricSample>,
    dropped: Vec<DroppedSpan>,
    lineage: HashMap<InstanceId, Lineage>,
    stats: CollectorStats,
    failing: Option<Failing>,
}

impl Ingress {
    /// Drop the oldest rows beyond `capacity`, remembering what was lost.
    fn trim(&mut self, capacity: usize) -> bool {
        let mut trimmed = false;
        while self.queue.len() > capacity {
            let Some(old) = self.queue.pop_front() else {
                break;
            };
            self.stats.dropped += 1;
            note_dropped(&mut self.dropped, &old);
            trimmed = true;
        }
        trimmed
    }
}

fn note_dropped(spans: &mut Vec<DroppedSpan>, s: &MetricSample) {
    if let Some(d) = spans
        .iter_mut()
        .rev()
        .find(|d| d.instance_id == s.instance_id)
        && s.at_ms >= d.from_ms - DROP_MERGE_MS
        && s.at_ms <= d.to_ms + DROP_MERGE_MS
    {
        d.from_ms = d.from_ms.min(s.at_ms);
        d.to_ms = d.to_ms.max(s.at_ms);
        d.samples += 1;
        return;
    }
    if spans.len() < MAX_DROPPED_SPANS {
        spans.push(DroppedSpan {
            instance_id: s.instance_id,
            from_ms: s.at_ms,
            to_ms: s.at_ms,
            samples: 1,
        });
    }
}

/// The reported Gateways' rows, each with its counter epoch (a Gateway without one is left out).
fn gateway_samples(
    reported: &[(GatewayId, &GatewayStatusWire)],
    epochs: &[(GatewayId, u32)],
) -> Vec<GatewaySample> {
    reported
        .iter()
        .filter_map(|(id, g)| {
            let epoch = epochs
                .binary_search_by_key(id, |(g, _)| *g)
                .ok()
                .map(|i| epochs[i].1)?;
            Some(GatewaySample {
                gateway_id: *id,
                epoch,
                payload_rx: g.payload_rx_bytes,
                payload_tx: g.payload_tx_bytes,
                active_tcp: g.tcp_active,
                active_udp: g.udp_active,
                serving: g.serving,
                connect: connect_of(g),
                ssh: Some(ssh_of(g)),
            })
        })
        .collect()
}

/// The Gateways' SSH parts, summed as their payload is (the same lineage).
fn ssh_sum(reported: &[(GatewayId, &GatewayStatusWire)]) -> SshBytes {
    reported
        .iter()
        .fold(SshBytes::default(), |mut sum, (_, g)| {
            sum.add(&ssh_of(g));
            sum
        })
}

/// What a Gateway relayed for SSH sessions and SSH downloads.
const fn ssh_of(g: &GatewayStatusWire) -> SshBytes {
    SshBytes {
        rx: g.ssh_rx_bytes,
        tx: g.ssh_tx_bytes,
        pull_rx: g.ssh_pull_rx_bytes,
        pull_tx: g.ssh_pull_tx_bytes,
    }
}

/// A Gateway's proxy-connect counters, `None` unless its histogram has the bucket layout.
fn connect_of(g: &GatewayStatusWire) -> Option<ConnectCounters> {
    Some(ConnectCounters {
        latency: Hist::from_wire(
            &g.connect_latency_buckets,
            g.connect_latency_sum_us,
            g.connect_timeouts,
        )?,
        failures: g.connect_failures,
        not_found: Some(g.connect_not_found),
        rejected: g.tcp_rejected,
    })
}

/// How the last rollup and retention runs went (for the status).
#[derive(Default)]
struct Maintenance {
    rollup: Option<MetricsTaskRun>,
    retention: Option<MetricsRetentionRun>,
}

fn task_run<T>(result: &Result<T, StoreError>) -> MetricsTaskRun {
    MetricsTaskRun {
        at: Timestamp::now(),
        ok: result.is_ok(),
        error: result.as_ref().err().map(|e| e.to_api().message),
    }
}

/// Where the collector writes (the Store; a stand-in in tests).
///
/// A batch the Store did not store because disk space is low ([`Appended::Skipped`]: its span is a gap) is handled, not
/// retried: the queue never grows for it.
pub trait MetricsSink: Send + Sync + 'static {
    fn append(
        &self,
        samples: Vec<MetricSample>,
        dropped: Vec<DroppedSpan>,
    ) -> impl Future<Output = Result<Appended, StoreError>> + Send;
}

impl MetricsSink for Arc<Store> {
    fn append(
        &self,
        samples: Vec<MetricSample>,
        dropped: Vec<DroppedSpan>,
    ) -> impl Future<Output = Result<Appended, StoreError>> + Send {
        let store = self.clone();
        async move { store.metrics_append(samples, dropped).await }
    }
}

pub struct MetricsCollector {
    ingress: Mutex<Ingress>,
    capacity: usize,
    started: Timestamp,
    maintenance: Mutex<Maintenance>,
}

impl MetricsCollector {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Self::with_capacity(QUEUE_CAPACITY)
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            ingress: Mutex::new(Ingress::default()),
            capacity: capacity.max(1),
            started: Timestamp::now(),
            maintenance: Mutex::new(Maintenance::default()),
        })
    }

    pub fn stats(&self) -> CollectorStats {
        self.ingress.lock().stats
    }

    pub fn queued(&self) -> usize {
        self.ingress.lock().queue.len()
    }

    /// Take a worker sample. Never waits: a short lock, no I/O.
    pub fn offer(&self, instance: InstanceId, s: &WorkerStatus) -> Offer {
        self.offer_at(instance, s, Timestamp::now().unix_millis())
    }

    /// [`Self::offer`] with the arrival time given (unix ms).
    pub fn offer_at(&self, instance: InstanceId, s: &WorkerStatus, at_ms: i64) -> Offer {
        let reported: Vec<(GatewayId, &GatewayStatusWire)> = s
            .gateways
            .iter()
            .filter_map(|g| Some((g.id?, g)))
            .take(MAX_GATEWAYS_PER_SAMPLE)
            .collect();
        let mut ids: Vec<GatewayId> = reported.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        ids.dedup();
        let (gateways_rx, gateways_tx) = reported.iter().fold((0u64, 0u64), |(rx, tx), (_, g)| {
            (
                rx.saturating_add(g.payload_rx_bytes),
                tx.saturating_add(g.payload_tx_bytes),
            )
        });
        // The Apps' part (port forwards, a strict sandbox's Apps) lives as long as the worker: it
        // never leaves the sum.
        let (apps_rx, apps_tx) = s.apps_payload();
        let (payload_rx, payload_tx) = (
            gateways_rx.saturating_add(apps_rx),
            gateways_tx.saturating_add(apps_tx),
        );
        let sandbox = s.sandbox_payload();
        let ssh = ssh_sum(&reported);
        // The Instance's connect counters are the Gateways' sum: known only if every part is.
        let connect = reported
            .iter()
            .try_fold(ConnectCounters::default(), |mut sum, (_, g)| {
                sum.add(&connect_of(g)?);
                Some(sum)
            });
        let mut guard = self.ingress.lock();
        let ing = &mut *guard;
        let (epoch, epochs) = match ing.lineage.get_mut(&instance) {
            Some(l) if s.generation < l.generation => {
                ing.stats.stale += 1;
                return Offer::Stale;
            }
            Some(l) if s.generation == l.generation && s.monotonic_ms <= l.monotonic_ms => {
                ing.stats.duplicates += 1;
                return Offer::Duplicate;
            }
            Some(l) if s.generation == l.generation => {
                // A Gateway whose counters left the sums (removed while running) breaks the
                // sums' lineage: no rate may span it.
                if l.gateways
                    .iter()
                    .any(|(g, _)| ids.binary_search(g).is_err())
                {
                    l.epoch += 1;
                }
                l.monotonic_ms = s.monotonic_ms;
                (l.epoch, l.gateway_epochs(&ids))
            }
            _ => {
                let mut l = Lineage::new(s.generation, s.monotonic_ms);
                let epochs = l.gateway_epochs(&ids);
                ing.lineage.insert(instance, l);
                (0, epochs)
            }
        };
        let gateways = gateway_samples(&reported, &epochs);
        let row = MetricSample {
            instance_id: instance,
            at_ms,
            generation: s.generation,
            epoch,
            mono_ms: s.monotonic_ms,
            payload_rx,
            payload_tx,
            wg_rx: s.wg_rx_bytes,
            wg_tx: s.wg_tx_bytes,
            tunnel_rx: s.tunnel_rx_bytes,
            tunnel_tx: s.tunnel_tx_bytes,
            dns_queries: s.dns_queries,
            dns_failures: s.dns_failures,
            dns_cache_hits: s.dns_cache_hits,
            active_tcp: s.active_tcp,
            active_udp: s.active_udp,
            cpu_ns: s.cpu_ns,
            rss_bytes: s.rss_bytes,
            gate_open: s.gate.map(|g| g == GateWire::Open),
            connect,
            dns_latency: Hist::from_wire(
                &s.dns_latency_buckets,
                s.dns_latency_sum_us,
                s.dns_timeouts,
            ),
            gateways,
            sandbox_rx: sandbox.map(|(rx, _)| rx),
            sandbox_tx: sandbox.map(|(_, tx)| tx),
            ssh: Some(ssh),
        };
        ing.queue.push_back(row);
        ing.stats.queued += 1;
        let dropped_oldest = ing.trim(self.capacity);
        drop(guard);
        if dropped_oldest {
            Offer::QueuedDroppedOldest
        } else {
            Offer::Queued
        }
    }

    fn take(&self) -> (Vec<MetricSample>, Vec<DroppedSpan>) {
        let mut ing = self.ingress.lock();
        (
            ing.queue.drain(..).collect(),
            std::mem::take(&mut ing.dropped),
        )
    }

    /// Put back a batch that could not be written (for `error`), in front of what arrived
    /// meanwhile; the oldest rows beyond capacity are dropped (and remembered).
    fn give_back(&self, samples: Vec<MetricSample>, dropped: Vec<DroppedSpan>, error: &StoreError) {
        let mut guard = self.ingress.lock();
        let ing = &mut *guard;
        ing.stats.write_failures += 1;
        let error = error.to_api().message;
        match &mut ing.failing {
            Some(f) => f.error = error,
            None => {
                ing.failing = Some(Failing {
                    since: Timestamp::now(),
                    error,
                });
            }
        }
        let newer = std::mem::take(&mut ing.queue);
        ing.queue = samples.into_iter().chain(newer).collect();
        let newer_spans = std::mem::replace(&mut ing.dropped, dropped);
        for d in newer_spans {
            if ing.dropped.len() < MAX_DROPPED_SPANS {
                ing.dropped.push(d);
            }
        }
        ing.trim(self.capacity);
        drop(guard);
    }

    /// Write what is queued now as one batch. Returns the rows written (none when the Store
    /// recorded the batch as a low-space gap instead); on failure the rows are kept for the next
    /// attempt.
    ///
    /// # Errors
    ///
    /// The sink's error when the batch could not be written (the rows stay queued).
    pub async fn flush<S: MetricsSink>(&self, sink: &S) -> Result<usize, StoreError> {
        let (samples, dropped) = self.take();
        if samples.is_empty() && dropped.is_empty() {
            return Ok(0);
        }
        let n = samples.len();
        match sink.append(samples.clone(), dropped.clone()).await {
            Ok(appended) => {
                let stored = appended == Appended::Stored;
                let mut ing = self.ingress.lock();
                ing.failing = None;
                if stored {
                    ing.stats.written += n as u64;
                }
                drop(ing);
                Ok(if stored { n } else { 0 })
            }
            Err(e) => {
                self.give_back(samples, dropped, &e);
                Err(e)
            }
        }
    }

    /// Since when writes fail, and why (the last failure), while they do.
    fn failing(&self) -> Option<(Timestamp, Text)> {
        self.ingress
            .lock()
            .failing
            .as_ref()
            .map(|f| (f.since, f.error.clone()))
    }

    /// The collector's part of the status.
    fn ingress_status(&self) -> MetricsCollectorStatus {
        let ing = self.ingress.lock();
        let s = ing.stats;
        MetricsCollectorStatus {
            since: self.started,
            queued: u32::try_from(ing.queue.len()).unwrap_or(u32::MAX),
            capacity: u32::try_from(self.capacity).unwrap_or(u32::MAX),
            written: s.written,
            dropped: s.dropped,
            duplicates: s.duplicates,
            stale: s.stale,
            write_failures: s.write_failures,
        }
    }
}

/// Write the queue every second, as long as the process runs; back off while it fails.
///
/// The sink is never given up: whatever made a write fail — even a store that says it is
/// closed — the next one is tried.
pub async fn flush_loop<S: MetricsSink>(collector: Arc<MetricsCollector>, sink: S) {
    let mut delay = FLUSH_EVERY;
    let mut failing_since: Option<Instant> = None;
    loop {
        tokio::time::sleep(delay).await;
        match collector.flush(&sink).await {
            Ok(_) => {
                if let Some(since) = failing_since.take() {
                    tracing::info!(after = ?since.elapsed(), "metrics are stored again");
                }
                delay = FLUSH_EVERY;
            }
            Err(e) => {
                if failing_since.is_none() {
                    tracing::warn!(error = %e, "metrics not stored; keeping the newest samples and retrying");
                    failing_since = Some(Instant::now());
                }
                delay = (delay * 2).min(FLUSH_BACKOFF_MAX);
            }
        }
    }
}

fn now_ms() -> i64 {
    Timestamp::now().unix_millis()
}

/// Fold rollups every few seconds; apply retention and the quota every few minutes. Like the
/// writer, it runs as long as the process does: a failed run is recorded, and the next one tried.
pub async fn maintain_loop(store: Arc<Store>, collector: Arc<MetricsCollector>) {
    let mut tick = tokio::time::interval(ROLLUP_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut retained: Option<Instant> = None;
    loop {
        tick.tick().await;
        // Free space first: while it is low the metrics database stays at its size (and
        // overwrites its oldest data); with room again its reserve comes back.
        store.metrics_space();
        let rolled = store.metrics_rollup(now_ms()).await;
        if let Err(e) = &rolled {
            tracing::debug!(error = %e, "metrics rollup deferred");
        }
        collector.maintenance.lock().rollup = Some(task_run(&rolled));
        if retained.is_some_and(|t| t.elapsed() < RETAIN_EVERY) {
            continue;
        }
        let policy = store
            .settings()
            .await
            .map_or_default(|s| MetricsPolicy::from_settings(&s));
        let result = store.metrics_retain(policy, now_ms()).await;
        match &result {
            Ok(r) => {
                retained = Some(Instant::now());
                if r.quota_deleted > 0 || r.over_quota {
                    tracing::warn!(
                        deleted = r.quota_deleted,
                        used_bytes = r.used_bytes,
                        quota_bytes = policy.quota_bytes,
                        over_quota = r.over_quota,
                        "metrics disk quota reached; the oldest data was deleted early"
                    );
                }
            }
            Err(e) => tracing::debug!(error = %e, "metrics retention deferred"),
        }
        collector.maintenance.lock().retention = Some(MetricsRetentionRun {
            run: task_run(&result),
            expired_rows: result
                .as_ref()
                .map_or(0, |r| (r.raw_deleted + r.buckets_deleted) as u64),
            quota_rows: result.as_ref().map_or(0, |r| r.quota_deleted as u64),
        });
    }
}

/// Start the writer and the rollup/retention task.
pub fn spawn(collector: Arc<MetricsCollector>, store: Arc<Store>) {
    tokio::spawn(flush_loop(collector.clone(), store.clone()));
    tokio::spawn(maintain_loop(store, collector));
}

/// Whether metric samples are being stored now.
///
/// Overwriting the oldest data while the data directory's volume is low on space, failing while
/// writes fail (a failure wins: nothing is stored then), recording otherwise.
pub fn recording(store: &Store, collector: &MetricsCollector) -> MetricsRecording {
    let disk = store.metrics_disk();
    // One busy moment is not a failure: writes count as failing once they have for a while.
    let failing = collector
        .failing()
        .filter(|(since, _)| now_ms() - since.unix_millis() >= FAILING_AFTER_MS);
    // What was overwritten counts while space is low (the spell it belongs to).
    let (overwritten_rows, lost_samples) = if disk.low {
        (disk.pruned_rows, disk.skipped_samples)
    } else {
        (0, 0)
    };
    let (state, since, error) = match failing {
        Some((since, error)) => (MetricsRecordingState::Failing, Some(since), Some(error)),
        None if disk.low => (MetricsRecordingState::Overwriting, disk.since, None),
        None => (MetricsRecordingState::Recording, None, None),
    };
    MetricsRecording {
        state,
        since,
        free_bytes: disk.free_bytes,
        resume_bytes: disk.resume_bytes,
        overwritten_rows,
        lost_samples,
        error,
    }
}

fn timed_out() -> ApiError {
    ApiError::new(
        ErrorCode::Timeout,
        tr!(
            "The metrics query timed out; try again later",
            "指標查詢逾時，請稍後再試",
            "メトリクスの問い合わせがタイムアウトしました。しばらくしてからもう一度お試しください"
        ),
    )
}

/// The persisted series of `scope` over `range` (answer to `Call::MetricsSeries`). A scope
/// naming an Instance or Gateway that does not exist is not found.
///
/// # Errors
///
/// Not found for a scope naming a missing Instance or Gateway, the Store's error when it cannot
/// be read, and a timeout when the query takes longer than its deadline.
pub async fn series(
    store: &Store,
    scope: MetricsScope,
    range: MetricsRange,
) -> Result<MetricsSeries, ApiError> {
    let exists = match scope {
        MetricsScope::All => true,
        MetricsScope::Instance(id) => store
            .get::<InstanceSpec>(id.to_string())
            .await
            .map_err(|e| e.to_api())?
            .is_some(),
        MetricsScope::Gateway(id) => store
            .get::<GatewaySpec>(id.to_string())
            .await
            .map_err(|e| e.to_api())?
            .is_some(),
    };
    if !exists {
        return Err(ApiError::not_found(match scope {
            MetricsScope::Gateway(_) => tr!("this Gateway", "這個代理埠", "このゲートウェイ"),
            _ => tr!("this connection", "這條連線", "この接続"),
        }));
    }
    let policy = MetricsPolicy::from_settings(&store.settings().await.map_err(|e| e.to_api())?);
    tokio::time::timeout(
        QUERY_DEADLINE,
        store.metrics_series(scope, range, now_ms(), policy.raw_retention_ms),
    )
    .await
    .map_err(|_| timed_out())?
    .map_err(|e| e.to_api())
}

/// What is kept, the space it takes and what went missing (answer to `Call::MetricsStatus`).
///
/// # Errors
///
/// The Store's error when its settings or metrics cannot be read, and a timeout when the query
/// takes longer than its deadline.
pub async fn status(
    store: &Store,
    collector: &MetricsCollector,
) -> Result<MetricsStatus, ApiError> {
    const HOUR_MS: i64 = 3_600_000;
    const DAY_MS: i64 = 24 * HOUR_MS;
    // Constants, and a raw retention the policy clamps to at most a week: all fit a `u32`.
    let small = |n: i64| u32::try_from(n).unwrap_or(u32::MAX);
    let policy = MetricsPolicy::from_settings(&store.settings().await.map_err(|e| e.to_api())?);
    let db = tokio::time::timeout(QUERY_DEADLINE, store.metrics_status(now_ms()))
        .await
        .map_err(|_| timed_out())?
        .map_err(|e| e.to_api())?;
    let (last_rollup, last_retention) = {
        let m = collector.maintenance.lock();
        (m.rollup.clone(), m.retention.clone())
    };
    Ok(MetricsStatus {
        sample_interval_ms: u32::try_from(SAMPLE_INTERVAL_MS).unwrap_or(u32::MAX),
        retention: MetricsRetention {
            raw_hours: small(policy.raw_retention_ms / HOUR_MS),
            minute_days: small(MINUTE_RETENTION_MS / DAY_MS),
            hour_days: small(HOUR_RETENTION_MS / DAY_MS),
        },

        quota_bytes: policy.quota_bytes,
        used_bytes: db.used_bytes,
        file_bytes: db.file_bytes,
        over_quota: db.used_bytes > policy.quota_bytes,
        oldest: db.oldest,
        pruned_before: db.pruned_before,
        rollup_until_ms: db.rollup_until_ms,
        gaps_24h: db.gaps_24h,
        last_rollup,
        last_retention,
        collector: collector.ingress_status(),
        observed_at: Timestamp::now(),
    })
}
