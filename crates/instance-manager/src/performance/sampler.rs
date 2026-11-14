//! The resource sampler. Every second it samples the manager itself (`getrusage`), each connected
//! controller by pid, and every running worker (from the worker's own report; its descriptor
//! count by pid). Every fifth tick (5 s) the samples are queued for the Store.
//!
//! The queue is bounded: when the Store is slow or busy the oldest rows are dropped and their
//! span recorded as a gap. A writer stores it every 5 s; another task folds rollups every minute
//! and applies retention and the quota every 5 minutes.

use std::collections::VecDeque;
use std::sync::{Arc, Weak};
use std::time::Duration;

use vpn_domain::{InstanceId, ProcessRole};
use vpn_performance::passive::{self, ProcessPoint, ProcessWindow};
use vpn_platform::resources::{self, ProcessIdentity};
use vpn_store::{MetricsPolicy, ResourceDropped, ResourceIdentity, ResourceSample};

use super::{Performance, ProcessEntry, now_ms, random_epoch};

const TICK: Duration = Duration::from_secs(1);
/// Persist every this many ticks.
const PERSIST_EVERY: u32 = 5;
/// Rows held while the Store is busy (about 100 processes × 40 ticks).
const QUEUE_ROWS: usize = 4_096;
const FLUSH_EVERY: Duration = Duration::from_secs(5);
const FLUSH_BACKOFF_MAX: Duration = Duration::from_secs(60);
const ROLLUP_EVERY: Duration = Duration::from_secs(60);
const RETAIN_EVERY: Duration = Duration::from_secs(300);
/// A worker sample older than this is not "now".
const FRESH_MS: i64 = 3_000;
/// Windows of Instances not heard from for this long are forgotten.
const FORGET_MS: i64 = 15 * 60_000;

/// One process at one tick.
struct Observation {
    role: ProcessRole,
    identity: ProcessIdentity,
    instance_id: Option<InstanceId>,
    generation: Option<u64>,
    mono_ms: u64,
    cpu_ns: Option<u64>,
    rss_bytes: Option<u64>,
    fd_count: Option<u32>,
}

/// A running worker's latest own report.
struct WorkerNow {
    instance: InstanceId,
    pid: u32,
    generation: u64,
    mono_ms: u64,
    cpu_ns: Option<u64>,
    rss_bytes: Option<u64>,
}

#[derive(Default)]
pub struct PersistQueue {
    rows: VecDeque<ResourceSample>,
    dropped: Vec<ResourceDropped>,
    pub dropped_rows: u64,
}

impl PersistQueue {
    fn note_dropped(&mut self, at_ms: i64) {
        self.dropped_rows += 1;
        if let Some(d) = self.dropped.last_mut()
            && at_ms >= d.from_ms - 5_000
            && at_ms <= d.to_ms + 5_000
        {
            d.from_ms = d.from_ms.min(at_ms);
            d.to_ms = d.to_ms.max(at_ms);
            return;
        }
        if self.dropped.len() < 64 {
            self.dropped.push(ResourceDropped {
                from_ms: at_ms,
                to_ms: at_ms,
            });
        }
    }

    fn trim(&mut self) {
        while self.rows.len() > QUEUE_ROWS {
            if let Some(old) = self.rows.pop_front() {
                self.note_dropped(old.at_ms);
            }
        }
    }

    pub(crate) fn push(&mut self, rows: Vec<ResourceSample>) {
        self.rows.extend(rows);
        self.trim();
    }

    fn take(&mut self) -> (Vec<ResourceSample>, Vec<ResourceDropped>) {
        (
            self.rows.drain(..).collect(),
            std::mem::take(&mut self.dropped),
        )
    }

    /// A batch the Store refused goes back in front of what arrived meanwhile.
    fn give_back(&mut self, rows: Vec<ResourceSample>, dropped: Vec<ResourceDropped>) {
        let newer = std::mem::take(&mut self.rows);
        self.rows = rows.into_iter().chain(newer).collect();
        let newer_spans = std::mem::replace(&mut self.dropped, dropped);
        for d in newer_spans {
            if self.dropped.len() < 64 {
                self.dropped.push(d);
            }
        }
        self.trim();
    }
}

pub(super) fn spawn(perf: &Arc<Performance>) {
    tokio::spawn(sample_loop(Arc::downgrade(perf)));
    tokio::spawn(flush_loop(Arc::downgrade(perf)));
    tokio::spawn(maintain_loop(Arc::downgrade(perf)));
}

async fn sample_loop(perf: Weak<Performance>) {
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut n: u32 = 0;
    loop {
        tick.tick().await;
        let Some(p) = perf.upgrade() else {
            return;
        };
        // A handful of proc_pidinfo / /proc reads: short blocking work off the async threads.
        let persist = n.is_multiple_of(PERSIST_EVERY);
        let done = tokio::task::spawn_blocking(move || p.sample_tick(persist)).await;
        if done.is_err() {
            tracing::warn!("resource sampler tick failed");
        }
        n = n.wrapping_add(1);
    }
}

impl Performance {
    /// The controllers to sample, and the workers whose latest report is fresh (sampled by pid,
    /// with the worker's own counters).
    fn sampled_now(&self, at_ms: i64) -> (Vec<ProcessIdentity>, Vec<WorkerNow>) {
        let state = self.state.lock();
        let controllers: Vec<ProcessIdentity> = state.controllers.keys().copied().collect();
        let workers: Vec<WorkerNow> = state
            .runtime
            .iter()
            .filter_map(|(id, rt)| {
                let (pid, generation) = (rt.pid?, rt.generation?);
                let latest = state
                    .windows
                    .get(id)
                    .and_then(|w| w.latest())
                    .filter(|p| p.generation == generation && at_ms - p.at_ms <= FRESH_MS)?;
                Some(WorkerNow {
                    instance: *id,
                    pid,
                    generation,
                    mono_ms: latest.mono_ms,
                    cpu_ns: latest.cpu_ns,
                    rss_bytes: latest.rss_bytes,
                })
            })
            .collect();
        drop(state);
        (controllers, workers)
    }

    /// Push `obs` into the in-memory windows (forgetting the stale ones) and return the rows to
    /// persist when `persist`.
    fn record(&self, obs: &[Observation], at_ms: i64, persist: bool) -> Vec<ResourceSample> {
        let mut rows = Vec::new();
        let mut state = self.state.lock();
        for o in obs {
            let key = format!(
                "{}|{}|{:?}",
                o.role.as_str(),
                o.identity.key(),
                o.generation
            );
            let entry = state.processes.entry(key).or_insert_with(|| ProcessEntry {
                window: ProcessWindow::new(
                    o.role,
                    o.identity.key(),
                    o.identity.pid,
                    Some(o.identity.start_unix_us),
                    o.instance_id,
                    o.generation,
                ),
                epoch: random_epoch(),
            });
            entry.window.push(ProcessPoint {
                at_ms,
                mono_ms: o.mono_ms,
                cpu_ns: o.cpu_ns,
                rss_bytes: o.rss_bytes,
                fd_count: o.fd_count,
            });
            if persist {
                rows.push(ResourceSample {
                    identity: ResourceIdentity {
                        role: o.role,
                        process_identity: o.identity.key(),
                        instance_id: o.instance_id,
                        generation: o.generation,
                        host_boot_id: self.boot_id.clone(),
                        counter_epoch: entry.epoch.clone(),
                    },
                    at_ms,
                    mono_ms: o.mono_ms,
                    cpu_ns: o.cpu_ns,
                    rss_bytes: o.rss_bytes,
                    fd_count: o.fd_count,
                });
            }
        }
        state.processes.retain(|_, e| {
            e.window
                .latest()
                .is_some_and(|p| at_ms - p.at_ms <= passive::LATENCY_WINDOW_MS.cast_signed())
        });
        if persist {
            state
                .windows
                .retain(|_, w| w.latest().is_some_and(|p| at_ms - p.at_ms <= FORGET_MS));
        }
        drop(state);
        rows
    }

    /// Sample every known process once.
    fn sample_tick(&self, persist: bool) {
        let at_ms = now_ms();
        let mono_ms = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut obs: Vec<Observation> = Vec::new();
        if let Some(me) = self.me {
            let s = resources::sample_self();
            obs.push(Observation {
                role: ProcessRole::Manager,
                identity: me,
                instance_id: None,
                generation: None,
                mono_ms,
                cpu_ns: Some(s.cpu_ns),
                rss_bytes: s.rss_bytes,
                fd_count: resources::fd_count_self(),
            });
        }
        let (controllers, workers) = self.sampled_now(at_ms);
        for id in controllers {
            // A controller that went away (or whose pid now belongs to another process) is skipped.
            if let Ok(s) = resources::sample_process(id.pid)
                && s.identity == id
            {
                obs.push(Observation {
                    role: ProcessRole::Controller,
                    identity: id,
                    instance_id: None,
                    generation: None,
                    mono_ms,
                    cpu_ns: Some(s.cpu_ns),
                    rss_bytes: s.rss_bytes,
                    fd_count: s.fd_count,
                });
            }
        }
        for w in workers {
            let (pid, generation) = (w.pid, w.generation);
            let known = self.state.lock().workers.get(&(pid, generation)).copied();
            let by_pid = resources::sample_process(pid).ok();
            let identity = match (known, by_pid) {
                (Some(id), Some(s)) if s.identity == id => id,
                // Gone, or the pid belongs to another process now: not this worker any more.
                (Some(_), _) | (None, None) => continue,
                (None, Some(s)) => {
                    let mut state = self.state.lock();
                    if state.workers.len() > 4_096 {
                        state.workers.clear();
                    }
                    state.workers.insert((pid, generation), s.identity);
                    drop(state);
                    s.identity
                }
            };
            obs.push(Observation {
                role: ProcessRole::Worker,
                identity,
                instance_id: Some(w.instance),
                generation: Some(generation),
                // The worker's own clock and counters: its CPU is differenced on its own clock.
                mono_ms: w.mono_ms,
                cpu_ns: w.cpu_ns,
                rss_bytes: w.rss_bytes,
                fd_count: by_pid.and_then(|s| s.fd_count),
            });
        }

        let rows = self.record(&obs, at_ms, persist);
        if !rows.is_empty() {
            self.persist.lock().push(rows);
        }
    }
}

async fn flush_loop(perf: Weak<Performance>) {
    let mut delay = FLUSH_EVERY;
    loop {
        tokio::time::sleep(delay).await;
        let Some(p) = perf.upgrade() else {
            return;
        };
        let (rows, dropped) = p.persist.lock().take();
        if rows.is_empty() && dropped.is_empty() {
            delay = FLUSH_EVERY;
            continue;
        }
        match p
            .store
            .resources_append(rows.clone(), dropped.clone())
            .await
        {
            Ok(()) => delay = FLUSH_EVERY,
            // Whatever failed (even a store that says it is closed), the next write is tried:
            // the loop ends only with the Performance Manager.
            Err(e) => {
                tracing::debug!(error = %e, "resource samples not stored yet; retrying");
                p.persist.lock().give_back(rows, dropped);
                delay = (delay * 2).min(FLUSH_BACKOFF_MAX);
            }
        }
    }
}

async fn maintain_loop(perf: Weak<Performance>) {
    let mut tick = tokio::time::interval(ROLLUP_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut retained: Option<std::time::Instant> = None;
    loop {
        tick.tick().await;
        let Some(p) = perf.upgrade() else {
            return;
        };
        if let Err(e) = p.store.resources_rollup(now_ms()).await {
            tracing::debug!(error = %e, "resource rollup deferred");
        }
        if retained.is_some_and(|t| t.elapsed() < RETAIN_EVERY) {
            continue;
        }
        let quota = p
            .store
            .settings()
            .await
            .map_or_default(|s| MetricsPolicy::from_settings(&s))
            .quota_bytes;
        match p.store.resources_retain(quota, now_ms()).await {
            Ok(r) => {
                retained = Some(std::time::Instant::now());
                if r.quota_deleted > 0 {
                    tracing::warn!(
                        deleted = r.quota_deleted,
                        "metrics disk quota reached; the oldest process samples were deleted early"
                    );
                }
            }
            Err(e) => tracing::debug!(error = %e, "resource retention deferred"),
        }
    }
}
