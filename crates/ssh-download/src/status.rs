//! What a job is doing, as the manager reports it: one board per job that the runner and its
//! workers update, a snapshot of it as `SshDownloadStatus`, and a publisher that sends at most one
//! status per job and second (a change is never lost: the latest state goes out after the pause).

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use vpn_domain::{
    Counter, SshDownloadActive, SshDownloadHostKey, SshDownloadJobId, SshDownloadState,
    SshDownloadStatus, SshDownloadStep, Text, Timestamp,
};
use vpn_store::StoredHostKey;
use vpn_sync::Mutex;

use crate::wire::Wire;

/// Statuses go out at most this often per job.
pub const PUBLISH_EVERY: Duration = Duration::from_secs(1);
/// Rates are measured over this window.
const RATE_WINDOW: Duration = Duration::from_secs(8);

/// Sends a job's status to whoever shows it (the manager's event stream).
pub type Publish = Arc<dyn Fn(SshDownloadStatus) + Send + Sync>;

/// A reason the user reads, with its stable code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    pub code: String,
    pub message: Text,
}

impl Reason {
    pub fn new(code: impl Into<String>, message: impl Into<Text>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// A file being worked on: its progress lives in atomics the transfer bumps without a lock.
pub struct Active {
    pub id: String,
    pub name: String,
    pub started_at: Timestamp,
    step: Mutex<SshDownloadStep>,
    done: AtomicU64,
    /// `u64::MAX` while unknown.
    total: AtomicU64,
    resumed_from: AtomicU64,
    attempt: AtomicU32,
    /// Connections that serve its reads: its own, and those that help.
    connections: AtomicU32,
    samples: Mutex<VecDeque<(Instant, u64)>>,
}

/// A connection that helps a file, counted on the board until it goes.
pub struct Joined(Arc<Active>);

impl Drop for Joined {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Active {
    fn new(id: &str, name: &str, step: SshDownloadStep, attempt: u32) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            started_at: Timestamp::now(),
            step: Mutex::new(step),
            done: AtomicU64::new(0),
            total: AtomicU64::new(u64::MAX),
            resumed_from: AtomicU64::new(0),
            attempt: AtomicU32::new(attempt.max(1)),
            connections: AtomicU32::new(1),
            samples: Mutex::new(VecDeque::new()),
        }
    }

    pub fn set_step(&self, step: SshDownloadStep) {
        *self.step.lock() = step;
    }

    /// A new attempt starts at `from` of `total` bytes.
    pub fn begin(&self, from: u64, total: u64) {
        self.resumed_from.store(from, Ordering::Relaxed);
        self.done.store(from, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        self.samples.lock().clear();
    }

    pub fn add(&self, n: u64) {
        self.done.fetch_add(n, Ordering::Relaxed);
    }

    pub fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }

    /// Where the current attempt started.
    pub fn resumed_from(&self) -> u64 {
        self.resumed_from.load(Ordering::Relaxed)
    }

    /// Another connection serves this file's reads until the guard drops.
    pub fn joined(self: &Arc<Self>) -> Joined {
        self.connections.fetch_add(1, Ordering::Relaxed);
        Joined(self.clone())
    }

    /// Connections that help this file now.
    pub fn helpers(&self) -> u32 {
        self.connections.load(Ordering::Relaxed).saturating_sub(1)
    }

    fn view(&self, now: Instant) -> SshDownloadActive {
        let done = self.done();
        let total = self.total.load(Ordering::Relaxed);
        let total = (total != u64::MAX).then_some(total);
        #[expect(
            clippy::cast_precision_loss,
            reason = "a byte count as f64 for a rate shown to the user; precision past 2^52 bytes is irrelevant"
        )]
        let rate = {
            let mut s = self.samples.lock();
            s.push_back((now, done));
            while s.len() > 64
                || s.front()
                    .is_some_and(|(t, _)| now.duration_since(*t) > RATE_WINDOW)
            {
                s.pop_front();
            }
            match (s.front(), s.back()) {
                (Some((t0, b0)), Some((t1, b1)))
                    if t1.duration_since(*t0) >= Duration::from_millis(900) =>
                {
                    Some(b1.saturating_sub(*b0) as f64 / t1.duration_since(*t0).as_secs_f64())
                }
                _ => None,
            }
        };
        #[expect(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "an ETA in seconds for display: the quotient is positive (r > 0) and saturates on overflow"
        )]
        let eta = match (rate, total) {
            (Some(r), Some(t)) if r > 0.0 => {
                Some((t.saturating_sub(done) as f64 / r).ceil() as u64)
            }
            _ => None,
        };
        SshDownloadActive {
            transfer_id: self.id.clone(),
            name: self.name.clone(),
            step: *self.step.lock(),
            bytes_done: Counter(done),
            bytes_total: total.map(Counter),
            resumed_from: Counter(self.resumed_from.load(Ordering::Relaxed)),
            rate_bps: rate,
            eta_secs: eta,
            attempt: self.attempt.load(Ordering::Relaxed),
            connections: self.connections.load(Ordering::Relaxed),
            started_at: self.started_at,
        }
    }
}

/// Everything a job's status is computed from.
#[derive(Default)]
pub struct Board {
    pub connections_max: u32,
    pub paused: bool,
    /// Stopped until the user acts (or, with `next_retry_at`, until it is checked again).
    pub error: Option<Reason>,
    /// The Gateway cannot carry traffic now.
    pub waiting: Option<Reason>,
    /// A failure that may pass.
    pub retrying: Option<Reason>,
    pub next_retry_at: Option<Timestamp>,
    /// A transfer still waiting for its own local storage operation to recover.
    pub local_retrying: Option<Reason>,
    pub local_next_retry_at: Option<Timestamp>,
    pub connecting: u32,
    pub sessions: u32,
    pub scanning: bool,
    pub queued: u32,
    pub queue_truncated: bool,
    pub unfinished: u32,
    pub active: Vec<Arc<Active>>,
    pub last_scan_at: Option<Timestamp>,
    pub next_scan_at: Option<Timestamp>,
    pub last_scan_skipped: u32,
    pub completed: u32,
    pub failed: u32,
    pub bytes: u64,
    pub host_key: Option<SshDownloadHostKey>,
    pub offered_host_key: Option<SshDownloadHostKey>,
    /// When this run of the job started (its folder and credentials were ready).
    pub running_since: Option<Timestamp>,
}

impl Board {
    /// What the job does, the most pressing first: a stop for the user, a pause, transfers,
    /// waiting for the VPN, listing, connecting, a retry, nothing.
    pub const fn state(&self) -> SshDownloadState {
        use SshDownloadState::{
            Connecting, Downloading, Error, Idle, Paused, Retrying, Scanning, WaitingVpn,
        };
        if self.error.is_some() {
            Error
        } else if self.paused {
            Paused
        } else if !self.active.is_empty() {
            Downloading
        } else if self.waiting.is_some() {
            WaitingVpn
        } else if self.scanning {
            Scanning
        } else if self.connecting > 0 {
            Connecting
        } else if self.retrying.is_some() || self.local_retrying.is_some() {
            Retrying
        } else {
            Idle
        }
    }

    /// Forget what only a running job has (it stopped).
    pub fn stopped(&mut self) {
        self.waiting = None;
        self.retrying = None;
        self.next_retry_at = None;
        self.local_retrying = None;
        self.local_next_retry_at = None;
        self.connecting = 0;
        self.sessions = 0;
        self.scanning = false;
        self.queued = 0;
        self.queue_truncated = false;
        self.active.clear();
        self.next_scan_at = None;
        self.running_since = None;
    }
}

pub fn host_key_view(k: &StoredHostKey) -> SshDownloadHostKey {
    SshDownloadHostKey {
        algorithm: k.algorithm.clone(),
        fingerprint: k.fingerprint.clone(),
        seen_at: Timestamp::from_unix_millis(k.seen_ms).unwrap_or_else(Timestamp::now),
    }
}

/// One job's board and the signal that it changed.
pub struct StatusCell {
    pub job_id: SshDownloadJobId,
    board: Mutex<Board>,
    dirty: Notify,
    /// What the job's SSH connections carried (counted without the board's lock).
    pub wire: Wire,
}

/// Removes a file from the board when its work ends, whatever way it ends.
pub struct ActiveGuard {
    cell: Arc<StatusCell>,
    pub active: Arc<Active>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        let id = self.active.id.clone();
        self.cell.update(|b| b.active.retain(|a| a.id != id));
    }
}

impl StatusCell {
    pub fn new(job_id: SshDownloadJobId, board: Board) -> Arc<Self> {
        Arc::new(Self {
            job_id,
            board: Mutex::new(board),
            dirty: Notify::new(),
            wire: Wire::default(),
        })
    }

    /// Change the board; the publisher sends the new status (within a second).
    pub fn update<T>(&self, f: impl FnOnce(&mut Board) -> T) -> T {
        let out = f(&mut self.board.lock());
        self.dirty.notify_one();
        out
    }

    /// Progress moved (no board change): a new status goes out with the next tick.
    pub fn touch(&self) {
        self.dirty.notify_one();
    }

    pub fn read<T>(&self, f: impl FnOnce(&Board) -> T) -> T {
        f(&self.board.lock())
    }

    /// A file starts its work: on the board until the guard drops.
    pub fn begin(
        self: &Arc<Self>,
        id: &str,
        name: &str,
        step: SshDownloadStep,
        attempt: u32,
    ) -> ActiveGuard {
        let active = Arc::new(Active::new(id, name, step, attempt));
        self.update(|b| {
            b.active.retain(|a| a.id != id);
            b.active.push(active.clone());
        });
        ActiveGuard {
            cell: self.clone(),
            active,
        }
    }

    pub fn snapshot(&self) -> SshDownloadStatus {
        let now = Instant::now();
        let (wire_rx, wire_tx) = self.wire.totals();
        let rates = self.wire.rates(now);
        let b = self.board.lock();
        let reason = b
            .error
            .as_ref()
            .or(if b.paused { None } else { b.waiting.as_ref() })
            .or(if b.paused { None } else { b.retrying.as_ref() })
            .or(if b.paused {
                None
            } else {
                b.local_retrying.as_ref()
            });
        SshDownloadStatus {
            job_id: self.job_id,
            state: b.state(),
            reason: reason.map(|r| r.message.clone()),
            reason_code: reason.map(|r| r.code.clone()),
            connections: b.sessions,
            connections_max: b.connections_max,
            queued: b.queued,
            queue_truncated: b.queue_truncated,
            unfinished: b.unfinished,
            active: b.active.iter().map(|a| a.view(now)).collect(),
            last_scan_at: b.last_scan_at,
            next_scan_at: if b.paused || b.error.is_some() {
                None
            } else {
                b.next_scan_at
            },
            last_scan_skipped: b.last_scan_skipped,
            next_retry_at: if b.paused {
                None
            } else if b.error.is_some() || b.waiting.is_some() || b.retrying.is_some() {
                b.next_retry_at
            } else {
                b.local_next_retry_at
            },
            completed: b.completed,
            failed: b.failed,
            bytes: Counter(b.bytes),
            host_key: b.host_key.clone(),
            offered_host_key: b.offered_host_key.clone(),
            wire_rx_bytes: Counter(wire_rx),
            wire_tx_bytes: Counter(wire_tx),
            wire_rx_bps: rates.map(|r| r.0),
            wire_tx_bps: rates.map(|r| r.1),
            running_since: if b.paused || b.error.is_some() {
                None
            } else {
                b.running_since
            },
            observed_at: Timestamp::now(),
        }
    }

    /// Publish the job's status whenever it changed, at most once per `every`, until `stop`. While
    /// the last status showed traffic it goes out every `every` regardless, so the rate shown
    /// falls to 0 once the traffic stops.
    pub async fn publish_loop(
        self: Arc<Self>,
        publish: Publish,
        every: Duration,
        stop: CancellationToken,
    ) {
        let mut moving = false;
        loop {
            if !moving {
                tokio::select! {
                    () = stop.cancelled() => return,
                    () = self.dirty.notified() => {}
                }
            }
            let status = self.snapshot();
            moving = [status.wire_rx_bps, status.wire_tx_bps]
                .into_iter()
                .any(|r| r.is_some_and(|r| r > 0.0));
            publish(status);
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(every) => {}
            }
        }
    }
}
