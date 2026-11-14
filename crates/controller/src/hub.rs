//! Event hub for `/v1/events` (SSE): a bounded ring buffer and a broadcast.
//!
//! The ring buffer serves `Last-Event-ID` resume within the same controller boot, and the
//! broadcast live delivery. Slow clients get
//! `resync_required` and are disconnected instead of slowing anyone down.
//!
//! An event gets its id, enters the ring and is broadcast under one lock, and a stream starts
//! (subscribes and reads what to replay) under the same lock: a reconnecting client receives
//! every event after its last one exactly once — replayed or live, never both, never neither.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use vpn_domain::{InstanceId, LiveRates, ServerEvent, Timestamp};
use vpn_sync::Mutex;

const RING: usize = 1024;
/// Live events a stream may fall behind by before it is told to resync and closed.
pub const LIVE_QUEUE: usize = 256;
/// Live rate points kept per Instance for instant charts (≈ 10 minutes at 1/s).
const LIVE_POINTS: usize = 600;

#[derive(Clone, Debug)]
pub struct Envelope {
    pub id: String,
    pub event: Arc<ServerEvent>,
}

/// How a new stream starts.
#[derive(Debug)]
pub enum Resume {
    /// No `Last-Event-ID`: live events only.
    Fresh,
    /// The events after the client's last one, then live events.
    Replay(Vec<Envelope>),
    /// Its last event is from another boot, malformed, or no longer buffered: the client must
    /// reload its snapshots.
    Resync,
}

struct Ring {
    seq: u64,
    events: VecDeque<Envelope>,
}

pub struct Hub {
    boot: String,
    ring: Mutex<Ring>,
    tx: broadcast::Sender<Envelope>,
    live: Mutex<HashMap<InstanceId, VecDeque<LiveRates>>>,
    /// Cancelled at shutdown: open event streams end so a graceful stop does not wait on them.
    closing: CancellationToken,
}

impl std::fmt::Debug for Hub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hub")
            .field("boot", &self.boot)
            .finish_non_exhaustive()
    }
}

fn seq_of(id: &str) -> Option<u64> {
    id.split_once(':')?.1.parse().ok()
}

impl Hub {
    #[must_use]
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(LIVE_QUEUE);
        Arc::new(Self {
            boot: format!("{:x}", Timestamp::now().unix_millis()),
            ring: Mutex::new(Ring {
                seq: 0,
                events: VecDeque::with_capacity(RING),
            }),
            tx,
            live: Mutex::new(HashMap::new()),
            closing: CancellationToken::new(),
        })
    }

    /// End every open event stream (controller shutdown).
    pub fn close(&self) {
        self.closing.cancel();
    }

    pub fn closing(&self) -> CancellationToken {
        self.closing.clone()
    }

    /// Never waits on a client: the broadcast drops what a slow stream did not take.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the id, the ring and the broadcast change under one lock (see `resume`)"
    )]
    pub fn publish(&self, event: ServerEvent) {
        if let ServerEvent::LiveRates { rates } = &event {
            let mut live = self.live.lock();
            let q = live.entry(rates.instance_id).or_default();
            if q.len() == LIVE_POINTS {
                q.pop_front();
            }
            q.push_back(rates.clone());
            drop(live);
        }
        let mut ring = self.ring.lock();
        ring.seq += 1;
        let env = Envelope {
            id: format!("{}:{}", self.boot, ring.seq),
            event: Arc::new(event),
        };
        if ring.events.len() == RING {
            ring.events.pop_front();
        }
        ring.events.push_back(env.clone());
        // Under the ring's lock, so a stream that starts meanwhile gets it once (see `resume`).
        if self.tx.send(env).is_err() {
            // No stream is open: only the ring keeps it, for a stream that resumes later.
            tracing::trace!("event kept in the ring only: no live stream");
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Envelope> {
        self.tx.subscribe()
    }

    /// Start a stream: a live subscription and what to send before it, decided under the lock
    /// that orders every event, so nothing is sent twice or missed in between.
    pub fn resume(&self, last_id: Option<&str>) -> (broadcast::Receiver<Envelope>, Resume) {
        let ring = self.ring.lock();
        let rx = self.tx.subscribe();
        let resume = last_id.map_or(Resume::Fresh, |last| {
            self.replay_locked(&ring, last)
                .map_or(Resume::Resync, Resume::Replay)
        });
        (rx, resume)
    }

    /// Events after `last_id`, or `None` when it is from another boot or no longer buffered
    /// (the client must reload snapshots).
    fn replay_locked(&self, ring: &Ring, last_id: &str) -> Option<Vec<Envelope>> {
        let (boot, seq) = last_id.split_once(':')?;
        if boot != self.boot {
            return None;
        }
        let seq: u64 = seq.parse().ok()?;
        // An id this boot never gave out.
        if seq > ring.seq {
            return None;
        }
        let first = match ring.events.front() {
            Some(e) => seq_of(&e.id)?,
            // Nothing buffered: only an id of nothing (0) is still in sequence.
            None => return (seq == ring.seq).then(Vec::new),
        };
        if seq + 1 < first {
            return None;
        }
        Some(
            ring.events
                .iter()
                .filter(|e| seq_of(&e.id).is_some_and(|s| s > seq))
                .cloned()
                .collect(),
        )
    }

    pub fn live(&self, id: InstanceId) -> Vec<LiveRates> {
        self.live
            .lock()
            .get(&id)
            .map_or_default(|q| q.iter().cloned().collect())
    }

    pub fn forget(&self, id: InstanceId) {
        self.live.lock().remove(&id);
    }
}
