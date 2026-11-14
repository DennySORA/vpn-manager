//! Bandwidth caps of one connection: a token bucket per direction.
//!
//! Download = destination → client, upload = client → destination; the buckets are shared by
//! every Gateway of the worker. Over the cap a
//! TCP relay waits before it writes, so it stops reading and TCP's own backpressure reaches the
//! sender: no stream data is dropped and nothing takes another path. A UDP datagram over the cap
//! is dropped and counted. A datagram larger than the whole burst (a full-size QUIC or RTP packet
//! under a slow cap) passes when the bucket is full and leaves its excess as debt: later traffic
//! waits it out, so the long-run rate stays the cap and no datagram size is refused for good. DNS
//! and the private management connector are not payload and are not capped.
//!
//! Each bucket schedules in virtual time (GCRA): `empty_at` is when the bucket would hold no
//! tokens after everything granted so far. `n` bytes are granted at
//! `max(empty_at, now − BURST) + n / rate`, so waiters pass in the order they asked, the long-run
//! rate is exact, and after an idle period at most `BURST` worth of the rate passes at once. The
//! state is a handful of integers however many relays wait (each holds one chunk at most).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;
use vpn_domain::BandwidthCaps;
use vpn_ipc::worker::ShapingWire;
use vpn_sync::Mutex;

/// Credit an idle bucket builds up: 50 ms of its rate.
const BURST_NS: u64 = 50_000_000;
/// Pauses between two waits up to this long still count as waiting (see `State::waited`).
const BRIDGE_NS: u64 = 5_000_000;
/// Largest piece a relay passes at once (the relay buffer), and the smallest; in between a piece
/// is about 20 ms of the rate, so a slow cap paces smoothly instead of in large steps.
pub const MAX_CHUNK: usize = 16 * 1024;
const MIN_CHUNK: usize = 1024;

/// One direction's cap.
pub struct Bucket {
    state: Mutex<State>,
    /// Waiters re-decide under a changed cap (or go at once when it was removed).
    changed: Notify,
    dropped: AtomicU64,
}

struct State {
    /// Bits per second; `None`: no cap.
    bps: Option<u64>,
    origin: Instant,
    /// Nanoseconds after `origin` at which the bucket is empty given what was granted.
    empty_at: u64,
    /// Union of the intervals during which someone waited (ns), up to `busy_until`.
    busy: u64,
    busy_until: u64,
}

impl State {
    fn now(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// Time `n` bytes take at `bps`, rounded up.
    fn cost(n: usize, bps: u64) -> u64 {
        let ns = (n as u128 * 8 * 1_000_000_000).div_ceil(u128::from(bps.max(1)));
        u64::try_from(ns).unwrap_or(u64::MAX)
    }

    /// Where a grant made `now` starts: the bucket's credit is `now − start`, at most `BURST`.
    fn start(&self, now: u64) -> u64 {
        self.empty_at.max(now.saturating_sub(BURST_NS))
    }

    /// When `n` bytes would be granted now (not taken).
    fn grant_at(&self, n: usize, bps: u64, now: u64) -> u64 {
        self.start(now).saturating_add(Self::cost(n, bps))
    }

    /// Someone waits from `now` until `until`: add what the union of waits does not hold yet. A
    /// relay asks again a moment after its turn (timer granularity, its own write); a pause
    /// shorter than `BRIDGE_NS` between two waits counts as waiting too, so a cap that binds all
    /// the time reads as binding all the time.
    const fn waited(&mut self, now: u64, until: u64) {
        if until <= now {
            return;
        }
        // Continue the union from where it ends when that is now, later, or just before.
        let from = if self.busy > 0 && now <= self.busy_until.saturating_add(BRIDGE_NS) {
            self.busy_until
        } else {
            now
        };
        if until > from {
            self.busy += until - from;
            self.busy_until = until;
        }
    }

    /// Waiting time that has passed by `now` (a wait in progress counts up to now).
    const fn waited_by(&self, now: u64) -> u64 {
        self.busy
            .saturating_sub(self.busy_until.saturating_sub(now))
    }
}

impl Bucket {
    fn new(bps: Option<u64>) -> Self {
        Self {
            state: Mutex::new(State {
                bps,
                origin: Instant::now(),
                empty_at: 0,
                busy: 0,
                busy_until: 0,
            }),
            changed: Notify::new(),
            dropped: AtomicU64::new(0),
        }
    }

    pub fn cap(&self) -> Option<u64> {
        self.state.lock().bps
    }

    /// A new cap (or none). Waiters decide again under it; the bucket starts empty.
    fn set(&self, bps: Option<u64>) {
        let mut s = self.state.lock();
        if s.bps == bps {
            return;
        }
        let now = s.now();
        // Only time that has passed stays counted as waiting.
        s.busy = s.waited_by(now);
        s.busy_until = now;
        s.empty_at = now;
        s.bps = bps;
        drop(s);
        self.changed.notify_waiters();
    }

    /// How many bytes a relay should read before asking for them (about 20 ms of the cap).
    pub fn chunk(&self) -> usize {
        self.cap().map_or(MAX_CHUNK, |bps| {
            usize::try_from(bps / 8 / 50)
                .unwrap_or(MAX_CHUNK)
                .clamp(MIN_CHUNK, MAX_CHUNK)
        })
    }

    /// Wait until `n` bytes may pass (at once without a cap).
    pub async fn acquire(&self, n: usize) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            // Registered before the state is read: a change made right after is not missed.
            changed.as_mut().enable();
            let until = {
                let mut s = self.state.lock();
                let Some(bps) = s.bps else { return };
                let now = s.now();
                let at = s.grant_at(n, bps, now);
                s.empty_at = at;
                s.waited(now, at);
                if at <= now {
                    return;
                }
                s.origin + Duration::from_nanos(at)
            };
            tokio::select! {
                () = tokio::time::sleep_until(until) => return,
                () = &mut changed => {}
            }
        }
    }

    /// Take `n` bytes now if the cap allows them (UDP); otherwise the datagram is dropped and
    /// counted. A datagram that costs more than the whole burst passes when the bucket is full,
    /// and what it costs beyond the credit is debt (`empty_at` lies ahead of now): nothing else
    /// passes until it is paid, so the long-run rate is still the cap.
    pub fn try_take(&self, n: usize) -> bool {
        let mut s = self.state.lock();
        let Some(bps) = s.bps else { return true };
        let now = s.now();
        let start = s.start(now);
        let credit = now.saturating_sub(start);
        let cost = State::cost(n, bps);
        if cost <= credit || credit >= BURST_NS {
            s.empty_at = start.saturating_add(cost);
            return true;
        }
        drop(s);
        self.dropped.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Milliseconds during which someone waited for this cap so far.
    pub fn wait_ms(&self) -> u64 {
        let s = self.state.lock();
        s.waited_by(s.now()) / 1_000_000
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Which way payload flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Destination → client.
    Download,
    /// Client → destination.
    Upload,
}

/// The connection's caps, one bucket per direction.
pub struct Shaper {
    download: Bucket,
    upload: Bucket,
}

impl Shaper {
    #[must_use]
    pub fn new(caps: BandwidthCaps) -> Arc<Self> {
        Arc::new(Self {
            download: Bucket::new(caps.download_bps),
            upload: Bucket::new(caps.upload_bps),
        })
    }

    /// No caps (tests, and a worker configured without them).
    #[must_use]
    pub fn unlimited() -> Arc<Self> {
        Self::new(BandwidthCaps::default())
    }

    pub const fn bucket(&self, direction: Direction) -> &Bucket {
        match direction {
            Direction::Download => &self.download,
            Direction::Upload => &self.upload,
        }
    }

    /// Replace the caps; relays waiting now decide again under the new ones.
    pub fn set(&self, caps: BandwidthCaps) {
        self.download.set(caps.download_bps);
        self.upload.set(caps.upload_bps);
    }

    pub fn caps(&self) -> BandwidthCaps {
        BandwidthCaps {
            download_bps: self.download.cap(),
            upload_bps: self.upload.cap(),
        }
    }

    /// The caps and their cumulative effect, for the status report.
    pub fn wire(&self) -> ShapingWire {
        ShapingWire {
            caps: self.caps(),
            download_wait_ms: self.download.wait_ms(),
            upload_wait_ms: self.upload.wait_ms(),
            download_dropped: self.download.dropped(),
            upload_dropped: self.upload.dropped(),
        }
    }

    /// An owned wait for `n` bytes (for a body that polls instead of awaiting).
    pub fn acquire_owned(
        self: &Arc<Self>,
        direction: Direction,
        n: usize,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let me = Arc::clone(self);
        Box::pin(async move { me.bucket(direction).acquire(n).await })
    }
}
