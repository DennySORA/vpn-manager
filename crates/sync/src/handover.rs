//! When an unlock hands the lock over.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// How long a thread waits for a lock like any other.
///
/// Until then it takes its chance with the rest: an unlock leaves the lock to whoever asks
/// first, which is what keeps a lock fast. Past it the thread is starved, and for as long as any
/// thread is, every unlock hands the lock to the thread that has been in the queue longest. The
/// lock then runs first come, first served, until everybody gets it within this time again.
///
/// `parking_lot` handed a contended lock over at a random 0 to 1 ms before 0.13. At a quarter of
/// a millisecond a waiter's median is what it was then and its worst case about half; the
/// measurements are in docs/architecture.md §2.
const PATIENCE: Duration = Duration::from_micros(250);

/// What a guard says when it is used after its `drop` gave the lock up, which cannot happen.
pub const HELD: &str = "a guard holds its lock until it is dropped";

/// The hand-over schedule of one lock: the threads that have waited [`PATIENCE`] for it and do
/// not have it yet.
///
/// The waiting thread keeps the time, so a thread that unlocks only reads this count.
pub struct Handover {
    starved: AtomicU32,
}

impl Handover {
    pub const fn new() -> Self {
        Self {
            starved: AtomicU32::new(0),
        }
    }

    /// Take the lock: `patient` waits for it up to the given time, `blocking` for as long as it
    /// takes. A thread whose patience runs out is starved until it has the lock.
    pub fn acquire<G>(
        &self,
        patient: impl FnOnce(Duration) -> Option<G>,
        blocking: impl FnOnce() -> G,
    ) -> G {
        patient(PATIENCE).unwrap_or_else(|| {
            self.starved.fetch_add(1, Ordering::Relaxed);
            let held = blocking();
            self.starved.fetch_sub(1, Ordering::Relaxed);
            held
        })
    }

    /// Unlock: `hand_over` the guard while a thread is starved, otherwise drop it, which leaves
    /// the lock to whoever asks first. A guard calls this from its `drop`, the one place `held`
    /// is emptied.
    pub fn release<G>(&self, held: &mut Option<G>, hand_over: impl FnOnce(G)) {
        let Some(held) = held.take() else { return };
        if self.starved.load(Ordering::Relaxed) == 0 {
            drop(held);
        } else {
            hand_over(held);
        }
    }
}
