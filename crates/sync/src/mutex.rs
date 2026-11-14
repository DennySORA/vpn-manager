//! The mutual exclusion lock.

use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::handover::{Handover, held};

/// `parking_lot::Mutex` under the workspace's hand-over schedule (see the crate documentation).
pub struct Mutex<T> {
    handover: Handover,
    inner: parking_lot::Mutex<T>,
}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            handover: Handover::new(),
            inner: parking_lot::Mutex::new(value),
        }
    }

    /// Wait for the lock. Dropping the guard releases it.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        let held = self.handover.acquire(
            |patience| self.inner.try_lock_for(patience),
            || self.inner.lock(),
        );
        MutexGuard {
            held: Some(held),
            handover: &self.handover,
        }
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// The held lock; dropping it unlocks.
#[must_use = "the lock is released as soon as the guard is dropped"]
#[derive(Debug)]
pub struct MutexGuard<'a, T> {
    /// `None` only once `drop` has taken it.
    held: Option<parking_lot::MutexGuard<'a, T>>,
    handover: &'a Handover,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        held(self.held.as_deref())
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        held(self.held.as_deref_mut())
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.handover
            .release(&mut self.held, parking_lot::MutexGuard::unlock_fair);
    }
}
