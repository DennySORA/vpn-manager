//! The reader-writer lock.

use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::handover::{Handover, held};

/// `parking_lot::RwLock` under the workspace's hand-over schedule (see the crate documentation).
///
/// As in `parking_lot`, a waiting writer goes before new readers, so a thread must not take the
/// read lock twice.
pub struct RwLock<T> {
    handover: Handover,
    inner: parking_lot::RwLock<T>,
}

impl<T> RwLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            handover: Handover::new(),
            inner: parking_lot::RwLock::new(value),
        }
    }

    /// Wait for shared access. Dropping the guard releases it.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        let held = self.handover.acquire(
            |patience| self.inner.try_read_for(patience),
            || self.inner.read(),
        );
        RwLockReadGuard {
            held: Some(held),
            handover: &self.handover,
        }
    }

    /// Wait for exclusive access. Dropping the guard releases it.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        let held = self.handover.acquire(
            |patience| self.inner.try_write_for(patience),
            || self.inner.write(),
        );
        RwLockWriteGuard {
            held: Some(held),
            handover: &self.handover,
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for RwLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// Shared access; dropping it unlocks.
#[must_use = "the lock is released as soon as the guard is dropped"]
#[derive(Debug)]
pub struct RwLockReadGuard<'a, T> {
    /// `None` only once `drop` has taken it.
    held: Option<parking_lot::RwLockReadGuard<'a, T>>,
    handover: &'a Handover,
}

impl<T> Deref for RwLockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        held(self.held.as_deref())
    }
}

impl<T> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        self.handover
            .release(&mut self.held, parking_lot::RwLockReadGuard::unlock_fair);
    }
}

/// Exclusive access; dropping it unlocks.
#[must_use = "the lock is released as soon as the guard is dropped"]
#[derive(Debug)]
pub struct RwLockWriteGuard<'a, T> {
    /// `None` only once `drop` has taken it.
    held: Option<parking_lot::RwLockWriteGuard<'a, T>>,
    handover: &'a Handover,
}

impl<T> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        held(self.held.as_deref())
    }
}

impl<T> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        held(self.held.as_deref_mut())
    }
}

impl<T> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.handover
            .release(&mut self.held, parking_lot::RwLockWriteGuard::unlock_fair);
    }
}
