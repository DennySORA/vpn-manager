//! Exclusive advisory file locks (`flock`).
//!
//! The kernel releases them when the holding process dies, which makes a successfully acquired lock
//! proof that no previous holder is alive — even one that was re-parented away from a crashed
//! manager.
#![allow(
    unsafe_code,
    reason = "the single-instance lock calls flock(2) via libc"
)]

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub struct FileLock {
    _file: File,
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("lock is held by another live process")]
    Held,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl FileLock {
    /// Try to take the lock without waiting.
    ///
    /// # Errors
    ///
    /// [`LockError::Held`] when another holder has the lock, [`LockError::Io`] when the file cannot
    /// be opened (including a symlink) or `flock` fails otherwise.
    pub fn try_acquire(path: &Path) -> Result<Self, LockError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        // SAFETY: flock on a descriptor we own.
        let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if r == 0 {
            Ok(Self { _file: file })
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                Err(LockError::Held)
            } else {
                Err(err.into())
            }
        }
    }

    /// Wait (polling) up to `timeout` for the lock.
    ///
    /// # Errors
    ///
    /// [`LockError::Held`] when the lock is still held at the deadline, or any other error of
    /// [`Self::try_acquire`] at once.
    pub async fn acquire_within(
        path: &Path,
        timeout: std::time::Duration,
    ) -> Result<Self, LockError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match Self::try_acquire(path) {
                Err(LockError::Held) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                other => return other,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_holder_is_refused_until_release() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.lock");
        let a = FileLock::try_acquire(&p).unwrap();
        assert!(matches!(FileLock::try_acquire(&p), Err(LockError::Held)));
        drop(a);
        // Another test thread's child may hold a copy of the descriptor between fork and
        // exec for a moment (it is close-on-exec); callers wait for that, and so do we.
        let mut taken = FileLock::try_acquire(&p);
        for _ in 0..200 {
            if taken.is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            taken = FileLock::try_acquire(&p);
        }
        assert!(taken.is_ok());
    }
}
