//! Host sockets that run out of kernel buffer space.
//!
//! Under a burst of traffic macOS refuses reads and writes on perfectly healthy loopback TCP and
//! Unix sockets with `ENOBUFS` ("No buffer space available") until its network buffers (mbufs)
//! free up again; Linux can do the same, more rarely. That is a passing shortage, not the end of
//! the connection. [`Patient`] wraps a socket (or one half of it) and, on `ENOBUFS`, waits and
//! tries the same read or write again — 1 ms, doubling up to 50 ms — and passes the error on only
//! after [`GIVE_UP`] without any progress, so a socket that really stays unusable still ends.
//! Every other result, errors included, passes through unchanged.
//!
//! The shortage is not left to chance either: [`fix_buffers`] bounds what one loopback
//! connection can hold of the host's network memory.
#![allow(
    unsafe_code,
    reason = "the ENOBUFS-aware socket buffer sizing calls getsockopt/setsockopt via libc"
)]

use std::future::Future;
use std::io;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// How long a socket may keep refusing for lack of buffer space, without any progress, before
/// the error is passed on.
pub const GIVE_UP: Duration = Duration::from_secs(30);
const FIRST_WAIT: Duration = Duration::from_millis(1);
const LONGEST_WAIT: Duration = Duration::from_millis(50);
/// At most one log line about waits this often (process-wide).
const LOG_EVERY_MS: u64 = 10_000;

/// Waits taken for `ENOBUFS` by this process so far.
static WAITS: AtomicU64 = AtomicU64::new(0);
/// Process clock (ms) of the last log line about them, plus one (0: never).
static LOGGED_AT: AtomicU64 = AtomicU64::new(0);

/// Waits taken for `ENOBUFS` by this process so far.
pub fn waits() -> u64 {
    WAITS.load(Ordering::Relaxed)
}

/// Kernel buffer, each way, of a loopback connection the product relays.
///
/// The relayed connections are a Gateway's client and a port forward's App. The size is ample for a
/// loopback round trip at any rate the tunnel carries, and a bound on what one connection holds of
/// the host's network memory.
pub const LOOPBACK_BUFFER: u32 = 128 * 1024;

/// Fix a socket's kernel receive and send buffers at `bytes` each.
///
/// That also stops the host from growing them by itself: on macOS each loopback connection whose
/// reader is slower than its writer (a relay waiting on the tunnel) otherwise grows to 4 MiB each
/// way, and a few hundred of them take the host's whole network memory (about 0.5 GB), after which
/// sockets everywhere on the host, other programs' too, fail with `ENOBUFS`.
///
/// # Errors
///
/// Fails with the OS error when `setsockopt` refuses either buffer size.
pub fn fix_buffers(socket: &impl AsRawFd, bytes: u32) -> io::Result<()> {
    let value = libc::c_int::try_from(bytes).unwrap_or(libc::c_int::MAX);
    for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
        // SAFETY: `setsockopt` reads `size_of::<c_int>()` bytes from `value`, which lives across
        // the call; the descriptor is borrowed from a live socket.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "size_of::<c_int>() is 4, which socklen_t holds"
        )]
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw const value).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Whether `e` says the host had no buffer space for the operation (`ENOBUFS`).
#[must_use]
pub fn is_no_buffer_space(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENOBUFS)
}

fn process_ms() -> u64 {
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Count one wait; say so in the log now and then (a burst can mean thousands).
fn note_wait() {
    let waits = WAITS.fetch_add(1, Ordering::Relaxed) + 1;
    let now = process_ms() + 1;
    let last = LOGGED_AT.load(Ordering::Relaxed);
    if (last == 0 || now >= last + LOG_EVERY_MS)
        && LOGGED_AT
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::info!(
            waits,
            "host socket out of buffer space (ENOBUFS): waiting it out instead of failing"
        );
    }
}

/// The waits of one direction of a socket.
#[derive(Default)]
struct Backoff {
    sleep: Option<Pin<Box<Sleep>>>,
    wait: Duration,
    /// The first `ENOBUFS` since the last progress.
    since: Option<Instant>,
}

impl Backoff {
    /// After an `ENOBUFS`: arm the next wait, or hand the error back after [`GIVE_UP`] without
    /// progress.
    fn after(&mut self, e: io::Error) -> io::Result<()> {
        let now = Instant::now();
        let since = *self.since.get_or_insert(now);
        if now.duration_since(since) >= GIVE_UP {
            *self = Self::default();
            return Err(e);
        }
        self.wait = if self.wait.is_zero() {
            FIRST_WAIT
        } else {
            (self.wait * 2).min(LONGEST_WAIT)
        };
        self.sleep = Some(Box::pin(tokio::time::sleep(self.wait)));
        note_wait();
        Ok(())
    }

    const fn progressed(&mut self) {
        self.since = None;
        self.wait = Duration::ZERO;
    }

    /// Ready once a pending wait is over (at once when there is none).
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(s) = self.sleep.as_mut() {
            ready!(s.as_mut().poll(cx));
            self.sleep = None;
        }
        Poll::Ready(())
    }

    /// The outcome of one attempt: `None` to wait and try again.
    fn judge<R>(&mut self, attempt: Poll<io::Result<R>>) -> Option<Poll<io::Result<R>>> {
        match attempt {
            Poll::Ready(Err(e)) if is_no_buffer_space(&e) => match self.after(e) {
                Ok(()) => None,
                Err(e) => Some(Poll::Ready(Err(e))),
            },
            Poll::Ready(Ok(v)) => {
                self.progressed();
                Some(Poll::Ready(Ok(v)))
            }
            other => Some(other),
        }
    }
}

/// A host socket, or one half of it, whose reads and writes wait out `ENOBUFS` (see the module
/// documentation).
pub struct Patient<T> {
    inner: T,
    read: Backoff,
    write: Backoff,
}

impl<T> Patient<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            read: Backoff::default(),
            write: Backoff::default(),
        }
    }

    pub const fn get_ref(&self) -> &T {
        &self.inner
    }

    pub const fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Patient<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            ready!(me.read.poll_ready(cx));
            let attempt = Pin::new(&mut me.inner).poll_read(cx, buf);
            if let Some(done) = me.read.judge(attempt) {
                return done;
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Patient<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        loop {
            ready!(me.write.poll_ready(cx));
            let attempt = Pin::new(&mut me.inner).poll_write(cx, buf);
            if let Some(done) = me.write.judge(attempt) {
                return done;
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            ready!(me.write.poll_ready(cx));
            let attempt = Pin::new(&mut me.inner).poll_flush(cx);
            if let Some(done) = me.write.judge(attempt) {
                return done;
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            ready!(me.write.poll_ready(cx));
            let attempt = Pin::new(&mut me.inner).poll_shutdown(cx);
            if let Some(done) = me.write.judge(attempt) {
                return done;
            }
        }
    }
}
