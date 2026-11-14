//! What a job's SSH connections carry on the wire: every byte of the stream to the Gateway (SSH
//! framing and encryption included — what that Gateway counts as its payload for them), and its
//! rate. Server → us is `rx`, us → server is `tx`.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use vpn_sync::Mutex;

use crate::status::StatusCell;

/// A rate is measured against a sample at least this old.
const RATE_MIN: Duration = Duration::from_secs(1);
/// Samples kept to measure against (statuses are taken about once a second).
const SAMPLES: usize = 16;

/// The bytes since the manager started the job, and the samples its rate is measured from.
#[derive(Default)]
pub struct Wire {
    rx: AtomicU64,
    tx: AtomicU64,
    rates: Mutex<Rates>,
}

#[derive(Default)]
struct Rates {
    /// `(when, rx, tx)`, oldest first.
    samples: VecDeque<(Instant, u64, u64)>,
    last: Option<(f64, f64)>,
}

impl Wire {
    pub fn add_rx(&self, n: u64) {
        self.rx.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_tx(&self, n: u64) {
        self.tx.fetch_add(n, Ordering::Relaxed);
    }

    /// `(rx, tx)` bytes so far.
    pub fn totals(&self) -> (u64, u64) {
        (
            self.rx.load(Ordering::Relaxed),
            self.tx.load(Ordering::Relaxed),
        )
    }

    /// `(rx, tx)` bytes per second at `now`, against the newest sample at least a second old
    /// (statuses go out about once a second, so over the last one to two seconds); the last
    /// measured rate while there is none, and `None` until one was measured.
    pub fn rates(&self, now: Instant) -> Option<(f64, f64)> {
        let (rx, tx) = self.totals();
        let mut r = self.rates.lock();
        if let Some(i) = r
            .samples
            .iter()
            .rposition(|(t, ..)| now.saturating_duration_since(*t) >= RATE_MIN)
        {
            let (t0, rx0, tx0) = r.samples[i];
            let secs = now.duration_since(t0).as_secs_f64();
            #[expect(
                clippy::cast_precision_loss,
                reason = "a byte count as f64 for a rate shown to the user; precision past 2^52 bytes is irrelevant"
            )]
            let per_sec = |a: u64, b: u64| a.saturating_sub(b) as f64 / secs;
            r.last = Some((per_sec(rx, rx0), per_sec(tx, tx0)));
            r.samples.drain(..i);
        }
        r.samples.push_back((now, rx, tx));
        while r.samples.len() > SAMPLES {
            r.samples.pop_front();
        }
        r.last
    }
}

/// A job's SSH stream to its Gateway, counting what passes on the job's board.
pub struct Counted<S> {
    inner: S,
    cell: Arc<StatusCell>,
}

impl<S> Counted<S> {
    pub const fn new(inner: S, cell: Arc<StatusCell>) -> Self {
        Self { inner, cell }
    }

    fn sent(&self, n: usize) {
        if n > 0 {
            self.cell.wire.add_tx(n as u64);
            self.cell.touch();
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        let n = buf.filled().len().saturating_sub(before);
        if matches!(polled, Poll::Ready(Ok(()))) && n > 0 {
            this.cell.wire.add_rx(n as u64);
            this.cell.touch();
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = polled {
            this.sent(n);
        }
        polled
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = polled {
            this.sent(n);
        }
        polled
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
