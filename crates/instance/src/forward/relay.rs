//! Bidirectional relay between a forwarded inbound connection and its App: half-close, live byte
//! counts and an idle bound. (Forward payload is not subject to the Gateways' bandwidth caps.)

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use vpn_platform::nobufs::Patient;

use super::APP_CONNECT_TIMEOUT;
use crate::counters::{ForwardCounters, RelayedCounters};

/// Per-direction relay buffer.
const BUF_SIZE: usize = 16 * 1024;

/// Relay until both directions have finished. EOF in one direction shuts down the write side
/// towards the other end (half-close) while the opposite direction keeps flowing; an error in
/// either direction ends both, and so does `idle` without a byte relayed either way. Bytes are
/// counted as delivered: remote → App as `bytes_in`, App → remote as `bytes_out`, and in the
/// generation's total of every forward (`relayed`). The App's socket waits out a host short of
/// buffer space (`ENOBUFS`) instead of ending the relay.
///
/// `header` (a PROXY protocol header, or empty) goes to the App whole before a single byte is
/// relayed in either direction, within [`APP_CONNECT_TIMEOUT`]: taking it is part of accepting
/// the connection. It is not payload: neither counter includes it.
pub(super) async fn relay<A, B>(
    remote: A,
    app: B,
    header: &[u8],
    counters: &ForwardCounters,
    relayed: &RelayedCounters,
    idle: Duration,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut app = Patient::new(app);
    if !header.is_empty() {
        // A fresh connection takes a few dozen bytes at once; the bound is for an App that
        // does not.
        let sent = tokio::time::timeout(APP_CONNECT_TIMEOUT, async {
            app.write_all(header).await?;
            app.flush().await
        });
        sent.await.map_err(|_elapsed| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "the App did not take the PROXY header in time",
            )
        })??;
    }
    let (mut remote_rx, mut remote_tx) = tokio::io::split(remote);
    let (mut app_rx, mut app_tx) = tokio::io::split(app);
    let started = Instant::now();
    // Milliseconds from `started` to the last delivered chunk, either direction.
    let last = AtomicU64::new(0);
    let touch = || {
        let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        last.store(ms, Ordering::Relaxed);
    };
    let inbound = pump(&mut remote_rx, &mut app_tx, |n| {
        counters.bytes_in.fetch_add(n, Ordering::Relaxed);
        relayed.rx_bytes.fetch_add(n, Ordering::Relaxed);
        touch();
    });
    let outbound = pump(&mut app_rx, &mut remote_tx, |n| {
        counters.bytes_out.fetch_add(n, Ordering::Relaxed);
        relayed.tx_bytes.fetch_add(n, Ordering::Relaxed);
        touch();
    });
    let silent = async {
        loop {
            let deadline = started + Duration::from_millis(last.load(Ordering::Relaxed)) + idle;
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    };
    tokio::select! {
        relayed = async { tokio::try_join!(inbound, outbound).map(|_| ()) } => relayed,
        () = silent => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "relay idle in both directions for too long",
        )),
    }
}

async fn pump<R, W>(reader: &mut R, writer: &mut W, count: impl Fn(u64)) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            // Propagate EOF. A peer that is already gone cannot be shut down; nothing is lost.
            if let Err(e) = writer.shutdown().await {
                tracing::trace!(error = %e, "EOF not passed on: the peer is gone");
            }
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
        count(n as u64);
    }
}
