//! Bidirectional byte relay between a client connection and a tunnel stream, with live payload
//! counting, the connection's bandwidth caps, TCP half-close and an idle bound.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::time::Instant;
use vpn_platform::nobufs::Patient;

use crate::counters::{GatewayCounters, Held, TcpClass};
use crate::shaping::{Bucket, Direction, MAX_CHUNK, Shaper};

/// Per-direction relay buffer.
const BUF_SIZE: usize = MAX_CHUNK;

/// How often a relay whose write towards the tunnel makes no progress checks whether the client
/// reset its connection meanwhile. Reading on would tell, but the data has nowhere to go.
const RESET_CHECK: Duration = Duration::from_secs(1);

/// The read half of a client connection: besides reading, it can tell whether the client reset
/// the connection without reading from it (the pending socket error).
pub(super) trait ClientRead: AsyncRead + Unpin {
    fn reset(&mut self) -> Option<io::Error>;
}

impl ClientRead for OwnedReadHalf {
    fn reset(&mut self) -> Option<io::Error> {
        match self.as_ref().take_error() {
            Ok(pending) => pending,
            Err(e) => Some(e),
        }
    }
}

/// A client connection whose resets cannot be observed without reading (only reading finds them).
pub(super) struct Unobserved<R>(pub(super) R);

impl<R: AsyncRead + Unpin> AsyncRead for Unobserved<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin> ClientRead for Unobserved<R> {
    fn reset(&mut self) -> Option<io::Error> {
        None
    }
}

impl<R: ClientRead> ClientRead for Patient<R> {
    fn reset(&mut self) -> Option<io::Error> {
        self.get_mut().reset()
    }
}

/// Relay until both directions have finished. `first` is sent upstream before anything read from
/// the client (bytes the client sent along with its request). EOF in one direction shuts down the
/// write side towards the other peer (half-close) while the opposite direction keeps flowing; an
/// error in either direction ends both, so does `idle` without a byte relayed in either direction,
/// and so does a client reset noticed while the tunnel side takes no more data (a stuck flow
/// would otherwise hold the dead client connection until it recovered or timed out). Bytes are
/// counted as they are delivered: client → upstream as `payload_tx_bytes`, upstream → client as
/// `payload_rx_bytes`, and also as `ssh_*_bytes` when `class` is [`TcpClass::Ssh`] (an open SSH
/// session meanwhile, `ssh_sessions`) or `ssh_pull_*_bytes` when it is [`TcpClass::SshPull`].
/// Each direction passes its cap of `shaper` before it is written. The
/// client's socket waits out a host short of buffer space (`ENOBUFS`, see
/// [`vpn_platform::nobufs`]) instead of ending the relay.
pub(super) async fn splice<CR, CW, B>(
    (client_rx, client_tx): (CR, CW),
    first: &[u8],
    upstream: B,
    counters: &GatewayCounters,
    class: TcpClass,
    shaper: &Shaper,
    idle: Duration,
) -> io::Result<()>
where
    CR: ClientRead,
    CW: AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    // An SSH session is open while its relay runs.
    let _session = (class == TcpClass::Ssh).then(|| Held::new(&counters.ssh_sessions));
    let (mut client_rx, mut client_tx) = (Patient::new(client_rx), Patient::new(client_tx));
    let (mut upstream_rx, mut upstream_tx) = tokio::io::split(upstream);
    let started = Instant::now();
    // Milliseconds from `started` to the last delivered chunk, either direction.
    let last = AtomicU64::new(0);
    let touch = || {
        let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        last.store(ms, Ordering::Relaxed);
    };
    let up = shaper.bucket(Direction::Upload);
    let down = shaper.bucket(Direction::Download);
    let outbound = async {
        for piece in first.chunks(up.chunk().max(1)) {
            send_watching(&mut upstream_tx, piece, up, &mut client_rx).await?;
            counters.add_tx_as(class, piece.len() as u64);
            touch();
        }
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            let max = up.chunk().min(BUF_SIZE);
            let n = client_rx.read(&mut buf[..max]).await?;
            if n == 0 {
                // Propagate EOF. A peer that is already gone cannot be shut down; nothing is lost.
                let _ = upstream_tx.shutdown().await;
                return Ok(());
            }
            send_watching(&mut upstream_tx, &buf[..n], up, &mut client_rx).await?;
            counters.add_tx_as(class, n as u64);
            touch();
        }
    };
    let inbound = pump(&mut upstream_rx, &mut client_tx, down, |n| {
        counters.add_rx_as(class, n);
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
        relayed = async { tokio::try_join!(outbound, inbound).map(|_| ()) } => relayed,
        () = silent => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "relay idle in both directions for too long",
        )),
    }
}

/// Pass `data` through `cap` and write all of it; while that is stuck, check every
/// [`RESET_CHECK`] whether the client the data came from reset its connection, and give up if it
/// did.
async fn send_watching<W, C>(
    writer: &mut W,
    data: &[u8],
    cap: &Bucket,
    client: &mut C,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    C: ClientRead,
{
    let send = async {
        cap.acquire(data.len()).await;
        writer.write_all(data).await?;
        writer.flush().await
    };
    tokio::pin!(send);
    loop {
        tokio::select! {
            // A send that completes at once never arms the timer.
            biased;
            outcome = &mut send => return outcome,
            () = tokio::time::sleep(RESET_CHECK) => {
                if let Some(e) = client.reset() {
                    return Err(e);
                }
            }
        }
    }
}

/// Over the cap the bytes read wait in the buffer and nothing more is read meanwhile: the
/// sender's TCP window closes, so the cap is backpressure, never a loss.
async fn pump<R, W>(
    reader: &mut R,
    writer: &mut W,
    cap: &Bucket,
    count: impl Fn(u64),
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        let max = cap.chunk().min(BUF_SIZE);
        let n = reader.read(&mut buf[..max]).await?;
        if n == 0 {
            // Propagate EOF. A peer that is already gone cannot be shut down; nothing is lost.
            let _ = writer.shutdown().await;
            return Ok(());
        }
        cap.acquire(n).await;
        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
        count(n as u64);
    }
}
