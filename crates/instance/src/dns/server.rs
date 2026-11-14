//! The Instance's resolver as a DNS server for the Apps of a strict sandbox.
//!
//! It answers on 127.0.0.53:53 (UDP and TCP) inside the sandbox — the address its
//! `resolv.conf` names — with the Instance's own resolver, so every App query is resolved
//! through the tunnel or not at all.
//!
//! The sockets are bound by the sandbox holder (port 53 needs the namespace's root; the worker
//! never is) and handed over. Queries are answered only while the payload gate is open;
//! otherwise at once with REFUSED, like a Gateway refuses connections. Bounded: concurrent UDP
//! queries, TCP connections, queries per TCP connection, idle time and message size.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use vpn_tunnel::TunnelConnector;

use super::{DnsResolver, ResolveError, wire};

/// UDP queries answered at once; more are answered SERVFAIL immediately.
const MAX_UDP_IN_FLIGHT: usize = 256;
/// TCP connections served at once; more are closed at accept.
const MAX_TCP_CONNECTIONS: usize = 64;
/// Queries served on one TCP connection.
const MAX_TCP_QUERIES: usize = 100;
/// A TCP connection without a complete query for this long is closed.
const TCP_IDLE: Duration = Duration::from_secs(10);

/// Whether the Instance admits App traffic right now (the payload gate is open).
pub type GateOpen = Arc<dyn Fn() -> bool + Send + Sync>;

/// A running DNS server. Dropping it stops it.
pub struct DnsServer {
    cancel: CancellationToken,
    tracker: TaskTracker,
}

impl DnsServer {
    /// Serve on the given sockets (std, switched to non-blocking here). Spawns on the current
    /// Tokio runtime.
    ///
    /// # Errors
    ///
    /// Fails if either socket cannot be switched to non-blocking mode or registered with the
    /// Tokio runtime.
    pub fn spawn<C: TunnelConnector>(
        udp: std::net::UdpSocket,
        tcp: std::net::TcpListener,
        resolver: DnsResolver<C>,
        open: GateOpen,
    ) -> io::Result<Self> {
        udp.set_nonblocking(true)?;
        tcp.set_nonblocking(true)?;
        let udp = Arc::new(UdpSocket::from_std(udp)?);
        let tcp = TcpListener::from_std(tcp)?;
        let cancel = CancellationToken::new();
        let tracker = TaskTracker::new();
        tracker.spawn(cancel.clone().run_until_cancelled_owned(serve_udp(
            udp,
            resolver.clone(),
            open.clone(),
        )));
        tracker.spawn(cancel.clone().run_until_cancelled_owned(serve_tcp(
            tcp,
            resolver,
            open,
            tracker.clone(),
            cancel.clone(),
        )));
        Ok(Self { cancel, tracker })
    }

    /// Stop serving; returns once every query task has ended.
    pub async fn shutdown(self) {
        let tracker = self.tracker.clone();
        drop(self);
        tracker.wait().await;
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tracker.close();
    }
}

/// The answer to one raw query: the resolver's, SERVFAIL when it failed, REFUSED while the gate
/// is closed. `None` for anything that is not a query.
async fn answer<C: TunnelConnector>(
    resolver: &DnsResolver<C>,
    open: &GateOpen,
    query: &[u8],
) -> Option<Vec<u8>> {
    if !open() {
        return wire::error_response(query, ResponseCode::Refused);
    }
    match resolver.query_message(query).await {
        Ok(response) => Some(response),
        Err(ResolveError::InvalidName) => None,
        Err(_) => wire::error_response(query, ResponseCode::ServFail),
    }
}

async fn serve_udp<C: TunnelConnector>(
    socket: Arc<UdpSocket>,
    resolver: DnsResolver<C>,
    open: GateOpen,
) {
    let slots = Arc::new(Semaphore::new(MAX_UDP_IN_FLIGHT));
    let mut buf = vec![0u8; 65_535];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf).await else {
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        let query = buf[..n].to_vec();
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            if let Some(r) = wire::error_response(&query, ResponseCode::ServFail) {
                let _ = socket.send_to(&r, from).await;
            }
            continue;
        };
        let (socket, resolver, open) = (socket.clone(), resolver.clone(), open.clone());
        tokio::spawn(async move {
            let _permit = permit;
            reply_udp(&socket, &resolver, &open, &query, from).await;
        });
    }
}

async fn reply_udp<C: TunnelConnector>(
    socket: &UdpSocket,
    resolver: &DnsResolver<C>,
    open: &GateOpen,
    query: &[u8],
    to: SocketAddr,
) {
    let Some(mut response) = answer(resolver, open, query).await else {
        return;
    };
    if response.len() > wire::udp_limit(query) {
        match wire::truncated(&response) {
            Some(cut) => response = cut,
            None => return,
        }
    }
    let _ = socket.send_to(&response, to).await;
}

async fn serve_tcp<C: TunnelConnector>(
    listener: TcpListener,
    resolver: DnsResolver<C>,
    open: GateOpen,
    tracker: TaskTracker,
    cancel: CancellationToken,
) {
    let slots = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let (resolver, open) = (resolver.clone(), open.clone());
        tracker.spawn(cancel.clone().run_until_cancelled_owned(async move {
            let _permit = permit;
            serve_connection(stream, &resolver, &open).await;
        }));
    }
}

/// RFC 7766: two-byte length prefix, several queries per connection, answered in order.
async fn serve_connection<C: TunnelConnector>(
    mut stream: TcpStream,
    resolver: &DnsResolver<C>,
    open: &GateOpen,
) {
    for _ in 0..MAX_TCP_QUERIES {
        let mut len = [0u8; 2];
        let read = async {
            stream.read_exact(&mut len).await?;
            let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
            stream.read_exact(&mut query).await?;
            Ok::<_, io::Error>(query)
        };
        let Ok(Ok(query)) = tokio::time::timeout(TCP_IDLE, read).await else {
            return;
        };
        let Some(response) = answer(resolver, open, &query).await else {
            return;
        };
        let Ok(n) = u16::try_from(response.len()) else {
            return;
        };
        let mut framed = Vec::with_capacity(2 + response.len());
        framed.extend_from_slice(&n.to_be_bytes());
        framed.extend_from_slice(&response);
        if stream.write_all(&framed).await.is_err() {
            return;
        }
    }
}
