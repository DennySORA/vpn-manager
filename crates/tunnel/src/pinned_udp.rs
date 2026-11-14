//! `WireGuard` underlay transport for `GotaTun`.
//!
//! The underlay is the only host socket an Instance worker owns that can reach the network, so it
//! is deliberately narrow:
//! - [`PeerPolicy::Pinned`]: datagrams are only sent to, and only accepted from, the configured
//!   peer endpoint(s). `GotaTun`'s endpoint roaming (an incoming handshake overwrites the endpoint)
//!   therefore cannot redirect encrypted traffic to an arbitrary address.
//! - [`PeerPolicy::AcceptAny`] exists only for the in-process test peer (`vpn-labpeer`), which acts
//!   as a server bound to loopback and learns its client's address from the handshake.
//!
//! The socket can be bound on demand, or handed in already open (Linux strict mode creates it in
//! the host network namespace before the worker enters its private namespace).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use gotatun::packet::{Packet, PacketBufPool};
use gotatun::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};
use vpn_sync::RwLock;

/// Which remote addresses the underlay may talk to.
#[derive(Debug, Clone)]
pub enum PeerPolicy {
    /// Only these exact endpoints (numeric IP + port).
    Pinned(Vec<SocketAddr>),
    /// Any remote address. Test peer only; never used by a product Instance.
    AcceptAny,
}

impl PeerPolicy {
    fn allows(&self, addr: SocketAddr) -> bool {
        let addr = canonical(addr);
        match self {
            Self::Pinned(endpoints) => endpoints.iter().any(|e| canonical(*e) == addr),
            Self::AcceptAny => true,
        }
    }
}

const fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// How the underlay socket is obtained.
#[derive(Debug, Clone)]
pub enum UdpSource {
    /// Bind a fresh socket on every (re)bind. `None` binds the unspecified address of the family
    /// required by the pinned endpoint, on an ephemeral port.
    Bind(Option<SocketAddr>),
    /// Duplicate this already-bound socket on every (re)bind.
    Preopened(Arc<std::net::UdpSocket>),
}

/// Underlay counters (`WireGuard` datagrams, not inner payload).
#[derive(Debug, Default)]
pub struct UnderlayStats {
    pub tx_datagrams: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_datagrams: AtomicU64,
    pub rx_bytes: AtomicU64,
    /// Datagrams `GotaTun` tried to send somewhere other than the pinned peer.
    pub blocked_tx: AtomicU64,
    /// Datagrams received from an address other than the pinned peer.
    pub blocked_rx: AtomicU64,
    /// Datagrams the host refused to send for lack of buffer space (`ENOBUFS`, which macOS
    /// returns under a burst instead of blocking): dropped, as a congested link would drop them.
    pub tx_dropped: AtomicU64,
}

impl UnderlayStats {
    /// Account for one send of `len` bytes. A send refused for lack of buffer space loses that
    /// datagram and nothing else: it is counted as dropped and reported as done, so the device
    /// carries on and `WireGuard` and the flows inside recover it like any lost packet (an error
    /// would also make `GotaTun` drop the rest of a batch). Other errors pass on.
    fn sent(&self, result: io::Result<usize>, len: u64) -> io::Result<()> {
        match result {
            Ok(_) => {
                self.tx_datagrams.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes.fetch_add(len, Ordering::Relaxed);
                Ok(())
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                let dropped = self.tx_dropped.fetch_add(1, Ordering::Relaxed) + 1;
                // A burst can mean thousands: say so at the 1st, 2nd, 4th, 8th, ... drop.
                if dropped.is_power_of_two() {
                    tracing::info!(
                        dropped,
                        "underlay datagram dropped: the host is out of buffer space (ENOBUFS)"
                    );
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

/// [`UdpTransportFactory`] enforcing a [`PeerPolicy`].
#[derive(Debug)]
pub struct PinnedUdpFactory {
    source: UdpSource,
    policy: Arc<RwLock<PeerPolicy>>,
    stats: Arc<UnderlayStats>,
}

impl PinnedUdpFactory {
    pub fn new(source: UdpSource, policy: PeerPolicy, stats: Arc<UnderlayStats>) -> Self {
        Self {
            source,
            policy: Arc::new(RwLock::new(policy)),
            stats,
        }
    }

    fn bind_addr(&self, params: &UdpTransportFactoryParams) -> SocketAddr {
        if let UdpSource::Bind(Some(addr)) = &self.source {
            *addr
        } else {
            // Bind the family of the pinned peer so no IPv4-mapped IPv6 handling is needed.
            let v6 = matches!(&*self.policy.read(), PeerPolicy::Pinned(e) if e.first().is_some_and(SocketAddr::is_ipv6));
            let ip: IpAddr = if v6 {
                Ipv6Addr::UNSPECIFIED.into()
            } else {
                Ipv4Addr::UNSPECIFIED.into()
            };
            SocketAddr::new(ip, params.port)
        }
    }
}

impl UdpTransportFactory for PinnedUdpFactory {
    type Send = PinnedUdpSocket;
    type Recv = PinnedUdpSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(Self::Send, Self::Recv)> {
        let std_socket = match &self.source {
            UdpSource::Preopened(sock) => sock.try_clone()?,
            UdpSource::Bind(_) => bind_again(self.bind_addr(params)).await?,
        };
        std_socket.set_nonblocking(true)?;
        let socket = Arc::new(tokio::net::UdpSocket::from_std(std_socket)?);
        let pinned = PinnedUdpSocket {
            socket,
            policy: self.policy.clone(),
            stats: self.stats.clone(),
        };
        Ok((pinned.clone(), pinned))
    }
}

/// How long a bind to a port in use is retried: `GotaTun` binds the same port again when it
/// rebuilds its connection (suspend, then resume), while the previous socket can still be held by
/// `GotaTun`'s buffered send and receive tasks that have not been dropped yet; Linux reports that as
/// `EADDRINUSE` for a moment. A port held by another program still fails, only this much later.
const REBIND_WAIT: Duration = Duration::from_secs(2);

async fn bind_again(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let deadline = tokio::time::Instant::now() + REBIND_WAIT;
    loop {
        match std::net::UdpSocket::bind(addr) {
            Err(e)
                if e.kind() == io::ErrorKind::AddrInUse
                    && addr.port() != 0
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            other => return other,
        }
    }
}

/// One bound underlay socket.
#[derive(Debug, Clone)]
pub struct PinnedUdpSocket {
    socket: Arc<tokio::net::UdpSocket>,
    policy: Arc<RwLock<PeerPolicy>>,
    stats: Arc<UnderlayStats>,
}

impl UdpSend for PinnedUdpSocket {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        if !self.policy.read().allows(destination) {
            self.stats.blocked_tx.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%destination, "underlay send to non-pinned endpoint dropped");
            return Ok(());
        }
        let len = packet.len() as u64;
        let sent = self.socket.send_to(&packet, destination).await;
        self.stats.sent(sent, len)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.socket.local_addr().map(Some)
    }
}

impl UdpRecv for PinnedUdpSocket {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        loop {
            let mut buf = pool.get();
            let (n, source) = self.socket.recv_from(&mut buf).await?;
            if !self.policy.read().allows(source) {
                self.stats.blocked_rx.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            buf.truncate(n);
            self.stats.rx_datagrams.fetch_add(1, Ordering::Relaxed);
            self.stats.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
            return Ok((buf, canonical(source)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_policy_matches_canonical_forms_only() {
        let peer: SocketAddr = "198.51.100.7:51820".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:198.51.100.7]:51820".parse().unwrap();
        let policy = PeerPolicy::Pinned(vec![peer]);
        assert!(policy.allows(peer));
        assert!(
            policy.allows(mapped),
            "IPv4-mapped form of the pinned peer is the same peer"
        );
        assert!(!policy.allows("198.51.100.7:51821".parse().unwrap()));
        assert!(!policy.allows("203.0.113.1:51820".parse().unwrap()));
    }
}
