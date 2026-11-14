//! Test-only `TunnelConnector` that dials host **loopback** sockets, so DNS and Gateway logic can
//! be unit-tested against local fixture servers without a `WireGuard` tunnel.
//!
//! Compiled only with the `testing` feature (enabled for this crate's own tests). It refuses
//! every non-loopback destination, so even a misconfigured test cannot reach the network.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::net::{TcpStream, UdpSocket};
use vpn_tunnel::{FlowClass, TunnelConnector, TunnelDatagram};

/// Loopback connector with a switchable "gate" to exercise `PermissionDenied` paths.
#[derive(Clone, Default)]
pub struct LoopbackConnector {
    closed: Arc<AtomicBool>,
    /// When set, IPv6 destinations report `NetworkUnreachable` (tunnel without IPv6).
    pub no_ipv6: bool,
}

impl LoopbackConnector {
    pub fn set_closed(&self, closed: bool) {
        self.closed.store(closed, Ordering::SeqCst);
    }

    fn admit(&self, dst: SocketAddr, class: FlowClass) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) && class == FlowClass::Payload {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "gate closed",
            ));
        }
        if self.no_ipv6 && dst.is_ipv6() {
            return Err(io::Error::new(io::ErrorKind::NetworkUnreachable, "no ipv6"));
        }
        if !dst.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test connector only dials loopback",
            ));
        }
        Ok(())
    }
}

pub struct LoopbackDatagram(UdpSocket, LoopbackConnector);

impl TunnelDatagram for LoopbackDatagram {
    async fn send_to(&self, data: &[u8], dst: SocketAddr) -> io::Result<()> {
        self.1.admit(dst, FlowClass::Control)?;
        self.0.send_to(data, dst).await.map(|_| ())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }
}

impl TunnelConnector for LoopbackConnector {
    type Stream = TcpStream;
    type Datagram = LoopbackDatagram;

    async fn connect_tcp(&self, dst: SocketAddr, class: FlowClass) -> io::Result<TcpStream> {
        self.admit(dst, class)?;
        TcpStream::connect(dst).await
    }

    fn bind_udp(&self, class: FlowClass) -> io::Result<LoopbackDatagram> {
        if self.closed.load(Ordering::SeqCst) && class == FlowClass::Payload {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "gate closed",
            ));
        }
        let std = std::net::UdpSocket::bind("127.0.0.1:0")?;
        std.set_nonblocking(true)?;
        Ok(LoopbackDatagram(UdpSocket::from_std(std)?, self.clone()))
    }

    fn supports(&self, ip: IpAddr) -> bool {
        !(self.no_ipv6 && ip.is_ipv6())
    }
}
