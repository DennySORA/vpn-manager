//! `AppEndpoint`: the worker's only host-side connection. Every other flow of the worker goes
//! into the tunnel; this one goes to the loopback port a managed App of the same connection
//! holds, and only while the manager's lease says the App's process tree holds it.
//!
//! It cannot be pointed anywhere else: an endpoint exists only for a loopback address and an
//! unprivileged port, and it only ever connects (TCP) or sends (UDP, from a socket bound on the
//! same loopback family and connected to the endpoint) to exactly that address. In Linux strict
//! mode the worker runs inside the connection's network namespace, so the same loopback address
//! is the sandbox's own.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::{TcpStream, UdpSocket};

/// A managed App's loopback port, as a lease grants it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppEndpoint(SocketAddr);

impl AppEndpoint {
    /// `None` unless `addr` is a loopback address with a port ≥ 1024 (what an App may hold;
    /// the manager never grants anything else).
    #[must_use]
    pub fn new(addr: SocketAddr) -> Option<Self> {
        let ip = addr.ip().to_canonical();
        (ip.is_loopback() && addr.port() >= 1024).then_some(Self(SocketAddr::new(ip, addr.port())))
    }

    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.0
    }

    /// Connect to the App, bounded by `within`.
    ///
    /// # Errors
    ///
    /// `TimedOut` if the App does not accept within `within`; otherwise the connect error.
    pub async fn connect(&self, within: Duration) -> io::Result<TcpStream> {
        let stream = tokio::time::timeout(within, TcpStream::connect(self.0))
            .await
            .map_err(|_elapsed| {
                io::Error::new(io::ErrorKind::TimedOut, "the App did not accept in time")
            })??;
        // Forwarded application streams: latency over coalescing, as in the tunnel.
        if let Err(e) = stream.set_nodelay(true) {
            tracing::debug!(error = %e, "TCP_NODELAY not set on a connection to an App");
        }
        // Bounded kernel buffers, as for a Gateway's clients.
        if let Err(e) =
            vpn_platform::nobufs::fix_buffers(&stream, vpn_platform::nobufs::LOOPBACK_BUFFER)
        {
            tracing::debug!(error = %e, "buffers of a connection to an App not fixed");
        }
        Ok(stream)
    }

    /// A UDP socket for one inbound flow: bound on loopback, connected to the App (so only the
    /// App's own port can answer through it).
    ///
    /// # Errors
    ///
    /// Fails if the loopback socket cannot be bound or connected to the App.
    pub async fn udp(&self) -> io::Result<UdpSocket> {
        let local: SocketAddr = match self.0.ip() {
            IpAddr::V4(_) => (Ipv4Addr::LOCALHOST, 0).into(),
            IpAddr::V6(_) => (Ipv6Addr::LOCALHOST, 0).into(),
        };
        let socket = UdpSocket::bind(local).await?;
        socket.connect(self.0).await?;
        Ok(socket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_and_unprivileged_ports_make_an_endpoint() {
        for ok in ["127.0.0.1:8080", "[::1]:1024", "127.0.0.2:65535"] {
            assert!(AppEndpoint::new(ok.parse().unwrap()).is_some(), "{ok}");
        }
        for bad in [
            "127.0.0.1:80",
            "0.0.0.0:8080",
            "10.99.0.2:8080",
            "192.168.1.5:8080",
            "[::]:8080",
            "[fe80::1]:8080",
            "8.8.8.8:8080",
        ] {
            assert!(AppEndpoint::new(bad.parse().unwrap()).is_none(), "{bad}");
        }
        // A mapped loopback address is the IPv4 one.
        let mapped = AppEndpoint::new("[::ffff:127.0.0.1]:8080".parse().unwrap()).unwrap();
        assert_eq!(mapped.addr(), "127.0.0.1:8080".parse().unwrap());
    }
}
