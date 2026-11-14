//! SOCKS5 UDP ASSOCIATE: a relay between one loopback client and one tunnel UDP socket.
//!
//! Lifecycle: the association lives while its controlling TCP connection is open and traffic
//! flows; it ends when that connection closes, after `udp_idle_timeout` without a relayed
//! datagram, when the tunnel socket closes, or on Gateway shutdown. Ending it closes the control
//! connection too.
//!
//! The relay socket is the only host UDP socket here. It is bound on the client's loopback
//! address, accepts datagrams only from the client's IP and port (the port is pinned from
//! `DST.PORT` when given, otherwise from the first datagram) and sends only to that client.
//! Everything else travels through the tunnel socket from `TunnelConnector::bind_udp`.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;
use vpn_tunnel::{FlowClass, TunnelConnector, TunnelDatagram};

use super::connect::{ConnectError, Host};
use super::socks5::{self, Address};
use super::{Gauge, Shared, udp_associations_active};
use crate::dns::{Family, Resolve};
use crate::shaping::Direction;

/// Largest datagram read in either direction.
const MAX_DATAGRAM: usize = 64 * 1024;
/// Resolved addresses considered per datagram with a domain destination.
const MAX_CANDIDATES: usize = 8;

pub(super) async fn associate<C: TunnelConnector, R: Resolve>(
    shared: &Arc<Shared<C, R>>,
    mut control: TcpStream,
    peer: SocketAddr,
    client_port: u16,
) {
    let Ok(_slot) = Arc::clone(&shared.udp_associations).try_acquire_owned() else {
        shared.counters.tcp_rejected.fetch_add(1, Ordering::Relaxed);
        return socks5::refuse(control, socks5::REP_GENERAL_FAILURE).await;
    };
    let tunnel = match shared.connector.bind_udp(FlowClass::Payload) {
        Ok(socket) => socket,
        Err(e) => {
            let error = ConnectError::from_io(&e);
            if error.is_refusal() {
                shared.counters.tcp_rejected.fetch_add(1, Ordering::Relaxed);
            }
            tracing::debug!(gateway = %shared.config.id, ?error, "UDP ASSOCIATE refused");
            return socks5::refuse(control, socks5::reply_code(&error)).await;
        }
    };
    let client_ip = peer.ip().to_canonical();
    let relay = match shared.relays.bind(client_ip).await {
        Ok(relay) => relay,
        Err(e) => {
            tracing::debug!(gateway = %shared.config.id, error = %e, "UDP relay socket unavailable");
            return socks5::refuse(control, socks5::REP_GENERAL_FAILURE).await;
        }
    };
    let Ok(bind) = relay.local_addr() else {
        return socks5::refuse(control, socks5::REP_GENERAL_FAILURE).await;
    };
    if vpn_platform::nobufs::Patient::new(&mut control)
        .write_all(&socks5::reply(socks5::REP_SUCCEEDED, bind))
        .await
        .is_err()
    {
        return;
    }
    let _active = Gauge::new(&shared.counters, udp_associations_active);
    let mut association = Association {
        shared,
        tunnel,
        relay,
        client_ip,
        expected_port: (client_port != 0).then_some(client_port),
        client: None,
    };
    let (reason, error_kind) = match association.run(&mut control).await {
        End::ControlClosed => ("control connection closed", None),
        End::IdleTimeout => ("idle timeout", None),
        End::TunnelClosed(kind) => ("tunnel socket closed", Some(kind)),
        End::RelayFailed(kind) => ("relay socket failed", Some(kind)),
    };
    tracing::debug!(gateway = %shared.config.id, reason, ?error_kind, "UDP association ended");
}

/// How long a strict worker waits for the manager to hand over a relay socket.
const RELAY_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Where the relay sockets of SOCKS5 UDP associations come from.
#[derive(Clone, Default)]
pub enum RelaySockets {
    /// Bound right here: this process shares the host's loopback (the userspace netstack).
    #[default]
    Local,
    /// Made by the Instance Manager in the host's network namespace: a strict worker lives in
    /// its sandbox's namespace, whose loopback no client of the Gateway can reach.
    Manager(tokio::sync::mpsc::Sender<RelayRequest>),
}

/// A request for one relay socket bound on `client_ip`, port 0.
pub struct RelayRequest {
    pub client_ip: IpAddr,
    pub reply: tokio::sync::oneshot::Sender<io::Result<std::net::UdpSocket>>,
}

impl RelaySockets {
    /// Relay socket on the client's loopback address; refuses anything that is not loopback.
    async fn bind(&self, client_ip: IpAddr) -> io::Result<UdpSocket> {
        if !client_ip.is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP relay only binds loopback addresses",
            ));
        }
        let requests = match self {
            Self::Local => return UdpSocket::bind(SocketAddr::new(client_ip, 0)).await,
            Self::Manager(requests) => requests,
        };
        let (reply, answer) = tokio::sync::oneshot::channel();
        requests
            .try_send(RelayRequest { client_ip, reply })
            .map_err(|_| io::Error::other("too many relay requests waiting"))?;
        let socket = tokio::time::timeout(RELAY_REQUEST_TIMEOUT, answer)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no relay socket in time"))?
            .map_err(|_| io::Error::other("relay request dropped"))??;
        // Whatever arrives must be what was asked for: a socket on the client's loopback.
        if socket.local_addr()?.ip().to_canonical() != client_ip {
            return Err(io::Error::other("relay socket bound elsewhere"));
        }
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    }
}

struct Association<'a, C: TunnelConnector, R> {
    shared: &'a Shared<C, R>,
    tunnel: C::Datagram,
    relay: UdpSocket,
    client_ip: IpAddr,
    /// `DST.PORT` of the request, when the client named it.
    expected_port: Option<u16>,
    /// The client's address, pinned on its first accepted datagram.
    client: Option<SocketAddr>,
}

enum End {
    ControlClosed,
    IdleTimeout,
    TunnelClosed(io::ErrorKind),
    RelayFailed(io::ErrorKind),
}

enum Event {
    Control(io::Result<usize>),
    Idle,
    FromClient(io::Result<(usize, SocketAddr)>),
    FromTunnel(io::Result<(usize, SocketAddr)>),
}

enum Outcome {
    Relayed,
    Dropped,
    TunnelClosed(io::ErrorKind),
}

impl<C: TunnelConnector, R: Resolve> Association<'_, C, R> {
    async fn run(&mut self, control: &mut TcpStream) -> End {
        let idle = self.shared.config.udp_idle_timeout;
        let mut from_client = vec![0u8; MAX_DATAGRAM];
        // Room in front of the payload for the SOCKS5 header added towards the client.
        let mut from_tunnel = vec![0u8; socks5::MAX_UDP_HEADER + MAX_DATAGRAM];
        let mut control_buf = [0u8; 256];
        let idle_timer = tokio::time::sleep(idle);
        tokio::pin!(idle_timer);
        loop {
            let event = tokio::select! {
                read = control.read(&mut control_buf) => Event::Control(read),
                () = &mut idle_timer => Event::Idle,
                received = self.relay.recv_from(&mut from_client) => Event::FromClient(received),
                received = self.tunnel.recv_from(&mut from_tunnel[socks5::MAX_UDP_HEADER..]) => {
                    Event::FromTunnel(received)
                }
            };
            let outcome = match event {
                // RFC 1928 defines no data on the control connection after the reply; ignore it.
                Event::Control(Ok(n)) if n > 0 => continue,
                Event::Control(_) => return End::ControlClosed,
                Event::Idle => return End::IdleTimeout,
                Event::FromClient(Ok((n, src))) => {
                    self.client_to_tunnel(&from_client[..n], src).await
                }
                Event::FromClient(Err(e)) if is_transient(&e) => Outcome::Dropped,
                Event::FromClient(Err(e)) => return End::RelayFailed(e.kind()),
                Event::FromTunnel(Ok((n, src))) => {
                    self.tunnel_to_client(&mut from_tunnel, n, src).await
                }
                Event::FromTunnel(Err(e)) if is_transient(&e) => Outcome::Dropped,
                Event::FromTunnel(Err(e)) => return End::TunnelClosed(e.kind()),
            };
            match outcome {
                Outcome::Relayed => idle_timer.as_mut().reset(Instant::now() + idle),
                Outcome::Dropped => {
                    self.shared
                        .counters
                        .udp_dropped
                        .fetch_add(1, Ordering::Relaxed);
                }
                Outcome::TunnelClosed(kind) => return End::TunnelClosed(kind),
            }
        }
    }

    /// Only the client's IP, and once pinned only its port, may use the association.
    fn accept_source(&mut self, src: SocketAddr) -> bool {
        if src.ip().to_canonical() != self.client_ip {
            return false;
        }
        match self.client {
            Some(pinned) => pinned.port() == src.port(),
            None if self.expected_port.is_some_and(|port| port != src.port()) => false,
            None => {
                self.client = Some(src);
                true
            }
        }
    }

    async fn client_to_tunnel(&mut self, datagram: &[u8], src: SocketAddr) -> Outcome {
        if !self.accept_source(src) {
            return Outcome::Dropped;
        }
        let Some((address, port, payload)) = socks5::parse_udp_datagram(datagram) else {
            return Outcome::Dropped;
        };
        let Some(dst) = self.destination(address, port).await else {
            return Outcome::Dropped;
        };
        // Over the upload cap: dropped (and counted by the cap), never queued.
        if !self
            .shared
            .shaper
            .bucket(Direction::Upload)
            .try_take(payload.len())
        {
            return Outcome::Dropped;
        }
        match self.tunnel.send_to(payload, dst).await {
            Ok(()) => {
                self.shared.counters.add_tx(payload.len() as u64);
                Outcome::Relayed
            }
            Err(e) if is_closed(&e) => Outcome::TunnelClosed(e.kind()),
            Err(_) => Outcome::Dropped,
        }
    }

    /// The first destination address that passes the policy and that the tunnel carries.
    /// Domains are resolved through the tunnel resolver.
    async fn destination(&self, address: Address, port: u16) -> Option<SocketAddr> {
        if port == 0 {
            return None;
        }
        let candidates = match address.into_host()? {
            Host::Ip(ip) => vec![ip],
            Host::Name(name) => self
                .shared
                .resolver
                .resolve(&name, Family::Any)
                .await
                .ok()?,
        };
        candidates
            .into_iter()
            .take(MAX_CANDIDATES)
            .map(|ip| SocketAddr::new(ip.to_canonical(), port))
            .find(|dst| {
                self.shared.policy.check(*dst).is_ok() && self.shared.connector.supports(dst.ip())
            })
    }

    /// `buf` holds the payload at `MAX_UDP_HEADER..MAX_UDP_HEADER + n`; the SOCKS5 header with
    /// the remote's address is written right in front of it.
    async fn tunnel_to_client(&self, buf: &mut [u8], n: usize, src: SocketAddr) -> Outcome {
        let Some(client) = self.client else {
            return Outcome::Dropped;
        };
        let src = SocketAddr::new(src.ip().to_canonical(), src.port());
        if self.shared.policy.check(src).is_err() {
            return Outcome::Dropped;
        }
        if !self.shared.shaper.bucket(Direction::Download).try_take(n) {
            return Outcome::Dropped;
        }
        let header = socks5::udp_header(src);
        let start = socks5::MAX_UDP_HEADER - header.len();
        buf[start..socks5::MAX_UDP_HEADER].copy_from_slice(&header);
        match self
            .relay
            .send_to(&buf[start..socks5::MAX_UDP_HEADER + n], client)
            .await
        {
            Ok(_) => {
                self.shared.counters.add_rx(n as u64);
                Outcome::Relayed
            }
            Err(_) => Outcome::Dropped,
        }
    }
}

/// Errors that concern one datagram: ICMP feedback on a host socket, a truncated datagram, a
/// host short of buffer space for a moment (`ENOBUFS`).
fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
            | io::ErrorKind::InvalidData
    ) || vpn_platform::nobufs::is_no_buffer_space(e)
}

/// The tunnel socket itself is gone (gate sealed, Instance shutting down).
fn is_closed(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionAborted | io::ErrorKind::NotConnected | io::ErrorKind::BrokenPipe
    )
}
