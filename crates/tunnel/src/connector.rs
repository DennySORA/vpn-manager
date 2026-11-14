//! `TunnelConnector`: the only way Instance services (DNS, Gateways, Port forward, Provider
//! connector) open network flows.
//!
//! Implementations decide *how* traffic reaches the tunnel; none
//! of them can reach the network any other way. `TunnelInbound` is its inbound side (port
//! forwards): listeners on ports of the tunnel's own addresses, never on a host interface.
//!
//! - [`crate::Netstack`]: smoltcp userspace stack over `GotaTun` (macOS, and Linux explicit proxy).
//! - [`crate::strict::KernelConnector`] (Linux strict mode): kernel sockets inside the
//!   Instance's sandbox network namespace, whose only interface is the TUN feeding `GotaTun`.
//! - Tests: a loopback-only implementation in each crate's test support.
//!
//! [`AnyConnector`] lets one worker pick its data path at run time while the DNS, Gateway and
//! Provider-connector code stays generic and shared; [`AnyInbound`] does the same for the Port
//! Controller.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::netstack::{
    FlowClass, GateState, Netstack, PortReservation, TcpListener, TcpStream, UdpSocket,
};
use crate::strict::{DirectUdpPolicy, DirectUdpPort};

/// A UDP socket bound on the tunnel side.
pub trait TunnelDatagram: Send + Sync + 'static {
    fn send_to(&self, data: &[u8], dst: SocketAddr) -> impl Future<Output = io::Result<()>> + Send;
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send;
}

/// Opens flows through one Instance's tunnel.
///
/// Errors use `io::ErrorKind` to tell callers what happened:
/// `PermissionDenied` = gate closed, `QuotaExceeded`/`OutOfMemory` = admission limit,
/// `NetworkUnreachable` = address family not carried by this tunnel, `ConnectionRefused`,
/// `TimedOut`.
pub trait TunnelConnector: Clone + Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    type Datagram: TunnelDatagram;

    fn connect_tcp(
        &self,
        dst: SocketAddr,
        class: FlowClass,
    ) -> impl Future<Output = io::Result<Self::Stream>> + Send;

    /// Bind a UDP socket on the tunnel side for flows of `class`.
    ///
    /// # Errors
    ///
    /// Fails with the kinds listed on the trait: the gate is closed or an admission limit is
    /// reached.
    fn bind_udp(&self, class: FlowClass) -> io::Result<Self::Datagram>;

    /// Whether the tunnel carries this address family at all.
    fn supports(&self, ip: IpAddr) -> bool;
}

/// The inbound side of a tunnel, for port forwards.
///
/// Ports are reserved on the tunnel's own addresses for a generation, with listeners on them.
/// Nothing here listens on a host interface: inbound
/// traffic can only arrive through the tunnel.
pub trait TunnelInbound: Clone + Send + Sync + 'static {
    /// A reserved port; dropping it frees the port.
    type Port: Send + Sync + 'static;
    type Listener: InboundListener;
    type Datagram: TunnelDatagram;

    /// Whether payload is admitted right now (the payload gate is open).
    fn payload_open(&self) -> bool;

    /// Reserve `port` for inbound TCP and/or UDP: no outbound flow takes it while reserved.
    ///
    /// # Errors
    ///
    /// `AddrInUse` when a flow or another reservation holds it now.
    fn reserve(&self, port: u16, tcp: bool, udp: bool) -> io::Result<Self::Port>;

    /// Listen for inbound TCP on a reserved port.
    ///
    /// # Errors
    ///
    /// Fails while payload is not admitted, or when the listener cannot be opened.
    fn listen_tcp(&self, port: &Self::Port, backlog: usize) -> io::Result<Self::Listener>;

    /// Receive inbound UDP on a reserved port.
    ///
    /// # Errors
    ///
    /// Fails while payload is not admitted, or when the socket cannot be opened.
    fn listen_udp(&self, port: &Self::Port) -> io::Result<Self::Datagram>;

    /// Let inbound UDP to `port` on the tunnel addresses straight into the sandbox, to the App
    /// socket that holds the port there, `policy` deciding on every new remote end while the
    /// port is open (a port forward whose UDP goes straight to its App). Nothing is reserved or
    /// relayed.
    ///
    /// # Errors
    ///
    /// Only the strict plane has a sandbox: `Unsupported` on any other; the strict plane fails
    /// when the port cannot be registered with its packet filter.
    fn direct_udp(&self, port: u16, policy: Arc<dyn DirectUdpPolicy>) -> io::Result<DirectUdpPort>;

    /// Reset every TCP connection on a reserved port now; returns how many.
    fn reset_port(&self, port: &Self::Port) -> usize;
}

/// The refusal of a data plane without a sandbox to take UDP straight to an App.
fn no_sandbox() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "only a strict sandbox takes UDP straight to its Apps",
    )
}

/// Inbound TCP on one reserved port.
pub trait InboundListener: Send + 'static {
    type Stream: InboundStream;

    /// The next established inbound connection. Fails (`QuotaExceeded`, `OutOfMemory`,
    /// `PermissionDenied`) while no connection can be taken; a later call tries again.
    fn accept(&mut self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// One inbound TCP connection.
pub trait InboundStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// The remote end: where the connection came from.
    fn peer_addr(&self) -> SocketAddr;
    /// This end: the tunnel address and port the remote connected to.
    fn local_addr(&self) -> SocketAddr;
    /// Reset (RST) instead of a graceful close.
    fn abort(&self);
}

impl TunnelInbound for Netstack {
    type Port = PortReservation;
    type Listener = TcpListener;
    type Datagram = UdpSocket;

    fn payload_open(&self) -> bool {
        self.gate() == GateState::Open
    }

    fn reserve(&self, port: u16, tcp: bool, udp: bool) -> io::Result<PortReservation> {
        self.reserve_inbound(port, tcp, udp)
    }

    fn listen_tcp(&self, port: &PortReservation, backlog: usize) -> io::Result<TcpListener> {
        port.listen_tcp(backlog)
    }

    fn listen_udp(&self, port: &PortReservation) -> io::Result<UdpSocket> {
        port.bind_udp()
    }

    fn direct_udp(&self, _: u16, _: Arc<dyn DirectUdpPolicy>) -> io::Result<DirectUdpPort> {
        Err(no_sandbox())
    }

    fn reset_port(&self, port: &PortReservation) -> usize {
        self.reset_tcp_port(port.port())
    }
}

impl InboundListener for TcpListener {
    type Stream = TcpStream;

    async fn accept(&mut self) -> io::Result<TcpStream> {
        Self::accept(self).await
    }
}

impl InboundStream for TcpStream {
    fn peer_addr(&self) -> SocketAddr {
        Self::peer_addr(self)
    }

    fn local_addr(&self) -> SocketAddr {
        Self::local_addr(self)
    }

    fn abort(&self) {
        Self::abort(self);
    }
}

impl TunnelDatagram for UdpSocket {
    async fn send_to(&self, data: &[u8], dst: SocketAddr) -> io::Result<()> {
        Self::send_to(self, data, dst).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Self::recv_from(self, buf).await
    }
}

impl TunnelConnector for Netstack {
    type Stream = TcpStream;
    type Datagram = UdpSocket;

    async fn connect_tcp(&self, dst: SocketAddr, class: FlowClass) -> io::Result<TcpStream> {
        Self::connect_tcp(self, dst, class).await
    }

    fn bind_udp(&self, class: FlowClass) -> io::Result<UdpSocket> {
        Self::bind_udp(self, class)
    }

    fn supports(&self, ip: IpAddr) -> bool {
        Self::supports(self, ip)
    }
}

/// The data path of one worker: the userspace netstack, or (Linux strict mode) kernel sockets
/// in the sandbox's network namespace.
#[derive(Debug, Clone)]
pub enum AnyConnector {
    Netstack(Netstack),
    #[cfg(target_os = "linux")]
    Kernel(crate::strict::KernelConnector),
}

/// A TCP stream of an [`AnyConnector`].
#[derive(Debug)]
pub enum AnyStream {
    Netstack(TcpStream),
    #[cfg(target_os = "linux")]
    Kernel(crate::strict::KernelStream),
}

/// A UDP socket of an [`AnyConnector`].
#[derive(Debug)]
pub enum AnyDatagram {
    Netstack(UdpSocket),
    #[cfg(target_os = "linux")]
    Kernel(crate::strict::KernelDatagram),
}

impl AsyncRead for AnyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Netstack(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(target_os = "linux")]
            Self::Kernel(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AnyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Netstack(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(target_os = "linux")]
            Self::Kernel(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Netstack(s) => Pin::new(s).poll_flush(cx),
            #[cfg(target_os = "linux")]
            Self::Kernel(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Netstack(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(target_os = "linux")]
            Self::Kernel(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl TunnelDatagram for AnyDatagram {
    async fn send_to(&self, data: &[u8], dst: SocketAddr) -> io::Result<()> {
        match self {
            Self::Netstack(s) => s.send_to(data, dst).await,
            #[cfg(target_os = "linux")]
            Self::Kernel(s) => s.send_to(data, dst).await,
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::Netstack(s) => s.recv_from(buf).await,
            #[cfg(target_os = "linux")]
            Self::Kernel(s) => s.recv_from(buf).await,
        }
    }
}

/// The inbound side of a worker's data path (port forwards): the netstack's listeners, or (Linux
/// strict mode) kernel sockets on the sandbox's tunnel addresses.
#[derive(Debug, Clone)]
pub enum AnyInbound {
    Netstack(Netstack),
    #[cfg(target_os = "linux")]
    Kernel(crate::strict::KernelConnector),
}

/// A reserved port of an [`AnyInbound`].
#[derive(Debug)]
pub enum AnyPort {
    Netstack(PortReservation),
    #[cfg(target_os = "linux")]
    Kernel(crate::strict::KernelPort),
}

/// A TCP listener of an [`AnyInbound`].
#[derive(Debug)]
pub enum AnyListener {
    Netstack(TcpListener),
    #[cfg(target_os = "linux")]
    Kernel(crate::strict::KernelListener),
}

#[cfg(target_os = "linux")]
fn other_plane() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "port reserved on another data path",
    )
}

impl TunnelInbound for AnyInbound {
    type Port = AnyPort;
    type Listener = AnyListener;
    type Datagram = AnyDatagram;

    fn payload_open(&self) -> bool {
        match self {
            Self::Netstack(n) => TunnelInbound::payload_open(n),
            #[cfg(target_os = "linux")]
            Self::Kernel(k) => TunnelInbound::payload_open(k),
        }
    }

    fn reserve(&self, port: u16, tcp: bool, udp: bool) -> io::Result<AnyPort> {
        match self {
            Self::Netstack(n) => TunnelInbound::reserve(n, port, tcp, udp).map(AnyPort::Netstack),
            #[cfg(target_os = "linux")]
            Self::Kernel(k) => TunnelInbound::reserve(k, port, tcp, udp).map(AnyPort::Kernel),
        }
    }

    fn listen_tcp(&self, port: &AnyPort, backlog: usize) -> io::Result<AnyListener> {
        match (self, port) {
            (Self::Netstack(n), AnyPort::Netstack(p)) => {
                TunnelInbound::listen_tcp(n, p, backlog).map(AnyListener::Netstack)
            }
            #[cfg(target_os = "linux")]
            (Self::Kernel(k), AnyPort::Kernel(p)) => {
                TunnelInbound::listen_tcp(k, p, backlog).map(AnyListener::Kernel)
            }
            #[cfg(target_os = "linux")]
            _ => Err(other_plane()),
        }
    }

    fn listen_udp(&self, port: &AnyPort) -> io::Result<AnyDatagram> {
        match (self, port) {
            (Self::Netstack(n), AnyPort::Netstack(p)) => {
                TunnelInbound::listen_udp(n, p).map(AnyDatagram::Netstack)
            }
            #[cfg(target_os = "linux")]
            (Self::Kernel(k), AnyPort::Kernel(p)) => {
                TunnelInbound::listen_udp(k, p).map(AnyDatagram::Kernel)
            }
            #[cfg(target_os = "linux")]
            _ => Err(other_plane()),
        }
    }

    fn direct_udp(&self, port: u16, policy: Arc<dyn DirectUdpPolicy>) -> io::Result<DirectUdpPort> {
        match self {
            Self::Netstack(n) => TunnelInbound::direct_udp(n, port, policy),
            #[cfg(target_os = "linux")]
            Self::Kernel(k) => TunnelInbound::direct_udp(k, port, policy),
        }
    }

    fn reset_port(&self, port: &AnyPort) -> usize {
        match (self, port) {
            (Self::Netstack(n), AnyPort::Netstack(p)) => TunnelInbound::reset_port(n, p),
            #[cfg(target_os = "linux")]
            (Self::Kernel(k), AnyPort::Kernel(p)) => TunnelInbound::reset_port(k, p),
            #[cfg(target_os = "linux")]
            _ => 0,
        }
    }
}

impl InboundListener for AnyListener {
    type Stream = AnyStream;

    async fn accept(&mut self) -> io::Result<AnyStream> {
        match self {
            Self::Netstack(l) => InboundListener::accept(l).await.map(AnyStream::Netstack),
            #[cfg(target_os = "linux")]
            Self::Kernel(l) => InboundListener::accept(l).await.map(AnyStream::Kernel),
        }
    }
}

impl InboundStream for AnyStream {
    fn peer_addr(&self) -> SocketAddr {
        match self {
            Self::Netstack(s) => InboundStream::peer_addr(s),
            #[cfg(target_os = "linux")]
            Self::Kernel(s) => InboundStream::peer_addr(s),
        }
    }

    fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Netstack(s) => InboundStream::local_addr(s),
            #[cfg(target_os = "linux")]
            Self::Kernel(s) => InboundStream::local_addr(s),
        }
    }

    fn abort(&self) {
        match self {
            Self::Netstack(s) => InboundStream::abort(s),
            #[cfg(target_os = "linux")]
            Self::Kernel(s) => InboundStream::abort(s),
        }
    }
}

impl TunnelConnector for AnyConnector {
    type Stream = AnyStream;
    type Datagram = AnyDatagram;

    async fn connect_tcp(&self, dst: SocketAddr, class: FlowClass) -> io::Result<AnyStream> {
        match self {
            Self::Netstack(n) => n.connect_tcp(dst, class).await.map(AnyStream::Netstack),
            #[cfg(target_os = "linux")]
            Self::Kernel(k) => k.connect_tcp(dst, class).await.map(AnyStream::Kernel),
        }
    }

    fn bind_udp(&self, class: FlowClass) -> io::Result<AnyDatagram> {
        match self {
            Self::Netstack(n) => n.bind_udp(class).map(AnyDatagram::Netstack),
            #[cfg(target_os = "linux")]
            Self::Kernel(k) => k.bind_udp(class).map(AnyDatagram::Kernel),
        }
    }

    fn supports(&self, ip: IpAddr) -> bool {
        match self {
            Self::Netstack(n) => n.supports(ip),
            #[cfg(target_os = "linux")]
            Self::Kernel(k) => k.supports(ip),
        }
    }
}
