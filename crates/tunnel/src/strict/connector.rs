//! [`TunnelConnector`] over kernel sockets inside a strict sandbox's network namespace.
//!
//! The worker of a strict Instance runs inside the sandbox's network namespace, whose only
//! interfaces are `lo` and the TUN device feeding `GotaTun` (checked when the tunnel starts). A
//! kernel socket opened there can therefore only reach the network through the tunnel; this
//! connector adds the same contract as the smoltcp netstack on top: the payload gate, flow
//! admission limits with a share kept for control flows, the address families the tunnel
//! carries, and no loopback or link-local destinations (the sandbox's loopback holds its DNS
//! listener and the Apps' own services, none of which a proxied flow may reach).
//!
//! Every socket is bound to the tunnel address and registered in [`OwnFlows`] before it sends
//! anything, so the packet filter knows its class. Sockets never set `SO_REUSEADDR` or
//! `SO_REUSEPORT`: no App in the sandbox can bind the same port while the socket exists.
//!
//! It is also the strict plane's [`TunnelInbound`] (port forwards): a reserved port is a TCP
//! and/or UDP socket bound on each tunnel address; the packet filter lets new connections and
//! datagrams through to it only while a listener is open, and connections it accepts are counted
//! and reset like the worker's own. Connections and datagrams from inside the sandbox (its
//! loopback, its own tunnel address) did not come through the tunnel and are refused. A forward
//! whose UDP goes straight to the App (`udp_direct`) holds no socket for it: the port is
//! registered with the packet filter as a direct port instead ([`DirectUdpPort`]).

#![allow(
    unsafe_code,
    reason = "kernel sockets in the sandbox namespace: libc socket options, fcntl, listen and OwnedFd adoption of fresh descriptors"
)]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::Notify;
use vpn_sync::Mutex;

use super::filter::{DirectPorts, DirectUdpPolicy, DirectUdpPort};
use super::flows::{FlowGuard, FlowKey, L4, ListenGuard, OwnFlows};
use super::packet;
use crate::connector::{
    InboundListener, InboundStream, TunnelConnector, TunnelDatagram, TunnelInbound,
};
use crate::netstack::{FlowClass, Gate, GateState, NetstackLimits, NetstackStats};
use crate::transport::{FlowTuning, Transport, TransportPlan};

/// How a live socket is ended by [`KernelConnector::reset`].
enum Ender {
    /// A duplicate of the stream's descriptor: `SO_LINGER 0` + `shutdown` ends it with a reset
    /// even while another task is reading or writing it.
    Tcp(OwnedFd),
    Udp(Arc<UdpEnd>),
}

#[derive(Default)]
struct UdpEnd {
    ended: AtomicBool,
    wake: Notify,
}

struct Live {
    class: FlowClass,
    ender: Ender,
    /// The remote end of a TCP connection.
    remote: Option<IpAddr>,
    /// The tunnel port of a connection a port forward accepted.
    inbound_port: Option<u16>,
}

/// End a TCP connection with a reset (`SO_LINGER 0` + `shutdown` on a duplicate of its
/// descriptor), even while another task is reading or writing it.
fn abort_tcp(fd: &OwnedFd) {
    abort_fd(fd.as_raw_fd());
}

fn abort_fd(fd: RawFd) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: valid descriptor; pointer to a live linger of the size we pass.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const linger).cast(),
            socklen::<libc::linger>(),
        );
        libc::shutdown(fd, libc::SHUT_RDWR);
    }
}

struct Inner {
    gate: Arc<Gate>,
    own: OwnFlows,
    /// The packet filter's direct UDP ports (port forwards with `udp_direct`).
    direct: DirectPorts,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    limits: NetstackLimits,
    /// What the worker's own connections are opened with. The kernel sizes their buffers
    /// itself; the timeouts, keep-alives and congestion control are the transport's.
    transport: Transport,
    /// The congestion control the kernel reported for the connection opened last.
    congestion: Mutex<Option<String>>,
    stats: NetstackStats,
    live: Mutex<HashMap<u64, Live>>,
    next_id: AtomicU64,
}

/// Opens flows through a strict sandbox's tunnel with kernel sockets. Cheap to clone.
#[derive(Clone)]
pub struct KernelConnector {
    inner: Arc<Inner>,
}

/// Keeps one flow counted, registered and resettable; undoes all of it when dropped.
struct Lease {
    inner: Arc<Inner>,
    id: u64,
    proto: L4,
    flows: Option<FlowGuard>,
    /// A port forward's UDP listener.
    listening: Option<ListenGuard>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.inner.live.lock().remove(&self.id);
        let counter = match self.proto {
            L4::Tcp => &self.inner.stats.active_tcp,
            L4::Udp => &self.inner.stats.active_udp,
        };
        counter.fetch_sub(1, Ordering::Relaxed);
    }
}

const fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Refuse what no tunnel flow may target: non-unicast destinations, and the sandbox-local
/// loopback / link-local ranges.
fn check_destination(dst: SocketAddr) -> io::Result<()> {
    let ip = dst.ip();
    if dst.port() == 0 || ip.is_unspecified() || ip.is_multicast() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination is not a unicast address",
        ));
    }
    if packet::is_special(ip) {
        return Err(io::Error::new(
            io::ErrorKind::NetworkUnreachable,
            "loopback and link-local destinations are not carried by the tunnel",
        ));
    }
    Ok(())
}

/// The size of `T` as a `socklen_t`, for socket option arguments.
#[expect(
    clippy::cast_possible_truncation,
    reason = "only used for socket option values of a few bytes"
)]
const fn socklen<T>() -> libc::socklen_t {
    std::mem::size_of::<T>() as libc::socklen_t
}

/// Set an integer socket option.
fn setsockopt_int(fd: RawFd, level: i32, name: i32, value: i32) -> io::Result<()> {
    // SAFETY: valid descriptor and a pointer to a live c_int of the size we pass.
    let r =
        unsafe { libc::setsockopt(fd, level, name, (&raw const value).cast(), socklen::<i32>()) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn dup(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC on a descriptor we own returns a new descriptor or -1.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `new` is a fresh descriptor owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

/// Keep-alive probes and a dead-peer timeout like the netstack's, so a silently gone remote
/// does not hold a flow forever, and the transport's congestion control. Best effort: a failure
/// only loses the early detection, or leaves the namespace's congestion control in place.
/// Returns the congestion control the socket runs, as the kernel names it.
fn tune(fd: RawFd, tuning: &FlowTuning) -> Option<String> {
    let idle = i32::try_from(tuning.tcp_keepalive.as_secs().max(1)).unwrap_or(i32::MAX);
    let user_timeout = i32::try_from(tuning.tcp_dead_peer_timeout.as_millis()).unwrap_or(i32::MAX);
    let _ = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1);
    let _ = setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, idle);
    let _ = setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, idle);
    let _ = setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 5);
    let _ = setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, user_timeout);
    // Refused where the kernel does not offer the algorithm to unprivileged programs (BBR
    // outside `tcp_allowed_congestion_control`): the flow then keeps the namespace's own, which
    // is what the answer read back says.
    let name = tuning.congestion.name().as_bytes();
    // SAFETY: valid descriptor; pointer to `name.len()` readable bytes.
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            name.as_ptr().cast(),
            libc::socklen_t::try_from(name.len()).unwrap_or_default(),
        );
    }
    congestion_of(fd)
}

/// The congestion control a TCP socket runs (`TCP_CONGESTION`), `None` when it cannot be read.
fn congestion_of(fd: RawFd) -> Option<String> {
    // `TCP_CA_NAME_MAX`.
    let mut name = [0u8; 16];
    let mut len = libc::socklen_t::try_from(name.len()).unwrap_or_default();
    // SAFETY: valid descriptor; a buffer of `len` writable bytes and its length.
    let read = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            name.as_mut_ptr().cast(),
            &raw mut len,
        )
    };
    if read != 0 {
        return None;
    }
    let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
    let name = std::str::from_utf8(&name[..end]).ok()?;
    (!name.is_empty()).then(|| name.to_owned())
}

impl KernelConnector {
    pub(crate) fn new(
        gate: Arc<Gate>,
        own: OwnFlows,
        direct: DirectPorts,
        v4: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
        limits: NetstackLimits,
        transport: TransportPlan,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                gate,
                own,
                direct,
                v4,
                v6,
                limits,
                transport: Transport::new(transport),
                congestion: Mutex::new(None),
                stats: NetstackStats::default(),
                live: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(1),
            }),
        }
    }

    #[must_use]
    pub fn stats(&self) -> &NetstackStats {
        &self.inner.stats
    }

    /// The transport of this plane: the plan the worker's own connections take and what was
    /// measured for it.
    #[must_use]
    pub fn transport(&self) -> &Transport {
        &self.inner.transport
    }

    /// The congestion control the plane's own TCP connections run, as the kernel names it: what
    /// it reported for the one opened last, `None` before the first.
    #[must_use]
    pub fn congestion(&self) -> Option<String> {
        self.inner.congestion.lock().clone()
    }

    /// Tune a new connection of the plane's own and keep what the kernel says it runs.
    fn tune(&self, fd: RawFd, tuning: &FlowTuning) {
        let Some(runs) = tune(fd, tuning) else {
            return;
        };
        let mut known = self.inner.congestion.lock();
        if known.as_deref() != Some(runs.as_str()) {
            *known = Some(runs);
        }
    }

    fn source_for(&self, ip: IpAddr) -> Option<IpAddr> {
        match ip {
            IpAddr::V4(_) => self.inner.v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.inner.v6.map(IpAddr::V6),
        }
    }

    /// The sandbox's loopback or its own tunnel address: not the tunnel.
    fn is_sandbox_local(&self, ip: IpAddr) -> bool {
        ip.is_loopback()
            || match ip {
                IpAddr::V4(a) => self.inner.v4 == Some(a),
                IpAddr::V6(a) => self.inner.v6 == Some(a),
            }
    }

    /// Count a new flow of `class`, or refuse it: closed gate, or the flow limit (payload stops
    /// short of the share kept for control flows, like the netstack).
    fn admit(&self, class: FlowClass, proto: L4) -> io::Result<()> {
        let inner = &self.inner;
        if !inner.gate.get().admits(class) {
            inner
                .stats
                .admission_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "instance payload gate is closed",
            ));
        }
        let (counter, max): (&AtomicUsize, usize) = match proto {
            L4::Tcp => (&inner.stats.active_tcp, inner.limits.max_tcp_flows),
            L4::Udp => (&inner.stats.active_udp, inner.limits.max_udp_flows),
        };
        let max = match class {
            FlowClass::Control => max,
            FlowClass::Payload => max - inner.limits.control_reserved_flows.min(max / 4),
        };
        if counter.fetch_add(1, Ordering::Relaxed) >= max {
            counter.fetch_sub(1, Ordering::Relaxed);
            inner
                .stats
                .admission_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::QuotaExceeded,
                "instance flow limit reached",
            ));
        }
        Ok(())
    }

    fn lease(
        &self,
        class: FlowClass,
        proto: L4,
        ender: Ender,
        remote: Option<IpAddr>,
        inbound_port: Option<u16>,
    ) -> Lease {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        self.inner.live.lock().insert(
            id,
            Live {
                class,
                ender,
                remote,
                inbound_port,
            },
        );
        Lease {
            inner: self.inner.clone(),
            id,
            proto,
            flows: None,
            listening: None,
        }
    }

    /// End existing flows of one class (all with `None`): TCP connections are reset, UDP sockets
    /// fail every further call.
    pub fn reset(&self, class: Option<FlowClass>) {
        let live = self.inner.live.lock();
        for flow in live.values() {
            if class.is_some_and(|c| c != flow.class) {
                continue;
            }
            match &flow.ender {
                Ender::Tcp(fd) => abort_tcp(fd),
                Ender::Udp(end) => {
                    end.ended.store(true, Ordering::Release);
                    end.wake.notify_waiters();
                }
            }
        }
    }

    /// Reset the TCP connections of `class` (connected or still connecting) whose remote address
    /// `remote` accepts — a destination a new deny rule covers; returns how many. UDP sockets
    /// have no fixed remote: their users check every datagram instead.
    pub fn reset_tcp_to(&self, class: FlowClass, remote: &dyn Fn(IpAddr) -> bool) -> usize {
        let live = self.inner.live.lock();
        let mut reset = 0;
        for flow in live.values() {
            if flow.class != class {
                continue;
            }
            if let (Ender::Tcp(fd), Some(ip)) = (&flow.ender, flow.remote)
                && remote(ip)
            {
                abort_tcp(fd);
                reset += 1;
            }
        }
        drop(live);
        reset
    }

    async fn connect(&self, dst: SocketAddr, class: FlowClass) -> io::Result<KernelStream> {
        let dst = canonical(dst);
        check_destination(dst)?;
        let source = self.source_for(dst.ip()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "the tunnel carries no address of this IP family",
            )
        })?;
        self.admit(class, L4::Tcp)?;
        let socket = match dst {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        };
        let socket = match socket {
            Ok(s) => s,
            Err(e) => {
                self.inner.stats.active_tcp.fetch_sub(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        let ender = match dup(socket.as_raw_fd()) {
            Ok(fd) => fd,
            Err(e) => {
                self.inner.stats.active_tcp.fetch_sub(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        let mut lease = self.lease(class, L4::Tcp, Ender::Tcp(ender), Some(dst.ip()), None);
        socket.bind(SocketAddr::new(source, 0))?;
        let local = socket.local_addr()?;
        lease.flows = Some(self.inner.own.register(
            vec![FlowKey {
                proto: L4::Tcp,
                local: local.ip(),
                port: local.port(),
            }],
            class,
        ));
        let (tuning, _) = self.inner.transport.select();
        self.tune(socket.as_raw_fd(), &tuning);
        let sent = Instant::now();
        let connecting = tokio::time::timeout(tuning.connect_timeout, socket.connect(dst)).await;
        let stream = match connecting {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                self.inner
                    .stats
                    .tcp_connect_failures
                    .fetch_add(1, Ordering::Relaxed);
                return Err(connect_error(e));
            }
            Err(_) => {
                self.inner
                    .stats
                    .tcp_connect_failures
                    .fetch_add(1, Ordering::Relaxed);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tcp connect timed out",
                ));
            }
        };
        // The handshake is one round trip: what the next connections are tuned for.
        self.inner.transport.record_handshake(sent.elapsed());
        let _ = stream.set_nodelay(!tuning.nagle);
        self.inner
            .stats
            .tcp_connects
            .fetch_add(1, Ordering::Relaxed);
        Ok(KernelStream {
            stream,
            peer: dst,
            local: canonical(local),
            _lease: lease,
        })
    }

    /// Take a connection a port forward accepted on `port`: counted (payload), resettable by
    /// port, class and remote address. Refused (reset) at the flow limit or a closed gate.
    fn adopt(&self, stream: TcpStream, peer: SocketAddr, port: u16) -> io::Result<KernelStream> {
        let local = match stream.local_addr() {
            Ok(a) => canonical(a),
            Err(e) => {
                abort_fd(stream.as_raw_fd());
                return Err(e);
            }
        };
        if let Err(e) = self.admit(FlowClass::Payload, L4::Tcp) {
            abort_fd(stream.as_raw_fd());
            return Err(e);
        }
        let ender = match dup(stream.as_raw_fd()) {
            Ok(fd) => fd,
            Err(e) => {
                self.inner.stats.active_tcp.fetch_sub(1, Ordering::Relaxed);
                abort_fd(stream.as_raw_fd());
                return Err(e);
            }
        };
        let lease = self.lease(
            FlowClass::Payload,
            L4::Tcp,
            Ender::Tcp(ender),
            Some(peer.ip()),
            Some(port),
        );
        let (tuning, _) = self.inner.transport.select();
        self.tune(stream.as_raw_fd(), &tuning);
        let _ = stream.set_nodelay(!tuning.nagle);
        Ok(KernelStream {
            stream,
            peer,
            local,
            _lease: lease,
        })
    }

    fn bind(&self, class: FlowClass) -> io::Result<KernelDatagram> {
        self.admit(class, L4::Udp)?;
        let end = Arc::new(UdpEnd::default());
        let mut lease = self.lease(class, L4::Udp, Ender::Udp(end.clone()), None, None);
        let bind = |ip: IpAddr| -> io::Result<UdpSocket> {
            let std = std::net::UdpSocket::bind(SocketAddr::new(ip, 0))?;
            std.set_nonblocking(true)?;
            UdpSocket::from_std(std)
        };
        let v4 = self.inner.v4.map(|a| bind(a.into())).transpose()?;
        let v6 = self.inner.v6.map(|a| bind(a.into())).transpose()?;
        let mut keys = Vec::new();
        for socket in v4.iter().chain(v6.iter()) {
            let local = socket.local_addr()?;
            keys.push(FlowKey {
                proto: L4::Udp,
                local: local.ip(),
                port: local.port(),
            });
        }
        lease.flows = Some(self.inner.own.register(keys, class));
        Ok(KernelDatagram {
            v4,
            v6,
            end,
            local_v4: self.inner.v4,
            local_v6: self.inner.v6,
            _lease: lease,
        })
    }
}

/// A refusal by the remote side or on the way is not the closed gate (that was checked before
/// the socket was made): ICMP "administratively prohibited" turns into EACCES on IPv6.
fn connect_error(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::PermissionDenied {
        io::Error::new(io::ErrorKind::HostUnreachable, e.to_string())
    } else {
        e
    }
}

/// A TCP connection through the tunnel.
pub struct KernelStream {
    stream: TcpStream,
    /// The remote end.
    peer: SocketAddr,
    /// This end: a tunnel address of the sandbox.
    local: SocketAddr,
    _lease: Lease,
}

impl InboundStream for KernelStream {
    fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    fn local_addr(&self) -> SocketAddr {
        self.local
    }

    fn abort(&self) {
        abort_fd(self.stream.as_raw_fd());
    }
}

impl AsyncRead for KernelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for KernelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// A UDP socket on the tunnel side: one kernel socket per address family the tunnel carries.
pub struct KernelDatagram {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
    end: Arc<UdpEnd>,
    local_v4: Option<Ipv4Addr>,
    local_v6: Option<Ipv6Addr>,
    _lease: Lease,
}

impl KernelDatagram {
    fn ended(&self) -> io::Result<()> {
        if self.end.ended.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "udp socket closed (gate or instance shutdown)",
            ));
        }
        Ok(())
    }

    /// Datagrams from inside the sandbox (its loopback or its own tunnel address) are not from
    /// the tunnel: an App could otherwise inject into a Gateway's UDP association.
    fn is_sandbox_local(&self, ip: IpAddr) -> bool {
        ip.is_loopback()
            || match ip {
                IpAddr::V4(a) => self.local_v4 == Some(a),
                IpAddr::V6(a) => self.local_v6 == Some(a),
            }
    }
}

async fn readable(socket: Option<&UdpSocket>) -> io::Result<&UdpSocket> {
    match socket {
        Some(s) => {
            s.readable().await?;
            Ok(s)
        }
        None => std::future::pending().await,
    }
}

impl TunnelDatagram for KernelDatagram {
    async fn send_to(&self, data: &[u8], dst: SocketAddr) -> io::Result<()> {
        self.ended()?;
        let dst = canonical(dst);
        check_destination(dst)?;
        let socket = match dst {
            SocketAddr::V4(_) => self.v4.as_ref(),
            SocketAddr::V6(_) => self.v6.as_ref(),
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "the tunnel carries no address of this IP family",
            )
        })?;
        socket.send_to(data, dst).await.map(|_| ())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            self.ended()?;
            let ended = self.end.wake.notified();
            tokio::pin!(ended);
            ended.as_mut().enable();
            self.ended()?;
            let socket = tokio::select! {
                s = readable(self.v4.as_ref()) => s?,
                s = readable(self.v6.as_ref()) => s?,
                () = &mut ended => continue,
            };
            match socket.try_recv_from(buf) {
                Ok((n, from)) => {
                    let from = canonical(from);
                    if self.is_sandbox_local(from.ip()) {
                        continue;
                    }
                    return Ok((n, from));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// A port forward's tunnel port (see [`TunnelInbound::reserve`]).
///
/// It is a TCP and/or UDP socket bound on each tunnel address, never with `SO_REUSEADDR`, so
/// neither the worker's own flows nor an App can take the port while it exists. Its TCP sockets listen from the first listener on; the
/// packet filter lets connection requests and datagrams through only while one is open.
/// Dropping it closes the sockets (connections the kernel completed but nobody took are reset).
pub struct KernelPort {
    port: u16,
    tcp: Arc<TcpHold>,
    udp: Vec<(FlowKey, std::net::UdpSocket)>,
    _held: FlowGuard,
}

/// The TCP sockets of a reserved port and how many listeners are open on them.
struct TcpHold {
    sockets: Vec<(FlowKey, OwnedFd)>,
    listeners: Mutex<usize>,
}

/// Inbound TCP on a reserved port (see [`TunnelInbound::listen_tcp`]).
pub struct KernelListener {
    connector: KernelConnector,
    port: u16,
    hold: Arc<TcpHold>,
    v4: Option<TcpListener>,
    v6: Option<TcpListener>,
    listening: Option<ListenGuard>,
}

impl Drop for KernelListener {
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the listener count stays locked while the last listener drains the accept queue, so a new listener cannot open in between"
    )]
    fn drop(&mut self) {
        // No new connection requests from here on.
        self.listening = None;
        let mut open = self.hold.listeners.lock();
        *open = open.saturating_sub(1);
        if *open > 0 {
            return;
        }
        // The last one: connections the kernel completed and nobody took are reset rather than
        // left for a later listener.
        for (_, socket) in &self.hold.sockets {
            loop {
                // SAFETY: accept4 on a listening descriptor we hold; a returned descriptor is
                // ours alone.
                let fd = unsafe {
                    libc::accept4(
                        socket.as_raw_fd(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    )
                };
                if fd < 0 {
                    break;
                }
                // SAFETY: a fresh descriptor owned by nobody else.
                let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                abort_tcp(&fd);
            }
        }
    }
}

async fn accept_on(listener: Option<&TcpListener>) -> io::Result<(TcpStream, SocketAddr)> {
    match listener {
        Some(l) => l.accept().await,
        None => std::future::pending().await,
    }
}

impl InboundListener for KernelListener {
    type Stream = KernelStream;

    async fn accept(&mut self) -> io::Result<KernelStream> {
        loop {
            let (stream, peer) = tokio::select! {
                r = accept_on(self.v4.as_ref()) => r?,
                r = accept_on(self.v6.as_ref()) => r?,
            };
            let peer = canonical(peer);
            // An App dialing the sandbox's own tunnel address: not through the tunnel.
            if self.connector.is_sandbox_local(peer.ip()) {
                abort_fd(stream.as_raw_fd());
                continue;
            }
            return self.connector.adopt(stream, peer, self.port);
        }
    }
}

impl TunnelInbound for KernelConnector {
    type Port = KernelPort;
    type Listener = KernelListener;
    type Datagram = KernelDatagram;

    fn payload_open(&self) -> bool {
        self.inner.gate.get() == GateState::Open
    }

    fn reserve(&self, port: u16, tcp: bool, udp: bool) -> io::Result<KernelPort> {
        if port == 0 || !(tcp || udp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nothing to reserve",
            ));
        }
        let addresses = self
            .inner
            .v4
            .map(IpAddr::V4)
            .into_iter()
            .chain(self.inner.v6.map(IpAddr::V6));
        let (mut tcp_sockets, mut udp_sockets) = (Vec::new(), Vec::new());
        for ip in addresses {
            let at = SocketAddr::new(ip, port);
            if tcp {
                let socket = match ip {
                    IpAddr::V4(_) => TcpSocket::new_v4()?,
                    IpAddr::V6(_) => TcpSocket::new_v6()?,
                };
                socket.bind(at)?;
                let key = FlowKey {
                    proto: L4::Tcp,
                    local: ip,
                    port,
                };
                // SAFETY: the descriptor comes from `into_raw_fd`; nobody else owns it.
                tcp_sockets.push((key, unsafe { OwnedFd::from_raw_fd(socket.into_raw_fd()) }));
            }
            if udp {
                let socket = std::net::UdpSocket::bind(at)?;
                socket.set_nonblocking(true)?;
                let key = FlowKey {
                    proto: L4::Udp,
                    local: ip,
                    port,
                };
                udp_sockets.push((key, socket));
            }
        }
        let keys = tcp_sockets
            .iter()
            .map(|(k, _)| *k)
            .chain(udp_sockets.iter().map(|(k, _)| *k))
            .collect();
        Ok(KernelPort {
            port,
            tcp: Arc::new(TcpHold {
                sockets: tcp_sockets,
                listeners: Mutex::new(0),
            }),
            udp: udp_sockets,
            _held: self.inner.own.reserve(keys),
        })
    }

    fn listen_tcp(&self, port: &KernelPort, backlog: usize) -> io::Result<KernelListener> {
        if port.tcp.sockets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "port not reserved for TCP",
            ));
        }
        if !self.payload_open() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "instance payload gate is closed",
            ));
        }
        let backlog = i32::try_from(backlog.max(1)).unwrap_or(i32::MAX);
        let mut open = port.tcp.listeners.lock();
        let (mut v4, mut v6) = (None, None);
        for (key, fd) in &port.tcp.sockets {
            // SAFETY: a valid descriptor of a bound TCP socket; listening again only resizes
            // the backlog.
            if unsafe { libc::listen(fd.as_raw_fd(), backlog) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let listener =
                TcpListener::from_std(std::net::TcpListener::from(dup(fd.as_raw_fd())?))?;
            match key.local {
                IpAddr::V4(_) => v4 = Some(listener),
                IpAddr::V6(_) => v6 = Some(listener),
            }
        }
        *open += 1;
        drop(open);
        let keys = port.tcp.sockets.iter().map(|(k, _)| *k).collect();
        Ok(KernelListener {
            connector: self.clone(),
            port: port.port,
            hold: port.tcp.clone(),
            v4,
            v6,
            listening: Some(self.inner.own.listen(keys)),
        })
    }

    fn listen_udp(&self, port: &KernelPort) -> io::Result<KernelDatagram> {
        if port.udp.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "port not reserved for UDP",
            ));
        }
        self.admit(FlowClass::Payload, L4::Udp)?;
        let end = Arc::new(UdpEnd::default());
        let mut lease = self.lease(
            FlowClass::Payload,
            L4::Udp,
            Ender::Udp(end.clone()),
            None,
            None,
        );
        let (mut v4, mut v6) = (None, None);
        for (key, socket) in &port.udp {
            let socket = UdpSocket::from_std(socket.try_clone()?)?;
            match key.local {
                IpAddr::V4(_) => v4 = Some(socket),
                IpAddr::V6(_) => v6 = Some(socket),
            }
        }
        lease.listening = Some(
            self.inner
                .own
                .listen(port.udp.iter().map(|(k, _)| *k).collect()),
        );
        Ok(KernelDatagram {
            v4,
            v6,
            end,
            local_v4: self.inner.v4,
            local_v6: self.inner.v6,
            _lease: lease,
        })
    }

    fn direct_udp(&self, port: u16, policy: Arc<dyn DirectUdpPolicy>) -> io::Result<DirectUdpPort> {
        self.inner.direct.register(port, policy)
    }

    fn reset_port(&self, port: &KernelPort) -> usize {
        let live = self.inner.live.lock();
        let mut reset = 0;
        for flow in live.values() {
            if let (Ender::Tcp(fd), Some(p)) = (&flow.ender, flow.inbound_port)
                && p == port.port
            {
                abort_tcp(fd);
                reset += 1;
            }
        }
        drop(live);
        reset
    }
}

impl TunnelConnector for KernelConnector {
    type Stream = KernelStream;
    type Datagram = KernelDatagram;

    async fn connect_tcp(&self, dst: SocketAddr, class: FlowClass) -> io::Result<KernelStream> {
        self.connect(dst, class).await
    }

    fn bind_udp(&self, class: FlowClass) -> io::Result<KernelDatagram> {
        self.bind(class)
    }

    fn supports(&self, ip: IpAddr) -> bool {
        self.source_for(ip.to_canonical()).is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::time::Duration;

    use tokio::io::AsyncReadExt;

    use super::super::flows::OwnInbound;
    use super::*;

    /// A connector whose "tunnel address" is 127.0.0.1: everything that reaches it is from
    /// inside (loopback), so nothing it accepts is forwarded.
    struct AllowAll;

    impl super::super::filter::DestinationCheck for AllowAll {
        fn allows(&self, _: SocketAddr) -> bool {
            true
        }
    }

    fn connector() -> (KernelConnector, Arc<Gate>) {
        let gate = Arc::new(Gate::default());
        gate.set(GateState::Open);
        let own = OwnFlows::default();
        let filter = super::super::filter::PacketFilter::new(
            gate.clone(),
            own.clone(),
            Arc::new(AllowAll),
            Some(Ipv4Addr::LOCALHOST),
            None,
        );
        let k = KernelConnector::new(
            gate.clone(),
            own,
            filter.direct_ports(),
            Some(Ipv4Addr::LOCALHOST),
            None,
            NetstackLimits::default(),
            TransportPlan::default(),
        );
        (k, gate)
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[tokio::test]
    async fn a_reserved_port_is_held_and_takes_connections_only_through_a_listener() {
        let (k, gate) = connector();
        let port = free_port();
        let key = FlowKey {
            proto: L4::Tcp,
            local: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        };
        let udp_key = FlowKey {
            proto: L4::Udp,
            ..key
        };
        let held = k.reserve(port, true, true).unwrap();
        // Nobody else in the namespace can take the port meanwhile.
        let taken = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap_err();
        assert_eq!(taken.kind(), io::ErrorKind::AddrInUse);
        let taken = std::net::UdpSocket::bind(("127.0.0.1", port)).unwrap_err();
        assert_eq!(taken.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(
            k.inner.own.admits_inbound(&key, true),
            Some(OwnInbound::Closed)
        );
        assert_eq!(
            k.inner.own.admits_inbound(&udp_key, false),
            Some(OwnInbound::Drop)
        );

        // Not while the gate is closed.
        gate.set(GateState::Closed);
        let closed = k.listen_tcp(&held, 4).err().unwrap();
        assert_eq!(closed.kind(), io::ErrorKind::PermissionDenied);
        gate.set(GateState::Open);

        let mut listener = k.listen_tcp(&held, 4).unwrap();
        let datagrams = k.listen_udp(&held).unwrap();
        assert_eq!(
            k.inner.own.admits_inbound(&key, true),
            Some(OwnInbound::Pass)
        );
        assert_eq!(
            k.inner.own.admits_inbound(&udp_key, false),
            Some(OwnInbound::Pass)
        );

        // A connection from inside the sandbox (its loopback) is reset, never handed over.
        let mut inside = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let accepted = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
        assert!(accepted.is_err(), "nothing from inside is accepted");
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), inside.read(&mut buf))
            .await
            .unwrap();
        assert_matches!(read, Ok(0) | Err(_));
        assert_eq!(k.reset_port(&held), 0);

        // A listener of the next lease opened before this one is gone keeps the port listening.
        let next = k.listen_tcp(&held, 4).unwrap();
        drop(listener);
        assert_eq!(
            k.inner.own.admits_inbound(&key, true),
            Some(OwnInbound::Pass)
        );
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
        );
        drop(next);
        drop(datagrams);
        assert_eq!(
            k.inner.own.admits_inbound(&key, true),
            Some(OwnInbound::Closed)
        );
        assert_eq!(
            k.inner.own.admits_inbound(&udp_key, false),
            Some(OwnInbound::Drop)
        );
        assert_eq!(k.stats().active_udp.load(Ordering::Relaxed), 0);

        drop(held);
        assert_eq!(k.inner.own.admits_inbound(&key, false), None);
        std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        std::net::UdpSocket::bind(("127.0.0.1", port)).unwrap();
    }
}
