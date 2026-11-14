//! TCP over the tunnel netstack.

use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::{self as stcp, RecvError, SendError, State};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{FlowClass, FlowMeta, Proto, Shared, Stack};
use crate::transport::{Congestion, FlowTuning};

/// The shortest time over which a connection's use of a buffer is measured: an application
/// empties or fills a buffer in bursts, which say nothing about the rate until they are averaged.
const MIN_GROWTH_WINDOW: Duration = Duration::from_millis(10);
/// The round trip assumed for a connection whose own is not known: one accepted before anything
/// was measured through the tunnel.
const DEFAULT_ROUND_TRIP: Duration = Duration::from_millis(100);
/// No handshake is taken to be faster than this (a measured zero would make every rate look
/// too slow to need a larger buffer, which is the safe side, but the arithmetic needs a value).
const MIN_ROUND_TRIP: Duration = Duration::from_micros(50);

fn new_socket(tuning: &FlowTuning) -> stcp::Socket<'static> {
    let rx = stcp::SocketBuffer::new(vec![0u8; tuning.tcp_rx_start()]);
    let tx = stcp::SocketBuffer::new(vec![0u8; tuning.tcp_tx_start()]);
    let mut socket = stcp::Socket::new(rx, tx);
    // The window scale is fixed by the handshake: offer one that fits the buffer once grown.
    socket.set_rx_capacity_limit(tuning.tcp_rx_buffer);
    socket.set_congestion_control(match tuning.congestion.userspace() {
        Congestion::Reno => stcp::CongestionControl::Reno,
        Congestion::Cubic | Congestion::Bbr => stcp::CongestionControl::Cubic,
    });
    socket.set_nagle_enabled(tuning.nagle);
    // Keep-alives alone only probe; the timeout is what ends a connection whose peer went
    // silent (smoltcp aborts once the peer sent nothing for that long).
    let micros = |d: Duration| {
        smoltcp::time::Duration::from_micros(u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
    };
    socket.set_ack_delay(tuning.ack_delay.map(micros));
    socket.set_keep_alive(Some(micros(tuning.tcp_keepalive)));
    socket.set_timeout(Some(micros(tuning.tcp_dead_peer_timeout)));
    socket
}

/// The buffer memory a TCP connection opens with.
const fn start_bytes(tuning: &FlowTuning) -> usize {
    tuning.tcp_rx_start() + tuning.tcp_tx_start()
}

/// Which buffer of a connection.
#[derive(Debug, Clone, Copy)]
enum Side {
    Rx,
    Tx,
}

/// What one buffer carried since `since`.
#[derive(Debug)]
struct Meter {
    since: Instant,
    bytes: usize,
}

impl Meter {
    fn new() -> Self {
        Self {
            since: Instant::now(),
            bytes: 0,
        }
    }

    /// Count `moved` more bytes. Once `window` has passed: whether a buffer of `capacity`
    /// carried at least half of its size per `round_trip` since the last answer (the next
    /// count starts over).
    fn busy(
        &mut self,
        moved: usize,
        window: Duration,
        round_trip: Duration,
        capacity: usize,
    ) -> bool {
        self.bytes = self.bytes.saturating_add(moved);
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.since);
        if elapsed < window {
            return false;
        }
        let carried = (self.bytes as u128).saturating_mul(round_trip.as_micros());
        let half = (capacity as u128).saturating_mul(elapsed.as_micros()) / 2;
        self.since = now;
        self.bytes = 0;
        carried >= half
    }
}

/// How a connection's buffers follow its use.
///
/// A buffer that carries at least half of its size per round trip limits the connection (the
/// sender fills the window the buffer offers once per round trip), so it is doubled, up to the
/// size the transport allows and while the buffer budget has room for it. An idle or slow
/// connection keeps the size it opened with, and so does a fast one on a short path: there the
/// same rate is a small part of the buffer per round trip.
#[derive(Debug)]
struct Growth {
    rx_max: usize,
    tx_max: usize,
    /// The connection's round trip.
    round_trip: Duration,
    /// The time each buffer's use is averaged over: a round trip, and never less than
    /// [`MIN_GROWTH_WINDOW`].
    window: Duration,
    rx: Meter,
    tx: Meter,
}

impl Growth {
    fn new(tuning: &FlowTuning, round_trip: Option<Duration>) -> Self {
        let round_trip = round_trip.map_or(DEFAULT_ROUND_TRIP, |r| r.max(MIN_ROUND_TRIP));
        Self {
            rx_max: tuning.tcp_rx_buffer,
            tx_max: tuning.tcp_tx_buffer,
            round_trip,
            window: round_trip.max(MIN_GROWTH_WINDOW),
            rx: Meter::new(),
            tx: Meter::new(),
        }
    }
}

pub(super) async fn connect(
    shared: Arc<Shared>,
    dst: SocketAddr,
    class: FlowClass,
) -> io::Result<TcpStream> {
    connect_from(shared, None, dst, class).await
}

/// Under the stack lock, pick the source and a local port for `dst` and add the connecting
/// socket; gives the flow slot and the `memory` reservation back when it fails.
fn add_connecting(
    shared: &Shared,
    src: Option<std::net::IpAddr>,
    dst: SocketAddr,
    class: FlowClass,
    tuning: &FlowTuning,
    memory: usize,
) -> io::Result<(SocketHandle, SocketAddr)> {
    let mut guard = shared.stack.lock();
    let stack = &mut *guard;
    let source = match src {
        Some(ip) => match stack.own_source(ip, dst.ip()) {
            Ok(s) => s,
            Err(e) => {
                shared.unreserve(Proto::Tcp, memory);
                return Err(e);
            }
        },
        None => {
            if let Some(s) = stack.source_for(dst.ip()) {
                s
            } else {
                shared.unreserve(Proto::Tcp, memory);
                return Err(io::Error::new(
                    io::ErrorKind::NetworkUnreachable,
                    "the tunnel carries no address of this IP family",
                ));
            }
        }
    };
    let Some(port) = stack.tcp_ports.alloc() else {
        shared.unreserve(Proto::Tcp, memory);
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no free tunnel port",
        ));
    };
    let mut socket = new_socket(tuning);
    if let Err(e) = socket.connect(stack.iface.context(), dst, (source, port)) {
        stack.tcp_ports.release(port);
        shared.unreserve(Proto::Tcp, memory);
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tcp connect rejected: {e:?}"),
        ));
    }
    let handle = stack.sockets.add(socket);
    stack.flows.insert(
        handle,
        FlowMeta {
            class,
            proto: Proto::Tcp,
            port,
            memory,
            orphaned_at: None,
        },
    );
    drop(guard);
    Ok((handle, SocketAddr::new(source.into(), port)))
}

/// [`connect`] from a given source, one of the stack's own addresses (`None`: the tunnel
/// address of the destination's family).
#[expect(
    clippy::significant_drop_tightening,
    reason = "each poll reads the socket state and registers the waker under one stack lock"
)]
pub(super) async fn connect_from(
    shared: Arc<Shared>,
    src: Option<std::net::IpAddr>,
    dst: SocketAddr,
    class: FlowClass,
) -> io::Result<TcpStream> {
    if dst.port() == 0 || dst.ip().is_unspecified() || dst.ip().is_multicast() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination is not a unicast address",
        ));
    }
    let tuning = shared.tuning(class);
    let memory = start_bytes(&tuning);
    shared.reserve(class, Proto::Tcp, memory)?;
    let (handle, local) = add_connecting(&shared, src, dst, class, &tuning, memory)?;
    shared.stats.opened(class);
    shared.wake.notify_one();
    let sent = Instant::now();

    // From here on the stream owns the socket: dropping it (timeout, cancellation) frees it.
    let mut stream = TcpStream {
        shared: shared.clone(),
        handle,
        local,
        peer: dst,
        growth: Growth::new(&tuning, None),
    };
    let established = poll_fn(|cx| {
        let mut guard = shared.stack.lock();
        let socket = guard.sockets.get_mut::<stcp::Socket<'_>>(handle);
        match socket.state() {
            State::SynSent | State::SynReceived => {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
            State::Closed | State::TimeWait | State::Listen => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "connection refused or reset by the remote host",
            ))),
            _ => Poll::Ready(Ok(())),
        }
    });
    match tokio::time::timeout(tuning.connect_timeout, established).await {
        Ok(Ok(())) => {
            // The handshake is one round trip: what the next flows are tuned for, and the
            // time this connection's use of its buffers is measured over.
            let round_trip = sent.elapsed();
            shared.transport.record_handshake(round_trip);
            stream.growth = Growth::new(&tuning, Some(round_trip));
            shared.stats.tcp_connects.fetch_add(1, Ordering::Relaxed);
            Ok(stream)
        }
        Ok(Err(e)) => {
            shared
                .stats
                .tcp_connect_failures
                .fetch_add(1, Ordering::Relaxed);
            Err(e)
        }
        Err(_) => {
            shared
                .stats
                .tcp_connect_failures
                .fetch_add(1, Ordering::Relaxed);
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "tcp connect through the tunnel timed out",
            ))
        }
    }
}

/// A TCP connection carried by the tunnel. Dropping it closes the connection gracefully (FIN);
/// the netstack frees the socket once the close completed or the linger time expired.
#[derive(Debug)]
pub struct TcpStream {
    shared: Arc<Shared>,
    handle: SocketHandle,
    local: SocketAddr,
    peer: SocketAddr,
    growth: Growth,
}

impl TcpStream {
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Reset the connection immediately instead of a graceful close.
    pub fn abort(&self) {
        let mut guard = self.shared.stack.lock();
        guard
            .sockets
            .get_mut::<stcp::Socket<'_>>(self.handle)
            .abort();
        drop(guard);
        self.shared.wake.notify_one();
    }

    fn reset_error() -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionReset,
            "connection reset (remote, gate or instance shutdown)",
        )
    }

    /// The buffer `side` carried `moved` more bytes: double it when it limits the connection
    /// (see [`Growth`]). Everything it holds stays in place; only its size changes.
    fn follow_use(&mut self, stack: &mut Stack, side: Side, moved: usize) {
        let (window, round_trip) = (self.growth.window, self.growth.round_trip);
        let socket = stack.sockets.get_mut::<stcp::Socket<'_>>(self.handle);
        let (capacity, max, meter) = match side {
            Side::Rx => (
                socket.recv_capacity(),
                self.growth.rx_max,
                &mut self.growth.rx,
            ),
            Side::Tx => (
                socket.send_capacity(),
                self.growth.tx_max,
                &mut self.growth.tx,
            ),
        };
        if capacity < max && meter.busy(moved, window, round_trip, capacity) {
            self.enlarge(stack, side);
        }
    }

    /// Double the buffer `side`, up to the size the transport allows and while the buffer
    /// budget has room for it; whether it grew.
    fn enlarge(&self, stack: &mut Stack, side: Side) -> bool {
        let socket = stack.sockets.get_mut::<stcp::Socket<'_>>(self.handle);
        let (capacity, max) = match side {
            Side::Rx => (socket.recv_capacity(), self.growth.rx_max),
            Side::Tx => (socket.send_capacity(), self.growth.tx_max),
        };
        let to = capacity.saturating_mul(2).min(max);
        let Some(meta) = stack.flows.get_mut(&self.handle) else {
            return false;
        };
        if to <= capacity || !self.shared.reserve_growth(to - capacity) {
            return false;
        }
        meta.memory += to - capacity;
        match side {
            Side::Rx => socket.grow_rx_buffer(vec![0u8; to]),
            Side::Tx => socket.grow_tx_buffer(vec![0u8; to]),
        }
        true
    }

    /// Double both buffers now, as a connection that uses them fully gets them: whether the
    /// receive and the transmit buffer grew.
    #[cfg(test)]
    pub(super) fn grow_now(&self) -> (bool, bool) {
        let mut guard = self.shared.stack.lock();
        let grew = (
            self.enlarge(&mut guard, Side::Rx),
            self.enlarge(&mut guard, Side::Tx),
        );
        drop(guard);
        self.shared.wake.notify_one();
        grew
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let shared = this.shared.clone();
        let mut guard = shared.stack.lock();
        let socket = guard.sockets.get_mut::<stcp::Socket<'_>>(this.handle);
        match socket.recv_slice(buf.initialize_unfilled()) {
            Ok(0) => {
                if socket.may_recv() {
                    socket.register_recv_waker(cx.waker());
                    Poll::Pending
                } else if socket.state() == State::Closed {
                    Poll::Ready(Err(Self::reset_error()))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            Ok(n) => {
                buf.advance(n);
                this.follow_use(&mut guard, Side::Rx, n);
                drop(guard);
                // The receive window grew; let the pump advertise it.
                shared.wake.notify_one();
                Poll::Ready(Ok(()))
            }
            Err(RecvError::Finished) => Poll::Ready(Ok(())),
            Err(RecvError::InvalidState) => Poll::Ready(Err(Self::reset_error())),
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let shared = this.shared.clone();
        let mut guard = shared.stack.lock();
        let socket = guard.sockets.get_mut::<stcp::Socket<'_>>(this.handle);
        match socket.send_slice(data) {
            Ok(0) => {
                if socket.may_send() {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                } else {
                    Poll::Ready(Err(Self::reset_error()))
                }
            }
            Ok(n) => {
                this.follow_use(&mut guard, Side::Tx, n);
                drop(guard);
                shared.wake.notify_one();
                Poll::Ready(Ok(n))
            }
            Err(SendError::InvalidState) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection is closed for writing",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Data handed to the socket buffer is transmitted by the pump; nothing to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.shared.stack.lock();
        guard
            .sockets
            .get_mut::<stcp::Socket<'_>>(self.handle)
            .close();
        drop(guard);
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.shared.orphan(self.handle);
    }
}

/// Inbound TCP on one tunnel port. Keeps `backlog` sockets listening so concurrent SYNs are
/// accepted; smoltcp turns a listening socket into the connection itself.
#[derive(Debug)]
pub struct TcpListener {
    shared: Arc<Shared>,
    port: u16,
    class: FlowClass,
    /// The sockets waiting for a connection, each with what it was opened with.
    listening: Vec<(SocketHandle, FlowTuning)>,
    backlog: usize,
    /// The listener claimed its port and frees it when dropped (a reserved port is freed by its
    /// reservation instead).
    owns_port: bool,
}

pub(super) fn listen(
    shared: Arc<Shared>,
    port: u16,
    backlog: usize,
    class: FlowClass,
) -> io::Result<TcpListener> {
    if port == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "port 0"));
    }
    {
        let mut guard = shared.stack.lock();
        if !guard.tcp_ports.claim(port) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "tunnel port already in use",
            ));
        }
    }
    listen_on(shared, port, backlog, class, true)
}

/// Listen on `port`, already claimed (by the caller when `owns_port`, else by a reservation).
pub(super) fn listen_on(
    shared: Arc<Shared>,
    port: u16,
    backlog: usize,
    class: FlowClass,
    owns_port: bool,
) -> io::Result<TcpListener> {
    let mut listener = TcpListener {
        shared,
        port,
        class,
        listening: Vec::new(),
        backlog: backlog.max(1),
        owns_port,
    };
    for _ in 0..listener.backlog {
        listener.add_listening()?;
    }
    Ok(listener)
}

impl TcpListener {
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Bring the listening sockets back up to the backlog; they run short while the flow or
    /// memory limit refuses new ones. Errors only when none is listening afterwards.
    fn replenish(&mut self) -> io::Result<()> {
        let mut last = None;
        while self.listening.len() < self.backlog {
            if let Err(e) = self.add_listening() {
                last = Some(e);
                break;
            }
        }
        match last {
            Some(e) if self.listening.is_empty() => Err(e),
            _ => Ok(()),
        }
    }

    fn add_listening(&mut self) -> io::Result<()> {
        let tuning = self.shared.tuning(self.class);
        let memory = start_bytes(&tuning);
        self.shared.reserve(self.class, Proto::TcpListen, memory)?;
        let mut guard = self.shared.stack.lock();
        let stack = &mut *guard;
        let mut socket = new_socket(&tuning);
        if let Err(e) = socket.listen(self.port) {
            self.shared.unreserve(Proto::TcpListen, memory);
            return Err(io::Error::other(format!("tcp listen failed: {e:?}")));
        }
        let handle = stack.sockets.add(socket);
        stack.flows.insert(
            handle,
            FlowMeta {
                class: self.class,
                proto: Proto::TcpListen,
                port: 0,
                memory,
                orphaned_at: None,
            },
        );
        drop(guard);
        self.listening.push((handle, tuning));
        Ok(())
    }

    /// Wait for the next established inbound connection. When no socket is listening (every
    /// one refused by the flow or memory limit, or the gate closed meanwhile) it fails with that
    /// refusal instead of waiting forever; calling it again later tries to listen again.
    ///
    /// # Errors
    ///
    /// The flow or memory limit's refusal (or the closed gate's) when no socket is listening,
    /// and `ConnectionAborted` once the Instance is sealed.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "each poll scans the backlog and checks the gate under one stack lock"
    )]
    pub async fn accept(&mut self) -> io::Result<TcpStream> {
        self.replenish()?;
        let shared = self.shared.clone();
        let accepted = poll_fn(|cx| {
            let mut guard = shared.stack.lock();
            let stack = &mut *guard;
            for (i, (handle, _)) in self.listening.iter().enumerate() {
                let socket = stack.sockets.get_mut::<stcp::Socket<'_>>(*handle);
                match socket.state() {
                    State::Listen | State::SynReceived => {
                        socket.register_recv_waker(cx.waker());
                        socket.register_send_waker(cx.waker());
                    }
                    State::Established | State::CloseWait => {
                        let peer = socket.remote_endpoint();
                        let local = socket.local_endpoint();
                        if let (Some(peer), Some(local)) = (peer, local) {
                            if let Some(meta) = stack.flows.get_mut(handle) {
                                meta.proto = Proto::Tcp;
                            }
                            return Poll::Ready(Ok((i, peer.into(), local.into())));
                        }
                    }
                    _ => {
                        // Reset before we accepted it: recycle the slot. (An aborted socket is
                        // closed and the port is not 0, so listening again does not fail; a
                        // slot that did stays closed and is tried again on the next poll.)
                        socket.abort();
                        if let Err(e) = socket.listen(self.port) {
                            tracing::debug!(
                                port = self.port,
                                error = %e,
                                "listening socket not recycled"
                            );
                        }
                        socket.register_recv_waker(cx.waker());
                    }
                }
            }
            if self.shared.gate.get() == super::GateState::Sealed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "instance sealed",
                )));
            }
            Poll::Pending
        })
        .await;
        let (index, peer, local): (usize, SocketAddr, SocketAddr) = accepted?;
        let (handle, tuning) = self.listening.swap_remove(index);
        // The handshake of an inbound connection is not timed: its use is measured over the
        // round trip of the tunnel's other connections.
        let (_, round_trip) = self.shared.transport.select();
        self.shared.stats.active_tcp.fetch_add(1, Ordering::Relaxed);
        self.shared.stats.opened(self.class);
        self.shared
            .stats
            .tcp_accepts
            .fetch_add(1, Ordering::Relaxed);
        // Keep the backlog full; failure (budget) just shrinks it until flows end.
        if let Err(e) = self.add_listening() {
            tracing::debug!(port = self.port, error = %e, "listener backlog not replenished");
        }
        self.shared.wake.notify_one();
        Ok(TcpStream {
            shared: self.shared.clone(),
            handle,
            local,
            peer,
            growth: Growth::new(&tuning, round_trip),
        })
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        for (handle, _) in self.listening.drain(..) {
            self.shared.orphan(handle);
        }
        if self.owns_port {
            self.shared.stack.lock().tcp_ports.release(self.port);
        }
    }
}
