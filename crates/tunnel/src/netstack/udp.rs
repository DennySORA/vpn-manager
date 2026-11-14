//! UDP over the tunnel netstack.

use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp::{self as sudp, RecvError, SendError};
use smoltcp::wire::IpEndpoint;

use super::{FlowClass, FlowMeta, Proto, Shared};

/// IPv6 has no in-stack fragmentation: keep datagrams within the minimum IPv6 MTU payload.
const MAX_V6_DATAGRAM: usize = 1280 - 40 - 8;

pub(super) fn bind(
    shared: Arc<Shared>,
    port: Option<u16>,
    class: FlowClass,
) -> io::Result<UdpSocket> {
    bind_at(shared, None, port, class, true)
}

/// Bind on `addr` (one of the stack's own addresses, checked by the caller; `None`: all of
/// them) and `port` (`None`: an ephemeral one). With `owns_port` a fixed port is claimed here
/// and freed with the socket; without, it is a reserved port the reservation frees.
pub(super) fn bind_at(
    shared: Arc<Shared>,
    addr: Option<std::net::IpAddr>,
    port: Option<u16>,
    class: FlowClass,
    owns_port: bool,
) -> io::Result<UdpSocket> {
    let tuning = shared.tuning(class);
    let memory = tuning.udp_buffer * 2;
    shared.reserve(class, Proto::Udp, memory)?;
    let mut guard = shared.stack.lock();
    let stack = &mut *guard;
    let port = match port {
        Some(p) if !owns_port => p,
        Some(p) => {
            if !stack.udp_ports.claim(p) {
                drop(guard);
                shared.unreserve(Proto::Udp, memory);
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "tunnel UDP port already in use",
                ));
            }
            p
        }
        None => {
            if let Some(p) = stack.udp_ports.alloc() {
                p
            } else {
                drop(guard);
                shared.unreserve(Proto::Udp, memory);
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no free tunnel port",
                ));
            }
        }
    };
    let packets = tuning.udp_packets;
    let rx = sudp::PacketBuffer::new(
        vec![sudp::PacketMetadata::EMPTY; packets],
        vec![0u8; tuning.udp_buffer],
    );
    let tx = sudp::PacketBuffer::new(
        vec![sudp::PacketMetadata::EMPTY; packets],
        vec![0u8; tuning.udp_buffer],
    );
    let mut socket = sudp::Socket::new(rx, tx);
    let endpoint = smoltcp::wire::IpListenEndpoint {
        addr: addr.map(Into::into),
        port,
    };
    // A reserved port stays with its reservation: the flow records port 0, which the garbage
    // collector never frees.
    let owned = if owns_port { port } else { 0 };
    if let Err(e) = socket.bind(endpoint) {
        stack.udp_ports.release(owned);
        drop(guard);
        shared.unreserve(Proto::Udp, memory);
        return Err(io::Error::other(format!("udp bind failed: {e:?}")));
    }
    let handle = stack.sockets.add(socket);
    stack.flows.insert(
        handle,
        FlowMeta {
            class,
            proto: Proto::Udp,
            port: owned,
            memory,
            orphaned_at: None,
        },
    );
    drop(guard);
    shared.stats.opened(class);
    Ok(UdpSocket {
        shared,
        handle,
        port,
    })
}

/// A UDP socket bound to a tunnel port. Dropping it frees the port.
#[derive(Debug)]
pub struct UdpSocket {
    shared: Arc<Shared>,
    handle: SocketHandle,
    port: u16,
}

impl UdpSocket {
    #[must_use]
    pub const fn local_port(&self) -> u16 {
        self.port
    }

    fn closed_error() -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "udp socket closed (gate or instance shutdown)",
        )
    }

    /// Send one datagram through the tunnel. Waits while the socket's send buffer is full.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for an oversized IPv6 datagram or an unaddressable destination,
    /// `NetworkUnreachable` when the tunnel carries no address of its family, and
    /// `ConnectionAborted` once the socket was closed.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "each poll checks the socket and registers the waker under one stack lock"
    )]
    pub async fn send_to(&self, data: &[u8], dst: SocketAddr) -> io::Result<()> {
        if dst.is_ipv6() && data.len() > MAX_V6_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram exceeds the IPv6 tunnel MTU",
            ));
        }
        if dst.port() == 0 || dst.ip().is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination is not addressable",
            ));
        }
        let endpoint = IpEndpoint::from(dst);
        poll_fn(|cx| {
            let mut guard = self.shared.stack.lock();
            let stack = &mut *guard;
            if stack.source_for(dst.ip()).is_none() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NetworkUnreachable,
                    "the tunnel carries no address of this IP family",
                )));
            }
            let socket = stack.sockets.get_mut::<sudp::Socket<'_>>(self.handle);
            if !socket.is_open() {
                return Poll::Ready(Err(Self::closed_error()));
            }
            match socket.send_slice(data, endpoint) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(SendError::BufferFull) => {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
                Err(SendError::Unaddressable) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "destination unaddressable",
                ))),
            }
        })
        .await?;
        self.shared.wake.notify_one();
        Ok(())
    }

    /// Receive one datagram. Truncates if `buf` is too small, like a kernel socket.
    ///
    /// # Errors
    ///
    /// `ConnectionAborted` once the socket was closed; `InvalidData` for a datagram smoltcp
    /// could only keep truncated.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "each poll copies the datagram out of the socket buffer under the stack lock"
    )]
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| {
            let mut guard = self.shared.stack.lock();
            let socket = guard.sockets.get_mut::<sudp::Socket<'_>>(self.handle);
            if !socket.is_open() {
                return Poll::Ready(Err(Self::closed_error()));
            }
            match socket.recv() {
                Ok((payload, meta)) => {
                    let n = payload.len().min(buf.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    Poll::Ready(Ok((n, SocketAddr::from(meta.endpoint))))
                }
                Err(RecvError::Exhausted) => {
                    socket.register_recv_waker(cx.waker());
                    Poll::Pending
                }
                Err(RecvError::Truncated) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated datagram",
                ))),
            }
        })
        .await
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        self.shared.orphan(self.handle);
    }
}
