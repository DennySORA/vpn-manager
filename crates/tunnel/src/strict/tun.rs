//! The sandbox's TUN device as `GotaTun`'s IP transport, with the packet filter on both
//! directions.
//!
//! - [`TunRecv`] (`GotaTun` reads): packets the sandbox sends are filtered; passed ones go to
//!   `GotaTun`, refused ones are answered right back into the TUN device (reset / ICMP error).
//!   Packets queued with [`Injector`] (resets towards remote hosts when flows end) go first.
//! - [`TunSend`] (`GotaTun` writes): decrypted packets from the peer are filtered before they are
//!   written into the TUN device.

#![expect(
    unsafe_code,
    reason = "the TUN device: libc ioctl, read and write on its descriptor and its AsyncFd registration"
)]

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Instant;

use crossbeam_queue::ArrayQueue;
use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;

use super::filter::{Inbound, Outbound, PacketFilter};

/// Packets handed to `GotaTun` per `recv` call at most.
const MAX_BATCH: usize = 64;
/// Injected packets waiting for `GotaTun` at most (more are dropped).
const INJECT_QUEUE: usize = 4096;

/// `TUNGETIFF` (`_IOR('T', 210, unsigned int)`).
const TUNGETIFF: libc::c_ulong = 0x8004_54d2;

/// `struct ifreq` as far as the TUN ioctls use it.
#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

pub struct Tun {
    fd: AsyncFd<OwnedFd>,
    mtu: u16,
}

/// Name of the interface a TUN descriptor is attached to.
pub fn interface_name(fd: RawFd) -> io::Result<String> {
    let mut req = IfReq {
        name: [0; libc::IFNAMSIZ],
        flags: 0,
        _pad: [0; 22],
    };
    // SAFETY: TUNGETIFF fills a `struct ifreq`, which `IfReq` matches in size and layout.
    let r = unsafe { libc::ioctl(fd, TUNGETIFF as _, &raw mut req) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    let end = req
        .name
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(req.name.len());
    Ok(String::from_utf8_lossy(&req.name[..end]).into_owned())
}

impl Tun {
    /// Take over a TUN descriptor, checking that it is attached to `expected` (so a worker never
    /// feeds some other device).
    pub(crate) fn new(fd: OwnedFd, expected: &str, mtu: u16) -> io::Result<Self> {
        let name = interface_name(fd.as_raw_fd())?;
        if name != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the TUN descriptor belongs to {name:?}, not {expected:?}"),
            ));
        }
        // SAFETY: F_GETFL on a descriptor we own; it takes no pointer.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_SETFL on a descriptor we own, with its own flags plus `O_NONBLOCK`; it takes
        // no pointer.
        let set = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if set < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: an `OwnedFd` stays open and refers to the same file description until the
        // `AsyncFd` (its only owner) is dropped.
        let fd = unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }?;
        Ok(Self { fd, mtu })
    }

    /// Write one packet into the TUN device (the sandbox receives it). The device never blocks
    /// a writer; a packet it cannot take is dropped like on a full link.
    pub(crate) fn write(&self, packet: &[u8]) -> io::Result<()> {
        loop {
            // SAFETY: writing an initialized buffer of the given length to a valid descriptor.
            let n = unsafe {
                libc::write(
                    self.fd.get_ref().as_raw_fd(),
                    packet.as_ptr().cast(),
                    packet.len(),
                )
            };
            if n >= 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

/// Packets for `GotaTun` that did not come from the TUN device.
pub struct Injector {
    queue: ArrayQueue<Packet<[u8]>>,
    wake: Notify,
}

impl Injector {
    pub(crate) fn new() -> Self {
        Self {
            queue: ArrayQueue::new(INJECT_QUEUE),
            wake: Notify::new(),
        }
    }

    pub(crate) fn push(&self, packet: &[u8]) {
        let packet = Packet::from_bytes(bytes::BytesMut::from(packet));
        if self.queue.push(packet).is_err() {
            // Full: the packet is dropped, like on a full link (see `INJECT_QUEUE`).
            tracing::trace!("injected packet dropped: queue full");
        }
        self.wake.notify_one();
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// `GotaTun`'s receiving side: what the sandbox sends.
pub struct TunRecv {
    pub(crate) tun: Arc<Tun>,
    pub(crate) filter: Arc<PacketFilter>,
    pub(crate) inject: Arc<Injector>,
}

impl IpRecv for TunRecv {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        loop {
            let injected = self.inject.wake.notified();
            tokio::pin!(injected);
            injected.as_mut().enable();
            let mut batch = Vec::new();
            while batch.len() < MAX_BATCH {
                let Some(packet) = self.inject.queue.pop() else {
                    break;
                };
                if let Ok(ip) = packet.try_into_ip() {
                    batch.push(ip);
                }
            }
            if !batch.is_empty() {
                return Ok(batch.into_iter());
            }
            let mut guard = tokio::select! {
                g = self.tun.fd.readable() => g?,
                () = &mut injected => continue,
            };
            let now = Instant::now();
            while batch.len() < MAX_BATCH {
                let mut buf = pool.get();
                let read = guard.try_io(|fd| {
                    // SAFETY: reading into a buffer we own, at most its length.
                    let n = unsafe {
                        libc::read(fd.get_ref().as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())
                    };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(n.cast_unsigned())
                    }
                });
                let n = match read {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                    // The device is gone: GotaTun treats this as fatal and the tunnel seals.
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => break,
                };
                buf.truncate(n);
                match self.filter.outbound(&buf, now) {
                    Outbound::Pass => {
                        if let Ok(ip) = buf.try_into_ip() {
                            batch.push(ip);
                        }
                    }
                    Outbound::Refuse(answer) => {
                        // Best effort: an answer the device cannot take is lost like any packet
                        // on a full link; a device that is gone fails the next read.
                        if let Err(e) = self.tun.write(&answer) {
                            tracing::trace!(error = %e, "refusal not written to the TUN device");
                        }
                    }
                    Outbound::Drop => {}
                }
            }
            if !batch.is_empty() {
                return Ok(batch.into_iter());
            }
        }
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.tun.mtu)
    }
}

/// `GotaTun`'s sending side: what the peer sends into the sandbox.
pub struct TunSend {
    pub(crate) tun: Arc<Tun>,
    pub(crate) filter: Arc<PacketFilter>,
    /// Where refusals go back into the tunnel.
    pub(crate) inject: Arc<Injector>,
}

impl IpSend for TunSend {
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait requires a future; the write never waits (a full device drops the packet)"
    )]
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let bytes = packet.into_bytes();
        match self.filter.inbound(&bytes, Instant::now()) {
            Inbound::Pass => {}
            Inbound::Drop => return Ok(()),
            Inbound::Refuse(answer) => {
                self.inject.push(&answer);
                return Ok(());
            }
        }
        match self.tun.write(&bytes) {
            // The device was deleted or detached: fatal for the tunnel.
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EBADF | libc::EBADFD | libc::ENODEV)
                ) =>
            {
                Err(e)
            }
            // Written; anything else loses this packet only (like a full queue).
            Ok(()) | Err(_) => Ok(()),
        }
    }
}
