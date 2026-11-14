//! Bounded IP packet channel between the `GotaTun` [`Device`](gotatun::device::Device) and the
//! userspace netstack.
//!
//! `GotaTun` sees this as its "TUN device":
//! - [`IpChannelTx`] implements [`IpSend`]: `GotaTun` hands us decrypted packets from the peer.
//! - [`IpChannelRx`] implements [`IpRecv`]: `GotaTun` pulls packets the netstack wants encrypted.
//!
//! Both directions are bounded lock-free queues. A full inbound queue drops the packet (like a NIC
//! ring overflow, counted); a full outbound queue makes the netstack's `transmit()` return `None`,
//! which keeps the data in the socket buffers instead of dropping it (backpressure).

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_queue::ArrayQueue;
use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use tokio::sync::Notify;

/// Maximum packets `GotaTun` takes from the outbound queue per `recv` call.
const MAX_BATCH: usize = 64;

/// Counters shared by both halves of the channel.
#[derive(Debug, Default)]
pub struct IpChannelStats {
    /// Decrypted packets accepted into the netstack inbound queue.
    pub inbound_packets: AtomicU64,
    /// Decrypted packets dropped because the inbound queue was full.
    pub inbound_dropped: AtomicU64,
    /// Packets handed to `GotaTun` for encryption.
    pub outbound_packets: AtomicU64,
    /// Packets dropped because the outbound queue was full when a reply token fired.
    pub outbound_dropped: AtomicU64,
    /// Decrypted IP payload bytes (inner packets) received from the peer.
    pub inbound_bytes: AtomicU64,
    /// IP payload bytes (inner packets) sent towards the peer.
    pub outbound_bytes: AtomicU64,
}

/// Shared state for both halves.
pub struct IpChannelShared {
    /// Peer -> netstack (decrypted).
    pub(crate) inbound: ArrayQueue<Packet<[u8]>>,
    /// Netstack -> peer (to be encrypted).
    pub(crate) outbound: ArrayQueue<Packet<[u8]>>,
    /// Wakes the netstack pump (new inbound packet or outbound space).
    pub(crate) stack_wake: Arc<Notify>,
    /// Wakes the `GotaTun` side (new outbound packet).
    pub(crate) outbound_ready: Notify,
    /// Buffers for outbound packets, so the netstack writes directly into GotaTun-compatible
    /// buffers and no extra copy happens on the way out.
    pub(crate) pool: PacketBufPool,
    pub(crate) mtu: u16,
    pub(crate) stats: Arc<IpChannelStats>,
}

/// Create a channel. `stack_wake` is the notifier of the netstack pump.
pub fn channel(
    capacity: usize,
    mtu: u16,
    stack_wake: Arc<Notify>,
    stats: Arc<IpChannelStats>,
) -> (IpChannelTx, IpChannelRx, Arc<IpChannelShared>) {
    let shared = Arc::new(IpChannelShared {
        inbound: ArrayQueue::new(capacity),
        outbound: ArrayQueue::new(capacity),
        stack_wake,
        outbound_ready: Notify::new(),
        pool: PacketBufPool::new(capacity.min(512)),
        mtu,
        stats,
    });
    (
        IpChannelTx {
            shared: shared.clone(),
        },
        IpChannelRx {
            shared: shared.clone(),
        },
        shared,
    )
}

/// `GotaTun` -> netstack half.
#[derive(Clone)]
pub struct IpChannelTx {
    shared: Arc<IpChannelShared>,
}

impl IpSend for IpChannelTx {
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait requires a future; pushing to the lock-free queue never waits"
    )]
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let packet = packet.into_bytes();
        let len = packet.len() as u64;
        match self.shared.inbound.push(packet) {
            Ok(()) => {
                self.shared
                    .stats
                    .inbound_packets
                    .fetch_add(1, Ordering::Relaxed);
                self.shared
                    .stats
                    .inbound_bytes
                    .fetch_add(len, Ordering::Relaxed);
            }
            Err(_dropped) => {
                self.shared
                    .stats
                    .inbound_dropped
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        self.shared.stack_wake.notify_one();
        Ok(())
    }
}

/// Netstack -> `GotaTun` half.
pub struct IpChannelRx {
    shared: Arc<IpChannelShared>,
}

impl IpRecv for IpChannelRx {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        loop {
            // Register interest before checking the queue so a concurrent push cannot be missed.
            let notified = self.shared.outbound_ready.notified();
            let mut batch = Vec::new();
            while batch.len() < MAX_BATCH {
                let Some(packet) = self.shared.outbound.pop() else {
                    break;
                };
                let len = packet.len() as u64;
                // The netstack only emits well-formed IP packets; anything else is dropped.
                if let Ok(ip) = packet.try_into_ip() {
                    self.shared
                        .stats
                        .outbound_packets
                        .fetch_add(1, Ordering::Relaxed);
                    self.shared
                        .stats
                        .outbound_bytes
                        .fetch_add(len, Ordering::Relaxed);
                    batch.push(ip);
                }
            }
            if !batch.is_empty() {
                // Space was freed: the netstack may have been holding back transmissions.
                self.shared.stack_wake.notify_one();
                return Ok(batch.into_iter());
            }
            notified.await;
        }
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.shared.mtu)
    }
}
