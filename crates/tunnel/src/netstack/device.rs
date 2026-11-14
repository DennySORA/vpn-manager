//! smoltcp `Device` over the bounded IP channel.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use gotatun::packet::Packet;
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

use crate::ipchan::IpChannelShared;

pub struct QueueDevice {
    pub(crate) chan: Arc<IpChannelShared>,
    pub(crate) mtu: usize,
}

impl QueueDevice {
    pub(crate) fn has_ingress(&self) -> bool {
        !self.chan.inbound.is_empty()
    }

    pub(crate) fn egress_full(&self) -> bool {
        self.chan.outbound.is_full()
    }
}

impl phy::Device for QueueDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.chan.inbound.pop()?;
        Some((RxToken(packet), TxToken { chan: &self.chan }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        // A full outbound queue is backpressure: smoltcp keeps the data in socket buffers.
        if self.chan.outbound.is_full() {
            None
        } else {
            Some(TxToken { chan: &self.chan })
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(64);
        caps
    }
}

pub struct RxToken(Packet<[u8]>);

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

pub struct TxToken<'a> {
    chan: &'a IpChannelShared,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = self.chan.pool.get();
        if packet.len() < len {
            packet = Packet::from_bytes(bytes::BytesMut::zeroed(len));
        }
        packet.truncate(len);
        let result = f(&mut packet);
        if self.chan.outbound.push(packet).is_err() {
            // Only reachable from a reply token handed out by `receive` while the queue filled up.
            self.chan
                .stats
                .outbound_dropped
                .fetch_add(1, Ordering::Relaxed);
        }
        self.chan.outbound_ready.notify_one();
        result
    }
}
