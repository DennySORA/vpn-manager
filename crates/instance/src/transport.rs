//! The connection's transport profile as the data plane takes it.

use std::time::Duration;

use vpn_domain::{CongestionControl, FlowSettings, ResolvedTransport};
use vpn_tunnel::{Band, Congestion, FlowTuning, TransportPlan};

const KIB: usize = 1024;

fn tuning(f: &FlowSettings) -> FlowTuning {
    let bytes = |kib: u32| (kib as usize).saturating_mul(KIB);
    FlowTuning {
        tcp_rx_buffer: bytes(f.tcp_recv_kib),
        tcp_rx_initial: bytes(f.tcp_recv_start_kib),
        tcp_tx_buffer: bytes(f.tcp_send_kib),
        tcp_tx_initial: bytes(f.tcp_send_start_kib),
        congestion: match f.congestion {
            CongestionControl::Cubic => Congestion::Cubic,
            CongestionControl::Reno => Congestion::Reno,
            CongestionControl::Bbr => Congestion::Bbr,
        },
        nagle: f.nagle,
        ack_delay: (f.ack_delay_ms > 0).then(|| Duration::from_millis(u64::from(f.ack_delay_ms))),
        connect_timeout: Duration::from_secs(u64::from(f.connect_timeout_secs)),
        tcp_keepalive: Duration::from_secs(u64::from(f.keepalive_secs)),
        tcp_dead_peer_timeout: Duration::from_secs(u64::from(f.dead_peer_secs)),
        udp_buffer: bytes(f.udp_buffer_kib),
        // One datagram slot per KiB of buffer, as the default of 64 slots for 64 KiB.
        udp_packets: (f.udp_buffer_kib as usize).clamp(16, 1024),
    }
}

/// The data plane's plan of a resolved transport.
///
/// The manager sends only what its validation accepted. Should the ranges still not be in order,
/// the worker runs the values every connection had before transport profiles existed instead of
/// refusing to start.
#[must_use]
pub fn plan(transport: &ResolvedTransport) -> TransportPlan {
    let bands = transport
        .bands
        .iter()
        .map(|b| Band {
            from_rtt: Duration::from_millis(u64::from(b.from_rtt_ms)),
            tuning: tuning(&b.flow),
        })
        .collect();
    TransportPlan::new(bands).unwrap_or_default()
}
