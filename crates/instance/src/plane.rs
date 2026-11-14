//! The worker's data plane: the userspace netstack, or the strict sandbox's TUN device.
//!
//! The netstack serves the explicit proxy; on Linux the strict sandbox's TUN device comes with
//! kernel sockets. Everything above it — DNS, Gateways, the Provider
//! connector, the inner watchdog — is the same code for both.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Duration;

use vpn_domain::{CongestionFallback, CongestionStatus};
use vpn_ipc::worker::SandboxWire;
use vpn_tunnel::{
    AnyConnector, AnyInbound, FlowClass, GateState, PeerSnapshot, TransportPlan, TransportSnapshot,
    Tunnel, TunnelError,
};

use crate::policy::DestinationPolicy;

/// The App-flow policy of a strict sandbox is the Instance's destination policy.
impl vpn_tunnel::strict::DestinationCheck for DestinationPolicy {
    fn allows(&self, dst: SocketAddr) -> bool {
        self.check(dst).is_ok()
    }
}

/// Counters of the data plane for the worker's status report.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlaneCounters {
    pub wg_rx_bytes: u64,
    pub wg_tx_bytes: u64,
    pub underlay_blocked: u64,
    pub tunnel_rx_bytes: u64,
    pub tunnel_tx_bytes: u64,
    pub active_tcp: u64,
    pub active_udp: u64,
    pub admission_rejected: u64,
    /// Socket buffer memory reserved in userspace (the kernel stack reserves none here).
    pub memory_reserved: u64,
    /// Strict mode: the sandbox's Apps (`None` on the netstack, which has no Apps behind it).
    pub sandbox: Option<SandboxWire>,
}

#[derive(Clone)]
pub enum Plane {
    Netstack(Tunnel),
    #[cfg(target_os = "linux")]
    Strict(vpn_tunnel::strict::StrictTunnel),
}

impl Plane {
    #[must_use]
    pub fn connector(&self) -> AnyConnector {
        match self {
            Self::Netstack(t) => AnyConnector::Netstack(t.netstack()),
            #[cfg(target_os = "linux")]
            Self::Strict(t) => AnyConnector::Kernel(t.connector()),
        }
    }

    /// The inbound side, for port forwards.
    #[must_use]
    pub fn inbound(&self) -> AnyInbound {
        match self {
            Self::Netstack(t) => AnyInbound::Netstack(t.netstack()),
            #[cfg(target_os = "linux")]
            Self::Strict(t) => AnyInbound::Kernel(t.connector()),
        }
    }

    #[must_use]
    pub fn gate(&self) -> GateState {
        match self {
            Self::Netstack(t) => t.netstack().gate(),
            #[cfg(target_os = "linux")]
            Self::Strict(t) => t.gate(),
        }
    }

    #[must_use]
    pub fn set_gate(&self, next: GateState) -> GateState {
        match self {
            Self::Netstack(t) => t.netstack().set_gate(next),
            #[cfg(target_os = "linux")]
            Self::Strict(t) => t.set_gate(next),
        }
    }

    pub fn reset_flows(&self, class: Option<FlowClass>) {
        match self {
            Self::Netstack(t) => t.netstack().reset_flows(class),
            #[cfg(target_os = "linux")]
            Self::Strict(t) => t.reset_flows(class),
        }
    }

    /// Reset the established TCP flows of `class` whose remote address `remote` accepts (a
    /// destination a new deny rule covers); returns how many.
    pub fn reset_tcp_flows_to(&self, class: FlowClass, remote: impl Fn(IpAddr) -> bool) -> usize {
        match self {
            Self::Netstack(t) => t.netstack().reset_tcp_flows_to(class, remote),
            #[cfg(target_os = "linux")]
            Self::Strict(t) => t.reset_tcp_flows_to(class, remote),
        }
    }

    pub async fn peer(&self) -> Option<PeerSnapshot> {
        match self {
            Self::Netstack(t) => t.peer().await,
            #[cfg(target_os = "linux")]
            Self::Strict(t) => t.peer().await,
        }
    }

    /// Wait up to `timeout` for the tunnel's first handshake.
    ///
    /// # Errors
    ///
    /// The tunnel's error when no handshake completes in time or the tunnel has failed.
    pub async fn handshake(&self, timeout: Duration) -> Result<(), TunnelError> {
        match self {
            Self::Netstack(t) => t.handshake(timeout).await,
            #[cfg(target_os = "linux")]
            Self::Strict(t) => t.handshake(timeout).await,
        }
    }

    pub async fn fatal(&self) -> String {
        match self {
            Self::Netstack(t) => t.fatal().await,
            #[cfg(target_os = "linux")]
            Self::Strict(t) => t.fatal().await,
        }
    }

    pub async fn shutdown(&self) {
        match self {
            Self::Netstack(t) => t.shutdown().await,
            #[cfg(target_os = "linux")]
            Self::Strict(t) => t.shutdown().await,
        }
    }

    /// Replace the transport: the flows opened from now on take `plan`.
    pub fn set_transport(&self, plan: TransportPlan) {
        match self {
            Self::Netstack(t) => t.netstack().transport().set_plan(plan),
            #[cfg(target_os = "linux")]
            Self::Strict(t) => t.connector().transport().set_plan(plan),
        }
    }

    /// A health probe through the tunnel was answered after `latency`: the round trip new
    /// flows are tuned for until a TCP connection's handshake measured it.
    pub fn record_probe(&self, latency: Duration) {
        match self {
            Self::Netstack(t) => t.netstack().transport().record_probe(latency),
            #[cfg(target_os = "linux")]
            Self::Strict(t) => t.connector().transport().record_probe(latency),
        }
    }

    /// What the transport does now.
    #[must_use]
    pub fn transport(&self) -> TransportSnapshot {
        match self {
            Self::Netstack(t) => t.netstack().transport().snapshot(),
            #[cfg(target_os = "linux")]
            Self::Strict(t) => t.connector().transport().snapshot(),
        }
    }

    /// The congestion control this plane's own TCP connections run, next to the one asked for.
    /// The userspace stack's is known from the start; the strict plane's is what the kernel
    /// reported for the connection opened last, `None` before the first.
    #[must_use]
    pub fn congestion(&self) -> Option<CongestionStatus> {
        match self {
            Self::Netstack(t) => {
                let asked = t.netstack().transport().select().0.congestion;
                let runs = asked.userspace();
                Some(CongestionStatus {
                    in_use: runs.name().to_owned(),
                    fallback: (runs != asked).then_some(CongestionFallback::UserspaceStack),
                })
            }
            #[cfg(target_os = "linux")]
            Self::Strict(t) => {
                let connector = t.connector();
                let asked = connector.transport().select().0.congestion;
                connector.congestion().map(|in_use| CongestionStatus {
                    fallback: (in_use != asked.name()).then_some(CongestionFallback::KernelRefused),
                    in_use,
                })
            }
        }
    }

    /// Open flows of the worker's own control traffic (DNS, health probes), not payload.
    #[must_use]
    pub fn control_flows(&self) -> u64 {
        match self {
            Self::Netstack(t) => t.netstack().stats().active_control.load(Ordering::Relaxed) as u64,
            #[cfg(target_os = "linux")]
            Self::Strict(t) => t.connector().stats().active_control.load(Ordering::Relaxed) as u64,
        }
    }

    #[must_use]
    pub fn counters(&self) -> PlaneCounters {
        match self {
            Self::Netstack(t) => {
                let net = t.netstack();
                let ns = net.stats();
                let ch = t.channel_stats();
                let ul = t.underlay_stats();
                PlaneCounters {
                    wg_rx_bytes: ul.rx_bytes.load(Ordering::Relaxed),
                    wg_tx_bytes: ul.tx_bytes.load(Ordering::Relaxed),
                    underlay_blocked: ul.blocked_tx.load(Ordering::Relaxed)
                        + ul.blocked_rx.load(Ordering::Relaxed),
                    tunnel_rx_bytes: ch.inbound_bytes.load(Ordering::Relaxed),
                    tunnel_tx_bytes: ch.outbound_bytes.load(Ordering::Relaxed),
                    active_tcp: ns.active_tcp.load(Ordering::Relaxed) as u64,
                    active_udp: ns.active_udp.load(Ordering::Relaxed) as u64,
                    admission_rejected: ns.admission_rejected.load(Ordering::Relaxed),
                    memory_reserved: ns.memory_reserved.load(Ordering::Relaxed) as u64,
                    sandbox: None,
                }
            }
            #[cfg(target_os = "linux")]
            Self::Strict(t) => {
                let ul = t.underlay_stats();
                let filter = t.filter_stats();
                let own = t.flow_stats();
                let (active_tcp, active_udp) = t.active_flows();
                let (app_tcp, app_udp) = t.app_flows();
                PlaneCounters {
                    wg_rx_bytes: ul.rx_bytes.load(Ordering::Relaxed),
                    wg_tx_bytes: ul.tx_bytes.load(Ordering::Relaxed),
                    underlay_blocked: ul.blocked_tx.load(Ordering::Relaxed)
                        + ul.blocked_rx.load(Ordering::Relaxed),
                    tunnel_rx_bytes: filter.inbound_bytes.load(Ordering::Relaxed),
                    tunnel_tx_bytes: filter.outbound_bytes.load(Ordering::Relaxed),
                    active_tcp,
                    active_udp,
                    admission_rejected: own.admission_rejected.load(Ordering::Relaxed)
                        + filter.refused.load(Ordering::Relaxed),
                    memory_reserved: 0,
                    sandbox: Some(SandboxWire {
                        rx_bytes: filter.app_rx_bytes.load(Ordering::Relaxed),
                        tx_bytes: filter.app_tx_bytes.load(Ordering::Relaxed),
                        tcp_flows: app_tcp,
                        udp_flows: app_udp,
                        evicted: filter.evicted.load(Ordering::Relaxed),
                        table_full: filter.table_full.load(Ordering::Relaxed),
                    }),
                }
            }
        }
    }
}
