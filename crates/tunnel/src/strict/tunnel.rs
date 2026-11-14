//! One strict tunnel: `GotaTun` between the sandbox's TUN device and a pinned underlay socket
//! created in the host network namespace, plus the kernel connector for the worker's own flows.

#![expect(
    unsafe_code,
    reason = "interface enumeration of the sandbox namespace through libc if_nameindex"
)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use gotatun::device::DeviceBuilder;
use gotatun::x25519::StaticSecret;
use ipnetwork::IpNetwork;
use zeroize::Zeroizing;

use super::connector::KernelConnector;
use super::filter::{DestinationCheck, FilterStats, PacketFilter};
use super::flows::OwnFlows;
use super::tun::{Injector, Tun, TunRecv, TunSend};
use crate::netstack::{FlowClass, Gate, GateState, NetstackLimits, NetstackStats};
use crate::pinned_udp::{PeerPolicy, PinnedUdpFactory, UdpSource, UnderlayStats};
use crate::transport::TransportPlan;
use crate::tunnel::{DeviceHandle, PeerConfig, PeerSnapshot, TunnelError, gotatun_peer};

/// Everything a strict tunnel needs. The worker must already be inside the sandbox's network
/// namespace (it is verified).
pub struct StrictTunnelConfig {
    pub private_key: Zeroizing<[u8; 32]>,
    pub peer: PeerConfig,
    /// The tunnel addresses (the first of each family is the sandbox's TUN address).
    pub addresses: Vec<IpNetwork>,
    pub mtu: u16,
    /// The sandbox's TUN device.
    pub tun: OwnedFd,
    /// Its interface name inside the sandbox.
    pub tun_name: String,
    /// The `WireGuard` underlay socket, created in the host network namespace.
    pub underlay: std::net::UdpSocket,
    pub underlay_policy: PeerPolicy,
    pub limits: NetstackLimits,
    /// What the worker's own connections are opened with.
    pub transport: TransportPlan,
    /// Destination policy for the Apps' new flows.
    pub policy: Arc<dyn DestinationCheck>,
}

impl std::fmt::Debug for StrictTunnelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StrictTunnelConfig")
            .field("peer", &self.peer)
            .field("addresses", &self.addresses)
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

/// The parts the gate and resets act on.
struct Plane {
    gate: Arc<Gate>,
    connector: KernelConnector,
    filter: Arc<PacketFilter>,
    inject: Arc<Injector>,
    tun: Arc<Tun>,
}

impl Plane {
    fn set_gate(&self, next: GateState) -> GateState {
        let in_force = self.gate.set(next);
        if in_force == GateState::Sealed {
            self.reset_flows(None);
        }
        in_force
    }

    /// [`Self::set_gate`] with [`GateState::Sealed`], which always takes effect (a sealed gate
    /// stays sealed): every flow is reset.
    fn seal(&self) {
        self.gate.set(GateState::Sealed);
        self.reset_flows(None);
    }

    fn reset_flows(&self, class: Option<FlowClass>) {
        self.connector.reset(class);
        if class == Some(FlowClass::Control) {
            return;
        }
        let (to_apps, to_remotes) = self.filter.reset_app_flows();
        self.send_resets(to_apps, to_remotes);
    }

    fn reset_tcp_flows_to(&self, class: FlowClass, remote: &dyn Fn(IpAddr) -> bool) -> usize {
        let mut reset = self.connector.reset_tcp_to(class, remote);
        // The Apps' flows are payload.
        if class == FlowClass::Payload {
            let apps = self.filter.reset_app_flows_to(remote);
            reset += apps.connections;
            self.send_resets(apps.to_apps, apps.to_remotes);
        }
        reset
    }

    fn send_resets(&self, to_apps: Vec<Vec<u8>>, to_remotes: Vec<Vec<u8>>) {
        for packet in to_apps {
            // Best effort, like every write into the device: a reset it cannot take is lost
            // and the App's connection ends by its own timeout instead.
            if let Err(e) = self.tun.write(&packet) {
                tracing::trace!(error = %e, "reset not written to the TUN device");
            }
        }
        for packet in to_remotes {
            self.inject.push(&packet);
        }
    }
}

/// Handle to a running strict tunnel. Cheap to clone.
#[derive(Clone)]
pub struct StrictTunnel {
    plane: Arc<Plane>,
    device: DeviceHandle,
    underlay_stats: Arc<UnderlayStats>,
}

impl std::fmt::Debug for StrictTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StrictTunnel").finish_non_exhaustive()
    }
}

/// Names of the network interfaces of this process's network namespace.
///
/// # Errors
///
/// Fails with the OS error when the interfaces cannot be listed.
pub fn interfaces() -> io::Result<Vec<String>> {
    // SAFETY: if_nameindex takes no arguments; it returns a heap array terminated by a zero
    // entry, or null on failure.
    let list = unsafe { libc::if_nameindex() };
    if list.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut names = Vec::new();
    let mut entry = list;
    loop {
        // SAFETY: `entry` points at an element of the array, at most its terminating entry
        // (the loop stops there), and the array stays allocated until if_freenameindex below;
        // we only read it.
        let current = unsafe { &*entry };
        if current.if_index == 0 || current.if_name.is_null() {
            break;
        }
        // SAFETY: the name of a listed interface is a NUL-terminated string inside the array,
        // copied into an owned `String` before the array is freed.
        let name = unsafe { std::ffi::CStr::from_ptr(current.if_name) };
        names.push(name.to_string_lossy().into_owned());
        // SAFETY: `entry` is not the terminating entry, so the next element is in the array.
        entry = unsafe { entry.add(1) };
    }
    // SAFETY: `list` came from if_nameindex and is handed back once; nothing points into it
    // any more.
    unsafe { libc::if_freenameindex(list) };
    Ok(names)
}

/// The proof that kernel sockets of this process cannot reach anything but the tunnel: its
/// network namespace holds exactly `lo` and the sandbox's TUN device.
///
/// # Errors
///
/// `PermissionDenied` when any other interface exists, `NotFound` when the TUN device is
/// missing, or the OS error when the interfaces cannot be listed.
pub fn verify_closed_namespace(tun_name: &str) -> io::Result<()> {
    let names = interfaces()?;
    let extra: Vec<&String> = names
        .iter()
        .filter(|n| n.as_str() != "lo" && n.as_str() != tun_name)
        .collect();
    if !extra.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("network namespace is not closed: unexpected interfaces {extra:?}"),
        ));
    }
    if !names.iter().any(|n| n == tun_name) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("network namespace has no interface {tun_name:?}"),
        ));
    }
    Ok(())
}

fn first_addresses(addresses: &[IpNetwork]) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let v4 = addresses.iter().find_map(|n| match n.ip() {
        IpAddr::V4(a) => Some(a),
        IpAddr::V6(_) => None,
    });
    let v6 = addresses.iter().find_map(|n| match n.ip() {
        IpAddr::V6(a) => Some(a),
        IpAddr::V4(_) => None,
    });
    (v4, v6)
}

impl StrictTunnel {
    /// Bring the tunnel up. The gate starts [`Closed`](GateState::Closed).
    ///
    /// # Errors
    ///
    /// [`TunnelError::Config`] for an MTU outside 576..=9000, an all-zero peer key or no
    /// interface address; [`TunnelError::Netstack`] when the namespace is not closed or the TUN
    /// device cannot be used; [`TunnelError::Device`] when the `WireGuard` device cannot start.
    pub async fn start(config: StrictTunnelConfig) -> Result<Self, TunnelError> {
        if !(576..=9000).contains(&config.mtu) {
            return Err(TunnelError::Config(format!(
                "mtu {} out of range",
                config.mtu
            )));
        }
        if config.peer.public_key == [0u8; 32] {
            return Err(TunnelError::Config("peer public key is all zeros".into()));
        }
        let (v4, v6) = first_addresses(&config.addresses);
        if v4.is_none() && v6.is_none() {
            return Err(TunnelError::Config(
                "tunnel has no interface address".into(),
            ));
        }
        verify_closed_namespace(&config.tun_name)?;
        let tun = Arc::new(Tun::new(config.tun, &config.tun_name, config.mtu)?);

        let gate = Arc::new(Gate::default());
        let own = OwnFlows::default();
        let filter = Arc::new(PacketFilter::new(
            gate.clone(),
            own.clone(),
            config.policy,
            v4,
            v6,
        ));
        let plane = Arc::new(Plane {
            connector: KernelConnector::new(
                gate.clone(),
                own,
                filter.direct_ports(),
                v4,
                v6,
                config.limits,
                config.transport,
            ),
            gate,
            filter: filter.clone(),
            inject: Arc::new(Injector::new()),
            tun: tun.clone(),
        });

        let underlay_stats = Arc::new(UnderlayStats::default());
        let udp = PinnedUdpFactory::new(
            UdpSource::Preopened(Arc::new(config.underlay)),
            config.underlay_policy,
            underlay_stats.clone(),
        );
        let (peer_key, peer) = gotatun_peer(config.peer);
        let device = DeviceBuilder::new()
            .with_udp(udp)
            .with_ip_pair(
                TunSend {
                    tun: tun.clone(),
                    filter: filter.clone(),
                    inject: plane.inject.clone(),
                },
                TunRecv {
                    tun,
                    filter,
                    inject: plane.inject.clone(),
                },
            )
            .with_listen_port(0)
            .with_private_key(StaticSecret::from(*config.private_key))
            .with_peer(peer)
            .build()
            .await?;
        // On a fatal device error the data path seals itself, like the netstack's.
        let sealed = plane.clone();
        let device = DeviceHandle::spawn(device, peer_key, move || sealed.seal());
        Ok(Self {
            plane,
            device,
            underlay_stats,
        })
    }

    /// The connector for DNS, Gateways and the Provider connector.
    #[must_use]
    pub fn connector(&self) -> KernelConnector {
        self.plane.connector.clone()
    }

    #[must_use]
    pub fn gate(&self) -> GateState {
        self.plane.gate.get()
    }

    /// Change what is admitted. Like the netstack, existing flows are left alone except when
    /// sealing, which resets everything.
    #[must_use]
    pub fn set_gate(&self, next: GateState) -> GateState {
        self.plane.set_gate(next)
    }

    /// Reset existing flows of one class (all with `None`): the worker's own connections, and
    /// for payload also every App TCP connection, at both ends.
    pub fn reset_flows(&self, class: Option<FlowClass>) {
        self.plane.reset_flows(class);
    }

    /// Reset the TCP connections of `class` whose remote address `remote` accepts (a destination
    /// a new deny rule covers) at both ends — the worker's own, and for payload the Apps' — and
    /// forget the Apps' UDP flows to it (their next datagram is checked again); returns how many
    /// TCP connections were reset.
    pub fn reset_tcp_flows_to(&self, class: FlowClass, remote: impl Fn(IpAddr) -> bool) -> usize {
        self.plane.reset_tcp_flows_to(class, &remote)
    }

    pub async fn peer(&self) -> Option<PeerSnapshot> {
        self.device.peer().await
    }

    /// Initiate a handshake if needed and wait until one completed, bounded by `timeout`.
    ///
    /// # Errors
    ///
    /// [`TunnelError::HandshakeTimeout`] when none completed in time, [`TunnelError::Stopped`]
    /// when the device stopped meanwhile.
    pub async fn handshake(&self, timeout: Duration) -> Result<(), TunnelError> {
        self.device.handshake(timeout).await
    }

    pub async fn fatal(&self) -> String {
        self.device.fatal().await
    }

    /// Seal (resetting every flow at both ends), give `GotaTun` a moment to send the resets
    /// towards the remote hosts, stop the device.
    pub async fn shutdown(&self) {
        self.plane.seal();
        for _ in 0..20 {
            if self.plane.inject.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.device.stop().await;
    }

    /// Counters of the worker's own flows.
    #[must_use]
    pub fn flow_stats(&self) -> &NetstackStats {
        self.plane.connector.stats()
    }

    /// Packet counters of the TUN path: every packet of the sandbox, and of them the Apps'
    /// payload (the worker's own flows are not in it).
    #[must_use]
    pub fn filter_stats(&self) -> &FilterStats {
        &self.plane.filter.stats
    }

    /// The Apps' payload per local port of the sandbox (the worker's own flows are not in it).
    #[must_use]
    pub fn port_payload(&self) -> Vec<super::PortPayload> {
        self.plane.filter.port_payload(std::time::Instant::now())
    }

    /// The Apps' flows the filter tracks, `(tcp, udp)` (the worker's own are not among them).
    #[must_use]
    pub fn app_flows(&self) -> (u64, u64) {
        let (tcp, udp) = self.plane.filter.app_flows();
        (tcp as u64, udp as u64)
    }

    #[must_use]
    pub fn underlay_stats(&self) -> &UnderlayStats {
        &self.underlay_stats
    }

    /// Open flows: the worker's own plus the Apps' tracked ones, `(tcp, udp)`.
    #[must_use]
    pub fn active_flows(&self) -> (u64, u64) {
        let (app_tcp, app_udp) = self.plane.filter.app_flows();
        let own = self.plane.connector.stats();
        (
            (own.active_tcp.load(Ordering::Relaxed) + app_tcp) as u64,
            (own.active_udp.load(Ordering::Relaxed) + app_udp) as u64,
        )
    }
}
