//! Per-Instance userspace TCP/IP stack on top of the `WireGuard` tunnel.
//!
//! One smoltcp [`Interface`] owned by a single pump task. Flow handles ([`TcpStream`],
//! [`UdpSocket`], [`TcpListener`]) share the stack through a short-held mutex and wake the pump
//! after every read/write. Nothing here can create a host socket: the only way out of the stack is
//! the IP channel into `GotaTun`. That is the structural "no direct fallback" guarantee.

mod device;
pub mod gate;
mod ports;
mod tcp;
mod udp;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use smoltcp::iface::{
    Config, Interface, PollIngressSingleResult, PollResult, SocketHandle, SocketSet,
};
use smoltcp::socket::{tcp as stcp, udp as sudp};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::sync::{Notify, watch};
use vpn_sync::Mutex;

use crate::ipchan::IpChannelShared;
use crate::transport::{FlowTuning, Transport, TransportPlan};
use device::QueueDevice;
pub use gate::{FlowClass, Gate, GateState};
use ports::PortAllocator;
pub use tcp::{TcpListener, TcpStream};
pub use udp::UdpSocket;

/// Ingress packets processed per pump round before egress gets a turn (bounded work).
const MAX_INGRESS_PER_ROUND: usize = 256;
/// How long a closed-by-us TCP socket may linger (FIN handshake) before it is reset and freed.
const ORPHAN_LINGER: Duration = Duration::from_secs(30);

/// Flows of each protocol kept for control traffic (DNS, health probes): payload alone can never
/// take the last ones, so a busy Instance still gets its liveness probe out.
pub const CONTROL_RESERVED_FLOWS: usize = 16;
/// Socket buffer memory kept for control flows (about 10 TCP or 64 UDP control sockets).
pub const CONTROL_RESERVED_MEMORY: usize = 8 * 1024 * 1024;
/// Keep-alive probe interval of an idle tunnel TCP connection.
pub const TCP_KEEPALIVE: Duration = Duration::from_secs(60);
/// A tunnel TCP connection whose peer sent nothing for this long is aborted.
///
/// Nothing means no data, no ACK, no answer to about five keep-alives; so a silently dead remote
/// cannot hold a flow and its buffers forever. Tunnel outages are handled earlier by the degraded recycle (90 s).
pub const TCP_DEAD_PEER_TIMEOUT: Duration = Duration::from_mins(5);

/// The share of the payload buffer budget that enlarging TCP buffers may fill (three quarters):
/// the rest stays free for new flows, which are never refused for the sake of a larger buffer.
const GROWTH_BUDGET_NUM: usize = 3;
const GROWTH_BUDGET_DEN: usize = 4;

/// Limits of one Instance's netstack. All of them are admission limits: a request beyond them is
/// refused immediately, never queued. What each admitted flow gets is the transport's
/// ([`crate::transport`]).
#[derive(Debug, Clone)]
pub struct NetstackLimits {
    pub max_tcp_flows: usize,
    pub max_udp_flows: usize,
    /// Upper bound of socket buffer memory reserved by all flows together.
    pub memory_budget: usize,
    /// Share of the flow limits and of the memory budget that payload flows cannot use (each
    /// capped at a quarter of its limit, so small limits stay usable).
    pub control_reserved_flows: usize,
    pub control_reserved_memory: usize,
}

impl Default for NetstackLimits {
    fn default() -> Self {
        Self {
            max_tcp_flows: 1024,
            max_udp_flows: 512,
            memory_budget: 512 * 1024 * 1024,
            control_reserved_flows: CONTROL_RESERVED_FLOWS,
            control_reserved_memory: CONTROL_RESERVED_MEMORY,
        }
    }
}

impl NetstackLimits {
    /// The buffer budget payload flows may reserve: the whole budget less the share kept for
    /// control flows.
    #[must_use]
    pub const fn payload_budget(&self) -> usize {
        let quarter = self.memory_budget / 4;
        let kept = if self.control_reserved_memory < quarter {
            self.control_reserved_memory
        } else {
            quarter
        };
        self.memory_budget - kept
    }
}

/// Netstack counters, readable without the stack lock.
#[derive(Debug, Default)]
pub struct NetstackStats {
    pub tcp_connects: AtomicU64,
    pub tcp_connect_failures: AtomicU64,
    pub tcp_accepts: AtomicU64,
    pub admission_rejected: AtomicU64,
    pub active_tcp: AtomicUsize,
    pub active_udp: AtomicUsize,
    /// Of the active TCP and UDP flows, those of [`FlowClass::Control`] (DNS lookups and health
    /// probes), so data and control flows can be reported apart.
    pub active_control: AtomicUsize,
    pub memory_reserved: AtomicUsize,
}

impl NetstackStats {
    /// A TCP or UDP flow of `class` became active.
    pub(crate) fn opened(&self, class: FlowClass) {
        if class == FlowClass::Control {
            self.active_control.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proto {
    Tcp,
    Udp,
    TcpListen,
}

#[derive(Debug)]
struct FlowMeta {
    class: FlowClass,
    proto: Proto,
    port: u16,
    memory: usize,
    /// Set once the handle was dropped; the pump frees the socket when it is closed.
    orphaned_at: Option<smoltcp::time::Instant>,
}

pub(crate) struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: QueueDevice,
    tcp_ports: PortAllocator,
    udp_ports: PortAllocator,
    flows: HashMap<SocketHandle, FlowMeta>,
    epoch: std::time::Instant,
}

impl Stack {
    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(
            i64::try_from(self.epoch.elapsed().as_micros()).unwrap_or(i64::MAX),
        )
    }

    /// Source address for a destination, or `None` when the tunnel carries no address of that
    /// family. (smoltcp's own IPv6 source selection always yields *some* address, so it cannot be
    /// used to decide whether IPv6 is routed through the tunnel at all.)
    fn source_for(&self, dst: IpAddr) -> Option<IpAddress> {
        match dst {
            IpAddr::V4(_) => self.iface.ipv4_addr().map(IpAddress::Ipv4),
            IpAddr::V6(_) => self.iface.ipv6_addr().map(IpAddress::Ipv6),
        }
    }

    /// `src` as a source for `dst`: one of this stack's own addresses, of the same family.
    /// Nothing else is ever put on the wire as a source.
    fn own_source(&self, src: IpAddr, dst: IpAddr) -> io::Result<IpAddress> {
        let own = self
            .iface
            .ip_addrs()
            .iter()
            .any(|c| IpAddr::from(c.address()) == src);
        if !own || src.is_ipv4() != dst.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "source is not an address of this tunnel",
            ));
        }
        Ok(src.into())
    }
}

pub(crate) struct Shared {
    pub(crate) stack: Mutex<Stack>,
    pub(crate) wake: Arc<Notify>,
    pub(crate) gate: Gate,
    pub(crate) limits: NetstackLimits,
    pub(crate) transport: Transport,
    pub(crate) stats: NetstackStats,
}

/// Shows the limits; the stack itself is behind its lock.
impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Shared {
    /// What a flow of `class` opened now gets; a control flow (a DNS lookup, a health probe)
    /// its small, fixed share of it.
    pub(crate) fn tuning(&self, class: FlowClass) -> FlowTuning {
        let (tuning, _) = self.transport.select();
        match class {
            FlowClass::Payload => tuning,
            FlowClass::Control => tuning.control(),
        }
    }

    /// Run one bounded round of ingress, egress and maintenance. Returns how long the pump may
    /// sleep, or `None` to wait for a wake-up only.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "one round runs entirely under the stack lock, through the final poll_delay"
    )]
    fn poll_round(&self) -> PumpNext {
        let mut guard = self.stack.lock();
        let stack = &mut *guard;
        let now = stack.now();
        let mut ingress_left = false;
        for i in 0..MAX_INGRESS_PER_ROUND {
            match stack
                .iface
                .poll_ingress_single(now, &mut stack.device, &mut stack.sockets)
            {
                PollIngressSingleResult::None => break,
                _ if i + 1 == MAX_INGRESS_PER_ROUND => ingress_left = stack.device.has_ingress(),
                _ => {}
            }
        }
        while stack
            .iface
            .poll_egress(now, &mut stack.device, &mut stack.sockets)
            == PollResult::SocketStateChanged
        {}
        stack.iface.poll_maintenance(now);
        self.collect_garbage(stack, now);

        if ingress_left || stack.device.has_ingress() {
            return PumpNext::Immediately;
        }
        match stack.iface.poll_delay(now, &stack.sockets) {
            // smoltcp wants to transmit but the outbound queue is full: wait for GotaTun to drain
            // it (it wakes us) instead of spinning.
            Some(d) if d.total_micros() == 0 && stack.device.egress_full() => PumpNext::WaitForWake,
            Some(d) if d.total_micros() == 0 => PumpNext::Immediately,
            Some(d) => PumpNext::Sleep(Duration::from_micros(d.total_micros())),
            None => PumpNext::WaitForWake,
        }
    }

    /// Free sockets whose handles are gone once their connection has finished.
    fn collect_garbage(&self, stack: &mut Stack, now: smoltcp::time::Instant) {
        let mut remove = Vec::new();
        for (handle, meta) in &mut stack.flows {
            let Some(orphaned_at) = meta.orphaned_at else {
                continue;
            };
            let done = match meta.proto {
                Proto::Tcp | Proto::TcpListen => {
                    let socket = stack.sockets.get_mut::<stcp::Socket<'_>>(*handle);
                    match socket.state() {
                        stcp::State::Closed | stcp::State::TimeWait | stcp::State::Listen => true,
                        _ if now - orphaned_at
                            > smoltcp::time::Duration::from_micros(
                                u64::try_from(ORPHAN_LINGER.as_micros()).unwrap_or(u64::MAX),
                            ) =>
                        {
                            socket.abort();
                            // Freed next round, after the RST had a chance to be sent.
                            meta.orphaned_at = Some(now);
                            false
                        }
                        _ => false,
                    }
                }
                Proto::Udp => true,
            };
            if done {
                remove.push(*handle);
            }
        }
        for handle in remove {
            if let Some(meta) = stack.flows.remove(&handle) {
                stack.sockets.remove(handle);
                match meta.proto {
                    Proto::Tcp => {
                        stack.tcp_ports.release(meta.port);
                        self.stats.active_tcp.fetch_sub(1, Ordering::Relaxed);
                    }
                    Proto::TcpListen => {}
                    Proto::Udp => {
                        stack.udp_ports.release(meta.port);
                        self.stats.active_udp.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                if meta.class == FlowClass::Control && meta.proto != Proto::TcpListen {
                    self.stats.active_control.fetch_sub(1, Ordering::Relaxed);
                }
                self.stats
                    .memory_reserved
                    .fetch_sub(meta.memory, Ordering::Relaxed);
            }
        }
    }

    /// Claim a flow slot and buffer memory for a new flow, or refuse. Payload flows stop short
    /// of the share kept for control flows; control flows may use everything.
    ///
    /// The slot is taken in the same step that checks the limit: of several callers that see
    /// the last free one, one gets it. A connecting TCP flow and a UDP socket hold their slot
    /// from here until the flow is removed. A listening socket holds none (it is refused while
    /// the limit is reached, and reserves its memory); the connection it accepts is counted when
    /// accepted, so inbound connections can exceed the limit by the sockets already listening.
    fn reserve(&self, class: FlowClass, proto: Proto, bytes: usize) -> io::Result<()> {
        if !self.gate.get().admits(class) {
            self.stats
                .admission_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "instance payload gate is closed",
            ));
        }
        let (active, max) = match proto {
            Proto::Tcp | Proto::TcpListen => (&self.stats.active_tcp, self.limits.max_tcp_flows),
            Proto::Udp => (&self.stats.active_udp, self.limits.max_udp_flows),
        };
        let budget = self.limits.memory_budget;
        let (max, budget) = match class {
            FlowClass::Control => (max, budget),
            FlowClass::Payload => (
                max - self.limits.control_reserved_flows.min(max / 4),
                self.limits.payload_budget(),
            ),
        };
        let free = if proto == Proto::TcpListen {
            active.load(Ordering::Relaxed) < max
        } else {
            active
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    (n < max).then_some(n + 1)
                })
                .is_ok()
        };
        if !free {
            self.stats
                .admission_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::QuotaExceeded,
                "instance flow limit reached",
            ));
        }
        let reserved = self
            .stats
            .memory_reserved
            .fetch_add(bytes, Ordering::Relaxed);
        if reserved + bytes > budget {
            self.unreserve(proto, bytes);
            self.stats
                .admission_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "instance buffer budget exhausted",
            ));
        }
        Ok(())
    }

    /// Give back what [`Self::reserve`] claimed for a flow that was not added after all.
    fn unreserve(&self, proto: Proto, bytes: usize) {
        match proto {
            Proto::Tcp => self.stats.active_tcp.fetch_sub(1, Ordering::Relaxed),
            Proto::Udp => self.stats.active_udp.fetch_sub(1, Ordering::Relaxed),
            Proto::TcpListen => 0,
        };
        self.stats
            .memory_reserved
            .fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Reserve `bytes` more for a flow that exists, to enlarge one of its buffers. Granted
    /// only within the share of the payload budget kept for it, so that new flows still find
    /// room; whether it was granted.
    fn reserve_growth(&self, bytes: usize) -> bool {
        let limit = self.limits.payload_budget() / GROWTH_BUDGET_DEN * GROWTH_BUDGET_NUM;
        let granted = self
            .stats
            .memory_reserved
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
                reserved.checked_add(bytes).filter(|total| *total <= limit)
            })
            .is_ok();
        if granted {
            self.transport.grew();
        } else {
            self.transport.growth_refused();
        }
        granted
    }

    /// Release ports a [`PortReservation`] held.
    fn release_reserved(&self, port: u16, tcp: bool, udp: bool) {
        let mut stack = self.stack.lock();
        if tcp {
            stack.tcp_ports.release(port);
        }
        if udp {
            stack.udp_ports.release(port);
        }
    }

    /// Mark a flow's handle as dropped; the pump frees it once the connection finished.
    pub(crate) fn orphan(&self, handle: SocketHandle) {
        let mut guard = self.stack.lock();
        let stack = &mut *guard;
        let now = stack.now();
        if let Some(meta) = stack.flows.get_mut(&handle) {
            match meta.proto {
                Proto::Tcp | Proto::TcpListen => {
                    let socket = stack.sockets.get_mut::<stcp::Socket<'_>>(handle);
                    if meta.proto == Proto::TcpListen {
                        socket.abort();
                    } else if socket.is_open() {
                        socket.close();
                    }
                }
                Proto::Udp => stack.sockets.get_mut::<sudp::Socket<'_>>(handle).close(),
            }
            meta.orphaned_at = Some(now);
        }
        drop(guard);
        self.wake.notify_one();
    }
}

enum PumpNext {
    Immediately,
    Sleep(Duration),
    WaitForWake,
}

/// Cloneable handle to one Instance's netstack; this is the `TunnelConnector` the DNS, Gateway
/// and Port-forward controllers use.
#[derive(Debug, Clone)]
pub struct Netstack {
    pub(crate) shared: Arc<Shared>,
    shutdown: watch::Sender<bool>,
}

impl Netstack {
    /// Build the stack over `chan` and spawn its pump on the current Tokio runtime.
    pub(crate) fn spawn(
        addresses: &[ipnetwork::IpNetwork],
        mtu: u16,
        limits: NetstackLimits,
        transport: TransportPlan,
        chan: Arc<IpChannelShared>,
    ) -> io::Result<Self> {
        let wake = chan.stack_wake.clone();
        let mut device = QueueDevice {
            chan,
            mtu: mtu as usize,
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let epoch = std::time::Instant::now();
        let mut iface = Interface::new(config, &mut device, smoltcp::time::Instant::from_micros(0));
        let mut have_v4 = None;
        let mut have_v6 = None;
        // The table holds more than the one IPv4 and one IPv6 address taken here.
        let mut full = false;
        iface.update_ip_addrs(|addrs| {
            for net in addresses {
                let cidr = IpCidr::new(net.ip().into(), net.prefix());
                match net.ip() {
                    IpAddr::V4(a) if have_v4.is_none() => {
                        have_v4 = Some(a);
                        full |= addrs.push(cidr).is_err();
                    }
                    IpAddr::V6(a) if have_v6.is_none() => {
                        have_v6 = Some(a);
                        full |= addrs.push(cidr).is_err();
                    }
                    _ => {}
                }
            }
        });
        if full {
            return Err(io::Error::other("interface address table full"));
        }
        if have_v4.is_none() && have_v6.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tunnel has no interface address",
            ));
        }
        // Medium::Ip has no neighbours; the default route only makes off-link destinations
        // routable. The next-hop value is never put on the wire. (`RouteTableFull` carries
        // nothing beyond its name, which the error says.)
        if let Some(a) = have_v4 {
            iface
                .routes_mut()
                .add_default_ipv4_route(a)
                .map_err(|_table_full| io::Error::other("route table full"))?;
        }
        if let Some(a) = have_v6 {
            iface
                .routes_mut()
                .add_default_ipv6_route(a)
                .map_err(|_table_full| io::Error::other("route table full"))?;
        }

        let shared = Arc::new(Shared {
            stack: Mutex::new(Stack {
                iface,
                sockets: SocketSet::new(Vec::new()),
                device,
                tcp_ports: PortAllocator::ephemeral(),
                udp_ports: PortAllocator::ephemeral(),
                flows: HashMap::new(),
                epoch,
            }),
            wake,
            gate: Gate::default(),
            limits,
            transport: Transport::new(transport),
            stats: NetstackStats::default(),
        });
        let (shutdown, shutdown_rx) = watch::channel(false);
        tokio::spawn(pump(shared.clone(), shutdown_rx));
        Ok(Self { shared, shutdown })
    }

    #[must_use]
    pub fn gate(&self) -> GateState {
        self.shared.gate.get()
    }

    /// Change which flows are *admitted*. Existing flows are deliberately left alone: they can
    /// only ever leave through `GotaTun`, so a temporary tunnel problem merely stalls them (TCP
    /// retransmits) and long-lived sessions survive a network blip. Use [`Self::reset_flows`] when
    /// a flow must end (generation change, Stop, emergency). Sealing also resets everything.
    #[must_use]
    pub fn set_gate(&self, next: GateState) -> GateState {
        let in_force = self.shared.gate.set(next);
        if in_force == GateState::Sealed {
            self.reset_flows(None);
        }
        in_force
    }

    /// Reset existing flows of one class, or all flows with `None`.
    pub fn reset_flows(&self, class: Option<FlowClass>) {
        self.abort_where(|c| class.is_none_or(|wanted| wanted == c));
    }

    /// Reset the established TCP flows of `class` whose remote address `remote` accepts (an
    /// address a new deny rule covers); returns how many. UDP sockets have no fixed remote:
    /// their users check every datagram instead.
    pub fn reset_tcp_flows_to(&self, class: FlowClass, remote: impl Fn(IpAddr) -> bool) -> usize {
        let mut guard = self.shared.stack.lock();
        let stack = &mut *guard;
        let mut reset = 0;
        for (handle, meta) in &stack.flows {
            if meta.class != class || meta.proto != Proto::Tcp {
                continue;
            }
            let socket = stack.sockets.get_mut::<stcp::Socket<'_>>(*handle);
            if let Some(ep) = socket.remote_endpoint()
                && remote(SocketAddr::from(ep).ip().to_canonical())
            {
                socket.abort();
                reset += 1;
            }
        }
        drop(guard);
        if reset > 0 {
            self.shared.wake.notify_one();
        }
        reset
    }

    fn abort_where(&self, pred: impl Fn(FlowClass) -> bool) {
        let mut guard = self.shared.stack.lock();
        let stack = &mut *guard;
        for (handle, meta) in &stack.flows {
            if !pred(meta.class) {
                continue;
            }
            match meta.proto {
                Proto::Tcp | Proto::TcpListen => {
                    stack.sockets.get_mut::<stcp::Socket<'_>>(*handle).abort();
                }
                Proto::Udp => stack.sockets.get_mut::<sudp::Socket<'_>>(*handle).close(),
            }
        }
        drop(guard);
        self.shared.wake.notify_one();
    }

    #[must_use]
    pub fn stats(&self) -> &NetstackStats {
        &self.shared.stats
    }

    #[must_use]
    pub fn limits(&self) -> &NetstackLimits {
        &self.shared.limits
    }

    /// The transport of this stack: the plan new flows take and what was measured for it.
    #[must_use]
    pub fn transport(&self) -> &Transport {
        &self.shared.transport
    }

    /// Whether the tunnel has an address of this family (IPv6 is denied, not leaked, otherwise).
    #[must_use]
    pub fn supports(&self, ip: IpAddr) -> bool {
        self.shared.stack.lock().source_for(ip).is_some()
    }

    /// Open a TCP connection through the tunnel.
    ///
    /// # Errors
    ///
    /// Fails with the kinds listed on [`crate::connector::TunnelConnector`]: gate closed,
    /// admission limit, family not carried, refused or timed out.
    pub async fn connect_tcp(&self, dst: SocketAddr, class: FlowClass) -> io::Result<TcpStream> {
        tcp::connect(self.shared.clone(), dst, class).await
    }

    /// Bind a UDP socket on an ephemeral tunnel port.
    ///
    /// # Errors
    ///
    /// Fails when the gate is closed for `class`, an admission limit is reached or no port is
    /// free.
    pub fn bind_udp(&self, class: FlowClass) -> io::Result<UdpSocket> {
        udp::bind(self.shared.clone(), None, class)
    }

    /// Bind a UDP socket on a fixed tunnel port (inbound services: Port forward, test peer).
    ///
    /// # Errors
    ///
    /// Fails when the gate is closed for `class`, an admission limit is reached or the port is
    /// in use.
    pub fn bind_udp_port(&self, port: u16, class: FlowClass) -> io::Result<UdpSocket> {
        udp::bind(self.shared.clone(), Some(port), class)
    }

    /// Listen for inbound TCP connections on a tunnel port.
    ///
    /// # Errors
    ///
    /// Fails when the gate is closed for `class`, an admission limit is reached or the port is
    /// in use.
    pub fn listen_tcp(
        &self,
        port: u16,
        backlog: usize,
        class: FlowClass,
    ) -> io::Result<TcpListener> {
        tcp::listen(self.shared.clone(), port, backlog, class)
    }

    /// Reserve `port` on the tunnel addresses for inbound TCP and/or UDP (a port forward).
    ///
    /// Until the reservation is dropped no outbound flow is given it as its local port, and
    /// listeners made from it come and go (gate changes) without the port ever being free in
    /// between.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for port 0 or neither protocol; `AddrInUse` when a flow or another
    /// reservation holds it right now.
    pub fn reserve_inbound(&self, port: u16, tcp: bool, udp: bool) -> io::Result<PortReservation> {
        if port == 0 || !(tcp || udp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nothing to reserve",
            ));
        }
        let mut stack = self.shared.stack.lock();
        if tcp && !stack.tcp_ports.claim(port) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "tunnel TCP port in use",
            ));
        }
        if udp && !stack.udp_ports.claim(port) {
            if tcp {
                stack.tcp_ports.release(port);
            }
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "tunnel UDP port in use",
            ));
        }
        drop(stack);
        Ok(PortReservation {
            shared: self.shared.clone(),
            port,
            tcp,
            udp,
        })
    }

    /// Reset every TCP connection whose local port is `port` (the flows of a revoked forward).
    /// Returns how many.
    #[must_use]
    pub fn reset_tcp_port(&self, port: u16) -> usize {
        let mut guard = self.shared.stack.lock();
        let stack = &mut *guard;
        let mut reset = 0;
        for (handle, meta) in &stack.flows {
            if meta.proto != Proto::Tcp {
                continue;
            }
            let socket = stack.sockets.get_mut::<stcp::Socket<'_>>(*handle);
            if socket.local_endpoint().is_some_and(|ep| ep.port == port) {
                socket.abort();
                reset += 1;
            }
        }
        drop(guard);
        if reset > 0 {
            self.shared.wake.notify_one();
        }
        reset
    }

    /// Open a TCP connection from `src`, which must be one of this stack's own addresses (the
    /// test peer uses it to play a host beyond the VPN server). Never a spoofed source.
    ///
    /// # Errors
    ///
    /// `AddrNotAvailable` when `src` is not an address of this tunnel; otherwise as
    /// [`Self::connect_tcp`].
    pub async fn connect_tcp_from(
        &self,
        src: IpAddr,
        dst: SocketAddr,
        class: FlowClass,
    ) -> io::Result<TcpStream> {
        tcp::connect_from(self.shared.clone(), Some(src), dst, class).await
    }

    /// Bind a UDP socket on an ephemeral port of `src`, one of this stack's own addresses: its
    /// datagrams leave from `src` (test peer, as for [`Self::connect_tcp_from`]).
    ///
    /// # Errors
    ///
    /// `AddrNotAvailable` when `src` is not an address of this tunnel; otherwise as
    /// [`Self::bind_udp`].
    pub fn bind_udp_from(&self, src: IpAddr, class: FlowClass) -> io::Result<UdpSocket> {
        {
            let stack = self.shared.stack.lock();
            stack.own_source(src, src)?;
        }
        udp::bind_at(self.shared.clone(), Some(src), None, class, true)
    }

    /// Add an interface address (the test peer's stand-in for a host beyond the VPN server).
    /// The product's stacks carry exactly the profile's addresses and never call this.
    ///
    /// # Errors
    ///
    /// Fails when the interface address table is full.
    pub fn add_address(&self, address: ipnetwork::IpNetwork) -> io::Result<()> {
        let cidr = IpCidr::new(address.ip().into(), address.prefix());
        let mut stack = self.shared.stack.lock();
        let mut full = false;
        stack.iface.update_ip_addrs(|addrs| {
            if !addrs.contains(&cidr) {
                full = addrs.push(cidr).is_err();
            }
        });
        drop(stack);
        if full {
            return Err(io::Error::other("interface address table full"));
        }
        Ok(())
    }

    /// Seal the gate for good and reset every flow: [`Self::set_gate`] with
    /// [`GateState::Sealed`], which always takes effect (a sealed gate stays sealed), so there
    /// is no state in force to check.
    pub(crate) fn seal(&self) {
        self.shared.gate.set(GateState::Sealed);
        self.reset_flows(None);
    }

    /// Stop the pump and reset every flow.
    pub fn shutdown(&self) {
        self.seal();
        if self.shutdown.send(true).is_err() {
            tracing::trace!("netstack pump already stopped");
        }
    }
}

/// A tunnel port held for inbound TCP and/or UDP (see [`Netstack::reserve_inbound`]). Dropping
/// it frees the port; listeners made from it never free it themselves.
#[derive(Debug)]
pub struct PortReservation {
    shared: Arc<Shared>,
    port: u16,
    tcp: bool,
    udp: bool,
}

impl PortReservation {
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Listen for inbound TCP on the reserved port, keeping `backlog` sockets ready (payload
    /// class: the gate must be open).
    ///
    /// # Errors
    ///
    /// `InvalidInput` when the port is not reserved for TCP; otherwise fails when the gate is
    /// closed or an admission limit is reached.
    pub fn listen_tcp(&self, backlog: usize) -> io::Result<TcpListener> {
        if !self.tcp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "port not reserved for TCP",
            ));
        }
        tcp::listen_on(
            self.shared.clone(),
            self.port,
            backlog,
            FlowClass::Payload,
            false,
        )
    }

    /// A UDP socket on the reserved port (payload class: the gate must be open).
    ///
    /// # Errors
    ///
    /// `InvalidInput` when the port is not reserved for UDP; otherwise fails when the gate is
    /// closed or an admission limit is reached.
    pub fn bind_udp(&self) -> io::Result<UdpSocket> {
        if !self.udp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "port not reserved for UDP",
            ));
        }
        udp::bind_at(
            self.shared.clone(),
            None,
            Some(self.port),
            FlowClass::Payload,
            false,
        )
    }
}

impl Drop for PortReservation {
    fn drop(&mut self) {
        self.shared.release_reserved(self.port, self.tcp, self.udp);
    }
}

async fn pump(shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    let mut spins = 0u32;
    loop {
        if *shutdown.borrow() {
            break;
        }
        let next = shared.poll_round();
        match next {
            PumpNext::Immediately => {
                spins += 1;
                if spins > 64 {
                    // Never monopolise a runtime thread, even under a packet flood.
                    spins = 0;
                    tokio::time::sleep(Duration::from_millis(1)).await;
                } else {
                    tokio::task::yield_now().await;
                }
            }
            PumpNext::Sleep(d) => {
                spins = 0;
                tokio::select! {
                    () = shared.wake.notified() => {}
                    () = tokio::time::sleep(d.min(Duration::from_secs(1))) => {}
                    _ = shutdown.changed() => break,
                }
            }
            PumpNext::WaitForWake => {
                spins = 0;
                tokio::select! {
                    () = shared.wake.notified() => {}
                    // Periodic maintenance even when idle (orphan GC, fragment expiry).
                    () = tokio::time::sleep(Duration::from_secs(1)) => {}
                    _ = shutdown.changed() => break,
                }
            }
        }
    }
    // Final teardown: reset everything still open so peers see RSTs promptly.
    let mut guard = shared.stack.lock();
    let stack = &mut *guard;
    let handles: Vec<_> = stack.flows.keys().copied().collect();
    for handle in handles {
        match stack.flows[&handle].proto {
            Proto::Tcp | Proto::TcpListen => {
                stack.sockets.get_mut::<stcp::Socket<'_>>(handle).abort();
            }
            Proto::Udp => stack.sockets.get_mut::<sudp::Socket<'_>>(handle).close(),
        }
    }
    let now = stack.now();
    let _ = stack
        .iface
        .poll_egress(now, &mut stack.device, &mut stack.sockets);
    drop(guard);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU8};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::ipchan::{self, IpChannelStats};

    /// A netstack whose IP channel the test drives itself (no `WireGuard`), gate open.
    fn stack(address: &str, limits: NetstackLimits) -> (Netstack, Arc<IpChannelShared>) {
        let (_to_stack, _from_stack, chan) = ipchan::channel(
            256,
            1420,
            Arc::new(Notify::new()),
            Arc::new(IpChannelStats::default()),
        );
        let net = Netstack::spawn(
            &[address.parse().unwrap()],
            1420,
            limits,
            TransportPlan::default(),
            chan.clone(),
        )
        .unwrap();
        assert_eq!(net.set_gate(GateState::Open), GateState::Open);
        (net, chan)
    }

    /// Carry packets between two stacks; once `cut` is set, drop them (a peer gone silent,
    /// without any reset).
    fn wire(a: Arc<IpChannelShared>, b: Arc<IpChannelShared>, cut: Arc<AtomicBool>) {
        tokio::spawn(async move {
            loop {
                let mut moved = false;
                for (from, to) in [(&a, &b), (&b, &a)] {
                    while let Some(packet) = from.outbound.pop() {
                        moved = true;
                        if !cut.load(Ordering::Relaxed) && to.inbound.push(packet).is_ok() {
                            to.stack_wake.notify_one();
                        }
                    }
                    from.stack_wake.notify_one();
                }
                if !moved {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        });
    }

    /// What [`stepped_wire`] does with the packets from `a` to `b`.
    const PASS: u8 = 0;
    /// Keep back the next packet that carries TCP payload, and drop every retransmission of it.
    const HOLD: u8 = 1;
    /// Deliver the packet kept back, then pass everything again.
    const RELEASE: u8 = 2;

    /// The sequence number of an IPv4 TCP segment that carries payload.
    fn tcp_data_seq(packet: &[u8]) -> Option<u32> {
        let ihl = usize::from(packet.first()? & 0x0f) * 4;
        let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
        let tcp = packet.get(ihl..)?;
        let header = usize::from(tcp.get(12)? >> 4) * 4;
        let carries = *packet.get(9)? == 6 && total > ihl + header;
        carries.then(|| u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]))
    }

    /// [`wire`] that the test steps through `mode` ([`PASS`], [`HOLD`], [`RELEASE`]): one data
    /// segment from `a` can be kept back while those after it arrive, so `b` holds data that
    /// arrived out of order until the test releases the missing segment.
    fn stepped_wire(a: Arc<IpChannelShared>, b: Arc<IpChannelShared>, mode: Arc<AtomicU8>) {
        tokio::spawn(async move {
            let mut held = None;
            loop {
                while let Some(packet) = a.outbound.pop() {
                    let seq = tcp_data_seq(&packet);
                    match (&held, seq) {
                        (None, Some(seq)) if mode.load(Ordering::Relaxed) == HOLD => {
                            held = Some((seq, packet));
                            continue;
                        }
                        (Some((kept, _)), Some(seq)) if *kept == seq => continue,
                        _ => {}
                    }
                    if b.inbound.push(packet).is_ok() {
                        b.stack_wake.notify_one();
                    }
                }
                if mode.load(Ordering::Relaxed) == RELEASE {
                    if let Some((_, packet)) = held.take()
                        && b.inbound.push(packet).is_ok()
                    {
                        b.stack_wake.notify_one();
                    }
                    mode.store(PASS, Ordering::Relaxed);
                }
                a.stack_wake.notify_one();
                while let Some(packet) = b.outbound.pop() {
                    if a.inbound.push(packet).is_ok() {
                        a.stack_wake.notify_one();
                    }
                }
                b.stack_wake.notify_one();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
    }

    /// The byte a stream carries at `offset`: no two neighbouring blocks look alike.
    fn pattern(offset: usize) -> u8 {
        (offset.wrapping_mul(31) ^ (offset >> 7) ^ (offset >> 15)).to_le_bytes()[0]
    }

    fn block(offset: usize, len: usize) -> Vec<u8> {
        (offset..offset + len).map(pattern).collect()
    }

    /// Read `len` bytes and check each against [`pattern`] from `offset` on.
    async fn expect(stream: &mut TcpStream, offset: usize, len: usize) {
        let mut got = vec![0u8; len];
        tokio::time::timeout(Duration::from_secs(60), stream.read_exact(&mut got))
            .await
            .expect("the data arrives")
            .unwrap();
        let first_wrong = got
            .iter()
            .enumerate()
            .find(|(i, byte)| **byte != pattern(offset + i));
        assert_eq!(first_wrong, None, "a byte of the stream differs");
    }

    /// Buffers are replaced by larger ones while they hold data: what was queued — not yet
    /// acknowledged on the sending side, received out of order on the receiving side — must come
    /// out exactly as it went in, and the memory taken for it must be given back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stream_is_carried_intact_while_its_buffers_grow() {
        const HELD: usize = 96 * 1024;
        const AFTER: usize = 4 * 1024 * 1024;
        let roomy = TransportPlan::fixed(FlowTuning {
            tcp_rx_buffer: 2 * 1024 * 1024,
            tcp_tx_buffer: 1024 * 1024,
            ..FlowTuning::default()
        });
        let (client, client_chan) = stack("10.0.0.1/24", NetstackLimits::default());
        let (server, server_chan) = stack("10.0.0.2/24", NetstackLimits::default());
        client.transport().set_plan(roomy.clone());
        server.transport().set_plan(roomy);
        let mode = Arc::new(AtomicU8::new(PASS));
        stepped_wire(client_chan, server_chan, mode.clone());
        let mut listener = server.listen_tcp(7, 1, FlowClass::Payload).unwrap();
        let accepted = tokio::spawn(async move {
            let stream = listener.accept().await.unwrap();
            (stream, listener)
        });
        let mut to_server = client
            .connect_tcp("10.0.0.2:7".parse().unwrap(), FlowClass::Payload)
            .await
            .unwrap();
        let (mut inbound, listener) = accepted.await.unwrap();
        let reserved = |net: &Netstack| net.stats().memory_reserved.load(Ordering::Relaxed);
        let opened = (reserved(&client), reserved(&server));

        // The first segment is kept back: the receiver holds the rest out of order and can hand
        // nothing to its reader; the sender holds all of it unacknowledged.
        mode.store(HOLD, Ordering::Relaxed);
        to_server.write_all(&block(0, HELD)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut byte = [0u8; 1];
        let early = tokio::time::timeout(Duration::from_millis(100), inbound.read(&mut byte)).await;
        assert!(early.is_err(), "data arrived before the missing segment");

        // Both ends grow their buffers around what they hold.
        assert_eq!(to_server.grow_now(), (true, true));
        assert_eq!(inbound.grow_now(), (true, true));
        assert_eq!(reserved(&client), opened.0 + (512 + 256) * 1024);
        assert_eq!(reserved(&server), opened.1 + (512 + 256) * 1024);

        // The missing segment arrives: everything comes out in order, and the stream goes on
        // through the larger buffers (several times around them).
        mode.store(RELEASE, Ordering::Relaxed);
        expect(&mut inbound, 0, HELD).await;
        let writer = tokio::spawn(async move {
            to_server.write_all(&block(HELD, AFTER)).await.unwrap();
            to_server
        });
        expect(&mut inbound, HELD, AFTER).await;
        let to_server = writer.await.unwrap();

        // Both ends closed: everything the connection held, grown or not, is released.
        drop((to_server, inbound, listener));
        for _ in 0..200 {
            if reserved(&client) == 0 && reserved(&server) == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!(
            "buffer memory still reserved: client {}, server {}",
            reserved(&client),
            reserved(&server)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn flows_to_one_remote_are_reset_and_the_others_continue() {
        let (client, client_chan) = stack("10.0.0.1/24", NetstackLimits::default());
        let (server, server_chan) = stack("10.0.0.2/24", NetstackLimits::default());
        wire(client_chan, server_chan, Arc::new(AtomicBool::new(false)));
        let mut listener = server.listen_tcp(7, 4, FlowClass::Payload).unwrap();
        let accepted = tokio::spawn(async move {
            let a = listener.accept().await.unwrap();
            let b = listener.accept().await.unwrap();
            (a, b, listener)
        });
        let mut to_server = client
            .connect_tcp("10.0.0.2:7".parse().unwrap(), FlowClass::Payload)
            .await
            .unwrap();
        let mut control = client
            .connect_tcp("10.0.0.2:7".parse().unwrap(), FlowClass::Control)
            .await
            .unwrap();
        let (mut peer_a, mut peer_b, _listener) = accepted.await.unwrap();

        // Another remote, and a control flow to the same one, are not touched.
        assert_eq!(
            client.reset_tcp_flows_to(FlowClass::Payload, |ip| ip
                == "10.0.0.9".parse::<IpAddr>().unwrap()),
            0
        );
        assert_eq!(
            client.reset_tcp_flows_to(FlowClass::Payload, |ip| ip
                == "10.0.0.2".parse::<IpAddr>().unwrap()),
            1
        );
        let mut rest = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), to_server.read_to_end(&mut rest))
            .await
            .expect("the reset flow ends");
        assert!(read.is_err(), "reset, not a clean end: {read:?}");
        let mut buf = [0u8; 2];
        control.write_all(b"ok").await.unwrap();
        // Whichever accepted socket is the control flow answers.
        let read_a =
            tokio::time::timeout(Duration::from_millis(500), peer_a.read_exact(&mut buf)).await;
        if !matches!(read_a, Ok(Ok(_))) {
            peer_b.read_exact(&mut buf).await.unwrap();
        }
        assert_eq!(&buf, b"ok");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reserved_port_outlives_its_listeners_and_its_flows_can_be_reset() {
        let (client, client_chan) = stack("10.0.0.1/24", NetstackLimits::default());
        let (server, server_chan) = stack("10.0.0.2/24", NetstackLimits::default());
        wire(client_chan, server_chan, Arc::new(AtomicBool::new(false)));
        let reserved = server.reserve_inbound(4000, true, true).unwrap();
        // Held for TCP and UDP: nobody else gets it, a second reservation neither.
        assert_eq!(
            server
                .listen_tcp(4000, 1, FlowClass::Payload)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::AddrInUse)
        );
        assert_eq!(
            server
                .bind_udp_port(4000, FlowClass::Payload)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::AddrInUse)
        );
        assert!(server.reserve_inbound(4000, false, true).is_err());

        // A listener made from it, dropped, leaves the port reserved.
        drop(reserved.listen_tcp(2).unwrap());
        assert!(server.listen_tcp(4000, 1, FlowClass::Payload).is_err());
        let mut listener = reserved.listen_tcp(2).unwrap();
        let accepted = tokio::spawn(async move {
            let s = listener.accept().await.unwrap();
            (s, listener)
        });
        let mut to_server = client
            .connect_tcp("10.0.0.2:4000".parse().unwrap(), FlowClass::Payload)
            .await
            .unwrap();
        let (mut inbound, listener) = accepted.await.unwrap();
        assert_eq!(inbound.peer_addr(), to_server.local_addr());
        to_server.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        inbound.read_exact(&mut buf).await.unwrap();

        // Resetting the port ends its connections (not other ports').
        assert_eq!(server.reset_tcp_port(4001), 0);
        assert_eq!(server.reset_tcp_port(4000), 1);
        let mut rest = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), to_server.read_to_end(&mut rest))
            .await
            .expect("the reset connection ends");
        assert!(read.is_err(), "reset, not a clean end: {read:?}");

        // UDP on the reserved port; then dropping everything frees it.
        let udp = reserved.bind_udp().unwrap();
        assert_eq!(udp.local_port(), 4000);
        drop((udp, listener, inbound));
        assert!(server.bind_udp_port(4000, FlowClass::Payload).is_err());
        drop(reserved);
        let again = server.listen_tcp(4000, 1, FlowClass::Payload).unwrap();
        drop(again);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sources_are_only_the_stacks_own_addresses() {
        let (client, client_chan) = stack("10.0.0.1/24", NetstackLimits::default());
        let (server, server_chan) = stack("10.0.0.2/24", NetstackLimits::default());
        wire(client_chan, server_chan, Arc::new(AtomicBool::new(false)));
        let mut listener = server.listen_tcp(7, 2, FlowClass::Payload).unwrap();
        let foreign: IpAddr = "192.88.99.7".parse().unwrap();
        let err = client
            .connect_tcp_from(foreign, "10.0.0.2:7".parse().unwrap(), FlowClass::Payload)
            .await
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
        assert!(client.bind_udp_from(foreign, FlowClass::Payload).is_err());

        // Once the address is the stack's own, it is a source like the first one.
        client
            .add_address("192.88.99.7/32".parse().unwrap())
            .unwrap();
        let accepted = tokio::spawn(async move {
            let a = listener.accept().await.unwrap();
            let b = listener.accept().await.unwrap();
            (a.peer_addr().ip(), b.peer_addr().ip())
        });
        let s = client
            .connect_tcp_from(foreign, "10.0.0.2:7".parse().unwrap(), FlowClass::Payload)
            .await
            .unwrap();
        assert_eq!(s.local_addr().ip(), foreign);
        // The default source stays the first address.
        let plain = client
            .connect_tcp("10.0.0.2:7".parse().unwrap(), FlowClass::Payload)
            .await
            .unwrap();
        let first: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(plain.local_addr().ip(), first);
        let (a, b) = accepted.await.unwrap();
        assert_eq!((a, b), (foreign, first));
    }
}
