//! The payload policy of a strict sandbox, enforced on every packet that crosses its TUN device.
//!
//! Outbound (sandbox → tunnel), from the Apps or the worker's own kernel sockets:
//! - the source must be the sandbox's tunnel address of that family, the destination must not be
//!   a special address (loopback, link-local, multicast, broadcast) — otherwise dropped;
//! - the worker's own sockets ([`OwnFlows`]) were admitted by the kernel connector, which already
//!   applied the gate and (for payload) the destination policy, so only the gate is re-checked;
//! - an App flow needs the gate open to start (TCP SYN, a new UDP peer, an ICMP echo) and the
//!   destination policy's consent; existing flows continue while the gate is in `probe` (a
//!   temporary tunnel problem stalls them, it does not cut them), nothing passes while it is
//!   `closed` or `sealed`;
//! - a TCP segment of a connection the filter does not track (it began in an earlier
//!   generation, or a new deny rule ended it) needs the policy's consent too, segment by
//!   segment until it is tracked: a connection a rule cut stays cut;
//! - a later fragment of a datagram has no transport header to check: it goes out only after its
//!   datagram's first fragment did (same addresses, protocol and identification), shortly
//!   before; one without it is dropped;
//! - a refused packet is answered at once, into the TUN: TCP gets a reset, everything else an
//!   ICMP "administratively prohibited". Nothing is ever sent anywhere but into `GotaTun`.
//!
//! Inbound (tunnel → sandbox): only to the tunnel address; nobody inside accepts connections or
//! unsolicited datagrams from the tunnel (a new TCP connection or a UDP datagram from a peer the
//! sandbox never sent to is dropped), so an App listening on a wildcard address is not exposed.
//! The one exception is a port forward's tunnel port, held by the worker: new connections and
//! datagrams reach it only while the forward listens (its lease stands and the gate is open), and
//! the worker's Port Controller puts every source through the inbound guard. A connection request
//! to it meanwhile is answered with a reset into the tunnel, as by a closed port.
//!
//! A port forward can also take its UDP straight into the sandbox (`udp_direct`): its port is
//! then not the worker's but a *direct port* ([`DirectUdpPort`]), held by the App's own socket.
//! A datagram to it from a remote end nobody in the sandbox sent to starts a new App UDP flow —
//! written into the TUN as it came, so the App reads the real source — only while the forward
//! takes new flows (its lease stands: [`DirectUdpPort::open`]), the gate is open and the forward's
//! policy ([`DirectUdpPolicy`]: the same inbound guard and flow limit as the relayed UDP) admits
//! the source. Everything else is dropped, and counted by the forward. Such a flow is tracked like
//! the App's own, the other way round: it is answered by the App's first datagram back, after
//! which it lasts as an answered flow; the App's datagrams on it pass out without the destination
//! policy, as a relayed answer would. Only new remote ends cost a decision: the datagrams of a
//! tracked flow pass on the table lookup alone. When the lease ends, the forward's flows are
//! forgotten at once (their next datagram is unsolicited again); flows the App started itself from
//! the same port are its own and stay. The forward counts its flows and their payload each way.
//!
//! App flows are tracked so UDP replies can be matched and every TCP flow can be reset from both
//! ends when the generation ends. Like Linux conntrack, a flow is kept as long as its state
//! warrants, counted from its last packet:
//! - UDP: [`UDP_UNREPLIED`] (30 s) until its first reply, then [`UDP_IDLE`] (2 min);
//! - TCP: [`TCP_OPENING`] (2 min) until the remote end answers (a SYN without a SYN-ACK — most
//!   P2P dials —, or a connection taken up mid-stream), [`TCP_IDLE`] (2 h 4 min) while
//!   established, [`TCP_CLOSING`] (2 min) after a FIN in one direction; a FIN each way or a reset
//!   ends it (a closed connection is gone at the next sweep).
//!
//! Each protocol's table holds [`UDP_FLOWS`] / [`TCP_FLOWS`] flows. A new flow that finds its
//! table full first drops what has expired (a full sweep at most once a second, so a full table
//! never costs a scan per packet), then evicts the least recently active flow the remote end has
//! not answered yet; only when every tracked flow has been answered is the new one refused (reset
//! or ICMP), the way Linux's "early drop" spares assured entries. Unanswered flows are kept in
//! least-recently-active order, so finding the expired ones and the one to evict costs no scan;
//! answered flows are swept every [`SWEEP_INTERVAL`].
//!
//! The Apps' payload is counted here, each way: TCP segment payload and UDP payload of the App
//! flows as they cross the TUN device, later fragments of an App datagram included. Like an
//! interface counter it counts what crosses, so a retransmitted segment counts again. The worker's
//! own flows (Gateway and Provider connections, DNS, port forwards) are not App traffic — a
//! Gateway counts its payload at its relay — and neither is ICMP nor what the filter writes itself
//! (resets, ICMP errors).
//!
//! The Apps' own flows are also counted per local port of the sandbox (the App socket's port,
//! each protocol apart), so that the manager can tell which App carried them: it knows which
//! ports each App's processes hold. A direct port's flows are its forward's (the forward counts
//! them), and later fragments carry no port: both are only in the totals.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use lru::LruCache;
use vpn_sync::Mutex;

use super::flows::{FlowKey, L4, OwnFlows, OwnInbound};
use super::packet::{self, Fragment, Parsed, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, Transport};
use crate::netstack::{Gate, GateState};

/// The destination policy for new App flows (blocked ports, private ranges, blocklists, bans).
/// Implemented by the Instance's `DestinationPolicy`.
pub trait DestinationCheck: Send + Sync + 'static {
    /// Whether a new payload flow to `dst` may start. `dst.port()` is 0 for ICMP.
    fn allows(&self, dst: SocketAddr) -> bool;
}

/// What a port forward decides and counts about the datagrams the filter lets straight into the
/// sandbox on its direct UDP port.
///
/// See the module docs. Implemented by the forward with its
/// inbound guard and counters. Called on the packet path with the flow table held: every method
/// must be quick and must never call back into the filter.
pub trait DirectUdpPolicy: Send + Sync + 'static {
    /// A datagram from `source` would start a new flow while the forward takes them (its lease
    /// stands, the gate is open): record the arrival and decide (blocklists, bans, auto-ban, the
    /// forward's flow limit). Refused, the datagram is dropped.
    fn admit(&self, source: IpAddr) -> bool;
    /// A datagram from `source` would start a new flow while the forward takes none (no lease,
    /// or the gate is not open): it is dropped; record the arrival.
    fn refused(&self, source: IpAddr);
    /// A flow it admitted is tracked from now on...
    fn started(&self);
    /// ...and no longer: expired, evicted, reset by a deny rule, or ended with the lease.
    fn ended(&self);
    /// Payload of its flows crossing the TUN device: from the remote end to the App...
    fn received(&self, bytes: u64);
    /// ...and from the App back to the remote end.
    fn sent(&self, bytes: u64);
    /// A datagram it admitted could not be tracked (the table is full of answered flows): dropped.
    fn dropped(&self);
}

/// App UDP flows tracked at once, answered or not.
pub const UDP_FLOWS: usize = 65_536;
/// App TCP connections tracked at once, answered or not.
pub const TCP_FLOWS: usize = 65_536;
/// A UDP flow without a reply yet is forgotten this long after its last datagram (a late reply
/// is then dropped)...
const UDP_UNREPLIED: Duration = Duration::from_secs(30);
/// ...and one that has seen replies, this long after its last datagram either way.
const UDP_IDLE: Duration = Duration::from_secs(120);
/// A TCP connection the remote end has not answered yet (Linux conntrack's `SYN_SENT`).
const TCP_OPENING: Duration = Duration::from_secs(120);
/// An established TCP connection: the idle bound of a Gateway's relayed TCP connection
/// (RFC 5382 REQ-5).
const TCP_IDLE: Duration = Duration::from_mins(124);
/// A TCP connection with a FIN in one direction (conntrack's `FIN_WAIT`).
const TCP_CLOSING: Duration = Duration::from_secs(120);
/// Fragmented datagrams followed at once, each way; the first fragment of one more outbound is
/// dropped (inbound it passes, its later fragments are not counted).
const FRAGMENTED: usize = 1024;
/// The later fragments of a datagram go out within this time of its first (Linux's reassembly
/// timeout); after it they are dropped.
const FRAGMENT_TIMEOUT: Duration = Duration::from_secs(30);
/// How often expired entries are swept while packets flow.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);
/// A full table is swept at most this often before a new flow evicts one or is refused.
const FULL_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// What to do with a packet read from the TUN device.
#[derive(Debug, PartialEq, Eq)]
pub enum Outbound {
    /// Hand it to `GotaTun`.
    Pass,
    Drop,
    /// Refused: write this answer (TCP reset or ICMP error) back into the TUN device.
    Refuse(Vec<u8>),
}

/// Resets that end App TCP connections at both ends.
pub struct Resets {
    /// Into the TUN device, for the Apps.
    pub(crate) to_apps: Vec<Vec<u8>>,
    /// Into the tunnel, for the remote hosts.
    pub(crate) to_remotes: Vec<Vec<u8>>,
    /// Connections ended.
    pub(crate) connections: usize,
}

/// What to do with a decrypted packet before it is written into the TUN device.
#[derive(Debug, PartialEq, Eq)]
pub enum Inbound {
    Pass,
    Drop,
    /// Refused: send this answer (a TCP reset) back into the tunnel.
    Refuse(Vec<u8>),
}

/// Packet counters of the TUN path.
#[derive(Debug, Default)]
pub struct FilterStats {
    /// Packets handed to `GotaTun`, and their bytes.
    pub outbound_packets: AtomicU64,
    pub outbound_bytes: AtomicU64,
    /// Decrypted packets written into the TUN device, and their bytes.
    pub inbound_packets: AtomicU64,
    pub inbound_bytes: AtomicU64,
    /// Flows refused (gate, policy, full table) and answered with a reset or ICMP error.
    pub refused: AtomicU64,
    /// Packets dropped silently: malformed, wrong source, special destination, unsolicited.
    pub dropped: AtomicU64,
    /// The Apps' payload (TCP segment payload, UDP payload) that crossed the TUN device: from the
    /// remote hosts to the Apps (rx) and back (tx). The worker's own flows are not in it.
    pub app_rx_bytes: AtomicU64,
    pub app_tx_bytes: AtomicU64,
    /// New App flows refused because their table was full of flows the remote end had answered
    /// (also counted in `refused`).
    pub table_full: AtomicU64,
    /// App flows the remote end had not answered, dropped from a full table to make room.
    pub evicted: AtomicU64,
}

/// What a passing packet carries: the App payload of a packet of an App flow (`None` for the
/// worker's own flows, ICMP, and packets that do not pass), and the port forward whose flow it
/// is when it belongs to a remote end's flow to a direct UDP port.
#[derive(Default)]
struct Carried {
    app: Option<u64>,
    forward: Option<Arc<dyn DirectUdpPolicy>>,
    /// The App socket's local port, when the packet has a transport header.
    port: Option<(L4, u16)>,
}

impl Carried {
    fn app(bytes: u32) -> Self {
        Self {
            app: Some(u64::from(bytes)),
            forward: None,
            port: None,
        }
    }

    fn of(bytes: u32, forward: Option<Arc<dyn DirectUdpPolicy>>) -> Self {
        Self {
            app: Some(u64::from(bytes)),
            forward,
            port: None,
        }
    }

    /// The same, on the App socket at `port` of `l4`.
    const fn at(mut self, l4: L4, port: u16) -> Self {
        self.port = Some((l4, port));
        self
    }
}

/// How long a local port keeps its counters after its last payload: long enough for every
/// reader to see its last bytes (the worker reports about once a second).
const PORT_IDLE: Duration = Duration::from_secs(30);

/// The App payload one local port of the sandbox carried, cumulative while the entry lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortPayload {
    pub l4: L4,
    pub port: u16,
    /// From the remote hosts to the App socket.
    pub rx_bytes: u64,
    /// From the App socket to the remote hosts.
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
struct PortCount {
    rx: u64,
    tx: u64,
    last: Instant,
}

/// The App payload per local port. An entry goes once its port has been idle for [`PORT_IDLE`];
/// a port used again later starts from 0.
#[derive(Debug, Default)]
struct PortCounts(Mutex<HashMap<(L4, u16), PortCount>>);

impl PortCounts {
    fn add(&self, key: (L4, u16), rx: u64, tx: u64, now: Instant) {
        let mut map = self.0.lock();
        let entry = map.entry(key).or_insert(PortCount {
            rx: 0,
            tx: 0,
            last: now,
        });
        entry.rx = entry.rx.saturating_add(rx);
        entry.tx = entry.tx.saturating_add(tx);
        entry.last = now;
        drop(map);
    }

    /// Every entry, after dropping the ones idle for [`PORT_IDLE`] (their last bytes were
    /// reported before).
    fn snapshot(&self, now: Instant) -> Vec<PortPayload> {
        let mut map = self.0.lock();
        map.retain(|_, c| now.saturating_duration_since(c.last) < PORT_IDLE);
        let mut out: Vec<PortPayload> = map
            .iter()
            .map(|(&(l4, port), c)| PortPayload {
                l4,
                port,
                rx_bytes: c.rx,
                tx_bytes: c.tx,
            })
            .collect();
        drop(map);
        out.sort_by_key(|p| (p.l4 == L4::Udp, p.port));
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowId {
    local_port: u16,
    remote: SocketAddr,
}

/// A tracked App UDP flow.
struct UdpTrack {
    last: Instant,
    /// Started by a remote end's datagram to a port forward's direct port: the forward's flow,
    /// answered by the App (an App's own flow is answered by the remote end).
    direct: Option<DirectFlow>,
}

impl UdpTrack {
    /// A flow the App starts.
    const fn app(now: Instant) -> Self {
        Self {
            last: now,
            direct: None,
        }
    }

    fn forward(&self) -> Option<Arc<dyn DirectUdpPolicy>> {
        self.direct.as_ref().map(|d| d.policy.clone())
    }
}

/// A port forward's hold on one of its flows: the forward counts it from the moment the filter
/// tracks it until the filter forgets it, however that happens (the entry is dropped).
struct DirectFlow {
    policy: Arc<dyn DirectUdpPolicy>,
}

impl DirectFlow {
    fn new(policy: Arc<dyn DirectUdpPolicy>) -> Self {
        policy.started();
        Self { policy }
    }
}

impl Drop for DirectFlow {
    fn drop(&mut self) {
        self.policy.ended();
    }
}

/// A port forward's direct UDP port, as the filter knows it.
struct DirectPort {
    /// Tells this registration from a later one of the same port.
    serial: u64,
    policy: Arc<dyn DirectUdpPolicy>,
    /// The forward's lease stands: new flows are admitted (while the gate is open).
    open: bool,
}

#[derive(Debug, Clone, Copy)]
struct TcpTrack {
    /// Next sequence number the App will send.
    app_next: u32,
    /// Next sequence number the remote end will send, once seen (the connection is answered).
    remote_next: Option<u32>,
    app_fin: bool,
    remote_fin: bool,
    last: Instant,
}

impl TcpTrack {
    /// A connection the remote end has not answered yet.
    const fn opening(app_next: u32, app_fin: bool, now: Instant) -> Self {
        Self {
            app_next,
            remote_next: None,
            app_fin,
            remote_fin: false,
            last: now,
        }
    }

    /// A FIN went each way: nothing more to carry.
    const fn closed(&self) -> bool {
        self.app_fin && self.remote_fin
    }

    /// How long an answered connection is kept after its last segment.
    const fn timeout(&self) -> Duration {
        if self.app_fin || self.remote_fin {
            TCP_CLOSING
        } else {
            TCP_IDLE
        }
    }
}

/// An outbound fragmented datagram: the key its fragments are reassembled by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DatagramId {
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    id: u32,
}

impl DatagramId {
    const fn of(p: &Parsed, f: Fragment) -> Self {
        Self {
            src: p.src,
            dst: p.dst,
            proto: f.proto,
            id: f.id,
        }
    }
}

/// An outbound datagram whose first fragment went out: when, whether it is an App's (its later
/// fragments are App payload), and the port forward whose flow it belongs to, if any.
struct Followed {
    first: Instant,
    app: bool,
    forward: Option<Arc<dyn DirectUdpPolicy>>,
}

/// An inbound App datagram whose first fragment came in: when, and the port forward whose flow it
/// belongs to, if any (its later fragments count for it too).
struct FragmentIn {
    first: Instant,
    forward: Option<Arc<dyn DirectUdpPolicy>>,
}

/// How many flows each table holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacity {
    pub tcp: usize,
    pub udp: usize,
}

impl Default for Capacity {
    fn default() -> Self {
        Self {
            tcp: TCP_FLOWS,
            udp: UDP_FLOWS,
        }
    }
}

fn idle(now: Instant, last: Instant) -> Duration {
    now.saturating_duration_since(last)
}

struct Tracks {
    capacity: Capacity,
    /// UDP flows that have seen a reply, and when they were last active.
    udp: HashMap<FlowId, UdpTrack>,
    /// UDP flows still waiting for their first reply, least recently active first.
    udp_unreplied: LruCache<FlowId, UdpTrack>,
    /// TCP connections the remote end has answered.
    tcp: HashMap<FlowId, TcpTrack>,
    /// TCP connections the remote end has not answered yet (SYN sent, or taken up mid-stream),
    /// least recently active first.
    tcp_opening: LruCache<FlowId, TcpTrack>,
    /// Outbound datagrams whose first fragment went out.
    fragmented: HashMap<DatagramId, Followed>,
    /// Inbound App datagrams whose first fragment came in.
    fragments_in: HashMap<DatagramId, FragmentIn>,
    /// Port forwards' direct UDP ports, by port.
    direct: HashMap<u16, DirectPort>,
    /// The serial of the next direct port registration.
    next_serial: u64,
    last_sweep: Option<Instant>,
}

/// Shows how many flows are tracked, not which.
impl std::fmt::Debug for Tracks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tracks")
            .field("udp", &self.udp.len())
            .field("udp_unreplied", &self.udp_unreplied.len())
            .field("tcp", &self.tcp.len())
            .field("tcp_opening", &self.tcp_opening.len())
            .field("fragmented", &self.fragmented.len())
            .finish_non_exhaustive()
    }
}

impl Tracks {
    fn new(capacity: Capacity) -> Self {
        Self {
            capacity,
            udp: HashMap::new(),
            udp_unreplied: LruCache::unbounded(),
            tcp: HashMap::new(),
            tcp_opening: LruCache::unbounded(),
            fragmented: HashMap::new(),
            fragments_in: HashMap::new(),
            direct: HashMap::new(),
            next_serial: 1,
            last_sweep: None,
        }
    }

    /// A datagram of a tracked UDP flow, from the App (`from_app`) or from the remote end: the
    /// flow is refreshed, and answered by its first datagram the other way (the remote end's for
    /// a flow the App started, the App's for a remote end's flow to a direct port). `None` when
    /// the flow is not tracked; otherwise the port forward whose flow it is, if any.
    #[expect(
        clippy::option_option,
        reason = "outer: whether the flow is tracked; inner: the port forward it belongs to, if any"
    )]
    fn udp_datagram(
        &mut self,
        id: &FlowId,
        from_app: bool,
        now: Instant,
    ) -> Option<Option<Arc<dyn DirectUdpPolicy>>> {
        if let Some(t) = self.udp.get_mut(id) {
            t.last = now;
            return Some(t.forward());
        }
        let answers = self.udp_unreplied.peek(id)?.direct.is_some() == from_app;
        if answers {
            let mut t = self.udp_unreplied.pop(id)?;
            t.last = now;
            let forward = t.forward();
            self.udp.insert(*id, t);
            Some(forward)
        } else {
            let t = self.udp_unreplied.get_mut(id)?;
            t.last = now;
            Some(t.forward())
        }
    }

    /// Forget the flows the forward on direct `port` admitted (its lease ended): the next datagram
    /// of their remote ends is unsolicited again. The App's own flows from the port stay.
    fn end_direct(&mut self, port: u16) {
        let theirs = |id: &FlowId, t: &UdpTrack| id.local_port == port && t.direct.is_some();
        self.udp.retain(|id, t| !theirs(id, t));
        let gone: Vec<FlowId> = self
            .udp_unreplied
            .iter()
            .filter(|(id, t)| theirs(id, t))
            .map(|(id, _)| *id)
            .collect();
        for id in gone {
            self.udp_unreplied.pop(&id);
        }
    }

    fn full(&self, l4: L4) -> bool {
        match l4 {
            L4::Udp => self.udp.len() + self.udp_unreplied.len() >= self.capacity.udp,
            L4::Tcp => self.tcp.len() + self.tcp_opening.len() >= self.capacity.tcp,
        }
    }

    /// Forget the unanswered flows whose time is up. They are in least-recently-active order:
    /// this stops at the first one still alive.
    fn expire_unanswered(&mut self, now: Instant) {
        while self
            .udp_unreplied
            .peek_lru()
            .is_some_and(|(_, t)| idle(now, t.last) >= UDP_UNREPLIED)
        {
            self.udp_unreplied.pop_lru();
        }
        while self
            .tcp_opening
            .peek_lru()
            .is_some_and(|(_, t)| idle(now, t.last) >= TCP_OPENING)
        {
            self.tcp_opening.pop_lru();
        }
    }

    fn sweep(&mut self, now: Instant) {
        self.expire_unanswered(now);
        self.udp.retain(|_, t| idle(now, t.last) < UDP_IDLE);
        self.tcp
            .retain(|_, t| !t.closed() && idle(now, t.last) < t.timeout());
        self.fragmented
            .retain(|_, f| idle(now, f.first) < FRAGMENT_TIMEOUT);
        self.fragments_in
            .retain(|_, f| idle(now, f.first) < FRAGMENT_TIMEOUT);
        self.last_sweep = Some(now);
    }

    fn maybe_sweep(&mut self, now: Instant) {
        if self
            .last_sweep
            .is_none_or(|t| idle(now, t) >= SWEEP_INTERVAL)
        {
            self.sweep(now);
        }
    }

    /// Room for one more flow of `l4`: the expired flows go first (a full sweep at most once a
    /// second), then the least recently active flow the remote end has not answered is evicted.
    /// False when every tracked flow has been answered: the new one is refused.
    fn make_room(&mut self, l4: L4, now: Instant, stats: &FilterStats) -> bool {
        if !self.full(l4) {
            return true;
        }
        self.expire_unanswered(now);
        if self.full(l4)
            && self
                .last_sweep
                .is_none_or(|t| idle(now, t) >= FULL_SWEEP_INTERVAL)
        {
            self.sweep(now);
        }
        if !self.full(l4) {
            return true;
        }
        let evicted = match l4 {
            L4::Udp => self.udp_unreplied.pop_lru().is_some(),
            L4::Tcp => self.tcp_opening.pop_lru().is_some(),
        };
        if evicted {
            stats.evicted.fetch_add(1, Ordering::Relaxed);
        }
        evicted
    }

    fn forget_tcp(&mut self, id: &FlowId) {
        self.tcp.remove(id);
        self.tcp_opening.pop(id);
    }

    /// Follow a segment the App sends on `id` that the policy let through (`next`: the sequence
    /// number after it). False when a connection request found the table full of answered
    /// connections: it is refused.
    fn app_tcp(
        &mut self,
        id: FlowId,
        opening: bool,
        flags: u8,
        next: u32,
        now: Instant,
        stats: &FilterStats,
    ) -> bool {
        let fin = flags & TCP_FIN != 0;
        if flags & TCP_RST != 0 {
            self.forget_tcp(&id);
        } else if opening {
            // A connection request is a new connection, also on the ports of one the
            // remote end answered before: it starts over, unanswered.
            self.tcp.remove(&id);
            if let Some(t) = self.tcp_opening.get_mut(&id) {
                t.app_next = next;
                t.last = now;
            } else if self.make_room(L4::Tcp, now, stats) {
                self.tcp_opening.put(id, TcpTrack::opening(next, fin, now));
            } else {
                return false;
            }
        } else if let Some(t) = self.tcp.get_mut(&id) {
            t.app_next = next;
            t.app_fin |= fin;
            t.last = now;
        } else if let Some(t) = self.tcp_opening.get_mut(&id) {
            t.app_next = next;
            t.app_fin |= fin;
            t.last = now;
        } else if self.make_room(L4::Tcp, now, stats) {
            // One that began before the filter tracked it: taken up, answered once the
            // remote end's next segment comes back.
            self.tcp_opening.put(id, TcpTrack::opening(next, fin, now));
        }
        // Otherwise (the table is full of answered connections) it stays untracked: its
        // next segment is checked against the policy again.
        true
    }

    /// Follow a segment the remote end sends on `id` (`remote_next`: the sequence number after
    /// it); its answer establishes a connection the App opened.
    fn remote_tcp(&mut self, id: FlowId, flags: u8, remote_next: u32, now: Instant) {
        let fin = flags & TCP_FIN != 0;
        if flags & TCP_RST != 0 {
            self.forget_tcp(&id);
        } else if let Some(t) = self.tcp.get_mut(&id) {
            t.remote_next = Some(remote_next);
            t.remote_fin |= fin;
            t.last = now;
        } else if let Some(mut t) = self.tcp_opening.pop(&id) {
            // The remote end answers: the connection is established.
            t.remote_next = Some(remote_next);
            t.remote_fin |= fin;
            t.last = now;
            self.tcp.insert(id, t);
        }
    }

    /// The first fragment of `id` goes out, carrying `carried`: follow its datagram. False when
    /// no more datagrams can be followed.
    fn first_fragment(&mut self, id: DatagramId, now: Instant, carried: &Carried) -> bool {
        if !self.fragmented.contains_key(&id) && self.fragmented.len() >= FRAGMENTED {
            self.fragmented
                .retain(|_, f| idle(now, f.first) < FRAGMENT_TIMEOUT);
            if self.fragmented.len() >= FRAGMENTED {
                return false;
            }
        }
        self.fragmented.insert(
            id,
            Followed {
                first: now,
                app: carried.app.is_some(),
                forward: carried.forward.clone(),
            },
        );
        true
    }

    /// Whether a later fragment of `id` may go out (its first one did, recently), and if so
    /// whether it is an App's and the port forward whose flow it belongs to. The last fragment
    /// ends the datagram.
    fn later_fragment(
        &mut self,
        id: DatagramId,
        more: bool,
        now: Instant,
    ) -> Option<(bool, Option<Arc<dyn DirectUdpPolicy>>)> {
        let follows = self
            .fragmented
            .get(&id)
            .filter(|f| idle(now, f.first) < FRAGMENT_TIMEOUT)
            .map(|f| (f.app, f.forward.clone()));
        if follows.is_none() || !more {
            self.fragmented.remove(&id);
        }
        follows
    }

    /// The first fragment of an App datagram came in: its later fragments are App payload (and
    /// `forward`'s, when it belongs to a direct port's flow).
    fn first_fragment_in(
        &mut self,
        id: DatagramId,
        now: Instant,
        forward: Option<Arc<dyn DirectUdpPolicy>>,
    ) {
        if !self.fragments_in.contains_key(&id) && self.fragments_in.len() >= FRAGMENTED {
            self.fragments_in
                .retain(|_, f| idle(now, f.first) < FRAGMENT_TIMEOUT);
            if self.fragments_in.len() >= FRAGMENTED {
                return;
            }
        }
        self.fragments_in.insert(
            id,
            FragmentIn {
                first: now,
                forward,
            },
        );
    }

    /// Whether a later inbound fragment of `id` belongs to an App datagram (`Some`), and the port
    /// forward whose flow it belongs to, if any. The last fragment ends it.
    #[expect(
        clippy::option_option,
        reason = "outer: whether the fragment is an App datagram's; inner: the port forward it belongs to, if any"
    )]
    fn later_fragment_in(
        &mut self,
        id: DatagramId,
        more: bool,
        now: Instant,
    ) -> Option<Option<Arc<dyn DirectUdpPolicy>>> {
        let app = self
            .fragments_in
            .get(&id)
            .filter(|f| idle(now, f.first) < FRAGMENT_TIMEOUT)
            .map(|f| f.forward.clone());
        if app.is_none() || !more {
            self.fragments_in.remove(&id);
        }
        app
    }
}

/// The direct UDP ports of one filter: the kernel connector registers port forwards' ports here.
#[derive(Clone)]
pub struct DirectPorts(Arc<Mutex<Tracks>>);

impl DirectPorts {
    /// Make `port` a port forward's direct UDP port, `policy` deciding on and counting its
    /// flows. It takes new flows only once opened ([`DirectUdpPort::open`]). `AddrInUse` when
    /// the port is another forward's already.
    pub(crate) fn register(
        &self,
        port: u16,
        policy: Arc<dyn DirectUdpPolicy>,
    ) -> io::Result<DirectUdpPort> {
        if port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "port 0 is no port",
            ));
        }
        let mut tracks = self.0.lock();
        if tracks.direct.contains_key(&port) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "the port takes another forward's UDP already",
            ));
        }
        let serial = tracks.next_serial;
        tracks.next_serial += 1;
        tracks.direct.insert(
            port,
            DirectPort {
                serial,
                policy,
                open: false,
            },
        );
        drop(tracks);
        Ok(DirectUdpPort {
            tracks: self.0.clone(),
            port,
            serial,
        })
    }
}

/// Forget a direct port's flows and, with `unregister`, the port itself — only if the
/// registration is still `serial`'s.
fn close_direct(tracks: &Mutex<Tracks>, port: u16, serial: u64, unregister: bool) {
    let mut t = tracks.lock();
    let Some(d) = t.direct.get_mut(&port).filter(|d| d.serial == serial) else {
        return;
    };
    d.open = false;
    if unregister {
        t.direct.remove(&port);
    }
    t.end_direct(port);
}

/// A port forward's UDP port whose datagrams the strict filter lets straight into the sandbox.
///
/// They go to the App socket holding the port there (see the module docs). Until it is opened, datagrams
/// from new remote ends are dropped and counted. Dropping it gives the port up: its flows are
/// forgotten and its datagrams are unsolicited like any others.
#[derive(Debug)]
pub struct DirectUdpPort {
    tracks: Arc<Mutex<Tracks>>,
    port: u16,
    serial: u64,
}

impl DirectUdpPort {
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Take new flows (the forward's lease stands; the gate must be open too) until the returned
    /// guard is dropped, which ends the forward's flows at once. One lease at a time: open the
    /// next only after the last one's guard is gone.
    #[must_use]
    pub fn open(&self) -> DirectUdpOpen {
        if let Some(d) = self
            .tracks
            .lock()
            .direct
            .get_mut(&self.port)
            .filter(|d| d.serial == self.serial)
        {
            d.open = true;
        }
        DirectUdpOpen {
            tracks: self.tracks.clone(),
            port: self.port,
            serial: self.serial,
        }
    }
}

impl Drop for DirectUdpPort {
    fn drop(&mut self) {
        close_direct(&self.tracks, self.port, self.serial, true);
    }
}

/// A direct UDP port taking new flows (see [`DirectUdpPort::open`]).
#[derive(Debug)]
pub struct DirectUdpOpen {
    tracks: Arc<Mutex<Tracks>>,
    port: u16,
    serial: u64,
}

impl Drop for DirectUdpOpen {
    fn drop(&mut self) {
        close_direct(&self.tracks, self.port, self.serial, false);
    }
}

pub struct PacketFilter {
    gate: Arc<Gate>,
    own: OwnFlows,
    policy: Arc<dyn DestinationCheck>,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    /// Shared with the direct UDP ports registered through [`Self::direct_ports`].
    tracks: Arc<Mutex<Tracks>>,
    pub(crate) stats: FilterStats,
    /// The App payload per local port.
    ports: PortCounts,
}

/// An ICMP message of type `kind` from the peer: errors and echo replies pass while the tunnel
/// is up, nothing else does.
const fn inbound_icmp(p: &Parsed, up: bool, kind: u8) -> Inbound {
    let v6 = p.is_v6();
    if up && (packet::icmp_is_error(v6, kind) || packet::icmp_is_echo_reply(v6, kind)) {
        Inbound::Pass
    } else {
        Inbound::Drop
    }
}

fn seq_len(flags: u8, payload: u32) -> u32 {
    payload
        .wrapping_add(u32::from(flags & TCP_SYN != 0))
        .wrapping_add(u32::from(flags & TCP_FIN != 0))
}

impl PacketFilter {
    pub(crate) fn new(
        gate: Arc<Gate>,
        own: OwnFlows,
        policy: Arc<dyn DestinationCheck>,
        v4: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
    ) -> Self {
        Self {
            gate,
            own,
            policy,
            v4,
            v6,
            tracks: Arc::new(Mutex::new(Tracks::new(Capacity::default()))),
            stats: FilterStats::default(),
            ports: PortCounts::default(),
        }
    }

    /// Where port forwards register their direct UDP ports with this filter.
    pub(crate) fn direct_ports(&self) -> DirectPorts {
        DirectPorts(self.tracks.clone())
    }

    fn is_ours(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => self.v4 == Some(a),
            IpAddr::V6(a) => self.v6 == Some(a),
        }
    }

    fn ours_for(&self, remote: IpAddr) -> Option<IpAddr> {
        match remote {
            IpAddr::V4(_) => self.v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.v6.map(IpAddr::V6),
        }
    }

    fn drop_packet(&self) -> Outbound {
        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
        Outbound::Drop
    }

    fn refuse(&self, raw: &[u8], p: &Parsed) -> Outbound {
        self.stats.refused.fetch_add(1, Ordering::Relaxed);
        let answer = match p.transport {
            Transport::Tcp { .. } => packet::tcp_reset_reply(p),
            _ => packet::icmp_prohibited(raw, p),
        };
        answer.map_or(Outbound::Drop, Outbound::Refuse)
    }

    /// A new App flow that found its table full of answered flows.
    fn refuse_full(&self, raw: &[u8], p: &Parsed) -> Outbound {
        self.stats.table_full.fetch_add(1, Ordering::Relaxed);
        self.refuse(raw, p)
    }

    /// Decide on a packet read from the TUN device.
    pub(crate) fn outbound(&self, raw: &[u8], now: Instant) -> Outbound {
        let (verdict, carried) = self.decide_outbound(raw, now);
        if verdict == Outbound::Pass {
            self.stats.outbound_packets.fetch_add(1, Ordering::Relaxed);
            self.stats
                .outbound_bytes
                .fetch_add(raw.len() as u64, Ordering::Relaxed);
            if let Some(n) = carried.app.filter(|n| *n > 0) {
                self.stats.app_tx_bytes.fetch_add(n, Ordering::Relaxed);
                // A direct port's forward counts its flows itself; the ports count the Apps' own.
                if let Some(forward) = &carried.forward {
                    forward.sent(n);
                } else if let Some(key) = carried.port {
                    self.ports.add(key, 0, n, now);
                }
            }
        }
        verdict
    }

    fn decide_outbound(&self, raw: &[u8], now: Instant) -> (Outbound, Carried) {
        let Some(p) = packet::parse(raw) else {
            return (self.drop_packet(), Carried::default());
        };
        if !self.is_ours(p.src) || packet::is_special(p.dst) {
            return (self.drop_packet(), Carried::default());
        }
        let Some(fragment) = p.fragment else {
            return self.decide_packet(raw, p, now);
        };
        let id = DatagramId::of(&p, fragment);
        if p.transport == Transport::Fragment {
            // No transport header to check: it goes where its first fragment went, or nowhere.
            let up = matches!(self.gate.get(), GateState::Open | GateState::Probe);
            let follows = if up {
                self.tracks.lock().later_fragment(id, fragment.more, now)
            } else {
                None
            };
            return match follows {
                Some((app, forward)) => (
                    Outbound::Pass,
                    Carried {
                        app: app.then_some(u64::from(fragment.bytes)),
                        forward,
                        port: None,
                    },
                ),
                None => (self.drop_packet(), Carried::default()),
            };
        }
        let (verdict, carried) = self.decide_packet(raw, p, now);
        let mut tracks = self.tracks.lock();
        if verdict != Outbound::Pass {
            // The rest of a refused datagram never follows.
            tracks.fragmented.remove(&id);
            return (verdict, Carried::default());
        }
        if tracks.first_fragment(id, now, &carried) {
            (Outbound::Pass, carried)
        } else {
            drop(tracks);
            (self.drop_packet(), Carried::default())
        }
    }

    /// Decide on an unfragmented packet or a first fragment (it has the transport header).
    fn decide_packet(&self, raw: &[u8], p: Parsed, now: Instant) -> (Outbound, Carried) {
        let gate = self.gate.get();
        let up = matches!(gate, GateState::Open | GateState::Probe);
        match p.transport {
            Transport::Tcp {
                src_port,
                dst_port,
                seq,
                flags,
                payload,
                ..
            } => {
                let opening = flags & TCP_SYN != 0 && flags & TCP_ACK == 0;
                let own = self.own.class_of(&FlowKey {
                    proto: L4::Tcp,
                    local: p.src,
                    port: src_port,
                });
                if let Some(class) = own {
                    let verdict = match (opening, up) {
                        (true, _) if gate.admits(class) => Outbound::Pass,
                        (true, _) => self.refuse(raw, &p),
                        (false, true) => Outbound::Pass,
                        (false, false) => self.drop_packet(),
                    };
                    return (verdict, Carried::default());
                }
                let id = FlowId {
                    local_port: src_port,
                    remote: SocketAddr::new(p.dst, dst_port),
                };
                if !up || (opening && gate != GateState::Open) {
                    // A reset is never answered with a reset.
                    if flags & TCP_RST != 0 {
                        return (self.drop_packet(), Carried::default());
                    }
                    return (self.refuse(raw, &p), Carried::default());
                }
                let mut tracks = self.tracks.lock();
                tracks.maybe_sweep(now);
                // A new connection needs the policy's consent, and so does every segment of a
                // connection not tracked here (one of an earlier generation, or one a new deny
                // rule ended) until it is tracked: the policy of now decides, and the reset
                // answers that very segment, so the App accepts it.
                let tracked = tracks.tcp.contains_key(&id) || tracks.tcp_opening.contains(&id);
                if (opening || !tracked) && !self.policy.allows(id.remote) {
                    drop(tracks);
                    // A reset is never answered with a reset.
                    if flags & TCP_RST != 0 {
                        return (self.drop_packet(), Carried::default());
                    }
                    return (self.refuse(raw, &p), Carried::default());
                }
                let next = seq.wrapping_add(seq_len(flags, payload));
                if !tracks.app_tcp(id, opening, flags, next, now, &self.stats) {
                    drop(tracks);
                    return (self.refuse_full(raw, &p), Carried::default());
                }
                (
                    Outbound::Pass,
                    Carried::app(payload).at(L4::Tcp, id.local_port),
                )
            }
            Transport::Udp {
                src_port,
                dst_port,
                payload,
            } => {
                let own = self.own.class_of(&FlowKey {
                    proto: L4::Udp,
                    local: p.src,
                    port: src_port,
                });
                if own.is_some() {
                    let verdict = if up {
                        Outbound::Pass
                    } else {
                        self.drop_packet()
                    };
                    return (verdict, Carried::default());
                }
                if !up {
                    return (self.refuse(raw, &p), Carried::default());
                }
                let id = FlowId {
                    local_port: src_port,
                    remote: SocketAddr::new(p.dst, dst_port),
                };
                self.outbound_udp(raw, &p, id, gate, payload, now)
            }
            Transport::Icmp { kind, .. } => (
                self.outbound_icmp(raw, &p, gate, up, kind),
                Carried::default(),
            ),
            // A later fragment is decided by its first one (`decide_outbound`).
            Transport::Fragment => (self.drop_packet(), Carried::default()),
            // Only TCP, UDP and ICMP are carried for Apps.
            Transport::Other(_) => (self.refuse(raw, &p), Carried::default()),
        }
    }

    /// Decide on an App's UDP datagram on `id` (`payload`: its payload bytes in this packet)
    /// while the tunnel is up.
    fn outbound_udp(
        &self,
        raw: &[u8],
        p: &Parsed,
        id: FlowId,
        gate: GateState,
        payload: u32,
        now: Instant,
    ) -> (Outbound, Carried) {
        let mut tracks = self.tracks.lock();
        tracks.maybe_sweep(now);
        // A tracked flow passes: the App's own, or a remote end's to a direct port that
        // the App answers (no destination policy for an answer, as for a relayed one).
        if let Some(forward) = tracks.udp_datagram(&id, true, now) {
            return (
                Outbound::Pass,
                Carried::of(payload, forward).at(L4::Udp, id.local_port),
            );
        }
        if gate != GateState::Open || !self.policy.allows(id.remote) {
            drop(tracks);
            return (self.refuse(raw, p), Carried::default());
        }
        if !tracks.make_room(L4::Udp, now, &self.stats) {
            drop(tracks);
            return (self.refuse_full(raw, p), Carried::default());
        }
        tracks.udp_unreplied.put(id, UdpTrack::app(now));
        drop(tracks);
        (
            Outbound::Pass,
            Carried::app(payload).at(L4::Udp, id.local_port),
        )
    }

    /// A datagram from the peer to `id.local_port` (`payload`: its payload bytes in this
    /// packet): a reply to the App's own flow (its first answers it), or a datagram of a remote
    /// end's flow to a direct port; no decision beyond the lookup. `None` drops it.
    fn inbound_udp(
        &self,
        id: FlowId,
        p: &Parsed,
        gate: GateState,
        payload: u32,
        now: Instant,
    ) -> Option<Carried> {
        let mut tracks = self.tracks.lock();
        if let Some(forward) = tracks.udp_datagram(&id, false, now) {
            return Some(Carried::of(payload, forward).at(L4::Udp, id.local_port));
        }
        let forward = self.direct_flow(&mut tracks, id, p, gate, now)?;
        drop(tracks);
        Some(Carried::of(payload, Some(forward)).at(L4::Udp, id.local_port))
    }

    /// Decide on an ICMP message of type `kind` the sandbox sends.
    fn outbound_icmp(
        &self,
        raw: &[u8],
        p: &Parsed,
        gate: GateState,
        up: bool,
        kind: u8,
    ) -> Outbound {
        let v6 = p.is_v6();
        if packet::icmp_is_echo_request(v6, kind) {
            if gate == GateState::Open && self.policy.allows(SocketAddr::new(p.dst, 0)) {
                Outbound::Pass
            } else {
                self.refuse(raw, p)
            }
        } else if up && (packet::icmp_is_error(v6, kind) || packet::icmp_is_echo_reply(v6, kind)) {
            // The sandbox's kernel answering what came in through the tunnel.
            Outbound::Pass
        } else {
            // Neighbour discovery, MLD, router solicitations...: nothing for a tunnel.
            self.drop_packet()
        }
    }

    /// What a later fragment from the peer carries: its first fragment said whose datagram it
    /// is, and an App's are App payload (and a direct port's forward's).
    fn later_fragment_carried(&self, p: &Parsed, now: Instant) -> Carried {
        p.fragment
            .and_then(|f| {
                let id = DatagramId::of(p, f);
                let forward = self.tracks.lock().later_fragment_in(id, f.more, now)?;
                Some(Carried {
                    app: Some(u64::from(f.bytes)),
                    forward,
                    port: None,
                })
            })
            .unwrap_or_default()
    }

    /// Decide on a decrypted packet from the peer.
    pub(crate) fn inbound(&self, raw: &[u8], now: Instant) -> Inbound {
        let (verdict, carried) = self.decide_inbound(raw, now);
        match verdict {
            Inbound::Pass => {
                self.stats.inbound_packets.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .inbound_bytes
                    .fetch_add(raw.len() as u64, Ordering::Relaxed);
                if let Some(n) = carried.app.filter(|n| *n > 0) {
                    self.stats.app_rx_bytes.fetch_add(n, Ordering::Relaxed);
                    if let Some(forward) = &carried.forward {
                        forward.received(n);
                    } else if let Some(key) = carried.port {
                        self.ports.add(key, n, 0, now);
                    }
                }
            }
            Inbound::Drop => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Inbound::Refuse(_) => {
                self.stats.refused.fetch_add(1, Ordering::Relaxed);
            }
        }
        verdict
    }

    fn decide_inbound(&self, raw: &[u8], now: Instant) -> (Inbound, Carried) {
        let Some(p) = packet::parse(raw) else {
            return (Inbound::Drop, Carried::default());
        };
        if !self.is_ours(p.dst) {
            return (Inbound::Drop, Carried::default());
        }
        let gate = self.gate.get();
        if gate == GateState::Sealed {
            return (Inbound::Drop, Carried::default());
        }
        let up = matches!(gate, GateState::Open | GateState::Probe);
        let (verdict, carried) = match p.transport {
            Transport::Tcp {
                src_port,
                dst_port,
                seq,
                flags,
                payload,
                ..
            } => {
                let opening = flags & TCP_SYN != 0 && flags & TCP_ACK == 0;
                let own = self.own.admits_inbound(
                    &FlowKey {
                        proto: L4::Tcp,
                        local: p.dst,
                        port: dst_port,
                    },
                    opening,
                );
                match own {
                    Some(OwnInbound::Pass) => return (Inbound::Pass, Carried::default()),
                    Some(OwnInbound::Drop) => return (Inbound::Drop, Carried::default()),
                    Some(OwnInbound::Closed) => {
                        let verdict =
                            packet::tcp_reset_reply(&p).map_or(Inbound::Drop, Inbound::Refuse);
                        return (verdict, Carried::default());
                    }
                    None => {}
                }
                if !up || opening {
                    return (Inbound::Drop, Carried::default());
                }
                let id = FlowId {
                    local_port: dst_port,
                    remote: SocketAddr::new(p.src, src_port),
                };
                let remote_next = seq.wrapping_add(seq_len(flags, payload));
                self.tracks.lock().remote_tcp(id, flags, remote_next, now);
                (
                    Inbound::Pass,
                    Carried::app(payload).at(L4::Tcp, id.local_port),
                )
            }
            Transport::Udp {
                src_port,
                dst_port,
                payload,
            } => {
                let own = self.own.admits_inbound(
                    &FlowKey {
                        proto: L4::Udp,
                        local: p.dst,
                        port: dst_port,
                    },
                    false,
                );
                match own {
                    Some(OwnInbound::Pass) => return (Inbound::Pass, Carried::default()),
                    Some(_) => return (Inbound::Drop, Carried::default()),
                    None => {}
                }
                if !up {
                    return (Inbound::Drop, Carried::default());
                }
                let id = FlowId {
                    local_port: dst_port,
                    remote: SocketAddr::new(p.src, src_port),
                };
                match self.inbound_udp(id, &p, gate, payload, now) {
                    Some(carried) => (Inbound::Pass, carried),
                    None => return (Inbound::Drop, Carried::default()),
                }
            }
            Transport::Icmp { kind, .. } => (inbound_icmp(&p, up, kind), Carried::default()),
            Transport::Fragment if up => {
                return (Inbound::Pass, self.later_fragment_carried(&p, now));
            }
            Transport::Fragment | Transport::Other(_) => (Inbound::Drop, Carried::default()),
        };
        if verdict == Inbound::Pass {
            self.first_fragment_in(&p, &carried, now);
        }
        (verdict, carried)
    }

    /// The first fragment of an App datagram passed: its later fragments are App payload too.
    fn first_fragment_in(&self, p: &Parsed, carried: &Carried, now: Instant) {
        if carried.app.is_some()
            && let Some(f) = p.fragment
        {
            self.tracks.lock().first_fragment_in(
                DatagramId::of(p, f),
                now,
                carried.forward.clone(),
            );
        }
    }

    /// A datagram to `id.local_port` from a remote end nobody in the sandbox sent to: a new flow,
    /// the forward's, when the port is a port forward's direct port, the forward takes new flows
    /// (its lease stands and the gate is open), it admits the source and the table has room.
    /// `None` drops the datagram; what the forward refused it counts.
    fn direct_flow(
        &self,
        tracks: &mut Tracks,
        id: FlowId,
        p: &Parsed,
        gate: GateState,
        now: Instant,
    ) -> Option<Arc<dyn DirectUdpPolicy>> {
        let port = tracks.direct.get(&id.local_port)?;
        // The sandbox's own address never comes through the tunnel.
        if self.is_ours(p.src) {
            return None;
        }
        let policy = port.policy.clone();
        if !port.open || gate != GateState::Open {
            policy.refused(p.src);
            return None;
        }
        if !policy.admit(p.src) {
            return None;
        }
        if !tracks.make_room(L4::Udp, now, &self.stats) {
            self.stats.table_full.fetch_add(1, Ordering::Relaxed);
            policy.dropped();
            return None;
        }
        tracks.udp_unreplied.put(
            id,
            UdpTrack {
                last: now,
                direct: Some(DirectFlow::new(policy.clone())),
            },
        );
        Some(policy)
    }

    /// Forget every App flow and return the resets that end the tracked TCP connections at both
    /// ends: `(into the TUN for the Apps, into the tunnel for the remote hosts)`.
    pub(crate) fn reset_app_flows(&self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let resets = self.reset_app_flows_to(&|_| true);
        (resets.to_apps, resets.to_remotes)
    }

    /// Forget the App flows whose remote address `remote` accepts (a destination a new deny
    /// rule covers) and return the resets that end those TCP connections at both ends, answered
    /// or not. A forgotten UDP flow's next datagram starts a new flow, checked against the
    /// policy again.
    pub(crate) fn reset_app_flows_to(&self, remote: &dyn Fn(IpAddr) -> bool) -> Resets {
        let tcp: Vec<(FlowId, TcpTrack)> = {
            let mut tracks = self.tracks.lock();
            tracks.udp.retain(|id, _| !remote(id.remote.ip()));
            let unreplied: Vec<FlowId> = tracks
                .udp_unreplied
                .iter()
                .filter(|(id, _)| remote(id.remote.ip()))
                .map(|(id, _)| *id)
                .collect();
            for id in &unreplied {
                tracks.udp_unreplied.pop(id);
            }
            tracks.fragmented.retain(|id, _| !remote(id.dst));
            tracks.fragments_in.retain(|id, _| !remote(id.src));
            let mut gone: Vec<(FlowId, TcpTrack)> = tracks
                .tcp
                .extract_if(|id, _| remote(id.remote.ip()))
                .collect();
            let opening: Vec<FlowId> = tracks
                .tcp_opening
                .iter()
                .filter(|(id, _)| remote(id.remote.ip()))
                .map(|(id, _)| *id)
                .collect();
            for id in opening {
                if let Some(t) = tracks.tcp_opening.pop(&id) {
                    gone.push((id, t));
                }
            }
            gone
        };
        let mut resets = Resets {
            to_apps: Vec::with_capacity(tcp.len()),
            to_remotes: Vec::with_capacity(tcp.len()),
            connections: tcp.len(),
        };
        for (id, t) in tcp {
            let Some(ours) = self.ours_for(id.remote.ip()) else {
                continue;
            };
            let local = SocketAddr::new(ours, id.local_port);
            // Exactly the next expected sequence number resets an established connection; one
            // still waiting for its SYN-ACK is reset by an acceptable ACK.
            let seq = t.remote_next.unwrap_or(0);
            let to_app = packet::tcp_reset(id.remote, local, seq, Some(t.app_next));
            resets.to_apps.extend(to_app);
            resets
                .to_remotes
                .extend(packet::tcp_reset(local, id.remote, t.app_next, None));
        }
        resets
    }

    /// The App payload per local port of the sandbox, cumulative per port (see [`PortCounts`]).
    pub(crate) fn port_payload(&self, now: Instant) -> Vec<PortPayload> {
        self.ports.snapshot(now)
    }

    /// App flows currently tracked: `(tcp, udp)`.
    pub(crate) fn app_flows(&self) -> (usize, usize) {
        let tracks = self.tracks.lock();
        (
            tracks.tcp.len() + tracks.tcp_opening.len(),
            tracks.udp.len() + tracks.udp_unreplied.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::packet::tests::{icmp_echo, tcp, udp, v4_fragment, v6_fragment};
    use super::*;
    use crate::netstack::FlowClass;
    use std::assert_matches;

    struct Deny(Vec<IpAddr>);

    impl DestinationCheck for Deny {
        fn allows(&self, dst: SocketAddr) -> bool {
            !self.0.contains(&dst.ip())
        }
    }

    fn filter(gate: GateState) -> (PacketFilter, Arc<Gate>, OwnFlows) {
        let g = Arc::new(Gate::default());
        g.set(gate);
        let own = OwnFlows::default();
        let f = PacketFilter::new(
            g.clone(),
            own.clone(),
            Arc::new(Deny(vec![
                "192.0.2.1".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ])),
            Some("10.99.0.2".parse().unwrap()),
            Some("fd99::2".parse().unwrap()),
        );
        (f, g, own)
    }

    fn is_reset(out: &Outbound) -> bool {
        let Outbound::Refuse(p) = out else {
            return false;
        };
        matches!(
            packet::parse(p).unwrap().transport,
            Transport::Tcp { flags, .. } if flags & TCP_RST != 0
        )
    }

    fn is_prohibited(out: &Outbound) -> bool {
        let Outbound::Refuse(p) = out else {
            return false;
        };
        matches!(
            packet::parse(p).unwrap().transport,
            Transport::Icmp { kind: 3, code: 13 } | Transport::Icmp { kind: 1, code: 1 }
        )
    }

    #[test]
    fn open_gate_admits_app_flows_the_policy_allows() {
        let (f, _, _) = filter(GateState::Open);
        let now = Instant::now();
        let syn = tcp("10.99.0.2:40000", "10.99.0.1:80", 1, 0, TCP_SYN, &[]);
        assert_eq!(f.outbound(&syn, now), Outbound::Pass);
        let denied = tcp("10.99.0.2:40001", "192.0.2.1:80", 1, 0, TCP_SYN, &[]);
        assert!(is_reset(&f.outbound(&denied, now)), "policy refusal");
        let dgram = udp("10.99.0.2:5000", "192.0.2.1:53", b"q");
        assert!(is_prohibited(&f.outbound(&dgram, now)));
        let ping = icmp_echo("fd99::2", "2606:4700::1111");
        assert_eq!(f.outbound(&ping, now), Outbound::Pass);
        let ping = icmp_echo("10.99.0.2", "192.0.2.1");
        assert!(is_prohibited(&f.outbound(&ping, now)));
        // SCTP and friends are not carried.
        let mut sctp = udp("10.99.0.2:5000", "10.99.0.1:5000", b"x");
        sctp[9] = 132;
        assert!(is_prohibited(&f.outbound(&sctp, now)));
    }

    #[test]
    fn spoofed_sources_and_special_destinations_are_dropped() {
        let (f, _, _) = filter(GateState::Open);
        let now = Instant::now();
        let spoofed = tcp("10.99.0.3:40000", "10.99.0.1:80", 1, 0, TCP_SYN, &[]);
        assert_eq!(f.outbound(&spoofed, now), Outbound::Drop);
        let multicast = udp("10.99.0.2:5353", "224.0.0.251:5353", b"mdns");
        assert_eq!(f.outbound(&multicast, now), Outbound::Drop);
        let link_local = udp("[fd99::2]:5353", "[fe80::1]:53", b"q");
        assert_eq!(f.outbound(&link_local, now), Outbound::Drop);
        assert_eq!(f.outbound(b"garbage", now), Outbound::Drop);
        assert_eq!(f.stats.dropped.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn probe_keeps_existing_flows_and_refuses_new_ones() {
        let (f, gate, _) = filter(GateState::Open);
        let now = Instant::now();
        let first = udp("10.99.0.2:5000", "10.99.0.1:53", b"q");
        assert_eq!(f.outbound(&first, now), Outbound::Pass);
        gate.set(GateState::Probe);
        assert_eq!(f.outbound(&first, now), Outbound::Pass, "known UDP flow");
        let new_udp = udp("10.99.0.2:5001", "10.99.0.1:53", b"q");
        assert!(is_prohibited(&f.outbound(&new_udp, now)));
        let data = tcp("10.99.0.2:40000", "10.99.0.1:80", 7, 9, TCP_ACK, b"x");
        assert_eq!(f.outbound(&data, now), Outbound::Pass, "established TCP");
        let syn = tcp("10.99.0.2:40002", "10.99.0.1:80", 1, 0, TCP_SYN, &[]);
        assert!(is_reset(&f.outbound(&syn, now)));
    }

    #[test]
    fn closed_and_sealed_refuse_every_app_packet() {
        for state in [GateState::Closed, GateState::Sealed] {
            let (f, _, _) = filter(state);
            let now = Instant::now();
            let data = tcp("10.99.0.2:40000", "10.99.0.1:80", 7, 9, TCP_ACK, b"x");
            assert!(is_reset(&f.outbound(&data, now)), "{state:?}");
            let rst = tcp("10.99.0.2:40000", "10.99.0.1:80", 7, 9, TCP_RST, &[]);
            assert_eq!(
                f.outbound(&rst, now),
                Outbound::Drop,
                "a reset is not answered"
            );
            let dgram = udp("10.99.0.2:5000", "10.99.0.1:53", b"q");
            assert!(is_prohibited(&f.outbound(&dgram, now)), "{state:?}");
        }
    }

    #[test]
    fn own_sockets_follow_their_class_and_skip_the_policy() {
        let (f, gate, own) = filter(GateState::Probe);
        let now = Instant::now();
        let local: IpAddr = "10.99.0.2".parse().unwrap();
        let _dns = own.register(
            vec![FlowKey {
                proto: L4::Udp,
                local,
                port: 6000,
            }],
            FlowClass::Control,
        );
        let _dial = own.register(
            vec![FlowKey {
                proto: L4::Tcp,
                local,
                port: 6001,
            }],
            FlowClass::Payload,
        );
        // A DNS probe to a resolver the payload policy would refuse still goes out in probe.
        let probe = udp("10.99.0.2:6000", "192.0.2.1:53", b"q");
        assert_eq!(f.outbound(&probe, now), Outbound::Pass);
        let reply = udp("192.0.2.1:53", "10.99.0.2:6000", b"a");
        assert_eq!(f.inbound(&reply, now), Inbound::Pass);
        // A payload dial waits for the open gate.
        let syn = tcp("10.99.0.2:6001", "10.99.0.1:80", 1, 0, TCP_SYN, &[]);
        assert!(is_reset(&f.outbound(&syn, now)));
        gate.set(GateState::Open);
        assert_eq!(f.outbound(&syn, now), Outbound::Pass);
        // Nothing of ours leaves once sealed.
        gate.set(GateState::Sealed);
        assert_eq!(f.outbound(&probe, now), Outbound::Drop);
    }

    #[test]
    fn a_forwarded_port_takes_connections_only_while_it_listens() {
        let (f, _, own) = filter(GateState::Open);
        let now = Instant::now();
        let local: IpAddr = "10.99.0.2".parse().unwrap();
        let keys = vec![
            FlowKey {
                proto: L4::Tcp,
                local,
                port: 51234,
            },
            FlowKey {
                proto: L4::Udp,
                local,
                port: 51234,
            },
        ];
        let syn = tcp("198.51.100.9:6000", "10.99.0.2:51234", 1, 0, TCP_SYN, &[]);
        let ack = tcp("198.51.100.9:6000", "10.99.0.2:51234", 2, 9, TCP_ACK, b"x");
        let dgram = udp("198.51.100.9:6000", "10.99.0.2:51234", b"hello");
        assert_eq!(f.inbound(&syn, now), Inbound::Drop, "not reserved");
        let held = own.reserve(keys.clone());
        // Reserved, nothing listening: refused like a closed port, nothing reaches the socket.
        let refused = |out: Inbound| {
            let Inbound::Refuse(reply) = out else {
                return false;
            };
            let p = packet::parse(&reply).unwrap();
            p.dst == "198.51.100.9".parse::<IpAddr>().unwrap()
                && matches!(
                    p.transport,
                    Transport::Tcp { src_port: 51234, dst_port: 6000, ack: 2, flags, .. }
                        if flags == TCP_RST | TCP_ACK
                )
        };
        assert!(refused(f.inbound(&syn, now)));
        assert_eq!(f.inbound(&dgram, now), Inbound::Drop);
        let listening = own.listen(keys);
        assert_eq!(f.inbound(&syn, now), Inbound::Pass);
        assert_eq!(f.inbound(&dgram, now), Inbound::Pass);
        // The worker's answers go out while the gate is up, as its own payload.
        let syn_ack = tcp(
            "10.99.0.2:51234",
            "198.51.100.9:6000",
            9,
            2,
            TCP_SYN | TCP_ACK,
            &[],
        );
        assert_eq!(f.outbound(&syn_ack, now), Outbound::Pass);
        let reply = udp("10.99.0.2:51234", "198.51.100.9:6000", b"hi");
        assert_eq!(f.outbound(&reply, now), Outbound::Pass);
        // Listening stops: established connections go on, nothing new comes in.
        drop(listening);
        assert!(refused(f.inbound(&syn, now)));
        assert_eq!(f.inbound(&ack, now), Inbound::Pass);
        assert_eq!(f.inbound(&dgram, now), Inbound::Drop);
        drop(held);
        assert_eq!(f.inbound(&syn, now), Inbound::Drop, "released");
        assert_eq!(f.inbound(&dgram, now), Inbound::Drop);
    }

    #[test]
    fn nothing_unsolicited_comes_in() {
        let (f, _, _) = filter(GateState::Open);
        let now = Instant::now();
        let syn_in = tcp("10.99.0.1:5555", "10.99.0.2:22", 1, 0, TCP_SYN, &[]);
        assert_eq!(f.inbound(&syn_in, now), Inbound::Drop);
        let stray = udp("10.99.0.1:53", "10.99.0.2:5000", b"a");
        assert_eq!(f.inbound(&stray, now), Inbound::Drop);
        // The reply to an App's own datagram comes in.
        let out = udp("10.99.0.2:5000", "10.99.0.1:53", b"q");
        assert_eq!(f.outbound(&out, now), Outbound::Pass);
        assert_eq!(f.inbound(&stray, now), Inbound::Pass);
        // Not addressed to the sandbox.
        let elsewhere = udp("10.99.0.1:53", "10.99.0.9:5000", b"a");
        assert_eq!(f.inbound(&elsewhere, now), Inbound::Drop);
        let echo_request = icmp_echo("10.99.0.1", "10.99.0.2");
        assert_eq!(f.inbound(&echo_request, now), Inbound::Drop);
    }

    /// A deny list that changes while flows run (a blocklist overlay, a ban).
    struct Changing(Mutex<Vec<IpAddr>>);

    impl DestinationCheck for Changing {
        fn allows(&self, dst: SocketAddr) -> bool {
            !self.0.lock().contains(&dst.ip())
        }
    }

    #[test]
    fn flows_to_a_newly_denied_destination_end_and_the_others_continue() {
        let gate = Arc::new(Gate::default());
        gate.set(GateState::Open);
        let policy = Arc::new(Changing(Mutex::new(Vec::new())));
        let f = PacketFilter::new(
            gate,
            OwnFlows::default(),
            policy.clone(),
            Some("10.99.0.2".parse().unwrap()),
            None,
        );
        let now = Instant::now();
        let denied: IpAddr = "198.51.100.7".parse().unwrap();
        let syn = tcp("10.99.0.2:40000", "198.51.100.7:443", 100, 0, TCP_SYN, &[]);
        assert_eq!(f.outbound(&syn, now), Outbound::Pass);
        let syn_ack = tcp(
            "198.51.100.7:443",
            "10.99.0.2:40000",
            5000,
            101,
            TCP_SYN | TCP_ACK,
            &[],
        );
        assert_eq!(f.inbound(&syn_ack, now), Inbound::Pass);
        let other = tcp("10.99.0.2:40001", "10.99.0.1:80", 1, 0, TCP_SYN, &[]);
        assert_eq!(f.outbound(&other, now), Outbound::Pass);
        let dgram = udp("10.99.0.2:5000", "198.51.100.7:53", b"q");
        assert_eq!(f.outbound(&dgram, now), Outbound::Pass);
        assert_eq!(f.app_flows(), (2, 1));

        // A new rule covers 198.51.100.7: its connection ends at both ends, the other stays.
        policy.0.lock().push(denied);
        let resets = f.reset_app_flows_to(&|ip| ip == denied);
        assert_eq!(resets.connections, 1);
        assert_eq!((resets.to_apps.len(), resets.to_remotes.len()), (1, 1));
        let app = packet::parse(&resets.to_apps[0]).unwrap();
        assert_eq!(app.src, denied);
        assert_matches!(
            app.transport,
            Transport::Tcp {
                src_port: 443,
                dst_port: 40000,
                seq: 5001,
                ..
            }
        );
        assert_eq!(f.app_flows(), (1, 0));
        // Its UDP flow is forgotten: the next datagram is a new flow, checked again.
        assert!(is_prohibited(&f.outbound(&dgram, now)));
        let data = tcp("10.99.0.2:40001", "10.99.0.1:80", 2, 9, TCP_ACK, b"x");
        assert_eq!(f.outbound(&data, now), Outbound::Pass);
        // The App had not taken the reset yet: its retransmission and its next segment are
        // refused as well, each with a reset from that segment's own ACK, so the App accepts
        // it. The connection is not taken up again.
        for (seq, flags) in [(101, TCP_ACK), (101, TCP_ACK), (106, TCP_ACK | TCP_FIN)] {
            let late = tcp(
                "10.99.0.2:40000",
                "198.51.100.7:443",
                seq,
                5001,
                flags,
                b"GET /",
            );
            let Outbound::Refuse(reply) = f.outbound(&late, now) else {
                panic!("segment {seq} of an ended connection passed");
            };
            let reply = packet::parse(&reply).unwrap();
            assert_eq!(reply.src, denied);
            assert_matches!(
                reply.transport,
                Transport::Tcp {
                    src_port: 443,
                    dst_port: 40000,
                    seq: 5001,
                    flags: TCP_RST,
                    ..
                }
            );
        }
        assert_eq!(f.app_flows(), (1, 0));
    }

    #[test]
    fn untracked_segments_need_the_policy_of_now() {
        // A filter of a new generation tracks nothing; connections of the last one go on.
        let (f, _, _) = filter(GateState::Probe);
        let now = Instant::now();
        let carried = tcp("10.99.0.2:40000", "10.99.0.1:80", 7, 9, TCP_ACK, b"x");
        assert_eq!(f.outbound(&carried, now), Outbound::Pass);
        assert_eq!(f.app_flows(), (1, 0), "tracked from now on");
        // One to a destination the policy refuses is refused, segment after segment.
        for denied in [
            tcp(
                "10.99.0.2:40001",
                "192.0.2.1:443",
                700,
                9000,
                TCP_ACK,
                b"more",
            ),
            tcp(
                "10.99.0.2:40001",
                "192.0.2.1:443",
                700,
                9000,
                TCP_ACK,
                b"more",
            ),
            tcp(
                "[fd99::2]:40002",
                "[2001:db8::1]:443",
                1,
                9000,
                TCP_ACK | TCP_FIN,
                &[],
            ),
        ] {
            let Outbound::Refuse(reply) = f.outbound(&denied, now) else {
                panic!("an untracked segment to a refused destination passed");
            };
            assert_matches!(
                packet::parse(&reply).unwrap().transport,
                Transport::Tcp {
                    seq: 9000,
                    flags: TCP_RST,
                    ..
                }
            );
        }
        // A reset to it is not answered, and does not go out either.
        let rst = tcp("10.99.0.2:40001", "192.0.2.1:443", 704, 0, TCP_RST, &[]);
        assert_eq!(f.outbound(&rst, now), Outbound::Drop);
        assert_eq!(f.app_flows(), (1, 0));
        assert_eq!(f.stats.refused.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn later_fragments_go_only_where_their_first_went() {
        let (f, gate, _) = filter(GateState::Open);
        let now = Instant::now();
        // An 8 KB datagram to a refused destination: the first fragment is refused, and the
        // rest never reach the tunnel.
        let denied = udp("10.99.0.2:5000", "192.0.2.1:53", &[0u8; 1400]);
        assert!(is_prohibited(
            &f.outbound(&v4_fragment(denied.clone(), 7, 0, true), now)
        ));
        for (offset, more) in [(185, true), (370, true), (555, true), (740, false)] {
            let later = v4_fragment(denied.clone(), 7, offset, more);
            assert_eq!(f.outbound(&later, now), Outbound::Drop, "offset {offset}");
        }
        // To an allowed one they all go out; the last fragment ends the datagram.
        let ok = udp("10.99.0.2:5000", "10.99.0.1:53", &[0u8; 1400]);
        let frag = |id, offset, more| v4_fragment(ok.clone(), id, offset, more);
        assert_eq!(f.outbound(&frag(8, 0, true), now), Outbound::Pass);
        assert_eq!(f.outbound(&frag(8, 185, true), now), Outbound::Pass);
        assert_eq!(f.outbound(&frag(8, 370, false), now), Outbound::Pass);
        assert_eq!(f.outbound(&frag(8, 370, false), now), Outbound::Drop);
        // Before (or without) its first fragment; of another destination or protocol.
        assert_eq!(f.outbound(&frag(9, 185, true), now), Outbound::Drop);
        assert_eq!(f.outbound(&frag(9, 0, true), now), Outbound::Pass);
        let elsewhere = udp("10.99.0.2:5000", "10.99.0.3:53", &[0u8; 1400]);
        let elsewhere = v4_fragment(elsewhere, 9, 185, true);
        assert_eq!(f.outbound(&elsewhere, now), Outbound::Drop);
        let mut other_proto = frag(9, 185, true);
        other_proto[9] = packet::PROTO_TCP;
        assert_eq!(f.outbound(&other_proto, now), Outbound::Drop);
        // Only shortly after the first.
        let soon = (now + FRAGMENT_TIMEOUT)
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        assert_eq!(f.outbound(&frag(9, 185, true), soon), Outbound::Pass);
        let late = now + FRAGMENT_TIMEOUT;
        assert_eq!(f.outbound(&frag(9, 370, true), late), Outbound::Drop);
        // Nothing follows while the gate is closed.
        assert_eq!(f.outbound(&frag(10, 0, true), now), Outbound::Pass);
        gate.set(GateState::Closed);
        assert_eq!(f.outbound(&frag(10, 185, true), now), Outbound::Drop);
    }

    #[test]
    fn ipv6_later_fragments_go_only_where_their_first_went() {
        let (f, _, _) = filter(GateState::Open);
        let now = Instant::now();
        let denied = udp("[fd99::2]:5000", "[2001:db8::1]:53", &[0u8; 1400]);
        let first = v6_fragment(&denied, 0xdead_beef, 0, true);
        assert!(is_prohibited(&f.outbound(&first, now)));
        let rest = v6_fragment(&denied, 0xdead_beef, 175, false);
        assert_eq!(f.outbound(&rest, now), Outbound::Drop);
        let ok = udp("[fd99::2]:5000", "[2606:4700::1111]:53", &[0u8; 1400]);
        assert_eq!(
            f.outbound(&v6_fragment(&ok, 1, 0, true), now),
            Outbound::Pass
        );
        assert_eq!(
            f.outbound(&v6_fragment(&ok, 1, 175, false), now),
            Outbound::Pass
        );
        let orphan = v6_fragment(&ok, 2, 175, false);
        assert_eq!(f.outbound(&orphan, now), Outbound::Drop);
    }

    #[test]
    fn followed_datagrams_are_bounded_and_end_with_a_deny_rule() {
        let (f, _, _) = filter(GateState::Open);
        let now = Instant::now();
        let ok = udp("10.99.0.2:5000", "10.99.0.1:53", &[0u8; 64]);
        let followed = u16::try_from(FRAGMENTED).unwrap();
        for id in 0..followed {
            let first = v4_fragment(ok.clone(), id, 0, true);
            assert_eq!(f.outbound(&first, now), Outbound::Pass);
        }
        let one_more = v4_fragment(ok.clone(), followed, 0, true);
        assert_eq!(f.outbound(&one_more, now), Outbound::Drop, "full");
        // Once their time is up there is room again.
        let later = now + FRAGMENT_TIMEOUT;
        assert_eq!(f.outbound(&one_more, later), Outbound::Pass);
        // A rule that ends the flows to a destination ends its datagrams too.
        let dst: IpAddr = "10.99.0.1".parse().unwrap();
        f.reset_app_flows_to(&|ip| ip == dst);
        let rest = v4_fragment(ok, followed, 8, false);
        assert_eq!(f.outbound(&rest, later), Outbound::Drop);
    }

    /// Trigger the periodic sweep at `t` with a datagram of a flow of its own (port `port`).
    fn sweep_at(f: &PacketFilter, port: u16, t: Instant) {
        let poke = udp(&format!("10.99.0.2:{port}"), "10.99.0.1:9", b"poke");
        assert_eq!(f.outbound(&poke, t), Outbound::Pass);
    }

    /// A port forward's decisions about its direct UDP port, for tests: it refuses the sources
    /// it lists and counts what the filter tells it.
    #[derive(Default)]
    struct Forward {
        deny: Mutex<Vec<IpAddr>>,
        /// Sources it was asked about while open, and those it heard of while closed.
        asked: Mutex<Vec<IpAddr>>,
        refused: Mutex<Vec<IpAddr>>,
        started: AtomicU64,
        ended: AtomicU64,
        received: AtomicU64,
        sent: AtomicU64,
        dropped: AtomicU64,
    }

    impl DirectUdpPolicy for Forward {
        fn admit(&self, source: IpAddr) -> bool {
            self.asked.lock().push(source);
            !self.deny.lock().contains(&source)
        }

        fn refused(&self, source: IpAddr) {
            self.refused.lock().push(source);
        }

        fn started(&self) {
            self.started.fetch_add(1, Ordering::Relaxed);
        }

        fn ended(&self) {
            self.ended.fetch_add(1, Ordering::Relaxed);
        }

        fn received(&self, bytes: u64) {
            self.received.fetch_add(bytes, Ordering::Relaxed);
        }

        fn sent(&self, bytes: u64) {
            self.sent.fetch_add(bytes, Ordering::Relaxed);
        }

        fn dropped(&self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl Forward {
        fn get(c: &AtomicU64) -> u64 {
            c.load(Ordering::Relaxed)
        }

        /// Flows it holds now.
        fn active(&self) -> u64 {
            Self::get(&self.started) - Self::get(&self.ended)
        }

        fn asked(&self) -> usize {
            self.asked.lock().len()
        }

        fn refused(&self) -> usize {
            self.refused.lock().len()
        }
    }

    /// A filter with a forward's direct UDP port 24680 registered (not open yet).
    fn direct(gate: GateState) -> (PacketFilter, Arc<Gate>, Arc<Forward>, DirectUdpPort) {
        let (f, g, _) = filter(gate);
        let forward = Arc::new(Forward::default());
        let port = f.direct_ports().register(24680, forward.clone()).unwrap();
        (f, g, forward, port)
    }

    #[test]
    fn a_remote_end_comes_in_to_a_direct_port_only_while_it_is_open_and_admitted() {
        let (f, _, forward, ()) = filter_with_unregistered_port();
        let now = Instant::now();
        let from_a = udp("198.51.100.9:6000", "10.99.0.2:24680", b"hello");
        // Not a forward's port: unsolicited, as ever.
        assert_eq!(f.inbound(&from_a, now), Inbound::Drop);
        let port = f.direct_ports().register(24680, forward.clone()).unwrap();
        // The forward's port, but its lease does not stand: dropped, and the forward hears of it.
        assert_eq!(f.inbound(&from_a, now), Inbound::Drop);
        assert_eq!(forward.refused(), 1);
        assert_eq!(forward.asked(), 0);
        assert_eq!(f.app_flows(), (0, 0));

        let open = port.open();
        // Admitted: in as it came, a flow of the forward's, its payload counted for it.
        assert_eq!(f.inbound(&from_a, now), Inbound::Pass);
        assert_eq!(
            *forward.asked.lock(),
            ["198.51.100.9".parse::<IpAddr>().unwrap()]
        );
        assert_eq!((forward.active(), Forward::get(&forward.received)), (1, 5));
        assert_eq!(f.app_flows(), (0, 1));
        // The flow's next datagram needs no decision.
        assert_eq!(f.inbound(&from_a, now), Inbound::Pass);
        assert_eq!((forward.asked(), Forward::get(&forward.received)), (1, 10));
        // The App answers from the port: it goes out like any tracked flow (no destination
        // policy for an answer), counted for the forward, and the flow is answered from now on.
        let answer = udp("10.99.0.2:24680", "198.51.100.9:6000", b"hi there");
        assert_eq!(f.outbound(&answer, now), Outbound::Pass);
        assert_eq!(Forward::get(&forward.sent), 8);
        assert_eq!(f.tracks.lock().udp.len(), 1, "answered");
        // Both count as the Apps' payload too.
        assert_eq!(f.stats.app_rx_bytes.load(Ordering::Relaxed), 10);
        assert_eq!(f.stats.app_tx_bytes.load(Ordering::Relaxed), 8);

        // Another port of the sandbox is not the forward's: dropped, nobody asked.
        let elsewhere = udp("198.51.100.9:6000", "10.99.0.2:27781", b"hello");
        assert_eq!(f.inbound(&elsewhere, now), Inbound::Drop);
        // A source the forward refuses (its blocklists, bans, auto-ban, flow limit) stays out.
        forward.deny.lock().push("203.0.113.5".parse().unwrap());
        let refused = udp("203.0.113.5:7000", "10.99.0.2:24680", b"hello");
        assert_eq!(f.inbound(&refused, now), Inbound::Drop);
        assert_eq!(f.inbound(&refused, now), Inbound::Drop, "asked again");
        assert_eq!((forward.asked(), forward.active()), (3, 1));
        // The sandbox's own address never comes through the tunnel.
        let spoofed = udp("10.99.0.2:7000", "10.99.0.2:24680", b"hello");
        assert_eq!(f.inbound(&spoofed, now), Inbound::Drop);
        assert_eq!(forward.asked(), 3);
        // Over IPv6 likewise, the same port.
        let v6 = udp("[2606:4700::1111]:6000", "[fd99::2]:24680", b"hello6");
        assert_eq!(f.inbound(&v6, now), Inbound::Pass);
        assert_eq!(forward.active(), 2);
        assert_eq!(Forward::get(&forward.dropped), 0);
        assert_eq!(forward.refused(), 1);

        // The lease ends: its flows are forgotten at once, and their datagrams are unsolicited
        // again (the forward hears of them, closed).
        drop(open);
        assert_eq!(forward.active(), 0);
        assert_eq!(f.app_flows(), (0, 0));
        assert_eq!(f.inbound(&from_a, now), Inbound::Drop);
        assert_eq!(forward.refused(), 2);
        assert_eq!(
            f.outbound(&answer, now),
            Outbound::Pass,
            "the App may still send"
        );
        assert_eq!(
            Forward::get(&forward.sent),
            8,
            "but that is its own flow now"
        );
        // The port given up: nothing for the forward any more.
        drop(port);
        let from_b = udp("198.51.100.10:6000", "10.99.0.2:24680", b"hello");
        assert_eq!(f.inbound(&from_b, now), Inbound::Drop);
        assert_eq!((forward.refused(), forward.asked()), (2, 4));
    }

    /// A filter whose port 24680 is no forward's yet.
    fn filter_with_unregistered_port() -> (PacketFilter, Arc<Gate>, Arc<Forward>, ()) {
        let (f, g, _) = filter(GateState::Open);
        (f, g, Arc::new(Forward::default()), ())
    }

    #[test]
    fn a_tightened_gate_keeps_a_direct_ports_flows_and_takes_no_new_ones() {
        let (f, gate, forward, port) = direct(GateState::Open);
        let _open = port.open();
        let now = Instant::now();
        let from_a = udp("198.51.100.9:6000", "10.99.0.2:24680", b"a");
        let to_a = udp("10.99.0.2:24680", "198.51.100.9:6000", b"b");
        let from_b = udp("198.51.100.10:6000", "10.99.0.2:24680", b"c");
        assert_eq!(f.inbound(&from_a, now), Inbound::Pass);
        gate.set(GateState::Probe);
        // The flow goes on both ways; a new remote end is turned away and the forward hears of it.
        assert_eq!(f.inbound(&from_a, now), Inbound::Pass);
        assert_eq!(f.outbound(&to_a, now), Outbound::Pass);
        assert_eq!(f.inbound(&from_b, now), Inbound::Drop);
        assert_eq!(
            *forward.refused.lock(),
            ["198.51.100.10".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(forward.asked(), 1);
        // Back open: new remote ends come in again.
        gate.set(GateState::Open);
        assert_eq!(f.inbound(&from_b, now), Inbound::Pass);
        assert_eq!(forward.active(), 2);
        // Closed and sealed, nothing comes in.
        for state in [GateState::Closed, GateState::Sealed] {
            gate.set(state);
            assert_eq!(f.inbound(&from_a, now), Inbound::Drop, "{state:?}");
        }
    }

    #[test]
    fn a_direct_ports_flows_last_as_their_state_warrants_and_end_with_a_deny_rule() {
        let (f, _, forward, port) = direct(GateState::Open);
        let _open = port.open();
        let t0 = Instant::now();
        let from_a = udp("198.51.100.9:6000", "10.99.0.2:24680", b"a");
        let from_b = udp("198.51.100.10:6000", "10.99.0.2:24680", b"b");
        let to_b = udp("10.99.0.2:24680", "198.51.100.10:6000", b"c");
        // A is never answered by the App; B is.
        assert_eq!(f.inbound(&from_a, t0), Inbound::Pass);
        assert_eq!(f.inbound(&from_b, t0), Inbound::Pass);
        assert_eq!(f.outbound(&to_b, t0), Outbound::Pass);
        // Unanswered, A goes 30 s after its last datagram (B's answered flow stays).
        let t1 = t0 + UDP_UNREPLIED + SWEEP_INTERVAL;
        sweep_at(&f, 7000, t1);
        assert_eq!(forward.active(), 1);
        // Its remote end's next datagram is a new flow, decided again.
        assert_eq!(f.inbound(&from_a, t1), Inbound::Pass);
        assert_eq!(forward.asked(), 3);
        // Answered, B lasts two minutes after its last datagram (A's second flow, unanswered
        // again, does not).
        let t2 = (t0 + UDP_IDLE)
            .checked_sub(Duration::from_secs(10))
            .unwrap();
        sweep_at(&f, 7001, t2);
        assert_eq!(forward.active(), 1);
        assert_eq!(f.inbound(&from_b, t2), Inbound::Pass);
        assert_eq!(forward.asked(), 3, "still B's flow");
        let t3 = t0 + UDP_IDLE + SWEEP_INTERVAL;
        sweep_at(&f, 7002, t3);
        assert_eq!(forward.active(), 1, "B's datagram at t2 kept it");

        // A new deny rule covering A (a ban, a blocklist): its flow ends, B's stays; A's next
        // datagram is decided again — and refused.
        assert_eq!(f.inbound(&from_a, t3), Inbound::Pass);
        assert_eq!(forward.active(), 2);
        let a: IpAddr = "198.51.100.9".parse().unwrap();
        forward.deny.lock().push(a);
        f.reset_app_flows_to(&|ip| ip == a);
        assert_eq!(forward.active(), 1);
        assert_eq!(f.inbound(&from_a, t3), Inbound::Drop);
        assert_eq!(forward.asked(), 5);
        assert_eq!(f.inbound(&from_b, t3), Inbound::Pass);
        // The generation ends: every flow goes.
        f.reset_app_flows();
        assert_eq!(forward.active(), 0);
        assert_eq!(f.app_flows(), (0, 0));
    }

    #[test]
    fn the_apps_own_flows_from_a_direct_port_are_its_own() {
        let (f, _, forward, port) = direct(GateState::Open);
        let open = port.open();
        let now = Instant::now();
        // The App asks a peer from its forwarded port (Kad does): an ordinary App flow, under the
        // destination policy...
        let ask = udp("10.99.0.2:24680", "198.51.100.9:4672", b"query");
        assert_eq!(f.outbound(&ask, now), Outbound::Pass);
        let denied = udp("10.99.0.2:24680", "192.0.2.1:4672", b"query");
        assert!(is_prohibited(&f.outbound(&denied, now)));
        // ...whose answer comes in as a reply, without the forward.
        let answer = udp("198.51.100.9:4672", "10.99.0.2:24680", b"answer");
        assert_eq!(f.inbound(&answer, now), Inbound::Pass);
        assert_eq!(
            (forward.asked(), forward.refused(), forward.active()),
            (0, 0, 0)
        );
        assert_eq!(Forward::get(&forward.received), 0);
        assert_eq!(f.stats.app_rx_bytes.load(Ordering::Relaxed), 6);
        // The forward's lease ending leaves it alone.
        drop(open);
        assert_eq!(f.app_flows(), (0, 1));
        assert_eq!(f.inbound(&answer, now), Inbound::Pass);
    }

    #[test]
    fn a_direct_port_is_one_forwards_and_a_stale_lease_never_closes_the_next() {
        let (f, _, first, port) = direct(GateState::Open);
        let again = f
            .direct_ports()
            .register(24680, Arc::new(Forward::default()));
        assert_eq!(
            again.err().map(|e| e.kind()),
            Some(io::ErrorKind::AddrInUse)
        );
        assert!(f.direct_ports().register(0, first.clone()).is_err());
        // The forward changes: its old registration goes, a new one takes the port; the old
        // lease's guard, dropped late, leaves the new registration open.
        let stale = port.open();
        drop(port);
        let second = Arc::new(Forward::default());
        let port = f.direct_ports().register(24680, second.clone()).unwrap();
        assert_eq!(port.port(), 24680);
        let _open = port.open();
        drop(stale);
        let now = Instant::now();
        let from_a = udp("198.51.100.9:6000", "10.99.0.2:24680", b"a");
        assert_eq!(f.inbound(&from_a, now), Inbound::Pass);
        assert_eq!((first.asked(), second.asked(), second.active()), (0, 1, 1));
    }
}
