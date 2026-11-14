//! Instance Manager <-> Instance worker protocol (one private socketpair per worker).
//!
//! Only the Instance Manager speaks this protocol; no other process holds the worker's control
//! socket. The sequence is fixed:
//!
//! ```text
//! M: Hello            W: Hello            (protocol + build id must match, else both close)
//! M: Configure(+fds)  W: Configured       (worker holds the per-key lock before replying)
//! M: Start            W: TunnelUp, Probe  (gate = probe: control flows only)
//! M: Activate(permit) W: Ready(permit)    (the only way the payload gate opens)
//! ... W: Status every second, Degraded/Recovered/Fatal as they happen
//! ... M: AddGateway(+fd) when a Gateway that could not be bound at start becomes bindable
//! ... M: SetOverlay   W: OverlayApplied (its own digest) | OverlayRejected
//! ... W: Banned (auto-ban)            M: Unban   W: Unbanned
//! ... M: SetBandwidth W: BandwidthApplied (the caps it now enforces)
//! ... M: SetTransport (Status names the transport it describes by its serial)
//! ... W: RelayRequest  M: Relay(+fd)   (strict mode: a SOCKS5 UDP relay socket on host loopback)
//! ... M: SetForwards (bindings of the generation; their tunnel ports are reserved)
//! ... M: GrantForward(lease) / RevokeForward  (Status reports what each forward does)
//! M: Stop             W: Stopped, exit
//! ```
//!
//! The initial blocklist overlay travels in `Configure`, so it is in force before the gate can
//! open; the worker reports `OverlayApplied` for it right after `Configured`.
//!
//! A port forward listens only while the manager's lease for it stands and the gate is open: the
//! lease names the loopback address the forward's App holds, which is the only host address the
//! worker ever connects to. A revoked lease closes the forward's connections at once.
//!
//! A worker exits immediately when the socket reaches EOF (manager gone): fail closed.
//!
//! A strict-mode worker (Linux) runs inside its Instance's sandbox network namespace; its
//! `Configure` carries the sandbox's descriptors after the Gateway listeners (see
//! [`StrictWire`]), and host-loopback sockets it needs later (SOCKS5 UDP relays) come from the
//! manager, since its own loopback is the sandbox's.

use std::net::{IpAddr, SocketAddr};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use vpn_domain::ipset::IpRangeSet;
use vpn_domain::{
    AppId, AutoBanSettings, BandwidthCaps, CongestionStatus, DnsCacheSettings, DnsOnFailure,
    DnsServer, ForwardBindingId, ForwardProtocol, GatewayId, GatewayKind, InstanceId,
    InstanceLimits, PortRange, ResolvedTransport, Text,
};

use crate::secret::SecretBytes;

pub const WORKER_PROTOCOL: u32 = 4;

/// Largest frame the manager sends a worker: a configuration or overlay carries up to 16 MiB of
/// compiled ranges (base64 inside JSON). Frames from a worker keep the default limit.
pub const TO_WORKER_MAX_FRAME: usize = 24 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub enum ToWorker {
    Hello {
        protocol: u32,
        build_id: String,
    },
    /// Gateway listener sockets follow as descriptors, in the order of `config.gateways`.
    Configure(Box<WorkerConfig>),
    /// Bring the tunnel up with the gate in `probe` and report `TunnelUp` / `Probe`.
    Start,
    /// Open the payload gate. `permit` must be the one issued for this generation.
    Activate {
        permit: u64,
    },
    /// Stop admitting new payload flows; existing flows continue.
    Tighten {
        reason: String,
    },
    /// Reset existing payload flows (generation change, stop).
    ResetPayload {
        reason: String,
    },
    /// Terminal: nothing is admitted again by this worker.
    Seal {
        reason: String,
    },
    /// Replace the blocklist overlay atomically (answered with `OverlayApplied` or
    /// `OverlayRejected`; the previous overlay stays until a new one is installed).
    SetOverlay(Box<OverlayWire>),
    /// Lift the auto-ban of `source` (answered with `Unbanned`). Blocklists still apply.
    Unban {
        source: IpAddr,
    },
    /// Serve one more Gateway of this generation; its listener socket follows as the frame's
    /// descriptor. Sent for a Gateway whose port was taken when the generation started.
    AddGateway(GatewaySpecWire),
    /// Stop serving a Gateway now: its listener closes and its connections end (deleted,
    /// disabled or changed while the generation runs).
    RemoveGateway {
        id: GatewayId,
    },
    /// Replace the bandwidth caps of the Gateway payload (answered with `BandwidthApplied`).
    /// The initial caps travel in `Configure` (`limits`).
    SetBandwidth(BandwidthCaps),
    /// Replace the transport: the flows opened from now on take it, the ones that exist keep
    /// what they have, and the health probes follow it. The initial one travels in `Configure`;
    /// every `Status` says which one it describes.
    SetTransport(Box<TransportWire>),
    /// Answer to [`FromWorker::RelayRequest`]: the UDP socket follows as the frame's descriptor.
    Relay {
        id: u64,
    },
    /// Answer to [`FromWorker::RelayRequest`] when no socket could be made.
    RelayFailed {
        id: u64,
        message: String,
    },
    /// The port forwards of this generation, all of them: new ones are added (their tunnel
    /// ports reserved), missing ones end with their connections, changed ones start over.
    SetForwards(Vec<ForwardSpecWire>),
    /// The forward's target is verified: listen and connect inbound traffic to it.
    GrantForward(ForwardLeaseWire),
    /// The forward's lease `lease_id` ends: stop listening and close its connections now.
    RevokeForward {
        binding: ForwardBindingId,
        lease_id: u64,
    },
    Stop {
        grace_ms: u32,
    },
    Ping {
        seq: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum FromWorker {
    Hello {
        protocol: u32,
        build_id: String,
        pid: u32,
    },
    Configured,
    /// The `WireGuard` handshake completed.
    TunnelUp {
        endpoint: SocketAddr,
    },
    /// Result of a DNS probe through the tunnel (readiness and liveness evidence).
    Probe {
        ok: bool,
        latency_ms: Option<u32>,
        error: Option<Text>,
        /// The probe did not run (local flow/memory limit reached, or another probe still
        /// running): it says nothing about the tunnel and never counts as a failure.
        #[serde(default)]
        inconclusive: bool,
        /// Answered by the fallback (the `WireGuard` profile's resolvers): every server of the
        /// DNS profile failed, for this reason.
        #[serde(default)]
        fallback: Option<Text>,
        /// Every server of the DNS profile failed and it asks nothing else (`on_failure:
        /// fail`), for this reason: names fail meanwhile. `ok` then says the tunnel itself is
        /// alive (its `WireGuard` session is fresh), not that a name resolved.
        #[serde(default)]
        interrupted: Option<Text>,
    },
    Ready {
        permit: u64,
    },
    Status(Box<WorkerStatus>),
    /// The inner watchdog tightened the gate.
    Degraded {
        code: String,
        message: Text,
    },
    /// Probes succeed again; only the manager may re-open the gate (Activate).
    Recovered,
    Fatal {
        code: String,
        message: Text,
    },
    Pong {
        seq: u64,
    },
    Stopped,
    /// The overlay `revision` is installed; `digest` is the worker's own SHA-256 of what it now
    /// enforces.
    OverlayApplied {
        revision: u64,
        digest: String,
    },
    /// The overlay `revision` was not installed (the previous one stays).
    OverlayRejected {
        revision: u64,
        reason: Text,
    },
    /// The auto-ban engine banned a source.
    Banned(BanReport),
    /// `source` is no longer banned; `found`: it was banned until now.
    Unbanned {
        source: IpAddr,
        found: bool,
    },
    /// The caps it enforces from now on.
    BandwidthApplied(BandwidthCaps),
    /// Strict mode: a SOCKS5 UDP association needs a relay socket bound on `client_ip` (a
    /// loopback address) in the host network namespace.
    RelayRequest {
        id: u64,
        client_ip: IpAddr,
    },
}

/// A compiled blocklist overlay: the union of the security profile's blocklists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayWire {
    /// Monotonic `enforcement_policy_revision`.
    pub revision: u64,
    /// SHA-256 of `set` as compiled; the worker installs only a set with this digest.
    pub digest: String,
    pub set: IpRangeSet,
}

/// A ban carried into a new generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanWire {
    pub source: IpAddr,
    pub remaining_secs: u32,
}

/// A ban the worker made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanReport {
    pub source: IpAddr,
    pub reason: Text,
    pub ban_secs: u32,
    /// The overlay revision in force.
    pub policy_revision: u64,
}

/// The transport a worker applies: the connection's transport profile with every reference
/// followed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportWire {
    /// Tells one transport of a generation from the next: a status report names the one it
    /// describes.
    pub serial: u64,
    pub transport: ResolvedTransport,
}

/// What a worker's transport does now.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportStatusWire {
    /// The [`TransportWire::serial`] this describes.
    pub serial: u64,
    /// Index of the range (of [`ResolvedTransport::bands`]) new flows take.
    pub band: u32,
    /// The round trip measured through the tunnel, microseconds; `None` while nothing was
    /// measured.
    pub rtt_us: Option<u64>,
    /// TCP buffers enlarged because their connection used them.
    pub buffers_grown: u64,
    /// Enlargements not made because the buffer budget had no room for them.
    pub growth_refused: u64,
    /// The congestion control the worker's own TCP connections run; `None` on the strict plane
    /// until it opened one.
    #[serde(default)]
    pub congestion: Option<CongestionStatus>,
}

/// Everything a worker needs, resolved by the manager at start. Secrets travel only here.
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerConfig {
    pub instance_id: InstanceId,
    pub generation: u64,
    pub tunnel: TunnelSpec,
    pub dns: DnsSpec,
    pub policy: PolicySpec,
    pub gateways: Vec<GatewaySpecWire>,
    pub limits: InstanceLimits,
    /// What each flow gets and how the connection's health is probed.
    pub transport: TransportWire,
    /// Lock file the worker must hold (exclusive flock) for its lifetime. Its holder is the only
    /// process allowed to use this `WireGuard` key.
    pub key_lock_path: String,
    /// Private management connector of this generation (0600 Unix socket), if any.
    #[serde(default)]
    pub connector_path: Option<String>,
    /// Installation key with which this worker's Gateways prove themselves to `vpnctl`.
    #[serde(default)]
    pub gateway_key: Option<SecretBytes>,
    /// Linux strict mode: the worker runs in the sandbox's network namespace with this layout
    /// of extra descriptors. `None`: the userspace netstack (explicit proxy only).
    #[serde(default)]
    pub strict: Option<StrictWire>,
    /// Port forwards of the generation (enabled ones). They listen only once leased.
    #[serde(default)]
    pub forwards: Vec<ForwardSpecWire>,
}

/// One port forward as the worker runs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardSpecWire {
    pub id: ForwardBindingId,
    pub protocol: ForwardProtocol,
    /// Port on the tunnel address(es) that receives inbound traffic.
    pub tunnel_port: u16,
    /// Concurrent TCP connections (and UDP flows) of this forward.
    pub max_connections: u32,
    /// Start every forwarded TCP connection with a PROXY protocol v2 header (UDP unchanged).
    /// Absent from a manager that predates it: off.
    #[serde(default)]
    pub proxy_protocol: bool,
    /// Its UDP goes straight into the strict sandbox, to the App's own socket on the tunnel
    /// port: the worker neither reserves nor relays it (the packet filter admits it). Absent
    /// from a manager that predates it: off.
    #[serde(default)]
    pub udp_direct: bool,
}

/// The manager's grant: the loopback addresses the forward's App held at its last check.
///
/// One address per protocol the worker relays (no UDP address when the UDP goes straight into
/// the sandbox). The worker refuses anything but loopback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardLeaseWire {
    pub binding: ForwardBindingId,
    /// New for every grant; a revocation names the lease it ends.
    pub lease_id: u64,
    pub tcp: Option<SocketAddr>,
    pub udp: Option<SocketAddr>,
}

/// The sandbox a strict worker serves.
///
/// Its descriptors follow the Gateway listeners in this
/// order: TUN device, `WireGuard` underlay UDP socket (host namespace, connected to the pinned
/// endpoint), DNS UDP socket and DNS TCP listener (127.0.0.53:53 in the sandbox).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrictWire {
    /// Interface name of the TUN device inside the sandbox.
    pub tun_name: String,
    pub sandbox_epoch: u64,
}

impl StrictWire {
    /// Descriptors that follow the Gateway listeners.
    pub const DESCRIPTORS: usize = 4;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TunnelSpec {
    pub private_key: SecretBytes,
    pub preshared_key: Option<SecretBytes>,
    pub peer_public_key: [u8; 32],
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<IpNetwork>,
    pub addresses: Vec<IpNetwork>,
    pub mtu: u16,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSpec {
    pub servers: Vec<DnsServer>,
    pub cache: DnsCacheSettings,
    pub query_timeout_ms: u32,
    pub attempts: u8,
    /// With a DNS profile, the `WireGuard` profile's own resolvers (plain UDP through the same
    /// tunnel): queries go there while every one of `servers` fails the health probe. Empty
    /// without a DNS profile (`servers` are those resolvers then) and with `on_failure: fail`.
    #[serde(default)]
    pub fallback: Vec<DnsServer>,
    /// What to do while every one of `servers` fails: `fail` asks nothing else, not even a
    /// `fallback` (absent: `wireguard_resolvers`).
    #[serde(default)]
    pub on_failure: DnsOnFailure,
}

/// The security policy of one generation: the base rules (fixed until a restart), the initial
/// blocklist overlay and the auto-ban engine's settings and carried-over bans.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicySpec {
    pub allow_private: Vec<IpNetwork>,
    pub blocked_ports: Vec<u16>,
    pub allowed_destinations: Vec<IpNetwork>,
    pub allowed_ports: Vec<PortRange>,
    /// Installed before `Configured` is answered (the gate cannot open without it).
    pub overlay: Option<OverlayWire>,
    pub auto_ban: AutoBanSettings,
    /// Active bans of earlier generations.
    pub bans: Vec<BanWire>,
    /// Addresses the connection itself needs (`WireGuard` peer, DNS servers): never banned.
    pub exempt: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewaySpecWire {
    pub id: GatewayId,
    pub kind: GatewayKind,
    pub port: u16,
    pub udp: bool,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateWire {
    Closed,
    Probe,
    Open,
    Sealed,
}

/// Cumulative counters and gauges, sent once per second. Rates are derived by the collector.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub generation: u64,
    /// Worker-local monotonic milliseconds (only differences are meaningful).
    pub monotonic_ms: u64,
    pub gate: Option<GateWire>,
    pub last_handshake_ms_ago: Option<u64>,
    pub endpoint: Option<SocketAddr>,
    pub wg_rx_bytes: u64,
    pub wg_tx_bytes: u64,
    pub underlay_blocked: u64,
    pub tunnel_rx_bytes: u64,
    pub tunnel_tx_bytes: u64,
    pub active_tcp: u64,
    pub active_udp: u64,
    pub admission_rejected: u64,
    pub memory_reserved: u64,
    pub dns_queries: u64,
    pub dns_cache_hits: u64,
    pub dns_failures: u64,
    /// DNS resolution latency (`latency-us-v1`): per-bucket counts of lookups answered from
    /// upstream (cache hits excluded), their summed microseconds and the lookups that timed out.
    pub dns_latency_buckets: Vec<u64>,
    pub dns_latency_sum_us: u64,
    pub dns_timeouts: u64,
    pub gateways: Vec<GatewayStatusWire>,
    pub rss_bytes: Option<u64>,
    pub cpu_ns: Option<u64>,
    /// Tunnel flows of the control class (DNS lookups and health probes), so the Performance
    /// Manager can report data flows apart from probe and control flows. `None` from a worker
    /// that does not report them.
    #[serde(default)]
    pub control_flows: Option<u64>,
    /// Health probes in flight.
    #[serde(default)]
    pub probe_flows: Option<u64>,
    /// Provider relays open on the private connector.
    #[serde(default)]
    pub connector_flows: Option<u64>,
    /// The bandwidth caps of the Gateway payload and what they did so far.
    #[serde(default)]
    pub shaping: Option<ShapingWire>,
    /// What the transport does now.
    #[serde(default)]
    pub transport: Option<TransportStatusWire>,
    /// Every forward of the generation.
    #[serde(default)]
    pub forwards: Vec<ForwardStatusWire>,
    /// Payload the worker relayed for its port forwards, all of them together: TCP connections
    /// and relayed UDP flows, from the remote ends to the Apps (`rx`) and back (`tx`).
    /// Cumulative for the generation: a forward removed meanwhile keeps its bytes in it (its
    /// own `bytes_in`/`bytes_out` leave with it). UDP that goes straight into the strict sandbox
    /// is not in it: the packet filter counts that with the sandbox's Apps (`sandbox`). A worker
    /// of an earlier release reports none: 0.
    #[serde(default)]
    pub forward_rx_bytes: u64,
    #[serde(default)]
    pub forward_tx_bytes: u64,
    /// Strict mode: what the Apps of the sandbox carried on their own flows. `None` from a worker
    /// without a sandbox (the userspace netstack) — there is nothing to count, which is not 0 —
    /// or from one that does not report it.
    #[serde(default)]
    pub sandbox: Option<SandboxWire>,
    /// Strict mode: the Apps' payload of [`Self::sandbox`] per local port of the sandbox (the
    /// App socket's port). An entry lives while its port carries payload and for a while after;
    /// a port used again after that starts from 0. The manager turns it into
    /// [`Self::app_payload`] and does not pass it on. Empty from a worker of an earlier release.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sandbox_ports: Vec<SandboxPortWire>,
    /// Filled in by the manager, never by the worker: the payload of each managed App of this
    /// connection, cumulative for the generation — its share of the sandbox's own flows (by the
    /// ports its processes hold) and of the port forwards that end at it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub app_payload: Vec<AppPayloadWire>,
}

/// The Apps' payload through one local port of a strict sandbox (see
/// [`WorkerStatus::sandbox_ports`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPortWire {
    pub udp: bool,
    pub port: u16,
    /// From the remote hosts to the App socket.
    pub rx_bytes: u64,
    /// From the App socket to the remote hosts.
    pub tx_bytes: u64,
}

/// One managed App's payload, cumulative for the worker's generation (see
/// [`WorkerStatus::app_payload`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPayloadWire {
    pub app_id: AppId,
    /// From the remote hosts to the App.
    pub rx_bytes: u64,
    /// From the App to the remote hosts.
    pub tx_bytes: u64,
}

impl WorkerStatus {
    /// The connection's payload that no Gateway relayed, `(rx, tx)`, cumulative for the
    /// generation: what its port forwards relayed to and from managed Apps and, in strict mode,
    /// what the sandbox's Apps carried on their own flows. With the Gateways' payload it makes
    /// the connection's; neither part counts a byte of the other.
    #[must_use]
    pub fn apps_payload(&self) -> (u64, u64) {
        let (rx, tx) = self.sandbox.map_or((0, 0), |s| (s.rx_bytes, s.tx_bytes));
        (
            rx.saturating_add(self.forward_rx_bytes),
            tx.saturating_add(self.forward_tx_bytes),
        )
    }

    /// Strict mode: everything the sandbox's Apps carried, `(rx, tx)` — their own flows and the
    /// connections forwarded to them. A strict worker runs inside the sandbox's network
    /// namespace and reaches only its loopback, so every forward ends at an App in the sandbox:
    /// this is all of [`Self::apps_payload`]. `None` without a sandbox.
    #[must_use]
    pub fn sandbox_payload(&self) -> Option<(u64, u64)> {
        self.sandbox.map(|_| self.apps_payload())
    }
}

/// The Apps of a strict sandbox as the TUN filter counts them, cumulative for the generation.
///
/// The worker's own flows (Gateway and Provider connections, DNS, port forwards) are not in it:
/// Gateways count their payload themselves, and so do port forwards
/// ([`WorkerStatus::forward_rx_bytes`]); [`WorkerStatus::sandbox_payload`] adds the forwards' to
/// this for everything the sandbox's Apps carried.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxWire {
    /// Transport payload of the Apps' flows (TCP segment payload, UDP payload) as it crossed the
    /// TUN device, from the remote hosts to the Apps; retransmitted segments count again.
    pub rx_bytes: u64,
    /// The same from the Apps to the remote hosts.
    pub tx_bytes: u64,
    /// App flows tracked now.
    pub tcp_flows: u64,
    pub udp_flows: u64,
    /// App flows the remote end had not answered, dropped from a full table for a new one.
    pub evicted: u64,
    /// New App flows refused because their table was full of answered flows.
    pub table_full: u64,
}

/// Bandwidth caps in force and their cumulative effect (counters only grow within a worker).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapingWire {
    pub caps: BandwidthCaps,
    /// Milliseconds during which some download payload waited for its cap.
    pub download_wait_ms: u64,
    pub upload_wait_ms: u64,
    /// UDP datagrams dropped because the cap was reached.
    pub download_dropped: u64,
    pub upload_dropped: u64,
}

/// What one port forward does, cumulative for the generation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardStatusWire {
    pub id: Option<ForwardBindingId>,
    /// The lease in force, if any.
    pub lease_id: Option<u64>,
    pub tcp_listening: bool,
    pub udp_listening: bool,
    /// Why it cannot listen although leased (e.g. the tunnel port is taken).
    pub error: Option<Text>,
    /// Inbound TCP connections and UDP flows connected to the App.
    pub accepted: u64,
    /// Refused by the inbound guard: not a unicast source, blocklisted, banned, over the
    /// auto-ban threshold with the ban table full.
    pub refused_invalid: u64,
    pub refused_blocklisted: u64,
    pub refused_banned: u64,
    pub refused_rate_limited: u64,
    /// Refused because the forward already carries its maximum.
    pub refused_limit: u64,
    /// Arrived while the gate was not open or the lease was ending.
    pub refused_closed: u64,
    /// The App did not accept the connection (nothing listening, refused, timed out).
    pub target_failed: u64,
    pub tcp_active: u64,
    pub udp_active: u64,
    /// Bytes from the remote side to the App, and back.
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// UDP datagrams dropped (App socket full, oversized for the tunnel).
    pub udp_dropped: u64,
    /// Since the last inbound connection (TCP) or flow (UDP) from a source outside the tunnel's
    /// own and private networks: evidence the forward is reachable from the Internet.
    pub external_tcp_ms_ago: Option<u64>,
    pub external_udp_ms_ago: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatewayStatusWire {
    pub id: Option<GatewayId>,
    pub serving: bool,
    pub tcp_accepted: u64,
    pub tcp_rejected: u64,
    pub tcp_active: u64,
    pub udp_active: u64,
    pub udp_dropped: u64,
    pub payload_rx_bytes: u64,
    pub payload_tx_bytes: u64,
    /// The part of `payload_*` relayed for SSH sessions: TCP connections to port 22, or marked
    /// as SSH by the client (`vpnctl ssh-proxy`); VPN Manager's own SSH downloads are not in it
    /// (`ssh_pull_*`). A worker of an earlier release reports none (0), and one of 2026-11-06
    /// counted the SSH downloads to port 22 here.
    #[serde(default)]
    pub ssh_rx_bytes: u64,
    #[serde(default)]
    pub ssh_tx_bytes: u64,
    /// The part of `payload_*` relayed for VPN Manager's own SSH downloads (marked by the
    /// component as such); 0 from a worker of an earlier release.
    #[serde(default)]
    pub ssh_pull_rx_bytes: u64,
    #[serde(default)]
    pub ssh_pull_tx_bytes: u64,
    /// SSH sessions (`ssh_*`) relayed now.
    #[serde(default)]
    pub ssh_sessions: u64,
    /// Proxy connect latency (`latency-us-v1`) of connects that reached the destination.
    pub connect_latency_buckets: Vec<u64>,
    pub connect_latency_count: u64,
    pub connect_latency_sum_us: u64,
    pub connect_timeouts: u64,
    /// Connects that failed otherwise (refused, unreachable, name not resolved).
    pub connect_failures: u64,
    /// Subset of `connect_failures`: the name had no address (NXDOMAIN, or none of a family the
    /// tunnel carries).
    #[serde(default)]
    pub connect_not_found: u64,
}
