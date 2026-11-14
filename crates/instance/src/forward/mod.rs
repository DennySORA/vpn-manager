//! Instance Port Controller: port forwards from the tunnel to a managed App.
//!
//! Every forward of the generation has its tunnel port reserved from the start (no outbound flow
//! can take it). It listens only while two things hold: the manager's lease for it stands, and
//! the payload gate is open. The lease names the loopback address the App's process tree holds
//! (checked by the manager every few seconds and on every App event); a revoked or replaced
//! lease ends the forward's connections at once. A gate that tightens stops new connections
//! (the TCP listener closes, new UDP flows are dropped) and keeps the existing ones, like the
//! Gateways do.
//!
//! Every new inbound TCP connection or UDP flow, in this order: evidence (a source outside the
//! tunnel's own and private networks is recorded as having reached the forward), the gate and the
//! lease, the inbound guard (blocklists, bans, auto-ban), the forward's connection limit, and
//! then the connection to the App through [`AppEndpoint`] — the worker's only host-side connect.
//! Refusals close the inbound connection (RST) or drop the datagram; nothing waits in a queue.
//!
//! The App's side of every forwarded connection comes from loopback. A forward that opted in
//! (`proxy_protocol`) therefore starts each TCP connection to the App with one PROXY protocol v2
//! header naming the remote peer and the tunnel address and port it reached, before any payload
//! and outside the byte counts. UDP datagrams are relayed as they are.
//!
//! What the forwards relay is payload of their connection: each forward counts its own
//! (`bytes_in`/`bytes_out`), and every forward of the generation adds to one total that only
//! grows ([`PortController::relayed`]), which the worker reports beside the Gateways' payload.
//! The packet filter leaves the forwards' tunnel side out of the strict sandbox's App count (it
//! is the worker's own socket), so nothing is counted twice.
//!
//! On a strict connection a forward can instead take its UDP straight into the sandbox
//! (`udp_direct`): the worker neither reserves nor relays the UDP port, which the App's own socket
//! holds; the packet filter lets a remote end's datagrams through to it unchanged (the App reads
//! the real source and answers from its port) only while the lease stands and the gate is open,
//! with the same decisions for every new flow ([`direct`]). TCP of the same forward is relayed as
//! ever. Without a sandbox the forward's UDP is not carried at all — never relayed instead.

mod direct;
mod endpoint;
mod proxy;
mod relay;
mod tcp;
mod udp;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use vpn_domain::validation::{is_private, is_special};
use vpn_domain::{ForwardBindingId, Text, tr};
use vpn_ipc::worker::{ForwardLeaseWire, ForwardSpecWire, ForwardStatusWire};
use vpn_sync::Mutex;
use vpn_tunnel::{DirectUdpOpen, DirectUdpPort, TunnelInbound};

pub use endpoint::AppEndpoint;

use crate::counters::{ForwardCounters, RelayedCounters};
use crate::inbound::{InboundDenied, InboundGuard};

/// Listening sockets kept ready per forward (concurrent handshakes in progress).
pub const TCP_BACKLOG: usize = 4;
/// UDP flows one forward relays at once, whatever its connection limit.
pub const MAX_UDP_FLOWS: u32 = 512;
/// How long the App gets to accept a forwarded connection.
pub const APP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// A UDP flow without a datagram in either direction for this long ends.
pub const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// What the forward loops share with the controller.
pub(crate) struct Shared<I: TunnelInbound> {
    pub net: I,
    pub guard: Arc<InboundGuard>,
    /// The tunnel's own networks: sources inside them never count as evidence.
    pub networks: Arc<Vec<IpNetwork>>,
    pub epoch: Instant,
    pub counters: Arc<ForwardCounters>,
    /// Every forward of the generation together: what they relayed.
    pub relayed: Arc<RelayedCounters>,
    pub tcp_idle: Duration,
}

impl<I: TunnelInbound> Shared<I> {
    /// Record an arrival from `source` as evidence when it came from outside.
    pub fn arrived(&self, source: IpAddr, udp: bool) {
        arrived(&self.counters, &self.networks, self.epoch, source, udp);
    }

    /// The inbound guard's decision, counted.
    pub fn admit(&self, source: IpAddr) -> bool {
        admit(&self.guard, &self.counters, source)
    }
}

/// A forward's problems as one text; `None` when it has none.
fn joined(problems: &[Text]) -> Option<Text> {
    (!problems.is_empty()).then(|| {
        tr!("; ", "；", "；").map(|language, separator| {
            problems
                .iter()
                .map(|p| p.get(language))
                .collect::<Vec<_>>()
                .join(separator)
        })
    })
}

/// Record an arrival from `source` in a forward's `counters` as evidence when it came from
/// outside the tunnel's own `networks` (milliseconds after `epoch`, plus one).
fn arrived(
    counters: &ForwardCounters,
    networks: &[IpNetwork],
    epoch: Instant,
    source: IpAddr,
    udp: bool,
) {
    if external(source, networks) {
        let at = u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX - 1) + 1;
        let slot = if udp {
            &counters.external_udp
        } else {
            &counters.external_tcp
        };
        slot.store(at, Ordering::Relaxed);
    }
}

/// The inbound guard's decision on `source`, a refusal counted in the forward's `counters`.
fn admit(guard: &InboundGuard, counters: &ForwardCounters, source: IpAddr) -> bool {
    match guard.admit(source) {
        Ok(()) => true,
        Err(denied) => {
            let counter = match denied {
                InboundDenied::InvalidSource => &counters.refused_invalid,
                InboundDenied::Blocklisted => &counters.refused_blocklisted,
                InboundDenied::Banned { .. } => &counters.refused_banned,
                InboundDenied::RateLimited => &counters.refused_rate_limited,
            };
            counter.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

/// Whether `source` lies outside the tunnel's own networks and every private or special range:
/// a connection from there reached the forward from the Internet.
#[must_use]
pub fn external(source: IpAddr, networks: &[IpNetwork]) -> bool {
    let ip = source.to_canonical();
    !is_special(ip) && !is_private(ip) && !networks.iter().any(|n| n.contains(ip))
}

/// A lease the manager granted, and what lives as long as it does.
struct Lease {
    id: u64,
    tcp: Option<AppEndpoint>,
    udp: Option<AppEndpoint>,
    /// Ends every connection and loop of the lease.
    flows: CancellationToken,
    tracker: TaskTracker,
    /// One permit per forwarded TCP connection.
    limit: Arc<Semaphore>,
    /// The TCP accept loop: only while the gate is open.
    listening: Option<CancellationToken>,
    /// The UDP relay (from the first moment the gate was open until the lease ends) and its
    /// flows by source.
    udp_flows: Option<Arc<Mutex<udp::Flows>>>,
    /// UDP straight into the sandbox: the direct port takes new flows until the lease ends,
    /// and its flows end with it.
    direct: Option<DirectUdpOpen>,
}

struct Forward<I: TunnelInbound> {
    spec: ForwardSpecWire,
    /// The reserved tunnel port (TCP, and UDP unless it goes straight into the sandbox; `None`
    /// when nothing is to be reserved), or why it could not be reserved (retried).
    port: Result<Option<I::Port>, Text>,
    /// UDP straight into the sandbox: the port registered with the packet filter, or why it
    /// could not be. `None` for a forward that relays its UDP or carries none.
    direct: Option<Result<DirectUdpPort, NotDirect>>,
    counters: Arc<ForwardCounters>,
    lease: Option<Lease>,
    /// Why it does not listen although leased.
    error: Option<Text>,
}

/// Why a forward's UDP does not go straight into the sandbox.
struct NotDirect {
    message: Text,
    /// Worth another try (the port was another forward's a moment ago). A data plane without a
    /// sandbox never takes it: tried once.
    retry: bool,
}

impl<I: TunnelInbound> Forward<I> {
    /// Whether the worker relays the forward's UDP (it carries UDP that does not go straight into
    /// the sandbox).
    const fn relays_udp(&self) -> bool {
        self.spec.protocol.udp() && !self.spec.udp_direct
    }
}

/// The Port Controller of one worker.
pub struct PortController<I: TunnelInbound> {
    net: I,
    guard: Arc<InboundGuard>,
    networks: Arc<Vec<IpNetwork>>,
    epoch: Instant,
    tcp_idle: Duration,
    forwards: HashMap<ForwardBindingId, Forward<I>>,
    /// What every forward of the generation relayed, removed ones included.
    relayed: Arc<RelayedCounters>,
}

impl<I: TunnelInbound> PortController<I> {
    /// `networks`: the tunnel interface's own addresses with their prefixes.
    pub fn new(
        net: I,
        guard: Arc<InboundGuard>,
        networks: Vec<IpNetwork>,
        tcp_idle: Duration,
    ) -> Self {
        Self {
            net,
            guard,
            networks: Arc::new(networks),
            epoch: Instant::now(),
            tcp_idle,
            forwards: HashMap::new(),
            relayed: Arc::new(RelayedCounters::default()),
        }
    }

    /// What every forward of the generation relayed so far, `(remote → App, App → remote)`:
    /// their TCP connections and relayed UDP flows, forwards removed meanwhile included. UDP
    /// straight into the sandbox is not in it (the packet filter counts it with the sandbox's
    /// Apps).
    #[must_use]
    pub fn relayed(&self) -> (u64, u64) {
        (
            self.relayed.rx_bytes.load(Ordering::Relaxed),
            self.relayed.tx_bytes.load(Ordering::Relaxed),
        )
    }

    /// The forwards of the generation, all of them. New ones get their tunnel port reserved;
    /// missing ones end (with their connections); a changed one starts over without a lease.
    pub fn set(&mut self, specs: Vec<ForwardSpecWire>) {
        let wanted: HashMap<ForwardBindingId, ForwardSpecWire> =
            specs.into_iter().map(|s| (s.id, s)).collect();
        let stale: Vec<ForwardBindingId> = self
            .forwards
            .iter()
            .filter(|(id, f)| wanted.get(id) != Some(&f.spec))
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some(mut f) = self.forwards.remove(&id) {
                self.end_lease(&mut f);
                tracing::info!(forward = %id, "port forward removed or changed");
            }
        }
        for (id, spec) in wanted {
            if self.forwards.contains_key(&id) {
                continue;
            }
            let counters = Arc::new(ForwardCounters::default());
            let port = self.reserve(&spec);
            let direct = self.direct(&spec, &counters);
            self.forwards.insert(
                id,
                Forward {
                    spec,
                    port,
                    direct,
                    counters,
                    lease: None,
                    error: None,
                },
            );
        }
    }

    /// Reserve what the worker serves on the tunnel port: TCP, and UDP unless it goes straight
    /// into the sandbox (the App's own socket holds that).
    fn reserve(&self, spec: &ForwardSpecWire) -> Result<Option<I::Port>, Text> {
        let (tcp, udp) = (spec.protocol.tcp(), spec.protocol.udp() && !spec.udp_direct);
        if !(tcp || udp) {
            return Ok(None);
        }
        self.net
            .reserve(spec.tunnel_port, tcp, udp)
            .map(Some)
            .map_err(|e| {
                tracing::warn!(forward = %spec.id, port = spec.tunnel_port, error = %e, "tunnel port not reserved");
                let port = spec.tunnel_port;
                tr!(
                    "tunnel port {port} cannot be reserved right now ({e}); it is retried shortly",
                    "tunnel port {port} 目前無法保留（{e}），稍後自動重試",
                    "tunnel port {port} を現在確保できません（{e}）。しばらくすると自動で再試行します"
                )
            })
    }

    /// Register the UDP port of a forward whose UDP goes straight into the sandbox with the
    /// packet filter, deciding on its new flows like the relay would; `None` for any other.
    fn direct(
        &self,
        spec: &ForwardSpecWire,
        counters: &Arc<ForwardCounters>,
    ) -> Option<Result<DirectUdpPort, NotDirect>> {
        if !(spec.udp_direct && spec.protocol.udp()) {
            return None;
        }
        let policy = Arc::new(direct::Direct {
            guard: self.guard.clone(),
            networks: self.networks.clone(),
            epoch: self.epoch,
            counters: counters.clone(),
            max: u64::from(spec.max_connections.max(1)),
        });
        Some(
            self.net
                .direct_udp(spec.tunnel_port, policy)
                .map_err(|e| {
                    tracing::warn!(forward = %spec.id, port = spec.tunnel_port, error = %e, "UDP not taken straight into the sandbox");
                    if e.kind() == std::io::ErrorKind::Unsupported {
                        NotDirect {
                            message: tr!(
                                "UDP straight into the sandbox is only for connections with strict isolation: this connection has no sandbox, so UDP is not forwarded",
                                "UDP 直接送進沙箱只用於嚴格隔離的連線：這條連線沒有沙箱，UDP 不轉送",
                                "サンドボックスへの UDP の直接送信は厳格な分離の接続でのみ使えます。この接続にはサンドボックスがないため、UDP は転送しません"
                            ),
                            retry: false,
                        }
                    } else {
                        let port = spec.tunnel_port;
                        NotDirect {
                            message: tr!(
                                "UDP of tunnel port {port} cannot go straight into the sandbox right now ({e}); it is retried shortly",
                                "tunnel port {port} 的 UDP 目前無法直接送進沙箱（{e}），稍後自動重試",
                                "tunnel port {port} の UDP を現在サンドボックスに直接送れません（{e}）。しばらくすると自動で再試行します"
                            ),
                            retry: true,
                        }
                    }
                }),
        )
    }

    /// The manager verified the target: start forwarding to it (replacing an earlier lease).
    pub fn grant(&mut self, wire: &ForwardLeaseWire) {
        let Some(mut f) = self.forwards.remove(&wire.binding) else {
            tracing::warn!(forward = %wire.binding, "lease for an unknown forward ignored");
            return;
        };
        self.end_lease(&mut f);
        let proto = f.spec.protocol;
        // UDP straight into the sandbox is connected to nothing: no UDP address to connect to.
        let relayed_udp = f.relays_udp();
        let tcp = wire.tcp.and_then(AppEndpoint::new);
        let udp = wire.udp.and_then(AppEndpoint::new);
        let complete = tcp.is_some() == proto.tcp()
            && udp.is_some() == relayed_udp
            && wire.tcp.is_some() == proto.tcp()
            && wire.udp.is_some() == relayed_udp;
        if complete {
            let max = f.spec.max_connections.max(1) as usize;
            f.lease = Some(Lease {
                id: wire.lease_id,
                tcp,
                udp,
                flows: CancellationToken::new(),
                tracker: TaskTracker::new(),
                limit: Arc::new(Semaphore::new(max.min(Semaphore::MAX_PERMITS))),
                listening: None,
                udp_flows: None,
                direct: None,
            });
            f.error = None;
            tracing::info!(forward = %wire.binding, "port forward lease granted");
        } else {
            // Never connect anywhere but a loopback address of the right protocol.
            tracing::warn!(forward = %wire.binding, "lease refused: not a loopback target of the forward's protocols");
            f.error = Some(tr!(
                "The target the manager gave is not a loopback address; not enabled",
                "manager 給的目標不是本機位址，未啟用",
                "manager が指定した転送先がループバックアドレスではないため、有効にしていません"
            ));
        }
        self.reconcile_one(&mut f);
        self.forwards.insert(wire.binding, f);
    }

    /// The lease `lease_id` ends: stop listening and close the forward's connections now.
    pub fn revoke(&mut self, binding: ForwardBindingId, lease_id: u64) {
        let Some(mut f) = self.forwards.remove(&binding) else {
            return;
        };
        if f.lease.as_ref().is_some_and(|l| l.id == lease_id) {
            self.end_lease(&mut f);
            f.error = None;
            tracing::info!(forward = %binding, "port forward lease revoked");
        }
        self.forwards.insert(binding, f);
    }

    /// Bring every forward in line with its lease and the gate: listen where both allow it,
    /// stop new connections where the gate does not. Also retries reservations and listeners
    /// that failed. Call after every gate change and periodically.
    pub fn reconcile(&mut self) {
        let ids: Vec<ForwardBindingId> = self.forwards.keys().copied().collect();
        for id in ids {
            if let Some(mut f) = self.forwards.remove(&id) {
                self.reconcile_one(&mut f);
                self.forwards.insert(id, f);
            }
        }
    }

    fn reconcile_one(&self, f: &mut Forward<I>) {
        if f.port.is_err() {
            f.port = self.reserve(&f.spec);
        }
        if matches!(&f.direct, Some(Err(e)) if e.retry) {
            f.direct = self.direct(&f.spec, &f.counters);
        }
        let open = self.net.payload_open();
        let Some(lease) = f.lease.as_mut() else {
            return;
        };
        if lease.flows.is_cancelled() {
            return;
        }
        let port = match &f.port {
            Ok(port) => port.as_ref(),
            Err(e) => {
                f.error = Some(e.clone());
                return;
            }
        };
        let shared = Arc::new(Shared {
            net: self.net.clone(),
            guard: self.guard.clone(),
            networks: self.networks.clone(),
            epoch: self.epoch,
            counters: f.counters.clone(),
            relayed: self.relayed.clone(),
            tcp_idle: self.tcp_idle,
        });
        let mut problems = Vec::new();
        // TCP: a listener exactly while the gate is open.
        match (open, lease.listening.is_some(), lease.tcp.zip(port)) {
            (true, false, Some((endpoint, port))) => match self.net.listen_tcp(port, TCP_BACKLOG) {
                Ok(listener) => {
                    let stop = lease.flows.child_token();
                    lease.tracker.spawn(tcp::accept_loop(
                        listener,
                        shared.clone(),
                        tcp::Lease {
                            endpoint,
                            flows: lease.flows.clone(),
                            tracker: lease.tracker.clone(),
                            limit: lease.limit.clone(),
                            proxy_protocol: f.spec.proxy_protocol,
                        },
                        stop.clone(),
                    ));
                    lease.listening = Some(stop);
                }
                Err(e) => problems.push(tr!(
                    "TCP cannot listen ({e})",
                    "TCP 無法監聽（{e}）",
                    "TCP で待ち受けできません（{e}）"
                )),
            },
            (false, true, _) => {
                if let Some(stop) = lease.listening.take() {
                    stop.cancel();
                }
            }
            _ => {}
        }
        // UDP: from the first moment the gate is open until the lease ends; new flows are
        // refused while it is not open.
        if let (true, None, Some((endpoint, port))) = (open, &lease.udp_flows, lease.udp.zip(port))
        {
            match self.net.listen_udp(port) {
                Ok(socket) => {
                    let flows = Arc::new(Mutex::new(udp::Flows::default()));
                    let max = f.spec.max_connections.clamp(1, MAX_UDP_FLOWS);
                    lease.tracker.spawn(udp::relay(
                        Arc::new(socket),
                        shared,
                        udp::Lease {
                            endpoint,
                            flows: lease.flows.clone(),
                            tracker: lease.tracker.clone(),
                            table: flows.clone(),
                            max: max as usize,
                        },
                    ));
                    lease.udp_flows = Some(flows);
                }
                Err(e) => problems.push(tr!(
                    "UDP cannot listen ({e})",
                    "UDP 無法監聽（{e}）",
                    "UDP で待ち受けできません（{e}）"
                )),
            }
        }
        // UDP straight into the sandbox: the direct port takes new flows for as long as the
        // lease stands (the packet filter also wants the gate open for each).
        if lease.direct.is_none() {
            match &f.direct {
                Some(Ok(direct)) => lease.direct = Some(direct.open()),
                Some(Err(e)) => problems.push(e.message.clone()),
                None => {}
            }
        }
        f.error = joined(&problems);
    }

    /// End a forward's lease: no more listening, its connections reset at once.
    fn end_lease(&self, f: &mut Forward<I>) {
        let Some(lease) = f.lease.take() else {
            return;
        };
        if let Ok(Some(port)) = &f.port {
            let reset = self.net.reset_port(port);
            if reset > 0 {
                tracing::info!(forward = %f.spec.id, reset, "forwarded connections reset");
            }
        }
        lease.flows.cancel();
        lease.tracker.close();
        // Its direct port takes no new flows and its flows there end (`lease.direct` dropped).
    }

    /// End the UDP flows of sources a new ban or blocklist covers (their TCP connections are
    /// reset by the caller's flow reset, on either plane; so are the flows of a direct UDP port,
    /// which the strict packet filter tracks as App flows).
    pub fn drop_sources(&self, covered: impl Fn(IpAddr) -> bool) {
        for f in self.forwards.values() {
            if let Some(table) = f.lease.as_ref().and_then(|l| l.udp_flows.as_ref()) {
                table
                    .lock()
                    .end_where(|src| covered(src.ip().to_canonical()));
            }
        }
    }

    /// Stop everything (the worker ends).
    pub fn shutdown(&mut self) {
        let ids: Vec<ForwardBindingId> = self.forwards.keys().copied().collect();
        for id in ids {
            if let Some(mut f) = self.forwards.remove(&id) {
                self.end_lease(&mut f);
            }
        }
    }

    /// What every forward does, for the status report.
    pub fn status(&self) -> Vec<ForwardStatusWire> {
        let ago = |at: u64| -> Option<u64> {
            (at > 0).then(|| {
                let now = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
                now.saturating_sub(at - 1)
            })
        };
        let mut out: Vec<ForwardStatusWire> = self
            .forwards
            .values()
            .map(|f| {
                let c = &f.counters;
                let get = |a: &std::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
                let lease = f.lease.as_ref().filter(|l| !l.flows.is_cancelled());
                ForwardStatusWire {
                    id: Some(f.spec.id),
                    lease_id: lease.map(|l| l.id),
                    tcp_listening: lease.is_some_and(|l| l.listening.is_some()),
                    udp_listening: lease
                        .is_some_and(|l| l.udp_flows.is_some() || l.direct.is_some())
                        && self.net.payload_open(),
                    error: f
                        .error
                        .clone()
                        .or_else(|| f.port.as_ref().err().cloned())
                        .or_else(|| {
                            f.direct
                                .as_ref()
                                .and_then(|d| d.as_ref().err())
                                .map(|e| e.message.clone())
                        }),
                    accepted: get(&c.accepted),
                    refused_invalid: get(&c.refused_invalid),
                    refused_blocklisted: get(&c.refused_blocklisted),
                    refused_banned: get(&c.refused_banned),
                    refused_rate_limited: get(&c.refused_rate_limited),
                    refused_limit: get(&c.refused_limit),
                    refused_closed: get(&c.refused_closed),
                    target_failed: get(&c.target_failed),
                    tcp_active: get(&c.tcp_active),
                    udp_active: get(&c.udp_active),
                    bytes_in: get(&c.bytes_in),
                    bytes_out: get(&c.bytes_out),
                    udp_dropped: get(&c.udp_dropped),
                    external_tcp_ms_ago: ago(get(&c.external_tcp)),
                    external_udp_ms_ago: ago(get(&c.external_udp)),
                }
            })
            .collect();
        out.sort_by_key(|s| s.id);
        out
    }
}

impl<I: TunnelInbound> Drop for PortController<I> {
    fn drop(&mut self) {
        self.shutdown();
    }
}
