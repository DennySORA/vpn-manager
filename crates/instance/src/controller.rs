//! Instance Controller: the main loop of one `vpnd instance` worker process.
//!
//! Lifecycle (see `vpn_ipc::worker`): Hello → Configure (+listener fds) → Start (handshake and DNS
//! probe as readiness evidence, gate = probe) → Activate (gate = open; the only way it opens) →
//! steady state with a status report every second and the inner watchdog's liveness probes.
//!
//! The worker never re-opens its own gate: after a watchdog tightening it reports `Recovered`
//! and waits for the manager's next `Activate`. It exits as soon as the manager is gone (EOF on
//! the control socket or re-parented to init) — fail closed.
//!
//! Strict mode (Linux): the manager started this process inside the Instance's sandbox network
//! namespace and hands over the sandbox's TUN device, a host-namespace `WireGuard` socket and the
//! DNS listener sockets; the data plane is then the TUN device with kernel sockets instead of
//! the userspace netstack, and the resolver also answers the sandbox's Apps.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::ops::ControlFlow;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Interval;
use vpn_domain::validation::ban_scope;
use vpn_domain::{HealthSettings, InstanceLimits, Text, tr};
use vpn_ipc::frame::{DEFAULT_MAX_FRAME, FrameReader, FrameWriter, split_with};
use vpn_ipc::identity;
use vpn_ipc::worker::{
    BanReport, DnsSpec, ForwardSpecWire, FromWorker, GateWire, GatewaySpecWire, GatewayStatusWire,
    OverlayWire, PolicySpec, StrictWire, TO_WORKER_MAX_FRAME, ToWorker, TransportStatusWire,
    TransportWire, TunnelSpec, WORKER_PROTOCOL, WorkerConfig, WorkerStatus,
};
use vpn_platform::lock::FileLock;
use vpn_platform::{process, resources};
use vpn_tunnel::{
    AnyConnector, FlowClass, GateState, NetstackLimits, PeerConfig, PeerPolicy, TransportPlan,
    Tunnel, TunnelConfig, UdpSource,
};

use crate::counters::{DnsCounters, GatewayCounters};
use zeroize::Zeroizing;

use crate::connector_socket::{ConnectorSocket, NetworkEpoch};
use crate::dns::server::DnsServer;
use crate::dns::{DnsConfig, DnsResolver, ProbeOk, ResolveError};
use crate::forward::PortController;
use crate::gateway::{
    DEFAULT_TCP_IDLE_TIMEOUT, Gateway, GatewayConfig, GatewayDeps, RelayRequest, RelaySockets,
};
use crate::inbound::InboundGuard;
use crate::plane::Plane;
use crate::policy::{BasePolicy, DestinationPolicy, Enforcement, Overlay};
use crate::shaping::Shaper;

/// Relay-socket requests of a strict worker's Gateways waiting for the manager at once.
const MAX_RELAY_REQUESTS: usize = 64;

/// Next probe after one that failed while the gate is not open (verifying a new generation, or
/// degraded): the manager gives a generation 30 s to verify, and the steady-state interval is as
/// long, so a first probe that missed (the peer back a moment later, routes being restored) would
/// otherwise always end in `START_TIMEOUT` and a new generation.
const PROBE_RETRY: Duration = Duration::from_secs(2);

/// Next probe after one that found DNS interrupted (the profile fails closed): names resolve
/// again this soon after a server answers, not up to a whole interval later.
const PROBE_RETRY_INTERRUPTED: Duration = Duration::from_secs(5);

/// While DNS is interrupted no name answers, so the tunnel's liveness is its `WireGuard`
/// session's: one this young means the peer answered a handshake recently. Probes keep sending
/// through the tunnel, and a live peer is handshaken with well within it (anew 15 s after
/// sending without an answer, a rekey every 120 s while sending); `GotaTun` drops a session at
/// this age (`REJECT_AFTER_TIME`).
const SESSION_ALIVE: Duration = Duration::from_secs(180);

/// Reported for a probe that did not run; never counted as a tunnel failure.
fn probe_not_run() -> Text {
    tr!(
        "The local connection or memory quota is full (or the previous probe is still running), so this probe did not run; it does not count as a tunnel failure",
        "本機連線或記憶體配額已滿（或上一個探測仍在進行），這次探測未執行；不視為 tunnel 故障",
        "ローカルの接続数またはメモリの割り当てが上限に達している（または前回のヘルスチェックがまだ実行中の）ため、今回のヘルスチェックは実行されませんでした。tunnel の障害とはみなしません"
    )
}

/// Exit codes (for the manager's fault classification).
pub mod exit {
    pub const OK: i32 = 0;
    pub const PROTOCOL: i32 = 10;
    pub const KEY_IN_USE: i32 = 11;
    pub const CONFIG: i32 = 12;
    pub const TUNNEL: i32 = 13;
    pub const MANAGER_GONE: i32 = 14;
}

enum Internal {
    Started(Result<SocketAddr, Text>),
    Probe(Result<ProbeOk, ResolveError>),
}

struct Running {
    tunnel: Plane,
    dns: DnsResolver<AnyConnector>,
    dns_counters: Arc<DnsCounters>,
    policy: Arc<DestinationPolicy>,
    /// Admission of inbound connections on forwarded ports (blocklists, bans, auto-ban): call
    /// `inbound.admit(source)` for every new inbound connection before serving it.
    inbound: Arc<InboundGuard>,
    /// Port forwards: listen only while leased by the manager and the gate is open (through the
    /// netstack, or on the strict plane with kernel sockets in the sandbox).
    forwards: Option<PortController<vpn_tunnel::AnyInbound>>,
    gateways: Vec<(GatewaySpecWire, Gateway, Arc<GatewayCounters>)>,
    /// Removed (socket closed and unlinked) when the worker ends.
    connector: Option<ConnectorSocket>,
    /// Advanced each time the payload gate opens; the connector refuses a Provider request whose
    /// exit check was made before the last opening.
    network_epoch: NetworkEpoch,
    /// Strict mode: the resolver's listener for the sandbox's Apps.
    dns_server: Option<DnsServer>,
    /// Where the Gateways' SOCKS5 UDP relay sockets come from.
    relays: RelaySockets,
    /// Strict mode: the Gateways' relay requests, forwarded to the manager.
    relay_requests: Option<mpsc::Receiver<RelayRequest>>,
    /// For Gateways added while running.
    gateway_key: Option<Arc<Zeroizing<[u8; 32]>>>,
    /// The bandwidth caps of every Gateway's payload (changed live by `SetBandwidth`).
    shaper: Arc<Shaper>,
    /// Each Gateway's cap on SOCKS5 UDP associations: the Instance's UDP flow limit (one
    /// association holds one tunnel UDP flow).
    max_udp_associations: u32,
    generation: u64,
    /// How the connection's health is probed (the transport's; changed live by `SetTransport`).
    health: HealthSettings,
    /// The serial of the transport in force.
    transport_serial: u64,
    _key_lock: FileLock,
    started_at: Instant,
}

/// Relay requests sent to the manager and not answered yet.
#[derive(Default)]
struct PendingRelays {
    next_id: u64,
    waiting: HashMap<u64, oneshot::Sender<std::io::Result<std::net::UdpSocket>>>,
}

impl Running {
    /// Bring the forwards in line with their leases and the gate.
    fn reconcile_forwards(&mut self) {
        if let Some(f) = self.forwards.as_mut() {
            f.reconcile();
        }
    }

    /// `AddGateway`: serve one more Gateway on the listener `fd`.
    fn add_gateway(&mut self, spec: GatewaySpecWire, fd: OwnedFd) {
        let net = self.tunnel.connector();
        match spawn_gateway(
            spec,
            fd,
            &net,
            &self.dns,
            &self.policy,
            self.gateway_key.as_ref(),
            &self.shaper,
            self.max_udp_associations,
            &self.relays,
        ) {
            Ok(gateway) => self.gateways.push(gateway),
            Err(e) => tracing::warn!(error = %e, "added gateway did not start"),
        }
    }

    /// End every forward and its connections (stop, seal, exit).
    fn end_forwards(&mut self) {
        if let Some(f) = self.forwards.as_mut() {
            f.shutdown();
        }
    }

    /// Seal the gate and end every Gateway, all at once: each stops accepting and answers the
    /// HTTP request it has in flight before its connections go.
    async fn end_gateways(&mut self) {
        self.tunnel.narrow_gate(GateState::Sealed);
        let mut ending = tokio::task::JoinSet::new();
        for (_, gw, _) in self.gateways.drain(..) {
            ending.spawn(gw.shutdown());
        }
        while ending.join_next().await.is_some() {}
    }
}

/// Run the worker on the inherited control socket. Returns the process exit code.
pub async fn run(control: OwnedFd) -> i32 {
    let std_stream = StdUnixStream::from(control);
    if std_stream.set_nonblocking(true).is_err() {
        return exit::PROTOCOL;
    }
    let Ok(stream) = UnixStream::from_std(std_stream) else {
        return exit::PROTOCOL;
    };
    // The manager's frames may carry a 16 MiB blocklist overlay; ours stay small.
    let (mut rx, mut tx) = split_with(stream, TO_WORKER_MAX_FRAME, DEFAULT_MAX_FRAME);
    if let Err(code) = hello(&mut rx, &mut tx).await {
        return code;
    }
    let (running, ban_reports) = match setup(&mut rx, &mut tx).await {
        Ok(r) => r,
        Err(code) => return code,
    };
    steady_state(rx, tx, running, ban_reports).await
}

/// Exchange `Hello`s: the manager must speak our protocol and be the same build.
async fn hello(rx: &mut FrameReader, tx: &mut FrameWriter) -> Result<(), i32> {
    let hello = FromWorker::Hello {
        protocol: WORKER_PROTOCOL,
        build_id: identity::build_id().to_string(),
        pid: std::process::id(),
    };
    if tx.send(&hello, &[]).await.is_err() {
        return Err(exit::MANAGER_GONE);
    }
    match rx.recv::<ToWorker>().await {
        Ok(Some((ToWorker::Hello { protocol, build_id }, _)))
            if protocol == WORKER_PROTOCOL && build_id == identity::build_id() =>
        {
            Ok(())
        }
        Ok(Some((ToWorker::Hello { .. }, _))) => {
            fatal(
                tx,
                "BUILD_MISMATCH",
                tr!(
                    "The manager and the worker are not the same build",
                    "manager 與 worker 不是同一個版本",
                    "manager と worker のバージョンが異なります"
                ),
            )
            .await;
            Err(exit::PROTOCOL)
        }
        _ => Err(exit::PROTOCOL),
    }
}

/// `Configure`: bring up the generation and confirm it, with the overlay now in force.
async fn setup(
    rx: &mut FrameReader,
    tx: &mut FrameWriter,
) -> Result<(Running, mpsc::Receiver<BanReport>), i32> {
    let Ok(Some((ToWorker::Configure(config), fds))) = rx.recv::<ToWorker>().await else {
        return Err(exit::PROTOCOL);
    };
    let (running, ban_reports) = match configure(*config, fds).await {
        Ok(r) => r,
        Err((code, exit_code, msg)) => {
            fatal(tx, code, msg).await;
            return Err(exit_code);
        }
    };
    if tx.send(&FromWorker::Configured, &[]).await.is_err() {
        running.tunnel.shutdown().await;
        return Err(exit::MANAGER_GONE);
    }
    // The initial overlay is in force (installed during Configure): say exactly what it is.
    let initial = running.policy.enforcement().overlay();
    if initial.revision > 0
        && tx
            .send(
                &FromWorker::OverlayApplied {
                    revision: initial.revision,
                    digest: initial.digest.clone(),
                },
                &[],
            )
            .await
            .is_err()
    {
        running.tunnel.shutdown().await;
        return Err(exit::MANAGER_GONE);
    }
    drop(initial);
    Ok((running, ban_reports))
}

/// The steady-state loop's own state besides the select sources.
struct Steady {
    running: Running,
    tx: FrameWriter,
    itx: mpsc::Sender<Internal>,
    probe_tick: Interval,
    started: bool,
    probe_failures: u32,
    degraded: bool,
    probe_in_flight: bool,
    pending_relays: PendingRelays,
}

/// The control loop until the worker ends, then the teardown. Returns the exit code.
async fn steady_state(
    mut rx: FrameReader,
    tx: FrameWriter,
    mut running: Running,
    mut ban_reports: mpsc::Receiver<BanReport>,
) -> i32 {
    let (itx, mut irx) = mpsc::channel::<Internal>(8);
    let mut status_tick = tokio::time::interval(Duration::from_secs(1));
    status_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let probe_tick = probe_ticker(&running.health);
    let mut reports_open = true;
    let fatal_tunnel = running.tunnel.clone();
    let mut relay_requests = running.relay_requests.take();
    let mut s = Steady {
        running,
        tx,
        itx,
        probe_tick,
        started: false,
        probe_failures: 0,
        degraded: false,
        probe_in_flight: false,
        pending_relays: PendingRelays::default(),
    };

    let code = loop {
        let flow = tokio::select! {
            msg = rx.recv::<ToWorker>() => {
                let Ok(Some((msg, fds))) = msg else {
                    // Manager gone: nothing may keep serving without its supervision.
                    break exit::MANAGER_GONE;
                };
                s.on_message(msg, fds).await
            }
            ev = irx.recv() => {
                let Some(ev) = ev else { continue };
                s.on_internal(ev).await
            }
            _ = s.probe_tick.tick(), if s.started && !s.probe_in_flight => {
                s.spawn_probe();
                ControlFlow::Continue(())
            }
            _ = status_tick.tick() => s.on_status().await,
            reason = fatal_tunnel.fatal() => {
                // The manager ends this process as soon as it hears of the failure, so what the
                // Gateways owe their clients goes out first: a request in flight gets its 503
                // instead of a closed connection. Nothing is carried meanwhile (sealed).
                s.running.end_gateways().await;
                tracing::error!(%reason, "the tunnel failed for good");
                fatal(
                    &mut s.tx,
                    "TUNNEL_FATAL",
                    tr!(
                        "The WireGuard device hit an unrecoverable error",
                        "WireGuard 裝置發生無法恢復的錯誤",
                        "WireGuard デバイスで回復できないエラーが発生しました"
                    ),
                )
                .await;
                break exit::TUNNEL;
            }
            report = ban_reports.recv(), if reports_open => {
                // The guard holds the sender for the worker's lifetime; should the channel
                // close anyway, stop polling it rather than spin.
                let Some(report) = report else {
                    reports_open = false;
                    continue;
                };
                s.on_ban(report).await
            }
            request = async {
                match relay_requests.as_mut() {
                    Some(r) => r.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                let Some(request) = request else { continue };
                s.on_relay_request(request).await
            }
        };
        if let ControlFlow::Break(code) = flow {
            break code;
        }
    };
    teardown(s.running, s.tx, code).await
}

/// Time between the liveness probes of a healthy connection.
fn probe_interval(health: &HealthSettings) -> Duration {
    Duration::from_secs(u64::from(health.probe_interval_secs.max(5)))
}

/// The probe timer: its first tick one interval from now.
fn probe_ticker(health: &HealthSettings) -> Interval {
    let mut tick = tokio::time::interval(probe_interval(health));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.reset();
    tick
}

/// Seal, end every forward, listener and Gateway, then the tunnel; `Stopped` on a clean stop.
async fn teardown(mut running: Running, mut tx: FrameWriter, code: i32) -> i32 {
    running.tunnel.narrow_gate(GateState::Sealed);
    running.end_forwards();
    if let Some(server) = running.dns_server.take() {
        server.shutdown().await;
    }
    running.end_gateways().await;
    running.tunnel.shutdown().await;
    if code == exit::OK
        && let Err(e) = tx.send(&FromWorker::Stopped, &[]).await
    {
        tracing::debug!(error = %e, "Stopped not reported: the manager is gone");
    }
    code
}

impl Steady {
    /// Send to the manager; `Break(MANAGER_GONE)` when it is gone.
    async fn send(&mut self, msg: &FromWorker) -> ControlFlow<i32> {
        if self.tx.send(msg, &[]).await.is_err() {
            ControlFlow::Break(exit::MANAGER_GONE)
        } else {
            ControlFlow::Continue(())
        }
    }

    /// One message from the manager.
    async fn on_message(&mut self, msg: ToWorker, fds: Vec<OwnedFd>) -> ControlFlow<i32> {
        let running = &mut self.running;
        match msg {
            ToWorker::Start if !self.started => {
                self.started = true;
                self.start();
            }
            ToWorker::Start => {}
            ToWorker::Activate { permit } => return self.activate(permit).await,
            ToWorker::Tighten { reason } => {
                tracing::info!(%reason, "gate tightened by manager");
                running.tunnel.narrow_gate(GateState::Probe);
                running.reconcile_forwards();
            }
            ToWorker::ResetPayload { reason } => {
                tracing::info!(%reason, "payload flows reset by manager");
                running.tunnel.reset_flows(Some(FlowClass::Payload));
            }
            ToWorker::Seal { reason } => {
                tracing::warn!(%reason, "sealed by manager");
                running.tunnel.narrow_gate(GateState::Sealed);
                running.end_forwards();
            }
            ToWorker::SetOverlay(overlay) => return self.set_overlay(*overlay).await,
            ToWorker::Unban { source } => {
                let found = running.inbound.unban(source);
                return self.send(&FromWorker::Unbanned { source, found }).await;
            }
            ToWorker::AddGateway(spec) => {
                // Its listener is the frame's descriptor.
                let Some(fd) = fds.into_iter().next() else {
                    return ControlFlow::Break(exit::PROTOCOL);
                };
                running.add_gateway(spec, fd);
            }
            ToWorker::Relay { id } => {
                let socket = fds.into_iter().next().map(std::net::UdpSocket::from);
                if let Some(reply) = self.pending_relays.waiting.remove(&id) {
                    answer_relay(
                        reply,
                        socket.ok_or_else(|| std::io::Error::other("no relay socket")),
                    );
                }
            }
            ToWorker::RelayFailed { id, message } => {
                if let Some(reply) = self.pending_relays.waiting.remove(&id) {
                    answer_relay(reply, Err(std::io::Error::other(message)));
                }
            }
            ToWorker::RemoveGateway { id } => {
                if let Some(pos) = running
                    .gateways
                    .iter()
                    .position(|(spec, _, _)| spec.id == id)
                {
                    let (_, gateway, _) = running.gateways.remove(pos);
                    // Closing waits for its connections to end; the control loop does not.
                    tokio::spawn(gateway.shutdown());
                }
            }
            ToWorker::SetBandwidth(caps) => {
                running.shaper.set(caps);
                let applied = FromWorker::BandwidthApplied(running.shaper.caps());
                return self.send(&applied).await;
            }
            ToWorker::SetTransport(wire) => self.set_transport(*wire),
            ToWorker::SetForwards(specs) => {
                if let Some(f) = running.forwards.as_mut() {
                    f.set(specs);
                }
            }
            ToWorker::GrantForward(lease) => {
                if let Some(f) = running.forwards.as_mut() {
                    f.grant(&lease);
                }
            }
            ToWorker::RevokeForward { binding, lease_id } => {
                if let Some(f) = running.forwards.as_mut() {
                    f.revoke(binding, lease_id);
                }
            }
            ToWorker::Stop { grace_ms } => {
                running.tunnel.narrow_gate(GateState::Probe);
                running.end_forwards();
                tokio::time::sleep(Duration::from_millis(u64::from(grace_ms.min(2000)))).await;
                return ControlFlow::Break(exit::OK);
            }
            ToWorker::Ping { seq } => return self.send(&FromWorker::Pong { seq }).await,
            ToWorker::Hello { .. } | ToWorker::Configure(_) => {
                return ControlFlow::Break(exit::PROTOCOL);
            }
        }
        ControlFlow::Continue(())
    }

    /// `SetTransport`: the flows opened from now on take it, and the health probes follow it.
    fn set_transport(&mut self, wire: TransportWire) {
        let TransportWire { serial, transport } = wire;
        let running = &mut self.running;
        running
            .tunnel
            .set_transport(crate::transport::plan(&transport));
        if probe_interval(&transport.health) != probe_interval(&running.health) {
            self.probe_tick = probe_ticker(&transport.health);
        }
        running.health = transport.health;
        running.transport_serial = serial;
        tracing::info!(
            profile = %transport.name.en,
            serial,
            "transport replaced: flows opened from now on take it"
        );
    }

    /// `Start`: gate = probe, then the handshake and the first DNS probe as readiness evidence.
    fn start(&self) {
        self.running.tunnel.narrow_gate(GateState::Probe);
        let t = self.running.tunnel.clone();
        let dns = self.running.dns.clone();
        let timeout =
            Duration::from_secs(u64::from(self.running.health.handshake_timeout_secs.max(3)));
        let itx = self.itx.clone();
        tokio::spawn(async move {
            let r = async {
                // The DNS probe itself makes traffic, which also triggers the handshake.
                let probe = tokio::spawn({
                    let dns = dns.clone();
                    async move { dns.probe().await }
                });
                t.handshake(timeout).await.map_err(|e| match e {
                    vpn_tunnel::TunnelError::HandshakeTimeout(d) => {
                        let secs = d.as_secs();
                        tr!(
                            "The peer did not answer within {secs} s (mismatched keys, an unreachable endpoint, or UDP blocked)",
                            "{secs} 秒內對端沒有回應（金鑰不符、端點無法到達或 UDP 被封鎖）",
                            "{secs} 秒以内にピアから応答がありません（鍵の不一致、エンドポイントに到達できない、または UDP がブロックされています）"
                        )
                    }
                    other => Text::from(other.to_string()),
                })?;
                let endpoint = t
                    .peer()
                    .await
                    .and_then(|p| p.endpoint)
                    .ok_or("peer endpoint unknown")?;
                notify(&itx, Internal::Started(Ok(endpoint))).await;
                let p = probe.await.map_err(|e| e.to_string())?;
                notify(&itx, Internal::Probe(p)).await;
                Ok::<_, Text>(())
            }
            .await;
            if let Err(e) = r {
                notify(&itx, Internal::Started(Err(e))).await;
            }
        });
    }

    /// `Activate`: open the gate (the only way it opens) and confirm with `Ready`.
    async fn activate(&mut self, permit: u64) -> ControlFlow<i32> {
        let running = &mut self.running;
        let before = running.tunnel.gate();
        let state = running.tunnel.set_gate(GateState::Open);
        if state == GateState::Open && before != GateState::Open {
            // A new network epoch: an exit check made before this opening no
            // longer authorizes a Provider request.
            running.network_epoch.advance();
        }
        running.reconcile_forwards();
        if state == GateState::Open {
            self.degraded = false;
            self.probe_failures = 0;
            return self.send(&FromWorker::Ready { permit }).await;
        }
        ControlFlow::Continue(())
    }

    /// `SetOverlay`: install it if verified and newer, end flows it now denies, answer.
    async fn set_overlay(&mut self, overlay: OverlayWire) -> ControlFlow<i32> {
        let running = &self.running;
        let answer = install_overlay(&running.policy, overlay);
        if matches!(answer, FromWorker::OverlayApplied { .. }) {
            // New flows are checked against it from now on; established ones to
            // a newly denied destination end now too.
            let installed = running.policy.enforcement().overlay();
            let reset = running
                .tunnel
                .reset_tcp_flows_to(FlowClass::Payload, |ip| installed.set.contains(ip));
            if reset > 0 {
                tracing::info!(
                    reset,
                    revision = installed.revision,
                    "flows to newly blocklisted destinations reset"
                );
            }
            // Forwarded UDP flows from a newly blocklisted source end too.
            if let Some(f) = &running.forwards {
                f.drop_sources(|ip| installed.set.contains(ip));
            }
        }
        self.send(&answer).await
    }

    /// An event of the worker's own tasks (readiness, probe results).
    async fn on_internal(&mut self, ev: Internal) -> ControlFlow<i32> {
        let msg = match ev {
            Internal::Started(Ok(endpoint)) => FromWorker::TunnelUp { endpoint },
            Internal::Started(Err(e)) => {
                fatal(
                    &mut self.tx,
                    "HANDSHAKE_FAILED",
                    tr!(
                        "The WireGuard handshake did not complete: {why}",
                        "WireGuard 握手未完成：{why}",
                        "WireGuard のハンドシェイクが完了しませんでした：{why}";
                        why = e
                    ),
                )
                .await;
                return ControlFlow::Break(exit::TUNNEL);
            }
            Internal::Probe(r) => self.on_probe(r).await?,
        };
        self.send(&msg).await
    }

    /// The inner watchdog's verdict on one probe; the report to send for it.
    async fn on_probe(&mut self, r: Result<ProbeOk, ResolveError>) -> ControlFlow<i32, FromWorker> {
        self.probe_in_flight = false;
        let report = match r {
            Ok(probe) => {
                // One question and its answer through the tunnel: the round trip flows are
                // tuned for until a TCP connection's handshake has measured it.
                self.running.tunnel.record_probe(probe.latency);
                self.tunnel_answers().await?;
                FromWorker::Probe {
                    ok: true,
                    latency_ms: Some(u32::try_from(probe.latency.as_millis()).unwrap_or(u32::MAX)),
                    error: None,
                    inconclusive: false,
                    fallback: probe.fallback,
                    interrupted: None,
                }
            }
            // Not run (flow/memory limit, or a probe still running): no verdict
            // on the tunnel, so it neither counts as a failure nor resets them.
            Err(ResolveError::Overloaded) => {
                self.retry_soon();
                FromWorker::Probe {
                    ok: false,
                    latency_ms: None,
                    error: Some(probe_not_run()),
                    inconclusive: true,
                    fallback: None,
                    interrupted: None,
                }
            }
            // Names fail, as the DNS profile asks while all its servers do; whether the tunnel
            // lives is for its WireGuard session to say.
            Err(ResolveError::Interrupted) => {
                let why = self.running.dns.probe_failure().unwrap_or_default();
                self.probe_tick.reset_after(PROBE_RETRY_INTERRUPTED);
                let fresh = self
                    .running
                    .tunnel
                    .peer()
                    .await
                    .and_then(|p| p.last_handshake)
                    .is_some_and(|age| age < SESSION_ALIVE);
                let error = if fresh {
                    self.tunnel_answers().await?;
                    None
                } else {
                    self.tunnel_fails().await?;
                    let secs = SESSION_ALIVE.as_secs();
                    Some(tr!(
                        "{interrupted}; the WireGuard session has not been renewed for over {secs} s: {why}",
                        "{interrupted}；WireGuard 工作階段超過 {secs} 秒沒有更新：{why}",
                        "{interrupted}；WireGuard のセッションが {secs} 秒以上更新されていません：{why}";
                        interrupted = ResolveError::Interrupted.text(),
                        why = why.clone()
                    ))
                };
                FromWorker::Probe {
                    ok: fresh,
                    latency_ms: None,
                    error,
                    inconclusive: false,
                    fallback: None,
                    interrupted: Some(why),
                }
            }
            Err(e) => {
                self.tunnel_fails().await?;
                // Why, server by server (the manager logs it and shows it in the status).
                let message = self.running.dns.probe_failure().map_or_else(
                    || e.text(),
                    |servers| {
                        tr!(
                            "{failed}: {servers}",
                            "{failed}：{servers}",
                            "{failed}：{servers}";
                            failed = e.text(),
                            servers = servers
                        )
                    },
                );
                FromWorker::Probe {
                    ok: false,
                    latency_ms: None,
                    error: Some(message),
                    inconclusive: false,
                    fallback: None,
                    interrupted: None,
                }
            }
        };
        ControlFlow::Continue(report)
    }

    /// A probe without a verdict, or one that failed, while the gate is not open: the next one
    /// soon (see [`PROBE_RETRY`]).
    fn retry_soon(&mut self) {
        if self.running.tunnel.gate() != GateState::Open {
            self.probe_tick.reset_after(PROBE_RETRY);
        }
    }

    /// The probe shows the tunnel alive: failures start over, and a tightened gate is reported
    /// recovered (only the manager may re-open it).
    async fn tunnel_answers(&mut self) -> ControlFlow<i32> {
        self.probe_failures = 0;
        if self.degraded {
            self.degraded = false;
            self.send(&FromWorker::Recovered).await?;
        }
        ControlFlow::Continue(())
    }

    /// The probe counts against the tunnel: past the threshold no new payload is admitted.
    async fn tunnel_fails(&mut self) -> ControlFlow<i32> {
        self.retry_soon();
        self.probe_failures += 1;
        if self.probe_failures >= self.running.health.probe_failures.max(1)
            && self.running.tunnel.gate() == GateState::Open
        {
            // Stop admitting new payload; existing flows stay (they can only
            // use the tunnel). Only the manager may re-open.
            self.running.tunnel.narrow_gate(GateState::Probe);
            self.running.reconcile_forwards();
            self.degraded = true;
            self.send(&FromWorker::Degraded {
                code: "PROBE_FAILED".into(),
                message: tr!(
                    "DNS probes through the tunnel failed repeatedly; new connections are no longer accepted",
                    "經 tunnel 的 DNS 探測連續失敗，已停止接受新連線",
                    "tunnel 経由の DNS ヘルスチェックが連続して失敗したため、新しい接続の受け付けを停止しました"
                ),
            })
            .await?;
        }
        ControlFlow::Continue(())
    }

    /// A steady-state probe of the inner watchdog.
    fn spawn_probe(&mut self) {
        self.probe_in_flight = true;
        let dns = self.running.dns.clone();
        let itx = self.itx.clone();
        tokio::spawn(async move {
            let r = dns.probe().await;
            notify(&itx, Internal::Probe(r)).await;
        });
    }

    /// The once-a-second status report (and the orphan check).
    async fn on_status(&mut self) -> ControlFlow<i32> {
        if process::orphaned() {
            return ControlFlow::Break(exit::MANAGER_GONE);
        }
        // Retries forwards whose port or listener was not available a moment ago.
        self.running.reconcile_forwards();
        let status = collect_status(&self.running).await;
        self.send(&FromWorker::Status(Box::new(status))).await
    }

    /// A new auto-ban: end the source's connections and report it.
    async fn on_ban(&mut self, report: BanReport) -> ControlFlow<i32> {
        // A banned source's open connections end as well (forwarded in, or to it): of
        // every address its scope covers (the IPv4 address, or the IPv6 /64).
        let source = report.source;
        let covered = |ip| ban_scope(ip) == source;
        self.running
            .tunnel
            .reset_tcp_flows_to(FlowClass::Payload, covered);
        if let Some(f) = &self.running.forwards {
            f.drop_sources(covered);
        }
        self.send(&FromWorker::Banned(report)).await
    }

    /// A strict Gateway's relay-socket request, forwarded to the manager.
    async fn on_relay_request(&mut self, request: RelayRequest) -> ControlFlow<i32> {
        let pending = &mut self.pending_relays;
        // Forget requests whose Gateway gave up waiting.
        pending.waiting.retain(|_, reply| !reply.is_closed());
        if pending.waiting.len() >= MAX_RELAY_REQUESTS {
            answer_relay(
                request.reply,
                Err(std::io::Error::other("too many relay requests")),
            );
            return ControlFlow::Continue(());
        }
        pending.next_id += 1;
        let id = pending.next_id;
        pending.waiting.insert(id, request.reply);
        let ask = FromWorker::RelayRequest {
            id,
            client_ip: request.client_ip,
        };
        self.send(&ask).await
    }
}

/// Hand an event of the worker's own tasks to the control loop. Once that loop has ended, the
/// worker is exiting and nothing waits for the event any more.
async fn notify(itx: &mpsc::Sender<Internal>, event: Internal) {
    if itx.send(event).await.is_err() {
        tracing::trace!("internal event dropped: the control loop has ended");
    }
}

/// Answer a strict Gateway's relay-socket request. A Gateway that gave up waiting no longer
/// listens; the socket of the answer is then closed with it.
fn answer_relay(
    reply: oneshot::Sender<std::io::Result<std::net::UdpSocket>>,
    answer: std::io::Result<std::net::UdpSocket>,
) {
    if reply.send(answer).is_err() {
        tracing::trace!("relay answer dropped: the Gateway stopped waiting");
    }
}

/// Report why the worker ends; the exit code says it too, should the manager be gone already.
async fn fatal(tx: &mut FrameWriter, code: &str, message: impl Into<Text>) {
    let fatal = FromWorker::Fatal {
        code: code.into(),
        message: message.into(),
    };
    if let Err(e) = tx.send(&fatal, &[]).await {
        tracing::debug!(code, error = %e, "fatal error not reported: the manager is gone");
    }
}

type ConfigError = (&'static str, i32, Text);

/// Install a new blocklist overlay if it is what the manager says it is. The answer carries the
/// digest of what is now enforced, computed here from the installed ranges.
fn install_overlay(policy: &DestinationPolicy, wire: OverlayWire) -> FromWorker {
    let revision = wire.revision;
    let overlay = Overlay::new(revision, wire.set);
    if overlay.digest != wire.digest {
        return FromWorker::OverlayRejected {
            revision,
            reason: tr!(
                "The blocklist content does not match its digest; not applied",
                "封鎖清單內容與摘要不符，未套用",
                "ブロックリストの内容がダイジェストと一致しないため、適用しませんでした"
            ),
        };
    }
    match policy.enforcement().swap(overlay) {
        Ok(installed) => FromWorker::OverlayApplied {
            revision: installed.revision,
            digest: installed.digest.clone(),
        },
        Err(current) => {
            let newer = current.revision;
            FromWorker::OverlayRejected {
                revision,
                reason: tr!(
                    "A newer revision ({newer}) is already in force",
                    "已在執行較新的版本 {newer}",
                    "より新しいリビジョン {newer} がすでに適用されています"
                ),
            }
        }
    }
}

/// The destination policy, the inbound guard sharing its overlay, and the guard's ban reports.
type Security = (
    Arc<DestinationPolicy>,
    Arc<InboundGuard>,
    mpsc::Receiver<BanReport>,
);

/// The security policy of the generation: the base rules, the initial overlay (verified against
/// its digest), and the inbound guard with the bans carried over.
fn security(spec: PolicySpec) -> Result<Security, ConfigError> {
    let overlay = match spec.overlay {
        Some(wire) => {
            let overlay = Overlay::new(wire.revision, wire.set);
            if overlay.digest != wire.digest {
                return Err((
                    "OVERLAY_DIGEST",
                    exit::CONFIG,
                    tr!(
                        "The blocklist content does not match its digest",
                        "封鎖清單內容與摘要不符",
                        "ブロックリストの内容がダイジェストと一致しません"
                    ),
                ));
            }
            overlay
        }
        None => Overlay::empty(),
    };
    let enforcement = Arc::new(Enforcement::new(
        overlay,
        spec.auto_ban.max_bans.max(1) as usize,
    ));
    let policy = Arc::new(DestinationPolicy::new(
        BasePolicy {
            allow_private: spec.allow_private,
            allowed_destinations: spec.allowed_destinations,
            allowed_ports: spec.allowed_ports,
            blocked_ports: spec.blocked_ports,
        },
        enforcement.clone(),
    ));
    let (inbound, reports) = InboundGuard::new(enforcement, spec.auto_ban, spec.exempt);
    for ban in spec.bans {
        inbound.restore_ban(
            ban.source,
            Duration::from_secs(u64::from(ban.remaining_secs)),
        );
    }
    Ok((policy, inbound, reports))
}

/// The sandbox descriptors of a strict worker, in `Configure` order.
#[cfg_attr(
    not(target_os = "linux"),
    expect(
        dead_code,
        reason = "only Linux starts a strict worker; elsewhere the descriptors are checked and closed unread"
    )
)]
struct StrictFds {
    tun: OwnedFd,
    underlay: OwnedFd,
    dns_udp: OwnedFd,
    dns_tcp: OwnedFd,
}

async fn configure(
    config: WorkerConfig,
    mut fds: Vec<OwnedFd>,
) -> Result<(Running, mpsc::Receiver<BanReport>), ConfigError> {
    let strict_fds = strict_descriptors(&config, &mut fds)?;
    let key_lock = lock_key(&config.key_lock_path).await?;

    let t = &config.tunnel;
    let private_key = t.private_key.as_key().ok_or_else(|| {
        (
            "BAD_KEY",
            exit::CONFIG,
            Text::from("private key must be 32 bytes"),
        )
    })?;
    let psk = preshared_key(t)?;
    let tuning = PlaneTuning::of(&config);
    // Before the data plane: a strict sandbox checks its Apps' new flows against it.
    let (policy, inbound, ban_reports) = security(config.policy)?;
    let peer = peer_config(t, psk);
    let (tunnel, sandbox_dns) = start_plane(
        config.strict.as_ref(),
        strict_fds,
        private_key,
        peer,
        t,
        tuning,
        &policy,
    )
    .await?;
    let net = tunnel.connector();

    let (dns, dns_counters) = resolver(&config.dns, &net);
    let forwards = port_controller(
        &tunnel,
        &inbound,
        config.tunnel.addresses.clone(),
        config.forwards,
    );
    let dns_server = spawn_dns_server(sandbox_dns, &tunnel, &dns)?;
    let (relays, relay_requests) = relay_sockets(config.strict.is_some());

    let gateway_key: Option<Arc<Zeroizing<[u8; 32]>>> = config
        .gateway_key
        .as_ref()
        .and_then(vpn_ipc::SecretBytes::as_key)
        .map(Arc::new);
    let network_epoch = NetworkEpoch::default();
    let route = vpn_ipc::relay::RelayRoute::Instance {
        instance_id: config.instance_id,
        generation: config.generation,
    };
    let connector = spawn_connector(
        config.connector_path.as_deref(),
        route,
        &network_epoch,
        &net,
        &dns,
        &policy,
    )?;

    let max_udp_associations = config.limits.max_udp_flows;
    // In force before the gate can open, like every other limit of the generation.
    let shaper = Shaper::new(bandwidth_caps(&config.limits));
    let gateways = config
        .gateways
        .into_iter()
        .zip(fds)
        .map(|(spec, fd)| {
            spawn_gateway(
                spec,
                fd,
                &net,
                &dns,
                &policy,
                gateway_key.as_ref(),
                &shaper,
                max_udp_associations,
                &relays,
            )
            .map_err(|e| ("GATEWAY_START", exit::CONFIG, e.to_string().into()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let running = Running {
        tunnel,
        dns,
        dns_counters,
        policy,
        inbound,
        forwards: Some(forwards),
        gateways,
        connector,
        network_epoch,
        dns_server,
        relays,
        relay_requests,
        gateway_key,
        shaper,
        max_udp_associations,
        generation: config.generation,
        health: config.transport.transport.health,
        transport_serial: config.transport.serial,
        _key_lock: key_lock,
        started_at: Instant::now(),
    };
    Ok((running, ban_reports))
}

/// The Instance's resolver, through the tunnel, and its counters.
fn resolver(spec: &DnsSpec, net: &AnyConnector) -> (DnsResolver<AnyConnector>, Arc<DnsCounters>) {
    let counters = Arc::new(DnsCounters::default());
    let dns = DnsResolver::new(
        net.clone(),
        DnsConfig {
            servers: spec.servers.clone(),
            cache: spec.cache.clone(),
            query_timeout: Duration::from_millis(u64::from(spec.query_timeout_ms)),
            attempts: spec.attempts,
            max_in_flight: 256,
            tls_roots: None,
            fallback: spec.fallback.clone(),
            on_failure: spec.on_failure,
        },
        counters.clone(),
    );
    (dns, counters)
}

/// The private management connector's socket, when the manager asked for one.
fn spawn_connector(
    path: Option<&str>,
    route: vpn_ipc::relay::RelayRoute,
    network_epoch: &NetworkEpoch,
    net: &AnyConnector,
    dns: &DnsResolver<AnyConnector>,
    policy: &Arc<DestinationPolicy>,
) -> Result<Option<ConnectorSocket>, ConfigError> {
    let Some(path) = path else {
        return Ok(None);
    };
    ConnectorSocket::spawn(
        std::path::Path::new(path),
        route,
        network_epoch.clone(),
        net.clone(),
        dns.clone(),
        policy.clone(),
    )
    .map(Some)
    .map_err(|e| ("CONNECTOR_START", exit::CONFIG, e.to_string().into()))
}

/// The tunnel's peer.
fn peer_config(t: &TunnelSpec, preshared_key: Option<Zeroizing<[u8; 32]>>) -> PeerConfig {
    PeerConfig {
        public_key: t.peer_public_key,
        preshared_key,
        endpoint: Some(t.endpoint),
        allowed_ips: t.allowed_ips.clone(),
        persistent_keepalive: t.persistent_keepalive,
    }
}

/// The port forwards of the generation, not yet leased.
///
/// They listen through the userspace netstack, or on the strict plane on kernel sockets of the
/// sandbox's tunnel addresses (the packet filter lets new connections reach them only while a
/// forward listens). Either way the App is reached on loopback: in strict mode this process is
/// inside the sandbox, where the App listens.
fn port_controller(
    tunnel: &Plane,
    inbound: &Arc<InboundGuard>,
    networks: Vec<ipnetwork::IpNetwork>,
    specs: Vec<ForwardSpecWire>,
) -> PortController<vpn_tunnel::AnyInbound> {
    let mut forwards = PortController::new(
        tunnel.inbound(),
        inbound.clone(),
        networks,
        DEFAULT_TCP_IDLE_TIMEOUT,
    );
    forwards.set(specs);
    forwards
}

/// What the data plane admits, and what each admitted flow gets.
struct PlaneTuning {
    limits: NetstackLimits,
    transport: TransportPlan,
}

impl PlaneTuning {
    fn of(config: &WorkerConfig) -> Self {
        Self {
            limits: netstack_limits(&config.limits),
            transport: crate::transport::plan(&config.transport.transport),
        }
    }
}

/// The bandwidth caps of the generation's limits.
const fn bandwidth_caps(limits: &InstanceLimits) -> vpn_domain::BandwidthCaps {
    vpn_domain::BandwidthCaps {
        download_bps: limits.download_bps,
        upload_bps: limits.upload_bps,
    }
}

/// The data plane's flow and memory limits of the generation.
fn netstack_limits(limits: &InstanceLimits) -> NetstackLimits {
    NetstackLimits {
        max_tcp_flows: limits.max_tcp_flows as usize,
        max_udp_flows: limits.max_udp_flows as usize,
        memory_budget: (limits.memory_mib as usize).saturating_mul(1024 * 1024),
        ..NetstackLimits::default()
    }
}

/// Where the Gateways' SOCKS5 UDP relay sockets come from.
///
/// A strict worker's own loopback is the sandbox's: relay sockets come from the manager, asked through the returned channel.
fn relay_sockets(strict: bool) -> (RelaySockets, Option<mpsc::Receiver<RelayRequest>>) {
    if strict {
        let (tx, rx) = mpsc::channel(MAX_RELAY_REQUESTS);
        (RelaySockets::Manager(tx), Some(rx))
    } else {
        (RelaySockets::Local, None)
    }
}

/// Take the identity lock: the proof that no older process still uses this key.
async fn lock_key(path: &str) -> Result<FileLock, ConfigError> {
    FileLock::acquire_within(std::path::Path::new(path), Duration::from_secs(3))
        .await
        .map_err(|e| {
            (
                "KEY_IN_USE",
                exit::KEY_IN_USE,
                tr!(
                    "This WireGuard key is still in use by another process: {e}",
                    "這把 WireGuard 金鑰仍被另一個程序使用：{e}",
                    "この WireGuard の鍵はまだ別のプロセスが使用しています：{e}"
                ),
            )
        })
}

/// Check the descriptor count and split off a strict worker's sandbox descriptors (after the
/// Gateways' listeners).
fn strict_descriptors(
    config: &WorkerConfig,
    fds: &mut Vec<OwnedFd>,
) -> Result<Option<StrictFds>, ConfigError> {
    let extra = if config.strict.is_some() {
        StrictWire::DESCRIPTORS
    } else {
        0
    };
    if fds.len() != config.gateways.len() + extra {
        return Err((
            "FD_MISMATCH",
            exit::PROTOCOL,
            "listener descriptors do not match the gateway list".into(),
        ));
    }
    if extra == 0 {
        return Ok(None);
    }
    let mut rest = fds.split_off(config.gateways.len()).into_iter();
    match (rest.next(), rest.next(), rest.next(), rest.next()) {
        (Some(tun), Some(underlay), Some(dns_udp), Some(dns_tcp)) => Ok(Some(StrictFds {
            tun,
            underlay,
            dns_udp,
            dns_tcp,
        })),
        _ => Err((
            "FD_MISMATCH",
            exit::PROTOCOL,
            "sandbox descriptors missing".into(),
        )),
    }
}

/// The tunnel's preshared key, if it has one.
fn preshared_key(t: &TunnelSpec) -> Result<Option<Zeroizing<[u8; 32]>>, ConfigError> {
    t.preshared_key
        .as_ref()
        .map(|k| {
            k.as_key().ok_or_else(|| {
                (
                    "BAD_KEY",
                    exit::CONFIG,
                    Text::from("preshared key must be 32 bytes"),
                )
            })
        })
        .transpose()
}

/// Start the data plane: the strict sandbox's when this worker is strict, else the netstack.
async fn start_plane(
    strict: Option<&StrictWire>,
    strict_fds: Option<StrictFds>,
    private_key: Zeroizing<[u8; 32]>,
    peer: PeerConfig,
    t: &TunnelSpec,
    tuning: PlaneTuning,
    policy: &Arc<DestinationPolicy>,
) -> Result<(Plane, SandboxDns), ConfigError> {
    if let (Some(strict), Some(fds)) = (strict, strict_fds) {
        return start_strict(strict, fds, private_key, peer, t, tuning, policy).await;
    }
    let tunnel = Tunnel::start(TunnelConfig {
        private_key,
        peer,
        addresses: t.addresses.clone(),
        mtu: t.mtu,
        underlay: UdpSource::Bind(None),
        underlay_policy: PeerPolicy::Pinned(vec![t.endpoint]),
        listen_port: 0,
        limits: tuning.limits,
        transport: tuning.transport,
    })
    .await
    .map_err(|e| ("TUNNEL_START", exit::TUNNEL, e.to_string().into()))?;
    Ok((Plane::Netstack(tunnel), None))
}

/// The sandbox's Apps ask the same resolver, while the payload gate is open.
fn spawn_dns_server(
    sandbox_dns: SandboxDns,
    tunnel: &Plane,
    dns: &DnsResolver<AnyConnector>,
) -> Result<Option<DnsServer>, ConfigError> {
    let Some((udp, tcp)) = sandbox_dns else {
        return Ok(None);
    };
    let plane = tunnel.clone();
    let open = Arc::new(move || plane.gate() == GateState::Open);
    DnsServer::spawn(
        std::net::UdpSocket::from(udp),
        StdTcpListener::from(tcp),
        dns.clone(),
        open,
    )
    .map(Some)
    .map_err(|e| ("DNS_LISTENER", exit::CONFIG, e.to_string().into()))
}

/// The DNS listener sockets of a strict sandbox (UDP, TCP).
type SandboxDns = Option<(OwnedFd, OwnedFd)>;

/// Bring up the strict data plane: `GotaTun` between the sandbox's TUN device and the
/// host-namespace underlay socket. Refuses unless this process really is in a closed sandbox
/// network namespace (only `lo` and the TUN device).
#[cfg(target_os = "linux")]
async fn start_strict(
    strict: &StrictWire,
    fds: StrictFds,
    private_key: Zeroizing<[u8; 32]>,
    peer: PeerConfig,
    t: &TunnelSpec,
    tuning: PlaneTuning,
    policy: &Arc<DestinationPolicy>,
) -> Result<(Plane, SandboxDns), ConfigError> {
    let tunnel = vpn_tunnel::strict::StrictTunnel::start(vpn_tunnel::strict::StrictTunnelConfig {
        private_key,
        peer,
        addresses: t.addresses.clone(),
        mtu: t.mtu,
        tun: fds.tun,
        tun_name: strict.tun_name.clone(),
        underlay: std::net::UdpSocket::from(fds.underlay),
        underlay_policy: PeerPolicy::Pinned(vec![t.endpoint]),
        limits: tuning.limits,
        transport: tuning.transport,
        policy: policy.clone(),
    })
    .await
    .map_err(|e| ("SANDBOX_TUNNEL", exit::TUNNEL, e.to_string().into()))?;
    tracing::info!(epoch = strict.sandbox_epoch, "strict data plane up");
    Ok((Plane::Strict(tunnel), Some((fds.dns_udp, fds.dns_tcp))))
}

#[cfg(not(target_os = "linux"))]
#[expect(
    clippy::unused_async,
    reason = "keeps the signature of the Linux `start_strict`, so its one caller awaits either"
)]
async fn start_strict(
    _strict: &StrictWire,
    _fds: StrictFds,
    _private_key: Zeroizing<[u8; 32]>,
    _peer: PeerConfig,
    _t: &TunnelSpec,
    _tuning: PlaneTuning,
    _policy: &Arc<DestinationPolicy>,
) -> Result<(Plane, SandboxDns), ConfigError> {
    Err((
        "STRICT_UNSUPPORTED",
        exit::CONFIG,
        "strict mode needs Linux network namespaces".into(),
    ))
}

/// Serve one Gateway on the listener the manager handed over.
#[expect(
    clippy::too_many_arguments,
    reason = "the Gateway's spec, listener and every shared part of the generation it serves"
)]
fn spawn_gateway(
    spec: GatewaySpecWire,
    listener: OwnedFd,
    net: &AnyConnector,
    dns: &DnsResolver<AnyConnector>,
    policy: &Arc<DestinationPolicy>,
    auth_key: Option<&Arc<Zeroizing<[u8; 32]>>>,
    shaper: &Arc<Shaper>,
    max_udp_associations: u32,
    relays: &RelaySockets,
) -> std::io::Result<(GatewaySpecWire, Gateway, Arc<GatewayCounters>)> {
    let counters = Arc::new(GatewayCounters::default());
    let gateway = Gateway::spawn_with_relays(
        StdTcpListener::from(listener),
        GatewayConfig {
            id: spec.id,
            kind: spec.kind,
            udp: spec.udp,
            max_connections: spec.max_connections,
            max_udp_associations,
            handshake_timeout: Duration::from_secs(10),
            udp_idle_timeout: Duration::from_secs(60),
            tcp_idle_timeout: DEFAULT_TCP_IDLE_TIMEOUT,
            auth_key: auth_key.cloned(),
        },
        GatewayDeps {
            connector: net.clone(),
            resolver: dns.clone(),
            policy: policy.clone(),
            counters: counters.clone(),
            shaper: shaper.clone(),
        },
        relays.clone(),
    )?;
    Ok((spec, gateway, counters))
}

/// What the transport does now: the range new flows take and the round trip it was chosen for.
fn transport_status(r: &Running) -> TransportStatusWire {
    let now = r.tunnel.transport();
    TransportStatusWire {
        serial: r.transport_serial,
        band: u32::try_from(now.band).unwrap_or(u32::MAX),
        rtt_us: now
            .rtt
            .map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX)),
        buffers_grown: now.grown,
        growth_refused: now.growth_refused,
        congestion: r.tunnel.congestion(),
    }
}

async fn collect_status(r: &Running) -> WorkerStatus {
    let peer = r.tunnel.peer().await;
    let gate = r.tunnel.gate();
    let c = r.tunnel.counters();
    let me = resources::sample_self();
    let relayed = r.forwards.as_ref().map_or((0, 0), PortController::relayed);
    WorkerStatus {
        generation: r.generation,
        monotonic_ms: u64::try_from(r.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
        gate: Some(match gate {
            GateState::Closed => GateWire::Closed,
            GateState::Probe => GateWire::Probe,
            GateState::Open => GateWire::Open,
            GateState::Sealed => GateWire::Sealed,
        }),
        last_handshake_ms_ago: peer
            .as_ref()
            .and_then(|p| p.last_handshake)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
        endpoint: peer.as_ref().and_then(|p| p.endpoint),
        wg_rx_bytes: c.wg_rx_bytes,
        wg_tx_bytes: c.wg_tx_bytes,
        underlay_blocked: c.underlay_blocked,
        tunnel_rx_bytes: c.tunnel_rx_bytes,
        tunnel_tx_bytes: c.tunnel_tx_bytes,
        active_tcp: c.active_tcp,
        active_udp: c.active_udp,
        admission_rejected: c.admission_rejected,
        memory_reserved: c.memory_reserved,
        dns_queries: r.dns_counters.queries.load(Ordering::Relaxed),
        dns_cache_hits: r.dns_counters.cache_hits.load(Ordering::Relaxed),
        dns_failures: r.dns_counters.failures.load(Ordering::Relaxed),
        dns_latency_buckets: r.dns_counters.latency.snapshot().to_vec(),
        dns_latency_sum_us: r.dns_counters.latency.sum_us.load(Ordering::Relaxed),
        dns_timeouts: r.dns_counters.latency.timeouts.load(Ordering::Relaxed),
        gateways: r
            .gateways
            .iter()
            .map(|(spec, _gw, c)| GatewayStatusWire {
                id: Some(spec.id),
                serving: gate == GateState::Open,
                tcp_accepted: c.tcp_accepted.load(Ordering::Relaxed),
                tcp_rejected: c.tcp_rejected.load(Ordering::Relaxed),
                tcp_active: c.tcp_active.load(Ordering::Relaxed),
                udp_active: c.udp_associations_active.load(Ordering::Relaxed),
                udp_dropped: c.udp_dropped.load(Ordering::Relaxed),
                payload_rx_bytes: c.payload_rx_bytes.load(Ordering::Relaxed),
                payload_tx_bytes: c.payload_tx_bytes.load(Ordering::Relaxed),
                ssh_rx_bytes: c.ssh_rx_bytes.load(Ordering::Relaxed),
                ssh_tx_bytes: c.ssh_tx_bytes.load(Ordering::Relaxed),
                ssh_pull_rx_bytes: c.ssh_pull_rx_bytes.load(Ordering::Relaxed),
                ssh_pull_tx_bytes: c.ssh_pull_tx_bytes.load(Ordering::Relaxed),
                ssh_sessions: c.ssh_sessions.load(Ordering::Relaxed),
                connect_latency_buckets: c.connect_latency.snapshot().to_vec(),
                connect_latency_count: c.connect_latency.count.load(Ordering::Relaxed),
                connect_latency_sum_us: c.connect_latency.sum_us.load(Ordering::Relaxed),
                connect_timeouts: c.connect_latency.timeouts.load(Ordering::Relaxed),
                connect_failures: c.connect_failures.load(Ordering::Relaxed),
                connect_not_found: c.connect_not_found.load(Ordering::Relaxed),
            })
            .collect(),
        rss_bytes: me.rss_bytes,
        cpu_ns: Some(me.cpu_ns),
        shaping: Some(r.shaper.wire()),
        transport: Some(transport_status(r)),
        control_flows: Some(r.tunnel.control_flows()),
        probe_flows: Some(r.dns.probes_in_flight()),
        connector_flows: Some(r.connector.as_ref().map_or(0, ConnectorSocket::active)),
        forwards: r.forwards.as_ref().map_or_default(PortController::status),
        forward_rx_bytes: relayed.0,
        forward_tx_bytes: relayed.1,
        sandbox: c.sandbox,
        sandbox_ports: r.tunnel.sandbox_ports(),
        app_payload: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use vpn_domain::AutoBanSettings;
    use vpn_domain::ipset::IpRangeSet;

    use super::*;
    use crate::inbound::InboundDenied;
    use crate::policy::Denied;
    use vpn_ipc::worker::BanWire;

    fn set(nets: &[&str]) -> IpRangeSet {
        IpRangeSet::from_networks(nets.iter().map(|n| n.parse().unwrap()))
    }

    fn wire(revision: u64, set: IpRangeSet) -> OverlayWire {
        OverlayWire {
            revision,
            digest: set.digest(),
            set,
        }
    }

    fn spec(overlay: Option<OverlayWire>) -> PolicySpec {
        PolicySpec {
            allow_private: vec!["10.99.0.0/24".parse().unwrap()],
            blocked_ports: vec![25],
            allowed_destinations: Vec::new(),
            allowed_ports: Vec::new(),
            overlay,
            auto_ban: AutoBanSettings {
                enabled: true,
                threshold: 2,
                ..AutoBanSettings::default()
            },
            bans: vec![BanWire {
                source: "93.184.216.34".parse().unwrap(),
                remaining_secs: 600,
            }],
            exempt: vec!["10.99.0.1".parse().unwrap()],
        }
    }

    #[test]
    fn the_initial_overlay_is_verified_and_bans_carry_over() {
        let (policy, inbound, _reports) =
            security(spec(Some(wire(5, set(&["203.0.113.0/24"]))))).unwrap();
        let check = |s: &str| policy.check(s.parse().unwrap());
        assert_eq!(check("203.0.113.1:443"), Err(Denied::PrivateNotAllowed));
        assert_eq!(check("10.99.0.1:53"), Ok(()));
        assert_eq!(policy.enforcement().overlay().revision, 5);
        assert_matches!(
            inbound.admit("93.184.216.34".parse().unwrap()),
            Err(InboundDenied::Banned { .. })
        );
        assert_eq!(check("93.184.216.34:443"), Err(Denied::Banned));
        // The exempt DNS server is never banned however often it connects.
        for _ in 0..10 {
            assert_eq!(inbound.admit("10.99.0.1".parse().unwrap()), Ok(()));
        }

        // A configuration whose overlay does not match its digest is refused outright.
        let mut bad = wire(5, set(&["203.0.113.0/24"]));
        bad.digest = set(&["192.0.2.0/24"]).digest();
        let err = security(spec(Some(bad))).err().unwrap();
        assert_eq!(err.0, "OVERLAY_DIGEST");
        // No overlay at all: an empty one, revision 0.
        let (policy, _, _) = security(spec(None)).unwrap();
        assert_eq!(policy.enforcement().overlay().revision, 0);
    }

    #[test]
    fn overlays_are_installed_only_when_verified_and_newer() {
        let (policy, _inbound, _reports) =
            security(spec(Some(wire(5, IpRangeSet::new())))).unwrap();
        let next = set(&["1.1.1.0/24"]);
        match install_overlay(&policy, wire(6, next.clone())) {
            FromWorker::OverlayApplied { revision, digest } => {
                assert_eq!(revision, 6);
                assert_eq!(
                    digest,
                    next.digest(),
                    "the worker's own digest of what it enforces"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            policy.check("1.1.1.1:443".parse().unwrap()),
            Err(Denied::Blocklisted)
        );
        // A wrong digest or an older revision changes nothing.
        let mut lying = wire(7, IpRangeSet::new());
        lying.digest = next.digest();
        assert_matches!(
            install_overlay(&policy, lying),
            FromWorker::OverlayRejected { revision: 7, .. }
        );
        assert_matches!(
            install_overlay(&policy, wire(4, IpRangeSet::new())),
            FromWorker::OverlayRejected { revision: 4, .. }
        );
        assert_eq!(
            policy.check("1.1.1.1:443".parse().unwrap()),
            Err(Denied::Blocklisted)
        );
        // Detaching is a newer, empty overlay.
        assert_matches!(
            install_overlay(&policy, wire(8, IpRangeSet::new())),
            FromWorker::OverlayApplied { revision: 8, .. }
        );
        assert_eq!(policy.check("1.1.1.1:443".parse().unwrap()), Ok(()));
    }
}
