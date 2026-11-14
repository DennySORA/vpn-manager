//! Connection to the manager (the "Store helper" client plus lifecycle intents) with automatic
//! reconnection, and the event pump that turns manager events into SSE events and live rates.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use vpn_domain::{
    ApiError, ErrorCode, GatewayRates, InstanceId, LiveRates, SandboxRates, ServerEvent,
    ShapingRates, Timestamp, tr,
};
use vpn_ipc::control::{Call, ControlClient, Event, Reply};
use vpn_ipc::worker::WorkerStatus;
use vpn_sync::RwLock;

use crate::hub::Hub;

/// How often the link checks that the manager still answers, and how long an answer may take.
const LIVENESS_EVERY: Duration = Duration::from_secs(15);
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(15);

pub struct ManagerLink {
    path: PathBuf,
    client: RwLock<Option<ControlClient>>,
    hub: Arc<Hub>,
    liveness: (Duration, Duration),
}

fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::Unavailable,
        tr!(
            "The core service (manager) is not connected; VPN connections are not affected. Wait a moment or check the service status",
            "核心服務（manager）未連線；VPN 連線不受影響，請稍候或檢查服務狀態",
            "コアサービス（manager）に接続していません。VPN 接続には影響しません。しばらく待つか、サービスの状態を確認してください"
        ),
    )
}

impl ManagerLink {
    pub fn new(path: PathBuf, hub: Arc<Hub>) -> Arc<Self> {
        Self::with_liveness(path, hub, LIVENESS_EVERY, LIVENESS_TIMEOUT)
    }

    fn with_liveness(
        path: PathBuf,
        hub: Arc<Hub>,
        every: Duration,
        timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            path,
            client: RwLock::new(None),
            hub,
            liveness: (every, timeout),
        })
    }

    pub fn connected(&self) -> bool {
        self.client
            .read()
            .as_ref()
            .is_some_and(ControlClient::is_connected)
    }

    /// Send `call` to the manager and wait for its reply.
    ///
    /// # Errors
    ///
    /// `MANAGER_UNAVAILABLE` while there is no connection, and the manager's own error for a
    /// call it refuses or that fails on the way.
    pub async fn call(&self, call: Call) -> Result<Reply, ApiError> {
        let client = self.client.read().clone();
        match client {
            Some(c) if c.is_connected() => c.call(call).await,
            _ => Err(unavailable()),
        }
    }

    /// Keep a connection and an event subscription alive forever. The two are one link: when
    /// either breaks — the call connection is lost, the event stream ends, or the manager leaves
    /// a liveness call unanswered — both are dropped and connected again. (A call connection
    /// lost while the events kept flowing used to leave the controller answering "manager not
    /// connected" until the manager was restarted.)
    pub async fn run(self: Arc<Self>) {
        let mut announced: Option<bool> = None;
        loop {
            match ControlClient::connect(&self.path).await {
                Ok(client) => {
                    *self.client.write() = Some(client.clone());
                    if announced != Some(true) {
                        tracing::info!(manager_build = %client.manager_build, "connected to manager");
                        self.hub
                            .publish(ServerEvent::ManagerConnection { connected: true });
                        announced = Some(true);
                    }
                    let why = match ControlClient::subscribe(&self.path).await {
                        Ok(events) => self.pump(&client, events).await,
                        Err(e) => format!("event subscription failed: {e}"),
                    };
                    *self.client.write() = None;
                    // Calls still waiting on the old connection fail now, not at their timeout.
                    client.close();
                    tracing::warn!(reason = %why, "manager link lost; connecting again");
                }
                Err(e) => {
                    if announced != Some(false) {
                        tracing::warn!(error = %e, path = %self.path.display(), "manager unreachable");
                    }
                }
            }
            if announced != Some(false) {
                self.hub
                    .publish(ServerEvent::ManagerConnection { connected: false });
                announced = Some(false);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Forward the manager's events until the link breaks; why it broke.
    async fn pump(&self, client: &ControlClient, mut events: mpsc::Receiver<Event>) -> String {
        let (every, timeout) = self.liveness;
        let liveness = async {
            loop {
                tokio::time::sleep(every).await;
                // Any answer, a refusal included, shows the manager serves this connection.
                if tokio::time::timeout(timeout, client.call(Call::System))
                    .await
                    .is_err()
                {
                    return format!(
                        "the manager left a liveness call unanswered for {} s",
                        timeout.as_secs()
                    );
                }
            }
        };
        tokio::pin!(liveness);
        let mut rates = RateTracker::default();
        loop {
            tokio::select! {
                ev = events.recv() => match ev {
                    Some(ev) => self.forward(ev, &mut rates),
                    None => return "the event stream ended".into(),
                },
                () = client.closed() => return "the call connection was lost".into(),
                why = &mut liveness => return why,
            }
        }
    }

    fn forward(&self, ev: Event, rates: &mut RateTracker) {
        match ev {
            Event::Status(s) => self.hub.publish(ServerEvent::InstanceStatus { status: *s }),
            Event::Sample {
                instance_id,
                generation,
                sample,
            } => {
                if let Some(r) = rates.update(instance_id, generation, &sample) {
                    self.hub.publish(ServerEvent::LiveRates { rates: r });
                }
            }
            Event::AppStatus(s) => self.hub.publish(ServerEvent::AppStatus { status: *s }),
            Event::ForwardStatus(s) => self.hub.publish(ServerEvent::ForwardStatus { status: *s }),
            Event::SshDownloadStatus(s) => self
                .hub
                .publish(ServerEvent::SshDownloadStatus { status: *s }),
        }
    }
}

/// Derives rates from consecutive cumulative samples of the same generation. A new generation,
/// a counter that went backwards or a long gap produces no rate (never a fake zero).
#[derive(Default)]
struct RateTracker {
    last: HashMap<InstanceId, (u64, WorkerStatus)>,
}

impl RateTracker {
    #[expect(
        clippy::cast_precision_loss,
        reason = "byte counters and nanoseconds become rates and percentages; f64 precision is ample"
    )]
    fn update(&mut self, id: InstanceId, generation: u64, s: &WorkerStatus) -> Option<LiveRates> {
        let prev = self.last.insert(id, (generation, s.clone()));
        let (pg, p) = prev?;
        if pg != generation || s.monotonic_ms <= p.monotonic_ms {
            return None;
        }
        let dt = (s.monotonic_ms - p.monotonic_ms) as f64 / 1000.0;
        if dt > 5.0 {
            return None;
        }
        // A counter that went backwards (a Gateway re-created on the running worker) or a
        // Gateway without an earlier sample gives no rate this time — not a zero.
        let rate = |now: u64, before: u64| -> Option<f64> {
            (now >= before).then(|| (now - before) as f64 * 8.0 / dt)
        };
        let (mut prx, mut ptx) = (0.0, 0.0);
        let mut gateways = Vec::with_capacity(s.gateways.len());
        for g in &s.gateways {
            let Some(id) = g.id else { continue };
            let before = p.gateways.iter().find(|x| x.id == Some(id))?;
            let rx = rate(g.payload_rx_bytes, before.payload_rx_bytes)?;
            let tx = rate(g.payload_tx_bytes, before.payload_tx_bytes)?;
            prx += rx;
            ptx += tx;
            gateways.push(GatewayRates {
                gateway_id: id,
                rx_bps: rx,
                tx_bps: tx,
                ssh_rx_bps: rate(g.ssh_rx_bytes, before.ssh_rx_bytes)?,
                ssh_tx_bps: rate(g.ssh_tx_bytes, before.ssh_tx_bytes)?,
                ssh_pull_rx_bps: rate(g.ssh_pull_rx_bytes, before.ssh_pull_rx_bytes)?,
                ssh_pull_tx_bps: rate(g.ssh_pull_tx_bytes, before.ssh_pull_tx_bytes)?,
                ssh_sessions: u32::try_from(g.ssh_sessions).unwrap_or(u32::MAX),
                active_tcp: u32::try_from(g.tcp_active).unwrap_or(u32::MAX),
                active_udp: u32::try_from(g.udp_active).unwrap_or(u32::MAX),
            });
        }
        // The Apps' part — what the port forwards relayed and, in strict mode, the sandbox's
        // Apps' own flows — is payload too. Its counters live as long as the worker, so one going
        // backwards (or a sandbox that came or went) means no rate this time, as for a Gateway.
        if s.sandbox.is_some() != p.sandbox.is_some() {
            return None;
        }
        let ((arx, atx), (brx, btx)) = (s.apps_payload(), p.apps_payload());
        let apps_rx = rate(arx, brx)?;
        let apps_tx = rate(atx, btx)?;
        prx += apps_rx;
        ptx += apps_tx;
        // In strict mode all of it is the sandbox's: every forward ends at an App inside it.
        let sandbox = s.sandbox.map(|now| SandboxRates {
            rx_bps: apps_rx,
            tx_bps: apps_tx,
            active_tcp: u32::try_from(now.tcp_flows).unwrap_or(u32::MAX),
            active_udp: u32::try_from(now.udp_flows).unwrap_or(u32::MAX),
            evicted: now.evicted,
            table_full: now.table_full,
        });
        let cpu = match (s.cpu_ns, p.cpu_ns) {
            (Some(a), Some(b)) if a >= b => Some((a - b) as f64 / (dt * 1e9) * 100.0),
            _ => None,
        };
        let shaping = match (&s.shaping, &p.shaping) {
            (Some(now), Some(before)) => {
                // Share of the interval a capped direction waited (bridged pauses can put a
                // few ms of the previous interval in this one: at most all of it).
                let share = |cap: Option<u64>, a: u64, b: u64| {
                    cap.and_then(|_| a.checked_sub(b))
                        .map(|ms| (ms as f64 / (dt * 1000.0)).min(1.0))
                };
                let per_sec = |a: u64, b: u64| a.checked_sub(b).map(|n| n as f64 / dt);
                let caps = now.caps;
                Some(ShapingRates {
                    download_bps: caps.download_bps,
                    upload_bps: caps.upload_bps,
                    download_limited: share(
                        caps.download_bps,
                        now.download_wait_ms,
                        before.download_wait_ms,
                    ),
                    upload_limited: share(
                        caps.upload_bps,
                        now.upload_wait_ms,
                        before.upload_wait_ms,
                    ),
                    download_dropped_per_sec: per_sec(
                        now.download_dropped,
                        before.download_dropped,
                    ),
                    upload_dropped_per_sec: per_sec(now.upload_dropped, before.upload_dropped),
                })
            }
            _ => None,
        };
        Some(LiveRates {
            instance_id: id,
            at: Timestamp::now(),
            generation,
            payload_rx_bps: prx,
            payload_tx_bps: ptx,
            wg_rx_bps: rate(s.wg_rx_bytes, p.wg_rx_bytes)?,
            wg_tx_bps: rate(s.wg_tx_bytes, p.wg_tx_bytes)?,
            active_tcp: u32::try_from(s.active_tcp).unwrap_or(u32::MAX),
            active_udp: u32::try_from(s.active_udp).unwrap_or(u32::MAX),
            cpu_core_pct: cpu,
            rss_bytes: s.rss_bytes.map(|b| b as f64),
            gateways,
            shaping,
            sandbox,
        })
    }
}
