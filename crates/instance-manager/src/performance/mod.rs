//! Performance Manager, manager side: process resource sampling and the passive analysis behind
//! `GET /v1/performance/summary` and `/series`.
//!
//! It lives in the manager because the manager owns the worker processes, sees every worker
//! sample first and survives controller restarts. The analysis itself is the pure logic of
//! `vpn_performance`; this module feeds it and keeps its windows bounded.
//!
//! Nothing here waits on the data path: worker samples arrive through the manager's event
//! broadcast (a slow consumer only loses samples, which become gaps), and resource samples are
//! persisted from a bounded queue that drops its oldest rows (recorded as a gap) when the Store
//! is busy.

mod sampler;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::broadcast;
use vpn_domain::{
    ApiError, ErrorCode, GatewayId, GatewaySpec, InstanceId, InstancePerformance, InstanceSpec,
    LATENCY_BUCKETS_US, MetricsGapReason, MetricsRange, MetricsScope, OperationId,
    PerformanceOverview, PerformanceScope, PerformanceScopeKind, PerformanceSeriesSet, Phase,
    SUMMARY_MAX_GATEWAYS, Timestamp, TransportProfile, tr,
};
use vpn_ipc::control::{PerfCall, PerfReply};
use vpn_ipc::worker::WorkerStatus;
use vpn_performance::histogram::Histogram;
use vpn_performance::passive::{
    self, GatewayMeta, GatewayPoint, HostMeta, InstanceMeta, InstanceWindow, ProcessWindow,
    WorkerPoint,
};
use vpn_performance::series::{self, BucketValue, RoleInput, TickValue};
use vpn_platform::resources::{self, ProcessIdentity};
use vpn_store::{RoleData, Store};
use vpn_sync::Mutex;

use crate::{Manager, ManagerEvent};

/// How long a series query may take.
const QUERY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);

/// Where an Instance's worker is now, from the manager's status events.
#[derive(Debug, Clone, Copy)]
struct Runtime {
    generation: Option<u64>,
    pid: Option<u32>,
}

struct ProcessEntry {
    window: ProcessWindow,
    /// Random per identity: its counters are comparable only within it.
    epoch: String,
}

#[derive(Default)]
struct State {
    windows: HashMap<InstanceId, InstanceWindow>,
    runtime: HashMap<InstanceId, Runtime>,
    processes: HashMap<String, ProcessEntry>,
    /// Controller processes connected to `manager.sock`, with their connection count.
    controllers: HashMap<ProcessIdentity, usize>,
    /// OS identity of each worker pid seen (pid, generation) → identity.
    workers: HashMap<(u32, u64), ProcessIdentity>,
}

pub struct Performance {
    manager: Arc<Manager>,
    store: Arc<Store>,
    state: Mutex<State>,
    started_ms: i64,
    host: HostMeta,
    boot_id: Option<String>,
    epoch: Instant,
    me: Option<ProcessIdentity>,
    persist: Mutex<sampler::PersistQueue>,
}

impl std::fmt::Debug for Performance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Performance")
            .field("started_ms", &self.started_ms)
            .field("boot_id", &self.boot_id)
            .finish_non_exhaustive()
    }
}

fn now_ms() -> i64 {
    Timestamp::now().unix_millis()
}

fn random_epoch() -> String {
    // A process's counter epoch: unrelated to anything else, never reused.
    OperationId::new().to_string()
}

/// A worker sample as the passive windows keep it.
fn point_of(s: &WorkerStatus, at_ms: i64) -> WorkerPoint {
    WorkerPoint {
        at_ms,
        generation: s.generation,
        mono_ms: s.monotonic_ms,
        wg_rx: s.wg_rx_bytes,
        wg_tx: s.wg_tx_bytes,
        admission_rejected: s.admission_rejected,
        underlay_blocked: s.underlay_blocked,
        memory_reserved: s.memory_reserved,
        tunnel_tcp: s.active_tcp,
        tunnel_udp: s.active_udp,
        control_flows: s.control_flows,
        probe_flows: s.probe_flows,
        connector_flows: s.connector_flows,
        cpu_ns: s.cpu_ns,
        rss_bytes: s.rss_bytes,
        dns: Histogram::from_buckets(
            &LATENCY_BUCKETS_US,
            &s.dns_latency_buckets,
            s.dns_latency_sum_us,
            s.dns_timeouts,
        ),
        gateways: s
            .gateways
            .iter()
            .filter_map(|g| {
                let connect = Histogram::from_buckets(
                    &LATENCY_BUCKETS_US,
                    &g.connect_latency_buckets,
                    g.connect_latency_sum_us,
                    g.connect_timeouts,
                )
                .unwrap_or_else(|| Histogram::empty(&LATENCY_BUCKETS_US));
                Some(GatewayPoint {
                    id: g.id?,
                    payload_rx: g.payload_rx_bytes,
                    payload_tx: g.payload_tx_bytes,
                    tcp_active: g.tcp_active,
                    udp_active: g.udp_active,
                    tcp_rejected: g.tcp_rejected,
                    udp_dropped: g.udp_dropped,
                    connect,
                    connect_failures: g.connect_failures,
                    connect_not_found: g.connect_not_found,
                })
            })
            .collect(),
        apps: s.apps_payload(),
    }
}

/// Keeps a controller registered while its connection lives.
#[derive(Debug)]
pub struct ControllerGuard {
    perf: Arc<Performance>,
    identity: ProcessIdentity,
}

impl Drop for ControllerGuard {
    fn drop(&mut self) {
        let mut state = self.perf.state.lock();
        if let Some(n) = state.controllers.get_mut(&self.identity) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                state.controllers.remove(&self.identity);
            }
        }
    }
}

impl Performance {
    /// Start sampling and analyzing. `events` must be subscribed before any worker starts so no
    /// sample of the first generations is missed.
    pub fn start(
        manager: Arc<Manager>,
        store: Arc<Store>,
        events: broadcast::Receiver<ManagerEvent>,
    ) -> Arc<Self> {
        let logical_cpus = resources::logical_cpus();
        let facts_ram = vpn_platform::system::ram_bytes();
        // The spec's reference host: 8 logical CPUs and 16 GiB. Anything else is reported as not
        // the reference environment (equivalence is not something this host can prove).
        let reference_environment =
            logical_cpus == 8 && facts_ram.is_some_and(|r| (15 << 30..=17 << 30).contains(&r));
        let perf = Arc::new(Self {
            manager,
            store,
            state: Mutex::new(State::default()),
            started_ms: now_ms(),
            host: HostMeta {
                logical_cpus,
                reference_environment,
            },
            boot_id: resources::host_boot_id(),
            epoch: Instant::now(),
            me: resources::self_identity().ok(),
            persist: Mutex::new(sampler::PersistQueue::default()),
        });
        tokio::spawn(feed(Arc::downgrade(&perf), events));
        sampler::spawn(&perf);
        perf
    }

    /// One Performance Manager call.
    ///
    /// # Errors
    ///
    /// The call's error: the Store's when it cannot be read, a timeout, or an invalid scope.
    pub async fn call(self: &Arc<Self>, call: PerfCall) -> Result<PerfReply, ApiError> {
        Ok(match call {
            PerfCall::Summary => PerfReply::Summary(self.summary().await?),
            PerfCall::Series { scope, range } => {
                PerfReply::Series(self.series(scope, range).await?)
            }
        })
    }

    /// A controller (or another same-user client) connected to `manager.sock`: sample its
    /// process while the connection lives. `None` when its identity cannot be read.
    pub fn controller_connected(self: &Arc<Self>, pid: u32) -> Option<ControllerGuard> {
        let identity = resources::process_identity(pid).ok()?;
        if Some(identity) == self.me {
            return None;
        }
        *self.state.lock().controllers.entry(identity).or_default() += 1;
        Some(ControllerGuard {
            perf: self.clone(),
            identity,
        })
    }

    fn on_event(&self, ev: ManagerEvent) {
        let mut state = self.state.lock();
        match ev {
            ManagerEvent::Status(s) => {
                state.runtime.insert(
                    s.instance_id,
                    Runtime {
                        generation: s.running.as_ref().map(|r| r.generation),
                        pid: s.running.as_ref().and_then(|r| r.pid),
                    },
                );
            }
            ManagerEvent::Sample {
                instance_id,
                sample,
                ..
            } => {
                let p = point_of(&sample, now_ms());
                state.windows.entry(instance_id).or_default().push(p);
            }
            // Managed Apps, port forwards and SSH downloads are not part of the passive analysis.
            ManagerEvent::AppStatus(_)
            | ManagerEvent::ForwardStatus(_)
            | ManagerEvent::SshDownloadStatus(_) => {}
        }
    }

    /// `GET /v1/performance/summary`.
    ///
    /// # Errors
    ///
    /// The Store's error when the Instances or Gateways cannot be read.
    pub async fn summary(&self) -> Result<PerformanceOverview, ApiError> {
        let specs: Vec<InstanceSpec> = self.store.list().await.map_err(|e| e.to_api())?;
        let gateways: Vec<GatewaySpec> = self.store.list().await.map_err(|e| e.to_api())?;
        let transports: Vec<TransportProfile> = self.store.list().await.map_err(|e| e.to_api())?;
        let statuses = self.manager.statuses().await;
        let now = now_ms();
        let state = self.state.lock();
        let mut budget = SUMMARY_MAX_GATEWAYS;
        let mut omitted = 0u32;
        let instances: Vec<InstancePerformance> = specs
            .iter()
            .map(|spec| {
                let status = statuses.iter().find(|s| s.instance_id == spec.id);
                let running = status.and_then(|s| s.running.as_ref());
                let mut gws: Vec<GatewayMeta> = gateways
                    .iter()
                    .filter(|g| g.instance_id == spec.id && g.enabled)
                    .map(|g| GatewayMeta {
                        id: g.id,
                        name: g.name.clone(),
                        port: g.port,
                        max_connections: g.max_connections,
                        udp: g.udp,
                    })
                    .collect();
                if gws.len() > budget {
                    omitted += u32::try_from(gws.len() - budget).unwrap_or(u32::MAX);
                    gws.truncate(budget);
                }
                budget -= gws.len();
                let meta = InstanceMeta {
                    id: spec.id,
                    name: spec.name.clone(),
                    phase: status.map_or(Phase::Stopped, |s| s.phase),
                    generation: running.map(|r| r.generation),
                    limits: spec.limits.clone(),
                    // A transport that cannot be followed (its profile is gone) does not run:
                    // the sizes every connection had before transport profiles stand in.
                    tcp_flow_bytes: vpn_domain::resolve_transport(&spec.transport, &transports)
                        .map_or_else(
                            |_| vpn_domain::FlowSettings::BALANCED.tcp_start_bytes(),
                            |t| t.tcp_start_bytes(),
                        ),
                    gateways: gws,
                };
                passive::analyze_instance(&meta, state.windows.get(&spec.id), self.host, now)
            })
            .collect();
        let windows: Vec<ProcessWindow> =
            state.processes.values().map(|p| p.window.clone()).collect();
        drop(state);
        let system = passive::analyze_processes(
            &windows,
            now,
            1_000,
            self.host.logical_cpus,
            self.boot_id.clone(),
        );
        Ok(PerformanceOverview {
            observed_at: Timestamp::from_unix_millis(now).unwrap_or_else(Timestamp::now),
            collecting_since: Timestamp::from_unix_millis(self.started_ms)
                .unwrap_or_else(Timestamp::now),
            rate_window_secs: u32::try_from(passive::RATE_WINDOW_MS / 1_000).unwrap_or(u32::MAX),
            latency_window_secs: u32::try_from(passive::LATENCY_WINDOW_MS / 1_000)
                .unwrap_or(u32::MAX),
            hints: passive::hints(&instances),
            reference: passive::reference(&instances),
            system,
            instances,
            omitted_gateways: omitted,
        })
    }

    /// `GET /v1/performance/series`.
    ///
    /// # Errors
    ///
    /// Invalid request for an unparsable entity id or the component scope, the Store's error
    /// when it cannot be read, and a timeout when the query takes longer than its deadline.
    pub async fn series(
        &self,
        scope: PerformanceScope,
        range: MetricsRange,
    ) -> Result<PerformanceSeriesSet, ApiError> {
        match scope.kind {
            PerformanceScopeKind::System => self.system_series(range).await,
            // The metrics service keeps these series; they are read, not recomputed.
            PerformanceScopeKind::Instance => {
                let id: InstanceId = scope
                    .entity_id
                    .as_deref()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| {
                        ApiError::new(
                            ErrorCode::InvalidRequest,
                            tr!(
                                "Invalid Instance id",
                                "Instance id 無效",
                                "Instance id が無効です"
                            ),
                        )
                    })?;
                let m =
                    crate::metrics::series(&self.store, MetricsScope::Instance(id), range).await?;
                Ok(series::store_series(scope, &m, self.host.logical_cpus))
            }
            PerformanceScopeKind::Gateway => {
                let id: GatewayId = scope
                    .entity_id
                    .as_deref()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| {
                        ApiError::new(
                            ErrorCode::InvalidRequest,
                            tr!(
                                "Invalid Gateway id",
                                "代理埠 id 無效",
                                "ゲートウェイの id が無効です"
                            ),
                        )
                    })?;
                let m =
                    crate::metrics::series(&self.store, MetricsScope::Gateway(id), range).await?;
                Ok(series::store_series(scope, &m, self.host.logical_cpus))
            }
            PerformanceScopeKind::Component => Err(ApiError::new(
                ErrorCode::InvalidRequest,
                tr!(
                    "For the component scope, use system instead (listed by role)",
                    "component 範圍請改用 system（依角色分列）",
                    "component スコープの代わりに system を使ってください（役割ごとに表示されます）"
                ),
            )),
        }
    }

    /// The system scope's series: VPN Manager's processes by role, from the resources table.
    async fn system_series(&self, range: MetricsRange) -> Result<PerformanceSeriesSet, ApiError> {
        let timed_out = || {
            ApiError::new(
                ErrorCode::Timeout,
                tr!(
                    "The performance series query timed out; try again later",
                    "效能曲線查詢逾時，請稍後再試",
                    "パフォーマンス曲線の問い合わせがタイムアウトしました。しばらくしてからもう一度お試しください"
                ),
            )
        };
        let now = now_ms();
        let from = now - range.duration_ms();
        let minute = series::system_resolution(range) > 5;
        let q = tokio::time::timeout(
            QUERY_DEADLINE,
            self.store.resources_query(from, now, minute),
        )
        .await
        .map_err(|_elapsed| timed_out())?
        .map_err(|e| e.to_api())?;
        let input = role_input(q.data);
        let gaps: Vec<(i64, i64, MetricsGapReason)> = q
            .gaps
            .iter()
            .map(|g| {
                (
                    g.from_ms,
                    g.to_ms,
                    match g.kind {
                        vpn_store::ResourceGapKind::Dropped => MetricsGapReason::Dropped,
                        vpn_store::ResourceGapKind::Quota => MetricsGapReason::Quota,
                    },
                )
            })
            .collect();
        Ok(series::system_series(
            range,
            now,
            self.host.logical_cpus,
            &input,
            &gaps,
        ))
    }
}

/// The resources table's rows as the series builder takes them.
fn role_input(data: RoleData) -> RoleInput {
    match data {
        RoleData::Ticks(by_role) => RoleInput::Ticks(
            by_role
                .into_iter()
                .map(|(role, ticks)| {
                    (
                        role,
                        ticks
                            .into_iter()
                            .map(|t| TickValue {
                                at_ms: t.at_ms,
                                cpu: t.cpu,
                                rss_bytes: t.rss_bytes,
                            })
                            .collect(),
                    )
                })
                .collect(),
        ),
        RoleData::Minutes(by_role) => RoleInput::Buckets(
            by_role
                .into_iter()
                .map(|(role, buckets)| {
                    (
                        role,
                        buckets
                            .into_iter()
                            .map(|b| BucketValue {
                                bucket_ms: b.bucket_ms,
                                cpu_ns: b.cpu_ns,
                                cpu_ms: b.cpu_ms,
                                rss_sum: b.rss_sum,
                                rss_ms: b.rss_ms,
                            })
                            .collect(),
                    )
                })
                .collect(),
        ),
    }
}

/// Feed manager events into the windows until the manager goes away.
async fn feed(perf: std::sync::Weak<Performance>, mut events: broadcast::Receiver<ManagerEvent>) {
    loop {
        match events.recv().await {
            Ok(ev) => match perf.upgrade() {
                Some(p) => p.on_event(ev),
                None => return,
            },
            // Missed samples are gaps in the windows, never guessed.
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::debug!(
                    missed = n,
                    "performance analysis lagged behind manager events"
                );
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}
