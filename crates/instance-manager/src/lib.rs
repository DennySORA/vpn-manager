//! Instance Manager: the only lifecycle owner of VPN Instances. VPN Core (in the controller)
//! submits intents here; nothing else can start, stop or open an Instance.

#![forbid(unsafe_code)]

mod actor;
pub mod apps;
pub mod bootstrap;
mod downloads;
pub mod egress;
mod forwards;
mod hold;
mod inputs;
pub mod inventory;
pub mod limits;
pub mod metrics;
pub mod performance;
pub mod policy;
mod ports;
pub mod recovery;
pub mod resolve;
pub mod rpc;
mod sandbox;
pub mod ssh;
mod stops;
pub mod system;
pub mod watchdog;
mod worker;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, mpsc, oneshot, watch};
use vpn_domain::{
    ApiError, AppStatus, ErrorCode, ForwardBinding, ForwardStatus, GatewayId, GatewaySpec,
    GatewayState, InstanceId, InstanceSpec, InstanceStatus, SshDownloadStatus, Timestamp,
    UnbanEffect, tr,
};
use vpn_ipc::worker::WorkerStatus;
use vpn_platform::limits::ResourceControl;
use vpn_platform::paths::Paths;
use vpn_store::{IntentChange, Store, StoreError};
use vpn_sync::Mutex;

use actor::{Actor, ActorCmd};
use hold::Hold;

/// How long a stop request waits for its actor to seal and reap the worker.
const STOP_WAIT: Duration = Duration::from_secs(10);
/// How long a stop request waits for the first latch write before answering `durable: false`
/// (the write and its retries go on in the background).
const LATCH_WAIT: Duration = Duration::from_secs(10);
/// Back-off between attempts to write a stop latch that did not reach the disk.
const LATCH_RETRY_MIN: Duration = Duration::from_secs(1);
const LATCH_RETRY_MAX: Duration = Duration::from_secs(30);
/// How long a manager that is shutting down tries once more to write a stop latch.
const LATCH_FLUSH_WAIT: Duration = Duration::from_secs(2);
/// How often expired bans are deleted (workers end them on time by themselves).
const BAN_SWEEP: Duration = Duration::from_secs(30);
/// How long lifting a ban waits for the running worker to confirm.
const UNBAN_WAIT: Duration = Duration::from_secs(3);

/// What the manager publishes to subscribers (the controller's SSE stream, metrics).
#[derive(Debug, Clone)]
pub enum ManagerEvent {
    Status(Box<InstanceStatus>),
    /// Raw per-second worker sample (cumulative counters) for metrics and live charts.
    Sample {
        instance_id: InstanceId,
        generation: u64,
        sample: Box<WorkerStatus>,
    },
    /// A managed App's status changed.
    AppStatus(Box<AppStatus>),
    /// A port forward's status changed (or its counters moved).
    ForwardStatus(Box<ForwardStatus>),
    /// An SSH download job's status (at most one per job and second).
    SshDownloadStatus(Box<SshDownloadStatus>),
}

pub(crate) struct Ctx {
    pub store: Arc<Store>,
    /// The managed-App supervisor (port forwards check their target Apps with it).
    pub apps: Arc<apps::Apps>,
    pub exe: PathBuf,
    pub paths: Paths,
    pub events: broadcast::Sender<ManagerEvent>,
    /// Installation key with which Gateways prove themselves to `vpnctl`.
    pub gateway_key: Option<Arc<zeroize::Zeroizing<[u8; 32]>>>,
    /// Takes every worker sample without waiting; stores them in the background.
    pub metrics: Arc<metrics::MetricsCollector>,
    /// What blocked starts wait for; every actor watches it.
    pub changes: watch::Sender<Changes>,
    /// What each running generation pinned (security profile, needed addresses), for the
    /// conflict check of blocklist saves.
    pub running: Mutex<HashMap<InstanceId, policy::RunningPolicy>>,
    /// Every worker started and not reaped yet (memory and records on disk).
    pub inventory: Arc<inventory::Inventory>,
    /// Held (shared) by every worker spawn until the worker took its key lock; a recovery
    /// holds it exclusively while it removes lock files, so no worker is between opening a
    /// lock file and locking it then.
    pub spawn_gate: tokio::sync::RwLock<()>,
    /// cgroup limits of worker and App trees (or why there are none).
    pub resources: Arc<ResourceControl>,
    /// What managed Apps need to start in each strict Instance's sandbox (Linux).
    pub strict_apps: Arc<sandbox::StrictApps>,
    /// The on-disk evidence of stops whose latch is not on disk ([`stops`]).
    pub stops: Arc<stops::PendingStops>,
    /// [`Manager::shutdown`] runs: no call is served and no actor created while every actor is
    /// let go (an Instance without its actor would read as deleted), and no sandbox is built.
    closing: AtomicBool,
}

/// Counters of what a blocked start may be waiting for, bumped when it changes. A watch:
/// changes coalesce, and whoever bumps them never waits for an actor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Changes {
    /// An Instance or a `WireGuard`, DNS or security profile was saved.
    pub config: u64,
    /// An Instance gave up its `WireGuard` key: it was stopped or deleted, or its new generation
    /// uses another key.
    pub released: u64,
    /// A security profile or a blocklist's content was saved: running workers recompile their
    /// overlay (applies without a restart).
    pub policy: u64,
}

impl Ctx {
    /// The manager is stopping.
    pub(crate) fn is_closing(&self) -> bool {
        self.closing.load(Ordering::SeqCst)
    }

    /// Configuration a start depends on was saved: starts blocked on it try again.
    pub(crate) fn config_changed(&self) {
        self.changes.send_modify(|c| c.config += 1);
    }

    /// An Instance gave up its `WireGuard` key: starts refused for that key try again.
    pub(crate) fn key_released(&self) {
        self.changes.send_modify(|c| c.released += 1);
    }

    /// Blocklists of a security profile changed: running workers get their new overlay.
    pub(crate) fn policy_changed(&self) {
        self.changes.send_modify(|c| c.policy += 1);
    }
}

/// Result of a stop / emergency stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopOutcome {
    /// The data path is closed (worker sealed and reaped).
    pub sealed: bool,
    /// The stop latch is on disk.
    pub durable: bool,
}

/// One Instance's actor and the stop hold it shares with the facade.
struct ActorEntry {
    tx: mpsc::Sender<ActorCmd>,
    hold: Arc<Hold>,
}

/// Finished operations are kept 30 days, at most 10,000 of them: long enough to answer any retry
/// of a lost reply, and the table never grows without bound.
fn spawn_operation_pruning(store: Arc<Store>) {
    /// 720 hours, in milliseconds.
    const KEEP_MILLIS: i64 = 720 * 3_600_000;
    const MAX: usize = 10_000;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_hours(6));
        loop {
            tick.tick().await;
            let cutoff = Timestamp::from_unix_millis(Timestamp::now().unix_millis() - KEEP_MILLIS);
            let Some(cutoff) = cutoff else { continue };
            match store.prune_operations(cutoff, MAX).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(operations = n, "old operations pruned"),
                Err(e) => tracing::warn!(error = %e, "could not prune old operations"),
            }
        }
    });
}

/// The Gateway key, or `None` when it cannot be loaded: Gateways still work for apps; `vpnctl`
/// then refuses them (it cannot verify).
fn load_gateway_key(paths: &Paths) -> Option<Arc<zeroize::Zeroizing<[u8; 32]>>> {
    match vpn_platform::keystore::load_or_create_key_file(&paths.gateway_key()) {
        Ok(k) => Some(Arc::new(k)),
        Err(e) => {
            tracing::warn!(error = %e, "gateway key unavailable");
            None
        }
    }
}

/// Expired bans leave the store on time; workers end them by themselves.
fn spawn_ban_sweep(sweep: Arc<Store>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(BAN_SWEEP);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if let Err(e) = sweep.expire_bans().await {
                tracing::warn!(error = %e, "expired bans not deleted");
            }
        }
    });
}

pub struct Manager {
    ctx: Arc<Ctx>,
    actors: Mutex<HashMap<InstanceId, ActorEntry>>,
    bootstrap: bootstrap::Bootstrap,
    apps: Arc<apps::Apps>,
    /// Held across the conflict check and the write of every save that changes what a blocklist
    /// covers or what a connection needs, so two saves cannot each pass alone and conflict
    /// together.
    policy_lock: tokio::sync::Mutex<()>,
    /// SSH download, an internal component this manager hosts (`crates/ssh-download`).
    downloads: std::sync::OnceLock<Arc<vpn_ssh_download::SshDownloads>>,
    /// This manager, for the tasks that watch its actors.
    me: Weak<Self>,
}

/// After an actor failed, how long until its replacement starts: soon, but not in a loop when
/// the replacement fails at once too.
const ACTOR_REPLACE_AFTER: Duration = Duration::from_secs(1);
const ACTOR_REPLACE_AFTER_EARLY: Duration = Duration::from_secs(30);
/// An actor that failed within this long of its start counts as failing at once.
const ACTOR_EARLY: Duration = Duration::from_secs(60);

/// One held Gateway listener, as the actor that holds it reports it.
#[derive(Debug, Clone)]
pub struct HeldListener {
    pub instance_id: InstanceId,
    pub gateway_id: GatewayId,
    pub port: u16,
    pub state: GatewayState,
}

/// The listeners the actors hold, and the Instances whose actor did not answer in time (their
/// listeners are unknown, not absent).
#[derive(Debug, Clone, Default)]
pub struct HeldListeners {
    pub held: Vec<HeldListener>,
    pub unanswered: Vec<InstanceId>,
}

/// The actor of an Instance is gone: its mailbox or its reply closed.
fn interrupted() -> ApiError {
    ApiError::new(
        ErrorCode::Unavailable,
        tr!(
            "Instance management was interrupted",
            "Instance 管理中斷",
            "Instance の管理が中断されました"
        ),
    )
}

/// The actor of an Instance did not answer a status query in time.
fn status_timed_out() -> ApiError {
    ApiError::new(
        ErrorCode::Timeout,
        tr!(
            "The Instance status query timed out",
            "Instance 狀態查詢逾時",
            "Instance の状態の問い合わせがタイムアウトしました"
        ),
    )
}

impl Manager {
    /// Create the manager and start an actor per stored Instance. Actors immediately recover
    /// every Instance whose durable intent is `running` without a latch — except one whose stop
    /// was asked for before this start and is not on disk: it stays closed, in
    /// `recovery_required`, until the user decides ([`stops`]).
    ///
    /// # Errors
    ///
    /// A Store error while reading the carried-over stops, the stored Instances or the Apps.
    pub async fn start(
        store: Arc<Store>,
        exe: PathBuf,
        paths: Paths,
    ) -> Result<Arc<Self>, StoreError> {
        let none = ResourceControl::none(tr!(
            "This manager has no resource control",
            "這個 manager 沒有啟用資源控制",
            "この manager ではリソース制御が有効になっていません"
        ));
        Self::start_with(store, exe, paths, Arc::new(none)).await
    }

    /// [`Self::start`] with the resource control `vpnd manager` prepared at start (the
    /// delegated cgroup on Linux): worker and App trees are confined by it.
    ///
    /// # Errors
    ///
    /// A Store error while reading the carried-over stops, the stored Instances or the Apps.
    pub async fn start_with(
        store: Arc<Store>,
        exe: PathBuf,
        paths: Paths,
        resources: Arc<ResourceControl>,
    ) -> Result<Arc<Self>, StoreError> {
        // Stops the previous run was asked for whose latch is not on disk: those Instances are
        // not started from their stored intent. Read before anything acts on an intent.
        let stops = Arc::new(stops::PendingStops::new(&paths.state));
        let mut carried = stops::carried_over(&store, &stops).await?;
        // Operations left unfinished by the previous run will never be finished by anyone.
        match store.abandon_unfinished_operations().await {
            Ok(0) => {}
            Ok(n) => tracing::info!(operations = n, "unfinished operations marked unknown"),
            Err(e) => tracing::warn!(error = %e, "could not mark unfinished operations unknown"),
        }
        spawn_operation_pruning(store.clone());
        let (events, _) = broadcast::channel(1024);
        let gateway_key = load_gateway_key(&paths);
        let collector = metrics::MetricsCollector::new();
        metrics::spawn(collector.clone(), store.clone());
        let apps = apps::Apps::new(
            store.clone(),
            paths.clone(),
            events.clone(),
            resources.clone(),
        );
        apps.load().await?;
        let inventory = inventory::Inventory::new(paths.worker_records());
        let strict_apps = sandbox::StrictApps::new(exe.clone(), Arc::downgrade(&apps));
        let ctx = Arc::new(Ctx {
            store: store.clone(),
            apps: apps.clone(),
            exe,
            paths,
            events,
            gateway_key,
            metrics: collector,
            changes: watch::Sender::new(Changes::default()),
            running: Mutex::new(HashMap::new()),
            inventory,
            spawn_gate: tokio::sync::RwLock::new(()),
            resources,
            strict_apps,
            stops,
            closing: AtomicBool::new(false),
        });
        // Linux: Apps in strict mode start in their connection's sandbox (wired before any App
        // is started again below).
        if cfg!(target_os = "linux") && vpn_platform::sandbox::detect().is_ok() {
            apps.set_strict_backend(ctx.strict_apps.clone());
        }
        let specs = store.list::<InstanceSpec>().await?;
        // Sandboxes of strict Instances outlive a manager restart; adopt those that prove they
        // are ours before any actor starts a new one.
        let mut adopted = sandbox::adopt_all(&ctx, &specs).await;
        // The previous process's direct grants died with it: recorded before anything is served
        // (an interrupted seal is committed forward, never reopened).
        let bootstrap = bootstrap::Bootstrap::new(ctx.paths.run.clone(), store.clone());
        if let Err(e) = bootstrap.recover().await {
            tracing::warn!(error = %e, "provider bootstrap runs not recovered; direct access stays closed");
        }
        let mgr = Arc::new_cyclic(|me| Self {
            bootstrap,
            ctx,
            actors: Mutex::new(HashMap::new()),
            apps: apps.clone(),
            policy_lock: tokio::sync::Mutex::new(()),
            downloads: std::sync::OnceLock::new(),
            me: me.clone(),
        });
        for spec in specs {
            let hold = match carried.remove(&spec.id) {
                Some(c) => {
                    tracing::warn!(instance = %spec.id, emergency = c.emergency, "a stop asked for before this start is not on disk: the connection stays closed until the user confirms it or starts it");
                    let hold = Arc::new(Hold::unconfirmed(c.emergency));
                    // Its marker stays (or is written now) until the user's decision is on disk.
                    stops::mirror(mgr.ctx.stops.clone(), spec.id, hold.clone()).await;
                    Some(hold)
                }
                None => None,
            };
            mgr.start_actor(spec.id, adopted.remove(&spec.id), hold);
        }
        spawn_ban_sweep(store.clone());
        // Managed Apps: watch the running ones; stop what a previous manager left running and
        // start again those that should run (after the actors above hold their Gateway ports).
        tokio::spawn(apps.clone().watch(Arc::downgrade(&mgr)));
        tokio::spawn(apps.recover(Arc::downgrade(&mgr)));
        mgr.start_downloads(store).await;
        Ok(mgr)
    }

    /// SSH download: its jobs reach their servers only through a Gateway's route, which this
    /// manager answers from the Instances' live state; unfinished files continue.
    async fn start_downloads(self: &Arc<Self>, store: Arc<Store>) {
        let routes = downloads::ManagerRoutes::new(
            Arc::downgrade(self),
            store.clone(),
            self.ctx.gateway_key.clone(),
        );
        routes.follow(self.subscribe());
        let events = self.ctx.events.clone();
        let publish: vpn_ssh_download::Publish = Arc::new(move |s| {
            let _ = events.send(ManagerEvent::SshDownloadStatus(Box::new(s)));
        });
        match vpn_ssh_download::SshDownloads::start(
            store,
            routes,
            publish,
            vpn_ssh_download::Options::default(),
        )
        .await
        {
            Ok(d) => {
                let _ = self.downloads.set(d);
            }
            Err(e) => tracing::warn!(error = %e, "SSH download not started"),
        }
    }

    /// The managed-App supervisor.
    pub const fn apps(&self) -> &Arc<apps::Apps> {
        &self.apps
    }

    /// The SSH download component (`None` when it could not start).
    pub fn ssh_downloads(&self) -> Option<&Arc<vpn_ssh_download::SshDownloads>> {
        self.downloads.get()
    }

    /// The port `instance` holds a listener on for `gateway`: `Ok(None)` when it holds none,
    /// `Err(())` when its actor did not answer within `wait` (unknown, never "not held").
    pub(crate) async fn held_gateway_port(
        &self,
        instance: InstanceId,
        gateway: GatewayId,
        wait: Duration,
    ) -> Result<Option<u16>, ()> {
        let Some(tx) = self.actor(instance) else {
            return Ok(None);
        };
        tokio::time::timeout(wait, async move {
            let (reply, rx) = oneshot::channel();
            if tx.send(ActorCmd::HeldPort(gateway, reply)).await.is_err() {
                return Ok(None);
            }
            Ok(rx.await.unwrap_or(None))
        })
        .await
        .unwrap_or(Err(()))
    }

    /// Serialises saves that change what a blocklist covers or what a connection needs: hold it
    /// across the conflict check and the write.
    pub async fn policy_lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.policy_lock.lock().await
    }

    /// What every running generation pinned, for conflict checks.
    pub fn running_policies(&self) -> HashMap<InstanceId, policy::RunningPolicy> {
        self.ctx.running.lock().clone()
    }

    /// A security profile's blocklists or a blocklist's content was saved: running workers
    /// recompile their overlay now.
    pub fn policy_changed(&self) {
        self.ctx.policy_changed();
    }

    /// Lift the ban of `source` on `id`'s running worker (the stored record is already gone).
    pub async fn unban(&self, id: InstanceId, source: std::net::IpAddr) -> UnbanEffect {
        let Some(tx) = self.actor(id) else {
            return UnbanEffect::NotRunning;
        };
        let (reply, rx) = oneshot::channel();
        if tx.send(ActorCmd::Unban { source, reply }).await.is_err() {
            return UnbanEffect::NotRunning;
        }
        match tokio::time::timeout(UNBAN_WAIT, rx).await {
            Ok(Ok(effect)) => effect,
            _ => UnbanEffect::Unconfirmed,
        }
    }

    /// The one-time direct bootstrap for Provider operations.
    pub const fn bootstrap(&self) -> &bootstrap::Bootstrap {
        &self.bootstrap
    }

    /// The Metrics Collector (its ingress and maintenance state feed the metrics status).
    pub fn metrics(&self) -> &metrics::MetricsCollector {
        &self.ctx.metrics
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ManagerEvent> {
        self.ctx.events.subscribe()
    }

    /// The executable workers are started from (this manager's own file).
    pub fn exe(&self) -> &Path {
        &self.ctx.exe
    }

    pub fn paths(&self) -> &Paths {
        &self.ctx.paths
    }

    pub fn inventory(&self) -> &Arc<inventory::Inventory> {
        &self.ctx.inventory
    }

    /// The metrics ingress since start, and how many rows wait now.
    pub fn metrics_ingress(&self) -> (metrics::CollectorStats, usize) {
        (self.ctx.metrics.stats(), self.ctx.metrics.queued())
    }

    pub(crate) fn spawn_gate(&self) -> &tokio::sync::RwLock<()> {
        &self.ctx.spawn_gate
    }

    /// No call is served any more: the manager is stopping.
    pub fn is_closing(&self) -> bool {
        self.ctx.is_closing()
    }

    /// The Gateway listeners every actor holds (actors that do not answer in time are left
    /// out: this is a report, never a basis for cleaning anything).
    pub async fn held_listeners(&self) -> HeldListeners {
        let actors: Vec<_> = self
            .actors
            .lock()
            .iter()
            .map(|(id, e)| (*id, e.tx.clone()))
            .collect();
        // Every actor is asked at once; each gets the same bounded time.
        let mut asks = tokio::task::JoinSet::new();
        for (id, tx) in actors {
            asks.spawn(async move {
                let ask = async {
                    let (reply, rx) = oneshot::channel();
                    // An actor that is gone holds nothing.
                    if tx.send(ActorCmd::Listeners(reply)).await.is_err() {
                        return Some(Vec::new());
                    }
                    rx.await.ok()
                };
                (
                    id,
                    tokio::time::timeout(Duration::from_secs(2), ask)
                        .await
                        .ok()
                        .flatten(),
                )
            });
        }
        let mut out = HeldListeners::default();
        while let Some(answer) = asks.join_next().await {
            let Ok((id, held)) = answer else { continue };
            match held {
                Some(held) => out
                    .held
                    .extend(
                        held.into_iter()
                            .map(|(gateway_id, port, state)| HeldListener {
                                instance_id: id,
                                gateway_id,
                                port,
                                state,
                            }),
                    ),
                None => out.unanswered.push(id),
            }
        }
        out.unanswered.sort();
        out
    }

    fn ensure_actor(&self, id: InstanceId) -> mpsc::Sender<ActorCmd> {
        self.start_actor(id, None, None)
    }

    /// The Instance's actor, started (with an adopted sandbox, if any) unless it runs already.
    /// A new Instance gets `hold` (at start: a stop carried over from before), else a fresh one.
    fn start_actor(
        &self,
        id: InstanceId,
        adopted: Option<vpn_platform::sandbox::SandboxLease>,
        hold: Option<Arc<Hold>>,
    ) -> mpsc::Sender<ActorCmd> {
        let mut actors = self.actors.lock();
        if self.is_closing() {
            // Stopping: nothing new may start. A closed sender makes every send fail.
            return mpsc::channel(1).0;
        }
        if let Some(entry) = actors.get(&id)
            && !entry.tx.is_closed()
        {
            return entry.tx.clone();
        }
        // A replacement actor keeps the Instance's hold.
        let hold = actors
            .get(&id)
            .map(|entry| entry.hold.clone())
            .or(hold)
            .unwrap_or_default();
        let (tx, rx) = mpsc::channel(32);
        let mut actor = Actor::new(id, self.ctx.clone(), hold.clone());
        if let Some(lease) = adopted {
            actor.adopt(lease);
        }
        let me = self.me.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            let ended = tokio::spawn(actor.run(rx)).await;
            // An actor ends with Remove or Shutdown. One that failed took its sandbox's lease and
            // its worker's connection with it: a new one takes over and adopts the sandbox again
            // (whose holder waits for a manager that lives).
            if ended.is_err_and(|e| e.is_panic()) {
                tracing::error!(instance = %id, "the connection's actor failed; a new one takes over");
                let wait = if started.elapsed() < ACTOR_EARLY {
                    ACTOR_REPLACE_AFTER_EARLY
                } else {
                    ACTOR_REPLACE_AFTER
                };
                tokio::time::sleep(wait).await;
                if let Some(manager) = me.upgrade() {
                    manager.replace_failed_actor(id);
                }
            }
        });
        actors.insert(
            id,
            ActorEntry {
                tx: tx.clone(),
                hold,
            },
        );
        tx
    }

    /// The actor of `id` failed: start its replacement, unless the Instance was deleted (or the
    /// manager stops) meanwhile, or another one took over already.
    fn replace_failed_actor(&self, id: InstanceId) {
        let failed = self
            .actors
            .lock()
            .get(&id)
            .is_some_and(|entry| entry.tx.is_closed());
        if failed {
            self.start_actor(id, None, None);
        }
    }

    fn actor(&self, id: InstanceId) -> Option<mpsc::Sender<ActorCmd>> {
        self.actors.lock().get(&id).map(|entry| entry.tx.clone())
    }

    fn hold(&self, id: InstanceId) -> Option<Arc<Hold>> {
        self.actors.lock().get(&id).map(|entry| entry.hold.clone())
    }

    /// A new Instance was stored (stopped).
    pub fn instance_created(&self, id: InstanceId) {
        self.ensure_actor(id);
    }

    /// Persist "running" and let the actor start it. Lifts an in-memory stop only once the
    /// Start is on disk, and only a stop requested before this Start.
    ///
    /// # Errors
    ///
    /// `EmergencyLatched` while an emergency stop is in force (or the Store refuses the start for
    /// that reason); a Store error writing the intent; the errors of [`Self::status`].
    pub async fn start_instance(&self, id: InstanceId) -> Result<InstanceStatus, ApiError> {
        let hold = self.hold(id);
        let seen = hold.as_ref().map(|h| h.get());
        if seen.is_some_and(|s| s.emergency) {
            // The emergency latch may not be on disk yet; it is cleared explicitly either way.
            return Err(ApiError::new(
                ErrorCode::EmergencyLatched,
                tr!(
                    "The emergency stop is still on; release it before starting",
                    "急停尚未解除，請先解除急停再啟動",
                    "緊急停止がまだ解除されていません。緊急停止を解除してから開始してください"
                ),
            ));
        }
        // Overriding a stop that is not on disk (pending, or carried over and unconfirmed): the
        // Start is written as a new revision even where the stored intent still says running,
        // so the decision is on disk and newer than that stop.
        let change = if seen.is_some_and(|s| s.pending()) {
            IntentChange::ConfirmStart
        } else {
            IntentChange::Start
        };
        {
            let _writes = match &hold {
                Some(h) => Some(h.writes.lock().await),
                None => None,
            };
            self.ctx
                .store
                .change_intent(id, change)
                .await
                .map_err(|e| match e {
                    StoreError::InvalidState(m) => ApiError::new(ErrorCode::EmergencyLatched, m),
                    other => other.to_api(),
                })?;
            if let (Some(h), Some(seen)) = (&hold, seen) {
                h.started(seen.epoch);
            }
        }
        if let Some(h) = &hold {
            stops::mirror(self.ctx.stops.clone(), id, h.clone()).await;
        }
        let tx = self.ensure_actor(id);
        let _ = tx.send(ActorCmd::Reconcile { user: true }).await;
        self.status(id).await
    }

    /// Stop: the data path is closed and the latch written concurrently. The in-memory hold is
    /// set first, so nothing can reopen the Instance while the command waits in the actor's
    /// mailbox or the latch is not on disk yet; a latch that fails is retried in the background
    /// (`durable: false` meanwhile, shown as pending persistence). The stop's marker file
    /// ([`stops`]) is written at the same moment, so the stop survives this process until its
    /// latch is on disk.
    ///
    /// # Errors
    ///
    /// None today: a latch or seal that does not finish in time is reported in the outcome
    /// (`sealed`, `durable`), not as an error.
    pub async fn stop_instance(
        &self,
        id: InstanceId,
        emergency: bool,
    ) -> Result<StopOutcome, ApiError> {
        let entry = self
            .actors
            .lock()
            .get(&id)
            .map(|entry| (entry.tx.clone(), entry.hold.clone()));
        let (answer, latched) = oneshot::channel();
        let mut marked = None;
        if let Some((_, hold)) = &entry {
            let epoch = hold.stop(emergency);
            // An emergency in force — also one not on disk yet, or carried over from before
            // this start — is latched by every stop until it is cleared.
            let change = if hold.get().emergency {
                IntentChange::Emergency
            } else {
                IntentChange::Stop
            };
            // Marker, seal and latch start together; none of them waits for another.
            marked = Some(tokio::spawn(stops::mirror(
                self.ctx.stops.clone(),
                id,
                hold.clone(),
            )));
            tokio::spawn(latch(
                self.ctx.clone(),
                hold.clone(),
                id,
                change,
                epoch,
                answer,
            ));
        } else {
            let change = if emergency {
                IntentChange::Emergency
            } else {
                IntentChange::Stop
            };
            let store = self.ctx.store.clone();
            tokio::spawn(async move {
                let _ = answer.send(store.change_intent(id, change).await.is_ok());
            });
        }
        let sealed = match &entry {
            Some((tx, _)) => {
                let (reply, rx) = oneshot::channel();
                if tx.send(ActorCmd::Stop { emergency, reply }).await.is_ok() {
                    tokio::time::timeout(STOP_WAIT, rx).await.is_ok()
                } else {
                    true
                }
            }
            None => true,
        };
        let durable = matches!(
            tokio::time::timeout(LATCH_WAIT, latched).await,
            Ok(Ok(true))
        );
        if !durable {
            let marked = match marked {
                Some(m) => matches!(tokio::time::timeout(LATCH_WAIT, m).await, Ok(Ok(true))),
                None => false,
            };
            if marked {
                tracing::error!(instance = %id, "stop latch not durable yet; retrying (its marker is on disk)");
            } else {
                tracing::error!(instance = %id, "stop latch not durable yet and its marker not written: the stop is held in memory only; retrying");
            }
        }
        // Make the actor observe the (possibly) updated intent.
        if let Some((tx, _)) = &entry {
            let _ = tx.send(ActorCmd::Reconcile { user: false }).await;
        }
        // Its worker is gone and its key lease with it: a start refused that key may go ahead.
        self.ctx.key_released();
        Ok(StopOutcome { sealed, durable })
    }

    /// Clear the emergency latch and let the actor reconcile.
    ///
    /// # Errors
    ///
    /// A Store error writing the intent; the errors of [`Self::status`].
    pub async fn clear_emergency(&self, id: InstanceId) -> Result<InstanceStatus, ApiError> {
        let hold = self.hold(id);
        let seen = hold.as_ref().map(|h| h.get().epoch);
        {
            let _writes = match &hold {
                Some(h) => Some(h.writes.lock().await),
                None => None,
            };
            self.ctx
                .store
                .change_intent(id, IntentChange::ClearEmergency)
                .await
                .map_err(|e| e.to_api())?;
            if let (Some(h), Some(seen)) = (&hold, seen) {
                h.emergency_cleared(seen);
            }
        }
        if let Some(h) = &hold {
            stops::mirror(self.ctx.stops.clone(), id, h.clone()).await;
        }
        if let Some(tx) = self.actor(id) {
            let _ = tx.send(ActorCmd::Reconcile { user: true }).await;
        }
        self.status(id).await
    }

    /// Stop the worker and start it again, keeping the user's "running" intent.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::start_instance`].
    pub async fn restart_instance(&self, id: InstanceId) -> Result<InstanceStatus, ApiError> {
        // A restart keeps the user's "running" intent: stop the worker, then reconcile.
        if let Some(tx) = self.actor(id) {
            let (reply, rx) = oneshot::channel();
            if tx
                .send(ActorCmd::Stop {
                    emergency: false,
                    reply,
                })
                .await
                .is_ok()
            {
                let _ = rx.await;
            }
        }
        self.start_instance(id).await
    }

    /// The Instance's status, from its actor.
    ///
    /// # Errors
    ///
    /// `NotFound` without an actor for `id`, `Unavailable` when the actor is gone, `Timeout`
    /// when it does not answer in time.
    pub async fn status(&self, id: InstanceId) -> Result<InstanceStatus, ApiError> {
        let tx = self
            .actor(id)
            .ok_or_else(|| ApiError::not_found("Instance"))?;
        let (reply, rx) = oneshot::channel();
        tx.send(ActorCmd::Inspect(reply))
            .await
            .map_err(|_| interrupted())?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| status_timed_out())?
            .map_err(|_| interrupted())
    }

    /// Where the controller reaches the Instance's private connector, and for which generation.
    /// Only while the Instance is Ready with its gate open; otherwise Provider work is blocked.
    ///
    /// # Errors
    ///
    /// `NotFound` without an actor, `Unavailable` when the actor is gone, `Timeout` when it does
    /// not answer in time, `InvalidState` when the Instance is not Ready with its gate open.
    pub async fn provider_route(&self, id: InstanceId) -> Result<(u64, String), ApiError> {
        let tx = self
            .actor(id)
            .ok_or_else(|| ApiError::not_found("Instance"))?;
        let (reply, rx) = oneshot::channel();
        tx.send(ActorCmd::Route(reply))
            .await
            .map_err(|_| interrupted())?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| status_timed_out())?
            .map_err(|_| interrupted())?
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::InvalidState,
                    tr!(
                        "The egress connection is not ready yet; provider operations are paused",
                        "出口連線尚未就緒，供應商操作暫停",
                        "出口の接続がまだ準備できていません。プロバイダーの操作は一時停止しています"
                    ),
                )
            })
    }

    pub async fn statuses(&self) -> Vec<InstanceStatus> {
        let ids: Vec<_> = self.actors.lock().keys().copied().collect();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Ok(s) = self.status(id).await {
                out.push(s);
            }
        }
        out
    }

    /// Start a process in a strict Instance's sandbox (Linux), e.g. a managed App with
    /// `AppIsolation::StrictNetns`. The sandbox is built for the stored configuration if it does
    /// not exist yet; the process is offline until the Instance runs, and goes offline (never
    /// elsewhere) whenever it stops. The result names the process by host pid and start time and
    /// can terminate or kill its whole tree.
    ///
    /// # Errors
    ///
    /// `NotFound` without an actor, `Unavailable` when the actor is gone, `Timeout` when the
    /// spawn does not finish in time, or the actor's own refusal of the spawn.
    pub async fn sandbox_spawn(
        &self,
        id: InstanceId,
        spec: vpn_platform::sandbox::SpawnSpec,
    ) -> Result<vpn_platform::sandbox::SandboxProcess, ApiError> {
        let tx = self
            .actor(id)
            .ok_or_else(|| ApiError::not_found("Instance"))?;
        let (reply, rx) = oneshot::channel();
        tx.send(ActorCmd::SandboxSpawn(Box::new(spec), reply))
            .await
            .map_err(|_| interrupted())?;
        tokio::time::timeout(Duration::from_secs(30), rx)
            .await
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::Timeout,
                    tr!(
                        "Starting in the sandbox timed out",
                        "sandbox 啟動逾時",
                        "サンドボックスでの起動がタイムアウトしました"
                    ),
                )
            })?
            .map_err(|_| interrupted())?
    }

    /// Gateway configuration of an Instance changed.
    pub async fn gateways_changed(&self, id: InstanceId) {
        if let Some(tx) = self.actor(id) {
            let _ = tx.send(ActorCmd::GatewaysChanged).await;
        }
    }

    /// Port forwards of an Instance were saved or deleted: a running worker gets them at once.
    pub async fn forwards_changed(&self, id: InstanceId) {
        if let Some(tx) = self.actor(id) {
            let _ = tx.send(ActorCmd::ForwardsChanged).await;
        }
    }

    /// One port forward's status, from the actor of its connection.
    ///
    /// # Errors
    ///
    /// `NotFound` when the forward's connection has no actor or the actor does not know the
    /// forward, `Unavailable` when the actor is gone, `Timeout` when it does not answer in time.
    pub async fn forward_status(
        &self,
        binding: &ForwardBinding,
    ) -> Result<ForwardStatus, ApiError> {
        let tx = self.actor(binding.instance_id).ok_or_else(|| {
            ApiError::not_found(tr!(
                "the connection of the port forward",
                "轉發的連線",
                "ポート転送の接続"
            ))
        })?;
        let (reply, rx) = oneshot::channel();
        tx.send(ActorCmd::ForwardStatus(binding.id, reply))
            .await
            .map_err(|_| interrupted())?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::Timeout,
                    tr!(
                        "The port forward status query timed out",
                        "轉發狀態查詢逾時",
                        "ポート転送の状態の問い合わせがタイムアウトしました"
                    ),
                )
            })?
            .map_err(|_| interrupted())?
            .ok_or_else(|| ApiError::not_found(tr!("the port forward", "轉發", "ポート転送")))
    }

    /// Every port forward's status (actors that do not answer in time are left out: their
    /// forwards have no status rather than a guessed one).
    pub async fn forward_statuses(&self) -> Vec<ForwardStatus> {
        let actors: Vec<_> = self.actors.lock().values().map(|e| e.tx.clone()).collect();
        let mut out = Vec::new();
        for tx in actors {
            let (reply, rx) = oneshot::channel();
            if tx.send(ActorCmd::ForwardStatuses(reply)).await.is_err() {
                continue;
            }
            if let Ok(Ok(v)) = tokio::time::timeout(Duration::from_secs(5), rx).await {
                out.extend(v);
            }
        }
        out
    }

    /// Rules of a forward that need the Store and the host: see [`forwards::check_binding`].
    ///
    /// # Errors
    ///
    /// The rule the binding breaks, or a Store error while checking it.
    pub async fn check_forward(&self, f: &ForwardBinding) -> Result<(), ApiError> {
        forwards::check_binding(&self.ctx.store, f).await
    }

    /// An Instance or a `WireGuard`, DNS or security profile was saved: Instances whose start is
    /// blocked by their configuration try again (only those the user still wants running).
    pub fn config_changed(&self) {
        self.ctx.config_changed();
    }

    /// Whether VPN Manager itself holds `g`'s port for `g`: its Instance keeps the listener
    /// while stopped and across generations, so a test bind would only meet our own socket.
    pub(crate) async fn holds_gateway_port(&self, g: &GatewaySpec) -> bool {
        let Some(tx) = self.actor(g.instance_id) else {
            return false;
        };
        let (reply, rx) = oneshot::channel();
        if tx.send(ActorCmd::HeldPort(g.id, reply)).await.is_err() {
            return false;
        }
        matches!(
            tokio::time::timeout(Duration::from_secs(5), rx).await,
            Ok(Ok(Some(port))) if port == g.port
        )
    }

    /// The Instance was deleted: release everything it held.
    pub async fn instance_removed(&self, id: InstanceId) {
        let entry = self.actors.lock().remove(&id);
        if let Some(entry) = entry {
            let (reply, rx) = oneshot::channel();
            if entry.tx.send(ActorCmd::Remove(reply)).await.is_ok() {
                let _ = rx.await;
            }
        }
        // So did its pending stop, if any.
        let stops = self.ctx.stops.clone();
        match tokio::task::spawn_blocking(move || stops.forget(id)).await {
            Ok(Ok(())) => {}
            _ => {
                tracing::warn!(instance = %id, "pending-stop marker of a deleted Instance not removed");
            }
        }
        // Its key leases went with it.
        self.ctx.key_released();
    }

    /// Stop every worker without touching intents (they recover on the next start). A stop whose
    /// latch is still not on disk gets one more attempt; failing that, its marker stays and the
    /// next start holds that Instance for the user to confirm — this exit is not a clean one for
    /// it, and its old `running` intent is not trusted.
    ///
    /// From its first moment no call is served (connections already open are still answered,
    /// with `UNAVAILABLE`): while the actors are let go one by one an Instance would otherwise
    /// read as not found, and a caller could take it for deleted.
    pub async fn shutdown(&self) {
        self.ctx.closing.store(true, Ordering::SeqCst);
        // SSH downloads stop (their records stay; the next start continues them).
        if let Some(d) = self.downloads.get() {
            d.shutdown().await;
        }
        // Managed Apps first: nothing supervises them once the manager is gone.
        self.apps.shutdown().await;
        self.flush_stops().await;
        let actors: Vec<_> = self.actors.lock().drain().collect();
        for (_, entry) in actors {
            let (reply, rx) = oneshot::channel();
            if entry.tx.send(ActorCmd::Shutdown(reply)).await.is_ok() {
                let _ = tokio::time::timeout(Duration::from_secs(5), rx).await;
            }
        }
        // Best effort: the last queued samples.
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            self.ctx.metrics.flush(&self.ctx.store),
        )
        .await;
    }

    /// Before exiting: one more attempt at every stop latch that is not on disk, and the marker
    /// of each stop that stays pending brought up to date. A stop carried over from before this
    /// start is left as it is: only the user's decision ends it.
    async fn flush_stops(&self) {
        let holds: Vec<(InstanceId, Arc<Hold>)> = self
            .actors
            .lock()
            .iter()
            .map(|(id, entry)| (*id, entry.hold.clone()))
            .collect();
        for (id, hold) in holds {
            let s = hold.get();
            if !s.pending() {
                continue;
            }
            if !s.unconfirmed {
                let change = if s.emergency {
                    IntentChange::Emergency
                } else {
                    IntentChange::Stop
                };
                let attempt = async {
                    let _writes = hold.writes.lock().await;
                    // A later Start or latch may have settled it meanwhile.
                    if hold.get() != s {
                        return true;
                    }
                    let ok = self.ctx.store.change_intent(id, change).await.is_ok();
                    if ok {
                        hold.latched(s.epoch);
                    }
                    ok
                };
                if !matches!(
                    tokio::time::timeout(LATCH_FLUSH_WAIT, attempt).await,
                    Ok(true)
                ) {
                    tracing::warn!(instance = %id, "stop latch still not on disk at shutdown");
                }
            }
            let marked = stops::mirror(self.ctx.stops.clone(), id, hold.clone()).await;
            if hold.get().pending() {
                tracing::error!(
                    instance = %id,
                    emergency = s.emergency,
                    marker = marked,
                    "the manager exits with a stop that is not on disk: the next start keeps this connection closed until the user confirms the stop or starts it"
                );
            }
        }
    }
}

/// Write the latch of stop `epoch` on the priority lane, after any earlier intent write of the
/// Instance, and keep retrying until it is on disk or a later intent write made it moot. The
/// first attempt answers the stop request.
async fn latch(
    ctx: Arc<Ctx>,
    hold: Arc<Hold>,
    id: InstanceId,
    change: IntentChange,
    epoch: u64,
    answer: oneshot::Sender<bool>,
) {
    let mut answer = Some(answer);
    let mut delay = LATCH_RETRY_MIN;
    loop {
        let result = {
            let _writes = hold.writes.lock().await;
            let state = hold.get();
            if !state.stopped || state.durable {
                // A later Start lifted this stop, or a later write already put it on disk.
                if let Some(answer) = answer.take() {
                    let _ = answer.send(state.durable);
                }
                return;
            }
            ctx.store.change_intent(id, change).await
        };
        match result {
            Ok(_) => {
                hold.latched(epoch);
                match answer.take() {
                    Some(answer) => {
                        let _ = answer.send(true);
                    }
                    // A retry: the stop request has long answered. Only now does the Store say
                    // stopped, which is what frees a key lease the stop could not release.
                    None => ctx.key_released(),
                }
                // On disk: its marker goes (unless a newer stop is pending meanwhile).
                stops::mirror(ctx.stops.clone(), id, hold).await;
                return;
            }
            // The Instance is gone: there is nothing left to latch.
            Err(StoreError::NotFound) => {
                if let Some(answer) = answer.take() {
                    let _ = answer.send(false);
                }
                let stops = ctx.stops.clone();
                let _ = tokio::task::spawn_blocking(move || stops.forget(id)).await;
                return;
            }
            Err(e) => {
                tracing::warn!(instance = %id, error = %e, retry_in = ?delay, "stop latch not on disk");
                if let Some(answer) = answer.take() {
                    let _ = answer.send(false);
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(LATCH_RETRY_MAX);
            }
        }
    }
}
