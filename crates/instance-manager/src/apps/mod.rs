//! Managed Apps: the supervisor. The Platform (`vpn_platform::apps`) does the OS work; this
//! module owns each App's lifecycle.
//!
//! - One entry per App; its starts, stops and approvals run one at a time.
//! - The user's intent (Start → running, Stop → stopped) is durable; faults never change it.
//! - A run is its root process's pid *and* start time. The run's record is in the Store from
//!   the moment it runs until its whole tree is confirmed gone, so a manager that restarts finds
//!   what it left behind: it stops those leftovers (it cannot reap them). Then it starts every
//!   App the user wants running with `restart_on_recovery`, however its last run ended (left by
//!   the previous manager, killed with its sandbox, crashed), once its connection is ready; the
//!   others show why they do not run.
//! - Every 2 s a watcher updates each running tree: new descendants, its sockets (an
//!   `enforced_proxy` App listening on a non-loopback address, or holding a connection that came
//!   in from the network, is stopped — Seatbelt can refuse neither that bind nor that accept), and
//!   whether VPN Manager still holds the Gateway's port (if not, the App is stopped before
//!   another program could take the port and receive its traffic). Seatbelt denials are counted
//!   from the unified log every 30 s. The tree's TCP listeners and UDP sockets are what port
//!   forwards are checked against ([`Apps::target`]); every watcher pass and every status change
//!   is announced on [`Apps::changes`].
//! - The tree is every descendant of the root, its process group, and every process carrying
//!   the run's marker (`proc::RunMarker`: its Seatbelt profile; on Linux `VPNM_RUN` in the
//!   environment and the run's cgroup), so a process that daemonized out of the tree is still
//!   the App's. Where no marker is authoritative (`proxy_env` without a cgroup) a run's end says
//!   that escape cannot be ruled out.
//! - Stop: SIGTERM to the process group and every tracked descendant, 10 s, SIGKILL, and
//!   "stopped" only once the process table shows nothing of the tree left.
//! - What the executable is ([`AppClass`]) decides how it starts: a browser gets a data
//!   directory of its own in the App's home (shown in the argv), so a copy the user already runs
//!   never receives the start; a program that may hand its start over (a macOS app, `open`) is
//!   refused under `enforced_proxy`. A root of such a program that exits 0 within seconds while
//!   the same program runs outside the tree is reported as a handoff (`APP_HANDOFF`), never as
//!   an ordinary end, and that other process is never signalled.
//! - A `strict_netns` App's local access ports ([`access`]) publish ports of its sandbox on the
//!   host: the manager holds their listeners for as long as the App is configured with them,
//!   admits each client, and hands it to the App's launcher, which relays it inside the sandbox.

mod access;
mod launch;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use rand::RngExt;
use tokio::sync::{broadcast, watch};
use vpn_domain::validation::{check_app, check_app_class};
use vpn_domain::{
    APP_STOP_GRACE_DEFAULT_SECS, APP_STOP_GRACE_SECS, ApiError, AppAction, AppClass, AppClassInfo,
    AppExit, AppId, AppIsolation, AppLimits, AppListener, AppLog, AppProcess, AppProcesses,
    AppResource, AppRunState, AppSpec, AppStatus, DesiredState, ErrorCode, ExecutableApproval,
    ExecutableCheck, Fault, FieldError, GatewayId, GatewaySpec, InstanceId, InstanceSpec,
    LimitKind, LimitMechanism, Persistence, ResourceStatus, Severity, Text, Timestamp,
    ValidationReport, tr,
};
use vpn_platform::apps::seatbelt::{self, LogCursor};
use vpn_platform::apps::{
    AppCommand, IsolationBackend, Plain, ProcessIdentity, SandboxProvider, Seatbelt, SpawnLimits,
    class as app_class, executable, log as app_log, proc,
};
use vpn_platform::limits::{Group, Leaf, ResourceControl, TreeLimits};
use vpn_platform::paths::{Paths, ensure_private_dir};
use vpn_store::{AppIntentRow, AppRunRecord, Store, StoreError};
use vpn_sync::{Mutex, RwLock};

use crate::{Manager, ManagerEvent, remove_dir_if_present, remove_file_if_present, send_event};
use access::{AccessPorts, Relay, RunAccess};
use launch::GatewayTarget;

const WATCH_EVERY: Duration = Duration::from_secs(2);
/// First denial count after a start, then the interval between counts.
const DENIALS_FIRST: Duration = Duration::from_secs(4);
const DENIALS_EVERY: Duration = Duration::from_secs(30);
/// After SIGTERM and the App's own grace ([`AppSpec::stop_grace_secs`]), SIGKILL; then this much
/// longer to see the tree gone.
const STOP_CONFIRM: Duration = Duration::from_secs(3);
/// How long a Stop or Restart action waits before it answers with the App still stopping (a
/// control call times out at 30 s).
const ANSWER_WITHIN: Duration = Duration::from_secs(20);
/// How long a start waits for the manager to confirm it holds the Gateway's port, and how long a
/// start after a manager restart keeps waiting for that (the Instance rebinds it first) — or for
/// a strict App's sandbox (the Instance adopts or builds it first).
const GATEWAY_ANSWER: Duration = Duration::from_secs(10);
const RECOVERY_GATEWAY_WAIT: Duration = Duration::from_secs(30);
/// A root that exits 0 this soon after its start, while the same program runs outside its tree,
/// most likely handed the start over to that process.
const HANDOFF_WINDOW: Duration = Duration::from_secs(5);
const MAX_LOG_LINES: u32 = 1000;
const MAX_PROCESSES: usize = 512;

fn fault(code: &str, message: impl Into<Text>) -> Fault {
    Fault {
        code: code.into(),
        message: message.into(),
        at: Timestamp::now(),
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "used as a `map_err` adapter, which hands the error over by value"
)]
fn api(e: StoreError) -> ApiError {
    e.to_api()
}

/// The blocking task of a call did not finish (it panicked): an internal error, whose message
/// sends the user to the service log — where its cause is.
fn task_failed(e: &tokio::task::JoinError) -> ApiError {
    tracing::error!(error = %e, "a blocking task of a managed-app call failed");
    ApiError::internal()
}

fn field_error(
    code: ErrorCode,
    path: &str,
    field_code: &str,
    message: impl Into<Text>,
) -> ApiError {
    let message = message.into();
    ApiError::new(code, message.clone()).with_fields(vec![FieldError {
        path: path.into(),
        code: field_code.into(),
        message,
    }])
}

/// What a missing App is called in a "not found" error.
fn managed_app() -> Text {
    tr!("the managed app", "受管 App", "管理対象アプリ")
}

/// Why strict isolation cannot start here: this build has no backend for it.
fn no_strict_backend() -> Text {
    tr!(
        "This build has no Linux strict isolation backend connected yet",
        "這個版本尚未接上 Linux 嚴格隔離後端",
        "このバージョンには Linux の厳格な分離のバックエンドがまだ接続されていません"
    )
}

/// A validation report's errors as one API error, located by field.
fn report_error(report: &ValidationReport) -> ApiError {
    let fields: Vec<FieldError> = report
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .map(|i| FieldError {
            path: i.path.clone(),
            code: i.code.clone(),
            message: i.message.clone(),
        })
        .collect();
    let first = fields.first().map_or_else(
        || {
            tr!(
                "Validation failed",
                "資料驗證失敗",
                "データの検証に失敗しました"
            )
        },
        |f| f.message.clone(),
    );
    ApiError::new(ErrorCode::ValidationFailed, first).with_fields(fields)
}

fn initial_status(app_id: AppId, desired: DesiredState) -> AppStatus {
    AppStatus {
        app_id,
        desired,
        intent_persistence: Persistence::Durable,
        state: AppRunState::Stopped,
        run_revision: None,
        pid: None,
        started_at: None,
        last_exit: None,
        last_error: None,
        isolation: None,
        gateway_id: None,
        gateway_port: None,
        process_count: None,
        listeners: None,
        sandbox_denials: None,
        resources: None,
        access: Vec::new(),
        observed_at: Timestamp::now(),
    }
}

/// Why a start failed: the reason recorded on the App and the API error class.
struct StartError {
    code: &'static str,
    message: Text,
    api: ErrorCode,
}

impl StartError {
    fn new(code: &'static str, message: impl Into<Text>, api: ErrorCode) -> Self {
        Self {
            code,
            message: message.into(),
            api,
        }
    }

    fn fault(&self) -> Fault {
        fault(self.code, self.message.clone())
    }

    fn api_error(&self) -> ApiError {
        ApiError::new(self.api, self.message.clone())
    }
}

/// The sockets an App's process tree holds, as one watcher pass found them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TreeSockets {
    /// Listening TCP sockets.
    pub tcp: Vec<std::net::SocketAddr>,
    /// Bound UDP sockets.
    pub udp: Vec<std::net::SocketAddr>,
    /// The processes of the tree that pass looked at: a port one of them holds that the pass
    /// did not see was bound after it.
    pub pids: Vec<u32>,
    /// Every local port the tree holds off loopback, `(udp, port)`: listening, connected or
    /// bound. A strict App's payload through the sandbox is told apart by them.
    pub ports: Vec<(bool, u16)>,
    pub at: Instant,
}

/// What a port forward needs to know about its target App right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TargetView {
    /// The supervisor knows no such App.
    Unknown,
    /// Not running (or still starting, or stopping).
    NotRunning(AppRunState),
    Running {
        run_id: String,
        pid: u32,
        /// The connection the run was started for.
        instance_id: InstanceId,
        isolation: AppIsolation,
        /// `None` until the watcher has looked at the tree (or could not read it).
        sockets: Option<TreeSockets>,
    },
}

/// One run of an App.
struct Run {
    /// The run's id, as its record, marker and log name it.
    id: String,
    name: String,
    root: ProcessIdentity,
    /// The connection the App's spec named when the run started.
    instance_id: InstanceId,
    /// The tree's sockets as of the last watcher pass (`None` before it, or when unreadable).
    sockets: Option<TreeSockets>,
    backend: Arc<dyn IsolationBackend>,
    tree: proc::Tree,
    isolation: AppIsolation,
    gateway: Option<GatewayTarget>,
    /// Seatbelt denial tag and where the count continues.
    tag: Option<String>,
    cursor: Option<LogCursor>,
    next_denials: Instant,
    /// A stop of this run is in progress (the exit watcher leaves the cleanup to it).
    stopping: bool,
    /// The run's cgroup (Linux, delegated) and the limits it was started with.
    cgroup: Option<Arc<Leaf>>,
    limits: AppLimits,
    /// Finds the run's processes that left the tree.
    marker: Arc<Mutex<proc::RunMarker>>,
    /// Whether every process of the run is found whatever it does (a Seatbelt marker, a cgroup,
    /// the strict sandbox's pid namespace).
    complete: bool,
    /// What the root runs, and when it started: a quick exit 0 is checked for a handoff.
    handoff: HandoffProbe,
    /// The App's ports its local access ports relay to, as the run was started with them, and
    /// where their connections go (`strict_netns`).
    access_ports: Vec<u16>,
    access: Option<Arc<vpn_platform::sandbox::AccessChannel>>,
    /// The configuration the run was started with (an access-port change of an App port it
    /// already relays applies at once).
    launched: AppSpec,
    /// How long it gets to exit after SIGTERM: the App's current setting (a change applies at
    /// once).
    grace: Duration,
}

/// The App's stop grace ([`AppSpec::stop_grace_secs`], within its bounds).
fn grace_of(spec: &AppSpec) -> Duration {
    Duration::from_secs(u64::from(
        spec.stop_grace_secs
            .clamp(*APP_STOP_GRACE_SECS.start(), *APP_STOP_GRACE_SECS.end()),
    ))
}

/// What a quick exit of a run's root is checked against.
#[derive(Clone)]
struct HandoffProbe {
    class: Option<AppClassInfo>,
    program: PathBuf,
    /// The macOS bundle the program is the main executable of.
    bundle: Option<PathBuf>,
    started: Instant,
}

struct Live {
    status: AppStatus,
    run: Option<Run>,
    /// Root of a tree an earlier manager left running that could not be confirmed ended. Its
    /// run record stays, no new run starts and the App is not deleted until a stop confirms it.
    leftover: Option<ProcessIdentity>,
    /// The leftover's run marker.
    leftover_marker: Option<Arc<Mutex<proc::RunMarker>>>,
    /// Bumped by every intent the user records; a background retry of an older one gives up.
    intent_epoch: u64,
}

struct Entry {
    /// Serialises starts, stops and approvals of the App.
    ops: tokio::sync::Mutex<()>,
    live: Mutex<Live>,
}

impl Entry {
    fn new(status: AppStatus) -> Self {
        Self {
            ops: tokio::sync::Mutex::new(()),
            live: Mutex::new(Live {
                status,
                run: None,
                leftover: None,
                leftover_marker: None,
                intent_epoch: 0,
            }),
        }
    }
}

/// How a leftover of an earlier manager ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Leftover {
    /// Nothing of it was running any more.
    Gone,
    /// It was running and has been stopped.
    Stopped,
    /// Processes of it could not be confirmed gone.
    Unconfirmed,
}

pub struct Apps {
    store: Arc<Store>,
    paths: Paths,
    events: broadcast::Sender<ManagerEvent>,
    entries: Mutex<HashMap<AppId, Arc<Entry>>>,
    /// Directories an App may never read or write: VPN Manager's data and sockets, `~/.ssh`,
    /// the SSH Manager's directory, an installed VPN Manager's data.
    private: RwLock<Vec<PathBuf>>,
    /// The Linux strict sandbox, once wired (`AppIsolation::StrictNetns`).
    strict: RwLock<Option<Arc<dyn SandboxProvider>>>,
    /// cgroup limits of the Apps' trees (or why there are none).
    resources: Arc<ResourceControl>,
    /// Bumped on every status change and after every watcher pass.
    changes: watch::Sender<u64>,
    /// The host's listeners of the Apps' local access ports.
    access: Arc<AccessPorts>,
}

impl std::fmt::Debug for Apps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Apps")
            .field("paths", &self.paths)
            .finish_non_exhaustive()
    }
}

const MIB: u64 = 1024 * 1024;

/// What the App's `limits` ask of its cgroup.
fn tree_limits(l: &AppLimits) -> TreeLimits {
    TreeLimits {
        memory_bytes: l.memory_mib.map(|m| u64::from(m) * MIB),
        tasks: l.processes.map(u64::from),
        cpu_percent: l.cpu_percent,
    }
}

/// The limits `l` sets, with the field each one is.
fn requested(l: &AppLimits) -> Vec<(LimitKind, &'static str)> {
    [
        (
            l.memory_mib.is_some(),
            LimitKind::Memory,
            "/limits/memory_mib",
        ),
        (
            l.cpu_percent.is_some(),
            LimitKind::Cpu,
            "/limits/cpu_percent",
        ),
        (
            l.processes.is_some(),
            LimitKind::Processes,
            "/limits/processes",
        ),
        (
            l.open_files.is_some(),
            LimitKind::OpenFiles,
            "/limits/open_files",
        ),
    ]
    .into_iter()
    .filter_map(|(set, kind, path)| set.then_some((kind, path)))
    .collect()
}

/// The run's confinement now: its cgroup's limits and use, and its open-files limit.
fn run_resources(leaf: Option<&Leaf>, l: &AppLimits) -> ResourceStatus {
    let mut s = leaf.map_or_else(
        || ResourceStatus {
            cgroup: None,
            enforced: Vec::new(),
            unenforced: Vec::new(),
            memory_bytes: None,
            oom_kills: None,
            observed_at: Timestamp::now(),
        },
        Leaf::status,
    );

    if let Some(n) = l.open_files {
        s.enforced.push(vpn_platform::limits::enforced(
            LimitKind::OpenFiles,
            LimitMechanism::Rlimit,
            u64::from(n),
        ));
    }
    s
}

/// What [`Apps::launch`] hands [`Apps::begin_run`]: a run whose root is up and confined.
struct Started {
    run_id: String,
    tmp: PathBuf,
    gateway: Option<GatewayTarget>,
    backend: Arc<dyn IsolationBackend>,
    tag: Option<String>,
    leaf: Option<Arc<Leaf>>,
    limits: AppLimits,
    root: ProcessIdentity,
    child: tokio::process::Child,
    relay: Option<Arc<vpn_platform::sandbox::AccessChannel>>,
    access_ports: Vec<u16>,
    handoff: HandoffProbe,
    pump: app_log::LogPump,
}

/// What one watcher pass found about a run.
struct Pass {
    tree: proc::Tree,
    sockets: Option<TreeSockets>,
    count: Option<u32>,
    listeners: Option<Vec<AppListener>>,
    resources: Option<ResourceStatus>,
    #[expect(
        clippy::option_option,
        reason = "`None`: not counted this pass; `Some(None)`: the unified log cannot be read (see `read_denials`)"
    )]
    denials: Option<Option<(u64, LogCursor)>>,
}

/// A run's arguments and environment.
fn command_line(
    spec: &AppSpec,
    class: Option<&AppClassInfo>,
    gateway: Option<GatewayTarget>,
    (home, tmp): (&Path, &Path),
    run_id: &str,
) -> (Vec<OsString>, Vec<(OsString, OsString)>) {
    let home_s = home.to_string_lossy().into_owned();
    let tmp_s = tmp.to_string_lossy().into_owned();
    let args: Vec<OsString> = launch::arguments(
        class.map(|c| c.class),
        &spec.args,
        gateway.map(|g| g.port),
        &home_s,
    )
    .into_iter()
    .map(OsString::from)
    .collect();
    let account = vpn_platform::apps::account();
    let env: Vec<(OsString, OsString)> = launch::environment(&launch::EnvFacts {
        spec_env: &spec.env,
        isolation: spec.isolation,
        gateway,
        home: &home_s,
        tmp: &tmp_s,
        user: account.as_ref().map(|(name, _)| name.as_str()),
        run_id,
    })
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    (args, env)
}

/// Make a run's private directories (`dir`, `home`, `tmp` and a browser's data directory) and
/// check that its working directory exists.
async fn prepare_dirs(
    dirs: (PathBuf, PathBuf, PathBuf, PathBuf, Option<PathBuf>),
) -> Result<(), StartError> {
    tokio::task::spawn_blocking(move || -> Result<(), StartError> {
        let (dir, home, tmp, cwd, data_dir) = dirs;
        for d in [&dir, &home, &tmp].into_iter().chain(data_dir.as_ref()) {
            ensure_private_dir(d).map_err(|e| {
                StartError::new(
                    "APP_RUN_DIR_UNAVAILABLE",
                    tr!(
                        "Cannot create the app's private directory: {e}",
                        "無法建立 App 的私有目錄：{e}",
                        "アプリのプライベートディレクトリを作成できません：{e}"
                    ),
                    ErrorCode::InvalidState,
                )
            })?;
        }
        if !cwd.is_dir() {
            let dir = cwd.display();
            return Err(StartError::new(
                "APP_WORKING_DIR",
                tr!(
                    "The working directory does not exist: {dir}",
                    "工作目錄不存在：{dir}",
                    "作業ディレクトリが存在しません：{dir}"
                ),
                ErrorCode::InvalidState,
            ));
        }
        Ok(())
    })
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "making an app run's directories failed");
        StartError::new(
            "APP_RUN_DIR_UNAVAILABLE",
            tr!(
                "Cannot create the app's private directory",
                "無法建立 App 的私有目錄",
                "アプリのプライベートディレクトリを作成できません"
            ),
            ErrorCode::Internal,
        )
    })?
}

/// Remove a run's cgroup (if it has one), logging a failure.
fn remove_leaf(leaf: Option<&Leaf>) {
    if let Some(l) = leaf
        && let Err(e) = l.remove()
    {
        tracing::warn!(cgroup = l.rel(), error = %e, "app cgroup not removed");
    }
}

/// Whichever backend started it: the root joins its cgroup now if it did not before `exec`, and
/// on Linux its open-files limit is set (again) by pid. Why a limit is not in force, if one is not.
fn limits_not_applied(
    leaf: Option<&Leaf>,
    root: ProcessIdentity,
    limits: &AppLimits,
) -> Option<Text> {
    let mut not_applied = None;
    if let Some(l) = leaf
        && !l.contains(root.pid)
    {
        // Whether it joined is checked below; the reason it did not goes to the log.
        if let Err(e) = l.place(root.pid) {
            tracing::debug!(cgroup = l.rel(), error = %e, "app root not placed in its cgroup");
        }
        if !l.contains(root.pid) && limits.wants_cgroup() {
            not_applied = Some(tr!(
                "the app did not join its cgroup",
                "App 沒有進入它的 cgroup",
                "アプリが自身の cgroup に入っていません"
            ));
        }
    }
    if cfg!(target_os = "linux")
        && let Some(n) = limits.open_files
    {
        match vpn_platform::limits::set_open_files_of(root.pid, u64::from(n)) {
            Ok(now) if now == u64::from(n) => {}
            Ok(now) => {
                not_applied = Some(tr!(
                    "the open files limit is {now}, not {n}",
                    "開啟檔案數上限是 {now}，不是 {n}",
                    "開けるファイル数の上限が {n} ではなく {now} です"
                ));
            }
            Err(e) => {
                not_applied = Some(tr!(
                    "cannot set the open files limit: {e}",
                    "無法設定開啟檔案數上限：{e}",
                    "開けるファイル数の上限を設定できません：{e}"
                ));
            }
        }
    }
    not_applied
}

/// The start error of a run whose resource limits did not take effect (`why`).
fn limits_not_in_force(why: Text) -> StartError {
    StartError::new(
        "APP_LIMITS_NOT_APPLIED",
        tr!(
            "The resource limits did not take effect ({why}); the app was stopped",
            "資源上限沒有生效（{why}），已停止 App",
            "リソースの上限が有効になりませんでした（{why}）。アプリを停止しました";
            why = why
        ),
        ErrorCode::InvalidState,
    )
}

/// What a stop answers when it cannot confirm that every process of the App ended.
fn stop_unconfirmed() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidState,
        tr!(
            "Cannot confirm that every process of the app has ended",
            "無法確認 App 的所有程序都已結束",
            "アプリのすべてのプロセスが終了したことを確認できません"
        ),
    )
}

/// Stop a run that cannot go on: kill its root, wait for it, kill and remove its cgroup.
async fn abandon(
    backend: &dyn IsolationBackend,
    root: ProcessIdentity,
    child: &mut tokio::process::Child,
    leaf: Option<&Leaf>,
) {
    backend.terminate(root, &[root], true);
    if let Err(e) = child.wait().await {
        tracing::warn!(pid = root.pid, error = %e, "abandoned app root not reaped");
    }
    if let Some(l) = leaf
        && let Err(e) = l.kill()
    {
        // Its removal below fails then too, and says so.
        tracing::debug!(cgroup = l.rel(), error = %e, "app cgroup not killed");
    }
    remove_leaf(leaf);
}

/// The run's cgroup: a process of the tree not in it yet (started before the root joined, or by
/// a backend that placed it elsewhere) joins it; then its use is read.
async fn cgroup_resources(entry: &Entry, alive: &[ProcessIdentity]) -> Option<ResourceStatus> {
    let confined = {
        let live = entry.live.lock();
        live.run
            .as_ref()
            .and_then(|r| r.cgroup.clone().map(|c| (c, r.limits)))
    };
    let (leaf, limits) = confined?;
    let members: Vec<u32> = alive.iter().map(|p| p.pid).collect();
    tokio::task::spawn_blocking(move || {
        let inside = leaf.pids().unwrap_or_default();
        for pid in members.into_iter().filter(|p| !inside.contains(p)) {
            // Best effort: one that did not join is tried again on the next pass.
            if let Err(e) = leaf.place(pid) {
                tracing::trace!(cgroup = leaf.rel(), pid, error = %e, "app process not placed in its cgroup");
            }
        }
        run_resources(Some(&leaf), &limits)
    })
    .await
    .ok()
}

/// One pass over every socket of the tree: its listeners and bound UDP sockets (what the status
/// shows and port forwards are checked against), and every TCP connection — a listener that
/// accepted one connection and closed between two passes leaves the connection behind.
///
/// `None` when a process of the tree could not be read (and the tree is not a strict App's).
async fn scan_sockets(
    pids: Vec<ProcessIdentity>,
    strict: bool,
) -> Option<(Vec<AppListener>, TreeSockets, Vec<String>)> {
    tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        let (mut tcp, mut udp) = (Vec::new(), Vec::new());
        // An `enforced_proxy` App cannot connect anywhere but the Gateway on 127.0.0.1: a
        // connection with another local address came in from the network.
        let mut reached = Vec::new();
        let mut ports = Vec::new();
        let mut seen = Vec::with_capacity(pids.len());
        for p in pids {
            seen.push(p.pid);
            // One pass, in each process's own network namespace (a strict App's are its
            // sandbox's).
            match proc::all_sockets(p.pid) {
                Some(s) => {
                    let off_loopback =
                        |a: &std::net::SocketAddr| !a.ip().to_canonical().is_loopback();
                    ports.extend(
                        s.tcp
                            .iter()
                            .filter(|t| off_loopback(&t.local))
                            .map(|t| (false, t.local.port())),
                    );
                    ports.extend(
                        s.udp
                            .iter()
                            .filter(|a| off_loopback(a))
                            .map(|a| (true, a.port())),
                    );
                    for t in &s.tcp {
                        if t.listening {
                            out.push(AppListener {
                                pid: p.pid,
                                address: t.local.to_string(),
                                loopback: t.local.ip().to_canonical().is_loopback(),
                            });
                            tcp.push(t.local);
                        } else if t.is_from_network() {
                            reached.push(t.remote.map_or_else(
                                || t.local.to_string(),
                                |r| format!("{} ← {r}", t.local),
                            ));
                        }
                    }
                    udp.extend(s.udp);
                }
                // Gone meanwhile: nothing to report for it.
                None if !proc::is_alive(p) => {}
                // A strict App's tree holds VPN Manager's sandbox launcher and the tree's
                // init, kept from ptrace: unreadable, and holding none of the App's sockets.
                // Leaving out what cannot be read only hides ports; it never verifies one.
                None if strict => {}
                None => return None,
            }
        }
        out.sort_by(|a, b| (a.pid, &a.address).cmp(&(b.pid, &b.address)));
        out.dedup();
        reached.sort();
        reached.dedup();
        ports.sort_unstable();
        ports.dedup();
        Some((
            out,
            TreeSockets {
                tcp,
                udp,
                pids: seen,
                ports,
                at: Instant::now(),
            },
            reached,
        ))
    })
    .await
    .ok()
    .flatten()
}

/// Whether the Gateway a run points at is no longer held by VPN Manager on its port.
async fn gateway_lost(manager: &Manager, gateway: Option<GatewayTarget>) -> bool {
    match gateway {
        Some(g) => matches!(
            manager
                .held_gateway_port(g.instance_id, g.id, Duration::from_secs(2))
                .await,
            Ok(port) if port != Some(g.port)
        ),
        None => false,
    }
}

/// The Seatbelt denials since `cursor`, when they are due: `None` when not counted this pass,
/// `Some(None)` when the unified log cannot be read.
async fn read_denials(
    tag: Option<&str>,
    cursor: Option<&LogCursor>,
    next_denials: Instant,
) -> Option<Option<(u64, LogCursor)>> {
    match (tag, cursor) {
        (Some(tag), Some(cursor)) if Instant::now() >= next_denials => {
            let (tag, cursor) = (tag.to_owned(), cursor.clone());
            Some(
                tokio::task::spawn_blocking(move || seatbelt::denials(&tag, &cursor))
                    .await
                    .ok()
                    .flatten(),
            )
        }
        _ => None,
    }
}

/// Why a watcher pass stops the App, if it does: an `enforced_proxy` App listening off loopback
/// or reached from the network, or a Gateway VPN Manager no longer holds.
fn stop_reason(
    isolation: AppIsolation,
    listeners: Option<&[AppListener]>,
    reached: &[String],
    gateway_lost: bool,
) -> Option<Fault> {
    let exposed: Vec<String> = listeners
        .into_iter()
        .flatten()
        .filter(|l| !l.loopback)
        .map(|l| l.address.clone())
        .collect();
    if isolation == AppIsolation::EnforcedProxy && !exposed.is_empty() {
        Some(fault(
            "APP_LISTENER_NOT_LOOPBACK",
            tr!(
                "The app listened on a non-loopback address ({listed}), so other hosts could connect to it; it was stopped",
                "App 在非本機位址監聽（{listed}），其他主機可能連入，已停止",
                "アプリがループバック以外のアドレスで待ち受けていたため（{listed}）、ほかのホストから接続される可能性がありました。停止しました";
                listed = listing(&exposed)
            ),
        ))
    } else if isolation == AppIsolation::EnforcedProxy && !reached.is_empty() {
        Some(fault(
            "APP_CONNECTION_NOT_LOOPBACK",
            tr!(
                "The app had connections that came in from the network, not through the proxy ({listed}); it was stopped",
                "App 有從網路連入、不經代理的連線（{listed}），已停止",
                "アプリに、ネットワークから着信したプロキシを経由しない接続がありました（{listed}）。停止しました";
                listed = listing(reached)
            ),
        ))
    } else if gateway_lost {
        Some(fault(
            "APP_GATEWAY_RELEASED",
            tr!(
                "VPN Manager no longer holds the Gateway's port: the app was stopped so that it cannot connect to another program",
                "代理埠已不再由 VPN Manager 持有：為免 App 連到其他程式，已停止",
                "ゲートウェイのポートを VPN Manager が保持しなくなりました。アプリがほかのプログラムに接続しないよう、停止しました"
            ),
        ))
    } else {
        None
    }
}

async fn snapshot() -> Option<proc::ProcTable> {
    tokio::task::spawn_blocking(proc::snapshot)
        .await
        .ok()
        .and_then(Result::ok)
}

fn exit_of(status: &std::io::Result<std::process::ExitStatus>) -> AppExit {
    use std::os::unix::process::ExitStatusExt;
    let (code, signal) = status
        .as_ref()
        .map_or((None, None), |s| (s.code(), s.signal()));
    AppExit {
        code,
        signal,
        at: Timestamp::now(),
    }
}

/// What a run's end cannot claim when its processes are found by their tree alone.
fn escape_not_ruled_out() -> Text {
    tr!(
        "Some of the app's processes may still be running: this mode cannot always find a process that left the process tree (such as a child that daemonized in the background with setsid), and so cannot end it",
        "無法排除仍有 App 的程序在執行：這個模式不一定找得到脫離程序樹的程序（例如以 setsid 在背景常駐的子程序），也就無法結束它",
        "アプリのプロセスがまだ実行中である可能性を否定できません。このモードでは、プロセスツリーから離れたプロセス（setsid でバックグラウンドに常駐した子プロセスなど）を見つけられるとは限らず、終了させることもできません"
    )
}

/// `reason` (or a plain "stopped"), saying that escape cannot be ruled out.
fn unverified(reason: Option<Fault>) -> Fault {
    match reason {
        Some(mut f) => {
            f.message = tr!(
                "{why}; {escape}",
                "{why}；{escape}",
                "{why}。{escape}";
                why = std::mem::take(&mut f.message),
                escape = escape_not_ruled_out()
            );
            f
        }
        None => fault(
            "APP_END_UNVERIFIED",
            tr!(
                "The app stopped; {escape}",
                "App 已停止；{escape}",
                "アプリは停止しました。{escape}";
                escape = escape_not_ruled_out()
            ),
        ),
    }
}

/// Bring the run's tree up to date: processes carrying its marker or in its cgroup join it, then
/// [`proc::track`] adds descendants and the root's group. Returns whether the tree is full.
fn follow(
    tree: &mut proc::Tree,
    root: ProcessIdentity,
    table: &proc::ProcTable,
    marker: &Mutex<proc::RunMarker>,
    cgroup: Option<&Leaf>,
) -> bool {
    let mut truncated = marker.lock().adopt(tree, root, table);
    // The cgroup holds every process of the App, wherever it went.
    for pid in cgroup.and_then(Leaf::pids).unwrap_or_default() {
        if let Some(info) = table.get(&pid).filter(|i| !i.zombie)
            && !tree.contains_key(&pid)
        {
            if tree.len() >= proc::MAX_TREE {
                truncated = true;
                break;
            }
            tree.insert(pid, info.started_us);
        }
    }
    proc::track(tree, root, table) || truncated
}

/// The marker of a run recorded as `run_id` with `backend`, `tmp` being the App's own temporary
/// directory.
fn marker_of(run_id: &str, backend: &str, tmp: &Path) -> proc::RunMarker {
    let dir = (backend == "seatbelt").then(|| seatbelt::real_path(tmp));
    proc::RunMarker::new(run_id, dir.as_deref())
}

/// Addresses for a message: the first few, and how many there are in all.
fn listing(items: &[String]) -> Text {
    const SHOWN: usize = 4;
    let shown = &items[..items.len().min(SHOWN)];
    let list = tr!(", ", "、", "、").map(|_, separator| shown.join(separator));
    let total = items.len();
    if total > SHOWN {
        tr!(
            "{list} ({total} in all)",
            "{list} 等 {total} 個",
            "{list} など計 {total} 件";
            list = list
        )
    } else {
        list
    }
}

fn exit_message(exit: &AppExit) -> Text {
    match (exit.code, exit.signal) {
        (Some(0), _) => tr!(
            "The app exited on its own (exit code 0)",
            "App 已自行結束（結束碼 0）",
            "アプリは自ら終了しました（終了コード 0）"
        ),
        (Some(c), _) => tr!(
            "The app exited (exit code {c})",
            "App 已結束（結束碼 {c}）",
            "アプリは終了しました（終了コード {c}）"
        ),
        (None, Some(s)) => tr!(
            "The app was ended by signal {s}",
            "App 被訊號 {s} 結束",
            "アプリはシグナル {s} で終了しました"
        ),
        _ => tr!(
            "The app exited (exit status unknown)",
            "App 已結束（結束狀態不明）",
            "アプリは終了しました（終了状態は不明）"
        ),
    }
}

/// The run's tree is gone: its cgroup goes too. A process still in it (one that left the
/// tracked tree, but never the App's cgroup) is the App's own and is killed first.
async fn release_leaf(leaf: Arc<Leaf>) {
    let released = tokio::task::spawn_blocking(move || {
        for _ in 0..20 {
            match leaf.pids() {
                Some(p) if !p.is_empty() => {
                    // Tried again until the cgroup is empty; its removal says if it never is.
                    if let Err(e) = leaf.kill() {
                        tracing::debug!(cgroup = leaf.rel(), error = %e, "app cgroup not killed");
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => break,
            }
        }
        if let Err(e) = leaf.remove() {
            tracing::warn!(cgroup = leaf.rel(), error = %e, "app cgroup not removed");
        }
    })
    .await;
    if let Err(e) = released {
        tracing::error!(error = %e, "releasing an app cgroup failed");
    }
}

/// Whether the root of a run, which just exited 0, most likely handed its start over to a
/// process outside the App's tree: the reason when so. Only programs that can do that (a
/// browser, a macOS app, a launcher) are checked, and only within [`HANDOFF_WINDOW`] of the
/// start. The tree is brought up to date first (its group, its marker, its cgroup), so the App's
/// own processes are never taken for another instance; nothing found is ever signalled.
async fn handed_off(
    probe: HandoffProbe,
    mut tree: proc::Tree,
    root: ProcessIdentity,
    marker: Arc<Mutex<proc::RunMarker>>,
    cgroup: Option<Arc<Leaf>>,
) -> Option<Fault> {
    let class = probe.class.clone()?;
    let after = probe.started.elapsed();
    if after > HANDOFF_WINDOW {
        return None;
    }
    let secs = after.as_secs().max(1);
    let name = &class.name;
    if class.class == AppClass::Launcher {
        return Some(fault(
            "APP_HANDOFF",
            tr!(
                "“{name}” ended within {secs} s of its start: it handed the start over to the system, so the program that started was not started by VPN Manager, is not in this app's process tree and is not managed by it, and its traffic does not necessarily go through the VPN",
                "「{name}」啟動後 {secs} 秒內就結束：它把啟動交給了系統，被啟動的程式不是 VPN Manager 啟動的、不在這個 App 的程序樹裡，不受它管理，流量也不一定經過 VPN",
                "「{name}」は起動後 {secs} 秒以内に終了しました。起動をシステムに引き渡したため、起動されたプログラムは VPN Manager が起動したものではなく、このアプリのプロセスツリーになく管理もされません。通信が VPN を経由するとも限りません"
            ),
        ));
    }
    let other = tokio::task::spawn_blocking(move || {
        let table = proc::snapshot().ok()?;
        follow(&mut tree, root, &table, &marker, cgroup.as_deref());
        app_class::same_program_elsewhere(&table, &tree, &probe.program, probe.bundle.as_deref())
    })
    .await
    .ok()
    .flatten()?;
    let pid = other.pid;
    Some(fault(
        "APP_HANDOFF",
        tr!(
            "The app exited with code 0 within {secs} s of its start, while “{name}” still runs a process outside this app's process tree (pid {pid}): this start most likely went to that process, which was already running and is not protected by VPN Manager; its traffic is not protected by this app's settings",
            "App 啟動後 {secs} 秒內就以結束碼 0 結束，而「{name}」還有不在這個 App 程序樹裡的程序在執行（pid {pid}）：這次啟動很可能交給了那個已在執行、不受 VPN Manager 保護的程序，它的流量不受這個 App 的設定保護",
            "アプリは起動後 {secs} 秒以内に終了コード 0 で終了しましたが、「{name}」にはこのアプリのプロセスツリーにないプロセスがまだ実行中です（pid {pid}）。今回の起動は、すでに実行中で VPN Manager に保護されていないそのプロセスに引き渡された可能性が高く、その通信はこのアプリの設定では保護されません"
        ),
    ))
}

/// Stop what an earlier manager left running of the run rooted at `root` (and marked by
/// `marker`): SIGTERM, up to `grace`, SIGKILL.
async fn stop_leftover(
    root: ProcessIdentity,
    marker: &Mutex<proc::RunMarker>,
    grace: Duration,
) -> Leftover {
    let mut tree = proc::Tree::new();
    let started = Instant::now();
    let mut termed = false;
    let mut found = false;
    loop {
        if let Some(table) = snapshot().await {
            follow(&mut tree, root, &table, marker, None);
            let alive = proc::alive(&tree, &table);
            if alive.is_empty() {
                return if found {
                    Leftover::Stopped
                } else {
                    Leftover::Gone
                };
            }
            found = true;
            if started.elapsed() >= grace {
                proc::signal_tree(root, &alive, true);
            } else if !termed {
                proc::signal_tree(root, &alive, false);
                termed = true;
            }
        }
        if started.elapsed() >= grace + STOP_CONFIRM {
            return Leftover::Unconfirmed;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

impl Apps {
    pub(crate) fn new(
        store: Arc<Store>,
        paths: Paths,
        events: broadcast::Sender<ManagerEvent>,
        resources: Arc<ResourceControl>,
    ) -> Arc<Self> {
        let mut private = vec![paths.state.clone(), paths.run.clone()];
        if let Some((_, home)) = vpn_platform::apps::account() {
            private.push(home.join(".ssh"));
        }
        // A development or test manager still keeps Apps out of an installed VPN Manager.
        if let Ok(installed) = Paths::default_for_user()
            && installed.state != paths.state
        {
            private.push(installed.state);
        }
        Arc::new_cyclic(|me| Self {
            store,
            paths,
            events,
            entries: Mutex::new(HashMap::new()),
            private: RwLock::new(private),
            strict: RwLock::new(None),
            resources,
            changes: watch::Sender::new(0),
            access: Arc::new(AccessPorts::new(
                me.clone(),
                Arc::new(vpn_platform::admission::OsHost),
            )),
        })
    }

    /// Announces every App status change and every watcher pass (fresh socket lists).
    pub(crate) fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn changed(&self) {
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// App `id` as a port forward target: its run, the connection it runs for, and the sockets
    /// its tree held at the last watcher pass.
    pub(crate) fn target(&self, id: AppId) -> TargetView {
        let Some(entry) = self.entries.lock().get(&id).cloned() else {
            return TargetView::Unknown;
        };
        let live = entry.live.lock();
        match live.run.as_ref() {
            Some(run) if live.status.state == AppRunState::Running && !run.stopping => {
                TargetView::Running {
                    run_id: run.id.clone(),
                    pid: run.root.pid,
                    instance_id: run.instance_id,
                    isolation: run.isolation,
                    sockets: run.sockets.clone(),
                }
            }
            _ => TargetView::NotRunning(live.status.state),
        }
    }

    /// Keep Apps out of `dir` too (the SSH Manager's directory when it is not `~/.ssh`).
    pub fn protect(&self, dir: PathBuf) {
        let mut private = self.private.write();
        if !private.contains(&dir) {
            private.push(dir);
        }
    }

    /// Wire the Linux strict sandbox: `strict_netns` Apps start through it.
    pub fn set_strict_backend(&self, provider: Arc<dyn SandboxProvider>) {
        *self.strict.write() = Some(provider);
    }

    pub(crate) fn private(&self) -> Vec<PathBuf> {
        self.private.read().clone()
    }

    /// Entries of the stored Apps (at manager start). An App with a run record left behind is
    /// `stopping` until recovery has dealt with it.
    pub(crate) async fn load(&self) -> Result<(), StoreError> {
        let specs = self.store.list::<AppSpec>().await?;
        // Their access ports are held from the start, running or not.
        self.access.sync(&specs).await;
        let intents: HashMap<AppId, AppIntentRow> = self
            .store
            .app_intents()
            .await?
            .into_iter()
            .map(|r| (r.app_id, r))
            .collect();
        let mut entries = self.entries.lock();
        for spec in specs {
            let row = intents.get(&spec.id);
            let mut status =
                initial_status(spec.id, row.map_or(DesiredState::Stopped, |r| r.desired));
            if row.is_some_and(|r| r.run.is_some()) {
                status.state = AppRunState::Stopping;
            }
            entries.insert(spec.id, Arc::new(Entry::new(status)));
        }
        drop(entries);
        Ok(())
    }

    fn entry(&self, id: AppId) -> Arc<Entry> {
        self.entries
            .lock()
            .entry(id)
            .or_insert_with(|| Arc::new(Entry::new(initial_status(id, DesiredState::Stopped))))
            .clone()
    }

    /// The entry of an App that exists in the Store.
    async fn existing(&self, id: AppId) -> Result<Arc<Entry>, ApiError> {
        let known = self.entries.lock().get(&id).cloned();
        if let Some(e) = known {
            return Ok(e);
        }
        match self
            .store
            .get::<AppSpec>(id.to_string())
            .await
            .map_err(api)?
        {
            Some(_) => Ok(self.entry(id)),
            None => Err(ApiError::not_found(managed_app())),
        }
    }

    fn emit(&self, status: AppStatus) {
        send_event(&self.events, ManagerEvent::AppStatus(Box::new(status)));
        self.changed();
    }

    /// Change an entry and publish its new status.
    fn publish(&self, entry: &Entry, f: impl FnOnce(&mut Live)) -> AppStatus {
        let mut live = entry.live.lock();
        f(&mut live);
        live.status.observed_at = Timestamp::now();
        let status = self.view(&live);
        drop(live);
        self.emit(status.clone());
        status
    }

    /// The App's status as reported: what the entry holds, with its access ports as they are.
    fn view(&self, live: &Live) -> AppStatus {
        let mut status = live.status.clone();
        let run = live
            .run
            .as_ref()
            .filter(|r| live.status.state == AppRunState::Running && !r.stopping)
            .map(|r| RunAccess {
                // Without its channel nothing reaches the App: as if started without them.
                ports: if r.access.is_some() {
                    r.access_ports.clone()
                } else {
                    Vec::new()
                },
                listeners: r.sockets.as_ref().map(|s| s.tcp.clone()),
            });
        status.access = self.access.status(status.app_id, run.as_ref());
        status
    }

    /// Publish the App's status again (its access ports changed).
    pub(crate) fn republish(&self, id: AppId) {
        let entry = self.entries.lock().get(&id).cloned();
        if let Some(entry) = entry {
            let status = self.view(&entry.live.lock());
            self.emit(status);
        }
    }

    /// Where a connection admitted on an access port of App `id` for its `app_port` goes now.
    pub(crate) fn access_relay(&self, id: AppId, app_port: u16) -> Relay {
        let entry = self.entries.lock().get(&id).cloned();
        let Some(entry) = entry else {
            return Relay::Stopped;
        };
        let live = entry.live.lock();
        match live.run.as_ref() {
            Some(run) if live.status.state == AppRunState::Running && !run.stopping => {
                if !run.access_ports.contains(&app_port) {
                    return Relay::RestartNeeded;
                }
                run.access
                    .as_ref()
                    .map_or(Relay::Unrelayed, |channel| Relay::Ready(channel.clone()))
            }
            _ => Relay::Stopped,
        }
    }

    /// Hold exactly the access ports the stored Apps configure (after every change of an App).
    async fn sync_access(&self) {
        match self.store.list::<AppSpec>().await {
            Ok(specs) => self.access.sync(&specs).await,
            Err(e) => tracing::warn!(error = %e, "access ports not updated: apps unreadable"),
        }
    }

    fn bump_epoch(entry: &Entry) -> u64 {
        let mut live = entry.live.lock();
        live.intent_epoch += 1;
        live.intent_epoch
    }

    // -----------------------------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------------------------

    /// The App's current status.
    ///
    /// # Errors
    ///
    /// Not found when no such App is stored; the Store's error when it cannot be read.
    pub async fn status(&self, id: AppId) -> Result<AppStatus, ApiError> {
        let entry = self.existing(id).await?;
        let status = self.view(&entry.live.lock());
        Ok(status)
    }

    pub fn statuses(&self) -> Vec<AppStatus> {
        let entries: Vec<Arc<Entry>> = self.entries.lock().values().cloned().collect();
        entries.iter().map(|e| self.view(&e.live.lock())).collect()
    }

    /// Which App of `instance`'s strict sandbox holds each local port, `(udp, port)`, as the
    /// latest watcher pass of each running App saw it. A port two Apps hold (one ended, the
    /// other took it since) belongs to neither.
    pub(crate) fn strict_ports(&self, instance: InstanceId) -> HashMap<(bool, u16), AppId> {
        let entries: Vec<(AppId, Arc<Entry>)> = self
            .entries
            .lock()
            .iter()
            .map(|(id, e)| (*id, e.clone()))
            .collect();
        let mut owners: HashMap<(bool, u16), Option<AppId>> = HashMap::new();
        for (id, entry) in entries {
            let held: Vec<(bool, u16)> = {
                let live = entry.live.lock();
                live.run
                    .as_ref()
                    .filter(|r| {
                        r.instance_id == instance
                            && r.isolation == AppIsolation::StrictNetns
                            && !r.stopping
                    })
                    .and_then(|r| r.sockets.as_ref())
                    .map_or_default(|s| s.ports.clone())
            };
            for key in &held {
                owners
                    .entry(*key)
                    .and_modify(|o| {
                        if *o != Some(id) {
                            *o = None;
                        }
                    })
                    .or_insert(Some(id));
            }
        }
        owners
            .into_iter()
            .filter_map(|(k, o)| o.map(|id| (k, id)))
            .collect()
    }

    /// The process trees this manager supervises, for the recovery report.
    pub fn resources(&self) -> Vec<AppResource> {
        let entries: Vec<(AppId, Arc<Entry>)> = self
            .entries
            .lock()
            .iter()
            .map(|(id, e)| (*id, e.clone()))
            .collect();
        let mut out: Vec<AppResource> = entries
            .iter()
            .filter_map(|(id, e)| {
                let live = e.live.lock();
                let run = live.run.as_ref()?;
                Some(AppResource {
                    app_id: *id,
                    pid: run.root.pid,
                    process_started_at: live.status.started_at,
                    state: live.status.state,
                    process_count: live.status.process_count,
                })
            })
            .collect();
        out.sort_by_key(|r| r.pid);
        out
    }

    /// Trees an earlier manager left running that could not be confirmed ended, by App.
    pub(crate) fn leftovers(&self) -> Vec<(AppId, ProcessIdentity)> {
        let entries: Vec<(AppId, Arc<Entry>)> = self
            .entries
            .lock()
            .iter()
            .map(|(id, e)| (*id, e.clone()))
            .collect();
        entries
            .iter()
            .filter_map(|(id, e)| e.live.lock().leftover.map(|root| (*id, root)))
            .collect()
    }

    /// Name of a running App that uses `gateway`: the Gateway's port, kind and listener must not
    /// change under it.
    pub fn gateway_in_use(&self, gateway: GatewayId) -> Option<String> {
        let entries: Vec<Arc<Entry>> = self.entries.lock().values().cloned().collect();
        entries.iter().find_map(|e| {
            let live = e.live.lock();
            live.run
                .as_ref()
                .filter(|r| r.gateway.is_some_and(|g| g.id == gateway))
                .map(|r| r.name.clone())
        })
    }

    /// What the executable at `path` is and whether it may be approved.
    ///
    /// # Errors
    ///
    /// Internal when the inspection task fails.
    pub async fn check_executable(&self, path: String) -> Result<ExecutableCheck, ApiError> {
        let private = self.private();
        tokio::task::spawn_blocking(move || executable::inspect(&path, &private))
            .await
            .map_err(|e| task_failed(&e))
    }

    /// The processes of the App's current run.
    ///
    /// # Errors
    ///
    /// Not found when no such App is stored; the Store's error when it cannot be read.
    pub async fn processes(&self, id: AppId) -> Result<AppProcesses, ApiError> {
        let entry = self.existing(id).await?;
        let run = {
            let live = entry.live.lock();
            live.run
                .as_ref()
                .map(|r| (r.root, r.tree.clone(), r.marker.clone(), r.cgroup.clone()))
        };
        let Some((root, mut tree, marker, cgroup)) = run else {
            return Ok(AppProcesses {
                app_id: id,
                processes: Vec::new(),
                truncated: false,
                observed_at: Timestamp::now(),
            });
        };
        let listed = tokio::task::spawn_blocking(move || {
            let table = proc::snapshot().ok()?;
            let truncated = follow(&mut tree, root, &table, &marker, cgroup.as_deref());
            let mut alive = proc::alive(&tree, &table);
            alive.sort_by_key(|i| (i.pid != root.pid, i.started_us, i.pid));
            let more = truncated || alive.len() > MAX_PROCESSES;
            alive.truncate(MAX_PROCESSES);
            let processes = alive
                .iter()
                .filter_map(|i| {
                    let info = table.get(&i.pid)?;
                    let usage = proc::usage(i.pid);
                    Some(AppProcess {
                        pid: i.pid,
                        ppid: info.ppid,
                        started_at: Timestamp::from_unix_millis(proc::started_unix_ms(
                            info.started_us,
                        )?)?,
                        name: info.name.clone(),
                        cpu_ms: usage.cpu_ns.map(|n| n / 1_000_000),
                        rss_bytes: usage.rss_bytes,
                    })
                })
                .collect();
            Some((processes, more))
        })
        .await
        .map_err(|e| task_failed(&e))?;
        let (processes, truncated) = listed.ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unavailable,
                tr!(
                    "The process list cannot be read right now",
                    "目前無法讀取程序清單",
                    "現在プロセスの一覧を読み取れません"
                ),
            )
        })?;
        Ok(AppProcesses {
            app_id: id,
            processes,
            truncated,
            observed_at: Timestamp::now(),
        })
    }

    /// The last `lines` lines of the App's output log.
    ///
    /// # Errors
    ///
    /// Not found when no such App is stored, internal when the read task fails, and
    /// unavailable when the log cannot be read.
    pub async fn log(&self, id: AppId, lines: u32) -> Result<AppLog, ApiError> {
        self.existing(id).await?;
        let path = self.paths.app_log(&id.to_string());
        let n = lines.clamp(1, MAX_LOG_LINES) as usize;
        let (lines, truncated) = tokio::task::spawn_blocking(move || app_log::tail(&path, n))
            .await
            .map_err(|e| task_failed(&e))?
            .map_err(|e| {
                tracing::warn!(app = %id, error = %e, "app output log not read");
                ApiError::new(
                    ErrorCode::Unavailable,
                    tr!(
                        "Cannot read the app's output log",
                        "無法讀取 App 的輸出紀錄",
                        "アプリの出力ログを読み取れません"
                    ),
                )
            })?;
        Ok(AppLog {
            app_id: id,
            lines,
            truncated,
            observed_at: Timestamp::now(),
        })
    }

    // -----------------------------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------------------------

    /// Whether `isolation` can run on this host (and build); the reason when not.
    async fn mode_available(&self, isolation: AppIsolation) -> Result<(), Text> {
        match isolation {
            AppIsolation::ProxyEnv => Ok(()),
            AppIsolation::EnforcedProxy => tokio::task::spawn_blocking(seatbelt::available)
                .await
                .unwrap_or_else(|_| {
                    Err(tr!(
                        "Cannot confirm whether Seatbelt is available",
                        "無法確認 Seatbelt 是否可用",
                        "Seatbelt が使用できるかを確認できません"
                    ))
                }),
            AppIsolation::StrictNetns => {
                if !cfg!(target_os = "linux") {
                    return Err(tr!(
                        "Strict isolation (rootless network namespace) is available on Linux only",
                        "嚴格隔離（rootless network namespace）只在 Linux 提供",
                        "厳格な分離（rootless network namespace）は Linux でのみ利用できます"
                    ));
                }
                if self.strict.read().is_none() {
                    return Err(no_strict_backend());
                }
                Ok(())
            }
        }
    }

    /// Rules that need the Store or the host: the isolation mode is available here, the
    /// Instance and Gateway exist and belong together, and no writable path opens a private
    /// directory.
    async fn validate(&self, spec: &AppSpec) -> Result<(), ApiError> {
        let report = check_app(spec);
        if report.has_errors() {
            return Err(report_error(&report));
        }
        // What the executable is decides more: a browser's data directory is the launcher's, and
        // a program that may hand its start over is not run as if it were confined.
        let exe = spec.executable.clone();
        let class = tokio::task::spawn_blocking(move || executable::recognise(&exe))
            .await
            .map_err(|e| task_failed(&e))?;
        let report = check_app_class(spec, class.as_ref());
        if report.has_errors() {
            return Err(report_error(&report));
        }
        if let Err(reason) = self.mode_available(spec.isolation).await {
            return Err(field_error(
                ErrorCode::UnsupportedCapability,
                "/isolation",
                "APP_ISOLATION_UNAVAILABLE",
                reason,
            ));
        }
        self.check_limits(spec)?;
        let Some(instance) = self
            .store
            .get::<InstanceSpec>(spec.instance_id.to_string())
            .await
            .map_err(api)?
        else {
            return Err(field_error(
                ErrorCode::ValidationFailed,
                "/instance_id",
                "APP_INSTANCE",
                tr!(
                    "Cannot find this connection",
                    "找不到這條連線",
                    "この接続が見つかりません"
                ),
            ));
        };
        // Strict mode runs the App in its connection's sandbox: there must be one.
        if spec.isolation == AppIsolation::StrictNetns && !instance.strict {
            return Err(field_error(
                ErrorCode::ValidationFailed,
                "/instance_id",
                "APP_INSTANCE_NOT_STRICT",
                tr!(
                    "An app with strict isolation needs a connection with strict isolation turned on",
                    "嚴格隔離的 App 需要啟用嚴格隔離的連線",
                    "厳格な分離のアプリには、厳格な分離を有効にした接続が必要です"
                ),
            ));
        }
        self.check_gateway(spec).await?;
        self.check_access(spec).await?;
        self.check_writable(spec).await
    }

    /// The limits `spec` asks for are ones this host enforces, within its open-files ceiling.
    fn check_limits(&self, spec: &AppSpec) -> Result<(), ApiError> {
        // A limit this host cannot enforce is refused, never stored as if it applied.
        for (kind, path) in requested(&spec.limits) {
            if let Some(reason) = self.resources.unavailable(kind) {
                return Err(field_error(
                    ErrorCode::UnsupportedCapability,
                    path,
                    "APP_LIMIT_UNAVAILABLE",
                    tr!(
                        "This host cannot apply this limit: {reason}",
                        "此主機無法套用這個上限：{reason}",
                        "このホストではこの上限を適用できません：{reason}";
                        reason = reason
                    ),
                ));
            }
        }
        if let (Some(n), Some(max)) = (
            spec.limits.open_files,
            vpn_platform::limits::open_files_max(),
        ) && u64::from(n) > max
        {
            return Err(field_error(
                ErrorCode::ValidationFailed,
                "/limits/open_files",
                "APP_LIMIT_OPEN_FILES",
                tr!(
                    "Open files cannot exceed {max}, the limit this host allows VPN Manager",
                    "開啟檔案數不能超過這台主機允許 VPN Manager 的上限 {max}",
                    "開けるファイル数は、このホストが VPN Manager に許可している上限 {max} を超えられません"
                ),
            ));
        }
        Ok(())
    }

    /// The Gateway `spec` names, if any, exists and belongs to the App's connection.
    async fn check_gateway(&self, spec: &AppSpec) -> Result<(), ApiError> {
        if let Some(gid) = spec.gateway_id {
            match self
                .store
                .get::<GatewaySpec>(gid.to_string())
                .await
                .map_err(api)?
            {
                None => {
                    return Err(field_error(
                        ErrorCode::ValidationFailed,
                        "/gateway_id",
                        "APP_GATEWAY",
                        tr!(
                            "Cannot find this Gateway",
                            "找不到這個代理埠",
                            "このゲートウェイが見つかりません"
                        ),
                    ));
                }
                Some(g) if g.instance_id != spec.instance_id => {
                    return Err(field_error(
                        ErrorCode::ValidationFailed,
                        "/gateway_id",
                        "APP_GATEWAY_INSTANCE",
                        tr!(
                            "The Gateway must belong to the connection the app uses",
                            "代理埠必須屬於 App 使用的連線",
                            "ゲートウェイはアプリが使用する接続のものでなければなりません"
                        ),
                    ));
                }
                Some(_) => {}
            }
        }
        Ok(())
    }

    /// No writable path of `spec` opens (or lies in) a private directory.
    async fn check_writable(&self, spec: &AppSpec) -> Result<(), ApiError> {
        let private = self.private();
        let writable = spec.writable_paths.clone();
        let overlap = tokio::task::spawn_blocking(move || {
            let private: Vec<PathBuf> = private.iter().map(|p| seatbelt::real_path(p)).collect();
            writable.iter().position(|w| {
                let real = seatbelt::real_path(Path::new(w));
                private
                    .iter()
                    .any(|p| real.starts_with(p) || p.starts_with(&real))
            })
        })
        .await
        .map_err(|e| task_failed(&e))?;
        if let Some(i) = overlap {
            return Err(field_error(
                ErrorCode::ValidationFailed,
                &format!("/writable_paths/{i}"),
                "APP_WRITABLE_PRIVATE",
                tr!(
                    "Must not contain or lie inside VPN Manager's data directory or SSH directory",
                    "不可包含或位於 VPN Manager 的資料目錄或 SSH 目錄",
                    "VPN Manager のデータディレクトリや SSH ディレクトリを含めたり、その中に置いたりすることはできません"
                ),
            ));
        }
        Ok(())
    }

    /// An App's access ports take host ports nothing else uses: no Gateway, no other App's
    /// access port, no other program (test-bound as the listener would bind it, unless VPN
    /// Manager already holds it for this App).
    async fn check_access(&self, spec: &AppSpec) -> Result<(), ApiError> {
        if spec.access_ports.is_empty() {
            return Ok(());
        }
        let gateways = self.store.list::<GatewaySpec>().await.map_err(api)?;
        let apps = self.store.list::<AppSpec>().await.map_err(api)?;
        for (i, p) in spec.access_ports.iter().enumerate() {
            let path = format!("/access_ports/{i}/host_port");
            let port = p.host_port;
            if let Some(g) = gateways.iter().find(|g| g.port == port) {
                let name = &g.name;
                return Err(field_error(
                    ErrorCode::ListenerConflict,
                    &path,
                    "PORT_IN_USE",
                    tr!(
                        "port {port} is used by the Gateway “{name}”",
                        "port {port} 已被代理埠「{name}」使用",
                        "ポート {port} はゲートウェイ「{name}」が使用しています"
                    ),
                ));
            }
            if let Some(o) = apps
                .iter()
                .find(|o| o.id != spec.id && o.access_ports.iter().any(|q| q.host_port == port))
            {
                let name = &o.name;
                return Err(field_error(
                    ErrorCode::ListenerConflict,
                    &path,
                    "PORT_IN_USE",
                    tr!(
                        "port {port} is used by a local access port of the app “{name}”",
                        "port {port} 已被 App「{name}」的本機存取埠使用",
                        "ポート {port} はアプリ「{name}」のローカルアクセスポートが使用しています"
                    ),
                ));
            }
            if self.access.holds(spec.id, port) {
                continue;
            }
            let addr = access::address_of(p.bind, port);
            if let Err(e) = access::bind(addr) {
                let message = if e.kind() == std::io::ErrorKind::AddrInUse {
                    tr!(
                        "port {port} is taken by another program; choose another port, or first close the program that holds it",
                        "port {port} 已被其他程式占用；請換一個 port，或先關閉占用它的程式",
                        "ポート {port} はほかのプログラムが使用中です。別のポートにするか、使用中のプログラムを先に終了してください"
                    )
                } else {
                    tr!(
                        "Cannot listen on {addr} ({e}); choose another port",
                        "無法在 {addr} 監聽（{e}）；請換一個 port",
                        "{addr} で待ち受けできません（{e}）。別のポートにしてください"
                    )
                };
                return Err(field_error(
                    ErrorCode::ListenerConflict,
                    &path,
                    "PORT_HELD",
                    message,
                ));
            }
        }
        Ok(())
    }

    /// Inspect `path` now and approve it: refused when it is unusable, or when `expected` (the
    /// SHA-256 the user saw) differs from what the file hashes to now.
    async fn approve_file(
        &self,
        path: &str,
        expected: Option<&str>,
    ) -> Result<ExecutableApproval, ApiError> {
        let check = self.check_executable(path.to_string()).await?;
        if !check.ok {
            let fields: Vec<FieldError> = check
                .issues
                .iter()
                .filter(|i| i.severity == Severity::Error)
                .map(|i| FieldError {
                    path: "/executable".into(),
                    code: i.code.clone(),
                    message: i.message.clone(),
                })
                .collect();
            let first = fields.first().map_or_else(
                || {
                    tr!(
                        "The executable cannot be used",
                        "執行檔無法使用",
                        "実行ファイルを使用できません"
                    )
                },
                |f| f.message.clone(),
            );
            return Err(ApiError::new(ErrorCode::ValidationFailed, first).with_fields(fields));
        }
        let (Some(resolved), Some(sha256), Some(size)) = (check.resolved, check.sha256, check.size)
        else {
            return Err(ApiError::internal());
        };
        if let Some(exp) = expected
            && !exp.trim().eq_ignore_ascii_case(&sha256)
        {
            return Err(field_error(
                ErrorCode::AppArtifactDigestMismatch,
                "/executable",
                "APP_ARTIFACT_DIGEST_MISMATCH",
                tr!(
                    "The executable changed after you checked it (its SHA-256 differs); check it again, then confirm",
                    "執行檔在你檢查之後又變更了（SHA-256 不同）；請重新檢查後再確認",
                    "チェックした後に実行ファイルが変更されました（SHA-256 が異なります）。もう一度チェックしてから確定してください"
                ),
            ));
        }
        Ok(ExecutableApproval {
            path: resolved,
            sha256,
            size,
            approved_at: Timestamp::now(),
            app_class: check.app_class,
        })
    }

    /// Validate, approve and store a new App.
    ///
    /// # Errors
    ///
    /// A validation error when the spec breaks a rule (or this host cannot run it), the
    /// approval's error when the executable cannot be approved, and the Store's error when the
    /// App cannot be stored.
    pub async fn create(
        &self,
        mut spec: AppSpec,
        expected_sha256: Option<String>,
    ) -> Result<AppSpec, ApiError> {
        self.validate(&spec).await?;
        spec.approval = Some(
            self.approve_file(&spec.executable, expected_sha256.as_deref())
                .await?,
        );
        let spec = self.store.create_app(spec).await.map_err(api)?;
        self.sync_access().await;
        let status = self.view(&self.entry(spec.id).live.lock());
        self.emit(status);
        Ok(spec)
    }

    /// A changed executable path is approved like on create; an unchanged one keeps its
    /// approval (a changed file is approved explicitly, with the `approve` action).
    ///
    /// # Errors
    ///
    /// Not found when no such App is stored, a validation or approval error as on create, and
    /// the Store's error (such as a revision conflict) when the update cannot be stored.
    pub async fn update(
        &self,
        mut spec: AppSpec,
        expected_revision: u64,
        expected_sha256: Option<String>,
    ) -> Result<AppSpec, ApiError> {
        let current: AppSpec = self
            .store
            .get(spec.id.to_string())
            .await
            .map_err(api)?
            .ok_or_else(|| ApiError::not_found(managed_app()))?;
        self.validate(&spec).await?;
        spec.approval = if spec.executable == current.executable {
            current.approval
        } else {
            Some(
                self.approve_file(&spec.executable, expected_sha256.as_deref())
                    .await?,
            )
        };
        let updated = self
            .store
            .update(spec, expected_revision)
            .await
            .map_err(api)?;
        self.sync_access().await;
        self.access_applied(&updated);
        Ok(updated)
    }

    /// What of a running App's new configuration its run takes at once: the stop grace always;
    /// the whole configuration when nothing else changed but its access ports — for App ports
    /// its run already relays (the listeners follow it at once).
    fn access_applied(&self, spec: &AppSpec) {
        let entry = self.entries.lock().get(&spec.id).cloned();
        let Some(entry) = entry else {
            return;
        };
        let Some((mut launched, relayed)) = entry
            .live
            .lock()
            .run
            .as_ref()
            .map(|run| (run.launched.clone(), run.access_ports.clone()))
        else {
            return;
        };
        launched.access_ports.clone_from(&spec.access_ports);
        launched.stop_grace_secs = spec.stop_grace_secs;
        launched.meta = spec.meta.clone();
        let applies = launched == *spec
            && spec
                .access_ports
                .iter()
                .all(|p| relayed.contains(&p.app_port));
        self.publish(&entry, |l| {
            if let Some(run) = l.run.as_mut() {
                run.grace = grace_of(spec);
                if applies {
                    run.launched = spec.clone();
                    l.status.run_revision = Some(spec.meta.revision);
                }
            }
        });
    }

    /// Delete an App that runs nothing, with its private directories and its log.
    ///
    /// # Errors
    ///
    /// Invalid state while the App runs (or its stop is unconfirmed), and the Store's error
    /// (not found, revision conflict) when it cannot be deleted.
    pub async fn delete(&self, id: AppId, expected_revision: u64) -> Result<(), ApiError> {
        let entry = self.entries.lock().get(&id).cloned();
        match &entry {
            Some(entry) => {
                let _ops = entry.ops.lock().await;
                let busy = {
                    let live = entry.live.lock();
                    live.run.is_some() || live.leftover.is_some()
                };
                if busy {
                    return Err(ApiError::new(
                        ErrorCode::InvalidState,
                        tr!(
                            "The app is still running (or not confirmed stopped yet); stop it first",
                            "App 仍在執行（或尚未確認停止），請先停止",
                            "アプリはまだ実行中です（または停止をまだ確認できていません）。先に停止してください"
                        ),
                    ));
                }
                self.store
                    .delete_app(id, expected_revision)
                    .await
                    .map_err(api)?;
            }
            None => self
                .store
                .delete_app(id, expected_revision)
                .await
                .map_err(api)?,
        }
        self.entries.lock().remove(&id);
        self.sync_access().await;
        let ids = id.to_string();
        let (dir, tmp, log) = (
            self.paths.app_dir(&ids),
            self.paths.app_tmp(&ids),
            self.paths.app_log(&ids),
        );
        // The App is deleted: what of its files cannot be removed stays behind (logged).
        let removed = tokio::task::spawn_blocking(move || {
            remove_dir_if_present(&dir);
            if !tmp.starts_with(&dir) {
                remove_dir_if_present(&tmp);
            }
            let mut old = log.clone().into_os_string();
            old.push(".1");
            remove_file_if_present(&log);
            remove_file_if_present(&PathBuf::from(old));
        })
        .await;
        if let Err(e) = removed {
            tracing::error!(app = %id, error = %e, "removing a deleted app's files failed");
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Actions
    // -----------------------------------------------------------------------------------------

    /// Start, stop, restart or approve an App.
    ///
    /// # Errors
    ///
    /// The action's error: not found, invalid state, a validation or approval error, or the
    /// Store's error.
    pub async fn action(
        self: &Arc<Self>,

        manager: &Manager,
        id: AppId,
        action: AppAction,
        sha256: Option<String>,
    ) -> Result<AppStatus, ApiError> {
        match action {
            AppAction::Start => self.start(manager, id, true, Duration::ZERO).await,
            // A stop may take the App's whole grace (up to 15 minutes): it goes on by itself,
            // and the answer comes once it is done or, at the latest, after a while with the App
            // still stopping (its status says when it ended).
            AppAction::Stop => {
                let me = Arc::clone(self);
                self.answer_soon(
                    id,
                    tokio::spawn(async move { me.stop(id, true, None).await }),
                )
                .await
            }
            AppAction::Restart => {
                let me = Arc::clone(self);
                let manager = manager.me.upgrade().ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::Unavailable,
                        tr!(
                            "The core service is stopping",
                            "核心服務正在停止",
                            "コアサービスを停止しています"
                        ),
                    )
                })?;
                self.answer_soon(
                    id,
                    tokio::spawn(async move {
                        me.stop(id, false, None).await?;
                        me.start(&manager, id, true, Duration::ZERO).await
                    }),
                )
                .await
            }
            AppAction::Approve => self.approve(id, sha256).await,
        }
    }

    /// The outcome of `task` on App `id` if it ends within [`ANSWER_WITHIN`], else the App's
    /// status as it is (the task goes on; the App's status follows it).
    async fn answer_soon(
        &self,
        id: AppId,
        task: tokio::task::JoinHandle<Result<AppStatus, ApiError>>,
    ) -> Result<AppStatus, ApiError> {
        match tokio::time::timeout(ANSWER_WITHIN, task).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => Err(ApiError::internal()),
            Err(_) => self.status(id).await,
        }
    }

    async fn approve(&self, id: AppId, sha256: Option<String>) -> Result<AppStatus, ApiError> {
        let Some(expected) = sha256 else {
            return Err(field_error(
                ErrorCode::ValidationFailed,
                "/sha256",
                "APP_APPROVE_DIGEST",
                tr!(
                    "Approving needs the SHA-256 you saw",
                    "核准時需要附上你看到的 SHA-256",
                    "承認するには、確認した SHA-256 を添えてください"
                ),
            ));
        };
        let entry = self.existing(id).await?;
        let _ops = entry.ops.lock().await;
        let mut spec: AppSpec = self
            .store
            .get(id.to_string())
            .await
            .map_err(api)?
            .ok_or_else(|| ApiError::not_found(managed_app()))?;
        let revision = spec.meta.revision;
        spec.approval = Some(self.approve_file(&spec.executable, Some(&expected)).await?);
        self.store.update(spec, revision).await.map_err(api)?;
        // A start refused for the old file may be tried again.
        Ok(self.publish(&entry, |l| {
            let refused = l.status.last_error.as_ref().is_some_and(|f| {
                matches!(
                    f.code.as_str(),
                    "APP_ARTIFACT_DIGEST_MISMATCH" | "APP_ARTIFACT_NOT_APPROVED"
                )
            });
            if refused && l.run.is_none() {
                l.status.last_error = None;
                l.status.state = AppRunState::Stopped;
            }
        }))
    }

    /// Start the App (`record_intent`: the user asked, so the durable intent becomes running).
    /// A start after a manager restart waits up to `gateway_wait` for the Gateway's port to be
    /// held again.
    async fn start(
        self: &Arc<Self>,
        manager: &Manager,
        id: AppId,
        record_intent: bool,
        gateway_wait: Duration,
    ) -> Result<AppStatus, ApiError> {
        let entry = self.existing(id).await?;
        let _ops = entry.ops.lock().await;
        {
            let live = entry.live.lock();
            if let Some(run) = &live.run {
                if !run.stopping && live.status.state == AppRunState::Running {
                    // At most one tree per App: a repeated start answers with the running one.
                    return Ok(self.view(&live));
                }
                return Err(ApiError::new(
                    ErrorCode::InvalidState,
                    tr!(
                        "The app is stopping (or cannot be confirmed stopped); wait for it to stop, or press Stop again",
                        "App 正在停止（或無法確認已停止）；請等它停止，或再按一次停止",
                        "アプリを停止しています（または停止を確認できません）。停止するまで待つか、もう一度「停止」を押してください"
                    ),
                ));
            }
            if live.leftover.is_some() {
                return Err(ApiError::new(
                    ErrorCode::InvalidState,
                    tr!(
                        "The app's previous run is not confirmed to have ended yet; press Stop first",
                        "上次啟動的 App 還無法確認已結束；請先按停止",
                        "前回起動したアプリの終了をまだ確認できません。先に「停止」を押してください"
                    ),
                ));
            }
        }
        let spec: AppSpec = self
            .store
            .get(id.to_string())
            .await
            .map_err(api)?
            .ok_or_else(|| ApiError::not_found(managed_app()))?;
        if record_intent {
            Self::bump_epoch(&entry);
            self.store
                .set_app_desired(id, DesiredState::Running)
                .await
                .map_err(api)?;
            self.publish(&entry, |l| {
                l.status.desired = DesiredState::Running;
                l.status.intent_persistence = Persistence::Durable;
            });
        }
        self.publish(&entry, |l| {
            l.status.state = AppRunState::Starting;
            l.status.last_error = None;
        });
        match self.launch(manager, &entry, &spec, gateway_wait).await {
            Ok(status) => Ok(status),
            Err(e) => {
                tracing::warn!(app = %id, code = e.code, "managed app did not start");
                self.publish(&entry, |l| {
                    l.status.state = AppRunState::Failed;
                    l.status.last_error = Some(e.fault());
                });
                Err(e.api_error())
            }
        }
    }

    /// The Gateway the run points at, once VPN Manager is confirmed to hold its port.
    async fn gateway_target(
        &self,
        manager: &Manager,
        spec: &AppSpec,
        wait: Duration,
    ) -> Result<Option<GatewayTarget>, StartError> {
        let Some(gid) = spec.gateway_id else {
            return Ok(None);
        };
        let deadline = Instant::now() + wait;
        loop {
            let g: GatewaySpec = self
                .store
                .get(gid.to_string())
                .await
                .map_err(|e| {
                    StartError::new(
                        "STORE_UNAVAILABLE",
                        e.to_api().message,
                        ErrorCode::Unavailable,
                    )
                })?
                .ok_or_else(|| {
                    StartError::new(
                        "APP_GATEWAY_MISSING",
                        tr!(
                            "Cannot find the app's Gateway",
                            "找不到 App 的代理埠",
                            "アプリのゲートウェイが見つかりません"
                        ),
                        ErrorCode::InvalidState,
                    )
                })?;
            if g.instance_id != spec.instance_id {
                return Err(StartError::new(
                    "APP_GATEWAY_INSTANCE",
                    tr!(
                        "The Gateway does not belong to the connection the app uses",
                        "代理埠不屬於 App 使用的連線",
                        "ゲートウェイがアプリの使用する接続のものではありません"
                    ),
                    ErrorCode::InvalidState,
                ));
            }
            if !g.enabled {
                let name = &g.name;
                return Err(StartError::new(
                    "APP_GATEWAY_DISABLED",
                    tr!(
                        "The Gateway “{name}” is disabled; enable it first",
                        "代理埠「{name}」已停用；請先啟用它",
                        "ゲートウェイ「{name}」は無効です。先に有効にしてください"
                    ),
                    ErrorCode::InvalidState,
                ));
            }
            let answer = manager
                .held_gateway_port(g.instance_id, g.id, GATEWAY_ANSWER)
                .await;
            if answer == Ok(Some(g.port)) {
                return Ok(Some(GatewayTarget {
                    instance_id: g.instance_id,
                    id: g.id,
                    port: g.port,
                    kind: g.kind,
                }));
            }
            if Instant::now() >= deadline {
                let port = g.port;
                let message = match answer {
                    Err(()) => tr!(
                        "Cannot confirm the Gateway's state (connection management is busy); try again later",
                        "無法確認代理埠的狀態（連線管理忙碌中），請稍後再試",
                        "ゲートウェイの状態を確認できません（接続の管理が混み合っています）。しばらくしてからもう一度お試しください"
                    ),
                    Ok(_) => tr!(
                        "VPN Manager does not hold the Gateway port 127.0.0.1:{port} now (another program may have taken it): the app's traffic to it could leave through another program, so the app is not started",
                        "代理埠 127.0.0.1:{port} 目前不由 VPN Manager 持有（可能被其他程式占用）：App 連到它的流量可能經由其他程式送出，所以不啟動",
                        "ゲートウェイのポート 127.0.0.1:{port} は現在 VPN Manager が保持していません（ほかのプログラムが使用している可能性があります）。アプリからそこへの通信がほかのプログラム経由で送られるおそれがあるため、起動しません"
                    ),
                };
                return Err(StartError::new(
                    "APP_GATEWAY_UNAVAILABLE",
                    message,
                    ErrorCode::InvalidState,
                ));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn launch(
        self: &Arc<Self>,
        manager: &Manager,
        entry: &Arc<Entry>,
        spec: &AppSpec,
        gateway_wait: Duration,
    ) -> Result<AppStatus, StartError> {
        self.mode_available(spec.isolation).await.map_err(|m| {
            StartError::new(
                "APP_ISOLATION_UNAVAILABLE",
                m,
                ErrorCode::UnsupportedCapability,
            )
        })?;
        let gateway = self.gateway_target(manager, spec, gateway_wait).await?;
        let private = self.private();
        let (program, class, bundle) = Self::verify_start(spec, &private).await?;
        let ids = spec.id.to_string();
        let (home, tmp, cwd) = self.run_dirs(&ids, spec, class.as_ref()).await?;

        let run_id = format!("{:016x}", rand::rng().random::<u64>());
        let (args, env) = command_line(spec, class.as_ref(), gateway, (&home, &tmp), &run_id);

        let (backend, tag) = self
            .isolation_backend(spec, gateway, &run_id, (&home, &tmp), private, gateway_wait)
            .await?;

        // Its limits: a limit the user set is in force when the App runs, or it does not run.
        let limits = spec.limits;
        let leaf = self.create_leaf(&ids, &limits)?;

        let (output, pump) = app_log::pipe(&self.paths.app_log(&ids)).map_err(|e| {
            remove_leaf(leaf.as_deref());
            StartError::new(
                "APP_RUN_DIR_UNAVAILABLE",
                tr!(
                    "Cannot create the app's output log: {e}",
                    "無法建立 App 的輸出紀錄：{e}",
                    "アプリの出力ログを作成できません：{e}"
                ),
                ErrorCode::InvalidState,
            )
        })?;
        let handoff = HandoffProbe {
            class,
            program: program.clone(),
            bundle,
            started: Instant::now(),
        };
        // Only a sandboxed App's ports need relaying: any other App is on the host already.
        let access_ports: Vec<u16> = if spec.isolation == AppIsolation::StrictNetns {
            spec.access_ports.iter().map(|p| p.app_port).collect()
        } else {
            Vec::new()
        };
        let spawned = backend
            .spawn(AppCommand {
                program,
                args,
                env,
                cwd,
                output,
                limits: SpawnLimits {
                    open_files: limits.open_files.map(u64::from),
                    cgroup_procs: leaf.as_deref().map(Leaf::procs_fd),
                },
                access_ports: access_ports.clone(),
                write_confinement: (spec.isolation == AppIsolation::StrictNetns
                    && spec.confine_writes)
                    .then(|| spec.writable_paths.iter().map(PathBuf::from).collect()),
            })
            .map_err(|e| {
                remove_leaf(leaf.as_deref());
                StartError::new(
                    "APP_SPAWN_FAILED",
                    tr!("Cannot start: {e}", "無法啟動：{e}", "起動できません：{e}"),
                    ErrorCode::InvalidState,
                )
            })?;
        let mut child = spawned.child;
        let root = spawned.identity;
        if let Some(why) = limits_not_applied(leaf.as_deref(), root, &limits) {
            abandon(backend.as_ref(), root, &mut child, leaf.as_deref()).await;
            return Err(limits_not_in_force(why));
        }
        self.begin_run(
            entry,
            spec,
            Started {
                run_id,
                tmp,
                gateway,
                backend,
                tag,
                leaf,
                limits,
                root,
                child,
                relay: spawned.access.map(Arc::new),
                access_ports,
                handoff,
                pump,
            },
        )
        .await
    }

    /// A run's private directories (0700: HOME, TMPDIR, a browser's data directory), made, and
    /// its working directory, checked: `(home, tmp, cwd)`.
    async fn run_dirs(
        &self,
        ids: &str,
        spec: &AppSpec,
        class: Option<&AppClassInfo>,
    ) -> Result<(PathBuf, PathBuf, PathBuf), StartError> {
        let (dir, home, tmp) = (
            self.paths.app_dir(ids),
            self.paths.app_home(ids),
            self.paths.app_tmp(ids),
        );
        let cwd = spec
            .working_dir
            .as_ref()
            .map_or_else(|| home.clone(), PathBuf::from);
        let data_dir = class.and_then(|c| c.class.data_dir()).map(|d| home.join(d));
        prepare_dirs((dir, home.clone(), tmp.clone(), cwd.clone(), data_dir)).await?;
        Ok((home, tmp, cwd))
    }

    /// A started run: recorded, reported running, its relay followed and its exit watched.
    async fn begin_run(
        self: &Arc<Self>,
        entry: &Arc<Entry>,
        spec: &AppSpec,
        started: Started,
    ) -> Result<AppStatus, StartError> {
        let Started {
            run_id,
            tmp,
            gateway,
            backend,
            tag,
            leaf,
            limits,
            root,
            mut child,
            relay,
            access_ports,
            handoff,
            pump,
        } = started;
        let started_at = Timestamp::now();
        // On disk before it is reported running: a manager that restarts must find it.
        let record = AppRunRecord {
            run_id: run_id.clone(),
            pid: root.pid,
            started_us: root.started_us,
            boot_id: proc::boot_id(),
            backend: backend.name().into(),
            revision: spec.meta.revision,
            gateway_port: gateway.map(|g| g.port),
            started_at,
        };
        if let Err(e) = self.store.set_app_run(spec.id, Some(record)).await {
            tracing::error!(app = %spec.id, error = %e, "run record not written; stopping the app");
            abandon(backend.as_ref(), root, &mut child, leaf.as_deref()).await;
            return Err(StartError::new(
                "STORE_UNAVAILABLE",
                tr!(
                    "Cannot record the running app (storage is unavailable); it was stopped",
                    "無法記錄執行中的 App（儲存服務無法使用），已將它停止",
                    "実行中のアプリを記録できません（ストレージを利用できません）。アプリを停止しました"
                ),
                ErrorCode::PersistenceUnavailable,
            ));
        }
        tokio::spawn(pump.run(format!(
            "--- vpn-manager: run {run_id} started {started_at} (pid {}) ---",
            root.pid
        )));
        tracing::info!(app = %spec.id, pid = root.pid, backend = backend.name(), "managed app started");
        let resources = run_resources(leaf.as_deref(), &limits);
        let marker = marker_of(&run_id, backend.name(), &tmp);
        let complete =
            marker.authoritative() || leaf.is_some() || spec.isolation == AppIsolation::StrictNetns;
        let marker = Arc::new(Mutex::new(marker));
        let status = self.publish(entry, |l| {
            l.run = Some(Run {
                id: run_id.clone(),
                name: spec.name.clone(),
                root,
                instance_id: spec.instance_id,
                sockets: None,
                backend: backend.clone(),
                tree: proc::Tree::from([(root.pid, root.started_us)]),
                isolation: spec.isolation,
                gateway,
                tag: tag.clone(),
                cursor: tag
                    .as_ref()
                    .and_then(|_| LogCursor::at(started_at.0.unix_timestamp().saturating_sub(1))),
                next_denials: Instant::now() + DENIALS_FIRST,
                stopping: false,
                cgroup: leaf.clone(),
                limits,
                marker,
                complete,
                handoff,
                access_ports: access_ports.clone(),
                access: relay.clone(),
                launched: spec.clone(),
                grace: grace_of(spec),
            });
            let s = &mut l.status;
            s.state = AppRunState::Running;
            s.run_revision = Some(spec.meta.revision);
            s.pid = Some(root.pid);
            s.started_at = Some(started_at);
            s.last_exit = None;
            s.last_error = None;
            s.isolation = Some(spec.isolation);
            s.gateway_id = gateway.map(|g| g.id);
            s.gateway_port = gateway.map(|g| g.port);
            s.process_count = Some(1);
            s.listeners = None;
            s.sandbox_denials = tag.as_ref().map(|_| 0);
            s.resources = Some(resources.clone());
        });
        self.follow_relay(spec.id, relay, &access_ports);
        // The root's exit, whoever causes it.
        let (me, waiting, id) = (Arc::clone(self), entry.clone(), spec.id);
        tokio::spawn(async move {
            let status = child.wait().await;
            me.root_exited(waiting, id, run_id, status).await;
        });
        Ok(status)
    }

    /// What the launcher says about the connections it relays.
    fn follow_relay(
        &self,
        id: AppId,
        relay: Option<Arc<vpn_platform::sandbox::AccessChannel>>,
        access_ports: &[u16],
    ) {
        if let Some(channel) = relay {
            let access = self.access.clone();
            tokio::spawn(async move {
                while let Some(report) = channel.report().await {
                    access.reported(id, report);
                }
            });
        } else if !access_ports.is_empty() {
            self.access.reported(
                id,
                vpn_platform::sandbox::AccessReport::Failed {
                    port: access_ports[0],
                    message: tr!(
                        "Relaying the app's local access ports is not enabled; restart the app",
                        "App 的本機存取埠轉送沒有啟用；請重新啟動 App",
                        "アプリのローカルアクセスポートの転送が有効になっていません。アプリを再起動してください"
                    ),
                },
            );
        }
    }

    /// The backend that confines a run of `spec`, with its Seatbelt denial tag (if any). A
    /// strict App's sandbox may take up to `wait` to be ready (after a manager start).
    async fn isolation_backend(
        &self,
        spec: &AppSpec,
        gateway: Option<GatewayTarget>,
        run_id: &str,
        (home, tmp): (&Path, &Path),
        private: Vec<PathBuf>,
        wait: Duration,
    ) -> Result<(Arc<dyn IsolationBackend>, Option<String>), StartError> {
        Ok(match spec.isolation {
            AppIsolation::ProxyEnv => (Arc::new(Plain), None),
            AppIsolation::EnforcedProxy => {
                let Some(g) = gateway else {
                    return Err(StartError::new(
                        "APP_GATEWAY_MISSING",
                        tr!(
                            "An enforced proxy needs a Gateway",
                            "強制代理需要代理埠",
                            "強制プロキシにはゲートウェイが必要です"
                        ),
                        ErrorCode::InvalidState,
                    ));
                };
                let tag = seatbelt::tag(run_id);
                let writable = spec.writable_paths.clone();
                let (home, tmp, run) = (home.to_path_buf(), tmp.to_path_buf(), run_id.to_owned());
                let policy = tokio::task::spawn_blocking(move || {
                    let own_tmp = seatbelt::real_path(&tmp);
                    // The files that mark the run's processes (they must exist).
                    seatbelt::create_markers(&own_tmp, &run).map_err(|e| {
                        tr!(
                            "Cannot create the sandbox marker files: {e}",
                            "無法建立沙箱標記檔：{e}",
                            "サンドボックスのマーカーファイルを作成できません：{e}"
                        )
                    })?;
                    Ok::<_, Text>(seatbelt::Policy {
                        tag: tag.clone(),
                        marker: seatbelt::marker_paths(&own_tmp, &run),
                        gateway_port: g.port,
                        private: private.iter().map(|p| seatbelt::real_path(p)).collect(),
                        own: vec![seatbelt::real_path(&home), own_tmp],
                        writable: writable
                            .iter()
                            .map(|w| seatbelt::real_path(Path::new(w)))
                            .collect(),
                    })
                })
                .await
                .map_err(|e| {
                    tracing::error!(app = %spec.id, error = %e, "generating an app's sandbox profile failed");
                    StartError::new(
                        "APP_SANDBOX_PROFILE",
                        tr!(
                            "Cannot generate the sandbox profile",
                            "無法產生沙箱設定",
                            "サンドボックスの設定を生成できません"
                        ),
                        ErrorCode::Internal,
                    )
                })?
                .map_err(|m| StartError::new("APP_SANDBOX_PROFILE", m, ErrorCode::InvalidState))?;
                let profile = seatbelt::profile(&policy).map_err(|m| {
                    StartError::new("APP_SANDBOX_PROFILE", m, ErrorCode::InvalidState)
                })?;
                (Arc::new(Seatbelt { profile }), Some(policy.tag))
            }
            AppIsolation::StrictNetns => {
                let provider = self.strict.read().clone();
                let Some(provider) = provider else {
                    return Err(StartError::new(
                        "APP_ISOLATION_UNAVAILABLE",
                        no_strict_backend(),
                        ErrorCode::UnsupportedCapability,
                    ));
                };
                let deadline = Instant::now() + wait;
                let backend = loop {
                    match provider.backend(&spec.instance_id.to_string()) {
                        Ok(backend) => break backend,
                        Err(_) if Instant::now() < deadline => {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                        Err(m) => {
                            return Err(StartError::new(
                                "APP_ISOLATION_UNAVAILABLE",
                                m,
                                ErrorCode::UnsupportedCapability,
                            ));
                        }
                    }
                };
                (backend, None)
            }
        })
    }

    /// The run's cgroup: refused when a limit the user set cannot be enforced here; `None` when
    /// nothing asked for one (or this host has none).
    fn create_leaf(&self, ids: &str, limits: &AppLimits) -> Result<Option<Arc<Leaf>>, StartError> {
        for (kind, _) in requested(limits) {
            if let Some(reason) = self.resources.unavailable(kind) {
                return Err(StartError::new(
                    "APP_LIMITS_UNAVAILABLE",
                    tr!(
                        "This host cannot apply the app's resource limits right now: {reason}",
                        "此主機目前無法套用 App 的資源上限：{reason}",
                        "このホストでは現在アプリのリソースの上限を適用できません：{reason}";
                        reason = reason
                    ),
                    ErrorCode::UnsupportedCapability,
                ));
            }
        }
        match self
            .resources
            .create(Group::Apps, ids, &tree_limits(limits))
        {
            Ok(leaf) => Ok(Some(Arc::new(leaf))),
            Err(reason) if limits.wants_cgroup() => Err(StartError::new(
                "APP_LIMITS_UNAVAILABLE",
                tr!(
                    "Cannot create the app's cgroup: {reason}",
                    "無法建立 App 的 cgroup：{reason}",
                    "アプリの cgroup を作成できません：{reason}";
                    reason = reason
                ),
                ErrorCode::UnsupportedCapability,
            )),
            // Nothing asked for one (or this host has none): the App runs without.
            Err(_) => Ok(None),
        }
    }

    /// The approved executable as it is now, checked again with what the file is: a browser
    /// never runs on a data directory of the user's, and a program that may hand its start over
    /// never runs as if it were confined.
    async fn verify_start(
        spec: &AppSpec,
        private: &[PathBuf],
    ) -> Result<(PathBuf, Option<AppClassInfo>, Option<PathBuf>), StartError> {
        let approval = spec.approval.clone().ok_or_else(|| {
            StartError::new(
                "APP_ARTIFACT_NOT_APPROVED",
                tr!(
                    "The executable is not approved yet; check and approve the current file",
                    "執行檔尚未核准；請檢查並核准目前的檔案",
                    "実行ファイルはまだ承認されていません。現在のファイルをチェックして承認してください"
                ),
                ErrorCode::AppArtifactDigestMismatch,
            )
        })?;
        let exe = spec.executable.clone();
        let verify_private = private.to_vec();

        let verified = tokio::task::spawn_blocking(move || {
            executable::verify(&exe, &approval, &verify_private).map(|v| {
                let bundle = app_class::bundle_of(&v.program);
                (v, bundle)
            })
        })
        .await
        .map_err(|e| {
            tracing::error!(app = %spec.id, error = %e, "checking an app's executable failed");
            StartError::new(
                "APP_EXECUTABLE_INVALID",
                tr!(
                    "Cannot check the executable",
                    "無法檢查執行檔",
                    "実行ファイルをチェックできません"
                ),
                ErrorCode::Internal,
            )
        })?
        .map_err(|e| match e {
            executable::VerifyError::Invalid(m) => {
                StartError::new("APP_EXECUTABLE_INVALID", m, ErrorCode::InvalidState)
            }
            executable::VerifyError::Changed(m) => StartError::new(
                "APP_ARTIFACT_DIGEST_MISMATCH",
                m,
                ErrorCode::AppArtifactDigestMismatch,
            ),
        })?;
        let (executable::Verified { program, class }, bundle) = verified;
        // Checked again with what the file is now (an App saved before these rules, or a file
        // that changed what it is): a browser never runs on a data directory of the user's, and
        // a program that may hand its start over never runs as if it were confined.
        if let Some(c) = &class
            && let Some(i) = check_app_class(spec, Some(c))
                .issues
                .into_iter()
                .find(|i| i.severity == Severity::Error)
        {
            let (code, api) = if i.code == "APP_PROFILE_ARG" {
                ("APP_PROFILE_ARG", ErrorCode::ValidationFailed)
            } else {
                ("APP_GUI_NOT_ENFORCEABLE", ErrorCode::UnsupportedCapability)
            };
            return Err(StartError::new(code, i.message, api));
        }
        Ok((program, class, bundle))
    }

    /// The root process ended. During a stop that stop finishes the run; otherwise the App ended
    /// on its own: what it left behind is stopped and the run finished with its exit.
    async fn root_exited(
        self: Arc<Self>,
        entry: Arc<Entry>,
        id: AppId,
        run_id: String,
        status: std::io::Result<std::process::ExitStatus>,
    ) {
        let exit = exit_of(&status);
        let mut stopping = None;
        let mut cgroup = None;
        let mut probe = None;
        self.publish(&entry, |l| {
            if let Some(r) = l.run.as_ref().filter(|r| r.id == run_id) {
                stopping = Some(r.stopping);
                cgroup = r.cgroup.clone().map(|c| (c, r.limits));
                // The strict sandbox reaches no running instance: nothing to hand over to.
                probe = (r.isolation != AppIsolation::StrictNetns).then(|| {
                    (
                        r.handoff.clone(),
                        r.tree.clone(),
                        r.root,
                        r.marker.clone(),
                        r.cgroup.clone(),
                    )
                });
                l.status.last_exit = Some(exit.clone());
                l.status.pid = None;
            }
        });
        if stopping != Some(false) {
            return;
        }
        let _ops = entry.ops.lock().await;
        let current = entry
            .live
            .lock()
            .run
            .as_ref()
            .is_some_and(|r| r.id == run_id && !r.stopping);
        if !current {
            return;
        }
        tracing::info!(app = %id, code = ?exit.code, signal = ?exit.signal, "managed app exited");
        // Killed by the kernel for exceeding its memory limit: said so, not "exited".
        let oom = cgroup
            .as_ref()
            .filter(|(leaf, _)| leaf.oom_kills().unwrap_or(0) > 0)
            .map(|(_, limits)| limits.memory_mib);
        // Exited 0 at once while the same program runs outside the tree: the start most likely
        // went to that process, which VPN Manager does not protect. Said so, not "exited".
        let handoff = match probe {
            Some((probe, tree, root, marker, leaf)) if oom.is_none() && exit.code == Some(0) => {
                handed_off(probe, tree, root, marker, leaf).await
            }
            _ => None,
        };
        let (failed, reason) = match (oom, handoff) {
            (Some(mib), _) => {
                let limit = mib.map_or_else(|| "—".to_string(), |m| m.to_string());
                (
                    true,
                    fault(
                        "APP_OOM_KILLED",
                        tr!(
                            "The app used more memory than its limit ({limit} MiB) and was ended by the system (OOM)",
                            "App 使用的記憶體超過上限（{limit} MiB），已被系統結束（OOM）",
                            "アプリが上限（{limit} MiB）を超えるメモリを使用したため、システムに終了されました（OOM）"
                        ),
                    ),
                )
            }
            (None, Some(handoff)) => {
                tracing::warn!(app = %id, "managed app exited at once; its start most likely went to a process outside its tree");
                (true, handoff)
            }
            (None, None) => (
                exit.code != Some(0),
                fault("APP_EXITED", exit_message(&exit)),
            ),
        };
        if oom.is_some() {
            tracing::warn!(app = %id, "managed app killed by the kernel: memory limit");
        }
        // How the run ended is on the App's status; a stop not confirmed is logged by `end_run`.
        if let Err(e) = self
            .end_run(&entry, id, &run_id, Some(reason), failed)
            .await
        {
            tracing::debug!(app = %id, error = %e, "the exited app's run did not end cleanly");
        }
    }

    /// Stop the App: its whole tree, confirmed. `user`: the user asked, so the durable intent
    /// becomes stopped (written at the same time, never waited for before the stop starts).
    pub(crate) async fn stop(
        self: &Arc<Self>,
        id: AppId,
        user: bool,
        reason: Option<Fault>,
    ) -> Result<AppStatus, ApiError> {
        let entry = self.existing(id).await?;
        let epoch = if user {
            Some(Self::bump_epoch(&entry))
        } else {
            None
        };
        // The intent is said as soon as it is on disk: a stop with a long grace is still going.
        let intent = async {
            let Some(epoch) = epoch else {
                return;
            };
            match self.store.set_app_desired(id, DesiredState::Stopped).await {
                Ok(_) => {
                    self.publish(&entry, |l| {
                        l.status.desired = DesiredState::Stopped;
                        l.status.intent_persistence = Persistence::Durable;
                    });
                }
                Err(StoreError::NotFound) => {}
                Err(e) => {
                    tracing::warn!(app = %id, error = %e, "app stop intent not on disk yet; retrying");
                    self.publish(&entry, |l| {
                        l.status.desired = DesiredState::Stopped;
                        l.status.intent_persistence = Persistence::Pending;
                    });
                    let (me, entry) = (Arc::clone(self), entry.clone());
                    tokio::spawn(async move { me.retry_stop_intent(entry, id, epoch).await });
                }
            }
        };
        let end = async {
            let _ops = entry.ops.lock().await;
            let run_id = entry.live.lock().run.as_ref().map(|r| r.id.clone());
            let leftover = entry.live.lock().leftover;
            match (run_id, leftover) {
                (Some(run_id), _) => {
                    let failed = reason.is_some();
                    self.end_run(&entry, id, &run_id, reason.clone(), failed)
                        .await
                }
                (None, Some(_)) => self
                    .end_leftover(&entry, id)
                    .await
                    .map(|(status, _)| status),
                (None, None) => Ok(self.publish(&entry, |l| {
                    l.status.state = AppRunState::Stopped;
                    l.status.last_error.clone_from(&reason);
                })),
            }
        };
        let ((), ended) = tokio::join!(intent, end);
        ended?;
        let status = self.view(&entry.live.lock());
        Ok(status)
    }

    /// Keep writing a stop intent that did not reach the disk, until it does or a newer intent
    /// replaces it.
    async fn retry_stop_intent(self: Arc<Self>, entry: Arc<Entry>, id: AppId, epoch: u64) {
        let mut delay = Duration::from_secs(1);
        loop {
            tokio::time::sleep(delay).await;
            if entry.live.lock().intent_epoch != epoch {
                return;
            }
            match self.store.set_app_desired(id, DesiredState::Stopped).await {
                Ok(_) => {
                    self.publish(&entry, |l| {
                        if l.intent_epoch == epoch {
                            l.status.intent_persistence = Persistence::Durable;
                        }
                    });
                    return;
                }
                Err(StoreError::NotFound) => return,
                Err(_) => delay = (delay * 2).min(Duration::from_secs(30)),
            }
        }
    }

    /// The stop grace of App `id` as saved (the default when it cannot be read).
    async fn stored_grace(&self, id: AppId) -> Duration {
        match self.store.get::<AppSpec>(id.to_string()).await {
            Ok(Some(spec)) => grace_of(&spec),
            _ => Duration::from_secs(u64::from(APP_STOP_GRACE_DEFAULT_SECS)),
        }
    }

    /// Try again to end the tree an earlier manager left running (see [`Live::leftover`]). Its
    /// run record goes once its end is confirmed; until then the App stays `failed`.
    async fn end_leftover(
        &self,
        entry: &Entry,
        id: AppId,
    ) -> Result<(AppStatus, Leftover), ApiError> {
        let Some(root) = entry.live.lock().leftover else {
            let status = self.view(&entry.live.lock());
            return Ok((status, Leftover::Gone));
        };
        self.publish(entry, |l| l.status.state = AppRunState::Stopping);
        let marker = entry
            .live
            .lock()
            .leftover_marker
            .clone()
            .unwrap_or_else(|| Arc::new(Mutex::new(proc::RunMarker::new("", None))));
        let grace = self.stored_grace(id).await;
        let outcome = stop_leftover(root, &marker, grace).await;
        let complete = marker.lock().authoritative();
        if outcome == Leftover::Unconfirmed {
            tracing::error!(app = %id, pid = root.pid, "leftover app processes still not confirmed ended");
            self.publish(entry, |l| {
                l.status.state = AppRunState::Failed;
                l.status.last_error = Some(fault(
                    "APP_STOP_UNCONFIRMED",
                    tr!(
                        "Still cannot confirm that the app's previous run has fully ended; you can press Stop again",
                        "仍無法確認上次啟動的 App 已全部結束；可以再按一次停止",
                        "前回起動したアプリがすべて終了したことをまだ確認できません。もう一度「停止」を押せます"
                    ),
                ));
            });
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                tr!(
                    "Cannot confirm that every process of the app's previous run has ended",
                    "無法確認上次啟動的 App 的所有程序都已結束",
                    "前回起動したアプリのすべてのプロセスが終了したことを確認できません"
                ),
            ));
        }
        if let Err(e) = self.store.set_app_run(id, None).await {
            tracing::warn!(app = %id, error = %e, "leftover run record not cleared");
        }
        tracing::info!(app = %id, ?outcome, "leftover of an earlier manager ended");
        let status = self.publish(entry, |l| {
            l.leftover = None;
            l.leftover_marker = None;
            l.status.state = AppRunState::Stopped;
            l.status.pid = None;
            l.status.last_error = (!complete).then(|| unverified(None));
        });
        Ok((status, outcome))
    }

    /// For recovery: end the leftover of App `id` (what its "stop" would do). `Ok(false)`: none
    /// was left.
    pub(crate) async fn end_leftover_of(&self, id: AppId) -> Result<bool, ApiError> {
        let entry = self.existing(id).await?;
        let _ops = entry.ops.lock().await;
        if entry.live.lock().leftover.is_none() {
            return Ok(false);
        }
        self.end_leftover(&entry, id).await.map(|_| true)
    }

    /// End run `run_id`: SIGTERM, up to the App's grace, SIGKILL, then confirm from the process
    /// table. Only a confirmed end clears the run (and its record); otherwise the App is `failed`
    /// with the run kept, so it can be stopped again and is not deleted meanwhile.
    async fn end_run(
        &self,
        entry: &Arc<Entry>,
        id: AppId,
        run_id: &str,
        reason: Option<Fault>,
        failed: bool,
    ) -> Result<AppStatus, ApiError> {
        let mut taken = None;
        self.publish(entry, |l| {
            if let Some(run) = l.run.as_mut().filter(|r| r.id == run_id) {
                run.stopping = true;
                taken = Some((
                    run.root,
                    run.backend.clone(),
                    run.tree.clone(),
                    run.cgroup.clone(),
                    run.marker.clone(),
                    run.complete,
                    run.grace,
                ));
                l.status.state = AppRunState::Stopping;
            }
        });
        let Some((root, backend, mut tree, cgroup, marker, complete, grace)) = taken else {
            let status = self.view(&entry.live.lock());
            return Ok(status);
        };
        let started = Instant::now();
        let mut termed: HashSet<u32> = HashSet::new();
        let confirmed = loop {
            if let Some(table) = snapshot().await {
                follow(&mut tree, root, &table, &marker, cgroup.as_deref());
                let alive = proc::alive(&tree, &table);
                if alive.is_empty() {
                    break true;
                }
                if started.elapsed() >= grace {
                    backend.terminate(root, &alive, true);
                } else {
                    // Newly found descendants get their SIGTERM too.
                    let fresh: Vec<ProcessIdentity> =
                        alive.into_iter().filter(|p| termed.insert(p.pid)).collect();
                    if !fresh.is_empty() {
                        backend.terminate(root, &fresh, false);
                    }
                }
            }
            if started.elapsed() >= grace + STOP_CONFIRM {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        if !confirmed {
            tracing::error!(app = %id, "could not confirm the app's processes ended");
            self.publish(entry, |l| {
                if let Some(run) = l.run.as_mut() {
                    run.stopping = false;
                    run.tree = tree;
                }
                l.status.state = AppRunState::Failed;
                l.status.last_error = Some(fault(
                    "APP_STOP_UNCONFIRMED",
                    tr!(
                        "Cannot confirm that every process of the app has ended; you can press Stop again",
                        "無法確認 App 的所有程序都已結束；可以再按一次停止",
                        "アプリのすべてのプロセスが終了したことを確認できません。もう一度「停止」を押せます"
                    ),
                ));
            });
            return Err(stop_unconfirmed());
        }
        if let Some(leaf) = cgroup {
            release_leaf(leaf).await;
        }
        if let Err(e) = self.store.set_app_run(id, None).await {
            tracing::warn!(app = %id, error = %e, "run record not cleared");
        }
        tracing::info!(app = %id, complete, "managed app stopped");
        // Nothing of the tree is left, but without an authoritative marker a process that left
        // it is not ruled out: said so, not claimed ended.
        let reason = if complete {
            reason
        } else {
            Some(unverified(reason))
        };
        Ok(self.publish(entry, |l| {
            l.run = None;
            let s = &mut l.status;
            s.state = if failed {
                AppRunState::Failed
            } else {
                AppRunState::Stopped
            };
            s.last_error = reason;
            s.pid = None;
            s.isolation = None;
            s.gateway_id = None;
            s.gateway_port = None;
            s.process_count = None;
            s.listeners = None;
            s.resources = None;
        }))
    }

    // -----------------------------------------------------------------------------------------
    // Watching, recovery, shutdown
    // -----------------------------------------------------------------------------------------

    /// Check every running App every 2 s, for as long as the manager lives.
    pub(crate) async fn watch(self: Arc<Self>, manager: Weak<Manager>) {
        let mut tick = tokio::time::interval(WATCH_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(manager) = manager.upgrade() else {
                return;
            };
            let running: Vec<(AppId, Arc<Entry>)> = self
                .entries
                .lock()
                .iter()
                .filter(|(_, e)| {
                    let live = e.live.lock();
                    live.status.state == AppRunState::Running
                        && live.run.as_ref().is_some_and(|r| !r.stopping)
                })
                .map(|(id, e)| (*id, e.clone()))
                .collect();
            if running.is_empty() {
                continue;
            }
            let Some(table) = snapshot().await else {
                continue;
            };
            for (id, entry) in running {
                self.check(&manager, id, &entry, &table).await;
            }
            // Port forwards re-check their targets against what this pass found.
            self.changed();
        }
    }

    /// One watcher pass over one running App.
    async fn check(
        self: &Arc<Self>,
        manager: &Manager,
        id: AppId,
        entry: &Arc<Entry>,
        table: &proc::ProcTable,
    ) {
        let taken = {
            let live = entry.live.lock();
            live.run.as_ref().filter(|r| !r.stopping).map(|r| {
                (
                    r.id.clone(),
                    r.root,
                    r.tree.clone(),
                    r.isolation,
                    r.gateway,
                    r.tag.clone(),
                    r.cursor.clone(),
                    r.next_denials,
                    r.marker.clone(),
                    r.cgroup.clone(),
                )
            })
        };
        let Some((
            run_id,
            root,
            mut tree,
            isolation,
            gateway,
            tag,
            cursor,
            next_denials,
            marker,
            cgroup,
        )) = taken
        else {
            return;
        };
        follow(&mut tree, root, table, &marker, cgroup.as_deref());
        let alive = proc::alive(&tree, table);
        let resources = cgroup_resources(entry, &alive).await;
        let pids: Vec<ProcessIdentity> = alive.iter().take(MAX_PROCESSES).copied().collect();
        let scanned = scan_sockets(pids, isolation == AppIsolation::StrictNetns).await;
        let (listeners, sockets, reached) = match scanned {
            Some((l, s, r)) => (Some(l), Some(s), r),
            None => (None, None, Vec::new()),
        };
        let gateway_lost = gateway_lost(manager, gateway).await;
        let denials = read_denials(tag.as_deref(), cursor.as_ref(), next_denials).await;
        let pass = Pass {
            tree,
            sockets,
            count: Some(u32::try_from(alive.len()).unwrap_or(u32::MAX)),
            listeners: listeners.clone(),
            resources,
            denials,
        };
        let Some((status, changed)) = self.record_pass(entry, &run_id, pass) else {
            return;
        };
        if changed {
            self.emit(status);
        }
        let reason = stop_reason(isolation, listeners.as_deref(), &reached, gateway_lost);
        if let Some(reason) = reason {
            tracing::warn!(app = %id, code = %reason.code, "stopping managed app");
            let me = Arc::clone(self);
            tokio::spawn(async move {
                // Its outcome is on the App's status; a stop not confirmed is logged by `stop`.
                if let Err(e) = me.stop(id, false, Some(reason)).await {
                    tracing::debug!(app = %id, error = %e, "managed app not stopped cleanly");
                }
            });
        }
    }

    /// Record a watcher pass in the run it looked at (unless that run ended or is stopping):
    /// the status as it is now, and whether it changed.
    fn record_pass(&self, entry: &Entry, run_id: &str, pass: Pass) -> Option<(AppStatus, bool)> {
        let mut changed = false;
        let status = {
            let mut live = entry.live.lock();
            let access_before = self.view(&live).access;
            let Live { run, status, .. } = &mut *live;
            let run = run.as_mut().filter(|r| r.id == run_id && !r.stopping)?;
            let Pass {
                tree,
                sockets,
                count,
                listeners,
                resources,
                denials,
            } = pass;
            run.tree = tree;
            run.sockets = sockets;
            if status.process_count != count {
                status.process_count = count;
                changed = true;
            }
            if status.listeners != listeners {
                status.listeners = listeners;
                changed = true;
            }
            if let Some(r) = resources {
                let now = (r.memory_bytes, r.oom_kills);
                if status
                    .resources
                    .as_ref()
                    .map(|s| (s.memory_bytes, s.oom_kills))
                    != Some(now)
                {
                    status.resources = Some(r);
                    changed = true;
                }
            }
            if let Some(counted) = denials {
                run.next_denials = Instant::now() + DENIALS_EVERY;
                let total = match counted {
                    Some((n, next)) => {
                        run.cursor = Some(next);
                        status.sandbox_denials.map(|d| d + n)
                    }
                    // The unified log cannot be read: unknown from now on, never "0".
                    None => None,
                };
                if status.sandbox_denials != total {
                    status.sandbox_denials = total;
                    changed = true;
                }
            }
            if changed {
                status.observed_at = Timestamp::now();
            }
            let view = self.view(&live);
            drop(live);
            if view.access != access_before {
                changed = true;
            }
            view
        };
        Some((status, changed))
    }

    /// After a manager start: stop what the previous manager left running (identity-checked),
    /// then start again the Apps the user wants running with `restart_on_recovery` — those whose
    /// run was left behind, and those whose last run ended before (with its sandbox, by itself)
    /// while the user's intent stayed `running`.
    pub(crate) async fn recover(self: Arc<Self>, manager: Weak<Manager>) {
        let rows = match self.store.app_intents().await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(error = %e, "cannot read app run records; leftovers not checked");
                return;
            }
        };
        for row in rows {
            let (me, manager) = (Arc::clone(&self), manager.clone());
            if row.run.is_some() {
                tokio::spawn(async move { me.recover_one(manager, row).await });
            } else if row.desired == DesiredState::Running {
                tokio::spawn(async move { me.resume_one(manager, row.app_id).await });
            }
        }
    }

    /// The user wants App `id` running, and no run of it was left: its last run ended while the
    /// previous manager ran (killed with its sandbox, crashed, ...). Started again like a
    /// recovered one; without `restart_on_recovery` it says why it does not run.
    async fn resume_one(self: Arc<Self>, manager: Weak<Manager>, id: AppId) {
        let spec = match self.store.get::<AppSpec>(id.to_string()).await {
            Ok(Some(spec)) => spec,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(app = %id, error = %e, "app spec unreadable at start");
                return;
            }
        };
        if spec.restart_on_recovery {
            if let Some(manager) = manager.upgrade() {
                tracing::info!(app = %id, "app meant to run: starting it again");
                // Its failure, if any, is recorded on the App by `start`.
                if let Err(e) = self.start(&manager, id, false, RECOVERY_GATEWAY_WAIT).await {
                    tracing::debug!(app = %id, error = %e, "app not started again");
                }
            }
            return;
        }
        let entry = self.entry(id);
        self.publish(&entry, |l| {
            l.status.state = AppRunState::Stopped;
            l.status.last_error = Some(fault(
                "APP_STOPPED_AFTER_MANAGER_RESTART",
                tr!(
                    "This app was not running when the core service (manager) restarted; it is set not to start again by itself",
                    "核心服務（manager）重新啟動時這個 App 沒有在執行；它設定為不自動再啟動",
                    "コアサービス（manager）の再起動時、このアプリは実行されていませんでした。自動では再起動しない設定です"
                ),
            ));
        });
    }

    async fn recover_one(self: Arc<Self>, manager: Weak<Manager>, row: AppIntentRow) {
        let Some(run) = row.run else { return };
        let id = row.app_id;
        let entry = self.entry(id);
        let root = ProcessIdentity {
            pid: run.pid,
            started_us: match run.boot_id {
                Some(_) => run.started_us,
                None => proc::legacy_start_us(run.started_us),
            },
        };
        // Nothing outlives a reboot: a run of another boot is gone, and its pid and start time
        // (counted from that boot on Linux) may well name a process of this one.
        let other_boot = matches!(
            (run.boot_id.as_deref(), proc::boot_id()),
            (Some(then), Some(now)) if then != now
        );
        let marker = Arc::new(Mutex::new(marker_of(
            &run.run_id,
            &run.backend,
            &self.paths.app_tmp(&id.to_string()),
        )));
        let complete = marker.lock().authoritative() || run.backend == "strict_netns";
        let grace = self.stored_grace(id).await;
        let outcome = {
            let _ops = entry.ops.lock().await;
            let outcome = if other_boot {
                tracing::info!(app = %id, pid = root.pid, "app run of an earlier boot: gone");
                Leftover::Gone
            } else {
                stop_leftover(root, &marker, grace).await
            };
            if outcome == Leftover::Unconfirmed {
                self.publish(&entry, |l| {
                    l.leftover = Some(root);
                    l.leftover_marker = Some(marker.clone());
                    l.status.pid = Some(root.pid);
                    l.status.started_at = Some(run.started_at);
                    l.status.state = AppRunState::Failed;
                    l.status.last_error = Some(fault(
                        "APP_STOP_UNCONFIRMED",
                        tr!(
                            "After the core service (manager) restarted, the app's previous run could not be confirmed to have fully ended",
                            "核心服務（manager）重新啟動後，無法確認上次啟動的 App 已全部結束",
                            "コアサービス（manager）の再起動後、前回起動したアプリがすべて終了したことを確認できません"
                        ),
                    ));
                });
                return;
            }
            if let Err(e) = self.store.set_app_run(id, None).await {
                tracing::warn!(app = %id, error = %e, "leftover run record not cleared");
            }
            outcome
        };
        tracing::info!(app = %id, ?outcome, "app left by the previous manager handled");
        let spec = match self.store.get::<AppSpec>(id.to_string()).await {
            Ok(Some(spec)) => Some(spec),
            Ok(None) => {
                // Deleted meanwhile: nothing to show.
                self.entries.lock().remove(&id);
                return;
            }
            Err(e) => {
                tracing::warn!(app = %id, error = %e, "app spec unreadable after recovery");
                None
            }
        };
        let restart = row.desired == DesiredState::Running
            && spec.as_ref().is_some_and(|s| s.restart_on_recovery);
        if restart && let Some(manager) = manager.upgrade() {
            // Its failure, if any, is recorded on the App by `start`.
            if let Err(e) = self.start(&manager, id, false, RECOVERY_GATEWAY_WAIT).await {
                tracing::debug!(app = %id, error = %e, "recovered app not started again");
            }
            return;
        }
        let message = match outcome {
            Leftover::Stopped => tr!(
                "The core service (manager) restarted: the app's previous run could no longer be watched, so it was stopped",
                "核心服務（manager）重新啟動：上次啟動的 App 無法再被監看，已停止",
                "コアサービス（manager）が再起動しました。前回起動したアプリを監視できなくなったため、停止しました"
            ),
            _ => tr!(
                "The app exited while the core service (manager) was restarting",
                "核心服務（manager）重新啟動期間，App 已結束",
                "コアサービス（manager）の再起動中にアプリは終了しました"
            ),
        };
        let reason = Some(fault("APP_STOPPED_AFTER_MANAGER_RESTART", message));
        // An earlier boot's run is gone for certain; otherwise only a marker rules out escape.
        let reason = if complete || other_boot {
            reason
        } else {
            Some(unverified(reason))
        };
        self.publish(&entry, |l| {
            l.status.state = AppRunState::Stopped;
            l.status.last_error = reason;
        });
    }

    /// The manager is stopping: end every App (nothing would supervise them). All get SIGTERM at
    /// once and each its own grace before SIGKILL (the service manager waits for the longest,
    /// see the installer's stop timeout). Their run records stay, so the next manager starts
    /// again those that should run.
    pub(crate) async fn shutdown(&self) {
        struct Ending {
            root: ProcessIdentity,
            backend: Arc<dyn IsolationBackend>,
            tree: proc::Tree,
            marker: Arc<Mutex<proc::RunMarker>>,
            cgroup: Option<Arc<Leaf>>,
            grace: Duration,
            termed: HashSet<u32>,
            gone: bool,
        }
        // No new connections for the Apps from here on.
        self.access.shutdown();
        let entries: Vec<Arc<Entry>> = self.entries.lock().values().cloned().collect();
        let mut runs: Vec<Ending> = entries
            .iter()
            .filter_map(|e| {
                let mut live = e.live.lock();
                let run = live.run.as_mut()?;
                run.stopping = true;
                let ending = Ending {
                    root: run.root,
                    backend: run.backend.clone(),
                    tree: run.tree.clone(),
                    marker: run.marker.clone(),
                    cgroup: run.cgroup.clone(),
                    grace: run.grace,
                    termed: HashSet::new(),
                    gone: false,
                };
                drop(live);
                Some(ending)
            })
            .collect();
        if runs.is_empty() {
            return;
        }
        let started = Instant::now();
        loop {
            let Some(table) = snapshot().await else { break };
            let mut waiting = false;
            for r in runs.iter_mut().filter(|r| !r.gone) {
                follow(&mut r.tree, r.root, &table, &r.marker, r.cgroup.as_deref());
                let alive = proc::alive(&r.tree, &table);
                if alive.is_empty() {
                    r.gone = true;
                    continue;
                }
                if started.elapsed() >= r.grace {
                    r.backend.terminate(r.root, &alive, true);
                } else {
                    // Newly found descendants get their SIGTERM too.
                    let fresh: Vec<ProcessIdentity> = alive
                        .into_iter()
                        .filter(|p| r.termed.insert(p.pid))
                        .collect();
                    if !fresh.is_empty() {
                        r.backend.terminate(r.root, &fresh, false);
                    }
                }
                // Past its grace and the confirmation: given up on (it was killed).
                if started.elapsed() < r.grace + STOP_CONFIRM {
                    waiting = true;
                }
            }
            if !waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
