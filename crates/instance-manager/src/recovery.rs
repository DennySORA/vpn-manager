//! Recovery: what the manager owns and what a crash left behind.
//!
//! [`inspect`] looks without changing anything. [`reconcile`] cleans only what it can prove is
//! ours and stale, checks each item again right before acting on it, and reports every action:
//!
//! - a leftover worker: its record (written at fork, removed after the reap) matches a running
//!   process in pid, user, OS start time and program, and it is not one of this manager's
//!   children → SIGKILL (through a pidfd on Linux), then its record goes;
//! - a record whose process is gone, or whose pid now runs something else → the record goes;
//!   that process is never touched;
//! - a key lock file nobody holds, for a key no stored profile uses → removed while we hold its
//!   lock and while worker spawns wait (the spawn gate);
//! - a connector, relay or sandbox socket of ours nobody listens on → removed;
//! - a strict-mode sandbox (Linux) nobody holds, whose holder proves it is ours (this
//!   installation, our user, this boot, and a pid that still names the process that answered)
//!   → its Apps get SIGTERM, then the sandbox is torn down around whatever is left; a sandbox
//!   one of our Instances holds is a resource, never an item;
//! - a temporary file of an atomic write whose writer is gone → removed;
//! - a managed App's process tree an earlier manager left running that its supervisor could not
//!   confirm ended (its run record: root pid with start time) → ended through the supervisor,
//!   which checks the identity of every process before it signals.
//!
//! Managed Apps are never taken for leftover workers: they have no worker record, and the trees
//! the App supervisor runs are listed as owned resources. Sandbox holders have no worker record
//! either: they are found by their rendezvous sockets.
//!
//! Nothing is ever started. Whatever is held by a process that is not provably ours is only
//! reported. A place that cannot be looked at (an unreadable directory, a connection that does
//! not answer) is reported as a gap: what was found there is unknown, not nothing.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use vpn_domain::{
    AppId, AppSpec, InstanceId, InstanceStatus, ListenerResource, LockResource, OwnedResources,
    ReconcileAction, ReconcileOutcome, ReconcileResult, RecoveryItem, RecoveryKind, RecoveryReport,
    RuntimeProfile, SandboxResource, ScanGap, SocketResource, Text, Timestamp, WorkerResource, tr,
};
use vpn_platform::lock::{FileLock, LockError};
use vpn_platform::probe::{self, Entry};
use vpn_platform::process::{self, KillOutcome, ProcessIdentity};
use vpn_platform::sandbox::{self as strict, SandboxClient, SandboxLease};
use vpn_store::Store;

use crate::inventory::{LiveWorker, WorkerRecord};
use crate::resolve::key_fingerprint;
use crate::{Manager, remove_file_if_present};

/// Most directory entries looked at per directory.
const SCAN_MAX: usize = 4096;
/// A temporary file of an atomic write this old was abandoned (writes take milliseconds).
const TEMP_STALE_SECS: u64 = 120;
/// ... and when it carries our own pid (we could be writing it right now), this old.
const OWN_TEMP_STALE_SECS: u64 = 3600;
/// How long a killed worker may take to disappear before we report it still there.
const KILL_WAIT: Duration = Duration::from_secs(2);

/// What a reconcile does about one item.
#[derive(Debug, Clone)]
enum Fix {
    Kill {
        identity: ProcessIdentity,
        record: PathBuf,
    },
    RemoveRecord(PathBuf),
    RemoveLock(PathBuf),
    RemoveSocket(PathBuf),
    /// A sandbox rendezvous socket (`SOCK_SEQPACKET`: probed by its own kind of connect).
    RemoveSandboxSocket(PathBuf),
    /// Tear down a sandbox nobody holds, if the same holder still answers at `socket`.
    TeardownSandbox {
        socket: PathBuf,
        installation: String,
        instance: String,
        epoch: u64,
        holder: ProcessIdentity,
    },
    RemoveFile(PathBuf),
    EndAppLeftover(AppId),
}

struct Found {
    item: RecoveryItem,
    fix: Option<Fix>,
}

/// The result of [`inspect`]: items, the resources seen, and where it could not look.
pub struct Inspection {
    found: Vec<Found>,
    pub resources: OwnedResources,
    gaps: Vec<ScanGap>,
}

impl std::fmt::Debug for Inspection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inspection")
            .field("resources", &self.resources)
            .field("found", &self.found.len())
            .field("gaps", &self.gaps.len())
            .finish_non_exhaustive()
    }
}

impl Inspection {
    #[must_use]
    pub fn report(&self) -> RecoveryReport {
        RecoveryReport {
            observed_at: Timestamp::now(),
            items: self.found.iter().map(|f| f.item.clone()).collect(),
            resources: self.resources.clone(),
            gaps: self.gaps.clone(),
        }
    }

    /// Where the inspection could not look.
    #[must_use]
    pub fn gaps(&self) -> &[ScanGap] {
        &self.gaps
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.found.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.found.is_empty()
    }
}

fn item_id(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update(b"\0");
    }
    // The first 8 bytes of the 32-byte digest: 16 hex digits.
    hex::encode(&h.finalize()[..8])
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[expect(
    clippy::too_many_arguments,
    reason = "one constructor for every recovery item: each argument is one field of the item, named at the call"
)]
fn found(
    kind: RecoveryKind,
    key: &[&str],
    title: impl Into<Text>,
    detail: impl Into<Text>,
    path: Option<&Path>,
    pid: Option<u32>,
    instance_id: Option<InstanceId>,
    fix: Option<(Fix, Text)>,
) -> Found {
    let kind_name = format!("{kind:?}");
    let mut parts = vec![kind_name.as_str()];
    parts.extend_from_slice(key);
    Found {
        item: RecoveryItem {
            id: item_id(&parts),
            kind,
            title: title.into(),
            detail: detail.into(),
            path: path.map(path_str),
            pid,
            instance_id,
            cleanable: fix.is_some(),
            action: fix.as_ref().map(|(_, a)| a.clone()),
        },
        fix: fix.map(|(f, _)| f),
    }
}

/// Entries of `dir` (at most [`SCAN_MAX`]) as `(name, path)`. A directory that does not exist
/// has none; one that cannot be read is a gap, never "empty".
fn entries(dir: &Path, what: &Text, gaps: &mut Vec<ScanGap>) -> Vec<(String, PathBuf)> {
    let it = match std::fs::read_dir(dir) {
        Ok(it) => it,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            gaps.push(gap(
                what.clone(),
                Some(dir),
                tr!("Cannot read: {e}", "無法讀取：{e}", "読み取れません：{e}"),
            ));
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    let mut unreadable = 0usize;
    for e in it.take(SCAN_MAX) {
        match e {
            Ok(e) => {
                if let Some(n) = e.file_name().to_str() {
                    out.push((n.to_string(), e.path()));
                }
            }
            Err(_) => unreadable += 1,
        }
    }
    if unreadable > 0 {
        let noun = if unreadable == 1 { "entry" } else { "entries" };
        gaps.push(gap(
            what.clone(),
            Some(dir),
            tr!(
                "Cannot read {unreadable} {noun}",
                "有 {unreadable} 個項目無法讀取",
                "{unreadable} 件の項目を読み取れません"
            ),
        ));
    }
    out
}

fn gap(what: impl Into<Text>, path: Option<&Path>, reason: impl Into<Text>) -> ScanGap {
    ScanGap {
        what: what.into(),
        path: path.map(path_str),
        reason: reason.into(),
    }
}

/// The pid of the process that wrote a temporary name of an atomic write: `…tmp-<pid>[-…]`.
fn temp_pid(name: &str) -> Option<u32> {
    let (_, rest) = name.rsplit_once("tmp-")?;
    rest.split('-').next()?.parse().ok()
}

/// Whether a temporary file of ours (by name) is abandoned. One written by this very process may
/// be in the middle of being written: it is abandoned only after an hour.
fn temp_abandoned(name: &str, path: &Path) -> bool {
    let Some(age) = probe::age_secs(path) else {
        return false;
    };
    match temp_pid(name) {
        Some(pid) if pid == std::process::id() => age >= OWN_TEMP_STALE_SECS,
        _ => age >= TEMP_STALE_SECS,
    }
}

/// Look at every resource the manager owns and at what a crash may have left behind. Changes
/// nothing (a lock file is test-locked for an instant to see whether anyone holds it).
pub async fn inspect(manager: &Manager, store: &Store, ssh_dir: Option<&Path>) -> Inspection {
    let paths = manager.paths();
    let live = manager.inventory().live();
    let statuses = manager.statuses().await;
    let mut out: Vec<Found> = Vec::new();
    let mut gaps: Vec<ScanGap> = Vec::new();
    let mut resources = owned_resources(manager, &live, &statuses, &mut gaps).await;

    inspect_app_leftovers(manager, store, &mut out).await;
    let (orphan_locks, orphan_sockets) =
        inspect_worker_records(manager, &live, &mut out, &mut gaps);
    inspect_key_locks(
        paths,
        &live,
        store,
        &orphan_locks,
        &mut resources,
        &mut out,
        &mut gaps,
    )
    .await;
    inspect_sockets(
        manager,
        &live,
        &orphan_sockets,
        &mut resources,
        &mut out,
        &mut gaps,
    )
    .await;
    inspect_sandboxes(paths, &statuses, store, &mut resources, &mut out).await;
    inspect_temps(paths, ssh_dir, &mut out, &mut gaps);

    Inspection {
        found: out,
        resources,
        gaps,
    }
}

/// What [`inspect`] lists as owned: the live workers and the Gateway listeners the actors hold.
async fn owned_resources(
    manager: &Manager,
    live: &[(u32, LiveWorker)],
    statuses: &[InstanceStatus],
    gaps: &mut Vec<ScanGap>,
) -> OwnedResources {
    let mut workers: Vec<WorkerResource> = live
        .iter()
        .map(|(pid, w)| WorkerResource {
            instance_id: w.instance_id,
            generation: w.generation,
            pid: *pid,
            process_started_at: w
                .process_started_at_ms
                .and_then(Timestamp::from_unix_millis),
            phase: statuses
                .iter()
                .find(|s| s.instance_id == w.instance_id)
                .map(|s| s.phase),
        })
        .collect();
    workers.sort_by_key(|w| (w.instance_id, w.generation));
    let held = manager.held_listeners().await;
    if !held.unanswered.is_empty() {
        let count = held.unanswered.len();
        let noun = if count == 1 {
            "connection"
        } else {
            "connections"
        };
        gaps.push(gap(
            tr!(
                "Gateways held by connections",
                "連線持有的代理埠",
                "接続が保持しているゲートウェイ"
            ),
            None,
            tr!(
                "The Gateways of {count} {noun} that did not answer in time are not listed",
                "{count} 條連線沒有在時限內回應，它們持有的代理埠沒有列出",
                "{count} 件の接続が時間内に応答しなかったため、それらが保持するゲートウェイは一覧にありません"
            ),
        ));
    }
    let mut listeners: Vec<ListenerResource> = held
        .held
        .into_iter()
        .map(|h| ListenerResource {
            instance_id: h.instance_id,
            gateway_id: h.gateway_id,
            port: h.port,
            state: h.state,
        })
        .collect();
    listeners.sort_by_key(|l| l.port);
    OwnedResources {
        workers,
        listeners,
        key_locks: Vec::new(),
        connector_sockets: Vec::new(),
        sandboxes: Vec::new(),
        apps: manager.apps().resources(),
        unanswered: held.unanswered,
    }
}

/// Managed Apps an earlier manager left running.
async fn inspect_app_leftovers(manager: &Manager, store: &Store, out: &mut Vec<Found>) {
    // Managed Apps: what an earlier manager left running and could not be confirmed ended.
    for (app, root) in manager.apps().leftovers() {
        let spec: Option<AppSpec> = store.get(app.to_string()).await.ok().flatten();
        let name = spec.as_ref().map_or_else(
            || {
                tr!(
                    "(no longer exists)",
                    "（已不存在的 App）",
                    "（存在しないアプリ）"
                )
            },
            |s| {
                let name = &s.name;
                tr!("“{name}”", "「{name}」", "「{name}」")
            },
        );
        let (pid_s, start_s) = (root.pid.to_string(), root.started_us.to_string());
        let pid = root.pid;
        out.push(found(
            RecoveryKind::AppLeftover,
            &[&app.to_string(), &pid_s, &start_s],
            tr!(
                "Leftover processes of managed app {name} (pid {pid})",
                "受管 App {name} 遺留的程序（pid {pid}）",
                "管理対象アプリ {name} の残留プロセス（pid {pid}）";
                name = name
            ),
            tr!(
                "A process tree an earlier manager started: the pid and start time of its root process match the run record, but after the restart it could not be confirmed to have ended. You can also stop it on the Managed apps page.",
                "先前的 manager 啟動的程序樹：根程序的 pid 與啟動時間和執行紀錄相符，但重新啟動後無法確認它已結束。也可以在「受管 App」頁按停止。",
                "以前の manager が起動したプロセスツリーです。ルートプロセスの pid と起動時刻は実行記録と一致しますが、再起動後に終了したことを確認できませんでした。「管理対象アプリ」ページで停止することもできます。"
            ),
            None,
            Some(root.pid),
            spec.map(|s| s.instance_id),
            Some((
                Fix::EndAppLeftover(app),
                tr!(
                    "End the whole process tree (SIGTERM, then SIGKILL after this app's stop grace period) and clear its run record",
                    "結束整個程序樹（先 SIGTERM，等到這個 App 的停止前等待時間後 SIGKILL）並清除執行紀錄",
                    "プロセスツリー全体を終了し（まず SIGTERM、このアプリの停止の猶予時間が過ぎたら SIGKILL）、実行記録を消去します"
                ),
            )),
        ));
    }
}

/// Worker records that are not of a live worker: leftover workers (whose key locks and
/// connector sockets are returned, by file) and stale records.
fn inspect_worker_records(
    manager: &Manager,
    live: &[(u32, LiveWorker)],
    out: &mut Vec<Found>,
    gaps: &mut Vec<ScanGap>,
) -> (HashMap<String, u32>, HashMap<String, u32>) {
    let paths = manager.paths();
    // Worker records: ours when live; otherwise a leftover worker or a stale record.
    let me = process::current_uid();
    let mut orphan_locks: HashMap<String, u32> = HashMap::new();
    let mut orphan_sockets: HashMap<String, u32> = HashMap::new();
    let records = match manager.inventory().records() {
        Ok(r) => r,
        Err(e) => {
            gaps.push(gap(
                tr!("worker records", "worker 紀錄", "worker の記録"),
                Some(&paths.worker_records()),
                tr!("Cannot read: {e}", "無法讀取：{e}", "読み取れません：{e}"),
            ));
            Vec::new()
        }
    };
    for rf in records {
        let file = path_str(&rf.path);
        let r = match rf.record {
            Ok(r) => r,
            Err(why) => {
                out.push(unreadable_record(&rf.path, &file, why));
                continue;
            }
        };
        let is_live = live.iter().any(|(pid, w)| {
            *pid == r.pid && w.instance_id == r.instance_id && w.generation == r.generation
        });
        if is_live {
            continue;
        }
        let recorded = r.identity();
        match process::identity(r.pid) {
            Some(now)
                if !now.zombie
                    && r.uid == me
                    && recorded.is_same_process(&now)
                    && live.iter().all(|(pid, _)| *pid != r.pid) =>
            {
                orphan_locks.insert(r.key_lock.clone(), r.pid);
                if let Some(c) = &r.connector {
                    orphan_sockets.insert(c.clone(), r.pid);
                }
                out.push(orphan_worker(&rf.path, &r));
            }
            Some(now) if !now.zombie => out.push(stale_worker_record(&rf.path, &file, &r, true)),
            _ => out.push(stale_worker_record(&rf.path, &file, &r, false)),
        }
    }
    (orphan_locks, orphan_sockets)
}

/// A record file that cannot be read: it proves nothing, so a reconcile deletes it.
fn unreadable_record(path: &Path, file: &str, why: Text) -> Found {
    found(
        RecoveryKind::StaleWorkerRecord,
        &[file],
        tr!(
            "Unreadable worker record",
            "無法讀取的 worker 紀錄",
            "読み取れない worker の記録"
        ),
        tr!(
            "The record file cannot be read ({why}), so it cannot prove that any process is ours",
            "紀錄檔無法讀取（{why}），不能用來證明任何程序屬於我們",
            "記録ファイルを読み取れないため（{why}）、どのプロセスがこちらのものかを証明できません";
            why = why
        ),
        Some(path),
        None,
        None,
        Some((Fix::RemoveRecord(path.to_path_buf()), delete_record())),
    )
}

/// A worker its record proves is ours (pid, user, start time and program) that the current
/// manager did not start: a reconcile kills it and deletes its record.
fn orphan_worker(path: &Path, r: &WorkerRecord) -> Found {
    let (pid, generation) = (r.pid, r.generation);
    found(
        RecoveryKind::OrphanWorker,
        &[&pid.to_string(), &r.start],
        tr!(
            "Leftover worker process (pid {pid})",
            "遺留的 worker 程序（pid {pid}）",
            "残留した worker プロセス（pid {pid}）"
        ),
        tr!(
            "A worker of generation {generation}: its pid, user, start time and program all match the record, but it does not belong to the current manager (an earlier manager was interrupted). It may still hold the key lock.",
            "第 {generation} 代的 worker：pid、使用者、啟動時間與程式都和紀錄相符，但它不屬於目前的 manager（先前的 manager 中斷了）。它可能仍持有金鑰鎖。",
            "第 {generation} 世代の worker です。pid、ユーザー、起動時刻、プログラムはすべて記録と一致しますが、現在の manager のものではありません（以前の manager が中断しました）。まだ鍵のロックを保持している可能性があります。"
        ),
        Some(path),
        Some(pid),
        Some(r.instance_id),
        Some((
            Fix::Kill {
                identity: r.identity(),
                record: path.to_path_buf(),
            },
            tr!(
                "End this process (SIGKILL) and delete its record",
                "結束這個程序（SIGKILL）並刪除紀錄",
                "このプロセスを終了し（SIGKILL）、記録を削除します"
            ),
        )),
    )
}

/// A record that names no worker of ours any more: its pid now runs another process (`reused`),
/// or the worker has ended. Only the record goes.
fn stale_worker_record(path: &Path, file: &str, r: &WorkerRecord, reused: bool) -> Found {
    let (pid, generation) = (r.pid, r.generation);
    let detail = if reused {
        tr!(
            "pid {pid} is now another process (its start time or program differs from the record) and is left alone; only this record is deleted",
            "pid {pid} 現在是另一個程序（啟動時間或程式和紀錄不同），不會動它；只刪除這個紀錄",
            "pid {pid} は現在別のプロセスです（起動時刻またはプログラムが記録と異なります）。そのプロセスには触れず、この記録だけを削除します"
        )
    } else {
        tr!(
            "The worker of generation {generation} (pid {pid}) has ended",
            "第 {generation} 代的 worker（pid {pid}）已經結束",
            "第 {generation} 世代の worker（pid {pid}）は終了しています"
        )
    };
    found(
        RecoveryKind::StaleWorkerRecord,
        &[file, &generation.to_string()],
        tr!(
            "Stale worker record",
            "過期的 worker 紀錄",
            "古い worker の記録"
        ),
        detail,
        Some(path),
        Some(pid),
        Some(r.instance_id),
        Some((Fix::RemoveRecord(path.to_path_buf()), delete_record())),
    )
}

/// What a reconcile does to a worker record that proves nothing.
fn delete_record() -> Text {
    tr!(
        "Delete this record file",
        "刪除這個紀錄檔",
        "この記録ファイルを削除します"
    )
}

/// The key fingerprints the stored `WireGuard` profiles use, or `None` (with a gap) when they
/// cannot be read.
async fn stored_fingerprints(store: &Store, gaps: &mut Vec<ScanGap>) -> Option<HashSet<String>> {
    match store.list::<RuntimeProfile>().await {
        Ok(ps) => Some(
            ps.iter()
                .map(|p| key_fingerprint(&p.interface.public_key))
                .collect(),
        ),
        Err(e) => {
            gaps.push(gap(
                tr!(
                    "whether key locks are still in use",
                    "金鑰鎖是否仍被使用",
                    "鍵のロックがまだ使われているか"
                ),
                None,
                tr!(
                    "Cannot read the WireGuard profiles ({why}), so it cannot tell whether a lock file nobody holds is no longer in use",
                    "無法讀取 WireGuard 設定（{why}），不能判斷沒人持有的鎖檔是否已不再使用",
                    "WireGuard 設定を読み取れないため（{why}）、誰も保持していないロックファイルが使われなくなったかを判断できません";
                    why = e.to_api().message
                ),
            ));
            None
        }
    }
}

/// Key lock files: held by our live workers, idle, or left over.
async fn inspect_key_locks(
    paths: &vpn_platform::paths::Paths,
    live: &[(u32, LiveWorker)],
    store: &Store,
    orphan_locks: &HashMap<String, u32>,
    resources: &mut OwnedResources,
    out: &mut Vec<Found>,
    gaps: &mut Vec<ScanGap>,
) {
    let stored = stored_fingerprints(store, gaps).await;
    let mut locks = entries(
        &paths.locks(),
        &tr!(
            "key lock directory",
            "金鑰鎖目錄",
            "鍵のロックのディレクトリ"
        ),
        gaps,
    );
    locks.sort();
    for (name, path) in locks {
        let Some(fp) = name
            .strip_prefix("key-")
            .and_then(|n| n.strip_suffix(".lock"))
        else {
            continue;
        };
        if probe::entry(&path) != Some(Entry::File) {
            continue;
        }
        let file = path_str(&path);
        if let Some((_, w)) = live.iter().find(|(_, w)| w.key_lock == file) {
            resources.key_locks.push(LockResource {
                file,
                held: Some(true),
                used_by: Some(w.instance_id),
            });
            continue;
        }
        match FileLock::try_acquire(&path) {
            Ok(lock) => {
                drop(lock);
                resources.key_locks.push(LockResource {
                    file: file.clone(),
                    held: Some(false),
                    used_by: None,
                });
                if stored.as_ref().is_some_and(|s| !s.contains(fp)) {
                    out.push(stale_key_lock(&path, &file));
                }
            }
            Err(LockError::Held) => {
                resources.key_locks.push(LockResource {
                    file: file.clone(),
                    held: Some(true),
                    used_by: None,
                });
                out.push(foreign_key_lock(
                    &path,
                    &file,
                    orphan_locks.get(&file).copied(),
                ));
            }
            Err(LockError::Io(e)) => {
                gaps.push(gap(
                    tr!("key lock", "金鑰鎖", "鍵のロック"),
                    Some(&path),
                    tr!(
                        "Cannot test whether a process holds it: {e}",
                        "無法測試是否有程序持有：{e}",
                        "プロセスが保持しているかをテストできません：{e}"
                    ),
                ));
                resources.key_locks.push(LockResource {
                    file,
                    held: None,
                    used_by: None,
                });
            }
        }
    }
}

/// Connector sockets (one per generation) and bootstrap relay sockets in the run directory.
async fn inspect_sockets(
    manager: &Manager,
    live: &[(u32, LiveWorker)],
    orphan_sockets: &HashMap<String, u32>,
    resources: &mut OwnedResources,
    out: &mut Vec<Found>,
    gaps: &mut Vec<ScanGap>,
) {
    let paths = manager.paths();
    // Connector sockets (one per generation) and bootstrap relay sockets in the run directory.
    let relay = manager.bootstrap().active().map(|g| g.connector);
    let mut sockets = entries(&paths.run, &socket_dir(), gaps);
    sockets.sort();
    for (name, path) in sockets {
        // With a prefix, a `sock` extension is the same as ending in ".sock".
        let sock = Path::new(&name).extension().is_some_and(|x| x == "sock");
        let connector = name.starts_with("c-") && sock;
        let bootstrap = name.starts_with("b-") && sock;
        if !(connector || bootstrap) || probe::entry(&path) != Some(Entry::Socket) {
            continue;
        }
        let file = path_str(&path);
        if connector
            && let Some((_, w)) = live
                .iter()
                .find(|(_, w)| w.connector.as_deref() == Some(&file))
        {
            resources.connector_sockets.push(SocketResource {
                file,
                live: true,
                used_by: Some(w.instance_id),
            });
            continue;
        }
        if bootstrap && relay.as_deref() == Some(file.as_str()) {
            continue;
        }
        // A leftover worker whose identity is proven (pid, user, start time, program) owns this
        // socket: it is never stale while that worker lives, even when it refuses connections. On
        // macOS a full accept queue (a hung worker) refuses exactly like a socket nobody holds.
        let owner = orphan_sockets.get(&file).copied();
        let listening = match owner {
            Some(_) => Some(true),
            None => probe::unix_socket_listening(&path).await,
        };
        if connector {
            resources.connector_sockets.push(SocketResource {
                file: file.clone(),
                live: false,
                used_by: None,
            });
        }
        match listening {
            Some(false) => out.push(stale_socket(&path, &file, connector)),
            Some(true) => out.push(listened_socket(&path, &file, owner)),
            None => gaps.push(gap(
                "socket",
                Some(&path),
                tr!(
                    "Cannot confirm whether a process listens on it",
                    "無法確認是否有程序在接聽",
                    "プロセスが待ち受けているかを確認できません"
                ),
            )),
        }
    }
}

/// What the run directory is called where it could not be read.
fn socket_dir() -> Text {
    tr!("socket directory", "socket 目錄", "ソケットのディレクトリ")
}

/// The title of a socket some process listens on that is not provably ours.
fn foreign_socket() -> Text {
    tr!(
        "Socket another process listens on",
        "有其他程序在接聽的 socket",
        "別のプロセスが待ち受けているソケット"
    )
}

/// What a reconcile does to a socket nobody listens on.
fn delete_socket() -> Text {
    tr!(
        "Delete the socket file",
        "刪除 socket 檔",
        "ソケットファイルを削除します"
    )
}

/// A key lock file nobody holds, for a key no stored profile uses: a reconcile deletes it.
fn stale_key_lock(path: &Path, file: &str) -> Found {
    found(
        RecoveryKind::StaleKeyLock,
        &[file],
        tr!(
            "Unused key lock file",
            "不再使用的金鑰鎖檔",
            "使われなくなった鍵のロックファイル"
        ),
        tr!(
            "No process holds it, and no WireGuard profile uses this key",
            "沒有程序持有它，也沒有任何 WireGuard 設定使用這把金鑰",
            "どのプロセスも保持しておらず、この鍵を使う WireGuard 設定もありません"
        ),
        Some(path),
        None,
        None,
        Some((
            Fix::RemoveLock(path.to_path_buf()),
            tr!(
                "Delete the lock file (holding its lock while deleting it)",
                "刪除鎖檔（刪除時持有它的鎖）",
                "ロックファイルを削除します（削除中はそのロックを保持します）"
            ),
        )),
    )
}

/// A key lock some process holds: a leftover worker (`owner`), or a process that is not provably
/// ours. Only reported.
fn foreign_key_lock(path: &Path, file: &str, owner: Option<u32>) -> Found {
    let detail = owner.map_or_else(
        || {
            tr!(
                "Held by a process that does not belong to this manager; it cannot be proven to be ours and is left alone",
                "被一個不屬於這個 manager 的程序持有；無法證明它是我們的，不會動它",
                "この manager のものではないプロセスが保持しています。こちらのものだと証明できないため、触れません"
            )
        },
        |pid| {
            tr!(
                "Held by a leftover worker (pid {pid}); the lock is released when that process ends",
                "由遺留的 worker（pid {pid}）持有；結束那個程序後鎖會自動釋放",
                "残留した worker（pid {pid}）が保持しています。そのプロセスを終了するとロックは自動的に解放されます"
            )
        },
    );
    found(
        RecoveryKind::ForeignKeyLock,
        &[file],
        tr!(
            "Key lock held by another process",
            "被其他程序持有的金鑰鎖",
            "別のプロセスが保持している鍵のロック"
        ),
        detail,
        Some(path),
        owner,
        None,
        None,
    )
}

/// A connector socket (`connector`) or a bootstrap relay socket nobody listens on: a reconcile
/// deletes it.
fn stale_socket(path: &Path, file: &str, connector: bool) -> Found {
    let title = if connector {
        tr!(
            "Leftover connector socket",
            "遺留的 connector socket",
            "残留した connector のソケット"
        )
    } else {
        tr!(
            "Leftover relay socket of the first direct connection",
            "遺留的首次直連中繼 socket",
            "残留した初回の直接接続のリレーソケット"
        )
    };
    found(
        RecoveryKind::StaleSocket,
        &[file],
        title,
        tr!(
            "No process listens on it (the process that created it has ended)",
            "沒有任何程序在接聽（建立它的程序已經結束）",
            "どのプロセスも待ち受けていません（作成したプロセスは終了しています）"
        ),
        Some(path),
        None,
        None,
        Some((Fix::RemoveSocket(path.to_path_buf()), delete_socket())),
    )
}

/// A socket some process listens on: a leftover worker (`owner`, cleaned up once it has ended),
/// or a process that is not a worker of this manager. Only reported.
fn listened_socket(path: &Path, file: &str, owner: Option<u32>) -> Found {
    let detail = owner.map_or_else(
        || {
            tr!(
                "A process listens on it, but it is not a worker of this manager; it is left alone",
                "有程序在接聽，但不是這個 manager 的 worker；不會動它",
                "プロセスが待ち受けていますが、この manager の worker ではありません。触れません"
            )
        },
        |pid| {
            tr!(
                "A leftover worker (pid {pid}) still holds it; it is cleaned up once that worker has ended",
                "遺留的 worker（pid {pid}）仍持有它；結束它之後才會清理",
                "残留した worker（pid {pid}）がまだ保持しています。その worker を終了してからクリーンアップします"
            )
        },
    );
    found(
        RecoveryKind::ForeignSocket,
        &[file],
        foreign_socket(),
        detail,
        Some(path),
        owner,
        None,
        None,
    )
}

/// Temporary files of atomic writes whose writer is gone.
fn inspect_temps(
    paths: &vpn_platform::paths::Paths,
    ssh_dir: Option<&Path>,
    out: &mut Vec<Found>,
    gaps: &mut Vec<ScanGap>,
) {
    // Temporary files of atomic writes whose writer is gone.
    let mut temps: Vec<(String, PathBuf)> = Vec::new();
    if let Some(dir) = ssh_dir {
        let what = tr!("SSH directory", "SSH 目錄", "SSH ディレクトリ");
        for (name, path) in entries(dir, &what, gaps) {
            let ours = name.starts_with(&format!(".{}.tmp-", vpn_ssh::MANAGED_FILE))
                || name.starts_with(".config.tmp-");
            if ours {
                temps.push((name, path));
            }
        }
    }
    let what = tr!(
        "worker record directory",
        "worker 紀錄目錄",
        "worker の記録のディレクトリ"
    );
    for (name, path) in entries(&paths.worker_records(), &what, gaps) {
        if name.starts_with(".record.tmp-") {
            temps.push((name, path));
        }
    }
    temps.sort();
    for (name, path) in temps {
        if probe::entry(&path) != Some(Entry::File) || !temp_abandoned(&name, &path) {
            continue;
        }
        let file = path_str(&path);
        out.push(found(
            RecoveryKind::TempFile,
            &[&file],
            tr!(
                "Interrupted temporary file",
                "中斷的暫存檔",
                "中断された一時ファイル"
            ),
            tr!(
                "Temporary data an atomic write left behind: the process that wrote it is gone, and its content never took effect",
                "原子寫入留下的暫存資料：寫入它的程序已不在，內容從未生效",
                "アトミックな書き込みが残した一時データです。書き込んだプロセスはもう存在せず、内容が有効になったことはありません"
            ),
            Some(&path),
            temp_pid(&name),
            None,
            Some((
                Fix::RemoveFile(path.clone()),
                tr!(
                    "Delete this temporary file",
                    "刪除這個暫存檔",
                    "この一時ファイルを削除します"
                ),
            )),
        ));
    }
}

/// Strict-mode sandboxes (Linux) by their rendezvous sockets (`sb-*.sock`): those our Instances
/// hold are resources; one nobody holds that proves it is ours is a leftover a reconcile tears
/// down; anything else listening there is only reported.
async fn inspect_sandboxes(
    paths: &vpn_platform::paths::Paths,
    statuses: &[InstanceStatus],
    store: &Store,
    resources: &mut OwnedResources,
    out: &mut Vec<Found>,
) {
    let installation = store.installation_id().to_string();
    let mut held: Vec<SandboxResource> = statuses
        .iter()
        .filter_map(|s| {
            s.sandbox.as_ref().map(|b| SandboxResource {
                instance_id: s.instance_id,
                epoch: b.epoch,
                holder_pid: b.holder_pid,
                file: path_str(&paths.sandbox_socket(&s.instance_id.to_string())),
            })
        })
        .collect();
    // The connector-socket scan above already reports this directory when it cannot be read.
    let mut sockets = entries(&paths.run, &socket_dir(), &mut Vec::new());
    sockets.sort();
    for (name, path) in sockets {
        if !(name.starts_with("sb-") && Path::new(&name).extension().is_some_and(|x| x == "sock"))
            || probe::entry(&path) != Some(Entry::Socket)
        {
            continue;
        }
        let file = path_str(&path);
        if held.iter().any(|s| s.file == file) {
            continue;
        }
        match strict::listening(&path) {
            Some(false) => out.push(found(
                RecoveryKind::StaleSocket,
                &[&file],
                tr!(
                    "Leftover strict isolation sandbox socket",
                    "遺留的嚴格隔離 sandbox socket",
                    "残留した厳格な分離のサンドボックスのソケット"
                ),
                tr!(
                    "No process listens on it (its sandbox has ended)",
                    "沒有任何程序在接聽（它的 sandbox 已經結束）",
                    "どのプロセスも待ち受けていません（そのサンドボックスは終了しています）"
                ),
                Some(&path),
                None,
                None,
                Some((Fix::RemoveSandboxSocket(path.clone()), delete_socket())),
            )),
            None => {}
            Some(true) => {
                inspect_listening_sandbox(&path, file, &installation, &mut held, out).await;
            }
        }
    }
    held.sort_by_key(|s| s.instance_id);
    resources.sandboxes = held;
}

/// [`inspect_sandboxes`]: a sandbox socket someone listens on that none of our Instances
/// reported: ours and in use, a leftover, or someone else's.
async fn inspect_listening_sandbox(
    path: &Path,
    file: String,
    installation: &str,
    held: &mut Vec<SandboxResource>,
    out: &mut Vec<Found>,
) {
    let client = match SandboxClient::connect(path).await {
        Ok(c) => c,
        Err(e) => {
            out.push(found(
                RecoveryKind::ForeignSocket,
                &[&file],
                foreign_socket(),
                tr!(
                    "A process listens on it, but it cannot be proven to be a sandbox of this VPN Manager ({e}); it is left alone",
                    "有程序在接聽，但無法證明它是這個 VPN Manager 的 sandbox（{e}）；不會動它",
                    "プロセスが待ち受けていますが、この VPN Manager のサンドボックスだと証明できません（{e}）。触れません"
                ),
                Some(path),
                None,
                None,
                None,
            ));
            return;
        }
    };
    let identity = client.identity();
    let holder = client.holder().clone();
    let instance_id = identity.instance_id.parse::<InstanceId>().ok();
    if identity.installation_id != installation {
        out.push(found(
            RecoveryKind::ForeignSocket,
            &[&file],
            tr!(
                "Sandbox of another VPN Manager installation",
                "其他 VPN Manager 安裝的 sandbox",
                "別の VPN Manager のインストールのサンドボックス"
            ),
            tr!(
                "This sandbox belongs to another VPN Manager installation; it is left alone",
                "這個 sandbox 屬於另一個 VPN Manager 安裝；不會動它",
                "このサンドボックスは別の VPN Manager のインストールのものです。触れません"
            ),
            Some(path),
            Some(holder.pid),
            None,
            None,
        ));
        return;
    }
    match (client.managed(), instance_id) {
        // Held by one of our Instances whose status did not arrive in time (one
        // manager runs per installation): ours and in use.
        (true, Some(id)) => held.push(SandboxResource {
            instance_id: id,
            epoch: identity.epoch,
            holder_pid: holder.pid,
            file,
        }),
        (true, None) => out.push(found(
            RecoveryKind::ForeignSocket,
            &[&file],
            tr!(
                "Unidentified sandbox",
                "無法辨識的 sandbox",
                "識別できないサンドボックス"
            ),
            tr!(
                "A manager holds it, but the connection ID it reports cannot be identified; it is left alone",
                "有 manager 持有它，但它回報的連線 ID 無法辨識；不會動它",
                "manager が保持していますが、報告された接続 ID を識別できません。触れません"
            ),
            Some(path),
            Some(holder.pid),
            None,
            None,
        )),
        (false, _) => out.push(orphan_sandbox(
            path,
            &file,
            installation,
            identity,
            holder,
            instance_id,
        )),
    }
}

/// A sandbox whose holder proves it is ours (this installation, this user, this boot) that no
/// manager holds: a reconcile ends its Apps and tears it down.
fn orphan_sandbox(
    path: &Path,
    file: &str,
    installation: &str,
    identity: &strict::SandboxIdentity,
    holder: ProcessIdentity,
    instance_id: Option<InstanceId>,
) -> Found {
    let (epoch, pid) = (identity.epoch, holder.pid);
    let (epoch_key, start) = (epoch.to_string(), holder.start.clone());
    found(
        RecoveryKind::OrphanSandbox,
        &[file, &epoch_key, &start],
        tr!(
            "Leftover strict isolation sandbox (pid {pid})",
            "遺留的嚴格隔離 sandbox（pid {pid}）",
            "残留した厳格な分離のサンドボックス（pid {pid}）"
        ),
        tr!(
            "A sandbox of epoch {epoch}: its holder proves it belongs to this installation, this user and this boot, but no manager holds it (an earlier manager was interrupted, or its teardown did not finish). The apps in it are offline; if it is not cleaned up, it closes by itself some time after losing its manager.",
            "epoch {epoch} 的 sandbox：holder 證明它屬於這個安裝、這個使用者與這次開機，但沒有任何 manager 持有它（先前的 manager 中斷了，或拆除沒有完成）。其中的 App 都離線；不清理時，它會在失去 manager 一段時間後自行關閉。",
            "epoch {epoch} のサンドボックスです。holder により、このインストール、このユーザー、今回の起動のものであることが証明されていますが、どの manager も保持していません（以前の manager が中断したか、撤去が完了しませんでした）。中のアプリはすべてオフラインです。クリーンアップしない場合、manager を失ってからしばらくすると自動的に閉じます。"
        ),
        Some(path),
        Some(pid),
        instance_id,
        Some((
            Fix::TeardownSandbox {
                socket: path.to_path_buf(),
                installation: installation.to_string(),
                instance: identity.instance_id.clone(),
                epoch,
                holder,
            },
            tr!(
                "End the apps in it first (SIGTERM, then SIGKILL after each app's stop grace period), then tear down the sandbox",
                "先結束其中的 App（SIGTERM，等到各 App 的停止前等待時間後 SIGKILL），再拆除 sandbox",
                "まず中のアプリを終了し（SIGTERM、各アプリの停止の猶予時間が過ぎたら SIGKILL）、それからサンドボックスを撤去します"
            ),
        )),
    )
}

/// Tear down a sandbox nobody holds, after proving again that it is the one inspected.
async fn teardown_sandbox(
    socket: &Path,
    installation: &str,
    instance: &str,
    epoch: u64,
    expected: &ProcessIdentity,
    grace: Duration,
) -> (ReconcileOutcome, Text) {
    // Attaching succeeds only while nobody holds the sandbox; it proves the installation again.
    let lease = match SandboxLease::attach(socket, installation).await {
        Ok(lease) => lease,
        Err(e) => {
            return match strict::listening(socket) {
                Some(false) => (
                    ReconcileOutcome::Skipped,
                    tr!(
                        "The sandbox has ended by itself",
                        "sandbox 已自行結束",
                        "サンドボックスは自ら終了しました"
                    ),
                ),
                _ => (
                    ReconcileOutcome::Skipped,
                    tr!(
                        "Cannot take over this sandbox ({e}); it was left alone",
                        "無法接手這個 sandbox（{e}），沒有動它",
                        "このサンドボックスを引き継げません（{e}）。触れませんでした"
                    ),
                ),
            };
        }
    };
    let same = strict::same_process(expected, lease.holder())
        && lease.identity().instance_id == instance
        && lease.identity().epoch == epoch;
    if !same {
        // Dropping the lease leaves it as it was: nobody holds it.
        return (
            ReconcileOutcome::Skipped,
            tr!(
                "Another sandbox listens there now; it was left alone",
                "接聽的已是另一個 sandbox，沒有動它",
                "待ち受けているのはすでに別のサンドボックスです。触れませんでした"
            ),
        );
    }
    let pid = expected.pid;
    if lease.teardown(grace).await {
        (
            ReconcileOutcome::Done,
            tr!(
                "Ended the apps in it and tore down the sandbox (holder pid {pid})",
                "已結束其中的 App 並拆除 sandbox（holder pid {pid}）",
                "中のアプリを終了し、サンドボックスを撤去しました（holder pid {pid}）"
            ),
        )
    } else {
        (
            ReconcileOutcome::Failed,
            tr!(
                "Asked for the teardown, but the holder (pid {pid}) did not end in time",
                "已要求拆除，但 holder（pid {pid}）沒有在時限內結束",
                "撤去を要求しましたが、holder（pid {pid}）は時間内に終了しませんでした"
            ),
        )
    }
}

/// Wait (bounded) until a killed process has ended.
async fn wait_ended(identity: &ProcessIdentity) -> bool {
    let deadline = tokio::time::Instant::now() + KILL_WAIT;
    loop {
        if process::ended(identity) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// End a leftover worker whose identity was proven, and remove its record.
async fn kill_worker(identity: &ProcessIdentity, record: &Path) -> (ReconcileOutcome, Text) {
    let pid = identity.pid;
    match process::kill_verified(identity) {
        Ok(KillOutcome::Killed) => {
            let ended = wait_ended(identity).await;
            remove_file_if_present(record);
            if ended {
                (
                    ReconcileOutcome::Done,
                    tr!(
                        "Ended pid {pid} and deleted its record",
                        "已結束 pid {pid}，並刪除紀錄",
                        "pid {pid} を終了し、記録を削除しました"
                    ),
                )
            } else {
                (
                    ReconcileOutcome::Done,
                    tr!(
                        "Sent SIGKILL to pid {pid}; the process is still ending; its record was deleted",
                        "已對 pid {pid} 送出 SIGKILL；程序還在結束中，已刪除紀錄",
                        "pid {pid} に SIGKILL を送りました。プロセスはまだ終了処理中です。記録は削除しました"
                    ),
                )
            }
        }
        Ok(KillOutcome::Gone) => {
            remove_file_if_present(record);
            (
                ReconcileOutcome::Done,
                tr!(
                    "The process had ended by itself; its record was deleted",
                    "程序已自行結束；已刪除紀錄",
                    "プロセスはすでに自ら終了していました。記録を削除しました"
                ),
            )
        }
        Ok(KillOutcome::NotOurs) => {
            remove_file_if_present(record);
            (
                ReconcileOutcome::Skipped,
                tr!(
                    "pid {pid} is now another process and was left alone; the stale record was deleted",
                    "pid {pid} 已是另一個程序，沒有動它；已刪除過期的紀錄",
                    "pid {pid} はすでに別のプロセスのため、触れませんでした。古い記録を削除しました"
                ),
            )
        }
        Err(e) => (
            ReconcileOutcome::Failed,
            tr!(
                "Cannot end the process: {e}",
                "無法結束程序：{e}",
                "プロセスを終了できません：{e}"
            ),
        ),
    }
}

/// A file removed by a reconcile.
fn deleted() -> (ReconcileOutcome, Text) {
    (
        ReconcileOutcome::Done,
        tr!("Deleted", "已刪除", "削除しました"),
    )
}

/// A file a reconcile could not remove.
fn not_deleted(e: &std::io::Error) -> (ReconcileOutcome, Text) {
    (
        ReconcileOutcome::Failed,
        tr!("Cannot delete: {e}", "無法刪除：{e}", "削除できません：{e}"),
    )
}

/// A socket a reconcile leaves because something may listen on it now.
fn still_listened_on() -> (ReconcileOutcome, Text) {
    (
        ReconcileOutcome::Skipped,
        tr!(
            "A process listens on it now (or that cannot be confirmed); not deleted",
            "現在有程序在接聽（或無法確認），沒有刪除",
            "現在プロセスが待ち受けている（または確認できない）ため、削除しませんでした"
        ),
    )
}

async fn apply(manager: &Manager, fix: &Fix) -> (ReconcileOutcome, Text) {
    let remove = |p: &Path, what: Entry| -> (ReconcileOutcome, Text) {
        if probe::entry(p) != Some(what) {
            return (
                ReconcileOutcome::Skipped,
                tr!(
                    "No longer there, or changed; not handled",
                    "已不存在或已改變，沒有處理",
                    "すでに存在しないか変更されているため、処理しませんでした"
                ),
            );
        }
        match std::fs::remove_file(p) {
            Ok(()) => deleted(),
            Err(e) => not_deleted(&e),
        }
    };
    match fix {
        Fix::Kill { identity, record } => kill_worker(identity, record).await,
        Fix::RemoveRecord(p) | Fix::RemoveFile(p) => remove(p, Entry::File),
        Fix::RemoveLock(p) => {
            if probe::entry(p) != Some(Entry::File) {
                return (
                    ReconcileOutcome::Skipped,
                    tr!(
                        "No longer there; not handled",
                        "已不存在，沒有處理",
                        "すでに存在しないため、処理しませんでした"
                    ),
                );
            }
            match FileLock::try_acquire(p) {
                // Removed while we hold it: nobody can be between opening and locking it.
                Ok(lock) => {
                    let r = std::fs::remove_file(p);
                    drop(lock);
                    match r {
                        Ok(()) => deleted(),
                        Err(e) => not_deleted(&e),
                    }
                }
                Err(LockError::Held) => (
                    ReconcileOutcome::Skipped,
                    tr!(
                        "A process holds this lock now; not deleted",
                        "現在有程序持有這個鎖，沒有刪除",
                        "現在プロセスがこのロックを保持しているため、削除しませんでした"
                    ),
                ),
                Err(LockError::Io(e)) => (
                    ReconcileOutcome::Failed,
                    tr!("Cannot check: {e}", "無法檢查：{e}", "確認できません：{e}"),
                ),
            }
        }
        Fix::RemoveSocket(p) => match probe::unix_socket_listening(p).await {
            Some(false) => remove(p, Entry::Socket),
            _ => still_listened_on(),
        },
        Fix::RemoveSandboxSocket(p) => match strict::listening(p) {
            Some(false) => remove(p, Entry::Socket),
            _ => still_listened_on(),
        },
        Fix::TeardownSandbox {
            socket,
            installation,
            instance,
            epoch,
            holder,
        } => {
            let grace = crate::sandbox::teardown_grace(&manager.ctx, instance).await;
            teardown_sandbox(socket, installation, instance, *epoch, holder, grace).await
        }
        Fix::EndAppLeftover(app) => match manager.apps().end_leftover_of(*app).await {
            Ok(true) => (
                ReconcileOutcome::Done,
                tr!(
                    "Ended this app's leftover process tree and cleared its run record",
                    "已結束這個 App 遺留的程序樹，並清除它的執行紀錄",
                    "このアプリの残留プロセスツリーを終了し、実行記録を消去しました"
                ),
            ),
            Ok(false) => (
                ReconcileOutcome::Skipped,
                tr!(
                    "No longer left over (stopped); not handled",
                    "已不再遺留（已停止），沒有處理",
                    "すでに残留していない（停止済み）ため、処理しませんでした"
                ),
            ),
            Err(e) => (ReconcileOutcome::Failed, e.message),
        },
    }
}

/// Clean what is verifiably ours and stale.
///
/// With `only`, just those item ids (what the user
/// confirmed); anything confirmed that is no longer found is reported as skipped. Worker spawns
/// wait meanwhile, so no worker is between opening and locking a lock file being removed.
pub async fn reconcile(
    manager: &Manager,
    store: &Store,
    ssh_dir: Option<&Path>,
    only: Option<Vec<String>>,
) -> ReconcileResult {
    let _gate = manager.spawn_gate().write().await;
    let inspection = inspect(manager, store, ssh_dir).await;
    let mut actions = Vec::new();
    for f in &inspection.found {
        let Some(fix) = &f.fix else { continue };
        if only.as_ref().is_some_and(|o| !o.contains(&f.item.id)) {
            actions.push(ReconcileAction {
                item_id: f.item.id.clone(),
                kind: Some(f.item.kind),
                title: f.item.title.clone(),
                outcome: ReconcileOutcome::Skipped,
                detail: tr!(
                    "Not in the confirmed list; not handled this time",
                    "不在確認的清單中，這次沒有處理",
                    "確認した一覧にないため、今回は処理しませんでした"
                ),
            });
            continue;
        }
        let (outcome, detail) = apply(manager, fix).await;
        if outcome == ReconcileOutcome::Done {
            tracing::info!(kind = ?f.item.kind, path = ?f.item.path, pid = ?f.item.pid, "recovery cleaned");
        }
        actions.push(ReconcileAction {
            item_id: f.item.id.clone(),
            kind: Some(f.item.kind),
            title: f.item.title.clone(),
            outcome,
            detail,
        });
    }
    for id in only.iter().flatten() {
        if !inspection.found.iter().any(|f| &f.item.id == id) {
            actions.push(ReconcileAction {
                item_id: id.clone(),
                kind: None,
                title: tr!("Confirmed item", "已確認的項目", "確認済みの項目"),
                outcome: ReconcileOutcome::Skipped,
                detail: tr!(
                    "No longer there when checked again; not handled",
                    "重新檢查時已不存在，沒有處理",
                    "再チェック時にはすでに存在しなかったため、処理しませんでした"
                ),
            });
        }
    }
    let remaining = inspect(manager, store, ssh_dir).await.report().items;
    ReconcileResult {
        operation_id: None,
        observed_at: Timestamp::now(),
        actions,
        remaining,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporary_names_carry_their_writer() {
        assert_eq!(
            temp_pid(".vpn-manager.conf.tmp-4242-1730000000"),
            Some(4242)
        );
        assert_eq!(temp_pid(".record.tmp-77-901"), Some(77));
        assert_eq!(temp_pid("plain"), None);
    }
}
