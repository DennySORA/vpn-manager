//! Recovery only touches what it can prove is ours and stale. Decoys: a process whose pid a
//! stale record names (other start time), one recorded with another program, one of our own
//! live workers, a lock and a socket another process holds. Only the genuine leftovers go.

#![cfg(test)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use vpn_domain::*;
use vpn_instance_manager::Manager;
use vpn_instance_manager::inventory::WorkerRecord;
use vpn_instance_manager::recovery::{inspect, reconcile};
use vpn_platform::lock::FileLock;
use vpn_platform::paths::Paths;
use vpn_platform::process::identity;
use vpn_store::Store;
use zeroize::Zeroizing;

fn not_a_worker() -> PathBuf {
    ["/usr/bin/false", "/bin/false"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .expect("a `false` executable")
}

fn sleeper() -> Child {
    Command::new("/bin/sleep").arg("120").spawn().unwrap()
}

fn alive(c: &mut Child) -> bool {
    c.try_wait().unwrap().is_none()
}

/// Clean-up: kill and reap the decoys (best effort: a failure is printed, never asserted).
fn end_all(decoys: impl IntoIterator<Item = Child>) {
    for mut c in decoys {
        if let Err(e) = c.kill() {
            eprintln!("decoy {} not killed: {e}", c.id());
        }
        if let Err(e) = c.wait() {
            eprintln!("decoy {} not reaped: {e}", c.id());
        }
    }
}

/// Write a worker record the way the manager does.
fn record(dir: &Path, r: &WorkerRecord) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join(format!("{}-{}.json", r.instance_id, r.generation));
    std::fs::write(&path, serde_json::to_vec(r).unwrap()).unwrap();
    path
}

fn record_of(pid: u32, generation: u64, paths: &Paths) -> WorkerRecord {
    let id = identity(pid).unwrap();
    WorkerRecord {
        format: 1,
        instance_id: InstanceId::new(),
        generation,
        pid,
        uid: id.uid,
        start: id.start,
        started_at_ms: id.started_at_ms,
        exe: id.exe.map(|p| p.to_string_lossy().into_owned()),
        key_lock: paths
            .key_lock(&format!("{generation:064x}"))
            .to_string_lossy()
            .into_owned(),
        connector: None,
        manager_pid: 1,
        recorded_at: Timestamp::now(),
    }
}

fn age(path: &Path, secs: u64) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(secs))
        .unwrap();
}

/// What an inspection of the decoys must report: one orphan, two stale records, one stale
/// and one foreign lock and socket, and only the abandoned temporary file.
fn assert_inspected(report: &RecoveryReport, orphan: u32, ours: u32, old_tmp: &Path) {
    let kinds = |k: RecoveryKind| {
        report
            .items
            .iter()
            .filter(|i| i.kind == k)
            .collect::<Vec<_>>()
    };
    let orphans = kinds(RecoveryKind::OrphanWorker);
    assert_eq!(orphans.len(), 1, "{:#?}", report.items);
    assert_eq!(orphans[0].pid, Some(orphan));
    assert!(orphans[0].cleanable);
    assert_eq!(kinds(RecoveryKind::StaleWorkerRecord).len(), 2);
    assert!(report.items.iter().all(|i| i.pid != Some(ours)));
    assert_eq!(kinds(RecoveryKind::StaleKeyLock).len(), 1);
    let foreign_lock = kinds(RecoveryKind::ForeignKeyLock);
    assert_eq!(foreign_lock.len(), 1);
    assert!(!foreign_lock[0].cleanable);
    assert_eq!(kinds(RecoveryKind::StaleSocket).len(), 1);
    assert_eq!(kinds(RecoveryKind::ForeignSocket).len(), 1);
    let temps = kinds(RecoveryKind::TempFile);
    assert_eq!(temps.len(), 1);
    assert_eq!(temps[0].path.as_deref(), Some(old_tmp.to_str().unwrap()));
}

/// A connector socket nobody listens on, and one someone else does (with its listener).
fn sockets(paths: &Paths) -> (PathBuf, PathBuf, tokio::net::UnixListener) {
    let stale_socket = paths.run.join("c-deadbeef-7.sock");
    drop(tokio::net::UnixListener::bind(&stale_socket).unwrap());
    let busy_socket = paths.run.join("c-cafebabe-1.sock");
    let listener = tokio::net::UnixListener::bind(&busy_socket).unwrap();
    (stale_socket, busy_socket, listener)
}

/// An abandoned temporary file of an atomic write, and a fresh one.
fn temp_files(ssh: &Path) -> (PathBuf, PathBuf) {
    let old_tmp = ssh.join(".vpn-manager.conf.tmp-999999-1");
    std::fs::write(&old_tmp, "Host x\n").unwrap();
    age(&old_tmp, 3600);
    let fresh_tmp = ssh.join(".vpn-manager.conf.tmp-999998-2");
    std::fs::write(&fresh_tmp, "Host y\n").unwrap();
    (old_tmp, fresh_tmp)
}

#[tokio::test]
async fn reconcile_cleans_only_what_is_provably_ours_and_stale() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(&dir.path().join("state"));
    paths.ensure().unwrap();
    let ssh = dir.path().join("ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let store = Arc::new(Store::open(&paths.state, &Zeroizing::new([3u8; 32]), 1).unwrap());
    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();
    let records = paths.worker_records();

    // Decoy 1: a stale record names this pid, but with another start time (pid reuse).
    let mut reused = sleeper();
    let mut r = record_of(reused.id(), 1, &paths);
    r.start = "1.000001".into();
    let reused_record = record(&records, &r);
    // Decoy 2: the right pid and start time, but another program was recorded.
    let mut other_program = sleeper();
    let mut r = record_of(other_program.id(), 2, &paths);
    r.exe = Some("/opt/vpn-manager/bin/vpnd".into());
    record(&records, &r);
    // Decoy 3: one of our own live workers (in the inventory and on disk).
    let mut ours = sleeper();
    let ticket = manager.inventory().spawned(
        ours.id(),
        InstanceId::new(),
        3,
        paths
            .key_lock(&"c".repeat(64))
            .to_string_lossy()
            .into_owned(),
        None,
    );
    // The genuine leftover: a process recorded exactly, not a child of this manager.
    let mut orphan = sleeper();
    let orphan_record = record(&records, &record_of(orphan.id(), 4, &paths));

    // Lock files: one nobody holds for a key no profile uses, one another process holds.
    let stale_lock = paths.key_lock(&"a".repeat(64));
    drop(FileLock::try_acquire(&stale_lock).unwrap());
    let held_lock = paths.key_lock(&"b".repeat(64));
    let holder = FileLock::try_acquire(&held_lock).unwrap();
    // Sockets: one nobody listens on, one someone else does.
    let (stale_socket, busy_socket, _listener) = sockets(&paths);
    // Temporary files: an abandoned one, and a fresh one (could be in the middle of a write).
    let (old_tmp, fresh_tmp) = temp_files(&ssh);

    let report = inspect(&manager, &store, Some(&ssh)).await.report();
    let kinds = |k: RecoveryKind| {
        report
            .items
            .iter()
            .filter(|i| i.kind == k)
            .collect::<Vec<_>>()
    };
    assert_inspected(&report, orphan.id(), ours.id(), &old_tmp);
    // The live worker is listed as a resource, not as an anomaly.
    assert!(report.resources.workers.iter().any(|w| w.pid == ours.id()));
    // Inspecting changed nothing.
    assert!(alive(&mut orphan) && stale_lock.exists() && stale_socket.exists());

    // Only what the user confirmed is cleaned.
    let socket_id = kinds(RecoveryKind::StaleSocket)[0].id.clone();
    let result = reconcile(&manager, &store, Some(&ssh), Some(vec![socket_id.clone()])).await;
    let done: Vec<_> = result
        .actions
        .iter()
        .filter(|a| a.outcome == ReconcileOutcome::Done)
        .collect();
    assert_eq!(done.len(), 1, "{:#?}", result.actions);
    assert_eq!(done[0].item_id, socket_id);
    assert!(!stale_socket.exists());
    assert!(alive(&mut orphan), "not confirmed: left alone");
    assert!(
        result
            .actions
            .iter()
            .any(|a| a.outcome == ReconcileOutcome::Skipped)
    );

    // Everything cleanable.
    let result = reconcile(&manager, &store, Some(&ssh), None).await;
    assert!(
        result
            .actions
            .iter()
            .all(|a| a.outcome == ReconcileOutcome::Done),
        "{:#?}",
        result.actions
    );
    let status = orphan.wait().unwrap();
    assert!(!status.success(), "the orphan was killed");
    assert!(!orphan_record.exists());
    assert!(!reused_record.exists(), "the stale record went");
    // The decoys and our own worker are untouched.
    assert!(
        alive(&mut reused),
        "a process a stale record named is never killed"
    );
    assert!(alive(&mut other_program), "another program is never killed");
    assert!(alive(&mut ours), "our own live worker is never killed");
    assert!(!stale_lock.exists());
    assert!(held_lock.exists(), "a held lock stays");
    assert!(busy_socket.exists(), "a socket someone listens on stays");
    assert!(!old_tmp.exists() && fresh_tmp.exists());
    // What remains is only what is not ours to clean.
    assert!(
        result.remaining.iter().all(|i| !i.cleanable),
        "{:#?}",
        result.remaining
    );

    drop(ticket);
    drop(holder);
    end_all([reused, other_program, ours]);
    manager.shutdown().await;
}

fn path_of(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[tokio::test]
async fn what_cannot_be_looked_at_is_a_gap() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(&dir.path().join("state"));
    paths.ensure().unwrap();
    let store = Arc::new(Store::open(&paths.state, &Zeroizing::new([5u8; 32]), 1).unwrap());
    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();

    // A directory that cannot be read: what is in it is unknown, not nothing.
    let locks = paths.locks();
    std::fs::create_dir_all(&locks).unwrap();
    std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o000)).unwrap();

    let report = inspect(&manager, &store, None).await.report();
    let gap = report
        .gaps
        .iter()
        .find(|g| g.path.as_deref() == Some(path_of(&locks).as_str()))
        .unwrap_or_else(|| panic!("{:#?}", report.gaps));
    assert!(gap.reason.zh_tw.contains("無法讀取"), "{gap:?}");

    std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700)).unwrap();
    let report = inspect(&manager, &store, None).await.report();
    assert!(report.gaps.is_empty(), "{:#?}", report.gaps);
    manager.shutdown().await;
}

/// A leftover worker that is alive but refuses connections on its connector socket (hung, or on
/// macOS a full accept queue, which refuses like a closed socket): the socket is still its, never
/// a stale socket to delete. Ending the worker is the fix offered.
#[tokio::test]
async fn a_socket_of_a_live_leftover_worker_is_never_stale_even_when_it_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(&dir.path().join("state"));
    paths.ensure().unwrap();
    let store = Arc::new(Store::open(&paths.state, &Zeroizing::new([5u8; 32]), 1).unwrap());
    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();

    // The worker's connector: bound, then nobody accepts (connections are refused).
    let socket = paths.run.join("c-0badf00d-9.sock");
    drop(tokio::net::UnixListener::bind(&socket).unwrap());
    let mut hung = sleeper();
    let mut r = record_of(hung.id(), 9, &paths);
    r.connector = Some(socket.to_string_lossy().into_owned());
    record(&paths.worker_records(), &r);

    let report = inspect(&manager, &store, None).await.report();
    let of = |k: RecoveryKind| {
        report
            .items
            .iter()
            .filter(|i| i.kind == k)
            .collect::<Vec<_>>()
    };
    assert!(
        of(RecoveryKind::StaleSocket).is_empty(),
        "{:#?}",
        report.items
    );
    let held = of(RecoveryKind::ForeignSocket);
    assert_eq!(held.len(), 1, "{:#?}", report.items);
    assert_eq!(held[0].pid, Some(hung.id()));
    assert!(!held[0].cleanable, "the socket goes only with its worker");
    let worker = of(RecoveryKind::OrphanWorker);
    assert_eq!(worker.len(), 1);
    assert!(worker[0].cleanable, "ending the worker is the fix");
    assert!(socket.exists() && alive(&mut hung));
    hung.kill().unwrap();
    hung.wait().unwrap();
}
