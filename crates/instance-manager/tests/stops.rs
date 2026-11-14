//! A stop whose latch never reached the disk survives the manager. While the Store cannot take
//! the latch, the stop holds in memory and its marker is on disk; a new controller connection
//! changes nothing. A manager that is killed — or that exits normally — before the latch is on
//! disk does not come back with the old `running` intent: the Instance stays closed in
//! `recovery_required` until the user stops it, clears its emergency or starts it, and only that
//! decision, once on disk, ends it. A stop recorded only as an operation (no marker, no memory)
//! counts too. A stop that did reach the disk leaves nothing behind.
//!
//! The "worker" is `false`: a start gets as far as spawning, which is enough to tell a start
//! attempt (`WORKER_START`) from an Instance that is held.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use std::assert_matches;
use vpn_domain::*;
use vpn_instance_manager::Manager;
use vpn_instance_manager::rpc::{SystemFacts, serve};
use vpn_ipc::control::{Call, ControlClient, Lifecycle, Reply};
use vpn_platform::paths::Paths;
use vpn_store::{Begin, IntentChange, Store};
use zeroize::Zeroizing;

const STOP_NOT_CONFIRMED: &str = "STOP_NOT_CONFIRMED";

fn meta() -> EntityMeta {
    EntityMeta {
        revision: 1,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
}

/// An executable that exits at once without speaking the worker protocol.
fn not_a_worker() -> PathBuf {
    ["/usr/bin/false", "/bin/false"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .expect("a `false` executable")
}

fn open(paths: &Paths) -> Arc<Store> {
    Arc::new(Store::open(&paths.state, &Zeroizing::new([5u8; 32]), 1).unwrap())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// An Instance whose stored intent says running, as a previous manager left it.
async fn running_instance(paths: &Paths) -> InstanceId {
    paths.ensure().unwrap();
    let store = open(paths);
    let key = store
        .put_secret(
            "wireguard_private_key".into(),
            None,
            Zeroizing::new(vec![7u8; 32]),
            None,
        )
        .await
        .unwrap();
    let profile = store
        .create(RuntimeProfile {
            id: ProfileId::new(),
            meta: meta(),
            name: "lab".into(),
            provider: ProviderKind::Generic,
            source: ProfileSource::Imported,
            interface: InterfaceSpec {
                private_key: key.secret_ref,
                public_key: WgKey::from_str("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=")
                    .unwrap(),
                addresses: vec!["10.99.0.2/32".parse().unwrap()],
                dns: vec!["10.64.0.1".parse().unwrap()],
                mtu: 1420,
            },
            peer: PeerSpec {
                public_key: WgKey::from_str("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
                    .unwrap(),
                preshared_key: None,
                endpoint: "198.51.100.7:51820".parse().unwrap(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                persistent_keepalive: None,
            },
            location: None,
            expires_at: None,
        })
        .await
        .unwrap();
    let spec = store
        .create_instance(InstanceSpec {
            id: InstanceId::new(),
            meta: meta(),
            name: "work".into(),
            profile_id: profile.id,
            dns_profile_id: None,
            security_profile_id: None,
            purpose: InstancePurpose::General,
            limits: InstanceLimits::default(),
            strict: false,
            transport: vpn_domain::TransportRef::default(),
        })
        .await
        .unwrap();
    store
        .change_intent(spec.id, IntentChange::Start)
        .await
        .unwrap();
    spec.id
}

fn marker(paths: &Paths, id: InstanceId) -> PathBuf {
    paths.state.join("pending-stops").join(id.to_string())
}

/// Another process holding the control database's write lock: every Store write fails (busy)
/// while reads go on — what a Store that cannot take a write looks like to the manager.
fn lock_writes(state: &Path) -> rusqlite::Connection {
    let c = rusqlite::Connection::open(state.join(vpn_store::CONTROL_FILE)).unwrap();
    c.busy_timeout(Duration::from_secs(5)).unwrap();
    c.execute_batch("BEGIN EXCLUSIVE").unwrap();
    c
}

fn fault(s: &InstanceStatus) -> Option<&str> {
    s.recovery.last_fault.as_ref().map(|f| f.code.as_str())
}

/// Wait (bounded) until the Instance's status satisfies `done`.
async fn eventually(
    manager: &Manager,
    id: InstanceId,
    what: &str,
    done: impl Fn(&InstanceStatus) -> bool,
) -> InstanceStatus {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let s = manager.status(id).await.unwrap();
        if done(&s) {
            return s;
        }
        assert!(tokio::time::Instant::now() < deadline, "{what}: {s:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Held for the user: closed, nothing started, the reason and the way out shown.
async fn held(manager: &Manager, id: InstanceId, emergency: bool) -> InstanceStatus {
    let s = eventually(manager, id, "held for the user's decision", |s| {
        s.phase == Phase::RecoveryRequired
    })
    .await;
    assert_eq!(fault(&s), Some(STOP_NOT_CONFIRMED), "{s:?}");
    let message = &s.recovery.last_fault.as_ref().unwrap().message.zh_tw;
    assert!(
        message.contains(if emergency {
            "解除急停"
        } else {
            "再確認一次停止"
        }),
        "{message}"
    );
    assert_eq!(s.enforcement, Enforcement::Blocked);
    assert_eq!(s.intent.emergency_latched, emergency);
    assert_eq!(s.intent.desired, DesiredState::Stopped);
    assert!(s.running.is_none());
    s
}

async fn wait_gone(path: &Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while path.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{} still there",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

const fn facts() -> SystemFacts {
    SystemFacts {
        ssh: None,
        capabilities: vec![],
        performance: None,
    }
}

#[test]
fn a_stop_whose_latch_never_reached_the_disk_survives_a_manager_crash() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let first = runtime();
    let (id, lock) = first.block_on(async {
        let id = running_instance(&paths).await;
        let store = open(&paths);
        let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
            .await
            .unwrap();
        eventually(&manager, id, "a start attempt", |s| {
            fault(s) == Some("WORKER_START")
        })
        .await;
        let sock = paths.manager_socket();
        tokio::spawn(serve(
            tokio::net::UnixListener::bind(&sock).unwrap(),
            manager.clone(),
            store.clone(),
            facts(),
        ));
        let controller = ControlClient::connect(&sock).await.unwrap();

        // The Store cannot take the latch: the emergency stop closes the Instance anyway and
        // says that its latch is not durable; its marker is on disk.
        let lock = lock_writes(&paths.state);
        let reply = controller
            .call(Call::Lifecycle(id, Lifecycle::Emergency))
            .await
            .unwrap();
        assert_matches!(
            reply,
            Reply::Stopped {
                sealed: true,
                durable: false
            }
        );
        assert!(marker(&paths, id).exists(), "the stop's marker is on disk");
        // Another owner restarts — a new controller connection — and finds the stop in force.
        drop(controller);
        let controller = ControlClient::connect(&sock).await.unwrap();
        let Reply::Status(s) = controller.call(Call::InstanceStatus(id)).await.unwrap() else {
            panic!("a status")
        };
        assert_eq!(
            (s.phase, s.enforcement),
            (Phase::Stopped, Enforcement::Blocked)
        );
        assert_eq!(s.intent.persistence, Persistence::Pending);
        assert!(s.intent.emergency_latched && s.intent.desired == DesiredState::Stopped);
        assert!(marker(&paths, id).exists());
        assert_eq!(
            store.intent(id).await.unwrap().desired,
            DesiredState::Running,
            "the latch is still not on disk"
        );
        (id, lock)
    });
    // The manager is killed: its tasks, the latch retry among them, end without any shutdown.
    first.shutdown_timeout(Duration::from_secs(5));
    // The Store could take writes again.
    drop(lock);

    let second = runtime();
    second.block_on(async {
        let store = open(&paths);
        assert_eq!(
            store.intent(id).await.unwrap().desired,
            DesiredState::Running,
            "the stored intent is the old one"
        );
        let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
            .await
            .unwrap();
        held(&manager, id, true).await;
        // And it stays so: nothing is attempted.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let s = held(&manager, id, true).await;
        assert_eq!(s.recovery.attempt, 0);
        assert!(marker(&paths, id).exists());

        // The emergency stands: Start is refused until it is cleared. Clearing it is the user's
        // decision "stopped", on disk.
        let refused = manager.start_instance(id).await.unwrap_err();
        assert_eq!(refused.code, ErrorCode::EmergencyLatched);
        manager.clear_emergency(id).await.unwrap();
        let s = eventually(&manager, id, "stopped", |s| s.phase == Phase::Stopped).await;
        assert_eq!(fault(&s), None);
        assert_eq!(s.intent.persistence, Persistence::Durable);
        assert!(!s.intent.emergency_latched && s.intent.manual_stop);
        assert!(!marker(&paths, id).exists());
        // Now an ordinary stopped Instance: Start runs it.
        manager.start_instance(id).await.unwrap();
        eventually(&manager, id, "a start attempt", |s| {
            fault(s) == Some("WORKER_START")
        })
        .await;
        manager.shutdown().await;
    });
}

#[test]
fn a_normal_exit_with_a_pending_stop_is_not_a_clean_one() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let first = runtime();
    let (id, lock) = first.block_on(async {
        let id = running_instance(&paths).await;
        let manager = Manager::start(open(&paths), not_a_worker(), paths.clone())
            .await
            .unwrap();
        eventually(&manager, id, "a start attempt", |s| {
            fault(s) == Some("WORKER_START")
        })
        .await;
        let lock = lock_writes(&paths.state);
        let o = manager.stop_instance(id, false).await.unwrap();
        assert!(o.sealed && !o.durable, "{o:?}");
        // The manager stops as on SIGTERM: one more attempt at the latch fails, so the stop's
        // marker stays.
        manager.shutdown().await;
        assert!(marker(&paths, id).exists());
        (id, lock)
    });
    // The process exits.
    first.shutdown_timeout(Duration::from_secs(5));
    drop(lock);

    let second = runtime();
    second.block_on(async {
        let store = open(&paths);
        let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
            .await
            .unwrap();
        held(&manager, id, false).await;
        // The user wants it running: written as a new intent, newer than the stop it overrides.
        let before = store.intent(id).await.unwrap();
        manager.start_instance(id).await.unwrap();
        eventually(&manager, id, "a start attempt", |s| {
            fault(s) == Some("WORKER_START")
        })
        .await;
        let after = store.intent(id).await.unwrap();
        assert_eq!(after.desired, DesiredState::Running);
        assert_eq!(after.intent_revision, before.intent_revision + 1);
        assert!(!marker(&paths, id).exists());
        manager.shutdown().await;
        drop(manager);
        // From now on a start trusts the stored intent again.
        let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
            .await
            .unwrap();
        eventually(&manager, id, "started from its intent", |s| {
            fault(s) == Some("WORKER_START")
        })
        .await;
        manager.shutdown().await;
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_recorded_only_as_an_operation_still_needs_the_users_decision() {
    // The previous manager recorded the user's stops as operations and died before their
    // latches: no marker, nothing in memory — only the records, one of them marked done (a stop
    // answers before its latch is on disk), one never finished.
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let id = running_instance(&paths).await;
    let store = open(&paths);
    let record = |kind: &'static str| {
        let store = store.clone();
        async move {
            let Begin::New(op) = store
                .begin_operation(kind.into(), Some(id.to_string()), None, None)
                .await
                .unwrap()
            else {
                panic!("a new operation")
            };
            op
        }
    };
    let done = record(OP_INSTANCE_STOP).await;
    store
        .finish_operation(
            done.id,
            OperationStatus::Succeeded,
            None,
            vec![id.to_string()],
        )
        .await
        .unwrap();
    let lost = record(OP_INSTANCE_EMERGENCY_STOP).await;

    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();
    held(&manager, id, true).await;
    assert_eq!(
        store.operation(lost.id).await.unwrap().unwrap().status,
        OperationStatus::Unknown
    );
    // The evidence is a marker now as well: it outlives the operations (pruned one day).
    assert!(marker(&paths, id).exists());
    // Another start without any memory of it holds it again.
    manager.shutdown().await;
    drop(manager);
    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();
    held(&manager, id, true).await;

    // The user confirms the emergency stop: on disk, the reason goes.
    let o = manager.stop_instance(id, true).await.unwrap();
    assert!(o.sealed && o.durable, "{o:?}");
    let s = eventually(&manager, id, "stopped", |s| s.phase == Phase::Stopped).await;
    assert_eq!(fault(&s), None);
    assert!(s.intent.emergency_latched && s.intent.persistence == Persistence::Durable);
    wait_gone(&marker(&paths, id)).await;
    manager.shutdown().await;
    drop(manager);
    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();
    let s = eventually(&manager, id, "stopped", |s| s.phase == Phase::Stopped).await;
    assert!(s.intent.emergency_latched);
    manager.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_on_disk_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    let id = running_instance(&paths).await;
    let store = open(&paths);
    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();
    eventually(&manager, id, "a start attempt", |s| {
        fault(s) == Some("WORKER_START")
    })
    .await;
    let o = manager.stop_instance(id, false).await.unwrap();
    assert!(o.sealed && o.durable, "{o:?}");
    wait_gone(&marker(&paths, id)).await;
    manager.shutdown().await;
    drop(manager);

    // A restart finds it stopped, as stored — no false alarm.
    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();
    let s = eventually(&manager, id, "stopped", |s| s.phase == Phase::Stopped).await;
    assert_eq!(fault(&s), None);
    manager.shutdown().await;
    drop(manager);

    // A marker left behind although its latch is on disk (a crash right between the two), and
    // one of an Instance that no longer exists: both removed, neither holds anything.
    let gone = InstanceId::new();
    std::fs::create_dir_all(paths.state.join("pending-stops")).unwrap();
    for i in [id, gone] {
        let text = serde_json::json!({
            "format": 1,
            "instance_id": i,
            "emergency": false,
            "written_at": Timestamp::now(),
            "manager_pid": 1,
        });
        std::fs::write(marker(&paths, i), text.to_string()).unwrap();
    }
    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();
    let s = eventually(&manager, id, "stopped", |s| s.phase == Phase::Stopped).await;
    assert_eq!(fault(&s), None);
    assert!(!marker(&paths, id).exists() && !marker(&paths, gone).exists());
    manager.shutdown().await;
}
