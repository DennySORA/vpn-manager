//! A tree an earlier manager left running that could not be confirmed ended: the supervisor
//! keeps it (no second tree, no delete), the recovery report shows it as an App leftover — never
//! as a leftover worker — and a stop or a reconcile ends it, identity-checked.

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command};

use vpn_store::AppRunRecord;
use zeroize::Zeroizing;

use super::*;
use vpn_domain::{
    AccessBind, AppAccessPort, EntityMeta, InstanceLimits, InstancePurpose, InterfaceSpec,
    PeerSpec, ProfileId, ProfileSource, ProviderKind, RuntimeProfile, WgKey,
};

fn meta() -> EntityMeta {
    EntityMeta {
        revision: 1,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
}

/// The (never started) Instance the Apps belong to.
async fn instance(store: &Store) -> InstanceId {
    use std::str::FromStr;
    let key = store
        .put_secret("k".into(), None, Zeroizing::new(vec![1; 32]), None)
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
                dns: vec![],
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
    store
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
        .unwrap()
        .id
}

fn spec(instance_id: InstanceId) -> AppSpec {
    AppSpec {
        id: AppId::new(),
        meta: meta(),
        instance_id,
        name: "leftover".into(),
        executable: "/bin/sleep".into(),
        args: vec!["300".into()],
        working_dir: None,
        env: Vec::new(),
        isolation: AppIsolation::ProxyEnv,
        gateway_id: None,
        restart_on_recovery: true,
        writable_paths: Vec::new(),
        confine_writes: false,
        stop_grace_secs: 10,
        approval: None,
        limits: AppLimits::default(),
        access_ports: Vec::new(),
    }
}

/// A `sleep` in its own process group, as the launcher starts an App.
fn sleeper() -> (Child, ProcessIdentity) {
    let child = Command::new("/bin/sleep")
        .arg("300")
        .process_group(0)
        .spawn()
        .unwrap();
    let root = proc::identity(child.id()).unwrap();
    (child, root)
}

/// Only a quick exit of a program that can hand its start over is taken for a handoff; a
/// launcher's always is one (what it starts is never its child).
#[tokio::test]
async fn only_a_quick_exit_of_a_program_that_can_hand_off_is_checked() {
    let root = ProcessIdentity {
        pid: std::process::id(),
        started_us: proc::now_start_us(),
    };
    let probe = |class: Option<AppClass>, started: Instant| HandoffProbe {
        class: class.map(|class| AppClassInfo {
            class,
            name: "open".into(),
            bundle_id: None,
        }),
        program: "/nonexistent/vpnm-probe".into(),
        bundle: None,
        started,
    };
    let check = |p: HandoffProbe| {
        handed_off(
            p,
            proc::Tree::new(),
            root,
            Arc::new(Mutex::new(proc::RunMarker::new("t", None))),
            None,
        )
    };
    let now = Instant::now();
    let f = check(probe(Some(AppClass::Launcher), now)).await.unwrap();
    assert_eq!(f.code, "APP_HANDOFF");
    assert!(f.message.zh_tw.contains("「open」"), "{}", f.message.zh_tw);
    // Long after the start, an ordinary program, or nothing else running the program: no.
    if let Some(late) = now.checked_sub(HANDOFF_WINDOW + Duration::from_secs(1)) {
        assert!(check(probe(Some(AppClass::Launcher), late)).await.is_none());
    }
    assert!(check(probe(None, now)).await.is_none());
    assert!(check(probe(Some(AppClass::Gui), now)).await.is_none());
    assert!(check(probe(Some(AppClass::Chromium), now)).await.is_none());
}

/// After a restart the manager finds a run record: a run of this boot is stopped (its pid and
/// start time still name it), a run recorded in another boot is gone whatever process holds that
/// pid and start time now, and is never signalled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_trusts_a_run_record_only_in_the_boot_that_wrote_it() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    paths.ensure().unwrap();
    let store = Arc::new(Store::open(&paths.state, &Zeroizing::new([5u8; 32]), 1).unwrap());
    let manager = Manager::start(store.clone(), "/usr/bin/false".into(), paths.clone())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let apps = manager.apps();
    let owner = instance(&store).await;
    let Some(this_boot) = proc::boot_id() else {
        manager.shutdown().await;
        return;
    };

    let mut ids = Vec::new();
    let mut children = Vec::new();
    for boot in [format!("{this_boot}-earlier"), this_boot] {
        let (child, root) = sleeper();
        let mut s = spec(owner);
        s.restart_on_recovery = false;
        let app = store.create_app(s).await.unwrap();
        store
            .set_app_desired(app.id, DesiredState::Running)
            .await
            .unwrap();
        store
            .set_app_run(
                app.id,
                Some(AppRunRecord {
                    run_id: "earlier".into(),
                    pid: root.pid,
                    started_us: root.started_us,
                    boot_id: Some(boot),
                    backend: "plain".into(),
                    revision: 1,
                    gateway_port: None,
                    started_at: Timestamp::now(),
                }),
            )
            .await
            .unwrap();
        ids.push(app.id);
        children.push((child, root));
    }
    for id in &ids {
        let row = store.app_intent(*id).await.unwrap();
        Arc::clone(apps)
            .recover_one(Arc::downgrade(&manager), row)
            .await;
        assert!(store.app_intent(*id).await.unwrap().run.is_none());
        assert_eq!(apps.status(*id).await.unwrap().state, AppRunState::Stopped);
    }
    let (mut other_boot, foreign_root) = children.remove(0);
    let (mut this_boot, _) = children.remove(0);
    assert!(
        proc::is_alive(foreign_root),
        "a process that only shares the pid and start time of another boot's run is not ours"
    );
    assert!(
        this_boot.wait().unwrap().signal().is_some(),
        "this boot's run is stopped"
    );
    other_boot.kill().unwrap();
    other_boot.wait().unwrap();
    manager.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Local access ports
// ---------------------------------------------------------------------------------------------

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A strict App (never started here) publishing its port 17890 on `host_port`.
fn strict_app(instance_id: InstanceId, host_port: u16) -> AppSpec {
    AppSpec {
        name: "p2p".into(),
        isolation: AppIsolation::StrictNetns,
        access_ports: vec![AppAccessPort {
            app_port: 17890,
            host_port,
            bind: AccessBind::Loopback,
            allow: Vec::new(),
        }],
        ..spec(instance_id)
    }
}

/// One HTTP request; everything that came back before the server closed.
async fn ask(port: u16) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    // A server that refuses the client may close before it reads the request (the write fails)
    // and reset the connection (the read fails): what came back until then is the answer.
    if let Err(e) = s
        .write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
    {
        eprintln!("request not sent whole: {e}");
    }
    let mut out = Vec::new();
    match tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => eprintln!("answer cut short: {e}"),
        Err(_elapsed) => eprintln!("the server did not close within 10 s"),
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A host whose every client socket belongs to another user.
struct OtherUser;

impl vpn_platform::admission::HostView for OtherUser {
    fn owner(
        &self,
        _local: std::net::SocketAddr,
        _peer: std::net::SocketAddr,
    ) -> std::io::Result<Option<vpn_platform::peer::PeerOwner>> {
        Ok(Some(vpn_platform::peer::PeerOwner {
            uid: vpn_platform::process::current_uid().wrapping_add(1),
            pid: Some(4242),
        }))
    }

    fn is_own_address(&self, _ip: std::net::IpAddr) -> std::io::Result<bool> {
        Ok(true)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_users_client_is_closed_unread_and_counted() {
    let ports = Arc::new(AccessPorts::new(Weak::new(), Arc::new(OtherUser)));
    let host_port = free_port();
    let app = strict_app(InstanceId::new(), host_port);
    ports.sync(std::slice::from_ref(&app)).await;
    for _ in 0..100 {
        if ports
            .status(app.id, None)
            .first()
            .is_some_and(|p| p.listening)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Refused before anything is read: not even told why.
    assert_eq!(ask(host_port).await, "");
    let mut status = ports.status(app.id, None);
    for _ in 0..100 {
        if status[0].refused == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        status = ports.status(app.id, None);
    }
    assert_eq!(status[0].refused, 1);
    let why = status[0].last_refused.as_ref().unwrap();
    assert_eq!(why.code, "ACCESS_REFUSED");
    assert!(
        why.message.zh_tw.contains("其他使用者"),
        "{}",
        why.message.zh_tw
    );
    ports.shutdown();
}
