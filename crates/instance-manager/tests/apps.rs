//! Managed Apps through the real supervisor and launcher: real processes, real process tables,
//! real Seatbelt on macOS. The Instance never starts (its worker binary is `false`), but it holds
//! its Gateway's port from the start, which is what an App needs. Network probes only reach
//! loopback and TEST-NET-1 (192.0.2.1, never routed); the "private" file is a fake in the test's
//! own state directory.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use vpn_domain::*;
use vpn_instance_manager::Manager;
use vpn_platform::apps::proc;
use vpn_platform::paths::Paths;
use vpn_store::Store;
use zeroize::Zeroizing;

fn meta() -> EntityMeta {
    EntityMeta {
        revision: 1,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn not_a_worker() -> PathBuf {
    ["/usr/bin/false", "/bin/false"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .unwrap()
}

struct Lab {
    paths: Paths,
    store: Arc<Store>,
    manager: Arc<Manager>,
    instance: InstanceId,
    gateway: GatewaySpec,
}

/// A store with one (stopped) Instance and one enabled Mixed Gateway on `port`, created when the
/// state directory is new, and a manager on it.
async fn lab(paths: &Paths, port: u16) -> Lab {
    paths.ensure().unwrap();
    let store = Arc::new(Store::open(&paths.state, &Zeroizing::new([4u8; 32]), 1).unwrap());
    let (instance, gateway) = if let Some(i) = store.list::<InstanceSpec>().await.unwrap().first() {
        (i.id, store.list::<GatewaySpec>().await.unwrap()[0].clone())
    } else {
        let key = store
            .put_secret("k".into(), None, Zeroizing::new(vec![1; 32]), None)
            .await
            .unwrap();
        let wg = WgKey::from_str("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=").unwrap();
        let profile = store
            .create(RuntimeProfile {
                id: ProfileId::new(),
                meta: meta(),
                name: "lab".into(),
                provider: ProviderKind::Generic,
                source: ProfileSource::Imported,
                interface: InterfaceSpec {
                    private_key: key.secret_ref,
                    public_key: wg,
                    addresses: vec!["10.99.0.2/32".parse().unwrap()],
                    dns: vec!["10.99.0.1".parse().unwrap()],
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
        let instance = store
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
        let gateway = store
            .create(GatewaySpec {
                id: GatewayId::new(),
                meta: meta(),
                instance_id: instance.id,
                name: "browser".into(),
                kind: GatewayKind::Mixed,
                port,
                enabled: true,
                udp: false,
                max_connections: 16,
            })
            .await
            .unwrap();
        (instance.id, gateway)
    };
    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();
    Lab {
        paths: paths.clone(),
        store,
        manager,
        instance,
        gateway,
    }
}

impl Lab {
    fn spec(&self, isolation: AppIsolation, executable: &str, args: &[&str]) -> AppSpec {
        AppSpec {
            id: AppId::new(),
            meta: meta(),
            instance_id: self.instance,
            name: "probe".into(),
            executable: executable.into(),
            args: args.iter().map(std::string::ToString::to_string).collect(),
            working_dir: None,
            env: vec![EnvVar {
                name: "PROBE".into(),
                value: "1".into(),
            }],
            isolation,
            gateway_id: (isolation != AppIsolation::StrictNetns).then_some(self.gateway.id),
            restart_on_recovery: false,
            writable_paths: Vec::new(),
            confine_writes: false,
            stop_grace_secs: 10,
            approval: None,
            limits: AppLimits::default(),
            access_ports: Vec::new(),
        }
    }

    async fn create(&self, spec: AppSpec) -> AppSpec {
        self.manager.apps().create(spec, None).await.unwrap()
    }

    async fn act(&self, id: AppId, action: AppAction) -> Result<AppStatus, ApiError> {
        self.manager
            .apps()
            .action(&self.manager, id, action, None)
            .await
    }

    async fn status(&self, id: AppId) -> AppStatus {
        self.manager.apps().status(id).await.unwrap()
    }

    /// Wait (bounded) until the App's status satisfies `done`.
    async fn until(&self, id: AppId, what: &str, done: impl Fn(&AppStatus) -> bool) -> AppStatus {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let s = self.status(id).await;
            if done(&s) {
                return s;
            }
            assert!(tokio::time::Instant::now() < deadline, "{what}: {s:?}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn log(&self, id: AppId) -> String {
        self.manager
            .apps()
            .log(id, 200)
            .await
            .unwrap()
            .lines
            .join("\n")
    }

    /// Stop and delete, removing the App's private directories (some live in /private/tmp).
    async fn remove(&self, app: &AppSpec) {
        let _ = self.act(app.id, AppAction::Stop).await;
        let rev = self
            .store
            .get::<AppSpec>(app.id.to_string())
            .await
            .unwrap()
            .unwrap()
            .meta
            .revision;
        self.manager.apps().delete(app.id, rev).await.unwrap();
        let ids = app.id.to_string();
        assert!(!self.paths.app_dir(&ids).exists());
        assert!(!self.paths.app_tmp(&ids).exists());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_executable_is_refused_until_the_user_approves_it() {
    let dir = tempfile::tempdir().unwrap();
    let lab = lab(&Paths::under(dir.path()), free_port()).await;
    let bin = tempfile::tempdir().unwrap();
    std::fs::set_permissions(bin.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let tool = bin.path().join("tool");
    std::fs::write(&tool, "#!/bin/sh\nsleep 300\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = tool.to_str().unwrap();
    let app = lab
        .create(lab.spec(AppIsolation::ProxyEnv, path, &[]))
        .await;
    let approval = app.approval.clone().unwrap();
    assert_eq!(
        approval.path,
        tool.canonicalize().unwrap().to_str().unwrap()
    );

    // Replaced after approval: refused, with the reason on the App.
    std::fs::write(&tool, "#!/bin/sh\necho different; sleep 300\n").unwrap();
    let err = lab.act(app.id, AppAction::Start).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::AppArtifactDigestMismatch, "{err}");
    let s = lab.status(app.id).await;
    assert_eq!(s.state, AppRunState::Failed);
    assert_eq!(
        s.last_error.as_ref().map(|f| f.code.as_str()),
        Some("APP_ARTIFACT_DIGEST_MISMATCH")
    );
    assert!(s.pid.is_none());

    // Approving needs the digest the user saw; a different one is refused.
    let check = lab
        .manager
        .apps()
        .check_executable(path.into())
        .await
        .unwrap();
    assert!(check.ok);
    let new_sha = check.sha256.unwrap();
    assert_ne!(new_sha, approval.sha256);
    let wrong = lab
        .manager
        .apps()
        .action(
            &lab.manager,
            app.id,
            AppAction::Approve,
            Some(approval.sha256.clone()),
        )
        .await
        .unwrap_err();
    assert_eq!(wrong.code, ErrorCode::AppArtifactDigestMismatch);
    let s = lab
        .manager
        .apps()
        .action(
            &lab.manager,
            app.id,
            AppAction::Approve,
            Some(new_sha.clone()),
        )
        .await
        .unwrap();
    assert!(s.last_error.is_none() && s.state == AppRunState::Stopped);
    let stored: AppSpec = lab.store.get(app.id.to_string()).await.unwrap().unwrap();
    assert_eq!(stored.approval.unwrap().sha256, new_sha);
    assert_eq!(stored.meta.revision, 2);

    let s = lab.act(app.id, AppAction::Start).await.unwrap();
    assert_eq!(s.state, AppRunState::Running);
    let first = proc::identity(s.pid.unwrap()).unwrap();
    // Restart: a new tree replaces the old one.
    let again = lab.act(app.id, AppAction::Restart).await.unwrap();
    assert_eq!(again.state, AppRunState::Running);
    assert_ne!(again.pid, s.pid);
    assert!(!proc::is_alive(first), "the old tree is gone");
    lab.remove(&app).await;
}

/// macOS Seatbelt: the App reaches its Gateway and nothing else, cannot read VPN Manager's data,
/// and can write its own home.
#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_enforced_app_reaches_only_its_gateway() {
    let dir = tempfile::tempdir().unwrap();
    let lab = lab(&Paths::under(dir.path()), free_port()).await;
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let secret = lab.paths.state.join("fake-vault.key");
    std::fs::write(&secret, "not a real key").unwrap();
    let gw = lab.gateway.port;
    let script = format!(
        "nc -vz -G 3 127.0.0.1 {gw} >/dev/null 2>&1 && echo GATEWAY_OK
nc -vz -G 3 127.0.0.1 {other} 2>&1 | grep -q 'not permitted' && echo OTHER_DENIED
nc -vz -G 3 192.0.2.1 443 2>&1 | grep -q 'not permitted' && echo TESTNET_DENIED
cat '{secret}' 2>&1 | grep -q 'not permitted' && echo DATA_DENIED
touch \"$HOME/w\" && echo HOME_WRITABLE
echo \"PROXY=$ALL_PROXY\"
exit 0",
        other = other.local_addr().unwrap().port(),
        secret = secret.display(),
    );
    let app = lab
        .create(lab.spec(AppIsolation::EnforcedProxy, "/bin/sh", &["-c", &script]))
        .await;
    let s = lab.act(app.id, AppAction::Start).await.unwrap();
    assert_eq!(s.isolation, Some(AppIsolation::EnforcedProxy));
    assert_eq!(s.sandbox_denials, Some(0), "counted from the start");
    let s = lab
        .until(app.id, "the probe script ends", |s| {
            s.state == AppRunState::Stopped
        })
        .await;
    assert_eq!(s.last_exit.as_ref().and_then(|e| e.code), Some(0));
    assert_eq!(
        s.last_error.as_ref().map(|f| f.code.as_str()),
        Some("APP_EXITED")
    );
    let log = lab.log(app.id).await;
    for line in [
        "GATEWAY_OK",
        "OTHER_DENIED",
        "TESTNET_DENIED",
        "DATA_DENIED",
        "HOME_WRITABLE",
    ] {
        assert!(log.contains(line), "{line} missing:\n{log}");
    }
    assert!(
        log.contains(&format!("PROXY=socks5h://127.0.0.1:{gw}")),
        "{log}"
    );
    lab.remove(&app).await;
}

/// Seatbelt cannot refuse a wildcard bind: the watcher stops the App within a few seconds and
/// says where it listened; a loopback listener is fine.
#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_enforced_app_listening_beyond_loopback_is_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let lab = lab(&Paths::under(dir.path()), free_port()).await;
    let local = free_port();
    let quiet = lab
        .create(lab.spec(
            AppIsolation::EnforcedProxy,
            "/usr/bin/nc",
            &["-l", "127.0.0.1", &local.to_string()],
        ))
        .await;
    lab.act(quiet.id, AppAction::Start).await.unwrap();
    let s = lab
        .until(quiet.id, "loopback listener seen", |s| {
            s.listeners.as_ref().is_some_and(|l| !l.is_empty())
        })
        .await;
    let listeners = s.listeners.unwrap();
    assert!(listeners.iter().all(|l| l.loopback), "{listeners:?}");
    assert!(
        listeners
            .iter()
            .any(|l| l.address == format!("127.0.0.1:{local}"))
    );

    let wild = free_port();
    let exposed = lab
        .create(lab.spec(
            AppIsolation::EnforcedProxy,
            "/usr/bin/nc",
            &["-l", &wild.to_string()],
        ))
        .await;
    let started = lab.act(exposed.id, AppAction::Start).await.unwrap();
    let s = lab
        .until(exposed.id, "stopped for its listener", |s| {
            s.state == AppRunState::Failed
        })
        .await;
    let why = s.last_error.unwrap();
    assert_eq!(why.code, "APP_LISTENER_NOT_LOOPBACK");
    assert!(
        why.message.zh_tw.contains(&format!(":{wild}")),
        "{}",
        why.message.zh_tw
    );
    assert!(proc::info(started.pid.unwrap()).is_none_or(|i| i.zombie));
    // The user's intent is untouched: it was a fault, not a stop by the user.
    assert_eq!(s.desired, DesiredState::Running);
    // The loopback one still runs.
    assert_eq!(lab.status(quiet.id).await.state, AppRunState::Running);
    lab.remove(&quiet).await;
    lab.remove(&exposed).await;
}

/// This host's address towards the outside (no packet is sent), when it has one.
#[cfg(target_os = "macos")]
fn lan_ip() -> Option<std::net::IpAddr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("192.0.2.1:9").ok()?;
    let ip = probe.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// Seatbelt lets an App accept a connection from the network on a wildcard listener. One that
/// accepts a single connection and closes its listener at once leaves no listener for the watch,
/// but keeps a direct two-way channel: the connection itself gets the App stopped. (Its listener
/// lives a few milliseconds; should a pass see it first, the App is stopped for the listener,
/// which is as good.)
#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_enforced_app_holding_a_connection_from_the_network_is_stopped() {
    let Some(lan) = lan_ip() else {
        eprintln!("no non-loopback address on this host: skipped");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let lab = lab(&Paths::under(dir.path()), free_port()).await;
    let port = free_port();
    // Listen on 0.0.0.0, accept one connection, close the listener, answer, keep the channel.
    let script = "my $l = IO::Socket::INET->new(LocalAddr => '0.0.0.0', LocalPort => $ARGV[0], \
                  Listen => 1, ReuseAddr => 1) or die \"listen: $!\"; \
                  my $c = $l->accept or die \"accept: $!\"; close $l; \
                  $c->autoflush(1); print $c \"out\\n\"; sleep 300;";
    let app = lab
        .create(lab.spec(
            AppIsolation::EnforcedProxy,
            "/usr/bin/perl",
            &["-MIO::Socket::INET", "-e", script, &port.to_string()],
        ))
        .await;
    let started = lab.act(app.id, AppAction::Start).await.unwrap();
    // From this host's LAN address, as another host on the LAN would: as soon as it listens.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut conn = loop {
        match tokio::net::TcpStream::connect((lan, port)).await {
            Ok(c) => break c,
            Err(e) => assert!(tokio::time::Instant::now() < deadline, "{e}"),
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    };
    // The channel works both ways (what Seatbelt allows).
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    conn.write_all(b"in\n").await.unwrap();
    let mut got = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut got))
        .await
        .expect("the App answers")
        .unwrap();
    assert_eq!(&got, b"out\n");
    let s = lab
        .until(app.id, "stopped for its connection", |s| {
            s.state == AppRunState::Failed
        })
        .await;
    let why = s.last_error.unwrap();
    match why.code.as_str() {
        "APP_CONNECTION_NOT_LOOPBACK" => assert!(
            why.message.zh_tw.contains(&format!("{lan}:{port}")),
            "{}",
            why.message.zh_tw
        ),
        "APP_LISTENER_NOT_LOOPBACK" => {}
        other => panic!("{other}: {}", why.message),
    }
    assert!(proc::info(started.pid.unwrap()).is_none_or(|i| i.zombie));
    assert_eq!(s.desired, DesiredState::Running);
    drop(conn);
    lab.remove(&app).await;
}

/// Wait (bounded) until `p` is gone; whether it went.
#[cfg(target_os = "macos")]
async fn gone(p: proc::ProcessIdentity, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while proc::is_alive(p) {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    true
}

/// The recovery report lists a running App's tree among the manager's own resources, never as
/// something to clean up, and a reconcile leaves it running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_lists_a_running_app_as_owned_and_leaves_it_alone() {
    let dir = tempfile::tempdir().unwrap();
    let lab = lab(&Paths::under(dir.path()), free_port()).await;
    let app = lab
        .create(lab.spec(AppIsolation::ProxyEnv, "/bin/sleep", &["300"]))
        .await;
    let s = lab.act(app.id, AppAction::Start).await.unwrap();
    let pid = s.pid.unwrap();
    let root = proc::identity(pid).unwrap();

    let report = vpn_instance_manager::recovery::inspect(&lab.manager, &lab.store, None)
        .await
        .report();
    assert_eq!(report.resources.apps.len(), 1, "{:?}", report.resources);
    let owned = &report.resources.apps[0];
    assert_eq!(
        (owned.app_id, owned.pid, owned.state),
        (app.id, pid, AppRunState::Running)
    );
    assert!(
        report.items.iter().all(|i| i.pid != Some(pid)),
        "{:?}",
        report.items
    );

    let result =
        vpn_instance_manager::recovery::reconcile(&lab.manager, &lab.store, None, None).await;
    assert!(
        result
            .actions
            .iter()
            .all(|a| a.kind != Some(RecoveryKind::AppLeftover)),
        "{:?}",
        result.actions
    );
    assert!(proc::is_alive(root));
    assert_eq!(lab.status(app.id).await.state, AppRunState::Running);
    lab.remove(&app).await;
}

/// A Stop gives the App its own grace (`stop_grace_secs`) after SIGTERM: an App that saves
/// within it ends by itself with its data written; one that needs longer is killed when its
/// grace is over — never earlier (a wallet or a database cut off mid-save is damaged).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_waits_for_the_apps_own_grace() {
    let dir = tempfile::tempdir().unwrap();
    let lab = lab(&Paths::under(dir.path()), free_port()).await;
    let bin = bin_dir();
    // Saves for $SAVE_SECS when told to stop, writes $SAVED_TO, exits 0. No child processes: the
    // stop's SIGTERM reaches it once.
    let saver = script(
        bin.path(),
        "saver",
        "#!/usr/bin/python3\n\
         import os, signal, sys, time\n\
         def save(*_):\n    \
             time.sleep(float(os.environ['SAVE_SECS']))\n    \
             open(os.environ['SAVED_TO'], 'w').write('saved')\n    \
             sys.exit(0)\n\
         signal.signal(signal.SIGTERM, save)\n\
         while True:\n    \
             time.sleep(0.1)\n",
    );
    // (case, grace, seconds the save takes, saved)
    let cases = [
        ("saves within its grace", 4, "1", true),
        ("needs longer than its grace", 1, "4", false),
    ];
    for (case, grace, save, saved) in cases {
        let saved_to = dir.path().join(format!("saved-{grace}"));
        let mut spec = lab.spec(AppIsolation::ProxyEnv, saver.to_str().unwrap(), &[]);
        spec.stop_grace_secs = grace;
        spec.env = vec![
            EnvVar {
                name: "SAVE_SECS".into(),
                value: save.into(),
            },
            EnvVar {
                name: "SAVED_TO".into(),
                value: saved_to.to_str().unwrap().into(),
            },
        ];
        let app = lab.create(spec).await;
        lab.act(app.id, AppAction::Start).await.unwrap();
        // The handler is in place once Python runs the loop.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let asked = std::time::Instant::now();
        let s = lab.act(app.id, AppAction::Stop).await.unwrap();
        let took = asked.elapsed();
        assert_eq!(s.state, AppRunState::Stopped, "{case}: {s:?}");
        assert_eq!(saved_to.exists(), saved, "{case}: took {took:?}");
        // Saved: once the save was done. Killed: at its grace, not before.
        let at_least = if saved { 1 } else { grace };
        assert!(
            took >= Duration::from_secs(u64::from(at_least)) && took < Duration::from_secs(4),
            "{case}: took {took:?}"
        );
        lab.remove(&app).await;
    }
}

/// `body` as an executable file `name` in `dir`.
fn script(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// A private directory for programs the tests run (an executable may live in no directory
/// others can write).
fn bin_dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

/// A fake program recognised by its macOS bundle identifier `id` (a bundle `<name>.app` whose
/// main executable is `body`) or, elsewhere, by its file name `file`. Returns the path an App
/// names and the file that runs.
fn fake_program(
    dir: &std::path::Path,
    name: &str,
    id: &str,
    file: &str,
    body: &str,
) -> (PathBuf, PathBuf) {
    if cfg!(target_os = "macos") {
        let bundle = dir.join(format!("{name}.app"));
        let exe_dir = bundle.join("Contents/MacOS");
        std::fs::create_dir_all(&exe_dir).unwrap();
        std::fs::write(
            bundle.join("Contents/Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>{name}</string><key>CFBundleIdentifier</key><string>{id}</string></dict></plist>
"#
            ),
        )
        .unwrap();
        let exe = script(&exe_dir, name, body);
        (bundle, exe)
    } else {
        let exe = script(dir, file, body);
        (exe.clone(), exe)
    }
}

/// A stand-in for a browser: one instance per data directory (`--user-data-dir`, by default one
/// shared directory). A start on a directory whose instance runs hands its arguments to that
/// instance and exits 0 — what Chrome does when the user's own copy already runs.
fn fake_browser(default_dir: &std::path::Path) -> String {
    format!(
        r#"#!/bin/sh
dir='{}'
for a in "$@"; do
  case "$a" in --user-data-dir=*) dir="${{a#--user-data-dir=}}" ;; esac
done
mkdir -p "$dir"
if [ -f "$dir/instance" ] && kill -0 "$(cat "$dir/instance")" 2>/dev/null; then
  echo "$*" >> "$dir/handed-over"
  echo "handed over to $(cat "$dir/instance")"
  exit 0
fi
echo $$ > "$dir/instance"
echo "own instance in $dir"
exec sleep 300
"#,
        default_dir.display()
    )
}

/// Wait (bounded) for `path` to exist.
async fn exists(path: &std::path::Path) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        if tokio::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

/// AC-19: with the user's own copy of the browser running, a managed one is started with a data
/// directory of its own inside its private home and runs as a separate instance; started on the
/// default directory, the same program hands over and exits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_browser_runs_as_its_own_instance_beside_the_users() {
    let dir = tempfile::tempdir().unwrap();
    let lab = lab(&Paths::under(dir.path()), free_port()).await;
    let bin = bin_dir();
    let default_dir = bin.path().join("default-profile");
    let (path, exe) = fake_program(
        bin.path(),
        "Chromium",
        "org.chromium.Chromium",
        "chromium",
        &fake_browser(&default_dir),
    );
    let check = lab
        .manager
        .apps()
        .check_executable(path.to_str().unwrap().into())
        .await
        .unwrap();
    assert!(check.ok, "{:?}", check.issues);
    assert_eq!(check.app_class.map(|c| c.class), Some(AppClass::Chromium));

    // The user's own browser, on the default data directory.
    let mut host = std::process::Command::new(&exe)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert!(exists(&default_dir.join("instance")).await);
    // Started again on that directory, the program hands over and exits 0.
    let again = std::process::Command::new(&exe)
        .arg("https://example.com/direct")
        .output()
        .unwrap();
    assert!(again.status.success());
    assert!(String::from_utf8_lossy(&again.stdout).contains("handed over to"));
    let handed = || std::fs::read_to_string(default_dir.join("handed-over")).unwrap_or_default();
    assert_eq!(handed().lines().count(), 1);

    // A data directory the App names itself is refused: the launcher's must stay in force.
    let own_dir = format!("--user-data-dir={}", default_dir.display());
    let refused = lab
        .manager
        .apps()
        .create(
            lab.spec(AppIsolation::ProxyEnv, path.to_str().unwrap(), &[&own_dir]),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(refused.code, ErrorCode::ValidationFailed);
    assert_eq!(refused.field_errors[0].code, "APP_PROFILE_ARG");
    assert_eq!(refused.field_errors[0].path, "/args/0");

    let app = lab
        .create(lab.spec(
            AppIsolation::ProxyEnv,
            path.to_str().unwrap(),
            &["https://example.com/managed"],
        ))
        .await;
    // Approved as what it is.
    assert_eq!(
        app.approval
            .as_ref()
            .and_then(|a| a.app_class.as_ref())
            .map(|c| c.class),
        Some(AppClass::Chromium)
    );
    let s = lab.act(app.id, AppAction::Start).await.unwrap();
    assert_eq!(s.state, AppRunState::Running);
    let data_dir = lab
        .paths
        .app_home(&app.id.to_string())
        .join("chromium-data");
    assert!(
        exists(&data_dir.join("instance")).await,
        "{}",
        lab.log(app.id).await
    );
    // The App's output reaches its log through the manager's pump: wait for the line.
    let said = format!("own instance in {}", data_dir.display());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut log = lab.log(app.id).await;
    while !log.contains(&said) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        log = lab.log(app.id).await;
    }
    assert!(log.contains(&said), "{log}");
    // Past the handoff window it still runs, and nothing reached the user's browser.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(lab.status(app.id).await.state, AppRunState::Running);
    assert_eq!(handed().lines().count(), 1, "{}", handed());
    lab.remove(&app).await;
    assert!(
        host.try_wait().unwrap().is_none(),
        "the user's browser is untouched"
    );
    host.kill().unwrap();
    host.wait().unwrap();
}

/// AC-19: a start that exits 0 at once while the same program runs outside the App's tree is a
/// failure that says so (the start most likely went to that unprotected process), never "exited
/// normally"; the other process is never signalled. Without one, the same exit is ordinary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_handed_to_a_running_instance_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let lab = lab(&Paths::under(dir.path()), free_port()).await;
    let bin = bin_dir();
    let other = bin_dir();
    // Ends at once, as a program that handed its start over does.
    let (path, exe) = fake_program(
        bin.path(),
        "Viewer",
        "com.example.viewer",
        "chromium",
        "#!/bin/sh\necho handing over\nexit 0\n",
    );
    // The instance that already runs: another file of the same bundle (macOS) or a script of
    // the same name (elsewhere, where the OS names a script's process by its file).
    let mut host = if cfg!(target_os = "macos") {
        // A copy of a system program inside a bundle is killed for its Apple signature; signed
        // ad hoc it runs.
        let helper = exe.with_file_name("Viewer Helper");
        std::fs::copy("/bin/sleep", &helper).unwrap();
        let signed = std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(&helper)
            .output()
            .unwrap();
        assert!(signed.status.success(), "{signed:?}");
        std::process::Command::new(helper)
            .arg("300")
            .spawn()
            .unwrap()
    } else {
        let host = script(
            other.path(),
            "chromium",
            "#!/bin/sh\nwhile :; do sleep 1; done\n",
        );
        std::process::Command::new(host).spawn().unwrap()
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let class = lab
        .manager
        .apps()
        .check_executable(path.to_str().unwrap().into())
        .await
        .unwrap()
        .app_class
        .unwrap();
    if cfg!(target_os = "macos") {
        assert_eq!(class.class, AppClass::Gui);
        // A macOS app is never run as if Seatbelt confined it.
        let refused = lab
            .manager
            .apps()
            .create(
                lab.spec(AppIsolation::EnforcedProxy, path.to_str().unwrap(), &[]),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(refused.field_errors[0].code, "APP_GUI_NOT_ENFORCEABLE");
        assert!(
            refused.message.zh_tw.contains("不保證流量經過 VPN"),
            "{}",
            refused.message.zh_tw
        );
    } else {
        assert_eq!(class.class, AppClass::Chromium);
    }

    let app = lab
        .create(lab.spec(AppIsolation::ProxyEnv, path.to_str().unwrap(), &[]))
        .await;
    lab.act(app.id, AppAction::Start).await.unwrap();
    let s = lab
        .until(app.id, "reported as handed over", |s| {
            s.state == AppRunState::Failed
        })
        .await;
    assert_eq!(s.last_exit.as_ref().and_then(|e| e.code), Some(0));
    let why = s.last_error.unwrap();
    assert_eq!(why.code, "APP_HANDOFF", "{}", why.message.zh_tw);
    assert!(
        why.message.zh_tw.contains(&format!("pid {}", host.id())),
        "{}",
        why.message.zh_tw
    );
    assert!(host.try_wait().unwrap().is_none(), "never signalled");

    // With nothing else running it, exiting 0 at once is an ordinary end.
    host.kill().unwrap();
    host.wait().unwrap();
    lab.act(app.id, AppAction::Start).await.unwrap();
    let s = lab
        .until(app.id, "an ordinary end", |s| {
            s.state == AppRunState::Stopped
        })
        .await;
    assert_eq!(
        s.last_error.as_ref().map(|f| f.code.as_str()),
        Some("APP_EXITED")
    );
    lab.remove(&app).await;
}
