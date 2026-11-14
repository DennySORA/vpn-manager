//! Rootless sandbox tests (Linux). This binary is also the sandbox holder: the sandbox is built
//! by re-executing it with `sandbox-holder` (like `vpnd sandbox-holder`), which is why it has no
//! test harness — `unshare(CLONE_NEWUSER)` must run before any thread exists.
//!
//! Nothing here needs root or changes the host: every namespace, mount and device lives in the
//! sandbox and is gone when its holder exits, which each test verifies.
#![allow(
    unsafe_code,
    reason = "the sandbox test binary inspects fds and signals the holder via fcntl/read/kill"
)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures: clippy.toml allows unwrap/expect in #[test] fns, not in the helper fns of a tests/ crate"
)]

#[cfg(not(target_os = "linux"))]
fn main() {
    if std::env::args().nth(1).as_deref() == Some("sandbox-holder") {
        std::process::exit(2);
    }
    println!("sandbox tests: Linux only, skipped");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().nth(1).as_deref() == Some("sandbox-holder") {
        std::process::exit(vpn_platform::sandbox::run_holder());
    }
    if std::env::args().nth(1).as_deref() == Some(vpn_platform::sandbox::APP_ROLE) {
        std::process::exit(vpn_platform::sandbox::run_app());
    }
    if std::env::args().nth(1).as_deref() == Some(linux::MANAGER_ROLE) {
        linux::manager_that_leaves();
        return;
    }
    if let Err(reason) = vpn_platform::sandbox::detect() {
        println!("sandbox tests skipped: {}", reason.en);
        return;
    }
    let filter: Option<String> = std::env::args().skip(1).find(|a| !a.starts_with('-'));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut failed = 0;
    let mut ran = 0;
    for (name, test) in linux::TESTS {
        if filter.as_deref().is_some_and(|f| !name.contains(f)) {
            continue;
        }
        ran += 1;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(test());
        }));
        if matches!(result, Ok(())) {
            println!("test {name} ... ok");
        } else {
            println!("test {name} ... FAILED");
            failed += 1;
        }
    }
    println!("\nsandbox tests: {} passed; {failed} failed", ran - failed);
    if failed > 0 {
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::future::Future;
    use std::io::Read;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::time::Duration;

    use vpn_platform::sandbox::{
        ExitStatus, SandboxLease, SandboxSpec, SpawnSpec, TUN_NAME, discover, probe,
    };

    type Test = fn() -> Pin<Box<dyn Future<Output = ()>>>;

    pub const TESTS: &[(&str, Test)] = &[
        ("probe_succeeds_and_leaves_nothing", || {
            Box::pin(probe_succeeds_and_leaves_nothing())
        }),
        ("apps_see_only_the_sandbox", || {
            Box::pin(apps_see_only_the_sandbox())
        }),
        ("traffic_can_only_reach_the_tun", || {
            Box::pin(traffic_can_only_reach_the_tun())
        }),
        ("process_trees_are_identified_and_killed_whole", || {
            Box::pin(process_trees_are_identified_and_killed_whole())
        }),
        ("a_restarted_manager_adopts_only_its_own_sandbox", || {
            Box::pin(a_restarted_manager_adopts_only_its_own_sandbox())
        }),
        ("a_sandbox_outlives_its_connection_not_its_manager", || {
            Box::pin(a_sandbox_outlives_its_connection_not_its_manager())
        }),
        ("a_family_the_profile_lacks_is_unreachable", || {
            Box::pin(a_family_the_profile_lacks_is_unreachable())
        }),
        ("managed_apps_start_inside_with_their_own_view", || {
            Box::pin(managed_apps_start_inside_with_their_own_view())
        }),
        ("managed_app_trees_end_together", || {
            Box::pin(managed_app_trees_end_together())
        }),
        ("a_confined_app_writes_only_where_allowed", || {
            Box::pin(a_confined_app_writes_only_where_allowed())
        }),
    ];

    fn exe() -> PathBuf {
        std::env::current_exe().unwrap()
    }

    struct Fixture {
        dir: tempfile::TempDir,
        spec: SandboxSpec,
    }

    fn fixture(orphan_grace: Duration) -> Fixture {
        // Short paths: the rendezvous socket path must fit a sockaddr_un.
        let dir = tempfile::Builder::new()
            .prefix("vpnm-sbt-")
            .tempdir()
            .unwrap();
        let state = dir.path().join("state");
        let run = dir.path().join("run");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&run).unwrap();
        std::fs::write(state.join("vault.key"), b"secret").unwrap();
        let spec = spec_in(dir.path(), orphan_grace);
        Fixture { dir, spec }
    }

    /// The sandbox of the fixture in `dir`.
    fn spec_in(dir: &Path, orphan_grace: Duration) -> SandboxSpec {
        let (state, run) = (dir.join("state"), dir.join("run"));
        SandboxSpec {
            installation_id: "11111111-2222-3333-4444-555555555555".into(),
            instance_id: "test-instance".into(),
            epoch: 7,
            mtu: 1420,
            addresses: vec![
                ("10.99.0.2".parse().unwrap(), 32),
                ("fd99::2".parse().unwrap(), 128),
            ],
            hide: vec![state, run.clone()],
            xdg_runtime_dir: std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            rendezvous: run.join("sb-test.sock"),
            orphan_grace,
        }
    }

    /// The first argument that makes this binary [`manager_that_leaves`].
    pub const MANAGER_ROLE: &str = "test-manager-that-leaves";

    /// A manager process that builds the sandbox of the fixture in `argv[2]` (orphan grace 1 s),
    /// prints its holder's pid and exits without tearing it down.
    pub fn manager_that_leaves() {
        let dir = PathBuf::from(std::env::args().nth(2).unwrap());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let lease = rt
            .block_on(SandboxLease::create(
                &exe(),
                spec_in(&dir, Duration::from_secs(1)),
            ))
            .unwrap();
        println!("{}", lease.holder().pid);
        // Gone without a teardown, as a crashed or stopped manager is.
        std::process::exit(0);
    }

    /// Run `script` with bash in the sandbox; return (exit status, stdout).
    async fn run(lease: &SandboxLease, script: &str) -> (Option<ExitStatus>, String) {
        let (mut reader, writer) = std::io::pipe().unwrap();
        let mut env = vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())];
        if let Ok(x) = std::env::var("XDG_RUNTIME_DIR") {
            env.push(("XDG_RUNTIME_DIR".into(), x));
        }
        let mut process = lease
            .spawn(SpawnSpec {
                argv: vec!["/bin/bash".into(), "-c".into(), script.into()],
                env,
                umask: 0o022,
                stdout: Some(OwnedFd::from(writer)),
                ..SpawnSpec::default()
            })
            .await
            .unwrap();
        let status = tokio::time::timeout(Duration::from_secs(20), process.wait())
            .await
            .expect("process ended");
        let mut out = String::new();
        reader.read_to_string(&mut out).unwrap();
        (status, out)
    }

    fn alive(pid: u32) -> bool {
        // SAFETY: signal 0 only checks for existence.
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    async fn gone(pid: u32) -> bool {
        for _ in 0..100 {
            if !alive(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    async fn probe_succeeds_and_leaves_nothing() {
        probe(&exe())
            .await
            .expect("this host allows strict sandboxes");
    }

    async fn apps_see_only_the_sandbox() {
        let f = fixture(Duration::from_secs(60));
        let lease = SandboxLease::create(&exe(), f.spec.clone()).await.unwrap();
        assert_eq!(lease.identity().tun_name, TUN_NAME);
        lease.check().await.unwrap();
        let state = f.spec.hide[0].display().to_string();
        let (status, out) = run(
            &lease,
            &format!(
                "grep -E '^(CapEff|CapPrm|CapBnd|CapAmb|NoNewPrivs):' /proc/self/status; \
                 echo interfaces: $(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | sort); \
                 echo routes: $(tail -n +2 /proc/net/route | cut -f1,2 | tr '\\t' ' '); \
                 echo pids: $(ls /proc | grep -c '^[0-9]'); \
                 echo resolv: $(grep -v '^#' /etc/resolv.conf); \
                 test -e {state}/vault.key && echo state-visible || echo state-hidden; \
                 test -e /run/dbus/system_bus_socket && echo dbus-visible || echo dbus-hidden; \
                 test -e /run/systemd/resolve/io.systemd.Resolve && echo resolved-visible || echo resolved-hidden; \
                 test -e \"$XDG_RUNTIME_DIR/bus\" && echo session-bus-visible || echo session-bus-hidden; \
                 echo tmp: $(ls -A /tmp | wc -l); \
                 echo uid: $(id -u); \
                 echo umask: $(umask)"
            ),
        )
        .await;
        assert_eq!(status, Some(ExitStatus::Code(0)), "{out}");
        for want in [
            "CapEff:\t0000000000000000",
            "CapPrm:\t0000000000000000",
            "CapBnd:\t0000000000000000",
            "CapAmb:\t0000000000000000",
            "NoNewPrivs:\t1",
            "interfaces: lo vpn0",
            "resolv: nameserver 127.0.0.53 options edns0",
            "state-hidden",
            "dbus-hidden",
            "resolved-hidden",
            "session-bus-hidden",
            "tmp: 0",
            "uid: 0",
            "umask: 0022",
        ] {
            assert!(out.contains(want), "missing {want:?} in:\n{out}");
        }
        // Only the default route through the TUN device (IPv4 table).
        assert!(out.contains("routes: vpn0 00000000"), "{out}");
        // The sandbox's own pid namespace: the holder, the App's init, the shell, its children.
        let pids: usize = out
            .lines()
            .find_map(|l| l.strip_prefix("pids: "))
            .and_then(|n| n.trim().parse().ok())
            .unwrap();
        assert!(pids <= 10, "host processes visible: {pids}\n{out}");
        let holder = lease.holder().pid;
        lease.teardown(Duration::from_secs(2)).await;
        assert!(gone(holder).await, "holder still running");
        assert!(!f.spec.rendezvous.exists(), "rendezvous socket left behind");
        drop(f.dir);
    }

    async fn traffic_can_only_reach_the_tun() {
        let f = fixture(Duration::from_secs(60));
        let lease = SandboxLease::create(&exe(), f.spec.clone()).await.unwrap();
        // Act as the worker: read what the sandbox sends into the TUN device.
        let tun = lease.tun().unwrap();
        // SAFETY: fcntl on a descriptor we own.
        unsafe {
            let flags = libc::fcntl(tun.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(tun.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        // A TEST-NET address and a typical LAN address: with no route but the TUN device, the
        // SYNs can only appear there. Loopback of the host is not loopback of the sandbox.
        let (_, out) = run(
            &lease,
            "for dst in 192.0.2.1 192.168.1.1; do \
               timeout 2 bash -c \"exec 3<>/dev/tcp/$dst/80\" 2>/dev/null; done; \
             (exec 3<>/dev/tcp/127.0.0.1/22) 2>/dev/null && echo host-ssh-reachable || echo host-ssh-unreachable; \
             echo done",
        )
        .await;
        let mut seen = Vec::new();
        let mut buf = [0u8; 2048];
        loop {
            // SAFETY: read into a local buffer from a descriptor we own.
            let n = unsafe { libc::read(tun.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            let p = &buf[..n.cast_unsigned()];
            if p[0] >> 4 == 4 && p[9] == 6 {
                let src = std::net::Ipv4Addr::new(p[12], p[13], p[14], p[15]);
                let dst = std::net::Ipv4Addr::new(p[16], p[17], p[18], p[19]);
                seen.push((src, dst));
            }
        }
        let src: std::net::Ipv4Addr = "10.99.0.2".parse().unwrap();
        for dst in ["192.0.2.1", "192.168.1.1"] {
            assert!(
                seen.contains(&(src, dst.parse().unwrap())),
                "no SYN to {dst} in the TUN device: {seen:?}"
            );
        }
        // The host's loopback services are not the sandbox's loopback.
        assert!(out.contains("host-ssh-unreachable"), "{out}");
        lease.teardown(Duration::from_secs(2)).await;
    }

    async fn process_trees_are_identified_and_killed_whole() {
        let f = fixture(Duration::from_secs(60));
        let lease = SandboxLease::create(&exe(), f.spec.clone()).await.unwrap();
        // A tree: the shell and a grandchild that ignores SIGTERM.
        let mut tree = lease
            .spawn(SpawnSpec {
                argv: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "(trap '' TERM; sleep 600) & sleep 600; wait".into(),
                ],
                env: vec![("PATH".into(), "/usr/bin:/bin".into())],
                umask: 0o022,
                ..SpawnSpec::default()
            })
            .await
            .unwrap();
        // Named as the host sees them: pid, our user, this boot's start time.
        let app = tree.identity().expect("App identity").clone();
        assert_eq!(app.pid, tree.pid());
        assert_eq!(app.uid, vpn_platform::process::current_uid());
        assert!(!app.start.is_empty() && app.exe.is_some(), "{app:?}");
        assert!(alive(app.pid));
        let init = tree.tree_init().expect("tree init identity").clone();
        assert_eq!(init.pid, tree.tree_init_pid());
        let now = vpn_platform::process::identity(init.pid).unwrap();
        assert!(vpn_platform::sandbox::same_process(&init, &now));
        tree.kill_tree().unwrap();
        tokio::time::timeout(Duration::from_secs(5), tree.wait())
            .await
            .expect("tree ended");
        assert!(gone(app.pid).await && gone(init.pid).await);

        // terminate: SIGTERM first; the App's own status is reported.
        let tree = lease
            .spawn(SpawnSpec {
                argv: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "trap 'exit 7' TERM; sleep 600 & wait".into(),
                ],
                env: vec![("PATH".into(), "/usr/bin:/bin".into())],
                umask: 0o022,
                ..SpawnSpec::default()
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let status = tree.terminate(Duration::from_secs(3)).await;
        assert_eq!(status, Some(ExitStatus::Code(7)));

        // A program that cannot be executed is an error, not a phantom process.
        let failed = lease
            .spawn(SpawnSpec {
                argv: vec!["/nonexistent/program".into()],
                ..SpawnSpec::default()
            })
            .await;
        assert!(failed.is_err());

        // Tearing the sandbox down ends every App with it.
        let sleeper = lease
            .spawn(SpawnSpec {
                argv: vec!["/bin/sleep".into(), "600".into()],
                ..SpawnSpec::default()
            })
            .await
            .unwrap();
        let pid = sleeper.pid();
        assert!(lease.teardown(Duration::from_secs(1)).await);
        assert!(gone(pid).await, "App survived its sandbox");
    }

    async fn a_restarted_manager_adopts_only_its_own_sandbox() {
        let f = fixture(Duration::from_secs(60));
        let lease = SandboxLease::create(&exe(), f.spec.clone()).await.unwrap();
        let holder = lease.holder().clone();
        let sleeper = lease
            .spawn(SpawnSpec {
                argv: vec!["/bin/sleep".into(), "600".into()],
                ..SpawnSpec::default()
            })
            .await
            .unwrap();
        let app = sleeper.pid();
        // The manager goes away without tearing anything down.
        drop(sleeper);
        drop(lease);
        let found = discover(f.spec.rendezvous.parent().unwrap());
        assert_eq!(found, vec![f.spec.rendezvous.clone()]);
        // Another installation's manager does not get it.
        assert!(
            SandboxLease::attach(&found[0], "99999999-0000-0000-0000-000000000000")
                .await
                .is_err()
        );
        let adopted = SandboxLease::attach(&found[0], &f.spec.installation_id)
            .await
            .unwrap();
        assert!(vpn_platform::sandbox::same_process(
            &holder,
            adopted.holder()
        ));
        assert_eq!(adopted.identity().epoch, 7);
        adopted.check().await.unwrap();
        assert!(
            alive(app),
            "the App kept running through the manager restart"
        );
        // Only one manager at a time.
        assert!(
            SandboxLease::attach(&found[0], &f.spec.installation_id)
                .await
                .is_err()
        );
        assert!(adopted.teardown(Duration::from_secs(1)).await);
        assert!(gone(app).await && gone(holder.pid).await);
        assert_eq!(
            discover(Path::new(f.spec.rendezvous.parent().unwrap())),
            Vec::<std::path::PathBuf>::new()
        );
    }

    /// A sandbox (and every App in it) is never shut down while its manager's process lives, even
    /// when the manager's connection went away: the manager adopts it again. Once no manager
    /// process is left, the orphan grace runs and the sandbox goes, its socket file with it.
    async fn a_sandbox_outlives_its_connection_not_its_manager() {
        // (what ended, whether the sandbox stays)
        let cases = [
            ("the connection only", true),
            ("the manager process", false),
        ];
        for (ended, stays) in cases {
            let f = fixture(Duration::from_secs(1));
            let holder = if stays {
                // This process is the manager: its lease (the connection) goes, it lives on.
                let lease = SandboxLease::create(&exe(), f.spec.clone()).await.unwrap();
                let holder = lease.holder().pid;
                drop(lease);
                holder
            } else {
                let out = std::process::Command::new(exe())
                    .arg(MANAGER_ROLE)
                    .arg(f.dir.path())
                    .output()
                    .unwrap();
                String::from_utf8(out.stdout)
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap()
            };
            // Three times the grace.
            for _ in 0..30 {
                if !alive(holder) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(alive(holder), stays, "{ended} ended");
            if stays {
                let again = SandboxLease::attach(&f.spec.rendezvous, &f.spec.installation_id)
                    .await
                    .unwrap();
                assert!(again.teardown(Duration::from_secs(1)).await, "{ended}");
            } else {
                assert!(gone(holder).await, "{ended}");
                assert!(!f.spec.rendezvous.exists(), "{ended}");
            }
        }
    }

    async fn a_family_the_profile_lacks_is_unreachable() {
        let mut f = fixture(Duration::from_secs(60));
        f.spec.addresses = vec![("10.99.0.2".parse().unwrap(), 32)];
        let lease = SandboxLease::create(&exe(), f.spec.clone()).await.unwrap();
        // No IPv6 on the TUN device and no IPv6 route: the kernel refuses at once, nothing is
        // sent anywhere. IPv4 still has its route through the device.
        let (_, out) = run(
            &lease,
            "echo v6-routes: $(tail -n +1 /proc/net/ipv6_route | grep -c vpn0); \
             echo v6-addresses: $(grep -c vpn0 /proc/net/if_inet6); \
             (exec 3<>/dev/tcp/2001:db8::1/80) 2>&1 | tail -1; \
             echo v4-routes: $(tail -n +2 /proc/net/route | grep -c vpn0)",
        )
        .await;
        assert!(out.contains("v6-routes: 0"), "{out}");
        assert!(out.contains("v6-addresses: 0"), "{out}");
        assert!(out.contains("Network is unreachable"), "{out}");
        assert!(out.contains("v4-routes: 1"), "{out}");
        lease.teardown(Duration::from_secs(1)).await;
    }

    fn app_command(
        program: &str,
        args: &[&str],
        env: &[(&str, &Path)],
        cwd: &Path,
    ) -> (std::io::PipeReader, vpn_platform::apps::AppCommand) {
        let (reader, writer) = std::io::pipe().unwrap();
        let mut vars: Vec<(std::ffi::OsString, std::ffi::OsString)> =
            vec![("PATH".into(), "/usr/bin:/bin".into())];
        vars.extend(
            env.iter()
                .map(|(k, v)| ((*k).into(), v.as_os_str().to_os_string())),
        );
        let cmd = vpn_platform::apps::AppCommand {
            program: program.into(),
            args: args.iter().map(Into::into).collect(),
            env: vars,
            cwd: cwd.to_path_buf(),
            output: OwnedFd::from(writer),
            limits: vpn_platform::apps::SpawnLimits::default(),
            access_ports: Vec::new(),
            write_confinement: None,
        };
        (reader, cmd)
    }

    async fn managed_apps_start_inside_with_their_own_view() {
        use vpn_platform::apps::IsolationBackend;
        let f = fixture(Duration::from_secs(60));
        let lease = SandboxLease::create(&exe(), f.spec.clone()).await.unwrap();
        let entry = std::sync::Arc::new(
            lease
                .app_entry(f.spec.hide.clone(), f.spec.xdg_runtime_dir.clone())
                .unwrap(),
        );
        // The App's own directories are in VPN Manager's (covered) state directory.
        let state = f.spec.hide[0].clone();
        let home = state.join("apps").join("a1").join("home");
        let tmp = state.join("apps").join("a1").join("tmp");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(home.join("marker"), b"mine").unwrap();
        // A private directory outside every socket directory gets a read-only cover; a
        // directory of the App's own inside it stays (the user's home and its .cargo here:
        // only read, and only in the App's mount namespace).
        let user_home = std::fs::canonicalize(std::env::var_os("HOME").unwrap()).unwrap();
        let kept = user_home.join(".cargo");
        let with_kept = std::fs::symlink_metadata(&kept).is_ok_and(|m| m.is_dir())
            && !user_home.starts_with("/tmp");
        let mut private = vec![f.dir.path().join("ssh")];
        std::fs::create_dir_all(&private[0]).unwrap();
        std::fs::write(private[0].join("id_ed25519"), b"key").unwrap();
        if with_kept {
            private.push(user_home.clone());
        }
        let backend = vpn_platform::sandbox::AppBackend::new(
            exe(),
            std::sync::Arc::downgrade(&entry),
            private.clone(),
        );
        let app_home: &Path = if with_kept { &kept } else { &home };
        let script = format!(
            "echo interfaces: $(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | sort); \
             echo pids: $(ls /proc | grep -c '^[0-9]'); \
             echo me: $$; \
             echo cwd: $(pwd); \
             echo marker: $(cat marker); \
             test -e {state}/vault.key && echo state-visible || echo state-hidden; \
             test -e {ssh}/id_ed25519 && echo ssh-visible || echo ssh-hidden; \
             echo user-home: $(awk -v h={user_home} '$5==h {{print $6}}' /proc/self/mountinfo | head -1 | cut -d, -f1); \
             echo user-home-entries: $(ls -A {user_home}); \
             test -d \"$HOME\" && echo home-kept; \
             touch \"$TMPDIR/t\" && echo tmp-writable; \
             grep -E '^(CapEff|NoNewPrivs):' /proc/self/status; \
             echo resolv: $(grep -c 127.0.0.53 /etc/resolv.conf); \
             echo uid: $(id -u); \
             exit 7",
            state = state.display(),
            ssh = private[0].display(),
            user_home = user_home.display(),
        );
        let (mut reader, cmd) = app_command(
            "/bin/bash",
            &["-c", &script],
            &[("HOME", app_home), ("TMPDIR", &tmp)],
            &home,
        );
        let mut app = backend.spawn(cmd).unwrap();
        assert_eq!(Some(app.identity.pid), app.child.id());
        let status = tokio::time::timeout(Duration::from_secs(20), app.child.wait())
            .await
            .expect("the App ended")
            .unwrap();
        let mut out = String::new();
        reader.read_to_string(&mut out).unwrap();
        // Its exit status, as if it were the manager's own child.
        assert_eq!(status.code(), Some(7), "{out}");
        for want in &expected_view(&home, with_kept) {
            assert!(out.contains(want.as_str()), "missing {want:?} in:\n{out}");
        }
        let pids: usize = out
            .lines()
            .find_map(|l| l.strip_prefix("pids: "))
            .and_then(|n| n.trim().parse().ok())
            .unwrap();
        // The tree's init, the shell, and the subshell, ls and grep counting them: the tree's
        // own /proc shows nothing else.
        assert!(
            pids <= 5,
            "processes beyond the App's tree visible: {pids}\n{out}"
        );
        assert!(tmp.join("t").exists(), "TMPDIR is the App's own directory");
        let holder = lease.holder().pid;
        drop(entry);
        assert!(lease.teardown(Duration::from_secs(2)).await);
        assert!(gone(holder).await);
    }

    /// A strict App with its writes confined (Landlock) writes beneath its writable
    /// directories, its HOME and TMPDIR and /dev, and nowhere else its user could; it still
    /// reads everywhere. Unconfined it writes wherever its user can (Apps saved before the
    /// switch existed keep that).
    async fn a_confined_app_writes_only_where_allowed() {
        use vpn_platform::apps::IsolationBackend;
        let f = fixture(Duration::from_secs(60));
        let lease = SandboxLease::create(&exe(), f.spec.clone()).await.unwrap();
        let entry = std::sync::Arc::new(
            lease
                .app_entry(f.spec.hide.clone(), f.spec.xdg_runtime_dir.clone())
                .unwrap(),
        );
        let backend = vpn_platform::sandbox::AppBackend::new(
            exe(),
            std::sync::Arc::downgrade(&entry),
            Vec::new(),
        );
        // The App's own directories, kept in place inside the sandbox's covers.
        let state = f.spec.hide[0].clone();
        let home = state.join("apps").join("a2").join("home");
        let tmp = state.join("apps").join("a2").join("tmp");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&tmp).unwrap();
        // Directories the App sees as they are (not under /tmp, which the sandbox covers): the
        // build's own temporary directory.
        let outside = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        // (case, writes confined, may it write the other directory)
        let cases = [("confined", true, false), ("unconfined", false, true)];
        for (case, confined, other_writable) in cases {
            let allowed = outside.path().join(format!("{case}-allowed"));
            let other = outside.path().join(format!("{case}-other"));
            std::fs::create_dir_all(&allowed).unwrap();
            std::fs::create_dir_all(&other).unwrap();
            std::fs::write(other.join("readme"), b"read me").unwrap();
            let script = format!(
                "touch {allowed}/f && echo allowed-written; \
                 touch {other}/f && echo other-written || echo other-refused; \
                 cat {other}/readme >/dev/null && echo other-read; \
                 touch \"$HOME/f\" && echo home-written; \
                 touch \"$TMPDIR/f\" && echo tmp-written; \
                 echo x > /dev/null && echo dev-written; \
                 exit 0",
                allowed = allowed.display(),
                other = other.display(),
            );
            let (mut reader, mut cmd) = app_command(
                "/bin/bash",
                &["-c", &script],
                &[("HOME", &home), ("TMPDIR", &tmp)],
                &home,
            );
            cmd.write_confinement = confined.then(|| vec![allowed.clone()]);
            let mut app = backend.spawn(cmd).unwrap();
            let status = tokio::time::timeout(Duration::from_secs(20), app.child.wait())
                .await
                .expect("the App ended")
                .unwrap();
            let mut out = String::new();
            reader.read_to_string(&mut out).unwrap();
            assert_eq!(status.code(), Some(0), "{case}: {out}");
            for want in [
                "allowed-written",
                "other-read",
                "home-written",
                "tmp-written",
                "dev-written",
            ] {
                assert!(out.contains(want), "{case}: missing {want} in:\n{out}");
            }
            let other_line = if other_writable {
                "other-written"
            } else {
                "other-refused"
            };
            assert!(out.contains(other_line), "{case}: {out}");
            assert_eq!(other.join("f").exists(), other_writable, "{case}: {out}");
        }
        let holder = lease.holder().pid;
        drop(entry);
        assert!(lease.teardown(Duration::from_secs(2)).await);
        assert!(gone(holder).await);
    }

    async fn managed_app_trees_end_together() {
        use vpn_platform::apps::IsolationBackend;
        let f = fixture(Duration::from_secs(60));
        let lease = SandboxLease::create(&exe(), f.spec.clone()).await.unwrap();
        let entry = std::sync::Arc::new(
            lease
                .app_entry(f.spec.hide.clone(), f.spec.xdg_runtime_dir.clone())
                .unwrap(),
        );
        let home = f.spec.hide[0].join("apps").join("a2");
        std::fs::create_dir_all(&home).unwrap();
        let backend = vpn_platform::sandbox::AppBackend::new(
            exe(),
            std::sync::Arc::downgrade(&entry),
            Vec::new(),
        );
        // Stop: SIGTERM reaches the whole tree through its init; the launcher ends the way the
        // App did.
        let (_r, cmd) = app_command(
            "/bin/bash",
            &["-c", "sleep 600 & sleep 600 & wait"],
            &[("HOME", &home)],
            &home,
        );
        let mut app = backend.spawn(cmd).unwrap();
        let root = app.identity;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let tree = descendants(root.pid);
        assert!(
            tree.len() >= 5,
            "launcher, starter, init, shell, two sleeps: {tree:?}"
        );
        backend.terminate(root, &[root], false);
        let status = tokio::time::timeout(Duration::from_secs(10), app.child.wait())
            .await
            .expect("the tree ended")
            .unwrap();
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGTERM),
            "{status:?}"
        );
        for pid in &tree {
            assert!(gone(*pid).await, "pid {pid} of the tree is still alive");
        }
        // The App exits, its background child does not: the rest of the tree goes with it.
        let (_r, cmd) = app_command(
            "/bin/bash",
            &["-c", "(trap '' TERM; sleep 600) & sleep 0.2; exit 3"],
            &[("HOME", &home)],
            &home,
        );
        let mut app = backend.spawn(cmd).unwrap();
        let status = tokio::time::timeout(Duration::from_secs(15), app.child.wait())
            .await
            .expect("the tree ended after the App")
            .unwrap();
        assert_eq!(status.code(), Some(3));
        // A program that cannot run is an error, not a phantom App.
        let (_r, cmd) = app_command("/nonexistent/app", &[], &[("HOME", &home)], &home);
        assert!(backend.spawn(cmd).is_err());
        // Tearing the sandbox down ends what runs in it.
        let (_r, cmd) = app_command("/bin/sleep", &["600"], &[("HOME", &home)], &home);
        let mut app = backend.spawn(cmd).unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let tree = descendants(app.identity.pid);
        drop(entry);
        assert!(lease.teardown(Duration::from_secs(1)).await);
        let status = tokio::time::timeout(Duration::from_secs(10), app.child.wait())
            .await
            .expect("the App ended with its sandbox")
            .unwrap();
        assert!(!status.success());
        for pid in &tree {
            assert!(gone(*pid).await, "pid {pid} survived its sandbox");
        }
        // Without the sandbox there is nothing to start in.
        let (_r, cmd) = app_command("/bin/true", &[], &[("HOME", &home)], &home);
        assert!(backend.spawn(cmd).is_err());
    }

    /// What the App of [`managed_apps_start_inside_with_their_own_view`] must print.
    fn expected_view(home: &Path, with_kept: bool) -> Vec<String> {
        let mut wants = vec![
            "interfaces: lo vpn0".to_string(),
            // pid 1 is the tree's init, the App is 2: nothing else is visible.
            "me: 2".into(),
            format!("cwd: {}", home.display()),
            "marker: mine".into(),
            "state-hidden".into(),
            "ssh-hidden".into(),
            "home-kept".into(),
            "tmp-writable".into(),
            "CapEff:\t0000000000000000".into(),
            "NoNewPrivs:\t1".into(),
            "resolv: 1".into(),
            "uid: 0".into(),
        ];
        if with_kept {
            wants.push("user-home: ro".into());
            wants.push("user-home-entries: .cargo".into());
        }
        wants
    }

    /// `pid` and every process below it (host view).
    fn descendants(pid: u32) -> Vec<u32> {
        let mut parents: Vec<(u32, u32)> = Vec::new();
        for e in std::fs::read_dir("/proc").unwrap().flatten() {
            let Ok(p) = e.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{p}/stat")) else {
                continue;
            };
            let Some((_, rest)) = stat.rsplit_once(')') else {
                continue;
            };
            let parent: u32 = rest
                .split_whitespace()
                .nth(1)
                .and_then(|x| x.parse().ok())
                .unwrap_or(0);
            parents.push((p, parent));
        }
        let mut out = vec![pid];
        let mut i = 0;
        while i < out.len() {
            let cur = out[i];
            out.extend(parents.iter().filter(|(_, pp)| *pp == cur).map(|(p, _)| *p));
            i += 1;
        }
        out
    }
}
