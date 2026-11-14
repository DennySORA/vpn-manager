//! Linux strict mode end to end, rootless, with the real programs: `vpnd manager` and
//! `vpnd controller` on a private state directory, an in-process `WireGuard` lab peer on
//! loopback, `vpnd sandbox-exec` for processes inside the connection's sandbox.
//!
//! - a strict connection comes up in its sandbox; a process in the sandbox fetches
//!   `http://x.lab/ip` through the tunnel (the name resolved by the connection's resolver on
//!   127.0.0.53), cannot reach a direct address or the host's loopback services, sees no host
//!   runtime directory, has no capabilities;
//! - the connection's Gateway (SOCKS5 CONNECT and UDP ASSOCIATE) still serves host clients —
//!   dials from the sandbox's kernel stack, UDP relay sockets from the manager;
//! - what the sandbox's processes download is App payload in the connection's metrics (and part
//!   of its payload); what the Gateway downloads is not, though it crosses the same TUN device;
//! - kill -9 of the worker: an App goes offline and comes back on the next generation without
//!   being restarted, in the same sandbox; likewise across a manager restart (adoption);
//! - a blocklist attached while the connection runs resets an App's connection to a listed
//!   address at once and refuses new ones (TCP reset), the rest still flows; detached, it lets
//!   them through again — all within the same generation;
//! - a managed App in strict mode, created and started through the API, runs in the
//!   connection's sandbox: it reaches the lab through the tunnel and nothing else, goes offline
//!   while the worker is down and online again without being restarted; stopping it ends its
//!   whole tree;
//! - recovery lists the connection's sandbox as a resource, never as a leftover; a sandbox of
//!   this installation nobody holds (as a crash leaves it) and a dead sandbox socket are
//!   reported and cleaned, the leftover's App first;
//! - deleting the connection terminates the App and leaves no holder, process or socket file;
//! - a port forward whose UDP goes straight into the sandbox: a datagram from a host beyond the
//!   server reaches the App's own socket with its real source and the App's answer goes back
//!   from the forwarded port, only once the forward exists and while it is enabled, never to
//!   another port, and not from a blocklisted source; its TCP is relayed as ever; the forward
//!   counts it and records the evidence.
//!
//! Nothing needs root or changes the host. A failing run still kills everything it started. The
//! tests run one at a time: each one's cleanup kills every sandbox holder of this build.

#![allow(
    unsafe_code,
    reason = "libc kill FFI to probe and signal the daemon processes under test"
)]
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures: clippy.toml allows unwrap/expect in #[test] fns, not in the helper fns of a tests/ crate"
)]

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use vpn_domain::*;
use vpn_labpeer::LabPeer;
use vpn_platform::paths::Paths;
use vpn_store::{IntentChange, Store};
use zeroize::Zeroizing;

fn vpnd() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vpnd"))
}

/// One test at a time: a test's [`Cleanup`] kills every sandbox holder of this build.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn meta() -> EntityMeta {
    EntityMeta {
        revision: 1,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
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
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Everything this test started, killed if it fails half-way: the sandbox holders (each takes
/// its whole pid namespace with it) and the manager, controller and sandbox-exec processes.
#[derive(Default)]
struct Cleanup {
    pids: Vec<u32>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let exe = vpnd();
        // Holders of this build (left by a failed run before their pid was known).
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for e in entries.flatten() {
                let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
                    continue;
                };
                let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
                    continue;
                };
                let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
                if args.first() == Some(&exe.as_os_str().as_encoded_bytes())
                    && args.get(1) == Some(&&b"sandbox-holder"[..])
                {
                    self.pids.push(pid);
                }
            }
        }
        for pid in &self.pids {
            // SAFETY: SIGKILL to a process this test started.
            unsafe {
                libc::kill(*pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }
}

/// The stack under test.
struct Stack {
    dir: PathBuf,
    paths: Paths,
    port: u16,
    manager: Option<Child>,
    controller: Child,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn log_file(dir: &Path, name: &str) -> Stdio {
    Stdio::from(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(name))
            .unwrap(),
    )
}

async fn start_manager(dir: &Path, paths: &Paths, cleanup: &mut Cleanup) -> Child {
    let child = Command::new(vpnd())
        .args(["manager", "--state-dir"])
        .arg(&paths.state)
        .arg("--ssh-dir")
        .arg(dir.join("ssh"))
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log_file(dir, "manager.log"))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    cleanup.pids.extend(child.id());
    for _ in 0..100 {
        if paths.manager_socket().exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    child
}

/// One HTTP/1.0 exchange with the controller (a JSON body); returns (status, body). Status 0:
/// the controller does not listen (yet).
async fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &str,
) -> (u16, String) {
    http_typed(port, method, path, headers, "application/json", body).await
}

async fn http_typed(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    content_type: &str,
    body: &str,
) -> (u16, String) {
    let Ok(mut s) = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await else {
        return (0, String::new());
    };
    let mut req = format!(
        "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        write!(req, "{k}: {v}\r\n").unwrap();
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, body.to_owned())
}

impl Stack {
    async fn view(&self, id: InstanceId) -> Option<InstanceView> {
        let (status, body) = http(self.port, "GET", &format!("/v1/instances/{id}"), &[], "").await;
        (status == 200).then(|| serde_json::from_str(&body).unwrap())
    }

    /// A mutation with the headers the API requires; returns (status, body).
    async fn send(
        &self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &str,
        revision: Option<u64>,
    ) -> (u16, String) {
        let mut headers = vec![
            ("Origin", format!("http://127.0.0.1:{}", self.port)),
            ("Idempotency-Key", uuid::Uuid::new_v4().to_string()),
        ];
        if let Some(r) = revision {
            headers.push(("If-Match", format!("\"{r}\"")));
        }
        http_typed(self.port, method, path, &headers, content_type, body).await
    }

    /// A JSON mutation; returns the status.
    async fn mutate(&self, method: &str, path: &str, body: &str, revision: Option<u64>) -> u16 {
        self.send(method, path, "application/json", body, revision)
            .await
            .0
    }

    /// A JSON POST; returns (status, body).
    async fn post(&self, path: &str, body: &str) -> (u16, String) {
        self.send("POST", path, "application/json", body, None)
            .await
    }

    /// Attach these blocklists to the security profile; returns the profile's new revision.
    async fn set_blocklists(
        &self,
        profile: SecurityProfileId,
        revision: u64,
        blocklists: Vec<BlocklistId>,
    ) -> u64 {
        let input = SecurityProfileInput {
            name: "lab".into(),
            allow_private: vec![
                "10.99.0.0/24".parse().unwrap(),
                "fd99::/64".parse().unwrap(),
            ],
            blocked_ports: Vec::new(),
            allowed_destinations: Vec::new(),
            allowed_ports: Vec::new(),
            blocklists,
            auto_ban: AutoBanSettings::default(),
        };
        let (status, body) = self
            .send(
                "PUT",
                &format!("/v1/security-profiles/{profile}"),
                "application/json",
                &serde_json::to_string(&input).unwrap(),
                Some(revision),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        serde_json::from_str::<SecurityProfile>(&body)
            .unwrap()
            .meta
            .revision
    }

    /// Wait until the running worker confirms an overlay newer than `after`; returns its status.
    async fn overlay_applied(&self, id: InstanceId, what: &str, after: u64) -> InstanceStatus {
        self.wait_for(id, what, |s| {
            s.running
                .as_ref()
                .and_then(|r| r.policy.as_ref())
                .is_some_and(|p| p.revision > after && p.applied_revision == Some(p.revision))
        })
        .await
    }

    async fn app_status(&self, id: AppId) -> AppStatus {
        let (status, body) =
            http(self.port, "GET", &format!("/v1/apps/{id}/status"), &[], "").await;
        assert_eq!(status, 200, "{body}");
        serde_json::from_str(&body).unwrap()
    }

    /// The connection's totals over the last 15 minutes, once `done` holds (bounded).
    async fn totals_until(
        &self,
        id: InstanceId,
        what: &str,
        done: impl Fn(&MetricsTotals) -> bool,
    ) -> MetricsTotals {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let (status, body) = http(
                self.port,
                "GET",
                &format!("/v1/instances/{id}/metrics?range=15m"),
                &[],
                "",
            )
            .await;
            assert_eq!(status, 200, "{body}");
            let totals = serde_json::from_str::<MetricsSeries>(&body).unwrap().totals;
            if done(&totals) {
                return totals;
            }
            assert!(tokio::time::Instant::now() < deadline, "{what}: {totals:?}");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn recovery(&self) -> RecoveryReport {
        let (status, body) = http(self.port, "GET", "/v1/recovery", &[], "").await;
        assert_eq!(status, 200, "{body}");
        serde_json::from_str(&body).unwrap()
    }

    async fn wait_for(
        &self,
        id: InstanceId,
        what: &str,
        done: impl Fn(&InstanceStatus) -> bool,
    ) -> InstanceStatus {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        loop {
            let status = self.view(id).await.and_then(|v| v.status);
            if let Some(s) = &status
                && done(s)
            {
                return s.clone();
            }
            if tokio::time::Instant::now() > deadline {
                let log = std::fs::read_to_string(self.dir.join("manager.log")).unwrap_or_default();
                panic!("{what}: {status:?}\nmanager log:\n{log}");
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    /// `vpnd sandbox-exec` with bash; returns (exit code, stdout).
    async fn exec(&self, id: InstanceId, script: &str) -> (i32, String) {
        let out = tokio::time::timeout(
            Duration::from_secs(30),
            Command::new(vpnd())
                .args(["sandbox-exec", "--state-dir"])
                .arg(&self.paths.state)
                .args([
                    "--instance",
                    &id.to_string(),
                    "--",
                    "/bin/bash",
                    "-c",
                    script,
                ])
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("sandbox-exec finished")
        .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }
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

/// Wait for a line containing `want` in the App's log after byte `from`; returns the offset
/// after that line and the line.
async fn log_until(path: &Path, from: usize, want: &str) -> (usize, String) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.len() > from {
            let mut offset = from;
            for line in text[from..].split_inclusive('\n') {
                offset += line.len();
                if line.ends_with('\n') && line.contains(want) {
                    return (offset, line.trim_end().to_owned());
                }
            }
        }
        assert!(
            tokio::time::Instant::now() <= deadline,
            "no {want:?} in the App's log after byte {from}:\n{text}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// An HTTP GET of x.lab/ip with bash's /dev/tcp: the name goes through the C library to the
/// sandbox's resolv.conf (127.0.0.53, the connection's resolver).
const FETCH: &str = "exec 3<>/dev/tcp/x.lab/80 && printf 'GET /ip HTTP/1.0\\r\\nHost: x.lab\\r\\n\\r\\n' >&3 && timeout 5 cat <&3";

async fn socks5_handshake(gateway: SocketAddr) -> tokio::net::TcpStream {
    let mut s = tokio::net::TcpStream::connect(gateway).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [5, 0]);
    s
}

/// HTTP GET of `path` through the Gateway (SOCKS5 CONNECT to a name the Gateway resolves in the
/// tunnel).
async fn gateway_fetch(gateway: SocketAddr, path: &str) -> String {
    let mut s = socks5_handshake(gateway).await;
    let host = b"x.lab";
    let mut req = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    req.extend_from_slice(host);
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut reply = [0u8; 4];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS5 CONNECT refused: {reply:?}");
    let rest = match reply[3] {
        1 => 6,
        4 => 18,
        _ => panic!("unexpected address type"),
    };
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: x.lab\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut body = String::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_string(&mut body))
        .await
        .unwrap()
        .unwrap();
    body
}

/// A DNS query to the lab resolver through the Gateway's UDP ASSOCIATE (relay socket made by the
/// manager on the host's loopback, tunnel socket in the sandbox).
async fn gateway_udp_dns(gateway: SocketAddr) {
    let mut control = socks5_handshake(gateway).await;
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "UDP ASSOCIATE refused: {reply:?}");
    let relay = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    assert!(relay.ip().is_loopback(), "relay on {relay}");
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Query `x.lab. A` (id 0x1234, RD) to 10.99.0.1:53.
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["x", "lab"] {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let mut datagram = vec![0, 0, 0, 1, 10, 99, 0, 1, 0, 53];
    datagram.extend_from_slice(&query);
    let mut buf = [0u8; 1500];
    for _ in 0..5 {
        udp.send_to(&datagram, relay).await.unwrap();
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut buf)).await
        {
            // SOCKS5 UDP header (10 bytes) + a DNS response with our id.
            assert!(n > 10 + 12 && buf[10] == 0x12 && buf[11] == 0x34);
            return;
        }
    }
    panic!("no DNS answer through the Gateway's UDP association");
}

/// Wait (bounded) for the App to print `want`.
async fn next_line(
    lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    want: &str,
) {
    let found = tokio::time::timeout(Duration::from_secs(40), async {
        while let Ok(Some(line)) = lines.next_line().await {
            if line == want {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(found, Ok(true), "no {want:?} line from the App");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_connection_end_to_end() {
    let _serial = SERIAL.lock().await;
    if let Err(reason) = vpn_platform::sandbox::detect() {
        eprintln!("skipped: {}", reason.en);
        return;
    }
    if !Path::new("/bin/bash").exists() {
        eprintln!("skipped: /bin/bash missing");
        return;
    }
    let mut cleanup = Cleanup::default();
    // A short directory: socket paths must fit a sockaddr_un.
    let tmp = tempfile::Builder::new()
        .prefix("vpnm-e2e-")
        .tempdir()
        .unwrap();
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("ssh")).unwrap();
    let paths = Paths::under(&dir.join("s"));
    paths.ensure().unwrap();

    let lab = LabPeer::start("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let gateway_port = free_port();
    let (id, gateway_id, installation, security_id) =
        configure_end_to_end(&paths, &lab, gateway_port).await;
    let mut stack = start_stack(&dir, &paths, &mut cleanup, id).await;

    let ready = stack
        .wait_for(id, "strict connection ready", |s| {
            s.phase == Phase::Ready && s.sandbox.is_some()
        })
        .await;
    cleanup
        .pids
        .push(ready.sandbox.as_ref().unwrap().holder_pid);
    // Everything below runs in the sandbox the connection built for itself after its first
    // one's holder was killed.
    let ready = holder_killed(&stack, &mut cleanup, id, &ready).await;
    let sandbox = ready.sandbox.clone().unwrap();
    assert_eq!(sandbox.tun_name, "vpn0");
    assert_eq!(sandbox.addresses, ["10.99.0.2/32", "fd99::2/128"]);
    let rendezvous = paths.sandbox_socket(&id.to_string());
    assert!(rendezvous.exists());
    let first = ready.running.as_ref().unwrap();
    eprintln!(
        "ready: generation {} worker {:?}; sandbox epoch {} holder {} {} {:?}",
        first.generation,
        first.pid,
        sandbox.epoch,
        sandbox.holder_pid,
        sandbox.tun_name,
        sandbox.addresses
    );

    sandbox_isolation(&stack, id).await;
    gateway_and_counters(&stack, id, gateway_port).await;
    blocklist_live(&stack, &mut cleanup, id, security_id).await;

    // An App runs on through worker crashes and a manager restart.
    let (mut looper, app, lines) = start_looper(&stack, &mut cleanup, id).await;
    let mut probe = Probe {
        id,
        sandbox,
        app,
        lines,
    };
    let managed = start_managed_app(&stack, id).await;
    let generation = ready.running.as_ref().unwrap().generation;
    let again = worker_crash(&stack, &mut probe, &ready, &managed).await;
    stop_managed_app(&stack, &managed).await;
    let adopted = restart_manager(&mut stack, &mut cleanup, &mut probe, &again, generation).await;
    recovery_spares_the_sandbox(&stack, &mut cleanup, &mut probe, &installation, &rendezvous).await;
    emergency_stop_keeps_the_sandbox(&stack, &mut probe, &adopted).await;
    delete_connection(&stack, &probe, &mut looper, gateway_id, &rendezvous).await;

    stop_stack(&mut stack).await;
    lab.shutdown().await;
}

/// What the end-to-end test follows across phases: the connection, its sandbox, and the
/// looping App inside it with its output.
/// The sandbox's holder is killed while the connection runs. Nothing can start in that sandbox
/// any more, so the connection lets it go and comes back by itself in a new one — a higher
/// epoch, another holder, the next generation — without the manager restarting.
async fn holder_killed(
    stack: &Stack,
    cleanup: &mut Cleanup,
    id: InstanceId,
    before: &InstanceStatus,
) -> InstanceStatus {
    let old = before.sandbox.clone().unwrap();
    let generation = before.running.as_ref().unwrap().generation;
    // SAFETY: SIGKILL to the sandbox holder of this test's manager.
    unsafe {
        libc::kill(old.holder_pid as libc::pid_t, libc::SIGKILL);
    }
    let after = stack
        .wait_for(id, "the connection back in a new sandbox", |s| {
            s.phase == Phase::Ready
                && s.running
                    .as_ref()
                    .is_some_and(|r| r.generation > generation)
                && s.sandbox
                    .as_ref()
                    .is_some_and(|new| new.epoch > old.epoch && new.holder_pid != old.holder_pid)
        })
        .await;
    let new = after.sandbox.clone().unwrap();
    cleanup.pids.push(new.holder_pid);
    assert!(gone(old.holder_pid).await, "the killed holder");
    assert!(alive(new.holder_pid));
    let log = std::fs::read_to_string(stack.dir.join("manager.log")).unwrap_or_default();
    assert!(log.contains("sandbox holder exited"), "{log}");
    eprintln!(
        "holder {} killed (SIGKILL): sandbox epoch {} -> {}, holder {}, generation {} -> {}",
        old.holder_pid,
        old.epoch,
        new.epoch,
        new.holder_pid,
        generation,
        after.running.as_ref().unwrap().generation
    );
    after
}

struct Probe {
    id: InstanceId,
    sandbox: SandboxStatus,
    app: u32,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
}

/// The managed App of the end-to-end test: its id, log, how far the log was read, its pid.
struct ManagedApp {
    id: AppId,
    log: PathBuf,
    offset: usize,
    pid: u32,
}

/// The end-to-end test's connection on the lab, written before the manager starts (it is
/// the Store's only writer then): its profile, security profile, a SOCKS5 Gateway on
/// `gateway_port`, meant to run. Returns the connection, the Gateway, the installation id and
/// the security profile.
async fn configure_end_to_end(
    paths: &Paths,
    lab: &LabPeer,
    gateway_port: u16,
) -> (InstanceId, GatewayId, String, SecurityProfileId) {
    let client = &lab.clients[0];
    let master = vpn_platform::keystore::load_or_create_key_file(&paths.vault_key()).unwrap();
    let store = Store::open(&paths.state, &master, 1).unwrap();
    let key = store
        .put_secret(
            "wireguard_private_key".into(),
            None,
            Zeroizing::new(client.private_key.to_vec()),
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
                public_key: WgKey(client.public_key),
                addresses: vec![
                    format!("{}/32", client.address_v4).parse().unwrap(),
                    format!("{}/128", client.address_v6).parse().unwrap(),
                ],
                dns: vec![IpAddr::V4(vpn_labpeer::SERVER_V4)],
                mtu: 1420,
            },
            peer: PeerSpec {
                public_key: WgKey(lab.public_key),
                preshared_key: None,
                endpoint: lab.endpoint,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
                persistent_keepalive: Some(25),
            },
            location: None,
            expires_at: None,
        })
        .await
        .unwrap();
    let security = store
        .create(SecurityProfile {
            id: SecurityProfileId::new(),
            meta: meta(),
            name: "lab".into(),
            allow_private: vec![
                "10.99.0.0/24".parse().unwrap(),
                "fd99::/64".parse().unwrap(),
            ],
            blocked_ports: Vec::new(),
            allowed_destinations: Vec::new(),
            allowed_ports: Vec::new(),
            blocklists: Vec::new(),
            auto_ban: AutoBanSettings::default(),
        })
        .await
        .unwrap();
    let spec = store
        .create_instance(InstanceSpec {
            id: InstanceId::new(),
            meta: meta(),
            name: "strict".into(),
            profile_id: profile.id,
            dns_profile_id: None,
            security_profile_id: Some(security.id),
            purpose: InstancePurpose::General,
            limits: InstanceLimits::default(),
            strict: true,
            transport: vpn_domain::TransportRef::default(),
        })
        .await
        .unwrap();
    let gateway = store
        .create(GatewaySpec {
            id: GatewayId::new(),
            meta: meta(),
            instance_id: spec.id,
            name: "socks".into(),
            kind: GatewayKind::Socks5,
            port: gateway_port,
            enabled: true,
            udp: true,
            max_connections: 16,
        })
        .await
        .unwrap();
    store
        .change_intent(spec.id, IntentChange::Start)
        .await
        .unwrap();
    (
        spec.id,
        gateway.id,
        store.installation_id().to_string(),
        security.id,
    )
}

/// A process in the sandbox reaches the lab through the tunnel, by name, and nothing else.
async fn sandbox_isolation(stack: &Stack, id: InstanceId) {
    let port = stack.port;
    let (code, out) = stack.exec(id, FETCH).await;
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("\"ip\":\"10.99.0.2\"") || out.contains("\"ip\":\"fd99::2\""),
        "{out}"
    );
    eprintln!(
        "sandboxed fetch of x.lab/ip: {}",
        out.lines().last().unwrap_or("")
    );
    // Direct addresses and the host's loopback services are not reachable; the host's runtime
    // directory and VPN Manager's state are not visible; no capabilities. The state directory
    // is either gone with the covered /tmp (a state directory there) or itself covered by an
    // empty tmpfs (anywhere else, e.g. a TMPDIR in a home directory): nothing of it shows.
    let state = stack.paths.state.display();
    let (_, out) = stack
        .exec(
            id,
            &format!(
                "(exec 3<>/dev/tcp/192.0.2.1/80) 2>/dev/null && echo direct-reached || echo direct-refused; \
                 (exec 3<>/dev/tcp/127.0.0.1/{port}) 2>/dev/null && echo ui-reached || echo ui-refused; \
                 test -n \"$(ls -A {state} 2>/dev/null)\" && echo state-visible || echo state-hidden; \
                 test -e /run/dbus/system_bus_socket && echo dbus-visible || echo dbus-hidden; \
                 cat /etc/resolv.conf | grep -c 'nameserver 127.0.0.53'; \
                 grep -E '^(CapEff|NoNewPrivs):' /proc/self/status"
            ),
        )
        .await;
    for want in [
        "direct-refused",
        "ui-refused",
        "state-hidden",
        "dbus-hidden",
        "CapEff:\t0000000000000000",
        "NoNewPrivs:\t1",
    ] {
        assert!(out.contains(want), "missing {want:?} in:\n{out}");
    }
    eprintln!("isolation inside the sandbox: {}", out.replace('\n', " | "));
}

/// The Gateway serves host clients, and the Apps' traffic is counted apart from the Gateway's.
async fn gateway_and_counters(stack: &Stack, id: InstanceId, gateway_port: u16) {
    let port = stack.port;
    // The Gateway serves host clients through the sandbox's kernel stack.
    let gateway: SocketAddr = (Ipv4Addr::LOCALHOST, gateway_port).into();
    let body = gateway_fetch(gateway, "/ip").await;
    assert!(body.contains("\"ip\""), "{body}");
    gateway_udp_dns(gateway).await;
    eprintln!(
        "gateway {gateway}: SOCKS5 CONNECT x.lab:80 -> {}; UDP ASSOCIATE DNS answered",
        body.lines().last().unwrap_or("")
    );

    // The Apps' traffic is counted where it crosses the sandbox's TUN device, apart from the
    // worker's own flows: a sandboxed download of 200,000 bytes is App payload and part of the
    // connection's payload; a Gateway's download of 300,000 bytes is the Gateway's alone.
    let known = |v: Option<u64>| v.unwrap_or(0);
    let before = stack.totals_until(id, "metrics", |_| true).await;
    let (code, out) = stack
        .exec(
            id,
            "exec 3<>/dev/tcp/x.lab/80 && printf 'GET /bytes/200000 HTTP/1.0\r\nHost: x.lab\r\n\r\n' >&3 && timeout 5 cat <&3 | wc -c",
        )
        .await;
    assert_eq!(code, 0, "{out}");
    assert!(out.trim().parse::<u64>().unwrap() > 200_000, "{out}");
    let apps = stack
        .totals_until(id, "the sandboxed download as App payload", |t| {
            known(t.sandbox_rx_bytes) >= known(before.sandbox_rx_bytes) + 200_000
        })
        .await;
    assert!(
        known(apps.payload_rx_bytes) >= known(before.payload_rx_bytes) + 200_000,
        "the connection's payload includes its Apps': {apps:?}"
    );
    let body = gateway_fetch(gateway, "/bytes/300000").await;
    assert!(body.len() > 300_000, "{} bytes", body.len());
    let after = stack
        .totals_until(id, "the Gateway's download as payload", |t| {
            known(t.payload_rx_bytes) >= known(apps.payload_rx_bytes) + 300_000
        })
        .await;
    let apps_added = known(after.sandbox_rx_bytes) - known(apps.sandbox_rx_bytes);
    assert!(
        apps_added < 50_000,
        "the Gateway's download counted as App payload: {apps_added} B"
    );
    let (status, live) = http(port, "GET", &format!("/v1/instances/{id}/live"), &[], "").await;
    assert_eq!(status, 200, "{live}");
    let live: Vec<LiveRates> = serde_json::from_str(&live).unwrap();
    assert!(
        live.last().is_some_and(|r| r.sandbox.is_some()),
        "live rates without the sandbox's"
    );
    eprintln!(
        "App payload: {} B received after the sandboxed download of 200000 B, +{apps_added} B with the Gateway's of 300000 B (connection payload +{} B)",
        known(apps.sandbox_rx_bytes) - known(before.sandbox_rx_bytes),
        known(after.payload_rx_bytes) - known(apps.payload_rx_bytes),
    );
}

/// A process in the sandbox holding a connection to 192.88.99.7:7 open, and its output.
async fn hold_connection(
    stack: &Stack,
    cleanup: &mut Cleanup,
    id: InstanceId,
) -> (
    Child,
    tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
) {
    let mut held = Command::new(vpnd())
        .args(["sandbox-exec", "--state-dir"])
        .arg(&stack.paths.state)
        .args([
            "--instance",
            &id.to_string(),
            "--",
            "/bin/bash",
            "-c",
            "exec 3<>/dev/tcp/192.88.99.7/7 && echo connected && timeout 30 cat <&3 2>&1; echo \"cat-status=$?\"",
        ])
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    cleanup.pids.extend(held.id());
    let mut held_lines = BufReader::new(held.stdout.take().unwrap()).lines();
    next_line(&mut held_lines, "connected").await;
    (held, held_lines)
}

/// A blocklist reaches the Apps' own flows, live, and is detached again.
async fn blocklist_live(
    stack: &Stack,
    cleanup: &mut Cleanup,
    id: InstanceId,
    security_id: SecurityProfileId,
) {
    // A blocklist reaches the Apps' own flows, live: an App's open connection to a listed address
    // is reset the moment the list is applied, new ones are refused, the rest still flows. The
    // address is the lab peer's stand-in for a host on the Internet (192.88.99.7, echo on port
    // 7 like its own addresses): a blocklist only holds public space, the lab's private
    // addresses (10.99.0.1, fd99::1) are left out of any list.
    let running_now = stack.view(id).await.unwrap().status.unwrap();
    let generation_now = running_now.running.as_ref().unwrap().generation;
    let overlay_before = running_now
        .running
        .as_ref()
        .and_then(|r| r.policy.as_ref())
        .map_or(0, |p| p.revision);
    let (mut held, mut held_lines) = hold_connection(stack, cleanup, id).await;
    // The lab's private addresses go with it and are left out (counted), not blocked.
    let listed = "192.88.99.7/32\nfd99::1/128\n";
    let (status, body) = stack
        .send("POST", "/v1/blocklists/preview", "text/plain", listed, None)
        .await;
    assert_eq!(status, 200, "{body}");
    let preview: BlocklistPreview = serde_json::from_str(&body).unwrap();
    assert_eq!(preview.stats.special_filtered, 1, "{body}");
    assert_eq!(preview.sample, ["192.88.99.7"], "{body}");
    let (status, body) = stack
        .post(
            "/v1/blocklists",
            &serde_json::json!({
                "name": "lab-internet",
                "source": { "kind": "upload" },
                "text": listed,
                "expected_import_hash": preview.import_hash,
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    let blocklist: BlocklistView = serde_json::from_str(&body).unwrap();
    let profile_revision = stack
        .set_blocklists(security_id, 1, vec![blocklist.blocklist.id])
        .await;
    let applied = stack
        .overlay_applied(id, "blocklist applied", overlay_before)
        .await;
    assert_eq!(
        applied.running.as_ref().unwrap().generation,
        generation_now,
        "applied to the running generation"
    );
    let mut ended = Vec::new();
    let finished = tokio::time::timeout(Duration::from_secs(10), async {
        while let Ok(Some(line)) = held_lines.next_line().await {
            let last = line.starts_with("cat-status=");
            ended.push(line);
            if last {
                break;
            }
        }
    })
    .await;
    assert!(
        finished.is_ok(),
        "the open connection was not ended: {ended:?}"
    );
    assert!(
        ended.iter().any(|l| l.contains("Connection reset by peer"))
            && ended.last().map(String::as_str) == Some("cat-status=1"),
        "{ended:?}"
    );
    let _ = held.wait().await;
    let (_, out) = stack
        .exec(
            id,
            "(exec 3<>/dev/tcp/192.88.99.7/7) 2>&1 | tail -1; \
             exec 4<>/dev/tcp/fd99::1/7 && echo ping-v6 >&4 && timeout 5 head -n 1 <&4",
        )
        .await;
    assert!(out.contains("Connection refused"), "{out}");
    assert!(
        out.contains("ping-v6"),
        "the private fd99::1 was not listed: {out}"
    );
    eprintln!(
        "blocklist 192.88.99.7/32 applied live (overlay revision {}): open connection reset ({}), new one refused, fd99::1 (left out of the list) still reachable",
        applied
            .running
            .as_ref()
            .unwrap()
            .policy
            .as_ref()
            .unwrap()
            .revision,
        ended.join(" | ")
    );
    let applied_revision = applied
        .running
        .as_ref()
        .unwrap()
        .policy
        .as_ref()
        .unwrap()
        .revision;
    blocklist_detached(stack, id, security_id, profile_revision, applied_revision).await;
}

/// With the blocklist detached, 192.88.99.7 is reachable again on the same generation.
async fn blocklist_detached(
    stack: &Stack,
    id: InstanceId,
    security_id: SecurityProfileId,
    profile_revision: u64,
    applied_revision: u64,
) {
    stack
        .set_blocklists(security_id, profile_revision, Vec::new())
        .await;
    stack
        .overlay_applied(id, "blocklist detached", applied_revision)
        .await;
    let (_, out) = stack
        .exec(
            id,
            "exec 3<>/dev/tcp/192.88.99.7/7 && echo ping-internet >&3 && timeout 5 head -n 1 <&3",
        )
        .await;
    assert!(out.contains("ping-internet"), "{out}");
    eprintln!("blocklist detached: 192.88.99.7 reachable again, same generation");
}

/// An App in the sandbox fetching through the tunnel in a loop: the process, its pid inside
/// the sandbox and its "online"/"offline" lines, once it is online.
async fn start_looper(
    stack: &Stack,
    cleanup: &mut Cleanup,
    id: InstanceId,
) -> (
    Child,
    u32,
    tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
) {
    let looper_script = format!(
        "while :; do (timeout 2 bash -c \"{}\" | grep -q '\"ip\"') && echo online || echo offline; sleep 0.3; done",
        FETCH.replace('"', "\\\"")
    );
    let mut looper = Command::new(vpnd())
        .args(["sandbox-exec", "--state-dir"])
        .arg(&stack.paths.state)
        .args([
            "--instance",
            &id.to_string(),
            "--",
            "/bin/bash",
            "-c",
            &looper_script,
        ])
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    cleanup.pids.extend(looper.id());
    let mut announce = BufReader::new(looper.stderr.take().unwrap()).lines();
    let line = tokio::time::timeout(Duration::from_secs(10), announce.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // "sandbox-exec: connection … sandbox epoch …: pid <pid> (start …)"
    let app: u32 = line
        .split("pid ")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("{line}"));
    let mut lines = BufReader::new(looper.stdout.take().unwrap()).lines();
    next_line(&mut lines, "online").await;
    eprintln!("App {app} online");
    (looper, app, lines)
}

/// A managed App in strict mode, created and started through the API: the manager starts it
/// in the connection's sandbox. It reaches the lab through the tunnel and nothing else.
async fn start_managed_app(stack: &Stack, id: InstanceId) -> ManagedApp {
    let port = stack.port;
    let paths = &stack.paths;
    let (status, body) = http(
        port,
        "GET",
        "/v1/apps/executable-check?path=/bin/bash",
        &[],
        "",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let check: ExecutableCheck = serde_json::from_str(&body).unwrap();
    assert!(check.ok, "{body}");
    let managed_script = format!(
        "echo isolation: \
         $( (exec 3<>/dev/tcp/192.0.2.1/80) 2>/dev/null && echo direct-reached || echo direct-refused ) \
         $( (exec 3<>/dev/tcp/127.0.0.1/{port}) 2>/dev/null && echo ui-reached || echo ui-refused ) \
         $(test -e {vault} && echo vault-visible || echo vault-hidden) \
         state: $(ls -A {state} | tr '\\n' ' ') \
         home: $(test \"$HOME\" = \"$(pwd)\" && test -w . && echo own) \
         interfaces: $(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | sort | tr '\\n' ' ') \
         pid: $$; \
         while :; do (timeout 2 bash -c \"{fetch}\" | grep -q '\"ip\"') && echo online || echo offline; sleep 0.3; done",
        vault = paths.vault_key().display(),
        state = paths.state.display(),
        fetch = FETCH.replace('"', "\\\""),
    );
    let (status, body) = stack
        .post(
            "/v1/apps",
            &serde_json::json!({
                "instance_id": id,
                "name": "strict-probe",
                "executable": "/bin/bash",
                "args": ["-c", managed_script],
                "isolation": "strict_netns",
                "executable_sha256": check.sha256,
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    let managed: AppView = serde_json::from_str(&body).unwrap();
    let app_id = managed.spec.id;
    let (status, body) = stack
        .post(
            &format!("/v1/apps/{app_id}/actions"),
            r#"{"action":"start"}"#,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let app_log = paths.app_log(&app_id.to_string());
    let (after_isolation, isolation) = log_until(&app_log, 0, "isolation:").await;
    // VPN Manager's state directory shows only the App's own directory, which stays its HOME.
    for want in [
        "direct-refused",
        "ui-refused",
        "vault-hidden",
        "state: apps home:",
        "home: own",
        "interfaces: lo vpn0",
        "pid: 2",
    ] {
        assert!(
            isolation.contains(want),
            "missing {want:?} in {isolation:?}"
        );
    }
    let (app_offset, _) = log_until(&app_log, after_isolation, "online").await;
    let running = stack.app_status(app_id).await;
    assert_eq!(running.state, AppRunState::Running, "{running:?}");
    assert_eq!(running.isolation, Some(AppIsolation::StrictNetns));
    let managed_pid = running.pid.unwrap();
    eprintln!(
        "managed App {app_id} (strict_netns, pid {managed_pid}, {} processes): {isolation}; online",
        running.process_count.unwrap_or(0)
    );
    ManagedApp {
        id: app_id,
        log: app_log,
        offset: app_offset,
        pid: managed_pid,
    }
}

/// kill -9 of the worker: offline, then online again on the next generation, in the same
/// sandbox, the managed App not restarted. Returns the new generation's status.
async fn worker_crash(
    stack: &Stack,
    probe: &mut Probe,
    ready: &InstanceStatus,
    managed: &ManagedApp,
) -> InstanceStatus {
    let (id, app) = (probe.id, probe.app);
    let sandbox = &probe.sandbox;
    let lines = &mut probe.lines;
    let (app_id, app_log, mut app_offset, managed_pid) =
        (managed.id, &managed.log, managed.offset, managed.pid);
    // kill -9 of the worker: offline, then online again on the next generation.
    let worker = ready.running.as_ref().unwrap().pid.unwrap();
    let generation = ready.running.as_ref().unwrap().generation;
    // SAFETY: SIGKILL to the worker of this test's manager.
    unsafe {
        libc::kill(worker as libc::pid_t, libc::SIGKILL);
    }
    next_line(lines, "offline").await;
    eprintln!("worker {worker} killed (SIGKILL): App offline");
    let again = stack
        .wait_for(id, "next generation", |s| {
            s.phase == Phase::Ready
                && s.running
                    .as_ref()
                    .is_some_and(|r| r.generation > generation)
        })
        .await;
    next_line(lines, "online").await;
    assert_eq!(
        again.sandbox.as_ref().map(|s| (s.epoch, s.holder_pid)),
        Some((sandbox.epoch, sandbox.holder_pid)),
        "the same sandbox"
    );
    assert!(alive(app), "the App was not restarted");
    let next = again.running.as_ref().unwrap();
    eprintln!(
        "generation {} (worker {:?}) in the same sandbox (epoch {}): App {app} online again",
        next.generation, next.pid, sandbox.epoch
    );
    // The managed App went offline with the worker and is back without a restart.
    let (o, _) = log_until(app_log, app_offset, "offline").await;
    let (o, _) = log_until(app_log, o, "online").await;
    app_offset = o;
    let still = stack.app_status(app_id).await;
    assert_eq!(still.state, AppRunState::Running, "{still:?}");
    assert_eq!(
        still.pid,
        Some(managed_pid),
        "the managed App was not restarted"
    );
    eprintln!(
        "managed App {managed_pid}: offline while the worker was down, online again on generation {} (log at byte {app_offset})",
        next.generation
    );
    again
}

/// Stopping the managed App through the API ends its whole tree; then it is deleted.
async fn stop_managed_app(stack: &Stack, managed: &ManagedApp) {
    let port = stack.port;
    let (app_id, managed_pid) = (managed.id, managed.pid);
    // Stopping it through the API ends its whole tree.
    let tree = descendants(managed_pid);
    assert!(tree.len() >= 4, "launcher, starter, init, App: {tree:?}");
    let (status, body) = stack
        .post(
            &format!("/v1/apps/{app_id}/actions"),
            r#"{"action":"stop"}"#,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let s = stack.app_status(app_id).await;
        if s.state == AppRunState::Stopped {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{s:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for pid in &tree {
        assert!(
            gone(*pid).await,
            "pid {pid} of the managed App's tree survived"
        );
    }
    let (status, body) = http(port, "GET", &format!("/v1/apps/{app_id}"), &[], "").await;
    assert_eq!(status, 200, "{body}");
    let revision = serde_json::from_str::<AppView>(&body)
        .unwrap()
        .spec
        .meta
        .revision;
    assert_eq!(
        stack
            .mutate("DELETE", &format!("/v1/apps/{app_id}"), "", Some(revision))
            .await,
        204
    );
    eprintln!(
        "managed App stopped through the API: its tree ({} processes) is gone; App deleted",
        tree.len()
    );
}

/// A manager restart: its worker ends with it (fail closed), the sandbox and the App stay, the
/// new manager adopts the sandbox and the App is back online. Returns the adopted status.
async fn restart_manager(
    stack: &mut Stack,
    cleanup: &mut Cleanup,
    probe: &mut Probe,
    again: &InstanceStatus,
    generation: u64,
) -> InstanceStatus {
    let (id, app) = (probe.id, probe.app);
    let sandbox = &probe.sandbox;
    let lines = &mut probe.lines;
    // A manager restart: its worker ends with it (fail closed), the sandbox and the App stay,
    // the new manager adopts the sandbox and the App is back online.
    let mut old = stack.manager.take().unwrap();
    // SAFETY: SIGTERM to the manager this test started.
    unsafe {
        libc::kill(old.id().unwrap() as libc::pid_t, libc::SIGTERM);
    }
    tokio::time::timeout(Duration::from_secs(15), old.wait())
        .await
        .unwrap()
        .unwrap();
    let worker = again.running.as_ref().unwrap().pid.unwrap();
    assert!(gone(worker).await, "the worker outlived its manager");
    assert!(alive(sandbox.holder_pid) && alive(app));
    next_line(lines, "offline").await;
    eprintln!("manager stopped: worker {worker} gone, holder and App {app} alive, App offline");
    let manager = start_manager(&stack.dir, &stack.paths, cleanup).await;
    stack.manager = Some(manager);
    let adopted = stack
        .wait_for(id, "ready after the manager restart", |s| {
            s.phase == Phase::Ready
                && s.running
                    .as_ref()
                    .is_some_and(|r| r.generation > generation + 1)
        })
        .await;
    assert_eq!(
        adopted.sandbox.as_ref().map(|s| (s.epoch, s.holder_pid)),
        Some((sandbox.epoch, sandbox.holder_pid)),
        "the adopted sandbox"
    );
    next_line(lines, "online").await;
    assert!(alive(app), "the App was not restarted");
    let log = std::fs::read_to_string(stack.dir.join("manager.log")).unwrap_or_default();
    assert!(log.contains("sandbox adopted"), "{log}");
    eprintln!(
        "new manager adopted the sandbox (epoch {}): generation {}, App {app} online again",
        sandbox.epoch,
        adopted.running.as_ref().unwrap().generation
    );
    adopted
}

/// Tells the test binary to act as [`leftover_sandbox_builder`]: installation id, connection
/// id, state folder and rendezvous socket, one per line.
const LEFTOVER_ENV: &str = "VPND_TEST_LEFTOVER";

/// Not a test of its own: [`leftover_sandbox`] runs it in a process of its own, where it builds
/// a sandbox with an App inside and exits without tearing it down. The holder watches the
/// process that built it, so a sandbox built by the test process itself would count as held for
/// as long as the test runs; this one's manager is gone, as after a crash.
#[tokio::test]
#[ignore = "run by strict_connection_end_to_end in a process of its own"]
async fn leftover_sandbox_builder() {
    let Ok(args) = std::env::var(LEFTOVER_ENV) else {
        return;
    };
    let mut args = args.lines();
    let mut next = || args.next().expect("four lines").to_owned();
    let (installation_id, instance_id, state, rendezvous) = (next(), next(), next(), next());
    let lease = vpn_platform::sandbox::SandboxLease::create(
        &vpnd(),
        vpn_platform::sandbox::SandboxSpec {
            installation_id,
            instance_id,
            epoch: 1,
            mtu: 1420,
            addresses: vec![(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 9)), 32)],
            hide: vec![PathBuf::from(state)],
            xdg_runtime_dir: None,
            rendezvous: PathBuf::from(rendezvous),
            orphan_grace: Duration::from_secs(120),
        },
    )
    .await
    .unwrap();
    let app = lease
        .spawn(vpn_platform::sandbox::SpawnSpec {
            argv: vec!["/bin/sleep".into(), "600".into()],
            ..Default::default()
        })
        .await
        .unwrap()
        .pid();
    println!("LEFTOVER {} {app}", lease.holder().pid);
    // Whoever held it is gone without tearing it down.
    std::process::exit(0);
}

/// A sandbox of this installation that nobody holds, as a crash leaves it, with an App inside:
/// its connection id, rendezvous socket, holder and App.
async fn leftover_sandbox(
    paths: &Paths,
    cleanup: &mut Cleanup,
    installation: &str,
) -> (InstanceId, PathBuf, u32, u32) {
    let leftover_id = InstanceId::new();
    let leftover_socket = paths.sandbox_socket(&leftover_id.to_string());
    // Its first line, then its exit: the holder it leaves behind keeps the pipe open, so the
    // end of its output would only come with the end of the sandbox.
    let mut builder = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "leftover_sandbox_builder",
            "--ignored",
            "--nocapture",
        ])
        .env(
            LEFTOVER_ENV,
            format!(
                "{installation}\n{leftover_id}\n{}\n{}",
                paths.state.display(),
                leftover_socket.display()
            ),
        )
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(builder.stdout.take().unwrap()).lines();
    let built = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if let Some(pids) = line.strip_prefix("LEFTOVER ") {
                        break Some(pids.to_owned());
                    }
                }
                _ => break None,
            }
        }
    })
    .await
    .ok()
    .flatten()
    .expect("the builder reported its sandbox");
    assert!(builder.wait().await.unwrap().success(), "the builder");
    let mut pids = built.split(' ').map(|pid| pid.parse::<u32>().unwrap());
    let (leftover_holder, leftover_app) = (pids.next().unwrap(), pids.next().unwrap());
    cleanup.pids.push(leftover_holder);
    (leftover_id, leftover_socket, leftover_holder, leftover_app)
}

/// Recovery: the connection's sandbox is a resource, never a leftover; a leftover sandbox and a
/// dead sandbox socket are reported, and cleaned when confirmed.
async fn recovery_spares_the_sandbox(
    stack: &Stack,
    cleanup: &mut Cleanup,
    probe: &mut Probe,
    installation: &str,
    rendezvous: &Path,
) {
    let (id, app) = (probe.id, probe.app);
    let sandbox = &probe.sandbox;
    let lines = &mut probe.lines;
    let paths = &stack.paths;
    // Recovery: the connection's sandbox is a resource, never a leftover. A sandbox of this
    // installation that nobody holds — as a crash leaves it, here with an App inside — and a
    // sandbox socket nobody listens on are reported, and cleaned when confirmed.
    let report = stack.recovery().await;
    assert!(
        report
            .resources
            .sandboxes
            .iter()
            .any(|s| s.instance_id == id
                && s.epoch == sandbox.epoch
                && s.holder_pid == sandbox.holder_pid),
        "{:?}",
        report.resources
    );
    let live_socket = rendezvous.to_string_lossy().into_owned();
    assert!(
        !report
            .items
            .iter()
            .any(|i| i.kind == RecoveryKind::OrphanSandbox
                || i.path.as_deref() == Some(live_socket.as_str())),
        "{:?}",
        report.items
    );
    let (leftover_id, leftover_socket, leftover_holder, leftover_app) =
        leftover_sandbox(paths, cleanup, installation).await;
    let dead = paths.run.join("sb-00000000deadbeef.sock");
    drop(std::os::unix::net::UnixListener::bind(&dead).unwrap());
    let report = stack.recovery().await;
    let orphans: Vec<&RecoveryItem> = report
        .items
        .iter()
        .filter(|i| i.kind == RecoveryKind::OrphanSandbox)
        .collect();
    assert_eq!(orphans.len(), 1, "{:?}", report.items);
    let orphan = orphans[0];
    assert!(orphan.cleanable);
    assert_eq!(orphan.pid, Some(leftover_holder));
    assert_eq!(orphan.instance_id, Some(leftover_id));
    assert_eq!(
        orphan.path.as_deref(),
        Some(leftover_socket.to_string_lossy().as_ref())
    );
    let dead_path = dead.to_string_lossy().into_owned();
    let stale = report
        .items
        .iter()
        .find(|i| i.kind == RecoveryKind::StaleSocket && i.path.as_deref() == Some(&dead_path))
        .unwrap_or_else(|| panic!("{:?}", report.items));
    assert!(stale.cleanable && alive(leftover_holder) && alive(leftover_app));
    eprintln!(
        "recovery: the connection's sandbox listed as a resource; leftover sandbox (holder {leftover_holder}, App {leftover_app}) reported as {:?}: {}",
        orphan.kind, orphan.detail.en
    );
    let (status, body) = stack
        .post(
            "/v1/recovery/reconcile",
            &format!(r#"{{"items":["{}","{}"]}}"#, orphan.id, stale.id),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let result: ReconcileResult = serde_json::from_str(&body).unwrap();
    assert_eq!(result.actions.len(), 2, "{:?}", result.actions);
    for a in &result.actions {
        assert_eq!(a.outcome, ReconcileOutcome::Done, "{a:?}");
    }
    assert!(gone(leftover_app).await, "the leftover's App survived");
    assert!(
        gone(leftover_holder).await,
        "the leftover's holder survived"
    );
    assert!(!leftover_socket.exists() && !dead.exists());
    assert!(
        !result
            .remaining
            .iter()
            .any(|i| i.kind == RecoveryKind::OrphanSandbox || i.kind == RecoveryKind::StaleSocket),
        "{:?}",
        result.remaining
    );
    assert!(alive(sandbox.holder_pid) && alive(app));
    next_line(lines, "online").await;
    eprintln!(
        "reconcile: {}; the connection's sandbox and App {app} untouched and online",
        result
            .actions
            .iter()
            .map(|a| format!("{:?} {}", a.outcome, a.detail.en))
            .collect::<Vec<_>>()
            .join("; ")
    );
}

/// Emergency stop: the sandbox stays, closed, until the latch is cleared and the connection
/// started again.
async fn emergency_stop_keeps_the_sandbox(
    stack: &Stack,
    probe: &mut Probe,
    adopted: &InstanceStatus,
) {
    let (id, app) = (probe.id, probe.app);
    let sandbox = &probe.sandbox;
    let lines = &mut probe.lines;
    // Emergency stop: the sandbox stays, closed — the App is offline, not routed elsewhere —
    // until the user clears the latch and starts the connection again.
    let before = adopted.running.as_ref().unwrap().generation;
    assert_eq!(
        stack
            .mutate(
                "POST",
                &format!("/v1/instances/{id}/emergency-stop"),
                "",
                None
            )
            .await,
        202
    );
    let latched = stack
        .wait_for(id, "emergency stop", |s| {
            s.phase == Phase::Stopped && s.intent.emergency_latched
        })
        .await;
    assert_eq!(
        latched.sandbox.as_ref().map(|s| s.epoch),
        Some(sandbox.epoch),
        "the sandbox stays during an emergency stop"
    );
    next_line(lines, "offline").await;
    assert!(alive(sandbox.holder_pid) && alive(app));
    eprintln!("emergency stop: sandbox kept closed, App {app} offline");
    for action in ["clear_emergency", "start"] {
        assert_eq!(
            stack
                .mutate(
                    "POST",
                    &format!("/v1/instances/{id}/actions"),
                    &format!(r#"{{"action":"{action}"}}"#),
                    None,
                )
                .await,
            202,
            "{action}"
        );
    }
    stack
        .wait_for(id, "ready after clearing the emergency stop", |s| {
            s.phase == Phase::Ready && s.running.as_ref().is_some_and(|r| r.generation > before)
        })
        .await;
    next_line(lines, "online").await;
    eprintln!("emergency cleared and started: App {app} online again in the same sandbox");
}

/// Deleting the connection ends the App and the sandbox, and leaves nothing.
async fn delete_connection(
    stack: &Stack,
    probe: &Probe,
    looper: &mut Child,
    gateway_id: GatewayId,
    rendezvous: &Path,
) {
    let (id, app) = (probe.id, probe.app);
    let sandbox = &probe.sandbox;
    let paths = &stack.paths;
    // Deleting the connection ends the App and the sandbox, and leaves nothing.
    assert_eq!(
        stack
            .mutate(
                "POST",
                &format!("/v1/instances/{id}/actions"),
                r#"{"action":"stop"}"#,
                None
            )
            .await,
        202
    );
    let revision = stack.view(id).await.unwrap().spec.meta.revision;
    assert_eq!(
        stack
            .mutate(
                "DELETE",
                &format!("/v1/instances/{id}?gateways={gateway_id}"),
                "",
                Some(revision),
            )
            .await,
        204
    );
    assert!(gone(sandbox.holder_pid).await, "sandbox holder left behind");
    assert!(gone(app).await, "App left behind");
    let ended = tokio::time::timeout(Duration::from_secs(10), looper.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!ended.success(), "the App was terminated, not finished");
    assert!(!rendezvous.exists(), "rendezvous socket left behind");
    let leftovers: Vec<_> = std::fs::read_dir(&paths.run)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("sb-") || n.starts_with("c-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    eprintln!(
        "connection deleted: holder {} and App {app} gone, sandbox-exec ended with {ended}, no socket left",
        sandbox.holder_pid
    );
}

/// The App of the forward test, in Python: a TCP echo on 127.0.0.1:<port> (where the forward
/// relays TCP) and, on every address, UDP on <port> and <port>+1 answering each datagram with
/// the source it read.
const ECHO_APP: &str = r#"
import socket, sys, threading
port = int(sys.argv[1])
def serve(c):
    with c:
        while True:
            d = c.recv(4096)
            if not d:
                return
            c.sendall(d)
def tcp(t):
    while True:
        c, _ = t.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()
def udp(u):
    while True:
        d, a = u.recvfrom(2048)
        u.sendto(("from %s:%d " % (a[0], a[1])).encode() + d, a)
t = socket.socket()
t.bind(("127.0.0.1", port))
t.listen(8)
socks = []
for p in (port, port + 1):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("0.0.0.0", p))
    socks.append(u)
threading.Thread(target=tcp, args=(t,), daemon=True).start()
threading.Thread(target=udp, args=(socks[1],), daemon=True).start()
print("listening", port, flush=True)
udp(socks[0])
"#;

/// A strict connection on the lab, configured before the manager starts (it is the Store's only
/// writer then): the lab's `WireGuard` settings, a security profile that lets it reach the lab's
/// private addresses, and the connection itself, meant to run.
async fn configure_strict(paths: &Paths, lab: &LabPeer) -> (InstanceId, SecurityProfileId) {
    let client = &lab.clients[0];
    let master = vpn_platform::keystore::load_or_create_key_file(&paths.vault_key()).unwrap();
    let store = Store::open(&paths.state, &master, 1).unwrap();
    let key = store
        .put_secret(
            "wireguard_private_key".into(),
            None,
            Zeroizing::new(client.private_key.to_vec()),
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
                public_key: WgKey(client.public_key),
                addresses: vec![
                    format!("{}/32", client.address_v4).parse().unwrap(),
                    format!("{}/128", client.address_v6).parse().unwrap(),
                ],
                dns: vec![IpAddr::V4(vpn_labpeer::SERVER_V4)],
                mtu: 1420,
            },
            peer: PeerSpec {
                public_key: WgKey(lab.public_key),
                preshared_key: None,
                endpoint: lab.endpoint,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
                persistent_keepalive: Some(25),
            },
            location: None,
            expires_at: None,
        })
        .await
        .unwrap();
    let security = store
        .create(SecurityProfile {
            id: SecurityProfileId::new(),
            meta: meta(),
            name: "lab".into(),
            allow_private: vec![
                "10.99.0.0/24".parse().unwrap(),
                "fd99::/64".parse().unwrap(),
            ],
            blocked_ports: Vec::new(),
            allowed_destinations: Vec::new(),
            allowed_ports: Vec::new(),
            blocklists: Vec::new(),
            auto_ban: AutoBanSettings::default(),
        })
        .await
        .unwrap();
    let spec = store
        .create_instance(InstanceSpec {
            id: InstanceId::new(),
            meta: meta(),
            name: "strict".into(),
            profile_id: profile.id,
            dns_profile_id: None,
            security_profile_id: Some(security.id),
            purpose: InstancePurpose::General,
            limits: InstanceLimits::default(),
            strict: true,
            transport: vpn_domain::TransportRef::default(),
        })
        .await
        .unwrap();
    store
        .change_intent(spec.id, IntentChange::Start)
        .await
        .unwrap();
    (spec.id, security.id)
}

/// The manager and the controller on `paths`, once the controller answers for `id`.
async fn start_stack(dir: &Path, paths: &Paths, cleanup: &mut Cleanup, id: InstanceId) -> Stack {
    let manager = start_manager(dir, paths, cleanup).await;
    let port = free_port();
    let controller = Command::new(vpnd())
        .args(["controller", "--port", &port.to_string(), "--state-dir"])
        .arg(&paths.state)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log_file(dir, "controller.log"))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    cleanup.pids.extend(controller.id());
    let stack = Stack {
        dir: dir.to_path_buf(),
        paths: paths.clone(),
        port,
        manager: Some(manager),
        controller,
    };
    for _ in 0..100 {
        if stack.view(id).await.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    stack
}

impl Stack {
    async fn forward(&self, id: ForwardBindingId) -> ForwardView {
        let (status, body) = http(
            self.port,
            "GET",
            &format!("/v1/forward-bindings/{id}"),
            &[],
            "",
        )
        .await;
        assert_eq!(status, 200, "{body}");
        serde_json::from_str(&body).unwrap()
    }

    /// The forward once `done` holds (bounded).
    async fn forward_until(
        &self,
        id: ForwardBindingId,
        what: &str,
        done: impl Fn(&ForwardView) -> bool,
    ) -> ForwardView {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        loop {
            let v = self.forward(id).await;
            if done(&v) {
                return v;
            }
            if tokio::time::Instant::now() > deadline {
                let log = std::fs::read_to_string(self.dir.join("manager.log")).unwrap_or_default();
                panic!("{what}: {:?}\nmanager log:\n{log}", v.status);
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }
}

/// Send `data` from the lab's `from` (a fresh socket, so a fresh source port) to `to` and wait a
/// moment for an answer: `(answer, where it came from, the source port asked from)`.
async fn udp_ask(
    lab: &vpn_tunnel::Netstack,
    from: IpAddr,
    to: SocketAddr,
    data: &[u8],
) -> (Option<(String, SocketAddr)>, u16) {
    use vpn_tunnel::TunnelDatagram;
    let socket = lab
        .bind_udp_from(from, vpn_tunnel::FlowClass::Payload)
        .unwrap();
    let local = socket.local_port();
    let mut buf = vec![0u8; 2048];
    for _ in 0..3 {
        TunnelDatagram::send_to(&socket, data, to).await.unwrap();
        if let Ok(Ok((n, src))) = tokio::time::timeout(
            Duration::from_millis(700),
            TunnelDatagram::recv_from(&socket, &mut buf),
        )
        .await
        {
            return (
                Some((String::from_utf8_lossy(&buf[..n]).into_owned(), src)),
                local,
            );
        }
    }
    (None, local)
}

/// SIGTERM to the manager and the controller of `stack`, and their end.
async fn stop_stack(stack: &mut Stack) {
    // SAFETY: SIGTERM to the processes this test started.
    unsafe {
        if let Some(m) = stack.manager.as_ref().and_then(Child::id) {
            libc::kill(m as libc::pid_t, libc::SIGTERM);
        }
        if let Some(c) = stack.controller.id() {
            libc::kill(c as libc::pid_t, libc::SIGTERM);
        }
    }
    if let Some(mut m) = stack.manager.take() {
        let _ = tokio::time::timeout(Duration::from_secs(15), m.wait()).await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(15), stack.controller.wait()).await;
}

/// The UDP/TCP echo App ([`ECHO_APP`]) on `port`, managed in `id`'s sandbox, once it listens.
async fn start_echo_app(stack: &Stack, id: InstanceId, port: u16) -> AppId {
    let (status, body) = http(
        stack.port,
        "GET",
        "/v1/apps/executable-check?path=/bin/bash",
        &[],
        "",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let check: ExecutableCheck = serde_json::from_str(&body).unwrap();
    let (status, body) = stack
        .post(
            "/v1/apps",
            &serde_json::json!({
                "instance_id": id,
                "name": "udp-echo",
                "executable": "/bin/bash",
                "args": ["-c", "exec /usr/bin/python3 -u -c \"$0\" \"$1\"", ECHO_APP, port.to_string()],
                "isolation": "strict_netns",
                "executable_sha256": check.sha256,
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    let app_id = serde_json::from_str::<AppView>(&body).unwrap().spec.id;
    let (status, body) = stack
        .post(
            &format!("/v1/apps/{app_id}/actions"),
            r#"{"action":"start"}"#,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    log_until(&stack.paths.app_log(&app_id.to_string()), 0, "listening").await;
    app_id
}

/// The body of the UDP test's forward: TCP＋UDP on `port`, its UDP straight into the sandbox, to
/// `app_id`'s `target_port`.
fn forward_input(
    id: InstanceId,
    port: u16,
    app_id: AppId,
    target_port: u16,
    enabled: bool,
) -> String {
    serde_json::json!({
        "instance_id": id,
        "name": "eD2k",
        "protocol": "both",
        "tunnel_port": port,
        "public_port": port,
        "target_app_id": app_id,
        "target_port": target_port,
        "enabled": enabled,
        "max_connections": 64,
        "udp_direct": true,
    })
    .to_string()
}

/// The forward to the echo App, its UDP straight into the sandbox (refused unless the App's
/// port is the tunnel port), once it listens.
async fn create_forward(
    stack: &Stack,
    id: InstanceId,
    port: u16,
    app_id: AppId,
) -> ForwardBindingId {
    let (status, body) = stack
        .post(
            "/v1/forward-bindings",
            &forward_input(id, port, app_id, port + 1, true),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("FORWARD_UDP_DIRECT_SAME_PORT"), "{body}");
    let (status, body) = stack
        .post(
            "/v1/forward-bindings",
            &forward_input(id, port, app_id, port, true),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    let fid = serde_json::from_str::<ForwardView>(&body)
        .unwrap()
        .binding
        .id;
    let listening = stack
        .forward_until(fid, "the forward listening", |v| {
            v.status
                .as_ref()
                .is_some_and(|s| s.state == ForwardState::Listening)
        })
        .await;
    let target = listening.status.unwrap().target.unwrap();
    assert_eq!(
        target.tcp_address.as_deref(),
        Some(&*format!("127.0.0.1:{port}"))
    );
    assert_eq!(
        target.udp_address.as_deref(),
        Some(&*format!("0.0.0.0:{port}"))
    );
    fid
}

/// The forward counts both the UDP and the TCP exchange, and both are evidence from outside.
async fn forward_counts_both(stack: &Stack, fid: ForwardBindingId, answer_len: usize) {
    let answered = u64::try_from(answer_len).unwrap();
    // The forward counts both, and both are evidence from outside.
    let counted = stack
        .forward_until(fid, "the forward's counts", |v| {
            v.status.as_ref().is_some_and(|s| {
                s.reachability.udp_observed_at.is_some()
                    && s.reachability.tcp_observed_at.is_some()
                    && s.counters.as_ref().is_some_and(|c| {
                        c.accepted.0 >= 2 && c.bytes_in.0 >= 12 && c.bytes_out.0 >= answered
                    })
            })
        })
        .await;
    let c = counted.status.unwrap().counters.unwrap();
    eprintln!(
        "forward counts: accepted {}, UDP active {}, in {} B, out {} B, refused closed {}",
        c.accepted.0, c.active_udp, c.bytes_in.0, c.bytes_out.0, c.refused_closed.0
    );
    assert!(c.active_udp >= 1, "{c:?}");
}

/// A blocklisted source stays out, counted; detached, it comes in again.
async fn blocklisted_source_stays_out(
    stack: &Stack,
    remote: &vpn_tunnel::Netstack,
    (id, security): (InstanceId, SecurityProfileId),
    fid: ForwardBindingId,
    to: SocketAddr,
) {
    let internet = IpAddr::V4(vpn_labpeer::INTERNET_V4);
    // A blocklisted source stays out, counted; detached, it comes in again.
    let running = stack.view(id).await.unwrap().status.unwrap();
    let overlay_before = running
        .running
        .as_ref()
        .and_then(|r| r.policy.as_ref())
        .map_or(0, |p| p.revision);
    let listed = format!("{internet}/32\n");
    let (status, body) = stack
        .send(
            "POST",
            "/v1/blocklists/preview",
            "text/plain",
            &listed,
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let preview: BlocklistPreview = serde_json::from_str(&body).unwrap();
    let (status, body) = stack
        .post(
            "/v1/blocklists",
            &serde_json::json!({
                "name": "lab-internet",
                "source": { "kind": "upload" },
                "text": listed,
                "expected_import_hash": preview.import_hash,
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    let blocklist: BlocklistView = serde_json::from_str(&body).unwrap();
    let revision = stack
        .set_blocklists(security, 1, vec![blocklist.blocklist.id])
        .await;
    let applied = stack
        .overlay_applied(id, "blocklist applied", overlay_before)
        .await
        .running
        .unwrap()
        .policy
        .unwrap()
        .revision;
    let (answer, _) = udp_ask(remote, internet, to, b"listed").await;
    assert_eq!(answer, None, "a blocklisted source reached the App");
    stack
        .forward_until(fid, "the blocklist refusal counted", |v| {
            v.status
                .as_ref()
                .and_then(|s| s.counters.as_ref())
                .is_some_and(|c| c.refused_blocklisted.0 >= 1)
        })
        .await;
    stack.set_blocklists(security, revision, Vec::new()).await;
    stack
        .overlay_applied(id, "blocklist detached", applied)
        .await;
    let (answer, _) = udp_ask(remote, internet, to, b"again").await;
    assert!(answer.is_some_and(|(t, _)| t.ends_with(" again")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_forward_takes_udp_straight_into_the_sandbox() {
    let _serial = SERIAL.lock().await;
    if let Err(reason) = vpn_platform::sandbox::detect() {
        eprintln!("skipped: {}", reason.en);
        return;
    }
    for tool in ["/bin/bash", "/usr/bin/python3"] {
        if !Path::new(tool).exists() {
            eprintln!("skipped: {tool} missing");
            return;
        }
    }
    let mut cleanup = Cleanup::default();
    let tmp = tempfile::Builder::new()
        .prefix("vpnm-udp-")
        .tempdir()
        .unwrap();
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("ssh")).unwrap();
    let paths = Paths::under(&dir.join("s"));
    paths.ensure().unwrap();
    let lab = LabPeer::start("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let remote = lab.netstack().unwrap();
    let client = SocketAddr::new(IpAddr::V4(lab.clients[0].address_v4), 0);
    let (id, security) = configure_strict(&paths, &lab).await;
    let mut stack = start_stack(&dir, &paths, &mut cleanup, id).await;
    let ready = stack
        .wait_for(id, "strict connection ready", |s| {
            s.phase == Phase::Ready && s.sandbox.is_some()
        })
        .await;
    cleanup
        .pids
        .push(ready.sandbox.as_ref().unwrap().holder_pid);

    // A managed App in the sandbox, on a port nobody else uses: TCP on 127.0.0.1, UDP on every
    // address (as a P2P client binds Kad).
    let port: u16 = 23780;
    let at = |p: u16| SocketAddr::new(client.ip(), p);
    let app_id = start_echo_app(&stack, id, port).await;

    // No forward yet: nothing unsolicited comes in, though the App is bound on every address.
    let internet = IpAddr::V4(vpn_labpeer::INTERNET_V4);
    let (answer, _) = udp_ask(&remote, internet, at(port), b"before").await;
    assert_eq!(answer, None, "an unsolicited datagram reached the App");

    // The forward: TCP＋UDP, its UDP straight into the sandbox. The App's port must be the
    // tunnel port.
    let fid = create_forward(&stack, id, port, app_id).await;

    // A host beyond the server: its datagram reaches the App's own socket with its real source,
    // and the App's answer comes back from the forwarded port.
    let (answer, from_port) = udp_ask(&remote, internet, at(port), b"ping").await;
    let (text, answered_from) = answer.expect("the App answered");
    assert_eq!(text, format!("from {internet}:{from_port} ping"));
    assert_eq!(answered_from, at(port));
    eprintln!("UDP straight into the sandbox: the App read \"{text}\" from {answered_from}");
    // Another port of the sandbox, the App listening there too, stays closed.
    let (other, _) = udp_ask(&remote, internet, at(port + 1), b"elsewhere").await;
    assert_eq!(other, None, "a datagram to another port reached the App");
    // TCP of the same forward is relayed as ever.
    let mut tcp = remote
        .connect_tcp_from(internet, at(port), vpn_tunnel::FlowClass::Payload)
        .await
        .unwrap();
    tcp.write_all(b"tcp ping").await.unwrap();
    let mut echoed = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"tcp ping");
    drop(tcp);
    forward_counts_both(&stack, fid, text.len()).await;

    blocklisted_source_stays_out(&stack, &remote, (id, security), fid, at(port)).await;

    // Disabled, the forward lets nothing in, though the App still holds the port.
    let revision = stack.forward(fid).await.binding.meta.revision;
    let (status, body) = stack
        .send(
            "PUT",
            &format!("/v1/forward-bindings/{fid}"),
            "application/json",
            &forward_input(id, port, app_id, port, false),
            Some(revision),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    stack
        .forward_until(fid, "the forward disabled", |v| {
            v.status
                .as_ref()
                .is_some_and(|s| s.state == ForwardState::Disabled)
        })
        .await;
    let (answer, _) = udp_ask(&remote, internet, at(port), b"disabled").await;
    assert_eq!(answer, None, "a disabled forward let a datagram in");
    eprintln!("blocklisted and disabled: nothing came in; detached: in again");

    stop_stack(&mut stack).await;
    lab.shutdown().await;
}
