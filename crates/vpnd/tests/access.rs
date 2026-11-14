//! Local access ports of a strict App, end to end on Linux, rootless, with the real programs
//! (`vpnd manager`, `vpnd controller` open to the LAN, a `WireGuard` lab peer on loopback):
//!
//! - a strict App (a small Python server) listens on 127.0.0.1 inside its sandbox; before it
//!   runs, its access port is held and answers an HTTP client with a 503 and the reason;
//! - once it runs, the host reaches it at 127.0.0.1:<host port> — bytes both ways, half-close
//!   kept — while another port the App listens on inside the sandbox is not reachable from the
//!   host at all; the App's own outbound traffic still only goes through vpn0 (the lab through
//!   the tunnel by name; no direct address, no host loopback service, not even the access port);
//! - a port open to the LAN serves a client from this host's LAN address in its allow list, and
//!   refuses it (closed unread) once the list no longer has it — applied live, the App's run
//!   unchanged; the controller itself, open to the LAN, serves the same client at the LAN
//!   address;
//! - stopped, the App's port answers 503 again; deleted, the port is released.
//!
//! Nothing needs root or changes the host. A failing run still kills everything it started.

#![cfg(test)]
#![cfg_attr(
    target_os = "linux",
    expect(
        unsafe_code,
        reason = "libc kill FFI to probe and signal the daemon processes under test"
    )
)]
#![cfg(target_os = "linux")]

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use vpn_domain::*;
use vpn_labpeer::LabPeer;
use vpn_platform::paths::Paths;
use vpn_store::{IntentChange, Store};
use zeroize::Zeroizing;

fn vpnd() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vpnd"))
}

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

/// Everything this test started, killed if it fails half-way.
#[derive(Default)]
struct Cleanup {
    pids: Vec<u32>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let exe = vpnd();
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

/// One HTTP/1.0 exchange with the controller at `at`, `Host` as given; returns (status, body).
/// Status 0: nothing answered.
async fn http_at(
    at: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &str,
) -> (u16, String) {
    let Ok(mut s) = tokio::net::TcpStream::connect(at).await else {
        return (0, String::new());
    };
    let mut req = format!(
        "{method} {path} HTTP/1.0\r\nHost: {host}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        write!(req, "{k}: {v}\r\n").unwrap();
    }
    req.push_str("\r\n");
    req.push_str(body);
    if s.write_all(req.as_bytes()).await.is_err() {
        return (0, String::new());
    }
    let mut resp = Vec::new();
    #[expect(
        clippy::let_underscore_must_use,
        reason = "what arrived is parsed either way: a timeout or a reset leaves part of the answer, or none (status 0)"
    )]
    let _ = tokio::time::timeout(Duration::from_secs(30), s.read_to_end(&mut resp)).await;
    let text = String::from_utf8_lossy(&resp).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, body.to_owned())
}

struct Stack {
    dir: PathBuf,
    port: u16,
}

impl Stack {
    fn at(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.port))
    }

    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    async fn get(&self, path: &str) -> (u16, String) {
        http_at(self.at(), &self.host(), "GET", path, &[], "").await
    }

    /// A JSON mutation with the headers the API requires; returns (status, body).
    async fn send(
        &self,
        method: &str,
        path: &str,
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
        http_at(self.at(), &self.host(), method, path, &headers, body).await
    }

    async fn instance(&self, id: InstanceId) -> Option<InstanceStatus> {
        let (status, body) = self.get(&format!("/v1/instances/{id}")).await;
        (status == 200)
            .then(|| serde_json::from_str::<InstanceView>(&body).unwrap())
            .and_then(|v| v.status)
    }

    async fn app(&self, id: AppId) -> AppView {
        let (status, body) = self.get(&format!("/v1/apps/{id}")).await;
        assert_eq!(status, 200, "{body}");
        serde_json::from_str(&body).unwrap()
    }

    /// Wait (bounded) until the App's status satisfies `done`.
    async fn app_until(
        &self,
        id: AppId,
        what: &str,
        done: impl Fn(&AppStatus) -> bool,
    ) -> AppStatus {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        loop {
            let s = self.app(id).await.status;
            if let Some(s) = &s
                && done(s)
            {
                return s.clone();
            }
            if tokio::time::Instant::now() > deadline {
                let log = std::fs::read_to_string(self.dir.join("manager.log")).unwrap_or_default();
                panic!("{what}: {s:?}\nmanager log:\n{log}");
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }
}

/// Wait for a line containing `want` in a log after byte `from`; returns the offset after it and
/// the line.
async fn log_until(path: &Path, from: usize, want: &str) -> (usize, String) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if let Some(rest) = text.get(from..) {
            let mut offset = from;
            for line in rest.split_inclusive('\n') {
                offset += line.len();
                if line.ends_with('\n') && line.contains(want) {
                    return (offset, line.trim_end().to_owned());
                }
            }
        }
        assert!(
            tokio::time::Instant::now() <= deadline,
            "no {want:?} in {} after byte {from}:\n{text}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Send `data` to `at`, close the sending side, and read until the server closes.
async fn exchange(at: SocketAddr, data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(at))
        .await
        .map_err(|_elapsed| std::io::Error::other("connect timed out"))??;
    #[expect(
        clippy::let_underscore_must_use,
        reason = "a refused client may be closed before anything is written: the read below tells"
    )]
    let _ = s.write_all(data).await;
    #[expect(
        clippy::let_underscore_must_use,
        reason = "a refused client may be closed before anything is written: the read below tells"
    )]
    let _ = s.shutdown().await;
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out))
        .await
        .map_err(|_elapsed| std::io::Error::other("no answer"))??;
    Ok(out)
}

/// Inside the sandbox: two servers on 127.0.0.1 that answer after the client's EOF with their
/// name, the client's address and what it sent (half-close both ways), and one more that the
/// host must never reach; then what the App can reach on its own.
const APP: &str = r#"
import socket, sys, threading, time

APP_PORT, API_PORT, OTHER_PORT, UI_PORT, ACCESS_PORT = (int(x) for x in sys.argv[1:6])

def handle(c, addr, tag):
    data = b""
    while True:
        d = c.recv(65536)
        if not d:
            break
        data += d
    c.sendall(tag.encode() + b" " + addr[0].encode() + b" " + data)
    c.close()

def serve(port, tag):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(16)
    while True:
        c, addr = s.accept()
        threading.Thread(target=handle, args=(c, addr, tag), daemon=True).start()

for port, tag in ((APP_PORT, "app"), (API_PORT, "api"), (OTHER_PORT, "other")):
    threading.Thread(target=serve, args=(port, tag), daemon=True).start()
time.sleep(0.5)
print("listening", flush=True)

def reach(host, port):
    try:
        socket.create_connection((host, port), timeout=3).close()
        return "reached"
    except OSError:
        return "refused"

out = ["direct-" + reach("192.0.2.1", 80), "ui-" + reach("127.0.0.1", UI_PORT),
       "access-" + reach("127.0.0.1", ACCESS_PORT)]
try:
    s = socket.create_connection(("x.lab", 80), timeout=10)
    s.sendall(b"GET /ip HTTP/1.0\r\nHost: x.lab\r\n\r\n")
    body = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        body += d
    out.append("tunnel-ok" if b'"ip"' in body else "tunnel-bad")
except OSError as e:
    out.append("tunnel-failed:" + str(e))
ifaces = sorted(l.split(":")[0].strip() for l in open("/proc/net/dev").read().splitlines()[2:])
print("outbound:", " ".join(out), "interfaces:", " ".join(ifaces), flush=True)
while True:
    time.sleep(3600)
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_app_ports_reach_the_host_and_nothing_else() {
    if let Err(reason) = vpn_platform::sandbox::detect() {
        eprintln!("skipped: {}", reason.en);
        return;
    }
    let python = PathBuf::from("/usr/bin/python3");
    if !python.exists() {
        eprintln!("skipped: /usr/bin/python3 missing");
        return;
    }
    // This host's LAN address stands in for a client on the LAN (it never leaves the host).
    let lan: Option<IpAddr> = vpn_platform::netif::reachable_addresses()
        .unwrap()
        .into_iter()
        .find(IpAddr::is_ipv4);
    let mut cleanup = Cleanup::default();
    let tmp = tempfile::Builder::new()
        .prefix("vpnm-acc-")
        .tempdir()
        .unwrap();
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("ssh")).unwrap();
    let paths = Paths::under(&dir.join("s"));
    paths.ensure().unwrap();

    let lab = LabPeer::start("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let id = configure_access(&paths, &lab).await;
    let (manager, controller, stack) =
        start_access_stack(&dir, &paths, &mut cleanup, lan, id).await;
    let port = stack.port;
    lan_controller(port, lan).await;

    // The App: its web UI (17890) on loopback, its API (17891) open to this host's LAN address,
    // and a third port (17892) it does not publish.
    let (status, body) = stack
        .get("/v1/apps/executable-check?path=/usr/bin/python3")
        .await;
    assert_eq!(status, 200, "{body}");
    let check: ExecutableCheck = serde_json::from_str(&body).unwrap();
    assert!(check.ok, "{body}");
    let plan = AppPlan {
        id,
        app_port: 17890,
        api_port: 17891,
        other_port: 17892,
        controller_port: port,
        ui_host: free_port(),
        api_host: free_port(),
        sha256: check.sha256,
    };
    let lan_allow: Vec<String> = lan.map(|l| format!("{l}/32")).into_iter().collect();
    let app = create_app(&stack, &plan, &lan_allow).await;
    let ui_host = plan.ui_host;
    let ui: SocketAddr = (Ipv4Addr::LOCALHOST, ui_host).into();

    held_then_started(&stack, app, ui, ui_host).await;
    let app_log = paths.app_log(&app.to_string());
    let (offset, _) = log_until(&app_log, 0, "listening").await;

    relayed_both_ways(&stack, &plan, app, ui, &app_log).await;

    // The App's own traffic: the lab through the tunnel by name, nothing else.
    let (_, outbound) = log_until(&app_log, offset, "outbound:").await;
    for want in [
        "direct-refused",
        "ui-refused",
        "access-refused",
        "tunnel-ok",
        "interfaces: lo vpn0",
    ] {
        assert!(outbound.contains(want), "missing {want:?} in {outbound:?}");
    }
    eprintln!("inside the sandbox: {outbound}");

    let serving = stack
        .app_until(app, "serving, the App seen listening", |s| {
            s.access
                .first()
                .is_some_and(|a| a.state == AccessState::Serving && a.app_listening == Some(true))
        })
        .await;
    assert!(serving.access[0].accepted >= 2, "{:?}", serving.access);
    assert_eq!(serving.access[0].last_error, None);

    lan_access(&stack, &plan, app, lan, &serving).await;

    stop_and_delete(&stack, &plan, app, ui).await;

    for child in [manager, controller] {
        if let Some(pid) = child.id() {
            // SAFETY: SIGTERM to a process this test started.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
        let mut child = child;
        #[expect(
            clippy::let_underscore_must_use,
            reason = "a bounded wait for the end: one still running is killed when dropped (`kill_on_drop`)"
        )]
        let _ = tokio::time::timeout(Duration::from_secs(15), child.wait()).await;
    }
    for pid in &cleanup.pids {
        let _ = alive(*pid);
    }
    lab.shutdown().await;
}

/// Not running, the App's port is held and an HTTP client is told why; then it is started.
async fn held_then_started(stack: &Stack, app: AppId, ui: SocketAddr, ui_host: u16) {
    // Not running: the port is held, and an HTTP client is told why.
    stack
        .app_until(app, "access port held", |s| {
            s.access.len() == 2 && s.access.iter().all(|a| a.listening)
        })
        .await;
    // Told in the language the request asks for.
    let request = b"GET / HTTP/1.1\r\nHost: x\r\nAccept-Language: zh-TW,en;q=0.8\r\n\r\n";
    let answer = exchange(ui, request).await.unwrap();
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");
    assert!(answer.contains("沒有在執行"), "{answer}");
    eprintln!("App stopped: 127.0.0.1:{ui_host} held, HTTP answered 503 with the reason");

    let (status, body) = stack
        .send(
            "POST",
            &format!("/v1/apps/{app}/actions"),
            r#"{"action":"start"}"#,
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
}

/// The test's strict connection on the lab, stored before the manager starts.
async fn configure_access(paths: &Paths, lab: &LabPeer) -> InstanceId {
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
            transport: TransportRef::default(),
        })
        .await
        .unwrap();
    store
        .change_intent(spec.id, IntentChange::Start)
        .await
        .unwrap();
    spec.id
}

/// The manager and the controller (open to the LAN for `lan` only), once the strict connection
/// `id` is ready.
async fn start_access_stack(
    dir: &Path,
    paths: &Paths,
    cleanup: &mut Cleanup,
    lan: Option<IpAddr>,
    id: InstanceId,
) -> (Child, Child, Stack) {
    let manager = Command::new(vpnd())
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
    cleanup.pids.extend(manager.id());
    for _ in 0..100 {
        if paths.manager_socket().exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // The controller, open to the LAN for this host's own LAN address only.
    let port = free_port();
    let mut args = vec!["controller".to_string(), "--port".into(), port.to_string()];
    if let Some(lan) = lan {
        args.extend([
            "--listen-address".into(),
            "0.0.0.0".into(),
            "--allow-client".into(),
            format!("{lan}/32"),
        ]);
    }
    let controller = Command::new(vpnd())
        .args(&args)
        .arg("--state-dir")
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
        port,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(s) = stack.instance(id).await
            && s.phase == Phase::Ready
            && s.sandbox.is_some()
        {
            cleanup.pids.push(s.sandbox.as_ref().unwrap().holder_pid);
            break;
        }
        if tokio::time::Instant::now() > deadline {
            let log = std::fs::read_to_string(dir.join("manager.log")).unwrap_or_default();
            panic!("strict connection not ready\n{log}");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    eprintln!("strict connection ready");
    (manager, controller, stack)
}

/// The controller open to the LAN: this host's LAN address is a Host it serves there, for a
/// client from that address (which is this user's program, on this host).
async fn lan_controller(port: u16, lan: Option<IpAddr>) {
    if let Some(lan) = lan {
        let at = SocketAddr::new(lan, port);
        let (status, body) = http_at(
            at,
            &format!("{lan}:{port}"),
            "GET",
            "/v1/system/status",
            &[],
            "",
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let system: SystemStatus = serde_json::from_str(&body).unwrap();
        assert_eq!(system.controller_listen, "0.0.0.0");
        assert_eq!(system.controller_allow_clients, [format!("{lan}/32")]);
        assert!(
            system.host_addresses.contains(&lan.to_string()),
            "{system:?}"
        );
        // A name is still refused (no DNS rebinding), at the LAN address too.
        let (status, _) = http_at(
            at,
            &format!("pc.example:{port}"),
            "GET",
            "/v1/system/status",
            &[],
            "",
        )
        .await;
        assert_eq!(status, 403);
        eprintln!(
            "controller open to the LAN: served at {at} with Host {lan}:{port}; a name refused"
        );
    }
}

/// The test App: its ports and how it is created.
struct AppPlan {
    id: InstanceId,
    app_port: u16,
    api_port: u16,
    other_port: u16,
    controller_port: u16,
    ui_host: u16,
    api_host: u16,
    sha256: Option<String>,
}

impl AppPlan {
    /// The App's access ports: its web UI on loopback, its API open to `allow` (on loopback
    /// when `allow` is empty).
    fn access(&self, allow: &[String]) -> Vec<serde_json::Value> {
        let mut ports = vec![serde_json::json!({
            "app_port": self.app_port, "host_port": self.ui_host, "bind": "loopback"
        })];
        ports.push(if allow.is_empty() {
            serde_json::json!({
                "app_port": self.api_port, "host_port": self.api_host, "bind": "loopback"
            })
        } else {
            serde_json::json!({
                "app_port": self.api_port, "host_port": self.api_host, "bind": "lan", "allow": allow
            })
        });
        ports
    }

    /// The App as the API creates it.
    fn input(&self, allow: &[String]) -> serde_json::Value {
        serde_json::json!({
            "instance_id": self.id,
            "name": "p2p",
            "executable": "/usr/bin/python3",
            "args": [
                "-c", APP,
                self.app_port.to_string(), self.api_port.to_string(), self.other_port.to_string(),
                self.controller_port.to_string(), self.ui_host.to_string(),
            ],
            "isolation": "strict_netns",
            "executable_sha256": self.sha256,
            "access_ports": self.access(allow),
        })
    }
}

/// Refused on a non-strict App, and on a Gateway's or a taken port; then created.
async fn create_app(stack: &Stack, plan: &AppPlan, lan_allow: &[String]) -> AppId {
    // Refused on a non-strict App, and on a Gateway's or a taken port.
    let mut proxy = plan.input(lan_allow);
    proxy["isolation"] = "proxy_env".into();
    let (status, body) = stack
        .send("POST", "/v1/apps", &proxy.to_string(), None)
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("APP_ACCESS_STRICT_ONLY"), "{body}");
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut taken = plan.input(lan_allow);
    taken["access_ports"][0]["host_port"] = squatter.local_addr().unwrap().port().into();
    let (status, body) = stack
        .send("POST", "/v1/apps", &taken.to_string(), None)
        .await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("PORT_HELD"), "{body}");
    drop(squatter);

    let (status, body) = stack
        .send("POST", "/v1/apps", &plan.input(lan_allow).to_string(), None)
        .await;
    assert_eq!(status, 201, "{body}");
    let created: AppView = serde_json::from_str(&body).unwrap();
    created.spec.id
}

/// The host reaches the App's published port both ways, and not the sandbox's other port.
async fn relayed_both_ways(
    stack: &Stack,
    plan: &AppPlan,
    app: AppId,
    ui: SocketAddr,
    app_log: &Path,
) {
    let (app_port, other_port, ui_host) = (plan.app_port, plan.other_port, plan.ui_host);
    // The host reaches the App's published port: both ways, the reply after the client's EOF.
    let echoed = match exchange(ui, b"hello from the host").await {
        Ok(e) => e,
        Err(e) => {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let status = stack.app(app).await.status;
            panic!(
                "{e}\nstatus: {status:?}\napp log:\n{}\nmanager log:\n{}",
                std::fs::read_to_string(app_log).unwrap_or_default(),
                std::fs::read_to_string(stack.dir.join("manager.log")).unwrap_or_default()
            );
        }
    };
    assert_eq!(
        String::from_utf8_lossy(&echoed),
        "app 127.0.0.1 hello from the host",
        "the App sees the relay on its own loopback"
    );
    // A bigger exchange, both directions in flight.
    let big: Vec<u8> = (0..512 * 1024)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let back = exchange(ui, &big).await.unwrap();
    assert_eq!(&back[..b"app 127.0.0.1 ".len()], b"app 127.0.0.1 ");
    assert_eq!(&back[b"app 127.0.0.1 ".len()..], &big[..]);
    // The other port the App listens on inside the sandbox is not on the host.
    let other = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, other_port)).await;
    assert!(
        other.is_err(),
        "the sandbox's port {other_port} reached from the host"
    );
    eprintln!(
        "127.0.0.1:{ui_host} → App {app_port}: relayed both ways (512 KiB, half-close); sandbox port {other_port} unreachable from the host"
    );
}

/// The port open to the LAN: a client from this host's LAN address, in the list, is served;
/// with the list changed live, refused, and the App runs on.
async fn lan_access(
    stack: &Stack,
    plan: &AppPlan,
    app: AppId,
    lan: Option<IpAddr>,
    serving: &AppStatus,
) {
    let (api_port, api_host) = (plan.api_port, plan.api_host);
    // The port open to the LAN: a client from this host's LAN address, in the list, is served.
    if let Some(lan) = lan {
        let at = SocketAddr::new(lan, api_host);
        let echoed = exchange(at, b"hello from the lan").await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&echoed),
            "api 127.0.0.1 hello from the lan"
        );
        // Loopback reaches it too (this user's program).
        let echoed = exchange((Ipv4Addr::LOCALHOST, api_host).into(), b"x")
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&echoed), "api 127.0.0.1 x");
        eprintln!("{at} → App {api_port}: served for an allowed LAN address");

        // The list without that address, applied live: refused before anything is read, and
        // the App runs on with its configuration current.
        let view = stack.app(app).await;
        let mut changed = plan.input(&["10.250.0.0/16".to_string()]);
        changed["executable_sha256"] = serde_json::Value::Null;
        let (status, body) = stack
            .send(
                "PUT",
                &format!("/v1/apps/{app}"),
                &changed.to_string(),
                Some(view.spec.meta.revision),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let updated: AppView = serde_json::from_str(&body).unwrap();
        let refused = exchange(at, b"hello from the lan").await;
        assert!(
            matches!(&refused, Ok(b) if b.is_empty()) || refused.is_err(),
            "{refused:?}"
        );
        let after = stack
            .app_until(app, "refusal counted", |s| s.access[1].refused >= 1)
            .await;
        let why = after.access[1].last_refused.as_ref().unwrap();
        assert!(why.message.zh_tw.contains("不在允許連入的網段"), "{why:?}");
        assert_eq!(
            after.run_revision,
            Some(updated.spec.meta.revision),
            "an access-only change applies to the running App"
        );
        assert_eq!(after.pid, serving.pid, "not restarted");
        eprintln!(
            "{at}: refused once the allow list no longer has it ({}), live",
            why.message.en
        );
    } else {
        eprintln!("no LAN address on this host: the LAN part is skipped");
    }
}

/// Stopped: refused with the reason again. Deleted: the ports are free.
async fn stop_and_delete(stack: &Stack, plan: &AppPlan, app: AppId, ui: SocketAddr) {
    let (ui_host, api_host) = (plan.ui_host, plan.api_host);
    // Stopped: refused with the reason again. Deleted: the port is free.
    let (status, body) = stack
        .send(
            "POST",
            &format!("/v1/apps/{app}/actions"),
            r#"{"action":"stop"}"#,
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    stack
        .app_until(app, "stopped", |s| {
            s.state == AppRunState::Stopped
                && s.access
                    .first()
                    .is_some_and(|a| a.state == AccessState::AppStopped)
        })
        .await;
    let answer = exchange(ui, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 503"));
    let revision = stack.app(app).await.spec.meta.revision;
    let (status, body) = stack
        .send("DELETE", &format!("/v1/apps/{app}"), "", Some(revision))
        .await;
    assert_eq!(status, 204, "{body}");
    std::net::TcpListener::bind(ui).expect("the port is released with the App");
    std::net::TcpListener::bind(("0.0.0.0", api_host)).expect("so is the LAN one");
    eprintln!("App stopped: 503 again; deleted: ports {ui_host} and {api_host} released");
}
