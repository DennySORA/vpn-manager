//! Built-in IP blocklists at the port forwards, end to end, rootless, with the real programs:
//! `vpnd manager` and `vpnd controller` on a private state directory and an in-process
//! `WireGuard` lab peer on loopback. The connection has no security profile, so it follows the
//! default policy: every enabled built-in list that has content.
//!
//! - every catalogue entry is a built-in list in the default policy (a release that adds entries
//!   creates them at start), the ones without content waiting for their first download;
//! - a list added on 2026-11-07 (CINS Army) with content as its download leaves it, disabled,
//!   guards nothing: a listed host beyond the server reaches the App through the forward over
//!   TCP and UDP;
//! - enabled through the API it applies at once, in the same generation: the listed host is
//!   refused over TCP and UDP and counted (`refused_blocklisted`), another host still comes in;
//!   disabled again, the listed host comes in again.
//!
//! Nothing needs root or changes the host. A run that fails half-way still ends what it started.

#![cfg(test)]
#![cfg_attr(
    target_os = "linux",
    expect(unsafe_code, reason = "libc kill FFI to stop the manager under test")
)]
#![cfg(target_os = "linux")]

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use vpn_domain::ipset::IpRangeSet;
use vpn_domain::*;
use vpn_labpeer::LabPeer;
use vpn_platform::paths::Paths;
use vpn_store::{IntentChange, Store};
use zeroize::Zeroizing;

/// The list this test fills, added to the catalogue on 2026-11-07.
const ADDED: &str = "cins-army";

/// A TCP echo on 127.0.0.1:<port> and a UDP echo on <port> (the forward relays both there).
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
t = socket.socket()
t.bind(("127.0.0.1", port))
t.listen(8)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("127.0.0.1", port))
threading.Thread(target=tcp, args=(t,), daemon=True).start()
print("listening", port, flush=True)
while True:
    d, a = u.recvfrom(2048)
    u.sendto(d, a)
"#;

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

/// The manager and the controller under test; both are killed when this is dropped.
struct Stack {
    dir: PathBuf,
    port: u16,
    manager: Child,
    _controller: Child,
}

impl Drop for Stack {
    /// Stop the manager instead of killing it. A killed manager leaves its Apps running (they
    /// outlive it until they are stopped); a stopped one ends them first, so the echo App does
    /// not stay behind on this host with its port — where the next run would find it.
    fn drop(&mut self) {
        let Some(pid) = self
            .manager
            .id()
            .and_then(|pid| libc::pid_t::try_from(pid).ok())
        else {
            return;
        };
        // SAFETY: SIGTERM to the manager this test started and has not yet reaped.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while matches!(self.manager.try_wait(), Ok(None)) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// One HTTP/1.0 exchange with the controller; returns (status, body). Status 0: not listening.
async fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &str,
) -> (u16, String) {
    let Ok(mut s) = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await else {
        return (0, String::new());
    };
    let mut req = format!(
        "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n",
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
    /// A GET that must succeed; its body.
    async fn get(&self, path: &str) -> String {
        let (status, body) = http(self.port, "GET", path, &[], "").await;
        assert_eq!(status, 200, "{path}: {body}");
        body
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
        http(self.port, method, path, &headers, body).await
    }

    /// The connection's status once `done` holds (bounded).
    async fn wait_for(
        &self,
        id: InstanceId,
        what: &str,
        done: impl Fn(&InstanceStatus) -> bool,
    ) -> InstanceStatus {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        loop {
            let (status, body) =
                http(self.port, "GET", &format!("/v1/instances/{id}"), &[], "").await;
            let s = (status == 200)
                .then(|| serde_json::from_str::<InstanceView>(&body).unwrap())
                .and_then(|v| v.status);
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

    /// The running generation's policy once its overlay revision passed `after` and is applied.
    async fn overlay_applied(&self, id: InstanceId, what: &str, after: u64) -> InstanceStatus {
        self.wait_for(id, what, |s| {
            s.running
                .as_ref()
                .and_then(|r| r.policy.as_ref())
                .is_some_and(|p| p.revision > after && p.applied_revision == Some(p.revision))
        })
        .await
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
            let v: ForwardView =
                serde_json::from_str(&self.get(&format!("/v1/forward-bindings/{id}")).await)
                    .unwrap();
            if done(&v) {
                return v;
            }
            assert!(
                tokio::time::Instant::now() <= deadline,
                "{what}: {:?}",
                v.status
            );
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    /// Enable or disable the built-in list `list` through the API.
    async fn set_enabled(&self, list: &BlocklistView, enabled: bool) -> BlocklistView {
        let path = format!("/v1/blocklists/{}", list.blocklist.id);
        let body = serde_json::json!({
            "name": list.blocklist.name,
            "source": list.blocklist.source,
            "enabled": enabled,
        });
        let (status, body) = self
            .send(
                "PUT",
                &path,
                &body.to_string(),
                Some(list.blocklist.meta.revision),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        serde_json::from_str(&body).unwrap()
    }
}

/// The lab connection without a security profile, meant to run, and the content of [`ADDED`]
/// as its download leaves it — listing `listed` — but disabled: configured before the manager
/// starts (the Store's only writer then).
async fn configure(paths: &Paths, lab: &LabPeer, listed: Ipv4Addr) -> InstanceId {
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
                addresses: vec![format!("{}/32", client.address_v4).parse().unwrap()],
                dns: vec![IpAddr::V4(vpn_labpeer::SERVER_V4)],
                mtu: 1420,
            },
            peer: PeerSpec {
                public_key: WgKey(lab.public_key),
                preshared_key: None,
                endpoint: lab.endpoint,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                persistent_keepalive: Some(25),
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
            name: "default policy".into(),
            profile_id: profile.id,
            dns_profile_id: None,
            security_profile_id: None,
            purpose: InstancePurpose::General,
            limits: InstanceLimits::default(),
            strict: false,
            transport: TransportRef::default(),
        })
        .await
        .unwrap();
    store
        .change_intent(spec.id, IntentChange::Start)
        .await
        .unwrap();
    // As its download leaves it (`controller::blocklists`), and turned off.
    let list = store
        .list::<Blocklist>()
        .await
        .unwrap()
        .into_iter()
        .find(|l| l.builtin.as_deref() == Some(ADDED))
        .expect("the catalogue entry is a list");
    let content = IpRangeSet::from_networks([format!("{listed}/32").parse().unwrap()]);
    let revision = list.meta.revision;
    let downloaded = Blocklist {
        stats: BlocklistStats {
            entries: 1,
            parsed_bytes: u32::try_from(content.encoded_len()).unwrap(),
            ..list.stats.clone()
        },
        content_sha256: content.digest(),
        content_updated_at: Timestamp::now(),
        enabled: false,
        ..list
    };
    store
        .update_blocklist(downloaded, revision, Some(content))
        .await
        .unwrap();
    spec.id
}

async fn start(dir: &Path, paths: &Paths, id: InstanceId) -> Stack {
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
    for _ in 0..100 {
        if paths.manager_socket().exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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
    let stack = Stack {
        dir: dir.to_path_buf(),
        port,
        manager,
        _controller: controller,
    };
    for _ in 0..100 {
        if http(port, "GET", &format!("/v1/instances/{id}"), &[], "")
            .await
            .0
            == 200
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    stack
}

/// The echo App behind the forward: managed, proxy variables of `gateway`, its executable a copy
/// of bash owned by this user (so it may be approved inside a user namespace too).
async fn start_echo_app(
    stack: &Stack,
    dir: &Path,
    id: InstanceId,
    gateway: GatewayId,
    port: u16,
) -> AppId {
    let bash = dir.join("bash");
    std::fs::copy("/bin/bash", &bash).unwrap();
    let check: ExecutableCheck = serde_json::from_str(
        &stack
            .get(&format!(
                "/v1/apps/executable-check?path={}",
                bash.display()
            ))
            .await,
    )
    .unwrap();
    let (status, body) = stack
        .send(
            "POST",
            "/v1/apps",
            &serde_json::json!({
                "instance_id": id,
                "name": "echo",
                "executable": bash,
                "args": ["-c", "exec /usr/bin/python3 -u -c \"$0\" \"$1\"", ECHO_APP, port.to_string()],
                "isolation": "proxy_env",
                "gateway_id": gateway,
                "executable_sha256": check.sha256,
            })
            .to_string(),
            None,
        )
        .await;
    assert_eq!(status, 201, "{body}");
    let app = serde_json::from_str::<AppView>(&body).unwrap().spec.id;
    let (status, body) = stack
        .send(
            "POST",
            &format!("/v1/apps/{app}/actions"),
            r#"{"action":"start"}"#,
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    app
}

/// Whether a TCP connection from `from` through the forward gets its bytes echoed.
async fn tcp_echoes(lab: &vpn_tunnel::Netstack, from: IpAddr, to: SocketAddr) -> bool {
    let attempt = async {
        let mut s = lab
            .connect_tcp_from(from, to, vpn_tunnel::FlowClass::Payload)
            .await
            .ok()?;
        s.write_all(b"tcp ping").await.ok()?;
        let mut got = [0u8; 8];
        s.read_exact(&mut got).await.ok()?;
        Some(&got == b"tcp ping")
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(3), attempt).await,
        Ok(Some(true))
    )
}

/// Whether a datagram from `from` through the forward gets echoed (three tries).
async fn udp_echoes(lab: &vpn_tunnel::Netstack, from: IpAddr, to: SocketAddr) -> bool {
    use vpn_tunnel::TunnelDatagram;
    let socket = lab
        .bind_udp_from(from, vpn_tunnel::FlowClass::Payload)
        .unwrap();
    let mut buf = vec![0u8; 2048];
    for _ in 0..3 {
        TunnelDatagram::send_to(&socket, b"udp ping", to)
            .await
            .unwrap();
        if let Ok(Ok((n, _))) = tokio::time::timeout(
            Duration::from_millis(700),
            TunnelDatagram::recv_from(&socket, &mut buf),
        )
        .await
        {
            return &buf[..n] == b"udp ping";
        }
    }
    false
}

/// Every catalogue entry is a built-in list of the default policy, all but [`ADDED`] waiting for
/// their first download; [`ADDED`] (its content in, turned off) as it stands.
async fn assert_catalogue(stack: &Stack) -> BlocklistView {
    let lists: Vec<BlocklistView> =
        serde_json::from_str(&stack.get("/v1/blocklists").await).unwrap();
    for b in builtin_blocklists::BUILTIN_BLOCKLISTS {
        let v = lists
            .iter()
            .find(|v| v.blocklist.builtin.as_deref() == Some(b.key))
            .unwrap_or_else(|| panic!("{} is not a list", b.key));
        assert_eq!(v.default_policy, v.blocklist.enabled, "{}", b.key);
        if b.key != ADDED {
            assert!(v.awaiting_content, "{}", b.key);
        }
    }
    let added = lists
        .into_iter()
        .find(|v| v.blocklist.builtin.as_deref() == Some(ADDED))
        .unwrap();
    assert!(!added.blocklist.enabled && !added.awaiting_content);
    added
}

/// A TCP＋UDP forward on `port` to the echo App, once it listens.
async fn echo_forward(stack: &Stack, dir: &Path, id: InstanceId, port: u16) -> ForwardBindingId {
    let (status, body) = stack
        .send(
            "POST",
            "/v1/gateways",
            &serde_json::json!({
                "instance_id": id, "name": "echo", "kind": "socks5", "port": free_port(),
                "udp": false, "enabled": true, "max_connections": 16,
            })
            .to_string(),
            None,
        )
        .await;
    assert_eq!(status, 201, "{body}");
    let gateway = serde_json::from_str::<GatewaySpec>(&body).unwrap().id;
    let app = start_echo_app(stack, dir, id, gateway, port).await;
    let (status, body) = stack
        .send(
            "POST",
            "/v1/forward-bindings",
            &serde_json::json!({
                "instance_id": id, "name": "echo", "protocol": "both", "tunnel_port": port,
                "public_port": port, "target_app_id": app, "target_port": port, "enabled": true,
                "max_connections": 64, "udp_direct": false,
            })
            .to_string(),
            None,
        )
        .await;
    assert_eq!(status, 201, "{body}");
    let fid = serde_json::from_str::<ForwardView>(&body)
        .unwrap()
        .binding
        .id;
    stack
        .forward_until(fid, "the forward listening", |v| {
            v.status
                .as_ref()
                .is_some_and(|s| s.state == ForwardState::Listening)
        })
        .await;
    fid
}

/// Both protocols of the forward at `to` let `from` in (or keep it out).
async fn comes_in(lab: &vpn_tunnel::Netstack, from: Ipv4Addr, to: SocketAddr, expected: bool) {
    let from = IpAddr::V4(from);
    assert_eq!(tcp_echoes(lab, from, to).await, expected, "TCP from {from}");
    assert_eq!(udp_echoes(lab, from, to).await, expected, "UDP from {from}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_builtin_list_guards_the_forwards_live() {
    // 0700 whatever the umask: the echo App's executable is copied in here, and an executable
    // in a folder others can write to is refused.
    let tmp = tempfile::Builder::new()
        .prefix("vpnm-bl-")
        .permissions(std::fs::Permissions::from_mode(0o700))
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
    // Two hosts beyond the server: one in the list, one not.
    let listed = vpn_labpeer::INTERNET_V4;
    let other = Ipv4Addr::new(192, 88, 99, 8);
    remote
        .add_address(ipnetwork::IpNetwork::new(IpAddr::V4(other), 32).unwrap())
        .unwrap();
    let id = configure(&paths, &lab, listed).await;
    let stack = start(&dir, &paths, id).await;
    let ready = stack
        .wait_for(id, "the connection ready", |s| s.phase == Phase::Ready)
        .await;
    let generation = ready.running.as_ref().unwrap().generation;
    let added = assert_catalogue(&stack).await;

    // An App behind a TCP＋UDP forward; until it answers, the forward may still be starting.
    let port: u16 = 23790;
    let fid = echo_forward(&stack, &dir, id, port).await;
    let to = SocketAddr::new(IpAddr::V4(lab.clients[0].address_v4), port);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !tcp_echoes(&remote, IpAddr::V4(other), to).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the App never answered"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // Disabled, the list guards nothing: the listed host comes in over TCP and UDP.
    comes_in(&remote, listed, to, true).await;

    // Enabled through the API: in force at once, in the same generation.
    let before = stack.wait_for(id, "running", |s| s.running.is_some()).await;
    let revision = before
        .running
        .as_ref()
        .and_then(|r| r.policy.as_ref())
        .map_or(0, |p| p.revision);
    let on = stack.set_enabled(&added, true).await;
    assert!(on.default_policy);
    let applied = stack
        .overlay_applied(id, "the list in force", revision)
        .await;
    let running = applied.running.as_ref().unwrap();
    assert_eq!(running.generation, generation, "no new generation");
    let in_force = running.policy.as_ref().unwrap();
    assert!(
        in_force.blocklists.iter().any(|l| l.id == on.blocklist.id),
        "{in_force:?}"
    );
    comes_in(&remote, listed, to, false).await;
    let counted = stack
        .forward_until(fid, "the refusals counted", |v| {
            v.status
                .as_ref()
                .and_then(|s| s.counters.as_ref())
                .is_some_and(|c| c.refused_blocklisted.0 >= 2)
        })
        .await;
    eprintln!(
        "listed host refused, counted at the forward: {:?}",
        counted
            .status
            .and_then(|s| s.counters)
            .map(|c| c.refused_blocklisted)
    );
    // Another host still comes in.
    comes_in(&remote, other, to, true).await;

    // Disabled again, the listed host comes in again — still the same generation.
    stack.set_enabled(&on, false).await;
    let applied = stack
        .overlay_applied(id, "the list out", in_force.revision)
        .await;
    assert_eq!(applied.running.unwrap().generation, generation);
    comes_in(&remote, listed, to, true).await;
}
