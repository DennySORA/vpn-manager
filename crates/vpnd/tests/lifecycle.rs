//! Lifecycle end to end with the real programs — `vpnd manager`, `vpnd controller` and the
//! workers they start — on a private state directory, against in-process `WireGuard` lab peers on
//! loopback. Both platforms; no root, nothing on the host changes, nothing outside the test's own
//! directories is touched.
//!
//! - A stop the Store cannot take (another process holds the database's write lock) closes the
//!   connection, says it is not on disk, and stays in force across a controller restart. The
//!   manager is then killed, and later stopped normally while another such stop is pending: each
//!   time the next manager keeps the connection closed in `recovery_required` — it never
//!   reconnects from the old `running` intent — until the user clears the emergency, stops it or
//!   starts it. A stop that did reach the disk comes back stopped, and nothing more.
//! - A controller killed while a connection runs changes nothing for it: same worker and
//!   generation, an open flow and new ones keep going; the next controller only reads the
//!   manager's state — no operation, no intent write, no generation.
//! - Two connections with the same tunnel addresses and the same DNS server address, each against
//!   its own lab peer, never cross: names resolve, and TCP and UDP flow, only through their own
//!   tunnel. One's worker killed, then the connection stopped, leaves the other's worker, rules
//!   and flows exactly as they were.

#![allow(
    unsafe_code,
    reason = "libc kill FFI to probe and signal the daemon processes under test"
)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures: clippy.toml allows unwrap/expect in #[test] fns, not in the helper fns of a tests/ crate"
)]

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use ipnetwork::IpNetwork;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use vpn_domain::*;
use vpn_labpeer::LabPeer;
use vpn_platform::paths::Paths;
use vpn_store::{IntentChange, Store};
use vpn_tunnel::FlowClass;
use zeroize::Zeroizing;

const STOP_NOT_CONFIRMED: &str = "STOP_NOT_CONFIRMED";
/// A port inside each lab tunnel that answers with the lab peer's own name.
const WHOAMI_PORT: u16 = 8000;
/// The lab peers' second DNS service (this test's own): it answers with the peer's own address
/// and records what it was asked.
const DNS_PORT: u16 = 5353;

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

fn log_file(dir: &Path, name: &str) -> Stdio {
    Stdio::from(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(name))
            .unwrap(),
    )
}

// ---------------------------------------------------------------------------------------------
// Lab peers
// ---------------------------------------------------------------------------------------------

/// A lab peer, with two services of this test inside its tunnel: `WHOAMI_PORT` answers with the
/// peer's name, and a DNS service on `DNS_PORT` answers every A question with the peer's own
/// extra address (which only this peer has) and records the names it was asked.
struct Lab {
    peer: LabPeer,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Lab {
    async fn start(name: &'static str, own: Ipv4Addr) -> Self {
        Self::start_dropping(name, own, Duration::ZERO).await
    }

    /// Like `start`, but its DNS service leaves every query unanswered for `silent` after the
    /// first one arrives (long enough for a whole probe, with its retries, to fail).
    async fn start_dropping(name: &'static str, own: Ipv4Addr, silent: Duration) -> Self {
        let peer = LabPeer::start("127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        let net = peer.netstack().unwrap();
        net.add_address(IpNetwork::new(IpAddr::V4(own), 32).unwrap())
            .unwrap();
        let mut whoami = net.listen_tcp(WHOAMI_PORT, 8, FlowClass::Payload).unwrap();
        tokio::spawn(async move {
            while let Ok(mut s) = whoami.accept().await {
                tokio::spawn(async move {
                    let _ = s.write_all(format!("{name}\n").as_bytes()).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        let dns = net.bind_udp_port(DNS_PORT, FlowClass::Payload).unwrap();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = asked.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut first: Option<std::time::Instant> = None;
            while let Ok((n, from)) = dns.recv_from(&mut buf).await {
                if first.get_or_insert_with(std::time::Instant::now).elapsed() < silent {
                    continue;
                }
                if let Some((names, reply)) = dns_reply(&buf[..n], own) {
                    log.lock().unwrap().extend(names);
                    let _ = dns.send_to(&reply, from).await;
                }
            }
        });
        Self { peer, asked }
    }

    fn was_asked(&self, name: &str) -> bool {
        self.asked.lock().unwrap().iter().any(|n| n == name)
    }
}

/// Answer every A question with `own`, anything else (the probe's `. NS`) with no data; returns
/// the names asked (lower case, no final dot) and the reply.
fn dns_reply(query: &[u8], own: Ipv4Addr) -> Option<(Vec<String>, Vec<u8>)> {
    let q = Message::from_vec(query).ok()?;
    if q.metadata.message_type != MessageType::Query {
        return None;
    }
    let mut r = Message::response(q.metadata.id, q.metadata.op_code);
    r.metadata.recursion_desired = q.metadata.recursion_desired;
    r.metadata.recursion_available = true;
    let mut names = Vec::new();
    for question in &q.queries {
        r.add_query(question.clone());
        let name = question.name().clone();
        names.push(name.to_string().trim_end_matches('.').to_ascii_lowercase());
        if question.query_type() == RecordType::A {
            r.add_answer(Record::from_rdata(name, 60, RData::A(A(own))));
        }
    }
    Some((names, r.to_vec().ok()?))
}

// ---------------------------------------------------------------------------------------------
// Configuration, written before the manager starts (it is the Store's only writer then)
// ---------------------------------------------------------------------------------------------

/// One connection to configure: its lab peer, its Gateway port and whether to use the shared
/// DNS profile (the lab's own DNS on `DNS_PORT`) instead of the profile's resolver.
struct Wanted<'a> {
    name: &'a str,
    lab: &'a LabPeer,
    gateway_port: u16,
    shared_dns: bool,
}

/// `w`'s `WireGuard` profile on its lab, with its private key in the vault.
async fn store_lab_profile(store: &Store, w: &Wanted<'_>) -> ProfileId {
    let client = &w.lab.clients[0];
    let key = store
        .put_secret(
            "wireguard_private_key".into(),
            None,
            Zeroizing::new(client.private_key.to_vec()),
            None,
        )
        .await
        .unwrap();
    store
        .create(RuntimeProfile {
            id: ProfileId::new(),
            meta: meta(),
            name: w.name.into(),
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
                public_key: WgKey(w.lab.public_key),
                preshared_key: None,
                endpoint: w.lab.endpoint,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
                persistent_keepalive: Some(25),
            },
            location: None,
            expires_at: None,
        })
        .await
        .unwrap()
        .id
}

/// Store the connections (each running, with a SOCKS5 Gateway with UDP), all on one security
/// profile that allows the lab networks and, where asked, one DNS profile. Returns their ids.
async fn configure(paths: &Paths, wanted: &[Wanted<'_>]) -> Vec<InstanceId> {
    let master = vpn_platform::keystore::load_or_create_key_file(&paths.vault_key()).unwrap();
    let store = Store::open(&paths.state, &master, 1).unwrap();
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
    // The same resolver address for every connection that uses it.
    let dns = store
        .create(DnsProfile {
            id: DnsProfileId::new(),
            meta: meta(),
            name: "lab".into(),
            servers: vec![DnsServer::Udp {
                address: SocketAddr::new(IpAddr::V4(vpn_labpeer::SERVER_V4), DNS_PORT),
            }],
            cache: DnsCacheSettings::default(),
            query_timeout_ms: 3000,
            attempts: 2,
            on_failure: DnsOnFailure::default(),
        })
        .await
        .unwrap();
    let mut ids = Vec::new();
    for w in wanted {
        let profile = store_lab_profile(&store, w).await;
        let spec = store
            .create_instance(InstanceSpec {
                id: InstanceId::new(),
                meta: meta(),
                name: w.name.into(),
                profile_id: profile,
                dns_profile_id: w.shared_dns.then_some(dns.id),
                security_profile_id: Some(security.id),
                purpose: InstancePurpose::General,
                limits: InstanceLimits::default(),
                strict: false,
                transport: vpn_domain::TransportRef::default(),
            })
            .await
            .unwrap();
        store
            .create(GatewaySpec {
                id: GatewayId::new(),
                meta: meta(),
                instance_id: spec.id,
                name: format!("{} socks", w.name),
                kind: GatewayKind::Socks5,
                port: w.gateway_port,
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
        ids.push(spec.id);
    }
    ids
}

// ---------------------------------------------------------------------------------------------
// The stack under test
// ---------------------------------------------------------------------------------------------

struct Stack {
    dir: PathBuf,
    paths: Paths,
    /// The controller's loopback port.
    port: u16,
    manager: Option<Child>,
    controller: Option<Child>,
}

impl Stack {
    fn new(dir: &Path) -> Self {
        std::fs::create_dir_all(dir.join("ssh")).unwrap();
        let paths = Paths::under(&dir.join("s"));
        paths.ensure().unwrap();
        Self {
            dir: dir.to_path_buf(),
            paths,
            port: free_port(),
            manager: None,
            controller: None,
        }
    }

    async fn start_manager(&mut self) {
        assert!(self.manager.is_none());
        let _ = std::fs::remove_file(self.paths.manager_socket());
        let child = Command::new(vpnd())
            .args(["manager", "--state-dir"])
            .arg(&self.paths.state)
            // Never the user's own ~/.ssh.
            .arg("--ssh-dir")
            .arg(self.dir.join("ssh"))
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log_file(&self.dir, "manager.log"))
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        self.manager = Some(child);
        for _ in 0..100 {
            if self.paths.manager_socket().exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the manager did not come up\n{}", self.log("manager.log"));
    }

    async fn start_controller(&mut self) {
        assert!(self.controller.is_none());
        let child = Command::new(vpnd())
            .args([
                "controller",
                "--port",
                &self.port.to_string(),
                "--state-dir",
            ])
            .arg(&self.paths.state)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log_file(&self.dir, "controller.log"))
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        self.controller = Some(child);
        for _ in 0..100 {
            if http(self.port, "GET", "/v1/instances", &[], "").await.0 == 200 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "the controller did not come up\n{}",
            self.log("controller.log")
        );
    }

    /// SIGKILL: nothing of the process's own shutdown runs.
    async fn kill(child: &mut Option<Child>) {
        let mut c = child.take().expect("running");
        c.start_kill().unwrap();
        c.wait().await.unwrap();
    }

    /// SIGTERM, as a service manager stops it; waits for its normal exit.
    async fn terminate(child: &mut Option<Child>) -> std::process::ExitStatus {
        let mut c = child.take().expect("running");
        // SAFETY: SIGTERM to a process this test started.
        unsafe {
            libc::kill(c.id().unwrap() as libc::pid_t, libc::SIGTERM);
        }
        tokio::time::timeout(Duration::from_secs(30), c.wait())
            .await
            .expect("exited in time")
            .unwrap()
    }

    fn log(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.join(name)).unwrap_or_default()
    }

    async fn view(&self, id: InstanceId) -> Option<InstanceView> {
        let (status, body) = http(self.port, "GET", &format!("/v1/instances/{id}"), &[], "").await;
        (status == 200).then(|| serde_json::from_str(&body).unwrap())
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
            assert!(
                tokio::time::Instant::now() <= deadline,
                "{what}: {status:?}\nmanager log:\n{}",
                self.log("manager.log")
            );
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    async fn ready(&self, id: InstanceId) -> InstanceStatus {
        self.wait_for(id, "connection ready", |s| s.phase == Phase::Ready)
            .await
    }

    /// A mutation with the headers the API requires; returns (status, body).
    async fn post(&self, path: &str, body: &str) -> (u16, String) {
        let headers = [
            ("Origin", format!("http://127.0.0.1:{}", self.port)),
            ("Idempotency-Key", uuid::Uuid::new_v4().to_string()),
        ];
        http(self.port, "POST", path, &headers, body).await
    }

    /// A lifecycle action; returns (status, body).
    async fn act(&self, id: InstanceId, action: &str) -> (u16, String) {
        self.post(
            &format!("/v1/instances/{id}/actions"),
            &format!(r#"{{"action":"{action}"}}"#),
        )
        .await
    }

    /// Stop or emergency-stop; returns the 202 body.
    async fn stop(&self, id: InstanceId, emergency: bool) -> Accepted {
        let (status, body) = if emergency {
            self.post(&format!("/v1/instances/{id}/emergency-stop"), "{}")
                .await
        } else {
            self.act(id, "stop").await
        };
        assert_eq!(status, 202, "{body}");
        serde_json::from_str(&body).unwrap()
    }

    fn marker(&self, id: InstanceId) -> PathBuf {
        self.paths.state.join("pending-stops").join(id.to_string())
    }

    /// The intent row as stored (read by this process, as any SQLite reader can).
    fn stored(&self, id: InstanceId) -> (String, u64, u64) {
        let c = rusqlite::Connection::open(self.paths.state.join(vpn_store::CONTROL_FILE)).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.query_row(
            "SELECT desired, intent_revision, next_generation FROM instance_intents WHERE instance_id = ?1",
            [id.to_string()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get::<_, i64>(1)?.cast_unsigned(),
                    r.get::<_, i64>(2)?.cast_unsigned(),
                ))
            },
        )
        .unwrap()
    }

    /// Another process holds the control database's write lock: every write of the manager's
    /// Store fails (busy) while reads go on, as when the Store cannot take a write.
    fn lock_writes(&self) -> rusqlite::Connection {
        let c = rusqlite::Connection::open(self.paths.state.join(vpn_store::CONTROL_FILE)).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.execute_batch("BEGIN EXCLUSIVE").unwrap();
        c
    }
}

/// One HTTP/1.0 exchange with the controller; returns (status, body). Status 0: nothing listens.
async fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &str,
) -> (u16, String) {
    let Ok(mut s) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await else {
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
    if s.write_all(req.as_bytes()).await.is_err() {
        return (0, String::new());
    }
    let mut resp = Vec::new();
    if s.read_to_end(&mut resp).await.is_err() {
        return (0, String::new());
    }
    let text = String::from_utf8_lossy(&resp).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, body.to_owned())
}

fn error_code(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body).unwrap()["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn fault(s: &InstanceStatus) -> Option<&str> {
    s.recovery.last_fault.as_ref().map(|f| f.code.as_str())
}

// ---------------------------------------------------------------------------------------------
// Through a Gateway
// ---------------------------------------------------------------------------------------------

/// Where a SOCKS5 CONNECT goes.
enum Target<'a> {
    Name(&'a str, u16),
    Addr(SocketAddr),
}

/// SOCKS5 CONNECT through the Gateway on `port`; Err when the TCP connection or the request is
/// refused (a stopped connection's listener refuses every request, SOCKS5 reply 2).
async fn socks(port: u16, target: Target<'_>) -> Result<TcpStream, String> {
    let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    s.write_all(&[5, 1, 0]).await.map_err(|e| e.to_string())?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await.map_err(|e| e.to_string())?;
    if sel != [5, 0] {
        return Err(format!("method selection {sel:?}"));
    }
    let mut req = vec![5, 1, 0];
    match target {
        Target::Name(host, p) => {
            req.push(3);
            req.push(u8::try_from(host.len()).unwrap());
            req.extend_from_slice(host.as_bytes());
            req.extend_from_slice(&p.to_be_bytes());
        }
        Target::Addr(SocketAddr::V4(a)) => {
            req.push(1);
            req.extend_from_slice(&a.ip().octets());
            req.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Addr(SocketAddr::V6(a)) => {
            req.push(4);
            req.extend_from_slice(&a.ip().octets());
            req.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    s.write_all(&req).await.map_err(|e| e.to_string())?;
    let mut reply = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut reply))
        .await
        .map_err(|_| "no SOCKS5 reply".to_string())?
        .map_err(|e| e.to_string())?;
    if reply[1] != 0 {
        return Err(format!("SOCKS5 reply {}", reply[1]));
    }
    let rest = match reply[3] {
        1 => 6,
        4 => 18,
        t => return Err(format!("address type {t}")),
    };
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).await.map_err(|e| e.to_string())?;
    Ok(s)
}

/// Everything the target sends until it closes.
async fn read_all(mut s: TcpStream) -> Result<String, String> {
    let mut out = String::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_string(&mut out))
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// `GET http://x.lab/ip` through the Gateway (the name resolved by the connection's resolver).
async fn fetch(port: u16) -> Result<String, String> {
    let mut s = socks(port, Target::Name("x.lab", 80)).await?;
    s.write_all(b"GET /ip HTTP/1.0\r\nHost: x.lab\r\n\r\n")
        .await
        .map_err(|e| e.to_string())?;
    let body = read_all(s).await?;
    if body.contains("\"ip\":\"10.99.0.2\"") || body.contains("\"ip\":\"fd99::2\"") {
        Ok(body)
    } else {
        Err(format!("unexpected answer: {body}"))
    }
}

/// Which lab peer answers on `WHOAMI_PORT` at `target`, through the Gateway on `port`.
async fn whoami(port: u16, target: Target<'_>) -> Result<String, String> {
    let s = socks(port, target).await?;
    Ok(read_all(s).await?.trim().to_owned())
}

/// An open flow through the Gateway to the lab's echo service; `echo` proves it still carries.
async fn echo_flow(port: u16) -> TcpStream {
    let lab_echo = SocketAddr::new(IpAddr::V4(vpn_labpeer::SERVER_V4), 7);
    socks(port, Target::Addr(lab_echo)).await.unwrap()
}

async fn echo(s: &mut TcpStream, text: &str) -> Result<(), String> {
    s.write_all(text.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut back = vec![0u8; text.len()];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut back))
        .await
        .map_err(|_| "no echo".to_string())?
        .map_err(|e| e.to_string())?;
    if back == text.as_bytes() {
        Ok(())
    } else {
        Err(format!("echoed {:?}", String::from_utf8_lossy(&back)))
    }
}

/// An A query for `name` to the lab resolver on `DNS_PORT`, sent as UDP payload through the
/// Gateway's UDP ASSOCIATE; returns the answered address.
async fn udp_lookup(port: u16, name: &str) -> Ipv4Addr {
    let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut sel = [0u8; 2];
    control.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [5, 0]);
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
    let mut query = Message::query();
    query.metadata.id = 0x4242;
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    let mut datagram = vec![0, 0, 0, 1];
    datagram.extend_from_slice(&vpn_labpeer::SERVER_V4.octets());
    datagram.extend_from_slice(&DNS_PORT.to_be_bytes());
    datagram.extend_from_slice(&query.to_vec().unwrap());
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0u8; 1500];
    for _ in 0..5 {
        udp.send_to(&datagram, relay).await.unwrap();
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut buf)).await
        {
            // The SOCKS5 UDP header is 10 bytes (IPv4 source).
            let answer = Message::from_vec(&buf[10..n]).unwrap();
            assert_eq!(answer.metadata.id, 0x4242);
            drop(control);
            return answer
                .answers
                .iter()
                .find_map(|r| match &r.data {
                    RData::A(a) => Some(a.0),
                    _ => None,
                })
                .expect("an A answer");
        }
    }
    panic!("no DNS answer through the Gateway's UDP association");
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// The manager is killed before the emergency latch could reach the disk (`lock` holds the
/// Store's writes until then): the next manager holds the connection for the user until the
/// emergency is cleared, then Start runs it again.
async fn held_after_a_lost_latch(
    stack: &mut Stack,
    id: InstanceId,
    gateway: u16,
    lock: rusqlite::Connection,
    first_generation: u64,
) {
    // The manager is killed before the latch could reach the disk; then the Store works again.
    Stack::kill(&mut stack.manager).await;
    drop(lock);
    let (desired, revision, next_generation) = stack.stored(id);
    assert_eq!(desired, "running", "the stored intent is the old one");
    stack.start_manager().await;
    // The controller reconnects by itself. The connection is not started from the old intent:
    // it is held closed, the reason and the way out shown.
    let s = stack
        .wait_for(id, "held for the user", |s| {
            s.phase == Phase::RecoveryRequired
        })
        .await;
    assert_eq!(fault(&s), Some(STOP_NOT_CONFIRMED), "{s:?}");
    assert!(s.intent.emergency_latched && s.running.is_none());
    tokio::time::sleep(Duration::from_secs(3)).await;
    let s = stack.view(id).await.unwrap().status.unwrap();
    assert_eq!(s.phase, Phase::RecoveryRequired);
    assert!(s.running.is_none() && s.recovery.attempt == 0);
    assert!(fetch(gateway).await.is_err(), "the Gateway still refuses");
    assert_eq!(
        stack.stored(id),
        ("running".into(), revision, next_generation),
        "no generation was started, no intent written"
    );

    // The emergency stands: Start is refused until it is cleared; clearing it is the decision
    // "stopped", on disk. Then Start runs it again.
    let (status, body) = stack.act(id, "start").await;
    assert_eq!(
        (status, error_code(&body)),
        (409, "EMERGENCY_LATCHED".into())
    );
    let (status, body) = stack.act(id, "clear_emergency").await;
    assert_eq!(status, 202, "{body}");
    let s = stack
        .wait_for(id, "stopped, on disk", |s| {
            s.phase == Phase::Stopped && s.intent.persistence == Persistence::Durable
        })
        .await;
    assert_eq!(fault(&s), None);
    assert!(!s.intent.emergency_latched);
    assert!(!stack.marker(id).exists());
    let (status, body) = stack.act(id, "start").await;
    assert_eq!(status, 202, "{body}");
    let again = stack.ready(id).await;
    assert!(again.running.as_ref().unwrap().generation > first_generation);
    fetch(gateway).await.unwrap();
}

/// A plain stop pending when the manager stops normally (SIGTERM) is not a clean exit either.
async fn pending_stop_on_sigterm(stack: &mut Stack, id: InstanceId, gateway: u16) {
    // A plain stop pending when the manager stops normally (SIGTERM) is not a clean exit either:
    // the next manager holds the connection again.
    let lock = stack.lock_writes();
    let accepted = stack.stop(id, false).await;
    assert_eq!(
        (accepted.sealed, accepted.durable),
        (Some(true), Some(false))
    );
    let exit = Stack::terminate(&mut stack.manager).await;
    assert!(exit.success(), "normal exit: {exit:?}");
    assert!(stack.marker(id).exists());
    drop(lock);
    let (_, revision, _) = stack.stored(id);
    stack.start_manager().await;
    let s = stack
        .wait_for(id, "held for the user", |s| {
            s.phase == Phase::RecoveryRequired
        })
        .await;
    assert_eq!(fault(&s), Some(STOP_NOT_CONFIRMED));
    assert!(!s.intent.emergency_latched);
    // The user wants it running: Start, written as a new intent newer than that stop.
    let (status, body) = stack.act(id, "start").await;
    assert_eq!(status, 202, "{body}");
    stack.ready(id).await;
    fetch(gateway).await.unwrap();
    let (desired, after, _) = stack.stored(id);
    assert_eq!((desired.as_str(), after), ("running", revision + 1));
    assert!(!stack.marker(id).exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_the_store_could_not_take_survives_the_manager() {
    // A short directory: socket paths must fit a sockaddr_un.
    let tmp = tempfile::Builder::new()
        .prefix("vpnm-e2e-")
        .tempdir()
        .unwrap();
    let mut stack = Stack::new(tmp.path());
    let lab = LabPeer::start("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let gateway = free_port();
    let id = configure(
        &stack.paths,
        &[Wanted {
            name: "東京",
            lab: &lab,
            gateway_port: gateway,
            shared_dns: false,
        }],
    )
    .await[0];
    stack.start_manager().await;
    stack.start_controller().await;
    let first = stack.ready(id).await;
    fetch(gateway).await.unwrap();
    let worker = first.running.as_ref().unwrap().pid.unwrap();

    // The Store cannot take the latch. The emergency stop closes the connection all the same,
    // and says so: sealed, not durable; its marker is on disk.
    let lock = stack.lock_writes();
    let accepted = stack.stop(id, true).await;
    assert_eq!(
        (accepted.sealed, accepted.durable),
        (Some(true), Some(false))
    );
    let s = stack
        .wait_for(id, "closed, pending", |s| {
            s.phase == Phase::Stopped && s.intent.persistence == Persistence::Pending
        })
        .await;
    assert!(s.intent.emergency_latched && s.enforcement == Enforcement::Blocked);
    assert!(fetch(gateway).await.is_err(), "the Gateway refuses");
    assert!(gone(worker).await, "the worker was reaped");
    assert!(stack.marker(id).exists(), "the stop's marker is on disk");

    // Another owner restarts: a controller killed and started again finds the stop in force.
    Stack::kill(&mut stack.controller).await;
    stack.start_controller().await;
    let s = stack
        .wait_for(id, "still closed and pending", |s| {
            s.intent.persistence == Persistence::Pending
        })
        .await;
    assert_eq!(s.phase, Phase::Stopped);
    assert!(s.intent.emergency_latched);
    assert!(stack.marker(id).exists());

    let first_generation = first.running.as_ref().unwrap().generation;
    held_after_a_lost_latch(&mut stack, id, gateway, lock, first_generation).await;
    pending_stop_on_sigterm(&mut stack, id, gateway).await;

    // A stop that reached the disk: a killed manager's successor finds it stopped, no more.
    let accepted = stack.stop(id, false).await;
    assert_eq!(
        (accepted.sealed, accepted.durable),
        (Some(true), Some(true))
    );
    for _ in 0..50 {
        if !stack.marker(id).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!stack.marker(id).exists());
    Stack::kill(&mut stack.manager).await;
    stack.start_manager().await;
    let s = stack
        .wait_for(id, "stopped", |s| s.phase == Phase::Stopped)
        .await;
    assert_eq!(fault(&s), None);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let s = stack.view(id).await.unwrap().status.unwrap();
    assert_eq!(
        (s.phase, s.intent.persistence),
        (Phase::Stopped, Persistence::Durable)
    );

    Stack::kill(&mut stack.controller).await;
    let _ = Stack::terminate(&mut stack.manager).await;
    lab.shutdown().await;
}

/// Names, the same destination address and UDP to the same DNS server address: each
/// connection reaches only its own peer. Returns a name only B's peer answers.
async fn each_resolves_through_its_own_peer(
    (lab_a, gw_a, own_a): (&Lab, u16, Ipv4Addr),
    (lab_b, gw_b, own_b): (&Lab, u16, Ipv4Addr),
) -> String {
    // Names: each resolver asks only its own peer, which answers with an address only that peer
    // has — and the connection to it goes through that same tunnel.
    let only_a = format!("a-{}.lab", uuid::Uuid::new_v4().simple());
    let only_b = format!("b-{}.lab", uuid::Uuid::new_v4().simple());
    assert_eq!(
        whoami(gw_a, Target::Name(&only_a, WHOAMI_PORT))
            .await
            .unwrap(),
        "lab-a"
    );
    assert_eq!(
        whoami(gw_b, Target::Name(&only_b, WHOAMI_PORT))
            .await
            .unwrap(),
        "lab-b"
    );
    assert!(lab_a.was_asked(&only_a) && !lab_b.was_asked(&only_a));
    assert!(lab_b.was_asked(&only_b) && !lab_a.was_asked(&only_b));
    // The same destination address reaches each connection's own peer.
    let server = SocketAddr::new(IpAddr::V4(vpn_labpeer::SERVER_V4), WHOAMI_PORT);
    assert_eq!(whoami(gw_a, Target::Addr(server)).await.unwrap(), "lab-a");
    assert_eq!(whoami(gw_b, Target::Addr(server)).await.unwrap(), "lab-b");
    // UDP payload to the same DNS server address: answered by each one's own peer.
    let udp_a = format!("u-{}.lab", uuid::Uuid::new_v4().simple());
    let udp_b = format!("v-{}.lab", uuid::Uuid::new_v4().simple());
    assert_eq!(udp_lookup(gw_a, &udp_a).await, own_a);
    assert_eq!(udp_lookup(gw_b, &udp_b).await, own_b);
    assert!(lab_a.was_asked(&udp_a) && !lab_b.was_asked(&udp_a));
    assert!(lab_b.was_asked(&udp_b) && !lab_a.was_asked(&udp_b));
    only_b
}

/// B as it was before anything happened to A: its worker, rules, intent and serving Gateway.
fn assert_untouched(s: &InstanceStatus, b_before: &InstanceStatus) {
    let run_b = b_before.running.as_ref().unwrap();
    let r = s.running.as_ref().unwrap();
    assert_eq!(s.phase, Phase::Ready);
    assert_eq!(s.enforcement, Enforcement::TunnelOnly);
    assert_eq!((r.generation, r.pid), (run_b.generation, run_b.pid));
    assert_eq!(r.policy, run_b.policy, "B's rules");
    assert_eq!(r.pending_changes, []);
    assert_eq!(s.intent, b_before.intent);
    // Its Gateway keeps serving (its live counters move with the flows).
    let ids = |s: &InstanceStatus| s.gateways.iter().map(|g| g.gateway_id).collect::<Vec<_>>();
    assert_eq!(ids(s), ids(b_before));
    assert!(
        s.gateways
            .iter()
            .all(|g| g.state == GatewayState::Serving && g.error.is_none()),
        "{:?}",
        s.gateways
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_with_the_same_addresses_stay_apart() {
    let tmp = tempfile::Builder::new()
        .prefix("vpnm-e2e-")
        .tempdir()
        .unwrap();
    let mut stack = Stack::new(tmp.path());
    // Two lab peers, each handing its client the same addresses (10.99.0.2, fd99::2) behind the
    // same server address 10.99.0.1, where both connections' resolver is.
    let own_a = Ipv4Addr::new(10, 99, 0, 65);
    let own_b = Ipv4Addr::new(10, 99, 0, 66);
    let lab_a = Lab::start("lab-a", own_a).await;
    let lab_b = Lab::start("lab-b", own_b).await;
    assert_eq!(
        (
            lab_a.peer.clients[0].address_v4,
            lab_a.peer.clients[0].address_v6
        ),
        (
            lab_b.peer.clients[0].address_v4,
            lab_b.peer.clients[0].address_v6
        )
    );
    let (gw_a, gw_b) = (free_port(), free_port());
    let ids = configure(
        &stack.paths,
        &[
            Wanted {
                name: "A",
                lab: &lab_a.peer,
                gateway_port: gw_a,
                shared_dns: true,
            },
            Wanted {
                name: "B",
                lab: &lab_b.peer,
                gateway_port: gw_b,
                shared_dns: true,
            },
        ],
    )
    .await;
    let (a, b) = (ids[0], ids[1]);
    stack.start_manager().await;
    stack.start_controller().await;
    let ready_a = stack.ready(a).await;
    let ready_b = stack.ready(b).await;
    let pid_a = ready_a.running.as_ref().unwrap().pid.unwrap();
    assert_ne!(Some(pid_a), ready_b.running.as_ref().unwrap().pid);

    let only_b =
        each_resolves_through_its_own_peer((&lab_a, gw_a, own_a), (&lab_b, gw_b, own_b)).await;
    let server = SocketAddr::new(IpAddr::V4(vpn_labpeer::SERVER_V4), WHOAMI_PORT);

    // B's worker, rules and an open flow, before anything happens to A.
    let mut flow_b = echo_flow(gw_b).await;
    echo(&mut flow_b, "b before").await.unwrap();
    let b_before = stack.view(b).await.unwrap().status.unwrap();

    // A fails: its worker is killed; it comes back with a new generation. B goes on.
    // SAFETY: SIGKILL to a worker this test's manager started.
    unsafe {
        libc::kill(pid_a as libc::pid_t, libc::SIGKILL);
    }
    assert!(gone(pid_a).await);
    echo(&mut flow_b, "b while a fails").await.unwrap();
    let back = stack
        .wait_for(a, "A back on a new generation", |s| {
            s.phase == Phase::Ready
                && s.running.as_ref().map(|r| r.generation)
                    > ready_a.running.as_ref().map(|r| r.generation)
        })
        .await;
    assert_ne!(back.running.as_ref().unwrap().pid, Some(pid_a));
    assert_untouched(&stack.view(b).await.unwrap().status.unwrap(), &b_before);
    echo(&mut flow_b, "b after a came back").await.unwrap();
    assert_eq!(whoami(gw_a, Target::Addr(server)).await.unwrap(), "lab-a");

    // A is stopped: closed; B's worker, rules and flow as they were.
    let accepted = stack.stop(a, false).await;
    assert_eq!(accepted.sealed, Some(true));
    stack
        .wait_for(a, "A stopped", |s| s.phase == Phase::Stopped)
        .await;
    assert!(whoami(gw_a, Target::Addr(server)).await.is_err());
    echo(&mut flow_b, "b after a stopped").await.unwrap();
    assert_untouched(&stack.view(b).await.unwrap().status.unwrap(), &b_before);
    assert_eq!(
        whoami(gw_b, Target::Name(&only_b, WHOAMI_PORT))
            .await
            .unwrap(),
        "lab-b"
    );
    let again = format!("w-{}.lab", uuid::Uuid::new_v4().simple());
    assert_eq!(udp_lookup(gw_b, &again).await, own_b);
    assert!(lab_b.was_asked(&again) && !lab_a.was_asked(&again));

    drop(flow_b);
    Stack::kill(&mut stack.controller).await;
    let _ = Stack::terminate(&mut stack.manager).await;
    lab_a.peer.shutdown().await;
    lab_b.peer.shutdown().await;
}
