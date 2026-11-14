//! `vpn-labpeer`: a controlled `WireGuard` peer for tests and demos.
//!
//! It is a real `WireGuard` endpoint (`GotaTun` + the same netstack as the product) bound to
//! loopback, serving synthetic services *inside the tunnel* only:
//!
//! | Address | Service |
//! |---|---|
//! | `10.99.0.1:7`, `[fd99::1]:7` TCP/UDP | echo |
//! | `10.99.0.1:9` TCP | discard (upload sink) |
//! | `10.99.0.1:19` TCP | source: streams bytes until the client closes (download) |
//! | `10.99.0.1:80` TCP | HTTP: `/` text, `/bytes/<n>`, `/ip` (JSON shaped like am.i.mullvad.net) |
//! | `10.99.0.1:53` UDP/TCP | DNS: every name → `10.99.0.1` / `fd99::1`; `. NS` answered |
//! | `10.99.0.1:<port>` TCP | with [`spawn_loopback_forward`] (`serve --forward-tcp`): relayed to a service on this host's loopback (a real `sshd`, say) |
//!
//! It forwards nothing to the real network; it is not a VPN server. For port-forward tests it
//! also connects *to* its client's tunnel address, from its own address or from
//! [`INTERNET_V4`] (a host beyond the server).

#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;

use anyhow::Context;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, NS};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use http_body_util::Full;
use hyper::{Request, Response};
use ipnetwork::IpNetwork;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vpn_tunnel::{
    FlowClass, GateState, Netstack, NetstackLimits, PeerConfig, PeerPolicy, TransportPlan, Tunnel,
    TunnelConfig, UdpSource, keys,
};
use zeroize::Zeroizing;

pub const SERVER_V4: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
pub const SERVER_V6: Ipv6Addr = Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, 1);
/// A stand-in for a host on the Internet beyond the VPN server.
///
/// The peer owns this address too, so port-forward tests can connect in from outside the tunnel's networks (the product counts
/// only such a connection as reachability evidence). Packets carrying it only ever travel inside
/// the lab tunnel on loopback. 192.88.99.0/24 is the retired 6to4 relay prefix (RFC 7526):
/// globally routable in form, used by nobody.
pub const INTERNET_V4: Ipv4Addr = Ipv4Addr::new(192, 88, 99, 7);

/// One client identity the peer accepts.
pub struct LabClient {
    pub private_key: Zeroizing<[u8; 32]>,
    pub public_key: [u8; 32],
    pub address_v4: Ipv4Addr,
    pub address_v6: Ipv6Addr,
}

impl LabClient {
    /// A `WireGuard` `.conf` for this client (contains its private key — test material only).
    #[must_use]
    pub fn wg_quick_config(&self, peer: &LabPeer) -> String {
        format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}/32, {}/128\nDNS = {}\nMTU = 1420\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {}\nPersistentKeepalive = 25\n",
            B64.encode(*self.private_key),
            self.address_v4,
            self.address_v6,
            SERVER_V4,
            B64.encode(peer.public_key),
            peer.endpoint
        )
    }
}

pub struct LabPeer {
    pub endpoint: SocketAddr,
    pub public_key: [u8; 32],
    pub clients: Vec<LabClient>,
    tunnel: Option<Tunnel>,
}

/// Private keys of a peer and its first client, so a restarted peer still matches an
/// imported client configuration (test material only).
pub struct LabKeys {
    pub server: Zeroizing<[u8; 32]>,
    pub client: Zeroizing<[u8; 32]>,
}

impl LabKeys {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            server: keys::generate_private(),
            client: keys::generate_private(),
        }
    }
}

impl LabPeer {
    /// Start a peer on `listen` (use port 0 for an ephemeral port) accepting `clients` clients.
    ///
    /// # Errors
    ///
    /// As [`LabPeer::start_with`].
    pub async fn start(listen: SocketAddr, clients: usize) -> anyhow::Result<Self> {
        Self::start_with(listen, clients, None).await
    }

    /// Like [`LabPeer::start`], reusing `keys` for the server and the first client.
    ///
    /// # Errors
    ///
    /// Fails for a non-loopback `listen`, a client count other than 1 (1..=200 is the accepted
    /// range, only one is implemented), when the UDP socket cannot be bound, or when the tunnel
    /// or its in-tunnel services cannot start.
    pub async fn start_with(
        listen: SocketAddr,
        clients: usize,
        keys: Option<&LabKeys>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(listen.ip().is_loopback(), "labpeer only binds loopback");
        anyhow::ensure!((1..=200).contains(&clients), "1..=200 clients");
        let socket = StdUdpSocket::bind(listen).context("bind labpeer UDP")?;
        let endpoint = socket.local_addr()?;
        let private_key = keys.map_or_else(keys::generate_private, |k| k.server.clone());
        let public_key = keys::public_from_private(&private_key);

        #[expect(
            clippy::cast_possible_truncation,
            reason = "at most 200 clients (checked above), so 2 + i fits in u8 and u16"
        )]
        let clients: Vec<LabClient> = (0..clients)
            .map(|i| {
                let k = match keys {
                    Some(lk) if i == 0 => lk.client.clone(),
                    _ => keys::generate_private(),
                };
                let pk = keys::public_from_private(&k);
                LabClient {
                    private_key: k,
                    public_key: pk,
                    address_v4: Ipv4Addr::new(10, 99, 0, 2 + i as u8),
                    address_v6: Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, 2 + i as u16),
                }
            })
            .collect();

        // GotaTun supports many peers; our Tunnel wrapper takes one, so each additional client
        // gets its own tunnel instance sharing nothing. Keep the common single-client case simple.
        anyhow::ensure!(
            clients.len() == 1,
            "multi-client mode not implemented yet (run one labpeer per client)"
        );
        let client = &clients[0];
        let tunnel = Tunnel::start(TunnelConfig {
            private_key,
            peer: PeerConfig {
                public_key: client.public_key,
                preshared_key: None,
                endpoint: None,
                allowed_ips: vec![
                    IpNetwork::new(IpAddr::V4(client.address_v4), 32)?,
                    IpNetwork::new(IpAddr::V6(client.address_v6), 128)?,
                ],
                persistent_keepalive: None,
            },
            addresses: vec![
                IpNetwork::new(IpAddr::V4(SERVER_V4), 24)?,
                IpNetwork::new(IpAddr::V6(SERVER_V6), 64)?,
            ],
            mtu: 1420,
            underlay: UdpSource::Preopened(Arc::new(socket)),
            underlay_policy: PeerPolicy::AcceptAny,
            listen_port: endpoint.port(),
            limits: NetstackLimits::default(),
            transport: TransportPlan::default(),
        })
        .await?;
        let net = tunnel.netstack();
        let _ = net.set_gate(GateState::Open);
        net.add_address(IpNetwork::new(IpAddr::V4(INTERNET_V4), 32)?)?;
        spawn_services(&net)?;
        Ok(Self {
            endpoint,
            public_key,
            clients,
            tunnel: Some(tunnel),
        })
    }

    pub fn netstack(&self) -> Option<Netstack> {
        self.tunnel.as_ref().map(Tunnel::netstack)
    }

    pub async fn shutdown(mut self) {
        if let Some(t) = self.tunnel.take() {
            t.shutdown().await;
        }
    }
}

/// One `dial` of the test API: connect in to the client's tunnel address.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DialRequest {
    pub port: u16,
    /// `tcp` (default) or `udp`.
    #[serde(default)]
    pub udp: bool,
    /// Connect from [`INTERNET_V4`] instead of the peer's own address.
    #[serde(default)]
    pub internet: bool,
    /// Attempts, one after the other (a burst for auto-ban tests); 1–500.
    #[serde(default = "one")]
    pub count: u32,
    /// Sent on each connection; the answer must echo it.
    #[serde(default)]
    pub send: String,
}

const fn one() -> u32 {
    1
}

/// What the attempts of one `dial` got.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DialReport {
    pub from: String,
    pub to: String,
    /// The answer echoed what was sent.
    pub echoed: u32,
    /// Refused, reset or closed before an answer.
    pub refused: u32,
    /// No answer in time.
    pub timed_out: u32,
    /// The first few distinct outcomes, in words.
    pub notes: Vec<String>,
}

impl DialReport {
    fn note(&mut self, what: String) {
        if self.notes.len() < 5 && !self.notes.contains(&what) {
            self.notes.push(what);
        }
    }
}

/// Connect in to `client` (its tunnel address) as `req` says, through the lab tunnel only.
pub async fn dial(net: &Netstack, client: Ipv4Addr, req: &DialRequest) -> DialReport {
    use std::time::Duration;
    let from = IpAddr::V4(if req.internet { INTERNET_V4 } else { SERVER_V4 });
    let to = SocketAddr::new(IpAddr::V4(client), req.port);
    let mut report = DialReport {
        from: from.to_string(),
        to: to.to_string(),
        ..DialReport::default()
    };
    let wait = Duration::from_secs(2);
    let payload = if req.send.is_empty() {
        b"labpeer".to_vec()
    } else {
        req.send.as_bytes().to_vec()
    };
    for _ in 0..req.count.clamp(1, 500) {
        if req.udp {
            let Ok(socket) = net.bind_udp_from(from, FlowClass::Payload) else {
                report.note("UDP socket unavailable".into());
                report.refused += 1;
                continue;
            };
            if socket.send_to(&payload, to).await.is_err() {
                report.refused += 1;
                continue;
            }
            let mut buf = vec![0u8; 2048];
            match tokio::time::timeout(wait, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) if buf[..n] == payload[..] => report.echoed += 1,
                Ok(_) => report.refused += 1,
                Err(_) => {
                    report.note("no UDP answer within 2 s".into());
                    report.timed_out += 1;
                }
            }
            continue;
        }
        let stream =
            tokio::time::timeout(wait, net.connect_tcp_from(from, to, FlowClass::Payload)).await;
        let mut stream = match stream {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                report.note(format!("connect: {e}"));
                report.refused += 1;
                continue;
            }
            Err(_) => {
                report.timed_out += 1;
                continue;
            }
        };
        let echoed = async {
            stream.write_all(&payload).await?;
            let mut got = vec![0u8; payload.len()];
            stream.read_exact(&mut got).await?;
            Ok::<bool, std::io::Error>(got == payload)
        };
        match tokio::time::timeout(wait, echoed).await {
            Ok(Ok(true)) => report.echoed += 1,
            Ok(Ok(false)) => report.refused += 1,
            Ok(Err(e)) => {
                report.note(format!("after connect: {e}"));
                report.refused += 1;
            }
            Err(_) => report.timed_out += 1,
        }
    }
    report
}

/// Identification line of the lab's SSH-looking service on port 22.
pub const SSH_BANNER: &str = "SSH-2.0-vpn-labpeer\r\n";

fn spawn_services(net: &Netstack) -> anyhow::Result<()> {
    spawn_stream_services(net)?;
    let mut http = net.listen_tcp(80, 16, FlowClass::Payload)?;
    tokio::spawn(async move {
        while let Ok(stream) = http.accept().await {
            let peer = stream.peer_addr();
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper::service::service_fn(move |req| http_service(req, peer));
                // Like common servers, answer a request whose client already half-closed.
                let _ = hyper::server::conn::http1::Builder::new()
                    .half_close(true)
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    let udp_echo = net.bind_udp_port(7, FlowClass::Payload)?;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = udp_echo.recv_from(&mut buf).await {
            let _ = udp_echo.send_to(&buf[..n], from).await;
        }
    });
    spawn_dns(net)
}

/// TCP echo (7), discard (9), chargen (19) and the SSH-looking service (22).
fn spawn_stream_services(net: &Netstack) -> anyhow::Result<()> {
    {
        let mut l = net.listen_tcp(7, 8, FlowClass::Payload)?;
        tokio::spawn(async move {
            while let Ok(mut s) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = s.shutdown().await;
                });
            }
        });
    }
    let mut discard = net.listen_tcp(9, 8, FlowClass::Payload)?;
    tokio::spawn(async move {
        while let Ok(mut s) = discard.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                }
            });
        }
    });
    let mut source = net.listen_tcp(19, 8, FlowClass::Payload)?;
    tokio::spawn(async move {
        while let Ok(mut s) = source.accept().await {
            tokio::spawn(async move {
                let chunk = vec![0xa5u8; 64 * 1024];
                while s.write_all(&chunk).await.is_ok() {}
            });
        }
    });
    // An SSH-looking server: sends its identification line (RFC 4253), then reads and discards.
    let mut ssh = net.listen_tcp(22, 8, FlowClass::Payload)?;
    tokio::spawn(async move {
        while let Ok(mut s) = ssh.accept().await {
            tokio::spawn(async move {
                if s.write_all(SSH_BANNER.as_bytes()).await.is_err() {
                    return;
                }
                let mut buf = vec![0u8; 4096];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                }
            });
        }
    });
    Ok(())
}

/// Relay TCP connections to `port` inside the tunnel to `target` on this host's loopback.
///
/// A real service behind the lab server (an unprivileged `sshd` for SSH tests). Only loopback:
/// nothing reaches the real network.
///
/// # Errors
///
/// `target` is not a loopback address, or `port` is already served inside the tunnel.
pub fn spawn_loopback_forward(net: &Netstack, port: u16, target: SocketAddr) -> anyhow::Result<()> {
    anyhow::ensure!(
        target.ip().is_loopback(),
        "a lab forward only reaches loopback, not {target}"
    );
    let mut listener = net.listen_tcp(port, 16, FlowClass::Payload)?;
    tokio::spawn(async move {
        while let Ok(mut inside) = listener.accept().await {
            tokio::spawn(async move {
                if let Ok(mut host) = tokio::net::TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut inside, &mut host).await;
                }
            });
        }
    });
    Ok(())
}

/// DNS over UDP and TCP (53), answered by [`dns_answer`].
fn spawn_dns(net: &Netstack) -> anyhow::Result<()> {
    let dns_udp = net.bind_udp_port(53, FlowClass::Payload)?;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, from)) = dns_udp.recv_from(&mut buf).await {
            if let Some(reply) = dns_answer(&buf[..n]) {
                let _ = dns_udp.send_to(&reply, from).await;
            }
        }
    });
    let mut dns_tcp = net.listen_tcp(53, 8, FlowClass::Payload)?;
    tokio::spawn(async move {
        while let Ok(mut s) = dns_tcp.accept().await {
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        break;
                    }
                    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                    if s.read_exact(&mut q).await.is_err() {
                        break;
                    }
                    let Some(reply) = dns_answer(&q) else { break };
                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "lab answers carry at most one small record per question"
                    )]
                    let mut out = (reply.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&reply);
                    if s.write_all(&out).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(())
}

#[expect(
    clippy::unused_async,
    reason = "hyper's service_fn takes a function returning a future"
)]
async fn http_service(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    let (status, ctype, body): (u16, &str, Bytes) = if path == "/" {
        (
            200,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"labpeer ok\n"),
        )
    } else if path == "/ip" {
        let v = serde_json::json!({
            "ip": peer.ip().to_string(),
            "country": "Lab",
            "city": "Loopback",
            "mullvad_exit_ip": true,
        });
        (200, "application/json", Bytes::from(v.to_string()))
    } else if let Some(n) = path
        .strip_prefix("/bytes/")
        .and_then(|s| s.parse::<usize>().ok())
    {
        let n = n.min(1 << 30);
        (
            200,
            "application/octet-stream",
            Bytes::from(vec![0x5au8; n]),
        )
    } else {
        (
            404,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"not found\n"),
        )
    };
    Ok(Response::builder()
        .status(status)
        .header("content-type", ctype)
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))))
}

/// Answer every A/AAAA question with the peer's addresses, `. NS` with a fixed name.
#[must_use]
pub fn dns_answer(query: &[u8]) -> Option<Vec<u8>> {
    let q = Message::from_vec(query).ok()?;
    if q.metadata.message_type != MessageType::Query {
        return None;
    }
    let mut r = Message::response(q.metadata.id, q.metadata.op_code);
    r.metadata.recursion_desired = q.metadata.recursion_desired;
    r.metadata.recursion_available = true;
    for question in &q.queries {
        r.add_query(question.clone());
        let name = question.name().clone();
        match question.query_type() {
            RecordType::A => {
                r.add_answer(Record::from_rdata(name, 60, RData::A(A(SERVER_V4))));
            }
            RecordType::AAAA => {
                r.add_answer(Record::from_rdata(name, 60, RData::AAAA(AAAA(SERVER_V6))));
            }
            RecordType::NS if name.is_root() => {
                let ns = Name::from_ascii("ns.lab.").ok()?;
                r.add_answer(Record::from_rdata(name, 3600, RData::NS(NS(ns))));
            }
            _ => {}
        }
    }
    if q.queries.is_empty() {
        r.metadata.response_code = ResponseCode::FormErr;
    }
    r.to_vec().ok()
}
