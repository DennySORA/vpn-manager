//! Gateway (SOCKS5 + HTTP proxy) end to end over `LoopbackConnector`: fixture servers on loopback
//! stand in for destinations behind the tunnel, a stub resolver maps the test names to 127.0.0.1
//! and the test policy admits loopback destinations (every other rule still applies).

// Fixture and client helpers panic on setup failures just like the `#[test]` bodies: test code
// throughout, so clippy.toml's test exemptions (`allow-unwrap-in-tests`, ...) cover them too.
#![cfg(test)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{Instant, timeout};
use vpn_domain::ipset::IpRangeSet;
use vpn_domain::{GatewayId, GatewayKind};
use vpn_instance::counters::GatewayCounters;
use vpn_instance::dns::{Family, Resolve, ResolveError};
use vpn_instance::gateway::{Gateway, GatewayConfig, GatewayDeps};
use vpn_instance::policy::{Denied, DestinationPolicy, Overlay};
use vpn_instance::shaping::Shaper;
use vpn_instance::testsupport::LoopbackConnector;

/// The closed-gate refusal, in English: the language of a request that names none of the interface's.
const GATE_CLOSED: &str = "The VPN Instance is not ready or is reconnecting; the connection was refused (it never falls back to the ordinary network)";
const CONNECT: u8 = 1;
const UDP_ASSOCIATE: u8 = 3;

/// Every name it knows points at the loopback fixtures.
#[derive(Clone)]
struct StubResolver(Arc<HashMap<&'static str, IpAddr>>);

impl StubResolver {
    fn new() -> Self {
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        Self(Arc::new(HashMap::from([
            ("echo.test", lo),
            ("origin.test", lo),
            ("other.test", lo),
        ])))
    }
}

impl Resolve for StubResolver {
    fn resolve(
        &self,
        host: &str,
        _family: Family,
    ) -> impl Future<Output = Result<Vec<IpAddr>, ResolveError>> + Send {
        std::future::ready(
            self.0
                .get(host)
                .map(|ip| vec![*ip])
                .ok_or(ResolveError::NotFound),
        )
    }
}

struct Harness {
    /// Kept alive for the test: dropping it stops the Gateway.
    _gateway: Gateway,
    addr: SocketAddr,
    connector: LoopbackConnector,
    counters: Arc<GatewayCounters>,
}

fn start(
    kind: GatewayKind,
    blocked_ports: Vec<u16>,
    configure: impl FnOnce(&mut GatewayConfig),
) -> Harness {
    start_shaped(kind, blocked_ports, configure, Shaper::unlimited())
}

fn start_shaped(
    kind: GatewayKind,
    blocked_ports: Vec<u16>,
    configure: impl FnOnce(&mut GatewayConfig),
    shaper: Arc<Shaper>,
) -> Harness {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut config = GatewayConfig::new(GatewayId::new(), kind, true, 64);
    configure(&mut config);
    let connector = LoopbackConnector::default();
    let counters = Arc::new(GatewayCounters::default());
    let gateway = Gateway::spawn(
        listener,
        config,
        GatewayDeps {
            connector: connector.clone(),
            resolver: StubResolver::new(),
            policy: Arc::new(DestinationPolicy::loopback_for_tests(
                blocked_ports,
                Vec::new(),
            )),
            counters: Arc::clone(&counters),
            shaper,
        },
    )
    .unwrap();
    let addr = gateway.local_addr();
    Harness {
        _gateway: gateway,
        addr,
        connector,
        counters,
    }
}

fn get(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::SeqCst)
}

/// Counters are updated by gateway tasks concurrently with the client; poll until they settle.
async fn eventually(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// TCP echo; closes its write side after the client closed its own (half-close).
async fn tcp_echo_on(bind: &str) -> Option<SocketAddr> {
    let listener = TcpListener::bind(bind).await.ok()?;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut rx, mut tx) = stream.split();
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the echo ends with the client's side, however that ends; the half-close follows either way"
                )]
                let _ = tokio::io::copy(&mut rx, &mut tx).await;
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "a client that reset the connection needs no half-close"
                )]
                let _ = tx.shutdown().await;
            });
        }
    });
    Some(addr)
}

async fn tcp_echo() -> SocketAddr {
    tcp_echo_on("127.0.0.1:0").await.unwrap()
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "an echo not sent shows as the missing reply the waiting test reports"
            )]
            let _ = socket.send_to(&buf[..n], src).await;
        }
    });
    addr
}

/// Answers every request with what it received: the number of the TCP connection it arrived on,
/// method, request-target, Host, any hop-by-hop header that leaked through, and the body.
async fn http_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut connections = 0u64;
        while let Ok((stream, _)) = listener.accept().await {
            connections += 1;
            let conn = connections;
            let service = hyper::service::service_fn(move |req: Request<Incoming>| async move {
                let leaked: Vec<&str> = [
                    "proxy-connection",
                    "proxy-authorization",
                    "keep-alive",
                    "x-hop",
                    "te",
                ]
                .into_iter()
                .filter(|name| req.headers().contains_key(*name))
                .collect();
                let host = req.headers()["host"].to_str().unwrap().to_owned();
                let head = format!(
                    "conn={conn} {} {} host={host} leaked={leaked:?}",
                    req.method(),
                    req.uri()
                );
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let text = format!("{head} body={}", String::from_utf8_lossy(&body));
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(text))))
            });
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service),
            );
        }
    });
    addr
}

// ---------------------------------------------------------------------------------------------
// SOCKS5 client side
// ---------------------------------------------------------------------------------------------

enum Target<'a> {
    Addr(SocketAddr),
    Name(&'a str, u16),
}

/// `ATYP DST.ADDR DST.PORT`.
fn encode(out: &mut Vec<u8>, target: &Target<'_>) {
    let port = match target {
        Target::Addr(SocketAddr::V4(addr)) => {
            out.push(1);
            out.extend_from_slice(&addr.ip().octets());
            addr.port()
        }
        Target::Addr(SocketAddr::V6(addr)) => {
            out.push(4);
            out.extend_from_slice(&addr.ip().octets());
            addr.port()
        }
        Target::Name(name, port) => {
            out.push(3);
            out.push(u8::try_from(name.len()).unwrap());
            out.extend_from_slice(name.as_bytes());
            *port
        }
    };
    out.extend_from_slice(&port.to_be_bytes());
}

/// A SOCKS5 UDP request datagram (`FRAG` = 0).
fn datagram(target: &Target<'_>, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, 0];
    encode(&mut out, target);
    out.extend_from_slice(payload);
    out
}

async fn socks_greet(stream: &mut TcpStream) {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await.unwrap();
    assert_eq!(choice, [5, 0], "no-auth method selected");
}

/// Greeting and request; returns `REP` and `BND`.
async fn socks_request(
    stream: &mut TcpStream,
    command: u8,
    target: &Target<'_>,
) -> (u8, SocketAddr) {
    socks_greet(stream).await;
    let mut request = vec![5, command, 0];
    encode(&mut request, target);
    stream.write_all(&request).await.unwrap();
    let mut head = [0u8; 4];
    timeout(Duration::from_secs(5), stream.read_exact(&mut head))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((head[0], head[2]), (5, 0));
    let ip = match head[3] {
        1 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await.unwrap();
            IpAddr::from(octets)
        }
        4 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await.unwrap();
            IpAddr::from(octets)
        }
        other => panic!("unexpected ATYP {other}"),
    };
    let port = stream.read_u16().await.unwrap();
    (head[1], SocketAddr::new(ip, port))
}

async fn socks_connect(gateway: SocketAddr, target: &Target<'_>) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(gateway).await.unwrap();
    let (code, bind) = socks_request(&mut stream, CONNECT, target).await;
    assert_eq!(
        bind,
        SocketAddr::from(([0, 0, 0, 0], 0)),
        "BND is 0.0.0.0:0"
    );
    (stream, code)
}

async fn recv(socket: &UdpSocket) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let (n, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    buf.truncate(n);
    buf
}

// ---------------------------------------------------------------------------------------------
// HTTP client side
// ---------------------------------------------------------------------------------------------

async fn proxy_client(gateway: SocketAddr) -> SendRequest<Full<Bytes>> {
    let stream = TcpStream::connect(gateway).await.unwrap();
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(connection);
    sender
}

/// One proxy request on an existing client connection; returns status, content type and body.
async fn proxy_request(
    sender: &mut SendRequest<Full<Bytes>>,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String, String) {
    let authority = uri
        .parse::<hyper::Uri>()
        .unwrap()
        .authority()
        .unwrap()
        .to_string();
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", authority);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request
        .body(Full::new(Bytes::from(body.to_owned())))
        .unwrap();
    sender.ready().await.unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .map_or_default(|value| value.to_str().unwrap().to_owned());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        content_type,
        String::from_utf8(body.to_vec()).unwrap(),
    )
}

/// Read a response head, leaving whatever follows it in the socket.
async fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let byte = timeout(Duration::from_secs(5), stream.read_u8())
            .await
            .unwrap()
            .unwrap();
        head.push(byte);
    }
    String::from_utf8(head).unwrap()
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_udp_associate_relays_pins_the_client_and_drops_fragments() {
    let h = start(GatewayKind::Mixed, Vec::new(), |_| {});
    let c = &h.counters;
    let echo = udp_echo().await;

    let mut control = TcpStream::connect(h.addr).await.unwrap();
    let unknown = Target::Addr(SocketAddr::from(([0, 0, 0, 0], 0)));
    let (code, relay) = socks_request(&mut control, UDP_ASSOCIATE, &unknown).await;
    assert_eq!(code, 0);
    assert!(relay.ip().is_loopback() && relay.port() != 0, "{relay}");
    eventually("association active", || {
        get(&c.udp_associations_active) == 1
    })
    .await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&datagram(&Target::Addr(echo), b"ping"), relay)
        .await
        .unwrap();
    assert_eq!(recv(&client).await, datagram(&Target::Addr(echo), b"ping"));

    // A name is resolved through the resolver; the reply names the remote by its address.
    client
        .send_to(
            &datagram(&Target::Name("echo.test", echo.port()), b"pong"),
            relay,
        )
        .await
        .unwrap();
    assert_eq!(recv(&client).await, datagram(&Target::Addr(echo), b"pong"));

    // A fragment, and a datagram from a port other than the pinned one, are dropped.
    let mut fragment = datagram(&Target::Addr(echo), b"frag");
    fragment[2] = 1;
    client.send_to(&fragment, relay).await.unwrap();
    let intruder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    intruder
        .send_to(&datagram(&Target::Addr(echo), b"nope"), relay)
        .await
        .unwrap();
    eventually("both dropped", || get(&c.udp_dropped) == 2).await;
    let mut buf = [0u8; 64];
    assert!(
        timeout(Duration::from_millis(200), client.recv_from(&mut buf))
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(50), intruder.recv_from(&mut buf))
            .await
            .is_err()
    );

    eventually("payload counted", || {
        get(&c.payload_tx_bytes) == 8 && get(&c.payload_rx_bytes) == 8
    })
    .await;

    // The association ends with its control connection.
    drop(control);
    eventually("association ended", || get(&c.udp_associations_active) == 0).await;
    eventually("connection released", || get(&c.tcp_active) == 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_denials_and_a_closed_gate_are_refused_without_fallback() {
    let blocked = tcp_echo().await;
    let h = start(GatewayKind::Mixed, vec![blocked.port()], |_| {});
    let c = &h.counters;
    let mut client = proxy_client(h.addr).await;

    // Destination policy: blocked port.
    let (_, code) = socks_connect(h.addr, &Target::Addr(blocked)).await;
    assert_eq!(code, 0x02);
    let denied_uri = format!("http://echo.test:{}/", blocked.port());
    // Answered in the language the request asks for.
    let chinese = [("accept-language", "zh-TW,zh;q=0.9,en;q=0.8")];
    let (status, content_type, body) =
        proxy_request(&mut client, "GET", &denied_uri, &chinese, "").await;
    assert_eq!(status, 403);
    assert_eq!(content_type, "text/plain; charset=utf-8");
    assert_eq!(body.trim_end(), Denied::BlockedPort.message().zh_tw);

    // Closed gate: refused although the destination is allowed and reachable.
    let open = tcp_echo().await;
    h.connector.set_closed(true);
    let (_, code) = socks_connect(h.addr, &Target::Addr(open)).await;
    assert_eq!(code, 0x02);
    let open_uri = format!("http://echo.test:{}/", open.port());
    let (status, _, body) = proxy_request(&mut client, "GET", &open_uri, &[], "").await;
    assert_eq!(status, 503);
    assert_eq!(body.trim_end(), GATE_CLOSED);
    let mut tunnel = TcpStream::connect(h.addr).await.unwrap();
    let connect = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", open.port());
    tunnel.write_all(connect.as_bytes()).await.unwrap();
    assert!(read_head(&mut tunnel).await.starts_with("HTTP/1.1 503 "));
    let mut control = TcpStream::connect(h.addr).await.unwrap();
    let unknown = Target::Addr(SocketAddr::from(([0, 0, 0, 0], 0)));
    let (code, _) = socks_request(&mut control, UDP_ASSOCIATE, &unknown).await;
    assert_eq!(code, 0x02, "UDP ASSOCIATE with a closed gate");

    eventually("refusals counted", || get(&c.tcp_rejected) == 6).await;
    assert_eq!(get(&c.payload_tx_bytes) + get(&c.payload_rx_bytes), 0);
    assert_eq!(get(&c.connect_latency.count), 0);
    assert_eq!(get(&c.connect_failures), 0, "refusals are not failures");
}

/// One request on its own client connection (no upstream kept from an earlier request).
async fn fetch_once(gateway: SocketAddr, uri: &str) -> (u16, String) {
    let mut client = proxy_client(gateway).await;
    let (status, _, body) = proxy_request(&mut client, "GET", uri, &[], "").await;
    (status, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocklist_attached_to_a_running_gateway_applies_at_once_and_detaches() {
    let origin = http_origin().await;
    let policy = Arc::new(DestinationPolicy::loopback_for_tests(
        Vec::new(),
        Vec::new(),
    ));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let gateway = Gateway::spawn(
        listener,
        GatewayConfig::new(GatewayId::new(), GatewayKind::Mixed, true, 64),
        GatewayDeps {
            connector: LoopbackConnector::default(),
            resolver: StubResolver::new(),
            policy: policy.clone(),
            counters: Arc::new(GatewayCounters::default()),
            shaper: Shaper::unlimited(),
        },
    )
    .unwrap();
    let addr = gateway.local_addr();
    let uri = format!("http://origin.test:{}/x", origin.port());
    assert_eq!(fetch_once(addr, &uri).await.0, 200);

    // Attached while the Gateway runs: a newer overlay covering the destination.
    let deny = IpRangeSet::from_networks(["127.0.0.1/32".parse().unwrap()]);
    policy.enforcement().swap(Overlay::new(2, deny)).unwrap();
    let (status, body) = fetch_once(addr, &uri).await;
    assert_eq!(status, 403);
    assert_eq!(body.trim_end(), Denied::Blocklisted.message().en);
    let (_, code) = socks_connect(addr, &Target::Addr(origin)).await;
    assert_eq!(code, 0x02, "SOCKS5: connection not allowed by ruleset");

    // Detached: a newer, empty overlay; the same Gateway serves again.
    policy
        .enforcement()
        .swap(Overlay::new(3, IpRangeSet::new()))
        .unwrap();
    assert_eq!(fetch_once(addr, &uri).await.0, 200);
    gateway.shutdown().await;
}
