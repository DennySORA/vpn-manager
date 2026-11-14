//! Instance DNS Controller against fixture resolvers on 127.0.0.1, dialled through the loopback
//! `TunnelConnector` (no tunnel, no host resolver, no real DNS server). Fixture answers are built
//! with hickory-proto; TLS fixtures use a throwaway CA made with rcgen.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

use std::convert::Infallible;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata};
use http::{Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;
use vpn_domain::{DnsCacheSettings, DnsOnFailure, DnsServer};
use vpn_instance::counters::DnsCounters;
use vpn_instance::dns::server::{self, GateOpen};
use vpn_instance::dns::{DnsConfig, DnsResolver, Family, Resolve, ResolveError};
use vpn_instance::testsupport::LoopbackConnector;

const V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const TLS_NAME: &str = "dns.test";
const DOH_URL: &str = "https://dns.test/dns-query";

// ---------------------------------------------------------------------------------------------
// Fixture zone and servers
// ---------------------------------------------------------------------------------------------

/// Record types of the queries a fixture server received.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<RecordType>>>);

impl Log {
    fn count(&self, kind: RecordType) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|k| **k == kind)
            .count()
    }

    fn record(&self, query: &[u8]) {
        if let Some(q) = Message::from_vec(query)
            .ok()
            .and_then(|m| m.queries.first().cloned())
        {
            self.0.lock().unwrap().push(q.query_type);
        }
    }

    fn total(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

/// The fixture zone: names whose first label is `nx` do not exist; every other name has one A
/// and one AAAA record (TTL 300); `.` has one NS record.
fn reply(query: &[u8], truncated: bool) -> Option<Vec<u8>> {
    answer_with(query, truncated, V4)
}

fn answer_with(query: &[u8], truncated: bool, v4: Ipv4Addr) -> Option<Vec<u8>> {
    let req = Message::from_vec(query).ok()?;
    let q = req.queries.first()?.clone();
    let mut resp = Message::response(req.metadata.id, OpCode::Query);
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.add_query(q.clone());
    if truncated {
        resp.metadata.truncation = true;
    } else if q.name.iter().next() == Some(&b"nx"[..]) {
        resp.metadata.response_code = ResponseCode::NXDomain;
    } else {
        let data = match q.query_type {
            RecordType::A => Some(RData::A(rdata::A(v4))),
            RecordType::AAAA => Some(RData::AAAA(rdata::AAAA(V6))),
            RecordType::NS => Some(RData::NS(rdata::NS(Name::from_ascii("ns.test.").ok()?))),
            _ => None,
        };
        if let Some(data) = data {
            resp.add_answer(Record::from_rdata(q.name, 300, data));
        }
    }
    resp.to_vec().ok()
}

/// Address planted in responses the resolver must reject.
const POISON: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 66);

/// `answer` with its question renamed (same ID, answer records unchanged).
fn foreign_question(answer: &[u8]) -> Vec<u8> {
    let mut msg = Message::from_vec(answer).unwrap();
    msg.queries[0].name = Name::from_ascii("other.test.").unwrap();
    msg.to_vec().unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UdpMode {
    Answer,
    /// Before the answer: garbage, the query echoed (QR=0), and poisoned answers with another
    /// ID or another question.
    Noisy,
    Truncate,
    Silent,
}

fn serve_udp(socket: UdpSocket, mode: UdpMode, delay: Duration) -> Log {
    let log = Log::default();
    let seen = log.clone();
    let socket = Arc::new(socket);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let query = buf[..len].to_vec();
            seen.record(&query);
            if mode == UdpMode::Silent {
                continue;
            }
            let socket = socket.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let Some(answer) = reply(&query, mode == UdpMode::Truncate) else {
                    return;
                };
                if mode == UdpMode::Noisy {
                    let poison = answer_with(&query, false, POISON).unwrap();
                    let mut other_id = poison.clone();
                    other_id[0] ^= 0x5a;
                    let foreign = foreign_question(&poison);
                    for junk in [
                        b"\x12\x34 not dns".to_vec(),
                        query.clone(),
                        other_id,
                        foreign,
                    ] {
                        let _ = socket.send_to(&junk, peer).await;
                    }
                }
                let _ = socket.send_to(&answer, peer).await;
            });
        }
    });
    log
}

/// A UDP fixture that answers only while `on` is set (silent otherwise: a resolver that is down).
fn serve_udp_while(socket: UdpSocket, on: Arc<AtomicBool>) -> Log {
    let log = Log::default();
    let seen = log.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            seen.record(&buf[..len]);
            if on.load(Ordering::SeqCst)
                && let Some(answer) = reply(&buf[..len], false)
            {
                let _ = socket.send_to(&answer, peer).await;
            }
        }
    });
    log
}

/// RFC 1035 length-framed DNS over any byte stream (TCP, `DoT`).
async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, log: Log) {
    loop {
        let mut prefix = [0u8; 2];
        if stream.read_exact(&mut prefix).await.is_err() {
            return;
        }
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        if stream.read_exact(&mut query).await.is_err() {
            return;
        }
        log.record(&query);
        let Some(answer) = reply(&query, false) else {
            return;
        };
        let mut framed = u16::try_from(answer.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(&answer);
        if stream.write_all(&framed).await.is_err() {
            return;
        }
    }
}

/// Throwaway CA and server certificates.
struct TestCa {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl TestCa {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        Self { issuer }
    }

    fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.issuer.der().clone()).unwrap();
        Arc::new(roots)
    }

    fn server_config(&self, name: &str, alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .signed_by(&key, &self.issuer)
            .unwrap();
        let chain: Vec<CertificateDer<'static>> = vec![cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    }
}

struct TlsFixture {
    addr: SocketAddr,
    /// DNS queries received after a completed handshake.
    log: Log,
    /// TCP connections accepted.
    connections: Arc<AtomicUsize>,
}

async fn dot_fixture(config: Arc<rustls::ServerConfig>) -> TlsFixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(config);
    let (log, connections) = (Log::default(), Arc::new(AtomicUsize::new(0)));
    let (seen, accepted) = (log.clone(), connections.clone());
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            let (acceptor, seen) = (acceptor.clone(), seen.clone());
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    serve_stream(tls, seen).await;
                }
            });
        }
    });
    TlsFixture {
        addr,
        log,
        connections,
    }
}

/// One `DoH` request as the fixture saw it.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
}

#[derive(Clone, Default)]
struct HttpLog(Arc<Mutex<Vec<Seen>>>);

impl HttpLog {
    fn all(&self) -> Vec<Seen> {
        self.0.lock().unwrap().clone()
    }
}

async fn doh_handle(
    req: http::Request<Incoming>,
    log: Log,
    http_log: HttpLog,
    redirect: bool,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let seen = Seen {
        path: req.uri().path().to_owned(),
    };
    http_log.0.lock().unwrap().push(seen);
    let query = req.into_body().collect().await.unwrap().to_bytes();
    log.record(&query);
    let answer = reply(&query, false).unwrap_or_default();
    // A redirect still carries a well-formed DNS answer: only the status may reject it.
    let status = if redirect {
        StatusCode::FOUND
    } else {
        StatusCode::OK
    };
    Ok(Response::builder()
        .status(status)
        .header(header::LOCATION, "https://dns.test/elsewhere")
        .header(header::CONTENT_TYPE, "application/dns-message")
        .body(Full::new(Bytes::from(answer)))
        .unwrap())
}

async fn doh_fixture(config: Arc<rustls::ServerConfig>, redirect: bool) -> (TlsFixture, HttpLog) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(config);
    let (log, http_log, connections) = (
        Log::default(),
        HttpLog::default(),
        Arc::new(AtomicUsize::new(0)),
    );
    let (seen, seen_http, accepted) = (log.clone(), http_log.clone(), connections.clone());
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            let (acceptor, seen, seen_http) = (acceptor.clone(), seen.clone(), seen_http.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let h2 = tls.get_ref().1.alpn_protocol() == Some(&b"h2"[..]);
                let service = service_fn(move |req| {
                    doh_handle(req, seen.clone(), seen_http.clone(), redirect)
                });
                let io = TokioIo::new(tls);
                if h2 {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                }
            });
        }
    });
    (
        TlsFixture {
            addr,
            log,
            connections,
        },
        http_log,
    )
}

// ---------------------------------------------------------------------------------------------
// Resolver helpers
// ---------------------------------------------------------------------------------------------

fn config(servers: Vec<DnsServer>, timeout_ms: u64) -> DnsConfig {
    DnsConfig {
        servers,
        cache: DnsCacheSettings::default(),
        query_timeout: Duration::from_millis(timeout_ms),
        attempts: 1,
        max_in_flight: DnsConfig::DEFAULT_MAX_IN_FLIGHT,
        tls_roots: None,
        fallback: Vec::new(),
        on_failure: DnsOnFailure::default(),
    }
}

fn resolver(
    connector: LoopbackConnector,
    config: DnsConfig,
) -> (DnsResolver<LoopbackConnector>, Arc<DnsCounters>) {
    let counters = Arc::new(DnsCounters::default());
    (
        DnsResolver::new(connector, config, counters.clone()),
        counters,
    )
}

fn dot(address: SocketAddr) -> DnsServer {
    DnsServer::Tls {
        address,
        server_name: TLS_NAME.to_owned(),
    }
}

fn doh(address: SocketAddr) -> DnsServer {
    DnsServer::Https {
        address,
        url: DOH_URL.to_owned(),
    }
}

fn load(counter: &AtomicUsize) -> usize {
    counter.load(Ordering::SeqCst)
}

/// The local DNS server the Apps of a strict sandbox ask, on 127.0.0.1 (gate open).
fn app_server(dns: DnsResolver<LoopbackConnector>) -> (server::DnsServer, SocketAddr) {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let open: GateOpen = Arc::new(|| true);
    (server::DnsServer::spawn(udp, tcp, dns, open).unwrap(), addr)
}

/// What an App gets back for `name IN A` from `server` (over UDP).
async fn app_asks(server: SocketAddr, id: u16, name: &str) -> Message {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&msg.to_vec().unwrap(), server)
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
        .await
        .expect("an answer")
        .unwrap();
    Message::from_vec(&buf[..len]).unwrap()
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn dot_with_a_certificate_for_another_name_fails_without_fallback() {
    let ca = TestCa::new();
    let server = dot_fixture(ca.server_config("other.test", &[])).await;
    // A plaintext listener on the same port would see any downgrade attempt.
    let plaintext = UdpSocket::bind(server.addr)
        .await
        .ok()
        .map(|socket| serve_udp(socket, UdpMode::Answer, Duration::ZERO));
    let deadline = Duration::from_millis(2_000);
    let (dns, _) = resolver(
        LoopbackConnector::default(),
        DnsConfig {
            attempts: 3,
            tls_roots: Some(ca.roots()),
            fallback: Vec::new(),
            ..config(vec![dot(server.addr)], 2_000)
        },
    );

    let started = Instant::now();
    assert_eq!(
        dns.resolve("www.example.test", Family::V4).await,
        Err(ResolveError::Failed)
    );
    assert!(
        started.elapsed() < deadline / 2,
        "a verification failure is final"
    );
    assert_eq!(server.log.total(), 0, "no query after a failed handshake");
    assert_eq!(load(&server.connections), 1, "not retried in later rounds");
    if let Some(plaintext) = plaintext {
        assert_eq!(plaintext.total(), 0, "no plaintext fallback");
    }
}

#[tokio::test]
async fn doh_redirect_is_a_failure() {
    let ca = TestCa::new();
    let (server, http_log) = doh_fixture(ca.server_config(TLS_NAME, &[b"h2"]), true).await;
    let (dns, _) = resolver(
        LoopbackConnector::default(),
        DnsConfig {
            attempts: 2,
            tls_roots: Some(ca.roots()),
            fallback: Vec::new(),
            ..config(vec![doh(server.addr)], 2_000)
        },
    );

    assert_eq!(
        dns.resolve("www.example.test", Family::V4).await,
        Err(ResolveError::Failed)
    );
    let seen = http_log.all();
    assert!(!seen.is_empty());
    assert!(
        seen.iter().all(|s| s.path == "/dns-query"),
        "redirect not followed: {seen:?}"
    );
}

#[tokio::test]
async fn a_profile_that_cannot_answer_hands_over_to_the_fallback_and_takes_back() {
    let up = Arc::new(AtomicBool::new(false));
    let primary_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let primary_addr = primary_socket.local_addr().unwrap();
    let primary = serve_udp_while(primary_socket, up.clone());
    let fallback_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fallback_addr = fallback_socket.local_addr().unwrap();
    let fallback = serve_udp(fallback_socket, UdpMode::Answer, Duration::ZERO);
    let (dns, _) = resolver(
        LoopbackConnector::default(),
        DnsConfig {
            fallback: vec![DnsServer::Udp {
                address: fallback_addr,
            }],
            ..config(
                vec![DnsServer::Udp {
                    address: primary_addr,
                }],
                400,
            )
        },
    );

    // Before any probe found the profile failing, its servers alone are asked.
    assert_eq!(
        dns.resolve("www.example.test", Family::V4).await,
        Err(ResolveError::Failed)
    );
    assert_eq!(fallback.total(), 0, "no fallback before a probe");

    // Every server of the profile fails the probe: the fallback answers it and stands in, and
    // the probe says why the profile's servers failed.
    let probe = dns.probe().await.unwrap();
    let why = probe.fallback.expect("on the fallback");
    assert!(
        why.zh_tw.contains(&format!("UDP {primary_addr}")) && why.zh_tw.contains("沒有回應"),
        "{}",
        why.zh_tw
    );
    assert_eq!(
        dns.resolve("www.example.test", Family::V4).await,
        Ok(vec![V4.into()])
    );
    assert_eq!(fallback.count(RecordType::A), 1);
    assert_eq!(
        primary.count(RecordType::A),
        1,
        "only the query before the probe"
    );

    // The profile answers again: the next probe takes it back, and nothing the fallback
    // answered is served from the cache any more.
    up.store(true, Ordering::SeqCst);
    assert_eq!(dns.probe().await.unwrap().fallback, None);
    assert_eq!(
        dns.resolve("www.example.test", Family::V4).await,
        Ok(vec![V4.into()])
    );
    assert_eq!(
        primary.count(RecordType::A),
        2,
        "asked again, not the cache"
    );
    assert_eq!(fallback.count(RecordType::A), 1);
}

#[tokio::test]
async fn a_probe_that_fails_says_why_server_by_server() {
    // Nothing listens on the DoT port (refused), and the UDP server is silent.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let refused = closed.local_addr().unwrap();
    drop(closed);
    let silent_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent = silent_socket.local_addr().unwrap();
    let _log = serve_udp(silent_socket, UdpMode::Silent, Duration::ZERO);
    let (dns, _) = resolver(
        LoopbackConnector::default(),
        config(vec![dot(refused), DnsServer::Udp { address: silent }], 400),
    );

    assert_eq!(dns.probe().await, Err(ResolveError::Failed));
    let why = dns.probe_failure().expect("a reason");
    assert!(
        why.zh_tw.contains(&format!("DoT {refused} 連線被拒")),
        "{}",
        why.zh_tw
    );
    assert!(
        why.zh_tw
            .contains(&format!("UDP {silent} 0.4 秒內沒有回應")),
        "{}",
        why.zh_tw
    );
}

/// The privacy boundary of a DNS profile that fails closed (`on_failure: fail`, the user's choice
/// for `NextDNS`, 2026-11-08): while every one of its servers fails, nothing else is asked — not
/// even resolvers it was handed as a fallback (the `WireGuard` profile's) — and an App's query is
/// answered SERVFAIL at once, not at the deadline; once a server answers a probe again, names
/// resolve through it. The same profile with the default still falls back.
#[tokio::test]
async fn a_profile_that_fails_closed_asks_nothing_else_and_answers_servfail_at_once() {
    let deadline = Duration::from_millis(2_000);
    let up = Arc::new(AtomicBool::new(false));
    let profile_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let profile_addr = profile_socket.local_addr().unwrap();
    let profile = serve_udp_while(profile_socket, up.clone());
    // The WireGuard profile's own resolver: always answering, so any query sent to it shows.
    let wireguard_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let wireguard_addr = wireguard_socket.local_addr().unwrap();
    let wireguard = serve_udp(wireguard_socket, UdpMode::Answer, Duration::ZERO);
    let servers = vec![DnsServer::Udp {
        address: profile_addr,
    }];
    let handed = vec![DnsServer::Udp {
        address: wireguard_addr,
    }];
    let deadline_ms = u64::try_from(deadline.as_millis()).unwrap();
    let (dns, _) = resolver(
        LoopbackConnector::default(),
        DnsConfig {
            on_failure: DnsOnFailure::Fail,
            fallback: handed.clone(),
            ..config(servers.clone(), deadline_ms)
        },
    );
    let (app_dns, app_dns_addr) = app_server(dns.clone());

    // Every server of the profile fails the probe: DNS is interrupted, and the probe says why.
    assert_eq!(dns.probe().await, Err(ResolveError::Interrupted));
    let why = dns.probe_failure().expect("a reason");
    assert!(
        why.zh_tw.contains(&format!("UDP {profile_addr}")),
        "{}",
        why.zh_tw
    );

    // An App's query and a proxy's lookup fail at once, and nothing is sent anywhere.
    let started = Instant::now();
    let answer = app_asks(app_dns_addr, 0x5a5a, "www.example.test.").await;
    assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(answer.metadata.id, 0x5a5a);
    assert_eq!(
        dns.resolve("other.example.test", Family::V4).await,
        Err(ResolveError::Interrupted)
    );
    assert!(
        started.elapsed() < deadline / 4,
        "SERVFAIL at once, not at the deadline: {:?}",
        started.elapsed()
    );
    assert_eq!(
        wireguard.total(),
        0,
        "the WireGuard profile's resolver is never asked"
    );
    assert_eq!(
        profile.count(RecordType::A),
        0,
        "nothing is sent while interrupted"
    );

    // A server answers again: the next probe ends the interruption and names resolve through it.
    up.store(true, Ordering::SeqCst);
    assert!(dns.probe().await.is_ok());
    let answer = app_asks(app_dns_addr, 0x1234, "www.example.test.").await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(profile.count(RecordType::A), 1);
    assert_eq!(wireguard.total(), 0, "never, from first to last");
    app_dns.shutdown().await;

    // The default (`wireguard_resolvers`): the same profile hands over to that resolver.
    up.store(false, Ordering::SeqCst);
    let (falls_back, _) = resolver(
        LoopbackConnector::default(),
        DnsConfig {
            fallback: handed,
            ..config(servers, deadline_ms)
        },
    );
    assert!(falls_back.probe().await.unwrap().fallback.is_some());
    assert_eq!(
        falls_back.resolve("www.example.test", Family::V4).await,
        Ok(vec![V4.into()])
    );
    assert_eq!(wireguard.count(RecordType::A), 1);
}
