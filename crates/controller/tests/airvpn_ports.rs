//! `AirVPN`'s forwarded ports through the Provider egress guard (architecture §7): a fake
//! airvpn.org (`providers/tests/support/airvpn_site.rs`) behind an in-memory relay socket that
//! admits relay lines v2 with the connectors' own `Admission`, with a throwaway CA. Every
//! website request — the sign-in page, the sign-in, the Ports page, each port call (the list, a
//! reservation, a delete, each setting, the sessions and their tests, the DDNS check, the search
//! for free ports) — takes its own fresh exit check, its share of airvpn.org's budget and its
//! own relay line; the session is kept per account in memory and reused; the credential, the
//! cookies and the page token never reach a relay line, an exit check, a log line, an answer or
//! an error. Nothing touches the network, a manager or a real account.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

#[path = "../../providers/tests/support/airvpn_site.rs"]
mod fake_site;

use std::convert::Infallible;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fake_site::{FakeSite, LoginPage};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio_rustls::TlsAcceptor;
use vpn_controller::provider::budget::Limits;
use vpn_controller::provider::guard::{Egress, PERMIT_TTL, RouteProfile};
use vpn_controller::provider::{Providers, Relay, Route};
use vpn_domain::*;
use vpn_ipc::relay::{Admission, RelayAnswer, RelayRoute};
use vpn_providers::Tls;
use vpn_providers::airvpn::Credentials;
use vpn_sync::Mutex;

const AIR: &str = "airvpn.org";
const MULLVAD_CHECK: &str = "ipv4.am.i.mullvad.net";
const CHECK_PATH: &str = "/api/whatismyip/";
const USER: &str = "Synthetic.User";
const PASSWORD: &str = "pä+/=&<ss wörd";

// -------------------------------------------------------------------------------------------
// TLS, the relay, the egress
// -------------------------------------------------------------------------------------------

fn tls() -> (RootCertStore, Arc<rustls::ServerConfig>) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(issuer.der().clone()).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![AIR.to_owned(), MULLVAD_CHECK.to_owned()])
        .unwrap()
        .signed_by(&key, &issuer)
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
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    (roots, Arc::new(config))
}

/// What the relay saw, in order.
#[derive(Debug, Clone)]
enum Seen {
    /// A relay line: where to, whether a check's permit authorized it (`expect`), as written.
    Line {
        host: String,
        authorized: bool,
        raw: String,
    },
    Http {
        method: String,
        path: String,
        cookie: Option<String>,
        body: Vec<u8>,
    },
}

struct RelaySocket {
    _dir: tempfile::TempDir,
    path: PathBuf,
    route: RelayRoute,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl RelaySocket {
    fn spawn(server: Arc<rustls::ServerConfig>, site: Arc<FakeSite>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let route = RelayRoute::Instance {
            instance_id: InstanceId::new(),
            generation: 2,
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        let admission = Arc::new(Admission::new(route));
        let acceptor = TlsAcceptor::from(server);
        let s = seen.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(
                    stream,
                    s.clone(),
                    admission.clone(),
                    acceptor.clone(),
                    site.clone(),
                ));
            }
        });
        Self {
            _dir: dir,
            path,
            route,
            seen,
        }
    }

    fn route(&self) -> Route {
        let RelayRoute::Instance {
            instance_id,
            generation,
        } = self.route
        else {
            unreachable!()
        };
        Route {
            mode: RouteMode::ViaInstance,
            instance_id: Some(instance_id),
            generation: Some(generation),
            egress_epoch: 3,
            relay: Relay::instance(self.path.display().to_string(), instance_id, generation),
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().clone()
    }

    /// Relay lines as `(host, authorized)`.
    fn lines(&self) -> Vec<(String, bool)> {
        self.seen()
            .into_iter()
            .filter_map(|s| match s {
                Seen::Line {
                    host, authorized, ..
                } => Some((host, authorized)),
                Seen::Http { .. } => None,
            })
            .collect()
    }

    /// HTTP requests as `METHOD path`.
    fn https(&self) -> Vec<String> {
        self.seen()
            .into_iter()
            .filter_map(|s| match s {
                Seen::Http { method, path, .. } => Some(format!("{method} {path}")),
                Seen::Line { .. } => None,
            })
            .collect()
    }
}

async fn serve(
    stream: UnixStream,
    seen: Arc<Mutex<Vec<Seen>>>,
    admission: Arc<Admission>,
    acceptor: TlsAcceptor,
    site: Arc<FakeSite>,
) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() {
        return;
    }
    let mut stream = reader.into_inner();
    let raw = line.trim_end().to_owned();
    let (answer, ok) = match admission.admit(&raw, 1) {
        Err(refusal) => (refusal, false),
        Ok(_) => (
            RelayAnswer::connected("203.0.113.5:443".parse().unwrap(), admission.epochs(1)),
            true,
        ),
    };
    let parsed: Option<vpn_ipc::relay::RelayLine> = serde_json::from_str(&raw).ok();
    seen.lock().push(Seen::Line {
        host: parsed.as_ref().map_or_default(|l| l.host.clone()),
        authorized: parsed.as_ref().and_then(|l| l.expect).is_some(),
        raw,
    });
    if stream.write_all(&answer.to_bytes()).await.is_err() || !ok {
        return;
    }
    let Ok(tls) = acceptor.accept(stream).await else {
        return;
    };
    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let (seen, site) = (seen.clone(), site.clone());
        async move {
            let (parts, body) = req.into_parts();
            let body = body
                .collect()
                .await
                .map_or_default(|b| b.to_bytes().to_vec());
            let header = |n: &str| {
                parts
                    .headers
                    .get(n)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            };
            let host = header("host").unwrap_or_default();
            let path = parts.uri.path().to_owned();
            seen.lock().push(Seen::Http {
                method: parts.method.to_string(),
                path: path.clone(),
                cookie: header("cookie"),
                body: body.clone(),
            });
            let a = match (host.as_str(), path.as_str()) {
                (AIR, CHECK_PATH) => fake_site::Answer::new(
                    200,
                    br#"{"result":"ok","ip":"198.51.100.20","airvpn":true}"#.to_vec(),
                ),
                (MULLVAD_CHECK, _) => fake_site::Answer::new(
                    200,
                    br#"{"ip":"198.51.100.9","country":"Sweden","city":"Gothenburg","mullvad_exit_ip":true}"#.to_vec(),
                ),
                _ => site.handle(&fake_site::Request {
                    method: parts.method.as_str(),
                    path: &path,
                    header: &header,
                    body: &body,
                }),
            };
            if a.stall {
                std::future::pending::<()>().await;
            }
            let mut response = hyper::Response::new(Full::new(Bytes::from(a.body)));
            *response.status_mut() = hyper::StatusCode::from_u16(a.status).unwrap();
            for (name, value) in a.headers {
                response.headers_mut().append(
                    hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    hyper::header::HeaderValue::from_str(&value).unwrap(),
                );
            }
            Ok::<_, Infallible>(response)
        }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(tls), service)
        .await;
}

/// The egress binding as the manager would answer: one route, read-counted, switchable.
struct FakeEgress {
    route: Mutex<Route>,
    provider: ProviderKind,
    reads: AtomicUsize,
    /// From this read on, the route in force is another one.
    switch_at: Mutex<Option<(usize, Route)>>,
}

impl FakeEgress {
    fn new(route: Route, provider: ProviderKind) -> Arc<Self> {
        Arc::new(Self {
            route: Mutex::new(route),
            provider,
            reads: AtomicUsize::new(0),
            switch_at: Mutex::new(None),
        })
    }
}

impl FakeEgress {
    /// The route in force for this read, switching to the next one when its read has come.
    fn read_route(&self) -> Route {
        let n = self.reads.fetch_add(1, Ordering::SeqCst);
        let due = self.switch_at.lock().take_if(|(at, _)| n >= *at);
        if let Some((_, next)) = due {
            *self.route.lock() = next;
        }
        self.route.lock().clone()
    }
}

impl Egress for FakeEgress {
    fn route(&self) -> impl Future<Output = Result<Route, ApiError>> + Send {
        std::future::ready(Ok(self.read_route()))
    }

    fn profile(&self, _: &Route) -> impl Future<Output = RouteProfile> + Send {
        std::future::ready(RouteProfile {
            provider: self.provider,
            ipv6: false,
        })
    }
}

// -------------------------------------------------------------------------------------------
// The test environment
// -------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Env {
    site: Arc<FakeSite>,
    relay: RelaySocket,
    egress: Arc<FakeEgress>,
    providers: Arc<Providers>,
    account: ProviderAccountId,
    logs: Arc<std::sync::Mutex<Vec<u8>>>,
    server: Arc<rustls::ServerConfig>,
    _logging: tracing::subscriber::DefaultGuard,
}

fn env_with(site: FakeSite, provider: ProviderKind, limits: Limits) -> Env {
    let logs = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Sink(logs.clone());
    let logging = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish(),
    );
    let (roots, server) = tls();
    let site = Arc::new(site);
    let relay = RelaySocket::spawn(server.clone(), site.clone());
    let egress = FakeEgress::new(relay.route(), provider);
    let providers = Providers::with(Tls::with_roots(roots), limits, PERMIT_TTL);
    Env {
        site,
        relay,
        egress,
        providers,
        account: ProviderAccountId::new(),
        logs,
        server,
        _logging: logging,
    }
}

fn env(site: FakeSite) -> Env {
    env_with(site, ProviderKind::Airvpn, Limits::default())
}

fn creds() -> Credentials {
    Credentials::new(USER, PASSWORD).unwrap()
}

impl Env {
    async fn list(&self) -> Result<ForwardedPorts, ApiError> {
        self.providers
            .forwarded_ports_via(&*self.egress, self.account, &creds())
            .await
    }

    fn gate(&self) -> ProviderGate {
        self.providers
            .gates()
            .into_iter()
            .find(|g| g.provider == ProviderKind::Airvpn && g.gate == ProviderGateKind::Forward)
            .unwrap()
    }

    fn logs(&self) -> String {
        String::from_utf8_lossy(&self.logs.lock().unwrap()).into_owned()
    }

    /// No secret of the account or the site in `text`.
    fn clean(&self, what: &str, text: &str) {
        for secret in self.site.secrets() {
            assert!(
                !text.to_lowercase().contains(&secret.to_lowercase()),
                "{what} carries {secret:?}: {text}"
            );
        }
    }

    /// No relay line carries a secret; no exit check carries a cookie or a body.
    fn relay_clean(&self) {
        let mut checks = 0;
        for s in self.relay.seen() {
            match s {
                Seen::Line { raw, .. } => self.clean("a relay line", &raw),
                Seen::Http {
                    path, cookie, body, ..
                } if path == CHECK_PATH || path == "/json" => {
                    checks += 1;
                    assert!(cookie.is_none(), "an exit check carried the session");
                    assert!(body.is_empty(), "an exit check carried a body");
                }
                Seen::Http { .. } => {}
            }
        }
        assert!(checks > 0, "no exit check was seen");
    }
}

/// `n` website requests over an `AirVPN` egress: each a check line then its authorized request.
fn paired(n: usize) -> Vec<(String, bool)> {
    (0..n)
        .flat_map(|_| [(AIR.to_owned(), false), (AIR.to_owned(), true)])
        .collect()
}

// -------------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn every_website_request_takes_its_own_exit_check_and_the_session_is_reused() {
    let e = env(FakeSite::new(USER, PASSWORD).with_ports(&[40000]));
    let list = e.list().await.unwrap();
    assert_eq!(list.ports.len(), 1);
    assert_eq!(list.ports[0].port, 40000);
    assert_eq!(list.ports[0].local_port, 40000);
    assert_eq!((list.limit, list.min_port), (5, 2049));
    assert_eq!(list.devices[0].name, "Default");
    assert_eq!(e.relay.lines(), paired(4));
    assert_eq!(
        e.relay.https(),
        [
            "GET /api/whatismyip/",
            "GET /login/",
            "GET /api/whatismyip/",
            "POST /login/",
            "GET /api/whatismyip/",
            "GET /ports/",
            "GET /api/whatismyip/",
            "POST /ports/",
        ]
    );
    let gate = e.gate();
    assert_eq!(gate.status, GateStatus::Passed, "{gate:?}");
    assert!(gate.reason.as_ref().unwrap().zh_tw.contains("已用 1／5 個"));
    assert_eq!(gate.instance_id, e.relay.route().instance_id);

    // The next operation: the session is reused — one check, one port call.
    e.list().await.unwrap();
    assert_eq!(e.relay.lines(), paired(5));
    assert_eq!(e.site.sign_ins(), 1);
    e.relay_clean();
    e.clean("the answer", &serde_json::to_string(&list).unwrap());
    e.clean("the log", &e.logs());

    // Forgetting the account drops its session: the next operation signs in again.
    e.providers.forget(e.account);
    e.list().await.unwrap();
    assert_eq!(e.site.sign_ins(), 2);
}

#[tokio::test]
async fn reserving_and_deleting_go_through_the_guard_and_answer_in_api_terms() {
    let e = env(FakeSite::new(USER, PASSWORD));
    let new = e
        .providers
        .reserve_port_via(&*e.egress, e.account, &creds(), None)
        .await
        .unwrap();
    assert_eq!(new.port, 35786);
    assert_eq!(new.protocol, ForwardProtocol::Both);
    assert_eq!(new.ip_layer, "both");
    assert_eq!(new.device_id, None);
    let chosen = e
        .providers
        .reserve_port_via(&*e.egress, e.account, &creds(), Some(40000))
        .await
        .unwrap();
    assert_eq!(chosen.port, 40000);
    let taken = e
        .providers
        .reserve_port_via(&*e.egress, e.account, &creds(), Some(40000))
        .await
        .unwrap_err();
    assert_eq!(taken.code, ErrorCode::InvalidState, "{taken:?}");
    assert_eq!(taken.field_errors[0].path, "/port");
    let low = e
        .providers
        .reserve_port_via(&*e.egress, e.account, &creds(), Some(1024))
        .await
        .unwrap_err();
    assert_eq!(low.code, ErrorCode::ValidationFailed);
    e.providers
        .delete_port_via(&*e.egress, e.account, &creds(), 35786)
        .await
        .unwrap();
    assert_eq!(e.site.ports(), [40000]);
    let missing = e
        .providers
        .delete_port_via(&*e.egress, e.account, &creds(), 35786)
        .await
        .unwrap_err();
    assert_eq!(missing.code, ErrorCode::NotFound);
    // Every request of every operation: a check, then the request it authorized.
    let lines = e.relay.lines();
    assert_eq!(lines.len() % 2, 0);
    assert_eq!(lines, paired(lines.len() / 2));
    e.relay_clean();
    e.clean("the log", &e.logs());
}

#[tokio::test]
async fn a_refused_sign_in_fails_the_gate_and_a_challenge_blocks_it_without_leaking() {
    let e = env(FakeSite::new(USER, "another password"));
    let err = e.list().await.unwrap_err();
    assert_eq!(err.code, ErrorCode::ProviderAuthRejected, "{err:?}");
    assert_eq!(e.gate().status, GateStatus::Failed);
    e.clean("the error", &serde_json::to_string(&err).unwrap());
    e.clean("the log", &e.logs());
    e.relay_clean();

    let e = env(FakeSite::new(USER, PASSWORD));
    e.site.knobs(|k| k.login_page = LoginPage::Captcha);
    let err = e.list().await.unwrap_err();
    assert_eq!(err.code, ErrorCode::ProviderLoginChallenge, "{err:?}");
    assert_eq!(e.gate().status, GateStatus::Blocked);
    assert_eq!(e.site.log(), ["GET /login/"], "no password posted");
    e.clean("the error", &serde_json::to_string(&err).unwrap());
}

#[tokio::test]
async fn a_switched_egress_stops_the_operation_where_it_is() {
    let e = env(FakeSite::new(USER, PASSWORD).with_ports(&[40000]));
    // Another connection takes over after the sign-in page went out (the guard reads the route
    // three times per request: before the check, before the line, before the first byte).
    let other = RelaySocket::spawn(e.server.clone(), e.site.clone());
    *e.egress.switch_at.lock() = Some((4, other.route()));
    let err = e.list().await.unwrap_err();
    assert_eq!(err.code, ErrorCode::ProviderEgressBlocked, "{err:?}");
    assert_eq!(e.site.log(), ["GET /login/"], "nothing more was sent");
    assert!(
        other.seen().is_empty(),
        "never follows the egress elsewhere"
    );
}

#[tokio::test]
async fn the_ddns_check_and_the_free_port_search_go_through_the_guard() {
    let e = env(FakeSite::new(USER, PASSWORD).with_ports(&[40000]));
    e.site.port(40000, |p| p.dns = "my-box".into());
    let report = e
        .providers
        .ddns_via(&*e.egress, e.account, &creds())
        .await
        .unwrap();
    assert_eq!(report.names.len(), 1);
    assert_eq!(report.names[0].name, "my-box");
    assert_eq!(report.names[0].sessions, 0, "no session uses it");
    let found = e
        .providers
        .free_ports_via(&*e.egress, e.account, &creds(), 2)
        .await
        .unwrap();
    assert_eq!(found.message, "Ports 41000-41001 are free right now.");
    let refused = e
        .providers
        .free_ports_via(&*e.egress, e.account, &creds(), 1)
        .await
        .unwrap_err();
    assert_eq!(refused.code, ErrorCode::ValidationFailed, "{refused:?}");
    assert_eq!(refused.field_errors[0].path, "/count");
    // Sign-in (3), the check, the search; the refused search sent nothing.
    assert_eq!(e.relay.lines(), paired(5));
    e.relay_clean();
    e.clean("the log", &e.logs());
}
