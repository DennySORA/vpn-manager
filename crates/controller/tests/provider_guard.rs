//! The Provider egress guard (spec AC-74, AC-76, AC-77, AC-82, AC-114) against in-memory relays.
//! Each relay is a Unix socket in a temporary directory that admits request lines with the
//! connectors' own `Admission` (nonce, route, epochs), then plays the provider's TLS endpoints
//! with a throwaway CA. The egress binding comes from a scripted fake of the manager. Nothing
//! touches the network, the manager, or a real account.

#![cfg(test)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::assert_matches;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use vpn_controller::provider::budget::Limits;
use vpn_controller::provider::guard::{Egress, PERMIT_TTL, RouteProfile};
use vpn_controller::provider::{Providers, Relay, Route};
use vpn_domain::*;
use vpn_ipc::relay::{Admission, RelayAnswer, RelayEpochs, RelayFamily, RelayRoute};
use vpn_providers::https::Request;
use vpn_providers::mullvad::{AccountNumber, Mullvad};
use vpn_providers::{Connect, Family, HttpsClient, ProviderError, Target, Tls};
use vpn_sync::Mutex;

const API: &str = "api.mullvad.net";
const MULLVAD_CHECK: &str = "ipv4.am.i.mullvad.net";
const AIR: &str = "airvpn.org";
const TOKEN: &str = include_str!("../../providers/tests/fixtures/mullvad/token.json");
const ACCOUNT: &str = include_str!("../../providers/tests/fixtures/mullvad/account.json");
const DEVICES: &str = include_str!("../../providers/tests/fixtures/mullvad/devices.json");
/// The access token in `TOKEN`: it must never appear in an exit check.
const TOKEN_SECRET: &str = "mva_d8c4f1a7e2b94c0d9e6f3a2b1c0d9e8f";
const HOSTS: &[&str] = &[
    API,
    MULLVAD_CHECK,
    "ipv6.am.i.mullvad.net",
    "ipv4.ipleak.net",
    AIR,
    // The built-in blocklists' sources.
    "www.spamhaus.org",
    "feeds.dshield.org",
    "raw.githubusercontent.com",
    "feodotracker.abuse.ch",
    "rules.emergingthreats.net",
    "cinsscore.com",
    "lists.blocklist.de",
];

// -------------------------------------------------------------------------------------------
// TLS: a throwaway CA
// -------------------------------------------------------------------------------------------

fn tls() -> (RootCertStore, Arc<rustls::ServerConfig>) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(issuer.der().clone()).unwrap();
    let key = KeyPair::generate().unwrap();
    let names = HOSTS.iter().map(|h| (*h).to_owned()).collect::<Vec<_>>();
    let cert = CertificateParams::new(names)
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

// -------------------------------------------------------------------------------------------
// A relay socket
// -------------------------------------------------------------------------------------------

/// What a relay saw, in order.
#[derive(Debug, Clone)]
enum Seen {
    /// A request line: where it was for, the epochs it expected (an authorized request), and
    /// the refusal code when it was refused.
    Line {
        host: String,
        port: u16,
        expect: Option<RelayEpochs>,
        refused: Option<String>,
        raw: String,
        at: Instant,
    },
    /// An HTTP request on an admitted connection.
    Http {
        host: String,
        method: String,
        path: String,
        authorization: Option<String>,
        body: Vec<u8>,
    },
}

impl Seen {
    fn is_line_to(&self, h: &str) -> bool {
        matches!(self, Self::Line { host, .. } if host == h)
    }
}

struct Answer {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: String,
}

fn ok(body: &str) -> Answer {
    Answer {
        status: 200,
        headers: Vec::new(),
        body: body.to_owned(),
    }
}

/// (host, method, path, family) → the answer.
type Handler = Arc<dyn Fn(&str, &str, &str, RelayFamily) -> Answer + Send + Sync>;

/// The exit checkers' answers: every exit is the provider's own.
fn checkers(host: &str, family: RelayFamily) -> Option<Answer> {
    let v6 = family == RelayFamily::V6;
    match host {
        MULLVAD_CHECK => Some(ok(
            r#"{"ip":"198.51.100.9","country":"Sweden","city":"Gothenburg","mullvad_exit_ip":true}"#,
        )),
        "ipv4.ipleak.net" => Some(ok(
            r#"{"ip":"198.51.100.23","country_name":"Netherlands","city_name":"Amsterdam"}"#,
        )),
        AIR if v6 => Some(ok(r#"{"result":"ok","ip":"2001:db8::20","airvpn":true}"#)),
        AIR => Some(ok(r#"{"result":"ok","ip":"198.51.100.20","airvpn":true}"#)),
        _ => None,
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    route: RelayRoute,
    seen: Arc<Mutex<Vec<Seen>>>,
    network: Arc<AtomicU64>,
    admission: Arc<Mutex<Arc<Admission>>>,
}

impl Fixture {
    /// A relay for `route`; `refuse_dial` names destinations it cannot reach (refused with
    /// that code after admission, like a connector whose dial failed).
    fn spawn(
        route: RelayRoute,
        server: Arc<rustls::ServerConfig>,
        handler: Handler,
        refuse_dial: fn(&str, u16, RelayFamily) -> Option<&'static str>,
    ) -> Self {
        // Private like the manager's run directory: a client refuses a socket others could replace.
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = dir.path().join("c.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let network = Arc::new(AtomicU64::new(1));
        let admission = Arc::new(Mutex::new(Arc::new(Admission::new(route))));
        let acceptor = TlsAcceptor::from(server);
        let (s, n, a) = (seen.clone(), network.clone(), admission.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (seen, network, admission) = (s.clone(), n.clone(), a.lock().clone());
                let (acceptor, handler) = (acceptor.clone(), handler.clone());
                tokio::spawn(serve(
                    stream,
                    seen,
                    network,
                    admission,
                    acceptor,
                    handler,
                    refuse_dial,
                ));
            }
        });
        Self {
            _dir: dir,
            path,
            route,
            seen,
            network,
            admission,
        }
    }

    fn relay(&self) -> Relay {
        match self.route {
            RelayRoute::Instance {
                instance_id,
                generation,
            } => Relay::instance(self.path.display().to_string(), instance_id, generation),
            RelayRoute::Bootstrap => Relay::bootstrap(self.path.display().to_string()),
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().clone()
    }

    /// Another connector behind the same path (a new connector epoch).
    fn replace_connector(&self) {
        *self.admission.lock() = Arc::new(Admission::new(self.route));
    }
}

async fn serve(
    stream: UnixStream,
    seen: Arc<Mutex<Vec<Seen>>>,
    network: Arc<AtomicU64>,
    admission: Arc<Admission>,
    acceptor: TlsAcceptor,
    handler: Handler,
    refuse_dial: fn(&str, u16, RelayFamily) -> Option<&'static str>,
) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() {
        return;
    }
    let mut stream = reader.into_inner();
    let raw = line.trim_end().to_owned();
    let epoch = network.load(Ordering::SeqCst);
    let admitted = admission.admit(&raw, epoch);
    let (answer, request) = match admitted {
        Err(refusal) => (refusal, None),
        Ok(r) => match refuse_dial(&r.host, r.port, r.family) {
            Some(code) => (
                RelayAnswer::refuse(code, "無法連線").with_epochs(admission.epochs(epoch)),
                Some(r),
            ),
            None => (
                RelayAnswer::connected("203.0.113.5:443".parse().unwrap(), admission.epochs(epoch)),
                Some(r),
            ),
        },
    };
    let parsed: Option<vpn_ipc::relay::RelayLine> = serde_json::from_str(&raw).ok();
    seen.lock().push(Seen::Line {
        host: parsed.as_ref().map_or_default(|l| l.host.clone()),
        port: parsed.as_ref().map_or(0, |l| l.port),
        expect: parsed.as_ref().and_then(|l| l.expect),
        refused: answer.code.clone(),
        raw,
        at: Instant::now(),
    });
    if stream.write_all(&answer.to_bytes()).await.is_err() || !answer.ok {
        return;
    }
    let Some(request) = request else { return };
    let Ok(tls) = acceptor.accept(stream).await else {
        return;
    };
    let family = request.family;
    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let (seen, handler) = (seen.clone(), handler.clone());
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
                host: host.clone(),
                method: parts.method.to_string(),
                path: path.clone(),
                authorization: header("authorization"),
                body,
            });
            let a = checkers(&host, family)
                .unwrap_or_else(|| handler(&host, parts.method.as_str(), &path, family));
            let mut response = hyper::Response::new(Full::new(Bytes::from(a.body)));
            *response.status_mut() = hyper::StatusCode::from_u16(a.status).unwrap();
            for (name, value) in a.headers {
                response
                    .headers_mut()
                    .insert(name, hyper::header::HeaderValue::from_str(&value).unwrap());
            }
            Ok::<_, Infallible>(response)
        }
    });
    #[expect(
        clippy::let_underscore_must_use,
        reason = "the connection ends when the client is done or gives up; either way this relay connection is over"
    )]
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(tls), service)
        .await;
}

const fn reach_all(_: &str, _: u16, _: RelayFamily) -> Option<&'static str> {
    None
}

// -------------------------------------------------------------------------------------------
// The manager, scripted
// -------------------------------------------------------------------------------------------

type Hook = Box<dyn FnOnce() + Send>;

/// The egress binding as the manager would answer, with scripted changes at given reads.
struct FakeEgress {
    route: Mutex<Route>,
    profile: Mutex<RouteProfile>,
    reads: AtomicUsize,
    /// Run before answering the n-th read (0-based).
    hooks: Mutex<HashMap<usize, Hook>>,
    /// Reads that take this long.
    slow: Mutex<HashMap<usize, Duration>>,
}

impl FakeEgress {
    fn new(route: Route, provider: ProviderKind) -> Arc<Self> {
        Arc::new(Self {
            route: Mutex::new(route),
            profile: Mutex::new(RouteProfile {
                provider,
                ipv6: false,
            }),
            reads: AtomicUsize::new(0),
            hooks: Mutex::default(),
            slow: Mutex::default(),
        })
    }

    fn at(&self, read: usize, hook: impl FnOnce() + Send + 'static) {
        self.hooks.lock().insert(read, Box::new(hook));
    }

    fn slow(&self, read: usize, by: Duration) {
        self.slow.lock().insert(read, by);
    }

    fn set(&self, route: Route) {
        *self.route.lock() = route;
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl Egress for FakeEgress {
    async fn route(&self) -> Result<Route, ApiError> {
        let n = self.reads.fetch_add(1, Ordering::SeqCst);
        let delay = self.slow.lock().remove(&n);
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        let hook = self.hooks.lock().remove(&n);
        if let Some(hook) = hook {
            hook();
        }
        Ok(self.route.lock().clone())
    }

    fn profile(&self, _: &Route) -> impl Future<Output = RouteProfile> + Send {
        std::future::ready(*self.profile.lock())
    }
}

fn instance_route(fixture: &Fixture, egress_epoch: u64) -> Route {
    let RelayRoute::Instance {
        instance_id,
        generation,
    } = fixture.route
    else {
        unreachable!()
    };
    Route {
        mode: RouteMode::ViaInstance,
        instance_id: Some(instance_id),
        generation: Some(generation),
        egress_epoch,
        relay: fixture.relay(),
    }
}

/// The route of a direct grant (the first setup's or a rebootstrap's): the manager's bootstrap
/// relay, no Instance behind it.
fn bootstrap_route(fixture: &Fixture, egress_epoch: u64) -> Route {
    Route {
        mode: RouteMode::BootstrapDirect,
        instance_id: None,
        generation: None,
        egress_epoch,
        relay: fixture.relay(),
    }
}

fn instance() -> RelayRoute {
    RelayRoute::Instance {
        instance_id: InstanceId::new(),
        generation: 3,
    }
}

/// Answers the Mullvad API with its recorded fixtures.
fn mullvad_api(_: &str, method: &str, path: &str, _: RelayFamily) -> Answer {
    match (method, path) {
        ("POST", "/auth/v1/token") => ok(TOKEN),
        ("GET", "/accounts/v1/accounts/me") => ok(ACCOUNT),
        ("GET", "/accounts/v1/devices") => ok(DEVICES),
        _ => ok("{}"),
    }
}

struct Env {
    roots: RootCertStore,
    server: Arc<rustls::ServerConfig>,
}

fn env() -> Env {
    let (roots, server) = tls();
    Env { roots, server }
}

impl Env {
    fn providers(&self, ttl: Duration) -> Arc<Providers> {
        Providers::with(Tls::with_roots(self.roots.clone()), Limits::default(), ttl)
    }

    fn relay(&self, route: RelayRoute, handler: Handler) -> Fixture {
        Fixture::spawn(route, self.server.clone(), handler, reach_all)
    }
}

fn number() -> AccountNumber {
    AccountNumber::parse("1234 5678 9012 3456").unwrap()
}

/// The checks and requests a relay saw, as `(line host, authorized)` pairs.
fn lines(seen: &[Seen]) -> Vec<(String, bool)> {
    seen.iter()
        .filter_map(|s| match s {
            Seen::Line { host, expect, .. } => Some((host.clone(), expect.is_some())),
            Seen::Http { .. } => None,
        })
        .collect()
}

fn https(seen: &[Seen]) -> Vec<(String, String, String)> {
    seen.iter()
        .filter_map(|s| match s {
            Seen::Http {
                host, method, path, ..
            } => Some((host.clone(), method.clone(), path.clone())),
            Seen::Line { .. } => None,
        })
        .collect()
}

/// The exit checkers' paths (Mullvad, `IPLeak`, `AirVPN`).
const CHECK_PATHS: &[&str] = &["/json", "/json/", "/api/whatismyip/"];

/// Every exit check carried nothing of the account — no `Authorization`, no body — and no relay
/// line carried the token.
fn checks_carry_no_credentials(seen: &[Seen]) {
    let mut checks = 0;
    for s in seen {
        match s {
            Seen::Http {
                host,
                path,
                authorization,
                body,
                ..
            } if CHECK_PATHS.contains(&path.as_str()) => {
                checks += 1;
                assert!(
                    authorization.is_none(),
                    "a check to {host} carried a credential"
                );
                assert!(body.is_empty(), "a check to {host} carried a body");
            }
            Seen::Line { raw, .. } => {
                assert!(
                    !raw.contains(TOKEN_SECRET),
                    "the token reached a relay line"
                );
            }
            Seen::Http { .. } => {}
        }
    }
    assert!(checks > 0, "no check was seen");
}

// -------------------------------------------------------------------------------------------
// AC-76: every HTTP request has its own fresh check
// -------------------------------------------------------------------------------------------

/// A direct grant — the first setup's or a manual rebootstrap's — is the manager's version-2
/// bootstrap relay: every provider request over it still gets its own fresh exit check (reported
/// as not through a tunnel), authorized by it; and once the run is sealed (the egress fence moves
/// to the new connection) nothing more leaves over the grant.
#[tokio::test]
async fn a_direct_grant_carries_each_request_after_its_own_fresh_check_until_the_seal() {
    let env = env();
    let relay = env.relay(RelayRoute::Bootstrap, Arc::new(mullvad_api));
    let egress = FakeEgress::new(bootstrap_route(&relay, 4), ProviderKind::Mullvad);
    let providers = env.providers(PERMIT_TTL);
    let guard = providers.guard(&*egress).await.unwrap();
    let api = Mullvad::new(providers.client(guard), Family::V4);

    let token = api.token(&number()).await.unwrap();
    api.account(&token).await.unwrap();
    let seen = relay.seen();
    assert_eq!(
        lines(&seen),
        vec![
            (MULLVAD_CHECK.into(), false),
            (API.into(), true),
            (MULLVAD_CHECK.into(), false),
            (API.into(), true),
        ],
        "each request over the grant preceded by its own check, and authorized by it"
    );
    checks_carry_no_credentials(&seen);
    let last = providers.last_check().unwrap();
    assert_eq!(last.route_mode, RouteMode::BootstrapDirect);
    assert!(
        !last.tunnel_verified,
        "a direct check never claims a tunnel"
    );

    // The seal: the binding now names the new connection (a new egress fence). The operation
    // pinned to the grant sends nothing more, over either path.
    let next = env.relay(instance(), Arc::new(mullvad_api));
    egress.set(instance_route(&next, 5));
    let before = relay.seen().len();
    let e = api.devices(&token).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::ProviderEgressBlocked, "{e}");
    assert!(e.text().zh_tw.contains("不會改走其他出口"), "{e}");
    assert_eq!(relay.seen().len(), before, "nothing more over the grant");
    assert!(
        next.seen().is_empty(),
        "never follows the egress to the new connection"
    );
}

#[tokio::test]
async fn a_token_refresh_and_each_api_call_get_their_own_fresh_check() {
    let env = env();
    let relay = env.relay(instance(), Arc::new(mullvad_api));
    let egress = FakeEgress::new(instance_route(&relay, 7), ProviderKind::Mullvad);
    let providers = env.providers(PERMIT_TTL);
    let guard = providers.guard(&*egress).await.unwrap();
    let api = Mullvad::new(providers.client(guard), Family::V4);

    let token = api.token(&number()).await.unwrap();
    let account = api.account(&token).await.unwrap();
    assert!(account.max_devices.is_some());

    let seen = relay.seen();
    assert_eq!(
        lines(&seen),
        vec![
            (MULLVAD_CHECK.into(), false),
            (API.into(), true),
            (MULLVAD_CHECK.into(), false),
            (API.into(), true),
        ],
        "each request preceded by its own check, and authorized by it"
    );
    assert_eq!(
        https(&seen),
        vec![
            (MULLVAD_CHECK.into(), "GET".into(), "/json".into()),
            (API.into(), "POST".into(), "/auth/v1/token".into()),
            (MULLVAD_CHECK.into(), "GET".into(), "/json".into()),
            (API.into(), "GET".into(), "/accounts/v1/accounts/me".into()),
        ]
    );
    // The account call carries the token; no check ever does.
    assert!(seen.iter().any(
        |s| matches!(s, Seen::Http { path, authorization: Some(a), .. }
        if path == "/accounts/v1/accounts/me" && a.contains(TOKEN_SECRET))
    ));
    checks_carry_no_credentials(&seen);
    // Each request names the epochs its own check saw.
    let expected = relay
        .admission
        .lock()
        .epochs(relay.network.load(Ordering::SeqCst));
    for s in &seen {
        if let Seen::Line {
            expect: Some(e), ..
        } = s
        {
            assert_eq!(*e, expected);
        }
    }
    // The latest check is the last probe, over this route.
    let last = providers.last_check().unwrap();
    assert_eq!(last.instance_id, instance_route(&relay, 7).instance_id);
    assert_eq!(last.provider_match, ProviderMatch::Match);
}

#[tokio::test]
async fn a_create_with_an_unknown_outcome_and_its_reconcile_each_get_a_fresh_check() {
    let env = env();
    let relay = env.relay(
        instance(),
        Arc::new(|h: &str, m: &str, p: &str, f| match (m, p) {
            ("POST", "/accounts/v1/devices") => Answer {
                status: 502,
                headers: Vec::new(),
                body: String::new(),
            },
            _ => mullvad_api(h, m, p, f),
        }),
    );
    let egress = FakeEgress::new(instance_route(&relay, 1), ProviderKind::Mullvad);
    let providers = env.providers(PERMIT_TTL);
    let api = Mullvad::new(
        providers.client(providers.guard(&*egress).await.unwrap()),
        Family::V4,
    );
    let token = api.token(&number()).await.unwrap();
    let key: WgKey = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU="
        .parse()
        .unwrap();
    let e = api.create_device(&token, &key).await.unwrap_err();
    assert!(e.outcome_unknown(), "{e:?}");
    let reconciled = api.reconcile_device(&token, &key).await.unwrap();
    assert_matches!(reconciled, vpn_providers::mullvad::Reconciled::Bound(_));
    let seen = relay.seen();
    assert_eq!(
        https(&seen)
            .into_iter()
            .map(|(h, m, p)| format!("{m} {h}{p}"))
            .collect::<Vec<_>>(),
        vec![
            "GET ipv4.am.i.mullvad.net/json",
            "POST api.mullvad.net/auth/v1/token",
            "GET ipv4.am.i.mullvad.net/json",
            "POST api.mullvad.net/accounts/v1/devices",
            "GET ipv4.am.i.mullvad.net/json",
            "GET api.mullvad.net/accounts/v1/devices",
        ]
    );
    checks_carry_no_credentials(&seen);
}

#[tokio::test]
async fn pages_and_retries_each_get_their_own_check_and_a_check_never_checks_itself() {
    let env = env();
    let tries = Arc::new(AtomicUsize::new(0));
    let t = tries.clone();
    let relay = env.relay(
        instance(),
        Arc::new(move |_: &str, _: &str, p: &str, _| {
            if p == "/flaky" && t.fetch_add(1, Ordering::SeqCst) == 0 {
                return Answer {
                    status: 503,
                    headers: Vec::new(),
                    body: String::new(),
                };
            }
            ok("{}")
        }),
    );
    let egress = FakeEgress::new(instance_route(&relay, 1), ProviderKind::Mullvad);
    let providers = env.providers(PERMIT_TTL);
    let client: HttpsClient<_> = providers.client(providers.guard(&*egress).await.unwrap());
    for page in 1..=3 {
        let r = client
            .send(Request::new(
                hyper::Method::GET,
                API,
                format!("/list?page={page}"),
                Family::V4,
            ))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
    }
    // A read retried after a server error.
    for _ in 0..2 {
        let _ = client
            .send(Request::new(hyper::Method::GET, API, "/flaky", Family::V4))
            .await
            .unwrap();
    }
    let seen = relay.seen();
    let l = lines(&seen);
    assert_eq!(l.len(), 10);
    for pair in l.chunks(2) {
        assert_eq!(pair[0], (MULLVAD_CHECK.into(), false), "{l:?}");
        assert_eq!(pair[1], (API.into(), true), "{l:?}");
    }
    checks_carry_no_credentials(&seen);
}

#[tokio::test]
async fn each_airvpn_bootstrap_attempt_gets_its_own_check() {
    let env = env();
    // No bootstrap address answers: Eddie's client tries them all.
    let relay = Fixture::spawn(
        instance(),
        env.server.clone(),
        Arc::new(|_: &str, _: &str, _: &str, _| ok("{}")),
        |_, port, _| (port == 80).then_some("CONNECT"),
    );
    let egress = FakeEgress::new(instance_route(&relay, 1), ProviderKind::Airvpn);
    let providers = env.providers(PERMIT_TTL);
    let guard = providers.guard(&*egress).await.unwrap();
    let credentials = vpn_providers::airvpn::Credentials::new("user", "password").unwrap();
    let e = vpn_providers::airvpn::AirVpn::new(guard)
        .user(&credentials)
        .await
        .unwrap_err();
    assert_matches!(e, ProviderError::Unavailable(_));
    let seen = relay.seen();
    let l = lines(&seen);
    let addresses: Vec<String> = vpn_providers::airvpn::BOOTSTRAP_IPS
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(l.len(), 8, "{l:?}");
    for (pair, ip) in l.chunks(2).zip(&addresses) {
        assert_eq!(pair[0], (AIR.into(), false));
        assert_eq!(pair[1], (ip.clone(), true));
    }
    assert!(seen.iter().all(|s| match s {
        Seen::Line { host, port, .. } if host == AIR => *port == 443,
        Seen::Line { port, .. } => *port == vpn_providers::airvpn::BOOTSTRAP_PORT,
        Seen::Http { .. } => true,
    }));
    // The password went to no check (it is sealed for AirVPN anyway, and never relayed here).
    assert!(!format!("{seen:?}").contains("password"));
    checks_carry_no_credentials(&seen);
}

// -------------------------------------------------------------------------------------------
// AC-77 / AC-74: nothing is sent once the binding moved, the check is stale, the nonce is
// spent or the request is not the one prepared
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_switch_between_the_check_and_the_request_sends_nothing_and_never_follows() {
    let env = env();
    let a = env.relay(instance(), Arc::new(mullvad_api));
    let b = env.relay(instance(), Arc::new(mullvad_api));
    let providers = env.providers(PERMIT_TTL);
    // Reads: 0 the guard, 1 before the check, 2 right before the line, 3 right before the
    // first byte.
    let egress = FakeEgress::new(instance_route(&a, 5), ProviderKind::Mullvad);
    let to_b = instance_route(&b, 6);
    let e2 = egress.clone();
    egress.at(2, move || e2.set(to_b));
    let api = Mullvad::new(
        providers.client(providers.guard(&*egress).await.unwrap()),
        Family::V4,
    );
    let e = api.token(&number()).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::ProviderEgressBlocked, "{e}");
    assert!(e.text().zh_tw.contains("不會改走其他出口"), "{e}");
    assert_eq!(lines(&a.seen()), vec![(MULLVAD_CHECK.into(), false)]);
    assert!(
        b.seen().is_empty(),
        "never moved to the new egress by itself"
    );
    // The operation stays refused: it is pinned to the route it started on.
    let again = api.token(&number()).await.unwrap_err();
    assert_eq!(again.code(), ErrorCode::ProviderEgressBlocked);
    assert!(b.seen().is_empty());
    assert_eq!(
        lines(&a.seen()).len(),
        1,
        "not even a check on the old route"
    );
    // A new operation runs on the route now chosen, and only there.
    let api = Mullvad::new(
        providers.client(providers.guard(&*egress).await.unwrap()),
        Family::V4,
    );
    api.token(&number()).await.unwrap();
    assert_eq!(
        lines(&b.seen()),
        vec![(MULLVAD_CHECK.into(), false), (API.into(), true)]
    );
    assert_eq!(lines(&a.seen()).len(), 1);
}

#[tokio::test]
async fn a_switch_after_the_line_is_caught_right_before_the_first_byte() {
    let env = env();
    let a = env.relay(instance(), Arc::new(mullvad_api));
    let b = env.relay(instance(), Arc::new(mullvad_api));
    let providers = env.providers(PERMIT_TTL);
    let egress = FakeEgress::new(instance_route(&a, 5), ProviderKind::Mullvad);
    let to_b = instance_route(&b, 6);
    let e2 = egress.clone();
    egress.at(3, move || e2.set(to_b));
    let api = Mullvad::new(
        providers.client(providers.guard(&*egress).await.unwrap()),
        Family::V4,
    );
    let e = api.token(&number()).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::ProviderEgressBlocked, "{e}");
    let seen = a.seen();
    // The line went out and TLS came up, but not one byte of the request.
    assert_eq!(
        lines(&seen),
        vec![(MULLVAD_CHECK.into(), false), (API.into(), true)]
    );
    assert_eq!(
        https(&seen),
        vec![(MULLVAD_CHECK.into(), "GET".into(), "/json".into())]
    );
    assert!(b.seen().is_empty());
    assert_eq!(egress.reads(), 4);
}

#[tokio::test]
async fn a_rebuild_or_turning_the_egress_off_after_the_check_sends_nothing() {
    let env = env();
    let a = env.relay(instance(), Arc::new(mullvad_api));
    let providers = env.providers(PERMIT_TTL);
    // A rebuild: the same connection, its next generation.
    let egress = FakeEgress::new(instance_route(&a, 5), ProviderKind::Mullvad);
    let mut rebuilt = instance_route(&a, 5);
    rebuilt.generation = Some(4);
    let e2 = egress.clone();
    egress.at(2, move || e2.set(rebuilt));
    let api = Mullvad::new(
        providers.client(providers.guard(&*egress).await.unwrap()),
        Family::V4,
    );
    let e = api.token(&number()).await.unwrap_err();
    assert!(e.text().zh_tw.contains("第 3 代 → 第 4 代"), "{e}");
    // Turned off and on again (or switched away and back): the egress epoch moved.
    let egress = FakeEgress::new(instance_route(&a, 5), ProviderKind::Mullvad);
    let back = instance_route(&a, 6);
    let e2 = egress.clone();
    egress.at(2, move || e2.set(back));
    let api = Mullvad::new(
        providers.client(providers.guard(&*egress).await.unwrap()),
        Family::V4,
    );
    let e = api.token(&number()).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::ProviderEgressBlocked);
    assert!(
        lines(&a.seen()).iter().all(|(h, _)| h == MULLVAD_CHECK),
        "no request line at all"
    );
}

#[tokio::test]
async fn a_check_older_than_two_seconds_is_never_used() {
    let env = env();
    let relay = env.relay(instance(), Arc::new(mullvad_api));
    let providers = env.providers(PERMIT_TTL);
    // The read right before the line takes longer than the permit lives: that check is
    // dropped and one fresh check made instead (a request queued too long is checked again).
    let egress = FakeEgress::new(instance_route(&relay, 1), ProviderKind::Mullvad);
    egress.slow(2, PERMIT_TTL + Duration::from_millis(100));
    let api = Mullvad::new(
        providers.client(providers.guard(&*egress).await.unwrap()),
        Family::V4,
    );
    api.token(&number()).await.unwrap();
    let seen = relay.seen();
    assert_eq!(
        lines(&seen),
        vec![
            (MULLVAD_CHECK.into(), false),
            (MULLVAD_CHECK.into(), false),
            (API.into(), true),
        ]
    );
    // The request went right after its own (second) check.
    let (Seen::Line { at: checked, .. }, Seen::Line { at: sent, .. }) = (
        seen.iter()
            .filter(|s| s.is_line_to(MULLVAD_CHECK))
            .nth(1)
            .unwrap(),
        seen.iter().find(|s| s.is_line_to(API)).unwrap(),
    ) else {
        unreachable!()
    };
    assert!(sent.duration_since(*checked) < PERMIT_TTL);
}

#[tokio::test]
async fn a_request_whose_checks_keep_going_stale_is_refused_unsent() {
    let env = env();
    let relay = env.relay(instance(), Arc::new(mullvad_api));
    let ttl = Duration::from_millis(200);
    let providers = env.providers(ttl);
    let egress = FakeEgress::new(instance_route(&relay, 1), ProviderKind::Mullvad);
    // Reads 2 and 4: right before the line, after the first and the second check.
    egress.slow(2, ttl + Duration::from_millis(100));
    egress.slow(4, ttl + Duration::from_millis(100));
    let api = Mullvad::new(
        providers.client(providers.guard(&*egress).await.unwrap()),
        Family::V4,
    );
    let e = api.token(&number()).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::ProviderPreflightFailed, "{e}");
    assert!(e.text().zh_tw.contains("未送出"), "{e}");
    assert!(lines(&relay.seen()).iter().all(|(h, _)| h == MULLVAD_CHECK));
}

#[tokio::test]
async fn the_connector_refuses_a_replayed_request_line() {
    let env = env();
    let relay = env.relay(instance(), Arc::new(mullvad_api));
    let providers = env.providers(PERMIT_TTL);
    let egress = FakeEgress::new(instance_route(&relay, 1), ProviderKind::Mullvad);
    let api = Mullvad::new(
        providers.client(providers.guard(&*egress).await.unwrap()),
        Family::V4,
    );
    api.token(&number()).await.unwrap();
    // Replaying the request's own line: refused by the connector before it dials.
    let raw = relay
        .seen()
        .into_iter()
        .find_map(|s| match s {
            Seen::Line {
                host, raw, expect, ..
            } if host == API && expect.is_some() => Some(raw),
            _ => None,
        })
        .unwrap();
    let mut s = UnixStream::connect(&relay.path).await.unwrap();
    s.write_all(format!("{raw}\n").as_bytes()).await.unwrap();
    let mut reader = BufReader::new(s);
    let mut answer = String::new();
    reader.read_line(&mut answer).await.unwrap();
    let answer: RelayAnswer = serde_json::from_str(answer.trim_end()).unwrap();
    assert!(!answer.ok);
    assert_eq!(answer.code.as_deref(), Some(vpn_ipc::relay::NONCE_REUSED));
    // The replay reached no provider: the one token request is all the relay served.
    let tokens = https(&relay.seen())
        .into_iter()
        .filter(|(_, _, p)| p == "/auth/v1/token")
        .count();
    assert_eq!(tokens, 1);
}

#[tokio::test]
async fn moved_network_or_connector_epochs_refuse_the_request_at_the_connector() {
    let env = env();
    let relay = Arc::new(env.relay(instance(), Arc::new(mullvad_api)));
    let providers = env.providers(PERMIT_TTL);
    // The tunnel went down and came back after the check (read 2: right before the line).
    let egress = FakeEgress::new(instance_route(&relay, 1), ProviderKind::Mullvad);
    let network = relay.network.clone();
    egress.at(2, move || {
        network.fetch_add(1, Ordering::SeqCst);
    });
    let api = Mullvad::new(
        providers.client(providers.guard(&*egress).await.unwrap()),
        Family::V4,
    );
    let e = api.token(&number()).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::ProviderPreflightFailed, "{e}");
    assert!(e.text().zh_tw.contains("tunnel 曾中斷"), "{e}");
    let refused: Vec<Option<String>> = relay
        .seen()
        .into_iter()
        .filter_map(|s| match s {
            Seen::Line { host, refused, .. } if host == API => Some(refused),
            _ => None,
        })
        .collect();
    assert_eq!(
        refused,
        vec![Some(vpn_ipc::relay::EPOCH_CHANGED.to_owned())]
    );
    assert!(
        https(&relay.seen())
            .iter()
            .all(|(h, _, _)| h == MULLVAD_CHECK)
    );

    // Another connector behind the same path after the check.
    let egress = FakeEgress::new(instance_route(&relay, 1), ProviderKind::Mullvad);
    let r = relay.clone();
    egress.at(2, move || r.replace_connector());
    let api = Mullvad::new(
        providers.client(providers.guard(&*egress).await.unwrap()),
        Family::V4,
    );
    let e = api.token(&number()).await.unwrap_err();
    assert!(e.text().zh_tw.contains("通道已更換"), "{e}");
}

#[tokio::test]
async fn a_permit_is_good_only_for_the_request_it_was_issued_for() {
    let env = env();
    let relay = env.relay(instance(), Arc::new(mullvad_api));
    let providers = env.providers(PERMIT_TTL);
    let egress = FakeEgress::new(instance_route(&relay, 1), ProviderKind::Mullvad);
    let guard = providers.guard(&*egress).await.unwrap();
    let prepared = Target {
        method: &hyper::Method::GET,
        host: API,
        port: 443,
        path: "/accounts/v1/devices",
        family: Family::V4,
        timeout: Duration::from_secs(10),
    };
    let mut opened = guard.connect_for(&prepared).await.ok().unwrap();
    let permit = opened.permit.as_mut().unwrap();
    for changed in [
        Target {
            method: &hyper::Method::DELETE,
            ..prepared
        },
        Target {
            path: "/accounts/v1/devices/0d9b6c1e-3f2a-4b5c-8d7e-9f0a1b2c3d4e",
            ..prepared
        },
    ] {
        let e = permit.confirm(&changed).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::ProviderPreflightFailed);
        assert!(e.message.zh_tw.contains("與出口檢查時準備的不同"), "{e}");
    }
    permit.confirm(&prepared).await.unwrap();
    drop(opened);
    // A connect without the request it is for opens nothing.
    assert!(guard.connect(API, 443, Family::V4).await.is_err());
    assert!(
        https(&relay.seen())
            .iter()
            .all(|(h, _, _)| h == MULLVAD_CHECK)
    );
}

// -------------------------------------------------------------------------------------------
// AC-82: the budget per origin
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_429_holds_the_origin_across_a_switch_and_the_queued_request_is_checked_after() {
    let env = env();
    let a = env.relay(
        instance(),
        Arc::new(|h: &str, m: &str, p: &str, f| match (m, p) {
            ("POST", "/auth/v1/token") => Answer {
                status: 429,
                headers: vec![("retry-after", "1".into())],
                body: String::new(),
            },
            _ => mullvad_api(h, m, p, f),
        }),
    );
    let b = env.relay(instance(), Arc::new(mullvad_api));
    let providers = env.providers(PERMIT_TTL);
    let egress = FakeEgress::new(instance_route(&a, 1), ProviderKind::Mullvad);
    let api = Mullvad::new(
        providers.client(providers.guard(&*egress).await.unwrap()),
        Family::V4,
    );
    let e = api.token(&number()).await.unwrap_err();
    assert_matches!(e, ProviderError::RateLimited { .. });
    let held_from = Instant::now();
    assert!(providers.budget().held(API).is_some());

    // The user switches the egress: the hold belongs to the origin, not to the route.
    egress.set(instance_route(&b, 2));
    let api = Mullvad::new(
        providers.client(providers.guard(&*egress).await.unwrap()),
        Family::V4,
    );
    api.token(&number()).await.unwrap();
    let seen = b.seen();
    let Some(Seen::Line { at: checked, .. }) = seen.first() else {
        panic!("{seen:?}")
    };
    assert!(
        checked.duration_since(held_from) >= Duration::from_millis(900),
        "the queued request's check ran only after the hold"
    );
    assert_eq!(
        lines(&seen),
        vec![(MULLVAD_CHECK.into(), false), (API.into(), true)]
    );
    assert_eq!(lines(&a.seen()).len(), 2, "nothing more to the old route");
}

// -------------------------------------------------------------------------------------------
// Built-in blocklists: downloaded only over the VPN egress connection
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn builtin_blocklists_are_downloaded_only_through_the_vpn_egress() {
    use vpn_domain::blocklist::parse_https_url;
    use vpn_domain::builtin_blocklists::BUILTIN_BLOCKLISTS;
    let env = env();
    // Each source answers in its own format.
    let lists: Handler = Arc::new(|host: &str, method: &str, path: &str, _| {
        match (host, method, path) {
            ("www.spamhaus.org", "GET", "/drop/drop_v4.json") => ok(
                "{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL256894\",\"rir\":\"apnic\"}\n{\"type\":\"metadata\",\"records\":1}\n",
            ),
            ("www.spamhaus.org", "GET", "/drop/drop_v6.json") => ok(
                "{\"cidr\":\"2001:678:254::/48\",\"sblid\":\"SBL697648\",\"rir\":\"ripencc\"}\n{\"type\":\"metadata\",\"records\":1}\n",
            ),
            ("feeds.dshield.org", "GET", "/block.txt") => ok(
                "# DShield.org Recommended Block List\n65.49.1.0\t65.49.1.255\t24\t341\tHURRICANE\tUS\tabuse@he.net\n",
            ),
            (
                "raw.githubusercontent.com",
                "GET",
                "/firehol/blocklist-ipsets/master/firehol_level1.netset",
            ) => ok("#\n# firehol_level1\n#\n1.10.16.0/20\n"),
            ("feodotracker.abuse.ch", "GET", "/downloads/ipblocklist_recommended.txt") => ok(
                "# abuse.ch Feodo Tracker Botnet C2 IP Blocklist\r\n50.16.16.211\r\n# END 1 entries\r\n",
            ),
            ("rules.emergingthreats.net", "GET", "/blockrules/compromised-ips.txt") => {
                ok("1.234.21.73\n")
            }
            ("cinsscore.com", "GET", "/list/ci-badguys.txt") => ok("1.12.231.30\n"),
            ("lists.blocklist.de", "GET", "/lists/all.txt") => ok("2.56.10.115\n"),
            ("raw.githubusercontent.com", "GET", "/stamparm/ipsum/master/levels/3.txt") => {
                ok("2.57.121.25\n")
            }
            _ => Answer {
                status: 404,
                headers: Vec::new(),
                body: String::new(),
            },
        }
    });
    let a = env.relay(instance(), lists.clone());
    let route = instance_route(&a, 1);
    let client = HttpsClient::with_roots(a.relay(), env.roots.clone());
    for b in BUILTIN_BLOCKLISTS {
        let url = parse_https_url(b.url).unwrap();
        let d = vpn_controller::blocklists::download_via(&route, &client, &url)
            .await
            .unwrap();
        assert_eq!(
            Some(d.fetch.via_instance_id),
            route.instance_id,
            "{}",
            b.key
        );
        assert_eq!(Some(d.fetch.via_generation), route.generation, "{}", b.key);
        assert_eq!(d.fetch.url, b.url);
        assert_eq!(d.parsed.stats.entries, 1, "{}", b.key);
        assert_eq!(d.parsed.stats.invalid, 0, "{}", b.key);
    }
    // One relay line per list, for the list's own host, on this Instance's route; no provider
    // permit is asked for (they are not provider requests), and one GET each.
    let seen = a.seen();
    let expected: Vec<(String, bool)> = BUILTIN_BLOCKLISTS
        .iter()
        .map(|b| (parse_https_url(b.url).unwrap().host, false))
        .collect();
    assert_eq!(lines(&seen), expected);
    let gets: Vec<(String, String)> = https(&seen)
        .into_iter()
        .map(|(host, method, path)| (format!("{method} {host}"), path))
        .collect();
    assert_eq!(gets.len(), BUILTIN_BLOCKLISTS.len());
    assert!(gets.iter().all(|(m, _)| m.starts_with("GET ")));

    // The first setup's direct exception never carries one: refused before a byte is sent.
    let direct = env.relay(RelayRoute::Bootstrap, lists);
    let client = HttpsClient::with_roots(direct.relay(), env.roots.clone());
    for b in BUILTIN_BLOCKLISTS {
        let url = parse_https_url(b.url).unwrap();
        let e =
            vpn_controller::blocklists::download_via(&bootstrap_route(&direct, 1), &client, &url)
                .await
                .err()
                .unwrap();
        assert_eq!(e.code, ErrorCode::ProviderEgressBlocked, "{}", b.key);
    }
    assert!(direct.seen().is_empty(), "nothing reached the direct relay");
}

// -------------------------------------------------------------------------------------------
// AC-114: each gate on its own
// -------------------------------------------------------------------------------------------
