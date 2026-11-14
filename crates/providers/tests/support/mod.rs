//! Offline fixtures: a throwaway CA made with rcgen, and a [`Fixture`] that is both the TLS +
//! HTTP/1.1 server and the [`Connect`] the client dials through. Every connection is an
//! in-memory duplex pipe: nothing touches a socket, a resolver or the network.

#![expect(dead_code, reason = "each test binary uses a different part")]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::DuplexStream;
use tokio_rustls::TlsAcceptor;
use vpn_providers::{BoxedStream, Connect, Family, HttpsClient};

/// Every origin this crate talks to; the fixture certificate covers them all.
pub const HOSTS: &[&str] = &[
    "api.mullvad.net",
    "ipv4.am.i.mullvad.net",
    "ipv6.am.i.mullvad.net",
    "ipv4.ipleak.net",
    "airvpn.org",
];

/// Throwaway CA and the server certificates it signs.
pub struct TestCa {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl TestCa {
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        Self { issuer }
    }

    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.issuer.der().clone()).unwrap();
        roots
    }

    /// Server certificate for `names`. The server also offers h2, so tests see which protocol
    /// the client picks.
    pub fn server_config(&self, names: &[&str]) -> Arc<rustls::ServerConfig> {
        let key = KeyPair::generate().unwrap();
        let names = names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        let cert = CertificateParams::new(names)
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
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    }
}

/// One request as the fixture server saw it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    /// TLS server name the client sent.
    pub sni: Option<String>,
    /// Protocol negotiated by ALPN.
    pub alpn: Option<Vec<u8>>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The `Host` header, which selects the fixture's answer like a virtual host.
    pub fn host(&self) -> &str {
        self.header("host").unwrap_or_default()
    }
}

/// One `connect` call the client made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dial {
    pub host: String,
    pub port: u16,
    pub family: Family,
}

pub enum Payload {
    /// Sent with `Content-Length`.
    Full(Vec<u8>),
    /// Sent with `Transfer-Encoding: chunked`, no declared length.
    Chunked(Vec<Vec<u8>>),
    /// Never answers.
    Stall,
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub payload: Payload,
}

impl Reply {
    pub fn json(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            payload: Payload::Full(body.as_bytes().to_vec()),
        }
    }

    pub const fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            payload: Payload::Full(Vec::new()),
        }
    }

    pub const fn chunked(status: u16, chunks: Vec<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            payload: Payload::Chunked(chunks),
        }
    }

    pub const fn stall() -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            payload: Payload::Stall,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    async fn into_response(self) -> Result<Response<TestBody>, Infallible> {
        let body = match self.payload {
            Payload::Full(bytes) => TestBody::new(vec![bytes], true),
            Payload::Chunked(chunks) => TestBody::new(chunks, false),
            Payload::Stall => std::future::pending().await,
        };
        let mut response = Response::new(body);
        *response.status_mut() = StatusCode::from_u16(self.status).unwrap();
        for (name, value) in &self.headers {
            response.headers_mut().append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        Ok(response)
    }
}

/// Response body that either declares its length or is sent chunked.
pub struct TestBody {
    chunks: VecDeque<Bytes>,
    declared: bool,
}

impl TestBody {
    fn new(chunks: Vec<Vec<u8>>, declared: bool) -> Self {
        Self {
            chunks: chunks
                .into_iter()
                .filter(|c| !c.is_empty())
                .map(Bytes::from)
                .collect(),
            declared,
        }
    }
}

impl Body for TestBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.chunks.pop_front().map(|c| Ok(Frame::data(c))))
    }

    fn is_end_stream(&self) -> bool {
        self.chunks.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        if self.declared {
            SizeHint::with_exact(self.chunks.iter().map(|c| c.len() as u64).sum())
        } else {
            SizeHint::default()
        }
    }
}

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

/// Fixture server and the connector that reaches it.
#[derive(Clone)]
pub struct Fixture {
    acceptor: TlsAcceptor,
    handler: Handler,
    seen: Arc<Mutex<Vec<Seen>>>,
    dials: Arc<Mutex<Vec<Dial>>>,
    refuse: Option<io::ErrorKind>,
}

impl Fixture {
    pub fn new(
        config: Arc<rustls::ServerConfig>,
        handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static,
    ) -> Self {
        Self {
            acceptor: TlsAcceptor::from(config),
            handler: Arc::new(handler),
            seen: Arc::default(),
            dials: Arc::default(),
            refuse: None,
        }
    }

    /// A connector that fails every connect, like a closed gate or a revoked bootstrap grant.
    pub const fn refusing(mut self, kind: io::ErrorKind) -> Self {
        self.refuse = Some(kind);
        self
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    pub fn dials(&self) -> Vec<Dial> {
        self.dials.lock().unwrap().clone()
    }
}

impl Fixture {
    /// What [`Connect::connect`] answers, at once.
    fn dial(&self, host: &str, port: u16, family: Family) -> io::Result<BoxedStream> {
        self.dials.lock().unwrap().push(Dial {
            host: host.to_owned(),
            port,
            family,
        });
        if let Some(kind) = self.refuse {
            return Err(io::Error::new(kind, "fixture connector refuses"));
        }
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(serve(
            server,
            self.acceptor.clone(),
            self.handler.clone(),
            self.seen.clone(),
        ));
        Ok(Box::new(client))
    }
}

impl Connect for Fixture {
    fn connect(
        &self,
        host: &str,
        port: u16,
        family: Family,
    ) -> impl Future<Output = io::Result<BoxedStream>> + Send {
        std::future::ready(self.dial(host, port, family))
    }
}

async fn serve(
    io: DuplexStream,
    acceptor: TlsAcceptor,
    handler: Handler,
    seen: Arc<Mutex<Vec<Seen>>>,
) {
    let Ok(tls) = acceptor.accept(io).await else {
        return;
    };
    let session = tls.get_ref().1;
    let sni = session.server_name().map(str::to_owned);
    let alpn = session.alpn_protocol().map(<[u8]>::to_vec);
    let service = service_fn(move |req: http::Request<Incoming>| {
        let (handler, seen, sni, alpn) = (handler.clone(), seen.clone(), sni.clone(), alpn.clone());
        async move {
            let (parts, body) = req.into_parts();
            let body = body
                .collect()
                .await
                .map_or_default(|b| b.to_bytes().to_vec());
            let request = Seen {
                method: parts.method.to_string(),
                path: parts.uri.path().to_owned(),
                headers: parts.headers,
                body,
                sni,
                alpn,
            };
            let reply = handler(&request);
            seen.lock().unwrap().push(request);
            reply.into_response().await
        }
    });
    #[expect(
        clippy::let_underscore_must_use,
        reason = "the client ends the connection when it is done or gives up; the tests check what the client saw"
    )]
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(tls), service)
        .await;
}

/// A CA, a fixture covering [`HOSTS`] with `handler`, and a client that trusts the CA.
pub struct Setup {
    pub ca: TestCa,
    pub fixture: Fixture,
    pub client: HttpsClient<Fixture>,
}

pub fn setup(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Setup {
    let ca = TestCa::new();
    let fixture = Fixture::new(ca.server_config(HOSTS), handler);
    let client = HttpsClient::with_roots(fixture.clone(), ca.roots());
    Setup {
        ca,
        fixture,
        client,
    }
}
