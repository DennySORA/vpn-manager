//! HTTPS/1.1 over a stream the caller provides.
//!
//! - The route is the caller's: [`Connect::connect`] gets the host name, port 443 and the
//!   [`Family`] (for the `AirVPN` bootstrap: one of its pinned IPv4 literals and port 80), and
//!   dials through the Instance tunnel (names resolved by the Instance DNS) or returns the
//!   manager's bootstrap socket. Nothing here reads proxy environment variables, resolves names
//!   or opens sockets.
//! - TLS: rustls with the webpki roots, SNI = request host, ALPN `http/1.1` only, certificate
//!   and host name verification always on. Session resumption is off, so no TLS state is carried
//!   from one route to the next (a resumed session would link two exits).
//! - HTTP: one request per connection (`Connection: close`), no redirects (3xx is an error, or —
//!   for a request that asks for it, `AirVPN`'s website — an answer with its headers that is never
//!   followed), the body limit is enforced while reading, and one deadline covers connect, TLS
//!   handshake, request and body. The same HTTP/1.1 exchange also carries the `AirVPN` bootstrap,
//!   which is plain HTTP by `AirVPN`'s design (its payload is encrypted end to end, see `airvpn`).
//! - Per-request authorization: the connector is told which prepared request each connection is
//!   for ([`Connect::connect_for`], a [`Target`]). One that authorizes requests one by one (the
//!   controller's Provider egress guard: budget, a fresh exit check, a single-use permit) hands
//!   back a [`Permit`], which the client confirms with the request it is about to write right
//!   before the request's first byte, and tells the answer's status. A [`Refusal`] stops the
//!   request unsent. The connector's own admission (waiting for its budget, the exit check) is
//!   not part of the request's deadline; the deadline starts when the connection is dialed.
//!
//! Request bodies and the received body sit in zeroizing buffers (a token request carries the
//! account number, a token response the token). Copies inside hyper and rustls are out of reach.

use std::fmt;
use std::future::Future;
use std::io::{self, Cursor};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsConnector;
use vpn_domain::{ErrorCode, Text, tr};
use zeroize::Zeroizing;

/// Provider origins are fixed `https://host` URLs.
const HTTPS_PORT: u16 = 443;
const ALPN_HTTP11: &[u8] = b"http/1.1";
/// hyper's read buffer bound; it also bounds the response head (status line and headers).
const MAX_BUF: usize = 32 * 1024;
/// Most of an error response's body that is kept.
const ERROR_BODY_LIMIT: usize = 8 * 1024;
const USER_AGENT: &str = concat!("vpn-manager/", env!("CARGO_PKG_VERSION"));
/// Body limit of a [`Request`] that does not set its own.
pub const DEFAULT_LIMIT: usize = 64 * 1024;
/// Deadline of a [`Request`] that does not set its own (spec: 10 s per attempt).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// IP address family of one request. The caller pins it (the preflight IP check and the API
/// request use the same family); there is no fallback to the other family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// Family of an address; IPv4-mapped IPv6 counts as IPv4.
    #[must_use]
    pub const fn of(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
}

/// Byte stream of one connection: a tunnel flow or a bootstrap socket.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> AsyncStream for T {}

pub type BoxedStream = Box<dyn AsyncStream>;

/// Opens the stream for one request, over the implementor's route and exactly `family`.
///
/// The implementor owns the route — the selected Instance's connector or the manager's
/// bootstrap socket — and must use exactly `family`: no Happy
/// Eyeballs, no fallback to a direct path. The stream carries TLS bytes, except to the `AirVPN`
/// bootstrap addresses (`airvpn::BOOTSTRAP_IPS`, port 80), whose payload is encrypted instead.
pub trait Connect: Send + Sync {
    fn connect(
        &self,
        host: &str,
        port: u16,
        family: Family,
    ) -> impl Future<Output = io::Result<BoxedStream>> + Send;

    /// Opens the connection for one prepared request (`target`). Every client in this crate
    /// opens connections this way. A connector that authorizes each request on its own
    /// overrides it and returns a [`Permit`]; the default dials [`Connect::connect`] within the
    /// request's deadline and needs none.
    fn connect_for<'a>(
        &'a self,
        target: &'a Target<'a>,
    ) -> impl Future<Output = Result<Opened<'a>, OpenError>> + Send + 'a {
        async move {
            let admitted = Instant::now();
            let dial = self.connect(target.host, target.port, target.family);
            match timeout_at(admitted + target.timeout, dial).await {
                Ok(Ok(stream)) => Ok(Opened {
                    stream,
                    permit: None,
                    admitted,
                }),
                Ok(Err(e)) => Err(OpenError::Io(e)),
                Err(_) => Err(OpenError::TimedOut),
            }
        }
    }
}

impl<T: Connect> Connect for Arc<T> {
    fn connect(
        &self,
        host: &str,
        port: u16,
        family: Family,
    ) -> impl Future<Output = io::Result<BoxedStream>> + Send {
        (**self).connect(host, port, family)
    }

    fn connect_for<'a>(
        &'a self,
        target: &'a Target<'a>,
    ) -> impl Future<Output = Result<Opened<'a>, OpenError>> + Send + 'a {
        (**self).connect_for(target)
    }
}

/// One prepared request as its connector sees it: what a [`Permit`] is issued for.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub method: &'a Method,
    /// Host name (or, for the `AirVPN` bootstrap, the pinned address) as the request names it.
    pub host: &'a str,
    pub port: u16,
    /// Origin-form path and query.
    pub path: &'a str,
    pub family: Family,
    /// The request's deadline, counted from when its connection is dialed.
    pub timeout: Duration,
}

impl<'a> Target<'a> {
    /// The request about to be written on a connection to `port` over `family`, as it stands:
    /// its method, `Host` header and request target (an unreadable `Host` is an empty name).
    pub fn of<B>(request: &'a hyper::Request<B>, port: u16, family: Family) -> Self {
        Self {
            method: request.method(),
            host: request
                .headers()
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                .unwrap_or_default(),
            port,
            path: request.uri().path_and_query().map_or("", |p| p.as_str()),
            family,
            timeout: Duration::ZERO,
        }
    }

    /// SHA-256 over method, host, port, path and family: a permit for one request is no good for
    /// another. The deadline is not part of it.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut input = Vec::with_capacity(16 + self.host.len() + self.path.len());
        for part in [self.method.as_str().as_bytes(), self.host.as_bytes()] {
            input.extend_from_slice(part);
            input.push(0);
        }
        input.extend_from_slice(&self.port.to_be_bytes());
        input.push(match self.family {
            Family::V4 => 4,
            Family::V6 => 6,
        });
        input.extend_from_slice(self.path.as_bytes());
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &input);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }
}

/// A connection opened for one request.
pub struct Opened<'a> {
    pub stream: BoxedStream,
    /// What the connector wants confirmed right before the request's first byte; `None` for a
    /// connector that does not authorize requests one by one.
    pub permit: Option<Box<dyn Permit + 'a>>,
    /// When the connection was dialed, after any admission of the connector's own: the
    /// request's deadline counts from here.
    pub admitted: Instant,
}

/// Why [`Connect::connect_for`] opened nothing. Nothing of the request was sent.
#[derive(Debug)]
pub enum OpenError {
    Io(io::Error),
    /// The connection did not come up within the request's deadline.
    TimedOut,
    /// The connector will not carry this request.
    Refused(Refusal),
}

/// What [`Permit::confirm`] returns.
pub type Confirmation<'a> = Pin<Box<dyn Future<Output = Result<(), Refusal>> + Send + 'a>>;

/// The authorization of one request by its connector, held by the client for the request's
/// lifetime.
pub trait Permit: Send {
    /// Right before the request's first byte: `sent` is the request about to be written. A
    /// refusal stops it unsent.
    fn confirm<'a>(&'a mut self, sent: &'a Target<'a>) -> Confirmation<'a>;

    /// The answer's status and headers (a 429's `Retry-After`).
    fn answered(&mut self, status: StatusCode, headers: &HeaderMap);
}

/// A connector's refusal to carry a request; nothing of the request was sent.
///
/// Its egress guard did not authorize it: no budget, a failed or stale exit check, a changed
/// route, a spent permit. `message` is the reason a person reads (`Display` is its English);
/// `code` is the API error to report. A connector that can only fail with an [`io::Error`] may
/// carry a refusal inside one ([`io::Error::other`]): [`HttpError::text`] reads its message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", .message.en)]
pub struct Refusal {
    pub code: ErrorCode,
    pub message: Text,
}

impl Refusal {
    pub fn new(code: ErrorCode, message: impl Into<Text>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// One HTTPS request. Hosts are `'static`: provider origins are fixed in source, never taken
/// from user input.
pub struct Request {
    method: Method,
    host: &'static str,
    path: String,
    family: Family,
    headers: HeaderMap,
    body: Zeroizing<Vec<u8>>,
    limit: usize,
    timeout: Duration,
    redirects: Redirects,
}

impl Request {
    /// `method https://{host}{path}` over `family`; `path` is origin-form (`/...`).
    pub fn new(
        method: Method,
        host: &'static str,
        path: impl Into<String>,
        family: Family,
    ) -> Self {
        Self {
            method,
            host,
            path: path.into(),
            family,
            headers: HeaderMap::new(),
            body: Zeroizing::new(Vec::new()),
            limit: DEFAULT_LIMIT,
            timeout: DEFAULT_TIMEOUT,
            redirects: Redirects::Refuse,
        }
    }

    /// JSON body (`Content-Type: application/json`).
    #[must_use]
    pub fn json(mut self, body: Zeroizing<Vec<u8>>) -> Self {
        self.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        self.body = body;
        self
    }

    /// HTML form body (`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`), as a
    /// browser posts it; `body` is already encoded (it may carry a password).
    #[must_use]
    pub fn form(mut self, body: Zeroizing<Vec<u8>>) -> Self {
        self.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
        self.body = body;
        self
    }

    /// Extra header. Secret values (`Authorization`, `Cookie`) must be marked sensitive. An
    /// `Accept` set here replaces the client's default (`application/json`).
    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// A 3xx answer comes back as a [`Response`] with its headers (its `Set-Cookie` and
    /// `Location`) and an empty body instead of failing with [`HttpError::Redirect`]. It is never
    /// followed: whether and where to go next is the caller's decision (`AirVPN`'s website answers
    /// a sign-in with a redirect).
    #[must_use]
    pub const fn returning_redirects(mut self) -> Self {
        self.redirects = Redirects::Return;
        self
    }

    /// Largest response body accepted, in bytes.
    #[must_use]
    pub const fn limit(mut self, bytes: usize) -> Self {
        self.limit = bytes;
        self
    }

    /// Deadline for the whole exchange: connect, TLS handshake, request and body.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the body or header values: they may carry the account number or a token.
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("host", &self.host)
            .field("path", &self.path)
            .field("family", &self.family)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// A non-redirect response. A 2xx body is complete (at most the request's limit); any other
/// body keeps only its first 8 KiB.
pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    /// May hold a secret (token response): zeroized on drop, never printed.
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Transport failure of one exchange. Messages carry no request or response content.
/// [`HttpError::text`] is the message a person reads; `Display` is its English (logs).
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    InvalidRequest,
    Connect(io::Error),
    Tls(rustls::Error),
    Timeout {
        sent: bool,
    },
    Transport {
        sent: bool,
    },
    Redirect(u16),
    TooLarge {
        limit: usize,
    },
    /// The connector would not carry the request; nothing of it was sent.
    Refused(Refusal),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text().en)
    }
}

impl From<OpenError> for HttpError {
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::Io(e) => Self::Connect(e),
            OpenError::TimedOut => Self::Timeout { sent: false },
            OpenError::Refused(r) => Self::Refused(r),
        }
    }
}

impl HttpError {
    /// The message a person reads, in the three languages. The operating system's or TLS
    /// library's own words are kept as they are; a [`Refusal`] or a [`vpn_domain::TextError`]
    /// carried inside an I/O error gives its words.
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::InvalidRequest => tr!(
                "Invalid request: the host name or path is not valid",
                "請求無效：主機名稱或路徑不合法",
                "無効なリクエストです：ホスト名またはパスが正しくありません"
            ),
            Self::Connect(e) => {
                let why = e
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<Refusal>())
                    .map_or_else(|| Text::of_io_error(e), |r| r.message.clone());
                tr!(
                    "Cannot connect: {why}",
                    "無法建立連線：{why}",
                    "接続できません：{why}";
                    why = why
                )
            }
            Self::Tls(e) => {
                let why = e.to_string();
                tr!(
                    "TLS verification failed, the connection was aborted (certificate verification is never skipped): {why}",
                    "TLS 驗證失敗，已中止連線（不會略過憑證驗證）：{why}",
                    "TLS の検証に失敗したため接続を中止しました（証明書の検証は省略しません）：{why}"
                )
            }
            Self::Timeout { .. } => tr!("Timed out", "逾時", "タイムアウトしました"),
            Self::Transport { .. } => tr!(
                "The connection was broken",
                "連線中斷",
                "接続が切断されました"
            ),
            Self::Redirect(status) => tr!(
                "The server asked for a redirect (HTTP {status}); refused",
                "伺服器要求重新導向（HTTP {status}），已拒絕",
                "サーバーがリダイレクトを求めました（HTTP {status}）。拒否しました"
            ),
            Self::TooLarge { limit } => tr!(
                "The response exceeds the {limit} bytes limit",
                "回應超過 {limit} bytes 上限",
                "応答が上限の {limit} bytes を超えています"
            ),
            Self::Refused(refusal) => refusal.message.clone(),
        }
    }

    /// Whether the server may have received the request, and so acted on it. A mutation that
    /// fails this way has an unknown outcome and must be reconciled, not resent.
    #[must_use]
    pub const fn maybe_delivered(&self) -> bool {
        match self {
            Self::InvalidRequest | Self::Connect(_) | Self::Tls(_) | Self::Refused(_) => false,
            Self::Timeout { sent } | Self::Transport { sent } => *sent,
            Self::Redirect(_) | Self::TooLarge { .. } => true,
        }
    }

    /// A certificate or handshake rejection is a TLS error; an I/O failure during the
    /// handshake is a broken connection (nothing was sent yet either way).
    fn tls(error: &io::Error) -> Self {
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
            .map_or(Self::Transport { sent: false }, |tls| {
                Self::Tls(tls.clone())
            })
    }
}

/// The TLS settings and trust of [`HttpsClient`]s: TLS 1.2/1.3 by aws-lc-rs, ALPN `http/1.1`
/// only, no session resumption, verification always on. Cheap to clone; every client made from
/// one shares it.
#[derive(Clone)]
pub struct Tls(TlsConnector);

impl Tls {
    /// Trusts the public web PKI (webpki roots). Verification cannot be disabled.
    #[must_use]
    pub fn web_pki() -> Self {
        Self::build(RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ))
    }

    /// Trusts only `roots`, for test fixtures with a throwaway CA. Products always use
    /// [`Tls::web_pki`].
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn with_roots(roots: RootCertStore) -> Self {
        Self::build(roots)
    }

    fn build(roots: RootCertStore) -> Self {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("aws-lc-rs offers TLS 1.2 and 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        Self(TlsConnector::from(Arc::new(config)))
    }

    /// A client over `connector` with this trust.
    pub fn client<C: Connect>(&self, connector: C) -> HttpsClient<C> {
        HttpsClient {
            connector,
            tls: self.0.clone(),
        }
    }
}

impl Default for Tls {
    fn default() -> Self {
        Self::web_pki()
    }
}

/// HTTPS/1.1 client over a caller-chosen [`Connect`]. Cheap to clone when `C` is.
#[derive(Clone)]
pub struct HttpsClient<C> {
    connector: C,
    tls: TlsConnector,
}

impl<C: Connect> HttpsClient<C> {
    /// Client that trusts the public web PKI (webpki roots). Verification cannot be disabled.
    pub fn new(connector: C) -> Self {
        Tls::web_pki().client(connector)
    }

    /// Client that trusts only `roots`, for test fixtures with a throwaway CA. Products always
    /// use [`HttpsClient::new`].
    #[cfg(any(test, feature = "testing"))]
    pub fn with_roots(connector: C, roots: RootCertStore) -> Self {
        Tls::with_roots(roots).client(connector)
    }

    pub const fn connector(&self) -> &C {
        &self.connector
    }

    /// Runs one exchange on a fresh connection. Any status except 3xx is returned with its
    /// body (see [`Response`]); mapping statuses to meaning is the adapter's job.
    ///
    /// # Errors
    ///
    /// [`HttpError::InvalidRequest`] for a host that is not a DNS name or a path that is not
    /// origin-form, [`HttpError::Refused`] or [`HttpError::Connect`] when the connector will not
    /// carry it, [`HttpError::Tls`], [`HttpError::Transport`] or [`HttpError::Timeout`] when the
    /// exchange fails, [`HttpError::Redirect`] for a 3xx the request does not take, and
    /// [`HttpError::TooLarge`] when the body exceeds the request's limit.
    pub async fn send(&self, request: Request) -> Result<Response, HttpError> {
        let Request {
            method,
            host,
            path,
            family,
            headers,
            body,
            limit,
            timeout,
            redirects,
        } = request;
        let Ok(server_name @ ServerName::DnsName(_)) = ServerName::try_from(host) else {
            return Err(HttpError::InvalidRequest);
        };
        let uri = origin_form(&path).ok_or(HttpError::InvalidRequest)?;
        let authority = HeaderValue::from_str(host).map_err(|_| HttpError::InvalidRequest)?;

        let target = Target {
            method: &method,
            host,
            port: HTTPS_PORT,
            path: &path,
            family,
            timeout,
        };
        let Opened {
            stream,
            mut permit,
            admitted,
        } = self.connector.connect_for(&target).await?;
        let deadline = admitted + timeout;
        let tls = match timeout_at(deadline, self.tls.connect(server_name, stream)).await {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => return Err(HttpError::tls(&e)),
            Err(_) => return Err(HttpError::Timeout { sent: false }),
        };
        // Only http/1.1 is offered; a server choosing anything else violates TLS.
        if tls
            .get_ref()
            .1
            .alpn_protocol()
            .is_some_and(|p| p != ALPN_HTTP11)
        {
            return Err(HttpError::Transport { sent: false });
        }

        let mut req = hyper::Request::new(Full::new(Cursor::new(body)));
        *req.method_mut() = method.clone();
        *req.uri_mut() = uri;
        let h = req.headers_mut();
        h.extend(headers);
        h.insert(header::HOST, authority);
        h.insert(header::USER_AGENT, HeaderValue::from_static(USER_AGENT));
        h.entry(header::ACCEPT)
            .or_insert(HeaderValue::from_static("application/json"));
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(header::CONNECTION, HeaderValue::from_static("close"));
        confirm(permit.as_deref_mut(), &req, HTTPS_PORT, family, deadline).await?;
        let response = exchange_with(tls, req, limit, deadline, redirects).await;
        answered(permit.as_deref_mut(), &response);
        response
    }

    /// `GET https://{host}:{port}{path}` of a user-supplied URL (a blocklist source; the host is
    /// a validated DNS name, `path` origin-form). Same TLS, family pinning and bounds as
    /// [`HttpsClient::send`]; a 3xx comes back as a response with its headers (empty body) so
    /// the caller applies its own redirect policy. No `Accept-Encoding` is sent.
    ///
    /// # Errors
    ///
    /// As for [`HttpsClient::send`], except that a 3xx is returned rather than an error.
    pub async fn get_user_url(
        &self,
        host: &str,
        port: u16,
        path: &str,
        family: Family,
        limit: usize,
        deadline: Instant,
    ) -> Result<Response, HttpError> {
        let Ok(server_name @ ServerName::DnsName(_)) = ServerName::try_from(host.to_owned()) else {
            return Err(HttpError::InvalidRequest);
        };
        let uri = origin_form(path).ok_or(HttpError::InvalidRequest)?;
        let authority = if port == HTTPS_PORT {
            HeaderValue::from_str(host)
        } else {
            HeaderValue::from_str(&format!("{host}:{port}"))
        }
        .map_err(|_| HttpError::InvalidRequest)?;
        let stream = match timeout_at(deadline, self.connector.connect(host, port, family)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(HttpError::Connect(e)),
            Err(_) => return Err(HttpError::Timeout { sent: false }),
        };
        let tls = match timeout_at(deadline, self.tls.connect(server_name, stream)).await {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => return Err(HttpError::tls(&e)),
            Err(_) => return Err(HttpError::Timeout { sent: false }),
        };
        if tls
            .get_ref()
            .1
            .alpn_protocol()
            .is_some_and(|p| p != ALPN_HTTP11)
        {
            return Err(HttpError::Transport { sent: false });
        }
        let mut req = hyper::Request::new(Full::new(Cursor::new(Zeroizing::new(Vec::new()))));
        *req.method_mut() = Method::GET;
        *req.uri_mut() = uri;
        let h = req.headers_mut();
        h.insert(header::HOST, authority);
        h.insert(header::USER_AGENT, HeaderValue::from_static(USER_AGENT));
        h.insert(
            header::ACCEPT,
            HeaderValue::from_static("text/plain, */*;q=0.5"),
        );
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(header::CONNECTION, HeaderValue::from_static("close"));
        exchange_with(tls, req, limit, deadline, Redirects::Return).await
    }
}

/// Right before the first byte of `request`: the connector's permit, if any, confirms the
/// request as it is about to be written. Its refusal (or no answer before `deadline`) stops it.
pub(crate) async fn confirm<B: Sync>(
    permit: Option<&mut (dyn Permit + '_)>,
    request: &hyper::Request<B>,
    port: u16,
    family: Family,
    deadline: Instant,
) -> Result<(), HttpError> {
    let Some(permit) = permit else {
        return Ok(());
    };
    let sent = Target::of(request, port, family);
    match timeout_at(deadline, permit.confirm(&sent)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(refusal)) => Err(HttpError::Refused(refusal)),
        Err(_) => Err(HttpError::Timeout { sent: false }),
    }
}

/// Tells the connector's permit, if any, how the request was answered.
pub(crate) fn answered(
    permit: Option<&mut (dyn Permit + '_)>,
    response: &Result<Response, HttpError>,
) {
    if let (Some(permit), Ok(r)) = (permit, response) {
        permit.answered(r.status, &r.headers);
    }
}

/// What [`exchange_with`] does with a 3xx answer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Redirects {
    /// Fail with [`HttpError::Redirect`] (provider APIs never redirect).
    Refuse,
    /// Return it (headers, empty body) for the caller to decide.
    Return,
}

/// Request body on the wire: the caller's zeroizing buffer.
pub(crate) type RequestBody = Full<Cursor<Zeroizing<Vec<u8>>>>;

/// One HTTP/1.1 exchange on an open connection — TLS, or the `AirVPN` bootstrap's plain HTTP —
/// before `deadline`. The request carries all its headers (`Connection: close` included). A 3xx
/// is [`HttpError::Redirect`]; the body is bounded while it is read (see [`Response`]).
pub(crate) async fn exchange<S: AsyncStream + 'static>(
    stream: S,
    request: hyper::Request<RequestBody>,
    limit: usize,
    deadline: Instant,
) -> Result<Response, HttpError> {
    exchange_with(stream, request, limit, deadline, Redirects::Refuse).await
}

async fn exchange_with<S: AsyncStream + 'static>(
    stream: S,
    request: hyper::Request<RequestBody>,
    limit: usize,
    deadline: Instant,
    redirects: Redirects,
) -> Result<Response, HttpError> {
    let handshake = http1::Builder::new()
        .max_buf_size(MAX_BUF)
        .handshake(TokioIo::new(stream));
    let (mut sender, connection) = match timeout_at(deadline, handshake).await {
        Ok(Ok(parts)) => parts,
        Ok(Err(_)) => return Err(HttpError::Transport { sent: false }),
        Err(_) => return Err(HttpError::Timeout { sent: false }),
    };
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    // Dropping this future (deadline, cancellation) closes the connection.
    let _driver = AbortOnDrop(driver.abort_handle());

    match timeout_at(deadline, sender.ready()).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(HttpError::Transport { sent: false }),
        Err(_) => return Err(HttpError::Timeout { sent: false }),
    }
    let response = match timeout_at(deadline, sender.send_request(request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => return Err(HttpError::Transport { sent: true }),
        Err(_) => return Err(HttpError::Timeout { sent: true }),
    };
    let status = response.status();
    if status.is_redirection() {
        if redirects == Redirects::Return {
            return Ok(Response {
                status,
                headers: response.headers().clone(),
                body: Zeroizing::new(Vec::new()),
            });
        }
        return Err(HttpError::Redirect(status.as_u16()));
    }
    let (parts, incoming) = response.into_parts();
    let read = if status.is_success() {
        let declared = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
        if declared.is_some_and(|len| len > limit as u64) {
            return Err(HttpError::TooLarge { limit });
        }
        read_body(incoming, limit, Overflow::Refuse)
    } else {
        // An error body only matters for a short machine code. A large error page (a
        // proxy's 503 HTML) is cut, so the status still decides what the failure means.
        read_body(incoming, limit.min(ERROR_BODY_LIMIT), Overflow::Cut)
    };
    let body = match timeout_at(deadline, read).await {
        Ok(body) => body?,
        Err(_) => return Err(HttpError::Timeout { sent: true }),
    };
    Ok(Response {
        status,
        headers: parts.headers,
        body,
    })
}

/// `path` as an origin-form request target (`/path?query`), nothing else.
fn origin_form(path: &str) -> Option<Uri> {
    if !path.starts_with('/') {
        return None;
    }
    let uri: Uri = path.parse().ok()?;
    (uri.scheme().is_none() && uri.authority().is_none()).then_some(uri)
}

/// What [`read_body`] does with a body longer than its limit.
enum Overflow {
    /// Fail with [`HttpError::TooLarge`] (chunked bodies declare no length up front).
    Refuse,
    /// Keep the first `limit` bytes and stop reading.
    Cut,
}

async fn read_body(
    mut body: Incoming,
    limit: usize,
    overflow: Overflow,
) -> Result<Zeroizing<Vec<u8>>, HttpError> {
    let mut out = Zeroizing::new(Vec::new());
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| HttpError::Transport { sent: true })?;
        let Ok(data) = frame.into_data() else {
            continue; // trailers
        };
        let room = limit - out.len();
        let take = match overflow {
            _ if data.len() <= room => data.len(),
            Overflow::Refuse => return Err(HttpError::TooLarge { limit }),
            Overflow::Cut => room,
        };
        let len = out.len() + take;
        if len > out.capacity() {
            // Grow into a fresh buffer: the old one is zeroized on drop instead of being left
            // behind by a reallocation.
            let capacity = len.max(out.capacity() * 2).min(limit);
            let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
            grown.extend_from_slice(&out);
            out = grown;
        }
        out.extend_from_slice(&data[..take]);
        if take < data.len() {
            break;
        }
    }
    Ok(out)
}

/// Aborts the task driving a hyper connection when the exchange ends or is dropped.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_origin_form_paths_are_accepted() {
        assert!(origin_form("/accounts/v1/devices").is_some());
        assert!(origin_form("/public/relays/wireguard/v2/").is_some());
        assert!(origin_form("accounts").is_none());
        assert!(origin_form("https://evil.example/x").is_none());
        assert!(origin_form("").is_none());
        assert!(origin_form("/a b").is_none());
    }
}
