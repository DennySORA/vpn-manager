//! HTTP proxy on hyper's HTTP/1 server: `CONNECT host:port` tunnels and absolute-form `http://`
//! forwarding, both dialed through the tunnel.
//!
//! Parsing is hyper's: request heads are bounded in size, header count and time
//! (`handshake_timeout`, which also bounds an idle keep-alive connection). A forwarded request is
//! rewritten to origin-form with its hop-by-hop headers removed and `Host` set from the
//! request-target (RFC 9112 §3.2.2), then sent on a hyper client connection over a tunnel
//! stream. That upstream connection is kept for the next request of the same client connection
//! while the origin stays the same. Errors are answered with a short text in the language the
//! request's `Accept-Language` asks for (one of the interface's; English when it names none of
//! them).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::uri::PathAndQuery;
use http::{Method, Request, Response, StatusCode, Uri, Version};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::http1 as client_http1;
use hyper::ext::ReasonPhrase;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpn_domain::{Language, Text, tr};
use vpn_platform::nobufs::Patient;
use vpn_tunnel::TunnelConnector;

use super::connect::{self, ConnectError, Host};
use super::{Shared, splice};
use crate::counters::{GatewayCounters, TcpClass};
use crate::dns::Resolve;
use crate::shaping::{Direction, Shaper};

/// Request head bounds.
const MAX_HEADERS: usize = 100;
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Read/write buffer cap of a client connection (above the head limit, so an oversized head gets
/// 431 from the head limit).
const MAX_BUF: usize = 128 * 1024;

/// How long a client gets when the Gateway stops: to take the answer of its request in flight,
/// or to deliver the head of the request it has just sent (and take that answer).
pub(super) const STOP_GRACE: Duration = Duration::from_millis(250);

/// Headers that apply to one hop only (RFC 9110 §7.6.1), plus the framing header hyper
/// regenerates for the next hop.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
    "transfer-encoding",
];

/// Serve one client connection. `first_head_deadline` bounds the first request head from accept;
/// hyper's `header_read_timeout` bounds each head from when it starts reading it. When the
/// Gateway stops, a request in flight is answered (503) rather than cut off without a word, and
/// so is the first request of a connection nothing was read from yet; nothing more is read
/// after that. A CONNECT relay ends at once.
pub(super) async fn serve<C: TunnelConnector, R: Resolve>(
    shared: &Arc<Shared<C, R>>,
    stream: TcpStream,
    first_head_deadline: Instant,
) {
    let conn = Arc::new(ClientConn {
        shared: Arc::clone(shared),
        first_request: AtomicBool::new(false),
        upstream: tokio::sync::Mutex::new(None),
        tunnel: vpn_sync::Mutex::new(None),
        cancel: shared.cancel.child_token(),
    });
    // Upstream connection drivers end with this client connection.
    let _upstreams = conn.cancel.clone().drop_guard();
    let service = {
        let conn = Arc::clone(&conn);
        service_fn(move |req| {
            let conn = Arc::clone(&conn);
            async move { Ok::<_, Infallible>(conn.handle(req).await) }
        })
    };
    let mut builder = server_http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(shared.config.handshake_timeout)
        .max_headers(MAX_HEADERS)
        .max_header_size(MAX_HEAD_BYTES)
        .max_buf_size(MAX_BUF)
        .half_close(true)
        .preserve_header_case(true);
    let connection = builder
        // A host short of buffer space (`ENOBUFS`) is waited out, as in the CONNECT relay.
        .serve_connection(TokioIo::new(Patient::new(stream)), service)
        .with_upgrades();
    tokio::pin!(connection);
    let first_head_late = async {
        tokio::time::sleep_until(first_head_deadline).await;
        if conn.first_request.load(Ordering::Relaxed) {
            std::future::pending::<()>().await;
        }
    };
    let served = tokio::select! {
        served = &mut connection => served,
        () = first_head_late => {
            tracing::debug!(gateway = %shared.config.id, "HTTP request head not received in time");
            return;
        }
        () = shared.cancel.cancelled() => {
            // Asked to stop, hyper closes a connection it has read nothing from at once: a
            // request already on its way would meet a reset. Such a connection keeps the grace
            // to deliver its head instead, and the answer to it closes the connection.
            if conn.first_request.load(Ordering::Relaxed) {
                connection.as_mut().graceful_shutdown();
            }
            match tokio::time::timeout(STOP_GRACE, &mut connection).await {
                Ok(served) => served,
                Err(_) => return,
            }
        }
    };
    if let Err(e) = served {
        tracing::debug!(gateway = %shared.config.id, error = %e, "HTTP proxy connection ended with an error");
    }

    // After a successful CONNECT, hyper hands the client connection over through the upgrade.
    let Some((on_upgrade, upstream, class)) = conn.tunnel.lock().take() else {
        return;
    };
    // An earlier forward-proxy upstream of this connection is not needed any more.
    drop(conn.upstream.lock().await.take());
    let relay = relay_upgraded(shared, on_upgrade, upstream, class);
    shared.cancel.run_until_cancelled(relay).await;
}

/// Relay a CONNECT tunnel once hyper hands the client connection over.
async fn relay_upgraded<C: TunnelConnector, R: Resolve>(
    shared: &Arc<Shared<C, R>>,
    on_upgrade: OnUpgrade,
    upstream: C::Stream,
    class: TcpClass,
) {
    match on_upgrade.await {
        Ok(upgraded) => {
            let idle = shared.config.tcp_idle_timeout;
            let (counters, shaper) = (&shared.counters, &shared.shaper);
            // The client's own socket back from hyper, so the relay can tell that the client
            // reset the connection even while the tunnel side takes nothing; plus the bytes the
            // client sent right after its request, which hyper had already read.
            let relayed = match upgraded.downcast::<TokioIo<Patient<TcpStream>>>() {
                Ok(parts) => {
                    let client = parts.io.into_inner().into_inner().into_split();
                    let first = parts.read_buf;
                    splice::splice(client, &first, upstream, counters, class, shaper, idle).await
                }
                Err(upgraded) => {
                    let (rx, tx) = tokio::io::split(TokioIo::new(upgraded));
                    let client = (splice::Unobserved(rx), tx);
                    splice::splice(client, &[], upstream, counters, class, shaper, idle).await
                }
            };
            if let Err(e) = relayed {
                tracing::debug!(gateway = %shared.config.id, error = %e, "CONNECT relay ended with an error");
            }
        }
        Err(e) => {
            tracing::debug!(gateway = %shared.config.id, error = %e, "CONNECT upgrade failed");
        }
    }
}

/// One client connection: the kept-alive upstream of forwarded requests, and a CONNECT tunnel
/// waiting for hyper to hand over the client side.
struct ClientConn<C: TunnelConnector, R> {
    shared: Arc<Shared<C, R>>,
    /// Set once hyper delivered a complete request head.
    first_request: AtomicBool,
    upstream: tokio::sync::Mutex<Option<Upstream>>,
    tunnel: vpn_sync::Mutex<Option<(OnUpgrade, C::Stream, TcpClass)>>,
    cancel: CancellationToken,
}

/// An HTTP/1 client connection to one origin, over a tunnel stream.
struct Upstream {
    origin: Origin,
    sender: client_http1::SendRequest<ProxyBody>,
}

/// Connection reuse key: the request-target's host (case-insensitive) and port.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    host: String,
    port: u16,
}

/// Where an absolute-form `http://` request goes.
struct ForwardTarget {
    host: Host,
    origin: Origin,
    host_header: HeaderValue,
    path_and_query: PathAndQuery,
}

impl<C: TunnelConnector, R: Resolve> ClientConn<C, R> {
    async fn handle(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        self.first_request.store(true, Ordering::Relaxed);
        let language = language_of(req.headers());
        let answer = async {
            if req.method() == Method::CONNECT {
                self.connect(req, language).await
            } else {
                self.forward(req, language).await
            }
        };
        tokio::select! {
            biased;
            response = answer => response,
            () = self.shared.cancel.cancelled() => stopping(language),
        }
    }

    async fn connect(&self, mut req: Request<Incoming>, language: Language) -> Response<ProxyBody> {
        let target = req
            .uri()
            .authority()
            .and_then(|authority| Some((Host::parse(authority.host()), authority.port_u16()?)));
        let Some((host, port)) = target else {
            return Refusal::BadRequest(tr!(
                "The target of CONNECT must be host:port",
                "CONNECT 的目標必須是 host:port",
                "CONNECT の宛先は host:port でなければなりません"
            ))
            .into_response(language);
        };
        match connect::connect(&self.shared, &host, port).await {
            Ok(upstream) => {
                *self.tunnel.lock() = Some((
                    hyper::upgrade::on(&mut req),
                    upstream,
                    TcpClass::of_port(port),
                ));
                let mut response = Response::new(ProxyBody::empty());
                response
                    .extensions_mut()
                    .insert(ReasonPhrase::from_static(b"Connection Established"));
                response
            }
            Err(error) => Refusal::Connect(error).into_response(language),
        }
    }

    async fn forward(&self, req: Request<Incoming>, language: Language) -> Response<ProxyBody> {
        match self.try_forward(req).await {
            Ok(response) => response,
            Err(refusal) => refusal.into_response(language),
        }
    }

    async fn try_forward(&self, req: Request<Incoming>) -> Result<Response<ProxyBody>, Refusal> {
        let target = forward_target(req.uri())?;
        let (mut parts, body) = req.into_parts();
        parts.uri = Uri::from(target.path_and_query.clone());
        parts.version = Version::HTTP_11;
        strip_hop_by_hop(&mut parts.headers);
        parts
            .headers
            .insert(header::HOST, target.host_header.clone());
        parts.extensions.remove::<OnUpgrade>();
        let request = Request::from_parts(
            parts,
            ProxyBody::counted(body, &self.shared, Direction::Upload),
        );
        let response = self.send(&target, request).await?;
        self.relay_response(response)
    }

    /// Send on the kept-alive upstream when it serves the same origin, otherwise (or when the
    /// origin closed it before the request was written) on a new one.
    async fn send(
        &self,
        target: &ForwardTarget,
        mut request: Request<ProxyBody>,
    ) -> Result<Response<Incoming>, Refusal> {
        let mut slot = self.upstream.lock().await;
        let reusable = slot
            .take()
            .filter(|upstream| upstream.origin == target.origin && !upstream.sender.is_closed());
        if let Some(mut upstream) = reusable
            && upstream.sender.ready().await.is_ok()
        {
            match upstream.sender.try_send_request(request).await {
                Ok(response) => {
                    *slot = Some(upstream);
                    return Ok(response);
                }
                Err(mut e) => {
                    // Never written: safe to retry on a fresh connection.
                    let Some(unsent) = e.take_message() else {
                        tracing::debug!(gateway = %self.shared.config.id, error = %e.error(), "upstream request failed");
                        return Err(Refusal::UpstreamBroken);
                    };
                    request = unsent;
                }
            }
        }
        let mut sender = self.open(target).await?;
        match sender.send_request(request).await {
            Ok(response) => {
                *slot = Some(Upstream {
                    origin: target.origin.clone(),
                    sender,
                });
                drop(slot);
                Ok(response)
            }
            Err(e) => {
                tracing::debug!(gateway = %self.shared.config.id, error = %e, "upstream request failed");
                Err(Refusal::UpstreamBroken)
            }
        }
    }

    /// A new upstream connection through the tunnel; its driver ends with the client connection.
    async fn open(
        &self,
        target: &ForwardTarget,
    ) -> Result<client_http1::SendRequest<ProxyBody>, Refusal> {
        let stream = connect::connect(&self.shared, &target.host, target.origin.port)
            .await
            .map_err(Refusal::Connect)?;
        let mut builder = client_http1::Builder::new();
        builder.preserve_header_case(true);
        let (sender, connection) = builder
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|e| {
                tracing::debug!(gateway = %self.shared.config.id, error = %e, "upstream handshake failed");
                Refusal::UpstreamBroken
            })?;
        let cancel = self.cancel.clone();
        self.shared.tracker.spawn(async move {
            if let Some(Err(e)) = cancel.run_until_cancelled(connection).await {
                tracing::debug!(error = %e, "upstream HTTP connection ended with an error");
            }
        });
        Ok(sender)
    }

    fn relay_response(&self, response: Response<Incoming>) -> Result<Response<ProxyBody>, Refusal> {
        let (mut parts, body) = response.into_parts();
        if parts.status == StatusCode::SWITCHING_PROTOCOLS {
            // No upgrade was requested upstream (`Upgrade` is hop-by-hop).
            return Err(Refusal::UpstreamBroken);
        }
        parts.version = Version::HTTP_11;
        strip_hop_by_hop(&mut parts.headers);
        Ok(Response::from_parts(
            parts,
            ProxyBody::counted(body, &self.shared, Direction::Download),
        ))
    }
}

/// Why the proxy answers a request itself instead of relaying it.
#[derive(Debug)]
enum Refusal {
    /// Not a request this proxy relays.
    BadRequest(Text),
    Connect(ConnectError),
    /// The origin's response was invalid or the upstream connection broke.
    UpstreamBroken,
}

impl Refusal {
    fn into_response(self, language: Language) -> Response<ProxyBody> {
        let error = match self {
            Self::BadRequest(message) => {
                return text(StatusCode::BAD_REQUEST, &message, language);
            }
            Self::UpstreamBroken => {
                let message = tr!(
                    "The destination server's response was invalid, or the connection broke",
                    "目的伺服器的回應無效或連線中斷",
                    "宛先サーバーの応答が無効か、接続が切断されました"
                );
                return text(StatusCode::BAD_GATEWAY, &message, language);
            }
            Self::Connect(error) => error,
        };
        let (status, message) = match error {
            ConnectError::Denied(reason) => (StatusCode::FORBIDDEN, reason.message()),
            ConnectError::GateClosed => (
                StatusCode::SERVICE_UNAVAILABLE,
                tr!(
                    "The VPN Instance is not ready or is reconnecting; the connection was refused (it never falls back to the ordinary network)",
                    "VPN Instance 尚未就緒或正在重新連線，連線已拒絕（不會改走一般網路）",
                    "VPN Instance はまだ準備ができていないか再接続中のため、接続を拒否しました（通常のネットワークに切り替えることはありません）"
                ),
            ),
            ConnectError::Admission => (
                StatusCode::SERVICE_UNAVAILABLE,
                tr!(
                    "The VPN Instance has reached its connection or memory limit; the connection was refused",
                    "VPN Instance 的連線數或記憶體已達上限，連線已拒絕",
                    "VPN Instance の接続数またはメモリが上限に達したため、接続を拒否しました"
                ),
            ),
            ConnectError::Resolve(e) => (
                StatusCode::BAD_GATEWAY,
                tr!(
                    "Cannot resolve the destination host: {why}",
                    "無法解析目的主機：{why}",
                    "宛先ホストを名前解決できません：{why}";
                    why = e.text()
                ),
            ),
            ConnectError::NetworkUnreachable => (
                StatusCode::BAD_GATEWAY,
                tr!(
                    "The VPN tunnel cannot reach the destination network (the address type is not supported, or there is no route)",
                    "VPN tunnel 無法到達目的網路（不支援該位址類型或沒有路由）",
                    "VPN tunnel から宛先ネットワークに到達できません（そのアドレスの種類に対応していないか、経路がありません）"
                ),
            ),
            ConnectError::HostUnreachable => (
                StatusCode::BAD_GATEWAY,
                tr!(
                    "The destination host is unreachable through the VPN tunnel",
                    "經 VPN tunnel 無法到達目的主機",
                    "VPN tunnel 経由で宛先ホストに到達できません"
                ),
            ),
            ConnectError::Refused => (
                StatusCode::BAD_GATEWAY,
                tr!(
                    "The destination host refused the connection",
                    "目的主機拒絕連線",
                    "宛先ホストが接続を拒否しました"
                ),
            ),
            ConnectError::TimedOut => (
                StatusCode::GATEWAY_TIMEOUT,
                tr!(
                    "Connecting to the destination host through the VPN tunnel timed out",
                    "經 VPN tunnel 連線到目的主機逾時",
                    "VPN tunnel 経由での宛先ホストへの接続がタイムアウトしました"
                ),
            ),
            ConnectError::Failed => (
                StatusCode::BAD_GATEWAY,
                tr!(
                    "Connecting through the VPN tunnel failed",
                    "經 VPN tunnel 連線失敗",
                    "VPN tunnel 経由の接続に失敗しました"
                ),
            ),
        };
        text(status, &message, language)
    }
}

/// Validate an absolute-form `http://` request-target. `https://` and origin-form requests are
/// not proxy requests here (HTTPS goes through CONNECT; TLS is never terminated).
fn forward_target(uri: &Uri) -> Result<ForwardTarget, Refusal> {
    match uri.scheme_str() {
        Some(scheme) if scheme.eq_ignore_ascii_case("http") => {}
        Some(_) => {
            return Err(Refusal::BadRequest(tr!(
                "Only http:// URLs can be proxied; for HTTPS use CONNECT (the proxy does not terminate TLS)",
                "只能代理 http:// 網址；HTTPS 請使用 CONNECT（代理不終結 TLS）",
                "プロキシできるのは http:// の URL だけです。HTTPS には CONNECT を使ってください（プロキシは TLS を終端しません）"
            )));
        }
        None => {
            return Err(Refusal::BadRequest(tr!(
                "This is an HTTP proxy: the request target must be an absolute http:// URL, or use CONNECT",
                "這是 HTTP 代理：請求目標必須是 http:// 絕對網址，或使用 CONNECT",
                "これは HTTP プロキシです。リクエストの宛先は http:// の絶対 URL にするか、CONNECT を使ってください"
            )));
        }
    }
    let bad_target = || {
        Refusal::BadRequest(tr!(
            "The host name of the request URL is invalid",
            "請求網址的主機名稱無效",
            "リクエスト URL のホスト名が無効です"
        ))
    };
    let authority = uri.authority().ok_or_else(bad_target)?;
    let host = authority.host();
    if host.is_empty() {
        return Err(bad_target());
    }
    // Host comes from the request-target (never its userinfo), with the port only if one was given.
    let host_header = authority
        .port()
        .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"));
    // `InvalidHeaderValue` says no more than the refusal does: the value does not parse.
    let host_header = HeaderValue::from_str(&host_header).map_err(|_not_a_value| bad_target())?;
    let path_and_query = uri.query().map_or_else(
        || uri.path().to_owned(),
        |query| format!("{}?{query}", uri.path()),
    );
    let path_and_query = PathAndQuery::try_from(path_and_query).map_err(|e| {
        tracing::debug!(error = %e, "request target refused: path or query unusable");
        bad_target()
    })?;
    Ok(ForwardTarget {
        host: Host::parse(host),
        origin: Origin {
            host: host.to_ascii_lowercase(),
            port: authority.port_u16().unwrap_or(80),
        },
        host_header,
        path_and_query,
    })
}

/// Remove `Connection`, every header it names, and the fixed hop-by-hop set.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// What a stopping Gateway answers: 503, and the connection ends with it.
fn stopping(language: Language) -> Response<ProxyBody> {
    let message = tr!(
        "The Gateway is stopping or restarting; the connection was refused (it never falls back to the ordinary network)",
        "代理埠正在停止或重新啟動，連線已拒絕（不會改走一般網路）",
        "ゲートウェイが停止中または再起動中のため、接続を拒否しました（通常のネットワークに切り替えることはありません）"
    );
    let mut response = text(StatusCode::SERVICE_UNAVAILABLE, &message, language);
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

/// The language to answer a request in (`Accept-Language`; English when it lists none of ours).
fn language_of(headers: &HeaderMap) -> Language {
    Language::of_accept_language(
        headers
            .get_all(header::ACCEPT_LANGUAGE)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    )
}

/// A short `text/plain; charset=utf-8` response: `message` in `language`.
fn text(status: StatusCode, message: &Text, language: Language) -> Response<ProxyBody> {
    let message = message.get(language);
    let mut response = Response::new(ProxyBody::full(Bytes::from(format!("{message}\n"))));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// Body of every response the proxy writes and every request it forwards: a fixed text, or a
/// streamed message body whose data bytes pass the connection's cap for their direction (in
/// pieces of about 20 ms of the cap) and are counted as payload when they pass.
struct ProxyBody(BodyKind);

/// A piece of a data frame waiting for its cap.
type Waiting = (Bytes, Pin<Box<dyn Future<Output = ()> + Send>>);

enum BodyKind {
    Full(Option<Bytes>),
    Counted {
        body: Incoming,
        counters: Arc<GatewayCounters>,
        shaper: Arc<Shaper>,
        direction: Direction,
        /// What is left of the current data frame.
        rest: Bytes,
        waiting: Option<Waiting>,
    },
}

impl ProxyBody {
    const fn empty() -> Self {
        Self(BodyKind::Full(None))
    }

    const fn full(data: Bytes) -> Self {
        Self(BodyKind::Full(Some(data)))
    }

    fn counted<C, R>(body: Incoming, shared: &Shared<C, R>, direction: Direction) -> Self {
        Self(BodyKind::Counted {
            body,
            counters: Arc::clone(&shared.counters),
            shaper: Arc::clone(&shared.shaper),
            direction,
            rest: Bytes::new(),
            waiting: None,
        })
    }
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let (body, counters, shaper, direction, rest, waiting) = match &mut self.get_mut().0 {
            BodyKind::Full(data) => {
                return Poll::Ready(data.take().map(|data| Ok(Frame::data(data))));
            }
            BodyKind::Counted {
                body,
                counters,
                shaper,
                direction,
                rest,
                waiting,
            } => (body, counters, shaper, *direction, rest, waiting),
        };
        let deliver = |data: Bytes| {
            let n = data.len() as u64;
            match direction {
                Direction::Upload => counters.add_tx(n),
                Direction::Download => counters.add_rx(n),
            }
            Poll::Ready(Some(Ok(Frame::data(data))))
        };
        loop {
            if let Some((_, wait)) = waiting.as_mut() {
                std::task::ready!(wait.as_mut().poll(cx));
                if let Some((piece, _)) = waiting.take() {
                    return deliver(piece);
                }
            }
            if !rest.is_empty() {
                let bucket = shaper.bucket(direction);
                if bucket.cap().is_none() {
                    return deliver(std::mem::take(rest));
                }
                let piece = rest.split_to(rest.len().min(bucket.chunk()));
                let wait = shaper.acquire_owned(direction, piece.len());
                *waiting = Some((piece, wait));
                continue;
            }
            match std::task::ready!(Pin::new(&mut *body).poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => *rest = data,
                    // Trailers pass as they are.
                    Err(frame) => return Poll::Ready(Some(Ok(frame))),
                },
                other => return Poll::Ready(other),
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.0 {
            BodyKind::Full(data) => data.is_none(),
            BodyKind::Counted {
                body,
                rest,
                waiting,
                ..
            } => body.is_end_stream() && rest.is_empty() && waiting.is_none(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.0 {
            BodyKind::Full(data) => {
                SizeHint::with_exact(data.as_ref().map_or(0, |data| data.len() as u64))
            }
            BodyKind::Counted {
                body,
                rest,
                waiting,
                ..
            } => {
                // Bytes taken from the inner body but not delivered yet are still to come.
                let held = (rest.len() + waiting.as_ref().map_or(0, |(p, _)| p.len())) as u64;
                let inner = body.size_hint();
                let mut hint = SizeHint::new();
                hint.set_lower(inner.lower() + held);
                if let Some(upper) = inner.upper() {
                    hint.set_upper(upper + held);
                }
                hint
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_headers_and_connection_tokens_are_removed() {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("connection", "keep-alive, X-Trace"),
            ("x-trace", "1"),
            ("proxy-connection", "keep-alive"),
            ("proxy-authorization", "Basic Zm9vOmJhcg=="),
            ("keep-alive", "timeout=5"),
            ("te", "trailers"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("accept", "*/*"),
            ("content-length", "3"),
        ] {
            headers.append(name, HeaderValue::from_static(value));
        }
        strip_hop_by_hop(&mut headers);
        let mut left: Vec<&str> = headers.keys().map(HeaderName::as_str).collect();
        left.sort_unstable();
        assert_eq!(left, ["accept", "content-length"]);
    }
}
