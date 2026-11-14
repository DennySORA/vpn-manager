//! Upstream servers and their transports. Every socket is opened through the Instance's
//! `TunnelConnector` with `FlowClass::Control`; nothing here can reach the host network or the
//! host resolver (DoT/DoH hostnames are never resolved: the configured numeric address is dialled
//! and the name is used only for SNI, certificate verification and the HTTP authority).
//!
//! - UDP: new socket and random ID per attempt; datagrams that are not the response to this
//!   query (source, ID, QR, opcode, question) are discarded and the wait goes on; TC=1 re-asks
//!   the same server over TCP.
//! - TCP: RFC 1035 two-byte length framing, new connection per attempt.
//! - `DoT` (RFC 7858): the same framing inside TLS verified for `server_name`. A TLS failure makes
//!   the server unusable for the rest of the resolution; there is no plaintext fallback.
//! - `DoH` (RFC 8484): `POST application/dns-message` over HTTP/2 or HTTP/1.1 (ALPN), certificate
//!   verified for the URL host, only `200` accepted (redirects are failures), body at most
//!   65535 bytes.
//!
//! `DoT` and `DoH` keep at most [`MAX_IDLE`] idle connections per server for [`IDLE_TIMEOUT`] (an
//! HTTP/2 connection is shared by concurrent queries). A reused connection that turns out broken
//! is dropped and the query retried once on a fresh connection.
//!
//! [`Upstreams::exchange`] runs one resolution inside one deadline: the plan is `attempts`
//! rounds over the server list in order. The next planned attempt starts when the newest one
//! fails, or when its share of the remaining time (`remaining / attempts left`, at least
//! [`MIN_STAGGER`]) elapses; in that case the earlier attempt keeps running, so a slow but alive
//! server can still answer, with at most [`MAX_PARALLEL`] attempts outstanding. When they are all
//! out, the oldest UDP attempt gives way (its datagram was likely lost); a TCP, `DoT` or `DoH`
//! attempt never does — over a far tunnel exit its handshakes take several round trips (a cold
//! `DoH` exchange is four or five), and cutting it short at every share would never let one finish
//! — so the next attempt then waits for one to end. The first valid answer wins; when the
//! deadline passes every outstanding attempt is dropped.

use std::future::{Future, poll_fn};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, ResponseCode};
use http::uri::{Authority, PathAndQuery, Scheme};
use http::{Method, Request, StatusCode, Uri, header};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use vpn_domain::{DnsServer, Text, tr};
use vpn_sync::Mutex;
use vpn_tunnel::{FlowClass, TunnelConnector, TunnelDatagram};

use super::wire::{self, Question, Reject};

/// Upstream servers per resolver (the DNS profile allows 1..=4).
pub(super) const MAX_SERVERS: usize = 4;
/// Idle DoT/DoH connections kept per server.
pub(super) const MAX_IDLE: usize = 2;
/// An idle connection is closed after this long.
pub(super) const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// How often idle connections are swept while any exist.
const REAP_INTERVAL: Duration = Duration::from_secs(5);
/// Outstanding attempts of one resolution: every configured server may be handshaking at once.
const MAX_PARALLEL: usize = MAX_SERVERS;
/// Shortest wait before the next planned attempt starts alongside a silent one.
const MIN_STAGGER: Duration = Duration::from_millis(100);
/// UDP receive buffer. We advertise an EDNS payload of 1232, so a datagram that fills this
/// buffer may have been cut and is re-asked over TCP.
const UDP_BUFFER: usize = 4096;
/// Foreign or mismatched datagrams/messages discarded per attempt before it gives up.
const MAX_DISCARDED: usize = 32;
const HTTP2_MAX_HEADER_LIST: u32 = 16 * 1024;
const HTTP1_MAX_BUFFER: usize = 16 * 1024;
const DNS_MESSAGE: &str = "application/dns-message";

/// A validated upstream response: QR=1, our ID, our question, RCODE NOERROR or NXDOMAIN.
pub(super) struct Reply {
    pub msg: Message,
    pub wire: Vec<u8>,
}

/// Why one attempt failed. Never carries names or addresses.
#[derive(Debug, Clone, Copy)]
pub(super) enum AttemptError {
    /// The server cannot work for this resolver (address family not carried by the tunnel,
    /// invalid `DoT` name or `DoH` URL, TLS verification/handshake failure). Skipped in later rounds.
    Unusable(&'static str),
    Io(io::ErrorKind),
    /// No acceptable response (malformed, too many foreign messages, truncated over a stream,
    /// wrong `DoH` content type or oversized body).
    Malformed,
    /// The server answered with a failure code (SERVFAIL, REFUSED, ...).
    Rcode(ResponseCode),
    /// `DoH` status other than 200, redirects included.
    Http(u16),
}

impl AttemptError {
    /// The reason in words for the status report (no names, no addresses).
    fn text(&self) -> Text {
        match self {
            Self::Unusable(reason) => match *reason {
                "server address family not carried by the tunnel" => tr!(
                    "this connection does not carry this kind of address",
                    "這條連線不承載這種位址",
                    "この接続はこの種類のアドレスを通しません"
                ),
                "TLS handshake or certificate verification failed" => tr!(
                    "TLS handshake or certificate verification failed (does the server name match the certificate?)",
                    "TLS 交握或憑證驗證失敗（伺服器名稱與憑證不符？）",
                    "TLS のハンドシェイクまたは証明書の検証に失敗しました（サーバー名が証明書と一致していない？）"
                ),
                "invalid DoT server name" => tr!(
                    "invalid DoT server name",
                    "DoT 的伺服器名稱無效",
                    "DoT のサーバー名が無効です"
                ),
                "invalid DoH URL" => {
                    tr!("invalid DoH URL", "DoH 的網址無效", "DoH の URL が無効です")
                }
                other => Text::verbatim(other),
            },
            Self::Io(io::ErrorKind::ConnectionRefused) => {
                tr!("connection refused", "連線被拒", "接続が拒否されました")
            }
            Self::Io(io::ErrorKind::TimedOut) => tr!(
                "connection timed out",
                "連線逾時",
                "接続がタイムアウトしました"
            ),
            Self::Io(io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => {
                tr!("connection dropped", "連線中斷", "接続が切断されました")
            }
            Self::Io(io::ErrorKind::PermissionDenied) => tr!(
                "the tunnel does not admit connections yet",
                "tunnel 尚未開放連線",
                "tunnel はまだ接続を受け付けていません"
            ),
            Self::Io(io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable) => tr!(
                "unreachable through the tunnel",
                "經 tunnel 無法到達",
                "tunnel 経由で到達できません"
            ),
            Self::Io(io::ErrorKind::QuotaExceeded | io::ErrorKind::OutOfMemory) => tr!(
                "the tunnel's connection or memory limit is reached",
                "tunnel 的連線數或記憶體已達上限",
                "tunnel の接続数またはメモリが上限に達しています"
            ),
            Self::Io(kind) => tr!(
                "connection error ({kind})",
                "連線錯誤（{kind}）",
                "接続エラー（{kind}）"
            ),
            Self::Malformed => tr!("unusable response", "回應無法使用", "応答を使用できません"),
            Self::Rcode(rcode) => tr!(
                "the server answered {rcode}",
                "伺服器回應 {rcode}",
                "サーバーが {rcode} を返しました"
            ),
            Self::Http(status) => tr!(
                "DoH answered HTTP {status}",
                "DoH 回應 HTTP {status}",
                "DoH が HTTP {status} を返しました"
            ),
        }
    }
}

impl std::fmt::Display for AttemptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unusable(reason) => write!(f, "server unusable: {reason}"),
            Self::Io(kind) => write!(f, "i/o error: {kind}"),
            Self::Malformed => f.write_str("no acceptable response"),
            Self::Rcode(rcode) => write!(f, "server answered {rcode}"),
            Self::Http(status) => write!(f, "DoH status {status}"),
        }
    }
}

impl AttemptError {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "used as a `map_err` adapter over owned `io::Error`s"
    )]
    fn io(err: io::Error) -> Self {
        Self::Io(err.kind())
    }

    /// TLS handshake errors are definitive for the server (bad certificate, wrong name, no
    /// common protocol); plain I/O errors during the handshake are not.
    fn tls(err: io::Error) -> Self {
        let rustls_error = err
            .get_ref()
            .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some());
        if rustls_error {
            Self::Unusable("TLS handshake or certificate verification failed")
        } else {
            Self::io(err)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExchangeError {
    /// The resolution deadline passed.
    Timeout,
    /// Every planned attempt failed before the deadline.
    Exhausted,
    /// Every attempt was refused locally by the tunnel's flow or memory limit before anything
    /// was sent: nothing is known about the tunnel or the servers.
    Admission,
    /// Not attempted: every server failed the latest health probe and the DNS profile asks
    /// nothing else (`DnsOnFailure::Fail`).
    Interrupted,
}

impl AttemptError {
    /// Refused by the tunnel's own admission limits (flows, buffer memory), not by the network.
    const fn is_admission(&self) -> bool {
        matches!(
            self,
            Self::Io(io::ErrorKind::QuotaExceeded | io::ErrorKind::OutOfMemory)
        )
    }
}

struct Idle<T> {
    conn: T,
    since: Instant,
}

struct DohEndpoint {
    server_name: ServerName<'static>,
    /// Absolute URI (HTTP/2 `:scheme`/`:authority`/`:path`).
    uri: Uri,
    /// HTTP/1.1 `Host` header and origin-form target.
    authority: Authority,
    path: PathAndQuery,
}

impl DohEndpoint {
    fn parse(url: &str) -> Option<Self> {
        let uri: Uri = url.parse().ok()?;
        if uri.scheme() != Some(&Scheme::HTTPS) {
            return None;
        }
        let authority = uri.authority()?.clone();
        if authority.as_str().contains('@') {
            return None;
        }
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let server_name = ServerName::try_from(host.to_owned()).ok()?;
        let path = uri
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| PathAndQuery::from_static("/"));
        Some(Self {
            server_name,
            uri,
            authority,
            path,
        })
    }
}

/// Aborts the task driving a hyper connection when the last handle on it goes away.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum Sender {
    H1(http1::SendRequest<Full<Bytes>>),
    H2(http2::SendRequest<Full<Bytes>>),
}

struct DohConn {
    sender: Sender,
    since: Instant,
    driver: Arc<AbortOnDrop>,
}

impl DohConn {
    /// Another handle on a shared HTTP/2 connection; `None` for HTTP/1.1.
    fn share(&self) -> Option<Self> {
        match &self.sender {
            Sender::H2(s) => Some(Self {
                sender: Sender::H2(s.clone()),
                since: self.since,
                driver: self.driver.clone(),
            }),
            Sender::H1(_) => None,
        }
    }

    const fn is_h2(&self) -> bool {
        matches!(self.sender, Sender::H2(_))
    }

    /// Not closed. An HTTP/1.1 connection may not be ready the instant its previous response
    /// ended (its driver task has not run yet); `post` waits for readiness.
    fn usable(&self) -> bool {
        match &self.sender {
            Sender::H1(s) => !s.is_closed(),
            Sender::H2(s) => !s.is_closed(),
        }
    }

    /// Unused for `IDLE_TIMEOUT`. A pooled connection is in use while some query holds another
    /// handle on it (shared HTTP/2).
    fn expired(&self, now: Instant) -> bool {
        Arc::strong_count(&self.driver) == 1
            && now.saturating_duration_since(self.since) >= IDLE_TIMEOUT
    }

    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.driver, &other.driver)
    }
}

enum Kind<S> {
    Udp,
    Tcp,
    Tls {
        name: Option<ServerName<'static>>,
        idle: Mutex<Vec<Idle<TlsStream<S>>>>,
    },
    Https {
        endpoint: Option<DohEndpoint>,
        conns: Mutex<Vec<DohConn>>,
    },
}

struct Server<S> {
    addr: SocketAddr,
    kind: Kind<S>,
}

/// What became of one resolution's attempts at each server, for the probe's report.
#[derive(Debug, Default)]
pub(super) struct Tally(Vec<Tried>);

#[derive(Debug, Clone, Copy, Default)]
struct Tried {
    /// An attempt went out and has neither answered nor failed.
    pending: bool,
    /// The latest attempt that failed, and why.
    error: Option<AttemptError>,
}

impl Tally {
    fn launched(&mut self, server: usize) {
        if let Some(t) = self.0.get_mut(server) {
            t.pending = true;
        }
    }

    fn failed(&mut self, server: usize, error: AttemptError) {
        if let Some(t) = self.0.get_mut(server) {
            *t = Tried {
                pending: false,
                error: Some(error),
            };
        }
    }
}

impl<S> Server<S> {
    /// One datagram per attempt: silence means it was likely lost.
    const fn is_datagram(&self) -> bool {
        matches!(self.kind, Kind::Udp)
    }

    /// `DoH 45.90.28.0:443`: what the report calls it.
    fn label(&self) -> String {
        let transport = match self.kind {
            Kind::Udp => "UDP",
            Kind::Tcp => "TCP",
            Kind::Tls { .. } => "DoT",
            Kind::Https { .. } => "DoH",
        };
        format!("{transport} {}", self.addr)
    }

    fn new(config: &DnsServer) -> Self {
        match config {
            DnsServer::Udp { address } => Self {
                addr: *address,
                kind: Kind::Udp,
            },
            DnsServer::Tcp { address } => Self {
                addr: *address,
                kind: Kind::Tcp,
            },
            DnsServer::Tls {
                address,
                server_name,
            } => Self {
                addr: *address,
                kind: Kind::Tls {
                    name: ServerName::try_from(server_name.clone()).ok(),
                    idle: Mutex::new(Vec::new()),
                },
            },
            DnsServer::Https { address, url } => Self {
                addr: *address,
                kind: Kind::Https {
                    endpoint: DohEndpoint::parse(url),
                    conns: Mutex::new(Vec::new()),
                },
            },
        }
    }
}

type AttemptFuture<'a> = Pin<Box<dyn Future<Output = Result<Reply, AttemptError>> + Send + 'a>>;

/// The configured upstream servers of one resolver, with their TLS settings and idle pools.
pub(super) struct Upstreams<C: TunnelConnector> {
    me: Weak<Self>,
    connector: C,
    servers: Vec<Server<C::Stream>>,
    rounds: usize,
    dot_tls: Option<TlsConnector>,
    doh_tls: Option<TlsConnector>,
    /// Whether the idle-connection sweeper task is running.
    reaper: AtomicBool,
}

impl<C: TunnelConnector> Upstreams<C> {
    pub fn new(
        connector: C,
        servers: &[DnsServer],
        attempts: u8,
        roots: Option<Arc<RootCertStore>>,
    ) -> Arc<Self> {
        let servers: Vec<Server<C::Stream>> =
            servers.iter().take(MAX_SERVERS).map(Server::new).collect();
        let needs_tls = servers
            .iter()
            .any(|s| matches!(s.kind, Kind::Tls { .. } | Kind::Https { .. }));
        let (tls_dot, tls_https) = if needs_tls {
            let roots = roots.unwrap_or_else(|| {
                Arc::new(RootCertStore::from_iter(
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                ))
            });
            let dot = tls_connector(roots.clone(), &[]);
            let doh = tls_connector(roots, &[b"h2", b"http/1.1"]);
            if dot.is_none() || doh.is_none() {
                tracing::warn!(
                    "DNS TLS client configuration unavailable; DoT/DoH servers will fail"
                );
            }
            (dot, doh)
        } else {
            (None, None)
        };
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            connector,
            servers,
            rounds: usize::from(attempts.clamp(1, 3)),
            dot_tls: tls_dot,
            doh_tls: tls_https,
            reaper: AtomicBool::new(false),
        })
    }

    /// Why each server gave no answer in a resolution that failed, as `tally` saw it: `DoH
    /// 45.90.28.0:443 no answer within 4.0 s`, `DoT 45.90.30.0:853 connection refused`… (never
    /// a query name).
    pub fn explain(&self, tally: &Tally, deadline: Duration) -> Vec<Text> {
        let secs = deadline.as_secs_f64();
        let parts: Vec<Text> = self
            .servers
            .iter()
            .zip(&tally.0)
            .filter_map(|(server, t)| {
                let why = match (t.error, t.pending) {
                    (Some(e), _) => e.text(),
                    (None, true) => tr!(
                        "no answer within {secs:.1} s",
                        "{secs:.1} 秒內沒有回應",
                        "{secs:.1} 秒以内に応答がありません"
                    ),
                    (None, false) => return None,
                };
                let label = server.label();
                Some(why.map(|_, why| format!("{label} {why}")))
            })
            .collect();
        if parts.is_empty() {
            vec![tr!(
                "no server to try",
                "沒有可以嘗試的伺服器",
                "試せるサーバーがありません"
            )]
        } else {
            parts
        }
    }

    /// Whether the tunnel carries IPv6 (`true`) or IPv4 (`false`) at all.
    pub fn carries(&self, v6: bool) -> bool {
        let probe = if v6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        self.connector.supports(probe)
    }

    pub fn supports(&self, ip: IpAddr) -> bool {
        self.connector.supports(ip)
    }

    /// One resolution of `q` across servers × attempts, all within `deadline`.
    pub async fn exchange(&self, q: &Question, deadline: Instant) -> Result<Reply, ExchangeError> {
        self.exchange_tallied(q, deadline, &mut Tally::default())
            .await
    }

    /// [`Self::exchange`], keeping in `tally` what became of the attempts at each server.
    pub async fn exchange_tallied(
        &self,
        q: &Question,
        deadline: Instant,
        tally: &mut Tally,
    ) -> Result<Reply, ExchangeError> {
        tally.0 = vec![Tried::default(); self.servers.len()];
        tokio::time::timeout_at(deadline, self.run_plan(q, deadline, tally))
            .await
            .unwrap_or(Err(ExchangeError::Timeout))
    }

    async fn run_plan(
        &self,
        q: &Question,
        deadline: Instant,
        tally: &mut Tally,
    ) -> Result<Reply, ExchangeError> {
        let n = self.servers.len();
        let plan = n * self.rounds;
        let mut next = 0;
        let mut unusable = vec![false; n];
        let mut running: Vec<(usize, AttemptFuture<'_>)> = Vec::with_capacity(MAX_PARALLEL);
        let mut stagger = Box::pin(tokio::time::sleep_until(deadline));
        let mut armed = false;
        let mut launch = true;
        // Whether every attempt so far failed, and only on local admission.
        let mut failed = false;
        let mut only_admission = true;
        loop {
            // A slot for the next attempt: a free one, or the oldest UDP attempt's (silent for a
            // whole share: its datagram was likely lost). Handshaking stream attempts keep theirs.
            let giving_way = if running.len() < MAX_PARALLEL {
                Some(None)
            } else {
                running
                    .iter()
                    .position(|(s, _)| self.servers[*s].is_datagram())
                    .map(Some)
            };
            if launch && let Some(slot) = giving_way {
                armed = false;
                if let Some(server) = next_server(&mut next, plan, n, &unusable) {
                    if let Some(i) = slot {
                        // It went out: not a local refusal.
                        drop(running.remove(i));
                        failed = true;
                        only_admission = false;
                    }
                    tally.launched(server);
                    running.push((server, Box::pin(self.attempt(server, q))));
                    let left = planned_left(next, plan, n, &unusable);
                    if left > 0 {
                        let now = Instant::now();
                        let share = deadline.saturating_duration_since(now)
                            / u32::try_from(left + 1).unwrap_or(u32::MAX);
                        stagger.as_mut().reset(now + share.max(MIN_STAGGER));
                        armed = true;
                    }
                }
            }
            if running.is_empty() {
                return Err(if failed && only_admission {
                    ExchangeError::Admission
                } else {
                    ExchangeError::Exhausted
                });
            }
            let event = poll_fn(|cx| {
                for (i, (_, attempt)) in running.iter_mut().enumerate() {
                    if let Poll::Ready(result) = attempt.as_mut().poll(cx) {
                        return Poll::Ready(Some((i, result)));
                    }
                }
                if armed && stagger.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(None);
                }
                Poll::Pending
            })
            .await;
            launch = match event {
                // The stagger fired: launch now if a slot is free, else when an attempt ends.
                None => {
                    armed = false;
                    true
                }
                Some((_, Ok(reply))) => return Ok(reply),
                Some((i, Err(error))) => {
                    let (server, _) = running.remove(i);
                    tracing::debug!(server, %error, "DNS upstream attempt failed");
                    tally.failed(server, error);
                    if matches!(error, AttemptError::Unusable(_)) {
                        unusable[server] = true;
                    }
                    failed = true;
                    only_admission &= error.is_admission();
                    // The newest attempt failing frees its turn at once, and so does any attempt
                    // when no launch is scheduled (all slots were taken by handshaking ones).
                    i == running.len() || !armed
                }
            };
        }
    }

    async fn attempt(&self, idx: usize, q: &Question) -> Result<Reply, AttemptError> {
        let server = &self.servers[idx];
        if !self.connector.supports(server.addr.ip()) {
            return Err(AttemptError::Unusable(
                "server address family not carried by the tunnel",
            ));
        }
        let reply = match &server.kind {
            Kind::Udp => self.udp(server.addr, q).await,
            Kind::Tcp => self.tcp(server.addr, q).await,
            Kind::Tls { name, idle } => self.dot(server.addr, name.as_ref(), idle, q).await,
            Kind::Https { endpoint, conns } => {
                self.doh(server.addr, endpoint.as_ref(), conns, q).await
            }
        }?;
        let rcode = reply.msg.metadata.response_code;
        if wire::is_answer(rcode) {
            Ok(reply)
        } else {
            Err(AttemptError::Rcode(rcode))
        }
    }

    async fn udp(&self, addr: SocketAddr, q: &Question) -> Result<Reply, AttemptError> {
        let socket = self
            .connector
            .bind_udp(FlowClass::Control)
            .map_err(AttemptError::io)?;
        let id: u16 = rand::random();
        let query = q.encode(id).ok_or(AttemptError::Malformed)?;
        socket
            .send_to(&query, addr)
            .await
            .map_err(AttemptError::io)?;
        let mut buf = vec![0u8; UDP_BUFFER];
        for _ in 0..MAX_DISCARDED {
            let (len, from) = socket.recv_from(&mut buf).await.map_err(AttemptError::io)?;
            if from.port() != addr.port() || from.ip().to_canonical() != addr.ip().to_canonical() {
                continue;
            }
            let Some(datagram) = buf.get(..len) else {
                continue;
            };
            if len >= UDP_BUFFER {
                if wire::is_response_to(datagram, id) {
                    return self.tcp(addr, q).await;
                }
                continue;
            }
            match wire::check_response(datagram, id, q) {
                Ok(msg) if msg.metadata.truncation => return self.tcp(addr, q).await,
                Ok(msg) => {
                    return Ok(Reply {
                        msg,
                        wire: datagram.to_vec(),
                    });
                }
                Err(_) => {}
            }
        }
        Err(AttemptError::Malformed)
    }

    async fn tcp(&self, addr: SocketAddr, q: &Question) -> Result<Reply, AttemptError> {
        let mut stream = self
            .connector
            .connect_tcp(addr, FlowClass::Control)
            .await
            .map_err(AttemptError::io)?;
        stream_exchange(&mut stream, q).await
    }

    async fn dot(
        &self,
        addr: SocketAddr,
        name: Option<&ServerName<'static>>,
        idle: &Mutex<Vec<Idle<TlsStream<C::Stream>>>>,
        q: &Question,
    ) -> Result<Reply, AttemptError> {
        let (Some(name), Some(tls)) = (name, self.dot_tls.as_ref()) else {
            return Err(AttemptError::Unusable("invalid DoT server name"));
        };
        if let Some(mut stream) = checkout(idle) {
            match stream_exchange(&mut stream, q).await {
                Ok(reply) => {
                    self.park(idle, stream);
                    return Ok(reply);
                }
                // Closed by the server while idle: retry once on a fresh connection.
                Err(AttemptError::Io(_)) => {}
                Err(other) => return Err(other),
            }
        }
        let tcp = self
            .connector
            .connect_tcp(addr, FlowClass::Control)
            .await
            .map_err(AttemptError::io)?;
        let mut stream = tls
            .connect(name.clone(), tcp)
            .await
            .map_err(AttemptError::tls)?;
        let reply = stream_exchange(&mut stream, q).await?;
        self.park(idle, stream);
        Ok(reply)
    }

    fn park(&self, idle: &Mutex<Vec<Idle<TlsStream<C::Stream>>>>, conn: TlsStream<C::Stream>) {
        let surplus = {
            let mut idle = idle.lock();
            if idle.len() < MAX_IDLE {
                idle.push(Idle {
                    conn,
                    since: Instant::now(),
                });
                drop(idle);
                None
            } else {
                Some(conn)
            }
        };
        drop(surplus);
        self.arm_reaper();
    }

    async fn doh(
        &self,
        addr: SocketAddr,
        endpoint: Option<&DohEndpoint>,
        conns: &Mutex<Vec<DohConn>>,
        q: &Question,
    ) -> Result<Reply, AttemptError> {
        let (Some(endpoint), Some(tls)) = (endpoint, self.doh_tls.as_ref()) else {
            return Err(AttemptError::Unusable("invalid DoH URL"));
        };
        // RFC 8484 §4.1: ID 0; HTTP pairs the response with the request.
        let query = Bytes::from(q.encode(0).ok_or(AttemptError::Malformed)?);
        if let Some(mut conn) = checkout_doh(conns) {
            match post(&mut conn, endpoint, query.clone()).await {
                Ok(body) => {
                    self.park_doh(conns, conn);
                    return doh_reply(body, q);
                }
                // Broken while idle: forget it and retry once on a fresh connection.
                Err(AttemptError::Io(_)) => conns.lock().retain(|c| !c.same(&conn)),
                Err(other) => return Err(other),
            }
        }
        let mut conn = self.doh_connect(addr, endpoint, tls).await?;
        if let Some(shared) = conn.share() {
            let mut pool = conns.lock();
            if pool.len() < MAX_IDLE {
                pool.push(shared);
            }
        }
        match post(&mut conn, endpoint, query).await {
            Ok(body) => {
                self.park_doh(conns, conn);
                doh_reply(body, q)
            }
            Err(error) => {
                if matches!(error, AttemptError::Io(_)) {
                    conns.lock().retain(|c| !c.same(&conn));
                }
                Err(error)
            }
        }
    }

    async fn doh_connect(
        &self,
        addr: SocketAddr,
        endpoint: &DohEndpoint,
        tls: &TlsConnector,
    ) -> Result<DohConn, AttemptError> {
        let tcp = self
            .connector
            .connect_tcp(addr, FlowClass::Control)
            .await
            .map_err(AttemptError::io)?;
        let stream = tls
            .connect(endpoint.server_name.clone(), tcp)
            .await
            .map_err(AttemptError::tls)?;
        let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
        let io = TokioIo::new(stream);
        let handshake_failed = |_| AttemptError::Io(io::ErrorKind::ConnectionAborted);
        let (sender, driver) = if h2 {
            let (sender, conn) = http2::Builder::new(TokioExecutor::new())
                .max_header_list_size(HTTP2_MAX_HEADER_LIST)
                .handshake(io)
                .await
                .map_err(handshake_failed)?;
            let driver = tokio::spawn(async move {
                if let Err(e) = conn.await {
                    tracing::debug!(error = %e, "DoH connection ended with an error");
                }
            });
            (Sender::H2(sender), driver)
        } else {
            let (sender, conn) = http1::Builder::new()
                .max_buf_size(HTTP1_MAX_BUFFER)
                .handshake(io)
                .await
                .map_err(handshake_failed)?;
            let driver = tokio::spawn(async move {
                if let Err(e) = conn.await {
                    tracing::debug!(error = %e, "DoH connection ended with an error");
                }
            });
            (Sender::H1(sender), driver)
        };
        Ok(DohConn {
            sender,
            since: Instant::now(),
            driver: Arc::new(AbortOnDrop(driver.abort_handle())),
        })
    }

    fn park_doh(&self, conns: &Mutex<Vec<DohConn>>, conn: DohConn) {
        let now = Instant::now();
        let surplus = {
            let mut pool = conns.lock();
            if conn.is_h2() {
                if let Some(pooled) = pool.iter_mut().find(|c| c.same(&conn)) {
                    pooled.since = now;
                }
                Some(conn)
            } else if pool.len() < MAX_IDLE {
                pool.push(DohConn { since: now, ..conn });
                drop(pool);
                None
            } else {
                Some(conn)
            }
        };
        drop(surplus);
        self.arm_reaper();
    }

    /// Starts the sweeper that closes idle connections past `IDLE_TIMEOUT`, unless it runs.
    fn arm_reaper(&self) {
        if self.reaper.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = self.me.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(REAP_INTERVAL).await;
                let Some(upstreams) = me.upgrade() else {
                    return;
                };
                if upstreams.reap(Instant::now()) {
                    continue;
                }
                upstreams.reaper.store(false, Ordering::Release);
                // A connection parked between the sweep and the store saw the flag still set:
                // take the job back unless another sweeper already did.
                if !upstreams.reap(Instant::now()) || upstreams.reaper.swap(true, Ordering::AcqRel)
                {
                    return;
                }
            }
        });
    }

    /// Closes expired or dead idle connections; returns whether any idle connection remains.
    fn reap(&self, now: Instant) -> bool {
        let mut left = false;
        for server in &self.servers {
            match &server.kind {
                Kind::Tls { idle, .. } => {
                    let mut idle = idle.lock();
                    idle.retain(|c| now.saturating_duration_since(c.since) < IDLE_TIMEOUT);
                    left |= !idle.is_empty();
                }
                Kind::Https { conns, .. } => {
                    let mut conns = conns.lock();
                    conns.retain(|c| c.usable() && !c.expired(now));
                    left |= !conns.is_empty();
                }
                Kind::Udp | Kind::Tcp => {}
            }
        }
        left
    }
}

fn tls_connector(roots: Arc<RootCertStore>, alpn: &[&[u8]]) -> Option<TlsConnector> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Some(TlsConnector::from(Arc::new(config)))
}

/// Next server in the plan (position `p` asks server `p % n`), skipping unusable servers.
const fn next_server(next: &mut usize, plan: usize, n: usize, unusable: &[bool]) -> Option<usize> {
    while *next < plan {
        let server = *next % n;
        *next += 1;
        if !unusable[server] {
            return Some(server);
        }
    }
    None
}

fn planned_left(next: usize, plan: usize, n: usize, unusable: &[bool]) -> usize {
    (next..plan).filter(|p| !unusable[p % n]).count()
}

fn checkout<T>(idle: &Mutex<Vec<Idle<T>>>) -> Option<T> {
    let now = Instant::now();
    let mut idle = idle.lock();
    idle.retain(|c| now.saturating_duration_since(c.since) < IDLE_TIMEOUT);
    idle.pop().map(|c| c.conn)
}

/// A pooled `DoH` connection: a handle on a shared HTTP/2 connection, else an idle HTTP/1.1 one
/// taken out of the pool.
fn checkout_doh(conns: &Mutex<Vec<DohConn>>) -> Option<DohConn> {
    let now = Instant::now();
    let mut pool = conns.lock();
    pool.retain(|c| c.usable() && !c.expired(now));
    if let Some(shared) = pool.iter().find_map(DohConn::share) {
        return Some(shared);
    }
    pool.pop()
}

/// One query over an RFC 1035 length-framed stream (TCP or `DoT`). Returns the matching response
/// whatever its RCODE, so a healthy connection can go back to the pool.
async fn stream_exchange<S>(stream: &mut S, q: &Question) -> Result<Reply, AttemptError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let id: u16 = rand::random();
    let query = q.encode(id).ok_or(AttemptError::Malformed)?;
    let len = u16::try_from(query.len()).map_err(|_too_long| AttemptError::Malformed)?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&query);
    stream.write_all(&framed).await.map_err(AttemptError::io)?;
    stream.flush().await.map_err(AttemptError::io)?;
    for _ in 0..MAX_DISCARDED {
        let mut prefix = [0u8; 2];
        stream
            .read_exact(&mut prefix)
            .await
            .map_err(AttemptError::io)?;
        let mut message = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream
            .read_exact(&mut message)
            .await
            .map_err(AttemptError::io)?;
        match wire::check_response(&message, id, q) {
            Ok(msg) if msg.metadata.truncation => return Err(AttemptError::Malformed),
            Ok(msg) => return Ok(Reply { msg, wire: message }),
            Err(Reject::Mismatch) => {}
            Err(Reject::Malformed) => return Err(AttemptError::Malformed),
        }
    }
    Err(AttemptError::Malformed)
}

/// `POST` one `DoH` query; returns the response body. Transport errors map to `Io` (the caller
/// may retry on a fresh connection); HTTP-level refusals to `Http` / `Malformed`.
async fn post(
    conn: &mut DohConn,
    endpoint: &DohEndpoint,
    query: Bytes,
) -> Result<Vec<u8>, AttemptError> {
    let broken = |_| AttemptError::Io(io::ErrorKind::ConnectionAborted);
    // The URL was checked when the server was configured; a request that still does not build
    // is no exchange, and why is logged.
    let unbuildable = |e: http::Error| {
        tracing::debug!(error = %e, "DoH request not built");
        AttemptError::Malformed
    };
    let request = Request::builder()
        .method(Method::POST)
        .header(header::CONTENT_TYPE, DNS_MESSAGE)
        .header(header::ACCEPT, DNS_MESSAGE);
    let response = match &mut conn.sender {
        Sender::H2(sender) => {
            let request = request
                .uri(endpoint.uri.clone())
                .body(Full::new(query))
                .map_err(unbuildable)?;
            sender.ready().await.map_err(broken)?;
            sender.send_request(request).await.map_err(broken)?
        }
        Sender::H1(sender) => {
            let request = request
                .uri(endpoint.path.clone())
                .header(header::HOST, endpoint.authority.as_str())
                .body(Full::new(query))
                .map_err(unbuildable)?;
            sender.ready().await.map_err(broken)?;
            sender.send_request(request).await.map_err(broken)?
        }
    };
    if response.status() != StatusCode::OK {
        return Err(AttemptError::Http(response.status().as_u16()));
    }
    let headers = response.headers();
    let media_type_ok = headers.get(header::CONTENT_TYPE).is_none_or(|v| {
        v.to_str().is_ok_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|m| m.trim().eq_ignore_ascii_case(DNS_MESSAGE))
        })
    });
    let declared_too_long = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
        .is_some_and(|len| len > wire::MAX_MESSAGE as u64);
    if !media_type_ok || declared_too_long {
        return Err(AttemptError::Malformed);
    }
    let body = Limited::new(response.into_body(), wire::MAX_MESSAGE)
        .collect()
        .await
        .map_err(|e| {
            if e.is::<LengthLimitError>() {
                AttemptError::Malformed
            } else {
                AttemptError::Io(io::ErrorKind::ConnectionAborted)
            }
        })?;
    Ok(body.to_bytes().to_vec())
}

fn doh_reply(body: Vec<u8>, q: &Question) -> Result<Reply, AttemptError> {
    match wire::check_response(&body, 0, q) {
        Ok(msg) if !msg.metadata.truncation => Ok(Reply { msg, wire: body }),
        _ => Err(AttemptError::Malformed),
    }
}
