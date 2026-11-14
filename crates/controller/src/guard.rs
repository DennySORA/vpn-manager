//! Browser-facing request guard. There is no login: the boundary is "only this machine, only
//! this origin". DNS-rebinding hosts, cross-site requests, proxies and CORS are refused.
//!
//! When the web UI is installed open to the LAN (`--listen-address`, `--allow-client`), the
//! browser on another host reaches it at one of this host's own addresses: such a Host
//! (`<address>:<port>`, an address this host has right now, not loopback or link-local) and the
//! matching Origin are accepted as well. Still never a name (no DNS rebinding), never a proxy,
//! never CORS; who may connect at all is decided before (`crate::tcp_listener`).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use vpn_domain::{ErrorCode, Text, tr};

use crate::http::bad;

pub struct GuardConfig {
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    /// The web UI is open to the LAN: this host's own addresses with its port count too.
    pub lan: Option<LanHosts>,
}

impl std::fmt::Debug for GuardConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardConfig")
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_origins", &self.allowed_origins)
            .field("lan", &self.lan.as_ref().map(|l| l.port))
            .finish()
    }
}

/// This host's own addresses, as its interfaces have them (or as a test says).
pub type AddressSource = Arc<dyn Fn() -> io::Result<Vec<IpAddr>> + Send + Sync>;

/// How long a looked-up address list is trusted for an address in it.
const ADDRESSES_FRESH: Duration = Duration::from_secs(10);
/// An address not in the list is looked up again at most this often (a forged Host header cannot
/// make the server enumerate interfaces on every request).
const ADDRESSES_RECHECK: Duration = Duration::from_secs(1);

/// Hosts at this host's own addresses (`<address>:<port>`).
pub struct LanHosts {
    port: u16,
    source: AddressSource,
    cache: vpn_sync::Mutex<(Option<Instant>, Vec<IpAddr>)>,
}

impl LanHosts {
    pub fn new(port: u16, source: AddressSource) -> Self {
        Self {
            port,
            source,
            cache: vpn_sync::Mutex::new((None, Vec::new())),
        }
    }

    /// The interfaces of this host.
    pub fn of_this_host(port: u16) -> Self {
        Self::new(port, Arc::new(vpn_platform::netif::addresses))
    }

    fn has_address(&self, ip: IpAddr) -> bool {
        let mut cache = self.cache.lock();
        let (at, list) = &mut *cache;
        if at.is_some_and(|t| t.elapsed() < ADDRESSES_FRESH) && list.contains(&ip) {
            return true;
        }
        if at.is_none_or(|t| t.elapsed() >= ADDRESSES_RECHECK) {
            *list = (self.source)()
                .unwrap_or_default()
                .into_iter()
                .map(|a| a.to_canonical())
                .collect();
            *at = Some(Instant::now());
        }
        let found = list.contains(&ip);
        drop(cache);
        found
    }

    /// `host` (a Host header value, or an Origin without its scheme) is `<one of this host's
    /// reachable addresses>:<the web UI's port>`.
    pub fn accepts(&self, host: &str) -> bool {
        let Ok(addr) = host.parse::<SocketAddr>() else {
            return false;
        };
        let ip = addr.ip().to_canonical();
        addr.port() == self.port && vpn_platform::netif::reachable(ip) && self.has_address(ip)
    }
}

impl GuardConfig {
    #[must_use]
    pub fn loopback(port: u16, dev_origins: &[String]) -> Self {
        let mut allowed_hosts = vec![format!("127.0.0.1:{port}"), format!("localhost:{port}")];
        let mut allowed_origins = vec![
            format!("http://127.0.0.1:{port}"),
            format!("http://localhost:{port}"),
        ];
        for o in dev_origins {
            allowed_origins.push(o.clone());
            if let Some(h) = o.strip_prefix("http://") {
                allowed_hosts.push(h.to_string());
            }
        }
        Self {
            allowed_hosts,
            allowed_origins,
            lan: None,
        }
    }

    /// Also accept this host's own addresses (the web UI is open to the LAN).
    #[must_use]
    pub fn with_lan(mut self, lan: LanHosts) -> Self {
        self.lan = Some(lan);
        self
    }

    fn host_allowed(&self, host: &str) -> bool {
        self.allowed_hosts
            .iter()
            .any(|a| a.eq_ignore_ascii_case(host))
            || self.lan.as_ref().is_some_and(|l| l.accepts(host))
    }

    fn origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|a| a == origin)
            || self.lan.as_ref().is_some_and(|l| {
                origin
                    .strip_prefix("http://")
                    .is_some_and(|host| l.accepts(host))
            })
    }
}

/// A request the guard refuses, and why.
fn forbidden(why: Text) -> Response {
    bad(ErrorCode::ForbiddenOrigin, why).into_response()
}

pub async fn guard(State(cfg): State<Arc<GuardConfig>>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    let hosts: Vec<_> = headers.get_all(header::HOST).iter().collect();
    let host_ok = hosts.len() == 1 && hosts[0].to_str().is_ok_and(|h| cfg.host_allowed(h));
    if !host_ok {
        return forbidden(tr!(
            "The Host is not this computer's management address",
            "Host 不是本機管理位址",
            "Host がこのコンピューターの管理アドレスではありません"
        ));
    }
    for h in [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-real-ip",
    ] {
        if headers.contains_key(h) {
            return forbidden(tr!(
                "Requests forwarded through a proxy are not accepted",
                "不接受經代理轉送的請求",
                "プロキシ経由で転送されたリクエストは受け付けません"
            ));
        }
    }
    let method = req.method().clone();
    if method == Method::OPTIONS {
        return forbidden(tr!(
            "Cross-origin requests are not supported",
            "不支援跨來源請求",
            "クロスオリジンのリクエストには対応していません"
        ));
    }
    let fetch_site = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let cross_site = matches!(fetch_site.as_deref(), Some("cross-site" | "same-site"));
    let is_api = req.uri().path().starts_with("/v1/");
    if !matches!(method, Method::GET | Method::HEAD) {
        let origin_ok = headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|o| cfg.origin_allowed(o));
        if !origin_ok || cross_site {
            return forbidden(tr!(
                "Only change requests from this computer's management page are accepted",
                "只接受來自本機管理頁的變更請求",
                "このコンピューターの管理ページからの変更リクエストだけを受け付けます"
            ));
        }
    } else if is_api && cross_site {
        return forbidden(tr!(
            "Only requests from this computer's management page are accepted",
            "只接受來自本機管理頁的請求",
            "このコンピューターの管理ページからのリクエストだけを受け付けます"
        ));
    }

    let mut resp = next.run(req).await;
    secure(resp.headers_mut(), is_api);
    resp
}

/// The security headers of every response (and `no-store` for an API answer that sets no cache
/// policy of its own).
fn secure(h: &mut HeaderMap, is_api: bool) {
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(vpn_web_provide::CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    );
    if is_api && !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}
