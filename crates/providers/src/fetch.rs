//! Bounded download of a user-supplied `https://` URL (IP blocklist sources).
//!
//! The download goes over the caller's [`Connect`] — in the product the Provider egress connection, so the download goes through a
//! VPN tunnel and never the host network.
//!
//! Same TLS client and bounds as the provider requests (web PKI, verification always on,
//! HTTP/1.1, one connection per request, the body bounded while it is read, one deadline for
//! everything, redirects included). Redirects are followed only within the same origin (host and
//! port; the scheme is always https), at most [`MAX_REDIRECTS`]; a redirect to another origin is
//! refused and named. No `Accept-Encoding` is sent and a compressed answer is refused.

use std::time::Duration;

use std::fmt;

use http::header;
use tokio::time::Instant;
use vpn_domain::blocklist::HttpsUrl;
use vpn_domain::{Text, tr};

use crate::https::{Connect, Family, HttpError, HttpsClient};

/// Same-origin redirects followed before giving up.
pub const MAX_REDIRECTS: usize = 3;

/// A completed download.
#[derive(Debug)]
pub struct Download {
    /// Where the content came from (after same-origin redirects).
    pub url: HttpsUrl,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

/// Why a download failed. [`DownloadError::text`] is the message a person reads; `Display` is
/// its English.
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    Http(#[from] HttpError),
    Status(u16),
    CrossOrigin(String),
    TooManyRedirects,
    BadRedirect,
    Encoded(String),
}

impl DownloadError {
    /// The message a person reads, in the three languages.
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::Http(e) => e.text(),
            Self::Status(status) => tr!(
                "The server answered HTTP {status}",
                "伺服器回應 HTTP {status}",
                "サーバーが HTTP {status} を返しました"
            ),
            Self::CrossOrigin(origin) => tr!(
                "The server redirected to another site ({origin}), refused; enter the final address directly",
                "伺服器重新導向到另一個網站（{origin}），已拒絕；請直接填寫最終的網址",
                "サーバーが別のサイト（{origin}）にリダイレクトしたため拒否しました。最終的なアドレスを直接入力してください"
            ),
            Self::TooManyRedirects => tr!(
                "More than {MAX_REDIRECTS} redirects",
                "重新導向超過 {MAX_REDIRECTS} 次",
                "リダイレクトが {MAX_REDIRECTS} 回を超えました"
            ),
            Self::BadRedirect => tr!(
                "The server's redirect address is not valid",
                "伺服器的重新導向位址無效",
                "サーバーのリダイレクト先アドレスが無効です"
            ),
            Self::Encoded(encoding) => tr!(
                "The server answered in a compressed format ({encoding}), not accepted",
                "伺服器以壓縮格式（{encoding}）回應，不接受",
                "サーバーが圧縮形式（{encoding}）で応答したため、受け付けません"
            ),
        }
    }
}

impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text().en)
    }
}

/// GET `url` over `client`'s connector and `family`; the body is at most `limit` bytes and the
/// whole exchange (redirects included) ends within `timeout`.
///
/// # Errors
///
/// [`DownloadError::Http`] when the connection, TLS, the size bound or the deadline fails,
/// [`DownloadError::Status`] for a status other than success or a redirect,
/// [`DownloadError::CrossOrigin`], [`DownloadError::TooManyRedirects`] or
/// [`DownloadError::BadRedirect`] for a redirect this does not follow, and
/// [`DownloadError::Encoded`] for a compressed answer.
pub async fn download<C: Connect>(
    client: &HttpsClient<C>,
    url: &HttpsUrl,
    family: Family,
    limit: usize,
    timeout: Duration,
) -> Result<Download, DownloadError> {
    let deadline = Instant::now() + timeout;
    let mut current = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        let mut response = client
            .get_user_url(
                &current.host,
                current.port,
                &current.path,
                family,
                limit,
                deadline,
            )
            .await?;
        if response.status.is_redirection() {
            let next = response
                .headers
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|location| current.join(location))
                .ok_or(DownloadError::BadRedirect)?;
            if next.host != current.host || next.port != current.port {
                return Err(DownloadError::CrossOrigin(next.origin()));
            }
            current = next;
            continue;
        }
        if !response.status.is_success() {
            return Err(DownloadError::Status(response.status.as_u16()));
        }
        if let Some(encoding) = response
            .headers
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .filter(|e| !e.trim().eq_ignore_ascii_case("identity"))
        {
            return Err(DownloadError::Encoded(encoding.chars().take(32).collect()));
        }
        let content_type = response
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.chars().take(100).collect());
        return Ok(Download {
            url: current,
            body: std::mem::take(&mut *response.body),
            content_type,
        });
    }
    Err(DownloadError::TooManyRedirects)
}
