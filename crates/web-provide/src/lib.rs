//! Web Provide Service: the React workbench embedded into the binary.
//!
//! Static content only — it holds no business state and calls nothing. Hashed assets are
//! immutable-cached; `index.html` is never cached. Unknown paths fall back to `index.html` so
//! client-side routes work on reload. Every response carries the strict CSP.

#![forbid(unsafe_code)]

use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode, Uri, header};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../web/dist"]
#[allow_missing = true]
struct Assets;

/// Content-Security-Policy for the workbench: same-origin only, no inline scripts, no
/// third-party anything.
///
/// Inline *styles* are allowed: the dialog scroll lock (Radix / react-remove-scroll) injects
/// `<style>` elements at runtime and the dark first paint is an inline style. Scripts, connections
/// and images stay `'self'`, so injected CSS cannot load or send anything off-origin.
pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

#[must_use]
pub fn has_assets() -> bool {
    Assets::get("index.html").is_some()
}

/// Serve an embedded asset or the SPA entry point.
#[expect(
    clippy::unused_async,
    reason = "the controller mounts it as an axum fallback handler, which must return a future"
)]
pub async fn serve(uri: Uri) -> Response<Body> {
    let path = uri.path().trim_start_matches('/');
    let (file, name, immutable) = match Assets::get(path) {
        Some(f) if !path.is_empty() => (Some(f), path.to_string(), path.starts_with("assets/")),
        _ => (Assets::get("index.html"), "index.html".to_string(), false),
    };
    let Some(file) = file else {
        // English: a build without the interface (a developer's), and this crate has no
        // `vpn_domain::Text` to write the three languages with.
        let mut r = Response::new(Body::from(
            "The VPN Manager web interface is not built (web/dist is missing). Run `pnpm --dir web build`, then rebuild vpnd.",
        ));
        *r.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        return r;
    };
    let mime = mime_guess::from_path(&name).first_or_octet_stream();
    let mut r = Response::new(Body::from(file.data.into_owned()));
    let h = r.headers_mut();
    if let Ok(v) = HeaderValue::from_str(mime.as_ref()) {
        h.insert(header::CONTENT_TYPE, v);
    }
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if immutable {
            "public, max-age=31536000, immutable"
        } else {
            "no-store"
        }),
    );
    r
}
