//! The browser boundary without login: only this machine, only this origin.

// Test fixtures: a failed setup step should panic right there.
#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap/expect in #[test] fns, not in the helper fns of a tests/ crate"
)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use vpn_controller::guard::GuardConfig;
use vpn_controller::hub::Hub;
use vpn_controller::link::ManagerLink;
use vpn_controller::routes::AppState;

fn app() -> axum::Router {
    let hub = Hub::new();
    // No manager is running: requests that pass the guard get 503, which proves they passed.
    let link = ManagerLink::new("/nonexistent/manager.sock".into(), hub.clone());
    vpn_controller::browser_router(
        AppState {
            link,
            hub,
            port: 18765,
            exposure: Arc::default(),
            data_dir: None,
            gateway_key: None,
            providers: vpn_controller::provider::Providers::new(),
        },
        GuardConfig::loopback(18765, &[]),
    )
}

async fn send(req: Request<Body>) -> (StatusCode, String) {
    let resp = app().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn post(host: &str, origin: Option<&str>, site: Option<&str>) -> Request<Body> {
    let mut b = Request::post("/v1/dns-profiles")
        .header("host", host)
        .header("content-type", "application/json")
        .header("idempotency-key", "0b8a2d7e-6a4c-4c8e-9b1a-2f3c4d5e6f70");
    if let Some(o) = origin {
        b = b.header("origin", o);
    }
    if let Some(s) = site {
        b = b.header("sec-fetch-site", s);
    }
    b.body(Body::from(
        r#"{"name":"x","servers":[{"transport":"udp","address":"9.9.9.9:53"}]}"#,
    ))
    .unwrap()
}

#[tokio::test]
async fn host_origin_and_fetch_metadata_are_enforced() {
    // DNS rebinding: attacker hostname resolving to 127.0.0.1.
    let (s, b) = send(post(
        "evil.example:18765",
        Some("http://evil.example:18765"),
        None,
    ))
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    // Cross-site form or fetch.
    let (s, _) = send(post(
        "127.0.0.1:18765",
        Some("https://evil.example"),
        Some("cross-site"),
    ))
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // A mutation without Origin.
    let (s, _) = send(post("127.0.0.1:18765", None, None)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Proxied requests are refused outright.
    let mut req = post(
        "127.0.0.1:18765",
        Some("http://127.0.0.1:18765"),
        Some("same-origin"),
    );
    req.headers_mut()
        .insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
    assert_eq!(send(req).await.0, StatusCode::FORBIDDEN);
    // CORS preflight does not exist.
    let pre = Request::options("/v1/dns-profiles")
        .header("host", "127.0.0.1:18765")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(pre).await.0, StatusCode::FORBIDDEN);
    // Same-origin mutation passes the guard (manager is down -> 503, with a Chinese message).
    let (s, b) = send(post(
        "127.0.0.1:18765",
        Some("http://127.0.0.1:18765"),
        Some("same-origin"),
    ))
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    assert!(b.contains("manager"), "{b}");
    // localhost works the same way.
    let (s, _) = send(post(
        "localhost:18765",
        Some("http://localhost:18765"),
        Some("same-origin"),
    ))
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn mutations_need_idempotency_key_and_api_responses_are_not_cached() {
    let mut req = post(
        "127.0.0.1:18765",
        Some("http://127.0.0.1:18765"),
        Some("same-origin"),
    );
    req.headers_mut().remove("idempotency-key");
    let resp = app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    assert!(
        resp.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'self'")
    );
}

/// The router of a web UI installed open to the LAN, on a host whose addresses are 127.0.0.1,
/// 192.168.20.100 and `fd00:20::100`.
fn lan_app() -> axum::Router {
    use vpn_controller::guard::LanHosts;
    let hub = Hub::new();
    let link = ManagerLink::new("/nonexistent/manager.sock".into(), hub.clone());
    let addresses: vpn_controller::guard::AddressSource = Arc::new(|| {
        Ok(vec![
            "127.0.0.1".parse().unwrap(),
            "192.168.20.100".parse().unwrap(),
            "fd00:20::100".parse().unwrap(),
            "fe80::1".parse().unwrap(),
        ])
    });
    vpn_controller::browser_router(
        AppState {
            link,
            hub,
            port: 18765,
            exposure: Arc::default(),
            data_dir: None,
            gateway_key: None,
            providers: vpn_controller::provider::Providers::new(),
        },
        GuardConfig::loopback(18765, &[]).with_lan(LanHosts::new(18765, addresses)),
    )
}

async fn send_lan(req: Request<Body>) -> (StatusCode, String) {
    let resp = lan_app().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn open_to_the_lan_this_hosts_own_addresses_are_its_hosts_and_origins() {
    // From the Mac on the LAN: the PC's address is the Host and the Origin.
    let (s, b) = send_lan(post(
        "192.168.20.100:18765",
        Some("http://192.168.20.100:18765"),
        Some("same-origin"),
    ))
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "passes the guard: {b}");
    let (s, _) = send_lan(post(
        "[fd00:20::100]:18765",
        Some("http://[fd00:20::100]:18765"),
        Some("same-origin"),
    ))
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    // Loopback keeps working.
    let (s, _) = send_lan(post(
        "127.0.0.1:18765",
        Some("http://127.0.0.1:18765"),
        Some("same-origin"),
    ))
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    // A page of another site cannot drive it, from wherever it is served.
    for origin in [
        "http://evil.example",
        "http://192.168.20.101:18765",
        "http://192.168.20.100:8080",
        "https://192.168.20.100:18765",
    ] {
        let (s, b) = send_lan(post("192.168.20.100:18765", Some(origin), None)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{origin}: {b}");
    }
    let (s, _) = send_lan(post(
        "192.168.20.100:18765",
        Some("http://192.168.20.100:18765"),
        Some("cross-site"),
    ))
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Hosts that are not this host's own addresses (or not reachable ones), names (DNS
    // rebinding), another port: refused.
    for host in [
        "192.168.20.101:18765",
        "192.168.20.100:18766",
        "pc.local:18765",
        "evil.example:18765",
        "[fe80::1]:18765",
        "0.0.0.0:18765",
    ] {
        let (s, b) = send_lan(post(host, Some(&format!("http://{host}")), None)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{host}: {b}");
    }
    // A loopback-only installation does not accept the LAN address at all.
    let (s, _) = send(post(
        "192.168.20.100:18765",
        Some("http://192.168.20.100:18765"),
        Some("same-origin"),
    ))
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}
