//! The HTTPS transport against an in-memory TLS fixture: certificate and name verification,
//! SNI/ALPN, the caller's connector and family, redirects, body limits, the deadline, and
//! redacted `Debug`.

#![cfg(test)]

mod support;

use std::io;

use http::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use http::{Method, StatusCode};
use std::assert_matches;
use support::{Dial, Fixture, HOSTS, Reply, TestCa, setup};
use vpn_providers::https::{Request, Response};
use vpn_providers::{Family, HttpError, HttpsClient};
use zeroize::Zeroizing;

const HOST: &str = "api.mullvad.net";

fn get(path: &str) -> Request {
    Request::new(Method::GET, HOST, path, Family::V4)
}

#[tokio::test]
async fn one_http11_request_goes_over_the_callers_connector_and_family() {
    let s = setup(|_| Reply::json(200, r#"{"ok":true}"#));
    let request = Request::new(Method::GET, HOST, "/accounts/v1/accounts/me", Family::V6);
    let response = s.client.send(request).await.unwrap();
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(&response.body[..], br#"{"ok":true}"#);

    assert_eq!(
        s.fixture.dials(),
        vec![Dial {
            host: HOST.into(),
            port: 443,
            family: Family::V6
        }]
    );
    let seen = s.fixture.seen();
    assert_eq!(seen.len(), 1);
    let seen = &seen[0];
    assert_eq!(seen.sni.as_deref(), Some(HOST), "SNI is the request host");
    assert_eq!(
        seen.alpn.as_deref(),
        Some(&b"http/1.1"[..]),
        "h2 is offered by the server but never by us"
    );
    assert_eq!(seen.method, "GET");
    assert_eq!(seen.path, "/accounts/v1/accounts/me");
    assert_eq!(seen.host(), HOST);
    assert_eq!(seen.header("connection"), Some("close"));
    assert_eq!(seen.header("accept"), Some("application/json"));
    assert_eq!(seen.header("authorization"), None);
}

#[tokio::test]
async fn an_untrusted_certificate_is_refused() {
    let s = setup(|_| Reply::json(200, "{}"));
    // The product constructor trusts the web PKI only, not the fixture's throwaway CA.
    let public = HttpsClient::new(s.fixture.clone());
    let e = public.send(get("/")).await.unwrap_err();
    assert_matches!(e, HttpError::Tls(rustls::Error::InvalidCertificate(_)));
    assert!(!e.maybe_delivered());
    assert!(
        s.fixture.seen().is_empty(),
        "no request after a failed handshake"
    );
}

#[tokio::test]
async fn a_certificate_for_another_name_is_refused() {
    let ca = TestCa::new();
    let fixture = Fixture::new(ca.server_config(&["api.mullvad.net"]), |_| {
        Reply::json(200, "{}")
    });
    let client = HttpsClient::with_roots(fixture.clone(), ca.roots());
    let request = Request::new(Method::GET, "ipv4.ipleak.net", "/json/", Family::V4);
    let e = client.send(request).await.unwrap_err();
    assert_matches!(e, HttpError::Tls(rustls::Error::InvalidCertificate(_)));
    assert!(fixture.seen().is_empty());
}

#[tokio::test]
async fn redirects_are_refused_not_followed() {
    let s = setup(|_| Reply::empty(302).with_header("location", "https://elsewhere.example/"));
    let e = s.client.send(get("/")).await.unwrap_err();
    assert_matches!(e, HttpError::Redirect(302));
    assert_eq!(s.fixture.seen().len(), 1);
    assert_eq!(s.fixture.dials().len(), 1, "the Location is never dialled");
}

#[tokio::test]
async fn a_connector_refusal_sends_nothing() {
    let ca = TestCa::new();
    let fixture = Fixture::new(ca.server_config(HOSTS), |_| Reply::json(200, "{}"))
        .refusing(io::ErrorKind::PermissionDenied);
    let client = HttpsClient::with_roots(fixture.clone(), ca.roots());
    let e = client.send(get("/")).await.unwrap_err();
    assert_matches!(&e, HttpError::Connect(io) if io.kind() == io::ErrorKind::PermissionDenied);
    assert!(!e.maybe_delivered());
    assert!(fixture.seen().is_empty());
}

#[tokio::test]
async fn hosts_must_be_names_and_paths_origin_form() {
    let s = setup(|_| Reply::json(200, "{}"));
    for request in [
        Request::new(Method::GET, "192.0.2.1", "/", Family::V4),
        Request::new(Method::GET, HOST, "https://elsewhere.example/", Family::V4),
    ] {
        let e = s.client.send(request).await.unwrap_err();
        assert_matches!(e, HttpError::InvalidRequest);
    }
    assert!(s.fixture.dials().is_empty(), "refused before dialling");
}

#[test]
fn debug_output_never_shows_bodies_or_credentials() {
    let mut bearer = HeaderValue::from_static("Bearer mva_secret_token_value");
    bearer.set_sensitive(true);
    let request = Request::new(Method::POST, HOST, "/auth/v1/token", Family::V4)
        .json(Zeroizing::new(
            br#"{"account_number":"1234567812345678"}"#.to_vec(),
        ))
        .header(AUTHORIZATION, bearer);
    let response = Response {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
        body: Zeroizing::new(br#"{"access_token":"mva_secret_token_value"}"#.to_vec()),
    };
    for printed in [format!("{request:?}"), format!("{response:?}")] {
        assert!(!printed.contains("1234567812345678"), "{printed}");
        assert!(!printed.contains("mva_secret_token_value"), "{printed}");
    }
}
