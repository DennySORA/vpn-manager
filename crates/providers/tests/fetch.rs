//! Downloading a user-supplied blocklist URL against the in-memory TLS fixture: the caller's
//! connector, family and port; certificate verification; same-origin redirects only; status,
//! encoding and size limits; one deadline.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

mod support;

use std::time::Duration;

use std::assert_matches;
use support::{Dial, Fixture, Reply, TestCa};
use vpn_domain::blocklist::parse_https_url;
use vpn_providers::fetch::{DownloadError, MAX_REDIRECTS, download};
use vpn_providers::{Family, HttpError, HttpsClient};

const HOST: &str = "lists.example.net";

fn client(
    handler: impl Fn(&support::Seen) -> Reply + Send + Sync + 'static,
) -> (Fixture, HttpsClient<Fixture>) {
    let ca = TestCa::new();
    let fixture = Fixture::new(ca.server_config(&[HOST, "cdn.example.org"]), handler);
    let client = HttpsClient::with_roots(fixture.clone(), ca.roots());
    (fixture, client)
}

fn text(status: u16, body: &str) -> Reply {
    Reply {
        status,
        headers: vec![("content-type".into(), "text/plain".into())],
        payload: support::Payload::Full(body.as_bytes().to_vec()),
    }
}

const LIMIT: usize = 8 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn the_list_comes_over_the_callers_connector_family_and_port() {
    let (fixture, client) = client(|_| text(200, "1.2.3.4\n10.0.0.0/8\n"));
    let url = parse_https_url("https://lists.example.net:8443/drop.txt?v=2").unwrap();
    let got = download(&client, &url, Family::V6, LIMIT, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(got.body, b"1.2.3.4\n10.0.0.0/8\n");
    assert_eq!(got.url, url);
    assert_eq!(
        fixture.dials(),
        vec![Dial {
            host: HOST.into(),
            port: 8443,
            family: Family::V6
        }]
    );
    let seen = &fixture.seen()[0];
    assert_eq!(seen.sni.as_deref(), Some(HOST));
    assert_eq!(seen.method, "GET");
    assert_eq!(seen.path, "/drop.txt");
    assert_eq!(seen.host(), "lists.example.net:8443");
    assert_eq!(
        seen.header("accept-encoding"),
        None,
        "nothing compressed is asked for"
    );
    assert!(seen.header("accept").unwrap().starts_with("text/plain"));
    assert_eq!(got.content_type.as_deref(), Some("text/plain"));
}

#[tokio::test]
async fn same_origin_redirects_are_followed_and_other_origins_refused() {
    let (fixture, client) = client(|seen| match seen.path.as_str() {
        "/old" => Reply::empty(301).with_header("location", "/v2/list.txt"),
        "/v2/list.txt" => text(200, "192.0.2.1\n"),
        "/elsewhere" => {
            Reply::empty(302).with_header("location", "https://cdn.example.org/list.txt")
        }
        "/loop" => Reply::empty(307).with_header("location", "/loop"),
        "/http" => Reply::empty(302).with_header("location", "http://lists.example.net/x"),
        _ => text(404, "missing"),
    });
    let url = |p: &str| parse_https_url(&format!("https://{HOST}{p}")).unwrap();
    let got = download(&client, &url("/old"), Family::V4, LIMIT, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(got.body, b"192.0.2.1\n");
    assert_eq!(got.url.path, "/v2/list.txt");

    match download(&client, &url("/elsewhere"), Family::V4, LIMIT, TIMEOUT).await {
        Err(DownloadError::CrossOrigin(to)) => assert_eq!(to, "https://cdn.example.org"),
        other => panic!("{other:?}"),
    }
    assert!(
        !fixture.dials().iter().any(|d| d.host == "cdn.example.org"),
        "never contacted"
    );
    let before = fixture.seen().len();
    assert_matches!(
        download(&client, &url("/loop"), Family::V4, LIMIT, TIMEOUT).await,
        Err(DownloadError::TooManyRedirects)
    );
    assert_eq!(fixture.seen().len() - before, MAX_REDIRECTS + 1);
    assert_matches!(
        download(&client, &url("/http"), Family::V4, LIMIT, TIMEOUT).await,
        Err(DownloadError::BadRedirect)
    );
    assert_matches!(
        download(&client, &url("/nope"), Family::V4, LIMIT, TIMEOUT).await,
        Err(DownloadError::Status(404))
    );
}

#[tokio::test]
async fn compressed_oversized_slow_and_untrusted_answers_fail() {
    let (_, gz) = client(|_| text(200, "x").with_header("content-encoding", "gzip"));
    let url = parse_https_url(&format!("https://{HOST}/list.txt")).unwrap();
    assert_matches!(download(&gz, &url, Family::V4, LIMIT, TIMEOUT).await,
        Err(DownloadError::Encoded(e)) if e == "gzip");

    let (_, big) = client(|_| Reply::chunked(200, vec![vec![b'1'; 600], vec![b'2'; 600]]));
    assert_matches!(
        download(&big, &url, Family::V4, 1000, TIMEOUT).await,
        Err(DownloadError::Http(HttpError::TooLarge { limit: 1000 }))
    );

    let (_, slow) = client(|_| Reply::stall());
    let started = std::time::Instant::now();
    assert_matches!(
        download(&slow, &url, Family::V4, LIMIT, Duration::from_millis(300)).await,
        Err(DownloadError::Http(HttpError::Timeout { .. }))
    );
    assert!(started.elapsed() < Duration::from_secs(3));

    // The product client trusts the web PKI only, not the fixture's CA.
    let ca = TestCa::new();
    let fixture = Fixture::new(ca.server_config(&[HOST]), |_| text(200, "1.1.1.1\n"));
    let public = HttpsClient::new(fixture.clone());
    assert_matches!(
        download(&public, &url, Family::V4, LIMIT, TIMEOUT).await,
        Err(DownloadError::Http(HttpError::Tls(_)))
    );
    assert!(fixture.seen().is_empty());
}
