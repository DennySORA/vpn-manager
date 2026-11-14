//! `api.sock`: the API for non-browser clients. Only peers of this user are served (no browser
//! guard applies there); a stale socket file of ours is replaced, a live one or anything that is
//! not our socket is never touched.

#![cfg(test)]

use std::path::Path;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use vpn_controller::api_socket::{ApiSocket, SameUserListener};
use vpn_controller::hub::Hub;
use vpn_controller::link::ManagerLink;
use vpn_controller::routes::AppState;

fn router() -> axum::Router {
    let hub = Hub::new();
    // No manager: a request that reaches a handler gets 503 (not the browser guard's 403).
    let link = ManagerLink::new("/nonexistent/manager.sock".into(), hub.clone());
    vpn_controller::routes::api(AppState {
        link,
        hub,
        port: 18765,
        exposure: Arc::default(),
        data_dir: None,
        gateway_key: None,
        providers: vpn_controller::provider::Providers::new(),
    })
}

/// One HTTP/1.1 request over the socket: `Some((status, body))`, or `None` when the server
/// closed the connection without answering.
async fn request(path: &Path, req: Request<Full<Bytes>>) -> Option<(u16, String)> {
    let stream = UnixStream::connect(path).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .ok()?;
    tokio::spawn(conn);
    let resp = sender.send_request(req).await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.ok()?.to_bytes();
    Some((status, String::from_utf8_lossy(&body).into_owned()))
}

fn get(uri: &str) -> Request<Full<Bytes>> {
    Request::get(uri)
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

#[tokio::test]
async fn same_user_peers_are_served_without_the_browser_guard() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    let sock = ApiSocket::bind(&path).await.unwrap();
    let mode =
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&path).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o600);
    let listener = SameUserListener::new(sock.listener, vpn_platform::process::current_uid());
    tokio::spawn(async move { axum::serve(listener, router()).await });

    assert_eq!(
        request(&path, get("/healthz")).await,
        Some((200, "ok".into()))
    );
    // A mutation without Origin or Fetch-Metadata reaches its handler (manager down: 503).
    let post = Request::post("/v1/dns-profiles")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("idempotency-key", "0b8a2d7e-6a4c-4c8e-9b1a-2f3c4d5e6f70")
        .body(Full::new(Bytes::from_static(
            br#"{"name":"x","servers":[{"transport":"udp","address":"9.9.9.9:53"}]}"#,
        )))
        .unwrap();
    let (status, body) = request(&path, post).await.unwrap();
    assert_eq!(status, 503, "{body}");
    // Same body limit as HTTP.
    let big = Request::post("/v1/dns-profiles")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("idempotency-key", "0b8a2d7e-6a4c-4c8e-9b1a-2f3c4d5e6f71")
        .body(Full::new(Bytes::from(vec![b' '; 300 * 1024])))
        .unwrap();
    let (status, _) = request(&path, big).await.unwrap();
    assert_eq!(status, 413);
}

#[tokio::test]
async fn peers_of_another_user_are_closed_unanswered() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    let sock = ApiSocket::bind(&path).await.unwrap();
    // The listener serves only a user we are not: our own connection must be refused.
    let other = vpn_platform::process::current_uid() + 1;
    let listener = SameUserListener::new(sock.listener, other);
    tokio::spawn(async move { axum::serve(listener, router()).await });
    assert_eq!(request(&path, get("/healthz")).await, None);
}

#[tokio::test]
async fn a_stale_socket_is_replaced_but_a_live_one_or_a_file_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    // Left behind by a controller that did not exit cleanly.
    drop(tokio::net::UnixListener::bind(&path).unwrap());
    assert!(path.exists());
    let sock = ApiSocket::bind(&path).await.unwrap();
    // A second controller must not take over the live one.
    let err = ApiSocket::bind(&path).await.err().unwrap();
    assert!(err.to_string().contains("already serves"), "{err}");
    // Removal only takes our own file.
    let inode = sock.inode();
    drop(sock);
    ApiSocket::remove(&path, inode);
    assert!(!path.exists());

    // Not a socket: never removed.
    std::fs::write(&path, b"not a socket").unwrap();
    assert!(ApiSocket::bind(&path).await.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
    ApiSocket::remove(&path, inode);
    assert!(path.exists(), "another inode is left alone");
}
