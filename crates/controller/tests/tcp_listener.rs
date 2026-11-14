//! The loopback TCP listener serves only this user's programs: the owner of each client socket
//! is looked up once per connection, and anything but this user is closed unserved.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vpn_controller::tcp_listener::{PeerLookup, SameUserTcpListener, os_lookup};
use vpn_platform::peer::PeerOwner;
use vpn_platform::process::current_uid;

async fn serve(lookup: PeerLookup) -> SocketAddr {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let listener = SameUserTcpListener::new(tcp, current_uid(), lookup).unwrap();
    let app = Router::new().route("/", get(|| async { "served" }));
    tokio::spawn(async move { axum::serve(listener, app).await });
    addr
}

/// Two requests on one connection (keep-alive); everything that came back.
async fn two_requests(addr: SocketAddr) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    // Refused connections are closed unread, so the write itself may already fail.
    let _ = s
        .write_all(
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n\
              GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

fn counting(inner: PeerLookup, calls: Arc<AtomicUsize>) -> PeerLookup {
    Arc::new(move |local, peer| {
        calls.fetch_add(1, Ordering::SeqCst);
        inner(local, peer)
    })
}

#[tokio::test]
async fn this_users_client_is_served_and_looked_up_once_per_connection() {
    let calls = Arc::new(AtomicUsize::new(0));
    let addr = serve(counting(os_lookup(), calls.clone())).await;
    let answer = two_requests(addr).await;
    assert_eq!(answer.matches("HTTP/1.1 200 OK").count(), 2, "{answer}");
    assert_eq!(answer.matches("served").count(), 2, "{answer}");
    // Keep-alive reuses the decision made when the connection was accepted.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_client_whose_owner_cannot_be_found_is_closed_unserved() {
    let calls = Arc::new(AtomicUsize::new(0));
    let lookup: PeerLookup = Arc::new(|_, _| Ok(None));
    let addr = serve(counting(lookup, calls.clone())).await;
    let answer = two_requests(addr).await;
    assert!(answer.is_empty(), "{answer}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn another_users_client_is_closed_unserved() {
    let other = current_uid().wrapping_add(1);
    let lookup: PeerLookup = Arc::new(move |_, _| {
        Ok(Some(PeerOwner {
            uid: other,
            pid: Some(4242),
        }))
    });
    let addr = serve(lookup).await;
    assert_eq!(two_requests(addr).await, "");
}

#[tokio::test]
async fn a_failed_lookup_fails_closed() {
    let lookup: PeerLookup = Arc::new(|_, _| Err(io::Error::other("socket table unreadable")));
    let addr = serve(lookup).await;
    assert_eq!(two_requests(addr).await, "");
}

#[tokio::test]
async fn the_lookup_sees_the_connection_as_the_server_accepted_it() {
    // What the listener asks about: our address, and the client's.
    let seen = Arc::new(std::sync::Mutex::new(None));
    let record = seen.clone();
    let lookup: PeerLookup = Arc::new(move |local, peer| {
        *record.lock().unwrap() = Some((local, peer));
        vpn_platform::peer::tcp_peer_owner(local, peer)
    });
    let addr = serve(lookup).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let client = s.local_addr().unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200 OK"));
    assert_eq!(*seen.lock().unwrap(), Some((addr, client)));
}

/// A host that takes every non-loopback client for another host, and finds no owner for any
/// socket (a loopback client is then refused, whatever the allow list says).
struct EveryoneElsewhere;

impl vpn_platform::admission::HostView for EveryoneElsewhere {
    fn owner(&self, _local: SocketAddr, _peer: SocketAddr) -> io::Result<Option<PeerOwner>> {
        Ok(None)
    }

    fn is_own_address(&self, _ip: std::net::IpAddr) -> io::Result<bool> {
        Ok(false)
    }
}

/// Whether a plain listener on 0.0.0.0 answers at `ip` (nothing in between holds it).
async fn reachable_at(ip: std::net::IpAddr) -> bool {
    let plain = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = plain.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = plain.accept().await {
            let _ = s.write_all(b"x").await;
        }
    });
    let reached = tokio::time::timeout(Duration::from_secs(3), async {
        let mut s = TcpStream::connect((ip, port)).await.ok()?;
        let mut b = [0u8; 1];
        s.read_exact(&mut b).await.ok()
    })
    .await;
    matches!(reached, Ok(Some(_)))
}

/// Serve on 0.0.0.0 for other hosts of `allow`; the port.
async fn serve_lan(allow: &[&str]) -> u16 {
    let tcp = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let listener = SameUserTcpListener::with_policy(
        vec![tcp],
        vpn_platform::admission::ClientPolicy {
            uid: current_uid(),
            allow: allow.iter().map(|n| n.parse().unwrap()).collect(),
        },
        Arc::new(EveryoneElsewhere),
    )
    .unwrap();
    let app = Router::new().route("/", get(|| async { "served" }));
    tokio::spawn(async move { axum::serve(listener, app).await });
    port
}

#[tokio::test]
async fn other_hosts_are_served_only_from_the_allowed_networks() {
    // A client arriving from a non-loopback address of this machine stands in for another host.
    let Some(lan) = vpn_platform::netif::reachable_addresses()
        .unwrap()
        .into_iter()
        .find(std::net::IpAddr::is_ipv4)
    else {
        eprintln!("skipped: this host has no non-loopback IPv4 address");
        return;
    };
    if !reachable_at(lan).await {
        // macOS: the application firewall holds connections to unsigned programs.
        eprintln!("skipped: a listener on 0.0.0.0 is not reachable at {lan} (firewall)");
        return;
    }
    let mine = format!("{lan}/32");
    // Listed: served.
    let port = serve_lan(&[&mine]).await;
    let answer = two_requests(SocketAddr::new(lan, port)).await;
    assert_eq!(answer.matches("served").count(), 2, "{answer}");
    // Not listed, or no list at all: closed before anything is read.
    for allow in [&["203.0.113.0/24"][..], &[]] {
        let port = serve_lan(allow).await;
        assert!(
            two_requests(SocketAddr::new(lan, port)).await.is_empty(),
            "{allow:?}"
        );
    }
    // Loopback is this host: its client must be this user's, list or not.
    let port = serve_lan(&[&mine]).await;
    assert_eq!(
        two_requests(SocketAddr::from(([127, 0, 0, 1], port))).await,
        ""
    );
}
