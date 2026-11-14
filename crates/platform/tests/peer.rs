//! The owner of a loopback TCP connection, found in the OS socket tables (macOS: libproc over
//! this user's processes; Linux: /proc/net/tcp{,6}).

#![cfg(any(target_os = "macos", target_os = "linux"))]
#![expect(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

use std::net::{SocketAddr, TcpListener, TcpStream};

use vpn_platform::peer::tcp_peer_owner;
use vpn_platform::process::current_uid;

/// A connected pair on `bind`: (server address, client address, the streams kept open).
fn connected(bind: &str) -> Option<(SocketAddr, SocketAddr, TcpStream, TcpStream)> {
    let listener = TcpListener::bind(bind).ok()?;
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, peer) = listener.accept().unwrap();
    assert_eq!(peer, client.local_addr().unwrap());
    Some((server.local_addr().unwrap(), peer, server, client))
}

#[test]
fn a_loopback_connection_of_this_user_is_found_with_its_owner() {
    let (local, peer, _server, _client) = connected("127.0.0.1:0").unwrap();
    let owner = tcp_peer_owner(local, peer).unwrap().expect("found");
    assert_eq!(owner.uid, current_uid());
    #[cfg(target_os = "macos")]
    assert_eq!(owner.pid, Some(std::process::id()));
}

#[test]
fn an_ipv6_loopback_connection_is_found_too() {
    // Hosts without IPv6 loopback have nothing to test here.
    let Some((local, peer, _server, _client)) = connected("[::1]:0") else {
        return;
    };
    let owner = tcp_peer_owner(local, peer).unwrap().expect("found");
    assert_eq!(owner.uid, current_uid());
}

#[test]
fn a_connection_that_does_not_exist_is_not_found() {
    let (local, _peer, _server, _client) = connected("127.0.0.1:0").unwrap();
    // A port nobody connects from (bound for a moment, then released).
    let unused = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    assert_eq!(tcp_peer_owner(local, unused).unwrap(), None);
    // Nor is a client that is connected to another server.
    let (other, client, _s, _c) = connected("127.0.0.1:0").unwrap();
    assert_ne!(other, local);
    assert_eq!(tcp_peer_owner(local, client).unwrap(), None);
}
