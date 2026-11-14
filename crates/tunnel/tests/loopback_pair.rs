//! Two real tunnels (client + server) over loopback UDP with `GotaTun`'s real `WireGuard` crypto.
//! Covers the core data-plane contract: TCP (v4/v6) and UDP through the tunnel, and that a closed
//! gate refuses new payload flows and resets existing ones.
#![cfg(test)]

use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vpn_tunnel::{
    FlowClass, GateState, NetstackLimits, PeerConfig, PeerPolicy, TransportPlan, Tunnel,
    TunnelConfig, UdpSource, keys,
};
use zeroize::Zeroizing;

struct Pair {
    client: Tunnel,
    server: Tunnel,
}

async fn pair() -> Pair {
    pair_over(PathImpairment::default()).await
}

/// What the encrypted path between the two tunnels does to datagrams.
#[derive(Debug, Clone, Copy, Default)]
struct PathImpairment {
    /// Added delay in each direction.
    one_way: Duration,
    /// `WireGuard` data messages dropped per million, drawn independently per datagram. Handshake
    /// messages are never dropped: these tests are about TCP over the tunnel, and a pair has
    /// only a few seconds for its handshake.
    loss_ppm: u32,
}

/// `WireGuard` transport data message type (the first byte of every data datagram).
const WG_DATA: u8 = 4;

/// A UDP relay in front of the server's `WireGuard` socket that delays and drops datagrams; returns
/// the address the client uses as its endpoint.
async fn impaired_path(server: SocketAddr, impairment: PathImpairment) -> SocketAddr {
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::time::Instant;

    let front = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind the relay front"),
    );
    let back = Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind the relay back"),
    );
    let endpoint = front.local_addr().expect("relay front address");
    let client = Arc::new(vpn_sync::Mutex::new(None::<SocketAddr>));

    // One delay line per direction; datagrams beyond its capacity are dropped (a full queue).
    let line = |out: Arc<UdpSocket>, to: Box<dyn Fn() -> Option<SocketAddr> + Send>| {
        let (tx, mut rx) = mpsc::channel::<(Instant, Vec<u8>)>(16_384);
        tokio::spawn(async move {
            while let Some((at, datagram)) = rx.recv().await {
                tokio::time::sleep_until(at).await;
                if let Some(dst) = to()
                    && out.send_to(&datagram, dst).await.is_err()
                {
                    tracing::trace!("relay: a datagram it cannot send is lost, as on a real path");
                }
            }
        });
        tx
    };
    let to_server = line(back.clone(), Box::new(move || Some(server)));
    let to_client = {
        let client = client.clone();
        line(front.clone(), Box::new(move || *client.lock()))
    };
    let receive = |from: Arc<UdpSocket>,
                   line: mpsc::Sender<(Instant, Vec<u8>)>,
                   learn: Option<Arc<vpn_sync::Mutex<Option<SocketAddr>>>>| {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            while let Ok((n, src)) = from.recv_from(&mut buf).await {
                if let Some(learn) = &learn {
                    *learn.lock() = Some(src);
                }
                if n > 0
                    && buf[0] == WG_DATA
                    && impairment.loss_ppm > 0
                    && rand::random_range(0..1_000_000) < impairment.loss_ppm
                {
                    continue;
                }
                if line
                    .try_send((Instant::now() + impairment.one_way, buf[..n].to_vec()))
                    .is_err()
                {
                    tracing::trace!("relay: delay line full, datagram dropped");
                }
            }
        });
    };
    receive(front, to_server, Some(client));
    receive(back, to_client, None);
    endpoint
}

async fn pair_over(impairment: PathImpairment) -> Pair {
    let client_key = keys::generate_private();
    let server_key = keys::generate_private();
    let client_pub = keys::public_from_private(&client_key);
    let server_pub = keys::public_from_private(&server_key);

    let server_socket = StdUdpSocket::bind("127.0.0.1:0").expect("bind the server underlay");
    let server_addr = server_socket.local_addr().expect("server underlay address");
    let endpoint = if impairment.one_way.is_zero() && impairment.loss_ppm == 0 {
        server_addr
    } else {
        impaired_path(server_addr, impairment).await
    };

    let server = Tunnel::start(TunnelConfig {
        private_key: server_key,
        peer: PeerConfig {
            public_key: client_pub,
            preshared_key: None,
            endpoint: None,
            allowed_ips: vec![
                "10.99.0.2/32".parse().expect("network literal"),
                "fd99::2/128".parse().expect("network literal"),
            ],
            persistent_keepalive: None,
        },
        addresses: vec![
            "10.99.0.1/24".parse().expect("network literal"),
            "fd99::1/64".parse().expect("network literal"),
        ],
        mtu: 1420,
        underlay: UdpSource::Preopened(Arc::new(server_socket)),
        underlay_policy: PeerPolicy::AcceptAny,
        listen_port: server_addr.port(),
        limits: NetstackLimits::default(),
        transport: TransportPlan::default(),
    })
    .await
    .expect("server tunnel");

    let psk = Zeroizing::new([7u8; 32]);
    let client = Tunnel::start(TunnelConfig {
        private_key: client_key,
        peer: PeerConfig {
            public_key: server_pub,
            preshared_key: None,
            endpoint: Some(endpoint),
            allowed_ips: vec![
                "0.0.0.0/0".parse().expect("network literal"),
                "::/0".parse().expect("network literal"),
            ],
            persistent_keepalive: None,
        },
        addresses: vec![
            "10.99.0.2/32".parse().expect("network literal"),
            "fd99::2/128".parse().expect("network literal"),
        ],
        mtu: 1420,
        underlay: UdpSource::Bind(None),
        underlay_policy: PeerPolicy::Pinned(vec![endpoint]),
        listen_port: 0,
        limits: NetstackLimits::default(),
        transport: TransportPlan::default(),
    })
    .await
    .expect("client tunnel");
    drop(psk);

    assert_eq!(server.netstack().set_gate(GateState::Open), GateState::Open);
    assert_eq!(client.netstack().set_gate(GateState::Open), GateState::Open);
    client
        .handshake(Duration::from_secs(5))
        .await
        .expect("handshake");
    Pair { client, server }
}

fn spawn_tcp_echo(server: &Tunnel, port: u16) {
    let mut listener = server
        .netstack()
        .listen_tcp(port, 4, FlowClass::Payload)
        .expect("listen for the echo service");
    tokio::spawn(async move {
        loop {
            let Ok(mut stream) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                if stream.shutdown().await.is_err() {
                    tracing::trace!("echo: the connection ended before its shutdown");
                }
            });
        }
    });
}

async fn echo_roundtrip(pair: &Pair, dst: SocketAddr, size: usize) {
    let stream = pair
        .client
        .netstack()
        .connect_tcp(dst, FlowClass::Payload)
        .await
        .expect("connect through tunnel");
    let payload: Vec<u8> = (0..size)
        .map(|i| u8::try_from(i % 251).expect("below 251"))
        .collect();
    let (mut rd, mut wr) = tokio::io::split(stream);
    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&sent).await.expect("upload");
        wr.shutdown().await.expect("shut the upload down");
    });
    let mut received = Vec::with_capacity(size);
    tokio::time::timeout(Duration::from_secs(30), rd.read_to_end(&mut received))
        .await
        .expect("echo did not finish")
        .expect("read");
    writer.await.expect("writer task");
    assert_eq!(received.len(), payload.len());
    assert!(received == payload, "echoed bytes differ");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_ipv4_and_ipv6_echo_through_real_wireguard() {
    let pair = pair().await;
    spawn_tcp_echo(&pair.server, 7);
    echo_roundtrip(&pair, "10.99.0.1:7".parse().unwrap(), 4 * 1024 * 1024).await;
    echo_roundtrip(&pair, "[fd99::1]:7".parse().unwrap(), 256 * 1024).await;

    let peer = pair.client.peer().await.expect("peer");
    assert!(peer.last_handshake.is_some());
    assert!(peer.tx_bytes > 4 * 1024 * 1024, "WireGuard bytes counted");
    let underlay = pair.client.underlay_stats();
    assert_eq!(underlay.blocked_tx.load(Relaxed), 0);
}

/// `GotaTun` upgrade gate (docs/decisions/0001, "UDP recreate"): the underlay socket is closed and
/// opened again through the pinned factory and the sessions are dropped; traffic resumes after a
/// fresh handshake, and the new socket still answers only the pinned peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_underlay_is_opened_again_and_stays_pinned() {
    let pair = pair().await;
    spawn_tcp_echo(&pair.server, 7);
    echo_roundtrip(&pair, "10.99.0.1:7".parse().unwrap(), 64 * 1024).await;
    let sent_before = pair.client.underlay_stats().tx_datagrams.load(Relaxed);
    // Let the first session age, so a fresh handshake after the rebind is visible.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    pair.client.rebind_underlay().await.expect("rebind");
    echo_roundtrip(&pair, "10.99.0.1:7".parse().unwrap(), 256 * 1024).await;
    assert!(pair.client.underlay_stats().tx_datagrams.load(Relaxed) > sent_before);
    let age = pair
        .client
        .peer()
        .await
        .and_then(|p| p.last_handshake)
        .expect("a handshake after the rebind");
    assert!(
        age < Duration::from_millis(1500),
        "no fresh handshake: {age:?}"
    );

    // The server learned the client's underlay address again from the new handshake.
    let client_addr = pair
        .server
        .peer()
        .await
        .and_then(|p| p.endpoint)
        .expect("client endpoint");
    let stray = StdUdpSocket::bind("127.0.0.1:0").unwrap();
    let blocked = &pair.client.underlay_stats().blocked_rx;
    let before = blocked.load(Relaxed);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while blocked.load(Relaxed) == before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a stray datagram was not refused"
        );
        stray.send_to(&[0u8; 64], client_addr).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(pair.client.underlay_stats().blocked_tx.load(Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_destination_is_refused_when_tunnel_has_no_ipv6() {
    let key = keys::generate_private();
    let peer_key = keys::public_from_private(&keys::generate_private());
    let tunnel = Tunnel::start(TunnelConfig {
        private_key: key,
        peer: PeerConfig {
            public_key: peer_key,
            preshared_key: None,
            endpoint: Some("127.0.0.1:9".parse().unwrap()),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            persistent_keepalive: None,
        },
        addresses: vec!["10.99.0.2/32".parse().unwrap()],
        mtu: 1420,
        underlay: UdpSource::Bind(None),
        underlay_policy: PeerPolicy::Pinned(vec!["127.0.0.1:9".parse().unwrap()]),
        listen_port: 0,
        limits: NetstackLimits::default(),
        transport: TransportPlan::default(),
    })
    .await
    .unwrap();
    assert_eq!(tunnel.netstack().set_gate(GateState::Open), GateState::Open);
    let err = tunnel
        .netstack()
        .connect_tcp("[2001:db8::1]:443".parse().unwrap(), FlowClass::Payload)
        .await
        .expect_err("IPv6 must be denied, not routed elsewhere");
    assert_eq!(err.kind(), std::io::ErrorKind::NetworkUnreachable);
}
