//! Port forwards through a real `WireGuard` tunnel: the lab peer connects in to the client's
//! tunnel address (from its own address, or from a stand-in for a host on the Internet), the
//! client's Port Controller admits the connection and relays it to an "App" listening on
//! loopback. Leases, the gate, the inbound guard (blocklists, auto-ban), the limits and the
//! PROXY protocol header are exercised on that real path. UDP straight into a sandbox needs the
//! strict plane (`crates/vpnd/tests/strict.rs`); here, without one, it is never relayed instead.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use std::assert_matches;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use vpn_domain::ipset::IpRangeSet;
use vpn_domain::{AutoBanSettings, ForwardBindingId, ForwardProtocol};
use vpn_instance::forward::PortController;
use vpn_instance::inbound::InboundGuard;
use vpn_instance::policy::{Enforcement, Overlay};
use vpn_ipc::worker::{BanReport, ForwardLeaseWire, ForwardSpecWire, ForwardStatusWire};
use vpn_labpeer::{INTERNET_V4, LabPeer, SERVER_V4};
use vpn_tunnel::{
    FlowClass, GateState, Netstack, NetstackLimits, PeerConfig, PeerPolicy, TcpStream,
    TransportPlan, Tunnel, TunnelConfig, UdpSource,
};

const CLIENT: &str = "10.99.0.2";

struct Lab {
    peer: LabPeer,
    client: Tunnel,
    /// The peer's netstack: the "remote" side that connects in.
    remote: Netstack,
    forwards: PortController<Netstack>,
    guard: Arc<InboundGuard>,
    bans: mpsc::Receiver<BanReport>,
}

async fn lab(auto_ban: AutoBanSettings, deny: &[&str]) -> Lab {
    let peer = LabPeer::start("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap();
    let conf = peer.clients[0].wg_quick_config(&peer);
    let (parsed, _) = vpn_domain::wgconf::parse(&conf).unwrap();
    let p = parsed.public;
    let addresses = p.addresses.clone();
    let client = Tunnel::start(TunnelConfig {
        private_key: parsed.private_key,
        peer: PeerConfig {
            public_key: p.peer_public_key.0,
            preshared_key: parsed.preshared_key,
            endpoint: Some(p.endpoint),
            allowed_ips: p.allowed_ips,
            persistent_keepalive: p.persistent_keepalive,
        },
        addresses: addresses.clone(),
        mtu: p.mtu.unwrap_or(1420),
        underlay: UdpSource::Bind(None),
        underlay_policy: PeerPolicy::Pinned(vec![p.endpoint]),
        listen_port: 0,
        limits: NetstackLimits::default(),
        transport: TransportPlan::default(),
    })
    .await
    .unwrap();
    let _ = client.netstack().set_gate(GateState::Open);
    client.handshake(Duration::from_secs(5)).await.unwrap();
    let overlay = Overlay::new(
        1,
        IpRangeSet::from_networks(deny.iter().map(|n| n.parse().unwrap())),
    );
    let max = auto_ban.max_bans as usize;
    let (guard, bans) = InboundGuard::new(
        Arc::new(Enforcement::new(overlay, max)),
        auto_ban,
        Vec::new(),
    );
    let forwards = PortController::new(
        client.netstack(),
        guard.clone(),
        addresses,
        Duration::from_secs(600),
    );
    let remote = peer.netstack().unwrap();
    Lab {
        peer,
        client,
        remote,
        forwards,
        guard,
        bans,
    }
}

impl Lab {
    async fn stop(self) {
        drop(self.forwards);
        self.client.shutdown().await;
        self.peer.shutdown().await;
    }

    fn status(&self, id: ForwardBindingId) -> ForwardStatusWire {
        self.forwards
            .status()
            .into_iter()
            .find(|s| s.id == Some(id))
            .unwrap()
    }

    /// Connect from `from` (the peer's own address or the Internet stand-in) to the client's
    /// tunnel address.
    async fn dial(&self, from: IpAddr, port: u16) -> io::Result<TcpStream> {
        self.remote
            .connect_tcp_from(
                from,
                SocketAddr::new(CLIENT.parse().unwrap(), port),
                FlowClass::Payload,
            )
            .await
    }

    /// Send a datagram from `from` and wait for its echo.
    async fn udp_echo(&self, from: IpAddr, port: u16, data: &[u8]) -> Option<Vec<u8>> {
        let socket = if from == IpAddr::V4(SERVER_V4) {
            self.remote.bind_udp(FlowClass::Payload).unwrap()
        } else {
            self.remote.bind_udp_from(from, FlowClass::Payload).unwrap()
        };
        let dst = SocketAddr::new(CLIENT.parse().unwrap(), port);
        socket.send_to(data, dst).await.unwrap();
        let mut buf = [0u8; 1500];
        match tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                assert_eq!(src, dst, "the answer comes from the forwarded port");
                Some(buf[..n].to_vec())
            }
            _ => None,
        }
    }
}

const fn lab_ip() -> IpAddr {
    IpAddr::V4(SERVER_V4)
}

const fn internet() -> IpAddr {
    IpAddr::V4(INTERNET_V4)
}

fn spec(port: u16, protocol: ForwardProtocol, max_connections: u32) -> ForwardSpecWire {
    ForwardSpecWire {
        id: ForwardBindingId::new(),
        protocol,
        tunnel_port: port,
        max_connections,
        proxy_protocol: false,
        udp_direct: false,
    }
}

/// The "App": TCP and UDP echo on loopback.
struct App {
    tcp: SocketAddr,
    udp: SocketAddr,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl App {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = listener.local_addr().unwrap();
        let t = tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp = socket.local_addr().unwrap();
        let u = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&buf[..n], from).await;
            }
        });
        Self {
            tcp,
            udp,
            tasks: vec![t, u],
        }
    }

    /// The App exits: nothing listens on its ports any more.
    fn exit(self) {
        for t in self.tasks {
            t.abort();
        }
    }
}

fn lease(binding: &ForwardSpecWire, id: u64, app: &App) -> ForwardLeaseWire {
    lease_to(binding, id, app.tcp, app.udp)
}

fn lease_to(
    binding: &ForwardSpecWire,
    id: u64,
    tcp: SocketAddr,
    udp: SocketAddr,
) -> ForwardLeaseWire {
    ForwardLeaseWire {
        binding: binding.id,
        lease_id: id,
        tcp: binding.protocol.tcp().then_some(tcp),
        udp: binding.protocol.udp().then_some(udp),
    }
}

async fn round_trip(s: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    s.write_all(data).await?;
    let mut got = vec![0u8; data.len()];
    tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut got))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no echo"))??;
    assert_eq!(got, data);
    Ok(())
}

/// The connection is refused or reset (by the forward) instead of reaching the App.
async fn refused(lab: &Lab, from: IpAddr, port: u16) -> bool {
    match lab.dial(from, port).await {
        Err(_) => true,
        Ok(mut s) => round_trip(&mut s, b"x").await.is_err(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_lease_closes_its_connections_and_a_new_one_serves_again() {
    let mut lab = lab(AutoBanSettings::default(), &[]).await;
    let app = App::start().await;
    let f = spec(40_001, ForwardProtocol::Both, 16);
    lab.forwards.set(vec![f.clone()]);
    lab.forwards.grant(&lease(&f, 1, &app));
    let mut open = lab.dial(internet(), 40_001).await.unwrap();
    round_trip(&mut open, b"before").await.unwrap();

    // A revocation naming another lease changes nothing.
    lab.forwards.revoke(f.id, 2);
    round_trip(&mut open, b"still").await.unwrap();

    lab.forwards.revoke(f.id, 1);
    let mut rest = Vec::new();
    let end = tokio::time::timeout(Duration::from_secs(3), open.read_to_end(&mut rest))
        .await
        .expect("the forwarded connection ends at once");
    assert!(end.is_err(), "reset, not a clean end: {end:?}");
    assert!(
        refused(&lab, internet(), 40_001).await,
        "no listener without a lease"
    );
    assert_eq!(lab.udp_echo(internet(), 40_001, b"u").await, None);
    let s = lab.status(f.id);
    assert_eq!(
        (s.lease_id, s.tcp_listening, s.udp_listening),
        (None, false, false)
    );

    // A new lease serves again; replacing it with another ends the first one's connections.
    lab.forwards.grant(&lease(&f, 3, &app));
    let mut second = lab.dial(internet(), 40_001).await.unwrap();
    round_trip(&mut second, b"again").await.unwrap();
    lab.forwards.grant(&lease(&f, 4, &app));
    let end = tokio::time::timeout(Duration::from_secs(3), second.read_to_end(&mut rest)).await;
    assert_matches!(end, Ok(Err(_)));
    let mut third = lab.dial(internet(), 40_001).await.unwrap();
    round_trip(&mut third, b"third").await.unwrap();
    assert_eq!(lab.status(f.id).lease_id, Some(4));
    app.exit();
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tightened_gate_refuses_new_connections_and_keeps_open_ones() {
    let mut lab = lab(AutoBanSettings::default(), &[]).await;
    let app = App::start().await;
    let f = spec(40_002, ForwardProtocol::Tcp, 16);
    lab.forwards.set(vec![f.clone()]);
    lab.forwards.grant(&lease(&f, 1, &app));
    let mut open = lab.dial(lab_ip(), 40_002).await.unwrap();
    round_trip(&mut open, b"open").await.unwrap();

    let _ = lab.client.netstack().set_gate(GateState::Probe);
    lab.forwards.reconcile();
    assert!(!lab.status(f.id).tcp_listening);
    assert!(refused(&lab, lab_ip(), 40_002).await);
    round_trip(&mut open, b"kept").await.unwrap();

    let _ = lab.client.netstack().set_gate(GateState::Open);
    lab.forwards.reconcile();
    assert!(lab.status(f.id).tcp_listening);
    let mut again = lab.dial(lab_ip(), 40_002).await.unwrap();
    round_trip(&mut again, b"open again").await.unwrap();
    app.exit();
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_ban_through_the_inbound_path_bans_refuses_and_lifts() {
    let settings = AutoBanSettings {
        enabled: true,
        window_secs: 30,
        threshold: 3,
        ban_secs: 600,
        max_bans: 100,
    };
    let mut lab = lab(settings, &[]).await;
    let app = App::start().await;
    let f = spec(40_003, ForwardProtocol::Tcp, 64);
    lab.forwards.set(vec![f.clone()]);
    lab.forwards.grant(&lease(&f, 1, &app));

    let mut kept = Vec::new();
    for i in 0..3 {
        let mut s = lab.dial(internet(), 40_003).await.unwrap();
        round_trip(&mut s, format!("conn {i}").as_bytes())
            .await
            .unwrap();
        kept.push(s);
    }
    // The fourth new connection within the window crosses the threshold: refused and banned.
    assert!(refused(&lab, internet(), 40_003).await);
    let report = tokio::time::timeout(Duration::from_secs(2), lab.bans.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.source, internet());
    assert_eq!(report.ban_secs, 600);
    assert!(refused(&lab, internet(), 40_003).await, "banned");
    // Another source is not affected.
    let mut other = lab.dial(lab_ip(), 40_003).await.unwrap();
    round_trip(&mut other, b"other source").await.unwrap();
    let s = lab.status(f.id);
    assert!(s.refused_banned >= 2, "{s:?}");
    assert_eq!(s.accepted, 4);

    // Lifting the ban admits the source again (with a fresh count).
    assert!(lab.guard.unban(internet()));
    let mut back = lab.dial(internet(), 40_003).await.unwrap();
    round_trip(&mut back, b"welcome back").await.unwrap();
    drop((kept, other, back));
    app.exit();
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocklisted_sources_never_reach_the_app() {
    let mut lab = lab(AutoBanSettings::default(), &["192.88.99.0/24"]).await;
    let app = App::start().await;
    let f = spec(40_004, ForwardProtocol::Both, 16);
    lab.forwards.set(vec![f.clone()]);
    lab.forwards.grant(&lease(&f, 1, &app));
    assert!(refused(&lab, internet(), 40_004).await);
    assert_eq!(lab.udp_echo(internet(), 40_004, b"u").await, None);
    let mut ok = lab.dial(lab_ip(), 40_004).await.unwrap();
    round_trip(&mut ok, b"not listed").await.unwrap();
    let s = lab.status(f.id);
    assert_eq!(s.refused_blocklisted, 2, "{s:?}");
    // Arrival from outside is still evidence that the forward is reachable.
    assert!(s.external_tcp_ms_ago.is_some() && s.external_udp_ms_ago.is_some());
    assert_eq!(s.accepted, 1);
    app.exit();
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_loopback_targets_of_the_forwards_protocols_are_accepted() {
    let mut lab = lab(AutoBanSettings::default(), &[]).await;
    let app = App::start().await;
    let f = spec(40_006, ForwardProtocol::Both, 16);
    lab.forwards.set(vec![f.clone()]);
    for bad in [
        ForwardLeaseWire {
            tcp: Some("10.99.0.1:8080".parse().unwrap()),
            ..lease(&f, 1, &app)
        },
        ForwardLeaseWire {
            udp: None,
            ..lease(&f, 2, &app)
        },
        ForwardLeaseWire {
            tcp: Some("127.0.0.1:22".parse().unwrap()),
            ..lease(&f, 3, &app)
        },
    ] {
        lab.forwards.grant(&bad);
        let s = lab.status(f.id);
        assert_eq!(s.lease_id, None);
        assert!(s.error.is_some());
        assert!(refused(&lab, lab_ip(), 40_006).await);
    }
    app.exit();
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_meant_for_a_sandbox_is_never_relayed_on_a_plane_without_one() {
    let mut lab = lab(AutoBanSettings::default(), &[]).await;
    let app = App::start().await;
    let f = ForwardSpecWire {
        udp_direct: true,
        ..spec(40_020, ForwardProtocol::Both, 16)
    };
    lab.forwards.set(vec![f.clone()]);
    // The manager names no UDP address for it: the worker connects nothing there.
    let wire = ForwardLeaseWire {
        udp: None,
        ..lease(&f, 1, &app)
    };
    lab.forwards.grant(&wire);
    let s = lab.status(f.id);
    assert_eq!(s.lease_id, Some(1), "the TCP side is leased");
    assert!(s.tcp_listening && !s.udp_listening, "{s:?}");
    assert!(
        s.error
            .as_ref()
            .is_some_and(|e| e.zh_tw.contains("嚴格隔離")),
        "{s:?}"
    );
    // TCP is relayed as ever...
    let mut conn = lab.dial(internet(), 40_020).await.unwrap();
    round_trip(&mut conn, b"tcp as ever").await.unwrap();
    // ...UDP reaches nobody: the port is not even reserved for it, and the App's loopback UDP
    // socket never hears of it.
    assert_eq!(lab.udp_echo(internet(), 40_020, b"udp").await, None);
    let s = lab.status(f.id);
    assert_eq!((s.udp_active, s.bytes_in), (0, b"tcp as ever".len() as u64));
    // A lease that names a UDP address for it is not this forward's: refused.
    lab.forwards.grant(&lease(&f, 2, &app));
    let s = lab.status(f.id);
    assert_eq!(s.lease_id, None);
    assert!(s.error.is_some());
    // The forward holds the TCP port only: the UDP port is free (the App's to take, in a
    // sandbox), the TCP one is not.
    let net = lab.client.netstack();
    assert!(net.reserve_inbound(40_020, false, true).is_ok());
    assert!(net.reserve_inbound(40_020, true, false).is_err());
    drop(conn);
    app.exit();
    lab.stop().await;
}
