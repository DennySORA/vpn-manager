//! The private management connector: one JSON request line (version 2: a single-use nonce and
//! the route it is meant for), the exact address family, the destination policy and the payload
//! gate, then a byte relay.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap/expect in #[test] fns, not in the helper fns of a tests/ crate"
)]

use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixStream};
use vpn_domain::InstanceId;
use vpn_instance::connector_socket::{ConnectorSocket, NetworkEpoch};
use vpn_instance::dns::{Family, Resolve, ResolveError};
use vpn_instance::policy::DestinationPolicy;
use vpn_instance::testsupport::LoopbackConnector;
use vpn_ipc::relay::{RelayAnswer, RelayFamily, RelayLine, RelayRoute};

/// `api.test` has only an IPv4 address (loopback, where the test origin listens).
#[derive(Clone)]
struct OnlyV4;

impl Resolve for OnlyV4 {
    fn resolve(
        &self,
        host: &str,
        family: Family,
    ) -> impl Future<Output = Result<Vec<IpAddr>, ResolveError>> + Send {
        std::future::ready(match (host, family) {
            ("api.test", Family::V4 | Family::Any) => Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            _ => Err(ResolveError::NotFound),
        })
    }
}

async fn send(path: &std::path::Path, line: &[u8]) -> (RelayAnswer, UnixStream) {
    let mut s = UnixStream::connect(path).await.unwrap();
    s.write_all(line).await.unwrap();
    let mut reader = BufReader::new(s);
    let mut reply = String::new();
    reader.read_line(&mut reply).await.unwrap();
    (
        serde_json::from_str(reply.trim_end()).unwrap(),
        reader.into_inner(),
    )
}

async fn request(path: &std::path::Path, line: &RelayLine) -> (RelayAnswer, UnixStream) {
    send(path, &line.to_bytes()).await
}

fn code(a: &RelayAnswer) -> &str {
    a.code.as_deref().unwrap_or("")
}

/// A loopback origin that answers each connection's 4-byte ping with `pong`.
async fn origin() -> u16 {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = origin.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4];
                if s.read_exact(&mut buf).await.is_ok() {
                    let _ = s.write_all(b"pong").await;
                }
            });
        }
    });
    port
}

struct Connector {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    socket: ConnectorSocket,
    loopback: LoopbackConnector,
    network: NetworkEpoch,
    route: RelayRoute,
}

fn connector() -> Connector {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.sock");
    let connector = LoopbackConnector::default();
    let policy = Arc::new(DestinationPolicy::loopback_for_tests(vec![], vec![]));
    let network = NetworkEpoch::default();
    network.advance();
    let route = RelayRoute::Instance {
        instance_id: InstanceId::new(),
        generation: 4,
    };
    let socket = ConnectorSocket::spawn(
        &path,
        route,
        network.clone(),
        connector.clone(),
        OnlyV4,
        policy,
    )
    .unwrap();
    Connector {
        _dir: dir,
        path,
        socket,
        loopback: connector,
        network,
        route,
    }
}

#[tokio::test]
async fn relays_to_the_named_host_over_the_requested_family_only() {
    let port = origin().await;
    let c = connector();

    // Only this user may connect.
    assert_eq!(
        std::fs::metadata(&c.path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let (reply, mut s) = request(
        &c.path,
        &RelayLine::new("api.test", port, RelayFamily::V4, c.route),
    )
    .await;
    assert!(reply.ok, "{reply:?}");
    assert!(reply.epochs.is_some(), "the answer names the epochs");
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");

    // IPv6 was not offered by the resolver: refused, never retried as IPv4.
    let (reply, _) = request(
        &c.path,
        &RelayLine::new("api.test", port, RelayFamily::V6, c.route),
    )
    .await;
    assert_eq!(code(&reply), "RESOLVE", "{reply:?}");

    // A closed gate refuses (the Instance is not Ready).
    c.loopback.set_closed(true);
    let (reply, _) = request(
        &c.path,
        &RelayLine::new("api.test", port, RelayFamily::V4, c.route),
    )
    .await;
    assert_eq!(code(&reply), "GATE_CLOSED", "{reply:?}");

    // Garbage is refused without a relay; so is the old line without nonce and route.
    let (reply, _) = send(&c.path, b"not json\n").await;
    assert_eq!(code(&reply), "BAD_REQUEST", "{reply:?}");
    let v1 = format!("{{\"v\":1,\"host\":\"api.test\",\"port\":{port},\"family\":\"v4\"}}\n");
    let (reply, _) = send(&c.path, v1.as_bytes()).await;
    assert_eq!(code(&reply), "BAD_VERSION", "{reply:?}");

    // Dropping it unlinks the socket.
    let path = c.path.clone();
    drop(c.socket);
    assert!(!path.exists());
}

#[tokio::test]
async fn a_nonce_is_good_for_one_line() {
    let port = origin().await;
    let c = connector();
    let line = RelayLine::new("api.test", port, RelayFamily::V4, c.route);
    let (first, _s) = request(&c.path, &line).await;
    assert!(first.ok, "{first:?}");
    let (again, _) = request(&c.path, &line).await;
    assert!(!again.ok);
    assert_eq!(code(&again), "NONCE_REUSED", "{again:?}");
}

#[tokio::test]
async fn a_line_for_another_instance_or_generation_is_refused() {
    let port = origin().await;
    let c = connector();
    let RelayRoute::Instance { instance_id, .. } = c.route else {
        unreachable!()
    };
    for other in [
        RelayRoute::Instance {
            instance_id,
            generation: 3,
        },
        RelayRoute::Instance {
            instance_id: InstanceId::new(),
            generation: 4,
        },
        RelayRoute::Bootstrap,
    ] {
        let (reply, _) = request(
            &c.path,
            &RelayLine::new("api.test", port, RelayFamily::V4, other),
        )
        .await;
        assert_eq!(code(&reply), "WRONG_ROUTE", "{other:?}: {reply:?}");
    }
}

#[tokio::test]
async fn an_authorized_request_is_refused_once_the_gate_opened_again() {
    let port = origin().await;
    let c = connector();
    // The exit check: an unauthorized line (a probe) reports the epochs.
    let (probe, _s) = request(
        &c.path,
        &RelayLine::new("api.test", port, RelayFamily::V4, c.route),
    )
    .await;
    let seen = probe.epochs.unwrap();
    let mut business = RelayLine::new("api.test", port, RelayFamily::V4, c.route);
    business.expect = Some(seen);
    let (ok, _s) = request(&c.path, &business).await;
    assert!(ok.ok, "{ok:?}");

    // The tunnel went down and the manager opened the gate again: the old check is void.
    c.network.advance();
    let mut late = RelayLine::new("api.test", port, RelayFamily::V4, c.route);
    late.expect = Some(seen);
    let (reply, _) = request(&c.path, &late).await;
    assert_eq!(code(&reply), "EPOCH_CHANGED", "{reply:?}");
    assert_ne!(reply.epochs, Some(seen));

    // Another connector at the same path (a new worker) is another connector epoch.
    let mut foreign = RelayLine::new("api.test", port, RelayFamily::V4, c.route);
    foreign.expect = Some(vpn_ipc::relay::RelayEpochs {
        connector: seen.connector.wrapping_add(1),
        network: c.network.get(),
    });
    let (reply, _) = request(&c.path, &foreign).await;
    assert_eq!(code(&reply), "EPOCH_CHANGED", "{reply:?}");
}
