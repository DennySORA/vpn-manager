//! One running `WireGuard` tunnel: `GotaTun` device + pinned underlay + netstack.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use gotatun::device::{Device, DeviceBuilder, DeviceTransports, Peer};
use gotatun::x25519::{PublicKey, StaticSecret};
use ipnetwork::IpNetwork;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use zeroize::Zeroizing;

use crate::ipchan::{self, IpChannelStats};
use crate::netstack::{Netstack, NetstackLimits};
use crate::pinned_udp::{PeerPolicy, PinnedUdpFactory, UdpSource, UnderlayStats};
use crate::transport::TransportPlan;

/// Capacity (packets) of each direction of the IP channel.
const IP_QUEUE_PACKETS: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("invalid tunnel configuration: {0}")]
    Config(String),
    /// No handshake completed before the deadline: the peer did not answer (wrong key,
    /// unreachable or filtered endpoint).
    #[error("no WireGuard handshake within {0:?}")]
    HandshakeTimeout(Duration),
    #[error("tunnel stopped")]
    Stopped,
    #[error("netstack: {0}")]
    Netstack(#[from] std::io::Error),
    #[error("wireguard device: {0}")]
    Device(#[from] gotatun::device::Error),
    #[error("underlay socket could not be opened again: {0}")]
    Rebind(String),
}

/// The remote `WireGuard` peer.
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: Option<Zeroizing<[u8; 32]>>,
    /// `None` only for the test peer acting as a server.
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNetwork>,
    pub persistent_keepalive: Option<u16>,
}

/// Everything needed to bring a tunnel up. Secrets are zeroized when dropped.
pub struct TunnelConfig {
    pub private_key: Zeroizing<[u8; 32]>,
    pub peer: PeerConfig,
    /// Interface addresses inside the tunnel (e.g. `10.64.1.2/32`, `fc00::1:2/128`).
    pub addresses: Vec<IpNetwork>,
    pub mtu: u16,
    pub underlay: UdpSource,
    pub underlay_policy: PeerPolicy,
    /// Fixed underlay port (test peer); `0` picks an ephemeral one.
    pub listen_port: u16,
    pub limits: NetstackLimits,
    /// What each new flow gets ([`crate::transport`]); replaced on a running tunnel through
    /// [`Netstack::transport`].
    pub transport: TransportPlan,
}

/// Observed peer state.
#[derive(Debug, Clone, Default)]
pub struct PeerSnapshot {
    /// Time since the last completed handshake.
    pub last_handshake: Option<Duration>,
    pub endpoint: Option<SocketAddr>,
    /// `WireGuard` bytes as counted by `GotaTun`.
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

enum Cmd {
    Peer(oneshot::Sender<Option<PeerSnapshot>>),
    /// Send a handshake initiation if no session exists (returns within ~50 ms).
    Kick(oneshot::Sender<()>),
    /// Close the underlay socket and open it again through the transport factory, dropping the
    /// sessions (`GotaTun` suspend + resume).
    Rebind(oneshot::Sender<Result<(), String>>),
    Stop(oneshot::Sender<()>),
}

/// Handle to a running tunnel. Cheap to clone; a background task owns the `GotaTun` device so
/// fatal-error waiting and status queries never contend for it.
#[derive(Clone)]
pub struct Tunnel {
    netstack: Netstack,
    device: DeviceHandle,
    channel_stats: Arc<IpChannelStats>,
    underlay_stats: Arc<UnderlayStats>,
}

impl Tunnel {
    /// Bring the tunnel up. The netstack gate starts [`Closed`](crate::GateState::Closed): no flow
    /// is admitted until the owner opens it.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Config`] for an MTU outside 576..=9000 or an all-zero peer key;
    /// [`TunnelError::Netstack`] or [`TunnelError::Device`] when the netstack or the `WireGuard`
    /// device cannot be set up.
    pub async fn start(config: TunnelConfig) -> Result<Self, TunnelError> {
        if !(576..=9000).contains(&config.mtu) {
            return Err(TunnelError::Config(format!(
                "mtu {} out of range",
                config.mtu
            )));
        }
        if config.peer.public_key == [0u8; 32] {
            return Err(TunnelError::Config("peer public key is all zeros".into()));
        }
        let wake = Arc::new(Notify::new());
        let channel_stats = Arc::new(IpChannelStats::default());
        let (tx, rx, chan) =
            ipchan::channel(IP_QUEUE_PACKETS, config.mtu, wake, channel_stats.clone());
        let netstack = Netstack::spawn(
            &config.addresses,
            config.mtu,
            config.limits,
            config.transport,
            chan,
        )?;

        let underlay_stats = Arc::new(UnderlayStats::default());
        let udp = PinnedUdpFactory::new(
            config.underlay,
            config.underlay_policy,
            underlay_stats.clone(),
        );

        let (peer_key, peer) = gotatun_peer(config.peer);

        let device = DeviceBuilder::new()
            .with_udp(udp)
            .with_ip_pair(tx, rx)
            .with_listen_port(config.listen_port)
            .with_private_key(StaticSecret::from(*config.private_key))
            .with_peer(peer)
            .build()
            .await;
        let device = match device {
            Ok(d) => d,
            Err(e) => {
                netstack.shutdown();
                return Err(e.into());
            }
        };
        let sealed = netstack.clone();
        let device = DeviceHandle::spawn(device, peer_key, move || {
            let _ = sealed.set_gate(crate::GateState::Sealed);
        });
        Ok(Self {
            netstack,
            device,
            channel_stats,
            underlay_stats,
        })
    }

    /// The connector for DNS, Gateways and Port forwards.
    #[must_use]
    pub fn netstack(&self) -> Netstack {
        self.netstack.clone()
    }

    #[must_use]
    pub fn channel_stats(&self) -> &IpChannelStats {
        &self.channel_stats
    }

    #[must_use]
    pub fn underlay_stats(&self) -> &UnderlayStats {
        &self.underlay_stats
    }

    /// Current peer state, if the device is still running.
    pub async fn peer(&self) -> Option<PeerSnapshot> {
        self.device.peer().await
    }

    /// Initiate a handshake if needed and wait until one completed, bounded by `timeout`.
    ///
    /// # Errors
    ///
    /// [`TunnelError::HandshakeTimeout`] when none completed in time, [`TunnelError::Stopped`]
    /// when the device stopped meanwhile.
    pub async fn handshake(&self, timeout: Duration) -> Result<(), TunnelError> {
        self.device.handshake(timeout).await
    }

    /// Resolves with a description once `GotaTun` hit an unrecoverable error (or the tunnel
    /// stopped).
    pub async fn fatal(&self) -> String {
        self.device.fatal().await
    }

    /// Close the underlay UDP socket and open it again (through the same pinned factory), and
    /// drop the sessions so the next packet handshakes afresh: what `GotaTun` does across a
    /// suspend. Part of the `GotaTun` upgrade gate (docs/decisions/0001).
    ///
    /// # Errors
    ///
    /// [`TunnelError::Rebind`] when the socket cannot be opened again, [`TunnelError::Stopped`]
    /// when the device stopped.
    pub async fn rebind_underlay(&self) -> Result<(), TunnelError> {
        self.device.rebind().await
    }

    /// Seal the netstack and stop the device.
    pub async fn shutdown(&self) {
        self.netstack.shutdown();
        self.device.stop().await;
    }
}

/// The `GotaTun` peer for `config`, and its public key.
pub fn gotatun_peer(config: PeerConfig) -> (PublicKey, Peer) {
    let peer_key = PublicKey::from(config.public_key);
    let mut peer = Peer::new(peer_key).with_allowed_ips(config.allowed_ips);
    if let Some(endpoint) = config.endpoint {
        peer = peer.with_endpoint(endpoint);
    }
    if let Some(psk) = &config.preshared_key {
        peer = peer.with_preshared_key(**psk);
    }
    peer.keepalive = config.persistent_keepalive;
    (peer_key, peer)
}

/// Commands to the task that owns a `GotaTun` device; shared by the userspace-netstack tunnel and
/// the strict (TUN) tunnel.
#[derive(Clone)]
pub struct DeviceHandle {
    cmd: mpsc::Sender<Cmd>,
    fatal: watch::Receiver<Option<String>>,
}

impl DeviceHandle {
    /// Hand `device` to its owner task. `on_fatal` runs first when `GotaTun` reports an
    /// unrecoverable error (it seals the data path).
    pub(crate) fn spawn<T: DeviceTransports>(
        device: Device<T>,
        peer_key: PublicKey,
        on_fatal: impl FnOnce() + Send + 'static,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (fatal_tx, fatal_rx) = watch::channel(None);
        tokio::spawn(device_task(
            device,
            peer_key,
            cmd_rx,
            fatal_tx,
            Box::new(on_fatal),
        ));
        Self {
            cmd: cmd_tx,
            fatal: fatal_rx,
        }
    }

    pub(crate) async fn peer(&self) -> Option<PeerSnapshot> {
        let (tx, rx) = oneshot::channel();
        self.cmd.send(Cmd::Peer(tx)).await.ok()?;
        rx.await.ok().flatten()
    }

    pub(crate) async fn handshake(&self, timeout: Duration) -> Result<(), TunnelError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut next_kick = tokio::time::Instant::now();
        loop {
            match self.peer().await {
                Some(p) if p.last_handshake.is_some() => return Ok(()),
                Some(_) => {}
                None => return Err(TunnelError::Stopped),
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(TunnelError::HandshakeTimeout(timeout));
            }
            if now >= next_kick {
                let (tx, rx) = oneshot::channel();
                if self.cmd.send(Cmd::Kick(tx)).await.is_err() {
                    return Err(TunnelError::Stopped);
                }
                let _ = rx.await;
                next_kick = now + Duration::from_secs(1);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    pub(crate) async fn fatal(&self) -> String {
        let mut rx = self.fatal.clone();
        rx.wait_for(Option::is_some).await.map_or_else(
            |_| "tunnel stopped".into(),
            |v| v.clone().unwrap_or_default(),
        )
    }

    pub(crate) async fn stop(&self) {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Cmd::Stop(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }

    pub(crate) async fn rebind(&self) -> Result<(), TunnelError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Rebind(tx))
            .await
            .map_err(|_| TunnelError::Stopped)?;
        rx.await
            .map_err(|_| TunnelError::Stopped)?
            .map_err(TunnelError::Rebind)
    }
}

async fn device_task<T: DeviceTransports>(
    mut device: Device<T>,
    peer_key: PublicKey,
    mut cmd: mpsc::Receiver<Cmd>,
    fatal: watch::Sender<Option<String>>,
    on_fatal: Box<dyn FnOnce() + Send>,
) {
    let mut on_fatal = Some(on_fatal);
    loop {
        tokio::select! {
            () = device.wait() => {
                tracing::error!("wireguard device reported a fatal error");
                if let Some(seal) = on_fatal.take() {
                    seal();
                }
                // English: this crate has no `vpn_domain::Text`; the worker words the
                // `TUNNEL_FATAL` fault for people.
                let _ = fatal.send(Some(
                    "The WireGuard device hit an unrecoverable error".into(),
                ));
                device.stop().await;
                return;
            }
            c = cmd.recv() => match c {
                Some(Cmd::Peer(reply)) => {
                    let peers = device.peers().await;
                    let snap = peers.into_iter().find(|p| p.peer.public_key == peer_key).map(|p| PeerSnapshot {
                        last_handshake: p.stats.last_handshake,
                        endpoint: p.peer.endpoint,
                        rx_bytes: p.stats.rx_bytes as u64,
                        tx_bytes: p.stats.tx_bytes as u64,
                    });
                    let _ = reply.send(snap);
                }
                Some(Cmd::Kick(reply)) => {
                    // force_handshake sends the initiation first and then waits for completion
                    // forever; cut the wait short so the device task stays responsive. Completion
                    // is observed through peer statistics.
                    let _ = tokio::time::timeout(
                        Duration::from_millis(50),
                        device.force_handshake(&peer_key),
                    )
                    .await;
                    let _ = reply.send(());
                }
                Some(Cmd::Rebind(reply)) => {
                    device.suspend().await;
                    let _ = reply.send(device.resume().await.map_err(|e| e.to_string()));
                }
                Some(Cmd::Stop(reply)) => {
                    device.stop().await;
                    let _ = fatal.send(Some("tunnel stopped".into()));
                    let _ = reply.send(());
                    return;
                }
                None => {
                    device.stop().await;
                    return;
                }
            }
        }
    }
}
