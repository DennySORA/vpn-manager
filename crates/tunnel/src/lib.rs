//! Data plane of one VPN Instance: the embedded `GotaTun` `WireGuard` device, its pinned underlay
//! and the userspace netstack that exposes the only way to send payload — through the tunnel.

pub mod connector;
mod ipchan;
pub mod netstack;
pub mod pinned_udp;
pub mod strict;
pub mod transport;
mod tunnel;

pub use connector::{
    AnyConnector, AnyDatagram, AnyInbound, AnyListener, AnyPort, AnyStream, InboundListener,
    InboundStream, TunnelConnector, TunnelDatagram, TunnelInbound,
};
pub use ipchan::IpChannelStats;
pub use netstack::{
    FlowClass, GateState, Netstack, NetstackLimits, NetstackStats, PortReservation, TcpListener,
    TcpStream, UdpSocket,
};
pub use pinned_udp::{PeerPolicy, UdpSource, UnderlayStats};
pub use strict::{DirectUdpOpen, DirectUdpPolicy, DirectUdpPort};
pub use transport::{Band, Congestion, FlowTuning, Transport, TransportPlan, TransportSnapshot};
pub use tunnel::{PeerConfig, PeerSnapshot, Tunnel, TunnelConfig, TunnelError};

/// `WireGuard` key helpers (x25519, as used by `GotaTun`).
pub mod keys {
    pub use gotatun::x25519::{PublicKey, StaticSecret};

    /// Derive the public key of a 32-byte private key.
    #[must_use]
    pub fn public_from_private(private: &[u8; 32]) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(*private)).to_bytes()
    }

    /// Generate a new random, clamped private key from the OS CSPRNG.
    ///
    /// # Panics
    ///
    /// Panics if the operating system random number generator is unavailable.
    #[must_use]
    pub fn generate_private() -> zeroize::Zeroizing<[u8; 32]> {
        use rand::TryRng;
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        rand::rngs::SysRng
            .try_fill_bytes(key.as_mut())
            .expect("operating system random number generator unavailable");
        key[0] &= 0b1111_1000;
        key[31] &= 0b0111_1111;
        key[31] |= 0b0100_0000;
        key
    }
}
