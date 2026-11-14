//! Linux strict mode data path.
//!
//! A strict Instance's managed Apps run in a rootless sandbox (user + network + mount + pid
//! namespaces, built by `vpn-platform`) whose only interface besides `lo` is a TUN device. The
//! Instance worker joins that network namespace and connects the TUN device to `GotaTun`
//! ([`StrictTunnel`]); its own flows (DNS upstream, Gateway dials, Provider connector) use
//! kernel sockets there ([`KernelConnector`]), never the smoltcp netstack, so one tunnel address
//! is never shared by two TCP/IP stacks. Every packet crossing the TUN device passes the payload
//! gate and the destination policy (the filter); a refused flow gets a TCP reset or an ICMP
//! "administratively prohibited", never a route elsewhere — there is no elsewhere in the sandbox.
//!
//! Only Linux has it. The packet logic itself is portable and unit-tested everywhere.

#[cfg_attr(
    not(target_os = "linux"),
    expect(
        dead_code,
        reason = "only Linux has the strict data path; elsewhere the packet logic runs in its tests"
    )
)]
mod filter;
#[cfg_attr(
    not(target_os = "linux"),
    expect(
        dead_code,
        reason = "only Linux has the strict data path; elsewhere the packet logic runs in its tests"
    )
)]
mod flows;
#[cfg_attr(
    not(target_os = "linux"),
    expect(
        dead_code,
        reason = "only Linux has the strict data path; elsewhere the packet logic runs in its tests"
    )
)]
mod packet;

#[cfg(target_os = "linux")]
mod connector;
#[cfg(target_os = "linux")]
mod tun;
#[cfg(target_os = "linux")]
mod tunnel;

pub use filter::{
    DestinationCheck, DirectUdpOpen, DirectUdpPolicy, DirectUdpPort, FilterStats, PortPayload,
};
pub use flows::L4;

#[cfg(target_os = "linux")]
pub use connector::{KernelConnector, KernelDatagram, KernelListener, KernelPort, KernelStream};
#[cfg(target_os = "linux")]
pub use tunnel::{StrictTunnel, StrictTunnelConfig, interfaces, verify_closed_namespace};
