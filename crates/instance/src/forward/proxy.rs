//! PROXY protocol v2 (`HAProxy`'s `proxy-protocol.txt`, §2.2): the header a forward that opted in
//! writes to its App before the first byte of a forwarded TCP connection. The App connection
//! itself always comes from loopback; the header tells the App who really connected — the remote
//! peer as the tunnel saw it — and where: the tunnel address and port it reached.
//!
//! Always the `PROXY` command over `STREAM`, IPv4 or IPv6, and no TLVs: 28 or 52 bytes.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// The fixed signature every v2 header starts with.
pub const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// Version 2 (high nibble), command `PROXY` (low nibble).
const VERSION_2_PROXY: u8 = 0x21;
/// `AF_INET` (high nibble) over `STREAM` (low nibble).
const TCP_OVER_IPV4: u8 = 0x11;
/// `AF_INET6` over `STREAM`.
const TCP_OVER_IPV6: u8 = 0x21;
/// Address block lengths: two addresses and two ports.
const IPV4_BLOCK: u16 = 4 + 4 + 2 + 2;
const IPV6_BLOCK: u16 = 16 + 16 + 2 + 2;

/// The header for a TCP connection from `source` to `destination`. IPv4-mapped IPv6 addresses
/// are taken as the IPv4 addresses they carry. One tunnel connection never mixes families; were
/// it to, both would go as IPv6 (IPv4 as IPv4-mapped), so the header still names both ends.
pub fn header(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let (src, dst) = (source.ip().to_canonical(), destination.ip().to_canonical());
    let mut out = Vec::with_capacity(SIGNATURE.len() + 4 + usize::from(IPV6_BLOCK));
    out.extend_from_slice(&SIGNATURE);
    out.push(VERSION_2_PROXY);
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            out.push(TCP_OVER_IPV4);
            out.extend_from_slice(&IPV4_BLOCK.to_be_bytes());
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
        }
        (s, d) => {
            out.push(TCP_OVER_IPV6);
            out.extend_from_slice(&IPV6_BLOCK.to_be_bytes());
            out.extend_from_slice(&v6(s).octets());
            out.extend_from_slice(&v6(d).octets());
        }
    }
    out.extend_from_slice(&source.port().to_be_bytes());
    out.extend_from_slice(&destination.port().to_be_bytes());
    out
}

const fn v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(a) => a.to_ipv6_mapped(),
        IpAddr::V6(a) => a,
    }
}
