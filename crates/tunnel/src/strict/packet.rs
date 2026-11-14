//! Just enough IPv4/IPv6 parsing to filter the packets of a strict sandbox's TUN device, and the
//! two kinds of packets the filter writes back: TCP resets and ICMP "administratively
//! prohibited" errors. Parsing never trusts lengths it has not checked against the buffer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// Extension headers walked before giving up on an IPv6 packet.
const MAX_V6_EXTENSIONS: usize = 8;
/// Hop limit / TTL of the packets we build.
const HOP_LIMIT: u8 = 64;
/// `ICMPv6` errors must not exceed the minimum IPv6 MTU (RFC 4443 §2.4).
const V6_MIN_MTU: usize = 1280;
/// `ICMPv4` errors quote at most this much of the offending datagram (RFC 1812: total ≤ 576).
const V4_ERROR_MAX: usize = 576;

/// The transport part of a packet, as far as the filter cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp {
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        /// Payload bytes after the TCP header.
        payload: u32,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        /// Payload bytes after the UDP header in this packet (of a first fragment: the part it
        /// carries).
        payload: u32,
    },
    /// ICMP (v4) or `ICMPv6` message.
    Icmp { kind: u8, code: u8 },
    /// A fragment other than the first: no transport header.
    Fragment,
    /// Any other protocol (number).
    Other(u8),
}

/// What ties one fragment of an IP datagram to the others: with the addresses, the key the
/// receiver reassembles by (RFC 791, RFC 8200).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment {
    /// IPv4 identification (16 bits) or IPv6 fragment identification (32 bits).
    pub id: u32,
    /// The IPv4 protocol, or the next header of the IPv6 fragment header.
    pub proto: u8,
    /// More fragments follow this one (false for the last).
    pub more: bool,
    /// Bytes of the datagram this fragment carries: everything after its IP header (for IPv6,
    /// after the fragment header).
    pub bytes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub transport: Transport,
    /// Set when the packet is one fragment of a larger datagram, the first one included.
    pub fragment: Option<Fragment>,
}

impl Parsed {
    pub(crate) const fn is_v6(&self) -> bool {
        self.dst.is_ipv6()
    }
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

/// Parse an IP packet. `None` for anything malformed or truncated.
pub fn parse(pkt: &[u8]) -> Option<Parsed> {
    match pkt.first()? >> 4 {
        4 => parse_v4(pkt),
        6 => parse_v6(pkt),
        _ => None,
    }
}

fn parse_v4(pkt: &[u8]) -> Option<Parsed> {
    let ihl = usize::from(pkt.first()? & 0x0f) * 4;
    let total = usize::from(be16(pkt, 2)?);
    if ihl < 20 || total < ihl || total > pkt.len() {
        return None;
    }
    let src = Ipv4Addr::from(be32(pkt, 12)?);
    let dst = Ipv4Addr::from(be32(pkt, 16)?);
    let proto = pkt[9];
    let id = be16(pkt, 4)?;
    let flags_offset = be16(pkt, 6)?;
    let fragment_offset = flags_offset & 0x1fff;
    let more = flags_offset & 0x2000 != 0;
    let transport = if fragment_offset != 0 {
        Transport::Fragment
    } else {
        transport(proto, &pkt[ihl..total], false)?
    };
    Some(Parsed {
        src: src.into(),
        dst: dst.into(),
        transport,
        fragment: (more || fragment_offset != 0).then_some(Fragment {
            id: u32::from(id),
            proto,
            more,
            bytes: u32::try_from(total - ihl).ok()?,
        }),
    })
}

fn parse_v6(pkt: &[u8]) -> Option<Parsed> {
    if pkt.len() < 40 {
        return None;
    }
    let payload_len = usize::from(be16(pkt, 4)?);
    let end = 40 + payload_len;
    if end > pkt.len() {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
    let mut next = pkt[6];
    let mut at = 40;
    let mut transport_found = None;
    let mut fragment = None;
    for _ in 0..MAX_V6_EXTENSIONS {
        match next {
            // Hop-by-hop, routing, destination options.
            0 | 43 | 60 => {
                let len = (usize::from(*pkt.get(at + 1)?) + 1) * 8;
                next = *pkt.get(at)?;
                at += len;
            }
            // Fragment header: only the first fragment carries the transport header.
            44 => {
                if at + 8 > end {
                    return None;
                }
                let field = be16(pkt, at + 2)?;
                let offset = field >> 3;
                let this = Fragment {
                    id: be32(pkt, at + 4)?,
                    proto: pkt[at],
                    more: field & 1 != 0,
                    bytes: u32::try_from(end - (at + 8)).ok()?,
                };
                // Offset 0 without more fragments is a whole datagram (an atomic fragment).
                if offset != 0 || this.more {
                    fragment = Some(this);
                }
                if offset != 0 {
                    transport_found = Some(Transport::Fragment);
                    break;
                }
                next = this.proto;
                at += 8;
            }
            // Authentication header.
            51 => {
                let len = (usize::from(*pkt.get(at + 1)?) + 2) * 4;
                next = *pkt.get(at)?;
                at += len;
            }
            proto => {
                if at > end {
                    return None;
                }
                transport_found = Some(transport(proto, &pkt[at..end], true)?);
                break;
            }
        }
        if at > end {
            return None;
        }
    }
    Some(Parsed {
        src: src.into(),
        dst: dst.into(),
        transport: transport_found?,
        fragment,
    })
}

fn transport(proto: u8, body: &[u8], v6: bool) -> Option<Transport> {
    Some(match proto {
        PROTO_TCP => {
            let offset = usize::from(body.get(12)? >> 4) * 4;
            if offset < 20 || offset > body.len() {
                return None;
            }
            Transport::Tcp {
                src_port: be16(body, 0)?,
                dst_port: be16(body, 2)?,
                seq: be32(body, 4)?,
                ack: be32(body, 8)?,
                flags: body[13],
                payload: u32::try_from(body.len() - offset).ok()?,
            }
        }
        PROTO_UDP => {
            if body.len() < 8 {
                return None;
            }
            // The UDP length covers the whole datagram (beyond a first fragment's end); bytes
            // past it in this packet are not payload.
            let len = usize::from(be16(body, 4)?).min(body.len());
            Transport::Udp {
                src_port: be16(body, 0)?,
                dst_port: be16(body, 2)?,
                payload: u32::try_from(len.saturating_sub(8)).ok()?,
            }
        }
        PROTO_ICMP if !v6 => Transport::Icmp {
            kind: *body.first()?,
            code: *body.get(1)?,
        },
        PROTO_ICMPV6 if v6 => Transport::Icmp {
            kind: *body.first()?,
            code: *body.get(1)?,
        },
        other => Transport::Other(other),
    })
}

/// Whether an ICMP message is an error report (carries a quoted packet) rather than a query.
pub const fn icmp_is_error(v6: bool, kind: u8) -> bool {
    if v6 {
        // Destination unreachable, packet too big, time exceeded, parameter problem.
        matches!(kind, 1..=4)
    } else {
        // Destination unreachable, source quench, redirect, time exceeded, parameter problem.
        matches!(kind, 3 | 4 | 5 | 11 | 12)
    }
}

/// ICMP echo request (ping).
pub const fn icmp_is_echo_request(v6: bool, kind: u8) -> bool {
    if v6 { kind == 128 } else { kind == 8 }
}

/// ICMP echo reply.
pub const fn icmp_is_echo_reply(v6: bool, kind: u8) -> bool {
    if v6 { kind == 129 } else { kind == 0 }
}

/// Addresses that never leave through a tunnel: loopback, unspecified, multicast, broadcast,
/// link-local (IPv4-mapped forms included).
pub const fn is_special(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------------------------

fn sum_words(data: &[u8], mut sum: u32) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*w)));
    }
    if let [last] = rest {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    sum
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the loop folds the sum to 16 bits before the cast"
)]
const fn fold(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn checksum(data: &[u8]) -> u16 {
    fold(sum_words(data, 0))
}

/// Checksum of a transport segment with its IPv4/IPv6 pseudo-header.
#[expect(
    clippy::cast_possible_truncation,
    reason = "a segment is the payload of one IP packet, far below 4 GiB"
)]
fn transport_checksum(src: IpAddr, dst: IpAddr, proto: u8, segment: &[u8]) -> u16 {
    let mut sum = 0u32;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum = sum_words(&s.octets(), sum);
            sum = sum_words(&d.octets(), sum);
            sum = sum.wrapping_add(u32::from(proto));
            sum = sum.wrapping_add(segment.len() as u32);
        }
        (s, d) => {
            let s = match s {
                IpAddr::V6(s) => s,
                IpAddr::V4(s) => s.to_ipv6_mapped(),
            };
            let d = match d {
                IpAddr::V6(d) => d,
                IpAddr::V4(d) => d.to_ipv6_mapped(),
            };
            sum = sum_words(&s.octets(), sum);
            sum = sum_words(&d.octets(), sum);
            let len = segment.len() as u32;
            sum = sum.wrapping_add(len >> 16).wrapping_add(len & 0xffff);
            sum = sum.wrapping_add(u32::from(proto));
        }
    }
    fold(sum_words(segment, sum))
}

// ---------------------------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------------------------

/// Wrap a transport segment in an IP header from `src` to `dst` (same family).
fn ip_packet(src: IpAddr, dst: IpAddr, proto: u8, segment: &[u8]) -> Option<Vec<u8>> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = u16::try_from(20 + segment.len()).ok()?;
            let mut p = Vec::with_capacity(usize::from(total));
            p.extend_from_slice(&[0x45, 0]);
            p.extend_from_slice(&total.to_be_bytes());
            // Identification 0, don't fragment.
            p.extend_from_slice(&[0, 0, 0x40, 0, HOP_LIMIT, proto, 0, 0]);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            let sum = checksum(&p[..20]);
            p[10..12].copy_from_slice(&sum.to_be_bytes());
            p.extend_from_slice(segment);
            Some(p)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let len = u16::try_from(segment.len()).ok()?;
            let mut p = Vec::with_capacity(40 + segment.len());
            p.extend_from_slice(&[0x60, 0, 0, 0]);
            p.extend_from_slice(&len.to_be_bytes());
            p.extend_from_slice(&[proto, HOP_LIMIT]);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(segment);
            Some(p)
        }
        _ => None,
    }
}

/// A bare TCP reset from `src` to `dst`. With `ack`, the ACK flag is set too.
pub fn tcp_reset(src: SocketAddr, dst: SocketAddr, seq: u32, ack: Option<u32>) -> Option<Vec<u8>> {
    let mut seg = [0u8; 20];
    seg[0..2].copy_from_slice(&src.port().to_be_bytes());
    seg[2..4].copy_from_slice(&dst.port().to_be_bytes());
    seg[4..8].copy_from_slice(&seq.to_be_bytes());
    seg[8..12].copy_from_slice(&ack.unwrap_or(0).to_be_bytes());
    seg[12] = 5 << 4;
    seg[13] = TCP_RST | if ack.is_some() { TCP_ACK } else { 0 };
    let sum = transport_checksum(src.ip(), dst.ip(), PROTO_TCP, &seg);
    seg[16..18].copy_from_slice(&sum.to_be_bytes());
    ip_packet(src.ip(), dst.ip(), PROTO_TCP, &seg)
}

/// The reset RFC 9293 §3.10.7.1 prescribes in answer to `p` (a TCP segment that must not be
/// accepted), addressed back to its sender. `None` if `p` is itself a reset.
pub fn tcp_reset_reply(p: &Parsed) -> Option<Vec<u8>> {
    let Transport::Tcp {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        payload,
    } = p.transport
    else {
        return None;
    };
    if flags & TCP_RST != 0 {
        return None;
    }
    let from = SocketAddr::new(p.dst, dst_port);
    let to = SocketAddr::new(p.src, src_port);
    if flags & TCP_ACK != 0 {
        tcp_reset(from, to, ack, None)
    } else {
        let len = payload
            .wrapping_add(u32::from(flags & TCP_SYN != 0))
            .wrapping_add(u32::from(flags & TCP_FIN != 0));
        tcp_reset(from, to, 0, Some(seq.wrapping_add(len)))
    }
}

/// An ICMP "communication administratively prohibited" error about `raw` (whose parse is `p`),
/// sent back to its source as if from its destination.
pub fn icmp_prohibited(raw: &[u8], p: &Parsed) -> Option<Vec<u8>> {
    if p.is_v6() {
        let quote = raw.len().min(V6_MIN_MTU - 40 - 8);
        let mut seg = Vec::with_capacity(8 + quote);
        // Destination unreachable, code 1: administratively prohibited.
        seg.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
        seg.extend_from_slice(&raw[..quote]);
        let sum = transport_checksum(p.dst, p.src, PROTO_ICMPV6, &seg);
        seg[2..4].copy_from_slice(&sum.to_be_bytes());
        ip_packet(p.dst, p.src, PROTO_ICMPV6, &seg)
    } else {
        let quote = raw.len().min(V4_ERROR_MAX - 20 - 8);
        let mut seg = Vec::with_capacity(8 + quote);
        // Destination unreachable, code 13: communication administratively prohibited.
        seg.extend_from_slice(&[3, 13, 0, 0, 0, 0, 0, 0]);
        seg.extend_from_slice(&raw[..quote]);
        let sum = checksum(&seg);
        seg[2..4].copy_from_slice(&sum.to_be_bytes());
        ip_packet(p.dst, p.src, PROTO_ICMP, &seg)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A TCP segment (no options) wrapped in an IP header, checksums filled in.
    pub fn tcp(src: &str, dst: &str, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let src: SocketAddr = src.parse().unwrap();
        let dst: SocketAddr = dst.parse().unwrap();
        let mut seg = vec![0u8; 20];
        seg[0..2].copy_from_slice(&src.port().to_be_bytes());
        seg[2..4].copy_from_slice(&dst.port().to_be_bytes());
        seg[4..8].copy_from_slice(&seq.to_be_bytes());
        seg[8..12].copy_from_slice(&ack.to_be_bytes());
        seg[12] = 5 << 4;
        seg[13] = flags;
        seg[14..16].copy_from_slice(&64240u16.to_be_bytes());
        seg.extend_from_slice(payload);
        let sum = transport_checksum(src.ip(), dst.ip(), PROTO_TCP, &seg);
        seg[16..18].copy_from_slice(&sum.to_be_bytes());
        ip_packet(src.ip(), dst.ip(), PROTO_TCP, &seg).unwrap()
    }

    pub fn udp(src: &str, dst: &str, payload: &[u8]) -> Vec<u8> {
        let src: SocketAddr = src.parse().unwrap();
        let dst: SocketAddr = dst.parse().unwrap();
        let mut seg = vec![0u8; 8];
        seg[0..2].copy_from_slice(&src.port().to_be_bytes());
        seg[2..4].copy_from_slice(&dst.port().to_be_bytes());
        seg[4..6].copy_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
        seg.extend_from_slice(payload);
        let sum = transport_checksum(src.ip(), dst.ip(), PROTO_UDP, &seg);
        seg[6..8].copy_from_slice(&sum.to_be_bytes());
        ip_packet(src.ip(), dst.ip(), PROTO_UDP, &seg).unwrap()
    }

    pub fn icmp_echo(src: &str, dst: &str) -> Vec<u8> {
        let src: IpAddr = src.parse().unwrap();
        let dst: IpAddr = dst.parse().unwrap();
        let (proto, kind) = if src.is_ipv6() {
            (PROTO_ICMPV6, 128)
        } else {
            (PROTO_ICMP, 8)
        };
        let mut seg = vec![kind, 0, 0, 0, 0, 1, 0, 1, b'p', b'i', b'n', b'g'];
        let sum = if src.is_ipv6() {
            transport_checksum(src, dst, proto, &seg)
        } else {
            checksum(&seg)
        };
        seg[2..4].copy_from_slice(&sum.to_be_bytes());
        ip_packet(src, dst, proto, &seg).unwrap()
    }

    /// IPv4 `pkt` as the fragment at `offset` (8-byte units) of datagram `id`.
    pub fn v4_fragment(mut pkt: Vec<u8>, id: u16, offset: u16, more: bool) -> Vec<u8> {
        pkt[4..6].copy_from_slice(&id.to_be_bytes());
        let field = offset | if more { 0x2000 } else { 0 };
        pkt[6..8].copy_from_slice(&field.to_be_bytes());
        pkt
    }

    /// IPv6 `pkt` (no extension headers) with a fragment header: the fragment at `offset`
    /// (8-byte units) of datagram `id`.
    pub fn v6_fragment(pkt: &[u8], id: u32, offset: u16, more: bool) -> Vec<u8> {
        let mut out = pkt[..40].to_vec();
        let next = out[6];
        out[6] = 44;
        let len = u16::from_be_bytes([out[4], out[5]]) + 8;
        out[4..6].copy_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&[next, 0]);
        out.extend_from_slice(&((offset << 3) | u16::from(more)).to_be_bytes());
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&pkt[40..]);
        out
    }

    #[test]
    fn non_first_fragments_have_no_transport() {
        let mut frag = udp("10.99.0.2:5000", "1.1.1.1:53", &[0u8; 32]);
        // More fragments, offset 100 (eight-byte units).
        frag[6..8].copy_from_slice(&(0x2000u16 | 0x0064).to_be_bytes());
        assert_eq!(parse(&frag).unwrap().transport, Transport::Fragment);
    }

    #[test]
    fn walks_ipv6_extension_headers() {
        let dgram = udp("[fd99::2]:5353", "[2606:4700::1111]:53", b"q");
        // Insert a destination-options header (8 bytes) between the IPv6 header and UDP.
        let mut pkt = dgram[..40].to_vec();
        pkt[6] = 60;
        let len = u16::from_be_bytes([pkt[4], pkt[5]]) + 8;
        pkt[4..6].copy_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(&[PROTO_UDP, 0, 1, 4, 0, 0, 0, 0]);
        pkt.extend_from_slice(&dgram[40..]);
        assert_eq!(
            parse(&pkt).unwrap().transport,
            Transport::Udp {
                src_port: 5353,
                dst_port: 53,
                payload: 1
            }
        );
    }

    #[test]
    fn special_addresses() {
        for s in [
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.251",
            "255.255.255.255",
            "169.254.1.1",
            "::1",
            "::",
            "ff02::fb",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_special(s.parse().unwrap()), "{s}");
        }
        assert!(!is_special("10.99.0.1".parse().unwrap()));
        assert!(!is_special("2606:4700::1111".parse().unwrap()));
    }
}
