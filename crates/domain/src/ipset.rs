//! A compact set of IP addresses: sorted, merged, inclusive IPv4 (`u32`) and IPv6 (`u128`)
//! ranges, looked up by binary search. Blocklists are stored, compiled and enforced in this
//! form.
//!
//! Every set has exactly one canonical form (ranges sorted, overlapping and adjacent ranges
//! merged), so equal sets encode to equal bytes and the SHA-256 of the encoding identifies the
//! content: the manager and the worker compare digests to prove what is enforced.
//!
//! Encoding (all integers big-endian): `"VMRS" | version u8 | 3 zero bytes | v4 count u32 |
//! v6 count u32 | v4 ranges (start u32, end u32)… | v6 ranges (start u128, end u128)…`. Decoding
//! accepts only the canonical form.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::validation::canonical_ip;

const MAGIC: &[u8; 4] = b"VMRS";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 16;
const V4_LEN: usize = 8;
const V6_LEN: usize = 32;

/// Largest encoding accepted anywhere (a compiled policy of at most 16 MiB of ranges).
pub const MAX_ENCODED_BYTES: usize = 16 * 1024 * 1024 + HEADER_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("not an IP range set")]
    Format,
    #[error("IP range set larger than allowed")]
    TooLarge,
    #[error("IP ranges are not in canonical order")]
    NotCanonical,
}

/// Sorted, merged, inclusive address ranges of both families.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct IpRangeSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl std::fmt::Debug for IpRangeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpRangeSet")
            .field("v4_ranges", &self.v4.len())
            .field("v6_ranges", &self.v6.len())
            .finish()
    }
}

/// Sort and merge overlapping or adjacent inclusive ranges in place.
fn normalize<T: Copy + Ord + MaxValue>(ranges: &mut Vec<(T, T)>) {
    for r in ranges.iter_mut() {
        if r.0 > r.1 {
            *r = (r.1, r.0);
        }
    }
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for &(start, end) in ranges.iter() {
        match out.last_mut() {
            // Overlapping, or adjacent (the previous range ends right before this one starts).
            Some(last) if last.1 == T::MAX || start <= last.1.next() => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => out.push((start, end)),
        }
    }
    *ranges = out;
}

trait MaxValue: Sized {
    const MAX: Self;
    /// `self + 1`; never called on `MAX`.
    fn next(self) -> Self;
    /// `self - 1`; never called on 0.
    fn prev(self) -> Self;
}

impl MaxValue for u32 {
    const MAX: Self = Self::MAX;
    fn next(self) -> Self {
        self + 1
    }
    fn prev(self) -> Self {
        self - 1
    }
}

impl MaxValue for u128 {
    const MAX: Self = Self::MAX;
    fn next(self) -> Self {
        self + 1
    }
    fn prev(self) -> Self {
        self - 1
    }
}

/// Take `x` out of the range that holds it, splitting the range when `x` is inside; the ranges
/// stay sorted, disjoint and non-adjacent.
fn cut<T: Copy + Ord + MaxValue>(ranges: &mut Vec<(T, T)>, x: T) {
    let idx = ranges.partition_point(|r| r.0 <= x);
    if idx == 0 || ranges[idx - 1].1 < x {
        return;
    }
    let (start, end) = ranges[idx - 1];
    let mut parts = Vec::with_capacity(2);
    if start < x {
        parts.push((start, x.prev()));
    }
    if x < end {
        parts.push((x.next(), end));
    }
    ranges.splice(idx - 1..idx, parts);
}

fn find<T: Copy + Ord>(ranges: &[(T, T)], x: T) -> bool {
    let idx = ranges.partition_point(|r| r.0 <= x);
    idx > 0 && ranges[idx - 1].1 >= x
}

/// Inclusive range of an IPv4 network.
#[must_use]
pub fn v4_range(addr: Ipv4Addr, prefix: u8) -> (u32, u32) {
    let a = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    };
    let start = a & mask;
    (start, start | !mask)
}

/// Inclusive range of an IPv6 network.
#[must_use]
pub fn v6_range(addr: Ipv6Addr, prefix: u8) -> (u128, u128) {
    let a = u128::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix.min(128)))
    };
    let start = a & mask;
    (start, start | !mask)
}

impl IpRangeSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A set of these ranges (any order, overlaps allowed; a reversed pair is swapped).
    #[must_use]
    pub fn from_ranges(mut v4: Vec<(u32, u32)>, mut v6: Vec<(u128, u128)>) -> Self {
        normalize(&mut v4);
        normalize(&mut v6);
        Self { v4, v6 }
    }

    /// The set of addresses inside these networks. IPv4-mapped IPv6 networks of at least /96
    /// count as the IPv4 network they map.
    pub fn from_networks(nets: impl IntoIterator<Item = IpNetwork>) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for net in nets {
            match net {
                IpNetwork::V4(n) => v4.push(v4_range(n.ip(), n.prefix())),
                IpNetwork::V6(n) => match n.ip().to_ipv4_mapped() {
                    Some(m) if n.prefix() >= 96 => v4.push(v4_range(m, n.prefix() - 96)),
                    _ => v6.push(v6_range(n.ip(), n.prefix())),
                },
            }
        }
        Self::from_ranges(v4, v6)
    }

    /// The set without these addresses, each taken out the way [`Self::contains`] looks it up (an
    /// IPv4-mapped or NAT64 address as its IPv4 host, a NAT64 one also as itself): afterwards
    /// `contains` is false for every one of them.
    #[must_use]
    pub fn without(&self, ips: &[IpAddr]) -> Self {
        let mut v4 = self.v4.clone();
        let mut v6 = self.v6.clone();
        for &ip in ips {
            if let IpAddr::V4(host) = canonical_ip(ip) {
                cut(&mut v4, u32::from(host));
            }
            if let IpAddr::V6(a) = ip {
                cut(&mut v6, u128::from(a));
            }
        }
        Self { v4, v6 }
    }

    /// Whether `ip` is in the set. An IPv4-mapped or NAT64 address is looked up as the IPv4 host
    /// it embeds ([`canonical_ip`]); a NAT64 address, an IPv6 destination too, is in the set
    /// when either form is.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match canonical_ip(ip) {
            IpAddr::V4(host) => {
                find(&self.v4, u32::from(host))
                    || matches!(ip, IpAddr::V6(a)
                        if a.to_ipv4_mapped().is_none() && find(&self.v6, u128::from(a)))
            }
            IpAddr::V6(a) => find(&self.v6, u128::from(a)),
        }
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Number of ranges of both families.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    #[must_use]
    pub fn v4_ranges(&self) -> &[(u32, u32)] {
        &self.v4
    }

    #[must_use]
    pub fn v6_ranges(&self) -> &[(u128, u128)] {
        &self.v6
    }

    /// IPv4 addresses covered (at most 2^32).
    #[must_use]
    pub fn v4_addresses(&self) -> u64 {
        self.v4.iter().map(|&(s, e)| u64::from(e - s) + 1).sum()
    }

    /// IPv6 addresses covered; saturates at `u128::MAX` (only `::/0` covers more).
    #[must_use]
    pub fn v6_addresses(&self) -> u128 {
        self.v6.iter().fold(0u128, |acc, &(s, e)| {
            acc.saturating_add((e - s).saturating_add(1))
        })
    }

    /// The union of several sets.
    pub fn union<'a>(sets: impl IntoIterator<Item = &'a Self>) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for s in sets {
            v4.extend_from_slice(&s.v4);
            v6.extend_from_slice(&s.v6);
        }
        Self::from_ranges(v4, v6)
    }

    /// Bytes of [`IpRangeSet::encode`] (also the memory the ranges take).
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        HEADER_LEN + self.v4.len() * V4_LEN + self.v6.len() * V6_LEN
    }

    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the wire format counts ranges in u32: sets come from bounded blocklist texts or a decoded u32 count"
    )]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&[0, 0, 0]);
        out.extend_from_slice(&(self.v4.len() as u32).to_be_bytes());
        out.extend_from_slice(&(self.v6.len() as u32).to_be_bytes());
        for &(s, e) in &self.v4 {
            out.extend_from_slice(&s.to_be_bytes());
            out.extend_from_slice(&e.to_be_bytes());
        }
        for &(s, e) in &self.v6 {
            out.extend_from_slice(&s.to_be_bytes());
            out.extend_from_slice(&e.to_be_bytes());
        }
        out
    }

    /// Decode a canonical encoding of at most `max_len` bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::TooLarge`] when `bytes` is longer than `max_len`, [`DecodeError::Format`]
    /// for a wrong header or a length that does not match the counts, and
    /// [`DecodeError::NotCanonical`] when the ranges are not sorted, disjoint and non-adjacent.
    pub fn decode(bytes: &[u8], max_len: usize) -> Result<Self, DecodeError> {
        if bytes.len() > max_len {
            return Err(DecodeError::TooLarge);
        }
        if bytes.len() < HEADER_LEN || &bytes[..4] != MAGIC || bytes[4] != VERSION {
            return Err(DecodeError::Format);
        }
        if bytes[5..8] != [0, 0, 0] {
            return Err(DecodeError::Format);
        }
        let n4 = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let n6 = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let expected = n4
            .checked_mul(V4_LEN)
            .and_then(|a| n6.checked_mul(V6_LEN).and_then(|b| a.checked_add(b)))
            .and_then(|body| body.checked_add(HEADER_LEN))
            .ok_or(DecodeError::Format)?;
        if expected != bytes.len() {
            return Err(DecodeError::Format);
        }
        let mut v4 = Vec::with_capacity(n4);
        let mut at = HEADER_LEN;
        for _ in 0..n4 {
            let s = u32::from_be_bytes(chunk(&bytes[at..at + 4]));
            let e = u32::from_be_bytes(chunk(&bytes[at + 4..at + 8]));
            v4.push((s, e));
            at += V4_LEN;
        }
        let mut v6 = Vec::with_capacity(n6);
        for _ in 0..n6 {
            let s = u128::from_be_bytes(chunk(&bytes[at..at + 16]));
            let e = u128::from_be_bytes(chunk(&bytes[at + 16..at + 32]));
            v6.push((s, e));
            at += V6_LEN;
        }
        if !canonical(&v4) || !canonical(&v6) {
            return Err(DecodeError::NotCanonical);
        }
        Ok(Self { v4, v6 })
    }

    /// SHA-256 of the encoding, lowercase hex: the identity of the content.
    #[must_use]
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.encode()))
    }

    /// The first `limit` ranges as text: an address, a CIDR, or `first – last`.
    #[must_use]
    pub fn labels(&self, limit: usize) -> Vec<String> {
        self.v4
            .iter()
            .map(|&(s, e)| v4_label(s, e))
            .chain(self.v6.iter().map(|&(s, e)| v6_label(s, e)))
            .take(limit)
            .collect()
    }
}

fn chunk<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(b);
    out
}

/// Sorted, each range well-formed, and a gap between neighbours (merged).
fn canonical<T: Copy + Ord + MaxValue>(ranges: &[(T, T)]) -> bool {
    ranges.iter().all(|r| r.0 <= r.1)
        && ranges
            .windows(2)
            .all(|w| w[0].1 != T::MAX && w[0].1.next() < w[1].0)
}

/// The prefix length when `[s, e]` is exactly one CIDR network.
fn cidr_prefix(span_minus_one: u128, start: u128, bits: u32) -> Option<u32> {
    let size = span_minus_one.checked_add(1);
    match size {
        // The whole address space of u128 (only for IPv6 ::/0).
        None => (start == 0).then_some(0),
        Some(size) if size.is_power_of_two() && start.is_multiple_of(size) => {
            Some(bits - size.trailing_zeros())
        }
        _ => None,
    }
}

fn v4_label(start: u32, end: u32) -> String {
    let (first, last) = (Ipv4Addr::from(start), Ipv4Addr::from(end));
    if start == end {
        return first.to_string();
    }
    cidr_prefix(u128::from(end - start), u128::from(start), 32).map_or_else(
        || format!("{first} – {last}"),
        |prefix| format!("{first}/{prefix}"),
    )
}

fn v6_label(start: u128, end: u128) -> String {
    let (first, last) = (Ipv6Addr::from(start), Ipv6Addr::from(end));
    if start == end {
        return first.to_string();
    }
    cidr_prefix(end - start, start, 128).map_or_else(
        || format!("{first} – {last}"),
        |prefix| format!("{first}/{prefix}"),
    )
}

impl Serialize for IpRangeSet {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(self.encode()))
    }
}

impl<'de> Deserialize<'de> for IpRangeSet {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        // Base64 grows by 4/3; refuse before decoding anything larger than a set may be.
        if text.len() > MAX_ENCODED_BYTES / 3 * 4 + 4 {
            return Err(serde::de::Error::custom(DecodeError::TooLarge));
        }
        let bytes = B64
            .decode(text.as_bytes())
            .map_err(|e| serde::de::Error::custom(format_args!("{}: {e}", DecodeError::Format)))?;
        Self::decode(&bytes, MAX_ENCODED_BYTES).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn set(nets: &[&str]) -> IpRangeSet {
        IpRangeSet::from_networks(nets.iter().map(|n| n.parse::<IpNetwork>().unwrap()))
    }

    /// Simple xorshift so the oracle test is deterministic without a dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn lookups_canonicalize_mapped_addresses() {
        let s = set(&["10.0.0.0/8", "2001:db8::/32", "::ffff:198.51.100.0/120"]);
        assert!(s.contains(ip("10.255.0.1")));
        assert!(
            s.contains(ip("::ffff:10.1.2.3")),
            "mapped v6 is looked up as v4"
        );
        assert!(!s.contains(ip("11.0.0.0")));
        assert!(s.contains(ip("2001:db8:ffff::1")));
        assert!(!s.contains(ip("2001:db9::")));
        assert!(
            s.contains(ip("198.51.100.77")),
            "a mapped network is stored as IPv4"
        );
        assert_eq!(s.v4_ranges().len(), 2);
        assert_eq!(s.v6_ranges().len(), 1);
    }

    #[test]
    fn nat64_addresses_are_the_ipv4_host_and_themselves() {
        let s = set(&["198.51.100.0/24", "64:ff9b::203.0.113.9/128"]);
        assert!(
            s.contains(ip("64:ff9b::198.51.100.7")),
            "the IPv4 host it embeds"
        );
        assert!(s.contains(ip("64:ff9b::c633:6401")));
        assert!(!s.contains(ip("64:ff9b::1.1.1.1")));
        assert!(
            s.contains(ip("64:ff9b::203.0.113.9")),
            "listed in its NAT64 form"
        );
        // A NAT64 address is an IPv6 destination as well; a mapped one is IPv4 only.
        let all6 = set(&["::/0"]);
        assert!(all6.contains(ip("64:ff9b::1.1.1.1")));
        assert!(!all6.contains(ip("::ffff:1.1.1.1")));
        assert!(!all6.contains(ip("1.1.1.1")));
    }

    #[test]
    fn lookup_matches_a_brute_force_oracle() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for round in 0..50 {
            let mut v4 = Vec::new();
            for _ in 0..=(rng.next() % 40) {
                // A narrow universe makes overlaps and adjacency common.
                let start = (rng.next() % 2000) as u32;
                let len = (rng.next() % 50) as u32;
                v4.push((start, start + len));
            }
            let s = IpRangeSet::from_ranges(v4.clone(), Vec::new());
            for x in 0..2100u32 {
                let oracle = v4.iter().any(|&(a, b)| a <= x && x <= b);
                assert_eq!(
                    s.contains(IpAddr::V4(Ipv4Addr::from(x))),
                    oracle,
                    "round {round}, address {x}"
                );
            }
            assert!(canonical(s.v4_ranges()));
            let covered = (0..2100u32)
                .filter(|&x| v4.iter().any(|&(a, b)| a <= x && x <= b))
                .count() as u64;
            assert_eq!(s.v4_addresses(), covered);
        }
        // Same for IPv6, near the top of the space.
        for _ in 0..20 {
            let base = u128::MAX - 5000;
            let mut v6 = Vec::new();
            for _ in 0..=(rng.next() % 30) {
                let start = base + u128::from(rng.next() % 4900);
                let len = u128::from(rng.next() % 60);
                v6.push((start, start.saturating_add(len)));
            }
            let s = IpRangeSet::from_ranges(Vec::new(), v6.clone());
            for off in 0..5000u128 {
                let x = base + off;
                let oracle = v6.iter().any(|&(a, b)| a <= x && x <= b);
                assert_eq!(s.contains(IpAddr::V6(Ipv6Addr::from(x))), oracle);
            }
        }
    }
}
