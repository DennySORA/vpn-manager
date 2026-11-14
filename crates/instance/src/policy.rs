//! Destination policy applied to every payload flow: Gateway dials (TCP and UDP), the Provider
//! connector, and the sources of datagrams relayed back to a client.
//!
//! Evaluation order, strongest first. A later step can only refuse what the earlier ones let
//! through, and nothing a user configures can reopen what an earlier step refuses:
//!
//! 1. System invariants: loopback, unspecified, multicast, broadcast and link-local are never
//!    reachable. The host and other connections are out of reach by construction: every flow is
//!    opened with this Instance's `TunnelConnector`, which only reaches the tunnel's peer; the
//!    worker holds no host socket that dials anywhere.
//! 2. Address family: a family the `WireGuard` profile has no tunnel address for is refused by the
//!    connector (`TunnelConnector::supports`), never routed another way.
//! 3. Private and other non-global ranges need an `allow_private` allowance.
//! 4. Allowed destinations: when the profile lists any, the destination must be inside one
//!    (default deny).
//! 5. Allowed ports: when the profile lists any, the port must be inside one (default deny).
//! 6. Blocked ports.
//! 7. The deny overlay: IP blocklists, then active auto-bans.
//!
//! Steps 3–6 (the base) are fixed for a generation. The overlay is swapped atomically while the
//! worker runs (blocklist saved, attached or detached; ban added, expired or lifted); it only
//! ever adds deny entries, so a swap cannot open anything the base refuses.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;
use vpn_domain::ipset::IpRangeSet;
use vpn_domain::validation::{ban_scope, canonical_ip, is_private, is_special};
use vpn_domain::{PortRange, Text, tr};
use vpn_sync::{Mutex, RwLock};

/// Why a destination was refused. `code()` is stable and safe to show; it never includes the
/// destination itself (no destination metadata in logs or UI events).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// Loopback, unspecified, multicast, broadcast, link-local.
    SpecialAddress,
    /// Private/internal range not allowed by the `SecurityProfile`.
    PrivateNotAllowed,
    /// Not inside the profile's allowed destinations.
    DestinationNotAllowed,
    /// Not inside the profile's allowed ports.
    PortNotAllowed,
    BlockedPort,
    Blocklisted,
    /// Banned by the auto-ban engine.
    Banned,
}

impl Denied {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SpecialAddress => "DEST_SPECIAL",
            Self::PrivateNotAllowed => "DEST_PRIVATE",
            Self::DestinationNotAllowed => "DEST_NOT_ALLOWED",
            Self::PortNotAllowed => "DEST_PORT_NOT_ALLOWED",
            Self::BlockedPort => "DEST_PORT_BLOCKED",
            Self::Blocklisted => "DEST_BLOCKLISTED",
            Self::Banned => "DEST_BANNED",
        }
    }

    /// A short explanation for HTTP error replies and the connector's refusals.
    #[must_use]
    pub fn message(self) -> Text {
        match self {
            Self::SpecialAddress => tr!(
                "The destination is this host or a special-purpose address, which cannot be reached through the VPN Gateway",
                "目的地是本機或特殊用途位址，不允許經 VPN Gateway 連線",
                "宛先がこのホストまたは特殊用途のアドレスのため、VPN ゲートウェイ経由では接続できません"
            ),
            Self::PrivateNotAllowed => tr!(
                "The destination is in a private network, which the security profile does not allow",
                "目的地是私有網段，安全設定未允許",
                "宛先はプライベートネットワークで、セキュリティ設定で許可されていません"
            ),
            Self::DestinationNotAllowed => tr!(
                "The destination is not in the security profile's allowed destinations",
                "目的地不在安全設定允許的目的地清單中",
                "宛先がセキュリティ設定で許可された宛先の一覧にありません"
            ),
            Self::PortNotAllowed => tr!(
                "The destination port is not in the security profile's allowed ports",
                "目的 port 不在安全設定允許的 port 清單中",
                "宛先ポートがセキュリティ設定で許可されたポートの一覧にありません"
            ),
            Self::BlockedPort => tr!(
                "The destination port is blocked by the security profile",
                "目的 port 已被安全設定封鎖",
                "宛先ポートはセキュリティ設定でブロックされています"
            ),
            Self::Blocklisted => tr!(
                "The destination is in an IP blocklist",
                "目的地在 IP 封鎖清單中",
                "宛先が IP ブロックリストに含まれています"
            ),
            Self::Banned => tr!(
                "The destination is auto-banned",
                "目的地已被自動封鎖",
                "宛先は自動ブロックされています"
            ),
        }
    }
}

/// The base rules of a generation (steps 3–6).
#[derive(Debug, Clone, Default)]
pub struct BasePolicy {
    pub allow_private: Vec<IpNetwork>,
    pub allowed_destinations: Vec<IpNetwork>,
    pub allowed_ports: Vec<PortRange>,
    pub blocked_ports: Vec<u16>,
}

/// One installed blocklist overlay.
#[derive(Debug)]
pub struct Overlay {
    pub revision: u64,
    /// SHA-256 of `set`, computed when it was installed.
    pub digest: String,
    pub set: IpRangeSet,
}

impl Overlay {
    #[must_use]
    pub fn new(revision: u64, set: IpRangeSet) -> Self {
        Self {
            revision,
            digest: set.digest(),
            set,
        }
    }

    /// No blocklist (revision 0).
    #[must_use]
    pub fn empty() -> Self {
        Self::new(0, IpRangeSet::new())
    }
}

/// Active auto-bans: ban scope (an IPv4 address, or the first address of an IPv6 /64) → when
/// the ban ends. Bounded by the generation's `max_bans`.
#[derive(Debug)]
pub struct BanTable {
    until: HashMap<IpAddr, Instant>,
    max: usize,
}

impl BanTable {
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            until: HashMap::new(),
            max,
        }
    }

    /// Time left on the ban of `ip` (removing it when it ran out).
    fn remaining(&mut self, ip: IpAddr, now: Instant) -> Option<Duration> {
        match self.until.get(&ip) {
            Some(&end) if end > now => Some(end - now),
            Some(_) => {
                self.until.remove(&ip);
                None
            }
            None => None,
        }
    }

    /// Ban `ip` until `end`. Refused when the table is full even after dropping expired bans.
    fn insert(&mut self, ip: IpAddr, end: Instant, now: Instant) -> bool {
        if !self.until.contains_key(&ip) && self.until.len() >= self.max {
            self.until.retain(|_, e| *e > now);
            if self.until.len() >= self.max {
                return false;
            }
        }
        self.until.insert(ip, end);
        true
    }

    fn remove(&mut self, ip: IpAddr) -> bool {
        self.until.remove(&ip).is_some()
    }

    fn active(&mut self, now: Instant) -> usize {
        self.until.retain(|_, e| *e > now);
        self.until.len()
    }
}

/// The overlay of one generation, shared by the destination policy and the inbound guard.
#[derive(Debug)]
pub struct Enforcement {
    overlay: RwLock<Arc<Overlay>>,
    bans: Mutex<BanTable>,
}

impl Enforcement {
    #[must_use]
    pub fn new(overlay: Overlay, max_bans: usize) -> Self {
        Self {
            overlay: RwLock::new(Arc::new(overlay)),
            bans: Mutex::new(BanTable::new(max_bans)),
        }
    }

    pub fn overlay(&self) -> Arc<Overlay> {
        self.overlay.read().clone()
    }

    /// Install `next` atomically: a check sees either the old or the new overlay, never a mix.
    /// Refused (the current one stays) unless it is newer than the installed one.
    ///
    /// # Errors
    ///
    /// The installed overlay, unchanged, when `next` is not newer than it.
    pub fn swap(&self, next: Overlay) -> Result<Arc<Overlay>, Arc<Overlay>> {
        let mut current = self.overlay.write();
        if next.revision <= current.revision {
            return Err(current.clone());
        }
        let next = Arc::new(next);
        *current = next.clone();
        drop(current);
        Ok(next)
    }

    pub fn blocklisted(&self, ip: IpAddr) -> bool {
        self.overlay.read().set.contains(ip)
    }

    /// Time left on an active ban covering `ip` (its own, or its IPv6 /64's).
    pub fn banned(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        self.bans.lock().remaining(ban_scope(ip), now)
    }

    /// Ban `ip`'s scope: the IPv4 address, or the whole IPv6 /64 it is in.
    pub(crate) fn ban(&self, ip: IpAddr, end: Instant, now: Instant) -> bool {
        self.bans.lock().insert(ban_scope(ip), end, now)
    }

    /// Lift the ban covering `ip`; whether there was one.
    pub fn unban(&self, ip: IpAddr) -> bool {
        self.bans.lock().remove(ban_scope(ip))
    }

    pub fn active_bans(&self, now: Instant) -> usize {
        self.bans.lock().active(now)
    }
}

/// Destination rules of one generation: its fixed base and the shared overlay.
#[derive(Debug)]
pub struct DestinationPolicy {
    allow_private: Vec<IpNetwork>,
    allowed_destinations: Vec<IpNetwork>,
    allowed_ports: Vec<PortRange>,
    blocked_ports: HashSet<u16>,
    enforcement: Arc<Enforcement>,
    /// Test fixtures run on loopback; this switch does not exist in product builds.
    #[cfg(feature = "testing")]
    allow_loopback_for_tests: bool,
}

impl DestinationPolicy {
    pub fn new(base: BasePolicy, enforcement: Arc<Enforcement>) -> Self {
        Self {
            allow_private: base.allow_private,
            allowed_destinations: base.allowed_destinations,
            allowed_ports: base.allowed_ports,
            blocked_ports: base.blocked_ports.into_iter().collect(),
            enforcement,
            #[cfg(feature = "testing")]
            allow_loopback_for_tests: false,
        }
    }

    /// Policy for unit tests whose fixture servers listen on loopback. Every other rule
    /// (blocked ports, the deny overlay) still applies.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn loopback_for_tests(blocked_ports: Vec<u16>, deny: Vec<IpNetwork>) -> Self {
        Self::loopback_for_tests_with(
            BasePolicy {
                blocked_ports,
                ..BasePolicy::default()
            },
            deny,
        )
    }

    /// [`Self::loopback_for_tests`] with any base rules.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn loopback_for_tests_with(base: BasePolicy, deny: Vec<IpNetwork>) -> Self {
        let overlay = Overlay::new(1, IpRangeSet::from_networks(deny));
        let mut p = Self::new(base, Arc::new(Enforcement::new(overlay, 1024)));
        p.allow_loopback_for_tests = true;
        p
    }

    #[must_use]
    pub const fn enforcement(&self) -> &Arc<Enforcement> {
        &self.enforcement
    }

    /// Judge one destination against the invariants, the profile and the overlay.
    ///
    /// # Errors
    ///
    /// The first rule `dst` breaks, as a [`Denied`] reason.
    pub fn check(&self, dst: SocketAddr) -> Result<(), Denied> {
        // Every rule judges the host: an IPv4-mapped or NAT64 address is the IPv4 host it embeds.
        let ip: IpAddr = canonical_ip(dst.ip());
        #[cfg(feature = "testing")]
        let loopback_ok = self.allow_loopback_for_tests && ip.is_loopback();
        #[cfg(not(feature = "testing"))]
        let loopback_ok = false;
        // 1. Invariants.
        if is_special(ip) && !loopback_ok {
            return Err(Denied::SpecialAddress);
        }
        // 2. Address family: the connector's `supports` (see the module docs).
        // 3. Private ranges need an allowance.
        if is_private(ip) && !self.allow_private.iter().any(|n| n.contains(ip)) {
            return Err(Denied::PrivateNotAllowed);
        }
        // 4. Allowed destinations (default deny when listed).
        if !self.allowed_destinations.is_empty()
            && !self.allowed_destinations.iter().any(|n| n.contains(ip))
        {
            return Err(Denied::DestinationNotAllowed);
        }
        // 5. Allowed ports (default deny when listed).
        if !self.allowed_ports.is_empty()
            && !self.allowed_ports.iter().any(|r| r.contains(dst.port()))
        {
            return Err(Denied::PortNotAllowed);
        }
        // 6. Blocked ports.
        if self.blocked_ports.contains(&dst.port()) {
            return Err(Denied::BlockedPort);
        }
        // 7. The overlay: blocklists (a NAT64 address listed in either form), then bans.
        if self.enforcement.blocklisted(dst.ip()) {
            return Err(Denied::Blocklisted);
        }
        if self.enforcement.banned(ip, Instant::now()).is_some() {
            return Err(Denied::Banned);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(v: &[&str]) -> Vec<IpNetwork> {
        v.iter().map(|n| n.parse().unwrap()).collect()
    }

    fn policy(base: BasePolicy, deny: &[&str]) -> DestinationPolicy {
        let overlay = Overlay::new(1, IpRangeSet::from_networks(nets(deny)));
        DestinationPolicy::new(base, Arc::new(Enforcement::new(overlay, 16)))
    }

    #[test]
    fn invariants_beat_user_allowances() {
        let policy = policy(
            BasePolicy {
                allow_private: nets(&["10.0.0.0/8"]),
                blocked_ports: vec![25],
                ..BasePolicy::default()
            },
            &["203.0.113.0/24"],
        );
        let check = |s: &str| policy.check(s.parse().unwrap());
        assert_eq!(check("127.0.0.1:80"), Err(Denied::SpecialAddress));
        assert_eq!(check("[::ffff:127.0.0.1]:80"), Err(Denied::SpecialAddress));
        assert_eq!(check("[fe80::1]:80"), Err(Denied::SpecialAddress));
        assert_eq!(check("192.168.1.1:80"), Err(Denied::PrivateNotAllowed));
        assert_eq!(check("10.1.2.3:80"), Ok(()));
        assert_eq!(check("1.1.1.1:25"), Err(Denied::BlockedPort));
        assert_eq!(
            check("203.0.113.9:443"),
            Err(Denied::PrivateNotAllowed),
            "documentation range is private"
        );
        assert_eq!(check("1.1.1.1:443"), Ok(()));
        let next = Overlay::new(2, IpRangeSet::from_networks(nets(&["1.1.1.0/24"])));
        policy.enforcement().swap(next).unwrap();
        assert_eq!(check("1.1.1.1:443"), Err(Denied::Blocklisted));
    }

    #[test]
    fn the_order_is_invariants_private_allowed_destinations_ports_blocked_overlay() {
        let p = policy(
            BasePolicy {
                allow_private: nets(&["10.99.0.0/24"]),
                allowed_destinations: nets(&[
                    "10.99.0.1/32",
                    "198.18.0.0/15",
                    "1.1.0.0/16",
                    "::/0",
                ]),
                allowed_ports: vec![
                    PortRange { start: 80, end: 80 },
                    PortRange {
                        start: 8000,
                        end: 8999,
                    },
                    PortRange { start: 25, end: 25 },
                ],
                blocked_ports: vec![25, 8080],
            },
            &["1.1.1.0/24", "2a00:1450::/32"],
        );
        let check = |s: &str| p.check(s.parse().unwrap());
        // 1: an allow rule never reopens a special address.
        assert_eq!(check("127.0.0.1:80"), Err(Denied::SpecialAddress));
        // 3 before 4: listed but private and not allowed as private.
        assert_eq!(check("198.18.0.1:80"), Err(Denied::PrivateNotAllowed));
        // 4: allowed as private, not listed as a destination.
        assert_eq!(check("10.99.0.2:80"), Err(Denied::DestinationNotAllowed));
        assert_eq!(check("10.99.0.1:80"), Ok(()));
        // 4: a public address outside the allowed destinations.
        assert_eq!(check("9.9.9.9:80"), Err(Denied::DestinationNotAllowed));
        // 5: listed destination, port not allowed.
        assert_eq!(check("1.1.9.9:443"), Err(Denied::PortNotAllowed));
        assert_eq!(check("1.1.9.9:8500"), Ok(()));
        // 6 after 5: allowed port range, but blocked.
        assert_eq!(check("1.1.9.9:8080"), Err(Denied::BlockedPort));
        assert_eq!(check("1.1.9.9:25"), Err(Denied::BlockedPort));
        // 7: allowed by every base rule, but blocklisted.
        assert_eq!(check("1.1.1.1:80"), Err(Denied::Blocklisted));
        assert_eq!(check("[2a00:1450::5]:80"), Err(Denied::Blocklisted));
        assert_eq!(check("[2606:4700::1]:80"), Ok(()));
        // A ban comes last and is lifted alone; the blocklist stays.
        let now = Instant::now();
        assert!(p.enforcement().ban(
            "1.1.9.9".parse().unwrap(),
            now + Duration::from_secs(60),
            now
        ));
        assert_eq!(check("1.1.9.9:80"), Err(Denied::Banned));
        assert!(p.enforcement().ban(
            "1.1.1.1".parse().unwrap(),
            now + Duration::from_secs(60),
            now
        ));
        assert!(p.enforcement().unban("1.1.1.1".parse().unwrap()));
        assert_eq!(check("1.1.1.1:80"), Err(Denied::Blocklisted));
    }

    #[test]
    fn nat64_addresses_meet_the_rules_of_the_ipv4_host_they_embed() {
        let p = policy(
            BasePolicy {
                allow_private: nets(&["10.0.0.0/8"]),
                ..BasePolicy::default()
            },
            &["9.9.9.0/24"],
        );
        let check = |s: &str| p.check(s.parse().unwrap());
        assert_eq!(check("[64:ff9b::9.9.9.9]:443"), Err(Denied::Blocklisted));
        assert_eq!(
            check("[64:ff9b::127.0.0.1]:443"),
            Err(Denied::SpecialAddress)
        );
        assert_eq!(
            check("[64:ff9b::a9fe:a9fe]:80"),
            Err(Denied::SpecialAddress)
        );
        assert_eq!(
            check("[64:ff9b::192.168.1.1]:443"),
            Err(Denied::PrivateNotAllowed)
        );
        assert_eq!(
            check("[64:ff9b::10.1.2.3]:443"),
            Ok(()),
            "allowed as private"
        );
        assert_eq!(
            check("[64:ff9b:1::1.1.1.1]:443"),
            Err(Denied::PrivateNotAllowed),
            "the local-use prefix"
        );
        assert_eq!(check("[64:ff9b::1.1.1.1]:443"), Ok(()));
        // A ban of the host covers its NAT64 form, and lifting either form lifts it.
        let now = Instant::now();
        let host: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(
            p.enforcement()
                .ban(host, now + Duration::from_secs(60), now)
        );
        assert_eq!(check("[64:ff9b::1.1.1.1]:443"), Err(Denied::Banned));
        assert!(p.enforcement().unban("64:ff9b::101:101".parse().unwrap()));
        assert_eq!(check("1.1.1.1:443"), Ok(()));
    }

    #[test]
    fn an_overlay_swap_is_atomic_and_only_moves_forward() {
        let e = Enforcement::new(
            Overlay::new(3, IpRangeSet::from_networks(nets(&["192.0.2.0/24"]))),
            4,
        );
        let stale = e.swap(Overlay::new(3, IpRangeSet::new())).unwrap_err();
        assert_eq!(
            stale.revision, 3,
            "same revision: refused, the current one stays"
        );
        assert!(e.blocklisted("192.0.2.1".parse().unwrap()));
        let installed = e
            .swap(Overlay::new(
                4,
                IpRangeSet::from_networks(nets(&["198.51.100.0/24"])),
            ))
            .unwrap();
        assert_eq!(installed.digest, installed.set.digest());
        assert!(!e.blocklisted("192.0.2.1".parse().unwrap()));
        assert!(e.blocklisted("::ffff:198.51.100.7".parse().unwrap()));
        assert!(e.swap(Overlay::new(2, IpRangeSet::new())).is_err());
    }
}
