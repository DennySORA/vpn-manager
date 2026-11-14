//! Inbound guard of forwarded ports: for every new connection that arrives through the tunnel on
//! a forwarded port, whether its source may connect at all.
//!
//! Order: a source that is not a unicast address is refused; then the blocklist overlay (shared
//! with the destination policy); then an active ban. With auto-ban on, the source's new
//! connections are then counted in a sliding window; the connection that takes a source over the
//! threshold is refused, the source is banned for `ban_secs` and the ban is reported to the
//! manager, which persists it (and carries it into the next generation). Addresses the connection
//! itself needs (its `WireGuard` peer, its DNS servers) are never counted or banned. Lifting a ban
//! (`Unban`) never lifts a blocklist entry.
//!
//! A source is counted and banned by its ban scope: an IPv4 address alone, an IPv6 address with
//! the whole /64 it is in ([`ban_scope`]), since one host can rotate through the addresses of its
//! subnet at will. The blocklist still judges the exact address.
//!
//! The window is split into [`SLOTS`] slots, so a connection is counted for between
//! `window - window/SLOTS` and `window` after it arrived: the count never includes anything older
//! than the window (no false ban), and can miss at most the oldest slot.
//!
//! Bounded: at most [`TRACKED_SOURCES`] sources are counted at once (the least recently seen is
//! dropped first), at most `max_bans` sources are banned (a source over the threshold while the
//! table is full is refused without a ban), and ban reports wait in a bounded queue (a full queue
//! loses the report, never the ban).

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use lru::LruCache;
use tokio::sync::mpsc;
use vpn_domain::validation::{ban_scope, is_special};
use vpn_domain::{AutoBanSettings, Text, tr};
use vpn_ipc::worker::BanReport;
use vpn_sync::Mutex;

use crate::policy::Enforcement;

/// Sources whose new connections are counted at once.
pub const TRACKED_SOURCES: usize = 16_384;
/// Slots of the sliding window.
pub const SLOTS: u64 = 10;
/// [`SLOTS`] as an array length.
#[expect(
    clippy::cast_possible_truncation,
    reason = "SLOTS is the constant 10, which fits every usize"
)]
const SLOT_COUNT: usize = SLOTS as usize;
/// Ban reports waiting for the manager.
const REPORT_QUEUE: usize = 64;

/// Why an inbound connection was refused. Carries no address: safe to log and count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundDenied {
    /// Not a unicast source (loopback, unspecified, multicast, broadcast, link-local).
    InvalidSource,
    Blocklisted,
    /// Banned by auto-ban; `remaining` until the ban ends.
    Banned {
        remaining: Duration,
    },
    /// Over the threshold while the ban table is full: refused without a ban.
    RateLimited,
}

impl InboundDenied {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidSource => "SOURCE_INVALID",
            Self::Blocklisted => "SOURCE_BLOCKLISTED",
            Self::Banned { .. } => "SOURCE_BANNED",
            Self::RateLimited => "SOURCE_RATE_LIMITED",
        }
    }

    #[must_use]
    pub fn message(&self) -> Text {
        match self {
            Self::InvalidSource => tr!(
                "Invalid source address",
                "來源位址無效",
                "送信元アドレスが無効です"
            ),
            Self::Blocklisted => tr!(
                "The source is in an IP blocklist",
                "來源在 IP 封鎖清單中",
                "送信元が IP ブロックリストに含まれています"
            ),
            Self::Banned { .. } => tr!(
                "The source is auto-banned",
                "來源已被自動封鎖",
                "送信元は自動ブロックされています"
            ),
            Self::RateLimited => tr!(
                "Too many new connections from the source (the auto-ban limit is reached)",
                "來源的新連線過多（自動封鎖數已達上限）",
                "送信元からの新しい接続が多すぎます（自動ブロック数が上限に達しています）"
            ),
        }
    }
}

/// What the guard decided, cumulatively.
#[derive(Debug, Default)]
pub struct InboundCounters {
    pub admitted: AtomicU64,
    pub refused_invalid: AtomicU64,
    pub refused_blocklisted: AtomicU64,
    pub refused_banned: AtomicU64,
    pub refused_rate: AtomicU64,
    pub bans: AtomicU64,
    /// Bans whose report did not fit the queue (still enforced here).
    pub reports_dropped: AtomicU64,
}

/// New connections of one source in the last `SLOTS` slots.
#[derive(Debug, Clone)]
struct Window {
    head: u64,
    counts: [u32; SLOT_COUNT],
}

impl Window {
    const fn new(slot: u64) -> Self {
        Self {
            head: slot,
            counts: [0; SLOT_COUNT],
        }
    }

    /// Count one connection in `slot`; the total over the window.
    fn record(&mut self, slot: u64) -> u64 {
        if slot > self.head {
            if slot - self.head >= SLOTS {
                self.counts = [0; SLOT_COUNT];
            } else {
                for s in self.head + 1..=slot {
                    self.counts[(s % SLOTS) as usize] = 0;
                }
            }
            self.head = slot;
        }
        let i = (self.head % SLOTS) as usize;
        self.counts[i] = self.counts[i].saturating_add(1);
        self.counts.iter().map(|&c| u64::from(c)).sum()
    }
}

/// The inbound side of a generation's security policy. Cheap to call from any task: one lock
/// for the overlay read, one for the ban table, one for the window of the source.
#[derive(Debug)]
pub struct InboundGuard {
    enforcement: Arc<Enforcement>,
    settings: AutoBanSettings,
    /// Ban scopes of the addresses the connection needs.
    exempt: HashSet<IpAddr>,
    /// Counts by ban scope.
    windows: Mutex<LruCache<IpAddr, Window>>,
    epoch: Instant,
    slot_ms: u64,
    reports: mpsc::Sender<BanReport>,
    pub counters: InboundCounters,
}

impl InboundGuard {
    /// A guard sharing `enforcement` (blocklists, bans) with the destination policy. Ban reports
    /// arrive on the returned receiver.
    pub fn new(
        enforcement: Arc<Enforcement>,
        settings: AutoBanSettings,
        exempt: impl IntoIterator<Item = IpAddr>,
    ) -> (Arc<Self>, mpsc::Receiver<BanReport>) {
        let (tx, rx) = mpsc::channel(REPORT_QUEUE);
        let slot_ms = (u64::from(settings.window_secs.max(1)) * 1000 / SLOTS).max(1);
        let guard = Arc::new(Self {
            enforcement,
            settings,
            exempt: exempt.into_iter().map(ban_scope).collect(),
            windows: Mutex::new(LruCache::unbounded()),
            epoch: Instant::now(),
            slot_ms,
            reports: tx,
            counters: InboundCounters::default(),
        });
        (guard, rx)
    }

    pub const fn enforcement(&self) -> &Arc<Enforcement> {
        &self.enforcement
    }

    pub const fn settings(&self) -> &AutoBanSettings {
        &self.settings
    }

    /// Carry a ban of an earlier generation over (`remaining` of it is left); an IPv6 source
    /// bans its /64. Exempt and non-unicast sources are never banned.
    pub fn restore_ban(&self, source: IpAddr, remaining: Duration) -> bool {
        let source = ban_scope(source);
        if is_special(source) || self.exempt.contains(&source) || remaining.is_zero() {
            return false;
        }
        let now = Instant::now();
        self.enforcement.ban(source, now + remaining, now)
    }

    /// Decide on one new inbound connection from `source`. Call it once per new TCP connection
    /// (or new UDP flow) on a forwarded port, before connecting it to its target; on `Err` close
    /// the connection at once.
    ///
    /// # Errors
    ///
    /// The [`InboundDenied`] reason: an invalid source, a blocklisted or banned one, or one that
    /// just went over the auto-ban threshold.
    pub fn admit(&self, source: IpAddr) -> Result<(), InboundDenied> {
        self.admit_at(source, Instant::now())
    }

    /// [`Self::admit`] at a given time (tests).
    ///
    /// # Errors
    ///
    /// As [`Self::admit`].
    pub fn admit_at(&self, source: IpAddr, now: Instant) -> Result<(), InboundDenied> {
        // Each check judges the host an IPv4-mapped or NAT64 address embeds (`canonical_ip`).
        let c = &self.counters;
        if is_special(source) {
            c.refused_invalid.fetch_add(1, Ordering::Relaxed);
            return Err(InboundDenied::InvalidSource);
        }
        if self.enforcement.blocklisted(source) {
            c.refused_blocklisted.fetch_add(1, Ordering::Relaxed);
            return Err(InboundDenied::Blocklisted);
        }
        if let Some(remaining) = self.enforcement.banned(source, now) {
            c.refused_banned.fetch_add(1, Ordering::Relaxed);
            return Err(InboundDenied::Banned { remaining });
        }
        // From here on the source is its scope: the address, or the IPv6 /64 it is in.
        let source = ban_scope(source);
        if !self.settings.enabled || self.exempt.contains(&source) {
            c.admitted.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let elapsed_ms = u64::try_from(now.saturating_duration_since(self.epoch).as_millis())
            .unwrap_or(u64::MAX);
        let slot = elapsed_ms / self.slot_ms;
        let count = {
            let mut windows = self.windows.lock();
            let count = windows
                .get_or_insert_mut(source, || Window::new(slot))
                .record(slot);
            while windows.len() > TRACKED_SOURCES {
                windows.pop_lru();
            }
            drop(windows);
            count
        };
        if count <= u64::from(self.settings.threshold) {
            c.admitted.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let ban = Duration::from_secs(u64::from(self.settings.ban_secs));
        if !self.enforcement.ban(source, now + ban, now) {
            c.refused_rate.fetch_add(1, Ordering::Relaxed);
            return Err(InboundDenied::RateLimited);
        }
        self.windows.lock().pop(&source);
        c.bans.fetch_add(1, Ordering::Relaxed);
        let (secs, threshold) = (self.settings.window_secs, self.settings.threshold);
        let noun = if count == 1 {
            "connection"
        } else {
            "connections"
        };
        let report = BanReport {
            source,
            reason: tr!(
                "{count} new {noun} within {secs} s (threshold {threshold})",
                "{secs} 秒內 {count} 個新連線（門檻 {threshold}）",
                "{secs} 秒以内に {count} 件の新しい接続（しきい値 {threshold}）"
            ),
            ban_secs: self.settings.ban_secs,
            policy_revision: self.enforcement.overlay().revision,
        };
        if self.reports.try_send(report).is_err() {
            c.reports_dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("auto-ban report queue full; the ban holds but is not persisted");
        }
        c.refused_banned.fetch_add(1, Ordering::Relaxed);
        Err(InboundDenied::Banned { remaining: ban })
    }

    /// Lift the ban of `source`'s scope (and forget its count); whether it was banned. A
    /// blocklist entry for it still applies.
    pub fn unban(&self, source: IpAddr) -> bool {
        let source = ban_scope(source);
        self.windows.lock().pop(&source);
        self.enforcement.unban(source)
    }

    /// Sources (ban scopes) currently counted (bounded by [`TRACKED_SOURCES`]).
    pub fn tracked(&self) -> usize {
        self.windows.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use vpn_domain::ipset::IpRangeSet;

    use super::*;
    use crate::policy::Overlay;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn settings(threshold: u32, window_secs: u32, ban_secs: u32, max_bans: u32) -> AutoBanSettings {
        AutoBanSettings {
            enabled: true,
            window_secs,
            threshold,
            ban_secs,
            max_bans,
        }
    }

    fn guard(
        s: AutoBanSettings,
        deny: &[&str],
        exempt: &[&str],
    ) -> (Arc<InboundGuard>, mpsc::Receiver<BanReport>) {
        let overlay = Overlay::new(
            7,
            IpRangeSet::from_networks(deny.iter().map(|n| n.parse().unwrap())),
        );
        let max = s.max_bans as usize;
        InboundGuard::new(
            Arc::new(Enforcement::new(overlay, max)),
            s,
            exempt.iter().map(|e| ip(e)),
        )
    }

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn without_auto_ban_only_blocklists_and_invalid_sources_are_refused() {
        let off = AutoBanSettings {
            enabled: false,
            ..AutoBanSettings::default()
        };
        let (g, _rx) = guard(off, &["203.0.113.0/24"], &[]);
        let t = Instant::now();
        for _ in 0..1000 {
            assert_eq!(g.admit_at(ip("198.51.100.1"), t), Ok(()));
        }
        assert_eq!(
            g.admit_at(ip("203.0.113.9"), t),
            Err(InboundDenied::Blocklisted)
        );
        assert_eq!(
            g.admit_at(ip("::ffff:203.0.113.9"), t),
            Err(InboundDenied::Blocklisted),
            "mapped addresses are the IPv4 they map"
        );
        assert_eq!(
            g.admit_at(ip("64:ff9b::203.0.113.9"), t),
            Err(InboundDenied::Blocklisted),
            "so are NAT64 addresses"
        );
        assert_eq!(
            g.admit_at(ip("64:ff9b::127.0.0.1"), t),
            Err(InboundDenied::InvalidSource)
        );
        for bad in ["127.0.0.1", "0.0.0.0", "224.0.0.1", "fe80::1", "::"] {
            assert_eq!(
                g.admit_at(ip(bad), t),
                Err(InboundDenied::InvalidSource),
                "{bad}"
            );
        }
        assert_eq!(g.tracked(), 0, "nothing is counted while auto-ban is off");
        assert_eq!(g.counters.admitted.load(Ordering::Relaxed), 1000);
    }

    #[test]
    fn crossing_the_threshold_bans_reports_and_expires() {
        let (g, mut rx) = guard(settings(5, 10, 60, 100), &[], &[]);
        let src = ip("198.51.100.7");
        let t0 = g.epoch;
        for i in 0..5 {
            assert_eq!(g.admit_at(src, t0 + S * i), Ok(()), "connection {i}");
        }
        // The sixth within the window is refused and bans the source.
        assert_eq!(
            g.admit_at(src, t0 + S * 5),
            Err(InboundDenied::Banned { remaining: S * 60 })
        );
        let report = rx.try_recv().unwrap();
        assert_eq!(report.source, src);
        assert_eq!(report.ban_secs, 60);
        assert_eq!(report.policy_revision, 7);
        assert_eq!(report.reason.zh_tw, "10 秒內 6 個新連線（門檻 5）");
        // While banned every connection is refused (and not reported again).
        assert_matches!(
            g.admit_at(src, t0 + S * 30),
            Err(InboundDenied::Banned { .. })
        );
        assert!(rx.try_recv().is_err());
        // Other sources are not affected.
        assert_eq!(g.admit_at(ip("198.51.100.8"), t0 + S * 30), Ok(()));
        // After the ban the source starts with a fresh count.
        let after = t0 + S * 66;
        for i in 0..5 {
            assert_eq!(g.admit_at(src, after + S * i), Ok(()), "after ban {i}");
        }
        assert_eq!(g.counters.bans.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn an_ipv6_source_is_counted_and_banned_with_its_64() {
        let (g, mut rx) = guard(settings(5, 10, 60, 100), &[], &[]);
        let t = g.epoch;
        // One host rotating through its subnet: six addresses, six connections.
        for i in 1..=5 {
            let src = ip(&format!("2001:4860:1:2::{i}"));
            assert_eq!(g.admit_at(src, t), Ok(()), "connection {i}");
        }
        assert_eq!(g.tracked(), 1, "one /64 counted once");
        assert_matches!(
            g.admit_at(ip("2001:4860:1:2:aaaa::6"), t),
            Err(InboundDenied::Banned { .. })
        );
        let report = rx.try_recv().unwrap();
        assert_eq!(report.source, ip("2001:4860:1:2::"), "reported as the /64");
        assert_eq!(report.reason.zh_tw, "10 秒內 6 個新連線（門檻 5）");
        // Every address of the /64 is banned, as a source and as a destination; the next /64
        // and IPv4 sources are not.
        assert_matches!(
            g.admit_at(ip("2001:4860:1:2:ffff:ffff:ffff:ffff"), t),
            Err(InboundDenied::Banned { .. })
        );
        assert!(g.enforcement().banned(ip("2001:4860:1:2::99"), t).is_some());
        assert_eq!(g.admit_at(ip("2001:4860:1:3::1"), t), Ok(()));
        assert_eq!(g.admit_at(ip("198.51.100.1"), t), Ok(()));
        // Lifting it through any of its addresses lifts the /64.
        assert!(g.unban(ip("2001:4860:1:2::1234")));
        assert_eq!(g.admit_at(ip("2001:4860:1:2::6"), t), Ok(()));
        // A ban carried over from an address covers its /64.
        assert!(g.restore_ban(ip("2001:4860:9:9::1"), S * 30));
        assert_matches!(
            g.admit_at(ip("2001:4860:9:9::2"), t),
            Err(InboundDenied::Banned { .. })
        );
        assert_eq!(g.enforcement().active_bans(t), 1);
    }

    #[test]
    fn exempt_sources_are_never_banned_but_blocklists_still_apply() {
        let (g, mut rx) = guard(
            settings(1, 10, 60, 100),
            &[],
            &["10.64.0.1", "198.51.100.200"],
        );
        let t = g.epoch;
        for _ in 0..50 {
            assert_eq!(g.admit_at(ip("10.64.0.1"), t), Ok(()));
            assert_eq!(g.admit_at(ip("::ffff:198.51.100.200"), t), Ok(()));
        }
        assert!(rx.try_recv().is_err());
        assert!(!g.restore_ban(ip("10.64.0.1"), S * 60));
    }

    #[test]
    fn unban_lifts_the_ban_and_its_count_but_not_a_blocklist() {
        let (g, _rx) = guard(settings(1, 10, 600, 10), &["203.0.113.0/24"], &[]);
        let t = g.epoch;
        let src = ip("198.51.100.9");
        assert_eq!(g.admit_at(src, t), Ok(()));
        assert_matches!(g.admit_at(src, t), Err(InboundDenied::Banned { .. }));
        assert!(g.unban(src));
        assert!(!g.unban(src));
        assert_eq!(g.admit_at(src, t), Ok(()), "a fresh count after the unban");
        // A blocklisted address that was also banned stays refused after the unban.
        let listed = ip("203.0.113.5");
        g.enforcement().ban(listed, t + S * 600, t);
        assert!(g.unban(listed));
        assert_eq!(g.admit_at(listed, t), Err(InboundDenied::Blocklisted));
    }

    #[test]
    fn carried_over_bans_hold_and_the_count_map_is_bounded() {
        let (g, mut rx) = guard(settings(1_000, 10, 600, 10), &[], &[]);
        assert!(g.restore_ban(ip("::ffff:192.0.2.77"), S * 30));
        assert_matches!(g.admit(ip("192.0.2.77")), Err(InboundDenied::Banned { .. }));
        assert!(!g.restore_ban(ip("127.0.0.1"), S * 30));
        let t = g.epoch;
        for i in 0..(u32::try_from(TRACKED_SOURCES).unwrap() + 100) {
            let src = IpAddr::from(std::net::Ipv4Addr::from(0x0b00_0000 + i));
            assert_eq!(g.admit_at(src, t), Ok(()));
        }
        assert_eq!(g.tracked(), TRACKED_SOURCES);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_full_report_queue_loses_the_report_not_the_ban() {
        let (g, _rx) = guard(settings(1, 10, 600, 10_000), &[], &[]);
        let t = g.epoch;
        for i in 0..(u32::try_from(REPORT_QUEUE).unwrap() + 5) {
            let src = IpAddr::from(std::net::Ipv4Addr::from(0xcb00_7100 + i));
            assert_eq!(g.admit_at(src, t), Ok(()));
            assert_matches!(g.admit_at(src, t), Err(InboundDenied::Banned { .. }));
        }
        assert_eq!(g.counters.reports_dropped.load(Ordering::Relaxed), 5);
        assert_eq!(g.enforcement().active_bans(t), REPORT_QUEUE + 5);
    }
}
