//! UDP of a forward that goes straight into the strict sandbox (`udp_direct`): the worker holds
//! no socket for it. The sandbox's packet filter writes every admitted datagram into the TUN
//! device as it came, so the App's own socket on the tunnel port reads the real source and
//! answers from that port; this is the forward's side of it — the decisions the relayed UDP
//! makes for a new flow, in the same order (evidence, the gate and the lease (the filter's),
//! the inbound guard, the forward's limit), and the forward's counts. Called from the packet
//! path: atomics and the guard only, never a wait.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use ipnetwork::IpNetwork;
use vpn_tunnel::DirectUdpPolicy;

use crate::counters::ForwardCounters;
use crate::inbound::InboundGuard;

/// One forward's policy for its direct UDP port.
pub(super) struct Direct {
    pub guard: Arc<InboundGuard>,
    /// The tunnel's own networks: sources inside them never count as evidence.
    pub networks: Arc<Vec<IpNetwork>>,
    pub epoch: Instant,
    pub counters: Arc<ForwardCounters>,
    /// Flows at once: the forward's connection limit.
    pub max: u64,
}

impl DirectUdpPolicy for Direct {
    fn admit(&self, source: IpAddr) -> bool {
        let source = source.to_canonical();
        let c = &self.counters;
        super::arrived(c, &self.networks, self.epoch, source, true);
        if !super::admit(&self.guard, c, source) {
            return false;
        }
        if c.udp_active.load(Ordering::Relaxed) >= self.max {
            c.refused_limit.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    fn refused(&self, source: IpAddr) {
        let c = &self.counters;
        super::arrived(c, &self.networks, self.epoch, source.to_canonical(), true);
        c.refused_closed.fetch_add(1, Ordering::Relaxed);
    }

    fn started(&self) {
        self.counters.accepted.fetch_add(1, Ordering::Relaxed);
        self.counters.udp_active.fetch_add(1, Ordering::Relaxed);
    }

    fn ended(&self) {
        // Paired with `started` by the filter; never below zero all the same.
        let active = &self.counters.udp_active;
        let decremented =
            active.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
        if decremented.is_err() {
            tracing::trace!("direct UDP flow ended without being counted started");
        }
    }

    fn received(&self, bytes: u64) {
        self.counters.bytes_in.fetch_add(bytes, Ordering::Relaxed);
    }

    fn sent(&self, bytes: u64) {
        self.counters.bytes_out.fetch_add(bytes, Ordering::Relaxed);
    }

    fn dropped(&self) {
        self.counters.udp_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use vpn_domain::AutoBanSettings;
    use vpn_domain::ipset::IpRangeSet;

    use super::*;
    use crate::policy::{Enforcement, Overlay};

    fn direct(max: u64, deny: &[&str], auto_ban: AutoBanSettings) -> Direct {
        let overlay = Overlay::new(
            1,
            IpRangeSet::from_networks(deny.iter().map(|n| n.parse().unwrap())),
        );
        let (guard, _reports) = InboundGuard::new(
            Arc::new(Enforcement::new(overlay, 16)),
            auto_ban,
            Vec::new(),
        );
        Direct {
            guard,
            networks: Arc::new(vec!["10.99.0.2/32".parse().unwrap()]),
            epoch: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
            counters: Arc::new(ForwardCounters::default()),
            max,
        }
    }

    fn get(c: &std::sync::atomic::AtomicU64) -> u64 {
        c.load(Ordering::Relaxed)
    }

    #[test]
    fn a_new_remote_end_meets_the_relays_decisions_in_its_order() {
        let d = direct(2, &["203.0.113.0/24"], AutoBanSettings::default());
        let c = d.counters.clone();
        let outside: IpAddr = "192.88.99.7".parse().unwrap();
        // Admitted: an arrival from outside is evidence; the flow counts once the filter tracks it.
        assert!(d.admit(outside));
        assert!(get(&c.external_udp) > 0 && get(&c.external_tcp) == 0);
        assert_eq!(get(&c.accepted), 0, "not tracked yet");
        d.started();
        assert_eq!((get(&c.accepted), get(&c.udp_active)), (1, 1));
        // A blocklisted source is refused by the guard and counted as such.
        assert!(!d.admit("203.0.113.5".parse().unwrap()));
        assert_eq!(get(&c.refused_blocklisted), 1);
        // An IPv4-mapped source is judged as the IPv4 host it is.
        assert!(!d.admit("::ffff:203.0.113.6".parse().unwrap()));
        assert_eq!(get(&c.refused_blocklisted), 2);
        // Not a unicast source.
        assert!(!d.admit("224.0.0.1".parse().unwrap()));
        assert_eq!(get(&c.refused_invalid), 1);
        // The forward's limit: two flows at once.
        assert!(d.admit("198.51.100.9".parse().unwrap()));
        d.started();
        assert!(!d.admit("198.51.100.10".parse().unwrap()));
        assert_eq!(get(&c.refused_limit), 1);
        // One ends: room for the next.
        d.ended();
        assert_eq!(get(&c.udp_active), 1);
        assert!(d.admit("198.51.100.10".parse().unwrap()));
        // Closed (no lease, or the gate not open): evidence still, and counted as not open.
        d.refused(outside);
        assert_eq!(get(&c.refused_closed), 1);
        // The counts of the flows' payload.
        d.received(100);
        d.sent(40);
        d.dropped();
        assert_eq!(
            (get(&c.bytes_in), get(&c.bytes_out), get(&c.udp_dropped)),
            (100, 40, 1)
        );
        // `ended` never takes the count below zero.
        d.ended();
        d.ended();
        assert_eq!(get(&c.udp_active), 0);
    }

    #[test]
    fn a_flood_of_new_flows_from_one_source_is_banned_as_on_the_relay() {
        let d = direct(
            1000,
            &[],
            AutoBanSettings {
                enabled: true,
                window_secs: 10,
                threshold: 3,
                ban_secs: 60,
                max_bans: 16,
            },
        );
        let source: IpAddr = "192.88.99.7".parse().unwrap();
        for _ in 0..3 {
            assert!(d.admit(source));
        }
        assert!(!d.admit(source), "over the threshold: banned");
        assert!(!d.admit(source), "and stays banned");
        assert_eq!(get(&d.counters.refused_banned), 2);
        assert!(
            d.guard
                .enforcement()
                .banned(source, Instant::now())
                .is_some()
        );
    }
}
