//! Lock-free counters updated on the data path and read by Instance Metrics once per second.
//! The data path never waits for metrics.

use std::sync::atomic::{AtomicU64, Ordering};

use vpn_domain::{LATENCY_BUCKET_COUNT, LATENCY_BUCKETS_US};

/// One Gateway's counters. Payload bytes are client-visible application bytes (no SOCKS/HTTP
/// handshake bytes, no tunnel overhead).
#[derive(Debug, Default)]
pub struct GatewayCounters {
    pub tcp_accepted: AtomicU64,
    /// Refused at admission (connection limit, gate closed, policy).
    pub tcp_rejected: AtomicU64,
    pub tcp_active: AtomicU64,
    pub udp_associations_active: AtomicU64,
    pub udp_dropped: AtomicU64,
    pub payload_rx_bytes: AtomicU64,
    pub payload_tx_bytes: AtomicU64,
    /// The part of `payload_*` relayed for SSH sessions ([`TcpClass::Ssh`]: TCP connections to
    /// port 22, or marked as SSH by the client): counted in addition to the payload, never
    /// instead of it. Only the class sums are kept — never a host, an address or anything else
    /// per destination.
    pub ssh_rx_bytes: AtomicU64,
    pub ssh_tx_bytes: AtomicU64,
    /// The part of `payload_*` relayed for VPN Manager's own SSH downloads
    /// ([`TcpClass::SshPull`]); never also in `ssh_*`.
    pub ssh_pull_rx_bytes: AtomicU64,
    pub ssh_pull_tx_bytes: AtomicU64,
    /// Gauge: SSH sessions ([`TcpClass::Ssh`]) being relayed now.
    pub ssh_sessions: AtomicU64,
    /// Proxy connect latency (resolve + connect) of connects that reached the destination;
    /// `connect_latency.timeouts` counts the ones that ran out of time.
    pub connect_latency: LatencyHistogram,
    /// Connects that failed otherwise: refused, unreachable, the name not resolved. Refusals of
    /// the Gateway itself are `tcp_rejected`, not failures.
    pub connect_failures: AtomicU64,
    /// Subset of `connect_failures`: the name had no address (NXDOMAIN, or none of a family the
    /// tunnel carries). Counted right after the failure itself.
    pub connect_not_found: AtomicU64,
}

impl GatewayCounters {
    pub fn add_rx(&self, n: u64) {
        self.payload_rx_bytes.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_tx(&self, n: u64) {
        self.payload_tx_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// Count `n` bytes upstream → client of a relayed connection of `class`.
    pub fn add_rx_as(&self, class: TcpClass, n: u64) {
        self.add_rx(n);
        match class {
            TcpClass::Other => {}
            TcpClass::Ssh => {
                self.ssh_rx_bytes.fetch_add(n, Ordering::Relaxed);
            }
            TcpClass::SshPull => {
                self.ssh_pull_rx_bytes.fetch_add(n, Ordering::Relaxed);
            }
        }
    }

    /// Count `n` bytes client → upstream of a relayed connection of `class`.
    pub fn add_tx_as(&self, class: TcpClass, n: u64) {
        self.add_tx(n);
        match class {
            TcpClass::Other => {}
            TcpClass::Ssh => {
                self.ssh_tx_bytes.fetch_add(n, Ordering::Relaxed);
            }
            TcpClass::SshPull => {
                self.ssh_pull_tx_bytes.fetch_add(n, Ordering::Relaxed);
            }
        }
    }
}

/// Holds a gauge one higher while it lives (a relay of a class that is counted open).
#[derive(Debug)]
pub struct Held<'a>(&'a AtomicU64);

impl<'a> Held<'a> {
    pub fn new(gauge: &'a AtomicU64) -> Self {
        gauge.fetch_add(1, Ordering::Relaxed);
        Self(gauge)
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The well-known SSH port: a relayed TCP connection to it counts as SSH.
pub const SSH_PORT: u16 = 22;

/// What a relayed TCP connection of a Gateway is counted as besides its payload.
///
/// Decided once when it is set up: from what the client says it carries (a SOCKS5 mark), else
/// from its destination port alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpClass {
    Other,
    /// An SSH session: destination port [`SSH_PORT`], or marked as SSH by the client
    /// (`vpnctl ssh-proxy`, whatever the port).
    Ssh,
    /// VPN Manager's own SSH download (marked by the client), whatever the port: never also an
    /// SSH session.
    SshPull,
}

impl TcpClass {
    #[must_use]
    pub const fn of_port(port: u16) -> Self {
        if port == SSH_PORT {
            Self::Ssh
        } else {
            Self::Other
        }
    }
}

/// Cumulative fixed-bucket histogram (`latency-us-v1`, bounds in [`LATENCY_BUCKETS_US`]).
///
/// Each bucket counts its own observations, so readers take differences per bucket. `count` is
/// read separately from the buckets; a reader wanting a count that matches them sums the
/// buckets.
#[derive(Debug, Default)]
pub struct LatencyHistogram {
    pub buckets: [AtomicU64; LATENCY_BUCKET_COUNT],
    pub count: AtomicU64,
    pub sum_us: AtomicU64,
    pub timeouts: AtomicU64,
}

impl LatencyHistogram {
    pub fn record(&self, micros: u64) {
        let idx = LATENCY_BUCKETS_US
            .iter()
            .position(|&b| micros <= b)
            .unwrap_or(LATENCY_BUCKET_COUNT - 1);
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(micros, Ordering::Relaxed);
    }

    pub fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> [u64; LATENCY_BUCKET_COUNT] {
        std::array::from_fn(|i| self.buckets[i].load(Ordering::Relaxed))
    }
}

/// One port forward's counters for the generation. Never records an address.
#[derive(Debug, Default)]
pub struct ForwardCounters {
    /// Inbound TCP connections and UDP flows connected to the App.
    pub accepted: AtomicU64,
    pub refused_invalid: AtomicU64,
    pub refused_blocklisted: AtomicU64,
    pub refused_banned: AtomicU64,
    pub refused_rate_limited: AtomicU64,
    /// The forward already carried its maximum.
    pub refused_limit: AtomicU64,
    /// Arrived while the gate was not open or the lease was ending.
    pub refused_closed: AtomicU64,
    /// The App did not accept the connection.
    pub target_failed: AtomicU64,
    pub tcp_active: AtomicU64,
    pub udp_active: AtomicU64,
    /// Remote → App.
    pub bytes_in: AtomicU64,
    /// App → remote.
    pub bytes_out: AtomicU64,
    pub udp_dropped: AtomicU64,
    /// When an inbound connection/flow last arrived from outside the tunnel's own and private
    /// networks: milliseconds after the controller's epoch, plus one (0 = never).
    pub external_tcp: AtomicU64,
    pub external_udp: AtomicU64,
}

/// What every port forward of a generation relayed between the remote ends and the Apps.
///
/// All forwards together: TCP connections and relayed UDP flows. UDP that goes straight into the
/// strict sandbox is not in it — the packet filter counts that as the sandbox's Apps'. Only
/// grows: a forward removed meanwhile keeps its bytes here, so the sum can stand in a cumulative
/// payload counter (each forward's own `bytes_in`/`bytes_out` leave with it).
#[derive(Debug, Default)]
pub struct RelayedCounters {
    /// Remote → App.
    pub rx_bytes: AtomicU64,
    /// App → remote.
    pub tx_bytes: AtomicU64,
}

/// DNS Controller counters. Query names are never recorded anywhere.
#[derive(Debug, Default)]
pub struct DnsCounters {
    pub queries: AtomicU64,
    pub cache_hits: AtomicU64,
    pub failures: AtomicU64,
    /// Refused because the in-flight limit was reached.
    pub overloaded: AtomicU64,
    /// Time until an upstream answer through the tunnel; lookups answered from cache are not
    /// observations. `latency.timeouts` counts failed lookups whose deadline passed.
    pub latency: LatencyHistogram,
}
