//! Transport tuning of one data plane: how each new flow is sized and timed.
//!
//! A [`TransportPlan`] holds one or more bands, each a set of values for the flows of a
//! round-trip range; a plan with one band is a fixed set. A new flow takes the band of the round
//! trip measured through the tunnel: the median handshake time of the latest TCP connections,
//! or a probe's time while none completed yet. Flows that exist keep what they were opened
//! with, so the plan can be replaced and the round trip can change without touching them.
//!
//! A band gives each TCP buffer two sizes: the one a connection opens with and the one it may
//! grow to. The userspace stack doubles a buffer that carried half of its size within one
//! round trip, while a share of the buffer budget is free (`netstack::tcp`); the strict plane
//! leaves the sizing to the kernel.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use vpn_sync::{Mutex, RwLock};

/// The receive buffer a TCP connection opens with by default, and a control flow's at most.
pub const TCP_RX_START: usize = 512 * 1024;
/// The transmit buffer a TCP connection opens with by default, and a control flow's at most.
pub const TCP_TX_START: usize = 256 * 1024;

/// Each direction of a control flow's UDP socket, at most (the default of a payload flow).
const UDP_CONTROL_BUFFER: usize = 64 * 1024;
const UDP_CONTROL_PACKETS: usize = 64;

/// Handshake times kept for the round-trip estimate.
const RTT_SAMPLES: usize = 16;
/// A measurement older than this says nothing about the path now.
const RTT_MAX_AGE: Duration = Duration::from_mins(10);

/// TCP congestion control of the userspace stack's connections, and of the strict plane's own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Congestion {
    #[default]
    Cubic,
    Reno,
    /// The kernel's BBR for the strict plane's own flows, where it may be chosen; Cubic for the
    /// userspace stack, which has no BBR.
    Bbr,
}

impl Congestion {
    /// The kernel's name of it (`TCP_CONGESTION`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cubic => "cubic",
            Self::Reno => "reno",
            Self::Bbr => "bbr",
        }
    }

    /// What the userspace stack runs when this is asked for: it has no BBR.
    #[must_use]
    pub const fn userspace(self) -> Self {
        match self {
            Self::Cubic | Self::Bbr => Self::Cubic,
            Self::Reno => Self::Reno,
        }
    }
}

/// What a new flow gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowTuning {
    /// The size the receive buffer of a TCP connection may grow to.
    pub tcp_rx_buffer: usize,
    /// The size it opens with (never more than it may grow to: see [`Self::tcp_rx_start`]).
    pub tcp_rx_initial: usize,
    /// The size the transmit buffer of a TCP connection may grow to.
    pub tcp_tx_buffer: usize,
    /// The size it opens with (see [`Self::tcp_tx_start`]).
    pub tcp_tx_initial: usize,
    pub congestion: Congestion,
    pub nagle: bool,
    /// `None`: every segment is acknowledged at once.
    pub ack_delay: Option<Duration>,
    pub connect_timeout: Duration,
    /// Keep-alive probe interval of an idle TCP connection.
    pub tcp_keepalive: Duration,
    /// A TCP connection whose peer sent nothing for this long is aborted.
    pub tcp_dead_peer_timeout: Duration,
    /// Each direction of a UDP flow.
    pub udp_buffer: usize,
    /// Datagrams each direction of a UDP flow holds.
    pub udp_packets: usize,
}

impl Default for FlowTuning {
    fn default() -> Self {
        Self {
            tcp_rx_buffer: TCP_RX_START,
            tcp_rx_initial: TCP_RX_START,
            tcp_tx_buffer: TCP_TX_START,
            tcp_tx_initial: TCP_TX_START,
            congestion: Congestion::Cubic,
            // Proxied application streams: latency matters more than coalescing tiny writes.
            nagle: false,
            ack_delay: Some(Duration::from_millis(10)),
            connect_timeout: Duration::from_secs(15),
            tcp_keepalive: crate::netstack::TCP_KEEPALIVE,
            tcp_dead_peer_timeout: crate::netstack::TCP_DEAD_PEER_TIMEOUT,
            udp_buffer: UDP_CONTROL_BUFFER,
            udp_packets: UDP_CONTROL_PACKETS,
        }
    }
}

impl FlowTuning {
    /// The receive buffer a TCP connection opens with.
    #[must_use]
    pub const fn tcp_rx_start(&self) -> usize {
        smaller(self.tcp_rx_initial, self.tcp_rx_buffer)
    }

    /// The transmit buffer a TCP connection opens with.
    #[must_use]
    pub const fn tcp_tx_start(&self) -> usize {
        smaller(self.tcp_tx_initial, self.tcp_tx_buffer)
    }

    /// The same for a control flow (a DNS lookup, a health probe): its TCP buffers open no
    /// larger than the default and never grow, and its UDP buffers are no larger than the
    /// default. The share of the budget kept for control flows is small.
    #[must_use]
    pub const fn control(mut self) -> Self {
        self.tcp_rx_buffer = smaller(self.tcp_rx_start(), TCP_RX_START);
        self.tcp_rx_initial = self.tcp_rx_buffer;
        self.tcp_tx_buffer = smaller(self.tcp_tx_start(), TCP_TX_START);
        self.tcp_tx_initial = self.tcp_tx_buffer;
        if self.udp_buffer > UDP_CONTROL_BUFFER {
            self.udp_buffer = UDP_CONTROL_BUFFER;
        }
        if self.udp_packets > UDP_CONTROL_PACKETS {
            self.udp_packets = UDP_CONTROL_PACKETS;
        }
        self
    }
}

const fn smaller(a: usize, b: usize) -> usize {
    if a < b { a } else { b }
}

/// The values of the flows whose round trip is at least `from_rtt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Band {
    pub from_rtt: Duration,
    pub tuning: FlowTuning,
}

/// The bands of a data plane, ascending by round trip; never empty, the first from zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportPlan {
    bands: Vec<Band>,
}

impl Default for TransportPlan {
    fn default() -> Self {
        Self::fixed(FlowTuning::default())
    }
}

impl TransportPlan {
    /// One set of values for every flow.
    #[must_use]
    pub fn fixed(tuning: FlowTuning) -> Self {
        Self {
            bands: vec![Band {
                from_rtt: Duration::ZERO,
                tuning,
            }],
        }
    }

    /// `None` unless `bands` starts at a round trip of zero and ascends strictly.
    #[must_use]
    pub fn new(bands: Vec<Band>) -> Option<Self> {
        let starts_at_zero = bands.first().is_some_and(|b| b.from_rtt.is_zero());
        let ascends = bands.windows(2).all(|w| w[0].from_rtt < w[1].from_rtt);
        (starts_at_zero && ascends).then_some(Self { bands })
    }

    #[must_use]
    pub fn bands(&self) -> &[Band] {
        &self.bands
    }

    /// The band of a round trip. Near a boundary it stays with `current`: a band is left
    /// downwards only once the round trip is a fifth below its threshold, so a round trip
    /// that hovers at a boundary does not alternate between two bands.
    fn band_for(&self, rtt: Option<Duration>, current: usize) -> usize {
        let Some(rtt) = rtt else {
            return 0;
        };
        let reached = self
            .bands
            .iter()
            .rposition(|b| rtt >= b.from_rtt)
            .unwrap_or(0);
        match self.bands.get(current) {
            Some(held) if reached < current && rtt * 5 >= held.from_rtt * 4 => current,
            _ => reached,
        }
    }
}

/// What was measured through the tunnel, and the band chosen from it.
#[derive(Debug, Default)]
struct Measured {
    /// Handshake times of the latest TCP connections, oldest first.
    handshakes: VecDeque<(Instant, Duration)>,
    /// The latest probe's time: the estimate while no handshake is recent.
    probe: Option<(Instant, Duration)>,
    /// The band new flows take.
    band: usize,
}

impl Measured {
    /// The round trip now: the median of the recent handshakes, else the last recent probe.
    fn round_trip(&mut self, now: Instant) -> Option<Duration> {
        let recent = |at: Instant| now.saturating_duration_since(at) <= RTT_MAX_AGE;
        while self.handshakes.front().is_some_and(|(at, _)| !recent(*at)) {
            self.handshakes.pop_front();
        }
        if self.handshakes.is_empty() {
            return self.probe.filter(|(at, _)| recent(*at)).map(|(_, d)| d);
        }
        let mut times: Vec<Duration> = self.handshakes.iter().map(|(_, d)| *d).collect();
        times.sort_unstable();
        times.get(times.len() / 2).copied()
    }
}

/// The transport of one data plane right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportSnapshot {
    /// Index of the band new flows take.
    pub band: usize,
    /// The round trip the band was chosen for; `None` while nothing was measured.
    pub rtt: Option<Duration>,
    /// TCP buffers enlarged because their connection used them.
    pub grown: u64,
    /// Enlargements not made because the buffer budget had no room for them.
    pub growth_refused: u64,
}

/// The plan in force, the round trip measured and what new flows take.
#[derive(Debug)]
pub struct Transport {
    plan: RwLock<Arc<TransportPlan>>,
    measured: Mutex<Measured>,
    grown: AtomicU64,
    growth_refused: AtomicU64,
}

impl Transport {
    #[must_use]
    pub fn new(plan: TransportPlan) -> Self {
        Self {
            plan: RwLock::new(Arc::new(plan)),
            measured: Mutex::new(Measured::default()),
            grown: AtomicU64::new(0),
            growth_refused: AtomicU64::new(0),
        }
    }

    /// Replace the plan: flows opened from now on take it. What was measured stays.
    pub fn set_plan(&self, plan: TransportPlan) {
        *self.plan.write() = Arc::new(plan);
        // The band is chosen again from the round trip by the next flow.
        self.measured.lock().band = 0;
    }

    #[must_use]
    pub fn plan(&self) -> Arc<TransportPlan> {
        self.plan.read().clone()
    }

    /// The band of the round trip measured now, and that round trip.
    fn choose(&self) -> (Band, usize, Option<Duration>) {
        let plan = self.plan();
        let mut measured = self.measured.lock();
        let rtt = measured.round_trip(Instant::now());
        let index = plan.band_for(rtt, measured.band);
        measured.band = index;
        drop(measured);
        // `band_for` returns an index of `plan.bands`, which is never empty.
        let band = plan.bands.get(index).copied().unwrap_or_else(|| Band {
            from_rtt: Duration::ZERO,
            tuning: FlowTuning::default(),
        });
        (band, index, rtt)
    }

    /// What a flow opened now gets, and the round trip it was chosen for.
    #[must_use]
    pub fn select(&self) -> (FlowTuning, Option<Duration>) {
        let (band, _, rtt) = self.choose();
        (band.tuning, rtt)
    }

    /// A TCP connection through the tunnel completed its handshake in `rtt`.
    pub fn record_handshake(&self, rtt: Duration) {
        let mut measured = self.measured.lock();
        if measured.handshakes.len() == RTT_SAMPLES {
            measured.handshakes.pop_front();
        }
        measured.handshakes.push_back((Instant::now(), rtt));
    }

    /// A probe through the tunnel was answered after `latency` (one request, one answer).
    pub fn record_probe(&self, latency: Duration) {
        self.measured.lock().probe = Some((Instant::now(), latency));
    }

    pub(crate) fn grew(&self) {
        self.grown.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn growth_refused(&self) {
        self.growth_refused.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> TransportSnapshot {
        let (_, band, rtt) = self.choose();
        TransportSnapshot {
            band,
            rtt,
            grown: self.grown.load(Ordering::Relaxed),
            growth_refused: self.growth_refused.load(Ordering::Relaxed),
        }
    }
}
