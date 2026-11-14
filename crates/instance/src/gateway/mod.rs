//! Gateway Manager / Gateway Provide: loopback SOCKS5 and HTTP proxies whose every outbound flow
//! goes through the Instance's `TunnelConnector`.
//!
//! Invariant: a proxied flow either goes through the tunnel or fails; there is no direct or host
//! fallback. Outbound TCP and UDP are opened only with `TunnelConnector` (`FlowClass::Payload`),
//! names are resolved only with [`Resolve`] (the tunnel's DNS), and every literal or resolved
//! destination passes [`DestinationPolicy`] before it is dialed. The only host sockets this module
//! owns are the loopback listener it is handed and, per SOCKS5 UDP association, one UDP relay
//! socket bound on the client's loopback address that only ever sends to that client.
//!
//! Everything is bounded: concurrent client connections (excess ones are closed at accept),
//! UDP associations, the time a client gets for SOCKS5 negotiation or an HTTP request head, how
//! long a relayed connection or UDP association may stay silent, the HTTP head size and header
//! count, datagram size and connect attempts per request.
//!
//! Counters: `payload_tx_bytes` counts client → destination and `payload_rx_bytes` destination →
//! client application bytes (spliced stream bytes, forwarded HTTP message bodies, UDP payloads),
//! never SOCKS/HTTP handshake bytes. Logs never contain destinations, URLs or names.
//!
//! The same payload passes the connection's bandwidth caps ([`crate::shaping`]): a stream waits
//! for its cap (backpressure), a UDP datagram over it is dropped.

mod connect;
mod http_proxy;
mod socks5;
mod splice;
mod udp;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use vpn_domain::{GatewayId, GatewayKind};
use vpn_tunnel::TunnelConnector;

use crate::counters::GatewayCounters;
use crate::dns::Resolve;
use crate::policy::DestinationPolicy;
use crate::shaping::Shaper;
pub use udp::{RelayRequest, RelaySockets};

/// Default cap on concurrent SOCKS5 UDP associations of one Gateway.
pub const DEFAULT_MAX_UDP_ASSOCIATIONS: u32 = 512;
/// Default time a client gets for SOCKS5 negotiation or an HTTP request head.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Default lifetime of a UDP association without traffic.
pub const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Default time a relayed TCP connection may stay silent in both directions.
///
/// Long on purpose: RFC 5382 (REQ-5) has NATs keep idle established TCP for at least 2 h 4 min, so applications
/// already keep long-lived sessions alive within it; a dead tunnel peer is released much sooner
/// by the netstack's keep-alive timeout.
pub const DEFAULT_TCP_IDLE_TIMEOUT: Duration = Duration::from_mins(124);

/// First byte of a SOCKS4 request; not offered.
const SOCKS4_VERSION: u8 = 0x04;
/// Back-off after a failed `accept` (e.g. out of file descriptors); doubles up to the maximum.
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(10);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// What one Gateway serves and its resource bounds.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub id: GatewayId,
    pub kind: GatewayKind,
    /// Allow SOCKS5 UDP ASSOCIATE.
    pub udp: bool,
    /// Concurrent client TCP connections of this Gateway; further ones are closed at accept.
    pub max_connections: u32,
    /// Concurrent SOCKS5 UDP associations; further requests get "general failure".
    pub max_udp_associations: u32,
    /// Time a client gets for SOCKS5 negotiation or an HTTP request head (slowloris bound).
    pub handshake_timeout: Duration,
    /// A UDP association with no traffic in either direction for this long ends.
    pub udp_idle_timeout: Duration,
    /// A relayed TCP connection (SOCKS5 CONNECT, HTTP CONNECT) with no bytes in either direction
    /// for this long is closed.
    pub tcp_idle_timeout: Duration,
    /// Installation key for the private SOCKS5 method with which this Gateway proves itself
    /// to `vpnctl` (see `vpn_ipc::identity::gateway_proof`).
    pub auth_key: Option<Arc<zeroize::Zeroizing<[u8; 32]>>>,
}

impl GatewayConfig {
    /// Configuration with the default UDP, handshake and idle bounds.
    #[must_use]
    pub const fn new(id: GatewayId, kind: GatewayKind, udp: bool, max_connections: u32) -> Self {
        Self {
            id,
            kind,
            udp,
            max_connections,
            max_udp_associations: DEFAULT_MAX_UDP_ASSOCIATIONS,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            udp_idle_timeout: DEFAULT_UDP_IDLE_TIMEOUT,
            tcp_idle_timeout: DEFAULT_TCP_IDLE_TIMEOUT,
            auth_key: None,
        }
    }
}

/// What a Gateway needs from its Instance.
#[derive(Debug)]
pub struct GatewayDeps<C: TunnelConnector, R: Resolve> {
    pub connector: C,
    pub resolver: R,
    pub policy: Arc<DestinationPolicy>,
    pub counters: Arc<GatewayCounters>,
    /// The connection's bandwidth caps, shared by all its Gateways.
    pub shaper: Arc<Shaper>,
}

/// A running Gateway. Dropping the handle stops it like [`Gateway::shutdown`], without waiting.
#[derive(Debug)]
pub struct Gateway {
    local_addr: SocketAddr,
    cancel: CancellationToken,
    tracker: TaskTracker,
}

impl Gateway {
    /// Serve on an already-bound loopback listener (std; it is switched to non-blocking here).
    /// Spawns on the current tokio runtime.
    ///
    /// # Errors
    ///
    /// As [`Gateway::spawn_with_relays`].
    pub fn spawn<C: TunnelConnector, R: Resolve>(
        listener: std::net::TcpListener,
        config: GatewayConfig,
        deps: GatewayDeps<C, R>,
    ) -> io::Result<Self> {
        Self::spawn_with_relays(listener, config, deps, RelaySockets::Local)
    }

    /// Like [`Gateway::spawn`], with SOCKS5 UDP relay sockets from `relays` (a strict worker,
    /// whose own loopback is its sandbox's, gets them from the Instance Manager).
    ///
    /// # Errors
    ///
    /// `InvalidInput` if the listener is not bound to a loopback address; an error if there is
    /// no current tokio runtime or the listener cannot be made non-blocking and registered.
    pub fn spawn_with_relays<C: TunnelConnector, R: Resolve>(
        listener: std::net::TcpListener,
        config: GatewayConfig,
        deps: GatewayDeps<C, R>,
        relays: RelaySockets,
    ) -> io::Result<Self> {
        let local_addr = listener.local_addr()?;
        if !local_addr.ip().to_canonical().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gateway listener must be bound to a loopback address",
            ));
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(io::Error::other(
                "Gateway::spawn must be called within a tokio runtime",
            ));
        }
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;
        let cancel = CancellationToken::new();
        let tracker = TaskTracker::new();
        let shared = Arc::new(Shared {
            connections: Arc::new(semaphore(config.max_connections)),
            udp_associations: Arc::new(semaphore(config.max_udp_associations)),
            config,
            connector: deps.connector,
            resolver: deps.resolver,
            policy: deps.policy,
            counters: deps.counters,
            shaper: deps.shaper,
            relays,
            cancel: cancel.clone(),
            tracker: tracker.clone(),
        });
        tracing::info!(
            gateway = %shared.config.id,
            kind = ?shared.config.kind,
            %local_addr,
            "gateway serving"
        );
        tracker.spawn(accept_loop(listener, shared));
        Ok(Self {
            local_addr,
            cancel,
            tracker,
        })
    }

    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop accepting and abort every active client connection and UDP association; returns once
    /// all of the Gateway's tasks have ended.
    pub async fn shutdown(self) {
        let tracker = self.tracker.clone();
        drop(self);
        tracker.wait().await;
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tracker.close();
    }
}

/// State shared by the accept loop and every client connection of one Gateway.
struct Shared<C, R> {
    config: GatewayConfig,
    connector: C,
    resolver: R,
    policy: Arc<DestinationPolicy>,
    counters: Arc<GatewayCounters>,
    shaper: Arc<Shaper>,
    /// One permit per served client TCP connection.
    connections: Arc<Semaphore>,
    /// One permit per SOCKS5 UDP association.
    udp_associations: Arc<Semaphore>,
    /// Where SOCKS5 UDP relay sockets come from.
    relays: RelaySockets,
    cancel: CancellationToken,
    tracker: TaskTracker,
}

fn semaphore(permits: u32) -> Semaphore {
    let permits = usize::try_from(permits).unwrap_or(usize::MAX);
    Semaphore::new(permits.min(Semaphore::MAX_PERMITS))
}

/// Keeps a gauge (`tcp_active`, `udp_associations_active`) incremented while alive.
struct Gauge {
    counters: Arc<GatewayCounters>,
    gauge: fn(&GatewayCounters) -> &AtomicU64,
}

impl Gauge {
    fn new(counters: &Arc<GatewayCounters>, gauge: fn(&GatewayCounters) -> &AtomicU64) -> Self {
        gauge(counters).fetch_add(1, Ordering::Relaxed);
        Self {
            counters: Arc::clone(counters),
            gauge,
        }
    }
}

impl Drop for Gauge {
    fn drop(&mut self) {
        (self.gauge)(&self.counters).fetch_sub(1, Ordering::Relaxed);
    }
}

const fn tcp_active(counters: &GatewayCounters) -> &AtomicU64 {
    &counters.tcp_active
}

const fn udp_associations_active(counters: &GatewayCounters) -> &AtomicU64 {
    &counters.udp_associations_active
}

async fn accept_loop<C: TunnelConnector, R: Resolve>(
    listener: TcpListener,
    shared: Arc<Shared<C, R>>,
) {
    let mut backoff = ACCEPT_BACKOFF_MIN;
    loop {
        let accepted = tokio::select! {
            biased;
            () = shared.cancel.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, peer)) => {
                backoff = ACCEPT_BACKOFF_MIN;
                admit(&shared, stream, peer);
            }
            // The client went away between the handshake and accept; nothing to back off from.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => {
                tracing::warn!(gateway = %shared.config.id, error = %e, "accept failed; backing off");
                let slept = shared
                    .cancel
                    .run_until_cancelled(tokio::time::sleep(backoff))
                    .await;
                if slept.is_none() {
                    break;
                }
                backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
            }
        }
    }
    tracing::info!(gateway = %shared.config.id, "gateway stopped accepting");
}

/// Admission: loopback peers only, at most `max_connections` at once. Refused connections are
/// closed immediately and never queued.
fn admit<C: TunnelConnector, R: Resolve>(
    shared: &Arc<Shared<C, R>>,
    stream: TcpStream,
    peer: SocketAddr,
) {
    let counters = &shared.counters;
    if !peer.ip().to_canonical().is_loopback() {
        counters.tcp_rejected.fetch_add(1, Ordering::Relaxed);
        reject(stream);
        return;
    }
    let Ok(permit) = Arc::clone(&shared.connections).try_acquire_owned() else {
        counters.tcp_rejected.fetch_add(1, Ordering::Relaxed);
        reject(stream);
        return;
    };
    counters.tcp_accepted.fetch_add(1, Ordering::Relaxed);
    let active = Gauge::new(counters, tcp_active);
    // Proxied traffic is often interactive; never delay small writes towards the client.
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(gateway = %shared.config.id, error = %e, "TCP_NODELAY not set on a client connection");
    }
    // Bounded kernel buffers: an upload waiting on the tunnel queues at most this much here
    // (left alone, macOS grows it to 4 MiB, and a few hundred such uploads exhaust the host's
    // network memory for every program on it).
    if let Err(e) =
        vpn_platform::nobufs::fix_buffers(&stream, vpn_platform::nobufs::LOOPBACK_BUFFER)
    {
        tracing::debug!(gateway = %shared.config.id, error = %e, "client connection buffers not fixed");
    }
    let conn_shared = Arc::clone(shared);
    shared.tracker.spawn(async move {
        let _permit = permit;
        let _active = active;
        serve_client(&conn_shared, stream, peer).await;
    });
}

/// Close a refused connection at once with a reset, so it leaves no `TIME_WAIT` state behind.
fn reject(stream: TcpStream) {
    // Without the option the close is an orderly one: refused all the same.
    if let Err(e) = stream.set_zero_linger() {
        tracing::trace!(error = %e, "refused connection closed without a reset");
    }
    drop(stream);
}

async fn serve_client<C: TunnelConnector, R: Resolve>(
    shared: &Arc<Shared<C, R>>,
    stream: TcpStream,
    peer: SocketAddr,
) {
    // Protocol detection, SOCKS5 negotiation and the first HTTP request head share one deadline
    // from accept; hyper bounds every later request head (and keep-alive idle time) itself.
    let deadline = Instant::now() + shared.config.handshake_timeout;
    // A stopping Gateway ends a SOCKS5 connection at once; the HTTP proxy answers the request
    // it has in flight first (`http_proxy::serve`).
    let stop = &shared.cancel;
    let socks = async |stream| {
        stop.run_until_cancelled(socks5::serve(shared, stream, peer, deadline))
            .await;
    };
    match shared.config.kind {
        GatewayKind::Socks5 => socks(stream).await,
        GatewayKind::Http => http_proxy::serve(shared, stream, deadline).await,
        GatewayKind::Mixed => {
            // Detection outlasts a stop by the proxy's grace: an HTTP request already on its way
            // is told that the Gateway stops; a SOCKS5 client is let go just below.
            let stopped = async {
                stop.cancelled().await;
                tokio::time::sleep(http_proxy::STOP_GRACE).await;
            };
            let first = tokio::select! {
                biased;
                first = first_byte(&stream, deadline) => first,
                () = stopped => None,
            };
            match first {
                Some(socks5::VERSION) => socks(stream).await,
                // SOCKS4 is not offered; EOF, error and timeout just close.
                Some(SOCKS4_VERSION) | None => {}
                Some(_) => http_proxy::serve(shared, stream, deadline).await,
            }
        }
    }
}

/// Peek the first byte without consuming it.
async fn first_byte(stream: &TcpStream, deadline: Instant) -> Option<u8> {
    let mut byte = [0u8; 1];
    match tokio::time::timeout_at(deadline, stream.peek(&mut byte)).await {
        Ok(Ok(n)) if n > 0 => Some(byte[0]),
        _ => None,
    }
}
