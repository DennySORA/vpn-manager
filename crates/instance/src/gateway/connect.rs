//! Destination resolution, policy and dialing shared by SOCKS5 CONNECT and the HTTP proxy. The
//! only outbound path is `TunnelConnector::connect_tcp`; there is no host fallback.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use vpn_tunnel::{FlowClass, TunnelConnector};

use super::Shared;
use crate::dns::{Family, Resolve, ResolveError};
use crate::policy::Denied;

/// Resolved addresses tried per request, in resolver order.
const MAX_ATTEMPTS: usize = 8;
/// Bound on all connect attempts of one request together; each attempt is also bounded by the
/// connector's own connect timeout.
const CONNECT_BUDGET: Duration = Duration::from_secs(30);

/// A destination host as the client named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Host {
    Ip(IpAddr),
    /// Hostname for the tunnel resolver; never an IP literal.
    Name(String),
}

impl Host {
    /// Classify a SOCKS5 domain or an HTTP authority host. IP literals (IPv6 with or without
    /// brackets) are used as they are and never sent to the resolver.
    pub(super) fn parse(host: &str) -> Self {
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        bare.parse::<IpAddr>()
            .map_or_else(|_| Self::Name(host.to_owned()), Self::Ip)
    }
}

/// Why a destination could not be reached through the tunnel.
///
/// Carries no destination data, so it is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ConnectError {
    /// Refused by the destination policy.
    Denied(Denied),
    /// Payload gate closed: the Instance is not ready or is reconnecting.
    GateClosed,
    Resolve(ResolveError),
    /// The tunnel does not carry the destination's address family (or has no route).
    NetworkUnreachable,
    HostUnreachable,
    Refused,
    TimedOut,
    /// Tunnel admission limit (flows or memory).
    Admission,
    Failed,
}

impl ConnectError {
    /// Map a `TunnelConnector` error by the kinds its contract defines.
    pub(super) fn from_io(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::PermissionDenied => Self::GateClosed,
            io::ErrorKind::QuotaExceeded | io::ErrorKind::OutOfMemory => Self::Admission,
            io::ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            io::ErrorKind::HostUnreachable => Self::HostUnreachable,
            io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => Self::Refused,
            io::ErrorKind::TimedOut => Self::TimedOut,
            _ => Self::Failed,
        }
    }

    /// Failures that concern one address only, so the next resolved address may still work.
    const fn try_next_address(&self) -> bool {
        matches!(
            self,
            Self::NetworkUnreachable
                | Self::HostUnreachable
                | Self::Refused
                | Self::TimedOut
                | Self::Failed
        )
    }

    /// Refusals counted in `tcp_rejected`: policy, closed gate, admission limit.
    pub(super) const fn is_refusal(&self) -> bool {
        matches!(self, Self::Denied(_) | Self::GateClosed | Self::Admission)
    }

    /// The name had no address: a failure that `connect_not_found` also counts.
    const fn is_not_found(&self) -> bool {
        matches!(self, Self::Resolve(ResolveError::NotFound))
    }
}

/// Resolve (names only), policy-check and dial `host:port` through the tunnel. Records the
/// connect latency (resolve + connect), a timeout, a failure (and whether its name had no
/// address) or a refusal: each attempt counts exactly once.
pub(super) async fn connect<C: TunnelConnector, R: Resolve>(
    shared: &Shared<C, R>,
    host: &Host,
    port: u16,
) -> Result<C::Stream, ConnectError> {
    let started = Instant::now();
    let result = resolve_and_dial(shared, host, port).await;
    let counters = &shared.counters;
    match &result {
        Ok(_) => counters
            .connect_latency
            .record(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)),
        Err(error) => {
            if *error == ConnectError::TimedOut {
                counters.connect_latency.record_timeout();
            } else if error.is_refusal() {
                counters.tcp_rejected.fetch_add(1, Ordering::Relaxed);
            } else {
                counters.connect_failures.fetch_add(1, Ordering::Relaxed);
                if error.is_not_found() {
                    counters.connect_not_found.fetch_add(1, Ordering::Relaxed);
                }
            }
            tracing::debug!(gateway = %shared.config.id, ?error, "destination not reached");
        }
    }
    result
}

async fn resolve_and_dial<C: TunnelConnector, R: Resolve>(
    shared: &Shared<C, R>,
    host: &Host,
    port: u16,
) -> Result<C::Stream, ConnectError> {
    if port == 0 {
        return Err(ConnectError::HostUnreachable);
    }
    let candidates = match host {
        Host::Ip(ip) => vec![*ip],
        Host::Name(name) => {
            let addrs = shared
                .resolver
                .resolve(name, Family::Any)
                .await
                .map_err(ConnectError::Resolve)?;
            if addrs.is_empty() {
                return Err(ConnectError::Resolve(ResolveError::NotFound));
            }
            addrs
        }
    };
    tokio::time::timeout(CONNECT_BUDGET, dial_first(shared, candidates, port))
        .await
        .unwrap_or(Err(ConnectError::TimedOut))
}

/// Try the candidates in order; each one is policy-checked before it is dialed. A closed gate or
/// an admission limit ends the attempt at once since every address would get the same answer.
async fn dial_first<C: TunnelConnector, R: Resolve>(
    shared: &Shared<C, R>,
    candidates: Vec<IpAddr>,
    port: u16,
) -> Result<C::Stream, ConnectError> {
    let mut denied = None;
    let mut last_error = None;
    for ip in candidates.into_iter().take(MAX_ATTEMPTS) {
        // A NAT64 address (an exit with DNS64 resolves every IPv4-only name to one) is judged
        // as the IPv4 host it embeds and dialed as it is, through the exit's translator.
        let dst = SocketAddr::new(ip.to_canonical(), port);
        if let Err(reason) = shared.policy.check(dst) {
            denied.get_or_insert(reason);
            continue;
        }
        if !shared.connector.supports(dst.ip()) {
            continue;
        }
        match shared.connector.connect_tcp(dst, FlowClass::Payload).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                let error = ConnectError::from_io(&e);
                if !error.try_next_address() {
                    return Err(error);
                }
                last_error = Some(error);
            }
        }
    }
    // A real connect failure says most; then a policy refusal; otherwise no candidate was of a
    // family the tunnel carries.
    Err(last_error
        .or_else(|| denied.map(ConnectError::Denied))
        .unwrap_or(ConnectError::NetworkUnreachable))
}
