//! Instance DNS Controller: resolves names through the Instance's tunnel only.
//!
//! The contract other modules depend on is [`Resolve`]; the Gateway uses it for SOCKS5 domain
//! addresses and HTTP proxy hosts. [`DnsResolver`] is the per-Instance implementation:
//!
//! - **Tunnel only.** Every upstream socket is opened through the Instance's [`TunnelConnector`]
//!   with `FlowClass::Control` and goes only to the configured resolvers. There is no host
//!   resolver, no host socket and no fallback of any kind: a DoT/DoH server whose TLS
//!   verification fails is a failed server, never a plaintext one.
//! - **While every server fails** (found by the health probe), the DNS profile decides: its
//!   `WireGuard` profile's own resolvers stand in (`DnsConfig::fallback`, through the same tunnel),
//!   or — `DnsOnFailure::Fail` — nothing else is asked at all and every lookup that needs an
//!   upstream answer fails at once ([`ResolveError::Interrupted`]) until a probe finds a server
//!   answering again. Cached answers (the profile's own) still answer meanwhile.
//! - **Bounded.** Servers (≤ 4) × attempts (≤ 3) share one deadline per resolution; calls waiting
//!   on upstream are capped by `max_in_flight` (beyond it: [`ResolveError::Overloaded`] at once,
//!   nothing is queued); the cache by entries and bytes; idle TLS connections by count and age;
//!   every message by 65535 bytes.
//! - **Cache** per resolver, keyed by (lowercase name, record type): positive answers live for the
//!   smallest answer TTL clamped to `max_ttl_secs`, NXDOMAIN/NODATA for `negative_ttl_secs`.
//! - **Coalescing.** Concurrent lookups of the same (name, type) share one upstream exchange; if
//!   the caller driving it goes away, a waiting caller takes over.
//! - **Privacy.** Query names are never logged or counted; logs carry a server index and an error
//!   kind only, at debug level.
//!
//! [`DnsCounters`] are per call of `resolve` / `query_message` (an `Any` lookup asking A and AAAA
//! is one query): `queries` every call that got as far as a lookup, `cache_hits` calls answered
//! entirely from cache, `overloaded` calls refused by the in-flight limit, `failures` calls that
//! ended in [`ResolveError::Failed`] or [`ResolveError::Interrupted`]. `latency` records calls
//! that waited for an upstream answer (NXDOMAIN included): the time until it arrived. A call
//! whose answer turned out to be cached after all (another lookup stored it a moment earlier) is
//! a cache hit, not an observation. `latency.timeouts` counts failed calls whose deadline passed.
//! Health probes are not counted.

mod cache;
pub mod server;
mod transport;
mod wire;

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};
use tokio::sync::{Semaphore, SemaphorePermit, watch};
use tokio::time::Instant;
use vpn_domain::{DnsCacheSettings, DnsOnFailure, DnsServer, Text, tr};
use vpn_sync::Mutex;
use vpn_tunnel::TunnelConnector;

use crate::counters::DnsCounters;
use cache::{Answer, Cache};
use transport::{ExchangeError, Reply, Tally, Upstreams};
use wire::{Question, Request};

/// Which address families the caller can use. The resolver never returns a family the tunnel
/// does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Any,
    V4,
    V6,
}

/// Why a lookup got no address. `Display` is English (logs); [`ResolveError::text`] is what a
/// person reads.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    /// The name does not exist (NXDOMAIN) or has no address of a usable family.
    #[error("The name does not exist or has no usable address")]
    NotFound,
    /// Every upstream failed or the deadline passed. Never falls back to the host resolver.
    #[error("DNS query failed (no upstream answered through the tunnel)")]
    Failed,
    /// Too many queries in flight; refused instead of queued.
    #[error("Too many DNS queries; refused")]
    Overloaded,
    /// Every server of the DNS profile failed the latest health probe and the profile asks
    /// nothing else (`DnsOnFailure::Fail`): nothing was sent, until a probe finds one answering.
    #[error(
        "DNS is interrupted (none of the DNS profile's servers answer, and as the profile says, no other DNS is asked)"
    )]
    Interrupted,
    #[error("Invalid host name")]
    InvalidName,
}

impl ResolveError {
    /// What a person reads.
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::NotFound => tr!(
                "The name does not exist or has no usable address",
                "名稱不存在或沒有可用位址",
                "名前が存在しないか、使用できるアドレスがありません"
            ),
            Self::Failed => tr!(
                "DNS query failed (no upstream answered through the tunnel)",
                "DNS 查詢失敗（所有經 tunnel 的上游都無回應）",
                "DNS の問い合わせに失敗しました（tunnel 経由のどの上流サーバーも応答しません）"
            ),
            Self::Overloaded => tr!(
                "Too many DNS queries; refused",
                "DNS 查詢過多，已拒絕",
                "DNS の問い合わせが多すぎるため、拒否しました"
            ),
            Self::Interrupted => tr!(
                "DNS is interrupted (none of the DNS profile's servers answer, and as the profile says, no other DNS is asked)",
                "DNS 已中斷（DNS 設定的伺服器都沒有回應，依設定不改問其他 DNS）",
                "DNS が中断しています（DNS 設定のサーバーがどれも応答せず、設定によりほかの DNS には問い合わせません）"
            ),
            Self::InvalidName => tr!("Invalid host name", "無效的主機名稱", "無効なホスト名です"),
        }
    }
}

/// Reasons server by server, as one text.
fn joined(parts: &[Text]) -> Text {
    tr!("; ", "；", "；").map(|language, separator| {
        parts
            .iter()
            .map(|p| p.get(language))
            .collect::<Vec<_>>()
            .join(separator)
    })
}

/// Name resolution through the tunnel.
pub trait Resolve: Clone + Send + Sync + 'static {
    /// Addresses for `host` (an ASCII/punycode hostname, not an IP literal), best first.
    fn resolve(
        &self,
        host: &str,
        family: Family,
    ) -> impl Future<Output = Result<Vec<IpAddr>, ResolveError>> + Send;
}

/// Settings of one Instance's resolver (from its DNS profile, or the profile's announced
/// resolvers as plain UDP servers).
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// 1..=4 upstream servers, tried in order. Extra entries are ignored.
    pub servers: Vec<DnsServer>,
    pub cache: DnsCacheSettings,
    /// Total deadline of one resolution across all attempts and servers (at most 60 s).
    pub query_timeout: Duration,
    /// 1..=3 rounds over the server list, sharing the deadline (clamped into that range).
    pub attempts: u8,
    /// Calls waiting on upstream at once; beyond it calls fail with `Overloaded` immediately.
    pub max_in_flight: usize,
    /// Trust anchors for DoT/DoH; `None` uses the bundled Web PKI roots (`webpki-roots`).
    pub tls_roots: Option<Arc<rustls::RootCertStore>>,
    /// Resolvers to use while every one of `servers` fails the health probe (the `WireGuard`
    /// profile's own, when a DNS profile names others); empty: none. Carried by the same
    /// tunnel: a fallback never reaches the host network either. Never used with
    /// `DnsOnFailure::Fail`.
    pub fallback: Vec<DnsServer>,
    /// While every one of `servers` fails: `Fail` asks nothing else (lookups fail at once).
    pub on_failure: DnsOnFailure,
}

/// A health probe that got an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOk {
    pub latency: Duration,
    /// The configured servers all failed and the fallback answered: why they failed.
    pub fallback: Option<Text>,
}

impl DnsConfig {
    pub const DEFAULT_MAX_IN_FLIGHT: usize = 256;
}

/// Upper bound applied to `query_timeout` (the DNS profile allows at most 10 s).
const MAX_QUERY_TIMEOUT: Duration = Duration::from_secs(60);

/// The DNS resolver of one Instance. Cheap to clone; clones share cache, connections and limits.
#[derive(Clone)]
pub struct DnsResolver<C: TunnelConnector> {
    inner: Arc<Inner<C>>,
}

impl<C: TunnelConnector> std::fmt::Debug for DnsResolver<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsResolver").finish_non_exhaustive()
    }
}

impl<C: TunnelConnector> DnsResolver<C> {
    pub fn new(connector: C, config: DnsConfig, counters: Arc<DnsCounters>) -> Self {
        let fail_closed = config.on_failure == DnsOnFailure::Fail;
        // A profile that fails closed never asks a fallback, whatever it was handed.
        let fallback = (!config.fallback.is_empty() && !fail_closed)
            .then(|| Upstreams::new(connector.clone(), &config.fallback, config.attempts, None));
        let upstreams = Upstreams::new(
            connector,
            &config.servers,
            config.attempts,
            config.tls_roots,
        );
        Self {
            inner: Arc::new(Inner {
                upstreams,
                fallback,
                on_fallback: AtomicBool::new(false),
                fail_closed,
                interrupted: AtomicBool::new(false),
                probe_failure: Mutex::new(None),
                cache: Cache::new(config.cache.max_entries),
                max_ttl: config.cache.max_ttl_secs,
                negative_ttl: config.cache.negative_ttl_secs,
                timeout: config.query_timeout.min(MAX_QUERY_TIMEOUT),
                inflight: Inflight::default(),
                permits: Semaphore::new(config.max_in_flight.clamp(1, Semaphore::MAX_PERMITS)),
                probes: Semaphore::new(1),
                counters,
            }),
        }
    }

    /// Health probes running right now (0 or 1), for the probe-flow count of the status report.
    #[must_use]
    pub fn probes_in_flight(&self) -> u64 {
        1u64.saturating_sub(self.inner.probes.available_permits() as u64)
    }

    /// Health probe used by the inner watchdog: asks `. IN NS` through the tunnel, bypassing
    /// cache and coalescing, within one query deadline. `Ok` on a NOERROR answer; `Overloaded`
    /// (no verdict on the tunnel) if another probe is still running or the tunnel's flow/memory
    /// limits refused every socket the probe needed.
    ///
    /// When every configured server fails and there is a fallback, the fallback is asked: if it
    /// answers, queries go to it until a later probe finds the configured servers answering
    /// again (`ProbeOk::fallback` says why they failed); the answers cached meanwhile are then
    /// forgotten. With `DnsOnFailure::Fail` nothing else is asked: lookups fail at once until a
    /// later probe finds a configured server answering. The reason a probe failed, server by
    /// server, is kept for [`Self::probe_failure`].
    ///
    /// # Errors
    ///
    /// `Overloaded` as above; `Interrupted` when every configured server failed and the profile
    /// fails closed (nothing about the tunnel itself); `Failed` when the upstreams (and the
    /// fallback) answer with anything but NOERROR or the exchange fails.
    pub async fn probe(&self) -> Result<ProbeOk, ResolveError> {
        let inner = &*self.inner;
        // Never closed: the only refusal is that a probe holds the permit.
        let _probe = inner
            .probes
            .try_acquire()
            .map_err(|_no_permit| ResolveError::Overloaded)?;
        let start = Instant::now();
        let q = Question::new(&Name::root(), RecordType::NS);
        match ask_root(&inner.upstreams, &q, start + inner.timeout, inner.timeout).await {
            Ok(()) => {
                if inner.on_fallback.swap(false, Ordering::AcqRel) {
                    // What the fallback answered never outlives it: the profile's servers may
                    // answer otherwise (a filtering resolver, for one).
                    inner.cache.clear();
                    tracing::debug!("the DNS profile's servers answer again: off the fallback");
                }
                if inner.interrupted.swap(false, Ordering::AcqRel) {
                    tracing::debug!("the DNS profile's servers answer again: names resolve again");
                }
                *inner.probe_failure.lock() = None;
                Ok(ProbeOk {
                    latency: start.elapsed(),
                    fallback: None,
                })
            }
            Err((ExchangeError::Admission, _)) => {
                tracing::debug!("DNS probe not run: tunnel flow or memory limit reached");
                Err(ResolveError::Overloaded)
            }
            Err((_, why)) => {
                let report = joined(&why);
                if inner.fail_closed {
                    // Nothing else is asked: lookups fail at once from now on.
                    if !inner.interrupted.swap(true, Ordering::AcqRel) {
                        tracing::debug!(reason = %report.en, "DNS profile failing: names fail");
                    }
                    *inner.probe_failure.lock() = Some(report);
                    return Err(ResolveError::Interrupted);
                }
                let Some(fallback) = &inner.fallback else {
                    *inner.probe_failure.lock() = Some(report);
                    return Err(ResolveError::Failed);
                };
                let again = Instant::now();
                let answered = ask_root(fallback, &q, again + inner.timeout, inner.timeout).await;
                if let Err((_, also)) = answered {
                    // Each of the fallback's servers is named as such.
                    let also = also.into_iter().map(|w| {
                        tr!(
                            "fallback {w}",
                            "備援 {w}",
                            "フォールバック {w}";
                            w = w
                        )
                    });
                    let all: Vec<Text> = why.into_iter().chain(also).collect();
                    *inner.probe_failure.lock() = Some(joined(&all));
                    return Err(ResolveError::Failed);
                }
                if !inner.on_fallback.swap(true, Ordering::AcqRel) {
                    tracing::debug!(reason = %report.en, "DNS profile failing: on the fallback");
                }
                *inner.probe_failure.lock() = None;
                Ok(ProbeOk {
                    latency: again.elapsed(),
                    fallback: Some(report),
                })
            }
        }
    }

    /// Why the latest probe failed, server by server (`DoH 45.90.28.0:443 no answer within 4.0
    /// s; …`); `None` after a probe got an answer.
    #[must_use]
    pub fn probe_failure(&self) -> Option<Text> {
        self.inner.probe_failure.lock().clone()
    }

    /// Answers one raw DNS query (wire format, at most 65535 bytes) through the cache and the
    /// tunnel; the response carries the request's ID and question. Unsupported requests get a
    /// local FORMERR / NOTIMP / REFUSED response; `InvalidName` means there is nothing to answer
    /// (not a DNS query). On `Failed` / `Overloaded` the caller answers SERVFAIL itself.
    ///
    /// # Errors
    ///
    /// `InvalidName` when the request is not a DNS query; `Failed` or `Overloaded` when no
    /// answer could be obtained through the tunnel.
    pub async fn query_message(&self, request: &[u8]) -> Result<Vec<u8>, ResolveError> {
        let inner = &*self.inner;
        let (req, q) = match wire::parse_request(request) {
            Request::Ask(req, q) => (req, q),
            Request::Reply(response) => return Ok(response),
            Request::Ignore => return Err(ResolveError::InvalidName),
        };
        inner.counters.queries.fetch_add(1, Ordering::Relaxed);
        // Never hand out addresses of a family this connection does not carry (the same rule as
        // `resolve`): an AAAA answer on an IPv4-only tunnel only makes a program try IPv6 first,
        // fail and fall back. The name may exist, so the answer is NODATA, not NXDOMAIN.
        let unusable = match q.qtype {
            RecordType::A => !inner.active().carries(false),
            RecordType::AAAA => !inner.active().carries(true),
            _ => false,
        };
        if unusable {
            return wire::no_data(&req).ok_or(ResolveError::Failed);
        }
        let start = Instant::now();
        let answer = if let Some(answer) = inner.cache.get(&q, start) {
            inner.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
            answer
        } else {
            let _permit = inner.admit()?;
            match inner.fetch(&q, start + inner.timeout).await {
                Ok((answer, upstream)) => {
                    inner.count_answer(upstream, start);
                    answer
                }
                Err(error) => {
                    inner.count_failure(error == ExchangeError::Timeout);
                    return Err(failure(error));
                }
            }
        };
        let (elapsed, remaining) = answer.age(Instant::now());
        wire::client_response(&req, &answer.wire, elapsed, remaining).ok_or(ResolveError::Failed)
    }
}

impl<C: TunnelConnector> Resolve for DnsResolver<C> {
    fn resolve(
        &self,
        host: &str,
        family: Family,
    ) -> impl Future<Output = Result<Vec<IpAddr>, ResolveError>> + Send {
        self.inner.resolve(host, family)
    }
}

/// Result of one (name, type) lookup, shared with coalesced callers: the answer, and whether it
/// came from an upstream exchange (rather than the cache).
type Outcome = Result<(Arc<Answer>, bool), ExchangeError>;

/// What a caller is told of a lookup that got no answer.
fn failure(error: ExchangeError) -> ResolveError {
    if error == ExchangeError::Interrupted {
        ResolveError::Interrupted
    } else {
        ResolveError::Failed
    }
}

/// `. IN NS` through `upstreams` within `deadline` (`timeout` from now): answered with NOERROR,
/// or why not, server by server.
async fn ask_root<C: TunnelConnector>(
    upstreams: &Upstreams<C>,
    q: &Question,
    deadline: Instant,
    timeout: Duration,
) -> Result<(), (ExchangeError, Vec<Text>)> {
    let mut tally = Tally::default();
    match upstreams.exchange_tallied(q, deadline, &mut tally).await {
        Ok(reply) if reply.msg.metadata.response_code == ResponseCode::NoError => Ok(()),
        Ok(_) => {
            tracing::debug!("DNS probe: NXDOMAIN for the root zone");
            let why = vec![tr!(
                "the server answered that the root zone does not exist (NXDOMAIN)",
                "伺服器回應根區域不存在（NXDOMAIN）",
                "サーバーはルートゾーンが存在しないと応答しました（NXDOMAIN）"
            )];
            Err((ExchangeError::Exhausted, why))
        }
        Err(error) => {
            tracing::debug!(?error, "DNS probe failed");
            Err((error, upstreams.explain(&tally, timeout)))
        }
    }
}

struct Inner<C: TunnelConnector> {
    upstreams: Arc<Upstreams<C>>,
    /// The `WireGuard` profile's resolvers, used while `on_fallback`.
    fallback: Option<Arc<Upstreams<C>>>,
    /// Every configured server failed the latest probe and the fallback answered.
    on_fallback: AtomicBool,
    /// `DnsOnFailure::Fail`: no fallback, lookups fail at once while `interrupted`.
    fail_closed: bool,
    /// Every configured server failed the latest probe and nothing else is asked.
    interrupted: AtomicBool,
    /// Why the latest probe failed, server by server.
    probe_failure: Mutex<Option<Text>>,
    cache: Cache,
    max_ttl: u32,
    negative_ttl: u32,
    timeout: Duration,
    inflight: Inflight,
    /// One permit per call waiting on upstream.
    permits: Semaphore,
    /// One health probe at a time.
    probes: Semaphore,
    counters: Arc<DnsCounters>,
}

impl<C: TunnelConnector> Inner<C> {
    /// The servers queries go to now: the configured ones, or the fallback while it stands in.
    fn active(&self) -> &Upstreams<C> {
        match &self.fallback {
            Some(fallback) if self.on_fallback.load(Ordering::Acquire) => fallback,
            _ => &self.upstreams,
        }
    }

    async fn resolve(&self, host: &str, family: Family) -> Result<Vec<IpAddr>, ResolveError> {
        let name = wire::parse_hostname(host).ok_or(ResolveError::InvalidName)?;
        // Only ask for families the tunnel carries.
        let ask = |wanted: bool, v6: bool, qtype| {
            (wanted && self.active().carries(v6)).then(|| Question::new(&name, qtype))
        };
        let a = ask(
            matches!(family, Family::Any | Family::V4),
            false,
            RecordType::A,
        );
        let aaaa = ask(
            matches!(family, Family::Any | Family::V6),
            true,
            RecordType::AAAA,
        );
        if a.is_none() && aaaa.is_none() {
            return Err(ResolveError::NotFound);
        }
        self.counters.queries.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();
        let cached_a = a.as_ref().and_then(|q| self.cache.get(q, start));
        let cached_aaaa = aaaa.as_ref().and_then(|q| self.cache.get(q, start));
        // NXDOMAIN is about the name, not the type: no need to ask for the other family.
        let nxdomain = [&cached_a, &cached_aaaa]
            .into_iter()
            .flatten()
            .any(|answer| answer.rcode == ResponseCode::NXDomain);
        let complete = a.is_some() == cached_a.is_some() && aaaa.is_some() == cached_aaaa.is_some();
        if nxdomain || complete {
            self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
            return self.addresses([
                cached_a.map(|answer| Ok((answer, false))),
                cached_aaaa.map(|answer| Ok((answer, false))),
            ]);
        }
        let _permit = self.admit()?;
        let deadline = start + self.timeout;
        let (from_a, from_aaaa) = tokio::join!(
            self.lookup(a.as_ref(), cached_a, deadline),
            self.lookup(aaaa.as_ref(), cached_aaaa, deadline),
        );
        let parts = [&from_a, &from_aaaa];
        let timed_out = parts
            .into_iter()
            .any(|o| matches!(o, Some(Err(ExchangeError::Timeout))));
        let upstream = parts.into_iter().any(|o| matches!(o, Some(Ok((_, true)))));
        let result = self.addresses([from_a, from_aaaa]);
        match &result {
            Ok(_) | Err(ResolveError::NotFound) => self.count_answer(upstream, start),
            Err(_) => self.count_failure(timed_out),
        }
        result
    }

    async fn lookup(
        &self,
        q: Option<&Question>,
        cached: Option<Arc<Answer>>,
        deadline: Instant,
    ) -> Option<Outcome> {
        let q = q?;
        Some(match cached {
            Some(answer) => Ok((answer, false)),
            None => self.fetch(q, deadline).await,
        })
    }

    /// A first, then AAAA; only families the tunnel carries.
    fn addresses(&self, parts: [Option<Outcome>; 2]) -> Result<Vec<IpAddr>, ResolveError> {
        let mut addrs = Vec::new();
        let mut nxdomain = false;
        let mut failed = None;
        for part in parts.into_iter().flatten() {
            match part {
                Ok((answer, _)) => {
                    nxdomain |= answer.rcode == ResponseCode::NXDomain;
                    addrs.extend(
                        answer
                            .addrs
                            .iter()
                            .copied()
                            .filter(|ip| self.active().supports(*ip)),
                    );
                }
                Err(error) => failed = Some(failure(error)),
            }
        }
        match failed {
            _ if !addrs.is_empty() => Ok(addrs),
            Some(error) if !nxdomain => Err(error),
            _ => Err(ResolveError::NotFound),
        }
    }

    fn admit(&self) -> Result<SemaphorePermit<'_>, ResolveError> {
        // Never closed: the only refusal is that every permit is taken.
        self.permits.try_acquire().map_err(|_no_permit| {
            self.counters.overloaded.fetch_add(1, Ordering::Relaxed);
            ResolveError::Overloaded
        })
    }

    /// A call answered without failure: the time until the upstream answer is an observation;
    /// an answer that was in the cache after all makes the call a cache hit.
    fn count_answer(&self, upstream: bool, start: Instant) {
        if upstream {
            self.counters.latency.record(micros(start.elapsed()));
        } else {
            self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn count_failure(&self, timed_out: bool) {
        self.counters.failures.fetch_add(1, Ordering::Relaxed);
        if timed_out {
            self.counters.latency.record_timeout();
        }
    }

    /// Upstream answer for `q`, shared with concurrent identical lookups and cached.
    async fn fetch(&self, q: &Question, deadline: Instant) -> Outcome {
        loop {
            match self.inflight.join(q) {
                Role::Leader(leader) => {
                    // Another leader may have finished between our cache miss and now.
                    if let Some(answer) = self.cache.get(q, Instant::now()) {
                        leader.finish(Ok((answer.clone(), false)));
                        return Ok((answer, false));
                    }
                    let outcome = if self.interrupted.load(Ordering::Acquire) {
                        // Every server failed the latest probe and the profile asks nothing
                        // else: fail now rather than at the deadline.
                        Err(ExchangeError::Interrupted)
                    } else {
                        match self.active().exchange(q, deadline).await {
                            Ok(reply) => {
                                let answer = Arc::new(self.answer(q, reply));
                                self.cache.insert(q.clone(), answer.clone());
                                Ok((answer, true))
                            }
                            Err(error) => Err(error),
                        }
                    };
                    leader.finish(outcome.clone());
                    return outcome;
                }
                Role::Waiter(mut rx) => {
                    let shared =
                        match tokio::time::timeout_at(deadline, rx.wait_for(Option::is_some)).await
                        {
                            Ok(Ok(value)) => Option::clone(&value),
                            // The caller driving the lookup went away without an answer: take over.
                            Ok(Err(_)) => None,
                            Err(_) => return Err(ExchangeError::Timeout),
                        };
                    if let Some(outcome) = shared {
                        return outcome;
                    }
                }
            }
        }
    }

    fn answer(&self, q: &Question, reply: Reply) -> Answer {
        let rcode = reply.msg.metadata.response_code;
        let addrs = wire::addresses(&reply.msg, q);
        let positive = rcode == ResponseCode::NoError && wire::has_data(&reply.msg, q, &addrs);
        let ttl = if positive {
            wire::min_answer_ttl(&reply.msg)
                .unwrap_or(0)
                .min(self.max_ttl)
        } else {
            self.negative_ttl
        };
        Answer {
            wire: reply.wire.into_boxed_slice(),
            rcode,
            addrs,
            ttl,
            fetched: Instant::now(),
        }
    }
}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

/// Lookups currently driven upstream, by question. Each entry belongs to a caller holding an
/// in-flight permit, so the map is bounded by `max_in_flight`.
#[derive(Default)]
struct Inflight {
    state: Mutex<InflightState>,
}

#[derive(Default)]
struct InflightState {
    map: HashMap<Question, (u64, watch::Receiver<Option<Outcome>>)>,
    next_token: u64,
}

enum Role<'a> {
    /// Drive the upstream exchange and publish its outcome.
    Leader(Leader<'a>),
    /// Wait for the leader's outcome.
    Waiter(watch::Receiver<Option<Outcome>>),
}

impl Inflight {
    fn join(&self, key: &Question) -> Role<'_> {
        let mut state = self.state.lock();
        if let Some((_, rx)) = state.map.get(key) {
            return Role::Waiter(rx.clone());
        }
        let (tx, rx) = watch::channel(None);
        state.next_token += 1;
        let token = state.next_token;
        state.map.insert(key.clone(), (token, rx));
        drop(state);
        Role::Leader(Leader {
            inflight: self,
            key: key.clone(),
            token,
            tx,
        })
    }

    fn leave(&self, key: &Question, token: u64) {
        let mut state = self.state.lock();
        if state.map.get(key).is_some_and(|(t, _)| *t == token) {
            state.map.remove(key);
        }
    }
}

struct Leader<'a> {
    inflight: &'a Inflight,
    key: Question,
    token: u64,
    tx: watch::Sender<Option<Outcome>>,
}

impl Leader<'_> {
    fn finish(self, outcome: Outcome) {
        self.inflight.leave(&self.key, self.token);
        self.tx.send_replace(Some(outcome));
    }
}

impl Drop for Leader<'_> {
    /// A leader dropped before `finish` (its caller was cancelled) unregisters; dropping the
    /// sender wakes the waiters, which then take over.
    fn drop(&mut self) {
        self.inflight.leave(&self.key, self.token);
    }
}
