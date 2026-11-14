//! The Provider egress guard: the one choke point of every provider HTTP request (spec AC-74,
//! AC-76, AC-77, AC-82; architecture §9 keeps "每次 Provider HTTP 都做 IP preflight").
//!
//! An operation takes a [`Guard`] pinned to the egress route it starts on, and every client of
//! that operation connects through it: the token, the account, the device list, a create and
//! its reconcile, every `AirVPN` bootstrap attempt, the server status list. Each connection is one
//! request, and each request, in this order:
//!
//! 1. reserves its exit check and itself together in the per-origin budget;
//! 2. reads the route in force from the manager. It must be the operation's own: a switch, a
//!    rebuild (another generation) or turning the egress off refuses every further request. The
//!    guard never follows the egress to another connection and never picks one by itself;
//! 3. runs a fresh exit check over that same route and address family — through the relay
//!    directly, not through the guard (no recursion), and without any account credential;
//! 4. right before the request's relay line is written: reads the route again (unchanged), and
//!    the check must be at most [`PERMIT_TTL`] old. A check that went stale waiting is replaced
//!    by one fresh check, never used;
//! 5. writes the relay line with a single-use nonce, the route, and the connector epochs the
//!    check saw; the connector refuses a reused nonce, a line for another route, and epochs
//!    that moved since the check (another connector, or the tunnel re-opened);
//! 6. right before the request's first byte (after the TLS handshake): reads the route once
//!    more, and the request about to be written must be the one the permit was issued for
//!    (method, host, path).
//!
//! A refusal at any step sends nothing to the provider and says why. A 429 — from the provider
//! or its exit checker — holds that origin for its `Retry-After`.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};
use tokio::time::{Instant, timeout_at};
use vpn_domain::{ApiError, ErrorCode, IpCheckStatus, ProviderKind, Text, tr};
use vpn_ipc::relay::RelayEpochs;
use vpn_providers::{
    BoxedStream, Confirmation, Connect, Family, OpenError, Opened, Permit, Refusal, Target,
};
use vpn_sync::Mutex;

use super::{Providers, RelayError, Route};
use crate::link::ManagerLink;

/// How long one exit check authorizes its request (spec: 2 s).
pub const PERMIT_TTL: Duration = Duration::from_secs(2);

/// The permit lifetime in force ([`PERMIT_TTL`] unless a test fixture shortens it).
#[derive(Debug, Clone, Copy)]
pub struct PermitTtl(pub Duration);

impl Default for PermitTtl {
    fn default() -> Self {
        Self(PERMIT_TTL)
    }
}

/// What a route's exit check depends on: whose checker answers for it (the profile's provider)
/// and whether the connection has an IPv6 address at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteProfile {
    pub provider: ProviderKind,
    pub ipv6: bool,
}

/// Where the guard reads the binding in force: the manager in the product, a fake in tests.
pub trait Egress: Send + Sync {
    /// The route provider traffic leaves by now, or why it cannot leave.
    fn route(&self) -> impl Future<Output = Result<Route, ApiError>> + Send;
    /// The profile behind `route`.
    fn profile(&self, route: &Route) -> impl Future<Output = RouteProfile> + Send;
}

impl Egress for ManagerLink {
    fn route(&self) -> impl Future<Output = Result<Route, ApiError>> + Send {
        super::route(self)
    }

    fn profile(&self, route: &Route) -> impl Future<Output = RouteProfile> + Send {
        super::route_profile(self, route)
    }
}

/// The host of the exit checker for `provider`'s profiles over `family`; `None` when there is
/// none (`IPLeak` over IPv6 is not verified: AIR-IPV6-01).
#[must_use]
pub const fn checker_host(provider: ProviderKind, family: Family) -> Option<&'static str> {
    use vpn_providers::ipcheck::{AIRVPN_HOST, IPLEAK_V4_HOST, MULLVAD_V4_HOST, MULLVAD_V6_HOST};
    match (provider, family) {
        (ProviderKind::Mullvad, Family::V4) => Some(MULLVAD_V4_HOST),
        (ProviderKind::Mullvad, Family::V6) => Some(MULLVAD_V6_HOST),
        (ProviderKind::Airvpn, _) => Some(AIRVPN_HOST),
        (ProviderKind::Generic, Family::V4) => Some(IPLEAK_V4_HOST),
        (ProviderKind::Generic, Family::V6) => None,
    }
}

fn refused(code: ErrorCode, message: impl Into<Text>) -> Refusal {
    Refusal::new(code, message)
}

/// The route in force is not the one the operation (and its check) started on.
fn switched(from: &Route, to: &Route) -> Refusal {
    let message = if from.mode == to.mode
        && from.instance_id == to.instance_id
        && from.egress_epoch == to.egress_epoch
        && from.generation != to.generation
    {
        let (was, now) = (from.generation.unwrap_or(0), to.generation.unwrap_or(0));
        tr!(
            "The egress connection was re-established during the operation (generation {was} → {now}); the request was not sent. Do the operation again",
            "出口連線在操作途中重新建立（第 {was} 代 → 第 {now} 代），未送出請求；請重新操作",
            "操作の途中で出口接続が再確立されました（第 {was} 世代 → 第 {now} 世代）。リクエストは送信していません。もう一度操作してください"
        )
    } else if from.mode == to.mode
        && from.instance_id == to.instance_id
        && from.egress_epoch == to.egress_epoch
    {
        tr!(
            "The provider channel was replaced during the operation; the request was not sent. Do the operation again",
            "供應商通道在操作途中已更換，未送出請求；請重新操作",
            "操作の途中でプロバイダーチャネルが入れ替わりました。リクエストは送信していません。もう一度操作してください"
        )
    } else {
        tr!(
            "The Provider egress changed during the operation (switched, disabled, or the first direct connection ended); the request was not sent. This operation never moves to another egress; do it again",
            "Provider 出口在操作途中已變更（切換、停用或首次直連結束），未送出請求；這個操作不會改走其他出口，請重新操作",
            "操作の途中で Provider 出口が変更されました（切り替え、無効化、または初回の直接接続の終了）。リクエストは送信していません。この操作がほかの出口に切り替わることはありません。もう一度操作してください"
        )
    };
    refused(ErrorCode::ProviderEgressBlocked, message)
}

/// What a check that authorizes one request is bound to.
struct Ticket {
    /// The connector's epochs as the check saw them; named in the relay line.
    epochs: RelayEpochs,
    /// The request it was issued for.
    digest: [u8; 32],
}

/// The guard of one operation, pinned to the route it started on.
pub struct Guard<'a, E: Egress> {
    egress: &'a E,
    providers: &'a Providers,
    route: Route,
    profile: RouteProfile,
}

impl<E: Egress> Clone for Guard<'_, E> {
    fn clone(&self) -> Self {
        Self {
            egress: self.egress,
            providers: self.providers,
            route: self.route.clone(),
            profile: self.profile,
        }
    }
}

impl<'a, E: Egress> Guard<'a, E> {
    /// The guard of an operation starting now, on the route in force.
    ///
    /// # Errors
    ///
    /// The Provider egress error when there is no usable route (disabled, none selected, not
    /// connected), or the manager's error when it cannot be read.
    pub async fn new(egress: &'a E, providers: &'a Providers) -> Result<Self, ApiError> {
        let route = egress.route().await?;
        let profile = egress.profile(&route).await;
        Ok(Self {
            egress,
            providers,
            route,
            profile,
        })
    }

    /// The route the operation is pinned to.
    #[must_use]
    pub const fn route(&self) -> &Route {
        &self.route
    }

    #[must_use]
    pub const fn profile(&self) -> RouteProfile {
        self.profile
    }

    /// The route in force now, which must still be the operation's own.
    async fn current(&self) -> Result<Route, Refusal> {
        let now = self.egress.route().await.map_err(|e| {
            // The reason ends where this sentence goes on: without its full stop (U+3002 in
            // Chinese and Japanese).
            let why = e
                .message
                .map(|_, s| s.trim_end_matches(['.', '\u{3002}']).to_owned());
            refused(
                e.code,
                tr!(
                    "{why}; no provider request was sent",
                    "{why}；未送出供應商請求",
                    "{why}。プロバイダーへのリクエストは送信していません";
                    why = why
                ),
            )
        })?;
        if now != self.route {
            return Err(switched(&self.route, &now));
        }
        Ok(now)
    }

    /// Steps 1–5 for one request (see the module documentation).
    async fn admit<'g>(&'g self, target: &'g Target<'g>) -> Result<Opened<'g>, OpenError> {
        let ttl = self.providers.permit_ttl.0;
        let budget = &self.providers.budget;
        let checker = checker_host(self.profile.provider, target.family).ok_or_else(|| {
            OpenError::Refused(refused(
                ErrorCode::ProviderPreflightFailed,
                tr!(
                    "This connection's exit check (IPLeak) does not support IPv6 (AIR-IPV6-01 is not verified yet), so no provider request is sent over IPv6",
                    "這條連線的出口檢查（IPLeak）不支援 IPv6（AIR-IPV6-01 尚未驗證），不經 IPv6 送出供應商請求",
                    "この接続の出口チェック（IPLeak）は IPv6 に対応していません（AIR-IPV6-01 は未検証）。IPv6 ではプロバイダーへのリクエストを送信しません"
                ),
            ))
        })?;
        budget
            .reserve(&[checker, target.host])
            .await
            .map_err(OpenError::Refused)?;
        for attempt in 0..2 {
            if attempt > 0 {
                // A fresh check for the one that went stale: its own share of the budget.
                budget
                    .reserve(&[checker])
                    .await
                    .map_err(OpenError::Refused)?;
            }
            let route = self.current().await.map_err(OpenError::Refused)?;
            let (check, why, epochs) = self
                .providers
                .probe(&route, self.profile.provider, target.family)
                .await;
            let checked_at = Instant::now();
            if check.status != IpCheckStatus::Ok {
                let why =
                    why.unwrap_or_else(|| tr!("cannot connect", "無法連線", "接続できません"));
                return Err(OpenError::Refused(refused(
                    ErrorCode::ProviderPreflightFailed,
                    tr!(
                        "The exit check did not pass, so no provider request was sent: {why}",
                        "出口檢查沒有通過，未送出任何供應商請求：{why}",
                        "出口チェックに合格しなかったため、プロバイダーへのリクエストは送信していません：{why}";
                        why = why
                    ),
                )));
            }
            let Some(epochs) = epochs else {
                return Err(OpenError::Refused(refused(
                    ErrorCode::ProviderPreflightFailed,
                    tr!(
                        "The exit check did not report the channel's state, so no provider request was sent",
                        "出口檢查沒有回報通道狀態，未送出供應商請求",
                        "出口チェックがチャネルの状態を報告しなかったため、プロバイダーへのリクエストは送信していません"
                    ),
                )));
            };
            // Right before the line: the same route, and a check young enough.
            self.current().await.map_err(OpenError::Refused)?;
            if checked_at.elapsed() > ttl {
                tracing::info!(
                    attempt,
                    "provider exit check went stale before its request; checking again"
                );
                continue;
            }
            let ticket = Ticket {
                epochs,
                digest: target.digest(),
            };
            let admitted = Instant::now();
            let open =
                route
                    .relay
                    .open(target.host, target.port, target.family, Some(ticket.epochs));
            let stream = match timeout_at(admitted + target.timeout, open).await {
                Ok(Ok((stream, _))) => stream,
                Ok(Err(RelayError::Refused(r))) => return Err(OpenError::Refused(r)),
                Ok(Err(RelayError::Io(e))) => return Err(OpenError::Io(e)),
                Err(_) => return Err(OpenError::TimedOut),
            };
            return Ok(Opened {
                stream: Box::new(stream),
                permit: Some(Box::new(Issued {
                    guard: self,
                    ticket,
                    origin: target.host.to_owned(),
                })),
                admitted,
            });
        }
        let secs = ttl.as_secs_f64();
        Err(OpenError::Refused(refused(
            ErrorCode::ProviderPreflightFailed,
            tr!(
                "The request was still not sent more than {secs} s after the exit check (the wait expired), so no provider request was sent; try again",
                "出口檢查之後超過 {secs} 秒仍未送出（等待逾期），未送出供應商請求；請重試",
                "出口チェックから {secs} 秒を過ぎても送信されなかったため（待機の期限切れ）、プロバイダーへのリクエストは送信していません。もう一度お試しください"
            ),
        )))
    }
}

impl<E: Egress> Connect for Guard<'_, E> {
    fn connect(
        &self,
        _: &str,
        _: u16,
        _: Family,
    ) -> impl Future<Output = io::Result<BoxedStream>> + Send {
        // A request is authorized together with what it is; nothing opens without that. The
        // refusal inside the I/O error is the reason a person reads.
        std::future::ready(Err(io::Error::other(refused(
            ErrorCode::Internal,
            tr!(
                "A provider request can only be sent through an exit check (internal error: the request is missing)",
                "供應商請求只能經出口檢查送出（內部錯誤：缺少請求內容）",
                "プロバイダーへのリクエストは出口チェックを経てのみ送信できます（内部エラー：リクエストの内容がありません）"
            ),
        ))))
    }

    fn connect_for<'g>(
        &'g self,
        target: &'g Target<'g>,
    ) -> impl Future<Output = Result<Opened<'g>, OpenError>> + Send + 'g {
        self.admit(target)
    }
}

/// The permit of one admitted request.
struct Issued<'g, 'a, E: Egress> {
    guard: &'g Guard<'a, E>,
    ticket: Ticket,
    origin: String,
}

impl<E: Egress> Permit for Issued<'_, '_, E> {
    fn confirm<'c>(&'c mut self, sent: &'c Target<'c>) -> Confirmation<'c> {
        Box::pin(async move {
            if sent.digest() != self.ticket.digest {
                return Err(refused(
                    ErrorCode::ProviderPreflightFailed,
                    tr!(
                        "The request about to be sent differs from the one prepared at the exit check (method, host or path); refused",
                        "要送出的請求與出口檢查時準備的不同（方法、主機或路徑），已拒絕送出",
                        "送信しようとしたリクエストが出口チェック時に準備したもの（メソッド、ホスト、パス）と異なるため、送信を拒否しました"
                    ),
                ));
            }
            self.guard.current().await.map(|_| ())
        })
    }

    fn answered(&mut self, status: StatusCode, headers: &HeaderMap) {
        if status == StatusCode::TOO_MANY_REQUESTS {
            self.guard
                .providers
                .budget
                .hold(&self.origin, vpn_providers::error::retry_delay(headers));
        }
    }
}

/// The relay of one exit check: unguarded (a check needs no permit and carries no credential),
/// remembering the epochs its connector reported.
pub(super) struct Probe {
    relay: super::Relay,
    epochs: Mutex<Option<RelayEpochs>>,
}

impl Probe {
    pub(super) fn new(relay: super::Relay) -> Arc<Self> {
        Arc::new(Self {
            relay,
            epochs: Mutex::new(None),
        })
    }

    pub(super) fn epochs(&self) -> Option<RelayEpochs> {
        *self.epochs.lock()
    }
}

impl Connect for Probe {
    async fn connect(&self, host: &str, port: u16, family: Family) -> io::Result<BoxedStream> {
        let (stream, epochs) = self
            .relay
            .open(host, port, family, None)
            .await
            .map_err(RelayError::into_io)?;
        *self.epochs.lock() = Some(epochs);
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_permit_lives_two_seconds() {
        assert_eq!(PERMIT_TTL, Duration::from_secs(2));
    }

    #[test]
    fn every_route_has_a_checker_except_ipleak_over_ipv6() {
        for p in [
            ProviderKind::Mullvad,
            ProviderKind::Airvpn,
            ProviderKind::Generic,
        ] {
            assert!(checker_host(p, Family::V4).is_some());
        }
        assert_eq!(
            checker_host(ProviderKind::Mullvad, Family::V6),
            Some("ipv6.am.i.mullvad.net")
        );
        assert_eq!(checker_host(ProviderKind::Generic, Family::V6), None);
    }
}
