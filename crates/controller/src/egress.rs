//! The Provider egress's direct exception on the controller side (architecture §7).
//!
//! **Scope.** A direct grant (the first setup's, or a manual rebootstrap's) carries only the
//! operations that build an egress: checking an account, its devices and keys, the server list,
//! building the one connection, and the exit check. Those handlers run inside [`recovery`]; any
//! other provider work — including anything a background task starts — sees no direct route
//! ([`crate::provider::route`] asks [`direct_allowed`]) and waits for a VPN egress.
//!
//! **Promotion.** The connection a run builds is recorded by the manager with the run (one Store
//! transaction with the Instance and its intent to run). [`drive`] completes that durable record:
//! once the connection is ready, its exit is checked through its own tunnel and the manager seals
//! the run (intent, grant closed, latch and binding committed); a connection that fails, is
//! stopped, deleted or not ready by the deadline is abandoned with the reason. A seal whose commit
//! the Store refused (its intent is on disk, direct access closed) is sent again, after a pause
//! that grows with each refusal, until it is committed: the manager closes direct access again and
//! commits, never reopens it. Nothing of this is kept here, so a restarted controller (or manager)
//! picks it up where it stands.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vpn_domain::{
    ApiError, BootstrapRun, BootstrapStage, DesiredState, ErrorCode, InstanceId, IpCheckStatus,
    OperationId, Phase, ProfileId, ProviderConnectResult, RouteMode, Text, Timestamp, tr,
};
use vpn_ipc::control::{Call, ChildClaimWire, EntityKind, Reply};

use crate::link::ManagerLink;
use crate::provider::{Providers, Relay, Route, egress, route_profile};

/// The active run of the direct exception, else the latest.
async fn latest_run(link: &ManagerLink) -> Result<Option<BootstrapRun>, ApiError> {
    match link.call(Call::BootstrapLatest).await? {
        Reply::BootstrapRun(r) => Ok(r.map(|r| *r)),
        _ => Err(ApiError::internal()),
    }
}

/// Which provider work the current task does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Building an egress: may use a direct grant.
    Recovery,
}

tokio::task_local! {
    static SCOPE: Scope;
}

/// Run `work` as an operation that builds an egress: it may use an open direct grant.
pub async fn recovery<F: Future>(work: F) -> F::Output {
    SCOPE.scope(Scope::Recovery, work).await
}

/// Whether the current task may use a direct grant.
#[must_use]
pub fn direct_allowed() -> bool {
    SCOPE.try_with(|s| *s == Scope::Recovery).unwrap_or(false)
}

/// Claim the active run's one connection for the connect request `operation` (before any provider
/// request is made).
///
/// # Errors
///
/// The manager's error (no active run, a refused claim), or an internal error when it answers
/// out of contract.
pub async fn claim(link: &ManagerLink, operation: OperationId) -> Result<ChildClaimWire, ApiError> {
    match link.call(Call::BootstrapClaimChild { operation }).await? {
        Reply::BootstrapClaim(c) => Ok(c),
        _ => Err(ApiError::internal()),
    }
}

/// How often a connect request renews its reservation of the run's one connection.
///
/// It renews while it builds it: several times within the Store's reservation lifetime (`RESERVATION_TTL`, 90 s),
/// which only a request that died (its controller gone) outlives.
pub const RESERVATION_RENEW: Duration = Duration::from_secs(20);

/// Run `work` and renew its reservation every `every` until it ends.
///
/// `work` builds run `run`'s one connection for the connect request `operation`; renewing
/// means another request cannot take it over
/// however slow the provider requests are. A renewal still on its way when `work` ends changes
/// nothing once the reservation is given back or the connection exists.
pub async fn renewing<F: Future>(
    link: &ManagerLink,
    run: &str,
    operation: OperationId,
    every: Duration,
    work: F,
) -> F::Output {
    let renew = async {
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let renewed = link
                .call(Call::BootstrapRenewChild {
                    run: run.to_string(),
                    operation,
                })
                .await;
            if let Err(e) = renewed {
                tracing::debug!(error = %e, "reservation of the run's connection not renewed this time");
            }
        }
    };
    tokio::select! {
        out = work => out,
        never = renew => never,
    }
}

/// Whether `profile` is the one a run of the direct exception built (and may be fixed over it).
pub async fn is_run_child(link: &ManagerLink, profile: ProfileId) -> bool {
    latest_run(link).await.is_ok_and(|r| {
        r.is_some_and(|r| r.stage.is_active() && r.child_profile_id == Some(profile))
    })
}

/// The run already has its connection: start it again and wait for it anew — no second
/// connection, device or key.
///
/// # Errors
///
/// An internal error when the run has no profile, and the manager's error when the connection
/// cannot be started again.
pub async fn reuse(
    link: &ManagerLink,
    run: String,
    instance: InstanceId,
    profile: Option<ProfileId>,
) -> Result<ProviderConnectResult, ApiError> {
    let profile_id = profile.ok_or_else(ApiError::internal)?;
    link.call(Call::BootstrapResumeChild { run }).await?;
    Ok(ProviderConnectResult {
        profile_id,
        instance_id: instance,
        gateway_id: None,
        device_id: String::new(),
        device: None,
        becomes_egress: true,
        reused: true,
    })
}

/// How often the durable promotion is looked at (one Store read).
const TICK: Duration = Duration::from_secs(1);
/// Between two exit checks of the same connection.
const RECHECK: Duration = Duration::from_secs(5);
/// The pause after a seal commit the Store refused, doubled after each further refusal up to
/// [`SEAL_RETRY_MAX`].
const SEAL_RETRY_MIN: Duration = Duration::from_secs(1);
const SEAL_RETRY_MAX: Duration = Duration::from_secs(30);

/// What the driver remembers between ticks (nothing durable: a restart starts over safely).
#[derive(Default)]
pub struct Promoter {
    last_check: Option<(InstanceId, u64, Instant)>,
    /// Why the last exit check through the new connection failed.
    last_failure: Option<Text>,
    /// The sealing run whose commit was refused last: not sent again before `next`.
    seal_retry: Option<SealRetry>,
}

impl std::fmt::Debug for Promoter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Promoter")
            .field("last_check", &self.last_check)
            .field("last_failure", &self.last_failure)
            .field("seal_retry", &self.seal_retry.is_some())
            .finish_non_exhaustive()
    }
}

struct SealRetry {
    run: String,
    next: Instant,
    pause: Duration,
}

impl Promoter {
    /// Whether the commit of sealing run `run` may be sent now.
    fn seal_due(&self, run: &str, now: Instant) -> bool {
        self.seal_retry
            .as_ref()
            .is_none_or(|r| r.run != run || now >= r.next)
    }

    /// The commit of `run` was refused at `now`: the pause before the next attempt.
    fn seal_refused(&mut self, run: &str, now: Instant) -> Duration {
        let pause = match &self.seal_retry {
            Some(r) if r.run == run => (r.pause * 2).min(SEAL_RETRY_MAX),
            _ => SEAL_RETRY_MIN,
        };
        self.seal_retry = Some(SealRetry {
            run: run.to_string(),
            next: now + pause,
            pause,
        });
        pause
    }
}

/// Complete or abandon the durable promotion, forever (one per controller).
pub async fn drive(providers: Arc<Providers>, link: Arc<ManagerLink>) {
    let mut p = Promoter::default();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if !link.connected() {
            continue;
        }
        if let Err(e) = step(&providers, &link, &mut p).await {
            tracing::debug!(error = %e, "provider egress promotion: not this time");
        }
    }
}

async fn abandon(link: &ManagerLink, run: &str, code: &str, reason: Text) -> Result<(), ApiError> {
    tracing::warn!(reason = %reason.en, "new connection was not made the provider egress");
    link.call(Call::BootstrapAbandon {
        run: run.to_string(),
        reason_code: code.into(),
        reason,
    })
    .await?;
    Ok(())
}

/// The run's connection did not connect and pass its exit check by the deadline.
async fn timed_out(link: &ManagerLink, run: &str, p: &mut Promoter) -> Result<(), ApiError> {
    let reason = p.last_failure.take().map_or_else(
        || {
            tr!(
                "The new connection did not come up and pass its exit check in time and was not made the egress",
                "新連線在時限內沒有連上並通過出口檢查，未設為出口",
                "新しい接続が期限内につながらないか、出口チェックに合格しなかったため、出口にしませんでした"
            )
        },
        |why| {
            tr!(
                "The new connection did not come up and pass its exit check in time and was not made the egress (exit check: {why})",
                "新連線在時限內沒有連上並通過出口檢查，未設為出口（出口檢查：{why}）",
                "新しい接続が期限内につながらないか、出口チェックに合格しなかったため、出口にしませんでした（出口チェック：{why}）";
                why = why
            )
        },
    );
    abandon(link, run, "PROMOTE_TIMEOUT", reason).await
}

/// Whether the Store no longer has Instance `id` (an error: not known).
async fn instance_gone(link: &ManagerLink, id: InstanceId) -> Result<bool, ApiError> {
    match link
        .call(Call::Get(EntityKind::Instance, id.to_string()))
        .await
    {
        Ok(_) => Ok(false),
        Err(e) if e.code == ErrorCode::NotFound => Ok(true),
        Err(e) => Err(e),
    }
}

/// A run whose seal stopped after its intent (the Store refused the commit — its queue or the
/// disk full, an I/O error — or the manager's start could not finish it): its commit is sent
/// again, at most once per pause. The manager closes the run's grant (if it still holds it) and
/// commits; nothing reopens direct access.
async fn commit_seal(
    link: &ManagerLink,
    run: BootstrapRun,
    p: &mut Promoter,
) -> Result<(), ApiError> {
    let Some(child) = run.child_instance_id else {
        return Ok(());
    };
    if !p.seal_due(&run.id, Instant::now()) {
        return Ok(());
    }
    // The commit does not look at the connection's generation: the exit check that decided the
    // seal passed before its intent was written, and the seal goes forward whatever happens now.
    let sent = link
        .call(Call::BootstrapSeal {
            run: run.id.clone(),
            instance: child,
            generation: 0,
        })
        .await;
    match sent {
        Ok(_) => {
            p.seal_retry = None;
            tracing::info!(instance = %child, "provider egress seal committed; direct access closed");
            Ok(())
        }
        Err(e) => {
            let pause = p.seal_refused(&run.id, Instant::now());
            tracing::warn!(error = %e, retry_in = ?pause, "provider egress seal not committed yet (direct access stays closed)");
            Err(e)
        }
    }
}

/// One look at the active run's connection: seal, abandon, or wait.
///
/// # Errors
///
/// The manager's error when the run, the connection's status or its route cannot be read or
/// the run cannot be abandoned or sealed; an internal error when it answers out of contract.
pub async fn step(
    providers: &Providers,
    link: &ManagerLink,
    p: &mut Promoter,
) -> Result<(), ApiError> {
    let Some(run) = latest_run(link).await?.filter(|r| {
        matches!(
            r.stage,
            BootstrapStage::InstanceRequested | BootstrapStage::Sealing
        )
    }) else {
        p.last_failure = None;
        p.seal_retry = None;
        return Ok(());
    };
    if run.stage == BootstrapStage::Sealing {
        return commit_seal(link, run, p).await;
    }
    let Some(child) = run.child_instance_id else {
        return Ok(());
    };
    let overdue = run
        .promote_deadline
        .is_some_and(|d| d.unix_millis() <= Timestamp::now().unix_millis());
    let status = match link.call(Call::InstanceStatus(child)).await {
        Ok(Reply::Status(s)) => *s,
        Ok(_) => return Err(ApiError::internal()),
        // The manager answers for an Instance only while its actor is there (not yet right
        // after the connection was created, no longer while it stops): only the Store's word
        // that the connection is gone ends the run as deleted. A delete through the Store ends
        // the run in the same transaction anyway.
        Err(e) if e.code == ErrorCode::NotFound => {
            if instance_gone(link, child).await? {
                return abandon(
                    link,
                    &run.id,
                    "CHILD_GONE",
                    tr!(
                        "The new connection was deleted and was not made the egress",
                        "新連線已被刪除，未設為出口",
                        "新しい接続が削除されたため出口にしませんでした"
                    ),
                )
                .await;
            }
            if overdue {
                return timed_out(link, &run.id, p).await;
            }
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let intent = &status.intent;
    if intent.manual_stop || intent.emergency_latched || intent.desired == DesiredState::Stopped {
        return abandon(
            link,
            &run.id,
            "CHILD_STOPPED",
            tr!(
                "The new connection was stopped and was not made the egress",
                "新連線已被停止，未設為出口",
                "新しい接続が停止されたため出口にしませんでした"
            ),
        )
        .await;
    }
    if matches!(status.phase, Phase::Failed | Phase::RecoveryRequired) {
        let reason = status.recovery.last_fault.as_ref().map_or_else(
            || {
                tr!(
                    "The new connection did not come up and was not made the egress",
                    "新連線沒有連上，未設為出口",
                    "新しい接続がつながらなかったため出口にしませんでした"
                )
            },
            |fault| {
                tr!(
                    "The new connection did not come up and was not made the egress: {why}",
                    "新連線沒有連上，未設為出口：{why}",
                    "新しい接続がつながらなかったため出口にしませんでした：{why}";
                    why = fault.message.clone()
                )
            },
        );
        return abandon(link, &run.id, "CHILD_FAILED", reason).await;
    }
    if overdue {
        return timed_out(link, &run.id, p).await;
    }
    let generation = match (&status.phase, &status.running) {
        (Phase::Ready, Some(r)) => r.generation,
        _ => return Ok(()),
    };
    prove_and_seal(providers, link, p, run.id, child, generation).await
}

/// Prove run `run`'s connection `child` (at `generation`) with an exit check through its own
/// tunnel, at most once per [`RECHECK`], and seal it as the egress when the check passes.
async fn prove_and_seal(
    providers: &Providers,
    link: &ManagerLink,
    p: &mut Promoter,
    run: String,
    child: InstanceId,
    generation: u64,
) -> Result<(), ApiError> {
    if p.last_check
        .is_some_and(|(i, g, at)| i == child && g == generation && at.elapsed() < RECHECK)
    {
        return Ok(());
    }
    p.last_check = Some((child, generation, Instant::now()));
    // Prove the new route before direct access is given up for good: the exit answers through
    // the new connection's own tunnel.
    let connector = match link.call(Call::ProviderRoute(child)).await? {
        Reply::ProviderRoute {
            generation: g,
            connector,
        } if g == generation => connector,
        Reply::ProviderRoute { .. } => return Ok(()),
        _ => return Err(ApiError::internal()),
    };
    let epoch = egress(link).await.map_or(0, |(e, _)| e.route_revision);
    let route = Route {
        mode: RouteMode::ViaInstance,
        instance_id: Some(child),
        generation: Some(generation),
        egress_epoch: epoch,
        relay: Relay::instance(connector, child, generation),
    };
    // The explicit check of a route: within the checker's budget, recorded as the latest check
    // (the switching egress shows it) and in the provider's gates.
    let profile = route_profile(link, &route).await;
    let ok = match providers.check_route(&route, profile).await {
        Ok((c, _)) if c.status == IpCheckStatus::Ok => true,
        Ok((_, why)) => {
            p.last_failure = Some(why.unwrap_or_else(|| {
                tr!("could not be completed", "無法完成", "完了できませんでした")
            }));
            false
        }
        Err(e) => {
            p.last_failure = Some(e.message);
            false
        }
    };
    if !ok {
        return Ok(());
    }
    link.call(Call::BootstrapSeal {
        run,
        instance: child,
        generation,
    })
    .await?;
    p.last_failure = None;
    tracing::info!(instance = %child, "new connection is the provider egress; direct access closed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_seal_commit_is_sent_again_after_a_growing_pause() {
        let mut p = Promoter::default();
        let t0 = Instant::now();
        assert!(p.seal_due("r", t0));
        assert_eq!(p.seal_refused("r", t0), SEAL_RETRY_MIN);
        assert!(!p.seal_due("r", t0));
        assert!(p.seal_due("r", t0 + SEAL_RETRY_MIN));
        assert_eq!(p.seal_refused("r", t0), SEAL_RETRY_MIN * 2);
        let mut pause = Duration::ZERO;
        for _ in 0..10 {
            pause = p.seal_refused("r", t0);
        }
        assert_eq!(pause, SEAL_RETRY_MAX);
        // Another run does not wait for this one's pause.
        assert!(p.seal_due("other", t0));
        assert_eq!(p.seal_refused("other", t0), SEAL_RETRY_MIN);
    }
}
