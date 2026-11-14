//! Provider request budget, per origin (the host a request names: `api.mullvad.net`,
//! `airvpn.org`, an `AirVPN` bootstrap address). Spec AC-82:
//!
//! - Every guarded request reserves its exit check and itself together, before either is sent:
//!   a check is never spent on a request that would then wait, and a request never waits after
//!   its check (it would only go stale).
//! - The budget belongs to the origin, not to the route: switching the egress neither resets it
//!   nor gives the new route a budget of its own.
//! - A 429 holds the origin until its `Retry-After` (capped at [`MAX_HOLD`]; a default when the
//!   provider names none). Nothing is sent to it before then.
//! - A request whose turn is further away than its queue allows is refused at once, with the
//!   time to wait, instead of hanging the user's request.
//!
//! Only provider requests pass here. App and Gateway payload never reaches the controller: it
//! is relayed inside each Instance worker and never waits for this budget.

use std::collections::HashMap;
use std::time::Duration;

use tokio::time::Instant;
use vpn_domain::{ErrorCode, tr};
use vpn_providers::Refusal;
use vpn_sync::Mutex;

/// Longest hold a provider's `Retry-After` can impose.
pub const MAX_HOLD: Duration = Duration::from_hours(1);

/// The budget's shape.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Requests an origin may take at once.
    pub burst: u32,
    /// Requests an origin regains per second.
    pub per_second: f64,
    /// Longest a request waits for its turn; beyond that it is refused at once.
    pub queue_max: Duration,
    /// Hold after a 429 that names no `Retry-After`.
    pub default_hold: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            burst: 20,
            per_second: 1.0,
            queue_max: Duration::from_secs(5),
            default_hold: Duration::from_secs(30),
        }
    }
}

struct Bucket {
    tokens: f64,
    at: Instant,
    hold_until: Option<Instant>,
}

impl Bucket {
    fn refill(&mut self, now: Instant, limits: &Limits) {
        let gained = now.saturating_duration_since(self.at).as_secs_f64() * limits.per_second;
        self.tokens = (self.tokens + gained).min(f64::from(limits.burst));
        self.at = now;
    }

    /// When `n` requests can go.
    fn ready_at(&self, n: u32, now: Instant, limits: &Limits) -> Instant {
        let missing = f64::from(n) - self.tokens;
        let by_rate = if missing <= 0.0 {
            now
        } else if limits.per_second > 0.0 {
            now + Duration::from_secs_f64(missing / limits.per_second)
        } else {
            // Nothing is regained: never within any queue.
            now + MAX_HOLD
        };
        self.hold_until.map_or(by_rate, |h| h.max(by_rate))
    }
}

pub struct Budget {
    limits: Limits,
    origins: Mutex<HashMap<String, Bucket>>,
}

impl std::fmt::Debug for Budget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Budget").finish_non_exhaustive()
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Budget {
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            origins: Mutex::default(),
        }
    }

    /// Reserve one request on each of `origins` (one listed twice takes two), all at once or
    /// none: waits for the turn (a hold, the rate) up to the queue limit and refuses at once
    /// when it is further away. Returns how long the request waited.
    ///
    /// # Errors
    ///
    /// A `PROVIDER_QUOTA_EXCEEDED` [`Refusal`] when one of `origins` is held or its turn is
    /// further away than the queue limit; nothing is reserved then.
    pub async fn reserve(&self, origins: &[&str]) -> Result<Duration, Refusal> {
        let started = Instant::now();
        let mut wanted: Vec<(String, u32)> = Vec::new();
        for o in origins {
            let o = o.to_ascii_lowercase();
            match wanted.iter_mut().find(|(w, _)| *w == o) {
                Some((_, n)) => *n += 1,
                None => wanted.push((o, 1)),
            }
        }
        if let Some((origin, _)) = wanted.iter().find(|(_, n)| *n > self.limits.burst) {
            return Err(refusal(origin, None, Duration::ZERO));
        }
        loop {
            let (origin, ready_at, held) = {
                let now = Instant::now();
                let mut map = self.origins.lock();
                let mut last: Option<(&str, Instant, bool)> = None;
                for (origin, n) in &wanted {
                    let b = map.entry(origin.clone()).or_insert_with(|| Bucket {
                        tokens: f64::from(self.limits.burst),
                        at: now,
                        hold_until: None,
                    });
                    b.refill(now, &self.limits);
                    let at = b.ready_at(*n, now, &self.limits);
                    let held = b.hold_until.is_some_and(|h| h >= at);
                    if last.is_none_or(|(_, l, _)| at > l) {
                        last = Some((origin, at, held));
                    }
                }
                let (origin, ready_at, held) = last.unwrap_or(("", now, false));
                if ready_at <= now {
                    for (origin, n) in &wanted {
                        if let Some(b) = map.get_mut(origin) {
                            b.tokens -= f64::from(*n);
                            if b.hold_until.is_some_and(|h| h <= now) {
                                b.hold_until = None;
                            }
                        }
                    }
                    return Ok(started.elapsed());
                }
                (origin.to_owned(), ready_at, held)
            };
            let wait = ready_at.saturating_duration_since(Instant::now());
            if started.elapsed() + wait > self.limits.queue_max {
                return Err(refusal(&origin, held.then_some(()), wait));
            }
            tokio::time::sleep(wait).await;
        }
    }

    /// `origin` answered 429: nothing more goes to it for `retry_after` (the provider's
    /// `Retry-After`, capped at [`MAX_HOLD`]; a default when it named none). An earlier, longer
    /// hold stays.
    pub fn hold(&self, origin: &str, retry_after: Option<Duration>) {
        let hold = retry_after
            .unwrap_or(self.limits.default_hold)
            .min(MAX_HOLD);
        let now = Instant::now();
        let until = now + hold;
        let mut map = self.origins.lock();
        let b = map
            .entry(origin.to_ascii_lowercase())
            .or_insert_with(|| Bucket {
                tokens: f64::from(self.limits.burst),
                at: now,
                hold_until: None,
            });
        b.hold_until = Some(b.hold_until.map_or(until, |h| h.max(until)));
        drop(map);
        tracing::warn!(
            origin,
            hold_secs = hold.as_secs(),
            "provider origin rate limited; held"
        );
    }

    /// How long `origin` is still held, if it is.
    pub fn held(&self, origin: &str) -> Option<Duration> {
        let now = Instant::now();
        self.origins
            .lock()
            .get(&origin.to_ascii_lowercase())
            .and_then(|b| b.hold_until)
            .filter(|h| *h > now)
            .map(|h| h - now)
    }
}

fn refusal(origin: &str, held: Option<()>, wait: Duration) -> Refusal {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "whole seconds of a Duration, at least 1: finite, positive and far below u64::MAX"
    )]
    let secs = wait.as_secs_f64().ceil().max(1.0) as u64;
    Refusal::new(
        ErrorCode::ProviderQuotaExceeded,
        match held {
            Some(()) => tr!(
                "The provider is limiting the request rate ({origin}); try again in {secs} s. No request was sent this time",
                "供應商限制請求頻率（{origin}），請 {secs} 秒後再試；這次沒有送出任何請求",
                "プロバイダーがリクエストの頻度を制限しています（{origin}）。{secs} 秒後にもう一度お試しください。今回はリクエストを送信していません"
            ),
            None if wait.is_zero() => tr!(
                "This operation needs more provider requests at once than the budget allows ({origin}); nothing was sent",
                "這個操作一次需要的供應商請求超過額度（{origin}），沒有送出",
                "この操作で一度に必要なプロバイダーへのリクエストが上限を超えています（{origin}）。送信していません"
            ),
            None => tr!(
                "Provider requests are too frequent ({origin}); try again in {secs} s. No request was sent this time",
                "供應商請求太頻繁（{origin}），請 {secs} 秒後再試；這次沒有送出任何請求",
                "プロバイダーへのリクエストが多すぎます（{origin}）。{secs} 秒後にもう一度お試しください。今回はリクエストを送信していません"
            ),
        },
    )
}
