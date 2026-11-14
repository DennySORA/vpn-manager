//! What a provider call can fail with, typed so the controller can decide — retry later, wait,
//! reconcile, or tell the user — without ever holding a provider body or a secret.

use std::fmt;
use std::time::Duration;

use http::StatusCode;
use http::header::{HeaderMap, RETRY_AFTER};
use time::format_description::StaticFormatDescription;
use time::{OffsetDateTime, PrimitiveDateTime};
use vpn_domain::{ErrorCode, Text, tr};

use crate::https::{HttpError, Refusal};

/// Longest `Retry-After` reported; larger values are clamped.
pub const MAX_RETRY_AFTER: Duration = Duration::from_hours(24);

/// RFC 9110 §5.6.7 IMF-fixdate, the only HTTP-date form senders generate.
const IMF_FIXDATE: StaticFormatDescription = time::macros::format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

/// Failure of one provider call (Mullvad API or IP check). [`ProviderError::text`] is the message
/// a person reads; `Display` is its English (logs).
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// 401/403, or a provider code naming the credential (invalid account number, invalid or
    /// expired access token).
    AuthRejected,
    /// 429. `retry_after` from `Retry-After` (seconds or HTTP date) when present.
    RateLimited { retry_after: Option<Duration> },
    /// The account cannot hold another device. Nothing was created and nothing is deleted to
    /// make room.
    DeviceLimitReached,
    /// 5xx or a transport failure (connector, TLS, timeout, broken connection).
    Unavailable(Unavailable),
    /// The response is not what the pinned contract describes (bad JSON, missing or invalid
    /// field, unexpected status, redirect, oversized body). Names the part, never the content.
    ContractDrift(Text),
    /// Any other 4xx; `code` is the provider's machine code when it is a plain `UPPER_SNAKE`
    /// token (free text and anything that could echo input is dropped).
    Rejected { status: u16, code: Option<String> },
    /// The connector would not carry the request (the egress guard did not authorize it);
    /// nothing reached the provider.
    Refused(Refusal),
}

/// Why the provider could not be reached or answered with a server error.
#[derive(Debug, thiserror::Error)]
pub enum Unavailable {
    Status(u16),
    Http(HttpError),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text().en)
    }
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text().en)
    }
}

impl Unavailable {
    /// The reason in the three languages.
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::Status(status) => tr!(
                "Server error (HTTP {status})",
                "伺服器錯誤（HTTP {status}）",
                "サーバーエラー（HTTP {status}）"
            ),
            Self::Http(e) => e.text(),
        }
    }
}

impl ProviderError {
    /// The message a person reads, in the three languages.
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::AuthRejected => tr!(
                "The provider refused authentication: the account details are invalid or expired",
                "供應商拒絕驗證：帳號資料無效或已過期",
                "プロバイダーが認証を拒否しました：アカウント情報が無効か期限切れです"
            ),
            Self::RateLimited { retry_after } => match retry_after.map(|d| d.as_secs()) {
                Some(secs) if secs > 0 => tr!(
                    "The provider is limiting the request rate; try again in {secs} s",
                    "供應商限制請求頻率，請 {secs} 秒後再試",
                    "プロバイダーがリクエストの頻度を制限しています。{secs} 秒後にもう一度お試しください"
                ),
                _ => tr!(
                    "The provider is limiting the request rate; try again later",
                    "供應商限制請求頻率，請稍後再試",
                    "プロバイダーがリクエストの頻度を制限しています。しばらくしてからもう一度お試しください"
                ),
            },
            Self::DeviceLimitReached => tr!(
                "The account has reached its device limit: revoke a device you no longer use first (no device is ever deleted automatically)",
                "帳號的裝置數已達上限：請先撤銷不再使用的裝置（不會自動刪除任何裝置）",
                "アカウントのデバイス数が上限に達しました：使わなくなったデバイスを先に取り消してください（デバイスが自動で削除されることはありません）"
            ),
            Self::Unavailable(why) => tr!(
                "The provider's service is unavailable: {why}",
                "無法使用供應商服務：{why}",
                "プロバイダーのサービスを利用できません：{why}";
                why = why.text()
            ),
            Self::ContractDrift(part) => tr!(
                "The provider's response does not match the known format ({part}); processing stopped",
                "供應商回應與已知格式不符（{part}），已停止處理",
                "プロバイダーの応答が既知の形式と一致しません（{part}）。処理を中止しました";
                part = part.clone()
            ),
            Self::Rejected {
                status,
                code: Some(code),
            } => tr!(
                "The provider refused the request (HTTP {status}, code {code})",
                "供應商拒絕請求（HTTP {status}，代碼 {code}）",
                "プロバイダーがリクエストを拒否しました（HTTP {status}、コード {code}）"
            ),
            Self::Rejected { status, code: None } => tr!(
                "The provider refused the request (HTTP {status})",
                "供應商拒絕請求（HTTP {status}）",
                "プロバイダーがリクエストを拒否しました（HTTP {status}）"
            ),
            Self::Refused(refusal) => refusal.message.clone(),
        }
    }

    /// Public error code for the API layer.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::AuthRejected => ErrorCode::ProviderAuthRejected,
            Self::RateLimited { .. } => ErrorCode::ProviderQuotaExceeded,
            Self::DeviceLimitReached => ErrorCode::DeviceLimitReached,
            Self::Unavailable(_) => ErrorCode::ProviderUnavailable,
            Self::ContractDrift(_) => ErrorCode::ProviderContractDrift,
            Self::Rejected { .. } => ErrorCode::ProviderRejected,
            Self::Refused(r) => r.code,
        }
    }

    /// For a mutation: whether the provider may have applied it. Then the result must be
    /// reconciled (e.g. [`crate::mullvad::reconcile_created_device`]), never blindly resent.
    /// A 4xx answer means it was not applied; a 5xx is treated as unknown because a gateway
    /// error does not prove the backend did nothing.
    #[must_use]
    pub const fn outcome_unknown(&self) -> bool {
        match self {
            Self::AuthRejected
            | Self::RateLimited { .. }
            | Self::DeviceLimitReached
            | Self::Rejected { .. }
            | Self::Refused(_) => false,
            Self::Unavailable(Unavailable::Status(_)) | Self::ContractDrift(_) => true,
            Self::Unavailable(Unavailable::Http(e)) => e.maybe_delivered(),
        }
    }
}

impl From<HttpError> for ProviderError {
    fn from(error: HttpError) -> Self {
        match error {
            HttpError::Redirect(_) => Self::ContractDrift(tr!(
                "redirect requested",
                "要求重新導向",
                "リダイレクトの要求"
            )),
            HttpError::TooLarge { .. } => Self::ContractDrift(tr!(
                "response over the size limit",
                "回應超過大小上限",
                "サイズ上限を超える応答"
            )),
            HttpError::Refused(r) => Self::Refused(r),
            other => Self::Unavailable(Unavailable::Http(other)),
        }
    }
}

/// A response's `Retry-After` as a delay from now (seconds or an HTTP date, clamped to
/// [`MAX_RETRY_AFTER`]); `None` when absent or unparsable.
#[must_use]
pub fn retry_delay(headers: &HeaderMap) -> Option<Duration> {
    retry_after(headers, OffsetDateTime::now_utc())
}

/// Error for a response outside the endpoint's success statuses, before provider-specific
/// codes are considered. `code` must already be sanitized.
pub(crate) fn status_error(
    status: StatusCode,
    headers: &HeaderMap,
    code: Option<String>,
) -> ProviderError {
    match status.as_u16() {
        429 => ProviderError::RateLimited {
            retry_after: retry_after(headers, OffsetDateTime::now_utc()),
        },
        401 | 403 => ProviderError::AuthRejected,
        status @ 400..=499 => ProviderError::Rejected { status, code },
        status @ 500..=599 => ProviderError::Unavailable(Unavailable::Status(status)),
        _ => ProviderError::ContractDrift(unexpected_status()),
    }
}

/// The part named by a [`ProviderError::ContractDrift`] for a status outside the contract.
pub(crate) fn unexpected_status() -> Text {
    tr!(
        "unexpected HTTP status",
        "非預期的 HTTP 狀態",
        "予期しない HTTP ステータス"
    )
}

/// `Retry-After` as delay-seconds or an IMF-fixdate, clamped to [`MAX_RETRY_AFTER`]; `None`
/// when absent or unparsable. A date in the past means "now".
pub(crate) fn retry_after(headers: &HeaderMap, now: OffsetDateTime) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    let delay = if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        Duration::from_secs(value.parse().unwrap_or(u64::MAX))
    } else {
        let at = PrimitiveDateTime::parse(value, IMF_FIXDATE)
            .ok()?
            .assume_utc();
        Duration::try_from(at - now).unwrap_or(Duration::ZERO)
    };
    Some(delay.min(MAX_RETRY_AFTER))
}

/// Whether a provider error code is a plain machine token (`MAX_DEVICES_REACHED`). Anything
/// else — free text, lower case, digits only — is dropped so an error can never echo input
/// such as an account number or token back into our messages.
pub(crate) fn is_machine_code(code: &str) -> bool {
    (2..=64).contains(&code.len())
        && code.starts_with(|c: char| c.is_ascii_uppercase())
        && code
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn only_machine_codes_survive() {
        assert!(is_machine_code("MAX_DEVICES_REACHED"));
        assert!(is_machine_code("PUBKEY_IN_USE"));
        assert!(!is_machine_code("1234567812345678"));
        assert!(!is_machine_code("mva_secret_token"));
        assert!(!is_machine_code("Invalid account"));
        assert!(!is_machine_code(""));
        assert!(!is_machine_code(&"A".repeat(65)));
    }
}
