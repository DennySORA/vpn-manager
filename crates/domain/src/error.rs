//! Public error contract. Messages are a [`Text`] in the three languages of the interface, never contain
//! secrets, raw provider bodies, stack traces or filesystem secret paths.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::ids::OperationId;
use crate::text::Text;
use crate::tr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[ts(export)]
pub enum ErrorCode {
    // Request shape / contract
    InvalidRequest,
    ValidationFailed,
    NotFound,
    RevisionRequired,
    RevisionConflict,
    IdempotencyConflict,
    IdempotencyKeyRequired,
    PayloadTooLarge,
    UnsupportedMediaType,
    ForbiddenOrigin,
    RateLimited,
    // Resource state
    InUse,
    IdentityInUse,
    ListenerConflict,
    InvalidState,
    ManualStopLatched,
    EmergencyLatched,
    RecoveryRequired,
    /// A managed App's executable is not the file the user approved.
    AppArtifactDigestMismatch,
    // Capabilities / platform
    UnsupportedCapability,
    UnverifiedCapability,
    VaultLocked,
    // Persistence
    StoreBusy,
    PersistenceUnavailable,
    // Outcomes
    OutcomeUnknown,
    Timeout,
    // Providers
    ProviderUnavailable,
    ProviderRejected,
    ProviderAuthRejected,
    ProviderQuotaExceeded,
    ProviderContractDrift,
    ProviderEgressBlocked,
    ProviderEgressInUse,
    ProviderPreflightFailed,
    BootstrapAlreadyConsumed,
    BootstrapInProgress,
    /// A manual rebootstrap was asked for while it is not allowed (the message says why).
    RebootstrapNotEligible,
    DeviceLimitReached,
    /// The provider's website asks for a CAPTCHA or a second factor to sign in: VPN Manager
    /// cannot do that for the user (the message says what to do instead).
    ProviderLoginChallenge,
    /// The account holds as many forwarded ports as the provider allows (`AirVPN`: 5).
    PortLimitReached,
    // Security
    /// A blocklist covers an address the connection itself needs (its `WireGuard` peer or a DNS
    /// server): the save is refused rather than dropping the user's rule.
    PolicyConflict,
    /// A blocklist URL could not be downloaded or its content was unusable.
    BlocklistFetchFailed,
    // Catch-all
    Internal,
    Unavailable,
}

impl ErrorCode {
    /// HTTP status for this code.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        use ErrorCode::{
            AppArtifactDigestMismatch, BlocklistFetchFailed, BootstrapAlreadyConsumed,
            BootstrapInProgress, DeviceLimitReached, EmergencyLatched, ForbiddenOrigin,
            IdempotencyConflict, IdempotencyKeyRequired, IdentityInUse, InUse, Internal,
            InvalidRequest, InvalidState, ListenerConflict, ManualStopLatched, NotFound,
            OutcomeUnknown, PayloadTooLarge, PersistenceUnavailable, PolicyConflict,
            PortLimitReached, ProviderAuthRejected, ProviderContractDrift, ProviderEgressBlocked,
            ProviderEgressInUse, ProviderLoginChallenge, ProviderPreflightFailed,
            ProviderQuotaExceeded, ProviderRejected, ProviderUnavailable, RateLimited,
            RebootstrapNotEligible, RecoveryRequired, RevisionConflict, RevisionRequired,
            StoreBusy, Timeout, Unavailable, UnsupportedCapability, UnsupportedMediaType,
            UnverifiedCapability, ValidationFailed, VaultLocked,
        };
        match self {
            InvalidRequest | ValidationFailed | IdempotencyKeyRequired => 400,
            ForbiddenOrigin => 403,
            NotFound => 404,
            InUse
            | IdentityInUse
            | ListenerConflict
            | InvalidState
            | ManualStopLatched
            | EmergencyLatched
            | RecoveryRequired
            | AppArtifactDigestMismatch
            | IdempotencyConflict
            | ProviderEgressInUse
            | BootstrapAlreadyConsumed
            | BootstrapInProgress
            | RebootstrapNotEligible
            | DeviceLimitReached
            | PortLimitReached
            | PolicyConflict => 409,
            RevisionConflict => 412,
            PayloadTooLarge => 413,
            UnsupportedMediaType => 415,
            UnsupportedCapability | UnverifiedCapability => 422,
            RevisionRequired => 428,
            RateLimited | ProviderQuotaExceeded => 429,
            Internal => 500,
            ProviderUnavailable
            | ProviderRejected
            | ProviderAuthRejected
            | ProviderLoginChallenge
            | ProviderContractDrift
            | ProviderPreflightFailed
            | BlocklistFetchFailed => 502,
            StoreBusy
            | PersistenceUnavailable
            | Unavailable
            | VaultLocked
            | ProviderEgressBlocked => 503,
            OutcomeUnknown | Timeout => 504,
        }
    }

    /// Whether retrying the same request later may succeed.
    #[must_use]
    pub const fn retryable(self) -> bool {
        use ErrorCode::{
            BlocklistFetchFailed, PersistenceUnavailable, ProviderEgressBlocked,
            ProviderQuotaExceeded, ProviderUnavailable, RateLimited, StoreBusy, Timeout,
            Unavailable, VaultLocked,
        };
        matches!(
            self,
            StoreBusy
                | PersistenceUnavailable
                | Unavailable
                | RateLimited
                | ProviderUnavailable
                | ProviderQuotaExceeded
                | ProviderEgressBlocked
                | Timeout
                | VaultLocked
                | BlocklistFetchFailed
        )
    }
}

/// One field-level problem, located by a JSON-pointer-like path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FieldError {
    pub path: String,
    pub code: String,
    pub message: Text,
}

/// Body of every non-2xx API response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: Text,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub field_errors: Vec<FieldError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<Text>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: code.retryable(),
            field_errors: Vec::new(),
            operation_id: None,
            request_id: None,
        }
    }

    #[must_use]
    pub fn with_fields(mut self, fields: Vec<FieldError>) -> Self {
        self.field_errors = fields;
        self
    }

    #[must_use]
    pub const fn with_operation(mut self, id: OperationId) -> Self {
        self.operation_id = Some(id);
        self
    }

    /// `what` names the missing thing, as it reads inside a sentence (“this Gateway”).
    #[must_use]
    pub fn not_found(what: impl Into<Text>) -> Self {
        Self::new(
            ErrorCode::NotFound,
            tr!("Cannot find {what}", "找不到{what}", "{what}が見つかりません"; what = what),
        )
    }

    #[must_use]
    pub fn internal() -> Self {
        Self::new(
            ErrorCode::Internal,
            tr!(
                "Internal error; see the service log",
                "內部錯誤，請查看服務紀錄",
                "内部エラーです。サービスのログを確認してください"
            ),
        )
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message.en)
    }
}

impl std::error::Error for ApiError {}
