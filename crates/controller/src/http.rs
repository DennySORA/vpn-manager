//! HTTP plumbing shared by the handlers: error responses, a JSON extractor with public error
//! messages, idempotency keys, If-Match and request fingerprints.

use axum::Json;
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use vpn_domain::{ApiError, ErrorCode, FieldError, Text, ValidationReport, tr};

/// An `ApiError` rendered as an HTTP response.
#[derive(Debug)]
pub struct HttpError(pub ApiError);

impl From<ApiError> for HttpError {
    fn from(e: ApiError) -> Self {
        Self(e)
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut r = (status, Json(self.0)).into_response();
        r.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        r
    }
}

pub type HttpResult<T> = Result<T, HttpError>;

pub fn bad(code: ErrorCode, msg: impl Into<Text>) -> HttpError {
    HttpError(ApiError::new(code, msg))
}

/// A validation report with errors becomes a 400 with field errors.
#[must_use]
pub fn report_error(report: &ValidationReport) -> HttpError {
    let fields = report
        .issues
        .iter()
        .filter(|i| i.severity == vpn_domain::Severity::Error)
        .map(|i| FieldError {
            path: i.path.clone(),
            code: i.code.clone(),
            message: i.message.clone(),
        })
        .collect::<Vec<_>>();
    let first = fields.first().map_or_else(
        || {
            tr!(
                "Validation failed",
                "資料驗證失敗",
                "データの検証に失敗しました"
            )
        },
        |f| f.message.clone(),
    );
    HttpError(ApiError::new(ErrorCode::ValidationFailed, first).with_fields(fields))
}

/// JSON body extractor whose rejections are public `ApiError`s in the three languages (no serde
/// internals).
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Self(v)),
            Err(rejection) => {
                use axum::extract::rejection::JsonRejection::{
                    BytesRejection, JsonDataError, JsonSyntaxError, MissingJsonContentType,
                };
                let (code, msg) = match &rejection {
                    MissingJsonContentType(_) => (
                        ErrorCode::UnsupportedMediaType,
                        tr!(
                            "The request must be application/json",
                            "請求必須是 application/json",
                            "リクエストは application/json にしてください"
                        ),
                    ),
                    JsonSyntaxError(_) => (
                        ErrorCode::InvalidRequest,
                        tr!(
                            "Malformed JSON",
                            "JSON 格式錯誤",
                            "JSON の形式が正しくありません"
                        ),
                    ),
                    JsonDataError(e) => {
                        let detail: String = e.body_text().chars().take(200).collect();
                        (
                            ErrorCode::ValidationFailed,
                            tr!(
                                "A field is not in the expected format: {detail}",
                                "欄位不符合格式：{detail}",
                                "フィールドの形式が正しくありません：{detail}"
                            ),
                        )
                    }
                    BytesRejection(_) => (
                        ErrorCode::PayloadTooLarge,
                        tr!(
                            "The request body is too large or cannot be read",
                            "請求內容過大或無法讀取",
                            "リクエストの内容が大きすぎるか、読み取れません"
                        ),
                    ),
                    _ => (ErrorCode::InvalidRequest, unreadable()),
                };
                Err(bad(code, msg))
            }
        }
    }
}

/// A request body that could not be read.
fn unreadable() -> Text {
    tr!(
        "Cannot read the request body",
        "無法讀取請求內容",
        "リクエストの内容を読み取れません"
    )
}

/// A request body within the route's limit; going over it is a public `PAYLOAD_TOO_LARGE`
/// error (not the framework's plain-text answer).
pub struct LimitedBody(pub axum::body::Bytes);

impl<S> FromRequest<S> for LimitedBody
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        axum::body::Bytes::from_request(req, state)
            .await
            .map(LimitedBody)
            .map_err(|r| {
                if r.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    bad(
                        ErrorCode::PayloadTooLarge,
                        tr!(
                            "The content is over the size limit (8 MiB at most for an IP blocklist)",
                            "內容超過大小上限（IP 封鎖清單最多 8 MiB）",
                            "内容がサイズの上限を超えています（IP ブロックリストは最大 8 MiB）"
                        ),
                    )
                } else {
                    bad(ErrorCode::InvalidRequest, unreadable())
                }
            })
    }
}

/// `Idempotency-Key` header (a UUID), required for mutations.
///
/// # Errors
///
/// `IDEMPOTENCY_KEY_REQUIRED` when the header is missing or not text, `INVALID_REQUEST` when
/// it is not a UUID.
pub fn idempotency_key(headers: &HeaderMap) -> HttpResult<String> {
    let v = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            bad(
                ErrorCode::IdempotencyKeyRequired,
                tr!(
                    "A change needs an Idempotency-Key header (a UUID)",
                    "變更操作需要 Idempotency-Key 標頭（UUID）",
                    "変更操作には Idempotency-Key ヘッダー（UUID）が必要です"
                ),
            )
        })?;
    let parsed = uuid::Uuid::parse_str(v.trim()).map_err(|_| {
        bad(
            ErrorCode::InvalidRequest,
            tr!(
                "Idempotency-Key must be a UUID",
                "Idempotency-Key 必須是 UUID",
                "Idempotency-Key は UUID にしてください"
            ),
        )
    })?;
    Ok(parsed.as_hyphenated().to_string())
}

/// `If-Match: "<revision>"`, required to change an existing entity.
///
/// # Errors
///
/// `REVISION_REQUIRED` when the header is missing or not text, `INVALID_REQUEST` when it
/// does not hold a revision number.
pub fn if_match(headers: &HeaderMap) -> HttpResult<u64> {
    let v = headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            bad(
                ErrorCode::RevisionRequired,
                tr!(
                    "Changing existing data needs an If-Match header (the current revision)",
                    "更新既有資料需要 If-Match 標頭（目前的 revision）",
                    "既存のデータを更新するには If-Match ヘッダー（現在の revision）が必要です"
                ),
            )
        })?;
    v.trim()
        .trim_start_matches("W/")
        .trim_matches('"')
        .parse()
        .map_err(|_| {
            bad(
                ErrorCode::InvalidRequest,
                tr!(
                    "If-Match must be \"<revision>\"",
                    "If-Match 必須是 \"<revision>\"",
                    "If-Match は \"<revision>\" にしてください"
                ),
            )
        })
}

/// Request fingerprint for idempotency: method, path, If-Match and the body (non-secret bodies
/// only; secret-bearing requests use a keyed fingerprint computed by the manager).
#[must_use]
pub fn fingerprint(method: &str, path: &str, if_match: Option<u64>, body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(method.as_bytes());
    h.update(b"\n");
    h.update(path.as_bytes());
    h.update(b"\n");
    h.update(if_match.map_or_default(|r| r.to_string()).as_bytes());
    h.update(b"\n");
    h.update(body);
    hex::encode(h.finalize())
}

/// JSON response with a strong `ETag` of the entity revision.
pub fn with_etag<T: Serialize>(status: StatusCode, revision: u64, body: &T) -> Response {
    let mut r = (status, Json(body)).into_response();
    if let Ok(v) = HeaderValue::from_str(&format!("\"{revision}\"")) {
        r.headers_mut().insert(header::ETAG, v);
    }
    r
}
