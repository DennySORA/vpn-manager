use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use vpn_domain::{ApiError, ErrorCode, Operation, OperationId, SecretMetadata, SecretRef, tr};
use vpn_ipc::control::{Call, Reply};

use super::{AppState, Body, idempotent, wrong};
use crate::http::{HttpError, HttpResult, bad};

#[derive(serde::Deserialize)]
pub struct ListQuery {
    limit: Option<u32>,
}

/// No operation with that id or Idempotency-Key.
fn operation_not_found() -> HttpError {
    HttpError(ApiError::not_found(tr!(
        "this operation",
        "這項操作",
        "この操作"
    )))
}

/// `GET /v1/operations?limit=` (default 50, at most 200): the newest operations, newest first.
pub async fn list(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> HttpResult<Json<Vec<Operation>>> {
    let limit = q.limit.unwrap_or(50);
    match state.link.call(Call::Operations { limit }).await? {
        Reply::Operations(ops) => Ok(Json(ops)),
        _ => Err(wrong()),
    }
}

pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<OperationId>,
) -> HttpResult<Json<Operation>> {
    match state.link.call(Call::Operation(id)).await? {
        Reply::Operation(Some(op)) => Ok(Json(op)),
        Reply::Operation(None) => Err(operation_not_found()),
        _ => Err(wrong()),
    }
}

pub async fn by_key(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> HttpResult<Json<Operation>> {
    match state.link.call(Call::OperationByKey(key)).await? {
        Reply::Operation(Some(op)) => Ok(Json(op)),
        Reply::Operation(None) => Err(operation_not_found()),
        _ => Err(wrong()),
    }
}

/// Secret metadata only; there is no endpoint that returns plaintext.
pub async fn secrets(State(state): State<AppState>) -> HttpResult<Json<Vec<SecretMetadata>>> {
    match state.link.call(Call::Secrets).await? {
        Reply::Secrets(v) => Ok(Json(
            v.into_iter()
                .map(|m| SecretMetadata {
                    secret_ref: m.secret_ref,
                    kind: m.kind,
                    label: m.label,
                    public_fingerprint: m.public_fingerprint,
                    created_at: m.created_at,
                })
                .collect(),
        )),
        _ => Err(wrong()),
    }
}

pub async fn delete_secret(
    State(state): State<AppState>,
    Path(secret): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let r = secret.parse::<SecretRef>().map_err(|e| {
        tracing::debug!(error = %e, "secret ref refused");
        bad(
            ErrorCode::InvalidRequest,
            tr!(
                "The secret ref is malformed",
                "secret ref 格式錯誤",
                "secret ref の形式が正しくありません"
            ),
        )
    })?;
    let link = state.link.clone();
    let path = format!("/v1/secrets/{r}");
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        None,
        &body,
        "secret.delete",
        Some(r.to_string()),
        |_| async move {
            link.call(Call::DeleteSecret(r)).await?;
            Ok((vec![r.to_string()], ()))
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
