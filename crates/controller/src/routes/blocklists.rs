//! IP blocklists: preview (uploaded/pasted text, or a URL downloaded through the Provider
//! egress), commit against the preview's hash, edit, refresh, delete.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use vpn_domain::blocklist::{MAX_RAW_BYTES, parse};
use vpn_domain::{
    ApiError, BlocklistId, BlocklistInput, BlocklistPreview, BlocklistUpdate, BlocklistUrlPreview,
    BlocklistView, BuiltinBlocklistState, ErrorCode, tr,
};
use vpn_ipc::control::Call;

use super::{AppState, Idem, idempotent, parse_json};
use crate::blocklists as service;
use crate::http::{HttpResult, LimitedBody, bad, if_match, with_etag};

/// Largest create/update body: the 8 MiB list as a JSON string (line breaks and quotes are
/// escaped) plus the other fields.
pub const COMMIT_BODY: usize = 12 * 1024 * 1024;
/// Largest preview body: the list itself.
pub const PREVIEW_BODY: usize = MAX_RAW_BYTES;

fn content_type(headers: &HeaderMap) -> &str {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// `POST /v1/blocklists/preview`: `text/plain` or `application/octet-stream` with the list
/// itself, or `application/json` `{ "url": … }` to download it first. Nothing is stored.
pub async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    LimitedBody(body): LimitedBody,
) -> HttpResult<Json<BlocklistPreview>> {
    let ct = content_type(&headers).to_ascii_lowercase();
    if ct.starts_with("application/json") {
        let input: BlocklistUrlPreview = parse_json(&headers, &body)?;
        let d = service::download(&state.link, &input.url).await?;
        return Ok(Json(service::preview(&d.parsed, Some(d.fetch), true)));
    }
    if !(ct.starts_with("text/plain") || ct.starts_with("application/octet-stream")) {
        return Err(bad(
            ErrorCode::UnsupportedMediaType,
            tr!(
                "Send the list content as text/plain (or application/octet-stream) and a URL as JSON",
                "清單內容請以 text/plain（或 application/octet-stream）送出，網址請以 JSON 送出",
                "リストの内容は text/plain（または application/octet-stream）で、URL は JSON で送信してください"
            ),
        ));
    }
    let parsed = parse(&body).map_err(|e| service::parse_error(&e))?;
    Ok(Json(service::preview(&parsed, None, false)))
}

pub async fn list(State(state): State<AppState>) -> HttpResult<Json<Vec<BlocklistView>>> {
    Ok(Json(service::views(&state.link).await?))
}

pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<BlocklistId>,
) -> HttpResult<Response> {
    let v = service::view(&state.link, id).await?;
    Ok(with_etag(StatusCode::OK, v.blocklist.meta.revision, &v))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    LimitedBody(body): LimitedBody,
) -> HttpResult<Response> {
    let input: BlocklistInput = parse_json(&headers, &body)?;
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        "/v1/blocklists",
        None,
        &body,
        "blocklist.create",
        None,
        |_| async move {
            let v = service::create(&link, input).await?;
            Ok((vec![v.blocklist.id.to_string()], v))
        },
    )
    .await?;
    let v = match out {
        Idem::Fresh { value, .. } => service::annotated(&state.link, value).await,
        Idem::Replayed(op) => {
            let id: BlocklistId = op
                .result_refs
                .first()
                .and_then(|r| r.parse().ok())
                .ok_or_else(super::wrong)?;
            service::view(&state.link, id).await?
        }
    };
    Ok(with_etag(
        StatusCode::CREATED,
        v.blocklist.meta.revision,
        &v,
    ))
}

/// `GET /v1/blocklists/builtin`: the built-in catalogue — each list's source, terms and refresh
/// interval — with the list each entry created, or when the user deleted it.
pub async fn builtin(
    State(state): State<AppState>,
) -> HttpResult<Json<Vec<BuiltinBlocklistState>>> {
    Ok(Json(service::builtin(&state.link).await?))
}

/// `POST /v1/blocklists/builtin/{key}/restore`: bring back a built-in list the user deleted (it
/// is never created again on its own).
pub async fn restore(
    State(state): State<AppState>,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: super::Body,
) -> HttpResult<Response> {
    if vpn_domain::builtin_blocklists::builtin(&key).is_none() {
        return Err(ApiError::new(
            ErrorCode::NotFound,
            tr!(
                "Built-in IP blocklist not found",
                "找不到內建 IP 封鎖清單",
                "組み込みの IP ブロックリストが見つかりません"
            ),
        )
        .into());
    }
    let link = state.link.clone();
    let path = format!("/v1/blocklists/builtin/{key}/restore");
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        &path,
        None,
        &body,
        "blocklist.restore_builtin",
        None,
        |_| async move {
            let v = service::restore(&link, &key).await?;
            Ok((vec![v.blocklist.id.to_string()], v))
        },
    )
    .await?;
    let v = match out {
        Idem::Fresh { value, .. } => value,
        Idem::Replayed(op) => {
            let id: BlocklistId = op
                .result_refs
                .first()
                .and_then(|r| r.parse().ok())
                .ok_or_else(super::wrong)?;
            service::view(&state.link, id).await?
        }
    };
    Ok(with_etag(
        StatusCode::CREATED,
        v.blocklist.meta.revision,
        &v,
    ))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<BlocklistId>,
    headers: HeaderMap,
    LimitedBody(body): LimitedBody,
) -> HttpResult<Response> {
    let rev = if_match(&headers)?;
    let input: BlocklistUpdate = parse_json(&headers, &body)?;
    let link = state.link.clone();
    let path = format!("/v1/blocklists/{id}");
    let out = idempotent(
        &state.link,
        &headers,
        "PUT",
        &path,
        Some(rev),
        &body,
        "blocklist.update",
        Some(id.to_string()),
        |_| async move {
            let v = service::update(&link, id, rev, input).await?;
            Ok((vec![id.to_string()], v))
        },
    )
    .await?;
    let v = match out {
        Idem::Fresh { value, .. } => service::annotated(&state.link, value).await,
        Idem::Replayed(_) => service::view(&state.link, id).await?,
    };
    Ok(with_etag(StatusCode::OK, v.blocklist.meta.revision, &v))
}

/// `POST /v1/blocklists/{id}/refresh`: download a URL source now. A failure is recorded (the
/// list turns stale, its content stays) and returned.
pub async fn refresh(
    State(state): State<AppState>,
    Path(id): Path<BlocklistId>,
    headers: HeaderMap,
    body: super::Body,
) -> HttpResult<Response> {
    let link = state.link.clone();
    let path = format!("/v1/blocklists/{id}/refresh");
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        &path,
        None,
        &body,
        "blocklist.refresh",
        Some(id.to_string()),
        |_| async move {
            let v = service::refresh(&link, id).await?;
            Ok((vec![id.to_string()], v))
        },
    )
    .await?;
    let v = match out {
        Idem::Fresh { value, .. } => service::annotated(&state.link, value).await,
        Idem::Replayed(_) => service::view(&state.link, id).await?,
    };
    Ok(with_etag(StatusCode::OK, v.blocklist.meta.revision, &v))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<BlocklistId>,
    headers: HeaderMap,
    body: super::Body,
) -> HttpResult<StatusCode> {
    let rev = if_match(&headers)?;
    let link = state.link.clone();
    let path = format!("/v1/blocklists/{id}");
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        Some(rev),
        &body,
        "blocklist.delete",
        Some(id.to_string()),
        |_| async move {
            link.call(Call::DeleteBlocklist {
                id,
                expected_revision: rev,
            })
            .await?;
            service::forget(id);
            Ok((vec![id.to_string()], ()))
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
