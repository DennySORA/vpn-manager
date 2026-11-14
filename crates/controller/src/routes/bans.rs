//! Auto-bans: list (all, or of one connection) and lift; and what inbound traffic auto-ban can
//! see at all (port forwards).

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use vpn_domain::{ApiError, Ban, BanId, InboundCount, InboundSummary, InstanceId};
use vpn_ipc::control::{Call, Entity, EntityKind, Reply};

use super::{AppState, Body, Idem, idempotent, list_entities, wrong};
use crate::http::HttpResult;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BansQuery {
    instance: Option<InstanceId>,
}

/// `GET /v1/bans?instance=`: active bans, newest first.
pub async fn list(
    State(state): State<AppState>,
    Query(q): Query<BansQuery>,
) -> HttpResult<Json<Vec<Ban>>> {
    match state.link.call(Call::Bans(q.instance)).await? {
        Reply::Bans(v) => Ok(Json(v)),
        _ => Err(wrong()),
    }
}

/// `DELETE /v1/bans/{id}`: lift a ban, on the running worker too (`worker` says whether it
/// confirmed). Blocklists and the base policy still apply. A replay of a lift that went through
/// answers 204: the record is gone.
pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<BanId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let link = state.link.clone();
    let path = format!("/v1/bans/{id}");
    let out = idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        None,
        &body,
        "ban.delete",
        Some(id.to_string()),
        |_| async move {
            match link.call(Call::Unban(id)).await? {
                Reply::Unbanned(r) => Ok((vec![id.to_string()], *r)),
                _ => Err(ApiError::internal()),
            }
        },
    )
    .await?;
    Ok(match out {
        Idem::Fresh { value, .. } => (StatusCode::OK, Json(value)).into_response(),
        Idem::Replayed(_) => StatusCode::NO_CONTENT.into_response(),
    })
}

/// `GET /v1/security/inbound`: port forwards per connection (auto-ban counts only forwarded
/// inbound connections, so without one it has nothing to act on).
pub async fn inbound(State(state): State<AppState>) -> HttpResult<Json<InboundSummary>> {
    let mut counts: BTreeMap<InstanceId, (u32, u32)> = BTreeMap::new();
    for e in list_entities(&state.link, EntityKind::Forward).await? {
        if let Entity::Forward(f) = e {
            let c = counts.entry(f.instance_id).or_default();
            c.0 += 1;
            c.1 += u32::from(f.enabled);
        }
    }
    Ok(Json(InboundSummary {
        instances: counts
            .into_iter()
            .map(|(instance_id, (forward_bindings, enabled))| InboundCount {
                instance_id,
                forward_bindings,
                enabled,
            })
            .collect(),
    }))
}
