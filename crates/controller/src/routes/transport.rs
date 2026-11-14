//! Transport profiles: the saved ones (create, change, delete) and the ones that are part of
//! the program (read only).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use vpn_domain::{
    BuiltinTransport, EntityMeta, TransportProfile, TransportProfileId, TransportProfileInput,
    builtin_transports, check_transport_profile,
};
use vpn_ipc::control::{Call, Entity, EntityKind};

use super::{
    AppState, Body, Idem, create_entity, get_entity, idempotent, list_entities, new_meta,
    parse_json, update_entity, wrong,
};
use crate::http::{HttpResult, if_match, report_error, with_etag};

fn as_transport(e: Entity) -> HttpResult<TransportProfile> {
    match e {
        Entity::Transport(p) => Ok(p),
        _ => Err(wrong()),
    }
}

fn build(id: TransportProfileId, meta: EntityMeta, i: TransportProfileInput) -> TransportProfile {
    TransportProfile {
        id,
        meta,
        name: i.name.trim().to_string(),
        health: i.health,
        settings: i.settings,
    }
}

/// `GET /v1/transport-profiles/builtin`: the profiles that are part of the program.
pub async fn builtin() -> Json<Vec<BuiltinTransport>> {
    Json(builtin_transports())
}

pub async fn list(State(state): State<AppState>) -> HttpResult<Json<Vec<TransportProfile>>> {
    let v = list_entities(&state.link, EntityKind::Transport).await?;
    Ok(Json(
        v.into_iter().filter_map(|e| as_transport(e).ok()).collect(),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<TransportProfileId>,
) -> HttpResult<Response> {
    let p = as_transport(get_entity(&state.link, EntityKind::Transport, id.to_string()).await?)?;
    Ok(with_etag(StatusCode::OK, p.meta.revision, &p))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let input: TransportProfileInput = parse_json(&headers, &body)?;
    let p = build(TransportProfileId::new(), new_meta(), input);
    let report = check_transport_profile(&p);
    if report.has_errors() {
        return Err(report_error(&report));
    }
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        "/v1/transport-profiles",
        None,
        &body,
        "transport_profile.create",
        None,
        |_| async move {
            let e = create_entity(&link, Entity::Transport(p)).await?;
            let id = match &e {
                Entity::Transport(p) => p.id.to_string(),
                _ => String::new(),
            };
            Ok((vec![id], e))
        },
    )
    .await?;
    let p = match out {
        Idem::Fresh { value, .. } => as_transport(value)?,
        Idem::Replayed(op) => {
            let id = op.result_refs.first().cloned().ok_or_else(wrong)?;
            as_transport(get_entity(&state.link, EntityKind::Transport, id).await?)?
        }
    };
    Ok(with_etag(StatusCode::CREATED, p.meta.revision, &p))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<TransportProfileId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let rev = if_match(&headers)?;
    let input: TransportProfileInput = parse_json(&headers, &body)?;
    let current =
        as_transport(get_entity(&state.link, EntityKind::Transport, id.to_string()).await?)?;
    let p = build(id, current.meta, input);
    let report = check_transport_profile(&p);
    if report.has_errors() {
        return Err(report_error(&report));
    }
    let link = state.link.clone();
    let path = format!("/v1/transport-profiles/{id}");
    let out = idempotent(
        &state.link,
        &headers,
        "PUT",
        &path,
        Some(rev),
        &body,
        "transport_profile.update",
        Some(id.to_string()),
        |_| async move {
            Ok((
                vec![id.to_string()],
                update_entity(&link, Entity::Transport(p), rev).await?,
            ))
        },
    )
    .await?;
    let p = match out {
        Idem::Fresh { value, .. } => as_transport(value)?,
        Idem::Replayed(_) => {
            as_transport(get_entity(&state.link, EntityKind::Transport, id.to_string()).await?)?
        }
    };
    Ok(with_etag(StatusCode::OK, p.meta.revision, &p))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<TransportProfileId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let rev = if_match(&headers)?;
    let link = state.link.clone();
    let path = format!("/v1/transport-profiles/{id}");
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        Some(rev),
        &body,
        "transport_profile.delete",
        Some(id.to_string()),
        |_| async move {
            link.call(Call::Delete {
                kind: EntityKind::Transport,
                id: id.to_string(),
                expected_revision: rev,
            })
            .await?;
            Ok((vec![id.to_string()], ()))
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
