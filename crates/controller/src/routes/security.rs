use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use vpn_domain::validation::check_security_profile;
use vpn_domain::{EntityMeta, SecurityProfile, SecurityProfileId, SecurityProfileInput};
use vpn_ipc::control::{Call, Entity, EntityKind};

use super::{
    AppState, Body, Idem, create_entity, get_entity, idempotent, list_entities, new_meta,
    parse_json, update_entity, wrong,
};
use crate::http::{HttpResult, if_match, report_error, with_etag};

fn as_security(e: Entity) -> HttpResult<SecurityProfile> {
    match e {
        Entity::Security(p) => Ok(p),
        _ => Err(wrong()),
    }
}

fn build(id: SecurityProfileId, meta: EntityMeta, i: SecurityProfileInput) -> SecurityProfile {
    SecurityProfile {
        id,
        meta,
        name: i.name.trim().to_string(),
        allow_private: i.allow_private,
        blocked_ports: i.blocked_ports,
        allowed_destinations: i.allowed_destinations,
        allowed_ports: i.allowed_ports,
        blocklists: i.blocklists,
        auto_ban: i.auto_ban,
    }
}

pub async fn list(State(state): State<AppState>) -> HttpResult<Json<Vec<SecurityProfile>>> {
    let v = list_entities(&state.link, EntityKind::Security).await?;
    Ok(Json(
        v.into_iter().filter_map(|e| as_security(e).ok()).collect(),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<SecurityProfileId>,
) -> HttpResult<Response> {
    let p = as_security(get_entity(&state.link, EntityKind::Security, id.to_string()).await?)?;
    Ok(with_etag(StatusCode::OK, p.meta.revision, &p))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let input: SecurityProfileInput = parse_json(&headers, &body)?;
    let p = build(SecurityProfileId::new(), new_meta(), input);
    let report = check_security_profile(&p);
    if report.has_errors() {
        return Err(report_error(&report));
    }
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        "/v1/security-profiles",
        None,
        &body,
        "security_profile.create",
        None,
        |_| async move {
            let e = create_entity(&link, Entity::Security(p)).await?;
            let id = match &e {
                Entity::Security(p) => p.id.to_string(),
                _ => String::new(),
            };
            Ok((vec![id], e))
        },
    )
    .await?;
    let p = match out {
        Idem::Fresh { value, .. } => as_security(value)?,
        Idem::Replayed(op) => {
            let id = op.result_refs.first().cloned().ok_or_else(wrong)?;
            as_security(get_entity(&state.link, EntityKind::Security, id).await?)?
        }
    };
    Ok(with_etag(StatusCode::CREATED, p.meta.revision, &p))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<SecurityProfileId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let rev = if_match(&headers)?;
    let input: SecurityProfileInput = parse_json(&headers, &body)?;
    let current =
        as_security(get_entity(&state.link, EntityKind::Security, id.to_string()).await?)?;
    let p = build(id, current.meta, input);
    let report = check_security_profile(&p);
    if report.has_errors() {
        return Err(report_error(&report));
    }
    let link = state.link.clone();
    let path = format!("/v1/security-profiles/{id}");
    let out = idempotent(
        &state.link,
        &headers,
        "PUT",
        &path,
        Some(rev),
        &body,
        "security_profile.update",
        Some(id.to_string()),
        |_| async move {
            Ok((
                vec![id.to_string()],
                update_entity(&link, Entity::Security(p), rev).await?,
            ))
        },
    )
    .await?;
    let p = match out {
        Idem::Fresh { value, .. } => as_security(value)?,
        Idem::Replayed(_) => {
            as_security(get_entity(&state.link, EntityKind::Security, id.to_string()).await?)?
        }
    };
    Ok(with_etag(StatusCode::OK, p.meta.revision, &p))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<SecurityProfileId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let rev = if_match(&headers)?;
    let link = state.link.clone();
    let path = format!("/v1/security-profiles/{id}");
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        Some(rev),
        &body,
        "security_profile.delete",
        Some(id.to_string()),
        |_| async move {
            link.call(Call::Delete {
                kind: EntityKind::Security,
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
