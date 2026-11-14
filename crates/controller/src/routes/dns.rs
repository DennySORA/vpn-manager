use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use vpn_domain::validation::check_dns_profile;
use vpn_domain::{DnsProfile, DnsProfileId, DnsProfileInput, EntityMeta};
use vpn_ipc::control::{Call, Entity, EntityKind};

use super::{
    AppState, Body, Idem, create_entity, get_entity, idempotent, list_entities, new_meta,
    parse_json, update_entity, wrong,
};
use crate::http::{HttpResult, if_match, report_error, with_etag};

fn as_dns(e: Entity) -> HttpResult<DnsProfile> {
    match e {
        Entity::Dns(p) => Ok(p),
        _ => Err(wrong()),
    }
}

fn build(id: DnsProfileId, meta: EntityMeta, i: DnsProfileInput) -> DnsProfile {
    DnsProfile {
        id,
        meta,
        name: i.name.trim().to_string(),
        servers: i.servers,
        cache: i.cache,
        query_timeout_ms: i.query_timeout_ms,
        attempts: i.attempts,
        on_failure: i.on_failure,
    }
}

pub async fn list(State(state): State<AppState>) -> HttpResult<Json<Vec<DnsProfile>>> {
    let v = list_entities(&state.link, EntityKind::Dns).await?;
    Ok(Json(v.into_iter().filter_map(|e| as_dns(e).ok()).collect()))
}

pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<DnsProfileId>,
) -> HttpResult<Response> {
    let p = as_dns(get_entity(&state.link, EntityKind::Dns, id.to_string()).await?)?;
    Ok(with_etag(StatusCode::OK, p.meta.revision, &p))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let input: DnsProfileInput = parse_json(&headers, &body)?;
    let p = build(DnsProfileId::new(), new_meta(), input);
    let report = check_dns_profile(&p);
    if report.has_errors() {
        return Err(report_error(&report));
    }
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        "/v1/dns-profiles",
        None,
        &body,
        "dns_profile.create",
        None,
        |_| async move {
            let e = create_entity(&link, Entity::Dns(p)).await?;
            let id = match &e {
                Entity::Dns(p) => p.id.to_string(),
                _ => String::new(),
            };
            Ok((vec![id], e))
        },
    )
    .await?;
    let p = match out {
        Idem::Fresh { value, .. } => as_dns(value)?,
        Idem::Replayed(op) => {
            let id = op.result_refs.first().cloned().ok_or_else(wrong)?;
            as_dns(get_entity(&state.link, EntityKind::Dns, id).await?)?
        }
    };
    Ok(with_etag(StatusCode::CREATED, p.meta.revision, &p))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<DnsProfileId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let rev = if_match(&headers)?;
    let input: DnsProfileInput = parse_json(&headers, &body)?;
    let current = as_dns(get_entity(&state.link, EntityKind::Dns, id.to_string()).await?)?;
    let p = build(id, current.meta, input);
    let report = check_dns_profile(&p);
    if report.has_errors() {
        return Err(report_error(&report));
    }
    let link = state.link.clone();
    let path = format!("/v1/dns-profiles/{id}");
    let out = idempotent(
        &state.link,
        &headers,
        "PUT",
        &path,
        Some(rev),
        &body,
        "dns_profile.update",
        Some(id.to_string()),
        |_| async move {
            Ok((
                vec![id.to_string()],
                update_entity(&link, Entity::Dns(p), rev).await?,
            ))
        },
    )
    .await?;
    let p = match out {
        Idem::Fresh { value, .. } => as_dns(value)?,
        Idem::Replayed(_) => {
            as_dns(get_entity(&state.link, EntityKind::Dns, id.to_string()).await?)?
        }
    };
    Ok(with_etag(StatusCode::OK, p.meta.revision, &p))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<DnsProfileId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let rev = if_match(&headers)?;
    let link = state.link.clone();
    let path = format!("/v1/dns-profiles/{id}");
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        Some(rev),
        &body,
        "dns_profile.delete",
        Some(id.to_string()),
        |_| async move {
            link.call(Call::Delete {
                kind: EntityKind::Dns,
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
