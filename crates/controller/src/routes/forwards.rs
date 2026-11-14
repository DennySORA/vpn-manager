//! Port forwards: configuration and what the manager observes (`/v1/forward-bindings*`). The
//! manager checks what needs the Store (the connection can forward, the App belongs to it, the
//! tunnel port is free on it) and runs everything; the controller checks request shapes.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use vpn_domain::validation::check_forward;
use vpn_domain::{
    ApiError, AssignmentSource, EntityMeta, ErrorCode, ForwardBinding, ForwardBindingId,
    ForwardInput, ForwardStatus, ForwardView, tr,
};
use vpn_ipc::control::{Call, Entity, EntityKind, Reply};

use super::{
    AppState, Body, Idem, create_entity, get_entity, idempotent, list_entities, new_meta,
    parse_json, update_entity, wrong,
};
use crate::http::{HttpResult, bad, if_match, report_error, with_etag};
use crate::link::ManagerLink;

fn as_forward(e: Entity) -> HttpResult<ForwardBinding> {
    match e {
        Entity::Forward(f) => Ok(f),
        _ => Err(wrong()),
    }
}

fn build(id: ForwardBindingId, meta: EntityMeta, i: &ForwardInput) -> ForwardBinding {
    ForwardBinding {
        id,
        meta,
        instance_id: i.instance_id,
        name: i.name.trim().to_string(),
        protocol: i.protocol,
        tunnel_port: i.tunnel_port,
        public_port: i.public_port,
        // Entered here by hand: never verified by a provider.
        assignment_source: AssignmentSource::Manual,
        target_app_id: i.target_app_id,
        target_port: i.target_port,
        enabled: i.enabled,
        max_connections: i.max_connections,
        proxy_protocol: i.proxy_protocol,
        udp_direct: i.udp_direct,
    }
}

fn validate(f: &ForwardBinding) -> HttpResult<()> {
    let report = check_forward(f);
    if report.has_errors() {
        return Err(report_error(&report));
    }
    Ok(())
}

async fn status_of(link: &ManagerLink, id: ForwardBindingId) -> Option<ForwardStatus> {
    match link.call(Call::ForwardStatus(id)).await {
        Ok(Reply::ForwardStatus(s)) => Some(*s),
        _ => None,
    }
}

async fn view(state: &AppState, id: ForwardBindingId) -> HttpResult<ForwardView> {
    let binding = as_forward(get_entity(&state.link, EntityKind::Forward, id.to_string()).await?)?;
    Ok(ForwardView {
        status: status_of(&state.link, id).await,
        binding,
    })
}

/// `GET /v1/forward-bindings`: every forward with its status (`null` while the manager cannot
/// say).
pub async fn list(State(state): State<AppState>) -> HttpResult<Json<Vec<ForwardView>>> {
    let bindings = list_entities(&state.link, EntityKind::Forward).await?;
    let statuses = match state.link.call(Call::ForwardStatuses).await {
        Ok(Reply::ForwardStatuses(v)) => v,
        _ => Vec::new(),
    };
    Ok(Json(
        bindings
            .into_iter()
            .filter_map(|e| as_forward(e).ok())
            .map(|binding| ForwardView {
                status: statuses
                    .iter()
                    .find(|s| s.binding_id == binding.id)
                    .cloned(),
                binding,
            })
            .collect(),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<ForwardBindingId>,
) -> HttpResult<Response> {
    let v = view(&state, id).await?;
    Ok(with_etag(StatusCode::OK, v.binding.meta.revision, &v))
}

/// `GET /v1/forward-bindings/{id}/status`: what the forward does right now.
pub async fn status(
    State(state): State<AppState>,
    Path(id): Path<ForwardBindingId>,
) -> HttpResult<Json<ForwardStatus>> {
    match state.link.call(Call::ForwardStatus(id)).await? {
        Reply::ForwardStatus(s) => Ok(Json(*s)),
        _ => Err(wrong()),
    }
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let input: ForwardInput = parse_json(&headers, &body)?;
    let f = build(ForwardBindingId::new(), new_meta(), &input);
    validate(&f)?;
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        "/v1/forward-bindings",
        None,
        &body,
        "forward.create",
        None,
        |_| async move {
            let e = create_entity(&link, Entity::Forward(f)).await?;
            let id = match &e {
                Entity::Forward(f) => f.id,
                _ => return Err(ApiError::internal()),
            };
            Ok((vec![id.to_string()], id))
        },
    )
    .await?;
    let id = match out {
        Idem::Fresh { value, .. } => value,
        Idem::Replayed(op) => op
            .result_refs
            .first()
            .and_then(|s| s.parse().ok())
            .ok_or_else(wrong)?,
    };
    let v = view(&state, id).await?;
    Ok(with_etag(StatusCode::CREATED, v.binding.meta.revision, &v))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<ForwardBindingId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let rev = if_match(&headers)?;
    let input: ForwardInput = parse_json(&headers, &body)?;
    let current = as_forward(get_entity(&state.link, EntityKind::Forward, id.to_string()).await?)?;
    if current.instance_id != input.instance_id {
        return Err(bad(
            ErrorCode::ValidationFailed,
            tr!(
                "A port forward cannot move to another connection; delete it and create it again on that connection",
                "轉發不能移到另一條連線；請刪除後在那條連線重建",
                "ポート転送は別の接続に移せません。削除してから、その接続で作り直してください"
            ),
        ));
    }
    let f = build(id, current.meta, &input);
    validate(&f)?;
    let link = state.link.clone();
    let path = format!("/v1/forward-bindings/{id}");
    idempotent(
        &state.link,
        &headers,
        "PUT",
        &path,
        Some(rev),
        &body,
        "forward.update",
        Some(id.to_string()),
        |_| async move {
            update_entity(&link, Entity::Forward(f), rev).await?;
            Ok((vec![id.to_string()], ()))
        },
    )
    .await?;
    let v = view(&state, id).await?;
    Ok(with_etag(StatusCode::OK, v.binding.meta.revision, &v))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<ForwardBindingId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let rev = if_match(&headers)?;
    let link = state.link.clone();
    let path = format!("/v1/forward-bindings/{id}");
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        Some(rev),
        &body,
        "forward.delete",
        Some(id.to_string()),
        |_| async move {
            link.call(Call::Delete {
                kind: EntityKind::Forward,
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
