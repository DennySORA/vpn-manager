use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use vpn_domain::validation::check_gateway;
use vpn_domain::{
    ApiError, EntityMeta, ErrorCode, FieldError, FreePort, GatewayId, GatewayInput, GatewaySpec, tr,
};
use vpn_ipc::control::{Call, Entity, EntityKind, Reply};

use super::{
    AppState, Body, Idem, create_entity, get_entity, idempotent, list_entities, new_meta,
    parse_json, update_entity, wrong,
};
use crate::http::{HttpError, HttpResult, bad, if_match, report_error, with_etag};

fn as_gateway(e: Entity) -> HttpResult<GatewaySpec> {
    match e {
        Entity::Gateway(g) => Ok(g),
        _ => Err(wrong()),
    }
}

fn build(id: GatewayId, meta: EntityMeta, i: &GatewayInput) -> GatewaySpec {
    GatewaySpec {
        id,
        meta,
        instance_id: i.instance_id,
        name: i.name.trim().to_string(),
        kind: i.kind,
        port: i.port,
        enabled: i.enabled,
        udp: i.udp,
        max_connections: i.max_connections,
    }
}

async fn check(state: &AppState, g: &GatewaySpec) -> HttpResult<()> {
    let report = check_gateway(g);
    if report.has_errors() {
        return Err(report_error(&report));
    }
    let others = list_entities(&state.link, EntityKind::Gateway).await?;
    let clash = others
        .iter()
        .any(|e| matches!(e, Entity::Gateway(o) if o.id != g.id && o.port == g.port));
    if clash {
        let port = g.port;
        return Err(HttpError(
            ApiError::new(
                ErrorCode::ListenerConflict,
                tr!(
                    "Port {port} is already used by another Gateway",
                    "port {port} 已被其他 Gateway 使用",
                    "ポート {port} は別のゲートウェイが使用しています"
                ),
            )
            .with_fields(vec![FieldError {
                path: "/port".into(),
                code: "PORT_IN_USE".into(),
                message: tr!(
                    "This port is already used by another Gateway",
                    "這個 port 已被其他 Gateway 使用",
                    "このポートは別のゲートウェイが使用しています"
                ),
            }]),
        ));
    }
    Ok(())
}

pub async fn list(State(state): State<AppState>) -> HttpResult<Json<Vec<GatewaySpec>>> {
    let v = list_entities(&state.link, EntityKind::Gateway).await?;
    Ok(Json(
        v.into_iter().filter_map(|e| as_gateway(e).ok()).collect(),
    ))
}

pub async fn get(State(state): State<AppState>, Path(id): Path<GatewayId>) -> HttpResult<Response> {
    let g = as_gateway(get_entity(&state.link, EntityKind::Gateway, id.to_string()).await?)?;
    Ok(with_etag(StatusCode::OK, g.meta.revision, &g))
}

#[derive(serde::Deserialize)]
pub struct FreePortQuery {
    from: Option<String>,
}

/// `GET /v1/ports/free?from=<port>`: the first port from `from` on (at most 200 tried) that no
/// Gateway uses and nothing holds on 127.0.0.1 right now; 409 when there is none. The manager
/// answers: it owns the listeners, the controller never binds.
pub async fn free_port(
    State(state): State<AppState>,
    Query(q): Query<FreePortQuery>,
) -> HttpResult<Json<FreePort>> {
    let from = q
        .from
        .as_deref()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .filter(|p| *p >= 1024)
        .ok_or_else(|| {
            bad(
                ErrorCode::InvalidRequest,
                tr!(
                    "from must be a port from 1024 to 65535",
                    "from 必須是 1024–65535 之間的 port",
                    "from は 1024–65535 のポート番号にしてください"
                ),
            )
        })?;
    match state.link.call(Call::FreePort { from }).await? {
        Reply::FreePort(port) => Ok(Json(FreePort { port })),
        _ => Err(wrong()),
    }
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let input: GatewayInput = parse_json(&headers, &body)?;
    let g = build(GatewayId::new(), new_meta(), &input);
    check(&state, &g).await?;
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        "/v1/gateways",
        None,
        &body,
        "gateway.create",
        None,
        |_| async move {
            let e = create_entity(&link, Entity::Gateway(g)).await?;
            let id = match &e {
                Entity::Gateway(g) => g.id.to_string(),
                _ => String::new(),
            };
            Ok((vec![id], e))
        },
    )
    .await?;
    let g = match out {
        Idem::Fresh { value, .. } => as_gateway(value)?,
        Idem::Replayed(op) => {
            let id = op.result_refs.first().cloned().ok_or_else(wrong)?;
            as_gateway(get_entity(&state.link, EntityKind::Gateway, id).await?)?
        }
    };
    Ok(with_etag(StatusCode::CREATED, g.meta.revision, &g))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<GatewayId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let rev = if_match(&headers)?;
    let input: GatewayInput = parse_json(&headers, &body)?;
    let current = as_gateway(get_entity(&state.link, EntityKind::Gateway, id.to_string()).await?)?;
    if current.instance_id != input.instance_id {
        return Err(bad(
            ErrorCode::ValidationFailed,
            tr!(
                "A Gateway cannot move to another Instance; delete it and create it again",
                "Gateway 不能移到另一個 Instance；請刪除後重建",
                "ゲートウェイは別の Instance に移せません。削除してから作り直してください"
            ),
        ));
    }
    let g = build(id, current.meta, &input);
    check(&state, &g).await?;
    let link = state.link.clone();
    let path = format!("/v1/gateways/{id}");
    let out = idempotent(
        &state.link,
        &headers,
        "PUT",
        &path,
        Some(rev),
        &body,
        "gateway.update",
        Some(id.to_string()),
        |_| async move {
            Ok((
                vec![id.to_string()],
                update_entity(&link, Entity::Gateway(g), rev).await?,
            ))
        },
    )
    .await?;
    let g = match out {
        Idem::Fresh { value, .. } => as_gateway(value)?,
        Idem::Replayed(_) => {
            as_gateway(get_entity(&state.link, EntityKind::Gateway, id.to_string()).await?)?
        }
    };
    Ok(with_etag(StatusCode::OK, g.meta.revision, &g))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<GatewayId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let rev = if_match(&headers)?;
    let link = state.link.clone();
    let path = format!("/v1/gateways/{id}");
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        Some(rev),
        &body,
        "gateway.delete",
        Some(id.to_string()),
        |_| async move {
            link.call(Call::Delete {
                kind: EntityKind::Gateway,
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
