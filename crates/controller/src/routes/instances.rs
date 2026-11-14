//! Instances: CRUD plus lifecycle intents. VPN Core never drives a worker: it records the
//! intent with the Instance Manager and reports what the manager observes.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use vpn_domain::check_transport_ref;
use vpn_domain::validation::{check_instance_limits, check_instance_strict, check_name};
use vpn_domain::{
    Accepted, ApiError, ErrorCode, GatewayId, GatewaySpec, InstanceId, InstanceInput,
    InstancePurpose, InstanceSpec, InstanceView, LifecycleAction, LifecycleRequest, LiveRates,
    OP_INSTANCE_EMERGENCY_STOP, OP_INSTANCE_STOP, Operation, OperationId, OperationStatus,
    ProfileSummary, RuntimeProfile, Timestamp, ValidationReport, tr,
};
use vpn_ipc::control::{Call, Entity, EntityKind, Lifecycle, Reply};

use super::{
    AppState, Body, Idem, create_entity, finish, get_entity, idempotent, list_entities, new_meta,
    parse_json, update_entity, wrong,
};
use crate::http::{
    HttpError, HttpResult, bad, fingerprint, idempotency_key, if_match, report_error, with_etag,
};
use crate::link::ManagerLink;

fn summary(p: &RuntimeProfile) -> ProfileSummary {
    ProfileSummary {
        id: p.id,
        name: p.name.clone(),
        provider: p.provider,
        location: p.location.clone(),
        entry: match &p.source {
            vpn_domain::ProfileSource::Provider { entry, .. } => entry.clone(),
            vpn_domain::ProfileSource::Imported => None,
        },
        endpoint: p.peer.endpoint.to_string(),
        ipv6: p
            .interface
            .addresses
            .iter()
            .any(ipnetwork::IpNetwork::is_ipv6),
        revision: p.meta.revision,
    }
}

pub async fn views(state: &AppState) -> HttpResult<Vec<InstanceView>> {
    let specs = list_entities(&state.link, EntityKind::Instance).await?;
    let profiles: Vec<RuntimeProfile> = list_entities(&state.link, EntityKind::Profile)
        .await?
        .into_iter()
        .filter_map(|e| match e {
            Entity::Profile(p) => Some(p),
            _ => None,
        })
        .collect();
    let gateways: Vec<GatewaySpec> = list_entities(&state.link, EntityKind::Gateway)
        .await?
        .into_iter()
        .filter_map(|e| match e {
            Entity::Gateway(g) => Some(g),
            _ => None,
        })
        .collect();
    let statuses = match state.link.call(Call::InstanceStatuses).await {
        Ok(Reply::Statuses(v)) => v,
        _ => Vec::new(),
    };
    Ok(specs
        .into_iter()
        .filter_map(|e| match e {
            Entity::Instance(spec) => Some(spec),
            _ => None,
        })
        .map(|spec| InstanceView {
            status: statuses.iter().find(|s| s.instance_id == spec.id).cloned(),
            profile: profiles
                .iter()
                .find(|p| p.id == spec.profile_id)
                .map(summary),
            gateways: gateways
                .iter()
                .filter(|g| g.instance_id == spec.id)
                .cloned()
                .collect(),
            spec,
        })
        .collect())
}

async fn view(state: &AppState, id: InstanceId) -> HttpResult<InstanceView> {
    views(state)
        .await?
        .into_iter()
        .find(|v| v.spec.id == id)
        .ok_or_else(|| HttpError(ApiError::connection_not_found()))
}

pub async fn list(State(state): State<AppState>) -> HttpResult<Json<Vec<InstanceView>>> {
    Ok(Json(views(&state).await?))
}

pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<InstanceId>,
) -> HttpResult<Response> {
    let v = view(&state, id).await?;
    Ok(with_etag(StatusCode::OK, v.spec.meta.revision, &v))
}

fn validate(input: &InstanceInput) -> HttpResult<()> {
    let mut r = ValidationReport::default();
    check_name(&mut r, "/name", &input.name);
    check_instance_strict(&mut r, input.strict.unwrap_or(false));
    if let Some(l) = &input.limits {
        check_instance_limits(&mut r, l);
    }
    if let Some(t) = &input.transport {
        check_transport_ref(&mut r, "/transport", t);
    }
    let r = r.finish();
    if r.has_errors() {
        return Err(report_error(&r));
    }
    Ok(())
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let input: InstanceInput = parse_json(&headers, &body)?;
    validate(&input)?;
    let spec = InstanceSpec {
        id: InstanceId::new(),
        meta: new_meta(),
        name: input.name.trim().to_string(),
        profile_id: input.profile_id,
        dns_profile_id: input.dns_profile_id,
        security_profile_id: input.security_profile_id,
        purpose: InstancePurpose::General,
        limits: input.limits.unwrap_or_default(),
        strict: input.strict.unwrap_or(false),
        transport: input.transport.unwrap_or_default(),
    };
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        "/v1/instances",
        None,
        &body,
        "instance.create",
        None,
        |_| async move {
            let e = create_entity(&link, Entity::Instance(spec)).await?;
            let id = match &e {
                Entity::Instance(s) => s.id,
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
    Ok(with_etag(StatusCode::CREATED, v.spec.meta.revision, &v))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<InstanceId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let rev = if_match(&headers)?;
    let input: InstanceInput = parse_json(&headers, &body)?;
    validate(&input)?;
    let Entity::Instance(current) =
        get_entity(&state.link, EntityKind::Instance, id.to_string()).await?
    else {
        return Err(wrong());
    };
    let spec = InstanceSpec {
        id,
        meta: current.meta,
        name: input.name.trim().to_string(),
        profile_id: input.profile_id,
        dns_profile_id: input.dns_profile_id,
        security_profile_id: input.security_profile_id,
        purpose: current.purpose,
        limits: input.limits.unwrap_or(current.limits),
        strict: input.strict.unwrap_or(current.strict),
        transport: input.transport.unwrap_or(current.transport),
    };
    let link = state.link.clone();
    let path = format!("/v1/instances/{id}");
    idempotent(
        &state.link,
        &headers,
        "PUT",
        &path,
        Some(rev),
        &body,
        "instance.update",
        Some(id.to_string()),
        |_| async move {
            update_entity(&link, Entity::Instance(spec), rev).await?;
            Ok((vec![id.to_string()], ()))
        },
    )
    .await?;
    let v = view(&state, id).await?;
    Ok(with_etag(StatusCode::OK, v.spec.meta.revision, &v))
}

#[derive(serde::Deserialize)]
pub struct DeleteQuery {
    /// Delete these Gateways with the Instance (comma-separated ids, exactly its current set).
    gateways: Option<String>,
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<InstanceId>,
    Query(q): Query<DeleteQuery>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let rev = if_match(&headers)?;
    let gateways: Option<Vec<GatewayId>> = match &q.gateways {
        None => None,
        Some(list) => Some(
            list.split(',')
                .filter(|s| !s.is_empty())
                .map(str::parse)
                .collect::<Result<_, _>>()
                .map_err(|e| {
                    tracing::debug!(error = %e, "gateways query refused");
                    bad(
                        ErrorCode::InvalidRequest,
                        tr!(
                            "gateways must be comma-separated ids",
                            "gateways 必須是以逗號分隔的 id",
                            "gateways はカンマ区切りの id にしてください"
                        ),
                    )
                })?,
        ),
    };
    let link = state.link.clone();
    let path = q.gateways.as_ref().map_or_else(
        || format!("/v1/instances/{id}"),
        |list| format!("/v1/instances/{id}?gateways={list}"),
    );
    let hub = state.hub.clone();
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        Some(rev),
        &body,
        "instance.delete",
        Some(id.to_string()),
        |_| async move {
            let call = gateways.map_or_else(
                || Call::Delete {
                    kind: EntityKind::Instance,
                    id: id.to_string(),
                    expected_revision: rev,
                },
                |gateways| Call::DeleteInstance {
                    id,
                    expected_revision: rev,
                    gateways,
                },
            );
            link.call(call).await?;
            hub.forget(id);
            Ok((vec![id.to_string()], ()))
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn accepted(a: Accepted) -> Response {
    let loc = format!("/v1/operations/{}", a.operation.id);
    let durable = a.operation.durable;
    let mut r = (StatusCode::ACCEPTED, Json(a)).into_response();
    // An operation the Store could not record has nothing to look up.
    if durable && let Ok(v) = HeaderValue::from_str(&loc) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r
}

async fn lifecycle(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    id: InstanceId,
    action: Lifecycle,
    path: &str,
) -> HttpResult<Response> {
    // A manager start reads the two stop kinds back (stops whose latch may never have reached
    // the disk), so they are shared constants.
    let kind = match action {
        Lifecycle::Start => "instance.start",
        Lifecycle::Stop => OP_INSTANCE_STOP,
        Lifecycle::Restart => "instance.restart",
        Lifecycle::ClearEmergency => "instance.clear_emergency",
        Lifecycle::Emergency => OP_INSTANCE_EMERGENCY_STOP,
    };
    if matches!(action, Lifecycle::Stop | Lifecycle::Emergency) {
        return stop(&state.link, headers, body, id, action, kind, path).await;
    }
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        headers,
        "POST",
        path,
        None,
        body,
        kind,
        Some(id.to_string()),
        |_| async move {
            match link.call(Call::Lifecycle(id, action)).await? {
                Reply::Stopped { sealed, durable } => {
                    Ok((vec![id.to_string()], (Some(sealed), Some(durable))))
                }
                Reply::Status(_) => Ok((vec![id.to_string()], (None, None))),
                _ => Err(ApiError::internal()),
            }
        },
    )
    .await?;
    let (sealed, durable) = match &out {
        Idem::Fresh { value, .. } => *value,
        Idem::Replayed(_) => (None, None),
    };
    Ok(accepted(Accepted {
        operation: out.operation().clone(),
        sealed,
        durable,
    }))
}

/// Stop and emergency stop go to the manager at once: never behind the operation record, whose
/// Store write takes the normal lane (which may be full, failing or slow). The manager's stop
/// latch takes the priority lane and is the durable record of a stop. The operation is recorded
/// alongside when the Store takes it, and once more afterwards if it did not; a stop is
/// idempotent, so a replayed key stops again and answers with the operation recorded first.
async fn stop(
    link: &ManagerLink,
    headers: &HeaderMap,
    body: &[u8],
    id: InstanceId,
    action: Lifecycle,
    kind: &str,
    path: &str,
) -> HttpResult<Response> {
    let key = idempotency_key(headers)?;
    let fp = fingerprint("POST", path, None, body);
    let record = || async {
        let begin = Call::BeginOperation {
            kind: kind.into(),
            target_id: Some(id.to_string()),
            idempotency_key: Some(key.clone()),
            fingerprint: Some(fp.clone()),
        };
        match link.call(begin).await {
            Ok(Reply::Begin {
                operation,
                existing,
            }) => Some((operation, existing)),
            Ok(_) => None,
            Err(e) => {
                tracing::warn!(code = ?e.code, %kind, "stop not recorded as an operation yet");
                None
            }
        }
    };
    let (begun, reply) = tokio::join!(record(), link.call(Call::Lifecycle(id, action)));
    let outcome = match reply {
        Ok(Reply::Stopped { sealed, durable }) => Ok((sealed, durable)),
        Ok(_) => Err(ApiError::internal()),
        Err(e) => Err(e),
    };
    let begun = match begun {
        Some(begun) => Some(begun),
        None => record().await,
    };
    let refs = vec![id.to_string()];
    let operation = match begun {
        // A replay keeps its record, unless this stop completed what the first one did not.
        Some((operation, true))
            if operation.status == OperationStatus::Succeeded || outcome.is_err() =>
        {
            operation
        }
        Some((operation, _)) => {
            let ended = outcome.as_ref().map(|_| refs.clone());
            finish(link, operation, ended).await
        }
        // Not recorded at all: the stop itself happened (or failed) regardless.
        None => match &outcome {
            Ok(_) => {
                let now = Timestamp::now();
                Operation {
                    id: OperationId::new(),
                    kind: kind.into(),
                    target_id: Some(id.to_string()),
                    status: OperationStatus::Succeeded,
                    error: None,
                    result_refs: refs,
                    durable: false,
                    created_at: now,
                    updated_at: now,
                }
            }
            Err(e) => return Err(HttpError(e.clone())),
        },
    };
    match outcome {
        Ok((sealed, durable)) => Ok(accepted(Accepted {
            operation,
            sealed: Some(sealed),
            durable: Some(durable),
        })),
        Err(e) => Err(HttpError(e.with_operation(operation.id))),
    }
}

pub async fn action(
    State(state): State<AppState>,
    Path(id): Path<InstanceId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let req: LifecycleRequest = parse_json(&headers, &body)?;
    let action = match req.action {
        LifecycleAction::Start => Lifecycle::Start,
        LifecycleAction::Stop => Lifecycle::Stop,
        LifecycleAction::Restart => Lifecycle::Restart,
        LifecycleAction::ClearEmergency => Lifecycle::ClearEmergency,
    };
    let path = format!("/v1/instances/{id}/actions");
    lifecycle(&state, &headers, &body, id, action, &path).await
}

/// Emergency stop: no If-Match (it must never be blocked by a revision race).
pub async fn emergency_stop(
    State(state): State<AppState>,
    Path(id): Path<InstanceId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let path = format!("/v1/instances/{id}/emergency-stop");
    lifecycle(&state, &headers, &body, id, Lifecycle::Emergency, &path).await
}

pub async fn live(
    State(state): State<AppState>,
    Path(id): Path<InstanceId>,
) -> Json<Vec<LiveRates>> {
    Json(state.hub.live(id))
}
