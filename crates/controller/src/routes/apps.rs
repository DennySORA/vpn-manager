//! Managed Apps: configuration, lifecycle actions and what the manager observes (status, the
//! process tree, the App's own output). The manager approves executables and runs everything;
//! the controller checks request shapes and relays.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use vpn_domain::validation::{check_app, network_of};
use vpn_domain::{
    APP_STOP_GRACE_DEFAULT_SECS, ApiError, AppAccessPort, AppAction, AppActionRequest,
    AppActionResult, AppId, AppInput, AppLog, AppProcesses, AppSpec, AppStatus, AppView,
    EntityMeta, ErrorCode, ExecutableApproval, ExecutableCheck, Operation, OperationId,
    OperationStatus, Timestamp, tr, validation,
};
use vpn_ipc::control::{Call, Entity, EntityKind, Reply};

use super::{
    AppState, Body, Idem, finish, get_entity, idempotent, list_entities, new_meta, parse_json,
    wrong,
};
use crate::http::{
    HttpError, HttpResult, bad, fingerprint, idempotency_key, if_match, report_error, with_etag,
};
use crate::link::ManagerLink;

fn as_app(e: Entity) -> HttpResult<AppSpec> {
    match e {
        Entity::App(a) => Ok(a),
        _ => Err(wrong()),
    }
}

fn trimmed(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// The App as saved from input `i`. What the input leaves out keeps `current`'s value (an update),
/// else the default (a new App).
fn build(
    id: AppId,
    meta: EntityMeta,
    i: AppInput,
    approval: Option<ExecutableApproval>,
    current: Option<&AppSpec>,
) -> AppSpec {
    let confine_writes = i
        .confine_writes
        .or_else(|| current.map(|c| c.confine_writes))
        .unwrap_or(false);
    let stop_grace_secs = i
        .stop_grace_secs
        .or_else(|| current.map(|c| c.stop_grace_secs))
        .unwrap_or(APP_STOP_GRACE_DEFAULT_SECS);
    AppSpec {
        id,
        meta,
        instance_id: i.instance_id,
        name: i.name.trim().to_string(),
        executable: i.executable.trim().to_string(),
        args: i.args,
        working_dir: i.working_dir.as_deref().and_then(trimmed),
        env: i.env,
        isolation: i.isolation,
        gateway_id: i.gateway_id,
        restart_on_recovery: i.restart_on_recovery,
        writable_paths: i.writable_paths.iter().filter_map(|p| trimmed(p)).collect(),
        confine_writes,
        stop_grace_secs,
        approval,
        limits: i.limits,
        // Networks as networks: `192.168.10.5/24` is kept as `192.168.10.0/24`.
        access_ports: i
            .access_ports
            .into_iter()
            .map(|p| AppAccessPort {
                allow: p.allow.into_iter().map(network_of).collect(),
                ..p
            })
            .collect(),
    }
}

fn validate(spec: &AppSpec) -> HttpResult<()> {
    let report = check_app(spec);
    if report.has_errors() {
        return Err(report_error(&report));
    }
    Ok(())
}

async fn status_of(link: &ManagerLink, id: AppId) -> Option<AppStatus> {
    match link.call(Call::AppStatus(id)).await {
        Ok(Reply::AppStatus(s)) => Some(*s),
        _ => None,
    }
}

async fn view(state: &AppState, id: AppId) -> HttpResult<AppView> {
    let spec = as_app(get_entity(&state.link, EntityKind::App, id.to_string()).await?)?;
    Ok(AppView {
        status: status_of(&state.link, id).await,
        spec,
    })
}

/// `GET /v1/apps`: every App with its status (`null` while the manager cannot say).
pub async fn list(State(state): State<AppState>) -> HttpResult<Json<Vec<AppView>>> {
    let specs = list_entities(&state.link, EntityKind::App).await?;
    let statuses = match state.link.call(Call::AppStatuses).await {
        Ok(Reply::AppStatuses(v)) => v,
        _ => Vec::new(),
    };
    Ok(Json(
        specs
            .into_iter()
            .filter_map(|e| as_app(e).ok())
            .map(|spec| AppView {
                status: statuses.iter().find(|s| s.app_id == spec.id).cloned(),
                spec,
            })
            .collect(),
    ))
}

pub async fn get(State(state): State<AppState>, Path(id): Path<AppId>) -> HttpResult<Response> {
    let v = view(&state, id).await?;
    Ok(with_etag(StatusCode::OK, v.spec.meta.revision, &v))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let input: AppInput = parse_json(&headers, &body)?;
    let expected = input.executable_sha256.clone();
    let spec = build(AppId::new(), new_meta(), input, None, None);
    validate(&spec)?;
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        "/v1/apps",
        None,
        &body,
        "app.create",
        None,
        |_| async move {
            match link
                .call(Call::CreateApp {
                    spec,
                    expected_sha256: expected,
                })
                .await?
            {
                Reply::Entity(e) => match *e {
                    Entity::App(a) => Ok((vec![a.id.to_string()], a.id)),
                    _ => Err(ApiError::internal()),
                },
                _ => Err(ApiError::internal()),
            }
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
    Path(id): Path<AppId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let rev = if_match(&headers)?;
    let input: AppInput = parse_json(&headers, &body)?;
    let expected = input.executable_sha256.clone();
    let current = as_app(get_entity(&state.link, EntityKind::App, id.to_string()).await?)?;
    // The manager decides what happens to the approval (kept for the same path).
    let spec = build(
        id,
        current.meta.clone(),
        input,
        current.approval.clone(),
        Some(&current),
    );
    validate(&spec)?;
    let link = state.link.clone();
    let path = format!("/v1/apps/{id}");
    idempotent(
        &state.link,
        &headers,
        "PUT",
        &path,
        Some(rev),
        &body,
        "app.update",
        Some(id.to_string()),
        |_| async move {
            match link
                .call(Call::UpdateApp {
                    spec,
                    expected_revision: rev,
                    expected_sha256: expected,
                })
                .await?
            {
                Reply::Entity(_) => Ok((vec![id.to_string()], ())),
                _ => Err(ApiError::internal()),
            }
        },
    )
    .await?;
    let v = view(&state, id).await?;
    Ok(with_etag(StatusCode::OK, v.spec.meta.revision, &v))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<AppId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let rev = if_match(&headers)?;
    let link = state.link.clone();
    let path = format!("/v1/apps/{id}");
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        Some(rev),
        &body,
        "app.delete",
        Some(id.to_string()),
        |_| async move {
            link.call(Call::DeleteApp {
                id,
                expected_revision: rev,
            })
            .await?;
            Ok((vec![id.to_string()], ()))
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/apps/{id}/actions`: start, stop, restart, approve. A stop goes to the manager at
/// once, never behind the operation record (whose Store write may be queued or failing); the
/// record is made alongside, like an Instance stop.
pub async fn action(
    State(state): State<AppState>,
    Path(id): Path<AppId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Json<AppActionResult>> {
    let req: AppActionRequest = parse_json(&headers, &body)?;
    let kind = match req.action {
        AppAction::Start => "app.start",
        AppAction::Stop => "app.stop",
        AppAction::Restart => "app.restart",
        AppAction::Approve => "app.approve",
    };
    let path = format!("/v1/apps/{id}/actions");
    let call = Call::AppAction {
        id,
        action: req.action,
        sha256: req.sha256.clone(),
    };
    if req.action == AppAction::Stop {
        return stop(&state.link, &headers, &body, id, call, kind, &path).await;
    }
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        &path,
        None,
        &body,
        kind,
        Some(id.to_string()),
        |_| async move {
            match link.call(call).await? {
                Reply::AppStatus(s) => Ok((vec![id.to_string()], *s)),
                _ => Err(ApiError::internal()),
            }
        },
    )
    .await?;
    let (operation, status) = match out {
        Idem::Fresh { operation, value } => (operation, Some(value)),
        Idem::Replayed(operation) => (operation, status_of(&state.link, id).await),
    };
    Ok(Json(AppActionResult { operation, status }))
}

async fn stop(
    link: &ManagerLink,
    headers: &HeaderMap,
    body: &[u8],
    id: AppId,
    call: Call,
    kind: &str,
    path: &str,
) -> HttpResult<Json<AppActionResult>> {
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
            _ => None,
        }
    };
    let (begun, reply) = tokio::join!(record(), link.call(call));
    let outcome = match reply {
        Ok(Reply::AppStatus(s)) => Ok(*s),
        Ok(_) => Err(ApiError::internal()),
        Err(e) => Err(e),
    };
    let begun = match begun {
        Some(b) => Some(b),
        None => record().await,
    };
    let refs = vec![id.to_string()];
    let operation = match begun {
        Some((operation, true))
            if operation.status == OperationStatus::Succeeded || outcome.is_err() =>
        {
            operation
        }
        Some((operation, _)) => {
            let ended = outcome.as_ref().map(|_| refs.clone());
            finish(link, operation, ended).await
        }
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
        Ok(status) => Ok(Json(AppActionResult {
            operation,
            status: Some(status),
        })),
        Err(e) => Err(HttpError(e.with_operation(operation.id))),
    }
}

pub async fn status(
    State(state): State<AppState>,
    Path(id): Path<AppId>,
) -> HttpResult<Json<AppStatus>> {
    match state.link.call(Call::AppStatus(id)).await? {
        Reply::AppStatus(s) => Ok(Json(*s)),
        _ => Err(wrong()),
    }
}

pub async fn processes(
    State(state): State<AppState>,
    Path(id): Path<AppId>,
) -> HttpResult<Json<AppProcesses>> {
    match state.link.call(Call::AppProcesses(id)).await? {
        Reply::AppProcesses(p) => Ok(Json(*p)),
        _ => Err(wrong()),
    }
}

#[derive(serde::Deserialize)]
pub struct LogQuery {
    lines: Option<String>,
}

/// `GET /v1/apps/{id}/log?lines=`: the newest lines (default 200, at most 1000).
pub async fn log(
    State(state): State<AppState>,
    Path(id): Path<AppId>,
    Query(q): Query<LogQuery>,
) -> HttpResult<Json<AppLog>> {
    let lines = match q.lines.as_deref().map(str::trim) {
        None | Some("") => 200,
        Some(s) => s
            .parse::<u32>()
            .ok()
            .filter(|n| (1..=1000).contains(n))
            .ok_or_else(|| {
                bad(
                    ErrorCode::InvalidRequest,
                    tr!(
                        "lines must be a whole number from 1 to 1000",
                        "lines 必須是 1 到 1000 的整數",
                        "lines は 1 から 1000 までの整数にしてください"
                    ),
                )
            })?,
    };
    match state.link.call(Call::AppLog { id, lines }).await? {
        Reply::AppLog(l) => Ok(Json(*l)),
        _ => Err(wrong()),
    }
}

#[derive(serde::Deserialize)]
pub struct ExecutableQuery {
    path: Option<String>,
}

/// `GET /v1/apps/executable-check?path=`: whether a path can be approved (the manager resolves,
/// checks and hashes it; nothing is stored).
pub async fn executable_check(
    State(state): State<AppState>,
    Query(q): Query<ExecutableQuery>,
) -> HttpResult<Json<ExecutableCheck>> {
    let path = q
        .path
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty() && p.len() <= validation::APP_MAX_PATH)
        .ok_or_else(|| {
            bad(
                ErrorCode::InvalidRequest,
                tr!(
                    "path is required (an absolute path)",
                    "需要 path（絕對路徑）",
                    "path（絶対パス）が必要です"
                ),
            )
        })?;
    match state.link.call(Call::CheckExecutable { path }).await? {
        Reply::ExecutableCheck(c) => Ok(Json(*c)),
        _ => Err(wrong()),
    }
}
