//! SSH download (`/v1/ssh-downloads*`): jobs that pull a remote folder into a local one through a
//! Gateway. The controller checks request shapes and relays; the manager checks the job against
//! the host (local folder, key file, Gateway), keeps its secrets in the vault and runs it — no
//! byte of a download passes through here.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use vpn_domain::{
    ApiError, EntityMeta, ErrorCode, FieldError, SSH_DOWNLOAD_FAILED_NAME, SSH_DOWNLOAD_WORK_NAME,
    SecretId, SecretRef, SshDownloadAction, SshDownloadActionRequest, SshDownloadActionResult,
    SshDownloadCleared, SshDownloadDirCheck, SshDownloadInput, SshDownloadJob, SshDownloadJobId,
    SshDownloadLog, SshDownloadTransfers, SshDownloadView, check_ssh_download, local_path_ok,
    sibling_dir, tr,
};
use vpn_ipc::SecretBytes;
use vpn_ipc::control::{Call, Reply};
use vpn_ipc::ssh_download::{JobSecrets, SecretChange, SshDownloadCall, SshDownloadReply};

use super::{AppState, Body, Idem, idempotent, new_meta, parse_json, run_once, wrong};
use crate::http::{HttpError, HttpResult, bad, idempotency_key, if_match, report_error, with_etag};
use crate::link::ManagerLink;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/ssh-downloads", get(list).post(create))
        .route("/v1/ssh-downloads/dir-check", get(dir_check))
        .route(
            "/v1/ssh-downloads/{id}",
            get(get_one).put(update).delete(delete),
        )
        .route("/v1/ssh-downloads/{id}/actions", post(action))
        .route(
            "/v1/ssh-downloads/{id}/transfers",
            get(transfers).delete(clear_history),
        )
        .route("/v1/ssh-downloads/{id}/log", get(log).delete(clear_log))
}

async fn call(link: &ManagerLink, c: SshDownloadCall) -> Result<SshDownloadReply, ApiError> {
    match link.call(Call::SshDownload(c)).await? {
        Reply::SshDownload(r) => Ok(*r),
        _ => Err(ApiError::internal()),
    }
}

async fn view(link: &ManagerLink, id: SshDownloadJobId) -> HttpResult<SshDownloadView> {
    match call(link, SshDownloadCall::Get(id)).await? {
        SshDownloadReply::View(v) => Ok(*v),
        _ => Err(wrong()),
    }
}

fn trimmed(v: Option<&str>) -> Option<String> {
    v.map(str::trim).filter(|s| !s.is_empty()).map(String::from)
}

/// The job an input describes (the secrets stay the stored job's until the manager applies the
/// input's).
fn build(
    id: SshDownloadJobId,
    meta: EntityMeta,
    i: &SshDownloadInput,
    current: Option<&SshDownloadJob>,
) -> SshDownloadJob {
    let source = i.source_dir.trim().to_string();
    let beside = |name: &str| sibling_dir(&source, name).unwrap_or_default();
    SshDownloadJob {
        id,
        meta,
        name: i.name.trim().to_string(),
        gateway_id: i.gateway_id,
        host: i.host.trim().to_string(),
        port: i.port,
        user: i.user.trim().to_string(),
        identity_file: trimmed(i.identity_file.as_deref()),
        key_passphrase: current.and_then(|c| c.key_passphrase),
        password: current.and_then(|c| c.password),
        work_dir: trimmed(i.work_dir.as_deref()).unwrap_or_else(|| beside(SSH_DOWNLOAD_WORK_NAME)),
        failed_dir: trimmed(i.failed_dir.as_deref())
            .unwrap_or_else(|| beside(SSH_DOWNLOAD_FAILED_NAME)),
        source_dir: source,
        local_dir: i.local_dir.trim().to_string(),
        connections: i.connections,
        retries: i.retries,
        retry_backoff_secs: i.retry_backoff_secs,
        scan_interval_secs: i.scan_interval_secs,
        name_filter: i.name_filter,
        skip_hidden: i.skip_hidden,
        record_names: i.record_names,
        history_days: i.history_days,
    }
}

fn change(value: Option<&str>, clear: bool, path: &str) -> HttpResult<SecretChange> {
    match (value.filter(|v| !v.is_empty()), clear) {
        (Some(_), true) => {
            let message = tr!(
                "Cannot set and clear it at the same time",
                "不能同時設定與清除",
                "設定とクリアを同時には行えません"
            );
            Err(HttpError(
                ApiError::new(ErrorCode::ValidationFailed, message.clone()).with_fields(vec![
                    FieldError {
                        path: path.into(),
                        code: "SECRET_SET_AND_CLEAR".into(),
                        message,
                    },
                ]),
            ))
        }
        (Some(v), false) => Ok(SecretChange::Set(SecretBytes::new(v.as_bytes().to_vec()))),
        (None, true) => Ok(SecretChange::Clear),
        (None, false) => Ok(SecretChange::Keep),
    }
}

fn secrets(i: &SshDownloadInput) -> HttpResult<JobSecrets> {
    Ok(JobSecrets {
        password: change(i.password.as_deref(), i.clear_password, "/password")?,
        key_passphrase: change(
            i.key_passphrase.as_deref(),
            i.clear_key_passphrase,
            "/key_passphrase",
        )?,
    })
}

/// The pure field rules, with the secrets as the input leaves them.
fn validate(job: &SshDownloadJob, s: &JobSecrets) -> HttpResult<()> {
    let mut intended = job.clone();
    let placeholder = || Some(SecretRef(SecretId::new()));
    if s.password.present(job.password.is_some()) {
        intended.password = intended.password.or_else(placeholder);
    } else {
        intended.password = None;
    }
    if s.key_passphrase.present(job.key_passphrase.is_some()) {
        intended.key_passphrase = intended.key_passphrase.or_else(placeholder);
    } else {
        intended.key_passphrase = None;
    }
    let report = check_ssh_download(&intended);
    if report.has_errors() {
        return Err(report_error(&report));
    }
    Ok(())
}

/// A request body that may carry a password: its idempotency fingerprint is keyed by the
/// manager (never a plain hash of the secret).
async fn keyed(link: &ManagerLink, body: &[u8]) -> HttpResult<String> {
    match link.call(Call::KeyedFingerprint(body.to_vec())).await? {
        Reply::Fingerprint(f) => Ok(f),
        _ => Err(wrong()),
    }
}

/// `GET /v1/ssh-downloads`: every job with its status (`null` while the manager cannot say).
pub async fn list(State(state): State<AppState>) -> HttpResult<Json<Vec<SshDownloadView>>> {
    match call(&state.link, SshDownloadCall::List).await? {
        SshDownloadReply::Views(v) => Ok(Json(v)),
        _ => Err(wrong()),
    }
}

pub async fn get_one(
    State(state): State<AppState>,
    Path(id): Path<SshDownloadJobId>,
) -> HttpResult<Response> {
    let v = view(&state.link, id).await?;
    Ok(with_etag(StatusCode::OK, v.job.meta.revision, &v))
}

/// `POST /v1/ssh-downloads` (Idempotency-Key).
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let input: SshDownloadInput = parse_json(&headers, &body)?;
    let job = build(SshDownloadJobId::new(), new_meta(), &input, None);
    let secrets = secrets(&input)?;
    validate(&job, &secrets)?;
    let key = idempotency_key(&headers)?;
    let fp = keyed(&state.link, &body).await?;
    let link = state.link.clone();
    let paused = input.paused;
    let out = run_once(
        &state.link,
        key,
        fp,
        "ssh_download.create",
        None,
        |_| async move {
            match call(
                &link,
                SshDownloadCall::Create {
                    job: Box::new(job),
                    secrets,
                    paused,
                },
            )
            .await?
            {
                SshDownloadReply::View(v) => Ok((vec![v.job.id.to_string()], *v)),
                _ => Err(ApiError::internal()),
            }
        },
    )
    .await?;
    let v = match out {
        Idem::Fresh { value, .. } => value,
        Idem::Replayed(op) => {
            let id = op
                .result_refs
                .first()
                .and_then(|s| s.parse().ok())
                .ok_or_else(wrong)?;
            view(&state.link, id).await?
        }
    };
    Ok(with_etag(StatusCode::CREATED, v.job.meta.revision, &v))
}

/// `PUT /v1/ssh-downloads/{id}` (If-Match, Idempotency-Key). `password` / `key_passphrase` left
/// out keep the stored ones.
pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<SshDownloadJobId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let rev = if_match(&headers)?;
    let input: SshDownloadInput = parse_json(&headers, &body)?;
    let current = view(&state.link, id).await?.job;
    let job = build(id, current.meta.clone(), &input, Some(&current));
    let secrets = secrets(&input)?;
    validate(&job, &secrets)?;
    let key = idempotency_key(&headers)?;
    // The revision is part of what is fingerprinted.
    let mut fingerprinted = rev.to_string().into_bytes();
    fingerprinted.push(b'\n');
    fingerprinted.extend_from_slice(&body);
    let fp = keyed(&state.link, &fingerprinted).await?;
    let link = state.link.clone();
    run_once(
        &state.link,
        key,
        fp,
        "ssh_download.update",
        Some(id.to_string()),
        |_| async move {
            match call(
                &link,
                SshDownloadCall::Update {
                    job: Box::new(job),
                    expected_revision: rev,
                    secrets,
                },
            )
            .await?
            {
                SshDownloadReply::View(_) => Ok((vec![id.to_string()], ())),
                _ => Err(ApiError::internal()),
            }
        },
    )
    .await?;
    let v = view(&state.link, id).await?;
    Ok(with_etag(StatusCode::OK, v.job.meta.revision, &v))
}

/// `DELETE /v1/ssh-downloads/{id}` (If-Match, Idempotency-Key): the job stops and goes with its
/// records and log; files in the remote working folder stay there.
pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<SshDownloadJobId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let rev = if_match(&headers)?;
    let link = state.link.clone();
    let path = format!("/v1/ssh-downloads/{id}");
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        Some(rev),
        &body,
        "ssh_download.delete",
        Some(id.to_string()),
        |_| async move {
            call(
                &link,
                SshDownloadCall::Delete {
                    id,
                    expected_revision: rev,
                },
            )
            .await?;
            Ok((vec![id.to_string()], ()))
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/ssh-downloads/{id}/actions` (Idempotency-Key): pause, resume, scan now, trust the
/// offered host key.
pub async fn action(
    State(state): State<AppState>,
    Path(id): Path<SshDownloadJobId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Json<SshDownloadActionResult>> {
    let req: SshDownloadActionRequest = parse_json(&headers, &body)?;
    let kind = match req.action {
        SshDownloadAction::Pause => "ssh_download.pause",
        SshDownloadAction::Resume => "ssh_download.resume",
        SshDownloadAction::Scan => "ssh_download.scan",
        SshDownloadAction::TrustHostKey => "ssh_download.trust_host_key",
    };
    let link = state.link.clone();
    let path = format!("/v1/ssh-downloads/{id}/actions");
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
            match call(
                &link,
                SshDownloadCall::Action {
                    id,
                    action: req.action,
                    fingerprint: req.fingerprint,
                },
            )
            .await?
            {
                SshDownloadReply::Status(s) => Ok((vec![id.to_string()], *s)),
                _ => Err(ApiError::internal()),
            }
        },
    )
    .await?;
    let (operation, status) = match out {
        Idem::Fresh { operation, value } => (operation, Some(value)),
        Idem::Replayed(operation) => (operation, view(&state.link, id).await?.status),
    };
    Ok(Json(SshDownloadActionResult { operation, status }))
}

#[derive(serde::Deserialize)]
pub struct TransfersQuery {
    state: Option<String>,
    before: Option<String>,
    limit: Option<String>,
}

fn bounded(v: Option<&str>, default: u32, max: u32, name: &str) -> HttpResult<u32> {
    match v.map(str::trim) {
        None | Some("") => Ok(default),
        Some(s) => s
            .parse::<u32>()
            .ok()
            .filter(|n| (1..=max).contains(n))
            .ok_or_else(|| {
                bad(
                    ErrorCode::InvalidRequest,
                    tr!(
                        "{name} must be a whole number from 1 to {max}",
                        "{name} 必須是 1 到 {max} 的整數",
                        "{name} は 1 から {max} までの整数にしてください"
                    ),
                )
            }),
    }
}

/// `GET /v1/ssh-downloads/{id}/transfers?state=active|history&before=&limit=`: the job's file
/// records, newest first (`history`, the default, pages with `before` = the previous `next`).
pub async fn transfers(
    State(state): State<AppState>,
    Path(id): Path<SshDownloadJobId>,
    Query(q): Query<TransfersQuery>,
) -> HttpResult<Json<SshDownloadTransfers>> {
    let finished = match q.state.as_deref().map(str::trim) {
        None | Some("" | "history") => true,
        Some("active") => false,
        Some(_) => {
            return Err(bad(
                ErrorCode::InvalidRequest,
                tr!(
                    "state must be active or history",
                    "state 必須是 active 或 history",
                    "state は active か history にしてください"
                ),
            ));
        }
    };
    let limit = bounded(q.limit.as_deref(), 50, 200, "limit")?;
    match call(
        &state.link,
        SshDownloadCall::Transfers {
            id,
            finished,
            before: q.before.filter(|b| !b.trim().is_empty()),
            limit,
        },
    )
    .await?
    {
        SshDownloadReply::Transfers(t) => Ok(Json(t)),
        _ => Err(wrong()),
    }
}

#[derive(serde::Deserialize)]
pub struct LogQuery {
    limit: Option<String>,
}

/// `GET /v1/ssh-downloads/{id}/log?limit=`: the newest lines (default 100, at most 500).
pub async fn log(
    State(state): State<AppState>,
    Path(id): Path<SshDownloadJobId>,
    Query(q): Query<LogQuery>,
) -> HttpResult<Json<SshDownloadLog>> {
    let limit = bounded(q.limit.as_deref(), 100, 500, "limit")?;
    match call(&state.link, SshDownloadCall::Log { id, limit }).await? {
        SshDownloadReply::Log(l) => Ok(Json(l)),
        _ => Err(wrong()),
    }
}

/// One clear of a job's log or history, run once per Idempotency-Key; a replay answers with the
/// count the first run deleted (kept with the operation).
async fn clear(
    state: &AppState,
    id: SshDownloadJobId,
    headers: &HeaderMap,
    body: &[u8],
    what: &str,
    call_for: fn(SshDownloadJobId) -> SshDownloadCall,
) -> HttpResult<Json<SshDownloadCleared>> {
    let link = state.link.clone();
    let path = format!("/v1/ssh-downloads/{id}/{what}");
    let kind = format!("ssh_download.clear_{what}");
    let out = idempotent(
        &state.link,
        headers,
        "DELETE",
        &path,
        None,
        body,
        &kind,
        Some(id.to_string()),
        |_| async move {
            match call(&link, call_for(id)).await? {
                SshDownloadReply::Cleared(c) => {
                    Ok((vec![id.to_string(), c.removed.to_string()], c))
                }
                _ => Err(ApiError::internal()),
            }
        },
    )
    .await?;
    Ok(Json(match out {
        Idem::Fresh { value, .. } => value,
        Idem::Replayed(op) => SshDownloadCleared {
            removed: op
                .result_refs
                .get(1)
                .and_then(|n| n.parse().ok())
                .unwrap_or_default(),
        },
    }))
}

/// `DELETE /v1/ssh-downloads/{id}/log` (Idempotency-Key): every line of the job's log goes, and
/// nothing of it is left in the database or its WAL; one line then says the log was cleared.
pub async fn clear_log(
    State(state): State<AppState>,
    Path(id): Path<SshDownloadJobId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Json<SshDownloadCleared>> {
    clear(&state, id, &headers, &body, "log", |id| {
        SshDownloadCall::ClearLog { id }
    })
    .await
}

/// `DELETE /v1/ssh-downloads/{id}/transfers` (Idempotency-Key): the job's finished records go
/// (its history). Unfinished ones stay — their files resume from them — and no file is touched.
pub async fn clear_history(
    State(state): State<AppState>,
    Path(id): Path<SshDownloadJobId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Json<SshDownloadCleared>> {
    clear(&state, id, &headers, &body, "transfers", |id| {
        SshDownloadCall::ClearHistory { id }
    })
    .await
}

#[derive(serde::Deserialize)]
pub struct DirQuery {
    path: Option<String>,
}

/// `GET /v1/ssh-downloads/dir-check?path=`: whether a local folder can take downloads (the
/// manager looks; nothing is created).
pub async fn dir_check(
    State(state): State<AppState>,
    Query(q): Query<DirQuery>,
) -> HttpResult<Json<SshDownloadDirCheck>> {
    let path = q
        .path
        .map(|p| p.trim().to_string())
        .filter(|p| local_path_ok(p))
        .ok_or_else(|| {
            bad(
                ErrorCode::InvalidRequest,
                tr!(
                    "path is required (a full path starting with / or ~/)",
                    "需要 path（以 / 或 ~/ 開頭的完整路徑）",
                    "path（/ または ~/ で始まる完全なパス）が必要です"
                ),
            )
        })?;
    match call(&state.link, SshDownloadCall::CheckDir { path }).await? {
        SshDownloadReply::DirCheck(c) => Ok(Json(c)),
        _ => Err(wrong()),
    }
}
