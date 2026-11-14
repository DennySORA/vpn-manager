//! VPN Web API routes. Handlers stay thin: validation (VPN Profile Checker), orchestration
//! (VPN Core) and every durable change go through the manager link.

mod apps;
mod bans;
mod blocklists;
mod diagnostics;
mod dns;
mod events;
mod forwards;
mod gateways;
mod instances;
mod metrics;
mod operations;
mod performance;
mod profiles;
mod providers;
mod recovery;
mod security;
mod ssh;
mod ssh_downloads;
mod system;
mod transport;

use std::future::Future;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderMap, header};
use axum::routing::{get, post};
use serde::de::DeserializeOwned;
use vpn_domain::{
    ApiError, EntityMeta, ErrorCode, Operation, OperationId, OperationStatus, Timestamp, tr,
};
use vpn_ipc::control::{Call, Entity, EntityKind, Reply};

use crate::http::{HttpError, HttpResult, bad, fingerprint, idempotency_key};
use crate::hub::Hub;
use crate::link::ManagerLink;

#[derive(Debug, Clone)]
pub struct AppState {
    pub link: Arc<ManagerLink>,
    pub hub: Arc<Hub>,
    /// Port of the web UI and API, reported in the system status.
    pub port: u16,
    /// Where the web UI and API listen and which other hosts may use them, reported in the
    /// system status.
    pub exposure: Arc<crate::Exposure>,
    /// The installation's directory, reported in the system status.
    pub data_dir: Option<Arc<str>>,
    /// The installation's Gateway key file (`<state>/gateway.key`): the SSH connection test
    /// must prove it reached our own Gateway.
    pub gateway_key: Option<Arc<std::path::PathBuf>>,
    /// Provider accounts and the egress route (tokens and catalogs live here, in memory).
    pub providers: Arc<crate::provider::Providers>,
}

pub const MAX_BODY: usize = 256 * 1024;

/// The API routes (`/healthz`, `/v1/...`) with their body limits.
pub fn api(state: AppState) -> Router {
    entity_routes()
        .merge(live_routes())
        .merge(service_routes())
        .merge(ssh_downloads::routes())
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

/// System, recovery, profiles, policies, blocklists, Instances and their actions.
fn entity_routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(system::healthz))
        .route("/v1/system/status", get(system::status))
        .route("/v1/system/capabilities", get(system::capabilities))
        .route("/v1/system/diagnostics", get(diagnostics::diagnostics))
        .route("/v1/recovery", get(recovery::inspect))
        .route("/v1/recovery/reconcile", post(recovery::reconcile))
        .route(
            "/v1/settings",
            get(system::get_settings).put(system::put_settings),
        )
        .route("/v1/profiles", get(profiles::list))
        .route("/v1/profiles/import", post(profiles::import))
        .route(
            "/v1/profiles/{id}",
            get(profiles::get)
                .put(profiles::update)
                .delete(profiles::delete),
        )
        .route("/v1/profiles/{id}/check", get(profiles::check))
        .route("/v1/dns-profiles", get(dns::list).post(dns::create))
        .route(
            "/v1/dns-profiles/{id}",
            get(dns::get).put(dns::update).delete(dns::delete),
        )
        .route(
            "/v1/security-profiles",
            get(security::list).post(security::create),
        )
        .route(
            "/v1/security-profiles/{id}",
            get(security::get)
                .put(security::update)
                .delete(security::delete),
        )
        .route(
            "/v1/transport-profiles",
            get(transport::list).post(transport::create),
        )
        .route("/v1/transport-profiles/builtin", get(transport::builtin))
        .route(
            "/v1/transport-profiles/{id}",
            get(transport::get)
                .put(transport::update)
                .delete(transport::delete),
        )
        // A list may be 8 MiB: these routes take larger bodies than the rest of the API.
        .route(
            "/v1/blocklists/preview",
            post(blocklists::preview).layer(DefaultBodyLimit::max(blocklists::PREVIEW_BODY)),
        )
        .route(
            "/v1/blocklists",
            get(blocklists::list)
                .post(blocklists::create)
                .layer(DefaultBodyLimit::max(blocklists::COMMIT_BODY)),
        )
        .route(
            "/v1/blocklists/{id}",
            get(blocklists::get)
                .put(blocklists::update)
                .delete(blocklists::delete)
                .layer(DefaultBodyLimit::max(blocklists::COMMIT_BODY)),
        )
        .route("/v1/blocklists/{id}/refresh", post(blocklists::refresh))
        .route("/v1/blocklists/builtin", get(blocklists::builtin))
        .route(
            "/v1/blocklists/builtin/{key}/restore",
            post(blocklists::restore),
        )
        .route("/v1/bans", get(bans::list))
        .route("/v1/bans/{id}", axum::routing::delete(bans::delete))
        .route("/v1/security/inbound", get(bans::inbound))
        .route(
            "/v1/instances",
            get(instances::list).post(instances::create),
        )
        .route(
            "/v1/instances/{id}",
            get(instances::get)
                .put(instances::update)
                .delete(instances::delete),
        )
        .route("/v1/instances/{id}/actions", post(instances::action))
        .route(
            "/v1/instances/{id}/emergency-stop",
            post(instances::emergency_stop),
        )
        .route("/v1/instances/{id}/live", get(instances::live))
}

/// Metrics, Provider egress, accounts and forwarded ports.
fn live_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/instances/{id}/metrics", get(metrics::instance))
        .route("/v1/metrics/series", get(metrics::series))
        .route("/v1/metrics/status", get(metrics::status))
        .route(
            "/v1/instances/{id}/ip-check",
            post(providers::check_instance),
        )
        .route(
            "/v1/provider-egress",
            get(providers::egress).put(providers::put_egress),
        )
        .route(
            "/v1/provider-egress/bootstrap",
            post(providers::bootstrap).delete(providers::end_bootstrap),
        )
        .route(
            "/v1/provider-egress/rebootstrap",
            post(providers::rebootstrap).delete(providers::cancel_rebootstrap),
        )
        .route("/v1/provider-egress/check", post(providers::check_egress))
        .route(
            "/v1/provider-accounts",
            get(providers::list).post(providers::create),
        )
        .route(
            "/v1/provider-accounts/{id}",
            get(providers::get).delete(providers::delete),
        )
        .route(
            "/v1/provider-accounts/{id}/refresh",
            post(providers::refresh),
        )
        .route(
            "/v1/provider-accounts/{id}/devices",
            get(providers::devices),
        )
        .route(
            "/v1/provider-accounts/{id}/devices/{device}",
            axum::routing::delete(providers::revoke_device),
        )
        .route(
            "/v1/provider-accounts/{id}/forwarded-ports",
            get(providers::forwarded_ports).post(providers::reserve_port),
        )
        .route(
            "/v1/provider-accounts/{id}/forwarded-ports/ddns",
            get(providers::ddns),
        )
        .route(
            "/v1/provider-accounts/{id}/forwarded-ports/free",
            get(providers::free_ports),
        )
        .route(
            "/v1/provider-accounts/{id}/forwarded-ports/{port}",
            axum::routing::delete(providers::delete_port).patch(providers::update_port),
        )
        .route(
            "/v1/provider-accounts/{id}/forwarded-ports/{port}/test",
            post(providers::test_port),
        )
}

/// Provider servers, Gateways, forwards, operations, SSH, performance and events.
fn service_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/provider-accounts/{id}/servers",
            get(providers::servers),
        )
        .route(
            "/v1/provider-accounts/{id}/connections",
            post(providers::connect),
        )
        .route(
            "/v1/provider-accounts/{id}/profiles/{profile}/server",
            post(providers::change_server),
        )
        .route("/v1/gateways", get(gateways::list).post(gateways::create))
        .route(
            "/v1/gateways/{id}",
            get(gateways::get)
                .put(gateways::update)
                .delete(gateways::delete),
        )
        .route("/v1/ports/free", get(gateways::free_port))
        .route(
            "/v1/forward-bindings",
            get(forwards::list).post(forwards::create),
        )
        .route(
            "/v1/forward-bindings/{id}",
            get(forwards::get)
                .put(forwards::update)
                .delete(forwards::delete),
        )
        .route("/v1/forward-bindings/{id}/status", get(forwards::status))
        .route("/v1/apps", get(apps::list).post(apps::create))
        .route("/v1/apps/executable-check", get(apps::executable_check))
        .route(
            "/v1/apps/{id}",
            get(apps::get).put(apps::update).delete(apps::delete),
        )
        .route("/v1/apps/{id}/actions", post(apps::action))
        .route("/v1/apps/{id}/status", get(apps::status))
        .route("/v1/apps/{id}/processes", get(apps::processes))
        .route("/v1/apps/{id}/log", get(apps::log))
        .route("/v1/operations", get(operations::list))
        .route("/v1/operations/{id}", get(operations::get))
        .route("/v1/operations/by-key/{key}", get(operations::by_key))
        .route("/v1/secrets", get(operations::secrets))
        .route(
            "/v1/secrets/{secret}",
            axum::routing::delete(operations::delete_secret),
        )
        .route("/v1/ssh", get(ssh::status))
        .route("/v1/ssh/include", post(ssh::include))
        .route("/v1/ssh/overwrite", post(ssh::overwrite))
        .route("/v1/ssh/apply", post(ssh::apply))
        .route("/v1/ssh-hosts", get(ssh::list).post(ssh::create))
        .route(
            "/v1/ssh-hosts/{id}",
            get(ssh::get).put(ssh::update).delete(ssh::delete),
        )
        .route("/v1/ssh-hosts/{id}/test", post(ssh::test))
        .route("/v1/performance/summary", get(performance::summary))
        .route("/v1/performance/series", get(performance::series))
        .route("/v1/events", get(events::stream))
}

// -------------------------------------------------------------------------------------------
// Shared helpers
// -------------------------------------------------------------------------------------------

/// Parse a JSON body (content type checked) into `T` with public error messages.
///
/// # Errors
///
/// `UNSUPPORTED_MEDIA_TYPE` when the body is not `application/json`, `VALIDATION_FAILED`
/// when it does not deserialize into `T`.
pub fn parse_json<T: DeserializeOwned>(headers: &HeaderMap, body: &[u8]) -> HttpResult<T> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct.starts_with("application/json") {
        return Err(bad(
            ErrorCode::UnsupportedMediaType,
            tr!(
                "The request must be application/json",
                "請求必須是 application/json",
                "リクエストは application/json にしてください"
            ),
        ));
    }
    serde_json::from_slice(body).map_err(|e| {
        let detail: String = e.to_string().chars().take(200).collect();
        bad(
            ErrorCode::ValidationFailed,
            tr!(
                "A field is not in the expected format: {detail}",
                "欄位不符合格式：{detail}",
                "フィールドの形式が正しくありません：{detail}"
            ),
        )
    })
}

#[must_use]
pub fn wrong() -> HttpError {
    HttpError(vpn_ipc::control::wrong_reply())
}

/// # Errors
///
/// The manager's error, or an internal error when it answers out of contract.
pub async fn list_entities(link: &ManagerLink, kind: EntityKind) -> HttpResult<Vec<Entity>> {
    match link.call(Call::List(kind)).await? {
        Reply::Entities(v) => Ok(v),
        _ => Err(wrong()),
    }
}

/// # Errors
///
/// The manager's error, or an internal error when it answers out of contract.
pub async fn get_entity(link: &ManagerLink, kind: EntityKind, id: String) -> HttpResult<Entity> {
    match link.call(Call::Get(kind, id)).await? {
        Reply::Entity(e) => Ok(*e),
        _ => Err(wrong()),
    }
}

/// # Errors
///
/// The manager's error, or an internal error when it answers out of contract.
pub async fn create_entity(link: &ManagerLink, e: Entity) -> Result<Entity, ApiError> {
    match link.call(Call::Create(e)).await? {
        Reply::Entity(e) => Ok(*e),
        _ => Err(ApiError::internal()),
    }
}

/// # Errors
///
/// The manager's error, or an internal error when it answers out of contract.
pub async fn update_entity(link: &ManagerLink, e: Entity, rev: u64) -> Result<Entity, ApiError> {
    match link
        .call(Call::Update {
            entity: e,
            expected_revision: rev,
        })
        .await?
    {
        Reply::Entity(e) => Ok(*e),
        _ => Err(ApiError::internal()),
    }
}

#[must_use]
pub fn new_meta() -> EntityMeta {
    let now = Timestamp::now();
    EntityMeta {
        revision: 1,
        created_at: now,
        updated_at: now,
    }
}

/// Outcome of an idempotent mutation.
#[derive(Debug)]
pub enum Idem<T> {
    /// Ran now.
    Fresh { operation: Operation, value: T },
    /// Same key and request seen before: the stored operation, nothing re-run.
    Replayed(Operation),
}

impl<T> Idem<T> {
    pub const fn operation(&self) -> &Operation {
        match self {
            Self::Fresh { operation, .. } | Self::Replayed(operation) => operation,
        }
    }
}

/// Run `work` at most once per Idempotency-Key.
///
/// `work` returns the result refs to record and a
/// value for the fresh response. A replay of a failed operation returns its stored error; a
/// replay whose outcome is unknown says so instead of running again.
///
/// # Errors
///
/// `IDEMPOTENCY_KEY_REQUIRED` or `INVALID_REQUEST` for a missing or malformed key, and
/// otherwise as for [`run_once`].
#[expect(
    clippy::too_many_arguments,
    reason = "the request's parts that make up its fingerprint, as every mutating handler has them"
)]
pub async fn idempotent<T, F, Fut>(
    link: &ManagerLink,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    if_match: Option<u64>,
    body: &[u8],
    kind: &str,
    target: Option<String>,
    work: F,
) -> HttpResult<Idem<T>>
where
    F: FnOnce(OperationId) -> Fut,
    Fut: Future<Output = Result<(Vec<String>, T), ApiError>>,
{
    let key = idempotency_key(headers)?;
    let fp = fingerprint(method, path, if_match, body);
    run_once(link, key, fp, kind, target, work).await
}

/// [`idempotent`] with a caller-supplied fingerprint (keyed fingerprints for secret bodies).
///
/// # Errors
///
/// The manager's error when the operation cannot be begun or finished, a conflict for a key
/// reused with another request, the stored error of a replayed failure, `OUTCOME_UNKNOWN` for a
/// replay whose outcome is unknown, and the error `work` returns.
pub async fn run_once<T, F, Fut>(
    link: &ManagerLink,
    key: String,
    fp: String,
    kind: &str,
    target: Option<String>,
    work: F,
) -> HttpResult<Idem<T>>
where
    F: FnOnce(OperationId) -> Fut,
    Fut: Future<Output = Result<(Vec<String>, T), ApiError>>,
{
    let Reply::Begin {
        operation,
        existing,
    } = link
        .call(Call::BeginOperation {
            kind: kind.into(),
            target_id: target,
            idempotency_key: Some(key),
            fingerprint: Some(fp),
        })
        .await?
    else {
        return Err(wrong());
    };
    if existing {
        return match operation.status {
            OperationStatus::Failed => Err(HttpError(
                operation
                    .error
                    .clone()
                    .unwrap_or_else(ApiError::internal)
                    .with_operation(operation.id),
            )),
            OperationStatus::Accepted | OperationStatus::Running | OperationStatus::Unknown => {
                Err(HttpError(
                    ApiError::new(
                        ErrorCode::OutcomeUnknown,
                        tr!(
                            "The same request is still in progress or its outcome is unknown; look up the operation instead of sending it again",
                            "相同的請求仍在處理或結果未知；請查詢 operation，不要重送",
                            "同じリクエストがまだ処理中か、結果が不明です。再送せずに operation を確認してください"
                        ),
                    )
                    .with_operation(operation.id),
                ))
            }
            _ => Ok(Idem::Replayed(operation)),
        };
    }
    let id = operation.id;
    match work(id).await {
        Ok((refs, value)) => {
            let operation = finish(link, operation, Ok(refs)).await;
            Ok(Idem::Fresh { operation, value })
        }
        Err(e) => {
            finish(link, operation, Err(&e)).await;
            Err(HttpError(e.with_operation(id)))
        }
    }
}

/// Record how an operation ended (best effort) and return it as recorded. A failure whose
/// effect may have happened anyway (no answer in time, connection lost after sending) is
/// `unknown`, never `failed`.
pub async fn finish(
    link: &ManagerLink,
    mut operation: Operation,
    outcome: Result<Vec<String>, &ApiError>,
) -> Operation {
    let (status, error, refs) = match outcome {
        Ok(refs) => (OperationStatus::Succeeded, None, refs),
        Err(e) if matches!(e.code, ErrorCode::Timeout | ErrorCode::OutcomeUnknown) => {
            (OperationStatus::Unknown, Some(e.clone()), Vec::new())
        }
        Err(e) => (OperationStatus::Failed, Some(e.clone()), Vec::new()),
    };
    if let Err(e) = link
        .call(Call::FinishOperation {
            id: operation.id,
            status,
            error: error.clone(),
            result_refs: refs.clone(),
        })
        .await
    {
        tracing::warn!(operation = %operation.id, error = %e, "operation outcome not recorded");
    }
    operation.status = status;
    operation.error = error;
    operation.result_refs = refs;
    operation.updated_at = Timestamp::now();
    operation
}

pub type Body = Bytes;
