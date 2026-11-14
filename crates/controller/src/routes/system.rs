use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use vpn_domain::{
    ApiError, Capability, CapabilityState, ErrorCode, METRICS_QUOTA_MIB, METRICS_RETENTION_HOURS,
    MetricsRecordingState, Phase, Settings, SettingsInput, StoreHealth, SystemStatus, Timestamp,
    tr,
};
use vpn_ipc::control::{Call, Reply, SystemInfo};

use super::{AppState, Body, idempotent, parse_json, wrong};
use crate::http::{HttpResult, bad, if_match, with_etag};

pub async fn healthz() -> &'static str {
    "ok"
}

async fn system_info(state: &AppState) -> Result<SystemInfo, ApiError> {
    match state.link.call(Call::System).await? {
        Reply::System(s) => Ok(*s),
        _ => Err(ApiError::internal()),
    }
}

/// System overview. When the manager is unreachable the answer says so instead of guessing.
pub async fn status(State(state): State<AppState>) -> HttpResult<Json<SystemStatus>> {
    let info = system_info(&state).await.ok();
    let statuses = match state.link.call(Call::InstanceStatuses).await {
        Ok(Reply::Statuses(v)) => v,
        _ => Vec::new(),
    };
    let running = u32::try_from(
        statuses
            .iter()
            .filter(|s| matches!(s.phase, Phase::Ready | Phase::Degraded))
            .count(),
    )
    .unwrap_or(u32::MAX);
    Ok(Json(SystemStatus {
        version: vpn_ipc::identity::VERSION.into(),
        build_id: vpn_ipc::identity::build_id().into(),
        os: std::env::consts::OS.into(),
        controller_port: state.port,
        controller_listen: state.exposure.listen.to_string(),
        controller_allow_clients: state
            .exposure
            .allow_clients
            .iter()
            .map(ToString::to_string)
            .collect(),
        // What other hosts reach this one at (for the addresses shown; unknown: none listed).
        host_addresses: vpn_platform::netif::reachable_addresses()
            .unwrap_or_default()
            .iter()
            .map(ToString::to_string)
            .collect(),
        data_dir: state.data_dir.as_deref().map(Into::into),
        installation_id: info.as_ref().map(|i| i.installation_id),
        manager_connected: info.is_some(),
        store: StoreHealth {
            control_ok: info.is_some(),
            metrics_ok: info.as_ref().is_some_and(|i| {
                i.metrics_recording
                    .as_ref()
                    .is_none_or(|r| r.state != MetricsRecordingState::Failing)
            }),
            metrics_recording: info.as_ref().and_then(|i| i.metrics_recording.clone()),
            keystore: info
                .as_ref()
                .and_then(|i| i.capabilities.iter().find(|c| c.name == "secret_keystore"))
                .map_or(CapabilityState::Unverified, |c| c.state),
            sqlite_version: info.as_ref().map_or_default(|i| i.sqlite_version.clone()),
        },
        instances_running: running,
        instances_total: u32::try_from(statuses.len()).unwrap_or(u32::MAX),
        capabilities: info.map_or_default(|i| i.capabilities),
        clock_synchronized: vpn_platform::clock::synchronized(),
        // Last, as the answer leaves: the browser takes the server's time from it.
        observed_at: Timestamp::now(),
    }))
}

pub async fn capabilities(State(state): State<AppState>) -> HttpResult<Json<Vec<Capability>>> {
    Ok(Json(system_info(&state).await?.capabilities))
}

pub async fn get_settings(State(state): State<AppState>) -> HttpResult<Response> {
    match state.link.call(Call::Settings).await? {
        Reply::Settings(s) => Ok(with_etag(StatusCode::OK, s.revision, &s)),
        _ => Err(wrong()),
    }
}

pub async fn put_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let rev = if_match(&headers)?;
    let input: SettingsInput = parse_json(&headers, &body)?;
    if !METRICS_RETENTION_HOURS.contains(&input.metrics_retention_raw_hours) {
        return Err(bad(
            ErrorCode::ValidationFailed,
            tr!(
                "Raw metrics retention must be between 1 and 168 hours (7 days)",
                "原始指標保留時間必須介於 1 與 168 小時（7 天）",
                "生のメトリクスの保持期間は 1〜168 時間（7 日）の範囲で指定してください"
            ),
        ));
    }
    if !METRICS_QUOTA_MIB.contains(&input.metrics_quota_mib) {
        return Err(bad(
            ErrorCode::ValidationFailed,
            tr!(
                "The metrics space limit must be between 16 and 65536 MiB",
                "指標空間上限必須介於 16 與 65536 MiB",
                "メトリクスの容量上限は 16〜65536 MiB の範囲で指定してください"
            ),
        ));
    }
    let input = Settings {
        revision: rev,
        metrics_retention_raw_hours: input.metrics_retention_raw_hours,
        metrics_quota_mib: input.metrics_quota_mib,
    };
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        &headers,
        "PUT",
        "/v1/settings",
        Some(rev),
        &body,
        "settings.update",
        None,
        |_| async move {
            match link
                .call(Call::PutSettings {
                    settings: input,
                    expected_revision: rev,
                })
                .await?
            {
                Reply::Settings(s) => Ok((vec!["settings".into()], s)),
                _ => Err(ApiError::internal()),
            }
        },
    )
    .await?;
    let s = match out {
        super::Idem::Fresh { value, .. } => value,
        super::Idem::Replayed(_) => match state.link.call(Call::Settings).await? {
            Reply::Settings(s) => s,
            _ => return Err(wrong()),
        },
    };
    Ok(with_etag(StatusCode::OK, s.revision, &s).into_response())
}
