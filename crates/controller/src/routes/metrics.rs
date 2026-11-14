//! Persisted metrics.
//!
//! - `GET /v1/metrics/series?range=15m|1h|6h|24h|7d|30d&scope=all|instance:<id>|gateway:<id>`
//!   (defaults `1h`, `all`): aligned columns, gaps with reasons and totals for the range. The
//!   manager picks the point spacing so an answer stays far below 10,000 points.
//! - `GET /v1/instances/{id}/metrics?range=…`: the same for `scope=instance:<id>`.
//! - `GET /v1/metrics/status`: retention, space, oldest data, gaps of the last 24 hours and the
//!   collector's state.
//!
//! A bad range or scope is refused here and never reaches the manager.

use axum::Json;
use axum::extract::{Path, Query, State};
use vpn_domain::{
    ErrorCode, InstanceId, MetricsRange, MetricsScope, MetricsSeries, MetricsStatus,
    UnknownMetricsRange, UnknownMetricsScope,
};
use vpn_ipc::control::{Call, Reply};

use super::{AppState, wrong};
use crate::http::{HttpResult, bad};

#[derive(serde::Deserialize)]
pub struct SeriesQuery {
    range: Option<String>,
    scope: Option<String>,
}

fn range_of(q: Option<&str>) -> HttpResult<MetricsRange> {
    match q.map(str::trim) {
        None | Some("") => Ok(MetricsRange::Last1h),
        Some(r) => r
            .parse()
            .map_err(|e: UnknownMetricsRange| bad(ErrorCode::InvalidRequest, e)),
    }
}

async fn query(
    state: &AppState,
    scope: MetricsScope,
    range: MetricsRange,
) -> HttpResult<Json<MetricsSeries>> {
    match state
        .link
        .call(Call::MetricsSeries { scope, range })
        .await?
    {
        Reply::MetricsSeries(series) => Ok(Json(*series)),
        _ => Err(wrong()),
    }
}

pub async fn series(
    State(state): State<AppState>,
    Query(q): Query<SeriesQuery>,
) -> HttpResult<Json<MetricsSeries>> {
    let range = range_of(q.range.as_deref())?;
    let scope = match q.scope.as_deref().map(str::trim) {
        None | Some("") => MetricsScope::All,
        Some(s) => s
            .parse()
            .map_err(|e: UnknownMetricsScope| bad(ErrorCode::InvalidRequest, e))?,
    };
    query(&state, scope, range).await
}

pub async fn instance(
    State(state): State<AppState>,
    Path(id): Path<InstanceId>,
    Query(q): Query<SeriesQuery>,
) -> HttpResult<Json<MetricsSeries>> {
    let range = range_of(q.range.as_deref())?;
    query(&state, MetricsScope::Instance(id), range).await
}

pub async fn status(State(state): State<AppState>) -> HttpResult<Json<MetricsStatus>> {
    match state.link.call(Call::MetricsStatus).await? {
        Reply::MetricsStatus(status) => Ok(Json(*status)),
        _ => Err(wrong()),
    }
}
