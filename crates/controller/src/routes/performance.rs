//! Performance Manager API (`/v1/performance/*`): the passive analysis the manager owns; these
//! handlers validate and translate. Neither generates traffic.
//!
//! - `GET /v1/performance/summary`
//! - `GET /v1/performance/series?scope=system|instance:<id>|gateway:<id>&range=15m|1h|6h|24h|7d|30d`
//!   (also `scope=instance&entity_id=<id>`).

use axum::Json;
use axum::extract::{Query, State};
use vpn_domain::{
    ApiError, ErrorCode, GatewayId, InstanceId, MetricsRange, PerformanceOverview,
    PerformanceScope, PerformanceSeriesSet, UnknownMetricsRange, tr,
};
use vpn_ipc::control::{Call, PerfCall, PerfReply, Reply};

use super::{AppState, wrong};
use crate::http::{HttpResult, bad};
use crate::link::ManagerLink;

async fn call(link: &ManagerLink, c: PerfCall) -> Result<PerfReply, ApiError> {
    match link.call(Call::Performance(c)).await? {
        Reply::Performance(r) => Ok(*r),
        _ => Err(ApiError::internal()),
    }
}

pub async fn summary(State(state): State<AppState>) -> HttpResult<Json<PerformanceOverview>> {
    match call(&state.link, PerfCall::Summary).await? {
        PerfReply::Summary(s) => Ok(Json(s)),
        PerfReply::Series(_) => Err(wrong()),
    }
}

#[derive(serde::Deserialize)]
pub struct SeriesQuery {
    scope: Option<String>,
    entity_id: Option<String>,
    range: Option<String>,
}

/// `system`, `instance:<id>`, `gateway:<id>`, or a kind with `entity_id`.
fn parse_scope(scope: Option<&str>, entity: Option<&str>) -> HttpResult<PerformanceScope> {
    let raw = scope.map_or("system", str::trim);
    let (kind, inline) = match raw.split_once(':') {
        Some((k, id)) => (k, Some(id)),
        None => (raw, None),
    };
    let entity = inline.or(entity).map(str::trim).filter(|s| !s.is_empty());
    let bad_scope = || {
        bad(
            ErrorCode::InvalidRequest,
            tr!(
                "scope must be system, instance:<id> or gateway:<id>",
                "scope 必須是 system、instance:<id> 或 gateway:<id>",
                "scope は system、instance:<id>、gateway:<id> のいずれかにしてください"
            ),
        )
    };
    match kind {
        "system" if entity.is_none() => Ok(PerformanceScope::system()),
        "system" => Err(bad(
            ErrorCode::InvalidRequest,
            tr!(
                "The system scope takes no entity_id",
                "system 範圍不帶 entity_id",
                "system スコープには entity_id を指定しません"
            ),
        )),
        "instance" => {
            let id: InstanceId = entity.and_then(|s| s.parse().ok()).ok_or_else(|| {
                bad(
                    ErrorCode::InvalidRequest,
                    tr!(
                        "The instance scope needs a valid Instance id",
                        "instance 範圍需要有效的 Instance id",
                        "instance スコープには有効な Instance id が必要です"
                    ),
                )
            })?;
            Ok(PerformanceScope::instance(id))
        }
        "gateway" => {
            let id: GatewayId = entity.and_then(|s| s.parse().ok()).ok_or_else(|| {
                bad(
                    ErrorCode::InvalidRequest,
                    tr!(
                        "The gateway scope needs a valid Gateway id",
                        "gateway 範圍需要有效的代理埠 id",
                        "gateway スコープには有効なゲートウェイ id が必要です"
                    ),
                )
            })?;
            Ok(PerformanceScope::gateway(id))
        }
        _ => Err(bad_scope()),
    }
}

pub async fn series(
    State(state): State<AppState>,
    Query(q): Query<SeriesQuery>,
) -> HttpResult<Json<PerformanceSeriesSet>> {
    let scope = parse_scope(q.scope.as_deref(), q.entity_id.as_deref())?;
    let range = match q.range.as_deref().map(str::trim) {
        None | Some("") => MetricsRange::Last1h,
        Some(r) => r
            .parse()
            .map_err(|e: UnknownMetricsRange| bad(ErrorCode::InvalidRequest, e))?,
    };
    match call(&state.link, PerfCall::Series { scope, range }).await? {
        PerfReply::Series(s) => Ok(Json(s)),
        PerfReply::Summary(_) => Err(wrong()),
    }
}
