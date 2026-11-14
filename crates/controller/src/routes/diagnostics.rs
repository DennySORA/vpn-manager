//! `GET /v1/system/diagnostics` (versions, programs, Store health, owned resources, checks).

use axum::Json;
use axum::extract::State;
use vpn_domain::DiagnosticReport;

use super::AppState;

pub async fn diagnostics(State(state): State<AppState>) -> Json<DiagnosticReport> {
    Json(crate::diagnostics::report(&state.link).await)
}
