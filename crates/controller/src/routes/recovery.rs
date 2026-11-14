//! Recovery: `GET /v1/recovery` lists what the manager owns and what a crash left behind;
//! `POST /v1/recovery/reconcile` cleans what is provably ours and stale (never starts anything).

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use vpn_domain::{
    ApiError, ErrorCode, ReconcileInput, ReconcileOutcome, ReconcileResult, RecoveryReport,
    Timestamp, tr,
};
use vpn_ipc::control::{Call, Reply};

use super::{AppState, Body, Idem, idempotent, parse_json, wrong};
use crate::http::{HttpResult, bad};
use crate::link::ManagerLink;

/// Most item ids one reconcile may confirm.
const ITEMS_MAX: usize = 500;

async fn inspection(link: &ManagerLink) -> HttpResult<RecoveryReport> {
    match link.call(Call::RecoveryInspect).await? {
        Reply::Recovery(r) => Ok(*r),
        _ => Err(wrong()),
    }
}

pub async fn inspect(State(state): State<AppState>) -> HttpResult<Json<RecoveryReport>> {
    Ok(Json(inspection(&state.link).await?))
}

/// `items`: the ids the user confirmed (only those still found and cleanable are cleaned);
/// omitted, everything cleanable now.
pub async fn reconcile(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Json<ReconcileResult>> {
    let input: ReconcileInput = if body.is_empty() {
        ReconcileInput::default()
    } else {
        parse_json(&headers, &body)?
    };
    if let Some(items) = &input.items {
        let shape_ok = items.len() <= ITEMS_MAX
            && items
                .iter()
                .all(|i| i.len() == 16 && i.bytes().all(|b| b.is_ascii_hexdigit()));
        if !shape_ok {
            return Err(bad(
                ErrorCode::ValidationFailed,
                tr!(
                    "items must be the ids of at most {ITEMS_MAX} check results",
                    "items 必須是最多 {ITEMS_MAX} 個檢查結果的 id",
                    "items には最大 {ITEMS_MAX} 件のチェック結果の id を指定してください"
                ),
            ));
        }
    }
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        "/v1/recovery/reconcile",
        None,
        &body,
        "recovery.reconcile",
        None,
        |_| async move {
            match link
                .call(Call::RecoveryReconcile { only: input.items })
                .await?
            {
                Reply::Reconciled(r) => {
                    let refs = r
                        .actions
                        .iter()
                        .filter(|a| a.outcome == ReconcileOutcome::Done)
                        .map(|a| a.item_id.clone())
                        .collect();
                    Ok((refs, *r))
                }
                _ => Err(ApiError::internal()),
            }
        },
    )
    .await?;
    match out {
        Idem::Fresh {
            operation,
            mut value,
        } => {
            value.operation_id = Some(operation.id);
            Ok(Json(value))
        }
        // Done before: what it did is in the operation; what is left is looked at now.
        Idem::Replayed(operation) => Ok(Json(ReconcileResult {
            operation_id: Some(operation.id),
            observed_at: Timestamp::now(),
            actions: Vec::new(),
            remaining: inspection(&state.link).await?.items,
        })),
    }
}
