//! Provider accounts, their devices and servers, connections built from them, and the global
//! Provider egress. All provider traffic goes through the egress route (see `crate::provider`).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use vpn_domain::{
    ApiError, EgressMode, ErrorCode, FieldError, ForwardedPort, ForwardedPortDdns,
    ForwardedPortInput, ForwardedPortSearch, ForwardedPortTest, ForwardedPortUpdate,
    ForwardedPorts, InstanceId, ProfileId, ProviderAccount, ProviderAccountId,
    ProviderAccountInput, ProviderConnectInput, ProviderConnectResult, ProviderDevice,
    ProviderEgressInput, ProviderEgressStatus, ProviderIpCheck, ProviderRebootstrapInput,
    ProviderServer, ProviderServerChangeInput, tr,
};
use vpn_ipc::control::{Call, Entity, EntityKind, Reply};

use super::{
    AppState, Body, Idem, get_entity, idempotent, list_entities, parse_json, run_once, wrong,
};
use crate::egress;
use crate::http::{HttpError, HttpResult, bad, idempotency_key, if_match, with_etag};

fn as_account(e: Entity) -> HttpResult<ProviderAccount> {
    match e {
        Entity::ProviderAccount(a) => Ok(a),
        _ => Err(wrong()),
    }
}

async fn account(state: &AppState, id: ProviderAccountId) -> HttpResult<ProviderAccount> {
    as_account(get_entity(&state.link, EntityKind::ProviderAccount, id.to_string()).await?)
}

// -------------------------------------------------------------------------------------------
// Egress
// -------------------------------------------------------------------------------------------

pub async fn egress(State(state): State<AppState>) -> HttpResult<Json<ProviderEgressStatus>> {
    Ok(Json(state.providers.status(&state.link).await?))
}

/// `PUT /v1/provider-egress` (If-Match): choose the egress Instance or turn egress off.
pub async fn put_egress(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Json<ProviderEgressStatus>> {
    let rev = if_match(&headers)?;
    let input: ProviderEgressInput = parse_json(&headers, &body)?;
    if input.desired_mode == EgressMode::Disabled && input.selected_instance_id.is_some() {
        return Err(bad(
            ErrorCode::ValidationFailed,
            tr!(
                "A connection cannot be chosen while the egress is being disabled",
                "停用出口時不能同時選擇連線",
                "出口を無効にするときは接続を選べません"
            ),
        ));
    }
    let link = state.link.clone();
    idempotent(
        &state.link,
        &headers,
        "PUT",
        "/v1/provider-egress",
        Some(rev),
        &body,
        "provider_egress.update",
        None,
        |_| async move {
            link.call(Call::PutProviderEgress {
                desired_mode: input.desired_mode,
                selected_instance_id: input.selected_instance_id,
                expected_revision: rev,
            })
            .await?;
            Ok((Vec::new(), ()))
        },
    )
    .await?;
    Ok(Json(state.providers.status(&state.link).await?))
}

/// `POST /v1/provider-egress/bootstrap`: open the one-time direct bootstrap (10 minutes).
pub async fn bootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Json<ProviderEgressStatus>> {
    let link = state.link.clone();
    idempotent(
        &state.link,
        &headers,
        "POST",
        "/v1/provider-egress/bootstrap",
        None,
        &body,
        "provider_egress.bootstrap",
        None,
        |op| async move {
            link.call(Call::BootstrapGrant {
                operation: Some(op),
            })
            .await?;
            Ok((Vec::new(), ()))
        },
    )
    .await?;
    Ok(Json(state.providers.status(&state.link).await?))
}

/// `DELETE /v1/provider-egress/bootstrap`: close the grant now.
pub async fn end_bootstrap(
    State(state): State<AppState>,
) -> HttpResult<Json<ProviderEgressStatus>> {
    state.link.call(Call::BootstrapRevoke).await?;
    Ok(Json(state.providers.status(&state.link).await?))
}

/// `POST /v1/provider-egress/check`: check the exit of the egress route now. Read-only. Part of
/// building an egress: a direct grant carries it.
pub async fn check_egress(State(state): State<AppState>) -> HttpResult<Json<ProviderIpCheck>> {
    Ok(Json(
        egress::recovery(state.providers.check_egress(&state.link)).await?,
    ))
}

/// `POST /v1/provider-egress/rebootstrap` (If-Match: the egress revision): a manual, one-time,
/// ten-minute direct exception to build a new egress after the selected one became unusable for
/// good. Refused with `REBOOTSTRAP_NOT_ELIGIBLE` and the reason whenever there is another way out;
/// `confirm_direct` must be `true`.
pub async fn rebootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Json<ProviderEgressStatus>> {
    let rev = if_match(&headers)?;
    let input: ProviderRebootstrapInput = parse_json(&headers, &body)?;
    if !input.confirm_direct {
        return Err(HttpError(
            ApiError::new(
                ErrorCode::ValidationFailed,
                tr!(
                    "A direct reconnection sends provider requests through this computer's ordinary network (not through the VPN); it needs explicit confirmation",
                    "重新直連會讓供應商請求經這台電腦的一般網路（不經 VPN）送出；需要明確確認",
                    "再度の直接接続では、プロバイダーへのリクエストがこのコンピューターの通常のネットワーク（VPN 経由ではない）を通って送信されます。明示的な確認が必要です"
                ),
            )
            .with_fields(vec![FieldError {
                path: "/confirm_direct".into(),
                code: "CONFIRMATION_REQUIRED".into(),
                message: tr!(
                    "Confirm that provider requests will leave through the ordinary network",
                    "需要確認供應商請求會經一般網路送出",
                    "プロバイダーへのリクエストが通常のネットワークを通って送信されることを確認してください"
                ),
            }]),
        ));
    }
    let link = state.link.clone();
    idempotent(
        &state.link,
        &headers,
        "POST",
        "/v1/provider-egress/rebootstrap",
        Some(rev),
        &body,
        "provider_egress.rebootstrap",
        None,
        |op| async move {
            link.call(Call::Rebootstrap {
                expected_revision: rev,
                operation: Some(op),
            })
            .await?;
            Ok((Vec::new(), ()))
        },
    )
    .await?;
    Ok(Json(state.providers.status(&state.link).await?))
}

/// `DELETE /v1/provider-egress/rebootstrap`: cancel the active rebootstrap now. Its grant closes
/// (every direct stream is cut) and a connection it built is not made the egress.
pub async fn cancel_rebootstrap(
    State(state): State<AppState>,
) -> HttpResult<Json<ProviderEgressStatus>> {
    state.link.call(Call::RebootstrapCancel).await?;
    Ok(Json(state.providers.status(&state.link).await?))
}

/// `POST /v1/instances/{id}/ip-check`: the exit of one running Instance, through its own tunnel
/// (IPv4, and IPv6 on its own when the connection has an IPv6 address; both recorded as gates).
pub async fn check_instance(
    State(state): State<AppState>,
    Path(id): Path<InstanceId>,
) -> HttpResult<Json<ProviderIpCheck>> {
    // Unknown Instances are told apart from ones that do not run.
    get_entity(&state.link, EntityKind::Instance, id.to_string()).await?;
    Ok(Json(state.providers.check_instance(&state.link, id).await?))
}

// -------------------------------------------------------------------------------------------
// Accounts
// -------------------------------------------------------------------------------------------

pub async fn list(State(state): State<AppState>) -> HttpResult<Json<Vec<ProviderAccount>>> {
    let v = list_entities(&state.link, EntityKind::ProviderAccount).await?;
    Ok(Json(
        v.into_iter().filter_map(|e| as_account(e).ok()).collect(),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<ProviderAccountId>,
) -> HttpResult<Response> {
    let a = account(&state, id).await?;
    Ok(with_etag(StatusCode::OK, a.meta.revision, &a))
}

/// `POST /v1/provider-accounts`: the credential is verified with the provider (over the egress
/// route), then kept only in the vault. Keyed fingerprint: the body carries a secret.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let input: ProviderAccountInput = parse_json(&headers, &body)?;
    let key = idempotency_key(&headers)?;
    let Reply::Fingerprint(fp) = state
        .link
        .call(Call::KeyedFingerprint(body.to_vec()))
        .await?
    else {
        return Err(wrong());
    };
    let (link, providers) = (state.link.clone(), state.providers.clone());
    let out = run_once(
        &state.link,
        key,
        fp,
        "provider_account.create",
        None,
        |_| async move {
            let a = Box::pin(egress::recovery(providers.add_account(&link, &input))).await?;
            Ok((vec![a.id.to_string()], a))
        },
    )
    .await?;
    let a = match out {
        Idem::Fresh { value, .. } => value,
        Idem::Replayed(op) => {
            let id = op.result_refs.first().cloned().ok_or_else(wrong)?;
            as_account(get_entity(&state.link, EntityKind::ProviderAccount, id).await?)?
        }
    };
    Ok(with_etag(StatusCode::CREATED, a.meta.revision, &a))
}

/// `DELETE /v1/provider-accounts/{id}` (If-Match): forget the account and its credential here.
/// Nothing is deleted at the provider; profiles generated from it keep it from deletion.
pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<ProviderAccountId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let rev = if_match(&headers)?;
    let a = account(&state, id).await?;
    let (link, providers) = (state.link.clone(), state.providers.clone());
    let path = format!("/v1/provider-accounts/{id}");
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        Some(rev),
        &body,
        "provider_account.delete",
        Some(id.to_string()),
        |_| async move {
            link.call(Call::Delete {
                kind: EntityKind::ProviderAccount,
                id: id.to_string(),
                expected_revision: rev,
            })
            .await?;
            let _ = link.call(Call::DeleteSecret(a.credential_ref)).await;
            providers.forget(id);
            Ok((vec![id.to_string()], ()))
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/provider-accounts/{id}/refresh`: re-read the account from the provider.
pub async fn refresh(
    State(state): State<AppState>,
    Path(id): Path<ProviderAccountId>,
) -> HttpResult<Json<ProviderAccount>> {
    let a = account(&state, id).await?;
    Ok(Json(
        Box::pin(egress::recovery(state.providers.refresh(&state.link, a))).await?,
    ))
}

pub async fn devices(
    State(state): State<AppState>,
    Path(id): Path<ProviderAccountId>,
) -> HttpResult<Json<Vec<ProviderDevice>>> {
    let a = account(&state, id).await?;
    Ok(Json(
        Box::pin(egress::recovery(state.providers.devices(&state.link, &a))).await?,
    ))
}

#[derive(serde::Deserialize)]
pub struct RevokeQuery {
    /// The user confirmed revoking a device whose key is not on this computer.
    #[serde(default)]
    unowned: bool,
}

/// `DELETE /v1/provider-accounts/{id}/devices/{device}`: revoke a device. One whose key is not
/// here needs `?unowned=true` (it may be in use elsewhere).
pub async fn revoke_device(
    State(state): State<AppState>,
    Path((id, device)): Path<(ProviderAccountId, String)>,
    axum::extract::Query(q): axum::extract::Query<RevokeQuery>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let a = account(&state, id).await?;
    let (link, providers) = (state.link.clone(), state.providers.clone());
    let path = format!(
        "/v1/provider-accounts/{id}/devices/{device}?unowned={}",
        q.unowned
    );
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        None,
        &body,
        "provider.revoke_device",
        Some(id.to_string()),
        |_| async move {
            providers
                .revoke_device(&link, &a, &device, q.unowned)
                .await?;
            Ok((Vec::new(), ()))
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// -------------------------------------------------------------------------------------------
// Forwarded ports (AirVPN's website)
// -------------------------------------------------------------------------------------------

/// `GET /v1/provider-accounts/{id}/forwarded-ports`: the account's forwarded ports, read from
/// `AirVPN`'s website over the egress route. Other providers: `UNSUPPORTED_CAPABILITY`.
pub async fn forwarded_ports(
    State(state): State<AppState>,
    Path(id): Path<ProviderAccountId>,
) -> HttpResult<Json<ForwardedPorts>> {
    let a = account(&state, id).await?;
    crate::provider::reservations(&a)?;
    Ok(Json(
        state.providers.forwarded_ports(&state.link, &a).await?,
    ))
}

/// `POST /v1/provider-accounts/{id}/forwarded-ports` (Idempotency-Key): reserve `{"port": n}`
/// (2049–65535), or one `AirVPN` picks with `{}`. 201 with the port. A replay answers with the
/// port the first request reserved, read from a fresh list.
pub async fn reserve_port(
    State(state): State<AppState>,
    Path(id): Path<ProviderAccountId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let input: ForwardedPortInput = parse_json(&headers, &body)?;
    let a = account(&state, id).await?;
    crate::provider::reservations(&a)?;
    // Refused before an operation is recorded or AirVPN is asked.
    crate::provider::reservable(input.port)?;
    let (link, providers, owner) = (state.link.clone(), state.providers.clone(), a.clone());
    let path = format!("/v1/provider-accounts/{id}/forwarded-ports");
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        &path,
        None,
        &body,
        "provider.reserve_port",
        Some(id.to_string()),
        |_| async move {
            let p = providers.reserve_port(&link, &owner, input.port).await?;
            Ok((vec![p.port.to_string()], p))
        },
    )
    .await?;
    let port = match out {
        Idem::Fresh { value, .. } => value,
        Idem::Replayed(op) => {
            let reserved: u16 = op
                .result_refs
                .first()
                .and_then(|s| s.parse().ok())
                .ok_or_else(wrong)?;
            listed(&state, &a, reserved, Did::Reserve).await?
        }
    };
    Ok((StatusCode::CREATED, Json(port)).into_response())
}

/// What a request did to a forwarded port (保留, 修改): the replay of the request says it.
#[derive(Debug, Clone, Copy)]
enum Did {
    Reserve,
    Update,
}

/// The account's forwarded port `port` as a fresh list has it: the answer to a replay of the
/// request that `did` it.
async fn listed(
    state: &AppState,
    a: &ProviderAccount,
    port: u16,
    did: Did,
) -> HttpResult<ForwardedPort> {
    state
        .providers
        .forwarded_ports(&state.link, a)
        .await?
        .ports
        .into_iter()
        .find(|p| p.port == port)
        .ok_or_else(|| {
            let message = match did {
                Did::Reserve => tr!(
                    "Inbound port {port}, which this request reserved earlier, is no longer in the account",
                    "這個請求先前保留的連入埠 {port} 已不在帳號中",
                    "このリクエストが以前に予約した着信ポート {port} は、もうアカウントにありません"
                ),
                Did::Update => tr!(
                    "Inbound port {port}, which this request changed earlier, is no longer in the account",
                    "這個請求先前修改的連入埠 {port} 已不在帳號中",
                    "このリクエストが以前に変更した着信ポート {port} は、もうアカウントにありません"
                ),
            };
            bad(ErrorCode::NotFound, message)
        })
}

/// The `{port}` of a path: 1–65535.
fn port_param(port: &str) -> HttpResult<u16> {
    port.parse().ok().filter(|p| *p > 0).ok_or_else(|| {
        bad(
            ErrorCode::ValidationFailed,
            tr!(
                "The inbound port must be a number from 1 to 65535",
                "連入埠必須是 1–65535 的數字",
                "着信ポートは 1–65535 の数字にしてください"
            ),
        )
    })
}

/// `PATCH /v1/provider-accounts/{id}/forwarded-ports/{port}` (Idempotency-Key): change some of
/// the port's settings on `AirVPN`'s website (`ForwardedPortUpdate`; a field left out stays). Only
/// the settings that differ are sent, one request each, then the port is read back: 200 with the
/// port as read back. A setting `AirVPN` refused or did not keep fails the request with
/// `PROVIDER_REJECTED`, a field error for each such setting, and a message naming what was
/// saved. A replay answers with the port as a fresh list has it.
pub async fn update_port(
    State(state): State<AppState>,
    Path((id, port)): Path<(ProviderAccountId, String)>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Json<ForwardedPort>> {
    let port = port_param(&port)?;
    let input: ForwardedPortUpdate = parse_json(&headers, &body)?;
    let a = account(&state, id).await?;
    crate::provider::reservations(&a)?;
    // Refused before an operation is recorded or AirVPN is asked.
    crate::provider::changeable(&input)?;
    let (link, providers, owner) = (state.link.clone(), state.providers.clone(), a.clone());
    let path = format!("/v1/provider-accounts/{id}/forwarded-ports/{port}");
    let out = idempotent(
        &state.link,
        &headers,
        "PATCH",
        &path,
        None,
        &body,
        "provider.update_port",
        Some(id.to_string()),
        |_| async move {
            let p = providers.update_port(&link, &owner, port, &input).await?;
            Ok((vec![port.to_string()], p))
        },
    )
    .await?;
    Ok(Json(match out {
        Idem::Fresh { value, .. } => value,
        Idem::Replayed(_) => listed(&state, &a, port, Did::Update).await?,
    }))
}

/// `POST /v1/provider-accounts/{id}/forwarded-ports/{port}/test`: `AirVPN` tests the port from the
/// server of every connected session of the account that uses it (TCP only, as its website
/// does), and says what it found per session. Changes nothing: no Idempotency-Key. No session:
/// an empty list.
pub async fn test_port(
    State(state): State<AppState>,
    Path((id, port)): Path<(ProviderAccountId, String)>,
) -> HttpResult<Json<ForwardedPortTest>> {
    let port = port_param(&port)?;
    let a = account(&state, id).await?;
    Ok(Json(
        state.providers.test_port(&state.link, &a, port).await?,
    ))
}

/// `GET /v1/provider-accounts/{id}/forwarded-ports/ddns`: `AirVPN`'s DDNS check — each DDNS name of
/// the account's ports, how many connected sessions it leads to, and the addresses it should
/// resolve to.
pub async fn ddns(
    State(state): State<AppState>,
    Path(id): Path<ProviderAccountId>,
) -> HttpResult<Json<ForwardedPortDdns>> {
    let a = account(&state, id).await?;
    Ok(Json(state.providers.ddns(&state.link, &a).await?))
}

#[derive(serde::Deserialize)]
pub struct FreeQuery {
    count: Option<String>,
}

/// `GET /v1/provider-accounts/{id}/forwarded-ports/free?count=n`: `AirVPN`'s search for `n` (2–10)
/// consecutive ports nobody holds, in its own words. Nothing is reserved.
pub async fn free_ports(
    State(state): State<AppState>,
    Path(id): Path<ProviderAccountId>,
    axum::extract::Query(q): axum::extract::Query<FreeQuery>,
) -> HttpResult<Json<ForwardedPortSearch>> {
    let count: u8 = q
        .count
        .as_deref()
        .and_then(|c| c.trim().parse().ok())
        .ok_or_else(|| {
            bad(
                ErrorCode::ValidationFailed,
                tr!(
                    "count must be a number from 2 to 10",
                    "count 必須是 2–10 的數字",
                    "count は 2–10 の数字にしてください"
                ),
            )
        })?;
    let a = account(&state, id).await?;
    Ok(Json(
        state.providers.free_ports(&state.link, &a, count).await?,
    ))
}

/// `DELETE /v1/provider-accounts/{id}/forwarded-ports/{port}` (Idempotency-Key): delete one of
/// the account's forwarded ports at `AirVPN`. Forwards here that use it are not changed.
pub async fn delete_port(
    State(state): State<AppState>,
    Path((id, port)): Path<(ProviderAccountId, String)>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let port = port_param(&port)?;
    let a = account(&state, id).await?;
    crate::provider::reservations(&a)?;
    let (link, providers) = (state.link.clone(), state.providers.clone());
    let path = format!("/v1/provider-accounts/{id}/forwarded-ports/{port}");
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        None,
        &body,
        "provider.delete_port",
        Some(id.to_string()),
        |_| async move {
            providers.delete_port(&link, &a, port).await?;
            Ok((vec![port.to_string()], ()))
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn servers(
    State(state): State<AppState>,
    Path(id): Path<ProviderAccountId>,
) -> HttpResult<Json<Vec<ProviderServer>>> {
    let a = account(&state, id).await?;
    Ok(Json(
        Box::pin(egress::recovery(state.providers.servers(&state.link, &a))).await?,
    ))
}

/// `POST /v1/provider-accounts/{id}/profiles/{profile}/server` (If-Match): point a profile built
/// from this account at another server, keeping its device and key.
pub async fn change_server(
    State(state): State<AppState>,
    Path((id, profile_id)): Path<(ProviderAccountId, ProfileId)>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let rev = if_match(&headers)?;
    let input: ProviderServerChangeInput = parse_json(&headers, &body)?;
    let a = account(&state, id).await?;
    let Entity::Profile(current) =
        get_entity(&state.link, EntityKind::Profile, profile_id.to_string()).await?
    else {
        return Err(wrong());
    };
    if current.meta.revision != rev {
        return Err(bad(
            ErrorCode::RevisionConflict,
            tr!(
                "The data was changed by another operation; reload and try again",
                "資料已被其他操作更新，請重新載入後再試",
                "データが別の操作で更新されました。再読み込みしてからもう一度お試しください"
            ),
        ));
    }
    let (link, providers) = (state.link.clone(), state.providers.clone());
    let path = format!("/v1/provider-accounts/{id}/profiles/{profile_id}/server");
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        &path,
        Some(rev),
        &body,
        "provider.change_server",
        Some(profile_id.to_string()),
        |_| async move {
            // Only the connection a run of the direct exception built may be fixed over it.
            let work = Box::pin(providers.change_server(&link, &a, current, &input));
            let changed = if egress::is_run_child(&link, profile_id).await {
                egress::recovery(work).await?
            } else {
                work.await?
            };
            let e = super::update_entity(&link, Entity::Profile(changed), rev).await?;
            Ok((vec![profile_id.to_string()], e))
        },
    )
    .await?;
    let profile = match out {
        Idem::Fresh { value, .. } => value,
        Idem::Replayed(_) => {
            get_entity(&state.link, EntityKind::Profile, profile_id.to_string()).await?
        }
    };
    match profile {
        Entity::Profile(p) => Ok(with_etag(StatusCode::OK, p.meta.revision, &p)),
        _ => Err(wrong()),
    }
}

/// `POST /v1/provider-accounts/{id}/connections`: build a profile and an Instance from one
/// device and one server, and start it.
pub async fn connect(
    State(state): State<AppState>,
    Path(id): Path<ProviderAccountId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let input: ProviderConnectInput = parse_json(&headers, &body)?;
    let a = account(&state, id).await?;
    let (link, providers) = (state.link.clone(), state.providers.clone());
    let path = format!("/v1/provider-accounts/{id}/connections");
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        &path,
        None,
        &body,
        "provider.connect",
        Some(id.to_string()),
        |op| async move {
            let r = Box::pin(egress::recovery(providers.connect(&link, &a, &input, op))).await?;
            let mut refs = vec![r.profile_id.to_string(), r.instance_id.to_string()];
            refs.extend(r.gateway_id.map(|g| g.to_string()));
            Ok((refs, r))
        },
    )
    .await?;
    match out {
        Idem::Fresh { value, .. } => Ok(with_etag(StatusCode::CREATED, 0, &value)),
        Idem::Replayed(op) => {
            let profile_id = op
                .result_refs
                .first()
                .and_then(|s| s.parse().ok())
                .ok_or_else(wrong)?;
            let instance_id = op
                .result_refs
                .get(1)
                .and_then(|s| s.parse().ok())
                .ok_or_else(wrong)?;
            let gateway_id = op.result_refs.get(2).and_then(|s| s.parse().ok());
            Ok(with_etag(
                StatusCode::CREATED,
                0,
                &ProviderConnectResult {
                    profile_id,
                    instance_id,
                    gateway_id,
                    device_id: String::new(),
                    device: None,
                    becomes_egress: false,
                    reused: false,
                },
            ))
        }
    }
}
