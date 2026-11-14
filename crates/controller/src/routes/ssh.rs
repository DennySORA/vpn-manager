//! SSH Manager API. Hosts are ordinary stored entities; the manager renders them into
//! `~/.ssh/vpn-manager.conf`. Cross-checks against the user's own `~/.ssh/config` (alias clashes,
//! overlay targets that cannot go through the VPN) run here so they come back as field errors.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use vpn_domain::validation::{check_ssh_host, ssh_vpn_unreachable};
use vpn_domain::{
    ApiError, EntityMeta, ErrorCode, FieldError, GatewayId, GatewayKind, SshActionResult, SshHost,
    SshHostId, SshHostInput, SshHostKind, SshStatus, SshTestResult, tr,
};
use vpn_ipc::control::{Call, Entity, EntityKind, Reply};

use super::{
    AppState, Body, Idem, create_entity, get_entity, idempotent, list_entities, new_meta,
    parse_json, update_entity, wrong,
};
use crate::http::{HttpError, HttpResult, bad, if_match, report_error, with_etag};
use crate::link::ManagerLink;

/// How long the connection test may take (CONNECT through the tunnel plus the SSH banner).
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

fn as_host(e: Entity) -> HttpResult<SshHost> {
    match e {
        Entity::SshHost(h) => Ok(h),
        _ => Err(wrong()),
    }
}

fn opt(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn build(id: SshHostId, meta: EntityMeta, i: SshHostInput) -> SshHost {
    SshHost {
        id,
        meta,
        kind: i.kind,
        alias: i.alias.trim().to_string(),
        host_name: opt(i.host_name),
        user: opt(i.user),
        port: i.port,
        identity_file: opt(i.identity_file),
        identities_only: i.identities_only,
        gateway_id: i.gateway_id,
        server_alive_interval: i.server_alive_interval,
    }
}

async fn ssh_status(link: &ManagerLink) -> HttpResult<SshStatus> {
    match link.call(Call::SshStatus).await? {
        Reply::SshStatus(s) => Ok(*s),
        _ => Err(wrong()),
    }
}

fn field(path: &str, code: &str, message: impl Into<vpn_domain::Text>) -> HttpError {
    let message = message.into();
    HttpError(
        ApiError::new(ErrorCode::ValidationFailed, message.clone()).with_fields(vec![FieldError {
            path: path.into(),
            code: code.into(),
            message,
        }]),
    )
}

async fn check(state: &AppState, h: &SshHost) -> HttpResult<()> {
    let report = check_ssh_host(h);
    if report.has_errors() {
        return Err(report_error(&report));
    }
    if let Some(g) = h.gateway_id {
        check_gateway(state, g).await?;
    }
    let others = list_entities(&state.link, EntityKind::SshHost).await?;
    if others
        .iter()
        .any(|e| matches!(e, Entity::SshHost(o) if o.id != h.id && o.alias == h.alias))
    {
        return Err(field(
            "/alias",
            "SSH_ALIAS_TAKEN",
            tr!(
                "VPN Manager already has a host with this name",
                "VPN Manager 已有同名的主機",
                "VPN Manager には同じ名前のホストがすでにあります"
            ),
        ));
    }
    let status = ssh_status(&state.link).await?;
    check_alias(h, &others, &status)
}

/// The host's Gateway `g` still exists and speaks SOCKS5.
async fn check_gateway(state: &AppState, g: GatewayId) -> HttpResult<()> {
    let gateways = list_entities(&state.link, EntityKind::Gateway).await?;
    match gateways.iter().find_map(|e| match e {
        Entity::Gateway(x) if x.id == g => Some(x),
        _ => None,
    }) {
        None => Err(field(
            "/gateway_id",
            "SSH_GATEWAY",
            tr!(
                "This Gateway no longer exists",
                "這個代理埠已不存在",
                "このゲートウェイはもう存在しません"
            ),
        )),
        // vpnctl speaks SOCKS5; an HTTP-only port would refuse every SSH connection.
        Some(x) if x.kind == GatewayKind::Http => Err(field(
            "/gateway_id",
            "SSH_GATEWAY_KIND",
            tr!(
                "An HTTP Gateway does not support SSH; choose a SOCKS5 or Mixed Gateway",
                "HTTP 代理埠不支援 SSH；請選擇 SOCKS5 或 Mixed 代理埠",
                "HTTP ゲートウェイは SSH に対応していません。SOCKS5 または Mixed のゲートウェイを選んでください"
            ),
        )),
        Some(_) => Ok(()),
    }
}

/// The host's alias against `~/.ssh/config` (`status`) and the other hosts.
fn check_alias(h: &SshHost, others: &[Entity], status: &SshStatus) -> HttpResult<()> {
    let existing = |alias: &str| {
        status
            .existing
            .iter()
            .find(|x| x.patterns.iter().any(|p| p == alias))
    };
    match h.kind {
        SshHostKind::Host => {
            if existing(&h.alias).is_some() {
                return Err(field(
                    "/alias",
                    "SSH_ALIAS_EXISTS",
                    tr!(
                        "~/.ssh/config already has this alias; to route it through the VPN, use “Existing host” instead",
                        "~/.ssh/config 已有這個別名；要讓它經 VPN，請改用「既有主機」",
                        "~/.ssh/config にこのエイリアスがすでにあります。VPN 経由にするには「既存のホスト」を使ってください"
                    ),
                ));
            }
        }
        SshHostKind::Overlay => match existing(&h.alias) {
            None => {
                return Err(field(
                    "/alias",
                    "SSH_ALIAS_UNKNOWN",
                    tr!(
                        "~/.ssh/config has no such host",
                        "~/.ssh/config 沒有這台主機",
                        "~/.ssh/config にこのホストはありません"
                    ),
                ));
            }
            Some(x) if x.wildcard => {
                return Err(field(
                    "/alias",
                    "SSH_ALIAS_WILDCARD",
                    tr!(
                        "A wildcard host cannot go through the VPN on its own; create a new host instead",
                        "萬用字元主機無法單獨經 VPN；請改建新主機",
                        "ワイルドカードのホストは単独では VPN 経由にできません。新しいホストを作成してください"
                    ),
                ));
            }
            Some(x) => {
                // The overlay covers every name of the block; without a HostName each name is
                // its own destination.
                let targets: Vec<&str> = x.host_name.as_ref().map_or_else(
                    || x.patterns.iter().map(String::as_str).collect(),
                    |t| vec![t.as_str()],
                );
                if let Some(why) = targets.iter().find_map(|t| ssh_vpn_unreachable(t)) {
                    return Err(field("/alias", "SSH_NOT_VIA_VPN", why));
                }
                let covered = others.iter().any(|e| {
                    matches!(e, Entity::SshHost(o) if o.id != h.id
                        && o.kind == SshHostKind::Overlay
                        && x.patterns.contains(&o.alias))
                });
                if covered {
                    return Err(field(
                        "/alias",
                        "SSH_ALIAS_TAKEN",
                        tr!(
                            "Another name of this host is already set to go through the VPN",
                            "這台主機的另一個名稱已經設定經 VPN",
                            "このホストの別の名前がすでに VPN 経由に設定されています"
                        ),
                    ));
                }
            }
        },
    }
    Ok(())
}

pub async fn status(State(state): State<AppState>) -> HttpResult<Json<SshStatus>> {
    Ok(Json(ssh_status(&state.link).await?))
}

/// `POST /v1/ssh/include`, `/v1/ssh/overwrite` and `/v1/ssh/apply`: one-off file actions. The
/// backup's name is kept with the operation, so a replayed request reports it too.
async fn file_action(
    state: &AppState,
    headers: &HeaderMap,
    body: &Body,
    path: &str,
    kind: &str,
    call: Call,
) -> HttpResult<Json<SshActionResult>> {
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        headers,
        "POST",
        path,
        None,
        body,
        kind,
        None,
        |_| async move {
            match link.call(call).await? {
                Reply::SshAction { status, backup } => Ok((
                    backup.iter().cloned().collect(),
                    SshActionResult {
                        status: *status,
                        backup,
                    },
                )),
                _ => Err(ApiError::internal()),
            }
        },
    )
    .await?;
    match out {
        Idem::Fresh { value, .. } => Ok(Json(value)),
        Idem::Replayed(op) => Ok(Json(SshActionResult {
            status: ssh_status(&state.link).await?,
            backup: op.result_refs.first().cloned(),
        })),
    }
}

pub async fn include(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Json<SshActionResult>> {
    file_action(
        &state,
        &headers,
        &body,
        "/v1/ssh/include",
        "ssh.include",
        Call::SshInclude,
    )
    .await
}

pub async fn overwrite(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Json<SshActionResult>> {
    file_action(
        &state,
        &headers,
        &body,
        "/v1/ssh/overwrite",
        "ssh.overwrite",
        Call::SshOverwrite,
    )
    .await
}

pub async fn apply(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Json<SshActionResult>> {
    file_action(
        &state,
        &headers,
        &body,
        "/v1/ssh/apply",
        "ssh.apply",
        Call::SshApply,
    )
    .await
}

pub async fn list(State(state): State<AppState>) -> HttpResult<Json<Vec<SshHost>>> {
    let v = list_entities(&state.link, EntityKind::SshHost).await?;
    Ok(Json(
        v.into_iter().filter_map(|e| as_host(e).ok()).collect(),
    ))
}

pub async fn get(State(state): State<AppState>, Path(id): Path<SshHostId>) -> HttpResult<Response> {
    let h = as_host(get_entity(&state.link, EntityKind::SshHost, id.to_string()).await?)?;
    Ok(with_etag(StatusCode::OK, h.meta.revision, &h))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let input: SshHostInput = parse_json(&headers, &body)?;
    let h = build(SshHostId::new(), new_meta(), input);
    check(&state, &h).await?;
    let link = state.link.clone();
    let out = idempotent(
        &state.link,
        &headers,
        "POST",
        "/v1/ssh-hosts",
        None,
        &body,
        "ssh_host.create",
        None,
        |_| async move {
            let e = create_entity(&link, Entity::SshHost(h)).await?;
            let id = match &e {
                Entity::SshHost(h) => h.id.to_string(),
                _ => String::new(),
            };
            Ok((vec![id], e))
        },
    )
    .await?;
    let h = match out {
        Idem::Fresh { value, .. } => as_host(value)?,
        Idem::Replayed(op) => {
            let id = op.result_refs.first().cloned().ok_or_else(wrong)?;
            as_host(get_entity(&state.link, EntityKind::SshHost, id).await?)?
        }
    };
    Ok(with_etag(StatusCode::CREATED, h.meta.revision, &h))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<SshHostId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let rev = if_match(&headers)?;
    let input: SshHostInput = parse_json(&headers, &body)?;
    let current = as_host(get_entity(&state.link, EntityKind::SshHost, id.to_string()).await?)?;
    let h = build(id, current.meta, input);
    check(&state, &h).await?;
    let link = state.link.clone();
    let path = format!("/v1/ssh-hosts/{id}");
    let out = idempotent(
        &state.link,
        &headers,
        "PUT",
        &path,
        Some(rev),
        &body,
        "ssh_host.update",
        Some(id.to_string()),
        |_| async move {
            Ok((
                vec![id.to_string()],
                update_entity(&link, Entity::SshHost(h), rev).await?,
            ))
        },
    )
    .await?;
    let h = match out {
        Idem::Fresh { value, .. } => as_host(value)?,
        Idem::Replayed(_) => {
            as_host(get_entity(&state.link, EntityKind::SshHost, id.to_string()).await?)?
        }
    };
    Ok(with_etag(StatusCode::OK, h.meta.revision, &h))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<SshHostId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let rev = if_match(&headers)?;
    let link = state.link.clone();
    let path = format!("/v1/ssh-hosts/{id}");
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        Some(rev),
        &body,
        "ssh_host.delete",
        Some(id.to_string()),
        |_| async move {
            link.call(Call::Delete {
                kind: EntityKind::SshHost,
                id: id.to_string(),
                expected_revision: rev,
            })
            .await?;
            Ok((vec![id.to_string()], ()))
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Read the server's SSH banner through the host's Gateway, which must prove it is ours (as
/// `vpnctl` requires). Read-only: no authentication, no state change, so no idempotency key is
/// needed. It shows that the Gateway reaches the host, not what `ssh <alias>` resolves to.
pub async fn test(
    State(state): State<AppState>,
    Path(id): Path<SshHostId>,
) -> HttpResult<Json<SshTestResult>> {
    let h = as_host(get_entity(&state.link, EntityKind::SshHost, id.to_string()).await?)?;
    let Some(gateway_id) = h.gateway_id else {
        return Err(bad(
            ErrorCode::InvalidState,
            tr!(
                "Test a host with a direct connection with ssh yourself",
                "直接連線的主機請自行用 ssh 測試",
                "直接接続のホストは ssh でご自身でテストしてください"
            ),
        ));
    };
    let Entity::Gateway(gateway) =
        get_entity(&state.link, EntityKind::Gateway, gateway_id.to_string()).await?
    else {
        return Err(wrong());
    };
    let (target, port) = match h.kind {
        SshHostKind::Host => (
            h.host_name.clone().unwrap_or_default(),
            h.port.unwrap_or(22),
        ),
        SshHostKind::Overlay => {
            let status = ssh_status(&state.link).await?;
            let x = status
                .existing
                .iter()
                .find(|x| x.patterns.iter().any(|p| p == &h.alias));
            (
                x.and_then(|x| x.host_name.clone())
                    .unwrap_or_else(|| h.alias.clone()),
                x.and_then(|x| x.port).unwrap_or(22),
            )
        }
    };
    let key = state
        .gateway_key
        .as_deref()
        .ok_or_else(|| {
            bad(
                ErrorCode::InvalidState,
                tr!(
                    "The Gateway key file was not found",
                    "找不到代理埠金鑰檔",
                    "ゲートウェイの鍵ファイルが見つかりません"
                ),
            )
        })
        .and_then(|p| {
            vpn_ssh::socks::read_key_file(p).map_err(|e| bad(ErrorCode::InvalidState, e))
        })?;
    let gw = SocketAddr::from((Ipv4Addr::LOCALHOST, gateway.port));
    let result =
        match vpn_ssh::socks::ssh_banner(gw, &target, port, Some(&*key), TEST_TIMEOUT).await {
            Ok((banner, elapsed)) => SshTestResult {
                ok: true,
                latency_ms: Some(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)),
                banner: Some(banner),
                error: None,
            },
            Err(e) => SshTestResult {
                ok: false,
                latency_ms: None,
                banner: None,
                error: Some(e),
            },
        };
    Ok(Json(result))
}
