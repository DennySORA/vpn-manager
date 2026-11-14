//! `WireGuard` runtime profiles. Profiles enter only through an import (or a Provider); keys,
//! endpoint and addresses are not hand-edited afterwards.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use vpn_domain::validation::check_profile;
use vpn_domain::{
    ApiError, ErrorCode, ImportCandidate, ImportMode, ImportRequest, ImportResult, InterfaceSpec,
    PeerSpec, ProfileId, ProfileSource, ProfileUpdate, ProviderKind, RuntimeProfile, SecretId,
    SecretRef, ValidationReport, WgKey, tr,
};
use vpn_ipc::SecretBytes;
use vpn_ipc::control::{Call, Entity, EntityKind, Reply};
use zeroize::Zeroize;

use super::{
    AppState, Body, Idem, get_entity, idempotent, list_entities, new_meta, parse_json, run_once,
    update_entity, wrong,
};
use crate::http::{HttpResult, bad, idempotency_key, if_match, report_error, with_etag};
use crate::link::ManagerLink;

fn as_profile(e: Entity) -> HttpResult<RuntimeProfile> {
    match e {
        Entity::Profile(p) => Ok(p),
        _ => Err(wrong()),
    }
}

pub async fn list(State(state): State<AppState>) -> HttpResult<Json<Vec<RuntimeProfile>>> {
    let v = list_entities(&state.link, EntityKind::Profile).await?;
    Ok(Json(
        v.into_iter().filter_map(|e| as_profile(e).ok()).collect(),
    ))
}

pub async fn get(State(state): State<AppState>, Path(id): Path<ProfileId>) -> HttpResult<Response> {
    let p = as_profile(get_entity(&state.link, EntityKind::Profile, id.to_string()).await?)?;
    Ok(with_etag(StatusCode::OK, p.meta.revision, &p))
}

pub async fn check(
    State(state): State<AppState>,
    Path(id): Path<ProfileId>,
) -> HttpResult<Json<ValidationReport>> {
    let p = as_profile(get_entity(&state.link, EntityKind::Profile, id.to_string()).await?)?;
    Ok(Json(check_profile(&p)))
}

fn public_key_of(private: &[u8; 32]) -> WgKey {
    let secret = x25519_dalek::StaticSecret::from(*private);
    WgKey(x25519_dalek::PublicKey::from(&secret).to_bytes())
}

/// The profile an import would store, with placeholder key references (for the check only).
fn placeholder_profile(req: &ImportRequest, candidate: &ImportCandidate) -> RuntimeProfile {
    let placeholder = SecretRef(SecretId::new());
    RuntimeProfile {
        id: ProfileId::new(),
        meta: new_meta(),
        name: req.name.trim().to_string(),
        provider: req.provider.unwrap_or(ProviderKind::Generic),
        source: ProfileSource::Imported,
        interface: InterfaceSpec {
            private_key: placeholder,
            public_key: candidate.public_key,
            addresses: candidate.addresses.clone(),
            dns: candidate.dns.clone(),
            mtu: candidate.mtu,
        },
        peer: PeerSpec {
            public_key: candidate.peer_public_key,
            preshared_key: candidate.has_preshared_key.then_some(placeholder),
            endpoint: candidate.endpoint,
            allowed_ips: candidate.allowed_ips.clone(),
            persistent_keepalive: candidate.persistent_keepalive,
        },
        location: req.location.clone(),
        expires_at: None,
    }
}

/// Store the imported keys in the vault and create `profile` with them; on a refused create the
/// keys are deleted again.
async fn store_imported(
    link: &ManagerLink,
    mut profile: RuntimeProfile,
    private: &[u8; 32],
    psk: Option<&[u8; 32]>,
    fingerprint_of_key: String,
) -> Result<(Vec<String>, RuntimeProfile), ApiError> {
    let sk = match link
        .call(Call::PutSecret {
            kind: "wireguard_private_key".into(),
            label: Some(profile.name.clone()),
            plaintext: SecretBytes::new(private.to_vec()),
            public_fingerprint: Some(fingerprint_of_key),
        })
        .await?
    {
        Reply::Secret(m) => m.secret_ref,
        _ => return Err(ApiError::internal()),
    };
    let psk_ref = match psk {
        Some(k) => match link
            .call(Call::PutSecret {
                kind: "wireguard_preshared_key".into(),
                label: Some(profile.name.clone()),
                plaintext: SecretBytes::new(k.to_vec()),
                public_fingerprint: None,
            })
            .await?
        {
            Reply::Secret(m) => Some(m.secret_ref),
            _ => return Err(ApiError::internal()),
        },
        None => None,
    };
    profile.interface.private_key = sk;
    profile.peer.preshared_key = psk_ref;
    match link.call(Call::Create(Entity::Profile(profile))).await {
        Ok(Reply::Entity(e)) => match *e {
            Entity::Profile(p) => Ok((vec![p.id.to_string()], p)),
            _ => Err(ApiError::internal()),
        },
        Ok(_) => Err(ApiError::internal()),
        Err(e) => {
            // Do not leave unreferenced key material behind.
            let _ = link.call(Call::DeleteSecret(sk)).await;
            if let Some(r) = psk_ref {
                let _ = link.call(Call::DeleteSecret(r)).await;
            }
            Err(e)
        }
    }
}

/// `POST /v1/profiles/import` — preview parses only; commit stores the keys in the vault and
/// creates the profile. The configuration text is never stored or echoed.
pub async fn import(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let mut req: ImportRequest = parse_json(&headers, &body)?;
    let parsed = vpn_domain::wgconf::parse(&req.config);
    req.config.zeroize();
    let (parsed, mut report) = match parsed {
        Ok(v) => v,
        Err(report) => {
            return Ok(with_etag(
                StatusCode::OK,
                0,
                &ImportResult {
                    candidate: None,
                    report,
                    profile: None,
                },
            ));
        }
    };
    let public_key = public_key_of(&parsed.private_key);
    let p = &parsed.public;
    let candidate = ImportCandidate {
        public_key,
        addresses: p.addresses.clone(),
        dns: p.dns.clone(),
        mtu: p.mtu.unwrap_or(1420),
        peer_public_key: p.peer_public_key,
        endpoint: p.endpoint,
        allowed_ips: p.allowed_ips.clone(),
        persistent_keepalive: p.persistent_keepalive,
        has_preshared_key: parsed.preshared_key.is_some(),
    };
    // Validate the profile as it would be stored (refs are placeholders for the check only).
    let profile = placeholder_profile(&req, &candidate);
    let checked = check_profile(&profile);
    report.issues.extend(checked.issues);
    let report = ValidationReport {
        valid: false,
        issues: report.issues,
    }
    .finish();
    if req.mode == ImportMode::Preview || report.has_errors() {
        let status = if report.has_errors() && req.mode == ImportMode::Commit {
            return Err(report_error(&report));
        } else {
            StatusCode::OK
        };
        return Ok(with_etag(
            status,
            0,
            &ImportResult {
                candidate: Some(candidate),
                report,
                profile: None,
            },
        ));
    }

    // Commit: keyed fingerprint because the body carries a private key.
    let key = idempotency_key(&headers)?;
    let Reply::Fingerprint(fp) = state
        .link
        .call(Call::KeyedFingerprint(body.to_vec()))
        .await?
    else {
        return Err(wrong());
    };
    let link = state.link.clone();
    let fingerprint_of_key = hex_sha256(&public_key.0);
    let private = parsed.private_key;
    let psk = parsed.preshared_key;
    let out = run_once(
        &state.link,
        key,
        fp,
        "profile.import",
        None,
        |_| async move {
            store_imported(&link, profile, &private, psk.as_deref(), fingerprint_of_key).await
        },
    )
    .await?;
    let created = match out {
        Idem::Fresh { value, .. } => value,
        Idem::Replayed(op) => {
            let id = op.result_refs.first().cloned().ok_or_else(wrong)?;
            as_profile(get_entity(&state.link, EntityKind::Profile, id).await?)?
        }
    };
    let rev = created.meta.revision;
    Ok(with_etag(
        StatusCode::CREATED,
        rev,
        &ImportResult {
            candidate: Some(candidate),
            report,
            profile: Some(created),
        },
    ))
}

fn hex_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<ProfileId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    let rev = if_match(&headers)?;
    let input: ProfileUpdate = parse_json(&headers, &body)?;
    let mut p = as_profile(get_entity(&state.link, EntityKind::Profile, id.to_string()).await?)?;
    if p.meta.revision != rev {
        return Err(bad(
            ErrorCode::RevisionConflict,
            tr!(
                "The data was changed by another operation; reload and try again",
                "資料已被其他操作更新，請重新載入後再試",
                "データが別の操作で更新されました。再読み込みしてからもう一度お試しください"
            ),
        ));
    }
    p.name = input.name.trim().to_string();
    p.location = input.location;
    if let Some(m) = input.mtu {
        p.interface.mtu = m;
    }
    if input.persistent_keepalive.is_some() {
        p.peer.persistent_keepalive = input.persistent_keepalive.filter(|k| *k > 0);
    }
    let report = check_profile(&p);
    if report.has_errors() {
        return Err(report_error(&report));
    }
    let link = state.link.clone();
    let path = format!("/v1/profiles/{id}");
    let out = idempotent(
        &state.link,
        &headers,
        "PUT",
        &path,
        Some(rev),
        &body,
        "profile.update",
        Some(id.to_string()),
        |_| async move {
            let e = update_entity(&link, Entity::Profile(p), rev).await?;
            Ok((vec![id.to_string()], e))
        },
    )
    .await?;
    let p = match out {
        Idem::Fresh { value, .. } => as_profile(value)?,
        Idem::Replayed(_) => {
            as_profile(get_entity(&state.link, EntityKind::Profile, id.to_string()).await?)?
        }
    };
    Ok(with_etag(StatusCode::OK, p.meta.revision, &p))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<ProfileId>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    let rev = if_match(&headers)?;
    let link = state.link.clone();
    let path = format!("/v1/profiles/{id}");
    idempotent(
        &state.link,
        &headers,
        "DELETE",
        &path,
        Some(rev),
        &body,
        "profile.delete",
        Some(id.to_string()),
        |_| async move {
            // Delete the profile, then its now-unreferenced keys.
            let p = match link
                .call(Call::Get(EntityKind::Profile, id.to_string()))
                .await?
            {
                Reply::Entity(e) => match *e {
                    Entity::Profile(p) => p,
                    _ => return Err(ApiError::internal()),
                },
                _ => return Err(ApiError::internal()),
            };
            link.call(Call::Delete {
                kind: EntityKind::Profile,
                id: id.to_string(),
                expected_revision: rev,
            })
            .await?;
            // A Mullvad device's key belongs to the device, not to this profile: it stays, so the
            // device can be reused or revoked from the provider page (which then forgets it).
            // Keys still used by another profile are refused by the vault and kept as well.
            let device_key = p.provider == ProviderKind::Mullvad
                && matches!(p.source, ProfileSource::Provider { .. });
            if !device_key {
                let _ = link.call(Call::DeleteSecret(p.interface.private_key)).await;
            }
            if let Some(r) = p.peer.preshared_key {
                let _ = link.call(Call::DeleteSecret(r)).await;
            }
            Ok((vec![id.to_string()], ()))
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
