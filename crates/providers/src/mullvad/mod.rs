//! Mullvad adapter for `api.mullvad.net`: access token, account, devices and the public
//! `WireGuard` relay catalog.
//!
//! Paths, request bodies and response shapes follow the official app (`mullvad-api` at the
//! snapshot pinned in SOURCES S09: `access.rs`, `device.rs`, `relay_list.rs`, `rest.rs`) and the
//! previous implementation (`web/adapters/mullvad/api.mjs`, `relays.mjs`), whose public catalog
//! endpoint `/public/relays/wireguard/v2/` this keeps. Unknown fields are ignored; a missing or
//! invalid required field is [`ProviderError::ContractDrift`].
//!
//! Mullvad refuses with a 4xx and `{"code": "…"}` (its newer format is
//! `application/problem+json` with `type`). Codes are checked before the status, as the official
//! daemon does: `MAX_DEVICES_REACHED` is [`ProviderError::DeviceLimitReached`] (the previous
//! implementation's `DEVICE_LIMIT_REACHED`), `INVALID_ACCOUNT` / `INVALID_ACCESS_TOKEN` are
//! [`ProviderError::AuthRejected`]. Any other non-429 4xx from the token endpoint is also
//! `AuthRejected` (the account number is its only input), as the previous implementation did.
//!
//! The adapter is stateless: token reuse, preflight IP checks, permits and quotas belong to the
//! caller. Each call is one request on a fresh connection over the adapter's [`Family`].

mod relays;
mod types;

use std::borrow::Cow;
use std::time::Duration;

use http::header::AUTHORIZATION;
use http::{Method, StatusCode};
use serde::Deserialize;
use vpn_domain::{WgKey, tr};
use zeroize::Zeroizing;

pub use relays::{
    City, Country, MTU, MultihopPorts, Relay, RelayCatalog, WIREGUARD_PORT, WireGuardNetwork,
    WireGuardParams, multihop_params, parse_catalog, parse_multihop, wireguard_params,
};
pub use types::{
    AccessToken, Account, AccountNumber, Device, DeviceId, InvalidAccountNumber, InvalidDeviceId,
    Reconciled, Removal, reconcile_created_device,
};

use crate::error::{ProviderError, is_machine_code, status_error, unexpected_status};
use crate::https::{Connect, Family, HttpsClient, Request, Response};

pub const API_HOST: &str = "api.mullvad.net";
/// Spec: 10 s per attempt.
pub const API_TIMEOUT: Duration = Duration::from_secs(10);

const TOKEN_PATH: &str = "/auth/v1/token";
const ACCOUNT_PATH: &str = "/accounts/v1/accounts/me";
const DEVICES_PATH: &str = "/accounts/v1/devices";
const RELAYS_PATH: &str = "/public/relays/wireguard/v2/";
/// The website's relay list: the only one that carries each relay's multihop port.
const WWW_RELAYS_PATH: &str = "/www/relays/wireguard/";
/// Token, account and device responses: a few hundred bytes each (at most 5 devices).
const SMALL_LIMIT: usize = 64 * 1024;
/// The relay catalog: a few hundred KiB today; the previous implementation allowed 4 MiB.
const CATALOG_LIMIT: usize = 4 * 1024 * 1024;

const MAX_DEVICES_REACHED: &str = "MAX_DEVICES_REACHED";
const INVALID_ACCOUNT: &str = "INVALID_ACCOUNT";
const INVALID_ACCESS_TOKEN: &str = "INVALID_ACCESS_TOKEN";
const DEVICE_NOT_FOUND: &str = "DEVICE_NOT_FOUND";

/// Mullvad API client pinned to one address family.
#[derive(Clone)]
pub struct Mullvad<C> {
    http: HttpsClient<C>,
    family: Family,
    timeout: Duration,
}

impl<C: Connect> Mullvad<C> {
    pub const fn new(http: HttpsClient<C>, family: Family) -> Self {
        Self {
            http,
            family,
            timeout: API_TIMEOUT,
        }
    }

    /// Deadline per request, e.g. the remaining operation budget when below [`API_TIMEOUT`].
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub const fn family(&self) -> Family {
        self.family
    }

    pub const fn http(&self) -> &HttpsClient<C> {
        &self.http
    }

    /// `POST /auth/v1/token`: exchanges the account number for an access token.
    ///
    /// # Errors
    ///
    /// [`ProviderError::AuthRejected`] when Mullvad refuses the account number with a 4xx other
    /// than 429; otherwise as for [`Mullvad::account`].
    pub async fn token(&self, account: &AccountNumber) -> Result<AccessToken, ProviderError> {
        let request = self
            .request(Method::POST, TOKEN_PATH)
            .json(account.token_request());
        let response = self.send(request).await?;
        if response.status == StatusCode::OK {
            return types::parse_token(&response.body);
        }
        if response.status.is_client_error() && response.status != StatusCode::TOO_MANY_REQUESTS {
            return Err(ProviderError::AuthRejected);
        }
        Err(failure(&response))
    }

    /// `GET /accounts/v1/accounts/me`.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Unavailable`] or [`ProviderError::Refused`] when the request fails,
    /// [`ProviderError::AuthRejected`], [`ProviderError::RateLimited`] or
    /// [`ProviderError::Rejected`] for the error status Mullvad answers with, and
    /// [`ProviderError::ContractDrift`] when the answer does not parse.
    pub async fn account(&self, token: &AccessToken) -> Result<Account, ProviderError> {
        let request = self
            .request(Method::GET, ACCOUNT_PATH)
            .header(AUTHORIZATION, token.authorization());
        let response = self.send(request).await?;
        expect(&response, StatusCode::OK)?;
        types::parse_account(&response.body)
    }

    /// `GET /accounts/v1/devices`.
    ///
    /// # Errors
    ///
    /// As for [`Mullvad::account`].
    pub async fn devices(&self, token: &AccessToken) -> Result<Vec<Device>, ProviderError> {
        let request = self
            .request(Method::GET, DEVICES_PATH)
            .header(AUTHORIZATION, token.authorization());
        let response = self.send(request).await?;
        expect(&response, StatusCode::OK)?;
        types::parse_devices(&response.body)
    }

    /// `POST /accounts/v1/devices` with `{"pubkey", "hijack_dns": false}` (as the official app
    /// and the previous implementation send it). The key pair is generated locally; only the
    /// public key leaves. If this fails with [`ProviderError::outcome_unknown`], or is rejected
    /// with `PUBKEY_IN_USE`, use [`Mullvad::reconcile_device`]; never call this again for the
    /// key. After `PUBKEY_IN_USE`, [`Reconciled::StillUnknown`] most likely means the key is
    /// registered outside this account: do not use that key.
    ///
    /// # Errors
    ///
    /// [`ProviderError::DeviceLimitReached`] when the account holds no more devices,
    /// [`ProviderError::ContractDrift`] when the created device carries another public key;
    /// otherwise as for [`Mullvad::account`].
    pub async fn create_device(
        &self,
        token: &AccessToken,
        pubkey: &WgKey,
    ) -> Result<Device, ProviderError> {
        // Base64 needs no JSON escaping.
        let body = format!(r#"{{"pubkey":"{pubkey}","hijack_dns":false}}"#);
        let request = self
            .request(Method::POST, DEVICES_PATH)
            .header(AUTHORIZATION, token.authorization())
            .json(Zeroizing::new(body.into_bytes()));
        let response = self.send(request).await?;
        // The official app expects 201; 200 with the same record is just as unambiguous.
        if !matches!(response.status, StatusCode::CREATED | StatusCode::OK) {
            return Err(failure(&response));
        }
        let device = types::parse_device(&response.body)?;
        if device.pubkey != *pubkey {
            return Err(ProviderError::ContractDrift(tr!(
                "the new device's public key is not the one sent",
                "新裝置的公鑰與送出的不同",
                "新しいデバイスの公開鍵が送信したものと異なる"
            )));
        }
        Ok(device)
    }

    /// `DELETE /accounts/v1/devices/{id}`. Only for a device the user chose and whose
    /// ownership the caller confirmed; a retry after a lost reply reports
    /// [`Removal::AlreadyAbsent`].
    ///
    /// # Errors
    ///
    /// As for [`Mullvad::account`]; a 404 naming the device as unknown is
    /// [`Removal::AlreadyAbsent`], not an error.
    pub async fn delete_device(
        &self,
        token: &AccessToken,
        id: &DeviceId,
    ) -> Result<Removal, ProviderError> {
        let path = format!("{DEVICES_PATH}/{}", id.as_str());
        let request = self
            .request(Method::DELETE, path)
            .header(AUTHORIZATION, token.authorization());
        let response = self.send(request).await?;
        if response.status == StatusCode::NO_CONTENT {
            return Ok(Removal::Deleted);
        }
        let error = failure(&response);
        let gone = response.status == StatusCode::NOT_FOUND
            && matches!(&error, ProviderError::Rejected { code: Some(code), .. } if code == DEVICE_NOT_FOUND);
        if gone {
            Ok(Removal::AlreadyAbsent)
        } else {
            Err(error)
        }
    }

    /// Reads the device list and looks for `pubkey`: the reconcile step after a create whose
    /// outcome is unknown.
    ///
    /// # Errors
    ///
    /// As for [`Mullvad::devices`].
    pub async fn reconcile_device(
        &self,
        token: &AccessToken,
        pubkey: &WgKey,
    ) -> Result<Reconciled, ProviderError> {
        reconcile_created_device(&self.devices(token).await?, pubkey)
    }

    /// `GET /public/relays/wireguard/v2/` (public, no token).
    ///
    /// # Errors
    ///
    /// As for [`Mullvad::account`].
    pub async fn relays(&self) -> Result<RelayCatalog, ProviderError> {
        let request = self.request(Method::GET, RELAYS_PATH).limit(CATALOG_LIMIT);
        let response = self.send(request).await?;
        expect(&response, StatusCode::OK)?;
        relays::parse_catalog(&response.body)
    }

    /// `GET /www/relays/wireguard/` (public, no token): each relay's multihop port.
    ///
    /// # Errors
    ///
    /// As for [`Mullvad::account`].
    pub async fn multihop_ports(&self) -> Result<MultihopPorts, ProviderError> {
        let request = self
            .request(Method::GET, WWW_RELAYS_PATH)
            .limit(CATALOG_LIMIT);
        let response = self.send(request).await?;
        expect(&response, StatusCode::OK)?;
        relays::parse_multihop(&response.body)
    }

    fn request(&self, method: Method, path: impl Into<String>) -> Request {
        Request::new(method, API_HOST, path, self.family)
            .limit(SMALL_LIMIT)
            .timeout(self.timeout)
    }

    async fn send(&self, request: Request) -> Result<Response, ProviderError> {
        Ok(self.http.send(request).await?)
    }
}

/// `Ok` for the endpoint's success status, the typed error otherwise.
fn expect(response: &Response, ok: StatusCode) -> Result<(), ProviderError> {
    if response.status == ok {
        Ok(())
    } else {
        Err(failure(response))
    }
}

/// Typed error for a response that is not the endpoint's success.
fn failure(response: &Response) -> ProviderError {
    let status = response.status;
    if status.is_success() {
        return ProviderError::ContractDrift(unexpected_status());
    }
    let code = error_code(&response.body);
    if status.is_client_error() && status != StatusCode::TOO_MANY_REQUESTS {
        match code.as_deref() {
            Some(MAX_DEVICES_REACHED) => return ProviderError::DeviceLimitReached,
            Some(INVALID_ACCOUNT | INVALID_ACCESS_TOKEN) => return ProviderError::AuthRejected,
            _ => {}
        }
    }
    status_error(status, &response.headers, code)
}

/// Mullvad's machine code: `code` (classic body) or the last path segment of `type`
/// (`application/problem+json`), kept only when it is a plain `UPPER_SNAKE` token. Read
/// borrowed from the (zeroizing) body, so text that is not a code is never copied out.
fn error_code(body: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody<'a> {
        #[serde(default, borrow)]
        code: Option<Cow<'a, str>>,
        #[serde(default, borrow, rename = "type")]
        kind: Option<Cow<'a, str>>,
    }
    let parsed: ErrorBody<'_> = serde_json::from_slice(body).ok()?;
    let raw = parsed.code.or(parsed.kind)?;
    let code = raw.rsplit('/').next()?;
    is_machine_code(code).then(|| code.to_owned())
}
