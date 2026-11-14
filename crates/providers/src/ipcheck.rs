//! Exit IP checkers: which public address a request over the chosen connector and family
//! leaves from, where that is, and whether the exit belongs to the provider.
//!
//! - Mullvad: `https://ipv4.am.i.mullvad.net/json` and `https://ipv6.am.i.mullvad.net/json`, the
//!   family-specific origins of the official app (`mullvad-daemon/src/geoip.rs`, SOURCES S16).
//!   `mullvad_exit_ip` is Mullvad's own membership evidence: `true` is
//!   [`ProviderMatch::Match`], `false` is [`ProviderMatch::Other`]; `mullvad_exit_ip_hostname`
//!   names the exit relay (kept as [`IpObservation::server`]), which tells a multihop exit apart.
//! - `AirVPN`: `https://airvpn.org/api/whatismyip/` (no key). Its `airvpn` flag is `AirVPN`'s own
//!   membership evidence: `true` is [`ProviderMatch::Match`], `false` is [`ProviderMatch::Other`].
//!   Shape recorded from an authorized read on 2026-10-27 (the IPCHECK-AIR discovery gate).
//! - Generic profiles: `https://ipv4.ipleak.net/json/` (SOURCES S17). It carries no membership
//!   flag, so the match is always [`ProviderMatch::Unknown`] — never guessed from country, ISP or
//!   ASN. IPv6 `IPLeak` is not verified yet (spec gate AIR-IPV6-01), so only IPv4 is offered.
//!
//! Only the address, country and city are kept, never coordinates. The address must belong to
//! the family that was checked. A check carries no account credential.

use std::net::IpAddr;
use std::time::Duration;

use http::{Method, StatusCode};
use serde::Deserialize;
use vpn_domain::tr;
use vpn_domain::validation::is_special;
use zeroize::Zeroizing;

use crate::display_text;
use crate::error::{ProviderError, status_error, unexpected_status};
use crate::https::{Connect, Family, HttpsClient, Request};

pub const MULLVAD_V4_HOST: &str = "ipv4.am.i.mullvad.net";
pub const MULLVAD_V6_HOST: &str = "ipv6.am.i.mullvad.net";
pub const IPLEAK_V4_HOST: &str = "ipv4.ipleak.net";
pub const AIRVPN_HOST: &str = "airvpn.org";
const MULLVAD_PATH: &str = "/json";
const IPLEAK_PATH: &str = "/json/";
const AIRVPN_PATH: &str = "/api/whatismyip/";
/// The preflight check's time.
///
/// The spec's 3 s was too short for a checker on another continent: from `AirVPN`'s Tokyo exit to airvpn.org a TLS handshake alone took 0.76–2.2 s and the whole
/// check 1.05–3.19 s (measured 2026-11-02), so about a third of provider requests failed
/// without trying.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(8);
/// Real answers are under 2 KiB.
const CHECK_LIMIT: usize = 16 * 1024;
const MAX_PLACE: usize = 128;

/// The checker's answer is not what its contract describes.
fn drift() -> ProviderError {
    ProviderError::ContractDrift(tr!("IP check response", "IP 檢測回應", "IP チェックの応答"))
}

/// Whether the observed exit belongs to the provider being checked (shared with the API).
pub use vpn_domain::ProviderMatch;

/// One exit observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpObservation {
    /// Public exit address, of the family that was checked.
    pub ip: IpAddr,
    pub country: Option<String>,
    pub city: Option<String>,
    pub provider_match: ProviderMatch,
    /// The exit server the checker names (Mullvad's exit relay hostname), when it names one.
    pub server: Option<String>,
}

/// Mullvad's checker over `family` (its IPv4-only or IPv6-only origin).
///
/// # Errors
///
/// [`ProviderError::Unavailable`] or [`ProviderError::Refused`] when the check cannot be made,
/// the status error of a non-200 answer, and [`ProviderError::ContractDrift`] when the answer
/// does not parse or names an address of another family.
pub async fn mullvad<C: Connect>(
    http: &HttpsClient<C>,
    family: Family,
) -> Result<IpObservation, ProviderError> {
    let host = match family {
        Family::V4 => MULLVAD_V4_HOST,
        Family::V6 => MULLVAD_V6_HOST,
    };
    let body = fetch(http, host, MULLVAD_PATH, family).await?;
    parse_mullvad(&body, family)
}

/// `AirVPN`'s checker over `family` (the name resolves for both; the connector pins the family).
///
/// # Errors
///
/// [`ProviderError::Unavailable`] or [`ProviderError::Refused`] when the check cannot be made,
/// the status error of a non-200 answer, and [`ProviderError::ContractDrift`] when the answer
/// does not parse or names an address of another family.
pub async fn airvpn<C: Connect>(
    http: &HttpsClient<C>,
    family: Family,
) -> Result<IpObservation, ProviderError> {
    let body = fetch(http, AIRVPN_HOST, AIRVPN_PATH, family).await?;
    parse_airvpn(&body, family)
}

/// `IPLeak` over IPv4, for generic profiles. The match is always unknown.
///
/// # Errors
///
/// [`ProviderError::Unavailable`] or [`ProviderError::Refused`] when the check cannot be made,
/// the status error of a non-200 answer, and [`ProviderError::ContractDrift`] when the answer
/// does not parse or names an address of another family.
pub async fn ipleak_v4<C: Connect>(http: &HttpsClient<C>) -> Result<IpObservation, ProviderError> {
    let body = fetch(http, IPLEAK_V4_HOST, IPLEAK_PATH, Family::V4).await?;
    parse_ipleak(&body, Family::V4)
}

async fn fetch<C: Connect>(
    http: &HttpsClient<C>,
    host: &'static str,
    path: &'static str,
    family: Family,
) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    let request = Request::new(Method::GET, host, path, family)
        .limit(CHECK_LIMIT)
        .timeout(CHECK_TIMEOUT);
    let response = http.send(request).await?;
    if response.status == StatusCode::OK {
        Ok(response.body)
    } else if response.status.is_success() {
        Err(ProviderError::ContractDrift(unexpected_status()))
    } else {
        Err(status_error(response.status, &response.headers, None))
    }
}

/// The official app's `AmIMullvad` fields that we keep; coordinates and the rest are ignored.
fn parse_mullvad(body: &[u8], family: Family) -> Result<IpObservation, ProviderError> {
    #[derive(Deserialize)]
    struct AmIMullvad {
        ip: String,
        country: String,
        #[serde(default)]
        city: Option<String>,
        mullvad_exit_ip: bool,
        #[serde(default)]
        mullvad_exit_ip_hostname: Option<String>,
    }
    let raw: AmIMullvad = serde_json::from_slice(body).map_err(|_| drift())?;
    Ok(IpObservation {
        ip: exit_ip(&raw.ip, family)?,
        country: place(Some(&raw.country))?,
        city: place(raw.city.as_deref())?,
        provider_match: if raw.mullvad_exit_ip {
            ProviderMatch::Match
        } else {
            ProviderMatch::Other
        },
        // A relay hostname (`se-got-wg-001`): anything else is not kept.
        server: raw
            .mullvad_exit_ip_hostname
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| relay_name(h)),
    })
}

/// A relay hostname as Mullvad names them: a DNS label of lower-case letters, digits and hyphens.
fn relay_name(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `AirVPN`'s `whatismyip`: `result`, `ip` and the `airvpn` flag are required; the place is optional
/// (`geo_additional` comes "without guarantees"). Coordinates, ISP and ASN are ignored.
fn parse_airvpn(body: &[u8], family: Family) -> Result<IpObservation, ProviderError> {
    #[derive(Deserialize)]
    struct Geo {
        #[serde(default)]
        name: Option<String>,
    }
    #[derive(Deserialize)]
    struct GeoAdditional {
        #[serde(default)]
        city_name: Option<String>,
    }
    #[derive(Deserialize)]
    struct WhatIsMyIp {
        result: String,
        ip: String,
        airvpn: bool,
        #[serde(default)]
        geo: Option<Geo>,
        #[serde(default)]
        geo_additional: Option<GeoAdditional>,
    }
    let raw: WhatIsMyIp = serde_json::from_slice(body).map_err(|_| drift())?;
    if raw.result != "ok" {
        return Err(drift());
    }
    Ok(IpObservation {
        ip: exit_ip(&raw.ip, family)?,
        country: place(raw.geo.and_then(|g| g.name).as_deref())?,
        city: place(raw.geo_additional.and_then(|g| g.city_name).as_deref())?,
        provider_match: if raw.airvpn {
            ProviderMatch::Match
        } else {
            ProviderMatch::Other
        },
        server: None,
    })
}

fn parse_ipleak(body: &[u8], family: Family) -> Result<IpObservation, ProviderError> {
    #[derive(Deserialize)]
    struct IpLeak {
        ip: String,
        #[serde(default)]
        country_name: Option<String>,
        #[serde(default)]
        city_name: Option<String>,
    }
    let raw: IpLeak = serde_json::from_slice(body).map_err(|_| drift())?;
    Ok(IpObservation {
        ip: exit_ip(&raw.ip, family)?,
        country: place(raw.country_name.as_deref())?,
        city: place(raw.city_name.as_deref())?,
        provider_match: ProviderMatch::Unknown,
        server: None,
    })
}

/// The reported address, which must be a usable address of the checked family.
fn exit_ip(value: &str, family: Family) -> Result<IpAddr, ProviderError> {
    let ip = value
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| drift())?
        .to_canonical();
    if Family::of(ip) != family || is_special(ip) {
        return Err(ProviderError::ContractDrift(tr!(
            "exit IP of another address family than the one checked",
            "出口 IP 與檢測的位址家族不符",
            "確認したものとは別のアドレスファミリーの出口 IP"
        )));
    }
    Ok(ip)
}

fn place(value: Option<&str>) -> Result<Option<String>, ProviderError> {
    value.map_or(Ok(None), |text| {
        display_text(text, MAX_PLACE).map_err(|_| drift())
    })
}
