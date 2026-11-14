// SPDX-License-Identifier: GPL-3.0-or-later

//! `AirVPN`'s public server status: each server's official entry addresses.
//!
//! The list (`https://airvpn.org/api/status/`, no key, over verified TLS) carries each server's
//! official entry addresses (`ip_v4_in1..4`, `ip_v6_in1..4`). The Eddie manifest
//! arrives without message authentication, so an endpoint taken from it is used only when this
//! list confirms it for the same server. Shape recorded from an authorized read on 2026-10-27.
//!
//! Entry addresses say where to connect, not who owns an exit: membership comes from `AirVPN`'s
//! `whatismyip` (see [`crate::ipcheck::airvpn`]), never from this list.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use http::{Method, StatusCode};
use serde::Deserialize;
use vpn_domain::tr;
use vpn_domain::validation::{is_private, is_special};

use crate::error::{ProviderError, status_error, unexpected_status};
use crate::https::{Connect, Family, HttpsClient, Request};

pub const STATUS_HOST: &str = "airvpn.org";
const STATUS_PATH: &str = "/api/status/";
/// Today about 210 KiB for 250 servers.
const STATUS_LIMIT: usize = 2 * 1024 * 1024;
const STATUS_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SERVERS: usize = 4096;

/// The status list is not what its contract describes.
fn drift() -> ProviderError {
    ProviderError::ContractDrift(tr!(
        "AirVPN server status",
        "AirVPN 伺服器狀態",
        "AirVPN のサーバー状態"
    ))
}

/// One server as `AirVPN`'s status list describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusServer {
    /// Lower-case public name (`albaldah`), as the Eddie manifest names servers.
    pub name: String,
    /// Upper-case ISO country code.
    pub country_code: String,
    pub location: Option<String>,
    pub entries_v4: Vec<Ipv4Addr>,
    pub entries_v6: Vec<Ipv6Addr>,
    pub load_percent: Option<u8>,
    pub healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusList {
    pub servers: Vec<StatusServer>,
}

impl StatusList {
    #[must_use]
    pub fn server(&self, name: &str) -> Option<&StatusServer> {
        self.servers
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
    }

    /// Whether `ip` is one of `name`'s official entry addresses.
    #[must_use]
    pub fn confirms(&self, name: &str, ip: IpAddr) -> bool {
        self.server(name).is_some_and(|s| match ip.to_canonical() {
            IpAddr::V4(v4) => s.entries_v4.contains(&v4),
            IpAddr::V6(v6) => s.entries_v6.contains(&v6),
        })
    }
}

/// Fetch the list over `family`.
///
/// # Errors
///
/// [`ProviderError::Unavailable`] or [`ProviderError::Refused`] when the request fails,
/// the status error of a non-200 answer, and [`ProviderError::ContractDrift`] when the list
/// does not parse.
pub async fn fetch<C: Connect>(
    http: &HttpsClient<C>,
    family: Family,
) -> Result<StatusList, ProviderError> {
    let request = Request::new(Method::GET, STATUS_HOST, STATUS_PATH, family)
        .limit(STATUS_LIMIT)
        .timeout(STATUS_TIMEOUT);
    let response = http.send(request).await?;
    if response.status != StatusCode::OK {
        return Err(if response.status.is_success() {
            ProviderError::ContractDrift(unexpected_status())
        } else {
            status_error(response.status, &response.headers, None)
        });
    }
    parse(&response.body)
}

#[derive(Deserialize)]
struct Raw {
    result: String,
    servers: Vec<RawServer>,
}

#[derive(Deserialize)]
struct RawServer {
    public_name: String,
    country_code: String,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    currentload: Option<i64>,
    #[serde(default)]
    health: Option<String>,
    #[serde(default)]
    ip_v4_in1: Option<String>,
    #[serde(default)]
    ip_v4_in2: Option<String>,
    #[serde(default)]
    ip_v4_in3: Option<String>,
    #[serde(default)]
    ip_v4_in4: Option<String>,
    #[serde(default)]
    ip_v6_in1: Option<String>,
    #[serde(default)]
    ip_v6_in2: Option<String>,
    #[serde(default)]
    ip_v6_in3: Option<String>,
    #[serde(default)]
    ip_v6_in4: Option<String>,
}

fn public(ip: IpAddr) -> bool {
    !is_special(ip) && !is_private(ip)
}

/// Strict on what identifies a server and on public, well-formed addresses; tolerant of fields
/// it does not use. An entry that is not a public address of its family is left out.
fn parse(body: &[u8]) -> Result<StatusList, ProviderError> {
    let raw: Raw = serde_json::from_slice(body).map_err(|_| drift())?;
    if raw.result != "ok" || raw.servers.is_empty() || raw.servers.len() > MAX_SERVERS {
        return Err(drift());
    }
    let mut seen = HashSet::new();
    let mut servers = Vec::with_capacity(raw.servers.len());
    for s in raw.servers {
        let name = s.public_name.trim().to_ascii_lowercase();
        let valid_name = !name.is_empty()
            && name.len() <= 63
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        let code = s.country_code.trim().to_ascii_uppercase();
        if !valid_name || code.len() != 2 || !code.chars().all(|c| c.is_ascii_uppercase()) {
            return Err(drift());
        }
        if !seen.insert(name.clone()) {
            return Err(ProviderError::ContractDrift(tr!(
                "duplicate AirVPN server names",
                "AirVPN 伺服器名稱重複",
                "AirVPN のサーバー名の重複"
            )));
        }
        let entries_v4 = [s.ip_v4_in1, s.ip_v4_in2, s.ip_v4_in3, s.ip_v4_in4]
            .into_iter()
            .flatten()
            .filter_map(|v| v.trim().parse::<Ipv4Addr>().ok())
            .filter(|ip| public(IpAddr::V4(*ip)))
            .collect();
        let entries_v6 = [s.ip_v6_in1, s.ip_v6_in2, s.ip_v6_in3, s.ip_v6_in4]
            .into_iter()
            .flatten()
            .filter_map(|v| v.trim().parse::<Ipv6Addr>().ok())
            .filter(|ip| public(IpAddr::V6(*ip)))
            .collect();
        servers.push(StatusServer {
            name,
            country_code: code,
            location: s
                .location
                .and_then(|l| crate::display_text(&l, 96).ok().flatten()),
            entries_v4,
            entries_v6,
            load_percent: s
                .currentload
                .filter(|l| (0..=100).contains(l))
                .and_then(|l| u8::try_from(l).ok()),
            healthy: s.health.as_deref() == Some("ok"),
        });
    }
    Ok(StatusList { servers })
}
