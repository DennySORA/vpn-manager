//! The public `WireGuard` relay catalog (`GET /public/relays/wireguard/v2/`) and the public
//! `WireGuard` parameters of a profile built from it.
//!
//! Required fields follow the official app's relay list types (`mullvad-api/src/relay_list.rs`):
//! a missing or mistyped one is contract drift. Like the official app, a location whose code is
//! not `cc-city` is ignored and a relay whose location is not listed is left out.
//!
//! **Multihop** (Mullvad's documented scheme for `WireGuard` clients other than its app, help page
//! "`WireGuard` on a router"): the tunnel's endpoint is the *entry* relay's IPv4 address on the
//! *exit* relay's multihop port, and its peer key is the exit relay's. The entry relay forwards
//! the UDP to the exit relay by that port; the `WireGuard` session is the exit relay's, so a key
//! that is not the exit's never completes a handshake. Only the website's relay list
//! (`GET /www/relays/wireguard/`) carries `multihop_port`; a port is used only when that list
//! gives the exit relay the catalog's key and address, and no other relay the same port
//! ([`MultihopPorts::port_of`]).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use serde::Deserialize;
use vpn_domain::validation::is_special;
use vpn_domain::{WgKey, tr};

use super::types::Device;
use crate::display_text;
use crate::error::ProviderError;
use crate::https::Family;

/// Port profiles use when the catalog's port ranges include it.
///
/// Otherwise the first port of the first range — the previous implementation's choice (`web/adapters/mullvad/relays.mjs`,
/// `WIREGUARD_PORT` and `normalizeCatalog`). Every port in the ranges reaches the same
/// `WireGuard` listener; 51820 is the standard one.
pub const WIREGUARD_PORT: u16 = 51820;

/// MTU of Mullvad profiles: 1420.
///
/// It is what the previous implementation wrote into every Mullvad profile (`web/adapters/mullvad/service.mjs`, `recipe()`; pinned by its test "keeps the
/// established fixed Profile values: port 51820, MTU 1420, gateway DNS, no PSK"). It is
/// wg-quick's default on a 1500-byte link (80 bytes of IPv6 + UDP + `WireGuard` overhead) and the
/// highest value profile validation accepts without a warning.
pub const MTU: u16 = 1420;

const MAX_RELAYS: usize = 4096;
const MAX_LOCATIONS: usize = 1024;
const MAX_PORT_RANGES: usize = 64;
const MAX_NAME: usize = 64;

const ANY_V4: Ipv4Network = match Ipv4Network::new_checked(Ipv4Addr::UNSPECIFIED, 0) {
    Some(net) => net,
    None => panic!("0.0.0.0/0 is a valid network"),
};
const ANY_V6: Ipv6Network = match Ipv6Network::new_checked(Ipv6Addr::UNSPECIFIED, 0) {
    Some(net) => net,
    None => panic!("::/0 is a valid network"),
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCatalog {
    /// Countries with their cities, sorted by code.
    pub countries: Vec<Country>,
    /// Every listed relay, active or not, sorted by hostname.
    pub relays: Vec<Relay>,
    pub network: WireGuardNetwork,
    /// Relays left out: location not listed, or an entry address that can never be a tunnel
    /// endpoint (loopback, multicast, ...). Worth logging; the rest of the catalog is usable.
    pub skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Country {
    /// ISO 3166-1 alpha-2, lower case (`se`).
    pub code: String,
    pub name: String,
    pub cities: Vec<City>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct City {
    /// Mullvad's city code (`got`); the location code is `{country}-{city}`.
    pub code: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    pub hostname: String,
    /// Location code, `se-got`.
    pub location: String,
    pub country_code: String,
    pub country: String,
    pub city_code: String,
    pub city: String,
    /// `WireGuard` entry addresses (`ipv4_addr_in` / `ipv6_addr_in`).
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub public_key: WgKey,
    pub active: bool,
    /// Mullvad owns the server, rather than renting it from `provider`.
    pub owned: bool,
    /// Hosting provider name as listed.
    pub provider: String,
}

impl Relay {
    /// Entry address of `family`, if the relay has one.
    pub fn entry(&self, family: Family) -> Option<IpAddr> {
        match family {
            Family::V4 => Some(IpAddr::V4(self.ipv4)),
            Family::V6 => self.ipv6.map(IpAddr::V6),
        }
    }
}

/// Catalog-wide `WireGuard` settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardNetwork {
    pub port_ranges: Vec<(u16, u16)>,
    /// The port profiles use (see [`WIREGUARD_PORT`]).
    pub port: u16,
    /// The relay-side gateway, which is also Mullvad's in-tunnel DNS resolver (`10.64.0.1`).
    pub ipv4_gateway: Ipv4Addr,
    pub ipv6_gateway: Option<Ipv6Addr>,
}

/// Public `WireGuard` parameters of a profile for one device on one relay. The private key stays
/// with the caller (Store); the interface public key is the device's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardParams {
    /// Interface addresses: the device's IPv4 and, when assigned, IPv6.
    pub addresses: Vec<IpNetwork>,
    /// In-tunnel DNS: the catalog's `ipv4_gateway`, as the previous implementation used
    /// (`relays.mjs` `normalizeCatalog`: `dns: [ipv4_gateway]`).
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
    pub peer_public_key: WgKey,
    /// Numeric `IP:port`: the relay's entry address and the catalog's `WireGuard` port.
    pub endpoint: SocketAddr,
    /// `0.0.0.0/0` and `::/0`: everything goes through the tunnel.
    pub allowed_ips: Vec<IpNetwork>,
    /// None, as before: Mullvad needs no keepalive for outbound use.
    pub persistent_keepalive: Option<u16>,
}

/// The website relay list's multihop port of each relay, with the key and entry address the list
/// gives it — a port is used only for a relay whose key and address match the catalog's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MultihopPorts {
    by_host: HashMap<String, MultihopPort>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MultihopPort {
    port: u16,
    public_key: WgKey,
    ipv4: Ipv4Addr,
}

impl MultihopPorts {
    /// The port that reaches `exit` as a multihop exit: the list's port for its hostname, when
    /// the list gives it the catalog's key and entry address. `None` otherwise — the relay cannot
    /// be a multihop exit now (never another relay's port).
    #[must_use]
    pub fn port_of(&self, exit: &Relay) -> Option<u16> {
        self.by_host
            .get(&exit.hostname)
            .filter(|p| p.public_key == exit.public_key && p.ipv4 == exit.ipv4)
            .map(|p| p.port)
    }

    /// Relays the list gave a port.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_host.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_host.is_empty()
    }
}

#[derive(Deserialize)]
struct RawWwwRelay {
    hostname: String,
    ipv4_addr_in: Ipv4Addr,
    pubkey: String,
    #[serde(default)]
    multihop_port: Option<u16>,
}

/// The website relay list (`/www/relays/wireguard/`): a JSON array of relays.
///
/// A relay without a port, with an invalid name or key, or sharing its port with another relay
/// is left out (a shared port could reach either); the rest are usable.
///
/// # Errors
///
/// [`ProviderError::ContractDrift`] when the answer is not such an array or is beyond the bounds.
pub fn parse_multihop(body: &[u8]) -> Result<MultihopPorts, ProviderError> {
    let drift = || {
        ProviderError::ContractDrift(tr!(
            "multihop server list",
            "多跳的伺服器清單",
            "マルチホップのサーバー一覧"
        ))
    };
    let raw: Vec<RawWwwRelay> = serde_json::from_slice(body).map_err(|_| drift())?;
    if raw.len() > MAX_RELAYS {
        return Err(drift());
    }
    let mut by_host: HashMap<String, MultihopPort> = HashMap::with_capacity(raw.len());
    let mut owners: HashMap<u16, usize> = HashMap::new();
    for relay in &raw {
        if let Some(port) = relay.multihop_port.filter(|p| *p != 0) {
            *owners.entry(port).or_default() += 1;
        }
    }
    for relay in raw {
        let Some(port) = relay.multihop_port.filter(|p| owners.get(p) == Some(&1)) else {
            continue;
        };
        let Ok(public_key) = relay.pubkey.parse::<WgKey>() else {
            continue;
        };
        if !valid_hostname(&relay.hostname) || is_special(IpAddr::V4(relay.ipv4_addr_in)) {
            continue;
        }
        let entry = MultihopPort {
            port,
            public_key,
            ipv4: relay.ipv4_addr_in,
        };
        // A hostname listed twice is ambiguous: neither is used.
        if by_host.insert(relay.hostname.clone(), entry).is_some() {
            by_host.insert(relay.hostname, MultihopPort { port: 0, ..entry });
        }
    }
    by_host.retain(|_, p| p.port != 0);
    Ok(MultihopPorts { by_host })
}

/// Parameters for `device` entering at relay `entry` and leaving at relay `exit` (Mullvad
/// multihop).
///
/// The endpoint is `entry`'s IPv4 address on `exit_port` — the exit relay's multihop port, from
/// [`MultihopPorts::port_of`] for this `exit` — and the key is `exit`'s. Interface addresses,
/// DNS and routes are as for one relay.
#[must_use]
pub fn multihop_params(
    device: &Device,
    entry: &Relay,
    exit: &Relay,
    exit_port: u16,
    network: &WireGuardNetwork,
) -> WireGuardParams {
    let mut addresses = vec![IpNetwork::V4(device.ipv4_address)];
    addresses.extend(device.ipv6_address.map(IpNetwork::V6));
    WireGuardParams {
        addresses,
        dns: vec![IpAddr::V4(network.ipv4_gateway)],
        mtu: MTU,
        peer_public_key: exit.public_key,
        endpoint: SocketAddr::new(IpAddr::V4(entry.ipv4), exit_port),
        allowed_ips: vec![IpNetwork::V4(ANY_V4), IpNetwork::V6(ANY_V6)],
        persistent_keepalive: None,
    }
}

/// Parameters for `device` on `relay`, entering over `endpoint`.
///
/// `None` when the relay has no entry address of that family. Pure: the caller must take `relay` and `network` from a
/// freshly fetched catalog (never from user input) and must hold the private key whose public
/// key is `device.pubkey`.
pub fn wireguard_params(
    device: &Device,
    relay: &Relay,
    network: &WireGuardNetwork,
    endpoint: Family,
) -> Option<WireGuardParams> {
    let entry = relay.entry(endpoint)?;
    let mut addresses = vec![IpNetwork::V4(device.ipv4_address)];
    addresses.extend(device.ipv6_address.map(IpNetwork::V6));
    Some(WireGuardParams {
        addresses,
        dns: vec![IpAddr::V4(network.ipv4_gateway)],
        mtu: MTU,
        peer_public_key: relay.public_key,
        endpoint: SocketAddr::new(entry, network.port),
        allowed_ips: vec![IpNetwork::V4(ANY_V4), IpNetwork::V6(ANY_V6)],
        persistent_keepalive: None,
    })
}

#[derive(Deserialize)]
struct RawCatalog {
    locations: BTreeMap<String, RawLocation>,
    wireguard: RawWireGuard,
}

#[derive(Deserialize)]
struct RawLocation {
    country: String,
    city: String,
}

#[derive(Deserialize)]
struct RawWireGuard {
    port_ranges: Vec<(u16, u16)>,
    ipv4_gateway: Ipv4Addr,
    #[serde(default)]
    ipv6_gateway: Option<Ipv6Addr>,
    relays: Vec<RawRelay>,
}

#[derive(Deserialize)]
struct RawRelay {
    hostname: String,
    location: String,
    active: bool,
    owned: bool,
    provider: String,
    ipv4_addr_in: Ipv4Addr,
    #[serde(default)]
    ipv6_addr_in: Option<Ipv6Addr>,
    public_key: String,
}

/// A listed location with validated codes and names.
struct Place {
    country_code: String,
    country: String,
    city_code: String,
    city: String,
}

/// The catalog answer (`/public/relays/wireguard/v2/`).
///
/// # Errors
///
/// [`ProviderError::ContractDrift`] when a required field is missing or invalid, or the answer
/// is beyond the bounds.
pub fn parse_catalog(body: &[u8]) -> Result<RelayCatalog, ProviderError> {
    let drift = || ProviderError::ContractDrift(tr!("server list", "伺服器清單", "サーバー一覧"));
    let raw: RawCatalog = serde_json::from_slice(body).map_err(|_| drift())?;
    let RawWireGuard {
        port_ranges,
        ipv4_gateway,
        ipv6_gateway,
        relays,
    } = raw.wireguard;
    let ranges_valid = (1..=MAX_PORT_RANGES).contains(&port_ranges.len())
        && port_ranges.iter().all(|&(lo, hi)| lo > 0 && lo <= hi);
    let gateways_valid = !is_special(IpAddr::V4(ipv4_gateway))
        && ipv6_gateway.is_none_or(|ip| !is_special(IpAddr::V6(ip)));
    if raw.locations.len() > MAX_LOCATIONS
        || relays.len() > MAX_RELAYS
        || !ranges_valid
        || !gateways_valid
    {
        return Err(drift());
    }

    let mut places = BTreeMap::new();
    for (code, location) in raw.locations {
        let Some((country_code, city_code)) = split_location(&code) else {
            continue;
        };
        let name = |s: &str| display_text(s, MAX_NAME).ok().flatten().ok_or_else(drift);
        let place = Place {
            country_code: country_code.to_owned(),
            country: name(&location.country)?,
            city_code: city_code.to_owned(),
            city: name(&location.city)?,
        };
        places.insert(code, place);
    }

    let mut hostnames = HashSet::with_capacity(relays.len());
    let mut kept = Vec::with_capacity(relays.len());
    let mut skipped = 0;
    for relay in relays {
        if !valid_hostname(&relay.hostname) || !hostnames.insert(relay.hostname.clone()) {
            return Err(drift());
        }
        let public_key: WgKey = relay.public_key.parse().map_err(|_| drift())?;
        let provider = display_text(&relay.provider, MAX_NAME)
            .map_err(|_| drift())?
            .unwrap_or_default();
        let Some(place) = places.get(&relay.location) else {
            skipped += 1;
            continue;
        };
        if is_special(IpAddr::V4(relay.ipv4_addr_in)) {
            skipped += 1;
            continue;
        }
        kept.push(Relay {
            hostname: relay.hostname,
            location: relay.location,
            country_code: place.country_code.clone(),
            country: place.country.clone(),
            city_code: place.city_code.clone(),
            city: place.city.clone(),
            ipv4: relay.ipv4_addr_in,
            ipv6: relay.ipv6_addr_in.filter(|ip| !is_special(IpAddr::V6(*ip))),
            public_key,
            active: relay.active,
            owned: relay.owned,
            provider,
        });
    }
    kept.sort_by(|a, b| a.hostname.cmp(&b.hostname));

    let countries = countries(&places);
    let port = profile_port(&port_ranges);
    Ok(RelayCatalog {
        countries,
        relays: kept,
        network: WireGuardNetwork {
            port_ranges,
            port,
            ipv4_gateway,
            ipv6_gateway,
        },
        skipped,
    })
}

/// The catalog's countries, each with its cities, in code order.
fn countries(places: &BTreeMap<String, Place>) -> Vec<Country> {
    let mut countries: BTreeMap<&str, Country> = BTreeMap::new();
    for place in places.values() {
        countries
            .entry(place.country_code.as_str())
            .or_insert_with(|| Country {
                code: place.country_code.clone(),
                name: place.country.clone(),
                cities: Vec::new(),
            })
            .cities
            .push(City {
                code: place.city_code.clone(),
                name: place.city.clone(),
            });
    }
    countries.into_values().collect()
}

/// [`WIREGUARD_PORT`] when `port_ranges` include it, otherwise the first port of the first range.
fn profile_port(port_ranges: &[(u16, u16)]) -> u16 {
    if port_ranges
        .iter()
        .any(|&(lo, hi)| (lo..=hi).contains(&WIREGUARD_PORT))
    {
        WIREGUARD_PORT
    } else {
        port_ranges.first().map_or(WIREGUARD_PORT, |&(lo, _)| lo)
    }
}

/// `cc-city`: a two-letter country code and a 2–12 character city code, as the official app
/// splits location codes.
fn split_location(code: &str) -> Option<(&str, &str)> {
    let (country, city) = code.split_once('-')?;
    let country_ok = country.len() == 2 && country.bytes().all(|b| b.is_ascii_lowercase());
    let city_ok = (2..=12).contains(&city.len())
        && city
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    (country_ok && city_ok).then_some((country, city))
}

/// Relay hostnames are DNS labels (`se-got-wg-001`); they become profile server IDs.
fn valid_hostname(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
