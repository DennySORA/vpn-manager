// SPDX-License-Identifier: GPL-3.0-or-later

//! The `WireGuard` server catalog of `act=manifest`, and the `WireGuard` parameters of a profile
//! built from it.
//!
//! Eddie (`Service.cs`): a server's attributes default to those of its `servers_group` (matched
//! on `group`); a `WireGuard` mode names a port and an `entry_index`, which selects the n-th IPv4
//! and, separately, the n-th IPv6 address of the server's `ips_entry` (`GetV4ByIndex`,
//! `GetV6ByIndex`). A server without that entry does not support the mode and no other address
//! is substituted. As in the previous implementation (`bootstrap.mjs`, `parseManifest`) the first
//! UDP `WireGuard` mode is the one used by default; unlike it, IPv6 entry addresses are kept.
//!
//! A connection may also enter at another of the server's `WireGuard` entries — any UDP
//! `WireGuard` mode the manifest lists ([`ServerCatalog::modes`]), on the server's address at that
//! mode's index ([`Server::endpoint_at`]). `AirVPN` has no multihop: every entry is the exit
//! server's own, and traffic leaves it from its exit addresses (`ips_exit`).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use vpn_domain::validation::{is_private, is_special};
use vpn_domain::{WgKey, tr};

use super::user::{Device, UserInfo};
use super::xml::{Document, Element};
use crate::error::ProviderError;
use crate::https::Family;

/// MTU of `AirVPN` profiles: Eddie's `WireGuard` default.
///
/// `ProfileOptions.cs` has `wireguard.interface.mtu = -1`, which `ConfigBuilder/WireGuard.cs` turns into 1320), as the
/// previous implementation used (`service.mjs`, `AIRVPN_MTU`).
pub const MTU: u16 = 1320;
/// Eddie's `wireguard.peer.persistentkeepalive` default (`ProfileOptions.cs`), as the previous
/// implementation used (`service.mjs`, `AIRVPN_KEEPALIVE`).
pub const PERSISTENT_KEEPALIVE: u16 = 15;

const MAX_SERVERS: usize = 2048;
const MAX_MODES: usize = 256;
/// The previous implementation's bound.
const MAX_ENTRY_INDEX: usize = 16;
const MAX_ENTRIES: usize = 64;
const MAX_NAME: usize = 63;
/// The previous implementation's bounds on display text.
const MAX_LOCATION: usize = 96;
const MAX_WARNING: usize = 160;
/// Eddie's `users_max` default.
const USERS_MAX: u128 = 100;

fn manifest_drift() -> ProviderError {
    ProviderError::ContractDrift(tr!("server list", "伺服器清單", "サーバー一覧"))
}

fn modes_drift() -> ProviderError {
    ProviderError::ContractDrift(tr!(
        "WireGuard connection modes",
        "WireGuard 連線模式",
        "WireGuard の接続モード"
    ))
}

fn entries_drift() -> ProviderError {
    ProviderError::ContractDrift(tr!(
        "server entry addresses",
        "伺服器進入位址",
        "サーバーの入口アドレス"
    ))
}

const ANY_V4: Ipv4Network = match Ipv4Network::new_checked(Ipv4Addr::UNSPECIFIED, 0) {
    Some(net) => net,
    None => panic!("0.0.0.0/0 is a valid network"),
};
const ANY_V6: Ipv6Network = match Ipv6Network::new_checked(Ipv6Addr::UNSPECIFIED, 0) {
    Some(net) => net,
    None => panic!("::/0 is a valid network"),
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCatalog {
    /// Servers with a public entry address for [`ServerCatalog::entry_index`], sorted by name.
    pub servers: Vec<Server>,
    /// Every UDP `WireGuard` mode in the manifest's order, without repeats: the first is the
    /// default ([`ServerCatalog::port`], [`ServerCatalog::entry_index`]).
    pub modes: Vec<EntryMode>,
    /// The ports of the UDP `WireGuard` modes on [`ServerCatalog::entry_index`], ascending: each
    /// reaches the same servers on the same entry addresses.
    pub ports: Vec<u16>,
    /// The port profiles use: the first UDP `WireGuard` mode's.
    pub port: u16,
    /// The first UDP `WireGuard` mode's `entry_index`.
    pub entry_index: usize,
    /// Servers left out because they have no public entry address of either family at
    /// `entry_index`. Worth logging; the rest of the catalog is usable.
    pub skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// `AirVPN`'s server name in lower case (`alchiba`); the profile's server ID.
    pub name: String,
    /// ISO 3166-1 alpha-2, upper case (`CH`).
    pub country_code: String,
    /// City as `AirVPN` writes it.
    pub location: Option<String>,
    /// Load in percent (Eddie's figure, see `load`).
    pub load: Option<u8>,
    pub warning: Option<ServerWarning>,
    /// Entry addresses at the catalog's `entry_index`; at least one is present.
    pub entry_v4: Option<Ipv4Addr>,
    pub entry_v6: Option<Ipv6Addr>,
    /// The catalog's [`ServerCatalog::port`], so a server alone gives an endpoint.
    pub port: u16,
    /// Every entry address of each family by its index (`ips_entry` order); `None` where the
    /// listed address is not public.
    pub entries_v4: Vec<Option<Ipv4Addr>>,
    pub entries_v6: Vec<Option<Ipv6Addr>>,
    /// The first public exit address of each family (`ips_exit`), when listed.
    pub exit_v4: Option<Ipv4Addr>,
    pub exit_v6: Option<Ipv6Addr>,
}

/// One UDP `WireGuard` mode: a port and the index of the entry address it uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryMode {
    pub port: u16,
    pub entry_index: usize,
}

/// A notice `AirVPN` attaches to a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerWarning {
    /// `warning_open`: usable, with a notice (Eddie shows a warning).
    Open(String),
    /// `warning_closed`: closed; Eddie treats it as an error and does not connect.
    Closed(String),
}

impl Server {
    /// Entry address of `family`, if the server has one.
    pub fn entry(&self, family: Family) -> Option<IpAddr> {
        match family {
            Family::V4 => self.entry_v4.map(IpAddr::V4),
            Family::V6 => self.entry_v6.map(IpAddr::V6),
        }
    }

    /// Numeric `IP:port` of `family`, if the server has an entry address of it.
    #[must_use]
    pub fn endpoint(&self, family: Family) -> Option<SocketAddr> {
        self.entry(family).map(|ip| SocketAddr::new(ip, self.port))
    }

    /// Numeric `IP:port` of `family` for `mode`: the server's public entry address at the mode's
    /// index on its port, if it has one.
    #[must_use]
    pub fn endpoint_at(&self, family: Family, mode: EntryMode) -> Option<SocketAddr> {
        let ip = match family {
            Family::V4 => self
                .entries_v4
                .get(mode.entry_index)
                .copied()
                .flatten()
                .map(IpAddr::V4),
            Family::V6 => self
                .entries_v6
                .get(mode.entry_index)
                .copied()
                .flatten()
                .map(IpAddr::V6),
        }?;
        Some(SocketAddr::new(ip, mode.port))
    }
}

/// Public `WireGuard` parameters of a profile for one device on one server. The device's private
/// key and preshared key go to the vault ([`Device::private_key`], [`Device::preshared_key`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardParams {
    /// The device's IPv4 address and, when `AirVPN` assigned one, its IPv6 address.
    pub addresses: Vec<IpNetwork>,
    /// The device's IPv4 resolver, and its IPv6 resolver when it also has an IPv6 address.
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
    /// The account's `wg_public_key`.
    pub peer_public_key: WgKey,
    /// The server's entry address of the requested family and the catalog's port.
    pub endpoint: SocketAddr,
    /// `0.0.0.0/0` and `::/0`, as Eddie configures them.
    pub allowed_ips: Vec<IpNetwork>,
    pub persistent_keepalive: Option<u16>,
    /// Always true: every `AirVPN` device has a preshared key, which the peer must carry.
    pub preshared_key: bool,
}

/// Parameters for `device` (of `account`) on `server`, entering over `family`.
///
/// `None` when the server has no entry address of that family. Pure: the caller takes `server` from a freshly
/// fetched catalog and `device` from the same account's [`UserInfo`].
#[must_use]
pub fn wireguard_params(
    device: &Device,
    server: &Server,
    account: &UserInfo,
    family: Family,
) -> Option<WireGuardParams> {
    Some(params_on(device, server.endpoint(family)?, account))
}

/// [`wireguard_params`] entering at `mode` — one of the catalog's [`ServerCatalog::modes`] — on
/// the server's address at its index.
///
/// `None` when the server has no public entry address of `family` there.
#[must_use]
pub fn wireguard_params_at(
    device: &Device,
    server: &Server,
    account: &UserInfo,
    family: Family,
    mode: EntryMode,
) -> Option<WireGuardParams> {
    Some(params_on(
        device,
        server.endpoint_at(family, mode)?,
        account,
    ))
}

fn params_on(device: &Device, endpoint: SocketAddr, account: &UserInfo) -> WireGuardParams {
    let mut addresses = vec![IpNetwork::V4(device.ipv4)];
    let mut dns = vec![IpAddr::V4(device.dns_v4)];
    if let Some(ipv6) = device.ipv6 {
        addresses.push(IpNetwork::V6(ipv6));
        // An IPv6 resolver is reachable only with an IPv6 tunnel address.
        dns.extend(device.dns_v6.map(IpAddr::V6));
    }
    WireGuardParams {
        addresses,
        dns,
        mtu: MTU,
        peer_public_key: account.peer_public_key,
        endpoint,
        allowed_ips: vec![IpNetwork::V4(ANY_V4), IpNetwork::V6(ANY_V6)],
        persistent_keepalive: Some(PERSISTENT_KEEPALIVE),
        preshared_key: true,
    }
}

/// A server's entry addresses of each family by index (`None` where not public) from its
/// `ips_entry`, and its first public exit address of each family from its `ips_exit`.
type Addresses = (
    Vec<Option<Ipv4Addr>>,
    Vec<Option<Ipv6Addr>>,
    Option<Ipv4Addr>,
    Option<Ipv6Addr>,
);

fn addresses(ips_entry: Option<&str>, ips_exit: Option<&str>) -> Result<Addresses, ProviderError> {
    let list = |value: Option<&str>| {
        value.map_or_else(
            || Ok((Vec::new(), Vec::new())),
            |list| entries(list).ok_or_else(entries_drift),
        )
    };
    let (v4, v6) = list(ips_entry)?;
    let (out4, out6) = list(ips_exit)?;
    Ok((
        v4.iter().map(|ip| public_v4(*ip).then_some(*ip)).collect(),
        v6.iter().map(|ip| public_v6(*ip).then_some(*ip)).collect(),
        out4.into_iter().find(|ip| public_v4(*ip)),
        out6.into_iter().find(|ip| public_v6(*ip)),
    ))
}

pub fn parse_manifest(xml: &str) -> Result<ServerCatalog, ProviderError> {
    let drift = manifest_drift;
    let doc = Document::parse(xml).map_err(|_| drift())?;
    let manifest = doc.root();
    // Eddie `FetchUrls`: an `error` on the document element is the server's refusal; the
    // request's only input of the caller's is the credentials.
    if manifest.raw("error").is_some() {
        return Err(ProviderError::AuthRejected);
    }
    if manifest.name() != "manifest" {
        return Err(drift());
    }
    let modes = wireguard_modes(&doc)?;
    let mode = *modes.first().ok_or_else(modes_drift)?;
    let mut ports: Vec<u16> = modes
        .iter()
        .filter(|m| m.entry_index == mode.entry_index)
        .map(|m| m.port)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    let groups = groups(&doc)?;

    let mut names = HashSet::new();
    let mut servers = Vec::new();
    let mut skipped = 0;
    for (listed, server) in doc.select("servers", "server").enumerate() {
        if listed == MAX_SERVERS {
            return Err(drift());
        }
        let group = groups
            .get(server.get("group").unwrap_or_default().as_ref())
            .copied();
        // Eddie `XmlGetServerAttribute`: the server's own attribute, else its group's.
        let attr = |name: &str| server.get(name).or_else(|| group.and_then(|g| g.get(name)));

        let name = server
            .get("name")
            .map(|n| n.trim().to_ascii_lowercase())
            .filter(|n| valid_name(n))
            .ok_or_else(drift)?;
        if !names.insert(name.clone()) {
            return Err(drift());
        }
        let country_code = attr("country_code")
            .map(|c| c.trim().to_ascii_uppercase())
            .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()))
            .ok_or_else(drift)?;
        let (entries_v4, entries_v6, exit_v4, exit_v6) =
            addresses(attr("ips_entry").as_deref(), attr("ips_exit").as_deref())?;
        let entry_v4 = entries_v4.get(mode.entry_index).copied().flatten();
        let entry_v6 = entries_v6.get(mode.entry_index).copied().flatten();
        if entry_v4.is_none() && entry_v6.is_none() {
            skipped += 1;
            continue;
        }
        let text = |name: &str, max: usize| attr(name).and_then(|value| clean_text(&value, max));
        let warning = text("warning_closed", MAX_WARNING)
            .map(ServerWarning::Closed)
            .or_else(|| text("warning_open", MAX_WARNING).map(ServerWarning::Open));
        // Eddie reads these leniently (`Conversions.ToInt64`); a figure that is not a number
        // is unknown here.
        let number = |name: &str| attr(name).and_then(|value| value.trim().parse::<i64>().ok());
        servers.push(Server {
            name,
            country_code,
            location: text("location", MAX_LOCATION),
            load: load(
                number("bw"),
                number("bw_max"),
                number("users"),
                number("users_max"),
            ),
            warning,
            entry_v4,
            entry_v6,
            port: mode.port,
            entries_v4,
            entries_v6,
            exit_v4,
            exit_v6,
        });
    }
    if servers.is_empty() {
        return Err(drift());
    }
    servers.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(ServerCatalog {
        servers,
        modes,
        ports,
        port: mode.port,
        entry_index: mode.entry_index,
        skipped,
    })
}

/// Every UDP `WireGuard` mode (`//modes/mode`, Eddie `ConnectionMode.ReadXML`) in the manifest's
/// order, without repeats; the first is the default. None at all is contract drift.
fn wireguard_modes(doc: &Document<'_>) -> Result<Vec<EntryMode>, ProviderError> {
    let drift = modes_drift;
    let mut modes: Vec<EntryMode> = Vec::new();
    for mode in doc.select("modes", "mode") {
        let wireguard = mode
            .get("type")
            .is_some_and(|t| t.trim().eq_ignore_ascii_case("wireguard"));
        // WireGuard runs over UDP only; a mode stating another protocol is not one to use.
        let udp = mode.get("protocol").is_none_or(|p| {
            let p = p.trim();
            p.is_empty() || p.eq_ignore_ascii_case("udp")
        });
        if !(wireguard && udp) {
            continue;
        }
        if modes.len() == MAX_MODES {
            return Err(drift());
        }
        let port = mode
            .get("port")
            .and_then(|p| p.trim().parse::<u16>().ok())
            .filter(|&p| p != 0)
            .ok_or_else(drift)?;
        // Eddie's default is entry 0.
        let entry_index = match mode.get("entry_index").filter(|i| !i.trim().is_empty()) {
            Some(index) => index
                .trim()
                .parse::<usize>()
                .ok()
                .filter(|&i| i <= MAX_ENTRY_INDEX)
                .ok_or_else(drift)?,
            None => 0,
        };
        let m = EntryMode { port, entry_index };
        if !modes.contains(&m) {
            modes.push(m);
        }
    }
    if modes.is_empty() {
        return Err(drift());
    }
    Ok(modes)
}

/// `//servers_groups/servers_group` by their `group`. Eddie takes the first of equal groups; two
/// are ambiguous here.
fn groups<'d, 'a>(
    doc: &'d Document<'a>,
) -> Result<HashMap<Cow<'a, str>, &'d Element<'a>>, ProviderError> {
    let mut groups = HashMap::new();
    for group in doc.select("servers_groups", "servers_group") {
        let Some(id) = group.get("group") else {
            continue; // never matched by a server
        };
        if groups.len() == MAX_SERVERS || groups.insert(id, group).is_some() {
            return Err(manifest_drift());
        }
    }
    Ok(groups)
}

/// `ips_entry`: IPv4 and IPv6 addresses separated by commas (or line breaks, which Eddie's
/// `IpAddresses.Add` also splits on); each family in listed order without repeats, as Eddie
/// indexes them. `None` when an item is not an address (Eddie would resolve it as a name).
fn entries(list: &str) -> Option<(Vec<Ipv4Addr>, Vec<Ipv6Addr>)> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let items = list
        .split([',', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty());
    for (n, item) in items.enumerate() {
        if n == MAX_ENTRIES {
            return None;
        }
        match item.parse::<IpAddr>().ok()? {
            IpAddr::V4(ip) if !v4.contains(&ip) => v4.push(ip),
            IpAddr::V6(ip) if !v6.contains(&ip) => v6.push(ip),
            _ => {}
        }
    }
    Some((v4, v6))
}

/// A public address: not special (loopback, multicast, link-local, …) nor private or reserved
/// (RFC 1918, CGNAT, documentation, …). An entry address must be reachable from anywhere.
fn public_v4(ip: Ipv4Addr) -> bool {
    !is_special(IpAddr::V4(ip)) && !is_private(IpAddr::V4(ip))
}

/// IPv6 must also be global unicast (`2000::/3`), which rules out IPv4-mapped addresses.
fn public_v6(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xe000 == 0x2000
        && !is_special(IpAddr::V6(ip))
        && !is_private(IpAddr::V6(ip))
}

/// Server names become profile server IDs: after lower-casing, `[a-z0-9][a-z0-9-]{0,62}` (the
/// previous implementation's rule; `AirVPN` names servers after stars, `Alchiba`).
fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Eddie's load (`ConnectionInfo.GetLoadForList`): twice the current bandwidth `bw` (bytes/s)
/// in Mbit/s against `bw_max` (Mbit/s), at most 100 %. Without bandwidth figures, `users`
/// against `users_max` (Eddie's `UsersPerc`, `users_max` 100 when unset), the previous
/// implementation's fallback. Negative figures (Eddie's "unknown") give `None`.
fn load(
    bw: Option<i64>,
    bw_max: Option<i64>,
    users: Option<i64>,
    users_max: Option<i64>,
) -> Option<u8> {
    let figure = |value: i64| u128::try_from(value).ok();
    // Rounded, at most 100; `None` against a maximum of 0.
    let percent = |value: u128, max: u128| {
        let ratio = (value * 100 + max / 2).checked_div(max)?;
        u8::try_from(ratio.min(100)).ok()
    };
    if let (Some(bw), Some(max)) = (bw, bw_max) {
        return percent(2 * figure(bw)? * 8 / 1_000_000, figure(max)?);
    }
    let max = match users_max {
        Some(max) => figure(max)?,
        None => USERS_MAX,
    };
    percent(figure(users?)?, max)
}

/// Provider text for display (location, warnings): control characters removed, trimmed, at
/// most `max` characters; `None` when nothing is left (the previous implementation's rule).
fn clean_text(value: &str, max: usize) -> Option<String> {
    let kept: String = value.chars().filter(|c| !c.is_control()).collect();
    let kept = kept.trim();
    let end = kept
        .char_indices()
        .nth(max)
        .map_or(kept.len(), |(at, _)| at);
    let text = kept[..end].trim_end();
    (!text.is_empty()).then(|| text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_are_entries() {
        for ip in ["185.100.1.10", "8.8.8.8"] {
            assert!(public_v4(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.0.2.10",
            "224.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "240.0.0.1",
        ] {
            assert!(!public_v4(ip.parse().unwrap()), "{ip}");
        }
        assert!(public_v6("2a00:1111:2222:1::10".parse().unwrap()));
        for ip in [
            "::1",
            "::",
            "fe80::1",
            "fd7d:76ee:e68f:a993::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:185.100.1.10",
            "64:ff9b::1",
        ] {
            assert!(!public_v6(ip.parse().unwrap()), "{ip}");
        }
    }
}
