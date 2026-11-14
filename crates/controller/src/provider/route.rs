//! Where a provider connection enters the provider's network and where it leaves it (使用者
//! 2026-11-07：「幫我在 VPN Manager 增加每個 Provide 應該能選擇入口跟出口」). `server_id` is always
//! the exit; the entry is checked against what the provider supports:
//!
//! - **Mullvad** (multihop): the entry is another relay. The tunnel connects to the entry relay's
//!   IPv4 address on the exit relay's multihop port, with the exit relay's key — Mullvad's
//!   documented scheme. The port is used only when the website's relay list gives it to a relay
//!   with the catalog's key and address (`MultihopPorts::port_of`), so a stale or shared port
//!   never sends the tunnel to another relay than the one shown.
//! - **`AirVPN`** (no multihop): the entry is one of the exit server's own `WireGuard` entries — an
//!   entry address and a UDP port that the manifest lists and the TLS-verified status list
//!   confirms for that server.
//! - Others: no provider flow; an imported profile's `.conf` decides.

use vpn_domain::{ApiError, ProfileEntry, ProviderEntryInput, ProviderServerEntry, tr};
use vpn_providers::Family;
use vpn_providers::airvpn::{self, EntryMode};
use vpn_providers::mullvad::{self, MultihopPorts, Relay, RelayCatalog};

use super::field_error;

/// The relays a Mullvad profile uses: its exit, and the entry relay with the exit's multihop port
/// when it enters elsewhere.
pub struct MullvadRoute<'c> {
    pub exit: &'c Relay,
    pub entry: Option<(&'c Relay, u16)>,
}

/// The route `exit_id` and `entry` name in `catalog`, checked: both relays listed and active, the
/// entry another relay than the exit (the same one is no multihop) over IPv4, and the exit's
/// multihop port confirmed by `ports`.
///
/// # Errors
///
/// A field error naming what cannot be used.
pub fn mullvad<'c>(
    catalog: &'c RelayCatalog,
    ports: Option<&MultihopPorts>,
    exit_id: &str,
    entry: Option<&ProviderEntryInput>,
    family: Family,
) -> Result<MullvadRoute<'c>, ApiError> {
    let relay = |id: &str, path: &str| {
        let r = catalog
            .relays
            .iter()
            .find(|r| r.hostname == id)
            .ok_or_else(|| {
                field_error(
                    path,
                    tr!(
                        "This server was not found",
                        "找不到這台伺服器",
                        "このサーバーが見つかりません"
                    ),
                )
            })?;
        if r.active {
            Ok(r)
        } else {
            Err(field_error(
                path,
                tr!(
                    "This server is disabled right now",
                    "這台伺服器目前停用",
                    "このサーバーは現在無効です"
                ),
            ))
        }
    };
    let exit = relay(exit_id, "/server_id")?;
    let entry_id = match entry {
        None => return Ok(MullvadRoute { exit, entry: None }),
        Some(ProviderEntryInput::Relay { server_id }) if server_id == exit_id => {
            return Ok(MullvadRoute { exit, entry: None });
        }
        Some(ProviderEntryInput::Relay { server_id }) => server_id,
        Some(ProviderEntryInput::Address { .. }) => {
            return Err(field_error(
                "/entry",
                tr!(
                    "Mullvad's entry is another server (multihop), not an address of the same server",
                    "Mullvad 的入口是另一台伺服器（多跳），不是同一台伺服器的位址",
                    "Mullvad の入口は別のサーバー（マルチホップ）で、同じサーバーのアドレスではありません"
                ),
            ));
        }
    };
    let entering = relay(entry_id, "/entry/server_id")?;
    if family != Family::V4 {
        return Err(field_error(
            "/endpoint_family",
            tr!(
                "Multihop goes only through the entry server's IPv4 address (as Mullvad documents it); use IPv4 instead",
                "多跳只經入口伺服器的 IPv4 位址（Mullvad 的說明）；請改用 IPv4",
                "マルチホップは入口サーバーの IPv4 アドレスだけを経由します（Mullvad の説明）。IPv4 を使ってください"
            ),
        ));
    }
    let port = ports.and_then(|p| p.port_of(exit)).ok_or_else(|| {
        field_error(
            "/server_id",
            tr!(
                "Mullvad's server list does not confirm this exit server's multihop port (or it does not match its key or address), so multihop through it is not possible now",
                "Mullvad 的伺服器清單沒有確認這台出口伺服器的多跳埠（或與它的金鑰、位址不符），現在不能經它多跳",
                "Mullvad のサーバー一覧でこの出口サーバーのマルチホップ用ポートが確認できない（または鍵やアドレスと一致しない）ため、現在このサーバーを経由するマルチホップはできません"
            ),
        )
    })?;
    Ok(MullvadRoute {
        exit,
        entry: Some((entering, port)),
    })
}

/// The parameters of `route` for `device` over `family` (`None`: the relay has no entry address
/// of that family).
pub fn mullvad_params(
    device: &mullvad::Device,
    route: &MullvadRoute<'_>,
    network: &mullvad::WireGuardNetwork,
    family: Family,
) -> Option<mullvad::WireGuardParams> {
    match route.entry {
        None => mullvad::wireguard_params(device, route.exit, network, family),
        Some((entry, port)) => Some(mullvad::multihop_params(
            device, entry, route.exit, port, network,
        )),
    }
}

/// What a profile records of `route`'s entry (`None`: it enters at its exit).
pub fn mullvad_entry(route: &MullvadRoute<'_>) -> Option<ProfileEntry> {
    route.entry.map(|(entry, _)| ProfileEntry::Relay {
        server_id: entry.hostname.clone(),
        country_code: Some(entry.country_code.to_ascii_uppercase()),
        country: Some(entry.country.clone()),
        city: Some(entry.city.clone()),
    })
}

/// The `AirVPN` entry `entry` names on `server`, checked: one of `modes` (the manifest's UDP
/// `WireGuard` modes) at which `server` has a confirmed address of `family`. `None`: the server's
/// default entry (none named, or the default named).
///
/// # Errors
///
/// A field error naming what cannot be used.
pub fn airvpn(
    modes: &[EntryMode],
    server: &airvpn::Server,
    entry: Option<&ProviderEntryInput>,
    family: Family,
) -> Result<Option<EntryMode>, ApiError> {
    let (index, port) = match entry {
        None => return Ok(None),
        Some(ProviderEntryInput::Address { index, port }) => (usize::from(*index), *port),
        Some(ProviderEntryInput::Relay { .. }) => {
            return Err(field_error(
                "/entry",
                tr!(
                    "AirVPN has no multihop: the entry and the exit are the same server, so only its entry address and port can be chosen",
                    "AirVPN 沒有多跳：入口與出口是同一台伺服器，只能選它的入口位址與埠",
                    "AirVPN にはマルチホップがありません。入口と出口は同じサーバーなので、選べるのはその入口のアドレスとポートだけです"
                ),
            ));
        }
    };
    let mode = EntryMode {
        port,
        entry_index: index,
    };
    if !modes.contains(&mode) {
        return Err(field_error(
            "/entry",
            tr!(
                "AirVPN's server list has no such entry (address and port combination)",
                "AirVPN 的伺服器清單沒有這個入口（位址與埠的組合）",
                "AirVPN のサーバー一覧にこの入口（アドレスとポートの組み合わせ）はありません"
            ),
        ));
    }
    if server.endpoint_at(family, mode).is_none() {
        return Err(field_error(
            "/entry",
            tr!(
                "This server has no address at this entry that AirVPN's official list confirms (or none of this IP version)",
                "這台伺服器在這個入口沒有經 AirVPN 官方清單確認的位址（或沒有這個 IP 版本）",
                "このサーバーには、この入口で AirVPN の公式一覧が確認したアドレスがありません（またはこの IP バージョンのアドレスがありません）"
            ),
        ));
    }
    Ok((modes.first() != Some(&mode)).then_some(mode))
}

/// The parameters for `device` (of `account`) on `server` at `mode` (`None`: the default entry)
/// over `family`; `None` when the server has no confirmed address of `family` there.
pub fn airvpn_params(
    device: &airvpn::Device,
    server: &airvpn::Server,
    account: &airvpn::UserInfo,
    family: Family,
    mode: Option<EntryMode>,
) -> Option<airvpn::WireGuardParams> {
    mode.map_or_else(
        || airvpn::wireguard_params(device, server, account, family),
        |m| airvpn::wireguard_params_at(device, server, account, family, m),
    )
}

/// What a profile records of an `AirVPN` entry (`None`: the default).
pub fn airvpn_entry(mode: Option<EntryMode>) -> Option<ProfileEntry> {
    mode.and_then(|m| {
        Some(ProfileEntry::Address {
            index: u8::try_from(m.entry_index).ok()?,
            port: m.port,
        })
    })
}

/// `server`'s `WireGuard` entries as the API lists them: each of `modes` at which it has a
/// confirmed address, the default first.
pub fn airvpn_entries(modes: &[EntryMode], server: &airvpn::Server) -> Vec<ProviderServerEntry> {
    modes
        .iter()
        .enumerate()
        .filter_map(|(n, m)| {
            let ipv4 = server
                .endpoint_at(Family::V4, *m)
                .map(|a| a.ip().to_string());
            let ipv6 = server
                .endpoint_at(Family::V6, *m)
                .map(|a| a.ip().to_string());
            if ipv4.is_none() && ipv6.is_none() {
                return None;
            }
            Some(ProviderServerEntry {
                index: u8::try_from(m.entry_index).ok()?,
                port: m.port,
                ipv4,
                ipv6,
                default: n == 0,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! The entry/exit choice never sends a tunnel to another peer than the one shown: Mullvad's
    //! multihop endpoint is the entry relay's address on the exit relay's own port with the exit
    //! relay's key, and a port that the list does not tie to the exit's key and address is never
    //! used; an `AirVPN` entry the status list did not confirm, or a mode the manifest does not
    //! list, is refused.

    use std::assert_matches;
    use std::net::{Ipv4Addr, SocketAddr};

    use vpn_domain::{ErrorCode, ProviderEntryInput, Timestamp, WgKey};
    use vpn_providers::Family;
    use vpn_providers::airvpn::{EntryMode, Server};
    use vpn_providers::mullvad::{self, Device, DeviceId, parse_multihop};

    fn b64(n: u8) -> String {
        WgKey([n; 32]).to_string()
    }

    /// Three relays: `se-got-wg-001` (entry), `jp-tyo-wg-001` (exit), `ch-zrh-wg-001` (the
    /// website list gives it another key: stale), and `us-nyc-wg-001` (inactive).
    fn catalog() -> mullvad::RelayCatalog {
        let relay = |host: &str, loc: &str, ip: &str, k: u8, active: bool| {
            format!(
                r#"{{"hostname":"{host}","location":"{loc}","active":{active},"owned":true,"provider":"x","ipv4_addr_in":"{ip}","public_key":"{}"}}"#,
                b64(k)
            )
        };
        let body = format!(
            r#"{{"locations":{{"se-got":{{"country":"Sweden","city":"Gothenburg"}},"jp-tyo":{{"country":"Japan","city":"Tokyo"}},"ch-zrh":{{"country":"Switzerland","city":"Zurich"}},"us-nyc":{{"country":"USA","city":"New York"}}}},
               "wireguard":{{"port_ranges":[[51820,51820]],"ipv4_gateway":"10.64.0.1","relays":[{},{},{},{}]}}}}"#,
            relay("se-got-wg-001", "se-got", "185.213.154.66", 1, true),
            relay("jp-tyo-wg-001", "jp-tyo", "185.209.196.70", 2, true),
            relay("ch-zrh-wg-001", "ch-zrh", "193.32.127.66", 3, true),
            relay("us-nyc-wg-001", "us-nyc", "146.70.165.2", 4, false),
        );
        mullvad::parse_catalog(body.as_bytes()).unwrap()
    }

    fn ports() -> mullvad::MultihopPorts {
        let www = |host: &str, ip: &str, k: u8, port: u16| {
            format!(
                r#"{{"hostname":"{host}","ipv4_addr_in":"{ip}","pubkey":"{}","multihop_port":{port}}}"#,
                b64(k)
            )
        };
        let body = format!(
            "[{},{},{},{}]",
            www("se-got-wg-001", "185.213.154.66", 1, 3001),
            www("jp-tyo-wg-001", "185.209.196.70", 2, 3002),
            // Another key than the catalog's: its port is not used.
            www("ch-zrh-wg-001", "193.32.127.66", 9, 3003),
            www("us-nyc-wg-001", "146.70.165.2", 4, 3004),
        );
        parse_multihop(body.as_bytes()).unwrap()
    }

    fn device() -> Device {
        Device {
            id: DeviceId::parse("d1").unwrap(),
            name: "calm heron".into(),
            pubkey: WgKey([7; 32]),
            ipv4_address: "10.64.0.2/32".parse().unwrap(),
            ipv6_address: None,
            created: Timestamp::now(),
        }
    }

    fn relay(server_id: &str) -> ProviderEntryInput {
        ProviderEntryInput::Relay {
            server_id: server_id.into(),
        }
    }

    #[test]
    fn multihop_enters_at_the_entry_on_the_exits_port_with_the_exits_key() {
        let (catalog, ports) = (catalog(), ports());
        let entry = relay("se-got-wg-001");
        let route = super::mullvad(
            &catalog,
            Some(&ports),
            "jp-tyo-wg-001",
            Some(&entry),
            Family::V4,
        )
        .unwrap();
        let p = super::mullvad_params(&device(), &route, &catalog.network, Family::V4).unwrap();
        assert_eq!(
            p.endpoint,
            SocketAddr::new(Ipv4Addr::new(185, 213, 154, 66).into(), 3002),
            "the entry relay's address on the exit relay's multihop port"
        );
        assert_eq!(p.peer_public_key, WgKey([2; 32]), "the exit relay's key");
        assert_matches!(super::mullvad_entry(&route),
            Some(vpn_domain::ProfileEntry::Relay { server_id, .. }) if server_id == "se-got-wg-001");

        // The same relay as entry and exit is no multihop: its own address, the standard port.
        let same = relay("jp-tyo-wg-001");
        let route = super::mullvad(
            &catalog,
            Some(&ports),
            "jp-tyo-wg-001",
            Some(&same),
            Family::V4,
        )
        .unwrap();
        assert!(route.entry.is_none());
        let p = super::mullvad_params(&device(), &route, &catalog.network, Family::V4).unwrap();
        assert_eq!(
            p.endpoint,
            SocketAddr::new(Ipv4Addr::new(185, 209, 196, 70).into(), 51820)
        );
    }

    #[test]
    fn a_port_not_tied_to_the_exits_key_and_address_is_never_used() {
        let (catalog, ports) = (catalog(), ports());
        let entry = relay("se-got-wg-001");
        let refused = |exit: &str, entry: &ProviderEntryInput, family, ports| {
            let e = super::mullvad(&catalog, ports, exit, Some(entry), family)
                .err()
                .unwrap();
            assert_eq!(e.code, ErrorCode::ValidationFailed, "{exit}");
        };
        // The website list gives the exit another key: stale, not used.
        refused("ch-zrh-wg-001", &entry, Family::V4, Some(&ports));
        // No list at all.
        refused("jp-tyo-wg-001", &entry, Family::V4, None);
        // Multihop only over IPv4; an inactive entry or exit; an unknown entry.
        refused("jp-tyo-wg-001", &entry, Family::V6, Some(&ports));
        refused(
            "jp-tyo-wg-001",
            &relay("us-nyc-wg-001"),
            Family::V4,
            Some(&ports),
        );
        refused("us-nyc-wg-001", &entry, Family::V4, Some(&ports));
        refused(
            "jp-tyo-wg-001",
            &relay("xx-nowhere-wg-001"),
            Family::V4,
            Some(&ports),
        );
        // An AirVPN-style entry is not Mullvad's.
        refused(
            "jp-tyo-wg-001",
            &ProviderEntryInput::Address {
                index: 0,
                port: 51820,
            },
            Family::V4,
            Some(&ports),
        );
        // Two relays sharing a port: neither gets one.
        let shared = parse_multihop(
            format!(
                r#"[{{"hostname":"se-got-wg-001","ipv4_addr_in":"185.213.154.66","pubkey":"{}","multihop_port":3009}},
                   {{"hostname":"jp-tyo-wg-001","ipv4_addr_in":"185.209.196.70","pubkey":"{}","multihop_port":3009}}]"#,
                b64(1),
                b64(2)
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(shared.is_empty());
        refused("jp-tyo-wg-001", &entry, Family::V4, Some(&shared));
    }

    fn air_server() -> Server {
        Server {
            name: "arber".into(),
            country_code: "GB".into(),
            location: Some("London".into()),
            load: None,
            warning: None,
            entry_v4: Some(Ipv4Addr::new(141, 98, 100, 146)),
            entry_v6: None,
            port: 1637,
            // The third address was not confirmed by the status list.
            entries_v4: vec![
                Some(Ipv4Addr::new(141, 98, 100, 146)),
                Some(Ipv4Addr::new(141, 98, 100, 147)),
                None,
            ],
            entries_v6: Vec::new(),
            exit_v4: None,
            exit_v6: None,
        }
    }

    #[test]
    fn an_airvpn_entry_is_a_listed_mode_on_a_confirmed_address_of_the_same_server() {
        let modes = [
            EntryMode {
                port: 1637,
                entry_index: 0,
            },
            EntryMode {
                port: 47107,
                entry_index: 0,
            },
            EntryMode {
                port: 1637,
                entry_index: 1,
            },
            EntryMode {
                port: 1637,
                entry_index: 2,
            },
        ];
        let server = air_server();
        let at = |index: u8, port: u16| ProviderEntryInput::Address { index, port };
        let chosen = super::airvpn(&modes, &server, Some(&at(1, 1637)), Family::V4).unwrap();
        assert_eq!(
            chosen,
            Some(EntryMode {
                port: 1637,
                entry_index: 1
            })
        );
        assert_eq!(
            server.endpoint_at(Family::V4, chosen.unwrap()),
            Some(SocketAddr::new(
                Ipv4Addr::new(141, 98, 100, 147).into(),
                1637
            ))
        );
        // The default named is the default (nothing recorded).
        assert_eq!(
            super::airvpn(&modes, &server, Some(&at(0, 1637)), Family::V4).unwrap(),
            None
        );
        // Not a listed mode; an address the status list did not confirm; no IPv6 there; a relay.
        for (entry, family) in [
            (at(1, 47107), Family::V4),
            (at(2, 1637), Family::V4),
            (at(1, 1637), Family::V6),
            (relay("arber"), Family::V4),
        ] {
            assert!(
                super::airvpn(&modes, &server, Some(&entry), family).is_err(),
                "{entry:?}"
            );
        }
        let listed = super::airvpn_entries(&modes, &server);
        assert_eq!(
            listed
                .iter()
                .map(|e| (e.index, e.port, e.default))
                .collect::<Vec<_>>(),
            [(0, 1637, true), (0, 47107, false), (1, 1637, false)],
            "the unconfirmed address is not offered"
        );
    }
}
