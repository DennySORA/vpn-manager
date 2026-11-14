//! Strict parser for `WireGuard` `.conf` files (one Interface, one Peer).
//!
//! Rejects anything that would execute code or change the host (`PostUp`, `PreDown`, ...),
//! hostname endpoints (resolving them would need the host resolver) and duplicate keys.
//! Secret values are returned zeroizing and never appear in errors.

use std::net::{IpAddr, SocketAddr};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ipnetwork::IpNetwork;
use zeroize::Zeroizing;

use crate::common::WgKey;
use crate::tr;
use crate::validation::ValidationReport;

pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// Parsed configuration; the two secrets are kept apart from the public fields.
pub struct ParsedConfig {
    pub private_key: Zeroizing<[u8; 32]>,
    pub preshared_key: Option<Zeroizing<[u8; 32]>>,
    pub public: PublicConfig,
}

/// Shows the public part only; the private and preshared keys stay out of logs.
impl std::fmt::Debug for ParsedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedConfig")
            .field("preshared_key", &self.preshared_key.is_some())
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Everything except the secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicConfig {
    pub addresses: Vec<IpNetwork>,
    pub dns: Vec<IpAddr>,
    /// Non-IP `DNS =` entries (search domains) are ignored with a warning.
    pub mtu: Option<u16>,
    pub peer_public_key: WgKey,
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<IpNetwork>,
    pub persistent_keepalive: Option<u16>,
}

const FORBIDDEN: [&str; 6] = [
    "postup",
    "postdown",
    "preup",
    "predown",
    "saveconfig",
    "include",
];
const IGNORED: [&str; 3] = ["listenport", "table", "fwmark"];

fn decode_key(value: &str) -> Option<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(B64.decode(value.trim()).ok()?);
    let mut key = Zeroizing::new([0u8; 32]);
    if bytes.len() != 32 {
        return None;
    }
    key.copy_from_slice(&bytes);
    if *key == [0u8; 32] {
        return None;
    }
    Some(key)
}

fn split_list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// The section a line of a configuration belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

/// The values a configuration has set so far.
#[derive(Default)]
struct Fields {
    private_key: Option<Zeroizing<[u8; 32]>>,
    preshared_key: Option<Zeroizing<[u8; 32]>>,
    addresses: Vec<IpNetwork>,
    dns: Vec<IpAddr>,
    mtu: Option<u16>,
    peer_public_key: Option<WgKey>,
    endpoint: Option<SocketAddr>,
    allowed_ips: Vec<IpNetwork>,
    keepalive: Option<u16>,
}

impl Fields {
    /// Take one `key = value` line of `section` (located at `at`), reporting what is wrong.
    fn apply(
        &mut self,
        section: Section,
        key: &str,
        value: &str,
        at: &str,
        r: &mut ValidationReport,
    ) {
        let known = match section {
            Section::Interface => self.apply_interface(key, value, at, r),
            Section::Peer => self.apply_peer(key, value, at, r),
            Section::None => {
                r.error(
                    "SYNTAX",
                    at,
                    tr!(
                        "A key must be under [Interface] or [Peer]",
                        "鍵值必須位於 [Interface] 或 [Peer] 之下",
                        "キーは [Interface] か [Peer] の下に置いてください"
                    ),
                );
                true
            }
        };
        if !known {
            r.error(
                "UNKNOWN_KEY",
                at,
                tr!(
                    "Unknown setting “{key}”",
                    "未知的設定「{key}」",
                    "不明な設定です：「{key}」"
                ),
            );
        }
    }

    /// Take one `key = value` line of `[Interface]`; whether the key is one of its keys.
    fn apply_interface(
        &mut self,
        key: &str,
        value: &str,
        at: &str,
        r: &mut ValidationReport,
    ) -> bool {
        match key {
            "privatekey" => match decode_key(value) {
                Some(k) => self.private_key = Some(k),
                None => r.error(
                    "PRIVATE_KEY",
                    at,
                    tr!(
                        "PrivateKey must be 32 bytes in base64 and not all zeros",
                        "PrivateKey 必須是 base64 的 32 bytes 且非全 0",
                        "PrivateKey は base64 の 32 bytes で、すべて 0 ではない値にしてください"
                    ),
                ),
            },
            "address" => {
                for item in split_list(value) {
                    match item.parse::<IpNetwork>() {
                        Ok(n) => self.addresses.push(n),
                        Err(_) => r.error(
                            "ADDRESS",
                            at,
                            tr!(
                                "Invalid address “{item}”",
                                "無效的位址「{item}」",
                                "無効なアドレスです：「{item}」"
                            ),
                        ),
                    }
                }
            }
            "dns" => {
                for item in split_list(value) {
                    match item.parse::<IpAddr>() {
                        Ok(ip) => self.dns.push(ip),
                        Err(_) => {
                            r.warning(
                                "DNS_SEARCH",
                                at,
                                tr!(
                                    "Ignored the DNS entry “{item}”, which is not an IP",
                                    "忽略非 IP 的 DNS 項目「{item}」",
                                    "IP ではない DNS の項目「{item}」を無視しました"
                                ),
                            );
                        }
                    }
                }
            }
            "mtu" => match value.parse::<u16>() {
                Ok(v) => self.mtu = Some(v),
                Err(_) => r.error(
                    "MTU",
                    at,
                    tr!(
                        "MTU must be an integer",
                        "MTU 必須是整數",
                        "MTU は整数にしてください"
                    ),
                ),
            },
            _ => return false,
        }
        true
    }

    /// Take one `key = value` line of `[Peer]`; whether the key is one of its keys.
    fn apply_peer(&mut self, key: &str, value: &str, at: &str, r: &mut ValidationReport) -> bool {
        match key {
            "publickey" => match value.parse::<WgKey>() {
                Ok(k) => self.peer_public_key = Some(k),
                Err(e) => r.error("PEER_PUBLIC_KEY", at, e.text()),
            },
            "presharedkey" => match decode_key(value) {
                Some(k) => self.preshared_key = Some(k),
                None => r.error(
                    "PRESHARED_KEY",
                    at,
                    tr!("PresharedKey must be 32 bytes in base64 and not all zeros", "PresharedKey 必須是 base64 的 32 bytes 且非全 0", "PresharedKey は base64 の 32 bytes で、すべて 0 ではない値にしてください"),
                ),
            },
            "endpoint" => match value.parse::<SocketAddr>() {
                Ok(sa) => self.endpoint = Some(sa),
                Err(_) => r.error(
                    "ENDPOINT_HOSTNAME",
                    at,
                    tr!("Endpoint must be a numeric IP:port (a host name needs the host's DNS resolver, which leaks and is out of control)", "Endpoint 必須是數字 IP:port（主機名稱需要 host DNS 解析，會洩漏且不受控）", "Endpoint は数値の IP:port にしてください（ホスト名にはホストの DNS による名前解決が必要で、漏えいし、制御もできません）"),
                ),
            },
            "allowedips" => {
                for item in split_list(value) {
                    match item.parse::<IpNetwork>() {
                        Ok(n) => self.allowed_ips.push(n),
                        Err(_) => {
                            r.error(
                                "ALLOWED_IPS",
                                at,
                                tr!(
                                    "Invalid AllowedIPs entry “{item}”",
                                    "無效的 AllowedIPs「{item}」",
                                    "無効な AllowedIPs です：「{item}」"
                                ),
                            );
                        }
                    }
                }
            }
            "persistentkeepalive" => {
                if value.eq_ignore_ascii_case("off") {
                    self.keepalive = None;
                } else {
                    match value.parse::<u16>() {
                        Ok(0) => self.keepalive = None,
                        Ok(v) => self.keepalive = Some(v),
                        Err(_) => r.error("KEEPALIVE", at, tr!("PersistentKeepalive must be an integer", "PersistentKeepalive 必須是整數", "PersistentKeepalive は整数にしてください")),
                    }
                }
            }
            _ => return false,
        }
        true
    }

    /// The parsed configuration, or the finished report when anything is missing or wrong.
    fn into_config(
        self,
        mut r: ValidationReport,
    ) -> Result<(ParsedConfig, ValidationReport), ValidationReport> {
        let Self {
            private_key,
            preshared_key,
            addresses,
            dns,
            mtu,
            peer_public_key,
            endpoint,
            allowed_ips,
            keepalive,
        } = self;
        let (Some(private_key), Some(peer_public_key), Some(endpoint)) =
            (private_key, peer_public_key, endpoint)
        else {
            if !r.has_errors() {
                r.error(
                    "MISSING_FIELDS",
                    "/",
                    tr!(
                        "PrivateKey, PublicKey or Endpoint is missing",
                        "缺少 PrivateKey、PublicKey 或 Endpoint",
                        "PrivateKey、PublicKey、Endpoint のいずれかがありません"
                    ),
                );
            }
            return Err(r.finish());
        };
        if r.has_errors() {
            return Err(r.finish());
        }
        Ok((
            ParsedConfig {
                private_key,
                preshared_key,
                public: PublicConfig {
                    addresses,
                    dns,
                    mtu,
                    peer_public_key,
                    endpoint,
                    allowed_ips,
                    persistent_keepalive: keepalive,
                },
            },
            r.finish(),
        ))
    }
}

/// Whether the line of `key` (located at `at`) is taken no further: a key repeated in its
/// section, one that would run host commands or change the host, or one that does not apply.
fn skip_key(key: &str, seen: &mut Vec<String>, at: &str, r: &mut ValidationReport) -> bool {
    if seen.iter().any(|k| k == key) && !matches!(key, "address" | "dns" | "allowedips") {
        r.error(
            "DUPLICATE_KEY",
            at,
            tr!(
                "“{key}” appears more than once",
                "「{key}」重複出現",
                "「{key}」が重複しています"
            ),
        );
        return true;
    }
    seen.push(key.to_owned());
    if FORBIDDEN.contains(&key) {
        r.error(
            "FORBIDDEN_KEY",
            at,
            tr!(
                "“{key}” is not supported: this product never runs host commands or changes the host's network",
                "不支援「{key}」：本產品不執行 host 指令或修改主機網路",
                "「{key}」には対応していません。この製品はホストのコマンドを実行せず、ホストのネットワークも変更しません"
            ),
        );
        return true;
    }
    if IGNORED.contains(&key) {
        r.warning(
            "IGNORED_KEY",
            at,
            tr!(
                "“{key}” does not apply to a userspace tunnel and was ignored",
                "「{key}」不適用於 userspace tunnel，已忽略",
                "「{key}」はユーザー空間のトンネルには当てはまらないため、無視しました"
            ),
        );
        return true;
    }
    false
}

/// Parse a configuration. On failure the report holds located errors; nothing secret is logged.
///
/// # Errors
///
/// The finished report, with every located error, when the text is too large or holds a NUL,
/// has an unknown, duplicate, forbidden or invalid entry, or lacks exactly one `[Interface]`
/// and one `[Peer]` with `PrivateKey`, `PublicKey` and `Endpoint`.
pub fn parse(text: &str) -> Result<(ParsedConfig, ValidationReport), ValidationReport> {
    let mut r = ValidationReport::default();
    if text.len() > MAX_CONFIG_BYTES {
        r.error(
            "CONFIG_TOO_LARGE",
            "/",
            tr!(
                "The configuration file is over 64 KiB",
                "設定檔超過 64 KiB",
                "設定ファイルが 64 KiB を超えています"
            ),
        );
        return Err(r.finish());
    }
    if text.contains('\0') {
        r.error(
            "CONFIG_INVALID",
            "/",
            tr!(
                "The configuration file contains a NUL character",
                "設定檔含 NUL 字元",
                "設定ファイルに NUL 文字が含まれています"
            ),
        );
        return Err(r.finish());
    }

    let mut section = Section::None;
    let mut interfaces = 0;
    let mut peers = 0;
    let mut seen: Vec<String> = Vec::new();

    let mut fields = Fields::default();

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let at = format!("/line/{}", lineno + 1);
        if line.starts_with('[') {
            match line.to_ascii_lowercase().as_str() {
                "[interface]" => {
                    section = Section::Interface;
                    interfaces += 1;
                }
                "[peer]" => {
                    section = Section::Peer;
                    peers += 1;
                }
                _ => r.error(
                    "UNKNOWN_SECTION",
                    &at,
                    tr!("Unknown section", "未知的區段", "不明なセクションです"),
                ),
            }
            seen.clear();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            r.error(
                "SYNTAX",
                &at,
                tr!(
                    "Expected “Key = Value”",
                    "預期「Key = Value」",
                    "「Key = Value」の形式にしてください"
                ),
            );
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if skip_key(&key, &mut seen, &at, &mut r) {
            continue;
        }
        fields.apply(section, &key, value, &at, &mut r);
    }

    if interfaces != 1 {
        r.error(
            "INTERFACE_COUNT",
            "/",
            tr!(
                "There must be exactly one [Interface]",
                "必須剛好有一個 [Interface]",
                "[Interface] はちょうど 1 つにしてください"
            ),
        );
    }
    if peers != 1 {
        r.error(
            "PEER_COUNT",
            "/",
            tr!(
                "There must be exactly one [Peer] (several peers are not supported)",
                "必須剛好有一個 [Peer]（多 peer 不支援）",
                "[Peer] はちょうど 1 つにしてください（複数のピアには対応していません）"
            ),
        );
    }
    fields.into_config(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = "[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.64.1.2/32, fc00:bbbb:bbbb:bb01::1:2/128
DNS = 10.64.0.1
MTU = 1380
ListenPort = 51820

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 198.51.100.7:51820
PersistentKeepalive = 25
";

    #[test]
    fn parses_a_complete_config_and_keeps_secrets_apart() {
        let (parsed, report) = parse(OK).ok().unwrap();
        assert!(report.valid);
        assert_eq!(report.issues.len(), 1, "ListenPort ignored with a warning");
        assert_eq!(parsed.public.addresses.len(), 2);
        assert_eq!(parsed.public.mtu, Some(1380));
        assert_eq!(parsed.public.persistent_keepalive, Some(25));
        assert!(parsed.preshared_key.is_some());
        assert_eq!(
            parsed.public.endpoint,
            "198.51.100.7:51820".parse().unwrap()
        );
    }

    #[test]
    fn rejects_hooks_hostnames_and_extra_peers_without_echoing_secrets() {
        let hooks = OK.replace("MTU = 1380", "MTU = 1380\nPostUp = curl evil");
        let r = parse(&hooks).err().unwrap();
        assert!(r.issues.iter().any(|i| i.code == "FORBIDDEN_KEY"));

        let host = OK.replace(
            "198.51.100.7:51820",
            "se-sto-wg-001.relays.mullvad.net:51820",
        );
        let r = parse(&host).err().unwrap();
        assert!(r.issues.iter().any(|i| i.code == "ENDPOINT_HOSTNAME"));

        let two =
            format!("{OK}\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n");
        let r = parse(&two).err().unwrap();
        assert!(r.issues.iter().any(|i| i.code == "PEER_COUNT"));

        let bad = OK.replace("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", "not-a-key");
        let r = parse(&bad).err().unwrap();
        assert!(
            r.issues
                .iter()
                .all(|i| !i.message.zh_tw.contains("not-a-key"))
        );
    }
}
