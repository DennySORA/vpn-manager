//! Pure validation of user configuration. Produces located issues, in the three languages of the
//! interface; never performs network or OS side effects (that is the Profile Checker's runtime part).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::config::{
    APP_CPU_PERCENT, APP_MEMORY_MIB, APP_OPEN_FILES, APP_PLACEHOLDER_GATEWAY_PORT,
    APP_PLACEHOLDER_HOME, APP_PROCESSES, APP_RESERVED_ENV, APP_STOP_GRACE_SECS, AccessBind,
    AppClass, AppClassInfo, AppIsolation, AppLimits, AppSpec, AssignmentSource, BANDWIDTH_BPS,
    BlocklistSource, DnsProfile, DnsServer, FORWARD_MAX_CONNECTIONS, ForwardBinding, GatewayKind,
    GatewaySpec, InstanceLimits, InterfaceSpec, PeerSpec, RuntimeProfile, SecurityProfile,
};
use crate::text::Text;
use crate::tr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Issue {
    pub severity: Severity,
    pub code: String,
    pub path: String,
    pub message: Text,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ValidationReport {
    pub valid: bool,
    pub issues: Vec<Issue>,
}

impl ValidationReport {
    pub fn error(&mut self, code: &str, path: &str, message: impl Into<Text>) {
        self.issues.push(Issue {
            severity: Severity::Error,
            code: code.into(),
            path: path.into(),
            message: message.into(),
        });
    }

    pub fn warning(&mut self, code: &str, path: &str, message: impl Into<Text>) {
        self.issues.push(Issue {
            severity: Severity::Warning,
            code: code.into(),
            path: path.into(),
            message: message.into(),
        });
    }

    #[must_use]
    pub fn finish(mut self) -> Self {
        self.valid = !self.issues.iter().any(|i| i.severity == Severity::Error);
        self
    }

    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.issues.iter().any(|i| i.severity == Severity::Error)
    }
}

pub fn check_name(r: &mut ValidationReport, path: &str, name: &str) {
    let n = name.trim();
    if n.is_empty() {
        r.error(
            "NAME_REQUIRED",
            path,
            tr!(
                "The name cannot be empty",
                "名稱不可空白",
                "名前は空にできません"
            ),
        );
    } else if n.chars().count() > 64 {
        r.error(
            "NAME_TOO_LONG",
            path,
            tr!(
                "A name has at most 64 characters",
                "名稱最多 64 個字元",
                "名前は 64 文字までです"
            ),
        );
    } else if n.chars().any(char::is_control) {
        r.error(
            "NAME_INVALID",
            path,
            tr!(
                "A name cannot contain control characters",
                "名稱不可包含控制字元",
                "名前に制御文字は使えません"
            ),
        );
    }
}

/// The address every destination and source rule judges `ip` as.
///
/// An IPv4-mapped address (`::ffff:0:0/96`) or an address of the well-known NAT64 prefix
/// (`64:ff9b::/96`, RFC 6052) is the IPv4 host it embeds, everything else is itself.
///
/// On an exit with DNS64/NAT64 a host has both forms, and every rule must see the same host. It is
/// not the address to dial: a NAT64 address is reached as it is, through the exit's translator.
///
/// The local-use prefix `64:ff9b:1::/48` (RFC 8215) embeds the IPv4 address where the operator's
/// prefix length puts it, which nothing here can know; it is not globally reachable and counts
/// as private instead (see [`is_private`]).
#[must_use]
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) if v6.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0] => {
            let o = v6.octets();
            IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
        }
        other => other,
    }
}

/// Prefix length of the IPv6 sources auto-ban counts and bans together: a /64 is one subnet,
/// whose hosts choose and rotate their own addresses in it (SLAAC, privacy addresses).
pub const BAN_V6_PREFIX: u8 = 64;

/// What an auto-ban of `ip` counts and covers, given by its first address: the IPv4 host
/// ([`canonical_ip`]), or the /64 an IPv6 address is in.
#[must_use]
pub fn ban_scope(ip: IpAddr) -> IpAddr {
    match canonical_ip(ip) {
        IpAddr::V6(v6) => {
            let mask = u128::MAX << (128 - u32::from(BAN_V6_PREFIX));
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// How a ban is shown: the IPv4 address, or the IPv6 /64 in CIDR form.
#[must_use]
pub fn ban_label(source: IpAddr) -> String {
    match ban_scope(source) {
        IpAddr::V6(net) => format!("{net}/{BAN_V6_PREFIX}"),
        v4 @ IpAddr::V4(_) => v4.to_string(),
    }
}

/// Addresses that may never be a tunnel endpoint or a payload destination.
#[must_use]
pub fn is_special(ip: IpAddr) -> bool {
    let ip = canonical_ip(ip);
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
        }
    }
}

/// Private / non-global ranges (RFC1918, CGNAT, ULA, documentation...). Payload to these needs
/// an explicit `SecurityProfile` allowance.
#[must_use]
pub fn is_private(ip: IpAddr) -> bool {
    let ip = canonical_ip(ip);
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || o[0] == 0
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] & 0xffc0) == 0xfec0 // site local (deprecated)
                || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001) // local-use NAT64
        }
    }
}

pub fn check_endpoint(r: &mut ValidationReport, path: &str, endpoint: &SocketAddr) {
    if endpoint.port() == 0 {
        r.error(
            "ENDPOINT_PORT",
            path,
            tr!(
                "The Endpoint port cannot be 0",
                "Endpoint port 不可為 0",
                "Endpoint のポートを 0 にすることはできません"
            ),
        );
    }
    let ip = endpoint.ip().to_canonical();
    if ip.is_loopback() {
        // A WireGuard peer on this machine (test peer, local relay) is legitimate: the encrypted
        // underlay just stays on the host. Make it visible rather than forbidden.
        r.warning(
            "ENDPOINT_LOOPBACK",
            path,
            tr!("The Endpoint is a local address: this only suits a WireGuard peer on this host (vpn-labpeer or a local relay, for example)", "Endpoint 是本機位址：只適用於本機 WireGuard 對端（例如 vpn-labpeer 或本機 relay）", "Endpoint はローカルアドレスです。このホスト上の WireGuard ピア（vpn-labpeer やローカルの relay など）にだけ使えます"),
        );
    } else if is_special(ip) {
        r.error(
            "ENDPOINT_ADDRESS",
            path,
            tr!(
                "The Endpoint cannot be an unspecified, multicast, broadcast or link-local address",
                "Endpoint 不可為未指定、multicast、broadcast 或 link-local 位址",
                "Endpoint に未指定、マルチキャスト、ブロードキャスト、リンクローカルのアドレスは使えません"
            ),
        );
    }
}

pub fn check_interface(r: &mut ValidationReport, iface: &InterfaceSpec) {
    if iface.addresses.is_empty() {
        r.error(
            "ADDRESS_REQUIRED",
            "/interface/addresses",
            tr!(
                "At least one address inside the tunnel is required",
                "至少需要一個 tunnel 內位址",
                "トンネル内のアドレスが少なくとも 1 つ必要です"
            ),
        );
    }
    let mut v4 = 0;
    let mut v6 = 0;
    for (i, net) in iface.addresses.iter().enumerate() {
        let path = format!("/interface/addresses/{i}");
        if is_special(net.ip()) {
            r.error(
                "ADDRESS_INVALID",
                &path,
                tr!(
                    "A tunnel address cannot be a special-purpose address",
                    "tunnel 位址不可為特殊用途位址",
                    "トンネルアドレスに特殊用途のアドレスは使えません"
                ),
            );
        }
        match net {
            IpNetwork::V4(_) => v4 += 1,
            IpNetwork::V6(_) => v6 += 1,
        }
    }
    if v4 > 1 || v6 > 1 {
        r.warning(
            "ADDRESS_EXTRA",
            "/interface/addresses",
            tr!(
                "Only the first address of each IP family is used",
                "每個 IP 家族只使用第一個位址",
                "IP ファミリーごとに最初のアドレスだけを使います"
            ),
        );
    }
    if !(576..=9000).contains(&iface.mtu) {
        r.error(
            "MTU_RANGE",
            "/interface/mtu",
            tr!(
                "The MTU must be between 576 and 9000",
                "MTU 必須介於 576 與 9000",
                "MTU は 576 から 9000 の間にしてください"
            ),
        );
    } else if v6 > 0 && iface.mtu < 1280 {
        r.error(
            "MTU_IPV6",
            "/interface/mtu",
            tr!(
                "With IPv6, the MTU must be at least 1280",
                "啟用 IPv6 時 MTU 至少 1280",
                "IPv6 を使う場合、MTU は 1280 以上にしてください"
            ),
        );
    } else if iface.mtu > 1420 {
        r.warning(
            "MTU_HIGH",
            "/interface/mtu",
            tr!(
                "An MTU above 1420 causes fragmentation or packet loss on most networks",
                "MTU 大於 1420 在多數網路上會造成分段或封包遺失",
                "MTU が 1420 を超えると、多くのネットワークで断片化やパケット損失が起きます"
            ),
        );
    }
    for (i, ip) in iface.dns.iter().enumerate() {
        if is_special(*ip) {
            r.error(
                "DNS_ADDRESS",
                &format!("/interface/dns/{i}"),
                tr!(
                    "The DNS server address is not valid",
                    "DNS 伺服器位址無效",
                    "DNS サーバーのアドレスが無効です"
                ),
            );
        }
    }
}

pub fn check_peer(r: &mut ValidationReport, peer: &PeerSpec, own_public: &crate::common::WgKey) {
    if &peer.public_key == own_public {
        r.error(
            "PEER_KEY_SELF",
            "/peer/public_key",
            tr!(
                "The Peer public key cannot be the same as the local public key",
                "Peer 公鑰不可與本機公鑰相同",
                "Peer の公開鍵をローカルの公開鍵と同じにすることはできません"
            ),
        );
    }
    check_endpoint(r, "/peer/endpoint", &peer.endpoint);
    if peer.allowed_ips.is_empty() {
        r.error(
            "ALLOWED_IPS_REQUIRED",
            "/peer/allowed_ips",
            tr!(
                "AllowedIPs cannot be empty",
                "AllowedIPs 不可空白",
                "AllowedIPs は空にできません"
            ),
        );
    }
    if let Some(k) = peer.persistent_keepalive
        && k > 3600
    {
        r.error(
            "KEEPALIVE_RANGE",
            "/peer/persistent_keepalive",
            tr!(
                "PersistentKeepalive is at most 3600 seconds",
                "PersistentKeepalive 最多 3600 秒",
                "PersistentKeepalive は最大 3600 秒です"
            ),
        );
    }
}

/// Address families of the profile that are fully routed through the tunnel.
#[must_use]
pub fn routes_family(profile_allowed: &[IpNetwork], ipv6: bool) -> bool {
    profile_allowed.iter().any(|n| match n {
        IpNetwork::V4(v) => !ipv6 && v.prefix() == 0,
        IpNetwork::V6(v) => ipv6 && v.prefix() == 0,
    })
}

pub fn check_profile(p: &RuntimeProfile) -> ValidationReport {
    let mut r = ValidationReport::default();
    check_name(&mut r, "/name", &p.name);
    check_interface(&mut r, &p.interface);
    check_peer(&mut r, &p.peer, &p.interface.public_key);
    let has_v4 = p.interface.addresses.iter().any(IpNetwork::is_ipv4);
    let has_v6 = p.interface.addresses.iter().any(IpNetwork::is_ipv6);
    if has_v4 && !routes_family(&p.peer.allowed_ips, false) {
        r.warning(
            "PARTIAL_IPV4",
            "/peer/allowed_ips",
            tr!("AllowedIPs does not cover 0.0.0.0/0: connections to other IPv4 destinations are refused (they never fall back to the ordinary network)", "AllowedIPs 未涵蓋 0.0.0.0/0：其他 IPv4 目的地的連線會被拒絕（不會改走一般網路）", "AllowedIPs が 0.0.0.0/0 をカバーしていません。ほかの IPv4 宛先への接続は拒否されます（通常のネットワークには切り替わりません）"),
        );
    }
    if has_v6 && !routes_family(&p.peer.allowed_ips, true) {
        r.warning(
            "PARTIAL_IPV6",
            "/peer/allowed_ips",
            tr!("AllowedIPs does not cover ::/0: connections to other IPv6 destinations are refused", "AllowedIPs 未涵蓋 ::/0：其他 IPv6 目的地的連線會被拒絕", "AllowedIPs が ::/0 をカバーしていません。ほかの IPv6 宛先への接続は拒否されます"),
        );
    }
    if !has_v6 {
        r.warning(
            "IPV6_BLOCKED",
            "/interface/addresses",
            tr!("This profile has no IPv6 address: IPv6 destinations are always refused and never sent over the ordinary network", "此設定沒有 IPv6 位址：IPv6 目的地一律拒絕，不會經一般網路送出", "この設定には IPv6 アドレスがありません。IPv6 の宛先はすべて拒否され、通常のネットワークで送信されることはありません"),
        );
    }
    r.finish()
}

/// One server of a DNS profile, located at `path`.
fn check_dns_server(r: &mut ValidationReport, path: &str, s: &DnsServer) {
    let address = match s {
        DnsServer::Udp { address } | DnsServer::Tcp { address } => address,
        DnsServer::Tls {
            address,
            server_name,
        } => {
            if !valid_hostname(server_name) {
                r.error(
                    "DNS_SERVER_NAME",
                    &format!("{path}/server_name"),
                    tr!(
                        "DoT needs a valid certificate host name",
                        "DoT 需要有效的憑證主機名稱",
                        "DoT には有効な証明書のホスト名が必要です"
                    ),
                );
            }
            address
        }
        DnsServer::Https { address, url } => {
            match url.strip_prefix("https://") {
                Some(rest) => {
                    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
                    let host = host.split(':').next().unwrap_or_default();
                    if !valid_hostname(host) {
                        r.error(
                            "DOH_URL",
                            &format!("{path}/url"),
                            tr!(
                                "A DoH URL needs a valid host name",
                                "DoH URL 需要有效的主機名稱",
                                "DoH URL には有効なホスト名が必要です"
                            ),
                        );
                    }
                }
                None => r.error(
                    "DOH_URL",
                    &format!("{path}/url"),
                    tr!(
                        "A DoH URL must start with https://",
                        "DoH URL 必須以 https:// 開頭",
                        "DoH URL は https:// で始める必要があります"
                    ),
                ),
            }
            address
        }
    };
    if address.port() == 0 || is_special(address.ip()) {
        r.error(
            "DNS_ADDRESS",
            &format!("{path}/address"),
            tr!(
                "A DNS server needs a numeric IP and a valid port",
                "DNS 伺服器需要數字 IP 與有效 port",
                "DNS サーバーには数値の IP と有効なポートが必要です"
            ),
        );
    }
}

#[must_use]
pub fn check_dns_profile(p: &DnsProfile) -> ValidationReport {
    let mut r = ValidationReport::default();
    check_name(&mut r, "/name", &p.name);
    if p.servers.is_empty() || p.servers.len() > 4 {
        r.error(
            "DNS_SERVER_COUNT",
            "/servers",
            tr!(
                "1 to 4 DNS servers are required",
                "需要 1 到 4 個 DNS 伺服器",
                "DNS サーバーが 1〜4 台必要です"
            ),
        );
    }
    for (i, s) in p.servers.iter().enumerate() {
        check_dns_server(&mut r, &format!("/servers/{i}"), s);
    }
    if !(250..=10_000).contains(&p.query_timeout_ms) {
        r.error(
            "DNS_TIMEOUT",
            "/query_timeout_ms",
            tr!(
                "The query deadline must be between 250 and 10000 ms",
                "查詢期限必須介於 250 與 10000 毫秒",
                "問い合わせ期限は 250 から 10000 ミリ秒の間にしてください"
            ),
        );
    }
    if !(1..=3).contains(&p.attempts) {
        r.error(
            "DNS_ATTEMPTS",
            "/attempts",
            tr!(
                "Attempts must be between 1 and 3",
                "嘗試次數必須介於 1 與 3",
                "試行回数は 1 から 3 の間にしてください"
            ),
        );
    }
    if p.cache.max_entries > 16_384 {
        r.error(
            "DNS_CACHE",
            "/cache/max_entries",
            tr!(
                "The cache holds at most 16384 entries",
                "快取最多 16384 筆",
                "キャッシュは最大 16384 件です"
            ),
        );
    }
    if p.cache.max_ttl_secs > 86_400 {
        r.error(
            "DNS_CACHE_TTL",
            "/cache/max_ttl_secs",
            tr!(
                "The TTL cap is at most 86400 seconds",
                "TTL 上限最多 86400 秒",
                "TTL の上限は最大 86400 秒です"
            ),
        );
    }
    if p.cache.negative_ttl_secs > 300 {
        r.error(
            "DNS_NEGATIVE_TTL",
            "/cache/negative_ttl_secs",
            tr!(
                "Negative caching lasts at most 300 seconds",
                "負快取最多 300 秒",
                "ネガティブキャッシュは最大 300 秒です"
            ),
        );
    }
    r.finish()
}

#[must_use]
pub fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Most networks in one list of a security profile (private allowances, allowed destinations).
pub const MAX_POLICY_NETWORKS: usize = 256;
/// Most blocked ports of a security profile.
pub const MAX_BLOCKED_PORTS: usize = 256;
/// Most allowed port ranges of a security profile.
pub const MAX_PORT_RANGES: usize = 32;

/// Whether `net` lies entirely inside one of `nets` (same family).
fn covered_by(net: &IpNetwork, nets: &[IpNetwork]) -> bool {
    nets.iter().any(|n| {
        n.is_ipv4() == net.is_ipv4() && n.prefix() <= net.prefix() && n.contains(net.network())
    })
}

/// The bounds of a security profile's auto-ban settings.
fn check_auto_ban(r: &mut ValidationReport, ab: &crate::config::AutoBanSettings) {
    if !(1..=3600).contains(&ab.window_secs) {
        r.error(
            "AUTOBAN_WINDOW",
            "/auto_ban/window_secs",
            tr!(
                "The window must be between 1 and 3600 seconds",
                "視窗必須介於 1 與 3600 秒",
                "ウィンドウは 1 から 3600 秒の間にしてください"
            ),
        );
    }
    if !(1..=100_000).contains(&ab.threshold) {
        r.error(
            "AUTOBAN_THRESHOLD",
            "/auto_ban/threshold",
            tr!(
                "The threshold must be between 1 and 100000",
                "門檻必須介於 1 與 100000",
                "しきい値は 1 から 100000 の間にしてください"
            ),
        );
    }
    if !(1..=604_800).contains(&ab.ban_secs) {
        r.error(
            "AUTOBAN_TTL",
            "/auto_ban/ban_secs",
            tr!(
                "The ban duration must be between 1 second and 7 days",
                "封鎖時間必須介於 1 秒與 7 天",
                "ブロック時間は 1 秒から 7 日の間にしてください"
            ),
        );
    }
    if !(1..=100_000).contains(&ab.max_bans) {
        r.error(
            "AUTOBAN_MAX",
            "/auto_ban/max_bans",
            tr!(
                "The ban limit must be between 1 and 100000",
                "封鎖上限必須介於 1 與 100000",
                "ブロック数の上限は 1 から 100000 の間にしてください"
            ),
        );
    }
}

/// The port rules of a security profile: allowed ranges and blocked ports.
fn check_ports(r: &mut ValidationReport, p: &SecurityProfile) {
    if p.allowed_ports.len() > MAX_PORT_RANGES {
        r.error(
            "ALLOWED_PORTS_COUNT",
            "/allowed_ports",
            tr!(
                "At most {MAX_PORT_RANGES} allowed port ranges",
                "允許的 port 範圍最多 {MAX_PORT_RANGES} 組",
                "許可するポート範囲は最大 {MAX_PORT_RANGES} 組です"
            ),
        );
    }
    for (i, range) in p.allowed_ports.iter().enumerate() {
        if range.start == 0 || range.end < range.start {
            r.error(
                "PORT_RANGE_INVALID",
                &format!("/allowed_ports/{i}"),
                tr!(
                    "A port range must lie within 1–65535 and must not start after it ends",
                    "port 範圍必須在 1–65535 之間，且起點不大於終點",
                    "ポート範囲は 1–65535 の中で、始点が終点より大きくならないようにしてください"
                ),
            );
        }
    }
    if p.blocked_ports.len() > MAX_BLOCKED_PORTS {
        r.error(
            "BLOCKED_PORTS_COUNT",
            "/blocked_ports",
            tr!(
                "At most {MAX_BLOCKED_PORTS} blocked ports",
                "封鎖的 port 最多 {MAX_BLOCKED_PORTS} 個",
                "ブロックするポートは最大 {MAX_BLOCKED_PORTS} 個です"
            ),
        );
    }
    if p.blocked_ports.contains(&0) {
        r.error(
            "PORT_INVALID",
            "/blocked_ports",
            tr!("Port 0 is not valid", "port 0 無效", "ポート 0 は無効です"),
        );
    }
}

#[must_use]
pub fn check_security_profile(p: &SecurityProfile) -> ValidationReport {
    let mut r = ValidationReport::default();
    check_name(&mut r, "/name", &p.name);
    if p.allow_private.len() > MAX_POLICY_NETWORKS {
        r.error(
            "ALLOW_PRIVATE_COUNT",
            "/allow_private",
            tr!(
                "At most {MAX_POLICY_NETWORKS} allowed private networks",
                "允許的私網最多 {MAX_POLICY_NETWORKS} 個",
                "許可するプライベートネットワークは最大 {MAX_POLICY_NETWORKS} 個です"
            ),
        );
    }
    for (i, net) in p.allow_private.iter().enumerate() {
        if is_special(net.ip()) || net.prefix() == 0 {
            r.error(
                "ALLOW_PRIVATE_INVALID",
                &format!("/allow_private/{i}"),
                tr!(
                    "Loopback, link-local, multicast or the whole address space cannot be allowed",
                    "不可允許 loopback、link-local、multicast 或整個位址空間",
                    "ループバック、リンクローカル、マルチキャスト、アドレス空間全体は許可できません"
                ),
            );
        }
    }
    if p.allowed_destinations.len() > MAX_POLICY_NETWORKS {
        r.error(
            "ALLOWED_DESTINATIONS_COUNT",
            "/allowed_destinations",
            tr!(
                "At most {MAX_POLICY_NETWORKS} allowed destinations",
                "允許的目的地最多 {MAX_POLICY_NETWORKS} 個",
                "許可する宛先は最大 {MAX_POLICY_NETWORKS} 個です"
            ),
        );
    }
    for (i, net) in p.allowed_destinations.iter().enumerate() {
        let path = format!("/allowed_destinations/{i}");
        // A whole family (`0.0.0.0/0`, `::/0`) only says "this family"; the invariants still
        // refuse its special addresses.
        if net.prefix() > 0 && is_special(net.ip()) {
            r.error(
                "ALLOWED_DESTINATION_INVALID",
                &path,
                tr!(
                    "Loopback, link-local or multicast addresses cannot be allowed",
                    "不可允許 loopback、link-local 或 multicast 位址",
                    "ループバック、リンクローカル、マルチキャストのアドレスは許可できません"
                ),
            );
        } else if is_private(net.ip()) && !covered_by(net, &p.allow_private) {
            r.warning(
                "ALLOWED_DESTINATION_PRIVATE",
                &path,
                tr!("This is a private network: list it under “Private networks allowed through the tunnel” as well to let it through", "這是私網：還要列在「允許經 tunnel 連線的私網」才會放行", "これはプライベートネットワークです。通すには「トンネル経由の接続を許可するプライベートネットワーク」にも指定してください"),
            );
        }
    }
    check_ports(&mut r, p);
    if p.blocklists.len() > crate::blocklist::MAX_LISTS_PER_PROFILE {
        let max = crate::blocklist::MAX_LISTS_PER_PROFILE;
        r.error(
            "BLOCKLIST_COUNT",
            "/blocklists",
            tr!(
                "A security profile uses at most {max} IP blocklists",
                "一份安全設定最多使用 {max} 份 IP 封鎖清單",
                "1 つのセキュリティ設定で使える IP ブロックリストは最大 {max} 件です"
            ),
        );
    }
    for (i, id) in p.blocklists.iter().enumerate() {
        if p.blocklists[..i].contains(id) {
            r.error(
                "BLOCKLIST_DUPLICATE",
                &format!("/blocklists/{i}"),
                tr!(
                    "The same blocklist is chosen more than once",
                    "同一份封鎖清單重複選取",
                    "同じブロックリストが重複して選択されています"
                ),
            );
        }
    }
    check_auto_ban(&mut r, &p.auto_ban);
    r.finish()
}

/// Name and source settings of a blocklist (its content is checked by the parser).
#[must_use]
pub fn check_blocklist(name: &str, source: &BlocklistSource) -> ValidationReport {
    let mut r = ValidationReport::default();
    check_name(&mut r, "/name", name);
    if let BlocklistSource::Url { url, refresh_hours } = source {
        if let Err(message) = crate::blocklist::parse_https_url(url) {
            r.error("BLOCKLIST_URL", "/source/url", message);
        }
        if let Some(h) = refresh_hours
            && !(crate::blocklist::MIN_REFRESH_HOURS..=crate::blocklist::MAX_REFRESH_HOURS)
                .contains(h)
        {
            let (min, max) = (
                crate::blocklist::MIN_REFRESH_HOURS,
                crate::blocklist::MAX_REFRESH_HOURS,
            );
            r.error(
                "BLOCKLIST_REFRESH",
                "/source/refresh_hours",
                tr!(
                    "The refresh interval must be between {min} and {max} hours",
                    "自動更新間隔必須介於 {min} 與 {max} 小時",
                    "自動更新の間隔は {min} から {max} 時間の間にしてください"
                ),
            );
        }
    }
    r.finish()
}

/// Strict mode exists only where the platform has rootless network namespaces (Linux).
pub const STRICT_SUPPORTED: bool = cfg!(target_os = "linux");

/// The strict-mode switch of an Instance: refused where the platform cannot provide it, never
/// stored as a protection that does not exist.
///
/// (Whether this particular Linux host allows it is a runtime capability, reported by the manager.)
pub fn check_instance_strict(r: &mut ValidationReport, strict: bool) {
    if strict && !STRICT_SUPPORTED {
        r.error(
            "STRICT_UNSUPPORTED",
            "/strict",
            tr!("Strict isolation (rootless network namespace) is available only on Linux; on this operating system, use a Gateway proxy", "嚴格隔離（rootless network namespace）只在 Linux 提供；這個作業系統請使用 Gateway 代理", "厳格な分離（rootless network namespace）は Linux でのみ利用できます。この OS ではゲートウェイのプロキシを使ってください"),
        );
    }
}

#[must_use]
pub fn check_gateway(g: &GatewaySpec) -> ValidationReport {
    let mut r = ValidationReport::default();
    check_name(&mut r, "/name", &g.name);
    if g.port < 1024 {
        r.error(
            "GATEWAY_PORT",
            "/port",
            tr!(
                "A Gateway port must be ≥ 1024 (no privileges are needed or taken)",
                "Gateway port 必須 ≥ 1024（不需要也不會取得特權）",
                "ゲートウェイのポートは 1024 以上にしてください（特権は不要で、取得もしません）"
            ),
        );
    }
    if !(1..=16_384).contains(&g.max_connections) {
        r.error(
            "GATEWAY_CONNECTIONS",
            "/max_connections",
            tr!(
                "Concurrent connections must be between 1 and 16384",
                "同時連線數必須介於 1 與 16384",
                "同時接続数は 1 から 16384 の間にしてください"
            ),
        );
    }
    if g.udp && g.kind == GatewayKind::Http {
        r.error(
            "GATEWAY_UDP",
            "/udp",
            tr!(
                "An HTTP proxy does not support UDP; use SOCKS5 or mixed instead",
                "HTTP 代理不支援 UDP；請改用 SOCKS5 或 mixed",
                "HTTP プロキシは UDP に対応していません。SOCKS5 か mixed を使ってください"
            ),
        );
    }
    r.finish()
}

/// Bounds of a connection's limits (paths below `/limits`).
pub fn check_instance_limits(r: &mut ValidationReport, l: &InstanceLimits) {
    if !(1..=16_384).contains(&l.max_tcp_flows) {
        r.error(
            "LIMIT_TCP",
            "/limits/max_tcp_flows",
            tr!(
                "The TCP connection limit must be between 1 and 16384",
                "TCP 連線上限必須介於 1 與 16384",
                "TCP 接続数の上限は 1 から 16384 の間にしてください"
            ),
        );
    }
    if !(1..=16_384).contains(&l.max_udp_flows) {
        r.error(
            "LIMIT_UDP",
            "/limits/max_udp_flows",
            tr!(
                "The UDP limit must be between 1 and 16384",
                "UDP 上限必須介於 1 與 16384",
                "UDP の上限は 1 から 16384 の間にしてください"
            ),
        );
    }
    if !(64..=8192).contains(&l.memory_mib) {
        r.error(
            "LIMIT_MEMORY",
            "/limits/memory_mib",
            tr!(
                "The memory budget must be between 64 and 8192 MiB",
                "記憶體預算必須介於 64 與 8192 MiB",
                "メモリ予算は 64 から 8192 MiB の間にしてください"
            ),
        );
    }
    if l.download_bps.is_some_and(|v| !BANDWIDTH_BPS.contains(&v)) {
        r.error(
            "LIMIT_DOWNLOAD",
            "/limits/download_bps",
            tr!(
                "The download limit must be between 0.1 Mbit/s and 100 Gbit/s",
                "下載上限必須介於 0.1 Mbit/s 與 100 Gbit/s",
                "ダウンロードの上限は 0.1 Mbit/s から 100 Gbit/s の間にしてください"
            ),
        );
    }
    if l.upload_bps.is_some_and(|v| !BANDWIDTH_BPS.contains(&v)) {
        r.error(
            "LIMIT_UPLOAD",
            "/limits/upload_bps",
            tr!(
                "The upload limit must be between 0.1 Mbit/s and 100 Gbit/s",
                "上傳上限必須介於 0.1 Mbit/s 與 100 Gbit/s",
                "アップロードの上限は 0.1 Mbit/s から 100 Gbit/s の間にしてください"
            ),
        );
    }
}

/// Bounds of an App's resource limits (paths below `/limits`). Whether this host enforces them
/// is the manager's check.
fn check_app_limits(r: &mut ValidationReport, l: &AppLimits) {
    let out = |v: Option<u32>, range: &std::ops::RangeInclusive<u32>| {
        v.is_some_and(|v| !range.contains(&v))
    };
    if out(l.memory_mib, &APP_MEMORY_MIB) {
        r.error(
            "APP_LIMIT_MEMORY",
            "/limits/memory_mib",
            tr!(
                "The memory limit must be between 16 MiB and 1048576 MiB (1 TiB)",
                "記憶體上限必須介於 16 MiB 與 1048576 MiB（1 TiB）",
                "メモリ上限は 16 MiB から 1048576 MiB（1 TiB）の間にしてください"
            ),
        );
    }
    if out(l.cpu_percent, &APP_CPU_PERCENT) {
        r.error(
            "APP_LIMIT_CPU",
            "/limits/cpu_percent",
            tr!(
                "The CPU limit must be between 1% and 6400% (percent of one core)",
                "CPU 上限必須介於 1% 與 6400%（單一核心的百分比）",
                "CPU 上限は 1% から 6400% の間にしてください（1 コアに対する割合）"
            ),
        );
    }
    if out(l.processes, &APP_PROCESSES) {
        r.error(
            "APP_LIMIT_PROCESSES",
            "/limits/processes",
            tr!(
                "The process limit must be between 1 and 65536 (threads included)",
                "程序數上限必須介於 1 與 65536（含執行緒）",
                "プロセス数の上限は 1 から 65536 の間にしてください（スレッドを含む）"
            ),
        );
    }
    if out(l.open_files, &APP_OPEN_FILES) {
        r.error(
            "APP_LIMIT_OPEN_FILES",
            "/limits/open_files",
            tr!(
                "The open-file limit must be between 16 and 1048576",
                "開啟檔案數上限必須介於 16 與 1048576",
                "開けるファイル数の上限は 16 から 1048576 の間にしてください"
            ),
        );
    }
}

/// Most local access ports of one App.
pub const APP_MAX_ACCESS_PORTS: usize = 8;
/// Most networks one allow list names (an access port's, or the web UI's `--allow-client`).
pub const MAX_CLIENT_NETWORKS: usize = 32;
/// Lowest port VPN Manager listens on, or relays to, for an App: lower ones need privileges
/// neither VPN Manager nor a sandboxed App has.
pub const ACCESS_MIN_PORT: u16 = 1024;

/// Why `net` cannot be a network other hosts are allowed to connect from, or `None`.
///
/// Every address at once is refused (list the LAN instead); loopback is not needed (this host's
/// own programs are always checked for being this user's); multicast, unspecified and
/// link-local addresses are never the source of a connection worth allowing.
#[must_use]
pub fn client_network_problem(net: &IpNetwork) -> Option<Text> {
    let ip = canonical_ip(net.network());
    if net.prefix() == 0 {
        return Some(tr!(
            "Every address (0.0.0.0/0, ::/0) cannot be allowed: list only the networks of your LAN, for example 192.168.10.0/24",
            "不能允許所有位址（0.0.0.0/0、::/0）：請只列出你的區網網段，例如 192.168.10.0/24",
            "すべてのアドレス（0.0.0.0/0、::/0）は許可できません。LAN のネットワークだけを指定してください（例：192.168.10.0/24）"
        ));
    }
    if ip.is_loopback() {
        return Some(tr!(
            "Loopback addresses (127.0.0.0/8, ::1) need not be listed: from this host, only programs of the same user are ever accepted",
            "本機位址（127.0.0.0/8、::1）不必列出：這台主機上的程式一律只接受同一個使用者的",
            "ループバックアドレス（127.0.0.0/8、::1）は指定する必要はありません。このホスト上のプログラムは、常に同じユーザーのものだけが受け付けられます"
        ));
    }
    if ip.is_unspecified() || ip.is_multicast() || is_special(ip) {
        return Some(tr!(
            "Other hosts never connect from such an address (unspecified, multicast or link-local)",
            "這不是其他主機連入時會用的位址（未指定、群播或 link-local）",
            "ほかのホストが接続に使うアドレスではありません（未指定、マルチキャスト、リンクローカル）"
        ));
    }
    None
}

/// `net` is (also) public address space: hosts on the internet may match it.
#[must_use]
pub fn client_network_public(net: &IpNetwork) -> bool {
    !is_private(net.network())
}

/// `ip` is in one of `nets` (an IPv4-mapped IPv6 address as the IPv4 address it is).
#[must_use]
pub fn allows_client(nets: &[IpNetwork], ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    nets.iter().any(|n| n.contains(ip))
}

/// `net` with its host bits cleared (`192.168.10.5/24` is `192.168.10.0/24`).
#[must_use]
pub fn network_of(net: IpNetwork) -> IpNetwork {
    IpNetwork::new(net.network(), net.prefix()).unwrap_or(net)
}

/// An allow list of networks other hosts may connect from, located at `path`.
///
/// At most [`MAX_CLIENT_NETWORKS`], each acceptable ([`client_network_problem`], error) and
/// preferably private ([`client_network_public`], warning).
pub fn check_client_networks(r: &mut ValidationReport, path: &str, nets: &[IpNetwork]) {
    if nets.len() > MAX_CLIENT_NETWORKS {
        r.error(
            "CLIENT_NETWORK_COUNT",
            path,
            tr!(
                "At most {MAX_CLIENT_NETWORKS} allowed networks",
                "允許的網段最多 {MAX_CLIENT_NETWORKS} 個",
                "許可するネットワークは最大 {MAX_CLIENT_NETWORKS} 個です"
            ),
        );
    }
    for (j, net) in nets.iter().enumerate() {
        let at = format!("{path}/{j}");
        if let Some(problem) = client_network_problem(net) {
            r.error("CLIENT_NETWORK", &at, problem);
        } else if client_network_public(net) {
            r.warning(
                "CLIENT_NETWORK_PUBLIC",
                &at,
                tr!(
                    "{net} is not a private network: hosts on the internet may match it too; make sure this is your LAN",
                    "{net} 不是私有網段：網際網路上的主機也可能符合，請確認這是你的區網",
                    "{net} はプライベートネットワークではありません。インターネット上のホストも当てはまる可能性があるため、LAN のネットワークか確認してください"
                ),
            );
        }
        if nets[..j].iter().any(|o| network_of(*o) == network_of(*net)) {
            r.error(
                "CLIENT_NETWORK_DUPLICATE",
                &at,
                tr!(
                    "{net} is listed more than once",
                    "{net} 重複列出",
                    "{net} が重複しています"
                ),
            );
        }
    }
}

/// The local access ports of an App (paths below `/access_ports`): only for `strict_netns`, at
/// most [`APP_MAX_ACCESS_PORTS`], unprivileged ports, no port twice, and an allow list exactly
/// when other hosts may connect. Clashes with other Apps, Gateways and programs are the
/// manager's check.
fn check_access_ports(r: &mut ValidationReport, a: &AppSpec) {
    if a.access_ports.is_empty() {
        return;
    }
    if a.isolation != AppIsolation::StrictNetns {
        r.error(
            "APP_ACCESS_STRICT_ONLY",
            "/access_ports",
            tr!("Only a strictly isolated app needs local access ports: an app in another mode is on this host's network, so connect to 127.0.0.1:<the app's port> directly", "只有嚴格隔離的 App 需要本機存取埠：其他模式的 App 就在這台主機的網路上，直接連 127.0.0.1:<App 的 port> 即可", "ローカルアクセスポートが必要なのは厳格な分離のアプリだけです。ほかのモードのアプリはこのホストのネットワーク上にあるため、127.0.0.1:<アプリのポート> に直接接続できます"),
        );
        return;
    }
    if a.access_ports.len() > APP_MAX_ACCESS_PORTS {
        r.error(
            "APP_ACCESS_COUNT",
            "/access_ports",
            tr!(
                "At most {APP_MAX_ACCESS_PORTS} local access ports",
                "本機存取埠最多 {APP_MAX_ACCESS_PORTS} 個",
                "ローカルアクセスポートは最大 {APP_MAX_ACCESS_PORTS} 個です"
            ),
        );
    }
    for (i, p) in a.access_ports.iter().enumerate() {
        let path = format!("/access_ports/{i}");
        let before = &a.access_ports[..i];
        if p.app_port < ACCESS_MIN_PORT {
            r.error(
                "APP_ACCESS_APP_PORT",
                &format!("{path}/app_port"),
                tr!("The app's port must be 1024–65535: an app in the sandbox has no permission to listen on a lower port", "App 的 port 必須是 1024–65535：沙箱裡的 App 沒有權限監聽更小的 port", "アプリのポートは 1024–65535 にしてください。サンドボックス内のアプリには、それより小さいポートで待ち受ける権限がありません"),
            );
        } else if before.iter().any(|o| o.app_port == p.app_port) {
            let port = p.app_port;
            r.error(
                "APP_ACCESS_DUPLICATE",
                &format!("{path}/app_port"),
                tr!(
                    "The app's port {port} already has a local access port",
                    "App 的 port {port} 已經有本機存取埠",
                    "アプリのポート {port} にはすでにローカルアクセスポートがあります"
                ),
            );
        }
        if p.host_port < ACCESS_MIN_PORT {
            r.error(
                "APP_ACCESS_HOST_PORT",
                &format!("{path}/host_port"),
                tr!(
                    "The port on this host must be 1024–65535",
                    "本機的 port 必須是 1024–65535",
                    "このホストのポートは 1024–65535 にしてください"
                ),
            );
        } else if before.iter().any(|o| o.host_port == p.host_port) {
            let port = p.host_port;
            r.error(
                "APP_ACCESS_DUPLICATE",
                &format!("{path}/host_port"),
                tr!(
                    "Port {port} on this host is used more than once",
                    "本機的 port {port} 重複使用",
                    "このホストのポート {port} が重複しています"
                ),
            );
        }
        match p.bind {
            AccessBind::Loopback if !p.allow.is_empty() => r.error(
                "APP_ACCESS_ALLOW_LOOPBACK",
                &format!("{path}/allow"),
                tr!("Listening only on this host (127.0.0.1) uses no allow list; to let other hosts connect, switch to the LAN", "只在本機（127.0.0.1）監聽時不使用允許清單；要讓其他主機連入請改成區網", "このホスト（127.0.0.1）だけで待ち受ける場合、許可リストは使いません。ほかのホストから接続させるには LAN に切り替えてください"),
            ),
            AccessBind::Loopback => {}
            AccessBind::Lan if p.allow.is_empty() => r.error(
                "APP_ACCESS_ALLOW_REQUIRED",
                &format!("{path}/allow"),
                tr!("Listening on the LAN needs the networks that may connect (192.168.10.0/24, for example); every other source is refused", "在區網監聽時必須列出允許連入的網段（例如 192.168.10.0/24）；其他來源一律拒絕", "LAN で待ち受けるときは、接続を許可するネットワークを指定してください（例：192.168.10.0/24）。それ以外の送信元はすべて拒否されます"),
            ),
            AccessBind::Lan => check_client_networks(r, &format!("{path}/allow"), &p.allow),
        }
    }
}

/// Most arguments, environment variables and extra writable directories of one App.
pub const APP_MAX_ARGS: usize = 256;
pub const APP_MAX_ENV: usize = 128;
pub const APP_MAX_WRITABLE: usize = 32;
/// Longest path accepted (macOS `PATH_MAX`).
pub const APP_MAX_PATH: usize = 1024;
/// All arguments together (the OS limit is larger; this keeps requests and argv small).
const APP_MAX_ARGS_BYTES: usize = 128 * 1024;

/// An absolute path without NUL or `..` segments, short enough for the OS.
#[must_use]
pub fn app_path_ok(p: &str) -> bool {
    p.starts_with('/')
        && p.len() <= APP_MAX_PATH
        && !p.contains('\0')
        && !p.split('/').any(|seg| seg == "..")
}

/// `{name}` tokens in an argument that are not placeholders the launcher knows.
fn unknown_placeholders(arg: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = arg;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else { break };
        let name = &after[..close];
        let token = &rest[open..open + close + 2];
        if !name.is_empty()
            && name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            && token != APP_PLACEHOLDER_GATEWAY_PORT
            && token != APP_PLACEHOLDER_HOME
        {
            out.push(token);
        }
        rest = &after[close + 1..];
    }
    out
}

/// An App's own environment variables: valid names and values, none reserved or repeated.
fn check_app_env(r: &mut ValidationReport, env: &[crate::config::EnvVar]) {
    if env.len() > APP_MAX_ENV {
        r.error(
            "APP_ENV_COUNT",
            "/env",
            tr!(
                "At most 128 environment variables",
                "環境變數最多 128 個",
                "環境変数は最大 128 個です"
            ),
        );
    }
    for (i, e) in env.iter().enumerate() {
        let path = format!("/env/{i}");
        let ok = !e.name.is_empty()
            && e.name.len() <= 128
            && e.name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !e.name.starts_with(|c: char| c.is_ascii_digit());
        if !ok || e.value.contains('\0') || e.value.len() > 8192 {
            r.error(
                "APP_ENV",
                &path,
                tr!(
                    "The environment variable's name or value is not valid",
                    "環境變數名稱或值無效",
                    "環境変数の名前または値が無効です"
                ),
            );
        } else if APP_RESERVED_ENV.contains(&e.name.as_str()) {
            let name = &e.name;
            r.error(
                "APP_ENV_RESERVED",
                &path,
                tr!(
                    "{name} is set by VPN Manager and cannot be overridden",
                    "{name} 由 VPN Manager 設定，不能覆寫",
                    "{name} は VPN Manager が設定するため、上書きできません"
                ),
            );
        } else if env[..i].iter().any(|o| o.name == e.name) {
            let name = &e.name;
            r.error(
                "APP_ENV_DUPLICATE",
                &path,
                tr!(
                    "{name} is set more than once",
                    "{name} 重複設定",
                    "{name} が重複しています"
                ),
            );
        }
    }
}

/// Where an App may write (`writable_paths`, `confine_writes`) and how long it gets to stop.
fn check_app_writes(r: &mut ValidationReport, a: &AppSpec) {
    match a.isolation {
        AppIsolation::ProxyEnv if !a.writable_paths.is_empty() => r.error(
            "APP_WRITABLE_MODE",
            "/writable_paths",
            tr!("“Proxy environment variables only” does not confine writes; leave this empty", "只設代理環境變數的模式不限制寫入；請留空", "「プロキシ環境変数の設定のみ」は書き込みを制限しません。空のままにしてください"),
        ),
        AppIsolation::StrictNetns if !a.writable_paths.is_empty() && !a.confine_writes => r
            .warning(
                "APP_WRITABLE_UNUSED",
                "/writable_paths",
                tr!("“Confine writes” is off: these directories are not applied, and the app can write anywhere its user can", "沒有開啟「限制寫入位置」：這些目錄不會套用，App 可以寫入它的使用者能寫的任何地方", "「書き込み先を制限」がオフです。これらのディレクトリは適用されず、アプリはそのユーザーが書き込めるすべての場所に書き込めます"),
            ),
        _ => {}
    }
    if a.confine_writes && a.isolation != AppIsolation::StrictNetns {
        r.error(
            "APP_CONFINE_MODE",
            "/confine_writes",
            tr!("Only strict isolation can confine writes as an option (enforced proxy confines writes anyway)", "只有嚴格隔離可以另外限制寫入位置（強制代理本來就限制寫入）", "書き込み先を別途制限できるのは厳格な分離だけです（強制プロキシはもともと書き込みを制限します）"),
        );
    }
    if !APP_STOP_GRACE_SECS.contains(&a.stop_grace_secs) {
        r.error(
            "APP_STOP_GRACE",
            "/stop_grace_secs",
            tr!(
                "The stop grace period must be between 1 and 900 seconds",
                "停止前等待的時間必須介於 1 與 900 秒",
                "停止の猶予時間は 1 から 900 秒の間にしてください"
            ),
        );
    }
    if a.writable_paths.len() > APP_MAX_WRITABLE {
        r.error(
            "APP_WRITABLE_COUNT",
            "/writable_paths",
            tr!(
                "At most 32 writable directories",
                "可寫入的目錄最多 32 個",
                "書き込み可能なディレクトリは最大 32 個です"
            ),
        );
    }
    for (i, p) in a.writable_paths.iter().enumerate() {
        if !app_path_ok(p) || p.trim_end_matches('/').is_empty() {
            r.error(
                "APP_WRITABLE_PATH",
                &format!("/writable_paths/{i}"),
                tr!("A writable directory must be an absolute path (without .., and not /)", "可寫入的目錄必須是絕對路徑（不含 ..，不可為 /）", "書き込み可能なディレクトリは絶対パスにしてください（.. を含まず、/ 以外のもの）"),
            );
        }
    }
}

pub fn check_app(a: &AppSpec) -> ValidationReport {
    let mut r = ValidationReport::default();
    check_name(&mut r, "/name", &a.name);
    if !app_path_ok(&a.executable) {
        r.error(
            "APP_EXECUTABLE",
            "/executable",
            tr!(
                "The executable must be an absolute path (without ..)",
                "執行檔必須是絕對路徑（不含 ..）",
                "実行ファイルは絶対パスにしてください（.. を含まないもの）"
            ),
        );
    }
    if a.args.len() > APP_MAX_ARGS
        || a.args.iter().map(String::len).sum::<usize>() > APP_MAX_ARGS_BYTES
        || a.args.iter().any(|x| x.len() > 4096 || x.contains('\0'))
    {
        r.error(
            "APP_ARGS",
            "/args",
            tr!(
                "At most 256 arguments, each of at most 4096 characters, without NUL",
                "參數最多 256 個、每個 4096 字元，且不可含 NUL",
                "引数は最大 256 個、それぞれ 4096 文字までで、NUL を含めることはできません"
            ),
        );
    }
    for (i, arg) in a.args.iter().enumerate() {
        let path = format!("/args/{i}");
        if arg.contains(APP_PLACEHOLDER_GATEWAY_PORT) && a.gateway_id.is_none() {
            r.error(
                "APP_PLACEHOLDER_GATEWAY",
                &path,
                tr!(
                    "{{gateway_port}} needs a Gateway to be chosen",
                    "{{gateway_port}} 需要選擇代理埠",
                    "{{gateway_port}} を使うにはゲートウェイを選択してください"
                ),
            );
        }
        for token in unknown_placeholders(arg) {
            r.warning(
                "APP_PLACEHOLDER_UNKNOWN",
                &path,
                tr!(
                    "{token} is not a placeholder that gets replaced; it is passed to the program as it is",
                    "{token} 不是可替換的符號，會原樣傳給程式",
                    "{token} は置き換えられるプレースホルダーではなく、そのままプログラムに渡されます"
                ),
            );
        }
    }
    if let Some(dir) = &a.working_dir
        && !app_path_ok(dir)
    {
        r.error(
            "APP_WORKING_DIR",
            "/working_dir",
            tr!(
                "The working directory must be an absolute path (without ..)",
                "工作目錄必須是絕對路徑（不含 ..）",
                "作業ディレクトリは絶対パスにしてください（.. を含まないもの）"
            ),
        );
    }
    check_app_env(&mut r, &a.env);
    match a.isolation {
        AppIsolation::ProxyEnv | AppIsolation::EnforcedProxy if a.gateway_id.is_none() => {
            r.error(
                "APP_GATEWAY",
                "/gateway_id",
                tr!(
                    "A proxy mode needs a Gateway of the same Instance",
                    "代理模式需要選擇同一 Instance 的 Gateway",
                    "プロキシモードでは同じ Instance のゲートウェイを選択する必要があります"
                ),
            );
        }
        AppIsolation::StrictNetns if a.gateway_id.is_some() => {
            r.error(
                "APP_GATEWAY_STRICT",
                "/gateway_id",
                tr!("A strictly isolated app has the tunnel as its only network interface and uses no Gateway", "嚴格隔離的 App 只有 tunnel 一個網路介面，不使用代理埠", "厳格な分離のアプリのネットワークインターフェースはトンネルだけで、ゲートウェイは使いません"),
            );
        }
        _ => {}
    }
    check_app_writes(&mut r, a);
    if a.isolation == AppIsolation::ProxyEnv {
        r.warning(
            "APP_PROXY_ONLY",
            "/isolation",
            tr!("Proxy environment variables only: connections that do not read the proxy settings are not protected", "只設定代理環境變數：不讀取代理設定的連線不受保護", "プロキシ環境変数の設定のみ：プロキシ設定を読まない接続は保護されません"),
        );
    }
    check_app_limits(&mut r, &a.limits);
    check_access_ports(&mut r, a);
    r.finish()
}

/// Why a start of an App of `class` gives no isolation under `enforced_proxy`.
#[must_use]
pub fn app_class_not_enforceable(class: &AppClassInfo) -> Text {
    let name = &class.name;
    match class.class {
        AppClass::Launcher => tr!(
            "“{name}” asks the system to start another program: the program that is started is not its child process and is not in VPN Manager's sandbox, so enforced proxy does not reach it. Name the program to run directly; “Proxy environment variables only” can run it, but does not guarantee that traffic goes through the VPN",
            "「{name}」會請系統另外啟動程式：被啟動的程式不是它的子程序，不在 VPN Manager 的沙箱裡，強制代理管不到它。請直接指定要執行的程式；「只設代理環境變數」可以執行，但不保證流量經過 VPN",
            "「{name}」はシステムにほかのプログラムの起動を依頼します。起動されたプログラムはその子プロセスではなく、VPN Manager のサンドボックスの中にもないため、強制プロキシが及びません。実行するプログラムを直接指定してください。「プロキシ環境変数の設定のみ」なら実行できますが、通信が VPN を経由する保証はありません"
        ),
        _ => tr!(
            "“{name}” is a macOS app, and VPN Manager cannot make it start as a separate new process every time: while it is already running, this start may be handed straight to the existing, unprotected process, and the limits of enforced proxy come to nothing. Apps of this kind cannot use enforced proxy; “Proxy environment variables only” can run it, but does not guarantee that traffic goes through the VPN",
            "「{name}」是 macOS App，VPN Manager 無法讓它一定以獨立的新程序啟動：它已在執行時，這次啟動可能直接交給既有、不受保護的程序，強制代理的限制就落空。這類 App 不能使用強制代理；「只設代理環境變數」可以執行，但不保證流量經過 VPN",
            "「{name}」は macOS アプリで、VPN Manager は毎回独立した新しいプロセスとして起動させることができません。すでに実行中のときは、今回の起動が保護されていない既存のプロセスにそのまま引き渡されることがあり、強制プロキシの制限が意味を失います。この種類のアプリは強制プロキシを使えません。「プロキシ環境変数の設定のみ」なら実行できますが、通信が VPN を経由する保証はありません"
        ),
    }
}

/// Rules that depend on what the App's executable is (`class`, from the executable check).
///
/// A browser's data directory is the launcher's, and a program that may hand its start to a process
/// VPN Manager did not start is refused under `enforced_proxy` instead of being run as if it were
/// confined.
///
/// Under `strict_netns` such a program is safe by construction (its own namespaces, `/run` and
/// `/tmp` masked: no running instance is reachable).
#[must_use]
pub fn check_app_class(a: &AppSpec, class: Option<&AppClassInfo>) -> ValidationReport {
    let mut r = ValidationReport::default();
    let Some(info) = class else {
        return r.finish();
    };
    for (i, arg) in a.args.iter().enumerate() {
        if info.class.selects_profile(arg) {
            let ours = info.class.launch_args().join(" ");
            let name = &info.name;
            r.error(
                "APP_PROFILE_ARG",
                &format!("/args/{i}"),
                tr!(
                    "VPN Manager sets the data directory of “{name}” ({ours}), so that it always starts as a separate process and is never handed to a browser that is already running; the arguments cannot set {arg} as well",
                    "「{name}」的資料目錄由 VPN Manager 指定（{ours}），讓它一定以獨立的程序啟動、不交給已在執行的瀏覽器；參數裡不能再指定 {arg}",
                    "「{name}」のデータディレクトリは VPN Manager が指定します（{ours}）。これにより常に独立したプロセスとして起動し、実行中のブラウザーに引き渡されることはありません。引数で {arg} を指定することはできません"
                ),
            );
        }
    }
    if info.class.may_hand_off() {
        match a.isolation {
            AppIsolation::EnforcedProxy => r.error(
                "APP_GUI_NOT_ENFORCEABLE",
                "/isolation",
                app_class_not_enforceable(info),
            ),
            AppIsolation::ProxyEnv => {
                let name = &info.name;
                r.warning(
                    "APP_GUI_HANDOFF",
                    "/executable",
                    match info.class {
                        AppClass::Launcher => tr!(
                            "“{name}” asks the system to start another program; the program that is started is not managed by VPN Manager, and its traffic does not necessarily go through the VPN",
                            "「{name}」會請系統另外啟動程式，被啟動的程式不由 VPN Manager 管理，流量也不一定經過 VPN",
                            "「{name}」はシステムにほかのプログラムの起動を依頼します。起動されたプログラムは VPN Manager の管理下になく、その通信が VPN を経由するとは限りません"
                        ),
                        _ => tr!(
                            "While “{name}” is already running, this start may be handed to the existing, unprotected process; proxy environment variables alone never guarantee that traffic goes through the VPN anyway",
                            "「{name}」已在執行時，這次啟動可能交給既有、不受保護的程序；只設代理環境變數本來就不保證流量經過 VPN",
                            "「{name}」がすでに実行中のときは、今回の起動が保護されていない既存のプロセスに引き渡されることがあります。そもそもプロキシ環境変数の設定だけでは、通信が VPN を経由する保証はありません"
                        ),
                    },
                );
            }
            AppIsolation::StrictNetns => {}
        }
    }
    r.finish()
}

/// Rules of one port forward that need nothing but the forward itself (the server adds those
/// that need the connection, its `WireGuard` settings and the target App).
#[must_use]
pub fn check_forward(f: &ForwardBinding) -> ValidationReport {
    let mut r = ValidationReport::default();
    check_name(&mut r, "/name", &f.name);
    if f.tunnel_port == 0 {
        r.error(
            "FORWARD_TUNNEL_PORT",
            "/tunnel_port",
            tr!(
                "The tunnel port must be between 1 and 65535",
                "tunnel port 必須介於 1 與 65535",
                "トンネルポートは 1 から 65535 の間にしてください"
            ),
        );
    }
    if f.public_port == Some(0) {
        r.error(
            "FORWARD_PUBLIC_PORT",
            "/public_port",
            tr!("The public port must be between 1 and 65535 (leave it empty if you do not know it)", "公開 port 必須介於 1 與 65535（不知道可以留空）", "公開ポートは 1 から 65535 の間にしてください（わからない場合は空のままにできます）"),
        );
    }
    if f.target_port < 1024 {
        r.error(
            "FORWARD_TARGET_PORT",
            "/target_port",
            tr!("The port the app listens on must be ≥ 1024 (the app needs no privileges and gets none)", "App 監聽的 port 必須 ≥ 1024（App 不需要也不會取得特權）", "アプリが待ち受けるポートは 1024 以上にしてください（アプリに特権は不要で、取得もしません）"),
        );
    }
    if !FORWARD_MAX_CONNECTIONS.contains(&f.max_connections) {
        let (min, max) = (
            FORWARD_MAX_CONNECTIONS.start(),
            FORWARD_MAX_CONNECTIONS.end(),
        );
        r.error(
            "FORWARD_CONNECTIONS",
            "/max_connections",
            tr!(
                "Concurrent connections must be between {min} and {max}",
                "同時連線數必須介於 {min} 與 {max}",
                "同時接続数は {min} から {max} の間にしてください"
            ),
        );
    }
    if f.assignment_source != AssignmentSource::Manual {
        r.error(
            "FORWARD_SOURCE",
            "/assignment_source",
            tr!(
                "No provider can verify a port assignment; it can only be entered by hand",
                "沒有供應商能核實 port 分配；只能手動登錄",
                "ポートの割り当てを確認できるプロバイダーはありません。手動でのみ登録できます"
            ),
        );
    }
    // The header opens a TCP stream; UDP datagrams are relayed as they are (with `both`, the
    // TCP side carries it and UDP is unchanged).
    if f.proxy_protocol && !f.protocol.tcp() {
        r.error(
            "FORWARD_PROXY_PROTOCOL_TCP_ONLY",
            "/proxy_protocol",
            tr!("PROXY protocol goes on TCP connections only; it cannot be turned on for a UDP-only forward", "PROXY protocol 只加在 TCP 連線上；只轉發 UDP 時不能開啟", "PROXY protocol は TCP 接続にだけ付けます。UDP だけを転送する場合は有効にできません"),
        );
    }
    // Straight into the sandbox, a datagram reaches the App on the tunnel port it came to:
    // nothing translates the port inside (the server adds: a strict connection and App).
    if f.udp_direct && !f.protocol.udp() {
        r.error(
            "FORWARD_UDP_DIRECT_NEEDS_UDP",
            "/udp_direct",
            tr!("“UDP straight into the sandbox” is for UDP only; it cannot be turned on for a TCP-only forward (choose UDP or TCP+UDP as the protocol)", "「UDP 直接送進沙箱」只用於 UDP；只轉發 TCP 時不能開啟（協定請選 UDP 或 TCP＋UDP）", "「UDP をサンドボックスへ直接送信」は UDP 専用です。TCP だけを転送する場合は有効にできません（プロトコルは UDP か TCP＋UDP を選んでください）"),
        );
    } else if f.udp_direct && f.target_port != f.tunnel_port {
        let (tunnel_port, target_port) = (f.tunnel_port, f.target_port);
        r.error(
            "FORWARD_UDP_DIRECT_SAME_PORT",
            "/udp_direct",
            tr!(
                "When UDP goes straight into the sandbox, datagrams arrive unchanged at tunnel port {tunnel_port}, with no address translation inside the sandbox: the app's port must equal the tunnel port (it is {target_port} now)",
                "UDP 直接送進沙箱時，datagram 原樣送到 tunnel port {tunnel_port}，沙箱內不轉換位址：App 的 port 必須等於 tunnel port（目前是 {target_port}）",
                "UDP をサンドボックスへ直接送る場合、データグラムはそのままトンネルポート {tunnel_port} に届き、サンドボックス内ではアドレスを変換しません。アプリのポートはトンネルポートと同じにしてください（現在は {target_port}）"
            ),
        );
    }
    r.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AutoBanSettings, PortRange};

    #[test]
    fn special_and_private_ranges() {
        for s in [
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "169.254.1.1",
            "::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(is_special(s.parse().unwrap()), "{s}");
        }
        assert!(
            is_special("::ffff:127.0.0.1".parse().unwrap()),
            "mapped loopback"
        );
        for s in [
            "10.0.0.1",
            "100.64.0.1",
            "192.168.1.1",
            "fd00::1",
            "2001:db8::1",
        ] {
            assert!(is_private(s.parse().unwrap()), "{s}");
        }
        assert!(!is_private("1.1.1.1".parse().unwrap()));
        assert!(!is_special("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn translated_addresses_are_the_ipv4_host_they_embed() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for (translated, host) in [
            ("::ffff:198.51.100.7", "198.51.100.7"),
            ("64:ff9b::198.51.100.7", "198.51.100.7"),
            ("64:ff9b::808:808", "8.8.8.8"),
            ("64:ff9b::", "0.0.0.0"),
        ] {
            assert_eq!(canonical_ip(ip(translated)), ip(host), "{translated}");
        }
        // Outside the /96, and other families' addresses, are themselves.
        for s in [
            "64:ff9b:0:0:0:1::1",
            "64:ff9b:1::808:808",
            "2606:4700::1111",
            "1.1.1.1",
        ] {
            assert_eq!(canonical_ip(ip(s)), ip(s), "{s}");
        }
        // So the IPv4 rules hold for the NAT64 form of an address too.
        for s in ["64:ff9b::127.0.0.1", "64:ff9b::a9fe:101", "64:ff9b::e000:1"] {
            assert!(is_special(ip(s)), "{s}");
        }
        for s in [
            "64:ff9b::10.0.0.1",
            "64:ff9b::192.168.1.1",
            "64:ff9b::100.64.0.1",
        ] {
            assert!(is_private(ip(s)), "{s}");
        }
        assert!(!is_private(ip("64:ff9b::1.1.1.1")));
        // The local-use prefix is not globally reachable.
        assert!(is_private(ip("64:ff9b:1::1.1.1.1")));
        assert!(is_private(ip("64:ff9b:1:ffff::1")));
        assert!(!is_private(ip("64:ff9b:2::1")));
    }

    fn security() -> SecurityProfile {
        use crate::{EntityMeta, SecurityProfileId, Timestamp};
        SecurityProfile {
            id: SecurityProfileId::new(),
            meta: EntityMeta {
                revision: 1,
                created_at: Timestamp::now(),
                updated_at: Timestamp::now(),
            },
            name: "office".into(),
            allow_private: vec!["10.0.0.0/8".parse().unwrap()],
            blocked_ports: vec![25],
            allowed_destinations: Vec::new(),
            allowed_ports: Vec::new(),
            blocklists: Vec::new(),
            auto_ban: AutoBanSettings::default(),
        }
    }

    fn issues(p: &SecurityProfile) -> Vec<(Severity, String, String)> {
        check_security_profile(p)
            .issues
            .into_iter()
            .map(|i| (i.severity, i.code, i.path))
            .collect()
    }

    #[test]
    fn allow_rules_never_open_special_addresses_and_are_bounded() {
        let p = SecurityProfile {
            allowed_destinations: vec![
                "1.1.1.0/24".parse().unwrap(),
                "127.0.0.0/8".parse().unwrap(),
                "ff02::/16".parse().unwrap(),
                "10.1.0.0/16".parse().unwrap(),
                "192.168.0.0/16".parse().unwrap(),
                "0.0.0.0/0".parse().unwrap(),
            ],
            allowed_ports: vec![
                PortRange { start: 80, end: 80 },
                PortRange { start: 0, end: 10 },
                PortRange {
                    start: 900,
                    end: 800,
                },
                PortRange {
                    start: 1024,
                    end: 65535,
                },
            ],
            ..security()
        };
        let found = issues(&p);
        let has = |sev: Severity, code: &str, path: &str| {
            found
                .iter()
                .any(|(s, c, p)| *s == sev && c == code && p == path)
        };
        assert!(has(
            Severity::Error,
            "ALLOWED_DESTINATION_INVALID",
            "/allowed_destinations/1"
        ));
        assert!(has(
            Severity::Error,
            "ALLOWED_DESTINATION_INVALID",
            "/allowed_destinations/2"
        ));
        // 10.1/16 is inside the allowed private 10/8; 192.168/16 is not.
        assert!(!has(
            Severity::Warning,
            "ALLOWED_DESTINATION_PRIVATE",
            "/allowed_destinations/3"
        ));
        assert!(has(
            Severity::Warning,
            "ALLOWED_DESTINATION_PRIVATE",
            "/allowed_destinations/4"
        ));
        assert!(has(
            Severity::Error,
            "PORT_RANGE_INVALID",
            "/allowed_ports/1"
        ));
        assert!(has(
            Severity::Error,
            "PORT_RANGE_INVALID",
            "/allowed_ports/2"
        ));
        assert_eq!(
            found.iter().filter(|(s, ..)| *s == Severity::Error).count(),
            4,
            "{found:?}"
        );

        let many = SecurityProfile {
            allowed_destinations: vec!["1.1.1.1/32".parse().unwrap(); MAX_POLICY_NETWORKS + 1],
            allowed_ports: vec![PortRange { start: 1, end: 2 }; MAX_PORT_RANGES + 1],
            blocked_ports: vec![9; MAX_BLOCKED_PORTS + 1],
            blocklists: vec![crate::BlocklistId::new(); 2],
            ..security()
        };
        let codes: Vec<String> = issues(&many).into_iter().map(|(_, c, _)| c).collect();
        for code in [
            "ALLOWED_DESTINATIONS_COUNT",
            "ALLOWED_PORTS_COUNT",
            "BLOCKED_PORTS_COUNT",
            "BLOCKLIST_DUPLICATE",
        ] {
            assert!(codes.iter().any(|c| c == code), "{code}: {codes:?}");
        }
    }

    #[test]
    fn blocklist_sources() {
        assert!(check_blocklist("FireHOL level 1", &BlocklistSource::Upload).valid);
        let url = |url: &str, refresh_hours| BlocklistSource::Url {
            url: url.into(),
            refresh_hours,
        };
        assert!(check_blocklist("x", &url("https://lists.example.net/a.txt", Some(24))).valid);
        assert!(check_blocklist("x", &url("https://lists.example.net/a.txt", None)).valid);
        let r = check_blocklist("x", &url("http://lists.example.net/a.txt", Some(1)));
        let codes: Vec<&str> = r.issues.iter().map(|i| i.code.as_str()).collect();
        assert_eq!(codes, ["BLOCKLIST_URL", "BLOCKLIST_REFRESH"]);
        assert!(!check_blocklist(" ", &BlocklistSource::Upload).valid);
    }
}

/// Why `host` can never be reached through a tunnel (an error), or `None`.
#[must_use]
pub fn ssh_vpn_unreachable(host: &str) -> Option<Text> {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") {
        return Some(tr!(
            "A local host name cannot be reached through the VPN",
            "本機名稱無法經 VPN 連線",
            "ローカルのホスト名には VPN 経由で接続できません"
        ));
    }
    // `h` is lowercase already; `.local` is its last label.
    if h.rsplit_once('.').is_some_and(|(_, tld)| tld == "local") {
        return Some(tr!(
            "An mDNS (.local) name exists only on the local network and cannot be reached through the VPN",
            "mDNS（.local）名稱只存在區網，無法經 VPN 連線",
            "mDNS（.local）の名前は LAN 内にしか存在せず、VPN 経由では接続できません"
        ));
    }
    if let Ok(ip) = h
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        && is_special(ip)
    {
        return Some(tr!(
            "A loopback, link-local or multicast address cannot be reached through the VPN",
            "loopback、link-local 或 multicast 位址無法經 VPN 到達",
            "ループバック、リンクローカル、マルチキャストのアドレスには VPN 経由で到達できません"
        ));
    }
    None
}

/// A private address (RFC 1918, CGNAT, ULA) is reachable through a tunnel only where allowed.
///
/// Only where the Instance's security profile allows it (an office or lab network behind the VPN);
/// otherwise the Gateway refuses — it never falls back to a direct connection.
pub fn ssh_vpn_private(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok_and(is_private)
}

/// A `HostName` that ssh and the resolver read the same way: a DNS name or a canonical IP literal.
///
/// IPv4 shorthands (`127.1`, `2130706433`, `0x7f.1`) are refused: they would slip past the
/// private-address check.
#[must_use]
pub fn valid_ssh_host_name(h: &str) -> bool {
    if h.parse::<IpAddr>().is_ok() {
        return true;
    }
    let last = h
        .trim_end_matches('.')
        .rsplit('.')
        .next()
        .unwrap_or_default();
    let numeric = !last.is_empty()
        && (last.chars().all(|c| c.is_ascii_digit())
            || last.to_ascii_lowercase().starts_with("0x"));
    !numeric && valid_hostname(h.trim_end_matches('.'))
}

fn ssh_alias_ok(a: &str) -> bool {
    let mut chars = a.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && a.len() <= 64
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// The fields of an SSH host entry of kind `host`: its address, user, port and identity file.
fn check_ssh_plain_host(r: &mut ValidationReport, h: &crate::config::SshHost) {
    match h.host_name.as_deref() {
        None | Some("") => {
            r.error("SSH_HOST_NAME_REQUIRED", "/host_name", tr!("Enter the host address", "請輸入主機位址", "ホストアドレスを入力してください"));
        }
        Some(n) if !valid_ssh_host_name(n) => r.error(
            "SSH_HOST_NAME",
            "/host_name",
            tr!("The host address must be a domain name or a complete IP address (short forms such as 127.1 are not accepted)", "主機位址必須是網域名稱或完整的 IP 位址（不接受 127.1 這類簡寫）", "ホストアドレスはドメイン名か完全な IP アドレスにしてください（127.1 のような省略形は使えません）"),
        ),
        Some(n) => {
            if h.gateway_id.is_some()
                && let Some(why) = ssh_vpn_unreachable(n)
            {
                r.error("SSH_NOT_VIA_VPN", "/host_name", why);
            }
            if h.gateway_id.is_some() && ssh_vpn_private(n) {
                r.warning(
                    "SSH_PRIVATE_VIA_VPN",
                    "/host_name",
                    tr!("A private address can be reached through the VPN only when this connection's security profile allows that network; otherwise the Gateway refuses it (it never falls back to the ordinary network)", "私有位址只有在這條連線的安全設定允許該網段時才能經 VPN 到達；否則代理埠會拒絕（不會改走一般網路）", "プライベートアドレスには、この接続のセキュリティ設定がそのネットワークを許可している場合にだけ VPN 経由で到達できます。許可されていなければゲートウェイが拒否します（通常のネットワークには切り替わりません）"),
                );
            }
            if h.gateway_id.is_some()
                && n.parse::<IpAddr>().is_err()
                && !n.trim_end_matches('.').contains('.')
            {
                r.warning(
                    "SSH_SINGLE_LABEL",
                    "/host_name",
                    tr!("A name without a domain usually resolves only on the local network and is not found through the VPN", "沒有網域的名稱通常只在區網可解析，經 VPN 時會找不到", "ドメインのない名前はたいてい LAN 内でしか名前解決できず、VPN 経由では見つかりません"),
                );
            }
            if h.alias == n.trim_end_matches('.') || h.alias.contains('.') {
                r.warning(
                    "SSH_ALIAS_RESOLVABLE",
                    "/alias",
                    tr!("When the alias itself can be resolved, ssh connects directly once the Include stops working; an alias without a . is recommended", "別名本身可被解析時，Include 失效後 ssh 會直接連線；建議使用不含 . 的別名", "エイリアス自体が名前解決できる場合、Include が効かなくなると ssh は直接接続します。. を含まないエイリアスをおすすめします"),
                );
            }
        }
    }
    if let Some(u) = &h.user
        && (u.is_empty()
            || u.len() > 64
            || u.starts_with('-')
            || !u
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@')))
    {
        r.error(
            "SSH_USER",
            "/user",
            tr!(
                "A user name may use only letters, digits and . _ - @",
                "使用者名稱只能使用英文字母、數字與 . _ - @",
                "ユーザー名に使えるのは英字、数字、. _ - @ だけです"
            ),
        );
    }
    if h.port == Some(0) {
        r.error(
            "SSH_PORT",
            "/port",
            tr!(
                "The port must be between 1 and 65535",
                "埠號必須介於 1 與 65535",
                "ポート番号は 1 から 65535 の間にしてください"
            ),
        );
    }
    if let Some(f) = &h.identity_file {
        let safe = f.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '@' | '+' | '~')
        });
        if !(f.starts_with("~/") || f.starts_with('/'))
            || f.len() > 255
            || !safe
            || f.split('/').any(|seg| seg == "..")
        {
            r.error(
                "SSH_IDENTITY_FILE",
                "/identity_file",
                tr!("The key file path must start with ~/ or / and contain no spaces, quotes, % or ..", "金鑰檔路徑必須以 ~/ 或 / 開頭，且不含空白、引號、% 或 ..", "鍵ファイルのパスは ~/ または / で始め、空白、引用符、%、.. を含まないようにしてください"),
            );
        }
    } else if h.identities_only {
        r.error(
            "SSH_IDENTITIES_ONLY",
            "/identities_only",
            tr!(
                "“Use only this key” needs a key file first",
                "「只用這把金鑰」需要先指定金鑰檔",
                "「この鍵だけを使う」には先に鍵ファイルを指定してください"
            ),
        );
    }
}

/// Field rules of an SSH host. Everything written into `vpn-manager.conf` comes from these
/// fields, so none of them may carry whitespace, quotes, `=`, `%` or a line break.
#[must_use]
pub fn check_ssh_host(h: &crate::config::SshHost) -> ValidationReport {
    use crate::config::SshHostKind;
    let mut r = ValidationReport::default();
    if !ssh_alias_ok(&h.alias) {
        r.error(
            "SSH_ALIAS",
            "/alias",
            tr!("An alias may use only lower-case letters, digits and . _ -, and must start with a letter or digit (at most 64 characters)", "別名只能使用小寫英文字母、數字與 . _ -，並以字母或數字開頭（最多 64 字元）", "エイリアスに使えるのは英小文字、数字、. _ - だけで、先頭は英字か数字にしてください（最大 64 文字）"),
        );
    }
    match h.kind {
        SshHostKind::Host => check_ssh_plain_host(&mut r, h),
        SshHostKind::Overlay => {
            if h.gateway_id.is_none() {
                r.error(
                    "SSH_OVERLAY_GATEWAY",
                    "/gateway_id",
                    tr!("An entry for an existing host is there to route it through the VPN: choose a Gateway", "既有主機項目用來讓它經 VPN，請選擇代理埠", "既存のホストの項目は VPN 経由にするためのものです。ゲートウェイを選択してください"),
                );
            }
            for (path, set) in [
                ("/host_name", h.host_name.is_some()),
                ("/user", h.user.is_some()),
                ("/port", h.port.is_some()),
                (
                    "/identity_file",
                    h.identity_file.is_some() || h.identities_only,
                ),
            ] {
                if set {
                    r.error(
                        "SSH_OVERLAY_FIELD",
                        path,
                        tr!("The other settings of an existing host stay in ~/.ssh/config and cannot be changed here", "既有主機的其他設定保留在 ~/.ssh/config，這裡不能修改", "既存のホストのほかの設定は ~/.ssh/config に残り、ここでは変更できません"),
                    );
                }
            }
        }
    }
    match (h.gateway_id.is_some(), h.server_alive_interval) {
        (true, None) => r.error(
            "SSH_INTERVAL_REQUIRED",
            "/server_alive_interval",
            tr!("A keepalive interval (10–240 seconds) is required through the VPN, so that idle connections are not cut", "經 VPN 時需要保活間隔（10–240 秒），閒置的連線才不會被中斷", "VPN 経由ではキープアライブ間隔（10–240 秒）が必要です。アイドル状態の接続が切断されないようにするためです"),
        ),
        (true, Some(s)) if !(10..=240).contains(&s) => r.error(
            "SSH_INTERVAL",
            "/server_alive_interval",
            tr!("Through the VPN, the keepalive interval must be between 10 and 240 seconds", "經 VPN 時保活間隔必須介於 10 與 240 秒", "VPN 経由では、キープアライブ間隔は 10 から 240 秒の間にしてください"),
        ),
        (false, Some(s)) if !(10..=3600).contains(&s) => r.error(
            "SSH_INTERVAL",
            "/server_alive_interval",
            tr!("The keepalive interval must be between 10 and 3600 seconds", "保活間隔必須介於 10 與 3600 秒", "キープアライブ間隔は 10 から 3600 秒の間にしてください"),
        ),
        _ => {}
    }
    r.finish()
}

#[cfg(test)]
mod ssh_tests {
    use std::str::FromStr;

    use super::*;
    use crate::{EntityMeta, GatewayId, SshHost, SshHostId, SshHostKind, Timestamp};

    fn host() -> SshHost {
        SshHost {
            id: SshHostId::new(),
            meta: EntityMeta {
                revision: 1,
                created_at: Timestamp::now(),
                updated_at: Timestamp::now(),
            },
            kind: SshHostKind::Host,
            alias: "work".into(),
            host_name: Some("git.example.com".into()),
            user: Some("deploy".into()),
            port: Some(22),
            identity_file: Some("~/.ssh/id_ed25519".into()),
            identities_only: true,
            gateway_id: Some(GatewayId::from_str("6f1c4a9e-2c1b-4c5e-9a40-0b7f1c2d3e4f").unwrap()),
            server_alive_interval: Some(60),
        }
    }

    fn codes(h: &SshHost) -> Vec<String> {
        check_ssh_host(h)
            .issues
            .into_iter()
            .filter(|i| i.severity == Severity::Error)
            .map(|i| i.code)
            .collect()
    }

    #[test]
    fn nothing_can_inject_ssh_directives() {
        for alias in ["work\nProxyCommand sh", "work x", "*", "Work", "-x", "a=b"] {
            assert!(
                codes(&SshHost {
                    alias: alias.into(),
                    ..host()
                })
                .contains(&"SSH_ALIAS".to_string()),
                "{alias:?}"
            );
        }
        for user in ["me\nHost x", "me x", "\"me\"", "-oProxyCommand=x"] {
            assert!(
                codes(&SshHost {
                    user: Some(user.into()),
                    ..host()
                })
                .contains(&"SSH_USER".to_string()),
                "{user:?}"
            );
        }
        for f in ["id_rsa", "~/../etc/x", "~/My Key", "~/a%h", "~/a\"b"] {
            assert!(
                codes(&SshHost {
                    identity_file: Some(f.into()),
                    ..host()
                })
                .contains(&"SSH_IDENTITY_FILE".to_string()),
                "{f:?}"
            );
        }
    }
}

#[cfg(test)]
mod app_tests {
    use super::*;
    use crate::{AppAccessPort, AppId, EntityMeta, EnvVar, GatewayId, InstanceId, Timestamp};

    fn app() -> AppSpec {
        AppSpec {
            id: AppId::new(),
            meta: EntityMeta {
                revision: 1,
                created_at: Timestamp::now(),
                updated_at: Timestamp::now(),
            },
            instance_id: InstanceId::new(),
            name: "browser".into(),
            executable: "/Applications/Firefox.app".into(),
            args: vec![
                "--profile".into(),
                "{app_home}/firefox".into(),
                "--proxy=socks5://127.0.0.1:{gateway_port}".into(),
            ],
            working_dir: None,
            env: vec![EnvVar {
                name: "LANG".into(),
                value: "zh_TW.UTF-8".into(),
            }],
            isolation: AppIsolation::EnforcedProxy,
            gateway_id: Some(GatewayId::new()),
            restart_on_recovery: false,
            writable_paths: vec!["/Users/me/Downloads".into()],
            confine_writes: false,
            stop_grace_secs: 10,
            approval: None,
            limits: AppLimits::default(),
            access_ports: Vec::new(),
        }
    }

    fn strict_app(access_ports: Vec<AppAccessPort>) -> AppSpec {
        AppSpec {
            isolation: AppIsolation::StrictNetns,
            gateway_id: None,
            writable_paths: Vec::new(),
            confine_writes: false,
            stop_grace_secs: 10,
            args: Vec::new(),
            access_ports,
            ..app()
        }
    }

    fn port(app_port: u16, host_port: u16, bind: AccessBind, allow: &[&str]) -> AppAccessPort {
        AppAccessPort {
            app_port,
            host_port,
            bind,
            allow: allow.iter().map(|n| n.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn a_lan_port_needs_an_allow_list_of_real_networks() {
        let lan = strict_app(vec![port(
            17890,
            17890,
            AccessBind::Lan,
            &["192.168.10.0/24", "192.168.20.0/24"],
        )]);
        assert!(check_app(&lan).valid, "{:?}", errors(&lan));
        // No list: nothing would be allowed — said so instead of listening for nobody.
        let none = strict_app(vec![port(17890, 17890, AccessBind::Lan, &[])]);
        assert_eq!(
            errors(&none),
            [(
                "APP_ACCESS_ALLOW_REQUIRED".to_string(),
                "/access_ports/0/allow".to_string()
            )]
        );
        // Loopback has no list.
        let loopback = strict_app(vec![port(
            17890,
            17890,
            AccessBind::Loopback,
            &["192.168.10.0/24"],
        )]);
        assert!(has(&loopback, "APP_ACCESS_ALLOW_LOOPBACK"));
        // Everything, loopback, multicast and link-local are refused, by position.
        let bad = strict_app(vec![port(
            17890,
            17890,
            AccessBind::Lan,
            &[
                "0.0.0.0/0",
                "127.0.0.0/8",
                "224.0.0.0/4",
                "fe80::/10",
                "::/0",
                "192.168.10.0/24",
                "192.168.10.9/24",
            ],
        )]);
        let found = errors(&bad);
        for j in 0..5 {
            assert!(
                found.contains(&(
                    "CLIENT_NETWORK".into(),
                    format!("/access_ports/0/allow/{j}")
                )),
                "{j}: {found:?}"
            );
        }
        // The same network twice, however written.
        assert!(found.contains(&(
            "CLIENT_NETWORK_DUPLICATE".into(),
            "/access_ports/0/allow/6".into()
        )));
        // A public range is allowed, with a warning.
        let public = strict_app(vec![port(
            17890,
            17890,
            AccessBind::Lan,
            &["203.0.112.0/24"],
        )]);
        let report = check_app(&public);
        assert!(report.valid);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "CLIENT_NETWORK_PUBLIC" && i.severity == Severity::Warning)
        );
    }

    #[test]
    fn allow_lists_match_by_network() {
        let nets: Vec<IpNetwork> = vec![
            "192.168.10.0/24".parse().unwrap(),
            "fd00:1::/64".parse().unwrap(),
        ];
        assert!(allows_client(&nets, "192.168.10.100".parse().unwrap()));
        assert!(allows_client(&nets, "::ffff:192.168.10.7".parse().unwrap()));
        assert!(allows_client(&nets, "fd00:1::5".parse().unwrap()));
        assert!(!allows_client(&nets, "192.168.20.100".parse().unwrap()));
        assert!(!allows_client(&nets, "fd00:2::5".parse().unwrap()));
        assert!(!allows_client(&[], "192.168.10.100".parse().unwrap()));
        assert_eq!(
            network_of("192.168.10.5/24".parse().unwrap()).to_string(),
            "192.168.10.0/24"
        );
    }

    fn errors(a: &AppSpec) -> Vec<(String, String)> {
        check_app(a)
            .issues
            .into_iter()
            .filter(|i| i.severity == Severity::Error)
            .map(|i| (i.code, i.path))
            .collect()
    }

    fn has(a: &AppSpec, code: &str) -> bool {
        errors(a).iter().any(|(c, _)| c == code)
    }

    #[test]
    fn paths_must_be_absolute_without_parent_segments() {
        for exe in ["firefox", "./x", "/usr/../bin/sh", "", "/a\0b"] {
            assert!(
                has(
                    &AppSpec {
                        executable: exe.into(),
                        ..app()
                    },
                    "APP_EXECUTABLE"
                ),
                "{exe:?}"
            );
        }
        assert!(has(
            &AppSpec {
                working_dir: Some("tmp".into()),
                ..app()
            },
            "APP_WORKING_DIR"
        ));
        for w in ["/", "relative", "/a/../b"] {
            assert!(
                has(
                    &AppSpec {
                        writable_paths: vec![w.into()],
                        confine_writes: false,
                        stop_grace_secs: 10,
                        ..app()
                    },
                    "APP_WRITABLE_PATH"
                ),
                "{w:?}"
            );
        }
    }

    #[test]
    fn injected_variables_cannot_be_overridden_or_duplicated() {
        for name in ["HOME", "TMPDIR", "ALL_PROXY", "https_proxy", "NO_PROXY"] {
            let a = AppSpec {
                env: vec![EnvVar {
                    name: name.into(),
                    value: "x".into(),
                }],
                ..app()
            };
            assert!(has(&a, "APP_ENV_RESERVED"), "{name}");
        }
        let dup = AppSpec {
            env: vec![
                EnvVar {
                    name: "A".into(),
                    value: "1".into(),
                },
                EnvVar {
                    name: "A".into(),
                    value: "2".into(),
                },
            ],
            ..app()
        };
        assert_eq!(
            errors(&dup),
            vec![("APP_ENV_DUPLICATE".to_string(), "/env/1".to_string())]
        );
        for bad in ["1A", "A-B", "A B", ""] {
            let a = AppSpec {
                env: vec![EnvVar {
                    name: bad.into(),
                    value: "x".into(),
                }],
                ..app()
            };
            assert!(has(&a, "APP_ENV"), "{bad:?}");
        }
    }

    fn class(class: AppClass, name: &str) -> AppClassInfo {
        AppClassInfo {
            class,
            name: name.into(),
            bundle_id: None,
        }
    }

    fn class_issues(a: &AppSpec, c: &AppClassInfo) -> Vec<(Severity, String, String)> {
        check_app_class(a, Some(c))
            .issues
            .into_iter()
            .map(|i| (i.severity, i.code, i.path))
            .collect()
    }

    #[test]
    fn a_browser_gets_a_data_directory_of_its_own_in_the_app_home() {
        for c in [AppClass::Chromium, AppClass::Firefox] {
            let args = c.launch_args();
            let dir = c.data_dir().unwrap();
            assert!(
                args.iter()
                    .any(|a| a.contains(&format!("{APP_PLACEHOLDER_HOME}/{dir}"))),
                "{c:?}: {args:?}"
            );
        }
        assert_eq!(
            AppClass::Chromium.launch_args(),
            ["--user-data-dir={app_home}/chromium-data"]
        );
        assert_eq!(
            AppClass::Firefox.launch_args(),
            [
                "-profile",
                "{app_home}/firefox-profile",
                "-no-remote",
                "-new-instance"
            ]
        );
        assert!(AppClass::Gui.launch_args().is_empty() && AppClass::Gui.data_dir().is_none());
        assert_eq!(AppClass::Launcher.launch_args(), [""; 0]);
        assert!(AppClass::Gui.may_hand_off() && AppClass::Launcher.may_hand_off());
        assert!(!AppClass::Chromium.may_hand_off() && !AppClass::Firefox.may_hand_off());
    }

    #[test]
    fn the_apps_own_profile_arguments_are_recognised() {
        let chromium = AppClass::Chromium;
        for a in [
            "--user-data-dir=/Users/me/Library/Application Support/Google/Chrome",
            "-user-data-dir=/x",
            "--user-data-dir",
            "--USER-DATA-DIR=/x",
        ] {
            assert!(chromium.selects_profile(a), "{a}");
        }
        for a in [
            "--profile-directory=Profile 1",
            "--proxy-server=socks5://127.0.0.1:1",
            "https://example.com/--user-data-dir=x",
            "user-data-dir",
        ] {
            assert!(!chromium.selects_profile(a), "{a}");
        }
        let firefox = AppClass::Firefox;
        for a in [
            "-profile",
            "--profile",
            "-P",
            "-p",
            "--ProfileManager",
            "-PROFILE",
        ] {
            assert!(firefox.selects_profile(a), "{a}");
        }
        for a in [
            "-no-remote",
            "-private-window",
            "https://example.com",
            "/profile",
        ] {
            assert!(!firefox.selects_profile(a), "{a}");
        }
        assert!(!AppClass::Gui.selects_profile("--user-data-dir=/x"));
    }

    #[test]
    fn a_browser_keeps_the_launchers_data_directory() {
        let chrome = class(AppClass::Chromium, "Google Chrome");
        let a = AppSpec {
            args: vec![
                "--proxy-server=socks5://127.0.0.1:{gateway_port}".into(),
                "--user-data-dir={app_home}/mine".into(),
            ],
            writable_paths: Vec::new(),
            confine_writes: false,
            stop_grace_secs: 10,
            ..app()
        };
        assert_eq!(
            class_issues(&a, &chrome),
            [(
                Severity::Error,
                "APP_PROFILE_ARG".to_string(),
                "/args/1".to_string()
            )]
        );
        // The fixture's own arguments (`--profile {app_home}/firefox`) are Firefox's profile.
        let firefox = class(AppClass::Firefox, "Firefox");
        let issues = class_issues(&app(), &firefox);
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].2, "/args/0");
        // Without such an argument a browser is fine in every mode.
        for isolation in [
            AppIsolation::ProxyEnv,
            AppIsolation::EnforcedProxy,
            AppIsolation::StrictNetns,
        ] {
            let ok = AppSpec {
                args: vec!["https://example.com".into()],
                isolation,
                ..app()
            };
            assert_eq!(check_app_class(&ok, Some(&chrome)).issues, []);
            assert_eq!(check_app_class(&ok, Some(&firefox)).issues, []);
        }
    }

    #[test]
    fn a_program_that_may_hand_off_is_refused_where_confinement_is_promised() {
        let safari = class(AppClass::Gui, "Safari");
        let open = class(AppClass::Launcher, "open");
        let in_mode = |isolation| AppSpec {
            args: Vec::new(),
            isolation,
            ..app()
        };
        for c in [&safari, &open] {
            // enforced_proxy: refused, saying why and what proxy_env does not guarantee.
            let r = check_app_class(&in_mode(AppIsolation::EnforcedProxy), Some(c));
            assert!(!r.valid);
            let refused = &r.issues[0];
            assert_eq!(
                (refused.code.as_str(), refused.path.as_str()),
                ("APP_GUI_NOT_ENFORCEABLE", "/isolation")
            );
            assert!(
                refused.message.zh_tw.contains(&c.name),
                "{}",
                refused.message.zh_tw
            );
            assert!(
                refused.message.zh_tw.contains("不保證流量經過 VPN"),
                "{}",
                refused.message.zh_tw
            );
            // proxy_env: allowed, with a warning.
            let r = check_app_class(&in_mode(AppIsolation::ProxyEnv), Some(c));
            assert!(r.valid);
            assert_eq!(r.issues[0].code, "APP_GUI_HANDOFF");
            assert_eq!(r.issues[0].severity, Severity::Warning);
            // strict_netns (Linux): safe by construction.
            assert_eq!(
                check_app_class(&in_mode(AppIsolation::StrictNetns), Some(c)).issues,
                []
            );
        }
        // An ordinary program has no class rules.
        assert!(check_app_class(&in_mode(AppIsolation::EnforcedProxy), None).valid);
    }
}
