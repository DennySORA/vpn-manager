// SPDX-License-Identifier: GPL-3.0-or-later

//! The Ports page's XHR answers (observed in a browser on 2026-11-02, and read from the page's
//! own scripts for the calls whose success was not captured):
//!
//! - `action=manifest` → `{"pool":2,"ports":[…],"keys":[{"id":"<50 hex>","name":"Default"}]}`;
//! - `action=insert` → the new port: `{"port":35786,"pool":2,"notes":null,"enabled":true,
//!   "device":"all","protocol":"both","iplayer":"both","local":35786,"dns":""}`;
//! - `action=delete` → `[]`;
//! - `action=edit_*` → the page shows "Saved" for any JSON object without an `error`;
//! - `action=sessions` → `{"items":[…]}`, one item per protocol and IP layer of each connected
//!   session that uses the port (observed without one: `{"items":[]}`);
//! - `action=test` → `{"type":<word>,"message":<text>}`, the page's `air_message_<type>`;
//! - `action=ddns_report` → `{"items":[{"name","nsessions","ipv4","ipv6",…}],"services":…}`;
//! - `action=seq_search` → `{"message":<text>}`.
//!
//! The page counts any JSON object with an `error` string as a failure and shows the text.
//!
//! Defensive: fields nobody uses are ignored; a field this client relies on that is missing or
//! out of shape is contract drift and names the field. Numbers may arrive as numeric strings
//! and flags as `0`/`1`. Display-only text (notes, DDNS name, an unknown IP layer word, a
//! server's name and place) is kept when it is plain text and dropped otherwise, never a reason
//! to fail an answer.

use std::net::IpAddr;

use serde_json::{Map, Value};
use vpn_domain::{
    AIRDNS_SUFFIX, ForwardProtocol, ForwardedPortDdnsName, IpFamily, PortTestState, Text, tr,
};

use super::MAX_NOTES;

/// Far more than the account may hold (5): anything near it is not the contract.
const MAX_LISTED: usize = 64;
const MAX_DEVICES: usize = 256;
const MAX_ID: usize = 128;
const MAX_DEVICE_NAME: usize = 64;
const MAX_DNS: usize = 253;
const MAX_POOL: u64 = 1_000_000;
/// Far more than an account's connected sessions times protocols and IP layers.
const MAX_SESSIONS: usize = 64;
const MAX_DDNS: usize = 64;
const MAX_PLACE: usize = 64;
const MAX_ADDRESS: usize = 64;
const MAX_WORD: usize = 32;

/// One forwarded port of the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub port: u16,
    /// `AirVPN`'s pool of the port; a delete names it.
    pub pool: u32,
    pub enabled: bool,
    pub protocol: ForwardProtocol,
    /// `both`, `ipv4`, `ipv6`, or `AirVPN`'s own word (lower case) for another choice.
    pub ip_layer: String,
    /// The device the port is limited to (`None`: every device, `AirVPN`'s `all`).
    pub device: Option<String>,
    /// Where `AirVPN` delivers it on the tunnel address when that is not `port` (`AirVPN`'s "local
    /// port"; `None` when equal or unset).
    pub local: Option<u16>,
    /// `AirVPN`'s DDNS name for it, the part before `.airdns.org`, in lower case.
    pub dns: Option<String>,
    pub notes: Option<String>,
}

impl Port {
    /// The port on the tunnel address that the forwarded traffic arrives at.
    #[must_use]
    pub fn local_port(&self) -> u16 {
        self.local.unwrap_or(self.port)
    }
}

/// One of the account's devices as the Ports page names it (`keys`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceName {
    pub id: String,
    pub name: String,
}

/// The account's forwarded ports and devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortList {
    pub ports: Vec<Port>,
    pub devices: Vec<DeviceName>,
    /// The pool the page names for the account, when it does.
    pub pool: Option<u32>,
}

impl PortList {
    #[must_use]
    pub fn device_name(&self, id: &str) -> Option<&str> {
        self.devices
            .iter()
            .find(|d| d.id == id)
            .map(|d| d.name.as_str())
    }
}

/// One connected session that uses a port, for one protocol and IP layer (`action=sessions`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SessionItem {
    pub(super) port: u16,
    pub(super) pool: u32,
    /// `tcp` or `udp`.
    pub(super) protocol: ForwardProtocol,
    pub(super) family: IpFamily,
    /// A valid address, as `AirVPN` wrote it: the test names it back.
    pub(super) server_ip: String,
    pub(super) server_name: Option<String>,
    pub(super) server_location: Option<String>,
    /// Two letters, lower case.
    pub(super) server_country: Option<String>,
    pub(super) client_ip: Option<String>,
    pub(super) local: Option<u16>,
    pub(super) device_name: Option<String>,
}

/// `AirVPN`'s verdict of one test (`action=test`): its word and its message, still raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Verdict {
    pub(super) word: String,
    pub(super) message: Option<String>,
}

/// What a parser makes of an answer: `None` when it is not the success shape at all (the caller
/// decides what it is), `Some(Err(field))` when it is but a field drifted (the field named for a
/// person).
pub(super) type Parsed<T> = Option<Result<T, Text>>;

fn json(body: &[u8]) -> Option<Value> {
    serde_json::from_slice(body).ok()
}

/// A JSON object the page counts as a success: one without an `error` string.
fn success(body: &[u8]) -> Option<Map<String, Value>> {
    match json(body)? {
        Value::Object(o) if !o.get("error").is_some_and(Value::is_string) => Some(o),
        _ => None,
    }
}

/// The `error` of an answer the page counts as a failure (a JSON object with an `error`
/// string). Still raw: the caller decides whether it can be shown.
pub(super) fn failure(body: &[u8]) -> Option<String> {
    match json(body)? {
        Value::Object(o) => o.get("error").and_then(Value::as_str).map(str::to_owned),
        _ => None,
    }
}

/// `action=manifest`.
pub(super) fn list(body: &[u8]) -> Parsed<PortList> {
    let value = json(body)?;
    let object = value.as_object()?;
    if !object.contains_key("ports") && !object.contains_key("keys") {
        return None;
    }
    Some(list_of(object))
}

fn list_of(o: &Map<String, Value>) -> Result<PortList, Text> {
    let field = |name: &str| {
        tr!(
            "{name} of the inbound port list",
            "連入埠清單的 {name}",
            "着信ポート一覧の {name}"
        )
    };
    let device_name = || tr!("device name", "裝置名稱", "デバイス名");
    let ports = o
        .get("ports")
        .and_then(Value::as_array)
        .ok_or_else(|| field("ports"))?;
    if ports.len() > MAX_LISTED {
        return Err(tr!(
            "inbound port list too long",
            "連入埠清單過長",
            "着信ポート一覧が長すぎる"
        ));
    }
    let keys = o
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| field("keys"))?;
    if keys.len() > MAX_DEVICES {
        return Err(tr!(
            "device list too long",
            "裝置清單過長",
            "デバイス一覧が長すぎる"
        ));
    }
    let devices = keys
        .iter()
        .map(|k| {
            let k = k
                .as_object()
                .ok_or_else(|| tr!("device list", "裝置清單", "デバイス一覧"))?;
            let id = k
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| valid_id(id))
                .ok_or_else(|| tr!("id of a device", "裝置的 id", "デバイスの id"))?;
            let name = match k.get("name") {
                Some(Value::String(n)) => crate::display_text(n, MAX_DEVICE_NAME)
                    .map_err(|_| device_name())?
                    .unwrap_or_else(|| id.to_owned()),
                _ => return Err(device_name()),
            };
            Ok(DeviceName {
                id: id.to_owned(),
                name,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let ports = ports
        .iter()
        .map(|p| {
            p.as_object()
                .ok_or_else(|| tr!("inbound port", "連入埠", "着信ポート"))
                .and_then(port_of)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PortList {
        ports,
        devices,
        pool: o.get("pool").and_then(pool),
    })
}

/// `action=insert`: the port object.
pub(super) fn inserted(body: &[u8]) -> Parsed<Port> {
    let value = json(body)?;
    let object = value.as_object()?;
    object.contains_key("port").then(|| port_of(object))
}

/// `action=delete`: `[]`.
pub(super) fn deleted(body: &[u8]) -> Parsed<()> {
    match json(body)? {
        Value::Array(a) if a.is_empty() => Some(Ok(())),
        _ => None,
    }
}

/// A message an answer that is not the success shape carries: `{"error": …}`,
/// `{"message": …}`, `{"msg": …}` or a bare JSON string. Still raw: the caller decides whether
/// it can be shown.
pub(super) fn said(body: &[u8]) -> Option<String> {
    match json(body)? {
        Value::String(s) => Some(s),
        Value::Object(o) => ["error", "message", "msg"]
            .iter()
            .find_map(|k| o.get(*k).and_then(Value::as_str).map(str::to_owned)),
        _ => None,
    }
}

/// `action=edit_*`: any JSON object without an `error` (the page then shows "Saved").
pub(super) fn edited(body: &[u8]) -> Parsed<()> {
    success(body).map(|_| Ok(()))
}

/// `action=sessions`: `{"items":[…]}`.
pub(super) fn sessions(body: &[u8]) -> Parsed<Vec<SessionItem>> {
    let o = success(body)?;
    let items = o.get("items")?;
    Some(sessions_of(items))
}

fn sessions_of(items: &Value) -> Result<Vec<SessionItem>, Text> {
    let items = items.as_array().ok_or_else(|| {
        tr!(
            "items of the connection list",
            "連線清單的 items",
            "接続一覧の items"
        )
    })?;
    if items.len() > MAX_SESSIONS {
        return Err(tr!(
            "connection list too long",
            "連線清單過長",
            "接続一覧が長すぎる"
        ));
    }
    items
        .iter()
        .map(|i| {
            i.as_object()
                .ok_or_else(|| tr!("connection list", "連線清單", "接続一覧"))
                .and_then(session_of)
        })
        .collect()
}

fn session_of(o: &Map<String, Value>) -> Result<SessionItem, Text> {
    let field = |name: &str| tr!("{name} of a connection", "連線的 {name}", "接続の {name}");
    let port = o
        .get("port")
        .and_then(port_number)
        .ok_or_else(|| field("port"))?;
    let pool = o.get("pool").and_then(pool).ok_or_else(|| field("pool"))?;
    let protocol = match o
        .get("protocol")
        .and_then(Value::as_str)
        .map(|p| p.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("tcp") => ForwardProtocol::Tcp,
        Some("udp") => ForwardProtocol::Udp,
        _ => return Err(field("protocol")),
    };
    let family = o
        .get("iplayer")
        .and_then(Value::as_str)
        .and_then(family)
        .ok_or_else(|| field("iplayer"))?;
    let server_ip = o
        .get("server_ip")
        .and_then(address)
        .ok_or_else(|| field("server_ip"))?;
    let server_country = o
        .get("server_country")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()))
        .map(str::to_ascii_lowercase);
    let local = o.get("local").and_then(port_number).filter(|l| *l != port);
    Ok(SessionItem {
        port,
        pool,
        protocol,
        family,
        server_ip,
        server_name: text(o, "server_name", MAX_PLACE),
        server_location: text(o, "server_location", MAX_PLACE),
        server_country,
        client_ip: o.get("client_ip").and_then(address),
        local,
        device_name: text(o, "device_name", MAX_DEVICE_NAME),
    })
}

/// `action=test`: `{"type":<word>,"message":<text>}`.
pub(super) fn probed(body: &[u8]) -> Parsed<Verdict> {
    let o = success(body)?;
    let word = o.get("type")?;
    let word = word
        .as_str()
        .map(|w| w.trim().to_ascii_lowercase())
        .filter(|w| {
            !w.is_empty()
                && w.len() <= MAX_WORD
                && w.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        });
    let drift = || {
        tr!(
            "type of the test result",
            "測試結果的 type",
            "テスト結果の type"
        )
    };
    Some(word.ok_or_else(drift).map(|word| Verdict {
        word,
        message: o.get("message").and_then(Value::as_str).map(str::to_owned),
    }))
}

/// What `AirVPN`'s answer to a test means (the page styles it `air_message_<word>`). Observed on
/// 2026-11-02 against a real account: an open port is `{"type":"info","message":"Open!"}`, a
/// closed one `{"type":"error","message":"Connection refused (111)"}`. `info` alone is only
/// information, so it counts as open only with that message; any other word stays unknown —
/// never a success.
pub(super) fn verdict(word: &str, message: Option<&str>) -> PortTestState {
    let says_open = message.is_some_and(|m| m.trim().to_ascii_lowercase().starts_with("open"));
    match word {
        "ok" | "success" | "open" => PortTestState::Open,
        "info" if says_open => PortTestState::Open,
        "error" | "danger" | "fail" | "failed" | "failure" | "closed" => PortTestState::Closed,
        "warning" | "warn" => PortTestState::Warning,
        _ => PortTestState::Unknown,
    }
}

/// `action=ddns_report`: `{"items":[…],"services":…}` (the services are not used).
pub(super) fn ddns(body: &[u8]) -> Parsed<Vec<ForwardedPortDdnsName>> {
    let o = success(body)?;
    let items = o.get("items")?;
    Some(ddns_of(items))
}

fn ddns_of(items: &Value) -> Result<Vec<ForwardedPortDdnsName>, Text> {
    let field = |name: &str| tr!("{name} of a DDNS name", "DDNS 的 {name}", "DDNS の {name}");
    let items = items.as_array().ok_or_else(|| {
        tr!(
            "items of the DDNS check",
            "DDNS 檢查的 items",
            "DDNS チェックの items"
        )
    })?;
    if items.len() > MAX_DDNS {
        return Err(tr!(
            "DDNS check too long",
            "DDNS 檢查過長",
            "DDNS チェックが長すぎる"
        ));
    }
    items
        .iter()
        .map(|i| {
            let o = i
                .as_object()
                .ok_or_else(|| tr!("DDNS check", "DDNS 檢查", "DDNS チェック"))?;
            Ok(ForwardedPortDdnsName {
                name: o
                    .get("name")
                    .and_then(Value::as_str)
                    .and_then(ddns_label)
                    .ok_or_else(|| field("name"))?,
                sessions: o
                    .get("nsessions")
                    .and_then(number)
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| field("nsessions"))?,
                ipv4: text(o, "ipv4", MAX_ADDRESS),
                ipv6: text(o, "ipv6", MAX_ADDRESS),
            })
        })
        .collect()
}

/// `action=seq_search`: `{"message":<text>}`, still raw.
pub(super) fn found(body: &[u8]) -> Parsed<String> {
    let o = success(body)?;
    let message = o.get("message")?;
    Some(message.as_str().map(str::to_owned).ok_or_else(|| {
        tr!(
            "message of the consecutive free port search",
            "連續空閒埠的 message",
            "連続した空きポート検索の message"
        )
    }))
}

/// A DDNS name as the page shows it before `.airdns.org`: lower case, without the suffix when an
/// answer carries it. `None` when empty or not plain text.
fn ddns_label(raw: &str) -> Option<String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let name = name.trim_suffix(AIRDNS_SUFFIX);
    crate::display_text(name, MAX_DNS).ok().flatten()
}

fn port_of(o: &Map<String, Value>) -> Result<Port, Text> {
    let field = |name: &str| {
        tr!(
            "{name} of an inbound port",
            "連入埠的 {name}",
            "着信ポートの {name}"
        )
    };
    let port = o
        .get("port")
        .and_then(port_number)
        .ok_or_else(|| field("port"))?;
    let pool = o.get("pool").and_then(pool).ok_or_else(|| field("pool"))?;
    let enabled = o
        .get("enabled")
        .and_then(flag)
        .ok_or_else(|| field("enabled"))?;
    let device = match o.get("device") {
        Some(Value::String(d)) => {
            let d = d.trim();
            if d.is_empty() || d.eq_ignore_ascii_case("all") {
                None
            } else if valid_id(d) {
                Some(d.to_owned())
            } else {
                return Err(field("device"));
            }
        }
        Some(Value::Null) => None,
        _ => return Err(field("device")),
    };
    let protocol = o
        .get("protocol")
        .and_then(Value::as_str)
        .and_then(protocol)
        .ok_or_else(|| field("protocol"))?;
    let ip_layer = o
        .get("iplayer")
        .and_then(Value::as_str)
        .and_then(ip_layer)
        .ok_or_else(|| field("iplayer"))?;
    let local = match o.get("local") {
        None => return Err(field("local")),
        Some(Value::Null) => None,
        Some(Value::String(s)) if s.trim().is_empty() => None,
        Some(v) => match number(v) {
            Some(0) => None,
            Some(n) => Some(u16::try_from(n).map_err(|_| field("local"))?),
            None => return Err(field("local")),
        },
    }
    .filter(|l| *l != port);
    Ok(Port {
        port,
        pool,
        enabled,
        protocol,
        ip_layer,
        device,
        local,
        dns: o.get("dns").and_then(Value::as_str).and_then(ddns_label),
        notes: o.get("notes").and_then(Value::as_str).and_then(notes),
    })
}

/// A string field as display text (`None` when absent, empty or not plain).
fn text(o: &Map<String, Value>, key: &str, max: usize) -> Option<String> {
    o.get(key)
        .and_then(Value::as_str)
        .and_then(|s| crate::display_text(s, max).ok().flatten())
}

/// An IP address as written (trimmed), when it is one.
fn address(v: &Value) -> Option<String> {
    let a = v.as_str()?.trim();
    a.parse::<IpAddr>().is_ok().then(|| a.to_owned())
}

fn pool(v: &Value) -> Option<u32> {
    number(v)
        .filter(|p| *p <= MAX_POOL)
        .and_then(|p| u32::try_from(p).ok())
}

/// A session's IP layer: `v4` or `v6` (observed), and their usual spellings.
fn family(raw: &str) -> Option<IpFamily> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "v4" | "ipv4" | "4" => Some(IpFamily::Ipv4),
        "v6" | "ipv6" | "6" => Some(IpFamily::Ipv6),
        _ => None,
    }
}

/// A JSON number or a numeric string, as an unsigned integer.
fn number(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => {
            let s = s.trim();
            (!s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit()))
                .then(|| s.parse().ok())
                .flatten()
        }
        _ => None,
    }
}

fn port_number(v: &Value) -> Option<u16> {
    number(v)
        .and_then(|n| u16::try_from(n).ok())
        .filter(|p| *p > 0)
}

fn flag(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => match n.as_u64() {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => None,
        },
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// `AirVPN`'s device key ids (50 hex digits today); any plain identifier is accepted.
pub(super) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `both` (observed), `tcp`, `udp`, and the ways a page may write "both".
pub(super) fn protocol(raw: &str) -> Option<ForwardProtocol> {
    let p: String = raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    match p.as_str() {
        "both" | "all" | "tcp+udp" | "tcp&udp" | "tcp/udp" | "tcpudp" | "tcp_udp" | "udp+tcp"
        | "udp/tcp" => Some(ForwardProtocol::Both),
        "tcp" => Some(ForwardProtocol::Tcp),
        "udp" => Some(ForwardProtocol::Udp),
        _ => None,
    }
}

/// `both` (observed), `ipv4`, `ipv6` and their usual spellings; any other plain word is kept as
/// `AirVPN` wrote it (it is shown, never acted on).
pub(super) fn ip_layer(raw: &str) -> Option<String> {
    let l: String = raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    let known = match l.as_str() {
        "both" | "all" | "dual" | "ipv4+ipv6" | "ipv4&ipv6" | "ipv4/ipv6" | "4+6" | "46"
        | "4and6" => "both",
        "ipv4" | "4" | "v4" | "ip4" | "ipv4only" => "ipv4",
        "ipv6" | "6" | "v6" | "ip6" | "ipv6only" => "ipv6",
        _ => {
            return crate::display_text(&l, 32).ok().flatten();
        }
    };
    Some(known.to_owned())
}

/// Notes are the member's own free text: control characters become spaces, at most 200
/// characters are kept.
pub(super) fn notes(raw: &str) -> Option<String> {
    let text: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_NOTES)
        .collect();
    (!text.is_empty()).then_some(text)
}
