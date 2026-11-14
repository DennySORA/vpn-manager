// SPDX-License-Identifier: GPL-3.0-or-later

//! `AirVPN`'s website as a signed-in member uses it, for one thing: the account's forwarded ports.
//!
//! `AirVPN`'s API (`airvpn.org/apisettings`: userinfo, status, notification, server, devices,
//! `dns_lists`, generator, disconnect, whatismyip) has no port service; the Client Area's Ports
//! page (`https://airvpn.org/ports/`) manages them with XHR form posts, and this module makes
//! those posts on the member's behalf with the account's own user name and password: everything
//! the page does — list, reserve, delete, change a port's settings, test it, the DDNS check and
//! the search for consecutive free ports — except its picture of used ports per pool (`graph`).
//!
//! The protocol, as observed with a signed-in browser on 2026-11-02 (and read from the page's own
//! scripts for the calls whose success was not captured) and, for what a signed-out client sees,
//! read from the public pages the same day:
//!
//! - **Sign-in** (Invision Community 4): `GET /login/` serves the form `POST /login/` with the
//!   hidden `csrfKey` (and `ref` on pages that link back), `auth` ("Display Name or Email
//!   Address"), `password`, the checkboxes `remember_me` (checked) and `anonymous`, and the
//!   submit button `_processLogin=usernamepassword`. This client posts what the form holds,
//!   with "Sign in anonymously" checked (a background sign-in should not show the member as
//!   online) and "Remember me" unchecked (no long-lived sign-in key for a session that lives in
//!   memory only). Every answer of the site carries `X-IPS-LoggedIn: 0|1`.
//! - **Page token**: the signed-in `GET /ports/` has an element `id="air_data"` whose
//!   `data-json` (HTML-escaped JSON) holds `ecsrf`, 64 hex digits. Signed out, the same element
//!   has no `ecsrf` and the page says "Login required.".
//! - **Port calls**: `POST /ports/` (`Content-Type: application/x-www-form-urlencoded;
//!   charset=UTF-8`, `X-Requested-With: XMLHttpRequest`, `Origin: https://airvpn.org`,
//!   `Referer: https://airvpn.org/ports/`, the session cookies) with `action=<name>`, the
//!   action's fields, `ecsrf=…` and `render=ajax`, in that order; answers in [`ports`]:
//!   - `manifest` (the list); `insert` with `port` (empty: `AirVPN` picks one); `delete` with
//!     `port` and `pool`;
//!   - one setting per call, as the page sends it when a control changes, each with `port`,
//!     `pool` and `value`: `edit_note`, `edit_enabled` (`1`/`0`), `edit_device` (`all` or a
//!     device key id of the list), `edit_protocol` (`both`/`tcp`/`udp`), `edit_layer`
//!     (`both`/`v4`/`v6`), `edit_localport`, `edit_ddns` (the name before `.airdns.org`; empty
//!     clears it);
//!   - `sessions` with `port` and `pool`: the connected sessions that use the port, one item per
//!     protocol and IP layer; then `test` with `ip` (the item's server), `port`, `pool` and
//!     `protocol` for each TCP item (the page tests no UDP);
//!   - `ddns_report` (the DDNS check) and `seq_search` with `n` (consecutive free ports).
//! - **Rules of the page**: at most [`MAX_PORTS`] ports per account, the same on every server;
//!   ports from [`MIN_PORT`] (the page's input minimum); notes up to [`MAX_NOTES`] characters,
//!   DDNS names up to [`MAX_DDNS_NAME`]; released 10 days after a premium plan expires. For P2P
//!   the program must listen on the forwarded port itself: never remapped.
//!
//! How this client behaves:
//!
//! - Every request is one request through the caller's [`HttpsClient`]: in the product the
//!   operation's Provider egress guard (a fresh exit check, the per-origin budget, relay line
//!   v2 through the egress connection). Nothing here dials or resolves.
//! - The session ([`Session`]: cookies and the page token) lives in memory only, is sent only to
//!   airvpn.org, and is never printed. It is reused across operations; the token is fetched
//!   again only after an answer says the session is signed out (or its token stale), and then
//!   with one new sign-in per operation at most — a second signed-out answer is an error, never
//!   a loop of sign-ins.
//! - A sign-in that the site refuses is told apart: wrong password ([`SiteError::LoginRejected`]),
//!   too many attempts, a CAPTCHA, a second factor, a changed form (nothing is posted then).
//! - A reservation or delete whose answer is not the known success is reconciled against a fresh
//!   list (a new port appeared, or the port is gone) instead of being sent again.
//! - A settings change is checked first as the page checks it (nothing is sent otherwise), sends
//!   only the settings that differ from a fresh list, one request each, then reads the list
//!   back: a setting counts as saved only when the read-back shows it. One refused, read back
//!   different or not sent is named with `AirVPN`'s reason ([`SiteError::NotSaved`]).
//! - A test answers per session. A word for the result this client does not know stays unknown,
//!   never a success. Each test waits at most [`PROBE_TIMEOUT`], and none starts after
//!   [`TEST_TIME`]: the rest are reported untested.
//! - An answer outside the known shape is contract drift, logged at debug level with its status
//!   and a short snippet scrubbed of the user name, password, cookies, token and anything
//!   token-like. Errors never carry a page or a secret.

mod cookies;
mod html;
mod ports;

use std::fmt;
use std::ops::RangeInclusive;
use std::time::Duration;

use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, StatusCode};
use time::OffsetDateTime;
use tokio::time::Instant;
use vpn_domain::{
    AIRDNS_SUFFIX, ErrorCode, ForwardProtocol, ForwardedPortDdns, ForwardedPortSearch,
    ForwardedPortSession, ForwardedPortTest, ForwardedPortUpdate, PortIpLayer, PortTestState, Text,
    Timestamp, tr,
};
use zeroize::Zeroizing;

pub use ports::{DeviceName, Port, PortList};

use self::cookies::Jar;
use self::html::{FormProblem, Token};
use self::ports::SessionItem;
use super::Credentials;
use crate::error::{ProviderError, Unavailable, status_error};
use crate::https::{Connect, DEFAULT_TIMEOUT, Family, HttpError, HttpsClient, Request};

/// The website's origin; every request of this module goes here and nowhere else.
pub const SITE_HOST: &str = "airvpn.org";
/// Ports an account may hold ("You are using N of 5").
pub const MAX_PORTS: usize = 5;
/// The lowest port the page accepts (its input's minimum; `AirVPN` reserves ports from 2048 up).
pub const MIN_PORT: u16 = 2049;
/// The page's limit for a port's notes, in characters.
pub const MAX_NOTES: usize = 200;
/// The page's limit for a DDNS name before [`AIRDNS_SUFFIX`], in characters.
pub const MAX_DDNS_NAME: usize = 60;
/// The page's word for every device of the account.
pub const ALL_DEVICES: &str = "all";
/// How many consecutive free ports one search may ask for.
pub const SEARCH_COUNT: RangeInclusive<u8> = 2..=10;
/// How long `AirVPN` may take to test a port from one server.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
/// No test of a port's sessions starts this long after the operation began.
pub const TEST_TIME: Duration = Duration::from_secs(35);
/// A test is not started with less time than this left.
const MIN_PROBE: Duration = Duration::from_secs(5);
/// Longest answer of a search for free ports that is shown (it may list ten ports).
const MAX_SEARCH_TEXT: usize = 400;

const LOGIN_PATH: &str = "/login/";
const PORTS_PATH: &str = "/ports/";
const ORIGIN: &str = "https://airvpn.org";
const LOGIN_PAGE: &str = "https://airvpn.org/login/";
const PORTS_PAGE: &str = "https://airvpn.org/ports/";
/// A signed-in Ports page is far smaller (a signed-out one is about 28 KiB).
const PAGE_LIMIT: usize = 1024 * 1024;
const JSON_LIMIT: usize = 256 * 1024;
const ACCEPT_HTML: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
/// What the page's jQuery sends for a JSON answer.
const ACCEPT_XHR: &str = "application/json, text/javascript, */*; q=0.01";
/// Invision Community's answer header: `1` signed in, `0` signed out.
const LOGGED_IN: &str = "x-ips-loggedin";
const X_REQUESTED_WITH: &str = "x-requested-with";

/// A session with `AirVPN`'s website: its cookies and the Ports page's token. In memory only;
/// zeroized on drop; `Debug` shows neither.
#[derive(Default)]
pub struct Session {
    jar: Jar,
    token: Option<Zeroizing<String>>,
}

impl Session {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the session holds a page token (it may still have expired at the site).
    #[must_use]
    pub const fn signed_in(&self) -> bool {
        self.token.is_some()
    }

    /// Forget the token: the next operation fetches it again (and signs in when the site asks).
    pub fn clear_token(&mut self) {
        self.token = None;
    }
}

#[expect(
    clippy::missing_fields_in_debug,
    reason = "redacted: the cookie values and the token are secrets, only their presence shows"
)]
impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("cookies", &self.jar.len())
            .field("signed_in", &self.signed_in())
            .finish()
    }
}

/// One setting of a forwarded port; the Ports page changes each with a request of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setting {
    Notes,
    Enabled,
    Device,
    Protocol,
    IpLayer,
    LocalPort,
    DnsName,
}

impl Setting {
    /// The page's action that changes it.
    const fn action(self) -> &'static str {
        match self {
            Self::Notes => "edit_note",
            Self::Enabled => "edit_enabled",
            Self::Device => "edit_device",
            Self::Protocol => "edit_protocol",
            Self::IpLayer => "edit_layer",
            Self::LocalPort => "edit_localport",
            Self::DnsName => "edit_ddns",
        }
    }

    /// Its field in a [`ForwardedPortUpdate`], as a JSON pointer.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Notes => "/notes",
            Self::Enabled => "/enabled",
            Self::Device => "/device",
            Self::Protocol => "/protocol",
            Self::IpLayer => "/ip_layer",
            Self::LocalPort => "/local_port",
            Self::DnsName => "/dns_name",
        }
    }

    /// Its name, as the settings dialog labels it.
    fn name(self) -> Text {
        match self {
            Self::Notes => tr!("Notes", "備註", "メモ"),
            Self::Enabled => tr!("Enabled", "啟用狀態", "有効／無効"),
            Self::Device => tr!("Device", "裝置", "デバイス"),
            Self::Protocol => tr!("Protocol", "協定", "プロトコル"),
            Self::IpLayer => tr!("IP version", "IP 版本", "IP バージョン"),
            Self::LocalPort => Text::verbatim("Local port"),
            Self::DnsName => tr!("DDNS name", "DDNS 名稱", "DDNS 名"),
        }
    }

    /// Whether `port`, as a list reads it, has `value` (the page's value for this setting): the
    /// value sent, read the way the list is read.
    fn holds(self, port: &Port, value: &str) -> bool {
        match self {
            Self::Notes => port.notes == ports::notes(value),
            Self::Enabled => port.enabled == (value == "1"),
            Self::Device => port.device.as_deref() == Some(value).filter(|v| *v != ALL_DEVICES),
            Self::Protocol => ports::protocol(value) == Some(port.protocol),
            Self::IpLayer => ports::ip_layer(value).as_deref() == Some(port.ip_layer.as_str()),
            Self::LocalPort => port.local_port().to_string() == value,
            Self::DnsName => port.dns.as_deref().unwrap_or_default() == value,
        }
    }
}

/// A setting `AirVPN` did not keep, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsaved {
    pub setting: Setting,
    pub why: Why,
}

/// Why a setting was not kept. [`Why::text`] is the reason a person reads; `Display` is its
/// English.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    /// The page's answer was an error: `AirVPN`'s reason, when it is a plain sentence.
    Refused(Option<String>),
    /// `AirVPN` did not refuse it, yet the list read back shows something else.
    Differs,
    /// Its request failed (the reason), and the list read back does not show it.
    Failed(Text),
    /// Not sent: an earlier request failed.
    NotSent,
}

impl Why {
    /// The reason, in the three languages (`AirVPN`'s own words as it wrote them).
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::Refused(Some(said)) => tr!("AirVPN: {said}", "AirVPN：{said}", "AirVPN：{said}"),
            Self::Refused(None) => tr!(
                "AirVPN refused this change",
                "AirVPN 拒絕了這項修改",
                "AirVPN がこの変更を拒否しました"
            ),
            Self::Differs => tr!(
                "AirVPN did not refuse it, but the value read back is not the one asked for",
                "AirVPN 沒有拒絕，但重新讀取後不是要求的值",
                "AirVPN は拒否しませんでしたが、読み直した値が要求した値ではありません"
            ),
            Self::Failed(why) => tr!(
                "Not completed: {why}",
                "沒有完成：{why}",
                "完了しませんでした：{why}";
                why = why.clone()
            ),
            Self::NotSent => tr!(
                "Not sent: the previous one did not complete",
                "沒有送出：前一項沒有完成",
                "送信していません：前の項目が完了しませんでした"
            ),
        }
    }
}

impl fmt::Display for Why {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text().en)
    }
}

/// What `AirVPN` was asked to do, as a refusal or an unknown outcome names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Reserve,
    Delete,
    Change,
    Test,
    DdnsCheck,
    Search,
}

impl Operation {
    /// The operation, as an answer outside the contract names it.
    fn name(self) -> Text {
        match self {
            Self::Reserve => tr!(
                "reserving an inbound port",
                "保留連入埠",
                "着信ポートの予約"
            ),
            Self::Delete => tr!("deleting an inbound port", "刪除連入埠", "着信ポートの削除"),
            Self::Change => tr!("changing an inbound port", "修改連入埠", "着信ポートの変更"),
            Self::Test => tr!(
                "testing an inbound port",
                "測試連入埠",
                "着信ポートのテスト"
            ),
            Self::DdnsCheck => tr!("DDNS check", "完成 DDNS 檢查", "DDNS チェック"),
            Self::Search => tr!(
                "search for consecutive free ports",
                "搜尋連續的空閒埠",
                "連続した空きポートの検索"
            ),
        }
    }

    /// `AirVPN` did not do it (to `port`, when one is named).
    fn refused(self, port: Option<u16>) -> Text {
        match (self, port) {
            (Self::Reserve, Some(port)) => tr!(
                "AirVPN did not reserve inbound port {port}",
                "AirVPN 沒有保留連入埠 {port}",
                "AirVPN は着信ポート {port} を予約しませんでした"
            ),
            (Self::Reserve, None) => tr!(
                "AirVPN did not reserve an inbound port",
                "AirVPN 沒有保留連入埠",
                "AirVPN は着信ポートを予約しませんでした"
            ),
            (Self::Delete, Some(port)) => tr!(
                "AirVPN did not delete inbound port {port}",
                "AirVPN 沒有刪除連入埠 {port}",
                "AirVPN は着信ポート {port} を削除しませんでした"
            ),
            (Self::Delete, None) => tr!(
                "AirVPN did not delete the inbound port",
                "AirVPN 沒有刪除連入埠",
                "AirVPN は着信ポートを削除しませんでした"
            ),
            (Self::Change, Some(port)) => tr!(
                "AirVPN did not change inbound port {port}",
                "AirVPN 沒有修改連入埠 {port}",
                "AirVPN は着信ポート {port} を変更しませんでした"
            ),
            (Self::Change, None) => tr!(
                "AirVPN did not change the inbound port",
                "AirVPN 沒有修改連入埠",
                "AirVPN は着信ポートを変更しませんでした"
            ),
            (Self::Test, Some(port)) => tr!(
                "AirVPN did not test inbound port {port}",
                "AirVPN 沒有測試連入埠 {port}",
                "AirVPN は着信ポート {port} をテストしませんでした"
            ),
            (Self::Test, None) => tr!(
                "AirVPN did not test the inbound port",
                "AirVPN 沒有測試連入埠",
                "AirVPN は着信ポートをテストしませんでした"
            ),
            // Account-wide: they name no port.
            (Self::DdnsCheck, _) => tr!(
                "AirVPN did not complete the DDNS check",
                "AirVPN 沒有完成 DDNS 檢查",
                "AirVPN は DDNS チェックを完了しませんでした"
            ),
            (Self::Search, _) => tr!(
                "AirVPN did not search for consecutive free ports",
                "AirVPN 沒有搜尋連續的空閒埠",
                "AirVPN は連続した空きポートを検索しませんでした"
            ),
        }
    }

    /// Whether `AirVPN` did it cannot be told.
    fn unknown(self) -> Text {
        match self {
            Self::Reserve => tr!(
                "Cannot tell whether AirVPN reserved the inbound port: refresh the inbound port list to check instead of sending it again",
                "無法確認 AirVPN 是否已保留連入埠：請重新整理連入埠清單確認，不要直接重送",
                "AirVPN が着信ポートを予約したか確認できません：再送せずに、着信ポートの一覧を再読み込みして確認してください"
            ),
            Self::Delete => tr!(
                "Cannot tell whether AirVPN deleted the inbound port: refresh the inbound port list to check instead of sending it again",
                "無法確認 AirVPN 是否已刪除連入埠：請重新整理連入埠清單確認，不要直接重送",
                "AirVPN が着信ポートを削除したか確認できません：再送せずに、着信ポートの一覧を再読み込みして確認してください"
            ),
            Self::Change => tr!(
                "Cannot tell whether AirVPN changed the inbound port: refresh the inbound port list to check instead of sending it again",
                "無法確認 AirVPN 是否已修改連入埠：請重新整理連入埠清單確認，不要直接重送",
                "AirVPN が着信ポートを変更したか確認できません：再送せずに、着信ポートの一覧を再読み込みして確認してください"
            ),
            // They change nothing: never reported as unknown, named for completeness.
            Self::Test | Self::DdnsCheck | Self::Search => tr!(
                "Cannot tell whether AirVPN completed it ({what}): refresh the inbound port list to check instead of sending it again",
                "無法確認 AirVPN 是否已完成（{what}）：請重新整理連入埠清單確認，不要直接重送",
                "AirVPN が完了したか確認できません（{what}）：再送せずに、着信ポートの一覧を再読み込みして確認してください";
                what = self.name()
            ),
        }
    }
}

/// A port as read back after its settings changed, and the list it was read in (which names
/// its device).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edited {
    pub port: Port,
    pub list: PortList,
}

/// Why a website operation failed; none carries a page, a cookie, the token or the credential.
///
/// [`SiteError::text`] is the message a person reads; `Display` is its English (logs). The
/// `String`s are `AirVPN`'s own reasons, when they are plain sentences.
#[derive(Debug, thiserror::Error)]
pub enum SiteError {
    /// The sign-in form came back with an error: the user name or password is not accepted.
    LoginRejected(Option<String>),
    /// Too many failed sign-ins: the site does not take one now.
    LoginLocked(Option<String>),
    /// The sign-in asks for a CAPTCHA.
    Captcha,
    /// The sign-in asks for a second factor.
    SecondFactor,
    /// The sign-in page is not the form this client knows (what differs); nothing was posted.
    LoginFormChanged(Text),
    /// Still signed out right after signing in (or a second signed-out answer in one
    /// operation): stopped instead of signing in again. Names the answer.
    NotSignedIn(Text),
    /// Signed in, yet the Ports page offers no ports (no token), e.g. without an active plan.
    PortsUnavailable(Option<String>),
    PortLimit {
        used: usize,
        limit: usize,
    },
    PortOutOfRange(u16),
    AlreadyReserved(u16),
    NotReserved(u16),
    /// A change or a search the page would not take (`field`: its JSON pointer); nothing was
    /// sent.
    Invalid {
        field: Option<&'static str>,
        reason: Text,
    },
    /// `AirVPN` answered without doing it (`action` names what); for a change of the list, a
    /// fresh list confirms nothing changed.
    Refused {
        action: Operation,
        port: Option<u16>,
        message: Option<String>,
    },
    /// `AirVPN` did not keep every setting asked for; the list read back says which it did.
    NotSaved {
        saved: Vec<Setting>,
        unsaved: Vec<Unsaved>,
    },
    /// The answer neither confirmed nor refused it, and a fresh list could not settle it.
    OutcomeUnknown(Operation),
    Provider(#[from] ProviderError),
}

impl fmt::Display for SiteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text().en)
    }
}

impl SiteError {
    /// The message a person reads, in the three languages.
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::LoginRejected(said) => with_said(
                tr!(
                    "AirVPN's website did not accept the sign-in: the user name or password is wrong (VPN Manager uses the user name and password given when the account was added; if you changed the password at AirVPN, remove the account and add it again)",
                    "AirVPN 網站沒有接受登入：使用者名稱或密碼不正確（VPN Manager 用的是加入帳號時的帳號與密碼；在 AirVPN 改過密碼的話，請移除帳號後重新加入）",
                    "AirVPN の Web サイトがログインを受け付けませんでした：ユーザー名またはパスワードが正しくありません（VPN Manager はアカウントを追加したときのユーザー名とパスワードを使います。AirVPN でパスワードを変更した場合は、アカウントを削除してから追加し直してください）"
                ),
                said.as_deref(),
            ),
            Self::LoginLocked(said) => with_said(
                tr!(
                    "AirVPN's website is not accepting sign-ins to this account for now after several failed attempts; try again later. VPN Manager does not retry by itself",
                    "AirVPN 網站因多次登入失敗暫時不接受這個帳號登入，請稍後再試；VPN Manager 不會自動重試",
                    "ログインの失敗が続いたため、AirVPN の Web サイトはこのアカウントのログインを一時的に受け付けていません。しばらくしてからもう一度お試しください。VPN Manager は自動で再試行しません"
                ),
                said.as_deref(),
            ),
            Self::Captcha => tr!(
                "AirVPN's website asks for a CAPTCHA to sign in, which VPN Manager cannot complete for you; sign in to AirVPN's website once in a browser and try again, or manage the inbound ports in the website's Client Area",
                "AirVPN 網站的登入要求人機驗證（CAPTCHA），VPN Manager 無法代為完成；請先在瀏覽器登入 AirVPN 網站一次再試，或直接在網站的 Client Area 管理連入埠",
                "AirVPN の Web サイトのログインで CAPTCHA が求められていますが、VPN Manager は代わりに完了できません。ブラウザーで一度 AirVPN の Web サイトにログインしてからもう一度お試しいただくか、Web サイトの Client Area で着信ポートを管理してください"
            ),
            Self::SecondFactor => tr!(
                "Signing in to AirVPN's website with this account needs a second factor (two-step verification), which VPN Manager cannot complete for you; manage the inbound ports in the Client Area of AirVPN's website",
                "這個 AirVPN 帳號的網站登入需要第二道驗證（兩步驟驗證），VPN Manager 無法代為完成；請在 AirVPN 網站的 Client Area 管理連入埠",
                "この AirVPN アカウントの Web サイトへのログインには 2 段階認証が必要で、VPN Manager は代わりに完了できません。AirVPN の Web サイトの Client Area で着信ポートを管理してください"
            ),
            Self::LoginFormChanged(what) => tr!(
                "The sign-in page of AirVPN's website does not match the known format ({what}); the password was not sent",
                "AirVPN 網站的登入頁與已知格式不符（{what}），沒有送出密碼",
                "AirVPN の Web サイトのログインページが既知の形式と一致しません（{what}）。パスワードは送信していません";
                what = what.clone()
            ),
            Self::NotSignedIn(what) => tr!(
                "AirVPN's website still shows signed out after signing in ({what}); stopped without signing in again and again",
                "AirVPN 網站在登入後仍顯示未登入（{what}），已停止，不會反覆登入",
                "ログイン後も AirVPN の Web サイトが未ログインと表示しています（{what}）。ログインを繰り返さずに中止しました";
                what = what.clone()
            ),
            Self::PortsUnavailable(said) => with_said(
                tr!(
                    "The inbound ports page of AirVPN's website cannot be used now (perhaps there is no active plan)",
                    "AirVPN 網站的連入埠頁面目前不能使用（可能沒有有效的方案）",
                    "AirVPN の Web サイトの着信ポートのページは現在使えません（有効なプランがない可能性があります）"
                ),
                said.as_deref(),
            ),
            Self::PortLimit { used, limit } => tr!(
                "AirVPN reserves at most {limit} inbound ports per account and {used} are in use; delete a port that is no longer used first (no port is ever deleted automatically)",
                "AirVPN 每個帳號最多保留 {limit} 個連入埠，目前已用 {used} 個；請先刪除不再使用的埠（不會自動刪除任何埠）",
                "AirVPN で予約できる着信ポートは 1 アカウントにつき最大 {limit} 個で、現在 {used} 個を使用中です。先に使わなくなったポートを削除してください（ポートが自動で削除されることはありません）"
            ),
            Self::PortOutOfRange(port) => tr!(
                "The inbound port must be {MIN_PORT}–65535 (AirVPN does not accept a smaller port); got {port}",
                "連入埠必須是 {MIN_PORT}–65535（AirVPN 不接受更小的 port），收到 {port}",
                "着信ポートは {MIN_PORT}–65535 にしてください（AirVPN はそれより小さい port を受け付けません）。受け取った値：{port}"
            ),
            Self::AlreadyReserved(port) => tr!(
                "This AirVPN account has already reserved inbound port {port}",
                "這個 AirVPN 帳號已經保留了連入埠 {port}",
                "この AirVPN アカウントは着信ポート {port} をすでに予約しています"
            ),
            Self::NotReserved(port) => tr!(
                "This AirVPN account has not reserved inbound port {port}",
                "這個 AirVPN 帳號沒有保留連入埠 {port}",
                "この AirVPN アカウントは着信ポート {port} を予約していません"
            ),
            Self::Invalid { reason, .. } => reason.clone(),
            Self::Refused {
                action,
                port,
                message,
            } => with_said(action.refused(*port), message.as_deref()),
            Self::NotSaved { saved, unsaved } => not_saved(saved, unsaved),
            Self::OutcomeUnknown(action) => action.unknown(),
            Self::Provider(e) => e.text(),
        }
    }

    /// Public error code for the API layer.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::LoginRejected(_) => ErrorCode::ProviderAuthRejected,
            Self::LoginLocked(_) => ErrorCode::ProviderQuotaExceeded,
            Self::Captcha | Self::SecondFactor => ErrorCode::ProviderLoginChallenge,
            Self::LoginFormChanged(_) | Self::NotSignedIn(_) => ErrorCode::ProviderContractDrift,
            Self::PortsUnavailable(_) | Self::Refused { .. } | Self::NotSaved { .. } => {
                ErrorCode::ProviderRejected
            }
            Self::PortLimit { .. } => ErrorCode::PortLimitReached,
            Self::PortOutOfRange(_) | Self::Invalid { .. } => ErrorCode::ValidationFailed,
            Self::AlreadyReserved(_) => ErrorCode::InvalidState,
            Self::NotReserved(_) => ErrorCode::NotFound,
            Self::OutcomeUnknown(_) => ErrorCode::OutcomeUnknown,
            Self::Provider(e) => e.code(),
        }
    }

    /// The sign-in itself failed (credentials, a challenge, the form): the forwarded-ports gate
    /// records it.
    #[must_use]
    pub const fn is_sign_in(&self) -> bool {
        matches!(
            self,
            Self::LoginRejected(_)
                | Self::LoginLocked(_)
                | Self::Captcha
                | Self::SecondFactor
                | Self::LoginFormChanged(_)
                | Self::NotSignedIn(_)
        )
    }

    /// The request may have reached `AirVPN` and acted (a mutation must be reconciled).
    const fn maybe_delivered(&self) -> bool {
        matches!(self, Self::Provider(e) if e.outcome_unknown())
    }

    /// `AirVPN` did not answer in time.
    const fn timed_out(&self) -> bool {
        matches!(
            self,
            Self::Provider(ProviderError::Unavailable(Unavailable::Http(
                HttpError::Timeout { .. }
            )))
        )
    }
}

/// `text` and, when `AirVPN` said something, its words: "… (`AirVPN`: …)".
fn with_said(text: Text, said: Option<&str>) -> Text {
    match said {
        Some(said) => tr!(
            "{text} (AirVPN: {said})",
            "{text}（AirVPN：{said}）",
            "{text}（AirVPN：{said}）";
            text = text
        ),
        None => text,
    }
}

/// "`AirVPN` did not save: DDNS name (`AirVPN`: …); saved: Notes".
fn not_saved(saved: &[Setting], unsaved: &[Unsaved]) -> Text {
    let unsaved = list(unsaved.iter().map(|u| {
        tr!(
            "{name} ({why})",
            "{name}（{why}）",
            "{name}（{why}）";
            name = u.setting.name(),
            why = u.why.text()
        )
    }));
    if saved.is_empty() {
        return tr!(
            "AirVPN did not save: {unsaved}",
            "AirVPN 沒有儲存：{unsaved}",
            "AirVPN が保存しなかった設定：{unsaved}";
            unsaved = unsaved
        );
    }
    let saved = list(saved.iter().map(|s| s.name()));
    tr!(
        "AirVPN did not save: {unsaved}; saved: {saved}",
        "AirVPN 沒有儲存：{unsaved}；已儲存：{saved}",
        "AirVPN が保存しなかった設定：{unsaved}。保存した設定：{saved}";
        unsaved = unsaved,
        saved = saved
    )
}

/// `items` one after another, with each language's separator ("A, B", "A、B").
fn list(items: impl Iterator<Item = Text>) -> Text {
    let items: Vec<Text> = items.collect();
    tr!(", ", "、", "、").map(|language, separator| {
        items
            .iter()
            .map(|item| item.get(language))
            .collect::<Vec<_>>()
            .join(separator)
    })
}

/// `port` is one the page accepts.
///
/// # Errors
///
/// [`SiteError::PortOutOfRange`] when `port` is below the page's minimum.
pub const fn check_port(port: u16) -> Result<(), SiteError> {
    if port < MIN_PORT {
        return Err(SiteError::PortOutOfRange(port));
    }
    Ok(())
}

/// `update` is a change the page takes (checked before anything is sent).
///
/// # Errors
///
/// [`SiteError::Invalid`] naming the field the page would not take.
pub fn check_update(update: &ForwardedPortUpdate) -> Result<(), SiteError> {
    requests(update).map(drop)
}

/// `count` consecutive free ports is a search the page takes.
///
/// # Errors
///
/// [`SiteError::Invalid`] naming `/count` when `count` is outside [`SEARCH_COUNT`].
pub fn check_count(count: u8) -> Result<(), SiteError> {
    if SEARCH_COUNT.contains(&count) {
        return Ok(());
    }
    let (min, max) = (SEARCH_COUNT.start(), SEARCH_COUNT.end());
    Err(SiteError::Invalid {
        field: Some("/count"),
        reason: tr!(
            "A search finds {min}–{max} consecutive free ports at a time; got {count}",
            "連續空閒埠一次可以找 {min}–{max} 個，收到 {count}",
            "連続した空きポートは一度に {min}–{max} 個まで検索できます。受け取った値：{count}"
        ),
    })
}

fn invalid(setting: Setting, reason: impl Into<Text>) -> SiteError {
    SiteError::Invalid {
        field: Some(setting.path()),
        reason: reason.into(),
    }
}

/// `update` as the page's requests, in the page's order: `(setting, value)`, each checked as the
/// page checks it.
fn requests(u: &ForwardedPortUpdate) -> Result<Vec<(Setting, String)>, SiteError> {
    let mut out = Vec::new();
    if let Some(notes) = &u.notes {
        let notes = notes.trim();
        if notes.chars().count() > MAX_NOTES {
            return Err(invalid(
                Setting::Notes,
                tr!(
                    "Notes have at most {MAX_NOTES} characters",
                    "備註最多 {MAX_NOTES} 個字",
                    "メモは {MAX_NOTES} 文字までです"
                ),
            ));
        }
        if notes.chars().any(char::is_control) {
            return Err(invalid(
                Setting::Notes,
                tr!(
                    "Notes must be a single line of text (no line breaks or control characters)",
                    "備註只能是一行文字（不能有換行或控制字元）",
                    "メモは 1 行のテキストにしてください（改行や制御文字は使えません）"
                ),
            ));
        }
        out.push((Setting::Notes, notes.to_owned()));
    }
    if let Some(enabled) = u.enabled {
        out.push((Setting::Enabled, if enabled { "1" } else { "0" }.to_owned()));
    }
    if let Some(device) = &u.device {
        let device = device.trim();
        if device != ALL_DEVICES && !ports::valid_id(device) {
            return Err(invalid(
                Setting::Device,
                tr!(
                    "The device must be all (every device) or the ID of a device of the account",
                    "裝置必須是 all（全部裝置）或帳號裡一台裝置的 ID",
                    "デバイスは all（すべてのデバイス）か、アカウントのデバイス 1 台の ID にしてください"
                ),
            ));
        }
        out.push((Setting::Device, device.to_owned()));
    }
    if let Some(protocol) = u.protocol {
        let word = match protocol {
            ForwardProtocol::Both => "both",
            ForwardProtocol::Tcp => "tcp",
            ForwardProtocol::Udp => "udp",
        };
        out.push((Setting::Protocol, word.to_owned()));
    }
    if let Some(layer) = u.ip_layer {
        let word = match layer {
            PortIpLayer::Both => "both",
            PortIpLayer::Ipv4 => "v4",
            PortIpLayer::Ipv6 => "v6",
        };
        out.push((Setting::IpLayer, word.to_owned()));
    }
    if let Some(local) = u.local_port {
        if local == 0 {
            return Err(invalid(
                Setting::LocalPort,
                tr!(
                    "Local port must be 1–65535",
                    "Local port 必須是 1–65535",
                    "Local port は 1–65535 にしてください"
                ),
            ));
        }
        out.push((Setting::LocalPort, local.to_string()));
    }
    if let Some(name) = &u.dns_name {
        out.push((Setting::DnsName, ddns_name(name)?));
    }
    if out.is_empty() {
        return Err(SiteError::Invalid {
            field: None,
            reason: tr!(
                "There is no setting to change",
                "沒有要修改的設定",
                "変更する設定がありません"
            ),
        });
    }
    Ok(out)
}

/// A DDNS name as the page takes it: the part before `.airdns.org` (typed with it or without),
/// in lower case; letters, digits and hyphens, a hyphen at neither end, at most
/// [`MAX_DDNS_NAME`]. Empty clears it.
fn ddns_name(raw: &str) -> Result<String, SiteError> {
    let name = raw.trim().to_ascii_lowercase();
    let name = name.trim_suffix(AIRDNS_SUFFIX);
    let label = name.len() <= MAX_DDNS_NAME
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if !label {
        return Err(invalid(
            Setting::DnsName,
            tr!(
                "A DDNS name has only letters, digits and hyphens (no hyphen at the start or the end), at most {MAX_DDNS_NAME} characters",
                "DDNS 名稱只能有英文字母、數字與連字號（連字號不能在開頭或結尾），最多 {MAX_DDNS_NAME} 個字",
                "DDNS 名に使えるのは英字、数字、ハイフンだけで（ハイフンは先頭と末尾に置けません）、最大 {MAX_DDNS_NAME} 文字です"
            ),
        ));
    }
    Ok(name.to_owned())
}

/// `port` in `list`.
fn reserved(list: &PortList, port: u16) -> Result<Port, SiteError> {
    list.ports
        .iter()
        .find(|p| p.port == port)
        .cloned()
        .ok_or(SiteError::NotReserved(port))
}

/// The website client of one operation, over the operation's HTTPS client (IPv4).
pub struct Site<'a, C> {
    http: &'a HttpsClient<C>,
    family: Family,
    timeout: Duration,
}

impl<'a, C: Connect> Site<'a, C> {
    pub const fn new(http: &'a HttpsClient<C>) -> Self {
        Self {
            http,
            family: Family::V4,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Deadline per request.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The account's forwarded ports.
    ///
    /// # Errors
    ///
    /// [`SiteError::LoginRejected`], [`SiteError::LoginLocked`], [`SiteError::Captcha`],
    /// [`SiteError::SecondFactor`], [`SiteError::LoginFormChanged`] or [`SiteError::NotSignedIn`]
    /// when signing in fails, [`SiteError::PortsUnavailable`] when the Ports page offers no
    /// ports, and [`SiteError::Provider`] when the website cannot be reached or answers outside
    /// the known contract.
    pub async fn ports(
        &self,
        session: &mut Session,
        credentials: &Credentials,
    ) -> Result<PortList, SiteError> {
        Run::new(self, session, credentials).list().await
    }

    /// Reserve `port`, or one `AirVPN` picks when `None`. Checked first against a fresh list: the
    /// port range, the account's limit, a port already held.
    ///
    /// # Errors
    ///
    /// [`SiteError::PortOutOfRange`], [`SiteError::PortLimit`] or [`SiteError::AlreadyReserved`]
    /// when the fresh list rules the port out, [`SiteError::Refused`] or
    /// [`SiteError::OutcomeUnknown`] when `AirVPN` does not confirm the reservation; otherwise as
    /// for [`Self::ports`].
    pub async fn reserve(
        &self,
        session: &mut Session,
        credentials: &Credentials,
        port: Option<u16>,
    ) -> Result<Port, SiteError> {
        if let Some(p) = port {
            check_port(p)?;
        }
        let mut run = Run::new(self, session, credentials);
        let before = run.list().await?;
        if before.ports.len() >= MAX_PORTS {
            return Err(SiteError::PortLimit {
                used: before.ports.len(),
                limit: MAX_PORTS,
            });
        }
        if let Some(p) = port
            && before.ports.iter().any(|x| x.port == p)
        {
            return Err(SiteError::AlreadyReserved(p));
        }
        run.insert(port, &before).await
    }

    /// Delete `port` (its pool read from a fresh list).
    ///
    /// # Errors
    ///
    /// [`SiteError::NotReserved`] when the account does not hold `port`, [`SiteError::Refused`]
    /// or [`SiteError::OutcomeUnknown`] when `AirVPN` does not confirm the deletion; otherwise as
    /// for [`Self::ports`].
    pub async fn delete(
        &self,
        session: &mut Session,
        credentials: &Credentials,
        port: u16,
    ) -> Result<(), SiteError> {
        let mut run = Run::new(self, session, credentials);
        let entry = reserved(&run.list().await?, port)?;
        run.remove(&entry).await
    }

    /// Change `port`'s settings: those that differ from a fresh list, each with its own request
    /// as the page sends it, then the list read back. Saved only when the read-back shows every
    /// change; otherwise [`SiteError::NotSaved`] names which were saved and which were not.
    ///
    /// # Errors
    ///
    /// [`SiteError::Invalid`] when `update` is not a change the page takes (nothing is sent),
    /// [`SiteError::NotReserved`] when the account does not hold `port`,
    /// [`SiteError::NotSaved`] when the read-back misses a change, [`SiteError::Refused`] or
    /// [`SiteError::OutcomeUnknown`] when `AirVPN` does not confirm it; otherwise as for
    /// [`Self::ports`].
    pub async fn edit(
        &self,
        session: &mut Session,
        credentials: &Credentials,
        port: u16,
        update: &ForwardedPortUpdate,
    ) -> Result<Edited, SiteError> {
        let asked = requests(update)?;
        let mut run = Run::new(self, session, credentials);
        let list = run.list().await?;
        let entry = reserved(&list, port)?;
        if let Some((_, device)) = asked.iter().find(|(s, _)| *s == Setting::Device)
            && device != ALL_DEVICES
            && list.device_name(device).is_none()
        {
            return Err(invalid(
                Setting::Device,
                tr!(
                    "This AirVPN account has no such device (read the inbound port list again, then choose)",
                    "這個 AirVPN 帳號沒有這台裝置（請重新讀取連入埠清單再選）",
                    "この AirVPN アカウントにそのデバイスはありません（着信ポートの一覧を読み直してから選んでください）"
                ),
            ));
        }
        let todo: Vec<(Setting, String)> = asked
            .into_iter()
            .filter(|(s, value)| !s.holds(&entry, value))
            .collect();
        if todo.is_empty() {
            return Ok(Edited { port: entry, list });
        }
        run.change(&entry, &todo).await
    }

    /// `AirVPN`'s test of `port` from the server of every connected session that uses it, as the
    /// page runs it: the sessions, then one test for each TCP one (the page tests no UDP).
    ///
    /// # Errors
    ///
    /// [`SiteError::NotReserved`] when the account does not hold `port`; otherwise as for
    /// [`Self::ports`].
    pub async fn test(
        &self,
        session: &mut Session,
        credentials: &Credentials,
        port: u16,
    ) -> Result<ForwardedPortTest, SiteError> {
        let deadline = Instant::now() + TEST_TIME;
        let mut run = Run::new(self, session, credentials);
        let entry = reserved(&run.list().await?, port)?;
        let items = run.sessions(&entry).await?;
        let mut sessions = Vec::with_capacity(items.len());
        for item in items {
            let left = deadline.saturating_duration_since(Instant::now());
            let probe = if item.protocol != ForwardProtocol::Tcp {
                Probe::untested(tr!(
                    "AirVPN tests TCP only, and this is a UDP connection",
                    "AirVPN 只測試 TCP，這是 UDP 的連線",
                    "AirVPN は TCP しかテストしません。これは UDP の接続です"
                ))
            } else if left < MIN_PROBE {
                let secs = TEST_TIME.as_secs();
                Probe::untested(tr!(
                    "This test went past {secs} s, so this one was not tested; test again",
                    "這次測試已超過 {secs} 秒，沒有測這一項；請再測一次",
                    "今回のテストは {secs} 秒を超えたため、この項目はテストしていません。もう一度テストしてください"
                ))
            } else {
                run.probe(&item, left.min(PROBE_TIMEOUT)).await?
            };
            sessions.push(probe.session(item));
        }
        Ok(ForwardedPortTest {
            port,
            sessions,
            observed_at: Timestamp::now(),
        })
    }

    /// `AirVPN`'s DDNS check: each DDNS name of the account's ports and how many connected sessions
    /// it leads to.
    ///
    /// # Errors
    ///
    /// As for [`Self::ports`].
    pub async fn ddns(
        &self,
        session: &mut Session,
        credentials: &Credentials,
    ) -> Result<ForwardedPortDdns, SiteError> {
        let names = Run::new(self, session, credentials)
            .ask("ddns_report", &[], ports::ddns, Operation::DdnsCheck, None)
            .await?;
        Ok(ForwardedPortDdns {
            names,
            observed_at: Timestamp::now(),
        })
    }

    /// `AirVPN`'s search for `count` consecutive ports nobody holds ([`SEARCH_COUNT`]). It reserves
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`SiteError::Invalid`] when `count` is outside [`SEARCH_COUNT`]; otherwise as for
    /// [`Self::ports`].
    pub async fn search(
        &self,
        session: &mut Session,
        credentials: &Credentials,
        count: u8,
    ) -> Result<ForwardedPortSearch, SiteError> {
        check_count(count)?;
        let mut run = Run::new(self, session, credentials);
        let n = count.to_string();
        let raw = run
            .ask(
                "seq_search",
                &[("n", &n)],
                ports::found,
                Operation::Search,
                None,
            )
            .await?;
        let Some(message) =
            html::plain(&html::fragment_text(&raw), MAX_SEARCH_TEXT, &run.secrets())
        else {
            tracing::debug!(
                snippet = %html::snippet(raw.as_bytes(), &run.secrets()),
                "AirVPN website answer outside the known contract"
            );
            return Err(ProviderError::ContractDrift(tr!(
                "answer to the consecutive free port search",
                "連續空閒埠的回覆",
                "連続した空きポート検索の応答"
            ))
            .into());
        };
        Ok(ForwardedPortSearch {
            count,
            message,
            observed_at: Timestamp::now(),
        })
    }
}

/// One session's test result.
struct Probe {
    state: PortTestState,
    word: Option<String>,
    message: Option<Text>,
}

impl Probe {
    const fn untested(why: Text) -> Self {
        Self {
            state: PortTestState::NotTested,
            word: None,
            message: Some(why),
        }
    }

    fn session(self, item: SessionItem) -> ForwardedPortSession {
        ForwardedPortSession {
            protocol: item.protocol,
            ip_layer: item.family,
            server_name: item.server_name,
            server_location: item.server_location,
            server_country: item.server_country,
            server_ip: item.server_ip,
            port: item.port,
            client_ip: item.client_ip,
            local_port: item.local.unwrap_or(item.port),
            device_name: item.device_name,
            state: self.state,
            word: self.word,
            message: self.message,
        }
    }
}

/// One answer of the site.
struct Page {
    status: StatusCode,
    headers: HeaderMap,
    body: Zeroizing<Vec<u8>>,
}

impl Page {
    /// `X-IPS-LoggedIn`, when the answer has it.
    fn signed_in(&self) -> Option<bool> {
        match self.headers.get(LOGGED_IN)?.to_str().ok()?.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        }
    }

    fn text(&self) -> Zeroizing<String> {
        Zeroizing::new(String::from_utf8_lossy(&self.body).into_owned())
    }

    fn location(&self) -> Option<&str> {
        self.headers.get(header::LOCATION)?.to_str().ok()
    }

    /// The answer says the session is signed out, or its token went stale: what one new sign-in
    /// fixes. Checked only on answers that are not the expected success.
    fn stale(&self) -> bool {
        if self.signed_in() == Some(false) || matches!(self.status.as_u16(), 401 | 403) {
            return true;
        }
        if self.status.is_redirection() {
            return self
                .location()
                .and_then(same_origin_path)
                .is_some_and(|p| html::is_login_path(&p));
        }
        if !self.status.is_success() {
            return false;
        }
        let text = self.text();
        html::signed_out(&text) || html::has_login_form(&text)
    }
}

/// A port call, as a signed-out or off-contract answer names it.
fn port_request() -> Text {
    tr!(
        "inbound port request",
        "連入埠請求",
        "着信ポートのリクエスト"
    )
}

/// The Ports page, as a signed-out or off-contract answer names it.
fn ports_page() -> Text {
    tr!("Ports page", "連入埠頁面", "Ports ページ")
}

/// The sign-in form, as a changed form names it.
fn sign_in_form() -> Text {
    tr!("sign-in form", "登入表單", "ログインフォーム")
}

/// The origin-form path of a `Location` on airvpn.org.
fn same_origin_path(location: &str) -> Option<String> {
    let path = location
        .strip_prefix("https://airvpn.org")
        .or_else(|| location.strip_prefix("//airvpn.org"))
        .unwrap_or(location);
    (path.starts_with('/') && !path.starts_with("//")).then(|| path.to_owned())
}

/// What a port call came back with.
enum Outcome<T> {
    Done(T),
    /// Neither the success nor a signed-out answer.
    Other(Page),
}

/// One operation: its requests, and whether it already signed in.
struct Run<'r, 'a, C> {
    site: &'r Site<'a, C>,
    session: &'r mut Session,
    credentials: &'r Credentials,
    /// One sign-in per operation at most.
    signed_in: bool,
}

impl<'r, 'a, C: Connect> Run<'r, 'a, C> {
    const fn new(
        site: &'r Site<'a, C>,
        session: &'r mut Session,
        credentials: &'r Credentials,
    ) -> Self {
        Self {
            site,
            session,
            credentials,
            signed_in: false,
        }
    }

    // ---------------------------------------------------------------------------------------
    // Requests
    // ---------------------------------------------------------------------------------------

    async fn send(&mut self, request: Request) -> Result<Page, SiteError> {
        let request = match self.session.jar.header() {
            Some(cookies) => request.header(header::COOKIE, cookies),
            None => request,
        };
        let response = self
            .site
            .http
            .send(request.returning_redirects())
            .await
            .map_err(ProviderError::from)?;
        self.session
            .jar
            .store(&response.headers, OffsetDateTime::now_utc());
        Ok(Page {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }

    async fn get(&mut self, path: &str) -> Result<Page, SiteError> {
        let request = Request::new(Method::GET, SITE_HOST, path, self.site.family)
            .header(header::ACCEPT, HeaderValue::from_static(ACCEPT_HTML))
            .limit(PAGE_LIMIT)
            .timeout(self.site.timeout);
        self.send(request).await
    }

    async fn post_login(
        &mut self,
        action: &str,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Page, SiteError> {
        let request = Request::new(Method::POST, SITE_HOST, action, self.site.family)
            .form(body)
            .header(header::ACCEPT, HeaderValue::from_static(ACCEPT_HTML))
            .header(header::ORIGIN, HeaderValue::from_static(ORIGIN))
            .header(header::REFERER, HeaderValue::from_static(LOGIN_PAGE))
            .limit(PAGE_LIMIT)
            .timeout(self.site.timeout);
        self.send(request).await
    }

    /// `POST /ports/` with `action`, its `params`, the token and `render=ajax`, in the page's
    /// order, answered within `timeout`.
    async fn post_action(
        &mut self,
        action: &str,
        params: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<Page, SiteError> {
        let body = {
            let token = self
                .session
                .token
                .as_ref()
                .ok_or_else(|| SiteError::NotSignedIn(port_request()))?;
            let mut fields = vec![("action", action)];
            fields.extend_from_slice(params);
            fields.push(("ecsrf", token.as_str()));
            fields.push(("render", "ajax"));
            html::form_body(&fields)
        };
        let request = Request::new(Method::POST, SITE_HOST, PORTS_PATH, self.site.family)
            .form(body)
            .header(header::ACCEPT, HeaderValue::from_static(ACCEPT_XHR))
            .header(
                HeaderName::from_static(X_REQUESTED_WITH),
                HeaderValue::from_static("XMLHttpRequest"),
            )
            .header(header::ORIGIN, HeaderValue::from_static(ORIGIN))
            .header(header::REFERER, HeaderValue::from_static(PORTS_PAGE))
            .limit(JSON_LIMIT)
            .timeout(timeout);
        self.send(request).await
    }

    // ---------------------------------------------------------------------------------------
    // Signing in
    // ---------------------------------------------------------------------------------------

    /// What must stay out of the debug log: the credential, the cookies, the token.
    fn secrets(&self) -> Vec<&str> {
        let mut s = vec![self.credentials.username(), self.credentials.password()];
        s.extend(self.session.jar.values());
        s.extend(self.session.token.as_deref().map(String::as_str));
        s
    }

    /// Log an answer outside the known shape: its status and a scrubbed snippet, at debug level.
    fn note(&self, page: &Page, what: &str) {
        tracing::debug!(
            status = page.status.as_u16(),
            what,
            signed_in = ?page.signed_in(),
            snippet = %html::snippet(&page.body, &self.secrets()),
            "AirVPN website answer outside the known contract"
        );
    }

    /// A message of the page that can be shown: a short plain sentence naming nothing secret,
    /// its markup dropped.
    fn readable(&self, raw: Option<String>) -> Option<String> {
        raw.and_then(|m| html::readable(&html::fragment_text(&m), &self.secrets()))
    }

    /// An answer that is neither the success nor signed out: its status decides. `what` names
    /// the answer.
    fn unexpected(&self, page: &Page, what: Text) -> SiteError {
        if page.status.is_success() || page.status.is_redirection() {
            self.note(page, &what.en);
            return SiteError::Provider(ProviderError::ContractDrift(what));
        }
        if page.status.is_client_error() && page.status != StatusCode::TOO_MANY_REQUESTS {
            self.note(page, &what.en);
        }
        SiteError::Provider(status_error(page.status, &page.headers, None))
    }

    /// An answer that is neither the success nor signed out, to a call that changes nothing:
    /// `AirVPN`'s refusal when it says one (`{"error": …}`), else [`Run::unexpected`].
    fn refusal(&self, page: &Page, action: Operation, port: Option<u16>) -> SiteError {
        match ports::failure(&page.body) {
            Some(raw) if page.status.is_success() => SiteError::Refused {
                action,
                port,
                message: self.readable(Some(raw)),
            },
            _ => self.unexpected(page, action.name()),
        }
    }

    async fn ensure(&mut self) -> Result<(), SiteError> {
        if self.session.token.is_some() {
            return Ok(());
        }
        self.sign_in().await
    }

    /// Sign in and fetch the page token. Once per operation at most.
    async fn sign_in(&mut self) -> Result<(), SiteError> {
        if self.signed_in {
            return Err(SiteError::NotSignedIn(port_request()));
        }
        self.signed_in = true;
        self.session.token = None;
        tracing::info!("signing in to AirVPN's website (forwarded ports)");
        let page = self.get(LOGIN_PATH).await?;
        // Signed in already (the cookies still hold a session; the page then sends the member
        // on): the token is all that is missing. Any other answer but the form is not the
        // contract, and nothing is posted.
        if page.signed_in() != Some(true) {
            if !page.status.is_success() {
                return Err(self.unexpected(&page, tr!("sign-in page", "登入頁", "ログインページ")));
            }
            let form = match html::login_form(&page.text()) {
                Ok(form) => form,
                Err(FormProblem::Captcha) => return Err(SiteError::Captcha),
                Err(FormProblem::NoForm) => {
                    let what = sign_in_form();
                    self.note(&page, &what.en);
                    return Err(SiteError::LoginFormChanged(what));
                }
                Err(FormProblem::Missing(what)) => {
                    self.note(&page, what);
                    return Err(SiteError::LoginFormChanged(Text::verbatim(what)));
                }
                Err(FormProblem::UnknownField(name)) => {
                    self.note(&page, &sign_in_form().en);
                    return Err(SiteError::LoginFormChanged(tr!(
                        "an extra field {name}",
                        "多了欄位 {name}",
                        "余分なフィールド {name}"
                    )));
                }
            };
            let body = form.body(self.credentials.username(), self.credentials.password());
            let answer = self.post_login(&form.action, body).await?;
            self.judge_sign_in(answer).await?;
        }
        self.fetch_token().await
    }

    /// What the answer to the posted form says.
    async fn judge_sign_in(&mut self, answer: Page) -> Result<(), SiteError> {
        if answer.status.is_redirection() {
            // Success sends the member on; a second step or the form again stays at /login/.
            return match answer.location().and_then(same_origin_path) {
                Some(path) if html::is_login_path(&path) => {
                    let page = self.get(&path).await?;
                    self.judge_sign_in_page(&page)
                }
                _ => Ok(()),
            };
        }
        if !answer.status.is_success() {
            return Err(self.unexpected(&answer, tr!("sign-in", "登入", "ログイン")));
        }
        self.judge_sign_in_page(&answer)
    }

    fn judge_sign_in_page(&self, page: &Page) -> Result<(), SiteError> {
        let text = page.text();
        if !matches!(
            html::login_form(&text),
            Err(FormProblem::NoForm | FormProblem::Missing(_))
        ) {
            // The form again: refused. Its message says why, when it is a plain sentence.
            let raw = html::message(&text);
            if html::captcha(&text) {
                return Err(SiteError::Captcha);
            }
            let said = self.readable(raw.clone());
            if raw.as_deref().is_some_and(html::locked) {
                return Err(SiteError::LoginLocked(said));
            }
            return Err(SiteError::LoginRejected(said));
        }
        if page.signed_in() == Some(true) {
            return Ok(());
        }
        if html::second_factor(&text) {
            return Err(SiteError::SecondFactor);
        }
        if html::captcha(&text) {
            return Err(SiteError::Captcha);
        }
        if page.signed_in() == Some(false) {
            if html::locked(&text) {
                return Err(SiteError::LoginLocked(self.readable(html::message(&text))));
            }
            let what = tr!(
                "page after signing in",
                "登入後的頁面",
                "ログイン後のページ"
            );
            self.note(page, &what.en);
            return Err(SiteError::NotSignedIn(what));
        }
        // Neither the form nor a verdict: the Ports page decides.
        Ok(())
    }

    /// `GET /ports/` for the page token.
    async fn fetch_token(&mut self) -> Result<(), SiteError> {
        let page = self.get(PORTS_PATH).await?;
        if page.status.is_redirection() {
            let to_login = page
                .location()
                .and_then(same_origin_path)
                .is_some_and(|p| html::is_login_path(&p));
            if to_login {
                return Err(SiteError::NotSignedIn(ports_page()));
            }
            return Err(self.unexpected(&page, ports_page()));
        }
        if !page.status.is_success() {
            return Err(self.unexpected(&page, ports_page()));
        }
        let text = page.text();
        let signed_out = page.signed_in() == Some(false) || html::signed_out(&text);
        match html::token(&text) {
            Token::Found(token) => {
                self.session.token = Some(token);
                Ok(())
            }
            Token::Absent | Token::NoElement if signed_out => {
                let what = ports_page();
                self.note(&page, &what.en);
                Err(SiteError::NotSignedIn(what))
            }
            Token::Absent => {
                self.note(&page, &ports_page().en);
                Err(SiteError::PortsUnavailable(
                    self.readable(html::message(&text)),
                ))
            }
            Token::Malformed => {
                let what = tr!(
                    "ecsrf of the Ports page",
                    "連入埠頁面的 ecsrf",
                    "Ports ページの ecsrf"
                );
                self.note(&page, &what.en);
                Err(ProviderError::ContractDrift(what).into())
            }
            Token::NoElement => {
                let what = ports_page();
                self.note(&page, &what.en);
                Err(ProviderError::ContractDrift(what).into())
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Port calls
    // ---------------------------------------------------------------------------------------

    /// One port call: signed in first; a signed-out answer signs in again (once per operation)
    /// and repeats it — the site did not act on a request it answered as signed out.
    async fn call<T>(
        &mut self,
        action: &str,
        params: &[(&str, &str)],
        parse: fn(&[u8]) -> ports::Parsed<T>,
    ) -> Result<Outcome<T>, SiteError> {
        let timeout = self.site.timeout;
        self.call_within(timeout, action, params, parse).await
    }

    /// [`Run::call`], each request of it answered within `timeout`.
    async fn call_within<T>(
        &mut self,
        timeout: Duration,
        action: &str,
        params: &[(&str, &str)],
        parse: fn(&[u8]) -> ports::Parsed<T>,
    ) -> Result<Outcome<T>, SiteError> {
        self.ensure().await?;
        let page = self.post_action(action, params, timeout).await?;
        if let Some(done) = self.parsed(&page, parse) {
            return done.map(Outcome::Done);
        }
        if !page.stale() {
            return Ok(Outcome::Other(page));
        }
        tracing::info!(
            status = page.status.as_u16(),
            "AirVPN website answered as signed out; signing in again"
        );
        self.sign_in().await?;
        let page = self.post_action(action, params, timeout).await?;
        if let Some(done) = self.parsed(&page, parse) {
            return done.map(Outcome::Done);
        }
        if page.stale() {
            let what = port_request();
            self.note(&page, &what.en);
            return Err(SiteError::NotSignedIn(what));
        }
        Ok(Outcome::Other(page))
    }

    fn parsed<T>(
        &self,
        page: &Page,
        parse: fn(&[u8]) -> ports::Parsed<T>,
    ) -> Option<Result<T, SiteError>> {
        if !page.status.is_success() {
            return None;
        }
        match parse(&page.body)? {
            Ok(v) => Some(Ok(v)),
            Err(what) => {
                self.note(page, &what.en);
                Some(Err(ProviderError::ContractDrift(what).into()))
            }
        }
    }

    /// A call that changes nothing, whose success is the result: else `AirVPN`'s refusal, else
    /// outside the contract.
    async fn ask<T>(
        &mut self,
        action: &str,
        params: &[(&str, &str)],
        parse: fn(&[u8]) -> ports::Parsed<T>,
        what: Operation,
        port: Option<u16>,
    ) -> Result<T, SiteError> {
        match self.call(action, params, parse).await? {
            Outcome::Done(v) => Ok(v),
            Outcome::Other(page) => Err(self.refusal(&page, what, port)),
        }
    }

    async fn list(&mut self) -> Result<PortList, SiteError> {
        match self.call("manifest", &[], ports::list).await? {
            Outcome::Done(list) => Ok(list),
            Outcome::Other(page) => Err(self.unexpected(
                &page,
                tr!("inbound port list", "連入埠清單", "着信ポートの一覧"),
            )),
        }
    }

    async fn insert(&mut self, port: Option<u16>, before: &PortList) -> Result<Port, SiteError> {
        let value = port.map_or_default(|p| p.to_string());
        let said = match self
            .call("insert", &[("port", &value)], ports::inserted)
            .await
        {
            Ok(Outcome::Done(new)) => {
                if port.is_some_and(|p| p != new.port) {
                    tracing::warn!(
                        asked = port,
                        got = new.port,
                        "AirVPN reserved another port than the one asked for"
                    );
                }
                return Ok(new);
            }
            Ok(Outcome::Other(page)) if page.status == StatusCode::TOO_MANY_REQUESTS => {
                return Err(self.unexpected(&page, Operation::Reserve.name()));
            }
            Ok(Outcome::Other(page)) => {
                self.note(&page, &Operation::Reserve.name().en);
                self.readable(ports::said(&page.body).or_else(|| html::message(&page.text())))
            }
            Err(e) if e.maybe_delivered() => None,
            Err(e) => return Err(e),
        };
        // Not the known success: a fresh list says what happened, nothing is sent again.
        let Ok(after) = self.list().await else {
            return Err(SiteError::OutcomeUnknown(Operation::Reserve));
        };
        let new: Vec<&Port> = after
            .ports
            .iter()
            .filter(|p| {
                !before
                    .ports
                    .iter()
                    .any(|b| b.port == p.port && b.pool == p.pool)
            })
            .collect();
        let mine = match port {
            Some(p) => new.iter().find(|n| n.port == p).copied(),
            None if new.len() == 1 => new.first().copied(),
            None => None,
        };
        match mine {
            Some(p) => Ok(p.clone()),
            None if new.is_empty() => Err(SiteError::Refused {
                action: Operation::Reserve,
                port,
                message: said,
            }),
            None => Err(SiteError::OutcomeUnknown(Operation::Reserve)),
        }
    }

    async fn remove(&mut self, entry: &Port) -> Result<(), SiteError> {
        let (port, pool) = (entry.port.to_string(), entry.pool.to_string());
        let params = [("port", port.as_str()), ("pool", pool.as_str())];
        let (said, failure) = match self.call("delete", &params, ports::deleted).await {
            Ok(Outcome::Done(())) => return Ok(()),
            Ok(Outcome::Other(page)) if page.status == StatusCode::TOO_MANY_REQUESTS => {
                return Err(self.unexpected(&page, Operation::Delete.name()));
            }
            Ok(Outcome::Other(page)) => {
                self.note(&page, &Operation::Delete.name().en);
                let said =
                    self.readable(ports::said(&page.body).or_else(|| html::message(&page.text())));
                (said, None)
            }
            Err(e) if e.maybe_delivered() => (None, Some(e)),
            Err(e) => return Err(e),
        };
        let Ok(after) = self.list().await else {
            return Err(SiteError::OutcomeUnknown(Operation::Delete));
        };
        if !after.ports.iter().any(|p| p.port == entry.port) {
            return Ok(());
        }
        Err(failure.unwrap_or(SiteError::Refused {
            action: Operation::Delete,
            port: Some(entry.port),
            message: said,
        }))
    }

    /// Send each change (`(setting, value)`) of `entry`, one request each, then read the list
    /// back: a change is saved when the read-back shows it. The first request that fails stops
    /// the rest; a refusal does not.
    async fn change(
        &mut self,
        entry: &Port,
        todo: &[(Setting, String)],
    ) -> Result<Edited, SiteError> {
        let (port, pool) = (entry.port.to_string(), entry.pool.to_string());
        let mut refused: Vec<(Setting, Option<String>)> = Vec::new();
        let mut stopped: Option<(usize, SiteError)> = None;
        for (i, (setting, value)) in todo.iter().enumerate() {
            let params = [
                ("port", port.as_str()),
                ("pool", pool.as_str()),
                ("value", value.as_str()),
            ];
            match self.call(setting.action(), &params, ports::edited).await {
                Ok(Outcome::Done(())) => {}
                Ok(Outcome::Other(page)) if page.status == StatusCode::TOO_MANY_REQUESTS => {
                    stopped = Some((i, self.unexpected(&page, Operation::Change.name())));
                    break;
                }
                Ok(Outcome::Other(page)) => match ports::failure(&page.body) {
                    Some(raw) => refused.push((*setting, self.readable(Some(raw)))),
                    // Neither saved nor refused: the list read back says which.
                    None => self.note(&page, &Operation::Change.name().en),
                },
                Err(e) => {
                    stopped = Some((i, e));
                    break;
                }
            }
        }
        // Nothing reached AirVPN: nothing to read back.
        let stopped = match stopped {
            Some((0, e)) if !e.maybe_delivered() => return Err(e),
            other => other,
        };
        let Ok(after) = self.list().await else {
            return Err(SiteError::OutcomeUnknown(Operation::Change));
        };
        let now = reserved(&after, entry.port)?;
        let (mut saved, mut unsaved) = (Vec::new(), Vec::new());
        for (i, (setting, value)) in todo.iter().enumerate() {
            if setting.holds(&now, value) {
                saved.push(*setting);
                continue;
            }
            let why = match (refused.iter().find(|(s, _)| s == setting), &stopped) {
                (Some((_, said)), _) => Why::Refused(said.clone()),
                (None, Some((at, e))) if i == *at => Why::Failed(e.text()),
                (None, Some((at, _))) if i > *at => Why::NotSent,
                _ => Why::Differs,
            };
            unsaved.push(Unsaved {
                setting: *setting,
                why,
            });
        }
        if unsaved.is_empty() {
            return Ok(Edited {
                port: now,
                list: after,
            });
        }
        Err(SiteError::NotSaved { saved, unsaved })
    }

    /// The connected sessions that use `entry`.
    async fn sessions(&mut self, entry: &Port) -> Result<Vec<SessionItem>, SiteError> {
        let (port, pool) = (entry.port.to_string(), entry.pool.to_string());
        self.ask(
            "sessions",
            &[("port", &port), ("pool", &pool)],
            ports::sessions,
            Operation::Test,
            Some(entry.port),
        )
        .await
    }

    /// `AirVPN`'s test of one session's port from its server, waiting at most `timeout`. A test
    /// `AirVPN` does not run or answer is reported per session; a request that cannot go out stops
    /// the operation.
    async fn probe(&mut self, item: &SessionItem, timeout: Duration) -> Result<Probe, SiteError> {
        let (port, pool) = (item.port.to_string(), item.pool.to_string());
        let params = [
            ("ip", item.server_ip.as_str()),
            ("port", port.as_str()),
            ("pool", pool.as_str()),
            ("protocol", "tcp"),
        ];
        match self
            .call_within(timeout, "test", &params, ports::probed)
            .await
        {
            Ok(Outcome::Done(verdict)) => Ok(Probe {
                state: ports::verdict(&verdict.word, verdict.message.as_deref()),
                message: self.readable(verdict.message).map(Text::verbatim),
                word: Some(verdict.word),
            }),
            Ok(Outcome::Other(page)) if page.status.is_success() => {
                let why = ports::failure(&page.body).map_or_else(
                    || {
                        self.note(&page, &Operation::Test.name().en);
                        tr!(
                            "AirVPN's answer to this test does not match the known format",
                            "AirVPN 對這項測試的回覆與已知格式不符",
                            "このテストに対する AirVPN の応答が既知の形式と一致しません"
                        )
                    },
                    |raw| {
                        with_said(
                            tr!(
                                "AirVPN did not complete this test",
                                "AirVPN 沒有完成這項測試",
                                "AirVPN はこのテストを完了しませんでした"
                            ),
                            self.readable(Some(raw)).as_deref(),
                        )
                    },
                );
                Ok(Probe::untested(why))
            }
            Ok(Outcome::Other(page)) => Err(self.unexpected(&page, Operation::Test.name())),
            Err(e) if e.timed_out() => {
                let secs = timeout.as_secs();
                Ok(Probe::untested(tr!(
                    "AirVPN did not answer this test within {secs} s",
                    "AirVPN 沒有在 {secs} 秒內回覆這項測試",
                    "AirVPN は {secs} 秒以内にこのテストに応答しませんでした"
                )))
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_prints_nothing_it_holds() {
        let mut s = Session::new();
        s.token = Some(Zeroizing::new("f".repeat(64)));
        let printed = format!("{s:?}");
        assert!(!printed.contains("ffff"), "{printed}");
        assert!(s.signed_in());
        s.clear_token();
        assert!(!s.signed_in());
    }

    #[test]
    fn only_paths_on_the_site_are_followed() {
        assert_eq!(
            same_origin_path("https://airvpn.org/login/?x=1").as_deref(),
            Some("/login/?x=1")
        );
        assert_eq!(same_origin_path("/ports/").as_deref(), Some("/ports/"));
        assert_eq!(same_origin_path("https://evil.example/login/"), None);
        assert_eq!(same_origin_path("//evil.example/login/"), None);
    }
}
