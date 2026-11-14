// SPDX-License-Identifier: GPL-3.0-or-later

//! `AirVPN` credentials (zeroizing, never printed) and the account answer of `act=user`: the peer
//! key every server presents, and the devices with the keys `AirVPN` issued for them.
//!
//! Shapes follow Eddie (`Service.cs`: `user@wg_public_key`, `keys/key@wg_private_key`,
//! `wg_preshared`, `wg_ipv4`, `wg_ipv6`, `wg_dns_ipv4`, `wg_dns_ipv6`) and the previous
//! implementation (`bootstrap.mjs`, `parseUser`). Unlike the latter, a device's IPv6 address and
//! IPv6 resolver are kept, and a device that does not fit the contract is drift rather than
//! silently left out.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ipnetwork::{Ipv4Network, Ipv6Network};
use time::format_description::StaticFormatDescription;
use time::format_description::well_known::{Rfc2822, Rfc3339};
use time::{Date, OffsetDateTime, PrimitiveDateTime, UtcOffset};
use vpn_domain::validation::is_special;
use vpn_domain::{Text, Timestamp, WgKey, tr};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::xml::{Document, Element};
use crate::display_text;
use crate::error::ProviderError;

/// The previous implementation's bounds (`service.mjs`, `normalizeCredentials`).
const MAX_USERNAME: usize = 128;
const MAX_PASSWORD: usize = 512;
const MAX_DEVICE_NAME: usize = 64;
/// The previous implementation's bound on the device list.
const MAX_DEVICES: usize = 64;
/// `expirationdate` as Unix seconds has at most 12 digits (the previous implementation's rule).
const MAX_EPOCH_DIGITS: usize = 12;

const DATE_TIME: StaticFormatDescription =
    time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
const DATE: StaticFormatDescription = time::macros::format_description!("[year]-[month]-[day]");

fn account_drift() -> ProviderError {
    ProviderError::ContractDrift(tr!("account response", "帳號回應", "アカウントの応答"))
}

fn peer_key_drift() -> ProviderError {
    ProviderError::ContractDrift(tr!("server public key", "伺服器公鑰", "サーバーの公開鍵"))
}

fn devices_drift() -> ProviderError {
    ProviderError::ContractDrift(tr!("device list", "裝置清單", "デバイス一覧"))
}

fn device_keys_drift() -> ProviderError {
    ProviderError::ContractDrift(tr!("device keys", "裝置金鑰", "デバイスの鍵"))
}

fn device_addresses_drift() -> ProviderError {
    ProviderError::ContractDrift(tr!(
        "device addresses or DNS",
        "裝置位址或 DNS",
        "デバイスのアドレスまたは DNS"
    ))
}

/// An `AirVPN` user name and password, the account's only credentials; they leave only inside
/// the encrypted bootstrap request. Zeroized on drop; `Debug` and `Display` never show them.
pub struct Credentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

/// Which credential is not acceptable (never what it was). [`InvalidCredentials::text`] is the
/// message a person reads; `Display` is its English.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidCredentials {
    Username,
    Password,
}

impl InvalidCredentials {
    /// The rule the credential breaks, in the three languages.
    #[must_use]
    pub fn text(self) -> Text {
        match self {
            Self::Username => tr!(
                "The AirVPN user name must have 1–128 characters and no control characters",
                "AirVPN 使用者名稱必須是 1–128 個字元，且不可包含控制字元",
                "AirVPN のユーザー名は 1〜128 文字で、制御文字を含めないでください"
            ),
            Self::Password => tr!(
                "The AirVPN password must have 1–512 characters and no line breaks or NUL characters",
                "AirVPN 密碼必須是 1–512 個字元，且不可包含換行或 NUL 字元",
                "AirVPN のパスワードは 1〜512 文字で、改行や NUL 文字を含めないでください"
            ),
        }
    }
}

impl fmt::Display for InvalidCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text().en)
    }
}

impl Credentials {
    /// The previous implementation's rules (`service.mjs`, `normalizeCredentials`): the user
    /// name is trimmed and has 1–128 characters, none in U+0000–U+001F or U+007F; the password
    /// is kept exactly as typed and has 1–512 UTF-16 units, without NUL, CR or LF.
    ///
    /// # Errors
    ///
    /// [`InvalidCredentials::Username`] or [`InvalidCredentials::Password`] naming the value that
    /// breaks these rules.
    pub fn new(username: &str, password: &str) -> Result<Self, InvalidCredentials> {
        let username = username.trim();
        let control = |c: char| matches!(c, '\0'..='\u{1f}' | '\u{7f}');
        if !(1..=MAX_USERNAME).contains(&username.chars().count()) || username.contains(control) {
            return Err(InvalidCredentials::Username);
        }
        if !(1..=MAX_PASSWORD).contains(&password.encode_utf16().count())
            || password.contains(['\0', '\r', '\n'])
        {
            return Err(InvalidCredentials::Password);
        }
        Ok(Self {
            username: Zeroizing::new(username.to_owned()),
            password: Zeroizing::new(password.to_owned()),
        })
    }

    /// The trimmed user name, e.g. to label the account. This crate never prints it.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    pub(crate) fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials(<redacted>)")
    }
}

impl fmt::Display for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A device's `WireGuard` private key as `AirVPN` issued it. Zeroized on drop; `Debug` and `Display`
/// never show it.
#[derive(Clone)]
pub struct PrivateKey(Zeroizing<[u8; 32]>);

impl PrivateKey {
    /// The raw key, for the vault.
    #[must_use]
    pub fn bytes(&self) -> Zeroizing<[u8; 32]> {
        self.0.clone()
    }

    /// The public key `WireGuard` derives from it (X25519 with the base point, as `wg pubkey`).
    #[must_use]
    pub fn public_key(&self) -> WgKey {
        let secret = StaticSecret::from(*self.0);
        WgKey(PublicKey::from(&secret).to_bytes())
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A device's `WireGuard` preshared key. Zeroized on drop; `Debug` and `Display` never show it.
#[derive(Clone)]
pub struct PresharedKey(Zeroizing<[u8; 32]>);

impl PresharedKey {
    /// The raw key, for the vault.
    #[must_use]
    pub fn bytes(&self) -> Zeroizing<[u8; 32]> {
        self.0.clone()
    }
}

impl fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PresharedKey(<redacted>)")
    }
}

impl fmt::Display for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// `act=user`: the account as `AirVPN` answers it.
#[derive(Debug, Clone)]
pub struct UserInfo {
    /// Paid-until date (`expirationdate`), when stated in a form this reads. Shown, never
    /// enforced.
    pub expires_at: Option<Timestamp>,
    /// `wg_public_key`: the account's `WireGuard` peer key, which every `AirVPN` server presents.
    pub peer_public_key: WgKey,
    /// The account's devices, in `AirVPN`'s order.
    pub devices: Vec<Device>,
}

impl UserInfo {
    /// The device whose (derived) public key is `public_key`: a device's identity.
    #[must_use]
    pub fn device(&self, public_key: &WgKey) -> Option<&Device> {
        self.devices.iter().find(|d| d.public_key == *public_key)
    }
}

/// One device of the account (`user/keys/key`) with the `WireGuard` keys `AirVPN` issued for it.
#[derive(Debug, Clone)]
pub struct Device {
    /// The name given on the `AirVPN` website.
    pub name: String,
    /// Derived from [`Device::private_key`] (`AirVPN` sends only the private key); unique on the
    /// account.
    pub public_key: WgKey,
    /// Tunnel addresses (`wg_ipv4`, `wg_ipv6`).
    pub ipv4: Ipv4Network,
    pub ipv6: Option<Ipv6Network>,
    /// In-tunnel resolvers (`wg_dns_ipv4`, `wg_dns_ipv6`).
    pub dns_v4: Ipv4Addr,
    pub dns_v6: Option<Ipv6Addr>,
    pub private_key: PrivateKey,
    pub preshared_key: PresharedKey,
}

pub fn parse_user(xml: &str) -> Result<UserInfo, ProviderError> {
    let doc = Document::parse(xml).map_err(|_malformed| account_drift())?;
    let user = doc.root();
    // Eddie `FetchUrls`: an `error` on the document element is the server's refusal.
    if user.raw("error").is_some() {
        return Err(ProviderError::AuthRejected);
    }
    if user.name() != "user" {
        return Err(account_drift());
    }
    // `message_action="stop"` (previous implementation) and any `message` (Eddie `Engine.Auth`
    // shows it and does not log in) refuse the session; so does a missing `login`.
    let stop = user
        .get("message_action")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("stop"));
    let message = user.get("message").is_some_and(|v| !v.trim().is_empty());
    let login = user.get("login").is_some_and(|v| !v.trim().is_empty());
    if stop || message || !login {
        return Err(ProviderError::AuthRejected);
    }
    let peer_public_key = user
        .get("wg_public_key")
        .and_then(|v| v.trim().parse::<WgKey>().ok())
        .ok_or_else(peer_key_drift)?;

    let mut devices: Vec<Device> = Vec::new();
    for key in doc.path(&["keys", "key"]) {
        if devices.len() == MAX_DEVICES {
            return Err(devices_drift());
        }
        let device = parse_device(key)?;
        // Two devices with one key, or a device holding the servers' key, is not the contract.
        if device.public_key == peer_public_key
            || devices.iter().any(|d| d.public_key == device.public_key)
        {
            return Err(devices_drift());
        }
        devices.push(device);
    }
    Ok(UserInfo {
        expires_at: user.get("expirationdate").and_then(|v| expiry(&v)),
        peer_public_key,
        devices,
    })
}

fn parse_device(key: &Element<'_>) -> Result<Device, ProviderError> {
    let name = key
        .get("name")
        .and_then(|v| display_text(&v, MAX_DEVICE_NAME).ok().flatten())
        .ok_or_else(devices_drift)?;
    let private_key = key
        .raw("wg_private_key")
        .and_then(key32)
        .map(PrivateKey)
        .ok_or_else(device_keys_drift)?;
    let preshared_key = key
        .raw("wg_preshared")
        .and_then(key32)
        .map(PresharedKey)
        .ok_or_else(device_keys_drift)?;
    let tunnel_v4 = |n: &Ipv4Network| !is_special(IpAddr::V4(n.ip()));
    let tunnel_v6 = |n: &Ipv6Network| !is_special(IpAddr::V6(n.ip()));
    let resolver_v4 = |ip: &Ipv4Addr| !is_special(IpAddr::V4(*ip));
    let resolver_v6 = |ip: &Ipv6Addr| !is_special(IpAddr::V6(*ip));
    Ok(Device {
        name,
        public_key: private_key.public_key(),
        ipv4: optional(key, "wg_ipv4", tunnel_v4)?.ok_or_else(device_addresses_drift)?,
        ipv6: optional(key, "wg_ipv6", tunnel_v6)?,
        dns_v4: optional(key, "wg_dns_ipv4", resolver_v4)?.ok_or_else(device_addresses_drift)?,
        dns_v6: optional(key, "wg_dns_ipv6", resolver_v6)?,
        private_key,
        preshared_key,
    })
}

/// An address attribute: `None` when absent or empty, drift when present but not a valid `T`.
fn optional<T: FromStr>(
    key: &Element<'_>,
    name: &str,
    valid: impl Fn(&T) -> bool,
) -> Result<Option<T>, ProviderError> {
    let Some(value) = key.get(name) else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    match value.parse::<T>() {
        Ok(parsed) if valid(&parsed) => Ok(Some(parsed)),
        _ => Err(device_addresses_drift()),
    }
}

/// Base64 of exactly 32 bytes, decoded without a stray copy (`decode_slice` wants room for its
/// 33-byte estimate).
fn key32(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    let text = text.trim();
    if text.len() != 44 {
        return None;
    }
    let mut buf = Zeroizing::new([0u8; 33]);
    let len = B64.decode_slice(text, &mut buf[..]).ok()?;
    if len != 32 {
        return None;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&buf[..32]);
    Some(key)
}

/// `expirationdate`: Unix seconds (at most 12 digits, as the previous implementation read
/// them), or a date in RFC 3339, RFC 2822 or `YYYY-MM-DD[ hh:mm:ss]` read as UTC (the common
/// forms of the previous implementation's `Date.parse`). `None` when absent, zero or in any
/// other form: the date is shown, never enforced.
fn expiry(value: &str) -> Option<Timestamp> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        if value.len() > MAX_EPOCH_DIGITS {
            return None;
        }
        let seconds: i64 = value.parse().ok()?;
        return (seconds > 0)
            .then(|| OffsetDateTime::from_unix_timestamp(seconds).ok())
            .flatten()
            .map(Timestamp);
    }
    let at = OffsetDateTime::parse(value, &Rfc3339)
        .or_else(|_| OffsetDateTime::parse(value, &Rfc2822))
        .or_else(|_| PrimitiveDateTime::parse(value, DATE_TIME).map(PrimitiveDateTime::assume_utc))
        .or_else(|_| Date::parse(value, DATE).map(|d| d.midnight().assume_utc()))
        .ok()?;
    Some(Timestamp(at.to_offset(UtcOffset::UTC)))
}
