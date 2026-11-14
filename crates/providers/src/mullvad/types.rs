//! Mullvad credentials (zeroizing, never printed) and the public records the account API
//! returns.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use http::HeaderValue;
use ipnetwork::{Ipv4Network, Ipv6Network};
use serde::Deserialize;
use vpn_domain::{Text, Timestamp, WgKey, tr};
use zeroize::Zeroizing;

use crate::display_text;
use crate::error::ProviderError;

const ACCOUNT_DIGITS: usize = 16;
/// Token length bounds of the previous implementation (`api.mjs`).
const TOKEN_LEN: std::ops::RangeInclusive<usize> = 8..=4096;
const MAX_DEVICE_ID: usize = 64;
const MAX_DEVICE_NAME: usize = 64;
/// Mullvad allows 5 devices per account; a longer list is not this contract.
const MAX_DEVICES_LISTED: usize = 64;

/// A Mullvad account number: 16 digits, and the account's only credential. Zeroized on drop;
/// `Debug` and `Display` never show it.
pub struct AccountNumber(Zeroizing<String>);

/// [`InvalidAccountNumber::text`] is the message a person reads; `Display` is its English.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.text().en)]
pub struct InvalidAccountNumber;

impl InvalidAccountNumber {
    /// The rule, in the three languages.
    #[must_use]
    pub fn text(&self) -> Text {
        tr!(
            "The account number must be 16 digits",
            "帳號號碼必須是 16 位數字",
            "アカウント番号は 16 桁の数字にしてください"
        )
    }
}

impl AccountNumber {
    /// 16 ASCII digits; spaces between groups are accepted, as Mullvad prints them.
    ///
    /// # Errors
    ///
    /// [`InvalidAccountNumber`] when `input` is not 16 digits in that form.
    pub fn parse(input: &str) -> Result<Self, InvalidAccountNumber> {
        if input.len() > 64 {
            return Err(InvalidAccountNumber);
        }
        // Sized up front: pushing never reallocates, so no stray copy is left behind.
        let mut digits = Zeroizing::new(String::with_capacity(ACCOUNT_DIGITS));
        for c in input.trim().chars() {
            match c {
                ' ' => {}
                '0'..='9' if digits.len() < ACCOUNT_DIGITS => digits.push(c),
                _ => return Err(InvalidAccountNumber),
            }
        }
        if digits.len() != ACCOUNT_DIGITS {
            return Err(InvalidAccountNumber);
        }
        Ok(Self(digits))
    }

    /// `{"account_number":"…"}`, built in a buffer sized up front for the same reason.
    pub(crate) fn token_request(&self) -> Zeroizing<Vec<u8>> {
        const PREFIX: &[u8] = br#"{"account_number":""#;
        const SUFFIX: &[u8] = br#""}"#;
        let mut body = Zeroizing::new(Vec::with_capacity(
            PREFIX.len() + ACCOUNT_DIGITS + SUFFIX.len(),
        ));
        body.extend_from_slice(PREFIX);
        body.extend_from_slice(self.0.as_bytes());
        body.extend_from_slice(SUFFIX);
        body
    }
}

impl fmt::Debug for AccountNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountNumber(<redacted>)")
    }
}

impl fmt::Display for AccountNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Bearer token from `POST /auth/v1/token`, valid until [`AccessToken::expires_at`]. Zeroized on
/// drop; `Debug` and `Display` never show it.
pub struct AccessToken {
    secret: Zeroizing<String>,
    expires_at: Timestamp,
}

impl AccessToken {
    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// `Authorization: Bearer …`, marked sensitive so `http`'s `Debug` hides it too.
    pub(crate) fn authorization(&self) -> HeaderValue {
        let mut value = Zeroizing::new(String::with_capacity(7 + self.secret.len()));
        value.push_str("Bearer ");
        value.push_str(&self.secret);
        let mut header =
            HeaderValue::from_str(&value).expect("token validated as visible ASCII at parse");
        header.set_sensitive(true);
        header
    }
}

#[expect(
    clippy::missing_fields_in_debug,
    reason = "redacted: the secret shows only as a placeholder under the name `token`"
)]
impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessToken")
            .field("token", &format_args!("<redacted>"))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl fmt::Display for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// `GET /accounts/v1/accounts/me`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub expiry: Timestamp,
    /// Device quota as Mullvad reports it, when the response carries it.
    pub max_devices: Option<u32>,
    pub can_add_devices: Option<bool>,
}

/// A Mullvad device ID. Checked before it becomes a path segment
/// (`/accounts/v1/devices/{id}`), so it can never add a segment, a query or an escape.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DeviceId(String);

/// [`InvalidDeviceId::text`] is the message a person reads; `Display` is its English.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.text().en)]
pub struct InvalidDeviceId;

impl InvalidDeviceId {
    /// The rule, in the three languages.
    #[must_use]
    pub fn text(&self) -> Text {
        tr!(
            "The device ID is not in the expected format",
            "裝置 ID 格式不正確",
            "デバイス ID の形式が正しくありません"
        )
    }
}

impl DeviceId {
    /// 1–64 characters of `[A-Za-z0-9-]` (the previous implementation's rule; Mullvad's IDs
    /// are UUIDs).
    ///
    /// # Errors
    ///
    /// [`InvalidDeviceId`] when `id` breaks this rule.
    pub fn parse(id: &str) -> Result<Self, InvalidDeviceId> {
        let valid = (1..=MAX_DEVICE_ID).contains(&id.len())
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if valid {
            Ok(Self(id.to_owned()))
        } else {
            Err(InvalidDeviceId)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for DeviceId {
    type Err = InvalidDeviceId;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.0)
    }
}

/// A device on the account (`/accounts/v1/devices`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: DeviceId,
    /// The name Mullvad gave the device ("calm heron").
    pub name: String,
    pub pubkey: WgKey,
    /// Tunnel addresses Mullvad assigned to this device.
    pub ipv4_address: Ipv4Network,
    pub ipv6_address: Option<Ipv6Network>,
    pub created: Timestamp,
}

/// Result of [`crate::mullvad::Mullvad::delete_device`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// 204: Mullvad removed the device.
    Deleted,
    /// 404 `DEVICE_NOT_FOUND`: no such device (e.g. an earlier attempt whose reply was lost
    /// already removed it).
    AlreadyAbsent,
}

/// What the device list says about a create whose outcome is unknown (timeout, broken
/// connection, 5xx, unreadable reply, or `PUBKEY_IN_USE`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciled {
    /// Exactly one device carries the key: the create took effect; bind to this device.
    Bound(Device),
    /// No device carries the key. The create may have failed or may still land, so the
    /// outcome stays unknown. Never re-create automatically: that can register a second device
    /// and spend a slot of the 5-device quota.
    StillUnknown,
}

/// Finds the device that carries `pubkey` in a freshly read device list.
///
/// # Errors
///
/// [`ProviderError::ContractDrift`] when more than one device carries `pubkey`.
pub fn reconcile_created_device(
    devices: &[Device],
    pubkey: &WgKey,
) -> Result<Reconciled, ProviderError> {
    let mut matching = devices.iter().filter(|d| d.pubkey == *pubkey);
    match (matching.next(), matching.next()) {
        (None, _) => Ok(Reconciled::StillUnknown),
        (Some(device), None) => Ok(Reconciled::Bound(device.clone())),
        // Mullvad refuses a key already in use (PUBKEY_IN_USE); two holders is not its contract.
        (Some(_), Some(_)) => Err(ProviderError::ContractDrift(tr!(
            "several devices with one public key",
            "多個裝置使用同一把公鑰",
            "同じ公開鍵を使う複数のデバイス"
        ))),
    }
}

pub fn parse_token(body: &[u8]) -> Result<AccessToken, ProviderError> {
    #[derive(Deserialize)]
    struct Raw<'a> {
        #[serde(borrow)]
        access_token: Cow<'a, str>,
        expiry: Timestamp,
    }
    let drift = || {
        ProviderError::ContractDrift(tr!(
            "access token response",
            "存取權杖回應",
            "アクセストークンの応答"
        ))
    };
    let raw: Raw<'_> = serde_json::from_slice(body).map_err(|_| drift())?;
    let secret = match raw.access_token {
        Cow::Borrowed(token) => Zeroizing::new(token.to_owned()),
        Cow::Owned(token) => Zeroizing::new(token),
    };
    // Visible ASCII only: it goes into a header value as is.
    if !TOKEN_LEN.contains(&secret.len()) || !secret.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(drift());
    }
    Ok(AccessToken {
        secret,
        expires_at: raw.expiry,
    })
}

pub fn parse_account(body: &[u8]) -> Result<Account, ProviderError> {
    #[derive(Deserialize)]
    struct Raw {
        expiry: Timestamp,
        #[serde(default)]
        max_devices: Option<u32>,
        #[serde(default)]
        can_add_devices: Option<bool>,
    }
    let raw: Raw = serde_json::from_slice(body).map_err(|_| {
        ProviderError::ContractDrift(tr!("account response", "帳號回應", "アカウントの応答"))
    })?;
    Ok(Account {
        expiry: raw.expiry,
        max_devices: raw.max_devices,
        can_add_devices: raw.can_add_devices,
    })
}

/// The device record of the official app (`mullvad-api/src/device.rs`, `DeviceResponse`).
#[derive(Deserialize)]
struct RawDevice {
    id: String,
    name: String,
    pubkey: String,
    ipv4_address: String,
    #[serde(default)]
    ipv6_address: Option<String>,
    created: Timestamp,
}

impl RawDevice {
    fn validate(self) -> Option<Device> {
        let ipv6_address = match self.ipv6_address {
            Some(address) => Some(address.parse().ok()?),
            None => None,
        };
        Some(Device {
            id: DeviceId::parse(&self.id).ok()?,
            name: display_text(&self.name, MAX_DEVICE_NAME).ok()??,
            pubkey: self.pubkey.parse().ok()?,
            ipv4_address: self.ipv4_address.parse().ok()?,
            ipv6_address,
            created: self.created,
        })
    }
}

pub fn parse_device(body: &[u8]) -> Result<Device, ProviderError> {
    let drift = || {
        ProviderError::ContractDrift(tr!(
            "new device response",
            "新裝置回應",
            "新しいデバイスの応答"
        ))
    };
    let raw: RawDevice = serde_json::from_slice(body).map_err(|_| drift())?;
    raw.validate().ok_or_else(drift)
}

pub fn parse_devices(body: &[u8]) -> Result<Vec<Device>, ProviderError> {
    let drift = || ProviderError::ContractDrift(tr!("device list", "裝置清單", "デバイス一覧"));
    let raw: Vec<RawDevice> = serde_json::from_slice(body).map_err(|_| drift())?;
    if raw.len() > MAX_DEVICES_LISTED {
        return Err(drift());
    }
    raw.into_iter()
        .map(|d| d.validate().ok_or_else(drift))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn tokens_must_be_header_safe() {
        let t =
            parse_token(br#"{"access_token":"mva_abc12345","expiry":"2026-10-27T09:30:00+00:00"}"#)
                .unwrap();
        assert_eq!(t.authorization().to_str().unwrap(), "Bearer mva_abc12345");
        assert!(t.authorization().is_sensitive());
        // An escaped character is still accepted (owned, not borrowed).
        let t = parse_token(br#"{"access_token":"mva\/abc12345","expiry":"2026-10-27T09:30:00Z"}"#)
            .unwrap();
        assert_eq!(t.authorization().to_str().unwrap(), "Bearer mva/abc12345");
        for bad in [
            br#"{"access_token":"has space inside","expiry":"2026-10-27T09:30:00Z"}"#.as_slice(),
            br#"{"access_token":"short","expiry":"2026-10-27T09:30:00Z"}"#,
            br#"{"access_token":"mva_abc12345"}"#,
            br#"{"access_token":"mva_abc12345","expiry":"tomorrow"}"#,
            b"not json",
        ] {
            assert_matches!(
                parse_token(bad),
                Err(ProviderError::ContractDrift(_)),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
