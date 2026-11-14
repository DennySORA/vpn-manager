//! Small shared value types.

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use ts_rs::TS;

use crate::ids::SecretId;
use crate::text::Text;
use crate::tr;

/// Monotonic per-entity revision, `1..=2^53-1`.
pub type Revision = u64;

/// Largest integer JavaScript represents exactly; revisions and generations stay below it.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// UTC timestamp, RFC 3339 on the wire.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, TS)]
#[ts(export, type = "string")]
pub struct Timestamp(pub OffsetDateTime);

impl Timestamp {
    #[must_use]
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "OffsetDateTime spans at most ±9999 years, whose milliseconds always fit in i64"
    )]
    pub const fn unix_millis(&self) -> i64 {
        (self.0.unix_timestamp_nanos() / 1_000_000) as i64
    }

    pub fn from_unix_millis(ms: i64) -> Option<Self> {
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
            .ok()
            .map(Self)
    }

    #[must_use]
    pub fn plus(&self, d: std::time::Duration) -> Self {
        Self(self.0 + d)
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.format(&Rfc3339) {
            Ok(s) => f.write_str(&s),
            Err(_) => f.write_str("<invalid time>"),
        }
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        OffsetDateTime::parse(&s, &Rfc3339)
            .map(|t| Self(t.to_offset(time::UtcOffset::UTC)))
            .map_err(serde::de::Error::custom)
    }
}

/// A `WireGuard` public key: base64 of exactly 32 bytes, never all-zero.
#[derive(Clone, Copy, PartialEq, Eq, Hash, TS)]
#[ts(export, type = "string")]
pub struct WgKey(pub [u8; 32]);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("a key must be 32 bytes, base64-encoded")]
    Encoding,
    #[error("a key cannot be all zeros")]
    AllZero,
}

impl KeyError {
    /// What to tell the user.
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::Encoding => tr!(
                "A key must be 32 bytes, base64-encoded",
                "金鑰必須是 base64 編碼的 32 bytes",
                "鍵は base64 でエンコードした 32 bytes にしてください"
            ),
            Self::AllZero => tr!(
                "A key cannot be all zeros",
                "金鑰不可全為 0",
                "鍵をすべて 0 にすることはできません"
            ),
        }
    }
}

impl WgKey {
    #[must_use]
    pub fn to_base64(self) -> String {
        B64.encode(self.0)
    }
}

impl FromStr for WgKey {
    type Err = KeyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[expect(
            clippy::map_err_ignore,
            reason = "every key that is not 32 bytes of base64 gets the one fixed message `KeyError::Encoding`, which users see translated; which symbol or length broke the base64 is not part of it"
        )]
        let bytes = B64.decode(s.trim()).map_err(|_| KeyError::Encoding)?;
        // The error hands back the decoded bytes; their wrong length is what `Encoding` says.
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_not_32_bytes| KeyError::Encoding)?;
        if key == [0u8; 32] {
            return Err(KeyError::AllZero);
        }
        Ok(Self(key))
    }
}

impl fmt::Display for WgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64())
    }
}

impl fmt::Debug for WgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WgKey({})", self.to_base64())
    }
}

impl Serialize for WgKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for WgKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Reference to a secret held by the Store. Wire form `secret:<uuid>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, TS)]
#[ts(export, type = "string")]
pub struct SecretRef(pub SecretId);

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "secret:{}", self.0)
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for SecretRef {
    type Err = String;
    #[expect(
        clippy::map_err_ignore,
        reason = "a malformed reference gets the one fixed text `invalid secret id`, which serde passes on as the wire error; the UUID parser's detail is not part of it"
    )]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix("secret:")
            .ok_or_else(|| "secret ref must start with `secret:`".to_string())?;
        rest.parse()
            .map(SecretRef)
            .map_err(|_| "invalid secret id".to_string())
    }
}

impl Serialize for SecretRef {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// u64 counter encoded as a decimal string (JavaScript cannot hold all u64 values).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, TS)]
#[ts(export, type = "string")]
pub struct Counter(pub u64);

impl fmt::Debug for Counter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for Counter {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Counter {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map(Counter).map_err(serde::de::Error::custom)
    }
}

/// Which provider a profile or account belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ProviderKind {
    Generic,
    Mullvad,
    Airvpn,
}

impl ProviderKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Mullvad => "mullvad",
            Self::Airvpn => "airvpn",
        }
    }
}

impl FromStr for ProviderKind {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "generic" => Ok(Self::Generic),
            "mullvad" => Ok(Self::Mullvad),
            "airvpn" => Ok(Self::Airvpn),
            _ => Err(()),
        }
    }
}
