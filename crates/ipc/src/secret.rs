//! Secret bytes for the private manager->worker channel only. No `Debug`/`Display` output,
//! zeroized on drop. Serialized as base64 on the private channels only; must never be placed in a
//! public DTO.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Exactly 32 bytes (`WireGuard` keys) or `None`.
    #[must_use]
    pub fn as_key(&self) -> Option<Zeroizing<[u8; 32]>> {
        let slice: &[u8] = &self.0;
        let arr: [u8; 32] = slice.try_into().ok()?;
        Some(Zeroizing::new(arr))
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine as _;
        let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&*self.0));
        s.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use base64::Engine as _;
        let encoded = Zeroizing::new(String::deserialize(d)?);
        base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .map(Self::new)
            .map_err(|_| serde::de::Error::custom("invalid secret encoding"))
    }
}
