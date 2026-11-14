//! Secret vault: XChaCha20-Poly1305 with a fresh random 24-byte nonce per secret and AAD binding
//! `installation | secret id | kind | key id`, so ciphertexts cannot be swapped between rows or
//! kinds. The 32-byte master key is VPN Manager's own key file (`vault.key`, Platform) and never
//! leaves the manager process. There is no API that returns plaintext to a public caller.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::TryRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::StoreError;

pub struct Vault {
    cipher: XChaCha20Poly1305,
    key_id: u32,
    fingerprint_key: Zeroizing<[u8; 32]>,
    installation: String,
    key_check: String,
}

/// Shows which key it is; the key and everything derived from it stay out of logs.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

pub struct Sealed {
    pub key_id: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// HMAC-SHA256 under `key`.
#[expect(
    clippy::expect_used,
    reason = "HMAC takes a key of any length: `new_from_slice` never fails for it"
)]
fn hmac_sha256(key: &[u8]) -> Hmac<Sha256> {
    <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length")
}

/// Names a master key without revealing it (HMAC of a fixed label): what the store records as
/// `vault_key_check`.
///
/// # Panics
///
/// Never in practice: HMAC-SHA256 accepts a key of any length.
#[must_use]
pub fn key_check_of(master_key: &[u8; 32]) -> String {
    let mut mac = hmac_sha256(master_key);
    mac.update(b"vpn-manager/vault-key-check/v1");
    hex::encode(mac.finalize().into_bytes())
}

impl Vault {
    pub fn new(master_key: &Zeroizing<[u8; 32]>, key_id: u32, installation: String) -> Self {
        // Separate subkey for request fingerprints (HMAC), so a fingerprint of a low-entropy
        // secret cannot be brute-forced offline from the database.
        let mut mac = hmac_sha256(master_key.as_ref());
        mac.update(b"vpn-manager/request-fingerprint/v1");
        let mut fingerprint_key = Zeroizing::new([0u8; 32]);
        fingerprint_key.copy_from_slice(&mac.finalize().into_bytes());
        let key: &[u8; 32] = master_key;
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
            key_id,
            fingerprint_key,
            installation,
            key_check: key_check_of(master_key),
        }
    }

    /// Names the master key without revealing it, so the store can tell whether a key file is
    /// the one its secrets were sealed with.
    pub fn key_check(&self) -> &str {
        &self.key_check
    }

    fn aad(&self, secret_id: &str, kind: &str, key_id: u32) -> Vec<u8> {
        format!("{}|{}|{}|{}", self.installation, secret_id, kind, key_id).into_bytes()
    }

    pub fn seal(
        &self,
        secret_id: &str,
        kind: &str,
        plaintext: &[u8],
    ) -> Result<Sealed, StoreError> {
        let mut nonce = [0u8; 24];
        rand::rngs::SysRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| StoreError::Vault(format!("rng: {e}")))?;
        let aad = self.aad(secret_id, kind, self.key_id);
        let ciphertext = self
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_opaque| StoreError::Vault("encryption failed".into()))?;
        Ok(Sealed {
            key_id: self.key_id,
            nonce,
            ciphertext,
        })
    }

    pub fn open(
        &self,
        secret_id: &str,
        kind: &str,
        key_id: u32,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        if key_id != self.key_id {
            return Err(StoreError::Vault(
                "secret sealed with an unknown key".into(),
            ));
        }
        let nonce = <&XNonce>::try_from(nonce)
            .map_err(|_wrong_length| StoreError::Vault("bad nonce".into()))?;
        let aad = self.aad(secret_id, kind, key_id);
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_opaque| StoreError::Vault("authentication failed".into()))
    }

    /// Keyed fingerprint (HMAC-SHA256, hex) for idempotency of requests that carry secrets.
    pub fn fingerprint(&self, data: &[u8]) -> String {
        let mut mac = hmac_sha256(self.fingerprint_key.as_ref());
        mac.update(data);
        hex::encode(mac.finalize().into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_binds_row_identity_and_tampering_fails() {
        let key = Zeroizing::new([9u8; 32]);
        let v = Vault::new(&key, 1, "inst".into());
        let s = v.seal("a", "wireguard_private_key", b"top secret").unwrap();
        let p = v
            .open("a", "wireguard_private_key", 1, &s.nonce, &s.ciphertext)
            .unwrap();
        assert_eq!(&p[..], b"top secret");
        // Moving the ciphertext to another row or kind fails authentication.
        assert!(
            v.open("b", "wireguard_private_key", 1, &s.nonce, &s.ciphertext)
                .is_err()
        );
        assert!(
            v.open("a", "provider_credential", 1, &s.nonce, &s.ciphertext)
                .is_err()
        );
        let mut tampered = s.ciphertext.clone();
        tampered[0] ^= 1;
        assert!(
            v.open("a", "wireguard_private_key", 1, &s.nonce, &tampered)
                .is_err()
        );
        // Nonces are fresh per seal.
        let s2 = v.seal("a", "wireguard_private_key", b"top secret").unwrap();
        assert_ne!(s.nonce, s2.nonce);
        // A different master key cannot open it.
        let other = Vault::new(&Zeroizing::new([8u8; 32]), 1, "inst".into());
        assert!(
            other
                .open("a", "wireguard_private_key", 1, &s.nonce, &s.ciphertext)
                .is_err()
        );
        assert_ne!(v.fingerprint(b"x"), other.fingerprint(b"x"));
    }

    /// What the vault wrote with the crates it used until 2026-11-11 (chacha20poly1305 0.10.1,
    /// hmac 0.12.1, sha2 0.10.9; the values below were made with those) is what it reads and
    /// writes now: a sealed secret opens, and the key check and a request fingerprint are the
    /// same strings. All of them are on disk.
    #[test]
    fn what_the_earlier_crates_wrote_still_holds() {
        let v = Vault::new(&Zeroizing::new([9u8; 32]), 1, "inst".into());
        let nonce = hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718").unwrap();
        let sealed = hex::decode("46ed81b19c267b70794c6782d62bfc761820279f0ed5a57fc638").unwrap();
        let opened = v
            .open("a", "wireguard_private_key", 1, &nonce, &sealed)
            .unwrap();
        assert_eq!(&opened[..], b"top secret");
        assert_eq!(
            v.key_check(),
            "00ecff3a78c356a73f758ca82f85d99f0ee8f23ac5ab609de285b55e096a22d0"
        );
        assert_eq!(
            v.fingerprint(b"x"),
            "d32e323ff2861d3e44bae3c57af5a44ba313b9b8f9cf5465e6eb5b2e5e73cab0"
        );
        // A nonce of another length is refused, not cut or padded.
        assert!(
            v.open("a", "wireguard_private_key", 1, &nonce[..23], &sealed)
                .is_err()
        );
    }
}
