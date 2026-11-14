// SPDX-License-Identifier: GPL-3.0-or-later

//! The encrypted exchange of Eddie's `Service.cs` (`FetchUrl`, `FetchUrls`, `AssocToUtf8Bytes`)
//! over the caller's connector.
//!
//! Each attempt draws a fresh AES-256 key and IV. `s` is RSA-PKCS#1 v1.5 (the pinned key) of
//! `assoc{key, iv}`, `d` is AES-256-CBC-PKCS#7 of `assoc(params)`, where "assoc" is
//! `base64(name):base64(value)\n` per pair. Both go base64 in a form body (`s=…&d=…`, percent
//! encoded like Eddie's `Uri.EscapeDataString`) to `POST /` on port 80; a 200 answer is
//! AES-256-CBC-PKCS#7 under the same key and IV. A key never serves a second request, so a
//! garbled answer teaches nothing that could be reused (no padding oracle across attempts).

use std::io::Cursor;
use std::net::Ipv4Addr;
use std::time::Duration;

use aws_lc_rs::cipher::{
    AES_256, DecryptionContext, EncryptionContext, PaddedBlockDecryptingKey,
    PaddedBlockEncryptingKey, UnboundCipherKey,
};
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rand;
use aws_lc_rs::rsa::{Pkcs1PublicEncryptingKey, PublicEncryptingKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use http::header::{self, HeaderValue};
use http::{Method, StatusCode, Uri};
use http_body_util::Full;
use vpn_domain::tr;
use zeroize::Zeroizing;

use super::{BOOTSTRAP_IPS, BOOTSTRAP_PORT, RESPONSE_LIMIT, RSA_EXPONENT, RSA_MODULUS};
use crate::error::{ProviderError, Unavailable, unexpected_status};
use crate::https::{self, Connect, Family, HttpError, Opened, Target};

/// One AES block: the most PKCS#7 padding adds.
const AES_BLOCK: usize = 16;
const FORM: &str = "application/x-www-form-urlencoded";

/// An answer that does not decrypt to text under the request's key.
fn ciphertext() -> ProviderError {
    ProviderError::ContractDrift(tr!("encrypted response", "加密回應", "暗号化された応答"))
}

/// The request cannot be sealed for the RSA key.
fn sealing() -> ProviderError {
    ProviderError::ContractDrift(tr!(
        "bootstrap encryption key",
        "bootstrap 加密金鑰",
        "bootstrap の暗号鍵"
    ))
}

/// The pinned key in the form aws-lc-rs reads.
pub fn pinned_key() -> PublicEncryptingKey {
    let modulus = B64
        .decode(RSA_MODULUS)
        .expect("the pinned modulus is base64");
    let exponent = B64
        .decode(RSA_EXPONENT)
        .expect("the pinned exponent is base64");
    let der = spki_der(&modulus, &exponent).expect("an RSA-4096 key fits DER lengths");
    PublicEncryptingKey::from_der(&der).expect("the pinned key is a valid RSA-4096 key")
}

/// Runs one request: each pinned address in turn until one answers, then `parse` on the
/// decrypted text. A transport failure, a status other than 200 or an answer that does not
/// decrypt moves on to the next address. A decrypted answer is final, refusals included: they
/// are never resent to the other addresses. Each attempt is its own connection, authorized on
/// its own by the connector; a connector's refusal ends the request (the route, not the
/// address, refused it).
pub async fn fetch<C: Connect, T>(
    connector: &C,
    rsa: &PublicEncryptingKey,
    params: &[(&str, &[u8])],
    timeout: Duration,
    parse: fn(&str) -> Result<T, ProviderError>,
) -> Result<T, ProviderError> {
    let mut failure = None;
    for ip in BOOTSTRAP_IPS {
        let error = match attempt(connector, rsa, ip, params, timeout).await {
            Ok(answer) => match std::str::from_utf8(answer.plaintext()) {
                Ok(text) => return parse(text),
                // Valid padding over garbage happens by chance; it is the same failure.
                Err(_) => ciphertext(),
            },
            Err(refused @ ProviderError::Refused(_)) => return Err(refused),
            Err(error) => error,
        };
        failure = Some(match failure {
            // An answer off the contract says more than an outage at another address.
            Some(drift @ ProviderError::ContractDrift(_))
                if !matches!(error, ProviderError::ContractDrift(_)) =>
            {
                drift
            }
            _ => error,
        });
    }
    Err(failure.expect("BOOTSTRAP_IPS is not empty"))
}

/// A decrypted answer in the buffer it was decrypted in; zeroized on drop (it carries the
/// devices' private keys).
struct Answer {
    buf: Zeroizing<Vec<u8>>,
    len: usize,
}

impl Answer {
    fn plaintext(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// One attempt at `ip` under a fresh key.
async fn attempt<C: Connect>(
    connector: &C,
    rsa: &PublicEncryptingKey,
    ip: Ipv4Addr,
    params: &[(&str, &[u8])],
    timeout: Duration,
) -> Result<Answer, ProviderError> {
    let Sealed { body, key, iv } = seal(rsa, params).ok_or_else(sealing)?;
    let host = ip.to_string();
    let target = Target {
        method: &Method::POST,
        host: &host,
        port: BOOTSTRAP_PORT,
        path: "/",
        family: Family::V4,
        timeout,
    };
    let Opened {
        stream,
        mut permit,
        admitted,
    } = connector
        .connect_for(&target)
        .await
        .map_err(HttpError::from)?;
    let deadline = admitted + timeout;
    let mut request = hyper::Request::new(Full::new(Cursor::new(body)));
    *request.method_mut() = Method::POST;
    *request.uri_mut() = Uri::from_static("/");
    let headers = request.headers_mut();
    let authority = HeaderValue::from_str(&host).map_err(|_| HttpError::InvalidRequest)?;
    headers.insert(header::HOST, authority);
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(FORM));
    headers.insert(header::CONNECTION, HeaderValue::from_static("close"));

    https::confirm(
        permit.as_deref_mut(),
        &request,
        BOOTSTRAP_PORT,
        Family::V4,
        deadline,
    )
    .await?;
    let response = https::exchange(stream, request, RESPONSE_LIMIT, deadline).await;
    https::answered(permit.as_deref_mut(), &response);
    let response = response?;
    let status = response.status;
    if status != StatusCode::OK {
        return Err(if status.is_client_error() || status.is_server_error() {
            ProviderError::Unavailable(Unavailable::Status(status.as_u16()))
        } else {
            ProviderError::ContractDrift(unexpected_status())
        });
    }
    let mut buf = response.body;
    let len = open(&key, &iv, &mut buf).ok_or_else(ciphertext)?;
    Ok(Answer { buf, len })
}

/// The form body of one attempt and the key and IV its answer comes back under.
struct Sealed {
    body: Zeroizing<Vec<u8>>,
    key: Zeroizing<[u8; 32]>,
    iv: Zeroizing<[u8; 16]>,
}

fn seal(rsa: &PublicEncryptingKey, params: &[(&str, &[u8])]) -> Option<Sealed> {
    let mut key = Zeroizing::new([0u8; 32]);
    let mut iv = Zeroizing::new([0u8; 16]);
    rand::fill(&mut key[..]).ok()?;
    rand::fill(&mut iv[..]).ok()?;

    let wrapped = {
        let secret = assoc(&[("key", &key[..]), ("iv", &iv[..])], 0);
        let rsa = Pkcs1PublicEncryptingKey::new(rsa.clone()).ok()?;
        let mut out = vec![0; rsa.ciphertext_size()];
        let len = rsa.encrypt(&secret, &mut out).ok()?.len();
        out.truncate(len);
        out
    };
    // Room for the padding, so the plaintext (the password) is never left in a reallocation.
    let mut data = assoc(params, AES_BLOCK);
    let aes = PaddedBlockEncryptingKey::cbc_pkcs7(UnboundCipherKey::new(&AES_256, &key[..]).ok()?)
        .ok()?;
    aes.less_safe_encrypt(
        &mut *data,
        EncryptionContext::Iv128(FixedLength::from(&*iv)),
    )
    .ok()?;
    Some(Sealed {
        body: form(&[("s", &wrapped), ("d", &data)]),
        key,
        iv,
    })
}

/// Decrypts an answer in place; the plaintext's length, or `None` when it does not decrypt
/// (wrong length or padding).
fn open(key: &[u8; 32], iv: &[u8; 16], body: &mut [u8]) -> Option<usize> {
    let aes =
        PaddedBlockDecryptingKey::cbc_pkcs7(UnboundCipherKey::new(&AES_256, key).ok()?).ok()?;
    let plaintext = aes
        .decrypt(body, DecryptionContext::Iv128(FixedLength::from(iv)))
        .ok()?;
    Some(plaintext.len())
}

/// Eddie's `AssocToUtf8Bytes`: `base64(name):base64(value)\n` for each pair, in order. Sized up
/// front with `room` spare bytes, so nothing is reallocated.
fn assoc(pairs: &[(&str, &[u8])], room: usize) -> Zeroizing<Vec<u8>> {
    let len: usize = pairs
        .iter()
        .map(|(name, value)| encoded_len(name.len()) + encoded_len(value.len()) + 2)
        .sum();
    let mut out = Zeroizing::new(Vec::with_capacity(len + room));
    out.resize(len, 0);
    let mut at = 0;
    for (name, value) in pairs {
        for (part, end) in [(name.as_bytes(), b':'), (*value, b'\n')] {
            at += B64
                .encode_slice(part, &mut out[at..])
                .expect("sized with encoded_len");
            out[at] = end;
            at += 1;
        }
    }
    out
}

/// Padded base64 length of `len` bytes.
const fn encoded_len(len: usize) -> usize {
    len.div_ceil(3) * 4
}

/// `application/x-www-form-urlencoded` of base64 values: `+`, `/` and `=` percent-encoded, the
/// rest of the alphabet as is.
fn form(fields: &[(&str, &[u8])]) -> Zeroizing<Vec<u8>> {
    let len: usize = fields
        .iter()
        .map(|(name, value)| name.len() + 2 + 3 * encoded_len(value.len()))
        .sum();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    for (i, (name, value)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(b'&');
        }
        out.extend_from_slice(name.as_bytes());
        out.push(b'=');
        for byte in B64.encode(value).bytes() {
            match byte {
                b'+' => out.extend_from_slice(b"%2B"),
                b'/' => out.extend_from_slice(b"%2F"),
                b'=' => out.extend_from_slice(b"%3D"),
                _ => out.push(byte),
            }
        }
    }
    out
}

/// `SubjectPublicKeyInfo` DER of an RSA public key (RFC 5280 §4.1, RFC 8017 A.1.1), the form
/// `PublicEncryptingKey::from_der` reads, from the big-endian modulus and exponent that Eddie
/// imports as `RSAParameters`.
fn spki_der(modulus: &[u8], exponent: &[u8]) -> Option<Vec<u8>> {
    /// `rsaEncryption` (1.2.840.113549.1.1.1) with NULL parameters.
    const RSA_ENCRYPTION: [u8; 15] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let key = tlv(0x30, &[integer(modulus)?, integer(exponent)?].concat())?;
    // BIT STRING with no unused bits.
    let bits = tlv(0x03, &[&[0u8][..], key.as_slice()].concat())?;
    tlv(0x30, &[&RSA_ENCRYPTION[..], bits.as_slice()].concat())
}

/// DER INTEGER of a big-endian unsigned value.
fn integer(value: &[u8]) -> Option<Vec<u8>> {
    let first = value
        .iter()
        .position(|&b| b != 0)
        .unwrap_or_else(|| value.len().saturating_sub(1));
    let value = &value[first..];
    let sign: &[u8] = match value.first() {
        None => return None,
        Some(b) if b & 0x80 != 0 => &[0],
        Some(_) => &[],
    };
    tlv(0x02, &[sign, value].concat())
}

/// Tag, definite length and contents; lengths up to 64 KiB (an RSA-8192 key is about 1 KiB).
fn tlv(tag: u8, contents: &[u8]) -> Option<Vec<u8>> {
    let len = contents.len();
    let mut out = Vec::with_capacity(len + 4);
    out.push(tag);
    let [high, low] = u16::try_from(len).ok()?.to_be_bytes();
    match (high, low) {
        (0, 0..=0x7f) => out.push(low),
        (0, _) => out.extend([0x81, low]),
        _ => out.extend([0x82, high, low]),
    }
    out.extend_from_slice(contents);
    Some(out)
}

#[cfg(test)]
mod tests {

    use aws_lc_rs::rsa::{KeySize, Pkcs1PrivateDecryptingKey, PrivateDecryptingKey};

    use super::*;

    #[test]
    fn the_pinned_key_is_airvpns_rsa_4096() {
        assert_eq!(pinned_key().key_size_bits(), 4096);
        assert_eq!(B64.decode(RSA_MODULUS).unwrap().len(), 512);
        assert_eq!(B64.decode(RSA_EXPONENT).unwrap(), [1, 0, 1]);
    }

    /// The inverse of `form` for base64 fields.
    fn field(body: &[u8], name: &str) -> Vec<u8> {
        let body = std::str::from_utf8(body).unwrap();
        let value = body
            .split('&')
            .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
            .unwrap();
        let value = value
            .replace("%2B", "+")
            .replace("%2F", "/")
            .replace("%3D", "=");
        B64.decode(value).unwrap()
    }

    #[test]
    fn a_sealed_request_opens_with_the_private_key_and_its_answer_with_the_aes_key() {
        let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let params: [(&str, &[u8]); 2] = [("act", b"user"), ("password", "pä+/=&ss".as_bytes())];
        let sealed = seal(&private.public_key(), &params).unwrap();

        let rsa = Pkcs1PrivateDecryptingKey::new(private).unwrap();
        let mut secret = vec![0; rsa.min_output_size()];
        let secret = rsa.decrypt(&field(&sealed.body, "s"), &mut secret).unwrap();
        let expected = format!(
            "a2V5:{}\naXY=:{}\n",
            B64.encode(*sealed.key),
            B64.encode(*sealed.iv)
        );
        assert_eq!(secret, expected.as_bytes());

        let mut data = field(&sealed.body, "d");
        let len = open(&sealed.key, &sealed.iv, &mut data).unwrap();
        assert_eq!(&data[..len], &assoc(&params, 0)[..]);

        // The answer comes back under the same key and IV.
        let aes = PaddedBlockEncryptingKey::cbc_pkcs7(
            UnboundCipherKey::new(&AES_256, &sealed.key[..]).unwrap(),
        )
        .unwrap();
        let mut answer = b"<user login=\"x\"/>".to_vec();
        aes.less_safe_encrypt(
            &mut answer,
            EncryptionContext::Iv128(FixedLength::from(&*sealed.iv)),
        )
        .unwrap();
        let len = open(&sealed.key, &sealed.iv, &mut answer).unwrap();
        assert_eq!(&answer[..len], b"<user login=\"x\"/>");
        // Not a whole number of blocks, or nothing at all: never decrypts.
        assert_eq!(open(&sealed.key, &sealed.iv, &mut answer[..15]), None);
        assert_eq!(open(&sealed.key, &sealed.iv, &mut []), None);
    }

    #[test]
    fn every_attempt_draws_a_fresh_key() {
        let key = pinned_key();
        let a = seal(&key, &[("act", b"user")]).unwrap();
        let b = seal(&key, &[("act", b"user")]).unwrap();
        assert_ne!(*a.key, *b.key);
        assert_ne!(*a.iv, *b.iv);
        assert_ne!(&a.body[..], &b.body[..]);
        // One RSA-4096 block.
        assert_eq!(field(&a.body, "s").len(), 512);
    }
}
