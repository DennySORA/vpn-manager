// SPDX-License-Identifier: GPL-3.0-or-later

//! The `AirVPN` adapter against a fake bootstrap server that holds a throwaway RSA key: it unwraps
//! `s`, decrypts `d`, records the parameters and answers with an encrypted fixture, the way
//! Eddie's server side must. Every connection is an in-memory pipe: nothing touches a socket, a
//! resolver or `AirVPN`.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

use std::io;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, OnceLock};

use aws_lc_rs::cipher::{
    AES_256, DecryptionContext, EncryptionContext, PaddedBlockDecryptingKey,
    PaddedBlockEncryptingKey, UnboundCipherKey,
};
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rsa::{KeySize, Pkcs1PrivateDecryptingKey, PrivateDecryptingKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use vpn_providers::airvpn::{AirVpn, Credentials};
use vpn_providers::{BoxedStream, Connect, Family};

const USER: &str = include_str!("fixtures/airvpn/user.xml");
const MANIFEST: &str = include_str!("fixtures/airvpn/manifest.xml");
const USERNAME: &str = "synthetic-user";
/// Characters that base64, the form encoding and XML each treat specially.
const PASSWORD: &str = "pä+/=&<ss wörd";
/// RFC 7748 §6.1 test vectors (the fixture's device keys): published, never anyone's key.
const ALICE_PRIVATE: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
const ALICE_PUBLIC: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
const BOB_PRIVATE: &str = "XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os=";

fn credentials() -> Credentials {
    Credentials::new(USERNAME, PASSWORD).unwrap()
}

/// The fake server's throwaway RSA key, one per test binary.
fn rsa_key() -> &'static PrivateDecryptingKey {
    static KEY: OnceLock<PrivateDecryptingKey> = OnceLock::new();
    KEY.get_or_init(|| PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap())
}

/// One request as the fake server saw it, decrypted.
#[derive(Debug, Clone)]
struct Seen {
    /// The decrypted parameters, in order.
    params: Vec<(String, String)>,
}

impl Seen {
    fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// How the fake answers one request.
enum Answer {
    /// 200 with this text encrypted under the request's key.
    Xml(String),
    /// This status, no body.
    Status(u16),
}

type Handler = Arc<dyn Fn(&Seen) -> Answer + Send + Sync>;

/// The fake bootstrap server and the connector that reaches it.
#[derive(Clone)]
struct Fake {
    rsa: Arc<Pkcs1PrivateDecryptingKey>,
    handler: Handler,
    refuse: Arc<Vec<Ipv4Addr>>,
    dials: Arc<Mutex<Vec<(String, u16, Family)>>>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Fake {
    fn new(handler: impl Fn(&Seen) -> Answer + Send + Sync + 'static) -> Self {
        Self {
            rsa: Arc::new(Pkcs1PrivateDecryptingKey::new(rsa_key().clone()).unwrap()),
            handler: Arc::new(handler),
            refuse: Arc::default(),
            dials: Arc::default(),
            seen: Arc::default(),
        }
    }

    fn client(&self) -> AirVpn<Self> {
        AirVpn::with_rsa_key(self.clone(), rsa_key().public_key())
    }

    async fn serve(self, mut io: DuplexStream) {
        let Some(request) = read_request(&mut io).await else {
            return;
        };
        let (seen, key, iv) = self.open(request);
        let answer = (self.handler)(&seen);
        self.seen.lock().unwrap().push(seen);
        let response = match answer {
            Answer::Xml(xml) => http(200, &encrypt(&key, &iv, xml.as_bytes())),
            Answer::Status(status) => http(status, b""),
        };
        let _ = io.write_all(&response).await;
        let _ = io.shutdown().await;
    }

    /// Unwraps `s` with the RSA key, then decrypts `d` with the AES key and IV inside it.
    fn open(&self, request: RawRequest) -> (Seen, [u8; 32], [u8; 16]) {
        let body = String::from_utf8(request.body).unwrap();
        let field = |name: &str| {
            let value = body
                .split('&')
                .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
                .unwrap();
            B64.decode(percent_decode(value)).unwrap()
        };
        let mut secret = vec![0; self.rsa.min_output_size()];
        let secret = assoc(self.rsa.decrypt(&field("s"), &mut secret).unwrap());
        let names: Vec<&[u8]> = secret.iter().map(|(n, _)| n.as_slice()).collect();
        assert_eq!(names, [b"key".as_slice(), b"iv"]);
        let key: [u8; 32] = secret[0].1.clone().try_into().unwrap();
        let iv: [u8; 16] = secret[1].1.clone().try_into().unwrap();

        let mut data = field("d");
        let aes =
            PaddedBlockDecryptingKey::cbc_pkcs7(UnboundCipherKey::new(&AES_256, &key).unwrap())
                .unwrap();
        let plaintext = aes
            .decrypt(&mut data, DecryptionContext::Iv128(FixedLength::from(&iv)))
            .unwrap();
        let params = assoc(plaintext)
            .into_iter()
            .map(|(n, v)| (String::from_utf8(n).unwrap(), String::from_utf8(v).unwrap()))
            .collect();
        let seen = Seen { params };
        (seen, key, iv)
    }
}

impl Fake {
    /// What [`Connect::connect`] answers, at once.
    fn dial(&self, host: &str, port: u16, family: Family) -> io::Result<BoxedStream> {
        self.dials
            .lock()
            .unwrap()
            .push((host.to_owned(), port, family));
        if self.refuse.iter().any(|ip| ip.to_string() == host) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "fake bootstrap refuses",
            ));
        }
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(self.clone().serve(server));
        Ok(Box::new(client))
    }
}

impl Connect for Fake {
    fn connect(
        &self,
        host: &str,
        port: u16,
        family: Family,
    ) -> impl Future<Output = io::Result<BoxedStream>> + Send {
        std::future::ready(self.dial(host, port, family))
    }
}

struct RawRequest {
    body: Vec<u8>,
}

/// One HTTP/1.1 request with a `Content-Length` body.
async fn read_request(io: &mut DuplexStream) -> Option<RawRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = io.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut request = httparse::Request::new(&mut headers);
        let httparse::Status::Complete(head) = request.parse(&buf).ok()? else {
            continue;
        };
        let headers: Vec<(String, String)> = request
            .headers
            .iter()
            .map(|h| {
                let value = String::from_utf8_lossy(h.value).into_owned();
                (h.name.to_ascii_lowercase(), value)
            })
            .collect();
        let length: usize = headers
            .iter()
            .find(|(n, _)| n == "content-length")?
            .1
            .parse()
            .ok()?;
        while buf.len() < head + length {
            let n = io.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        return Some(RawRequest {
            body: buf[head..head + length].to_vec(),
        });
    }
}

/// `base64(name):base64(value)\n` pairs, decoded.
fn assoc(text: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let text = std::str::from_utf8(text).unwrap();
    assert!(text.ends_with('\n'), "{text:?}");
    text.lines()
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (B64.decode(name).unwrap(), B64.decode(value).unwrap())
        })
        .collect()
}

fn percent_decode(text: &str) -> String {
    let mut out = Vec::new();
    let mut rest = text.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%' {
            let hex = std::str::from_utf8(&tail[..2]).unwrap();
            out.push(u8::from_str_radix(hex, 16).unwrap());
            rest = &tail[2..];
        } else {
            out.push(byte);
            rest = tail;
        }
    }
    String::from_utf8(out).unwrap()
}

fn encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let aes =
        PaddedBlockEncryptingKey::cbc_pkcs7(UnboundCipherKey::new(&AES_256, key).unwrap()).unwrap();
    let mut data = plaintext.to_vec();
    aes.less_safe_encrypt(&mut data, EncryptionContext::Iv128(FixedLength::from(iv)))
        .unwrap();
    data
}

fn http(status: u16, body: &[u8]) -> Vec<u8> {
    // A 204 has no body and so no length.
    let length = match status {
        204 => String::new(),
        _ => format!("Content-Length: {}\r\n", body.len()),
    };
    let mut out = format!(
        "HTTP/1.1 {status} Fake\r\nContent-Type: text/html\r\n{length}Connection: close\r\n\r\n"
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// The fixture for each `act`.
fn fixtures(seen: &Seen) -> Answer {
    match seen.param("act") {
        Some("user") => Answer::Xml(USER.into()),
        Some("manifest") => Answer::Xml(MANIFEST.into()),
        _ => Answer::Status(400),
    }
}

#[tokio::test]
async fn secrets_stay_out_of_debug_display_and_errors() {
    let credentials = credentials();
    let fake = Fake::new(fixtures);
    let user = fake.client().user(&credentials).await.unwrap();
    let laptop = &user.devices[0];
    for printed in [
        format!("{credentials:?}"),
        format!("{credentials}"),
        format!("{user:?}"),
        format!("{laptop:?}"),
        format!("{:?} {}", laptop.private_key, laptop.private_key),
        format!("{:?} {}", laptop.preshared_key, laptop.preshared_key),
    ] {
        for secret in [
            USERNAME,
            "wörd",
            ALICE_PRIVATE,
            BOB_PRIVATE,
            "ERERERER",
            "IiIiIiIi",
        ] {
            assert!(!printed.contains(secret), "{printed}");
        }
    }
    // Public keys may show.
    assert!(format!("{user:?}").contains(ALICE_PUBLIC));

    // An answer that echoes the credentials cannot put them into an error.
    let fake = Fake::new(|_| {
        Answer::Xml(
            r#"<user error="synthetic-user: wrong password p&#228;+/=&amp;&lt;ss w&#246;rd"/>"#
                .into(),
        )
    });
    let e = fake.client().user(&credentials).await.unwrap_err();
    for printed in [format!("{e:?}"), e.to_string()] {
        assert!(
            !printed.contains(USERNAME) && !printed.contains("wörd"),
            "{printed}"
        );
    }
}
