//! The request line of the manager's relay sockets, shared by the controller and both connectors.
//!
//! The sockets are an Instance generation's private connector and the one-time bootstrap grant
//! (architecture §7); the controller writes the line and both connectors check it before they
//! dial.
//!
//! One JSON line per connection, answered by one JSON line before the relay starts:
//!
//! ```text
//! → {"v":2,"host":"api.mullvad.net","port":443,"family":"v4","nonce":"<32 hex digits>",
//!    "route":{"mode":"instance","instance_id":"…","generation":7},
//!    "expect":{"connector":…,"network":…}}
//! ← {"ok":true,"peer":"203.0.113.5:443","epochs":{"connector":…,"network":…}}
//! ← {"ok":false,"code":"NONCE_REUSED","message":"…","epochs":{…}}
//! ```
//!
//! - `nonce`: 16 random bytes, good for one line. A connector remembers the nonces it has seen
//!   and refuses one it saw before, so no line — and no permit bound into one — can be replayed.
//! - `route`: which relay the line is meant for. A connector refuses a line for another Instance,
//!   another generation, or the bootstrap grant, so a controller still holding an old binding
//!   reaches nothing.
//! - `expect`: present when the line carries a request that a fresh exit check authorized: the
//!   connector's epochs as that check saw them. A connector whose epochs moved since — another
//!   connector behind the path (`connector`), or the tunnel opened again after an outage
//!   (`network`) — refuses before it dials.
//! - `epochs`, in every answer: what a request authorized by this connection's check expects.
//!
//! Version 1 (no nonce, no route) is refused: the controller, the manager and the worker are one
//! build (`vpnd`), so nothing legitimate still speaks it.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use vpn_domain::{InstanceId, Text, tr};
use vpn_sync::Mutex;

/// Version of the request line.
pub const VERSION: u8 = 2;
/// Longest request line a connector reads, its newline included.
pub const LINE_MAX: usize = 1024;
/// Nonces one connector remembers; the oldest is forgotten first.
///
/// Every Provider request is
/// rate limited per origin by the controller, so thousands of lines pass through one generation
/// (or one ten-minute grant) only over a long time — and a nonce is 128 random bits, never
/// legitimately sent twice.
pub const NONCES_REMEMBERED: usize = 4096;

/// The line is not valid JSON of this protocol, or its destination is invalid.
pub const BAD_REQUEST: &str = "BAD_REQUEST";
/// The line is of another version.
pub const BAD_VERSION: &str = "BAD_VERSION";
/// The nonce was seen before.
pub const NONCE_REUSED: &str = "NONCE_REUSED";
/// The line is meant for another relay (Instance, generation, or the bootstrap grant).
pub const WRONG_ROUTE: &str = "WRONG_ROUTE";
/// The connector's epochs moved since the exit check that authorized the request.
pub const EPOCH_CHANGED: &str = "EPOCH_CHANGED";

/// Address family the connector must use, and only that one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayFamily {
    V4,
    V6,
}

/// Which relay a line is meant for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelayRoute {
    /// The private connector of one Instance generation.
    Instance {
        instance_id: InstanceId,
        generation: u64,
    },
    /// The one-time bootstrap grant of the manager.
    Bootstrap,
}

/// A connector's identity and the state of its network path. Reported in every answer; named in
/// `expect` by a request that an exit check over this connector authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayEpochs {
    /// Random per connector (each generation's connector, each grant): another connector behind
    /// the same path has another value.
    pub connector: u64,
    /// Advanced each time the connector's network path opens again: an Instance's payload gate
    /// re-opened after the tunnel was down (sleep, network change, peer silence). Constant for
    /// the bootstrap grant, whose path is the host's network.
    pub network: u64,
}

/// 16 random bytes, written as 32 lowercase hex digits. Good for one line.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce([u8; 16]);

impl Nonce {
    #[must_use]
    pub fn fresh() -> Self {
        Self(rand::random())
    }

    fn parse(text: &str) -> Option<Self> {
        let mut bytes = [0u8; 16];
        let lower = text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        (text.len() == 32 && lower && hex::decode_to_slice(text, &mut bytes).is_ok())
            .then_some(Self(bytes))
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({}…)", hex::encode(&self.0[..2]))
    }
}

impl Serialize for Nonce {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::parse(&text).ok_or_else(|| serde::de::Error::custom("nonce: 32 lowercase hex digits"))
    }
}

/// One request line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayLine {
    pub v: u8,
    pub host: String,
    pub port: u16,
    pub family: RelayFamily,
    pub nonce: Nonce,
    pub route: RelayRoute,
    /// The connector's epochs as the exit check that authorized this request saw them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<RelayEpochs>,
}

impl RelayLine {
    /// A line of this version with a fresh nonce.
    #[must_use]
    pub fn new(host: &str, port: u16, family: RelayFamily, route: RelayRoute) -> Self {
        Self {
            v: VERSION,
            host: host.to_owned(),
            port,
            family,
            nonce: Nonce::fresh(),
            route,
            expect: None,
        }
    }

    /// The bytes to send, newline included.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut line = serde_json::to_vec(self).unwrap_or_default();
        line.push(b'\n');
        line
    }
}

/// The one answer line before the relay starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAnswer {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Why it was refused, for people.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epochs: Option<RelayEpochs>,
}

impl RelayAnswer {
    #[must_use]
    pub fn connected(peer: SocketAddr, epochs: RelayEpochs) -> Self {
        Self {
            ok: true,
            peer: Some(peer.to_string()),
            code: None,
            message: None,
            epochs: Some(epochs),
        }
    }

    pub fn refuse(code: &str, message: impl Into<Text>) -> Self {
        Self {
            ok: false,
            peer: None,
            code: Some(code.to_owned()),
            message: Some(message.into()),
            epochs: None,
        }
    }

    #[must_use]
    pub const fn with_epochs(mut self, epochs: RelayEpochs) -> Self {
        self.epochs = Some(epochs);
        self
    }

    /// The bytes to send, newline included.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut line = serde_json::to_vec(self).unwrap_or_default();
        line.push(b'\n');
        line
    }
}

/// What one connector checks on every line before it dials.
///
/// It checks the version, a well-formed destination, a nonce it has not seen, its own route, and — for a request an exit check
/// authorized — epochs that have not moved since that check.
#[derive(Debug)]
pub struct Admission {
    route: RelayRoute,
    connector: u64,
    seen: Mutex<Seen>,
}

#[derive(Debug, Default)]
struct Seen {
    set: HashSet<Nonce>,
    order: VecDeque<Nonce>,
}

impl Seen {
    /// Whether `nonce` is new; it is remembered from now on.
    fn insert(&mut self, nonce: Nonce) -> bool {
        if !self.set.insert(nonce) {
            return false;
        }
        self.order.push_back(nonce);
        if self.order.len() > NONCES_REMEMBERED
            && let Some(oldest) = self.order.pop_front()
        {
            self.set.remove(&oldest);
        }
        true
    }
}

impl Admission {
    /// The admission of a connector serving `route`, with a fresh connector epoch.
    #[must_use]
    pub fn new(route: RelayRoute) -> Self {
        Self {
            route,
            connector: rand::random(),
            seen: Mutex::default(),
        }
    }

    pub const fn route(&self) -> RelayRoute {
        self.route
    }

    /// The epochs to report while the network path is at `network`.
    pub const fn epochs(&self, network: u64) -> RelayEpochs {
        RelayEpochs {
            connector: self.connector,
            network,
        }
    }

    /// One request line (its newline removed), checked while the network path is at `network`.
    ///
    /// A nonce counts as used from the moment its line is read, whatever happens to the line
    /// next.
    ///
    /// # Errors
    ///
    /// The answer to send instead of dialing: `BAD_VERSION`, `BAD_REQUEST` (malformed line or
    /// invalid destination), `NONCE_REUSED`, `WRONG_ROUTE` or `EPOCH_CHANGED`.
    pub fn admit(&self, line: &str, network: u64) -> Result<RelayLine, RelayAnswer> {
        #[derive(Deserialize)]
        struct Version {
            v: u8,
        }
        let epochs = self.epochs(network);
        let refuse =
            |code: &str, message: Text| RelayAnswer::refuse(code, message).with_epochs(epochs);
        let malformed = || {
            tr!(
                "Malformed request",
                "請求格式錯誤",
                "リクエストの形式が正しくありません"
            )
        };
        // The version first, so a line of another version is told so, not "malformed".
        match serde_json::from_str::<Version>(line) {
            Ok(Version { v: VERSION }) => {}
            Ok(_) => {
                return Err(refuse(
                    BAD_VERSION,
                    tr!(
                        "The request format version does not match (version 2 is needed: a one-time nonce and a route)",
                        "請求格式版本不符（需要第 2 版：帶一次性 nonce 與路徑）",
                        "リクエスト形式のバージョンが一致しません（1 回限りの nonce と経路を含む第 2 版が必要です）"
                    ),
                ));
            }
            Err(_) => return Err(refuse(BAD_REQUEST, malformed())),
        }
        #[expect(
            clippy::map_err_ignore,
            reason = "a malformed line is answered with the fixed `BAD_REQUEST` code and its translated message, like the version check above; the JSON parser's detail is not part of the answer"
        )]
        let request: RelayLine =
            serde_json::from_str(line).map_err(|_| refuse(BAD_REQUEST, malformed()))?;
        if request.port == 0
            || request.host.is_empty()
            || request.host.len() > 253
            || !request.host.is_ascii()
        {
            return Err(refuse(
                BAD_REQUEST,
                tr!("Invalid destination", "目的地無效", "宛先が無効です"),
            ));
        }
        if !self.seen.lock().insert(request.nonce) {
            return Err(refuse(
                NONCE_REUSED,
                tr!(
                    "This request's one-time token was already used, so it is refused as a replay; nothing was connected",
                    "這個請求的一次性憑證已經用過，拒絕重送；未連線",
                    "このリクエストのワンタイムトークンは使用済みのため、再送として拒否しました。接続していません"
                ),
            ));
        }
        if request.route != self.route {
            return Err(refuse(
                WRONG_ROUTE,
                tr!(
                    "This request is not meant for this channel (the connection, generation or first direct connection does not match); nothing was connected",
                    "這個請求不是給這條通道的（連線、世代或首次直連不符），未連線",
                    "このリクエストはこのチャネル宛てではありません（接続、世代、初回の直接接続のいずれかが一致しません）。接続していません"
                ),
            ));
        }
        if let Some(expect) = request.expect
            && expect != epochs
        {
            return Err(refuse(
                EPOCH_CHANGED,
                if expect.connector == epochs.connector {
                    tunnel_reopened()
                } else {
                    tr!(
                        "The channel changed after the exit check; nothing was connected. Try again",
                        "出口檢查之後通道已更換，未連線；請重新操作",
                        "出口チェックの後にチャネルが切り替わったため、接続していません。もう一度操作してください"
                    )
                },
            ));
        }
        Ok(request)
    }

    /// After dialing: whether the network path is still the one `request` was admitted on
    /// (a request an exit check authorized must not ride a path that re-opened meanwhile).
    ///
    /// # Errors
    ///
    /// An `EPOCH_CHANGED` answer when `request` carried expected epochs and the network epoch
    /// moved since.
    pub fn still_valid(&self, request: &RelayLine, network: u64) -> Result<(), RelayAnswer> {
        match request.expect {
            Some(expect) if expect.network != network => {
                Err(RelayAnswer::refuse(EPOCH_CHANGED, tunnel_reopened())
                    .with_epochs(self.epochs(network)))
            }
            _ => Ok(()),
        }
    }
}

/// `EPOCH_CHANGED`: the tunnel went down and came back after the exit check.
fn tunnel_reopened() -> Text {
    tr!(
        "The tunnel went down and came back after the exit check; nothing was connected. Try again",
        "出口檢查之後 tunnel 曾中斷並重新開通，未連線；請重新操作",
        "出口チェックの後にトンネルが切断されて再開通したため、接続していません。もう一度操作してください"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance() -> RelayRoute {
        RelayRoute::Instance {
            instance_id: InstanceId::new(),
            generation: 3,
        }
    }

    fn line(route: RelayRoute) -> RelayLine {
        RelayLine::new("api.mullvad.net", 443, RelayFamily::V4, route)
    }

    fn text(l: &RelayLine) -> String {
        String::from_utf8(l.to_bytes())
            .unwrap()
            .trim_end()
            .to_owned()
    }

    fn code(r: Result<RelayLine, RelayAnswer>) -> String {
        r.expect_err("refused").code.unwrap()
    }

    #[test]
    fn a_line_is_admitted_once() {
        let route = instance();
        let a = Admission::new(route);
        let l = line(route);
        assert_eq!(a.admit(&text(&l), 1).unwrap(), l);
        assert_eq!(code(a.admit(&text(&l), 1)), NONCE_REUSED);
        // A fresh nonce for the same request is fine.
        assert!(a.admit(&text(&line(route)), 1).is_ok());
    }

    #[test]
    fn a_line_for_another_route_is_refused() {
        let route = instance();
        let a = Admission::new(route);
        let RelayRoute::Instance { instance_id, .. } = route else {
            unreachable!()
        };
        let older = RelayRoute::Instance {
            instance_id,
            generation: 2,
        };
        assert_eq!(code(a.admit(&text(&line(older)), 1)), WRONG_ROUTE);
        assert_eq!(code(a.admit(&text(&line(instance())), 1)), WRONG_ROUTE);
        assert_eq!(
            code(a.admit(&text(&line(RelayRoute::Bootstrap)), 1)),
            WRONG_ROUTE
        );
        let b = Admission::new(RelayRoute::Bootstrap);
        assert_eq!(code(b.admit(&text(&line(route)), 0)), WRONG_ROUTE);
        assert!(b.admit(&text(&line(RelayRoute::Bootstrap)), 0).is_ok());
    }

    #[test]
    fn moved_epochs_refuse_an_authorized_request_only() {
        let route = instance();
        let a = Admission::new(route);
        let seen = a.epochs(4);
        let mut l = line(route);
        l.expect = Some(seen);
        assert!(a.admit(&text(&l), 4).is_ok());
        // The tunnel re-opened after the check.
        let mut l = line(route);
        l.expect = Some(seen);
        let r = a.admit(&text(&l), 5).expect_err("refused");
        assert_eq!(r.code.as_deref(), Some(EPOCH_CHANGED));
        assert_eq!(
            r.epochs,
            Some(a.epochs(5)),
            "the answer names the new epochs"
        );
        // Another connector behind the same path.
        let other = Admission::new(route);
        let mut l = line(route);
        l.expect = Some(seen);
        assert_eq!(code(other.admit(&text(&l), 4)), EPOCH_CHANGED);
        // A probe (no expectation) is admitted whatever the epochs.
        assert!(a.admit(&text(&line(route)), 9).is_ok());
        // Re-checked after dialing.
        let mut l = line(route);
        l.expect = Some(a.epochs(6));
        assert!(a.still_valid(&l, 6).is_ok());
        assert_eq!(
            a.still_valid(&l, 7).unwrap_err().code.as_deref(),
            Some(EPOCH_CHANGED)
        );
    }

    #[test]
    fn version_one_and_malformed_lines_are_refused() {
        let a = Admission::new(RelayRoute::Bootstrap);
        let v1 = r#"{"v":1,"host":"api.mullvad.net","port":443,"family":"v4"}"#;
        assert_eq!(code(a.admit(v1, 0)), BAD_VERSION);
        assert_eq!(code(a.admit("not json", 0)), BAD_REQUEST);
        let mut l = line(RelayRoute::Bootstrap);
        l.port = 0;
        assert_eq!(code(a.admit(&text(&l), 0)), BAD_REQUEST);
        let upper = text(&line(RelayRoute::Bootstrap)).replace("\"nonce\":\"", "\"nonce\":\"A");
        assert_eq!(code(a.admit(&upper, 0)), BAD_REQUEST);
        let extra = text(&line(RelayRoute::Bootstrap)).replace("{\"v\":2,", "{\"v\":2,\"x\":1,");
        assert_eq!(code(a.admit(&extra, 0)), BAD_REQUEST);
        assert!(text(&line(RelayRoute::Bootstrap)).len() < LINE_MAX / 2);
    }
}
