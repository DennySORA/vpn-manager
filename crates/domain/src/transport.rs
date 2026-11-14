//! Transport profiles: how the flows of a connection are sized and timed, and how its health is
//! probed.
//!
//! A connection uses one profile: one that is part of the program ([`builtin_transports`]) or
//! one the user saved ([`TransportProfile`]). A profile is either one fixed set of values or
//! automatic: it names a profile for each range of the round trip measured through the tunnel,
//! and new flows take the values of the range the connection is in. Nothing here needs a
//! restart: a running connection applies a change to the flows it opens from then on.
//!
//! The TCP buffer sizes are what a connection opens with and what it may grow to: a buffer
//! grows only while its connection really uses it and the buffer budget has room, so a large
//! upper size costs nothing for the connections that stay small. A connection in Linux strict
//! mode leaves the sizing to the kernel; there the upper sizes only raise the kernel's own
//! limits, never lower them.

use std::ops::RangeInclusive;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::config::EntityMeta;
use crate::ids::TransportProfileId;
use crate::text::Text;
use crate::tr;
use crate::validation::{ValidationReport, check_name};

/// Key of the built-in profile every connection uses until another is chosen.
pub const AUTO_TRANSPORT: &str = "auto";

/// Each TCP buffer of a connection, KiB (the opening and the upper size).
pub const TCP_BUFFER_KIB: RangeInclusive<u32> = 16..=16_384;
/// Each direction of a UDP flow, KiB.
pub const UDP_BUFFER_KIB: RangeInclusive<u32> = 16..=4_096;
/// Delayed ACK, milliseconds (0: every segment is acknowledged at once).
pub const ACK_DELAY_MS: RangeInclusive<u32> = 0..=500;
pub const CONNECT_TIMEOUT_SECS: RangeInclusive<u32> = 3..=120;
pub const KEEPALIVE_SECS: RangeInclusive<u32> = 10..=3_600;
pub const DEAD_PEER_SECS: RangeInclusive<u32> = 30..=7_200;
pub const PROBE_INTERVAL_SECS: RangeInclusive<u32> = 5..=600;
pub const PROBE_FAILURES: RangeInclusive<u32> = 1..=10;
pub const HANDSHAKE_TIMEOUT_SECS: RangeInclusive<u32> = 3..=120;
/// Ranges of an automatic profile.
pub const AUTO_BANDS: RangeInclusive<usize> = 1..=6;
/// The longest round trip an automatic profile's range may start at, milliseconds.
pub const AUTO_RTT_MAX_MS: u32 = 10_000;

/// TCP congestion control of a connection's own flows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum CongestionControl {
    #[default]
    Cubic,
    Reno,
    /// Goes by the rate the path delivers instead of backing off at every lost packet: on a long
    /// path that loses a packet now and then, Cubic and Reno fall to a fraction of what the path
    /// carries. Only the kernel has it: a strict connection's own flows use it where the kernel
    /// offers it to unprivileged programs (`net.ipv4.tcp_allowed_congestion_control`), and
    /// everything else — the userspace stack included — uses Cubic.
    Bbr,
}

/// What each new flow of a connection gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FlowSettings {
    /// The size the receive buffer of a TCP connection may grow to, KiB: with the round trip,
    /// the ceiling of one connection's download.
    pub tcp_recv_kib: u32,
    /// The size it opens with, KiB; at most `tcp_recv_kib`.
    pub tcp_recv_start_kib: u32,
    /// The size the send buffer of a TCP connection may grow to, KiB: the ceiling of one
    /// connection's upload.
    pub tcp_send_kib: u32,
    /// The size it opens with, KiB; at most `tcp_send_kib`.
    pub tcp_send_start_kib: u32,
    pub congestion: CongestionControl,
    /// Collect small writes into full segments (Nagle's algorithm).
    pub nagle: bool,
    /// How long an acknowledgement may wait for data to ride on, milliseconds; 0 sends it at
    /// once.
    pub ack_delay_ms: u32,
    /// How long a TCP connection may take to be established.
    pub connect_timeout_secs: u32,
    /// Keep-alive probe interval of an idle TCP connection.
    pub keepalive_secs: u32,
    /// A TCP connection whose remote end sent nothing for this long is ended; at least twice
    /// `keepalive_secs`.
    pub dead_peer_secs: u32,
    /// Each direction of a UDP flow, KiB.
    pub udp_buffer_kib: u32,
}

impl FlowSettings {
    /// The values every connection had before transport profiles existed.
    pub const BALANCED: Self = Self {
        tcp_recv_kib: 512,
        tcp_recv_start_kib: 512,
        tcp_send_kib: 256,
        tcp_send_start_kib: 256,
        congestion: CongestionControl::Cubic,
        nagle: false,
        ack_delay_ms: 10,
        connect_timeout_secs: 15,
        keepalive_secs: 60,
        dead_peer_secs: 300,
        udp_buffer_kib: 64,
    };

    /// Buffer memory a TCP connection reserves when it opens, bytes.
    #[must_use]
    pub fn tcp_start_bytes(&self) -> u64 {
        let recv = self.tcp_recv_start_kib.min(self.tcp_recv_kib);
        let send = self.tcp_send_start_kib.min(self.tcp_send_kib);
        (u64::from(recv) + u64::from(send)) * 1024
    }

    /// Buffer memory a UDP flow reserves, bytes (both directions).
    #[must_use]
    pub fn udp_bytes(&self) -> u64 {
        u64::from(self.udp_buffer_kib) * 2 * 1024
    }
}

/// How a connection's health is probed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct HealthSettings {
    /// Seconds between the probes of a healthy connection.
    pub probe_interval_secs: u32,
    /// Failed probes in a row before the connection stops taking new flows.
    pub probe_failures: u32,
    /// How long the first `WireGuard` handshake of a start may take.
    pub handshake_timeout_secs: u32,
}

impl HealthSettings {
    /// The values every connection had before transport profiles existed.
    pub const DEFAULT: Self = Self {
        probe_interval_secs: 30,
        probe_failures: 2,
        handshake_timeout_secs: 15,
    };
}

/// A transport profile, by where it lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[ts(export)]
pub enum TransportRef {
    /// One that is part of the program, by its key ([`builtin_transports`]).
    Builtin { key: String },
    /// One the user saved.
    Profile { id: TransportProfileId },
}

impl Default for TransportRef {
    fn default() -> Self {
        Self::Builtin {
            key: AUTO_TRANSPORT.into(),
        }
    }
}

/// One range of an automatic profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AutoBand {
    /// The range starts at this round trip, milliseconds; the first at 0.
    pub from_rtt_ms: u32,
    /// The fixed profile whose values the flows of this range take.
    pub profile: TransportRef,
}

/// What a profile holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[ts(export)]
pub enum TransportSettings {
    /// One set of values, whatever is measured.
    Fixed { flow: FlowSettings },
    /// A fixed profile for each range of the measured round trip, ascending.
    Auto { bands: Vec<AutoBand> },
}

/// A transport profile the user saved; any number of connections may use it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TransportProfile {
    pub id: TransportProfileId,
    #[serde(flatten)]
    pub meta: EntityMeta,
    pub name: String,
    /// An automatic profile probes with its own values, not those of the profiles it names.
    pub health: HealthSettings,
    pub settings: TransportSettings,
}

/// A transport profile that is part of the program (`GET /v1/transport-profiles/builtin`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BuiltinTransport {
    pub key: String,
    pub name: Text,
    /// What it is for, in one sentence.
    pub summary: Text,
    pub health: HealthSettings,
    pub settings: TransportSettings,
}

/// A built-in fixed profile: `BALANCED` with what differs. Its words are written when the
/// catalog is read.
struct Preset {
    key: &'static str,
    name: fn() -> Text,
    summary: fn() -> Text,
    health: HealthSettings,
    flow: FlowSettings,
}

const BALANCED_KEY: &str = "balanced";
const LONG_HAUL_KEY: &str = "long_haul";
const ULTRA_LONG_KEY: &str = "ultra_long";

/// The built-in automatic profile: the round trip (ms) each of its ranges starts at.
const AUTO_RANGES: [(u32, &str); 3] = [
    (0, BALANCED_KEY),
    (40, LONG_HAUL_KEY),
    (150, ULTRA_LONG_KEY),
];

const PRESETS: [Preset; 6] = [
    Preset {
        key: BALANCED_KEY,
        name: || tr!("Balanced", "平衡", "バランス"),
        summary: || {
            tr!(
                "Everyday browsing over a short single hop. Each connection keeps a fixed 256 KiB for sending and 512 KiB for receiving, as before transport profiles existed.",
                "一般上網、近距離單跳。每條連線固定送 256 KiB、收 512 KiB，與加入傳輸設定之前相同。",
                "一般的な Web 閲覧、近距離のシングルホップ向け。各接続は送信 256 KiB、受信 512 KiB で固定され、トランスポート設定が導入される前と同じです。"
            )
        },
        health: HealthSettings::DEFAULT,
        flow: FlowSettings::BALANCED,
    },
    Preset {
        key: LONG_HAUL_KEY,
        name: || {
            tr!(
                "Long haul / multi-hop",
                "長距離／多跳",
                "長距離／マルチホップ"
            )
        },
        summary: || {
            tr!(
                "Across continents or several hops, with a round trip of about 40–150 ms. A fast connection's buffers can grow to 1 MiB for sending and 2 MiB for receiving; a strictly isolated connection uses BBR where the kernel supports it.",
                "跨洲或多跳，往返約 40–150 毫秒。傳得快的連線緩衝可放大到送 1 MiB、收 2 MiB；嚴格隔離的連線在核心支援時用 BBR。",
                "大陸間やマルチホップで、往復が約 40–150 ミリ秒の場合。速い接続のバッファーは送信 1 MiB、受信 2 MiB まで拡大できます。厳格な分離の接続は、カーネルが対応していれば BBR を使います。"
            )
        },
        health: HealthSettings {
            handshake_timeout_secs: 20,
            ..HealthSettings::DEFAULT
        },
        flow: FlowSettings {
            tcp_recv_kib: 2_048,
            tcp_send_kib: 1_024,
            congestion: CongestionControl::Bbr,
            connect_timeout_secs: 20,
            ..FlowSettings::BALANCED
        },
    },
    Preset {
        key: ULTRA_LONG_KEY,
        name: || {
            tr!(
                "Ultra long haul / double VPN",
                "超長距離／雙層 VPN",
                "超長距離／二重 VPN"
            )
        },
        summary: || {
            tr!(
                "Double VPN, satellite, or a round trip of 150 ms or more. Buffers can grow to 8 MiB for sending and 16 MiB for receiving, and timeouts and health probes are relaxed; a strictly isolated connection uses BBR where the kernel supports it.",
                "雙層 VPN、衛星或往返 150 毫秒以上。緩衝可放大到送 8 MiB、收 16 MiB，逾時與健康探測也放寬；嚴格隔離的連線在核心支援時用 BBR。",
                "二重 VPN、衛星回線、または往復 150 ミリ秒以上の場合。バッファーは送信 8 MiB、受信 16 MiB まで拡大でき、タイムアウトとヘルスチェックも緩めます。厳格な分離の接続は、カーネルが対応していれば BBR を使います。"
            )
        },
        health: HealthSettings {
            probe_failures: 3,
            handshake_timeout_secs: 30,
            ..HealthSettings::DEFAULT
        },
        flow: FlowSettings {
            tcp_recv_kib: 16_384,
            tcp_send_kib: 8_192,
            congestion: CongestionControl::Bbr,
            connect_timeout_secs: 30,
            dead_peer_secs: 600,
            ..FlowSettings::BALANCED
        },
    },
    Preset {
        key: "many_flows",
        name: || tr!("Many connections", "大量連線", "大量の接続"),
        summary: || {
            tr!(
                "P2P, crawlers and other programs that open many connections at once. Each connection uses only 64 KiB for sending and 128 KiB for receiving, so the same connection buffer holds about four times as many connections.",
                "P2P、爬蟲等同時開很多連線。每條連線只用送 64 KiB、收 128 KiB，同樣的連線緩衝能容納約四倍的連線。",
                "P2P やクローラーなど、多数の接続を同時に開く用途向け。各接続は送信 64 KiB、受信 128 KiB だけを使うため、同じ接続バッファーで約 4 倍の接続を収容できます。"
            )
        },
        health: HealthSettings::DEFAULT,
        flow: FlowSettings {
            tcp_recv_kib: 128,
            tcp_recv_start_kib: 128,
            tcp_send_kib: 64,
            tcp_send_start_kib: 64,
            keepalive_secs: 120,
            dead_peer_secs: 600,
            udp_buffer_kib: 32,
            ..FlowSettings::BALANCED
        },
    },
    Preset {
        key: "low_memory",
        name: || tr!("Low memory", "省記憶體", "省メモリ"),
        summary: || {
            tr!(
                "Hosts with very little memory. Each connection uses 32 KiB for sending and 64 KiB for receiving, and the UDP buffer is 16 KiB.",
                "記憶體很小的主機。每條連線送 32 KiB、收 64 KiB，UDP 緩衝 16 KiB。",
                "メモリがとても少ないホスト向け。各接続は送信 32 KiB、受信 64 KiB、UDP バッファーは 16 KiB です。"
            )
        },
        health: HealthSettings::DEFAULT,
        flow: FlowSettings {
            tcp_recv_kib: 64,
            tcp_recv_start_kib: 64,
            tcp_send_kib: 32,
            tcp_send_start_kib: 32,
            keepalive_secs: 120,
            dead_peer_secs: 600,
            udp_buffer_kib: 16,
            ..FlowSettings::BALANCED
        },
    },
    Preset {
        key: "unstable",
        name: || tr!("Unstable line", "不穩定線路", "不安定な回線"),
        summary: || {
            tr!(
                "Mobile networks or lines that often lose packets. The connect timeout, the no-response timeout and the health probe are relaxed, so a brief outage does not mark a connection as failed; a strictly isolated connection uses BBR where the kernel supports it.",
                "行動網路或常掉包的線路。連線逾時、無回應中止與健康探測都放寬，短暫中斷不會讓連線被判定失效；嚴格隔離的連線在核心支援時用 BBR。",
                "モバイル回線やパケットロスの多い回線向け。接続タイムアウト、無応答タイムアウト、ヘルスチェックをすべて緩めるため、短い中断で接続が失敗と判定されることはありません。厳格な分離の接続は、カーネルが対応していれば BBR を使います。"
            )
        },
        health: HealthSettings {
            probe_interval_secs: 20,
            probe_failures: 4,
            handshake_timeout_secs: 30,
        },
        flow: FlowSettings {
            congestion: CongestionControl::Bbr,
            connect_timeout_secs: 30,
            keepalive_secs: 30,
            dead_peer_secs: 600,
            ..FlowSettings::BALANCED
        },
    },
];

/// The profiles that are part of the program: the automatic one first, then the fixed ones.
#[must_use]
pub fn builtin_transports() -> Vec<BuiltinTransport> {
    let auto = BuiltinTransport {
        key: AUTO_TRANSPORT.into(),
        name: tr!("Automatic", "自動", "自動"),
        summary: tr!(
            "Switches between “Balanced”, “Long haul / multi-hop” and “Ultra long haul / double VPN” by the measured round-trip time; a connection's buffers grow only when it really is fast.",
            "依量到的往返時間，在「平衡」「長距離／多跳」「超長距離／雙層 VPN」之間切換；每條連線的緩衝只在它真的傳得快時才放大。",
            "測定した往復時間に応じて「バランス」「長距離／マルチホップ」「超長距離／二重 VPN」を切り替えます。各接続のバッファーは、実際に高速なときだけ拡大します。"
        ),
        health: HealthSettings::DEFAULT,
        settings: TransportSettings::Auto {
            bands: AUTO_RANGES
                .iter()
                .map(|(from_rtt_ms, key)| AutoBand {
                    from_rtt_ms: *from_rtt_ms,
                    profile: TransportRef::Builtin { key: (*key).into() },
                })
                .collect(),
        },
    };
    std::iter::once(auto)
        .chain(PRESETS.iter().map(|p| BuiltinTransport {
            key: p.key.into(),
            name: (p.name)(),
            summary: (p.summary)(),
            health: p.health,
            settings: TransportSettings::Fixed { flow: p.flow },
        }))
        .collect()
}

/// The built-in profile of `key`.
#[must_use]
pub fn builtin_transport(key: &str) -> Option<BuiltinTransport> {
    builtin_transports().into_iter().find(|b| b.key == key)
}

/// One range of a connection's transport, with the values its flows take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ResolvedBand {
    pub from_rtt_ms: u32,
    /// Name of the fixed profile the values come from.
    pub name: Text,
    pub flow: FlowSettings,
}

/// A connection's transport with every reference followed: what its worker runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ResolvedTransport {
    /// Name of the profile the connection uses.
    pub name: Text,
    pub automatic: bool,
    pub health: HealthSettings,
    /// One for a fixed profile; an automatic profile's ranges, ascending.
    pub bands: Vec<ResolvedBand>,
}

impl ResolvedTransport {
    /// Buffer memory a new TCP connection reserves, bytes: the largest of the ranges, so the
    /// number of connections a buffer budget holds is never overstated.
    #[must_use]
    pub fn tcp_start_bytes(&self) -> u64 {
        self.bands
            .iter()
            .map(|b| b.flow.tcp_start_bytes())
            .max()
            .unwrap_or_else(|| FlowSettings::BALANCED.tcp_start_bytes())
    }

    /// Buffer memory a UDP flow reserves, bytes: the largest of the ranges.
    #[must_use]
    pub fn udp_bytes(&self) -> u64 {
        self.bands
            .iter()
            .map(|b| b.flow.udp_bytes())
            .max()
            .unwrap_or_else(|| FlowSettings::BALANCED.udp_bytes())
    }

    /// The largest sizes any range lets a TCP buffer reach, KiB: `(receive, send)`.
    #[must_use]
    pub fn tcp_ceilings_kib(&self) -> (u32, u32) {
        let recv = self.bands.iter().map(|b| b.flow.tcp_recv_kib).max();
        let send = self.bands.iter().map(|b| b.flow.tcp_send_kib).max();
        (
            recv.unwrap_or(FlowSettings::BALANCED.tcp_recv_kib),
            send.unwrap_or(FlowSettings::BALANCED.tcp_send_kib),
        )
    }
}

/// Why a transport reference cannot be followed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// No built-in profile has this key.
    UnknownBuiltin(String),
    /// The saved profile does not exist (any more).
    Missing,
    /// A range of the automatic profile `0` names another automatic profile.
    NestedAuto(Text),
}

impl TransportError {
    /// What to tell the user.
    #[must_use]
    pub fn message(&self) -> Text {
        match self {
            Self::UnknownBuiltin(key) => tr!(
                "There is no built-in transport profile named “{key}”",
                "沒有名為「{key}」的內建傳輸設定",
                "「{key}」という組み込みのトランスポート設定はありません"
            ),
            Self::Missing => tr!(
                "The chosen transport profile does not exist",
                "選用的傳輸設定不存在",
                "選択したトランスポート設定は存在しません"
            ),
            Self::NestedAuto(name) => tr!(
                "Each range of the automatic transport profile “{name}” can only use a fixed profile",
                "自動傳輸設定「{name}」的每個區間只能選用固定的傳輸設定",
                "自動トランスポート設定「{name}」の各範囲には固定の設定しか選べません";
                name = name.clone()
            ),
        }
    }
}

/// A profile as it is used, wherever it lives.
struct Found {
    name: Text,
    health: HealthSettings,
    settings: TransportSettings,
}

fn find(reference: &TransportRef, saved: &[TransportProfile]) -> Result<Found, TransportError> {
    match reference {
        TransportRef::Builtin { key } => builtin_transport(key)
            .map(|b| Found {
                name: b.name,
                health: b.health,
                settings: b.settings,
            })
            .ok_or_else(|| TransportError::UnknownBuiltin(key.clone())),
        TransportRef::Profile { id } => saved
            .iter()
            .find(|p| p.id == *id)
            .map(|p| Found {
                name: Text::verbatim(p.name.clone()),
                health: p.health,
                settings: p.settings.clone(),
            })
            .ok_or(TransportError::Missing),
    }
}

/// Follow `choice` through the built-in profiles and the `saved` ones.
///
/// # Errors
///
/// [`TransportError`] when the profile, or one an automatic profile names, does not exist, or
/// when an automatic profile names another automatic one.
pub fn resolve_transport(
    choice: &TransportRef,
    saved: &[TransportProfile],
) -> Result<ResolvedTransport, TransportError> {
    let chosen = find(choice, saved)?;
    let (automatic, bands) = match chosen.settings {
        TransportSettings::Fixed { flow } => (
            false,
            vec![ResolvedBand {
                from_rtt_ms: 0,
                name: chosen.name.clone(),
                flow,
            }],
        ),
        TransportSettings::Auto { bands } => {
            let mut resolved = Vec::with_capacity(bands.len());
            for band in &bands {
                let used = find(&band.profile, saved)?;
                let TransportSettings::Fixed { flow } = used.settings else {
                    return Err(TransportError::NestedAuto(chosen.name));
                };
                resolved.push(ResolvedBand {
                    from_rtt_ms: band.from_rtt_ms,
                    name: used.name,
                    flow,
                });
            }
            (true, resolved)
        }
    };
    Ok(ResolvedTransport {
        name: chosen.name,
        automatic,
        health: chosen.health,
        bands,
    })
}

/// `what` names the value, as a label (“Connect timeout (s)”).
fn out_of(
    r: &mut ValidationReport,
    range: &RangeInclusive<u32>,
    value: u32,
    path: &str,
    what: Text,
) {
    if !range.contains(&value) {
        let (min, max) = (range.start(), range.end());
        r.error(
            "TRANSPORT_RANGE",
            path,
            tr!(
                "{what} must be between {min} and {max}",
                "{what}必須介於 {min} 與 {max}",
                "{what}は {min} から {max} の間にしてください";
                what = what
            ),
        );
    }
}

/// Bounds of a fixed profile's values (paths below `base`).
pub fn check_flow_settings(r: &mut ValidationReport, base: &str, f: &FlowSettings) {
    check_buffers(r, base, f);
    let at = |field: &str| format!("{base}/{field}");
    out_of(
        r,
        &ACK_DELAY_MS,
        f.ack_delay_ms,
        &at("ack_delay_ms"),
        tr!("Delayed ACK (ms)", "延遲 ACK（毫秒）", "遅延 ACK（ミリ秒）"),
    );
    out_of(
        r,
        &CONNECT_TIMEOUT_SECS,
        f.connect_timeout_secs,
        &at("connect_timeout_secs"),
        tr!(
            "Connect timeout (seconds)",
            "連線逾時（秒）",
            "接続タイムアウト（秒）"
        ),
    );
    out_of(
        r,
        &KEEPALIVE_SECS,
        f.keepalive_secs,
        &at("keepalive_secs"),
        tr!(
            "Keepalive interval (seconds)",
            "keepalive 間隔（秒）",
            "keepalive 間隔（秒）"
        ),
    );
    out_of(
        r,
        &DEAD_PEER_SECS,
        f.dead_peer_secs,
        &at("dead_peer_secs"),
        tr!(
            "No-response timeout (seconds)",
            "無回應中止時間（秒）",
            "無応答タイムアウト（秒）"
        ),
    );
    if f.dead_peer_secs < f.keepalive_secs.saturating_mul(2) {
        r.error(
            "TRANSPORT_DEAD_PEER",
            &at("dead_peer_secs"),
            tr!(
                "The no-response timeout must be at least twice the keepalive interval, or ordinary idle connections are cut",
                "無回應中止時間至少要是 keepalive 間隔的兩倍，否則正常的閒置連線會被中止",
                "無応答タイムアウトはキープアライブ間隔の 2 倍以上にしてください。そうしないと、通常のアイドル状態の接続が切断されます"
            ),
        );
    }
}

/// Bounds of a fixed profile's buffers (paths below `base`).
fn check_buffers(r: &mut ValidationReport, base: &str, f: &FlowSettings) {
    let at = |field: &str| format!("{base}/{field}");
    for (value, field, what) in [
        (
            f.tcp_recv_kib,
            "tcp_recv_kib",
            tr!(
                "Receive buffer limit (KiB)",
                "接收緩衝上限（KiB）",
                "受信バッファーの上限（KiB）"
            ),
        ),
        (
            f.tcp_recv_start_kib,
            "tcp_recv_start_kib",
            tr!(
                "Initial receive buffer (KiB)",
                "接收緩衝起始（KiB）",
                "受信バッファーの初期サイズ（KiB）"
            ),
        ),
        (
            f.tcp_send_kib,
            "tcp_send_kib",
            tr!(
                "Send buffer limit (KiB)",
                "送出緩衝上限（KiB）",
                "送信バッファーの上限（KiB）"
            ),
        ),
        (
            f.tcp_send_start_kib,
            "tcp_send_start_kib",
            tr!(
                "Initial send buffer (KiB)",
                "送出緩衝起始（KiB）",
                "送信バッファーの初期サイズ（KiB）"
            ),
        ),
    ] {
        out_of(r, &TCP_BUFFER_KIB, value, &at(field), what);
    }
    if f.tcp_recv_start_kib > f.tcp_recv_kib {
        r.error(
            "TRANSPORT_START",
            &at("tcp_recv_start_kib"),
            tr!(
                "The initial receive buffer cannot be larger than its limit",
                "接收緩衝的起始大小不能超過上限",
                "受信バッファーの初期サイズは上限を超えられません"
            ),
        );
    }
    if f.tcp_send_start_kib > f.tcp_send_kib {
        r.error(
            "TRANSPORT_START",
            &at("tcp_send_start_kib"),
            tr!(
                "The initial send buffer cannot be larger than its limit",
                "送出緩衝的起始大小不能超過上限",
                "送信バッファーの初期サイズは上限を超えられません"
            ),
        );
    }
    out_of(
        r,
        &UDP_BUFFER_KIB,
        f.udp_buffer_kib,
        &at("udp_buffer_kib"),
        tr!(
            "UDP buffer (KiB)",
            "UDP 緩衝（KiB）",
            "UDP バッファー（KiB）"
        ),
    );
}

/// Bounds of a profile's health probing (paths below `/health`).
pub fn check_health_settings(r: &mut ValidationReport, h: &HealthSettings) {
    out_of(
        r,
        &PROBE_INTERVAL_SECS,
        h.probe_interval_secs,
        "/health/probe_interval_secs",
        tr!(
            "Health probe interval (seconds)",
            "健康探測間隔（秒）",
            "ヘルスチェックの間隔（秒）"
        ),
    );
    out_of(
        r,
        &PROBE_FAILURES,
        h.probe_failures,
        "/health/probe_failures",
        tr!("Consecutive failures", "連續失敗次數", "連続失敗回数"),
    );
    out_of(
        r,
        &HANDSHAKE_TIMEOUT_SECS,
        h.handshake_timeout_secs,
        "/health/handshake_timeout_secs",
        tr!(
            "Handshake timeout (seconds)",
            "握手逾時（秒）",
            "ハンドシェイクのタイムアウト（秒）"
        ),
    );
}

/// A reference that needs no stored data to judge: a built-in key must exist. Whether a saved
/// profile exists is the store's check.
pub fn check_transport_ref(r: &mut ValidationReport, path: &str, reference: &TransportRef) {
    if let TransportRef::Builtin { key } = reference
        && builtin_transport(key).is_none()
    {
        r.error(
            "TRANSPORT_UNKNOWN",
            path,
            TransportError::UnknownBuiltin(key.clone()).message(),
        );
    }
}

fn check_auto_bands(r: &mut ValidationReport, bands: &[AutoBand]) {
    if !AUTO_BANDS.contains(&bands.len()) {
        let (min, max) = (AUTO_BANDS.start(), AUTO_BANDS.end());
        r.error(
            "TRANSPORT_BANDS",
            "/settings/bands",
            tr!(
                "An automatic profile needs {min} to {max} ranges",
                "自動設定需要 {min} 到 {max} 個區間",
                "自動設定には {min}〜{max} 個の区間が必要です"
            ),
        );
        return;
    }
    let mut previous = None;
    for (i, band) in bands.iter().enumerate() {
        let path = format!("/settings/bands/{i}");
        let from = band.from_rtt_ms;
        match previous {
            None if from != 0 => r.error(
                "TRANSPORT_BAND_START",
                &format!("{path}/from_rtt_ms"),
                tr!(
                    "The first range must start at 0 ms",
                    "第一個區間必須從 0 毫秒開始",
                    "最初の区間は 0 ミリ秒から始める必要があります"
                ),
            ),
            Some(last) if from <= last => r.error(
                "TRANSPORT_BAND_ORDER",
                &format!("{path}/from_rtt_ms"),
                tr!(
                    "Each range must start after the previous one",
                    "每個區間的起點必須大於前一個區間",
                    "各区間の開始点は前の区間より大きくしてください"
                ),
            ),
            _ if from > AUTO_RTT_MAX_MS => r.error(
                "TRANSPORT_BAND_START",
                &format!("{path}/from_rtt_ms"),
                tr!(
                    "A range starts at {AUTO_RTT_MAX_MS} ms at most",
                    "區間的起點最多 {AUTO_RTT_MAX_MS} 毫秒",
                    "区間の開始点は最大 {AUTO_RTT_MAX_MS} ミリ秒です"
                ),
            ),
            _ => {}
        }
        previous = Some(from);
        let reference = format!("{path}/profile");
        check_transport_ref(r, &reference, &band.profile);
        if let TransportRef::Builtin { key } = &band.profile
            && matches!(
                builtin_transport(key).map(|b| b.settings),
                Some(TransportSettings::Auto { .. })
            )
        {
            r.error(
                "TRANSPORT_NESTED",
                &reference,
                tr!(
                    "A range can use only a fixed transport profile, not an automatic one",
                    "區間只能選用固定的傳輸設定，不能選用自動",
                    "区間には固定のトランスポート設定しか選べず、自動は選べません"
                ),
            );
        }
    }
}

/// A saved transport profile. Whether the saved profiles its ranges name exist and are fixed
/// is checked where the stored profiles are at hand.
#[must_use]
pub fn check_transport_profile(p: &TransportProfile) -> ValidationReport {
    let mut r = ValidationReport::default();
    check_name(&mut r, "/name", &p.name);
    check_health_settings(&mut r, &p.health);
    match &p.settings {
        TransportSettings::Fixed { flow } => check_flow_settings(&mut r, "/settings/flow", flow),
        TransportSettings::Auto { bands } => {
            check_auto_bands(&mut r, bands);
            for (i, band) in bands.iter().enumerate() {
                if band.profile == (TransportRef::Profile { id: p.id }) {
                    r.error(
                        "TRANSPORT_NESTED",
                        &format!("/settings/bands/{i}/profile"),
                        tr!(
                            "A range cannot use this profile itself",
                            "區間不能選用這個設定自己",
                            "区間でこの設定自体を選ぶことはできません"
                        ),
                    );
                }
            }
        }
    }
    r.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved(settings: TransportSettings) -> TransportProfile {
        TransportProfile {
            id: TransportProfileId::new(),
            meta: EntityMeta {
                revision: 1,
                created_at: crate::Timestamp::now(),
                updated_at: crate::Timestamp::now(),
            },
            name: "測試".into(),
            health: HealthSettings::DEFAULT,
            settings,
        }
    }

    fn band(from_rtt_ms: u32, profile: TransportRef) -> AutoBand {
        AutoBand {
            from_rtt_ms,
            profile,
        }
    }

    fn builtin(key: &str) -> TransportRef {
        TransportRef::Builtin { key: key.into() }
    }

    /// The buffer sizes become allocations in every worker: nothing outside the bounds may be
    /// stored, and every built-in profile is within them.
    #[test]
    fn values_outside_the_bounds_are_refused() {
        for b in builtin_transports() {
            let resolved = resolve_transport(&builtin(&b.key), &[]).expect("a built-in resolves");
            assert!(!resolved.bands.is_empty(), "{}", b.key);
            for range in &resolved.bands {
                let mut r = ValidationReport::default();
                check_flow_settings(&mut r, "/settings/flow", &range.flow);
                assert!(!r.has_errors(), "{}: {:?}", b.key, r.issues);
            }
        }
        let ok = FlowSettings::BALANCED;
        let cases = [
            (ok, true),
            (
                FlowSettings {
                    tcp_recv_kib: 16_384,
                    ..ok
                },
                true,
            ),
            (
                FlowSettings {
                    tcp_recv_kib: 16_385,
                    ..ok
                },
                false,
            ),
            (
                FlowSettings {
                    tcp_send_kib: u32::MAX,
                    ..ok
                },
                false,
            ),
            (
                FlowSettings {
                    tcp_send_start_kib: 15,
                    ..ok
                },
                false,
            ),
            // An opening size above the upper size.
            (
                FlowSettings {
                    tcp_recv_kib: 256,
                    ..ok
                },
                false,
            ),
            (
                FlowSettings {
                    udp_buffer_kib: 4_097,
                    ..ok
                },
                false,
            ),
            (
                FlowSettings {
                    ack_delay_ms: 501,
                    ..ok
                },
                false,
            ),
            (
                FlowSettings {
                    connect_timeout_secs: 0,
                    ..ok
                },
                false,
            ),
            (
                FlowSettings {
                    keepalive_secs: 9,
                    ..ok
                },
                false,
            ),
            // A dead-peer timeout an idle connection would hit between two keep-alives.
            (
                FlowSettings {
                    keepalive_secs: 200,
                    ..ok
                },
                false,
            ),
        ];
        for (flow, valid) in cases {
            let p = saved(TransportSettings::Fixed { flow });
            assert_eq!(!check_transport_profile(&p).has_errors(), valid, "{flow:?}");
        }
    }

    /// A worker runs fixed values only: a profile whose ranges are out of order, or name
    /// something that is missing or automatic, is refused before it is stored or run.
    #[test]
    fn ranges_that_cannot_be_followed_are_refused() {
        let cases = [
            (vec![band(0, builtin("balanced"))], true),
            (
                vec![
                    band(0, builtin("balanced")),
                    band(80, builtin("ultra_long")),
                ],
                true,
            ),
            (Vec::new(), false),
            (vec![band(5, builtin("balanced"))], false),
            (
                vec![band(0, builtin("balanced")), band(0, builtin("long_haul"))],
                false,
            ),
            (
                vec![
                    band(0, builtin("balanced")),
                    band(10_001, builtin("long_haul")),
                ],
                false,
            ),
            (vec![band(0, builtin("no_such_profile"))], false),
            (vec![band(0, builtin(AUTO_TRANSPORT))], false),
        ];
        for (bands, valid) in cases {
            let p = saved(TransportSettings::Auto {
                bands: bands.clone(),
            });
            assert_eq!(
                !check_transport_profile(&p).has_errors(),
                valid,
                "{bands:?}"
            );
        }

        let fixed = saved(TransportSettings::Fixed {
            flow: FlowSettings::BALANCED,
        });
        let auto = saved(TransportSettings::Auto {
            bands: vec![band(0, builtin("balanced"))],
        });
        let naming = |id| {
            saved(TransportSettings::Auto {
                bands: vec![band(0, TransportRef::Profile { id })],
            })
        };
        let (of_fixed, of_auto) = (naming(fixed.id), naming(auto.id));
        let all = [fixed, auto, of_fixed.clone(), of_auto.clone()];
        let resolve = |id| resolve_transport(&TransportRef::Profile { id }, &all);
        assert!(resolve(of_fixed.id).is_ok());
        assert_eq!(
            resolve(of_auto.id),
            Err(TransportError::NestedAuto("測試".into()))
        );
        assert_eq!(
            resolve(TransportProfileId::new()),
            Err(TransportError::Missing)
        );
        // A range that names its own profile.
        let mut own = of_fixed;
        own.settings = TransportSettings::Auto {
            bands: vec![band(0, TransportRef::Profile { id: own.id })],
        };
        assert!(check_transport_profile(&own).has_errors());
    }
}
