//! IP blocklist text: a bounded, pure parser and the rules shared by the controller (preview,
//! commit, URL refresh), the manager (compile) and the UI (which mirrors the limits).
//!
//! Format: UTF-8 text (a BOM and CRLF line ends are tolerated), one IPv4/IPv6 address or CIDR per
//! line, `#` or `;` starting a comment (whole line or after the entry). IPv4-mapped IPv6 becomes
//! the IPv4 it maps; a CIDR with host bits set is normalized to its network and counted.
//! Hostnames, URLs, ranges, zone ids, NUL and anything else make that line invalid (line number
//! and reason; the first 50 are kept). Duplicates and overlapping or adjacent ranges are merged
//! into one [`IpRangeSet`]. Compressed files are refused outright (no archive bombs).
//!
//! Two native formats of the built-in lists are read line by line as well
//! ([`crate::builtin_blocklists`]):
//! - JSON lines (Spamhaus DROP since 2024): a line that starts with `{` is one JSON object; its
//!   `cidr` is the entry, an object with `"type": "metadata"` is a comment, anything else is an
//!   invalid line.
//! - Tab-separated rows (`DShield`'s recommended block list): `start <TAB> end <TAB> prefix …`,
//!   where `start/prefix` must span exactly `start`–`end`; the further columns (counts, names,
//!   contacts) are ignored.
//!
//! Private and special-use address space ([`SPECIAL_USE_V4`], [`SPECIAL_USE_V6`]) is left out of
//! every list and counted (`special_filtered`): such an entry would either do nothing (special
//! addresses are never reachable) or deny what the user allows as a private network, such as a
//! VPN provider's in-tunnel DNS (Mullvad's 10.64.0.1). Private networks are governed by the
//! security profile's private-network allowance, not by blocklists.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;
use std::time::Duration;

use crate::common::Timestamp;
use crate::config::{Blocklist, BlocklistSource, BlocklistStats, InvalidLine};
use crate::ipset::{IpRangeSet, v4_range, v6_range};
use crate::text::Text;
use crate::tr;

/// Largest raw text accepted (upload, paste or download).
pub const MAX_RAW_BYTES: usize = 8 * 1024 * 1024;
/// Most valid entries one list may have.
pub const MAX_ENTRIES: u32 = 200_000;
/// Largest compiled form of one list, and of the union a connection enforces.
pub const MAX_PARSED_BYTES: usize = 16 * 1024 * 1024;
/// Invalid lines reported (the count covers all of them).
pub const MAX_INVALID_KEPT: usize = 50;
/// Ranges shown in a preview.
pub const SAMPLE_RANGES: usize = 20;
/// Most blocklists one security profile may use.
pub const MAX_LISTS_PER_PROFILE: usize = 32;
/// Shortest automatic refresh interval, and the longest.
pub const MIN_REFRESH_HOURS: u32 = 6;
pub const MAX_REFRESH_HOURS: u32 = 720;
/// A failed automatic refresh is retried after at most this long.
pub const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(3600);
/// Longest URL accepted.
pub const MAX_URL_LEN: usize = 2048;

/// Characters of an invalid line kept for display.
const EXCERPT_CHARS: usize = 60;
/// Longest entry (after comments and whitespace are removed) that can be an address or CIDR.
const MAX_ENTRY_CHARS: usize = 64;
/// Longest JSON line or tab-separated row read (Spamhaus' metadata line is under 200 bytes).
const MAX_ROW_CHARS: usize = 1024;

/// IPv4 space no blocklist keeps.
///
/// Every block of the IANA IPv4 Special-Purpose Address Registry marked "Globally Reachable:
/// False" (2025-10-09), multicast, and everything the policy treats as special or private
/// (`validation::is_special`, `validation::is_private`), so a list can never deny what a
/// private-network allowance opens.
///
/// `192.0.0.0/24` is left out whole, like the policy does; the deprecated 6to4 relay prefix
/// `192.88.99.0/24` has no reachability verdict and stays (except the 6a44 relay address).
pub const SPECIAL_USE_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::UNSPECIFIED, 8),           // "this network" (RFC 791)
    (Ipv4Addr::new(10, 0, 0, 0), 8),      // private use (RFC 1918)
    (Ipv4Addr::new(100, 64, 0, 0), 10),   // shared address space, CGNAT (RFC 6598)
    (Ipv4Addr::new(127, 0, 0, 0), 8),     // loopback
    (Ipv4Addr::new(169, 254, 0, 0), 16),  // link-local
    (Ipv4Addr::new(172, 16, 0, 0), 12),   // private use (RFC 1918)
    (Ipv4Addr::new(192, 0, 0, 0), 24),    // IETF protocol assignments (RFC 6890)
    (Ipv4Addr::new(192, 0, 2, 0), 24),    // documentation, TEST-NET-1 (RFC 5737)
    (Ipv4Addr::new(192, 88, 99, 2), 32),  // 6a44 relay anycast (RFC 6751)
    (Ipv4Addr::new(192, 168, 0, 0), 16),  // private use (RFC 1918)
    (Ipv4Addr::new(198, 18, 0, 0), 15),   // benchmarking (RFC 2544)
    (Ipv4Addr::new(198, 51, 100, 0), 24), // documentation, TEST-NET-2
    (Ipv4Addr::new(203, 0, 113, 0), 24),  // documentation, TEST-NET-3
    (Ipv4Addr::new(224, 0, 0, 0), 4),     // multicast
    (Ipv4Addr::new(240, 0, 0, 0), 4),     // reserved, and the limited broadcast address
];

/// IPv6 space no blocklist keeps.
///
/// The IANA IPv6 Special-Purpose Address Registry's blocks marked "Globally Reachable: False"
/// (2025-10-09), multicast, the deprecated site-local prefix, and the NAT64 forms
/// (`64:ff9b::/96`) of [`SPECIAL_USE_V4`] (the policy judges a NAT64 address as the IPv4 host it
/// embeds).
///
/// IPv4-mapped entries are stored as IPv4 already.
pub const SPECIAL_USE_V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::UNSPECIFIED, 127), // unspecified and loopback
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96), // IPv4-mapped
    (Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48), // local-use NAT64 (RFC 8215)
    (Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0), 63), // discard-only and dummy (RFC 6666, 9780)
    (Ipv6Addr::new(0x2001, 0x2, 0, 0, 0, 0, 0, 0), 48), // benchmarking (RFC 5180)
    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32), // documentation (RFC 3849)
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20), // documentation (RFC 9637)
    (Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16), // SRv6 SIDs (RFC 9602)
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7), // unique local (RFC 4193)
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10), // link-local
    (Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10), // site-local, deprecated (RFC 3879)
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8), // multicast
];

/// The well-known NAT64 prefix `64:ff9b::/96` (RFC 6052) as a number.
const NAT64_PREFIX: u128 = 0x0064_ff9b_u128 << 96;

/// [`SPECIAL_USE_V4`] and [`SPECIAL_USE_V6`] (with the NAT64 forms) as sorted, merged ranges.
static SPECIAL_USE: LazyLock<IpRangeSet> = LazyLock::new(|| {
    let v4: Vec<(u32, u32)> = SPECIAL_USE_V4
        .iter()
        .map(|&(a, p)| v4_range(a, p))
        .collect();
    let mut v6: Vec<(u128, u128)> = SPECIAL_USE_V6
        .iter()
        .map(|&(a, p)| v6_range(a, p))
        .collect();
    v6.extend(
        v4.iter()
            .map(|&(s, e)| (NAT64_PREFIX | u128::from(s), NAT64_PREFIX | u128::from(e))),
    );
    IpRangeSet::from_ranges(v4, v6)
});

/// Private and special-use address space, as one set: what [`parse`] leaves out of every list.
#[must_use]
pub fn special_use() -> &'static IpRangeSet {
    &SPECIAL_USE
}

/// Push the parts of `range` outside the sorted, merged `holes` to `out`; whether any part was
/// inside one.
fn subtract<T: Copy + Ord + Step>(range: (T, T), holes: &[(T, T)], out: &mut Vec<(T, T)>) -> bool {
    let (mut start, end) = range;
    let first = holes.partition_point(|h| h.1 < start);
    let mut cut = false;
    for &(hs, he) in &holes[first..] {
        if hs > end {
            break;
        }
        cut = true;
        if hs > start {
            out.push((start, hs.prev()));
        }
        if he >= end {
            return true;
        }
        start = he.next();
    }
    out.push((start, end));
    cut
}

/// Neighbouring addresses; never called past either end (see [`subtract`]).
trait Step: Sized {
    fn next(self) -> Self;
    fn prev(self) -> Self;
}

impl Step for u32 {
    fn next(self) -> Self {
        self + 1
    }
    fn prev(self) -> Self {
        self - 1
    }
}

impl Step for u128 {
    fn next(self) -> Self {
        self + 1
    }
    fn prev(self) -> Self {
        self - 1
    }
}

/// Why a whole text cannot be used (an individual bad line is an [`InvalidLine`] instead).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlocklistError {
    #[error("the list is over the {} MiB limit", MAX_RAW_BYTES / 1024 / 1024)]
    TooLarge,
    #[error("this is a {0} compressed file")]
    Compressed(&'static str),
    #[error("more than {MAX_ENTRIES} valid entries")]
    TooManyEntries,
    #[error("the parsed list is over the {} MiB limit", MAX_PARSED_BYTES / 1024 / 1024)]
    TooLargeParsed,
}

impl BlocklistError {
    /// What to tell the user.
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::TooLarge => {
                let mib = MAX_RAW_BYTES / 1024 / 1024;
                tr!(
                    "The list is over the {mib} MiB limit",
                    "清單超過 {mib} MiB 上限",
                    "リストが上限の {mib} MiB を超えています"
                )
            }
            Self::Compressed(kind) => tr!(
                "This is a {kind} compressed file: decompress it first, then import the text list inside",
                "這是 {kind} 壓縮檔：請先解壓縮，再匯入其中的文字清單",
                "これは {kind} の圧縮ファイルです。先に展開してから、中のテキストのリストをインポートしてください"
            ),
            Self::TooManyEntries => tr!(
                "The valid entries are over the limit of {MAX_ENTRIES}",
                "有效項目超過 {MAX_ENTRIES} 筆上限",
                "有効な項目が上限の {MAX_ENTRIES} 件を超えています"
            ),
            Self::TooLargeParsed => {
                let mib = MAX_PARSED_BYTES / 1024 / 1024;
                tr!(
                    "The parsed list is over the {mib} MiB limit",
                    "解析後的清單超過 {mib} MiB 上限",
                    "解析後のリストが上限の {mib} MiB を超えています"
                )
            }
        }
    }
}

/// The parsed list: what is enforced and what the user is shown about it.
#[derive(Debug, Clone)]
pub struct ParsedBlocklist {
    pub set: IpRangeSet,
    pub stats: BlocklistStats,
    /// The first [`MAX_INVALID_KEPT`] invalid lines.
    pub invalid: Vec<InvalidLine>,
}

impl ParsedBlocklist {
    /// SHA-256 of the canonical content: what a preview showed and a commit must match.
    #[must_use]
    pub fn import_hash(&self) -> String {
        self.set.digest()
    }

    /// Why this content cannot be saved at all (nothing to block), or `None`.
    #[must_use]
    pub fn unusable(&self) -> Option<Text> {
        if self.stats.entries == 0 {
            return Some(tr!(
                "There is no valid IP address or CIDR, so the list cannot be saved",
                "沒有任何有效的 IP 位址或 CIDR，無法儲存",
                "有効な IP アドレスや CIDR が 1 つもないため、保存できません"
            ));
        }
        if self.set.is_empty() {
            let entries = self.stats.entries;
            return Some(tr!(
                "Every entry ({entries} in all) is a private or special-use address (left out): there is nothing to block, so the list cannot be saved",
                "{entries} 筆項目都是私有或特殊用途位址（已略過），沒有可封鎖的內容，無法儲存",
                "{entries} 件の項目はすべてプライベートまたは特殊用途のアドレスで（除外済み）、ブロックする内容がないため保存できません"
            ));
        }
        None
    }

    /// Why downloaded content should not replace a list (an error page, an empty answer), or
    /// `None`. A list is never replaced by nothing.
    #[must_use]
    pub fn anomaly(&self) -> Option<Text> {
        if self.stats.entries == 0 {
            return Some(tr!(
                "The content has no valid IP address or CIDR",
                "內容沒有任何有效的 IP 位址或 CIDR",
                "内容に有効な IP アドレスや CIDR が 1 つもありません"
            ));
        }
        if let Some(why) = self.unusable() {
            return Some(why);
        }
        if self.stats.invalid > 0 && self.stats.invalid >= self.stats.entries {
            let (invalid, entries) = (self.stats.invalid, self.stats.entries);
            return Some(tr!(
                "Most of the content is not addresses (invalid lines: {invalid}, valid entries: {entries}); it may be an error page",
                "內容大多不是位址（{invalid} 行無效、{entries} 筆有效），可能是錯誤頁面",
                "内容の大部分がアドレスではありません（無効な行 {invalid} 行、有効な項目 {entries} 件）。エラーページの可能性があります"
            ));
        }
        None
    }
}

/// Known compressed or archive formats, by their first bytes.
fn compressed(raw: &[u8]) -> Option<&'static str> {
    const MAGIC: &[(&[u8], &str)] = &[
        (&[0x1f, 0x8b], "gzip"),
        (&[0x1f, 0x9d], "compress (.Z)"),
        (b"PK\x03\x04", "zip"),
        (b"PK\x05\x06", "zip"),
        (b"PK\x07\x08", "zip"),
        (b"BZh", "bzip2"),
        (&[0xfd, b'7', b'z', b'X', b'Z', 0x00], "xz"),
        (&[0x28, 0xb5, 0x2f, 0xfd], "zstd"),
        (&[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c], "7z"),
        (&[0x04, 0x22, 0x4d, 0x18], "lz4"),
        (b"Rar!\x1a\x07", "rar"),
        (&[0x5d, 0x00, 0x00], "lzma"),
    ];
    MAGIC
        .iter()
        .find(|(m, _)| raw.starts_with(m))
        .map(|(_, name)| *name)
}

/// A short, printable excerpt of a line for the invalid-line report.
fn excerpt(line: &[u8]) -> String {
    let text = String::from_utf8_lossy(line);
    let mut out: String = text
        .chars()
        .take(EXCERPT_CHARS)
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect();
    if text.chars().count() > EXCERPT_CHARS {
        out.push('…');
    }
    out
}

/// Why one line is not an entry. Its words are written only for the lines that are kept
/// ([`MAX_INVALID_KEPT`]), not for every invalid line of a long text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineProblem {
    TooLong,
    NotOneEntry,
    Url,
    ZoneId,
    Range,
    HostName,
    NotAddress,
    BadMask,
    JsonTooLong,
    NotJson,
    JsonCidrNotText,
    JsonNoCidr,
    BadRowMask,
    RowMismatch,
    Nul,
    NotUtf8,
}

impl LineProblem {
    fn text(self) -> Text {
        match self {
            Self::TooLong => tr!(
                "This line is too long to be an IP address or CIDR",
                "這一行太長，不是 IP 位址或 CIDR",
                "この行は長すぎるため、IP アドレスや CIDR ではありません"
            ),
            Self::NotOneEntry => tr!(
                "A line can hold only one address or CIDR",
                "一行只能有一個位址或 CIDR",
                "1 行に書けるアドレスまたは CIDR は 1 つだけです"
            ),
            Self::Url => tr!(
                "This is a URL; only an IP address or CIDR is accepted",
                "這是網址，只接受 IP 位址或 CIDR",
                "これは URL です。IP アドレスか CIDR だけを受け付けます"
            ),
            Self::ZoneId => tr!(
                "An IPv6 zone id (%…) is not accepted",
                "不接受 IPv6 zone id（%…）",
                "IPv6 の zone id（%…）は使えません"
            ),
            Self::Range => tr!(
                "An address range (a-b) is not accepted; use a CIDR instead",
                "不接受位址範圍（a-b），請改用 CIDR",
                "アドレス範囲（a-b）は使えません。CIDR を使ってください"
            ),
            Self::HostName => tr!(
                "A host name is not accepted; only an IP address or CIDR is",
                "不接受主機名稱，只接受 IP 位址或 CIDR",
                "ホスト名は使えません。IP アドレスか CIDR だけを受け付けます"
            ),
            Self::NotAddress => tr!(
                "Not a valid IP address or CIDR",
                "不是有效的 IP 位址或 CIDR",
                "有効な IP アドレスまたは CIDR ではありません"
            ),
            Self::BadMask => tr!(
                "The mask length is not valid",
                "遮罩長度無效",
                "マスク長が無効です"
            ),
            Self::JsonTooLong => tr!(
                "This line is too long to be a readable JSON line",
                "這一行太長，不是可讀的 JSON 行",
                "この行は長すぎるため、読み取れる JSON 行ではありません"
            ),
            Self::NotJson => tr!(
                "Not a valid JSON line",
                "不是有效的 JSON 行",
                "有効な JSON 行ではありません"
            ),
            Self::JsonCidrNotText => tr!(
                "The cidr of the JSON line is not text",
                "JSON 行的 cidr 不是文字",
                "JSON 行の cidr が文字列ではありません"
            ),
            Self::JsonNoCidr => tr!(
                "The JSON line has no cidr field",
                "JSON 行沒有 cidr 欄位",
                "JSON 行に cidr フィールドがありません"
            ),
            Self::BadRowMask => tr!(
                "The mask length after the start and end addresses is not valid",
                "起訖位址之後的遮罩長度無效",
                "開始・終了アドレスの後のマスク長が無効です"
            ),
            Self::RowMismatch => tr!(
                "The start and end addresses do not match the mask length",
                "起訖位址與遮罩長度不一致",
                "開始・終了アドレスとマスク長が一致しません"
            ),
            Self::Nul => tr!(
                "Contains a NUL character",
                "含有 NUL 字元",
                "NUL 文字が含まれています"
            ),
            Self::NotUtf8 => tr!(
                "Not UTF-8 text",
                "不是 UTF-8 文字",
                "UTF-8 のテキストではありません"
            ),
        }
    }
}

/// One parsed entry: its inclusive range and what normalizing it took.
enum Entry {
    V4 {
        range: (u32, u32),
        host_bits: bool,
    },
    V6 {
        range: (u128, u128),
        host_bits: bool,
    },
}

/// Parse one entry (comments and surrounding whitespace already removed).
fn entry(token: &str, mapped: &mut bool) -> Result<Entry, LineProblem> {
    if token.chars().count() > MAX_ENTRY_CHARS {
        return Err(LineProblem::TooLong);
    }
    if token.chars().any(char::is_whitespace) {
        return Err(LineProblem::NotOneEntry);
    }
    if token.contains("://") {
        return Err(LineProblem::Url);
    }
    if token.contains('%') {
        return Err(LineProblem::ZoneId);
    }
    let (addr, prefix) = match token.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (token, None),
    };
    // An `AddrParseError` says only "not an IP address"; the token itself tells which kind of
    // wrong entry it is.
    let ip: IpAddr = addr.parse().map_err(|_not_an_ip| {
        let range = token
            .split_once('-')
            .is_some_and(|(a, b)| a.parse::<IpAddr>().is_ok() && b.parse::<IpAddr>().is_ok());
        let hostname = !token.contains(':')
            && token.chars().any(|c| c.is_ascii_alphabetic())
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
        if range {
            LineProblem::Range
        } else if hostname {
            LineProblem::HostName
        } else {
            LineProblem::NotAddress
        }
    })?;
    let bits: u8 = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        None => bits,
        Some(p) => {
            if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(LineProblem::BadMask);
            }
            match p.parse::<u8>() {
                Ok(n) if n <= bits => n,
                _ => return Err(LineProblem::BadMask),
            }
        }
    };
    Ok(match ip {
        IpAddr::V4(a) => {
            let range = v4_range(a, prefix);
            Entry::V4 {
                host_bits: range.0 != u32::from(a),
                range,
            }
        }
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            // `::ffff:a.b.c.d` (and mapped networks of /96 or longer) are IPv4.
            Some(m) if prefix >= 96 => {
                *mapped = true;
                let range = v4_range(m, prefix - 96);
                Entry::V4 {
                    host_bits: range.0 != u32::from(m),
                    range,
                }
            }
            _ => {
                let range = v6_range(a, prefix);
                Entry::V6 {
                    host_bits: range.0 != u128::from(a),
                    range,
                }
            }
        },
    })
}

/// One JSON line (Spamhaus DROP): its `cidr`, or `None` for the metadata line.
fn json_line(line: &str) -> Result<Option<String>, LineProblem> {
    #[derive(serde::Deserialize)]
    struct Row {
        cidr: Option<serde_json::Value>,
        #[serde(rename = "type")]
        kind: Option<serde_json::Value>,
    }
    if line.len() > MAX_ROW_CHARS {
        return Err(LineProblem::JsonTooLong);
    }
    #[expect(
        clippy::map_err_ignore,
        reason = "an invalid line is reported as one fixed, translated reason next to its excerpt; the JSON parser's message is not part of that report"
    )]
    let row: Row = serde_json::from_str(line).map_err(|_| LineProblem::NotJson)?;
    match (row.cidr, row.kind) {
        (Some(serde_json::Value::String(cidr)), _) => Ok(Some(cidr)),
        (Some(_), _) => Err(LineProblem::JsonCidrNotText),
        (None, Some(serde_json::Value::String(kind))) if kind == "metadata" => Ok(None),
        (None, _) => Err(LineProblem::JsonNoCidr),
    }
}

/// One tab-separated row (`DShield`'s block list): `start <TAB> end <TAB> prefix [<TAB> …]` as
/// `start/prefix`, which must span exactly `start`–`end`.
fn tab_row(row: &str) -> Result<String, LineProblem> {
    if row.len() > MAX_ROW_CHARS {
        return Err(LineProblem::TooLong);
    }
    let mut cols = row.split('\t').map(str::trim);
    let (Some(start), Some(end), Some(prefix)) = (cols.next(), cols.next(), cols.next()) else {
        return Err(LineProblem::NotOneEntry);
    };
    let (Ok(start), Ok(end)) = (start.parse::<IpAddr>(), end.parse::<IpAddr>()) else {
        return Err(LineProblem::NotOneEntry);
    };
    if prefix.is_empty() || prefix.len() > 3 || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return Err(LineProblem::BadRowMask);
    }
    // One to three digits: the only error left is a value over 255, which `BadRowMask` reports.
    let prefix: u8 = prefix
        .parse()
        .map_err(|_over_255| LineProblem::BadRowMask)?;
    let exact = match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) if prefix <= 32 => {
            v4_range(s, prefix) == (u32::from(s), u32::from(e))
        }
        (IpAddr::V6(s), IpAddr::V6(e)) if prefix <= 128 => {
            v6_range(s, prefix) == (u128::from(s), u128::from(e))
        }
        _ => false,
    };
    if !exact {
        return Err(LineProblem::RowMismatch);
    }
    Ok(format!("{start}/{prefix}"))
}

/// How one line of a blocklist text reads, before its address or CIDR is parsed.
enum LineToken<'a> {
    Blank,
    Comment,
    /// The address or CIDR text of the line.
    Token(std::borrow::Cow<'a, str>),
    /// Why the line is not an entry.
    Invalid(LineProblem),
}

/// Classify one line (without its line break) of a blocklist text.
fn line_token(line: &[u8]) -> LineToken<'_> {
    if line.contains(&0) {
        return LineToken::Invalid(LineProblem::Nul);
    }
    let Ok(text) = std::str::from_utf8(line) else {
        return LineToken::Invalid(LineProblem::NotUtf8);
    };
    let trimmed = text.trim();
    // A JSON line is read whole: its strings may hold `#` or `;`.
    if trimmed.starts_with('{') {
        return match json_line(trimmed) {
            Ok(Some(cidr)) => LineToken::Token(cidr.into()),
            Ok(None) => LineToken::Comment,
            Err(reason) => LineToken::Invalid(reason),
        };
    }
    let token = text.split(['#', ';']).next().unwrap_or_default().trim();
    if token.is_empty() {
        return if trimmed.is_empty() {
            LineToken::Blank
        } else {
            LineToken::Comment
        };
    }
    if token.contains('\t') {
        return match tab_row(token) {
            Ok(cidr) => LineToken::Token(cidr.into()),
            Err(reason) => LineToken::Invalid(reason),
        };
    }
    LineToken::Token(token.into())
}

/// Parse a blocklist text. Lines that are not an address or CIDR are reported, not fatal; the
/// text as a whole fails only on the size limits or when it is a compressed file.
///
/// # Errors
///
/// [`BlocklistError::TooLarge`] when `raw` is over [`MAX_RAW_BYTES`],
/// [`BlocklistError::Compressed`] when it is a compressed file,
/// [`BlocklistError::TooManyEntries`] past [`MAX_ENTRIES`] entries and
/// [`BlocklistError::TooLargeParsed`] when the parsed set is over [`MAX_PARSED_BYTES`].
pub fn parse(raw: &[u8]) -> Result<ParsedBlocklist, BlocklistError> {
    if raw.len() > MAX_RAW_BYTES {
        return Err(BlocklistError::TooLarge);
    }
    if let Some(kind) = compressed(raw) {
        return Err(BlocklistError::Compressed(kind));
    }
    let body = raw.trim_prefix(&[0xef, 0xbb, 0xbf]);
    let mut stats = BlocklistStats {
        raw_bytes: u32::try_from(raw.len()).unwrap_or(u32::MAX),
        ..BlocklistStats::default()
    };
    let mut invalid = Vec::new();
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut lines = body.split(|b| *b == b'\n').peekable();
    let mut number = 0u32;
    while let Some(line) = lines.next() {
        // A final line break does not start another (empty) line.
        if line.is_empty() && lines.peek().is_none() {
            break;
        }
        number += 1;
        stats.lines += 1;
        let line = line.trim_suffix(b"\r");
        let mut reject = |reason: LineProblem| {
            stats.invalid += 1;
            if invalid.len() < MAX_INVALID_KEPT {
                invalid.push(InvalidLine {
                    line: number,
                    reason: reason.text(),
                    content: excerpt(line),
                });
            }
        };
        let token = match line_token(line) {
            LineToken::Token(token) => token,
            LineToken::Blank => {
                stats.blank += 1;
                continue;
            }
            LineToken::Comment => {
                stats.comments += 1;
                continue;
            }
            LineToken::Invalid(reason) => {
                reject(reason);
                continue;
            }
        };
        let mut mapped = false;
        match entry(&token, &mut mapped) {
            Ok(e) => {
                stats.entries += 1;
                if stats.entries > MAX_ENTRIES {
                    return Err(BlocklistError::TooManyEntries);
                }
                if mapped {
                    stats.mapped_ipv4 += 1;
                }
                // Private and special-use space is left out (see the module docs).
                let special = special_use();
                let filtered = match e {
                    Entry::V4 { range, host_bits } => {
                        stats.host_bits_normalized += u32::from(host_bits);
                        subtract(range, special.v4_ranges(), &mut v4)
                    }
                    Entry::V6 { range, host_bits } => {
                        stats.host_bits_normalized += u32::from(host_bits);
                        subtract(range, special.v6_ranges(), &mut v6)
                    }
                };
                stats.special_filtered += u32::from(filtered);
            }
            Err(reason) => reject(reason),
        }
    }
    let set = IpRangeSet::from_ranges(v4, v6);
    let parsed_bytes = set.encoded_len();
    if parsed_bytes > MAX_PARSED_BYTES {
        return Err(BlocklistError::TooLargeParsed);
    }
    stats.parsed_bytes = u32::try_from(parsed_bytes).unwrap_or(u32::MAX);
    stats.v4_ranges = u32::try_from(set.v4_ranges().len()).unwrap_or(u32::MAX);
    stats.v6_ranges = u32::try_from(set.v6_ranges().len()).unwrap_or(u32::MAX);
    stats.v4_addresses = set.v4_addresses();
    stats.v6_addresses = set.v6_addresses().to_string();
    Ok(ParsedBlocklist {
        set,
        stats,
        invalid,
    })
}

/// A validated `https://` URL of a blocklist source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsUrl {
    /// Lowercase DNS name (never an IP literal).
    pub host: String,
    pub port: u16,
    /// Origin-form request target: path and query, starting with `/`.
    pub path: String,
}

impl HttpsUrl {
    /// The origin as text (`https://host[:port]`).
    #[must_use]
    pub fn origin(&self) -> String {
        if self.port == 443 {
            format!("https://{}", self.host)
        } else {
            format!("https://{}:{}", self.host, self.port)
        }
    }

    #[must_use]
    pub fn to_url(&self) -> String {
        format!("{}{}", self.origin(), self.path)
    }

    /// Resolve a redirect `Location` against this URL; `None` if it is not a usable https URL.
    #[must_use]
    pub fn join(&self, location: &str) -> Option<Self> {
        let location = location.trim();
        if location.starts_with("//") {
            return parse_https_url(&format!("https:{location}")).ok();
        }
        if location.starts_with('/') {
            return parse_https_url(&format!("{}{location}", self.origin())).ok();
        }
        parse_https_url(location).ok()
    }
}

/// Parse and check a blocklist source URL: `https://` only, a DNS host name (no IP literals,
/// no user info, no local-only names), an optional port, a path. Fragments are dropped.
///
/// # Errors
///
/// A user-facing reason when the input is empty or too long, holds whitespace or control
/// characters, is not `https://`, carries user info, an IP literal, an invalid port or host name,
/// a local-only name, or a non-ASCII path.
pub fn parse_https_url(input: &str) -> Result<HttpsUrl, Text> {
    let s = input.trim();
    if s.is_empty() {
        return Err(tr!("Enter a URL", "請輸入網址", "URL を入力してください"));
    }
    if s.len() > MAX_URL_LEN {
        return Err(tr!("The URL is too long", "網址太長", "URL が長すぎます"));
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(tr!(
            "A URL cannot contain spaces or control characters",
            "網址不可包含空白或控制字元",
            "URL に空白や制御文字は使えません"
        ));
    }
    let Some(rest) = s
        .split_at_checked(8)
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("https://"))
        .map(|(_, rest)| rest)
    else {
        return Err(tr!(
            "Only https:// URLs are accepted",
            "只接受 https:// 網址",
            "https:// の URL だけを受け付けます"
        ));
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (host, port) = https_authority(authority)?;
    let tail = tail.split('#').next().unwrap_or_default();
    let path = if tail.is_empty() {
        "/".to_string()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_string()
    };
    if !path.is_ascii() {
        return Err(tr!(
            "Write the path URL-encoded (non-ASCII characters are not accepted)",
            "路徑請使用 URL 編碼（不接受非 ASCII 字元）",
            "パスは URL エンコードしてください（ASCII 以外の文字は使えません）"
        ));
    }
    Ok(HttpsUrl { host, port, path })
}

/// The host (lowercase) and port of an `https://` URL's authority: a DNS name that is neither an
/// IP literal nor a local-only name, no user info.
fn https_authority(authority: &str) -> Result<(String, u16), Text> {
    if authority.contains('@') {
        return Err(tr!(
            "A URL cannot contain a user name or password",
            "網址不可包含帳號或密碼",
            "URL にユーザー名やパスワードは含められません"
        ));
    }
    let no_ip = || {
        tr!(
            "Use a host name; IP addresses are not accepted",
            "請使用主機名稱，不接受 IP 位址",
            "ホスト名を使ってください。IP アドレスは使えません"
        )
    };
    if authority.starts_with('[') {
        return Err(no_ip());
    }
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => {
            let port =
                p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| {
                    tr!("The port is not valid", "連接埠無效", "ポートが無効です")
                })?;
            (h, port)
        }
        None => (authority, 443),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(tr!(
            "The URL has no host name",
            "網址缺少主機名稱",
            "URL にホスト名がありません"
        ));
    }
    if host.parse::<Ipv4Addr>().is_ok()
        || host.parse::<Ipv6Addr>().is_ok()
        || host
            .rsplit('.')
            .next()
            .is_some_and(|l| l.chars().all(|c| c.is_ascii_digit()))
    {
        return Err(no_ip());
    }
    if !crate::validation::valid_hostname(&host) || !host.contains('.') {
        return Err(tr!(
            "The host name is not valid (a fully qualified domain name is needed)",
            "主機名稱無效（需要完整網域名稱）",
            "ホスト名が無効です（完全なドメイン名が必要です）"
        ));
    }
    // `host` is lowercase already; `.local` is the last label.
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.rsplit_once('.').is_some_and(|(_, tld)| tld == "local")
    {
        return Err(tr!(
            "A name of this host or the local network cannot be downloaded from through the VPN",
            "本機或區網名稱無法經 VPN 下載",
            "このホストや LAN の名前からは VPN 経由でダウンロードできません"
        ));
    }
    Ok((host, port))
}

/// The blocklists a connection enforces, in order. The precedence, in one place:
///
/// 1. A connection with a security profile enforces exactly that profile's selection. (A new
///    profile starts with the enabled built-in lists selected; the user may change that.)
/// 2. A connection without one follows the default security policy: every enabled built-in list
///    ([`default_lists`]).
///
/// Either way a disabled list is left out (a profile keeps it selected for when it is enabled
/// again). An id with no list is kept, for the caller to report; a list still awaiting its first
/// content is kept and contributes nothing.
#[must_use]
pub fn effective_lists(
    security: Option<&crate::config::SecurityProfile>,
    lists: &[Blocklist],
) -> Vec<crate::ids::BlocklistId> {
    security.map_or_else(
        || default_lists(lists),
        |s| {
            s.blocklists
                .iter()
                .copied()
                .filter(|id| lists.iter().find(|l| l.id == *id).is_none_or(|l| l.enabled))
                .collect()
        },
    )
}

/// The default security policy's lists: every enabled built-in list, in catalogue order.
#[must_use]
pub fn default_lists(lists: &[Blocklist]) -> Vec<crate::ids::BlocklistId> {
    let mut builtin: Vec<(usize, crate::ids::BlocklistId)> = lists
        .iter()
        .filter(|l| l.enabled)
        .filter_map(|l| {
            l.builtin
                .as_deref()
                .map(|key| (crate::builtin_blocklists::order(key), l.id))
        })
        .collect();
    builtin.sort_unstable();
    builtin.into_iter().map(|(_, id)| id).collect()
}

/// When an automatic refresh of `list` is due: `None` when it is not automatic or the list is
/// disabled.
///
/// Never earlier than the last attempt plus the interval (or [`RETRY_AFTER_FAILURE`] after a
/// failure). A URL list still waiting for its first content (a built-in list) is due at once,
/// whatever its interval, and again [`RETRY_AFTER_FAILURE`] after a failed try.
#[must_use]
pub fn next_refresh_due(
    list: &Blocklist,
    last_attempt: Option<(Timestamp, bool)>,
) -> Option<Timestamp> {
    let BlocklistSource::Url { refresh_hours, .. } = &list.source else {
        return None;
    };
    if !list.enabled {
        return None;
    }
    if list.awaiting_content() {
        return Some(match last_attempt {
            Some((at, false)) => at.plus(RETRY_AFTER_FAILURE),
            _ => list.content_updated_at,
        });
    }
    let hours = (*refresh_hours)?;
    let interval = Duration::from_secs(u64::from(hours) * 3600);
    Some(match last_attempt {
        Some((at, true)) => at.plus(interval),
        Some((at, false)) => at.plus(interval.min(RETRY_AFTER_FAILURE)),
        None => list.content_updated_at.plus(interval),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_urls() {
        let u = parse_https_url("https://Lists.Example.net/drop.txt?x=1#frag").unwrap();
        assert_eq!(u.host, "lists.example.net");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/drop.txt?x=1");
        assert_eq!(u.to_url(), "https://lists.example.net/drop.txt?x=1");
        let p = parse_https_url("https://lists.example.net:8443").unwrap();
        assert_eq!((p.port, p.path.as_str()), (8443, "/"));
        assert_eq!(p.origin(), "https://lists.example.net:8443");
        for bad in [
            "http://lists.example.net/x",
            "ftp://lists.example.net/x",
            "https://1.2.3.4/x",
            "https://[2001:db8::1]/x",
            "https://user:pw@lists.example.net/x",
            "https://localhost/x",
            "https://nas.local/x",
            "https://intranet/x",
            "https://lists.example.net:0/x",
            "https://lists.example.net:99999/x",
            "https://lists example.net/x",
            "https://lists.example.net/路徑",
            "",
        ] {
            assert!(parse_https_url(bad).is_err(), "{bad}");
        }
        // Redirect targets resolve against the current URL.
        assert_eq!(
            u.join("/v2/drop.txt").unwrap().to_url(),
            "https://lists.example.net/v2/drop.txt"
        );
        assert_eq!(
            u.join("https://cdn.example.org/drop.txt").unwrap().host,
            "cdn.example.org"
        );
        assert!(u.join("http://lists.example.net/x").is_none());
    }
}
