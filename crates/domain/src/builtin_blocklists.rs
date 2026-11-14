//! Built-in IP blocklists: public lists made for blocking, from the most conservative (Spamhaus
//! DROP, `DShield`) to larger report-driven ones (see below).
//!
//! They are part of the program: the store creates each one as a URL blocklist with automatic
//! refresh on first start, and an upgrade creates them through a store migration step (a list the
//! user deleted is remembered and never created again). Like every URL list they are downloaded
//! only through the Provider egress connection, and until one exists they wait.
//!
//! They apply by default: the default security policy (a connection without a security profile)
//! enforces every enabled built-in list, and a new security profile starts with them selected.
//! A connection with a security profile enforces exactly that profile's selection.
//!
//! Chosen on 2026-11-02, with the URL, format, size and terms of each verified that day:
//!
//! - **Spamhaus DROP and `DROPv6`** ("Don't Route Or Peer"): netblocks hijacked or leased by
//!   professional spam or cyber-crime operations; Spamhaus: "false positives are extremely low"
//!   and "IP address space under the control of any legitimate network will never be listed".
//!   EDROP was merged into DROP on 2024-04-10. JSON lines since 2024 (`drop.txt`/`dropv6.txt`
//!   are still published but will be deprecated): 1,754 IPv4 networks (107 KB) and 89 IPv6
//!   networks (6 KB). Free for everyone; a product that uses it credits The Spamhaus Project;
//!   automated downloads at least an hour apart, once a day is enough.
//! - **`DShield` recommended block list** (SANS Internet Storm Center): the 20 /24 networks whose
//!   scans reached the most targets in the last three days; regenerated hourly, 2 KB. Data use is
//!   permitted with attribution (CC BY-NC-SA; protecting your own network is allowed, reselling
//!   the data is not); at most one download an hour.
//!
//! Together they are what `FireHOL`'s "level 1" list (made for "maximum protection with minimum
//! false positives") is built from, taken from the original sources and without its full bogons.
//!
//! Added on 2026-11-07 at the user's request ("將網路上好的名單都加入"), each previewed on the PC
//! and its terms checked that day:
//!
//! - **`FireHOL` level 1**: `DShield`, Feodo, Spamhaus DROP and Team Cymru's full bogons (4,651
//!   lines). The bogons include private and reserved space (`10.0.0.0/8`, `100.64.0.0/10`,
//!   `224.0.0.0/3`…); `blocklist::parse` leaves every special-use range out of every list, so
//!   it never reaches a LAN or a provider's in-tunnel DNS. The GitHub copy (updated once a day)
//!   is the URL the user's list already had. No licence of its own: its sources' terms apply.
//! - **abuse.ch Feodo Tracker, recommended**: botnet C2 servers active now or in the last hours;
//!   nearly empty since the 2024 takedowns (one entry), kept for when new C2s appear. CC0; no
//!   high-volume automated access.
//! - **Emerging Threats compromised IPs** (Proofpoint ET Open): hosts reported compromised or
//!   hostile, from several sources, updated on weekdays; at most one download an hour.
//! - **CINS Army** (Sentinel IPS): addresses with a very poor Rogue Packet score or several
//!   trusted alerts, capped at 15,000; no terms beyond "use as you see fit".
//! - **blocklist.de, all**: addresses that attacked its members' servers in the last 48 hours
//!   (IPv4 and some IPv6), regenerated every 30 minutes; free except excessive volume.
//! - **`IPsum` level 3**: addresses on three or more of 30+ public lists, daily; Unlicense.
//!
//! The last four are larger and report-driven: a VPN server's address can appear in them. A
//! built-in list therefore never covers what a connection needs (its `WireGuard` endpoint, its
//! DNS servers): those addresses are left out of that connection's overlay instead of refusing
//! the list or the start (`instance-manager` `policy::compile`).
//!
//! Still not chosen: abuse.ch SSLBL (deprecated on 2025-01-03) and Emerging Threats
//! `emerging-Block-IPs.txt` (a copy of Spamhaus DROP, `DShield` and Feodo).

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::text::Text;
use crate::tr;

/// The address family a built-in list carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum BlocklistFamily {
    Ipv4,
    Ipv6,
    /// IPv4 and IPv6 in one list.
    Both,
}

/// The native format of a list's text (all read by `blocklist::parse`, which tells them apart
/// line by line).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum BlocklistFormat {
    /// One address or CIDR per line; `#` and `;` comments.
    Plain,
    /// One JSON object per line with a `cidr`, and a final metadata object (Spamhaus).
    JsonLines,
    /// Tab-separated `start  end  prefix …` rows with `#` comments (`DShield`).
    TabRanges,
}

/// One entry of the built-in catalogue. Its words are written when it is read ([`Self::name`],
/// [`Self::description`], [`Self::terms`]).
#[derive(Debug, Clone, Copy)]
pub struct BuiltinBlocklist {
    /// Stable identifier, remembered with the list it created (and when the user deleted it).
    pub key: &'static str,
    /// Display name (the source credited by name).
    name: fn() -> Text,
    /// The official download URL (`https://`, downloaded through the Provider egress).
    pub url: &'static str,
    /// The page that describes the list.
    pub homepage: &'static str,
    pub family: BlocklistFamily,
    pub format: BlocklistFormat,
    /// Automatic refresh interval (within `blocklist::MIN_REFRESH_HOURS..=MAX_REFRESH_HOURS`, and
    /// as often as the source allows at most).
    pub refresh_hours: u32,
    /// What the list holds and why it is safe to block.
    description: fn() -> Text,
    /// The source's terms of use, in short.
    terms: fn() -> Text,
    pub terms_url: &'static str,
}

impl BuiltinBlocklist {
    /// Display name (the source credited by name).
    #[must_use]
    pub fn name(&self) -> Text {
        (self.name)()
    }

    /// The name the list created from this entry is stored with: the Traditional Chinese
    /// [`Self::name`]. A list's name is one string the user may change; where the list is still
    /// the built-in one, the interface shows the catalogue's name in the reader's language.
    #[must_use]
    pub fn list_name(&self) -> String {
        self.name().zh_tw.clone()
    }

    /// What the list holds and why it is safe to block.
    #[must_use]
    pub fn description(&self) -> Text {
        (self.description)()
    }

    /// The source's terms of use, in short.
    #[must_use]
    pub fn terms(&self) -> Text {
        (self.terms)()
    }
}

/// The built-in lists, in the order they are created and shown.
pub const BUILTIN_BLOCKLISTS: &[BuiltinBlocklist] = &[
    BuiltinBlocklist {
        key: "spamhaus-drop-v4",
        name: || {
            tr!(
                "Spamhaus DROP (IPv4)",
                "Spamhaus DROP（IPv4）",
                "Spamhaus DROP（IPv4）"
            )
        },
        url: "https://www.spamhaus.org/drop/drop_v4.json",
        homepage: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
        family: BlocklistFamily::Ipv4,
        format: BlocklistFormat::JsonLines,
        refresh_hours: 24,
        description: || {
            tr!(
                "Spamhaus's “Don't Route Or Peer” list: networks hijacked or leased by professional spam or cyber-crime operations. Spamhaus says addresses of legitimate networks are never listed, and false positives are extremely rare.",
                "Spamhaus 的「Don't Route Or Peer」清單：被職業垃圾郵件或網路犯罪集團劫持、租用的網段。Spamhaus 表示合法網路的位址不會被列入，誤判極低。",
                "Spamhaus の「Don't Route Or Peer」リスト：プロのスパム業者やサイバー犯罪組織に乗っ取られたり借りられたりしているネットワークです。Spamhaus によれば正当なネットワークのアドレスが載ることはなく、誤検知は極めてまれです。"
            )
        },
        terms: spamhaus_terms,
        terms_url: "https://www.spamhaus.org/drop/terms/",
    },
    BuiltinBlocklist {
        key: "spamhaus-drop-v6",
        name: || {
            tr!(
                "Spamhaus DROPv6 (IPv6)",
                "Spamhaus DROPv6（IPv6）",
                "Spamhaus DROPv6（IPv6）"
            )
        },
        url: "https://www.spamhaus.org/drop/drop_v6.json",
        homepage: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
        family: BlocklistFamily::Ipv6,
        format: BlocklistFormat::JsonLines,
        refresh_hours: 24,
        description: || {
            tr!(
                "The IPv6 version of Spamhaus DROP: IPv6 networks hijacked or leased by professional spam or cyber-crime operations, with extremely rare false positives.",
                "Spamhaus DROP 的 IPv6 版本：被職業垃圾郵件或網路犯罪集團劫持、租用的 IPv6 網段，誤判極低。",
                "Spamhaus DROP の IPv6 版：プロのスパム業者やサイバー犯罪組織に乗っ取られたり借りられたりしている IPv6 ネットワークです。誤検知は極めてまれです。"
            )
        },
        terms: spamhaus_terms,
        terms_url: "https://www.spamhaus.org/drop/terms/",
    },
    BuiltinBlocklist {
        key: "dshield-block",
        name: || {
            tr!(
                "DShield recommended block list",
                "DShield 建議封鎖清單",
                "DShield 推奨ブロックリスト"
            )
        },
        url: "https://feeds.dshield.org/block.txt",
        homepage: "https://isc.sans.edu/feeds_doc.html",
        family: BlocklistFamily::Ipv4,
        format: BlocklistFormat::TabRanges,
        refresh_hours: 6,
        description: || {
            tr!(
                "The recommended block list of the SANS Internet Storm Center (DShield): the 20 /24 networks whose scans reached the most targets in the last three days, regenerated every hour.",
                "SANS Internet Storm Center（DShield）的建議封鎖清單：最近三天掃描最多目標的 20 個 /24 網段，每小時重新產生。",
                "SANS Internet Storm Center（DShield）の推奨ブロックリスト：直近 3 日間で最も多くの対象をスキャンした 20 個の /24 ネットワークです。1 時間ごとに再生成されます。"
            )
        },
        terms: || {
            tr!(
                "SANS ISC allows use with attribution (CC BY-NC-SA: protecting your own network is allowed, reselling the data is not); download at most once an hour (refreshed here every 6 hours).",
                "SANS ISC 允許註明來源後使用（CC BY-NC-SA；用來保護自己的網路可以，不得轉售資料）；下載請至少間隔 1 小時（這裡每 6 小時更新）。",
                "SANS ISC は出典を表記すれば利用を認めています（CC BY-NC-SA。自分のネットワークの保護には使えますが、データの転売はできません）。ダウンロードは 1 時間以上の間隔を空けてください（ここでは 6 時間ごとに更新）。"
            )
        },
        terms_url: "https://isc.sans.edu/api/",
    },
    BuiltinBlocklist {
        key: "firehol-level1",
        name: || Text::verbatim("FireHOL Level 1"),
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        homepage: "https://iplists.firehol.org/?ipset=firehol_level1",
        family: BlocklistFamily::Ipv4,
        format: BlocklistFormat::Plain,
        refresh_hours: 24,
        description: || {
            tr!(
                "FireHOL's merged “Level 1”: DShield, Feodo, Spamhaus DROP and Team Cymru's unallocated addresses (fullbogons), aiming at the fewest false positives. Its private and reserved networks (10/8, 100.64/10, 192.168/16 and others) are always filtered out, so it never blocks the LAN or the DNS inside the VPN. The copy on GitHub is updated once a day.",
                "FireHOL 合併的「Level 1」：DShield、Feodo、Spamhaus DROP 與 Team Cymru 的未分配位址（fullbogons），目標是最少的誤判。其中的私網與保留網段（10/8、100.64/10、192.168/16 等）一律被過濾，不會擋到區網或 VPN 內部的 DNS。GitHub 上的副本每天更新一次。",
                "FireHOL が統合した「Level 1」：DShield、Feodo、Spamhaus DROP、Team Cymru の未割り当てアドレス（fullbogons）で、誤検知を最小にすることを目指しています。含まれるプライベートや予約済みのネットワーク（10/8、100.64/10、192.168/16 など）は常に除外されるため、LAN や VPN 内部の DNS をブロックすることはありません。GitHub 上のコピーは 1 日 1 回更新されます。"
            )
        },
        terms: || {
            tr!(
                "FireHOL has no license of its own; the terms of each source apply: DShield is CC BY-NC-SA (protecting your own network is allowed, reselling is not), and Spamhaus must be credited as The Spamhaus Project. No download interval is stated (refreshed here every 24 hours).",
                "FireHOL 沒有自己的授權，沿用各來源的條款：DShield 為 CC BY-NC-SA（保護自己的網路可以，不得轉售），Spamhaus 須註明來源 The Spamhaus Project。沒有說明下載間隔（這裡每 24 小時更新）。",
                "FireHOL には独自のライセンスがなく、各ソースの条件に従います。DShield は CC BY-NC-SA（自分のネットワークの保護には使えますが、転売はできません）、Spamhaus は出典 The Spamhaus Project の表記が必要です。ダウンロード間隔の指定はありません（ここでは 24 時間ごとに更新）。"
            )
        },
        terms_url: "https://github.com/firehol/blocklist-ipsets#about-this-repo",
    },
    BuiltinBlocklist {
        key: "abusech-feodo",
        name: || {
            tr!(
                "abuse.ch Feodo Tracker recommended list",
                "abuse.ch Feodo Tracker 建議清單",
                "abuse.ch Feodo Tracker 推奨リスト"
            )
        },
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        homepage: "https://feodotracker.abuse.ch/blocklist/",
        family: BlocklistFamily::Ipv4,
        format: BlocklistFormat::Plain,
        refresh_hours: 12,
        description: || {
            tr!(
                "The recommended list of abuse.ch Feodo Tracker: botnet command-and-control servers (Emotet, Dridex, QakBot and others) that are active now or were in the last few hours, answering valid commands. Nearly empty since the 2024 takedowns (1 entry in 2026-11), it is kept so that new control servers are blocked automatically.",
                "abuse.ch Feodo Tracker 的建議清單：目前或最近幾小時仍在運作、回應有效指令的殭屍網路控制伺服器（Emotet、Dridex、QakBot 等）。2024 年的掃蕩之後幾乎是空的（2026-11 只有 1 筆），留著是為了有新的控制伺服器時自動擋下。",
                "abuse.ch Feodo Tracker の推奨リスト：現在または直近数時間に稼働し、有効なコマンドに応答しているボットネットの C&C サーバー（Emotet、Dridex、QakBot など）です。2024 年の摘発以降ほぼ空ですが（2026-11 時点で 1 件）、新しい C&C サーバーが現れたときに自動でブロックするために残しています。"
            )
        },
        terms: || {
            tr!(
                "abuse.ch releases it under CC0: free for commercial and non-commercial use, without attribution; high-volume automated access is forbidden (downloaded here every 12 hours; regenerated at the source every 5 minutes).",
                "abuse.ch 以 CC0 釋出：商業與非商業都可免費使用，不必註明來源；禁止大量的自動存取（這裡每 12 小時下載一次，官方每 5 分鐘重新產生）。",
                "abuse.ch は CC0 で公開しています。商用・非商用を問わず無料で使え、出典の表記も不要です。大量の自動アクセスは禁止されています（ここでは 12 時間ごとにダウンロード。公式は 5 分ごとに再生成）。"
            )
        },
        terms_url: "https://abuse.ch/terms-of-use/",
    },
    BuiltinBlocklist {
        key: "et-compromised",
        name: || {
            tr!(
                "Emerging Threats compromised hosts",
                "Emerging Threats 已入侵主機",
                "Emerging Threats 侵害済みホスト"
            )
        },
        url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        homepage: "https://rules.emergingthreats.net/blockrules/",
        family: BlocklistFamily::Ipv4,
        format: BlocklistFormat::Plain,
        refresh_hours: 24,
        description: || {
            tr!(
                "The block list of Proofpoint Emerging Threats (ET Open): compromised or hostile hosts reported by several sources (BruteForceBlocker among them), updated every weekday.",
                "Proofpoint Emerging Threats（ET Open）的封鎖清單：多個來源（含 BruteForceBlocker）回報的已入侵或惡意主機，平日每天更新。",
                "Proofpoint Emerging Threats（ET Open）のブロックリスト：複数のソース（BruteForceBlocker を含む）から報告された、侵害済みまたは悪意のあるホストです。平日に毎日更新されます。"
            )
        },
        terms: || {
            tr!(
                "ET Open is free (the rule files of the same series are under a BSD-style license); automated downloads at most once an hour, once a day recommended (here every 24 hours); downloading too often is refused for a while (HTTP 429).",
                "ET Open 免費提供（同系列的規則檔為 BSD 式授權）；自動下載不得超過每小時一次、建議每天一次（這裡每 24 小時），太頻繁會被暫時拒絕（HTTP 429）。",
                "ET Open は無料で提供されています（同シリーズのルールファイルは BSD 系のライセンス）。自動ダウンロードは 1 時間に 1 回までで、1 日 1 回が推奨です（ここでは 24 時間ごと）。頻繁すぎると一時的に拒否されます（HTTP 429）。"
            )
        },
        terms_url: "https://rules.emergingthreats.net/OPEN_download_instructions.html",
    },
    BuiltinBlocklist {
        key: "cins-army",
        name: || Text::verbatim("CINS Army"),
        url: "https://cinsscore.com/list/ci-badguys.txt",
        homepage: "https://cinsscore.com/#list",
        family: BlocklistFamily::Ipv4,
        format: BlocklistFormat::Plain,
        refresh_hours: 24,
        description: || {
            tr!(
                "CINS Army from Sentinel IPS: addresses with a very poor Rogue Packet score or several trusted alerts (mostly sources of scans and brute-force attacks), at most 15,000.",
                "Sentinel IPS 的 CINS Army：Rogue Packet 評分很差、或觸發多次可信警報的位址（多半是掃描與暴力破解的來源），最多 15,000 筆。",
                "Sentinel IPS の CINS Army：Rogue Packet スコアが非常に悪いか、信頼できるアラートを何度も発生させたアドレス（主にスキャンや総当たり攻撃の送信元）です。最大 15,000 件です。"
            )
        },
        terms: || {
            tr!(
                "The site says it may be used as you see fit, with no further terms or download limits (refreshed here every 24 hours).",
                "網站表示可以依需要任意使用，沒有另外的條款或下載限制（這裡每 24 小時更新）。",
                "サイトによれば必要に応じて自由に使ってよく、ほかの条件やダウンロード制限はありません（ここでは 24 時間ごとに更新）。"
            )
        },
        terms_url: "https://cinsscore.com/#list",
    },
    BuiltinBlocklist {
        key: "blocklist-de-all",
        name: || {
            tr!(
                "blocklist.de (all)",
                "blocklist.de（全部）",
                "blocklist.de（すべて）"
            )
        },
        url: "https://lists.blocklist.de/lists/all.txt",
        homepage: "https://www.blocklist.de/en/export.html",
        family: BlocklistFamily::Both,
        format: BlocklistFormat::Plain,
        refresh_hours: 12,
        description: || {
            tr!(
                "The full list of blocklist.de: addresses that attacked its members' servers in the last 48 hours (brute force and scans against SSH, mail and website logins), regenerated every 30 minutes, with a few IPv6 addresses.",
                "blocklist.de 的完整清單：過去 48 小時攻擊過成員伺服器（SSH、郵件、網站登入的暴力破解與掃描）的位址，每 30 分鐘重新產生，含少量 IPv6。",
                "blocklist.de の完全なリスト：過去 48 時間にメンバーのサーバーを攻撃した（SSH、メール、Web サイトのログインへの総当たり攻撃やスキャン）アドレスです。30 分ごとに再生成され、少数の IPv6 も含みます。"
            )
        },
        terms: || {
            tr!(
                "Free, at your own risk; excessive download volumes are not covered by the free use (downloaded here every 12 hours).",
                "免費提供、使用風險自負；下載量過大時不在免費範圍內（這裡每 12 小時下載一次）。",
                "無料で提供され、利用は自己責任です。ダウンロード量が多すぎる場合は無料の範囲外です（ここでは 12 時間ごとにダウンロード）。"
            )
        },
        terms_url: "https://www.blocklist.de/en/terms.html",
    },
    BuiltinBlocklist {
        key: "ipsum-level3",
        name: || Text::verbatim("IPsum Level 3"),
        url: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        homepage: "https://github.com/stamparm/ipsum",
        family: BlocklistFamily::Ipv4,
        format: BlocklistFormat::Plain,
        refresh_hours: 24,
        description: || {
            tr!(
                "IPsum merges more than 30 public blocklists every day; Level 3 takes only addresses that appear on 3 or more of them, which cuts the false positives of any single source. It also includes some research scanners (Censys and Shadowserver, for example).",
                "IPsum 每天彙整 30 多份公開封鎖清單；Level 3 只收同時出現在 3 份以上的位址，減少單一來源的誤判。也包含部分研究用的掃描器（例如 Censys、Shadowserver）。",
                "IPsum は 30 以上の公開ブロックリストを毎日集約しています。Level 3 は 3 つ以上のリストに同時に載っているアドレスだけを収録し、単一ソースによる誤検知を減らしています。研究目的のスキャナー（Censys、Shadowserver など）も一部含まれます。"
            )
        },
        terms: || {
            tr!(
                "Released under the Unlicense (public domain): free to use; updated once a day (here every 24 hours).",
                "以 Unlicense 釋出（公眾領域），可以自由使用；每天更新一次（這裡每 24 小時）。",
                "Unlicense（パブリックドメイン）で公開されており、自由に使えます。1 日 1 回更新されます（ここでは 24 時間ごと）。"
            )
        },
        terms_url: "https://github.com/stamparm/ipsum/blob/master/LICENSE",
    },
];

/// The terms of both Spamhaus lists.
fn spamhaus_terms() -> Text {
    tr!(
        "Free from Spamhaus, at any scale and for any purpose; credit the source, The Spamhaus Project. Automated downloads at least an hour apart; once a day is enough (refreshed here every 24 hours).",
        "Spamhaus 免費提供，不限規模或用途；使用時須註明來源 The Spamhaus Project。自動下載至少間隔 1 小時，每天一次即可（這裡每 24 小時更新）。",
        "Spamhaus が無料で提供しており、規模や用途の制限はありません。利用時は出典 The Spamhaus Project の表記が必要です。自動ダウンロードは 1 時間以上の間隔を空け、1 日 1 回で十分です（ここでは 24 時間ごとに更新）。"
    )
}

/// The catalogue entry named `key`.
#[must_use]
pub fn builtin(key: &str) -> Option<&'static BuiltinBlocklist> {
    BUILTIN_BLOCKLISTS.iter().find(|b| b.key == key)
}

/// Where `key` stands in the catalogue (its display order); unknown keys sort last.
#[must_use]
pub fn order(key: &str) -> usize {
    BUILTIN_BLOCKLISTS
        .iter()
        .position(|b| b.key == key)
        .unwrap_or(usize::MAX)
}
