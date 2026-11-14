//! What `vpnctl` prints: the API's JSON with `--json`, otherwise short Traditional Chinese text
//! with aligned columns (CJK characters are two columns wide in a terminal).

use serde::Serialize;
use vpn_domain::{
    CheckStatus, EnforcedLimit, GatewayKind, InstanceView, LimitKind, LimitMechanism, Phase,
    ResourceStatus, Timestamp,
};

/// Output mode of one invocation.
#[derive(Clone, Copy)]
pub struct Out {
    pub json: bool,
}

impl Out {
    /// Print `value` as pretty JSON (only in `--json` mode).
    pub fn json<T: Serialize + ?Sized>(self, value: &T) {
        if self.json {
            match serde_json::to_string_pretty(value) {
                Ok(s) => println!("{s}"),
                Err(e) => eprintln!("vpnctl: 無法輸出 JSON：{e}"),
            }
        }
    }

    /// Print a line of human output (not in `--json` mode).
    pub fn line(self, text: impl AsRef<str>) {
        if !self.json {
            println!("{}", text.as_ref());
        }
    }
}

/// Columns a character takes in a terminal: East Asian wide and fullwidth forms take two.
const fn char_width(c: char) -> usize {
    let u = c as u32;
    let wide = matches!(u,
        0x1100..=0x115F
            | 0x2E80..=0x303E
            | 0x3041..=0x33FF
            | 0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xA000..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE30..=0xFE4F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x20000..=0x3FFFD);
    if wide { 2 } else { 1 }
}

pub fn width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// Aligned columns, two spaces apart; the last column is not padded.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let n = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| width(h)).collect();
    for r in rows {
        for (i, cell) in r.iter().enumerate().take(n) {
            widths[i] = widths[i].max(width(cell));
        }
    }
    let line = |cells: Vec<&str>| {
        let mut out = String::new();
        for (i, cell) in cells.iter().enumerate() {
            out.push_str(cell);
            if i + 1 < cells.len() {
                out.push_str(&" ".repeat(widths[i] - width(cell) + 2));
            }
        }
        out.trim_end().to_string()
    };
    let mut out = vec![line(headers.to_vec())];
    for r in rows {
        out.push(line(r.iter().map(String::as_str).collect()));
    }
    out.join("\n")
}

/// The same words as the web UI.
pub const fn phase_label(p: Phase) -> &'static str {
    match p {
        Phase::Stopped => "已停止",
        Phase::Starting => "啟動中",
        Phase::Connecting => "握手中",
        Phase::Verifying => "驗證 DNS",
        Phase::Ready => "已連線",
        Phase::Degraded => "不穩定",
        Phase::Reconnecting => "重新連線中",
        Phase::Stopping => "停止中",
        Phase::Failed => "需要處理",
        Phase::RecoveryRequired => "需人工確認",
    }
}

/// An Instance's state in one word: a decision it waits for first, then an emergency latch,
/// unknown when there is no status.
pub fn instance_state(v: &InstanceView) -> String {
    match &v.status {
        None => "狀態未知".into(),
        Some(s) if s.phase == Phase::RecoveryRequired => phase_label(s.phase).into(),
        Some(s) if s.intent.emergency_latched => "已急停".into(),
        Some(s) => phase_label(s.phase).into(),
    }
}

/// Fault code of a connection held closed because a stop from before the manager's restart is
/// not on disk (the manager's `STOP_NOT_CONFIRMED`).
const STOP_NOT_CONFIRMED: &str = "STOP_NOT_CONFIRMED";

/// For a connection that waits for the user's decision (`recovery_required`): why, and the
/// commands that decide it. None for any other connection.
pub fn recovery_help(v: &InstanceView) -> Option<(String, String)> {
    let s = v
        .status
        .as_ref()
        .filter(|s| s.phase == Phase::RecoveryRequired)?;
    let why = s
        .recovery
        .last_fault
        .as_ref()
        .filter(|f| f.code == STOP_NOT_CONFIRMED)
        .map_or_else(
            || "無法證明先前狀態，為安全起見保持封鎖，等你確認。".into(),
            |f| f.message.clone(),
        );
    let id = short(&v.spec.id);
    let how = if s.intent.emergency_latched {
        format!(
            "維持急停：vpnctl emergency-stop {id}；恢復連線：先 vpnctl instance clear-emergency {id}，再 vpnctl instance start {id}"
        )
    } else {
        format!("確認停止：vpnctl instance stop {id}；重新連線：vpnctl instance start {id}")
    };
    Some((why.zh_tw.clone(), how))
}

/// The lines under a list of connections for those that wait for the user's decision.
pub fn recovery_lines(list: &[InstanceView]) -> Vec<String> {
    let mut out = Vec::new();
    for v in list {
        if let Some((why, how)) = recovery_help(v) {
            out.push(format!("「{}」需人工確認：{why}", v.spec.name));
            out.push(format!("  處理方式：{how}"));
        }
    }
    out
}

pub const fn check_label(s: CheckStatus) -> &'static str {
    match s {
        CheckStatus::Ok => "正常",
        CheckStatus::Warning => "警告",
        CheckStatus::Failed => "失敗",
        CheckStatus::Unknown => "未知",
    }
}

pub const fn gateway_kind(k: GatewayKind) -> &'static str {
    match k {
        GatewayKind::Mixed => "Mixed（SOCKS5＋HTTP）",
        GatewayKind::Socks5 => "SOCKS5",
        GatewayKind::Http => "HTTP",
    }
}

/// Bytes with a binary unit.
#[expect(
    clippy::cast_precision_loss,
    reason = "display only: one decimal of a binary unit, far coarser than f64's precision"
)]
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

pub fn opt_bytes(n: Option<u64>) -> String {
    n.map_or_else(|| "—".into(), bytes)
}

/// A bandwidth cap: `20 Mbit/s`, `0.5 Mbit/s`, or 不限.
#[expect(
    clippy::cast_precision_loss,
    reason = "display only: three decimals of Mbit/s, far coarser than f64's precision"
)]
pub fn cap(bps: Option<u64>) -> String {
    bps.map_or_else(
        || "不限".into(),
        |b| {
            let m = b as f64 / 1e6;
            let text = format!("{m:.3}");
            format!(
                "{} Mbit/s",
                text.trim_end_matches('0').trim_end_matches('.')
            )
        },
    )
}

const fn limit_label(kind: LimitKind) -> &'static str {
    match kind {
        LimitKind::Memory => "記憶體",
        LimitKind::Cpu => "CPU",
        LimitKind::Processes => "程序（含執行緒）",
        LimitKind::OpenFiles => "開啟檔案",
    }
}

fn limit_value(e: &EnforcedLimit) -> String {
    match e.kind {
        LimitKind::Memory => bytes(e.value),
        LimitKind::Cpu => format!("{}%", e.value),
        LimitKind::Processes | LimitKind::OpenFiles => e.value.to_string(),
    }
}

/// How the OS confines a tree, one line per fact: limits in force by mechanism, limits not in
/// force with the reason, and the cgroup's use.
pub fn resources(r: &ResourceStatus) -> Vec<String> {
    let mut out = Vec::new();
    for (mechanism, label) in [
        (LimitMechanism::Cgroup, "cgroup"),
        (LimitMechanism::Rlimit, "rlimit"),
    ] {
        let set: Vec<String> = r
            .enforced
            .iter()
            .filter(|e| e.mechanism == mechanism)
            .map(|e| format!("{} {}", limit_label(e.kind), limit_value(e)))
            .collect();
        if !set.is_empty() {
            out.push(format!("{label}：{}", set.join("、")));
        }
    }
    for e in r.enforced.iter().filter(|e| e.note.is_some()) {
        out.push(format!(
            "{}：{}",
            limit_label(e.kind),
            e.note.as_ref().map_or("", |n| n.zh_tw.as_str())
        ));
    }
    let mut reasons: Vec<(&str, Vec<&str>)> = Vec::new();
    for u in &r.unenforced {
        match reasons.iter_mut().find(|(why, _)| *why == u.reason.zh_tw) {
            Some((_, kinds)) => kinds.push(limit_label(u.kind)),
            None => reasons.push((u.reason.zh_tw.as_str(), vec![limit_label(u.kind)])),
        }
    }
    for (why, kinds) in reasons {
        out.push(format!("{}上限未生效：{why}", kinds.join("、")));
    }
    if let Some(m) = r.memory_bytes {
        let oom = r
            .oom_kills
            .map_or_default(|n| format!("，記憶體超限被結束 {n} 次"));
        out.push(format!(
            "使用中：記憶體 {}{oom}（{}）",
            bytes(m),
            r.cgroup.as_deref().unwrap_or("—")
        ));
    }
    if out.is_empty() {
        out.push("沒有設定上限".into());
    }
    out
}

/// A duration in seconds, in the largest sensible units.
pub fn duration(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d} 天 {h} 小時")
    } else if h > 0 {
        format!("{h} 小時 {m} 分")
    } else if m > 0 {
        format!("{m} 分 {s} 秒")
    } else {
        format!("{s} 秒")
    }
}

/// A time, as `2026-10-27 11:45 UTC`.
pub fn time(t: &Timestamp) -> String {
    let s = t.to_string();
    match (s.get(..10), s.get(11..16)) {
        (Some(d), Some(hm)) => format!("{d} {hm} UTC"),
        _ => s,
    }
}

pub fn opt_time(t: Option<&Timestamp>) -> String {
    t.map_or_else(|| "—".into(), time)
}

/// The first 8 characters of an id (as the web UI shows them).
pub fn short(id: &impl ToString) -> String {
    id.to_string().chars().take(8).collect()
}
