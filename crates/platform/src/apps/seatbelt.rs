//! macOS Seatbelt (`sandbox-exec`) for `enforced_proxy` Apps.
//!
//! The profile denies all network access except TCP to the App's Gateway on IPv4 loopback, so
//! an App that ignores its proxy settings has no network at all. Measured on macOS 26.6 (and
//! enforced by the tests below):
//! - `(remote tcp "localhost:P")` also admits `[::1]:P`, where any program could listen (the
//!   Gateway binds 127.0.0.1 only); `tcp4` admits IPv4 loopback alone.
//! - Binding is not address-precise: `(local tcp "localhost:*")` (also `tcp4`, `ip4`, and after
//!   a `deny` of `(local ip "*:*")`) lets the App listen on `0.0.0.0` and even on the LAN
//!   address itself, and accept connections from the network.
//! - Inbound cannot be filtered by the peer: `network-inbound` is decided at `listen()`, before
//!   there is a peer — a `(remote …)` filter in its allow makes every `listen` fail, and one in a
//!   `deny` never matches, so a connection from the LAN is accepted whatever it says.
//!   The manager therefore watches every TCP socket of the tree and stops the App on a listener
//!   that is not loopback or on a connection whose local address is not (one that came in from
//!   the network; the App cannot connect out except to the Gateway). That is detection, every
//!   2 s, not prevention: a connection opened and closed between two passes goes unseen.
//! - No UDP is allowed: this Gateway's SOCKS5 UDP relay sits on an ephemeral port, and nothing
//!   of VPN Manager holds UDP on the Gateway port, so allowing it would let the App reach
//!   whichever program binds that UDP port.
//! - The mDNSResponder socket and the DNS-SD / background-download services are refused, so
//!   names resolve only through the proxy (`socks5h`).
//!
//! Every deny carries `(with message "vpnm-app:<run id>")`: the kernel's denial reports in the
//! unified log name the run, however short-lived the process was.
//!
//! Each profile also denies reading one path of the App's own directory, unique to the run, and
//! allows its sibling ([`marker_paths`]): `sandbox_check` on the two finds every process under
//! the run's profile, including one that daemonized out of the tree (a sandbox is inherited and
//! cannot be left). One path would not do: other sandboxes of the user (App Sandbox apps, XPC
//! services) deny reading it too, and they deny both.
//!
//! What this is not: full App isolation. System services the App asks to act for it (XPC
//! services such as `WebKit`'s network process, `LaunchServices` opening another app, certificate
//! checks by trustd) run outside the profile, and Apple does not document `sandbox-exec` as a
//! stable interface.
#![allow(
    unsafe_code,
    reason = "the seatbelt profile timestamp calls localtime_r via libc"
)]

use std::path::{Path, PathBuf};

use vpn_domain::{Text, tr};

pub const TAG_PREFIX: &str = "vpnm-app:";

/// The denial tag of one run.
#[must_use]
pub fn tag(run_id: &str) -> String {
    format!("{TAG_PREFIX}{run_id}")
}

const MARKER_PREFIX: &str = ".vpnm-run-";

/// The file the run's profile denies reading, and its sibling the profile allows like the rest
/// of `dir` (the App's own directory, real path) (`super::proc::RunMarker`).
#[must_use]
pub fn marker_paths(dir: &Path, run_id: &str) -> (PathBuf, PathBuf) {
    (
        dir.join(format!("{MARKER_PREFIX}{run_id}")),
        dir.join(format!("{MARKER_PREFIX}{run_id}.open")),
    )
}

/// Create the run's two marker files in `dir` (empty; the check needs them to exist) and remove
/// those of earlier runs, so the directory holds one pair at most.
///
/// # Errors
///
/// Fails when `dir` cannot be listed or a marker file cannot be written.
pub fn create_markers(dir: &Path, run_id: &str) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)?.flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(MARKER_PREFIX))
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    let (denied, open) = marker_paths(dir, run_id);
    std::fs::write(denied, b"")?;
    std::fs::write(open, b"")
}

/// What one run may do.
#[derive(Debug, Clone)]
pub struct Policy {
    /// `vpnm-app:<run id>`.
    pub tag: String,
    /// The run's [`marker_paths`].
    pub marker: (PathBuf, PathBuf),
    /// The Gateway's port on 127.0.0.1 (TCP only).
    pub gateway_port: u16,
    /// Never readable or writable, whatever else is allowed: VPN Manager's data and socket
    /// directories (vault key, databases, `gateway.key`), `~/.ssh` and the SSH Manager's
    /// directory.
    pub private: Vec<PathBuf>,
    /// The App's own home and temporary directory: readable, writable and usable for Unix
    /// sockets even when they lie inside a private directory.
    pub own: Vec<PathBuf>,
    /// Extra directories the user lets the App write.
    pub writable: Vec<PathBuf>,
}

/// Mach services that resolve names or fetch on a caller's behalf.
const DENIED_SERVICES: [&str; 2] = ["com.apple.dnssd.service", "com.apple.nsurlsessiond"];

/// Device nodes ordinary programs write to.
const DEVICE_WRITES: &str = r#"(literal "/dev/null") (literal "/dev/zero") (literal "/dev/dtracehelper") (literal "/dev/random") (literal "/dev/urandom") (subpath "/dev/fd") (regex #"^/dev/tty")"#;

/// The resolved form of `p` (Seatbelt matches real paths: `/var` is `/private/var`): the
/// longest existing prefix canonicalized, the rest appended.
#[must_use]
pub fn real_path(p: &Path) -> PathBuf {
    let mut missing = Vec::new();
    let mut cur = p.to_path_buf();
    loop {
        if let Ok(real) = cur.canonicalize() {
            return missing.iter().rev().fold(real, |acc, part| acc.join(part));
        }
        match (
            cur.file_name().map(std::ffi::OsStr::to_os_string),
            cur.parent(),
        ) {
            (Some(name), Some(parent)) => {
                missing.push(name);
                cur = parent.to_path_buf();
            }
            _ => return p.to_path_buf(),
        }
    }
}

/// A path as an SBPL string literal. Refuses what cannot be written safely.
fn literal(p: &Path) -> Result<String, Text> {
    let s = p.to_str().ok_or_else(|| {
        let path = p.display();
        tr!(
            "The path is not valid UTF-8: {path}",
            "路徑不是有效的 UTF-8：{path}",
            "パスが有効な UTF-8 ではありません：{path}"
        )
    })?;
    if !s.starts_with('/') || s.chars().any(char::is_control) {
        return Err(tr!(
            "This path cannot be written into the sandbox profile: {s}",
            "無法寫入沙箱設定的路徑：{s}",
            "サンドボックスの設定に書き込めないパスです：{s}"
        ));
    }
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn subpaths(paths: &[PathBuf]) -> Result<String, Text> {
    paths
        .iter()
        .map(|p| literal(p).map(|l| format!("(subpath {l})")))
        .collect::<Result<Vec<_>, _>>()
        .map(|v| v.join(" "))
}

/// The profile for one run. Every `deny` carries the run's tag.
///
/// # Errors
///
/// The reason when the tag is empty or holds a quote, backslash or control character, there is
/// no private directory, or a path is not absolute UTF-8 without control characters.
pub fn profile(p: &Policy) -> Result<String, Text> {
    if p.tag.is_empty()
        || p.tag
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
    {
        return Err(tr!(
            "The sandbox tag is not valid",
            "沙箱標記無效",
            "サンドボックスのタグが無効です"
        ));
    }
    if p.own.is_empty() {
        return Err(tr!(
            "The app needs a private directory",
            "App 需要私有目錄",
            "アプリには専用のディレクトリが必要です"
        ));
    }
    let why = format!("(with message \"{}\")", p.tag);
    let own = subpaths(&p.own)?;
    let unix_local: Vec<String> = p
        .own
        .iter()
        .map(|d| literal(d).map(|l| format!("(local unix-socket (subpath {l}))")))
        .collect::<Result<_, _>>()?;
    let unix_remote: Vec<String> = p
        .own
        .iter()
        .map(|d| literal(d).map(|l| format!("(remote unix-socket (subpath {l}))")))
        .collect::<Result<_, _>>()?;
    let services: Vec<String> = DENIED_SERVICES
        .iter()
        .map(|s| format!("(global-name \"{s}\")"))
        .collect();
    let mut lines = vec![
        "(version 1)".to_string(),
        "(allow default)".to_string(),
        // The only way out: the Gateway, TCP over IPv4 loopback.
        format!("(deny network* {why})"),
        format!(
            "(allow network-outbound (remote tcp4 \"localhost:{}\"))",
            p.gateway_port
        ),
        // The App's own loopback listeners. Not address-precise: a wildcard bind, and what it
        // accepts from the network, is caught by the manager's socket watch.
        "(allow network-bind network-inbound (local tcp \"localhost:*\"))".to_string(),
        // Unix sockets only inside its own directories (e.g. a browser's singleton socket).
        format!("(allow network* {})", unix_local.join(" ")),
        format!("(allow network-outbound {})", unix_remote.join(" ")),
        format!("(deny mach-lookup {} {why})", services.join(" ")),
        format!("(deny file-write* {why})"),
    ];
    let mut writes = vec![DEVICE_WRITES.to_string()];
    if !p.writable.is_empty() {
        writes.push(subpaths(&p.writable)?);
    }
    lines.push(format!("(allow file-write* {})", writes.join(" ")));
    if !p.private.is_empty() {
        // After the user's writable list: a listed directory never opens a private one.
        lines.push(format!(
            "(deny file-read* file-write* {} {why})",
            subpaths(&p.private)?
        ));
    }
    lines.push(format!("(allow file-read* file-write* {own})"));
    // `stat` of the directories above the App's own ones (`mkdir -p` and `realpath` walk them);
    // their contents stay unreadable.
    let mut ancestors: Vec<PathBuf> = Vec::new();
    for dir in &p.own {
        for private in p.private.iter().filter(|pr| dir.starts_with(pr)) {
            let mut a = dir.parent();
            while let Some(anc) = a {
                if !anc.starts_with(private) {
                    break;
                }
                if !ancestors.iter().any(|x| x == anc) {
                    ancestors.push(anc.to_path_buf());
                }
                a = anc.parent();
            }
        }
    }
    if !ancestors.is_empty() {
        let lits: Vec<String> = ancestors
            .iter()
            .map(|a| literal(a).map(|l| format!("(literal {l})")))
            .collect::<Result<_, _>>()?;
        lines.push(format!("(allow file-read-metadata {})", lits.join(" ")));
    }
    // Last, so no rule above can open them: how the run's processes are found. The App may
    // read neither change nor remove them (a missing marker would read as denied to everyone).
    let (denied, open) = (literal(&p.marker.0)?, literal(&p.marker.1)?);
    lines.push(format!("(deny file-read-data (literal {denied}) {why})"));
    lines.push(format!(
        "(deny file-write* (literal {denied}) (literal {open}) {why})"
    ));
    Ok(lines.join("\n") + "\n")
}

/// Whether `sandbox-exec` works on this host and actually enforces a profile (checked once,
/// the first time anyone asks; it runs three short probe processes). `Err` holds the reason
/// shown to the user.
///
/// # Errors
///
/// The reason when `sandbox-exec` is missing, cannot run, or does not enforce the probe profile
/// (always on other systems than macOS).
pub fn available() -> Result<(), Text> {
    static RESULT: std::sync::OnceLock<Result<(), Text>> = std::sync::OnceLock::new();
    RESULT.get_or_init(probe).clone()
}

pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

#[cfg(target_os = "macos")]
fn probe() -> Result<(), Text> {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    if !Path::new(SANDBOX_EXEC).exists() {
        return Err(tr!(
            "This macOS has no /usr/bin/sandbox-exec",
            "此 macOS 沒有 /usr/bin/sandbox-exec",
            "この macOS には /usr/bin/sandbox-exec がありません"
        ));
    }
    let no_port = |e: std::io::Error| {
        tr!(
            "Cannot open a local port for the probe: {e}",
            "無法建立探測用的本機連接埠：{e}",
            "確認用のローカルポートを作成できません：{e}"
        )
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(no_port)?;
    let port = listener.local_addr().map_err(no_port)?.port();
    let run = |profile: &str| -> Result<bool, Text> {
        let mut child = Command::new(SANDBOX_EXEC)
            .args(["-p", profile, "/usr/bin/nc", "-z", "-G", "2", "127.0.0.1"])
            .arg(port.to_string())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                tr!(
                    "sandbox-exec cannot run: {e}",
                    "sandbox-exec 無法執行：{e}",
                    "sandbox-exec を実行できません：{e}"
                )
            })?;
        wait_bounded(&mut child, Duration::from_secs(10))
            .map(|s| s.success())
            .ok_or_else(|| {
                tr!(
                    "The sandbox-exec probe timed out",
                    "sandbox-exec 探測逾時",
                    "sandbox-exec の確認がタイムアウトしました"
                )
            })
    };
    let allowed = format!(
        "(version 1)(allow default)(deny network*)(allow network-outbound (remote tcp4 \"localhost:{port}\"))"
    );
    if !run(&allowed)? {
        return Err(tr!(
            "sandbox-exec cannot apply a profile that allows the Gateway (the probe connection failed)",
            "sandbox-exec 無法套用允許代理埠的設定（探測連線失敗）",
            "sandbox-exec がゲートウェイを許可する設定を適用できません（確認用の接続に失敗しました）"
        ));
    }
    if run("(version 1)(allow default)(deny network*)")? {
        return Err(tr!(
            "sandbox-exec does not really block the network (the probe connection was not refused)",
            "sandbox-exec 沒有實際阻擋網路（探測連線未被拒絕）",
            "sandbox-exec が実際にはネットワークをブロックしていません（確認用の接続が拒否されませんでした）"
        ));
    }
    drop(listener);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn probe() -> Result<(), Text> {
    Err(tr!(
        "Seatbelt (sandbox-exec) is available only on macOS",
        "Seatbelt（sandbox-exec）只在 macOS 提供",
        "Seatbelt（sandbox-exec）は macOS でのみ利用できます"
    ))
}

#[cfg(target_os = "macos")]
use super::wait_bounded;

/// Where a denial count continues: the newest unified-log timestamp already counted
/// (`2026-10-27 21:04:05.123456+0900`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogCursor(pub String);

impl LogCursor {
    /// Start counting at `epoch_secs` (the run's start).
    pub fn at(epoch_secs: i64) -> Option<Self> {
        local_stamp(epoch_secs).map(LogCursor)
    }
}

/// `YYYY-MM-DD HH:MM:SS` in local time, the form `log show --start` takes.
fn local_stamp(epoch_secs: i64) -> Option<String> {
    let t = epoch_secs as libc::time_t;
    // SAFETY: localtime_r writes into the zeroed struct we pass; `t` is a valid time_t.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call.
    if unsafe { libc::localtime_r(&raw const t, &raw mut tm) }.is_null() {
        return None;
    }
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    ))
}

/// Count the kernel's denial reports tagged `tag` after `since`. `None` when the unified log
/// cannot be read (not measurable, never "0"). Bounded: at most 20 s, and lines are counted
/// as they stream.
#[cfg(target_os = "macos")]
pub fn denials(tag: &str, since: &LogCursor) -> Option<(u64, LogCursor)> {
    use std::io::{BufRead, BufReader, Read};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    if tag.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
        return None;
    }
    let start = since.0.get(..19)?;
    let mut child = Command::new("/usr/bin/log")
        .args(["show", "--start", start, "--style", "ndjson", "--predicate"])
        .arg(format!("eventMessage CONTAINS \"{tag}\""))
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn({
        let since = since.0.clone();
        move || {
            let mut count = 0u64;
            let mut newest: Option<String> = None;
            // Each line is bounded; a longer one is skipped, never buffered whole.
            let mut lines = BufReader::new(stdout.take(256 * 1024 * 1024));
            let mut line = Vec::new();
            loop {
                line.clear();
                match lines.by_ref().take(64 * 1024).read_until(b'\n', &mut line) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => return None,
                }
                if line.last() != Some(&b'\n') && line.len() >= 64 * 1024 {
                    // Skip the rest of an over-long line without buffering it.
                    let _ = lines.skip_until(b'\n');
                    continue;
                }
                let Ok(entry) = serde_json::from_slice::<serde_json::Value>(&line) else {
                    continue;
                };
                let (Some(stamp), Some(message)) = (
                    entry.get("timestamp").and_then(|v| v.as_str()),
                    entry.get("eventMessage").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                // Only the kernel's reports (`log` also logs its own query) newer than the cursor.
                if !message.starts_with("Sandbox: ") || !message.contains(" deny(") {
                    continue;
                }
                if stamp <= since.as_str() {
                    continue;
                }
                count += 1;
                if newest.as_deref().is_none_or(|n| stamp > n) {
                    newest = Some(stamp.to_string());
                }
            }
            Some((count, newest))
        }
    });
    let status = wait_bounded(&mut child, Duration::from_secs(20))?;
    let (count, newest) = reader.join().ok()??;
    if !status.success() {
        return None;
    }
    Some((count, newest.map_or_else(|| since.clone(), LogCursor)))
}

#[cfg(not(target_os = "macos"))]
#[must_use]
pub const fn denials(_tag: &str, _since: &LogCursor) -> Option<(u64, LogCursor)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            tag: tag("run-1"),
            marker: marker_paths(Path::new("/private/tmp/vpnm-501-a1"), "run-1"),
            gateway_port: 29210,
            private: vec![PathBuf::from("/state"), PathBuf::from("/Users/me/.ssh")],
            own: vec![
                PathBuf::from("/state/apps/a1/home"),
                PathBuf::from("/private/tmp/vpnm-501-a1"),
            ],
            writable: vec![PathBuf::from("/Users/me/Downloads")],
        }
    }

    #[test]
    fn every_deny_is_tagged_and_the_gateway_is_the_only_way_out() {
        let p = profile(&policy()).unwrap();
        let denies: Vec<&str> = p.lines().filter(|l| l.starts_with("(deny")).collect();
        assert!(denies.len() >= 4, "{p}");
        for d in &denies {
            assert!(
                d.ends_with("(with message \"vpnm-app:run-1\"))"),
                "untagged deny: {d}"
            );
        }
        assert!(p.contains("(deny network* (with message"), "{p}");
        // One destination, IPv4 loopback TCP only: no ::1, no UDP, no other port.
        assert_eq!(p.matches("network-outbound (remote tcp").count(), 1, "{p}");
        assert!(p.contains("(allow network-outbound (remote tcp4 \"localhost:29210\"))"));
        assert!(
            !p.contains("(remote tcp \"")
                && !p.contains("(remote udp")
                && !p.contains("(remote ip")
        );
        assert!(!p.contains("localhost:*\"))\n(allow network-outbound"));
        assert!(p.contains("com.apple.dnssd.service") && p.contains("com.apple.nsurlsessiond"));
    }

    #[test]
    fn private_directories_stay_closed_even_to_listed_writable_paths() {
        let p = profile(&policy()).unwrap();
        let lines: Vec<&str> = p.lines().collect();
        let pos = |needle: &str| {
            lines
                .iter()
                .position(|l| l.starts_with(needle))
                .unwrap_or_else(|| panic!("{needle} missing in {p}"))
        };
        let write_all = pos("(deny file-write*");
        let writable = pos("(allow file-write*");
        let private = pos("(deny file-read* file-write*");
        let own = pos("(allow file-read* file-write*");
        // Later rules win: the private denial comes after the user's list, the App's own
        // directories after the private denial.
        assert!(
            write_all < writable && writable < private && private < own,
            "{p}"
        );
        assert!(lines[writable].contains("(subpath \"/Users/me/Downloads\")"));
        assert!(lines[private].contains("(subpath \"/state\")"));
        assert!(lines[private].contains("(subpath \"/Users/me/.ssh\")"));
        assert!(lines[own].contains("(subpath \"/state/apps/a1/home\")"));
        // Only the directories above the home are stat-able, not their contents.
        let meta = lines[pos("(allow file-read-metadata")];
        for a in ["/state", "/state/apps", "/state/apps/a1"] {
            assert!(meta.contains(&format!("(literal \"{a}\")")), "{meta}");
        }
        assert!(!meta.contains("subpath"));
    }

    #[test]
    fn unsafe_paths_and_tags_are_refused() {
        let mut p = policy();
        p.writable = vec![PathBuf::from("/tmp/a\nb")];
        assert!(profile(&p).is_err());
        let mut p = policy();
        p.tag = "x\")(allow network*".into();
        assert!(profile(&p).is_err());
        let mut p = policy();
        p.writable = vec![PathBuf::from("/q\"x")];
        let s = profile(&p).unwrap();
        assert!(s.contains("(subpath \"/q\\\"x\")"), "{s}");
    }

    #[test]
    fn real_paths_resolve_existing_prefixes() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().canonicalize().unwrap();
        assert_eq!(real_path(&dir.path().join("a/b")), real.join("a/b"));
    }
}

/// The generated profile under the real `sandbox-exec`. "Internet" probes use TEST-NET-1
/// (192.0.2.1, never routed), so even a profile that failed open would reach no one; the
/// "private" files are fakes in a temporary directory, never the real data directory or ~/.ssh.
#[cfg(test)]
#[cfg(target_os = "macos")]
mod real {
    use std::net::TcpListener;
    use std::process::{Command, Stdio};

    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        data: PathBuf,
        home: PathBuf,
        ssh: PathBuf,
        rw: PathBuf,
        outside: PathBuf,
        gateway: TcpListener,
        other: TcpListener,
        profile: String,
        tag: String,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let data = root.join("data");
        let home = data.join("apps/a1/home");
        let ssh = root.join("ssh");
        let rw = root.join("rw");
        let outside = root.join("outside");
        for d in [&home, &ssh, &rw, &outside] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(data.join("vault.key"), "k").unwrap();
        std::fs::write(ssh.join("id_ed25519"), "s").unwrap();
        std::fs::write(outside.join("r"), "r").unwrap();
        let gateway = TcpListener::bind("127.0.0.1:0").unwrap();
        let tag = tag(&format!("t-{}", std::process::id()));
        let profile = profile(&Policy {
            tag: tag.clone(),
            marker: marker_paths(&home, &format!("t-{}", std::process::id())),
            gateway_port: gateway.local_addr().unwrap().port(),
            private: vec![data.clone(), ssh.clone()],
            own: vec![home.clone()],
            writable: vec![rw.clone()],
        })
        .unwrap();
        Fixture {
            _dir: dir,
            data,
            home,
            ssh,
            rw,
            outside,
            gateway,
            other: TcpListener::bind("127.0.0.1:0").unwrap(),
            profile,
            tag,
        }
    }

    /// Run a shell snippet under the profile; (success, combined output).
    fn sh(f: &Fixture, script: &str) -> (bool, String) {
        let out = Command::new(SANDBOX_EXEC)
            .arg("-p")
            .arg(&f.profile)
            .args(["/bin/sh", "-c", script])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &f.home)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    #[test]
    fn the_probe_passes_here() {
        assert_eq!(available(), Ok(()));
    }

    #[test]
    fn only_the_gateway_is_reachable() {
        let f = fixture();
        let gw = f.gateway.local_addr().unwrap().port();
        let other = f.other.local_addr().unwrap().port();
        assert!(sh(&f, &format!("nc -vz -G 3 127.0.0.1 {gw}")).0, "gateway");
        let (ok, out) = sh(&f, &format!("nc -vz -G 3 127.0.0.1 {other}"));
        assert!(
            !ok && out.contains("not permitted"),
            "another local port: {out}"
        );
        let (ok, out) = sh(&f, "nc -vz -G 3 192.0.2.1 443");
        assert!(!ok && out.contains("not permitted"), "TEST-NET: {out}");
        let (ok, out) = sh(&f, &format!("nc -vz -G 3 ::1 {gw}"));
        assert!(
            !ok && out.contains("not permitted"),
            "IPv6 loopback on the Gateway port: {out}"
        );
        let (_, out) = sh(
            &f,
            "echo x | nc -vu -w 1 127.0.0.1 53 2>&1; echo x | nc -vu -w 1 192.0.2.1 53 2>&1",
        );
        assert_eq!(out.matches("not permitted").count(), 2, "UDP: {out}");
    }

    #[test]
    fn private_files_stay_closed_and_writes_are_limited() {
        let f = fixture();
        let q = |p: &Path| format!("'{}'", p.display());
        let (ok, out) = sh(&f, &format!("cat {}", q(&f.data.join("vault.key"))));
        assert!(
            !ok && out.contains("not permitted"),
            "data directory: {out}"
        );
        let (ok, out) = sh(&f, &format!("cat {}", q(&f.ssh.join("id_ed25519"))));
        assert!(!ok && out.contains("not permitted"), "ssh directory: {out}");
        assert!(
            sh(&f, &format!("cat {}", q(&f.outside.join("r")))).0,
            "other files stay readable"
        );
        assert!(
            sh(&f, &format!("touch {}", q(&f.rw.join("w")))).0,
            "listed writable directory"
        );
        assert!(
            !sh(&f, &format!("touch {}", q(&f.outside.join("w")))).0,
            "unlisted directory"
        );
        // Its own home inside the data directory: usable, also through `mkdir -p`.
        let nested = f.home.join("a/b");
        assert!(
            sh(
                &f,
                &format!(
                    "mkdir -p {} && echo hi > {}/f && cat {}/f",
                    q(&nested),
                    q(&nested),
                    q(&nested)
                )
            )
            .0,
            "own home"
        );
        // A symlink in its home pointing into the data directory does not open it.
        let (ok, _) = sh(
            &f,
            &format!(
                "ln -s {} {} && cat {}",
                q(&f.data.join("vault.key")),
                q(&f.home.join("link")),
                q(&f.home.join("link"))
            ),
        );
        assert!(!ok, "symlink into the data directory");
        // A child process inherits the profile.
        let (ok, _) = sh(
            &f,
            &format!("/bin/sh -c \"cat {}\"", q(&f.data.join("vault.key"))),
        );
        assert!(!ok, "child");
    }

    #[test]
    fn denials_are_counted_by_tag_with_a_cursor() {
        let f = fixture();
        let since = LogCursor::at(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .cast_signed()
                - 1,
        )
        .unwrap();
        let other = f.other.local_addr().unwrap().port();
        sh(
            &f,
            &format!("nc -z -G 3 127.0.0.1 {other}; nc -z -G 3 192.0.2.1 443"),
        );
        // The unified log delivers entries late and a denial may be logged more than once:
        // wait until the count stops changing before checking the cursor.
        let mut counted: Option<(u64, LogCursor)> = None;
        let mut stable = 0;
        for _ in 0..40 {
            let now = denials(&f.tag, &since);
            let same = matches!((&now, &counted), (Some((a, _)), Some((b, _))) if a == b);
            stable = if same { stable + 1 } else { 0 };
            counted = now;
            if stable >= 2 && counted.as_ref().is_some_and(|(n, _)| *n >= 2) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        let (n, cursor) = counted.expect("the unified log is readable");
        assert!(n >= 2, "{n}");
        assert_ne!(cursor, since);
        // Count from the cursor, then everything again: an entry that arrived late is counted
        // in both, and nothing before the cursor may be counted twice.
        let after = denials(&f.tag, &cursor).map(|(m, _)| m).expect("readable");
        let total = denials(&f.tag, &since).map(|(t, _)| t).expect("readable");
        assert!(n + after <= total, "counted twice: {n} + {after} > {total}");
    }
}
