//! Which file an App runs, and whether it can be trusted to stay the file the user approved.
//!
//! The file must be an absolute path to a regular executable file owned by this user or root, not
//! writable by group or others, in a directory not writable by group or others. A macOS `.app`
//! bundle runs its main executable (`CFBundleExecutable` in `Contents/Info.plist`). The approval
//! records the resolved path and its SHA-256; every start checks both again.
//!
//! Not covered: the same user replacing the file between the check and `exec` (that user could
//! run it directly anyway), and the other files of a bundle (frameworks, plug-ins): only the
//! main executable is hashed.
#![expect(
    unsafe_code,
    reason = "executable checks call access(2) and getuid(2) via libc"
)]

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use vpn_domain::validation::app_path_ok;
use vpn_domain::{
    AppClassInfo, ExecutableApproval, ExecutableCheck, ExecutableKind, Issue, Severity, Text, tr,
};

/// Largest executable that is hashed; anything bigger is refused rather than read for minutes.
pub const MAX_SIZE: u64 = 2 * 1024 * 1024 * 1024;

fn issue(code: &str, message: impl Into<Text>) -> Issue {
    Issue {
        severity: Severity::Error,
        code: code.into(),
        path: "/executable".into(),
        message: message.into(),
    }
}

/// `APP_EXECUTABLE_DIRECTORY`.
fn a_directory() -> Issue {
    issue(
        "APP_EXECUTABLE_DIRECTORY",
        tr!(
            "This is a folder, not an executable",
            "這是資料夾，不是執行檔",
            "これはフォルダーで、実行ファイルではありません"
        ),
    )
}

/// `APP_EXECUTABLE_UNREADABLE` for a file that cannot be read.
fn unreadable(e: &std::io::Error) -> Issue {
    issue(
        "APP_EXECUTABLE_UNREADABLE",
        tr!("Cannot read: {e}", "無法讀取：{e}", "読み取れません：{e}"),
    )
}

/// `APP_EXECUTABLE_TOO_LARGE`.
fn too_large() -> Issue {
    issue(
        "APP_EXECUTABLE_TOO_LARGE",
        tr!(
            "The executable is larger than 2 GiB",
            "執行檔超過 2 GiB",
            "実行ファイルが 2 GiB を超えています"
        ),
    )
}

/// Check `path` as a start would: resolve it, check ownership and permissions, hash it.
/// `private`: directories an executable may not live in (VPN Manager's data, `~/.ssh`).
#[must_use]
pub fn inspect(path: &str, private: &[PathBuf]) -> ExecutableCheck {
    let mut check = ExecutableCheck {
        path: path.into(),
        kind: None,
        resolved: None,
        sha256: None,
        size: None,
        issues: Vec::new(),
        ok: false,
        app_class: None,
    };
    if !app_path_ok(path) {
        check.issues.push(issue(
            "APP_EXECUTABLE",
            tr!(
                "The executable must be an absolute path (without ..)",
                "執行檔必須是絕對路徑（不含 ..）",
                "実行ファイルは絶対パスにしてください（.. を含まないもの）"
            ),
        ));
        return check;
    }
    let (kind, file) = match resolve(Path::new(path)) {
        Ok(r) => r,
        Err(i) => {
            check.issues.push(i);
            return check;
        }
    };
    check.kind = Some(kind);
    check.resolved = Some(file.to_string_lossy().into_owned());
    check.app_class = super::class::classify(Path::new(path), &file, kind);
    check.issues.extend(permission_problems(&file));
    if private
        .iter()
        .any(|p| file.starts_with(super::seatbelt::real_path(p)))
    {
        check.issues.push(issue(
            "APP_EXECUTABLE_PRIVATE",
            tr!(
                "The executable cannot be inside VPN Manager's data directory or the SSH directory",
                "執行檔不可位於 VPN Manager 的資料目錄或 SSH 目錄內",
                "実行ファイルを VPN Manager のデータディレクトリや SSH ディレクトリの中に置くことはできません"
            ),
        ));
    }
    if check.issues.is_empty() {
        match digest(&file) {
            Ok((sha, size)) => {
                check.sha256 = Some(sha);
                check.size = Some(size);
            }
            Err(i) => check.issues.push(i),
        }
    }
    check.ok = !check.issues.iter().any(|i| i.severity == Severity::Error);
    check
}

/// Why a start may not run the approved executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The path no longer resolves to an acceptable file (message for the user).
    Invalid(Text),
    /// It resolves to another file, or the file's content changed: the user must approve it.
    Changed(Text),
}

/// What a start runs: the approved file, and what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub program: PathBuf,
    pub class: Option<AppClassInfo>,
}

/// What `path` is (see [`super::class`]) without hashing it; `None` for an ordinary program or
/// a path that does not resolve (the check reports that).
#[must_use]
pub fn recognise(path: &str) -> Option<AppClassInfo> {
    if !app_path_ok(path) {
        return None;
    }
    let (kind, file) = resolve(Path::new(path)).ok()?;
    super::class::classify(Path::new(path), &file, kind)
}

/// The file to run, if `path` still resolves to the approved file with the approved content.
///
/// # Errors
///
/// [`VerifyError::Invalid`] when the executable fails its checks now, [`VerifyError::Changed`]
/// when it resolves to another file or its SHA-256 differs from the approval.
pub fn verify(
    path: &str,
    approval: &ExecutableApproval,
    private: &[PathBuf],
) -> Result<Verified, VerifyError> {
    let check = inspect(path, private);
    if !check.ok {
        let why = check.issues.first().map_or_else(
            || {
                tr!(
                    "The executable cannot be used",
                    "執行檔無法使用",
                    "実行ファイルを使用できません"
                )
            },
            |i| i.message.clone(),
        );
        return Err(VerifyError::Invalid(why));
    }
    let resolved = check.resolved.unwrap_or_default();
    if resolved != approval.path {
        let approved = &approval.path;
        return Err(VerifyError::Changed(tr!(
            "The executable now points to {resolved}, not to {approved} as when it was approved; check it and approve it again",
            "執行檔現在指向 {resolved}，不是核准時的 {approved}；請確認後重新核准",
            "実行ファイルの参照先が、承認時の {approved} ではなく {resolved} になっています。確認してから再度承認してください"
        )));
    }
    if check.sha256.as_deref() != Some(approval.sha256.as_str()) {
        return Err(VerifyError::Changed(tr!(
            "The executable's content differs from when it was approved (the SHA-256 does not match); check it and approve it again",
            "執行檔的內容與核准時不同（SHA-256 不符）；請確認後重新核准",
            "実行ファイルの内容が承認時と異なります（SHA-256 が一致しません）。確認してから再度承認してください"
        )));
    }
    Ok(Verified {
        program: PathBuf::from(resolved),
        class: check.app_class,
    })
}

fn resolve(p: &Path) -> Result<(ExecutableKind, PathBuf), Issue> {
    let meta = std::fs::metadata(p).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => issue(
            "APP_EXECUTABLE_MISSING",
            tr!(
                "This file cannot be found",
                "找不到這個檔案",
                "このファイルが見つかりません"
            ),
        ),
        std::io::ErrorKind::PermissionDenied => issue(
            "APP_EXECUTABLE_UNREADABLE",
            tr!(
                "This path cannot be read (permission denied)",
                "無法讀取這個路徑（權限不足）",
                "このパスを読み取れません（権限がありません）"
            ),
        ),
        _ => issue(
            "APP_EXECUTABLE_UNREADABLE",
            tr!(
                "This path cannot be read: {e}",
                "無法讀取這個路徑：{e}",
                "このパスを読み取れません：{e}"
            ),
        ),
    })?;
    if meta.is_dir() {
        if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("app")) {
            return bundle_executable(p).map(|f| (ExecutableKind::AppBundle, f));
        }
        return Err(a_directory());
    }
    let file = p.canonicalize().map_err(|e| {
        issue(
            "APP_EXECUTABLE_UNREADABLE",
            tr!(
                "This path cannot be resolved: {e}",
                "無法解析這個路徑：{e}",
                "このパスを解決できません：{e}"
            ),
        )
    })?;
    Ok((ExecutableKind::File, file))
}

/// One string value of a bundle's `Contents/Info.plist` (`Ok(None)`: no such key, or not a
/// string). plutil reads both XML and binary property lists.
#[cfg(target_os = "macos")]
pub(crate) fn info_plist_string(bundle: &Path, key: &str) -> std::io::Result<Option<String>> {
    use std::process::{Command, Stdio};
    let plist = bundle.join("Contents/Info.plist");
    let mut child = Command::new("/usr/bin/plutil")
        .args(["-extract", key, "raw", "-expect", "string", "-o", "-"])
        .arg(&plist)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut out = String::new();
    // A failed read is only logged: plutil's exit status still decides, and it is waited for.
    if let Some(stdout) = child.stdout.take()
        && let Err(e) = stdout.take(4096).read_to_string(&mut out)
    {
        tracing::debug!(error = %e, key, "plutil's answer unreadable");
    }
    let ok = super::wait_bounded(&mut child, std::time::Duration::from_secs(5))
        .is_some_and(|s| s.success());
    let value = out.trim();
    Ok((ok && !value.is_empty()).then(|| value.to_string()))
}

#[cfg(target_os = "macos")]
fn bundle_executable(bundle: &Path) -> Result<PathBuf, Issue> {
    let bad = |m: Text| issue("APP_BUNDLE", m);
    if !bundle.join("Contents/Info.plist").is_file() {
        return Err(bad(tr!(
            "This .app has no Contents/Info.plist",
            "這個 .app 沒有 Contents/Info.plist",
            "この .app には Contents/Info.plist がありません"
        )));
    }
    let name = info_plist_string(bundle, "CFBundleExecutable")
        .map_err(|e| {
            bad(tr!(
                "Cannot read Info.plist: {e}",
                "無法讀取 Info.plist：{e}",
                "Info.plist を読み取れません：{e}"
            ))
        })?
        .unwrap_or_default();
    let name = name.as_str();
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.chars().any(char::is_control)
    {
        return Err(bad(tr!(
            "Info.plist has no usable CFBundleExecutable",
            "Info.plist 沒有可用的 CFBundleExecutable",
            "Info.plist に使用できる CFBundleExecutable がありません"
        )));
    }
    let real_bundle = bundle.canonicalize().map_err(|e| {
        bad(tr!(
            "Cannot resolve this .app: {e}",
            "無法解析這個 .app：{e}",
            "この .app を解決できません：{e}"
        ))
    })?;
    let file = real_bundle
        .join("Contents/MacOS")
        .join(name)
        .canonicalize()
        .map_err(|e| {
            tracing::debug!(error = %e, "a .app's main executable does not resolve");
            bad(tr!(
                "The .app's main executable cannot be found (Contents/MacOS)",
                "找不到 .app 的主執行檔（Contents/MacOS）",
                ".app のメイン実行ファイルが見つかりません（Contents/MacOS）"
            ))
        })?;
    if !file.starts_with(&real_bundle) {
        return Err(bad(tr!(
            "The main executable points outside the .app",
            "主執行檔指向 .app 之外",
            "メイン実行ファイルが .app の外を指しています"
        )));
    }
    Ok(file)
}

#[cfg(not(target_os = "macos"))]
fn bundle_executable(_bundle: &Path) -> Result<PathBuf, Issue> {
    Err(a_directory())
}

fn permission_problems(file: &Path) -> Vec<Issue> {
    let mut out = Vec::new();
    let meta = match std::fs::metadata(file) {
        Ok(m) => m,
        Err(e) => {
            out.push(unreadable(&e));
            return out;
        }
    };
    if !meta.is_file() {
        out.push(issue(
            "APP_EXECUTABLE_NOT_FILE",
            tr!(
                "Not a regular file",
                "不是一般檔案",
                "通常のファイルではありません"
            ),
        ));
        return out;
    }
    let executable = {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(file.as_os_str().as_bytes()).ok();
        // SAFETY: access with a NUL-terminated path we own.
        meta.mode() & 0o111 != 0
            && c.is_some_and(|c| unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0)
    };
    if !executable {
        out.push(issue(
            "APP_EXECUTABLE_NOT_EXECUTABLE",
            tr!(
                "No permission to execute",
                "沒有執行權限",
                "実行権限がありません"
            ),
        ));
    }
    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    if meta.uid() != me && meta.uid() != 0 {
        out.push(issue(
            "APP_EXECUTABLE_OWNER",
            tr!(
                "The file's owner is neither the current user nor root",
                "檔案的擁有者不是目前使用者或 root",
                "ファイルの所有者が現在のユーザーでも root でもありません"
            ),
        ));
    }
    if meta.mode() & 0o022 != 0 {
        out.push(issue(
            "APP_EXECUTABLE_WRITABLE",
            tr!(
                "Other users (the group or everyone) can write to the file",
                "檔案可被其他使用者（群組或所有人）寫入",
                "ほかのユーザー（グループまたは全員）がファイルに書き込めます"
            ),
        ));
    }
    match file.parent().map(std::fs::metadata) {
        Some(Ok(dir)) if dir.mode() & 0o022 != 0 => out.push(issue(
            "APP_EXECUTABLE_DIR_WRITABLE",
            tr!(
                "Other users can write to its folder, so the file could be replaced",
                "所在資料夾可被其他使用者寫入，檔案可能被替換",
                "ファイルのあるフォルダーにほかのユーザーが書き込めるため、ファイルが置き換えられるおそれがあります"
            ),
        )),
        Some(Ok(_)) => {}
        _ => out.push(issue(
            "APP_EXECUTABLE_UNREADABLE",
            tr!(
                "Its folder cannot be read",
                "無法讀取所在資料夾",
                "ファイルのあるフォルダーを読み取れません"
            ),
        )),
    }
    out
}

/// SHA-256 (lowercase hex) and size, read in bounded chunks.
fn digest(file: &Path) -> Result<(String, u64), Issue> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(file)
        .map_err(|e| unreadable(&e))?;
    let size = f.metadata().map_err(|e| unreadable(&e))?.len();
    if size > MAX_SIZE {
        return Err(too_large());
    }
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut read = 0u64;
    loop {
        let n = f.read(&mut buf).map_err(|e| {
            issue(
                "APP_EXECUTABLE_UNREADABLE",
                tr!(
                    "Reading failed: {e}",
                    "讀取失敗：{e}",
                    "読み取りに失敗しました：{e}"
                ),
            )
        })?;
        if n == 0 {
            break;
        }
        read += n as u64;
        if read > MAX_SIZE {
            return Err(too_large());
        }
        hasher.update(&buf[..n]);
    }
    Ok((hex::encode(hasher.finalize()), read))
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn codes(c: &ExecutableCheck) -> Vec<&str> {
        c.issues.iter().map(|i| i.code.as_str()).collect()
    }

    /// An executable script in a private 0700 directory of ours.
    fn script(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("tool");
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn private_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    #[test]
    fn unsafe_files_and_places_are_refused() {
        let d = private_dir();
        let p = script(d.path(), "#!/bin/sh\n");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(codes(&inspect(p.to_str().unwrap(), &[])).contains(&"APP_EXECUTABLE_WRITABLE"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            codes(&inspect(p.to_str().unwrap(), &[])).contains(&"APP_EXECUTABLE_NOT_EXECUTABLE")
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(codes(&inspect(p.to_str().unwrap(), &[])).contains(&"APP_EXECUTABLE_DIR_WRITABLE"));
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // Inside VPN Manager's data directory (or ~/.ssh): refused.
        assert!(
            codes(&inspect(p.to_str().unwrap(), &[d.path().to_path_buf()]))
                .contains(&"APP_EXECUTABLE_PRIVATE")
        );
        assert_eq!(
            codes(&inspect("/nonexistent/x", &[])),
            vec!["APP_EXECUTABLE_MISSING"]
        );
        assert_eq!(
            codes(&inspect(d.path().to_str().unwrap(), &[])),
            vec!["APP_EXECUTABLE_DIRECTORY"]
        );
        assert_eq!(codes(&inspect("relative", &[])), vec!["APP_EXECUTABLE"]);
    }

    #[test]
    fn a_changed_file_or_target_is_a_mismatch() {
        let d = private_dir();
        let p = script(d.path(), "#!/bin/sh\necho one\n");
        let c = inspect(p.to_str().unwrap(), &[]);
        let approval = ExecutableApproval {
            path: c.resolved.clone().unwrap(),
            sha256: c.sha256.clone().unwrap(),
            size: c.size.unwrap(),
            approved_at: vpn_domain::Timestamp::now(),
            app_class: None,
        };
        assert_eq!(
            verify(p.to_str().unwrap(), &approval, &[]),
            Ok(Verified {
                program: p.canonicalize().unwrap(),
                class: None
            })
        );
        std::fs::write(&p, "#!/bin/sh\necho two\n").unwrap();
        assert_matches!(
            verify(p.to_str().unwrap(), &approval, &[]),
            Err(VerifyError::Changed(_))
        );
        // A symlink retargeted to another file is a different file.
        let other = d.path().join("other");
        std::fs::copy(&p, &other).unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        let via_link = inspect(link.to_str().unwrap(), &[]);
        let approval = ExecutableApproval {
            path: via_link.resolved.clone().unwrap(),
            sha256: via_link.sha256.clone().unwrap(),
            size: via_link.size.unwrap(),
            approved_at: vpn_domain::Timestamp::now(),
            app_class: None,
        };
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&other, &link).unwrap();
        assert_matches!(
            verify(link.to_str().unwrap(), &approval, &[]),
            Err(VerifyError::Changed(_))
        );
        std::fs::remove_file(&other).unwrap();
        assert_matches!(
            verify(link.to_str().unwrap(), &approval, &[]),
            Err(VerifyError::Invalid(_))
        );
    }
}
