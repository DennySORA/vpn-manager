//! The diagnostics report (`GET /v1/system/diagnostics`).
//!
//! It holds the controller's own facts, the manager's report and the conclusions drawn from
//! both. Nothing in it is a secret, a
//! destination or an account number; it is meant to be downloaded and shared.

use vpn_domain::{
    ApiError, BinaryDigest, CheckStatus, ComponentVersions, DIAGNOSTICS_SCHEMA, DatabaseReport,
    DiagnosticCheck, DiagnosticReport, DiskReport, DiskSpaceState, ManagerReport, ProcessReport,
    ReserveState, SshFileState, SshProjectionReport, Text, Timestamp, VaultKeyState, tr,
};
use vpn_ipc::control::{Call, Reply};
use vpn_ipc::identity;

use crate::link::ManagerLink;

/// The data plane's versions: the workspace pins both exactly (`=`), and a test keeps these in
/// step with the pins.
const GOTATUN_VERSION: &str = "0.10.3";
const SMOLTCP_VERSION: &str = "0.14.0";

/// The linked SQLite should have the WAL fix of 3.51.3 (STORE.md).
const SQLITE_MIN: (u32, u32, u32) = (3, 51, 3);

fn version_triple(v: &str) -> Option<(u32, u32, u32)> {
    let mut it = v.split('.').map(|p| p.parse::<u32>().ok());
    Some((it.next()??, it.next()??, it.next().flatten().unwrap_or(0)))
}

fn controller_binary() -> BinaryDigest {
    // nosemgrep: rust.lang.security.current-exe.current-exe -- only shown in the diagnostics report; the digest below is the identity
    let path = std::env::current_exe().map_or_else(|_| "vpnd".into(), |p| p.display().to_string());
    match identity::executable_sha256() {
        Ok((sha256, size)) => BinaryDigest {
            path,
            sha256: Some(sha256.to_string()),
            size_bytes: Some(size),
            error: None,
        },
        Err(e) => BinaryDigest {
            path,
            sha256: None,
            size_bytes: None,
            error: Some(Text::verbatim(e)),
        },
    }
}

/// `12.5 MiB` (binary units, one decimal), as the UI shows sizes.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    #[expect(
        clippy::cast_precision_loss,
        reason = "a size shown with one decimal; precision beyond 2^52 bytes does not matter"
    )]
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

fn check(id: &str, status: CheckStatus, message: impl Into<Text>) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.into(),
        status,
        message: message.into(),
    }
}

/// A size the report gives, or that it is not known.
fn size(bytes: Option<u64>) -> Text {
    bytes.map_or_else(
        || tr!("unknown", "未知", "不明"),
        |n| Text::verbatim(human_bytes(n)),
    )
}

/// Whether both databases still have their reserves.
fn reserves(d: &DiskReport) -> Text {
    match (d.reserve, d.metrics_reserve) {
        (ReserveState::Held, ReserveState::Held) => {
            let each = human_bytes(d.reserve_bytes);
            tr!(
                "the reserves of the control data and the metrics ({each} each) are in place",
                "控制資料與指標的保留空間（各 {each}）已備妥",
                "制御データとメトリクスの予約領域（各 {each}）は確保済みです"
            )
        }
        (control, metrics) => {
            let state = |r: ReserveState| match r {
                ReserveState::Held => tr!("is in place", "已備妥", "確保済みです"),
                ReserveState::Released => tr!(
                    "was given up to writes when the disk was full and is set aside again once there is space",
                    "已在磁碟滿時讓給寫入，有空間後會重新配置",
                    "ディスクが満杯になったときに書き込み用に解放され、空きができると再確保されます"
                ),
                ReserveState::Missing => {
                    tr!("is not set aside yet", "尚未配置", "まだ確保されていません")
                }
            };
            tr!(
                "the control data's reserve {control}, and the metrics' reserve {metrics}",
                "控制資料的保留空間{control}，指標的保留空間{metrics}",
                "制御データの予約領域は{control}。メトリクスの予約領域は{metrics}";
                control = state(control),
                metrics = state(metrics)
            )
        }
    }
}

/// What the metrics database does while the data directory's disk is low, then `reserve` and
/// `problem`.
fn disk_low(d: &DiskReport, reserve: Text, problem: Text) -> Text {
    let full = if d.metrics_full_at.is_some() {
        tr!(
            "the disk was full when metrics were written; ",
            "指標寫入時磁碟已滿；",
            "メトリクスの書き込み時にディスクが満杯でした。"
        )
    } else {
        Text::default()
    };
    let skipped = d.samples_skipped;
    let lost = match skipped {
        0 => Text::default(),
        1 => tr!(
            ", and 1 sample was not saved because it did not fit even by overwriting",
            "，有 1 筆樣本連覆蓋都放不下而沒有保存",
            "。上書きしても収まらず保存されなかったサンプルが 1 件あります"
        ),
        _ => tr!(
            ", and {skipped} samples were not saved because they did not fit even by overwriting",
            "，有 {skipped} 筆樣本連覆蓋都放不下而沒有保存",
            "。上書きしても収まらず保存されなかったサンプルが {skipped} 件あります"
        ),
    };
    let pruned = d.rows_pruned;
    tr!(
        "The data directory's disk is low on space ({free} free, threshold {threshold}): {full}the metrics database no longer grows, new data is still saved, and the {pruned} oldest metrics records were overwritten (marked “Low disk space” on the charts){lost}; control data and secrets are never deleted, {reserve}{problem}",
        "資料目錄的磁碟空間不足（可用 {free}，門檻 {threshold}）：{full}指標資料庫不再變大，新的數據照常保存，已覆蓋 {pruned} 筆最舊的指標資料（圖表上標為「磁碟空間不足」）{lost}；控制資料與秘密不會被刪除，{reserve}{problem}",
        "データディレクトリのディスク容量が不足しています（空き {free}、しきい値 {threshold}）。{full}メトリクスデータベースはこれ以上大きくならず、新しいデータは通常どおり保存され、最も古いメトリクスデータ {pruned} 件を上書きしました（グラフでは「ディスク容量不足」と表示）{lost}。制御データとシークレットは削除されません。{reserve}{problem}";
        free = size(d.free_bytes),
        threshold = size(d.low_threshold_bytes),
        full = full,
        lost = lost,
        reserve = reserve,
        problem = problem
    )
}

/// The data directory's free space: what the metrics database overwrote for it, and whether
/// both databases still have their reserves.
fn disk_check(d: &DiskReport) -> DiagnosticCheck {
    let reserve = reserves(d);
    let problem = d.error.as_ref().map_or_else(
        Text::default,
        |e| tr!(" ({e})", "（{e}）", "（{e}）"; e = e.clone()),
    );
    match d.state {
        DiskSpaceState::Unknown => check(
            "disk_space",
            CheckStatus::Unknown,
            d.error.clone().map_or_else(
                || {
                    tr!(
                        "Cannot read the free space of the data directory",
                        "無法讀取資料目錄的可用空間",
                        "データディレクトリの空き容量を読み取れません"
                    )
                },
                Text::from,
            ),
        ),
        DiskSpaceState::Low => check(
            "disk_space",
            CheckStatus::Warning,
            disk_low(d, reserve, problem),
        ),
        DiskSpaceState::Normal
            if d.reserve != ReserveState::Held
                || d.metrics_reserve != ReserveState::Held
                || d.error.is_some() =>
        {
            check(
                "disk_space",
                CheckStatus::Warning,
                tr!(
                    "{free} free on the data directory's disk; {reserve}{problem}",
                    "資料目錄的磁碟可用 {free}；{reserve}{problem}",
                    "データディレクトリのディスクの空きは {free} です。{reserve}{problem}";
                    free = size(d.free_bytes),
                    reserve = reserve,
                    problem = problem
                ),
            )
        }
        DiskSpaceState::Normal => check(
            "disk_space",
            CheckStatus::Ok,
            tr!(
                "{free} free on the data directory's disk ({total} in all); below {threshold} the metrics database stops growing and overwrites its oldest data instead; {reserve}",
                "資料目錄的磁碟可用 {free}（共 {total}）；低於 {threshold} 時指標資料庫不再變大、改為覆蓋最舊的資料，{reserve}",
                "データディレクトリのディスクの空きは {free} です（合計 {total}）。{threshold} を下回るとメトリクスデータベースはそれ以上大きくならず、最も古いデータを上書きします。{reserve}";
                free = size(d.free_bytes),
                total = size(d.total_bytes),
                threshold = size(d.low_threshold_bytes),
                reserve = reserve
            ),
        ),
    }
}

/// Conclusions from the report: every one says what it saw; unknown stays unknown.
#[must_use]
pub fn checks(
    controller: &ProcessReport,
    manager: Option<&ManagerReport>,
    manager_error: Option<&Text>,
    capabilities_error: Option<&Text>,
) -> Vec<DiagnosticCheck> {
    let mut out = Vec::new();
    let Some(m) = manager else {
        let why = manager_error
            .cloned()
            .unwrap_or_else(|| tr!("no answer", "沒有回應", "応答がありません"));
        out.push(check(
            "manager",
            CheckStatus::Failed,
            tr!(
                "Cannot connect to the manager: {why}",
                "無法連線到 manager：{why}",
                "manager に接続できません：{why}";
                why = why
            ),
        ));
        return out;
    };
    out.push(check(
        "manager",
        CheckStatus::Ok,
        tr!(
            "The manager is connected",
            "manager 已連線",
            "manager に接続しています"
        ),
    ));
    out.extend(build_checks(controller, m));
    for db in &m.databases {
        out.extend(database_checks(db));
    }
    out.extend(state_checks(m));
    out.push(recovery_check(m));
    if let Some(e) = &m.logs_error {
        out.push(check("logs", CheckStatus::Unknown, e.clone()));
    }
    if let Some(e) = capabilities_error {
        out.push(check(
            "capabilities",
            CheckStatus::Unknown,
            tr!(
                "Cannot read this computer's capabilities: {e}",
                "無法讀取這台電腦的能力：{e}",
                "このコンピューターの機能を読み取れません：{e}";
                e = e.clone()
            ),
        ));
    }
    out.push(sqlite_check(m));
    if let Some(ssh) = &m.ssh {
        out.push(ssh_check(ssh));
    }
    out
}

/// Whether controller and manager are one build, and whether vpnctl is usable.
fn build_checks(controller: &ProcessReport, m: &ManagerReport) -> Vec<DiagnosticCheck> {
    let mut out = Vec::new();
    let ours = &controller.build_id;
    let theirs = &m.process.build_id;
    if theirs == ours {
        out.push(check(
            "build",
            CheckStatus::Ok,
            tr!(
                "The controller and the manager are the same build ({ours})",
                "controller 與 manager 是同一個 build（{ours}）",
                "controller と manager は同じビルドです（{ours}）"
            ),
        ));
    } else {
        out.push(check(
            "build",
            CheckStatus::Warning,
            tr!(
                "The controller ({ours}) and the manager ({theirs}) are not the same build",
                "controller（{ours}）與 manager（{theirs}）不是同一個 build",
                "controller（{ours}）と manager（{theirs}）は同じビルドではありません"
            ),
        ));
    }
    let path = &m.vpnctl.path;
    match (&m.vpnctl.sha256, &m.vpnctl.error) {
        (Some(_), _) => out.push(check(
            "vpnctl",
            CheckStatus::Ok,
            tr!(
                "vpnctl is at {path}",
                "vpnctl 在 {path}",
                "vpnctl は {path} にあります"
            ),
        )),
        (None, e) => {
            let why = e.clone().map_or_else(
                || tr!("cannot be read", "無法讀取", "読み取れません"),
                Text::from,
            );
            out.push(check(
                "vpnctl",
                CheckStatus::Warning,
                tr!(
                    "No usable vpnctl ({path}: {why}): the command line and SSH through the VPN cannot be used",
                    "找不到可用的 vpnctl（{path}：{why}）：命令列與 SSH 經 VPN 無法使用",
                    "使用できる vpnctl が見つかりません（{path}：{why}）。コマンドラインと VPN 経由の SSH は使えません";
                    why = why
                ),
            ));
        }
    }
    out
}

/// What a database is called in the checks.
fn database_name(db: &DatabaseReport) -> Text {
    if db.name == "control" {
        tr!("control database", "控制資料庫", "制御データベース")
    } else {
        tr!("metrics database", "指標資料庫", "メトリクスデータベース")
    }
}

/// One database's integrity, schema version and write queue.
fn database_checks(db: &DatabaseReport) -> Vec<DiagnosticCheck> {
    let mut out = Vec::new();
    let detail = &db.quick_check;
    out.push(match db.quick_check_ok {
        Some(true) => check(
            &format!("{}_integrity", db.name),
            CheckStatus::Ok,
            tr!(
                "The {label} passed its integrity check",
                "{label}完整性檢查通過",
                "{label}の整合性チェックに合格しました";
                label = database_name(db)
            ),
        ),
        Some(false) => check(
            &format!("{}_integrity", db.name),
            CheckStatus::Failed,
            tr!(
                "The {label} integrity check found problems: {detail}",
                "{label}完整性檢查發現問題：{detail}",
                "{label}の整合性チェックで問題が見つかりました：{detail}";
                label = database_name(db),
                detail = detail.clone()
            ),
        ),
        None => check(
            &format!("{}_integrity", db.name),
            CheckStatus::Unknown,
            tr!(
                "The {label} integrity check did not finish: {detail}",
                "{label}完整性檢查沒有完成：{detail}",
                "{label}の整合性チェックが完了しませんでした：{detail}";
                label = database_name(db),
                detail = detail.clone()
            ),
        ),
    });
    let supported = db.supported_version;
    out.push(match db.schema_version {
        Some(v) if v == supported => check(
            &format!("{}_schema", db.name),
            CheckStatus::Ok,
            tr!(
                "The {label} schema version is {v}",
                "{label} schema 版本 {v}",
                "{label}のスキーマバージョンは {v} です";
                label = database_name(db)
            ),
        ),
        Some(v) => check(
            &format!("{}_schema", db.name),
            CheckStatus::Warning,
            tr!(
                "The {label} schema version is {v}; this version uses {supported}",
                "{label} schema 版本 {v}，這個版本使用 {supported}",
                "{label}のスキーマバージョンは {v} ですが、このバージョンは {supported} を使います";
                label = database_name(db)
            ),
        ),
        None => check(
            &format!("{}_schema", db.name),
            CheckStatus::Unknown,
            tr!(
                "Cannot read the {label} schema version",
                "無法讀取{label}的 schema 版本",
                "{label}のスキーマバージョンを読み取れません";
                label = database_name(db)
            ),
        ),
    });
    let q = &db.queue;
    let (depth, capacity) = (q.depth, q.capacity);
    out.push(if q.busy_refusals > 0 {
        let refusals = q.busy_refusals;
        check(
            &format!("{}_queue", db.name),
            CheckStatus::Warning,
            tr!(
                "The {label} write queue was full and refused {refusals} writes (now {depth}/{capacity})",
                "{label}的寫入佇列曾經滿載，拒絕了 {refusals} 次寫入（目前 {depth}/{capacity}）",
                "{label}の書き込みキューが満杯になり、{refusals} 回の書き込みを拒否しました（現在 {depth}/{capacity}）";
                label = database_name(db)
            ),
        )
    } else {
        check(
            &format!("{}_queue", db.name),
            CheckStatus::Ok,
            tr!(
                "The {label} write queue: {depth}/{capacity}",
                "{label}的寫入佇列 {depth}/{capacity}",
                "{label}の書き込みキュー：{depth}/{capacity}";
                label = database_name(db)
            ),
        )
    });
    out
}

/// The vault key, the disk and the metrics ingress.
fn state_checks(m: &ManagerReport) -> Vec<DiagnosticCheck> {
    let mut out = Vec::new();
    out.push(match m.vault_key.state {
        VaultKeyState::Matches => check(
            "vault_key",
            CheckStatus::Ok,
            tr!(
                "vault.key matches the key check in the database",
                "vault.key 與資料庫的金鑰檢查相符",
                "vault.key はデータベースの鍵チェックと一致します"
            ),
        ),
        _ => check(
            "vault_key",
            CheckStatus::Failed,
            m.vault_key.detail.clone().unwrap_or_else(|| {
                tr!(
                    "vault.key has a problem",
                    "vault.key 有問題",
                    "vault.key に問題があります"
                )
            }),
        ),
    });
    if let Some(d) = &m.disk {
        out.push(disk_check(d));
    }
    let ingress = &m.metrics_ingress;
    out.push(if ingress.dropped > 0 || ingress.write_failures > 0 {
        let (dropped, failures) = (ingress.dropped, ingress.write_failures);
        check(
            "metrics_ingress",
            CheckStatus::Warning,
            tr!(
                "Metrics writing fell behind: {dropped} samples dropped, {failures} writes failed (gaps on the charts, never filled with 0)",
                "指標寫入落後：丟棄 {dropped} 筆、寫入失敗 {failures} 次（圖表上是缺口，不會補 0）",
                "メトリクスの書き込みが遅れています：{dropped} 件を破棄、書き込み失敗 {failures} 回（グラフでは欠落となり、0 では埋めません）"
            ),
        )
    } else {
        let written = ingress.written;
        check(
            "metrics_ingress",
            CheckStatus::Ok,
            tr!(
                "{written} metrics samples written, none dropped",
                "指標已寫入 {written} 筆，沒有丟棄",
                "メトリクスを {written} 件書き込みました。破棄はありません"
            ),
        )
    });
    out
}

/// Leftover resources and what could not be scanned for them.
fn recovery_check(m: &ManagerReport) -> DiagnosticCheck {
    match (m.recovery_gaps.first(), m.recovery_items) {
        (Some(first), items) => {
            let what = &first.what;
            let place = first
                .path
                .as_deref()
                .map_or_else(Text::default, |p| tr!(" ({p})", "（{p}）", "（{p}）"));
            let more = match m.recovery_gaps.len() - 1 {
                0 => Text::default(),
                1 => tr!(
                    "; 1 more place could not be checked",
                    "；另有 1 處無法檢查",
                    "。ほかに 1 か所を確認できませんでした"
                ),
                n => tr!(
                    "; {n} more places could not be checked",
                    "；另有 {n} 處無法檢查",
                    "。ほかに {n} か所を確認できませんでした"
                ),
            };
            let found = match items {
                0 => Text::default(),
                1 => tr!(
                    "; 1 leftover item was found",
                    "；已找到 1 個遺留項目",
                    "。残留項目が 1 件見つかりました"
                ),
                n => tr!(
                    "; {n} leftover items were found",
                    "；已找到 {n} 個遺留項目",
                    "。残留項目が {n} 件見つかりました"
                ),
            };
            check(
                "recovery",
                CheckStatus::Unknown,
                tr!(
                    "Cannot fully check for leftover resources: {what}{place}: {reason}{more}{found}",
                    "無法完整檢查遺留資源：{what}{place}：{reason}{more}{found}",
                    "残留リソースを完全には確認できません：{what}{place}：{reason}{more}{found}";
                    what = what.clone(),
                    place = place,
                    reason = first.reason.clone(),
                    more = more,
                    found = found
                ),
            )
        }
        (None, 1) => check(
            "recovery",
            CheckStatus::Warning,
            tr!(
                "1 leftover resource or record; check it under “Recovery”",
                "有 1 個遺留的資源或紀錄，請到「恢復」檢查",
                "残留したリソースまたは記録が 1 件あります。「復旧」で確認してください"
            ),
        ),
        (None, n) if n > 0 => check(
            "recovery",
            CheckStatus::Warning,
            tr!(
                "{n} leftover resources or records; check them under “Recovery”",
                "有 {n} 個遺留的資源或紀錄，請到「恢復」檢查",
                "残留したリソースまたは記録が {n} 件あります。「復旧」で確認してください"
            ),
        ),
        (None, _) => check(
            "recovery",
            CheckStatus::Ok,
            tr!(
                "No leftover processes, locks, sockets or temporary files",
                "沒有遺留的程序、鎖、socket 或暫存檔",
                "残留したプロセス、ロック、ソケット、一時ファイルはありません"
            ),
        ),
    }
}

/// The linked SQLite against [`SQLITE_MIN`].
fn sqlite_check(m: &ManagerReport) -> DiagnosticCheck {
    let version = &m.sqlite_version;
    match version_triple(version) {
        Some(v) if v >= SQLITE_MIN => check("sqlite", CheckStatus::Ok, format!("SQLite {version}")),
        Some(_) => {
            let (major, minor, patch) = SQLITE_MIN;
            check(
                "sqlite",
                CheckStatus::Warning,
                tr!(
                    "SQLite {version} is older than the recommended {major}.{minor}.{patch} (WAL fix)",
                    "SQLite {version} 早於建議的 {major}.{minor}.{patch}（WAL 修正）",
                    "SQLite {version} は推奨の {major}.{minor}.{patch}（WAL の修正）より古いバージョンです"
                ),
            )
        }
        None => check(
            "sqlite",
            CheckStatus::Unknown,
            tr!(
                "Cannot parse SQLite version {version}",
                "無法解讀 SQLite 版本 {version}",
                "SQLite のバージョン {version} を解釈できません"
            ),
        ),
    }
}

/// The SSH projection: its last error, its file and its hosts.
fn ssh_check(ssh: &SshProjectionReport) -> DiagnosticCheck {
    match (&ssh.last_error, ssh.file) {
        (Some(e), _) => check(
            "ssh",
            CheckStatus::Warning,
            tr!(
                "The SSH configuration was not written: {e}",
                "SSH 設定沒有寫入：{e}",
                "SSH 設定は書き込まれていません：{e}";
                e = e.clone()
            ),
        ),
        (None, SshFileState::Modified) => check(
            "ssh",
            CheckStatus::Warning,
            tr!(
                "vpn-manager.conf was edited by hand; VPN Manager does not overwrite it",
                "vpn-manager.conf 被手動修改過，VPN Manager 不會覆寫",
                "vpn-manager.conf は手動で変更されています。VPN Manager は上書きしません"
            ),
        ),
        (None, SshFileState::Unsafe) => check(
            "ssh",
            CheckStatus::Warning,
            tr!(
                "vpn-manager.conf is unsafe (a symbolic link, or its permissions); it is not written",
                "vpn-manager.conf 不安全（符號連結或權限），不會寫入",
                "vpn-manager.conf は安全ではありません（シンボリックリンクまたは権限）。書き込みません"
            ),
        ),
        _ => ssh.hosts.map_or_else(
            || {
                check(
                    "ssh",
                    CheckStatus::Unknown,
                    ssh.hosts_error.clone().map_or_else(
                        || {
                            tr!(
                                "Cannot read the SSH hosts",
                                "無法讀取 SSH 主機",
                                "SSH ホストを読み取れません"
                            )
                        },
                        Text::from,
                    ),
                )
            },
            |n| {
                check(
                    "ssh",
                    CheckStatus::Ok,
                    if n == 1 {
                        tr!("1 SSH host", "SSH 主機 1 台", "SSH ホスト 1 台")
                    } else {
                        tr!("{n} SSH hosts", "SSH 主機 {n} 台", "SSH ホスト {n} 台")
                    },
                )
            },
        ),
    }
}

/// Whether something keeps this host's clock synchronized: what is recorded and every expiry
/// is judged by it.
fn clock_check(synchronized: bool) -> DiagnosticCheck {
    if synchronized {
        check(
            "clock",
            CheckStatus::Ok,
            tr!(
                "The host clock is synchronized",
                "主機時間已同步",
                "ホストの時刻は同期されています"
            ),
        )
    } else {
        check(
            "clock",
            CheckStatus::Warning,
            tr!(
                "The host clock is not synchronized (no time synchronization service such as NTP, or not synchronized yet): recorded times and every expiry follow this clock; enable time synchronization on the host, for example systemd-timesyncd or chrony",
                "主機時間沒有同步（沒有 NTP 等時間同步服務，或還沒同步上）：記錄的時間與到期判斷都照這個時鐘；請在主機啟用時間同步，例如 systemd-timesyncd 或 chrony",
                "ホストの時刻が同期されていません（NTP などの時刻同期サービスがないか、まだ同期していません）。記録される時刻と期限の判定はすべてこの時計に従います。ホストで時刻同期を有効にしてください（例：systemd-timesyncd、chrony）"
            ),
        )
    }
}

/// Assemble the full report. The manager being unreachable is part of the answer, not an error.
pub async fn report(link: &ManagerLink) -> DiagnosticReport {
    let controller = vpn_platform::resources::process_report(
        "controller",
        identity::VERSION,
        identity::build_id(),
        identity::GIT_REV,
        controller_binary(),
    );
    let (manager, manager_error) = match link.call(Call::Diagnostics).await {
        Ok(Reply::Diagnostics(m)) => (Some(*m), None),
        Ok(_) => (None, Some(ApiError::internal().message)),
        Err(e) => (None, Some(e.message)),
    };
    let (capabilities, capabilities_error) = match &manager {
        Some(_) => match link.call(Call::System).await {
            Ok(Reply::System(s)) => (s.capabilities, None),
            Ok(_) => (Vec::new(), Some(ApiError::internal().message)),
            Err(e) => (Vec::new(), Some(e.message)),
        },
        // Already said by `manager_error`.
        None => (Vec::new(), None),
    };
    let mut checks = checks(
        &controller,
        manager.as_ref(),
        manager_error.as_ref(),
        capabilities_error.as_ref(),
    );
    // This host's clock, whatever the manager says (only Linux tells).
    if let Some(synchronized) = vpn_platform::clock::synchronized() {
        checks.push(clock_check(synchronized));
    }
    DiagnosticReport {
        schema_version: DIAGNOSTICS_SCHEMA,
        redacted: true,
        generated_at: Timestamp::now(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        components: ComponentVersions {
            gotatun: GOTATUN_VERSION.into(),
            smoltcp: SMOLTCP_VERSION.into(),
            sqlite: manager.as_ref().map(|m| m.sqlite_version.clone()),
        },
        checks,
        controller,
        manager,
        manager_error: manager_error.clone(),
        capabilities,
        capabilities_error,
    }
}
