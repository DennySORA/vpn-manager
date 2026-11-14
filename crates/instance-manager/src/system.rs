//! What the manager reports about itself for the diagnostics report.
//!
//! That is its process and program, the Store's files, schemas, integrity and queues, the vault key on disk, the metrics
//! ingress, owned resources and the SSH projection.
//!
//! Only facts that carry no secret, destination or account: sizes, versions, counts, states.
//! Entity contents (names, endpoints, host names, labels) are never part of it.

use std::path::Path;
use std::time::Duration;

use vpn_domain::{
    BinaryDigest, DatabaseReport, FileReport, ManagerReport, MetricsIngressReport, PhaseCount,
    SshHost, SshProjectionReport, Text, Timestamp, VaultKeyReport, VaultKeyState, tr,
};
use vpn_ipc::identity;
use vpn_platform::keystore::{self, KeyFileError};
use vpn_platform::probe;
use vpn_store::{Database, Store};

use crate::Manager;
use crate::rpc::SystemFacts;

/// Longest a `quick_check` may run before the report says so instead of waiting.
const QUICK_CHECK_DEADLINE: Duration = Duration::from_secs(10);
/// Most log files listed.
const LOGS_MAX: usize = 32;

/// SHA-256 of a program file as it is on disk now.
#[must_use]
pub fn binary_digest(path: &Path) -> BinaryDigest {
    match identity::file_sha256(path) {
        Ok((sha256, size)) => BinaryDigest {
            path: path.display().to_string(),
            sha256: Some(sha256),
            size_bytes: Some(size),
            error: None,
        },
        Err(e) => BinaryDigest {
            path: path.display().to_string(),
            sha256: None,
            size_bytes: None,
            error: Some(if e.kind() == std::io::ErrorKind::NotFound {
                tr!(
                    "The file does not exist",
                    "檔案不存在",
                    "ファイルが存在しません"
                )
            } else {
                Text::of_io_error(&e)
            }),
        },
    }
}

/// The running program, hashed once at start.
#[must_use]
pub fn own_binary(exe: &Path) -> BinaryDigest {
    match identity::executable_sha256() {
        Ok((sha256, size)) => BinaryDigest {
            path: exe.display().to_string(),
            sha256: Some(sha256.to_string()),
            size_bytes: Some(size),
            error: None,
        },
        Err(e) => BinaryDigest {
            path: exe.display().to_string(),
            sha256: None,
            size_bytes: None,
            error: Some(Text::verbatim(e)),
        },
    }
}

fn file_report(name: &str, path: &Path) -> FileReport {
    FileReport {
        name: name.into(),
        path: path.display().to_string(),
        size_bytes: probe::file_size(path),
    }
}

async fn database(store: &Store, which: Database) -> DatabaseReport {
    let path = store.dir().join(which.file());
    let wal = store.dir().join(format!("{}-wal", which.file()));
    let schema_version = store.schema_version(which).await.ok();
    let (quick_check_ok, quick_check) =
        match tokio::time::timeout(QUICK_CHECK_DEADLINE, store.quick_check(which)).await {
            Ok(Ok(answer)) => (Some(answer == "ok"), Text::verbatim(answer)),
            Ok(Err(e)) => (
                None,
                tr!(
                    "Could not run: {why}",
                    "無法執行：{why}",
                    "実行できませんでした：{why}";
                    why = e.to_api().message
                ),
            ),
            Err(_) => {
                let secs = QUICK_CHECK_DEADLINE.as_secs();
                (
                    None,
                    tr!(
                        "Did not finish within {secs} seconds",
                        "{secs} 秒內沒有完成",
                        "{secs} 秒以内に完了しませんでした"
                    ),
                )
            }
        };
    DatabaseReport {
        name: which.name().into(),
        path: path.display().to_string(),
        size_bytes: probe::file_size(&path),
        wal_bytes: probe::file_size(&wal),
        schema_version,
        supported_version: which.supported_version(),
        quick_check_ok,
        quick_check,
        queue: store.queue_health(which),
    }
}

/// `vault.key` as it is on disk now, compared with the key the Store's secrets are sealed with.
fn vault_key(store: &Store, path: &Path) -> VaultKeyReport {
    match keystore::read_key_file(path) {
        Ok(key) if store.is_vault_key(&key) => VaultKeyReport {
            state: VaultKeyState::Matches,
            detail: None,
        },
        Ok(_) => VaultKeyReport {
            state: VaultKeyState::Mismatch,
            detail: Some(tr!(
                "The vault.key on disk is no longer the key in use: the next manager start will be refused. Put the original file back",
                "磁碟上的 vault.key 已不是目前使用的金鑰：下次啟動 manager 會被拒絕。請放回原本的檔案",
                "ディスク上の vault.key は現在使用中の鍵ではなくなっています。次回の manager の起動は拒否されます。元のファイルを戻してください"
            )),
        },
        Err(KeyFileError::Missing) => VaultKeyReport {
            state: VaultKeyState::Missing,
            detail: Some(tr!(
                "vault.key is missing: the next manager start will be refused. Restore it from a backup",
                "vault.key 不見了：下次啟動 manager 會被拒絕。請從備份放回",
                "vault.key が見つかりません。次回の manager の起動は拒否されます。バックアップから戻してください"
            )),
        },
        Err(KeyFileError::Unsafe) => VaultKeyReport {
            state: VaultKeyState::Unsafe,
            detail: Some(tr!(
                "The owner, permissions (must be 0600) or length of vault.key are wrong: the next start will be refused",
                "vault.key 的擁有者、權限（必須是 0600）或長度不對：下次啟動會被拒絕",
                "vault.key の所有者、権限（0600 である必要があります）、または長さが正しくありません。次回の起動は拒否されます"
            )),
        },
        Err(KeyFileError::Io(e)) => VaultKeyReport {
            state: VaultKeyState::Unreadable,
            detail: Some(tr!(
                "Cannot read vault.key: {e}",
                "無法讀取 vault.key：{e}",
                "vault.key を読み取れません：{e}"
            )),
        },
    }
}

/// The log files, and why the directory could not be read (a missing one has none: the
/// manager then logs to its supervisor, e.g. on the dev stack).
fn logs(dir: &Path) -> (Vec<FileReport>, Option<Text>) {
    let it = match std::fs::read_dir(dir) {
        Ok(it) => it,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Vec::new(), None),
        Err(e) => {
            return (
                Vec::new(),
                Some(tr!(
                    "Cannot read the log directory: {e}",
                    "無法讀取日誌目錄：{e}",
                    "ログディレクトリを読み取れません：{e}"
                )),
            );
        }
    };
    #[expect(
        clippy::case_sensitive_file_extension_comparisons,
        reason = "the manager writes these log names itself, in lower case; `.log` alone counts too"
    )]
    let mut out: Vec<FileReport> = it
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            (name.ends_with(".log") || name.ends_with(".log.1"))
                .then(|| file_report(&name, &e.path()))
        })
        .filter(|f| f.size_bytes.is_some())
        .take(LOGS_MAX)
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    (out, None)
}

/// The manager's part of `GET /v1/system/diagnostics`.
pub async fn report(manager: &Manager, store: &Store, facts: &SystemFacts) -> ManagerReport {
    let paths = manager.paths();
    let exe = manager.exe();
    let process = vpn_platform::resources::process_report(
        "manager",
        identity::VERSION,
        identity::build_id(),
        identity::GIT_REV,
        own_binary(exe),
    );
    let databases = vec![
        database(store, Database::Control).await,
        database(store, Database::Metrics).await,
    ];
    let (stats, queued) = manager.metrics_ingress();
    let statuses = manager.statuses().await;
    let mut phases: Vec<PhaseCount> = Vec::new();
    for s in &statuses {
        match phases.iter_mut().find(|p| p.phase == s.phase) {
            Some(p) => p.count += 1,
            None => phases.push(PhaseCount {
                phase: s.phase,
                count: 1,
            }),
        }
    }
    let (logs, logs_error) = logs(&paths.logs());
    let inspection = crate::recovery::inspect(
        manager,
        store,
        facts.ssh.as_deref().map(super::ssh::SshProjector::ssh_dir),
    )
    .await;
    let ssh = match &facts.ssh {
        Some(ssh) => {
            let s = ssh.status(store).await;
            let (hosts, hosts_error) = match store.list::<SshHost>().await {
                Ok(h) => (Some(u32::try_from(h.len()).unwrap_or(u32::MAX)), None),
                Err(e) => (
                    None,
                    Some(tr!(
                        "Cannot read the SSH hosts: {why}",
                        "無法讀取 SSH 主機：{why}",
                        "SSH ホストを読み取れません：{why}";
                        why = e.to_api().message
                    )),
                ),
            };
            Some(SshProjectionReport {
                available: s.available,
                include: s.include,
                file: s.file,
                pending: s.pending,
                hosts,
                hosts_error,
                last_error: s.last_error,
            })
        }
        None => None,
    };
    ManagerReport {
        process,
        vpnctl: binary_digest(&exe.with_file_name("vpnctl")),
        installation_id: store.installation_id(),
        data_dir: paths.state.display().to_string(),
        run_dir: paths.run.display().to_string(),
        sqlite_version: Store::sqlite_version().to_string(),
        databases,
        vault_key: vault_key(store, &paths.vault_key()),
        files: vec![
            file_report("vault.key", &paths.vault_key()),
            file_report("gateway.key", &paths.gateway_key()),
        ],
        logs,
        logs_error,
        metrics_ingress: MetricsIngressReport {
            queued_now: u32::try_from(queued).unwrap_or(u32::MAX),
            accepted: stats.queued,
            written: stats.written,
            duplicates: stats.duplicates,
            stale: stats.stale,
            dropped: stats.dropped,
            write_failures: stats.write_failures,
        },
        instances: phases,
        recovery_items: u32::try_from(inspection.len()).unwrap_or(u32::MAX),
        recovery_gaps: inspection.gaps().to_vec(),
        resources: inspection.resources,
        ssh,
        disk: Some(store.disk_report()),
        observed_at: Timestamp::now(),
    }
}
