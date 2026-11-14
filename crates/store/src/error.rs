use vpn_domain::{ApiError, ErrorCode, Text, tr};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store queue is full")]
    Busy,
    #[error("store is closed")]
    Closed,
    #[error("not found")]
    NotFound,
    #[error("revision conflict: expected {expected}, current {current}")]
    RevisionConflict { expected: u64, current: u64 },
    /// What still references it, in words: the kind and the first few names.
    #[error("still referenced by {}", .0.en)]
    InUse(Text),
    #[error("identity in use by another instance")]
    IdentityInUse,
    #[error("idempotency key reused with a different request")]
    IdempotencyConflict,
    #[error("invalid state: {}", .0.en)]
    InvalidState(Text),
    /// Refused by a rule that has its own public error code (e.g. the Provider egress's direct
    /// exception).
    #[error("refused ({code:?}): {}", .message.en)]
    Refused { code: ErrorCode, message: Text },
    #[error("database integrity check failed: {0}")]
    Corrupt(String),
    #[error("schema version {found} is newer than this binary supports ({supported})")]
    SchemaTooNew { found: i64, supported: i64 },
    #[error("vault: {0}")]
    Vault(String),
    #[error(
        "vault key does not belong to this store (vault.key was replaced or lost; restore the original file)"
    )]
    VaultKeyMismatch,
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("encoding: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(String),
    /// A job panicked or left its transaction open: rolled back, nothing of it stored; the
    /// database goes on with the next job.
    #[error("store job aborted: {0}")]
    Aborted(&'static str),
}

impl StoreError {
    /// SQLite found the disk (or the database's page limit) full: `SQLITE_FULL`.
    #[must_use]
    pub fn is_disk_full(&self) -> bool {
        matches!(
            self,
            Self::Sqlite(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::DiskFull
        )
    }

    /// Map to the public error contract (never leaks SQL or paths).
    #[must_use]
    pub fn to_api(&self) -> ApiError {
        if self.is_disk_full() {
            return ApiError::new(
                ErrorCode::PersistenceUnavailable,
                tr!(
                    "The disk that holds the data directory is full, so nothing can be written; free up disk space first",
                    "資料目錄所在的磁碟已滿，無法寫入；請先釋放磁碟空間",
                    "データディレクトリのあるディスクがいっぱいで書き込めません。先にディスクの空き容量を確保してください"
                ),
            );
        }
        match self {
            Self::Busy => ApiError::new(
                ErrorCode::StoreBusy,
                tr!(
                    "The storage queue is full; try again later",
                    "儲存佇列已滿，請稍後再試",
                    "保存キューがいっぱいです。しばらくしてからもう一度お試しください"
                ),
            ),
            Self::Closed | Self::Io(_) | Self::Sqlite(_) => ApiError::new(
                ErrorCode::PersistenceUnavailable,
                tr!(
                    "Storage is temporarily unavailable",
                    "儲存服務暫時無法使用",
                    "保存機能は一時的に利用できません"
                ),
            ),
            Self::NotFound => {
                ApiError::not_found(tr!("the requested data", "指定的資料", "指定されたデータ"))
            }
            Self::RevisionConflict { .. } => ApiError::new(
                ErrorCode::RevisionConflict,
                tr!(
                    "The data was changed by another operation; reload and try again",
                    "資料已被其他操作更新，請重新載入後再試",
                    "データが別の操作で更新されました。再読み込みしてからもう一度お試しください"
                ),
            ),
            Self::InUse(what) => ApiError::new(
                ErrorCode::InUse,
                tr!(
                    "Cannot delete: still used by {what}",
                    "仍被{what}使用，無法刪除",
                    "{what}で使用中のため削除できません";
                    what = what.clone()
                ),
            ),
            Self::IdentityInUse => ApiError::new(
                ErrorCode::IdentityInUse,
                tr!(
                    "This WireGuard key is in use by another Instance",
                    "這把 WireGuard 金鑰正被另一個 Instance 使用",
                    "この WireGuard 鍵は別の Instance が使用しています"
                ),
            ),
            Self::IdempotencyConflict => ApiError::new(
                ErrorCode::IdempotencyConflict,
                tr!(
                    "This Idempotency-Key was already used for a different request",
                    "同一個 Idempotency-Key 已用於不同的請求",
                    "同じ Idempotency-Key がすでに別のリクエストに使われています"
                ),
            ),
            Self::InvalidState(m) => ApiError::new(ErrorCode::InvalidState, m.clone()),
            Self::Refused { code, message } => ApiError::new(*code, message.clone()),
            Self::Corrupt(_) | Self::SchemaTooNew { .. } => ApiError::new(
                ErrorCode::PersistenceUnavailable,
                tr!(
                    "The database needs maintenance (integrity or version mismatch); writing has stopped",
                    "資料庫需要維護（完整性或版本不符），已停止寫入",
                    "データベースのメンテナンスが必要です（整合性またはバージョンの不一致）。書き込みを停止しました"
                ),
            ),
            Self::Vault(_) | Self::VaultKeyMismatch => ApiError::new(
                ErrorCode::VaultLocked,
                tr!(
                    "The secret vault is unavailable",
                    "秘密金庫無法使用",
                    "シークレット保管庫を利用できません"
                ),
            ),
            Self::Encoding(_) | Self::Aborted(_) => ApiError::internal(),
        }
    }
}
