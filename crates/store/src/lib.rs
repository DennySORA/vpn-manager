//! Store: the only owner of SQLite in VPN Manager. Two databases (control, metrics) with
//! independent writers, a secret vault, revisioned entities, durable Instance intents with an
//! unqueued priority lane for stop/emergency latches, identity leases and idempotent operations.
//!
//! Nothing here performs network or OS work inside a transaction.

mod apps;
mod bootstrap;
mod db;
mod disk;
mod entities;
mod error;
mod forwards;
mod metrics;
mod num;
mod provider;
mod resources;
mod schema;
mod scrub;
mod security;
mod ssh_download;
mod text_column;
mod vault;

use std::path::Path;
use std::sync::Arc;

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use vpn_domain::{
    ApiError, DesiredState, DiskReport, ErrorCode, GatewayId, InstallationId, InstanceId,
    InstanceSpec, OP_INSTANCE_EMERGENCY_STOP, OP_INSTANCE_STOP, Operation, OperationId,
    OperationStatus, QueueHealth, SecretId, SecretRef, Settings, Timestamp, tr,
};
use zeroize::Zeroizing;

pub use apps::{AppIntentRow, AppRunRecord};
pub use bootstrap::{
    BootstrapRow, ChildClaim, GrantEnd, REASON_CHILD_GONE, REASON_EGRESS_CHANGED,
    REASON_MANAGER_RESTARTED, REASON_PROMOTE_TIMEOUT, REASON_SEAL_RECOVERED, RESERVATION_TTL,
    initial_bootstrap_key,
};
pub use db::Durability;
pub use disk::{
    LOW_SPACE_CAP, LOW_SPACE_PERCENT, METRICS_RESERVE_FILE, MetricsSpace, RESERVE_BYTES,
    RESERVE_FILE, Space, SpaceProbe, Statvfs, low_threshold, resume_threshold,
};
pub use entities::Entity;
pub use error::StoreError;
pub use forwards::ForwardEvidence;
pub use metrics::{
    Appended, ConnectCounters, DroppedSpan, GatewaySample, HOUR_RETENTION_MS, Hist,
    MINUTE_RETENTION_MS, MetricSample, MetricsPolicy, MetricsStoreStatus, RetentionReport,
    RollupReport, SAMPLE_INTERVAL_MS, SshBytes,
};
pub use resources::{
    RESOURCE_MAX_GAP_MS, RESOURCE_SAMPLE_INTERVAL_MS, ResourceDropped, ResourceGap,
    ResourceGapKind, ResourceIdentity, ResourceQuery, ResourceRetention, ResourceSample,
    RoleBucket, RoleData, RoleTick,
};
pub use security::{BanAdded, ban_source_ok};
pub use ssh_download::{
    SSH_DOWNLOAD_HISTORY_KEPT, SSH_DOWNLOAD_LOG_KEPT, SshDownloadStateRow, SshDownloadTransferRow,
    StoredHostKey,
};

use db::Db;
use vault::Vault;

/// Durable intent row of one Instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentRow {
    pub instance_id: InstanceId,
    pub desired: DesiredState,
    pub manual_stop: bool,
    pub emergency_latched: bool,
    pub intent_revision: u64,
}

/// User intent changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentChange {
    Start,
    /// A Start that overrides a stop which is not on disk (still pending, or carried over from
    /// before a restart and never confirmed): like `Start`, but always written as a new revision
    /// — also when the stored intent already says running — so that the user's decision is on
    /// disk and newer than the stop it overrides.
    ConfirmStart,
    Stop,
    Emergency,
    ClearEmergency,
}

/// A recorded stop or emergency stop whose latch nothing on disk proves was ever written.
///
/// The Store recorded it as an operation, newer than the Instance's last durable intent write,
/// whose effect that intent does not show: the stop was asked for, but nothing proves the latch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnconfirmedStop {
    pub instance_id: InstanceId,
    pub operation_id: OperationId,
    pub emergency: bool,
    pub requested_at: Timestamp,
}

/// Result of starting an idempotent operation.
#[derive(Debug, Clone)]
pub enum Begin {
    New(Operation),
    /// Same key and same request: return the original operation, do nothing again.
    Existing(Operation),
}

/// Public metadata of a stored secret. Never contains the plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMeta {
    pub secret_ref: SecretRef,
    pub kind: String,
    pub label: Option<String>,
    pub public_fingerprint: Option<String>,
    pub created_at: Timestamp,
}

#[derive(Debug)]
pub struct Store {
    control: Db,
    metrics: Db,
    /// The data directory's free space: metrics yield when it runs low; control writes get the
    /// reserve.
    disk: Arc<disk::Disk>,
    vault: Arc<Vault>,
    installation_id: InstallationId,
    /// The directory holding both databases.
    dir: std::path::PathBuf,
}

/// File names of the two databases in the state directory.
pub const CONTROL_FILE: &str = "control.sqlite";
pub const METRICS_FILE: &str = "metrics.sqlite";

pub use schema::{CONTROL_VERSION, METRICS_VERSION};
pub use vault::key_check_of;

/// Which of the two databases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Database {
    Control,
    Metrics,
}

impl Database {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Metrics => "metrics",
        }
    }

    #[must_use]
    pub const fn file(self) -> &'static str {
        match self {
            Self::Control => CONTROL_FILE,
            Self::Metrics => METRICS_FILE,
        }
    }

    #[must_use]
    pub const fn supported_version(self) -> i64 {
        match self {
            Self::Control => CONTROL_VERSION,
            Self::Metrics => METRICS_VERSION,
        }
    }
}

const READERS_CONTROL: usize = 4;
const READERS_METRICS: usize = 2;
const MAX_EVENTS: i64 = 10_000;

impl Store {
    /// Open the store in `dir` (which the caller created with mode 0700). `master_key` is the
    /// installation's vault key file; one that does not belong to this store is refused.
    ///
    /// # Errors
    ///
    /// `Sqlite` or `Io` when a database cannot be opened, `SchemaTooNew` for a database written by
    /// a newer binary, `Corrupt` when an integrity check or the stored installation id fails,
    /// `VaultKeyMismatch` when `master_key` does not belong to this store.
    pub fn open(
        dir: &Path,
        master_key: &Zeroizing<[u8; 32]>,
        key_id: u32,
    ) -> Result<Self, StoreError> {
        Self::open_with_space(dir, master_key, key_id, Arc::new(Statvfs))
    }

    /// [`Self::open`] reading the volume's free space through `probe` (a stand-in in tests).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::open`].
    pub fn open_with_space(
        dir: &Path,
        master_key: &Zeroizing<[u8; 32]>,
        key_id: u32,
        probe: Arc<dyn SpaceProbe>,
    ) -> Result<Self, StoreError> {
        // First: on a volume too full for the databases' WAL files the metrics reserve makes
        // their room.
        let disk = disk::Disk::new(dir, probe);
        let mut control = Db::open(
            &dir.join(CONTROL_FILE),
            Durability::Full,
            READERS_CONTROL,
            |c| {
                // What the control database deletes leaves nothing behind (`scrub`).
                scrub::overwrite_deleted(c)?;
                schema::migrate_control(c)?;
                scrub::rebuild_once(c);
                Ok(())
            },
        )?;
        let mut metrics = Db::open(
            &dir.join(METRICS_FILE),
            Durability::Normal,
            READERS_METRICS,
            metrics::open_metrics,
        )?;
        // Installation id is created once and never changes.
        let installation_id = {
            let path = dir.join(CONTROL_FILE);
            let conn = rusqlite::Connection::open(path)?;
            conn.busy_timeout(std::time::Duration::from_secs(2))?;
            let existing: Option<String> = conn
                .query_row(
                    "SELECT value FROM meta WHERE key = 'installation_id'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(v) = existing {
                v.parse()
                    .map_err(|e| StoreError::Corrupt(format!("installation id: {e}")))?
            } else {
                let id = InstallationId::new();
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('installation_id', ?1)",
                    params![id.to_string()],
                )?;
                id
            }
        };
        let vault = Arc::new(Vault::new(master_key, key_id, installation_id.to_string()));
        {
            let conn = rusqlite::Connection::open(dir.join(CONTROL_FILE))?;
            conn.busy_timeout(std::time::Duration::from_secs(2))?;
            check_vault_key(&conn, &vault)?;
        }
        // A control write that finds the disk full gets the reserve and runs once more.
        let reserve = disk.clone();
        control.retry_when_full(Arc::new(move |_: &mut rusqlite::Connection| {
            reserve.release_reserve()
        }));
        // So does a metrics write, in the room made for it: the database stays at its size from
        // now on, its WAL starts over in the blocks it has, its oldest data makes the whole ring
        // of free pages again (what was free did not hold this write), and its reserve goes back
        // to the volume for what still needs new blocks.
        let ring = disk.clone();
        metrics.retry_when_full(Arc::new(move |c: &mut rusqlite::Connection| {
            ring.metrics_full();
            let released = ring.release_metrics_reserve();
            let restarted = metrics::restart_wal(c);
            let pruned =
                metrics::ring_room_when_full(c, Timestamp::now().unix_millis()).unwrap_or(0);
            ring.pruned(pruned as u64);
            released || restarted || pruned > 0
        }));
        Ok(Self {
            control,
            metrics,
            disk,
            vault,
            installation_id,
            dir: dir.to_path_buf(),
        })
    }

    pub const fn installation_id(&self) -> InstallationId {
        self.installation_id
    }

    #[must_use]
    pub fn sqlite_version() -> &'static str {
        rusqlite::version()
    }

    /// The directory holding the databases (the state directory).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The data directory's free space, whether metrics yield, and the control reserve.
    pub fn disk_report(&self) -> DiskReport {
        self.disk.report()
    }

    /// Read the data directory's free space now: whether it is low (the metrics database then
    /// stays at its size and overwrites its oldest data). Run by the metrics maintenance, so the
    /// state follows the volume also while no samples arrive, and the reserves come back once
    /// there is room.
    pub fn metrics_space(&self) -> bool {
        self.disk.low(true)
    }

    /// Whether the volume is low on space, since when, its free space and the free space at
    /// which the metrics database may grow again, and what was overwritten (or not stored at
    /// all) since space ran low.
    pub fn metrics_disk(&self) -> MetricsSpace {
        self.disk.metrics()
    }

    const fn db(&self, which: Database) -> &Db {
        match which {
            Database::Control => &self.control,
            Database::Metrics => &self.metrics,
        }
    }

    /// Write queue depth and `STORE_BUSY` refusals of one database.
    pub fn queue_health(&self, which: Database) -> QueueHealth {
        self.db(which).queue_health()
    }

    /// `PRAGMA user_version` of one database.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn schema_version(&self, which: Database) -> Result<i64, StoreError> {
        self.db(which)
            .read(|c| Ok(c.query_row("PRAGMA user_version", [], |r| r.get(0))?))
            .await
    }

    /// `PRAGMA quick_check` of one database: `ok`, or the first problems (at most 10).
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn quick_check(&self, which: Database) -> Result<String, StoreError> {
        self.db(which)
            .read(|c| {
                let mut stmt = c.prepare("PRAGMA quick_check(10)")?;
                let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
                let lines = rows.collect::<Result<Vec<_>, _>>()?;
                Ok(lines.join("; "))
            })
            .await
    }

    /// Whether `master_key` (e.g. the key file as it is on disk now) is the key this Store's
    /// secrets are sealed with.
    pub fn is_vault_key(&self, master_key: &[u8; 32]) -> bool {
        key_check_of(master_key) == self.vault.key_check()
    }

    // -----------------------------------------------------------------------------------------
    // Entities
    // -----------------------------------------------------------------------------------------

    /// Insert a new entity.
    ///
    /// # Errors
    ///
    /// `InvalidState` when the id exists already or a referenced entity is missing; `Busy` when the
    /// write queue is full, `Closed` once the store has shut down, and `Sqlite` or `Encoding` when
    /// the transaction fails.
    pub async fn create<E: Entity>(&self, e: E) -> Result<E, StoreError> {
        self.control.write(move |c| entities::insert(c, e)).await
    }

    /// Replace an entity, compare-and-set on `expected_revision`.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown entity, `RevisionConflict` when `expected_revision` is stale,
    /// `InvalidState` when a referenced entity is missing; `Busy` when the write queue is full,
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the transaction
    /// fails.
    pub async fn update<E: Entity>(&self, e: E, expected_revision: u64) -> Result<E, StoreError> {
        self.control
            .write(move |c| entities::update(c, e, expected_revision))
            .await
    }

    /// Delete an entity nothing references, compare-and-set on `expected_revision`.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown entity, `RevisionConflict` when `expected_revision` is stale,
    /// `InUse` while something references it; `Busy` when the write queue is full, `Closed` once
    /// the store has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn delete<E: Entity>(
        &self,
        id: String,
        expected_revision: u64,
    ) -> Result<(), StoreError> {
        self.control
            .write(move |c| entities::delete::<E>(c, &id, expected_revision))
            .await
    }

    /// The current version of entity `id`, if it exists.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn get<E: Entity>(&self, id: String) -> Result<Option<E>, StoreError> {
        self.control.read(move |c| entities::get::<E>(c, &id)).await
    }

    /// Entity `id` as it was at `revision`, if that revision is kept.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn get_revision<E: Entity>(
        &self,
        id: String,
        revision: u64,
    ) -> Result<Option<E>, StoreError> {
        self.control
            .read(move |c| entities::get_revision::<E>(c, &id, revision))
            .await
    }

    /// Every entity of the kind.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn list<E: Entity>(&self) -> Result<Vec<E>, StoreError> {
        self.control.read(entities::list::<E>).await
    }

    /// Create an Instance and its (stopped) intent row in one transaction (so a write retried on
    /// a full disk repeats both, never only the second).
    ///
    /// # Errors
    ///
    /// `InvalidState` when the id exists already or a referenced entity is missing; `Busy` when the
    /// write queue is full, `Closed` once the store has shut down, and `Sqlite` or `Encoding` when
    /// the transaction fails.
    pub async fn create_instance(&self, spec: InstanceSpec) -> Result<InstanceSpec, StoreError> {
        self.control
            .write(move |c| {
                let id = spec.id.to_string();
                let tx = c.transaction()?;
                let spec = entities::insert_in(&tx, spec)?;
                tx.execute(
                    "INSERT INTO instance_intents (instance_id, desired, updated_at) VALUES (?1, 'stopped', ?2)",
                    params![id, Timestamp::now().to_string()],
                )?;
                tx.commit()?;
                Ok(spec)
            })
            .await
    }

    /// Delete an Instance (must be stopped; checked by the caller) and its intent.
    ///
    /// # Errors
    ///
    /// `InvalidState` while the Instance is set to run or is the Provider egress, `Refused`
    /// (`BOOTSTRAP_IN_PROGRESS`) while it is a sealing run's connection, `NotFound` or
    /// `RevisionConflict` from the compare-and-set, `InUse` while something references it; `Busy`
    /// when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn delete_instance(
        &self,
        id: InstanceId,
        expected_revision: u64,
    ) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                let ids = id.to_string();
                let running: Option<String> = c
                    .query_row(
                        "SELECT desired FROM instance_intents WHERE instance_id = ?1",
                        params![ids],
                        |r| r.get(0),
                    )
                    .optional()?;
                if running.as_deref() == Some("running") {
                    return Err(StoreError::InvalidState(tr!(
                        "The Instance is still set to run; stop it first",
                        "Instance 仍設定為執行中，請先停止",
                        "Instance はまだ実行する設定になっています。先に停止してください"
                    )));
                }
                provider::ensure_not_egress(c, &ids)?;
                let tx = c.transaction()?;
                bootstrap::on_instance_deleted(&tx, &ids)?;
                entities::delete_in::<InstanceSpec>(&tx, &ids, expected_revision)?;
                tx.execute(
                    "DELETE FROM instance_intents WHERE instance_id = ?1",
                    params![ids],
                )?;
                tx.execute(
                    "DELETE FROM identity_leases WHERE instance_id = ?1",
                    params![ids],
                )?;
                tx.execute("DELETE FROM bans WHERE instance_id = ?1", params![ids])?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// Delete a stopped Instance together with its Gateways in one transaction. `gateways` must
    /// be exactly its current set (what the user confirmed): a Gateway added or removed meanwhile
    /// changes nothing and reports the conflict. A Gateway still used elsewhere (SSH host, app)
    /// keeps everything.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown Instance, `RevisionConflict` when `expected_revision` is stale,
    /// `InvalidState` while it is set to run, is the Provider egress or its Gateways changed since
    /// `gateways`, `Refused` (`BOOTSTRAP_IN_PROGRESS`) while it is a sealing run's connection,
    /// `InUse` while something else references them; `Busy` when the write queue is full, `Closed`
    /// once the store has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn delete_instance_with_gateways(
        &self,
        id: InstanceId,
        expected_revision: u64,
        gateways: Vec<GatewayId>,
    ) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                let ids = id.to_string();
                let tx = c.transaction()?;
                let desired: Option<String> = tx
                    .query_row(
                        "SELECT desired FROM instance_intents WHERE instance_id = ?1",
                        params![ids],
                        |r| r.get(0),
                    )
                    .optional()?;
                if desired.as_deref() == Some("running") {
                    return Err(StoreError::InvalidState(tr!(
                        "The Instance is still set to run; stop it first",
                        "Instance 仍設定為執行中，請先停止",
                        "Instance はまだ実行する設定になっています。先に停止してください"
                    )));
                }
                provider::ensure_not_egress(&tx, &ids)?;
                bootstrap::on_instance_deleted(&tx, &ids)?;
                let current =
                    entities::head_revision(&tx, "instance", &ids)?.ok_or(StoreError::NotFound)?;
                if current != expected_revision {
                    return Err(StoreError::RevisionConflict {
                        expected: expected_revision,
                        current,
                    });
                }
                let now: std::collections::BTreeSet<String> = {
                    let mut stmt = tx.prepare(
                        "SELECT h.id FROM entity_heads h JOIN entity_revisions r
                           ON r.kind = h.kind AND r.id = h.id AND r.revision = h.revision
                         WHERE h.kind = 'gateway' AND json_extract(r.body, '$.instance_id') = ?1",
                    )?;
                    let rows = stmt.query_map(params![ids], |r| r.get::<_, String>(0))?;
                    rows.collect::<Result<_, _>>()?
                };
                let confirmed: std::collections::BTreeSet<String> =
                    gateways.iter().map(ToString::to_string).collect();
                if now != confirmed {
                    return Err(StoreError::InvalidState(tr!(
                        "The Gateways changed after you confirmed; confirm again before deleting",
                        "代理埠在確認之後有變動，請重新確認後再刪除",
                        "確認後にゲートウェイが変わりました。もう一度確認してから削除してください"
                    )));
                }
                for g in &now {
                    entities::unreferenced_named(&tx, "gateway", g)?;
                    tx.execute(
                        "DELETE FROM entity_heads WHERE kind = 'gateway' AND id = ?1",
                        params![g],
                    )?;
                }
                entities::unreferenced_named(&tx, "instance", &ids)?;
                tx.execute(
                    "DELETE FROM entity_heads WHERE kind = 'instance' AND id = ?1",
                    params![ids],
                )?;
                tx.execute(
                    "DELETE FROM instance_intents WHERE instance_id = ?1",
                    params![ids],
                )?;
                tx.execute(
                    "DELETE FROM identity_leases WHERE instance_id = ?1",
                    params![ids],
                )?;
                tx.execute("DELETE FROM bans WHERE instance_id = ?1", params![ids])?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Intents, generations, identity leases
    // -----------------------------------------------------------------------------------------

    /// The intent of Instance `id`.
    ///
    /// # Errors
    ///
    /// `NotFound` when it has no intent row; `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the read or a row's decoding fails.
    pub async fn intent(&self, id: InstanceId) -> Result<IntentRow, StoreError> {
        self.control.read(move |c| read_intent(c, id)).await
    }

    /// The intent row of every Instance.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn intents(&self) -> Result<Vec<IntentRow>, StoreError> {
        self.control
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT instance_id, desired, manual_stop, emergency_latched, intent_revision FROM instance_intents",
                )?;
                let rows = stmt.query_map([], intent_from_row)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
            })
            .await
    }

    /// Apply a user intent change. Stop/emergency use the priority lane and are durable when
    /// this returns `Ok`.
    ///
    /// # Errors
    ///
    /// `NotFound` when the Instance has no intent row, `InvalidState` for a start while the
    /// emergency latch is set; `Busy` when the normal write queue is full (a stop on the priority
    /// lane is never refused for depth), `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn change_intent(
        &self,
        id: InstanceId,
        change: IntentChange,
    ) -> Result<IntentRow, StoreError> {
        let job = move |c: &mut rusqlite::Connection| -> Result<IntentRow, StoreError> {
            let tx = c.transaction()?;
            let cur = read_intent(&tx, id)?;
            let (desired, manual, emergency) = match change {
                IntentChange::Start | IntentChange::ConfirmStart => {
                    if cur.emergency_latched {
                        return Err(StoreError::InvalidState(tr!(
                            "The emergency stop is still on; release it before starting",
                            "急停尚未解除，請先解除急停再啟動",
                            "緊急停止がまだ解除されていません。緊急停止を解除してから開始してください"
                        )));
                    }
                    if change == IntentChange::Start
                        && cur.desired == DesiredState::Running
                        && !cur.manual_stop
                    {
                        // Already running: nothing changes. A new revision would make the
                        // running generation's next re-activation look like an intent change
                        // and replace it.
                        return Ok(cur);
                    }
                    ("running", false, false)
                }
                IntentChange::Stop => ("stopped", true, cur.emergency_latched),
                IntentChange::Emergency => ("stopped", true, true),
                IntentChange::ClearEmergency => ("stopped", true, false),
            };
            tx.execute(
                "UPDATE instance_intents SET desired = ?2, manual_stop = ?3, emergency_latched = ?4,
                    intent_revision = intent_revision + 1, updated_at = ?5 WHERE instance_id = ?1",
                params![id.to_string(), desired, manual, emergency, Timestamp::now().to_string()],
            )?;
            let row = read_intent(&tx, id)?;
            tx.commit()?;
            Ok(row)
        };
        match change {
            IntentChange::Stop | IntentChange::Emergency => self.control.write_priority(job).await,
            IntentChange::Start | IntentChange::ConfirmStart | IntentChange::ClearEmergency => {
                self.control.write(job).await
            }
        }
    }

    /// Stops and emergency stops recorded as operations (in flight, done or of unknown outcome)
    /// that are newer than their Instance's last intent write and whose effect that intent does
    /// not show (see [`UnconfirmedStop`]). Read when the manager starts: such a stop was asked for
    /// after the stored intent was written, and only its latch would have made it durable.
    ///
    /// A time that cannot be read counts as newer: the order cannot be shown, so the stop is not
    /// taken as superseded.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn unconfirmed_stops(&self) -> Result<Vec<UnconfirmedStop>, StoreError> {
        self.control
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT o.id, o.kind, o.target_id, o.created_at,
                            i.desired, i.manual_stop, i.emergency_latched, i.updated_at
                       FROM operations o JOIN instance_intents i ON i.instance_id = o.target_id
                      WHERE o.kind IN (?1, ?2) AND o.status NOT IN ('failed', 'cancelled')",
                )?;
                let rows =
                    stmt.query_map(params![OP_INSTANCE_STOP, OP_INSTANCE_EMERGENCY_STOP], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, String>(3)?,
                            r.get::<_, String>(4)?,
                            r.get::<_, bool>(5)?,
                            r.get::<_, bool>(6)?,
                            r.get::<_, String>(7)?,
                        ))
                    })?;
                let time = |s: String| -> Option<Timestamp> {
                    serde_json::from_value(serde_json::Value::String(s)).ok()
                };
                let mut out = Vec::new();
                for row in rows {
                    let (op, kind, target, created, desired, manual, latched, updated) = row?;
                    let emergency = kind == OP_INSTANCE_EMERGENCY_STOP;
                    // The intent already shows the stop (its latch, or a later stop's).
                    if desired == "stopped" && manual && (latched || !emergency) {
                        continue;
                    }
                    let created = time(created);
                    // Written after the stop was recorded: the user decided again since.
                    if let (Some(c), Some(u)) = (&created, time(updated))
                        && c.0 < u.0
                    {
                        continue;
                    }
                    let (Ok(instance_id), Ok(operation_id)) = (target.parse(), op.parse()) else {
                        continue;
                    };
                    out.push(UnconfirmedStop {
                        instance_id,
                        operation_id,
                        emergency,
                        requested_at: created.unwrap_or_else(Timestamp::now),
                    });
                }
                Ok(out)
            })
            .await
    }

    /// Reserve the next generation for a start/recovery attempt and take the identity lease of
    /// `key_fingerprint`. Fails if the intent changed (`expected_intent_revision`), is not
    /// `running`, carries a latch, or the key is leased to another Instance that may still run.
    ///
    /// A lease only blocks while its holder's intent is `running`: a stopped (or deleted) holder
    /// has no worker, so its lease is stale (e.g. its release failed) and is taken over. The
    /// per-key flock remains the proof that no older worker still uses the key.
    ///
    /// # Errors
    ///
    /// `NotFound` when the Instance has no intent row, `RevisionConflict` when the intent changed,
    /// `InvalidState` when it is no longer `running`, `IdentityInUse` when another Instance holds
    /// the key; `Busy` when the write queue is full, `Closed` once the store has shut down, and
    /// `Sqlite` or `Encoding` when the transaction fails.
    pub async fn reserve_generation(
        &self,
        id: InstanceId,
        expected_intent_revision: u64,
        key_fingerprint: String,
    ) -> Result<u64, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let cur = read_intent(&tx, id)?;
                if cur.intent_revision != expected_intent_revision {
                    return Err(StoreError::RevisionConflict {
                        expected: expected_intent_revision,
                        current: cur.intent_revision,
                    });
                }
                if cur.desired != DesiredState::Running || cur.manual_stop || cur.emergency_latched {
                    return Err(StoreError::InvalidState(tr!(
                        "The desired state is no longer running",
                        "意圖已不是執行中",
                        "目標の状態はもう実行中ではありません"
                    )));
                }
                let holder: Option<(String, bool)> = tx
                    .query_row(
                        "SELECT l.instance_id,
                                COALESCE(i.desired = 'running' AND i.manual_stop = 0
                                         AND i.emergency_latched = 0, 0)
                           FROM identity_leases l
                           LEFT JOIN instance_intents i ON i.instance_id = l.instance_id
                          WHERE l.key_fingerprint = ?1",
                        params![key_fingerprint],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                if let Some((holder, holder_may_run)) = holder
                    && holder != id.to_string()
                    && holder_may_run
                {
                    return Err(StoreError::IdentityInUse);
                }
                let generation: i64 = tx.query_row(
                    "SELECT next_generation FROM instance_intents WHERE instance_id = ?1",
                    params![id.to_string()],
                    |r| r.get(0),
                )?;
                tx.execute(
                    "UPDATE instance_intents SET next_generation = next_generation + 1 WHERE instance_id = ?1",
                    params![id.to_string()],
                )?;
                // One key per Instance at a time: leases on keys it no longer uses are stale.
                tx.execute(
                    "DELETE FROM identity_leases WHERE instance_id = ?1 AND key_fingerprint <> ?2",
                    params![id.to_string(), key_fingerprint],
                )?;
                tx.execute(
                    "INSERT INTO identity_leases (key_fingerprint, instance_id, generation, acquired_at)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (key_fingerprint) DO UPDATE SET instance_id = excluded.instance_id,
                        generation = excluded.generation, acquired_at = excluded.acquired_at",
                    params![key_fingerprint, id.to_string(), generation, Timestamp::now().to_string()],
                )?;
                tx.commit()?;
                Ok(generation.cast_unsigned())
            })
            .await
    }

    /// Release every identity lease of an Instance once it has no worker (stopped, or reaped
    /// during a back-off), whichever keys they name.
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn release_identities(&self, id: InstanceId) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                c.execute(
                    "DELETE FROM identity_leases WHERE instance_id = ?1",
                    params![id.to_string()],
                )?;
                Ok(())
            })
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Operations (idempotency)
    // -----------------------------------------------------------------------------------------

    /// Start an operation. With an idempotency key, a repeated identical request returns the
    /// original operation; the same key with a different fingerprint is a conflict.
    ///
    /// # Errors
    ///
    /// `IdempotencyConflict` when the key was used with a different fingerprint; `Busy` when the
    /// write queue is full, `Closed` once the store has shut down, and `Sqlite` or `Encoding` when
    /// the transaction fails.
    pub async fn begin_operation(
        &self,
        kind: String,
        target_id: Option<String>,
        idempotency_key: Option<String>,
        fingerprint: Option<String>,
    ) -> Result<Begin, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                if let Some(key) = &idempotency_key {
                    let existing: Option<(String, Option<String>)> = tx
                        .query_row(
                            "SELECT id, request_fingerprint FROM operations WHERE idempotency_key = ?1",
                            params![key],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()?;
                    if let Some((id, fp)) = existing {
                        if fp != fingerprint {
                            return Err(StoreError::IdempotencyConflict);
                        }
                        let op = read_operation(&tx, &id)?.ok_or(StoreError::NotFound)?;
                        return Ok(Begin::Existing(op));
                    }
                }
                let now = Timestamp::now();
                let op = Operation {
                    id: OperationId::new(),
                    kind,
                    target_id,
                    status: OperationStatus::Accepted,
                    error: None,
                    result_refs: Vec::new(),
                    durable: true,
                    created_at: now,
                    updated_at: now,
                };
                tx.execute(
                    "INSERT INTO operations (id, kind, target_id, status, idempotency_key, request_fingerprint, created_at, updated_at)
                     VALUES (?1, ?2, ?3, 'accepted', ?4, ?5, ?6, ?6)",
                    params![op.id.to_string(), op.kind, op.target_id, idempotency_key, fingerprint, now.to_string()],
                )?;
                tx.commit()?;
                Ok(Begin::New(op))
            })
            .await
    }

    /// Record how an operation ended. Only an operation still in flight (accepted or running) is
    /// changed: one that already ended — succeeded, failed, cancelled, or marked unknown — keeps
    /// its outcome, so nothing late can overwrite it. Returns whether it was recorded.
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn finish_operation(
        &self,
        id: OperationId,
        status: OperationStatus,
        error: Option<ApiError>,
        result_refs: Vec<String>,
    ) -> Result<bool, StoreError> {
        self.control
            .write(move |c| {
                let err = error.map(|e| serde_json::to_string(&e)).transpose()?;
                let refs = serde_json::to_string(&result_refs)?;
                let status = serde_json::to_value(status)?
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string();
                let n = c.execute(
                    "UPDATE operations SET status = ?2, error = ?3, result_refs = ?4, updated_at = ?5
                      WHERE id = ?1 AND status IN ('accepted', 'running')",
                    params![id.to_string(), status, err, refs, Timestamp::now().to_string()],
                )?;
                if n == 0 {
                    tracing::debug!(operation = %id, "operation already ended; its outcome is kept");
                }
                Ok(n > 0)
            })
            .await
    }

    /// Mark every operation that never finished as `unknown`; returns how many. Run when the
    /// manager starts: whatever was carrying them (a controller request on a manager connection)
    /// is gone, nothing will finish them any more, and their effect may or may not have happened.
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn abandon_unfinished_operations(&self) -> Result<usize, StoreError> {
        let error = serde_json::to_string(&ApiError::new(
            ErrorCode::OutcomeUnknown,
            tr!(
                "This operation had not finished when the core service (manager) restarted, so its outcome is unknown; check the current state before deciding whether to retry",
                "核心服務（manager）重新啟動時這個操作尚未完成，結果未知；請先確認目前狀態再決定是否重試",
                "コアサービス（manager）の再起動時にこの操作は完了していなかったため、結果は不明です。現在の状態を確認してから、再試行するかどうか決めてください"
            ),
        ))?;
        self.control
            .write(move |c| {
                let n = c.execute(
                    "UPDATE operations SET status = 'unknown', error = COALESCE(error, ?1), updated_at = ?2
                     WHERE status IN ('accepted', 'running')",
                    params![error, Timestamp::now().to_string()],
                )?;
                Ok(n)
            })
            .await
    }

    /// Forget finished operations created before `older_than` or beyond the newest `keep`;
    /// returns how many. Unfinished ones stay. Keeps the table bounded; an idempotency key stays
    /// answerable for as long as its operation is kept.
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn prune_operations(
        &self,
        older_than: Timestamp,
        keep: usize,
    ) -> Result<usize, StoreError> {
        self.control
            .write(move |c| {
                let n = c.execute(
                    "DELETE FROM operations WHERE status NOT IN ('accepted', 'running')
                     AND (created_at < ?1 OR id NOT IN
                          (SELECT id FROM operations ORDER BY created_at DESC LIMIT ?2))",
                    params![
                        older_than.to_string(),
                        i64::try_from(keep).unwrap_or(i64::MAX)
                    ],
                )?;
                Ok(n)
            })
            .await
    }

    /// The newest operations, newest first.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn recent_operations(&self, limit: usize) -> Result<Vec<Operation>, StoreError> {
        self.control
            .read(move |c| {
                let mut stmt =
                    c.prepare("SELECT id FROM operations ORDER BY created_at DESC LIMIT ?1")?;
                let ids = stmt
                    .query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
                        r.get::<_, String>(0)
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                let mut out = Vec::with_capacity(ids.len());
                for id in ids {
                    if let Some(op) = read_operation(c, &id)? {
                        out.push(op);
                    }
                }
                Ok(out)
            })
            .await
    }

    /// Operation `id`, if it is kept.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn operation(&self, id: OperationId) -> Result<Option<Operation>, StoreError> {
        self.control
            .read(move |c| read_operation(c, &id.to_string()))
            .await
    }

    /// The operation started with idempotency key `key`, if it is kept.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn operation_by_key(&self, key: String) -> Result<Option<Operation>, StoreError> {
        self.control
            .read(move |c| {
                let id: Option<String> = c
                    .query_row(
                        "SELECT id FROM operations WHERE idempotency_key = ?1",
                        params![key],
                        |r| r.get(0),
                    )
                    .optional()?;
                id.map(|id| read_operation(c, &id))
                    .transpose()
                    .map(Option::flatten)
            })
            .await
    }

    /// Keyed fingerprint for idempotency of requests carrying secrets.
    pub fn keyed_fingerprint(&self, data: &[u8]) -> String {
        self.vault.fingerprint(data)
    }

    // -----------------------------------------------------------------------------------------
    // Secrets
    // -----------------------------------------------------------------------------------------

    /// Seal `plaintext` in the vault and store it as a new secret.
    ///
    /// # Errors
    ///
    /// `Vault` when sealing fails; `Busy` when the write queue is full, `Closed` once the store has
    /// shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn put_secret(
        &self,
        kind: String,
        label: Option<String>,
        plaintext: Zeroizing<Vec<u8>>,
        public_fingerprint: Option<String>,
    ) -> Result<SecretMeta, StoreError> {
        let vault = self.vault.clone();
        self.control
            .write(move |c| {
                let id = SecretId::new();
                let sealed = vault.seal(&id.to_string(), &kind, &plaintext)?;
                let now = Timestamp::now();
                c.execute(
                    "INSERT INTO secrets (id, kind, label, key_id, nonce, ciphertext, public_fingerprint, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        id.to_string(),
                        kind,
                        label,
                        sealed.key_id,
                        sealed.nonce.to_vec(),
                        sealed.ciphertext,
                        public_fingerprint,
                        now.to_string()
                    ],
                )?;
                Ok(SecretMeta {
                    secret_ref: SecretRef(id),
                    kind,
                    label,
                    public_fingerprint,
                    created_at: now,
                })
            })
            .await
    }

    /// Decrypt a secret for delivery inside the manager (worker key delivery, provider lease).
    /// Never exposed through a public API.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown secret, `Vault` when it does not decrypt (wrong key or tampered);
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn open_secret(&self, r: SecretRef) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let vault = self.vault.clone();
        self.control
            .read(move |c| {
                let row: Option<(String, u32, Vec<u8>, Vec<u8>)> = c
                    .query_row(
                        "SELECT kind, key_id, nonce, ciphertext FROM secrets WHERE id = ?1",
                        params![r.0.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .optional()?;
                let (kind, key_id, nonce, ct) = row.ok_or(StoreError::NotFound)?;
                vault.open(&r.0.to_string(), &kind, key_id, &nonce, &ct)
            })
            .await
    }

    /// Metadata of every stored secret (never the plaintext).
    ///
    /// # Errors
    ///
    /// `Corrupt` for a malformed secret id; `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the read or a row's decoding fails.
    pub async fn secrets(&self) -> Result<Vec<SecretMeta>, StoreError> {
        self.control
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT id, kind, label, public_fingerprint, created_at FROM secrets ORDER BY created_at, id",
                )?;
                let rows = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                })?;
                let mut out = Vec::new();
                for row in rows {
                    let (id, kind, label, fp, at) = row?;
                    out.push(SecretMeta {
                        secret_ref: SecretRef(
                            id.parse()
                                .map_err(|e| StoreError::Corrupt(format!("secret id: {e}")))?,
                        ),
                        kind,
                        label,
                        public_fingerprint: fp,
                        created_at: serde_json::from_value(serde_json::Value::String(at))?,
                    });
                }
                Ok(out)
            })
            .await
    }

    /// Delete a secret no profile references.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown secret, `InUse` while a `WireGuard` profile references it; `Busy`
    /// when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn delete_secret(&self, r: SecretRef) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                let s = r.to_string();
                let used: i64 = c.query_row(
                    "SELECT count(*) FROM entity_heads h JOIN entity_revisions e
                       ON e.kind = h.kind AND e.id = h.id AND e.revision = h.revision
                     WHERE h.kind = 'runtime_profile'
                       AND (json_extract(e.body, '$.interface.private_key') = ?1
                         OR json_extract(e.body, '$.peer.preshared_key') = ?1)",
                    params![s],
                    |row| row.get(0),
                )?;
                if used > 0 {
                    return Err(StoreError::InUse(tr!(
                        "WireGuard profile",
                        "WireGuard 設定",
                        "WireGuard 設定"
                    )));
                }
                let n = c.execute(
                    "DELETE FROM secrets WHERE id = ?1",
                    params![r.0.to_string()],
                )?;
                if n == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            })
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Settings and events
    // -----------------------------------------------------------------------------------------

    /// The installation's settings (defaults until first written).
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn settings(&self) -> Result<Settings, StoreError> {
        self.control
            .read(|c| {
                let body: Option<String> = c
                    .query_row("SELECT body FROM settings WHERE id = 1", [], |r| r.get(0))
                    .optional()?;
                Ok(match body {
                    Some(b) => serde_json::from_str(&b)?,
                    None => Settings::default(),
                })
            })
            .await
    }

    /// Replace the settings, compare-and-set on `expected_revision`.
    ///
    /// # Errors
    ///
    /// `RevisionConflict` when `expected_revision` is stale; `Busy` when the write queue is full,
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the transaction
    /// fails.
    pub async fn put_settings(
        &self,
        mut s: Settings,
        expected_revision: u64,
    ) -> Result<Settings, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let current: u64 = tx
                    .query_row("SELECT revision FROM settings WHERE id = 1", [], |r| r.get::<_, i64>(0))
                    .optional()?
                    .map_or(1, i64::cast_unsigned);
                if current != expected_revision {
                    return Err(StoreError::RevisionConflict {
                        expected: expected_revision,
                        current,
                    });
                }
                s.revision = current + 1;
                let body = serde_json::to_string(&s)?;
                tx.execute(
                    "INSERT INTO settings (id, revision, body) VALUES (1, ?1, ?2)
                     ON CONFLICT (id) DO UPDATE SET revision = excluded.revision, body = excluded.body",
                    params![s.revision.cast_signed(), body],
                )?;
                tx.commit()?;
                Ok(s)
            })
            .await
    }

    /// Append a public event (bounded table): the event and the trim in one transaction, so a
    /// write retried on a full disk never appends it twice.
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn append_event(
        &self,
        kind: String,
        entity_id: Option<String>,
        body: serde_json::Value,
    ) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                tx.execute(
                    "INSERT INTO events (at, kind, entity_id, body) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        Timestamp::now().to_string(),
                        kind,
                        entity_id,
                        body.to_string()
                    ],
                )?;
                tx.execute(
                    "DELETE FROM events WHERE seq <= (SELECT max(seq) FROM events) - ?1",
                    params![MAX_EVENTS],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// Read from the metrics database.
    ///
    /// # Errors
    ///
    /// Whatever `f` returns, and `Closed` once the store has shut down.
    pub async fn metrics_read<T: Send + 'static>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        self.metrics.read(f).await
    }
}

fn intent_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<IntentRow> {
    let id: String = r.get(0)?;
    let desired: String = r.get(1)?;
    Ok(IntentRow {
        instance_id: id.parse().map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        desired: if desired == "running" {
            DesiredState::Running
        } else {
            DesiredState::Stopped
        },
        manual_stop: r.get(2)?,
        emergency_latched: r.get(3)?,
        intent_revision: r.get::<_, i64>(4)?.cast_unsigned(),
    })
}

fn read_intent(c: &rusqlite::Connection, id: InstanceId) -> Result<IntentRow, StoreError> {
    c.query_row(
        "SELECT instance_id, desired, manual_stop, emergency_latched, intent_revision FROM instance_intents WHERE instance_id = ?1",
        params![id.to_string()],
        intent_from_row,
    )
    .optional()?
    .ok_or(StoreError::NotFound)
}

/// `operations` columns: id, kind, `target_id`, status, error, `result_refs`, `created_at`, `updated_at`.
type OperationRow = (
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    String,
    String,
    String,
);

fn read_operation(c: &rusqlite::Connection, id: &str) -> Result<Option<Operation>, StoreError> {
    let row: Option<OperationRow> = c
        .query_row(
            "SELECT id, kind, target_id, status, error, result_refs, created_at, updated_at FROM operations WHERE id = ?1",
            params![id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((id, kind, target_id, status, error, refs, created, updated)) = row else {
        return Ok(None);
    };
    Ok(Some(Operation {
        id: id
            .parse()
            .map_err(|e| StoreError::Corrupt(format!("operation id: {e}")))?,
        kind,
        target_id,
        status: serde_json::from_value(serde_json::Value::String(status))?,
        error: error.map(|e| serde_json::from_str(&e)).transpose()?,
        result_refs: serde_json::from_str(&refs)?,
        durable: true,
        created_at: serde_json::from_value(serde_json::Value::String(created))?,
        updated_at: serde_json::from_value(serde_json::Value::String(updated))?,
    }))
}

/// The vault key is a file kept beside the data. A key that does not belong to this store (lost
/// or replaced) must stop the manager rather than start a vault its secrets cannot be opened
/// with. The check is recorded on first use; a store from before it proves the key with one of
/// its secrets.
fn check_vault_key(conn: &rusqlite::Connection, vault: &Vault) -> Result<(), StoreError> {
    let stored: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'vault_key_check'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    match stored {
        Some(v) if v == vault.key_check() => Ok(()),
        Some(_) => Err(StoreError::VaultKeyMismatch),
        None => {
            let sample = conn
                .query_row(
                    "SELECT id, kind, key_id, nonce, ciphertext FROM secrets LIMIT 1",
                    [],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, u32>(2)?,
                            r.get::<_, Vec<u8>>(3)?,
                            r.get::<_, Vec<u8>>(4)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((id, kind, key_id, nonce, ciphertext)) = sample {
                vault
                    .open(&id, &kind, key_id, &nonce, &ciphertext)
                    .map_err(|e| {
                        tracing::warn!(
                            error = %e,
                            "a stored secret does not open with the vault key"
                        );
                        StoreError::VaultKeyMismatch
                    })?;
            }
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('vault_key_check', ?1)",
                params![vault.key_check()],
            )?;
            Ok(())
        }
    }
}
