//! Managed Apps: the user's intent per App and the record of the run the manager supervises.
//!
//! The intent changes only by the user's Start/Stop; the run record is written when a process
//! is started and cleared once its whole tree is confirmed gone. A record left behind (manager
//! crash, shutdown, reboot) is how the next manager finds — and stops — what it left running.

use rusqlite::{Connection, OptionalExtension, params};
use vpn_domain::{AppId, AppSpec, DesiredState, Timestamp, tr};

use crate::Store;
use crate::entities;
use crate::error::StoreError;

/// The run of an App as the manager started it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRunRecord {
    pub run_id: String,
    /// Root process: pid with its start time (`vpn_platform::apps::ProcessIdentity`: macOS
    /// microseconds since the epoch, Linux microseconds since boot).
    pub pid: u32,
    pub started_us: u64,
    /// The boot it was started in (`None`: written by an older version, or unknown).
    pub boot_id: Option<String>,
    /// Isolation backend (`plain`, `seatbelt`, `strict_netns`).
    pub backend: String,
    /// Spec revision it runs.
    pub revision: u64,
    pub gateway_port: Option<u16>,
    pub started_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIntentRow {
    pub app_id: AppId,
    pub desired: DesiredState,
    pub intent_revision: u64,
    pub run: Option<AppRunRecord>,
}

impl AppIntentRow {
    const fn stopped(app_id: AppId) -> Self {
        Self {
            app_id,
            desired: DesiredState::Stopped,
            intent_revision: 1,
            run: None,
        }
    }
}

const COLUMNS: &str = "app_id, desired, intent_revision, run_id, run_pid, run_started_us, run_backend, run_revision, run_gateway_port, run_started_at, run_boot_id";

fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AppIntentRow> {
    let bad = |c: &str| rusqlite::Error::InvalidColumnName(c.into());
    let id: String = r.get(0)?;
    let desired: String = r.get(1)?;
    let run_id: Option<String> = r.get(3)?;
    let run = match run_id {
        None => None,
        Some(run_id) => {
            let started_at: Option<String> = r.get(9)?;
            Some(AppRunRecord {
                run_id,
                pid: {
                    #[expect(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss,
                        reason = "the column is only written from a u32 pid; decode kept bit-identical"
                    )]
                    let pid = r.get::<_, i64>(4)? as u32;
                    pid
                },
                started_us: r.get::<_, i64>(5)?.cast_unsigned(),
                boot_id: r.get(10)?,
                backend: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                revision: r.get::<_, Option<i64>>(7)?.unwrap_or(0).cast_unsigned(),
                gateway_port: r
                    .get::<_, Option<i64>>(8)?
                    .and_then(|p| u16::try_from(p).ok()),
                started_at: started_at
                    .and_then(|s| serde_json::from_value(serde_json::Value::String(s)).ok())
                    .ok_or_else(|| bad("run_started_at"))?,
            })
        }
    };
    Ok(AppIntentRow {
        app_id: id.parse().map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        desired: if desired == "running" {
            DesiredState::Running
        } else {
            DesiredState::Stopped
        },
        intent_revision: r.get::<_, i64>(2)?.cast_unsigned(),
        run,
    })
}

fn read(c: &Connection, id: AppId) -> Result<AppIntentRow, StoreError> {
    Ok(c.query_row(
        &format!("SELECT {COLUMNS} FROM app_intents WHERE app_id = ?1"),
        params![id.to_string()],
        from_row,
    )
    .optional()?
    .unwrap_or_else(|| AppIntentRow::stopped(id)))
}

impl Store {
    /// Create an App and its (stopped) intent row in one transaction (so a write retried on a
    /// full disk repeats both, never only the second).
    ///
    /// # Errors
    ///
    /// `InvalidState` when the id exists already or a referenced entity is missing; `Busy` when the
    /// write queue is full, `Closed` once the store has shut down, and `Sqlite` or `Encoding` when
    /// the transaction fails.
    pub async fn create_app(&self, spec: AppSpec) -> Result<AppSpec, StoreError> {
        self.control
            .write(move |c| {
                let id = spec.id.to_string();
                let tx = c.transaction()?;
                let spec = entities::insert_in(&tx, spec)?;
                tx.execute(
                    "INSERT INTO app_intents (app_id, desired, updated_at) VALUES (?1, 'stopped', ?2)
                     ON CONFLICT (app_id) DO NOTHING",
                    params![id, Timestamp::now().to_string()],
                )?;
                tx.commit()?;
                Ok(spec)
            })
            .await
    }

    /// Delete an App with no supervised run left (the caller checks what runs in memory) and
    /// its intent row, in one transaction.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown App, `RevisionConflict` when `expected_revision` is stale,
    /// `InvalidState` while a run is still recorded, `InUse` while something references it; `Busy`
    /// when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn delete_app(&self, id: AppId, expected_revision: u64) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                let ids = id.to_string();
                let tx = c.transaction()?;
                if read(&tx, id)?.run.is_some() {
                    return Err(StoreError::InvalidState(tr!(
                        "The app is still running or its stop is not confirmed yet; stop it first",
                        "App 仍在執行或尚未確認停止，請先停止",
                        "アプリはまだ実行中か、停止がまだ確認されていません。先に停止してください"
                    )));
                }
                let current =
                    entities::head_revision(&tx, "app", &ids)?.ok_or(StoreError::NotFound)?;
                if current != expected_revision {
                    return Err(StoreError::RevisionConflict {
                        expected: expected_revision,
                        current,
                    });
                }
                entities::unreferenced(&tx, "app", &ids)?;
                tx.execute(
                    "DELETE FROM entity_heads WHERE kind = 'app' AND id = ?1",
                    params![ids],
                )?;
                tx.execute("DELETE FROM app_intents WHERE app_id = ?1", params![ids])?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// Intent rows of every App that has one.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn app_intents(&self) -> Result<Vec<AppIntentRow>, StoreError> {
        self.control
            .read(|c| {
                let mut stmt = c.prepare(&format!("SELECT {COLUMNS} FROM app_intents"))?;
                let rows = stmt.query_map([], from_row)?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(StoreError::from)
            })
            .await
    }

    /// One App's intent (an App without a row is stopped).
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn app_intent(&self, id: AppId) -> Result<AppIntentRow, StoreError> {
        self.control.read(move |c| read(c, id)).await
    }

    /// Record the user's Start (`running`) or Stop (`stopped`). A Stop takes the priority lane,
    /// like an Instance's stop latch.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown App; `Busy` when the normal write queue is full (a stop on the
    /// priority lane is never refused for depth), `Closed` once the store has shut down, and
    /// `Sqlite` or `Encoding` when the transaction fails.
    pub async fn set_app_desired(
        &self,
        id: AppId,
        desired: DesiredState,
    ) -> Result<AppIntentRow, StoreError> {
        let job = move |c: &mut Connection| -> Result<AppIntentRow, StoreError> {
            let tx = c.transaction()?;
            if entities::head_revision(&tx, "app", &id.to_string())?.is_none() {
                return Err(StoreError::NotFound);
            }
            let value = match desired {
                DesiredState::Running => "running",
                DesiredState::Stopped => "stopped",
            };
            tx.execute(
                "INSERT INTO app_intents (app_id, desired, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT (app_id) DO UPDATE SET desired = excluded.desired,
                    intent_revision = intent_revision + 1, updated_at = excluded.updated_at",
                params![id.to_string(), value, Timestamp::now().to_string()],
            )?;
            let row = read(&tx, id)?;
            tx.commit()?;
            Ok(row)
        };
        match desired {
            DesiredState::Stopped => self.control.write_priority(job).await,
            DesiredState::Running => self.control.write(job).await,
        }
    }

    /// Record the run now supervised (`Some`) or that none is left (`None`).
    ///
    /// # Errors
    ///
    /// `Busy` when the normal write queue is full (a stop on the priority lane is never refused for
    /// depth), `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the
    /// transaction fails.
    pub async fn set_app_run(
        &self,
        id: AppId,
        run: Option<AppRunRecord>,
    ) -> Result<(), StoreError> {
        // Clearing a record follows a confirmed stop: never queued behind ordinary writes.
        let clearing = run.is_none();
        // One transaction: a write retried on a full disk repeats all of it.
        let job = move |c: &mut Connection| -> Result<(), StoreError> {
            let now = Timestamp::now().to_string();
            let tx = c.transaction()?;
            match run {
                Some(r) => {
                    tx.execute(
                        "INSERT INTO app_intents (app_id, desired, updated_at) VALUES (?1, 'stopped', ?2)
                         ON CONFLICT (app_id) DO NOTHING",
                        params![id.to_string(), now],
                    )?;
                    tx.execute(
                        "UPDATE app_intents SET run_id = ?2, run_pid = ?3, run_started_us = ?4,
                            run_backend = ?5, run_revision = ?6, run_gateway_port = ?7,
                            run_started_at = ?8, updated_at = ?9, run_boot_id = ?10
                          WHERE app_id = ?1",
                        params![
                            id.to_string(),
                            r.run_id,
                            i64::from(r.pid),
                            r.started_us.cast_signed(),
                            r.backend,
                            r.revision.cast_signed(),
                            r.gateway_port.map(i64::from),
                            r.started_at.to_string(),
                            now,
                            r.boot_id
                        ],
                    )?;
                }
                None => {
                    tx.execute(
                        "UPDATE app_intents SET run_id = NULL, run_pid = NULL, run_started_us = NULL,
                            run_backend = NULL, run_revision = NULL, run_gateway_port = NULL,
                            run_started_at = NULL, run_boot_id = NULL, updated_at = ?2
                          WHERE app_id = ?1",
                        params![id.to_string(), now],
                    )?;
                }
            }
            tx.commit()?;
            Ok(())
        };
        if clearing {
            self.control.write_priority(job).await
        } else {
            self.control.write(job).await
        }
    }
}
