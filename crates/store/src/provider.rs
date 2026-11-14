//! The global Provider egress binding: one row whose `bootstrap_consumed` latch and
//! `route_revision` fence only move forward (the schema refuses anything else).

use rusqlite::{Connection, OptionalExtension, params};
use vpn_domain::{EgressMode, InstanceId, ProviderEgress, Timestamp, tr};

use crate::Store;
use crate::entities;
use crate::error::StoreError;

const fn mode_str(m: EgressMode) -> &'static str {
    match m {
        EgressMode::ViaInstance => "via_instance",
        EgressMode::Disabled => "disabled",
    }
}

pub fn read(c: &Connection) -> Result<ProviderEgress, StoreError> {
    let (revision, route_revision, mode, consumed, selected) = c.query_row(
        "SELECT revision, route_revision, desired_mode, bootstrap_consumed, selected_instance_id
           FROM provider_egress WHERE id = 1",
        [],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        },
    )?;
    Ok(ProviderEgress {
        revision: revision.cast_unsigned(),
        route_revision: route_revision.cast_unsigned(),
        desired_mode: match mode.as_str() {
            "via_instance" => EgressMode::ViaInstance,
            "disabled" => EgressMode::Disabled,
            other => return Err(StoreError::Corrupt(format!("provider egress mode {other}"))),
        },
        bootstrap_consumed: consumed,
        selected_instance_id: selected
            .map(|s| {
                s.parse()
                    .map_err(|_| StoreError::Corrupt("provider egress instance".into()))
            })
            .transpose()?,
    })
}

/// The Instance Provider traffic goes through cannot be deleted from under it.
pub fn ensure_not_egress(c: &Connection, instance_id: &str) -> Result<(), StoreError> {
    let selected: Option<String> = c
        .query_row(
            "SELECT selected_instance_id FROM provider_egress WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    if selected.as_deref() == Some(instance_id) {
        return Err(StoreError::InvalidState(tr!(
            "This connection is the Provider egress; switch the Provider egress or turn it off first",
            "這個連線是 Provider 出口；請先切換或停用 Provider 出口",
            "この接続は Provider 出口です。先に Provider 出口を切り替えるか無効にしてください"
        )));
    }
    Ok(())
}

impl Store {
    /// The Provider egress choice and route state.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn provider_egress(&self) -> Result<ProviderEgress, StoreError> {
        self.control.read(read).await
    }

    /// Change the user's choice (CAS on `revision`). Every change also advances the route fence,
    /// so Provider work started for the previous route can no longer complete.
    ///
    /// # Errors
    ///
    /// `RevisionConflict` when `revision` is stale, `InvalidState` when the selected Instance does
    /// not exist, `Refused` (`BOOTSTRAP_IN_PROGRESS`) while a run is sealing; `Busy` when the write
    /// queue is full, `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the
    /// transaction fails.
    pub async fn put_provider_egress(
        &self,
        desired_mode: EgressMode,
        selected: Option<InstanceId>,
        expected_revision: u64,
    ) -> Result<ProviderEgress, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let current = read(&tx)?;
                if current.revision != expected_revision {
                    return Err(StoreError::RevisionConflict {
                        expected: expected_revision,
                        current: current.revision,
                    });
                }
                if let Some(id) = selected
                    && entities::head_revision(&tx, "instance", &id.to_string())?.is_none()
                {
                    return Err(StoreError::InvalidState(tr!(
                        "The selected connection does not exist",
                        "選擇的連線不存在",
                        "選択した接続が存在しません"
                    )));
                }
                // Choosing an Instance or turning egress off ends a run of the direct exception
                // (its connection is then not promoted), in this same transaction.
                crate::bootstrap::on_binding_change(
                    &tx,
                    selected.is_some() || desired_mode == EgressMode::Disabled,
                )?;
                tx.execute(
                    "UPDATE provider_egress
                        SET revision = revision + 1, route_revision = route_revision + 1,
                            desired_mode = ?1, selected_instance_id = ?2, updated_at = ?3
                      WHERE id = 1",
                    params![
                        mode_str(desired_mode),
                        selected.map(|s| s.to_string()),
                        Timestamp::now().to_string()
                    ],
                )?;
                let out = read(&tx)?;
                tx.commit()?;
                Ok(out)
            })
            .await
    }

    /// Use up the one direct bootstrap for good: idempotent, never undone. The first time it
    /// also advances the route fence, ending everything that ran on the bootstrap route.
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn consume_bootstrap(&self) -> Result<ProviderEgress, StoreError> {
        self.control
            .write(|c| {
                c.execute(
                    "UPDATE provider_egress
                        SET route_revision = route_revision + (1 - bootstrap_consumed),
                            bootstrap_consumed = 1, updated_at = ?1
                      WHERE id = 1",
                    params![Timestamp::now().to_string()],
                )?;
                read(c)
            })
            .await
    }
}
