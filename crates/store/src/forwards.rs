//! Port forwards: the binding entities (revisioned, kind `forward_binding`) and the evidence that
//! a forward was reached from outside.
//!
//! Evidence is runtime state: per binding and protocol, when an inbound connection last arrived
//! from outside the tunnel's own and private networks. It counts only while the binding keeps
//! the connection and tunnel port it was observed on (a moved binding starts unverified); it
//! goes with the binding.

use rusqlite::{Connection, params};
use vpn_domain::{ForwardBindingId, InstanceId, Timestamp};

use crate::Store;
use crate::entities;
use crate::error::StoreError;

/// One protocol's latest arrival from outside at a port forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardEvidence {
    pub binding_id: ForwardBindingId,
    /// `true` for UDP, `false` for TCP.
    pub udp: bool,
    pub instance_id: InstanceId,
    pub tunnel_port: u16,
    pub observed_at: Timestamp,
}

const fn protocol(udp: bool) -> &'static str {
    if udp { "udp" } else { "tcp" }
}

fn rows(c: &Connection) -> Result<Vec<ForwardEvidence>, StoreError> {
    let mut stmt = c.prepare(
        "SELECT binding_id, protocol, instance_id, tunnel_port, observed_ms FROM forward_evidence",
    )?;
    let mapped = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, i64>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in mapped {
        let (binding, proto, instance, port, ms) = row?;
        // A row this build cannot read is skipped, never guessed.
        let (Ok(binding_id), Ok(instance_id), Ok(tunnel_port), Some(observed_at)) = (
            binding.parse(),
            instance.parse(),
            u16::try_from(port),
            Timestamp::from_unix_millis(ms),
        ) else {
            continue;
        };
        out.push(ForwardEvidence {
            binding_id,
            udp: proto == "udp",
            instance_id,
            tunnel_port,
            observed_at,
        });
    }
    Ok(out)
}

impl Store {
    /// Delete a port forward and its evidence in one transaction.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown forward, `RevisionConflict` when `expected_revision` is stale;
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn delete_forward(
        &self,
        id: ForwardBindingId,
        expected_revision: u64,
    ) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                let ids = id.to_string();
                let tx = c.transaction()?;
                let current = entities::head_revision(&tx, "forward_binding", &ids)?
                    .ok_or(StoreError::NotFound)?;
                if current != expected_revision {
                    return Err(StoreError::RevisionConflict {
                        expected: expected_revision,
                        current,
                    });
                }
                tx.execute(
                    "DELETE FROM entity_heads WHERE kind = 'forward_binding' AND id = ?1",
                    params![ids],
                )?;
                tx.execute(
                    "DELETE FROM forward_evidence WHERE binding_id = ?1",
                    params![ids],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// Record an arrival from outside at `e.tunnel_port` of `e.instance_id`. The newer time
    /// wins for the same connection and port; a different one replaces the row.
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn record_forward_evidence(&self, e: ForwardEvidence) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                if entities::head_revision(c, "forward_binding", &e.binding_id.to_string())?
                    .is_none()
                {
                    // Deleted meanwhile: nothing to keep evidence for.
                    return Ok(());
                }
                c.execute(
                    "INSERT INTO forward_evidence
                        (binding_id, protocol, instance_id, tunnel_port, observed_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT (binding_id, protocol) DO UPDATE SET
                        observed_ms = CASE
                            WHEN instance_id = excluded.instance_id
                             AND tunnel_port = excluded.tunnel_port
                            THEN MAX(observed_ms, excluded.observed_ms)
                            ELSE excluded.observed_ms END,
                        instance_id = excluded.instance_id,
                        tunnel_port = excluded.tunnel_port",
                    params![
                        e.binding_id.to_string(),
                        protocol(e.udp),
                        e.instance_id.to_string(),
                        i64::from(e.tunnel_port),
                        e.observed_at.unix_millis(),
                    ],
                )?;
                Ok(())
            })
            .await
    }

    /// Every evidence row (one per forward and protocol at most).
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn forward_evidence(&self) -> Result<Vec<ForwardEvidence>, StoreError> {
        self.control.read(rows).await
    }
}
