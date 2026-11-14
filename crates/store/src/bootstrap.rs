//! The runs of the Provider egress's direct exception (architecture §7), one row each in
//! `bootstrap_journal`: the first setup — a single permanent row whose key is derived from the
//! installation id — and every manual rebootstrap.
//!
//! A run holds the direct grant (the manager keeps the socket in memory; the row says which grant
//! and until when), at most one connection it builds (its *child*), and the seal sequence: the
//! intent to seal is written before the manager closes direct access, and the latch, the binding
//! and the end of the run are committed together afterwards. The child is created with its
//! Instance, its Gateway and a `running` intent in one transaction, so a crash right after leaves
//! a connection that starts by itself and a promotion that resumes or ends by its deadline.
//!
//! What the schema itself guarantees, whatever the code above does and however many writers race:
//! one first-setup row ever (its key is unique, derived and never changed; no row is ever
//! deleted); at most one active run; the first setup never gets a grant again once the latch is
//! set; a rebootstrap only exists with the latch set; a seal intent is never withdrawn (the run
//! ends sealed or blocked, never active again); a sealed run stays sealed and implies the latch;
//! a finished rebootstrap stays finished.

use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use vpn_domain::tr;
use vpn_domain::{
    BootstrapKind, BootstrapRun, BootstrapStage, EgressMode, ErrorCode, GatewaySpec,
    InstallationId, InstanceId, InstanceSpec, OperationId, ProfileId, ProviderEgress, Text,
    Timestamp,
};

use crate::error::StoreError;
use crate::{Store, entities, provider};

pub const CONTROL_STEP: &str = r"
CREATE TABLE bootstrap_journal (
    id                    TEXT    PRIMARY KEY,
    kind                  TEXT    NOT NULL CHECK (kind IN ('initial', 'rebootstrap')),
    initial_bootstrap_key TEXT    UNIQUE
                          CHECK (initial_bootstrap_key IS NULL OR length(initial_bootstrap_key) = 64),
    stage                 TEXT    NOT NULL CHECK (stage IN ('grant_active', 'instance_requested',
                              'sealing', 'sealed', 'blocked', 'cancelled', 'expired')),
    operation_id          TEXT,
    grant_id              TEXT,
    grant_expires_ms      INTEGER,
    child_operation_id    TEXT    UNIQUE,
    child_reserved_ms     INTEGER,
    child_instance_id     TEXT    UNIQUE,
    child_profile_id      TEXT,
    promote_deadline_ms   INTEGER,
    seal_intent_ms        INTEGER,
    revoked_ms            INTEGER,
    reason_code           TEXT,
    reason                TEXT,
    created_at            TEXT    NOT NULL,
    updated_at            TEXT    NOT NULL,
    CHECK ((kind = 'initial') = (initial_bootstrap_key IS NOT NULL)),
    CHECK ((grant_id IS NULL) = (grant_expires_ms IS NULL)),
    CHECK ((child_operation_id IS NULL) = (child_reserved_ms IS NULL)),
    CHECK (stage <> 'grant_active' OR grant_id IS NOT NULL),
    CHECK (stage IN ('grant_active', 'instance_requested', 'sealing') OR grant_id IS NULL),
    CHECK (stage NOT IN ('instance_requested', 'sealing', 'sealed') OR child_instance_id IS NOT NULL),
    CHECK (stage NOT IN ('sealing', 'sealed') OR seal_intent_ms IS NOT NULL)
) WITHOUT ROWID;
-- One first-setup row at most, whatever key a writer computed.
CREATE UNIQUE INDEX bootstrap_journal_one_initial ON bootstrap_journal (kind) WHERE kind = 'initial';
-- At most one run holds or prepares direct access.
CREATE UNIQUE INDEX bootstrap_journal_one_active ON bootstrap_journal
    ((stage IN ('grant_active', 'instance_requested', 'sealing')))
    WHERE stage IN ('grant_active', 'instance_requested', 'sealing');
CREATE TRIGGER bootstrap_journal_kept
BEFORE DELETE ON bootstrap_journal
BEGIN
    SELECT RAISE(ABORT, 'bootstrap runs are permanent');
END;
CREATE TRIGGER bootstrap_journal_identity
BEFORE UPDATE OF id, kind, initial_bootstrap_key, created_at ON bootstrap_journal
WHEN NEW.id IS NOT OLD.id OR NEW.kind IS NOT OLD.kind
  OR NEW.initial_bootstrap_key IS NOT OLD.initial_bootstrap_key
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'a bootstrap run keeps its identity');
END;
CREATE TRIGGER bootstrap_journal_seal_intent
BEFORE UPDATE ON bootstrap_journal
WHEN OLD.seal_intent_ms IS NOT NULL
 AND (NEW.seal_intent_ms IS NOT OLD.seal_intent_ms OR NEW.stage NOT IN ('sealing', 'sealed', 'blocked'))
BEGIN
    SELECT RAISE(ABORT, 'a seal intent is never withdrawn');
END;
CREATE TRIGGER bootstrap_journal_sealed
BEFORE UPDATE ON bootstrap_journal
WHEN OLD.stage = 'sealed' AND NEW.stage <> 'sealed'
BEGIN
    SELECT RAISE(ABORT, 'a sealed bootstrap run stays sealed');
END;
CREATE TRIGGER bootstrap_journal_sealed_latch
BEFORE UPDATE OF stage ON bootstrap_journal
WHEN NEW.stage = 'sealed' AND (SELECT bootstrap_consumed FROM provider_egress WHERE id = 1) IS NOT 1
BEGIN
    SELECT RAISE(ABORT, 'a sealed bootstrap run needs the latch');
END;
CREATE TRIGGER bootstrap_journal_rebootstrap_finished
BEFORE UPDATE OF stage ON bootstrap_journal
WHEN OLD.kind = 'rebootstrap' AND OLD.stage IN ('sealed', 'blocked', 'cancelled', 'expired')
 AND NEW.stage <> OLD.stage
BEGIN
    SELECT RAISE(ABORT, 'a finished rebootstrap stays finished');
END;
CREATE TRIGGER bootstrap_journal_initial_reopen
BEFORE UPDATE OF grant_id ON bootstrap_journal
WHEN NEW.kind = 'initial' AND NEW.grant_id IS NOT NULL AND NEW.grant_id IS NOT OLD.grant_id
 AND (SELECT bootstrap_consumed FROM provider_egress WHERE id = 1) IS NOT 0
BEGIN
    SELECT RAISE(ABORT, 'the first-setup bootstrap is used up');
END;
CREATE TRIGGER bootstrap_journal_initial_open
BEFORE INSERT ON bootstrap_journal
WHEN NEW.kind = 'initial' AND NEW.grant_id IS NOT NULL
 AND (SELECT bootstrap_consumed FROM provider_egress WHERE id = 1) IS NOT 0
BEGIN
    SELECT RAISE(ABORT, 'the first-setup bootstrap is used up');
END;
CREATE TRIGGER bootstrap_journal_rebootstrap_latch
BEFORE INSERT ON bootstrap_journal
WHEN NEW.kind = 'rebootstrap' AND (SELECT bootstrap_consumed FROM provider_egress WHERE id = 1) IS NOT 1
BEGIN
    SELECT RAISE(ABORT, 'a rebootstrap keeps the latch set');
END;
";

/// How long a connect request holds the run's one connection before it is built.
///
/// The time runs since it took or last renewed the reservation; after that (the request died with its controller) another
/// request may take it over. Far shorter than a grant, so a dead request does not block the rest
/// of it; a request still building renews it well within this ([`Store::renew_bootstrap_child`]),
/// however slow its provider requests are.
pub const RESERVATION_TTL: Duration = Duration::from_secs(90);

/// The key of the first setup: SHA-256 of the installation id (canonical UTF-8) followed by
/// `/initial-bootstrap-v1`, in lowercase hex. Not a secret.
#[must_use]
pub fn initial_bootstrap_key(installation: InstallationId) -> String {
    let mut h = Sha256::new();
    h.update(installation.to_string().as_bytes());
    h.update(b"/initial-bootstrap-v1");
    hex::encode(h.finalize())
}

/// One run as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapRow {
    pub id: String,
    pub kind: BootstrapKind,
    pub stage: BootstrapStage,
    /// The request that opened (or last reopened) it.
    pub operation_id: Option<String>,
    /// The manager's grant, while open.
    pub grant_id: Option<String>,
    pub grant_expires_at: Option<Timestamp>,
    /// The connect request building the run's connection, and since when.
    pub child_operation_id: Option<String>,
    pub child_reserved_at: Option<Timestamp>,
    pub child_instance_id: Option<InstanceId>,
    pub child_profile_id: Option<ProfileId>,
    pub promote_deadline: Option<Timestamp>,
    pub seal_intent_at: Option<Timestamp>,
    /// Evidence of the seal: when the manager closed the grant for it.
    pub revoked_at: Option<Timestamp>,
    pub reason_code: Option<String>,
    pub reason: Option<Text>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl BootstrapRow {
    /// The public view (no operation ids, no grant id).
    #[must_use]
    pub fn view(&self) -> BootstrapRun {
        BootstrapRun {
            id: self.id.clone(),
            kind: self.kind,
            stage: self.stage,
            child_instance_id: self.child_instance_id,
            child_profile_id: self.child_profile_id,
            grant_expires_at: self.grant_expires_at,
            promote_deadline: self.promote_deadline,
            reason_code: self.reason_code.clone(),
            reason: self.reason.clone(),
            updated_at: self.updated_at,
        }
    }
}

/// Why an open grant ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantEnd {
    Expired,
    Cancelled,
}

/// What a connect request gets from the active run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildClaim {
    /// No run builds a connection now: an ordinary connection.
    None,
    /// This request builds the run's one connection.
    Reserved(BootstrapRow),
    /// The run already has its connection: it is used again; nothing new is built.
    Existing(BootstrapRow),
}

// Reasons recorded on runs (public words).
pub const REASON_MANAGER_RESTARTED: &str = "MANAGER_RESTARTED";
pub const REASON_PROMOTE_TIMEOUT: &str = "PROMOTE_TIMEOUT";
pub const REASON_CHILD_GONE: &str = "CHILD_GONE";
pub const REASON_EGRESS_CHANGED: &str = "EGRESS_CHANGED";
pub const REASON_SEAL_RECOVERED: &str = "SEAL_RECOVERED";

const fn stage_str(s: BootstrapStage) -> &'static str {
    match s {
        BootstrapStage::GrantActive => "grant_active",
        BootstrapStage::InstanceRequested => "instance_requested",
        BootstrapStage::Sealing => "sealing",
        BootstrapStage::Sealed => "sealed",
        BootstrapStage::Blocked => "blocked",
        BootstrapStage::Cancelled => "cancelled",
        BootstrapStage::Expired => "expired",
    }
}

fn parse_stage(s: &str) -> Result<BootstrapStage, StoreError> {
    Ok(match s {
        "grant_active" => BootstrapStage::GrantActive,
        "instance_requested" => BootstrapStage::InstanceRequested,
        "sealing" => BootstrapStage::Sealing,
        "sealed" => BootstrapStage::Sealed,
        "blocked" => BootstrapStage::Blocked,
        "cancelled" => BootstrapStage::Cancelled,
        "expired" => BootstrapStage::Expired,
        other => return Err(StoreError::Corrupt(format!("bootstrap stage {other}"))),
    })
}

const fn ms(t: Timestamp) -> i64 {
    t.unix_millis()
}

fn at(ms: Option<i64>) -> Result<Option<Timestamp>, StoreError> {
    ms.map(|v| {
        Timestamp::from_unix_millis(v).ok_or_else(|| StoreError::Corrupt("bootstrap time".into()))
    })
    .transpose()
}

fn text_ts(s: &str) -> Result<Timestamp, StoreError> {
    Ok(serde_json::from_value(serde_json::Value::String(
        s.to_string(),
    ))?)
}

fn parse_id<T: std::str::FromStr>(s: Option<String>, what: &str) -> Result<Option<T>, StoreError> {
    s.map(|v| {
        v.parse()
            .map_err(|_| StoreError::Corrupt(format!("bootstrap {what}")))
    })
    .transpose()
}

const COLUMNS: &str = "id, kind, stage, operation_id, grant_id, grant_expires_ms, child_operation_id, \
     child_reserved_ms, child_instance_id, child_profile_id, promote_deadline_ms, seal_intent_ms, \
     revoked_ms, reason_code, reason, created_at, updated_at";

type Raw = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
    String,
    String,
);

fn raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<Raw> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
        r.get(12)?,
        r.get(13)?,
        r.get(14)?,
        r.get(15)?,
        r.get(16)?,
    ))
}

fn row_of(r: Raw) -> Result<BootstrapRow, StoreError> {
    let (
        id,
        kind,
        stage,
        operation_id,
        grant_id,
        grant_expires,
        child_operation_id,
        child_reserved,
        child_instance,
        child_profile,
        deadline,
        seal_intent,
        revoked,
        reason_code,
        reason,
        created,
        updated,
    ) = r;
    Ok(BootstrapRow {
        id,
        kind: match kind.as_str() {
            "initial" => BootstrapKind::Initial,
            "rebootstrap" => BootstrapKind::Rebootstrap,
            other => return Err(StoreError::Corrupt(format!("bootstrap kind {other}"))),
        },
        stage: parse_stage(&stage)?,
        operation_id,
        grant_id,
        grant_expires_at: at(grant_expires)?,
        child_operation_id,
        child_reserved_at: at(child_reserved)?,
        child_instance_id: parse_id(child_instance, "instance")?,
        child_profile_id: parse_id(child_profile, "profile")?,
        promote_deadline: at(deadline)?,
        seal_intent_at: at(seal_intent)?,
        revoked_at: at(revoked)?,
        reason_code,
        reason: reason.map(crate::text_column::from_column),
        created_at: text_ts(&created)?,
        updated_at: text_ts(&updated)?,
    })
}

fn one(
    c: &Connection,
    filter: &str,
    p: impl rusqlite::Params,
) -> Result<Option<BootstrapRow>, StoreError> {
    c.query_row(
        &format!("SELECT {COLUMNS} FROM bootstrap_journal WHERE {filter}"),
        p,
        raw,
    )
    .optional()?
    .map(row_of)
    .transpose()
}

pub fn get(c: &Connection, id: &str) -> Result<Option<BootstrapRow>, StoreError> {
    one(c, "id = ?1", params![id])
}

pub fn active(c: &Connection) -> Result<Option<BootstrapRow>, StoreError> {
    one(
        c,
        "stage IN ('grant_active', 'instance_requested', 'sealing')",
        [],
    )
}

fn initial(c: &Connection) -> Result<Option<BootstrapRow>, StoreError> {
    one(c, "kind = 'initial'", [])
}

fn require(c: &Connection, id: &str) -> Result<BootstrapRow, StoreError> {
    get(c, id)?.ok_or(StoreError::NotFound)
}

fn now_text() -> String {
    Timestamp::now().to_string()
}

fn refused(code: ErrorCode, message: impl Into<Text>) -> StoreError {
    StoreError::Refused {
        code,
        message: message.into(),
    }
}

/// The first setup's direct connection was used: provider work goes through the VPN only.
fn first_direct_used() -> StoreError {
    refused(
        ErrorCode::BootstrapAlreadyConsumed,
        tr!(
            "The first direct connection has already been used; provider operations only go through the selected VPN connection",
            "首次直連已經使用過；供應商操作只會經選定的 VPN 連線",
            "初回の直接接続はすでに使用済みです。プロバイダーの操作は選択した VPN 接続だけを経由します"
        ),
    )
}

/// No direct connection opens while the Provider egress is off.
fn egress_disabled() -> StoreError {
    StoreError::InvalidState(tr!(
        "The Provider egress is turned off",
        "Provider 出口已停用",
        "Provider 出口は無効になっています"
    ))
}

/// A rebootstrap holds the one direct connection there may be.
fn rebootstrap_running() -> StoreError {
    refused(
        ErrorCode::BootstrapInProgress,
        tr!(
            "A direct reconnection is in progress; only one direct connection can be open at a time",
            "重新直連正在進行；一次只能有一個直連",
            "再度の直接接続が進行中です。直接接続は一度に 1 つだけです"
        ),
    )
}

/// The run's connection is being made the egress (the seal is under way).
fn sealing_wait() -> StoreError {
    refused(
        ErrorCode::BootstrapInProgress,
        tr!(
            "The new connection is being made the Provider egress; please wait",
            "正在把新連線設為 Provider 出口，請稍候",
            "新しい接続を Provider 出口に設定しています。しばらくお待ちください"
        ),
    )
}

fn instance_exists(c: &Connection, id: InstanceId) -> Result<bool, StoreError> {
    Ok(entities::head_revision(c, "instance", &id.to_string())?.is_some())
}

/// Set the latch (forward only; the first time also advances the route fence).
fn latch(c: &Connection) -> Result<(), StoreError> {
    c.execute(
        "UPDATE provider_egress
            SET route_revision = route_revision + (1 - bootstrap_consumed),
                bootstrap_consumed = 1, updated_at = ?1
          WHERE id = 1",
        params![now_text()],
    )?;
    Ok(())
}

/// End `row` at `stage` (not active), closing its grant; a reservation without a connection
/// goes with it.
fn end_row(
    c: &Connection,
    row: &BootstrapRow,
    stage: BootstrapStage,
    code: &str,
    reason: &Text,
) -> Result<(), StoreError> {
    c.execute(
        "UPDATE bootstrap_journal
            SET stage = ?2, grant_id = NULL, grant_expires_ms = NULL,
                child_operation_id = CASE WHEN child_instance_id IS NULL THEN NULL ELSE child_operation_id END,
                child_reserved_ms = CASE WHEN child_instance_id IS NULL THEN NULL ELSE child_reserved_ms END,
                reason_code = ?3, reason = ?4, updated_at = ?5
          WHERE id = ?1",
        params![
            row.id,
            stage_str(stage),
            code,
            crate::text_column::to_column(reason),
            now_text()
        ],
    )?;
    Ok(())
}

/// The commit of a seal: the latch, the binding to the run's connection and the run's end, in
/// the caller's transaction. Without its connection (deleted meanwhile) the run ends blocked —
/// the latch is set all the same.
fn commit_seal(
    c: &Connection,
    row: &BootstrapRow,
    revoked_at: Timestamp,
) -> Result<(), StoreError> {
    let child = row
        .child_instance_id
        .ok_or_else(|| StoreError::Corrupt("sealing run without its connection".into()))?;
    if !instance_exists(c, child)? {
        latch(c)?;
        c.execute(
            "UPDATE bootstrap_journal
                SET stage = 'blocked', grant_id = NULL, grant_expires_ms = NULL, revoked_ms = ?2,
                    reason_code = ?3, reason = ?4, updated_at = ?5
              WHERE id = ?1",
            params![
                row.id,
                ms(revoked_at),
                REASON_CHILD_GONE,
                crate::text_column::to_column(&tr!(
                    "The new connection no longer exists and was not made the egress; the direct connection is closed",
                    "新連線已不存在，未設為出口；直連已關閉",
                    "新しい接続はもう存在しないため出口にしませんでした。直接接続は閉じています"
                )),
                now_text()
            ],
        )?;
        return Ok(());
    }
    c.execute(
        "UPDATE provider_egress
            SET revision = revision + 1, route_revision = route_revision + 1,
                bootstrap_consumed = 1, desired_mode = 'via_instance',
                selected_instance_id = ?1, updated_at = ?2
          WHERE id = 1",
        params![child.to_string(), now_text()],
    )?;
    c.execute(
        "UPDATE bootstrap_journal
            SET stage = 'sealed', grant_id = NULL, grant_expires_ms = NULL, revoked_ms = ?2,
                reason_code = NULL, reason = NULL, updated_at = ?3
          WHERE id = ?1",
        params![row.id, ms(revoked_at), now_text()],
    )?;
    Ok(())
}

/// The user changed the binding (chose an Instance or turned egress off): an active run ends,
/// in the same transaction. A run that is sealing refuses the change instead (it is about to
/// write the binding itself; the window is a moment).
pub fn on_binding_change(c: &Connection, ends_runs: bool) -> Result<(), StoreError> {
    let Some(row) = active(c)? else {
        return Ok(());
    };
    if row.stage == BootstrapStage::Sealing {
        return Err(refused(
            ErrorCode::BootstrapInProgress,
            tr!(
                "The new connection is being made the Provider egress; try again in a moment",
                "正在把新連線設為 Provider 出口，請稍候再試",
                "新しい接続を Provider 出口に設定しています。しばらくしてからもう一度お試しください"
            ),
        ));
    }
    if ends_runs {
        end_row(
            c,
            &row,
            BootstrapStage::Cancelled,
            REASON_EGRESS_CHANGED,
            &tr!(
                "The Provider egress was changed by hand; this direct connection ends, and a new connection (if any) does not become the egress by itself",
                "已手動變更 Provider 出口；這次直連結束，新連線（若有）不會自動成為出口",
                "Provider 出口が手動で変更されたため、この直接接続は終了します。新しい接続（あれば）が自動で出口になることはありません"
            ),
        )?;
    }
    Ok(())
}

/// An Instance is being deleted: a run whose connection it is forgets it. While the run's
/// grant is open the run goes on (it may build another one); without a grant it ends blocked.
pub fn on_instance_deleted(c: &Connection, id: &str) -> Result<(), StoreError> {
    if let Some(row) = active(c)?
        && row.child_instance_id.map(|i| i.to_string()).as_deref() == Some(id)
    {
        if row.stage == BootstrapStage::Sealing {
            return Err(refused(
                ErrorCode::BootstrapInProgress,
                tr!(
                    "This connection is becoming the Provider egress; try again in a moment",
                    "這條連線正在成為 Provider 出口，請稍候再試",
                    "この接続を Provider 出口に設定しています。しばらくしてからもう一度お試しください"
                ),
            ));
        }
        if row.grant_id.is_some() {
            c.execute(
                "UPDATE bootstrap_journal
                    SET stage = 'grant_active', child_instance_id = NULL, child_profile_id = NULL,
                        child_operation_id = NULL, child_reserved_ms = NULL,
                        promote_deadline_ms = NULL, reason_code = ?2, reason = ?3, updated_at = ?4
                  WHERE id = ?1",
                params![
                    row.id,
                    REASON_CHILD_GONE,
                    crate::text_column::to_column(&tr!(
                        "The new connection was deleted and was not made the egress",
                        "新連線已被刪除，未設為出口",
                        "新しい接続が削除されたため出口にしませんでした"
                    )),
                    now_text()
                ],
            )?;
        } else {
            end_row(
                c,
                &row,
                BootstrapStage::Blocked,
                REASON_CHILD_GONE,
                &tr!(
                    "The new connection was deleted and was not made the egress",
                    "新連線已被刪除，未設為出口",
                    "新しい接続が削除されたため出口にしませんでした"
                ),
            )?;
        }
    }
    Ok(())
}

impl Store {
    /// The first setup's key for this installation (see [`initial_bootstrap_key`]).
    pub fn initial_bootstrap_key(&self) -> String {
        initial_bootstrap_key(self.installation_id)
    }

    /// Run `id`, if it exists.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn bootstrap_run(&self, id: String) -> Result<Option<BootstrapRow>, StoreError> {
        self.control.read(move |c| get(c, &id)).await
    }

    /// The active run, else the one that changed last.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn latest_bootstrap(&self) -> Result<Option<BootstrapRow>, StoreError> {
        self.control
            .read(|c| {
                active(c)?.map_or_else(
                    || one(c, "1 = 1 ORDER BY updated_at DESC, id LIMIT 1", []),
                    |r| Ok(Some(r)),
                )
            })
            .await
    }

    /// Every run, newest first.
    ///
    /// # Errors
    ///
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the read or a row's
    /// decoding fails.
    pub async fn bootstrap_runs(&self) -> Result<Vec<BootstrapRow>, StoreError> {
        self.control
            .read(|c| {
                let mut stmt = c.prepare(&format!(
                    "SELECT {COLUMNS} FROM bootstrap_journal ORDER BY created_at DESC, id"
                ))?;
                let rows = stmt.query_map([], raw)?;
                rows.map(|r| row_of(r?)).collect()
            })
            .await
    }

    /// Give the first setup's run the grant `grant_id`: creates the permanent row the first time,
    /// reopens it on a retry — keeping the connection it built, if that still exists. Refused once
    /// the latch is set or a seal intent exists, while a rebootstrap is active, while an egress
    /// Instance is chosen or egress is off.
    ///
    /// # Errors
    ///
    /// `Refused` (`BOOTSTRAP_ALREADY_CONSUMED` once the bootstrap was used or sealed,
    /// `BOOTSTRAP_IN_PROGRESS` while a rebootstrap runs), `InvalidState` when the Provider egress
    /// is off or an egress connection is already selected; `Busy` when the write queue is full,
    /// `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the transaction
    /// fails.
    pub async fn open_initial_bootstrap(
        &self,
        grant_id: String,
        expires_at: Timestamp,
        operation: Option<OperationId>,
    ) -> Result<BootstrapRow, StoreError> {
        let key = self.initial_bootstrap_key();
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let egress = provider::read(&tx)?;
                if egress.bootstrap_consumed {
                    return Err(first_direct_used());
                }
                if egress.desired_mode == EgressMode::Disabled {
                    return Err(egress_disabled());
                }
                if egress.selected_instance_id.is_some() {
                    return Err(StoreError::InvalidState(tr!(
                        "An egress connection is already selected; no direct connection is needed",
                        "已選定出口連線，不需要直連",
                        "出口の接続が選択済みのため、直接接続は不要です"
                    )));
                }
                if let Some(a) = active(&tx)?
                    && a.kind != BootstrapKind::Initial
                {
                    return Err(rebootstrap_running());
                }
                let now = Timestamp::now();
                let op = operation.map(|o| o.to_string());
                match initial(&tx)? {
                    None => {
                        tx.execute(
                            "INSERT INTO bootstrap_journal
                                (id, kind, initial_bootstrap_key, stage, operation_id, grant_id,
                                 grant_expires_ms, created_at, updated_at)
                             VALUES (?1, 'initial', ?2, 'grant_active', ?3, ?4, ?5, ?6, ?6)",
                            params![
                                uuid::Uuid::new_v4().to_string(),
                                key,
                                op,
                                grant_id,
                                ms(expires_at),
                                now.to_string()
                            ],
                        )?;
                    }
                    // The manager asks only while it holds no grant: one still on record died
                    // with an earlier process and is replaced.
                    Some(r) => {
                        if r.seal_intent_at.is_some() || r.stage == BootstrapStage::Sealed {
                            return Err(refused(
                                ErrorCode::BootstrapAlreadyConsumed,
                                tr!(
                                    "The first setup is already sealed; provider operations only go through the selected VPN connection",
                                    "首次設定已完成封存；供應商操作只會經選定的 VPN 連線",
                                    "初回設定はすでに封印済みです。プロバイダーの操作は選択した VPN 接続だけを経由します"
                                ),
                            ));
                        }
                        // A connection deleted since is forgotten; one that exists is kept (a
                        // retry continues with it instead of building another).
                        let child = match r.child_instance_id {
                            Some(i) if instance_exists(&tx, i)? => Some(i),
                            _ => None,
                        };
                        let stage = if child.is_some()
                            && r.stage == BootstrapStage::InstanceRequested
                        {
                            BootstrapStage::InstanceRequested
                        } else {
                            BootstrapStage::GrantActive
                        };
                        tx.execute(
                            "UPDATE bootstrap_journal
                                SET stage = ?2, operation_id = ?3, grant_id = ?4, grant_expires_ms = ?5,
                                    child_instance_id = ?6,
                                    child_profile_id = CASE WHEN ?6 IS NULL THEN NULL ELSE child_profile_id END,
                                    child_operation_id = CASE WHEN ?6 IS NULL THEN NULL ELSE child_operation_id END,
                                    child_reserved_ms = CASE WHEN ?6 IS NULL THEN NULL ELSE child_reserved_ms END,
                                    promote_deadline_ms = CASE WHEN ?6 IS NULL THEN NULL ELSE promote_deadline_ms END,
                                    reason_code = NULL, reason = NULL, updated_at = ?7
                              WHERE id = ?1",
                            params![
                                r.id,
                                stage_str(stage),
                                op,
                                grant_id,
                                ms(expires_at),
                                child.map(|i| i.to_string()),
                                now.to_string()
                            ],
                        )?;
                    }
                }
                let out = initial(&tx)?.ok_or(StoreError::NotFound)?;
                tx.commit()?;
                Ok(out)
            })
            .await
    }

    /// Open a manual rebootstrap run with the grant `grant_id` (the caller checked eligibility):
    /// compare-and-set on the egress revision the user saw, refused while another run is active.
    /// The latch is set in the same transaction and stays set.
    ///
    /// # Errors
    ///
    /// `RevisionConflict` when the egress revision moved, `InvalidState` when the Provider egress
    /// is off, `Refused` (`BOOTSTRAP_IN_PROGRESS`) while another run is active, `NotFound` when run
    /// `id` does not exist; `Busy` when the write queue is full, `Closed` once the store has shut
    /// down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn open_rebootstrap(
        &self,
        grant_id: String,
        expires_at: Timestamp,
        operation: Option<OperationId>,
        expected_revision: u64,
    ) -> Result<BootstrapRow, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let egress = provider::read(&tx)?;
                if egress.revision != expected_revision {
                    return Err(StoreError::RevisionConflict {
                        expected: expected_revision,
                        current: egress.revision,
                    });
                }
                if egress.desired_mode == EgressMode::Disabled {
                    return Err(egress_disabled());
                }
                if active(&tx)?.is_some() {
                    return Err(refused(
                        ErrorCode::BootstrapInProgress,
                        tr!(
                            "A direct connection (first setup or direct reconnection) is already in progress; only one can be open at a time",
                            "已有進行中的直連（首次設定或重新直連）；一次只能有一個",
                            "直接接続（初回設定または再度の直接接続）がすでに進行中です。一度に 1 つだけです"
                        ),
                    ));
                }
                latch(&tx)?;
                let id = uuid::Uuid::new_v4().to_string();
                let now = Timestamp::now().to_string();
                tx.execute(
                    "INSERT INTO bootstrap_journal
                        (id, kind, stage, operation_id, grant_id, grant_expires_ms, created_at, updated_at)
                     VALUES (?1, 'rebootstrap', 'grant_active', ?2, ?3, ?4, ?5, ?5)",
                    params![
                        id,
                        operation.map(|o| o.to_string()),
                        grant_id,
                        ms(expires_at),
                        now
                    ],
                )?;
                let out = require(&tx, &id)?;
                tx.commit()?;
                Ok(out)
            })
            .await
    }

    /// The grant `grant_id` of run `id` closed. A run that only held the grant ends (`end`); one
    /// whose connection exists keeps waiting for it. `None`: the run holds another grant (or none).
    ///
    /// # Errors
    ///
    /// `NotFound` when run `id` does not exist; `Busy` when the write queue is full, `Closed` once
    /// the store has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn close_bootstrap_grant(
        &self,
        id: String,
        grant_id: String,
        end: GrantEnd,
        reason_code: String,
        reason: Text,
    ) -> Result<Option<BootstrapRow>, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let Some(row) = get(&tx, &id)? else {
                    return Ok(None);
                };
                if row.grant_id.as_deref() != Some(grant_id.as_str()) {
                    return Ok(None);
                }
                if row.stage == BootstrapStage::GrantActive {
                    let stage = match end {
                        GrantEnd::Expired => BootstrapStage::Expired,
                        GrantEnd::Cancelled => BootstrapStage::Cancelled,
                    };
                    end_row(&tx, &row, stage, &reason_code, &reason)?;
                } else {
                    tx.execute(
                        "UPDATE bootstrap_journal SET grant_id = NULL, grant_expires_ms = NULL, updated_at = ?2
                          WHERE id = ?1",
                        params![row.id, now_text()],
                    )?;
                }
                let out = require(&tx, &id)?;
                tx.commit()?;
                Ok(Some(out))
            })
            .await
    }

    /// Claim the active run's one connection for the connect request `operation`, before any
    /// provider request is made. Another live reservation refuses (`BOOTSTRAP_IN_PROGRESS`); a
    /// connection that exists is returned to be used again.
    ///
    /// # Errors
    ///
    /// `Refused` (`BOOTSTRAP_IN_PROGRESS`) while the run is sealing or another request holds the
    /// reservation; `Busy` when the write queue is full, `Closed` once the store has shut down, and
    /// `Sqlite` or `Encoding` when the transaction fails.
    pub async fn claim_bootstrap_child(
        &self,
        operation: OperationId,
    ) -> Result<ChildClaim, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let Some(row) = active(&tx)? else {
                    return Ok(ChildClaim::None);
                };
                if row.stage == BootstrapStage::Sealing {
                    return Err(sealing_wait());
                }
                if let Some(i) = row.child_instance_id {
                    if instance_exists(&tx, i)? {
                        tx.commit()?;
                        return Ok(ChildClaim::Existing(row));
                    }
                    // Deleted: the run may build another one while its grant is open.
                    tx.execute(
                        "UPDATE bootstrap_journal
                            SET child_instance_id = NULL, child_profile_id = NULL,
                                child_operation_id = NULL, child_reserved_ms = NULL,
                                promote_deadline_ms = NULL,
                                stage = CASE WHEN grant_id IS NULL THEN 'blocked' ELSE 'grant_active' END,
                                reason_code = CASE WHEN grant_id IS NULL THEN ?2 ELSE NULL END,
                                reason = CASE WHEN grant_id IS NULL THEN ?3 ELSE NULL END,
                                updated_at = ?4
                          WHERE id = ?1",
                        params![
                            row.id,
                            REASON_CHILD_GONE,
                            crate::text_column::to_column(&tr!(
                                "The new connection was deleted and was not made the egress",
                                "新連線已被刪除，未設為出口",
                                "新しい接続が削除されたため出口にしませんでした"
                            )),
                            now_text()
                        ],
                    )?;
                }
                let row = require(&tx, &row.id)?;
                if row.stage != BootstrapStage::GrantActive {
                    tx.commit()?;
                    return Ok(ChildClaim::None);
                }
                let mine = operation.to_string();
                if let (Some(holder), Some(since)) = (&row.child_operation_id, row.child_reserved_at)
                    && *holder != mine
                    && Timestamp::now().unix_millis() - since.unix_millis()
                        < i64::try_from(RESERVATION_TTL.as_millis()).unwrap_or(i64::MAX)
                {
                    return Err(refused(
                        ErrorCode::BootstrapInProgress,
                        tr!(
                            "Another request is creating the connection of this direct connection; one direct connection creates one connection only",
                            "另一個請求正在建立這次直連的連線；一次直連只建立一條連線",
                            "別のリクエストがこの直接接続の接続を作成しています。1 回の直接接続で作成できる接続は 1 つだけです"
                        ),
                    ));
                }
                tx.execute(
                    "UPDATE bootstrap_journal
                        SET child_operation_id = ?2, child_reserved_ms = ?3, updated_at = ?4
                      WHERE id = ?1",
                    params![row.id, mine, Timestamp::now().unix_millis(), now_text()],
                )?;
                let out = require(&tx, &row.id)?;
                tx.commit()?;
                Ok(ChildClaim::Reserved(out))
            })
            .await
    }

    /// `operation` is still building run `id`'s connection: its reservation runs from now again.
    /// Only a reservation it still holds, with nothing built yet, on a run that still has its
    /// grant — never one given back, taken over or turned into a connection — so a renewal that
    /// arrives late changes nothing. Returns whether it was renewed.
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn renew_bootstrap_child(
        &self,
        id: String,
        operation: OperationId,
    ) -> Result<bool, StoreError> {
        self.control
            .write(move |c| {
                // Not a change of the run (its `updated_at` stays): only how long it is held.
                let n = c.execute(
                    "UPDATE bootstrap_journal SET child_reserved_ms = ?3
                      WHERE id = ?1 AND child_operation_id = ?2 AND child_instance_id IS NULL
                        AND stage = 'grant_active'",
                    params![id, operation.to_string(), Timestamp::now().unix_millis()],
                )?;
                Ok(n > 0)
            })
            .await
    }

    /// Give up the reservation of `operation` (its connection was not built).
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn release_bootstrap_child(
        &self,
        id: String,
        operation: OperationId,
    ) -> Result<(), StoreError> {
        self.control
            .write(move |c| {
                c.execute(
                    "UPDATE bootstrap_journal
                        SET child_operation_id = NULL, child_reserved_ms = NULL, updated_at = ?3
                      WHERE id = ?1 AND child_operation_id = ?2 AND child_instance_id IS NULL",
                    params![id, operation.to_string(), now_text()],
                )?;
                Ok(())
            })
            .await
    }

    /// Create the run's connection — the Instance with its intent `running` (it starts without
    /// any further request), its Gateway, and the run's record of it with the promotion deadline —
    /// in one transaction. Only for the request holding the reservation.
    ///
    /// # Errors
    ///
    /// `NotFound` when run `id` does not exist, `Refused` (`BOOTSTRAP_IN_PROGRESS`) when another
    /// request built the connection or the run ended, `InvalidState` when the Gateway does not
    /// belong to the connection or an entity cannot be inserted; `Busy` when the write queue is
    /// full, `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the transaction
    /// fails.
    pub async fn create_bootstrap_child(
        &self,
        id: String,
        operation: OperationId,
        spec: InstanceSpec,
        gateway: Option<GatewaySpec>,
        deadline: Timestamp,
    ) -> Result<(InstanceSpec, Option<GatewaySpec>, BootstrapRow), StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let row = require(&tx, &id)?;
                if row.stage != BootstrapStage::GrantActive
                    || row.child_instance_id.is_some()
                    || row.child_operation_id.as_deref() != Some(operation.to_string().as_str())
                {
                    return Err(refused(
                        ErrorCode::BootstrapInProgress,
                        tr!(
                            "Another request already created the connection of this direct connection, or the direct connection has ended",
                            "這次直連的連線已由另一個請求建立，或直連已結束",
                            "この直接接続の接続は別のリクエストですでに作成されたか、直接接続が終了しています"
                        ),
                    ));
                }
                if gateway.as_ref().is_some_and(|g| g.instance_id != spec.id) {
                    return Err(StoreError::InvalidState(tr!(
                        "The Gateway does not belong to this connection",
                        "代理埠不屬於這條連線",
                        "このゲートウェイはこの接続に属していません"
                    )));
                }
                let iid = spec.id.to_string();
                let profile = spec.profile_id.to_string();
                let spec = entities::insert_in(&tx, spec)?;
                tx.execute(
                    "INSERT INTO instance_intents (instance_id, desired, updated_at) VALUES (?1, 'running', ?2)",
                    params![iid, now_text()],
                )?;
                let gateway = gateway.map(|g| entities::insert_in(&tx, g)).transpose()?;
                tx.execute(
                    "UPDATE bootstrap_journal
                        SET stage = 'instance_requested', child_instance_id = ?2, child_profile_id = ?3,
                            promote_deadline_ms = ?4, reason_code = NULL, reason = NULL, updated_at = ?5
                      WHERE id = ?1",
                    params![row.id, iid, profile, ms(deadline), now_text()],
                )?;
                let out = require(&tx, &id)?;
                tx.commit()?;
                Ok((spec, gateway, out))
            })
            .await
    }

    /// The run's connection exists already: wait for it anew (until `deadline`). The caller starts
    /// it.
    ///
    /// # Errors
    ///
    /// `NotFound` when run `id` does not exist, `InvalidState` when the run has no connection to
    /// resume, `Refused` (`BOOTSTRAP_IN_PROGRESS`) while a run is sealing; `Busy` when the write
    /// queue is full, `Closed` once the store has shut down, and `Sqlite` or `Encoding` when the
    /// transaction fails.
    pub async fn resume_bootstrap_child(
        &self,
        id: String,
        deadline: Timestamp,
    ) -> Result<BootstrapRow, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let row = require(&tx, &id)?;
                let resumable = match row.child_instance_id {
                    Some(i) => row.stage.is_active() && instance_exists(&tx, i)?,
                    None => false,
                };
                if !resumable {
                    return Err(StoreError::InvalidState(tr!(
                        "This direct connection has no connection to resume",
                        "這次直連沒有可以繼續的連線",
                        "この直接接続には再開できる接続がありません"
                    )));
                }
                if row.stage == BootstrapStage::Sealing {
                    return Err(sealing_wait());
                }
                tx.execute(
                    "UPDATE bootstrap_journal
                        SET stage = 'instance_requested', promote_deadline_ms = ?2,
                            reason_code = NULL, reason = NULL, updated_at = ?3
                      WHERE id = ?1",
                    params![row.id, ms(deadline), now_text()],
                )?;
                let out = require(&tx, &id)?;
                tx.commit()?;
                Ok(out)
            })
            .await
    }

    /// Seal, step 1: the durable intent, written before direct access is closed. From here on no
    /// crash reopens direct access: the run ends sealed (or blocked), never active again.
    ///
    /// # Errors
    ///
    /// `NotFound` when run `id` does not exist, `InvalidState` when the connection is not the run's
    /// own or the run already ended; `Busy` when the write queue is full, `Closed` once the store
    /// has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn seal_bootstrap_intent(
        &self,
        id: String,
        child: InstanceId,
    ) -> Result<BootstrapRow, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let row = require(&tx, &id)?;
                if row.child_instance_id != Some(child) {
                    return Err(StoreError::InvalidState(tr!(
                        "This connection was not created by this direct connection",
                        "這條連線不是這次直連建立的",
                        "この接続はこの直接接続で作成されたものではありません"
                    )));
                }
                match row.stage {
                    BootstrapStage::Sealing => {}
                    BootstrapStage::InstanceRequested => {
                        tx.execute(
                            "UPDATE bootstrap_journal
                                SET stage = 'sealing', seal_intent_ms = ?2, updated_at = ?3
                              WHERE id = ?1",
                            params![row.id, Timestamp::now().unix_millis(), now_text()],
                        )?;
                    }
                    _ => {
                        return Err(StoreError::InvalidState(tr!(
                            "This direct connection has already ended",
                            "這次直連已經結束",
                            "この直接接続はすでに終了しています"
                        )));
                    }
                }
                let out = require(&tx, &id)?;
                tx.commit()?;
                Ok(out)
            })
            .await
    }

    /// Seal, step 2 (after the manager closed the grant at `revoked_at`): the latch, the binding
    /// to the run's connection (a new route revision) and the end of the run, in one transaction.
    /// A run already sealed is returned as it is.
    ///
    /// # Errors
    ///
    /// `NotFound` when run `id` does not exist, `InvalidState` when no seal intent was written;
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn seal_bootstrap_commit(
        &self,
        id: String,
        revoked_at: Timestamp,
    ) -> Result<(ProviderEgress, BootstrapRow), StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let row = require(&tx, &id)?;
                match row.stage {
                    BootstrapStage::Sealing => commit_seal(&tx, &row, revoked_at)?,
                    BootstrapStage::Sealed => {}
                    _ => {
                        return Err(StoreError::InvalidState(tr!(
                            "No seal intent was written, so the seal cannot be completed",
                            "沒有寫入封存意圖，不能完成封存",
                            "封印の意図が書き込まれていないため、封印を完了できません"
                        )));
                    }
                }
                let out = (provider::read(&tx)?, require(&tx, &id)?);
                tx.commit()?;
                Ok(out)
            })
            .await
    }

    /// The run's connection did not become the egress (not connected by the deadline, failed,
    /// stopped by the user, its exit did not answer). While the run's grant is still open the run
    /// goes on with it (the user may retry with the same connection or fix it); otherwise it ends
    /// blocked. Only a run waiting for its connection changes; any other is returned as it is.
    ///
    /// # Errors
    ///
    /// `NotFound` when run `id` does not exist; `Busy` when the write queue is full, `Closed` once
    /// the store has shut down, and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn abandon_bootstrap_promotion(
        &self,
        id: String,
        reason_code: String,
        reason: Text,
    ) -> Result<BootstrapRow, StoreError> {
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let row = require(&tx, &id)?;
                if row.stage == BootstrapStage::InstanceRequested {
                    if row.grant_id.is_some() {
                        tx.execute(
                            "UPDATE bootstrap_journal
                                SET stage = 'grant_active', promote_deadline_ms = NULL,
                                    reason_code = ?2, reason = ?3, updated_at = ?4
                              WHERE id = ?1",
                            params![
                                row.id,
                                reason_code,
                                crate::text_column::to_column(&reason),
                                now_text()
                            ],
                        )?;
                    } else {
                        end_row(&tx, &row, BootstrapStage::Blocked, &reason_code, &reason)?;
                    }
                }
                let out = require(&tx, &id)?;
                tx.commit()?;
                Ok(out)
            })
            .await
    }

    /// End run `id` without an egress (the user cancelled it, or it cannot go on). A sealing run can only end blocked, and the latch is set with it. An ended
    /// run is returned as it is.
    ///
    /// # Errors
    ///
    /// `InvalidState` for an end other than blocked, cancelled or expired, `NotFound` when run `id`
    /// does not exist; `Busy` when the write queue is full, `Closed` once the store has shut down,
    /// and `Sqlite` or `Encoding` when the transaction fails.
    pub async fn end_bootstrap(
        &self,
        id: String,
        stage: BootstrapStage,
        reason_code: String,
        reason: Text,
    ) -> Result<BootstrapRow, StoreError> {
        if stage.is_active() || stage == BootstrapStage::Sealed {
            return Err(StoreError::InvalidState(tr!(
                "A direct connection can only end as blocked, cancelled or expired",
                "結束直連只能是封鎖、取消或逾期",
                "直接接続の終了はブロック、取消、期限切れのいずれかに限られます"
            )));
        }
        self.control
            .write(move |c| {
                let tx = c.transaction()?;
                let row = require(&tx, &id)?;
                if row.stage.is_active() {
                    let stage = if row.stage == BootstrapStage::Sealing {
                        latch(&tx)?;
                        BootstrapStage::Blocked
                    } else {
                        stage
                    };
                    end_row(&tx, &row, stage, &reason_code, &reason)?;
                }
                let out = require(&tx, &id)?;
                tx.commit()?;
                Ok(out)
            })
            .await
    }

    /// When the manager starts: every grant died with the previous process. A run that only held
    /// its grant ends expired; a run whose promotion deadline passed ends blocked; a run whose seal
    /// was interrupted after its intent is committed forward (latch and binding; never back to
    /// direct). Returns the runs changed.
    ///
    /// # Errors
    ///
    /// `Busy` when the write queue is full, `Closed` once the store has shut down, and `Sqlite` or
    /// `Encoding` when the transaction fails.
    pub async fn recover_bootstrap(&self) -> Result<Vec<BootstrapRow>, StoreError> {
        self.control
            .write(|c| {
                let tx = c.transaction()?;
                let now = Timestamp::now();
                let mut changed = Vec::new();
                let rows: Vec<BootstrapRow> = {
                    let mut stmt = tx.prepare(&format!(
                        "SELECT {COLUMNS} FROM bootstrap_journal
                          WHERE grant_id IS NOT NULL
                             OR stage IN ('grant_active', 'instance_requested', 'sealing')"
                    ))?;
                    let rows = stmt.query_map([], raw)?;
                    rows.map(|r| row_of(r?)).collect::<Result<_, _>>()?
                };
                for row in rows {
                    match row.stage {
                        BootstrapStage::GrantActive => end_row(
                            &tx,
                            &row,
                            BootstrapStage::Expired,
                            REASON_MANAGER_RESTARTED,
                            &tr!(
                "The core service (manager) restarted, so the direct-connection grant was revoked; open it again when you need it",
                "核心服務（manager）重新啟動，直連授權已撤銷；需要時請重新開啟",
                "コアサービス（manager）が再起動したため、直接接続の許可を取り消しました。必要なら開き直してください"
            ),
                        )?,
                        BootstrapStage::Sealing => {
                            commit_seal(&tx, &row, now)?;
                            tx.execute(
                                "UPDATE bootstrap_journal SET reason_code = ?2, reason = ?3
                                  WHERE id = ?1 AND stage = 'sealed'",
                                params![
                                    row.id,
                                    REASON_SEAL_RECOVERED,
                                    crate::text_column::to_column(&tr!(
                                        "Sealing finished when the core service (manager) restarted: the direct connection is closed and the new connection is the egress",
                                        "封存在核心服務（manager）重新啟動時完成：直連已關閉，新連線是出口",
                                        "封印はコアサービス（manager）の再起動時に完了しました。直接接続は閉じ、新しい接続が出口です"
                                    ))
                                ],
                            )?;
                        }
                        BootstrapStage::InstanceRequested
                            if row
                                .promote_deadline
                                .is_some_and(|d| d.unix_millis() < now.unix_millis()) =>
                        {
                            end_row(
                                &tx,
                                &row,
                                BootstrapStage::Blocked,
                                REASON_PROMOTE_TIMEOUT,
                                &tr!(
                "The new connection did not come up in time and was not made the egress",
                "新連線在時限內沒有連上，未設為出口",
                "新しい接続が期限内につながらなかったため出口にしませんでした"
            ),
                            )?;
                        }
                        _ => {
                            tx.execute(
                                "UPDATE bootstrap_journal
                                    SET grant_id = NULL, grant_expires_ms = NULL, updated_at = ?2
                                  WHERE id = ?1 AND grant_id IS NOT NULL",
                                params![row.id, now.to_string()],
                            )?;
                        }
                    }
                    changed.push(require(&tx, &row.id)?);
                }
                tx.commit()?;
                Ok(changed)
            })
            .await
    }
}
