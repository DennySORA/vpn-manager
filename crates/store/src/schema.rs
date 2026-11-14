//! Schemas and forward-only migrations. A database written by a newer binary is refused (no
//! silent downgrade); a migration runs in one transaction and verifies foreign keys before commit.

use rusqlite::Connection;

use crate::error::StoreError;

pub const CONTROL_VERSION: i64 = 14;
pub const METRICS_VERSION: i64 = 8;

const CONTROL_V1: &str = r"
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

-- Immutable revisions of every configuration entity.
CREATE TABLE entity_revisions (
    kind       TEXT    NOT NULL,
    id         TEXT    NOT NULL,
    revision   INTEGER NOT NULL CHECK (revision >= 1),
    body       TEXT    NOT NULL CHECK (json_valid(body)),
    created_at TEXT    NOT NULL,
    PRIMARY KEY (kind, id, revision)
) WITHOUT ROWID;

-- Current revision of each live entity.
CREATE TABLE entity_heads (
    kind       TEXT    NOT NULL,
    id         TEXT    NOT NULL,
    revision   INTEGER NOT NULL,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL,
    PRIMARY KEY (kind, id),
    FOREIGN KEY (kind, id, revision) REFERENCES entity_revisions (kind, id, revision)
) WITHOUT ROWID;

-- Durable user intent per Instance. Faults never write here.
CREATE TABLE instance_intents (
    instance_id       TEXT PRIMARY KEY,
    desired           TEXT    NOT NULL CHECK (desired IN ('running', 'stopped')),
    manual_stop       INTEGER NOT NULL DEFAULT 0 CHECK (manual_stop IN (0, 1)),
    emergency_latched INTEGER NOT NULL DEFAULT 0 CHECK (emergency_latched IN (0, 1)),
    intent_revision   INTEGER NOT NULL DEFAULT 1,
    next_generation   INTEGER NOT NULL DEFAULT 1,
    updated_at        TEXT    NOT NULL
) WITHOUT ROWID;

-- One live user of a WireGuard key at a time (fingerprint = sha256 of the public key).
CREATE TABLE identity_leases (
    key_fingerprint TEXT PRIMARY KEY,
    instance_id     TEXT    NOT NULL,
    generation      INTEGER NOT NULL,
    acquired_at     TEXT    NOT NULL
) WITHOUT ROWID;

CREATE TABLE operations (
    id                  TEXT PRIMARY KEY,
    kind                TEXT NOT NULL,
    target_id           TEXT,
    status              TEXT NOT NULL,
    idempotency_key     TEXT UNIQUE,
    request_fingerprint TEXT,
    error               TEXT,
    result_refs         TEXT NOT NULL DEFAULT '[]',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX operations_created ON operations (created_at);

CREATE TABLE secrets (
    id                 TEXT PRIMARY KEY,
    kind               TEXT    NOT NULL,
    label              TEXT,
    key_id             INTEGER NOT NULL,
    nonce              BLOB    NOT NULL CHECK (length(nonce) = 24),
    ciphertext         BLOB    NOT NULL,
    public_fingerprint TEXT,
    created_at         TEXT    NOT NULL
) WITHOUT ROWID;

CREATE TABLE settings (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL,
    body     TEXT    NOT NULL CHECK (json_valid(body))
);

-- Bounded audit/event log (public data only; pruned to the newest rows).
CREATE TABLE events (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    at        TEXT NOT NULL,
    kind      TEXT NOT NULL,
    entity_id TEXT,
    body      TEXT NOT NULL CHECK (json_valid(body))
);
";

/// v2: the global Provider egress binding, one row. The used-up direct bootstrap and the route
/// fence only move forward, whatever the code above does.
const CONTROL_V2: &str = r"
CREATE TABLE provider_egress (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    revision             INTEGER NOT NULL CHECK (revision >= 1),
    route_revision       INTEGER NOT NULL CHECK (route_revision >= 1),
    desired_mode         TEXT    NOT NULL CHECK (desired_mode IN ('via_instance', 'disabled')),
    bootstrap_consumed   INTEGER NOT NULL CHECK (bootstrap_consumed IN (0, 1)),
    selected_instance_id TEXT,
    updated_at           TEXT    NOT NULL
);
CREATE TRIGGER provider_egress_forward_only
BEFORE UPDATE ON provider_egress
WHEN NEW.bootstrap_consumed < OLD.bootstrap_consumed
  OR NEW.route_revision < OLD.route_revision
  OR NEW.revision < OLD.revision
BEGIN
    SELECT RAISE(ABORT, 'provider_egress only moves forward');
END;
CREATE TRIGGER provider_egress_kept
BEFORE DELETE ON provider_egress
BEGIN
    SELECT RAISE(ABORT, 'provider_egress is never deleted');
END;
INSERT INTO provider_egress
    (id, revision, route_revision, desired_mode, bootstrap_consumed, selected_instance_id, updated_at)
VALUES (1, 1, 1, 'via_instance', 0, NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
";

/// v3: imports from the previous VPN Manager (removed; v10 drops both tables). The step stays as
/// written so an older database still migrates one step at a time.
const CONTROL_V3: &str = r"
CREATE TABLE legacy_imports (
    id         TEXT PRIMARY KEY,
    revision   INTEGER NOT NULL CHECK (revision >= 1),
    status     TEXT    NOT NULL CHECK (status IN ('applied', 'partially_rolled_back', 'rolled_back')),
    plan_hash  TEXT    NOT NULL,
    body       TEXT    NOT NULL CHECK (json_valid(body)),
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
) WITHOUT ROWID;
CREATE TABLE legacy_import_items (
    source_fp   TEXT    PRIMARY KEY,
    import_id   TEXT    NOT NULL REFERENCES legacy_imports (id),
    item_key    TEXT    NOT NULL,
    target_kind TEXT    NOT NULL,
    target_id   TEXT    NOT NULL,
    created     INTEGER NOT NULL CHECK (created IN (0, 1)),
    secret_ids  TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(secret_ids))
) WITHOUT ROWID;
CREATE INDEX legacy_import_items_import ON legacy_import_items (import_id);
";

/// v4 (security): blocklist content, the refresh state of URL blocklists, and auto-bans. The
/// blocklist records themselves are revisioned entities (`entity_revisions`, kind `blocklist`).
const CONTROL_V4: &str = r"
-- Compiled ranges of a blocklist (canonical IpRangeSet encoding), keyed by list and the entity
-- revision that set them; only the newest is kept. A rowid table: a row can be megabytes.
CREATE TABLE blocklist_content (
    blocklist_id TEXT    NOT NULL,
    revision     INTEGER NOT NULL CHECK (revision >= 1),
    sha256       TEXT    NOT NULL CHECK (length(sha256) = 64),
    ranges       BLOB    NOT NULL CHECK (length(ranges) <= 16777232),
    created_at   TEXT    NOT NULL,
    PRIMARY KEY (blocklist_id, revision)
);

-- Latest refresh attempt of a URL blocklist: runtime state, not a configuration revision.
CREATE TABLE blocklist_refresh (
    blocklist_id TEXT PRIMARY KEY,
    attempted_at TEXT    NOT NULL,
    ok           INTEGER NOT NULL CHECK (ok IN (0, 1)),
    message      TEXT,
    succeeded_at TEXT,
    stale_since  TEXT
) WITHOUT ROWID;

-- Sources banned by an Instance's auto-ban engine; deleted when they expire or are lifted.
CREATE TABLE bans (
    id                        TEXT PRIMARY KEY,
    instance_id               TEXT    NOT NULL,
    source                    TEXT    NOT NULL,
    reason                    TEXT    NOT NULL,
    security_profile_id       TEXT,
    security_profile_revision INTEGER,
    policy_revision           INTEGER NOT NULL,
    generation                INTEGER NOT NULL,
    created_ms                INTEGER NOT NULL,
    expires_ms                INTEGER NOT NULL CHECK (expires_ms > created_ms),
    UNIQUE (instance_id, source)
) WITHOUT ROWID;
CREATE INDEX bans_expiry ON bans (expires_ms);
";

/// v5: managed Apps. The user's intent per App (faults never write it) and the run the manager
/// supervises — root pid with its start time, never the pid alone — so a manager that restarts
/// finds what it left running. One row per App, created with it and deleted with it.
const CONTROL_V5: &str = r"
CREATE TABLE app_intents (
    app_id           TEXT PRIMARY KEY,
    desired          TEXT    NOT NULL CHECK (desired IN ('running', 'stopped')),
    intent_revision  INTEGER NOT NULL DEFAULT 1 CHECK (intent_revision >= 1),
    run_id           TEXT,
    run_pid          INTEGER CHECK (run_pid IS NULL OR run_pid > 0),
    run_started_us   INTEGER,
    run_backend      TEXT,
    run_revision     INTEGER,
    run_gateway_port INTEGER CHECK (run_gateway_port IS NULL OR run_gateway_port BETWEEN 1 AND 65535),
    run_started_at   TEXT,
    updated_at       TEXT    NOT NULL,
    CHECK ((run_id IS NULL) = (run_pid IS NULL)),
    CHECK ((run_pid IS NULL) = (run_started_us IS NULL))
) WITHOUT ROWID;
";

/// v6: benchmark runs of the Performance Manager. The benchmarks are gone (v10 drops the table);
/// the step stays as written so an older database still migrates one step at a time.
const CONTROL_V6: &str = r"
CREATE TABLE performance_runs (
    id                TEXT PRIMARY KEY,
    revision          INTEGER NOT NULL CHECK (revision >= 1),
    operation_id      TEXT    NOT NULL,
    request           TEXT    NOT NULL CHECK (json_valid(request)),
    state             TEXT    NOT NULL CHECK (state IN ('queued', 'preparing', 'warming_up',
                          'running', 'finalizing', 'cancelling', 'completed', 'cancelled', 'failed',
                          'interrupted', 'blocked')),
    verdict           TEXT    NOT NULL CHECK (verdict IN ('pass', 'fail', 'inconclusive', 'not_evaluated')),
    reason_code       TEXT,
    reason_message    TEXT,
    created_at        TEXT    NOT NULL,
    started_at        TEXT,
    ended_at          TEXT,
    report_id         TEXT,
    report_sha256     TEXT,
    report_bytes      INTEGER,
    report_expires_at TEXT,
    report_state      TEXT    NOT NULL DEFAULT 'none'
                          CHECK (report_state IN ('none', 'pending', 'stored', 'expired')),
    manager_boot      TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL
) WITHOUT ROWID;
CREATE INDEX performance_runs_created ON performance_runs (created_at, id);
-- At most one run generates traffic at a time.
CREATE UNIQUE INDEX performance_runs_one_active ON performance_runs
    ((state IN ('preparing', 'warming_up', 'running', 'finalizing', 'cancelling')))
    WHERE state IN ('preparing', 'warming_up', 'running', 'finalizing', 'cancelling');
CREATE TRIGGER performance_runs_terminal
BEFORE UPDATE OF state ON performance_runs
WHEN OLD.state IN ('completed', 'cancelled', 'failed', 'interrupted', 'blocked')
 AND NEW.state <> OLD.state
BEGIN
    SELECT RAISE(ABORT, 'a finished run does not change state');
END;
CREATE TRIGGER performance_runs_report_immutable
BEFORE UPDATE ON performance_runs
WHEN OLD.report_sha256 IS NOT NULL
 AND (NEW.report_sha256 IS NOT OLD.report_sha256 OR NEW.report_id IS NOT OLD.report_id)
BEGIN
    SELECT RAISE(ABORT, 'a stored report is immutable');
END;
";

/// v7: port forwards. The bindings are revisioned entities (kind `forward_binding`); this is the
/// evidence that a forward was reached from outside: per binding and protocol, the latest
/// inbound arrival from a source outside the tunnel's own and private networks, valid while the
/// binding keeps the connection and tunnel port it was seen on. Deleted with the binding.
const CONTROL_V7: &str = r"
CREATE TABLE forward_evidence (
    binding_id  TEXT    NOT NULL,
    protocol    TEXT    NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    instance_id TEXT    NOT NULL,
    tunnel_port INTEGER NOT NULL CHECK (tunnel_port BETWEEN 1 AND 65535),
    observed_ms INTEGER NOT NULL,
    PRIMARY KEY (binding_id, protocol)
) WITHOUT ROWID;
";

const METRICS_V1: &str = r"
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

-- Compressed snapshot chunks (CBOR, optionally zstd); never contain destinations or names.
CREATE TABLE metric_chunks (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scope             TEXT    NOT NULL,
    entity_id         TEXT,
    generation        INTEGER,
    start_ms          INTEGER NOT NULL,
    end_ms            INTEGER NOT NULL,
    sample_count      INTEGER NOT NULL,
    codec             TEXT    NOT NULL,
    uncompressed_size INTEGER NOT NULL,
    sha256            TEXT    NOT NULL,
    payload           BLOB    NOT NULL
);
CREATE INDEX metric_chunks_scope ON metric_chunks (scope, entity_id, start_ms);

-- Pre-aggregated series (minute/hour) for fast charts.
CREATE TABLE metric_rollups (
    scope      TEXT    NOT NULL,
    entity_id  TEXT    NOT NULL,
    metric     TEXT    NOT NULL,
    resolution INTEGER NOT NULL,
    bucket_ms  INTEGER NOT NULL,
    value      REAL,
    min        REAL,
    max        REAL,
    covered_ms INTEGER NOT NULL,
    PRIMARY KEY (scope, entity_id, metric, resolution, bucket_ms)
) WITHOUT ROWID;

CREATE TABLE metric_gaps (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scope     TEXT    NOT NULL,
    entity_id TEXT,
    start_ms  INTEGER NOT NULL,
    end_ms    INTEGER NOT NULL,
    reason    TEXT    NOT NULL
);

CREATE TABLE performance_reports (
    run_id     TEXT PRIMARY KEY,
    digest     TEXT NOT NULL,
    body       TEXT NOT NULL CHECK (json_valid(body)),
    created_at TEXT NOT NULL
) WITHOUT ROWID;
";

fn user_version(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
}

/// One migration step: SQL, or code for what SQL alone cannot write (entities with their JSON
/// bodies, a decision per row). Either runs inside the step's transaction.
#[derive(Clone, Copy)]
pub enum Step {
    Sql(&'static str),
    Code(fn(&rusqlite::Transaction<'_>) -> Result<(), StoreError>),
}

fn migrate(
    conn: &mut Connection,
    target: i64,
    steps: &[(i64, &'static str)],
) -> Result<(), StoreError> {
    let steps: Vec<(i64, Step)> = steps.iter().map(|&(v, sql)| (v, Step::Sql(sql))).collect();
    migrate_steps(conn, target, &steps)
}

fn migrate_steps(
    conn: &mut Connection,
    target: i64,
    steps: &[(i64, Step)],
) -> Result<(), StoreError> {
    let current = user_version(conn)?;
    if current > target {
        return Err(StoreError::SchemaTooNew {
            found: current,
            supported: target,
        });
    }
    for (version, step) in steps {
        if *version <= current {
            continue;
        }
        let tx = conn.transaction()?;
        match step {
            Step::Sql(sql) => tx.execute_batch(sql)?,
            Step::Code(run) => run(&tx)?,
        }
        let violations: i64 =
            tx.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })?;
        if violations != 0 {
            return Err(StoreError::Corrupt(format!(
                "migration to v{version} left {violations} foreign key violations"
            )));
        }
        tx.pragma_update(None, "user_version", version)?;
        tx.commit()?;
    }
    Ok(())
}

/// v10: the active benchmarks, the legacy data import and Store backup/restore were removed, and
/// their records go with them: the benchmark runs, the registered test peers (revisioned
/// entities of kind `performance_target`, which nothing refers to), the import reports with
/// their item mappings, and the App intents only a restore could leave (no App, no run). The
/// entities and secrets an import created are ordinary data and stay.
const CONTROL_V10: &str = r"
DROP TABLE IF EXISTS performance_runs;
DELETE FROM entity_heads WHERE kind = 'performance_target';
DELETE FROM entity_revisions WHERE kind = 'performance_target';
DROP TABLE IF EXISTS legacy_import_items;
DROP TABLE IF EXISTS legacy_imports;
DELETE FROM app_intents
 WHERE run_id IS NULL AND app_id NOT IN (SELECT id FROM entity_heads WHERE kind = 'app');
";

/// v8: the boot an App run was started in. Its root's start time is counted from that boot on
/// Linux (clock ticks, which no clock step moves), so a run of another boot is known gone
/// without looking for its pid. NULL: written before v8 (or the boot was unknown).
const CONTROL_V8: &str = "ALTER TABLE app_intents ADD COLUMN run_boot_id TEXT;";

/// v12: port forwards can start each TCP connection with a PROXY protocol v2 header
/// (`proxy_protocol` of a `forward_binding`). Every revision saved before it says so explicitly:
/// off, which is what it did. Nothing else in a body changes and no revision is added; a body
/// that already names it keeps its value. The step itself is what keeps an older build away:
/// it refuses this database instead of reading the option it does not know and relaying such a
/// forward without the header.
const CONTROL_V12: &str = r"
UPDATE entity_revisions
   SET body = json_set(body, '$.proxy_protocol', json('false'))
 WHERE kind = 'forward_binding'
   AND json_type(body, '$.proxy_protocol') IS NULL;
";

/// v14: a port forward's UDP can go straight into a strict sandbox (`udp_direct` of a
/// `forward_binding`). Every revision saved before it says so explicitly: relayed, which is what
/// it did. Nothing else in a body changes and no revision is added; a body that already names it
/// keeps its value. As with v12, the step is what keeps an older build away: it refuses this
/// database instead of relaying (or holding the port of) a forward whose UDP the user sent
/// straight to the App.
const CONTROL_V14: &str = r"
UPDATE entity_revisions
   SET body = json_set(body, '$.udp_direct', json('false'))
 WHERE kind = 'forward_binding'
   AND json_type(body, '$.udp_direct') IS NULL;
";

const CONTROL_STEPS: [(i64, Step); 14] = [
    (1, Step::Sql(CONTROL_V1)),
    (2, Step::Sql(CONTROL_V2)),
    (3, Step::Sql(CONTROL_V3)),
    (4, Step::Sql(CONTROL_V4)),
    (5, Step::Sql(CONTROL_V5)),
    // Performance Manager: benchmark runs (dropped in v10).
    (6, Step::Sql(CONTROL_V6)),
    // Port forwards: reachability evidence.
    (7, Step::Sql(CONTROL_V7)),
    // App runs: their boot.
    (8, Step::Sql(CONTROL_V8)),
    // Provider egress: the runs of the direct exception.
    (9, Step::Sql(crate::bootstrap::CONTROL_STEP)),
    // The benchmark runs and test peers, and the legacy import records, removed.
    (10, Step::Sql(CONTROL_V10)),
    // Security defaults: the built-in blocklists, and auto-ban on.
    (11, Step::Code(crate::security::defaults_step)),
    // Port forwards: the PROXY protocol option, off for the ones saved before it.
    (12, Step::Sql(CONTROL_V12)),
    // SSH download: job state, file records and log.
    (13, Step::Sql(crate::ssh_download::CONTROL_STEP)),
    // Port forwards: UDP straight into the sandbox, off for the ones saved before it.
    (14, Step::Sql(CONTROL_V14)),
];

pub fn migrate_control(conn: &mut Connection) -> Result<(), StoreError> {
    migrate_steps(conn, CONTROL_VERSION, &CONTROL_STEPS)?;
    // Built-in lists a later release adds to the catalogue are created on the next start (a list
    // the user deleted never is).
    crate::security::ensure_builtin_blocklists(conn)
}

/// A control database as an earlier release left it (migration tests).
#[cfg(test)]
pub fn migrate_control_to(conn: &mut Connection, version: i64) -> Result<(), StoreError> {
    let steps = usize::try_from(version)
        .map_err(|_| StoreError::InvalidState("negative schema version".into()))?;
    migrate_steps(conn, version, &CONTROL_STEPS[..steps])
}

/// v6: the benchmark reports and measurement points, and the process samples of the benchmark
/// tools (runner, peer), removed with the benchmarks. The passive process samples stay.
const METRICS_V6: &str = r"
DROP TABLE IF EXISTS performance_reports;
DROP TABLE IF EXISTS benchmark_measurements;
DELETE FROM resource_samples
 WHERE series IN (SELECT id FROM resource_series WHERE role IN ('runner', 'peer'));
DELETE FROM resource_series WHERE role IN ('runner', 'peer');
DELETE FROM resource_buckets WHERE role IN ('runner', 'peer');
";

/// Metrics steps: v1 chunks (unused), v2 samples and rollups, v3 latency, connect outcomes, the
/// gate and per-Gateway tables, v4 process resource samples (Performance Manager), v5 the failed
/// connects whose name had no address, v6 the benchmark data removed, v7 the payload of a strict
/// sandbox's Apps, v8 the SSH sessions' and SSH downloads' part of the payload.
const METRICS_STEPS: [(i64, &str); 8] = [
    (1, METRICS_V1),
    (2, crate::metrics::METRICS_V2),
    (3, crate::metrics::METRICS_V3),
    (4, crate::resources::METRICS_STEP),
    (5, crate::metrics::METRICS_V5),
    (6, METRICS_V6),
    (7, crate::metrics::METRICS_V7),
    (8, crate::metrics::METRICS_V8),
];

pub fn migrate_metrics(conn: &mut Connection) -> Result<(), StoreError> {
    migrate(conn, METRICS_VERSION, &METRICS_STEPS)
}

/// A metrics database as an earlier release left it (migration tests).
#[cfg(test)]
pub fn migrate_metrics_to(conn: &mut Connection, version: i64) -> Result<(), StoreError> {
    let steps = usize::try_from(version)
        .map_err(|_| StoreError::InvalidState("negative schema version".into()))?;
    migrate(conn, version, &METRICS_STEPS[..steps])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tables(c: &Connection) -> Vec<String> {
        let mut st = c
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        st.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn count(c: &Connection, sql: &str) -> i64 {
        c.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn a_v2_database_migrates_to_the_current_version() {
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrate(&mut c, 2, &[(1, CONTROL_V1), (2, CONTROL_V2)]).unwrap();
        migrate_control(&mut c).unwrap();
        assert_eq!(user_version(&c).unwrap(), CONTROL_VERSION);
        let t = tables(&c);
        for gone in ["legacy_imports", "legacy_import_items", "performance_runs"] {
            assert!(!t.contains(&gone.to_string()), "{gone}: {t:?}");
        }
        for kept in ["provider_egress", "bans", "app_intents", "forward_evidence"] {
            assert!(t.contains(&kept.to_string()), "{kept}: {t:?}");
        }
    }

    /// A manual eD2k-style forward on port 24680 at `revision`, `udp_direct` off.
    fn test_forward(
        revision: u64,
        name: &str,
        protocol: vpn_domain::ForwardProtocol,
        proxy_protocol: bool,
    ) -> vpn_domain::ForwardBinding {
        use vpn_domain::{
            AppId, AssignmentSource, EntityMeta, ForwardBinding, ForwardBindingId, InstanceId,
            Timestamp,
        };
        ForwardBinding {
            id: ForwardBindingId::new(),
            meta: EntityMeta {
                revision,
                created_at: Timestamp::now(),
                updated_at: Timestamp::now(),
            },
            instance_id: InstanceId::new(),
            name: name.into(),
            protocol,
            tunnel_port: 24680,
            public_port: Some(24680),
            assignment_source: AssignmentSource::Manual,
            target_app_id: AppId::new(),
            target_port: 24680,
            enabled: true,
            max_connections: 256,
            proxy_protocol,
            udp_direct: false,
        }
    }

    /// Write one entity revision as an older release did.
    fn put_revision(c: &Connection, kind: &str, id: &str, revision: u64, body: &serde_json::Value) {
        c.execute(
            "INSERT INTO entity_revisions (kind, id, revision, body, created_at)
                 VALUES (?1, ?2, ?3, ?4, 't')",
            rusqlite::params![kind, id, revision.cast_signed(), body.to_string()],
        )
        .unwrap();
    }

    /// Point an entity's head at `revision`.
    fn put_head(c: &Connection, kind: &str, id: &str, revision: u64) {
        c.execute(
            "INSERT INTO entity_heads (kind, id, revision, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 't', 't')",
            rusqlite::params![kind, id, revision.cast_signed()],
        )
        .unwrap();
    }

    /// Every stored revision: `(id, revision, body)`, ordered by kind, id and revision.
    fn revision_bodies(c: &Connection) -> Vec<(String, i64, serde_json::Value)> {
        let mut st = c
            .prepare("SELECT id, revision, body FROM entity_revisions ORDER BY kind, id, revision")
            .unwrap();
        st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .map(|row| {
            let (id, revision, body) = row.unwrap();
            (id, revision, serde_json::from_str(&body).unwrap())
        })
        .collect()
    }

    /// The stored body of revision `revision` of entity `id`.
    fn revision_body(c: &Connection, id: &str, revision: i64) -> serde_json::Value {
        let text: String = c
            .query_row(
                "SELECT body FROM entity_revisions WHERE id = ?1 AND revision = ?2",
                rusqlite::params![id, revision],
                |r| r.get(0),
            )
            .unwrap();
        serde_json::from_str(&text).unwrap()
    }

    /// A v9 control database holding benchmark runs, a test peer, an applied legacy import and
    /// App intents (one of them a restore's residue).
    fn v9_database() -> Connection {
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrate(
            &mut c,
            9,
            &[
                (1, CONTROL_V1),
                (2, CONTROL_V2),
                (3, CONTROL_V3),
                (4, CONTROL_V4),
                (5, CONTROL_V5),
                (6, CONTROL_V6),
                (7, CONTROL_V7),
                (8, CONTROL_V8),
                (9, crate::bootstrap::CONTROL_STEP),
            ],
        )
        .unwrap();
        // A finished run with a stored report and one that was running when the manager stopped.
        let run = "INSERT INTO performance_runs
                (id, revision, operation_id, request, state, verdict, created_at, report_id,
                 report_sha256, report_state, manager_boot, updated_at)
             VALUES (?1, 1, 'op', '{}', ?2, ?3, 't', ?4, ?5, ?6, 'boot', 't')";
        c.execute(
            run,
            rusqlite::params!["r1", "completed", "pass", "rep", "ab", "stored"],
        )
        .unwrap();
        c.execute(
            run,
            rusqlite::params![
                "r2",
                "running",
                "not_evaluated",
                None::<String>,
                None::<String>,
                "none"
            ],
        )
        .unwrap();
        // A registered test peer, a connection and an App, all revisioned entities.
        for (kind, id) in [
            ("performance_target", "peer"),
            ("instance", "inst"),
            ("app", "kept-app"),
        ] {
            c.execute(
                "INSERT INTO entity_revisions (kind, id, revision, body, created_at)
                 VALUES (?1, ?2, 1, '{}', 't')",
                [kind, id],
            )
            .unwrap();
            c.execute(
                "INSERT INTO entity_heads (kind, id, revision, created_at, updated_at)
                 VALUES (?1, ?2, 1, 't', 't')",
                [kind, id],
            )
            .unwrap();
        }
        // An applied import and the mapping of the connection it created.
        c.execute(
            "INSERT INTO legacy_imports (id, revision, status, plan_hash, body, created_at, updated_at)
             VALUES ('imp', 1, 'applied', 'h', '{}', 't', 't')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO legacy_import_items (source_fp, import_id, item_key, target_kind, target_id, created)
             VALUES ('fp', 'imp', 'k', 'instance', 'inst', 1)",
            [],
        )
        .unwrap();
        // App intents: of an existing App; one a restore left for an App the restored data never
        // had (no run any more); and one whose run is still supervised.
        let intent =
            "INSERT INTO app_intents (app_id, desired, updated_at) VALUES (?1, 'stopped', 't')";
        for id in ["kept-app", "restore-residue", "still-running"] {
            c.execute(intent, [id]).unwrap();
        }
        c.execute(
            "UPDATE app_intents SET run_id = 'run', run_pid = 42, run_started_us = 1
              WHERE app_id = 'still-running'",
            [],
        )
        .unwrap();
        c
    }

    /// A database the previous release wrote (v9), with benchmark runs, registered test peers
    /// and legacy imports: v10 removes exactly those and keeps everything else.
    #[test]
    fn a_v9_database_loses_its_benchmark_runs_test_peers_and_import_records() {
        let mut c = v9_database();
        migrate_control(&mut c).unwrap();
        assert_eq!(user_version(&c).unwrap(), CONTROL_VERSION);
        let t = tables(&c);
        for gone in ["performance_runs", "legacy_imports", "legacy_import_items"] {
            assert!(!t.contains(&gone.to_string()), "{gone}: {t:?}");
        }
        let indexes = count(
            &c,
            "SELECT count(*) FROM sqlite_master
              WHERE name LIKE 'performance_runs%' OR name LIKE 'legacy_import%'",
        );
        assert_eq!(indexes, 0, "their indexes and triggers went with them");
        assert_eq!(
            count(
                &c,
                "SELECT count(*) FROM entity_revisions WHERE kind = 'performance_target'"
            ),
            0
        );
        assert_eq!(
            count(
                &c,
                "SELECT count(*) FROM entity_heads WHERE kind = 'performance_target'"
            ),
            0
        );
        // The connection the import created is ordinary data and stays.
        assert_eq!(
            count(
                &c,
                "SELECT count(*) FROM entity_heads WHERE kind = 'instance' AND id = 'inst'"
            ),
            1
        );
        // Only the residue goes: an App's intent stays, and so does one with a run to end.
        let mut st = c
            .prepare("SELECT app_id FROM app_intents ORDER BY app_id")
            .unwrap();
        let intents: Vec<String> = st
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        drop(st);
        assert_eq!(intents, ["kept-app", "still-running"]);
        assert_eq!(
            count(&c, "SELECT count(*) FROM pragma_foreign_key_check"),
            0
        );
        // Running the migration again changes nothing.
        migrate_control(&mut c).unwrap();
        assert_eq!(user_version(&c).unwrap(), CONTROL_VERSION);
    }

    /// A metrics database the previous release wrote (v5), with a benchmark report, measurement
    /// points and samples of the benchmark tools: v6 removes those, the product's samples stay.
    #[test]
    fn a_v5_metrics_database_loses_the_benchmark_data_and_keeps_the_process_samples() {
        let mut c = Connection::open_in_memory().unwrap();
        migrate_metrics_to(&mut c, 5).unwrap();
        c.execute(
            "INSERT INTO performance_reports (run_id, digest, body, created_at)
             VALUES ('r1', 'ab', '{}', 't')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO benchmark_measurements (run_id, at_ms, body) VALUES ('r1', 1, '{}')",
            [],
        )
        .unwrap();
        for (id, role) in [(1, "manager"), (2, "worker"), (3, "runner"), (4, "peer")] {
            c.execute(
                "INSERT INTO resource_series
                    (id, role, process_identity, counter_epoch, local)
                 VALUES (?1, ?2, ?3, 'e', 1)",
                rusqlite::params![id, role, format!("pid:{id}/start:1")],
            )
            .unwrap();
            c.execute(
                "INSERT INTO resource_samples (series, at_ms, mono_ms, cpu_ns, rss_bytes)
                 VALUES (?1, 1000, 1000, 1, 1)",
                [id],
            )
            .unwrap();
            c.execute(
                "INSERT INTO resource_buckets
                    (role, bucket_ms, ticks, processes, cpu_ns, cpu_ms, rss_sum, rss_ms)
                 VALUES (?1, 0, 1, 1, 1, 1, 1.0, 1)",
                [role],
            )
            .unwrap();
        }

        migrate_metrics(&mut c).unwrap();
        assert_eq!(user_version(&c).unwrap(), METRICS_VERSION);
        let t = tables(&c);
        for gone in ["performance_reports", "benchmark_measurements"] {
            assert!(!t.contains(&gone.to_string()), "{gone}: {t:?}");
        }
        let roles = |sql: &str| -> String {
            c.query_row(sql, [], |r| r.get::<_, Option<String>>(0))
                .unwrap()
                .unwrap_or_default()
        };
        assert_eq!(
            roles(
                "SELECT group_concat(role, ',') FROM (SELECT role FROM resource_series ORDER BY id)"
            ),
            "manager,worker"
        );
        assert_eq!(
            roles(
                "SELECT group_concat(role, ',') FROM (SELECT role FROM resource_buckets ORDER BY role)"
            ),
            "manager,worker"
        );
        assert_eq!(
            count(&c, "SELECT count(*) FROM resource_samples"),
            2,
            "the product's samples stay"
        );
        assert_eq!(
            count(&c, "SELECT count(*) FROM resource_samples WHERE series > 2"),
            0
        );
    }

    #[test]
    fn a_v3_database_gains_the_security_tables() {
        let mut c = Connection::open_in_memory().unwrap();
        migrate(
            &mut c,
            3,
            &[(1, CONTROL_V1), (2, CONTROL_V2), (3, CONTROL_V3)],
        )
        .unwrap();
        c.execute(
            "INSERT INTO meta (key, value) VALUES ('installation_id', 'x')",
            [],
        )
        .unwrap();
        migrate_control(&mut c).unwrap();
        assert_eq!(user_version(&c).unwrap(), CONTROL_VERSION);
        for table in ["blocklist_content", "blocklist_refresh", "bans"] {
            let n: i64 = c
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "{table}");
        }
        // Existing data is untouched.
        let id: String = c
            .query_row(
                "SELECT value FROM meta WHERE key = 'installation_id'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(id, "x");
        // A ban always expires after it was made; one source is banned once per Instance.
        let insert = "INSERT INTO bans (id, instance_id, source, reason, policy_revision, generation, created_ms, expires_ms)
                      VALUES (?1, 'i', '203.0.113.9', 'r', 1, 1, ?2, ?3)";
        assert!(c.execute(insert, rusqlite::params!["a", 10, 5]).is_err());
        c.execute(insert, rusqlite::params!["a", 10, 20]).unwrap();
        assert!(c.execute(insert, rusqlite::params!["b", 10, 20]).is_err());
        // Content rows are bounded and need a real digest length.
        assert!(
            c.execute(
                "INSERT INTO blocklist_content (blocklist_id, revision, sha256, ranges, created_at) VALUES ('l', 1, 'short', x'00', 't')",
                []
            )
            .is_err()
        );
    }

    #[test]
    fn a_v6_database_gains_the_forward_evidence_table() {
        let mut c = Connection::open_in_memory().unwrap();
        migrate(
            &mut c,
            6,
            &[
                (1, CONTROL_V1),
                (2, CONTROL_V2),
                (3, CONTROL_V3),
                (4, CONTROL_V4),
                (5, CONTROL_V5),
                (6, CONTROL_V6),
            ],
        )
        .unwrap();
        migrate_control(&mut c).unwrap();
        assert_eq!(user_version(&c).unwrap(), CONTROL_VERSION);
        let insert = "INSERT INTO forward_evidence (binding_id, protocol, instance_id, tunnel_port, observed_ms)
                      VALUES ('f', ?1, 'i', ?2, 1)";
        c.execute(insert, rusqlite::params!["tcp", 51234]).unwrap();
        c.execute(insert, rusqlite::params!["udp", 51234]).unwrap();
        // One row per binding and protocol; only TCP/UDP; only real ports.
        assert!(c.execute(insert, rusqlite::params!["tcp", 51234]).is_err());
        assert!(c.execute(insert, rusqlite::params!["sctp", 1]).is_err());
        c.execute("DELETE FROM forward_evidence", []).unwrap();
        assert!(c.execute(insert, rusqlite::params!["tcp", 0]).is_err());
        assert!(c.execute(insert, rusqlite::params!["tcp", 65536]).is_err());
    }

    #[test]
    fn a_v8_database_gains_the_bootstrap_journal_and_keeps_its_latch() {
        let mut c = Connection::open_in_memory().unwrap();
        migrate(
            &mut c,
            8,
            &[
                (1, CONTROL_V1),
                (2, CONTROL_V2),
                (3, CONTROL_V3),
                (4, CONTROL_V4),
                (5, CONTROL_V5),
                (6, CONTROL_V6),
                (7, CONTROL_V7),
                (8, CONTROL_V8),
            ],
        )
        .unwrap();
        // An installation that used its first-setup bootstrap before v9.
        c.execute("UPDATE provider_egress SET bootstrap_consumed = 1", [])
            .unwrap();
        migrate_control(&mut c).unwrap();
        assert_eq!(user_version(&c).unwrap(), CONTROL_VERSION);
        let rows: i64 = c
            .query_row("SELECT count(*) FROM bootstrap_journal", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0);
        // The latch it set before v9 keeps the first setup from ever getting a grant.
        let insert = "INSERT INTO bootstrap_journal
                (id, kind, initial_bootstrap_key, stage, grant_id, grant_expires_ms, created_at, updated_at)
             VALUES ('a', 'initial', ?1, 'grant_active', 'g', 1, 't', 't')";
        assert!(c.execute(insert, ["ab".repeat(32)]).is_err());
    }

    #[test]
    fn a_v1_database_gains_the_egress_row_and_its_latch_holds() {
        let mut c = Connection::open_in_memory().unwrap();
        migrate(&mut c, 1, &[(1, CONTROL_V1)]).unwrap();
        assert_eq!(user_version(&c).unwrap(), 1);
        migrate_control(&mut c).unwrap();
        assert_eq!(user_version(&c).unwrap(), CONTROL_VERSION);
        let consumed: i64 = c
            .query_row("SELECT bootstrap_consumed FROM provider_egress", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(consumed, 0);
        c.execute("UPDATE provider_egress SET bootstrap_consumed = 1", [])
            .unwrap();
        assert!(
            c.execute("UPDATE provider_egress SET bootstrap_consumed = 0", [])
                .is_err()
        );
        assert!(
            c.execute("UPDATE provider_egress SET route_revision = 0", [])
                .is_err()
        );
        assert!(c.execute("DELETE FROM provider_egress", []).is_err());
        assert!(
            c.execute(
                "INSERT INTO provider_egress (id, revision, route_revision, desired_mode, bootstrap_consumed, updated_at) VALUES (2, 1, 1, 'disabled', 0, 'x')",
                []
            )
            .is_err()
        );
    }

    /// A database the previous release wrote (v11), with a forward saved twice and another
    /// kind of entity: v12 writes the PROXY protocol option, off, into every forward revision and
    /// touches nothing else.
    #[test]
    fn a_v11_database_says_its_forwards_send_no_proxy_header() {
        use vpn_domain::{EntityMeta, ForwardBinding, ForwardProtocol};
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrate_control_to(&mut c, 11).unwrap();
        let forward =
            |revision: u64, name: &str| test_forward(revision, name, ForwardProtocol::Both, false);
        // As v11 wrote them: no `proxy_protocol` at all (nor the later `udp_direct`).
        let older = |f: &ForwardBinding| {
            let mut v = serde_json::to_value(f).unwrap();
            v.as_object_mut().unwrap().remove("proxy_protocol");
            v.as_object_mut().unwrap().remove("udp_direct");
            v
        };
        let put = |kind: &str, id: &str, revision: u64, body: &serde_json::Value| {
            put_revision(&c, kind, id, revision, body);
        };
        let head = |kind: &str, id: &str, revision: u64| put_head(&c, kind, id, revision);
        let first = forward(1, "eD2k 24680");
        let second = ForwardBinding {
            meta: EntityMeta {
                revision: 2,
                ..first.meta.clone()
            },
            name: "eD2k".into(),
            ..first
        };
        let id = first.id.to_string();
        put("forward_binding", &id, 1, &older(&first));
        put("forward_binding", &id, 2, &older(&second));
        head("forward_binding", &id, 2);
        // A body that already names the option (a later build's) keeps its value.
        let named = ForwardBinding {
            proxy_protocol: true,
            ..forward(1, "BT")
        };
        let named_body = serde_json::to_value(&named).unwrap();
        put("forward_binding", &named.id.to_string(), 1, &named_body);
        head("forward_binding", &named.id.to_string(), 1);
        let other = serde_json::json!({ "id": "g", "name": "socks" });
        put("gateway", "g", 1, &other);
        head("gateway", "g", 1);
        let bodies = revision_bodies;

        migrate_control(&mut c).unwrap();
        assert_eq!(user_version(&c).unwrap(), CONTROL_VERSION);
        let after = bodies(&c);
        let body_of = |id: &str, revision: i64| {
            after
                .iter()
                .find(|(i, r, _)| i == id && *r == revision)
                .map(|(_, _, b)| b.clone())
                .unwrap()
        };
        // Every revision of the old forward: explicitly off (and, from v14, relayed), and
        // otherwise exactly as it was.
        for (revision, was) in [(1, &first), (2, &second)] {
            let mut body = body_of(&id, revision);
            assert_eq!(body["proxy_protocol"], serde_json::Value::Bool(false));
            assert_eq!(body["udp_direct"], serde_json::Value::Bool(false));
            body.as_object_mut().unwrap().remove("proxy_protocol");
            body.as_object_mut().unwrap().remove("udp_direct");
            assert_eq!(body, older(was), "revision {revision}");
        }
        assert_eq!(body_of(&named.id.to_string(), 1), named_body);
        assert_eq!(body_of("g", 1), other, "other kinds are not touched");
        // No revision was added; the head still names the second one, and it reads back as off.
        let read: ForwardBinding = crate::entities::get(&c, &id).unwrap().unwrap();
        assert_eq!(read.meta.revision, 2);
        assert_eq!(read.name, "eD2k");
        assert!(!read.proxy_protocol);
        let read: ForwardBinding = crate::entities::get(&c, &named.id.to_string())
            .unwrap()
            .unwrap();
        assert!(read.proxy_protocol);
        // Running the migration again changes nothing.
        migrate_control(&mut c).unwrap();
        assert_eq!(bodies(&c), after);
    }

    /// A database the previous release wrote (v12), with its entities: v13 adds the SSH download
    /// tables and leaves everything else as it was; a finished record must say it is finished.
    #[test]
    fn a_v12_database_gains_the_ssh_download_tables() {
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrate_control_to(&mut c, 12).unwrap();
        let before = count(&c, "SELECT count(*) FROM entity_heads");
        migrate_control(&mut c).unwrap();
        assert_eq!(user_version(&c).unwrap(), CONTROL_VERSION);
        let t = tables(&c);
        for added in [
            "ssh_download_state",
            "ssh_download_transfers",
            "ssh_download_log",
        ] {
            assert!(t.contains(&added.to_string()), "{added}: {t:?}");
        }
        assert_eq!(count(&c, "SELECT count(*) FROM entity_heads"), before);
        let insert = |state: &str, finished: Option<i64>| {
            c.execute(
                "INSERT INTO ssh_download_transfers (id, job_id, name, state, source_path, work_path,
                    local_dir, created_ms, finished_ms, updated_ms)
                 VALUES (?1, 'j', 'n', ?2, 's', 'w', 'l', 1, ?3, 1)",
                rusqlite::params![format!("{state}-{finished:?}"), state, finished],
            )
        };
        assert!(insert("downloading", None).is_ok());
        assert!(insert("completed", Some(5)).is_ok());
        assert!(
            insert("completed", None).is_err(),
            "finished without a time"
        );
        assert!(
            insert("downloading", Some(5)).is_err(),
            "a time without being finished"
        );
        assert!(insert("lost", None).is_err(), "an unknown state");
        migrate_control(&mut c).unwrap();
        assert_eq!(user_version(&c).unwrap(), CONTROL_VERSION);
    }

    /// A database the previous release wrote (v13), with a forward saved twice, one a later build
    /// saved with the option on, and another kind of entity: v14 writes `udp_direct: false` into
    /// every forward revision without it and touches nothing else.
    #[test]
    fn a_v13_database_says_its_forwards_relay_their_udp() {
        use vpn_domain::{EntityMeta, ForwardBinding, ForwardProtocol};
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        migrate_control_to(&mut c, 13).unwrap();
        let forward = |revision: u64, name: &str, protocol: ForwardProtocol| {
            test_forward(revision, name, protocol, true)
        };
        // As v13 wrote them: `proxy_protocol` (step 12) but no `udp_direct`.
        let older = |f: &ForwardBinding| {
            let mut v = serde_json::to_value(f).unwrap();
            v.as_object_mut().unwrap().remove("udp_direct");
            v
        };
        let put = |kind: &str, id: &str, revision: u64, body: &serde_json::Value| {
            c.execute(
                "INSERT INTO entity_revisions (kind, id, revision, body, created_at)
                 VALUES (?1, ?2, ?3, ?4, 't')",
                rusqlite::params![kind, id, revision.cast_signed(), body.to_string()],
            )
            .unwrap();
            c.execute(
                "INSERT INTO entity_heads (kind, id, revision, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 't', 't')
                 ON CONFLICT (kind, id) DO UPDATE SET revision = excluded.revision",
                rusqlite::params![kind, id, revision.cast_signed()],
            )
            .unwrap();
        };
        let first = forward(1, "eD2k 24680（TCP）", ForwardProtocol::Tcp);
        let second = ForwardBinding {
            meta: EntityMeta {
                revision: 2,
                ..first.meta.clone()
            },
            protocol: ForwardProtocol::Both,
            ..first.clone()
        };
        let id = first.id.to_string();
        put("forward_binding", &id, 1, &older(&first));
        put("forward_binding", &id, 2, &older(&second));
        let named = ForwardBinding {
            udp_direct: true,
            ..forward(1, "Kad", ForwardProtocol::Udp)
        };
        let named_body = serde_json::to_value(&named).unwrap();
        put("forward_binding", &named.id.to_string(), 1, &named_body);
        let other = serde_json::json!({ "id": "g", "name": "socks", "udp": true });
        put("gateway", "g", 1, &other);
        let body = revision_body;
        let revisions = |c: &Connection| -> i64 {
            c.query_row("SELECT count(*) FROM entity_revisions", [], |r| r.get(0))
                .unwrap()
        };
        let before = revisions(&c);

        migrate_control(&mut c).unwrap();
        assert_eq!(user_version(&c).unwrap(), CONTROL_VERSION);
        assert_eq!(CONTROL_VERSION, 14);
        for (revision, was) in [(1, &first), (2, &second)] {
            let mut b = body(&c, &id, revision);
            assert_eq!(b["udp_direct"], serde_json::Value::Bool(false));
            b.as_object_mut().unwrap().remove("udp_direct");
            assert_eq!(b, older(was), "revision {revision}");
        }
        assert_eq!(body(&c, &named.id.to_string(), 1), named_body, "kept");
        assert_eq!(body(&c, "g", 1), other, "other kinds are not touched");
        assert_eq!(revisions(&c), before, "no revision added");
        let read: ForwardBinding = crate::entities::get(&c, &id).unwrap().unwrap();
        assert_eq!(read.meta.revision, 2);
        assert!(!read.udp_direct && read.proxy_protocol);
        let read: ForwardBinding = crate::entities::get(&c, &named.id.to_string())
            .unwrap()
            .unwrap();
        assert!(read.udp_direct);
        // Running the migration again changes nothing.
        migrate_control(&mut c).unwrap();
        assert_eq!(
            body(&c, &id, 1)["udp_direct"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(revisions(&c), before);
    }
}
