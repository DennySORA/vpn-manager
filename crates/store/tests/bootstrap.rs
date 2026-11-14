//! The runs of the Provider egress's direct exception (`bootstrap_journal`): one permanent
//! first-setup row with a derived key, at most one active run, a latch that only moves forward,
//! one connection per run created with a running intent, and a seal intent that is never
//! withdrawn — held by the schema itself against racing writers and across reopening.

// Test fixtures: a failed setup step should panic right there.
#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap/expect in #[test] fns, not in the helper fns of a tests/ crate"
)]

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Barrier;
use std::time::Duration;

use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::assert_matches;
use vpn_domain::*;
use vpn_store::{ChildClaim, GrantEnd, Store, StoreError};
use zeroize::Zeroizing;

fn key() -> Zeroizing<[u8; 32]> {
    Zeroizing::new([3u8; 32])
}

fn meta() -> EntityMeta {
    EntityMeta {
        revision: 0,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
}

fn soon() -> Timestamp {
    Timestamp::now().plus(Duration::from_secs(600))
}

fn grant() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn control(dir: &Path) -> PathBuf {
    dir.join("control.sqlite")
}

/// A raw writer on the control database, as another process (or buggy code) would be.
fn raw(dir: &Path) -> Connection {
    let c = Connection::open(control(dir)).unwrap();
    c.busy_timeout(Duration::from_secs(10)).unwrap();
    c.pragma_update(None, "foreign_keys", "ON").unwrap();
    c
}

fn refused(r: Result<impl std::fmt::Debug, StoreError>, code: ErrorCode) {
    match r {
        Err(e) => assert_eq!(e.to_api().code, code, "{e}"),
        Ok(v) => panic!("accepted: {v:?}"),
    }
}

async fn profile(store: &Store) -> RuntimeProfile {
    let sm = store
        .put_secret(
            "wireguard_private_key".into(),
            None,
            Zeroizing::new(vec![9; 32]),
            None,
        )
        .await
        .unwrap();
    store
        .create(RuntimeProfile {
            id: ProfileId::new(),
            meta: meta(),
            name: "first".into(),
            provider: ProviderKind::Mullvad,
            source: ProfileSource::Imported,
            interface: InterfaceSpec {
                private_key: sm.secret_ref,
                public_key: WgKey::from_str("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=")
                    .unwrap(),
                addresses: vec!["10.99.0.2/32".parse().unwrap()],
                dns: vec!["10.64.0.1".parse().unwrap()],
                mtu: 1420,
            },
            peer: PeerSpec {
                public_key: WgKey::from_str("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
                    .unwrap(),
                preshared_key: None,
                endpoint: "198.51.100.7:51820".parse().unwrap(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                persistent_keepalive: None,
            },
            location: None,
            expires_at: None,
        })
        .await
        .unwrap()
}

fn spec(profile_id: ProfileId) -> InstanceSpec {
    InstanceSpec {
        id: InstanceId::new(),
        meta: meta(),
        name: "first".into(),
        profile_id,
        dns_profile_id: None,
        security_profile_id: None,
        purpose: InstancePurpose::General,
        limits: InstanceLimits::default(),
        strict: false,
        transport: vpn_domain::TransportRef::default(),
    }
}

/// The first setup's run with its connection created through the store, as the manager does.
async fn with_child(store: &Store) -> (vpn_store::BootstrapRow, InstanceSpec) {
    let run = store
        .open_initial_bootstrap(grant(), soon(), None)
        .await
        .unwrap();
    let op = OperationId::new();
    assert_matches!(
        store.claim_bootstrap_child(op).await.unwrap(),
        ChildClaim::Reserved(_)
    );
    let p = profile(store).await;
    let (i, _, run) = store
        .create_bootstrap_child(run.id, op, spec(p.id), None, soon())
        .await
        .unwrap();
    (run, i)
}

#[tokio::test]
async fn the_first_setup_has_one_permanent_row_and_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    // The key is derived from the installation: SHA-256(id + "/initial-bootstrap-v1").
    let expected = hex::encode(Sha256::digest(
        format!("{}/initial-bootstrap-v1", store.installation_id()).as_bytes(),
    ));
    assert_eq!(store.initial_bootstrap_key(), expected);
    let g = grant();
    let first = store
        .open_initial_bootstrap(g.clone(), soon(), None)
        .await
        .unwrap();
    assert_eq!(first.kind, BootstrapKind::Initial);
    assert_eq!(first.stage, BootstrapStage::GrantActive);
    // Its grant expires; a retry reopens the same row.
    store
        .close_bootstrap_grant(
            first.id.clone(),
            g,
            GrantEnd::Expired,
            "EXPIRED".into(),
            "逾期".into(),
        )
        .await
        .unwrap()
        .unwrap();
    let again = store
        .open_initial_bootstrap(grant(), soon(), None)
        .await
        .unwrap();
    assert_eq!(again.id, first.id);
    assert_eq!(store.bootstrap_runs().await.unwrap().len(), 1);
    drop(store);

    // Nothing gets rid of it or gives it another key, kind or identity.
    let c = raw(dir.path());
    let id = first.id.clone();
    for (what, sql) in [
        ("delete", "DELETE FROM bootstrap_journal"),
        (
            "rekey",
            "UPDATE bootstrap_journal SET initial_bootstrap_key = lower(hex(randomblob(32)))",
        ),
        (
            "forget the key",
            "UPDATE bootstrap_journal SET initial_bootstrap_key = NULL",
        ),
        (
            "change kind",
            "UPDATE bootstrap_journal SET kind = 'rebootstrap'",
        ),
        ("change id", "UPDATE bootstrap_journal SET id = 'other'"),
    ] {
        assert!(c.execute(sql, []).is_err(), "{what} was accepted");
    }
    // A second first-setup row is refused with the same key or any other.
    for key in [expected.clone(), "ab".repeat(32)] {
        assert!(
            c.execute(
                "INSERT INTO bootstrap_journal (id, kind, initial_bootstrap_key, stage, created_at, updated_at)
                 VALUES (?1, 'initial', ?2, 'expired', 'now', 'now')",
                params![uuid::Uuid::new_v4().to_string(), key],
            )
            .is_err()
        );
    }
    let (kept_id, kept_key): (String, String) = c
        .query_row(
            "SELECT id, initial_bootstrap_key FROM bootstrap_journal WHERE kind = 'initial'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((kept_id, kept_key), (id, expected));
}

/// Two writers on their own connections, released at the same moment; each runs `sql` in an
/// immediate transaction. Returns how many committed.
fn race(dir: &Path, a: &str, b: &str) -> usize {
    let barrier = Barrier::new(2);
    let barrier = &barrier;
    let results: Vec<bool> = std::thread::scope(|s| {
        let run = move |sql: &str| {
            let mut c = raw(dir);
            barrier.wait();
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let ok = tx.execute_batch(sql).is_ok();
            if ok { tx.commit().is_ok() } else { false }
        };
        let ha = s.spawn(move || run(a));
        let hb = s.spawn(move || run(b));
        vec![ha.join().unwrap(), hb.join().unwrap()]
    });
    results.into_iter().filter(|ok| *ok).count()
}

fn insert_run(kind: &str, stage: &str, key: Option<&str>) -> String {
    let grant = if stage == "grant_active" {
        format!("'{}', 1", uuid::Uuid::new_v4())
    } else {
        "NULL, NULL".into()
    };
    format!(
        "INSERT INTO bootstrap_journal
            (id, kind, initial_bootstrap_key, stage, grant_id, grant_expires_ms, created_at, updated_at)
         VALUES ('{}', '{kind}', {}, '{stage}', {grant},
                 strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));",
        uuid::Uuid::new_v4(),
        key.map_or_else(|| "NULL".into(), |k| format!("'{k}'"))
    )
}

#[tokio::test]
async fn racing_writers_get_one_first_setup_and_one_active_run() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let k = store.initial_bootstrap_key();
    drop(store);

    // Two writers both creating the first setup's row (each its own row id, the same derived
    // key): one wins.
    let initial = || insert_run("initial", "grant_active", Some(&k));
    assert_eq!(race(dir.path(), &initial(), &initial()), 1);
    // Two writers both opening a rebootstrap (the latch set first, as the store does) while the
    // first setup is still active: neither, there is already an active run.
    let latch = "UPDATE provider_egress SET bootstrap_consumed = 1;";
    let rebootstrap = || format!("{latch}{}", insert_run("rebootstrap", "grant_active", None));
    assert_eq!(race(dir.path(), &rebootstrap(), &rebootstrap()), 0);
    // The first setup ends; now two rebootstraps race: exactly one becomes active.
    raw(dir.path())
        .execute(
            "UPDATE bootstrap_journal SET stage = 'expired', grant_id = NULL, grant_expires_ms = NULL",
            [],
        )
        .unwrap();
    assert_eq!(race(dir.path(), &rebootstrap(), &rebootstrap()), 1);
    // A writer reactivating the first setup races one more rebootstrap: none can join the active
    // one (and the first setup never gets a grant again: the latch is set).
    let reopen = format!(
        "UPDATE bootstrap_journal SET stage = 'grant_active', grant_id = '{}', grant_expires_ms = 1
          WHERE kind = 'initial';",
        uuid::Uuid::new_v4()
    );
    assert_eq!(race(dir.path(), &reopen, &rebootstrap()), 0);
    let c = raw(dir.path());
    let active: i64 = c
        .query_row(
            "SELECT count(*) FROM bootstrap_journal WHERE stage IN ('grant_active', 'instance_requested', 'sealing')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(active, 1);
    let initials: i64 = c
        .query_row(
            "SELECT count(*) FROM bootstrap_journal WHERE kind = 'initial'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(initials, 1);
    // And through the store, the same rules answer with their own codes.
    drop(c);
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let egress = store.provider_egress().await.unwrap();
    refused(
        store
            .open_rebootstrap(grant(), soon(), None, egress.revision)
            .await,
        ErrorCode::BootstrapInProgress,
    );
    refused(
        store.open_initial_bootstrap(grant(), soon(), None).await,
        ErrorCode::BootstrapAlreadyConsumed,
    );
}

#[tokio::test]
async fn racing_writers_cannot_reopen_the_first_setup_or_reset_the_latch() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let k = store.initial_bootstrap_key();
    let (run, _) = with_child(&store).await;
    store
        .seal_bootstrap_intent(run.id.clone(), run.child_instance_id.unwrap())
        .await
        .unwrap();
    store
        .seal_bootstrap_commit(run.id.clone(), Timestamp::now())
        .await
        .unwrap();
    drop(store);
    // One writer tries to reset the latch while the other tries to give the first setup a grant
    // again: neither commits, the latch holds and the sealed run stays sealed.
    let reset = "UPDATE provider_egress SET bootstrap_consumed = 0;";
    let reopen = format!(
        "UPDATE bootstrap_journal SET stage = 'grant_active', grant_id = '{}', grant_expires_ms = 1
          WHERE initial_bootstrap_key = '{k}';",
        uuid::Uuid::new_v4()
    );
    assert_eq!(race(dir.path(), reset, &reopen), 0);
    // Together in one transaction they fail too (the latch first, then the run).
    assert_eq!(
        race(dir.path(), &format!("{reset}{reopen}"), "SELECT 1;"),
        1
    );
    let c = raw(dir.path());
    let (consumed, stage): (i64, String) = c
        .query_row(
            "SELECT e.bootstrap_consumed, j.stage FROM provider_egress e, bootstrap_journal j WHERE j.kind = 'initial'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((consumed, stage.as_str()), (1, "sealed"));
    // A rebootstrap row can only exist with the latch set, and a finished one never reopens.
    drop(c);
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let egress = store.provider_egress().await.unwrap();
    let r = store
        .open_rebootstrap(grant(), soon(), None, egress.revision)
        .await
        .unwrap();
    assert!(store.provider_egress().await.unwrap().bootstrap_consumed);
    store
        .end_bootstrap(
            r.id.clone(),
            BootstrapStage::Cancelled,
            "CANCELLED".into(),
            "取消".into(),
        )
        .await
        .unwrap();
    drop(store);
    let c = raw(dir.path());
    assert!(
        c.execute(
            "UPDATE bootstrap_journal SET stage = 'grant_active', grant_id = 'g', grant_expires_ms = 1 WHERE id = ?1",
            params![r.id],
        )
        .is_err(),
        "a finished rebootstrap reopened"
    );
}

#[tokio::test]
async fn a_seal_intent_is_never_withdrawn_and_a_restart_finishes_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let (run, child) = with_child(&store).await;
    let sealing = store
        .seal_bootstrap_intent(run.id.clone(), child.id)
        .await
        .unwrap();
    assert_eq!(sealing.stage, BootstrapStage::Sealing);
    // Neither the user's choice nor a cancel takes it back to direct access.
    let egress = store.provider_egress().await.unwrap();
    refused(
        store
            .put_provider_egress(EgressMode::Disabled, None, egress.revision)
            .await,
        ErrorCode::BootstrapInProgress,
    );
    refused(
        store.open_initial_bootstrap(grant(), soon(), None).await,
        ErrorCode::BootstrapAlreadyConsumed,
    );
    drop(store);
    let c = raw(dir.path());
    for sql in [
        "UPDATE bootstrap_journal SET stage = 'instance_requested'",
        "UPDATE bootstrap_journal SET stage = 'cancelled'",
        "UPDATE bootstrap_journal SET seal_intent_ms = NULL",
    ] {
        assert!(c.execute(sql, []).is_err(), "{sql}");
    }
    drop(c);
    // The process died between the intent and the commit: the next start commits it forward.
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let changed = store.recover_bootstrap().await.unwrap();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].stage, BootstrapStage::Sealed);
    assert_eq!(changed[0].reason_code.as_deref(), Some("SEAL_RECOVERED"));
    let egress = store.provider_egress().await.unwrap();
    assert!(egress.bootstrap_consumed);
    assert_eq!(egress.selected_instance_id, Some(child.id));
    assert_eq!(egress.desired_mode, EgressMode::ViaInstance);
    // A sealed run stays sealed.
    drop(store);
    assert!(
        raw(dir.path())
            .execute("UPDATE bootstrap_journal SET stage = 'blocked'", [])
            .is_err()
    );
}

#[tokio::test]
async fn a_restart_ends_grants_and_overdue_promotions() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let run = store
        .open_initial_bootstrap(grant(), soon(), None)
        .await
        .unwrap();
    drop(store);
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let changed = store.recover_bootstrap().await.unwrap();
    assert_eq!(changed[0].stage, BootstrapStage::Expired);
    assert_eq!(changed[0].grant_id, None);
    assert_eq!(changed[0].reason_code.as_deref(), Some("MANAGER_RESTARTED"));
    assert!(!store.provider_egress().await.unwrap().bootstrap_consumed);

    // A promotion whose deadline passed while the manager was down ends blocked; one still
    // within its deadline keeps waiting (without a grant).
    let reopened = store
        .open_initial_bootstrap(grant(), soon(), None)
        .await
        .unwrap();
    assert_eq!(reopened.id, run.id);
    let op = OperationId::new();
    store.claim_bootstrap_child(op).await.unwrap();
    let p = profile(&store).await;
    let past = Timestamp::from_unix_millis(Timestamp::now().unix_millis() - 1_000).unwrap();
    store
        .create_bootstrap_child(run.id.clone(), op, spec(p.id), None, past)
        .await
        .unwrap();
    drop(store);
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let changed = store.recover_bootstrap().await.unwrap();
    assert_eq!(changed[0].stage, BootstrapStage::Blocked);
    assert_eq!(changed[0].reason_code.as_deref(), Some("PROMOTE_TIMEOUT"));
}

#[tokio::test]
async fn choosing_an_egress_or_deleting_the_connection_ends_the_run() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let (run, child) = with_child(&store).await;
    // The user stops and deletes the new connection while the grant is open: the run forgets it
    // and may build another one (its grant stays on record with the manager's).
    store
        .change_intent(child.id, vpn_store::IntentChange::Stop)
        .await
        .unwrap();
    store.delete_instance(child.id, 1).await.unwrap();
    let freed = store.bootstrap_run(run.id.clone()).await.unwrap().unwrap();
    assert_eq!(freed.stage, BootstrapStage::GrantActive);
    assert_eq!(freed.child_instance_id, None);
    assert!(freed.grant_id.is_some());
    assert_eq!(freed.reason_code.as_deref(), Some("CHILD_GONE"));
    // Another one is built; the grant ends; that one is deleted too: now the run ends blocked.
    let op = OperationId::new();
    assert_matches!(
        store.claim_bootstrap_child(op).await.unwrap(),
        ChildClaim::Reserved(_)
    );
    let p = profile(&store).await;
    let (second, _, _) = store
        .create_bootstrap_child(run.id.clone(), op, spec(p.id), None, soon())
        .await
        .unwrap();
    store
        .close_bootstrap_grant(
            run.id.clone(),
            freed.grant_id.clone().unwrap(),
            GrantEnd::Expired,
            "EXPIRED".into(),
            "逾期".into(),
        )
        .await
        .unwrap();
    store
        .change_intent(second.id, vpn_store::IntentChange::Stop)
        .await
        .unwrap();
    store.delete_instance(second.id, 1).await.unwrap();
    let ended = store.bootstrap_run(run.id.clone()).await.unwrap().unwrap();
    assert_eq!(ended.stage, BootstrapStage::Blocked);
    assert_eq!(ended.reason_code.as_deref(), Some("CHILD_GONE"));
    // Reopened, then the user picks an egress by hand: the run ends cancelled with it.
    let reopened = store
        .open_initial_bootstrap(grant(), soon(), None)
        .await
        .unwrap();
    assert_eq!(
        reopened.child_instance_id, None,
        "a deleted connection is forgotten"
    );
    let p = profile(&store).await;
    let other = store.create_instance(spec(p.id)).await.unwrap();
    let egress = store.provider_egress().await.unwrap();
    store
        .put_provider_egress(EgressMode::ViaInstance, Some(other.id), egress.revision)
        .await
        .unwrap();
    let ended = store.bootstrap_run(run.id).await.unwrap().unwrap();
    assert_eq!(ended.stage, BootstrapStage::Cancelled);
    assert_eq!(ended.grant_id, None);
    assert_eq!(ended.reason_code.as_deref(), Some("EGRESS_CHANGED"));
}
