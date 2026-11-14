//! Core Store contracts: revisions and reference protection, durable intents and latches,
//! identity leases, idempotency, and that secrets never reach disk in plaintext.

// Test fixtures: a failed setup step should panic right there.
#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap/expect in #[test] fns, not in the helper fns of a tests/ crate"
)]

use std::str::FromStr;

use std::assert_matches;
use vpn_domain::*;
use vpn_store::{Begin, IntentChange, Store, StoreError};
use zeroize::Zeroizing;

fn key() -> Zeroizing<[u8; 32]> {
    Zeroizing::new([42u8; 32])
}

fn meta() -> EntityMeta {
    EntityMeta {
        revision: 0,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
}

fn profile(secret: SecretRef) -> RuntimeProfile {
    RuntimeProfile {
        id: ProfileId::new(),
        meta: meta(),
        name: "lab".into(),
        provider: ProviderKind::Generic,
        source: ProfileSource::Imported,
        interface: InterfaceSpec {
            private_key: secret,
            public_key: WgKey::from_str("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=").unwrap(),
            addresses: vec!["10.99.0.2/32".parse().unwrap()],
            dns: vec![],
            mtu: 1420,
        },
        peer: PeerSpec {
            public_key: WgKey::from_str("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=").unwrap(),
            preshared_key: None,
            endpoint: "198.51.100.7:51820".parse().unwrap(),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            persistent_keepalive: None,
        },
        location: None,
        expires_at: None,
    }
}

fn instance(profile_id: ProfileId) -> InstanceSpec {
    InstanceSpec {
        id: InstanceId::new(),
        meta: meta(),
        name: "work".into(),
        profile_id,
        dns_profile_id: None,
        security_profile_id: None,
        purpose: InstancePurpose::General,
        limits: InstanceLimits::default(),
        strict: false,
        transport: vpn_domain::TransportRef::default(),
    }
}

#[tokio::test]
async fn revisions_references_and_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &key(), 1).unwrap();

    let marker = b"SYNTHETIC-PRIVATE-KEY-MARKER-0123456789".to_vec();
    let sm = store
        .put_secret(
            "wireguard_private_key".into(),
            Some("lab".into()),
            Zeroizing::new(marker.clone()),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        &store.open_secret(sm.secret_ref).await.unwrap()[..],
        &marker[..]
    );

    let p = store.create(profile(sm.secret_ref)).await.unwrap();
    assert_eq!(p.meta.revision, 1);
    let mut p2 = p.clone();
    p2.name = "lab 2".into();
    let p2 = store.update(p2, 1).await.unwrap();
    assert_eq!(p2.meta.revision, 2);
    assert_matches!(
        store.update(p.clone(), 1).await,
        Err(StoreError::RevisionConflict { .. })
    );
    let old: RuntimeProfile = store
        .get_revision(p.id.to_string(), 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        old.name, "lab",
        "old revisions stay readable for running generations"
    );

    let i = store.create_instance(instance(p.id)).await.unwrap();
    assert_matches!(
        store.delete::<RuntimeProfile>(p.id.to_string(), 2).await,
        Err(StoreError::InUse(_))
    );
    assert_matches!(
        store.delete_secret(sm.secret_ref).await,
        Err(StoreError::InUse(_))
    );

    // Plaintext never reaches the database files (WAL included).
    drop(store);
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes.windows(marker.len()).any(|w| w == marker.as_slice()),
            "secret plaintext found on disk"
        );
    }
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    store.delete_instance(i.id, 1).await.unwrap();
    store
        .delete::<RuntimeProfile>(p.id.to_string(), 2)
        .await
        .unwrap();
    store.delete_secret(sm.secret_ref).await.unwrap();
}

#[tokio::test]
async fn intents_latches_generations_and_identity_leases() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let sm = store
        .put_secret("k".into(), None, Zeroizing::new(vec![1; 32]), None)
        .await
        .unwrap();
    let p = store.create(profile(sm.secret_ref)).await.unwrap();
    let a = store.create_instance(instance(p.id)).await.unwrap();
    let b = store.create_instance(instance(p.id)).await.unwrap();

    let ia = store
        .change_intent(a.id, IntentChange::Start)
        .await
        .unwrap();
    assert_eq!(ia.desired, DesiredState::Running);
    // Start on a running intent changes nothing: the running generation stays current.
    let again = store
        .change_intent(a.id, IntentChange::Start)
        .await
        .unwrap();
    assert_eq!(again, ia, "a repeated Start keeps the intent revision");
    let g1 = store
        .reserve_generation(a.id, ia.intent_revision, "fp".into())
        .await
        .unwrap();
    let g2 = store
        .reserve_generation(a.id, ia.intent_revision, "fp".into())
        .await
        .unwrap();
    assert!(g2 > g1, "generations are monotonic");

    // Same key cannot be leased by another Instance.
    let ib = store
        .change_intent(b.id, IntentChange::Start)
        .await
        .unwrap();
    assert_matches!(
        store
            .reserve_generation(b.id, ib.intent_revision, "fp".into())
            .await,
        Err(StoreError::IdentityInUse)
    );

    // Emergency latch survives a restart and blocks Start until cleared; clearing stays stopped.
    let e = store
        .change_intent(a.id, IntentChange::Emergency)
        .await
        .unwrap();
    assert!(e.emergency_latched && e.manual_stop && e.desired == DesiredState::Stopped);
    assert!(
        store
            .reserve_generation(a.id, e.intent_revision, "fp".into())
            .await
            .is_err()
    );
    drop(store);
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let after = store.intent(a.id).await.unwrap();
    assert!(after.emergency_latched, "latch is durable");
    assert!(
        store
            .change_intent(a.id, IntentChange::Start)
            .await
            .is_err()
    );
    let cleared = store
        .change_intent(a.id, IntentChange::ClearEmergency)
        .await
        .unwrap();
    assert!(!cleared.emergency_latched && cleared.desired == DesiredState::Stopped);
    // A stale intent revision cannot reserve (a Stop raced the recovery attempt).
    assert_matches!(
        store
            .reserve_generation(a.id, ia.intent_revision, "fp".into())
            .await,
        Err(StoreError::RevisionConflict { .. })
    );
    // A's lease was never released, but A is stopped: a stale lease does not block B.
    let ib = store.intent(b.id).await.unwrap();
    store
        .reserve_generation(b.id, ib.intent_revision, "fp".into())
        .await
        .unwrap();
    // Now B holds the key and may run, so A is the one refused.
    let ia = store
        .change_intent(a.id, IntentChange::Start)
        .await
        .unwrap();
    assert_matches!(
        store
            .reserve_generation(a.id, ia.intent_revision, "fp".into())
            .await,
        Err(StoreError::IdentityInUse)
    );
    // Releasing every lease of B frees the key for A.
    store.release_identities(b.id).await.unwrap();
    store
        .reserve_generation(a.id, ia.intent_revision, "fp".into())
        .await
        .unwrap();
    // A moves to another key: its lease on the old one goes with that reservation.
    store
        .reserve_generation(a.id, ia.intent_revision, "fp2".into())
        .await
        .unwrap();
    store
        .reserve_generation(b.id, ib.intent_revision, "fp".into())
        .await
        .unwrap();
}

/// Record a stop operation of `id` as the controller does, with `status` as its outcome.
async fn stop_op(store: &Store, id: InstanceId, emergency: bool, status: Option<OperationStatus>) {
    let kind = if emergency {
        OP_INSTANCE_EMERGENCY_STOP
    } else {
        OP_INSTANCE_STOP
    };
    let Begin::New(op) = store
        .begin_operation(kind.into(), Some(id.to_string()), None, None)
        .await
        .unwrap()
    else {
        panic!("no idempotency key: always new")
    };
    if let Some(status) = status {
        store
            .finish_operation(op.id, status, None, vec![id.to_string()])
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn stops_the_intent_does_not_show_are_found_and_a_confirmed_start_supersedes_them() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let sm = store
        .put_secret("k".into(), None, Zeroizing::new(vec![1; 32]), None)
        .await
        .unwrap();
    let p = store.create(profile(sm.secret_ref)).await.unwrap();
    let a = store.create_instance(instance(p.id)).await.unwrap();
    let b = store.create_instance(instance(p.id)).await.unwrap();
    let c = store.create_instance(instance(p.id)).await.unwrap();
    for i in [a.id, b.id, c.id] {
        store.change_intent(i, IntentChange::Start).await.unwrap();
    }
    // Recorded after the last intent write, and the intent still says running: unconfirmed,
    // whatever the operation's recorded outcome (a stop answers before its latch is on disk).
    stop_op(&store, a.id, true, None).await;
    stop_op(&store, b.id, false, Some(OperationStatus::Succeeded)).await;
    // A stop that failed never happened.
    stop_op(&store, c.id, false, Some(OperationStatus::Failed)).await;
    let mut found = store.unconfirmed_stops().await.unwrap();
    found.sort_by_key(|s| s.emergency);
    assert_eq!(
        found
            .iter()
            .map(|s| (s.instance_id, s.emergency))
            .collect::<Vec<_>>(),
        [(b.id, false), (a.id, true)]
    );
    // Marked unknown at the next manager start: still unconfirmed.
    store.abandon_unfinished_operations().await.unwrap();
    assert_eq!(store.unconfirmed_stops().await.unwrap().len(), 2);

    // A's latch reaches the disk: the intent shows it.
    store
        .change_intent(a.id, IntentChange::Emergency)
        .await
        .unwrap();
    // B's user starts it again: a plain Start on a running intent writes nothing, so it would
    // not show the decision; a confirmed Start is a new revision, newer than the stop.
    let before = store.intent(b.id).await.unwrap();
    assert_eq!(
        store
            .change_intent(b.id, IntentChange::Start)
            .await
            .unwrap(),
        before
    );
    assert_eq!(store.unconfirmed_stops().await.unwrap().len(), 1);
    let confirmed = store
        .change_intent(b.id, IntentChange::ConfirmStart)
        .await
        .unwrap();
    assert_eq!(confirmed.intent_revision, before.intent_revision + 1);
    assert_eq!(confirmed.desired, DesiredState::Running);
    assert_eq!(store.unconfirmed_stops().await.unwrap(), []);
    // An emergency latch is never lifted by a Start of either kind.
    assert_matches!(
        store.change_intent(a.id, IntentChange::ConfirmStart).await,
        Err(StoreError::InvalidState(_))
    );
    // A plain stop recorded while an emergency stop is on disk: shown by the intent.
    stop_op(&store, a.id, false, None).await;
    assert_eq!(store.unconfirmed_stops().await.unwrap(), []);
}

#[tokio::test]
async fn idempotency_keys() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let first = store
        .begin_operation(
            "instance.start".into(),
            Some("x".into()),
            Some("k1".into()),
            Some("fp-a".into()),
        )
        .await
        .unwrap();
    let Begin::New(op) = first else {
        panic!("first use creates")
    };
    let again = store
        .begin_operation(
            "instance.start".into(),
            Some("x".into()),
            Some("k1".into()),
            Some("fp-a".into()),
        )
        .await
        .unwrap();
    assert_matches!(again, Begin::Existing(ref o) if o.id == op.id);
    assert_matches!(
        store
            .begin_operation(
                "instance.start".into(),
                None,
                Some("k1".into()),
                Some("fp-b".into())
            )
            .await,
        Err(StoreError::IdempotencyConflict)
    );
    store
        .finish_operation(op.id, OperationStatus::Succeeded, None, vec!["x".into()])
        .await
        .unwrap();
    let got = store.operation_by_key("k1".into()).await.unwrap().unwrap();
    assert_eq!(got.status, OperationStatus::Succeeded);

    // An operation nobody finished (its controller request or manager connection is gone) is
    // marked unknown when the manager starts; finished ones are left alone.
    let Begin::New(lost) = store
        .begin_operation(
            "instance.create".into(),
            None,
            Some("k2".into()),
            Some("fp-c".into()),
        )
        .await
        .unwrap()
    else {
        panic!("first use creates")
    };
    assert_eq!(store.abandon_unfinished_operations().await.unwrap(), 1);
    let lost = store.operation(lost.id).await.unwrap().unwrap();
    assert_eq!(lost.status, OperationStatus::Unknown);
    assert_eq!(lost.error.map(|e| e.code), Some(ErrorCode::OutcomeUnknown));
    let done = store.operation_by_key("k1".into()).await.unwrap().unwrap();
    assert_eq!(done.status, OperationStatus::Succeeded);

    // An outcome, once recorded, is never overwritten by a late report.
    assert!(
        !store
            .finish_operation(op.id, OperationStatus::Failed, None, Vec::new())
            .await
            .unwrap()
    );
    assert!(
        !store
            .finish_operation(lost.id, OperationStatus::Succeeded, None, Vec::new())
            .await
            .unwrap()
    );
    let done = store.operation(op.id).await.unwrap().unwrap();
    assert_eq!(done.status, OperationStatus::Succeeded);
    assert_eq!(done.result_refs, vec!["x".to_string()]);
    assert_eq!(
        store.operation(lost.id).await.unwrap().unwrap().status,
        OperationStatus::Unknown
    );
}

fn gateway(instance_id: InstanceId, port: u16) -> GatewaySpec {
    GatewaySpec {
        id: GatewayId::new(),
        meta: meta(),
        instance_id,
        name: format!("gw{port}"),
        kind: GatewayKind::Mixed,
        port,
        enabled: true,
        udp: true,
        max_connections: 64,
    }
}

#[tokio::test]
async fn an_instance_and_its_gateways_go_together_or_not_at_all() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    let secret = store
        .put_secret(
            "wireguard_private_key".into(),
            None,
            Zeroizing::new(vec![7; 32]),
            None,
        )
        .await
        .unwrap();
    let p = store.create(profile(secret.secret_ref)).await.unwrap();
    let i = store.create_instance(instance(p.id)).await.unwrap();
    let a = store.create(gateway(i.id, 1080)).await.unwrap();
    let b = store.create(gateway(i.id, 1081)).await.unwrap();

    // A set that is not exactly the current one changes nothing.
    let err = store
        .delete_instance_with_gateways(i.id, i.meta.revision, vec![a.id])
        .await
        .unwrap_err();
    assert_matches!(err, StoreError::InvalidState(_));
    assert!(
        store
            .get::<GatewaySpec>(a.id.to_string())
            .await
            .unwrap()
            .is_some()
    );

    // A Gateway used by an SSH host keeps everything.
    let ssh = store
        .create(SshHost {
            id: SshHostId::new(),
            meta: meta(),
            kind: SshHostKind::Host,
            alias: "work".into(),
            host_name: Some("git.example.com".into()),
            user: None,
            port: None,
            identity_file: None,
            identities_only: false,
            gateway_id: Some(b.id),
            server_alive_interval: Some(60),
        })
        .await
        .unwrap();
    let err = store
        .delete_instance_with_gateways(i.id, i.meta.revision, vec![a.id, b.id])
        .await
        .unwrap_err();
    assert_matches!(err, StoreError::InUse(_));
    assert!(
        store
            .get::<GatewaySpec>(a.id.to_string())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get::<InstanceSpec>(i.id.to_string())
            .await
            .unwrap()
            .is_some()
    );

    store
        .delete::<SshHost>(ssh.id.to_string(), ssh.meta.revision)
        .await
        .unwrap();
    store
        .delete_instance_with_gateways(i.id, i.meta.revision, vec![b.id, a.id])
        .await
        .unwrap();
    assert!(
        store
            .get::<GatewaySpec>(a.id.to_string())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get::<GatewaySpec>(b.id.to_string())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get::<InstanceSpec>(i.id.to_string())
            .await
            .unwrap()
            .is_none()
    );
}

/// The vault key is a file beside the data: a replaced or lost key stops the store instead of
/// starting a vault the secrets cannot be opened with — also for a store made before the check.
#[tokio::test]
async fn a_vault_key_that_is_not_the_stores_own_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let other = Zeroizing::new([7u8; 32]);
    let store = Store::open(dir.path(), &key(), 1).unwrap();
    store
        .put_secret("k".into(), None, Zeroizing::new(vec![1; 32]), None)
        .await
        .unwrap();
    drop(store);
    assert!(Store::open(dir.path(), &key(), 1).is_ok());
    assert!(matches!(
        Store::open(dir.path(), &other, 1),
        Err(StoreError::VaultKeyMismatch)
    ));

    // A store from before the check: proven with one of its secrets, then recorded.
    let conn = rusqlite::Connection::open(dir.path().join("control.sqlite")).unwrap();
    conn.execute("DELETE FROM meta WHERE key = 'vault_key_check'", [])
        .unwrap();
    drop(conn);
    assert!(matches!(
        Store::open(dir.path(), &other, 1),
        Err(StoreError::VaultKeyMismatch)
    ));
    assert!(Store::open(dir.path(), &key(), 1).is_ok());
    assert!(matches!(
        Store::open(dir.path(), &other, 1),
        Err(StoreError::VaultKeyMismatch)
    ));
}
