//! The Provider egress's direct exception through the manager, with real actors (the "worker" is
//! `false`, so a start gets as far as spawning): the run's one connection is created durably with
//! its intent to run and starts without a Start; concurrent and retried requests get that same
//! connection; recovery is required only when the selected egress cannot come back by itself, and
//! a manual rebootstrap is refused — with the exact reason — whenever there is another way out.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use vpn_domain::*;
use vpn_instance_manager::Manager;
use vpn_instance_manager::rpc::{SystemFacts, serve};
use vpn_ipc::control::{Call, ChildClaimWire, ControlClient, Reply};
use vpn_platform::paths::Paths;
use vpn_store::Store;
use zeroize::Zeroizing;

fn meta() -> EntityMeta {
    EntityMeta {
        revision: 1,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
}

fn not_a_worker() -> PathBuf {
    ["/usr/bin/false", "/bin/false"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .expect("a `false` executable")
}

async fn profile(store: &Store, name: &str, endpoint: &str) -> RuntimeProfile {
    let key = store
        .put_secret(
            "wireguard_private_key".into(),
            None,
            Zeroizing::new(vec![7u8; 32]),
            None,
        )
        .await
        .unwrap();
    store
        .create(RuntimeProfile {
            id: ProfileId::new(),
            meta: meta(),
            name: name.into(),
            provider: ProviderKind::Mullvad,
            source: ProfileSource::Imported,
            interface: InterfaceSpec {
                private_key: key.secret_ref,
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
                endpoint: endpoint.parse().unwrap(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                persistent_keepalive: None,
            },
            location: None,
            expires_at: None,
        })
        .await
        .unwrap()
}

fn spec(name: &str, profile_id: ProfileId) -> InstanceSpec {
    InstanceSpec {
        id: InstanceId::new(),
        meta: meta(),
        name: name.into(),
        profile_id,
        dns_profile_id: None,
        security_profile_id: None,
        purpose: InstancePurpose::General,
        limits: InstanceLimits::default(),
        strict: false,
        transport: vpn_domain::TransportRef::default(),
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Served {
    manager: Arc<Manager>,
    client: ControlClient,
}

async fn serve_manager(paths: &Paths, store: Arc<Store>) -> Served {
    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();
    let sock = paths.manager_socket();
    let _ = std::fs::remove_file(&sock);
    tokio::spawn(serve(
        tokio::net::UnixListener::bind(&sock).unwrap(),
        manager.clone(),
        store,
        SystemFacts {
            ssh: None,
            capabilities: vec![],
            performance: None,
        },
    ));
    Served {
        manager,
        client: ControlClient::connect(&sock).await.unwrap(),
    }
}

type EgressReply = (
    ProviderEgress,
    Option<vpn_ipc::control::BootstrapGrantWire>,
    Option<BootstrapRun>,
    Option<EgressRecovery>,
);

async fn egress(c: &ControlClient) -> EgressReply {
    match c.call(Call::ProviderEgress).await.unwrap() {
        Reply::ProviderEgress(w) => (w.egress, w.bootstrap, w.run, w.recovery),
        other => panic!("{other:?}"),
    }
}

async fn eventually<T>(what: &str, mut f: impl AsyncFnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(v) = f().await {
            return v;
        }
        assert!(tokio::time::Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Two connections asked for at the same moment: exactly one reserves the run's connection, the
/// other is refused. Returns the winner's operation.
async fn claim_race(client: &ControlClient) -> OperationId {
    let (op_a, op_b) = (OperationId::new(), OperationId::new());
    let (ra, rb) = tokio::join!(
        client.call(Call::BootstrapClaimChild { operation: op_a }),
        client.call(Call::BootstrapClaimChild { operation: op_b })
    );
    match (ra, rb) {
        (Ok(Reply::BootstrapClaim(ChildClaimWire::Reserved { .. })), Err(e)) => {
            assert_eq!(e.code, ErrorCode::BootstrapInProgress, "{e:?}");
            op_a
        }
        (Err(e), Ok(Reply::BootstrapClaim(ChildClaimWire::Reserved { .. }))) => {
            assert_eq!(e.code, ErrorCode::BootstrapInProgress, "{e:?}");
            op_b
        }
        other => panic!("not exactly one reservation: {other:?}"),
    }
}

/// The run's connection (and its Gateway) created in one call; no Lifecycle Start follows.
async fn create_child(
    client: &ControlClient,
    run_id: &str,
    winner: OperationId,
    inst: &InstanceSpec,
) -> InstanceSpec {
    let port = free_port();
    let gateway = GatewaySpec {
        id: GatewayId::new(),
        meta: meta(),
        instance_id: inst.id,
        name: format!("代理埠 {port}"),
        kind: GatewayKind::Mixed,
        port,
        enabled: true,
        udp: true,
        max_connections: 64,
    };
    match client
        .call(Call::BootstrapCreateChild {
            run: run_id.to_owned(),
            operation: winner,
            instance: inst.clone(),
            gateway: Some(gateway),
        })
        .await
        .unwrap()
    {
        Reply::BootstrapChild { instance, gateway } => {
            assert!(gateway.is_some());
            *instance
        }
        other => panic!("{other:?}"),
    }
}

/// AC-71: the first setup's connection is created with its intent to run in the same transaction
/// as the run's record, and starts without any Start; two requests at once and a retry of the
/// expired setup all end with that one connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_connection_is_enqueued_durably_and_is_the_only_one() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    paths.ensure().unwrap();
    let store = Arc::new(Store::open(&paths.state, &Zeroizing::new([5u8; 32]), 1).unwrap());
    let served = serve_manager(&paths, store.clone()).await;
    let client = &served.client;

    client
        .call(Call::BootstrapGrant { operation: None })
        .await
        .unwrap();
    let (_, grant, run, _) = egress(client).await;
    let grant = grant.unwrap();
    assert_eq!(grant.kind, BootstrapKind::Initial);
    let run = run.unwrap();
    assert_eq!(run.stage, BootstrapStage::GrantActive);

    // A Mullvad and an AirVPN connection asked for at the same moment: one holds the run's one
    // connection, the other is refused before it made a device or a key.
    let winner = claim_race(client).await;

    // The profile passed the checker: the connection, its Gateway and the run's record of it in
    // one call — no Lifecycle Start follows.
    let prof = profile(&store, "東京", "198.51.100.7:51820").await;
    let inst = spec("Mullvad · 東京", prof.id);
    let created = create_child(client, &run.id, winner, &inst).await;
    assert_eq!(created.id, inst.id);
    // It starts by itself: its intent says running and its actor already tried.
    let st = eventually("the new connection starts by itself", async || {
        let st = served.manager.status(inst.id).await.ok()?;
        (st.intent.desired == DesiredState::Running && st.phase != Phase::Stopped).then_some(st)
    })
    .await;
    assert!(!st.intent.manual_stop);
    let (_, _, run, _) = egress(client).await;
    let run = run.unwrap();
    assert_eq!(run.stage, BootstrapStage::InstanceRequested);
    assert_eq!(run.child_instance_id, Some(inst.id));
    assert!(run.promote_deadline.is_some());

    // A later request (another provider, a retry with a new key) gets that connection back.
    match client
        .call(Call::BootstrapClaimChild {
            operation: OperationId::new(),
        })
        .await
        .unwrap()
    {
        Reply::BootstrapClaim(ChildClaimWire::Existing { instance, .. }) => {
            assert_eq!(instance, inst.id);
        }
        other => panic!("{other:?}"),
    }

    // The setup expires without the connection coming up; the user retries: the same run, the
    // same connection, started again — still one connection.
    client.call(Call::BootstrapRevoke).await.unwrap();
    client
        .call(Call::BootstrapAbandon {
            run: run.id.clone(),
            reason_code: "PROMOTE_TIMEOUT".into(),
            reason: "新連線在時限內沒有連上，未設為出口".into(),
        })
        .await
        .unwrap();
    let (_, grant, ended, _) = egress(client).await;
    assert!(grant.is_none());
    assert_eq!(ended.unwrap().stage, BootstrapStage::Blocked);
    client
        .call(Call::BootstrapGrant { operation: None })
        .await
        .unwrap();
    let (_, _, again, _) = egress(client).await;
    let again = again.unwrap();
    assert_eq!(again.id, run.id);
    assert_eq!(again.child_instance_id, Some(inst.id));
    let Reply::BootstrapClaim(ChildClaimWire::Existing { run: run_id, .. }) = client
        .call(Call::BootstrapClaimChild {
            operation: OperationId::new(),
        })
        .await
        .unwrap()
    else {
        panic!("the retry must map to the existing connection");
    };
    client
        .call(Call::BootstrapResumeChild { run: run_id })
        .await
        .unwrap();
    let (_, _, resumed, _) = egress(client).await;
    assert_eq!(resumed.unwrap().stage, BootstrapStage::InstanceRequested);
    let all: Vec<InstanceSpec> = store.list().await.unwrap();
    assert_eq!(all.len(), 1);
    let gateways: Vec<GatewaySpec> = store.list().await.unwrap();
    assert_eq!(gateways.len(), 1);

    // A manager restart keeps the connection's intent (it starts again by itself) and the run
    // waiting for it; the grant did not survive.
    drop(served);
    let served = serve_manager(&paths, store.clone()).await;
    let (_, grant, run, _) = egress(&served.client).await;
    assert!(grant.is_none(), "no direct access after a restart");
    assert_eq!(run.unwrap().stage, BootstrapStage::InstanceRequested);
    eventually(
        "the connection starts again after the restart",
        async || {
            let st = served.manager.status(inst.id).await.ok()?;
            (st.phase != Phase::Stopped).then_some(())
        },
    )
    .await;
}

/// The selected egress as its actor reports it, once `done` holds.
async fn egress_status(
    manager: &Manager,
    id: InstanceId,
    what: &str,
    done: impl Fn(&InstanceStatus) -> bool + Sync,
) -> InstanceStatus {
    eventually(what, async || {
        let s = manager.status(id).await.ok()?;
        done(&s).then_some(s)
    })
    .await
}

/// Delete secret `id` from the vault behind the Store's back.
fn delete_secret(paths: &Paths, id: String) {
    let conn = rusqlite::Connection::open(paths.state.join("control.sqlite")).unwrap();
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    conn.execute("DELETE FROM secrets WHERE id = ?1", [id])
        .unwrap();
}

/// A rebootstrap at `revision` is refused as not eligible, saying `words` (Traditional Chinese).
async fn refused_saying(mgr: &Manager, revision: u64, words: &str) {
    let refused = mgr.rebootstrap(revision, None).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::RebootstrapNotEligible);
    assert!(
        refused.message.zh_tw.contains(words),
        "{}",
        refused.message.zh_tw
    );
}

/// Stopped by the user, the egress is started again instead; then it fails again.
async fn stopped_by_the_user_is_not_eligible(mgr: &Manager, id: InstanceId) {
    mgr.stop_instance(id, false).await.unwrap();
    let view = mgr.provider_egress().await.unwrap();
    assert_eq!(view.recovery.unwrap().reason_code, "EGRESS_STOPPED");
    assert_eq!(
        mgr.rebootstrap(view.egress.revision, None)
            .await
            .unwrap_err()
            .code,
        ErrorCode::RebootstrapNotEligible
    );
    mgr.start_instance(id).await.unwrap();
    egress_status(mgr, id, "fails again", |st| st.phase == Phase::Failed).await;
}

/// AC-83/84: recovery is required when the selected egress's key is gone; a rebootstrap is
/// refused with the exact reason while another profile could serve, while the egress is stopped
/// by the user, with a stale revision, and while one is active; allowed it opens a ten-minute
/// grant of its own kind and keeps the latch set, and cancelling closes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rebootstrap_is_allowed_only_when_nothing_else_can_serve() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    paths.ensure().unwrap();
    let store = Arc::new(Store::open(&paths.state, &Zeroizing::new([5u8; 32]), 1).unwrap());
    let prof = profile(&store, "東京", "198.51.100.7:51820").await;
    let egress = store.create_instance(spec("出口", prof.id)).await.unwrap();
    // The first setup ended long ago with this egress.
    store.consume_bootstrap().await.unwrap();
    let cur = store.provider_egress().await.unwrap();
    store
        .put_provider_egress(EgressMode::ViaInstance, Some(egress.id), cur.revision)
        .await
        .unwrap();
    let served = serve_manager(&paths, store.clone()).await;
    let mgr = &served.manager;

    // It merely fails to start (no worker here): that is an outage, not a reason for direct.
    mgr.start_instance(egress.id).await.unwrap();
    egress_status(mgr, egress.id, "retrying", |st| {
        st.phase == Phase::Reconnecting
    })
    .await;
    let view = mgr.provider_egress().await.unwrap();
    let recovery = view.recovery.unwrap();
    assert!(!recovery.required && !recovery.rebootstrap_eligible);
    assert_eq!(recovery.reason_code, "EGRESS_RECOVERING");
    refused_saying(mgr, view.egress.revision, "暫時斷線").await;

    // Its key disappears from the vault (behind the Store's back): the next attempt fails for
    // good and recovery is required.
    delete_secret(&paths, prof.interface.private_key.0.to_string());
    let st = egress_status(mgr, egress.id, "fails for want of its key", |st| {
        st.phase == Phase::Failed
            && st.recovery.last_fault.as_ref().map(|f| f.code.as_str()) == Some("KEY_MISSING")
    })
    .await;
    assert!(
        st.recovery
            .last_fault
            .unwrap()
            .message
            .zh_tw
            .contains("私鑰")
    );
    let view = mgr.provider_egress().await.unwrap();
    let recovery = view.recovery.clone().unwrap();
    assert!(
        recovery.required && recovery.rebootstrap_eligible,
        "{recovery:?}"
    );
    assert_eq!(recovery.reason_code, "KEY_MISSING");

    // Another valid profile here: use it instead.
    let spare = profile(&store, "大阪備用", "203.0.113.9:51820").await;
    let view = mgr.provider_egress().await.unwrap();
    let recovery = view.recovery.unwrap();
    assert!(recovery.required && !recovery.rebootstrap_eligible);
    assert_eq!(recovery.reason_code, "LOCAL_PROFILE_AVAILABLE");
    refused_saying(mgr, view.egress.revision, "大阪備用").await;
    store
        .delete::<RuntimeProfile>(spare.id.to_string(), 1)
        .await
        .unwrap();

    // Stopped by the user: start it; no direct access.
    stopped_by_the_user_is_not_eligible(mgr, egress.id).await;

    // Eligible: a stale revision is refused, the right one opens the grant.
    let view = mgr.provider_egress().await.unwrap();
    assert!(view.recovery.as_ref().unwrap().rebootstrap_eligible);
    assert_eq!(
        mgr.rebootstrap(view.egress.revision + 1, None)
            .await
            .unwrap_err()
            .code,
        ErrorCode::RevisionConflict
    );
    let opened = mgr.rebootstrap(view.egress.revision, None).await.unwrap();
    let grant = opened.grant.unwrap();
    assert_eq!(grant.kind, BootstrapKind::Rebootstrap);
    let left = grant.expires_at.unix_millis() - Timestamp::now().unix_millis();
    assert!((9 * 60_000..=10 * 60_000).contains(&left), "{left} ms");
    assert!(opened.egress.bootstrap_consumed, "the latch stays set");
    assert_eq!(
        opened.run.as_ref().unwrap().kind,
        BootstrapKind::Rebootstrap
    );
    // Only one at a time; the first setup's grant is not available either.
    assert!(mgr.rebootstrap(opened.egress.revision, None).await.is_err());
    assert!(mgr.bootstrap().grant(None).await.is_err());

    // Cancelled: the grant closes, the run ends, the latch stays.
    let cancelled = mgr.cancel_rebootstrap().await.unwrap();
    assert!(cancelled.grant.is_none());
    assert!(std::fs::metadata(&grant.connector).is_err());
    assert_eq!(cancelled.run.unwrap().stage, BootstrapStage::Cancelled);
    assert!(cancelled.egress.bootstrap_consumed);
    // Through the protocol the same refusal carries its code.
    let egress = served
        .client
        .call(Call::Rebootstrap {
            expected_revision: 1,
            operation: None,
        })
        .await
        .unwrap_err();
    assert_eq!(egress.code, ErrorCode::RevisionConflict);
}

/// The selected egress held closed by an emergency stop carried over from before this start,
/// which nothing on disk confirms: the user has to decide on the connection (confirm the stop, or
/// clear it and start) — it is not reported as a manual stop that a Start would end (Start is
/// refused until the emergency is cleared), and no direct access is offered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unconfirmed_stop_of_the_egress_asks_for_the_users_decision() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(dir.path());
    paths.ensure().unwrap();
    let store = Arc::new(Store::open(&paths.state, &Zeroizing::new([5u8; 32]), 1).unwrap());
    let prof = profile(&store, "東京", "198.51.100.7:51820").await;
    let egress = store.create_instance(spec("出口", prof.id)).await.unwrap();
    store
        .change_intent(egress.id, vpn_store::IntentChange::Start)
        .await
        .unwrap();
    store.consume_bootstrap().await.unwrap();
    let cur = store.provider_egress().await.unwrap();
    store
        .put_provider_egress(EgressMode::ViaInstance, Some(egress.id), cur.revision)
        .await
        .unwrap();
    // The previous manager recorded an emergency stop of it and died before its latch.
    store
        .begin_operation(
            OP_INSTANCE_EMERGENCY_STOP.into(),
            Some(egress.id.to_string()),
            None,
            None,
        )
        .await
        .unwrap();
    let served = serve_manager(&paths, store.clone()).await;
    let mgr = &served.manager;
    let st = egress_status(mgr, egress.id, "held for the user's decision", |st| {
        st.phase == Phase::RecoveryRequired
    })
    .await;
    assert!(
        st.intent.manual_stop && st.intent.emergency_latched,
        "{st:?}"
    );
    assert_eq!(st.intent.persistence, Persistence::Pending);

    let view = mgr.provider_egress().await.unwrap();
    let recovery = view.recovery.unwrap();
    assert_eq!(
        recovery.reason_code, "EGRESS_NEEDS_DECISION",
        "{recovery:?}"
    );
    assert!(!recovery.required && !recovery.rebootstrap_eligible);
    assert!(
        recovery.reason.zh_tw.contains("解除急停"),
        "{}",
        recovery.reason.zh_tw
    );
    assert!(
        !recovery.reason.zh_tw.contains("啟動它即可恢復"),
        "{}",
        recovery.reason.zh_tw
    );
    assert_eq!(
        mgr.start_instance(egress.id).await.unwrap_err().code,
        ErrorCode::EmergencyLatched
    );
    assert_eq!(
        mgr.rebootstrap(view.egress.revision, None)
            .await
            .unwrap_err()
            .code,
        ErrorCode::RebootstrapNotEligible
    );
}
