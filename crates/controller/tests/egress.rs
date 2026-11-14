//! The Provider egress's direct exception over HTTP, against a real manager (the "worker" is
//! `false`; nothing here reaches a provider or any network: every path exercised stops before a
//! provider request, or only asks the manager where requests would go).
//!
//! - a rebootstrap is offered and opened only while the selected egress cannot come back by
//!   itself, needs the explicit acknowledgement and the egress revision, keeps the latch set, and
//!   is cancelled with its grant; refused with the reason while another profile could serve;
//! - its grant carries only the operations that build an egress: other provider work is refused
//!   before it sends anything;
//! - the first setup builds one connection: a second request while one is being built is refused
//!   before any provider request, and a request after it exists gets it back (started again);
//! - the durable promotion is abandoned, with its reason shown, when its connection is stopped.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use vpn_controller::hub::Hub;
use vpn_controller::link::ManagerLink;
use vpn_controller::provider::Providers;
use vpn_controller::routes::{AppState, api};
use vpn_domain::*;
use vpn_instance_manager::Manager;
use vpn_instance_manager::rpc::{SystemFacts, serve};
use vpn_ipc::control::ChildClaimWire;
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

struct Fixture {
    _dir: tempfile::TempDir,
    paths: Paths,
    store: Arc<Store>,
    manager: Arc<Manager>,
    link: Arc<ManagerLink>,
    providers: Arc<Providers>,
    app: axum::Router,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(&dir.path().join("state"));
    paths.ensure().unwrap();
    let master = vpn_platform::keystore::load_or_create_key_file(&paths.vault_key()).unwrap();
    let store = Arc::new(Store::open(&paths.state, &master, 1).unwrap());
    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();
    let sock = paths.manager_socket();
    tokio::spawn(serve(
        tokio::net::UnixListener::bind(&sock).unwrap(),
        manager.clone(),
        store.clone(),
        SystemFacts {
            capabilities: vec![],
            ssh: None,
            performance: None,
        },
    ));
    let hub = Hub::new();
    let link = ManagerLink::new(sock, hub.clone());
    tokio::spawn(link.clone().run());
    for _ in 0..100 {
        if link.connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(link.connected(), "controller reaches the manager");
    let providers = Providers::new();
    let app = api(AppState {
        link: link.clone(),
        hub,
        port: 18765,
        exposure: Arc::default(),
        data_dir: None,
        gateway_key: None,
        providers: providers.clone(),
    });
    Fixture {
        _dir: dir,
        paths,
        store,
        manager,
        link,
        providers,
        app,
    }
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

async fn account(store: &Store) -> ProviderAccount {
    let credential = store
        .put_secret(
            "provider_credential".into(),
            None,
            Zeroizing::new(b"SYNTHETIC-NOT-AN-ACCOUNT".to_vec()),
            None,
        )
        .await
        .unwrap();
    store
        .create(ProviderAccount {
            id: ProviderAccountId::new(),
            meta: meta(),
            provider: ProviderKind::Mullvad,
            label: "main".into(),
            credential_ref: credential.secret_ref,
            expires_at: None,
            observed_at: None,
        })
        .await
        .unwrap()
}

async fn call(app: &axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn key() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn post(uri: &str, body: &str, if_match: Option<u64>) -> Request<Body> {
    let mut r = Request::post(uri)
        .header("content-type", "application/json")
        .header("idempotency-key", key());
    if let Some(rev) = if_match {
        r = r.header("if-match", format!("\"{rev}\""));
    }
    r.body(Body::from(body.to_string())).unwrap()
}

async fn egress(app: &axum::Router) -> ProviderEgressStatus {
    let (status, body) = call(
        app,
        Request::get("/v1/provider-egress")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_str(&body).unwrap()
}

async fn eventually_egress(
    app: &axum::Router,
    what: &str,
    done: impl Fn(&ProviderEgressStatus) -> bool,
) -> ProviderEgressStatus {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let s = egress(app).await;
        if done(&s) {
            return s;
        }
        assert!(tokio::time::Instant::now() < deadline, "{what}: {s:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn error(body: &str) -> ApiError {
    serde_json::from_str(body).unwrap()
}

/// AC-83/84 over HTTP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rebootstrap_needs_a_dead_egress_an_acknowledgement_and_carries_only_recovery() {
    let f = fixture().await;
    let prof = profile(&f.store, "東京", "198.51.100.7:51820").await;
    let inst = f
        .store
        .create_instance(spec("出口", prof.id))
        .await
        .unwrap();
    let acct = account(&f.store).await;
    f.store.consume_bootstrap().await.unwrap();
    let cur = f.store.provider_egress().await.unwrap();
    f.store
        .put_provider_egress(EgressMode::ViaInstance, Some(inst.id), cur.revision)
        .await
        .unwrap();
    // Its key is gone from the vault (behind the Store's back), then it is started.
    {
        let c = rusqlite::Connection::open(f.paths.state.join("control.sqlite")).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.execute(
            "DELETE FROM secrets WHERE id = ?1",
            [prof.interface.private_key.0.to_string()],
        )
        .unwrap();
    }
    f.manager.start_instance(inst.id).await.unwrap();
    let st = eventually_egress(&f.app, "recovery required", |st| {
        st.phase == EgressPhase::RecoveryRequired
    })
    .await;
    let rec = st.recovery.clone().unwrap();
    assert!(rec.required && rec.rebootstrap_eligible, "{rec:?}");
    assert_eq!(st.reason_code.as_deref(), Some("KEY_MISSING"));
    assert_eq!(
        st.egress.selected_instance_id,
        Some(inst.id),
        "the selection stays"
    );

    // The acknowledgement and the revision are required.
    let rev = st.egress.revision;
    let url = "/v1/provider-egress/rebootstrap";
    let (status, body) = call(&f.app, post(url, r#"{"confirm_direct":true}"#, None)).await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "{body}");
    let (status, body) = call(&f.app, post(url, r#"{"confirm_direct":false}"#, Some(rev))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(error(&body).field_errors[0].path, "/confirm_direct");
    let (status, body) = call(
        &f.app,
        post(url, r#"{"confirm_direct":true,"all":true}"#, Some(rev)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = call(
        &f.app,
        post(url, r#"{"confirm_direct":true}"#, Some(rev + 7)),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");

    // Opened: ten minutes, its own kind, the latch still set.
    let (status, body) = call(&f.app, post(url, r#"{"confirm_direct":true}"#, Some(rev))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let st: ProviderEgressStatus = serde_json::from_str(&body).unwrap();
    assert_eq!(st.phase, EgressPhase::BootstrapDirect);
    assert!(st.egress.bootstrap_consumed);
    let run = st.bootstrap.clone().unwrap();
    assert_eq!(
        (run.kind, run.stage),
        (BootstrapKind::Rebootstrap, BootstrapStage::GrantActive)
    );
    let left = st.bootstrap_expires_at.unwrap().unix_millis() - Timestamp::now().unix_millis();
    assert!((9 * 60_000..=10 * 60_000).contains(&left), "{left} ms");

    only_recovery_rides_the_grant(&f, url, &acct, st.egress.revision).await;

    // Cancelled: the grant closes, the run ends, the latch stays; the egress needs recovery again.
    let (status, body) = call(&f.app, Request::delete(url).body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let st: ProviderEgressStatus = serde_json::from_str(&body).unwrap();
    assert!(st.bootstrap_expires_at.is_none());
    assert_eq!(st.bootstrap.unwrap().stage, BootstrapStage::Cancelled);
    assert!(st.egress.bootstrap_consumed);
    assert_eq!(st.phase, EgressPhase::RecoveryRequired);
    assert!(
        vpn_controller::egress::recovery(vpn_controller::provider::route(&f.link))
            .await
            .is_err(),
        "no direct route after the cancel"
    );

    // A valid profile here: refused, and the reason says which one to use.
    let spare = profile(&f.store, "大阪備用", "203.0.113.9:51820").await;
    let st = egress(&f.app).await;
    assert!(!st.recovery.as_ref().unwrap().rebootstrap_eligible);
    let (status, body) = call(
        &f.app,
        post(url, r#"{"confirm_direct":true}"#, Some(st.egress.revision)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let refused = error(&body);
    assert_eq!(refused.code, ErrorCode::RebootstrapNotEligible);
    assert!(
        refused.message.zh_tw.contains(&spare.name),
        "{}",
        refused.message.zh_tw
    );
}

/// While a rebootstrap grant is open, only an operation that builds an egress rides it; a
/// second grant at the same time is refused.
async fn only_recovery_rides_the_grant(
    f: &Fixture,
    url: &str,
    account: &ProviderAccount,
    revision: u64,
) {
    // Its scope: an operation that builds an egress is routed over it ...
    let route = vpn_controller::egress::recovery(vpn_controller::provider::route(&f.link))
        .await
        .unwrap();
    assert_eq!(route.mode, RouteMode::BootstrapDirect);
    // ... anything else is refused before a single byte goes to a provider: revoking a device,
    // or the same route asked for outside the scope (a background job).
    let (status, body) = call(
        &f.app,
        Request::delete(format!(
            "/v1/provider-accounts/{}/devices/some-device?unowned=true",
            account.id
        ))
        .header("idempotency-key", key())
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let refused = error(&body);
    assert_eq!(refused.code, ErrorCode::ProviderEgressBlocked);
    assert!(
        refused.message.zh_tw.contains("只開放以直連建立出口"),
        "{}",
        refused.message.zh_tw
    );
    match vpn_controller::provider::route(&f.link).await {
        Err(blocked) => assert_eq!(blocked.code, ErrorCode::ProviderEgressBlocked),
        Ok(routed) => panic!("routed outside the scope: {:?}", routed.mode),
    }
    // A second one at the same time is refused.
    let (status, body) = call(
        &f.app,
        post(url, r#"{"confirm_direct":true}"#, Some(revision)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

/// The Store refuses (`on`) or takes again every commit of a seal, as a full disk or an I/O error
/// would.
fn refuse_seal_commits(paths: &Paths, on: bool) {
    let c = rusqlite::Connection::open(paths.state.join("control.sqlite")).unwrap();
    c.busy_timeout(Duration::from_secs(5)).unwrap();
    c.execute_batch(if on {
        "CREATE TRIGGER test_seal_commit_refused BEFORE UPDATE OF stage ON bootstrap_journal
         WHEN NEW.stage = 'sealed' BEGIN SELECT RAISE(ABORT, 'test: the commit failed'); END;"
    } else {
        "DROP TRIGGER test_seal_commit_refused;"
    })
    .unwrap();
}

/// A seal whose last step did not go through — its intent is on disk and direct access closed,
/// but the Store refused the commit — is committed by the promotion as soon as the Store takes
/// it (not only at the next manager start), tried again after a pause rather than every tick,
/// and never by reopening direct access.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_seal_whose_commit_failed_is_committed_by_the_promotion() {
    let f = fixture().await;
    let (status, body) = call(&f.app, post("/v1/provider-egress/bootstrap", "{}", None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let op = OperationId::new();
    let ChildClaimWire::Reserved { run } = f.manager.bootstrap_claim(op).await.unwrap() else {
        panic!("a reservation");
    };
    let p = profile(&f.store, "Mullvad · 東京", "198.51.100.7:51820").await;
    let child = spec("Mullvad · 東京", p.id);
    f.manager
        .bootstrap_create_child(run.clone(), op, child.clone(), None)
        .await
        .unwrap();
    // The seal's first two steps — its intent, then the grant closed — and a refused commit.
    f.store
        .seal_bootstrap_intent(run.clone(), child.id)
        .await
        .unwrap();
    assert!(f.manager.bootstrap().revoke().is_some());
    refuse_seal_commits(&f.paths, true);
    let mut promoter = vpn_controller::egress::Promoter::default();
    let _ = vpn_controller::egress::step(&f.providers, &f.link, &mut promoter).await;
    let s = egress(&f.app).await;
    assert_eq!(s.bootstrap.as_ref().unwrap().stage, BootstrapStage::Sealing);
    assert!(
        s.bootstrap_expires_at.is_none(),
        "no direct access meanwhile"
    );
    // The Store takes writes again; the next tick waits for the pause after the failure.
    refuse_seal_commits(&f.paths, false);
    vpn_controller::egress::step(&f.providers, &f.link, &mut promoter)
        .await
        .unwrap();
    let s = egress(&f.app).await;
    assert_eq!(s.bootstrap.as_ref().unwrap().stage, BootstrapStage::Sealing);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    vpn_controller::egress::step(&f.providers, &f.link, &mut promoter)
        .await
        .unwrap();
    let s = egress(&f.app).await;
    let sealed = s.bootstrap.clone().unwrap();
    assert_eq!(sealed.stage, BootstrapStage::Sealed, "{s:?}");
    assert!(s.egress.bootstrap_consumed);
    assert_eq!(s.egress.selected_instance_id, Some(child.id));
    assert!(s.bootstrap_expires_at.is_none());
    assert!(f.manager.bootstrap().active().is_none());
    match vpn_controller::egress::recovery(vpn_controller::provider::route(&f.link)).await {
        Ok(r) => assert_ne!(r.mode, RouteMode::BootstrapDirect),
        Err(e) => assert_eq!(e.code, ErrorCode::ProviderEgressBlocked),
    }
    // Committed: later ticks leave it as it is.
    vpn_controller::egress::step(&f.providers, &f.link, &mut promoter)
        .await
        .unwrap();
    assert_eq!(
        egress(&f.app).await.bootstrap.unwrap().stage,
        BootstrapStage::Sealed
    );
}

/// AC-71 over HTTP: the first setup's one connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_setup_builds_one_connection_and_maps_retries_to_it() {
    let f = fixture().await;
    let acct = account(&f.store).await;
    let (status, body) = call(&f.app, post("/v1/provider-egress/bootstrap", "{}", None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let st: ProviderEgressStatus = serde_json::from_str(&body).unwrap();
    assert_eq!(st.phase, EgressPhase::BootstrapDirect);
    assert_eq!(st.bootstrap.as_ref().unwrap().kind, BootstrapKind::Initial);

    let connect = |name: &str| {
        post(
            &format!("/v1/provider-accounts/{}/connections", acct.id),
            &format!(
                r#"{{"device_id":null,"server_id":"jp-tyo-wg-001","name":"{name}","endpoint_family":"ipv4","gateway_port":null,"start":true}}"#
            ),
            None,
        )
    };
    // Another request (say, another provider's) holds the run's connection while it builds it:
    // this one is refused before it sends anything to a provider.
    let other = OperationId::new();
    let ChildClaimWire::Reserved { run } = f.manager.bootstrap_claim(other).await.unwrap() else {
        panic!("a reservation");
    };
    let (status, body) = call(&f.app, connect("second")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(error(&body).code, ErrorCode::BootstrapInProgress);

    // That request built it (its profile passed the checker): one durable step, no Start.
    let prof = profile(
        &f.store,
        "Mullvad · 東京 jp-tyo-wg-001",
        "198.51.100.7:51820",
    )
    .await;
    let child = spec("Mullvad · 東京 jp-tyo-wg-001", prof.id);
    f.manager
        .bootstrap_create_child(run, other, child.clone(), None)
        .await
        .unwrap();
    let st = egress(&f.app).await;
    assert_eq!(st.phase, EgressPhase::Switching);
    assert_eq!(
        st.bootstrap.as_ref().unwrap().child_instance_id,
        Some(child.id)
    );

    // A retry (a new request, a new key) gets that connection back: nothing new is built.
    let (status, body) = call(&f.app, connect("retry")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let made: ProviderConnectResult = serde_json::from_str(&body).unwrap();
    assert!(made.reused && made.becomes_egress);
    assert_eq!((made.instance_id, made.profile_id), (child.id, prof.id));
    let all: Vec<InstanceSpec> = f.store.list().await.unwrap();
    assert_eq!(all.len(), 1);
    let profiles: Vec<RuntimeProfile> = f.store.list().await.unwrap();
    assert_eq!(profiles.len(), 1);

    // The user stops the new connection: the durable promotion is given up, with the reason, and
    // the run goes on within its grant (the user may retry with the same connection).
    f.manager.stop_instance(child.id, false).await.unwrap();
    let mut promoter = vpn_controller::egress::Promoter::default();
    vpn_controller::egress::step(&f.providers, &f.link, &mut promoter)
        .await
        .unwrap();
    let st = egress(&f.app).await;
    assert_eq!(st.phase, EgressPhase::BootstrapDirect);
    assert_eq!(st.reason_code.as_deref(), Some("CHILD_STOPPED"));
    assert!(st.reason.unwrap().zh_tw.contains("停止"));
    let run = st.bootstrap.unwrap();
    assert_eq!(run.stage, BootstrapStage::GrantActive);
    assert_eq!(run.child_instance_id, Some(child.id));
    assert!(!st.egress.bootstrap_consumed, "nothing was sealed");
}
