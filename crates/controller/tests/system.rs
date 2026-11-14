//! The system API against a real manager: the diagnostics report carries no secret,
//! destination, account or name; recovery is inspected and reconciled; a manager that is
//! stopping serves nothing and says so.

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
use serde_json::Value;
use tower::ServiceExt;
use vpn_controller::hub::Hub;
use vpn_controller::link::ManagerLink;
use vpn_controller::routes::{AppState, api};
use vpn_domain::*;
use vpn_instance_manager::Manager;
use vpn_instance_manager::rpc::{SystemFacts, serve};
use vpn_instance_manager::ssh::SshProjector;
use vpn_platform::paths::Paths;
use vpn_store::Store;
use zeroize::Zeroizing;

const SECRET: &str = "SYNTHETIC-SECRET-PLAINTEXT-7f3a";
const ACCOUNT: &str = "1234567812345678";
const ENDPOINT: &str = "198.51.100.77";
const SSH_HOST: &str = "secret-host.example";
const SSH_ALIAS: &str = "secret-alias";
const INSTANCE_NAME: &str = "東京秘密出口";
const LABEL: &str = "acct-label-zq";

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
    manager: Arc<Manager>,
    app: axum::Router,
}

/// The profile, Instance, SSH host and provider account, with their recognisable secrets.
async fn seed(store: &Store) {
    let key = store
        .put_secret(
            "wireguard_private_key".into(),
            None,
            Zeroizing::new(SECRET.as_bytes().to_vec()),
            None,
        )
        .await
        .unwrap();
    let profile = store
        .create(RuntimeProfile {
            id: ProfileId::new(),
            meta: meta(),
            name: "lab".into(),
            provider: ProviderKind::Generic,
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
                endpoint: format!("{ENDPOINT}:51820").parse().unwrap(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                persistent_keepalive: None,
            },
            location: None,
            expires_at: None,
        })
        .await
        .unwrap();
    store
        .create_instance(InstanceSpec {
            id: InstanceId::new(),
            meta: meta(),
            name: INSTANCE_NAME.into(),
            profile_id: profile.id,
            dns_profile_id: None,
            security_profile_id: None,
            purpose: InstancePurpose::General,
            limits: InstanceLimits::default(),
            strict: false,
            transport: vpn_domain::TransportRef::default(),
        })
        .await
        .unwrap();
    store
        .create(SshHost {
            id: SshHostId::new(),
            meta: meta(),
            kind: SshHostKind::Host,
            alias: SSH_ALIAS.into(),
            host_name: Some(SSH_HOST.into()),
            user: None,
            port: None,
            identity_file: None,
            identities_only: false,
            gateway_id: None,
            server_alive_interval: None,
        })
        .await
        .unwrap();
    let credential = store
        .put_secret(
            "provider_credential".into(),
            None,
            Zeroizing::new(ACCOUNT.as_bytes().to_vec()),
            None,
        )
        .await
        .unwrap();
    store
        .create(ProviderAccount {
            id: ProviderAccountId::new(),
            meta: meta(),
            provider: ProviderKind::Mullvad,
            label: LABEL.into(),
            credential_ref: credential.secret_ref,
            expires_at: None,
            observed_at: None,
        })
        .await
        .unwrap();
}

/// A manager with a profile, an Instance, an SSH host and a provider account carrying
/// recognisable secrets and destinations; a router connected to it.
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::under(&dir.path().join("state"));
    paths.ensure().unwrap();
    let ssh_dir = dir.path().join("ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    // As `vpnd manager` does: the vault key is the file beside the data.
    let master = vpn_platform::keystore::load_or_create_key_file(&paths.vault_key()).unwrap();
    let store = Arc::new(Store::open(&paths.state, &master, 1).unwrap());
    seed(&store).await;

    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();
    let ssh = Arc::new(SshProjector::new(
        ssh_dir,
        Some(dir.path()),
        &dir.path().join("vpnctl"),
        &paths.gateway_key(),
        &paths.state,
    ));
    let sock = paths.manager_socket();
    tokio::spawn(serve(
        tokio::net::UnixListener::bind(&sock).unwrap(),
        manager.clone(),
        store,
        SystemFacts {
            capabilities: vec![],
            ssh: Some(ssh),
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
    let app = api(AppState {
        link,
        hub,
        port: 18765,
        exposure: Arc::default(),
        data_dir: None,
        gateway_key: None,
        providers: vpn_controller::provider::Providers::new(),
    });
    Fixture {
        _dir: dir,
        paths,
        manager,
        app,
    }
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

fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

fn post(uri: &str, key: &str, body: &str) -> Request<Body> {
    Request::post(uri)
        .header("content-type", "application/json")
        .header("idempotency-key", key)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn key() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diagnostics_report_the_system_without_secrets_destinations_or_names() {
    let f = fixture().await;
    let (status, body) = call(&f.app, get("/v1/system/diagnostics")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for leak in [
        SECRET,
        ACCOUNT,
        ENDPOINT,
        SSH_HOST,
        SSH_ALIAS,
        INSTANCE_NAME,
        LABEL,
    ] {
        assert!(!body.contains(leak), "the report contains {leak}: {body}");
    }
    let r: DiagnosticReport = serde_json::from_str(&body).unwrap();
    assert!(r.redacted);
    assert_eq!(r.components.gotatun, "0.10.3");
    let m = r.manager.as_ref().expect("manager part");
    assert_eq!(m.databases.len(), 2);
    assert!(m.databases.iter().all(|d| d.quick_check_ok == Some(true)));
    assert!(
        m.databases
            .iter()
            .all(|d| d.schema_version == Some(d.supported_version))
    );
    assert_eq!(m.vault_key.state, VaultKeyState::Matches);
    assert!(
        m.process
            .binary
            .sha256
            .as_deref()
            .is_some_and(|s| s.len() == 64)
    );
    assert!(m.process.started_at.is_some() && m.process.uptime_secs.is_some());
    let ssh = m.ssh.as_ref().expect("ssh projection");
    assert_eq!(ssh.hosts, Some(1));
    for id in [
        "manager",
        "control_integrity",
        "metrics_integrity",
        "vault_key",
    ] {
        let c = r.checks.iter().find(|c| c.id == id).unwrap();
        assert_eq!(c.status, CheckStatus::Ok, "{c:?}");
    }
    assert!(m.recovery_gaps.is_empty(), "{:?}", m.recovery_gaps);

    // A place the recovery inspection cannot look at: unknown, never "nothing left behind".
    {
        use std::os::unix::fs::PermissionsExt;
        let locks = f.paths.locks();
        std::fs::create_dir_all(&locks).unwrap();
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o000)).unwrap();
        let (_, body) = call(&f.app, get("/v1/system/diagnostics")).await;
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700)).unwrap();
        let r: DiagnosticReport = serde_json::from_str(&body).unwrap();
        let recovery = r.checks.iter().find(|c| c.id == "recovery").unwrap();
        assert_eq!(recovery.status, CheckStatus::Unknown, "{recovery:?}");
        assert!(
            recovery.message.zh_tw.contains("金鑰鎖目錄"),
            "{recovery:?}"
        );
        assert_ne!(r.manager.unwrap().recovery_gaps, []);
    }

    // vault.key replaced on disk: the report says the next start would be refused.
    std::fs::remove_file(f.paths.vault_key()).unwrap();
    vpn_platform::keystore::load_or_create_key_file(&f.paths.vault_key()).unwrap();
    let (_, body) = call(&f.app, get("/v1/system/diagnostics")).await;
    let r: DiagnosticReport = serde_json::from_str(&body).unwrap();
    assert_eq!(r.manager.unwrap().vault_key.state, VaultKeyState::Mismatch);
    assert!(
        r.checks
            .iter()
            .any(|c| c.id == "vault_key" && c.status == CheckStatus::Failed)
    );
    f.manager.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopping_manager_serves_nothing_and_an_emergency_stop_says_it_was_not_latched() {
    let f = fixture().await;
    let (_, body) = call(&f.app, get("/v1/instances")).await;
    let instance = serde_json::from_str::<Vec<InstanceView>>(&body).unwrap()[0]
        .spec
        .id;
    f.manager.shutdown().await;
    assert!(f.manager.is_closing());
    let (status, _) = call(&f.app, get("/v1/recovery")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    // An emergency stop pressed now is refused, and says that nothing was latched or recorded.
    let (status, body) = call(
        &f.app,
        post(
            &format!("/v1/instances/{instance}/emergency-stop"),
            &key(),
            "{}",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let refusal: ApiError = serde_json::from_str(&body).unwrap();
    assert!(refusal.message.zh_tw.contains("急停沒有記錄"), "{body}");
    assert!(refusal.retryable, "{body}");
    assert!(!body.contains("sealed"), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_is_inspected_and_reconciled_through_the_api() {
    let f = fixture().await;
    let stale = f.paths.run.join("c-0badf00d-9.sock");
    drop(tokio::net::UnixListener::bind(&stale).unwrap());
    let (status, body) = call(&f.app, get("/v1/recovery")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let report: RecoveryReport = serde_json::from_str(&body).unwrap();
    let item = report
        .items
        .iter()
        .find(|i| i.kind == RecoveryKind::StaleSocket)
        .unwrap();
    assert!(item.cleanable);
    assert!(stale.exists(), "inspecting changes nothing");

    // Bad ids are refused before anything happens.
    let (status, _) = call(
        &f.app,
        post("/v1/recovery/reconcile", &key(), r#"{"items":["../../x"]}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = call(
        &f.app,
        post(
            "/v1/recovery/reconcile",
            &key(),
            &format!(r#"{{"items":["{}"]}}"#, item.id),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let result: ReconcileResult = serde_json::from_str(&body).unwrap();
    assert!(result.operation_id.is_some());
    assert!(
        result
            .actions
            .iter()
            .any(|a| a.item_id == item.id && a.outcome == ReconcileOutcome::Done)
    );
    assert!(!stale.exists());
    let value: Value = serde_json::from_str(&body).unwrap();
    assert!(value["remaining"].as_array().unwrap().is_empty(), "{body}");
    f.manager.shutdown().await;
}
