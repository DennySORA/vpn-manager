//! The SSH download API (`/v1/ssh-downloads*`) against a real manager: the conventions of the
//! other entities (Idempotency-Key, If-Match and `ETags`, field errors, one operation per key), the
//! manager's checks against the host (a Gateway that speaks SOCKS5, the local folder), secrets
//! that go into the vault and never come back, and a job that waits — connecting nowhere — while
//! its connection is stopped. Nothing reaches a network: the only Instance never runs.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures: clippy.toml allows unwrap in tests, but not in helper fns of a tests/ crate"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
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
use vpn_platform::paths::Paths;
use vpn_store::Store;

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
    dir: tempfile::TempDir,
    store: Arc<Store>,
    app: axum::Router,
    socks: GatewayId,
    http: GatewayId,
}

async fn gateway(store: &Store, instance: InstanceId, kind: GatewayKind, port: u16) -> GatewayId {
    store
        .create(GatewaySpec {
            id: GatewayId::new(),
            meta: meta(),
            instance_id: instance,
            name: format!("埠 {port}"),
            kind,
            port,
            enabled: true,
            udp: false,
            max_connections: 64,
        })
        .await
        .unwrap()
        .id
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let paths = Paths::under(&dir.path().join("state"));
    paths.ensure().unwrap();
    let master = vpn_platform::keystore::load_or_create_key_file(&paths.vault_key()).unwrap();
    let store = Arc::new(Store::open(&paths.state, &master, 1).unwrap());
    let key: WgKey = "aGVsbG8gd29ybGQgdGhpcyBpcyAzMiBieXRlcyEhISE="
        .parse()
        .unwrap();
    let profile = store
        .create(RuntimeProfile {
            id: ProfileId::new(),
            meta: meta(),
            name: "p".into(),
            provider: ProviderKind::Generic,
            source: ProfileSource::Imported,
            interface: InterfaceSpec {
                private_key: SecretRef(SecretId::new()),
                public_key: key,
                addresses: vec!["10.0.0.2/32".parse().unwrap()],
                dns: vec![],
                mtu: 1420,
            },
            peer: PeerSpec {
                public_key: key,
                preshared_key: None,
                endpoint: "203.0.113.1:51820".parse().unwrap(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                persistent_keepalive: None,
            },
            location: None,
            expires_at: None,
        })
        .await
        .unwrap();
    let instance = store
        .create_instance(InstanceSpec {
            id: InstanceId::new(),
            meta: meta(),
            name: "東京".into(),
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
    let socks = gateway(&store, instance.id, GatewayKind::Socks5, 42_180).await;
    let http = gateway(&store, instance.id, GatewayKind::Http, 42_181).await;
    let manager = Manager::start(store.clone(), not_a_worker(), paths.clone())
        .await
        .unwrap();
    let sock = paths.manager_socket();
    tokio::spawn(serve(
        tokio::net::UnixListener::bind(&sock).unwrap(),
        manager,
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
    let app = api(AppState {
        link,
        hub,
        port: 18765,
        data_dir: None,
        gateway_key: None,
        providers: Providers::new(),
        exposure: Arc::default(),
    });
    Fixture {
        dir,
        store,
        app,
        socks,
        http,
    }
}

struct Answer {
    status: StatusCode,
    etag: Option<String>,
    body: String,
}

impl Answer {
    fn json<T: serde::de::DeserializeOwned>(&self) -> T {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{e}: {}", self.body))
    }
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<&str>,
    key: Option<&str>,
    if_match: Option<u64>,
) -> Answer {
    let mut r = Request::builder().method(method).uri(uri);
    if body.is_some() {
        r = r.header("content-type", "application/json");
    }
    if let Some(k) = key {
        r = r.header("idempotency-key", k);
    }
    if let Some(rev) = if_match {
        r = r.header("if-match", format!("\"{rev}\""));
    }
    let req = r
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_owned())))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    Answer {
        status,
        etag,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn key() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn input(f: &Fixture, gateway: GatewayId, extra: &serde_json::Value) -> String {
    let mut v = serde_json::json!({
        "name": "NAS 下載",
        "gateway_id": gateway,
        "host": "files.example.net",
        "user": "puller",
        "password": "s3cret-pass",
        "source_dir": "/srv/drop/todo",
        "local_dir": f.dir.path().join("incoming").display().to_string(),
    });
    if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        for (k, x) in e {
            o.insert(k.clone(), x.clone());
        }
    }
    v.to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jobs_follow_the_api_conventions_and_keep_their_secrets() {
    let f = fixture().await;
    let base = "/v1/ssh-downloads";

    let body = input(&f, f.socks, &serde_json::json!({}));
    let open = bad_requests_are_refused_by_field(&f, base, &body).await;
    let (id, secret) = a_job_is_created_once(&f, base, &body).await;
    let one = format!("{base}/{id}");
    a_job_waits_for_its_vpn(&f, &one).await;
    updates_need_the_revision(&f, &one, secret).await;
    actions_are_operations(&f, &one).await;
    records_log_and_folder_check(&f, base, &one, &open).await;

    // The Gateway it uses cannot be deleted under it.
    let a = send(
        &f.app,
        "DELETE",
        &format!("/v1/gateways/{}", f.socks),
        None,
        Some(&key()),
        Some(1),
    )
    .await;
    assert_eq!(a.status, StatusCode::CONFLICT, "{}", a.body);
    assert!(a.body.contains("SSH 下載"), "{}", a.body);

    // Deleted with its secret.
    let a = send(&f.app, "DELETE", &one, None, Some(&key()), Some(2)).await;
    assert_eq!(a.status, StatusCode::NO_CONTENT, "{}", a.body);
    assert_eq!(
        send(&f.app, "GET", &one, None, None, None).await.status,
        StatusCode::NOT_FOUND
    );
    assert!(
        f.store.open_secret(secret).await.is_err(),
        "the secret went with the job"
    );
}

/// The refusals before anything is created; returns a local folder others can write.
async fn bad_requests_are_refused_by_field(f: &Fixture, base: &str, body: &str) -> PathBuf {
    // A change needs its Idempotency-Key; bad fields come back named.
    let a = send(&f.app, "POST", base, Some(body), None, None).await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
    assert_eq!(a.json::<ApiError>().code, ErrorCode::IdempotencyKeyRequired);
    let bad = input(
        f,
        f.socks,
        &serde_json::json!({ "host": "localhost", "connections": 99 }),
    );
    let e: ApiError = send(&f.app, "POST", base, Some(&bad), Some(&key()), None)
        .await
        .json();
    let paths: Vec<&str> = e.field_errors.iter().map(|x| x.path.as_str()).collect();
    assert_eq!(paths, ["/host", "/connections"], "{e:?}");
    // The manager's checks: an HTTP-only Gateway cannot carry SSH.
    let http = input(f, f.http, &serde_json::json!({}));
    let e: ApiError = send(&f.app, "POST", base, Some(&http), Some(&key()), None)
        .await
        .json();
    assert_eq!(e.field_errors[0].path, "/gateway_id", "{e:?}");
    assert_eq!(e.field_errors[0].code, "GATEWAY_NOT_SOCKS");
    // A local folder others can write is refused.
    let open = f.dir.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    let loose = input(
        f,
        f.socks,
        &serde_json::json!({ "local_dir": open.display().to_string() }),
    );
    let e: ApiError = send(&f.app, "POST", base, Some(&loose), Some(&key()), None)
        .await
        .json();
    assert_eq!(e.field_errors[0].path, "/local_dir", "{e:?}");
    open
}

/// Created once for one Idempotency-Key; returns the job and its password's vault reference.
async fn a_job_is_created_once(
    f: &Fixture,
    base: &str,
    body: &str,
) -> (SshDownloadJobId, SecretRef) {
    // Created: 201 with its revision, the sibling folders as defaults, the password a reference.
    let k = key();
    let a = send(&f.app, "POST", base, Some(body), Some(&k), None).await;
    assert_eq!(a.status, StatusCode::CREATED, "{}", a.body);
    assert_eq!(a.etag.as_deref(), Some("\"1\""));
    assert!(
        !a.body.contains("s3cret-pass"),
        "the password came back: {}",
        a.body
    );
    let v: SshDownloadView = a.json();
    assert_eq!(v.job.work_dir, "/srv/drop/doing");
    assert_eq!(v.job.failed_dir, "/srv/drop/failed");
    assert_eq!((v.job.port, v.job.connections, v.job.retries), (22, 3, 3));
    let secret = v.job.password.expect("a vault reference");
    assert_eq!(
        &**f.store.open_secret(secret).await.unwrap(),
        b"s3cret-pass",
        "the vault holds it"
    );
    assert!(
        f.dir.path().join("incoming").is_dir(),
        "the local folder was created"
    );
    let id = v.job.id;
    // The same request again: the same job, nothing created twice.
    let again: SshDownloadView = send(&f.app, "POST", base, Some(body), Some(&k), None)
        .await
        .json();
    assert_eq!(again.job.id, id);
    let all: Vec<SshDownloadView> = send(&f.app, "GET", base, None, None, None).await.json();
    assert_eq!(all.len(), 1);
    (id, secret)
}

/// While its connection is stopped the job at `one` waits and says why.
async fn a_job_waits_for_its_vpn(f: &Fixture, one: &str) {
    // Its connection is stopped: it waits, and says why.
    let mut waited = None;
    for _ in 0..100 {
        let v: SshDownloadView = send(&f.app, "GET", one, None, None, None).await.json();
        if let Some(s) = v.status.filter(|s| s.state == SshDownloadState::WaitingVpn) {
            waited = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let s = waited.expect("waiting for the VPN");
    assert_eq!(s.reason_code.as_deref(), Some("VPN_NOT_READY"));
    assert!(s.reason.unwrap().zh_tw.contains("東京"));
}

/// Updates of the job at `one` need its revision; `secret` is its password's reference.
async fn updates_need_the_revision(f: &Fixture, one: &str, secret: SecretRef) {
    // An update needs the revision; the password left out stays.
    let renamed = input(
        f,
        f.socks,
        &serde_json::json!({ "name": "改名", "password": null }),
    );
    let a = send(&f.app, "PUT", one, Some(&renamed), Some(&key()), None).await;
    assert_eq!(a.status, StatusCode::PRECONDITION_REQUIRED, "{}", a.body);
    let a = send(&f.app, "PUT", one, Some(&renamed), Some(&key()), Some(1)).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(a.etag.as_deref(), Some("\"2\""));
    let v: SshDownloadView = a.json();
    assert_eq!(
        (v.job.name.as_str(), v.job.password),
        ("改名", Some(secret))
    );
    let a = send(&f.app, "PUT", one, Some(&renamed), Some(&key()), Some(1)).await;
    assert_eq!(a.status, StatusCode::PRECONDITION_FAILED, "{}", a.body);
    // Setting and clearing at once is refused; clearing removes the secret.
    let both = input(f, f.socks, &serde_json::json!({ "clear_password": true }));
    let e: ApiError = send(&f.app, "PUT", one, Some(&both), Some(&key()), Some(2))
        .await
        .json();
    assert_eq!(e.field_errors[0].path, "/password", "{e:?}");
    let none = input(
        f,
        f.socks,
        &serde_json::json!({ "password": null, "clear_password": true }),
    );
    let e: ApiError = send(&f.app, "PUT", one, Some(&none), Some(&key()), Some(2))
        .await
        .json();
    assert_eq!(e.field_errors[0].code, "SSH_DL_AUTH_REQUIRED", "{e:?}");
}

/// Pause, resume and a listing of the job at `one`, each one operation.
async fn actions_are_operations(f: &Fixture, one: &str) {
    // Actions: pause, resume, a listing now; each one operation.
    let act = format!("{one}/actions");
    let r: SshDownloadActionResult = send(
        &f.app,
        "POST",
        &act,
        Some(r#"{"action":"pause"}"#),
        Some(&key()),
        None,
    )
    .await
    .json();
    assert_eq!(r.status.unwrap().state, SshDownloadState::Paused);
    assert_eq!(r.operation.kind, "ssh_download.pause");
    let a = send(
        &f.app,
        "POST",
        &act,
        Some(r#"{"action":"scan"}"#),
        Some(&key()),
        None,
    )
    .await;
    assert_eq!(
        a.status,
        StatusCode::CONFLICT,
        "a paused job does not list: {}",
        a.body
    );
    let r: SshDownloadActionResult = send(
        &f.app,
        "POST",
        &act,
        Some(r#"{"action":"resume"}"#),
        Some(&key()),
        None,
    )
    .await
    .json();
    assert_ne!(r.status.unwrap().state, SshDownloadState::Paused);
    let e: ApiError = send(
        &f.app,
        "POST",
        &act,
        Some(r#"{"action":"trust_host_key"}"#),
        Some(&key()),
        None,
    )
    .await
    .json();
    assert_eq!(e.field_errors[0].path, "/fingerprint", "{e:?}");
}

/// The job's records and log, and the folder check.
async fn records_log_and_folder_check(f: &Fixture, base: &str, one: &str, open: &Path) {
    // Records and log.
    let transfers: SshDownloadTransfers =
        send(&f.app, "GET", &format!("{one}/transfers"), None, None, None)
            .await
            .json();
    assert!(transfers.items.is_empty() && transfers.next.is_none());
    let listed = send(
        &f.app,
        "GET",
        &format!("{one}/transfers?state=all"),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(listed.status, StatusCode::BAD_REQUEST);
    let log: SshDownloadLog = send(
        &f.app,
        "GET",
        &format!("{one}/log?limit=10"),
        None,
        None,
        None,
    )
    .await
    .json();
    let codes: Vec<&str> = log.items.iter().map(|x| x.code.as_str()).collect();
    assert!(
        codes.contains(&"CREATED") && codes.contains(&"PAUSED"),
        "{codes:?}"
    );
    assert!(!serde_json::to_string(&log).unwrap().contains("s3cret"));

    // The folder check.
    let check: SshDownloadDirCheck = send(
        &f.app,
        "GET",
        &format!(
            "{base}/dir-check?path={}",
            f.dir.path().join("new/inner").display()
        ),
        None,
        None,
        None,
    )
    .await
    .json();
    assert!(check.would_create && check.problem.is_none(), "{check:?}");
    let check: SshDownloadDirCheck = send(
        &f.app,
        "GET",
        &format!("{base}/dir-check?path={}", open.display()),
        None,
        None,
        None,
    )
    .await
    .json();
    assert!(check.problem.is_some(), "{check:?}");
}
