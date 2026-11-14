//! The `vpnctl` binary against a stand-in controller on `api.sock`: exit codes, output, and the
//! follow-up of a change whose answer was lost (looked up by its Idempotency-Key, never sent
//! twice).

#![cfg(test)]
#![expect(
    unsafe_code,
    reason = "libc pty, termios and write FFI for the hidden-prompt test"
)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Arc, Mutex};

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use vpn_domain::*;

/// What the stand-in does with a lifecycle request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lost {
    /// The connection drops before an answer; the operation is recorded as succeeded.
    ThenSucceeded,
    /// The connection drops; nothing is recorded under the key.
    ThenNothing,
}

#[derive(Default)]
struct Seen {
    /// Lifecycle requests received, by Idempotency-Key.
    keys: Vec<String>,
}

fn meta() -> EntityMeta {
    EntityMeta {
        revision: 1,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
}

fn view(name: &str) -> InstanceView {
    InstanceView {
        spec: InstanceSpec {
            id: InstanceId::new(),
            meta: meta(),
            name: name.into(),
            profile_id: ProfileId::new(),
            dns_profile_id: None,
            security_profile_id: None,
            purpose: InstancePurpose::General,
            limits: InstanceLimits::default(),
            strict: false,
            transport: TransportRef::default(),
        },
        profile: None,
        gateways: vec![],
        status: None,
    }
}

/// A stopped connection as the manager reports it after a stop: `enforcement` says whether the
/// data path is closed.
fn stopped_view(name: &str, enforcement: Enforcement) -> InstanceView {
    let mut v = view(name);
    v.status = Some(InstanceStatus {
        instance_id: v.spec.id,
        spec_revision: 1,
        intent: InstanceIntent {
            desired: DesiredState::Stopped,
            manual_stop: true,
            emergency_latched: false,
            intent_revision: 2,
            persistence: Persistence::Durable,
        },
        phase: Phase::Stopped,
        enforcement,
        health: Health::Unknown,
        running: None,
        tunnel: None,
        dns: None,
        gateways: vec![],
        recovery: RecoveryStatus {
            attempt: 0,
            next_retry_at: None,
            last_fault: None,
            unreachable_attempts: 0,
        },
        observed_at: Timestamp::now(),
        sandbox: None,
    });
    v
}

fn ssh_status(file: SshFileState) -> SshStatus {
    SshStatus {
        available: true,
        unavailable_reason: None,
        ssh_dir: "~/.ssh".into(),
        managed_path: "~/.ssh/vpn-manager.conf".into(),
        include_line: "Include vpn-manager.conf".into(),
        include: SshIncludeState::Present,
        config_linked: false,
        config_problem: None,
        file,
        pending: file == SshFileState::Modified,
        existing: vec![],
        preview: String::new(),
        proxy_command: None,
        control_path: None,
        current_text: None,
        last_error: None,
    }
}

fn json(status: StatusCode, v: &impl serde::Serialize) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(v).unwrap())))
        .unwrap()
}

fn account() -> ProviderAccount {
    ProviderAccount {
        id: ProviderAccountId::new(),
        meta: meta(),
        provider: ProviderKind::Mullvad,
        label: "家裡的帳號".into(),
        credential_ref: SecretRef(SecretId::new()),
        expires_at: Timestamp::from_unix_millis(1_830_000_000_000),
        observed_at: None,
    }
}

fn airvpn_account() -> ProviderAccount {
    ProviderAccount {
        provider: ProviderKind::Airvpn,
        label: "AirVPN 帳號".into(),
        ..account()
    }
}

fn forwarded_port(port: u16) -> ForwardedPort {
    ForwardedPort {
        port,
        pool: 2,
        enabled: true,
        protocol: ForwardProtocol::Both,
        ip_layer: "both".into(),
        device_id: None,
        device_name: None,
        local_port: port,
        dns_name: None,
        notes: None,
    }
}

/// The account's one device, as `AirVPN` names it.
const DEVICE: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a697887";

/// One session of a port test.
fn tested(
    protocol: ForwardProtocol,
    ip_layer: IpFamily,
    server_ip: &str,
    state: PortTestState,
    word: Option<&str>,
    message: &str,
) -> ForwardedPortSession {
    ForwardedPortSession {
        protocol,
        ip_layer,
        server_name: Some("Alchiba".into()),
        server_location: Some("Amsterdam".into()),
        server_country: Some("nl".into()),
        server_ip: server_ip.into(),
        port: 40000,
        client_ip: Some(match ip_layer {
            IpFamily::Ipv4 => "10.128.0.2".into(),
            IpFamily::Ipv6 => "fd7d:76ee:e68f:a993::2".into(),
        }),
        local_port: 40000,
        device_name: Some("Default".into()),
        state,
        word: word.map(str::to_owned),
        message: Some(message.into()),
    }
}

/// `AirVPN`'s forwarded ports as the controller answers them: the list, a reservation (201 with
/// the port; `AirVPN`'s pick is 37587), a delete (204), a settings change (the port as read back;
/// `AirVPN` refuses the DDNS name of 40001), a test (sessions on 40000 only), the DDNS check and
/// the search for free ports. Every request but a read is recorded.
async fn forwarded_ports(s: &StandIn, req: Request<Incoming>) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or_default().to_owned();
    let method = req.method().clone();
    let key = req
        .headers()
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let account = s.accounts.iter().find(|a| path.contains(&a.id.to_string()));
    let Some(account) = account.filter(|a| a.provider == ProviderKind::Airvpn) else {
        return json(
            StatusCode::UNPROCESSABLE_ENTITY,
            &ApiError::new(ErrorCode::UnsupportedCapability, "不支援"),
        );
    };
    let tail = path
        .split_once("/forwarded-ports")
        .map_or("", |(_, t)| t)
        .to_owned();
    let now = Timestamp::now();
    if method == hyper::Method::GET {
        return match tail.as_str() {
            "/ddns" => json(
                StatusCode::OK,
                &ForwardedPortDdns {
                    names: vec![ForwardedPortDdnsName {
                        name: "my-box".into(),
                        sessions: 1,
                        ipv4: Some("198.51.100.20".into()),
                        ipv6: None,
                    }],
                    observed_at: now,
                },
            ),
            "/free" => {
                s.port_calls.lock().unwrap().push((
                    "GET".into(),
                    format!("{path}?{query}"),
                    key,
                    String::new(),
                ));
                json(
                    StatusCode::OK,
                    &ForwardedPortSearch {
                        count: 3,
                        message: "Ports 41000-41002 are free right now.".into(),
                        observed_at: now,
                    },
                )
            }
            _ => port_list(account, now),
        };
    }
    s.port_calls.lock().unwrap().push((
        method.to_string(),
        path,
        key,
        String::from_utf8_lossy(&body).into_owned(),
    ));
    let port: u16 = tail
        .trim_start_matches('/')
        .split('/')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or_default();
    if method == hyper::Method::POST && tail.ends_with("/test") {
        let sessions = port_test_sessions(port);
        return json(
            StatusCode::OK,
            &ForwardedPortTest {
                port,
                sessions,
                observed_at: now,
            },
        );
    }
    if method == hyper::Method::PATCH {
        return port_edit(port, &body);
    }
    if method == hyper::Method::POST {
        let input: ForwardedPortInput = serde_json::from_slice(&body).unwrap();
        return json(
            StatusCode::CREATED,
            &forwarded_port(input.port.unwrap_or(37587)),
        );
    }
    no_content()
}

/// The forwarded-ports list the stand-in answers: 35786, and 40000 with every setting changed.
fn port_list(account: &ProviderAccount, now: Timestamp) -> Response<Full<Bytes>> {
    let mut limited = forwarded_port(40000);
    limited.local_port = 41000;
    limited.device_id = Some(DEVICE.into());
    limited.device_name = Some("Default".into());
    limited.protocol = ForwardProtocol::Tcp;
    limited.enabled = false;
    json(
        StatusCode::OK,
        &ForwardedPorts {
            account_id: account.id,
            ports: vec![forwarded_port(35786), limited],
            devices: vec![ForwardedPortDevice {
                id: DEVICE.into(),
                name: "Default".into(),
            }],
            limit: 5,
            min_port: 2049,
            observed_at: now,
        },
    )
}

/// The sessions a test of `port` reports: three on 40000, none elsewhere.
fn port_test_sessions(port: u16) -> Vec<ForwardedPortSession> {
    if port == 40000 {
        vec![
            tested(
                ForwardProtocol::Tcp,
                IpFamily::Ipv4,
                "198.51.100.20",
                PortTestState::Open,
                Some("ok"),
                "Port is open.",
            ),
            tested(
                ForwardProtocol::Udp,
                IpFamily::Ipv4,
                "198.51.100.20",
                PortTestState::NotTested,
                None,
                "AirVPN 只測試 TCP，這是 UDP 的連線",
            ),
            tested(
                ForwardProtocol::Tcp,
                IpFamily::Ipv6,
                "2001:db8::20",
                PortTestState::Unknown,
                Some("info"),
                "Test queued.",
            ),
        ]
    } else {
        vec![]
    }
}

/// A settings change of `port`: the port as read back; `AirVPN` refuses the DDNS name of 40001.
fn port_edit(port: u16, body: &[u8]) -> Response<Full<Bytes>> {
    if port == 40001 {
        let message = "AirVPN：This DDNS name is already in use.";
        return json(
            StatusCode::BAD_GATEWAY,
            &ApiError::new(
                ErrorCode::ProviderRejected,
                format!("AirVPN 沒有儲存：DDNS 名稱（{message}）"),
            )
            .with_fields(vec![FieldError {
                path: "/dns_name".into(),
                code: "NOT_SAVED".into(),
                message: message.into(),
            }]),
        );
    }
    let u: ForwardedPortUpdate = serde_json::from_slice(body).unwrap();
    let mut p = forwarded_port(port);
    p.notes = u.notes.filter(|n| !n.is_empty());
    p.enabled = u.enabled.unwrap_or(p.enabled);
    if let Some(d) = u.device.filter(|d| d != "all") {
        p.device_id = Some(d);
        p.device_name = Some("Default".into());
    }
    p.protocol = u.protocol.unwrap_or(p.protocol);
    p.ip_layer = u.ip_layer.map_or(p.ip_layer, |l| l.as_str().into());
    p.local_port = u.local_port.unwrap_or(p.local_port);
    p.dns_name = u.dns_name.filter(|n| !n.is_empty());
    json(StatusCode::OK, &p)
}

fn diagnostics(checks: Vec<DiagnosticCheck>) -> DiagnosticReport {
    let process = ProcessReport {
        role: "controller".into(),
        pid: 1,
        version: "0.1.0".into(),
        build_id: "0.1.0+test".into(),
        git_rev: "test".into(),
        binary: BinaryDigest {
            path: "/x/vpnd".into(),
            sha256: Some("0".repeat(64)),
            size_bytes: Some(1),
            error: None,
        },
        started_at: None,
        uptime_secs: None,
        rss_bytes: None,
        cpu_ms: 0,
    };
    DiagnosticReport {
        schema_version: DIAGNOSTICS_SCHEMA,
        redacted: true,
        generated_at: Timestamp::now(),
        os: "macos".into(),
        arch: "aarch64".into(),
        components: ComponentVersions {
            gotatun: "0.10.3".into(),
            smoltcp: "0.14.0".into(),
            sqlite: None,
        },
        checks,
        controller: process,
        manager: None,
        manager_error: Some("測試".into()),
        capabilities: vec![],
        capabilities_error: None,
    }
}

struct StandIn {
    views: Vec<InstanceView>,
    apps: Vec<AppView>,
    accounts: Vec<ProviderAccount>,
    lost: Lost,
    seen: Mutex<Seen>,
    ops: Mutex<HashMap<String, Operation>>,
    blocklists: Vec<BlocklistView>,
    bans: Vec<Ban>,
    /// DELETE requests received: path and If-Match.
    deletes: Mutex<Vec<(String, Option<String>)>>,
    /// The checks the diagnostics report carries.
    checks: Mutex<Vec<DiagnosticCheck>>,
    /// What `GET /v1/provider-egress` answers.
    egress: Mutex<Option<ProviderEgressStatus>>,
    /// Changes of the Provider egress received.
    egress_calls: Mutex<Vec<EgressCall>>,
    /// Bodies of `POST /v1/provider-accounts` (what the controller would verify and keep).
    created: Mutex<Vec<serde_json::Value>>,
    /// Changes of forwarded ports received: method, path, Idempotency-Key and body.
    port_calls: Mutex<Vec<EgressCall>>,
    /// What `GET /v1/forward-bindings` answers.
    forwards: Vec<ForwardView>,
    /// Saves of a forward received: path, If-Match and body.
    forward_puts: Mutex<Vec<(String, Option<String>, serde_json::Value)>>,
}

/// One change of the Provider egress the stand-in received: method, path, If-Match and body.
type EgressCall = (String, String, Option<String>, String);

/// What `GET /v1/recovery` answers: one stale socket that can be cleaned, and a directory the
/// inspection could not read.
fn recovery_report() -> RecoveryReport {
    RecoveryReport {
        observed_at: Timestamp::now(),
        items: vec![RecoveryItem {
            id: "0123456789abcdef".into(),
            kind: RecoveryKind::StaleSocket,
            title: "遺留的 connector socket".into(),
            detail: "沒有任何程序在接聽".into(),
            path: Some("/run/c-1.sock".into()),
            pid: None,
            instance_id: None,
            cleanable: true,
            action: Some("刪除 socket 檔".into()),
        }],
        resources: OwnedResources::default(),
        gaps: vec![ScanGap {
            what: "金鑰鎖目錄".into(),
            path: Some("/state/locks".into()),
            reason: "無法讀取：Permission denied".into(),
        }],
    }
}

fn check(id: &str, status: CheckStatus) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.into(),
        status,
        message: (format!("{id}：測試")).into(),
    }
}

fn no_content() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// IP blocklists and bans, as the controller answers them.
fn security(s: &StandIn, req: &Request<Incoming>) -> Option<Response<Full<Bytes>>> {
    let path = req.uri().path();
    let method = req.method();
    let missing = || {
        json(
            StatusCode::NOT_FOUND,
            &ApiError::new(ErrorCode::NotFound, "找不到"),
        )
    };
    if path == "/v1/blocklists" && method == hyper::Method::GET {
        return Some(json(StatusCode::OK, &s.blocklists));
    }
    if let Some(rest) = path.strip_prefix("/v1/blocklists/") {
        let id = rest.trim_end_matches("/refresh");
        let Some(v) = s
            .blocklists
            .iter()
            .find(|v| v.blocklist.id.to_string() == id)
        else {
            return Some(missing());
        };
        if rest.ends_with("/refresh") && method == hyper::Method::POST {
            return Some(match v.blocklist.source {
                BlocklistSource::Upload => json(
                    StatusCode::CONFLICT,
                    &ApiError::new(ErrorCode::InvalidState, "只有網址來源的清單可以重新下載"),
                ),
                BlocklistSource::Url { .. } => {
                    let mut after = v.clone();
                    let now = Timestamp::now();
                    after.refresh = Some(BlocklistRefreshState {
                        attempted_at: now,
                        ok: true,
                        message: Some("已更新為 6 筆".into()),
                        succeeded_at: Some(now),
                        stale_since: None,
                    });
                    after.stale = false;
                    json(StatusCode::OK, &after)
                }
            });
        }
        if method == hyper::Method::DELETE {
            let if_match = req
                .headers()
                .get("if-match")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            s.deletes.lock().unwrap().push((path.to_string(), if_match));
            return Some(no_content());
        }
    }
    if path == "/v1/bans" && method == hyper::Method::GET {
        let instance = req.uri().query().and_then(|q| q.strip_prefix("instance="));
        let bans: Vec<&Ban> = s
            .bans
            .iter()
            .filter(|b| instance.is_none_or(|i| b.instance_id.to_string() == i))
            .collect();
        return Some(json(StatusCode::OK, &bans));
    }
    if let Some(id) = path.strip_prefix("/v1/bans/")
        && method == hyper::Method::DELETE
    {
        s.deletes.lock().unwrap().push((path.to_string(), None));
        return Some(
            s.bans
                .iter()
                .find(|b| b.id.to_string() == id)
                .map_or_else(missing, |ban| {
                    json(
                        StatusCode::OK,
                        &UnbanResult {
                            ban: ban.clone(),
                            worker: UnbanEffect::Applied,
                        },
                    )
                }),
        );
    }
    None
}

/// Port forwards: the list, and a save (recorded) answered with the forward as saved.
async fn forward_bindings(s: &StandIn, req: Request<Incoming>) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let if_match = req
        .headers()
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = req.into_body().collect().await.unwrap().to_bytes();
    if method == hyper::Method::GET && path == "/v1/forward-bindings" {
        return json(StatusCode::OK, &s.forwards);
    }
    let found = path
        .strip_prefix("/v1/forward-bindings/")
        .and_then(|id| s.forwards.iter().find(|v| v.binding.id.to_string() == id));
    let Some(current) = found else {
        return json(
            StatusCode::NOT_FOUND,
            &ApiError::new(ErrorCode::NotFound, "找不到"),
        );
    };
    if method != hyper::Method::PUT {
        return json(StatusCode::OK, current);
    }
    let input: ForwardInput = serde_json::from_slice(&body).unwrap();
    s.forward_puts
        .lock()
        .unwrap()
        .push((path, if_match, serde_json::from_slice(&body).unwrap()));
    let mut saved = current.clone();
    let b = &mut saved.binding;
    b.meta.revision += 1;
    b.enabled = input.enabled;
    b.proxy_protocol = input.proxy_protocol;
    b.protocol = input.protocol;
    b.udp_direct = input.udp_direct;
    json(StatusCode::OK, &saved)
}

/// The Provider egress: its status, and opening or cancelling a rebootstrap (recorded).
async fn provider_egress(s: &StandIn, req: Request<Incoming>) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let if_match = req
        .headers()
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let Some(current) = s.egress.lock().unwrap().clone() else {
        return json(
            StatusCode::NOT_FOUND,
            &ApiError::new(ErrorCode::NotFound, "找不到"),
        );
    };
    if method == hyper::Method::GET {
        return json(StatusCode::OK, &current);
    }
    s.egress_calls.lock().unwrap().push((
        method.to_string(),
        path,
        if_match,
        String::from_utf8_lossy(&body).into_owned(),
    ));
    let mut next = current;
    if method == hyper::Method::POST {
        next.phase = EgressPhase::BootstrapDirect;
        next.bootstrap_expires_at =
            Some(Timestamp::now().plus(std::time::Duration::from_secs(600)));
        next.bootstrap = Some(BootstrapRun {
            id: "r1".into(),
            kind: BootstrapKind::Rebootstrap,
            stage: BootstrapStage::GrantActive,
            child_instance_id: None,
            child_profile_id: None,
            grant_expires_at: next.bootstrap_expires_at,
            promote_deadline: None,
            reason_code: None,
            reason: None,
            updated_at: Timestamp::now(),
        });
    } else {
        next.bootstrap_expires_at = None;
    }
    json(StatusCode::OK, &next)
}

async fn handle(
    s: Arc<StandIn>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    if req.uri().path().starts_with("/v1/provider-egress") {
        return Ok(provider_egress(&s, req).await);
    }
    if req.uri().path().contains("/forwarded-ports") {
        return Ok(forwarded_ports(&s, req).await);
    }
    if req.uri().path().starts_with("/v1/forward-bindings") {
        return Ok(forward_bindings(&s, req).await);
    }
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let key = req
        .headers()
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if let Some(answer) = security(&s, &req) {
        return Ok(answer);
    }
    if method == hyper::Method::POST && path == "/v1/provider-accounts" {
        return Ok(create_account(&s, req).await);
    }
    if method == hyper::Method::DELETE && path.starts_with("/v1/provider-accounts/") {
        let if_match = req
            .headers()
            .get("if-match")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        s.deletes.lock().unwrap().push((path.clone(), if_match));
        return Ok(no_content());
    }
    if method == hyper::Method::GET && path == "/v1/instances" {
        return Ok(json(StatusCode::OK, &s.views));
    }
    if method == hyper::Method::GET && path == "/v1/system/status" {
        return Ok(json(StatusCode::OK, &system_status(&s)));
    }
    if method == hyper::Method::GET
        && let Some(id) = path.strip_prefix("/v1/instances/")
        && let Some(v) = s.views.iter().find(|v| v.spec.id.to_string() == id)
    {
        return Ok(json(StatusCode::OK, v));
    }
    if method == hyper::Method::GET && path == "/v1/ssh" {
        // Someone edited the file by hand: an apply leaves it alone.
        return Ok(json(StatusCode::OK, &ssh_status(SshFileState::Modified)));
    }
    if method == hyper::Method::GET && path == "/v1/recovery" {
        return Ok(json(StatusCode::OK, &recovery_report()));
    }
    if method == hyper::Method::GET && path == "/v1/apps" {
        return Ok(json(StatusCode::OK, &s.apps));
    }
    if method == hyper::Method::GET && path == "/v1/provider-accounts" {
        return Ok(json(StatusCode::OK, &s.accounts));
    }
    if method == hyper::Method::GET && path == "/v1/system/diagnostics" {
        return Ok(json(
            StatusCode::OK,
            &diagnostics(s.checks.lock().unwrap().clone()),
        ));
    }
    if let Some(k) = path.strip_prefix("/v1/operations/by-key/") {
        return Ok(s.ops.lock().unwrap().get(k).map_or_else(
            || {
                json(
                    StatusCode::NOT_FOUND,
                    &ApiError::new(ErrorCode::NotFound, "找不到這項操作"),
                )
            },
            |op| json(StatusCode::OK, op),
        ));
    }
    if method == hyper::Method::POST && path.ends_with("/refresh") {
        let mut a = s.accounts[0].clone();
        a.observed_at = Some(Timestamp::now());
        return Ok(json(StatusCode::OK, &a));
    }
    if method == hyper::Method::POST
        && (path.ends_with("/actions")
            || path.ends_with("/emergency-stop")
            || path == "/v1/ssh/apply"
            || path == "/v1/recovery/reconcile")
    {
        let key = key.unwrap_or_default();
        s.seen.lock().unwrap().keys.push(key.clone());
        if s.lost == Lost::ThenSucceeded {
            record_succeeded(&s, key);
        }
        // No answer: the connection drops (as when the controller stops mid-request).
        return Err(std::io::Error::other("connection dropped by the stand-in"));
    }
    Ok(json(
        StatusCode::NOT_FOUND,
        &ApiError::new(ErrorCode::NotFound, "找不到"),
    ))
}

/// A new Provider account (recorded) answered with the account as created.
async fn create_account(s: &StandIn, req: Request<Incoming>) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let input: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let mut a = account();
    a.label = input["label"].as_str().unwrap_or_default().into();
    if input["credential"]["provider"] == "airvpn" {
        a.provider = ProviderKind::Airvpn;
    }
    s.created.lock().unwrap().push(input);
    json(StatusCode::CREATED, &a)
}

/// The system status the stand-in answers.
fn system_status(s: &StandIn) -> SystemStatus {
    SystemStatus {
        version: "0.1.0".into(),
        build_id: "0.1.0+test".into(),
        os: "macos".into(),
        controller_port: 18765,
        controller_listen: "127.0.0.1".into(),
        controller_allow_clients: Vec::new(),
        host_addresses: Vec::new(),
        data_dir: None,
        installation_id: Some(InstallationId::new()),
        manager_connected: true,
        store: StoreHealth {
            control_ok: true,
            metrics_ok: true,
            metrics_recording: None,
            keystore: CapabilityState::Supported,
            sqlite_version: "3".into(),
        },
        instances_running: 0,
        instances_total: u32::try_from(s.views.len()).unwrap(),
        capabilities: vec![],
        clock_synchronized: Some(true),
        observed_at: Timestamp::now(),
    }
}

/// The operation recorded under `key` for a change whose answer is lost but that succeeded.
fn record_succeeded(s: &StandIn, key: String) {
    let now = Timestamp::now();
    s.ops.lock().unwrap().insert(
        key,
        Operation {
            id: OperationId::new(),
            kind: "instance.stop".into(),
            target_id: None,
            status: OperationStatus::Succeeded,
            error: None,
            result_refs: vec![],
            durable: true,
            created_at: now,
            updated_at: now,
        },
    );
}

/// Serve the stand-in on the API socket of the state directory `state`.
fn serve(state: &Path, s: Arc<StandIn>) {
    let paths = vpn_platform::paths::Paths::under(state);
    paths.ensure().unwrap();
    let listener = tokio::net::UnixListener::bind(paths.api_socket()).unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let s = s.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| handle(s.clone(), req));
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "a connection the stand-in drops on purpose (a lost answer) ends in an error; the tests check what vpnctl saw"
                )]
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
}

async fn vpnctl(state: &Path, args: &[&str]) -> Output {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_vpnctl"));
    cmd.arg("--state-dir").arg(state).args(args);
    cmd.output().await.unwrap()
}

/// `vpnctl` with `input` on its standard input (a pipe, not a terminal).
async fn vpnctl_fed(state: &Path, args: &[&str], input: &str) -> Output {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_vpnctl"))
        .arg("--state-dir")
        .arg(state)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input.as_bytes()).await.unwrap();
    drop(stdin);
    child.wait_with_output().await.unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn stand_in(views: Vec<InstanceView>, lost: Lost) -> Arc<StandIn> {
    Arc::new(StandIn {
        views,
        apps: vec![],
        accounts: vec![account(), airvpn_account()],
        lost,
        seen: Mutex::default(),
        ops: Mutex::default(),
        blocklists: vec![],
        bans: vec![],
        deletes: Mutex::default(),
        checks: Mutex::new(vec![check("manager", CheckStatus::Failed)]),
        egress: Mutex::default(),
        egress_calls: Mutex::default(),
        created: Mutex::default(),
        port_calls: Mutex::default(),
        forwards: vec![],
        forward_puts: Mutex::default(),
    })
}

fn blocklist(name: &str, source: BlocklistSource, revision: u64) -> BlocklistView {
    let now = Timestamp::now();
    BlocklistView {
        blocklist: Blocklist {
            id: BlocklistId::new(),
            meta: EntityMeta {
                revision,
                created_at: now,
                updated_at: now,
            },
            name: name.into(),
            source,
            stats: BlocklistStats {
                lines: 8,
                entries: 6,
                invalid: 1,
                v4_ranges: 4,
                v6_ranges: 1,
                v4_addresses: 641,
                v6_addresses: "1208925819614629174706176".into(),
                raw_bytes: 338,
                parsed_bytes: 80,
                ..BlocklistStats::default()
            },
            content_sha256: "a".repeat(64),
            content_updated_at: now,
            invalid_lines: vec![InvalidLine {
                line: 10,
                reason: "不接受主機名稱，只接受 IP 位址或 CIDR".into(),
                content: "example.com".into(),
            }],
            builtin: None,
            enabled: true,
        },
        refresh: None,
        stale: false,
        next_refresh_at: None,
        used_by: vec![],
        builtin: None,
        default_policy: false,
        awaiting_content: false,
        waiting: None,
    }
}

fn state_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    (dir, state)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_answer_is_looked_up_by_its_key_not_sent_again() {
    let (_dir, state) = state_dir();
    let s = stand_in(
        vec![stopped_view("東京", Enforcement::Blocked)],
        Lost::ThenSucceeded,
    );
    serve(&state, s.clone());
    let out = vpnctl(&state, &["instance", "stop", "東京"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    // The record says it was done; the connection itself shows the evidence a reply carries.
    assert!(stdout.contains("紀錄顯示"), "{stdout}");
    assert!(
        stdout.contains("資料路徑已封閉，停止意圖已寫入磁碟"),
        "{stdout}"
    );
    assert_eq!(s.seen.lock().unwrap().keys.len(), 1, "sent exactly once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_answer_without_a_record_is_an_unknown_outcome() {
    let (_dir, state) = state_dir();
    let s = stand_in(vec![view("東京")], Lost::ThenNothing);
    serve(&state, s.clone());
    let out = vpnctl(&state, &["instance", "stop", "東京"]).await;
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    let err = text(&out.stderr);
    let key = s.seen.lock().unwrap().keys[0].clone();
    assert!(err.contains("結果未知") && err.contains(&key), "{err}");
    assert_eq!(s.seen.lock().unwrap().keys.len(), 1, "never sent twice");

    // The same in JSON: the key is there to look it up later.
    let out = vpnctl(&state, &["--json", "instance", "stop", "東京"]).await;
    assert_eq!(out.status.code(), Some(3));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "OUTCOME_UNKNOWN");
    // The same shape as the API's messages.
    assert!(v["error"]["message"]["zh-TW"].is_string(), "{v}");
    assert!(v["idempotency_key"].is_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn names_must_be_unique_and_known() {
    let (_dir, state) = state_dir();
    let views = vec![view("東京"), view("東京"), view("大阪")];
    let osaka = views[2].spec.id.to_string();
    serve(&state, stand_in(views, Lost::ThenNothing));
    let out = vpnctl(&state, &["instance", "stop", "東京"]).await;
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("請改用 ID"),
        "{}",
        text(&out.stderr)
    );
    let out = vpnctl(&state, &["instance", "inspect", "名古屋"]).await;
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("大阪"), "lists what exists");
    // A unique id prefix works (inspect of a view without status reports it unknown: exit 1).
    let out = vpnctl(&state, &["instance", "inspect", osaka.get(..8).unwrap()]).await;
    assert!(text(&out.stdout).contains("大阪"), "{}", text(&out.stdout));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_says_where_it_could_not_look_and_a_recovered_clean_is_checked_again() {
    let (_dir, state) = state_dir();
    let s = stand_in(vec![], Lost::ThenSucceeded);
    serve(&state, s.clone());
    let out = vpnctl(&state, &["recovery", "inspect"]).await;
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("無法檢查：金鑰鎖目錄（/state/locks）：無法讀取"),
        "{stdout}"
    );
    // The answer to the clean is lost; the record says it ran, but the confirmed item is still
    // there: whether it was tried is unknown (exit 3), and nothing is sent twice.
    let out = vpnctl(&state, &["recovery", "reconcile", "--yes"]).await;
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(3), "{stdout}");
    assert!(stdout.contains("仍有 1 個確認的項目"), "{stdout}");
    assert_eq!(s.seen.lock().unwrap().keys.len(), 1);
}

/// A URL blocklist whose last refresh failed, used by one security profile.
fn lab_blocklist(now: Timestamp) -> BlocklistView {
    let mut lab = blocklist(
        "實驗室下載",
        BlocklistSource::Url {
            url: "https://x.lab/drop.txt".into(),
            refresh_hours: Some(24),
        },
        3,
    );
    lab.refresh = Some(BlocklistRefreshState {
        attempted_at: now,
        ok: false,
        message: Some("下載失敗：經 tunnel 連線失敗：connection refused".into()),
        succeeded_at: None,
        stale_since: Some(now),
    });
    lab.stale = true;
    lab.used_by = vec![NamedRef {
        id: SecurityProfileId::new().to_string(),
        name: "Lab 內網".into(),
    }];
    lab
}

/// A ban of 203.0.113.9 on `instance`, 15 minutes long.
fn ban_of(instance: &InstanceView, now: Timestamp) -> Ban {
    Ban {
        id: BanId::new(),
        instance_id: instance.spec.id,
        source: "203.0.113.9".parse().unwrap(),
        reason: "10 秒內 101 個新連線（門檻 100）".into(),
        security_profile_id: None,
        security_profile_revision: None,
        policy_revision: 2,
        generation: 1,
        created_at: now,
        expires_at: now.plus(std::time::Duration::from_mins(15)),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocklists_and_bans_from_the_command_line() {
    let (_dir, state) = state_dir();
    let tokyo = view("東京");
    let now = Timestamp::now();
    let lab = lab_blocklist(now);
    let uploaded = blocklist("上傳清單", BlocklistSource::Upload, 1);
    let ban = ban_of(&tokyo, now);
    let s = Arc::new(StandIn {
        blocklists: vec![lab.clone(), uploaded],
        bans: vec![ban.clone()],
        ..Arc::into_inner(stand_in(vec![tokyo], Lost::ThenNothing)).unwrap()
    });
    serve(&state, s.clone());

    let out = vpnctl(&state, &["blocklist", "list"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    for want in [
        "實驗室下載",
        "上傳清單",
        "更新失敗",
        "1 份安全設定",
        "6 筆 · IPv4 4 段 · IPv6 1 段",
    ] {
        assert!(stdout.contains(want), "{want}: {stdout}");
    }
    let out = vpnctl(&state, &["blocklist", "show", "實驗室下載"]).await;
    let stdout = text(&out.stdout);
    for want in [
        "https://x.lab/drop.txt（每 24 小時自動更新）",
        "connection refused",
        "「Lab 內網」",
        "第 10 行  example.com",
    ] {
        assert!(stdout.contains(want), "{want}: {stdout}");
    }

    // Only a URL source is downloaded again; the answer says what changed.
    let out = vpnctl(&state, &["blocklist", "refresh", "上傳清單"]).await;
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("只有網址來源"));
    let out = vpnctl(&state, &["blocklist", "refresh", "實驗室下載"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("已更新為 6 筆"));

    // A delete needs --yes, names who still uses the list, and is sent against its revision.
    let out = vpnctl(&state, &["blocklist", "delete", "實驗室下載"]).await;
    assert_eq!(out.status.code(), Some(2));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("--yes") && stderr.contains("Lab 內網"),
        "{stderr}"
    );
    assert!(s.deletes.lock().unwrap().is_empty(), "nothing sent");
    let out = vpnctl(&state, &["blocklist", "delete", "實驗室下載", "--yes"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        s.deletes.lock().unwrap().clone(),
        vec![(
            format!("/v1/blocklists/{}", lab.blocklist.id),
            Some("\"3\"".to_string())
        )]
    );

    // Bans of one connection, then lifting one by its source address.
    let out = vpnctl(&state, &["ban", "list", "--instance", "東京"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    for want in ["203.0.113.9", "東京", "門檻 100"] {
        assert!(stdout.contains(want), "{want}: {stdout}");
    }
    let out = vpnctl(&state, &["--json", "ban", "list"]).await;
    let listed: Vec<Ban> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(listed, vec![ban.clone()]);
    let out = vpnctl(&state, &["ban", "remove", "203.0.113.9"]).await;
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("--yes"));
    let out = vpnctl(&state, &["ban", "remove", "203.0.113.9", "--yes"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("已確認不再封鎖"));
    assert_eq!(
        s.deletes.lock().unwrap().last().unwrap().0,
        format!("/v1/bans/{}", ban.id)
    );
}

fn egress_needing_recovery(eligible: bool) -> ProviderEgressStatus {
    ProviderEgressStatus {
        egress: ProviderEgress {
            revision: 7,
            route_revision: 9,
            desired_mode: EgressMode::ViaInstance,
            bootstrap_consumed: true,
            selected_instance_id: Some(InstanceId::new()),
        },
        phase: EgressPhase::RecoveryRequired,
        selected_instance_name: Some("東京".into()),
        selected_generation: None,
        reason_code: Some("KEY_MISSING".into()),
        reason: Some(
            "出口連線「東京」的 WireGuard 金鑰不在這台電腦或無法使用，無法自行恢復".into(),
        ),
        bootstrap_expires_at: None,
        bootstrap: None,
        recovery: Some(EgressRecovery {
            required: true,
            rebootstrap_eligible: eligible,
            reason_code: if eligible {
                "KEY_MISSING".into()
            } else {
                "LOCAL_PROFILE_AVAILABLE".into()
            },
            reason: if eligible {
                "金鑰不在這台電腦；可以重新直連".into()
            } else {
                "這台電腦還有可用的 WireGuard 設定「大阪備用」：請用它建立連線並選為出口，不需要直連".into()
            },
        }),
        last_check: None,
        gates: vec![],
        observed_at: Timestamp::now(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rebootstrap_needs_its_flag_carries_the_revision_and_can_be_cancelled() {
    let (_dir, state) = state_dir();
    let s = stand_in(vec![], Lost::ThenNothing);
    *s.egress.lock().unwrap() = Some(egress_needing_recovery(true));
    serve(&state, s.clone());

    // Inspect says it needs recovery and how.
    let out = vpnctl(&state, &["provider-egress", "inspect"]).await;
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("出口需要恢復"), "{stdout}");
    assert!(stdout.contains("--confirm-direct"), "{stdout}");

    // Without the acknowledgement nothing is sent.
    let out = vpnctl(&state, &["provider-egress", "rebootstrap"]).await;
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("--confirm-direct"),
        "{}",
        text(&out.stderr)
    );
    assert!(s.egress_calls.lock().unwrap().is_empty());

    // With it: the egress revision shown goes along, with the acknowledgement in the body.
    let out = vpnctl(
        &state,
        &["provider-egress", "rebootstrap", "--confirm-direct"],
    )
    .await;
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("已開啟重新直連"), "{stdout}");
    assert!(stdout.contains("重新直連：開放中"), "{stdout}");
    let (method, path, if_match, body) = s.egress_calls.lock().unwrap()[0].clone();
    assert_eq!(
        (method.as_str(), path.as_str()),
        ("POST", "/v1/provider-egress/rebootstrap")
    );
    assert_eq!(if_match.as_deref(), Some("\"7\""));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({ "confirm_direct": true })
    );

    // Cancelled.
    let out = vpnctl(&state, &["provider-egress", "rebootstrap", "--cancel"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("已取消重新直連"));
    assert_eq!(s.egress_calls.lock().unwrap()[1].0, "DELETE");

    // Not eligible: the reason, and nothing is sent.
    *s.egress.lock().unwrap() = Some(egress_needing_recovery(false));
    let out = vpnctl(
        &state,
        &["provider-egress", "rebootstrap", "--confirm-direct"],
    )
    .await;
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("大阪備用"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(s.egress_calls.lock().unwrap().len(), 2);
}

/// AC-66: a provider account is added from the CLI with the credential read from standard input
/// only, sent once through the controller's API (the web form's), and never printed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_account_is_added_with_the_credential_from_stdin_only() {
    let (_dir, state) = state_dir();
    let s = stand_in(vec![], Lost::ThenNothing);
    serve(&state, s.clone());
    let number = "1234 5678 9012 3456";
    let out = vpnctl_fed(
        &state,
        &[
            "provider",
            "account",
            "add",
            "--provider",
            "mullvad",
            "--label",
            "家裡",
        ],
        &format!("{number}\n"),
    )
    .await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(stdout.contains("已加入 Mullvad 帳號「家裡」"), "{stdout}");
    for printed in [&stdout, &stderr] {
        assert!(
            !printed.contains("1234") && !printed.contains("9012"),
            "{printed}"
        );
    }
    assert_eq!(
        s.created.lock().unwrap().clone(),
        vec![serde_json::json!({
            "label": "家裡",
            "credential": { "provider": "mullvad", "account_number": number }
        })]
    );

    // AirVPN: user name, then password; --json prints the account, never the credential.
    let out = vpnctl_fed(
        &state,
        &[
            "--json",
            "provider",
            "account",
            "add",
            "--provider",
            "airvpn",
        ],
        "someone\n pass word\n",
    )
    .await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let printed: ProviderAccount = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(printed.provider, ProviderKind::Airvpn);
    assert_eq!(printed.label, "AirVPN", "the default label");
    let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(
        !all.contains("someone") && !all.contains("pass word"),
        "{all}"
    );
    assert_eq!(
        s.created.lock().unwrap()[1]["credential"],
        serde_json::json!({ "provider": "airvpn", "username": "someone", "password": " pass word" })
    );

    // Nothing on standard input: nothing is sent.
    let out = vpnctl_fed(
        &state,
        &["provider", "account", "add", "--provider", "airvpn"],
        "someone\n",
    )
    .await;
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("標準輸入"),
        "{}",
        text(&out.stderr)
    );
    // A credential as an argument is not accepted at all.
    let out = vpnctl_fed(
        &state,
        &[
            "provider",
            "account",
            "add",
            "--provider",
            "mullvad",
            "--account-number",
            number,
        ],
        "",
    )
    .await;
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(s.created.lock().unwrap().len(), 2, "nothing more was sent");
}

/// AC-66: removing an account needs --yes and is sent against its revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_account_is_removed_only_when_confirmed() {
    let (_dir, state) = state_dir();
    let s = stand_in(vec![], Lost::ThenNothing);
    serve(&state, s.clone());
    let out = vpnctl(&state, &["provider", "account", "remove", "家裡的帳號"]).await;
    assert_eq!(out.status.code(), Some(2));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("--yes") && stderr.contains("供應商那邊的帳號與裝置不受影響"),
        "{stderr}"
    );
    assert!(s.deletes.lock().unwrap().is_empty(), "nothing sent");
    let out = vpnctl(
        &state,
        &["provider", "account", "remove", "家裡的帳號", "--yes"],
    )
    .await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("已移除 Mullvad 帳號「家裡的帳號」"));
    let id = s.accounts[0].id;
    assert_eq!(
        s.deletes.lock().unwrap().clone(),
        vec![(
            format!("/v1/provider-accounts/{id}"),
            Some("\"1\"".to_string())
        )]
    );
}

/// `AirVPN`'s forwarded ports from the command line: listed with what is unusual about each,
/// reserved at random or by number (one change each, with its own Idempotency-Key), deleted only
/// with --yes; a Mullvad account or a port below 2049 is refused before anything is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn airvpn_forwarded_ports_are_listed_reserved_and_deleted() {
    let (_dir, state) = state_dir();
    let s = stand_in(vec![], Lost::ThenNothing);
    serve(&state, s.clone());
    let out = vpnctl(&state, &["provider", "ports", "list", "AirVPN 帳號"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    for expected in [
        "已用 2／5 個",
        "35786",
        "TCP＋UDP",
        "IPv4＋IPv6",
        "全部裝置",
        "Default",
        "停用",
        "轉到 local port 41000",
    ] {
        assert!(stdout.contains(expected), "{expected}: {stdout}");
    }

    let out = vpnctl(&state, &["provider", "ports", "list", "家裡的帳號"]).await;
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("Mullvad 已停止提供 port forwarding"),
        "{}",
        text(&out.stderr)
    );
    let out = vpnctl(
        &state,
        &[
            "provider",
            "ports",
            "reserve",
            "AirVPN 帳號",
            "--port",
            "80",
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(2));
    assert!(s.port_calls.lock().unwrap().is_empty(), "nothing sent");

    let out = vpnctl(&state, &["provider", "ports", "reserve", "AirVPN 帳號"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("已在 AirVPN 保留連入埠 37587"),
        "{}",
        text(&out.stdout)
    );
    let out = vpnctl(
        &state,
        &[
            "--json",
            "provider",
            "ports",
            "reserve",
            "AirVPN 帳號",
            "--port",
            "40001",
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let reserved: ForwardedPort = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(reserved.port, 40001);

    let out = vpnctl(
        &state,
        &["provider", "ports", "delete", "AirVPN 帳號", "35786"],
    )
    .await;
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("--yes"), "{}", text(&out.stderr));
    let out = vpnctl(
        &state,
        &[
            "provider",
            "ports",
            "delete",
            "AirVPN 帳號",
            "35786",
            "--yes",
        ],
    )
    .await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    assert_port_changes_sent(&s);
}

/// The reservations and the delete went out once each, as the API takes them, every one with
/// its own Idempotency-Key.
fn assert_port_changes_sent(s: &StandIn) {
    let id = s.accounts[1].id;
    let calls = s.port_calls.lock().unwrap().clone();
    let shape: Vec<(String, String, String)> = calls
        .iter()
        .map(|(m, p, _, b)| (m.clone(), p.clone(), b.clone()))
        .collect();
    assert_eq!(
        shape,
        vec![
            (
                "POST".into(),
                format!("/v1/provider-accounts/{id}/forwarded-ports"),
                r#"{"port":null}"#.into()
            ),
            (
                "POST".into(),
                format!("/v1/provider-accounts/{id}/forwarded-ports"),
                r#"{"port":40001}"#.into()
            ),
            (
                "DELETE".into(),
                format!("/v1/provider-accounts/{id}/forwarded-ports/35786"),
                String::new()
            ),
        ]
    );
    let keys: std::collections::HashSet<_> = calls
        .iter()
        .map(|(_, _, k, _)| k.clone().unwrap())
        .collect();
    assert_eq!(keys.len(), 3, "each change its own Idempotency-Key");
}

/// A pseudo-terminal: the side a user types into, and the terminal device a program reads.
fn pty() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
    use std::os::fd::{FromRawFd, OwnedFd};
    // SAFETY: posix_openpt has no preconditions; it returns a new descriptor or -1.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    assert!(master >= 0, "posix_openpt");
    // SAFETY: `master` is the pty master this test just opened.
    assert_eq!(unsafe { libc::grantpt(master) }, 0);
    // SAFETY: as for grantpt.
    assert_eq!(unsafe { libc::unlockpt(master) }, 0);
    // SAFETY: ptsname of the pty master this test owns: null or a pointer to static storage.
    let name = unsafe { libc::ptsname(master) };
    assert!(!name.is_null(), "ptsname");
    // SAFETY: `name` is the NUL-terminated name ptsname returned; it is copied at once, before
    // this test opens another pty.
    let name = unsafe { std::ffi::CStr::from_ptr(name) }.to_owned();
    // SAFETY: open with a NUL-terminated path; the result is a new descriptor or -1.
    let slave = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    assert!(slave >= 0, "open {name:?}");
    // SAFETY: `master` was opened above and nothing else owns it.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    // SAFETY: `slave` was opened above and nothing else owns it.
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    (master, slave)
}

fn echo_on(fd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: termios is plain data that tcgetattr fills in.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: a terminal descriptor this test owns.
    assert_eq!(unsafe { libc::tcgetattr(fd.as_raw_fd(), &raw mut t) }, 0);
    t.c_lflag & libc::ECHO != 0
}

/// AC-66: typed on a terminal, the credential is not echoed — the terminal never shows it —
/// and the terminal's settings are back afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_a_terminal_the_credential_is_read_without_echo() {
    use std::os::fd::AsRawFd;
    let (_dir, state) = state_dir();
    let s = stand_in(vec![], Lost::ThenNothing);
    serve(&state, s.clone());
    let (master, slave) = pty();
    assert!(echo_on(&slave));
    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_vpnctl"))
        .arg("--state-dir")
        .arg(&state)
        .args(["provider", "account", "add", "--provider", "mullvad"])
        .stdin(std::process::Stdio::from(slave.try_clone().unwrap()))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // It turns echo off before it asks.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while echo_on(&slave) {
        assert!(
            std::time::Instant::now() < deadline,
            "echo never turned off"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let typed = b"1234 5678 9012 3456\n";
    // SAFETY: writing a buffer we own to the terminal's user side.
    let n = unsafe { libc::write(master.as_raw_fd(), typed.as_ptr().cast(), typed.len()) };
    assert_eq!(usize::try_from(n).ok(), Some(typed.len()));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    // What the terminal showed for it (a non-blocking read of the user side).
    let fd = master.as_raw_fd();
    // SAFETY: fcntl on a descriptor this test owns.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // SAFETY: as above.
    unsafe {
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let mut buf = [0u8; 256];
    // SAFETY: read on a descriptor this test owns, into a buffer of the length given.
    let got = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    let shown = String::from_utf8_lossy(&buf[..usize::try_from(got).unwrap_or(0)]).into_owned();
    assert!(
        !shown.contains("1234") && !shown.contains("9012"),
        "{shown:?}"
    );
    let out = child.wait_with_output().await.unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("Mullvad 帳號號碼（不會顯示）："),
        "{}",
        text(&out.stderr)
    );
    assert!(text(&out.stdout).contains("已加入 Mullvad 帳號「Mullvad」"));
    assert!(echo_on(&slave), "the terminal's settings are back");
    assert_eq!(
        s.created.lock().unwrap()[0]["credential"]["account_number"],
        "1234 5678 9012 3456"
    );
}
