//! Local access ports of managed Apps (`strict_netns`): the host side.
//!
//! A strict App lives in its connection's sandbox, whose loopback is not the host's: its web UI on
//! `127.0.0.1:<port>` there cannot be reached from the host. An access port publishes one such
//! port: the manager binds `127.0.0.1:<host_port>` (or `0.0.0.0:<host_port>` for `lan`) in the
//! host's network namespace and holds it for as long as the App is configured with it, whether
//! the App runs or not — like a Gateway's listener across generations, the port stays VPN
//! Manager's and a client always gets an answer.
//!
//! Each connection is judged before a byte of it is read ([`vpn_platform::admission`]): a client
//! on this host must be a program of this user (`ssh -L` included: the user's own sshd holds the
//! socket); another host must come from one of the port's allowed networks (`lan` only).
//! Refused clients are closed unread and logged, at most a line a second. An admitted
//! connection goes to the App's launcher, which lives in the sandbox's network namespace and
//! relays it to the App's port on the sandbox's loopback ([`vpn_platform::sandbox`]); while the
//! App does not run (or was started before the port was added), the client is told so — an
//! HTTP client with a 503 and the reason — and closed.
//!
//! Nothing here involves the tunnel or the destination policy: the bytes go between a client on
//! the host (or the LAN) and the App, never to the network through the sandbox.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use vpn_domain::{
    AccessBind, AccessState, AppAccessStatus, AppId, AppIsolation, AppSpec, Fault, Language, Text,
    tr,
};
use vpn_platform::admission::{self, ClientPolicy, HostView, RefusalLog};
use vpn_platform::sandbox::AccessChannel;
use vpn_sync::Mutex;

use super::{Apps, fault};

/// Clients judged at once (each may read the OS socket tables); the next accepted one waits.
const JUDGING: usize = 8;
/// Back-off of a port that cannot be bound: doubles from the first to the last.
const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_LAST: Duration = Duration::from_secs(30);
/// A refused client's state is announced at most this often per port (the counters keep
/// counting in between).
const ANNOUNCE_REFUSALS: Duration = Duration::from_secs(5);
/// How long an unserved client gets to show it speaks HTTP (so it is told why).
const PEEK: Duration = Duration::from_secs(2);
/// Unserved clients being told why at once; beyond that they are just closed.
const EXPLAINING: usize = 64;
/// How much of an unserved client's request is looked at for the language of the answer.
const HEAD_PEEK: usize = 4096;

/// Where an admitted connection of an App's port goes now.
pub enum Relay {
    /// To the App's launcher.
    Ready(Arc<AccessChannel>),
    /// Nowhere: the App does not run.
    Stopped,
    /// Nowhere: the App's run was started without this port.
    RestartNeeded,
    /// Nowhere: the App's run has no relay (it could not be set up).
    Unrelayed,
}

/// How a port is configured (changes in place: the App's port, the allowed networks).
#[derive(Debug, Clone)]
struct PortConfig {
    /// Position in the App's list (status order).
    order: usize,
    app_port: u16,
    allow: Vec<IpNetwork>,
    /// The App's name, for what a refused client is told.
    name: String,
}

#[derive(Debug, Default)]
struct PortStats {
    listening: bool,
    accepted: u64,
    refused: u64,
    last_refused: Option<Fault>,
    last_error: Option<Fault>,
    /// When a refusal was last announced.
    announced: Option<Instant>,
}

/// One access port of one App: its listener's task and what it saw.
struct Port {
    app: AppId,
    /// The host port it listens on (the spec's `host_port`).
    listening_on: u16,
    bind: AccessBind,
    config: Mutex<PortConfig>,
    stats: Mutex<PortStats>,
    cancel: CancellationToken,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Port {
    fn policy(&self, uid: u32) -> ClientPolicy {
        ClientPolicy {
            uid,
            allow: match self.bind {
                AccessBind::Loopback => Vec::new(),
                AccessBind::Lan => self.config.lock().allow.clone(),
            },
        }
    }

    fn app_port(&self) -> u16 {
        self.config.lock().app_port
    }

    fn address(&self) -> SocketAddr {
        address_of(self.bind, self.listening_on)
    }

    /// Record a problem; whether it is news.
    fn error(&self, code: &str, message: impl Into<Text>) -> bool {
        let message = message.into();
        let mut s = self.stats.lock();
        let news = s.last_error.as_ref().is_none_or(|f| f.message != message);
        s.last_error = Some(fault(code, message));
        news
    }

    /// The port works (again); whether that is news.
    fn clear_error(&self) -> bool {
        self.stats.lock().last_error.take().is_some()
    }
}

/// The host's listeners of every App's access ports.
pub struct AccessPorts {
    apps: Weak<Apps>,
    uid: u32,
    host: Arc<dyn HostView>,
    log: Arc<RefusalLog>,
    judging: Arc<Semaphore>,
    explaining: Arc<Semaphore>,
    ports: Mutex<HashMap<(AppId, u16), Arc<Port>>>,
    /// Serialises reconfigurations (a port moving between apps or binds is released first).
    sync: tokio::sync::Mutex<()>,
}

/// `addr` bound as a listener of an access port (non-blocking, for the runtime).
pub fn bind(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let l = std::net::TcpListener::bind(addr)?;
    l.set_nonblocking(true)?;
    Ok(l)
}

/// Where a port of `bind` listens.
pub fn address_of(bind: AccessBind, host_port: u16) -> SocketAddr {
    match bind {
        AccessBind::Loopback => SocketAddr::from((Ipv4Addr::LOCALHOST, host_port)),
        AccessBind::Lan => SocketAddr::from((Ipv4Addr::UNSPECIFIED, host_port)),
    }
}

impl AccessPorts {
    pub(crate) fn new(apps: Weak<Apps>, host: Arc<dyn HostView>) -> Self {
        Self {
            apps,
            uid: vpn_platform::process::current_uid(),
            host,
            log: Arc::new(RefusalLog::new("local access port client")),
            judging: Arc::new(Semaphore::new(JUDGING)),
            explaining: Arc::new(Semaphore::new(EXPLAINING)),
            ports: Mutex::new(HashMap::new()),
            sync: tokio::sync::Mutex::new(()),
        }
    }

    /// Whether this manager holds (or keeps trying to hold) `host_port` for `app`.
    pub(crate) fn holds(&self, app: AppId, host_port: u16) -> bool {
        self.ports.lock().contains_key(&(app, host_port))
    }

    /// Hold exactly the access ports `specs` configure (`strict_netns` Apps): new ones are bound,
    /// gone ones released (their connections already relayed stay with the App), changed ones
    /// updated in place — a new bind address is a new listener.
    pub(crate) async fn sync(self: &Arc<Self>, specs: &[AppSpec]) {
        let _one = self.sync.lock().await;
        let mut wanted: HashMap<(AppId, u16), (AccessBind, PortConfig)> = HashMap::new();
        for spec in specs
            .iter()
            .filter(|s| s.isolation == AppIsolation::StrictNetns)
        {
            for (order, p) in spec.access_ports.iter().enumerate() {
                wanted.insert(
                    (spec.id, p.host_port),
                    (
                        p.bind,
                        PortConfig {
                            order,
                            app_port: p.app_port,
                            allow: p.allow.clone(),
                            name: spec.name.clone(),
                        },
                    ),
                );
            }
        }
        let gone: Vec<Arc<Port>> = {
            let mut ports = self.ports.lock();
            let keys: Vec<(AppId, u16)> = ports
                .iter()
                .filter(|(key, port)| wanted.get(key).is_none_or(|(b, _)| *b != port.bind))
                .map(|(key, _)| *key)
                .collect();
            let gone = keys.iter().filter_map(|k| ports.remove(k)).collect();
            drop(ports);
            gone
        };
        let mut touched: Vec<AppId> = Vec::new();
        for port in gone {
            touched.push(port.app);
            port.cancel.cancel();
            let task = port.task.lock().take();
            // Its listener is closed once the task is gone: a new one may take the port.
            if let Some(task) = task
                && let Err(e) = task.await
            {
                tracing::warn!(app = %port.app, error = %e, "access port task failed");
            }
            tracing::info!(app = %port.app, port = port.listening_on, "access port released");
        }
        for (key, (bind, config)) in wanted {
            let existing = self.ports.lock().get(&key).cloned();
            if let Some(port) = existing {
                let mut c = port.config.lock();
                if c.app_port != config.app_port || c.allow != config.allow {
                    touched.push(key.0);
                }
                *c = config;
            } else {
                let port = Arc::new(Port {
                    app: key.0,
                    listening_on: key.1,
                    bind,
                    config: Mutex::new(config),
                    stats: Mutex::new(PortStats::default()),
                    cancel: CancellationToken::new(),
                    task: Mutex::new(None),
                });
                self.ports.lock().insert(key, port.clone());
                let task = tokio::spawn(self.clone().hold(port.clone()));
                *port.task.lock() = Some(task);
                touched.push(key.0);
            }
        }
        touched.sort();
        touched.dedup();
        for app in touched {
            self.announce(app);
        }
    }

    /// Release every port (the manager is stopping).
    pub(crate) fn shutdown(&self) {
        for port in self.ports.lock().values() {
            port.cancel.cancel();
        }
    }

    /// The App's status changed (state, error, listener): published again.
    fn announce(&self, app: AppId) {
        if let Some(apps) = self.apps.upgrade() {
            apps.republish(app);
        }
    }

    /// Bind the port (retrying while another program holds it) and serve it until released.
    async fn hold(self: Arc<Self>, port: Arc<Port>) {
        let mut wait = RETRY_FIRST;
        let address = port.address();
        let listener = loop {
            match bind(address) {
                Ok(l) => match tokio::net::TcpListener::from_std(l) {
                    Ok(l) => break l,
                    Err(e) => {
                        port.error(
                            "ACCESS_PORT_UNAVAILABLE",
                            tr!(
                                "Cannot use {address}: {e}",
                                "無法使用 {address}：{e}",
                                "{address} を使用できません：{e}"
                            ),
                        );
                    }
                },
                Err(e) => {
                    let message = if e.kind() == std::io::ErrorKind::AddrInUse {
                        tr!(
                            "{address} is in use by another program; once that program closes, VPN Manager takes the port over by itself, or choose another local port",
                            "{address} 已被其他程式占用；關閉占用它的程式後會自動接手，或換一個本機的 port",
                            "{address} はほかのプログラムが使用中です。そのプログラムを終了すると VPN Manager が自動的に引き継ぎます。別のローカルポートにすることもできます"
                        )
                    } else {
                        tr!(
                            "Cannot listen on {address}: {e}",
                            "無法在 {address} 監聽：{e}",
                            "{address} で待ち受けできません：{e}"
                        )
                    };
                    if port.error("ACCESS_PORT_UNAVAILABLE", message) {
                        tracing::warn!(app = %port.app, address = %port.address(), error = %e, "access port unavailable");
                        self.announce(port.app);
                    }
                }
            }
            tokio::select! {
                () = port.cancel.cancelled() => return,
                () = tokio::time::sleep(wait) => {}
            }
            wait = (wait * 2).min(RETRY_LAST);
        };
        {
            let mut s = port.stats.lock();
            s.listening = true;
            s.last_error = None;
        }
        tracing::info!(app = %port.app, address = %port.address(), "access port listening");
        self.announce(port.app);
        loop {
            let accepted = tokio::select! {
                () = port.cancel.cancelled() => break,
                a = listener.accept() => a,
            };
            let (stream, peer) = match accepted {
                Ok(a) => a,
                Err(e) => {
                    // Out of descriptors and the like: back off instead of spinning.
                    tracing::debug!(error = %e, "access port accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let permit = tokio::select! {
                () = port.cancel.cancelled() => break,
                p = self.judging.clone().acquire_owned() => match p {
                    Ok(p) => p,
                    Err(_) => break,
                },
            };
            let (me, port) = (self.clone(), port.clone());
            tokio::spawn(async move {
                let judged = me.admit(&port, &stream, peer).await;
                drop(permit);
                if judged {
                    me.deliver(&port, stream).await;
                }
            });
        }
        port.stats.lock().listening = false;
    }

    /// Judge one client; a refused one is counted, logged (rate-limited) and dropped unread.
    async fn admit(&self, port: &Port, stream: &TcpStream, peer: SocketAddr) -> bool {
        let Ok(local) = stream.local_addr() else {
            return false;
        };
        match admission::judge(port.policy(self.uid), self.host.clone(), local, peer).await {
            Ok(_) => true,
            Err(refusal) => {
                self.log.refused(
                    peer,
                    &format!("access port {}", port.listening_on),
                    &refusal,
                );
                let ip = peer.ip();
                self.refused(
                    port,
                    fault(
                        "ACCESS_REFUSED",
                        tr!(
                            "{ip}: {why}",
                            "{ip}：{why}",
                            "{ip}：{why}";
                            why = refusal.message()
                        ),
                    ),
                );
                false
            }
        }
    }

    fn refused(&self, port: &Port, why: Fault) {
        let announce = {
            let mut s = port.stats.lock();
            s.refused += 1;
            s.last_refused = Some(why);
            let due = s
                .announced
                .is_none_or(|at| at.elapsed() >= ANNOUNCE_REFUSALS);
            if due {
                s.announced = Some(Instant::now());
            }
            due
        };
        if announce {
            self.announce(port.app);
        }
    }

    /// Hand an admitted connection to the App, or tell the client why not.
    async fn deliver(&self, port: &Port, stream: TcpStream) {
        let Some(apps) = self.apps.upgrade() else {
            return;
        };
        let (app_port, name) = {
            let c = port.config.lock();
            (c.app_port, c.name.clone())
        };
        let closed = |why: Text| fault("ACCESS_APP_NOT_SERVING", why);
        match apps.access_relay(port.app, app_port) {
            Relay::Ready(channel) => {
                // A copy goes to the launcher; ours closes when the hand-over is done.
                let sent = stream
                    .as_fd()
                    .try_clone_to_owned()
                    .and_then(|fd: OwnedFd| channel.send(app_port, fd));
                match sent {
                    Ok(()) => {
                        port.stats.lock().accepted += 1;
                    }
                    Err(e) => {
                        let message = if e.kind() == std::io::ErrorKind::WouldBlock {
                            tr!(
                                "The app's relay process cannot keep up; this connection was refused",
                                "App 的轉送程序忙不過來，這條連線已拒絕",
                                "アプリの転送プロセスが処理しきれないため、この接続を拒否しました"
                            )
                        } else {
                            tr!(
                                "Cannot hand the connection over to the app's relay process: {e}",
                                "無法把連線交給 App 的轉送程序：{e}",
                                "接続をアプリの転送プロセスに引き渡せません：{e}"
                            )
                        };
                        if port.error("ACCESS_HANDOFF", message.clone()) {
                            self.announce(port.app);
                        }
                        self.explain(stream, &message).await;
                    }
                }
            }
            other => {
                let why = match other {
                    Relay::RestartNeeded => tr!(
                        "The app “{name}” was started before this local access port existed; it opens once the app restarts",
                        "App「{name}」啟動時還沒有這個本機存取埠；重新啟動 App 後才會開放",
                        "アプリ「{name}」の起動時にはこのローカルアクセスポートがありませんでした。アプリを再起動すると開放されます"
                    ),
                    Relay::Unrelayed => tr!(
                        "Relaying the local access ports of the app “{name}” is not enabled; restart the app",
                        "App「{name}」的本機存取埠轉送沒有啟用；請重新啟動 App",
                        "アプリ「{name}」のローカルアクセスポートの転送が有効になっていません。アプリを再起動してください"
                    ),
                    _ => tr!(
                        "The app “{name}” is not running; start it in VPN Manager",
                        "App「{name}」沒有在執行；請在 VPN Manager 啟動它",
                        "アプリ「{name}」は実行されていません。VPN Manager で起動してください"
                    ),
                };
                self.refused(port, closed(why.clone()));
                self.explain(stream, &why).await;
            }
        }
    }

    /// Tell an unserved client why (a bounded number at once; the rest are just closed).
    async fn explain(&self, stream: TcpStream, why: &Text) {
        if let Ok(_explaining) = self.explaining.clone().try_acquire_owned() {
            unavailable(stream, why).await;
        }
    }

    /// The launcher's report about a connection it was handed.
    pub(crate) fn reported(&self, app: AppId, report: vpn_platform::sandbox::AccessReport) {
        use vpn_platform::sandbox::AccessReport;
        let (app_port, failure) = match report {
            AccessReport::Relayed { port } => (port, None),
            AccessReport::Failed { port, message } => (port, Some(message)),
        };
        let ports: Vec<Arc<Port>> = self
            .ports
            .lock()
            .values()
            .filter(|p| p.app == app && p.app_port() == app_port)
            .cloned()
            .collect();
        let mut news = false;
        for port in ports {
            news |= failure.as_ref().map_or_else(
                || port.clear_error(),
                |m| port.error("ACCESS_APP_REFUSED", m.clone()),
            );
        }
        if news {
            self.announce(app);
        }
    }

    /// The status of `app`'s ports, in the App's order; `run` says what the App's current run
    /// relays (`None` while it does not run).
    pub(crate) fn status(&self, app: AppId, run: Option<&RunAccess>) -> Vec<AppAccessStatus> {
        let mut ports: Vec<Arc<Port>> = self
            .ports
            .lock()
            .values()
            .filter(|p| p.app == app)
            .cloned()
            .collect();
        ports.sort_by_key(|p| p.config.lock().order);
        ports
            .iter()
            .map(|p| {
                let app_port = p.app_port();
                let s = p.stats.lock();
                let state = if s.listening {
                    match run {
                        None => AccessState::AppStopped,
                        Some(r) if !r.ports.contains(&app_port) => AccessState::RestartNeeded,
                        Some(_) => AccessState::Serving,
                    }
                } else {
                    AccessState::Unavailable
                };
                AppAccessStatus {
                    app_port,
                    host_port: p.listening_on,
                    bind: p.bind,
                    state,
                    listening: s.listening,
                    app_listening: run.and_then(|r| r.listening(app_port)),
                    accepted: s.accepted,
                    refused: s.refused,
                    last_refused: s.last_refused.clone(),
                    last_error: s.last_error.clone(),
                }
            })
            .collect()
    }
}

/// What a run of an App relays: the App's ports it was started with, and whether its tree
/// listens on them.
pub struct RunAccess {
    pub ports: Vec<u16>,
    /// The tree's TCP listeners at the last watcher pass (`None`: not looked at yet).
    pub listeners: Option<Vec<SocketAddr>>,
}

impl RunAccess {
    /// Whether the tree listens on `app_port` where the relay connects (the sandbox's loopback,
    /// or every address).
    fn listening(&self, app_port: u16) -> Option<bool> {
        self.listeners.as_ref().map(|l| {
            l.iter().any(|a| {
                let ip = a.ip().to_canonical();
                a.port() == app_port && (ip.is_loopback() || ip.is_unspecified())
            })
        })
    }
}

/// The first bytes of an HTTP request (a browser or an API client).
fn looks_like_http(first: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ", b"HEAD", b"POST", b"PUT ", b"DELE", b"OPTI", b"PATC", b"CONN", b"TRAC",
    ];
    METHODS.iter().any(|m| first.starts_with(m))
}

/// The language to answer an HTTP request in (`Accept-Language`; English when it names none of
/// ours or is not in `head`).
fn language_of(head: &[u8]) -> Language {
    let head = String::from_utf8_lossy(head);
    Language::of_accept_language(
        head.split("\r\n")
            .skip(1)
            .take_while(|line| !line.is_empty())
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.trim().eq_ignore_ascii_case("accept-language"))
            .map(|(_, value)| value),
    )
}

/// Tell an unserved client why, if it speaks HTTP, and close it.
async fn unavailable(mut stream: TcpStream, why: &Text) {
    let mut head = [0u8; HEAD_PEEK];
    let peeked = tokio::time::timeout(PEEK, async {
        // The request may arrive in more than one piece.
        loop {
            match stream.peek(&mut head).await {
                Ok(n) if n >= 4 => return Some(n),
                Ok(0) | Err(_) => return None,
                Ok(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await;
    if let Ok(Some(n)) = peeked
        && let Some(head) = head.get(..n)
        && looks_like_http(head)
    {
        let body = tr!(
            "VPN Manager: {why}",
            "VPN Manager：{why}",
            "VPN Manager：{why}";
            why = why.clone()
        );
        let body = format!("{}\n", body.get(language_of(head)));
        let resp = format!(
            "HTTP/1.1 503 Service Unavailable\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\nretry-after: 5\r\n\r\n{body}",
            body.len()
        );
        // Best effort: a client that left gets nothing.
        if let Err(e) = stream.write_all(resp.as_bytes()).await {
            tracing::trace!(error = %e, "unserved client not told why");
        }
        // Lingering close: FIN first, then drain what the client already sent (closing with
        // unread input sends a reset, and the client would lose the answer).
        if let Err(e) = stream.shutdown().await {
            tracing::trace!(error = %e, "unserved client's connection not shut down");
        }
        let mut sink = [0u8; 4096];
        let drain = async {
            let mut total = 0usize;
            while let Ok(n) = stream.read(&mut sink).await {
                if n == 0 || total > 64 * 1024 {
                    break;
                }
                total += n;
            }
        };
        if tokio::time::timeout(PEEK, drain).await.is_err() {
            tracing::trace!("unserved client still sending: closed");
        }
    }
}
