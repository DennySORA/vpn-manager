//! The private management connector of one generation, used by the controller for Provider
//! HTTPS (TLS ends in the controller; this side only relays ciphertext).
//!
//! A 0600 Unix socket whose path carries the generation, so a controller still holding an older
//! path can never reach a newer worker. One request per connection: a JSON line of version 2
//! (`vpn_ipc::relay`) carrying a single-use nonce and the route it is meant for. The line is
//! refused before anything is dialed when its nonce was seen before, when it is meant for another
//! Instance or generation, or — for a request a fresh exit check authorized — when this connector
//! or its network epoch moved since that check (the payload gate opened again after an outage).
//! The name is resolved through the tunnel's DNS for exactly that family (no switching between
//! families behind the caller's back), the destination policy and the payload gate apply as for
//! any flow, and the answer `{"ok":true,"peer":"ip:port","epochs":…}` or
//! `{"ok":false,"code":…,"message":…}` precedes the relay.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use vpn_domain::{Text, tr};
use vpn_ipc::relay::{Admission, LINE_MAX, RelayAnswer, RelayFamily, RelayLine, RelayRoute};
use vpn_tunnel::{FlowClass, TunnelConnector};

use crate::dns::{Family, Resolve};
use crate::policy::DestinationPolicy;

/// Concurrent streams; a Provider session needs a handful at most.
pub const MAX_STREAMS: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_BUDGET: Duration = Duration::from_secs(10);
/// A Provider operation session lasts at most 60 s; no stream outlives it.
const SESSION_MAX: Duration = Duration::from_secs(60);
const MAX_ATTEMPTS: usize = 8;

fn refuse(code: &'static str, message: Text) -> RelayAnswer {
    RelayAnswer::refuse(code, message)
}

/// A request line this connector cannot read.
fn malformed() -> Text {
    tr!(
        "Malformed request",
        "請求格式錯誤",
        "リクエストの形式が正しくありません"
    )
}

/// The network epoch of one generation: advanced each time its payload gate opens, so a request
/// authorized by an exit check made before the tunnel was last down is refused here.
#[derive(Debug, Clone, Default)]
pub struct NetworkEpoch(Arc<AtomicU64>);

impl NetworkEpoch {
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    /// The payload gate opened (again).
    pub fn advance(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

/// The listening connector; dropping it stops accepting and removes the socket file.
#[derive(Debug)]
pub struct ConnectorSocket {
    path: PathBuf,
    cancel: CancellationToken,
    /// One permit per open relay (for the control-flow count of the status report).
    slots: Arc<Semaphore>,
}

/// What every line is checked against: the connector's admission (route, nonces, connector
/// epoch) and the generation's network epoch.
#[derive(Clone)]
struct Checks {
    admission: Arc<Admission>,
    network: NetworkEpoch,
}

impl ConnectorSocket {
    /// Provider relays open right now.
    #[must_use]
    pub fn active(&self) -> u64 {
        MAX_STREAMS.saturating_sub(self.slots.available_permits()) as u64
    }

    /// Listen on `path` for lines meant for `route` (this generation).
    ///
    /// # Errors
    ///
    /// Fails if the socket at `path` cannot be bound or its permissions cannot be set to 0600.
    pub fn spawn<C: TunnelConnector, R: Resolve>(
        path: &Path,
        route: RelayRoute,
        network: NetworkEpoch,
        net: C,
        dns: R,
        policy: Arc<DestinationPolicy>,
    ) -> io::Result<Self> {
        remove_socket_file(path);
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let slots = Arc::new(Semaphore::new(MAX_STREAMS));
        let counted = slots.clone();
        let checks = Checks {
            admission: Arc::new(Admission::new(route)),
            network,
        };
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    () = stop.cancelled() => return,
                    r = listener.accept() => r,
                };
                let Ok((stream, _)) = accepted else { continue };
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    let busy = tr!(
                        "Too many connections at once",
                        "同時連線過多",
                        "同時接続数が多すぎます"
                    );
                    tokio::spawn(answer(stream, refuse("BUSY", busy)));
                    continue;
                };
                let (net, dns, policy, stop, checks) = (
                    net.clone(),
                    dns.clone(),
                    policy.clone(),
                    stop.clone(),
                    checks.clone(),
                );
                tokio::spawn(async move {
                    tokio::select! {
                        () = stop.cancelled() => {}
                        _ = tokio::time::timeout(SESSION_MAX, serve(stream, &checks, &net, &dns, &policy)) => {}
                    }
                    drop(permit);
                });
            }
        });
        Ok(Self {
            path: path.to_path_buf(),
            cancel,
            slots: counted,
        })
    }
}

impl Drop for ConnectorSocket {
    fn drop(&mut self) {
        self.cancel.cancel();
        remove_socket_file(&self.path);
    }
}

/// Remove the socket file at `path`, if there is one. A file that cannot be removed only makes a
/// later bind of the same path fail (which reports it); why it stayed is logged here.
fn remove_socket_file(path: &Path) {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != io::ErrorKind::NotFound
    {
        tracing::debug!(error = %e, "connector socket file not removed");
    }
}

/// Send a refusal. A controller that already closed the connection does not need it.
async fn answer(mut stream: UnixStream, reply: RelayAnswer) {
    if let Err(e) = stream.write_all(&reply.to_bytes()).await {
        tracing::trace!(error = %e, "connector answer not delivered: the controller is gone");
    }
}

async fn serve<C: TunnelConnector, R: Resolve>(
    stream: UnixStream,
    checks: &Checks,
    net: &C,
    dns: &R,
    policy: &DestinationPolicy,
) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let read = tokio::time::timeout(
        REQUEST_TIMEOUT,
        (&mut reader).take(LINE_MAX as u64).read_line(&mut line),
    )
    .await;
    let stream = reader.into_inner();
    let epochs = checks.admission.epochs(checks.network.get());
    if !matches!(read, Ok(Ok(n)) if n > 0 && line.ends_with('\n')) {
        return answer(
            stream,
            refuse("BAD_REQUEST", malformed()).with_epochs(epochs),
        )
        .await;
    }
    let request = match checks.admission.admit(line.trim_end(), epochs.network) {
        Ok(r) => r,
        Err(reply) => return answer(stream, reply).await,
    };
    let upstream =
        match tokio::time::timeout(CONNECT_BUDGET, dial(net, dns, policy, &request)).await {
            Ok(Ok(u)) => u,
            Ok(Err(reply)) => return answer(stream, reply.with_epochs(epochs)).await,
            Err(_) => {
                let why = tr!(
                    "Connecting through the tunnel timed out",
                    "經 tunnel 連線逾時",
                    "tunnel 経由の接続がタイムアウトしました"
                );
                let reply = refuse("TIMED_OUT", why).with_epochs(epochs);
                return answer(stream, reply).await;
            }
        };
    // The gate may have closed and opened again while dialing: a request its check authorized
    // must not ride a path that check did not see.
    let network = checks.network.get();
    if let Err(reply) = checks.admission.still_valid(&request, network) {
        return answer(stream, reply).await;
    }
    let (mut tunnel, peer) = upstream;
    let ok = RelayAnswer::connected(peer, checks.admission.epochs(network));
    // The local socket waits out a host short of buffer space (`ENOBUFS`).
    let mut stream = vpn_platform::nobufs::Patient::new(stream);
    if stream.write_all(&ok.to_bytes()).await.is_err() {
        return;
    }
    if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await {
        tracing::debug!(error = %e, "Provider relay ended with an error");
    }
}

async fn dial<C: TunnelConnector, R: Resolve>(
    net: &C,
    dns: &R,
    policy: &DestinationPolicy,
    request: &RelayLine,
) -> Result<(C::Stream, SocketAddr), RelayAnswer> {
    let bare = request.host.trim_start_matches('[').trim_end_matches(']');
    let want_v4 = request.family == RelayFamily::V4;
    let candidates: Vec<IpAddr> = match bare.parse::<IpAddr>() {
        Ok(ip) if ip.is_ipv4() == want_v4 => vec![ip],
        Ok(_) => {
            return Err(refuse(
                "FAMILY_MISMATCH",
                tr!(
                    "The address does not match the requested IP version",
                    "位址與要求的 IP 版本不符",
                    "アドレスが要求された IP バージョンと一致しません"
                ),
            ));
        }
        Err(_) => {
            let family = if want_v4 { Family::V4 } else { Family::V6 };
            match dns.resolve(&request.host, family).await {
                Ok(v) if !v.is_empty() => v,
                Ok(_) => {
                    return Err(refuse(
                        "RESOLVE",
                        tr!(
                            "The name has no address of this IP version",
                            "名稱沒有這個 IP 版本的位址",
                            "この名前にはこの IP バージョンのアドレスがありません"
                        ),
                    ));
                }
                Err(e) => return Err(refuse("RESOLVE", e.text())),
            }
        }
    };
    let mut last = refuse(
        "UNREACHABLE",
        tr!(
            "The tunnel does not carry this address",
            "tunnel 不承載這個位址",
            "tunnel はこのアドレスを通しません"
        ),
    );
    for ip in candidates
        .into_iter()
        .filter(|ip| ip.is_ipv4() == want_v4)
        .take(MAX_ATTEMPTS)
    {
        let dst = SocketAddr::new(ip.to_canonical(), request.port);
        if let Err(denied) = policy.check(dst) {
            last = refuse("DENIED", denied.message());
            continue;
        }
        if !net.supports(dst.ip()) {
            continue;
        }
        match net.connect_tcp(dst, FlowClass::Payload).await {
            Ok(s) => return Ok((s, dst)),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                return Err(refuse(
                    "GATE_CLOSED",
                    tr!(
                        "The connection is not ready or is reconnecting",
                        "連線尚未就緒或正在重新連線",
                        "接続はまだ準備ができていないか、再接続中です"
                    ),
                ));
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::QuotaExceeded | io::ErrorKind::OutOfMemory
                ) =>
            {
                return Err(refuse(
                    "ADMISSION",
                    tr!(
                        "The connection or memory limit is reached",
                        "連線數或記憶體已達上限",
                        "接続数またはメモリが上限に達しています"
                    ),
                ));
            }
            Err(e) => {
                let kind = e.kind();
                last = refuse(
                    "CONNECT",
                    tr!(
                        "Connecting through the tunnel failed: {kind}",
                        "經 tunnel 連線失敗：{kind}",
                        "tunnel 経由の接続に失敗しました：{kind}"
                    ),
                );
            }
        }
    }
    Err(last)
}
