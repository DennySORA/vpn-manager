//! The TCP listener of the web UI and API, which admits each client before reading from it.
//!
//! It serves only programs of the user VPN Manager runs as, the rule `api.sock` enforces with peer credentials — and, only when installed with
//! `--listen-address` and `--allow-client`, other hosts of the allowed networks.
//!
//! The browser checks (Host, Origin, Fetch-Metadata) stop web pages from driving the API; they
//! cannot stop another local account, which can send any header it likes. So before a single
//! byte of a TCP connection is read, its client is judged ([`vpn_platform::admission`]): a
//! client on this host (loopback, or one of this host's own addresses) is served only when the
//! OS socket tables say its socket is this user's; a client on another host only when its
//! address is in an allowed network. Anything else — another user, no owner found (the client
//! is gone, or invisible to us), a failed lookup, a host outside the list — is closed unserved
//! and logged. The decision is made once per connection; keep-alive requests and event streams on
//! it reuse it.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use vpn_platform::admission::{self, ClientPolicy, HostView, OsHost, RefusalLog};
use vpn_platform::peer::PeerOwner;

/// Finds the owner of the client end of a connection accepted on `local` from `peer`.
pub type PeerLookup =
    Arc<dyn Fn(SocketAddr, SocketAddr) -> io::Result<Option<PeerOwner>> + Send + Sync>;

/// The OS lookup.
pub fn os_lookup() -> PeerLookup {
    Arc::new(vpn_platform::peer::tcp_peer_owner)
}

/// The OS, with socket owners found by `lookup` (tests put their own in).
struct WithLookup(PeerLookup);

impl HostView for WithLookup {
    fn owner(&self, local: SocketAddr, peer: SocketAddr) -> io::Result<Option<PeerOwner>> {
        (self.0)(local, peer)
    }

    fn is_own_address(&self, ip: IpAddr) -> io::Result<bool> {
        OsHost.is_own_address(ip)
    }
}

/// Lookups at the same time (each one may walk this user's processes).
const CONCURRENT_LOOKUPS: usize = 4;
/// Approved connections waiting for the server to take them.
const APPROVED_QUEUE: usize = 64;

/// Accepts on its listeners, judges each client, and hands over only the admitted ones.
#[derive(Debug)]
pub struct SameUserTcpListener {
    approved: mpsc::Receiver<(TcpStream, SocketAddr)>,
    local: SocketAddr,
    accept_tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl SameUserTcpListener {
    /// This host's programs of user `uid` only, owners found by `lookup`.
    ///
    /// # Errors
    ///
    /// When the listener's local address cannot be read.
    pub fn new(inner: TcpListener, uid: u32, lookup: PeerLookup) -> io::Result<Self> {
        Self::with_policy(
            vec![inner],
            ClientPolicy::same_user(uid),
            Arc::new(WithLookup(lookup)),
        )
    }

    /// Serve `inners` (the first one's address is reported) to the clients `policy` admits.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when `inners` is empty, and the error of reading the first listener's
    /// local address.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the policy and the host view are handed over like the listeners; each accept task gets its own clone"
    )]
    pub fn with_policy(
        inners: Vec<TcpListener>,
        policy: ClientPolicy,
        host: Arc<dyn HostView>,
    ) -> io::Result<Self> {
        let local = inners
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no listener"))?
            .local_addr()?;
        let (tx, approved) = mpsc::channel(APPROVED_QUEUE);
        let lookups = Arc::new(Semaphore::new(CONCURRENT_LOOKUPS));
        let log = Arc::new(RefusalLog::new("web UI client"));
        let accept_tasks = inners
            .into_iter()
            .map(|inner| {
                tokio::spawn(accept_loop(
                    inner,
                    policy.clone(),
                    host.clone(),
                    lookups.clone(),
                    log.clone(),
                    tx.clone(),
                ))
            })
            .collect();
        Ok(Self {
            approved,
            local,
            accept_tasks,
        })
    }
}

impl Drop for SameUserTcpListener {
    fn drop(&mut self) {
        for task in &self.accept_tasks {
            task.abort();
        }
    }
}

async fn accept_loop(
    inner: TcpListener,
    policy: ClientPolicy,
    host: Arc<dyn HostView>,
    lookups: Arc<Semaphore>,
    log: Arc<RefusalLog>,
    tx: mpsc::Sender<(TcpStream, SocketAddr)>,
) {
    let at = inner.local_addr().map_or_default(|a| a.to_string());
    loop {
        let accepted = tokio::select! {
            r = inner.accept() => r,
            // Nobody takes connections any more (the server stopped).
            () = tx.closed() => return,
        };
        let (stream, peer) = match accepted {
            Ok(a) => a,
            Err(e) => {
                // Out of descriptors and the like: back off instead of spinning.
                tracing::debug!(error = %e, "TCP accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = lookups.clone().acquire_owned().await else {
            return;
        };
        let (tx, host, log, policy, at) = (
            tx.clone(),
            host.clone(),
            log.clone(),
            policy.clone(),
            at.clone(),
        );
        tokio::spawn(async move {
            let _permit = permit;
            let local = match stream.local_addr() {
                Ok(l) => l,
                Err(e) => {
                    log.refused(peer, &at, &format!("its local address is unknown ({e})"));
                    return;
                }
            };
            match admission::judge(policy, host, local, peer).await {
                // The server may be gone meanwhile; the stream then just closes.
                Ok(_) => {
                    if tx.send((stream, peer)).await.is_err() {
                        tracing::debug!(%peer, "admitted client closed: the server stopped");
                    }
                }
                Err(refusal) => {
                    log.refused(peer, &at, &refusal);
                }
            }
            // A refused stream is dropped here: closed before anything was read from it.
        });
    }
}

impl axum::serve::Listener for SameUserTcpListener {
    type Io = TcpStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.approved.recv().await {
            Some(next) => next,
            // The accept loops ended: no connection will come any more.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}
