//! Who may use a TCP listener of VPN Manager (the web UI and API, an App's local access port).
//!
//! The rule, decided once per connection before a byte of it is read:
//!
//! - A client on this host — its address is loopback, or one of this host's own addresses (such
//!   a connection never left the machine) — is served only when its socket belongs to the user
//!   VPN Manager runs as ([`crate::peer`]: Linux socket tables, macOS libproc). Another user, no
//!   owner found, or a failed lookup: refused (fail closed). An `ssh -L` forward is served: the
//!   user's own sshd session process owns the forwarded connection's socket.
//! - A client on another host is served only when the listener has an allow list and the
//!   client's address is in one of its networks. Without a list, no other host is served.
//! - A client on this host using a non-loopback address must pass both: it is in the list, and
//!   it is this user's.
//!
//! A refusal is closed before anything is read and logged — at most one line a second, the rest
//! counted ([`RefusalLog`]), so a flood of connections cannot flood the log.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;
use vpn_domain::validation::allows_client;
use vpn_domain::{Text, tr};

use crate::peer::PeerOwner;

/// The rules of one listener.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientPolicy {
    /// The user VPN Manager runs as: a client on this host must be one of its programs.
    pub uid: u32,
    /// Networks other hosts may connect from; empty: this host only.
    pub allow: Vec<IpNetwork>,
}

impl ClientPolicy {
    /// This host's programs of user `uid` only.
    #[must_use]
    pub const fn same_user(uid: u32) -> Self {
        Self {
            uid,
            allow: Vec::new(),
        }
    }
}

/// What the OS says about a client.
pub trait HostView: Send + Sync {
    /// The owner of the client end of the connection accepted on `local` from `peer`;
    /// `Ok(None)` when no such socket is found (another user's that cannot be inspected, or
    /// already closed).
    ///
    /// # Errors
    ///
    /// Fails when the OS socket tables (or libproc) cannot be read.
    fn owner(&self, local: SocketAddr, peer: SocketAddr) -> io::Result<Option<PeerOwner>>;
    /// Whether `ip` is one of this host's own addresses.
    ///
    /// # Errors
    ///
    /// Fails when the host's interface addresses cannot be listed.
    fn is_own_address(&self, ip: IpAddr) -> io::Result<bool>;
}

/// The OS itself: socket tables or libproc, and the interfaces' addresses.
#[derive(Debug)]
pub struct OsHost;

impl HostView for OsHost {
    fn owner(&self, local: SocketAddr, peer: SocketAddr) -> io::Result<Option<PeerOwner>> {
        crate::peer::tcp_peer_owner(local, peer)
    }

    fn is_own_address(&self, ip: IpAddr) -> io::Result<bool> {
        Ok(crate::netif::addresses()?
            .iter()
            .any(|a| a.to_canonical() == ip))
    }
}

/// An admitted client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    /// A program of this user on this host.
    Local(PeerOwner),
    /// Another host, from an allowed network.
    Remote,
}

/// Why a client was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Another host, and no allowed network has its address.
    NotAllowed { ip: IpAddr, listed: bool },
    /// A program of another user on this host.
    OtherUser { uid: u32, pid: Option<u32> },
    /// No program of this user holds the client's socket (another user's that cannot be
    /// inspected, or already closed).
    NoOwner,
    /// The owner could not be looked up.
    LookupFailed(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAllowed { ip, listed: false } => {
                write!(f, "{ip} is another host and only this host is served")
            }
            Self::NotAllowed { ip, listed: true } => {
                write!(f, "{ip} is in none of the allowed networks")
            }
            Self::OtherUser { uid, pid } => write!(
                f,
                "it belongs to another user (uid {uid}{})",
                pid.map_or_default(|p| format!(", pid {p}"))
            ),
            Self::NoOwner => {
                f.write_str("no process of this user holds it (another user's, or already closed)")
            }
            Self::LookupFailed(e) => write!(f, "its owner could not be found ({e})"),
        }
    }
}

impl Refusal {
    /// The reason for people, without the address (the caller says whose).
    #[must_use]
    pub fn message(&self) -> Text {
        match self {
            Self::NotAllowed { listed: false, .. } => tr!(
                "From another host; this port accepts only connections from this host",
                "來自其他主機；這個埠只接受這台主機上的連線",
                "ほかのホストからの接続です。このポートはこのホストからの接続だけを受け付けます"
            ),
            Self::NotAllowed { listed: true, .. } => tr!(
                "Not in the networks allowed to connect",
                "不在允許連入的網段",
                "接続を許可するネットワークに含まれていません"
            ),
            Self::OtherUser { uid, .. } => tr!(
                "The connection comes from a program of another user on this host (uid {uid})",
                "連線來自這台主機上其他使用者（uid {uid}）的程式",
                "このホスト上のほかのユーザー（uid {uid}）のプログラムからの接続です"
            ),
            Self::NoOwner => tr!(
                "No program of this user holds this connection (it is another user's, or already closed)",
                "找不到這個使用者持有這條連線的程式（其他使用者的，或已經關閉）",
                "この接続を持つこのユーザーのプログラムが見つかりません（ほかのユーザーのものか、すでに閉じられています）"
            ),
            Self::LookupFailed(e) => tr!(
                "Cannot tell which program the connection comes from ({e})",
                "無法確認連線來自哪個程式（{e}）",
                "接続元のプログラムを確認できません（{e}）"
            ),
        }
    }
}

/// Judge the client of a connection accepted on `local` from `peer`.
///
/// # Errors
///
/// [`Refusal`] when the peer is outside the allow list, belongs to another user of this host,
/// has no owner this user can see, or the owner lookup failed.
pub fn decide(
    policy: &ClientPolicy,
    host: &dyn HostView,
    local: SocketAddr,
    peer: SocketAddr,
) -> Result<Client, Refusal> {
    let ip = peer.ip().to_canonical();
    // Unknown counts as this host: its programs must prove they are this user's.
    let on_this_host = ip.is_loopback() || host.is_own_address(ip).unwrap_or(true);
    if !ip.is_loopback() && !allows_client(&policy.allow, ip) {
        return Err(Refusal::NotAllowed {
            ip,
            listed: !policy.allow.is_empty(),
        });
    }
    if !on_this_host {
        return Ok(Client::Remote);
    }
    match host.owner(local, peer) {
        Ok(Some(owner)) if owner.uid == policy.uid => Ok(Client::Local(owner)),
        Ok(Some(owner)) => Err(Refusal::OtherUser {
            uid: owner.uid,
            pid: owner.pid,
        }),
        Ok(None) => Err(Refusal::NoOwner),
        Err(e) => Err(Refusal::LookupFailed(e.to_string())),
    }
}

/// Whether the web UI may listen on `listen` for other hosts of `allow` (the installation's
/// `--listen-address` and `--allow-client`); why not.
///
/// An address other hosts can reach needs an allow list — nothing but this host is served
/// otherwise, and the user should say so rather than find it out — and loopback has none.
///
/// # Errors
///
/// The reason when `listen` is multicast, loopback is combined with an allow list, a reachable
/// address has no allow list, the list is too long, or a listed network is unusable.
pub fn check_exposure(listen: IpAddr, allow: &[IpNetwork]) -> Result<(), Text> {
    use vpn_domain::validation::{MAX_CLIENT_NETWORKS, client_network_problem};
    if listen.is_multicast() {
        return Err(tr!(
            "--listen-address {listen} is a multicast address and cannot be listened on",
            "--listen-address {listen} 是群播位址，不能監聽",
            "--listen-address {listen} はマルチキャストアドレスのため、待ち受けには使えません"
        ));
    }
    if listen.is_loopback() {
        if !allow.is_empty() {
            return Err(tr!(
                "--allow-client is used only when --listen-address is not a loopback address: when listening only on this host, other hosts cannot connect anyway",
                "--allow-client 只在 --listen-address 不是本機位址時使用：只在本機監聽時，其他主機本來就連不到",
                "--allow-client は --listen-address がループバックアドレスでない場合にだけ使います。このホストだけで待ち受ける場合、ほかのホストはもともと接続できません"
            ));
        }
        return Ok(());
    }
    if allow.is_empty() {
        return Err(tr!(
            "--listen-address {listen} lets other hosts reach the management interface of VPN Manager; list the networks allowed to connect with --allow-client <network> (for example --allow-client 192.168.10.0/24); every other source is refused",
            "--listen-address {listen} 會讓其他主機連到 VPN Manager 的管理介面；請以 --allow-client <網段> 列出允許連入的網段（例如 --allow-client 192.168.10.0/24），其他來源一律拒絕",
            "--listen-address {listen} では、ほかのホストが VPN Manager の管理画面に接続できます。--allow-client <ネットワーク> で接続を許可するネットワークを指定してください（例：--allow-client 192.168.10.0/24）。それ以外の送信元はすべて拒否されます"
        ));
    }
    if allow.len() > MAX_CLIENT_NETWORKS {
        return Err(tr!(
            "--allow-client takes at most {MAX_CLIENT_NETWORKS} networks",
            "--allow-client 最多 {MAX_CLIENT_NETWORKS} 個網段",
            "--allow-client に指定できるネットワークは最大 {MAX_CLIENT_NETWORKS} 個です"
        ));
    }
    for net in allow {
        if let Some(problem) = client_network_problem(net) {
            return Err(tr!(
                "--allow-client {net}: {problem}",
                "--allow-client {net}：{problem}",
                "--allow-client {net}：{problem}";
                problem = problem
            ));
        }
    }
    Ok(())
}

/// A lookup slower than this is logged.
const SLOW_LOOKUP: Duration = Duration::from_millis(100);

/// [`decide`] off the async runtime (the lookup reads OS tables or walks processes); a slow one
/// is logged.
///
/// # Errors
///
/// The same [`Refusal`]s as [`decide`].
pub async fn judge(
    policy: ClientPolicy,
    host: Arc<dyn HostView>,
    local: SocketAddr,
    peer: SocketAddr,
) -> Result<Client, Refusal> {
    let started = Instant::now();
    let decided = tokio::task::spawn_blocking(move || decide(&policy, &*host, local, peer)).await;
    let took = started.elapsed();
    if took > SLOW_LOOKUP {
        tracing::warn!(?took, %peer, "finding the owner of a TCP client was slow");
    } else {
        tracing::trace!(?took, %peer, "TCP client judged");
    }
    decided.unwrap_or_else(|_| Err(Refusal::LookupFailed("the lookup did not finish".into())))
}

/// At most one refusal is logged per this interval (the rest are counted).
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(1);

/// Refusal logging without letting a flood of connections flood the log.
#[derive(Debug)]
pub struct RefusalLog {
    /// What was refused, for the log line ("web UI client", "access port client").
    what: &'static str,
    started: Instant,
    last_ms: AtomicU64,
    suppressed: AtomicU64,
}

impl RefusalLog {
    #[must_use]
    pub fn new(what: &'static str) -> Self {
        Self {
            what,
            started: Instant::now(),
            last_ms: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    /// Log `peer`'s refusal unless one was logged within the interval; returns whether it was.
    pub fn refused(&self, peer: SocketAddr, at: &str, why: &dyn std::fmt::Display) -> bool {
        let now = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX - 1) + 1;
        let last = self.last_ms.load(Ordering::Relaxed);
        let interval = u64::try_from(REFUSAL_LOG_INTERVAL.as_millis()).unwrap_or(u64::MAX);
        let due = last == 0 || now.saturating_sub(last) >= interval;
        if due
            && self
                .last_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let suppressed = self.suppressed.swap(0, Ordering::Relaxed);
            tracing::warn!(%peer, at, suppressed, "refused a {}: {why}", self.what);
            true
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::collections::HashMap;

    use super::*;

    const ME: u32 = 501;

    /// A host with these own addresses and these client sockets.
    struct Fake {
        own: Vec<IpAddr>,
        owners: HashMap<SocketAddr, io::Result<Option<PeerOwner>>>,
        addresses_fail: bool,
    }

    impl Fake {
        fn new(own: &[&str]) -> Self {
            Self {
                own: own.iter().map(|a| a.parse().unwrap()).collect(),
                owners: HashMap::new(),
                addresses_fail: false,
            }
        }

        fn owned(mut self, peer: &str, uid: u32) -> Self {
            self.owners.insert(
                peer.parse().unwrap(),
                Ok(Some(PeerOwner { uid, pid: Some(77) })),
            );
            self
        }

        fn failing(mut self, peer: &str) -> Self {
            self.owners
                .insert(peer.parse().unwrap(), Err(io::Error::other("unreadable")));
            self
        }
    }

    impl HostView for Fake {
        fn owner(&self, _local: SocketAddr, peer: SocketAddr) -> io::Result<Option<PeerOwner>> {
            match self.owners.get(&peer) {
                Some(Ok(o)) => Ok(*o),
                Some(Err(e)) => Err(io::Error::other(e.to_string())),
                None => Ok(None),
            }
        }

        fn is_own_address(&self, ip: IpAddr) -> io::Result<bool> {
            if self.addresses_fail {
                return Err(io::Error::other("no getifaddrs"));
            }
            Ok(self.own.contains(&ip))
        }
    }

    fn policy(allow: &[&str]) -> ClientPolicy {
        ClientPolicy {
            uid: ME,
            allow: allow.iter().map(|n| n.parse().unwrap()).collect(),
        }
    }

    fn judge(p: &ClientPolicy, host: &Fake, peer: &str) -> Result<Client, Refusal> {
        decide(
            p,
            host,
            "192.168.20.100:18765".parse().unwrap(),
            peer.parse().unwrap(),
        )
    }

    #[test]
    fn this_hosts_clients_must_be_this_users() {
        let host = Fake::new(&["127.0.0.1", "192.168.20.100"])
            .owned("127.0.0.1:50000", ME)
            .owned("127.0.0.1:50001", ME + 1)
            .failing("127.0.0.1:50003")
            .owned("[::ffff:127.0.0.1]:50004", ME);
        for p in [policy(&[]), policy(&["192.168.10.0/24"])] {
            assert_matches!(judge(&p, &host, "127.0.0.1:50000"), Ok(Client::Local(_)));
            assert_eq!(
                judge(&p, &host, "127.0.0.1:50001"),
                Err(Refusal::OtherUser {
                    uid: ME + 1,
                    pid: Some(77)
                })
            );
            assert_eq!(judge(&p, &host, "127.0.0.1:50002"), Err(Refusal::NoOwner));
            assert_matches!(
                judge(&p, &host, "127.0.0.1:50003"),
                Err(Refusal::LookupFailed(_))
            );
        }
    }

    #[test]
    fn other_hosts_need_an_allowed_network() {
        let host = Fake::new(&["127.0.0.1", "192.168.20.100"]);
        // Only this host: every other host is refused, whatever its address.
        assert_eq!(
            judge(&policy(&[]), &host, "192.168.10.100:50000"),
            Err(Refusal::NotAllowed {
                ip: "192.168.10.100".parse().unwrap(),
                listed: false
            })
        );
        let lan = policy(&["192.168.10.0/24", "192.168.20.0/24"]);
        assert_eq!(
            judge(&lan, &host, "192.168.10.100:50000"),
            Ok(Client::Remote)
        );
        assert_eq!(
            judge(&lan, &host, "[::ffff:192.168.10.7]:50000"),
            Ok(Client::Remote)
        );
        assert_eq!(
            judge(&lan, &host, "192.168.30.5:50000"),
            Err(Refusal::NotAllowed {
                ip: "192.168.30.5".parse().unwrap(),
                listed: true
            })
        );
        assert_eq!(
            judge(&lan, &host, "[2001:db8::5]:50000"),
            Err(Refusal::NotAllowed {
                ip: "2001:db8::5".parse().unwrap(),
                listed: true
            })
        );
    }

    #[test]
    fn this_host_on_its_lan_address_is_still_checked_for_the_user() {
        let host = Fake::new(&["127.0.0.1", "192.168.20.100"])
            .owned("192.168.20.100:50000", ME)
            .owned("192.168.20.100:50001", ME + 1);
        let lan = policy(&["192.168.20.0/24"]);
        assert_matches!(
            judge(&lan, &host, "192.168.20.100:50000"),
            Ok(Client::Local(_))
        );
        // Another account on this host cannot pass as a LAN client.
        assert_matches!(
            judge(&lan, &host, "192.168.20.100:50001"),
            Err(Refusal::OtherUser { .. })
        );
        assert_eq!(
            judge(&lan, &host, "192.168.20.100:50002"),
            Err(Refusal::NoOwner)
        );
        // Not listed: refused even for this user's own programs.
        assert_matches!(
            judge(&policy(&["192.168.10.0/24"]), &host, "192.168.20.100:50000"),
            Err(Refusal::NotAllowed { listed: true, .. })
        );
        // Interfaces unreadable: every client must prove it is this user's.
        let blind = Fake {
            addresses_fail: true,
            ..Fake::new(&[])
        };
        assert_eq!(
            judge(&lan, &blind, "192.168.20.7:50000"),
            Err(Refusal::NoOwner)
        );
    }

    #[test]
    fn a_reachable_listen_address_needs_an_allow_list() {
        let nets =
            |n: &[&str]| -> Vec<IpNetwork> { n.iter().map(|x| x.parse().unwrap()).collect() };
        let any: IpAddr = "0.0.0.0".parse().unwrap();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(check_exposure(lo, &[]), Ok(()));
        assert_eq!(
            check_exposure(any, &nets(&["192.168.10.0/24", "192.168.20.0/24"])),
            Ok(())
        );
        assert_eq!(
            check_exposure(
                "192.168.20.100".parse().unwrap(),
                &nets(&["192.168.10.0/24"])
            ),
            Ok(())
        );
        let none = check_exposure(any, &[]).unwrap_err();
        assert!(none.zh_tw.contains("--allow-client"), "{}", none.zh_tw);
        assert!(check_exposure(lo, &nets(&["192.168.10.0/24"])).is_err());
        let everything = check_exposure(any, &nets(&["0.0.0.0/0"])).unwrap_err();
        assert!(
            everything.zh_tw.contains("0.0.0.0/0"),
            "{}",
            everything.zh_tw
        );
        assert!(check_exposure("224.0.0.1".parse().unwrap(), &nets(&["192.168.10.0/24"])).is_err());
    }
}
