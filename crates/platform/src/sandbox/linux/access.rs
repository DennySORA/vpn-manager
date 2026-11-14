//! Local access ports of a sandboxed App: the relay inside the sandbox and the manager's end of
//! it.
//!
//! The manager holds the host's listener of each access port (host network namespace), admits
//! each connection (this user's programs; other hosts only from allowed networks) and hands the
//! accepted socket over the App launcher's control socket (`SCM_RIGHTS`) to the App's relay: a
//! process the launcher forks once the App runs, in the sandbox's network namespace (and its
//! pid namespace, beside the App's tree: the App cannot see it). The relay connects to the App's
//! port on the sandbox's loopback — only a port the App was started with — and relays bytes both
//! ways until both directions have ended (half-close kept). It never listens, and it never
//! connects anywhere else; a connection it is handed is in the host's namespace, a connection it
//! makes is in the sandbox's, and the two only meet as byte streams in this process. It holds no
//! capability, relays at most [`MAX_RELAYS`] connections at once, and ends with the App: it is
//! killed the moment the launcher exits, which is when the App's tree is gone.
#![allow(
    unsafe_code,
    reason = "this module owns the access-port forwarder fork and its fd and prctl setup via libc"
)]

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;
use vpn_domain::{Text, tr};

use super::{caps, wire};
use crate::sandbox::AccessReport;

/// Most connections one App's launcher relays at once; more are closed at once.
pub const MAX_RELAYS: usize = 256;
/// How long the App gets to accept a relayed connection.
const APP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Manager → launcher.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum AccessMsg {
    /// Relay this connection (the message's one descriptor) to the App's `port`.
    Connection { port: u16 },
}

/// `fd`, non-blocking, registered with the current runtime for reading.
fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    set_nonblocking(fd.as_raw_fd())?;
    // SAFETY: an `OwnedFd` stays open until the `AsyncFd` owning it is dropped.
    unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }.map_err(io::Error::from)
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor we hold.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// One message from a non-blocking socket registered with the runtime; `None` at its end.
async fn receive(fd: &AsyncFd<OwnedFd>) -> Option<wire::Received> {
    loop {
        let mut ready = fd.readable().await.ok()?;
        match ready.try_io(|fd| wire::recv(fd.get_ref().as_raw_fd())) {
            Ok(Ok(r)) => return r,
            Ok(Err(e)) if e.kind() == io::ErrorKind::InvalidData => {
                // A malformed message: dropped (its descriptors close), the next one is read.
            }
            Ok(Err(_)) => return None,
            Err(_would_block) => {}
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The manager's end
// ---------------------------------------------------------------------------------------------

/// The manager's end of a running App launcher's control socket: connections for the App go
/// out on it, and the launcher tells how each went.
pub struct AccessChannel {
    fd: AsyncFd<OwnedFd>,
}

impl AccessChannel {
    /// Take over the control socket once the App runs (within a tokio runtime).
    pub(crate) fn new(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self { fd: register(fd)? })
    }

    /// Hand `conn` to the launcher for the App's `port`. Never waits: a launcher that does not
    /// keep up refuses it (`WouldBlock`), one that is gone fails it.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::WouldBlock`] when the launcher's socket is full, any other error when the
    /// launcher is gone.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "taking `conn` closes our copy of the descriptor once it is sent"
    )]
    pub fn send(&self, port: u16, conn: OwnedFd) -> io::Result<()> {
        wire::send_json(
            self.fd.get_ref().as_raw_fd(),
            &AccessMsg::Connection { port },
            &[conn.as_raw_fd()],
        )
        // `conn` closes here: the launcher holds its own copy.
    }

    /// The launcher's next report; `None` once it is gone.
    pub async fn report(&self) -> Option<AccessReport> {
        loop {
            let received = receive(&self.fd).await?;
            // Reports carry no descriptor; anything that is not a report is skipped.
            if let Ok(r) = serde_json::from_slice::<AccessReport>(&received.data) {
                return Some(r);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The launcher's end
// ---------------------------------------------------------------------------------------------

/// Start relaying for the App: a child process of the launcher takes `control`, and relays the
/// connections the manager sends on it to `ports` on this network namespace's loopback (the
/// sandbox's). Not a thread: the launcher joined the sandbox's pid namespace for what it starts,
/// and from then on the kernel refuses it a thread (`CLONE_THREAD` after `setns(CLONE_NEWPID)`);
/// a child is in that namespace already. Must be called while the launcher has no thread.
/// `last_cap`: read while the host's `/proc` was still in view.
pub fn start_relay(control: OwnedFd, ports: Vec<u16>, last_cap: u32) -> io::Result<()> {
    // SAFETY: fork in a single-threaded process; the child only runs the relay and `_exit`s.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid > 0 {
        // The launcher: the child holds the control socket now.
        drop(control);
        return Ok(());
    }
    let code = relay_process(control, ports, last_cap);
    // SAFETY: _exit is always safe; nothing of the launcher's state is unwound here.
    unsafe { libc::_exit(code) }
}

/// The relay process: dies with the launcher, keeps only the control socket and stdio, holds no
/// capability, and serves until the manager's end closes and every relayed connection ended.
fn relay_process(control: OwnedFd, ports: Vec<u16>, last_cap: u32) -> i32 {
    // SAFETY: prctl and getppid with constant arguments.
    unsafe {
        if libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        ) < 0
        {
            return 1;
        }
        // The launcher is outside the sandbox's pid namespace, where this process is: seen from
        // here its pid is 0 while it lives. Anything else is the sandbox's init, which took this
        // process over because the launcher ended before the death signal was armed.
        if libc::getppid() != 0 {
            return 0;
        }
        // How it shows in the App's process list.
        libc::prctl(libc::PR_SET_NAME, c"access-relay".as_ptr(), 0, 0, 0);
    }
    // Nothing of the launcher's but stdio (its log) and the control socket: no report socket, no
    // signal or process descriptor. Its stack is never unwound here (the process `_exit`s), so
    // nothing closes them twice.
    let ctl = control.as_raw_fd();
    for fd in 3..1024 {
        if fd != ctl {
            // SAFETY: closing a descriptor number this process may hold; errors are irrelevant.
            unsafe {
                libc::close(fd);
            }
        }
    }
    if let Err(e) = caps::drop_all(last_cap) {
        super::app::log_line(&format!(
            "local access ports are not enabled: cannot drop privileges ({e})"
        ));
        return 1;
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            super::app::log_line(&format!("local access ports are not enabled: {e}"));
            return 1;
        }
    };
    runtime.block_on(relay(control, ports));
    0
}

fn report(ctl: &AsyncFd<OwnedFd>, r: &AccessReport) {
    // Best effort: a manager that does not read only misses the news.
    let _ = wire::send_json(ctl.get_ref().as_raw_fd(), r, &[]);
}

async fn relay(control: OwnedFd, ports: Vec<u16>) {
    let ctl = match register(control) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            super::app::log_line(&format!("local access ports are not enabled: {e}"));
            return;
        }
    };
    let limit = Arc::new(Semaphore::new(MAX_RELAYS));
    let tracker = TaskTracker::new();
    while let Some(received) = receive(&ctl).await {
        let Ok(AccessMsg::Connection { port }) = serde_json::from_slice(&received.data) else {
            continue;
        };
        let mut fds = received.fds;
        let (Some(conn), true) = (fds.pop(), fds.is_empty()) else {
            continue;
        };
        if !ports.contains(&port) {
            report(
                &ctl,
                &AccessReport::Failed {
                    port,
                    message: tr!(
                        "The app had no local access port for port {port} when it started; it opens after the app restarts",
                        "App 啟動時沒有 port {port} 的本機存取埠；重新啟動 App 後才會開放",
                        "アプリの起動時にポート {port} のローカルアクセスポートはありませんでした。アプリを再起動すると開きます"
                    ),
                },
            );
            continue;
        }
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            report(
                &ctl,
                &AccessReport::Failed {
                    port,
                    message: tr!(
                        "The relayed connections are at their limit ({MAX_RELAYS}); this connection was closed",
                        "同時轉送的連線已達上限（{MAX_RELAYS}），這條連線已關閉",
                        "同時に中継する接続数が上限（{MAX_RELAYS}）に達したため、この接続を閉じました"
                    ),
                },
            );
            continue;
        };
        let ctl = ctl.clone();
        tracker.spawn(async move {
            let _permit = permit;
            serve(conn, port, &ctl).await;
        });
    }
    // The manager is gone, or ended the App: what is open runs to its end (the launcher exits
    // with the App anyway).
    tracker.close();
    tracker.wait().await;
}

/// The App's own loopback: IPv4 first, then IPv6 (an App that listens on `::1` only).
async fn connect_app(port: u16) -> io::Result<TcpStream> {
    let v4 = tokio::time::timeout(
        APP_CONNECT_TIMEOUT,
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)),
    )
    .await;
    match v4 {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
            match tokio::time::timeout(
                APP_CONNECT_TIMEOUT,
                TcpStream::connect((Ipv6Addr::LOCALHOST, port)),
            )
            .await
            {
                Ok(Ok(s)) => Ok(s),
                _ => Err(e),
            }
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(tr!(
            "The app did not accept the connection in time",
            "App 沒有在時間內接受連線",
            "アプリが時間内に接続を受け付けませんでした"
        )
        .into_io_error(io::ErrorKind::TimedOut)),
    }
}

async fn serve(conn: OwnedFd, port: u16, ctl: &AsyncFd<OwnedFd>) {
    let client = std::net::TcpStream::from(conn);
    let client = match client
        .set_nonblocking(true)
        .and_then(|()| TcpStream::from_std(client))
    {
        Ok(c) => c,
        Err(e) => {
            report(
                ctl,
                &AccessReport::Failed {
                    port,
                    message: tr!(
                        "Cannot take over the connection: {e}",
                        "無法接手連線：{e}",
                        "接続を引き継げません：{e}";
                        e = Text::of_io_error(&e)
                    ),
                },
            );
            return;
        }
    };
    let mut client = client;
    match connect_app(port).await {
        Ok(mut app) => {
            report(ctl, &AccessReport::Relayed { port });
            // Interactive traffic (a web UI, an API): latency over coalescing.
            let _ = client.set_nodelay(true);
            let _ = app.set_nodelay(true);
            // EOF one way shuts down the write side the other way; the other direction goes
            // on until it ends too. An error either way ends both.
            let _ = tokio::io::copy_bidirectional(&mut client, &mut app).await;
        }
        Err(e) => report(
            ctl,
            &AccessReport::Failed {
                port,
                message: tr!(
                    "The app did not accept the relayed connection (127.0.0.1:{port} in the sandbox: {e})",
                    "App 沒有接受轉送的連線（沙箱內 127.0.0.1:{port}：{e}）",
                    "アプリが中継された接続を受け付けませんでした（サンドボックス内の 127.0.0.1:{port}：{e}）";
                    e = Text::of_io_error(&e)
                ),
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Both ends in one process (the "sandbox" is this test's own network namespace): the
    /// manager's end hands over an accepted connection, the relay reaches the App's port only.
    #[tokio::test]
    async fn connections_reach_only_the_apps_ports_both_ways_with_half_close() {
        let (mine, theirs) = wire::seqpacket_pair().unwrap();
        // The App: an echo server that answers after the client's EOF (half-close).
        let app = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let app_port = app.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = app.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut got = Vec::new();
                    s.read_to_end(&mut got).await.unwrap();
                    s.write_all(b"echo:").await.unwrap();
                    s.write_all(&got).await.unwrap();
                });
            }
        });
        let unused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = unused.local_addr().unwrap().port();
        drop(unused);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(relay(theirs, vec![app_port, closed_port]));
        });
        let channel = AccessChannel::new(mine).unwrap();

        // The host side: a listener the manager accepted a client on.
        let host = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host_addr = host.local_addr().unwrap();
        let mut client = TcpStream::connect(host_addr).await.unwrap();
        let (accepted, _) = host.accept().await.unwrap();
        channel
            .send(app_port, OwnedFd::from(accepted.into_std().unwrap()))
            .unwrap();
        assert_eq!(
            channel.report().await,
            Some(AccessReport::Relayed { port: app_port })
        );
        client.write_all(b"hello").await.unwrap();
        client.shutdown().await.unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut answer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(answer, b"echo:hello");

        // A port the App was not started with is never dialed.
        let mut other = TcpStream::connect(host_addr).await.unwrap();
        let (accepted, _) = host.accept().await.unwrap();
        channel
            .send(9, OwnedFd::from(accepted.into_std().unwrap()))
            .unwrap();
        assert_matches!(
            channel.report().await,
            Some(AccessReport::Failed { port: 9, .. })
        );
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), other.read(&mut buf))
            .await
            .unwrap();
        assert_matches!(read, Ok(0) | Err(_));

        // Nothing listens on the App's port: said so, and the client is closed.
        let mut refused = TcpStream::connect(host_addr).await.unwrap();
        let (accepted, _) = host.accept().await.unwrap();
        channel
            .send(closed_port, OwnedFd::from(accepted.into_std().unwrap()))
            .unwrap();
        match channel.report().await {
            Some(AccessReport::Failed { port, message }) => {
                assert_eq!(port, closed_port);
                assert!(message.zh_tw.contains("App 沒有接受"), "{}", message.zh_tw);
            }
            other => panic!("{other:?}"),
        }
        let read = tokio::time::timeout(Duration::from_secs(5), refused.read(&mut buf))
            .await
            .unwrap();
        assert_matches!(read, Ok(0) | Err(_));

        // The manager's end gone: the relay ends (no more reports, the launcher's end closes).
        drop(channel);
    }
}
