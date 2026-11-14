//! Manager side of one worker process: spawn, handshake, configure, event stream, stop.

use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UnixStream;
use tokio::process::Child;
use tokio::sync::mpsc;
use vpn_domain::{Text, tr};
use vpn_ipc::frame::{DEFAULT_MAX_FRAME, FrameReader, FrameWriter, split_with};
use vpn_ipc::identity;
use vpn_ipc::worker::{FromWorker, TO_WORKER_MAX_FRAME, ToWorker, WORKER_PROTOCOL, WorkerConfig};
use vpn_platform::process::spawn_worker;

use crate::inventory::{Inventory, WorkerTicket};

#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    #[error("could not start the worker process: {0}")]
    Spawn(std::io::Error),
    #[error("worker protocol error: {0}")]
    Protocol(String),
    #[error("worker refused: {code}: {}", .message.en)]
    Refused { code: String, message: Text },
    #[error("worker did not answer in time")]
    Timeout,
}

impl SpawnError {
    /// What a person reads about the start that failed (`Display` is the English of the log).
    #[must_use]
    pub fn text(&self) -> Text {
        match self {
            Self::Spawn(e) => tr!(
                "Could not start the worker process: {e}",
                "無法啟動 worker 程序：{e}",
                "worker プロセスを起動できませんでした：{e}";
                e = Text::of_io_error(e)
            ),
            Self::Protocol(detail) => tr!(
                "Worker protocol error: {detail}",
                "worker 通訊協定錯誤：{detail}",
                "worker のプロトコルエラー：{detail}"
            ),
            Self::Refused { code, message } => tr!(
                "The worker refused: {code}: {message}",
                "worker 拒絕：{code}：{message}",
                "worker が拒否しました：{code}：{message}";
                message = message.clone()
            ),
            Self::Timeout => tr!(
                "The worker did not answer in time",
                "worker 沒有及時回應",
                "worker が時間内に応答しませんでした"
            ),
        }
    }
}

pub enum WorkerEvent {
    Msg(FromWorker),
    /// The control socket closed (worker exited or crashed).
    Closed,
}

pub struct WorkerHandle {
    pub pid: u32,
    child: Child,
    tx: FrameWriter,
    pub events: mpsc::Receiver<WorkerEvent>,
    /// Keeps the worker in the inventory until the handle goes — after the reap.
    _ticket: WorkerTicket,
}

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const CONFIGURE_TIMEOUT: Duration = Duration::from_secs(15);

/// The Hello exchange and the configuration, each within its timeout.
async fn handshake(
    rx: &mut FrameReader,
    tx: &mut FrameWriter,
    config: WorkerConfig,
    listener_fds: &[OwnedFd],
) -> Result<(), SpawnError> {
    let first = tokio::time::timeout(HELLO_TIMEOUT, rx.recv::<FromWorker>())
        .await
        .map_err(|_| SpawnError::Timeout)?
        .map_err(|e| SpawnError::Protocol(e.to_string()))?;
    match first {
        Some((
            FromWorker::Hello {
                protocol, build_id, ..
            },
            _,
        )) => {
            if protocol != WORKER_PROTOCOL || build_id != identity::build_id() {
                return Err(SpawnError::Protocol(format!(
                    "worker build {build_id} (protocol {protocol}) does not match manager build {} — restart the manager after upgrades",
                    identity::build_id()
                )));
            }
        }
        _ => return Err(SpawnError::Protocol("expected Hello".into())),
    }
    tx.send(
        &ToWorker::Hello {
            protocol: WORKER_PROTOCOL,
            build_id: identity::build_id().to_string(),
        },
        &[],
    )
    .await
    .map_err(|e| SpawnError::Protocol(e.to_string()))?;
    let fds: Vec<_> = listener_fds.iter().map(|f| f.as_fd()).collect();
    tx.send(&ToWorker::Configure(Box::new(config)), &fds)
        .await
        .map_err(|e| SpawnError::Protocol(e.to_string()))?;
    let reply = tokio::time::timeout(CONFIGURE_TIMEOUT, rx.recv::<FromWorker>())
        .await
        .map_err(|_| SpawnError::Timeout)?
        .map_err(|e| SpawnError::Protocol(e.to_string()))?;
    match reply {
        Some((FromWorker::Configured, _)) => Ok(()),
        Some((FromWorker::Fatal { code, message }, _)) => {
            Err(SpawnError::Refused { code, message })
        }
        Some(_) => Err(SpawnError::Protocol("expected Configured".into())),
        None => Err(SpawnError::Protocol(
            "worker exited during configure".into(),
        )),
    }
}

/// Start a worker. With `sandbox` (Linux strict mode) it joins the sandbox's user and network
/// namespaces before it runs; `listener_fds` then also carry the sandbox's descriptors.
/// `cgroup_procs`: the worker's cgroup (`Leaf::procs_fd`), joined before `exec`.
pub async fn spawn(
    exe: &Path,
    config: WorkerConfig,
    listener_fds: &[OwnedFd],
    sandbox: Option<&vpn_platform::sandbox::WorkerEntry>,
    inventory: &Arc<Inventory>,
    cgroup_procs: Option<std::os::fd::RawFd>,
) -> Result<WorkerHandle, SpawnError> {
    let (parent, child_end) = StdUnixStream::pair().map_err(SpawnError::Spawn)?;
    let control = OwnedFd::from(child_end);
    let child = match sandbox {
        None => spawn_worker(exe, ["instance"], control, cgroup_procs),
        #[cfg(target_os = "linux")]
        Some(entry) => vpn_platform::process::spawn_with_control_fd_in(
            exe,
            ["instance"],
            control,
            entry,
            cgroup_procs,
        ),
        #[cfg(not(target_os = "linux"))]
        Some(_) => {
            Err(vpn_platform::sandbox::unsupported().into_io_error(std::io::ErrorKind::Unsupported))
        }
    };
    let mut child = child.map_err(SpawnError::Spawn)?;
    let pid = child.id().unwrap_or(0);
    // Recorded before the first await: from now on a recovery knows this child is ours.
    let ticket = inventory.spawned(
        pid,
        config.instance_id,
        config.generation,
        config.key_lock_path.clone(),
        config.connector_path.clone(),
    );
    parent.set_nonblocking(true).map_err(SpawnError::Spawn)?;
    let stream = UnixStream::from_std(parent).map_err(SpawnError::Spawn)?;
    // Configure and SetOverlay may carry a 16 MiB blocklist overlay; a worker's own frames stay
    // small (a misbehaving worker cannot make the manager hold a large frame).
    let (mut rx, mut tx) = split_with(stream, DEFAULT_MAX_FRAME, TO_WORKER_MAX_FRAME);

    let result = handshake(&mut rx, &mut tx, config, listener_fds).await;

    if let Err(e) = result {
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        return Err(e);
    }

    let (ev_tx, ev_rx) = mpsc::channel(128);
    tokio::spawn(async move {
        loop {
            if let Ok(Some((msg, _))) = rx.recv::<FromWorker>().await {
                // Status samples may be dropped under pressure; lifecycle events never are.
                if matches!(msg, FromWorker::Status(_)) {
                    let _ = ev_tx.try_send(WorkerEvent::Msg(msg));
                } else if ev_tx.send(WorkerEvent::Msg(msg)).await.is_err() {
                    return;
                }
            } else {
                let _ = ev_tx.send(WorkerEvent::Closed).await;
                return;
            }
        }
    });
    Ok(WorkerHandle {
        pid,
        child,
        tx,
        events: ev_rx,
        _ticket: ticket,
    })
}

impl WorkerHandle {
    /// Send a message. One that cannot be sent (the host out of buffers past the wait the frame
    /// gives it, a broken socket) ends the worker: it would otherwise run on with a state the
    /// manager no longer knows — a gate it did not tighten, a lease it did not revoke — while the
    /// manager waits for a `Closed` event that never comes. Ended, it fails closed and its
    /// `Closed` event follows; the generation is replaced.
    pub async fn send(&mut self, msg: &ToWorker) -> std::io::Result<()> {
        let sent = self.tx.send(msg, &[]).await;
        self.ended_unless_sent(&sent);
        sent
    }

    /// Send a message whose descriptors travel with it (`AddGateway`, `Relay`); as [`Self::send`].
    pub async fn send_with_fds(
        &mut self,
        msg: &ToWorker,
        fds: &[std::os::fd::BorrowedFd<'_>],
    ) -> std::io::Result<()> {
        let sent = self.tx.send(msg, fds).await;
        self.ended_unless_sent(&sent);
        sent
    }

    fn ended_unless_sent(&mut self, sent: &std::io::Result<()>) {
        if let Err(e) = sent {
            tracing::warn!(pid = self.pid, error = %e, "a message could not reach the worker: ending it");
            let _ = self.child.start_kill();
        }
    }

    /// Ask the worker to stop, then make sure the process is gone (killed after `grace`).
    /// Returns once the process has been reaped — the proof its descriptors are closed.
    pub async fn stop(mut self, grace: Duration) {
        let _ = self
            .tx
            .send(
                &ToWorker::Stop {
                    grace_ms: grace.as_millis().min(2000) as u32,
                },
                &[],
            )
            .await;
        if tokio::time::timeout(grace + Duration::from_secs(2), self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.start_kill();
            let _ = self.child.wait().await;
        }
    }

    /// Kill immediately and reap.
    pub async fn kill(mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use vpn_domain::InstanceId;

    use super::*;

    /// A message that does not reach a running worker ends that worker, so its `Closed` event
    /// really follows instead of the manager waiting for it while the worker runs on with a state
    /// the manager no longer knows.
    #[tokio::test]
    async fn a_message_that_cannot_reach_the_worker_ends_it() {
        let dir = tempfile::tempdir().unwrap();
        let inventory = Inventory::new(dir.path().join("workers"));
        // Stands in for a worker that is running fine.
        let child = tokio::process::Command::new("sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let ticket = inventory.spawned(pid, InstanceId::new(), 1, "/x/key.lock".into(), None);
        // A control socket the message cannot go through.
        let (ours, theirs) = StdUnixStream::pair().unwrap();
        drop(theirs);
        ours.set_nonblocking(true).unwrap();
        let (_rx, tx) = split_with(
            UnixStream::from_std(ours).unwrap(),
            DEFAULT_MAX_FRAME,
            TO_WORKER_MAX_FRAME,
        );
        let (_events_tx, events) = mpsc::channel(1);
        let mut handle = WorkerHandle {
            pid,
            child,
            tx,
            events,
            _ticket: ticket,
        };
        assert!(handle.send(&ToWorker::Start).await.is_err());
        let status = tokio::time::timeout(Duration::from_secs(5), handle.child.wait())
            .await
            .expect("the worker was ended")
            .unwrap();
        assert!(!status.success());
    }
}
