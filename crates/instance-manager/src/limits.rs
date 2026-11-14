//! The OS limits of a connection's worker.
//!
//! Its cgroup's memory limit is the connection's buffer
//! budget (`memory_mib`, what the netstack may hold in socket buffers) plus a fixed overhead for
//! everything else a worker holds; its task limit leaves room for the runtime's threads.

use vpn_domain::{InstanceLimits, LimitKind, ResourceStatus, Text, Timestamp, UnenforcedLimit, tr};
use vpn_platform::limits::{Leaf, ResourceControl, TreeLimits};

const MIB: u64 = 1024 * 1024;

/// What a worker holds besides its connection buffers.
///
/// That is the program and its runtime threads, the
/// IP queues between `GotaTun` and the netstack (at most 4 MiB each way), relay buffers, the DNS
/// cache, a blocklist overlay of up to 16 MiB while the frame carrying the next one (24 MiB at
/// most) is decoded, and the kernel's socket buffers of its Gateway clients.
pub const WORKER_OVERHEAD_MIB: u64 = 256;

/// The limits of a worker's cgroup: memory = budget + overhead (swap not used), tasks = 64 plus
/// two per CPU (the runtime starts one thread per CPU).
#[must_use]
pub fn worker_tree(l: &InstanceLimits) -> TreeLimits {
    let cpus = u64::from(vpn_platform::resources::logical_cpus());
    TreeLimits {
        memory_bytes: Some((u64::from(l.memory_mib) + WORKER_OVERHEAD_MIB) * MIB),
        tasks: Some(64 + 2 * cpus),
        cpu_percent: None,
    }
}

/// The confinement of a worker that has no cgroup: its memory and task limits are not in force,
/// and why.
#[must_use]
pub fn without_cgroup(rc: &ResourceControl, reason: Option<&Text>) -> ResourceStatus {
    let why = |kind| {
        reason
            .cloned()
            .or_else(|| rc.unavailable(kind))
            .unwrap_or_else(|| {
                tr!(
                    "No cgroup was created",
                    "沒有建立 cgroup",
                    "cgroup は作成されていません"
                )
            })
    };
    ResourceStatus {
        cgroup: None,
        enforced: Vec::new(),
        unenforced: [LimitKind::Memory, LimitKind::Processes]
            .into_iter()
            .map(|kind| UnenforcedLimit {
                kind,
                reason: why(kind),
            })
            .collect(),
        memory_bytes: None,
        oom_kills: None,
        observed_at: Timestamp::now(),
    }
}

/// The status of a worker in `leaf`; `placed`: the process was confirmed inside it.
#[must_use]
pub fn in_leaf(leaf: &Leaf, placed: bool) -> ResourceStatus {
    let mut s = leaf.status();
    if !placed {
        let moved = std::mem::take(&mut s.enforced);
        s.unenforced
            .extend(moved.into_iter().map(|e| UnenforcedLimit {
                kind: e.kind,
                reason: tr!(
                    "The worker process did not enter its cgroup",
                    "worker 程序沒有進入它的 cgroup",
                    "worker プロセスが自分の cgroup に入っていません"
                ),
            }));
        s.memory_bytes = None;
        s.oom_kills = None;
    }
    s
}
