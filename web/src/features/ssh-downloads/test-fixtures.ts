// Fixtures of the SSH download tests: a job, its status and the view of both.
import type { SshDownloadJob } from "@/api/generated/SshDownloadJob";
import type { SshDownloadStatus } from "@/api/generated/SshDownloadStatus";
import type { SshDownloadView } from "@/api/generated/SshDownloadView";

export const T = "2026-11-06T10:00:00Z";

export function job(p: Partial<SshDownloadJob> = {}): SshDownloadJob {
  return {
    id: "j1",
    name: "NAS downloads",
    gateway_id: "g1",
    host: "files.example.net",
    port: 22,
    user: "puller",
    identity_file: "~/.ssh/id_ed25519",
    key_passphrase: null,
    password: "secret:6f1d2c1a-1111-4222-8333-944455556666",
    source_dir: "/data/todo",
    work_dir: "/data/doing",
    failed_dir: "/data/failed",
    local_dir: "/home/me/incoming",
    connections: 3,
    retries: 3,
    retry_backoff_secs: 5,
    scan_interval_secs: 60,
    name_filter: "all",
    skip_hidden: true,
    record_names: true,
    history_days: null,
    revision: 2,
    created_at: T,
    updated_at: T,
    ...p,
  };
}

export function status(p: Partial<SshDownloadStatus> = {}): SshDownloadStatus {
  return {
    job_id: "j1",
    state: "idle",
    reason: null,
    reason_code: null,
    connections: 1,
    connections_max: 3,
    queued: 0,
    queue_truncated: false,
    unfinished: 0,
    active: [],
    last_scan_at: T,
    next_scan_at: "2026-11-06T10:01:00Z",
    last_scan_skipped: 0,
    next_retry_at: null,
    completed: 4,
    failed: 1,
    bytes: "5242880",
    host_key: { algorithm: "ssh-ed25519", fingerprint: "SHA256:known", seen_at: T },
    offered_host_key: null,
    wire_rx_bytes: "0",
    wire_tx_bytes: "0",
    wire_rx_bps: null,
    wire_tx_bps: null,
    running_since: null,
    observed_at: T,
    ...p,
  };
}

/** A view; `null` for a job whose status the manager did not report. */
export function view(s: Partial<SshDownloadStatus> | null = {}, j: Partial<SshDownloadJob> = {}): SshDownloadView {
  return { job: job(j), status: s === null ? null : status(s) };
}
