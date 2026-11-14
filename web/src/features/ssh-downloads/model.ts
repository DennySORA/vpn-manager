// SSH download (/ssh-downloads): the job's states as words, the list's filters and orders, progress as text, and the
// dialog's form rules — the same rules the server applies (crates/domain/src/ssh_download.rs). Pure.
import {
  ArrowDownToLine,
  CircleCheck,
  Clock,
  FolderSearch,
  LoaderCircle,
  OctagonX,
  Pause,
  RefreshCw,
  ShieldEllipsis,
  TriangleAlert,
} from "lucide-react";
import type { GatewaySpec } from "@/api/generated/GatewaySpec";
import type { SshDownloadActive } from "@/api/generated/SshDownloadActive";
import type { SshDownloadInput } from "@/api/generated/SshDownloadInput";
import type { SshDownloadJob } from "@/api/generated/SshDownloadJob";
import type { SshDownloadNameFilter } from "@/api/generated/SshDownloadNameFilter";
import type { SshDownloadState } from "@/api/generated/SshDownloadState";
import type { SshDownloadStep } from "@/api/generated/SshDownloadStep";
import type { SshDownloadTransferState } from "@/api/generated/SshDownloadTransferState";
import type { SshDownloadView } from "@/api/generated/SshDownloadView";
import { m as ui } from "@/components/ui/messages";
import { intlLocale } from "@/i18n";
import { formatBytes, relativeTime } from "@/lib/format";
import { type StateLook, type Tone, UNKNOWN_STATE } from "@/lib/status";
import { m as dialog } from "./dialog/messages";
import { m } from "./messages";

export const STATE: Record<SshDownloadState, StateLook> = {
  paused: { label: m.state.paused, tone: "neutral", icon: Pause },
  waiting_vpn: { label: m.state.waiting_vpn, tone: "warning", icon: ShieldEllipsis },
  connecting: { label: m.state.connecting, tone: "info", icon: LoaderCircle, busy: true },
  scanning: { label: m.state.scanning, tone: "info", icon: FolderSearch },
  downloading: { label: m.state.downloading, tone: "info", icon: ArrowDownToLine },
  idle: { label: m.state.idle, tone: "neutral", icon: Clock },
  retrying: { label: m.state.retrying, tone: "warning", icon: RefreshCw },
  error: { label: m.state.error, tone: "danger", icon: OctagonX },
};

/** The job's state as a word: what the manager reports, else unknown (never assumed). */
export function jobLook(v: SshDownloadView): StateLook {
  return v.status ? STATE[v.status.state] : UNKNOWN_STATE;
}

export const STEP_LABEL: Record<SshDownloadStep, string> = {
  claiming: m.step.claiming,
  downloading: m.step.downloading,
  finalizing: m.step.finalizing,
  failing: m.step.failing,
};

export const TRANSFER_LOOK: Record<SshDownloadTransferState, { label: string; tone: Tone; icon: StateLook["icon"] }> = {
  claiming: { label: m.transfer.claiming, tone: "info", icon: LoaderCircle },
  downloading: { label: m.transfer.downloading, tone: "info", icon: ArrowDownToLine },
  finalizing: { label: m.transfer.finalizing, tone: "info", icon: LoaderCircle },
  local_done: { label: m.transfer.local_done, tone: "info", icon: LoaderCircle },
  failing: { label: m.transfer.failing, tone: "warning", icon: TriangleAlert },
  completed: { label: m.transfer.completed, tone: "success", icon: CircleCheck },
  failed: { label: m.transfer.failed, tone: "danger", icon: OctagonX },
};

export const FILTER_LABEL: Record<SshDownloadNameFilter, { title: string; text: string }> = {
  all: { title: ui.common.all, text: m.nameFilter.all.text },
  skip_uuid: m.nameFilter.skip_uuid,
  only_uuid: m.nameFilter.only_uuid,
};

export type JobFilter = "all" | "running" | "paused" | "attention";

export const JOB_FILTERS: { value: JobFilter; label: string; title: string }[] = [
  { value: "all", label: ui.common.all, title: m.filter.allTitle },
  { value: "running", label: ui.common.running, title: m.filter.runningTitle },
  { value: "paused", label: m.state.paused, title: m.filter.pausedTitle },
  { value: "attention", label: m.state.error, title: m.filter.attentionTitle },
];

/** Each job is in exactly one of running / paused / attention (an unknown status counts as running). */
export function matchesJobFilter(v: SshDownloadView, f: JobFilter): boolean {
  const s = v.status?.state;
  switch (f) {
    case "running":
      return s !== "paused" && s !== "error";
    case "paused":
      return s === "paused";
    case "attention":
      return s === "error";
    case "all":
      return true;
  }
}

export type JobSort = "name" | "created";

export const JOB_SORTS: { value: JobSort; label: string }[] = [
  { value: "name", label: ui.common.name },
  { value: "created", label: m.sort.created },
];

const collator = new Intl.Collator(intlLocale, { numeric: true, sensitivity: "base" });

export function sortJobs(list: readonly SshDownloadView[], sort: JobSort): SshDownloadView[] {
  const out = [...list];
  if (sort === "created")
    out.sort(
      (a, b) => Date.parse(a.job.created_at) - Date.parse(b.job.created_at) || collator.compare(a.job.name, b.job.name),
    );
  else
    out.sort(
      (a, b) => collator.compare(a.job.name, b.job.name) || Date.parse(a.job.created_at) - Date.parse(b.job.created_at),
    );
  return out;
}

/** `user@host:port` (an IPv6 literal in brackets). */
export function targetText(j: Pick<SshDownloadJob, "user" | "host" | "port">): string {
  const host = j.host.includes(":") ? `[${j.host}]` : j.host;
  return `${j.user}@${host}${j.port === 22 ? "" : `:${j.port}`}`;
}

/** Bytes per second as a file-size rate ("4.5 MiB/s"); unknown stays unknown. */
export function formatRate(bps: number | null | undefined): string {
  if (bps === null || bps === undefined || !Number.isFinite(bps)) return "—";
  return `${formatBytes(bps)}/s`;
}

/** How long until a planned moment ("33 秒後"); `null` once it is due (within 5 s, or already past). */
export function dueIn(iso: string | null | undefined, now: number): string | null {
  const t = iso ? Date.parse(iso) : Number.NaN;
  if (!Number.isFinite(t) || t - now < 5000) return null;
  return relativeTime(iso, now);
}

/** "3 分 20 秒" / "45 秒" / "2 小時 5 分"; unknown stays unknown. */
export function formatEta(secs: number | null | undefined): string {
  if (secs === null || secs === undefined || !Number.isFinite(secs)) return "—";
  if (secs < 60) return m.duration.seconds(Math.max(0, Math.round(secs)));
  if (secs < 3600) return m.duration.minutes(Math.floor(secs / 60), Math.round(secs % 60));
  return m.duration.hours(Math.floor(secs / 3600), Math.round((secs % 3600) / 60));
}

/** How long a run has lasted at `now` ("3 分 20 秒"); "—" without a start. */
export function runningFor(since: string | null | undefined, now: number): string {
  const t = since ? Date.parse(since) : Number.NaN;
  if (!Number.isFinite(t)) return "—";
  return formatEta(Math.floor(Math.max(0, now - t) / 1000));
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return `${ms} ms`;
  return formatEta(ms / 1000);
}

/** One file's progress: "12 MiB／40 MiB（30%）", or the bytes alone while the size is unknown. */
export function progressText(a: SshDownloadActive): string {
  const done = Number(a.bytes_done);
  if (a.bytes_total === null) return formatBytes(done);
  const total = Number(a.bytes_total);
  const pct = total > 0 ? Math.floor((done / total) * 100) : 100;
  return m.progress(formatBytes(done), formatBytes(total), pct);
}

// ---------------------------------------------------------------------------------------------------------------
// The dialog's form

export interface JobForm {
  name: string;
  gateway_id: string;
  host: string;
  port: string;
  user: string;
  identity_file: string;
  key_passphrase: string;
  clear_key_passphrase: boolean;
  password: string;
  clear_password: boolean;
  source_dir: string;
  work_dir: string;
  failed_dir: string;
  local_dir: string;
  connections: string;
  retries: string;
  retry_backoff_secs: string;
  scan_interval_secs: string;
  name_filter: SshDownloadNameFilter;
  skip_hidden: boolean;
  /** Keep file names in the log and history (off: the transfer number only). */
  record_names: boolean;
  /** Days the log and history are kept; empty: the newest only (500 lines, 1,000 records). */
  history_days: string;
  paused: boolean;
}

/** Gateways that can carry SSH: SOCKS5 or Mixed (an HTTP-only one cannot). */
export function socksCapable(g: Pick<GatewaySpec, "kind">): boolean {
  return g.kind !== "http";
}

export function emptyForm(gateways: readonly GatewaySpec[]): JobForm {
  return {
    name: "",
    gateway_id: gateways.find(socksCapable)?.id ?? "",
    host: "",
    port: "22",
    user: "",
    identity_file: "",
    key_passphrase: "",
    clear_key_passphrase: false,
    password: "",
    clear_password: false,
    source_dir: "",
    work_dir: "",
    failed_dir: "",
    local_dir: "",
    connections: "3",
    retries: "3",
    retry_backoff_secs: "5",
    scan_interval_secs: "60",
    name_filter: "all",
    skip_hidden: true,
    record_names: true,
    history_days: "",
    paused: false,
  };
}

export function formOf(j: SshDownloadJob): JobForm {
  return {
    name: j.name,
    gateway_id: j.gateway_id,
    host: j.host,
    port: String(j.port),
    user: j.user,
    identity_file: j.identity_file ?? "",
    key_passphrase: "",
    clear_key_passphrase: false,
    password: "",
    clear_password: false,
    source_dir: j.source_dir,
    work_dir: j.work_dir,
    failed_dir: j.failed_dir,
    local_dir: j.local_dir,
    connections: String(j.connections),
    retries: String(j.retries),
    retry_backoff_secs: String(j.retry_backoff_secs),
    scan_interval_secs: String(j.scan_interval_secs),
    name_filter: j.name_filter,
    skip_hidden: j.skip_hidden,
    record_names: j.record_names,
    history_days: j.history_days === null ? "" : String(j.history_days),
    paused: false,
  };
}

/** The folder named `name` beside `source` (the server's `sibling_dir`): `/data/todo` → `/data/doing`. */
export function siblingDir(source: string, name: string): string | null {
  let s = source.trim().replace(/\/+$/, "");
  if (s.startsWith("~/")) s = s.slice(2);
  if (!s || s === "~") return null;
  const at = s.lastIndexOf("/");
  if (at < 0) return name;
  if (at === 0) return `/${name}`;
  return `${s.slice(0, at)}/${name}`;
}

const int = (v: string): number | null => (/^\d+$/.test(v.trim()) ? Number(v.trim()) : null);

const RANGES = {
  port: [1, 65535],
  connections: [1, 8],
  retries: [1, 20],
  retry_backoff_secs: [1, 3600],
  scan_interval_secs: [5, 86_400],
} as const;

function dotSegments(p: string): boolean {
  return p.split("/").some((seg) => seg === "." || seg === "..");
}

function controlChars(p: string): boolean {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: the rule is exactly about control characters.
  // eslint-disable-next-line no-control-regex -- input validation: a path must not contain control characters
  return /[\u0000-\u001f\u007f]/.test(p);
}

export function localPathOk(p: string): boolean {
  const t = p.trim();
  return (
    (t.startsWith("/") || t.startsWith("~/")) && !dotSegments(t) && !controlChars(t) && t.replace(/\/+$/, "") !== ""
  );
}

/** Field problems by JSON-pointer path, like the server's (`hasPassword`: a password is (still) stored). */
export function formErrors(f: JobForm, o: { hasPassword: boolean; hasPassphrase: boolean }): Map<string, string> {
  const e = new Map<string, string>();
  const text = dialog.errors;
  if (!f.name.trim()) e.set("/name", ui.common.enterName);
  else if (Array.from(f.name.trim()).length > 64) e.set("/name", ui.common.nameTooLong);
  if (!f.gateway_id) e.set("/gateway_id", text.gateway);
  if (!f.host.trim()) e.set("/host", text.hostRequired);
  else if (/\s/.test(f.host.trim())) e.set("/host", text.hostSpaces);
  const user = f.user.trim();
  if (!user) e.set("/user", text.userRequired);
  else if (/\s/.test(user) || controlChars(user)) e.set("/user", text.userInvalid);
  const password = f.password ? true : f.clear_password ? false : o.hasPassword;
  if (!f.identity_file.trim() && !password) e.set("/identity_file", text.loginRequired);
  else if (f.identity_file.trim() && !localPathOk(f.identity_file)) e.set("/identity_file", text.identityPath);
  const passphrase = f.key_passphrase ? true : f.clear_key_passphrase ? false : o.hasPassphrase;
  if (passphrase && !f.identity_file.trim()) e.set("/key_passphrase", text.passphraseNeedsKey);
  /** A remote folder: `required` when it cannot be empty, `dots` when it has `.` or `..` segments. */
  const remote = (path: string, v: string, dots: string, required: string | null) => {
    const t = v.trim();
    if (!t) {
      if (required !== null) e.set(path, required);
      return;
    }
    if (dotSegments(t) || controlChars(t)) e.set(path, dots);
  };
  remote("/source_dir", f.source_dir, text.sourceDots, text.sourceRequired);
  remote("/work_dir", f.work_dir, text.workDots, null);
  remote("/failed_dir", f.failed_dir, text.failedDots, null);
  if (!e.has("/source_dir") && !f.work_dir.trim() && siblingDir(f.source_dir, "doing") === null)
    e.set("/work_dir", text.noParent);
  const norm = (v: string, fallback: string | null) =>
    (v.trim() || (fallback ?? "")).replace(/\/+$/, "").replace(/^~\//, "");
  const s = norm(f.source_dir, null);
  const w = norm(f.work_dir, siblingDir(f.source_dir, "doing"));
  const fd = norm(f.failed_dir, siblingDir(f.source_dir, "failed"));
  if (s && w === s) e.set("/work_dir", text.workIsSource);
  if (s && fd === s) e.set("/failed_dir", text.failedIsSource);
  else if (w && fd === w) e.set("/failed_dir", text.failedIsWork);
  if (!f.local_dir.trim()) e.set("/local_dir", text.localRequired);
  else if (!localPathOk(f.local_dir)) e.set("/local_dir", text.localPath);
  for (const [k, [lo, hi]] of Object.entries(RANGES) as [keyof typeof RANGES, readonly [number, number]][]) {
    const n = int(f[k]);
    if (n === null || n < lo || n > hi) e.set(`/${k}`, text.wholeNumber(lo, hi));
  }
  if (f.history_days.trim()) {
    const n = int(f.history_days);
    if (n === null || n < 1 || n > 3650) e.set("/history_days", text.days);
  }
  return e;
}

/** A job's record settings in words: whether names are kept, and for how long the log and history. */
export function recordsText(j: Pick<SshDownloadJob, "record_names" | "history_days">): {
  names: string;
  kept: string;
} {
  return {
    names: j.record_names ? m.records.names : m.records.noNames,
    kept: j.history_days === null ? m.records.newest : m.records.days(j.history_days),
  };
}

/** The request body of a valid form. On an update, empty secret fields keep the stored ones. */
export function inputOf(f: JobForm, creating: boolean): SshDownloadInput {
  const opt = (v: string) => (v.trim() ? v.trim() : null);
  return {
    name: f.name.trim(),
    gateway_id: f.gateway_id,
    host: f.host.trim(),
    port: Number(f.port),
    user: f.user.trim(),
    identity_file: opt(f.identity_file),
    key_passphrase: f.key_passphrase ? f.key_passphrase : null,
    clear_key_passphrase: !creating && !f.key_passphrase && f.clear_key_passphrase,
    password: f.password ? f.password : null,
    clear_password: !creating && !f.password && f.clear_password,
    source_dir: f.source_dir.trim(),
    work_dir: opt(f.work_dir),
    failed_dir: opt(f.failed_dir),
    local_dir: f.local_dir.trim(),
    connections: Number(f.connections),
    retries: Number(f.retries),
    retry_backoff_secs: Number(f.retry_backoff_secs),
    scan_interval_secs: Number(f.scan_interval_secs),
    name_filter: f.name_filter,
    skip_hidden: f.skip_hidden,
    record_names: f.record_names,
    history_days: f.history_days.trim() ? Number(f.history_days.trim()) : null,
    paused: creating && f.paused,
  };
}
