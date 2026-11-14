// Managed Apps: state looks, honest isolation labels, and the form model. The rules mirror
// `check_app` (crates/domain/src/validation.rs) so problems show before a request is sent; the
// server still decides.

import type { LucideIcon } from "lucide-react";
import {
  Ban,
  Box,
  CircleSlash,
  Hourglass,
  LoaderCircle,
  OctagonX,
  Play,
  ShieldHalf,
  Square,
  TriangleAlert,
  Variable,
} from "lucide-react";
import type {
  AppClass,
  AppClassInfo,
  AppInput,
  AppIsolation,
  AppRunState,
  AppSpec,
  AppView,
  Capability,
  CapabilityState,
  GatewayKind,
  GatewaySpec,
} from "@/api/types";
import { m as ui } from "@/components/ui/messages";
import { intlLocale, localized } from "@/i18n";
import { type StateLook, UNKNOWN_STATE } from "@/lib/status";
import { type LimitDraft, limitDraft, parseLimits } from "@/features/limits/model";
import { type AccessRow, accessProblems, rowsOf, toPorts } from "./access";
import { m } from "./messages";

export const RUN_STATE: Record<AppRunState, StateLook> = {
  stopped: { label: ui.common.stopped, tone: "neutral", icon: Square },
  starting: { label: ui.common.starting, tone: "info", icon: LoaderCircle, busy: true },
  // A running process is an observed fact, not a protection claim (the isolation tag says that).
  running: { label: ui.common.running, tone: "brand", icon: Play },
  stopping: { label: ui.common.stopping, tone: "info", icon: Hourglass, busy: true },
  failed: { label: m.needsAttention, tone: "danger", icon: OctagonX },
};

/** What the App's state means, with the reason refining "failed". */
export function appLook(v: AppView): StateLook {
  const s = v.status;
  if (!s) return UNKNOWN_STATE;
  if (s.state === "failed") {
    switch (s.last_error?.code) {
      case "APP_EXITED":
        return { label: m.state.exited, tone: "danger", icon: OctagonX };
      case "APP_OOM_KILLED":
        return { label: m.state.outOfMemory, tone: "danger", icon: OctagonX };
      case "APP_LISTENER_NOT_LOOPBACK":
      case "APP_CONNECTION_NOT_LOOPBACK":
      case "APP_GATEWAY_RELEASED":
        return { label: m.state.forcedStop, tone: "danger", icon: Ban };
      case "APP_STOP_UNCONFIRMED":
        return { label: m.state.stopUnconfirmed, tone: "danger", icon: TriangleAlert };
      case "APP_HANDOFF":
        return { label: m.state.handedOff, tone: "danger", icon: TriangleAlert };
      case "APP_ARTIFACT_DIGEST_MISMATCH":
      case "APP_ARTIFACT_NOT_APPROVED":
        return { label: m.state.awaitsApproval, tone: "warning", icon: TriangleAlert };
      case undefined:
      default:
        return { label: m.state.cannotStart, tone: "danger", icon: OctagonX };
    }
  }
  // Wanted running but not running (e.g. stopped across a manager restart).
  if (s.state === "stopped" && s.desired === "running" && s.last_error)
    return { label: ui.common.stopped, tone: "warning", icon: CircleSlash };
  return RUN_STATE[s.state];
}

/** A tree is (or may still be) in place: stopping is the safe action, starting is not offered. */
export function hasRun(v: AppView): boolean {
  const s = v.status;
  if (!s) return false;
  return (
    s.state === "running" ||
    s.state === "starting" ||
    s.state === "stopping" ||
    s.last_error?.code === "APP_STOP_UNCONFIRMED"
  );
}

/**
 * Why the executable needs (re-)approval before a start, or null. A refused start stays refused
 * until an approval clears it; approving the unchanged file again is how a restored file is accepted.
 */
export function approvalProblem(v: AppView): string | null {
  if (!v.spec.approval || v.status?.last_error?.code === "APP_ARTIFACT_NOT_APPROVED")
    return m.approvalProblem.notApproved;
  if (v.status?.last_error?.code === "APP_ARTIFACT_DIGEST_MISMATCH") return m.approvalProblem.changed;
  return null;
}

/** Listening sockets of the tree on an address other hosts may reach (proxy variables do not stop them). */
export function exposedListeners(v: AppView): number {
  return v.status?.listeners?.filter((l) => !l.loopback).length ?? 0;
}

/**
 * Something the user should look at (the list's 「需要處理」 and the row's second line), or null: a failure with the
 * manager's reason, a stop it did not ask for, an executable waiting for approval, a listener other hosts reach, an
 * intent the manager cannot write to disk. Unknown is not a problem of the App (the status says 「狀態未知」).
 */
export function appAttention(v: AppView): string | null {
  const s = v.status;
  if (!s) return null;
  if (s.state === "failed")
    return s.last_error ? m.labelAndDetail(appLook(v).label, localized(s.last_error.message)) : appLook(v).label;
  if (s.state === "stopped" && s.desired === "running" && s.last_error)
    return m.attention.stopped(localized(s.last_error.message));
  const approval = approvalProblem(v);
  if (approval) return approval;
  const exposed = exposedListeners(v);
  if (exposed) return m.attention.exposed(exposed);
  if (s.intent_persistence === "unavailable") return m.attention.intentNotStored;
  return null;
}

/** Saved settings the running program was not started with (a restart applies them), or null. */
export function pendingConfig(v: AppView): string | null {
  const s = v.status;
  if (s?.state !== "running" || s.run_revision === null || s.run_revision === v.spec.revision) return null;
  return m.attention.pendingRevision(s.run_revision, v.spec.revision);
}

/** What to look at first: a problem, else settings a restart would apply. */
export function appNeedsAttention(v: AppView): string | null {
  return appAttention(v) ?? (pendingConfig(v) ? m.attention.settingsChanged : null);
}

/**
 * The inspector's conclusion: what the App's network is now, in a sentence. Never a protection claim beyond what the
 * manager reports (the mode actually applied to the running tree); proxy variables always say what they do not do.
 */
export function appTraffic(
  v: AppView,
  ownerName: string | null,
): { tone: "info" | "warning"; title?: string; text: string } {
  const s = v.status;
  // Where the traffic enters, when the manager reported the port (the sentences name the Gateway otherwise).
  const port = s?.gateway_port ?? null;
  const running = s?.state === "running";
  const mode = (running ? s.isolation : null) ?? v.spec.isolation;
  if (mode === "proxy_env")
    return {
      tone: "warning",
      title: ISOLATION.proxy_env.title,
      text: running ? m.network.proxyEnvRunning(port, ownerName, ISOLATION.proxy_env.limit) : ISOLATION.proxy_env.limit,
    };
  if (!s) return { tone: "warning", text: m.network.noStatus };
  switch (s.state) {
    case "running":
      return mode === "strict_netns"
        ? { tone: "info", text: m.network.strictRunning(ownerName) }
        : { tone: "info", text: m.network.enforcedRunning(port, ownerName) };
    case "starting":
      return { tone: "info", text: m.network.starting };
    case "stopping":
      return { tone: "info", text: m.network.stopping };
    case "failed":
    case "stopped":
    default:
      return { tone: "info", text: m.network.stopped };
  }
}

/**
 * The Apps that run in a connection's strict sandbox. They share its one tunnel interface, so the sandbox's traffic is
 * theirs together: no counter tells one App's flows from another's.
 */
export function sandboxApps(apps: readonly AppView[], instanceId: string): AppView[] {
  return apps.filter((a) => a.spec.instance_id === instanceId && a.spec.isolation === "strict_netns");
}

/** The sandbox's Apps in a few words: "P2P client", "P2P client 等 3 個 App". */
export function sandboxAppsLabel(apps: readonly AppView[]): string {
  const first = apps[0]?.spec.name ?? "";
  return apps.length > 1 ? m.sandboxApps(first, apps.length) : first;
}

/** Running Apps whose saved settings apply only after a restart (the list's batch action). */
export function pendingRestartApps(views: readonly AppView[]): AppView[] {
  return views.filter((v) => pendingConfig(v) !== null);
}

export type AppFilter = "all" | "running" | "stopped" | "attention";

export const APP_FILTERS: { value: AppFilter; label: string; title: string }[] = [
  { value: "all", label: ui.common.all, title: m.filter.all },
  { value: "running", label: ui.common.running, title: m.filter.running },
  { value: "stopped", label: ui.common.stopped, title: m.noRunningProcess },
  { value: "attention", label: m.needsAttention, title: m.filter.attention },
];

/** A known App is in exactly one of running / stopped; 需要處理 overlaps both. */
export function matchesAppFilter(v: AppView, f: AppFilter): boolean {
  switch (f) {
    case "running":
      return hasRun(v);
    case "stopped":
      return Boolean(v.status) && !hasRun(v);
    case "attention":
      return appNeedsAttention(v) !== null;
    case "all":
    default:
      return true;
  }
}

export type AppSort = "name" | "state" | "instance";

export const APP_SORTS: { value: AppSort; label: string }[] = [
  { value: "name", label: ui.common.name },
  { value: "state", label: ui.common.status },
  { value: "instance", label: m.connection },
];

const collator = new Intl.Collator(intlLocale, { numeric: true, sensitivity: "base" });

/** Something to handle first, then running, then on the way, then stopped; unknown last. */
function appStateRank(v: AppView): number {
  const s = v.status;
  if (!s) return 4;
  if (appNeedsAttention(v) !== null) return 0;
  if (s.state === "running") return 1;
  if (hasRun(v)) return 2;
  return 3;
}

/** A new array in the chosen order; ties fall back to the name, then the ID, so rows never swap places by chance. */
export function sortApps(list: readonly AppView[], sort: AppSort, instanceName: (v: AppView) => string): AppView[] {
  const byName = (a: AppView, b: AppView) =>
    collator.compare(a.spec.name, b.spec.name) || collator.compare(a.spec.id, b.spec.id);
  const out = [...list];
  if (sort === "state") out.sort((a, b) => appStateRank(a) - appStateRank(b) || byName(a, b));
  else if (sort === "instance") out.sort((a, b) => collator.compare(instanceName(a), instanceName(b)) || byName(a, b));
  else out.sort(byName);
  return out;
}

export interface IsolationInfo {
  title: string;
  short: string;
  icon: LucideIcon;
  /** The capability that says whether this host runs the mode. */
  capability: string;
  text: string;
  /** What this mode does not do; shown wherever the mode is chosen or in effect. */
  limit: string;
}

export const ISOLATION: Record<AppIsolation, IsolationInfo> = {
  proxy_env: {
    title: m.isolation.proxy_env.title,
    short: m.isolation.proxy_env.short,
    icon: Variable,
    capability: "app_proxy_env",
    text: m.isolation.proxy_env.text,
    limit: m.isolation.proxy_env.limit,
  },
  enforced_proxy: {
    title: m.isolation.enforced_proxy.title,
    short: m.isolation.enforced_proxy.short,
    icon: ShieldHalf,
    capability: "app_enforced_proxy",
    text: m.isolation.enforced_proxy.text,
    limit: m.isolation.enforced_proxy.limit,
  },
  strict_netns: {
    title: m.isolation.strict_netns.title,
    short: m.isolation.strict_netns.short,
    icon: Box,
    capability: "app_strict_netns",
    text: m.isolation.strict_netns.text,
    limit: m.isolation.strict_netns.limit,
  },
};

export const ISOLATIONS: AppIsolation[] = ["proxy_env", "enforced_proxy", "strict_netns"];

export interface ModeAvailability {
  available: boolean;
  state: CapabilityState | null;
  /** Why not (or what to know), as the host reports it. */
  reason: string | null;
}

/** Whether this host runs `mode`, from the capability matrix (unknown while it loads). */
export function modeAvailability(mode: AppIsolation, caps: Capability[] | undefined): ModeAvailability {
  if (!caps) return { available: false, state: null, reason: m.mode.reading };
  const c = caps.find((x) => x.name === ISOLATION[mode].capability);
  if (!c) return { available: false, state: null, reason: m.mode.notReported };
  const available = c.state === "supported" || c.state === "degraded";
  return { available, state: c.state, reason: c.reason ? localized(c.reason) : null };
}

/** Which proxy variables a Gateway of `kind` gets (SOCKS needs SOCKS5 or Mixed, HTTP needs HTTP or Mixed). */
export function proxyVariables(kind: GatewayKind, port: number): string {
  const socks = `ALL_PROXY=socks5h://127.0.0.1:${port}`;
  const http = `HTTP(S)_PROXY=http://127.0.0.1:${port}`;
  if (kind === "mixed") return m.proxyVariables.mixed(socks, http);
  if (kind === "socks5") return m.proxyVariables.socks5(socks);
  return m.proxyVariables.http(http);
}

export const PLACEHOLDER_PORT = "{gateway_port}";
export const PLACEHOLDER_HOME = "{app_home}";

/** What the executable check recognised a program as, in a few words. */
export const CLASS_LABEL: Record<AppClass, string> = m.appClass.label;

/** Arguments the launcher puts before the App's own for a program of `cls` (mirrors `AppClass::launch_args`). */
export function classArgs(cls: AppClass | null | undefined): string[] {
  if (cls === "chromium") return ["--user-data-dir={app_home}/chromium-data"];
  if (cls === "firefox") return ["-profile", "{app_home}/firefox-profile", "-no-remote", "-new-instance"];
  return [];
}

/** A start may hand over to a process VPN Manager did not start (mirrors `AppClass::may_hand_off`). */
export function mayHandOff(cls: AppClass | null | undefined): boolean {
  return cls === "gui" || cls === "launcher";
}

/** One of the App's own arguments chooses the data directory or profile itself (mirrors `AppClass::selects_profile`). */
export function selectsProfile(cls: AppClass | null | undefined, arg: string): boolean {
  const bare = arg.startsWith("--") ? arg.slice(2) : arg.startsWith("-") ? arg.slice(1) : "";
  const name = bare.split("=")[0]?.toLowerCase() ?? "";
  if (cls === "chromium") return name === "user-data-dir";
  if (cls === "firefox") return name === "p" || name === "profile" || name === "profilemanager";
  return false;
}

/** What VPN Manager does about a program of this class (shown with the executable check). */
export function classNote(info: AppClassInfo): string {
  return m.appClass.note[info.class](info.name);
}

/** Why `enforced_proxy` gives this program no isolation (mirrors `app_class_not_enforceable`). */
export function notEnforceable(info: AppClassInfo): string {
  return info.class === "launcher"
    ? m.appClass.notEnforceable.launcher(info.name)
    : m.appClass.notEnforceable.gui(info.name);
}

/** Names VPN Manager sets for every App (mirrors APP_RESERVED_ENV). */
export const RESERVED_ENV = [
  "VPNM_RUN",
  "HOME",
  "TMPDIR",
  "ALL_PROXY",
  "all_proxy",
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "NO_PROXY",
  "no_proxy",
];

export const MAX_ARGS = 256;
export const MAX_ENV = 128;
export const MAX_WRITABLE = 32;
const MAX_PATH = 1024;

/** One row of a list editor; `key` keeps the row's identity while rows are added and removed. */
export interface Row {
  key: string;
  value: string;
}

export interface EnvRow {
  key: string;
  name: string;
  value: string;
}

export interface Draft {
  name: string;
  instanceId: string;
  /** "" when none. */
  gatewayId: string;
  isolation: AppIsolation;
  executable: string;
  args: Row[];
  workingDir: string;
  env: EnvRow[];
  writable: Row[];
  /** Strict isolation: write only under `writable`, the private home and temp, and /dev. */
  confineWrites: boolean;
  restartOnRecovery: boolean;
  /** Seconds to exit after SIGTERM before it is killed, as typed. */
  stopGrace: string;
  /** Resource limits as typed ("" = none). */
  limits: LimitDraft;
  /** Strict isolation: the sandbox's ports published on this host. */
  access: AccessRow[];
}

let rowSeq = 0;
export function rowKey(): string {
  rowSeq += 1;
  return `r${rowSeq}`;
}

export function emptyDraft(instanceId: string, gatewayId: string, isolation: AppIsolation): Draft {
  return {
    name: "",
    instanceId,
    gatewayId,
    isolation,
    executable: "",
    args: [],
    workingDir: "",
    env: [],
    writable: [],
    confineWrites: false,
    restartOnRecovery: false,
    stopGrace: String(STOP_GRACE_DEFAULT),
    limits: limitDraft(undefined),
    access: [],
  };
}

export function fromSpec(a: AppSpec): Draft {
  return {
    name: a.name,
    instanceId: a.instance_id,
    gatewayId: a.gateway_id ?? "",
    isolation: a.isolation,
    executable: a.executable,
    args: a.args.map((value) => ({ key: rowKey(), value })),
    workingDir: a.working_dir ?? "",
    env: a.env.map((e) => ({ key: rowKey(), name: e.name, value: e.value })),
    writable: a.writable_paths.map((value) => ({ key: rowKey(), value })),
    confineWrites: a.confine_writes,
    restartOnRecovery: a.restart_on_recovery,
    stopGrace: String(a.stop_grace_secs),
    limits: limitDraft(a.limits),
    access: rowsOf(a.access_ports, rowKey),
  };
}

/** The request body. Fields a mode does not use are not sent (the server refuses them). */
export function toInput(d: Draft, executableSha256: string | null): AppInput {
  const strict = d.isolation === "strict_netns";
  return {
    instance_id: d.instanceId,
    name: d.name.trim(),
    executable: d.executable.trim(),
    args: d.args.map((r) => r.value),
    working_dir: d.workingDir.trim() || null,
    env: d.env.map((e) => ({ name: e.name.trim(), value: e.value })),
    isolation: d.isolation,
    gateway_id: strict ? null : d.gatewayId || null,
    restart_on_recovery: d.restartOnRecovery,
    writable_paths: usesWritable(d) ? d.writable.map((r) => r.value.trim()).filter(Boolean) : [],
    confine_writes: strict && d.confineWrites,
    stop_grace_secs: Number(d.stopGrace.trim()),
    executable_sha256: executableSha256,
    limits: parseLimits(d.limits).limits,
    access_ports: strict ? toPorts(d.access) : [],
  };
}

/** Seconds an App may take to exit after SIGTERM (`stop_grace_secs`), and the default. */
export const STOP_GRACE_MIN = 1;
export const STOP_GRACE_MAX = 900;
export const STOP_GRACE_DEFAULT = 10;

/** Whether the App's writable directories apply: enforced proxy, or strict isolation with its writes confined. */
export function usesWritable(d: Pick<Draft, "isolation" | "confineWrites">): boolean {
  return d.isolation === "enforced_proxy" || (d.isolation === "strict_netns" && d.confineWrites);
}

/** An absolute path without `..` segments, as the server requires. */
export function absolutePath(p: string): boolean {
  return p.startsWith("/") && p.length <= MAX_PATH && !p.includes("\0") && !p.split("/").includes("..");
}

/** `{name}` tokens of an argument that are not placeholders the launcher replaces. */
export function unknownPlaceholders(arg: string): string[] {
  return [...arg.matchAll(/\{([a-z_]+)\}/g)]
    .map((match) => match[0])
    .filter((t) => t !== PLACEHOLDER_PORT && t !== PLACEHOLDER_HOME);
}

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

export interface Problems {
  /** By JSON pointer, as the server reports them (`/args/2`). */
  errors: Map<string, string>;
  warnings: Map<string, string>;
}

/**
 * `cls`: what the executable check recognised the program as (the rules of `check_app_class`:
 * a browser's data directory is the launcher's; a program that may hand its start over cannot
 * use enforced_proxy). `gateways`: their ports are not free for an access port.
 */
export function validate(d: Draft, cls: AppClassInfo | null = null, gateways: GatewaySpec[] = []): Problems {
  const errors = new Map<string, string>();
  const warnings = new Map<string, string>();
  const name = d.name.trim();
  if (!name) errors.set("/name", m.validation.nameEmpty);
  else if (Array.from(name).length > 64) errors.set("/name", ui.common.nameTooLong);
  if (!d.instanceId) errors.set("/instance_id", m.validation.connection);
  const exe = d.executable.trim();
  if (!exe) errors.set("/executable", m.validation.executableEmpty);
  else if (!absolutePath(exe)) errors.set("/executable", m.validation.executableNotAbsolute);
  if (d.args.length > MAX_ARGS) errors.set("/args", m.validation.tooManyArgs(MAX_ARGS));
  d.args.forEach((r, i) => {
    const path = `/args/${i}`;
    if (r.value.length > 4096) errors.set(path, m.validation.argTooLong);
    else if (r.value.includes(PLACEHOLDER_PORT) && (d.isolation === "strict_netns" || !d.gatewayId))
      errors.set(path, m.validation.portNeedsGateway);
    else if (cls && selectsProfile(cls.class, r.value))
      errors.set(path, m.validation.profileArg(cls.name, classArgs(cls.class).join(" "), r.value));
    else {
      const unknown = unknownPlaceholders(r.value);
      if (unknown.length) warnings.set(path, m.validation.unknownPlaceholders(unknown));
    }
  });
  const dir = d.workingDir.trim();
  if (dir && !absolutePath(dir)) errors.set("/working_dir", m.validation.workingDir);
  if (d.env.length > MAX_ENV) errors.set("/env", m.validation.tooManyEnv(MAX_ENV));
  const seen = new Set<string>();
  d.env.forEach((e, i) => {
    const path = `/env/${i}`;
    const n = e.name.trim();
    if (!ENV_NAME.test(n) || n.length > 128) errors.set(path, m.validation.envName);
    else if (RESERVED_ENV.includes(n)) errors.set(path, m.validation.envReserved(n));
    else if (seen.has(n)) errors.set(path, m.validation.envRepeated(n));
    else if (e.value.length > 8192) errors.set(path, m.validation.envValueTooLong);
    seen.add(n);
  });
  if (d.isolation === "strict_netns") {
    // Nothing to check: the sandbox has no proxy port.
  } else if (!d.gatewayId) errors.set("/gateway_id", m.validation.gateway);
  const grace = d.stopGrace.trim();
  if (!/^\d+$/.test(grace) || Number(grace) < STOP_GRACE_MIN || Number(grace) > STOP_GRACE_MAX)
    errors.set("/stop_grace_secs", m.validation.stopGrace(STOP_GRACE_MIN, STOP_GRACE_MAX));
  if (usesWritable(d)) {
    if (d.writable.length > MAX_WRITABLE) errors.set("/writable_paths", m.validation.tooManyWritable(MAX_WRITABLE));
    d.writable.forEach((r, i) => {
      const p = r.value.trim();
      if (!absolutePath(p) || p.replace(/\/+$/, "") === "")
        errors.set(`/writable_paths/${i}`, m.validation.writablePath);
    });
  }
  if (cls && mayHandOff(cls.class)) {
    if (d.isolation === "enforced_proxy") errors.set("/isolation", notEnforceable(cls));
    else if (d.isolation === "proxy_env")
      warnings.set(
        "/executable",
        cls.class === "launcher"
          ? m.appClass.proxyEnvWarning.launcher(cls.name)
          : m.appClass.proxyEnvWarning.gui(cls.name),
      );
  }
  for (const [path, message] of parseLimits(d.limits).errors) errors.set(path, message);
  // Only a strict App's rows are sent (the others are kept, unsent, while the mode is switched).
  if (d.isolation === "strict_netns")
    for (const [path, message] of accessProblems(d.access, gateways)) errors.set(path, message);
  return { errors, warnings };
}

/** The last path segment (an App's executable in a list). */
export function basename(path: string): string {
  const trimmed = path.replace(/\/+$/, "");
  return trimmed.slice(trimmed.lastIndexOf("/") + 1) || path;
}

/**
 * The argv the launcher will run: what the program's class puts first (a browser's own data
 * directory), then the App's arguments, with what the placeholders become (one pass, like the launcher).
 */
export function argvPreview(
  d: Pick<Draft, "executable" | "args">,
  gatewayPort: number | null,
  home: string,
  cls: AppClass | null = null,
): string[] {
  const port = gatewayPort === null ? PLACEHOLDER_PORT : String(gatewayPort);
  const sub = (a: string) =>
    a.replace(/\{gateway_port\}|\{app_home\}/g, (token) => (token === PLACEHOLDER_PORT ? port : home));
  return [d.executable.trim(), ...classArgs(cls).map(sub), ...d.args.map((r) => sub(r.value))];
}

/** Short form of a SHA-256 for display (the full value is copyable). */
export function shortDigest(sha: string): string {
  return sha.length > 16 ? `${sha.slice(0, 12)}…${sha.slice(-4)}` : sha;
}

/** Search across what the list shows. */
export function matchesApp(v: AppView, q: string, instanceName: string | undefined): boolean {
  const t = q.trim().toLowerCase();
  if (!t) return true;
  return [v.spec.name, v.spec.executable, ISOLATION[v.spec.isolation].short, instanceName ?? ""]
    .join(" ")
    .toLowerCase()
    .includes(t);
}

/**
 * A line of an App's output as text: terminal escape sequences (colors, cursor moves, titles)
 * are dropped, many programs color their logs even when writing to a file, and so are other
 * control characters except tab.
 */
export function plainText(line: string): string {
  /* eslint-disable no-control-regex -- matching terminal escape sequences and control characters is the point */
  return line
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "")
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\x1b[@-Z\\-_]/g, "")
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");
  /* eslint-enable no-control-regex */
}
