// 數據統計: pure view logic over the persisted series (GET /v1/metrics/series) and the metrics
// status. Unknown stays unknown: every helper that cannot know a value returns `null` together
// with the reason, never 0.

import type {
  AppView,
  GatewayMetricsTotals,
  GatewaySpec,
  InstanceMetricsTotals,
  InstanceView,
  MetricsGap,
  MetricsGapReason,
  MetricsRange,
  MetricsRecording,
  MetricsSeries,
  MetricsTotals,
} from "@/api/types";
import { m as ui } from "@/components/ui/messages";
import { intlLocale, localized } from "@/i18n";
import { absoluteTime, formatBytes, relativeTime } from "@/lib/format";
import { m } from "./messages";

export const RANGES: { value: MetricsRange; label: string; long: string }[] = [
  { value: "15m", label: m.ranges.minutes(15), long: m.ranges.lastMinutes(15) },
  { value: "1h", label: m.ranges.hours(1), long: m.ranges.lastHours(1) },
  { value: "6h", label: m.ranges.hours(6), long: m.ranges.lastHours(6) },
  { value: "24h", label: m.ranges.hours(24), long: m.ranges.lastHours(24) },
  { value: "7d", label: m.ranges.days(7), long: m.ranges.lastDays(7) },
  { value: "30d", label: m.ranges.days(30), long: m.ranges.lastDays(30) },
];

export const DEFAULT_RANGE: MetricsRange = "1h";

export function parseRange(value: string | null): MetricsRange {
  return RANGES.find((r) => r.value === value)?.value ?? DEFAULT_RANGE;
}

export type Scope = { kind: "all" } | { kind: "instance"; id: string } | { kind: "gateway"; id: string };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** The `scope` query value; anything malformed means every connection. */
export function parseScope(value: string | null): Scope {
  const [kind, id] = (value ?? "").split(":", 2);
  if ((kind === "instance" || kind === "gateway") && id && UUID.test(id)) return { kind, id };
  return { kind: "all" };
}

export function scopeParam(s: Scope): string {
  return s.kind === "all" ? "all" : `${s.kind}:${s.id}`;
}

/** The scope in words, from what is configured (a deleted object keeps a recognizable label). */
export function scopeLabel(scope: Scope, views: InstanceView[], gateways: GatewaySpec[]): string {
  if (scope.kind === "all") return m.scope.all;
  if (scope.kind === "instance")
    return views.find((v) => v.spec.id === scope.id)?.spec.name ?? m.scope.connectionId(scope.id.slice(0, 8));
  const g = gateways.find((x) => x.id === scope.id);
  if (!g) return m.scope.gatewayId(scope.id.slice(0, 8));
  const owner = views.find((v) => v.spec.id === g.instance_id)?.spec.name;
  return m.scope.gateway(g.name, g.port, owner);
}

export interface ScopeOption {
  /** The `scope` query value. */
  value: string;
  label: string;
  group: "all" | "instance" | "gateway" | "missing";
}

/**
 * What the 對象 menu offers: every connection, then every proxy port (each named with its port and connection); a scope
 * that is no longer configured stays listed (marked 找不到) so the menu always shows the current choice.
 */
export function scopeOptions(scope: Scope, views: InstanceView[], gateways: GatewaySpec[]): ScopeOption[] {
  const out: ScopeOption[] = [{ value: "all", label: m.scope.all, group: "all" }];
  const current = scopeParam(scope);
  const known =
    current === "all" ||
    views.some((v) => `instance:${v.spec.id}` === current) ||
    gateways.some((g) => `gateway:${g.id}` === current);
  if (!known)
    out.push({ value: current, label: m.scope.missing(scopeLabel(scope, views, gateways)), group: "missing" });
  for (const v of views) out.push({ value: `instance:${v.spec.id}`, label: v.spec.name, group: "instance" });
  for (const g of gateways)
    out.push({
      value: `gateway:${g.id}`,
      label: scopeLabel({ kind: "gateway", id: g.id }, views, gateways),
      group: "gateway",
    });
  return out;
}

/** "每點 1 秒" etc. */
export function resolutionText(secs: number): string {
  if (secs < 60) return m.resolution.seconds(secs);
  if (secs < 3600) return m.resolution.minutes(secs / 60);
  return m.resolution.hours(secs / 3600);
}

/** What one point averages over: "1 秒", "5 分鐘", "1 小時". */
export function pointSpan(secs: number): string {
  if (secs < 60) return m.pointSpan.seconds(secs);
  if (secs < 3600) return m.pointSpan.minutes(secs / 60);
  return m.pointSpan.hours(secs / 3600);
}

// --- Gap reasons ------------------------------------------------------------------------------

/** Band styles: nothing recorded; data lost or rates undefined; a restart; a reading not given. */
export type GapClass = "absent" | "incomplete" | "restart" | "unavailable";

export const GAP_REASON: Record<MetricsGapReason, { label: string; detail: string; cls: GapClass }> = {
  missing: { label: ui.common.noData, detail: m.gaps.missing.detail, cls: "absent" },
  new_generation: { ...m.gaps.new_generation, cls: "restart" },
  long_interval: { ...m.gaps.long_interval, cls: "incomplete" },
  counter_reset: { ...m.gaps.counter_reset, cls: "incomplete" },
  dropped: { ...m.gaps.dropped, cls: "incomplete" },
  quota: { ...m.gaps.quota, cls: "incomplete" },
  disk_low: { ...m.gaps.disk_low, cls: "incomplete" },
  unavailable: { ...m.gaps.unavailable, cls: "unavailable" },
};

export interface GapTotal {
  reason: MetricsGapReason;
  spans: number;
  ms: number;
}

/** Reasons present in `[from, to)`, with their span count and clipped duration, in a stable order. */
export function summarizeGaps(gaps: MetricsGap[], from: number, to: number): GapTotal[] {
  const order = Object.keys(GAP_REASON) as MetricsGapReason[];
  const by = new Map<MetricsGapReason, GapTotal>();
  for (const g of gaps) {
    const ms = Math.min(g.to_ms, to) - Math.max(g.from_ms, from);
    if (ms <= 0) continue;
    const t = by.get(g.reason) ?? { reason: g.reason, spans: 0, ms: 0 };
    t.spans += 1;
    t.ms += ms;
    by.set(g.reason, t);
  }
  return order.flatMap((r) => by.get(r) ?? []);
}

/** The reasons whose spans cover time `t` (most specific first). */
export function gapsAt(gaps: MetricsGap[], t: number): MetricsGapReason[] {
  return gaps.filter((g) => g.from_ms <= t && t < g.to_ms).map((g) => g.reason);
}

/**
 * The shaded spans of a chart: nothing recorded is a neutral band, lost or undefined data an amber one. The window
 * without a rate right after a restart is only "not known" (neutral; the restart itself is its marker); readings the
 * host does not report (`unavailable`) shade only the resource charts (`resource`).
 */
export function gapBands(
  gaps: readonly MetricsGap[],
  resource: boolean,
): { from: number; to: number; tone: "absent" | "incomplete" }[] {
  const out: { from: number; to: number; tone: "absent" | "incomplete" }[] = [];
  for (const g of gaps) {
    if (g.reason === "unavailable" && !resource) continue;
    out.push({
      from: g.from_ms,
      to: g.to_ms,
      tone: GAP_REASON[g.reason].cls === "incomplete" ? "incomplete" : "absent",
    });
  }
  return out;
}

/** Where a restart's marker goes: the middle of the window that holds it, like the points. */
export function restartMarkers(restarts: readonly number[], stepMs: number, to: number): number[] {
  return restarts.map((t) => t + (Math.min(t + stepMs, to) - t) / 2);
}

// --- Values -----------------------------------------------------------------------------------

/** "500 µs", "2 ms", "1.5 s": a latency bucket bound. */
export function formatMicros(us: number): string {
  if (us < 1_000) return `${us} µs`;
  if (us < 1_000_000) return `${trim(us / 1_000)} ms`;
  return `${trim(us / 1_000_000)} s`;
}

function trim(v: number): string {
  return Number.isInteger(v) ? String(v) : v.toFixed(1).replace(/\.0$/, "");
}

/** Last finite bucket bound of `latency-us-v1` (the +∞ bucket starts above it). */
export const LATENCY_TOP_US = 30_000_000;

export interface Known {
  value: string | null;
  /** Why the value is not known (or not a number). */
  reason: string | null;
}

/**
 * A latency quantile with its bucket-bound wording. `count` is how many observations the window
 * or range holds: `null` nothing measured it, `0` none happened, otherwise a `null` quantile lies
 * in the +∞ bucket.
 */
export function latencyText(us: number | null, count: number | null, none = m.values.noneCompleted): Known {
  if (count === null) return { value: null, reason: ui.common.noData };
  if (count === 0) return { value: null, reason: none };
  if (us === null) return { value: null, reason: m.values.over(formatMicros(LATENCY_TOP_US)) };
  // Non-breaking: "≤ 20 ms" never splits across lines.
  return { value: `≤\u00a0${formatMicros(us).replace(" ", "\u00a0")}`, reason: null };
}

/**
 * What follows a failed-connect count when some of those failures named a host that does not
 * exist: "（名稱不存在 N）". Nothing when there were none, or when that was not recorded.
 */
export function notFoundText(n: number | null | undefined, format: (n: number) => string = String): string {
  return n ? m.values.notFound(format(n)) : "";
}

/**
 * The failed connects of a range whose name did not exist, for the summary: the total when every
 * point recorded it; otherwise the part that did, and how many failures came before names were
 * told apart (data from before the upgrade that added the count).
 */
export function notFoundSummary(s: Pick<MetricsSeries, "totals" | "connect_failures" | "connect_not_found">): string {
  if (s.totals.connect_not_found !== null) return notFoundText(s.totals.connect_not_found);
  let known = 0;
  let earlier = 0;
  let any = false;
  for (const [i, f] of s.connect_failures.entries()) {
    const nf = s.connect_not_found[i];
    if (nf === null || nf === undefined) earlier += f ?? 0;
    else {
      any = true;
      known += nf;
    }
  }
  if (!any || earlier === 0) return notFoundText(any ? known : null);
  return m.values.notFoundUnclassified(known, earlier);
}

/** Failed DNS lookups over all lookups in the range. */
export function dnsFailureRate(t: MetricsTotals): Known & { ratio: number | null } {
  if (t.dns_queries === null || t.dns_failures === null) return { value: null, ratio: null, reason: ui.common.noData };
  if (t.dns_queries === 0) return { value: null, ratio: null, reason: m.values.noDnsQueries };
  const ratio = t.dns_failures / t.dns_queries;
  return { value: formatRatio(ratio), ratio, reason: null };
}

export function formatRatio(r: number): string {
  const pct = r * 100;
  if (pct > 0 && pct < 0.1) return "< 0.1%";
  return `${pct >= 10 || Number.isInteger(pct) ? Math.round(pct) : pct.toFixed(1)}%`;
}

/**
 * Time the payload gate was open over the recorded time; `null` when the gate state is not known.
 * Time without samples (not running, host asleep, or before this object was recorded) counts
 * neither way: `coverage` says how much of the range the value stands for.
 */
export function availability(t: MetricsTotals): number | null {
  return t.serving_ms === null || t.covered_ms <= 0 ? null : Math.min(1, t.serving_ms / t.covered_ms);
}

export function coverage(t: MetricsTotals): number {
  return t.range_ms > 0 ? Math.min(1, t.covered_ms / t.range_ms) : 0;
}

/** "9 分 17 秒", "2 小時 5 分", "3 天 4 小時". */
export function formatDuration(ms: number): string {
  const s = Math.round(ms / 1_000);
  if (s < 60) return m.duration.seconds(s);
  const min = Math.floor(s / 60);
  if (min < 60) return m.duration.minutes(min, s % 60);
  const h = Math.floor(min / 60);
  if (h < 24) return m.duration.hours(h, min % 60);
  const d = Math.floor(h / 24);
  return m.duration.days(d, h % 24);
}

/** A gauge mean: whole numbers stay whole, others keep one decimal. */
export function formatGauge(v: number): string {
  return Number.isInteger(v) ? String(v) : v.toFixed(1);
}

export function formatRate(v: number): string {
  if (v === 0) return m.values.perSecond("0");
  if (v < 0.01) return m.values.perSecond("< 0.01");
  return m.values.perSecond(v < 10 ? v.toFixed(2).replace(/\.?0+$/, "") : String(Math.round(v)));
}

// --- Time ---------------------------------------------------------------------------------------

const hms = new Intl.DateTimeFormat(intlLocale, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const hm = new Intl.DateTimeFormat(intlLocale, { hour: "2-digit", minute: "2-digit", hour12: false });
const mdhm = new Intl.DateTimeFormat(intlLocale, {
  month: "numeric",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});
const md = new Intl.DateTimeFormat(intlLocale, { month: "numeric", day: "numeric" });

/** The window a point stands for: "12:03:15", "12:03:15–12:03:20", "12:03", "10/27 12:00–13:00". */
export function windowLabel(start: number, stepSecs: number, to: number): string {
  const end = Math.min(start + stepSecs * 1_000, to);
  // The newest window is still open: it ends at the next sample, not at `to`.
  if (end < start + stepSecs * 1_000) return m.values.openWindow(stepSecs < 60 ? hms.format(start) : hm.format(start));
  if (stepSecs <= 1) return hms.format(start);
  if (stepSecs < 60) return `${hms.format(start)}–${hms.format(end)}`;
  if (stepSecs < 3600) return hm.format(start);
  return `${mdhm.format(start)}–${hm.format(end)}`;
}

/** Axis ticks: round local times, at most `max` of them. */
export function timeTicks(from: number, to: number, max = 6): { t: number; label: string }[] {
  const span = to - from;
  const MIN = 60_000;
  const steps = [
    MIN,
    5 * MIN,
    10 * MIN,
    15 * MIN,
    30 * MIN,
    60 * MIN,
    180 * MIN,
    360 * MIN,
    720 * MIN,
    1_440 * MIN,
    10_080 * MIN,
  ];
  const step = steps.find((s) => span / s <= max) ?? steps[steps.length - 1] ?? MIN;
  // Round in local time: offset by the timezone so hour and day ticks land on local boundaries.
  const offset = new Date(from).getTimezoneOffset() * MIN;
  const first = Math.ceil((from - offset) / step) * step + offset;
  const out: { t: number; label: string }[] = [];
  for (let t = first; t < to; t += step) {
    out.push({ t, label: step >= 1_440 * MIN ? md.format(t) : hm.format(t) });
  }
  return out;
}

// --- Breakdown ----------------------------------------------------------------------------------

export interface BreakdownRow {
  /**
   * A connection, or a part of its traffic: one of its proxy ports (its ordinary proxy traffic: SSH apart), its App
   * sandbox (the strict Apps' traffic), its SSH downloads (`pull`) or its SSH sessions (`ssh`) through its ports.
   */
  kind: "instance" | "gateway" | "sandbox" | "pull" | "ssh";
  /** The object's id; a sandbox and the SSH parts have none of their own and carry their connection's. */
  id: string;
  /** Owning Instance (for a Gateway or a sandbox). */
  instanceId: string;
  name: string;
  /** Still configured (links work), or only history remains. */
  exists: boolean;
  /** `:port` of a Gateway; the Apps of a sandbox. */
  detail: string | null;
  /** The sandbox's App to open (the first of them). */
  appId?: string | undefined;
  /** A proxy port's figures leave out its SSH traffic (which has rows of its own). */
  withoutSsh?: boolean | undefined;
  totals: MetricsTotals | null;
}

/** No proxy connects of its own: for a part whose connects are its proxy ports' (or that has none). */
const NO_CONNECTS = {
  connect_count: null,
  connect_timeouts: null,
  connect_failures: null,
  connect_not_found: null,
  connect_rejected: null,
  connect_p50_us: null,
  connect_p95_us: null,
  connect_p99_us: null,
} as const;

/**
 * A sandbox's part of its connection's totals, in the shape of a row: its payload is the Apps', and it has no proxy
 * connects or availability of its own (both belong to the connection).
 */
export function sandboxTotals(t: MetricsTotals): MetricsTotals {
  return {
    ...t,
    ...NO_CONNECTS,
    serving_ms: null,
    payload_rx_bytes: t.sandbox_rx_bytes,
    payload_tx_bytes: t.sandbox_tx_bytes,
    peak_payload_rx_bps: t.peak_sandbox_rx_bps,
    peak_payload_tx_bps: t.peak_sandbox_tx_bps,
  };
}

/** The SSH downloads' (`pull`) or SSH sessions' (`ssh`) part of a connection's totals, in the shape of a row. */
export function sshTotals(t: MetricsTotals, part: "pull" | "ssh"): MetricsTotals {
  const pull = part === "pull";
  return {
    ...t,
    ...NO_CONNECTS,
    serving_ms: null,
    payload_rx_bytes: pull ? t.ssh_pull_rx_bytes : t.ssh_rx_bytes,
    payload_tx_bytes: pull ? t.ssh_pull_tx_bytes : t.ssh_tx_bytes,
    peak_payload_rx_bps: pull ? t.peak_ssh_pull_rx_bps : t.peak_ssh_rx_bps,
    peak_payload_tx_bps: pull ? t.peak_ssh_pull_tx_bps : t.peak_ssh_tx_bps,
  };
}

/** Whether a total carried any SSH of that part (null: not recorded). */
const carried = (rx: number | null, tx: number | null) => (rx ?? 0) > 0 || (tx ?? 0) > 0;

/**
 * A proxy port's totals without its SSH traffic (its ordinary proxy traffic), where that was recorded; otherwise as
 * they are. Its connects stay its own: they include the SSH connects.
 */
export function withoutSsh(t: MetricsTotals): { totals: MetricsTotals; subtracted: boolean } {
  const known = [t.ssh_rx_bytes, t.ssh_tx_bytes, t.ssh_pull_rx_bytes, t.ssh_pull_tx_bytes].every((v) => v !== null);
  if (!known || !(carried(t.ssh_rx_bytes, t.ssh_tx_bytes) || carried(t.ssh_pull_rx_bytes, t.ssh_pull_tx_bytes))) {
    return { totals: t, subtracted: false };
  }
  const less = (all: number | null, a: number | null, b: number | null) =>
    all === null ? null : Math.max(0, all - (a ?? 0) - (b ?? 0));
  return {
    totals: {
      ...t,
      payload_rx_bytes: less(t.payload_rx_bytes, t.ssh_rx_bytes, t.ssh_pull_rx_bytes),
      payload_tx_bytes: less(t.payload_tx_bytes, t.ssh_tx_bytes, t.ssh_pull_tx_bytes),
      peak_payload_rx_bps: t.peak_non_ssh_rx_bps ?? t.peak_payload_rx_bps,
      peak_payload_tx_bps: t.peak_non_ssh_tx_bps ?? t.peak_payload_tx_bps,
    },
    subtracted: true,
  };
}

export type SortKey = "rx" | "tx" | "peak" | "p95" | "avail";

const sortValue: Record<SortKey, (t: MetricsTotals | null) => number | null> = {
  rx: (t) => t?.payload_rx_bytes ?? null,
  tx: (t) => t?.payload_tx_bytes ?? null,
  peak: (t) => t?.peak_payload_rx_bps ?? null,
  p95: (t) => t?.connect_p95_us ?? null,
  avail: (t) => (t ? availability(t) : null),
};

/** Larger first, except latency (faster first); unknown always last. */
function compare(key: SortKey, a: MetricsTotals | null, b: MetricsTotals | null): number {
  const va = sortValue[key](a);
  const vb = sortValue[key](b);
  if (va === null || vb === null) return va === null ? (vb === null ? 0 : 1) : -1;
  return key === "p95" ? va - vb : vb - va;
}

/**
 * One row per connection (configured ones even without data, deleted ones that still have data), each followed by its
 * parts: its Gateways and, when it has strict Apps or its sandbox has data in the range, its App sandbox; sorted by
 * `key` within each level.
 */
export function breakdownRows(
  views: InstanceView[],
  gatewaySpecs: GatewaySpec[],
  instances: InstanceMetricsTotals[],
  gateways: GatewayMetricsTotals[],
  key: SortKey,
  onlyInstance?: string,
  apps: readonly AppView[] = [],
): { row: BreakdownRow; parts: BreakdownRow[] }[] {
  const instanceTotals = new Map(instances.map((i) => [i.instance_id, i.totals]));
  const ids = new Set<string>([...views.map((v) => v.spec.id), ...instances.map((i) => i.instance_id)]);
  const groups = [...ids]
    .filter((id) => onlyInstance === undefined || id === onlyInstance)
    .map((id) => {
      const v = views.find((x) => x.spec.id === id);
      const row: BreakdownRow = {
        kind: "instance",
        id,
        instanceId: id,
        name: v?.spec.name ?? m.deleted.connection(id.slice(0, 8)),
        exists: Boolean(v),
        detail: null,
        totals: instanceTotals.get(id) ?? null,
      };
      const gwIds = new Set<string>([
        ...gatewaySpecs.filter((g) => g.instance_id === id).map((g) => g.id),
        ...gateways.filter((g) => g.instance_id === id).map((g) => g.gateway_id),
      ]);
      const gws = [...gwIds].map((gid): BreakdownRow => {
        const spec = gatewaySpecs.find((g) => g.id === gid);
        const own = gateways.find((g) => g.gateway_id === gid && g.instance_id === id)?.totals ?? null;
        // Its SSH traffic is in the connection's SSH rows, not here as well.
        const plain = own ? withoutSsh(own) : null;
        return {
          kind: "gateway",
          id: gid,
          instanceId: id,
          name: spec?.name ?? m.deleted.gateway(gid.slice(0, 8)),
          exists: Boolean(spec),
          detail: spec ? `:${spec.port}` : null,
          withoutSsh: plain?.subtracted,
          totals: plain?.totals ?? null,
        };
      });
      const parts = [...gws];
      const t = row.totals;
      for (const part of ["pull", "ssh"] as const) {
        if (!t) continue;
        const pull = part === "pull";
        if (!carried(pull ? t.ssh_pull_rx_bytes : t.ssh_rx_bytes, pull ? t.ssh_pull_tx_bytes : t.ssh_tx_bytes))
          continue;
        parts.push({
          kind: part,
          id,
          instanceId: id,
          name: pull ? m.parts.sshDownloads : m.parts.sshProxy,
          exists: Boolean(v),
          detail: null,
          totals: sshTotals(t, part),
        });
      }
      const strict = apps.filter((a) => a.spec.instance_id === id && a.spec.isolation === "strict_netns");
      // Unknown is null; an answer of an older manager has no such field at all.
      const measured =
        (row.totals?.sandbox_rx_bytes ?? null) !== null || (row.totals?.sandbox_tx_bytes ?? null) !== null;
      if (strict.length || measured) {
        const names = strict.map((a) => a.spec.name);
        parts.push({
          kind: "sandbox",
          id,
          instanceId: id,
          name: m.parts.appSandbox,
          exists: Boolean(v),
          detail: names.length ? m.parts.appNames(names) : null,
          appId: strict[0]?.spec.id,
          totals: measured && row.totals ? sandboxTotals(row.totals) : null,
        });
      }
      parts.sort((a, b) => compare(key, a.totals, b.totals) || a.name.localeCompare(b.name, intlLocale));
      return { row, parts };
    });
  groups.sort((a, b) => compare(key, a.row.totals, b.row.totals) || a.row.name.localeCompare(b.row.name, intlLocale));
  return groups;
}

/** Index of the point nearest to `t` in ascending `timestamps` (window starts), or null. */
export function nearestIndex(timestamps: number[], stepMs: number, t: number): number | null {
  if (!timestamps.length) return null;
  const first = timestamps[0] ?? 0;
  const i = Math.floor((t - first) / stepMs);
  return Math.max(0, Math.min(timestamps.length - 1, i));
}

// --- Recording ----------------------------------------------------------------------------------

/** What to say about recording while it is not as usual (a notice above the views). */
export interface RecordingNotice {
  tone: "warning" | "danger";
  title: string;
  detail: string;
  /** The link to 系統 › 執行環境 (disk space, metric writes). */
  action: string;
}

/** "3 分鐘前（11/7 12:00:00）". */
function since(iso: string | null, now: number): string {
  return iso ? m.when(relativeTime(iso, now), absoluteTime(iso)) : m.recording.justNow;
}

/** The oldest data had to make room (or samples could not be stored even then) while space is low. */
function overwrote(r: MetricsRecording): boolean {
  return r.state === "overwriting" && (r.overwritten_rows > 0 || r.lost_samples > 0);
}

function overwriteTitle(r: MetricsRecording): string {
  return r.free_bytes === 0 ? m.recording.diskFull : m.recording.diskLow;
}

/**
 * The notice while recording is not as usual: samples that cannot be written, or the oldest data overwritten on a low
 * or full disk. Nothing while samples are stored as usual — also on a low disk before anything had to be overwritten.
 */
export function recordingNotice(r: MetricsRecording | null | undefined, now: number): RecordingNotice | null {
  if (!r) return null;
  if (r.state === "failing")
    return {
      tone: "danger",
      title: m.recording.failingTitle,
      detail: m.recording.failingDetail(since(r.since, now), r.error ? localized(r.error) : ui.common.unknownReason),
      action: m.recording.failingAction,
    };
  if (!overwrote(r)) return null;
  const space =
    r.free_bytes !== null && r.resume_bytes !== null
      ? { free: formatBytes(r.free_bytes), resume: formatBytes(r.resume_bytes) }
      : null;
  return {
    tone: "warning",
    title: overwriteTitle(r),
    action: m.recording.overwriteAction,
    detail: m.recording.overwriteDetail(
      since(r.since, now),
      r.overwritten_rows,
      GAP_REASON.disk_low.label,
      r.lost_samples,
      space,
    ),
  };
}

/** The same in one line for 總覽's 需要處理 (no clock in it). */
export function recordingAttention(r: MetricsRecording | null | undefined): string | null {
  if (!r) return null;
  if (r.state === "failing") return m.recording.failingLine(r.error ? localized(r.error) : ui.common.unknownReason);
  return overwrote(r) ? m.recording.overwriteLine(overwriteTitle(r)) : null;
}
