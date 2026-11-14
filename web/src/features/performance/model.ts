// The 效能統計 vocabulary and the pure decisions behind the page: words for roles and reason
// codes, value formatting, and the summary's freshness. Unknown stays unknown: every helper
// returns null (shown as —) with the reason, never 0.

import type { ByteObservation } from "@/api/generated/ByteObservation";
import type { MetricsRange } from "@/api/generated/MetricsRange";
import type { NumericObservation } from "@/api/generated/NumericObservation";
import type { PerformanceMetric } from "@/api/generated/PerformanceMetric";
import type { PerformanceOverview } from "@/api/generated/PerformanceOverview";
import type { PerformanceSeriesSet } from "@/api/generated/PerformanceSeriesSet";
import type { ProcessRole } from "@/api/generated/ProcessRole";
import type { Frame } from "@/components/charts/series-chart";
import { m as ui } from "@/components/ui/messages";
import { formatBytes } from "@/lib/format";
import { m } from "./messages";

// ---------------------------------------------------------------------------------------------
// The trends' range (one control above every trend chart, in the URL)
// ---------------------------------------------------------------------------------------------

export const PERF_RANGES: { value: MetricsRange; label: string; long: string }[] = [
  { value: "15m", ...m.ranges["15m"] },
  { value: "1h", ...m.ranges["1h"] },
  { value: "6h", ...m.ranges["6h"] },
  { value: "24h", ...m.ranges["24h"] },
  { value: "7d", ...m.ranges["7d"] },
  { value: "30d", ...m.ranges["30d"] },
];

export const DEFAULT_PERF_RANGE: MetricsRange = "1h";

/** The `range` query value; anything else is the default hour. */
export function parsePerfRange(value: string | null): MetricsRange {
  return PERF_RANGES.find((r) => r.value === value)?.value ?? DEFAULT_PERF_RANGE;
}

/** One column of a series set (the scope as a whole with `role` null); all unknown when the set has none. */
export function seriesOf(
  set: PerformanceSeriesSet | undefined,
  metric: PerformanceMetric,
  role: ProcessRole | null,
): (number | null)[] {
  const col = set?.series.find((c) => c.metric === metric && c.role === role);
  return col?.values ?? (set ? set.timestamps.map(() => null) : []);
}

/** The windows of a series set, as the shared chart reads them. */
export function perfFrame(
  set: Pick<PerformanceSeriesSet, "timestamps" | "resolution_secs" | "from_ms" | "to_ms">,
): Frame {
  return { timestamps: set.timestamps, stepMs: set.resolution_secs * 1_000, from: set.from_ms, to: set.to_ms };
}

// ---------------------------------------------------------------------------------------------
// Words
// ---------------------------------------------------------------------------------------------

export const ROLE_LABEL: Record<ProcessRole, string> = m.role;

/** Reason codes of unknown or qualified values, in words. The code itself is shown beside. */
export const REASON: Record<string, string> = m.reason;

export function reasonText(code: string | null | undefined): string {
  if (!code) return ui.common.unknown;
  return REASON[code] ?? code;
}

export function formatUs(us: number | string | null | undefined): string {
  if (us === null || us === undefined) return "—";
  const n = typeof us === "string" ? Number(us) : us;
  if (!Number.isFinite(n)) return "—";
  if (n < 1_000) return `${n} µs`;
  if (n < 1_000_000) return `${(n / 1_000).toFixed(n < 10_000 ? 1 : 0)} ms`;
  return `${(n / 1_000_000).toFixed(1)} s`;
}

/** p50／p95／p99 in the unit of the largest: "200/500/500 ms", "0.5/2/2 s". */
export function latencyTriple(...us: (string | number | null)[]): string {
  const n = us.map((v) => (v === null ? null : Number(v)));
  const known = n.filter((v): v is number => v !== null && Number.isFinite(v));
  if (!known.length) return us.map((v) => formatUs(v)).join(" / ");
  const max = Math.max(...known);
  const [div, unit] = max >= 1_000_000 ? [1_000_000, "s"] : max >= 1_000 ? [1_000, "ms"] : [1, "µs"];
  const part = (v: number | null) => {
    if (v === null || !Number.isFinite(v)) return "—";
    const x = v / div;
    return x >= 10
      ? String(Math.round(x))
      : x >= 1
        ? x.toFixed(1).replace(/\.0$/, "")
        : x.toFixed(2).replace(/0$/, "").replace(/\.0?$/, "");
  };
  return `${n.map(part).join("/")} ${unit}`;
}

/** A numeric observation as text: the value, or — with the reason. */
export function obs(
  o: NumericObservation | null | undefined,
  fmt: (v: number) => string,
): { text: string; reason: string | null } {
  if (!o) return { text: "—", reason: null };
  if (o.value === null) return { text: "—", reason: o.reason_code };
  return { text: fmt(o.value), reason: null };
}

export function bytesObs(o: ByteObservation | null | undefined): { text: string; reason: string | null } {
  if (!o) return { text: "—", reason: null };
  if (o.value === null) return { text: "—", reason: o.reason_code };
  return { text: formatBytes(o.value), reason: null };
}

export function pct(v: number): string {
  return `${v < 10 ? v.toFixed(2) : v.toFixed(1)} %`;
}

// ---------------------------------------------------------------------------------------------
// The passive summary's state
// ---------------------------------------------------------------------------------------------

export type SummaryState =
  /** The manager started moments ago: windows are not full yet. */
  | { kind: "collecting"; secondsLeft: number }
  /** The last answer is older than a few refreshes. */
  | { kind: "stale"; ageSeconds: number }
  /** Some figures are missing (gateways left out, Instances with low coverage). */
  | { kind: "partial"; omittedGateways: number; lowCoverage: number }
  | { kind: "ok" };

/** An answer older than this is stale (the manager refreshes every 5 s). */
export const STALE_AFTER_MS = 20_000;

export function summaryState(s: PerformanceOverview, now: number): SummaryState {
  const observed = Date.parse(s.observed_at);
  if (Number.isFinite(observed) && now - observed > STALE_AFTER_MS) {
    return { kind: "stale", ageSeconds: Math.round((now - observed) / 1000) };
  }
  const since = Date.parse(s.collecting_since);
  const window = s.latency_window_secs * 1000;
  if (Number.isFinite(since) && Number.isFinite(observed) && observed - since < window) {
    return { kind: "collecting", secondsLeft: Math.max(0, Math.round((window - (observed - since)) / 1000)) };
  }
  const lowCoverage = s.instances.filter((i) => i.phase === "ready" && i.summary.coverage_ratio < 0.99).length;
  if (s.omitted_gateways > 0 || lowCoverage > 0) {
    return { kind: "partial", omittedGateways: s.omitted_gateways, lowCoverage };
  }
  return { kind: "ok" };
}
