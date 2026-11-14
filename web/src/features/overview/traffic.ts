// 總覽's traffic chart, pure: every connection's payload over a range — the stored series of 數據統計 (scope all, its
// windows, gap bands and restart markers), extended past its last stored window by the live samples the event stream
// brought, on the same grid — with its parts: SSH 下載 (VPN Manager's SSH download jobs), SSH 代理 (SSH sessions through
// the proxy ports) and the App sandboxes. Times are the host's (the series and the samples are stamped by it; `now`
// comes from useServerNow), so the right edge is the host's now. Unknown stays unknown: a window without data is null
// and its line breaks, never 0.

import type { LiveRates, MetricsRange, MetricsSeries } from "@/api/types";
import type { Band, Frame } from "@/components/charts/series-chart";
import { portKinds } from "@/features/gateways/ssh-traffic";
import { gapBands, RANGES, restartMarkers, timeTicks } from "@/features/metrics/model";

/** The ranges 總覽 offers: the short ones of 數據統計, under the same names. */
export const OVERVIEW_RANGES = RANGES.filter(
  (r) => r.value === "15m" || r.value === "1h" || r.value === "6h" || r.value === "24h",
);
export const OVERVIEW_RANGE_VALUES = OVERVIEW_RANGES.map((r) => r.value);
export const OVERVIEW_DEFAULT_RANGE: MetricsRange = "1h";

/** One value per window and direction: the whole payload and each part of it (null: unknown or nothing to count). */
interface Columns {
  rx: (number | null)[];
  tx: (number | null)[];
  /** The App sandboxes' part; null where no connection had a sandbox. */
  sandboxRx: (number | null)[];
  sandboxTx: (number | null)[];
  /** SSH 下載's part; null where it was not recorded. */
  pullRx: (number | null)[];
  pullTx: (number | null)[];
  /** SSH 代理's part, the same way. */
  sshRx: (number | null)[];
  sshTx: (number | null)[];
}

type Column = keyof Columns;
const COLUMNS: readonly Column[] = ["rx", "tx", "sandboxRx", "sandboxTx", "pullRx", "pullTx", "sshRx", "sshTx"];

export interface TrafficView extends Columns {
  frame: Frame;
  /** Windows from here on come from live samples (not stored yet). */
  liveFrom: number;
  bands: Band[];
  markers: number[];
  ticks: { t: number; label: string }[];
}

/** A window of live samples: every connection's mean over its own samples in it, summed over the connections. */
type WindowSum = Record<Column, number> & {
  /** Connections with a sandbox in this window. */
  sandboxes: number;
};

const zero = (): WindowSum => ({
  rx: 0,
  tx: 0,
  sandboxRx: 0,
  sandboxTx: 0,
  pullRx: 0,
  pullTx: 0,
  sshRx: 0,
  sshTx: 0,
  sandboxes: 0,
});

/** One sample's values per column (a sandbox's only when the connection has one). */
function sampleValues(s: LiveRates): Record<Column, number> {
  const k = portKinds(s.gateways);
  return {
    rx: s.payload_rx_bps,
    tx: s.payload_tx_bps,
    sandboxRx: s.sandbox?.rx_bps ?? 0,
    sandboxTx: s.sandbox?.tx_bps ?? 0,
    pullRx: k.pull.rx,
    pullTx: k.pull.tx,
    sshRx: k.proxy.rx,
    sshTx: k.proxy.tx,
  };
}

/**
 * Live samples (`at` in [after, to)) on the series' grid: per window, every connection's mean over its own samples in
 * it, summed over the connections that reported — what the stored series says for scope all. A new worker generation
 * marks a restart at its first sample's window.
 */
export function liveWindows(
  live: ReadonlyMap<string, readonly LiveRates[] | undefined>,
  stepMs: number,
  after: number,
  to: number,
): { windows: Map<number, WindowSum>; restarts: number[] } {
  const windows = new Map<number, WindowSum>();
  const restarts: number[] = [];
  for (const samples of live.values()) {
    if (!samples) continue;
    // Per window: the samples, those with a sandbox, and their sums.
    const own = new Map<number, { n: number; sn: number; sum: WindowSum }>();
    let generation: number | null = null;
    for (const s of samples) {
      const t = Date.parse(s.at);
      const restarted = generation !== null && s.generation !== generation;
      generation = s.generation;
      if (!Number.isFinite(t) || t < after || t >= to) continue;
      const w = Math.floor(t / stepMs) * stepMs;
      if (restarted) restarts.push(w);
      const a = own.get(w) ?? { n: 0, sn: 0, sum: zero() };
      a.n += 1;
      if (s.sandbox) a.sn += 1;
      const v = sampleValues(s);
      for (const c of COLUMNS) a.sum[c] += v[c];
      own.set(w, a);
    }
    for (const [w, a] of own) {
      const sum = windows.get(w) ?? zero();
      for (const c of COLUMNS) {
        const sandbox = c === "sandboxRx" || c === "sandboxTx";
        if (sandbox && !a.sn) continue;
        sum[c] += a.sum[c] / (sandbox ? a.sn : a.n);
      }
      if (a.sn) sum.sandboxes += 1;
      windows.set(w, sum);
    }
  }
  return { windows, restarts };
}

/** A live window's values per column (the sandboxes' null where none had one). */
function liveValues(l: WindowSum | undefined): Record<Column, number | null> {
  const out = {} as Record<Column, number | null>;
  for (const c of COLUMNS) {
    out[c] = !l || ((c === "sandboxRx" || c === "sandboxTx") && !l.sandboxes) ? null : l[c];
  }
  return out;
}

/** A stored window's values per column. */
function storedValues(s: MetricsSeries, i: number): Record<Column, number | null> {
  return {
    rx: s.payload_rx_bps[i] ?? null,
    tx: s.payload_tx_bps[i] ?? null,
    sandboxRx: s.sandbox_rx_bps[i] ?? null,
    sandboxTx: s.sandbox_tx_bps[i] ?? null,
    pullRx: s.ssh_pull_rx_bps[i] ?? null,
    pullTx: s.ssh_pull_tx_bps[i] ?? null,
    sshRx: s.ssh_rx_bps[i] ?? null,
    sshTx: s.ssh_tx_bps[i] ?? null,
  };
}

/**
 * The chart at `now`: the range slid to end now; the stored windows that still overlap it; then one window per step up
 * to the open one, from the live samples (null where none arrived). Live samples also fill the newest stored windows the
 * store had not written yet (null there), never one it measured.
 */
export function trafficView(
  s: MetricsSeries,
  live: ReadonlyMap<string, readonly LiveRates[] | undefined>,
  now: number,
): TrafficView {
  const step = s.resolution_secs * 1_000;
  const span = s.to_ms - s.from_ms;
  const to = Math.max(now, s.to_ms);
  const from = to - span;
  const lastStored = s.timestamps[s.timestamps.length - 1] ?? Math.floor(s.to_ms / step) * step - step;
  const liveFrom = lastStored + step;
  const fillFrom = lastStored - step;
  const { windows, restarts } = liveWindows(live, step, fillFrom, to);

  const timestamps: number[] = [];
  const columns: Columns = {
    rx: [],
    tx: [],
    sandboxRx: [],
    sandboxTx: [],
    pullRx: [],
    pullTx: [],
    sshRx: [],
    sshTx: [],
  };
  const push = (t: number, v: Record<Column, number | null>) => {
    timestamps.push(t);
    for (const c of COLUMNS) columns[c].push(v[c]);
  };
  s.timestamps.forEach((t, i) => {
    if (t + step <= from) return;
    const stored = s.payload_rx_bps[i] ?? null;
    const l = stored === null && t >= fillFrom ? windows.get(t) : undefined;
    push(t, l ? liveValues(l) : storedValues(s, i));
  });
  // The open window holds `to`; every window after the stored ones gets a point (null without samples).
  const open = Math.floor((to - 1) / step) * step;
  for (let t = Math.max(liveFrom, Math.floor(from / step) * step); t <= open; t += step) {
    push(t, liveValues(windows.get(t)));
  }
  const markers = [...new Set([...s.restarts, ...restarts.filter((t) => t >= liveFrom)])];
  return {
    frame: { timestamps, stepMs: step, from, to },
    ...columns,
    liveFrom,
    bands: gapBands(s.gaps, false),
    markers: restartMarkers(markers, step, to),
    ticks: timeTicks(from, to),
  };
}

/** A part's share of the payload over the range (both directions), or null when the part was never known in it. */
export function partShare(v: TrafficView, part: "sandbox" | "pull" | "ssh"): number | null {
  const prx = v[`${part}Rx`];
  const ptx = v[`${part}Tx`];
  let all = 0;
  let sum = 0;
  let any = false;
  for (const [i, r] of v.rx.entries()) {
    const x = v.tx[i] ?? null;
    if (r === null || x === null) continue;
    all += r + x;
    const pr = prx[i] ?? null;
    const px = ptx[i] ?? null;
    if (pr !== null || px !== null) {
      any = true;
      sum += (pr ?? 0) + (px ?? 0);
    }
  }
  if (!any || all <= 0) return null;
  return Math.min(1, sum / all);
}
