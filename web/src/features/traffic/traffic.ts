// The top bar's live traffic: what every running connection carries now, summed. Only fresh samples count (the latest
// second each worker reported, at most 3.5 s old); a connection without one is not counted as 0 — it makes the total
// partial, and with none at all the total is unknown.
import type { InstanceView, LiveRates } from "@/api/types";
import { latest } from "@/components/charts/rate-chart";
import { intlLocale } from "@/i18n";
import { formatBps } from "@/lib/format";
import { m } from "./messages";

/** A connection that should be running, with its latest fresh sample (null: none). */
export interface TrafficRow {
  view: InstanceView;
  rates: LiveRates | null;
}

export interface TrafficTotal {
  /** Connections that should be running. */
  running: number;
  /** Of them, connections with a fresh sample: the totals are theirs (none: unknown). */
  fresh: number;
  rx: number;
  tx: number;
  /** TCP connections and UDP flows open in their tunnels. */
  flows: number;
}

/** The connections the strip follows: those whose intent is to run (the same as the overview's live rates). */
export function runningViews(views: readonly InstanceView[]): InstanceView[] {
  return views.filter((v) => v.status?.intent.desired === "running");
}

export function trafficRows(
  views: readonly InstanceView[],
  live: ReadonlyMap<string, LiveRates[] | undefined>,
  now: number,
): TrafficRow[] {
  return runningViews(views).map((view) => ({ view, rates: latest(live.get(view.spec.id), now) }));
}

export function trafficTotal(rows: readonly TrafficRow[]): TrafficTotal {
  const t: TrafficTotal = { running: rows.length, fresh: 0, rx: 0, tx: 0, flows: 0 };
  for (const { rates } of rows) {
    if (!rates) continue;
    t.fresh += 1;
    t.rx += rates.payload_rx_bps;
    t.tx += rates.payload_tx_bps;
    t.flows += rates.active_tcp + rates.active_udp;
  }
  return t;
}

/** A total as the strip shows it: unknown is a dash, never 0. */
export function totalText(t: TrafficTotal): { rx: string; tx: string; flows: string } {
  if (!t.fresh) return { rx: "—", tx: "—", flows: "—" };
  return { rx: formatBps(t.rx), tx: formatBps(t.tx), flows: t.flows.toLocaleString(intlLocale) };
}

/** The strip's accessible name: every figure in one sentence, also the ones a narrow window hides. */
export function trafficSentence(t: TrafficTotal): string {
  if (!t.running) return m.sentence.none;
  if (!t.fresh) return m.sentence.noData(t.running);
  const v = totalText(t);
  return m.sentence.total(v.rx, v.tx, v.flows, t.fresh, t.running - t.fresh);
}
