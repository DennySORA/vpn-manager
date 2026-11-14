import type { InstanceView, LiveRates } from "@/api/types";
import { latest } from "@/components/charts/rate-chart";
import { formatBps } from "@/lib/format";
import { m } from "./messages";

export interface Onboarding {
  /** Done or not: get a profile, create a connection, create a proxy port, start and pass verification. */
  steps: [boolean, boolean, boolean, boolean];
  /** The first step not done (-1: all done). */
  next: number;
  show: boolean;
}

/**
 * Setup guidance, not a status panel: it ends once a connection with a proxy port has been started
 * (now, or earlier: its last tunnel facts are kept); from then on problems belong to "需要處理".
 * Until then the last step stays, so it can be the next one. With no status known it says nothing
 * about that step.
 */
export function onboarding(profiles: number, views: InstanceView[], gateways: number): Onboarding {
  const statuses = views.flatMap((v) => (v.status ? [v.status] : []));
  const ready = statuses.some((s) => s.phase === "ready");
  const started = statuses.some((s) => s.intent.desired === "running" || s.tunnel !== null);
  const steps: Onboarding["steps"] = [profiles > 0, views.length > 0, gateways > 0, ready];
  const setUp = steps[0] && steps[1] && steps[2];
  return { steps, next: steps.indexOf(false), show: !(setUp && (ready || started || !statuses.length)) };
}

/** The latest second of the connections that report one: their payload, and the App sandboxes' part of it. */
export interface LiveTotal {
  /** Connections with a fresh sample (none: the totals are unknown, not 0). */
  fresh: number;
  rx: number;
  tx: number;
  /** Of them, connections with a strict sandbox, and what its Apps carried (already in `rx`, `tx`). */
  sandboxes: number;
  sandboxRx: number;
  sandboxTx: number;
}

export function liveTotal(live: ReadonlyMap<string, LiveRates[] | undefined>, now: number): LiveTotal {
  const t: LiveTotal = { fresh: 0, rx: 0, tx: 0, sandboxes: 0, sandboxRx: 0, sandboxTx: 0 };
  for (const samples of live.values()) {
    const cur = latest(samples, now);
    if (!cur) continue;
    t.fresh += 1;
    t.rx += cur.payload_rx_bps;
    t.tx += cur.payload_tx_bps;
    if (cur.sandbox) {
      t.sandboxes += 1;
      t.sandboxRx += cur.sandbox.rx_bps;
      t.sandboxTx += cur.sandbox.tx_bps;
    }
  }
  return t;
}

/** The 下載／上傳 figure's second line: the App sandboxes' part of it, only where a connection has one. */
export function liveSandboxNote(t: LiveTotal, direction: "rx" | "tx"): string | null {
  if (!t.sandboxes) return null;
  return m.summary.sandboxShare(formatBps(direction === "rx" ? t.sandboxRx : t.sandboxTx));
}
