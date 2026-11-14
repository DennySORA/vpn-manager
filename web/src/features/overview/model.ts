import type { LiveRates } from "@/api/types";
import { latest } from "@/components/charts/rate-chart";
import { formatBps } from "@/lib/format";
import { m } from "./messages";

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
