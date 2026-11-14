// The VPN Manager host's clock as this browser sees it. The server's timestamps (a live sample's `at`, an
// `observed_at`, an expiry) are compared with the server's own time, never with this device's clock: on a host whose
// clock is off (no NTP), or for a viewer whose clock is, every live figure would otherwise count as stale and every
// "12 秒前" would be shifted. The offset (server minus browser) comes from GET /v1/system/status, whose `observed_at`
// the controller stamps as its answer leaves (the shell polls it every 15 s); taken when the answer arrives, it errs
// only by the answer's transit, and a stalled feed still ages in real time against it.
import { useSyncExternalStore } from "react";
import { useNow } from "./use-media";

/** A new reading that moves the offset less than this changes nothing (no re-render for transit jitter). */
const JITTER_MS = 250;
/** Clocks this far apart are worth saying (系統 › 執行環境). */
export const CLOCK_SKEW_NOTICE_MS = 5_000;

let offsetMs: number | null = null;
const listeners = new Set<() => void>();

function subscribe(l: () => void) {
  listeners.add(l);
  return () => {
    listeners.delete(l);
  };
}
const snapshot = () => offsetMs;

/** The server said its time was `serverIso` in an answer that arrived at `receivedAt` (this browser's clock). */
export function noteServerTime(serverIso: string, receivedAt: number = Date.now()): void {
  const t = Date.parse(serverIso);
  if (!Number.isFinite(t)) return;
  const next = t - receivedAt;
  if (offsetMs !== null && Math.abs(next - offsetMs) < JITTER_MS) return;
  offsetMs = next;
  for (const l of listeners) l();
}

/** Server minus browser in milliseconds; `null` until the server has answered once. */
export function useServerOffset(): number | null {
  return useSyncExternalStore(subscribe, snapshot, snapshot);
}

/** The server's time now (ms since the epoch), as far as known: this browser's until the server has answered. */
export function serverNow(): number {
  return Date.now() + (offsetMs ?? 0);
}

/** The shared one-second clock in the server's time: compare the server's timestamps with this. */
export function useServerNow(): number {
  const now = useNow();
  const offset = useServerOffset();
  return now + (offset ?? 0);
}
