import { useCallback, useSyncExternalStore } from "react";

// Subscribe functions are stable (module scope or memoized): React resubscribes whenever the
// function identity changes, and a resubscribe must never change the snapshot by itself.

/** Live `matchMedia` result (re-renders when the query flips). */
export function useMedia(query: string): boolean {
  const subscribe = useCallback(
    (notify: () => void) => {
      const mq = window.matchMedia(query);
      mq.addEventListener("change", notify);
      return () => {
        mq.removeEventListener("change", notify);
      };
    },
    [query],
  );
  return useSyncExternalStore(
    subscribe,
    () => window.matchMedia(query).matches,
    () => false,
  );
}

/** ≥ 1280px: the inspector sits beside the collection instead of in a drawer. */
export function useWideLayout(): boolean {
  return useMedia("(min-width: 80rem)");
}

function subscribeVisibility(notify: () => void) {
  document.addEventListener("visibilitychange", notify);
  return () => {
    document.removeEventListener("visibilitychange", notify);
  };
}
const pageVisible = () => document.visibilityState === "visible";

/** Document visible (tab in front); effect regions pause when hidden. */
export function usePageVisible(): boolean {
  return useSyncExternalStore(subscribeVisibility, pageVisible, () => true);
}

// One shared one-second clock for relative times ("12 秒前") and sliding chart windows.
let now = Date.now();
const clockListeners = new Set<() => void>();
let clockTimer: number | undefined;

function tick() {
  now = Date.now();
  for (const l of clockListeners) l();
}

function subscribeClock(notify: () => void) {
  clockListeners.add(notify);
  if (clockTimer === undefined) {
    clockTimer = window.setInterval(tick, 1000);
    // Refresh a value that went stale while nobody listened, outside the subscribe call.
    window.setTimeout(tick, 0);
  }
  return () => {
    clockListeners.delete(notify);
    if (clockListeners.size === 0 && clockTimer !== undefined) {
      window.clearInterval(clockTimer);
      clockTimer = undefined;
    }
  };
}
const getNow = () => now;

export function useNow(): number {
  return useSyncExternalStore(subscribeClock, getNow, getNow);
}
