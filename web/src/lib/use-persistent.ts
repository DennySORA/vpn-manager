// Adapted from Phasyn Studio (Apache-2.0).
// Layout preferences of this browser (localStorage, keys `vpnm.<kind>.<key>`). A failed read or write (private mode,
// blocked site data) falls back to the default and the value lives for this session only; nothing else depends on it.
import { useCallback, useState } from "react";

function write(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Only for this session.
  }
}

export function usePersistentFlag(key: string, fallback: boolean) {
  const storageKey = `vpnm.flag.${key}`;
  const [value, setValue] = useState(() => {
    try {
      const raw = window.localStorage.getItem(storageKey);
      return raw === null ? fallback : raw === "1";
    } catch {
      return fallback;
    }
  });
  const update = useCallback(
    (next: boolean) => {
      setValue(next);
      write(storageKey, next ? "1" : "0");
    },
    [storageKey],
  );
  return [value, update] as const;
}

/** One of `allowed`, remembered by this browser under `vpnm.choice.<key>`; anything else stored reads as `fallback`. */
export function usePersistentChoice<V extends string>(key: string, allowed: readonly V[], fallback: V) {
  const storageKey = `vpnm.choice.${key}`;
  const [value, setValue] = useState<V>(() => {
    try {
      const raw = window.localStorage.getItem(storageKey);
      return allowed.find((v) => v === raw) ?? fallback;
    } catch {
      return fallback;
    }
  });
  const update = useCallback(
    (next: V) => {
      setValue(next);
      write(storageKey, next);
    },
    [storageKey],
  );
  return [value, update] as const;
}
