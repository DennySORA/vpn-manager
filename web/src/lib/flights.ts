import { useSyncExternalStore } from "react";

/**
 * Intents on their way, by object (docs/frontend-design.md §8.1): one store outside React that every view of an object
 * reads — its list row, its inspector — so they all show the same spinner, and the identical intent
 * is never sent twice while it is on its way. One intent per object at a time is the caller's rule (the action model
 * disables the others with a reason); the store only records what is flying.
 */
export interface Flights<W extends string> {
  /** Runs `send` as object `id`'s intent `what`; while the identical one is on its way, that one is returned instead. */
  fly(id: string, what: W, send: () => Promise<void>): Promise<void>;
  /** The intent of object `id` on its way, or null (re-renders when it changes). */
  useSending(id: string): W | null;
}

export function createFlights<W extends string>(onSettled?: () => void): Flights<W> {
  const sending = new Map<string, W>();
  const flights = new Map<string, Promise<void>>();
  const listeners = new Set<() => void>();
  let snapshot: ReadonlyMap<string, W> = new Map();
  const publish = () => {
    snapshot = new Map(sending);
    for (const l of listeners) l();
  };
  const subscribe = (l: () => void) => {
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  };
  return {
    fly(id, what, send) {
      const key = `${id}␟${what}`;
      const existing = flights.get(key);
      if (existing) return existing;
      sending.set(id, what);
      publish();
      const flight = send().finally(() => {
        flights.delete(key);
        if (sending.get(id) === what) sending.delete(id);
        publish();
        onSettled?.();
      });
      flights.set(key, flight);
      return flight;
    },
    useSending(id) {
      return useSyncExternalStore(
        subscribe,
        () => snapshot.get(id) ?? null,
        () => null,
      );
    },
  };
}
