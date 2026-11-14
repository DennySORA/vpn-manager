import { useMemo, useRef } from "react";
import { ApiFailure, newIdempotencyKey } from "@/api/client";

/**
 * Keys of intents whose outcome is unknown, by scope and body fingerprint. Module-level, so
 * closing and reopening a dialog and sending the same content again still reuses the key: the
 * server then answers with the original result instead of acting twice.
 */
const unknownKeys = new Map<string, string>();

/** FNV-1a 64-bit, hex: identifies a body without keeping it (bodies may hold private keys). */
export function fingerprint(text: string): string {
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i++) {
    h ^= BigInt(text.charCodeAt(i));
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, "0");
}

/** The outcome of `key` is known now (looked up): a later identical intent gets a new key. */
export function forgetUnknownKey(key: string) {
  for (const [fp, k] of unknownKeys) if (k === key) unknownKeys.delete(fp);
}

/**
 * The key of one intent sent from outside a component (e.g. a notification's action), with the
 * same rules as `useIntentKey`: an identical intent whose outcome is still unknown reuses its key.
 */
export function intentKey(scope: string, body: unknown): { key: string; settle: (error?: unknown) => void } {
  const fp = `${scope}|${fingerprint(JSON.stringify(body ?? null))}`;
  const key = unknownKeys.get(fp) ?? newIdempotencyKey();
  return {
    key,
    settle(error?: unknown) {
      if (error instanceof ApiFailure && error.kind === "unknown_outcome") unknownKeys.set(fp, key);
      else unknownKeys.delete(fp);
    },
  };
}

/**
 * Idempotency keys for one kind of user intent (`scope`, e.g. "instance.create"). The identical
 * body reuses its key while a request is in flight or its outcome is unknown; a changed body, a
 * success or a definite failure starts a new key.
 */
export function useIntentKey(scope: string) {
  const last = useRef<{ key: string; fp: string } | null>(null);
  return useMemo(
    () => ({
      next(body: unknown): string {
        const fp = `${scope}|${fingerprint(JSON.stringify(body ?? null))}`;
        const pending = unknownKeys.get(fp) ?? (last.current?.fp === fp ? last.current.key : undefined);
        const key = pending ?? newIdempotencyKey();
        last.current = { key, fp };
        return key;
      },
      settle(error?: unknown) {
        const cur = last.current;
        if (!cur) return;
        if (error instanceof ApiFailure && error.kind === "unknown_outcome") {
          unknownKeys.set(cur.fp, cur.key);
          return;
        }
        unknownKeys.delete(cur.fp);
        last.current = null;
      },
      /** Forget this component's attempt (e.g. its dialog closed); unknown outcomes are kept. */
      reset() {
        last.current = null;
      },
    }),
    [scope],
  );
}
