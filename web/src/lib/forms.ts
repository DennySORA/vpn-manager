import { useState } from "react";
import { ApiFailure } from "@/api/client";

/** A new number each time `open` turns true; key a form with it so every opening starts fresh. */
export function useOpenSession(open: boolean): number {
  const [prev, setPrev] = useState(open);
  const [session, setSession] = useState(0);
  if (open !== prev) {
    setPrev(open);
    if (open) setSession((s) => s + 1);
  }
  return session;
}

/** Server field errors by JSON-pointer path ("/port"). */
export function serverFieldErrors(e: unknown): Map<string, string> {
  return e instanceof ApiFailure ? e.fieldErrors() : new Map<string, string>();
}

export function isRevisionConflict(e: unknown): boolean {
  return e instanceof ApiFailure && e.code === "REVISION_CONFLICT";
}

/** Parse a whole-number field; `null` when empty or not an integer. */
export function parseIntField(v: string): number | null {
  const t = v.trim();
  if (!/^\d+$/.test(t)) return null;
  const n = Number(t);
  return Number.isSafeInteger(n) ? n : null;
}
