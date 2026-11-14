// The port suggested for a new local proxy port. The controller knows which ports are actually free
// on this host (`GET /v1/ports/free`); when it cannot answer, the first port no Gateway uses.

import { useFreePort } from "@/api/queries";

/** Where suggestions start (the conventional SOCKS port). */
export const FIRST_PORT = 1080;

/** The first port at or after `from` that no Gateway uses (local fallback). */
export function suggestPort(used: number[], from = FIRST_PORT): number {
  for (let p = from; p <= 65535; p++) if (!used.includes(p)) return p;
  return from;
}

/** The controller's answer when it has one that no known Gateway holds; the local guess otherwise. */
export function pickPort(server: number | undefined, used: number[], from = FIRST_PORT): number {
  if (server !== undefined && Number.isInteger(server) && server >= 1024 && server <= 65535 && !used.includes(server))
    return server;
  return suggestPort(used, from);
}

/** The suggestion for a new Gateway; asks the controller only while `enabled`. */
export function useSuggestedPort(used: number[], enabled = true): number {
  const free = useFreePort(FIRST_PORT, enabled);
  return pickPort(enabled && free.isSuccess ? free.data.port : undefined, used);
}
