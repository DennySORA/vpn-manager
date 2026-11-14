// The actions of an automatic ban — one model for its table row (docs/frontend-design.md
// §8.1). A ban has no inspector: the row's quick action is 解除封鎖 and its ⋯ menu holds the rest (複製來源位址,
// 前往所屬連線 — the proxy port's name and icon for the same navigation). An expired ban still shows the action, with why
// it is not needed. `sendUnban` is the one way a lift is sent (idempotent per ban; the row shows it while on its way).
import { Copy, LockOpen, Network } from "lucide-react";
import { apiMutate } from "@/api/client";
import { keys } from "@/api/queries";
import type { Ban, UnbanResult } from "@/api/types";
import { queryClient } from "@/api/query-client";
import type { ActionSpec } from "@/components/ui/action-model";
import { writeClipboard } from "@/components/ui/copy";
import { reportFailure, toast } from "@/components/ui/toast";
import { createFlights } from "@/lib/flights";
import { intentKey } from "@/lib/intent";
import { m } from "./bans/messages";
import { secondsLeft } from "./model";

export type BanActionId = "unban" | "copy_source" | "open_instance";

export interface BanActionContext {
  /** Why nothing can be sent now (the controller or the manager is unreachable), or null. */
  blocked: string | null;
  now: number;
  /** The connection that banned it still exists (else 前往所屬連線 says why not). */
  instanceKnown: boolean;
  /** The ban's lift on its way, if any. */
  sending?: "unban" | null;
}

export function banActions(b: Ban, ctx: BanActionContext): ActionSpec<BanActionId>[] {
  const expired = secondsLeft(b.expires_at, ctx.now) === 0;
  return [
    {
      id: "unban",
      label: m.actions.unban,
      icon: LockOpen,
      slot: "header",
      quick: true,
      disabledReason: ctx.blocked ?? (expired ? m.actions.expired : null),
      pendingLabel: m.actions.unbanning,
    },
    { id: "copy_source", label: m.actions.copySource, icon: Copy, slot: "menu", disabledReason: null },
    {
      id: "open_instance",
      label: m.actions.openConnection,
      icon: Network,
      slot: "menu",
      disabledReason: ctx.instanceKnown ? null : m.actions.connectionDeleted,
    },
  ];
}

const flights = createFlights<"unban">(() => void queryClient.invalidateQueries({ queryKey: keys.allBans }));

/** The ban's lift on its way, if any. */
export const useUnbanSending = (id: string) => flights.useSending(id);

/** Copies the banned source; the notification says what is on the clipboard. */
export async function copySource(b: Ban): Promise<void> {
  try {
    await writeClipboard(b.source);
    toast.success(m.actions.copied(b.source));
  } catch {
    toast.error(m.actions.copyFailed, m.actions.copyRefused(b.source));
  }
}

/**
 * Lifts the ban: the source may come in again through a forward, and proxied connections to it are no longer refused.
 * Blocklists and the security profile still apply. `onDone` runs once it was accepted.
 */
export function sendUnban(b: Ban, onDone: () => void): Promise<void> {
  return flights.fly(b.id, "unban", async () => {
    const intent = intentKey(`ban.delete:${b.id}`, { id: b.id });
    try {
      const r = await apiMutate<UnbanResult | undefined>("DELETE", `/v1/bans/${b.id}`, undefined, {
        idempotencyKey: intent.key,
      });
      intent.settle();
      onDone();
      const w = r.data?.worker;
      if (w === "applied") toast.success(m.actions.unbanned(b.source), m.actions.applied);
      else if (w === "not_running") toast.success(m.actions.unbanned(b.source), m.actions.notRunning);
      else if (w === "unconfirmed") toast.info(m.actions.recordRemoved(b.source), m.actions.unconfirmed);
      else toast.success(m.actions.unbanned(b.source));
    } catch (e) {
      intent.settle(e);
      reportFailure(m.actions.unbanIntent(b.source), e);
    }
  });
}
