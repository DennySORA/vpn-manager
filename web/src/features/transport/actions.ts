// The actions of a transport profile — one model for its list row (the ⋯ menu) and its editor
// (docs/frontend-design.md §8.1): footer = 儲存 (a saved profile's editor) or 複製成我的設定 (a built-in one, which
// cannot be changed), menu = 複製、刪除. Nothing is hidden for being unavailable: 刪除 says what still uses the profile.
// `sendTransportDelete` is the one way the deletion is sent (idempotent per profile and revision; every view of the
// profile shows it while it is on its way).
import { Copy, Save, Trash2 } from "lucide-react";
import { apiMutate } from "@/api/client";
import { keys } from "@/api/queries";
import type { TransportProfile } from "@/api/types";
import { queryClient } from "@/api/query-client";
import type { ActionSpec } from "@/components/ui/action-model";
import { m as ui } from "@/components/ui/messages";
import { reportFailure, toast } from "@/components/ui/toast";
import { createFlights } from "@/lib/flights";
import { intentKey } from "@/lib/intent";
import { m } from "./messages";
import type { Choice } from "./model";

export type TransportActionId = "save" | "copy" | "delete";

export interface TransportActionContext {
  /** Why nothing can be sent now (the controller or the manager is unreachable), or null. */
  blocked: string | null;
  /** Connections that use this profile: it cannot be deleted while one does. */
  users: number;
  /** Automatic profiles a range of which names this one (their names): it cannot be deleted while one does. */
  namedBy: readonly string[];
  /** The editor holds changes that are not saved (the row has no draft: false). */
  dirty?: boolean | undefined;
  /** The profile's intent on its way, if any. */
  sending?: "delete" | null;
}

export function transportActions(c: Choice, ctx: TransportActionContext): ActionSpec<TransportActionId>[] {
  if (c.builtin) {
    // Part of the program: a copy is the way to change it.
    return [{ id: "copy", label: m.actions.copyBuiltIn, icon: Copy, slot: "footer", disabledReason: ctx.blocked }];
  }
  const busy = ctx.sending === "delete" ? m.actions.deleting : null;
  const inUse = ctx.users ? m.actions.inUse(ctx.users) : ctx.namedBy.length ? m.actions.namedBy(ctx.namedBy) : null;
  return [
    {
      id: "save",
      label: ui.common.save,
      icon: Save,
      slot: "footer",
      disabledReason: ctx.blocked ?? busy ?? (ctx.dirty ? null : ui.common.noUnsavedChanges),
      pendingLabel: ui.common.saving,
    },
    { id: "copy", label: m.actions.copy, icon: Copy, slot: "menu", disabledReason: ctx.blocked ?? busy },
    {
      id: "delete",
      label: ui.common.delete,
      icon: Trash2,
      slot: "menu",
      danger: true,
      disabledReason: ctx.blocked ?? inUse,
      pendingLabel: ui.common.deleting,
    },
  ];
}

const flights = createFlights<"delete">(() => void queryClient.invalidateQueries({ queryKey: keys.transport }));

/** The profile's intent on its way, if any. */
export function useTransportSending(id: string): "delete" | null {
  return flights.useSending(id);
}

/** Deletes the profile (connections are not affected: none uses it); `onDone` runs once it is gone. */
export function sendTransportDelete(p: TransportProfile, onDone: () => void): Promise<void> {
  return flights.fly(p.id, "delete", async () => {
    const intent = intentKey(`transport.delete:${p.id}`, { rev: p.revision });
    try {
      await apiMutate<undefined>("DELETE", `/v1/transport-profiles/${p.id}`, undefined, {
        idempotencyKey: intent.key,
        ifMatch: p.revision,
      });
      intent.settle();
      toast.success(m.actions.deleted(p.name));
      onDone();
    } catch (e) {
      intent.settle(e);
      reportFailure(m.actions.deleteIntent(p.name), e);
    }
  });
}
