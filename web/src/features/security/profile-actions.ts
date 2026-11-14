// The actions of a security profile — one model for its list row (the ⋯ menu) and its editor
// (docs/frontend-design.md §8.1): footer = 儲存 (the editor's one primary action), menu = 刪除. Nothing is hidden for
// being unavailable: 刪除 says which connections still use the profile. `sendSecurityDelete` is the one way the deletion
// is sent (idempotent per profile and revision; every view of the profile shows it while it is on its way).
import { Save, Trash2 } from "lucide-react";
import { apiMutate } from "@/api/client";
import { keys } from "@/api/queries";
import type { SecurityProfile } from "@/api/types";
import { queryClient } from "@/api/query-client";
import type { ActionSpec } from "@/components/ui/action-model";
import { m as ui } from "@/components/ui/messages";
import { reportFailure, toast } from "@/components/ui/toast";
import { createFlights } from "@/lib/flights";
import { intentKey } from "@/lib/intent";
import { m } from "./messages";

export type SecurityActionId = "save" | "delete";

export interface SecurityActionContext {
  /** Why nothing can be sent now (the controller or the manager is unreachable), or null. */
  blocked: string | null;
  /** Connections whose security profile this is: it cannot be deleted while one does. */
  users: number;
  /** The editor holds changes that are not saved (the row has no draft: false). */
  dirty?: boolean | undefined;
  /** The profile's intent on its way, if any. */
  sending?: "delete" | null;
}

export function securityActions(_p: SecurityProfile, ctx: SecurityActionContext): ActionSpec<SecurityActionId>[] {
  const busy = ctx.sending === "delete" ? m.actions.deleting : null;
  return [
    {
      id: "save",
      label: ui.common.save,
      icon: Save,
      slot: "footer",
      disabledReason: ctx.blocked ?? busy ?? (ctx.dirty ? null : ui.common.noUnsavedChanges),
      pendingLabel: ui.common.saving,
    },
    {
      id: "delete",
      label: ui.common.delete,
      icon: Trash2,
      slot: "menu",
      danger: true,
      disabledReason: ctx.blocked ?? (ctx.users ? m.actions.inUse(ctx.users) : null),
      pendingLabel: ui.common.deleting,
    },
  ];
}

const flights = createFlights<"delete">(() => {
  void queryClient.invalidateQueries({ queryKey: keys.security });
  // Which profiles use a list changes with it.
  void queryClient.invalidateQueries({ queryKey: keys.blocklists });
});

/** The profile's intent on its way, if any. */
export const useSecuritySending = (id: string) => flights.useSending(id);

/** Deletes the profile (no connection uses it); `onDone` runs once it is gone. */
export function sendSecurityDelete(p: SecurityProfile, onDone: () => void): Promise<void> {
  return flights.fly(p.id, "delete", async () => {
    const intent = intentKey(`security.delete:${p.id}`, { rev: p.revision });
    try {
      await apiMutate<undefined>("DELETE", `/v1/security-profiles/${p.id}`, undefined, {
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
