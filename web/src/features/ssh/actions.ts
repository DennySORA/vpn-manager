// The actions of an SSH host entry — one model for its list row (the ⋯ menu) and its editor
// (docs/frontend-design.md §8.1): header = 測試連線 (its result is the editor's first fact), footer = 儲存 (the editor's
// one primary action), menu = 移除. A block of the user's own ~/.ssh/config is read only: its one action is to route it
// through the VPN (or open the entry that already does). The file actions (加入 Include, 寫入 vpn-manager.conf, 以
// VPN Manager 的內容取代) belong to the page's status strip. Nothing is hidden for being unavailable.
import { FileCheck2, FilePlus2, Radar, Replace, Route, Save, Trash2 } from "lucide-react";
import { apiMutate } from "@/api/client";
import { keys, type SshFileAction } from "@/api/queries";
import type { SshExistingHost, SshHost } from "@/api/types";
import { queryClient } from "@/api/query-client";
import type { ActionSpec } from "@/components/ui/action-model";
import { m as ui } from "@/components/ui/messages";
import { reportFailure, toast } from "@/components/ui/toast";
import { createFlights } from "@/lib/flights";
import { intentKey } from "@/lib/intent";
import { m } from "./messages";

export type SshActionId = "test" | "save" | "remove";

export interface SshActionContext {
  /** Why nothing can be sent now (the controller or the manager is unreachable), or null. */
  blocked: string | null;
  /** The editor holds changes that are not saved (the row has no draft: false). */
  dirty?: boolean | undefined;
  /** The entry's removal on its way, if any. */
  sending?: "remove" | null;
}

export function sshActions(h: SshHost, ctx: SshActionContext): ActionSpec<SshActionId>[] {
  const busy = ctx.sending === "remove" ? m.actions.removeSending : null;
  return [
    {
      id: "test",
      label: m.actions.test,
      icon: Radar,
      slot: "header",
      // A read-only probe through the saved proxy port: nothing to probe for a direct entry or an unsaved route.
      disabledReason: busy ?? (!h.gateway_id ? m.actions.testDirect : ctx.dirty ? m.actions.testUnsaved : null),
      pendingLabel: m.actions.testing,
    },
    {
      id: "save",
      label: ui.common.save,
      icon: Save,
      slot: "footer",
      disabledReason: ctx.blocked ?? busy ?? (ctx.dirty ? null : ui.common.noUnsavedChanges),
      pendingLabel: ui.common.saving,
    },
    {
      id: "remove",
      label: m.actions.remove,
      icon: Trash2,
      slot: "menu",
      danger: true,
      disabledReason: ctx.blocked,
      pendingLabel: m.actions.removing,
    },
  ];
}

export type ExistingActionId = "route" | "open_overlay";

/** A block of ~/.ssh/config (read only): route it through the VPN, or open the entry that already does. */
export function existingActions(x: SshExistingHost, overlay: SshHost | undefined): ActionSpec<ExistingActionId>[] {
  return overlay
    ? [{ id: "open_overlay", label: m.actions.openEntry, icon: Route, slot: "footer", disabledReason: null }]
    : [
        {
          id: "route",
          label: m.actions.route,
          icon: Route,
          slot: "footer",
          disabledReason: x.wildcard ? m.actions.wildcard : null,
        },
      ];
}

/** The one name and icon of each file action, wherever it is offered or reported. */
export const FILE_ACTION: Record<SshFileAction, { label: string; icon: typeof Save }> = {
  include: { label: m.file.action.include, icon: FilePlus2 },
  apply: { label: m.file.action.apply, icon: FileCheck2 },
  overwrite: { label: m.file.action.overwrite, icon: Replace },
};

const flights = createFlights<"remove">(() => {
  void queryClient.invalidateQueries({ queryKey: keys.ssh });
  void queryClient.invalidateQueries({ queryKey: keys.sshHosts });
});

/** The entry's removal on its way, if any. */
export const useSshSending = (id: string) => flights.useSending(id);

/** Removes the entry from vpn-manager.conf (an overlaid host goes back to the user's own block); `onDone` once gone. */
export function sendSshRemove(h: SshHost, onDone: () => void): Promise<void> {
  return flights.fly(h.id, "remove", async () => {
    const intent = intentKey(`ssh_host.remove:${h.id}`, { rev: h.revision });
    try {
      await apiMutate<undefined>("DELETE", `/v1/ssh-hosts/${h.id}`, undefined, {
        idempotencyKey: intent.key,
        ifMatch: h.revision,
      });
      intent.settle();
      toast.success(m.remove.removed(h.alias));
      onDone();
    } catch (e) {
      intent.settle(e);
      reportFailure(m.intent.remove(h.alias), e);
    }
  });
}
