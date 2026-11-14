// The actions of an IP blocklist — one model for its list row and its detail
// (docs/frontend-design.md §8.1): header = 停用／啟用 (also the row's quick action) and 編輯; footer = the view's
// primary action, getting new content — 立即更新 for a list downloaded from its URL, 更新內容 for an uploaded one;
// menu = 刪除. Nothing is hidden for being unavailable: each action says why it waits. The switch, the download and the
// deletion are sent from here (idempotent per list and revision; every view of the list shows the one on its way, and
// one intent per list at a time).
import { Pencil, Power, PowerOff, RefreshCw, Trash2, Upload } from "lucide-react";
import { apiMutate } from "@/api/client";
import { keys } from "@/api/queries";
import type { BlocklistUpdate, BlocklistView } from "@/api/types";
import { queryClient } from "@/api/query-client";
import type { ActionSpec } from "@/components/ui/action-model";
import { m as ui } from "@/components/ui/messages";
import { reportFailure, toast } from "@/components/ui/toast";
import { localized } from "@/i18n";
import { createFlights } from "@/lib/flights";
import { intentKey } from "@/lib/intent";
import { m } from "./blocklists/messages";
import { listName } from "./model";

export type BlocklistActionId = "enable" | "disable" | "edit" | "refresh" | "replace" | "delete";

type Sends = "enable" | "disable" | "refresh" | "delete";

const WORD: Record<Sends, string> = {
  enable: ui.common.enable,
  disable: ui.common.disable,
  refresh: m.actions.refresh,
  delete: ui.common.delete,
};

export function sendsOf(id: BlocklistActionId): Sends | null {
  return id === "enable" || id === "disable" || id === "refresh" || id === "delete" ? id : null;
}

export interface BlocklistActionContext {
  /** Why nothing can be sent now (the controller or the manager is unreachable), or null. */
  blocked: string | null;
  /** The list's intent on its way, if any. */
  sending?: Sends | null;
}

export function blocklistActions(v: BlocklistView, ctx: BlocklistActionContext): ActionSpec<BlocklistActionId>[] {
  const b = v.blocklist;
  // One intent per list at a time: the others wait for it (the one on its way shows a spinner instead).
  const lock = (id: Sends): string | null =>
    ctx.blocked ?? (ctx.sending && ctx.sending !== id ? m.actions.busy(WORD[ctx.sending]) : null);
  const users = v.used_by.length;
  return [
    b.enabled
      ? {
          id: "disable",
          label: ui.common.disable,
          icon: PowerOff,
          slot: "header",
          quick: true,
          disabledReason: lock("disable"),
          pendingLabel: m.actions.disabling,
        }
      : {
          id: "enable",
          label: ui.common.enable,
          icon: Power,
          slot: "header",
          quick: true,
          disabledReason: lock("enable"),
          pendingLabel: ui.common.enabling,
        },
    { id: "edit", label: ui.common.edit, icon: Pencil, slot: "header", disabledReason: null },
    b.source.kind === "url"
      ? {
          id: "refresh",
          label: m.actions.refresh,
          icon: RefreshCw,
          slot: "footer",
          disabledReason:
            lock("refresh") ?? (!b.enabled ? m.actions.listDisabled : v.waiting ? localized(v.waiting) : null),
          pendingLabel: m.downloading,
        }
      : { id: "replace", label: m.actions.replace, icon: Upload, slot: "footer", disabledReason: null },
    {
      id: "delete",
      label: ui.common.delete,
      icon: Trash2,
      slot: "menu",
      danger: true,
      disabledReason: lock("delete") ?? (users ? m.actions.inUse(users) : null),
      pendingLabel: ui.common.deleting,
    },
  ];
}

// ---------------------------------------------------------------------------------------------------------------
// Sending: one intent per list at a time, shared by every place that offers it. Lists, the security profiles that use
// them and the overlays running connections enforce all change with a list.

const flights = createFlights<Sends>(() => {
  void queryClient.invalidateQueries({ queryKey: keys.blocklists });
  void queryClient.invalidateQueries({ queryKey: keys.security });
  void queryClient.invalidateQueries({ queryKey: keys.instances });
});

/** The list's intent on its way, if any. */
export const useBlocklistSending = (id: string) => flights.useSending(id);

/** Turns the list on or off at once: a disabled list is neither downloaded nor enforced anywhere. All else unchanged. */
export function sendBlocklistEnabled(v: BlocklistView, enabled: boolean): Promise<void> {
  const b = v.blocklist;
  return flights.fly(b.id, enabled ? "enable" : "disable", async () => {
    const input: BlocklistUpdate = { name: b.name, source: b.source, text: null, expected_import_hash: null, enabled };
    const intent = intentKey(`blocklist.enabled:${b.id}`, { enabled, revision: b.revision });
    try {
      await apiMutate<BlocklistView>("PUT", `/v1/blocklists/${b.id}`, input, {
        idempotencyKey: intent.key,
        ifMatch: b.revision,
      });
      intent.settle();
      toast.success(
        enabled ? m.actions.enabled(listName(v)) : m.actions.disabled(listName(v)),
        enabled ? m.actions.enabledNote : m.actions.disabledNote,
      );
    } catch (e) {
      intent.settle(e);
      reportFailure(enabled ? m.actions.enableIntent(listName(v)) : m.actions.disableIntent(listName(v)), e);
    }
  });
}

/** Downloads a URL list now (through the Provider egress); a failure is also recorded on the list (stale). */
export function sendBlocklistRefresh(v: BlocklistView): Promise<void> {
  const b = v.blocklist;
  return flights.fly(b.id, "refresh", async () => {
    const intent = intentKey(`blocklist.refresh:${b.id}`, { id: b.id, at: b.revision });
    try {
      const r = await apiMutate<BlocklistView>(
        "POST",
        `/v1/blocklists/${b.id}/refresh`,
        {},
        { idempotencyKey: intent.key },
      );
      intent.settle();
      const said = r.data.refresh?.message;
      toast.success(m.actions.refreshed(listName(v)), said ? localized(said) : undefined);
    } catch (e) {
      intent.settle(e);
      reportFailure(m.actions.refreshIntent(listName(v)), e);
    }
  });
}

/** Deletes the list and its content (no security profile uses it); `onDone` runs once it is gone. */
export function sendBlocklistDelete(v: BlocklistView, onDone: () => void): Promise<void> {
  const b = v.blocklist;
  return flights.fly(b.id, "delete", async () => {
    const intent = intentKey(`blocklist.delete:${b.id}`, { rev: b.revision });
    try {
      await apiMutate<undefined>("DELETE", `/v1/blocklists/${b.id}`, undefined, {
        idempotencyKey: intent.key,
        ifMatch: b.revision,
      });
      intent.settle();
      toast.success(m.actions.deleted(listName(v)), v.builtin ? m.actions.builtinDeleted : undefined);
      onDone();
    } catch (e) {
      intent.settle(e);
      reportFailure(m.actions.deleteIntent(listName(v)), e);
    }
  });
}
