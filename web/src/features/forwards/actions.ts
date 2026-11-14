// The actions of a port forward — one model for its list row and its inspector
// (docs/frontend-design.md §8.1): header = 停用／啟用 (also the row's quick action) and 編輯; footer = 測試連入 (the
// inspector's evidence check: AirVPN connects to the port from its servers); menu = 前往目標 App, 前往所屬連線 | 刪除.
// `sendForwardEnabled` / `sendForwardDelete` are the one way each intent is sent (idempotent, shown on every view of the
// forward while on its way).
import { AppWindow, Network, Pencil, Power, PowerOff, ScanSearch, Trash2 } from "lucide-react";
import { apiMutate } from "@/api/client";
import { keys } from "@/api/queries";
import type { ForwardInput, ForwardView } from "@/api/types";
import { queryClient } from "@/api/query-client";
import type { ActionSpec } from "@/components/ui/action-model";
import { m as ui } from "@/components/ui/messages";
import { reportFailure, toast } from "@/components/ui/toast";
import { createFlights } from "@/lib/flights";
import { intentKey } from "@/lib/intent";
import { m } from "./messages";

export type ForwardActionId = "enable" | "disable" | "edit" | "test" | "open_app" | "open_instance" | "delete";

type Sends = "enable" | "disable" | "delete";

const WORD: Record<Sends, string> = { enable: ui.common.enable, disable: ui.common.disable, delete: ui.common.delete };

export interface ForwardActionContext {
  /** The forward's intent on its way, if any. */
  sending?: Sends | null;
  /** Why the forward cannot be switched on at all (the connection's provider does not forward), or null. */
  unsupported: string | null;
  /** Why AirVPN cannot test it now, or null (it can). */
  testProblem: string | null;
  /** Whether its target App and its connection are known (else 前往… says why not). */
  appKnown: boolean;
  ownerKnown: boolean;
}

/** Why AirVPN cannot test a forward of `protocol` on a connection of `account` (null: not built from an account). */
export function testProblemOf(
  protocol: ForwardView["binding"]["protocol"],
  hasAccount: boolean,
  blocked: string | null,
): string | null {
  if (blocked) return blocked;
  if (!hasAccount) return m.actions.testNeedsAccount;
  if (protocol === "udp") return m.actions.testTcpOnly;
  return null;
}

export function forwardActions(f: ForwardView, ctx: ForwardActionContext): ActionSpec<ForwardActionId>[] {
  const b = f.binding;
  const lock = (id: Sends): string | null =>
    ctx.sending && ctx.sending !== id ? m.actions.busy(WORD[ctx.sending]) : null;
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
          disabledReason: lock("enable") ?? ctx.unsupported,
          pendingLabel: ui.common.enabling,
        },
    { id: "edit", label: ui.common.edit, icon: Pencil, slot: "header", disabledReason: null },
    {
      id: "test",
      label: m.actions.test,
      icon: ScanSearch,
      slot: "footer",
      disabledReason: ctx.testProblem,
      pendingLabel: m.actions.testing,
    },
    {
      id: "open_app",
      label: m.actions.openApp,
      icon: AppWindow,
      slot: "menu",
      disabledReason: ctx.appKnown ? null : m.actions.appNotFound,
    },
    {
      id: "open_instance",
      label: m.actions.openInstance,
      icon: Network,
      slot: "menu",
      disabledReason: ctx.ownerKnown ? null : m.actions.instanceNotFound,
    },
    { id: "delete", label: ui.common.delete, icon: Trash2, slot: "menu", danger: true, disabledReason: lock("delete") },
  ];
}

const flights = createFlights<Sends>(() => {
  void queryClient.invalidateQueries({ queryKey: keys.forwards });
  void queryClient.invalidateQueries({ queryKey: keys.inbound });
});

/** The forward's intent on its way, if any. */
export function useForwardSending(id: string): Sends | null {
  return flights.useSending(id);
}

/** The binding as it is, but switched on or off. */
function toggled(b: ForwardView["binding"], enabled: boolean): ForwardInput {
  return {
    instance_id: b.instance_id,
    name: b.name,
    protocol: b.protocol,
    tunnel_port: b.tunnel_port,
    public_port: b.public_port,
    target_app_id: b.target_app_id,
    target_port: b.target_port,
    enabled,
    max_connections: b.max_connections,
    proxy_protocol: b.proxy_protocol,
    udp_direct: b.udp_direct,
  };
}

/** Switches the forward on or off (it listens once its connection runs and its App holds the port): the saved revision, all else unchanged. */
export function sendForwardEnabled(f: ForwardView, enabled: boolean): Promise<void> {
  const b = f.binding;
  return flights.fly(b.id, enabled ? "enable" : "disable", async () => {
    const input = toggled(b, enabled);
    const intent = intentKey(`forward.toggle:${b.id}`, { rev: b.revision, input });
    try {
      await apiMutate<ForwardView>("PUT", `/v1/forward-bindings/${b.id}`, input, {
        idempotencyKey: intent.key,
        ifMatch: b.revision,
      });
      intent.settle();
      toast.success(enabled ? m.toast.enabled(b.name) : m.toast.disabled(b.name));
    } catch (e) {
      intent.settle(e);
      reportFailure(enabled ? m.toast.enableIntent(b.name) : m.toast.disableIntent(b.name), e);
    }
  });
}

/**
 * Forwards deleted from this page: their inspector place shows 「選擇一個轉發」, not 「找不到這個轉發」, in the moment
 * between the forward leaving the list and the selection leaving the URL.
 */
const deletedHere = new Set<string>();

export function wasDeletedHere(id: string): boolean {
  return deletedHere.has(id);
}

/** Deletes the forward (the provider's reserved port and the App are not affected); `onDone` runs once it is gone. */
export function sendForwardDelete(f: ForwardView, onDone: () => void): Promise<void> {
  const b = f.binding;
  return flights.fly(b.id, "delete", async () => {
    const intent = intentKey(`forward.delete:${b.id}`, { rev: b.revision });
    try {
      await apiMutate<undefined>("DELETE", `/v1/forward-bindings/${b.id}`, undefined, {
        idempotencyKey: intent.key,
        ifMatch: b.revision,
      });
      intent.settle();
      deletedHere.add(b.id);
      // It leaves the list at once (its row fades out); the list reloads in the background.
      queryClient.setQueryData<ForwardView[]>(keys.forwards, (all) => all?.filter((x) => x.binding.id !== b.id));
      toast.success(m.toast.deleted(b.name));
      onDone();
    } catch (e) {
      intent.settle(e);
      reportFailure(m.toast.deleteIntent(b.name), e);
    }
  });
}
