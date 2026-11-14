// The actions of a local proxy port (Gateway) — one model for its list row and its inspector
// (docs/frontend-design.md §8.1): header = 停用／啟用 and 編輯, footer = 複製代理位址 (the view's primary task: using
// the port), menu = 前往所屬連線 and 刪除. `sendEnabled` is the one way the switch is sent (idempotent, shown on every
// view of the port while on its way).
import { Copy, Network, Pencil, Power, PowerOff, Trash2 } from "lucide-react";
import { apiMutate } from "@/api/client";
import { keys } from "@/api/queries";
import type { GatewayInput, GatewaySpec } from "@/api/types";
import { queryClient } from "@/api/query-client";
import type { ActionSpec } from "@/components/ui/action-model";
import { writeClipboard } from "@/components/ui/copy";
import { m as ui } from "@/components/ui/messages";
import { reportFailure, toast } from "@/components/ui/toast";
import { createFlights } from "@/lib/flights";
import { intentKey } from "@/lib/intent";
import { m } from "./messages";

export type GatewayActionId = "enable" | "disable" | "edit" | "copy_address" | "open_instance" | "delete";

type Sends = "enable" | "disable" | "delete";

const WORD: Record<Sends, string> = {
  enable: ui.common.enable,
  disable: ui.common.disable,
  delete: ui.common.delete,
};

export interface GatewayActionContext {
  /** The port's intent on its way, if any. */
  sending?: Sends | null;
  /** Whether the connection it belongs to is known (else 前往所屬連線 says why not). */
  ownerKnown: boolean;
}

export function gatewayActions(g: GatewaySpec, ctx: GatewayActionContext): ActionSpec<GatewayActionId>[] {
  const lock = (id: Sends): string | null =>
    ctx.sending && ctx.sending !== id ? m.action.busy(WORD[ctx.sending]) : null;
  return [
    g.enabled
      ? {
          id: "disable",
          label: ui.common.disable,
          icon: PowerOff,
          slot: "header",
          quick: true,
          disabledReason: lock("disable"),
          pendingLabel: m.action.disabling,
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
    { id: "copy_address", label: m.action.copyAddress, icon: Copy, slot: "footer", disabledReason: null },
    {
      id: "open_instance",
      label: m.action.openInstance,
      icon: Network,
      slot: "menu",
      disabledReason: ctx.ownerKnown ? null : m.ownerNotFound,
    },
    { id: "delete", label: ui.common.delete, icon: Trash2, slot: "menu", danger: true, disabledReason: lock("delete") },
  ];
}

const flights = createFlights<Sends>(() => {
  void queryClient.invalidateQueries({ queryKey: keys.gateways });
  void queryClient.invalidateQueries({ queryKey: keys.instances });
});

/** The port's intent on its way, if any. */
export function useGatewaySending(id: string): Sends | null {
  return flights.useSending(id);
}

/** Turns the port on or off (bound while its connection runs, or not): the saved revision, all else unchanged. */
export function sendEnabled(g: GatewaySpec, enabled: boolean): Promise<void> {
  return flights.fly(g.id, enabled ? "enable" : "disable", async () => {
    const input: GatewayInput = {
      instance_id: g.instance_id,
      name: g.name,
      kind: g.kind,
      port: g.port,
      enabled,
      udp: g.udp,
      max_connections: g.max_connections,
    };
    const intent = intentKey(`gateway.toggle:${g.id}`, { rev: g.revision, input });
    try {
      await apiMutate<GatewaySpec>("PUT", `/v1/gateways/${g.id}`, input, {
        idempotencyKey: intent.key,
        ifMatch: g.revision,
      });
      intent.settle();
      toast.success(enabled ? m.toast.enabled(g.name) : m.toast.disabled(g.name));
    } catch (e) {
      intent.settle(e);
      reportFailure(enabled ? m.intent.enable(g.name) : m.intent.disable(g.name), e);
    }
  });
}

/** Deletes the port (its connection is not affected); `onDone` runs once it is gone. */
export function sendDelete(g: GatewaySpec, onDone: () => void): Promise<void> {
  return flights.fly(g.id, "delete", async () => {
    const intent = intentKey(`gateway.delete:${g.id}`, { rev: g.revision });
    try {
      await apiMutate<undefined>("DELETE", `/v1/gateways/${g.id}`, undefined, {
        idempotencyKey: intent.key,
        ifMatch: g.revision,
      });
      intent.settle();
      toast.success(m.toast.deleted(g.name));
      onDone();
    } catch (e) {
      intent.settle(e);
      reportFailure(m.intent.delete(g.name), e);
    }
  });
}

/** 127.0.0.1:<port>: what applications are configured with. */
export function proxyAddress(g: Pick<GatewaySpec, "port">): string {
  return `127.0.0.1:${g.port}`;
}

/** Copies the port's address; the notification says what is on the clipboard. */
export async function copyAddress(g: GatewaySpec): Promise<void> {
  const address = proxyAddress(g);
  try {
    await writeClipboard(address);
    toast.success(m.toast.copied(address), m.toast.copiedHint);
  } catch {
    toast.error(m.toast.copyFailed, m.toast.copyFailedHint(address));
  }
}
