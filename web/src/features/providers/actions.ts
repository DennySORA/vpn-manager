// The actions of the provider page's objects (docs/frontend-design.md §8.1): a provider account, one of its AirVPN
// forwarded ports (連入埠), one of its devices, and the Provider egress. Each is one pure list of what the object offers
// now — its one name and icon, where it shows and why it cannot run — that every place showing the object renders, so a
// name, an icon or a reason never differs between the account's list row and its page, or between a port's quick action
// and its ⋯ menu. Nothing unavailable is hidden: it says why instead.
import {
  ArrowRightLeft,
  ArrowUpRight,
  Ban,
  FilePlus2,
  Globe,
  Plus,
  Power,
  Radar,
  RefreshCw,
  Route,
  Settings2,
  Trash2,
  Unplug,
  X,
} from "lucide-react";
import { apiMutate } from "@/api/client";
import { keys } from "@/api/queries";
import type { ForwardedPort, ProviderAccount, ProviderDevice, ProviderEgressStatus } from "@/api/types";
import { queryClient } from "@/api/query-client";
import type { ActionSpec } from "@/components/ui/action-model";
import { m as ui } from "@/components/ui/messages";
import { reportFailure, toast } from "@/components/ui/toast";
import { createFlights } from "@/lib/flights";
import { m as egressText } from "./egress/messages";
import { m } from "./messages";
import { rebootstrapOpen } from "./model";
import { m as portText } from "./ports/messages";

// ---------------------------------------------------------------------------------------------------------------
// A provider account: header = 重新讀取帳號 (also the list row's quick action), footer = 建立連線 (the account page's
// primary task), menu = 移除帳號.

export type AccountActionId = "refresh" | "connect" | "remove";

export interface AccountActionContext {
  /** Provider requests can leave now (an egress connection is ready, or a direct grant is open). */
  egressUsable: boolean;
  /** Why nothing can be changed now (the controller or the manager is unreachable), or null. */
  blocked: string | null;
  /** WireGuard profiles this account built (an account is kept while one of them exists). */
  profiles: number;
}

const NO_EGRESS = m.egressNeeded.forRequests;

export function accountActions(_a: ProviderAccount, ctx: AccountActionContext): ActionSpec<AccountActionId>[] {
  return [
    {
      id: "refresh",
      label: m.account.refresh,
      icon: RefreshCw,
      slot: "header",
      quick: true,
      disabledReason: ctx.blocked ?? (ctx.egressUsable ? null : NO_EGRESS),
      pendingLabel: m.account.refreshing,
    },
    {
      id: "connect",
      label: m.account.connect,
      icon: Plus,
      slot: "footer",
      disabledReason: ctx.blocked ?? (ctx.egressUsable ? null : m.egressNeeded.forServerList),
    },
    {
      id: "remove",
      label: m.account.remove,
      icon: Trash2,
      slot: "menu",
      danger: true,
      disabledReason: ctx.blocked ?? (ctx.profiles ? m.account.removeBlockedByProfiles(ctx.profiles) : null),
    },
  ];
}

// Reading an account again is sent once, whichever view asked (its list row or its page): both show the spinner.
const accountFlights = createFlights<"refresh">();

/** The account's read on its way, if any (re-renders when it settles). */
export const useAccountSending = (id: string) => accountFlights.useSending(id);

/**
 * 重新讀取帳號: the provider is asked again (through the Provider egress) for the account's paid-until date; its devices,
 * servers and forwarded ports are read again too (they sit under the account's query key).
 */
export function sendRefresh(a: Pick<ProviderAccount, "id" | "label">): Promise<void> {
  return accountFlights.fly(a.id, "refresh", async () => {
    try {
      await apiMutate<ProviderAccount>("POST", `/v1/provider-accounts/${a.id}/refresh`, {});
      void queryClient.invalidateQueries({ queryKey: keys.providerAccounts });
      toast.success(m.account.refreshed(a.label), m.account.refreshedDetail);
    } catch (e) {
      reportFailure(m.account.refreshIntent(a.label), e);
    }
  });
}

// ---------------------------------------------------------------------------------------------------------------
// An AirVPN forwarded port (連入埠). A row shows its quick action (測試: AirVPN's test of the port, asked for again and
// again) and one ⋯ menu with the rest; there is no inspector: 設定 is its dialog.

export type PortActionId = "test" | "forward" | "settings" | "delete";

export interface PortActionContext {
  /** Why a forward cannot be built: no connection of this account receives it, or null. */
  noConnection: string | null;
  blocked: string | null;
  /** The port AirVPN is testing now, if any (one test at a time). */
  testing: number | null;
}

export function portActions(p: Pick<ForwardedPort, "port">, ctx: PortActionContext): ActionSpec<PortActionId>[] {
  const otherTest = ctx.testing !== null && ctx.testing !== p.port ? portText.actions.testBusy(ctx.testing) : null;
  return [
    {
      id: "test",
      label: portText.actions.test,
      icon: Radar,
      slot: "header",
      quick: true,
      disabledReason: otherTest,
      pendingLabel: portText.actions.testing,
    },
    {
      id: "forward",
      label: portText.actions.forward,
      icon: ArrowRightLeft,
      slot: "menu",
      disabledReason: ctx.blocked ?? ctx.noConnection,
    },
    { id: "settings", label: portText.actions.settings, icon: Settings2, slot: "menu", disabledReason: ctx.blocked },
    { id: "delete", label: ui.common.delete, icon: Trash2, slot: "menu", danger: true, disabledReason: ctx.blocked },
  ];
}

// ---------------------------------------------------------------------------------------------------------------
// A device of the account: Mullvad devices can be revoked here (one ⋯ menu on the row); AirVPN hands its devices and
// keys out on its website, so its devices have no actions here.

export type DeviceActionId = "revoke";

export interface DeviceActionContext {
  /** Profiles built on the device's key (revoking it breaks them all). */
  usedBy: readonly string[];
  blocked: string | null;
}

export function deviceActions(
  account: Pick<ProviderAccount, "provider">,
  _d: ProviderDevice,
  ctx: DeviceActionContext,
): ActionSpec<DeviceActionId>[] {
  if (account.provider !== "mullvad") return [];
  return [
    {
      id: "revoke",
      label: m.devices.revoke,
      icon: Ban,
      slot: "menu",
      danger: true,
      disabledReason: ctx.blocked ?? (ctx.usedBy.length ? m.devices.revokeBlockedByProfiles(ctx.usedBy) : null),
    },
  ];
}

// ---------------------------------------------------------------------------------------------------------------
// The Provider egress: the one fix its state calls for (slot `footer`, at most one: the strip's primary button), and the
// other controls (slot `header`). A rebootstrap the egress is not eligible for is not an action: the strip says
// 「不能重新直連」 and why.

export type EgressActionId =
  | "check"
  | "choose"
  | "open_bootstrap"
  | "end_bootstrap"
  | "rebootstrap"
  | "cancel_rebootstrap"
  | "enable"
  | "open_instance"
  | "import";

export interface EgressActionContext {
  /** There is a connection to choose as the egress. */
  hasInstances: boolean;
  blocked: string | null;
}

/** A rebootstrap can be cancelled while it runs: its grant is open, or its new connection waits to become the egress. */
export function rebootstrapCancellable(s: Pick<ProviderEgressStatus, "bootstrap">): boolean {
  return (
    s.bootstrap?.kind === "rebootstrap" &&
    (s.bootstrap.stage === "grant_active" || s.bootstrap.stage === "instance_requested")
  );
}

export function egressActions(s: ProviderEgressStatus, ctx: EgressActionContext): ActionSpec<EgressActionId>[] {
  const out: ActionSpec<EgressActionId>[] = [];
  const blocked = ctx.blocked;
  const noInstance = egressText.actions.noConnection;
  const choose = (primary: boolean): ActionSpec<EgressActionId> => ({
    id: "choose",
    label: egressText.actions.choose,
    icon: Route,
    slot: primary ? "footer" : "header",
    disabledReason: blocked ?? (ctx.hasInstances ? null : noInstance),
  });
  const openInstance: ActionSpec<EgressActionId> = {
    id: "open_instance",
    label: egressText.actions.openInstance,
    icon: ArrowUpRight,
    slot: "header",
    disabledReason: null,
  };
  const rebootstrap = rebootstrapOpen(s);
  switch (s.phase) {
    case "unconfigured":
      if (ctx.hasInstances) out.push(choose(true));
      if (!s.bootstrap_consumed)
        out.push({
          id: "open_bootstrap",
          label: m.add.allowDirect,
          icon: Globe,
          slot: ctx.hasInstances ? "header" : "footer",
          disabledReason: blocked,
          pendingLabel: egressText.actions.opening,
        });
      else if (!ctx.hasInstances)
        out.push({
          id: "import",
          label: egressText.actions.importProfile,
          icon: FilePlus2,
          slot: "footer",
          disabledReason: null,
        });
      if (!ctx.hasInstances) out.push(choose(false));
      break;
    case "bootstrap_direct":
      out.push(
        rebootstrap
          ? {
              id: "cancel_rebootstrap",
              label: egressText.actions.cancelRebootstrap,
              icon: X,
              slot: "header",
              danger: true,
              disabledReason: blocked,
              pendingLabel: egressText.actions.cancelling,
            }
          : {
              id: "end_bootstrap",
              label: egressText.actions.endDirect,
              icon: Unplug,
              slot: "header",
              disabledReason: blocked,
              pendingLabel: egressText.actions.ending,
            },
      );
      break;
    case "recovery_required":
      if (s.recovery?.rebootstrap_eligible)
        out.push({
          id: "rebootstrap",
          label: egressText.actions.rebootstrap,
          icon: Globe,
          slot: "header",
          disabledReason: blocked,
        });
      if (s.selected_instance_id) out.push(openInstance);
      break;
    case "blocked":
      if (s.selected_instance_id) out.push(openInstance);
      break;
    case "disabled":
      out.push({
        id: "enable",
        label: egressText.actions.enable,
        icon: Power,
        slot: "footer",
        disabledReason: blocked,
        pendingLabel: ui.common.enabling,
      });
      break;
    case "starting_instance":
    case "switching":
    case "vpn_ready":
      break;
  }
  // A rebootstrap can be cancelled in any phase while it runs (its new connection waiting to become the egress, or the
  // selected egress back meanwhile).
  if (rebootstrapCancellable(s) && !out.some((a) => a.id === "cancel_rebootstrap"))
    out.push({
      id: "cancel_rebootstrap",
      label: egressText.actions.cancelRebootstrap,
      icon: X,
      slot: "header",
      danger: true,
      disabledReason: blocked,
      pendingLabel: egressText.actions.cancelling,
    });
  const canCheck = s.phase === "vpn_ready" || s.phase === "bootstrap_direct";
  out.push({
    id: "check",
    label: egressText.actions.check,
    icon: Radar,
    slot: "header",
    disabledReason: blocked ?? (canCheck ? null : egressText.actions.checkUnavailable),
    pendingLabel: ui.common.checking,
  });
  if (s.phase !== "unconfigured") out.push(choose(false));
  return out;
}
