// The actions of a managed App — one model for its list row and its inspector
// (docs/frontend-design.md §8.1). `appActions` says which actions exist in the App's present state, their one name and
// icon, where they show and why one cannot run now: header = the lifecycle control its state calls for (停止／啟動,
// also the row's quick action) and 編輯; footer = 檢查並核准執行檔 (the inspector's evidence check: the file on disk
// against the approved one); menu = 重新啟動, 新增轉發 | 刪除. `sendAppAction` is the one way an intent is sent:
// idempotent per App (an identical intent whose outcome is unknown keeps its key, one on its way is not sent twice),
// shown on every view of the App while on its way (useAppSending).
import { FileCheck2, Pencil, Play, Plus, RotateCw, Square, Trash2 } from "lucide-react";
import { apiMutate } from "@/api/client";
import { patchAppStatus } from "@/api/events";
import { keys } from "@/api/queries";
import type { AppAction, AppActionResult, AppStatus, AppView, Capability, InstanceView } from "@/api/types";
import { queryClient } from "@/api/query-client";
import type { ActionSpec } from "@/components/ui/action-model";
import { m as ui } from "@/components/ui/messages";
import { reportFailure, toast } from "@/components/ui/toast";
import { providerGuide } from "@/features/forwards/model";
import { createFlights } from "@/lib/flights";
import { intentKey } from "@/lib/intent";
import { m } from "./messages";
import { approvalProblem, hasRun, ISOLATION, modeAvailability, shortDigest } from "./model";

export const VERB: Record<AppAction, string> = {
  start: ui.common.start,
  stop: ui.common.stop,
  restart: ui.common.restart,
  approve: m.actions.approveVerb,
};

export type AppActionId = "start" | "stop" | "edit" | "approve" | "restart" | "add_forward" | "delete";

/** The intents sent in place (the others open a dialog on the App's page). */
const SENDS: Partial<Record<AppActionId, AppAction>> = { start: "start", stop: "stop", restart: "restart" };

export function appSendsOf(id: AppActionId): AppAction | null {
  return SENDS[id] ?? null;
}

export interface AppActionContext {
  /** Why nothing can be sent now (the controller or the manager is unreachable), or null. */
  blocked: string | null;
  /** The App's intent on its way, if any (one intent at a time). */
  sending?: AppAction | null;
  /** The host's capabilities (whether it runs the App's isolation); undefined while they load. */
  caps: Capability[] | undefined;
  /** The App's connection, when known: whether forwards can reach it. */
  owner?: InstanceView | undefined;
  /** Names of the forwards that deliver to the App (it cannot be deleted while they do). */
  forwards?: readonly string[];
}

/** Why the App cannot be deleted while forwards deliver to it (the server refuses it too), or null. */
function forwardsInTheWay(names: readonly string[] | undefined): string | null {
  if (!names?.length) return null;
  return m.actions.forwardsInTheWay(names.slice(0, 3), names.length);
}

/** Why the App cannot start on this host now (its isolation, its executable), or null. */
function startProblem(v: AppView, caps: Capability[] | undefined): string | null {
  const mode = modeAvailability(v.spec.isolation, caps);
  if (!mode.available) return caps ? m.mode.unavailable(ISOLATION[v.spec.isolation].title, mode.reason) : mode.reason;
  return approvalProblem(v);
}

/**
 * Every action the App offers now. Header: 停止 while a tree is (or may still be) in place — also while the status is
 * unknown, since stopping is safe and idempotent — else 啟動; then 編輯. Footer: 檢查並核准執行檔. Menu: the rest,
 * destructive last. Nothing is hidden for being unavailable: it carries the reason instead.
 */
export function appActions(v: AppView, ctx: AppActionContext): ActionSpec<AppActionId>[] {
  const s = v.status;
  const waiting = ctx.sending ? m.actions.waitingFor(VERB[ctx.sending]) : null;
  // One intent at a time: the others wait for the one on its way (which shows its spinner instead of a reason).
  const lock = (action: AppAction): string | null =>
    ctx.blocked ?? (ctx.sending && ctx.sending !== action ? waiting : null);
  const out: ActionSpec<AppActionId>[] = [];
  if (hasRun(v) || !s)
    out.push({
      id: "stop",
      label: ui.common.stop,
      icon: Square,
      slot: "header",
      quick: true,
      disabledReason: lock("stop"),
      pendingLabel: ui.common.stopping,
    });
  else
    out.push({
      id: "start",
      label: ui.common.start,
      icon: Play,
      slot: "header",
      quick: true,
      disabledReason: lock("start") ?? startProblem(v, ctx.caps),
      pendingLabel: ui.common.starting,
    });
  out.push({ id: "edit", label: ui.common.edit, icon: Pencil, slot: "header", disabledReason: null });
  out.push({
    id: "approve",
    label: m.actions.approve,
    icon: FileCheck2,
    slot: "footer",
    disabledReason: lock("approve"),
    pendingLabel: m.actions.approving,
  });
  out.push({
    id: "restart",
    label: ui.common.restart,
    icon: RotateCw,
    slot: "menu",
    disabledReason: lock("restart") ?? (s?.state === "running" ? null : m.actions.restartNeedsRunning),
    pendingLabel: ui.common.restarting,
  });
  out.push({
    id: "add_forward",
    label: m.actions.addForward,
    icon: Plus,
    slot: "menu",
    disabledReason: providerGuide(ctx.owner).unsupported,
  });
  out.push({
    id: "delete",
    label: ui.common.delete,
    icon: Trash2,
    slot: "menu",
    danger: true,
    disabledReason: !s
      ? m.actions.deleteUnknown
      : hasRun(v)
        ? m.actions.deleteRunning
        : (forwardsInTheWay(ctx.forwards) ?? waiting),
  });
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// Sending: one intent per App at a time, shared by every place that offers it.

const flights = createFlights<AppAction>();

/** The intent of App `id` on its way, if any (re-renders when it settles). */
export function useAppSending(id: string): AppAction | null {
  return flights.useSending(id);
}

/** Only an observed outcome is reported as done; otherwise the status shows the truth later. */
function announce(action: AppAction, name: string, s: AppStatus | null, sha256?: string) {
  const running = s?.state === "running";
  const detail =
    running && s.pid ? `PID ${s.pid}${s.isolation ? ` · ${ISOLATION[s.isolation].short}` : ""}` : undefined;
  switch (action) {
    case "start":
      if (running) toast.success(m.actions.done.started(name), detail);
      else toast.info(m.actions.done.startSent(name), m.actions.done.updatesWhenConfirmed);
      break;
    case "restart":
      if (running) toast.success(m.actions.done.restarted(name), detail);
      else toast.info(m.actions.done.restartSent(name), m.actions.done.updatesWhenConfirmed);
      break;
    case "stop":
      if (s?.state === "stopped") toast.success(m.actions.done.stopped(name), m.actions.done.treeExited);
      else toast.info(m.actions.done.stopSent(name), m.actions.done.stopUnconfirmed);
      break;
    case "approve":
      toast.success(m.actions.done.approved(name), sha256 ? `SHA-256 ${shortDigest(sha256)}` : undefined);
      break;
  }
}

/**
 * Sends one intent for App `v` and reports the outcome; `onDone` runs once it was accepted (a dialog closes). The
 * idempotency key belongs to the App and the body (scope `app.action:<id>`).
 */
export function sendAppAction(
  v: AppView,
  action: AppAction,
  opts: { sha256?: string; onDone?: () => void } = {},
): Promise<void> {
  return flights.fly(v.spec.id, action, async () => {
    const intent = intentKey(`app.action:${v.spec.id}`, { id: v.spec.id, action, sha256: opts.sha256 });
    try {
      const r = await apiMutate<AppActionResult>(
        "POST",
        `/v1/apps/${v.spec.id}/actions`,
        { action, ...(opts.sha256 ? { sha256: opts.sha256 } : {}) },
        { idempotencyKey: intent.key },
      );
      intent.settle();
      if (r.data.status) patchAppStatus(queryClient, r.data.status);
      opts.onDone?.();
      announce(action, v.spec.name, r.data.status, opts.sha256);
    } catch (e) {
      intent.settle(e);
      reportFailure(m.actions.intent[action](v.spec.name), e);
    } finally {
      // An approval changes the spec; any action changes the tree and the log.
      void queryClient.invalidateQueries({ queryKey: action === "approve" ? keys.apps : keys.appProcesses(v.spec.id) });
    }
  });
}

/**
 * Apps being deleted from this page: once one leaves the list, its inspector place shows 「選擇一個 App」, not 「找不到這個
 * App」, in the moment before the selection leaves the URL. Marked when the deletion is sent (the list drops the App as
 * soon as the server confirms), unmarked if it fails.
 */
const deletedHere = new Set<string>();

export function markDeleting(id: string, deleting: boolean): void {
  if (deleting) deletedHere.add(id);
  else deletedHere.delete(id);
}

export function wasDeletedHere(id: string): boolean {
  return deletedHere.has(id);
}

/** The list's batch action: restart these running Apps, each as its own intent (the same one as its 重新啟動). */
export async function restartApps(targets: readonly AppView[]): Promise<void> {
  if (!targets.length) {
    toast.info(m.actions.done.nothingToRestart, m.actions.done.nothingToRestartDetail);
    return;
  }
  await Promise.all(targets.map((v) => sendAppAction(v, "restart")));
}
