// The actions of a connection (Instance) — one model for its list row and its inspector
// (docs/frontend-design.md §8.1). `instanceActions` says which actions exist in the connection's present state, their
// one name and icon, where they show and why one cannot run now. `sendLifecycle` / `sendEmergencyStop` are the one way
// each intent is sent: idempotent per connection (an identical intent whose outcome is unknown keeps its key, one already
// on its way is not sent twice), with the same feedback wherever it was chosen. While an intent is on its way, every
// view of that connection shows it (useSending).
import { LockOpen, OctagonX, Pencil, Play, Plus, Radar, RotateCw, Square, Trash2 } from "lucide-react";
import { apiMutate } from "@/api/client";
import { keys } from "@/api/queries";
import type { Accepted, InstanceView, LifecycleAction } from "@/api/types";
import { queryClient } from "@/api/query-client";
import type { ActionSpec } from "@/components/ui/action-model";
import { m as ui } from "@/components/ui/messages";
import { reportFailure, toast } from "@/components/ui/toast";
import { createFlights } from "@/lib/flights";
import { intentKey } from "@/lib/intent";
import { m } from "./messages";
import { isRunning, recoveryWayOut, restartTargets, type SharedConfig, usesConfig } from "./model";

export const VERB: Record<LifecycleAction, string> = {
  start: ui.common.start,
  stop: ui.common.stop,
  restart: ui.common.restart,
  clear_emergency: m.action.clearEmergency,
};

export type InstanceActionId =
  | "start"
  | "stop"
  | "clear_emergency"
  | "confirm_stop"
  | "keep_emergency"
  | "edit"
  | "check_exit"
  | "restart"
  | "add_gateway"
  | "emergency_stop"
  | "delete";

/** What the lifecycle and emergency actions send. */
const SENDS: Partial<Record<InstanceActionId, LifecycleAction | "emergency_stop">> = {
  start: "start",
  stop: "stop",
  restart: "restart",
  clear_emergency: "clear_emergency",
  confirm_stop: "stop",
  keep_emergency: "emergency_stop",
};

export function sendsOf(id: InstanceActionId): LifecycleAction | "emergency_stop" | null {
  return SENDS[id] ?? null;
}

export interface InstanceActionContext {
  /** Why nothing can be sent now (the controller or the manager is unreachable), or null. */
  blocked: string | null;
  /** The intent of this connection on its way, if any (one lifecycle intent at a time). */
  sending?: LifecycleAction | "emergency_stop" | null;
}

const SENDING_WORD: Record<LifecycleAction | "emergency_stop", string> = {
  ...VERB,
  emergency_stop: m.action.emergencyStop,
};

/**
 * Every action the connection offers now. Header: the lifecycle control its state calls for (the two choices of a
 * connection that waits for a decision) and 編輯; footer: 檢查出口 IP; menu: the rest, destructive last. Nothing is
 * hidden for being unavailable: it carries the reason instead.
 */
export function instanceActions(v: InstanceView, ctx: InstanceActionContext): ActionSpec<InstanceActionId>[] {
  const s = v.status;
  const running = isRunning(v);
  const latched = s?.intent.emergency_latched ?? false;
  const wayOut = recoveryWayOut(v);
  // One lifecycle intent at a time: the others wait for it (the one on its way shows a spinner instead).
  const lock = (id: InstanceActionId): string | null => {
    if (ctx.blocked) return ctx.blocked;
    const sends = SENDS[id];
    return ctx.sending && sends !== ctx.sending ? m.reason.sending(SENDING_WORD[ctx.sending]) : null;
  };
  const start: ActionSpec<InstanceActionId> = {
    id: "start",
    label: ui.common.start,
    icon: Play,
    slot: "header",
    disabledReason: lock("start"),
    pendingLabel: ui.common.starting,
  };
  const clear: ActionSpec<InstanceActionId> = {
    id: "clear_emergency",
    label: m.action.clearEmergency,
    icon: LockOpen,
    slot: "header",
    disabledReason: lock("clear_emergency"),
    pendingLabel: m.action.clearing,
  };
  const out: ActionSpec<InstanceActionId>[] = [];
  if (wayOut) {
    // Held closed until the user decides: run it again, or keep it closed. Either one is written to disk.
    out.push(wayOut.resume === "start" ? start : clear);
    out.push(
      wayOut.keep === "stop"
        ? {
            id: "confirm_stop",
            label: m.action.confirmStop,
            icon: Square,
            slot: "header",
            disabledReason: lock("confirm_stop"),
            pendingLabel: ui.common.stopping,
          }
        : {
            id: "keep_emergency",
            label: m.action.keepEmergency,
            icon: OctagonX,
            slot: "header",
            danger: true,
            disabledReason: lock("keep_emergency"),
            pendingLabel: m.action.emergencyStopping,
          },
    );
  } else if (latched) {
    out.push({ ...clear, quick: true });
  } else if (running || !s) {
    // While the status is unknown, stopping is still offered: it is safe and idempotent.
    out.push({
      id: "stop",
      label: ui.common.stop,
      icon: Square,
      slot: "header",
      quick: true,
      disabledReason: lock("stop"),
      pendingLabel: ui.common.stopping,
    });
  } else {
    out.push({ ...start, quick: true });
  }
  out.push({ id: "edit", label: ui.common.edit, icon: Pencil, slot: "header", disabledReason: null });
  out.push({
    id: "check_exit",
    label: m.action.checkExit,
    icon: Radar,
    slot: "footer",
    disabledReason: ctx.blocked ?? (s?.phase === "ready" ? null : m.reason.checkNeedsReady),
    pendingLabel: ui.common.checking,
  });
  out.push({
    id: "restart",
    label: ui.common.restart,
    icon: RotateCw,
    slot: "menu",
    disabledReason:
      lock("restart") ?? (latched ? m.reason.restartLatched : running ? null : m.reason.restartNotRunning),
    pendingLabel: ui.common.restarting,
  });
  out.push({ id: "add_gateway", label: m.action.addGateway, icon: Plus, slot: "menu", disabledReason: null });
  out.push({
    id: "emergency_stop",
    label: m.action.emergencyStop,
    icon: OctagonX,
    slot: "menu",
    danger: true,
    // An emergency stop that is not on disk can be confirmed by stopping again.
    disabledReason: ctx.blocked ?? (latched && !wayOut ? m.reason.alreadyLatched : null),
    pendingLabel: m.action.emergencyStopping,
  });
  out.push({
    id: "delete",
    label: ui.common.delete,
    icon: Trash2,
    slot: "menu",
    danger: true,
    disabledReason: !s ? m.reason.deleteUnknown : running ? m.reason.deleteRunning : null,
  });
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// Sending: one intent per connection at a time, shared by every place that offers it.

const flights = createFlights<LifecycleAction | "emergency_stop">(
  () => void queryClient.invalidateQueries({ queryKey: keys.instances }),
);
const fly: typeof flights.fly = (id, what, send) => flights.fly(id, what, send);

/** The intent of connection `id` on its way, if any (re-renders when it settles). */
export const useSending = (id: string) => flights.useSending(id);

function announce(action: LifecycleAction, name: string, a: Accepted) {
  switch (action) {
    case "start":
      toast.success(m.sent.start(name), m.sent.startDetail);
      break;
    case "restart":
      toast.success(m.sent.restart(name), m.sent.restartDetail);
      break;
    case "stop":
      // Only a confirmed seal is reported as closed; otherwise the status shows the truth.
      if (a.sealed !== true) toast.info(m.sent.stop(name), m.sent.stopDetail);
      else if (a.durable === false) toast.info(m.sent.stopped(name), m.sent.stoppedNotDurable);
      else toast.success(m.sent.stopped(name), m.sent.stoppedDetail);
      break;
    case "clear_emergency":
      toast.success(m.sent.emergencyCleared(name), m.sent.emergencyClearedDetail);
      break;
  }
}

/**
 * Sends one lifecycle intent for `v` and reports the outcome. The idempotency key belongs to the connection and the
 * body (scope `instance.lifecycle:<id>`), the same scope a notification's restart offer uses.
 */
export function sendLifecycle(v: InstanceView, action: LifecycleAction): Promise<void> {
  return fly(v.spec.id, action, async () => {
    const body = { id: v.spec.id, action };
    const intent = intentKey(`instance.lifecycle:${v.spec.id}`, body);
    try {
      const r = await apiMutate<Accepted>(
        "POST",
        `/v1/instances/${v.spec.id}/actions`,
        { action },
        { idempotencyKey: intent.key },
      );
      intent.settle();
      announce(action, v.spec.name, r.data);
    } catch (e) {
      intent.settle(e);
      reportFailure(m.intent[action](v.spec.name), e);
    }
  });
}

/** Emergency stop: every connection through it is refused at once; `onDone` runs once it was accepted. */
export function sendEmergencyStop(v: InstanceView, onDone?: () => void): Promise<void> {
  return fly(v.spec.id, "emergency_stop", async () => {
    const body = { id: v.spec.id, emergency: true };
    const intent = intentKey(`instance.lifecycle:${v.spec.id}`, body);
    const name = v.spec.name;
    try {
      const r = await apiMutate<Accepted>(
        "POST",
        `/v1/instances/${v.spec.id}/emergency-stop`,
        {},
        { idempotencyKey: intent.key },
      );
      intent.settle();
      onDone?.();
      if (r.data.sealed !== true) toast.info(m.sent.emergency(name), m.sent.emergencyDetail);
      else if (r.data.durable === false) toast.info(m.sent.emergencyStopped(name), m.sent.emergencyNotDurable);
      else toast.success(m.sent.emergencyStopped(name), m.sent.emergencyStoppedDetail);
    } catch (e) {
      intent.settle(e);
      reportFailure(m.intent.emergency_stop(name), e);
    }
  });
}

/** Restart these connections, each as its own intent (the same one as its 重新啟動 action). */
async function restartConnections(targets: InstanceView[]) {
  if (!targets.length) {
    toast.info(m.sent.nothingToRestart, m.sent.nothingToRestartDetail);
    return;
  }
  const sent = await Promise.all(
    targets.map(async (v) => {
      const body = { id: v.spec.id, action: "restart" as const };
      const intent = intentKey(`instance.lifecycle:${v.spec.id}`, body);
      try {
        await apiMutate<Accepted>(
          "POST",
          `/v1/instances/${v.spec.id}/actions`,
          { action: "restart" },
          { idempotencyKey: intent.key },
        );
        intent.settle();
        return true;
      } catch (e) {
        intent.settle(e);
        reportFailure(m.intent.restart(v.spec.name), e);
        return false;
      }
    }),
  );
  void queryClient.invalidateQueries({ queryKey: keys.instances });
  const ok = targets.filter((_, i) => sent[i]);
  if (ok.length)
    toast.success(
      ok.length === 1 ? m.sent.restart(ok[0]?.spec.name ?? "") : m.sent.restartMany(ok.length),
      m.sent.restartDetail,
    );
}

/** The list's batch action: restart the running connections whose saved configuration waits for a restart. */
export function restartPending(targets: InstanceView[]): Promise<void> {
  return restartConnections(targets);
}

const cachedViews = () => queryClient.getQueryData<InstanceView[]>(keys.instances) ?? [];

/**
 * Success feedback after saving a WireGuard, DNS or security profile. When running connections
 * still use the previous version, it offers to restart exactly those: a deliberate click, since a
 * restart interrupts their live sessions. Who to restart is decided again when clicked.
 */
export function announceSaved(o: {
  title: string;
  kind: SharedConfig;
  id: string;
  revision: number;
  workerChanged: boolean;
}) {
  const views = cachedViews();
  if (!o.workerChanged || !views.some((v) => usesConfig(v, o.kind, o.id))) {
    toast.success(o.title);
    return;
  }
  const n = restartTargets(views, o.kind, o.id, o.revision).length;
  if (!n) {
    toast.success(o.title, m.saved.appliesOnNextStart);
    return;
  }
  toast.success(o.title, m.saved.restartNeeded(n), {
    label: m.saved.restartOffer(n),
    pendingLabel: ui.common.restarting,
    run: () => restartConnections(restartTargets(cachedViews(), o.kind, o.id, o.revision)),
  });
}
