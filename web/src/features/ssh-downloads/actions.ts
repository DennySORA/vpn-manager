// The actions of an SSH download job — one model for its list row and its inspector
// (docs/frontend-design.md §8.1). Header = the lifecycle control its state calls for (暫停／繼續／重試, also the row's
// quick action) and 編輯; footer = 立即掃描 (the view's primary task: look for new files now); menu = 信任新的主機金鑰…,
// 前往代理埠 | 清除傳輸紀錄…, 清除日誌…, 刪除. `sendJobAction` is the one way an intent is sent: idempotent per job,
// shown on every view of the job while on its way.
import { Eraser, EthernetPort, FolderSearch, KeyRound, Pause, Pencil, Play, RotateCw, Trash2 } from "lucide-react";
import { apiMutate } from "@/api/client";
import type { SshDownloadAction } from "@/api/generated/SshDownloadAction";
import type { SshDownloadActionResult } from "@/api/generated/SshDownloadActionResult";
import type { SshDownloadCleared } from "@/api/generated/SshDownloadCleared";
import type { SshDownloadView } from "@/api/generated/SshDownloadView";
import { patchSshDownloadStatus, sshDownloadKeys } from "@/api/ssh-downloads";
import { queryClient } from "@/api/query-client";
import type { ActionSpec } from "@/components/ui/action-model";
import { m as ui } from "@/components/ui/messages";
import { reportFailure, toast } from "@/components/ui/toast";
import { createFlights } from "@/lib/flights";
import { intentKey } from "@/lib/intent";
import { m } from "./messages";

export type JobActionId =
  | "pause"
  | "resume"
  | "retry"
  | "edit"
  | "scan"
  | "trust_host_key"
  | "open_gateway"
  | "clear_history"
  | "clear_log"
  | "delete";

/** What a job's log or history clear deletes: `log` lines, or finished `transfers` (the API's path). */
export type ClearWhat = "log" | "transfers";

type Sends = SshDownloadAction | "delete" | "clear_log" | "clear_history";

export const VERB: Record<Sends, string> = {
  pause: m.verb.pause,
  resume: m.verb.resume,
  scan: m.verb.scan,
  trust_host_key: m.verb.trust_host_key,
  clear_log: m.verb.clear_log,
  clear_history: m.verb.clear_history,
  delete: ui.common.delete,
};

/** The intents sent in place (the others open a dialog on the job's page). */
const SENDS: Partial<Record<JobActionId, SshDownloadAction>> = {
  pause: "pause",
  resume: "resume",
  retry: "resume",
  scan: "scan",
};

export function jobSendsOf(id: JobActionId): SshDownloadAction | null {
  return SENDS[id] ?? null;
}

export interface JobActionContext {
  /** Why nothing can be sent now (the controller or the manager is unreachable), or null. */
  blocked: string | null;
  /** The job's intent on its way, if any (one at a time). */
  sending?: Sends | null;
  /** Whether the job's Gateway is known (else 前往代理埠 says why not). */
  gatewayKnown: boolean;
}

/**
 * Every action the job offers now. Header: 重試 when it stopped for the user, 繼續 when paused, else 暫停 (also while
 * the status is unknown: pausing is safe); then 編輯. Footer: 立即掃描. Menu: the rest, destructive last. Nothing is
 * hidden for being unavailable: it carries the reason instead.
 */
export function jobActions(v: SshDownloadView, ctx: JobActionContext): ActionSpec<JobActionId>[] {
  const s = v.status;
  const waiting = ctx.sending ? m.action.sending(VERB[ctx.sending]) : null;
  const lock = (what: Sends): string | null => ctx.blocked ?? (ctx.sending && ctx.sending !== what ? waiting : null);
  const out: ActionSpec<JobActionId>[] = [];
  if (s?.state === "error")
    out.push({
      id: "retry",
      label: m.action.retry,
      icon: RotateCw,
      slot: "header",
      quick: true,
      disabledReason: lock("resume"),
      pendingLabel: m.action.retrying,
    });
  else if (s?.state === "paused")
    out.push({
      id: "resume",
      label: m.action.resume,
      icon: Play,
      slot: "header",
      quick: true,
      disabledReason: lock("resume"),
      pendingLabel: m.action.resuming,
    });
  else
    out.push({
      id: "pause",
      label: m.action.pause,
      icon: Pause,
      slot: "header",
      quick: true,
      disabledReason: lock("pause"),
      pendingLabel: m.action.pausing,
    });
  out.push({ id: "edit", label: ui.common.edit, icon: Pencil, slot: "header", disabledReason: null });
  const scanBlocked =
    s?.state === "paused" ? m.action.paused : s?.state === "error" ? m.action.stopped : !s ? m.action.unknown : null;
  out.push({
    id: "scan",
    label: m.action.scan,
    icon: FolderSearch,
    slot: "footer",
    disabledReason: lock("scan") ?? scanBlocked,
    pendingLabel: m.state.scanning,
  });
  out.push({
    id: "trust_host_key",
    label: m.action.trust,
    icon: KeyRound,
    slot: "menu",
    disabledReason: s?.offered_host_key ? lock("trust_host_key") : m.action.noOfferedKey,
  });
  out.push({
    id: "open_gateway",
    label: m.action.openGateway,
    icon: EthernetPort,
    slot: "menu",
    disabledReason: ctx.gatewayKnown ? null : m.action.gatewayMissing,
  });
  out.push({
    id: "clear_history",
    label: m.action.clearHistory,
    icon: Eraser,
    slot: "menu",
    danger: true,
    disabledReason: lock("clear_history"),
    pendingLabel: m.action.clearing,
  });
  out.push({
    id: "clear_log",
    label: m.action.clearLog,
    icon: Eraser,
    slot: "menu",
    danger: true,
    disabledReason: lock("clear_log"),
    pendingLabel: m.action.clearing,
  });
  out.push({
    id: "delete",
    label: ui.common.delete,
    icon: Trash2,
    slot: "menu",
    danger: true,
    disabledReason: lock("delete"),
  });
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// Sending: one intent per job at a time, shared by every place that offers it.

const flights = createFlights<Sends>(() => {
  void queryClient.invalidateQueries({ queryKey: sshDownloadKeys.all });
});

export const useJobSending = (id: string) => flights.useSending(id);

function announce(action: SshDownloadAction, name: string, r: SshDownloadActionResult) {
  const s = r.status;
  switch (action) {
    case "pause":
      toast.success(m.sent.paused(name), s?.unfinished ? m.sent.pausedUnfinished(s.unfinished) : undefined);
      break;
    case "resume":
      toast.success(m.sent.resumed(name), m.sent.vpnOnly);
      break;
    case "scan":
      toast.info(m.sent.scanning(name), m.sent.scanningDetail);
      break;
    case "trust_host_key":
      toast.success(m.sent.trusted(name), s?.host_key?.fingerprint);
      break;
  }
}

/** Sends one intent for job `v`; `onDone` runs once it was accepted (a dialog closes). */
export function sendJobAction(
  v: SshDownloadView,
  action: SshDownloadAction,
  opts: { fingerprint?: string; onDone?: () => void } = {},
): Promise<void> {
  return flights.fly(v.job.id, action, async () => {
    const body = { action, fingerprint: opts.fingerprint ?? null };
    const intent = intentKey(`ssh_download.action:${v.job.id}`, body);
    try {
      const r = await apiMutate<SshDownloadActionResult>("POST", `/v1/ssh-downloads/${v.job.id}/actions`, body, {
        idempotencyKey: intent.key,
      });
      intent.settle();
      if (r.data.status) patchSshDownloadStatus(queryClient, r.data.status);
      opts.onDone?.();
      announce(action, v.job.name, r.data);
    } catch (e) {
      intent.settle(e);
      reportFailure(m.intent[action](v.job.name), e);
    }
  });
}

/**
 * Deletes job `v`'s log lines or finished records for good (unfinished ones stay: their files resume; no file is
 * touched); `onDone` runs once it was done (a dialog closes).
 */
export function sendClear(v: SshDownloadView, what: ClearWhat, onDone: () => void): Promise<void> {
  const sends = what === "log" ? "clear_log" : "clear_history";
  return flights.fly(v.job.id, sends, async () => {
    const intent = intentKey(`ssh_download.clear_${what}:${v.job.id}`, {});
    try {
      const r = await apiMutate<SshDownloadCleared>("DELETE", `/v1/ssh-downloads/${v.job.id}/${what}`, undefined, {
        idempotencyKey: intent.key,
      });
      intent.settle();
      const n = r.data.removed;
      void queryClient.invalidateQueries({ queryKey: sshDownloadKeys.log(v.job.id) });
      void queryClient.invalidateQueries({ queryKey: sshDownloadKeys.transfers(v.job.id, "history") });
      toast.success(
        what === "log" ? m.sent.logCleared(v.job.name, n) : m.sent.historyCleared(v.job.name, n),
        what === "log" ? undefined : m.sent.keepsUnfinished,
      );
      onDone();
    } catch (e) {
      intent.settle(e);
      reportFailure(m.intent[sends](v.job.name), e);
    }
  });
}

/** Deletes the job (its records and log go with it; remote files in the working folder stay). */
export function sendDelete(v: SshDownloadView, onDone: () => void): Promise<void> {
  return flights.fly(v.job.id, "delete", async () => {
    const intent = intentKey(`ssh_download.delete:${v.job.id}`, { rev: v.job.revision });
    try {
      await apiMutate<undefined>("DELETE", `/v1/ssh-downloads/${v.job.id}`, undefined, {
        idempotencyKey: intent.key,
        ifMatch: v.job.revision,
      });
      intent.settle();
      queryClient.setQueryData<SshDownloadView[]>(sshDownloadKeys.all, (all) =>
        all?.filter((x) => x.job.id !== v.job.id),
      );
      toast.success(m.sent.deleted(v.job.name));
      onDone();
    } catch (e) {
      intent.settle(e);
      reportFailure(m.intent.delete(v.job.name), e);
    }
  });
}
