// The actions of 系統 — one model per thing that has them (docs/frontend-design.md §8.1): the diagnostics report
// (重新診斷, 下載 JSON), the recovery inspection (重新檢查, and 清理 for every cleanable leftover at once) and each leftover
// it found (清理 just that one). Every action has one name and one icon wherever it shows; an action that cannot run
// now stays visible with its reason. Cleaning is destructive: it always goes through a confirmation that lists exactly
// the items it will touch.
import { BrushCleaning, Download, RefreshCw } from "lucide-react";
import type { DiagnosticReport, RecoveryItem, RecoveryReport } from "@/api/types";
import type { ActionSpec } from "@/components/ui/action-model";
import { m as ui } from "@/components/ui/messages";
import { m as diag } from "./diagnostics/messages";
import { m as rec } from "./recovery/messages";

export type DiagnosticsActionId = "rerun" | "download";

/** The report's actions: run it again (pending while it runs), save exactly what is shown as JSON. */
export function diagnosticsActions(report: DiagnosticReport | undefined): ActionSpec<DiagnosticsActionId>[] {
  return [
    {
      id: "rerun",
      label: diag.actions.rerun,
      icon: RefreshCw,
      slot: "header",
      disabledReason: null,
      pendingLabel: diag.actions.rerunning,
    },
    {
      id: "download",
      label: diag.actions.download,
      icon: Download,
      slot: "header",
      disabledReason: report ? null : diag.actions.notLoaded,
    },
  ];
}

export type RecoveryActionId = "recheck" | "clean_all";
export type RecoveryItemActionId = "clean";

export interface RecoveryActionContext {
  /** Why nothing can be sent now (the controller or the manager is unreachable), or null. */
  blocked: string | null;
  /** The clean on its way: the items it covers and whether it is the one for every cleanable item; null when none is. */
  cleaning: { items: ReadonlySet<string>; all: boolean } | null;
}

const WAIT = rec.actions.busy;

/** Leftovers a clean may touch: verifiably this VPN Manager's and stale. */
export function cleanableItems(r: Pick<RecoveryReport, "items"> | undefined): RecoveryItem[] {
  return r?.items.filter((i) => i.cleanable) ?? [];
}

/** Why a leftover is only reported: held by something else, or not provably ours. */
export function reportOnlyReason(item: Pick<RecoveryItem, "cleanable" | "kind">): string | null {
  if (item.cleanable) return null;
  if (item.kind === "foreign_key_lock" || item.kind === "foreign_socket") return rec.actions.foreign;
  return rec.actions.unproven;
}

/** The inspection's actions: inspect again; clean every cleanable leftover (named with how many). */
export function recoveryActions(
  r: Pick<RecoveryReport, "items"> | undefined,
  ctx: RecoveryActionContext,
): ActionSpec<RecoveryActionId>[] {
  const n = cleanableItems(r).length;
  return [
    {
      id: "recheck",
      label: rec.actions.recheck,
      icon: RefreshCw,
      slot: "header",
      disabledReason: null,
      pendingLabel: ui.common.checking,
    },
    {
      id: "clean_all",
      label: n ? rec.actions.cleanCount(n) : rec.actions.clean,
      icon: BrushCleaning,
      slot: "header",
      danger: true,
      pendingLabel: rec.actions.cleaning,
      disabledReason: ctx.cleaning
        ? ctx.cleaning.all
          ? null
          : WAIT
        : (ctx.blocked ?? (r ? (n ? null : rec.actions.nothing) : rec.actions.notChecked)),
    },
  ];
}

/** One leftover's action: 清理 it alone (the row's quick action), or why it cannot be cleaned now. */
export function recoveryItemActions(
  item: RecoveryItem,
  ctx: RecoveryActionContext,
): ActionSpec<RecoveryItemActionId>[] {
  const inFlight = ctx.cleaning?.items.has(item.id) ?? false;
  return [
    {
      id: "clean",
      label: rec.actions.clean,
      icon: BrushCleaning,
      slot: "header",
      quick: true,
      danger: true,
      pendingLabel: rec.actions.cleaning,
      disabledReason: inFlight ? null : (reportOnlyReason(item) ?? ctx.blocked ?? (ctx.cleaning ? WAIT : null)),
    },
  ];
}

/** Whether action `id` of the inspection is the one on its way (its button then shows the spinner). */
export function recoveryPending(id: RecoveryActionId, ctx: RecoveryActionContext, recheckRunning: boolean): boolean {
  return id === "recheck" ? recheckRunning : Boolean(ctx.cleaning?.all);
}
