// The actions of a WireGuard profile — one model for its list row and its inspector
// (docs/frontend-design.md §8.1). Header: 編輯 and 更換入口／出口 (the frequent ones); footer: 建立連線 (the view's primary
// task: use the profile; also the row's quick action) and 檢查設定 (the inspector's own check, its answer shown there);
// menu: 刪除. An action that cannot run says why instead of disappearing.
import { ArrowLeftRight, ClipboardCheck, Pencil, Plus, Trash2 } from "lucide-react";
import type { RuntimeProfile } from "@/api/types";
import type { ActionSpec } from "@/components/ui/action-model";
import { m as ui } from "@/components/ui/messages";
import { m } from "./messages";
import { canChangeServer } from "./model";

export type ProfileActionId = "edit" | "change_server" | "create_instance" | "check" | "delete";

/** The actions that open a dialog on the profiles page (a row, the inspector and `?do=` open the same one). */
export const PROFILE_DIALOGS: ReadonlySet<ProfileActionId> = new Set<ProfileActionId>([
  "edit",
  "change_server",
  "delete",
]);

export interface ProfileActionContext {
  /** The connections that use the profile (a profile in use cannot be deleted). */
  users: number;
  /** Why nothing can be changed now (the controller or the manager is unreachable), or null. */
  blocked: string | null;
}

export function profileActions(p: RuntimeProfile, ctx: ProfileActionContext): ActionSpec<ProfileActionId>[] {
  return [
    { id: "edit", label: ui.common.edit, icon: Pencil, slot: "header", disabledReason: null },
    {
      id: "change_server",
      label: m.actions.changeServer,
      icon: ArrowLeftRight,
      slot: "header",
      disabledReason: canChangeServer(p) ? null : m.actions.cannotChangeServer,
    },
    {
      id: "create_instance",
      label: m.actions.createInstance,
      icon: Plus,
      slot: "footer",
      quick: true,
      disabledReason: null,
    },
    {
      id: "check",
      label: m.actions.check,
      icon: ClipboardCheck,
      slot: "footer",
      disabledReason: null,
      pendingLabel: ui.common.checking,
    },
    {
      id: "delete",
      label: ui.common.delete,
      icon: Trash2,
      slot: "menu",
      danger: true,
      disabledReason: ctx.blocked ?? (ctx.users ? m.actions.inUse(ctx.users) : null),
    },
  ];
}

/** Where 建立連線 goes: the new-connection dialog of the connections page, this profile chosen. */
export function createInstancePath(p: Pick<RuntimeProfile, "id">): string {
  return `/instances?new=1&profile=${encodeURIComponent(p.id)}`;
}
