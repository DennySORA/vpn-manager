// The action model of an object (docs/frontend-design.md §8 and §8.1): every action an object offers — its one name
// and icon, where it shows, whether it is destructive, and why it cannot run now. Each entity builds one list of these
// (features/<entity>/actions.ts); its list row and its inspector both render that same list, so a
// name, an icon or a disabled reason can never differ between them. Pure data and helpers; the buttons and the menu
// that render it are in entity-actions.tsx.
import type { LucideIcon } from "lucide-react";
import { m } from "./messages";

/**
 * Where an action shows in the object's inspector:
 * - `header`: the frequent ones (啟動／停止, 編輯) in the EntityHeader's action row;
 * - `footer`: the view's primary action in the InspectorFooter (the first footer action is the primary button);
 * - `menu`: everything else, in the one overflow menu (⋯) — the same menu the list row shows.
 */
export type ActionSlot = "header" | "footer" | "menu";

export interface ActionSpec<Id extends string = string> {
  id: Id;
  /** The action's one name: the same in buttons, menus and notifications. */
  label: string;
  icon: LucideIcon;
  slot: ActionSlot;
  /** Destructive: the danger tone, and a confirmation that states its exact scope before it acts. */
  danger?: boolean | undefined;
  /** Why it cannot run now: shown and announced, the control stays focusable. null = available. */
  disabledReason: string | null;
  /** The list row's quick action (a row shows at most one: the first one marked). */
  quick?: boolean | undefined;
  /** The word shown while it runs (e.g. "停止中"). */
  pendingLabel?: string | undefined;
}

/** An action bound to its object: whether it is in flight and what pressing it does. */
export interface EntityAction<Id extends string = string> extends ActionSpec<Id> {
  /** In flight: a spinner in place of the icon, aria-busy, repeated presses ignored. */
  pending: boolean;
  run: () => void;
}

export function headerActions<A extends ActionSpec>(actions: readonly A[]): A[] {
  return actions.filter((a) => a.slot === "header");
}

export function footerActions<A extends ActionSpec>(actions: readonly A[]): A[] {
  return actions.filter((a) => a.slot === "footer");
}

/** The overflow menu in order: the other actions first, the destructive ones last (a separator goes between). */
export function menuActions<A extends ActionSpec>(actions: readonly A[]): A[] {
  const menu = actions.filter((a) => a.slot === "menu");
  return [...menu.filter((a) => !a.danger), ...menu.filter((a) => a.danger)];
}

/** The row's one quick action, or null. */
export function quickAction<A extends ActionSpec>(actions: readonly A[]): A | null {
  return actions.find((a) => a.quick) ?? null;
}

/** Why an action cannot run now, including "it is already running" (menus show this under the item). */
export function blockedReason(
  a: Pick<EntityAction, "disabledReason" | "pending" | "pendingLabel" | "label">,
): string | null {
  if (a.pending) return a.pendingLabel === undefined ? m.action.running(a.label) : `${a.pendingLabel}…`;
  return a.disabledReason;
}
