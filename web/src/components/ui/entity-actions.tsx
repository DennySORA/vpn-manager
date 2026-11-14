// The renderers of an object's action model (action-model.ts; docs/frontend-design.md §8.1): the EntityHeader's action
// row, the InspectorFooter's buttons, the one overflow menu (⋯) and a list row's quick action. The row and the
// inspector render the same model, so the row's menu always equals the inspector's and every name, icon and disabled
// reason is the same wherever the action appears. Unavailable actions stay visible and focusable with their reason;
// an action in flight shows a spinner in place and ignores repeated presses.
import { Ellipsis } from "lucide-react";
import { Fragment, type ReactNode } from "react";
import { cn } from "@/lib/cn";
import { ActionButton } from "./action-button";
import {
  blockedReason,
  type EntityAction,
  footerActions,
  headerActions,
  menuActions,
  quickAction,
} from "./action-model";
import { IconButton } from "./button";
import { Menu, MenuItem, MenuSeparator } from "./menu";
import { m } from "./messages";
import { ToolButton } from "./tool-strip";

/**
 * The one overflow menu (⋯) of an object, destructive items last after a separator. An unavailable or running item stays
 * focusable with its reason underneath; choosing it does nothing.
 */
export function ActionMenu({
  actions,
  label,
  triggerLabel,
  size = "md",
  className,
}: {
  actions: readonly EntityAction[];
  /** The menu's accessible name (e.g. "東京出口 的操作"). */
  label: string;
  /** The ⋯ button's name and tooltip. */
  triggerLabel: string;
  /** sm = 28 px for dense rows. */
  size?: "sm" | "md" | undefined;
  className?: string | undefined;
}) {
  const items = menuActions(actions);
  if (!items.length) return null;
  return (
    <Menu
      label={label}
      trigger={<IconButton label={triggerLabel} icon={Ellipsis} className={cn(size === "sm" && "size-7", className)} />}
    >
      {items.map((a, i) => {
        const reason = blockedReason(a);
        return (
          <Fragment key={a.id}>
            {a.danger && i > 0 && !items[i - 1]?.danger ? <MenuSeparator /> : null}
            <MenuItem
              icon={a.icon}
              tone={a.danger ? "danger" : "default"}
              disabled={reason !== null}
              reason={reason ?? undefined}
              onSelect={a.run}
            >
              {a.label}
            </MenuItem>
          </Fragment>
        );
      })}
    </Menu>
  );
}

/** The EntityHeader's action row: the frequent actions as small buttons, then the overflow menu at the far end. */
export function HeaderActions({ actions, menuLabel }: { actions: readonly EntityAction[]; menuLabel: string }) {
  return (
    <>
      {headerActions(actions).map((a) => (
        <ActionButton
          key={a.id}
          size="sm"
          variant={a.danger ? "danger" : "secondary"}
          icon={a.icon}
          pending={a.pending}
          pendingLabel={a.pendingLabel}
          disabledReason={a.pending ? null : a.disabledReason}
          onClick={a.run}
        >
          {a.label}
        </ActionButton>
      ))}
      <ActionMenu actions={actions} label={menuLabel} triggerLabel={m.action.more} className="ml-auto" />
    </>
  );
}

/**
 * The EntityHeader's title row of an object without header actions (an editor whose one primary action is in its
 * footer): the status, then the same ⋯ menu — instead of an action row that would hold nothing but the menu.
 */
export function TitleActions({
  actions,
  menuLabel,
  children,
}: {
  actions: readonly EntityAction[];
  menuLabel: string;
  children?: ReactNode | undefined;
}) {
  return (
    <span className="flex items-center gap-1.5">
      {children}
      <ActionMenu actions={actions} label={menuLabel} triggerLabel={m.action.more} size="sm" className="-my-1" />
    </span>
  );
}

/** The InspectorFooter's buttons: the first footer action is the view's primary action, the others secondary. */
export function FooterActions({ actions }: { actions: readonly EntityAction[] }) {
  return (
    <>
      {footerActions(actions).map((a, i) => (
        <ActionButton
          key={a.id}
          size="sm"
          variant={i === 0 ? "primary" : a.danger ? "danger" : "secondary"}
          icon={a.icon}
          pending={a.pending}
          pendingLabel={a.pendingLabel}
          disabledReason={a.pending ? null : a.disabledReason}
          onClick={a.run}
        >
          {a.label}
        </ActionButton>
      ))}
    </>
  );
}

/**
 * A list row's actions: at most one quick action (a 28 px icon button named "<action> <object>") and the same overflow
 * menu as the inspector. Without a quick action its place stays empty, so the menus line up.
 */
export function RowActions({
  actions,
  name,
  className,
}: {
  actions: readonly EntityAction[];
  name: string;
  className?: string | undefined;
}) {
  const quick = quickAction(actions);
  const Icon = quick?.icon;
  return (
    <div className={cn("flex items-center justify-end gap-0.5", className)}>
      {quick && Icon ? (
        <ToolButton
          label={m.action.quickOn(quick.label, name)}
          icon={<Icon aria-hidden />}
          pending={quick.pending}
          disabledReason={quick.pending ? null : quick.disabledReason}
          onClick={quick.run}
          className={quick.danger ? "text-danger hover:text-danger" : undefined}
        />
      ) : (
        <span aria-hidden className="size-7 shrink-0" />
      )}
      <ActionMenu actions={actions} label={m.action.menuOf(name)} triggerLabel={m.action.moreOf(name)} size="sm" />
    </div>
  );
}
