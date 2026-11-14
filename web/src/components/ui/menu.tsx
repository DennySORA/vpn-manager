// Adapted from Phasyn Studio (Apache-2.0).
// Action menus (Radix DropdownMenu: menu button + menu, ↑↓ wrap, Home/End, Enter/Space, Escape closes and returns focus
// to the trigger, typeahead). Look: popover glass; the highlighted item is the soft brand gradient with a cyan icon, a
// destructive item a soft red. Motion: it pops in from the trigger side (4 px + 0.96 → 1, snappy); closing removes it
// at once with focus already back on the trigger. An unavailable item stays focusable and says why underneath.
import type { LucideIcon } from "lucide-react";
import { Check } from "lucide-react";
import { DropdownMenu as M } from "radix-ui";
import { type ReactElement, type ReactNode, useId } from "react";
import { cn } from "@/lib/cn";

export function Menu({
  trigger,
  children,
  align = "end",
  label,
  onCloseAutoFocus,
}: {
  trigger: ReactElement;
  children: ReactNode;
  align?: "start" | "center" | "end" | undefined;
  /** Accessible name of the menu (e.g. "東京出口 的操作"); defaults to the trigger's name. */
  label?: string | undefined;
  /** Focus goes back to the trigger on close unless this calls `preventDefault()` (e.g. the choice removed it). */
  onCloseAutoFocus?: ((event: Event) => void) | undefined;
}) {
  return (
    <M.Root modal={false}>
      <M.Trigger asChild>{trigger}</M.Trigger>
      <M.Portal>
        <M.Content
          align={align}
          sideOffset={6}
          collisionPadding={8}
          // Radix names the menu by its trigger (aria-labelledby), which would win over aria-label: drop it for a label.
          {...(label ? { "aria-label": label, "aria-labelledby": undefined } : {})}
          onCloseAutoFocus={onCloseAutoFocus}
          className={cn(
            "material-popover z-50 grid max-h-[var(--radix-dropdown-menu-content-available-height)] max-w-80 min-w-56 overflow-y-auto rounded-xl p-1 text-fg outline-none",
            "origin-(--radix-dropdown-menu-content-transform-origin) animate-pop-in",
            // It appears from the trigger side: below the trigger it drops in, above it rises.
            "data-[side=top]:[--motion-pop-y:var(--motion-shift)] data-[side=bottom]:[--motion-pop-y:calc(var(--motion-shift)*-1)]",
            "forced-colors:border forced-colors:border-[CanvasText]",
          )}
        >
          {children}
        </M.Content>
      </M.Portal>
    </M.Root>
  );
}

/**
 * A menu item. An unavailable item (`disabled`) stays focusable and readable: its `reason` shows underneath and is its
 * description for assistive technology; choosing it does nothing and keeps the menu open.
 */
export function MenuItem({
  icon: Icon,
  children,
  onSelect,
  tone = "default",
  disabled,
  reason,
  shortcut,
}: {
  icon?: LucideIcon | undefined;
  children: ReactNode;
  onSelect: () => void;
  tone?: "default" | "danger" | undefined;
  disabled?: boolean | undefined;
  reason?: string | undefined;
  shortcut?: string | undefined;
}) {
  const reasonId = useId();
  const blocked = Boolean(disabled);
  return (
    <M.Item
      aria-disabled={blocked || undefined}
      aria-describedby={blocked && reason ? reasonId : undefined}
      data-blocked={blocked || undefined}
      onSelect={(event) => {
        if (blocked) {
          event.preventDefault();
          return;
        }
        onSelect();
      }}
      className={cn(
        "flex min-h-8 cursor-default select-none items-start gap-2 rounded-lg px-2 py-1.5 text-data outline-none",
        "transition-colors duration-(--duration-fast) [&_svg]:mt-0.5 [&_svg]:size-3.5 [&_svg]:shrink-0",
        "focus-visible:ring-1 focus-visible:ring-brand-blue/55 focus-visible:ring-inset",
        blocked
          ? "cursor-not-allowed text-fg-disabled data-[highlighted]:bg-white/5 forced-colors:text-[GrayText]"
          : tone === "danger"
            ? "text-danger data-[highlighted]:bg-danger/12"
            : "text-fg data-[highlighted]:bg-brand-gradient-soft [&_svg]:text-fg-secondary data-[highlighted]:[&_svg]:text-brand-cyan",
      )}
    >
      {Icon ? <Icon aria-hidden /> : <span aria-hidden className="size-3.5 shrink-0" />}
      <span className="grid min-w-0 flex-1">
        <span className="truncate">{children}</span>
        {blocked && reason ? (
          <span id={reasonId} className="text-caption text-fg-tertiary">
            {reason}
          </span>
        ) : null}
      </span>
      {shortcut ? <kbd className="machine ml-3 shrink-0 text-caption text-fg-tertiary">{shortcut}</kbd> : null}
    </M.Item>
  );
}

export function MenuSeparator() {
  return <M.Separator className="mx-2 my-1 h-px bg-white/8" />;
}

/** A single choice inside a menu (sort order, a view mode): menuitemradio semantics, the chosen one carries a check. */
export function MenuRadioGroup<V extends string>({
  value,
  onValueChange,
  children,
  label,
}: {
  value: V;
  onValueChange: (value: V) => void;
  children: ReactNode;
  label?: string | undefined;
}) {
  return (
    <M.RadioGroup
      value={value}
      onValueChange={(v) => {
        onValueChange(v as V);
      }}
      aria-label={label}
    >
      {children}
    </M.RadioGroup>
  );
}

export function MenuRadioItem({ value, children }: { value: string; children: ReactNode }) {
  return (
    <M.RadioItem
      value={value}
      className={cn(
        "flex min-h-8 cursor-default select-none items-center gap-2 rounded-lg px-2 py-1.5 text-data text-fg outline-none",
        "transition-colors duration-(--duration-fast) data-[highlighted]:bg-brand-gradient-soft",
        "focus-visible:ring-1 focus-visible:ring-brand-blue/55 focus-visible:ring-inset",
      )}
    >
      <span aria-hidden className="grid size-3.5 shrink-0 place-items-center">
        <M.ItemIndicator>
          <Check className="size-3.5 text-brand-cyan" />
        </M.ItemIndicator>
      </span>
      <span className="min-w-0 flex-1 truncate">{children}</span>
    </M.RadioItem>
  );
}

export function MenuLabel({ children }: { children: ReactNode }) {
  return <M.Label className="px-2 pt-1.5 pb-1 text-caption font-medium text-fg-tertiary">{children}</M.Label>;
}
