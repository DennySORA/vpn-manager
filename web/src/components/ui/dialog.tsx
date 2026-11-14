// Adapted from Phasyn Studio (Apache-2.0); portions of its dialog follow shadcn/ui (MIT). See THIRD_PARTY_NOTICES.md.
// Radix Dialog / AlertDialog: initial focus, focus trap, Escape, focus back to the opener. The portal sits in
// document.body, still inside <html data-theme="noir">, so the tokens apply.
// Look: a deep-space scrim with a 6 px blur; dialogs and sheets are material-sheet (glass, window shadow, 14 px radius)
// with a thin brand-gradient line along the top edge. Motion: the scrim fades, a dialog rises 12 px from 0.94 (smooth
// spring), a sheet slides in from its edge (smooth); exits are 140–180 ms ease-exit. Enter and exit are driven by
// data-state (Radix Presence keeps the content until its exit animation ends); a closing dialog is inert and lets
// clicks through at once.
import { X } from "lucide-react";
import { AlertDialog as AD, Dialog as D } from "radix-ui";
import { type ReactNode, useRef } from "react";
import { cn } from "@/lib/cn";
import { Button } from "./button";
import { useFocusReturn } from "./focus-return";
import { BRAND_HAIRLINE } from "./look";
import { m } from "./messages";

// While closing (data-state=closed) the scrim never intercepts a click: Radix writes an inline pointer-events: auto on
// it, hence the important.
const overlay =
  "fixed inset-0 z-40 bg-[rgb(2_4_10_/_0.66)] backdrop-blur-[6px] data-[state=open]:animate-fade-in data-[state=closed]:animate-fade-out data-[state=closed]:pointer-events-none!";

/**
 * Dialogs are anchored near the top (VPN Manager): their forms grow downward as errors, previews and results appear,
 * so a dialog never jumps around a vertical centre.
 */
const content = cn(
  "material-sheet fixed top-[max(1rem,9vh)] left-1/2 z-50 flex max-h-[min(84vh,52rem)] w-[min(calc(100vw-2rem),var(--dialog-w,560px))] -translate-x-1/2 flex-col overflow-hidden rounded-xl border border-[rgb(255_255_255_/_0.08)] text-fg outline-none",
  BRAND_HAIRLINE,
  "data-[state=open]:animate-dialog-in data-[state=closed]:animate-dialog-out data-[state=closed]:pointer-events-none!",
  "forced-colors:border-[CanvasText]",
);

const closeButton =
  "pressable absolute top-3 right-3 inline-flex size-9 items-center justify-center rounded-md text-fg-secondary hover:bg-raised hover:text-fg active:bg-sunken";

/**
 * Opening focus goes to the body's `[data-autofocus]` element, else its first field — not the header's close button.
 */
function focusFirstField(e: Event, body: HTMLElement | null) {
  const target =
    body?.querySelector<HTMLElement>("[data-autofocus]") ??
    body?.querySelector<HTMLElement>(
      "input:not([disabled]):not([type=hidden]):not([type=file]), textarea:not([disabled]), select:not([disabled])",
    );
  if (target) {
    e.preventDefault();
    target.focus();
  }
}

/** Modal dialog: focus moves in, stays contained, Escape closes, focus returns to the trigger (or the opener). */
export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  width = 560,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode | undefined;
  children: ReactNode;
  footer?: ReactNode | undefined;
  width?: number | undefined;
}) {
  const body = useRef<HTMLDivElement>(null);
  const focus = useFocusReturn(open, {
    onOpenAutoFocus: (e) => {
      focusFirstField(e, body.current);
    },
  });
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className={overlay} />
        <D.Content
          className={content}
          style={{ ["--dialog-w" as string]: `${width}px` }}
          inert={!open || undefined}
          {...focus}
        >
          <div className="flex shrink-0 flex-col gap-1 border-b border-line-subtle px-6 pt-5 pr-14 pb-4">
            <D.Title className="text-section font-semibold text-fg [overflow-wrap:anywhere]">{title}</D.Title>
            {description ? <D.Description className="text-data text-fg-secondary">{description}</D.Description> : null}
          </div>
          <div ref={body} className="min-h-0 flex-1 overflow-y-auto px-6 py-4">
            {children}
          </div>
          {footer ? (
            <div className="flex shrink-0 flex-wrap items-center justify-end gap-2 border-t border-line-subtle px-6 py-4">
              {footer}
            </div>
          ) : null}
          <D.Close asChild>
            <button type="button" aria-label={m.common.close} title={m.common.close} className={closeButton}>
              <X aria-hidden className="size-4" />
            </button>
          </D.Close>
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}

/**
 * Confirmation for consequential actions. It states the exact scope before acting (what changes, what stays, what can
 * be undone); a destructive confirmation uses the danger-confirm button.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  children,
  confirmLabel,
  pending,
  tone = "danger",
  onConfirm,
  onCloseAutoFocus,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  pending?: boolean | undefined;
  tone?: "danger" | "primary" | undefined;
  onConfirm: () => void;
  /**
   * Where focus goes when it closes, when not back to its opener: e.g. after deleting, the row that opened it is gone.
   * Call preventDefault() and move focus yourself; otherwise the default applies.
   */
  onCloseAutoFocus?: ((event: Event) => void) | undefined;
}) {
  const focus = useFocusReturn(open, { onCloseAutoFocus });
  return (
    <AD.Root open={open} onOpenChange={onOpenChange}>
      <AD.Portal>
        <AD.Overlay className={overlay} />
        <AD.Content className={cn(content, "[--dialog-w:460px]")} inert={!open || undefined} {...focus}>
          <div className="min-h-0 overflow-y-auto px-6 pt-5 pb-2">
            <AD.Title className="text-section font-semibold text-fg [overflow-wrap:anywhere]">{title}</AD.Title>
            <AD.Description asChild>
              <div className="mt-2 space-y-2 text-body text-fg-secondary">{children}</div>
            </AD.Description>
          </div>
          <div className="flex shrink-0 flex-wrap items-center justify-end gap-2 px-6 pt-3 pb-5">
            <AD.Cancel asChild>
              <Button variant="quiet">{m.common.cancel}</Button>
            </AD.Cancel>
            <Button
              variant={tone === "danger" ? "danger-confirm" : "primary"}
              pending={pending}
              pendingLabel={m.working}
              onClick={(e) => {
                e.preventDefault();
                onConfirm();
              }}
            >
              {confirmLabel}
            </Button>
          </div>
        </AD.Content>
      </AD.Portal>
    </AD.Root>
  );
}

/**
 * Side sheet: the inspector below the wide breakpoint, recent operations, and (side="left") the navigation drawer of
 * narrow windows. Glass, brand hairline, slides in from its edge.
 */
export function Sheet({
  open,
  onOpenChange,
  title,
  children,
  side = "right",
  hideTitle = false,
  closeLabel = m.common.close,
  className,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  children: ReactNode;
  side?: "right" | "left" | undefined;
  /** The title names the sheet for assistive technology only (the content shows its own heading). */
  hideTitle?: boolean | undefined;
  closeLabel?: string | undefined;
  className?: string | undefined;
}) {
  const focus = useFocusReturn(open);
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className={overlay} />
        <D.Content
          aria-describedby={undefined}
          inert={!open || undefined}
          {...focus}
          className={cn(
            "material-sheet fixed inset-y-0 z-50 flex w-[min(420px,94vw)] flex-col text-fg outline-none",
            BRAND_HAIRLINE,
            side === "left"
              ? "left-0 border-r border-[rgb(255_255_255_/_0.08)] data-[state=open]:animate-drawer-in data-[state=closed]:animate-drawer-out"
              : "right-0 border-l border-[rgb(255_255_255_/_0.08)] data-[state=open]:animate-sheet-in data-[state=closed]:animate-sheet-out",
            "data-[state=closed]:pointer-events-none! forced-colors:border-[CanvasText]",
            className,
          )}
        >
          {hideTitle ? (
            <D.Title className="sr-only">{title}</D.Title>
          ) : (
            <div className="flex h-12 shrink-0 items-center gap-3 border-b border-line-subtle pr-12 pl-4">
              <D.Title className="truncate text-section font-semibold text-fg">{title}</D.Title>
            </div>
          )}
          <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
          <D.Close asChild>
            <button
              type="button"
              aria-label={closeLabel}
              title={closeLabel}
              className={cn(closeButton, "top-1.5 right-2")}
            >
              <X aria-hidden className="size-4" />
            </button>
          </D.Close>
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}
