// A popover (Radix Popover) in the menu's look: popover glass, popping in from the trigger side (4 px + 0.96 → 1,
// snappy); Escape or a click outside closes it and focus goes back to the trigger. For details behind a compact
// control (the top bar's traffic strip), never for the only copy of a fact or a reason.
import { Popover as P } from "radix-ui";
import type { ReactElement, ReactNode } from "react";
import { cn } from "@/lib/cn";

export function Popover({
  trigger,
  children,
  label,
  open,
  onOpenChange,
  align = "end",
  className,
}: {
  /** The button that opens it (its accessible name says what it opens). */
  trigger: ReactElement;
  children: ReactNode;
  /** The popover's accessible name (a dialog). */
  label: string;
  open?: boolean | undefined;
  onOpenChange?: ((open: boolean) => void) | undefined;
  align?: "start" | "center" | "end" | undefined;
  className?: string | undefined;
}) {
  return (
    <P.Root open={open} onOpenChange={onOpenChange}>
      <P.Trigger asChild>{trigger}</P.Trigger>
      <P.Portal>
        <P.Content
          align={align}
          sideOffset={6}
          collisionPadding={8}
          aria-label={label}
          className={cn(
            "material-popover z-50 max-h-[var(--radix-popover-content-available-height)] w-[min(24rem,calc(100vw-1rem))] overflow-y-auto overscroll-contain rounded-xl text-fg outline-none",
            "origin-(--radix-popover-content-transform-origin) animate-pop-in",
            "data-[side=top]:[--motion-pop-y:var(--motion-shift)] data-[side=bottom]:[--motion-pop-y:calc(var(--motion-shift)*-1)]",
            "forced-colors:border forced-colors:border-[CanvasText]",
            className,
          )}
        >
          {children}
        </P.Content>
      </P.Portal>
    </P.Root>
  );
}
