// Adapted from Phasyn Studio (Apache-2.0).
// Buttons: primary = the deep action gradient (#2767DE → #4D5FE3 → #7A4FD9) with white text (≥ 5.1:1 on every stop)
// and a 1 px inner top light, glowing on hover and keyboard focus; secondary = raised; quiet = text only; danger = a
// soft red; danger-confirm = the solid destructive confirmation. Disabled removes gradient, glow and shadow. Motion:
// pressable — pressing shrinks to 0.97 in 90 ms and releases on the snappy spring, colours move in 120 ms.
// One primary per task area.
import type { LucideIcon } from "lucide-react";
import { LoaderCircle } from "lucide-react";
import { type ButtonHTMLAttributes, forwardRef, type ReactNode } from "react";
import { Link } from "react-router";
import { cn } from "@/lib/cn";
import { m } from "./messages";

/** `ghost` and `danger-quiet` are the earlier names of `quiet` and `danger`; they render the same. */
export type ButtonVariant = "primary" | "secondary" | "quiet" | "danger" | "danger-confirm" | "ghost" | "danger-quiet";
export type ButtonSize = "md" | "sm" | "icon" | "icon-sm";

const BASE = cn(
  "pressable relative inline-flex shrink-0 select-none items-center justify-center gap-2 whitespace-nowrap rounded-md border font-medium no-underline",
  "disabled:cursor-not-allowed disabled:border-line-subtle disabled:bg-raised disabled:bg-none disabled:text-fg-disabled disabled:shadow-none disabled:brightness-100",
  "aria-busy:cursor-progress [&_svg]:size-4 [&_svg]:shrink-0",
);

const VARIANT: Record<ButtonVariant, string> = {
  // A transparent border is invisible here and drawn by forced colors, where the fill disappears.
  primary:
    "border-transparent bg-action-gradient font-semibold text-[#fff] shadow-[inset_0_1px_0_rgb(255_255_255_/_0.18),0_1px_2px_rgb(0_0_0_/_0.35)] hover:shadow-glow-sm hover:brightness-105 focus-visible:shadow-glow-sm active:brightness-95 aria-busy:animate-shimmer",
  secondary:
    "border-line-strong bg-raised text-fg shadow-edge hover:border-action/60 hover:bg-overlay active:bg-sunken",
  quiet: "border-transparent bg-transparent text-fg-secondary hover:bg-raised hover:text-fg active:bg-sunken",
  ghost: "border-transparent bg-transparent text-fg-secondary hover:bg-raised hover:text-fg active:bg-sunken",
  danger: "border-danger/40 bg-danger/10 text-danger hover:border-danger/70 hover:bg-danger/15 active:bg-danger/20",
  "danger-quiet":
    "border-danger/40 bg-danger/10 text-danger hover:border-danger/70 hover:bg-danger/15 active:bg-danger/20",
  // Light solid with dark text: hover and press adjust brightness (text contrast stays ≥ 9:1).
  "danger-confirm":
    "border-danger-fill bg-danger-fill font-semibold text-on-accent hover:bg-danger-fill enabled:hover:brightness-105 active:bg-danger-fill enabled:active:brightness-95",
};

const SIZE: Record<ButtonSize, string> = {
  md: "min-h-10 px-3.5 text-body",
  sm: "min-h-8 gap-1.5 px-3 text-data",
  icon: "size-10 p-0",
  "icon-sm": "size-8 p-0",
};

/** The button look as classes, for links that look like buttons. */
export function buttonVariants({
  variant = "secondary",
  size = "md",
}: { variant?: ButtonVariant | undefined; size?: ButtonSize | undefined } = {}): string {
  return cn(BASE, VARIANT[variant], SIZE[size]);
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant | undefined;
  size?: ButtonSize | undefined;
  icon?: LucideIcon | undefined;
  /**
   * Work in flight: a spinner with `pendingLabel` takes the label's place in the same cell (the button keeps its width),
   * announced with aria-busy + aria-disabled, and repeated clicks (an implicit form submit too) are ignored. The
   * disabled attribute is never set: a keyboard user keeps focus on the button while it waits.
   */
  pending?: boolean | undefined;
  pendingLabel?: string | undefined;
  children?: ReactNode | undefined;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = "secondary",
    size = "md",
    icon: Icon,
    pending,
    pendingLabel,
    className,
    children,
    disabled,
    onClick,
    type = "button",
    ...rest
  },
  ref,
) {
  const busy = Boolean(pending);
  return (
    <button
      ref={ref}
      type={type}
      {...rest}
      disabled={disabled}
      aria-busy={busy || undefined}
      aria-disabled={busy ? true : rest["aria-disabled"]}
      onClick={(e) => {
        // Pending blocks duplicates without disabling (focus stays on the control).
        if (busy) {
          e.preventDefault();
          return;
        }
        onClick?.(e);
      }}
      className={cn(buttonVariants({ variant, size }), className)}
    >
      {pending === undefined ? (
        <>
          {Icon ? <Icon aria-hidden /> : null}
          {children}
        </>
      ) : (
        // Idle and pending content share one grid cell, the hidden one keeping its space: the button is as wide as
        // the wider of the two, so it never jumps and never cuts the label.
        <span className="inline-grid place-items-center gap-[inherit]">
          <span
            aria-hidden={busy || undefined}
            className={cn("col-start-1 row-start-1 inline-flex items-center gap-[inherit]", busy && "invisible")}
          >
            {Icon ? <Icon aria-hidden /> : null}
            {children}
          </span>
          <span
            aria-hidden={!busy || undefined}
            className={cn(
              "col-start-1 row-start-1 inline-flex items-center gap-1.5 whitespace-nowrap",
              !busy && "invisible",
            )}
          >
            <LoaderCircle aria-hidden className={cn(busy && "animate-spin")} />
            {size === "icon" || size === "icon-sm" ? (
              <span className="sr-only">{pendingLabel ?? m.working}</span>
            ) : (
              (pendingLabel ?? m.working)
            )}
          </span>
        </span>
      )}
    </button>
  );
});

/**
 * A 32 px icon-only button: `label` is its accessible name and tooltip. As a menu trigger (Radix sets data-state=open)
 * it shows the soft brand fill and ring while its menu is open.
 */
export const IconButton = forwardRef<
  HTMLButtonElement,
  { label: string; icon: LucideIcon } & Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children">
>(function IconButton({ label, icon: Icon, className, type = "button", ...rest }, ref) {
  return (
    <button
      ref={ref}
      type={type}
      aria-label={label}
      title={label}
      {...rest}
      className={cn(
        "pressable inline-flex size-8 shrink-0 items-center justify-center rounded-md text-fg-tertiary [&_svg]:size-4",
        "hover:bg-raised hover:text-fg active:bg-sunken",
        "data-[state=open]:bg-brand-gradient-soft data-[state=open]:text-fg data-[state=open]:ring-1 data-[state=open]:ring-brand-blue/50 data-[state=open]:ring-inset",
        "disabled:cursor-not-allowed disabled:text-fg-disabled disabled:hover:bg-transparent",
        "aria-disabled:cursor-not-allowed aria-disabled:text-fg-disabled aria-disabled:hover:bg-transparent",
        className,
      )}
    >
      <Icon aria-hidden />
    </button>
  );
});

/** A navigation that looks like a button (e.g. "新增" opening a create route). A page change uses a View Transition. */
export function ButtonLink({
  to,
  variant = "secondary",
  size = "md",
  icon: Icon,
  children,
  className,
}: {
  to: string;
  variant?: ButtonVariant | undefined;
  size?: ButtonSize | undefined;
  icon?: LucideIcon | undefined;
  children: ReactNode;
  className?: string | undefined;
}) {
  return (
    <Link to={to} className={cn(buttonVariants({ variant, size }), className)}>
      {Icon ? <Icon aria-hidden /> : null}
      {children}
    </Link>
  );
}
