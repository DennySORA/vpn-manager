// Adapted from Phasyn Studio (Apache-2.0).
// The tool strip above a collection: search, filters, the count, and the list's batch actions (the right group, split
// with ml-auto). Operation aggregation: actions on the whole list or on the selected rows live here, once.
import { LoaderCircle } from "lucide-react";
import { forwardRef, type ButtonHTMLAttributes, type HTMLAttributes, type ReactNode, type Ref, useId } from "react";
import { cn } from "@/lib/cn";
import { m } from "./messages";

/** A 40 px strip (role="group" with a name); left and right groups split with `ml-auto`. */
export function ToolStrip({
  label,
  className,
  children,
  ref,
  ...props
}: HTMLAttributes<HTMLDivElement> & { label: string; ref?: Ref<HTMLDivElement> }) {
  return (
    <div
      ref={ref}
      role="group"
      aria-label={label}
      className={cn(
        "flex min-h-10 shrink-0 flex-wrap items-center gap-x-2 gap-y-1 border-b border-line-subtle px-2 py-1",
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export function ToolSeparator({ className }: { className?: string | undefined }) {
  return <span aria-hidden className={cn("mx-0.5 h-5 w-px shrink-0 bg-line-subtle", className)} />;
}

export interface ToolButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children"> {
  /** Accessible name and tooltip. */
  label: string;
  icon: ReactNode;
  /** A toggle's state (aria-pressed). */
  pressed?: boolean | undefined;
  /** Why it is unavailable: in the title, the button stays focusable (aria-disabled). */
  disabledReason?: string | null | undefined;
  /** Text next to the icon (when the strip has room). */
  text?: ReactNode | undefined;
  /**
   * Work in flight: a spinner takes the icon's place (same size, nothing moves), aria-busy, and presses are ignored
   * until it settles. Focus stays on the button.
   */
  pending?: boolean | undefined;
}

/**
 * A 28 px icon button; unavailable keeps focus, its reason in the title and aria-describedby. Presses with `pressable`;
 * a toggle that is on shows the soft brand ground and a thin ring.
 */
export const ToolButton = forwardRef<HTMLButtonElement, ToolButtonProps>(function ToolButton(
  { label, icon, pressed, disabledReason, text, pending = false, className, onClick, title, type = "button", ...props },
  ref,
) {
  const reasonId = useId();
  const blocked = Boolean(disabledReason);
  return (
    <>
      <button
        ref={ref}
        type={type}
        aria-label={text ? undefined : label}
        aria-pressed={pressed}
        aria-disabled={blocked || pending || undefined}
        aria-busy={pending || undefined}
        title={blocked ? m.toolButton.blocked(label, disabledReason ?? "") : (title ?? label)}
        onClick={blocked || pending ? undefined : onClick}
        className={cn(
          "pressable inline-flex h-7 min-w-7 shrink-0 items-center justify-center gap-1.5 rounded-md px-1.5 text-data text-fg-secondary [&_svg]:size-4 [&_svg]:shrink-0",
          "hover:bg-raised hover:text-fg active:bg-sunken",
          "aria-pressed:bg-brand-soft aria-pressed:text-fg aria-pressed:shadow-[inset_0_0_0_1px_rgb(62_137_255_/_0.35)] aria-pressed:[&_svg]:text-action-fg",
          // As a menu trigger (Radix sets data-state=open): the soft brand ground and ring while its menu is open.
          "data-[state=open]:bg-brand-gradient-soft data-[state=open]:text-fg data-[state=open]:ring-1 data-[state=open]:ring-brand-blue/50 data-[state=open]:ring-inset",
          // Unavailable looks disabled; in flight (aria-busy, also aria-disabled) keeps its colour and shows progress.
          "[&[aria-disabled=true]:not([aria-busy=true])]:cursor-not-allowed [&[aria-disabled=true]:not([aria-busy=true])]:text-fg-disabled aria-disabled:hover:bg-transparent",
          // Forced colors: an unavailable tool button in GrayText (aria-disabled alone keeps the enabled colour there).
          "forced-colors:[&[aria-disabled=true]:not([aria-busy=true])]:text-[GrayText]",
          "aria-busy:cursor-progress",
          className,
        )}
        {...props}
        aria-describedby={blocked ? reasonId : props["aria-describedby"]}
      >
        {pending ? <LoaderCircle aria-hidden className="animate-spin" /> : icon}
        {text ? <span className="whitespace-nowrap">{text}</span> : null}
      </button>
      {blocked ? (
        <span id={reasonId} className="sr-only">
          {disabledReason}
        </span>
      ) : null}
    </>
  );
});
