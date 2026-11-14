// Adapted from Phasyn Studio (Apache-2.0).
import { forwardRef, useId } from "react";
import { cn } from "@/lib/cn";
import { Button, type ButtonProps } from "./button";

export interface ActionButtonProps extends ButtonProps {
  /**
   * Why the action is unavailable right now. The button stays focusable (aria-disabled), the reason is its title and a
   * description linked with aria-describedby, and clicks do nothing. null/undefined = available.
   */
  disabledReason?: string | null | undefined;
}

// Unavailable (the reason is in title / aria-describedby): no gradient, glow or brightness change, so it does not look
// pressable, while it stays focusable. Forced colors draw it in GrayText (an aria-disabled button would otherwise get
// the enabled ButtonText colour).
const BLOCKED =
  "cursor-not-allowed border-line-subtle bg-raised bg-none text-fg-disabled shadow-none hover:border-line-subtle hover:bg-raised hover:text-fg-disabled hover:shadow-none hover:brightness-100 focus-visible:shadow-none active:bg-raised active:brightness-100 forced-colors:border-[GrayText] forced-colors:text-[GrayText]";

/** A button that says why it cannot be used instead of silently being disabled. */
export const ActionButton = forwardRef<HTMLButtonElement, ActionButtonProps>(function ActionButton(
  { disabledReason, onClick, className, pending, title, ...props },
  ref,
) {
  const reasonId = useId();
  const blocked = Boolean(disabledReason);
  return (
    <>
      <Button
        ref={ref}
        {...props}
        pending={pending}
        aria-disabled={blocked || undefined}
        aria-describedby={blocked ? reasonId : props["aria-describedby"]}
        title={disabledReason ?? title}
        className={cn(className, blocked && BLOCKED)}
        onClick={(event) => {
          if (blocked || pending) {
            event.preventDefault();
            return;
          }
          onClick?.(event);
        }}
      />
      {blocked ? (
        <span id={reasonId} className="sr-only">
          {disabledReason}
        </span>
      ) : null}
    </>
  );
});
