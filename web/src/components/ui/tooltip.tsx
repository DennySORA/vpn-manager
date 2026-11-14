// Adapted from Phasyn Studio (Apache-2.0).
import { Tooltip as T } from "radix-ui";
import type { ReactElement, ReactNode } from "react";

/** One provider at the root; a short delay so hover hints feel responsive but never flash while the pointer passes. */
export function TooltipProvider({ children }: { children: ReactNode }) {
  return (
    <T.Provider delayDuration={300} skipDelayDuration={200}>
      {children}
    </T.Provider>
  );
}

/**
 * Supplementary hint on popover glass that pops in from its trigger. Never the only place a fact or a disabled reason
 * lives for keyboard users. Supporting text in popovers uses fg-secondary (contrast over the glass).
 */
export function Tip({
  content,
  side = "top",
  children,
}: {
  content: ReactNode;
  side?: "top" | "right" | "bottom" | "left" | undefined;
  children: ReactElement;
}) {
  if (content === null || content === undefined || content === "") return children;
  return (
    <T.Root>
      <T.Trigger asChild>{children}</T.Trigger>
      <T.Portal>
        <T.Content
          side={side}
          sideOffset={6}
          collisionPadding={8}
          className={
            "material-popover z-50 max-w-72 rounded-lg px-2.5 py-1.5 text-caption text-fg-secondary " +
            "origin-(--radix-tooltip-content-transform-origin) animate-pop-in " +
            "data-[side=top]:[--motion-pop-y:var(--motion-shift)] data-[side=bottom]:[--motion-pop-y:calc(var(--motion-shift)*-1)] " +
            "data-[side=left]:[--motion-pop-y:0px] data-[side=right]:[--motion-pop-y:0px] " +
            "forced-colors:border forced-colors:border-[CanvasText]"
          }
        >
          {content}
        </T.Content>
      </T.Portal>
    </T.Root>
  );
}
