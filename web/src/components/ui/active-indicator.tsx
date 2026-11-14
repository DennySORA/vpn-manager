// Adapted from Phasyn Studio (Apache-2.0).
import { type RefObject, useCallback, useRef } from "react";
import { cn } from "@/lib/cn";
import { type IndicatorOptions, useActiveIndicator } from "./motion";

// Horizontal indicators use the brand gradient (stretched by scaleX); the left edge uses the same stops top to bottom.
const EDGE_CLASS = {
  bottom: "bottom-0 left-0 h-0.5 w-px origin-left rounded-full bg-brand-gradient",
  top: "top-0 left-0 h-0.5 w-px origin-left rounded-full bg-brand-gradient",
  left: "top-0 left-0 h-px w-0.5 origin-top rounded-full bg-[image:linear-gradient(180deg,var(--color-brand-cyan),var(--color-brand-blue)_36%,var(--color-brand-iris)_68%,var(--color-brand-violet))]",
} as const;

/**
 * The current-position line of tabs and navigation (brand gradient): put it inside the position: relative tablist or
 * navigation; it slides to the current item with transform only. Purely decorative
 * (aria-hidden): the selection is still aria-selected / aria-current. as="li" inside a <ul> (lists hold only li).
 */
export function ActiveIndicator({
  container,
  edge = "bottom",
  as: Tag = "span",
  className,
  ...options
}: Omit<IndicatorOptions, "axis"> & {
  container: RefObject<HTMLElement | null>;
  edge?: keyof typeof EDGE_CLASS | undefined;
  as?: "span" | "li" | undefined;
  className?: string | undefined;
}) {
  const ref = useRef<HTMLElement | null>(null);
  const attach = useCallback((node: HTMLElement | null) => {
    ref.current = node;
  }, []);
  useActiveIndicator(container, ref, { ...options, axis: edge === "left" ? "y" : "x" });
  return (
    <Tag
      ref={attach}
      aria-hidden
      role={Tag === "li" ? "presentation" : undefined}
      data-tab-indicator=""
      className={cn("pointer-events-none absolute z-[1]", EDGE_CLASS[edge], className)}
    />
  );
}
