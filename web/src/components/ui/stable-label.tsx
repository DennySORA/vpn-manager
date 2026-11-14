// Adapted from Phasyn Studio (Apache-2.0).
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

/**
 * A label that keeps its width when it turns bold: an invisible bold copy (aria-hidden) holds the width and the visible
 * text sits centred in the same cell. Used on tabs and segments, so switching never shifts the neighbours. Not for long
 * labels that must truncate.
 */
export function StableLabel({
  children,
  weight = "semibold",
  className,
}: {
  children: ReactNode;
  weight?: "medium" | "semibold" | undefined;
  className?: string | undefined;
}) {
  return (
    <span className={cn("inline-grid justify-items-center", className)}>
      <span className="[grid-area:1/1]">{children}</span>
      <span
        aria-hidden
        className={cn("invisible [grid-area:1/1]", weight === "medium" ? "font-medium" : "font-semibold")}
      >
        {children}
      </span>
    </span>
  );
}
