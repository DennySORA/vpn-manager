// Adapted from Phasyn Studio (Apache-2.0).
import { ChevronRight } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

/**
 * Native details/summary: Enter/Space open it, collapsed content leaves the Tab order. The chevron turns on the snappy
 * spring; where ::details-content is supported the height opens on the smooth spring (.disclosure in app.css),
 * elsewhere the content fades in (reveal).
 */
export function Disclosure({
  summary,
  children,
  defaultOpen = false,
  className,
  summaryClassName,
}: {
  summary: ReactNode;
  children: ReactNode;
  defaultOpen?: boolean | undefined;
  className?: string | undefined;
  summaryClassName?: string | undefined;
}) {
  return (
    <details
      open={defaultOpen || undefined}
      className={cn("disclosure min-w-0 [&[open]>div]:animate-reveal", className)}
    >
      <summary
        className={cn(
          "flex min-h-8 cursor-pointer list-none items-center gap-1.5 rounded-sm text-data text-fg-secondary hover:text-fg [&::-webkit-details-marker]:hidden",
          summaryClassName,
        )}
      >
        <ChevronRight
          aria-hidden
          className="size-3.5 shrink-0 transition-[rotate] duration-(--duration-spring-snappy) ease-(--ease-spring-snappy) [[open]>summary>&]:rotate-90"
        />
        <span className="min-w-0">{summary}</span>
      </summary>
      <div className="mt-2 min-w-0">{children}</div>
    </details>
  );
}

/**
 * A region that expands with grid-template-rows 0fr → 1fr (smooth spring). The content stays in the DOM (so it can
 * transition) and is inert + aria-hidden when collapsed, at once. The trigger gives aria-expanded / aria-controls.
 */
export function Expand({
  id,
  open,
  children,
  className,
  innerClassName,
}: {
  id?: string | undefined;
  open: boolean;
  children: ReactNode;
  className?: string | undefined;
  innerClassName?: string | undefined;
}) {
  return (
    <div
      id={id}
      inert={!open || undefined}
      aria-hidden={open ? undefined : true}
      className={cn(
        "grid transition-[grid-template-rows,opacity] duration-(--duration-spring-smooth) ease-(--ease-spring-smooth)",
        open ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0",
        className,
      )}
    >
      <div className={cn("min-h-0 overflow-hidden", innerClassName)}>{children}</div>
    </div>
  );
}
