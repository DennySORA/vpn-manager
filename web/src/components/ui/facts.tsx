// Adapted from Phasyn Studio (Apache-2.0): the property-grid recipe (a fixed label column and data-density values).
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

/** Evidence list: each fact names where it came from and when (signature 2). Labels share one fixed column. */
export function Facts({ children, className }: { children: ReactNode; className?: string | undefined }) {
  return (
    <dl className={cn("grid grid-cols-[minmax(6.5rem,7.5rem)_minmax(0,1fr)] items-start gap-x-3 gap-y-2", className)}>
      {children}
    </dl>
  );
}

export function Fact({
  label,
  children,
  source,
  mono,
}: {
  label: string;
  children: ReactNode;
  /** Origin and age of the fact, e.g. "WireGuard · 12 秒前". */
  source?: ReactNode | undefined;
  mono?: boolean | undefined;
}) {
  return (
    <>
      <dt className="pt-px text-data text-fg-tertiary [overflow-wrap:anywhere]">{label}</dt>
      <dd className="min-w-0">
        <div className={cn("text-data text-fg [overflow-wrap:anywhere]", mono && "machine")}>{children}</div>
        {source ? <div className="text-caption text-fg-tertiary">{source}</div> : null}
      </dd>
    </>
  );
}

/** Section inside an inspector or form: a small heading, an optional trailing control. */
export function Section({
  title,
  action,
  children,
  className,
}: {
  title: string;
  action?: ReactNode | undefined;
  children: ReactNode;
  className?: string | undefined;
}) {
  return (
    <section className={cn("space-y-3", className)} aria-label={title}>
      <div className="flex min-h-8 items-center justify-between gap-2">
        <h3 className="text-data font-semibold text-fg">{title}</h3>
        {action}
      </div>
      {children}
    </section>
  );
}
