// Adapted from Phasyn Studio (Apache-2.0): the dock-panel header grammar (icon + title + count, actions on the right).
import type { LucideIcon } from "lucide-react";
import type { CSSProperties, ReactNode } from "react";
import { cn } from "@/lib/cn";

/** One titled frame: heading (optional icon and count), optional one-line caption and trailing action. */
export function Panel({
  title,
  description,
  children,
  action,
  icon: Icon,
  count,
  className,
  flush,
  style,
}: {
  title: string;
  description?: ReactNode | undefined;
  children: ReactNode;
  action?: ReactNode | undefined;
  icon?: LucideIcon | undefined;
  count?: ReactNode | undefined;
  className?: string | undefined;
  /** No body padding (a table fills the panel). */
  flush?: boolean | undefined;
  /** E.g. the page's entrance stagger (motion.staggerStyle). */
  style?: CSSProperties | undefined;
}) {
  return (
    <section aria-label={title} style={style} className={cn("panel min-w-0", className)}>
      <div className="flex min-h-11 flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-line-subtle px-4 py-2">
        <div className="min-w-0">
          <h2 className="flex min-w-0 items-center gap-2 text-data font-semibold text-fg">
            {Icon ? <Icon aria-hidden className="size-4 shrink-0 text-fg-tertiary" /> : null}
            <span className="[overflow-wrap:anywhere]">{title}</span>
            {count !== undefined && count !== null ? (
              <span className="machine text-caption font-normal text-fg-tertiary">{count}</span>
            ) : null}
          </h2>
          {description ? <p className="text-caption text-fg-tertiary">{description}</p> : null}
        </div>
        {action ? <div className="flex shrink-0 flex-wrap items-center gap-1">{action}</div> : null}
      </div>
      <div className={flush ? undefined : "px-4 py-4"}>{children}</div>
    </section>
  );
}
