// Adapted from Phasyn Studio (Apache-2.0).
import type { HTMLAttributes, ReactNode, Ref } from "react";
import { cn } from "@/lib/cn";

/**
 * A workbench panel: rounded, hairline, inner top light; panels sit apart by the parent's gap, showing the canvas.
 * The content area (`DockBody`) scrolls, never the panel itself. At most two raised panels per view.
 */
export function DockPanel({
  as: Tag = "section",
  raised = false,
  className,
  children,
  ref,
  ...props
}: HTMLAttributes<HTMLElement> & {
  as?: "section" | "aside" | "nav" | "div" | undefined;
  raised?: boolean | undefined;
  ref?: Ref<HTMLElement> | undefined;
}) {
  return (
    <Tag
      ref={ref as Ref<HTMLDivElement>}
      className={cn(
        "relative flex min-h-0 min-w-0 flex-col overflow-hidden rounded-lg border border-line-subtle bg-surface shadow-edge",
        raised && "panel-raised",
        className,
      )}
      {...props}
    >
      {children}
    </Tag>
  );
}

/** Panel title bar (36 px): icon + 13 px title + count; 28 px icon actions on the right. */
export function DockHeader({
  icon,
  title,
  titleId,
  count,
  actions,
  className,
  children,
}: {
  icon?: ReactNode | undefined;
  title: ReactNode;
  titleId?: string | undefined;
  count?: number | null | undefined;
  actions?: ReactNode | undefined;
  className?: string | undefined;
  /** Extra content between the title and the actions (e.g. compact tabs). */
  children?: ReactNode | undefined;
}) {
  return (
    <div className={cn("flex h-9 shrink-0 items-center gap-2 border-b border-line-subtle px-3", className)}>
      <h2
        id={titleId}
        className="flex min-w-0 items-center gap-2 text-data font-semibold text-fg [&_svg]:size-4 [&_svg]:shrink-0 [&_svg]:text-fg-tertiary"
      >
        {icon}
        <span className="truncate">{title}</span>
        {count !== undefined && count !== null ? (
          <span className="machine text-caption font-normal text-fg-tertiary">{count}</span>
        ) : null}
      </h2>
      {children}
      {actions ? <div className="ml-auto flex shrink-0 items-center gap-0.5">{actions}</div> : null}
    </div>
  );
}

/** Panel content: the only scroll owner. */
export function DockBody({
  className,
  children,
  ref,
  ...props
}: HTMLAttributes<HTMLDivElement> & { ref?: Ref<HTMLDivElement> }) {
  return (
    <div ref={ref} className={cn("relative min-h-0 flex-1 overflow-auto", className)} {...props}>
      {children}
    </div>
  );
}
