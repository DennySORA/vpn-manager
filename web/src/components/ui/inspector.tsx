// Adapted from Phasyn Studio (Apache-2.0).
// Inspector primitives: the object's header (type tile, name, status, one-line description, ID with copy, and the
// object's action row), collapsible property sections, a fixed-label property grid and the fixed footer with the
// primary and secondary actions. Operation aggregation: an object's actions live in its EntityHeader action row (the
// frequent ones, plus one overflow menu) and its InspectorFooter (the primary action of the view) — nowhere else.
import { ChevronDown, type LucideIcon } from "lucide-react";
import { type ReactNode, useId, useState } from "react";
import { cn } from "@/lib/cn";
import { ButtonLink } from "./button";
import { CopyButton } from "./copy";
import { type TabItem, TabPanel, Tabs } from "./tabs";
import { TILE_TONE, type ToneKey } from "./tones";

/** The object's header: 40 px type tile, 16 px name + status chip, one-line description, ID + copy, then the action row. */
export function EntityHeader({
  icon: Icon,
  tone = "neutral",
  title,
  status,
  description,
  id,
  idLabel = "ID",
  actions,
  className,
}: {
  icon: LucideIcon;
  tone?: ToneKey | undefined;
  title: ReactNode;
  status?: ReactNode | undefined;
  description?: ReactNode | undefined;
  /** The raw ID (mono, copyable). */
  id?: string | null | undefined;
  idLabel?: string | undefined;
  actions?: ReactNode | undefined;
  className?: string | undefined;
}) {
  return (
    <div className={cn("grid shrink-0 gap-2.5 border-b border-line-subtle px-4 py-3.5", className)}>
      <div className="flex min-w-0 gap-3">
        <span aria-hidden className={cn("grid size-10 shrink-0 place-items-center rounded-lg border", TILE_TONE[tone])}>
          <Icon className="size-5" />
        </span>
        <div className="grid min-w-0 flex-1 content-start gap-0.5">
          <div className="flex min-w-0 flex-wrap items-start justify-between gap-x-2 gap-y-1">
            <h2 className="min-w-0 text-section font-semibold text-fg [overflow-wrap:anywhere]">{title}</h2>
            {status ? <span className="mt-0.5 shrink-0">{status}</span> : null}
          </div>
          {description ? <div className="text-caption text-fg-secondary">{description}</div> : null}
          {id ? (
            <div className="flex min-w-0 items-center gap-1 text-caption">
              <span className="machine truncate text-fg-tertiary" title={id}>
                {id}
              </span>
              <CopyButton value={id} label={idLabel} />
            </div>
          ) : null}
        </div>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-1.5">{actions}</div> : null}
    </div>
  );
}

/**
 * A collapsible property section (APG accordion: a button inside h3 with aria-expanded). The body opens with
 * grid-template-rows 0fr → 1fr on the smooth spring and the chevron turns on snappy; a collapsed body is inert at once,
 * never after the animation. Controllable (open / onOpenChange) for "jump to the field with the problem".
 */
export function PropertySection({
  title,
  icon,
  count,
  defaultOpen = true,
  open: controlledOpen,
  onOpenChange,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title: ReactNode;
  icon?: ReactNode | undefined;
  count?: number | null | undefined;
  defaultOpen?: boolean | undefined;
  open?: boolean | undefined;
  onOpenChange?: ((open: boolean) => void) | undefined;
  actions?: ReactNode | undefined;
  children: ReactNode;
  className?: string | undefined;
  bodyClassName?: string | undefined;
}) {
  const [localOpen, setLocalOpen] = useState(defaultOpen);
  const open = controlledOpen ?? localOpen;
  const setOpen = (next: boolean) => {
    setLocalOpen(next);
    onOpenChange?.(next);
  };
  const bodyId = useId();
  return (
    <section className={cn("border-b border-line-subtle last:border-b-0", className)}>
      <div className="flex h-9 items-center gap-1 px-2">
        <h3 className="min-w-0 flex-1">
          <button
            type="button"
            aria-expanded={open}
            aria-controls={bodyId}
            onClick={() => {
              setOpen(!open);
            }}
            className="flex h-7 w-full min-w-0 items-center gap-1.5 rounded-md px-1.5 text-left text-data font-semibold text-fg hover:bg-raised active:bg-sunken [&_svg]:shrink-0"
          >
            <ChevronDown
              aria-hidden
              className={cn(
                "size-3.5 text-fg-tertiary transition-[rotate] duration-(--duration-spring-snappy) ease-(--ease-spring-snappy)",
                !open && "-rotate-90",
              )}
            />
            {icon ? <span className="flex text-fg-tertiary [&_svg]:size-3.5">{icon}</span> : null}
            <span className="truncate">{title}</span>
            {count !== undefined && count !== null ? (
              <span className="machine text-caption font-normal text-fg-tertiary">{count}</span>
            ) : null}
          </button>
        </h3>
        {actions ? <div className="flex shrink-0 items-center gap-0.5">{actions}</div> : null}
      </div>
      <div
        id={bodyId}
        inert={!open || undefined}
        className={cn(
          "grid transition-[grid-template-rows] duration-(--duration-spring-smooth) ease-(--ease-spring-smooth)",
          open ? "grid-rows-[1fr]" : "grid-rows-[0fr]",
        )}
      >
        <div className="min-h-0 overflow-hidden">
          <div className={cn("px-4 pb-3.5", bodyClassName)}>{children}</div>
        </div>
      </div>
    </section>
  );
}

/**
 * A link in a PropertySection's header (e.g. "歷史數據" to the metrics of this object): quiet, 28 px, in the action
 * colour. Navigation, not an action of the object, so it is not part of the action model; a page change transitions.
 */
export function SectionLink({
  to,
  icon,
  children,
}: {
  to: string;
  icon?: LucideIcon | undefined;
  children: ReactNode;
}) {
  return (
    <ButtonLink
      to={to}
      variant="quiet"
      size="sm"
      icon={icon}
      className="min-h-7 gap-1 px-2 text-caption text-action-fg hover:text-action-fg"
    >
      {children}
    </ButtonLink>
  );
}

/** Label / value grid of properties (the label column is 104–120 px; 120–144 px for the longer Japanese labels). */
export function PropertyGrid({ children, className }: { children: ReactNode; className?: string | undefined }) {
  return (
    <div
      className={cn(
        "grid grid-cols-[minmax(6.5rem,7.5rem)_minmax(0,1fr)] items-start gap-x-3 gap-y-1",
        "[&:lang(ja)]:grid-cols-[minmax(7.5rem,9rem)_minmax(0,1fr)]",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** A property row: a control is linked with htmlFor; a plain value needs none. full = the value spans both columns. */
export function PropertyRow({
  label,
  htmlFor,
  hint,
  children,
  full = false,
  mono = false,
}: {
  label: ReactNode;
  htmlFor?: string | undefined;
  hint?: ReactNode | undefined;
  children: ReactNode;
  full?: boolean | undefined;
  mono?: boolean | undefined;
}) {
  // A value with a source line under it is taller than its label: both then align on their first line.
  return (
    <>
      <div
        className={cn(
          "flex min-h-8 text-data text-fg-tertiary",
          hint ? "items-start py-1.5" : "items-center",
          full && "col-span-2 min-h-6",
        )}
      >
        {htmlFor ? <label htmlFor={htmlFor}>{label}</label> : <span>{label}</span>}
      </div>
      <div
        className={cn(
          "flex min-h-8 min-w-0 flex-col items-start gap-0.5 text-data text-fg [overflow-wrap:anywhere]",
          hint ? "justify-start py-1.5" : "justify-center",
          mono && "machine",
          full && "col-span-2",
        )}
      >
        {children}
        {hint ? <span className="font-sans text-caption text-fg-tertiary">{hint}</span> : null}
      </div>
    </>
  );
}

/** The action bar fixed to the inspector's bottom: the primary and secondary actions and a one-line status. */
export function InspectorFooter({
  children,
  note,
  className,
}: {
  children: ReactNode;
  note?: ReactNode | undefined;
  className?: string | undefined;
}) {
  return (
    <div className={cn("grid shrink-0 gap-1.5 border-t border-line-subtle bg-surface px-4 py-2.5", className)}>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
      {note ? <div className="text-caption text-fg-tertiary">{note}</div> : null}
    </div>
  );
}

/**
 * The inspector's frame: the EntityHeader on top and the InspectorFooter at the bottom stay in place, the sections in
 * between are the only scroll owner. It fills the inspector column or sheet. On very short windows (200 % zoom) the
 * whole frame scrolls instead, so the sections never shrink to a sliver between the two bars.
 *
 * `tabbed`: the children are one `InspectorTabs`; its tab list stays under the header and each tab's panel is the
 * scroll owner instead (on very short windows the whole frame still scrolls, the tab list with it).
 */
export function InspectorFrame({
  header,
  footer,
  children,
  className,
  tabbed = false,
}: {
  header: ReactNode;
  footer?: ReactNode | undefined;
  children: ReactNode;
  className?: string | undefined;
  tabbed?: boolean | undefined;
}) {
  return (
    <div
      className={cn(
        "flex h-full min-h-0 flex-1 flex-col [@media(max-height:35rem)]:block [@media(max-height:35rem)]:overflow-y-auto",
        className,
      )}
    >
      {header}
      <div
        className={cn(
          "relative min-h-0 flex-1 [@media(max-height:35rem)]:overflow-visible",
          tabbed ? "flex flex-col [@media(max-height:35rem)]:block" : "overflow-y-auto",
        )}
      >
        {children}
      </div>
      {footer}
    </div>
  );
}

/**
 * The views of one object in its inspector or editor (inside a `tabbed` InspectorFrame): compact tabs under the
 * header, each panel its own scroll owner. The value lives in the URL (`useTabParam("tab", …)`), so a reload, Back and
 * a shared link keep the view, and selecting another object of the list keeps the same tab where it has it.
 */
export function InspectorTabs<V extends string>({
  label,
  value,
  onChange,
  items,
  children,
}: {
  label: string;
  value: V;
  onChange: (value: V) => void;
  items: TabItem<V>[];
  children: ReactNode;
}) {
  return (
    <Tabs
      size="compact"
      label={label}
      value={value}
      onChange={onChange}
      items={items}
      className="[@media(max-height:35rem)]:block"
    >
      {children}
    </Tabs>
  );
}

/**
 * One view of an inspector's tabs: its conclusion callouts first (`lead`, padded like the frame's top block), then its
 * sections. Short windows let the frame scroll instead of the panel.
 */
export function InspectorTab({
  value,
  lead,
  children,
}: {
  value: string;
  lead?: ReactNode | undefined;
  children: ReactNode;
}) {
  return (
    <TabPanel value={value} className="[@media(max-height:35rem)]:overflow-visible">
      {lead ? <div className="grid grid-cols-1 gap-2.5 border-b border-line-subtle px-4 py-3.5">{lead}</div> : null}
      {children}
    </TabPanel>
  );
}
