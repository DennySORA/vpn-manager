// Adapted from Phasyn Studio (Apache-2.0): the page header (icon tile, title, one-line description with its (?) help,
// actions), the collection tool strip, list rows and the side panels. Page content rises in with a CSS stagger
// (header, then the list, then the inspector), once, when the page opens; selection and polling never replay it. The
// inspector and the editor pane swap their content with Motion: keyed by the shown object (swapKey), the new content
// slides in from the right edge (panelVariants) while the old one pops out and fades; nothing plays on the first load.
// At ≥1280 px the inspector column collapses to a 44 px rail (remembered in this browser); selecting an object opens it.
import type { LucideIcon } from "lucide-react";
import { ChevronLeft, PanelRightClose, PanelRightOpen, Search, X } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { createContext, type ReactNode, type Ref, useContext, useEffect, useId, useRef, useState } from "react";
import { Link, useLocation, useParams } from "react-router";
import { ActiveIndicator } from "@/components/ui/active-indicator";
import { ButtonLink } from "@/components/ui/button";
import { ChangeValue } from "@/components/ui/change-value";
import { Sheet } from "@/components/ui/dialog";
import { HelpButton, HelpText } from "@/components/ui/help-tip";
import { LIST_ROW, LIST_ROW_IDLE, LIST_ROW_SELECTED, ROW_SELECTED, STAGGER_IN } from "@/components/ui/look";
import { staggerStyle, swapKey, usePanelToggleFocus, usePresenceInert } from "@/components/ui/motion";
import { panelVariants } from "@/components/ui/motion-tokens";
import { Tip } from "@/components/ui/tooltip";
import { cn } from "@/lib/cn";
import { useMedia, useWideLayout } from "@/lib/use-media";
import { usePersistentFlag } from "@/lib/use-persistent";
import { sectionFor } from "./nav";
import { consumeRouteFocus } from "./route-focus";
import { m } from "./messages";

/** A view fills the main area; only its inner regions scroll. */
export function Page({ children }: { children: ReactNode }) {
  return <div className="flex h-full min-h-0 flex-col">{children}</div>;
}

/**
 * The page header: an icon tile (the page's navigation icon unless given), the 20 px title, a one-line description,
 * and the page's primary actions on the right. Details go into `help`: a (?) button after the description shows them
 * below it (and as its tooltip when `helpText` is given) instead of a long paragraph here. After a page change, focus
 * moves to the title (polling and selection never move it). It is the first item of the page's entrance stagger.
 */
export function PageHeader({
  title,
  description,
  help,
  helpText,
  actions,
  icon,
  meta,
}: {
  title: string;
  description?: ReactNode | undefined;
  /** The details behind the one-line description (shown by the (?) button). */
  help?: ReactNode | undefined;
  /** The same details as plain text for the (?) button's tooltip. */
  helpText?: string | undefined;
  actions?: ReactNode | undefined;
  /** Defaults to the current navigation section's icon. */
  icon?: LucideIcon | null | undefined;
  /** A line of status chips under the description. */
  meta?: ReactNode | undefined;
}) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  const helpId = useId();
  const [helpOpen, setHelpOpen] = useState(false);
  const { pathname } = useLocation();
  const Icon = icon === null ? null : (icon ?? sectionFor(pathname)?.icon ?? null);
  useEffect(() => {
    if (consumeRouteFocus()) headingRef.current?.focus({ preventScroll: true });
  }, [pathname]);
  return (
    <header
      style={staggerStyle(0)}
      className={cn(
        "flex shrink-0 flex-wrap items-center justify-between gap-x-6 gap-y-3 px-4 pt-5 pb-4 md:px-6",
        STAGGER_IN,
      )}
    >
      <div className="flex min-w-0 flex-1 basis-80 items-center gap-3">
        {Icon ? (
          <span
            aria-hidden
            className="grid size-9 shrink-0 place-items-center rounded-lg border border-action/25 bg-brand-gradient-soft text-brand-cyan shadow-edge [&_svg]:size-[18px]"
          >
            <Icon />
          </span>
        ) : null}
        <div className="grid min-w-0 gap-0.5">
          <h1
            ref={headingRef}
            id="page-title"
            tabIndex={-1}
            className="text-page font-semibold text-fg outline-none [overflow-wrap:anywhere] focus-visible:outline-2"
          >
            {title}
          </h1>
          {description || help ? (
            <div className="flex min-w-0 max-w-[80ch] items-start gap-1 text-data text-fg-secondary">
              {description ? <div className="min-w-0">{description}</div> : null}
              {help ? (
                <HelpButton
                  open={helpOpen}
                  onToggle={() => {
                    setHelpOpen((o) => !o);
                  }}
                  controls={helpId}
                  label={title}
                  text={helpText}
                  className="-my-0.5"
                />
              ) : null}
            </div>
          ) : null}
          {help ? (
            <HelpText id={helpId} open={helpOpen} className="max-w-[80ch] text-data text-fg-tertiary">
              {help}
            </HelpText>
          ) : null}
          {meta ? <div className="mt-1 flex flex-wrap items-center gap-2">{meta}</div> : null}
        </div>
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}

/**
 * Search / filters / count above a collection, and the collection's batch actions (put them last, after the count).
 * With a `label` it is a named group.
 */
export function Toolbar({ children, label }: { children: ReactNode; label?: string | undefined }) {
  return (
    <div
      role={label ? "group" : undefined}
      aria-label={label}
      className="flex min-h-12 shrink-0 flex-wrap items-center gap-x-2.5 gap-y-2 border-b border-line-subtle px-3 py-2"
    >
      {children}
    </div>
  );
}

export function SearchInput({
  value,
  onChange,
  label,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  label: string;
  placeholder: string;
}) {
  // The value usually lives in the URL, and router updates render in a transition — after the
  // next keystroke may already have arrived. Show what was typed until the value catches up (or
  // the field loses focus), so no keystroke is lost; then follow the value again.
  const [typed, setTyped] = useState<string | null>(null);
  if (typed !== null && typed === value) setTyped(null);
  const shown = typed ?? value;
  const change = (v: string) => {
    setTyped(v);
    onChange(v);
  };
  return (
    <div className="group/search relative w-64 min-w-40">
      <Search
        aria-hidden
        className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-fg-tertiary transition-colors duration-(--duration-fast) group-focus-within/search:text-brand-cyan"
      />
      <input
        type="search"
        name="q"
        value={shown}
        onChange={(e) => {
          change(e.target.value);
        }}
        onBlur={() => {
          setTyped(null);
        }}
        aria-label={label}
        placeholder={placeholder}
        spellCheck={false}
        autoComplete="off"
        className="h-8 w-full rounded-md border border-line-control/70 bg-sunken pr-7 pl-8 text-data text-ellipsis text-fg transition-[border-color,box-shadow] duration-(--duration-fast) placeholder:text-fg-tertiary hover:border-fg-tertiary focus-visible:outline-offset-0 focus-visible:shadow-[0_0_0_4px_rgb(79_123_255_/_0.18)] [&::-webkit-search-cancel-button]:hidden"
      />
      {shown ? (
        <button
          type="button"
          aria-label={m.clearSearch}
          onClick={() => {
            change("");
          }}
          className="pressable absolute top-1/2 right-1 inline-flex size-6 -translate-y-1/2 items-center justify-center rounded-md text-fg-tertiary hover:bg-raised hover:text-fg"
        >
          <X aria-hidden className="size-3.5" />
        </button>
      ) : null}
    </div>
  );
}

/**
 * "N 條連線" / "顯示 n／N 條連線" after the filters (it carries ml-auto: the list's batch actions follow it on the
 * right). The numbers fade briefly when they change.
 */
export function Count({ shown, total, unit }: { shown: number; total: number; unit: string }) {
  return (
    <span className="ml-auto whitespace-nowrap text-caption text-fg-tertiary" aria-live="polite">
      {shown === total ? (
        <>
          <ChangeValue value={total} className="machine" /> {unit}
        </>
      ) : (
        <>
          {m.showingLead}
          <ChangeValue value={m.shownOfTotal(shown, total)} className="machine" /> {unit}
          {m.showingTrail}
        </>
      )}
    </span>
  );
}

/**
 * Content that slides in from the right edge when its identity changes (another object, loading → content): keyed by
 * `swapKey`, inside AnimatePresence with `initial={false}`, so the first render shows it at once. The old copy pops out
 * of the layout, inert, and fades.
 */
export function PaneSwap({ children, className }: { children: ReactNode; className: string }) {
  return (
    <AnimatePresence initial={false} mode="popLayout">
      <PaneCopy key={swapKey(children)} className={className}>
        {children}
      </PaneCopy>
    </AnimatePresence>
  );
}

function PaneCopy({
  children,
  className,
  ref,
}: {
  children: ReactNode;
  className: string;
  ref?: Ref<HTMLDivElement> | undefined;
}) {
  const { props } = usePresenceInert();
  return (
    <motion.div
      ref={ref}
      {...props}
      variants={panelVariants("right")}
      initial="hidden"
      animate="shown"
      exit="gone"
      className={className}
    >
      {children}
    </motion.div>
  );
}

const PANEL_TOGGLE_LOOK =
  "pressable inline-flex size-7 shrink-0 items-center justify-center rounded-md text-fg-tertiary hover:bg-raised hover:text-fg active:bg-sunken [&_svg]:size-4";

/** The collapsed inspector: a 44 px rail holding the toggle that opens it again. */
function InspectorRail({
  title,
  onExpand,
  ref,
}: {
  title: string;
  onExpand: () => void;
  ref?: Ref<HTMLDivElement> | undefined;
}) {
  const { props } = usePresenceInert();
  return (
    <motion.div
      ref={ref}
      {...props}
      variants={panelVariants("right")}
      initial="hidden"
      animate="shown"
      exit="gone"
      className="panel-raised flex h-full w-11 flex-col items-center py-2"
    >
      <Tip content={m.expandDetailsOf(title)} side="left">
        <button
          type="button"
          data-panel-toggle=""
          aria-expanded={false}
          aria-label={m.expandDetails}
          onClick={onExpand}
          className={PANEL_TOGGLE_LOOK}
        >
          <PanelRightOpen aria-hidden />
        </button>
      </Tip>
    </motion.div>
  );
}

/** The open inspector column: its content swaps by object; the collapse toggle sits on its left edge, over the gap. */
function InspectorColumn({
  id,
  title,
  empty,
  onCollapse,
  children,
  ref,
}: {
  id: string;
  title: string;
  /** Nothing is selected: the column is narrow and shows the placeholder. */
  empty: boolean;
  onCollapse: () => void;
  children: ReactNode;
  ref?: Ref<HTMLDivElement> | undefined;
}) {
  const { props } = usePresenceInert();
  return (
    <motion.div
      ref={ref}
      {...props}
      variants={panelVariants("right")}
      initial="hidden"
      animate="shown"
      exit="gone"
      className={cn("relative flex h-full min-h-0", empty ? "w-[260px]" : "w-[340px] 2xl:w-[400px]")}
    >
      <aside
        id={id}
        aria-label={title}
        className="panel-raised relative flex min-h-0 min-w-0 flex-1 flex-col overflow-y-auto"
      >
        <PaneSwap className="flex min-h-0 flex-1 flex-col">{children}</PaneSwap>
      </aside>
      <button
        type="button"
        data-panel-toggle=""
        aria-expanded
        aria-controls={id}
        aria-label={m.collapseDetails}
        title={m.collapseDetails}
        onClick={onCollapse}
        className="pressable absolute top-3.5 -left-3 z-[3] inline-flex size-6 items-center justify-center rounded-full border border-line bg-raised text-fg-tertiary shadow-edge hover:bg-overlay hover:text-fg active:bg-sunken [&_svg]:size-3.5"
      >
        <PanelRightClose aria-hidden />
      </button>
    </motion.div>
  );
}

/**
 * Collection + inspector. At ≥1280px the inspector is a column beside the list (always present, so the list never
 * jumps): narrow with a compact placeholder while nothing is selected, and its content slides in from the right edge
 * when it shows another object. Its left-edge toggle collapses it to a 44 px rail (the list takes the freed space at
 * once; remembered in this browser for every page); selecting another object opens it again, and focus moves to the
 * toggle that remains. Below 1280px it opens as a side sheet while something is selected. An inspector that fills the
 * column (InspectorFrame: fixed header and footer, scrolling body) takes its full height; any other content scrolls in
 * the column. The list and the inspector rise in after the page header.
 */
export function SplitView({
  list,
  inspector,
  inspectorTitle,
  onCloseInspector,
  placeholder,
}: {
  list: ReactNode;
  inspector: ReactNode | null;
  inspectorTitle: string;
  onCloseInspector: () => void;
  placeholder: ReactNode;
}) {
  const wide = useWideLayout();
  const inspectorId = useId();
  const [collapsed, setCollapsed] = usePersistentFlag("shell.inspector.collapsed", false);
  // Selecting another object opens a collapsed inspector with it (the remembered preference stays as it was).
  const selection = inspector === null ? null : swapKey(inspector);
  const [seen, setSeen] = useState(selection);
  const [opened, setOpened] = useState(false);
  if (selection !== seen) {
    setSeen(selection);
    setOpened(selection !== null);
  }
  const open = !collapsed || opened;
  const column = useRef<HTMLDivElement>(null);
  const noteToggle = usePanelToggleFocus(column, open);
  const toggle = (next: boolean) => {
    noteToggle();
    setOpened(false);
    setCollapsed(!next);
  };
  return (
    <div className="flex min-h-0 flex-1 gap-4 px-4 pb-4 md:px-6 md:pb-6">
      <section
        aria-label={m.list}
        style={staggerStyle(1)}
        className={cn("panel flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden", STAGGER_IN)}
      >
        {list}
      </section>
      {wide ? (
        // The width changes at once; only the content of the side that appears slides in from the right edge.
        <div ref={column} style={staggerStyle(2)} className={cn("relative flex min-h-0 shrink-0", STAGGER_IN)}>
          <AnimatePresence initial={false} mode="popLayout">
            {open ? (
              <InspectorColumn
                key="column"
                id={inspectorId}
                title={inspectorTitle}
                empty={inspector === null}
                onCollapse={() => {
                  toggle(false);
                }}
              >
                {inspector ?? placeholder}
              </InspectorColumn>
            ) : (
              <InspectorRail
                key="rail"
                title={inspectorTitle}
                onExpand={() => {
                  toggle(true);
                }}
              />
            )}
          </AnimatePresence>
        </div>
      ) : (
        <Sheet
          open={Boolean(inspector)}
          onOpenChange={(o) => {
            if (!o) onCloseInspector();
          }}
          title={inspectorTitle}
        >
          {inspector}
        </Sheet>
      )}
    </div>
  );
}

/** Below md (840 px) a MasterDetail shows one pane at a time (the same breakpoint as the `max-md:` utilities). */
const STACKED_QUERY = "(width < 52.5rem)";

/**
 * A short list beside a wide editor (DNS, security profiles, IP blocklists, SSH hosts, provider accounts). Each side owns
 * its scroll; the list and then the editor rise in after the page header, and the editor slides in when it shows another
 * object. An editor that fills the pane (InspectorFrame) takes its full height; other content scrolls in the pane.
 *
 * Below md (840 px) the two never squeeze side by side: one pane shows at a time. With an object selected (`selected`,
 * by default "the route has an :id") it is the editor, under a back control to `backTo` (default: the path without its
 * last segment); otherwise the list, and the editor is not rendered at all (so an editor that opens the only object by
 * itself does not take the list away). Switching panes is navigation: an editor with unsaved changes still asks first
 * (UnsavedGuard), the pane that appears slides in, and focus moves into it when the pane it was in went away — back on the
 * list, to the item that was open.
 */
export function MasterDetail({
  list,
  detail,
  listLabel,
  detailLabel = m.edit,
  selected,
  backTo,
  backLabel = m.backToList,
}: {
  list: ReactNode;
  detail: ReactNode;
  listLabel: string;
  /** The editor pane's accessible name. */
  detailLabel?: string | undefined;
  /** An object is selected: below md the editor shows instead of the list. Defaults to the route's `:id`. */
  selected?: boolean | undefined;
  /** Where the back control above the editor goes below md. */
  backTo?: string | undefined;
  backLabel?: string | undefined;
}) {
  const params = useParams();
  const location = useLocation();
  const stacked = useMedia(STACKED_QUERY);
  const detailLeads = selected ?? Boolean(params.id);
  const back = backTo ?? (location.pathname.replace(/\/[^/]+\/?$/, "") || "/");
  const listPane = useRef<HTMLElement>(null);
  const detailPane = useRef<HTMLElement>(null);
  const showing: "both" | "list" | "detail" = stacked ? (detailLeads ? "detail" : "list") : "both";

  // The object the editor showed last, so returning to the list can focus its item.
  const here = `${location.pathname}${location.search}`;
  const opened = useRef<string | null>(null);
  useEffect(() => {
    if (detailLeads) opened.current = here;
  }, [detailLeads, here]);
  const previous = useRef(showing);
  useEffect(() => {
    if (previous.current === showing) return;
    const was = previous.current;
    previous.current = showing;
    if (showing === "both" || was === "both") return;
    // Only when the pane that held focus went away (focus fell to the page), never when the user already moved on.
    const active = document.activeElement;
    const target = showing === "detail" ? detailPane.current : listPane.current;
    if (!target || (active && active !== document.body && target.contains(active))) return;
    if (
      active &&
      active !== document.body &&
      !(showing === "detail" ? listPane.current : detailPane.current)?.contains(active)
    )
      return;
    const item =
      showing === "list" && opened.current
        ? target.querySelector<HTMLElement>(`a[href="${CSS.escape(opened.current)}"]`)
        : null;
    (item ?? target).focus({ preventScroll: !item });
  }, [showing]);

  return (
    <div className="flex min-h-0 flex-1 gap-4 px-4 pb-4 md:px-6 md:pb-6">
      <section
        ref={listPane}
        aria-label={listLabel}
        tabIndex={-1}
        style={staggerStyle(1)}
        className={cn(
          "panel flex min-h-0 flex-col overflow-hidden outline-none",
          STAGGER_IN,
          showing === "both" ? "w-[240px] shrink-0 lg:w-[300px]" : showing === "list" ? "min-w-0 flex-1" : "hidden",
        )}
      >
        {list}
      </section>
      <section
        ref={detailPane}
        aria-label={detailLabel}
        tabIndex={-1}
        style={staggerStyle(2)}
        className={cn(
          "panel-raised flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden outline-none",
          STAGGER_IN,
          showing === "list" && "hidden",
        )}
      >
        {showing === "detail" ? (
          <div className="flex h-11 shrink-0 items-center border-b border-line-subtle px-2">
            <ButtonLink to={back} variant="quiet" size="sm" icon={ChevronLeft} className="-ml-0.5 gap-1 px-2">
              {backLabel}
            </ButtonLink>
          </div>
        ) : null}
        <div className="relative min-h-0 flex-1 overflow-y-auto">
          <PaneSwap className="h-full">{showing === "list" ? null : detail}</PaneSwap>
        </div>
      </section>
    </div>
  );
}

/** Inside a MasterList, the list's one sliding marker shows the current item (the items draw none of their own). */
const ListMarkerContext = createContext(false);

/**
 * The list of a MasterDetail: a named navigation and its own scroll owner (groups and their headings, PresenceLists of
 * ListItems). One 3 px brand marker slides to the current item on the snappy spring — placed without motion the first
 * time, hidden while nothing is current, Highlight in forced colours.
 */
export function MasterList({
  label,
  children,
  className,
}: {
  label: string;
  children: ReactNode;
  className?: string | undefined;
}) {
  const container = useRef<HTMLDivElement>(null);
  return (
    <nav aria-label={label} className="min-h-0 flex-1 overflow-y-auto">
      <div ref={container} className={cn("relative grid grid-cols-1 content-start gap-0.5 p-2", className)}>
        <ListMarkerContext.Provider value>{children}</ListMarkerContext.Provider>
        <ActiveIndicator
          container={container}
          edge="left"
          selector='[aria-current="page"]'
          inset={6}
          className="left-2 w-[3px]"
        />
      </div>
    </nav>
  );
}

/** A group heading inside a MasterList (e.g. "VPN Manager 管理", "~/.ssh/config（唯讀）"). */
export function MasterListHeading({ children, id }: { children: ReactNode; id?: string | undefined }) {
  return (
    <p id={id} className="px-3 pt-2 pb-1 text-caption font-medium text-fg-tertiary first:pt-1">
      {children}
    </p>
  );
}

/**
 * One entry of a MasterDetail list: hover tints, press darkens, the current one has the soft brand fill (and, outside a
 * MasterList, its own 3 px gradient marker). `actions` are the object's row actions — its ⋯ menu, the same as the
 * editor's, and at most one quick action — placed beside the link, never inside it.
 */
export function ListItem({
  to,
  selected,
  title,
  meta,
  actions,
}: {
  to: string;
  selected: boolean;
  title: string;
  meta?: ReactNode | undefined;
  actions?: ReactNode | undefined;
}) {
  const sliding = useContext(ListMarkerContext);
  const look = selected ? (sliding ? ROW_SELECTED : LIST_ROW_SELECTED) : LIST_ROW_IDLE;
  const body = (
    <>
      <span className="block text-data font-medium text-fg [overflow-wrap:anywhere]">{title}</span>
      {meta ? <span className="block text-caption text-fg-tertiary [overflow-wrap:anywhere]">{meta}</span> : null}
    </>
  );
  if (!actions) {
    return (
      <Link
        to={to}
        aria-current={selected ? "page" : undefined}
        className={cn(LIST_ROW, "block rounded-lg px-3 py-2.5 no-underline", look)}
      >
        {body}
      </Link>
    );
  }
  // The row (fill, marker) holds the link and the actions side by side: a button never sits inside a link.
  return (
    <div className={cn(LIST_ROW, "flex items-start rounded-lg", look)}>
      <Link
        to={to}
        aria-current={selected ? "page" : undefined}
        className="block min-w-0 flex-1 rounded-lg py-2.5 pr-1 pl-3 no-underline"
      >
        {body}
      </Link>
      <div className="flex shrink-0 items-center pt-1.5 pr-1.5">{actions}</div>
    </div>
  );
}
