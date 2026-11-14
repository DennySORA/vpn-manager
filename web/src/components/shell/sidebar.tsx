// Adapted from Phasyn Studio (Apache-2.0).
// The glass sidebar (material-sidebar): the brand header, the navigation (總覽, then its groups), and the footer with
// the service state and the collapse control. 232 px wide, or a 64 px icon rail whose names appear as tips; below 840 px
// it is the left drawer. Each group's heading is a toggle that collapses it (remembered by this browser): its entries
// fold away on the smooth spring and leave the Tab order, except the current page's, which stays — the page you are on
// is never hidden. The rail shows every entry (its groups are dividers). The current page is a soft brand-gradient item
// with a gradient-stroked icon, and one 3 px brand marker on the left edge slides between items on the snappy spring.
import { ChevronRight, PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { memo, type ReactNode, useId, useRef } from "react";
import { Link, useLocation } from "react-router";
import { useGateways, useInstancesSelect, useProfiles, useSystemStatus } from "@/api/queries";
import type { InstanceView } from "@/api/types";
import { ActiveIndicator } from "@/components/ui/active-indicator";
import { Dot } from "@/components/ui/badge";
import { Tip } from "@/components/ui/tooltip";
import { cn } from "@/lib/cn";
import { usePersistentFlag } from "@/lib/use-persistent";
import { LogoMark } from "./logo";
import { NAV_GROUPS, type NavGroup, type NavItem, sectionFor } from "./nav";
import { useServiceState } from "./service";
import { m } from "./messages";

/** The brand header: VPN Manager's mark with its glow and name; only the mark when collapsed. Leads to the overview. */
function SidebarBrand({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: (() => void) | undefined }) {
  return (
    <div className="relative flex h-16 shrink-0 items-center overflow-hidden px-3">
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(90%_120%_at_20%_-20%,rgb(62_137_255_/_0.2),transparent_70%)]"
      />
      <Link
        to="/"
        onClick={onNavigate}
        aria-label={m.brandLink}
        className={cn(
          "pressable relative flex min-w-0 items-center gap-2.5 rounded-lg py-1.5 text-fg no-underline",
          collapsed ? "mx-auto justify-center px-1" : "px-1.5",
        )}
      >
        <LogoMark size={collapsed ? 30 : 28} glow />
        {collapsed ? null : (
          <span className="truncate text-section font-semibold tracking-tight text-fg animate-fade-in">
            VPN Manager
          </span>
        )}
      </Link>
    </div>
  );
}

/**
 * One navigation entry; memoized, so a route change or a count re-renders only the entries it touches. `shown`: false
 * folds it away (its group is collapsed): the row closes on the smooth spring, inert and hidden from assistive
 * technology at once.
 */
const NavLink = memo(function NavLink({
  item,
  count,
  collapsed,
  active,
  shown,
  onNavigate,
}: {
  item: NavItem;
  count?: ReactNode | undefined;
  collapsed: boolean;
  active: boolean;
  shown: boolean;
  onNavigate?: (() => void) | undefined;
}) {
  const Icon = item.icon;
  const link = (
    <Link
      to={item.to}
      onClick={onNavigate}
      aria-current={active ? "page" : undefined}
      title={collapsed ? undefined : item.hint}
      className={cn(
        "pressable group/nav relative flex h-9 items-center rounded-lg border text-data no-underline",
        collapsed ? "mx-auto w-10 justify-center" : "gap-3 px-3",
        active
          ? "border-action/25 bg-brand-gradient-soft font-medium text-fg shadow-[inset_0_1px_0_rgb(255_255_255_/_0.05)]"
          : "border-transparent text-fg-secondary hover:bg-raised/80 hover:text-fg forced-colors:border-[Canvas]",
      )}
    >
      {/* The current item's icon is stroked with the shell's shared brand gradient (falls back to brand cyan). */}
      <Icon
        aria-hidden
        className={cn(
          "size-[18px] shrink-0 transition-colors duration-(--duration-fast)",
          active
            ? "text-brand-cyan [stroke:url(#vpnm-brand-gradient)_var(--color-brand-cyan)]"
            : "text-fg-tertiary group-hover/nav:text-fg-secondary",
        )}
      />
      <span className={collapsed ? "sr-only" : "min-w-0 flex-1 truncate animate-fade-in"}>{item.label}</span>
      {!collapsed && count !== undefined ? (
        <span className="machine shrink-0 text-micro text-fg-tertiary">{count}</span>
      ) : null}
    </Link>
  );
  return (
    <li
      inert={!shown || undefined}
      aria-hidden={shown ? undefined : true}
      className={cn(
        "grid transition-[grid-template-rows,opacity] duration-(--duration-spring-smooth) ease-(--ease-spring-smooth)",
        shown ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0",
      )}
    >
      {/* The clip keeps a folding row inside its shrinking box; the padding is the gap to the next row. */}
      <div className="min-h-0 overflow-hidden pb-0.5">
        {collapsed ? (
          <Tip content={item.label} side="right">
            {link}
          </Tip>
        ) : (
          link
        )}
      </div>
    </li>
  );
});

function readyCount(views: InstanceView[]): string {
  return `${views.filter((v) => v.status?.phase === "ready").length}/${views.length}`;
}

/**
 * One group of the navigation. Its heading toggles it (aria-expanded; remembered as `vpnm.flag.sidebar.group.<id>`);
 * collapsed, only the current page's entry stays and the heading counts the folded ones. The rail (`collapsed`) has
 * no headings: a divider before every group but the first, and every entry.
 */
function NavSection({
  group,
  first,
  collapsed,
  current,
  counts,
  onNavigate,
}: {
  group: NavGroup;
  first: boolean;
  collapsed: boolean;
  current: string | undefined;
  counts: Record<string, ReactNode>;
  onNavigate?: (() => void) | undefined;
}) {
  const [folded, setFolded] = usePersistentFlag(`sidebar.group.${group.id}`, false);
  const listId = useId();
  const label = group.label;
  const closed = folded && label !== null && !collapsed;
  const shown = (item: NavItem) => !closed || item.to === current;
  const hidden = group.items.filter((item) => !shown(item)).length;
  return (
    <div className="grid">
      {collapsed ? (
        first ? null : (
          <div aria-hidden className="mx-2 my-1.5 h-px bg-line-subtle forced-colors:bg-[GrayText]" />
        )
      ) : label === null ? null : (
        <button
          type="button"
          aria-expanded={!closed}
          aria-controls={listId}
          title={
            closed
              ? m.expandGroup(label)
              : group.items.some((item) => item.to === current)
                ? m.collapseGroupKeepsCurrent(label)
                : m.collapseGroup(label)
          }
          onClick={() => {
            setFolded(!folded);
          }}
          className={cn(
            "pressable group/section mb-0.5 flex h-6 items-center gap-1.5 rounded-md px-3 text-left text-caption font-medium text-fg-tertiary outline-none hover:bg-raised/60 hover:text-fg-secondary focus-visible:ring-2 focus-visible:ring-focus",
            first ? "mt-0.5" : "mt-1",
          )}
        >
          <ChevronRight
            aria-hidden
            className={cn(
              "size-3.5 shrink-0 transition-[rotate] duration-(--duration-spring-snappy) ease-(--ease-spring-snappy)",
              closed ? "rotate-0" : "rotate-90",
            )}
          />
          <span className="min-w-0 flex-1 truncate">{label}</span>
          {closed && hidden ? (
            <>
              <span className="sr-only">{m.hiddenItems(hidden)}</span>
              <span aria-hidden className="machine shrink-0 text-micro text-fg-tertiary animate-fade-in">
                {hidden}
              </span>
            </>
          ) : null}
        </button>
      )}
      <ul id={listId} aria-label={label ?? m.nav.overview.label} className="grid">
        {group.items.map((item) => (
          <NavLink
            key={item.to}
            item={item}
            count={counts[item.to]}
            collapsed={collapsed}
            active={item.to === current}
            shown={shown(item)}
            onNavigate={onNavigate}
          />
        ))}
      </ul>
    </div>
  );
}

/** The navigation (sidebar and drawer): 總覽 and the collapsible groups; in the rail, the groups become dividers. */
function SidebarNav({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: (() => void) | undefined }) {
  const { pathname } = useLocation();
  const current = sectionFor(pathname)?.to;
  const listRef = useRef<HTMLDivElement>(null);
  // Only the counts: the navigation re-renders when a count changes, not on every status event.
  const instanceCount = useInstancesSelect(readyCount).data;
  const profiles = useProfiles();
  const gateways = useGateways();
  const counts: Record<string, ReactNode> = {
    "/instances": instanceCount,
    "/profiles": profiles.data?.length,
    "/gateways": gateways.data?.length,
  };
  return (
    <nav aria-label={m.mainNavigation} className="min-h-0 flex-1 overflow-x-hidden overflow-y-auto py-1">
      <div ref={listRef} className="relative grid px-3 pt-1 pb-2">
        {NAV_GROUPS.map((g, i) => (
          <NavSection
            key={g.id}
            group={g}
            first={i === 0}
            collapsed={collapsed}
            current={current}
            counts={counts}
            onNavigate={onNavigate}
          />
        ))}
        <ActiveIndicator container={listRef} edge="left" inset={8} className="w-[3px]" />
      </div>
    </nav>
  );
}

/** Service health and this installation: the controller's version and the address the page was opened at. */
function ServiceCard({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: (() => void) | undefined }) {
  const s = useServiceState();
  const sys = useSystemStatus();
  if (collapsed) {
    return (
      <Tip content={m.stateAndDetail(s.label, s.detail)} side="right">
        <Link
          to="/system"
          onClick={onNavigate}
          aria-label={m.stateInSystem(s.label)}
          className="pressable mx-auto grid size-10 place-items-center rounded-lg hover:bg-raised/80"
        >
          <Dot tone={s.tone} pulse={s.pulse} />
        </Link>
      </Tip>
    );
  }
  return (
    <Link
      to="/system"
      onClick={onNavigate}
      title={s.detail}
      className="pressable flex min-w-0 flex-col gap-0.5 rounded-lg border border-line-subtle bg-canvas/50 px-3 py-2 no-underline hover:border-line hover:bg-raised/60"
    >
      <span className="flex items-center gap-2 text-data text-fg">
        <Dot tone={s.tone} pulse={s.pulse} />
        <span className="truncate">{s.label}</span>
      </span>
      <span className="machine truncate text-micro text-fg-tertiary">
        {sys.data ? `v${sys.data.version}` : m.versionUnknown} · {window.location.host}
      </span>
    </Link>
  );
}

function SidebarFooter({
  collapsed,
  onToggle,
  onNavigate,
}: {
  collapsed: boolean;
  onToggle?: (() => void) | undefined;
  onNavigate?: (() => void) | undefined;
}) {
  return (
    <div className="grid shrink-0 gap-1 border-t border-line-subtle px-3 py-2">
      <ServiceCard collapsed={collapsed} onNavigate={onNavigate} />
      {onToggle ? (
        <button
          type="button"
          onClick={onToggle}
          data-panel-toggle=""
          aria-label={collapsed ? m.expandSidebar : m.collapseSidebar}
          aria-expanded={!collapsed}
          aria-controls="shell-sidebar"
          title={collapsed ? m.expandSidebarHint : m.collapseSidebarHint}
          className={cn(
            "pressable relative flex h-9 items-center rounded-lg text-caption text-fg-tertiary hover:bg-raised/80 hover:text-fg",
            collapsed ? "mx-auto w-10 justify-center" : "gap-2.5 px-3",
          )}
        >
          {collapsed ? (
            <PanelLeftOpen aria-hidden className="size-4 shrink-0" />
          ) : (
            <PanelLeftClose aria-hidden className="size-4 shrink-0" />
          )}
          {collapsed ? null : <span className="animate-fade-in">{m.collapseSidebar}</span>}
        </button>
      ) : null}
    </div>
  );
}

/** Sidebar content (header, navigation, footer); the drawer passes onNavigate (a chosen link closes it) and no onToggle. */
export function SidebarContent({
  collapsed,
  onToggle,
  onNavigate,
}: {
  collapsed: boolean;
  onToggle?: (() => void) | undefined;
  onNavigate?: (() => void) | undefined;
}) {
  return (
    <>
      <SidebarBrand collapsed={collapsed} onNavigate={onNavigate} />
      <SidebarNav collapsed={collapsed} onNavigate={onNavigate} />
      <SidebarFooter collapsed={collapsed} onToggle={onToggle} onNavigate={onNavigate} />
    </>
  );
}
