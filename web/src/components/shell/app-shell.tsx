// Adapted from Phasyn Studio (Apache-2.0).
// The application shell: the glass sidebar on the left (232 px, or a 64 px icon rail; the preference is kept in this
// browser, collapsed by default on windows narrower than 1600 px; below 840 px it is a left drawer), and on the right
// the 44 px top bar over the main region. It is fixed to the window and never scrolls (relative + overflow-clip: any
// absolute descendant is clipped by the shell). Under everything sits the deep-space ground: radial brand glows on the
// canvas, in CSS only. Motion: the routed content sits in React's <ViewTransition>, keyed by the page, so a page change
// (react-router commits navigations in a transition) fades the old page out and the new one rises in (app.css,
// .route-exit / .route-enter); selecting another object on the same page or a query-only change updates in place.
// Collapsing the sidebar morphs the shell (a typed View Transition, runViewTransition) with the state committed at once.
import { OctagonX, Unplug } from "lucide-react";
import { type ReactNode, useLayoutEffect, useRef, useState, ViewTransition } from "react";
import { Outlet, useLocation } from "react-router";
import { useEventStream } from "@/api/events";
import { Sheet } from "@/components/ui/dialog";
import { runViewTransition } from "@/components/ui/motion";
import { useMedia } from "@/lib/use-media";
import { usePersistentFlag } from "@/lib/use-persistent";
import { markRouteFocusPending } from "./route-focus";
import { useServiceState } from "./service";
import { SidebarContent } from "./sidebar";
import { Topbar } from "./topbar";
import { pageOf } from "./view-transition";
import { m } from "./messages";

/** Sidebar width (px), expanded and collapsed. */
export const SIDEBAR_WIDTH = { expanded: 232, collapsed: 64 } as const;

/**
 * The shell's one shared brand gradient (userSpaceOnUse 2–22, the lucide 24-unit box): the current navigation icon
 * strokes with `url(#vpnm-brand-gradient)`. userSpaceOnUse keeps perfectly horizontal or vertical strokes visible.
 */
function SharedGradients() {
  return (
    <svg
      aria-hidden
      focusable="false"
      width="0"
      height="0"
      className="pointer-events-none absolute size-0 overflow-hidden"
    >
      <defs>
        <linearGradient id="vpnm-brand-gradient" x1="2" y1="2" x2="22" y2="22" gradientUnits="userSpaceOnUse">
          <stop offset="0" style={{ stopColor: "var(--color-brand-cyan)" }} />
          <stop offset="0.36" style={{ stopColor: "var(--color-brand-blue)" }} />
          <stop offset="0.68" style={{ stopColor: "var(--color-brand-iris)" }} />
          <stop offset="1" style={{ stopColor: "var(--color-brand-violet)" }} />
        </linearGradient>
      </defs>
    </svg>
  );
}

/** The fixed, very quiet deep-space ground (CSS only): seen through the sidebar glass and around the page's panels. */
function SpaceBackdrop() {
  return (
    <div
      aria-hidden
      className="pointer-events-none fixed inset-0 bg-canvas"
      style={{ backgroundImage: "var(--gradient-space)" }}
    />
  );
}

/** Shown while the facts on screen may be stale: the controller or the manager is unreachable. */
function ServiceBanner() {
  const s = useServiceState();
  if (s.tone !== "danger") return null;
  const Icon = s.down === "controller" ? Unplug : OctagonX;
  return (
    <div
      role="status"
      className="flex shrink-0 items-center gap-2.5 border-b border-danger/30 bg-danger/8 px-6 py-2 text-data animate-fade-in"
    >
      <Icon aria-hidden className="size-4 shrink-0 text-danger" />
      <span className="font-medium text-danger">{s.label}</span>
      <span className="text-fg-secondary">{s.detail}</span>
    </div>
  );
}

export function AppShell({ traffic }: { traffic: ReactNode }) {
  useEventStream();
  const { pathname } = useLocation();
  const page = pageOf(pathname);
  const previousPage = useRef(page);
  const [collapsed, setCollapsed] = usePersistentFlag(
    "shell.sidebar.collapsed",
    typeof window !== "undefined" && window.innerWidth < 1600,
  );
  const [drawerOpen, setDrawerOpen] = useState(false);
  // The drawer exists only below 840 px: a window widened past it shows the sidebar instead, so the drawer closes.
  const drawerViewport = useMedia("(width < 52.5rem)");
  if (drawerOpen && !drawerViewport) setDrawerOpen(false);

  // A page change (not another object on the same page) hands focus to the new page's title.
  useLayoutEffect(() => {
    if (previousPage.current !== page) {
      previousPage.current = page;
      markRouteFocusPending();
    }
  }, [page]);

  const toggleSidebar = () => {
    runViewTransition("sidebar", () => {
      setCollapsed(!collapsed);
    });
  };

  return (
    <div className="relative grid h-dvh grid-cols-[auto_minmax(0,1fr)] overflow-clip text-fg max-md:grid-cols-1">
      <SpaceBackdrop />
      <SharedGradients />
      <a
        href="#main-content"
        className="sr-only-focusable fixed top-2 left-4 z-[70] rounded-md border border-focus bg-surface px-4 py-2 text-body text-fg no-underline"
      >
        {m.skipToContent}
      </a>
      <aside
        id="shell-sidebar"
        aria-label={m.sidebar}
        className="material-sidebar relative z-30 flex h-full min-h-0 flex-col [view-transition-name:shell-sidebar] max-md:hidden"
        style={{ width: collapsed ? SIDEBAR_WIDTH.collapsed : SIDEBAR_WIDTH.expanded }}
      >
        <SidebarContent collapsed={collapsed} onToggle={toggleSidebar} />
      </aside>
      <div className="relative grid min-h-0 min-w-0 grid-rows-[2.75rem_minmax(0,1fr)]">
        {/* min-w-0: a long breadcrumb truncates instead of widening the column (and the page) on a narrow window. */}
        <div className="relative z-20 min-w-0 [view-transition-name:shell-topbar]">
          <Topbar
            traffic={traffic}
            navOpen={drawerOpen}
            onOpenNav={() => {
              setDrawerOpen(true);
            }}
          />
        </div>
        <main
          id="main-content"
          tabIndex={-1}
          className="relative flex min-h-0 min-w-0 flex-col overflow-hidden outline-none [view-transition-name:main-content]"
        >
          <ServiceBanner />
          <div className="min-h-0 flex-1">
            {/* Only a new page (a new key) enters and exits; updates inside a page never animate the whole content. */}
            <ViewTransition key={page} enter="route-enter" exit="route-exit" default="none">
              <div className="h-full min-h-0">
                <Outlet />
              </div>
            </ViewTransition>
          </div>
        </main>
      </div>
      <Sheet
        side="left"
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        title={m.navigation}
        hideTitle
        closeLabel={m.closeNavigation}
        className="w-[min(18rem,86vw)] md:hidden"
      >
        <div className="flex h-full min-h-0 flex-col">
          <SidebarContent
            collapsed={false}
            onNavigate={() => {
              setDrawerOpen(false);
            }}
          />
        </div>
      </Sheet>
    </div>
  );
}
