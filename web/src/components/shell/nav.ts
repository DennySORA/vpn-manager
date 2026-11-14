import type { LucideIcon } from "lucide-react";
import {
  AppWindow,
  Building2,
  ChartLine,
  EthernetPort,
  FileKey,
  FolderDown,
  Gauge,
  Globe,
  LayoutDashboard,
  ListX,
  Network,
  Server,
  Shield,
  ShieldBan,
  SlidersHorizontal,
  SquareTerminal,
  Waypoints,
} from "lucide-react";
import { useEffect, useSyncExternalStore } from "react";
import { m } from "./messages";

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** The item's tooltip in the sidebar. */
  hint: string;
}

export interface NavGroup {
  /** Stable key (its collapsed state is remembered under it). */
  id: string;
  /** Its heading; null for the home entry, which is no group and never collapses. */
  label: string | null;
  items: NavItem[];
}

/**
 * The navigation: 總覽 on its own, then what the traffic leaves through (出口), what uses the connections (代理與 App),
 * SSH, observation, policy and the host. Every labelled group can be collapsed (see sidebar.tsx).
 */
export const NAV_GROUPS: NavGroup[] = [
  {
    id: "home",
    label: null,
    items: [{ to: "/", ...m.nav.overview, icon: LayoutDashboard }],
  },
  {
    id: "exits",
    label: m.nav.exits,
    items: [
      { to: "/instances", ...m.nav.instances, icon: Network },
      { to: "/providers", ...m.nav.providers, icon: Building2 },
      { to: "/profiles", ...m.nav.profiles, icon: FileKey },
    ],
  },
  {
    id: "uses",
    label: m.nav.proxiesAndApps,
    items: [
      { to: "/gateways", ...m.nav.gateways, icon: EthernetPort },
      { to: "/apps", ...m.nav.apps, icon: AppWindow },
      { to: "/forwards", ...m.nav.forwards, icon: Waypoints },
    ],
  },
  {
    id: "ssh",
    label: "SSH",
    items: [
      { to: "/ssh", ...m.nav.ssh, icon: SquareTerminal },
      { to: "/ssh-downloads", ...m.nav.sshDownloads, icon: FolderDown },
    ],
  },
  {
    id: "observe",
    label: m.nav.monitoring,
    items: [
      { to: "/metrics", ...m.nav.metrics, icon: ChartLine },
      { to: "/performance", ...m.nav.performance, icon: Gauge },
    ],
  },
  {
    id: "policy",
    label: m.nav.policies,
    items: [
      { to: "/dns", ...m.nav.dns, icon: Globe },
      { to: "/transport", ...m.nav.transport, icon: SlidersHorizontal },
      { to: "/security", ...m.nav.security, icon: Shield },
      { to: "/security/blocklists", ...m.nav.blocklists, icon: ListX },
      { to: "/security/bans", ...m.nav.bans, icon: ShieldBan },
    ],
  },
  {
    id: "host",
    label: m.nav.host,
    items: [{ to: "/system", ...m.nav.system, icon: Server }],
  },
];

export const NAV_ITEMS = NAV_GROUPS.flatMap((g) => g.items);

/** The navigation item of a path: the longest matching one (`/security/bans` is not `/security`). */
export function sectionFor(pathname: string): NavItem | undefined {
  if (pathname === "/") return NAV_ITEMS[0];
  let best: NavItem | undefined;
  for (const i of NAV_ITEMS) {
    if (
      i.to !== "/" &&
      (pathname === i.to || pathname.startsWith(`${i.to}/`)) &&
      (!best || i.to.length > best.to.length)
    )
      best = i;
  }
  return best;
}

// The selected object's name for the breadcrumb and the document title. Pages set it; the shell reads it.
let crumb: string | null = null;
const listeners = new Set<() => void>();

function subscribe(l: () => void) {
  listeners.add(l);
  return () => {
    listeners.delete(l);
  };
}
const snapshot = () => crumb;

export function useCrumbValue(): string | null {
  return useSyncExternalStore(subscribe, snapshot);
}

export function useCrumb(detail: string | null | undefined) {
  useEffect(() => {
    crumb = detail ?? null;
    for (const l of listeners) l();
    return () => {
      crumb = null;
      for (const l of listeners) l();
    };
  }, [detail]);
}
