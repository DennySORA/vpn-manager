import { createBrowserRouter } from "react-router";
import { AppShell } from "@/components/shell/app-shell";
import { BrandLoading } from "@/components/shell/brand-loading";
import { TrafficStrip } from "@/features/traffic/traffic-strip";
import { NotFound, RouteError } from "./route-error";
import { m } from "./messages";

/** The shell with what it shows of the features: the top bar's traffic strip. */
function Shell() {
  return <AppShell traffic={<TrafficStrip />} />;
}

/** While a page's code arrives (the first visit to it; the shell stays on screen). */
function RouteLoading() {
  return <BrandLoading label={m.loadingPage} />;
}

// Every page is its own chunk, loaded when first opened, so the first paint carries only the shell and the page in
// view. The URL is the view state: section, selected object (path) and filters/dialogs (query).
export const router = createBrowserRouter([
  {
    path: "/",
    Component: Shell,
    ErrorBoundary: RouteError,
    HydrateFallback: RouteLoading,
    children: [
      {
        index: true,
        lazy: async () => ({ Component: (await import("@/features/overview/overview-page")).OverviewPage }),
      },
      {
        path: "instances/:id?",
        lazy: async () => ({ Component: (await import("@/features/instances/instances-page")).InstancesPage }),
      },
      {
        path: "providers/:id?",
        lazy: async () => ({ Component: (await import("@/features/providers/providers-page")).ProvidersPage }),
      },
      {
        path: "profiles/:id?",
        lazy: async () => ({ Component: (await import("@/features/profiles/profiles-page")).ProfilesPage }),
      },
      {
        path: "gateways/:id?",
        lazy: async () => ({ Component: (await import("@/features/gateways/gateways-page")).GatewaysPage }),
      },
      { path: "apps/:id?", lazy: async () => ({ Component: (await import("@/features/apps/apps-page")).AppsPage }) },
      {
        path: "forwards/:id?",
        lazy: async () => ({ Component: (await import("@/features/forwards/forwards-page")).ForwardsPage }),
      },
      { path: "dns/:id?", lazy: async () => ({ Component: (await import("@/features/dns/dns-page")).DnsPage }) },
      {
        path: "transport/:id?",
        lazy: async () => ({ Component: (await import("@/features/transport/transport-page")).TransportPage }),
      },
      {
        path: "security/blocklists/:id?",
        lazy: async () => ({ Component: (await import("@/features/security/blocklists-page")).BlocklistsPage }),
      },
      {
        path: "security/bans",
        lazy: async () => ({ Component: (await import("@/features/security/bans-page")).BansPage }),
      },
      {
        path: "security/:id?",
        lazy: async () => ({ Component: (await import("@/features/security/security-page")).SecurityPage }),
      },
      { path: "ssh/:id?", lazy: async () => ({ Component: (await import("@/features/ssh/ssh-page")).SshPage }) },
      {
        path: "ssh-downloads/:id?",
        lazy: async () => ({
          Component: (await import("@/features/ssh-downloads/ssh-downloads-page")).SshDownloadsPage,
        }),
      },
      {
        path: "performance",
        lazy: async () => ({ Component: (await import("@/features/performance/performance-page")).PerformancePage }),
      },
      { path: "system", lazy: async () => ({ Component: (await import("@/features/system/system-page")).SystemPage }) },
      {
        path: "metrics",
        lazy: async () => ({ Component: (await import("@/features/metrics/metrics-page")).MetricsPage }),
      },
      { path: "*", Component: NotFound },
    ],
  },
]);
