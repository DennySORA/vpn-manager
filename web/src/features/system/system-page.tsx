// 系統 (/system): the installation in six tabs (`?view=`): 狀態 (is it healthy, how it is reached, this installation,
// metrics settings, the vault), 能力 (what this host can do), 診斷 (the report's checks, owned resources and databases),
// 執行環境 (the report's processes, disk, programs, files and metrics), 恢復 (leftovers and their cleanup) and 操作紀錄
// (what this installation was asked to do and how it ended). Each view starts with its one raised conclusion and carries
// its own actions there (docs/frontend-design.md §8.1); the tab underline slides and the new view fades in, its sections
// rising in once.
import { Activity, Cpu, History, LifeBuoy, ShieldCheck, Stethoscope } from "lucide-react";
import { lazy, type ReactNode, Suspense } from "react";
import { m as shell } from "@/components/shell/messages";
import { Page, PageHeader } from "@/components/shell/page";
import { STAGGER_IN } from "@/components/ui/look";
import { Skeleton } from "@/components/ui/states";
import { type TabItem, TabPanel, Tabs } from "@/components/ui/tabs";
import { cn } from "@/lib/cn";
import { useTabParam } from "@/lib/url";
import { m } from "./messages";
import { CapabilitiesView, OverviewView } from "./overview";

// The maintenance views load when first opened: they are rarely needed and keep the main bundle
// small. A failed chunk load surfaces in the route's error view.
const DiagnosticsView = lazy(() => import("./diagnostics").then((mod) => ({ default: mod.DiagnosticsView })));
const RecoveryView = lazy(() => import("./recovery").then((mod) => ({ default: mod.RecoveryView })));
const OperationsView = lazy(() => import("./operations").then((mod) => ({ default: mod.OperationsView })));

function Loading({ children }: { children: ReactNode }) {
  return (
    <Suspense
      fallback={
        <div className="px-4 pt-5 md:px-6">
          <div role="status" aria-label={m.page.loading} className={cn("panel-raised space-y-3 px-5 py-5", STAGGER_IN)}>
            <Skeleton className="w-64" />
            <Skeleton className="w-48" />
          </div>
        </div>
      }
    >
      {children}
    </Suspense>
  );
}

export type SystemView = "overview" | "capabilities" | "diagnostics" | "runtime" | "recovery" | "operations";

export const SYSTEM_VIEWS: TabItem<SystemView>[] = [
  { value: "overview", label: m.views.overview, icon: Activity },
  { value: "capabilities", label: m.views.capabilities, icon: ShieldCheck },
  { value: "diagnostics", label: m.views.diagnostics, icon: Stethoscope },
  { value: "runtime", label: m.views.runtime, icon: Cpu },
  { value: "recovery", label: m.views.recovery, icon: LifeBuoy },
  { value: "operations", label: m.views.operations, icon: History },
];

export function SystemPage() {
  const [view, setView] = useTabParam<SystemView>(
    "view",
    SYSTEM_VIEWS.map((v) => v.value),
  );
  return (
    <Page>
      <PageHeader
        title={shell.nav.system.label}
        description={m.page.description}
        help={m.page.help}
        helpText={m.page.helpText}
      />
      <Tabs
        label={shell.nav.system.label}
        value={view}
        onChange={setView}
        items={SYSTEM_VIEWS}
        // The second step of the page's entrance (after the header).
        className={cn(STAGGER_IN, "[--i:1]")}
      >
        <TabPanel value="overview">
          <OverviewView />
        </TabPanel>
        <TabPanel value="capabilities">
          <CapabilitiesView />
        </TabPanel>
        <TabPanel value="diagnostics">
          <Loading>
            <DiagnosticsView part="checks" />
          </Loading>
        </TabPanel>
        <TabPanel value="runtime">
          <Loading>
            <DiagnosticsView part="runtime" />
          </Loading>
        </TabPanel>
        <TabPanel value="recovery">
          <Loading>
            <RecoveryView />
          </Loading>
        </TabPanel>
        <TabPanel value="operations">
          <Loading>
            <OperationsView />
          </Loading>
        </TabPanel>
      </Tabs>
    </Page>
  );
}
