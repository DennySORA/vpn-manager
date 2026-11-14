import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type { AppStatus, AppView, Capability, ForwardView, LiveRates } from "@/api/types";
import { serverText, view } from "@/test/fixtures";
import { AppsPage } from "./apps-page";

const T = "2026-10-27T12:00:00Z";

const CAPS: Capability[] = [
  { name: "app_proxy_env", state: "supported", reason: serverText("只設定代理環境變數") },
  { name: "app_enforced_proxy", state: "supported", reason: serverText("macOS Seatbelt") },
  { name: "app_strict_netns", state: "unsupported", reason: serverText("嚴格隔離只在 Linux 提供") },
];

function status(p: Partial<AppStatus> = {}): AppStatus {
  return {
    app_id: "a1",
    desired: "running",
    intent_persistence: "durable",
    state: "running",
    run_revision: 1,
    pid: 4242,
    started_at: T,
    last_exit: null,
    last_error: null,
    isolation: "enforced_proxy",
    gateway_id: "g1",
    gateway_port: 1080,
    process_count: 1,
    listeners: [],
    sandbox_denials: 0,
    resources: null,
    access: [],
    observed_at: T,
    ...p,
  };
}

function app(s: AppStatus | null): AppView {
  return {
    spec: {
      id: "a1",
      instance_id: "i1",
      name: "HTTP 伺服器",
      executable: "/usr/bin/python3",
      args: ["-m", "http.server"],
      working_dir: null,
      env: [],
      isolation: "enforced_proxy",
      gateway_id: "g1",
      restart_on_recovery: false,
      writable_paths: [],
      confine_writes: false,
      stop_grace_secs: 10,
      approval: { path: "/usr/bin/python3", sha256: "ab".repeat(32), size: 1000, approved_at: T, app_class: null },
      limits: { memory_mib: null, cpu_percent: null, processes: null, open_files: null },
      access_ports: [],
      revision: 1,
      created_at: T,
      updated_at: T,
    },
    status: s,
  };
}

const stopped = () =>
  app(
    status({
      state: "stopped",
      desired: "stopped",
      pid: null,
      process_count: null,
      isolation: null,
      gateway_port: null,
    }),
  );

/** The wide layout (≥1280: the inspector is a column beside the list), motion allowed. */
function wideWindow() {
  vi.spyOn(window, "matchMedia").mockImplementation(
    (query: string) =>
      ({
        matches: query.includes("min-width: 80rem"),
        media: query,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
      }) as unknown as MediaQueryList,
  );
}

function renderAt(url: string, apps: AppView[], forwards: ForwardView[] = [], live?: LiveRates[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ code: "NOT_FOUND", message: "找不到", retryable: false }), { status: 404 }),
      ),
    ),
  );
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Number.POSITIVE_INFINITY }, mutations: { retry: false } },
  });
  qc.setQueryData(keys.apps, apps);
  qc.setQueryData(keys.instances, [view()]);
  qc.setQueryData(keys.gateways, view().gateways);
  qc.setQueryData(keys.capabilities, CAPS);
  qc.setQueryData(keys.forwards, forwards);
  qc.setQueryData(keys.system, { data_dir: "/var/lib/vpn-manager", host_addresses: [], controller_port: 18765 });
  if (live) qc.setQueryData(keys.live("i1"), live);
  for (const a of apps) {
    qc.setQueryData(keys.appProcesses(a.spec.id), { processes: [], truncated: false, observed_at: T });
    qc.setQueryData([...keys.appLog(a.spec.id), 200], { lines: [], truncated: false });
  }
  const router = createMemoryRouter([{ path: "/apps/:id?", Component: AppsPage }], { initialEntries: [url] });
  render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

beforeEach(() => {
  wideWindow();
});
afterEach(() => vi.unstubAllGlobals());

describe("one action model for the App row and the App inspector", () => {
  it("the row's menu and the inspector open the same delete confirmation, stating its scope", async () => {
    const user = userEvent.setup();
    renderAt("/apps/a1", [stopped()]);
    await screen.findByRole("complementary", { name: "HTTP 伺服器 的詳細資料" });
    await user.click(screen.getByRole("button", { name: "HTTP 伺服器 的更多操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "刪除" }));
    const confirm = await screen.findByRole("alertdialog", { name: "刪除受管 App「HTTP 伺服器」？" });
    expect(confirm.textContent).toContain("私有家目錄");
    expect(confirm.textContent).toContain("執行檔本身、所屬連線與代理埠不受影響");
    expect(within(confirm).getByRole("button", { name: "刪除" })).toBeTruthy();
  });
});
