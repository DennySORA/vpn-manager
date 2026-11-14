import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type { InstanceView } from "@/api/types";
import { status, view } from "@/test/fixtures";
import { InstancesPage } from "./instances-page";

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

function renderAt(url: string, views: InstanceView[]) {
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
  qc.setQueryData(keys.instances, views);
  qc.setQueryData(keys.dns, []);
  qc.setQueryData(keys.security, []);
  qc.setQueryData(keys.profiles, []);
  qc.setQueryData(
    keys.gateways,
    views.flatMap((v) => v.gateways),
  );
  const router = createMemoryRouter([{ path: "/instances/:id?", Component: InstancesPage }], { initialEntries: [url] });
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

const stoppedView = () =>
  view({
    status: status({
      phase: "stopped",
      enforcement: "blocked",
      running: null,
      intent: { ...status().intent, desired: "stopped" },
    }),
  });

describe("one action model for the row and the inspector", () => {
  it("the row's menu and the inspector open the same delete confirmation, stating its scope", async () => {
    const user = userEvent.setup();
    renderAt("/instances/i1", [stoppedView()]);
    await screen.findByRole("complementary", { name: "東京出口 的詳細資料" });
    await user.click(screen.getByRole("button", { name: "東京出口 的更多操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "刪除" }));
    const confirm = await screen.findByRole("alertdialog", { name: "刪除連線「東京出口」？" });
    expect(confirm.textContent).toContain("它的 1 個代理埠（:1080）會一起刪除");
    expect(within(confirm).getByRole("button", { name: "刪除" })).toBeTruthy();
  });
});
