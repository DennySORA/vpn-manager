import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type { InstanceView, RuntimeProfile } from "@/api/types";
import { ProfilesPage } from "./profiles-page";
import { airvpnProfile, profile } from "./test-fixtures";

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

function client(profiles: RuntimeProfile[], views: InstanceView[]) {
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
  qc.setQueryData(keys.system, { manager_connected: true });
  qc.setQueryData(keys.profiles, profiles);
  qc.setQueryData(keys.instances, views);
  qc.setQueryData(
    keys.gateways,
    views.flatMap((v) => v.gateways),
  );
  qc.setQueryData(keys.providerAccounts, []);
  qc.setQueryData(keys.providerEgress, null);
  return qc;
}

function renderAt(url: string, profiles: RuntimeProfile[], views: InstanceView[] = []) {
  const qc = client(profiles, views);
  const router = createMemoryRouter([{ path: "/profiles/:id?", Component: ProfilesPage }], { initialEntries: [url] });
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

describe("one action model for the profile row and its inspector", () => {
  it("the row's menu opens the delete confirmation, stating its exact scope", async () => {
    const user = userEvent.setup();
    renderAt("/profiles", [profile(), airvpnProfile()]);
    await user.click(await screen.findByRole("button", { name: "AirVPN · 荷蘭 piautos 的更多操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "刪除" }));
    const confirm = await screen.findByRole("alertdialog", { name: "刪除 WireGuard 設定「AirVPN · 荷蘭 piautos」？" });
    expect(confirm.textContent).toContain("這份設定與加密保存的金鑰會一起刪除");
    expect(confirm.textContent).toContain("其他設定、連線與供應商帳號不受影響");
    expect(within(confirm).getByRole("button", { name: "刪除" }).className).toContain("bg-danger-fill");
  });
});
