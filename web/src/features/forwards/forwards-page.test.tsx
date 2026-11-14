import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type { AppView, ForwardView, InstanceView, ProviderAccount, RuntimeProfile } from "@/api/types";
import { view } from "@/test/fixtures";
import { ForwardsPage } from "./forwards-page";

const T = "2026-10-27T12:00:00Z";

function forward(p: Partial<ForwardView["binding"]> = {}): ForwardView {
  return {
    binding: {
      id: "f1",
      instance_id: "i1",
      name: "BitTorrent 35786",
      protocol: "both",
      tunnel_port: 35786,
      public_port: 35786,
      assignment_source: "manual",
      target_app_id: "a1",
      target_port: 35786,
      enabled: true,
      max_connections: 256,
      proxy_protocol: false,
      udp_direct: false,
      revision: 1,
      created_at: T,
      updated_at: T,
      ...p,
    },
    status: {
      binding_id: "f1",
      instance_id: "i1",
      state: p.enabled === false ? "disabled" : "listening",
      reason_code: null,
      reason: null,
      target: null,
      lease: null,
      counters: null,
      reachability: { state: "unverified", tcp_observed_at: null, udp_observed_at: null },
      observed_at: T,
    },
  };
}

const app = {
  spec: { id: "a1", instance_id: "i1", name: "P2P client", isolation: "strict_netns" },
  status: null,
} as unknown as AppView;

/** The wide layout (≥1280: the inspector is a column beside the list). */
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

function renderAt(
  url: string,
  forwards: ForwardView[],
  o: { owner?: InstanceView; profiles?: RuntimeProfile[]; accounts?: ProviderAccount[]; fetch?: typeof fetch } = {},
) {
  vi.stubGlobal(
    "fetch",
    o.fetch ??
      vi.fn(() =>
        Promise.resolve(
          new Response(JSON.stringify({ code: "NOT_FOUND", message: "找不到", retryable: false }), { status: 404 }),
        ),
      ),
  );
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Number.POSITIVE_INFINITY }, mutations: { retry: false } },
  });
  qc.setQueryData(keys.forwards, forwards);
  qc.setQueryData(keys.instances, [o.owner ?? view()]);
  qc.setQueryData(keys.apps, [app]);
  qc.setQueryData(keys.profiles, o.profiles ?? []);
  qc.setQueryData(keys.providerAccounts, o.accounts ?? []);
  qc.setQueryData(keys.system, { data_dir: "/var/lib/vpn-manager", host_addresses: [], controller_port: 18765 });
  const router = createMemoryRouter([{ path: "/forwards/:id?", Component: ForwardsPage }], { initialEntries: [url] });
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

describe("one action model for the forward row and the forward inspector", () => {
  it("the row's menu and the inspector open the same delete confirmation, stating its scope", async () => {
    const user = userEvent.setup();
    renderAt("/forwards/f1", [forward()]);
    await screen.findByRole("complementary", { name: "BitTorrent 35786 的詳細資料" });
    await user.click(screen.getByRole("button", { name: "BitTorrent 35786 的更多操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "刪除" }));
    const confirm = await screen.findByRole("alertdialog", { name: "刪除轉發「BitTorrent 35786」？" });
    expect(confirm.textContent).toContain("tunnel :35786（TCP＋UDP）會立即停止監聽");
    expect(confirm.textContent).toContain("供應商那邊保留的 port 都不受影響");
  });
});
