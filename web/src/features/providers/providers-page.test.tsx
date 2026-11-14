import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type { ProviderAccount, ProviderEgressStatus, RuntimeProfile } from "@/api/types";
import { ProvidersPage } from "./providers-page";
import { account, egress, forwardedPort, forwardedPorts, gate } from "./test-fixtures";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

interface Stub {
  /** The egress status the server holds now (what a fresh read answers). */
  egressNow?: ProviderEgressStatus;
  /** Holds the forwarded-ports read until called. */
  holdPorts?: boolean;
}

/** The API behind the page: the reads it makes, with the forwarded-ports read held back when asked. */
function stubApi({ egressNow, holdPorts }: Stub = {}) {
  let release: () => void = () => undefined;
  const portsHeld = new Promise<void>((r) => {
    release = r;
  });
  const calls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const u = url;
      calls.push(`${init?.method ?? "GET"} ${u}`);
      if (u === "/v1/provider-accounts/a1/forwarded-ports") {
        if (holdPorts) await portsHeld;
        return json(200, forwardedPorts([forwardedPort()]));
      }
      if (u === "/v1/provider-egress" && egressNow) return json(200, egressNow);
      if (u === "/v1/provider-accounts/a1/devices") return json(200, []);
      return json(404, { code: "NOT_FOUND", message: "找不到", retryable: false });
    }),
  );
  return {
    calls,
    release: () => {
      release();
    },
  };
}

function renderAt(
  url: string,
  o: { accounts?: ProviderAccount[]; profiles?: RuntimeProfile[]; status?: ProviderEgressStatus } = {},
) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Number.POSITIVE_INFINITY }, mutations: { retry: false } },
  });
  qc.setQueryData(keys.system, { manager_connected: true });
  qc.setQueryData(keys.providerAccounts, o.accounts ?? [account()]);
  qc.setQueryData(keys.providerEgress, o.status ?? egress({ gates: [gate()] }));
  qc.setQueryData(keys.instances, []);
  qc.setQueryData(keys.profiles, o.profiles ?? []);
  qc.setQueryData(keys.gateways, []);
  qc.setQueryData(keys.forwards, []);
  qc.setQueryData(keys.apps, []);
  const router = createMemoryRouter([{ path: "/providers/:id?", Component: ProvidersPage }], { initialEntries: [url] });
  render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

afterEach(() => vi.unstubAllGlobals());

describe("one action model for the account's row and its page", () => {
  it("the row's menu opens the remove confirmation, stating what changes and what does not", async () => {
    stubApi();
    const user = userEvent.setup();
    renderAt("/providers/a1");
    await user.click(await screen.findByRole("button", { name: "我的 AirVPN 的更多操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "移除帳號" }));
    const confirm = await screen.findByRole("alertdialog", { name: "移除帳號「我的 AirVPN」？" });
    expect(confirm.textContent).toContain("只刪除這台電腦保存的帳號資料");
    expect(confirm.textContent).toContain("AirVPN 上的裝置、連入埠與付費狀態都不會改變");
  });
});
