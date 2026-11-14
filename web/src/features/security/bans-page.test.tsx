import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type { Ban } from "@/api/types";
import { serverText, view } from "@/test/fixtures";
import { BansPage } from "./bans-page";

const at = (minutes: number) => new Date(Date.now() + minutes * 60_000).toISOString();
const ban = (p: Partial<Ban>): Ban => ({
  id: "ban1",
  instance_id: "i1",
  source: "203.0.113.7",
  reason: serverText("10 秒內開啟 120 個新連線"),
  security_profile_id: null,
  security_profile_revision: null,
  policy_revision: 4,
  generation: 1,
  created_at: at(-2),
  expires_at: at(13),
  ...p,
});
const active = ban({});
const expired = ban({ id: "ban2", source: "198.51.100.9", created_at: at(-20), expires_at: at(-1) });

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function renderAt(url: string) {
  const sent: { method: string; url: string }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((u: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      if (method !== "GET") {
        sent.push({ method, url: u });
        return Promise.resolve(json({ ban: active, worker: "applied" }));
      }
      return Promise.resolve(json(u.startsWith("/v1/bans") ? [active, expired] : []));
    }),
  );
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Number.POSITIVE_INFINITY }, mutations: { retry: false } },
  });
  qc.setQueryData(keys.bans(null), [active, expired]);
  qc.setQueryData(keys.instances, [view()]);
  qc.setQueryData(keys.security, []);
  qc.setQueryData(keys.inbound, { instances: [{ instance_id: "i1", forward_bindings: 1, enabled: 1 }] });
  const router = createMemoryRouter([{ path: "/security/bans", Component: BansPage }], { initialEntries: [url] });
  render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { router, sent };
}

afterEach(() => vi.unstubAllGlobals());

describe("automatic bans", () => {
  it("lifts a ban only after a confirmation that states its scope", async () => {
    const { sent } = renderAt("/security/bans");
    await userEvent.click(screen.getByRole("button", { name: "解除封鎖 203.0.113.7" }));
    const confirm = await screen.findByRole("alertdialog", { name: "解除 203.0.113.7 的封鎖？" });
    expect(confirm.textContent).toContain("可以再次經轉發連入「東京出口」");
    expect(confirm.textContent).toContain("IP 封鎖清單與安全設定的規則仍然適用");
    expect(sent).toEqual([]);
    await userEvent.click(within(confirm).getByRole("button", { name: "解除封鎖" }));
    await waitFor(() => {
      expect(sent).toEqual([{ method: "DELETE", url: "/v1/bans/ban1" }]);
    });
  });
});
