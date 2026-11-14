import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type { DnsProfile, InstanceView } from "@/api/types";
import { view } from "@/test/fixtures";
import { DnsPage } from "./dns-page";

const T = "2026-10-27T00:00:00Z";
const dns = (id: string, name: string): DnsProfile => ({
  id,
  name,
  servers: [
    { transport: "udp", address: "10.99.0.1:53" },
    { transport: "tls", address: "1.1.1.1:853", server_name: "cloudflare-dns.com" },
  ],
  cache: { max_entries: 4096, max_ttl_secs: 3600, negative_ttl_secs: 60 },
  query_timeout_ms: 3000,
  attempts: 2,
  on_failure: "wireguard_resolvers",
  revision: 2,
  created_at: T,
  updated_at: T,
});
const lab = dns("d1", "Lab DNS");
const spare = dns("d2", "備用 DNS");
const user: InstanceView = { ...view(), spec: { ...view().spec, dns_profile_id: "d1" } };

function json(body: unknown, status = 200) {
  return new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** Records every mutation; reads answer from the fixtures. */
function renderAt(url: string) {
  const sent: { method: string; url: string; ifMatch: string | null }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((u: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      if (method !== "GET") {
        sent.push({ method, url: u, ifMatch: new Headers(init?.headers).get("if-match") });
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      return Promise.resolve(json(u.startsWith("/v1/dns-profiles") ? [lab, spare] : [user]));
    }),
  );
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Number.POSITIVE_INFINITY }, mutations: { retry: false } },
  });
  qc.setQueryData(keys.dns, [lab, spare]);
  qc.setQueryData(keys.instances, [user]);
  const router = createMemoryRouter([{ path: "/dns/:id?", Component: DnsPage }], { initialEntries: [url] });
  render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { router, sent };
}

afterEach(() => vi.unstubAllGlobals());

describe("DNS profiles: one action model for the row and the editor", () => {
  it("the row's menu opens the delete confirmation, which states its scope and deletes that revision", async () => {
    const { router, sent } = renderAt("/dns/d2");
    await screen.findByRole("region", { name: "備用 DNS 的設定" });
    await userEvent.click(screen.getByRole("button", { name: "備用 DNS 的更多操作" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "刪除" }));
    const confirm = await screen.findByRole("alertdialog", { name: "刪除 DNS 設定「備用 DNS」？" });
    expect(confirm.textContent).toContain("它的 2 個伺服器與快取設定會一起刪除");
    expect(confirm.textContent).toContain("不影響任何連線");
    await userEvent.click(within(confirm).getByRole("button", { name: "刪除" }));
    await waitFor(() => {
      expect(sent).toEqual([{ method: "DELETE", url: "/v1/dns-profiles/d2", ifMatch: '"2"' }]);
    });
    // The editor of the deleted profile is gone, without asking about its (empty) draft.
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/dns");
    });
  });
});
