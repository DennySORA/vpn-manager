import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type { BlocklistView, BuiltinBlocklistState } from "@/api/types";
import { blocklistView, BUILTIN, serverText, view } from "@/test/fixtures";
import { BlocklistsPage } from "./blocklists-page";
import { defined } from "@/test/defined";

const WAITING = "還沒有選擇 Provider 出口連線";
const drop = blocklistView("b1", "Spamhaus DROP（IPv4）", {
  builtin: "spamhaus-drop-v4",
  awaiting: true,
  waiting: WAITING,
});
const dshield: BlocklistView = {
  ...blocklistView("b2", "DShield 建議封鎖清單", { builtin: "dshield-block", specialFiltered: 2 }),
  refresh: {
    attempted_at: "2026-10-27T00:00:00Z",
    ok: true,
    message: serverText("已下載 20 筆"),
    succeeded_at: "2026-10-27T00:00:00Z",
    stale_since: null,
  },
};
const lists = [drop, dshield, blocklistView("l1", "我的清單")];
/** DShield present, Spamhaus DROPv6 deleted by the user. */
const catalogue: BuiltinBlocklistState[] = [
  { info: defined(BUILTIN["spamhaus-drop-v4"]), blocklist_id: "b1", deleted_at: null },
  {
    info: {
      ...defined(BUILTIN["spamhaus-drop-v4"]),
      key: "spamhaus-drop-v6",
      name: { en: "Spamhaus DROPv6 (IPv6)", "zh-TW": "Spamhaus DROPv6（IPv6）", ja: "Spamhaus DROPv6（IPv6）" },
    },
    blocklist_id: null,
    deleted_at: "2026-10-28T00:00:00Z",
  },
  { info: defined(BUILTIN["dshield-block"]), blocklist_id: "b2", deleted_at: null },
];

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** Records every mutation; reads answer from the fixtures. */
function serve() {
  const sent: { method: string; url: string; body: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const u = url;
      const method = init?.method ?? "GET";
      if (method !== "GET") {
        sent.push({ method, url: u, body: init?.body ? JSON.parse(init.body as string) : null });
        if (u.endsWith("/restore"))
          return Promise.resolve(
            json(blocklistView("b3", "Spamhaus DROPv6（IPv6）", { builtin: "spamhaus-drop-v4", awaiting: true }), 201),
          );
        return Promise.resolve(json({ ...drop, blocklist: { ...drop.blocklist, enabled: false, revision: 2 } }));
      }
      if (u.startsWith("/v1/blocklists/builtin")) return Promise.resolve(json(catalogue));
      if (u.startsWith("/v1/blocklists")) return Promise.resolve(json(lists));
      if (u.startsWith("/v1/instances")) return Promise.resolve(json([view()]));
      return Promise.resolve(json({}));
    }),
  );
  return sent;
}

function open(at: string) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Number.POSITIVE_INFINITY }, mutations: { retry: false } },
  });
  qc.setQueryData(keys.blocklists, lists);
  qc.setQueryData(keys.builtinBlocklists, catalogue);
  // One connection without a security profile: it follows the default policy.
  qc.setQueryData(keys.instances, [view()]);
  const router = createMemoryRouter([{ path: "/security/blocklists/:id?", Component: BlocklistsPage }], {
    initialEntries: [at],
  });
  render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("IP blocklists page", () => {
  it("restores a deleted built-in list only when asked", async () => {
    const sent = serve();
    open("/security/blocklists");
    expect(screen.getByText("已刪除的內建清單（不會自動加回）")).toBeTruthy();
    expect(screen.getByText("Spamhaus DROPv6（IPv6）")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "還原 Spamhaus DROPv6（IPv6）" }));
    await waitFor(() => {
      expect(sent).toHaveLength(1);
    });
    expect(sent[0]).toMatchObject({ method: "POST", url: "/v1/blocklists/builtin/spamhaus-drop-v6/restore" });
  });
});
