import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type { ReconcileResult, RecoveryItem, RecoveryReport } from "@/api/types";
import { serverText } from "@/test/fixtures";
import { RecoveryView } from "./recovery";

const item = (p: Partial<RecoveryItem>): RecoveryItem => ({
  id: "x",
  kind: "stale_key_lock",
  title: serverText(""),
  detail: serverText("沒有程序持有它"),
  path: null,
  pid: null,
  instance_id: null,
  cleanable: true,
  action: serverText("刪除"),
  ...p,
});

const LOCK = item({
  id: "lock",
  title: serverText("不再使用的金鑰鎖檔"),
  path: "/state/locks/key-1.lock",
  action: serverText("刪除鎖檔"),
});
const SOCKET = item({
  id: "sock",
  kind: "stale_socket",
  title: serverText("遺留的 connector socket"),
  action: serverText("刪除 socket 檔"),
});
const FOREIGN = item({
  id: "held",
  kind: "foreign_key_lock",
  title: serverText("被其他程序持有的金鑰鎖"),
  cleanable: false,
  action: null,
});

const REPORT: RecoveryReport = {
  observed_at: "2026-11-03T00:00:00Z",
  items: [FOREIGN, LOCK, SOCKET],
  gaps: [],
  resources: {
    workers: [],
    listeners: [],
    key_locks: [],
    connector_sockets: [],
    sandboxes: [],
    apps: [],
    unanswered: [],
  },
};

/** Renders 恢復 over a seeded inspection; every request answers 404 except the clean, which is recorded. */
function renderView() {
  const sent: { items: string[] | null }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((path: string, init?: RequestInit) => {
      if (path === "/v1/recovery/reconcile" && init?.method === "POST") {
        const input = JSON.parse(init.body as string) as { items: string[] | null };
        sent.push(input);
        const result: ReconcileResult = {
          operation_id: null,
          observed_at: "2026-11-03T00:00:05Z",
          actions: (input.items ?? []).map((id) => ({
            item_id: id,
            kind: null,
            title: serverText(id),
            outcome: "done",
            detail: serverText("已刪除"),
          })),
          remaining: REPORT.items.filter((i) => !(input.items ?? []).includes(i.id)),
        };
        return Promise.resolve(new Response(JSON.stringify(result), { status: 200 }));
      }
      return Promise.resolve(
        new Response(JSON.stringify({ code: "NOT_FOUND", message: "找不到", retryable: false }), { status: 404 }),
      );
    }),
  );
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Number.POSITIVE_INFINITY }, mutations: { retry: false } },
  });
  qc.setQueryData(keys.recovery, REPORT);
  qc.setQueryData(keys.instances, []);
  qc.setQueryData(keys.apps, []);
  const router = createMemoryRouter([{ path: "/system", Component: RecoveryView }], {
    initialEntries: ["/system?view=recovery"],
  });
  render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { sent };
}

afterEach(() => vi.unstubAllGlobals());

describe("恢復", () => {
  it("a row's 清理 confirms exactly that item; an item that is only reported says why it cannot be cleaned", async () => {
    const user = userEvent.setup();
    renderView();
    const held = await screen.findByRole("button", { name: "清理 被其他程序持有的金鑰鎖" });
    expect(held.getAttribute("aria-disabled")).toBe("true");
    expect(held.getAttribute("title")).toBe("清理 被其他程序持有的金鑰鎖：被其他程序使用：只回報，不會清理");
    // Named with its file, so two leftovers with the same title are told apart.
    await user.click(screen.getByRole("button", { name: "清理 不再使用的金鑰鎖檔（key-1.lock）" }));
    const confirm = await screen.findByRole("alertdialog", { name: "清理「不再使用的金鑰鎖檔」？" });
    const listed = within(confirm)
      .getAllByRole("listitem")
      .map((li) => li.textContent);
    // The item, what cleaning does to it, and the exact file.
    expect(listed).toEqual(["不再使用的金鑰鎖檔：刪除鎖檔/state/locks/key-1.lock"]);
    expect(confirm.textContent).toContain("無法復原");
  });

  it("the batch confirms every cleanable item and sends exactly those ids", async () => {
    const user = userEvent.setup();
    const { sent } = renderView();
    const band = await screen.findByRole("region", { name: "恢復結論" });
    await user.click(within(band).getByRole("button", { name: "清理 2 個項目" }));
    const confirm = await screen.findByRole("alertdialog", { name: "清理 2 個項目？" });
    expect(
      within(confirm)
        .getAllByRole("listitem")
        .map((li) => li.textContent),
    ).toEqual(["不再使用的金鑰鎖檔：刪除鎖檔/state/locks/key-1.lock", "遺留的 connector socket：刪除 socket 檔"]);
    expect(confirm.textContent).not.toContain("被其他程序持有的金鑰鎖");
    await user.click(within(confirm).getByRole("button", { name: "清理 2 個項目" }));
    await waitFor(() => {
      expect(sent).toEqual([{ items: ["lock", "sock"] }]);
    });
    expect(await screen.findByRole("region", { name: "清理結果" })).toBeTruthy();
  });
});
