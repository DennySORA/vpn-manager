import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type { InstanceView } from "@/api/types";
import { queryClient } from "@/api/query-client";
import { Toaster } from "@/components/ui/toast";
import { status, view } from "@/test/fixtures";
import { announceSaved } from "./actions";
import { defined } from "@/test/defined";

/** The fixture connection on DNS profile d1, its worker started with DNS revision `rev`. */
function onDns(rev: number): InstanceView {
  const v = view();
  return {
    ...v,
    spec: { ...v.spec, dns_profile_id: "d1" },
    status: status({ running: { ...defined(status().running), dns_profile_revision: rev } }),
  };
}

afterEach(async () => {
  vi.unstubAllGlobals();
  queryClient.clear();
  render(<Toaster />);
  for (const b of screen.queryAllByRole("button", { name: "關閉通知" })) await userEvent.click(b);
});

describe("restart offer after saving a profile", () => {
  it("restarts exactly the running connections on the older revision, only when clicked", async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ operation: {}, sealed: null, durable: null }), {
        status: 202,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);
    queryClient.setQueryData(keys.instances, [onDns(1)]);
    render(<Toaster />);
    act(() => {
      announceSaved({ title: "已儲存 加密 DNS", kind: "dns", id: "d1", revision: 2, workerChanged: true });
    });
    const offer = screen.getByRole("button", { name: "重新啟動使用中的 1 條連線" });
    expect(fetch).not.toHaveBeenCalled();
    await userEvent.click(offer);
    await waitFor(() => {
      expect(screen.getByText("已送出重新啟動 東京出口")).toBeTruthy();
    });
    const [url, init] = (fetch.mock.calls.find((c) => String(c[0]).includes("/actions")) ?? []) as [
      string?,
      RequestInit?,
    ];
    expect(url).toBe("/v1/instances/i1/actions");
    expect(JSON.parse(defined(init).body as string)).toEqual({ action: "restart" });
    expect((defined(init).headers as Record<string, string>)["idempotency-key"]).toBeTruthy();
  });
});
