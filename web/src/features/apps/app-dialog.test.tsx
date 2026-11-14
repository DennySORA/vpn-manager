import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type { Capability, CapabilityState, ExecutableCheck } from "@/api/types";
import { serverText, view } from "@/test/fixtures";
import { AppDialog } from "./app-dialog";

const SHA = "ab".repeat(32);
const T = "2026-10-27T12:00:00Z";

function caps(enforced: CapabilityState): Capability[] {
  return [
    { name: "app_proxy_env", state: "supported", reason: serverText("只設定代理環境變數") },
    {
      name: "app_enforced_proxy",
      state: enforced,
      reason: serverText(enforced === "supported" ? "macOS Seatbelt" : "Seatbelt（sandbox-exec）只在 macOS 提供"),
    },
    {
      name: "app_strict_netns",
      state: "unsupported",
      reason: serverText("嚴格隔離（rootless network namespace）只在 Linux 提供"),
    },
  ];
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

interface Call {
  url: string;
  method: string;
  body: Record<string, unknown> | null;
}

/**
 * The new-App dialog; the manager answers executable checks and creates. With `seeded` the lists
 * are already cached when it opens, otherwise they arrive over the network afterwards (a dialog
 * opened from the URL on a fresh page load).
 */
function open(capabilities: Capability[], checkResult?: (path: string) => ExecutableCheck, seeded = true) {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const u = url;
      const method = init?.method ?? "GET";
      calls.push({
        url: u,
        method,
        body: init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null,
      });
      if (u === "/v1/instances") return Promise.resolve(json([view()]));
      if (u === "/v1/gateways") return Promise.resolve(json(view().gateways));
      if (u === "/v1/system/capabilities") return Promise.resolve(json(capabilities));
      if (u.startsWith("/v1/apps/executable-check")) {
        const path = new URL(u, "http://127.0.0.1").searchParams.get("path") ?? "";
        const c: ExecutableCheck = checkResult?.(path) ?? {
          path,
          kind: "file",
          resolved: path,
          sha256: SHA,
          size: 1234,
          issues: [],
          ok: true,
          app_class: null,
        };
        return Promise.resolve(json(c));
      }
      // The manager's free-port answer: the asked port itself.
      if (u.startsWith("/v1/ports/free"))
        return Promise.resolve(json({ port: Number(new URL(u, "http://127.0.0.1").searchParams.get("from")) }));
      if (u === "/v1/apps" && method === "POST") {
        const input = JSON.parse(init?.body as string) as Record<string, unknown>;
        return Promise.resolve(
          json(
            { spec: { ...input, id: "a1", approval: null, revision: 1, created_at: T, updated_at: T }, status: null },
            201,
          ),
        );
      }
      return Promise.resolve(json({ code: "NOT_FOUND", message: "找不到", retryable: false }, 404));
    }),
  );
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Number.POSITIVE_INFINITY }, mutations: { retry: false } },
  });
  if (seeded) {
    qc.setQueryData(keys.instances, [view()]);
    qc.setQueryData(keys.gateways, view().gateways);
    qc.setQueryData(keys.capabilities, capabilities);
    qc.setQueryData(keys.system, {
      data_dir: "/home/u/.local/share/vpn-manager",
      host_addresses: ["192.168.20.100"],
      controller_port: 18765,
    });
  }
  const onOpenChange = vi.fn();
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AppDialog open onOpenChange={onOpenChange} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { calls, onOpenChange };
}

afterEach(() => vi.unstubAllGlobals());

describe("new managed App dialog", () => {
  it("approves exactly the file the check showed", async () => {
    const { calls, onOpenChange } = open(caps("supported"));
    await userEvent.type(screen.getByLabelText(/^名稱/), "curl 迴圈");
    await userEvent.type(screen.getByLabelText(/^執行檔/), "/usr/bin/curl");
    await screen.findByText("可以執行");
    expect(screen.getByText(/abababababab…abab/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "新增參數" }));
    await userEvent.type(screen.getByLabelText("參數 1"), "--socks5-hostname=127.0.0.1:{{gateway_port}");
    // The argv as it will run, with the Gateway's port in place.
    expect(screen.getByText("/usr/bin/curl --socks5-hostname=127.0.0.1:1080")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "建立 App" }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === "POST")).toBe(true);
    });
    const post = calls.find((c) => c.method === "POST");
    expect(post?.body).toMatchObject({
      name: "curl 迴圈",
      executable: "/usr/bin/curl",
      isolation: "enforced_proxy",
      gateway_id: "g1",
      args: ["--socks5-hostname=127.0.0.1:{gateway_port}"],
      executable_sha256: SHA,
    });
    await waitFor(() => {
      expect(onOpenChange).toHaveBeenCalledWith(false);
    });
  });
});
