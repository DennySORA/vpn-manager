import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type { SshHost, SshStatus } from "@/api/types";
import { view } from "@/test/fixtures";
import { SshPage } from "./ssh-page";

const T = "2026-10-27T00:00:00Z";
const work: SshHost = {
  id: "h1",
  kind: "host",
  alias: "work",
  host_name: "git.example.com",
  user: "deploy",
  port: null,
  identity_file: null,
  identities_only: false,
  gateway_id: "g1",
  server_alive_interval: 60,
  revision: 2,
  created_at: T,
  updated_at: T,
};
const status = (p: Partial<SshStatus> = {}): SshStatus => ({
  available: true,
  unavailable_reason: null,
  ssh_dir: "~/.ssh",
  managed_path: "~/.ssh/vpn-manager.conf",
  include_line: "Include ~/.ssh/vpn-manager.conf",
  include: "present",
  config_linked: false,
  config_problem: null,
  file: "ok",
  pending: false,
  existing: [
    {
      patterns: ["build"],
      host_name: "build.internal",
      user: null,
      port: null,
      proxied: false,
      wildcard: false,
      line: 3,
    },
    { patterns: ["*.corp"], host_name: null, user: null, port: null, proxied: false, wildcard: true, line: 9 },
  ],
  preview: "",
  proxy_command: null,
  control_path: null,
  current_text: null,
  last_error: null,
  ...p,
});

function renderAt(url: string, s: SshStatus = status()) {
  const sent: { method: string; url: string }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((u: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      if (method !== "GET") sent.push({ method, url: u });
      return Promise.resolve(
        new Response(JSON.stringify({ code: "NOT_FOUND", message: "找不到", retryable: false }), { status: 404 }),
      );
    }),
  );
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Number.POSITIVE_INFINITY }, mutations: { retry: false } },
  });
  qc.setQueryData(keys.ssh, s);
  qc.setQueryData(keys.sshHosts, [work]);
  qc.setQueryData(keys.gateways, view().gateways);
  qc.setQueryData(keys.instances, [view()]);
  const router = createMemoryRouter([{ path: "/ssh/:id?", Component: SshPage }], { initialEntries: [url] });
  render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { router, sent };
}

afterEach(() => vi.unstubAllGlobals());

describe("SSH hosts", () => {
  it("移除 states what happens to the host before anything is sent", async () => {
    const { sent } = renderAt("/ssh/h1");
    await userEvent.click(screen.getByRole("button", { name: "work 的更多操作" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "移除" }));
    const confirm = await screen.findByRole("alertdialog", { name: "移除「work」？" });
    expect(confirm.textContent).toContain("ssh work 將找不到這台主機");
    expect(confirm.textContent).toContain("這是最後一個項目");
    expect(sent).toEqual([]);
  });
});
