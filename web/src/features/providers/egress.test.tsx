import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type { BootstrapRun, EgressRecovery, ProviderEgressStatus } from "@/api/types";
import { serverText } from "@/test/fixtures";
import { EgressStrip } from "./egress";

/** A fetch answer: `status` with the JSON of `body`. */
const json = (status: number, body: unknown) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));

function status(p: Partial<ProviderEgressStatus>): ProviderEgressStatus {
  return {
    revision: 3,
    route_revision: 5,
    desired_mode: "via_instance",
    bootstrap_consumed: true,
    selected_instance_id: "i1",
    phase: "recovery_required",
    selected_instance_name: "東京出口",
    selected_generation: null,
    reason_code: "KEY_MISSING",
    reason: serverText(
      "出口連線「東京出口」的 WireGuard 金鑰不在這台電腦或無法使用，無法自行恢復；可以用這台電腦目前的網路重新建立出口（重新直連，最多 10 分鐘）",
    ),
    bootstrap_expires_at: null,
    bootstrap: null,
    recovery: null,
    last_check: null,
    gates: [],
    observed_at: "2026-11-02T10:00:00Z",
    ...p,
  };
}

const eligible: EgressRecovery = {
  required: true,
  rebootstrap_eligible: true,
  reason_code: "KEY_MISSING",
  reason: serverText("金鑰不在這台電腦"),
};

function show(s: ProviderEgressStatus) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Number.POSITIVE_INFINITY }, mutations: { retry: false } },
  });
  qc.setQueryData(keys.system, { manager_connected: true });
  qc.setQueryData(keys.instances, []);
  qc.setQueryData(keys.providerEgress, s);
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <EgressStrip status={s} hasInstances />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("the egress needs recovery", () => {
  it("offers the rebootstrap only after the exposure is acknowledged, with the revision shown", async () => {
    const sent: { method?: string; headers: Record<string, string>; body: unknown }[] = [];
    const run: BootstrapRun = {
      id: "r1",
      kind: "rebootstrap",
      stage: "grant_active",
      child_instance_id: null,
      child_profile_id: null,
      grant_expires_at: "2026-11-02T10:10:00Z",
      promote_deadline: null,
      reason_code: null,
      reason: null,
      updated_at: "2026-11-02T10:00:00Z",
    };
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string, init?: RequestInit) => {
        if (url === "/v1/provider-egress/rebootstrap" && init?.method === "POST") {
          sent.push({
            method: init.method,
            headers: init.headers as Record<string, string>,
            body: JSON.parse(init.body as string),
          });
          return json(
            200,
            status({
              phase: "bootstrap_direct",
              bootstrap: run,
              bootstrap_expires_at: run.grant_expires_at,
              recovery: { ...eligible, rebootstrap_eligible: false },
            }),
          );
        }
        return json(404, { code: "NOT_FOUND", message: "找不到", retryable: false });
      }),
    );
    show(status({ recovery: eligible }));
    expect(screen.getByText(/金鑰不在這台電腦或無法使用，無法自行恢復/)).toBeTruthy();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "以一般網路重新建立出口…" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("這段時間的供應商請求不經 VPN")).toBeTruthy();
    expect(within(dialog).getByText(/只開放 10 分鐘/)).toBeTruthy();
    const confirm = within(dialog).getByRole<HTMLButtonElement>("button", { name: "開啟重新直連（10 分鐘）" });
    expect(confirm.disabled).toBe(true);
    await user.click(within(dialog).getByRole("checkbox"));
    expect(confirm.disabled).toBe(false);
    await user.click(confirm);
    await waitFor(() => {
      expect(sent).toHaveLength(1);
    });
    expect(sent[0]?.body).toEqual({ confirm_direct: true });
    expect(sent[0]?.headers["if-match"]).toBe('"3"');
    expect(sent[0]?.headers["idempotency-key"]).toBeTruthy();
  });
});
