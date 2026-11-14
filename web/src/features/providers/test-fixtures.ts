// Test data for the provider tests (not used by the app).
import type { ForwardedPort, ForwardedPorts, ProviderAccount, ProviderEgressStatus, ProviderGate } from "@/api/types";

const T = "2026-11-02T10:00:00Z";

export function account(p: Partial<ProviderAccount> = {}): ProviderAccount {
  return {
    id: "a1",
    provider: "airvpn",
    label: "我的 AirVPN",
    credential_ref: "s1",
    expires_at: "2026-11-25T00:00:00Z",
    observed_at: T,
    revision: 1,
    created_at: T,
    updated_at: T,
    ...p,
  };
}

export function gate(p: Partial<ProviderGate> = {}): ProviderGate {
  return {
    provider: "airvpn",
    gate: "forward",
    status: "unverified",
    reason: {
      en: "Not read from the AirVPN site yet",
      "zh-TW": "還沒有經 AirVPN 網站讀取連入埠",
      ja: "まだ AirVPN のサイトから読み取っていません",
    },
    observed_at: null,
    instance_id: null,
    ...p,
  };
}

export function egress(p: Partial<ProviderEgressStatus> = {}): ProviderEgressStatus {
  return {
    revision: 3,
    route_revision: 5,
    desired_mode: "via_instance",
    bootstrap_consumed: true,
    selected_instance_id: "i1",
    phase: "vpn_ready",
    selected_instance_name: "東京出口",
    selected_generation: 1,
    reason_code: null,
    reason: null,
    bootstrap_expires_at: null,
    bootstrap: null,
    recovery: null,
    last_check: null,
    gates: [],
    observed_at: T,
    ...p,
  };
}

export function forwardedPort(p: Partial<ForwardedPort> = {}): ForwardedPort {
  return {
    port: 35786,
    pool: 2,
    enabled: true,
    protocol: "both",
    ip_layer: "both",
    device_id: null,
    device_name: null,
    local_port: p.port ?? 35786,
    dns_name: null,
    notes: null,
    ...p,
  };
}

export function forwardedPorts(list: ForwardedPort[], accountId = "a1"): ForwardedPorts {
  return { account_id: accountId, ports: list, devices: [], limit: 5, min_port: 2049, observed_at: T };
}
