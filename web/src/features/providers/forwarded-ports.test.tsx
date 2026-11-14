import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keys } from "@/api/keys";
import type {
  AppView,
  ForwardedPort,
  ForwardedPorts,
  ForwardedPortSession,
  ForwardedPortUpdate,
  ForwardView,
  InstanceView,
  ProviderAccount,
  RuntimeProfile,
} from "@/api/types";
import { serverText } from "@/test/fixtures";
import { ForwardedPortsSection } from "./forwarded-ports";

const T = "2026-11-02T10:00:00Z";
/** A fetch answer: `status` with the JSON of `body`. */
const json = (status: number, body: unknown) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));

const account: ProviderAccount = {
  id: "acc1",
  provider: "airvpn",
  label: "我的 AirVPN",
  credential_ref: "s1",
  expires_at: null,
  observed_at: null,
  revision: 1,
  created_at: T,
  updated_at: T,
};

function port(p: Partial<ForwardedPort> = {}): ForwardedPort {
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

const DEVICE = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a697887";

function ports(list: ForwardedPort[]): ForwardedPorts {
  return {
    account_id: "acc1",
    ports: list,
    devices: [{ id: DEVICE, name: "Default" }],
    limit: 5,
    min_port: 2049,
    observed_at: T,
  };
}

const profile = {
  id: "p1",
  name: "AirVPN · 東京 albaldah",
  provider: "airvpn",
  source: { kind: "provider", account_id: "acc1", device_id: "Default", server_id: "albaldah" },
} as RuntimeProfile;

const connection = {
  spec: { id: "i1", name: "AirVPN 東京", profile_id: "p1", strict: false } as InstanceView["spec"],
  status: null,
  profile: {
    id: "p1",
    name: "AirVPN · 東京 albaldah",
    provider: "airvpn",
    entry: null,
    location: null,
    endpoint: "198.51.100.7:1637",
    ipv6: false,
    revision: 1,
  },
  gateways: [],
} as InstanceView;

const app = {
  spec: { id: "a1", instance_id: "i1", name: "qBittorrent", isolation: "proxy_env" },
  status: null,
} as AppView;

const forward = {
  binding: {
    id: "f1",
    instance_id: "i1",
    name: "BT",
    protocol: "both",
    tunnel_port: 35786,
    public_port: 35786,
    target_app_id: "a1",
    target_port: 35786,
  },
  status: null,
} as unknown as ForwardView;

/** The cache as the page would hold it; the forwarded ports themselves come from the stubbed API. */
function client(extra: (qc: QueryClient) => void = () => undefined) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Number.POSITIVE_INFINITY }, mutations: { retry: false } },
  });
  qc.setQueryData(keys.system, { manager_connected: true });
  qc.setQueryData(keys.instances, [connection]);
  qc.setQueryData(keys.profiles, [profile]);
  qc.setQueryData(keys.providerAccounts, [account]);
  qc.setQueryData(keys.apps, [app]);
  qc.setQueryData(keys.forwards, [forward]);
  extra(qc);
  return qc;
}

interface Sent {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: unknown;
}

const BASE = "/v1/provider-accounts/acc1/forwarded-ports";

/** One session of AirVPN's test of 40000. */
function session(s: Partial<ForwardedPortSession>): ForwardedPortSession {
  return {
    protocol: "tcp",
    ip_layer: "ipv4",
    server_name: "Alchiba",
    server_location: "Amsterdam",
    server_country: "nl",
    server_ip: "198.51.100.20",
    port: 40000,
    client_ip: "10.128.0.2",
    local_port: 40000,
    device_name: "Default",
    state: "open",
    word: "ok",
    message: serverText("Port is open."),
    ...s,
  };
}

/**
 * The API: the list (reads counted), a reservation (AirVPN picks 37587), a delete, a settings
 * change (the port read back; the DDNS name "taken" is refused), AirVPN's test (sessions on 40000
 * only), the DDNS check and the free-port search; every request but the list recorded.
 */
function stubApi(initial: ForwardedPort[]) {
  const sent: Sent[] = [];
  const reads = { list: 0 };
  let current = [...initial];
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      const u = url;
      if (u === BASE && method === "GET") {
        reads.list += 1;
        return json(200, ports(current));
      }
      sent.push({
        method,
        url: u,
        headers: (init?.headers ?? {}) as Record<string, string>,
        body: init?.body ? JSON.parse(init.body as string) : undefined,
      });
      if (u === BASE && method === "POST") {
        const asked = (JSON.parse(init?.body as string) as { port: number | null }).port;
        const made = port({ port: asked ?? 37587 });
        current = [...current, made];
        return json(201, made);
      }
      if (u === `${BASE}/ddns`) {
        return json(200, {
          names: [{ name: "my-box", sessions: 1, ipv4: "198.51.100.20", ipv6: null }],
          observed_at: T,
        });
      }
      if (u.startsWith(`${BASE}/free?count=`)) {
        return json(200, {
          count: Number(u.split("=")[1]),
          message: "Ports 41000-41002 are free right now.",
          observed_at: T,
        });
      }
      const at = Number(u.slice(BASE.length + 1).split("/")[0]);
      if (u.endsWith("/test") && method === "POST") {
        const sessions =
          at === 40000
            ? [
                session({}),
                session({
                  protocol: "udp",
                  state: "not_tested",
                  word: null,
                  message: serverText("AirVPN 只測試 TCP，這是 UDP 的連線"),
                }),
                session({
                  ip_layer: "ipv6",
                  server_ip: "2001:db8::20",
                  client_ip: "fd7d:76ee:e68f:a993::2",
                  state: "unknown",
                  word: "info",
                  message: serverText("Test queued."),
                }),
              ]
            : [];
        return json(200, { port: at, sessions, observed_at: T });
      }
      if (method === "PATCH") {
        const u2 = JSON.parse(init?.body as string) as ForwardedPortUpdate;
        if (u2.dns_name === "taken") {
          const said = "AirVPN：This DDNS name is already in use.";
          return json(502, {
            code: "PROVIDER_REJECTED",
            message: `AirVPN 沒有儲存：DDNS 名稱（${said}）；已儲存：協定`,
            retryable: false,
            field_errors: [{ path: "/dns_name", code: "NOT_SAVED", message: said }],
          });
        }
        current = current.map((p) =>
          p.port === at
            ? {
                ...p,
                ...(u2.notes !== undefined ? { notes: u2.notes || null } : {}),
                ...(u2.enabled !== undefined ? { enabled: u2.enabled } : {}),
                ...(u2.protocol ? { protocol: u2.protocol } : {}),
                ...(u2.ip_layer ? { ip_layer: u2.ip_layer } : {}),
                ...(u2.local_port ? { local_port: u2.local_port } : {}),
                ...(u2.dns_name !== undefined ? { dns_name: u2.dns_name || null } : {}),
              }
            : p,
        );
        return json(
          200,
          current.find((p) => p.port === at),
        );
      }
      if (method === "DELETE") {
        current = current.filter((p) => p.port !== at);
        return new Response(null, { status: 204 });
      }
      return json(404, { code: "NOT_FOUND", message: "找不到", retryable: false });
    }),
  );
  return Object.assign(sent, { reads });
}

/** A port row's action from its ⋯ menu (the row's one menu: 建立轉發, 設定 | 刪除). */
async function fromMenu(user: ReturnType<typeof userEvent.setup>, port: number, item: string) {
  await user.click(await screen.findByRole("button", { name: `連入埠 ${port} 的更多操作` }));
  await user.click(await screen.findByRole("menuitem", { name: item }));
}

function showSection(qc = client()) {
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ForwardedPortsSection account={account} egressUsable />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => vi.unstubAllGlobals());

describe("連入埠 on the AirVPN account page", () => {
  it("deletes only after a confirmation that names the forwards it cuts off", async () => {
    const sent = stubApi([port()]);
    showSection();
    const user = userEvent.setup();
    await fromMenu(user, 35786, "刪除");
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/轉發「BT」使用這個埠/)).toBeTruthy();
    expect(sent).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: "刪除連入埠" }));
    await waitFor(() => {
      expect(sent).toHaveLength(1);
    });
    expect(sent[0]).toMatchObject({ method: "DELETE", url: "/v1/provider-accounts/acc1/forwarded-ports/35786" });
    await waitFor(() => {
      expect(screen.queryByText("35786")).toBeNull();
    });
  });
});
