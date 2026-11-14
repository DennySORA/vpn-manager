import type {
  AppIsolation,
  AppRunState,
  AppView,
  BlocklistView,
  BuiltinBlocklistInfo,
  InstanceStatus,
  InstanceView,
  LiveRates,
  SandboxRates,
  Text,
} from "@/api/types";

export const NOW = Date.parse("2026-10-26T12:00:00Z");

/** Text the server wrote, the same words in every language (the tests read the page in Traditional Chinese). */
export function serverText(words: string): Text {
  return { en: words, "zh-TW": words, ja: words };
}

export function status(p: Partial<InstanceStatus> = {}): InstanceStatus {
  return {
    instance_id: "i1",
    spec_revision: 1,
    intent: {
      desired: "running",
      manual_stop: false,
      emergency_latched: false,
      intent_revision: 1,
      persistence: "durable",
    },
    phase: "ready",
    enforcement: "tunnel_only",
    health: "healthy",
    running: {
      generation: 1,
      profile_revision: 1,
      dns_profile_revision: null,
      security_profile_revision: null,
      started_at: "2026-10-26T11:59:00Z",
      ready_at: "2026-10-26T11:59:01Z",
      pid: 42,
      pending_changes: [],
      policy: null,
      resources: null,
      bandwidth: null,
      transport: null,
    },
    tunnel: {
      endpoint: "203.0.113.10:51820",
      last_handshake_at: "2026-10-26T11:59:30Z",
      wg_rx_bytes: "1024",
      wg_tx_bytes: "2048",
      ipv6: true,
    },
    dns: { healthy: true, last_probe_at: "2026-10-26T11:59:50Z", last_error: null, fallback: null, interrupted: null },
    gateways: [{ gateway_id: "g1", state: "serving", active_tcp: 1, active_udp: 0, error: null }],
    recovery: { attempt: 0, next_retry_at: null, last_fault: null, unreachable_attempts: 0 },
    observed_at: "2026-10-26T11:59:59Z",
    ...p,
  };
}

export function view(p: { status?: InstanceStatus | null; name?: string } = {}): InstanceView {
  return {
    spec: {
      id: "i1",
      name: p.name ?? "東京出口",
      profile_id: "p1",
      dns_profile_id: null,
      security_profile_id: null,
      purpose: "general",
      limits: { max_tcp_flows: 1024, max_udp_flows: 512, memory_mib: 512, download_bps: null, upload_bps: null },
      strict: false,
      transport: { kind: "builtin", key: "auto" },
      revision: 1,
      created_at: "2026-10-26T11:00:00Z",
      updated_at: "2026-10-26T11:00:00Z",
    },
    status: p.status === undefined ? status() : p.status,
    profile: {
      id: "p1",
      name: "Lab",
      provider: "generic",
      entry: null,
      location: { country_code: "JP", country: "日本", city: "東京", server: null },
      endpoint: "203.0.113.10:51820",
      ipv6: true,
      revision: 1,
    },
    gateways: [
      {
        id: "g1",
        instance_id: "i1",
        name: "瀏覽器",
        kind: "mixed",
        port: 1080,
        enabled: true,
        udp: true,
        max_connections: 1024,
        revision: 1,
        created_at: "2026-10-26T11:00:00Z",
        updated_at: "2026-10-26T11:00:00Z",
      },
    ],
  };
}

/** The catalogue entries of the built-in lists, as the server describes them. */
export const BUILTIN: Record<string, BuiltinBlocklistInfo> = {
  "spamhaus-drop-v4": {
    key: "spamhaus-drop-v4",
    name: { en: "Spamhaus DROP (IPv4)", "zh-TW": "Spamhaus DROP（IPv4）", ja: "Spamhaus DROP（IPv4）" },
    url: "https://www.spamhaus.org/drop/drop_v4.json",
    homepage: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
    family: "ipv4",
    format: "json_lines",
    refresh_hours: 24,
    description: serverText("Spamhaus 的「Don't Route Or Peer」清單：被職業垃圾郵件或網路犯罪集團劫持、租用的網段。"),
    terms: serverText("Spamhaus 免費提供，不限規模或用途；使用時須註明來源 The Spamhaus Project。"),
    terms_url: "https://www.spamhaus.org/drop/terms/",
  },
  "dshield-block": {
    key: "dshield-block",
    name: { en: "DShield recommended block list", "zh-TW": "DShield 建議封鎖清單", ja: "DShield 推奨ブロックリスト" },
    url: "https://feeds.dshield.org/block.txt",
    homepage: "https://isc.sans.edu/feeds_doc.html",
    family: "ipv4",
    format: "tab_ranges",
    refresh_hours: 6,
    description: serverText(
      "SANS Internet Storm Center（DShield）的建議封鎖清單：最近三天掃描最多目標的 20 個 /24 網段。",
    ),
    terms: serverText("SANS ISC 允許註明來源後使用（CC BY-NC-SA；用來保護自己的網路可以，不得轉售資料）。"),
    terms_url: "https://isc.sans.edu/api/",
  },
};

/**
 * A blocklist as `GET /v1/blocklists` answers: an uploaded list of one entry, or with `builtin` the
 * named built-in list (part of the default policy while enabled; `awaiting` before its first
 * download).
 */
export function blocklistView(
  id: string,
  name: string,
  p: {
    builtin?: string;
    enabled?: boolean;
    awaiting?: boolean;
    waiting?: string | null;
    specialFiltered?: number;
  } = {},
): BlocklistView {
  const info = p.builtin ? BUILTIN[p.builtin] : undefined;
  const enabled = p.enabled ?? true;
  const awaiting = Boolean(info && p.awaiting);
  const T = "2026-10-27T00:00:00Z";
  return {
    blocklist: {
      id,
      name,
      source: info ? { kind: "url", url: info.url, refresh_hours: info.refresh_hours } : { kind: "upload" },
      stats: {
        lines: awaiting ? 0 : 1,
        entries: awaiting ? 0 : 1,
        comments: 0,
        blank: 0,
        invalid: 0,
        host_bits_normalized: 0,
        mapped_ipv4: 0,
        v4_ranges: awaiting ? 0 : 1,
        v6_ranges: 0,
        v4_addresses: awaiting ? 0 : 1,
        v6_addresses: "0",
        raw_bytes: awaiting ? 0 : 10,
        parsed_bytes: 24,
        special_filtered: p.specialFiltered ?? 0,
      },
      content_sha256: "a".repeat(64),
      content_updated_at: T,
      invalid_lines: [],
      builtin: info ? info.key : null,
      enabled,
      revision: 1,
      created_at: T,
      updated_at: T,
    },
    refresh: null,
    stale: false,
    next_refresh_at: info && enabled ? T : null,
    used_by: [],
    builtin: info ?? null,
    default_policy: Boolean(info) && enabled,
    awaiting_content: awaiting,
    waiting: info && enabled && p.waiting ? serverText(p.waiting) : null,
  };
}

export function rates(at: number, rx: number, tx = 0, generation = 1): LiveRates {
  return {
    instance_id: "i1",
    at: new Date(at).toISOString(),
    generation,
    payload_rx_bps: rx,
    payload_tx_bps: tx,
    wg_rx_bps: rx,
    wg_tx_bps: tx,
    active_tcp: 1,
    active_udp: 0,
    shaping: null,
    cpu_core_pct: null,
    rss_bytes: null,
    gateways: [],
    sandbox: null,
  };
}

/** A strict sandbox's Apps over one interval (bit/s). */
export function sandboxRates(rx: number, tx = 0, p: Partial<SandboxRates> = {}): SandboxRates {
  return { rx_bps: rx, tx_bps: tx, active_tcp: 3_800, active_udp: 4_096, evicted: 0, table_full: 0, ...p };
}

/** A managed App of connection i1 (strict isolation unless said otherwise); `state: null`: the manager has not said. */
export function appView(
  p: { id?: string; name?: string; instanceId?: string; isolation?: AppIsolation; state?: AppRunState | null } = {},
): AppView {
  const T = "2026-10-27T12:00:00Z";
  const id = p.id ?? "a1";
  const isolation = p.isolation ?? "strict_netns";
  const state = p.state === undefined ? "running" : p.state;
  const running = state === "running";
  return {
    spec: {
      id,
      instance_id: p.instanceId ?? "i1",
      name: p.name ?? "P2P client",
      executable: "/usr/local/bin/p2pd",
      args: [],
      working_dir: null,
      env: [],
      isolation,
      gateway_id: isolation === "strict_netns" ? null : "g1",
      restart_on_recovery: true,
      writable_paths: [],
      confine_writes: false,
      stop_grace_secs: 10,
      approval: { path: "/usr/local/bin/p2pd", sha256: "ab".repeat(32), size: 1000, approved_at: T, app_class: null },
      limits: { memory_mib: null, cpu_percent: null, processes: null, open_files: null },
      access_ports: [],
      revision: 1,
      created_at: T,
      updated_at: T,
    },
    status:
      state === null
        ? null
        : {
            app_id: id,
            desired: running ? "running" : "stopped",
            intent_persistence: "durable",
            state,
            run_revision: 1,
            pid: running ? 4242 : null,
            started_at: running ? T : null,
            last_exit: null,
            last_error: null,
            isolation: running ? isolation : null,
            gateway_id: null,
            gateway_port: null,
            process_count: running ? 2 : null,
            listeners: [],
            sandbox_denials: null,
            resources: null,
            access: [],
            observed_at: T,
          },
  };
}
