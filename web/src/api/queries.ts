// Server state (TanStack Query). The controller is the only source of truth; SSE events patch
// these caches (see events.ts) and a resync reloads them.

import {
  keepPreviousData,
  type QueryClient,
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { noteServerTime } from "@/lib/server-clock";
import { ApiFailure, apiGet, apiMutate, apiPreview } from "./client";
import { connectionSnapshot, newerAppStatus, newerForwardStatus, patchAppStatus } from "./events";
import { keys } from "./keys";
import type {
  Accepted,
  AppAction,
  AppActionResult,
  AppInput,
  AppLog,
  AppProcesses,
  AppView,
  Ban,
  BlocklistInput,
  BlocklistUpdate,
  BlocklistView,
  BuiltinBlocklistState,
  Capability,
  ExecutableCheck,
  ForwardInput,
  ForwardView,
  ForwardedPort,
  ForwardedPortDdns,
  ForwardedPorts,
  ForwardedPortSearch,
  ForwardedPortTest,
  ForwardedPortUpdate,
  InboundSummary,
  UnbanResult,
  DnsProfile,
  DnsProfileInput,
  GatewayInput,
  GatewaySpec,
  ImportRequest,
  ImportResult,
  InstanceInput,
  InstanceView,
  LifecycleAction,
  LiveRates,
  MetricsRange,
  MetricsSeries,
  MetricsStatus,
  ProfileUpdate,
  RuntimeProfile,
  SecretMetadata,
  SecurityProfile,
  SecurityProfileInput,
  Settings,
  SettingsInput,
  BuiltinTransport,
  TransportProfile,
  TransportProfileInput,
  ProviderAccount,
  ProviderAccountInput,
  ProviderConnectInput,
  ProviderConnectResult,
  Operation,
  ProviderDevice,
  ProviderServerChangeInput,
  ProviderEgressInput,
  ProviderEgressStatus,
  ProviderRebootstrapInput,
  ProviderIpCheck,
  ProviderServer,
  SshActionResult,
  SshHost,
  SshHostInput,
  SshStatus,
  SshTestResult,
  SystemStatus,
} from "./types";

export { keys } from "./keys";

/** The system status, polled; each answer also tells the browser the server's time (`observed_at`). */
export function useSystemStatus() {
  return useQuery({
    queryKey: keys.system,
    queryFn: async ({ signal }) => {
      const status = await apiGet<SystemStatus>("/v1/system/status", signal);
      noteServerTime(status.observed_at);
      return status;
    },
    refetchInterval: 15_000,
  });
}

export function useCapabilities() {
  return useQuery({
    queryKey: keys.capabilities,
    queryFn: ({ signal }) => apiGet<Capability[]>("/v1/system/capabilities", signal),
    staleTime: 60_000,
  });
}

/**
 * A refetch must not undo newer facts: per Instance the status with the later `observed_at`
 * wins (an SSE update may land while the request is in flight), and a missing status does not
 * erase a known one while the manager is connected (one slow Inspect is not "unknown").
 */
export function mergeStatuses(
  prev: InstanceView[] | undefined,
  next: InstanceView[],
  managerConnected: boolean | null,
): InstanceView[] {
  if (!prev) return next;
  const before = new Map(prev.map((v) => [v.spec.id, v.status]));
  return next.map((v) => {
    const old = before.get(v.spec.id);
    if (!old) return v;
    if (!v.status) return managerConnected === true ? { ...v, status: old } : v;
    return Date.parse(old.observed_at) > Date.parse(v.status.observed_at) ? { ...v, status: old } : v;
  });
}

function instancesQuery(qc: QueryClient) {
  return {
    queryKey: keys.instances,
    queryFn: async ({ signal }: { signal: AbortSignal }) =>
      mergeStatuses(
        qc.getQueryData<InstanceView[]>(keys.instances),
        await apiGet<InstanceView[]>("/v1/instances", signal),
        connectionSnapshot().manager,
      ),
    // SSE keeps status fresh; this is the safety net when events are missed.
    refetchInterval: 20_000,
  };
}

export function useInstances() {
  const qc = useQueryClient();
  return useQuery(instancesQuery(qc));
}

/**
 * One value derived from the connections (a count, a label): the caller re-renders only when that value changes, not
 * on every status event (one arrives every two seconds per running connection).
 */
export function useInstancesSelect<T>(select: (views: InstanceView[]) => T) {
  const qc = useQueryClient();
  return useQuery({ ...instancesQuery(qc), select });
}

export function useProfiles() {
  return useQuery({
    queryKey: keys.profiles,
    queryFn: ({ signal }) => apiGet<RuntimeProfile[]>("/v1/profiles", signal),
  });
}

export function useGateways() {
  return useQuery({ queryKey: keys.gateways, queryFn: ({ signal }) => apiGet<GatewaySpec[]>("/v1/gateways", signal) });
}

/**
 * A local port the controller found free (no Gateway uses it and nothing else listens on it), at or
 * after `from`. 409 when none is; callers fall back to their own suggestion on any failure.
 */
export function useFreePort(from: number, enabled = true) {
  return useQuery({
    queryKey: keys.freePort(from),
    queryFn: ({ signal }) => apiGet<{ port: number }>(`/v1/ports/free?from=${from}`, signal),
    enabled,
    staleTime: 0,
    retry: false,
  });
}

export function useDnsProfiles() {
  return useQuery({
    queryKey: keys.dns,
    queryFn: ({ signal }) => apiGet<DnsProfile[]>("/v1/dns-profiles", signal),
  });
}

export function useSecurityProfiles() {
  return useQuery({
    queryKey: keys.security,
    queryFn: ({ signal }) => apiGet<SecurityProfile[]>("/v1/security-profiles", signal),
  });
}

export function useSecrets() {
  return useQuery({ queryKey: keys.secrets, queryFn: ({ signal }) => apiGet<SecretMetadata[]>("/v1/secrets", signal) });
}

export function useSettings() {
  return useQuery({ queryKey: keys.settings, queryFn: ({ signal }) => apiGet<Settings>("/v1/settings", signal) });
}

export function useLiveRates(id: string | undefined) {
  return useQuery({
    queryKey: keys.live(id ?? "none"),
    queryFn: ({ signal }) => apiGet<LiveRates[]>(`/v1/instances/${id}/live`, signal),
    enabled: Boolean(id),
    staleTime: Number.POSITIVE_INFINITY,
  });
}

/** How often a metrics answer changes: about one new point per refresh. */
export function metricsRefetchMs(resolutionSecs: number | undefined): number {
  if (resolutionSecs === 1) return 5_000;
  if (resolutionSecs === undefined || resolutionSecs <= 5) return 10_000;
  return resolutionSecs <= 60 ? 30_000 : 300_000;
}

/**
 * Persisted metrics of a scope over a range. Polled about once per new point; switching range or
 * scope keeps the previous answer on screen (marked as placeholder) until the new one lands.
 */
export function useMetricsSeries(range: MetricsRange, scope: string) {
  return useQuery({
    queryKey: keys.metricsSeries(range, scope),
    queryFn: ({ signal }) =>
      apiGet<MetricsSeries>(
        `/v1/metrics/series?range=${encodeURIComponent(range)}&scope=${encodeURIComponent(scope)}`,
        signal,
      ),
    placeholderData: keepPreviousData,
    refetchInterval: (q) => metricsRefetchMs(q.state.data?.resolution_secs),
    // A missing Instance or Gateway (404) or a refused query will not fix itself.
    retry: (n, e) => !(e instanceof ApiFailure && e.status >= 400 && e.status < 500) && n < 2,
  });
}

export function useMetricsStatus() {
  return useQuery({
    queryKey: keys.metricsStatus,
    queryFn: ({ signal }) => apiGet<MetricsStatus>("/v1/metrics/status", signal),
    refetchInterval: 30_000,
  });
}

/** Live rate series of several Instances at once (id → samples). */
export function useLiveRatesMap(ids: string[]): Map<string, LiveRates[] | undefined> {
  const results = useQueries({
    queries: ids.map((id) => ({
      queryKey: keys.live(id),
      queryFn: ({ signal }: { signal: AbortSignal }) => apiGet<LiveRates[]>(`/v1/instances/${id}/live`, signal),
      staleTime: Number.POSITIVE_INFINITY,
    })),
  });
  return new Map(ids.map((id, i) => [id, results[i]?.data]));
}

// --- Mutations --------------------------------------------------------------------------------

/** A mutation variable that carries the idempotency key of the user's intent. */
export interface Keyed {
  key: string;
}

export function useCreateInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { input: InstanceInput }) =>
      apiMutate<InstanceView>("POST", "/v1/instances", v.input, { idempotencyKey: v.key }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.instances }),
  });
}

export function useUpdateInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; revision: number; input: InstanceInput }) =>
      apiMutate<InstanceView>("PUT", `/v1/instances/${v.id}`, v.input, { idempotencyKey: v.key, ifMatch: v.revision }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.instances }),
  });
}

export function useDeleteInstance() {
  const qc = useQueryClient();
  return useMutation({
    /** `gateways`: exactly the Gateways the user confirmed; they go with the Instance or nothing does. */
    mutationFn: (v: Keyed & { id: string; revision: number; gateways: string[] }) =>
      apiMutate<undefined>("DELETE", `/v1/instances/${v.id}?gateways=${v.gateways.join(",")}`, undefined, {
        idempotencyKey: v.key,
        ifMatch: v.revision,
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.instances });
      void qc.invalidateQueries({ queryKey: keys.gateways });
    },
  });
}

export function useLifecycle() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; action: LifecycleAction }) =>
      apiMutate<Accepted>("POST", `/v1/instances/${v.id}/actions`, { action: v.action }, { idempotencyKey: v.key }),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.instances }),
  });
}

export function useEmergencyStop() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string }) =>
      apiMutate<Accepted>("POST", `/v1/instances/${v.id}/emergency-stop`, {}, { idempotencyKey: v.key }),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.instances }),
  });
}

export function useImportProfile() {
  const qc = useQueryClient();
  return useMutation({
    // The request holds a private key: drop the finished mutation (and its variables) at once.
    gcTime: 0,
    mutationFn: (v: Keyed & { request: ImportRequest }) =>
      apiMutate<ImportResult>("POST", "/v1/profiles/import", v.request, { idempotencyKey: v.key }),
    onSuccess: (r) => {
      if (r.data.profile) {
        void qc.invalidateQueries({ queryKey: keys.profiles });
        void qc.invalidateQueries({ queryKey: keys.secrets });
      }
    },
  });
}

export function useUpdateProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; revision: number; input: ProfileUpdate }) =>
      apiMutate<RuntimeProfile>("PUT", `/v1/profiles/${v.id}`, v.input, { idempotencyKey: v.key, ifMatch: v.revision }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.profiles });
      void qc.invalidateQueries({ queryKey: keys.instances });
    },
  });
}

/** Point a provider-built profile at another server of its account; its device and key stay. */
export function useChangeProviderServer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { account: string; profile: string; revision: number; input: ProviderServerChangeInput }) =>
      apiMutate<RuntimeProfile>("POST", `/v1/provider-accounts/${v.account}/profiles/${v.profile}/server`, v.input, {
        idempotencyKey: v.key,
        ifMatch: v.revision,
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.profiles });
      void qc.invalidateQueries({ queryKey: keys.instances });
    },
  });
}

export function useDeleteProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; revision: number }) =>
      apiMutate<undefined>("DELETE", `/v1/profiles/${v.id}`, undefined, { idempotencyKey: v.key, ifMatch: v.revision }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.profiles });
      void qc.invalidateQueries({ queryKey: keys.secrets });
    },
  });
}

export function useCreateGateway() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { input: GatewayInput }) =>
      apiMutate<GatewaySpec>("POST", "/v1/gateways", v.input, { idempotencyKey: v.key }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.gateways });
      void qc.invalidateQueries({ queryKey: keys.instances });
    },
  });
}

export function useUpdateGateway() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; revision: number; input: GatewayInput }) =>
      apiMutate<GatewaySpec>("PUT", `/v1/gateways/${v.id}`, v.input, { idempotencyKey: v.key, ifMatch: v.revision }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.gateways });
      void qc.invalidateQueries({ queryKey: keys.instances });
    },
  });
}

export function useDeleteGateway() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; revision: number }) =>
      apiMutate<undefined>("DELETE", `/v1/gateways/${v.id}`, undefined, { idempotencyKey: v.key, ifMatch: v.revision }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.gateways });
      void qc.invalidateQueries({ queryKey: keys.instances });
    },
  });
}

export function useSaveDnsProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id?: string | undefined; revision?: number | undefined; input: DnsProfileInput }) =>
      v.id
        ? apiMutate<DnsProfile>("PUT", `/v1/dns-profiles/${v.id}`, v.input, {
            idempotencyKey: v.key,
            ifMatch: v.revision,
          })
        : apiMutate<DnsProfile>("POST", "/v1/dns-profiles", v.input, { idempotencyKey: v.key }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.dns }),
  });
}

export function useDeleteDnsProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; revision: number }) =>
      apiMutate<undefined>("DELETE", `/v1/dns-profiles/${v.id}`, undefined, {
        idempotencyKey: v.key,
        ifMatch: v.revision,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.dns }),
  });
}

export function useTransportProfiles() {
  return useQuery({
    queryKey: keys.transport,
    queryFn: ({ signal }) => apiGet<TransportProfile[]>("/v1/transport-profiles", signal),
  });
}

/** The transport profiles that are part of the program: they change only when the program does. */
export function useBuiltinTransports() {
  return useQuery({
    queryKey: keys.builtinTransports,
    queryFn: ({ signal }) => apiGet<BuiltinTransport[]>("/v1/transport-profiles/builtin", signal),
    staleTime: Number.POSITIVE_INFINITY,
  });
}

export function useSaveTransportProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (
      v: Keyed & { id?: string | undefined; revision?: number | undefined; input: TransportProfileInput },
    ) =>
      v.id
        ? apiMutate<TransportProfile>("PUT", `/v1/transport-profiles/${v.id}`, v.input, {
            idempotencyKey: v.key,
            ifMatch: v.revision,
          })
        : apiMutate<TransportProfile>("POST", "/v1/transport-profiles", v.input, { idempotencyKey: v.key }),
    // A running connection that uses it applies the change at once: its status changes too.
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.transport });
      void qc.invalidateQueries({ queryKey: keys.instances });
    },
  });
}

export function useSaveSecurityProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id?: string | undefined; revision?: number | undefined; input: SecurityProfileInput }) =>
      v.id
        ? apiMutate<SecurityProfile>("PUT", `/v1/security-profiles/${v.id}`, v.input, {
            idempotencyKey: v.key,
            ifMatch: v.revision,
          })
        : apiMutate<SecurityProfile>("POST", "/v1/security-profiles", v.input, { idempotencyKey: v.key }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.security });
      // Which profiles use a list, and the overlay running connections enforce, change with it.
      void qc.invalidateQueries({ queryKey: keys.blocklists });
      void qc.invalidateQueries({ queryKey: keys.instances });
    },
  });
}

// --- IP blocklists and bans ----------------------------------------------------------------------

export function useBlocklists() {
  return useQuery({
    queryKey: keys.blocklists,
    queryFn: ({ signal }) => apiGet<BlocklistView[]>("/v1/blocklists", signal),
    // Automatic refreshes happen on the server: pick up their result now and then.
    refetchInterval: 30_000,
  });
}

/** Active bans of one connection (or of all with `null`); newest first. */
export function useBans(instance: string | null) {
  return useQuery({
    queryKey: keys.bans(instance),
    queryFn: ({ signal }) =>
      apiGet<Ban[]>(`/v1/bans${instance ? `?instance=${encodeURIComponent(instance)}` : ""}`, signal),
    // Bans appear when a worker decides them: poll while the view is open.
    refetchInterval: 10_000,
  });
}

/** Port forwards per connection: auto-ban only acts on connections forwarded in. */
export function useInboundSummary() {
  return useQuery({
    queryKey: keys.inbound,
    queryFn: ({ signal }) => apiGet<InboundSummary>("/v1/security/inbound", signal),
    staleTime: 30_000,
  });
}

function useBlocklistsChanged() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: keys.blocklists });
    void qc.invalidateQueries({ queryKey: keys.security });
    void qc.invalidateQueries({ queryKey: keys.instances });
  };
}

export function useCreateBlocklist() {
  const done = useBlocklistsChanged();
  return useMutation({
    // The variables may hold an 8 MiB list: nothing keeps them after the call.
    gcTime: 0,
    mutationFn: (v: Keyed & { input: BlocklistInput }) =>
      apiMutate<BlocklistView>("POST", "/v1/blocklists", v.input, { idempotencyKey: v.key }),
    onSuccess: done,
  });
}

export function useUpdateBlocklist() {
  const done = useBlocklistsChanged();
  return useMutation({
    gcTime: 0,
    mutationFn: (v: Keyed & { id: string; revision: number; input: BlocklistUpdate }) =>
      apiMutate<BlocklistView>("PUT", `/v1/blocklists/${v.id}`, v.input, {
        idempotencyKey: v.key,
        ifMatch: v.revision,
      }),
    onSuccess: done,
  });
}

/** Download a URL source now; a failure is recorded on the list (stale) as well as returned. */
export function useRefreshBlocklist() {
  const done = useBlocklistsChanged();
  return useMutation({
    mutationFn: (v: Keyed & { id: string }) =>
      apiMutate<BlocklistView>("POST", `/v1/blocklists/${v.id}/refresh`, {}, { idempotencyKey: v.key }),
    onSettled: done,
  });
}

export function useDeleteBlocklist() {
  const done = useBlocklistsChanged();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; revision: number }) =>
      apiMutate<undefined>("DELETE", `/v1/blocklists/${v.id}`, undefined, {
        idempotencyKey: v.key,
        ifMatch: v.revision,
      }),
    onSuccess: done,
  });
}

/** The built-in catalogue: each list's source and terms, and which ones the user deleted. */
export function useBuiltinBlocklists() {
  return useQuery({
    queryKey: keys.builtinBlocklists,
    queryFn: ({ signal }) => apiGet<BuiltinBlocklistState[]>("/v1/blocklists/builtin", signal),
  });
}

/** Bring back a built-in list the user deleted (it is never re-added on its own). */
export function useRestoreBuiltinBlocklist() {
  const done = useBlocklistsChanged();
  return useMutation({
    mutationFn: (v: Keyed & { builtin: string }) =>
      apiMutate<BlocklistView>(
        "POST",
        `/v1/blocklists/builtin/${encodeURIComponent(v.builtin)}/restore`,
        {},
        { idempotencyKey: v.key },
      ),
    onSuccess: done,
  });
}

/** Lift a ban. `data` is undefined when a replay of an earlier lift answered 204. */
export function useUnban() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string }) =>
      apiMutate<UnbanResult | undefined>("DELETE", `/v1/bans/${v.id}`, undefined, { idempotencyKey: v.key }),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.allBans }),
  });
}

export function useDeleteSecurityProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; revision: number }) =>
      apiMutate<undefined>("DELETE", `/v1/security-profiles/${v.id}`, undefined, {
        idempotencyKey: v.key,
        ifMatch: v.revision,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.security }),
  });
}

export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    // The server takes the revision from If-Match.
    mutationFn: (v: Keyed & { input: SettingsInput; revision: number }) =>
      apiMutate<Settings>("PUT", "/v1/settings", v.input, { idempotencyKey: v.key, ifMatch: v.revision }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.settings }),
  });
}

// --- SSH Manager --------------------------------------------------------------------------------

export function useSshStatus() {
  return useQuery({
    queryKey: keys.ssh,
    queryFn: ({ signal }) => apiGet<SshStatus>("/v1/ssh", signal),
    // The files can change outside the app; re-read now and then while the page is open.
    refetchInterval: 15_000,
  });
}

export function useSshHosts(enabled = true) {
  return useQuery({
    queryKey: keys.sshHosts,
    queryFn: ({ signal }) => apiGet<SshHost[]>("/v1/ssh-hosts", signal),
    enabled,
  });
}

function useSshInvalidate() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: keys.ssh });
    void qc.invalidateQueries({ queryKey: keys.sshHosts });
  };
}

export function useSaveSshHost() {
  const done = useSshInvalidate();
  return useMutation({
    mutationFn: (v: Keyed & { id?: string | undefined; revision?: number | undefined; input: SshHostInput }) =>
      v.id
        ? apiMutate<SshHost>("PUT", `/v1/ssh-hosts/${v.id}`, v.input, { idempotencyKey: v.key, ifMatch: v.revision })
        : apiMutate<SshHost>("POST", "/v1/ssh-hosts", v.input, { idempotencyKey: v.key }),
    onSuccess: done,
  });
}

export function useDeleteSshHost() {
  const done = useSshInvalidate();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; revision: number }) =>
      apiMutate<undefined>("DELETE", `/v1/ssh-hosts/${v.id}`, undefined, {
        idempotencyKey: v.key,
        ifMatch: v.revision,
      }),
    onSuccess: done,
  });
}

export type SshFileAction = "include" | "overwrite" | "apply";

export function useSshFileAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { action: SshFileAction }) =>
      apiMutate<SshActionResult>("POST", `/v1/ssh/${v.action}`, {}, { idempotencyKey: v.key }),
    onSuccess: (r) => qc.setQueryData(keys.ssh, r.data.status),
  });
}

/** Read-only probe (SOCKS5 CONNECT + SSH banner); nothing changes on the server. */
export function useSshTest() {
  return useMutation({
    mutationFn: (v: Keyed & { id: string }) =>
      apiMutate<SshTestResult>("POST", `/v1/ssh-hosts/${v.id}/test`, {}, { idempotencyKey: v.key }),
  });
}

// -------------------------------------------------------------------------------------------
// Providers
// -------------------------------------------------------------------------------------------

/** The Provider egress. Polled faster while it is changing (bootstrap countdown, switching). */
/** The newest operations (系統 › 操作紀錄); polled while that tab is open. */
export function useOperations(enabled: boolean) {
  return useQuery({
    queryKey: keys.operations,
    queryFn: ({ signal }) => apiGet<Operation[]>("/v1/operations?limit=50", signal),
    enabled,
    refetchInterval: enabled ? 5_000 : false,
  });
}

export function useProviderEgress() {
  return useQuery({
    queryKey: keys.providerEgress,
    queryFn: ({ signal }) => apiGet<ProviderEgressStatus>("/v1/provider-egress", signal),
    refetchInterval: (q) => {
      const phase = q.state.data?.phase;
      return phase === "bootstrap_direct" || phase === "switching" || phase === "starting_instance" ? 2_000 : 15_000;
    },
  });
}

function useEgressUpdate() {
  const qc = useQueryClient();
  return (s: ProviderEgressStatus) => {
    qc.setQueryData(keys.providerEgress, s);
    void qc.invalidateQueries({ queryKey: keys.instances });
  };
}

export function usePutProviderEgress() {
  const done = useEgressUpdate();
  return useMutation({
    mutationFn: (v: Keyed & { revision: number; input: ProviderEgressInput }) =>
      apiMutate<ProviderEgressStatus>("PUT", "/v1/provider-egress", v.input, {
        idempotencyKey: v.key,
        ifMatch: v.revision,
      }),
    onSuccess: (r) => {
      done(r.data);
    },
  });
}

/** Open the one-time direct bootstrap (10 minutes). */
export function useOpenBootstrap() {
  const done = useEgressUpdate();
  return useMutation({
    mutationFn: (v: Keyed) =>
      apiMutate<ProviderEgressStatus>("POST", "/v1/provider-egress/bootstrap", {}, { idempotencyKey: v.key }),
    onSuccess: (r) => {
      done(r.data);
    },
  });
}

export function useEndBootstrap() {
  const done = useEgressUpdate();
  return useMutation({
    mutationFn: () => apiMutate<ProviderEgressStatus>("DELETE", "/v1/provider-egress/bootstrap", undefined),
    onSuccess: (r) => {
      done(r.data);
    },
  });
}

/**
 * Open a manual rebootstrap (10 minutes, recovery operations only) for the egress revision the
 * user saw; the server refuses it with the reason unless the egress cannot come back by itself.
 */
export function useRebootstrap() {
  const done = useEgressUpdate();
  return useMutation({
    mutationFn: (v: Keyed & { revision: number; input: ProviderRebootstrapInput }) =>
      apiMutate<ProviderEgressStatus>("POST", "/v1/provider-egress/rebootstrap", v.input, {
        idempotencyKey: v.key,
        ifMatch: v.revision,
      }),
    onSuccess: (r) => {
      done(r.data);
    },
  });
}

/** Cancel the active rebootstrap: its direct access closes now. */
export function useCancelRebootstrap() {
  const done = useEgressUpdate();
  return useMutation({
    mutationFn: () => apiMutate<ProviderEgressStatus>("DELETE", "/v1/provider-egress/rebootstrap", undefined),
    onSuccess: (r) => {
      done(r.data);
    },
  });
}

/** Read-only: where provider traffic leaves right now. */
export function useCheckEgress() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => apiMutate<ProviderIpCheck>("POST", "/v1/provider-egress/check", {}),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.providerEgress }),
  });
}

/** Read-only: the exit of one running connection, through its own tunnel. */
export function useInstanceIpCheck() {
  return useMutation({
    mutationFn: (id: string) => apiMutate<ProviderIpCheck>("POST", `/v1/instances/${id}/ip-check`, {}),
  });
}

export function useProviderAccounts() {
  return useQuery({
    queryKey: keys.providerAccounts,
    queryFn: ({ signal }) => apiGet<ProviderAccount[]>("/v1/provider-accounts", signal),
  });
}

export function useCreateProviderAccount() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { input: ProviderAccountInput }) =>
      apiMutate<ProviderAccount>("POST", "/v1/provider-accounts", v.input, { idempotencyKey: v.key }),
    // gcTime 0: the variables hold a credential; nothing keeps them after the call.
    gcTime: 0,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.providerAccounts });
      void qc.invalidateQueries({ queryKey: keys.providerEgress });
    },
  });
}

export function useDeleteProviderAccount() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; revision: number }) =>
      apiMutate<undefined>("DELETE", `/v1/provider-accounts/${v.id}`, undefined, {
        idempotencyKey: v.key,
        ifMatch: v.revision,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.providerAccounts }),
  });
}

export function useRefreshProviderAccount() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiMutate<ProviderAccount>("POST", `/v1/provider-accounts/${id}/refresh`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.providerAccounts }),
  });
}

export function useProviderDevices(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: keys.providerDevices(id ?? ""),
    queryFn: ({ signal }) => apiGet<ProviderDevice[]>(`/v1/provider-accounts/${id}/devices`, signal),
    enabled: Boolean(id) && enabled,
    staleTime: 60_000,
    retry: false,
  });
}

export function useProviderServers(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: keys.providerServers(id ?? ""),
    queryFn: ({ signal }) => apiGet<ProviderServer[]>(`/v1/provider-accounts/${id}/servers`, signal),
    enabled: Boolean(id) && enabled,
    staleTime: 5 * 60_000,
    retry: false,
  });
}

export function useProviderConnect() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { account: string; input: ProviderConnectInput }) =>
      apiMutate<ProviderConnectResult>("POST", `/v1/provider-accounts/${v.account}/connections`, v.input, {
        idempotencyKey: v.key,
      }),
    onSuccess: (r, v) => {
      void qc.invalidateQueries({ queryKey: keys.instances });
      void qc.invalidateQueries({ queryKey: keys.profiles });
      void qc.invalidateQueries({ queryKey: keys.gateways });
      void qc.invalidateQueries({ queryKey: keys.providerEgress });
      // A new device can take a while to appear in the provider's own list: show the one the
      // connection uses now, and read the list again later instead of right away.
      const device = r.data.device;
      if (device) {
        qc.setQueryData<ProviderDevice[]>(keys.providerDevices(v.account), (old) =>
          old
            ? old.some((d) => d.id === device.id)
              ? old.map((d) => (d.id === device.id ? device : d))
              : [...old, device]
            : old,
        );
        void qc.invalidateQueries({ queryKey: keys.providerDevices(v.account), refetchType: "none" });
      } else {
        void qc.invalidateQueries({ queryKey: keys.providerDevices(v.account) });
      }
    },
  });
}

/**
 * AirVPN's forwarded ports of an account. Every read signs in to (or reuses a session with)
 * AirVPN's website through the Provider egress, so it is read when asked for, not polled, and
 * a failure is not retried by itself.
 */
export function useForwardedPorts(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: keys.providerPorts(id ?? ""),
    queryFn: ({ signal }) => apiGet<ForwardedPorts>(`/v1/provider-accounts/${id}/forwarded-ports`, signal),
    enabled: Boolean(id) && enabled,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
    retry: false,
  });
}

/**
 * Change the cached list in place after a reservation or delete (the answer says what changed),
 * and mark it stale without reading AirVPN's website again right away.
 */
function usePortsChanged() {
  const qc = useQueryClient();
  return (account: string, change: (ports: ForwardedPort[]) => ForwardedPort[]) => {
    qc.setQueryData<ForwardedPorts>(keys.providerPorts(account), (old) =>
      old ? { ...old, ports: change(old.ports) } : old,
    );
    void qc.invalidateQueries({ queryKey: keys.providerPorts(account), refetchType: "none" });
  };
}

/** Reserve a forwarded port at AirVPN: `port` null lets AirVPN pick one. */
export function useReserveForwardedPort() {
  const changed = usePortsChanged();
  return useMutation({
    mutationFn: (v: Keyed & { account: string; port: number | null }) =>
      apiMutate<ForwardedPort>(
        "POST",
        `/v1/provider-accounts/${v.account}/forwarded-ports`,
        { port: v.port },
        { idempotencyKey: v.key },
      ),
    onSuccess: (r, v) => {
      changed(v.account, (ports) => [...ports.filter((p) => p.port !== r.data.port), r.data]);
    },
  });
}

/** Delete a forwarded port at AirVPN (it is released there at once). */
export function useDeleteForwardedPort() {
  const changed = usePortsChanged();
  return useMutation({
    mutationFn: (v: Keyed & { account: string; port: number }) =>
      apiMutate<undefined>("DELETE", `/v1/provider-accounts/${v.account}/forwarded-ports/${v.port}`, undefined, {
        idempotencyKey: v.key,
      }),
    onSuccess: (_r, v) => {
      changed(v.account, (ports) => ports.filter((p) => p.port !== v.port));
    },
  });
}

/**
 * Change some of a forwarded port's settings at AirVPN (only the fields given): the answer is the
 * port as read back. A refusal may have saved the other settings and an unknown outcome any of
 * them, so the list is read again after either.
 */
export function useUpdateForwardedPort() {
  const qc = useQueryClient();
  const changed = usePortsChanged();
  return useMutation({
    mutationFn: (v: Keyed & { account: string; port: number; update: ForwardedPortUpdate }) =>
      apiMutate<ForwardedPort>("PATCH", `/v1/provider-accounts/${v.account}/forwarded-ports/${v.port}`, v.update, {
        idempotencyKey: v.key,
      }),
    onSuccess: (r, v) => {
      changed(v.account, (ports) => ports.map((p) => (p.port === v.port ? r.data : p)));
    },
    onError: (e, v) => {
      if (e instanceof ApiFailure && (e.code === "PROVIDER_REJECTED" || e.kind === "unknown_outcome")) {
        void qc.invalidateQueries({ queryKey: keys.providerPorts(v.account) });
      }
    },
  });
}

/** The controller starts no test of a port after 35 s and waits at most 15 s for one. */
const PORT_TEST_TIMEOUT_MS = 60_000;

/**
 * AirVPN's test of a forwarded port from the server of each connected session that uses it (TCP
 * only, as its website). Changes nothing; asked for, never repeated by itself.
 */
export function useTestForwardedPort() {
  return useMutation({
    mutationFn: (v: { account: string; port: number }) =>
      apiPreview<ForwardedPortTest>(
        `/v1/provider-accounts/${v.account}/forwarded-ports/${v.port}/test`,
        "{}",
        "application/json",
        undefined,
        PORT_TEST_TIMEOUT_MS,
      ),
  });
}

/** AirVPN's DDNS check of an account's forwarded ports: asked for, never polled. */
export function useDdnsCheck() {
  return useMutation({
    mutationFn: (account: string) => apiGet<ForwardedPortDdns>(`/v1/provider-accounts/${account}/forwarded-ports/ddns`),
  });
}

/** AirVPN's search for `count` consecutive free ports (it reserves nothing): asked for, never polled. */
export function useFreePortSearch() {
  return useMutation({
    mutationFn: (v: { account: string; count: number }) =>
      apiGet<ForwardedPortSearch>(`/v1/provider-accounts/${v.account}/forwarded-ports/free?count=${v.count}`),
  });
}

/** Revoke a device this installation owns (its key is then forgotten here). */
export function useRevokeProviderDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { account: string; device: string; unowned?: boolean }) =>
      apiMutate<undefined>(
        "DELETE",
        `/v1/provider-accounts/${v.account}/devices/${encodeURIComponent(v.device)}${v.unowned ? "?unowned=true" : ""}`,
        undefined,
        { idempotencyKey: v.key },
      ),
    onSuccess: (_r, v) => qc.invalidateQueries({ queryKey: keys.providerDevices(v.account) }),
  });
}

// -------------------------------------------------------------------------------------------
// Managed Apps
// -------------------------------------------------------------------------------------------

/**
 * Like `mergeStatuses` for Instances: per App the status with the later `observed_at` wins, and a
 * missing status does not erase a known one while the manager is connected.
 */
export function mergeAppStatuses(
  prev: AppView[] | undefined,
  next: AppView[],
  managerConnected: boolean | null,
): AppView[] {
  if (!prev) return next;
  const before = new Map(prev.map((v) => [v.spec.id, v.status]));
  return next.map((v) => {
    const old = before.get(v.spec.id) ?? null;
    if (!v.status) return managerConnected === true && old ? { ...v, status: old } : v;
    return { ...v, status: newerAppStatus(old, v.status) };
  });
}

export function useApps() {
  const qc = useQueryClient();
  return useQuery({
    queryKey: keys.apps,
    queryFn: async ({ signal }) =>
      mergeAppStatuses(
        qc.getQueryData<AppView[]>(keys.apps),
        await apiGet<AppView[]>("/v1/apps", signal),
        connectionSnapshot().manager,
      ),
    // Events keep the status fresh; this is the safety net when events are missed.
    refetchInterval: 20_000,
  });
}

/**
 * Apps deleted from this page: their own queries never run again. Removing the queries is not
 * enough, since the inspector stays mounted until it unmounts and would fetch them into a 404.
 */
const deletedApps = new Set<string>();

/** The App's process tree, refreshed while it runs. */
export function useAppProcesses(id: string | undefined, running: boolean) {
  return useQuery({
    queryKey: keys.appProcesses(id ?? "none"),
    queryFn: ({ signal }) => apiGet<AppProcesses>(`/v1/apps/${id}/processes`, signal),
    enabled: Boolean(id) && !deletedApps.has(id ?? ""),
    refetchInterval: running ? 4_000 : false,
  });
}

/** The newest lines of the App's own output, refreshed while it runs. */
export function useAppLog(id: string | undefined, running: boolean, lines = 200) {
  return useQuery({
    queryKey: [...keys.appLog(id ?? "none"), lines],
    queryFn: ({ signal }) => apiGet<AppLog>(`/v1/apps/${id}/log?lines=${lines}`, signal),
    enabled: Boolean(id) && !deletedApps.has(id ?? ""),
    refetchInterval: running ? 4_000 : false,
  });
}

/** What the manager finds at `path` (resolved file, permissions, SHA-256); nothing is stored. */
export function useExecutableCheck(path: string | null) {
  return useQuery({
    queryKey: keys.executableCheck(path ?? ""),
    queryFn: ({ signal }) =>
      apiGet<ExecutableCheck>(`/v1/apps/executable-check?path=${encodeURIComponent(path ?? "")}`, signal),
    enabled: Boolean(path),
    // The file can change at any time: never answer from an old result.
    staleTime: 0,
    gcTime: 30_000,
    retry: false,
  });
}

export function useSaveApp() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id?: string | undefined; revision?: number | undefined; input: AppInput }) =>
      v.id
        ? apiMutate<AppView>("PUT", `/v1/apps/${v.id}`, v.input, { idempotencyKey: v.key, ifMatch: v.revision })
        : apiMutate<AppView>("POST", "/v1/apps", v.input, { idempotencyKey: v.key }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.apps }),
  });
}

export function useDeleteApp() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; revision: number }) =>
      apiMutate<undefined>("DELETE", `/v1/apps/${v.id}`, undefined, { idempotencyKey: v.key, ifMatch: v.revision }),
    onSuccess: (_r, v) => {
      // The deleted App leaves the list at once (its inspector unmounts); its tree and log are
      // dropped instead of refetched into a 404, and the list reloads in the background.
      deletedApps.add(v.id);
      qc.setQueryData<AppView[]>(keys.apps, (all) => all?.filter((a) => a.spec.id !== v.id));
      qc.removeQueries({ queryKey: keys.appProcesses(v.id) });
      qc.removeQueries({ queryKey: keys.appLog(v.id) });
      void qc.invalidateQueries({ queryKey: keys.apps, exact: true });
    },
  });
}

export function useAppAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; action: AppAction; sha256?: string }) =>
      apiMutate<AppActionResult>(
        "POST",
        `/v1/apps/${v.id}/actions`,
        { action: v.action, ...(v.sha256 ? { sha256: v.sha256 } : {}) },
        { idempotencyKey: v.key },
      ),
    onSuccess: (r) => {
      if (r.data.status) patchAppStatus(qc, r.data.status);
    },
    // An approval changes the spec; any action changes the tree and the log.
    onSettled: (_r, _e, v) =>
      qc.invalidateQueries({ queryKey: v.action === "approve" ? keys.apps : keys.appProcesses(v.id) }),
  });
}

// -------------------------------------------------------------------------------------------
// Port forwards
// -------------------------------------------------------------------------------------------

/** Like the Apps: per forward the later observation wins; a missing one keeps a known one. */
export function mergeForwardStatuses(
  prev: ForwardView[] | undefined,
  next: ForwardView[],
  managerConnected: boolean | null,
): ForwardView[] {
  if (!prev) return next;
  const before = new Map(prev.map((v) => [v.binding.id, v.status]));
  return next.map((v) => {
    const old = before.get(v.binding.id) ?? null;
    if (!v.status) return managerConnected === true && old ? { ...v, status: old } : v;
    return { ...v, status: newerForwardStatus(old, v.status) };
  });
}

export function useForwards() {
  const qc = useQueryClient();
  return useQuery({
    queryKey: keys.forwards,
    queryFn: async ({ signal }) =>
      mergeForwardStatuses(
        qc.getQueryData<ForwardView[]>(keys.forwards),
        await apiGet<ForwardView[]>("/v1/forward-bindings", signal),
        connectionSnapshot().manager,
      ),
    // Events keep the status fresh; this is the safety net when events are missed.
    refetchInterval: 15_000,
  });
}

export function useSaveForward() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id?: string | undefined; revision?: number | undefined; input: ForwardInput }) =>
      v.id
        ? apiMutate<ForwardView>("PUT", `/v1/forward-bindings/${v.id}`, v.input, {
            idempotencyKey: v.key,
            ifMatch: v.revision,
          })
        : apiMutate<ForwardView>("POST", "/v1/forward-bindings", v.input, { idempotencyKey: v.key }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.forwards });
      void qc.invalidateQueries({ queryKey: keys.inbound });
    },
  });
}

export function useDeleteForward() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { id: string; revision: number }) =>
      apiMutate<undefined>("DELETE", `/v1/forward-bindings/${v.id}`, undefined, {
        idempotencyKey: v.key,
        ifMatch: v.revision,
      }),
    onSuccess: (_r, v) => {
      qc.setQueryData<ForwardView[]>(keys.forwards, (all) => all?.filter((f) => f.binding.id !== v.id));
      void qc.invalidateQueries({ queryKey: keys.forwards, exact: true });
      void qc.invalidateQueries({ queryKey: keys.inbound });
    },
  });
}
