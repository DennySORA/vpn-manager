// SSH download server state: the jobs with what the manager observes (the SSE `ssh_download_status` event patches
// it, at most once per job and second), each job's file records (paged) and log, the local folder check, and the
// changes. Kept apart from queries.ts like performance.ts.

import {
  keepPreviousData,
  type QueryClient,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { apiGet, apiMutate } from "./client";
import type { SshDownloadDirCheck } from "./generated/SshDownloadDirCheck";
import type { SshDownloadInput } from "./generated/SshDownloadInput";
import type { SshDownloadLog } from "./generated/SshDownloadLog";
import type { SshDownloadStatus } from "./generated/SshDownloadStatus";
import type { SshDownloadTransfers } from "./generated/SshDownloadTransfers";
import type { SshDownloadView } from "./generated/SshDownloadView";

export const sshDownloadKeys = {
  all: ["ssh-downloads"] as const,
  /** Under `all`: reloading the jobs refreshes an open job's records and log too. */
  transfers: (id: string, state: "active" | "history") => ["ssh-downloads", id, "transfers", state] as const,
  log: (id: string) => ["ssh-downloads", id, "log"] as const,
  dirCheck: (path: string) => ["ssh-download-dir-check", path] as const,
};

/** The newer of two observations of one job (an event may land while a request is in flight). */
export function newerSshDownloadStatus(
  a: SshDownloadStatus | null,
  b: SshDownloadStatus | null,
): SshDownloadStatus | null {
  if (!a) return b;
  if (!b) return a;
  return Date.parse(a.observed_at) > Date.parse(b.observed_at) ? a : b;
}

/** A refetch never replaces a status observed after it. */
export function mergeSshDownloads(prev: SshDownloadView[] | undefined, next: SshDownloadView[]): SshDownloadView[] {
  if (!prev) return next;
  const before = new Map(prev.map((v) => [v.job.id, v.status]));
  return next.map((v) => ({ ...v, status: newerSshDownloadStatus(before.get(v.job.id) ?? null, v.status) }));
}

/** Put a fresher status of one job into the list cache (from an action's answer or an event). */
export function patchSshDownloadStatus(qc: QueryClient, status: SshDownloadStatus) {
  qc.setQueryData<SshDownloadView[]>(sshDownloadKeys.all, (views) =>
    views?.map((v) => (v.job.id === status.job_id ? { ...v, status: newerSshDownloadStatus(v.status, status) } : v)),
  );
}

export function useSshDownloads() {
  const qc = useQueryClient();
  return useQuery({
    queryKey: sshDownloadKeys.all,
    queryFn: async ({ signal }) =>
      mergeSshDownloads(
        qc.getQueryData<SshDownloadView[]>(sshDownloadKeys.all),
        await apiGet<SshDownloadView[]>("/v1/ssh-downloads", signal),
      ),
    // The event stream keeps statuses fresh; this is the safety net when events are missed.
    refetchInterval: 20_000,
  });
}

/** One job's records, newest first: `history` pages through the finished ones, `active` lists the unfinished ones. */
export function useSshDownloadTransfers(id: string | undefined, state: "active" | "history") {
  return useInfiniteQuery({
    queryKey: sshDownloadKeys.transfers(id ?? "", state),
    queryFn: ({ pageParam, signal }) => {
      const q = new URLSearchParams({ state, limit: state === "history" ? "25" : "50" });
      if (pageParam) q.set("before", pageParam);
      return apiGet<SshDownloadTransfers>(`/v1/ssh-downloads/${id}/transfers?${q}`, signal);
    },
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next ?? undefined,
    enabled: Boolean(id),
  });
}

export function useSshDownloadLog(id: string | undefined, lines = 60) {
  return useQuery({
    queryKey: sshDownloadKeys.log(id ?? ""),
    queryFn: ({ signal }) => apiGet<SshDownloadLog>(`/v1/ssh-downloads/${id}/log?limit=${lines}`, signal),
    enabled: Boolean(id),
    placeholderData: keepPreviousData,
  });
}

/** Whether a local folder can take downloads (the manager looks; nothing is created). */
export function useSshDownloadDirCheck(path: string | null) {
  return useQuery({
    queryKey: sshDownloadKeys.dirCheck(path ?? ""),
    queryFn: ({ signal }) =>
      apiGet<SshDownloadDirCheck>(`/v1/ssh-downloads/dir-check?path=${encodeURIComponent(path ?? "")}`, signal),
    enabled: Boolean(path),
    staleTime: 0,
    retry: false,
  });
}

export function useSaveSshDownload() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: {
      id?: string | undefined;
      revision?: number | undefined;
      input: SshDownloadInput;
      key: string;
    }) =>
      v.id
        ? apiMutate<SshDownloadView>("PUT", `/v1/ssh-downloads/${v.id}`, v.input, {
            idempotencyKey: v.key,
            ifMatch: v.revision,
          })
        : apiMutate<SshDownloadView>("POST", "/v1/ssh-downloads", v.input, { idempotencyKey: v.key }),
    onSuccess: () => qc.invalidateQueries({ queryKey: sshDownloadKeys.all }),
  });
}
