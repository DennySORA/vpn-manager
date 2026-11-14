// System maintenance: diagnostics and recovery. Same rules as queries.ts: the controller is the
// only source of truth; every change carries the idempotency key of the user's intent.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiMutate } from "./client";
import { keys } from "./keys";
import type { Keyed } from "./queries";
import type { DiagnosticReport, ReconcileInput, ReconcileResult, RecoveryReport } from "./types";

/** The report runs integrity checks and hashes programs: fetched when the view opens or on request. */
export function useDiagnostics(enabled = true) {
  return useQuery({
    queryKey: keys.diagnostics,
    queryFn: ({ signal }) => apiGet<DiagnosticReport>("/v1/system/diagnostics", signal),
    enabled,
    staleTime: 30_000,
  });
}

export function useRecovery(enabled = true) {
  return useQuery({
    queryKey: keys.recovery,
    queryFn: ({ signal }) => apiGet<RecoveryReport>("/v1/recovery", signal),
    enabled,
    staleTime: 0,
  });
}

/** Clean exactly the confirmed items (ids from the inspection the user saw). */
export function useReconcile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: Keyed & { input: ReconcileInput }) =>
      apiMutate<ReconcileResult>("POST", "/v1/recovery/reconcile", v.input, { idempotencyKey: v.key }),
    onSuccess: (r) => {
      qc.setQueryData<RecoveryReport | undefined>(keys.recovery, (prev) =>
        prev ? { ...prev, items: r.data.remaining, observed_at: r.data.observed_at } : prev,
      );
      void qc.invalidateQueries({ queryKey: keys.recovery });
      void qc.invalidateQueries({ queryKey: keys.diagnostics });
    },
  });
}
