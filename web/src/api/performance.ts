// Performance Manager server state: the passive analysis (refreshed every 5 s, generates no
// traffic) and its series.

import { useQuery } from "@tanstack/react-query";
import { apiGet } from "./client";
import type { MetricsRange } from "./generated/MetricsRange";
import type { PerformanceOverview } from "./generated/PerformanceOverview";
import type { PerformanceSeriesSet } from "./generated/PerformanceSeriesSet";
import { keys } from "./keys";

/** The passive analysis is recomputed every 5 s by the manager. */
const SUMMARY_REFRESH_MS = 5_000;

export function usePerformanceSummary() {
  return useQuery({
    queryKey: keys.perfSummary,
    queryFn: ({ signal }) => apiGet<PerformanceOverview>("/v1/performance/summary", signal),
    refetchInterval: SUMMARY_REFRESH_MS,
  });
}

/** `scope`: `system`, `instance:<id>` or `gateway:<id>`. */
export function usePerformanceSeries(scope: string | null, range: MetricsRange) {
  return useQuery({
    queryKey: keys.perfSeries(scope ?? "", range),
    queryFn: ({ signal }) =>
      apiGet<PerformanceSeriesSet>(
        `/v1/performance/series?scope=${encodeURIComponent(scope ?? "")}&range=${range}`,
        signal,
      ),
    enabled: Boolean(scope),
    // Short ranges move with the 5 s samples; long ones are minute rollups.
    refetchInterval: range === "15m" || range === "1h" ? 10_000 : 60_000,
    placeholderData: (prev) => prev,
  });
}
