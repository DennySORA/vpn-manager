import { QueryClient } from "@tanstack/react-query";
import { ApiFailure } from "@/api/client";

/**
 * Reads retry transient failures a couple of times; a definite HTTP answer (404, 409, 422 …) is
 * final. Mutations never retry by themselves: an unknown outcome is looked up, not re-sent.
 */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      refetchOnWindowFocus: true,
      retry: (count, error) => {
        if (error instanceof ApiFailure && error.kind === "http" && error.status < 500) return false;
        return count < 2;
      },
    },
    mutations: { retry: false },
  },
});
