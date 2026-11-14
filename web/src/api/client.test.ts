import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiFailure, apiMutate } from "./client";

function respond(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

afterEach(() => vi.unstubAllGlobals());

/** The ApiFailure a request ends with (the test fails if it resolves or throws anything else). */
async function failure(request: Promise<unknown>): Promise<ApiFailure> {
  try {
    await request;
  } catch (e) {
    expect(e).toBeInstanceOf(ApiFailure);
    if (e instanceof ApiFailure) return e;
  }
  throw new Error("the request did not fail with an ApiFailure");
}

describe("apiMutate", () => {
  it("sends the idempotency key and If-Match, and reads the ETag revision", async () => {
    const fetch = vi.fn().mockResolvedValue(respond(200, { ok: true }, { etag: '"7"' }));
    vi.stubGlobal("fetch", fetch);
    const r = await apiMutate("PUT", "/v1/x", { a: 1 }, { idempotencyKey: "k1", ifMatch: 6 });
    expect(r.etag).toBe(7);
    expect(r.idempotencyKey).toBe("k1");
    const init = fetch.mock.calls[0]?.[1] as RequestInit;
    expect((init.headers as Record<string, string>)["idempotency-key"]).toBe("k1");
    expect((init.headers as Record<string, string>)["if-match"]).toBe('"6"');
  });

  it("classifies a lost response as an unknown outcome that keeps its key", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    const e = await failure(apiMutate("POST", "/v1/x", {}, { idempotencyKey: "k2" }));
    expect(e.kind).toBe("unknown_outcome");
    expect(e.idempotencyKey).toBe("k2");
  });

  it("classifies OUTCOME_UNKNOWN from the server as unknown, not as a failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(respond(503, { code: "OUTCOME_UNKNOWN", message: "不確定", retryable: false })),
    );
    const e = await failure(apiMutate("POST", "/v1/x", {}));
    expect(e.kind).toBe("unknown_outcome");
  });
});
