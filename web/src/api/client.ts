// Same-origin HTTP client for the VPN Web API. Every mutation carries an Idempotency-Key; a
// mutation whose response never arrived has an *unknown* outcome and is never re-sent blindly —
// callers look it up with `lookupOperation(key)` instead.

import { localized } from "@/i18n";
import type { ApiError } from "./generated/ApiError";
import type { Operation } from "./generated/Operation";
import { m } from "./messages";

export type FailureKind = "http" | "network" | "unknown_outcome";

/** A read that takes longer is reported as a connection problem (and retried by the query). */
const READ_TIMEOUT_MS = 20_000;
/** A change without an answer by then has an unknown outcome: it is looked up, never re-sent. */
const MUTATION_TIMEOUT_MS = 30_000;

export class ApiFailure extends Error {
  readonly kind: FailureKind;
  readonly status: number;
  readonly error: ApiError | null;
  readonly idempotencyKey: string | null;

  constructor(kind: FailureKind, status: number, error: ApiError | null, key: string | null, message: string) {
    super(message);
    this.kind = kind;
    this.status = status;
    this.error = error;
    this.idempotencyKey = key;
  }

  get code(): string {
    return this.error?.code ?? (this.kind === "network" ? "NETWORK" : "UNKNOWN");
  }

  /** Fields of a validation failure, by JSON-pointer path. */
  fieldErrors(): Map<string, string> {
    const m = new Map<string, string>();
    for (const f of this.error?.field_errors ?? []) m.set(f.path, localized(f.message));
    return m;
  }
}

/**
 * A random UUID v4. Built from `getRandomValues`: `crypto.randomUUID` exists only in secure
 * contexts, and the web UI is also served over plain HTTP to an allowed LAN.
 */
export function newIdempotencyKey(): string {
  const b = crypto.getRandomValues(new Uint8Array(16));
  const [b6 = 0, b8 = 0] = [b[6], b[8]];
  b[6] = (b6 & 0x0f) | 0x40;
  b[8] = (b8 & 0x3f) | 0x80;
  const h = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

type Method = "POST" | "PUT" | "PATCH" | "DELETE";

interface MutateOptions {
  /** Reuse the same key when retrying the *same* intent; a new intent gets a new key. */
  idempotencyKey?: string | undefined;
  ifMatch?: number | undefined;
  signal?: AbortSignal | undefined;
}

/** What a failed request says went wrong, in this page's language. */
function failureMessage(err: ApiError | null, status: number): string {
  return err ? localized(err.message) : m.requestFailed(status);
}

async function parseError(res: Response): Promise<ApiError | null> {
  try {
    const body: unknown = await res.json();
    // The body is the server's ApiError only when it is an object with a string code (a proxy may answer otherwise).
    return typeof body === "object" && body !== null && "code" in body && typeof body.code === "string"
      ? (body as ApiError)
      : null;
  } catch {
    return null;
  }
}

export async function apiGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  let res: Response;
  const timeout = AbortSignal.timeout(READ_TIMEOUT_MS);
  try {
    res = await fetch(path, {
      headers: { accept: "application/json" },
      signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
      cache: "no-store",
    });
  } catch (e) {
    if (signal?.aborted) throw e;
    throw new ApiFailure("network", 0, null, null, timeout.aborted ? m.timeout : m.unreachable);
  }
  if (!res.ok) {
    const err = await parseError(res);
    throw new ApiFailure("http", res.status, err, null, failureMessage(err, res.status));
  }
  return (await res.json()) as T;
}

export interface MutationResult<T> {
  data: T;
  etag: number | null;
  idempotencyKey: string;
}

export async function apiMutate<T>(
  method: Method,
  path: string,
  body: unknown,
  opts: MutateOptions = {},
): Promise<MutationResult<T>> {
  const key = opts.idempotencyKey ?? newIdempotencyKey();
  const headers: Record<string, string> = { accept: "application/json", "idempotency-key": key };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (opts.ifMatch !== undefined) headers["if-match"] = `"${opts.ifMatch}"`;
  let res: Response;
  try {
    const timeout = AbortSignal.timeout(MUTATION_TIMEOUT_MS);
    res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? null : JSON.stringify(body),
      signal: opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout,
      cache: "no-store",
    });
  } catch {
    // The request may or may not have reached the server.
    throw new ApiFailure("unknown_outcome", 0, null, key, m.unknownOutcome);
  }
  if (!res.ok) {
    const err = await parseError(res);
    const kind: FailureKind = err?.code === "OUTCOME_UNKNOWN" || err?.code === "TIMEOUT" ? "unknown_outcome" : "http";
    throw new ApiFailure(kind, res.status, err, key, failureMessage(err, res.status));
  }
  const etagHeader = res.headers.get("etag");
  const etag = etagHeader ? Number(etagHeader.replace(/W\/|"/g, "")) : null;
  const data = res.status === 204 ? (undefined as T) : ((await res.json()) as T);
  return { data, etag: Number.isFinite(etag) ? etag : null, idempotencyKey: key };
}

/**
 * POST a body that changes nothing on the server (a blocklist preview: an uploaded file, pasted
 * text, or `{ url }` as JSON; a test). Failures are plain HTTP or network failures, never unknown
 * outcomes. `timeoutMs` for a request known to take longer than a change.
 */
export async function apiPreview<T>(
  path: string,
  body: Blob | string,
  contentType: string,
  signal?: AbortSignal,
  timeoutMs = MUTATION_TIMEOUT_MS,
): Promise<T> {
  let res: Response;
  const timeout = AbortSignal.timeout(timeoutMs);
  try {
    res = await fetch(path, {
      method: "POST",
      headers: { accept: "application/json", "content-type": contentType },
      body,
      signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
      cache: "no-store",
    });
  } catch (e) {
    if (signal?.aborted) throw e;
    throw new ApiFailure("network", 0, null, null, timeout.aborted ? m.timeout : m.unreachable);
  }
  if (!res.ok) {
    const err = await parseError(res);
    throw new ApiFailure("http", res.status, err, null, failureMessage(err, res.status));
  }
  return (await res.json()) as T;
}

/** Look up what happened to a mutation whose response was lost. */
export async function lookupOperation(key: string): Promise<Operation | null> {
  try {
    return await apiGet<Operation>(`/v1/operations/by-key/${encodeURIComponent(key)}`);
  } catch (e) {
    if (e instanceof ApiFailure && e.status === 404) return null;
    throw e;
  }
}

export function describeFailure(e: unknown): string {
  if (e instanceof ApiFailure) return e.message;
  if (e instanceof Error) return e.message;
  return m.unexpected;
}
