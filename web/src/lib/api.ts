import type { AuditListItem, AuditRecord, Health, RuleInfo, StageInfo } from "./types";

export const API_URL = (process.env.NEXT_PUBLIC_RUNG_API_URL ?? "http://localhost:8000").replace(
  /\/+$/,
  "",
);

export type ApiErrorKind = "network" | "timeout" | "http" | "invalid";

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | null;

  constructor(kind: ApiErrorKind, message: string, status: number | null = null) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
  }
}

export function describeError(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return "Something unexpected went wrong.";
}

export function isUnreachable(error: unknown): boolean {
  return error instanceof ApiError && (error.kind === "network" || error.kind === "timeout");
}

const AUDIT_ID = /^[A-Za-z0-9_-]{1,64}$/;

/** Audit ids come from the URL bar, so check them before they go into a request path. */
export function isValidAuditId(id: unknown): id is string {
  return typeof id === "string" && AUDIT_ID.test(id);
}

interface RequestOptions {
  method?: "GET" | "POST" | "DELETE";
  body?: unknown;
  timeoutMs?: number;
  signal?: AbortSignal;
}

async function request(path: string, options: RequestOptions = {}): Promise<unknown> {
  const { method = "GET", body, timeoutMs = 15_000, signal } = options;
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const onAbort = () => controller.abort();
  signal?.addEventListener("abort", onAbort);

  try {
    let response: Response;
    try {
      response = await fetch(`${API_URL}${path}`, {
        method,
        headers: body === undefined ? undefined : { "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
        cache: "no-store",
      });
    } catch (cause) {
      if (timedOut) {
        throw new ApiError("timeout", `The rung API did not answer within ${Math.round(timeoutMs / 1000)} s.`);
      }
      if (signal?.aborted) throw cause;
      throw new ApiError("network", `The rung API at ${API_URL} is not reachable.`);
    }

    if (response.status === 204) return null;
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      if (response.ok) throw new ApiError("invalid", "The rung API sent a response that is not JSON.");
    }
    if (!response.ok) {
      throw new ApiError("http", detailOf(payload) ?? `The rung API answered ${response.status}.`, response.status);
    }
    return payload;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}

function detailOf(payload: unknown): string | null {
  if (typeof payload !== "object" || payload === null) return null;
  const detail = (payload as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    // FastAPI validation errors: [{msg, loc, ...}]
    const messages = detail
      .map((d) => (typeof d === "object" && d !== null ? (d as { msg?: unknown }).msg : null))
      .filter((m): m is string => typeof m === "string");
    if (messages.length > 0) return messages.join("; ");
  }
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function asAuditRecord(payload: unknown): AuditRecord {
  if (
    isRecord(payload) &&
    isRecord(payload.report) &&
    isRecord(payload.report.classification) &&
    Array.isArray(payload.report.classification.progress) &&
    Array.isArray(payload.report.rules) &&
    Array.isArray(payload.report.findings) &&
    Array.isArray(payload.report.checklist) &&
    Array.isArray(payload.report.dimensions) &&
    isRecord(payload.report.summary) &&
    isRecord(payload.report.repo)
  ) {
    return payload as unknown as AuditRecord;
  }
  throw new ApiError("invalid", "The rung API sent an audit this dashboard cannot read.");
}

/** List endpoints answer `{"items": [...]}`; a bare array is accepted too. */
function asList<T>(payload: unknown): T[] {
  if (Array.isArray(payload)) return payload as T[];
  if (isRecord(payload) && Array.isArray(payload.items)) return payload.items as T[];
  throw new ApiError("invalid", "The rung API sent a list this dashboard cannot read.");
}

export async function getHealth(signal?: AbortSignal): Promise<Health> {
  return (await request("/api/health", { signal, timeoutMs: 5_000 })) as Health;
}

export async function getRules(signal?: AbortSignal): Promise<RuleInfo[]> {
  return asList<RuleInfo>(await request("/api/rules", { signal }));
}

export async function getStages(signal?: AbortSignal): Promise<StageInfo[]> {
  return asList<StageInfo>(await request("/api/stages", { signal }));
}

/** Synchronous on the server: cloning and auditing a large repo can take minutes. */
export async function createAudit(source: string, signal?: AbortSignal): Promise<AuditRecord> {
  return asAuditRecord(
    await request("/api/audits", { method: "POST", body: { source }, timeoutMs: 300_000, signal }),
  );
}

export async function listAudits(limit = 10, offset = 0, signal?: AbortSignal): Promise<AuditListItem[]> {
  return asList<AuditListItem>(await request(`/api/audits?limit=${limit}&offset=${offset}`, { signal }));
}

export async function getAudit(id: string, signal?: AbortSignal): Promise<AuditRecord> {
  if (!isValidAuditId(id)) throw new ApiError("invalid", "That audit id is not valid.");
  return asAuditRecord(await request(`/api/audits/${encodeURIComponent(id)}`, { signal }));
}

export async function getAuditSarif(id: string): Promise<unknown> {
  if (!isValidAuditId(id)) throw new ApiError("invalid", "That audit id is not valid.");
  return request(`/api/audits/${encodeURIComponent(id)}/sarif`, { timeoutMs: 30_000 });
}

export async function deleteAudit(id: string): Promise<void> {
  if (!isValidAuditId(id)) throw new ApiError("invalid", "That audit id is not valid.");
  await request(`/api/audits/${encodeURIComponent(id)}`, { method: "DELETE" });
}
