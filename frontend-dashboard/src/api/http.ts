/**
 * Client HTTP de la passerelle : jeton d'accès en mémoire uniquement, rafraîchissement
 * transparent (cookie HttpOnly) sur 401, erreurs RFC 9457 typées.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail: string | undefined;
  readonly errors: { location: string; message: string }[];
  readonly retryAfter: number | undefined;

  constructor(init: {
    status: number;
    code: string;
    title: string;
    detail?: string;
    errors?: { location: string; message: string }[];
    retryAfter?: number;
  }) {
    super(init.detail ?? init.title);
    this.name = "ApiError";
    this.status = init.status;
    this.code = init.code;
    this.detail = init.detail;
    this.errors = init.errors ?? [];
    this.retryAfter = init.retryAfter;
  }

  get isUnavailable(): boolean {
    return this.status === 0 || this.status === 502 || this.status === 503 || this.status === 504;
  }
}

export interface AuthHooks {
  getToken(): string | null;
  /** Renvoie un nouveau jeton, ou null si la session est perdue. */
  refresh(): Promise<string | null>;
  onSessionLost(): void;
}

let hooks: AuthHooks = {
  getToken: () => null,
  refresh: async () => null,
  onSessionLost: () => undefined,
};

export function configureAuth(next: AuthHooks): void {
  hooks = next;
}

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  headers?: Record<string, string>;
  auth?: boolean;
  signal?: AbortSignal;
}

export interface ApiResponse<T> {
  data: T;
  status: number;
  headers: Headers;
}

async function toApiError(response: Response): Promise<ApiError> {
  const retryAfterHeader = response.headers.get("retry-after");
  const retryAfter = retryAfterHeader ? Number.parseInt(retryAfterHeader, 10) : undefined;
  let body: Record<string, unknown> = {};
  try {
    body = (await response.json()) as Record<string, unknown>;
  } catch {
    // corps absent ou non JSON (ex. erreur de passerelle)
  }
  return new ApiError({
    status: response.status,
    code: typeof body.code === "string" ? body.code : `HTTP_${response.status}`,
    title: typeof body.title === "string" ? body.title : response.statusText || "Request failed",
    detail: typeof body.detail === "string" ? body.detail : undefined,
    errors: Array.isArray(body.errors) ? (body.errors as { location: string; message: string }[]) : undefined,
    retryAfter: Number.isFinite(retryAfter) ? retryAfter : undefined,
  });
}

async function send(path: string, options: RequestOptions, token: string | null): Promise<Response> {
  const headers: Record<string, string> = { Accept: "application/json", ...options.headers };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  try {
    return await fetch(path, {
      method: options.method ?? "GET",
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "same-origin",
      signal: options.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError({ status: 0, code: "NETWORK_ERROR", title: "Network error", detail: "La plateforme est injoignable" });
  }
}

export async function api<T>(path: string, options: RequestOptions = {}): Promise<ApiResponse<T>> {
  const useAuth = options.auth !== false;
  let response = await send(path, options, useAuth ? hooks.getToken() : null);

  if (response.status === 401 && useAuth) {
    const renewed = await hooks.refresh();
    if (renewed) {
      response = await send(path, options, renewed);
    }
    if (response.status === 401) {
      hooks.onSessionLost();
    }
  }
  if (!response.ok) throw await toApiError(response);

  const text = response.status === 204 ? "" : await response.text();
  const data = (text ? JSON.parse(text) : undefined) as T;
  return { data, status: response.status, headers: response.headers };
}

export function newIdempotencyKey(prefix = "ui"): string {
  return `${prefix}-${crypto.randomUUID()}`;
}
