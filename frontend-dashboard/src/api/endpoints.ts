/** Points d'accès publiés par la passerelle (allowlist nginx). */

import { api, newIdempotencyKey } from "./http";
import type {
  Account,
  ChatReply,
  HealthHistory,
  IncidentDetail,
  IncidentSummary,
  Overview,
  Page,
  Principal,
  Timeline,
  TokenResponse,
  Transaction,
  TransactionDetail,
} from "./types";

const AUTH = "/api/auth/v1";
const PAYMENT = "/api/payment/v1";
const LAB = "/api/payment/lab/v1";
const SUPERVISION = "/api/supervision/v1";
const ASSISTANT = "/api/assistant/v1";

// --------------------------------------------------------------------- auth
export const authApi = {
  login: (username: string, password: string) =>
    api<TokenResponse>(`${AUTH}/auth/login`, { method: "POST", body: { username, password }, auth: false }),
  refresh: () =>
    api<TokenResponse>(`${AUTH}/auth/refresh`, {
      method: "POST",
      auth: false,
      headers: { "X-Requested-With": "ra-dashboard" },
    }),
  logout: () => api<void>(`${AUTH}/auth/logout`, { method: "POST" }),
  me: () => api<Principal & { token_expires_at: string }>(`${AUTH}/me`),
};

// ------------------------------------------------------------------ paiements
export interface PaymentInput {
  debit_account_id: string;
  credit_account_number: string;
  amount: { value: string; currency: string };
  description?: string;
  auto_execute: boolean;
}

export const paymentApi = {
  accounts: (includeSynthetic = false) =>
    api<{ items: Account[] }>(`${PAYMENT}/accounts${includeSynthetic ? "?include_synthetic=true" : ""}`),
  transactions: (params: { cursor?: string | null; limit?: number; status?: string } = {}) => {
    const query = new URLSearchParams({ limit: String(params.limit ?? 25) });
    if (params.cursor) query.set("cursor", params.cursor);
    if (params.status) query.set("status", params.status);
    return api<Page<Transaction>>(`${PAYMENT}/transactions?${query}`);
  },
  transaction: (id: string) => api<TransactionDetail>(`${PAYMENT}/transactions/${encodeURIComponent(id)}`),
  create: (input: PaymentInput, idempotencyKey: string = newIdempotencyKey()) =>
    api<Transaction>(`${PAYMENT}/transactions`, {
      method: "POST",
      body: input,
      headers: { "Idempotency-Key": idempotencyKey },
    }),
  execute: (id: string) => api<Transaction>(`${PAYMENT}/transactions/${encodeURIComponent(id)}/execute`, { method: "POST" }),
  cancel: (id: string) => api<Transaction>(`${PAYMENT}/transactions/${encodeURIComponent(id)}/cancel`, { method: "POST" }),
  streamTicket: () => api<{ ticket: string; expires_in: number }>(`${PAYMENT}/stream-tickets`, { method: "POST" }),
  streamUrl: `${PAYMENT}/transactions/events`,
};

// ------------------------------------------------------------ laboratoire
export interface FaultRequest {
  type: "LATENCY" | "ERROR_RATE" | "READINESS_FAILURE" | "POOL_EXHAUSTION" | "CRASH" | "BALANCE_TAMPER";
  params?: Record<string, unknown>;
  duration_seconds?: number;
}

export const labApi = {
  faults: () => api<{ items: { fault_id: string; type: string; active_until: string | null }[] }>(`${LAB}/faults`),
  inject: (fault: FaultRequest) => api<{ fault_id: string; type: string }>(`${LAB}/faults`, { method: "POST", body: fault }),
  clear: () => api<{ cleared: number }>(`${LAB}/faults`, { method: "DELETE" }),
};

// -------------------------------------------------------------- supervision
export const supervisionApi = {
  overview: () => api<Overview>(`${SUPERVISION}/overview`),
  timeline: (from: Date, to: Date) =>
    api<Timeline>(`${SUPERVISION}/timeline?from=${encodeURIComponent(from.toISOString())}&to=${encodeURIComponent(to.toISOString())}`),
  incidents: (limit = 20) => api<Page<IncidentSummary>>(`${SUPERVISION}/incidents?limit=${limit}`),
  incident: (id: string) => api<IncidentDetail>(`${SUPERVISION}/incidents/${encodeURIComponent(id)}`),
  health: (window: string) => api<HealthHistory>(`${SUPERVISION}/services/health?window=${encodeURIComponent(window)}`),
  streamTicket: () => api<{ ticket: string; expires_in: number }>(`${SUPERVISION}/stream-tickets`, { method: "POST" }),
  streamUrl: `${SUPERVISION}/stream`,
};

// ----------------------------------------------------------- administration
export const HUMAN_ROLES = [
  "auth.admin",
  "chaos.operator",
  "noc.viewer",
  "payment.operator",
  "remediation.admin",
  "payment.customer",
] as const;

export interface AdminPrincipal {
  id: string;
  username: string;
  display_name: string;
  kind: "USER" | "SERVICE";
  roles: string[];
  is_active: boolean;
  locked_until: string | null;
  last_login_at: string | null;
}

export interface PlaybookInfo {
  code: string;
  title: string;
  category: string;
  enabled: boolean;
  max_attempts: number;
  cooldown_seconds: number;
  steps: unknown[];
}

const ADMIN = `${SUPERVISION}/admin`;

export const adminApi = {
  principals: () => api<{ items: AdminPrincipal[] }>(`${AUTH}/admin/principals?limit=200`),
  setRole: (id: string, role: string, grant: boolean) =>
    api<AdminPrincipal>(`${AUTH}/admin/principals/${id}/roles/${role}`, { method: grant ? "POST" : "DELETE" }),
  principalAction: (id: string, action: "disable" | "enable" | "revoke-tokens") =>
    api<unknown>(`${AUTH}/admin/principals/${id}/${action}`, { method: "POST", body: { reason: "ADMIN_CONSOLE" } }),
  sessions: () =>
    api<{ items: { family_id: string; username: string; last_refresh: string; expires_at: string; client_ip: string | null; user_agent: string | null }[] }>(
      `${AUTH}/admin/sessions`,
    ),
  authAudit: () =>
    api<{ items: { occurred_at: string; event_type: string; outcome: string; username: string | null; actor: string | null }[] }>(
      `${AUTH}/admin/audit?limit=100`,
    ),
  playbooks: () => api<PlaybookInfo[]>(`${ADMIN}/playbooks`),
  togglePlaybook: (code: string, enabled: boolean) =>
    api<PlaybookInfo>(`${ADMIN}/playbooks/${encodeURIComponent(code)}`, { method: "PATCH", body: { enabled } }),
  engineAudit: () =>
    api<{ items: { at: string; incident_id: string; target_service: string; kind: string; action: string; detail: string; actor: "human" | "automated" }[] }>(
      `${ADMIN}/audit?limit=150`,
    ),
  engineSettings: () => api<Record<string, number | boolean>>(`${ADMIN}/settings`),
  verify: (id: string, reason: string) => api<unknown>(`${ADMIN}/incidents/${id}/verify`, { method: "POST", body: { reason } }),
  acknowledge: (id: string, reason: string) =>
    api<unknown>(`${ADMIN}/incidents/${id}/acknowledge`, { method: "POST", body: { reason } }),
  simulateAlert: (body: { service: string; category: string; severity: string }) =>
    api<{ incident_id: string; deduplicated: boolean }>(`${ADMIN}/simulate-alert`, { method: "POST", body }),
};

// ---------------------------------------------------------------- assistant
export const assistantApi = {
  chat: (message: string, conversationId: string | null, context: { incident_id?: string; phase?: string }) =>
    api<ChatReply>(`${ASSISTANT}/chat`, {
      method: "POST",
      body: { conversation_id: conversationId, message, context },
    }),
};
