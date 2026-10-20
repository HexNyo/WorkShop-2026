/** Types des contrats d'API (docs/03-contrats-api.md). */

export type Role =
  | "payment.customer"
  | "payment.operator"
  | "noc.viewer"
  | "remediation.admin"
  | "auth.admin"
  | "chaos.operator";

export interface Principal {
  id: string;
  username: string;
  display_name: string;
  kind: "USER" | "SERVICE";
  roles: string[];
}

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  principal: Principal;
}

export interface Money {
  value: string;
  currency: string;
  minor: number;
}

export interface Account {
  id: string;
  account_number: string;
  holder_name: string;
  currency: string;
  status: "ACTIVE" | "FROZEN" | "CLOSED";
  is_synthetic: boolean;
  balance: Money;
  updated_at: string;
}

export type TransactionStatus = "PENDING" | "VALIDATED" | "EXECUTED" | "REJECTED" | "FAILED" | "CANCELLED";

export interface Transaction {
  id: string;
  status: TransactionStatus;
  debit_account: { id: string; account_number: string };
  credit_account: { id: string; account_number: string };
  amount: Money;
  description: string | null;
  is_synthetic: boolean;
  failure: { code: string; reason: string | null } | null;
  idempotency_key: string;
  created_at: string;
  validated_at: string | null;
  executed_at: string | null;
}

export interface TransactionDetail extends Transaction {
  history: { status: TransactionStatus; at: string }[];
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

/** Charge utile des événements SSE transaction.created / transaction.updated. */
export interface TransactionEventPayload {
  id: string;
  status: TransactionStatus;
  debit_account_number: string;
  credit_account_number: string;
  amount: Money;
  failure: { code: string; reason: string | null } | null;
  is_synthetic: boolean;
  updated_at: string;
}

// ------------------------------------------------------------------ supervision
export type Phase = "NOMINAL" | "DEGRADED" | "CRITICAL" | "RECOVERING" | "RESTORED";
export type ServiceStatus = "UP" | "DEGRADED" | "DOWN" | "UNKNOWN";
export type IncidentStatus = "OPEN" | "TRIAGED" | "REMEDIATING" | "VERIFYING" | "RESOLVED" | "ESCALATED" | "SUPPRESSED";

export interface IncidentSummary {
  id: string;
  title: string;
  category: string;
  severity: "INFO" | "WARNING" | "HIGH" | "CRITICAL";
  status: IncidentStatus;
  status_reason: string;
  target_service: string;
  playbook_code: string | null;
  attempt: number;
  alert_count: number;
  resolution: string | null;
  opened_at: string;
  closed_at: string | null;
  mttr_seconds: number | null;
}

export interface ServiceHealth {
  name: string;
  status: ServiceStatus;
  latency_ms: number | null;
  checked_at: string | null;
  detail?: string | null;
}

export interface Overview {
  phase: Phase;
  phase_since: string;
  phase_incident_id: string | null;
  active_incident: IncidentSummary | null;
  services: ServiceHealth[];
  counters: { open_incidents: number; resolved_24h: number; escalated_24h: number; mttr_p50_seconds: number | null };
  last_verification: {
    run_id: string;
    status: "PASSED" | "FAILED";
    trigger_source: string;
    failed_check: string | null;
    finished_at: string | null;
  } | null;
  stream_seq: number;
}

export interface RemediationStep {
  phase: "REMEDIATION" | "POST_VERIFICATION";
  seq: number;
  action: string;
  target: string | null;
  status: "PENDING" | "RUNNING" | "SUCCEEDED" | "FAILED" | "SKIPPED";
  duration_ms: number | null;
  output: Record<string, unknown> | null;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface Execution {
  id: string;
  attempt: number;
  status: "RUNNING" | "SUCCEEDED" | "FAILED" | "ABORTED";
  playbook_code: string;
  playbook_version: number;
  started_at: string;
  finished_at: string | null;
  error: string | null;
  steps: RemediationStep[];
}

export interface VerificationCheck {
  seq: number;
  code: string;
  passed: boolean;
  latency_ms: number | null;
  detail: Record<string, unknown>;
}

export interface Verification {
  id: string;
  trigger_source: string;
  status: "RUNNING" | "PASSED" | "FAILED";
  failed_check: string | null;
  started_at: string;
  finished_at: string | null;
  synthetic_transaction_ids: string[];
  checks: VerificationCheck[];
}

export interface IncidentDetail {
  id: string;
  title: string;
  category: string;
  severity: IncidentSummary["severity"];
  status: IncidentStatus;
  status_reason: string;
  resolution: string | null;
  last_error: string | null;
  target: { service: string; principal_id: string | null; account_id: string | null };
  playbook_code: string | null;
  attempt: number;
  opened_at: string;
  remediation_started_at: string | null;
  verified_at: string | null;
  closed_at: string | null;
  mttr_seconds: number | null;
  alerts: {
    id: string;
    source: string;
    external_id: string;
    category: string;
    severity: string;
    confidence: number | null;
    title: string;
    detected_at: string;
    received_at: string;
  }[];
  transitions: { from: IncidentStatus | null; to: IncidentStatus; reason: string; at: string }[];
  executions: Execution[];
  verifications: Verification[];
}

export interface Timeline {
  segments: { phase: Phase; from: string; to: string | null; incident_id: string | null }[];
  markers: { at: string; kind: string; label: string; incident_id: string | null }[];
}

export interface HealthHistory {
  series: { service: string; points: { t: string; status: ServiceStatus; latency_ms: number | null }[] }[];
}

export interface StreamEnvelope<P = Record<string, unknown>> {
  type: string;
  seq: number;
  occurred_at: string;
  incident_id?: string | null;
  payload: P;
}

// -------------------------------------------------------------------- assistant
export interface ChatSource {
  title: string;
  uri: string;
  excerpt: string;
  score: number;
}

export interface ChatReply {
  conversation_id: string;
  message_id: string;
  answer: string;
  sources: ChatSource[];
  created_at: string;
}
