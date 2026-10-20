import type { IncidentDetail } from "../../api/types";
import { Card, Code, EmptyState, StatusPill } from "../../components/ui";
import { formatDuration, formatTime, humanizeAction } from "../../lib/format";
import { STEP_STATUS } from "../../lib/status";

const PHASE_LABEL = { REMEDIATION: "Remédiation", POST_VERIFICATION: "Après vérification" } as const;

function summarize(output: Record<string, unknown> | null): string | null {
  if (!output) return null;
  const parts = Object.entries(output)
    .filter(([, value]) => value !== null && typeof value !== "object")
    .slice(0, 4)
    .map(([key, value]) => `${key.replaceAll("_", " ")} : ${String(value)}`);
  return parts.length ? parts.join(" · ") : null;
}

/** Journal pas-à-pas du moteur : chaque tentative, chaque action, son résultat. */
export function RemediationLog({ detail }: { detail: IncidentDetail | null }) {
  const executions = detail?.executions ?? [];
  return (
    <Card title="Journal de remédiation" subtitle="Exécution pas-à-pas du playbook (temps réel)">
      {executions.length === 0 ? (
        <EmptyState>{detail ? "Aucune action exécutée pour cet incident." : "En attente d'un incident."}</EmptyState>
      ) : (
        <ol className="space-y-4" data-testid="remediation-log">
          {executions.map((execution) => (
            <li key={execution.id}>
              <p className="mb-1.5 text-xs font-semibold">
                Tentative {execution.attempt} · <span className="font-mono">{execution.playbook_code}</span>
                <span className="ml-2 font-normal text-muted">
                  {formatTime(execution.started_at)} — {execution.status}
                  {execution.error && (
                    <>
                      {" · "}
                      <Code>{execution.error}</Code>
                    </>
                  )}
                </span>
              </p>
              <ol className="space-y-1.5 border-l border-line pl-3">
                {execution.steps.map((step) => (
                  <li key={`${step.phase}-${step.seq}`} className="text-xs" data-testid="remediation-step" data-status={step.status}>
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusPill visual={STEP_STATUS[step.status] ?? STEP_STATUS.PENDING!} compact />
                      <span className="font-medium capitalize">{humanizeAction(step.action)}</span>
                      <Code>{step.action}</Code>
                      {step.target && <span className="text-ink-2">→ {step.target}</span>}
                      <span className="tabular text-muted">{formatDuration(step.duration_ms !== null ? step.duration_ms / 1000 : null)}</span>
                      {step.phase === "POST_VERIFICATION" && <span className="text-[0.7rem] text-muted">({PHASE_LABEL[step.phase]})</span>}
                    </div>
                    {(step.error || summarize(step.output)) && (
                      <p className="mt-1">{step.error ? <Code>{step.error}</Code> : <span className="text-ink-2">{summarize(step.output)}</span>}</p>
                    )}
                  </li>
                ))}
              </ol>
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}
