import type { IncidentDetail } from "../../api/types";
import { Card, StatusPill } from "../../components/ui";
import { formatTime } from "../../lib/format";
import { VERIFICATION_CHECKS, type StatusVisual } from "../../lib/status";

const STATES: Record<"passed" | "failed" | "pending" | "skipped", StatusVisual> = {
  passed: { tone: "good", icon: "✔", label: "OK" },
  failed: { tone: "critical", icon: "✖", label: "Échec" },
  pending: { tone: "neutral", icon: "○", label: "À venir" },
  skipped: { tone: "neutral", icon: "–", label: "Non exécuté" },
};

/** Protocole de validation post-reprise : l'incident n'est clos que si les 9 contrôles passent. */
export function VerificationChecklist({ detail }: { detail: IncidentDetail | null }) {
  const run = detail?.verifications.at(-1) ?? null;
  const results = new Map(run?.checks.map((check) => [check.code, check]) ?? []);
  const failedIndex = run?.failed_check ? VERIFICATION_CHECKS.findIndex((check) => check.code === run.failed_check) : -1;

  return (
    <Card
      title="Vérification post-reprise"
      subtitle="Transaction synthétique de bout en bout — condition de clôture"
      actions={
        run && (
          <StatusPill
            visual={
              run.status === "PASSED"
                ? { tone: "good", icon: "✔", label: "Reprise prouvée" }
                : run.status === "FAILED"
                  ? { tone: "critical", icon: "✖", label: `Échec : ${run.failed_check}` }
                  : { tone: "accent", icon: "⋯", label: "En cours" }
            }
          />
        )
      }
    >
      {!run ? (
        <p className="text-xs text-muted">
          Aucune vérification pour cet incident. Le moteur la lance automatiquement après les actions de remédiation.
        </p>
      ) : (
        <ol className="space-y-1" data-testid="verification-checklist" data-status={run.status}>
          {VERIFICATION_CHECKS.map((check, index) => {
            const result = results.get(check.code);
            const state = result
              ? result.passed
                ? "passed"
                : "failed"
              : failedIndex >= 0 && index > failedIndex
                ? "skipped"
                : "pending";
            return (
              <li key={check.code} className="flex items-center justify-between gap-3 text-xs">
                <div className="min-w-0">
                  <p className="font-medium">{check.label}</p>
                  <p className="truncate text-[0.7rem] text-muted" title={check.proves}>
                    prouve que {check.proves}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  {result?.latency_ms !== null && result?.latency_ms !== undefined && (
                    <span className="tabular text-muted">{result.latency_ms} ms</span>
                  )}
                  <StatusPill visual={STATES[state]} compact />
                </div>
              </li>
            );
          })}
          <li className="pt-1 text-[0.7rem] text-muted">
            Démarrée {formatTime(run.started_at)}
            {run.finished_at ? ` · terminée ${formatTime(run.finished_at)}` : ""} · déclencheur {run.trigger_source}
          </li>
        </ol>
      )}
    </Card>
  );
}
