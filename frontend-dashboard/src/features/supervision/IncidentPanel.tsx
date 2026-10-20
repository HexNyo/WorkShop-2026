import { useState } from "react";

import { adminApi } from "../../api/endpoints";
import type { IncidentDetail } from "../../api/types";
import { useAuth } from "../../auth/AuthProvider";
import { Button, Card, Code, Drawer, EmptyState, ErrorBanner, Input, StatusPill, cx } from "../../components/ui";
import { formatDateTime, formatDuration, formatSince } from "../../lib/format";
import { INCIDENT_FLOW, INCIDENT_STATUS, TONE_CLASSES } from "../../lib/status";
import { RemediationLog } from "./RemediationLog";
import { VerificationChecklist } from "./VerificationChecklist";

const CATEGORY_LABELS: Record<string, string> = {
  SERVICE_UNAVAILABLE: "Service indisponible",
  PERFORMANCE_DEGRADATION: "Dégradation des performances",
  RESOURCE_EXHAUSTION: "Épuisement de ressources",
  DATA_INTEGRITY_VIOLATION: "Atteinte à l'intégrité des données",
  CREDENTIAL_COMPROMISE: "Identifiants compromis",
  ANOMALOUS_TRAFFIC: "Trafic anormal",
  FRAUD_PATTERN: "Schéma de fraude",
};

/** Progression OPEN → RESOLVED ; une escalade est signalée hors du flux nominal. */
function Stepper({ detail }: { detail: IncidentDetail }) {
  const reached = new Set(detail.transitions.map((transition) => transition.to));
  const escalated = detail.status === "ESCALATED";
  return (
    <ol className="flex flex-wrap items-center gap-1" aria-label="Progression de l'incident">
      {INCIDENT_FLOW.map((status, index) => {
        const current = detail.status === status;
        const done = reached.has(status) && !current;
        const visual = INCIDENT_STATUS[status];
        return (
          <li key={status} className="flex items-center gap-1">
            <span
              aria-current={current ? "step" : undefined}
              className={cx(
                "rounded-full border px-2 py-0.5 text-[0.7rem]",
                current
                  ? cx(TONE_CLASSES[visual.tone].border, TONE_CLASSES[visual.tone].soft, "font-semibold text-ink")
                  : done
                    ? "border-line text-ink-2"
                    : "border-dashed border-line text-muted",
              )}
            >
              {done ? "✔ " : current ? `${visual.icon} ` : ""}
              {visual.label}
            </span>
            {index < INCIDENT_FLOW.length - 1 && (
              <span aria-hidden="true" className="text-muted">
                ›
              </span>
            )}
          </li>
        );
      })}
      {escalated && <StatusPill visual={INCIDENT_STATUS.ESCALATED} compact />}
    </ol>
  );
}

/** Pilotage d'un incident escaladé : commande CLI complète + actions directes (remediation.admin). */
function EscalationBox({ detail, onChanged }: { detail: IncidentDetail; onChanged: () => void }) {
  const { principal, hasRole } = useAuth();
  const [reason, setReason] = useState("cause corrigée, vérification demandée");
  const [busy, setBusy] = useState<"verify" | "ack" | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [copied, setCopied] = useState(false);
  const command = `ra-ctl --user ${principal?.username ?? "admin"} verify ${detail.id} --reason "${reason.replaceAll('"', "'")}"`;
  const run = async (kind: "verify" | "ack") => {
    setBusy(kind);
    setError(null);
    try {
      await (kind === "verify" ? adminApi.verify(detail.id, reason) : adminApi.acknowledge(detail.id, reason));
      onChanged();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(null);
    }
  };
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false); // presse-papiers refusé (contexte non sécurisé) : la commande reste sélectionnable
    }
  };
  return (
    <div role="alert" className="space-y-2 rounded-lg border border-red-500/40 bg-red-950/30 px-3 py-2.5 text-xs">
      <p className="font-semibold">
        <span aria-hidden="true" className="mr-1 inline-block animate-pulse text-red-400">
          ⚑
        </span>
        Action humaine requise
      </p>
      {detail.last_error && <Code block>{detail.last_error}</Code>}
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <Code block>{command}</Code>
        </div>
        <Button variant="secondary" onClick={() => void copy()} aria-label="Copier la commande">
          {copied ? "Copié ✔" : "Copier"}
        </Button>
      </div>
      {hasRole("remediation.admin") && (
        <>
          <label className="block text-muted" htmlFor="operator-reason">
            Motif (journalisé)
          </label>
          <Input id="operator-reason" value={reason} minLength={5} maxLength={256} onChange={(event) => setReason(event.target.value)} />
          <div className="flex flex-wrap gap-2">
            <Button variant="danger" busy={busy === "verify"} disabled={reason.trim().length < 5} onClick={() => void run("verify")}>
              Forcer la vérification
            </Button>
            <Button variant="secondary" busy={busy === "ack"} disabled={reason.trim().length < 5} onClick={() => void run("ack")}>
              Acquitter l'incident
            </Button>
          </div>
          <ErrorBanner error={error} title="Action refusée" />
        </>
      )}
    </div>
  );
}

const BADGE =
  "inline-flex items-center gap-1 rounded border border-white/[0.08] bg-black/40 px-1.5 py-0.5 font-mono text-[0.7rem] text-zinc-300 hover:border-white/[0.2]";

export function IncidentPanel({
  detail,
  pinned,
  onUnpin,
  onChanged,
}: {
  detail: IncidentDetail | null;
  pinned: boolean;
  onUnpin: () => void;
  onChanged: () => void;
}) {
  const [logsOpen, setLogsOpen] = useState(false);
  return (
    <Card
      title="Incident"
      subtitle={pinned ? "Sélection manuelle" : "Incident actif ou le plus récent"}
      actions={
        pinned ? (
          <button type="button" className="text-xs text-accent underline" onClick={onUnpin}>
            Suivre l'incident actif
          </button>
        ) : undefined
      }
    >
      {!detail ? (
        <EmptyState>Aucun incident enregistré. La plateforme fonctionne en régime nominal.</EmptyState>
      ) : (
        <div className="space-y-3" data-testid="incident-panel" data-status={detail.status}>
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div>
              <p className="text-sm font-semibold">{detail.title}</p>
              <p className="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-ink-2">
                {CATEGORY_LABELS[detail.category] ?? detail.category}
                <button type="button" className={BADGE} onClick={() => setLogsOpen(true)} title="Voir les journaux de tentative">
                  {detail.category} ↗
                </button>
                · cible <Code>{detail.target.service}</Code>
              </p>
            </div>
            <StatusPill visual={INCIDENT_STATUS[detail.status]} />
          </div>
          <Stepper detail={detail} />
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs sm:grid-cols-4">
            <div>
              <dt className="text-muted">Ouvert</dt>
              <dd className="tabular">{formatDateTime(detail.opened_at)}</dd>
            </div>
            <div>
              <dt className="text-muted">Playbook</dt>
              <dd>
                {detail.playbook_code ? (
                  <button type="button" className={BADGE} onClick={() => setLogsOpen(true)} title="Voir les journaux de tentative">
                    {detail.playbook_code} ↗
                  </button>
                ) : (
                  "—"
                )}
              </dd>
            </div>
            <div>
              <dt className="text-muted">Tentative</dt>
              <dd className="tabular">{detail.attempt}</dd>
            </div>
            <div>
              <dt className="text-muted">{detail.closed_at ? "Temps de rétablissement" : "Durée en cours"}</dt>
              <dd className="tabular font-semibold">
                {detail.closed_at ? formatDuration(detail.mttr_seconds) : formatSince(detail.opened_at)}
              </dd>
            </div>
          </dl>
          <p className="text-xs text-ink-2">
            <span className="text-muted">Dernière décision : </span>
            <Code>{detail.status_reason}</Code>
          </p>
          {detail.status === "ESCALATED" && <EscalationBox detail={detail} onChanged={onChanged} />}
          <p className="text-[0.7rem] text-muted">
            {detail.alerts.length} alerte(s) · sources : {[...new Set(detail.alerts.map((alert) => alert.source))].join(", ")}
          </p>
          {logsOpen && (
            <Drawer title={`Journaux de tentative · ${detail.playbook_code ?? detail.category}`} onClose={() => setLogsOpen(false)} wide>
              <div className="space-y-4">
                <RemediationLog detail={detail} />
                <VerificationChecklist detail={detail} />
              </div>
            </Drawer>
          )}
        </div>
      )}
    </Card>
  );
}
