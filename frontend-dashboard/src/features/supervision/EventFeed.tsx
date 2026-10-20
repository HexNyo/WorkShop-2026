import type { StreamEnvelope } from "../../api/types";
import { Card, EmptyState } from "../../components/ui";
import { StreamIndicator } from "../payments/TransactionsTable";
import type { StreamStatus } from "../../hooks/useEventStream";
import { formatTime, humanizeAction } from "../../lib/format";
import { PHASES } from "../../lib/status";
import type { Phase } from "../../api/types";

function describe(event: StreamEnvelope): { icon: string; text: string } | null {
  const p = event.payload as Record<string, unknown>;
  switch (event.type) {
    case "alert.received":
      return {
        icon: "▼",
        text: `Alerte ${p.severity} ${p.category} (${p.source}${p.confidence ? `, confiance ${Number(p.confidence).toFixed(2)}` : ""})${
          p.deduplicated ? " — rattachée à l'incident ouvert" : ""
        }`,
      };
    case "incident.opened":
      return { icon: "!", text: `Incident ouvert : ${p.title}` };
    case "incident.status_changed":
      return { icon: "›", text: `Incident ${p.from} → ${p.to} : ${p.reason}` };
    case "remediation.step":
      return p.status === "RUNNING"
        ? { icon: "↻", text: `Action ${humanizeAction(String(p.action))} en cours${p.target ? ` → ${p.target}` : ""}` }
        : { icon: p.status === "SUCCEEDED" ? "✔" : "✖", text: `Action ${humanizeAction(String(p.action))} : ${p.status}${p.error ? ` — ${p.error}` : ""}` };
    case "verification.started":
      return { icon: "⋯", text: `Vérification synthétique démarrée (${p.trigger_source})` };
    case "verification.check":
      return { icon: p.passed ? "✔" : "✖", text: `Contrôle ${p.code} ${p.passed ? "réussi" : "en échec"}` };
    case "verification.completed":
      return { icon: p.status === "PASSED" ? "✔" : "✖", text: `Vérification ${p.status}${p.failed_check ? ` (${p.failed_check})` : ""}` };
    case "incident.closed":
      return { icon: "●", text: `Incident clos : ${p.resolution}${p.mttr_seconds ? ` en ${p.mttr_seconds} s` : ""}` };
    case "incident.acknowledged":
      return { icon: "✋", text: `Incident acquitté par ${p.by} : ${p.reason}` };
    case "system.phase_changed":
      return { icon: PHASES[p.phase as Phase]?.icon ?? "◆", text: `Phase ${p.previous} → ${p.phase} : ${p.reason}` };
    default:
      return null;
  }
}

/** Fil des événements temps réel (hors battements de santé). */
export function EventFeed({ events, status }: { events: StreamEnvelope[]; status: StreamStatus }) {
  const visible = events
    .filter((event) => event.type !== "service.health")
    .map((event) => ({ event, line: describe(event) }))
    .filter((item): item is { event: StreamEnvelope; line: { icon: string; text: string } } => item.line !== null);

  return (
    <Card title="Événements en direct" subtitle="Alertes, décisions et contrôles du moteur" actions={<StreamIndicator status={status} />}>
      {visible.length === 0 ? (
        <EmptyState>Aucun événement depuis l'ouverture de la console.</EmptyState>
      ) : (
        <ol className="max-h-80 space-y-1 overflow-y-auto pr-1 text-xs" aria-live="polite" data-testid="event-feed">
          {visible.map(({ event, line }) => (
            <li key={event.seq} className="flex gap-2">
              <span className="tabular shrink-0 text-muted">{formatTime(event.occurred_at)}</span>
              <span aria-hidden="true" className="w-3 shrink-0 text-center text-ink-2">
                {line.icon}
              </span>
              <span className="text-ink">{line.text}</span>
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}
