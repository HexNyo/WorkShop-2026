import { useState } from "react";

import type { HealthHistory, IncidentSummary, ServiceHealth } from "../../api/types";
import { Card, StatusPill, cx } from "../../components/ui";
import { formatTime } from "../../lib/format";
import { SERVICE_STATUS, TONE_CLASSES } from "../../lib/status";

const LABELS: Record<string, string> = {
  "auth-service": "Authentification",
  "payment-api": "API de paiement",
  database: "Base de données",
  "remediation-engine": "Moteur de remédiation",
  "frontend-dashboard": "Portail / passerelle",
};

/** Bande d'état des 15 dernières minutes (une cellule par sondage, infobulle native). */
function HealthStrip({ points }: { points: HealthHistory["series"][number]["points"] }) {
  const recent = points.slice(-90);
  if (recent.length === 0) return <p className="text-[0.7rem] text-muted">pas d'historique</p>;
  return (
    <div className="flex h-3 gap-px" role="img" aria-label={`Historique de santé : ${recent.length} sondages`}>
      {recent.map((point) => (
        <span
          key={point.t}
          title={`${formatTime(point.t)} · ${SERVICE_STATUS[point.status].label}${point.latency_ms !== null ? ` · ${point.latency_ms} ms` : ""}`}
          className={cx("min-w-[2px] flex-1 rounded-[1px]", TONE_CLASSES[SERVICE_STATUS[point.status].tone].bg)}
        />
      ))}
    </div>
  );
}

export function ServicesPanel({
  services,
  history,
  activeIncident,
  onSelectIncident,
}: {
  services: ServiceHealth[];
  history: HealthHistory | null;
  activeIncident: IncidentSummary | null;
  onSelectIncident: (id: string) => void;
}) {
  const [showDetail, setShowDetail] = useState(false);
  return (
    <Card
      title="Santé des microservices"
      subtitle="Sondes de disponibilité toutes les 5 s — 15 dernières minutes"
      actions={
        <button type="button" className="text-xs text-accent underline" onClick={() => setShowDetail((value) => !value)}>
          {showDetail ? "Masquer les détails" : "Détails"}
        </button>
      }
    >
      <ul className="space-y-3">
        {services.map((service) => {
          const points = history?.series.find((series) => series.service === service.name)?.points ?? [];
          return (
            <li key={service.name} data-testid={`service-${service.name}`} data-status={service.status}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="text-sm font-medium">{LABELS[service.name] ?? service.name}</p>
                  <p className="font-mono text-[0.7rem] text-muted">{service.name}</p>
                </div>
                <div className="flex items-center gap-3">
                  {/* La pastille reste la vérité de la sonde ; le lien signale l'incident qui cible ce service. */}
                  {activeIncident?.target_service === service.name && (
                    <button
                      type="button"
                      onClick={() => onSelectIncident(activeIncident.id)}
                      className="rounded-full border border-red-500/40 bg-red-950/40 px-2 py-0 text-[0.7rem] font-medium text-red-300 hover:border-red-400"
                    >
                      Incident ouvert ↗
                    </button>
                  )}
                  <span className="tabular text-xs text-ink-2">
                    {service.latency_ms !== null ? `${service.latency_ms} ms` : "—"}
                  </span>
                  <StatusPill visual={SERVICE_STATUS[service.status]} compact />
                </div>
              </div>
              <div className="mt-1.5">
                <HealthStrip points={points} />
              </div>
              {showDetail && (
                <p className="mt-1 text-[0.7rem] text-muted">
                  dernier sondage {formatTime(service.checked_at)}
                  {service.detail ? ` · ${service.detail}` : ""}
                </p>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
