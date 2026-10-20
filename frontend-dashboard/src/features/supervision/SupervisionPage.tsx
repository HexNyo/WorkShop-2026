import { useEffect, useRef } from "react";

import { useAuth } from "../../auth/AuthProvider";
import { ErrorBanner, Spinner, StatTile } from "../../components/ui";
import { formatDuration, formatTime } from "../../lib/format";
import { playAlert, useSettings } from "../../lib/settings";
import { ChaosLabPanel } from "./ChaosLabPanel";
import { EventFeed } from "./EventFeed";
import { IncidentHistory } from "./IncidentHistory";
import { IncidentPanel } from "./IncidentPanel";
import { PhaseBanner } from "./PhaseBanner";
import { PhaseTimeline } from "./PhaseTimeline";
import { RemediationLog } from "./RemediationLog";
import { ServicesPanel } from "./ServicesPanel";
import { useSupervision } from "./useSupervision";
import { VerificationChecklist } from "./VerificationChecklist";

export function SupervisionPage() {
  const { hasRole } = useAuth();
  const state = useSupervision();
  const { overview } = state;
  const settings = useSettings();
  const lastPhase = useRef(overview?.phase);

  // Alerte sonore / notification navigateur au passage en phase critique (préférences locales).
  useEffect(() => {
    const phase = overview?.phase;
    if (phase === "CRITICAL" && lastPhase.current && lastPhase.current !== "CRITICAL") {
      if (settings.audioAlert) playAlert();
      if (settings.browserNotifications && "Notification" in window && Notification.permission === "granted") {
        new Notification("RESILIENCE-ALPHA — incident critique", { body: state.phaseReason ?? "Phase système critique" });
      }
    }
    lastPhase.current = phase;
  }, [overview?.phase, settings.audioAlert, settings.browserNotifications, state.phaseReason]);

  if (!overview) {
    return (
      <div className="space-y-4">
        <ErrorBanner error={state.error} title="Console indisponible" />
        {!state.error && <Spinner label="Chargement de la console…" />}
      </div>
    );
  }

  const last = overview.last_verification;
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold">Centre de supervision NOC/SOC</h1>
        <p className="text-xs text-muted">
          Détection → décision → remédiation → vérification synthétique, sans intervention humaine.
        </p>
      </div>
      <ErrorBanner error={state.error} title="Mise à jour partielle" />

      <PhaseBanner phase={overview.phase} since={overview.phase_since} reason={state.phaseReason} />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile
          label="Incidents ouverts"
          value={overview.counters.open_incidents}
          valueClass={overview.counters.open_incidents > 0 ? "text-red-400" : "text-ink"}
          hint={overview.active_incident ? `actif : ${overview.active_incident.target_service}` : "aucun incident actif"}
        />
        <StatTile
          label="Résolus automatiquement (24 h)"
          value={overview.counters.resolved_24h}
          valueClass="text-emerald-400"
          hint="Zero-Touch, vérification synthétique PASSED"
        />
        <StatTile
          label="Escaladés à un humain (24 h)"
          value={overview.counters.escalated_24h}
          valueClass={overview.counters.escalated_24h > 0 ? "text-amber-400" : "text-ink"}
          hint="fenêtre glissante 24 h"
        />
        <StatTile
          label="Temps médian de rétablissement (24 h)"
          value={formatDuration(overview.counters.mttr_p50_seconds)}
          valueClass={(overview.counters.mttr_p50_seconds ?? 0) > settings.slaSeconds ? "text-amber-400" : "text-emerald-400"}
          hint={`Objectif SLA < ${settings.slaSeconds} s${
            last ? ` · dernière vérif. ${last.status === "PASSED" ? "réussie" : "en échec"} à ${formatTime(last.finished_at)}` : ""
          }`}
        />
      </div>

      <PhaseTimeline
        timeline={state.timeline}
        range={state.range}
        onRange={state.setRange}
        onFocusIncident={state.detail || overview.active_incident ? state.focusIncident : undefined}
      />

      <div className="grid gap-5 xl:grid-cols-3">
        <div className="space-y-5 xl:col-span-2">
          <IncidentPanel detail={state.detail} pinned={state.pinned} onUnpin={() => state.select(null)} onChanged={state.reload} />
          <div className="grid gap-5 lg:grid-cols-2">
            <RemediationLog detail={state.detail} />
            <VerificationChecklist detail={state.detail} />
          </div>
        </div>
        <div className="space-y-5">
          <ServicesPanel
            services={overview.services}
            history={state.health}
            activeIncident={overview.active_incident}
            onSelectIncident={(id) => state.select(id)}
          />
          <EventFeed events={state.feed} status={state.streamStatus} />
        </div>
      </div>

      <IncidentHistory incidents={state.incidents} selectedId={state.selectedId} onSelect={(id) => state.select(id)} />

      {hasRole("chaos.operator") && <ChaosLabPanel />}
    </div>
  );
}
