import { useEffect, useRef } from "react";

import { useAuth } from "../../auth/AuthProvider";
import { ErrorBanner, Spinner, StatTile } from "../../components/ui";
import { formatDuration } from "../../lib/format";
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
        new Notification("Workshop 2026 — incident critique", { body: state.phaseReason ?? "Phase système critique" });
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

  return (
    <div className="space-y-5">
      <h1 className="sr-only">Supervision</h1>
      <ErrorBanner error={state.error} title="Mise à jour partielle" />

      <PhaseBanner phase={overview.phase} since={overview.phase_since} reason={state.phaseReason} />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile
          label="Incidents ouverts"
          value={overview.counters.open_incidents}
          valueClass={overview.counters.open_incidents > 0 ? "text-red-400" : "text-ink"}
          hint={overview.active_incident?.target_service}
          className="border-t-2 border-t-rose-400 from-rose-500/10"
        />
        <StatTile
          label="Résolus auto. (24 h)"
          value={overview.counters.resolved_24h}
          valueClass="text-emerald-400"
          className="border-t-2 border-t-emerald-400 from-emerald-500/10"
        />
        <StatTile
          label="Escaladés (24 h)"
          value={overview.counters.escalated_24h}
          valueClass={overview.counters.escalated_24h > 0 ? "text-amber-400" : "text-ink"}
          className="border-t-2 border-t-amber-400 from-amber-500/10"
        />
        <StatTile
          className="border-t-2 border-t-violet-400 from-violet-500/10"
          label="Temps de rétablissement"
          value={formatDuration(overview.counters.mttr_p50_seconds)}
          valueClass={(overview.counters.mttr_p50_seconds ?? 0) > settings.slaSeconds ? "text-amber-400" : "text-emerald-400"}
          hint={`objectif < ${settings.slaSeconds} s`}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <IncidentPanel detail={state.detail} pinned={state.pinned} onUnpin={() => state.select(null)} onChanged={state.reload} />
        </div>
        <ServicesPanel
          services={overview.services}
          history={state.health}
          activeIncident={overview.active_incident}
          onSelectIncident={(id) => state.select(id)}
        />
      </div>

      {/* Replié en régime nominal pour ne pas noyer l'opérateur ; s'ouvre seul pendant un incident. */}
      <details open={Boolean(overview.active_incident) || undefined}>
        <summary className="cursor-pointer select-none text-sm font-medium text-ink-2 hover:text-ink">Détails techniques</summary>
        <div className="mt-5 space-y-5">
          <PhaseTimeline
            timeline={state.timeline}
            range={state.range}
            onRange={state.setRange}
            onFocusIncident={state.detail || overview.active_incident ? state.focusIncident : undefined}
          />
          <div className="grid gap-5 lg:grid-cols-2">
            <RemediationLog detail={state.detail} />
            <VerificationChecklist detail={state.detail} />
          </div>
          <div className="grid gap-5 lg:grid-cols-2">
            <IncidentHistory incidents={state.incidents} selectedId={state.selectedId} onSelect={(id) => state.select(id)} />
            <EventFeed events={state.feed} status={state.streamStatus} />
          </div>
        </div>
      </details>

      {hasRole("chaos.operator") && <ChaosLabPanel />}
    </div>
  );
}
