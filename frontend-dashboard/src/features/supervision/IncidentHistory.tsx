import type { IncidentSummary } from "../../api/types";
import { Card, EmptyState, StatusPill, cx } from "../../components/ui";
import { formatDateTime, formatDuration } from "../../lib/format";
import { INCIDENT_STATUS } from "../../lib/status";

export function IncidentHistory({
  incidents,
  selectedId,
  onSelect,
}: {
  incidents: IncidentSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <Card title="Historique des incidents" subtitle="20 plus récents — cliquer pour afficher le détail">
      {incidents.length === 0 ? (
        <EmptyState>Aucun incident.</EmptyState>
      ) : (
        <div className="overflow-x-auto">
          <table className="tabular w-full min-w-[620px] text-left text-xs">
            <thead className="text-muted">
              <tr className="border-b border-line">
                <th className="py-1.5 pr-3 font-medium">Ouvert</th>
                <th className="py-1.5 pr-3 font-medium">Catégorie</th>
                <th className="py-1.5 pr-3 font-medium">Cible</th>
                <th className="py-1.5 pr-3 font-medium">Statut</th>
                <th className="py-1.5 pr-3 font-medium">Résolution</th>
                <th className="py-1.5 font-medium">Rétablissement</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => (
                <tr
                  key={incident.id}
                  onClick={() => onSelect(incident.id)}
                  className={cx(
                    "cursor-pointer border-b border-line/60 hover:bg-surface-2/60",
                    incident.id === selectedId && "bg-accent/5",
                  )}
                  aria-selected={incident.id === selectedId}
                >
                  <td className="py-1.5 pr-3">{formatDateTime(incident.opened_at)}</td>
                  <td className="py-1.5 pr-3 font-mono text-[0.7rem]">{incident.category}</td>
                  <td className="py-1.5 pr-3 font-mono text-[0.7rem]">{incident.target_service}</td>
                  <td className="py-1.5 pr-3">
                    <StatusPill visual={INCIDENT_STATUS[incident.status]} compact />
                  </td>
                  <td className="py-1.5 pr-3 text-ink-2">{incident.resolution ?? "—"}</td>
                  <td className="py-1.5">{formatDuration(incident.mttr_seconds)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
