import type { Transaction } from "../../api/types";
import { Button, Card, EmptyState, Spinner, StatusPill } from "../../components/ui";
import type { StreamStatus } from "../../hooks/useEventStream";
import { formatMoney, formatTime } from "../../lib/format";
import { TRANSACTION_STATUS } from "../../lib/status";

export function StreamIndicator({ status }: { status: StreamStatus }) {
  const labels: Record<StreamStatus, { text: string; dot: string }> = {
    open: { text: "Temps réel actif", dot: "bg-good" },
    connecting: { text: "Connexion au flux…", dot: "bg-neutral" },
    reconnecting: { text: "Reconnexion au flux…", dot: "bg-warning" },
    idle: { text: "Flux inactif", dot: "bg-neutral" },
  };
  const label = labels[status];
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-ink-2" data-testid="stream-status" data-status={status}>
      <span className={`h-2 w-2 rounded-full ${label.dot}`} aria-hidden="true" />
      {label.text}
    </span>
  );
}

export function TransactionsTable({
  transactions,
  loading,
  streamStatus,
  hasMore,
  onLoadMore,
  onSelect,
}: {
  transactions: Transaction[];
  loading: boolean;
  streamStatus: StreamStatus;
  hasMore: boolean;
  onLoadMore: () => void;
  onSelect: (id: string) => void;
}) {
  return (
    <Card title="Transactions" subtitle="Les plus récentes d'abord" actions={<StreamIndicator status={streamStatus} />}>
      {loading ? (
        <Spinner label="Chargement…" />
      ) : transactions.length === 0 ? (
        <EmptyState>Aucune transaction pour le moment.</EmptyState>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-xs">
            <thead className="text-muted">
              <tr className="border-b border-line">
                <th className="py-2 pr-3 font-medium">Heure</th>
                <th className="py-2 pr-3 font-medium">Débit</th>
                <th className="py-2 pr-3 font-medium">Crédit</th>
                <th className="py-2 pr-3 text-right font-medium">Montant</th>
                <th className="py-2 pr-3 font-medium">Statut</th>
                <th className="py-2 font-medium">Motif</th>
              </tr>
            </thead>
            <tbody className="tabular">
              {transactions.map((tx) => (
                <tr
                  key={tx.id}
                  className="cursor-pointer border-b border-line/60 hover:bg-surface-2/60"
                  onClick={() => onSelect(tx.id)}
                  data-testid="transaction-row"
                  data-status={tx.status}
                >
                  <td className="py-1.5 pr-3 text-ink-2">{formatTime(tx.created_at)}</td>
                  <td className="py-1.5 pr-3 font-mono">{tx.debit_account.account_number}</td>
                  <td className="py-1.5 pr-3 font-mono">{tx.credit_account.account_number}</td>
                  <td className="py-1.5 pr-3 text-right">{formatMoney(tx.amount.value, tx.amount.currency)}</td>
                  <td className="py-1.5 pr-3">
                    <StatusPill visual={TRANSACTION_STATUS[tx.status]} compact />
                  </td>
                  <td className="py-1.5 text-ink-2">{tx.failure?.code ?? tx.description ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {hasMore && (
        <div className="mt-3">
          <Button onClick={onLoadMore}>Afficher plus</Button>
        </div>
      )}
    </Card>
  );
}
