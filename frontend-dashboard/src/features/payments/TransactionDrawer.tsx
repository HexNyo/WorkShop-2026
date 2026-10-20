import { useCallback, useEffect, useState } from "react";

import { paymentApi } from "../../api/endpoints";
import type { TransactionDetail } from "../../api/types";
import { Button, ErrorBanner, Spinner, StatusPill } from "../../components/ui";
import { formatDateTime, formatMoney } from "../../lib/format";
import { TRANSACTION_STATUS } from "../../lib/status";

export function TransactionDrawer({
  id,
  canAct,
  onClose,
  onChanged,
  onError,
}: {
  id: string;
  canAct: boolean;
  onClose: () => void;
  onChanged: () => void;
  onError: (error: unknown) => void;
}) {
  const [detail, setDetail] = useState<TransactionDetail | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setDetail((await paymentApi.transaction(id)).data);
      setError(null);
    } catch (failure) {
      setError(failure);
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const act = async (action: "execute" | "cancel") => {
    setBusy(true);
    try {
      await (action === "execute" ? paymentApi.execute(id) : paymentApi.cancel(id));
      await load();
      onChanged();
    } catch (failure) {
      setError(failure);
      onError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-30 flex justify-end bg-black/30" onClick={onClose}>
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Détail de la transaction"
        className="h-full w-full max-w-md overflow-y-auto border-l border-line bg-surface p-5 shadow-xl"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold">Transaction</h2>
          <Button variant="ghost" onClick={onClose} aria-label="Fermer">
            ✕
          </Button>
        </div>
        <ErrorBanner error={error} />
        {!detail ? (
          !error && <Spinner label="Chargement…" />
        ) : (
          <div className="mt-3 space-y-4 text-xs">
            <div className="flex items-center gap-2">
              <StatusPill visual={TRANSACTION_STATUS[detail.status]} />
              <span className="tabular text-lg font-semibold">{formatMoney(detail.amount.value, detail.amount.currency)}</span>
            </div>
            <dl className="grid grid-cols-[auto,1fr] gap-x-3 gap-y-1.5">
              <dt className="text-muted">Identifiant</dt>
              <dd className="break-all font-mono">{detail.id}</dd>
              <dt className="text-muted">Débit</dt>
              <dd className="font-mono">{detail.debit_account.account_number}</dd>
              <dt className="text-muted">Crédit</dt>
              <dd className="font-mono">{detail.credit_account.account_number}</dd>
              <dt className="text-muted">Libellé</dt>
              <dd>{detail.description ?? "—"}</dd>
              <dt className="text-muted">Clé d'idempotence</dt>
              <dd className="break-all font-mono">{detail.idempotency_key}</dd>
              {detail.failure && (
                <>
                  <dt className="text-muted">Motif</dt>
                  <dd>
                    <span className="font-mono">{detail.failure.code}</span> — {detail.failure.reason}
                  </dd>
                </>
              )}
            </dl>
            <div>
              <h3 className="mb-1.5 font-semibold">Historique</h3>
              <ol className="space-y-1">
                {detail.history.map((step, index) => (
                  <li key={`${step.status}-${index}`} className="flex items-center gap-2">
                    <StatusPill visual={TRANSACTION_STATUS[step.status]} compact />
                    <span className="tabular text-ink-2">{formatDateTime(step.at)}</span>
                  </li>
                ))}
              </ol>
            </div>
            {canAct && (detail.status === "VALIDATED" || detail.status === "PENDING") && (
              <div className="flex gap-2">
                {detail.status === "VALIDATED" && (
                  <Button variant="primary" busy={busy} onClick={() => void act("execute")}>
                    Exécuter
                  </Button>
                )}
                <Button variant="danger" busy={busy} onClick={() => void act("cancel")}>
                  Annuler
                </Button>
              </div>
            )}
          </div>
        )}
      </aside>
    </div>
  );
}
