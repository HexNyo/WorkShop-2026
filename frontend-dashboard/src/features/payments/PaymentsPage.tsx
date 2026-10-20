import { useCallback, useEffect, useState } from "react";

import { paymentApi } from "../../api/endpoints";
import { ApiError } from "../../api/http";
import type { Account, StreamEnvelope, Transaction, TransactionEventPayload } from "../../api/types";
import { useAuth } from "../../auth/AuthProvider";
import { ErrorBanner } from "../../components/ui";
import { useDebouncedCallback } from "../../hooks/useDebounced";
import { useEventStream } from "../../hooks/useEventStream";
import { AccountsPanel } from "./AccountsPanel";
import { FlowGenerator } from "./FlowGenerator";
import { PaymentForm } from "./PaymentForm";
import { TransactionDrawer } from "./TransactionDrawer";
import { TransactionsTable } from "./TransactionsTable";

const EVENTS = ["transaction.created", "transaction.updated"] as const;

/** Applique un événement SSE à la liste (insertion ou mise à jour, sans recharger). */
export function applyTransactionEvent(list: Transaction[], event: TransactionEventPayload): Transaction[] {
  const index = list.findIndex((item) => item.id === event.id);
  if (index === -1) {
    const created: Transaction = {
      id: event.id,
      status: event.status,
      debit_account: { id: "", account_number: event.debit_account_number },
      credit_account: { id: "", account_number: event.credit_account_number },
      amount: event.amount,
      description: null,
      is_synthetic: event.is_synthetic,
      failure: event.failure,
      idempotency_key: "",
      created_at: event.updated_at,
      validated_at: null,
      executed_at: null,
    };
    return [created, ...list].slice(0, 200);
  }
  const next = [...list];
  next[index] = { ...next[index]!, status: event.status, failure: event.failure };
  return next;
}

export function PaymentsPage() {
  const { hasRole } = useAuth();
  const canInitiate = hasRole("payment.customer");
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [writeRestricted, setWriteRestricted] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadAccounts = useCallback(async () => {
    try {
      setAccounts((await paymentApi.accounts()).data.items);
    } catch (error) {
      setLoadError(error);
    }
  }, []);

  const loadTransactions = useCallback(async () => {
    try {
      const { data } = await paymentApi.transactions({ limit: 25 });
      setTransactions(data.items);
      setCursor(data.next_cursor);
      setLoadError(null);
    } catch (error) {
      setLoadError(error);
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshBalances = useDebouncedCallback(() => void loadAccounts(), 400);

  useEffect(() => {
    void loadAccounts();
    void loadTransactions();
  }, [loadAccounts, loadTransactions]);

  const stream = useEventStream({
    enabled: true,
    issueTicket: paymentApi.streamTicket,
    url: paymentApi.streamUrl,
    eventTypes: EVENTS,
    onEvent: (event: StreamEnvelope) => {
      const payload = event.payload as unknown as TransactionEventPayload;
      setTransactions((current) => applyTransactionEvent(current, payload));
      if (payload.status === "EXECUTED") refreshBalances();
    },
    onResync: () => {
      void loadTransactions();
      void loadAccounts();
    },
  });

  const loadMore = async () => {
    if (!cursor) return;
    const { data } = await paymentApi.transactions({ limit: 25, cursor });
    setTransactions((current) => [...current, ...data.items.filter((item) => !current.some((known) => known.id === item.id))]);
    setCursor(data.next_cursor);
  };

  const onWriteError = (error: unknown) => {
    if (error instanceof ApiError && error.code === "WRITE_MODE_RESTRICTED") {
      setWriteRestricted(error.detail ?? "Opérations d'écriture temporairement suspendues");
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">Portail métier</h1>
          <p className="text-xs text-muted">
            Paiements fictifs, exécutés de manière atomique et idempotente. Statuts mis à jour en temps réel.
          </p>
        </div>
      </div>

      {writeRestricted && (
        <div role="status" className="rounded-md border border-serious/50 bg-serious/15 px-3 py-2 text-xs">
          <p className="font-semibold">
            <span aria-hidden="true" className="mr-1 text-serious">
              ↻
            </span>
            Plateforme en quarantaine
          </p>
          <p className="text-ink-2">
            {writeRestricted}. La remédiation automatique vérifie le service avant de rouvrir le trafic réel.
          </p>
          <button type="button" className="mt-1 text-accent underline" onClick={() => setWriteRestricted(null)}>
            Masquer
          </button>
        </div>
      )}
      <ErrorBanner error={loadError} title="Chargement impossible" />

      <AccountsPanel accounts={accounts} />

      {canInitiate && (
        <div className="grid gap-5 lg:grid-cols-2">
          <PaymentForm accounts={accounts.filter((account) => account.status === "ACTIVE")} onError={onWriteError} />
          <FlowGenerator accounts={accounts.filter((account) => account.status === "ACTIVE")} onError={onWriteError} />
        </div>
      )}

      <TransactionsTable
        transactions={transactions}
        loading={loading}
        streamStatus={stream}
        hasMore={Boolean(cursor)}
        onLoadMore={() => void loadMore()}
        onSelect={setSelected}
      />

      {selected && (
        <TransactionDrawer
          id={selected}
          canAct={canInitiate}
          onClose={() => setSelected(null)}
          onChanged={() => void loadAccounts()}
          onError={onWriteError}
        />
      )}
    </div>
  );
}
