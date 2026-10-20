import { useEffect, useRef, useState } from "react";

import { paymentApi } from "../../api/endpoints";
import type { Account, TransactionStatus } from "../../api/types";
import { Button, Card, ErrorBanner, Field, Input, Select } from "../../components/ui";
import { TRANSACTION_STATUS } from "../../lib/status";

const ACCOUNT_PATTERN = /^RA-[0-9]{4}-[0-9]{4}$/;

type Tally = Partial<Record<TransactionStatus | "ERROR", number>>;

/** Flux continu de petits paiements : rend visible l'impact d'un incident en temps réel. */
export function FlowGenerator({ accounts, onError }: { accounts: Account[]; onError: (error: unknown) => void }) {
  const [debit, setDebit] = useState("");
  const [credit, setCredit] = useState("RA-2000-0001");
  const [count, setCount] = useState(20);
  const [intervalMs, setIntervalMs] = useState(500);
  const [running, setRunning] = useState(false);
  const [sent, setSent] = useState(0);
  const [tally, setTally] = useState<Tally>({});
  const [lastError, setLastError] = useState<unknown>(null);
  const stop = useRef(false);

  useEffect(() => {
    if (!debit && accounts[0]) setDebit(accounts[0].id);
  }, [accounts, debit]);
  useEffect(() => () => {
    stop.current = true;
  }, []);

  const account = accounts.find((item) => item.id === debit);
  const valid = Boolean(account) && ACCOUNT_PATTERN.test(credit) && count >= 1 && count <= 500;

  const run = async () => {
    if (!account) return;
    stop.current = false;
    setRunning(true);
    setSent(0);
    setTally({});
    setLastError(null);
    for (let index = 0; index < count && !stop.current; index += 1) {
      const cents = 50 + Math.floor(Math.random() * 450);
      try {
        const { data } = await paymentApi.create({
          debit_account_id: account.id,
          credit_account_number: credit,
          amount: { value: (cents / 100).toFixed(2), currency: account.currency },
          description: `flux démo #${index + 1}`,
          auto_execute: true,
        });
        setTally((current) => ({ ...current, [data.status]: (current[data.status] ?? 0) + 1 }));
      } catch (error) {
        setLastError(error);
        onError(error);
        setTally((current) => ({ ...current, ERROR: (current.ERROR ?? 0) + 1 }));
      }
      setSent(index + 1);
      if (index + 1 < count) await new Promise((resolve) => window.setTimeout(resolve, intervalMs));
    }
    setRunning(false);
  };

  return (
    <Card title="Générateur de flux" subtitle="Envoie une série de paiements à cadence régulière">
      <div className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Compte débité" htmlFor="flow-debit">
            <Select id="flow-debit" value={debit} onChange={(event) => setDebit(event.target.value)} disabled={running}>
              {accounts.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.account_number}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Bénéficiaire" htmlFor="flow-credit">
            <Input id="flow-credit" value={credit} onChange={(event) => setCredit(event.target.value.toUpperCase().trim())} disabled={running} />
          </Field>
          <Field label="Nombre de paiements" htmlFor="flow-count">
            <Input
              id="flow-count"
              type="number"
              min={1}
              max={500}
              value={count}
              onChange={(event) => setCount(Number(event.target.value))}
              disabled={running}
            />
          </Field>
          <Field label="Intervalle (ms)" htmlFor="flow-interval">
            <Input
              id="flow-interval"
              type="number"
              min={100}
              max={10000}
              step={100}
              value={intervalMs}
              onChange={(event) => setIntervalMs(Math.max(100, Number(event.target.value)))}
              disabled={running}
            />
          </Field>
        </div>

        <div className="h-1.5 overflow-hidden rounded-full bg-surface-2" aria-hidden="true">
          <div className="h-full bg-accent transition-all" style={{ width: `${count ? (sent / count) * 100 : 0}%` }} />
        </div>
        <p className="text-xs text-ink-2" aria-live="polite">
          {sent}/{count} envoyés
          {Object.entries(tally).map(([status, value]) => (
            <span key={status} className="ml-3">
              {status === "ERROR" ? "Erreurs" : TRANSACTION_STATUS[status as TransactionStatus].label} : <strong>{value}</strong>
            </span>
          ))}
        </p>
        <ErrorBanner error={lastError} title="Dernière erreur du flux" />
        <div className="flex gap-2">
          <Button variant="primary" onClick={() => void run()} disabled={!valid || running} busy={running}>
            Démarrer le flux
          </Button>
          <Button onClick={() => (stop.current = true)} disabled={!running}>
            Arrêter
          </Button>
        </div>
      </div>
    </Card>
  );
}
