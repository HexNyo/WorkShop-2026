import { useEffect, useMemo, useState, type FormEvent } from "react";

import { paymentApi } from "../../api/endpoints";
import { newIdempotencyKey } from "../../api/http";
import type { Account, Transaction } from "../../api/types";
import { Button, Card, ErrorBanner, Field, Input, Select, StatusPill } from "../../components/ui";
import { formatMoney, isValidAmount } from "../../lib/format";
import { TRANSACTION_STATUS } from "../../lib/status";

const ACCOUNT_PATTERN = /^RA-[0-9]{4}-[0-9]{4}$/;

export function PaymentForm({ accounts, onError }: { accounts: Account[]; onError: (error: unknown) => void }) {
  const [debit, setDebit] = useState("");
  const [credit, setCredit] = useState("");
  const [amount, setAmount] = useState("");
  const [description, setDescription] = useState("");
  const [autoExecute, setAutoExecute] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<{ tx: Transaction; replayed: boolean } | null>(null);
  // Une clé d'idempotence par intention de paiement : un nouvel essai après coupure
  // réseau réutilise la même clé (aucun double débit possible).
  const [idempotencyKey, setIdempotencyKey] = useState(() => newIdempotencyKey("pay"));

  useEffect(() => {
    if (!debit && accounts[0]) setDebit(accounts[0].id);
  }, [accounts, debit]);

  const debitAccount = useMemo(() => accounts.find((account) => account.id === debit), [accounts, debit]);
  const currency = debitAccount?.currency ?? "EUR";
  const valid = Boolean(debitAccount) && ACCOUNT_PATTERN.test(credit) && isValidAmount(amount) && credit !== debitAccount?.account_number;

  const resetIntent = () => setIdempotencyKey(newIdempotencyKey("pay"));

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!debitAccount) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const response = await paymentApi.create(
        {
          debit_account_id: debitAccount.id,
          credit_account_number: credit,
          amount: { value: amount, currency },
          description: description || undefined,
          auto_execute: autoExecute,
        },
        idempotencyKey,
      );
      setResult({ tx: response.data, replayed: response.headers.get("idempotent-replayed") === "true" });
      resetIntent();
      setAmount("");
      setDescription("");
    } catch (failure) {
      setError(failure);
      onError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Nouveau paiement" subtitle="Virement fictif entre comptes RA-NNNN-NNNN">
      <form onSubmit={submit} className="space-y-3" noValidate>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Compte débité" htmlFor="debit">
            <Select id="debit" value={debit} onChange={(event) => { setDebit(event.target.value); resetIntent(); }}>
              {accounts.map((account) => (
                <option key={account.id} value={account.id}>
                  {account.account_number} · {formatMoney(account.balance.value, account.currency)}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Compte bénéficiaire" htmlFor="credit" hint="Ex. RA-1000-0003 (Bob) ou RA-2000-0001 (marchand)">
            <Input
              id="credit"
              value={credit}
              onChange={(event) => { setCredit(event.target.value.toUpperCase().trim()); resetIntent(); }}
              placeholder="RA-1000-0003"
              aria-invalid={credit !== "" && !ACCOUNT_PATTERN.test(credit)}
            />
          </Field>
          <Field label={`Montant (${currency})`} htmlFor="amount">
            <Input
              id="amount"
              inputMode="decimal"
              value={amount}
              onChange={(event) => { setAmount(event.target.value.replace(",", ".")); resetIntent(); }}
              placeholder="125.50"
              aria-invalid={amount !== "" && !isValidAmount(amount)}
            />
          </Field>
          <Field label="Libellé (facultatif)" htmlFor="description">
            <Input id="description" maxLength={140} value={description} onChange={(event) => setDescription(event.target.value)} />
          </Field>
        </div>
        <label className="flex items-center gap-2 text-xs text-ink-2">
          <input type="checkbox" checked={autoExecute} onChange={(event) => setAutoExecute(event.target.checked)} />
          Exécuter immédiatement (sinon la transaction reste « validée » en attente d'exécution)
        </label>
        <ErrorBanner error={error} title="Paiement refusé" />
        {result && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border border-line bg-surface-2/50 px-3 py-2 text-xs" role="status">
            <StatusPill visual={TRANSACTION_STATUS[result.tx.status]} />
            <span className="tabular">{formatMoney(result.tx.amount.value, result.tx.amount.currency)}</span>
            <span className="text-muted">vers {result.tx.credit_account.account_number}</span>
            {result.tx.failure && <span className="text-ink-2">— {result.tx.failure.code}</span>}
            {result.replayed && <span className="text-muted">(rejeu idempotent)</span>}
          </div>
        )}
        <Button type="submit" variant="primary" busy={busy} disabled={!valid}>
          Envoyer le paiement
        </Button>
      </form>
    </Card>
  );
}
