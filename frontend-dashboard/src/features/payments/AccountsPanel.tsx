import type { Account } from "../../api/types";
import { Badge, Card, EmptyState } from "../../components/ui";
import { formatMoney, formatTime } from "../../lib/format";

export function AccountsPanel({ accounts }: { accounts: Account[] }) {
  return (
    <Card title="Comptes" subtitle="Soldes disponibles (projection du grand livre en partie double)">
      {accounts.length === 0 ? (
        <EmptyState>Aucun compte visible pour ce profil.</EmptyState>
      ) : (
        <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {accounts.map((account) => (
            <li key={account.id} className="rounded-md border border-line bg-surface-2/40 px-3 py-2.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-ink-2">{account.account_number}</span>
                {account.status !== "ACTIVE" ? (
                  <Badge tone="critical">{account.status === "FROZEN" ? "Gelé" : "Clôturé"}</Badge>
                ) : (
                  <Badge tone="good">Actif</Badge>
                )}
              </div>
              <p className="mt-1 truncate text-sm" title={account.holder_name}>
                {account.holder_name}
              </p>
              <p className="tabular mt-1 text-xl font-semibold" data-testid={`balance-${account.account_number}`}>
                {formatMoney(account.balance.value, account.currency)}
              </p>
              <p className="text-[0.7rem] text-muted">mis à jour {formatTime(account.updated_at)}</p>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
