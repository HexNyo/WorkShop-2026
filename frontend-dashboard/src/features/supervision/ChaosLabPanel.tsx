import { useCallback, useEffect, useState } from "react";

import { labApi, type FaultRequest } from "../../api/endpoints";
import { ApiError } from "../../api/http";
import { Button, Card, ErrorBanner } from "../../components/ui";

const SCENARIOS: { id: string; label: string; detail: string; fault: FaultRequest; variant: "danger" | "secondary" }[] = [
  {
    id: "tamper",
    label: "Altérer un solde",
    detail: "+500,00 € sur RA-1000-0003 sans écriture au grand livre (attaque sur les données)",
    fault: { type: "BALANCE_TAMPER", params: { account_number: "RA-1000-0003", delta: "500.00" } },
    variant: "danger",
  },
  {
    id: "readiness",
    label: "Rendre l'API non prête",
    detail: "payment-api répond 503 sur sa sonde de disponibilité",
    fault: { type: "READINESS_FAILURE" },
    variant: "danger",
  },
  {
    id: "crash",
    label: "Crash de payment-api",
    detail: "Arrêt brutal du processus",
    fault: { type: "CRASH" },
    variant: "danger",
  },
  {
    id: "latency",
    label: "Latence 800 ms (60 s)",
    detail: "Dégradation des temps de réponse de l'API métier",
    fault: { type: "LATENCY", params: { ms: 800 }, duration_seconds: 60 },
    variant: "secondary",
  },
];

/**
 * Laboratoire d'injection de pannes (rôle chaos.operator, CHAOS_LAB_ENABLED=true).
 * Aucune alerte n'est envoyée par la console : la détection est laissée au moteur
 * ML/SIEM ou au watchdog intégré, ce qui démontre la boucle sans intervention.
 */
export function ChaosLabPanel() {
  const [available, setAvailable] = useState<boolean | null>(null);
  const [active, setActive] = useState<string[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const { data } = await labApi.faults();
      setActive(data.items.map((item) => item.type));
      setAvailable(true);
    } catch (failure) {
      if (failure instanceof ApiError && (failure.status === 404 || failure.status === 403)) setAvailable(false);
      else setError(failure);
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 10_000);
    return () => window.clearInterval(timer);
  }, [load]);

  if (available === false) return null;

  const inject = async (id: string, fault: FaultRequest) => {
    setBusy(id);
    setError(null);
    try {
      await labApi.inject(fault);
      setNotice(`Panne injectée (${fault.type}). Observez la détection et la remédiation automatiques ci-dessus.`);
      await load();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(null);
    }
  };

  const clear = async () => {
    setBusy("clear");
    try {
      const { data } = await labApi.clear();
      setNotice(`${data.cleared} panne(s) levée(s).`);
      await load();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card
      title="Laboratoire d'attaque"
      subtitle="Démonstration uniquement — désactivé en production"
      actions={
        <Button onClick={() => void clear()} busy={busy === "clear"} disabled={active.length === 0}>
          Lever les pannes actives ({active.length})
        </Button>
      }
    >
      <div className="grid gap-2 sm:grid-cols-2" data-testid="chaos-lab">
        {SCENARIOS.map((scenario) => (
          <div key={scenario.id} className="flex flex-col justify-between gap-2 rounded-md border border-line p-3">
            <div>
              <p className="text-xs font-semibold">{scenario.label}</p>
              <p className="text-[0.7rem] text-muted">{scenario.detail}</p>
            </div>
            <Button
              variant={scenario.variant}
              busy={busy === scenario.id}
              onClick={() => void inject(scenario.id, scenario.fault)}
              data-testid={`chaos-${scenario.id}`}
            >
              Déclencher
            </Button>
          </div>
        ))}
      </div>
      {notice && (
        <p className="mt-3 text-xs text-ink-2" role="status">
          {notice}
        </p>
      )}
      <div className="mt-2">
        <ErrorBanner error={error} title="Laboratoire indisponible" />
      </div>
    </Card>
  );
}
