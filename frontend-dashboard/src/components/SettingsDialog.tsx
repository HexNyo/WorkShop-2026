import { useEffect, useState } from "react";

import { MIN_PASSWORD_LENGTH, adminApi, authApi } from "../api/endpoints";
import { useAuth } from "../auth/AuthProvider";
import { updateSettings, useSettings } from "../lib/settings";
import { Button, Code, Drawer, ErrorBanner, Field, Input, Select, Spinner } from "./ui";

const ENGINE_LABELS: Record<string, string> = {
  health_poll_seconds: "Intervalle des sondes (s)",
  watchdog_enabled: "Watchdog actif",
  watchdog_down_polls: "Seuil d'échecs consécutifs (watchdog)",
  scheduled_stm_seconds: "Transaction synthétique planifiée (s)",
  max_per_target_per_hour: "Remédiations max par cible et par heure",
  min_confidence: "Confiance minimale d'une alerte",
  restored_hold_seconds: "Maintien de la phase « Rétabli » (s)",
};

function Toggle({ id, label, checked, onChange, disabled }: { id: string; label: string; checked: boolean; onChange?: (value: boolean) => void; disabled?: boolean }) {
  return (
    <label htmlFor={id} className="flex items-center justify-between gap-3 py-1 text-sm">
      <span className={disabled ? "text-muted" : "text-ink"}>{label}</span>
      <input id={id} type="checkbox" className="h-4 w-4 accent-[rgb(var(--accent))]" checked={checked} disabled={disabled} onChange={(event) => onChange?.(event.target.checked)} />
    </label>
  );
}

function PasswordSection() {
  const { logout } = useAuth();
  const [form, setForm] = useState({ current: "", next: "", confirm: "" });
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const mismatch = form.confirm !== "" && form.confirm !== form.next;

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await authApi.changePassword(form.current, form.next);
      await logout(); // le serveur a fermé toutes les sessions, celle-ci comprise
    } catch (failure) {
      setError(failure);
      setBusy(false);
    }
  };

  return (
    <section className="space-y-2">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Mot de passe</h3>
      <form
        className="space-y-2"
        onSubmit={(event) => {
          event.preventDefault();
          if (!mismatch) void submit();
        }}
      >
        <Field label="Mot de passe actuel" htmlFor="pwd-current">
          <Input id="pwd-current" type="password" required autoComplete="current-password" value={form.current} onChange={(event) => setForm({ ...form, current: event.target.value })} />
        </Field>
        <Field label="Nouveau mot de passe" htmlFor="pwd-next" hint={`${MIN_PASSWORD_LENGTH} caractères minimum`}>
          <Input id="pwd-next" type="password" required minLength={MIN_PASSWORD_LENGTH} maxLength={256} autoComplete="new-password" value={form.next} onChange={(event) => setForm({ ...form, next: event.target.value })} />
        </Field>
        <Field label="Confirmation" htmlFor="pwd-confirm" hint={mismatch ? "Les deux mots de passe diffèrent" : "Vous serez déconnecté de toutes vos sessions"}>
          <Input id="pwd-confirm" type="password" required aria-invalid={mismatch} autoComplete="new-password" value={form.confirm} onChange={(event) => setForm({ ...form, confirm: event.target.value })} />
        </Field>
        <ErrorBanner error={error} title="Changement refusé" />
        <Button type="submit" busy={busy} disabled={mismatch}>
          Changer le mot de passe
        </Button>
      </form>
    </section>
  );
}

/** Préférences locales (navigateur) + réglages du moteur en lecture seule (source : configuration serveur). */
export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const settings = useSettings();
  const { hasRole } = useAuth();
  const [engine, setEngine] = useState<Record<string, number | boolean> | null>(null);
  const [error, setError] = useState<unknown>(null);
  const canReadEngine = hasRole("remediation.admin");

  useEffect(() => {
    if (!canReadEngine) return;
    adminApi.engineSettings().then(({ data }) => setEngine(data), setError);
  }, [canReadEngine]);

  const askNotifications = async (value: boolean) => {
    if (value && "Notification" in window && Notification.permission !== "granted") {
      if ((await Notification.requestPermission()) !== "granted") return;
    }
    updateSettings({ browserNotifications: value });
  };

  return (
    <Drawer title="Paramètres" onClose={onClose}>
      <div className="space-y-6">
        <section className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Affichage (ce navigateur)</h3>
          <Field label="Densité" htmlFor="density">
            <Select id="density" value={settings.density} onChange={(event) => updateSettings({ density: event.target.value as "comfortable" | "compact" })}>
              <option value="comfortable">Confortable</option>
              <option value="compact">Compacte</option>
            </Select>
          </Field>
          <Field label="Objectif SLA de rétablissement (s)" htmlFor="sla" hint="Seuil d'affichage du temps médian (vert / ambre).">
            <Input id="sla" type="number" min={1} max={3600} value={settings.slaSeconds} onChange={(event) => updateSettings({ slaSeconds: Number(event.target.value) })} />
          </Field>
          <Toggle id="auto-refresh" label="Rafraîchissement périodique (frise, santé)" checked={settings.autoRefresh} onChange={(value) => updateSettings({ autoRefresh: value })} />
          <Toggle id="audio" label="Alerte sonore en phase critique" checked={settings.audioAlert} onChange={(value) => updateSettings({ audioAlert: value })} />
          <Toggle id="notify" label="Notification navigateur en phase critique" checked={settings.browserNotifications} onChange={(value) => void askNotifications(value)} />
        </section>

        <PasswordSection />

        <section className="space-y-1">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Intégrations sortantes</h3>
          <Toggle id="webhook" label="Webhook générique" checked={false} disabled />
          <Toggle id="slack" label="Slack" checked={false} disabled />
          <Toggle id="pagerduty" label="PagerDuty" checked={false} disabled />
          <p className="text-[0.7rem] text-muted">Non configuré côté serveur : aucun secret d'intégration n'est injecté dans le moteur.</p>
        </section>

        <section className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Moteur de remédiation (lecture seule)</h3>
          {!canReadEngine ? (
            <p className="text-xs text-muted">Réservé au rôle remediation.admin.</p>
          ) : error ? (
            <ErrorBanner error={error} title="Réglages indisponibles" />
          ) : !engine ? (
            <Spinner label="Chargement…" />
          ) : (
            <dl className="space-y-1.5 text-xs">
              {Object.entries(engine).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between gap-3">
                  <dt className="text-ink-2">{ENGINE_LABELS[key] ?? key}</dt>
                  <dd>
                    <Code>{String(value)}</Code>
                  </dd>
                </div>
              ))}
              <p className="pt-1 text-[0.7rem] text-muted">
                Modifiables par variables d'environnement <Code>REMEDIATION_*</Code> puis redémarrage (aucune configuration sensible exposée à l'interface).
              </p>
            </dl>
          )}
        </section>
      </div>
    </Drawer>
  );
}
