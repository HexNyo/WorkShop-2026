/** Console d'administration : RBAC, sessions, chaos, playbooks et audit (chaque onglet porte son rôle). */
import { useCallback, useEffect, useState } from "react";

import { HUMAN_ROLES, adminApi, type AdminPrincipal, type PlaybookInfo } from "../../api/endpoints";
import { useAuth } from "../../auth/AuthProvider";
import { Badge, Button, Card, Code, EmptyState, ErrorBanner, Field, Select, Spinner, cx } from "../../components/ui";
import { formatDateTime } from "../../lib/format";
import { ChaosLabPanel } from "../supervision/ChaosLabPanel";

type Loaded<T> = { data: T | null; error: unknown; reload: () => void };

function useLoad<T>(load: () => Promise<{ data: T }>, enabled: boolean): Loaded<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const reload = useCallback(() => {
    if (!enabled) return;
    load().then(
      ({ data: value }) => {
        setData(value);
        setError(null);
      },
      setError,
    );
  }, [load, enabled]);
  useEffect(reload, [reload]);
  return { data, error, reload };
}

function UsersTab() {
  const { principal: me } = useAuth();
  const principals = useLoad(adminApi.principals, true);
  const sessions = useLoad(adminApi.sessions, true);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const act = async (key: string, call: () => Promise<unknown>) => {
    setBusy(key);
    setError(null);
    try {
      await call();
      principals.reload();
      sessions.reload();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(null);
    }
  };
  const humans = (principals.data?.items ?? []).filter((item: AdminPrincipal) => item.kind === "USER");

  return (
    <div className="space-y-5">
      <ErrorBanner error={error ?? principals.error} title="Action refusée" />
      <Card title="Utilisateurs et rôles" subtitle="Retirer un rôle révoque immédiatement les jetons de l'utilisateur">
        {!principals.data ? (
          <Spinner label="Chargement…" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-muted">
                <tr className="border-b border-white/[0.06]">
                  <th className="py-1.5 pr-3 font-medium">Utilisateur</th>
                  {HUMAN_ROLES.map((role) => (
                    <th key={role} className="px-1 py-1.5 text-center font-mono text-[0.65rem] font-medium">
                      {role}
                    </th>
                  ))}
                  <th className="py-1.5 pl-3 font-medium">Compte</th>
                </tr>
              </thead>
              <tbody>
                {humans.map((user) => (
                  <tr key={user.id} className="border-b border-white/[0.04]" data-testid={`admin-user-${user.username}`}>
                    <td className="py-1.5 pr-3">
                      <p className="font-medium">{user.display_name}</p>
                      <p className="font-mono text-[0.7rem] text-muted">{user.username}</p>
                    </td>
                    {HUMAN_ROLES.map((role) => {
                      const has = user.roles.includes(role);
                      return (
                        <td key={role} className="px-1 py-1.5 text-center">
                          <input
                            type="checkbox"
                            aria-label={`${role} pour ${user.username}`}
                            className="h-4 w-4 accent-[rgb(var(--accent))]"
                            checked={has}
                            disabled={busy !== null || (user.id === me?.id && role === "auth.admin")}
                            onChange={() => void act(`${user.id}:${role}`, () => adminApi.setRole(user.id, role, !has))}
                          />
                        </td>
                      );
                    })}
                    <td className="space-x-1 whitespace-nowrap py-1.5 pl-3">
                      <Badge tone={user.is_active ? "good" : "critical"}>{user.is_active ? "actif" : "désactivé"}</Badge>
                      {user.id !== me?.id && (
                        <>
                          <Button
                            variant="ghost"
                            busy={busy === `${user.id}:state`}
                            onClick={() => void act(`${user.id}:state`, () => adminApi.principalAction(user.id, user.is_active ? "disable" : "enable"))}
                          >
                            {user.is_active ? "Désactiver" : "Réactiver"}
                          </Button>
                          <Button variant="ghost" busy={busy === `${user.id}:revoke`} onClick={() => void act(`${user.id}:revoke`, () => adminApi.principalAction(user.id, "revoke-tokens"))}>
                            Révoquer les jetons
                          </Button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card title="Sessions actives" subtitle="Une ligne par famille de refresh token valide">
        <ErrorBanner error={sessions.error} title="Sessions indisponibles" />
        {sessions.data?.items.length === 0 ? (
          <EmptyState>Aucune session active.</EmptyState>
        ) : (
          <ul className="space-y-1.5 text-xs">
            {(sessions.data?.items ?? []).map((session) => (
              <li key={session.family_id} className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{session.username}</span>
                <Code>{session.client_ip ?? "ip inconnue"}</Code>
                <span className="text-muted">dernier renouvellement {formatDateTime(session.last_refresh)} · expire {formatDateTime(session.expires_at)}</span>
                {session.user_agent && <Code>{session.user_agent.slice(0, 60)}</Code>}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

const SERVICES = ["auth-service", "payment-api", "database", "remediation-engine", "frontend-dashboard"];
const CATEGORIES = [
  "SERVICE_UNAVAILABLE",
  "PERFORMANCE_DEGRADATION",
  "RESOURCE_EXHAUSTION",
  "DATA_INTEGRITY_VIOLATION",
  "CREDENTIAL_COMPROMISE",
  "ANOMALOUS_TRAFFIC",
  "FRAUD_PATTERN",
];

function ChaosTab() {
  const [form, setForm] = useState({ service: SERVICES[1]!, category: CATEGORIES[0]!, severity: "CRITICAL" });
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const { data } = await adminApi.simulateAlert(form);
      setResult(`${data.deduplicated ? "rattachée à l'incident" : "incident créé"} ${data.incident_id}`);
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="space-y-5">
      <Card title="Simulateur d'alerte" subtitle="Injecte une alerte opérateur dans le moteur (laboratoire de chaos activé uniquement)">
        <div className="grid gap-3 sm:grid-cols-4">
          <Field label="Service" htmlFor="sim-service">
            <Select id="sim-service" value={form.service} onChange={(event) => setForm({ ...form, service: event.target.value })}>
              {SERVICES.map((service) => (
                <option key={service}>{service}</option>
              ))}
            </Select>
          </Field>
          <Field label="Catégorie" htmlFor="sim-category">
            <Select id="sim-category" value={form.category} onChange={(event) => setForm({ ...form, category: event.target.value })}>
              {CATEGORIES.map((category) => (
                <option key={category}>{category}</option>
              ))}
            </Select>
          </Field>
          <Field label="Sévérité" htmlFor="sim-severity">
            <Select id="sim-severity" value={form.severity} onChange={(event) => setForm({ ...form, severity: event.target.value })}>
              {["INFO", "WARNING", "HIGH", "CRITICAL"].map((severity) => (
                <option key={severity}>{severity}</option>
              ))}
            </Select>
          </Field>
          <div className="flex items-end">
            <Button variant="danger" busy={busy} onClick={() => void submit()}>
              Déclencher l'alerte
            </Button>
          </div>
        </div>
        <div className="mt-3 space-y-2">
          <ErrorBanner error={error} title="Simulation refusée" />
          {result && <Code>{result}</Code>}
        </div>
      </Card>
      <ChaosLabPanel />
    </div>
  );
}

function PlaybooksTab() {
  const playbooks = useLoad(adminApi.playbooks, true);
  const [error, setError] = useState<unknown>(null);
  const toggle = async (playbook: PlaybookInfo) => {
    try {
      await adminApi.togglePlaybook(playbook.code, !playbook.enabled);
      playbooks.reload();
    } catch (failure) {
      setError(failure);
    }
  };
  return (
    <Card title="Playbooks" subtitle="Activation à chaud ; étapes et tentatives max sont versionnées en base (migration)">
      <ErrorBanner error={error ?? playbooks.error} title="Action refusée" />
      {!playbooks.data ? (
        <Spinner label="Chargement…" />
      ) : (
        <ul className="divide-y divide-white/[0.04] text-xs">
          {playbooks.data.map((playbook) => (
            <li key={playbook.code} className="flex flex-wrap items-center justify-between gap-2 py-2">
              <div>
                <p className="font-medium">{playbook.title}</p>
                <p className="mt-0.5 flex flex-wrap gap-1.5">
                  <Code>{playbook.code}</Code>
                  <Code>{playbook.category}</Code>
                  <span className="text-muted">
                    {playbook.steps.length} étape(s) · {playbook.max_attempts} tentative(s) max · délai {playbook.cooldown_seconds} s
                  </span>
                </p>
              </div>
              <label className="flex items-center gap-2">
                <span className={playbook.enabled ? "text-emerald-400" : "text-muted"}>{playbook.enabled ? "activé" : "désactivé"}</span>
                <input type="checkbox" aria-label={`Activer ${playbook.code}`} className="h-4 w-4 accent-[rgb(var(--accent))]" checked={playbook.enabled} onChange={() => void toggle(playbook)} />
              </label>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function AuditTab({ engine, auth }: { engine: boolean; auth: boolean }) {
  const engineAudit = useLoad(adminApi.engineAudit, engine);
  const authAudit = useLoad(adminApi.authAudit, auth);
  return (
    <div className="grid gap-5 xl:grid-cols-2">
      {engine && (
        <Card title="Remédiation : automatique vs humain" subtitle="Transitions, étapes de playbook et acquittements">
          <ErrorBanner error={engineAudit.error} title="Audit indisponible" />
          <ol className="max-h-[32rem] space-y-1 overflow-y-auto text-xs">
            {(engineAudit.data?.items ?? []).map((item, index) => (
              <li key={`${item.at}-${index}`} className="flex flex-wrap items-center gap-2">
                <span className="tabular text-muted">{formatDateTime(item.at)}</span>
                <Badge tone={item.actor === "human" ? "warning" : "accent"}>{item.actor === "human" ? "humain" : "automatique"}</Badge>
                <Code>{item.action}</Code>
                <span className="text-ink-2">{item.target_service}</span>
                <span className="w-full pl-1">
                  <Code>{item.detail}</Code>
                </span>
              </li>
            ))}
          </ol>
        </Card>
      )}
      {auth && (
        <Card title="Authentification" subtitle="Connexions, rôles, révocations">
          <ErrorBanner error={authAudit.error} title="Audit indisponible" />
          <ol className="max-h-[32rem] space-y-1 overflow-y-auto text-xs">
            {(authAudit.data?.items ?? []).map((item, index) => (
              <li key={`${item.occurred_at}-${index}`} className="flex flex-wrap items-center gap-2">
                <span className="tabular text-muted">{formatDateTime(item.occurred_at)}</span>
                <Code>{item.event_type}</Code>
                <Badge tone={item.outcome === "SUCCESS" ? "good" : "critical"}>{item.outcome}</Badge>
                <span className="text-ink-2">{item.username ?? "—"}</span>
                {item.actor && <span className="text-muted">par {item.actor}</span>}
              </li>
            ))}
          </ol>
        </Card>
      )}
    </div>
  );
}

export function AdminPage() {
  const { hasRole } = useAuth();
  const tabs = [
    { id: "users", label: "Utilisateurs & RBAC", allowed: hasRole("auth.admin") },
    { id: "chaos", label: "Simulateur de chaos", allowed: hasRole("chaos.operator") },
    { id: "playbooks", label: "Playbooks", allowed: hasRole("remediation.admin") },
    { id: "audit", label: "Audit", allowed: hasRole("auth.admin", "remediation.admin") },
  ].filter((tab) => tab.allowed);
  const [tab, setTab] = useState(tabs[0]?.id ?? "audit");

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold">Administration</h1>
        <p className="text-xs text-muted">Chaque action est journalisée et soumise au contrôle de rôle côté serveur.</p>
      </div>
      <div role="tablist" aria-label="Sections d'administration" className="flex flex-wrap gap-1 border-b border-white/[0.08]">
        {tabs.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={tab === item.id}
            onClick={() => setTab(item.id)}
            className={cx(
              "-mb-px border-b-2 px-3 py-2 text-sm",
              tab === item.id ? "border-accent font-semibold text-ink" : "border-transparent text-ink-2 hover:text-ink",
            )}
          >
            {item.label}
          </button>
        ))}
      </div>
      {tab === "users" && <UsersTab />}
      {tab === "chaos" && <ChaosTab />}
      {tab === "playbooks" && <PlaybooksTab />}
      {tab === "audit" && <AuditTab engine={hasRole("remediation.admin")} auth={hasRole("auth.admin")} />}
    </div>
  );
}
