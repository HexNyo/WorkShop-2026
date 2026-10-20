import { useState, type FormEvent } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { ApiError } from "../../api/http";
import { useAuth } from "../../auth/AuthProvider";
import { Button, ErrorBanner, Field, Input } from "../../components/ui";
import { homeFor } from "../../routes";

export function LoginPage() {
  const { status, login, principal } = useAuth();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  if (status === "authenticated" && principal) {
    const from = (location.state as { from?: string } | null)?.from;
    return <Navigate to={from ?? homeFor(principal.roles)} replace />;
  }

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (failure) {
      setError(failure);
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  const message =
    error instanceof ApiError && error.code === "ACCOUNT_LOCKED"
      ? new ApiError({
          status: 403,
          code: error.code,
          title: "Compte verrouillé",
          detail: `Trop de tentatives. Réessayez dans ${Math.ceil((error.retryAfter ?? 60) / 60)} min.`,
        })
      : error instanceof ApiError && error.code === "INVALID_CREDENTIALS"
        ? new ApiError({ status: 401, code: error.code, title: "Échec", detail: "Identifiant ou mot de passe incorrect." })
        : error;

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2">
          <img src="/favicon.svg" alt="" className="h-8 w-8" />
          <div>
            <h1 className="text-lg font-semibold">RESILIENCE-ALPHA</h1>
            <p className="text-xs text-muted">Plateforme de paiement fictive · reprise autonome</p>
          </div>
        </div>
        <form onSubmit={submit} className="space-y-4 rounded-lg border border-line bg-surface p-5 shadow-sm" noValidate>
          <Field label="Identifiant" htmlFor="username">
            <Input
              id="username"
              name="username"
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              required
              minLength={3}
              autoFocus
            />
          </Field>
          <Field label="Mot de passe" htmlFor="password">
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </Field>
          <ErrorBanner error={message} title="Connexion refusée" />
          <Button type="submit" variant="primary" className="w-full" busy={busy} disabled={!username || !password}>
            Se connecter
          </Button>
          <p className="text-[0.7rem] text-muted">
            Toutes les données sont fictives. La session est conservée en mémoire et renouvelée par un cookie sécurisé.
          </p>
        </form>
      </div>
    </div>
  );
}
