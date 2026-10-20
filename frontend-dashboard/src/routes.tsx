import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { ROLE_GROUPS, useAuth } from "./auth/AuthProvider";
import { Spinner } from "./components/ui";

export function homeFor(roles: string[]): string {
  if (ROLE_GROUPS.supervision.some((role) => roles.includes(role))) return "/supervision";
  if (ROLE_GROUPS.payments.some((role) => roles.includes(role))) return "/payments";
  return "/forbidden";
}

/** Garde de route : session requise, puis au moins un des rôles. */
export function RequireRole({ roles, children }: { roles: readonly string[]; children: ReactNode }) {
  const { status, hasRole } = useAuth();
  const location = useLocation();
  if (status === "restoring") {
    return (
      <div className="flex justify-center py-20">
        <Spinner label="Restauration de la session…" />
      </div>
    );
  }
  if (status === "anonymous") return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  if (!hasRole(...roles)) return <Forbidden />;
  return <>{children}</>;
}

export function Forbidden() {
  return (
    <div className="mx-auto max-w-md py-16 text-center">
      <p className="text-3xl" aria-hidden="true">
        ⛔
      </p>
      <h1 className="mt-2 text-base font-semibold">Accès non autorisé</h1>
      <p className="mt-1 text-sm text-ink-2">Votre rôle ne donne pas accès à cette vue.</p>
    </div>
  );
}
