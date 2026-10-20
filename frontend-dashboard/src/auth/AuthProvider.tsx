/**
 * Session : jeton d'accès en mémoire uniquement (jamais localStorage), restauré au
 * chargement via le cookie de rafraîchissement HttpOnly, renouvelé avant expiration.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { authApi } from "../api/endpoints";
import { ApiError, configureAuth } from "../api/http";
import type { Principal, TokenResponse } from "../api/types";

interface Session {
  token: string;
  principal: Principal;
  expiresAt: number;
}

interface AuthState {
  status: "restoring" | "anonymous" | "authenticated";
  principal: Principal | null;
  login(username: string, password: string): Promise<void>;
  logout(): Promise<void>;
  hasRole(...roles: string[]): boolean;
  /** Jeton courant (flux SSE : échange contre un ticket). */
  token(): string | null;
}

const AuthContext = createContext<AuthState | null>(null);
const REFRESH_MARGIN_MS = 30_000;

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [status, setStatus] = useState<AuthState["status"]>("restoring");
  const sessionRef = useRef<Session | null>(null);
  const refreshing = useRef<Promise<string | null> | null>(null);

  const apply = useCallback((response: TokenResponse | null) => {
    const next = response
      ? { token: response.access_token, principal: response.principal, expiresAt: Date.now() + response.expires_in * 1000 }
      : null;
    sessionRef.current = next;
    setSession(next);
    setStatus(next ? "authenticated" : "anonymous");
  }, []);

  const refresh = useCallback(async (): Promise<string | null> => {
    // Une seule rotation à la fois : le refresh token est à usage unique.
    if (!refreshing.current) {
      refreshing.current = authApi
        .refresh()
        .then(({ data }) => {
          apply(data);
          return data.access_token;
        })
        .catch(() => {
          apply(null);
          return null;
        })
        .finally(() => {
          refreshing.current = null;
        });
    }
    return refreshing.current;
  }, [apply]);

  useEffect(() => {
    configureAuth({
      getToken: () => sessionRef.current?.token ?? null,
      refresh,
      onSessionLost: () => apply(null),
    });
    void refresh();
  }, [apply, refresh]);

  useEffect(() => {
    if (!session) return undefined;
    const delay = Math.max(session.expiresAt - Date.now() - REFRESH_MARGIN_MS, 5_000);
    const timer = window.setTimeout(() => void refresh(), delay);
    return () => window.clearTimeout(timer);
  }, [session, refresh]);

  const login = useCallback(
    async (username: string, password: string) => {
      const { data } = await authApi.login(username, password);
      apply(data);
    },
    [apply],
  );

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch (error) {
      if (!(error instanceof ApiError)) throw error;
    } finally {
      apply(null);
    }
  }, [apply]);

  const value = useMemo<AuthState>(
    () => ({
      status,
      principal: session?.principal ?? null,
      login,
      logout,
      hasRole: (...roles: string[]) => roles.some((role) => session?.principal.roles.includes(role) ?? false),
      token: () => sessionRef.current?.token ?? null,
    }),
    [status, session, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside <AuthProvider>");
  return context;
}

export const ROLE_GROUPS = {
  payments: ["payment.customer", "payment.operator"],
  supervision: ["noc.viewer", "remediation.admin"],
  assistant: ["noc.viewer"],
  admin: ["auth.admin", "remediation.admin", "chaos.operator"],
} as const;
