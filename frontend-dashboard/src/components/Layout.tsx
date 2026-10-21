import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";

import { ROLE_GROUPS, useAuth } from "../auth/AuthProvider";
import { SettingsDialog } from "./SettingsDialog";
import { Button, cx } from "./ui";

export const LINKS = [
  { to: "/payments", label: "Portail métier", roles: ROLE_GROUPS.payments },
  { to: "/supervision", label: "Supervision NOC/SOC", roles: ROLE_GROUPS.supervision },
  { to: "/assistant", label: "Assistant opérateur", roles: ROLE_GROUPS.assistant },
  { to: "/admin", label: "Administration", roles: ROLE_GROUPS.admin },
] as const;

export function Layout() {
  const { principal, hasRole, logout } = useAuth();
  const links = LINKS.filter((link) => hasRole(...link.roles));
  const [settingsOpen, setSettingsOpen] = useState(false);

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-20 border-b border-white/[0.08] bg-zinc-950/90 backdrop-blur">
        <div className="mx-auto flex max-w-[1400px] flex-wrap items-center gap-x-6 gap-y-2 px-4 py-2.5">
          <div className="flex items-center gap-2">
            <img src="/favicon.svg" alt="" className="h-6 w-6" />
            <span className="font-semibold tracking-tight">RESILIENCE-ALPHA</span>
            <span className="hidden rounded bg-surface-2 px-1.5 py-0.5 text-[0.65rem] font-medium text-muted sm:inline">
              données fictives
            </span>
          </div>
          <nav aria-label="Navigation principale" className="flex flex-1 flex-wrap gap-1">
            {links.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                className={({ isActive }) =>
                  cx(
                    "rounded-md px-3 py-1.5 text-sm",
                    isActive ? "bg-accent/10 font-semibold text-accent" : "text-ink-2 hover:bg-surface-2 hover:text-ink",
                  )
                }
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
          {principal && (
            <div className="flex items-center gap-3">
              <div className="text-right leading-tight">
                <p className="text-sm font-medium">{principal.display_name}</p>
                <div className="group relative inline-block">
                  <button type="button" className="text-[0.7rem] text-muted hover:text-ink" aria-label={`Rôles : ${principal.roles.join(", ")}`}>
                    {principal.roles.length} rôle{principal.roles.length > 1 ? "s" : ""} actif{principal.roles.length > 1 ? "s" : ""} ▾
                  </button>
                  <ul className="absolute right-0 top-full z-30 hidden min-w-[11rem] rounded-md border border-white/[0.08] bg-zinc-900 p-2 text-left shadow-xl group-focus-within:block group-hover:block">
                    {principal.roles.map((role) => (
                      <li key={role} className="py-0.5 font-mono text-[0.7rem] text-zinc-300">
                        {role}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
              <Button variant="ghost" onClick={() => setSettingsOpen(true)} aria-label="Paramètres" title="Paramètres">
                ⚙
              </Button>
              <Button variant="ghost" onClick={() => void logout()}>
                Se déconnecter
              </Button>
            </div>
          )}
        </div>
      </header>
      {settingsOpen && <SettingsDialog onClose={() => setSettingsOpen(false)} />}
      <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-5">
        <Outlet />
      </main>
    </div>
  );
}
