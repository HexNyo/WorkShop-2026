import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";

import { useAuth } from "../auth/AuthProvider";
import { LINKS } from "./Layout";
import { SettingsDialog } from "./SettingsDialog";
import { cx } from "./ui";

/** Accroche typographique de chaque vue (thème éditorial). */
const HEROES: Record<string, { lines: string[]; accent: number; coord: string }> = {
  "/payments": { lines: ["L'argent", "circule,", "sans bruit."], accent: 1, coord: "48.8566 N" },
  "/supervision": { lines: ["Rien", "ne tombe", "longtemps."], accent: 2, coord: "2.3522 E" },
  "/assistant": { lines: ["Demandez.", "La machine", "se souvient."], accent: 2, coord: "T+00:42" },
  "/admin": { lines: ["Qui entre,", "qui reste,", "qui part."], accent: 1, coord: "0001.α" },
};
const FALLBACK = { lines: ["Workshop", "2026."], accent: 1, coord: "—" };
const MARQUEE = "détection ✳ décision ✳ remédiation ✳ vérification ✳ zéro intervention humaine ✳ ";

/** Curseur suiveur + effet magnétique sur [data-magnetic] ; souris uniquement, coupé si moins d'animations demandé. */
function useCursor() {
  const cursor = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!matchMedia("(pointer: fine)").matches || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const dot = cursor.current!;
    dot.hidden = false;
    let x = innerWidth / 2, y = innerHeight / 2, cx = x, cy = y, frame = 0;
    let last: HTMLElement | null = null;
    const move = (e: PointerEvent) => {
      x = e.clientX;
      y = e.clientY;
      const target = (e.target as Element).closest("a, button, input, select, textarea, [data-magnetic]");
      dot.dataset.hover = target ? "1" : "";
      const magnet = (e.target as Element).closest<HTMLElement>("[data-magnetic]");
      if (last && last !== magnet) last.style.transform = "";
      last = magnet;
      if (magnet) {
        const r = magnet.getBoundingClientRect();
        magnet.style.transform = `translate(${(x - r.left - r.width / 2) * 0.15}px, ${(y - r.top - r.height / 2) * 0.3}px)`;
      }
    };
    const loop = () => {
      cx += (x - cx) * 0.14;
      cy += (y - cy) * 0.14;
      dot.style.transform = `translate(${cx}px, ${cy}px) translate(-50%, -50%)`;
      frame = requestAnimationFrame(loop);
    };
    addEventListener("pointermove", move);
    loop();
    document.documentElement.classList.add("has-cursor");
    return () => {
      removeEventListener("pointermove", move);
      cancelAnimationFrame(frame);
      document.documentElement.classList.remove("has-cursor");
    };
  }, []);
  return cursor;
}

/** Rail de défilement dessiné (remplace la barre native de la page) : clic ou glisser pour se déplacer. */
function ScrollRail() {
  const rail = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = rail.current!;
    const root = document.documentElement;
    const max = () => root.scrollHeight - innerHeight;
    let shown = 0, frame = 0;
    const loop = () => {
      const target = max() > 0 ? scrollY / max() : 0;
      shown += (target - shown) * 0.12;
      el.style.setProperty("--p", String(shown));
      el.dataset.label = String(Math.round(target * 100)).padStart(3, "0");
      el.hidden = max() <= 0;
      frame = requestAnimationFrame(loop);
    };
    loop();
    const seek = (e: PointerEvent) => scrollTo({ top: (e.clientY / innerHeight) * max(), behavior: "instant" });
    const down = (e: PointerEvent) => {
      el.setPointerCapture(e.pointerId);
      el.dataset.drag = "1";
      seek(e);
    };
    const move = (e: PointerEvent) => el.dataset.drag === "1" && seek(e);
    const up = () => (el.dataset.drag = "");
    el.addEventListener("pointerdown", down);
    el.addEventListener("pointermove", move);
    el.addEventListener("pointerup", up);
    el.addEventListener("pointercancel", up);
    return () => cancelAnimationFrame(frame);
  }, []);
  return (
    <div ref={rail} aria-hidden="true" className="ed-rail">
      <span className="ed-rail-fill" />
      <span className="ed-rail-mark" />
    </div>
  );
}

export function EditorialLayout() {
  const { principal, hasRole, logout } = useAuth();
  const { pathname } = useLocation();
  const links = LINKS.filter((link) => hasRole(...link.roles));
  const [settingsOpen, setSettingsOpen] = useState(false);
  const cursor = useCursor();
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("ed-dark"));
  const toggleMode = () => {
    document.documentElement.classList.toggle("ed-dark", !dark);
    try {
      localStorage.setItem("ra.theme.mode", dark ? "light" : "dark");
    } catch {
      // stockage indisponible : le choix vaut pour cet onglet seulement
    }
    setDark(!dark);
  };
  const hero = HEROES[pathname] ?? FALLBACK;
  const chapter = Math.max(0, links.findIndex((link) => link.to === pathname)) + 1;

  return (
    <div className="ed-shell">
      <div ref={cursor} hidden aria-hidden="true" className="ed-cursor" />
      <ScrollRail />

      <aside className="ed-aside">
        <div className="flex items-start justify-between">
          <span className="font-mono text-xs font-semibold" data-magnetic>
            R—α
          </span>
          <details className="ed-menu lg:hidden">
            <summary className="cursor-pointer font-mono text-[0.68rem] uppercase tracking-wider" aria-label="Menu">
              Menu ☰
            </summary>
            <Coordinates links={links} />
          </details>
        </div>

        <div key={pathname} className="ed-hero">
          <p className="font-mono text-[0.68rem] uppercase tracking-[0.2em] text-muted">
            §{String(chapter).padStart(2, "0")} · {hero.coord}
          </p>
          <p className="mt-3 font-serif text-[clamp(2.75rem,6vw,6rem)] font-black leading-[0.85] tracking-[-0.05em]">
            {hero.lines.map((line, index) => (
              <span key={line} className="ed-line" style={{ animationDelay: `${index * 90}ms` }}>
                <span className={cx(index === hero.accent && "font-light italic text-accent")}>{line}</span>
              </span>
            ))}
          </p>
        </div>

        <div className="hidden lg:block">
          <Coordinates links={links} />
        </div>

        {principal && (
          <div className="flex flex-wrap items-end justify-between gap-3 border-t border-line pt-3 font-mono text-[0.68rem]">
            <div>
              <p className="font-serif text-base italic">{principal.display_name}</p>
              <p className="text-muted" title={principal.roles.join(", ")}>
                {principal.roles.join(" · ")}
              </p>
            </div>
            <div className="flex gap-4 uppercase tracking-wider">
              <button
                type="button"
                className="hover:text-accent"
                onClick={toggleMode}
                aria-label={dark ? "Passer en mode jour" : "Passer en mode nuit"}
                data-magnetic
              >
                {dark ? "☀ Jour" : "☾ Nuit"}
              </button>
              <button type="button" className="hover:text-accent" onClick={() => setSettingsOpen(true)} data-magnetic>
                Réglages
              </button>
              <button type="button" className="hover:text-accent" onClick={() => void logout()} data-magnetic>
                Sortir →
              </button>
            </div>
          </div>
        )}
      </aside>

      <div className="ed-content">
        <div className="overflow-hidden border-b border-line py-3" aria-hidden="true">
          <div className="ed-marquee font-serif text-2xl italic lg:text-4xl">
            <span className="px-6">{MARQUEE.repeat(2)}</span>
            <span className="px-6">{MARQUEE.repeat(2)}</span>
          </div>
        </div>
        <main className="ed-main px-4 py-8 lg:px-10">
          <div key={pathname} className="ed-page">
            <Outlet />
          </div>
        </main>
      </div>

      {settingsOpen && <SettingsDialog onClose={() => setSettingsOpen(false)} />}
    </div>
  );
}

function Coordinates({ links }: { links: readonly (typeof LINKS)[number][] }) {
  return (
    <nav aria-label="Navigation principale">
      <ol className="divide-y divide-line border-y border-line">
        {links.map((link, index) => (
          <li key={link.to}>
            <NavLink
              to={link.to}
              data-magnetic
              className={({ isActive }) =>
                cx(
                  "flex items-baseline justify-between gap-4 py-2 transition-colors hover:text-accent",
                  isActive ? "text-accent" : "text-ink",
                )
              }
            >
              <span className="font-mono text-[0.68rem]">§{String(index + 1).padStart(2, "0")}</span>
              <span className="font-serif text-xl italic">{link.label}</span>
            </NavLink>
          </li>
        ))}
      </ol>
    </nav>
  );
}
