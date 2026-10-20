/**
 * Préférences d'affichage, propres au navigateur (localStorage). Les réglages du moteur
 * (sondes, seuils, tentatives) ne sont PAS ici : ils sont lus côté serveur, en lecture seule.
 */
import { useSyncExternalStore } from "react";

export interface UiSettings {
  density: "comfortable" | "compact";
  autoRefresh: boolean;
  audioAlert: boolean;
  browserNotifications: boolean;
  slaSeconds: number;
}

export const DEFAULT_SETTINGS: UiSettings = {
  density: "comfortable",
  autoRefresh: true,
  audioAlert: false,
  browserNotifications: false,
  slaSeconds: 30,
};

const KEY = "ra.ui-settings.v1";
const listeners = new Set<() => void>();

/** Valide une valeur stockée (navigateur = source non fiable) champ par champ. */
export function parseSettings(raw: string | null): UiSettings {
  let stored: Record<string, unknown> = {};
  try {
    stored = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
  } catch {
    stored = {};
  }
  const sla = Number(stored.slaSeconds);
  return {
    density: stored.density === "compact" ? "compact" : "comfortable",
    autoRefresh: typeof stored.autoRefresh === "boolean" ? stored.autoRefresh : DEFAULT_SETTINGS.autoRefresh,
    audioAlert: stored.audioAlert === true,
    browserNotifications: stored.browserNotifications === true,
    slaSeconds: Number.isFinite(sla) && sla >= 1 && sla <= 3600 ? Math.round(sla) : DEFAULT_SETTINGS.slaSeconds,
  };
}

function read(): UiSettings {
  try {
    return parseSettings(localStorage.getItem(KEY));
  } catch {
    return DEFAULT_SETTINGS; // stockage indisponible (navigation privée, sandbox)
  }
}

let current = read();

export function applySettings(settings: UiSettings): void {
  document.documentElement.style.setProperty("--card-pad", settings.density === "compact" ? "0.625rem" : "1rem");
}

export function updateSettings(patch: Partial<UiSettings>): void {
  current = parseSettings(JSON.stringify({ ...current, ...patch }));
  try {
    localStorage.setItem(KEY, JSON.stringify(current));
  } catch {
    // préférence conservée pour la session uniquement
  }
  applySettings(current);
  listeners.forEach((listener) => listener());
}

export function useSettings(): UiSettings {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}

applySettings(current);

/** Bip court (alerte sonore sur incident critique) — Web Audio, sans fichier. */
export function playAlert(): void {
  try {
    const context = new AudioContext();
    const oscillator = context.createOscillator();
    const gain = context.createGain();
    oscillator.frequency.value = 880;
    gain.gain.setValueAtTime(0.15, context.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, context.currentTime + 0.6);
    oscillator.connect(gain).connect(context.destination);
    oscillator.start();
    oscillator.stop(context.currentTime + 0.6);
  } catch {
    // audio indisponible : l'alerte visuelle suffit
  }
}
