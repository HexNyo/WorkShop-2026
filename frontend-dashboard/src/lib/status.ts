/**
 * Sémantique visuelle des états : chaque état a un ton de la palette « status »,
 * une icône ET un libellé — la couleur ne porte jamais l'information seule.
 */
import type { IncidentStatus, Phase, ServiceStatus, TransactionStatus } from "../api/types";

export type Tone = "good" | "warning" | "serious" | "critical" | "neutral" | "accent";

export interface StatusVisual {
  tone: Tone;
  icon: string;
  label: string;
}

/** Lecture « Avant / Pendant / Après » de la phase système. */
export type Era = "AVANT" | "PENDANT" | "APRÈS";

export const PHASES: Record<Phase, StatusVisual & { era: Era; headline: string }> = {
  NOMINAL: { tone: "good", icon: "●", label: "Nominal", era: "AVANT", headline: "Fonctionnement nominal" },
  DEGRADED: { tone: "warning", icon: "▲", label: "Dégradé", era: "PENDANT", headline: "Service dégradé" },
  CRITICAL: { tone: "critical", icon: "✖", label: "Critique", era: "PENDANT", headline: "Incident critique en cours" },
  RECOVERING: { tone: "serious", icon: "↻", label: "Rétablissement", era: "PENDANT", headline: "Remédiation automatique en cours" },
  RESTORED: { tone: "good", icon: "✔", label: "Rétabli", era: "APRÈS", headline: "Service rétabli et vérifié" },
};

export const PHASE_ORDER: Phase[] = ["NOMINAL", "DEGRADED", "CRITICAL", "RECOVERING", "RESTORED"];

export const SERVICE_STATUS: Record<ServiceStatus, StatusVisual> = {
  UP: { tone: "good", icon: "●", label: "Disponible" },
  DEGRADED: { tone: "warning", icon: "▲", label: "Dégradé" },
  DOWN: { tone: "critical", icon: "✖", label: "Indisponible" },
  UNKNOWN: { tone: "neutral", icon: "?", label: "Inconnu" },
};

export const INCIDENT_STATUS: Record<IncidentStatus, StatusVisual> = {
  OPEN: { tone: "critical", icon: "!", label: "Ouvert" },
  TRIAGED: { tone: "warning", icon: "◆", label: "Qualifié" },
  REMEDIATING: { tone: "serious", icon: "↻", label: "Remédiation" },
  VERIFYING: { tone: "accent", icon: "⋯", label: "Vérification" },
  RESOLVED: { tone: "good", icon: "✔", label: "Résolu" },
  ESCALATED: { tone: "critical", icon: "⚑", label: "Escaladé" },
  SUPPRESSED: { tone: "neutral", icon: "–", label: "Ignoré" },
};

export const INCIDENT_FLOW: IncidentStatus[] = ["OPEN", "TRIAGED", "REMEDIATING", "VERIFYING", "RESOLVED"];

export const TRANSACTION_STATUS: Record<TransactionStatus, StatusVisual> = {
  PENDING: { tone: "neutral", icon: "…", label: "En attente" },
  VALIDATED: { tone: "accent", icon: "◆", label: "Validée" },
  EXECUTED: { tone: "good", icon: "✔", label: "Exécutée" },
  REJECTED: { tone: "warning", icon: "▲", label: "Refusée" },
  FAILED: { tone: "critical", icon: "✖", label: "Échouée" },
  CANCELLED: { tone: "neutral", icon: "–", label: "Annulée" },
};

export const STEP_STATUS: Record<string, StatusVisual> = {
  PENDING: { tone: "neutral", icon: "○", label: "En attente" },
  RUNNING: { tone: "accent", icon: "↻", label: "En cours" },
  SUCCEEDED: { tone: "good", icon: "✔", label: "Réussie" },
  FAILED: { tone: "critical", icon: "✖", label: "Échec" },
  SKIPPED: { tone: "neutral", icon: "–", label: "Ignorée" },
};

/** Libellés des contrôles de la vérification post-reprise (docs/04 § 4). */
export const VERIFICATION_CHECKS: { code: string; label: string; proves: string }[] = [
  { code: "API_READINESS", label: "V1 · API prête", proves: "l'API est joignable et ses dépendances prêtes" },
  { code: "AUTH_M2M_TOKEN", label: "V2 · Authentification", proves: "un jeton de service frais est émis" },
  { code: "SYNTHETIC_BALANCES_READ", label: "V3 · Lecture des soldes", proves: "la lecture des données fonctionne" },
  { code: "SYNTHETIC_TX_EXECUTE", label: "V4 · Transaction de test", proves: "le traitement métier est fonctionnel" },
  { code: "IDEMPOTENCY_REPLAY", label: "V5 · Idempotence", proves: "un rejeu ne crée pas de doublon" },
  { code: "TX_READ_BACK", label: "V6 · Relecture & grand livre", proves: "historique, écriture et soldes cohérents" },
  { code: "SYNTHETIC_TX_COMPENSATE", label: "V7 · Compensation", proves: "les comptes sondes sont rétablis" },
  { code: "DATA_INTEGRITY", label: "V8 · Intégrité des données", proves: "les 7 contrôles d'intégrité passent" },
  { code: "STABILITY_WINDOW", label: "V9 · Stabilité", proves: "la reprise n'est pas transitoire" },
];

/**
 * `on` / `onFill` : encre lisible SUR l'aplat du ton (texte sombre sur good, warning,
 * serious, neutral ; blanc sur critical et accent) — contraste ≥ 4.5:1 dans les deux thèmes.
 */
export const TONE_CLASSES: Record<
  Tone,
  { text: string; bg: string; soft: string; border: string; fill: string; on: string; onFill: string }
> = {
  good: { text: "text-good", bg: "bg-good", soft: "bg-good/10", border: "border-good/40", fill: "fill-good", on: "text-[#0b0b0b]", onFill: "fill-[#0b0b0b]" },
  warning: { text: "text-warning", bg: "bg-warning", soft: "bg-warning/15", border: "border-warning/50", fill: "fill-warning", on: "text-[#0b0b0b]", onFill: "fill-[#0b0b0b]" },
  serious: { text: "text-serious", bg: "bg-serious", soft: "bg-serious/15", border: "border-serious/50", fill: "fill-serious", on: "text-[#0b0b0b]", onFill: "fill-[#0b0b0b]" },
  critical: { text: "text-critical", bg: "bg-critical", soft: "bg-critical/10", border: "border-critical/40", fill: "fill-critical", on: "text-white", onFill: "fill-white" },
  neutral: { text: "text-muted", bg: "bg-neutral", soft: "bg-neutral/10", border: "border-line", fill: "fill-neutral", on: "text-[#0b0b0b]", onFill: "fill-[#0b0b0b]" },
  accent: { text: "text-accent", bg: "bg-accent", soft: "bg-accent/10", border: "border-accent/40", fill: "fill-accent", on: "text-white", onFill: "fill-white" },
};