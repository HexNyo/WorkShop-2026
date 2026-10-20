/** Formats d'affichage (fr-FR). Les montants restent des chaînes décimales côté API. */

const timeFormat = new Intl.DateTimeFormat("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const shortTime = new Intl.DateTimeFormat("fr-FR", { hour: "2-digit", minute: "2-digit" });
const dateTimeFormat = new Intl.DateTimeFormat("fr-FR", {
  day: "2-digit",
  month: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

export function formatMoney(value: string, currency: string): string {
  const amount = Number(value);
  if (!Number.isFinite(amount)) return `${value} ${currency}`;
  return new Intl.NumberFormat("fr-FR", { style: "currency", currency }).format(amount);
}

export function formatTime(iso: string | null | undefined): string {
  return iso ? timeFormat.format(new Date(iso)) : "—";
}

export function formatShortTime(date: Date): string {
  return shortTime.format(date);
}

export function formatDateTime(iso: string | null | undefined): string {
  return iso ? dateTimeFormat.format(new Date(iso)) : "—";
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "—";
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 90) return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  if (minutes < 60) return rest ? `${minutes} min ${rest} s` : `${minutes} min`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

export function formatSince(iso: string, now: number = Date.now()): string {
  return formatDuration(Math.max((now - new Date(iso).getTime()) / 1000, 0));
}

/** "payment.repair_balances" -> "repair balances" (libellé lisible d'une action de playbook). */
export function humanizeAction(action: string): string {
  const [, name = action] = action.split(".");
  return name.replaceAll("_", " ");
}

export function isValidAmount(value: string, minorUnits = 2): boolean {
  const pattern = new RegExp(`^(0|[1-9][0-9]{0,11})(\\.[0-9]{1,${minorUnits}})?$`);
  return pattern.test(value) && Number(value) > 0;
}
