/** Primitives d'interface (Tailwind, jetons de thème). */
import { useEffect, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";

import { ApiError } from "../api/http";
import { TONE_CLASSES, type StatusVisual, type Tone } from "../lib/status";

export function cx(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(" ");
}

type Variant = "primary" | "secondary" | "danger" | "ghost";

export function Button({
  variant = "secondary",
  busy = false,
  className,
  children,
  disabled,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; busy?: boolean }) {
  const styles: Record<Variant, string> = {
    primary: "bg-accent text-accent-ink hover:bg-accent/90 border-transparent",
    secondary: "bg-surface text-ink hover:bg-surface-2 border-line",
    danger: "bg-critical text-white hover:bg-critical/90 border-transparent",
    ghost: "bg-transparent text-ink-2 hover:bg-surface-2 border-transparent",
  };
  return (
    <button
      type="button"
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-md border px-3 py-1.5 text-sm font-medium transition-colors",
        "disabled:cursor-not-allowed disabled:opacity-50",
        styles[variant],
        className,
      )}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      {...props}
    >
      {busy && <Spinner />}
      {children}
    </button>
  );
}

export function Card({
  title,
  subtitle,
  actions,
  children,
  className,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={cx(
        "rounded-xl border border-white/[0.08] bg-gradient-to-b from-zinc-900/90 to-zinc-950 shadow-sm transition-colors hover:border-white/[0.15]",
        className,
      )}
    >
      {(title || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-2 border-b border-white/[0.06] px-4 py-3">
          <div>
            {title && <h2 className="text-sm font-semibold text-ink">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-muted">{subtitle}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      {/* pb : la dernière ligne (sources d'alerte, horodatages) ne doit jamais être rognée */}
      <div className="p-[var(--card-pad)] pb-[calc(var(--card-pad)+0.25rem)]">{children}</div>
    </section>
  );
}

/** Pastille d'état : ton + icône + libellé (jamais la couleur seule). */
export function StatusPill({ visual, compact = false }: { visual: StatusVisual; compact?: boolean }) {
  const tone = TONE_CLASSES[visual.tone];
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border font-medium text-ink",
        tone.border,
        tone.soft,
        compact ? "px-2 py-0 text-xs" : "px-2.5 py-0.5 text-xs",
      )}
    >
      <span aria-hidden="true" className={cx("text-[0.7rem] leading-none", tone.text)}>
        {visual.icon}
      </span>
      {visual.label}
    </span>
  );
}

export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span className={cx("inline-flex rounded px-1.5 py-0.5 text-[0.7rem] font-medium text-ink-2", TONE_CLASSES[tone].soft)}>
      {children}
    </span>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span role="status" className="inline-flex items-center gap-2 text-muted">
      <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" aria-hidden="true" />
      {label && <span className="text-xs">{label}</span>}
    </span>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <p className="rounded-md border border-dashed border-line px-4 py-6 text-center text-xs text-muted">{children}</p>;
}

export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 0) return "La plateforme est injoignable. Nouvel essai automatique dès le rétablissement.";
    const details = error.errors.map((item) => `${item.location.replace(/^body\./, "")} : ${item.message}`).join(" · ");
    return [error.detail ?? error.message, details].filter(Boolean).join(" — ");
  }
  return error instanceof Error ? error.message : "Erreur inattendue";
}

export function ErrorBanner({ error, title = "Une erreur est survenue" }: { error: unknown; title?: string }) {
  if (!error) return null;
  const code = error instanceof ApiError ? error.code : null;
  return (
    <div role="alert" className="rounded-md border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-ink">
      <p className="font-semibold">
        <span aria-hidden="true" className="mr-1 text-critical">
          ✖
        </span>
        {title}
        {code && <span className="ml-2 font-mono text-[0.7rem] text-ink-2">{code}</span>}
      </p>
      <p className="mt-0.5 text-ink-2">{describeError(error)}</p>
    </div>
  );
}

export function Field({ label, hint, children, htmlFor }: { label: string; hint?: string; children: ReactNode; htmlFor: string }) {
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={htmlFor} className="text-xs font-medium text-ink-2">
        {label}
      </label>
      {children}
      {hint && <p className="text-[0.7rem] text-muted">{hint}</p>}
    </div>
  );
}

const control =
  "w-full rounded-md border border-line bg-surface px-2.5 py-1.5 text-sm text-ink placeholder:text-muted " +
  "focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/30 disabled:opacity-60";

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cx(control, props.className)} />;
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={cx(control, props.className)} />;
}

export function StatTile({
  label,
  value,
  hint,
  valueClass = "text-ink",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  valueClass?: string;
}) {
  return (
    <div className="rounded-xl border border-white/[0.08] bg-gradient-to-b from-zinc-900/90 to-zinc-950 px-4 py-3 transition-colors hover:border-white/[0.15]">
      <p className="text-xs text-muted">{label}</p>
      <p className={cx("mt-1 text-2xl font-semibold tabular-nums", valueClass)}>{value}</p>
      {hint && <p className="mt-0.5 text-[0.7rem] text-muted">{hint}</p>}
    </div>
  );
}

/** Pastille monospace pour les journaux et codes techniques bruts (restent en anglais). */
export function Code({ children, block = false }: { children: ReactNode; block?: boolean }) {
  return block ? (
    <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-white/[0.08] bg-black/40 px-2.5 py-1.5 font-mono text-[0.7rem] text-zinc-300">
      {children}
    </pre>
  ) : (
    <code className="rounded border border-white/[0.08] bg-black/40 px-1.5 py-0.5 font-mono text-[0.7rem] text-zinc-300">{children}</code>
  );
}

/** Panneau latéral modal (Échap ou clic extérieur pour fermer). */
export function Drawer({ title, onClose, children, wide = false }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-30 flex justify-end bg-black/60" onClick={onClose}>
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={cx("h-full w-full overflow-y-auto border-l border-white/[0.08] bg-zinc-950 p-5 shadow-xl", wide ? "max-w-3xl" : "max-w-md")}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold">{title}</h2>
          <Button variant="ghost" onClick={onClose} aria-label="Fermer">
            ✕
          </Button>
        </div>
        {children}
      </aside>
    </div>
  );
}
