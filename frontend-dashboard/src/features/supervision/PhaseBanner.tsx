import { useEffect, useState } from "react";

import type { Phase } from "../../api/types";
import { cx } from "../../components/ui";
import { formatSince, formatTime } from "../../lib/format";
import { PHASES, TONE_CLASSES, type Era } from "../../lib/status";

const ERAS: { era: Era; caption: string }[] = [
  { era: "AVANT", caption: "Nominal" },
  { era: "PENDANT", caption: "Attaque / incident" },
  { era: "APRÈS", caption: "Rétabli et vérifié" },
];

/** Bandeau principal : lecture immédiate de l'état Avant / Pendant / Après. */
export function PhaseBanner({ phase, since, reason }: { phase: Phase; since: string; reason: string | null }) {
  const visual = PHASES[phase];
  const tone = TONE_CLASSES[visual.tone];
  const critical = visual.tone === "critical";
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <section
      aria-label="Phase système"
      data-testid="phase-banner"
      data-phase={phase}
      className={cx(
        "rounded-xl border px-5 py-4",
        critical ? "border-red-500/40 bg-red-950/30 shadow-[0_0_30px_-10px_rgba(239,68,68,0.25)]" : cx("bg-zinc-900/80", tone.border),
      )}
    >
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <span
            aria-hidden="true"
            className={cx("flex h-12 w-12 items-center justify-center rounded-full text-2xl", tone.bg, tone.on, critical && "animate-pulse")}
          >
            {visual.icon}
          </span>
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-muted">Phase système · {visual.label}</p>
            <p className="text-xl font-semibold">{visual.headline}</p>
            <p className="text-xs text-ink-2">
              depuis {formatTime(since)} ({formatSince(since, now)}){reason ? ` — ${reason}` : ""}
            </p>
          </div>
        </div>
        <ol className="flex items-stretch gap-1" aria-label="Chronologie de l'incident">
          {ERAS.map(({ era, caption }, index) => {
            const active = era === visual.era;
            return (
              <li key={era} className="flex items-center gap-1">
                <div
                  className={cx(
                    "min-w-[7.5rem] rounded-md border px-3 py-1.5 text-center",
                    active ? cx(tone.border, tone.soft, "font-semibold text-ink") : "border-line text-muted",
                  )}
                  aria-current={active ? "step" : undefined}
                >
                  <p className="text-sm tracking-wide">{era}</p>
                  <p className="text-[0.7rem]">{caption}</p>
                </div>
                {index < ERAS.length - 1 && (
                  <span aria-hidden="true" className="text-muted">
                    →
                  </span>
                )}
              </li>
            );
          })}
        </ol>
      </div>
    </section>
  );
}
