/**
 * Frise des phases (Avant / Pendant / Après) : remplissages séparés par un écart de
 * surface, repères d'événements, infobulle au survol, légende et vue tableau.
 */
import { useEffect, useMemo, useRef, useState } from "react";

import type { Timeline } from "../../api/types";
import { Button, Card, EmptyState, cx } from "../../components/ui";
import { formatDuration, formatShortTime, formatTime } from "../../lib/format";
import { PHASE_ORDER, PHASES, TONE_CLASSES } from "../../lib/status";
import { layoutTimeline, timeTicks } from "../../lib/timeline";
import { RANGES, type RangeLabel } from "./useSupervision";

const BAR_Y = 26;
const BAR_HEIGHT = 30;
const AXIS_Y = BAR_Y + BAR_HEIGHT + 14;
const HEIGHT = AXIS_Y + 6;

const MARKER: Record<string, { glyph: string; label: string }> = {
  "alert.received": { glyph: "▼", label: "Alerte reçue" },
  "verification.completed": { glyph: "✔", label: "Vérification synthétique" },
  "incident.closed": { glyph: "●", label: "Incident clos" },
};

interface Hover {
  x: number;
  title: string;
  lines: string[];
}

export function PhaseTimeline({
  timeline,
  range,
  onRange,
  onFocusIncident,
}: {
  timeline: Timeline | null;
  range: RangeLabel;
  onRange: (range: RangeLabel) => void;
  onFocusIncident?: () => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(800);
  const [hover, setHover] = useState<Hover | null>(null);
  const [asTable, setAsTable] = useState(false);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const element = container.current;
    if (!element) return undefined;
    const observer = new ResizeObserver(([entry]) => entry && setWidth(Math.max(entry.contentRect.width, 240)));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 5000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => setNow(Date.now()), [timeline]);

  const bounds = useMemo(() => ({ from: now - RANGES[range] * 60_000, to: now }), [now, range]);
  const layout = useMemo(
    () => (timeline ? layoutTimeline(timeline, bounds, width) : { segments: [], markers: [] }),
    [timeline, bounds, width],
  );
  const ticks = useMemo(() => timeTicks(bounds), [bounds]);
  const present = new Set(layout.segments.map((segment) => segment.phase));

  return (
    <Card
      title="Chronologie des phases"
      subtitle="Avant l'incident · pendant l'attaque · après la remédiation"
      actions={
        <>
          <div role="radiogroup" aria-label="Période" className="flex rounded-md border border-line p-0.5">
            {(Object.keys(RANGES) as RangeLabel[]).map((label) => (
              <button
                key={label}
                type="button"
                role="radio"
                aria-checked={label === range}
                onClick={() => onRange(label)}
                className={cx(
                  "rounded px-2 py-0.5 text-xs",
                  label === range ? "bg-accent/10 font-semibold text-accent" : "text-ink-2 hover:bg-surface-2",
                )}
              >
                {label}
              </button>
            ))}
          </div>
          {onFocusIncident && (
            <Button variant="ghost" onClick={onFocusIncident}>
              ⌖ Focus début incident
            </Button>
          )}
          <Button variant="ghost" onClick={() => setAsTable((value) => !value)}>
            {asTable ? "Vue frise" : "Vue tableau"}
          </Button>
        </>
      }
    >
      {/* Conteneur toujours monté : la largeur est mesurée dès le premier rendu. */}
      <div ref={container}>
      {!timeline ? (
        <EmptyState>Chargement de la chronologie…</EmptyState>
      ) : asTable ? (
        <table className="tabular w-full text-left text-xs">
          <thead className="text-muted">
            <tr className="border-b border-line">
              <th className="py-1.5 pr-3 font-medium">Phase</th>
              <th className="py-1.5 pr-3 font-medium">Début</th>
              <th className="py-1.5 pr-3 font-medium">Fin</th>
              <th className="py-1.5 font-medium">Durée</th>
            </tr>
          </thead>
          <tbody>
            {layout.segments.map((segment) => (
              <tr key={`${segment.phase}-${segment.start}`} className="border-b border-line/60">
                <td className="py-1 pr-3">
                  {PHASES[segment.phase].icon} {PHASES[segment.phase].label} · {PHASES[segment.phase].era}
                </td>
                <td className="py-1 pr-3">{formatTime(new Date(segment.start).toISOString())}</td>
                <td className="py-1 pr-3">{segment.end >= bounds.to ? "en cours" : formatTime(new Date(segment.end).toISOString())}</td>
                <td className="py-1">{formatDuration((segment.end - segment.start) / 1000)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="relative" onMouseLeave={() => setHover(null)}>
          <svg
            width={width}
            height={HEIGHT}
            role="img"
            aria-label="Frise des phases système sur la période sélectionnée"
            data-testid="phase-timeline"
          >
            {ticks.map((tick) => {
              const x = ((tick - bounds.from) / (bounds.to - bounds.from)) * width;
              return (
                <g key={tick}>
                  <line x1={x} x2={x} y1={BAR_Y - 4} y2={BAR_Y + BAR_HEIGHT + 4} className="stroke-line" strokeWidth={1} />
                  <text x={x} y={AXIS_Y} textAnchor="middle" className="fill-muted text-[10px]">
                    {formatShortTime(new Date(tick))}
                  </text>
                </g>
              );
            })}
            {layout.segments.map((segment) => {
              const visual = PHASES[segment.phase];
              const label = `${visual.icon} ${visual.label}`;
              return (
                <g
                  key={`${segment.phase}-${segment.start}`}
                  onMouseMove={(event) =>
                    setHover({
                      x: event.nativeEvent.offsetX,
                      title: `${visual.label} · ${visual.era}`,
                      lines: [
                        `${formatTime(new Date(segment.start).toISOString())} → ${
                          segment.end >= bounds.to ? "maintenant" : formatTime(new Date(segment.end).toISOString())
                        }`,
                        `Durée : ${formatDuration((segment.end - segment.start) / 1000)}`,
                      ],
                    })
                  }
                >
                  <rect
                    x={segment.x}
                    y={BAR_Y}
                    width={segment.width}
                    height={BAR_HEIGHT}
                    rx={4}
                    className={TONE_CLASSES[visual.tone].fill}
                    data-phase={segment.phase}
                  />
                  {segment.width > label.length * 7 + 12 && (
                    <text x={segment.x + 8} y={BAR_Y + BAR_HEIGHT / 2 + 4} className={cx("pointer-events-none text-[11px] font-semibold", TONE_CLASSES[visual.tone].onFill)}>
                      {label}
                    </text>
                  )}
                </g>
              );
            })}
            {layout.markers.map((marker) => {
              const meta = MARKER[marker.kind] ?? { glyph: "◆", label: marker.kind };
              return (
                <g
                  key={`${marker.kind}-${marker.at}`}
                  onMouseMove={() =>
                    setHover({ x: marker.x, title: meta.label, lines: [formatTime(new Date(marker.at).toISOString()), marker.label] })
                  }
                >
                  {/* zone de survol plus large que le repère */}
                  <rect x={marker.x - 8} y={2} width={16} height={BAR_Y - 2} className="fill-transparent" />
                  <text x={marker.x} y={BAR_Y - 8} textAnchor="middle" className="fill-ink-2 text-[11px]">
                    {meta.glyph}
                  </text>
                </g>
              );
            })}
          </svg>
          {hover && (
            <div
              className="pointer-events-none absolute top-0 z-10 -translate-x-1/2 -translate-y-full rounded-md border border-line bg-surface px-2.5 py-1.5 text-xs shadow-lg"
              style={{ left: Math.min(Math.max(hover.x, 80), width - 80) }}
              role="tooltip"
            >
              <p className="font-semibold">{hover.title}</p>
              {hover.lines.map((line) => (
                <p key={line} className="tabular text-ink-2">
                  {line}
                </p>
              ))}
            </div>
          )}
          <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[0.7rem] text-ink-2" aria-label="Légende">
            {PHASE_ORDER.filter((phase) => present.has(phase) || phase === "NOMINAL").map((phase) => (
              <li key={phase} className="flex items-center gap-1.5">
                <span className={cx("h-2.5 w-2.5 rounded-sm", TONE_CLASSES[PHASES[phase].tone].bg)} aria-hidden="true" />
                {PHASES[phase].icon} {PHASES[phase].label} ({PHASES[phase].era})
              </li>
            ))}
            {Object.values(MARKER).map((meta) => (
              <li key={meta.label} className="flex items-center gap-1.5">
                <span aria-hidden="true">{meta.glyph}</span>
                {meta.label}
              </li>
            ))}
          </ul>
        </div>
      )}
      </div>
    </Card>
  );
}
