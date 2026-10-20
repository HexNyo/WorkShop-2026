/** Géométrie pure de la frise des phases (testable sans DOM). */
import type { Phase, Timeline } from "../api/types";

export interface SegmentBox {
  phase: Phase;
  start: number;
  end: number;
  x: number;
  width: number;
  incidentId: string | null;
}

export interface MarkerPoint {
  at: number;
  x: number;
  kind: string;
  label: string;
  incidentId: string | null;
}

export const SEGMENT_GAP = 2; // espace de surface entre deux remplissages adjacents

export function layoutTimeline(
  timeline: Timeline,
  range: { from: number; to: number },
  width: number,
): { segments: SegmentBox[]; markers: MarkerPoint[] } {
  const span = Math.max(range.to - range.from, 1);
  const scale = (t: number) => ((Math.min(Math.max(t, range.from), range.to) - range.from) / span) * width;

  const segments: SegmentBox[] = [];
  for (const segment of timeline.segments) {
    const start = Math.max(new Date(segment.from).getTime(), range.from);
    const end = Math.min(segment.to ? new Date(segment.to).getTime() : range.to, range.to);
    if (end <= start) continue;
    const x = scale(start);
    const raw = scale(end) - x;
    const isLast = end >= range.to;
    // Un segment visible occupe au moins 2 px ; l'écart de 2 px sépare deux phases successives.
    const widthPx = Math.max(raw - (isLast ? 0 : SEGMENT_GAP), 2);
    segments.push({ phase: segment.phase, start, end, x, width: widthPx, incidentId: segment.incident_id });
  }

  const markers = timeline.markers
    .map((marker) => ({ ...marker, time: new Date(marker.at).getTime() }))
    .filter((marker) => marker.time >= range.from && marker.time <= range.to)
    .map((marker) => ({
      at: marker.time,
      x: scale(marker.time),
      kind: marker.kind,
      label: marker.label,
      incidentId: marker.incident_id,
    }));

  return { segments, markers };
}

/** Graduations de l'axe temporel : pas « rond » donnant environ `target` repères. */
export function timeTicks(range: { from: number; to: number }, target = 6): number[] {
  const minute = 60_000;
  const steps = [1, 2, 5, 10, 15, 30, 60, 120, 240, 360].map((value) => value * minute);
  const span = range.to - range.from;
  const step = steps.find((candidate) => span / candidate <= target) ?? steps[steps.length - 1]!;
  const first = Math.ceil(range.from / step) * step;
  const ticks: number[] = [];
  for (let t = first; t <= range.to; t += step) ticks.push(t);
  return ticks;
}
