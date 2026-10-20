import type { Timeline } from "../api/types";
import { formatDuration, formatMoney, humanizeAction, isValidAmount } from "./format";
import { INCIDENT_STATUS, PHASES, SERVICE_STATUS, TONE_CLASSES, TRANSACTION_STATUS, VERIFICATION_CHECKS } from "./status";
import { SEGMENT_GAP, layoutTimeline, timeTicks } from "./timeline";

describe("format", () => {
  it("formats money in fr-FR without floating-point surprises", () => {
    expect(formatMoney("125.50", "EUR").replace(/\s/g, " ")).toBe("125,50 €");
    expect(formatMoney("0.01", "EUR").replace(/\s/g, " ")).toBe("0,01 €");
  });

  it("formats durations for MTTR and steps", () => {
    expect(formatDuration(0.25)).toBe("250 ms");
    expect(formatDuration(4.2)).toBe("4.2 s");
    expect(formatDuration(40)).toBe("40 s");
    expect(formatDuration(125)).toBe("2 min 5 s");
    expect(formatDuration(null)).toBe("—");
  });

  it("validates amounts like the API contract", () => {
    expect(isValidAmount("125.50")).toBe(true);
    expect(isValidAmount("1.001")).toBe(false);
    expect(isValidAmount("0")).toBe(false);
    expect(isValidAmount("-1")).toBe(false);
    expect(isValidAmount("01")).toBe(false);
  });

  it("humanizes playbook actions", () => {
    expect(humanizeAction("payment.repair_balances")).toBe("repair balances");
  });
});

describe("status semantics", () => {
  it("never relies on color alone: every state has an icon and a label", () => {
    for (const table of [PHASES, SERVICE_STATUS, INCIDENT_STATUS, TRANSACTION_STATUS]) {
      for (const visual of Object.values(table)) {
        expect(visual.icon.length).toBeGreaterThan(0);
        expect(visual.label.length).toBeGreaterThan(0);
        expect(TONE_CLASSES[visual.tone]).toBeDefined();
      }
    }
  });

  it("maps phases onto the before / during / after reading", () => {
    expect(PHASES.NOMINAL.era).toBe("AVANT");
    expect(PHASES.CRITICAL.era).toBe("PENDANT");
    expect(PHASES.RECOVERING.era).toBe("PENDANT");
    expect(PHASES.RESTORED.era).toBe("APRÈS");
  });

  it("lists the nine post-recovery checks in protocol order", () => {
    expect(VERIFICATION_CHECKS.map((check) => check.code)).toEqual([
      "API_READINESS",
      "AUTH_M2M_TOKEN",
      "SYNTHETIC_BALANCES_READ",
      "SYNTHETIC_TX_EXECUTE",
      "IDEMPOTENCY_REPLAY",
      "TX_READ_BACK",
      "SYNTHETIC_TX_COMPENSATE",
      "DATA_INTEGRITY",
      "STABILITY_WINDOW",
    ]);
  });
});

describe("timeline layout", () => {
  const from = Date.parse("2026-10-19T08:00:00Z");
  const to = Date.parse("2026-10-19T09:00:00Z");
  const timeline: Timeline = {
    segments: [
      { phase: "NOMINAL", from: "2026-10-19T07:00:00Z", to: "2026-10-19T08:30:00Z", incident_id: null },
      { phase: "CRITICAL", from: "2026-10-19T08:30:00Z", to: "2026-10-19T08:30:01Z", incident_id: "i" },
      { phase: "RECOVERING", from: "2026-10-19T08:30:01Z", to: "2026-10-19T08:45:00Z", incident_id: "i" },
      { phase: "RESTORED", from: "2026-10-19T08:45:00Z", to: null, incident_id: "i" },
    ],
    markers: [
      { at: "2026-10-19T08:30:00Z", kind: "alert.received", label: "x", incident_id: "i" },
      { at: "2026-10-19T07:59:00Z", kind: "alert.received", label: "outside", incident_id: null },
    ],
  };

  it("clips segments to the range, separates them and keeps tiny phases visible", () => {
    const { segments, markers } = layoutTimeline(timeline, { from, to }, 600);
    expect(segments.map((segment) => segment.phase)).toEqual(["NOMINAL", "CRITICAL", "RECOVERING", "RESTORED"]);
    expect(segments[0]!.x).toBe(0);
    expect(segments[0]!.width).toBeCloseTo(300 - SEGMENT_GAP);
    expect(segments[1]!.width).toBe(2); // une seconde de CRITICAL reste visible
    expect(segments[3]!.x + segments[3]!.width).toBeCloseTo(600); // le dernier segment touche « maintenant »
    expect(markers).toHaveLength(1);
    expect(markers[0]!.x).toBeCloseTo(300);
  });

  it("produces round time ticks", () => {
    const ticks = timeTicks({ from, to });
    expect(ticks.length).toBeGreaterThanOrEqual(4);
    expect(ticks.length).toBeLessThanOrEqual(7);
    expect(ticks.every((tick) => tick % 60_000 === 0)).toBe(true);
  });
});
