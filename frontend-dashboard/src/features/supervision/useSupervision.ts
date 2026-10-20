/**
 * État de la console : la base de remédiation fait foi ; le flux SSE sert de
 * déclencheur (rechargements regroupés) et alimente le fil d'événements en direct.
 */
import { useCallback, useEffect, useRef, useState } from "react";

import { supervisionApi } from "../../api/endpoints";
import type { HealthHistory, IncidentDetail, IncidentSummary, Overview, StreamEnvelope, Timeline } from "../../api/types";
import { useDebouncedCallback } from "../../hooks/useDebounced";
import { useEventStream } from "../../hooks/useEventStream";
import { useSettings } from "../../lib/settings";

export const SUPERVISION_EVENTS = [
  "system.phase_changed",
  "service.health",
  "alert.received",
  "incident.opened",
  "incident.status_changed",
  "remediation.step",
  "verification.started",
  "verification.check",
  "verification.completed",
  "incident.closed",
  "incident.acknowledged",
] as const;

export const RANGES = { "15 min": 15, "1 h": 60, "6 h": 360, "24 h": 1440 } as const;
export type RangeLabel = keyof typeof RANGES;

const FEED_SIZE = 60;

export function useSupervision() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [pinned, setPinned] = useState(false);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [timeline, setTimeline] = useState<Timeline | null>(null);
  const [health, setHealth] = useState<HealthHistory | null>(null);
  const [range, setRangeState] = useState<RangeLabel>("1 h");
  const { autoRefresh } = useSettings();
  const userRange = useRef(false);
  const autoFocused = useRef<string | null>(null);
  const [feed, setFeed] = useState<StreamEnvelope[]>([]);
  const [phaseReason, setPhaseReason] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const selectedRef = useRef<string | null>(null);
  selectedRef.current = selectedId;

  const loadOverview = useCallback(async () => {
    try {
      const { data } = await supervisionApi.overview();
      setOverview(data);
      setError(null);
    } catch (failure) {
      setError(failure);
    }
  }, []);

  const loadIncidents = useCallback(async () => {
    try {
      setIncidents((await supervisionApi.incidents(20)).data.items);
    } catch (failure) {
      setError(failure);
    }
  }, []);

  const loadDetail = useCallback(async () => {
    const id = selectedRef.current;
    if (!id) {
      setDetail(null);
      return;
    }
    try {
      setDetail((await supervisionApi.incident(id)).data);
    } catch (failure) {
      setError(failure);
    }
  }, []);

  const loadTimeline = useCallback(async () => {
    const to = new Date();
    const from = new Date(to.getTime() - RANGES[range] * 60_000);
    try {
      setTimeline((await supervisionApi.timeline(from, to)).data);
    } catch (failure) {
      setError(failure);
    }
  }, [range]);

  const loadHealth = useCallback(async () => {
    try {
      setHealth((await supervisionApi.health("15m")).data);
    } catch (failure) {
      setError(failure);
    }
  }, []);

  const refreshOverview = useDebouncedCallback(() => void loadOverview(), 500);
  const refreshIncidents = useDebouncedCallback(() => void loadIncidents(), 1000);
  const refreshDetail = useDebouncedCallback(() => void loadDetail(), 300);
  const refreshTimeline = useDebouncedCallback(() => void loadTimeline(), 800);

  useEffect(() => {
    void loadOverview();
    void loadIncidents();
    void loadHealth();
  }, [loadOverview, loadIncidents, loadHealth]);

  useEffect(() => {
    void loadTimeline();
    if (!autoRefresh) return undefined; // le flux SSE reste actif : seules les recharges périodiques sont coupées
    const timer = window.setInterval(() => void loadTimeline(), 30_000);
    return () => window.clearInterval(timer);
  }, [loadTimeline, autoRefresh]);

  useEffect(() => {
    if (!autoRefresh) return undefined;
    const timer = window.setInterval(() => void loadHealth(), 15_000);
    return () => window.clearInterval(timer);
  }, [loadHealth, autoRefresh]);

  // Incident actif depuis plus de 15 min : la frise passe une fois sur 6 h, sauf choix explicite de l'opérateur.
  const active = overview?.active_incident ?? null;
  useEffect(() => {
    if (!active || userRange.current || autoFocused.current === active.id) return;
    if (Date.now() - Date.parse(active.opened_at) > 15 * 60_000 && RANGES[range] < RANGES["6 h"]) {
      autoFocused.current = active.id;
      setRangeState("6 h");
    }
  }, [active, range]);

  const setRange = useCallback((next: RangeLabel) => {
    userRange.current = true;
    setRangeState(next);
  }, []);

  /** Plus petite période qui montre le début de l'incident affiché (marge de 20 %). */
  const focusIncident = useCallback(() => {
    const opened = detail?.opened_at ?? active?.opened_at;
    if (!opened) return;
    const minutes = ((Date.now() - Date.parse(opened)) / 60_000) * 1.2;
    const labels = Object.keys(RANGES) as RangeLabel[];
    setRange(labels.find((label) => RANGES[label] >= minutes) ?? "24 h");
  }, [detail, active, setRange]);

  // Incident affiché : choix de l'opérateur, sinon l'incident actif, sinon le plus récent.
  useEffect(() => {
    if (pinned) return;
    const next = overview?.active_incident?.id ?? incidents[0]?.id ?? null;
    if (next !== selectedId) setSelectedId(next);
  }, [overview, incidents, pinned, selectedId]);

  useEffect(() => {
    void loadDetail();
  }, [selectedId, loadDetail]);

  const onEvent = useCallback(
    (event: StreamEnvelope) => {
      setFeed((current) => [event, ...current].slice(0, FEED_SIZE));
      switch (event.type) {
        case "system.phase_changed":
          setPhaseReason(String(event.payload.reason ?? ""));
          refreshOverview();
          refreshTimeline();
          break;
        case "service.health":
          setOverview((current) =>
            current
              ? {
                  ...current,
                  services: current.services.map((service) =>
                    service.name === event.payload.service
                      ? {
                          ...service,
                          status: event.payload.status as Overview["services"][number]["status"],
                          latency_ms: (event.payload.latency_ms as number | null) ?? null,
                          detail: (event.payload.detail as string | null) ?? null,
                          checked_at: event.occurred_at,
                        }
                      : service,
                  ),
                }
              : current,
          );
          break;
        case "alert.received":
        case "incident.opened":
        case "incident.closed":
          refreshOverview();
          refreshIncidents();
          refreshTimeline();
          if (!pinned && event.incident_id) setSelectedId(event.incident_id);
          break;
        default:
          refreshOverview();
          refreshIncidents();
      }
      if (event.incident_id && event.incident_id === selectedRef.current) refreshDetail();
    },
    [pinned, refreshDetail, refreshIncidents, refreshOverview, refreshTimeline],
  );

  const streamStatus = useEventStream({
    enabled: true,
    issueTicket: supervisionApi.streamTicket,
    url: supervisionApi.streamUrl,
    eventTypes: SUPERVISION_EVENTS,
    onEvent,
    onResync: () => {
      void loadOverview();
      void loadIncidents();
      void loadDetail();
      void loadTimeline();
    },
  });

  const select = useCallback((id: string | null) => {
    setPinned(id !== null);
    setSelectedId(id);
  }, []);

  return {
    overview,
    incidents,
    detail,
    selectedId,
    pinned,
    select,
    timeline,
    health,
    range,
    setRange,
    focusIncident,
    reload: () => {
      void loadOverview();
      void loadDetail();
      void loadIncidents();
    },
    feed,
    phaseReason,
    streamStatus,
    error,
  };
}
