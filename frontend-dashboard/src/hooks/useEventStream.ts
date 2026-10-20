/**
 * Abonnement SSE robuste : ticket à usage unique -> EventSource ; à chaque coupure
 * (erreur réseau, jeton expiré, révocation, fenêtre de reprise dépassée), nouveau
 * ticket + nouvelle connexion avec backoff, puis `onResync` pour recharger l'état.
 */
import { useEffect, useRef, useState } from "react";

import type { StreamEnvelope } from "../api/types";

export type StreamStatus = "idle" | "connecting" | "open" | "reconnecting";

interface Options {
  enabled: boolean;
  issueTicket: () => Promise<{ data: { ticket: string } }>;
  url: string;
  eventTypes: readonly string[];
  onEvent: (event: StreamEnvelope) => void;
  onResync?: () => void;
}

const CONTROL_EVENTS = ["stream.expired", "stream.revoked", "stream.reset"] as const;

export function useEventStream({ enabled, issueTicket, url, eventTypes, onEvent, onResync }: Options): StreamStatus {
  const [status, setStatus] = useState<StreamStatus>("idle");
  const handlers = useRef({ onEvent, onResync, issueTicket });
  handlers.current = { onEvent, onResync, issueTicket };
  const typesKey = eventTypes.join(",");

  useEffect(() => {
    if (!enabled) {
      setStatus("idle");
      return undefined;
    }
    let source: EventSource | null = null;
    let timer: number | undefined;
    let attempt = 0;
    let cancelled = false;
    const types = typesKey.split(",");

    const schedule = () => {
      if (cancelled) return;
      source?.close();
      source = null;
      setStatus("reconnecting");
      const delay = Math.min(1000 * 2 ** attempt, 15_000);
      attempt += 1;
      timer = window.setTimeout(() => void connect(), delay);
    };

    const connect = async () => {
      setStatus(attempt === 0 ? "connecting" : "reconnecting");
      let ticket: string;
      try {
        ticket = (await handlers.current.issueTicket()).data.ticket;
      } catch {
        schedule();
        return;
      }
      if (cancelled) return;
      const opened = new EventSource(`${url}?ticket=${encodeURIComponent(ticket)}`);
      source = opened;
      opened.onopen = () => {
        if (attempt > 0) handlers.current.onResync?.();
        attempt = 0;
        setStatus("open");
      };
      opened.onerror = () => schedule();
      for (const type of types) {
        opened.addEventListener(type, (message) => {
          try {
            handlers.current.onEvent(JSON.parse((message as MessageEvent<string>).data) as StreamEnvelope);
          } catch {
            // événement mal formé : ignoré
          }
        });
      }
      for (const type of CONTROL_EVENTS) {
        opened.addEventListener(type, () => {
          attempt = Math.max(attempt, 1); // impose un resync à la reconnexion
          schedule();
        });
      }
    };

    void connect();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      source?.close();
    };
  }, [enabled, url, typesKey]);

  return status;
}
