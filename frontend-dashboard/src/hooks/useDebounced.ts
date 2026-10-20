import { useCallback, useEffect, useRef } from "react";

/** Regroupe des déclenchements rapprochés (ex. rafale d'événements SSE) en un seul appel. */
export function useDebouncedCallback(callback: () => void, delayMs: number): () => void {
  const saved = useRef(callback);
  const timer = useRef<number | undefined>(undefined);
  saved.current = callback;

  useEffect(() => () => window.clearTimeout(timer.current), []);

  return useCallback(() => {
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => saved.current(), delayMs);
  }, [delayMs]);
}
