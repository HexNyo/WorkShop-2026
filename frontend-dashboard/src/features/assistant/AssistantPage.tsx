import { useEffect, useRef, useState, type FormEvent } from "react";

import { assistantApi, supervisionApi } from "../../api/endpoints";
import { ApiError } from "../../api/http";
import type { ChatSource, IncidentSummary } from "../../api/types";
import { Button, Card, Field, Select, cx } from "../../components/ui";
import { formatDateTime, formatTime } from "../../lib/format";

interface Message {
  id: string;
  role: "operator" | "assistant" | "system";
  text: string;
  sources?: ChatSource[];
  at: string;
}

const SUGGESTIONS = [
  "Pourquoi payment-api est-il passé en SYNTHETIC_ONLY ?",
  "Quelles sont les étapes du playbook PB-INTEGRITY-RESTORE ?",
  "Que faire si un incident est escaladé avec LEDGER_COMPROMISED ?",
  "Comment interpréter un échec du contrôle V8 DATA_INTEGRITY ?",
];

export function explainAssistantError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "Session expirée : reconnectez-vous.";
    if (error.status === 403) return "Votre rôle ne permet pas d'interroger l'assistant (noc.viewer requis).";
    if (error.status === 429) return "Trop de questions rapprochées : patientez quelques secondes.";
    if (error.isUnavailable) {
      return "L'agent documentaire est indisponible (non déployé ou injoignable). La supervision et la remédiation ne sont pas affectées.";
    }
    return error.detail ?? error.message;
  }
  return "Erreur inattendue lors de l'appel à l'assistant.";
}

export function AssistantPage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      role: "system",
      text: "Posez une question sur les runbooks, les playbooks ou un incident. Les réponses citent leurs sources documentaires.",
      at: new Date().toISOString(),
    },
  ]);
  const [draft, setDraft] = useState("");
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [incidentId, setIncidentId] = useState("");
  const [busy, setBusy] = useState(false);
  const bottom = useRef<HTMLLIElement>(null);

  useEffect(() => {
    supervisionApi
      .incidents(10)
      .then(({ data }) => setIncidents(data.items))
      .catch(() => setIncidents([]));
  }, []);
  useEffect(() => {
    // Corps en bloc : Chrome récent renvoie une Promise que React prendrait pour une fonction de nettoyage.
    bottom.current?.scrollIntoView({ block: "end" });
  }, [messages]);

  const ask = async (question: string) => {
    const text = question.trim();
    if (!text || busy) return;
    const now = new Date().toISOString();
    setMessages((current) => [...current, { id: crypto.randomUUID(), role: "operator", text, at: now }]);
    setDraft("");
    setBusy(true);
    try {
      const { data } = await assistantApi.chat(text, conversationId, incidentId ? { incident_id: incidentId } : {});
      setConversationId(data.conversation_id);
      setMessages((current) => [
        ...current,
        { id: data.message_id, role: "assistant", text: data.answer, sources: data.sources, at: data.created_at },
      ]);
    } catch (error) {
      setMessages((current) => [
        ...current,
        { id: crypto.randomUUID(), role: "system", text: explainAssistantError(error), at: new Date().toISOString() },
      ]);
    } finally {
      setBusy(false);
    }
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void ask(draft);
  };

  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Assistant opérateur</h1>
        <p className="text-xs text-muted">Agent documentaire (RAG) : runbooks, playbooks, architecture.</p>
      </div>
      <Card
        title="Conversation"
        actions={
          <Button
            variant="ghost"
            onClick={() => {
              setConversationId(null);
              setMessages((current) => current.slice(0, 1));
            }}
          >
            Nouvelle conversation
          </Button>
        }
      >
        <ol className="max-h-[55vh] space-y-3 overflow-y-auto pr-1" aria-live="polite" data-testid="chat-messages">
          {messages.map((message) => (
            <li
              key={message.id}
              data-role={message.role}
              className={cx(
                "max-w-[85%] rounded-lg px-3 py-2 text-sm",
                message.role === "operator" && "ml-auto bg-accent text-accent-ink",
                message.role === "assistant" && "border border-line bg-surface-2/60",
                message.role === "system" && "mx-auto border border-dashed border-line text-xs text-ink-2",
              )}
            >
              <p className="whitespace-pre-wrap">{message.text}</p>
              {message.sources && message.sources.length > 0 && (
                <ul className="mt-2 space-y-1 border-t border-line pt-2 text-xs">
                  {message.sources.map((source) => (
                    <li key={source.uri}>
                      <span className="font-medium">{source.title}</span>{" "}
                      <span className="font-mono text-[0.7rem] text-muted">{source.uri}</span>
                      <span className="ml-1 text-muted">· pertinence {source.score.toFixed(2)}</span>
                      <p className="text-ink-2">« {source.excerpt} »</p>
                    </li>
                  ))}
                </ul>
              )}
              <p className={cx("mt-1 text-[0.65rem]", message.role === "operator" ? "text-accent-ink/80" : "text-muted")}>
                {formatTime(message.at)}
              </p>
            </li>
          ))}
          {busy && <li className="text-xs text-muted">L'assistant rédige une réponse…</li>}
          <li ref={bottom} aria-hidden="true" />
        </ol>

        <form onSubmit={submit} className="mt-4 space-y-3">
          <div className="grid gap-3 sm:grid-cols-[1fr,16rem]">
            <Field label="Question" htmlFor="question">
              <textarea
                id="question"
                rows={2}
                maxLength={2000}
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void ask(draft);
                  }
                }}
                className="w-full rounded-md border border-line bg-surface px-2.5 py-1.5 text-sm focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/30"
              />
            </Field>
            <Field label="Contexte d'incident" htmlFor="context">
              <Select id="context" value={incidentId} onChange={(event) => setIncidentId(event.target.value)}>
                <option value="">Aucun</option>
                {incidents.map((incident) => (
                  <option key={incident.id} value={incident.id}>
                    {formatDateTime(incident.opened_at)} · {incident.category}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" variant="primary" busy={busy} disabled={!draft.trim()}>
              Envoyer
            </Button>
            {SUGGESTIONS.map((suggestion) => (
              <button
                key={suggestion}
                type="button"
                onClick={() => void ask(suggestion)}
                className="rounded-full border border-line px-2.5 py-1 text-xs text-ink-2 hover:bg-surface-2"
              >
                {suggestion}
              </button>
            ))}
          </div>
        </form>
      </Card>
    </div>
  );
}
