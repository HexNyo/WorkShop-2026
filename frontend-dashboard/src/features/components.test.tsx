import { fireEvent, render, screen } from "@testing-library/react";

import { ApiError } from "../api/http";
import type { IncidentDetail, Transaction } from "../api/types";
import { explainAssistantError } from "./assistant/AssistantPage";
import { applyTransactionEvent } from "./payments/PaymentsPage";
import { PhaseBanner } from "./supervision/PhaseBanner";
import { VerificationChecklist } from "./supervision/VerificationChecklist";

describe("PhaseBanner", () => {
  it("highlights the current era with text, not color alone", () => {
    render(<PhaseBanner phase="RECOVERING" since={new Date().toISOString()} reason="automatic remediation remediating" />);
    expect(screen.getByText("Remédiation automatique en cours")).toBeInTheDocument();
    const current = screen.getByText("PENDANT").closest("[aria-current]");
    expect(current).toHaveAttribute("aria-current", "step");
    expect(screen.getByText(/automatic remediation/)).toBeInTheDocument();
  });
});

describe("VerificationChecklist", () => {
  it("shows passed checks, the failing one, and skips the rest", () => {
    const detail = {
      verifications: [
        {
          id: "r",
          trigger_source: "REMEDIATION",
          status: "FAILED",
          failed_check: "SYNTHETIC_TX_EXECUTE",
          started_at: new Date().toISOString(),
          finished_at: new Date().toISOString(),
          synthetic_transaction_ids: [],
          checks: [
            { seq: 1, code: "API_READINESS", passed: true, latency_ms: 12, detail: {} },
            { seq: 2, code: "AUTH_M2M_TOKEN", passed: true, latency_ms: 30, detail: {} },
            { seq: 3, code: "SYNTHETIC_BALANCES_READ", passed: true, latency_ms: 8, detail: {} },
            { seq: 4, code: "SYNTHETIC_TX_EXECUTE", passed: false, latency_ms: 40, detail: {} },
          ],
        },
      ],
    } as unknown as IncidentDetail;
    render(<VerificationChecklist detail={detail} />);
    expect(screen.getAllByText("OK")).toHaveLength(3);
    expect(screen.getByText("Échec")).toBeInTheDocument();
    expect(screen.getAllByText("Non exécuté")).toHaveLength(5);
    expect(screen.getByText(/Échec : SYNTHETIC_TX_EXECUTE/)).toBeInTheDocument();
  });
});

describe("live transaction updates", () => {
  const base: Transaction = {
    id: "t1",
    status: "PENDING",
    debit_account: { id: "a", account_number: "RA-1000-0001" },
    credit_account: { id: "b", account_number: "RA-1000-0003" },
    amount: { value: "1.00", currency: "EUR", minor: 100 },
    description: null,
    is_synthetic: false,
    failure: null,
    idempotency_key: "k",
    created_at: "2026-10-19T08:00:00Z",
    validated_at: null,
    executed_at: null,
  };

  it("updates a known transaction in place and prepends unknown ones", () => {
    const event = {
      id: "t1",
      status: "EXECUTED" as const,
      debit_account_number: "RA-1000-0001",
      credit_account_number: "RA-1000-0003",
      amount: base.amount,
      failure: null,
      is_synthetic: false,
      updated_at: "2026-10-19T08:00:01Z",
    };
    const updated = applyTransactionEvent([base], event);
    expect(updated).toHaveLength(1);
    expect(updated[0]!.status).toBe("EXECUTED");
    const prepended = applyTransactionEvent([base], { ...event, id: "t2" });
    expect(prepended.map((tx) => tx.id)).toEqual(["t2", "t1"]);
  });
});

describe("assistant degradation", () => {
  it("explains an absent RAG agent without alarming the operator", () => {
    const message = explainAssistantError(new ApiError({ status: 503, code: "ASSISTANT_UNAVAILABLE", title: "x" }));
    expect(message).toMatch(/indisponible/);
    expect(message).toMatch(/ne sont pas affectées/);
    expect(explainAssistantError(new ApiError({ status: 403, code: "FORBIDDEN", title: "x" }))).toMatch(/noc.viewer/);
  });
});

describe("AssistantPage", () => {
  it("shows an inline message instead of crashing when the agent is unavailable", async () => {
    Element.prototype.scrollIntoView = vi.fn(() => Promise.resolve()) as never; // comme Chrome récent (absent de jsdom)
    const { AssistantPage } = await import("./assistant/AssistantPage");
    const problem = { status: 503, code: "ASSISTANT_UNAVAILABLE", title: "Assistant unavailable", detail: "The documentary agent is not reachable" };
    vi.stubGlobal("fetch", (input: string) =>
      Promise.resolve(
        input.includes("/assistant/")
          ? new Response(JSON.stringify(problem), { status: 503, headers: { "content-type": "application/problem+json" } })
          : new Response(JSON.stringify({ items: [], next_cursor: null }), { status: 200 }),
      ),
    );
    render(<AssistantPage />);
    fireEvent.change(screen.getByLabelText("Question"), { target: { value: "test" } });
    fireEvent.click(screen.getByRole("button", { name: "Envoyer" }));
    expect(await screen.findByText(/agent documentaire est indisponible/)).toBeInTheDocument();
    vi.unstubAllGlobals();
  });
});
