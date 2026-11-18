import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

import ThreatTriagePanel from "@/components/ThreatTriagePanel";
import type { ThreatDetail } from "@/lib/api/threats";
import { setRole } from "./helpers";

vi.mock("@/lib/api", () => ({ api: { cases: { patchThreat: vi.fn() } } }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

function threat(over: Partial<ThreatDetail> = {}): ThreatDetail {
  return {
    short_id: "THR-1", status: "open", severity: "high", event_count: 1, enrichment: {}, tags: [],
    ai_analysis: {
      evidence: [
        { source: "rule:TB-AUTH-001", detail: "Brute force (matched on event_type)" },
        { source: "event", detail: "203.0.113.9 failed 40 logons", verified: true },
        { source: "llm", detail: "198.51.100.200 hosted C2 in 2021", verified: false },
      ],
      reconciliation: {
        adjusted: true, notes: ["severity raised low -> high"], llm_severity: "low", final_severity: "high",
        provenance: { severity: "rules_floor_over_model", model_severity: "low", rule_severity_floor: "high", model_used: true },
        grounding: { confidence_capped: true, unsupported_in_text: ["198.51.100.200"], dropped_attack_techniques: ["T9999"], secrets_or_prompt_text_redacted: 1 },
      },
    },
    rule_hits: [
      { rule_id: "TB-AUTH-001", name: "Brute force", severity: "high", confidence: 85, techniques: ["T1110"], matched_fields: [], kind: "rule" },
      { rule_id: "TB-DISC-001", name: "AD recon command", severity: "low", confidence: 60, techniques: ["T1087"], matched_fields: [], kind: "rule", signal: true },
      {
        rule_id: "TB-UEBA-009", name: "Unusual behaviour across 2 independent signals", severity: "medium", confidence: 70, techniques: ["T1078"], matched_fields: [],
        kind: "behavior", explanation: { signals: [{ feature: "auth.hour", explanation: { summary: "alice signed in at 03:00 UTC; only 0.6% of sign-ins happen then." } }], note: "Statistical deviation, not a signature." },
      },
    ],
    ...over,
  } as unknown as ThreatDetail;
}

describe("ThreatTriagePanel provenance", () => {
  it("separates deterministic rules from statistical and AI-generated content", () => {
    setRole("analyst");
    render(<ThreatTriagePanel threat={threat()} onUpdated={() => {}} />);
    expect(screen.getAllByText("Deterministic rule").length).toBeGreaterThan(0);
    expect(screen.getByText("Behavioural (statistical)")).toBeInTheDocument();
    expect(screen.getByText("Signal (context only)")).toBeInTheDocument();
    expect(screen.getByText(/alice signed in at 03:00 UTC/)).toBeInTheDocument();
    expect(screen.getByText("deterministic")).toBeInTheDocument();
    expect(screen.getByText("AI-generated · unverified")).toBeInTheDocument();
    expect(screen.getAllByText("AI-generated").length).toBe(1);
  });

  it("says who decided the severity and what the platform refused to trust", () => {
    setRole("analyst");
    render(<ThreatTriagePanel threat={threat()} onUpdated={() => {}} />);
    expect(screen.getByTestId("provenance")).toHaveTextContent(/decided by a deterministic rule, which overrode a lower AI rating \(the model said low\)/);
    const warn = screen.getByTestId("grounding-warning");
    expect(warn).toHaveTextContent("198.51.100.200");
    expect(warn).toHaveTextContent("T9999");
    expect(warn).toHaveTextContent(/redacted/);
  });

  it("shows nothing alarming for a grounded, model-agreeing verdict", () => {
    setRole("analyst");
    const t = threat({ ai_analysis: { evidence: [{ source: "event", detail: "root failed logons", verified: null }], reconciliation: { final_severity: "high", provenance: { severity: "model", model_severity: "high", model_used: true }, grounding: { confidence_capped: false } } } });
    render(<ThreatTriagePanel threat={t} onUpdated={() => {}} />);
    expect(screen.queryByTestId("grounding-warning")).not.toBeInTheDocument();
    expect(screen.getByTestId("provenance")).toHaveTextContent(/decided by the AI model/);
  });
});
