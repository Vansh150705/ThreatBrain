import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import DetectionPage from "@/pages/DetectionPage";
import { renderWithRouter, setRole } from "./helpers";

const api = vi.hoisted(() => ({
  listRules: vi.fn(),
  getCoverage: vi.fn(),
  setBuiltinOverride: vi.fn(),
  validateRule: vi.fn(),
  createRule: vi.fn(),
  setRuleStatus: vi.fn(),
  deleteRule: vi.fn(),
  convertSigma: vi.fn(),
  importSigma: vi.fn(),
  proposeTuning: vi.fn(),
}));
vi.mock("@/lib/api", () => ({ api: { detection: api } }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const builtin = (id: string, name: string, extra = {}) => ({
  id, name, severity: "high", confidence: 80, tactics: ["TA0002"], techniques: ["T1059"], tags: ["x"], tuning: "", tests: 2,
  enabled: true, severity_override: null, override_reason: null, ...extra,
});

beforeEach(() => {
  Object.values(api).forEach((f) => f.mockReset());
  api.listRules.mockResolvedValue({
    version: "2026.10.2",
    builtin: [builtin("TB-EXEC-001", "Encoded PowerShell"), builtin("TB-WEB-003", "SQL injection", { techniques: ["T1190"], severity: "medium" }),
              builtin("TB-DISC-001", "AD recon", { enabled: false, override_reason: "admins do this daily" })],
    custom: [{ id: "c1", rule_key: "corp-x", name: "Corp rule", severity: "low", confidence: 60, techniques: [], tactics: [], status: "draft", origin: "native", version: 1, match: {}, tests: [] }],
  });
  api.getCoverage.mockResolvedValue({ rule_version: "2026.10.2", techniques: {}, tactics: [
    { id: "TA0002", name: "Execution", techniques_in_catalog: 10, covered: 8, uncovered: ["T1047", "T1559"] },
    { id: "TA0043", name: "Reconnaissance", techniques_in_catalog: 4, covered: 1, uncovered: ["T1592"] } ] });
});
afterEach(() => vi.restoreAllMocks());

describe("DetectionPage", () => {
  it("shows the rules with their rule-set version and filters by search text, technique and state", async () => {
    setRole("admin");
    renderWithRouter(<DetectionPage />);
    expect(await screen.findByText("Encoded PowerShell")).toBeInTheDocument();
    expect(screen.getByText(/rule set 2026.10.2/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Search rules"), "T1190");
    expect(screen.queryByText("Encoded PowerShell")).not.toBeInTheDocument();
    expect(screen.getByText("SQL injection")).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText("Search rules"));
    await userEvent.click(screen.getByLabelText("Disabled only"));
    expect(screen.getByText("AD recon")).toBeInTheDocument();
    expect(screen.queryByText("SQL injection")).not.toBeInTheDocument();
    expect(screen.getByText(/Disabled because: admins do this daily/)).toBeInTheDocument();
  });

  it("requires a reason to disable a rule and sends it with the override", async () => {
    setRole("admin");
    api.setBuiltinOverride.mockResolvedValue({});
    const prompt = vi.spyOn(window, "prompt");
    renderWithRouter(<DetectionPage />);
    await screen.findByText("Encoded PowerShell");
    const row = screen.getByText("Encoded PowerShell").closest("tr")!;

    prompt.mockReturnValueOnce("   ");                      // blank reason: nothing happens
    await userEvent.click(within(row).getByRole("button", { name: "Disable" }));
    expect(api.setBuiltinOverride).not.toHaveBeenCalled();

    prompt.mockReturnValueOnce("noisy in our estate");
    await userEvent.click(within(row).getByRole("button", { name: "Disable" }));
    await waitFor(() => expect(api.setBuiltinOverride).toHaveBeenCalledWith("TB-EXEC-001", { enabled: false, severity_override: null, reason: "noisy in our estate" }));
  });

  it("hides every editing control from non-admins", async () => {
    setRole("analyst");
    renderWithRouter(<DetectionPage />);
    await screen.findByText("Encoded PowerShell");
    expect(screen.queryByRole("button", { name: "Disable" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Propose tuning/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /Custom rules/ }));
    expect(screen.queryByLabelText("Rule definition")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Enable" })).not.toBeInTheDocument();
  });

  it("explains that coverage counts rules, not detection quality, and shows gaps", async () => {
    setRole("analyst");
    renderWithRouter(<DetectionPage />);
    await userEvent.click(await screen.findByRole("tab", { name: "Coverage" }));
    expect(await screen.findByText(/counts techniques that have a rule, not how well/)).toBeInTheDocument();
    expect(screen.getByLabelText("Execution: 8 of 10 techniques covered")).toBeInTheDocument();
    expect(screen.getByText(/T1047 T1559/)).toBeInTheDocument();
  });

  it("validates a custom rule and shows per-test results without saving", async () => {
    setRole("admin");
    api.validateRule.mockResolvedValue({ valid: true, tactics: ["TA0011"], tests_passed: false, has_positive_and_negative: true, attack_warnings: [],
      tests: [{ name: "tool runs", expected: true, matched: true, passed: true }, { name: "browser", expected: false, matched: true, passed: false }] });
    renderWithRouter(<DetectionPage />);
    await userEvent.click(await screen.findByRole("tab", { name: /Custom rules/ }));
    await userEvent.click(screen.getByRole("button", { name: /Validate & run tests/ }));
    expect(await screen.findByText(/not ready to enable/)).toBeInTheDocument();
    expect(screen.getByText(/✗ browser: expected no match, got match/)).toBeInTheDocument();
    expect(api.createRule).not.toHaveBeenCalled();
  });

  it("reports invalid JSON locally and server-side rule errors verbatim", async () => {
    setRole("admin");
    renderWithRouter(<DetectionPage />);
    await userEvent.click(await screen.findByRole("tab", { name: /Custom rules/ }));
    const box = screen.getByLabelText("Rule definition");
    await userEvent.clear(box);
    await userEvent.type(box, "not json");
    await userEvent.click(screen.getByRole("button", { name: /Validate & run tests/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Not valid JSON/);
    expect(api.validateRule).not.toHaveBeenCalled();
  });

  it("surfaces the agent's verified tuning proposal as a draft, and a rejection with its reasons", async () => {
    setRole("admin");
    api.proposeTuning.mockResolvedValueOnce({ run_id: "r", recommendation: "tune", assessment: "ansible does this", rationale: "exclude it", changes: [], stored_rule_id: "new", evidence: {},
      verification: { accepted: true, reasons: [], measurements: { fp_matched_before: 4, fp_matched_after: 0, tp_matched_before: 1, tp_matched_after: 1 } } });
    renderWithRouter(<DetectionPage />);
    await userEvent.click(await screen.findByLabelText("Propose tuning for TB-EXEC-001"));
    expect(await screen.findByText(/false positives 4→0/)).toBeInTheDocument();
    expect(screen.getByText(/Saved as a/)).toHaveTextContent(/draft/);
    api.proposeTuning.mockResolvedValueOnce({ run_id: "r", recommendation: "tune", assessment: "x", rationale: "y", changes: [], stored_rule_id: null, evidence: {},
      verification: { accepted: false, reasons: ["loses genuine detections (1 -> 0 of 1 samples)"], measurements: {} } });
    await userEvent.click(screen.getByLabelText("Propose tuning for TB-WEB-003"));
    expect(await screen.findByText(/Proposal rejected by verification: loses genuine detections/)).toBeInTheDocument();
  });

  it("previews a Sigma conversion with its warnings and refuses unsupported rules with the server's reason", async () => {
    setRole("admin");
    api.convertSigma.mockResolvedValueOnce({ rule: { rule_key: "sigma-x", name: "X", severity: "high", match: { field: "command_line", contains: "evil" } }, warnings: ["logsource is not enforced"] });
    renderWithRouter(<DetectionPage />);
    await userEvent.click(await screen.findByRole("tab", { name: "Sigma import" }));
    await userEvent.type(screen.getByLabelText("Sigma rule YAML"), "title: Xyz detection: none");
    await userEvent.click(screen.getByRole("button", { name: "Preview conversion" }));
    expect(await screen.findByText(/logsource is not enforced/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import as draft" })).toBeEnabled();
    api.convertSigma.mockRejectedValueOnce(new Error("unsupported: aggregation/'near' conditions"));
    await userEvent.click(screen.getByRole("button", { name: "Preview conversion" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/unsupported: aggregation/);
    expect(screen.getByRole("button", { name: "Import as draft" })).toBeDisabled();
  });
});
