import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import BehaviorPage from "@/pages/BehaviorPage";
import { setRole } from "./helpers";

const m = {
  getStatus: vi.fn(), listAnomalies: vi.fn(), getSettings: vi.fn(), setDisposition: vi.fn(), putSettings: vi.fn(), learnFromHistory: vi.fn(), getBaseline: vi.fn(),
};
vi.mock("@/lib/api", () => ({ api: { behavior: new Proxy({}, { get: (_t, k: string) => (...a: unknown[]) => (m as Record<string, (...x: unknown[]) => unknown>)[k](...a) }) } }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const status = (over = {}) => ({
  enabled: true, sensitivity: "balanced", profiles: { user: 4, host: 2 }, mature_profiles: { user: 3, host: 1 }, learning: false,
  last_24h: { anomalies: 9, alerts: 2, suppressed: 1 }, analyst_feedback: { confirmed: 3, benign: 1, precision: 0.75 }, maturity_requirements: { min_events: 40, min_days: 3 }, ...over,
});
const anomaly = {
  id: "a1", entity_type: "user", entity_id: "alice", feature: "auth.source_net", value_key: "198.51.100.0/24", score: 0.83, severity: "medium", alerted: true,
  suppressed_reason: null, disposition: "open", observed_at: "2026-04-01T03:10:00Z",
  explanation: { summary: "alice: signed in from 198.51.100.0/24 — never seen in 21 days of activity.", peer: { prevalence: 0, peers: 12, scope: "tenant" } },
};
const settings = { enabled: true, sensitivity: "balanced", params: {}, bounds: {}, effective: { alert_score: 0.7, min_families: 2 } };

describe("BehaviorPage", () => {
  beforeEach(() => {
    Object.values(m).forEach((f) => f.mockReset());
    m.getStatus.mockResolvedValue(status());
    m.listAnomalies.mockResolvedValue([anomaly]);
    m.getSettings.mockResolvedValue(settings);
  });

  it("explains each deviation, what it was compared with, and lets an analyst teach the baseline", async () => {
    setRole("analyst");
    m.setDisposition.mockResolvedValue({});
    render(<BehaviorPage />);
    expect(await screen.findByText(/never seen in 21 days/)).toBeInTheDocument();
    expect(screen.getByText(/Compared with 12 comparable entities/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /expected/i }));
    expect(m.setDisposition).toHaveBeenCalledWith("a1", "expected");
  });

  it("says plainly that nothing is flagged while baselines are still being learned", async () => {
    setRole("admin");
    m.getStatus.mockResolvedValue(status({ learning: true, mature_profiles: { user: 0, host: 0 } }));
    render(<BehaviorPage />);
    expect(await screen.findByTestId("learning-banner")).toHaveTextContent(/nothing is flagged yet/);
    await userEvent.click(screen.getByRole("button", { name: /learn from history/i }));
    expect(m.learnFromHistory).toHaveBeenCalledWith(14);
  });

  it("lets only administrators change sensitivity, and shows a viewer the status only", async () => {
    setRole("viewer");
    render(<BehaviorPage />);
    expect(await screen.findByText("Behaviour")).toBeInTheDocument();
    expect(m.listAnomalies).not.toHaveBeenCalled();
    expect(screen.queryByText("Sensitivity")).not.toBeInTheDocument();
  });

  it("changes sensitivity for an admin", async () => {
    setRole("admin");
    render(<BehaviorPage />);
    await userEvent.click(await screen.findByRole("button", { name: "high" }));
    await waitFor(() => expect(m.putSettings).toHaveBeenCalledWith({ sensitivity: "high" }));
  });

  it("shows the baseline of an entity", async () => {
    setRole("analyst");
    m.getBaseline.mockResolvedValue({ entity: { type: "user", id: "alice" }, mature: true, events: 72, active_days: 12, first_seen: null, last_seen: null, peer_group: "g1",
      requirements: { min_events: 40, min_days: 3 }, features: { "auth.host": { top: [["ws-alice", 60], ["fs-01", 12]] } } });
    render(<BehaviorPage />);
    await userEvent.type(await screen.findByLabelText("Entity"), "alice");
    await userEvent.click(screen.getByRole("button", { name: /show baseline/i }));
    expect(await screen.findByTestId("baseline")).toHaveTextContent(/ws-alice \(60\)/);
    expect(screen.getByTestId("baseline")).toHaveTextContent(/peer group g1/);
  });
});
