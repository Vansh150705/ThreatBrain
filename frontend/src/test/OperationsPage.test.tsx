import { describe, expect, it, vi, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { render } from "@testing-library/react";

import OperationsPage from "@/pages/OperationsPage";

const ops = vi.hoisted(() => ({ getSystemStatus: vi.fn(), listJobs: vi.fn(), requeueJob: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { ops } }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const status = (over: Record<string, unknown> = {}) => ({
  version: "0.1.0", environment: "production",
  readiness: { ready: true, warnings: [] as string[], checks: {
    database: { ok: true, latency_ms: 12 },
    schema: { ok: true, required: "026_correlation_ledger.sql", missing_tables: [], ledger_has_required: true },
    workers: { ok: true, live: 2, embedded: false, workers: [{ worker_id: "host-1-abc", role: "worker", age_seconds: 4 }] },
    queue: { ok: true, queued: 3, running: 1, dead: 0, oldest_queued_seconds: 2 } } },
  detection: { rules_version: "2026.10.2", rules: 101, correlations: 14 },
  llm: { provider: "groq", configured: true, model_override: null },
  ingest: { triage_mode: "matched", max_batch: 50, queue_max_depth: 5000, queue_max_depth_per_org: 2000 },
  retention_days: { events: 30, evidence: 365, jobs: 14, pipeline_runs: 90 },
  security: { public_signup: false, signed_ingest_available: true, oidc_configured: false, metrics_enabled: true, max_token_age_minutes: null },
  ...over,
});

beforeEach(() => Object.values(ops).forEach((f) => f.mockReset()));

describe("OperationsPage", () => {
  it("summarises platform health from the status endpoint", async () => {
    ops.getSystemStatus.mockResolvedValue(status());
    ops.listJobs.mockResolvedValue([]);
    render(<OperationsPage />);
    expect(await screen.findByText("ready")).toBeInTheDocument();
    expect(screen.getByText(/2026.10.2 \(101 rules, 14 correlations\)/)).toBeInTheDocument();
    expect(screen.getByText("12 ms")).toBeInTheDocument();
    expect(screen.getByText(/None\. Every job that exhausted/)).toBeInTheDocument();
  });

  it("makes degraded states obvious: warnings, no workers, rules-only mode, dead-lettered jobs", async () => {
    const s = status({ llm: { provider: "none", configured: false, model_override: null } });
    s.readiness.warnings = ["no live queue workers: ingested events will not be processed"];
    s.readiness.checks.workers = { ok: false, live: 0, embedded: false, workers: [] };
    s.readiness.checks.queue = { ok: false, queued: 40, running: 0, dead: 2, oldest_queued_seconds: 900 };
    ops.getSystemStatus.mockResolvedValue(s);
    ops.listJobs.mockResolvedValue([{ id: "j1", kind: "event.process", status: "dead", attempts: 5, max_attempts: 5, last_error: "boom", created_at: "2026-01-01T00:00:00Z", finished_at: null }]);
    render(<OperationsPage />);
    expect(await screen.findByText(/no live queue workers/)).toBeInTheDocument();
    expect(screen.getByText(/rules-only mode/)).toBeInTheDocument();
    expect(screen.getByText("boom")).toBeInTheDocument();
    expect(screen.getByText("900s")).toBeInTheDocument();
  });

  it("requeues a dead job and refreshes", async () => {
    ops.getSystemStatus.mockResolvedValue(status());
    ops.listJobs.mockResolvedValueOnce([{ id: "j1", kind: "event.process", status: "dead", attempts: 5, max_attempts: 5, last_error: "boom", created_at: "2026-01-01T00:00:00Z", finished_at: null }]).mockResolvedValue([]);
    ops.requeueJob.mockResolvedValue({});
    render(<OperationsPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Requeue" }));
    expect(ops.requeueJob).toHaveBeenCalledWith("j1");
    await waitFor(() => expect(screen.queryByText("boom")).not.toBeInTheDocument());
  });

  it("shows the error instead of an empty page when the caller is not allowed", async () => {
    ops.getSystemStatus.mockRejectedValue(new Error("403: forbidden"));
    ops.listJobs.mockRejectedValue(new Error("403: forbidden"));
    render(<OperationsPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("403: forbidden");
  });
});
