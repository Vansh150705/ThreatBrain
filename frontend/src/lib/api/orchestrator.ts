import http from "./client";
import type { OrchestratorResponse, TriageEventPayload } from "./types";

export interface HandleEventRequest {
  event: TriageEventPayload;
  primary_asset_id?: string;
  promote_threats?: boolean;
  run_threat_intel?: boolean;
  run_investigation?: boolean;
  run_response?: boolean;
  run_forensics?: boolean;
  run_compliance?: boolean;
  investigation_lookback_hours?: number;
}

// Run an event through the full agent pipeline.
// The full 6-stage run can take 60-90s (the LLM tier is rate-limited per
// minute), well past the client's default 60s timeout, so extend it here to
// avoid a false "timeout" failure while the backend is still working.
const PIPELINE_TIMEOUT_MS = 180_000;

export async function handleEvent(
  request: HandleEventRequest
): Promise<OrchestratorResponse> {
  const { data } = await http.post<OrchestratorResponse>(
    "/orchestrator/handle-event",
    request,
    { timeout: PIPELINE_TIMEOUT_MS }
  );
  return data;
}