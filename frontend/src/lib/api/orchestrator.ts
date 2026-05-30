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

// Run an event through the full agent pipeline
export async function handleEvent(
  request: HandleEventRequest
): Promise<OrchestratorResponse> {
  const { data } = await http.post<OrchestratorResponse>(
    "/orchestrator/handle-event",
    request
  );
  return data;
}