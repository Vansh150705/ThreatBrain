// Common API response shapes

export interface Pagination {
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  pagination: Pagination;
}

export interface ListResponse<T> {
  items: T[];
  total: number;
}

// Agent shapes
export interface Agent {
  id: string;
  agent_key: string;
  name: string;
  description: string | null;
  status: string;
  enabled: boolean;
  model: string | null;
  temperature: number | null;
  max_tokens: number | null;
  total_runs: number;
  successful_runs: number;
  failed_runs: number;
  avg_latency_ms: number | null;
  last_run_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AgentRunSummary {
  id: string;
  agent_key: string;
  trigger_type: string;
  trigger_id: string | null;
  status: string;
  error_message: string | null;
  model: string | null;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  latency_ms: number | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface AgentRunDetail extends AgentRunSummary {
  input: Record<string, unknown>;
  output: Record<string, unknown>;
  reasoning: string | null;
}

// Orchestrator shapes
export interface TriageEventPayload {
  title: string;
  description?: string;
  source?: string;
  event_type?: string;
  source_ip?: string;
  destination_ip?: string;
  destination_port?: number;
  username?: string;
  asset_name?: string;
  asset_type?: string;
  asset_environment?: string;
  asset_criticality?: string;
}

export interface OrchestratorStage {
  status: "ok" | "failed" | "skipped";
  run_id?: string;
  verdict?: Record<string, unknown>;
  latency_ms?: number;
  tokens?: number;
  error?: string;
  reason?: string;
}

export interface OrchestratorSummary {
  stages_run: number;
  stages_succeeded: number;
  stages_failed: number;
  stages_skipped: number;
  incident_short_id: string | null;
  promoted_threat_id: string | null;
}

export interface OrchestratorResponse {
  stages: Record<string, OrchestratorStage>;
  summary: OrchestratorSummary;
}