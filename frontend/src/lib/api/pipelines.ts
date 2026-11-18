import http from "./client";

export interface TraceEntry {
  stage: string;
  status: string;
  at: string;
  duration_ms: number;
  attempts: number;
  run_id: string | null;
  error: string | null;
  reason: string | null;
}

export interface PipelineRunItem {
  id: string;
  status: "queued" | "running" | "completed" | "failed";
  source: string | null;
  title: string | null;
  created_by: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  summary: Record<string, unknown>;
}

export interface PipelineRunDetail extends PipelineRunItem {
  event: Record<string, unknown>;
  stages: Record<string, Record<string, unknown>>;
  trace: TraceEntry[];
}

export async function listPipelineRuns(status?: string): Promise<{ items: PipelineRunItem[]; total: number }> {
  const { data } = await http.get("/orchestrator/runs", { params: status ? { status } : undefined });
  return data;
}

export async function getPipelineRun(id: string): Promise<PipelineRunDetail> {
  const { data } = await http.get<PipelineRunDetail>(`/orchestrator/runs/${id}`);
  return data;
}
