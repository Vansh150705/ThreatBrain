import http from "./client";
import type {
  Agent,
  AgentRunDetail,
  AgentRunSummary,
  ListResponse,
  PaginatedResponse,
} from "./types";

// List all agents for the caller's org
export async function listAgents(): Promise<ListResponse<Agent>> {
  const { data } = await http.get<ListResponse<Agent>>("/agents");
  return data;
}

// Get one agent
export async function getAgent(agentKey: string): Promise<Agent> {
  const { data } = await http.get<Agent>(`/agents/${agentKey}`);
  return data;
}

// Recent runs across ALL agents
export async function listRecentRuns(params?: {
  page?: number;
  page_size?: number;
  run_status?: string;
}): Promise<PaginatedResponse<AgentRunSummary>> {
  const { data } = await http.get<PaginatedResponse<AgentRunSummary>>(
    "/agents/recent-runs",
    { params }
  );
  return data;
}

// Runs for one specific agent
export async function listAgentRuns(
  agentKey: string,
  params?: { page?: number; page_size?: number; run_status?: string }
): Promise<PaginatedResponse<AgentRunSummary>> {
  const { data } = await http.get<PaginatedResponse<AgentRunSummary>>(
    `/agents/${agentKey}/runs`,
    { params }
  );
  return data;
}

// Full details of a single run
export async function getAgentRun(runId: string): Promise<AgentRunDetail> {
  const { data } = await http.get<AgentRunDetail>(`/agents/runs/${runId}`);
  return data;
}