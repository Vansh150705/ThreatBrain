import http from "./client";

// Incident list item
export interface IncidentListItem {
  id: string;
  short_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "open" | "investigating" | "contained" | "resolved" | "false_positive";
  priority: "p1" | "p2" | "p3" | "p4" | "p5";
  confidence: number;
  risk_score: number | null;
  threat_count: number;
  asset_count: number;
  kill_chain: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  source_ips: string[];
  assigned_to: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  contained_at: string | null;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
}

// Full incident detail
export interface IncidentDetail extends IncidentListItem {
  description: string | null;
  affected_asset_ids: string[];
  attribution: Record<string, unknown>;
  timeline: Array<Record<string, unknown>> | Record<string, unknown>;
  playbook_runs: Array<Record<string, unknown>> | Record<string, unknown>;
  ai_summary: Record<string, unknown>;
  tags: string[];
}

// Paginated response
export interface IncidentListResponse {
  items: IncidentListItem[];
  total: number;
  page: number;
  page_size: number;
  has_more: boolean;
}

// Threats under an incident
export interface IncidentThreatItem {
  id: string;
  short_id: string;
  title: string;
  severity: string;
  status: string;
  confidence: number;
  mitre_techniques: string[];
  detected_at: string;
  created_at: string;
}

export interface IncidentThreatsResponse {
  items: IncidentThreatItem[];
  total: number;
}

// List query params
export interface ListIncidentsParams {
  page?: number;
  page_size?: number;
  severity?: string;
  status?: string;
  priority?: string;
  sort_by?: string;
  sort_dir?: "asc" | "desc";
}

// Fetch the paginated incidents list
export async function listIncidents(
  params: ListIncidentsParams = {}
): Promise<IncidentListResponse> {
  const { data } = await http.get<IncidentListResponse>("/incidents", { params });
  return data;
}

// Fetch a single incident by UUID or short_id
export async function getIncident(identifier: string): Promise<IncidentDetail> {
  const { data } = await http.get<IncidentDetail>(`/incidents/${identifier}`);
  return data;
}

// Fetch the threats grouped under an incident
export async function getIncidentThreats(
  identifier: string
): Promise<IncidentThreatsResponse> {
  const { data } = await http.get<IncidentThreatsResponse>(
    `/incidents/${identifier}/threats`
  );
  return data;
}