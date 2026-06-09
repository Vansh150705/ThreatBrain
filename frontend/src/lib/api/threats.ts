import http from "./client";

// Threat list item
export interface ThreatListItem {
  id: string;
  short_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "open" | "investigating" | "resolved" | "false_positive" | "contained";
  confidence: number;
  risk_score: number | null;
  mitre_tactics: string[];
  mitre_techniques: string[];
  source_ips: string[];
  target_ips: string[];
  affected_users: string[];
  assigned_to: string | null;
  detected_at: string;
  created_at: string;
  updated_at: string;
}

// Full threat detail
export interface ThreatDetail extends ThreatListItem {
  description: string | null;
  attack_chain: string[];
  iocs: Record<string, unknown>;
  enrichment: Record<string, unknown>;
  ai_analysis: Record<string, unknown>;
  tags: string[];
  primary_asset_id: string | null;
  incident_id: string | null;
  resolved_at: string | null;
}

// Paginated response
export interface ThreatListResponse {
  items: ThreatListItem[];
  total: number;
  page: number;
  page_size: number;
  has_more: boolean;
}

// List query params
export interface ListThreatsParams {
  page?: number;
  page_size?: number;
  severity?: string;
  status?: string;
  sort_by?: string;
  sort_dir?: "asc" | "desc";
}

// Fetch the paginated threats list
export async function listThreats(
  params: ListThreatsParams = {}
): Promise<ThreatListResponse> {
  const { data } = await http.get<ThreatListResponse>("/threats", { params });
  return data;
}

// Fetch a single threat by UUID or short_id
export async function getThreat(identifier: string): Promise<ThreatDetail> {
  const { data } = await http.get<ThreatDetail>(`/threats/${identifier}`);
  return data;
}

// ── Geo map types ────────────────────────────────────────────────────────────

export interface GeoThreatSummary {
  short_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  detected_at: string;
}

export interface GeoThreatPoint {
  country: string;
  country_name: string;
  city: string | null;
  latitude: number;
  longitude: number;
  threat_count: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source_ips: string[];
  recent_threats: GeoThreatSummary[];
}

export interface GeoThreatResponse {
  items: GeoThreatPoint[];
  total_countries: number;
  total_threats: number;
}

export async function getGeoThreats(): Promise<GeoThreatResponse> {
  const { data } = await http.get<GeoThreatResponse>("/threats/geo");
  return data;
}