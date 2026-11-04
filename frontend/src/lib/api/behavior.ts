import http from "./client";

export type Disposition = "open" | "confirmed" | "benign" | "expected";
export type Sensitivity = "low" | "balanced" | "high";

export interface BehaviorStatus {
  enabled: boolean;
  sensitivity: Sensitivity;
  profiles: { user: number; host: number };
  mature_profiles: { user: number; host: number };
  learning: boolean;
  last_24h: { anomalies: number; alerts: number; suppressed: number };
  analyst_feedback: { confirmed: number; benign: number; precision: number | null };
  maturity_requirements: { min_events: number; min_days: number };
}

export interface Anomaly {
  id: string;
  entity_type: "user" | "host";
  entity_id: string;
  feature: string;
  value_key: string;
  score: number;
  severity: string;
  alerted: boolean;
  suppressed_reason: string | null;
  disposition: Disposition;
  observed_at: string;
  explanation: { summary?: string; method?: string; peer?: { prevalence: number; peers: number; scope: string }; baseline?: Record<string, unknown> };
}

export interface BehaviorSettings {
  enabled: boolean;
  sensitivity: Sensitivity;
  params: Record<string, number>;
  bounds: Record<string, [number, number]>;
  effective: Record<string, number>;
}

export interface EntityBaseline {
  entity: { type: string; id: string };
  mature: boolean;
  events: number;
  active_days: number;
  first_seen: string | null;
  last_seen: string | null;
  peer_group: string | null;
  requirements: { min_events: number; min_days: number };
  features: Record<string, { distinct?: number; observations?: number; top?: Array<[string, number]>; hour_histogram_utc?: number[] }>;
}

export const getStatus = async () => (await http.get<BehaviorStatus>("/behavior/status")).data;
export const listAnomalies = async (params: { alerted?: boolean; disposition?: Disposition; entity_id?: string; limit?: number } = {}) =>
  (await http.get<Anomaly[]>("/behavior/anomalies", { params })).data;
export const setDisposition = async (id: string, disposition: Exclude<Disposition, "open">, note?: string) =>
  (await http.patch(`/behavior/anomalies/${id}`, { disposition, note })).data;
export const getSettings = async () => (await http.get<BehaviorSettings>("/behavior/settings")).data;
export const putSettings = async (body: { enabled?: boolean; sensitivity?: Sensitivity; params?: Record<string, number> }) =>
  (await http.put("/behavior/settings", body)).data;
export const learnFromHistory = async (days = 14) => (await http.post("/behavior/learn", null, { params: { days } })).data;
export const getBaseline = async (type: "user" | "host", id: string) =>
  (await http.get<EntityBaseline>(`/behavior/entities/${type}/${encodeURIComponent(id)}`)).data;
