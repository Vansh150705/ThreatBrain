import http from "./client";

export interface TimeStat {
  count: number;
  median_minutes: number | null;
  mean_minutes: number | null;
}

export interface DailyPoint {
  date: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface SocMetrics {
  window_days: number;
  truncated: boolean;
  totals: {
    threats: number;
    raw_events_folded: number;
    duplicates_suppressed: number;
    incidents_created: number;
    open_incidents: number;
    unassigned_open_incidents: number;
    critical_open_incidents: number;
  };
  severity: Record<"critical" | "high" | "medium" | "low" | "info", number>;
  daily: DailyPoint[];
  mttd: TimeStat;
  mtta: TimeStat;
  mttc: TimeStat;
  mttr: TimeStat;
  top_source_ips: Array<{ ip: string; threats: number }>;
  top_techniques: Array<{ technique: string; threats: number }>;
  tactics: Array<{ tactic: string; threats: number }>;
  agents: Array<{
    agent_key: string;
    runs: number;
    failed: number;
    success_rate: number;
    avg_latency_ms: number | null;
    tokens: number;
  }>;
  approvals: Record<"pending" | "approved" | "rejected" | "executed" | "failed", number>;
}

export async function getSocMetrics(days = 7): Promise<SocMetrics> {
  const { data } = await http.get<SocMetrics>("/stats/soc", { params: { days } });
  return data;
}
