import http from "./client";

export interface DashboardStats {
  open_incidents: number;
  total_threats: number;
  open_threats: number;
  critical_threats: number;
}

// Fetch dashboard stat counts for the current org
export async function getDashboardStats(): Promise<DashboardStats> {
  const { data } = await http.get<DashboardStats>("/stats/dashboard");
  return data;
}