import http from "./client";

export interface AuditLogItem {
  id: string;
  short_id: string;
  actor_type: string;
  actor_name: string | null;
  actor_email: string | null;
  action: string;
  target_type: string | null;
  target_short_id: string | null;
  target_name: string | null;
  severity: string;
  status: string;
  reason: string | null;
  changes: Record<string, unknown>;
  created_at: string;
}

export interface AuditListResponse {
  items: AuditLogItem[];
  total: number;
}

export interface ListAuditParams {
  severity?: string;
  actor_type?: string;
  limit?: number;
  offset?: number;
}

// get the audit events for the current org, newest first
export async function listAuditLogs(params: ListAuditParams = {}): Promise<AuditListResponse> {
  const { data } = await http.get<AuditListResponse>("/audit", { params });
  return data;
}
