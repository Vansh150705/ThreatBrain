import http from "./client";

export interface ApprovalItem {
  id: string;
  incident_id: string | null;
  incident_short_id: string | null;
  incident_title: string | null;
  playbook_name: string;
  action_type: string;
  target: string;
  priority: number;
  rationale: string | null;
  status: "pending" | "approved" | "rejected";
  requested_by: string | null;
  decided_by_name: string | null;
  decision_note: string | null;
  decided_at: string | null;
  created_at: string;
}

export interface ApprovalListResponse {
  items: ApprovalItem[];
  total: number;
}

// List the org's playbook approval queue
export async function listApprovals(status?: string): Promise<ApprovalListResponse> {
  const { data } = await http.get<ApprovalListResponse>("/playbooks/approvals", {
    params: status ? { status } : undefined,
  });
  return data;
}

// Approve or reject a pending recommendation (admin/owner only)
export async function decideApproval(
  id: string,
  decision: "approved" | "rejected",
  note?: string
): Promise<ApprovalItem> {
  const { data } = await http.post<ApprovalItem>(`/playbooks/approvals/${id}/decision`, {
    decision,
    note,
  });
  return data;
}
