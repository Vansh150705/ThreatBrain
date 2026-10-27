import http from "./client";

export type CaseStatus =
  | "open"
  | "investigating"
  | "contained"
  | "resolved"
  | "closed"
  | "false_positive";

export interface Member {
  id: string;
  full_name: string | null;
  email: string | null;
  role: string;
}

export interface IncidentNote {
  id: string;
  author_id: string | null;
  author_name: string | null;
  body: string;
  created_at: string;
}

export interface TimelineEntry {
  ts: string;
  kind: "threat" | "audit" | "note" | "forensics";
  severity: string;
  title: string;
  detail: string | null;
  actor: string | null;
}

export interface IncidentPatch {
  status?: CaseStatus;
  priority?: "p1" | "p2" | "p3" | "p4";
  /** a user id, or null to unassign */
  assigned_to?: string | null;
}

export async function patchIncident(identifier: string, patch: IncidentPatch) {
  const { data } = await http.patch(`/incidents/${identifier}`, patch);
  return data;
}

export async function patchThreat(
  identifier: string,
  patch: { status?: CaseStatus; assigned_to?: string | null }
) {
  const { data } = await http.patch(`/threats/${identifier}`, patch);
  return data;
}

export async function listNotes(identifier: string): Promise<IncidentNote[]> {
  const { data } = await http.get<{ items: IncidentNote[] }>(`/incidents/${identifier}/notes`);
  return data.items;
}

export async function addNote(identifier: string, body: string): Promise<IncidentNote> {
  const { data } = await http.post<IncidentNote>(`/incidents/${identifier}/notes`, { body });
  return data;
}

export async function getTimeline(identifier: string): Promise<TimelineEntry[]> {
  const { data } = await http.get<{ items: TimelineEntry[] }>(`/incidents/${identifier}/timeline`);
  return data.items;
}

export async function listMembers(): Promise<Member[]> {
  const { data } = await http.get<{ items: Member[] }>("/organizations/members");
  return data.items;
}
