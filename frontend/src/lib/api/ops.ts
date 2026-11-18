import http from "./client";

export interface OnboardingStep {
  id: string;
  title: string;
  done: boolean;
  where: string;
}
export interface Onboarding {
  steps: OnboardingStep[];
  completed: number;
  total: number;
  next: string | null;
  demo_loaded: boolean;
}

export interface SystemStatus {
  version: string;
  environment: string;
  readiness: {
    ready: boolean;
    warnings: string[];
    checks: {
      database: { ok: boolean; latency_ms?: number };
      schema?: { ok: boolean; required: string; missing_tables: string[]; ledger_has_required: boolean | null };
      workers?: { ok: boolean; live: number; embedded: boolean; workers: Array<{ worker_id: string; role: string; age_seconds: number }> };
      queue?: { ok: boolean; queued: number; running: number; dead: number; oldest_queued_seconds: number };
    };
  };
  detection: { rules_version: string; rules: number; correlations: number };
  llm: { provider: string; configured: boolean; model_override: string | null };
  ingest: { triage_mode: string; max_batch: number; queue_max_depth: number; queue_max_depth_per_org: number };
  retention_days: { events: number; evidence: number; jobs: number; pipeline_runs: number };
  security: { public_signup: boolean; signed_ingest_available: boolean; oidc_configured: boolean; metrics_enabled: boolean; max_token_age_minutes: number | null };
}

export interface JobRow {
  id: string;
  kind: string;
  status: string;
  attempts: number;
  max_attempts: number;
  last_error: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface MemberRow {
  id: string;
  full_name: string | null;
  email: string | null;
  role: "viewer" | "analyst" | "admin" | "owner";
  status: "active" | "disabled";
}

export const getOnboarding = async (): Promise<Onboarding> => (await http.get<Onboarding>("/onboarding")).data;
export const loadDemo = async () => (await http.post<{ accepted: number; duplicates: number; total_events: number; note: string }>("/onboarding/demo")).data;
export const getSystemStatus = async (): Promise<SystemStatus> => (await http.get<SystemStatus>("/system/status")).data;
export const listJobs = async (status: "dead" | "queued" | "running" | "succeeded" = "dead"): Promise<JobRow[]> =>
  (await http.get<{ items: JobRow[] }>("/system/jobs", { params: { status } })).data.items;
export const requeueJob = async (id: string) => (await http.post(`/system/jobs/${id}/requeue`)).data;

export const listAllMembers = async (): Promise<MemberRow[]> =>
  (await http.get<{ items: MemberRow[] }>("/organizations/members", { params: { include_disabled: true } })).data.items;
export const updateMember = async (id: string, body: { role?: MemberRow["role"]; status?: MemberRow["status"] }): Promise<MemberRow> =>
  (await http.patch<MemberRow>(`/organizations/members/${id}`, body)).data;

export const rotateApiKey = async (id: string, graceHours = 24) =>
  (await http.post<{ id: string; name: string; api_key: string; signing_secret: string | null }>(`/api-keys/${id}/rotate`, { grace_hours: graceHours })).data;
