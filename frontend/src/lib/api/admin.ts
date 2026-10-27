import http from "./client";

export interface ApiKeyItem {
  id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  role: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
}

export interface ApiKeyCreated extends ApiKeyItem {
  api_key: string;
}

export interface IntegrationStatus {
  llm: boolean;
  abuseipdb: boolean;
  virustotal: boolean;
  otx: boolean;
  discord_notifications: boolean;
  public_signup: boolean;
  hunt_scheduler: boolean;
  rate_limiting: boolean;
}

export async function listApiKeys(): Promise<ApiKeyItem[]> {
  const { data } = await http.get<{ items: ApiKeyItem[] }>("/api-keys");
  return data.items;
}

export async function createApiKey(body: {
  name: string;
  scopes: Array<"ingest" | "executor">;
  expires_in_days?: number;
}): Promise<ApiKeyCreated> {
  const { data } = await http.post<ApiKeyCreated>("/api-keys", body);
  return data;
}

export async function revokeApiKey(id: string): Promise<void> {
  await http.delete(`/api-keys/${id}`);
}

export async function getIntegrations(): Promise<IntegrationStatus> {
  const { data } = await http.get<IntegrationStatus>("/system/integrations");
  return data;
}
