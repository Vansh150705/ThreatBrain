import http from "./client";

export interface OrganizationMini {
  id: string;
  name: string;
  slug: string | null;
  plan: string | null;
}

export interface MeResponse {
  id: string;
  email: string | null;
  full_name: string | null;
  role: string;
  status: string | null;
  avatar_url: string | null;
  organization: OrganizationMini;
}

// Fetch the current user's profile + organization
export async function getMe(): Promise<MeResponse> {
  const { data } = await http.get<MeResponse>("/me");
  return data;
}