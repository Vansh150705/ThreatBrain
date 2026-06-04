import * as agents from "./agents";
import * as orchestrator from "./orchestrator";
import * as me from "./me";
import * as threats from "./threats";
import * as stats from "./stats";

export { default as http } from "./client";
export { ApiError, AuthError, ForbiddenError, NotFoundError } from "./errors";
export { getToken, setToken, clearToken } from "./client";
export type { MeResponse, OrganizationMini } from "./me";
export type {
  ThreatListItem,
  ThreatDetail,
  ThreatListResponse,
  ListThreatsParams,
} from "./threats";
export type { DashboardStats } from "./stats";

export const api = {
  agents,
  orchestrator,
  me,
  threats,
  stats,
};

export type * from "./types";