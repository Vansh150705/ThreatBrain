import * as agents from "./agents";
import * as orchestrator from "./orchestrator";
import * as me from "./me";
import * as threats from "./threats";

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

export const api = {
  agents,
  orchestrator,
  me,
  threats,
};

export type * from "./types";