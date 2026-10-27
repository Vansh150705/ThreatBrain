import * as agents from "./agents";
import * as orchestrator from "./orchestrator";
import * as me from "./me";
import * as threats from "./threats";
import * as incidents from "./incidents";
import * as stats from "./stats";
import * as cases from "./cases";
import * as soc from "./soc";
import * as admin from "./admin";
import * as pipelines from "./pipelines";
import * as logAnalysis from "./logAnalysis";

export { default as http } from "./client";
export { ApiError, AuthError, ForbiddenError, NotFoundError } from "./errors";
export { getToken, setToken, clearToken } from "./client";
export { withColdStartRetry, isColdStartError } from "./retry";
export type { MeResponse, OrganizationMini } from "./me";
export type {
  ThreatListItem,
  ThreatDetail,
  ThreatListResponse,
  ListThreatsParams,
  GeoThreatPoint,
  GeoThreatSummary,
  GeoThreatResponse,
} from "./threats";
export type {
  IncidentListItem,
  IncidentDetail,
  IncidentListResponse,
  IncidentThreatItem,
  IncidentThreatsResponse,
  ListIncidentsParams,
} from "./incidents";
export type { DashboardStats } from "./stats";

export const api = {
  agents,
  orchestrator,
  me,
  threats,
  incidents,
  stats,
  cases,
  soc,
  admin,
  pipelines,
  logAnalysis,
};

export type * from "./types";