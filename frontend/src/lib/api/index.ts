import * as agents from "./agents";
import * as orchestrator from "./orchestrator";
import * as me from "./me";

export { default as http } from "./client";
export { ApiError, AuthError, ForbiddenError, NotFoundError } from "./errors";
export { getToken, setToken, clearToken } from "./client";
export type { MeResponse, OrganizationMini } from "./me";

export const api = {
  agents,
  orchestrator,
  me,
};

export type * from "./types";