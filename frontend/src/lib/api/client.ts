import axios, { AxiosError, type AxiosInstance, type InternalAxiosRequestConfig } from "axios";

import { ApiError, AuthError, ForbiddenError, NotFoundError } from "./errors";

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

// Token storage key
const TOKEN_KEY = "threatbrain.auth.token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

// Build the singleton axios instance
const http: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  timeout: 60_000,
  headers: { "Content-Type": "application/json" },
});

// attach the stored token to every request
http.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = getToken();
  if (token) {
    config.headers.set("Authorization", `Bearer ${token}`);
  }
  return config;
});

// turn failed responses into our own error classes
http.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (!error.response) {
      // no response means the backend is down, cors, or a timeout
      return Promise.reject(
        new ApiError(
          error.message || "Network error — is the backend running?",
          0,
          "network_error"
        )
      );
    }

    const { status, data } = error.response;
    const body = (data as Record<string, unknown>) || {};
    const detail = body.detail;
    // Backend errors arrive as {detail: "text"}, {detail: {error, message}},
    // {detail: [{loc, msg}]} (validation) or {error, message} (unhandled).
    const detailObj =
      detail && typeof detail === "object" && !Array.isArray(detail)
        ? (detail as Record<string, unknown>)
        : null;
    let rawMessage: unknown =
      body.message ?? detailObj?.message ?? detail ?? `Request failed with status ${status}`;
    if (Array.isArray(rawMessage)) {
      rawMessage = rawMessage
        .map((e) => {
          const item = e as { loc?: unknown[]; msg?: string };
          const field = Array.isArray(item.loc) ? item.loc.filter((p) => p !== "body").join(".") : "";
          return field ? `${field}: ${item.msg}` : item.msg;
        })
        .join("; ");
    }
    const message =
      typeof rawMessage === "string" ? rawMessage : JSON.stringify(rawMessage);
    const code = (body.error ?? detailObj?.error) as string | undefined;

    if (status === 429) {
      return Promise.reject(
        new ApiError(
          "Too many requests. Please wait a moment and try again.",
          429,
          "rate_limited",
          body
        )
      );
    }

    if (status === 401) {
      clearToken();
      return Promise.reject(
        new AuthError("Your session has expired. Please sign in again.")
      );
    }
    if (status === 403) {
      return Promise.reject(new ForbiddenError(message));
    }
    if (status === 404) {
      return Promise.reject(new NotFoundError(message));
    }
    return Promise.reject(new ApiError(message, status, code, body));
  }
);

export default http;