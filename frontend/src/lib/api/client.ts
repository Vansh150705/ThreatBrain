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

// Request interceptor — inject JWT on every call
http.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = getToken();
  if (token) {
    config.headers.set("Authorization", `Bearer ${token}`);
  }
  return config;
});

// Response interceptor — normalize errors into our custom classes
http.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (!error.response) {
      // Network error — backend down, CORS, timeout
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
    const message =
      (body.message as string) ||
      (body.detail as string) ||
      `Request failed with status ${status}`;
    const code = body.error as string | undefined;

    if (status === 401) {
      clearToken();
      return Promise.reject(new AuthError(message));
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