import { ApiError } from "./errors";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// The backend runs on a free Hugging Face Space that sleeps after inactivity
// and answers 503 (or drops the connection) while it cold-starts. Both shapes
// surface as ApiError: a real 503, or a network error with status 0.
export function isColdStartError(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 503 || err.status === 0);
}

interface RetryOptions {
  // How many extra attempts after the first try.
  retries?: number;
  baseDelayMs?: number;
  // Called the first time a cold start is detected, so the UI can show a
  // "waking up" state. Receives the attempt number (1-based).
  onRetry?: (attempt: number) => void;
}

// Runs `fn`, retrying only when the failure looks like a cold start. Any other
// error (401, 404, 500, …) rejects immediately. Uses capped linear backoff so
// a sleeping Space gets enough time to boot (~2s, 4s, 6s … up to 10s).
export async function withColdStartRetry<T>(
  fn: () => Promise<T>,
  { retries = 5, baseDelayMs = 2000, onRetry }: RetryOptions = {}
): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (!isColdStartError(err) || attempt === retries) throw err;
      onRetry?.(attempt + 1);
      await sleep(Math.min(baseDelayMs * (attempt + 1), 10_000));
    }
  }
  throw lastErr;
}
