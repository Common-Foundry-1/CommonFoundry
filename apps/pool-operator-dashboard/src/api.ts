import type { OperatorLog, OperatorStatus } from "./types";

interface SessionDocument {
  ok: true;
  csrf_token: string;
}

interface ErrorDocument {
  ok: false;
  error: string;
}

async function readResponse<T>(response: Response): Promise<T> {
  const value = (await response.json()) as T | ErrorDocument;
  if (!response.ok || ("ok" in (value as ErrorDocument) && !(value as ErrorDocument).ok)) {
    throw new Error((value as ErrorDocument).error || `Operator API returned HTTP ${response.status}`);
  }
  return value as T;
}

export async function createOperatorSession(): Promise<string> {
  const response = await fetch("/api/v1/operator/session", {
    headers: { Accept: "application/json" },
  });
  return (await readResponse<SessionDocument>(response)).csrf_token;
}

export async function fetchOperatorStatus(signal?: AbortSignal): Promise<OperatorStatus> {
  const response = await fetch("/api/v1/operator/status", {
    headers: { Accept: "application/json" },
    signal,
  });
  return readResponse<OperatorStatus>(response);
}

export async function fetchOperatorLog(): Promise<OperatorLog> {
  const response = await fetch("/api/v1/operator/log", {
    headers: { Accept: "application/json" },
  });
  return readResponse<OperatorLog>(response);
}

async function mutate(path: string, csrfToken: string, body: object = {}): Promise<void> {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CMFD-Operator-CSRF": csrfToken,
    },
    body: JSON.stringify(body),
  });
  await readResponse<{ ok: true }>(response);
}

export function runPoolAction(action: "start" | "stop" | "restart", csrfToken: string): Promise<void> {
  return mutate(`/api/v1/operator/action/${action}`, csrfToken);
}

export function savePoolSettings(
  settings: { operator_fee_bps: number; pplns_window_shares: number },
  csrfToken: string,
): Promise<void> {
  return mutate("/api/v1/operator/settings", csrfToken, settings);
}
