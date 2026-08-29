import type { DashboardDocument } from "./types";

export async function fetchPoolDashboard(signal?: AbortSignal): Promise<DashboardDocument> {
  const response = await fetch("/api/v1/pool", {
    headers: { Accept: "application/json" },
    signal,
  });
  if (!response.ok) {
    throw new Error(`Pool status returned HTTP ${response.status}`);
  }
  return (await response.json()) as DashboardDocument;
}
