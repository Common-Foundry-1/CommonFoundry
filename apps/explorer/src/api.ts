import { demoBlock, demoSnapshot, demoTransactions } from "./demoData";
import type { ExplorerBlockDetail, ExplorerSnapshot, ExplorerTransaction } from "./types";

export type ExplorerLoad = { data: ExplorerSnapshot; preview: boolean };

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`Explorer request failed (${response.status})`);
  return response.json() as Promise<T>;
}

export async function loadExplorer(): Promise<ExplorerLoad> {
  try {
    return { data: await fetchJson<ExplorerSnapshot>("/v1/explorer"), preview: false };
  } catch {
    if (!import.meta.env.DEV) throw new Error("The explorer node is unavailable.");
    return { data: demoSnapshot, preview: true };
  }
}

export async function loadBlock(query: string, preview: boolean): Promise<ExplorerBlockDetail> {
  if (!preview) return fetchJson<ExplorerBlockDetail>(`/v1/explorer/block/${encodeURIComponent(query)}`);
  const block = demoSnapshot.latest_blocks.find((item) => String(item.height) === query || item.block_id === query);
  if (!block) throw new Error("Block not found in preview data.");
  return demoBlock(block);
}

export async function loadTransaction(query: string, preview: boolean): Promise<ExplorerTransaction> {
  if (!preview) return fetchJson<ExplorerTransaction>(`/v1/explorer/transaction/${encodeURIComponent(query)}`);
  const transaction = demoTransactions.find((item) => item.txid === query);
  if (!transaction) throw new Error("Transaction not found in preview data.");
  return transaction;
}
