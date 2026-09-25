import { demoBlock, demoSnapshot, demoTransactions } from "./demoData";
import type { ExplorerBlockDetail, ExplorerSnapshot, ExplorerTransaction } from "./types";
import { MAINNET_NETWORK_ID, NETWORK_HEADER } from "../shared/network";
import { isExplorerBlockDetail, isExplorerSnapshot, isExplorerTransaction } from "./validation";

export type ExplorerLoad = { data: ExplorerSnapshot; preview: boolean };
export const MAINNET_MODE = import.meta.env.VITE_EXPLORER_NETWORK === "mainnet";

async function fetchJson<T>(path: string, validate: (value: unknown) => value is T): Promise<T> {
  const response = await fetch(path, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(12_000) });
  if (!response.ok) throw new Error(`Explorer request failed (${response.status})`);
  if (MAINNET_MODE && response.headers.get(NETWORK_HEADER) !== MAINNET_NETWORK_ID) {
    throw new Error("The explorer rejected an unidentified or different network.");
  }
  const data: unknown = await response.json();
  if (!validate(data)) throw new Error("The explorer node returned invalid data.");
  return data;
}

export async function loadExplorer(): Promise<ExplorerLoad> {
  try {
    const data = await fetchJson("/v1/explorer", isExplorerSnapshot);
    if (MAINNET_MODE && data.network_id !== MAINNET_NETWORK_ID) {
      throw new Error("The snapshot belongs to a different network.");
    }
    return { data, preview: false };
  } catch (error) {
    if (MAINNET_MODE) throw new Error("No verified mainnet connection is available. " + (error instanceof Error ? error.message : "Please retry shortly."));
    if (!import.meta.env.DEV) throw new Error("The explorer node is unavailable.");
    return { data: demoSnapshot, preview: true };
  }
}

export async function loadBlock(query: string, preview: boolean): Promise<ExplorerBlockDetail> {
  if (!preview) return fetchJson(`/v1/explorer/block/${encodeURIComponent(query)}`, isExplorerBlockDetail);
  if (MAINNET_MODE) throw new Error("Mainnet never uses preview blocks.");
  const block = demoSnapshot.latest_blocks.find((item) => String(item.height) === query || item.block_id === query);
  if (!block) throw new Error("Block not found in preview data.");
  return demoBlock(block);
}

export async function loadTransaction(query: string, preview: boolean): Promise<ExplorerTransaction> {
  if (!preview) return fetchJson(`/v1/explorer/transaction/${encodeURIComponent(query)}`, isExplorerTransaction);
  if (MAINNET_MODE) throw new Error("Mainnet never uses preview transactions.");
  const transaction = demoTransactions.find((item) => item.txid === query);
  if (!transaction) throw new Error("Transaction not found in preview data.");
  return transaction;
}
