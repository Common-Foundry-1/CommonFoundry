import { demoBlock, demoSnapshot, demoTransactions } from "./demoData";
import type { ExplorerAddress, ExplorerBlockDetail, ExplorerSnapshot, ExplorerTransaction } from "./types";
import { MAINNET_NETWORK_ID, NETWORK_HEADER } from "../shared/network";
import { isExplorerAddress, isExplorerBlockDetail, isExplorerSnapshot, isExplorerTransaction } from "./validation";
import { ADDRESS_HASH, isAddressCursor } from "../shared/address";

export type ExplorerLoad = { data: ExplorerSnapshot; preview: boolean };
export const MAINNET_MODE = import.meta.env.VITE_EXPLORER_NETWORK === "mainnet";

export class ExplorerRequestError extends Error {
  constructor(message: string, readonly status: number, readonly code?: string) {
    super(message);
    this.name = "ExplorerRequestError";
  }
}

async function fetchJson<T>(path: string, validate: (value: unknown) => value is T): Promise<T> {
  const response = await fetch(path, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(12_000) });
  if (MAINNET_MODE && response.headers.get(NETWORK_HEADER) !== MAINNET_NETWORK_ID) {
    throw new Error("The explorer rejected an unidentified or different network.");
  }
  if (!response.ok) {
    const body: unknown = await response.json().catch(() => null);
    let message = `Explorer request failed (${response.status})`;
    let code: string | undefined;
    if (typeof body === "object" && body !== null && !Array.isArray(body)) {
      if ("error" in body && typeof body.error === "string" && body.error.length <= 512) message = body.error;
      if ("code" in body && typeof body.code === "string" && /^[a-z_]{1,64}$/.test(body.code)) code = body.code;
    }
    throw new ExplorerRequestError(message, response.status, code);
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

export async function loadAddress(query: string, cursor: string | null = null, preview = false): Promise<ExplorerAddress> {
  if (preview) throw new Error("Address search requires a live node; preview balances are never generated.");
  if (!ADDRESS_HASH.test(query) || (cursor !== null && !isAddressCursor(cursor))) throw new Error("Enter a valid address and pagination cursor.");
  const address = query.toLowerCase();
  const path = `/v1/explorer/address/${address}${cursor ? `/${cursor}` : ""}`;
  const data = await fetchJson(path, isExplorerAddress);
  if (data.address.toLowerCase() !== address || (cursor && data.tip.toLowerCase() !== cursor.split(".")[0].toLowerCase())) {
    throw new Error("The address response does not match the requested address or chain tip.");
  }
  return data;
}
