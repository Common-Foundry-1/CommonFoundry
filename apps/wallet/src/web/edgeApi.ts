// Same-origin client for the wallet edge Worker (apps/wallet-edge). Read-only explorer
// routes plus three wallet routes that the Worker forwards to the mainnet gateway.
import { NodeApiError } from "../api/errors";

export interface ExplorerSnapshot {
  network: string;
  network_short_name: string;
  network_id: string;
  consensus_fingerprint: string;
  proof_of_work: string;
  proof_profile: string;
  tip: string;
  cumulative_work: string;
  accepted_height: number;
  expected_target: string;
  utxo_count: number;
  mempool_transactions: number;
  mempool_bytes: number;
  connected_peers: number;
  recent_transactions: ExplorerTransaction[];
}

export interface ExplorerTransaction {
  txid: string;
  status: "mempool" | "confirmed" | string;
  block_id: string | null;
  block_height: number | null;
  timestamp: number | null;
  encoded_bytes: number;
  fee_burned_atoms: string | null;
}

export interface ExplorerAddressActivity {
  txid: string;
  block_id: string;
  block_height: number;
  timestamp: number;
  confirmations: number;
  kind: "coinbase" | "received" | "sent" | "self" | string;
  received_atoms: string;
  received_outputs: number;
  spent_inputs: number;
}

export interface ExplorerAddress {
  address: string;
  tip: string;
  accepted_height: number;
  confirmed_atoms: string;
  spendable_atoms: string;
  immature_atoms: string;
  utxo_count: number;
  history: ExplorerAddressActivity[];
  page_limit: number;
  has_more: boolean;
  next_cursor: string | null;
}

export interface AddressUtxo {
  txid: string;
  vout: number;
  value_atoms: string;
  spendable_height: number;
}

export interface UtxoCursor {
  snapshot: string;
  txid: string;
  vout: number;
}

export interface AddressUtxoPage {
  height: number;
  utxos: AddressUtxo[];
  has_more: boolean;
  next_cursor: UtxoCursor | null;
}

export interface TransactionOutputs {
  vout: { value_atoms: string; destination_hex: string | null }[];
}

export interface EdgeApi {
  snapshot(signal?: AbortSignal): Promise<ExplorerSnapshot>;
  address(destination: string, signal?: AbortSignal): Promise<ExplorerAddress>;
  /** Resolves null when the explorer does not know the transaction. */
  transaction(txid: string, signal?: AbortSignal): Promise<ExplorerTransaction | null>;
  utxos(destination: string, cursor: UtxoCursor | null): Promise<AddressUtxoPage>;
  transactionOutputs(txid: string, blockId: string, signal?: AbortSignal): Promise<TransactionOutputs>;
  broadcast(transactionHex: string): Promise<{ txid: string }>;
}

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      headers: { Accept: "application/json", ...(init.body ? { "Content-Type": "application/json" } : {}), ...init.headers },
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new NodeApiError("The Common Foundry network service is unreachable. Check your connection and try again.", 0, "network_unreachable", true);
  }
  const body = await response.json().catch(() => null) as { error?: unknown; message?: unknown } | null;
  if (!response.ok) {
    const code = typeof body?.error === "string" ? body.error : "request_failed";
    // The node reports prose in `error`; edge routes report a snake_case code plus `message`.
    const prose = /\s/.test(code) ? code : null;
    const message = typeof body?.message === "string"
      ? body.message
      : response.status === 429
        ? "Too many requests from this connection. Wait a minute and try again."
        : prose ?? `The network service returned ${response.status}.`;
    throw new NodeApiError(message, response.status, code, response.status === 429 || response.status >= 500);
  }
  return body as T;
}

const post = <T>(path: string, payload: unknown, signal?: AbortSignal) =>
  call<T>(path, { method: "POST", body: JSON.stringify(payload), signal });

export const edgeApi: EdgeApi = {
  snapshot: (signal) => call<ExplorerSnapshot>("/v1/explorer", { signal }),
  address: (destination, signal) => call<ExplorerAddress>(`/v1/explorer/address/${destination}`, { signal }),
  transaction: async (txid, signal) => {
    try {
      return await call<ExplorerTransaction>(`/v1/explorer/transaction/${txid}`, { signal });
    } catch (cause) {
      if (cause instanceof NodeApiError && cause.status === 404) return null;
      throw cause;
    }
  },
  utxos: (destination, cursor) => post<AddressUtxoPage>("/v1/wallet/utxos", { address: destination, cursor }),
  transactionOutputs: (txid, blockId, signal) => post<TransactionOutputs>("/v1/wallet/transaction", { txid, block_id: blockId }, signal),
  broadcast: (transactionHex) => post<{ txid: string }>("/v1/wallet/broadcast", { transaction_hex: transactionHex }),
};
