import type { ExplorerBlock, ExplorerBlockDetail, ExplorerSnapshot, ExplorerTransaction } from "./types";

const HASH = /^[0-9a-f]{64}$/i;
const ATOMS = /^(0|[1-9][0-9]{0,19})$/;
const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const natural = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const hash = (value: unknown): value is string => typeof value === "string" && HASH.test(value);
const atoms = (value: unknown): value is string => typeof value === "string" && ATOMS.test(value);
const nullableHash = (value: unknown) => value === null || hash(value);
const nullableNatural = (value: unknown) => value === null || natural(value);

export function isExplorerTransaction(value: unknown): value is ExplorerTransaction {
  return record(value) && hash(value.txid) && nullableHash(value.block_id)
    && nullableNatural(value.block_height) && nullableNatural(value.timestamp)
    && natural(value.inputs) && natural(value.outputs) && natural(value.encoded_bytes)
    && atoms(value.output_atoms) && (value.fee_burned_atoms === null || atoms(value.fee_burned_atoms))
    && (value.status === "confirmed" || value.status === "mempool");
}

export function isExplorerBlock(value: unknown): value is ExplorerBlock {
  return record(value)
    && ["block_id", "previous_block", "transaction_root", "target", "work_digest"].every((key) => hash(value[key]))
    && ["height", "timestamp", "transactions", "encoded_bytes", "confirmations"].every((key) => natural(value[key]))
    && atoms(value.coinbase_atoms) && atoms(value.nonce);
}

export function isExplorerBlockDetail(value: unknown): value is ExplorerBlockDetail {
  if (!record(value) || !natural(value.coinbase_outputs) || !Array.isArray(value.transactions_detail)) return false;
  const transactions = value.transactions_detail;
  return isExplorerBlock(value) && transactions.length === value.transactions
    && transactions.every(isExplorerTransaction);
}

export function isExplorerSnapshot(value: unknown): value is ExplorerSnapshot {
  if (!record(value)) return false;
  return ["network", "network_short_name", "proof_profile", "proof_of_work", "cumulative_work"]
    .every((key) => typeof value[key] === "string" && value[key].length > 0 && value[key].length <= 256)
    && ["network_id", "consensus_fingerprint", "tip", "expected_target"].every((key) => hash(value[key]))
    && ["accepted_height", "utxo_count", "mempool_transactions", "mempool_bytes", "connected_peers"].every((key) => natural(value[key]))
    && Array.isArray(value.latest_blocks) && value.latest_blocks.length <= 12 && value.latest_blocks.every(isExplorerBlock)
    && Array.isArray(value.recent_transactions) && value.recent_transactions.length <= 24 && value.recent_transactions.every(isExplorerTransaction);
}
