import type { ExplorerAddress, ExplorerAddressActivity, ExplorerBlock, ExplorerBlockDetail, ExplorerSnapshot, ExplorerTransaction } from "./types";
import { ADDRESS_PAGE_SIZE, isAddressCursor } from "../shared/address";

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
    && (value.total_supply_atoms === undefined || totalAtoms(value.total_supply_atoms))
    && Array.isArray(value.latest_blocks) && value.latest_blocks.length <= 12 && value.latest_blocks.every(isExplorerBlock)
    && Array.isArray(value.recent_transactions) && value.recent_transactions.length <= 24 && value.recent_transactions.every(isExplorerTransaction);
}

const totalAtoms = (value: unknown): value is string => typeof value === "string"
  && /^(0|[1-9][0-9]{0,38})$/.test(value) && BigInt(value) <= (1n << 128n) - 1n;

function isAddressActivity(value: unknown): value is ExplorerAddressActivity {
  return record(value) && hash(value.txid) && hash(value.block_id)
    && natural(value.block_height) && value.block_height > 0 && natural(value.timestamp)
    && natural(value.confirmations) && value.confirmations > 0
    && typeof value.kind === "string" && ["coinbase", "received", "sent", "self"].includes(value.kind)
    && totalAtoms(value.received_atoms) && natural(value.received_outputs) && natural(value.spent_inputs)
    && (value.received_outputs > 0 || value.spent_inputs > 0);
}

export function isExplorerAddress(value: unknown): value is ExplorerAddress {
  if (!record(value) || !hash(value.address) || !hash(value.tip) || !natural(value.accepted_height)
      || value.balance_scope !== "key_outputs" || value.includes_mempool !== false
      || !totalAtoms(value.confirmed_atoms) || !totalAtoms(value.spendable_atoms) || !totalAtoms(value.immature_atoms)
      || !natural(value.utxo_count) || value.page_limit !== ADDRESS_PAGE_SIZE || typeof value.has_more !== "boolean"
      || !Array.isArray(value.history) || value.history.length > ADDRESS_PAGE_SIZE || !value.history.every(isAddressActivity)) return false;
  if (BigInt(value.confirmed_atoms) !== BigInt(value.spendable_atoms) + BigInt(value.immature_atoms)) return false;
  const entries = value.history;
  const height = value.accepted_height;
  if (entries.some((entry, index) => entry.block_height > height || entry.confirmations !== height - entry.block_height + 1
      || (index > 0 && entry.block_height > entries[index - 1].block_height))) return false;
  if (new Set(entries.map((entry) => `${entry.block_id}:${entry.txid}`)).size !== entries.length) return false;
  if (!value.has_more) return value.next_cursor === null;
  if (entries.length !== ADDRESS_PAGE_SIZE || !isAddressCursor(value.next_cursor)) return false;
  const [tip, lastHeight, position] = value.next_cursor.split(".");
  const last = entries[entries.length - 1];
  return tip.toLowerCase() === value.tip.toLowerCase() && BigInt(lastHeight) === BigInt(last.block_height)
    && ((position === "0") === (last.kind === "coinbase"));
}
