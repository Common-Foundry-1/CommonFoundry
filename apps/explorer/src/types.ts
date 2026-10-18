export type ExplorerTransaction = {
  txid: string;
  block_id: string | null;
  block_height: number | null;
  timestamp: number | null;
  inputs: number;
  outputs: number;
  output_atoms: string;
  fee_burned_atoms: string | null;
  encoded_bytes: number;
  status: "confirmed" | "mempool";
};

/** A transaction with the validated height it was read with. */
export type ExplorerTransactionDetail = ExplorerTransaction & {
  validated_height?: number | null;
};

export type ExplorerBlock = {
  height: number;
  block_id: string;
  previous_block: string;
  transaction_root: string;
  timestamp: number;
  target: string;
  nonce: string;
  work_digest: string;
  transactions: number;
  encoded_bytes: number;
  coinbase_atoms: string;
  confirmations: number;
};

export type ExplorerSnapshot = {
  network: string;
  network_short_name: string;
  network_id: string;
  consensus_fingerprint: string;
  proof_profile: string;
  proof_of_work: string;
  tip: string;
  accepted_height: number;
  /**
   * Every block up to this height is pinned by the release or has had its
   * work re-executed by the node; blocks above it are still being checked.
   * Null on a network without that rule; absent from nodes before 1.0.16.
   */
  validated_height?: number | null;
  expected_target: string;
  cumulative_work: string;
  utxo_count: number;
  mempool_transactions: number;
  mempool_bytes: number;
  connected_peers: number;
  latest_blocks: ExplorerBlock[];
  recent_transactions: ExplorerTransaction[];
};

export type ExplorerBlockDetail = ExplorerBlock & {
  validated_height?: number | null;
  coinbase_outputs: number;
  transactions_detail: ExplorerTransaction[];
};

export type ExplorerView =
  | { kind: "overview" }
  | { kind: "block"; block: ExplorerBlockDetail }
  | { kind: "transaction"; transaction: ExplorerTransactionDetail }
  | { kind: "address"; address: ExplorerAddress };

export type ExplorerSearchKind = "chain" | "address";

export type ExplorerAddressActivity = {
  txid: string;
  block_id: string;
  block_height: number;
  timestamp: number;
  confirmations: number;
  kind: "coinbase" | "received" | "sent" | "self";
  received_atoms: string;
  received_outputs: number;
  spent_inputs: number;
};

export type ExplorerAddress = {
  address: string;
  tip: string;
  accepted_height: number;
  validated_height?: number | null;
  balance_scope: "key_outputs";
  includes_mempool: false;
  confirmed_atoms: string;
  spendable_atoms: string;
  immature_atoms: string;
  utxo_count: number;
  history: ExplorerAddressActivity[];
  page_limit: number;
  has_more: boolean;
  next_cursor: string | null;
};
