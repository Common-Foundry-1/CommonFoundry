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
  coinbase_outputs: number;
  transactions_detail: ExplorerTransaction[];
};

export type ExplorerView =
  | { kind: "overview" }
  | { kind: "block"; block: ExplorerBlockDetail }
  | { kind: "transaction"; transaction: ExplorerTransaction };
