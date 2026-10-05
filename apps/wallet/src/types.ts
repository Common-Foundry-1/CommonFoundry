export type WalletHistoryKind = "mined" | "received" | "sent" | "consolidated";

export interface PeerObservation {
  address: string;
  direction: "inbound" | "outbound";
  state: "connected" | "reachable" | "failed";
  first_seen: number;
  last_seen: number;
  last_success: number | null;
  successful_sessions: number;
  failed_sessions: number;
  active_connections: number;
  remote_height: number | null;
  remote_tip: string | null;
}

export interface PeerSettings {
  peers: string[];
  bootstrap_peers: string[];
  default_peer_port: number;
  max_peers: number;
}

export interface WalletCustodyStatus {
  network: string;
  storage: "missing" | "plaintext" | "encrypted";
  unlocked: boolean;
  requires_migration: boolean;
  can_restore: boolean;
  data_directory: string;
  destination: string | null;
  launch?: { mining_start_utc: string; ready: boolean; error: string | null } | null;
}

export interface ProofAdmissionClassTelemetry {
  active: number;
  queued: number;
  wait_events: number;
  rejections: number;
  proof_failures: number;
}

export interface NodeStatus {
  network: string;
  network_short_name: string;
  network_notice: string;
  network_purpose: string;
  network_id: string;
  consensus_fingerprint: string;
  proof_of_work: string;
  proof_profile: string;
  rpc_port: number;
  p2p_port: number;
  pool_port: number;
  node_data_dir_identity: string;
  wallet_data_dir_identity: string;
  miner_data_dir_identity: string;
  bounded_reference_mining: boolean;
  tip: string;
  cumulative_work: string;
  accepted_height: number;
  next_height: number;
  expected_target: string;
  utxo_count: number;
  mempool_transactions: number;
  mempool_bytes: number;
  proof_verification_active: number;
  proof_verification_queued: number;
  proof_verification_normal_admission: ProofAdmissionClassTelemetry;
  proof_verification_priority_admission: ProofAdmissionClassTelemetry;
  proof_verification_remote_admission: ProofAdmissionClassTelemetry;
  proof_verification_remote_admission_capacity: number;
  proof_verification_remote_admission_wait_timeout_ms: number;
  proof_verification_capacity: number;
  proof_verification_queue_capacity: number;
  proof_verification_mode: string;
  proof_verification_timeout_ms: number | null;
  proof_verification_memory_limit_bytes: number | null;
  proof_verification_teardown_failures: number | null;
  storage_healthy: boolean;
  public_peer_mode: boolean;
  peers: PeerObservation[];
}

export interface WalletBalances {
  spendable_atoms: string;
  immature_atoms: string;
  pending_atoms: string;
}

export interface WalletHistoryEntry {
  kind: WalletHistoryKind;
  txid: string;
  height: number | null;
  timestamp: number | null;
  confirmations: number;
  status: "confirmed" | "immature" | "pending";
  net_amount_atoms: string;
  fee_burned_atoms: string;
  counterparty: string | null;
  /** Web wallet only: a send signed elsewhere, so its fee (and any fee in net_amount_atoms) is unknown. */
  fee_unknown?: boolean;
}

export interface WalletSnapshot {
  network: string;
  devnet_only: boolean;
  insecure_demo_wallet: boolean;
  warning: string;
  destination: string;
  accepted_height: number;
  next_height: number;
  balances: WalletBalances;
  spendable_utxo_count: number;
  immature_utxo_count: number;
  reserved_utxo_count: number;
  mempool: {
    transactions: number;
    bytes: number;
  };
  history_limit: number;
  history: WalletHistoryEntry[];
}

export interface MempoolEntry {
  txid: string;
  encoded_bytes: number;
  fee_burned: number;
  fee_burned_atoms?: string;
}

export interface MempoolSnapshot {
  transactions: number;
  bytes: number;
  entries: MempoolEntry[];
}

export interface WalletSendRequest {
  recipient: string;
  amount: string;
  fee: string;
}

export interface WalletSendResult {
  network: string;
  devnet_only: boolean;
  insecure_demo_wallet: boolean;
  warning: string;
  txid: string;
  amount_atoms: string;
  fee_burned_atoms: string;
  change_atoms: string;
  mempool_transactions: number;
  mempool_bytes: number;
}

export interface ConsolidationRequest {
  fee: string;
  max_inputs: number;
}

export interface ConsolidationResult {
  network: string;
  devnet_only: boolean;
  insecure_demo_wallet: boolean;
  warning: string;
  txid: string;
  inputs_consolidated: number;
  input_atoms: string;
  output_atoms: string;
  fee_burned_atoms: string;
  mempool_transactions: number;
  mempool_bytes: number;
}

export interface MineResult {
  accepted: boolean;
  block_id: string;
  height: number;
  tip: string;
}
