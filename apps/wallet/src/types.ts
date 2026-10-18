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

/** What a resync did: where the stored chain was moved, and its size. */
export interface ChainResyncReport {
  custody: WalletCustodyStatus;
  moved_to: string;
  moved_bytes: number;
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

export interface WorkRuleAlarms {
  engine_divergence: number;
  own_engine_mismatches: number;
  engine_failures: number;
  store_conflicts: number;
  peers_on_invalid_chain: number;
}

/**
 * Where a desktop wallet catching up stands. Present only on a desktop wallet
 * started with `--work-check standard` (the default) where the catch-up is on.
 */
export interface WalletCatchUpStatus {
  state:
    | "release_stale"
    | "single_source"
    | "caught_up"
    | "catching_up"
    | "checking_newest"
    | "waiting_for_check";
  /** With `waiting_for_check`: why the coins still wait. */
  reason: "earlier_blocks" | "difficulty" | "other" | null;
  /** Coins in blocks up to this height are available. */
  available_height: number;
  /** How many blocks the state still waits for; the wallet shows this number as is. */
  blocks_left: number;
  /** The newest blocks checked on this computer, up to `newest_needed`. */
  newest_checked: number;
  newest_needed: number;
  /** Relays that reported their height recently. */
  sources_answering: number;
  /** A block taken without a check here lies above the available height: Solo mining waits. */
  granted_above_available: boolean;
}

/** How the node re-executes block work, on a network with that rule. */
export interface WorkRuleStatus {
  enforced: boolean;
  engines: string | null;
  /** Whether the CPU engine holds the model bank in memory or reads it for each block; absent from nodes older than 1.0.16. */
  bank?: "resident" | "streamed" | null;
  engine_state: "pending" | "qualifying" | "ready" | "failed";
  engine_ready: boolean;
  independent_engines: boolean;
  halted: boolean;
  checkpoint_height: number;
  checkpoint_hash: string;
  activation_height: number;
  validated_height: number;
  pending_side_blocks: number;
  /** The lowest unchecked active block, when one engine found its work does not match and nothing has settled it. */
  unsettled_height: number | null;
  /** The id of that block, in hex. */
  unsettled_block_id: string | null;
  /** The check of stored blocks is paused (on battery). */
  backlog_paused: boolean;
  alarms: WorkRuleAlarms;
  /** Only on a desktop wallet with the catch-up on. */
  wallet_catch_up?: WalletCatchUpStatus | null;
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
  work_rule?: WorkRuleStatus | null;
}

export interface WalletBalances {
  spendable_atoms: string;
  immature_atoms: string;
  pending_atoms: string;
  /** Coins in blocks whose work the node has not re-executed yet. */
  verifying_atoms?: string;
}

export interface WalletHistoryEntry {
  kind: WalletHistoryKind;
  txid: string;
  height: number | null;
  timestamp: number | null;
  confirmations: number;
  status: "confirmed" | "immature" | "pending" | "verifying";
  net_amount_atoms: string;
  fee_burned_atoms: string;
  counterparty: string | null;
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
  verifying_utxo_count?: number;
  validated_height?: number | null;
  /** Coins in blocks up to this height are available; only on a desktop wallet with the catch-up on. */
  available_height?: number | null;
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
