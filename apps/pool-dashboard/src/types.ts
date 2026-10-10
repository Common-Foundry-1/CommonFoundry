export interface PoolWorker {
  worker: string;
  payout: string;
  connected: boolean;
  accepted_shares: number;
  rejected_shares: number;
  stale_shares: number;
  pool_blocks: number;
  credited_devnet_atoms: number;
  reported_work_rate_fw_per_second: number;
  reported_average_work_rate_fw_per_second: number;
  telemetry_age_seconds: number | null;
  earned_atoms_last_24h: number;
  estimated_24h_earnings_atoms: number | null;
  low_difficulty_shares: number;
  duplicate_shares: number;
  invalid_proof_shares: number;
}

export interface PoolPayout {
  payout: string;
  accepted_shares: number;
  rejected_shares: number;
  stale_shares: number;
  pool_blocks: number;
  credited_devnet_atoms: number;
  reserved_payout_atoms: number;
  confirmed_payout_atoms: number;
  available_payout_atoms: number;
  payout_on_hold?: boolean;
  held_payout_atoms?: number;
  bonus_atoms?: number;
}

export interface PoolBonusFunding {
  txid: string;
  height: number;
  amount_atoms: number;
}

export interface PoolPayoutProtection {
  requires_reconciliation: boolean;
  all_payouts_paused: boolean;
  affected_payouts: string[];
  unresolved_incidents: { id: number; reason: string; block_id: string | null; payout_txid: string | null; detected_tip: string; detected_height: number }[];
  resolved_incidents: number;
}

export interface PoolBlock {
  block_id: string;
  parent: string;
  height: number;
  payout: string;
  state: string;
  confirmations: number;
  miner_reward_atoms: number | null;
  operator_fee_bps: number | null;
  operator_fee_atoms: number | null;
  distributable_atoms: number | null;
  pplns_window_shares: number | null;
  pplns_distributed: boolean;
  bonus_rate_bps?: number | null;
  bonus_atoms?: number | null;
}

export interface PoolPayoutTransaction {
  txid: string;
  payout: string;
  amount_atoms: number;
  fee_atoms: number;
  state: string;
  confirmations: number;
}

export interface PoolLedger {
  accounting_semantics: string;
  persistence: string;
  accepted_shares: number;
  rejected_shares: number;
  stale_shares: number;
  pool_blocks: number;
  credited_devnet_atoms: number;
  operator_fee_atoms: number;
  pplns_window_shares: number;
  pplns_pending_blocks: number;
  pplns_distributed_blocks: number;
  canonical_pool_blocks: number;
  orphaned_pool_blocks: number;
  sessions: unknown[];
  payouts: PoolPayout[];
  blocks: PoolBlock[];
  payout_transactions: PoolPayoutTransaction[];
  payout_protection?: PoolPayoutProtection;
  bonus_funded_atoms?: number;
  bonus_credited_atoms?: number;
  bonus_reserve_atoms?: number;
  bonus_scanned_height?: number | null;
  bonus_funding?: PoolBonusFunding[];
}

export interface PoolSnapshot {
  generated_at_unix_seconds: number;
  network_name: string;
  network_short_name: string;
  network_notice: string;
  proof_profile: string;
  accepted_height: number;
  tip: string;
  current_job_id: string;
  share_target: string;
  active_connections: number;
  connection_capacity: number;
  max_connections_per_source: number;
  round_accepted_shares?: number;
  expected_shares_per_block?: number;
  active_share_verifications: number;
  queued_share_verifications: number;
  share_verification_capacity: number;
  share_verification_queue_capacity: number;
  automatic_testnet_payouts: boolean;
  minimum_payout_atoms: number | null;
  payout_fee_atoms: number | null;
  operator_fee_bps: number | null;
  configured_pplns_window_shares: number | null;
  effective_pplns_window_shares: number | null;
  reported_work_rate_fw_per_second: number;
  reported_average_work_rate_fw_per_second: number;
  credited_atoms_last_24h: number;
  estimated_24h_credited_atoms: number | null;
  earnings_observation_seconds: number;
  bonus_rate_bps?: number | null;
  bonus_sponsor?: string | null;
  bonus_reserve_atoms?: number;
  bonus_funded_atoms?: number;
  bonus_credited_atoms?: number;
  workers: PoolWorker[];
  ledger: PoolLedger;
}

export interface DashboardDocument {
  public_pool_url: string;
  certificate_sha256: string;
  refresh_interval_seconds: number;
  pool: PoolSnapshot;
}
