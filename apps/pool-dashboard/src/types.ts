export interface PoolWorker {
  worker: string;
  payout: string;
  connected: boolean;
  accepted_shares: number;
  rejected_shares: number;
  pool_blocks: number;
  credited_devnet_atoms: number;
}

export interface PoolPayout {
  payout: string;
  accepted_shares: number;
  rejected_shares: number;
  pool_blocks: number;
  credited_devnet_atoms: number;
  reserved_payout_atoms: number;
  confirmed_payout_atoms: number;
  available_payout_atoms: number;
}

export interface PoolBlock {
  block_id: string;
  parent: string;
  height: number;
  payout: string;
  state: string;
  confirmations: number;
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
  pool_blocks: number;
  credited_devnet_atoms: number;
  canonical_pool_blocks: number;
  orphaned_pool_blocks: number;
  sessions: unknown[];
  payouts: PoolPayout[];
  blocks: PoolBlock[];
  payout_transactions: PoolPayoutTransaction[];
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
  active_share_verifications: number;
  queued_share_verifications: number;
  share_verification_capacity: number;
  share_verification_queue_capacity: number;
  automatic_testnet_payouts: boolean;
  minimum_payout_atoms: number | null;
  payout_fee_atoms: number | null;
  workers: PoolWorker[];
  ledger: PoolLedger;
}

export interface DashboardDocument {
  public_pool_url: string;
  certificate_sha256: string;
  refresh_interval_seconds: number;
  pool: PoolSnapshot;
}
