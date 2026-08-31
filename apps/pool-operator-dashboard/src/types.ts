export interface OperatorPoolState {
  running: boolean;
  pid: number | null;
  uptime_seconds: number | null;
  dashboard_url: string | null;
  dashboard_healthy: boolean;
  dashboard_error: string | null;
  log_file: string | null;
}

export interface OperatorSettings {
  public_numeric_address: string;
  private_bind_address: string;
  pool_port: number | string;
  p2p_bind: string;
  dashboard_bind: string;
  operator_fee_bps: number;
  pplns_window_shares: number;
}

export interface PoolWorker {
  worker: string;
  connected: boolean;
  accepted_shares: number;
  rejected_shares: number;
}

export interface PoolBlock {
  block_id: string;
  height: number;
  state: string;
  confirmations: number;
  operator_fee_atoms: number | null;
  pplns_distributed: boolean;
}

export interface PoolPayoutTransaction {
  txid: string;
  payout: string;
  amount_atoms: number;
  state: string;
  confirmations: number;
}

export interface PoolSnapshot {
  generated_at_unix_seconds: number;
  network_name: string;
  network_short_name: string;
  accepted_height: number;
  active_connections: number;
  active_share_verifications: number;
  queued_share_verifications: number;
  operator_fee_bps: number | null;
  configured_pplns_window_shares: number | null;
  effective_pplns_window_shares: number | null;
  workers: PoolWorker[];
  ledger: {
    accepted_shares: number;
    rejected_shares: number;
    pool_blocks: number;
    operator_fee_atoms: number;
    pplns_pending_blocks: number;
    pplns_distributed_blocks: number;
    blocks: PoolBlock[];
    payout_transactions: PoolPayoutTransaction[];
  };
}

export interface PublicPoolDocument {
  public_pool_url: string;
  certificate_sha256: string;
  pool: PoolSnapshot;
}

export interface OperatorEvent {
  time_unix_seconds: number;
  event: string;
  details: string;
  source: string;
}

export interface OperatorStatus {
  ok: true;
  generated_at_unix_seconds: number;
  platform: "windows" | "linux";
  operator_bind: string;
  action_busy: boolean;
  pool: OperatorPoolState;
  settings: OperatorSettings | null;
  snapshot: PublicPoolDocument | null;
  paths: {
    data_directory: string;
    settings_file: string;
  };
  events: OperatorEvent[];
}

export interface OperatorLog {
  ok: true;
  path: string | null;
  text: string;
}
