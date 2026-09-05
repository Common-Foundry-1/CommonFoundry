export type MiningMode = "solo" | "pool";
export type MiningEngine = "cpu" | "cuda";

export type MiningLifecycle =
  | "stopped"
  | "starting"
  | "running"
  | "stopping"
  | "error";

export interface MiningStartRequest {
  mode: MiningMode;
  payout: string;
  pool_url?: string;
  worker_name?: string;
}

export interface MinedBlockSummary {
  height: number;
  block_id: string;
}

export interface MiningStatus {
  lifecycle: MiningLifecycle;
  mode: MiningMode | null;
  payout: string | null;
  pool_url: string | null;
  worker_name: string | null;
  engine: MiningEngine;
  device: string | null;
  matrix_attempts_per_second: number;
  session_attempts: number;
  blocks_found: number;
  shares_accepted: number;
  shares_rejected: number;
  credited_atoms: string;
  pool_connected: boolean;
  current_height: number;
  last_block: MinedBlockSummary | null;
  last_error: string | null;
  production_solo_available?: boolean;
  production_solo_setup?: string | null;
  stage?: string | null;
}
