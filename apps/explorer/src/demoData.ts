import type { ExplorerBlockDetail, ExplorerSnapshot, ExplorerTransaction } from "./types";

const hex = (seed: string) => seed.repeat(64).slice(0, 64);
const now = Math.floor(Date.now() / 1000);

export const demoTransactions: ExplorerTransaction[] = [
  { txid: hex("8f31a2"), block_id: hex("a91c6e"), block_height: 160, timestamp: now - 34, inputs: 2, outputs: 2, output_atoms: "12500000000", fee_burned_atoms: "1", encoded_bytes: 318, status: "confirmed" },
  { txid: hex("5db84c"), block_id: hex("c2379d"), block_height: 159, timestamp: now - 102, inputs: 1, outputs: 2, output_atoms: "4200000000", fee_burned_atoms: "1", encoded_bytes: 246, status: "confirmed" },
  { txid: hex("d1720f"), block_id: null, block_height: null, timestamp: null, inputs: 3, outputs: 2, output_atoms: "810000000", fee_burned_atoms: "2", encoded_bytes: 422, status: "mempool" },
];

export const demoSnapshot: ExplorerSnapshot = {
  network: "ProductionV4 Testnet-1",
  network_short_name: "ProductionV4 Testnet-1",
  network_id: hex("b9e55d5a5e"),
  consensus_fingerprint: hex("a219cb4dfb"),
  proof_profile: "ForgeMatrix V4",
  proof_of_work: "ForgeMatrix V4 transparent proof",
  tip: hex("a91c6e"),
  accepted_height: 160,
  expected_target: "000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  cumulative_work: hex("0000d4"),
  utxo_count: 477,
  mempool_transactions: 1,
  mempool_bytes: 422,
  connected_peers: 3,
  latest_blocks: [160, 159, 158, 157, 156].map((height, index) => ({
    height,
    block_id: index === 0 ? hex("a91c6e") : hex(`${height}bc7`),
    previous_block: hex(`${height - 1}bc7`),
    transaction_root: hex(`${height}7aa`),
    timestamp: now - 34 - index * 64,
    target: "000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    nonce: String(89211 + index * 941),
    work_digest: hex(`000${index + 1}d9`),
    transactions: index === 0 ? 1 : index % 3,
    encoded_bytes: 238412 + index * 127,
    coinbase_atoms: "5000000000",
    confirmations: index + 1,
  })),
  recent_transactions: demoTransactions,
};

export function demoBlock(block: (typeof demoSnapshot.latest_blocks)[number]): ExplorerBlockDetail {
  return {
    ...block,
    coinbase_outputs: 3,
    transactions_detail: demoTransactions.filter((tx) => tx.block_height === block.height),
  };
}
