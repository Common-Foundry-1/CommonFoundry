import type { ExplorerAddress } from "../types";

export const fixtureAddress = "a1".repeat(32);
export const fixtureTip = "d1".repeat(32);

export function addressFixture(options: { address?: string; tip?: string; height?: number; start?: number; count?: number; more?: boolean } = {}): ExplorerAddress {
  const height = options.height ?? 100;
  const start = options.start ?? height;
  const count = options.count ?? 20;
  const more = options.more ?? count === 20;
  const tip = options.tip ?? fixtureTip;
  return {
    address: options.address ?? fixtureAddress, tip, accepted_height: height,
    balance_scope: "key_outputs", includes_mempool: false,
    confirmed_atoms: "1234567000000", spendable_atoms: "1000000000000", immature_atoms: "234567000000",
    utxo_count: 12, page_limit: 20, has_more: more,
    next_cursor: more ? `${tip}.${start - count + 1}.1` : null,
    history: Array.from({ length: count }, (_, index) => ({
      txid: (start - index + 1000).toString(16).padStart(64, "0"),
      block_id: (start - index + 2000).toString(16).padStart(64, "0"),
      block_height: start - index, timestamp: 1_790_000_000 + (start - index) * 60,
      confirmations: height - (start - index) + 1, kind: "received",
      received_atoms: "100000000", received_outputs: 1, spent_inputs: 0,
    })),
  };
}
