import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { WalletSnapshot } from "../types";
import { Overview } from "./Overview";

function wallet(availableHeight: number | null): WalletSnapshot {
  return {
    network: "CommonFoundry Mainnet",
    devnet_only: false,
    insecure_demo_wallet: false,
    warning: "",
    destination: "12".repeat(32),
    accepted_height: 128,
    next_height: 129,
    balances: {
      spendable_atoms: "100000000",
      pending_atoms: "0",
      immature_atoms: "0",
      verifying_atoms: "50000000",
    },
    spendable_utxo_count: 1,
    immature_utxo_count: 0,
    reserved_utxo_count: 0,
    verifying_utxo_count: 1,
    validated_height: 100,
    available_height: availableHeight,
    mempool: { transactions: 0, bytes: 0 },
    history_limit: 50,
    history: [],
  } as WalletSnapshot;
}

function verifyingTitle(availableHeight: number | null): string | null {
  cleanup();
  render(
    <Overview
      wallet={wallet(availableHeight)}
      status={null}
      refreshing={false}
      onSend={vi.fn()}
      onReceive={vi.fn()}
      onViewTransactions={vi.fn()}
      onViewNetwork={vi.fn()}
      onRefresh={vi.fn()}
    />,
  );
  return screen.getByText("Verifying").parentElement?.getAttribute("title") ?? null;
}

describe("Overview", () => {
  afterEach(cleanup);

  it("explains Verifying coins without claiming every Available coin was checked here", () => {
    // Full mode: coins wait for the blocks that hold them.
    expect(verifyingTitle(null))
      .toBe("Coins in blocks the wallet has not checked yet. They can be sent once those blocks are checked.");
    // Standard mode, catching up: they wait for the newest blocks.
    expect(verifyingTitle(120))
      .toBe("Coins in recent blocks. They can be sent once the newest blocks are checked.");
  });
});
