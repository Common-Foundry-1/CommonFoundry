import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { WalletSnapshot } from "../types";
import { SendDialog } from "./SendDialog";

vi.mock("../api/nodeClient", () => ({ sendWalletTransaction: vi.fn() }));

const key = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

const wallet: WalletSnapshot = {
  network: "CommonFoundry Mainnet",
  devnet_only: false,
  insecure_demo_wallet: false,
  warning: "Mainnet wallet.",
  destination: "1d16453b3ab3132acb0a5bc16cc49690d819a585267a15cd5a064e2a0ad40599",
  accepted_height: 10,
  next_height: 11,
  // 10 CMFD spendable, 10 more Verifying.
  balances: { spendable_atoms: "1000000000", immature_atoms: "0", pending_atoms: "0", verifying_atoms: "1000000000" },
  spendable_utxo_count: 1,
  immature_utxo_count: 0,
  reserved_utxo_count: 0,
  verifying_utxo_count: 1,
  validated_height: 4,
  mempool: { transactions: 0, bytes: 0 },
  history_limit: 100,
  history: [],
};

async function sendMoreThanSpendable(snapshot: WalletSnapshot): Promise<HTMLElement> {
  const user = userEvent.setup();
  render(<SendDialog open wallet={snapshot} onClose={() => {}} onCompleted={() => {}} onRefresh={() => {}} />);
  await waitFor(() => expect(screen.getByRole("dialog")).toHaveFocus());
  await user.type(screen.getByRole("textbox", { name: "Recipient" }), key);
  await user.type(screen.getByRole("textbox", { name: "Amount" }), "15");
  await user.click(screen.getByRole("button", { name: "Review transaction" }));
  return screen.getByRole("dialog");
}

afterEach(cleanup);

describe("SendDialog Verifying copy", () => {
  it("says a catching-up wallet's Verifying coins wait for the newest blocks", async () => {
    const dialog = await sendMoreThanSpendable({ ...wallet, available_height: 4 });
    expect(dialog).toHaveTextContent(
      "The amount and burned fee exceed the spendable balance. 10.00000000 CMFD is Verifying. These coins can be sent once the newest blocks are checked.",
    );
  });

  it("keeps the background-check copy without the catch-up", async () => {
    const dialog = await sendMoreThanSpendable(wallet);
    expect(dialog).toHaveTextContent("CMFD is still being verified and can be sent once the blocks that hold it are checked.");
    expect(dialog).not.toHaveTextContent("newest blocks");
  });
});
