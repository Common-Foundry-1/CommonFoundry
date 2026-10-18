import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { sendWalletTransaction } from "../api/nodeClient";
import { MAINNET_HRP, TEST_NETWORK_HRP, encode } from "../lib/addressCodec";
import { walletAddressHrp } from "../lib/walletAddress";
import type { WalletSnapshot } from "../types";
import { ReceiveDialog } from "./ReceiveDialog";
import { SendDialog } from "./SendDialog";

vi.mock("../api/nodeClient", () => ({ sendWalletTransaction: vi.fn() }));

const key = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const checksummed = "cmfd10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq4yhywr";

const wallet: WalletSnapshot = {
  network: "CommonFoundry Mainnet",
  devnet_only: false,
  insecure_demo_wallet: false,
  warning: "Mainnet wallet.",
  destination: key,
  accepted_height: 10,
  next_height: 11,
  balances: { spendable_atoms: "1000000000", immature_atoms: "0", pending_atoms: "0" },
  spendable_utxo_count: 1,
  immature_utxo_count: 0,
  reserved_utxo_count: 0,
  mempool: { transactions: 0, bytes: 0 },
  history_limit: 100,
  history: [],
};

async function enterRecipient(recipient: string, network = wallet.network) {
  const user = userEvent.setup();
  render(<SendDialog open wallet={{ ...wallet, network }} onClose={() => {}} onCompleted={() => {}} onRefresh={() => {}} />);
  // The dialog takes focus on the next frame; typing before that loses keys.
  await waitFor(() => expect(screen.getByRole("dialog")).toHaveFocus());
  await user.type(screen.getByRole("textbox", { name: "Recipient" }), recipient);
  await user.type(screen.getByRole("textbox", { name: "Amount" }), "1");
  await user.click(screen.getByRole("button", { name: "Review transaction" }));
  return user;
}

afterEach(() => {
  cleanup();
  vi.mocked(sendWalletTransaction).mockReset();
});

describe("wallet address forms", () => {
  it("derives the prefix from either network name", () => {
    expect(walletAddressHrp("CommonFoundry Mainnet")).toBe(MAINNET_HRP);
    expect(walletAddressHrp("Mainnet")).toBe(MAINNET_HRP);
    expect(walletAddressHrp("CommonFoundry RCNet-1")).toBe(TEST_NETWORK_HRP);
    expect(walletAddressHrp("CommonFoundry Devnet-0")).toBe(TEST_NETWORK_HRP);
    expect(walletAddressHrp(undefined)).toBe(TEST_NETWORK_HRP);
  });

  it.each([checksummed, checksummed.toUpperCase()])("sends a checksummed recipient as hex: %s", async (recipient) => {
    vi.mocked(sendWalletTransaction).mockResolvedValue({
      network: wallet.network, devnet_only: false, insecure_demo_wallet: false, warning: "",
      txid: "66".repeat(32), amount_atoms: "100000000", fee_burned_atoms: "10000000", change_atoms: "0",
      mempool_transactions: 1, mempool_bytes: 100,
    });
    const user = await enterRecipient(recipient);
    expect(screen.getByLabelText("Full recipient public key")).toHaveTextContent(key);
    expect(screen.getByLabelText("Checksummed recipient address")).toHaveTextContent(checksummed);
    await user.click(screen.getByRole("button", { name: "Send transaction" }));
    expect(sendWalletTransaction).toHaveBeenCalledWith({ recipient: key, amount: "1", fee: "0.10000000" });
  });

  it.each([key, key.toUpperCase()])("keeps hex recipient %s as lowercase hex", async (recipient) => {
    await enterRecipient(recipient);
    expect(screen.getByLabelText("Full recipient public key")).toHaveTextContent(key);
    expect(screen.queryByLabelText("Checksummed recipient address")).not.toBeInTheDocument();
  });

  it("accepts the test-network prefix on test networks only", async () => {
    await enterRecipient(encode(TEST_NETWORK_HRP, key), "CommonFoundry RCNet-1");
    expect(screen.getByLabelText("Full recipient public key")).toHaveTextContent(key);
    cleanup();
    await enterRecipient(checksummed, "CommonFoundry RCNet-1");
    expect(screen.getByText("Address is for another network: expected tcmfd1..., found cmfd1...")).toBeInTheDocument();
  });

  it.each([
    [checksummed.slice(0, -1) + "q", "Address checksum does not match: the address is mistyped or incomplete."],
    [checksummed.replace("cmfd", "cmfe"), "Address checksum does not match: the address is mistyped or incomplete."],
    [encode(TEST_NETWORK_HRP, key), "Address is for another network: expected cmfd1..., found tcmfd1..."],
    [checksummed.slice(0, -1) + "R", "Address mixes upper and lower case."],
    [key.slice(0, 63), "Expected a cmfd1... address or 64 lowercase hexadecimal characters encoding an x-only public key."],
    [checksummed.slice(0, 40), "Address checksum does not match: the address is mistyped or incomplete."],
  ])("explains why %s cannot be sent to", async (recipient, message) => {
    await enterRecipient(recipient);
    expect(screen.getByText(message)).toHaveAttribute("id", "send-recipient-error");
    expect(screen.queryByRole("button", { name: "Send transaction" })).not.toBeInTheDocument();
    expect(sendWalletTransaction).not.toHaveBeenCalled();
  });

  it("offers the checksummed receive address as a separate copy, keeping hex primary", async () => {
    const user = userEvent.setup();
    render(<ReceiveDialog open wallet={wallet} onClose={() => {}} />);
    expect(screen.getByLabelText("Wallet address")).toHaveTextContent(key);
    expect(screen.getByLabelText("Checksummed wallet address")).toHaveTextContent(checksummed);

    await user.click(screen.getByRole("button", { name: "Copy checksummed address" }));
    expect(await navigator.clipboard.readText()).toBe(checksummed);
    expect(screen.getByRole("button", { name: "Checksummed address copied" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy address" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Copy address" }));
    expect(await navigator.clipboard.readText()).toBe(key);
    expect(screen.getByRole("button", { name: "Address copied" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy checksummed address" })).toBeInTheDocument();
  });

  it("uses the test-network prefix for a test-network receive address", () => {
    render(<ReceiveDialog open wallet={{ ...wallet, network: "CommonFoundry RCNet-1" }} onClose={() => {}} />);
    expect(screen.getByLabelText("Checksummed wallet address")).toHaveTextContent(encode(TEST_NETWORK_HRP, key));
  });
});
