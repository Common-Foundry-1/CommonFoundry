import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { updateStatus } from "./test/updateFixtures";
import { App } from "./App";

const apiMocks = vi.hoisted(() => ({
  usesEmbeddedNode: true,
  getNodeStatus: vi.fn(),
  getWalletSnapshot: vi.fn(),
  getMempool: vi.fn(),
  getWalletCustodyStatus: vi.fn(),
  resyncChain: vi.fn(),
  unlockWallet: vi.fn(),
  lockWallet: vi.fn(),
  backupWallet: vi.fn(),
  createWallet: vi.fn(),
  chooseWalletBackupPath: vi.fn(),
  migrateWalletEncryption: vi.fn(),
  restoreWallet: vi.fn(),
}));
const invoke = vi.hoisted(() => vi.fn());

vi.mock("./api/nodeClient", () => apiMocks);
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

function nodeAnswers(error: Error) {
  apiMocks.getNodeStatus.mockRejectedValue(error);
  apiMocks.getWalletSnapshot.mockRejectedValue(error);
  apiMocks.getMempool.mockRejectedValue(error);
}

describe("a stored chain the node refused", () => {
  afterEach(cleanup);

  it("offers the resync instead of asking to unlock the wallet", async () => {
    const refused = Object.assign(
      new Error("The blocks this wallet stored differ from the chain this release pins."),
      { code: "chain_resync_required" },
    );
    nodeAnswers(refused);
    apiMocks.getWalletCustodyStatus.mockResolvedValue({
      network: "ProductionV4 Testnet-1",
      storage: "encrypted",
      unlocked: false,
      requires_migration: false,
      can_restore: false,
      data_directory: "C:\wallet-data",
      destination: null,
    });
    render(<App />);

    expect(await screen.findByText("Stored chain needs a resync")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Resync chain" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry" })).not.toBeInTheDocument();
    await vi.waitFor(() => expect(apiMocks.getWalletCustodyStatus).toHaveBeenCalled());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("on mainnet, leaves the launch screen for the resync when the unlock finds the stored chain refused", async () => {
    const user = userEvent.setup();
    const launch = { mining_start_utc: "2026-10-03T17:00:00Z", ready: true, error: null };
    const locked = {
      network: "CommonFoundry Mainnet",
      storage: "encrypted",
      unlocked: false,
      requires_migration: false,
      can_restore: false,
      data_directory: "C:\\wallet-data",
      destination: null,
      launch,
    };
    const walletLocked = () => Object.assign(new Error("Unlock the wallet to start the node."), { code: "wallet_locked" });
    const refused = Object.assign(
      new Error("The blocks this wallet stored differ from the chain this release pins. Resync the chain."),
      { code: "chain_resync_required" },
    );
    // A locked mainnet wallet does not open its node at launch.
    nodeAnswers(walletLocked());
    apiMocks.getWalletCustodyStatus.mockResolvedValue(locked);
    invoke.mockImplementation((command: string) => (command === "get_update_status"
      ? Promise.resolve(updateStatus({ status: { state: "up_to_date" } }))
      : Promise.reject(new Error(`unexpected ${command}`))));
    // The unlock opens the stored chain, and the node refuses it.
    apiMocks.unlockWallet.mockImplementation(async () => {
      nodeAnswers(refused);
      throw refused;
    });
    render(<App />);

    expect(await screen.findByText("Mainnet is ready to connect")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Unlock and connect" }));
    const unlock = screen.getByRole("dialog");
    await user.type(within(unlock).getByLabelText("Wallet passphrase"), "correct horse battery staple");
    await user.click(within(unlock).getByRole("button", { name: "Unlock wallet" }));
    expect(await within(unlock).findByRole("alert")).toHaveTextContent("Resync the chain");

    // The next status read shows the refusal: the main layout, with the
    // resync, replaces the launch screen.
    expect(await screen.findByText("Stored chain needs a resync", {}, { timeout: 9_000 })).toBeInTheDocument();
    expect(screen.queryByText("Mainnet is ready to connect")).not.toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    // The resync leaves the encrypted wallet locked, so the launch screen
    // comes back, and it says where the old chain went.
    apiMocks.resyncChain.mockImplementation(async () => {
      nodeAnswers(walletLocked());
      return { custody: locked, moved_to: "C:\\wallet-data\\chain-set-aside-1", moved_bytes: 1_500_000_000 };
    });
    await user.click(screen.getByRole("button", { name: "Resync chain" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Resync chain" }));
    expect(await screen.findByText("Mainnet is ready to connect")).toBeInTheDocument();
    expect(screen.getByText(
      "The stored chain (1.5 GB) was moved to C:\\wallet-data\\chain-set-aside-1. "
        + "You can delete that folder once the wallet has synced again. Unlock the wallet to download the chain again.",
    )).toBeInTheDocument();
  }, 30_000);
});
