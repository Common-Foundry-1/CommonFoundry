import { cleanup, render, screen } from "@testing-library/react";
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

describe("a wallet held after a newer version failed", () => {
  afterEach(cleanup);

  it("asks Retry or Run anyway instead of asking to unlock the wallet", async () => {
    const held = Object.assign(
      new Error("Version 1.0.17 stopped after it had opened this wallet's data (corrupt_block_log)."),
      { code: "update_fallback_held" },
    );
    apiMocks.getNodeStatus.mockRejectedValue(held);
    apiMocks.getWalletSnapshot.mockRejectedValue(held);
    apiMocks.getMempool.mockRejectedValue(held);
    apiMocks.getWalletCustodyStatus.mockResolvedValue({
      network: "ProductionV4 Mainnet",
      storage: "encrypted",
      unlocked: false,
      requires_migration: false,
      can_restore: false,
      data_directory: "C:\\wallet-data",
      destination: null,
    });
    invoke.mockImplementation((command: string) => (command === "get_update_status"
      ? Promise.resolve(updateStatus({
        status: { state: "idle" },
        fallback: { version: "1.0.17", reason: "corrupt_block_log", after_data: true, held: true },
      }))
      : Promise.reject(new Error(`unexpected ${command}`))));
    render(<App />);

    expect(await screen.findByText("Version 1.0.17 stopped after it opened your wallet data")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry 1.0.17" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run 1.0.16 anyway" })).toBeInTheDocument();
    await vi.waitFor(() => expect(apiMocks.getWalletCustodyStatus).toHaveBeenCalled());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByText("Local node unavailable")).not.toBeInTheDocument();
  });

  it("asks Retry or Run anyway on mainnet, where the custody status reports the launch", async () => {
    const held = Object.assign(
      new Error("Version 1.0.17 stopped after it had opened this wallet's data (corrupt_block_log)."),
      { code: "update_fallback_held" },
    );
    apiMocks.getNodeStatus.mockRejectedValue(held);
    apiMocks.getWalletSnapshot.mockRejectedValue(held);
    apiMocks.getMempool.mockRejectedValue(held);
    apiMocks.getWalletCustodyStatus.mockResolvedValue({
      network: "CommonFoundry Mainnet",
      storage: "encrypted",
      unlocked: false,
      requires_migration: false,
      can_restore: false,
      data_directory: "C:\\wallet-data",
      destination: null,
      launch: { mining_start_utc: "2026-10-03T17:00:00Z", ready: true, error: null },
    });
    invoke.mockImplementation((command: string) => (command === "get_update_status"
      ? Promise.resolve(updateStatus({
        status: { state: "idle" },
        fallback: { version: "1.0.17", reason: "corrupt_block_log", after_data: true, held: true },
      }))
      : Promise.reject(new Error(`unexpected ${command}`))));
    render(<App />);

    expect(await screen.findByText("Version 1.0.17 stopped after it opened your wallet data")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry 1.0.17" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run 1.0.16 anyway" })).toBeInTheDocument();
    expect(screen.queryByText("Mainnet is ready to connect")).not.toBeInTheDocument();
  });

  it("still explains the hold when the update status cannot be read", async () => {
    const held = Object.assign(
      new Error("Version 1.0.17 stopped after it had opened this wallet's data (corrupt_block_log)."),
      { code: "update_fallback_held" },
    );
    apiMocks.getNodeStatus.mockRejectedValue(held);
    apiMocks.getWalletSnapshot.mockRejectedValue(held);
    apiMocks.getMempool.mockRejectedValue(held);
    apiMocks.getWalletCustodyStatus.mockResolvedValue({
      network: "ProductionV4 Mainnet",
      storage: "encrypted",
      unlocked: false,
      requires_migration: false,
      can_restore: false,
      data_directory: "C:\\wallet-data",
      destination: null,
    });
    invoke.mockImplementation((command: string) => Promise.reject(
      command === "get_update_status"
        ? { code: "update_request_failed", message: "The updater is not running", status: 500 }
        : new Error(`unexpected ${command}`),
    ));
    render(<App />);

    expect(await screen.findByText("This wallet waits for your choice")).toBeInTheDocument();
    expect(await screen.findByText(/Version 1\.0\.17 stopped after it had opened this wallet's data/))
      .toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check again" })).toBeInTheDocument();
    await vi.waitFor(() => expect(apiMocks.getWalletCustodyStatus).toHaveBeenCalled());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("a mainnet wallet that runs because a newer version could not start", () => {
  afterEach(cleanup);

  it("says why on the launch screen, before the wallet is unlocked", async () => {
    const locked = Object.assign(new Error("Unlock the wallet to start the node."), { code: "wallet_locked" });
    apiMocks.getNodeStatus.mockRejectedValue(locked);
    apiMocks.getWalletSnapshot.mockRejectedValue(locked);
    apiMocks.getMempool.mockRejectedValue(locked);
    apiMocks.getWalletCustodyStatus.mockResolvedValue({
      network: "CommonFoundry Mainnet",
      storage: "encrypted",
      unlocked: false,
      requires_migration: false,
      can_restore: false,
      data_directory: "C:\\wallet-data",
      destination: null,
      launch: { mining_start_utc: "2026-10-03T17:00:00Z", ready: true, error: null },
    });
    invoke.mockImplementation((command: string) => (command === "get_update_status"
      ? Promise.resolve(updateStatus({
        status: { state: "idle" },
        fallback: { version: "1.0.17", reason: "mainnet_launch_evidence", after_data: false, held: false },
      }))
      : Promise.reject(new Error(`unexpected ${command}`))));
    render(<App />);

    expect(await screen.findByText("Version 1.0.17 could not start")).toBeInTheDocument();
    expect(screen.getByText("Reason: mainnet_launch_evidence. This version (1.0.16) is running instead."))
      .toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry 1.0.17" })).toBeInTheDocument();
    expect(screen.getByText("Mainnet is ready to connect")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Unlock and connect" })).toBeInTheDocument();
  });
});
