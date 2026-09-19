import { useState } from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WalletCustodyStatus } from "../types";
import { PrelaunchWallet } from "./PrelaunchWallet";

const api = vi.hoisted(() => ({
  createWallet: vi.fn(), chooseWalletBackupPath: vi.fn(), unlockWallet: vi.fn(),
  backupWallet: vi.fn(), restoreWallet: vi.fn(), migrateWalletEncryption: vi.fn(), lockWallet: vi.fn(),
}));
vi.mock("../api/nodeClient", () => api);
const missing: WalletCustodyStatus = {
  network: "CommonFoundry Mainnet", storage: "missing", unlocked: false,
  requires_migration: false, can_restore: true, data_directory: "C:\\mainnet",
  destination: null, launch: { mining_start_utc: "2026-10-03T17:00:00Z", ready: false, error: null },
};
const prepared = { ...missing, storage: "encrypted" as const, can_restore: false, destination: "12".repeat(32) };
function Harness({ initial = missing }: { initial?: WalletCustodyStatus }) {
  const [status, setStatus] = useState(initial);
  return <PrelaunchWallet status={status} statusError={null} onStatusChange={setStatus} onRefresh={async () => {}} />;
}
describe("prelaunch preparation", () => {
  beforeEach(() => { for (const mock of Object.values(api)) mock.mockReset(); });
  afterEach(cleanup);

  it("creates and backs up a wallet, then displays its address while remaining offline", async () => {
    const user = userEvent.setup();
    api.chooseWalletBackupPath.mockResolvedValue("D:\\mainnet.cmfd-backup");
    api.createWallet.mockResolvedValue(prepared);
    render(<Harness />);
    expect(screen.getByText(/October 3, 2026.*12:00 PM CDT/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /send|mine/i })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Set up wallet" }));
    await user.click(screen.getByRole("button", { name: "Choose save location…" }));
    await user.type(screen.getByLabelText("New wallet passphrase"), "correct horse battery staple");
    await user.type(screen.getByLabelText("Confirm passphrase"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Create an encrypted wallet" }));
    expect(screen.getByLabelText("Prepared wallet address")).toHaveTextContent(prepared.destination!);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByText("Waiting for the launch certificate")).toBeInTheDocument();
    expect(api.unlockWallet).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Copy address / QR code" }));
    await user.click(screen.getByRole("button", { name: "Copy address" }));
    expect(screen.getByRole("button", { name: "Address copied" })).toBeInTheDocument();
    expect(await navigator.clipboard.readText()).toBe(prepared.destination);
  });

  it("never displays an address after a failed prelaunch authentication", async () => {
    const user = userEvent.setup();
    api.unlockWallet.mockRejectedValue(new Error("Wallet authentication failed"));
    render(<Harness initial={{ ...prepared, destination: null }} />);
    await user.click(screen.getByRole("button", { name: "Show receiving address" }));
    await user.type(screen.getByLabelText("Wallet passphrase"), "incorrect passphrase");
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Show receiving address" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Wallet authentication failed");
    expect(screen.queryByLabelText("Prepared wallet address")).not.toBeInTheDocument();
  });

  it("requires an explicit unlock after launch and reports preparation errors", async () => {
    render(<Harness initial={{ ...prepared, launch: { ...missing.launch!, ready: true } }} />);
    expect(screen.getByText("Launch certificate verified")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Unlock and connect" })).toBeInTheDocument();
    expect(api.unlockWallet).not.toHaveBeenCalled();
    cleanup();
    render(<Harness initial={{ ...missing, launch: { ...missing.launch!, error: "Launch beacon publication failed" } }} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Launch beacon publication failed");
  });
});
