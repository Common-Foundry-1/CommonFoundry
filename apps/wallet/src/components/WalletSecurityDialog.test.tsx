import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { WalletCustodyStatus } from "../types";
import { WalletSecurityDialog } from "./WalletSecurityDialog";

const apiMocks = vi.hoisted(() => ({
  backupWallet: vi.fn(),
  chooseWalletBackupPath: vi.fn(),
  lockWallet: vi.fn(),
  migrateWalletEncryption: vi.fn(),
  restoreWallet: vi.fn(),
  unlockWallet: vi.fn(),
}));

vi.mock("../api/nodeClient", () => apiMocks);

const locked: WalletCustodyStatus = {
  network: "ProductionV4 Testnet-1",
  storage: "encrypted",
  unlocked: false,
  requires_migration: false,
  can_restore: false,
  data_directory: "C:\\wallet-data",
  destination: null,
};

const unlocked: WalletCustodyStatus = {
  ...locked,
  unlocked: true,
  destination: "11".repeat(32),
};

function renderDialog(status: WalletCustodyStatus) {
  const onStatusChange = vi.fn();
  render(
    <WalletSecurityDialog
      open
      required={!status.unlocked}
      status={status}
      statusError={null}
      onClose={vi.fn()}
      onStatusChange={onStatusChange}
      onCompleted={vi.fn()}
      onRefresh={vi.fn()}
    />,
  );
  return { onStatusChange };
}

describe("WalletSecurityDialog", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMocks)) mock.mockReset();
  });

  afterEach(cleanup);

  it("backs up to the selected path without requiring typed paths", async () => {
    const user = userEvent.setup();
    const selected = "D:\\My Backups\\wallet.cmfd-backup";
    apiMocks.chooseWalletBackupPath.mockResolvedValue(selected);
    apiMocks.backupWallet.mockResolvedValue(locked);
    renderDialog(unlocked);
    expect(screen.getByLabelText("New backup file")).toHaveAttribute("readonly");
    await user.click(screen.getByRole("button", { name: "Choose save location…" }));
    expect(apiMocks.chooseWalletBackupPath).toHaveBeenCalledWith(false);
    expect(screen.getByLabelText("New backup file")).toHaveValue(selected);
    await user.type(screen.getByLabelText("Wallet passphrase"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Back up wallet" }));
    expect(apiMocks.backupWallet).toHaveBeenCalledWith(selected, "correct horse battery staple");
  });

  it("cancelling the picker retains the prior selection and never creates a backup", async () => {
    const user = userEvent.setup();
    apiMocks.chooseWalletBackupPath.mockResolvedValueOnce("D:\\wallet.cmfd-backup").mockResolvedValueOnce(null);
    renderDialog(unlocked);
    await user.click(screen.getByRole("button", { name: "Choose save location…" }));
    await user.click(screen.getByRole("button", { name: "Choose save location…" }));
    expect(screen.getByLabelText("New backup file")).toHaveValue("D:\\wallet.cmfd-backup");
    expect(apiMocks.backupWallet).not.toHaveBeenCalled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("requires a selection if the first save dialog is cancelled", async () => {
    const user = userEvent.setup();
    apiMocks.chooseWalletBackupPath.mockResolvedValue(null);
    renderDialog(unlocked);
    await user.click(screen.getByRole("button", { name: "Choose save location…" }));
    expect(screen.getByLabelText("New backup file")).toHaveValue("");
    await user.type(screen.getByLabelText("Wallet passphrase"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Back up wallet" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Choose where to save your backup.");
    expect(apiMocks.backupWallet).not.toHaveBeenCalled();
  });

  it("opens the restore picker and shows picker errors without using an invalid path", async () => {
    const user = userEvent.setup();
    renderDialog({ ...locked, storage: "missing", can_restore: true });
    await user.click(screen.getByRole("button", { name: "Restore backup" }));
    apiMocks.chooseWalletBackupPath.mockRejectedValueOnce(new Error("The file picker could not open."));
    await user.click(screen.getByRole("button", { name: "Choose backup file…" }));
    expect(apiMocks.chooseWalletBackupPath).toHaveBeenCalledWith(true);
    expect(screen.getByRole("alert")).toHaveTextContent("The file picker could not open.");
    expect(apiMocks.restoreWallet).not.toHaveBeenCalled();
    apiMocks.chooseWalletBackupPath.mockResolvedValue("D:\\wallet.cmfd-backup");
    apiMocks.restoreWallet.mockResolvedValue(locked);
    await user.click(screen.getByRole("button", { name: "Choose backup file…" }));
    expect(screen.getByLabelText("Backup file to restore")).toHaveValue("D:\\wallet.cmfd-backup");
    await user.type(screen.getByLabelText("Wallet passphrase"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Restore wallet" }));
    expect(apiMocks.restoreWallet).toHaveBeenCalledWith("D:\\wallet.cmfd-backup", "correct horse battery staple");
  });

  it("unlocks an encrypted wallet without retaining the submitted passphrase", async () => {
    const user = userEvent.setup();
    apiMocks.unlockWallet.mockResolvedValue(unlocked);
    const { onStatusChange } = renderDialog(locked);
    await waitFor(() => expect(screen.getByRole("dialog", { name: "Unlock wallet" })).toHaveFocus());
    const passphrase = screen.getByLabelText("Wallet passphrase");

    await user.type(passphrase, "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Unlock wallet" }));

    expect(apiMocks.unlockWallet).toHaveBeenCalledWith("correct horse battery staple");
    expect(passphrase).toHaveValue("");
    await waitFor(() => expect(onStatusChange).toHaveBeenCalledWith(unlocked));
  });

  it("keeps the passphrase field focused across parent polling renders", async () => {
    const user = userEvent.setup();
    const props = {
      open: true,
      required: true,
      status: locked,
      statusError: null,
      onStatusChange: vi.fn(),
      onCompleted: vi.fn(),
      onRefresh: vi.fn(),
    };
    const view = render(<WalletSecurityDialog {...props} onClose={() => undefined} />);
    await waitFor(() => expect(screen.getByRole("dialog", { name: "Unlock wallet" })).toHaveFocus());
    const passphrase = screen.getByLabelText("Wallet passphrase");
    await user.click(passphrase);
    await user.type(passphrase, "correct horse");

    view.rerender(<WalletSecurityDialog {...props} onClose={() => undefined} />);
    await act(async () => {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    });

    expect(passphrase).toHaveFocus();
    expect(passphrase).toHaveValue("correct horse");
  });

  it("describes and validates the minimum in characters", async () => {
    const user = userEvent.setup();
    renderDialog(locked);

    expect(screen.getByText(/At least 12 characters/)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Wallet passphrase"), "éééééé");
    await user.click(screen.getByRole("button", { name: "Unlock wallet" }));

    expect(apiMocks.unlockWallet).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent("Use a passphrase containing at least 12 characters.");
  });

  it("requires a no-overwrite backup path and confirmation before migration", async () => {
    const user = userEvent.setup();
    const plaintext: WalletCustodyStatus = {
      ...locked,
      storage: "plaintext",
      unlocked: true,
      requires_migration: true,
    };
    apiMocks.migrateWalletEncryption.mockResolvedValue(locked);
    const { onStatusChange } = renderDialog(plaintext);
    await waitFor(() => expect(screen.getByRole("dialog", { name: "Encrypt existing wallet" })).toHaveFocus());

    apiMocks.chooseWalletBackupPath.mockResolvedValue("D:\\Offline\\wallet.cmfd-backup");
    await user.click(screen.getByRole("button", { name: "Choose save location…" }));
    await user.type(screen.getByLabelText("New wallet passphrase"), "correct horse battery staple");
    await user.type(screen.getByLabelText("Confirm passphrase"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Encrypt existing wallet" }));

    await waitFor(() => expect(apiMocks.migrateWalletEncryption).toHaveBeenCalledWith(
      "D:\\Offline\\wallet.cmfd-backup",
      "correct horse battery staple",
    ));
    expect(screen.getByLabelText("New wallet passphrase")).toHaveValue("");
    expect(screen.getByLabelText("Confirm passphrase")).toHaveValue("");
    await waitFor(() => expect(onStatusChange).toHaveBeenCalledWith(locked));
  });
});
