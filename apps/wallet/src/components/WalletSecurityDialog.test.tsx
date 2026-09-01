import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { WalletCustodyStatus } from "../types";
import { WalletSecurityDialog } from "./WalletSecurityDialog";

const apiMocks = vi.hoisted(() => ({
  backupWallet: vi.fn(),
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

  it("unlocks an encrypted wallet without retaining the submitted passphrase", async () => {
    const user = userEvent.setup();
    apiMocks.unlockWallet.mockResolvedValue(unlocked);
    const { onStatusChange } = renderDialog(locked);
    const passphrase = screen.getByLabelText("Wallet passphrase");

    await user.type(passphrase, "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Unlock wallet" }));

    expect(apiMocks.unlockWallet).toHaveBeenCalledWith("correct horse battery staple");
    expect(passphrase).toHaveValue("");
    await waitFor(() => expect(onStatusChange).toHaveBeenCalledWith(unlocked));
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

    fireEvent.change(screen.getByLabelText("New backup file"), {
      target: { value: "D:\\Offline\\wallet.cmfd-backup" },
    });
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
