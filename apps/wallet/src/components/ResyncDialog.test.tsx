import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ChainResyncReport, WalletCustodyStatus } from "../types";
import { ResyncDialog, formatStorageSize, resyncCompletedMessage } from "./ResyncDialog";

const apiMocks = vi.hoisted(() => ({ resyncChain: vi.fn() }));

vi.mock("../api/nodeClient", () => apiMocks);

const locked: WalletCustodyStatus = {
  network: "ProductionV4 Testnet-1",
  storage: "encrypted",
  unlocked: false,
  requires_migration: false,
  can_restore: false,
  data_directory: "C:\wallet-data",
  destination: null,
};

function renderDialog() {
  const props = {
    onClose: vi.fn(),
    onStatusChange: vi.fn(),
    onCompleted: vi.fn(),
    onRefresh: vi.fn(),
  };
  render(<ResyncDialog open {...props} />);
  return props;
}

describe("ResyncDialog", () => {
  afterEach(() => {
    cleanup();
    apiMocks.resyncChain.mockReset();
  });

  it("resyncs once on confirmation and reports the new wallet state", async () => {
    const user = userEvent.setup();
    let finish!: (report: ChainResyncReport) => void;
    apiMocks.resyncChain.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    const props = renderDialog();

    await user.click(screen.getByRole("button", { name: "Resync chain" }));
    expect(screen.getByText("Moving the stored chain aside…")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Resync chain" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
    await user.keyboard("{Escape}");
    expect(props.onClose).not.toHaveBeenCalled();

    finish({ custody: locked, moved_to: "/wallet-data/resync-1", moved_bytes: 52_400_000_000 });
    await vi.waitFor(() => expect(props.onClose).toHaveBeenCalledTimes(1));
    expect(apiMocks.resyncChain).toHaveBeenCalledTimes(1);
    expect(props.onStatusChange).toHaveBeenCalledWith(locked);
    expect(props.onCompleted).toHaveBeenCalledWith(
      "The stored chain (52.4 GB) was moved to /wallet-data/resync-1. "
        + "You can delete that folder once the wallet has synced again. "
        + "Unlock the wallet to download the chain again.",
    );
    expect(props.onRefresh).toHaveBeenCalledTimes(1);
  });

  it("says where the chain went, how large it is and what comes next", () => {
    expect(formatStorageSize(512)).toBe("512 bytes");
    expect(formatStorageSize(3_400_000)).toBe("3.4 MB");
    const unlocked = { ...locked, unlocked: true };
    expect(resyncCompletedMessage({ custody: unlocked, moved_to: "/data/resync-2", moved_bytes: 1_500_000_000 }))
      .toBe(
        "The stored chain (1.5 GB) was moved to /data/resync-2. "
          + "You can delete that folder once the wallet has synced again. "
          + "The wallet is downloading the chain again.",
      );
  });

  it("keeps the dialog open with the reason when the resync fails", async () => {
    const user = userEvent.setup();
    apiMocks.resyncChain.mockRejectedValue(
      new Error("The stored chain could not be moved aside. Close and reopen the wallet, then try again."),
    );
    const props = renderDialog();

    await user.click(screen.getByRole("button", { name: "Resync chain" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("could not be moved aside");
    expect(props.onClose).not.toHaveBeenCalled();
    expect(props.onStatusChange).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(props.onClose).toHaveBeenCalledTimes(1);
  });
});
