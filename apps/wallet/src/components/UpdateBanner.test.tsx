import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { publishUpdateStatus } from "../api/updateClient";
import { fakeUpdateTransport, refusal, updateStatus } from "../test/updateFixtures";
import { bannerView, formatCheckDate, UpdateBanner } from "./UpdateBanner";

const ready = updateStatus({ status: { state: "ready", version: "1.0.17", folder: "C:\\CF-Wallet\\v1.0.17" } });
const held = updateStatus({
  status: { state: "idle" },
  fallback: { version: "1.0.17", reason: "corrupt_block_log", after_data: true, held: true },
});

describe("update banner", () => {
  afterEach(cleanup);

  it("offers Restart to update and Later for a ready version", async () => {
    const transport = fakeUpdateTransport(ready);
    render(<UpdateBanner transport={transport} />);

    expect(await screen.findByText("Version 1.0.17 is ready.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Restart to update" }));

    expect(transport.restartToUpdate).toHaveBeenCalledWith({ stopMining: false, acceptUnconfirmed: false });
    expect(await screen.findByText("Restarting the wallet…")).toBeInTheDocument();
  });

  it("hides the version after Later and shows a newer one", async () => {
    const transport = fakeUpdateTransport(ready);
    render(<UpdateBanner transport={transport} />);

    await userEvent.click(await screen.findByRole("button", { name: "Later" }));
    expect(screen.queryByText("Version 1.0.17 is ready.")).not.toBeInTheDocument();
    expect(transport.restartToUpdate).not.toHaveBeenCalled();

    act(() => publishUpdateStatus(updateStatus({
      status: { state: "ready", version: "1.0.18", folder: "C:\\CF-Wallet\\v1.0.18" },
    })));
    expect(await screen.findByText("Version 1.0.18 is ready.")).toBeInTheDocument();
  });

  it("shows the wallet's plain refusal during a send, backup or restore", async () => {
    const transport = fakeUpdateTransport(ready);
    transport.restartToUpdate.mockRejectedValue(refusal(
      "update_busy",
      "Finish the current send, backup or restore first, then restart to update.",
    ));
    render(<UpdateBanner transport={transport} />);

    await userEvent.click(await screen.findByRole("button", { name: "Restart to update" }));

    expect(await screen.findByText("Finish the current send, backup or restore first, then restart to update."))
      .toBeInTheDocument();
    expect(screen.queryByText("Restarting the wallet…")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Restart to update" })).toBeEnabled();
  });

  it("asks before it stops mining, then restarts with mining stopped", async () => {
    const transport = fakeUpdateTransport(ready);
    transport.restartToUpdate
      .mockRejectedValueOnce(refusal(
        "update_mining_active",
        "Mining will stop. After the restart, unlock the wallet and start mining again.",
      ))
      .mockResolvedValueOnce(undefined);
    render(<UpdateBanner transport={transport} />);

    await userEvent.click(await screen.findByRole("button", { name: "Restart to update" }));
    expect(await screen.findByText("Mining will stop. After the restart, unlock the wallet and start mining again."))
      .toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Stop mining and restart" }));

    expect(transport.restartToUpdate.mock.calls).toEqual([
      [{ stopMining: false, acceptUnconfirmed: false }],
      [{ stopMining: true, acceptUnconfirmed: false }],
    ]);
  });

  it("does nothing more when the user cancels", async () => {
    const transport = fakeUpdateTransport(ready);
    transport.restartToUpdate.mockRejectedValue(refusal("update_unconfirmed", "1 of your transactions are unconfirmed."));
    render(<UpdateBanner transport={transport} />);

    await userEvent.click(await screen.findByRole("button", { name: "Restart to update" }));
    await userEvent.click(await screen.findByRole("button", { name: "Cancel" }));

    expect(transport.restartToUpdate).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("1 of your transactions are unconfirmed.")).not.toBeInTheDocument();
  });

  it("offers Download and Later when updates are not automatic", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      automatic: false,
      status: { state: "available", version: "1.0.17" },
    }));
    render(<UpdateBanner transport={transport} />);

    await userEvent.click(await screen.findByRole("button", { name: "Download" }));
    expect(transport.downloadUpdate).toHaveBeenCalledWith(false);
  });

  it("asks Retry or Run anyway while the wallet is held, and never Restart to update", async () => {
    const transport = fakeUpdateTransport(held);
    let refreshed = 0;
    render(<UpdateBanner transport={transport} onRunAnyway={() => { refreshed += 1; }} />);

    expect(await screen.findByText("Version 1.0.17 stopped after it opened your wallet data")).toBeInTheDocument();
    expect(screen.getByText(/corrupt_block_log/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Restart to update" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Later" })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Run 1.0.16 anyway" }));
    const runAnyway = screen.getByRole("button", { name: "Run anyway" });
    expect(runAnyway).toBeDisabled();

    transport.runOlderAnyway.mockRejectedValueOnce(refusal(
      "update_confirmation_required",
      "Type \"run anyway\" to run this older version on the wallet data.",
    ));
    await userEvent.type(screen.getByLabelText(/type "run anyway"/), "run");
    await userEvent.click(runAnyway);
    expect(await screen.findByText("Type \"run anyway\" to run this older version on the wallet data."))
      .toBeInTheDocument();
    expect(refreshed).toBe(0);

    await userEvent.type(screen.getByLabelText(/type "run anyway"/), " anyway");
    await userEvent.click(screen.getByRole("button", { name: "Run anyway" }));
    expect(transport.runOlderAnyway).toHaveBeenLastCalledWith("run anyway");
    expect(refreshed).toBe(1);
  });

  it("says when the held version's installed files are damaged, and offers Reinstall", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      status: { state: "damaged", version: "1.0.17", reason: "common-foundry-wallet.exe is missing or changed" },
      fallback: {
        version: "1.0.17",
        reason: "its installed files are damaged: common-foundry-wallet.exe is missing or changed",
        after_data: true,
        held: true,
      },
    }));
    render(<UpdateBanner transport={transport} />);

    expect(await screen.findByText("Version 1.0.17's installed files are damaged")).toBeInTheDocument();
    expect(screen.queryByText("Version 1.0.17 stopped after it opened your wallet data")).not.toBeInTheDocument();
    expect(screen.getByText(/Run anyway lasts until this wallet closes/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run 1.0.16 anyway" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Later" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Reinstall 1.0.17" }));
    expect(transport.downloadUpdate).toHaveBeenCalledWith(false);
  });

  it("keeps the plain held view without Reinstall for other reasons", async () => {
    const transport = fakeUpdateTransport(held);
    render(<UpdateBanner transport={transport} />);

    expect(await screen.findByText("Version 1.0.17 stopped after it opened your wallet data")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Reinstall/ })).not.toBeInTheDocument();
  });

  it("retries the held version", async () => {
    const transport = fakeUpdateTransport(held);
    render(<UpdateBanner transport={transport} />);

    await userEvent.click(await screen.findByRole("button", { name: "Retry 1.0.17" }));
    expect(transport.retryUpdate).toHaveBeenCalledWith("1.0.17", { stopMining: false, acceptUnconfirmed: false });
  });

  it("says why a version failed to start and offers Retry", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      status: { state: "failed_to_start", version: "1.0.17", reason: "it exited with code 1" },
    }));
    render(<UpdateBanner transport={transport} />);

    expect(await screen.findByText("Version 1.0.17 failed to start")).toBeInTheDocument();
    expect(screen.getByText(/it exited with code 1\. This version \(1\.0\.16\) is running instead\./)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry 1.0.17" }));
    expect(transport.retryUpdate).toHaveBeenCalledWith("1.0.17", { stopMining: false, acceptUnconfirmed: false });
  });

  it("says why the last restart could not start the update", async () => {
    const transport = fakeUpdateTransport(updateStatus({ restart_failed: "access is denied" }));
    render(<UpdateBanner transport={transport} />);

    expect(await screen.findByText("The update could not be started")).toBeInTheDocument();
    expect(screen.getByText(/access is denied/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(transport.restartToUpdate).toHaveBeenCalled();
  });

  it("explains a version that could not start before it opened the wallet data", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      fallback: { version: "1.0.17", reason: "the model bank is missing", after_data: false, held: false },
    }));
    render(<UpdateBanner transport={transport} />);

    expect(await screen.findByText("Version 1.0.17 could not start")).toBeInTheDocument();
    expect(screen.getByText(/the model bank is missing\. This version \(1\.0\.16\) is running instead\./))
      .toBeInTheDocument();
  });

  it("says a ready version starts on the next launch", async () => {
    render(<UpdateBanner transport={fakeUpdateTransport(ready)} />);

    expect(await screen.findByText("It starts the next time you open the wallet, or now with Restart to update."))
      .toBeInTheDocument();
  });

  it("asks before it copies the model bank, with updates automatic", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      status: { state: "needs_copy_consent", version: "1.0.17", bytes: 6_400_000_000 },
    }));
    render(<UpdateBanner transport={transport} />);

    expect(await screen.findByText("Version 1.0.17 waits for your consent to install")).toBeInTheDocument();
    expect(screen.getByText(/OneDrive, or a USB or exFAT drive.*uses 6\.4 GB more disk space/)).toBeInTheDocument();
    expect(transport.downloadUpdate).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Copy and install" }));
    expect(transport.downloadUpdate).toHaveBeenCalledWith(true);
  });

  it("keeps showing a download asked for in the banner until it needs consent", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      automatic: false,
      status: { state: "available", version: "1.0.17" },
    }));
    const downloading = updateStatus({ automatic: false, status: { state: "downloading", version: "1.0.17" } });
    const consent = updateStatus({
      automatic: false,
      status: { state: "needs_copy_consent", version: "1.0.17", bytes: 6_400_000_000 },
    });
    transport.downloadUpdate.mockImplementationOnce(async () => {
      transport.getUpdateStatus.mockResolvedValue(downloading);
      return downloading;
    });
    render(<UpdateBanner transport={transport} />);

    await userEvent.click(await screen.findByRole("button", { name: "Download" }));
    expect(await screen.findByText("Downloading version 1.0.17…")).toBeInTheDocument();

    transport.getUpdateStatus.mockResolvedValue(consent);
    act(() => publishUpdateStatus(consent));
    await userEvent.click(await screen.findByRole("button", { name: "Copy and install" }));
    expect(transport.downloadUpdate.mock.calls).toEqual([[false], [true]]);
  });

  it("does not announce a background download", async () => {
    const transport = fakeUpdateTransport(updateStatus({ status: { state: "downloading", version: "1.0.17" } }));
    const { container } = render(<UpdateBanner transport={transport} />);
    await vi.waitFor(() => expect(transport.getUpdateStatus).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("says an install failed, offers Try again, and Later hides it", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      status: {
        state: "install_failed",
        version: "1.0.17",
        reason: "production-v4/cmfd-v4-replay is missing",
        retry_automatically: false,
      },
    }));
    render(<UpdateBanner transport={transport} />);

    expect(await screen.findByText("Version 1.0.17 could not be installed")).toBeInTheDocument();
    expect(screen.getByText(/cmfd-v4-replay is missing\. It is not tried again on its own\. Antivirus/))
      .toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(transport.downloadUpdate).toHaveBeenCalledWith(false);

    await userEvent.click(screen.getByRole("button", { name: "Later" }));
    expect(screen.queryByText("Version 1.0.17 could not be installed")).not.toBeInTheDocument();
  });

  it("says when an update must be installed by hand or did not pass its checks", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      status: { state: "manual", version: "1.0.17", reason: "this update changes the proof bank; install it by hand" },
    }));
    render(<UpdateBanner transport={transport} />);

    expect(await screen.findByText("Version 1.0.17 must be installed by hand")).toBeInTheDocument();
    expect(screen.getByText(/changes the proof bank/)).toBeInTheDocument();

    act(() => publishUpdateStatus(updateStatus({
      status: { state: "not_verified", version: "1.0.17", reason: "the signature does not match" },
    })));
    expect(await screen.findByText("Version 1.0.17 did not pass its checks, so it was not installed"))
      .toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Later" })).toBeEnabled();
  });

  it("lets Later hide a fallback notice and then shows the ready version behind it", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      status: { state: "ready", version: "1.0.18", folder: "C:\\CF-Wallet\\v1.0.18" },
      fallback: { version: "1.0.17", reason: "corrupt_block_log", after_data: true, held: false },
    }));
    render(<UpdateBanner transport={transport} />);

    expect(await screen.findByText(/You chose to run 1\.0\.16 anyway/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Later" }));
    expect(screen.queryByText(/You chose to run 1\.0\.16 anyway/)).not.toBeInTheDocument();
    expect(await screen.findByText("Version 1.0.18 is ready.")).toBeInTheDocument();
  });

  it("lets Later hide a failed restart until another reason comes", async () => {
    const transport = fakeUpdateTransport(updateStatus({ restart_failed: "access is denied" }));
    render(<UpdateBanner transport={transport} />);

    await userEvent.click(await screen.findByRole("button", { name: "Later" }));
    expect(screen.queryByText("The update could not be started")).not.toBeInTheDocument();

    act(() => publishUpdateStatus(updateStatus({ restart_failed: "the file is in use" })));
    expect(await screen.findByText(/the file is in use/)).toBeInTheDocument();
  });

  it("drops an open question when its notice goes away", async () => {
    const transport = fakeUpdateTransport(ready);
    transport.restartToUpdate.mockRejectedValue(refusal(
      "update_mining_active",
      "Mining will stop. After the restart, unlock the wallet and start mining again.",
    ));
    render(<UpdateBanner transport={transport} />);

    await userEvent.click(await screen.findByRole("button", { name: "Restart to update" }));
    expect(await screen.findByRole("button", { name: "Stop mining and restart" })).toBeInTheDocument();

    act(() => publishUpdateStatus(updateStatus()));
    act(() => publishUpdateStatus(ready));

    expect(await screen.findByRole("button", { name: "Restart to update" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Stop mining and restart" })).not.toBeInTheDocument();
    expect(transport.restartToUpdate).toHaveBeenCalledTimes(1);
  });

  it("keeps the node's message for a held wallet when the update status cannot be read", async () => {
    const transport = fakeUpdateTransport(held);
    transport.getUpdateStatus.mockRejectedValue(refusal("update_request_failed", "The update request failed"));
    render(<UpdateBanner transport={transport} heldMessage="Version 1.0.17 stopped after it had opened this wallet's data." />);

    expect(await screen.findByText("This wallet waits for your choice")).toBeInTheDocument();
    expect(screen.getByText("Version 1.0.17 stopped after it had opened this wallet's data.")).toBeInTheDocument();
    expect(await screen.findByText(/could not be read: The update request failed/)).toBeInTheDocument();

    transport.getUpdateStatus.mockResolvedValue(held);
    await userEvent.click(screen.getByRole("button", { name: "Check again" }));
    expect(await screen.findByRole("button", { name: "Retry 1.0.17" })).toBeInTheDocument();
  });

  it("says an installed version is damaged and offers Reinstall", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      status: { state: "damaged", version: "1.0.17", reason: "common-foundry-wallet.exe is missing or changed" },
    }));
    render(<UpdateBanner transport={transport} />);

    expect(await screen.findByText("Version 1.0.17 is installed, but some of its files are missing or changed"))
      .toBeInTheDocument();
    expect(screen.getByText(/missing or changed\. Antivirus software may have removed one of its files\./))
      .toBeInTheDocument();
    expect(screen.queryByText(/is ready/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Reinstall" }));
    expect(transport.downloadUpdate).toHaveBeenCalledWith(false);
  });

  it("says so quietly once checks keep failing, and not before", () => {
    const now = 1_800_000_000;
    const failing = (failures: number, since: number) => updateStatus({
      status: { state: "check_failed", reason: "curl exit 35" },
      check_failures: failures,
      check_failed_since: since,
    });
    // One failure, or three in a day: nothing yet.
    expect(bannerView(failing(1, now - 60), new Set(), null, now)).toBeNull();
    expect(bannerView(failing(3, now - 20 * 3600), new Set(), null, now)).toBeNull();
    // Four in a row, or 48 hours without a check that worked.
    expect(bannerView(failing(4, now - 20 * 3600), new Set(), null, now))
      .toEqual({ kind: "check_stale", since: now - 20 * 3600 });
    expect(bannerView(failing(1, now - 48 * 3600), new Set(), null, now))
      .toEqual({ kind: "check_stale", since: now - 48 * 3600 });
    // A check that worked clears it, and anything more urgent comes first.
    expect(bannerView(updateStatus({ check_failures: 0, check_failed_since: null }), new Set(), null, now)).toBeNull();
    expect(bannerView({
      ...failing(9, now - 72 * 3600),
      status: { state: "ready", version: "1.0.17", folder: "C:\\CF-Wallet\\v1.0.17" },
    }, new Set(), null, now)).toEqual({ kind: "ready", version: "1.0.17" });
  });

  it("shows the stale check line with its date, and Later hides it", async () => {
    const since = Math.floor(Date.now() / 1000) - 3 * 24 * 3600;
    const transport = fakeUpdateTransport(updateStatus({
      status: { state: "check_failed", reason: "curl exit 35" },
      check_failures: 5,
      check_failed_since: since,
    }));
    render(<UpdateBanner transport={transport} />);

    expect(await screen.findByText(`Updates could not be checked since ${formatCheckDate(since)}.`))
      .toBeInTheDocument();
    expect(screen.getByText("Network → Updates has details.")).toBeInTheDocument();
    expect(screen.getByRole("status")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Later" }));
    expect(screen.queryByText(/could not be checked since/)).not.toBeInTheDocument();
  });

  it("drops an error when its notice goes away", async () => {
    const failed = updateStatus({
      status: { state: "install_failed", version: "1.0.17", reason: "disk full", retry_automatically: true },
    });
    const transport = fakeUpdateTransport(failed);
    transport.downloadUpdate.mockRejectedValue(refusal("update_busy", "Another update action is running."));
    render(<UpdateBanner transport={transport} />);

    await userEvent.click(await screen.findByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Another update action is running.")).toBeInTheDocument();

    act(() => publishUpdateStatus(ready));
    expect(await screen.findByText("Version 1.0.17 is ready.")).toBeInTheDocument();
    expect(screen.queryByText("Another update action is running.")).not.toBeInTheDocument();
  });

  it("shows nothing when the wallet is up to date", async () => {
    const transport = fakeUpdateTransport(updateStatus());
    const { container } = render(<UpdateBanner transport={transport} />);
    await vi.waitFor(() => expect(transport.getUpdateStatus).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });
});
