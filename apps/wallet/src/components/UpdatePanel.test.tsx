import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { fakeUpdateTransport, refusal, updateStatus } from "../test/updateFixtures";
import { UpdatePanel } from "./UpdatePanel";

describe("updates card", () => {
  afterEach(cleanup);

  it("shows Update automatically switched on by default and saves a change", async () => {
    const transport = fakeUpdateTransport(updateStatus());
    transport.setUpdateAutomatic.mockResolvedValue(updateStatus({ automatic: false }));
    render(<UpdatePanel transport={transport} />);

    const toggle = await screen.findByRole("switch", { name: "Update automatically" });
    expect(await screen.findByText("Up to date.")).toBeInTheDocument();
    expect(toggle).toBeChecked();
    expect(screen.getByText("Version 1.0.16")).toBeInTheDocument();

    await userEvent.click(toggle);
    expect(transport.setUpdateAutomatic).toHaveBeenCalledWith(false);
    expect(await screen.findByRole("switch", { name: "Update automatically" })).not.toBeChecked();
    expect(screen.getByText(/Nothing is downloaded until you choose Download/)).toBeInTheDocument();
  });

  it("with the switch off, says a version is available and offers Download", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      automatic: false,
      status: { state: "available", version: "1.0.17" },
    }));
    render(<UpdatePanel transport={transport} />);

    expect(await screen.findByText("Version 1.0.17 is available.")).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "Update automatically" })).not.toBeChecked();
    await userEvent.click(screen.getByRole("button", { name: "Download" }));
    expect(transport.downloadUpdate).toHaveBeenCalledWith(false);
  });

  it("checks now", async () => {
    const transport = fakeUpdateTransport(updateStatus({ last_checked_at: 1_760_000_000 }));
    const checking = updateStatus({ status: { state: "checking" } });
    transport.checkForUpdates.mockResolvedValue(checking);
    render(<UpdatePanel transport={transport} />);

    expect(await screen.findByText(/^Up to date \(checked .+\)\.$/)).toBeInTheDocument();
    transport.getUpdateStatus.mockResolvedValue(checking);
    await userEvent.click(screen.getByRole("button", { name: "Check now" }));
    expect(transport.checkForUpdates).toHaveBeenCalledTimes(1);
    expect(await screen.findByText("Checking for updates…")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check now" })).toBeDisabled();
  });

  it("copies the model bank only after the user agrees", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      status: { state: "needs_copy_consent", version: "1.0.17", bytes: 6_400_000_000 },
    }));
    render(<UpdatePanel transport={transport} />);

    expect(await screen.findByText(/uses 6\.4 GB more disk space/)).toBeInTheDocument();
    expect(transport.downloadUpdate).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Copy and install" }));
    expect(transport.downloadUpdate).toHaveBeenCalledWith(true);
  });

  it("restarts a ready version and shows a refusal plainly", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      status: { state: "ready", version: "1.0.17", folder: "C:\\CF-Wallet\\v1.0.17" },
    }));
    transport.restartToUpdate.mockRejectedValue(refusal(
      "update_tx_pending",
      "1 of your transactions may not have reached the network yet.",
    ));
    render(<UpdatePanel transport={transport} />);

    await userEvent.click(await screen.findByRole("button", { name: "Restart to update" }));
    expect(await screen.findByText("1 of your transactions may not have reached the network yet.")).toBeInTheDocument();
  });

  it("does not offer Restart to update while the wallet waits for Retry or Run anyway", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      status: { state: "ready", version: "1.0.18", folder: "C:\\CF-Wallet\\v1.0.18" },
      fallback: { version: "1.0.17", reason: "corrupt", after_data: true, held: true },
    }));
    render(<UpdatePanel transport={transport} />);

    expect(await screen.findByText(/Version 1\.0\.18 is ready/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Restart to update" })).not.toBeInTheDocument();
  });

  it("turns everything off when a launch option disabled updates", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      disabled_by_launch_option: true,
      status: { state: "disabled" },
    }));
    render(<UpdatePanel transport={transport} />);

    expect(await screen.findByText(/turned off for this run by a launch option/)).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "Update automatically" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Check now" })).toBeDisabled();
    // The saved switch is on, but it does not apply to this run.
    expect(screen.getByRole("switch", { name: "Update automatically" })).not.toBeChecked();
    expect(screen.getByText("Turned off for this run by a launch option. Without it, the saved setting applies again."))
      .toBeInTheDocument();
    expect(screen.queryByText(/downloads them and installs them/)).not.toBeInTheDocument();
  });

  it("says an installed version is damaged and reinstalls it", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      status: { state: "damaged", version: "1.0.17", reason: "common-foundry-wallet.exe is missing or changed" },
    }));
    render(<UpdatePanel transport={transport} />);

    expect(await screen.findByText(
      "Version 1.0.17 is installed but damaged: common-foundry-wallet.exe is missing or changed. "
        + "Antivirus software may have removed one of its files. Reinstall downloads it again.",
    )).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Reinstall" }));
    expect(transport.downloadUpdate).toHaveBeenCalledWith(false);
  });

  it("lists old versions by their files and removes them after a confirmation", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      old_versions: [{ path: "C:\\CF-Wallet\\v1.0.14", bytes: 7_100_000_000 }],
    }));
    transport.removeOldVersions.mockResolvedValue(updateStatus());
    render(<UpdatePanel transport={transport} />);

    expect(await screen.findByText("C:\\CF-Wallet\\v1.0.14")).toBeInTheDocument();
    expect(screen.getByText("7.1 GB of files in folder")).toBeInTheDocument();
    expect(screen.queryByText(/freed/)).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Remove old versions" }));
    expect(transport.removeOldVersions).not.toHaveBeenCalled();
    const question = screen.getByRole("alertdialog", { name: "Confirm removal" });
    await userEvent.click(within(question).getByRole("button", { name: "Delete" }));

    expect(transport.removeOldVersions).toHaveBeenCalledTimes(1);
    expect(await screen.findByText("Up to date.")).toBeInTheDocument();
    expect(screen.queryByText("C:\\CF-Wallet\\v1.0.14")).not.toBeInTheDocument();
  });

  it("shows what is left after a removal that only partly worked", async () => {
    const v14 = { path: "D:/CF-Wallet/v1.0.14", bytes: 7_100_000_000 };
    const v13 = { path: "D:/CF-Wallet/v1.0.13", bytes: 7_000_000_000 };
    const transport = fakeUpdateTransport(updateStatus({ old_versions: [v14, v13] }));
    transport.removeOldVersions.mockImplementation(async () => {
      transport.getUpdateStatus.mockResolvedValue(updateStatus({ old_versions: [v13] }));
      throw refusal("update_remove_failed", "Some old versions could not be removed: D:/CF-Wallet/v1.0.13: in use");
    });
    render(<UpdatePanel transport={transport} />);

    await userEvent.click(await screen.findByRole("button", { name: "Remove old versions" }));
    await userEvent.click(within(screen.getByRole("alertdialog", { name: "Confirm removal" }))
      .getByRole("button", { name: "Delete" }));

    expect(await screen.findByText(/could not be removed: .*v1\.0\.13: in use/)).toBeInTheDocument();
    expect(screen.queryByText("D:/CF-Wallet/v1.0.14")).not.toBeInTheDocument();
    expect(screen.getByText("D:/CF-Wallet/v1.0.13")).toBeInTheDocument();
  });

  it("says why an install failed and lets the user try again", async () => {
    const transport = fakeUpdateTransport(updateStatus({
      status: {
        state: "install_failed",
        version: "1.0.17",
        reason: "antivirus software removed a file",
        retry_automatically: false,
      },
    }));
    render(<UpdatePanel transport={transport} />);

    expect(await screen.findByText("Version 1.0.17 could not be installed: antivirus software removed a file"))
      .toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(transport.downloadUpdate).toHaveBeenCalledWith(false);
  });
});
