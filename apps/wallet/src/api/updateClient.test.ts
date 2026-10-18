import { describe, expect, it, vi } from "vitest";

import { refusal } from "../test/updateFixtures";
import type { NativeInvoke } from "./nodeClient";
import {
  browserUpdateTransport,
  createTauriUpdateTransport,
  restartWithConfirmations,
  type RestartOptions,
} from "./updateClient";

describe("update transport", () => {
  it("calls the eight update commands with camelCase arguments", async () => {
    const invokeMock = vi.fn().mockResolvedValue({});
    const invoke: NativeInvoke = (command, args) => invokeMock(command, args);
    const transport = createTauriUpdateTransport(invoke);

    await transport.getUpdateStatus();
    await transport.setUpdateAutomatic(false);
    await transport.checkForUpdates();
    await transport.downloadUpdate(true);
    await transport.restartToUpdate({ stopMining: true, acceptUnconfirmed: false });
    await transport.retryUpdate("1.0.17", { stopMining: false, acceptUnconfirmed: true });
    await transport.runOlderAnyway("run anyway");
    await transport.removeOldVersions();

    expect(invokeMock.mock.calls).toEqual([
      ["get_update_status", undefined],
      ["set_update_automatic", { automatic: false }],
      ["check_for_updates", undefined],
      ["download_update", { allowCopy: true }],
      ["restart_to_update", { stopMining: true, acceptUnconfirmed: false }],
      ["retry_update", { version: "1.0.17", stopMining: false, acceptUnconfirmed: true }],
      ["run_older_anyway", { confirmText: "run anyway" }],
      ["remove_old_versions", undefined],
    ]);
  });

  it("keeps the wallet's code and message when it refuses", async () => {
    const invoke: NativeInvoke = () => Promise.reject(refusal("update_busy", "Finish the current send first."));
    await expect(createTauriUpdateTransport(invoke).restartToUpdate({
      stopMining: false,
      acceptUnconfirmed: false,
    })).rejects.toMatchObject({ code: "update_busy", message: "Finish the current send first.", status: 409 });
  });

  it("does not pretend the browser wallet updates itself", async () => {
    await expect(browserUpdateTransport.getUpdateStatus()).rejects.toMatchObject({
      code: "updates_desktop_only",
      status: 501,
    });
  });
});

describe("restart with confirmations", () => {
  const mining = refusal("update_mining_active", "Mining will stop.");
  const unconfirmed = refusal("update_unconfirmed", "2 of your transactions are unconfirmed.");

  it("asks before it stops mining and drops unconfirmed sends, and keeps both answers", async () => {
    const restart = vi.fn<(options: RestartOptions) => Promise<void>>()
      .mockRejectedValueOnce(mining)
      .mockRejectedValueOnce(unconfirmed)
      .mockResolvedValueOnce(undefined);
    const confirm = vi.fn().mockResolvedValue(true);

    await expect(restartWithConfirmations(restart, confirm)).resolves.toBe(true);

    expect(restart.mock.calls).toEqual([
      [{ stopMining: false, acceptUnconfirmed: false }],
      [{ stopMining: true, acceptUnconfirmed: false }],
      [{ stopMining: true, acceptUnconfirmed: true }],
    ]);
    expect(confirm.mock.calls).toEqual([
      ["Mining will stop.", "Stop mining and restart"],
      ["2 of your transactions are unconfirmed.", "Restart"],
    ]);
  });

  it("stops when the user says no", async () => {
    const restart = vi.fn<(options: RestartOptions) => Promise<void>>().mockRejectedValue(mining);
    await expect(restartWithConfirmations(restart, () => Promise.resolve(false))).resolves.toBe(false);
    expect(restart).toHaveBeenCalledTimes(1);
  });

  it("passes every other refusal on with its message", async () => {
    const restart = vi.fn<(options: RestartOptions) => Promise<void>>()
      .mockRejectedValue(refusal("update_busy", "Finish the current send, backup or restore first."));
    const confirm = vi.fn();
    await expect(restartWithConfirmations(restart, confirm)).rejects.toMatchObject({
      code: "update_busy",
      message: "Finish the current send, backup or restore first.",
    });
    expect(confirm).not.toHaveBeenCalled();
  });

  it("does not ask twice for the same thing", async () => {
    const restart = vi.fn<(options: RestartOptions) => Promise<void>>().mockRejectedValue(mining);
    await expect(restartWithConfirmations(restart, () => Promise.resolve(true))).rejects.toMatchObject({
      code: "update_mining_active",
    });
    expect(restart).toHaveBeenCalledTimes(2);
  });

  it("counts a restart already under way as started", async () => {
    const restart = vi.fn<(options: RestartOptions) => Promise<void>>()
      .mockRejectedValue(refusal("update_restarting", "The wallet is restarting to update."));
    await expect(restartWithConfirmations(restart, vi.fn())).resolves.toBe(true);
  });
});
