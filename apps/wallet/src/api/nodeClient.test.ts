import { describe, expect, it, vi } from "vitest";
import type { NativeInvoke } from "./nodeClient";
import { NodeApiError, createTauriNodeTransport } from "./nodeClient";

describe("Tauri node transport", () => {
  it("maps all native commands without retrying mutations", async () => {
    const invokeMock = vi.fn().mockResolvedValue({ ok: true });
    const invoke: NativeInvoke = (command, args) => invokeMock(command, args);
    const transport = createTauriNodeTransport(invoke);

    await transport.getNodeStatus();
    await transport.getWalletSnapshot();
    await transport.getMempool();
    await transport.getPeerSettings();
    await transport.updatePeerSettings(["192.168.1.20:18444"]);
    await transport.sendWalletTransaction({ recipient: "11".repeat(32), amount: "1", fee: "0.00000001" });
    await transport.consolidateWallet({ fee: "0.00000001", max_inputs: 12 });
    await transport.mineDevnetBlock("22".repeat(32), 50);
    await transport.getWalletCustodyStatus();
    await transport.unlockWallet("correct horse battery staple");
    await transport.lockWallet();
    await transport.backupWallet("C:\\offline\\wallet.cmfd-backup", "correct horse battery staple");
    await transport.migrateWalletEncryption("C:\\offline\\wallet.cmfd-backup", "correct horse battery staple");
    await transport.restoreWallet("C:\\offline\\wallet.cmfd-backup", "correct horse battery staple");

    expect(invokeMock.mock.calls).toEqual([
      ["get_node_status", undefined],
      ["get_wallet_snapshot", undefined],
      ["get_mempool_snapshot", undefined],
      ["get_peer_settings", undefined],
      ["update_peer_settings", { request: { peers: ["192.168.1.20:18444"] } }],
      ["send_wallet_transaction", { request: { recipient: "11".repeat(32), amount: "1", fee: "0.00000001" } }],
      ["consolidate_wallet", { request: { fee: "0.00000001", max_inputs: 12 } }],
      ["mine_devnet_block", { request: { miner: "22".repeat(32), attempts: 50 } }],
      ["get_wallet_custody_status", undefined],
      ["unlock_wallet", { request: { passphrase: "correct horse battery staple" } }],
      ["lock_wallet", undefined],
      ["backup_wallet", { request: { path: "C:\\offline\\wallet.cmfd-backup", passphrase: "correct horse battery staple" } }],
      ["migrate_wallet_encryption", { request: { path: "C:\\offline\\wallet.cmfd-backup", passphrase: "correct horse battery staple" } }],
      ["restore_wallet", { request: { path: "C:\\offline\\wallet.cmfd-backup", passphrase: "correct horse battery staple" } }],
    ]);
  });

  it("normalizes structured native failures", async () => {
    const invoke: NativeInvoke = vi.fn().mockRejectedValue({
      code: "wallet_insufficient_funds",
      message: "Wallet has insufficient funds",
      status: 422,
      retryable: false,
    });
    const transport = createTauriNodeTransport(invoke);

    await expect(transport.sendWalletTransaction({
      recipient: "11".repeat(32),
      amount: "1",
      fee: "0.00000001",
    })).rejects.toMatchObject({
      name: "NodeApiError",
      code: "wallet_insufficient_funds",
      status: 422,
      retryable: false,
    } satisfies Partial<NodeApiError>);
  });

  it("rejects an aborted read while allowing the native work to finish harmlessly", async () => {
    let resolveInvoke: ((value: unknown) => void) | undefined;
    const invokeMock = vi.fn((_command: string, _args?: Record<string, unknown>) => new Promise<unknown>((resolve) => {
      resolveInvoke = resolve;
    }));
    const invoke: NativeInvoke = <T>(command: string, args?: Record<string, unknown>) => (
      invokeMock(command, args) as Promise<T>
    );
    const transport = createTauriNodeTransport(invoke);
    const controller = new AbortController();

    const pending = transport.getNodeStatus(controller.signal);
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    resolveInvoke?.({ accepted_height: 0 });

    expect(invokeMock).toHaveBeenCalledTimes(1);
  });
});
