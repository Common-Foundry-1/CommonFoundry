import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { consolidateWallet } from "../api/nodeClient";
import type { NodeStatus, WalletSnapshot } from "../types";
import { autoConsolidationReason, useAutoConsolidation } from "./useAutoConsolidation";

vi.mock("../api/nodeClient", () => ({
  usesEmbeddedNode: true,
  consolidateWallet: vi.fn(),
}));

const status = {
  network: "Mainnet",
  network_id: "11".repeat(32),
  accepted_height: 500,
  tip: "22".repeat(32),
  storage_healthy: true,
  peers: [{ active_connections: 1, remote_height: 500, remote_tip: "22".repeat(32) }],
} as NodeStatus;

const wallet = {
  network: "Mainnet",
  destination: "33".repeat(32),
  accepted_height: 500,
  spendable_utxo_count: 80,
  reserved_utxo_count: 0,
  history: [],
} as unknown as WalletSnapshot;

describe("automatic consolidation", () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.mocked(consolidateWallet).mockReset().mockResolvedValue({} as Awaited<ReturnType<typeof consolidateWallet>>);
  });

  afterEach(() => cleanup());

  it("requires an unlocked wallet, healthy matching tip, and no pending wallet activity", () => {
    expect(autoConsolidationReason(status, wallet, false, 64)).toMatch(/unlock/);
    expect(autoConsolidationReason({ ...status, storage_healthy: false }, wallet, true, 64)).toMatch(/storage/);
    expect(autoConsolidationReason({ ...status, peers: [] }, wallet, true, 64)).toMatch(/peer/);
    expect(autoConsolidationReason(status, { ...wallet, reserved_utxo_count: 1 }, true, 64)).toMatch(/pending/);
    expect(autoConsolidationReason(status, { ...wallet, history: [{ status: "pending" }] } as WalletSnapshot, true, 64)).toMatch(/pending/);
    expect(autoConsolidationReason(status, { ...wallet, spendable_utxo_count: 63 }, true, 64)).toMatch(/64/);
    expect(autoConsolidationReason(status, wallet, true, 64)).toBeNull();
  });

  it("stays off by default and submits only one capped batch across refresh and remount", async () => {
    const refresh = vi.fn().mockResolvedValue(undefined);
    const now = new Date();
    const hook = renderHook(
      ({ updated }) => useAutoConsolidation(status, wallet, true, true, updated, refresh),
      { initialProps: { updated: now } },
    );
    expect(consolidateWallet).not.toHaveBeenCalled();

    act(() => hook.result.current.setSettings({ enabled: true, threshold: 64 }));
    await waitFor(() => expect(consolidateWallet).toHaveBeenCalledWith({
      fee: "0.10000000", max_inputs: 80, max_fee_basis_points: 100,
    }));
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));

    hook.rerender({ updated: new Date(now.getTime() + 4_000) });
    expect(consolidateWallet).toHaveBeenCalledTimes(1);
    hook.unmount();

    const reopened = renderHook(() => useAutoConsolidation(status, wallet, true, true, new Date(now.getTime() + 8_000), refresh));
    await waitFor(() => expect(reopened.result.current.settings.enabled).toBe(true));
    expect(consolidateWallet).toHaveBeenCalledTimes(1);
    expect(reopened.result.current.waitingForBlock).toBe(true);
  });

  it("does not submit from a saved setting while the node is offline", async () => {
    window.localStorage.setItem(`cmfd:auto-consolidation:v1:${status.network_id}:${wallet.destination}`,
      JSON.stringify({ enabled: true, threshold: 64 }));
    const refresh = vi.fn().mockResolvedValue(undefined);
    const hook = renderHook(() => useAutoConsolidation(status, wallet, true, false, new Date(), refresh));
    await waitFor(() => expect(hook.result.current.settings.enabled).toBe(true));
    expect(hook.result.current.reason).toMatch(/fresh node data/);
    expect(consolidateWallet).not.toHaveBeenCalled();
  });

  it("keeps a failed attempt in cooldown instead of retrying on the next render", async () => {
    vi.mocked(consolidateWallet).mockRejectedValue(new Error("fee cap exceeded"));
    const refresh = vi.fn().mockResolvedValue(undefined);
    const hook = renderHook(() => useAutoConsolidation(status, wallet, true, true, new Date(), refresh));
    act(() => hook.result.current.setSettings({ enabled: true, threshold: 64 }));
    await waitFor(() => expect(hook.result.current.error).toBe("fee cap exceeded"));
    hook.rerender();
    expect(consolidateWallet).toHaveBeenCalledTimes(1);
    expect(hook.result.current.coolingDown).toBe(true);
  });
});
