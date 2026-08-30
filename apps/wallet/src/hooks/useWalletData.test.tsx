import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MempoolSnapshot, NodeStatus, WalletSnapshot } from "../types";
import { useWalletData } from "./useWalletData";

const apiMocks = vi.hoisted(() => ({
  getNodeStatus: vi.fn(),
  getWalletSnapshot: vi.fn(),
  getMempool: vi.fn(),
}));

vi.mock("../api/nodeClient", () => apiMocks);

const status = { accepted_height: 7 } as NodeStatus;
const wallet = { accepted_height: 7 } as WalletSnapshot;
const mempool = { transactions: 0, bytes: 0, entries: [] } as MempoolSnapshot;

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

describe("useWalletData", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    apiMocks.getNodeStatus.mockReset();
    apiMocks.getWalletSnapshot.mockReset();
    apiMocks.getMempool.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("joins scheduled and manual refreshes without aborting or overlapping", async () => {
    const pendingStatus = deferred<NodeStatus>();
    const pendingWallet = deferred<WalletSnapshot>();
    const pendingMempool = deferred<MempoolSnapshot>();
    apiMocks.getNodeStatus.mockReturnValueOnce(pendingStatus.promise).mockResolvedValue(status);
    apiMocks.getWalletSnapshot.mockReturnValueOnce(pendingWallet.promise).mockResolvedValue(wallet);
    apiMocks.getMempool.mockReturnValueOnce(pendingMempool.promise).mockResolvedValue(mempool);

    const { result } = renderHook(() => useWalletData(4_000));
    expect(apiMocks.getNodeStatus).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(12_000);
    });
    const joinedRefresh = result.current.refresh();
    expect(result.current.refresh()).toBe(joinedRefresh);
    expect(apiMocks.getNodeStatus).toHaveBeenCalledTimes(1);
    expect(apiMocks.getWalletSnapshot).toHaveBeenCalledTimes(1);
    expect(apiMocks.getMempool).toHaveBeenCalledTimes(1);
    expect(apiMocks.getNodeStatus.mock.calls[0][0]).not.toHaveProperty("aborted", true);

    await act(async () => {
      pendingStatus.resolve(status);
      pendingWallet.resolve(wallet);
      pendingMempool.resolve(mempool);
      await joinedRefresh;
    });
    expect(result.current.loading).toBe(false);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_000);
    });
    expect(apiMocks.getNodeStatus).toHaveBeenCalledTimes(2);
    expect(apiMocks.getWalletSnapshot).toHaveBeenCalledTimes(2);
    expect(apiMocks.getMempool).toHaveBeenCalledTimes(2);
  });

  it("aborts the active refresh on unmount", async () => {
    let signal: AbortSignal | undefined;
    const waitForAbort = (incoming?: AbortSignal) => new Promise<never>((_resolve, reject) => {
      signal = incoming;
      incoming?.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
    });
    apiMocks.getNodeStatus.mockImplementation(waitForAbort);
    apiMocks.getWalletSnapshot.mockImplementation(waitForAbort);
    apiMocks.getMempool.mockImplementation(waitForAbort);

    const { unmount } = renderHook(() => useWalletData());
    expect(signal?.aborted).toBe(false);

    unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () => Promise.resolve());
  });

  it("keeps startup feedback active while the embedded node is opening", async () => {
    const starting = Object.assign(new Error("Opening wallet"), { code: "node_starting" });
    apiMocks.getNodeStatus.mockRejectedValueOnce(starting).mockResolvedValue(status);
    apiMocks.getWalletSnapshot.mockResolvedValue(wallet);
    apiMocks.getMempool.mockResolvedValue(mempool);

    const { result } = renderHook(() => useWalletData(4_000));
    await act(async () => Promise.resolve());

    expect(result.current.starting).toBe(true);
    expect(result.current.loading).toBe(true);
    expect(result.current.error).toBeNull();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_000);
    });
    expect(result.current.starting).toBe(false);
    expect(result.current.status).toBe(status);
  });
});
