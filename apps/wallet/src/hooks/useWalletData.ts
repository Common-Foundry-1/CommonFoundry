import { useCallback, useEffect, useRef, useState } from "react";
import { getMempool, getNodeStatus, getWalletSnapshot } from "../api/nodeClient";
import type { MempoolSnapshot, NodeStatus, WalletSnapshot } from "../types";

interface WalletDataState {
  status: NodeStatus | null;
  wallet: WalletSnapshot | null;
  mempool: MempoolSnapshot | null;
  loading: boolean;
  starting: boolean;
  refreshing: boolean;
  error: string | null;
  lastUpdated: Date | null;
}

const INITIAL_STATE: WalletDataState = {
  status: null,
  wallet: null,
  mempool: null,
  loading: true,
  starting: true,
  refreshing: false,
  error: null,
  lastUpdated: null,
};

export function useWalletData(refreshInterval = 4_000) {
  const [state, setState] = useState<WalletDataState>(INITIAL_STATE);
  const requestRef = useRef<AbortController | null>(null);
  const inFlightRef = useRef<Promise<void> | null>(null);

  const refresh = useCallback((): Promise<void> => {
    if (inFlightRef.current) return inFlightRef.current;

    const controller = new AbortController();
    requestRef.current = controller;
    setState((current) => ({ ...current, refreshing: !current.loading }));

    const request = (async () => {
      try {
        const [status, wallet, mempool] = await Promise.all([
          getNodeStatus(controller.signal),
          getWalletSnapshot(controller.signal),
          getMempool(controller.signal),
        ]);
        if (controller.signal.aborted) return;
        setState({
          status,
          wallet,
          mempool,
          loading: false,
          starting: false,
          refreshing: false,
          error: null,
          lastUpdated: new Date(),
        });
      } catch (error) {
        if (controller.signal.aborted) return;
        const starting = error !== null
          && typeof error === "object"
          && "code" in error
          && error.code === "node_starting";
        setState((current) => ({
          ...current,
          loading: starting,
          starting,
          refreshing: false,
          error: starting
            ? null
            : error instanceof Error
              ? error.message
              : "Unable to reach the local node",
        }));
      } finally {
        if (requestRef.current === controller) {
          requestRef.current = null;
          inFlightRef.current = null;
        }
      }
    })();

    inFlightRef.current = request;
    return request;
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), refreshInterval);
    return () => window.clearInterval(timer);
  }, [refresh, refreshInterval]);

  useEffect(() => () => {
    requestRef.current?.abort();
    requestRef.current = null;
    inFlightRef.current = null;
  }, []);

  return { ...state, refresh };
}
