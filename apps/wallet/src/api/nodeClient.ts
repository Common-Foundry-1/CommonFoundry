import type {
  ConsolidationRequest,
  ConsolidationResult,
  MempoolSnapshot,
  MineResult,
  NodeStatus,
  PeerSettings,
  WalletSendRequest,
  WalletSendResult,
  WalletCustodyStatus,
  WalletSnapshot,
} from "../types";
import { invoke } from "@tauri-apps/api/core";

const RPC_ROOT = "/rpc";

interface NativeErrorEnvelope {
  code?: unknown;
  message?: unknown;
  status?: unknown;
  retryable?: unknown;
}

export class NodeApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryable: boolean;

  constructor(
    message: string,
    status: number,
    code = "node_request_failed",
    retryable = false,
  ) {
    super(message);
    this.name = "NodeApiError";
    this.status = status;
    this.code = code;
    this.retryable = retryable;
  }
}

export interface NodeTransport {
  getNodeStatus(signal?: AbortSignal): Promise<NodeStatus>;
  getWalletSnapshot(signal?: AbortSignal): Promise<WalletSnapshot>;
  getMempool(signal?: AbortSignal): Promise<MempoolSnapshot>;
  getPeerSettings(): Promise<PeerSettings>;
  updatePeerSettings(peers: string[]): Promise<PeerSettings>;
  sendWalletTransaction(payload: WalletSendRequest): Promise<WalletSendResult>;
  consolidateWallet(payload: ConsolidationRequest): Promise<ConsolidationResult>;
  mineDevnetBlock(miner: string, attempts?: number): Promise<MineResult>;
  getWalletCustodyStatus(): Promise<WalletCustodyStatus>;
  unlockWallet(passphrase: string): Promise<WalletCustodyStatus>;
  lockWallet(): Promise<WalletCustodyStatus>;
  backupWallet(path: string, passphrase: string): Promise<WalletCustodyStatus>;
  migrateWalletEncryption(path: string, passphrase: string): Promise<WalletCustodyStatus>;
  restoreWallet(path: string, passphrase: string): Promise<WalletCustodyStatus>;
}

export type NativeInvoke = <T>(
  command: string,
  args?: Record<string, unknown>,
) => Promise<T>;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${RPC_ROOT}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...init?.headers,
    },
  });

  const body = (await response.json().catch(() => null)) as
    | T
    | { error?: string }
    | null;
  if (!response.ok) {
    const message = body
      && typeof body === "object"
      && "error" in body
      && typeof body.error === "string"
      ? body.error
      : response.statusText;
    throw new NodeApiError(message || "Node request failed", response.status);
  }
  return body as T;
}

export const httpNodeTransport: NodeTransport = {
  getNodeStatus: (signal) => request<NodeStatus>("/v1/status", { signal }),
  getWalletSnapshot: (signal) => request<WalletSnapshot>("/v1/wallet", { signal }),
  getMempool: (signal) => request<MempoolSnapshot>("/v1/mempool", { signal }),
  getPeerSettings: () => Promise.reject(new NodeApiError(
    "Peer settings are available in the desktop wallet.",
    501,
    "peer_settings_unavailable",
  )),
  updatePeerSettings: () => Promise.reject(new NodeApiError(
    "Peer settings are available in the desktop wallet.",
    501,
    "peer_settings_unavailable",
  )),
  sendWalletTransaction: (payload) => request<WalletSendResult>("/v1/wallet/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }),
  consolidateWallet: (payload) => request<ConsolidationResult>("/v1/wallet/consolidate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }),
  mineDevnetBlock: (miner, attempts = 1_000_000) => {
    const query = new URLSearchParams({ miner, attempts: attempts.toString() });
    return request<MineResult>(`/v1/mine?${query.toString()}`, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: new Uint8Array(),
    });
  },
  getWalletCustodyStatus: () => custodyUnavailable(),
  unlockWallet: () => custodyUnavailable(),
  lockWallet: () => custodyUnavailable(),
  backupWallet: () => custodyUnavailable(),
  migrateWalletEncryption: () => custodyUnavailable(),
  restoreWallet: () => custodyUnavailable(),
};

function custodyUnavailable<T>(): Promise<T> {
  return Promise.reject(new NodeApiError(
    "Wallet security controls are available in the desktop wallet.",
    501,
    "wallet_custody_unavailable",
  ));
}

function abortError(): DOMException {
  return new DOMException("The node request was aborted", "AbortError");
}

function withAbort<T>(operation: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return operation;
  if (signal.aborted) return Promise.reject(abortError());

  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const abort = () => {
      if (settled) return;
      settled = true;
      reject(abortError());
    };
    signal.addEventListener("abort", abort, { once: true });
    operation.then(
      (value) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (cause) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener("abort", abort);
        reject(normalizeNativeError(cause));
      },
    );
  });
}

function normalizeNativeError(cause: unknown): NodeApiError {
  if (cause instanceof NodeApiError) return cause;
  if (cause instanceof Error) {
    return new NodeApiError(cause.message || "Native node request failed", 0);
  }
  if (cause && typeof cause === "object") {
    const envelope = cause as NativeErrorEnvelope;
    return new NodeApiError(
      typeof envelope.message === "string" ? envelope.message : "Native node request failed",
      typeof envelope.status === "number" ? envelope.status : 0,
      typeof envelope.code === "string" ? envelope.code : "node_request_failed",
      envelope.retryable === true,
    );
  }
  return new NodeApiError(
    typeof cause === "string" && cause ? cause : "Native node request failed",
    0,
  );
}

async function nativeCall<T>(
  invoke: NativeInvoke,
  command: string,
  args?: Record<string, unknown>,
): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (cause) {
    throw normalizeNativeError(cause);
  }
}

export function createTauriNodeTransport(invoke: NativeInvoke): NodeTransport {
  return {
    getNodeStatus: (signal) => withAbort(
      nativeCall<NodeStatus>(invoke, "get_node_status"),
      signal,
    ),
    getWalletSnapshot: (signal) => withAbort(
      nativeCall<WalletSnapshot>(invoke, "get_wallet_snapshot"),
      signal,
    ),
    getMempool: (signal) => withAbort(
      nativeCall<MempoolSnapshot>(invoke, "get_mempool_snapshot"),
      signal,
    ),
    getPeerSettings: () => nativeCall<PeerSettings>(
      invoke,
      "get_peer_settings",
    ),
    updatePeerSettings: (peers) => nativeCall<PeerSettings>(
      invoke,
      "update_peer_settings",
      { request: { peers } },
    ),
    sendWalletTransaction: (payload) => nativeCall<WalletSendResult>(
      invoke,
      "send_wallet_transaction",
      { request: payload },
    ),
    consolidateWallet: (payload) => nativeCall<ConsolidationResult>(
      invoke,
      "consolidate_wallet",
      { request: payload },
    ),
    mineDevnetBlock: (miner, attempts = 1_000_000) => nativeCall<MineResult>(
      invoke,
      "mine_devnet_block",
      { request: { miner, attempts } },
    ),
    getWalletCustodyStatus: () => nativeCall<WalletCustodyStatus>(
      invoke,
      "get_wallet_custody_status",
    ),
    unlockWallet: (passphrase) => nativeCall<WalletCustodyStatus>(
      invoke,
      "unlock_wallet",
      { request: { passphrase } },
    ),
    lockWallet: () => nativeCall<WalletCustodyStatus>(
      invoke,
      "lock_wallet",
    ),
    backupWallet: (path, passphrase) => nativeCall<WalletCustodyStatus>(
      invoke,
      "backup_wallet",
      { request: { path, passphrase } },
    ),
    migrateWalletEncryption: (path, passphrase) => nativeCall<WalletCustodyStatus>(
      invoke,
      "migrate_wallet_encryption",
      { request: { path, passphrase } },
    ),
    restoreWallet: (path, passphrase) => nativeCall<WalletCustodyStatus>(
      invoke,
      "restore_wallet",
      { request: { path, passphrase } },
    ),
  };
}

const nativeInvoke: NativeInvoke = (command, args) => invoke(command, args);

export const usesEmbeddedNode = import.meta.env.VITE_CMFD_TRANSPORT === "tauri";

const transport = usesEmbeddedNode
  ? createTauriNodeTransport(nativeInvoke)
  : httpNodeTransport;

export function getNodeStatus(signal?: AbortSignal): Promise<NodeStatus> {
  return transport.getNodeStatus(signal);
}

export function getWalletSnapshot(signal?: AbortSignal): Promise<WalletSnapshot> {
  return transport.getWalletSnapshot(signal);
}

export function getMempool(signal?: AbortSignal): Promise<MempoolSnapshot> {
  return transport.getMempool(signal);
}

export function getPeerSettings(): Promise<PeerSettings> {
  return transport.getPeerSettings();
}

export function updatePeerSettings(peers: string[]): Promise<PeerSettings> {
  return transport.updatePeerSettings(peers);
}

export function sendWalletTransaction(payload: WalletSendRequest): Promise<WalletSendResult> {
  return transport.sendWalletTransaction(payload);
}

export function consolidateWallet(payload: ConsolidationRequest): Promise<ConsolidationResult> {
  return transport.consolidateWallet(payload);
}

export function mineDevnetBlock(
  miner: string,
  attempts = 1_000_000,
): Promise<MineResult> {
  return transport.mineDevnetBlock(miner, attempts);
}

export function getWalletCustodyStatus(): Promise<WalletCustodyStatus> {
  return transport.getWalletCustodyStatus();
}

export function unlockWallet(passphrase: string): Promise<WalletCustodyStatus> {
  return transport.unlockWallet(passphrase);
}

export function lockWallet(): Promise<WalletCustodyStatus> {
  return transport.lockWallet();
}

export function backupWallet(path: string, passphrase: string): Promise<WalletCustodyStatus> {
  return transport.backupWallet(path, passphrase);
}

export function migrateWalletEncryption(
  path: string,
  passphrase: string,
): Promise<WalletCustodyStatus> {
  return transport.migrateWalletEncryption(path, passphrase);
}

export function restoreWallet(path: string, passphrase: string): Promise<WalletCustodyStatus> {
  return transport.restoreWallet(path, passphrase);
}
