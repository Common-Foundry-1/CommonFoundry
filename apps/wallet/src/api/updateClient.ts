import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useState } from "react";
import { usesEmbeddedNode, type NativeInvoke } from "./nodeClient";

/** What the updater is doing (the backend's `UpdaterStatus`). */
export type UpdaterState =
  | { state: "unsupported"; reason: string }
  | { state: "disabled" }
  | { state: "idle" }
  | { state: "checking" }
  | { state: "up_to_date" }
  | { state: "available"; version: string }
  | { state: "downloading"; version: string }
  | { state: "ready"; version: string; folder: string }
  | { state: "not_verified"; version: string; reason: string }
  | { state: "check_failed"; reason: string }
  /** An installed newer version has files missing; Download installs it again. */
  | { state: "damaged"; version: string; reason: string }
  | { state: "needs_copy_consent"; version: string; bytes: number }
  | { state: "manual"; version: string; reason: string }
  | { state: "install_failed"; version: string; reason: string; retry_automatically: boolean }
  | { state: "failed_to_start"; version: string; reason: string };

/** A newer version that failed to start, so this one runs instead. */
export interface UpdateFallback {
  version: string;
  reason: string;
  /** It had opened the wallet data. */
  after_data: boolean;
  /** This wallet waits for "Retry" or "Run anyway" before it opens them. */
  held: boolean;
}

export interface OldVersion {
  path: string;
  /** Size of the files in the folder; shared (hard-linked) files count in full. */
  bytes: number;
}

export interface UpdateStatus {
  build: string;
  current_version: string;
  automatic: boolean;
  disabled_by_launch_option: boolean;
  status: UpdaterState;
  /** Unix seconds. */
  last_checked_at: number | null;
  /** Checks in a row that could not read the release list, in this run. */
  check_failures: number;
  /** Unix seconds: since when checks have failed; null while they work. */
  check_failed_since: number | null;
  fallback: UpdateFallback | null;
  /** Why the last "Restart to update" could not start the new version. */
  restart_failed: string | null;
  old_versions: OldVersion[];
}

export interface RestartOptions {
  stopMining: boolean;
  acceptUnconfirmed: boolean;
}

export interface UpdateTransport {
  getUpdateStatus(): Promise<UpdateStatus>;
  setUpdateAutomatic(automatic: boolean): Promise<UpdateStatus>;
  checkForUpdates(): Promise<UpdateStatus>;
  downloadUpdate(allowCopy: boolean): Promise<UpdateStatus>;
  restartToUpdate(options: RestartOptions): Promise<void>;
  retryUpdate(version: string, options: RestartOptions): Promise<void>;
  runOlderAnyway(confirmText: string): Promise<UpdateStatus>;
  removeOldVersions(): Promise<UpdateStatus>;
}

/** What "Run anyway" must be confirmed with. */
export const RUN_ANYWAY_TEXT = "run anyway";

/** A refusal or failure of an update command, with the wallet's code. */
export class UpdateError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryable: boolean;

  constructor(message: string, status: number, code: string, retryable = false) {
    super(message);
    this.name = "UpdateError";
    this.status = status;
    this.code = code;
    this.retryable = retryable;
  }
}

interface NativeErrorEnvelope {
  code?: unknown;
  message?: unknown;
  status?: unknown;
  retryable?: unknown;
}

function normalizeNativeError(cause: unknown): UpdateError {
  if (cause instanceof UpdateError) return cause;
  if (cause && typeof cause === "object") {
    const envelope = cause as NativeErrorEnvelope;
    return new UpdateError(
      typeof envelope.message === "string" && envelope.message ? envelope.message : "The update request failed",
      typeof envelope.status === "number" ? envelope.status : 0,
      typeof envelope.code === "string" ? envelope.code : "update_request_failed",
      envelope.retryable === true,
    );
  }
  return new UpdateError(
    typeof cause === "string" && cause ? cause : "The update request failed",
    0,
    "update_request_failed",
  );
}

async function nativeCall<T>(
  nativeInvoke: NativeInvoke,
  command: string,
  args?: Record<string, unknown>,
): Promise<T> {
  try {
    return await nativeInvoke<T>(command, args);
  } catch (cause) {
    throw normalizeNativeError(cause);
  }
}

// Tauri passes command arguments with camelCase keys (`allowCopy` reaches
// the Rust parameter `allow_copy`).
export function createTauriUpdateTransport(nativeInvoke: NativeInvoke): UpdateTransport {
  return {
    getUpdateStatus: () => nativeCall(nativeInvoke, "get_update_status"),
    setUpdateAutomatic: (automatic) => nativeCall(nativeInvoke, "set_update_automatic", { automatic }),
    checkForUpdates: () => nativeCall(nativeInvoke, "check_for_updates"),
    downloadUpdate: (allowCopy) => nativeCall(nativeInvoke, "download_update", { allowCopy }),
    restartToUpdate: ({ stopMining, acceptUnconfirmed }) => nativeCall(
      nativeInvoke,
      "restart_to_update",
      { stopMining, acceptUnconfirmed },
    ),
    retryUpdate: (version, { stopMining, acceptUnconfirmed }) => nativeCall(
      nativeInvoke,
      "retry_update",
      { version, stopMining, acceptUnconfirmed },
    ),
    runOlderAnyway: (confirmText) => nativeCall(nativeInvoke, "run_older_anyway", { confirmText }),
    removeOldVersions: () => nativeCall(nativeInvoke, "remove_old_versions"),
  };
}

function desktopOnly(): Promise<never> {
  return Promise.reject(new UpdateError(
    "Updates are handled by the desktop wallet.",
    501,
    "updates_desktop_only",
    false,
  ));
}

export const browserUpdateTransport: UpdateTransport = {
  getUpdateStatus: desktopOnly,
  setUpdateAutomatic: desktopOnly,
  checkForUpdates: desktopOnly,
  downloadUpdate: desktopOnly,
  restartToUpdate: desktopOnly,
  retryUpdate: desktopOnly,
  runOlderAnyway: desktopOnly,
  removeOldVersions: desktopOnly,
};

const nativeInvoke: NativeInvoke = (command, args) => invoke(command, args);
export const updateTransport: UpdateTransport = usesEmbeddedNode
  ? createTauriUpdateTransport(nativeInvoke)
  : browserUpdateTransport;

/** Asks the user to confirm a restart the wallet refused for now. */
export type RestartConfirm = (message: string, action: string) => Promise<boolean>;

/**
 * Runs "Restart to update" (or "Retry"), asking the user when the wallet
 * wants consent first: to stop mining, and to drop unconfirmed sends from
 * memory. Resolves `true` once the wallet is closing to restart, `false`
 * when the user said no. Every other refusal is thrown with its message.
 */
export async function restartWithConfirmations(
  restart: (options: RestartOptions) => Promise<void>,
  confirm: RestartConfirm,
): Promise<boolean> {
  const options: RestartOptions = { stopMining: false, acceptUnconfirmed: false };
  for (;;) {
    try {
      await restart({ ...options });
      return true;
    } catch (cause) {
      const error = normalizeNativeError(cause);
      if (error.code === "update_restarting") return true;
      if (error.code === "update_mining_active" && !options.stopMining) {
        if (!(await confirm(error.message, "Stop mining and restart"))) return false;
        options.stopMining = true;
      } else if (error.code === "update_unconfirmed" && !options.acceptUnconfirmed) {
        if (!(await confirm(error.message, "Restart"))) return false;
        options.acceptUnconfirmed = true;
      } else {
        throw error;
      }
    }
  }
}

export function updateErrorMessage(cause: unknown): string {
  return normalizeNativeError(cause).message;
}

// The banner and the Updates card each poll; whatever one learns (a poll or
// an action's answer) reaches both.
const listeners = new Set<(status: UpdateStatus) => void>();

export function publishUpdateStatus(status: UpdateStatus): void {
  for (const listener of listeners) listener(status);
}

const BUSY_POLL_MS = 2_000;
const IDLE_POLL_MS = 30_000;

function busy(status: UpdateStatus | null): boolean {
  return status?.status.state === "checking" || status?.status.state === "downloading";
}

/** The updater's status, polled while mounted (faster during a check or download). */
export function useUpdateStatus(transport: UpdateTransport = updateTransport) {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      publishUpdateStatus(await transport.getUpdateStatus());
      setError(null);
    } catch (cause) {
      setError(updateErrorMessage(cause));
    }
  }, [transport]);

  useEffect(() => {
    listeners.add(setStatus);
    return () => {
      listeners.delete(setStatus);
    };
  }, []);

  const polling = busy(status);
  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      await refresh();
      if (active) timer = setTimeout(() => void poll(), polling ? BUSY_POLL_MS : IDLE_POLL_MS);
    };
    void poll();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [refresh, polling]);

  return { status, error, refresh };
}

/** "3:05 PM" for a Unix time in seconds. */
export function formatCheckedAt(seconds: number): string {
  return new Date(seconds * 1000).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}
