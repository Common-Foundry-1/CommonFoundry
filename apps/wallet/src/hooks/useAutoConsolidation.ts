import { useCallback, useEffect, useRef, useState } from "react";

import { consolidateWallet, usesEmbeddedNode } from "../api/nodeClient";
import { DEFAULT_TRANSACTION_FEE } from "../lib/fees";
import type { NodeStatus, WalletSnapshot } from "../types";

export type AutoConsolidationThreshold = 32 | 64 | 128 | 256;

interface Settings {
  enabled: boolean;
  threshold: AutoConsolidationThreshold;
}

interface StoredSettings {
  key: string | null;
  value: Settings;
}

interface Attempt {
  at: number;
  height: number;
  submitted: boolean;
}

const DEFAULT_SETTINGS: Settings = { enabled: false, threshold: 64 };
const COOLDOWN_MS = 15 * 60 * 1_000;
const THRESHOLDS: AutoConsolidationThreshold[] = [32, 64, 128, 256];

function readJson(key: string): unknown {
  try { return JSON.parse(window.localStorage.getItem(key) ?? "null"); } catch { return null; }
}

function writeJson(key: string, value: unknown): boolean {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch { return false; }
}

function readSettings(key: string): Settings {
  const value = readJson(key);
  if (!value || typeof value !== "object") return DEFAULT_SETTINGS;
  const stored = value as Partial<Settings>;
  return typeof stored.enabled === "boolean" && THRESHOLDS.includes(stored.threshold as AutoConsolidationThreshold)
    ? { enabled: stored.enabled, threshold: stored.threshold as AutoConsolidationThreshold }
    : DEFAULT_SETTINGS;
}

function readAttempt(key: string): Attempt | null {
  const value = readJson(key);
  if (!value || typeof value !== "object") return null;
  const attempt = value as Partial<Attempt>;
  return typeof attempt.at === "number" && Number.isFinite(attempt.at)
    && typeof attempt.height === "number" && Number.isSafeInteger(attempt.height)
    && typeof attempt.submitted === "boolean" ? attempt as Attempt : null;
}

export function autoConsolidationReason(
  status: NodeStatus | null,
  wallet: WalletSnapshot | null,
  unlocked: boolean,
  threshold: AutoConsolidationThreshold,
): string | null {
  if (!usesEmbeddedNode) return "Available in the installed wallet only.";
  if (!unlocked) return "Waiting for wallet unlock.";
  if (!status || !wallet) return "Waiting for node data.";
  if (!status.storage_healthy) return "Waiting for healthy node storage.";
  if (status.network !== wallet.network || status.accepted_height !== wallet.accepted_height) {
    return "Waiting for a consistent chain snapshot.";
  }
  if (!status.peers.some((peer) => peer.active_connections > 0
    && peer.remote_height === status.accepted_height && peer.remote_tip === status.tip)) {
    return "Waiting for a connected peer at the same chain tip.";
  }
  if (wallet.history.some((entry) => entry.status === "pending") || wallet.reserved_utxo_count > 0) {
    return "Waiting for pending wallet activity to settle.";
  }
  if (wallet.spendable_utxo_count < threshold) return `Waiting for ${threshold} spendable outputs.`;
  return null;
}

export function useAutoConsolidation(
  status: NodeStatus | null,
  wallet: WalletSnapshot | null,
  unlocked: boolean,
  online: boolean,
  lastUpdated: Date | null,
  refresh: () => Promise<void>,
) {
  const identity = status && wallet ? `${status.network_id}:${wallet.destination}` : null;
  const settingsKey = identity ? `cmfd:auto-consolidation:v1:${identity}` : null;
  const attemptKey = settingsKey ? `${settingsKey}:attempt` : null;
  const [stored, setStored] = useState<StoredSettings>({ key: null, value: DEFAULT_SETTINGS });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);

  useEffect(() => {
    setStored({ key: settingsKey, value: settingsKey ? readSettings(settingsKey) : DEFAULT_SETTINGS });
    setError(null);
  }, [settingsKey]);

  const settings = stored.key === settingsKey ? stored.value : DEFAULT_SETTINGS;
  const setSettings = useCallback((next: Settings) => {
    if (!settingsKey || !writeJson(settingsKey, next)) {
      setError("Could not save automatic consolidation settings on this device.");
      return;
    }
    setStored({ key: settingsKey, value: next });
    setError(null);
  }, [settingsKey]);

  const reason = !online || !lastUpdated || Date.now() - lastUpdated.getTime() > 10_000
    ? "Waiting for fresh node data."
    : autoConsolidationReason(status, wallet, unlocked, settings.threshold);
  const attempt = attemptKey ? readAttempt(attemptKey) : null;
  const now = Date.now();
  const coolingDown = attempt !== null && (now < attempt.at || now - attempt.at < COOLDOWN_MS);
  const waitingForBlock = attempt?.submitted === true && wallet !== null && wallet.accepted_height <= attempt.height;

  useEffect(() => {
    if (!settings.enabled || reason || !status || !wallet || !attemptKey || !lastUpdated
      || coolingDown || waitingForBlock || inFlight.current) return;
    const at = Date.now();
    const pending: Attempt = { at, height: wallet.accepted_height, submitted: false };
    if (!writeJson(attemptKey, pending)) {
      setError("Could not record the attempt safely on this device.");
      return;
    }
    inFlight.current = true;
    setBusy(true);
    setError(null);
    void consolidateWallet({
      fee: DEFAULT_TRANSACTION_FEE,
      max_inputs: Math.min(128, wallet.spendable_utxo_count),
      max_fee_basis_points: 100,
    }).then(() => {
      writeJson(attemptKey, { ...pending, submitted: true });
      void refresh();
    }).catch((cause: unknown) => {
      setError(cause instanceof Error ? cause.message : "Automatic consolidation failed.");
    }).finally(() => {
      inFlight.current = false;
      setBusy(false);
    });
  }, [attemptKey, coolingDown, lastUpdated, reason, refresh, settings.enabled, status, waitingForBlock, wallet]);

  return { settings, setSettings, busy, error, reason, coolingDown, waitingForBlock, available: usesEmbeddedNode };
}
