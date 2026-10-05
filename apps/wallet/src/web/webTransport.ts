// NodeTransport for the hosted web wallet. The signing key is generated, encrypted, and used
// only in this browser; the edge API supplies chain data and relays signed transactions.
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { NodeApiError } from "../api/errors";
import type { NodeTransport } from "../api/nodeClient";
import { parseCmfd } from "../lib/amount";
import { MIN_TRANSACTION_FEE_ATOMS, MINIMUM_FEE_MESSAGE } from "../lib/fees";
import type {
  ConsolidationResult,
  MempoolSnapshot,
  NodeStatus,
  WalletCustodyStatus,
  WalletHistoryEntry,
  WalletSnapshot,
} from "../types";
import { decryptWalletKey, encryptWalletKey, WalletBackupError } from "./backup";
import { isValidDestination, MAX_TRANSACTION_INPUTS, signTransaction, type UnsignedTransaction } from "./codec";
import { edgeApi, type EdgeApi, type ExplorerAddress, type ExplorerAddressActivity, type ExplorerSnapshot, type UtxoCursor } from "./edgeApi";
import { createLocalWalletStore, StorageUnavailableError, type LocalTransaction, type WalletStore } from "./store";

export const MAINNET_NETWORK_ID = "88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62";
const COINBASE_MATURITY = 100;
const MIN_RELAY_FEE_PER_KIB = 1n;
const PENDING_DROP_AFTER_MS = 30 * 60_000;
const SNAPSHOT_TTL_MS = 2_000;
const MAX_UTXO_PAGES = 20;
const MAX_LOOKUPS_PER_REFRESH = 5;
const MAX_LOCAL_TRANSACTIONS = 200;

export interface BackupFiles {
  /** Lets the person pick a backup file; resolves null when they cancel. */
  pick(): Promise<File | null>;
  save(name: string, bytes: Uint8Array): void;
}

export interface WebTransportOptions {
  api?: EdgeApi;
  store?: WalletStore;
  files?: BackupFiles;
  networkId?: string;
  now?: () => number;
}

interface UnlockedWallet {
  secretKey: Uint8Array;
  destination: string;
}

interface Coin {
  txid: string;
  index: number;
  value: bigint;
}

export function createWebNodeTransport(options: WebTransportOptions = {}): NodeTransport {
  const networkId = options.networkId ?? MAINNET_NETWORK_ID;
  const api = options.api ?? edgeApi;
  const store = options.store ?? createLocalWalletStore(networkId);
  const files = options.files ?? browserFiles;
  const now = options.now ?? Date.now;
  let unlocked: UnlockedWallet | null = null;
  let restoreFile: File | null = null;
  let snapshotCache: { at: number; value: Promise<ExplorerSnapshot> } | null = null;
  let networkName = "CommonFoundry Mainnet";

  const custody = (): WalletCustodyStatus => {
    const stored = store.loadKey();
    return {
      network: networkName,
      storage: stored ? "encrypted" : "missing",
      unlocked: unlocked !== null,
      requires_migration: false,
      can_restore: stored === null,
      data_directory: "This browser",
      destination: unlocked?.destination ?? null,
      launch: null,
    };
  };

  const requireUnlocked = (): UnlockedWallet => {
    if (!unlocked) throw new NodeApiError("Unlock the wallet first.", 423, "wallet_locked");
    return unlocked;
  };

  const snapshot = (signal?: AbortSignal): Promise<ExplorerSnapshot> => {
    if (snapshotCache && now() - snapshotCache.at < SNAPSHOT_TTL_MS) return snapshotCache.value;
    const value = api.snapshot(signal).then((result) => {
      if (result.network_id !== networkId) {
        throw new NodeApiError("The network service reported a different network. Refusing to continue.", 502, "network_mismatch");
      }
      networkName = result.network;
      return result;
    });
    snapshotCache = { at: now(), value };
    value.catch(() => {
      if (snapshotCache?.value === value) snapshotCache = null;
    });
    return value;
  };

  const localTransactions = (destination: string) => store.loadTransactions(destination);

  const saveLocal = (destination: string, transactions: LocalTransaction[]) => {
    const kept = transactions
      .filter((entry) => entry.state !== "dropped" || now() - entry.created_at < 24 * 60 * 60_000)
      .sort((left, right) => right.created_at - left.created_at)
      .slice(0, MAX_LOCAL_TRANSACTIONS);
    store.saveTransactions(destination, kept);
  };

  /** Moves pending sends to confirmed once the explorer has them in a block it has indexed. */
  const reconcile = async (destination: string, acceptedHeight: number, signal?: AbortSignal) => {
    const transactions = localTransactions(destination);
    let changed = false;
    for (const entry of transactions) {
      if (entry.state !== "pending") continue;
      const seen = await api.transaction(entry.txid, signal);
      if (seen?.status === "confirmed" && seen.block_height !== null && seen.block_height <= acceptedHeight) {
        entry.state = "confirmed";
        changed = true;
      } else if (!seen && now() - entry.created_at > PENDING_DROP_AFTER_MS) {
        entry.state = "dropped";
        changed = true;
      }
    }
    if (changed) saveLocal(destination, transactions);
    return transactions;
  };

  const historyEntries = async (
    destination: string,
    address: ExplorerAddress,
    local: LocalTransaction[],
    signal?: AbortSignal,
  ): Promise<WalletHistoryEntry[]> => {
    const byTxid = new Map(local.map((entry) => [entry.txid, entry]));
    const lookups = store.loadLookups();
    let lookupsChanged = false;
    let lookupBudget = MAX_LOOKUPS_PER_REFRESH;
    const entries: WalletHistoryEntry[] = [];

    for (const activity of address.history) {
      const base = {
        txid: activity.txid,
        height: activity.block_height,
        timestamp: activity.timestamp,
        confirmations: activity.confirmations,
      };
      const signed = byTxid.get(activity.txid);
      if (signed) {
        entries.push({ ...base, ...localAmounts(signed, destination), status: "confirmed" });
        continue;
      }
      if (activity.kind === "coinbase") {
        const immature = activity.confirmations < COINBASE_MATURITY && BigInt(address.immature_atoms) > 0n;
        entries.push({ ...base, kind: "mined", status: immature ? "immature" : "confirmed", net_amount_atoms: activity.received_atoms, fee_burned_atoms: "0", counterparty: null });
      } else if (activity.kind === "received") {
        entries.push({ ...base, kind: "received", status: "confirmed", net_amount_atoms: activity.received_atoms, fee_burned_atoms: "0", counterparty: null });
      } else if (activity.kind === "sent") {
        let lookup = lookups[activity.txid];
        if (!lookup && lookupBudget > 0) {
          lookupBudget -= 1;
          lookup = await sentLookup(activity, destination, signal).catch(() => undefined) as typeof lookup;
          if (lookup) {
            lookups[activity.txid] = lookup;
            lookupsChanged = true;
          }
        }
        entries.push({
          ...base,
          kind: "sent",
          status: "confirmed",
          net_amount_atoms: lookup ? (-BigInt(lookup.sent_atoms)).toString() : "0",
          fee_burned_atoms: "0",
          counterparty: lookup?.counterparty ?? null,
          fee_unknown: true,
        });
      } else {
        entries.push({ ...base, kind: "consolidated", status: "confirmed", net_amount_atoms: "0", fee_burned_atoms: "0", counterparty: null, fee_unknown: true });
      }
    }
    if (lookupsChanged) {
      try {
        store.saveLookups(lookups);
      } catch {
        // The lookup cache is an optimization; history still renders without it.
      }
    }
    return entries;
  };

  const sentLookup = async (activity: ExplorerAddressActivity, destination: string, signal?: AbortSignal) => {
    const { vout } = await api.transactionOutputs(activity.txid, activity.block_id, signal);
    const others = vout.filter((output) => output.destination_hex !== destination);
    const recipients = new Set(others.map((output) => output.destination_hex));
    return {
      sent_atoms: others.reduce((total, output) => total + BigInt(output.value_atoms), 0n).toString(),
      counterparty: recipients.size === 1 ? [...recipients][0] : null,
    };
  };

  /** Every mature, unreserved coin for this address, from the gateway's UTXO view. */
  const spendableCoins = async (wallet: UnlockedWallet) => {
    const reserved = new Set(
      localTransactions(wallet.destination)
        .filter((entry) => entry.state === "pending")
        .flatMap((entry) => entry.inputs),
    );
    const coins: Coin[] = [];
    let cursor: UtxoCursor | null = null;
    for (let page = 0; page < MAX_UTXO_PAGES; page += 1) {
      const result = await api.utxos(wallet.destination, cursor);
      for (const utxo of result.utxos) {
        if (reserved.has(`${utxo.txid}:${utxo.vout}`) || utxo.spendable_height > result.height + 1) continue;
        coins.push({ txid: utxo.txid, index: utxo.vout, value: BigInt(utxo.value_atoms) });
      }
      if (!result.has_more || !result.next_cursor) return { height: result.height, coins };
      cursor = result.next_cursor;
    }
    throw new NodeApiError(
      "This wallet holds too many separate outputs to load in a browser. Consolidate it with the desktop wallet first.",
      413,
      "too_many_outputs",
    );
  };

  /** Signs, records (reserving the inputs), then broadcasts. */
  const signAndBroadcast = async (
    wallet: UnlockedWallet,
    transaction: UnsignedTransaction,
    record: Omit<LocalTransaction, "txid" | "encoded_bytes" | "inputs" | "created_at" | "state">,
  ) => {
    const signed = signTransaction(transaction, wallet.secretKey);
    const fee = BigInt(record.fee_atoms);
    const relayFee = (BigInt(Math.ceil(signed.frame.length / 1024)) * MIN_RELAY_FEE_PER_KIB);
    const minimum = relayFee > MIN_TRANSACTION_FEE_ATOMS ? relayFee : MIN_TRANSACTION_FEE_ATOMS;
    if (fee < minimum) throw new NodeApiError(MINIMUM_FEE_MESSAGE, 422, "fee_too_low");

    const entry: LocalTransaction = {
      ...record,
      txid: signed.txid,
      encoded_bytes: signed.frame.length,
      inputs: transaction.inputs.map((input) => `${input.txid}:${input.index}`),
      created_at: now(),
      state: "pending",
    };
    const transactions = localTransactions(wallet.destination);
    saveLocal(wallet.destination, [entry, ...transactions]);
    try {
      const accepted = await api.broadcast(bytesToHex(signed.frame));
      if (accepted.txid !== signed.txid) {
        throw new NodeApiError("The network acknowledged a different transaction id.", 502, "txid_mismatch");
      }
    } catch (cause) {
      // Only release the inputs when the transaction certainly never reached a mempool.
      if (cause instanceof NodeApiError && [400, 413, 422, 429].includes(cause.status)) {
        saveLocal(wallet.destination, localTransactions(wallet.destination).filter((item) => item.txid !== signed.txid));
      }
      throw cause;
    }
    snapshotCache = null;
    return { entry, mempool: await snapshot().catch(() => null) };
  };

  return {
    getNodeStatus: async (signal) => nodeStatus(await snapshot(signal)),

    getWalletSnapshot: async (signal) => {
      const wallet = unlocked;
      if (!wallet) return emptySnapshot(networkName);
      const address = await api.address(wallet.destination, signal);
      if (address.address !== wallet.destination) {
        throw new NodeApiError("The network service returned a different address.", 502, "address_mismatch");
      }
      const local = await reconcile(wallet.destination, address.accepted_height, signal);
      const pending = local.filter((entry) => entry.state === "pending");
      const reserved = pending.reduce((total, entry) => total + BigInt(entry.input_atoms), 0n);
      const returning = pending.reduce((total, entry) => total + returnedAtoms(entry, wallet.destination), 0n);
      const spendable = BigInt(address.spendable_atoms) - reserved;
      const history = [
        ...pending.map((entry): WalletHistoryEntry => ({
          ...localAmounts(entry, wallet.destination),
          txid: entry.txid,
          height: null,
          timestamp: Math.floor(entry.created_at / 1000),
          confirmations: 0,
          status: "pending",
        })),
        ...await historyEntries(wallet.destination, address, local, signal),
      ];
      return {
        network: networkName,
        devnet_only: false,
        insecure_demo_wallet: false,
        warning: "",
        destination: wallet.destination,
        accepted_height: address.accepted_height,
        next_height: address.accepted_height + 1,
        balances: {
          spendable_atoms: (spendable > 0n ? spendable : 0n).toString(),
          immature_atoms: address.immature_atoms,
          pending_atoms: returning.toString(),
        },
        spendable_utxo_count: Math.max(0, address.utxo_count - pending.reduce((total, entry) => total + entry.inputs.length, 0)),
        immature_utxo_count: 0,
        reserved_utxo_count: pending.reduce((total, entry) => total + entry.inputs.length, 0),
        mempool: {
          transactions: pending.length,
          bytes: pending.reduce((total, entry) => total + entry.encoded_bytes, 0),
        },
        history_limit: address.page_limit,
        history,
      };
    },

    getMempool: async (signal): Promise<MempoolSnapshot> => {
      const current = await snapshot(signal);
      return {
        transactions: current.mempool_transactions,
        bytes: current.mempool_bytes,
        entries: current.recent_transactions
          .filter((entry) => entry.status === "mempool")
          .map((entry) => ({
            txid: entry.txid,
            encoded_bytes: entry.encoded_bytes,
            fee_burned: Number(entry.fee_burned_atoms ?? "0"),
            fee_burned_atoms: entry.fee_burned_atoms ?? "0",
          })),
      };
    },

    getPeerSettings: () => Promise.reject(unavailable("Peer settings are available in the desktop wallet.")),
    updatePeerSettings: () => Promise.reject(unavailable("Peer settings are available in the desktop wallet.")),
    mineDevnetBlock: () => Promise.reject(unavailable("Mining is available in the desktop wallet.")),
    migrateWalletEncryption: () => Promise.reject(unavailable("Web wallet keys are always encrypted.")),

    sendWalletTransaction: async (payload) => {
      const wallet = requireUnlocked();
      const recipient = payload.recipient.trim().toLowerCase();
      if (!isValidDestination(recipient)) {
        throw new NodeApiError("Enter a valid Common Foundry address (64 hexadecimal characters).", 400, "invalid_recipient");
      }
      const amount = parseCmfd(payload.amount);
      const fee = parseCmfd(payload.fee);
      if (amount === null || amount <= 0n) throw new NodeApiError("Enter an amount greater than zero.", 400, "invalid_amount");
      if (fee === null || fee < MIN_TRANSACTION_FEE_ATOMS) throw new NodeApiError(MINIMUM_FEE_MESSAGE, 400, "fee_too_low");

      const required = amount + fee;
      const { height, coins } = await spendableCoins(wallet);
      const available = coins.reduce((total, coin) => total + coin.value, 0n);
      coins.sort((left, right) => compareCoins(right, left));
      const selected: Coin[] = [];
      let selectedValue = 0n;
      for (const coin of coins.slice(0, MAX_TRANSACTION_INPUTS)) {
        selected.push(coin);
        selectedValue += coin.value;
        if (selectedValue >= required) break;
      }
      if (selectedValue < required) {
        throw available >= required
          ? new NodeApiError("This payment needs more than 128 inputs. Consolidate the wallet first, then send again.", 422, "wallet_input_limit")
          : new NodeApiError("Insufficient spendable balance for this amount and fee.", 422, "insufficient_funds");
      }
      const change = selectedValue - required;
      const spendableHeight = BigInt(height + 1);
      const outputs = [{ value: amount, destination: recipient, spendableHeight }];
      if (change > 0n) outputs.push({ value: change, destination: wallet.destination, spendableHeight });

      const { entry, mempool } = await signAndBroadcast(wallet, {
        networkId,
        inputs: selected.map(({ txid, index }) => ({ txid, index })),
        outputs,
      }, {
        kind: "sent",
        recipient,
        amount_atoms: amount.toString(),
        fee_atoms: fee.toString(),
        change_atoms: change.toString(),
        input_atoms: selectedValue.toString(),
      });
      return {
        network: networkName,
        devnet_only: false,
        insecure_demo_wallet: false,
        warning: "",
        txid: entry.txid,
        amount_atoms: entry.amount_atoms,
        fee_burned_atoms: entry.fee_atoms,
        change_atoms: entry.change_atoms,
        mempool_transactions: mempool?.mempool_transactions ?? 0,
        mempool_bytes: mempool?.mempool_bytes ?? 0,
      };
    },

    consolidateWallet: async (payload): Promise<ConsolidationResult> => {
      const wallet = requireUnlocked();
      const fee = parseCmfd(payload.fee);
      if (fee === null || fee < MIN_TRANSACTION_FEE_ATOMS) throw new NodeApiError(MINIMUM_FEE_MESSAGE, 400, "fee_too_low");
      if (!Number.isInteger(payload.max_inputs) || payload.max_inputs < 2 || payload.max_inputs > MAX_TRANSACTION_INPUTS) {
        throw new NodeApiError(`Choose between 2 and ${MAX_TRANSACTION_INPUTS} outputs to consolidate.`, 400, "invalid_max_inputs");
      }
      const { height, coins } = await spendableCoins(wallet);
      coins.sort(compareCoins);
      const selected = coins.slice(0, payload.max_inputs);
      if (selected.length < 2) {
        throw new NodeApiError("At least two mature outputs are needed to consolidate.", 422, "not_enough_outputs");
      }
      const inputAtoms = selected.reduce((total, coin) => total + coin.value, 0n);
      const outputAtoms = inputAtoms - fee;
      if (outputAtoms <= 0n) throw new NodeApiError("The selected outputs do not cover the fee.", 422, "consolidation_fee");

      const { entry, mempool } = await signAndBroadcast(wallet, {
        networkId,
        inputs: selected.map(({ txid, index }) => ({ txid, index })),
        outputs: [{ value: outputAtoms, destination: wallet.destination, spendableHeight: BigInt(height + 1) }],
      }, {
        kind: "consolidated",
        recipient: null,
        amount_atoms: "0",
        fee_atoms: fee.toString(),
        change_atoms: outputAtoms.toString(),
        input_atoms: inputAtoms.toString(),
      });
      return {
        network: networkName,
        devnet_only: false,
        insecure_demo_wallet: false,
        warning: "",
        txid: entry.txid,
        inputs_consolidated: selected.length,
        input_atoms: inputAtoms.toString(),
        output_atoms: outputAtoms.toString(),
        fee_burned_atoms: fee.toString(),
        mempool_transactions: mempool?.mempool_transactions ?? 0,
        mempool_bytes: mempool?.mempool_bytes ?? 0,
      };
    },

    getWalletCustodyStatus: async () => custody(),

    unlockWallet: async (passphrase) => {
      const stored = store.loadKey();
      if (!stored) throw new NodeApiError("No wallet is stored in this browser.", 404, "wallet_missing");
      unlocked = await custodyCall(() => decryptWalletKey(stored, networkId, passphrase));
      return custody();
    },

    lockWallet: async () => {
      unlocked?.secretKey.fill(0);
      unlocked = null;
      return custody();
    },

    chooseWalletBackupPath: async (restore) => {
      if (!restore) return defaultBackupName(now());
      restoreFile = await files.pick();
      return restoreFile?.name ?? null;
    },

    createWallet: async (path, passphrase) => {
      if (store.loadKey()) throw new NodeApiError("A wallet is already stored in this browser.", 409, "wallet_exists");
      const secretKey = schnorr.utils.randomSecretKey();
      const encrypted = await custodyCall(() => encryptWalletKey(secretKey, networkId, passphrase));
      await custodyCall(async () => store.saveKey(encrypted));
      files.save(path || defaultBackupName(now()), encrypted);
      unlocked?.secretKey.fill(0);
      unlocked = { secretKey, destination: bytesToHex(schnorr.getPublicKey(secretKey)) };
      return custody();
    },

    backupWallet: async (path, passphrase) => {
      const stored = store.loadKey();
      if (!stored) throw new NodeApiError("No wallet is stored in this browser.", 404, "wallet_missing");
      // Prove the passphrase before handing out a file the person could not open later.
      const opened = await custodyCall(() => decryptWalletKey(stored, networkId, passphrase));
      opened.secretKey.fill(0);
      files.save(path || defaultBackupName(now()), stored);
      return custody();
    },

    restoreWallet: async (path, passphrase) => {
      if (store.loadKey()) throw new NodeApiError("A wallet is already stored in this browser.", 409, "wallet_exists");
      const file = restoreFile;
      if (!file || file.name !== path) throw new NodeApiError("Choose the backup file to restore.", 400, "backup_missing");
      const bytes = new Uint8Array(await file.arrayBuffer());
      const opened = await custodyCall(() => decryptWalletKey(bytes, networkId, passphrase));
      await custodyCall(async () => store.saveKey(bytes));
      unlocked?.secretKey.fill(0);
      unlocked = opened;
      restoreFile = null;
      return custody();
    },
  };
}

function localAmounts(entry: LocalTransaction, destination: string) {
  const fee = BigInt(entry.fee_atoms);
  const toSelf = entry.kind === "consolidated" || entry.recipient === destination;
  return {
    kind: toSelf ? "consolidated" as const : "sent" as const,
    net_amount_atoms: (toSelf ? -fee : -(BigInt(entry.amount_atoms) + fee)).toString(),
    fee_burned_atoms: entry.fee_atoms,
    counterparty: toSelf ? null : entry.recipient,
  };
}

function returnedAtoms(entry: LocalTransaction, destination: string): bigint {
  if (entry.kind === "consolidated") return BigInt(entry.change_atoms);
  return BigInt(entry.change_atoms) + (entry.recipient === destination ? BigInt(entry.amount_atoms) : 0n);
}

function compareCoins(left: Coin, right: Coin): number {
  if (left.value !== right.value) return left.value < right.value ? -1 : 1;
  if (left.txid !== right.txid) return left.txid < right.txid ? -1 : 1;
  return left.index - right.index;
}

async function custodyCall<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (cause) {
    if (cause instanceof WalletBackupError) {
      throw new NodeApiError(cause.message, cause.code === "invalid_passphrase" ? 400 : 401, cause.code);
    }
    if (cause instanceof StorageUnavailableError) throw new NodeApiError(cause.message, 507, "storage_unavailable");
    throw cause;
  }
}

function unavailable(message: string) {
  return new NodeApiError(message, 501, "web_wallet_unavailable");
}

function defaultBackupName(timestamp: number) {
  return `common-foundry-wallet-${new Date(timestamp).toISOString().slice(0, 10)}.cmfd-backup`;
}

function emptySnapshot(network: string): WalletSnapshot {
  return {
    network,
    devnet_only: false,
    insecure_demo_wallet: false,
    warning: "",
    destination: "",
    accepted_height: 0,
    next_height: 0,
    balances: { spendable_atoms: "0", immature_atoms: "0", pending_atoms: "0" },
    spendable_utxo_count: 0,
    immature_utxo_count: 0,
    reserved_utxo_count: 0,
    mempool: { transactions: 0, bytes: 0 },
    history_limit: 0,
    history: [],
  };
}

function nodeStatus(snapshot: ExplorerSnapshot): NodeStatus {
  const idle = { active: 0, queued: 0, wait_events: 0, rejections: 0, proof_failures: 0 };
  return {
    network: snapshot.network,
    network_short_name: snapshot.network_short_name,
    network_notice: "Your signing key stays in this browser. Balances come from the public explorer index.",
    network_purpose: "Web wallet",
    network_id: snapshot.network_id,
    consensus_fingerprint: snapshot.consensus_fingerprint,
    proof_of_work: snapshot.proof_of_work,
    proof_profile: snapshot.proof_profile,
    rpc_port: 0,
    p2p_port: 0,
    pool_port: 0,
    node_data_dir_identity: "",
    wallet_data_dir_identity: "",
    miner_data_dir_identity: "",
    bounded_reference_mining: false,
    tip: snapshot.tip,
    cumulative_work: snapshot.cumulative_work,
    accepted_height: snapshot.accepted_height,
    next_height: snapshot.accepted_height + 1,
    expected_target: snapshot.expected_target,
    utxo_count: snapshot.utxo_count,
    mempool_transactions: snapshot.mempool_transactions,
    mempool_bytes: snapshot.mempool_bytes,
    proof_verification_active: 0,
    proof_verification_queued: 0,
    proof_verification_normal_admission: idle,
    proof_verification_priority_admission: idle,
    proof_verification_remote_admission: idle,
    proof_verification_remote_admission_capacity: 0,
    proof_verification_remote_admission_wait_timeout_ms: 0,
    proof_verification_capacity: 0,
    proof_verification_queue_capacity: 0,
    proof_verification_mode: "none",
    proof_verification_timeout_ms: null,
    proof_verification_memory_limit_bytes: null,
    proof_verification_teardown_failures: null,
    storage_healthy: true,
    public_peer_mode: false,
    peers: [],
  };
}

const browserFiles: BackupFiles = {
  pick: () => new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".cmfd-backup,application/octet-stream";
    input.addEventListener("change", () => resolve(input.files?.[0] ?? null), { once: true });
    input.addEventListener("cancel", () => resolve(null), { once: true });
    input.click();
  }),
  save: (name, bytes) => {
    const url = URL.createObjectURL(new Blob([bytes as Uint8Array<ArrayBuffer>], { type: "application/octet-stream" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    link.rel = "noopener";
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
  },
};
