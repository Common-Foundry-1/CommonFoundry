// Browser persistence for the web wallet. Only the encrypted CMFDWLT1 key is stored;
// the decrypted signing key never leaves memory.
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

const PREFIX = "cmfd-web-wallet:v1";

/** A transaction this browser signed; kept so its inputs stay reserved and its amounts stay exact. */
export interface LocalTransaction {
  txid: string;
  kind: "sent" | "consolidated";
  created_at: number;
  recipient: string | null;
  amount_atoms: string;
  fee_atoms: string;
  change_atoms: string;
  input_atoms: string;
  inputs: string[];
  encoded_bytes: number;
  state: "pending" | "confirmed" | "dropped";
}

/** Amount paid to other addresses by a confirmed send this browser did not sign. */
export interface SentLookup {
  sent_atoms: string;
  counterparty: string | null;
}

export interface WalletStore {
  loadKey(): Uint8Array | null;
  saveKey(encrypted: Uint8Array): void;
  removeKey(): void;
  loadTransactions(destination: string): LocalTransaction[];
  saveTransactions(destination: string, transactions: LocalTransaction[]): void;
  loadLookups(): Record<string, SentLookup>;
  saveLookups(lookups: Record<string, SentLookup>): void;
}

export class StorageUnavailableError extends Error {
  constructor() {
    super("This browser is blocking site storage, so the wallet cannot be kept here. Allow storage for this site or use a normal (non-private) window.");
    this.name = "StorageUnavailableError";
  }
}

export function createLocalWalletStore(networkId: string, storage: () => Storage = () => window.localStorage): WalletStore {
  const keyName = `${PREFIX}:${networkId}:key`;
  const lookupsName = `${PREFIX}:${networkId}:lookups`;
  const transactionsName = (destination: string) => `${PREFIX}:${networkId}:${destination}:transactions`;

  const read = (name: string): string | null => {
    try {
      return storage().getItem(name);
    } catch {
      return null;
    }
  };
  const write = (name: string, value: string) => {
    try {
      storage().setItem(name, value);
    } catch {
      throw new StorageUnavailableError();
    }
  };
  const readJson = <T>(name: string, fallback: T): T => {
    const raw = read(name);
    if (raw === null) return fallback;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return fallback;
    }
  };

  return {
    loadKey: () => {
      const hex = read(keyName);
      return hex && /^[0-9a-f]+$/.test(hex) ? hexToBytes(hex) : null;
    },
    saveKey: (encrypted) => write(keyName, bytesToHex(encrypted)),
    removeKey: () => {
      try {
        storage().removeItem(keyName);
      } catch {
        throw new StorageUnavailableError();
      }
    },
    loadTransactions: (destination) => {
      const value = readJson<unknown>(transactionsName(destination), []);
      return Array.isArray(value) ? value as LocalTransaction[] : [];
    },
    saveTransactions: (destination, transactions) => write(transactionsName(destination), JSON.stringify(transactions)),
    loadLookups: () => readJson<Record<string, SentLookup>>(lookupsName, {}),
    saveLookups: (lookups) => write(lookupsName, JSON.stringify(lookups)),
  };
}
