// @vitest-environment node
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it, vi } from "vitest";
import { NodeApiError } from "../api/errors";
import { decryptWalletKey } from "./backup";
import { publicKeyHex, signTransaction } from "./codec";
import type { AddressUtxo, EdgeApi, ExplorerAddress, ExplorerSnapshot } from "./edgeApi";
import vectors from "./fixtures/rust-vectors.json";
import { createLocalWalletStore } from "./store";
import { createWebNodeTransport, MAINNET_NETWORK_ID, type BackupFiles } from "./webTransport";

const PASSPHRASE = vectors.backup.passphrase;
const ME = vectors.backup.destination;
const OTHER = vectors.secrets[0].public_key;

function memoryStorage(): Storage {
  const items = new Map<string, string>();
  return {
    get length() { return items.size; },
    clear: () => items.clear(),
    getItem: (key) => items.get(key) ?? null,
    key: (index) => [...items.keys()][index] ?? null,
    removeItem: (key) => { items.delete(key); },
    setItem: (key, value) => { items.set(key, value); },
  };
}

function snapshot(overrides: Partial<ExplorerSnapshot> = {}): ExplorerSnapshot {
  return {
    network: "CommonFoundry Mainnet",
    network_short_name: "Mainnet",
    network_id: MAINNET_NETWORK_ID,
    consensus_fingerprint: "e9".repeat(32),
    proof_of_work: "ForgeMatrix-v4",
    proof_profile: "ProductionV4",
    tip: "aa".repeat(32),
    cumulative_work: "01",
    accepted_height: 3_600,
    expected_target: "00".repeat(32),
    utxo_count: 19_000,
    mempool_transactions: 1,
    mempool_bytes: 291,
    connected_peers: 40,
    recent_transactions: [
      { txid: "cc".repeat(32), status: "mempool", block_id: null, block_height: null, timestamp: null, encoded_bytes: 291, fee_burned_atoms: "10000000" },
    ],
    ...overrides,
  };
}

function address(overrides: Partial<ExplorerAddress> = {}): ExplorerAddress {
  return {
    address: ME,
    tip: "aa".repeat(32),
    accepted_height: 3_600,
    confirmed_atoms: "1000000000",
    spendable_atoms: "1000000000",
    immature_atoms: "0",
    utxo_count: 3,
    history: [],
    page_limit: 20,
    has_more: false,
    next_cursor: null,
    ...overrides,
  };
}

const coin = (byte: string, value: number, vout = 0): AddressUtxo => ({ txid: byte.repeat(32), vout, value_atoms: String(value), spendable_height: 10 });

function harness(utxos: AddressUtxo[] = [coin("01", 100_000_000), coin("02", 500_000_000), coin("03", 400_000_000)]) {
  const api = {
    snapshot: vi.fn(async () => snapshot()),
    address: vi.fn(async () => address()),
    transaction: vi.fn(async () => null),
    utxos: vi.fn(async () => ({ height: 3_600, utxos, has_more: false, next_cursor: null })),
    transactionOutputs: vi.fn(async () => ({ vout: [] as { value_atoms: string; destination_hex: string | null }[] })),
    broadcast: vi.fn(async (hex: string) => ({ txid: "" + hex.length })),
  } satisfies EdgeApi;
  const saved: { name: string; bytes: Uint8Array }[] = [];
  let picked: File | null = null;
  const files: BackupFiles = {
    pick: async () => picked,
    save: (name, bytes) => { saved.push({ name, bytes }); },
  };
  let clock = Date.parse("2026-10-05T12:00:00Z");
  const storage = memoryStorage();
  const store = createLocalWalletStore(MAINNET_NETWORK_ID, () => storage);
  const transport = createWebNodeTransport({ api, store, files, now: () => clock });
  return {
    api,
    saved,
    store,
    transport,
    pick(file: File) { picked = file; },
    advance(ms: number) { clock += ms; },
  };
}

/** Make broadcast echo the txid the transaction actually has. */
function acceptBroadcasts(api: ReturnType<typeof harness>["api"], secret: string) {
  const txids = new Map<string, string>();
  api.broadcast.mockImplementation(async (hex: string) => {
    const known = txids.get(hex);
    if (known) return { txid: known };
    throw new Error("unexpected frame");
  });
  return (unsigned: Parameters<typeof signTransaction>[0]) => {
    const signed = signTransaction(unsigned, hexToBytes(secret));
    txids.set(bytesToHex(signed.frame), signed.txid);
  };
}

async function restoredWallet(h: ReturnType<typeof harness>) {
  h.pick(new File([hexToBytes(vectors.backup.encrypted) as Uint8Array<ArrayBuffer>], "known.cmfd-backup"));
  const name = await h.transport.chooseWalletBackupPath(true);
  return h.transport.restoreWallet(name!, PASSPHRASE);
}

describe("web wallet custody", () => {
  it("creates an encrypted wallet, downloads its backup, and stays unlocked", async () => {
    const h = harness();
    expect(await h.transport.getWalletCustodyStatus()).toMatchObject({ storage: "missing", unlocked: false, can_restore: true });

    const status = await h.transport.createWallet("", PASSPHRASE);
    expect(status).toMatchObject({ storage: "encrypted", unlocked: true, data_directory: "This browser" });
    expect(h.saved).toHaveLength(1);
    expect(h.saved[0].name).toBe("common-foundry-wallet-2026-10-05.cmfd-backup");
    const opened = await decryptWalletKey(h.saved[0].bytes, MAINNET_NETWORK_ID, PASSPHRASE);
    expect(opened.destination).toBe(status.destination);
    await expect(h.transport.createWallet("", PASSPHRASE)).rejects.toMatchObject({ code: "wallet_exists" });
  });

  it("restores a desktop backup, locks, and unlocks only with the right passphrase", async () => {
    const h = harness();
    expect(await restoredWallet(h)).toMatchObject({ unlocked: true, destination: ME });
    expect((await h.transport.lockWallet()).unlocked).toBe(false);
    expect(await h.transport.getWalletSnapshot()).toMatchObject({ destination: "", history: [] });
    await expect(h.transport.unlockWallet("not the passphrase")).rejects.toMatchObject({ status: 401, code: "authentication_failed" });
    expect(await h.transport.unlockWallet(PASSPHRASE)).toMatchObject({ unlocked: true, destination: ME });
  });

  it("verifies the passphrase before downloading a backup", async () => {
    const h = harness();
    await restoredWallet(h);
    await expect(h.transport.backupWallet("", "not the passphrase")).rejects.toMatchObject({ code: "authentication_failed" });
    expect(h.saved).toHaveLength(0);
    await h.transport.backupWallet("", PASSPHRASE);
    expect(bytesToHex(h.saved[0].bytes)).toBe(vectors.backup.encrypted);
  });
});

describe("web wallet chain data", () => {
  it("refuses a network service that reports another network", async () => {
    const h = harness();
    h.api.snapshot.mockResolvedValue(snapshot({ network_id: "00".repeat(32) }));
    await expect(h.transport.getNodeStatus()).rejects.toMatchObject({ code: "network_mismatch" });
  });

  it("maps explorer activity into wallet history", async () => {
    const h = harness();
    await restoredWallet(h);
    h.api.address.mockResolvedValue(address({
      immature_atoms: "5",
      history: [
        { txid: "a1".repeat(32), block_id: "b1".repeat(32), block_height: 3_599, timestamp: 1, confirmations: 2, kind: "coinbase", received_atoms: "5", received_outputs: 1, spent_inputs: 0 },
        { txid: "a2".repeat(32), block_id: "b2".repeat(32), block_height: 3_500, timestamp: 2, confirmations: 101, kind: "received", received_atoms: "70", received_outputs: 1, spent_inputs: 0 },
        { txid: "a3".repeat(32), block_id: "b3".repeat(32), block_height: 3_400, timestamp: 3, confirmations: 201, kind: "sent", received_atoms: "30", received_outputs: 1, spent_inputs: 1 },
      ],
    }));
    h.api.transactionOutputs.mockResolvedValue({ vout: [{ value_atoms: "40", destination_hex: OTHER }, { value_atoms: "30", destination_hex: ME }] });

    const wallet = await h.transport.getWalletSnapshot();
    expect(wallet.history.map((entry) => [entry.kind, entry.status, entry.net_amount_atoms, entry.counterparty])).toEqual([
      ["mined", "immature", "5", null],
      ["received", "confirmed", "70", null],
      ["sent", "confirmed", "-40", OTHER],
    ]);
    expect(wallet.history[2].fee_unknown).toBe(true);
    expect(h.api.transactionOutputs).toHaveBeenCalledWith("a3".repeat(32), "b3".repeat(32), undefined);

    await h.transport.getWalletSnapshot();
    expect(h.api.transactionOutputs).toHaveBeenCalledTimes(1);
  });
});

describe("web wallet spending", () => {
  it("selects largest coins first, returns change, and reserves inputs until confirmation", async () => {
    const h = harness();
    await restoredWallet(h);
    const expect_ = acceptBroadcasts(h.api, vectors.backup.secret);
    const spendableHeight = 3_601n;
    expect_({
      networkId: MAINNET_NETWORK_ID,
      inputs: [{ txid: "02".repeat(32), index: 0 }, { txid: "03".repeat(32), index: 0 }],
      outputs: [
        { value: 600_000_000n, destination: OTHER, spendableHeight },
        { value: 290_000_000n, destination: ME, spendableHeight },
      ],
    });

    const result = await h.transport.sendWalletTransaction({ recipient: OTHER.toUpperCase(), amount: "6", fee: "0.1" });
    expect(result).toMatchObject({ amount_atoms: "600000000", fee_burned_atoms: "10000000", change_atoms: "290000000", mempool_transactions: 1 });

    const pending = await h.transport.getWalletSnapshot();
    expect(pending.balances).toEqual({ spendable_atoms: "100000000", immature_atoms: "0", pending_atoms: "290000000" });
    expect(pending.history[0]).toMatchObject({ kind: "sent", status: "pending", net_amount_atoms: "-610000000", counterparty: OTHER });

    // Reserved coins are never offered to the next spend.
    await expect(h.transport.sendWalletTransaction({ recipient: OTHER, amount: "2", fee: "0.1" }))
      .rejects.toMatchObject({ code: "insufficient_funds" });

    h.api.transaction.mockResolvedValue({ txid: result.txid, status: "confirmed", block_id: "b9".repeat(32), block_height: 3_601, timestamp: 9, encoded_bytes: 508, fee_burned_atoms: null } as never);
    h.api.address.mockResolvedValue(address({ accepted_height: 3_601, spendable_atoms: "390000000" }));
    const confirmed = await h.transport.getWalletSnapshot();
    expect(confirmed.balances.spendable_atoms).toBe("390000000");
    expect(confirmed.history.filter((entry) => entry.status === "pending")).toHaveLength(0);
  });

  it("releases inputs after a definite rejection but keeps them after an ambiguous failure", async () => {
    const h = harness([coin("01", 500_000_000)]);
    await restoredWallet(h);
    h.api.broadcast.mockRejectedValueOnce(new NodeApiError("fee too low", 422, "transaction_rejected"));
    await expect(h.transport.sendWalletTransaction({ recipient: OTHER, amount: "1", fee: "0.1" })).rejects.toMatchObject({ status: 422 });
    expect((await h.transport.getWalletSnapshot()).balances.spendable_atoms).toBe("1000000000");

    h.api.broadcast.mockRejectedValueOnce(new NodeApiError("upstream timeout", 502, "upstream_failure"));
    await expect(h.transport.sendWalletTransaction({ recipient: OTHER, amount: "1", fee: "0.1" })).rejects.toMatchObject({ status: 502 });
    expect((await h.transport.getWalletSnapshot()).balances.spendable_atoms).toBe("500000000");

    // A transaction the explorer never saw is dropped after 30 minutes, freeing its inputs.
    h.advance(31 * 60_000);
    expect((await h.transport.getWalletSnapshot()).balances.spendable_atoms).toBe("1000000000");
  });

  it("consolidates the smallest coins into one output to itself", async () => {
    const h = harness([coin("01", 300), coin("02", 200_000_000), coin("03", 100_000_000), coin("04", 50_000_000)]);
    await restoredWallet(h);
    const expect_ = acceptBroadcasts(h.api, vectors.backup.secret);
    expect_({
      networkId: MAINNET_NETWORK_ID,
      inputs: [{ txid: "01".repeat(32), index: 0 }, { txid: "04".repeat(32), index: 0 }, { txid: "03".repeat(32), index: 0 }],
      outputs: [{ value: 140_000_300n, destination: ME, spendableHeight: 3_601n }],
    });
    const result = await h.transport.consolidateWallet({ fee: "0.1", max_inputs: 3 });
    expect(result).toMatchObject({ inputs_consolidated: 3, input_atoms: "150000300", output_atoms: "140000300" });
  });

  it("validates recipients and fees before touching the network", async () => {
    const h = harness();
    await restoredWallet(h);
    await expect(h.transport.sendWalletTransaction({ recipient: "00".repeat(31) + "05", amount: "1", fee: "0.1" })).rejects.toMatchObject({ code: "invalid_recipient" });
    await expect(h.transport.sendWalletTransaction({ recipient: OTHER, amount: "1", fee: "0.01" })).rejects.toMatchObject({ code: "fee_too_low" });
    expect(h.api.utxos).not.toHaveBeenCalled();
    expect(publicKeyHex(hexToBytes(vectors.backup.secret))).toBe(ME);
  });
});
