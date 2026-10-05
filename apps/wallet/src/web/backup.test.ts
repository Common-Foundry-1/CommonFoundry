// @vitest-environment node
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { decryptWalletKey, encryptWalletKey, ENCRYPTED_WALLET_BYTES, inspectWalletKey } from "./backup";
import vectors from "./fixtures/rust-vectors.json";

const { backup } = vectors;
const NETWORK = vectors.network_id;

describe("CMFDWLT1 encrypted wallet keys", () => {
  it("opens a backup written by the Rust wallet", async () => {
    const opened = await decryptWalletKey(hexToBytes(backup.encrypted), NETWORK, backup.passphrase);
    expect(bytesToHex(opened.secretKey)).toBe(backup.secret);
    expect(opened.destination).toBe(backup.destination);
  });

  it("round-trips its own backups with the Rust header layout", async () => {
    const encrypted = await encryptWalletKey(hexToBytes(backup.secret), NETWORK, backup.passphrase);
    expect(encrypted).toHaveLength(ENCRYPTED_WALLET_BYTES);
    expect(bytesToHex(encrypted.subarray(0, 24))).toBe(backup.encrypted.slice(0, 48));
    expect(inspectWalletKey(encrypted)).toEqual({ networkId: NETWORK, destination: backup.destination });
    const opened = await decryptWalletKey(encrypted, NETWORK, backup.passphrase);
    expect(bytesToHex(opened.secretKey)).toBe(backup.secret);
  });

  it("fails closed on a wrong passphrase, network, or tampered header", async () => {
    const encrypted = hexToBytes(backup.encrypted);
    await expect(decryptWalletKey(encrypted, NETWORK, "wrong passphrase!")).rejects.toMatchObject({ code: "authentication_failed" });
    await expect(decryptWalletKey(encrypted, "00".repeat(32), backup.passphrase)).rejects.toMatchObject({ code: "wrong_network" });
    await expect(decryptWalletKey(encrypted, NETWORK, "short")).rejects.toMatchObject({ code: "invalid_passphrase" });
    const tampered = encrypted.slice();
    tampered[127] ^= 1;
    await expect(decryptWalletKey(tampered, NETWORK, backup.passphrase)).rejects.toMatchObject({ code: "authentication_failed" });
    await expect(decryptWalletKey(encrypted.slice(1), NETWORK, backup.passphrase)).rejects.toMatchObject({ code: "invalid_backup" });
  });
});
