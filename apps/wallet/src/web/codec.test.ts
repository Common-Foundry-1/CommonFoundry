// @vitest-environment node
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  isValidDestination,
  networkMagic,
  publicKeyHex,
  signingDigest,
  signTransaction,
  type UnsignedTransaction,
} from "./codec";
import vectors from "./fixtures/rust-vectors.json";

function unsigned(vector: (typeof vectors.transactions)[number]): UnsignedTransaction {
  return {
    networkId: vector.transaction.network_id,
    inputs: vector.transaction.inputs.map(({ txid, index }) => ({ txid, index })),
    outputs: vector.transaction.outputs.map((output) => ({
      value: BigInt(output.value),
      destination: output.destination,
      spendableHeight: BigInt(output.spendable_height),
    })),
  };
}

describe("consensus transaction codec", () => {
  it("derives the Rust network magic", () => {
    expect(bytesToHex(networkMagic(vectors.network_id))).toBe(vectors.network_magic);
  });

  it.each(vectors.secrets)("derives the x-only key for $secret", ({ secret, public_key }) => {
    expect(publicKeyHex(hexToBytes(secret))).toBe(public_key);
    expect(isValidDestination(public_key)).toBe(true);
  });

  it.each(vectors.transactions)("matches Rust byte-for-byte: $name", (vector) => {
    const transaction = unsigned(vector);
    const secret = hexToBytes(vector.secret);
    expect(bytesToHex(signingDigest(transaction, hexToBytes(vector.public_key)))).toBe(vector.signing_digest);
    const signed = signTransaction(transaction, secret);
    expect(signed.txid).toBe(vector.txid);
    expect(bytesToHex(signed.frame)).toBe(vector.frame);
    expect(bytesToHex(signed.frame)).toContain(vector.signature);
  });

  it("rejects malformed recipients", () => {
    expect(isValidDestination("A".repeat(64))).toBe(false);
    expect(isValidDestination("ab".repeat(31))).toBe(false);
    // x = 5 is not on secp256k1 (5^3 + 7 is a non-residue), so lift_x fails like VerifyingKey::from_bytes.
    expect(isValidDestination("00".repeat(31) + "05")).toBe(false);
  });

  it("refuses shapes consensus would reject", () => {
    const base = unsigned(vectors.transactions[0]);
    const secret = hexToBytes(vectors.transactions[0].secret);
    expect(() => signTransaction({ ...base, inputs: [] }, secret)).toThrow(/inputs/);
    expect(() => signTransaction({ ...base, outputs: [{ ...base.outputs[0], value: 0n }] }, secret)).toThrow(/positive/);
    expect(() => signTransaction({ ...base, inputs: [base.inputs[0], base.inputs[0]] }, secret)).toThrow(/twice/);
    expect(() => signTransaction({ ...base, outputs: [{ ...base.outputs[0], destination: "00".repeat(31) + "05" }] }, secret)).toThrow(/destination/);
  });
});
