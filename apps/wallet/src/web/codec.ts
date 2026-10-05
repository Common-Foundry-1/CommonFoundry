// Browser port of the consensus transaction encoding (crates/cmfd-consensus/src/chain.rs
// and wire.rs). Golden vectors from the Rust code pin every byte; see codec.test.ts.
import { schnorr } from "@noble/curves/secp256k1.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

const TX_SIGNING_DOMAIN = /* @__PURE__ */ utf8ToBytes("CMFD/TRANSACTION/SIGNING/V1");
const TX_ID_DOMAIN = /* @__PURE__ */ utf8ToBytes("CMFD/TRANSACTION/ID/V1");
const NETWORK_MAGIC_DOMAIN = /* @__PURE__ */ utf8ToBytes("CMFD/WIRE/NETWORK-MAGIC/V1");
const FRAME_MAGIC = /* @__PURE__ */ utf8ToBytes("CMFD");
const WIRE_VERSION = 1;
const TRANSACTION_KIND = 1;
const TRANSACTION_VERSION = 1;
const KEY_WITNESS_TAG = 0;
const KEY_LOCK_TAG = 0;
const SIGNATURE_BYTES = 64;
const U64_MAX = (1n << 64n) - 1n;

export const MAX_TRANSACTION_INPUTS = 128;
export const MAX_TRANSACTION_OUTPUTS = 128;
export const MAX_TRANSACTION_BYTES = 64 * 1024;

const HASH_HEX = /^[0-9a-f]{64}$/;

export interface OutPoint {
  txid: string;
  index: number;
}

export interface TransactionOutput {
  value: bigint;
  destination: string;
  spendableHeight: bigint;
}

export interface UnsignedTransaction {
  networkId: string;
  inputs: OutPoint[];
  outputs: TransactionOutput[];
}

export interface SignedTransaction {
  txid: string;
  frame: Uint8Array;
}

/** A recipient is valid only when it is a lowercase 64-hex x-only key on secp256k1. */
export function isValidDestination(value: string): boolean {
  if (!HASH_HEX.test(value)) return false;
  try {
    schnorr.utils.lift_x(BigInt(`0x${value}`));
    return true;
  } catch {
    return false;
  }
}

export function publicKeyHex(secretKey: Uint8Array): string {
  return bytesToHex(schnorr.getPublicKey(secretKey));
}

export function networkMagic(networkId: string): Uint8Array {
  return blake3(hash32(networkId, "network id"), { context: NETWORK_MAGIC_DOMAIN }).slice(0, 4);
}

/**
 * Signs every input with one key, as Transaction::sign_all does: BIP340 over
 * SHA-256(signing digest) with zero auxiliary randomness (k256's `Signer::sign`).
 */
export function signTransaction(transaction: UnsignedTransaction, secretKey: Uint8Array): SignedTransaction {
  validateShape(transaction);
  const publicKey = schnorr.getPublicKey(secretKey);
  const digest = signingDigest(transaction, publicKey);
  const signature = schnorr.sign(sha256(digest), secretKey, new Uint8Array(32));
  const frame = encodeFrame(transaction, publicKey, signature);
  if (frame.length > MAX_TRANSACTION_BYTES) throw new Error("The transaction is larger than 64 KiB.");
  return { txid: bytesToHex(transactionId(transaction, publicKey, signature)), frame };
}

export function signingDigest(transaction: UnsignedTransaction, publicKey: Uint8Array): Uint8Array {
  const hasher = blake3.create({ context: TX_SIGNING_DOMAIN });
  hasher.update(unsignedEncoding(transaction, publicKey));
  return hasher.digest();
}

function transactionId(transaction: UnsignedTransaction, publicKey: Uint8Array, signature: Uint8Array): Uint8Array {
  const writer = new Writer();
  for (let index = 0; index < transaction.inputs.length; index += 1) {
    writer.u8(KEY_WITNESS_TAG);
    writer.bytes(publicKey);
    writer.u64(BigInt(signature.length));
    writer.bytes(signature);
  }
  const hasher = blake3.create({ context: TX_ID_DOMAIN });
  hasher.update(unsignedEncoding(transaction, publicKey));
  hasher.update(writer.finish());
  return hasher.digest();
}

// encode_unsigned_transaction: counts are u64 here, unlike the u32 wire counts.
function unsignedEncoding(transaction: UnsignedTransaction, publicKey: Uint8Array): Uint8Array {
  const writer = new Writer();
  writer.bytes(hash32(transaction.networkId, "network id"));
  writer.u32(TRANSACTION_VERSION);
  writer.u64(BigInt(transaction.inputs.length));
  for (const input of transaction.inputs) {
    writer.bytes(hash32(input.txid, "input txid"));
    writer.u32(input.index);
    writer.u8(KEY_WITNESS_TAG);
    writer.bytes(publicKey);
  }
  writer.u64(BigInt(transaction.outputs.length));
  for (const output of transaction.outputs) writeOutput(writer, output);
  return writer.finish();
}

function encodeFrame(transaction: UnsignedTransaction, publicKey: Uint8Array, signature: Uint8Array): Uint8Array {
  if (signature.length !== SIGNATURE_BYTES) throw new Error("Signatures must be 64 bytes.");
  const payload = new Writer();
  payload.bytes(hash32(transaction.networkId, "network id"));
  payload.u32(TRANSACTION_VERSION);
  payload.u32(transaction.inputs.length);
  for (const input of transaction.inputs) {
    payload.bytes(hash32(input.txid, "input txid"));
    payload.u32(input.index);
    payload.u8(KEY_WITNESS_TAG);
    payload.bytes(publicKey);
    payload.bytes(signature);
  }
  payload.u32(transaction.outputs.length);
  for (const output of transaction.outputs) writeOutput(payload, output);
  const body = payload.finish();

  const frame = new Writer();
  frame.bytes(FRAME_MAGIC);
  frame.bytes(networkMagic(transaction.networkId));
  frame.u16(WIRE_VERSION);
  frame.u8(TRANSACTION_KIND);
  frame.u8(0);
  frame.u32(body.length);
  frame.bytes(body);
  return frame.finish();
}

function writeOutput(writer: Writer, output: TransactionOutput) {
  writer.u64(output.value);
  writer.u8(KEY_LOCK_TAG);
  writer.bytes(hash32(output.destination, "output destination"));
  writer.u64(output.spendableHeight);
}

function validateShape(transaction: UnsignedTransaction) {
  const { inputs, outputs } = transaction;
  if (inputs.length === 0 || inputs.length > MAX_TRANSACTION_INPUTS) {
    throw new Error(`A transaction needs between 1 and ${MAX_TRANSACTION_INPUTS} inputs.`);
  }
  if (outputs.length === 0 || outputs.length > MAX_TRANSACTION_OUTPUTS) {
    throw new Error(`A transaction needs between 1 and ${MAX_TRANSACTION_OUTPUTS} outputs.`);
  }
  const spent = new Set<string>();
  for (const input of inputs) {
    const key = `${input.txid}:${input.index}`;
    if (spent.has(key)) throw new Error("A transaction cannot spend the same output twice.");
    spent.add(key);
  }
  let total = 0n;
  for (const output of outputs) {
    if (output.value <= 0n) throw new Error("Transaction outputs must carry a positive amount.");
    if (!isValidDestination(output.destination)) throw new Error("A transaction output has an invalid destination.");
    total += output.value;
    if (total > U64_MAX) throw new Error("Transaction outputs overflow.");
  }
}

function hash32(value: string, field: string): Uint8Array {
  if (!HASH_HEX.test(value)) throw new Error(`Invalid ${field}.`);
  return hexToBytes(value);
}

class Writer {
  private readonly chunks: Uint8Array[] = [];
  private length = 0;

  bytes(value: Uint8Array) {
    this.chunks.push(value);
    this.length += value.length;
  }

  u8(value: number) {
    this.bytes(Uint8Array.of(value));
  }

  u16(value: number) {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    this.bytes(bytes);
  }

  u32(value: number) {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) throw new Error("u32 out of range.");
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    this.bytes(bytes);
  }

  u64(value: bigint) {
    if (value < 0n || value > U64_MAX) throw new Error("u64 out of range.");
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    this.bytes(bytes);
  }

  finish(): Uint8Array {
    const out = new Uint8Array(this.length);
    let offset = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }
}
