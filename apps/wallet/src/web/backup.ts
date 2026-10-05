// Browser port of the CMFDWLT1 encrypted key format (crates/cmfd-node/src/wallet_backup.rs).
// The same 176-byte file is the desktop wallet.key, a .cmfd-backup, and the web wallet's stored key.
import { schnorr } from "@noble/curves/secp256k1.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { equalBytes } from "@noble/ciphers/utils.js";
import { argon2idAsync } from "@noble/hashes/argon2.js";
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

const MAGIC = /* @__PURE__ */ utf8ToBytes("CMFDWLT1");
const VERSION = 1;
const KDF_ARGON2ID = 1;
const CIPHER_XCHACHA20_POLY1305 = 1;
const ARGON2_MEMORY_KIB = 65_536;
const ARGON2_ITERATIONS = 3;
const ARGON2_PARALLELISM = 1;
const SALT_BYTES = 16;
const NONCE_BYTES = 24;
const SECRET_BYTES = 32;
const TAG_BYTES = 16;
const HEADER_BYTES = 8 + 2 + 1 + 1 + 4 + 4 + 4 + SALT_BYTES + NONCE_BYTES + 32 + 32;
export const ENCRYPTED_WALLET_BYTES = HEADER_BYTES + SECRET_BYTES + TAG_BYTES;
export const MINIMUM_PASSPHRASE_BYTES = 12;
export const MAXIMUM_PASSPHRASE_BYTES = 1_024;

export type BackupErrorCode =
  | "invalid_passphrase"
  | "invalid_backup"
  | "wrong_network"
  | "authentication_failed"
  | "destination_mismatch";

export class WalletBackupError extends Error {
  readonly code: BackupErrorCode;

  constructor(code: BackupErrorCode, message: string) {
    super(message);
    this.name = "WalletBackupError";
    this.code = code;
  }
}

export interface DecryptedWallet {
  secretKey: Uint8Array;
  destination: string;
}

function passphraseBytes(passphrase: string): Uint8Array {
  const bytes = utf8ToBytes(passphrase);
  if (bytes.length < MINIMUM_PASSPHRASE_BYTES || bytes.length > MAXIMUM_PASSPHRASE_BYTES) {
    throw new WalletBackupError("invalid_passphrase", "Use a passphrase between 12 and 1024 bytes long.");
  }
  return bytes;
}

async function deriveKey(passphrase: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  try {
    return await argon2idAsync(passphrase, salt, {
      m: ARGON2_MEMORY_KIB,
      t: ARGON2_ITERATIONS,
      p: ARGON2_PARALLELISM,
      dkLen: 32,
      asyncTick: 25,
    });
  } finally {
    passphrase.fill(0);
  }
}

function header(networkId: Uint8Array, destination: Uint8Array, salt: Uint8Array, nonce: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(HEADER_BYTES);
  const view = new DataView(bytes.buffer);
  bytes.set(MAGIC, 0);
  view.setUint16(8, VERSION, true);
  bytes[10] = KDF_ARGON2ID;
  bytes[11] = CIPHER_XCHACHA20_POLY1305;
  view.setUint32(12, ARGON2_MEMORY_KIB, true);
  view.setUint32(16, ARGON2_ITERATIONS, true);
  view.setUint32(20, ARGON2_PARALLELISM, true);
  bytes.set(salt, 24);
  bytes.set(nonce, 40);
  bytes.set(networkId, 64);
  bytes.set(destination, 96);
  return bytes;
}

export async function encryptWalletKey(
  secretKey: Uint8Array,
  networkId: string,
  passphrase: string,
): Promise<Uint8Array> {
  const password = passphraseBytes(passphrase);
  const destination = schnorr.getPublicKey(secretKey);
  const salt = randomBytes(SALT_BYTES);
  const nonce = randomBytes(NONCE_BYTES);
  const aad = header(hexToBytes(networkId), destination, salt, nonce);
  const key = await deriveKey(password, salt);
  try {
    const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(secretKey);
    const encrypted = new Uint8Array(ENCRYPTED_WALLET_BYTES);
    encrypted.set(aad, 0);
    encrypted.set(ciphertext, HEADER_BYTES);
    return encrypted;
  } finally {
    key.fill(0);
  }
}

/** Unauthenticated header fields; the destination is trusted only after decryption. */
export function inspectWalletKey(encrypted: Uint8Array): { networkId: string; destination: string } {
  if (!hasSupportedHeader(encrypted)) throw new WalletBackupError("invalid_backup", "This is not a Common Foundry wallet backup.");
  return {
    networkId: bytesToHex(encrypted.subarray(64, 96)),
    destination: bytesToHex(encrypted.subarray(96, 128)),
  };
}

export async function decryptWalletKey(
  encrypted: Uint8Array,
  networkId: string,
  passphrase: string,
): Promise<DecryptedWallet> {
  const password = passphraseBytes(passphrase);
  const header = inspectWalletKey(encrypted);
  if (header.networkId !== networkId) {
    throw new WalletBackupError("wrong_network", "This wallet backup belongs to a different network.");
  }
  const key = await deriveKey(password, encrypted.slice(24, 40));
  let secretKey: Uint8Array;
  try {
    secretKey = xchacha20poly1305(key, encrypted.slice(40, 64), encrypted.slice(0, HEADER_BYTES))
      .decrypt(encrypted.slice(HEADER_BYTES));
  } catch {
    throw new WalletBackupError("authentication_failed", "The passphrase is incorrect or the backup is damaged.");
  } finally {
    key.fill(0);
  }
  let destination: Uint8Array;
  try {
    destination = schnorr.getPublicKey(secretKey);
  } catch {
    secretKey.fill(0);
    throw new WalletBackupError("invalid_backup", "This wallet backup does not contain a valid key.");
  }
  if (!equalBytes(destination, encrypted.subarray(96, 128))) {
    secretKey.fill(0);
    throw new WalletBackupError("destination_mismatch", "The backup key does not match its recorded address.");
  }
  return { secretKey, destination: bytesToHex(destination) };
}

function hasSupportedHeader(encrypted: Uint8Array): boolean {
  if (encrypted.length !== ENCRYPTED_WALLET_BYTES) return false;
  const view = new DataView(encrypted.buffer, encrypted.byteOffset, encrypted.byteLength);
  return equalBytes(encrypted.subarray(0, 8), MAGIC)
    && view.getUint16(8, true) === VERSION
    && encrypted[10] === KDF_ARGON2ID
    && encrypted[11] === CIPHER_XCHACHA20_POLY1305
    && view.getUint32(12, true) === ARGON2_MEMORY_KIB
    && view.getUint32(16, true) === ARGON2_ITERATIONS
    && view.getUint32(20, true) === ARGON2_PARALLELISM;
}
