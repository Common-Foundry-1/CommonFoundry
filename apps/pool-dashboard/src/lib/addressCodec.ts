// Text forms of a Common Foundry address: a TypeScript port of
// crates/cmfd-node/src/address.rs (1.0.16).
//
// Identical copies live at apps/{wallet,explorer,pool-dashboard}/src/lib/
// addressCodec.ts; addressCodec.test.ts (also identical) fails when they
// differ. Edit one copy, then copy it over the others.
//
// An address is the 32-byte x-only secp256k1 public key that an output pays.
// It is written either as 64 lowercase hex characters (no checksum) or as
// bech32m (BIP-350): the network prefix, "1", 52 key symbols and a 6-symbol
// checksum, with no witness-version symbol. Both forms decode to the same key.
//
// Unlike the Rust codec, this one does not check that the key is a point on
// the curve (no secp256k1 library is bundled); the node and the wallet
// backend refuse such keys.

export const MAINNET_HRP = "cmfd";
export const TEST_NETWORK_HRP = "tcmfd";

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST = 0x2bc830a3;
const CHECKSUM_SYMBOLS = 6;
const KEY_SYMBOLS = 52;
const MAX_LENGTH = 90;
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

export type AddressFormat = "hex" | "bech32m";

export type AddressErrorKind =
  | "unrecognized"
  | "uppercase_hex"
  | "mixed_case"
  | "invalid_character"
  | "checksum"
  | "wrong_network"
  | "wrong_length"
  | "bad_payload";

export class AddressError extends Error {
  readonly kind: AddressErrorKind;

  constructor(kind: AddressErrorKind, message: string) {
    super(message);
    this.name = "AddressError";
    this.kind = kind;
  }
}

const errors = {
  unrecognized: (hrp: string) => new AddressError("unrecognized",
    `expected a ${hrp}1... address or 64 lowercase hexadecimal characters encoding an x-only public key`),
  uppercaseHex: () => new AddressError("uppercase_hex", "hex addresses must be lowercase"),
  mixedCase: () => new AddressError("mixed_case", "address mixes upper and lower case"),
  invalidCharacter: () => new AddressError("invalid_character", "address contains a character that is not used in addresses"),
  checksum: () => new AddressError("checksum", "address checksum does not match: the address is mistyped or incomplete"),
  wrongNetwork: (expected: string, found: string) => new AddressError("wrong_network",
    `address is for another network: expected ${expected}1..., found ${found}1...`),
  wrongLength: () => new AddressError("wrong_length", "address has the wrong length"),
  badPayload: () => new AddressError("bad_payload", "address does not hold a 32-byte key"),
};

/** The address prefix of a network, from its short name ("Mainnet", "RCNet-1"). */
export function hrpForNetwork(networkName: string): string {
  return networkName.toLowerCase() === "mainnet" ? MAINNET_HRP : TEST_NETWORK_HRP;
}

export interface DecodedAddress {
  /** The key as 64 lowercase hex characters. */
  hex: string;
  format: AddressFormat;
}

/**
 * Reads either form of an address for the network whose prefix is `hrp`.
 * Throws an AddressError saying what is wrong with it.
 */
export function decode(hrp: string, text: string): DecodedAddress {
  if (/^[0-9a-fA-F]+$/.test(text)) {
    // Every network prefix has a letter that is not a hex digit, so this is a
    // hex address or a damaged one, never bech32m.
    if (text.length !== 64) throw errors.unrecognized(hrp);
    if (/[A-F]/.test(text)) throw errors.uppercaseHex();
    return { hex: text, format: "hex" };
  }
  if (!text.includes("1")) throw errors.unrecognized(hrp);
  // The checksum is checked before the prefix, so a typo in the prefix is
  // reported as a typo rather than as another network.
  const { hrp: found, symbols } = splitChecked(text);
  if (found !== hrp) throw errors.wrongNetwork(hrp, found);
  const key = keyFromSymbols(symbols);
  if (key === null) throw errors.badPayload();
  return { hex: key, format: "bech32m" };
}

/** Writes a 64-character hex key as a lowercase bech32m address. */
export function encode(hrp: string, hex: string): string {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw errors.unrecognized(hrp);
  const symbols: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (let index = 0; index < 64; index += 2) {
    buffer = ((buffer << 8) | Number.parseInt(hex.slice(index, index + 2), 16)) & 0xfff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      symbols.push((buffer >> bits) & 31);
    }
  }
  if (bits > 0) symbols.push((buffer << (5 - bits)) & 31);
  return joinChecked(hrp, symbols);
}

/** Appends the BIP-350 checksum to 5-bit `symbols` and writes the string. */
export function joinChecked(hrp: string, symbols: readonly number[]): string {
  const value = polymod([...hrpExpand(hrp), ...symbols, 0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST;
  const checksum = Array.from({ length: CHECKSUM_SYMBOLS }, (_, index) => (value >>> (5 * (CHECKSUM_SYMBOLS - 1 - index))) & 31);
  return `${hrp}1${[...symbols, ...checksum].map((symbol) => CHARSET[symbol]).join("")}`;
}

/**
 * Validates any bech32m string (BIP-350) and returns its lowercase prefix and
 * its data symbols without the checksum.
 */
export function splitChecked(text: string): { hrp: string; symbols: number[] } {
  if (new TextEncoder().encode(text).length > MAX_LENGTH) throw errors.wrongLength();
  if ([...text].some((character) => character.charCodeAt(0) < 33 || character.charCodeAt(0) > 126)) {
    throw errors.invalidCharacter();
  }
  if (/[a-z]/.test(text) && /[A-Z]/.test(text)) throw errors.mixedCase();
  const lower = text.toLowerCase();
  const separator = lower.lastIndexOf("1");
  if (separator < 0) throw errors.invalidCharacter();
  const hrp = lower.slice(0, separator);
  const data = lower.slice(separator + 1);
  if (hrp.length === 0 || data.length < CHECKSUM_SYMBOLS) throw errors.wrongLength();
  const symbols = [...data].map((character) => CHARSET.indexOf(character));
  if (symbols.some((symbol) => symbol < 0)) throw errors.invalidCharacter();
  if (polymod([...hrpExpand(hrp), ...symbols]) !== BECH32M_CONST) throw errors.checksum();
  return { hrp, symbols: symbols.slice(0, -CHECKSUM_SYMBOLS) };
}

/** An AddressError as a sentence for a form ("Address checksum does not match: ..."). */
export function addressErrorSentence(error: unknown): string {
  if (!(error instanceof AddressError)) return "The address could not be read.";
  const sentence = `${error.message[0].toUpperCase()}${error.message.slice(1)}`;
  return sentence.endsWith(".") ? sentence : `${sentence}.`;
}

/** Regroups 52 five-bit symbols into 32 bytes; the 4 leftover bits must be 0. */
function keyFromSymbols(symbols: readonly number[]): string | null {
  if (symbols.length !== KEY_SYMBOLS) return null;
  let hex = "";
  let buffer = 0;
  let bits = 0;
  for (const symbol of symbols) {
    buffer = ((buffer << 5) | symbol) & 0xfff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      hex += ((buffer >> bits) & 0xff).toString(16).padStart(2, "0");
    }
  }
  return bits === 4 && (buffer & 0xf) === 0 ? hex : null;
}

function hrpExpand(hrp: string): number[] {
  const codes = [...hrp].map((character) => character.charCodeAt(0));
  return [...codes.map((code) => code >> 5), 0, ...codes.map((code) => code & 31)];
}

function polymod(values: readonly number[]): number {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x01ffffff) << 5) ^ value;
    for (let index = 0; index < 5; index += 1) {
      if ((top >>> index) & 1) checksum ^= GENERATOR[index];
    }
  }
  return checksum >>> 0;
}
