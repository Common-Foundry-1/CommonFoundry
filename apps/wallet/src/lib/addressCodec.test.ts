// @vitest-environment node
// Identical in every app that carries addressCodec.ts; see that file.
import { describe, expect, it } from "vitest";
import {
  AddressError,
  MAINNET_HRP,
  TEST_NETWORK_HRP,
  addressErrorSentence,
  decode,
  encode,
  hrpForNetwork,
  joinChecked,
  splitChecked,
} from "./addressCodec";

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
// x of the generator point G (secret key 1), as in the Rust codec's tests.
const G = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/** Deterministic 32-byte keys. The TS codec does not check curve points. */
function keys(count: number): string[] {
  let state = 0x9e3779b9;
  return Array.from({ length: count }, () => Array.from({ length: 32 }, () => {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    return ((state >>> 0) & 0xff).toString(16).padStart(2, "0");
  }).join(""));
}

function errorKind(hrp: string, text: string): string | null {
  try {
    decode(hrp, text);
    return null;
  } catch (error) {
    if (error instanceof AddressError) return error.kind;
    throw error;
  }
}

describe("address codec", () => {
  it("encodes the known key to the fixed addresses in the Rust tests", () => {
    expect(encode(MAINNET_HRP, G)).toBe("cmfd10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq4yhywr");
    expect(encode(TEST_NETWORK_HRP, G)).toBe("tcmfd10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq236tfw");
    expect(decode(MAINNET_HRP, "cmfd10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq4yhywr")).toEqual({ hex: G, format: "bech32m" });
  });

  it("accepts the BIP-350 valid vectors", () => {
    for (const text of [
      "A1LQFN3A",
      "a1lqfn3a",
      "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
      "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
      "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
      "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
      "?1v759aa",
    ]) {
      expect(() => splitChecked(text), text).not.toThrow();
    }
  });

  it("refuses the BIP-350 invalid vectors", () => {
    for (const text of [
      " " + "1xj0phk",
      "\u007f" + "1g6xzxy",
      "\u0080" + "1vctc34",
      "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
      "qyrz8wqd2c9m",
      "1qyrz8wqd2c9m",
      "y1b0jsk6g",
      "lt1igcx5c0",
      "in1muywd",
      "mm1crxm3i",
      "au1s5cgom",
      "M1VUXWEZ",
      "16plkw9",
      "1p2gdwpf",
    ]) {
      expect(() => splitChecked(text), JSON.stringify(text)).toThrow(AddressError);
    }
  });

  it("round-trips keys through both forms on both networks", () => {
    for (const key of [G, "00".repeat(32), "ff".repeat(32), ...keys(64)]) {
      const text = encode(MAINNET_HRP, key);
      expect(text).toHaveLength(63);
      expect(text.startsWith("cmfd1")).toBe(true);
      expect(decode(MAINNET_HRP, text)).toEqual({ hex: key, format: "bech32m" });
      expect(decode(MAINNET_HRP, key)).toEqual({ hex: key, format: "hex" });
      const test = encode(TEST_NETWORK_HRP, key);
      expect(test).toHaveLength(64);
      expect(decode(TEST_NETWORK_HRP, test)).toEqual({ hex: key, format: "bech32m" });
    }
  });

  it("detects every single-character substitution", () => {
    for (const key of [G, ...keys(3)]) {
      const text = encode(MAINNET_HRP, key);
      for (let position = 0; position < text.length; position += 1) {
        for (const replacement of CHARSET + "cmfdbio") {
          if (text[position] === replacement) continue;
          const typo = text.slice(0, position) + replacement + text.slice(position + 1);
          expect(errorKind(MAINNET_HRP, typo), typo).not.toBeNull();
        }
      }
    }
  });

  it("detects every adjacent transposition", () => {
    for (const key of [G, ...keys(8)]) {
      const text = encode(MAINNET_HRP, key);
      for (let position = 0; position < text.length - 1; position += 1) {
        if (text[position] === text[position + 1]) continue;
        const swapped = text.slice(0, position) + text[position + 1] + text[position] + text.slice(position + 2);
        expect(errorKind(MAINNET_HRP, swapped), swapped).not.toBeNull();
      }
    }
  });

  it("detects dropped and added characters", () => {
    const text = encode(MAINNET_HRP, keys(1)[0]);
    for (let position = 0; position < text.length; position += 1) {
      const shorter = text.slice(0, position) + text.slice(position + 1);
      expect(errorKind(MAINNET_HRP, shorter), shorter).not.toBeNull();
      for (const extra of CHARSET) {
        const longer = text.slice(0, position) + extra + text.slice(position);
        expect(errorKind(MAINNET_HRP, longer), longer).not.toBeNull();
      }
    }
  });

  it("refuses another network's address but reports a prefix typo as a checksum error", () => {
    expect(() => decode(MAINNET_HRP, encode(TEST_NETWORK_HRP, G)))
      .toThrow("address is for another network: expected cmfd1..., found tcmfd1...");
    expect(errorKind(TEST_NETWORK_HRP, encode(MAINNET_HRP, G))).toBe("wrong_network");
    expect(errorKind(MAINNET_HRP, encode("bc", G))).toBe("wrong_network");
    expect(errorKind(MAINNET_HRP, encode(MAINNET_HRP, G).replace("cmfd", "cmfe"))).toBe("checksum");
    expect(hrpForNetwork("Mainnet")).toBe(MAINNET_HRP);
    expect(hrpForNetwork("mainnet")).toBe(MAINNET_HRP);
    expect(hrpForNetwork("RCNet-1")).toBe(TEST_NETWORK_HRP);
    expect(hrpForNetwork("Devnet-0")).toBe(TEST_NETWORK_HRP);
  });

  it("follows the BIP-173 case rules and keeps hex lowercase-only", () => {
    const lower = encode(MAINNET_HRP, G);
    expect(decode(MAINNET_HRP, lower.toUpperCase())).toEqual({ hex: G, format: "bech32m" });
    const letter = lower.search(/[a-z][^a-z]*$/);
    const mixed = lower.slice(0, letter) + lower[letter].toUpperCase() + lower.slice(letter + 1);
    expect(() => decode(MAINNET_HRP, mixed)).toThrow("address mixes upper and lower case");
    expect(() => decode(MAINNET_HRP, G.toUpperCase())).toThrow("hex addresses must be lowercase");
    expect(errorKind(MAINNET_HRP, G.slice(0, 63) + "A")).toBe("uppercase_hex");
  });

  it("refuses malformed payloads and junk", () => {
    const { hrp, symbols } = splitChecked(encode(MAINNET_HRP, G));
    expect(splitChecked(joinChecked(hrp, symbols))).toEqual({ hrp, symbols });
    const padded = [...symbols];
    padded[padded.length - 1] |= 1;
    expect(() => decode(MAINNET_HRP, joinChecked(hrp, padded))).toThrow("address does not hold a 32-byte key");
    for (const length of [50, 51, 53, 54]) {
      expect(errorKind(MAINNET_HRP, joinChecked(hrp, new Array<number>(length).fill(0)))).toBe("bad_payload");
    }
    for (const junk of ["", "cmfd", "cmfd1", G.slice(0, 63), G + "0", "not an address", ` ${G}`]) {
      expect(errorKind(MAINNET_HRP, junk), JSON.stringify(junk)).not.toBeNull();
    }
    expect(() => decode(MAINNET_HRP, "")).toThrow(
      "expected a cmfd1... address or 64 lowercase hexadecimal characters encoding an x-only public key",
    );
    expect(errorKind(MAINNET_HRP, "cmfd1" + "q".repeat(90))).toBe("wrong_length");
    expect(errorKind(MAINNET_HRP, encode(MAINNET_HRP, G).replace("q", "b"))).toBe("invalid_character");
  });

  it("phrases errors as sentences for forms", () => {
    expect(addressErrorSentence(new AddressError("checksum", "address checksum does not match: the address is mistyped or incomplete")))
      .toBe("Address checksum does not match: the address is mistyped or incomplete.");
    expect(addressErrorSentence(new AddressError("wrong_network", "address is for another network: expected cmfd1..., found tcmfd1...")))
      .toBe("Address is for another network: expected cmfd1..., found tcmfd1...");
    expect(addressErrorSentence(new Error("other"))).toBe("The address could not be read.");
  });

  it("is identical in every app that carries it", () => {
    // node:fs without adding @types/node to the app's type program.
    const { readFileSync } = (globalThis as unknown as {
      process: { getBuiltinModule(id: "node:fs"): { readFileSync(path: URL, encoding: "utf8"): string } };
    }).process.getBuiltinModule("node:fs");
    const here = import.meta.url; // a variable, so Vite does not rewrite new URL() as an asset import
    for (const name of ["addressCodec.ts", "addressCodec.test.ts"]) {
      const copies = ["wallet", "explorer", "pool-dashboard"]
        .map((app) => readFileSync(new URL(`../../../${app}/src/lib/${name}`, here), "utf8"));
      expect(new Set(copies).size, `apps/*/src/lib/${name} differ`).toBe(1);
    }
  });
});
