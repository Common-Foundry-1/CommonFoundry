import { describe, expect, it } from "vitest";
import { emissionAtHeight } from "./economics";

describe("emissionAtHeight", () => {
  it.each([
    [1, 50_000_000_000n],
    [2, 49_999_980_974n],
    [1_314_000, 25_000_019_025n],
    [2_628_000, 19_025n],
    [2_628_001, 500_000_000n],
  ])("returns the consensus subsidy at block %i", (height, expected) => {
    expect(emissionAtHeight(height)).toBe(expected);
  });

  it("rejects a negative height", () => {
    expect(() => emissionAtHeight(-1)).toThrow(RangeError);
  });
});
