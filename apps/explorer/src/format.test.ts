import { expect, test } from "vitest";
import { blockWork, formatBlockWork, formatNetworkWorkRate } from "./format";

test("block work matches consensus target math", () => {
  expect(blockWork("f".repeat(64))).toBe(1n);
  expect(blockWork(`7${"f".repeat(63)}`)).toBe(2n);
  expect(blockWork(`${"0".repeat(63)}1`)).toBe(1n << 255n);
});

test("network work rate is block work over the 60-second spacing", () => {
  const mainnetTarget = "0000140632f60b2b0e1f7f3bde7071b38dc1baaca37a94d90755d6507557e25c";
  expect(blockWork(mainnetTarget)).toBe(837_846n);
  expect(formatBlockWork(mainnetTarget)).toBe("838K FW per block");
  expect(formatNetworkWorkRate(mainnetTarget)).toBe("14K FW/s");
  expect(formatNetworkWorkRate(`000${"f".repeat(61)}`)).toBe("68.3 FW/s");
});
