import { describe, expect, it } from "vitest";
import { isExplorerApiPath } from "./index";

describe("explorer edge API allowlist", () => {
  it("allows only the bounded read-only explorer routes", () => {
    expect(isExplorerApiPath("/v1/explorer")).toBe(true);
    expect(isExplorerApiPath("/v1/explorer/block/42")).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/block/${"ab".repeat(32)}`)).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/transaction/${"01".repeat(32)}`)).toBe(true);
  });

  it("does not expose general node RPC routes", () => {
    expect(isExplorerApiPath("/v1/status")).toBe(false);
    expect(isExplorerApiPath("/v1/explorer/block/latest/extra")).toBe(false);
    expect(isExplorerApiPath("/v1/explorer/transaction/not-a-transaction")).toBe(false);
  });
});
