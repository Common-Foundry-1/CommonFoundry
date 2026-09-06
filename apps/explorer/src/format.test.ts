import { afterEach, expect, test, vi } from "vitest";
import { formatAge } from "./format";

const now = Date.UTC(2026, 8, 6, 20);
afterEach(() => vi.restoreAllMocks());

test.each([
  [0, "0s ago"], [59, "59s ago"], [60, "1m ago"],
  [3599, "59m ago"], [3600, "1h ago"], [86400, "1d ago"],
  [-30, "in 30s"], [-60, "in 1m"], [-75606, "in 21h"], [-86400, "in 1d"],
])("formats a signed block-time difference of %i seconds", (difference, expected) => {
  vi.spyOn(Date, "now").mockReturnValue(now);
  expect(formatAge(now / 1000 - difference)).toBe(expected);
});
