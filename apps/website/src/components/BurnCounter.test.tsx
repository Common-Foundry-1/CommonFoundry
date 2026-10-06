import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BurnCounter, burnedUsd } from "./BurnCounter";
import { CMFD_USD_PRICE, SUPPLY_API_URL } from "../content";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fee burn counter", () => {
  it("shows the CMFD burned and its dollar value from the explorer supply API", async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json({ height: 5081, burned_fees_atoms: "175990000000" }));
    vi.stubGlobal("fetch", fetch);
    render(<BurnCounter />);
    expect(await screen.findByText("1,759.9")).toBeVisible();
    expect(screen.getByText("$75.68")).toBeVisible();
    expect(screen.getByText(/Valued at \$0\.043 per CMFD · block 5,081/)).toBeVisible();
    expect(String(fetch.mock.calls[0][0])).toBe(SUPPLY_API_URL);
  });

  it("keeps placeholders when the explorer does not report a burn", async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json({ height: 5081, burned_fees_atoms: null }));
    vi.stubGlobal("fetch", fetch);
    render(<BurnCounter />);
    await vi.waitFor(() => expect(fetch).toHaveBeenCalled());
    expect(screen.getAllByText("—")).toHaveLength(2);
  });

  it("values the burn at the configured price", () => {
    expect(CMFD_USD_PRICE).toBe(0.043);
    expect(burnedUsd(0n)).toBe("$0.00");
    expect(burnedUsd(100_000_000_000_000n)).toBe("$43,000.00");
  });
});
