import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BurnCounter, burnedUsd } from "./BurnCounter";
import { PRICE_API_URL, SUPPLY_API_URL } from "../content";

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Answers the explorer's supply and price endpoints. */
function explorer(supply: Response, price: Response) {
  return vi.fn().mockImplementation(async (url: string) => (url === SUPPLY_API_URL ? supply : price));
}

describe("fee burn counter", () => {
  it("values the CMFD burned at the last TidoEx trade", async () => {
    const fetch = explorer(
      Response.json({ height: 5081, burned_fees_atoms: "175990000000" }),
      Response.json({ market: "CMFD_USDT", exchange: "TidoEx", last_price: "0.0105", quote_currency: "USDT" }),
    );
    vi.stubGlobal("fetch", fetch);
    render(<BurnCounter />);
    expect(await screen.findByText("1,759.9")).toBeVisible();
    expect(await screen.findByText("$18.48")).toBeVisible();
    expect(screen.getByText(/Valued at \$0\.0105 per CMFD, the last CMFD\/USDT trade on TidoEx\. As of block 5,081\./)).toBeVisible();
    expect(fetch.mock.calls.map(([url]) => String(url))).toEqual([SUPPLY_API_URL, PRICE_API_URL]);
  });

  it("shows the burn without a dollar value when there is no market price", async () => {
    vi.stubGlobal("fetch", explorer(
      Response.json({ height: 5081, burned_fees_atoms: "175990000000" }),
      Response.json({ error: "price_unavailable" }, { status: 503 }),
    ));
    render(<BurnCounter />);
    expect(await screen.findByText("1,759.9")).toBeVisible();
    expect(screen.getByText("—")).toBeVisible();
    expect(screen.getByText(/not paid to miners\. As of block 5,081\./)).toBeVisible();
    expect(screen.queryByText(/Valued at/)).toBeNull();
  });

  it("keeps placeholders when the explorer does not report a burn", async () => {
    const fetch = explorer(
      Response.json({ height: 5081, burned_fees_atoms: null }),
      Response.json({ last_price: "-1" }),
    );
    vi.stubGlobal("fetch", fetch);
    render(<BurnCounter />);
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
    expect(screen.getAllByText("—")).toHaveLength(2);
  });

  it("values the burn at the given price", () => {
    expect(burnedUsd(0n, 0.0105)).toBe("$0.00");
    expect(burnedUsd(100_000_000_000_000n, 0.01)).toBe("$10,000.00");
  });
});
