import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MainnetLive } from "./MainnetLive";
import { EXPLORER_URL, MAINNET_FIRST_BLOCK_AT, MAINNET_LAUNCH_AT, WALLET_URL } from "../content";

describe("mainnet live banner", () => {
  it("states the real launch and first-block times and links the live services", () => {
    render(<MainnetLive />);
    expect(screen.getByText("October 3, 2026")).toHaveAttribute("dateTime", MAINNET_LAUNCH_AT);
    expect(screen.getByText("17:06 UTC")).toHaveAttribute("dateTime", MAINNET_FIRST_BLOCK_AT);
    expect(screen.getByRole("link", { name: "Block explorer" })).toHaveAttribute("href", EXPLORER_URL);
    expect(screen.getByRole("link", { name: "Web wallet" })).toHaveAttribute("href", WALLET_URL);
    expect(screen.queryByRole("timer")).not.toBeInTheDocument();
  });
});
