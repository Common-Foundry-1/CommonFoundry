import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MainnetCountdown } from "./MainnetCountdown";
import { DISCORD_URL, MAINNET_LAUNCH_AT } from "../content";

afterEach(() => vi.useRealTimers());

describe("mainnet countdown", () => {
  it("counts down to the exact scheduled start and then points to verified status", () => {
    vi.useFakeTimers();
    vi.setSystemTime(Date.parse(MAINNET_LAUNCH_AT) - 2_000);
    render(<MainnetCountdown />);

    expect(screen.getByRole("timer")).toHaveAttribute("aria-label", "0 days, 0 hours, 0 minutes, 2 seconds remaining");
    expect(screen.getByText(/October 3, 2026 · Noon CDT \/ 17:00 UTC/)).toHaveAttribute("dateTime", MAINNET_LAUNCH_AT);

    act(() => vi.advanceTimersByTime(2_000));

    expect(screen.queryByRole("timer")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Scheduled start time reached.");
    expect(screen.getByRole("link", { name: /official launch status in Discord/i })).toHaveAttribute("href", DISCORD_URL);
    expect(screen.queryByText(/mainnet is live/i)).not.toBeInTheDocument();
  });
});
