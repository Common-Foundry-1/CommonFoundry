import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import { DISCORD_URL, EMISSION_URL, MAINNET_LAUNCH_AT, MAINNET_POOL_URL, MAINNET_RELEASE_KEY_FINGERPRINT, MAINNET_RELEASE_KEY_URL, MAINNET_RELEASE_URL, MAINNET_SEED_PEER, MINING_GUIDE_URL, SOURCE_RELEASE_AT, RELEASE_URL, RELEASE_VERSION, SECURITY_URL, WHITEPAPER_URL } from "./content";

describe("Discord-first launch website", () => {
  it("leads with inference and makes Discord the primary first-screen action", () => {
    render(<App />);
    const hero = screen.getByRole("region", { name: /Inference first.*Built to lead/i });
    const primary = within(hero).getByRole("link", { name: "Join Discord" });
    expect(primary).toHaveAttribute("href", DISCORD_URL);
    expect(primary).toHaveClass("button-link--primary");
    expect(within(hero).getByRole("link", { name: "Launch schedule" })).toHaveAttribute("href", "#launch");
    expect(within(hero).getByRole("link", { name: "Mainnet pool connection details" })).toHaveAttribute("href", "#pool-setup");
    expect(within(hero).queryByRole("link", { name: /RC5|download/i })).not.toBeInTheDocument();
    expect(within(hero).getByText("Setup help. Mining guidance. Launch announcements.")).toBeVisible();
    expect(within(screen.getByRole("banner")).getByRole("link", { name: "Join Discord" })).toHaveAttribute("href", DISCORD_URL);
  });

  it("retains the exact launch schedule without presenting test downloads as mainnet", () => {
    render(<App />);
    const launch = screen.getByRole("region", { name: "Two dates. One shared start." });
    expect(within(launch).getByText("October 2, 2026")).toHaveAttribute("datetime", SOURCE_RELEASE_AT);
    expect(within(launch).getByText("October 3, 2026")).toHaveAttribute("datetime", MAINNET_LAUNCH_AT);
    expect(Date.parse(MAINNET_LAUNCH_AT) - Date.parse(SOURCE_RELEASE_AT)).toBe(86_400_000);
    expect(within(launch).getAllByText(/12:00 PM CDT · 17:00 UTC/)).toHaveLength(2);
    expect(within(launch).getByText(/Mainnet is not live yet/)).toBeVisible();
    expect(within(launch).getByText(/signed mainnet packages are available/)).toBeVisible();
    expect(within(launch).getByRole("link", { name: "Get mainnet v1.0.0 packages" })).toHaveAttribute("href", MAINNET_RELEASE_URL);
    expect(within(launch).getByRole("link", { name: "Get launch-ready in Discord" })).toHaveAttribute("href", DISCORD_URL);
    expect(within(launch).getByText(MAINNET_RELEASE_KEY_FINGERPRINT)).toBeVisible();
    expect(within(launch).getByRole("link", { name: "View the public release key" })).toHaveAttribute("href", MAINNET_RELEASE_KEY_URL);
    const pool = within(launch).getByRole("complementary", { name: "Official pool connection" });
    expect(within(pool).getByText(MAINNET_POOL_URL)).toBeVisible();
    expect(within(pool).getByText(MAINNET_SEED_PEER)).toBeVisible();
    expect(within(pool).getByText(/not accepting connections before activation/)).toBeVisible();
    expect(within(pool).getByText(/dashboard shows RCNet/)).toBeVisible();
  });

  it("uses the same official Discord destination across the conversion flow", () => {
    render(<App />);
    const discordLinks = screen.getAllByRole("link").filter((link) => link.getAttribute("href") === DISCORD_URL);
    expect(discordLinks.length).toBeGreaterThanOrEqual(7);
    for (const link of discordLinks) {
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
      expect(link).toHaveAttribute("rel", expect.stringContaining("noreferrer"));
    }
    expect(screen.getByRole("heading", { name: /Start in Discord.*help from there/i })).toBeVisible();
    expect(screen.getByRole("link", { name: "RCNet test downloads" })).toHaveAttribute("href", RELEASE_URL);
  });

  it("offers the combined beginner guide with current mainnet downloads", () => {
    render(<App />);
    const hero = screen.getByRole("region", { name: /Inference first.*Built to lead/i });
    expect(within(hero).getByRole("link", { name: "Windows + Linux mining guide (PDF)" })).toHaveAttribute("href", MINING_GUIDE_URL);
    const guide = screen.getByRole("article", { name: "Windows & Linux mining guide" });
    expect(guide).toHaveAttribute("id", "mining-guide");
    expect(within(guide).getByText(/terminal-only Linux and rented GPUs/)).toBeVisible();
    expect(within(guide).getByRole("link", { name: "Read mining guide (PDF)" })).toHaveAttribute("href", MINING_GUIDE_URL);
    expect(within(guide).getByRole("link", { name: "Download PDF" })).toHaveAttribute("download");
    expect(within(guide).getByRole("link", { name: "Download PDF" })).toHaveAttribute("href", MINING_GUIDE_URL);
    expect(within(guide).getByText(/released mainnet software now/)).toBeVisible();
    expect(within(guide).getByRole("link", { name: "Ask in Discord." })).toHaveAttribute("href", DISCORD_URL);
  });

  it("opens the shareable guide anchor after the app mounts", () => {
    const original = Element.prototype.scrollIntoView;
    const scroll = vi.fn();
    Element.prototype.scrollIntoView = scroll;
    window.history.replaceState(null, "", "/#mining-guide");
    try {
      render(<App />);
      expect(scroll).toHaveBeenCalledWith({ block: "start" });
    } finally {
      window.history.replaceState(null, "", "/");
      Element.prototype.scrollIntoView = original;
    }
  });

  it("opens the shareable pool setup anchor after the app mounts", () => {
    const original = Element.prototype.scrollIntoView;
    const scroll = vi.fn();
    Element.prototype.scrollIntoView = scroll;
    window.history.replaceState(null, "", "/#pool-setup");
    try {
      render(<App />);
      expect(scroll).toHaveBeenCalledWith({ block: "start" });
    } finally {
      window.history.replaceState(null, "", "/");
      Element.prototype.scrollIntoView = original;
    }
  });

  it("highlights the immutable pool setup fix without changing the mining guide", () => {
    render(<App />);
    const notice = screen.getByRole("complementary", { name: "Running your own pool? Fresh-install setup fix" });
    expect(document.getElementById("mining-guide")).toContainElement(notice);
    expect(within(notice).getByRole("link", { name: "Pool setup fix & installation steps" })).toHaveAttribute("href", "https://github.com/Common-Foundry-1/CommonFoundry/blob/366054828601557e7f53becff508db83d6af2a34/packaging/mainnet/linux/POOL-LAUNCHER-UPDATE.md");
    expect(within(notice).getByText(/For pool operators only/)).toBeVisible();
    expect(within(notice).getByText(/signed v1.0.0 packages and the launch schedule are unchanged/)).toBeVisible();
  });

  it("keeps the inference vision separate from deployed proof-of-work functionality", () => {
    render(<App />);
    const thesis = screen.getByRole("region", { name: "Open compute. Built by people like you." });
    const inference = within(thesis).getByRole("button", { name: /Inference is the direction/i });
    expect(inference).toHaveAttribute("aria-pressed", "true");
    expect(within(thesis).getByText(/remains in development and is not part of the initial mainnet launch/i)).toBeVisible();
    expect(within(thesis).getByText(/sending and receiving do not require a GPU/i)).toBeVisible();
    const foundation = within(thesis).getByRole("button", { name: /A GPU-powered foundation/i });
    fireEvent.click(foundation);
    expect(foundation).toHaveAttribute("aria-pressed", "true");
    expect(inference).toHaveAttribute("aria-pressed", "false");
    expect(screen.queryByText(/independent review.*(progress|ahead)/i)).not.toBeInTheDocument();
  });

  it("opens and closes mobile navigation with a matching Discord call to action", () => {
    render(<App />);
    const toggle = screen.getByRole("button", { name: "Open navigation" });
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const menu = document.getElementById("mobile-menu")!;
    expect(menu).toHaveAttribute("aria-hidden", "false");
    expect(within(menu).getByRole("link", { name: "Join Discord" })).toHaveAttribute("href", DISCORD_URL);
    fireEvent.click(within(menu).getByRole("link", { name: "Economics" }));
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(menu).toHaveAttribute("aria-hidden", "true");
    fireEvent.click(toggle);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(toggle).toHaveFocus();
  });

  it("retains the emission controls and expandable roadmap details", () => {
    render(<App />);
    const emission = screen.getByRole("slider", { name: "Block height" });
    fireEvent.change(emission, { target: { value: "2628001" } });
    expect(screen.getByText(/Block 2,628,001 · 5 CMFD per block/)).toBeVisible();
    const gate = screen.getByRole("button", { name: /October 3 · Mainnet/i });
    fireEvent.click(gate);
    expect(gate).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText(/24 hours after the source-release window/i)).toBeVisible();
  });

  it("preserves economic disclosures and keeps technical resources accessible", () => {
    render(<App />);
    expect(screen.getByText(/permanent 5 CMFD tail goes only to miners/i)).toBeVisible();
    expect(screen.getByText(/planned mainnet minimum is 0.1 CMFD/i)).toBeVisible();
    expect(screen.getByText(/25% stewardship and 5% community allocations/i)).toBeVisible();
    expect(screen.getByText(/tail is perpetual, not a hard supply cap/i)).toBeVisible();
    expect(screen.getByText(RELEASE_VERSION)).toBeVisible();
    expect(screen.queryByText(/all usage fees burned/i)).not.toBeInTheDocument();
    expect(WHITEPAPER_URL).toBe("/docs/Common-Foundry-Technical-Whitepaper-v0.4.pdf");
    for (const link of screen.getAllByRole("link", { name: /white paper/i })) {
      expect(link).toHaveAttribute("href", WHITEPAPER_URL);
    }
    expect(screen.getByRole("link", { name: "Security" })).toHaveAttribute("href", SECURITY_URL);
    expect(screen.getByRole("link", { name: /emission rules/i })).toHaveAttribute("href", EMISSION_URL);
  });
});
