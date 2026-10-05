import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import App from "./App";
import { DISCORD_URL, EMISSION_URL, EXPLORER_URL, MAINNET_LAUNCH_AT, MAINNET_RELEASE_KEY_FINGERPRINT, MAINNET_RELEASE_KEY_URL, MAINNET_RELEASE_URL, MAINNET_RELEASE_VERSION, MAINNET_SEED_PEER, SOURCE_RELEASE_AT, SECURITY_URL, WALLET_URL, WHITEPAPER_URL } from "./content";

describe("Discord-first launch website", () => {
  it("leads with inference and makes Discord the primary first-screen action", () => {
    render(<App />);
    const hero = screen.getByRole("region", { name: /Inference first.*Built to lead/i });
    const primary = within(hero).getByRole("link", { name: "Join Discord" });
    expect(primary).toHaveAttribute("href", DISCORD_URL);
    expect(primary).toHaveClass("button-link--primary");
    expect(within(hero).getByRole("link", { name: "Mainnet status" })).toHaveAttribute("href", "#launch");
    expect(within(hero).queryByRole("link", { name: /RC5|download/i })).not.toBeInTheDocument();
    expect(within(hero).getByText("Setup help. Mining guidance. Release announcements.")).toBeVisible();
    expect(within(hero).getByText("Mainnet is live")).toBeVisible();
    expect(within(hero).queryByRole("timer")).not.toBeInTheDocument();
    expect(within(screen.getByRole("banner")).getByRole("link", { name: "Join Discord" })).toHaveAttribute("href", DISCORD_URL);
  });

  it("records the launch as completed and points to the live services", () => {
    render(<App />);
    const launch = screen.getByRole("region", { name: "Mainnet is live." });
    expect(within(launch).getByText("October 2, 2026")).toHaveAttribute("datetime", SOURCE_RELEASE_AT);
    expect(within(launch).getByText("October 3, 2026")).toHaveAttribute("datetime", MAINNET_LAUNCH_AT);
    expect(Date.parse(MAINNET_LAUNCH_AT) - Date.parse(SOURCE_RELEASE_AT)).toBe(86_400_000);
    expect(within(launch).getAllByText(/12:00 PM CDT · 17:00 UTC/)).toHaveLength(2);
    expect(within(launch).getByText(/first block was mined at/)).toBeVisible();
    expect(within(launch).queryByText(/not live yet|coming soon|before activation/)).not.toBeInTheDocument();
    expect(within(launch).getByRole("link", { name: "Get the latest mainnet packages" })).toHaveAttribute("href", MAINNET_RELEASE_URL);
    expect(within(launch).getByRole("link", { name: "Open the block explorer" })).toHaveAttribute("href", EXPLORER_URL);
    expect(within(launch).getByRole("link", { name: "Open the web wallet" })).toHaveAttribute("href", WALLET_URL);
    expect(within(launch).getByText(MAINNET_RELEASE_KEY_FINGERPRINT)).toBeVisible();
    expect(within(launch).getByRole("link", { name: "View the public release key" })).toHaveAttribute("href", MAINNET_RELEASE_KEY_URL);
    const node = within(launch).getByRole("complementary", { name: "Bootstrap peer" });
    expect(within(node).getByText(MAINNET_SEED_PEER)).toBeVisible();
    expect(screen.queryByText(/official pool/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/cmfd\+tls:/)).not.toBeInTheDocument();
    expect(document.getElementById("pool-setup")).toBeNull();
  });

  it("uses the same official Discord destination across the conversion flow", () => {
    render(<App />);
    const discordLinks = screen.getAllByRole("link").filter((link) => link.getAttribute("href") === DISCORD_URL);
    expect(discordLinks.length).toBeGreaterThanOrEqual(6);
    for (const link of discordLinks) {
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
      expect(link).toHaveAttribute("rel", expect.stringContaining("noreferrer"));
    }
    expect(screen.getByRole("heading", { name: /Start in Discord.*help from there/i })).toBeVisible();
    expect(screen.getByRole("link", { name: "Mainnet downloads" })).toHaveAttribute("href", MAINNET_RELEASE_URL);
    expect(screen.queryByText(/RCNet test/)).not.toBeInTheDocument();
  });

  it("no longer publishes the mining guide", () => {
    render(<App />);
    expect(screen.queryByText(/mining guide/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /PDF/ })).not.toBeInTheDocument();
    expect(document.getElementById("mining-guide")).toBeNull();
  });

  it("keeps the self-hosted pool setup fix for operators", () => {
    render(<App />);
    const notice = screen.getByRole("complementary", { name: "Running your own pool? Fresh-install setup fix" });
    expect(within(notice).getByRole("link", { name: "Pool setup fix & installation steps" })).toHaveAttribute("href", "https://github.com/Common-Foundry-1/CommonFoundry/blob/366054828601557e7f53becff508db83d6af2a34/packaging/mainnet/linux/POOL-LAUNCHER-UPDATE.md");
    expect(within(notice).getByText(/For pool operators only/)).toBeVisible();
    expect(within(notice).getByText(/does not change the signed mainnet packages/)).toBeVisible();
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
    const gate = screen.getByRole("button", { name: /October 3 · Mainnet live/i });
    fireEvent.click(gate);
    expect(gate).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText(/first block was mined at 17:06 UTC/i)).toBeVisible();
  });

  it("preserves economic disclosures and keeps technical resources accessible", () => {
    render(<App />);
    expect(screen.getByText(/permanent 5 CMFD tail goes only to miners/i)).toBeVisible();
    expect(screen.getByText(/mainnet minimum is 0.1 CMFD/i)).toBeVisible();
    expect(screen.getByText(/25% stewardship and 5% community allocations/i)).toBeVisible();
    expect(screen.getByText(/tail is perpetual, not a hard supply cap/i)).toBeVisible();
    expect(screen.getByText(MAINNET_RELEASE_VERSION)).toBeVisible();
    expect(screen.queryByText(/all usage fees burned/i)).not.toBeInTheDocument();
    expect(WHITEPAPER_URL).toBe("/docs/Common-Foundry-Technical-Whitepaper-v0.4.pdf");
    for (const link of screen.getAllByRole("link", { name: /white paper/i })) {
      expect(link).toHaveAttribute("href", WHITEPAPER_URL);
    }
    expect(screen.getByRole("link", { name: "Security" })).toHaveAttribute("href", SECURITY_URL);
    expect(screen.getByRole("link", { name: /emission rules/i })).toHaveAttribute("href", EMISSION_URL);
  });
});
