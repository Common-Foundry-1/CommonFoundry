import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import App from "./App";
import { DISCORD_URL, EMISSION_URL, MAINNET_LAUNCH_AT, SOURCE_RELEASE_AT, RELEASE_URL, RELEASE_VERSION, SECURITY_URL, WHITEPAPER_URL } from "./content";

describe("investor website", () => {
  it("announces the mainnet target and a 24-hour preparation window without presenting RC downloads as mainnet", () => {
    render(<App />);
    const launch = screen.getByRole("region", { name: "Two dates. One shared start." });
    expect(within(launch).getByText("October 2, 2026")).toHaveAttribute("datetime", SOURCE_RELEASE_AT);
    expect(within(launch).getByText("October 3, 2026")).toHaveAttribute("datetime", MAINNET_LAUNCH_AT);
    expect(Date.parse(MAINNET_LAUNCH_AT) - Date.parse(SOURCE_RELEASE_AT)).toBe(86_400_000);
    expect(within(launch).getAllByText(/12:00 PM CDT · 17:00 UTC/)).toHaveLength(2);
    expect(within(launch).getByText(/Mainnet is not live yet; current RC5 downloads connect to RCNet/)).toBeVisible();
    expect(screen.getByRole("link", { name: "See the launch plan" })).toHaveAttribute("href", "#launch");
    expect(screen.queryByRole("link", { name: /download mainnet/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/not announced launches/i)).not.toBeInTheDocument();
  });

  it("links RC5 downloads and the community through their correct destinations", () => {
    render(<App />);

    const releaseLinks = screen.getAllByRole("link", { name: /RC5|release notes and setup/i });
    expect(releaseLinks.length).toBeGreaterThan(2);
    for (const link of releaseLinks) {
      expect(link).toHaveAttribute("href", RELEASE_URL);
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
    }
    expect(screen.getByRole("link", { name: /join the community/i })).toHaveAttribute("href", DISCORD_URL);
  });

  it("opens and closes the accessible mobile navigation", () => {
    render(<App />);

    const toggle = screen.getByRole("button", { name: "Open navigation" });
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const mobileNavigation = screen.getByRole("navigation", { name: "Mobile navigation" });
    expect(mobileNavigation).toBeVisible();

    fireEvent.click(within(mobileNavigation).getByRole("link", { name: /economics/i }));
    expect(screen.getByRole("button", { name: "Open navigation" })).toHaveAttribute(
      "aria-expanded",
      "false",
    );
  });

  it("supports keyboard-oriented native emission controls and expandable gates", () => {
    render(<App />);

    const emission = screen.getByRole("slider", { name: "Block height" });
    emission.focus();
    fireEvent.keyDown(emission, { key: "ArrowRight" });
    fireEvent.change(emission, { target: { value: "2628001" } });
    expect(screen.getByText(/Block 2,628,001 · 5 CMFD per block/)).toBeVisible();

    const gate = screen.getByRole("button", {
      name: /Full-shape ProductionV4 proof/i,
    });
    gate.focus();
    fireEvent.click(gate);
    expect(gate).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText(/384-layer ForgeMatrix proof is measured/i)).toBeVisible();
  });

  it("presents ProductionV4 milestones and links bundled source documents", () => {
    render(<App />);

    expect(screen.getByText("Independent implementations and review")).toBeVisible();
    expect(screen.getByText(/permanent 5 CMFD tail goes only to miners/i)).toBeVisible();
    expect(screen.getByText(RELEASE_VERSION)).toBeVisible();
    expect(screen.queryByText(/devnet[.-]16/i)).not.toBeInTheDocument();
    expect(screen.getByText(/RC5 enforces a 0.1 CMFD minimum/i)).toBeVisible();
    expect(screen.getByText(/lasting value depends on adoption and execution/i)).toBeVisible();
    expect(screen.getByText(/RCNet is a test network, not mainnet/i)).toBeVisible();
    const rejectedAuditCount = ["two", "external", "audits"].join(" ");
    expect(screen.queryByText(new RegExp(rejectedAuditCount, "i"))).not.toBeInTheDocument();

    expect(screen.getAllByRole("link", { name: /white paper/i })[0]).toHaveAttribute(
      "href",
      WHITEPAPER_URL,
    );
    expect(screen.getByRole("link", { name: /security/i })).toHaveAttribute(
      "href",
      SECURITY_URL,
    );
    expect(screen.getByRole("link", { name: /emission rules/i })).toHaveAttribute(
      "href",
      EMISSION_URL,
    );
  });
});
