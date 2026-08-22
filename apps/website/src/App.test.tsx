import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import App from "./App";
import { DISCORD_URL, EMISSION_URL, SECURITY_URL, WHITEPAPER_URL } from "./content";

describe("investor website", () => {
  it("uses the corrected Discord invite safely for every Devnet CTA", () => {
    render(<App />);

    const devnetLinks = screen.getAllByRole("link", { name: /join the devnet/i });
    expect(devnetLinks.length).toBeGreaterThan(2);
    for (const link of devnetLinks) {
      expect(link).toHaveAttribute("href", DISCORD_URL);
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
    }
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
      name: /Freeze the specification and canonical vectors/i,
    });
    gate.focus();
    fireEvent.click(gate);
    expect(gate).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText(/Pin every field, arithmetic rule/i)).toBeVisible();
  });

  it("discloses gated work and links bundled source documents", () => {
    render(<App />);

    expect(screen.getByText("External security review")).toBeVisible();
    expect(screen.getByText(/founder-controlled pre-tail allocation/i)).toBeVisible();
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
