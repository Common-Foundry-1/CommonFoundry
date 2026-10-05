import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { render, screen, within } from "@testing-library/react";
import { expect, it } from "vitest";
import App from "./App";
import { MAINNET_RELEASE_KEY_FINGERPRINT } from "./content";

it("renders the fingerprint derived from the exact approved public release policy", () => {
  const policy = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../public/mainnet-release-key.txt"));
  expect(policy).toHaveLength(144);
  expect(createHash("sha256").update(policy).digest("hex")).toBe("9c5be92681092801d89687823837823d0966055c03a84e64551e26387da179d2");
  const text = policy.toString("utf8");
  expect(text).not.toContain("\r");
  const match = text.match(/^commonfoundry-mainnet-owner namespaces="commonfoundry-release" ssh-ed25519 ([A-Za-z0-9+/]+={0,2})\n$/);
  expect(match).not.toBeNull();
  const keyBlob = Buffer.from(match[1], "base64");
  const fingerprint = `SHA256:${createHash("sha256").update(keyBlob).digest("base64").replace(/=+$/, "")}`;
  expect(fingerprint).toBe(MAINNET_RELEASE_KEY_FINGERPRINT);
  render(<App />);
  const launch = screen.getByRole("region", { name: "Mainnet is live." });
  expect(within(launch).getByText(fingerprint)).toBeVisible();
  expect(within(launch).getByRole("link", { name: "View the public release key" })).toHaveAttribute("href", "/mainnet-release-key.txt");
});
