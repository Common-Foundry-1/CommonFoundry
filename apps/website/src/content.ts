export const DISCORD_URL = "https://discord.gg/XGuutqWMWP";
export const GITHUB_URL = "https://github.com/Common-Foundry-1";
export const X_URL = "https://x.com/CommonFoundry1";
export const WHITEPAPER_URL = "/docs/Common-Foundry-Technical-Whitepaper-v0.1.pdf";
export const SECURITY_URL = "/docs/SECURITY.md";
export const EMISSION_URL = "/docs/emission.md";

export type SectionId =
  | "thesis"
  | "technology"
  | "progress"
  | "economics"
  | "roadmap";

export interface NavItem {
  id: SectionId;
  label: string;
}

export const navItems: readonly NavItem[] = [
  { id: "thesis", label: "Thesis" },
  { id: "technology", label: "Technology" },
  { id: "progress", label: "Progress" },
  { id: "economics", label: "Economics" },
  { id: "roadmap", label: "Roadmap" },
];

export type ProgressIcon =
  | "ledger"
  | "network"
  | "wallet"
  | "burn"
  | "channel"
  | "lock";

export interface ProgressItem {
  label: string;
  icon: ProgressIcon;
}

export const implementedItems: readonly ProgressItem[] = [
  { label: "Canonical UTXO ledger", icon: "ledger" },
  { label: "Multi-node synchronization", icon: "network" },
  { label: "Wallet with solo and pool mining", icon: "wallet" },
  { label: "Fee burning and emission rules", icon: "burn" },
  { label: "Inference-channel settlement", icon: "channel" },
];

export const gatedItems: readonly ProgressItem[] = [
  { label: "Succinct production proof", icon: "lock" },
  { label: "6 GiB model ceremony", icon: "lock" },
  { label: "Public networking and DoS hardening", icon: "lock" },
  { label: "Independent implementations", icon: "lock" },
  { label: "External security review", icon: "lock" },
];

export interface RoadmapGate {
  number: string;
  title: string;
  detail: string;
  phase: "active" | "future";
}

export const roadmapGates: readonly RoadmapGate[] = [
  {
    number: "01",
    title: "Freeze the specification and canonical vectors",
    detail:
      "Pin every field, arithmetic rule, transcript message, and rejection case before production activation.",
    phase: "active",
  },
  {
    number: "02",
    title: "Build the transparent proof and model ceremony",
    detail:
      "Bind the published model bytes, all matrix layers, ranges, challenge, nonce, target, and final digest.",
    phase: "active",
  },
  {
    number: "03",
    title: "Benchmark hardware and reproduce independent implementations",
    detail:
      "Publish reproducible memory, proving, verification, power, and cross-implementation evidence.",
    phase: "future",
  },
  {
    number: "04",
    title:
      "Run an adversarial public testnet and harden wallet, pool, and networking",
    detail:
      "Exercise forks, restarts, custody, discovery, denial-of-service resistance, and mixed hardware under public load.",
    phase: "future",
  },
  {
    number: "05",
    title: "Complete independent review and transparent governance",
    detail:
      "Document control, custody, reporting, conflicts, and the evidence required before any public-value activation.",
    phase: "future",
  },
];
