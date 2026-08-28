export const DISCORD_URL = "https://discord.gg/XGuutqWMWP";
export const GITHUB_URL = "https://github.com/Common-Foundry-1";
export const X_URL = "https://x.com/CommonFoundry1";
export const WHITEPAPER_URL = "/docs/Common-Foundry-Technical-Whitepaper-v0.2.pdf";
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
  { label: "Full 384-layer ForgeMatrix profile", icon: "ledger" },
  { label: "Transparent ProductionV4 proof", icon: "network" },
  { label: "6.093-second RTX 5090 online proof", icon: "wallet" },
  { label: "Verified RTX 5070 Ti 16 GB path", icon: "burn" },
  { label: "Windows and Linux tester packages", icon: "channel" },
];

export const nextItems: readonly ProgressItem[] = [
  { label: "Faster 16 GB proving", icon: "lock" },
  { label: "Broader GPU and driver qualification", icon: "lock" },
  { label: "Expanded public testnet participation", icon: "lock" },
  { label: "Independent implementations and review", icon: "lock" },
  { label: "Wallet, pool, and distribution polish", icon: "lock" },
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
    title: "Full-shape ProductionV4 proof",
    detail:
      "The 384-layer ForgeMatrix proof is measured, CPU-verified, accepted through normal P2P admission, and persisted by another node.",
    phase: "active",
  },
  {
    number: "02",
    title: "Consumer-GPU testnet packages",
    detail:
      "Windows and Linux node, wallet, and miner packages support the qualified RTX 5090 and physical RTX 5070 Ti 16 GB paths.",
    phase: "active",
  },
  {
    number: "03",
    title: "Optimize the 16 GB proving path",
    detail:
      "Improve complete proof latency while measuring memory, power, and efficiency across consumer GPU tiers.",
    phase: "future",
  },
  {
    number: "04",
    title: "Scale the public testnet",
    detail:
      "Add more peers and mixed hardware while exercising propagation, forks, restarts, wallet flows, and pool operation.",
    phase: "future",
  },
  {
    number: "05",
    title: "Independent review and release hardening",
    detail:
      "Expand canonical vectors, independent implementations, cryptographic review, and reproducible signed releases.",
    phase: "future",
  },
];
