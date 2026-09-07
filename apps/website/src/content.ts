export const DISCORD_URL = "https://discord.gg/XGuutqWMWP";
export const GITHUB_URL = "https://github.com/Common-Foundry-1";
export const X_URL = "https://x.com/CommonFoundry1";
export const RELEASE_VERSION = "v0.1.0-rc.5";
export const RELEASE_URL = `https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/tag/${RELEASE_VERSION}`;
export const WHITEPAPER_URL = "/docs/Common-Foundry-Technical-Whitepaper-v0.3.pdf";
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
  { label: "384-layer proof with CPU verification", icon: "ledger" },
  { label: "RTX 5090 and 5070 Ti 16 GB proof paths", icon: "network" },
  { label: "Wallet-integrated GPU solo mining", icon: "wallet" },
  { label: "Native encrypted backup and restore", icon: "lock" },
  { label: "Signed release manifests and runtime setup", icon: "channel" },
];

export const nextItems: readonly ProgressItem[] = [
  { label: "Faster 16 GB proving", icon: "lock" },
  { label: "Broader GPU and driver qualification", icon: "lock" },
  { label: "Expanded public testnet participation", icon: "lock" },
  { label: "Independent implementations and review", icon: "lock" },
  { label: "Mainnet readiness and operator adoption", icon: "lock" },
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
    title: "RC5 wallet and mining release",
    detail:
      "RC5 ships Windows and Linux runtime setup, wallet-integrated solo mining, native backup dialogs and a network-enforced 0.1 CMFD minimum fee burn. Initial mining packages target NVIDIA RTX 50-series; platform prerequisites are in the release guide.",
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
    title: "Mainnet diligence and ecosystem growth",
    detail:
      "Build on reproducible releases with independent cryptographic review, broader operator testing and exchange-integration diligence. Mainnet and any exchange availability remain future milestones, not announced launches.",
    phase: "future",
  },
];
