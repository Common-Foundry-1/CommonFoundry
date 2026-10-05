export const DISCORD_URL = "https://discord.gg/XGuutqWMWP";
export const GITHUB_URL = "https://github.com/Common-Foundry-1";
export const WALLET_URL = "https://wallet.commonfoundry.ai";
export const X_URL = "https://x.com/CommonFoundry1";
export const EXPLORER_URL = "https://explorer.commonfoundry.ai";
export const WHITEPAPER_URL = "/docs/Common-Foundry-Technical-Whitepaper-v0.4.pdf";
export const MINING_GUIDE_URL = "/docs/Common-Foundry-Mainnet-Mining-Guide-Windows-Linux.pdf";
export const SECURITY_URL = "/docs/SECURITY.md";
export const EMISSION_URL = "/docs/emission.md";
export const MAINNET_LAUNCH_AT = "2026-10-03T17:00:00Z";
export const MAINNET_FIRST_BLOCK_AT = "2026-10-03T17:06:17Z";
export const SOURCE_RELEASE_AT = "2026-10-02T17:00:00Z";
export const MAINNET_RELEASE_VERSION = "v1.0.8";
export const MAINNET_RELEASE_KEY_URL = "/mainnet-release-key.txt";
export const MAINNET_RELEASE_KEY_FINGERPRINT = "SHA256:cA1Tsf8hL/pxDV5WpOE3iPW3b4uDQosu1dOh//4a/fk";
export const MAINNET_RELEASE_URL = "https://github.com/Common-Foundry-1/CommonFoundry/releases/latest";
export const MAINNET_SEED_PEER = "173.249.35.251:29444";

export type SectionId =
  | "launch"
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
  { id: "launch", label: "Mainnet" },
  { id: "thesis", label: "Why Common Foundry" },
  { id: "progress", label: "What's ready" },
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
  { label: "Mainnet live since October 3, 2026", icon: "network" },
  { label: "Windows and Linux wallets and nodes", icon: "wallet" },
  { label: "Web wallet at wallet.commonfoundry.ai", icon: "wallet" },
  { label: "Solo and pool mining on mainnet", icon: "network" },
  { label: "GPU proofs checked by CPU nodes", icon: "ledger" },
  { label: "Encrypted wallet backup and restore", icon: "lock" },
  { label: "Public block explorer", icon: "ledger" },
];

export const nextItems: readonly ProgressItem[] = [
  { label: "Exchange integrations", icon: "channel" },
  { label: "Broader GPU and operator participation", icon: "ledger" },
  { label: "Customer-paid inference development", icon: "channel" },
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
    title: "A working foundation",
    detail:
      "Mainnet brings together GPU proof of work, wallets, transfers and node synchronization. Its production-sized ForgeMatrix proofs are checked by CPU nodes.",
    phase: "active",
  },
  {
    number: "02",
    title: "Get ready with the community",
    detail:
      "Join Discord for setup help, supported-hardware guidance and current mainnet releases. You do not need a mining rig or a finished setup to join the conversation.",
    phase: "active",
  },
  {
    number: "03",
    title: "October 2 · Source release",
    detail:
      "Public source and matching launch packages were released October 2, 2026 at noon CDT / 17:00 UTC, with release notes and checksums.",
    phase: "active",
  },
  {
    number: "04",
    title: "October 3 · Mainnet live",
    detail:
      "Mainnet mining began on schedule October 3, 2026 at noon CDT / 17:00 UTC; the first block was mined at 17:06 UTC. The chain, the public explorer and the web wallet are running. Follow Discord for releases and operational updates.",
    phase: "active",
  },
  {
    number: "05",
    title: "Build toward open inference",
    detail:
      "Customer-paid AI inference is a separate service layer in development, not a feature promised for the initial mainnet launch. We want GPU operators and developers involved in shaping it.",
    phase: "future",
  },
];
