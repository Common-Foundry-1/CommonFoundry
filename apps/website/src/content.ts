export const DISCORD_URL = "https://discord.gg/XGuutqWMWP";
export const GITHUB_URL = "https://github.com/Common-Foundry-1";
export const X_URL = "https://x.com/CommonFoundry1";
export const RELEASE_VERSION = "v0.1.0-rc.5";
export const RELEASE_URL = `https://github.com/JustAResearcher/CommonFoundry-Binaries/releases/tag/${RELEASE_VERSION}`;
export const WHITEPAPER_URL = "/docs/Common-Foundry-Technical-Whitepaper-v0.4.pdf";
export const MINING_GUIDE_URL = "/docs/Common-Foundry-Mainnet-Mining-Guide-Windows-Linux.pdf";
export const SECURITY_URL = "/docs/SECURITY.md";
export const EMISSION_URL = "/docs/emission.md";
export const MAINNET_LAUNCH_AT = "2026-10-03T17:00:00Z";
export const SOURCE_RELEASE_AT = "2026-10-02T17:00:00Z";
export const MAINNET_RELEASE_KEY_URL = "/mainnet-release-key.txt";
export const MAINNET_RELEASE_KEY_FINGERPRINT = "SHA256:cA1Tsf8hL/pxDV5WpOE3iPW3b4uDQosu1dOh//4a/fk";
export const MAINNET_RELEASE_URL = "https://github.com/Common-Foundry-1/CommonFoundry/releases/tag/v1.0.0";
export const MAINNET_POOL_URL = "cmfd+tls://107.214.187.2:29445?pin=0a896a857857354781f06fe5b9ca05e632a35eab915b9cfd68545905bd1300d2";
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
  { id: "launch", label: "Launch" },
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
  { label: "Windows and Linux wallets and nodes", icon: "wallet" },
  { label: "Solo and pool mining workflows", icon: "network" },
  { label: "GPU proofs checked by CPU nodes", icon: "ledger" },
  { label: "Encrypted wallet backup and restore", icon: "lock" },
  { label: "Sending, receiving and syncing on RCNet", icon: "channel" },
];

export const nextItems: readonly ProgressItem[] = [
  { label: "Launch-time network and pool checks", icon: "lock" },
  { label: "Mainnet pool opens after the beacon", icon: "channel" },
  { label: "Mainnet mining · October 3", icon: "network" },
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
      "RCNet brings together GPU proof of work, wallets, transfers and node synchronization. Its production-sized ForgeMatrix proofs are checked by CPU nodes.",
    phase: "active",
  },
  {
    number: "02",
    title: "Get ready with the community",
    detail:
      "Join Discord for setup help, supported-hardware guidance and current mainnet packages. You do not need a mining rig or a finished setup to join the conversation.",
    phase: "active",
  },
  {
    number: "03",
    title: "October 2 · Prepare",
    detail:
      "Public source and matching launch packages were released October 2, 2026 at noon CDT / 17:00 UTC, with release notes and checksums. Verify the packages and configure your miner before activation.",
    phase: "active",
  },
  {
    number: "04",
    title: "October 3 · Mainnet",
    detail:
      "Mainnet mining is planned to begin October 3, 2026 at noon CDT / 17:00 UTC, 24 hours after the source-release window. Final release and deployment checks remain in progress; any schedule changes will be announced.",
    phase: "future",
  },
  {
    number: "05",
    title: "Build toward open inference",
    detail:
      "Customer-paid AI inference is a separate service layer in development, not a feature promised for the initial mainnet launch. We want GPU operators and developers involved in shaping it.",
    phase: "future",
  },
];
