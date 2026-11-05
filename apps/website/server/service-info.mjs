export const SERVER_INFO = Object.freeze({
  name: "common-foundry-public",
  title: "Common Foundry public data and guides",
  version: "0.1.0",
  websiteUrl: "https://commonfoundry.ai/docs/mcp/",
});

export const GUIDES = Object.freeze({
  overview: { title: "Common Foundry status and getting started", path: "/learn/", asset: "learn.md" },
  mining: { title: "CMFD mining setup", path: "/learn/mining/", asset: "mining.md" },
  forgematrix: { title: "ForgeMatrix explained", path: "/learn/forgematrix/", asset: "forgematrix.md" },
  "gpu-renting": { title: "GPU rental beta", path: "/learn/gpu-renting/", asset: "gpu-renting.md" },
  api: { title: "Public read-only API", path: "/docs/api/", asset: "api.md" },
  whitepaper: { title: "White paper publication context", path: "/docs/whitepaper/", asset: "whitepaper.md" },
  mcp: { title: "Connecting to the public MCP service", path: "/docs/mcp/", asset: "mcp.md" },
});

// Server-card discovery is an emerging convention; runtime capabilities are authoritative.
export const SERVER_CARD = Object.freeze({
  $schema: "https://static.modelcontextprotocol.io/schemas/mcp-server-card/v1.json",
  version: "1.0",
  protocolVersion: "2026-07-28",
  serverInfo: SERVER_INFO,
  description: "Read public CMFD mainnet status, supply, and maintained setup guides. No wallet, signing, spending, mining-control, or rental-control tools are exposed.",
  documentationUrl: "https://commonfoundry.ai/docs/mcp/",
  iconUrl: "https://commonfoundry.ai/assets/common-foundry-mark.png",
  transport: { type: "streamable-http", endpoint: "https://commonfoundry.ai/mcp" },
  capabilities: { tools: {}, resources: {} },
  authentication: { required: false, schemes: [] },
});
