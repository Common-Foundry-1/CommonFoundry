import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { MAINNET_ID } from "../server/public-data.mjs";

const url = new URL(process.argv[2] ?? "https://commonfoundry.ai/mcp");
if (url.protocol !== "https:" || url.pathname !== "/mcp" ||
    !(url.hostname === "commonfoundry.ai" || url.hostname.endsWith(".commonfoundry.pages.dev"))) {
  throw new Error("Use the Common Foundry production or preview /mcp endpoint.");
}
const exchanges = [];
const fetchBounded = async (input, init) => {
  const request = new Request(input, init);
  const response = await fetch(new Request(request, { signal: AbortSignal.any([request.signal, AbortSignal.timeout(12000)]) }));
  if (request.method === "POST") {
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
    exchanges.push({ status: response.status, contentType: response.headers.get("Content-Type") });
  }
  return response;
};
const modern = process.argv[4] === "modern";
const client = new Client({ name: "cmfd-public-service-verification", version: "1.0.0" }, modern ? {
  versionNegotiation: { mode: { pin: "2026-07-28" } },
} : {});
try {
  await client.connect(new StreamableHTTPClientTransport(url, { fetch: fetchBounded }));
  const list = await client.listTools();
  assert.deepEqual(list.tools.map((t) => t.name).sort(), ["get_network_status", "get_supply", "read_guide"]);
  assert.ok(list.tools.every((t) => t.annotations.readOnlyHint === true && t.annotations.destructiveHint === false));
  const status = await client.callTool({ name: "get_network_status", arguments: {} });
  assert.notEqual(status.isError, true, JSON.stringify(status));
  assert.equal(status.structuredContent.data.network_id, MAINNET_ID);
  const supply = await client.callTool({ name: "get_supply", arguments: {} });
  assert.notEqual(supply.isError, true, JSON.stringify(supply));
  assert.equal(supply.structuredContent.data.network, "mainnet");
  const resources = await client.listResources();
  const guide = await client.readResource({ uri: "https://commonfoundry.ai/learn/mining/" });
  assert.match(guide.contents[0].text, /# How do I start mining CMFD/);
  const invalid = await client.callTool({ name: "read_guide", arguments: { guide: "https://127.0.0.1/private" } });
  assert.equal(invalid.isError, true);
  const cardResult = await client.readResource({ uri: "mcp://server-card.json" });
  const card = JSON.parse(cardResult.contents[0].text);
  assert.equal(card.serverInfo.name, "common-foundry-public");
  const report = { endpoint: url.href, checkedUtc: new Date().toISOString(), passed: true,
    serviceVersion: card.serverInfo.version, protocolMode: modern ? "2026-07-28" : "legacy", tools: list.tools.map((t) => t.name), resourceCount: resources.resources.length,
    networkId: status.structuredContent.data.network_id, acceptedHeight: status.structuredContent.data.accepted_height,
    supplyHeight: supply.structuredContent.data.height, statusFetchedAt: status.structuredContent.fetchedAt,
    supplyFetchedAt: supply.structuredContent.fetchedAt, guideRead: "mining", invalidInputRejected: true, exchanges };
  if (process.argv[3]) await writeFile(process.argv[3], `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
} finally { await client.close(); }
