import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createPublicMcpEndpoint, createBurstGuard } from "../server/mcp-service.mjs";
import { MAINNET_ID, boundedText, createPublicDataReader, selectPublicData } from "../server/public-data.mjs";

const tip = "a".repeat(64);
const fixtures = {
  status: { network: "CommonFoundry Mainnet", network_id: MAINNET_ID, proof_profile: "ProductionV4", accepted_height: 100, validated_height: 99,
    tip, connected_peers: 3, mempool_transactions: 2, mempool_bytes: 512, utxo_count: 40, total_supply_atoms: "5000000000000", private_extra: "not forwarded" },
  supply: { network: "mainnet", height: 100, tip, max_supply: null, total_supply: "50000.00000000", total_supply_atoms: "5000000000000",
    circulating_supply: "35000.00000000", circulating_supply_atoms: "3500000000000", burned_fees: "10.00000000", burned_fees_atoms: "1000000000" },
};
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

function setup({ fetcher, now, burstGuard } = {}) {
  const requests = [];
  const readData = createPublicDataReader({ cacheProvider: async () => null, now, fetcher: fetcher ?? (async (url, init) => {
    requests.push({ url, method: init.method ?? "GET", headers: init.headers });
    return json(url.endsWith("/api/supply") ? fixtures.supply : fixtures.status);
  }) });
  const endpoint = createPublicMcpEndpoint({ readData, burstGuard });
  const assets = { async fetch(request) {
    const path = new URL(request.url).pathname;
    assert.match(path, /^\/agent-text\/[a-z-]+\.md$/);
    try { return new Response(await readFile(`dist${path}`, "utf8"), { headers: { "Content-Type": "text/markdown" } }); }
    catch { return new Response("not found", { status: 404 }); }
  } };
  return { requests, endpoint, send: (request) => {
    // A real HTTP server supplies Host; in-process Fetch Requests do not.
    const headers = new Headers(request.headers);
    if (!headers.has("Host")) headers.set("Host", new URL(request.url).host);
    return endpoint({ request: new Request(request, { headers }), env: { ASSETS: assets } });
  } };
}

async function connected(options = {}, clientOptions = {}) {
  const s = setup(options);
  const client = new Client({ name: "cmfd-protocol-test", version: "1.0.0" }, clientOptions);
  const transport = new StreamableHTTPClientTransport(new URL("https://commonfoundry.ai/mcp"), {
    fetch: (input, init) => s.send(new Request(input, init)),
  });
  await client.connect(transport);
  return { ...s, client };
}

async function rpcBody(response) {
  const text = await response.text();
  if (response.headers.get("Content-Type")?.includes("text/event-stream")) {
    const data = text.split("\n").find((line) => line.startsWith("data: "));
    return JSON.parse(data.slice(6));
  }
  return JSON.parse(text);
}

test("a real MCP client lists the read-only surface and calls both public data tools", async () => {
  const { client, requests } = await connected();
  try {
    const tools = await client.listTools();
    assert.deepEqual(tools.tools.map((t) => t.name).sort(), ["get_network_status", "get_supply", "read_guide"]);
    assert.ok(tools.tools.every((t) => t.annotations.readOnlyHint && !t.annotations.destructiveHint));
    const status = await client.callTool({ name: "get_network_status", arguments: {} });
    assert.equal(status.structuredContent.data.network_id, MAINNET_ID);
    assert.equal(status.structuredContent.data.private_extra, undefined);
    assert.equal(status.structuredContent.cacheMaxAgeSeconds, 15);
    const supply = await client.callTool({ name: "get_supply", arguments: {} });
    assert.equal(supply.structuredContent.data.total_supply_atoms, "5000000000000");
    assert.ok(requests.every((r) => r.method === "GET" && r.url.startsWith("https://explorer.commonfoundry.ai/")));
    assert.ok(requests.every((r) => !Object.keys(r.headers).some((h) => /authorization|cookie/i.test(h))));
  } finally { await client.close(); }
});

test("a pinned modern MCP client discovers and executes without a legacy handshake", async () => {
  const { client } = await connected({}, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  try {
    assert.equal((await client.listTools()).tools.length, 3);
    const status = await client.callTool({ name: "get_network_status", arguments: {} });
    assert.equal(status.structuredContent.data.network_id, MAINNET_ID);
  } finally { await client.close(); }
});

test("real MCP resource and guide reads return maintained Markdown", async () => {
  const { client, requests } = await connected();
  try {
    const resources = await client.listResources();
    assert.equal(resources.resources.length, 8);
    const guide = await client.readResource({ uri: "https://commonfoundry.ai/learn/mining/" });
    assert.match(guide.contents[0].text, /# How do I start mining CMFD/);
    const tool = await client.callTool({ name: "read_guide", arguments: { guide: "forgematrix" } });
    assert.match(tool.content[0].resource.text, /# What does ForgeMatrix do/);
    const card = await client.readResource({ uri: "mcp://server-card.json" });
    assert.equal(JSON.parse(card.contents[0].text).transport.endpoint, "https://commonfoundry.ai/mcp");
    assert.deepEqual(requests, []);
  } finally { await client.close(); }
});

test("invalid tool arguments cannot turn guide reads into arbitrary URL requests", async () => {
  const { client, requests } = await connected();
  try {
    const badGuide = await client.callTool({ name: "read_guide", arguments: { guide: "https://127.0.0.1/private" } });
    const badSupply = await client.callTool({ name: "get_supply", arguments: { url: "https://attacker.example" } });
    assert.equal(badGuide.isError, true);
    assert.equal(badSupply.isError, true);
    assert.deepEqual(requests, []);
  } finally { await client.close(); }
});

test("concurrent public reads coalesce, then expire without presenting stale fetch times", async () => {
  let time = 1800000000000;
  let calls = 0;
  const read = createPublicDataReader({ now: () => time, cacheProvider: async () => null, fetcher: async () => { calls++; return json(fixtures.supply); } });
  const values = await Promise.all(Array.from({ length: 12 }, () => read("supply")));
  assert.equal(calls, 1);
  assert.equal(new Set(values.map((v) => v.fetchedAt)).size, 1);
  time += 15001;
  const fresh = await read("supply");
  assert.equal(calls, 2);
  assert.notEqual(fresh.fetchedAt, values[0].fetchedAt);
});

test("wrong network data is rejected and failed upstream reads have a short cooldown", async () => {
  let time = 1800000000000;
  let calls = 0;
  const read = createPublicDataReader({ now: () => time, cacheProvider: async () => null,
    fetcher: async () => { calls++; return json({ ...fixtures.status, network_id: "b".repeat(64) }); } });
  await assert.rejects(read("status"), /unexpected_network_data/);
  await assert.rejects(read("status"), /unexpected_network_data/);
  assert.equal(calls, 1);
  time += 3001;
  await assert.rejects(read("status"), /unexpected_network_data/);
  assert.equal(calls, 2);
});

test("upstream failures are tool errors instead of fabricated live data", async () => {
  const { client } = await connected({ fetcher: async () => json({ error: "unavailable" }, 503) });
  try {
    const result = await client.callTool({ name: "get_network_status", arguments: {} });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /upstream_unavailable/);
    assert.equal(result.structuredContent, undefined);
  } finally { await client.close(); }
});

test("public upstream redirects are never followed to another destination", async () => {
  let requests = 0;
  const read = createPublicDataReader({ cacheProvider: async () => null, fetcher: async (url, init) => {
    requests++;
    assert.equal(url, "https://explorer.commonfoundry.ai/v1/explorer");
    assert.equal(init.redirect, "manual");
    return new Response(null, { status: 302, headers: { Location: "https://untrusted.example/" } });
  } });
  await assert.rejects(read("status"), /upstream_unavailable/);
  assert.equal(requests, 1);
});

test("atom quantities must remain strings to prevent silent precision loss", () => {
  assert.throws(() => selectPublicData("status", { ...fixtures.status, total_supply_atoms: 5000000000000 }), /invalid_response/);
  assert.throws(() => selectPublicData("supply", { ...fixtures.supply, total_supply_atoms: 5000000000000 }), /invalid_response/);
});

test("untrusted origins and hosts are rejected before tool processing", async () => {
  const { send, requests } = setup();
  for (const request of [
    new Request("https://attacker.example/mcp", { method: "POST" }),
    new Request("https://commonfoundry.ai/mcp", { method: "POST", headers: { Host: "attacker.example" } }),
    new Request("https://commonfoundry.ai/mcp", { method: "POST", headers: { Origin: "https://attacker.example" } }),
  ]) assert.equal((await send(request)).status, 403);
  assert.deepEqual(requests, []);
});

test("allowed browser preflight is credential-free and has bounded methods", async () => {
  const { send } = setup();
  const response = await send(new Request("https://commonfoundry.ai/mcp", { method: "OPTIONS", headers: {
    Origin: "https://chatgpt.com", "Access-Control-Request-Headers": "content-type,mcp-protocol-version",
  } }));
  assert.equal(response.status, 204);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://chatgpt.com");
  assert.equal(response.headers.get("Access-Control-Allow-Credentials"), null);
  assert.equal(response.headers.get("Access-Control-Allow-Methods"), "POST, OPTIONS");
});

test("SDK request size limit and adapter response size limit stop oversized payloads", async () => {
  const { send, requests } = setup();
  const response = await send(new Request("https://commonfoundry.ai/mcp", { method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" }, body: "x".repeat(32769) }));
  assert.equal(response.status, 413);
  assert.deepEqual(requests, []);
  await assert.rejects(boundedText(new Response(new Uint8Array(131073))), /response_too_large/);
});

test("burst guard resets after its window and isolates clients", () => {
  let time = 10000;
  const guard = createBurstGuard({ now: () => time, maximum: 2 });
  const request = new Request("https://commonfoundry.ai/mcp", { headers: { "CF-Connecting-IP": "192.0.2.1" } });
  assert.equal(guard(request), 0);
  assert.equal(guard(request), 0);
  assert.equal(guard(request), 60);
  assert.equal(guard(new Request("https://commonfoundry.ai/mcp", { headers: { "CF-Connecting-IP": "192.0.2.2" } })), 0);
  time += 60000;
  assert.equal(guard(request), 0);
});

test("stateless legacy MCP initialization and tool discovery interoperate", async () => {
  const { send } = setup();
  const request = (body) => new Request("https://commonfoundry.ai/mcp", { method: "POST", headers: {
    "Content-Type": "application/json", Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25",
  }, body: JSON.stringify(body) });
  const init = await rpcBody(await send(request({ jsonrpc: "2.0", id: 1, method: "initialize", params: {
    protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "legacy-check", version: "1" },
  } })));
  assert.equal(init.result.serverInfo.name, "common-foundry-public");
  const listed = await rpcBody(await send(request({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })));
  assert.equal(listed.result.tools.length, 3);
});
