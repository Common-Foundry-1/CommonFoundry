import { createMcpHandler, McpServer, hostHeaderValidationResponse, originValidationResponse } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { GUIDES, SERVER_INFO, SERVER_CARD } from "./service-info.mjs";
import { boundedText, createPublicDataReader, PublicDataError } from "./public-data.mjs";

const ANNOTATIONS = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };
const PUBLIC_HOSTS = ["commonfoundry.ai", "www.commonfoundry.ai", "commonfoundry.pages.dev"];
const PUBLIC_ORIGINS = ["commonfoundry.ai", "www.commonfoundry.ai", "chatgpt.com", "claude.ai", "localhost", "127.0.0.1"];

export function createBurstGuard({ now = Date.now, maximum = 120 } = {}) {
  const buckets = new Map();
  return (request) => {
    const key = (request.headers.get("CF-Connecting-IP") ?? "unknown").slice(0, 64);
    const time = now();
    let bucket = buckets.get(key);
    if (!bucket || time >= bucket.until) {
      if (buckets.size >= 4096) buckets.delete(buckets.keys().next().value);
      bucket = { used: 0, until: time + 60000 };
      buckets.set(key, bucket);
    }
    if (bucket.used >= maximum) return Math.max(1, Math.ceil((bucket.until - time) / 1000));
    bucket.used++;
    return 0;
  };
}

function responseHeaders(response, origin) {
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  headers.set("Referrer-Policy", "no-referrer");
  if (origin) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
    headers.set("Access-Control-Expose-Headers", "MCP-Protocol-Version, Mcp-Session-Id, Retry-After");
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function failure(status, code, extraHeaders = {}) {
  return new Response(JSON.stringify({ error: code, documentation: "https://commonfoundry.ai/docs/mcp/" }), {
    status, headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

export function createPublicMcpEndpoint({ readData = createPublicDataReader(), burstGuard = createBurstGuard() } = {}) {
  return async function handle(context) {
    const { request } = context;
    const hostname = new URL(request.url).hostname;
    const preview = hostname.endsWith(".commonfoundry.pages.dev");
    const hosts = preview ? [...PUBLIC_HOSTS, hostname] : PUBLIC_HOSTS;
    const origins = preview ? [...PUBLIC_ORIGINS, hostname] : PUBLIC_ORIGINS;
    const rejected = hostHeaderValidationResponse(request, hosts) ?? originValidationResponse(request, origins);
    if (rejected) return responseHeaders(rejected, null);
    const origin = request.headers.get("Origin");
    if (request.method === "OPTIONS") {
      const requested = (request.headers.get("Access-Control-Request-Headers") ?? "").split(",").map((h) => h.trim()).filter(Boolean);
      if (requested.some((h) => !/^(accept|content-type|last-event-id|mcp-[a-z-]+)$/i.test(h))) {
        return responseHeaders(failure(400, "unsupported_request_header"), origin);
      }
      return responseHeaders(new Response(null, { status: 204, headers: {
        "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": requested.join(", "), "Access-Control-Max-Age": "600",
      } }), origin);
    }
    if (request.method !== "POST") return responseHeaders(failure(405, "use_mcp_post", { Allow: "POST, OPTIONS" }), origin);
    const retry = burstGuard(request);
    if (retry) return responseHeaders(failure(429, "request_rate_exceeded", { "Retry-After": String(retry) }), origin);

    const readGuide = async (key) => {
      const guide = GUIDES[key];
      const asset = await context.env.ASSETS.fetch(new Request(new URL(`/agent-text/${guide.asset}`, request.url)));
      if (asset.status !== 200) throw new PublicDataError("guide_unavailable");
      const text = await boundedText(asset, 65536);
      if (!/^# |\n# /.test(text) || /<html|<script/i.test(text)) throw new PublicDataError("guide_unavailable");
      return { uri: `https://commonfoundry.ai${guide.path}`, mimeType: "text/markdown", text };
    };
    const handler = createMcpHandler(() => {
      const server = new McpServer(SERVER_INFO, { maxToolInputElements: 16,
        instructions: "Public read-only explorer observations and maintained documentation. Snapshot timestamps and heights matter; data can lag or change after a reorganization. This service does not independently verify consensus proofs." });
      for (const [name, kind, description] of [
        ["get_network_status", "status", "Read the public CMFD mainnet identity, observed heights, tip, peer count, and mempool counts."],
        ["get_supply", "supply", "Read public CMFD total and circulating supply and burned fees. Amounts are decimal strings and atom counts are integer strings."],
      ]) {
        server.registerTool(name, { description, inputSchema: z.strictObject({}), annotations: ANNOTATIONS }, async () => {
          try {
            const value = await readData(kind);
            return { content: [{ type: "text", text: JSON.stringify(value) }], structuredContent: value };
          } catch (error) {
            const code = error instanceof PublicDataError ? error.code : "data_unavailable";
            return { isError: true, content: [{ type: "text", text: JSON.stringify({ error: code, retryable: true }) }] };
          }
        });
      }
      server.registerTool("read_guide", { description: "Read a maintained Common Foundry guide for project status, mining, ForgeMatrix, GPU renting, public API use, the white paper, or MCP connection.",
        inputSchema: z.strictObject({ guide: z.enum(Object.keys(GUIDES)) }), annotations: { ...ANNOTATIONS, openWorldHint: false } }, async ({ guide }) => {
        try { return { content: [{ type: "resource", resource: await readGuide(guide) }] }; }
        catch { return { isError: true, content: [{ type: "text", text: "guide_unavailable" }] }; }
      });
      for (const [key, guide] of Object.entries(GUIDES)) {
        const uri = `https://commonfoundry.ai${guide.path}`;
        server.registerResource(key, uri, { title: guide.title, mimeType: "text/markdown" }, async () => ({ contents: [await readGuide(key)] }));
      }
      server.registerResource("server-card", "mcp://server-card.json", { title: "MCP discovery metadata", mimeType: "application/json" }, async () => ({
        contents: [{ uri: "mcp://server-card.json", mimeType: "application/json", text: JSON.stringify(SERVER_CARD) }],
      }));
      return server;
    }, { legacy: "stateless", maxRequestBodySize: 32768, maxSubscriptions: 0, keepAliveMs: 0 });
    try { return responseHeaders(await handler.fetch(request), origin); }
    catch { return responseHeaders(failure(500, "mcp_request_failed"), origin); }
  };
}
