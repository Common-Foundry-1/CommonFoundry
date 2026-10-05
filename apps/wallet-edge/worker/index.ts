// Edge for the hosted web wallet. Keys never reach this Worker: the browser signs, and this
// Worker only serves the app, proxies read-only explorer routes, and relays three narrow
// wallet calls to the mainnet gateway under the Worker's own credential.
import {
  HASH,
  isExplorerPath,
  MAINNET_FRAME_PREFIX,
  MAX_BODY_BYTES,
  MAX_TRANSACTION_BYTES,
  NETWORK_HEADER,
  SECURITY_HEADERS,
} from "./policy";

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

class EdgeError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function withSecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  if (headers.get("Content-Type")?.startsWith("text/html")) headers.set("Cache-Control", "no-store");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function proxyExplorer(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (request.method !== "GET") return json({ error: "method_not_allowed" }, 405);
  if (url.search || !isExplorerPath(url.pathname)) return json({ error: "not_found" }, 404);
  const { success } = await env.WALLET_READ_LIMIT.limit({ key: request.headers.get("CF-Connecting-IP") ?? "unknown" });
  if (!success) return json({ error: "rate_limited", message: "Too many requests from this connection. Wait a minute and try again." }, 429);
  const upstreamUrl = new URL(url.pathname, env.EXPLORER_ORIGIN);
  // Reads are idempotent, so one retry rides out the tunnel's occasional 502.
  for (let attempt = 0; ; attempt += 1) {
    let upstream: Response;
    try {
      upstream = await fetch(upstreamUrl, {
        headers: { Accept: "application/json" },
        redirect: "manual",
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      if (attempt === 0) continue;
      return json({ error: "explorer_unavailable", message: "The network explorer is unreachable. Try again shortly." }, 503);
    }
    // 503 is the origin shedding load, so only a 502 (tunnel hiccup) is retried.
    if (upstream.status === 502 && attempt === 0) {
      await upstream.body?.cancel();
      continue;
    }
    const type = upstream.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();
    if (upstream.headers.get(NETWORK_HEADER) !== env.EXPECTED_NETWORK_ID || type !== "application/json") {
      await upstream.body?.cancel();
      return json({ error: "explorer_identity_rejected", message: "The network explorer did not identify as mainnet." }, 503);
    }
    return new Response(upstream.body, {
      status: upstream.status,
      headers: { "Cache-Control": "no-store", "Content-Type": "application/json", [NETWORK_HEADER]: env.EXPECTED_NETWORK_ID },
    });
  }
}

async function readJsonBody(request: Request): Promise<Record<string, unknown>> {
  if (request.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    throw new EdgeError(415, "json_required", "Send application/json.");
  }
  // Refuse oversized bodies before buffering them.
  const declared = Number(request.headers.get("Content-Length") ?? "0");
  if (!Number.isFinite(declared) || declared > MAX_BODY_BYTES) throw new EdgeError(413, "body_too_large", "The request is too large.");
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) throw new EdgeError(413, "body_too_large", "The request is too large.");
  try {
    const body = JSON.parse(text) as unknown;
    if (body && typeof body === "object" && !Array.isArray(body)) return body as Record<string, unknown>;
  } catch {
    // Fall through to the shared error.
  }
  throw new EdgeError(400, "invalid_json", "The request body must be a JSON object.");
}

const isHash = (value: unknown): value is string => typeof value === "string" && HASH.test(value);
const isHeight = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
const isIndex = (value: unknown): value is number => Number.isInteger(value) && (value as number) >= 0 && (value as number) <= 0xffff_ffff;
const isAtoms = (value: unknown): value is string => typeof value === "string" && /^(?:0|[1-9][0-9]{0,19})$/.test(value);
const invalidGatewayResponse = () => new EdgeError(502, "gateway_invalid_response", "The network gateway sent an unexpected response.");

function hash(value: unknown, field: string): string {
  if (typeof value !== "string" || !HASH.test(value)) throw new EdgeError(400, "invalid_params", `${field} must be 64 lowercase hex characters.`);
  return value;
}

/**
 * One JSON-RPC call to the gateway. Only failures where the gateway certainly did not
 * process the call map to 4xx; anything ambiguous maps to 502 so the browser keeps the
 * transaction's inputs reserved instead of risking a double spend.
 */
async function gateway(env: Env, method: string, params: JsonValue[]): Promise<Record<string, unknown>> {
  let upstream: Response;
  try {
    upstream = await fetch(env.GATEWAY_URL, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Basic ${btoa(`${env.GATEWAY_USERNAME}:${env.GATEWAY_PASSWORD}`)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      redirect: "manual",
      signal: AbortSignal.timeout(method === "sendrawtransaction" ? 30_000 : 20_000),
    });
  } catch {
    throw new EdgeError(502, "gateway_unavailable", "The network gateway did not answer. If you were sending, check your activity before trying again.");
  }
  if (upstream.status === 429 || upstream.status === 503) {
    await upstream.body?.cancel();
    // nginx rejects these before the gateway sees them.
    throw new EdgeError(429, "gateway_busy", "The network gateway is busy. Wait a moment and try again.");
  }
  if (upstream.status !== 200) {
    await upstream.body?.cancel();
    console.error(JSON.stringify({ message: "gateway_status", method, status: upstream.status }));
    throw new EdgeError(502, "gateway_unavailable", "The network gateway is unavailable. If you were sending, check your activity before trying again.");
  }
  const body = await upstream.json().catch(() => null) as { result?: unknown; error?: { message?: unknown; data?: { code?: unknown } } } | null;
  if (body?.error) {
    const code = typeof body.error.data?.code === "string" ? body.error.data.code : "rpc_error";
    const message = typeof body.error.message === "string" ? body.error.message : "The network rejected the request.";
    if (code === "upstream_failure") throw new EdgeError(502, code, message);
    throw new EdgeError(422, code, message);
  }
  if (!body || typeof body.result !== "object" && typeof body.result !== "string") {
    throw new EdgeError(502, "gateway_invalid_response", "The network gateway sent an unexpected response.");
  }
  return typeof body.result === "string" ? { value: body.result } : body.result as Record<string, unknown>;
}

async function walletRoute(request: Request, env: Env, route: string): Promise<Response> {
  const body = await readJsonBody(request);
  if (route === "utxos") {
    const address = hash(body.address, "address");
    const cursor = body.cursor ?? null;
    if (cursor !== null) {
      const value = cursor as Record<string, unknown>;
      if (typeof cursor !== "object" || Array.isArray(cursor) || Object.keys(value).sort().join() !== "snapshot,txid,vout") {
        throw new EdgeError(400, "invalid_params", "Invalid cursor.");
      }
      hash(value.snapshot, "cursor.snapshot");
      hash(value.txid, "cursor.txid");
      if (!Number.isInteger(value.vout) || (value.vout as number) < 0 || (value.vout as number) > 0xffff_ffff) {
        throw new EdgeError(400, "invalid_params", "Invalid cursor.");
      }
    }
    const result = await gateway(env, "getaddressutxos", [address, 1000, cursor as JsonValue]);
    if (result.network_id !== env.EXPECTED_NETWORK_ID || result.destination_hex !== address
        || !Array.isArray(result.utxos) || !isHeight(result.height)) {
      throw invalidGatewayResponse();
    }
    const utxos = [];
    for (const raw of result.utxos as unknown[]) {
      const utxo = (raw ?? {}) as Record<string, unknown>;
      if (utxo.lock_type !== "key" || utxo.destination_hex !== address) continue;
      if (!isHash(utxo.txid) || !isIndex(utxo.vout) || !isAtoms(utxo.value_atoms) || !isHeight(utxo.spendable_height)) {
        throw invalidGatewayResponse();
      }
      utxos.push({ txid: utxo.txid, vout: utxo.vout, value_atoms: utxo.value_atoms, spendable_height: utxo.spendable_height });
    }
    return json({
      height: result.height,
      utxos,
      has_more: result.has_more === true,
      next_cursor: result.next_cursor ?? null,
    });
  }
  if (route === "transaction") {
    const txid = hash(body.txid, "txid");
    const blockId = hash(body.block_id, "block_id");
    const result = await gateway(env, "getrawtransaction", [txid, true, blockId]);
    if (result.txid !== txid || result.network_id !== env.EXPECTED_NETWORK_ID || !Array.isArray(result.vout)) {
      throw invalidGatewayResponse();
    }
    const vout = (result.vout as unknown[]).map((raw) => {
      const output = (raw ?? {}) as Record<string, unknown>;
      if (!isAtoms(output.value_atoms) || !(output.destination_hex === null || isHash(output.destination_hex))) {
        throw invalidGatewayResponse();
      }
      return { value_atoms: output.value_atoms, destination_hex: output.destination_hex };
    });
    return json({ vout });
  }
  if (route === "broadcast") {
    const frame = body.transaction_hex;
    if (typeof frame !== "string" || !/^(?:[0-9a-f]{2})+$/.test(frame) || frame.length > 2 * MAX_TRANSACTION_BYTES) {
      throw new EdgeError(400, "invalid_transaction", "The transaction encoding is invalid.");
    }
    // Only mainnet transaction frames ("CMFD" + mainnet magic, wire v1, kind 1).
    if (!frame.startsWith(`${MAINNET_FRAME_PREFIX}01000100`)) {
      throw new EdgeError(400, "wrong_network", "Only Common Foundry mainnet transactions can be sent here.");
    }
    const result = await gateway(env, "sendrawtransaction", [frame]);
    if (typeof result.value !== "string" || !HASH.test(result.value)) {
      throw new EdgeError(502, "gateway_invalid_response", "The network gateway sent an unexpected response.");
    }
    return json({ txid: result.value });
  }
  return json({ error: "not_found" }, 404);
}

async function handleWallet(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const route = /^\/v1\/wallet\/(utxos|transaction|broadcast)$/.exec(url.pathname)?.[1];
  if (!route || url.search) return json({ error: "not_found" }, 404);
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  const origin = request.headers.get("Origin");
  if (origin !== null && origin !== url.origin) return json({ error: "forbidden_origin" }, 403);
  const client = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const { success } = await env.WALLET_RPC_LIMIT.limit({ key: client });
  if (!success) return json({ error: "rate_limited", message: "Too many requests from this connection. Wait a minute and try again." }, 429);
  try {
    return await walletRoute(request, env, route);
  } catch (cause) {
    if (cause instanceof EdgeError) return json({ error: cause.code, message: cause.message }, cause.status);
    console.error(JSON.stringify({ message: "wallet_route_failed", route, error: cause instanceof Error ? cause.name : "unknown" }));
    return json({ error: "internal_error", message: "The wallet service failed unexpectedly." }, 500);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    const response = pathname.startsWith("/v1/wallet/")
      ? await handleWallet(request, env)
      : pathname.startsWith("/v1/")
        ? await proxyExplorer(request, env)
        : await env.ASSETS.fetch(request);
    return withSecurityHeaders(response);
  },
} satisfies ExportedHandler<Env>;
