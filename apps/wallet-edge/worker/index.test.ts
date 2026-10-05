// @vitest-environment node
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "./index";
import { isExplorerPath, MAINNET_FRAME_PREFIX, SECURITY_HEADERS } from "./policy";
import vectors from "../../wallet/src/web/fixtures/rust-vectors.json";

const NETWORK_ID = vectors.network_id;
const ADDRESS = vectors.backup.destination;
const ORIGIN = "https://wallet.commonfoundry.ai";

function environment(overrides: Partial<Env> = {}) {
  const limit = vi.fn(async () => ({ success: true }));
  const env = {
    ASSETS: { fetch: async () => new Response("<!doctype html>", { headers: { "Content-Type": "text/html" } }), connect: () => { throw new Error("unused"); } },
    WALLET_RPC_LIMIT: { limit },
    EXPLORER_ORIGIN: "https://mainnet-explorer-origin.commonfoundry.ai",
    EXPECTED_NETWORK_ID: NETWORK_ID,
    GATEWAY_URL: "https://13.140.66.6/mainnet",
    GATEWAY_USERNAME: "webwallet",
    GATEWAY_PASSWORD: "secret-password",
    ...overrides,
  } as unknown as Env;
  return { env, limit };
}

function explorerResponse(body: unknown, network = NETWORK_ID, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "X-CMFD-Network-Id": network } });
}

function rpcResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function post(path: string, body: unknown, headers: Record<string, string> = {}) {
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, "CF-Connecting-IP": "203.0.113.9", ...headers },
    body: JSON.stringify(body),
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("static app", () => {
  it("serves the app with a CSP that allows nothing off-origin", async () => {
    const response = await worker.fetch(new Request(`${ORIGIN}/`), environment().env);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) expect(response.headers.get(name)).toBe(value);
    const csp = SECURITY_HEADERS["Content-Security-Policy"];
    expect(csp).not.toMatch(/https?:|\*|unsafe/);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  it("is pinned to the mainnet plan and its own hostname", () => {
    const config = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8").replace(/^\s*\/\/.*$/gm, ""));
    const plan = JSON.parse(readFileSync(new URL("../../../packaging/mainnet/MAINNET-PLAN.json", import.meta.url), "utf8"));
    expect(config.vars.EXPECTED_NETWORK_ID).toBe(plan.network_id);
    expect(config.routes).toEqual([{ pattern: "wallet.commonfoundry.ai", custom_domain: true }]);
    expect(config.workers_dev).toBe(false);
    expect(config.assets.run_worker_first).toBe(true);
    expect(config.vars.GATEWAY_PASSWORD).toBeUndefined();
  });
});

describe("explorer proxy", () => {
  it("allows only the routes the wallet reads", () => {
    expect(isExplorerPath("/v1/explorer")).toBe(true);
    expect(isExplorerPath(`/v1/explorer/address/${ADDRESS}`)).toBe(true);
    expect(isExplorerPath(`/v1/explorer/transaction/${"ab".repeat(32)}`)).toBe(true);
    expect(isExplorerPath(`/v1/explorer/address/${ADDRESS.toUpperCase()}`)).toBe(false);
    expect(isExplorerPath("/v1/explorer/block/42")).toBe(false);
    expect(isExplorerPath("/v1/wallet")).toBe(false);
    expect(isExplorerPath("/v1/status")).toBe(false);
  });

  it("retries once and rejects an origin that is not mainnet", async () => {
    const upstream = vi.fn()
      .mockResolvedValueOnce(new Response("bad gateway", { status: 502 }))
      .mockResolvedValueOnce(explorerResponse({ accepted_height: 1 }));
    vi.stubGlobal("fetch", upstream);
    const ok = await worker.fetch(new Request(`${ORIGIN}/v1/explorer`), environment().env);
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ accepted_height: 1 });
    expect(upstream).toHaveBeenCalledTimes(2);

    vi.stubGlobal("fetch", vi.fn(async () => explorerResponse({}, "00".repeat(32))));
    const wrong = await worker.fetch(new Request(`${ORIGIN}/v1/explorer`), environment().env);
    expect(wrong.status).toBe(503);
  });

  it("never forwards query strings or other methods", async () => {
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);
    expect((await worker.fetch(new Request(`${ORIGIN}/v1/explorer?x=1`), environment().env)).status).toBe(404);
    expect((await worker.fetch(new Request(`${ORIGIN}/v1/explorer`, { method: "POST" }), environment().env)).status).toBe(405);
    expect(upstream).not.toHaveBeenCalled();
  });
});

describe("wallet gateway routes", () => {
  it("lists UTXOs through the gateway with the Worker's own credential", async () => {
    const upstream = vi.fn(async () => rpcResponse({ jsonrpc: "2.0", id: 1, result: {
      network_id: NETWORK_ID, destination_hex: ADDRESS, height: 3600, has_more: false, next_cursor: null,
      utxos: [{ txid: "aa".repeat(32), vout: 1, value_atoms: "5", spendable_height: 10, lock_type: "key", destination_hex: ADDRESS }],
    } }));
    vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(post("/v1/wallet/utxos", { address: ADDRESS, cursor: null }), environment().env);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ height: 3600, has_more: false, next_cursor: null, utxos: [{ txid: "aa".repeat(32), vout: 1, value_atoms: "5", spendable_height: 10 }] });
    const [url, init] = upstream.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://13.140.66.6/mainnet");
    expect(new Headers(init.headers).get("Authorization")).toBe(`Basic ${btoa("webwallet:secret-password")}`);
    expect(JSON.parse(init.body as string)).toEqual({ jsonrpc: "2.0", id: 1, method: "getaddressutxos", params: [ADDRESS, 1000, null] });
  });

  it("rejects bad input, foreign origins, and rate-limited clients before the gateway", async () => {
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);
    expect((await worker.fetch(post("/v1/wallet/utxos", { address: ADDRESS.toUpperCase() }), environment().env)).status).toBe(400);
    expect((await worker.fetch(post("/v1/wallet/utxos", { address: ADDRESS, cursor: { txid: "x" } }), environment().env)).status).toBe(400);
    expect((await worker.fetch(post("/v1/wallet/utxos", { address: ADDRESS }, { Origin: "https://evil.example" }), environment().env)).status).toBe(403);
    expect((await worker.fetch(post("/v1/wallet/utxos", { address: ADDRESS }, { "Content-Type": "text/plain" }), environment().env)).status).toBe(415);
    expect((await worker.fetch(new Request(`${ORIGIN}/v1/wallet/utxos`), environment().env)).status).toBe(405);
    const limited = environment();
    limited.limit.mockResolvedValue({ success: false });
    expect((await worker.fetch(post("/v1/wallet/utxos", { address: ADDRESS }), limited.env)).status).toBe(429);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("only relays mainnet transaction frames", async () => {
    const frame = vectors.transactions[0].frame;
    expect(frame.startsWith(`${MAINNET_FRAME_PREFIX}01000100`)).toBe(true);
    expect(MAINNET_FRAME_PREFIX).toBe(`434d4644${vectors.network_magic}`);

    const upstream = vi.fn(async () => rpcResponse({ jsonrpc: "2.0", id: 1, result: vectors.transactions[0].txid }));
    vi.stubGlobal("fetch", upstream);
    const sent = await worker.fetch(post("/v1/wallet/broadcast", { transaction_hex: frame }), environment().env);
    expect(await sent.json()).toEqual({ txid: vectors.transactions[0].txid });

    const foreign = `434d4644deadbeef${frame.slice(16)}`;
    expect((await worker.fetch(post("/v1/wallet/broadcast", { transaction_hex: foreign }), environment().env)).status).toBe(400);
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it("separates definite rejections from ambiguous failures", async () => {
    const frame = vectors.transactions[0].frame;
    const send = () => worker.fetch(post("/v1/wallet/broadcast", { transaction_hex: frame }), environment().env);

    vi.stubGlobal("fetch", vi.fn(async () => rpcResponse({ jsonrpc: "2.0", id: 1, error: { code: -26, message: "input already spent", data: { code: "mempool_conflict" } } })));
    const rejected = await send();
    expect(rejected.status).toBe(422);
    expect(await rejected.json()).toEqual({ error: "mempool_conflict", message: "input already spent" });

    vi.stubGlobal("fetch", vi.fn(async () => new Response("<html>limit</html>", { status: 503 })));
    expect((await send()).status).toBe(429);

    vi.stubGlobal("fetch", vi.fn(async () => rpcResponse({ jsonrpc: "2.0", id: 1, error: { code: -32603, message: "check status", data: { code: "upstream_failure" } } })));
    expect((await send()).status).toBe(502);

    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network down"); }));
    expect((await send()).status).toBe(502);
  });

  it("returns only output values and destinations for history lookups", async () => {
    const txid = "ab".repeat(32);
    const upstream = vi.fn(async () => rpcResponse({ jsonrpc: "2.0", id: 1, result: {
      txid, network_id: NETWORK_ID, hex: "00", vin: [], vout: [{ n: 0, value_atoms: "7", destination_hex: ADDRESS, lock_type: "key", spendable_height: 0, channel_id: null }],
    } }));
    vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(post("/v1/wallet/transaction", { txid, block_id: "cd".repeat(32) }), environment().env);
    expect(await response.json()).toEqual({ vout: [{ value_atoms: "7", destination_hex: ADDRESS }] });
    const [, init] = upstream.mock.calls[0] as unknown as [string, RequestInit];
    expect(JSON.parse(init.body as string).params).toEqual([txid, true, "cd".repeat(32)]);
  });
});
