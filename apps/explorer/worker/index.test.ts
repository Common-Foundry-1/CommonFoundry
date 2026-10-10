// @vitest-environment node
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker, { formatCmfd, FUND_ADDRESSES, isExplorerApiPath, mintedAtoms, SECURITY_HEADERS } from "./index";
import { MAINNET_NETWORK_ID, NETWORK_HEADER } from "../shared/network";

function environment(overrides: Partial<Env> = {}): Env {
  return {
    ASSETS: { fetch: async () => new Response("static explorer"), connect: () => { throw new Error("unused asset connect"); } },
    EXPLORER_ORIGIN: "https://mainnet-explorer-origin.commonfoundry.ai",
    EXPLORER_NETWORK: "mainnet",
    EXPLORER_EXPECTED_NETWORK_ID: MAINNET_NETWORK_ID,
    ...overrides,
  };
}

afterEach(() => vi.unstubAllGlobals());

/** An origin answering the snapshot, and each fund address at the snapshot's tip. */
function origin(snapshot: Record<string, unknown>, fundAtoms = "0") {
  return vi.fn().mockImplementation(async (url: URL) => Response.json(
    String(url).includes("/v1/explorer/address/") ? { tip: snapshot.tip, confirmed_atoms: fundAtoms } : snapshot,
    { headers: { [NETWORK_HEADER]: MAINNET_NETWORK_ID } },
  ));
}

describe("explorer edge API allowlist", () => {
  it("keeps the prepared origin rule anchored to only public explorer paths", () => {
    const yaml = readFileSync(new URL("../origin-ingress.example.yml", import.meta.url), "utf8");
    const expression = /^\s+path: '(.*)'$/m.exec(yaml)?.[1];
    if (!expression) throw new Error("Origin example must contain a quoted path expression");
    const originPath = new RegExp(expression);
    for (const path of ["/v1/explorer", "/v1/explorer/block/42", `/v1/explorer/transaction/${"ab".repeat(32)}`, `/v1/explorer/address/${"a1".repeat(32)}`, `/v1/explorer/address/${"a1".repeat(32)}/${"d1".repeat(32)}.81.1`]) {
      expect(originPath.test(path)).toBe(true);
    }
    for (const path of ["/v1/wallet", "/v1/status", "/prefix/v1/explorer", "/v1/explorer/extra", `/v1/explorer/address/${"a1".repeat(32)}/extra/private`, `/v1/explorer/transaction/${"ab".repeat(32)}.json`]) {
      expect(originPath.test(path)).toBe(false);
    }
    expect(yaml).toContain("hostname: mainnet-explorer-origin.commonfoundry.ai");
    expect(yaml).toContain("service: http://127.0.0.1:29443");
    expect(yaml.trimEnd().endsWith("- service: http_status:404")).toBe(true);
  });

  it("allows only the bounded read-only explorer routes", () => {
    expect(isExplorerApiPath("/v1/explorer")).toBe(true);
    expect(isExplorerApiPath("/v1/explorer/block/42")).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/block/${"ab".repeat(32)}`)).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/transaction/${"01".repeat(32)}`)).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/address/${"a1".repeat(32)}`)).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/address/${"a1".repeat(32)}/${"d1".repeat(32)}.81.1`)).toBe(true);
  });

  it("does not expose general node RPC routes", () => {
    expect(isExplorerApiPath("/v1/status")).toBe(false);
    expect(isExplorerApiPath("/v1/explorer/block/latest/extra")).toBe(false);
    expect(isExplorerApiPath("/v1/explorer/transaction/not-a-transaction")).toBe(false);
  });
});

describe("mainnet explorer identity gate", () => {
  it("pins configuration to the approved plan and gives the public domain only to mainnet", () => {
    const plan = JSON.parse(readFileSync(new URL("../../../packaging/mainnet/MAINNET-PLAN.json", import.meta.url), "utf8"));
    const config = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
    expect(MAINNET_NETWORK_ID).toBe(plan.network_id);
    expect(config.env.mainnet.vars.EXPLORER_EXPECTED_NETWORK_ID).toBe(MAINNET_NETWORK_ID);
    expect(config.env.mainnet.routes).toEqual([{ pattern: "explorer.commonfoundry.ai", custom_domain: true }]);
    expect(config.env.mainnet.workers_dev).toBe(false);
    expect(config.env.mainnet.preview_urls).toBe(false);
    // A plain (Devnet) deploy must never move the public domain off mainnet.
    expect(config.routes).toBeUndefined();
  });

  it("serves hashed assets without the Worker, with the same static security headers", () => {
    const config = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
    expect(config.assets.run_worker_first).toEqual(["/*", "!/assets/*"]);
    expect(config.env.mainnet.assets.run_worker_first).toEqual(["/*", "!/assets/*"]);
    const rules = readFileSync(new URL("../public/_headers", import.meta.url), "utf8").split(/\r?\n/);
    expect(rules[0]).toBe("/*");
    const declared = Object.fromEntries(rules.slice(1).filter(Boolean).map((line) => {
      const separator = line.indexOf(":");
      return [line.slice(0, separator).trim(), line.slice(separator + 1).trim()];
    }));
    expect(declared).toEqual(SECURITY_HEADERS);
  });

  it.each(["bad", `${"ab".repeat(32)}.0.0`, `${"ab".repeat(32)}.01.0`, `${"ab".repeat(32)}.1.1025`, `${"ab".repeat(32)}.18446744073709551616.0`, `${"ab".repeat(32)}.1.0/extra`])(
    "rejects invalid address cursor %s without forwarding", async (cursor) => {
      const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
      const path = `/v1/explorer/address/${"a1".repeat(32)}/${cursor}`;
      expect(isExplorerApiPath(path)).toBe(false);
      expect((await worker.fetch(new Request("https://explorer.test" + path), environment())).status).toBe(404);
      expect(upstream).not.toHaveBeenCalled();
    },
  );

  it.each(["/v1/explorer", "/v1/explorer/block/42", `/v1/explorer/transaction/${"ab".repeat(32)}`, `/v1/explorer/address/${"a1".repeat(32)}`, `/v1/explorer/address/${"a1".repeat(32)}/${"d1".repeat(32)}.81.1`])(
    "streams only correctly identified responses for %s", async (path) => {
      const upstream = vi.fn().mockResolvedValue(new Response('{"ok":true}', {
        headers: { "Content-Type": "application/json", [NETWORK_HEADER]: MAINNET_NETWORK_ID },
      }));
      vi.stubGlobal("fetch", upstream);
      const response = await worker.fetch(new Request("https://explorer.test" + path, {
        headers: { Authorization: "must-not-forward", Cookie: "must-not-forward" },
      }), environment());
      expect(response.status).toBe(200);
      expect(response.headers.get(NETWORK_HEADER)).toBe(MAINNET_NETWORK_ID);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(await response.json()).toEqual({ ok: true });
      const [url, options] = upstream.mock.calls[0];
      expect(String(url)).toBe("https://mainnet-explorer-origin.commonfoundry.ai" + path);
      expect(options.headers).toEqual({ Accept: "application/json" });
      expect(options.redirect).toBe("manual");
      expect(options.signal).toBeInstanceOf(AbortSignal);
    },
  );

  it.each([null, "63".repeat(32), MAINNET_NETWORK_ID + "," + MAINNET_NETWORK_ID])(
    "rejects absent, RC, or ambiguous identity %s before forwarding the body", async (pin) => {
      const cancelled = vi.fn();
      const body = new ReadableStream({ cancel: cancelled });
      const headers = new Headers({ "Content-Type": "application/json" });
      if (pin !== null) headers.set(NETWORK_HEADER, pin);
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(body, { headers })));
      const response = await worker.fetch(new Request("https://explorer.test/v1/explorer"), environment());
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({ error: "explorer_network_identity_rejected" });
      expect(cancelled).toHaveBeenCalledOnce();
    },
  );

  it("checks identity on not-found responses too", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json({ error: "not found" }, { status: 404 })));
    const response = await worker.fetch(new Request("https://explorer.test/v1/explorer/block/42"), environment());
    expect(response.status).toBe(503);
  });

  it("streams authenticated stale-cursor errors but rejects unidentified ones", async () => {
    const data = { error: "Restart pagination", code: "explorer_cursor_stale", retryable: true };
    const upstream = vi.fn().mockResolvedValueOnce(Response.json(data, { status: 409, headers: { [NETWORK_HEADER]: MAINNET_NETWORK_ID } }))
      .mockResolvedValueOnce(Response.json(data, { status: 409 }));
    vi.stubGlobal("fetch", upstream);
    const request = new Request(`https://explorer.test/v1/explorer/address/${"a1".repeat(32)}/${"d1".repeat(32)}.81.1`);
    const response = await worker.fetch(request, environment());
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual(data);
    expect((await worker.fetch(request, environment())).status).toBe(503);
  });

  it.each(["", "63".repeat(32)])("refuses a missing or incorrect configured mainnet pin", async (pin) => {
    const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(new Request("https://explorer.test/v1/explorer"), environment({ EXPLORER_EXPECTED_NETWORK_ID: pin }));
    expect(response.status).toBe(503);
    expect(upstream).not.toHaveBeenCalled();
  });

  it.each(["http://example.test", "https://user:secret@example.test", "https://example.test/private", "https://example.test/?key=secret"])(
    "refuses unsafe origin configuration", async (origin) => {
      const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
      const response = await worker.fetch(new Request("https://explorer.test/v1/explorer"), environment({ EXPLORER_ORIGIN: origin }));
      expect(response.status).toBe(503);
      expect(upstream).not.toHaveBeenCalled();
    },
  );

  it.each(["/v1/wallet", "/v1/status", "/v1/explorer?limit=all"])("never forwards disallowed route %s", async (path) => {
    const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(new Request("https://explorer.test" + path), environment());
    expect(response.status).toBe(404);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("rejects writes and redirects, and preserves RC compatibility", async () => {
    const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
    expect((await worker.fetch(new Request("https://explorer.test/v1/explorer", { method: "POST" }), environment())).status).toBe(405);
    expect(upstream).not.toHaveBeenCalled();
    upstream.mockResolvedValue(new Response(null, { status: 302, headers: { Location: "https://other.test" } }));
    expect((await worker.fetch(new Request("https://explorer.test/v1/explorer"), environment())).status).toBe(502);
    upstream.mockResolvedValue(Response.json({ network: "RCNet-1" }));
    const response = await worker.fetch(new Request("https://explorer.test/v1/explorer"), environment({ EXPLORER_NETWORK: "rc", EXPLORER_EXPECTED_NETWORK_ID: "" }));
    expect(await response.json()).toEqual({ network: "RCNet-1" });
  });

  it("gives each page a fresh script nonce and never revalidates it", async () => {
    const seen: Request[] = [];
    const page = () => new Response("<!doctype html>", { headers: { "Content-Type": "text/html", ETag: '"page"' } });
    const env = environment({ ASSETS: { fetch: async (request: Request) => { seen.push(request); return page(); }, connect: () => { throw new Error("unused"); } } as unknown as Fetcher });
    const request = () => new Request("https://explorer.test/block/42", { headers: { "If-None-Match": '"page"', "If-Modified-Since": "Sat, 03 Oct 2026 00:00:00 GMT" } });
    const [first, second] = [await worker.fetch(request(), env), await worker.fetch(request(), env)];
    const nonce = (response: Response) => response.headers.get("Content-Security-Policy")?.match(/script-src 'self' 'nonce-([0-9a-f]{32})' https:\/\/static\.cloudflareinsights\.com;/)?.[1];
    expect(nonce(first)).toBeDefined();
    expect(nonce(second)).toBeDefined();
    expect(nonce(first)).not.toBe(nonce(second));
    expect(first.headers.get("Cache-Control")).toBe("no-store");
    expect(seen.every((sent) => !sent.headers.has("If-None-Match") && !sent.headers.has("If-Modified-Since"))).toBe(true);
  });

  it("serves the total supply from the checked snapshot", async () => {
    const snapshot = { accepted_height: 4721, tip: "ab".repeat(32), total_supply_atoms: "236059876543210" };
    const upstream = vi.fn().mockImplementation(async () => Response.json(snapshot, {
      headers: { [NETWORK_HEADER]: MAINNET_NETWORK_ID },
    }));
    vi.stubGlobal("fetch", upstream);
    const total = await worker.fetch(new Request("https://explorer.test/api/supply/total"), environment());
    expect(total.status).toBe(200);
    expect(total.headers.get("Content-Type")).toBe("text/plain; charset=utf-8");
    expect(total.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(await total.text()).toBe("2360598.76543210");
    // The total needs only the snapshot.
    expect(upstream.mock.calls.map(([url]) => String(url))).toEqual(["https://mainnet-explorer-origin.commonfoundry.ai/v1/explorer"]);
    expect(formatCmfd("5")).toBe("0.00000005");
  });

  it("pins the fund addresses to the plan's reward destinations", () => {
    const plan = JSON.parse(readFileSync(new URL("../../../packaging/mainnet/MAINNET-PLAN.json", import.meta.url), "utf8"));
    const destinations = plan.payload.rules.reward_destinations;
    expect(FUND_ADDRESSES).toEqual([
      { label: "steward", address: destinations.steward_xonly_public_key },
      { label: "community", address: destinations.community_xonly_public_key },
    ]);
  });

  it("leaves the steward and community fund balances out of the circulating supply", async () => {
    const tip = "ab".repeat(32);
    const balances: Record<string, string> = { [FUND_ADDRESSES[0].address]: "50000000000000", [FUND_ADDRESSES[1].address]: "9876543210" };
    const upstream = vi.fn().mockImplementation(async (url: URL) => {
      const address = /\/v1\/explorer\/address\/([0-9a-f]{64})$/.exec(String(url))?.[1];
      const body = address
        ? { address, tip, accepted_height: 4721, confirmed_atoms: balances[address] }
        : { accepted_height: 4721, tip, total_supply_atoms: "236059876543210" };
      return Response.json(body, { headers: { [NETWORK_HEADER]: MAINNET_NETWORK_ID } });
    });
    vi.stubGlobal("fetch", upstream);
    const circulating = await worker.fetch(new Request("https://explorer.test/api/supply/circulating"), environment());
    expect(circulating.headers.get("Content-Type")).toBe("text/plain; charset=utf-8");
    expect(await circulating.text()).toBe("1860500.00000000");
    const json = await worker.fetch(new Request("https://explorer.test/api/supply"), environment());
    expect(await json.json()).toMatchObject({
      network: "mainnet", height: 4721, total_supply: "2360598.76543210", total_supply_atoms: "236059876543210",
      circulating_supply: "1860500.00000000", circulating_supply_atoms: "186050000000000", max_supply: null,
      excluded_from_circulating: [
        { label: "steward", address: FUND_ADDRESSES[0].address, balance: "500000.00000000", balance_atoms: "50000000000000" },
        { label: "community", address: FUND_ADDRESSES[1].address, balance: "98.76543210", balance_atoms: "9876543210" },
      ],
    });
    expect(upstream.mock.calls.slice(0, 3).map(([url]) => String(url))).toEqual([
      "https://mainnet-explorer-origin.commonfoundry.ai/v1/explorer",
      `https://mainnet-explorer-origin.commonfoundry.ai/v1/explorer/address/${FUND_ADDRESSES[0].address}`,
      `https://mainnet-explorer-origin.commonfoundry.ai/v1/explorer/address/${FUND_ADDRESSES[1].address}`,
    ]);
  });

  it("reads the fund balances at the snapshot's tip", async () => {
    let round = 0;
    const upstream = vi.fn().mockImplementation(async (url: URL) => {
      const isSnapshot = String(url).endsWith("/v1/explorer");
      if (isSnapshot) round += 1;
      // The first round's fund views come from the next block.
      const tip = !isSnapshot && round === 1 ? "cd".repeat(32) : "ab".repeat(32);
      const body = isSnapshot
        ? { accepted_height: 4721, tip, total_supply_atoms: "300" }
        : { tip, confirmed_atoms: round === 1 ? "999" : "100" };
      return Response.json(body, { headers: { [NETWORK_HEADER]: MAINNET_NETWORK_ID } });
    });
    vi.stubGlobal("fetch", upstream);
    const circulating = await worker.fetch(new Request("https://explorer.test/api/supply/circulating"), environment());
    expect(await circulating.text()).toBe("0.00000100");
    expect(upstream).toHaveBeenCalledTimes(6);
    // Views that never agree on a tip are not published.
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (url: URL) => Response.json(
      String(url).endsWith("/v1/explorer")
        ? { accepted_height: 4721, tip: "ab".repeat(32), total_supply_atoms: "300" }
        : { tip: "cd".repeat(32), confirmed_atoms: "100" },
      { headers: { [NETWORK_HEADER]: MAINNET_NETWORK_ID } },
    )));
    expect((await worker.fetch(new Request("https://explorer.test/api/supply"), environment())).status).toBe(503);
  });

  it("serves the last TidoEx CMFD/USDT trade", async () => {
    const markets = [{ market_id: "BTC_USDT", last_price: "82160.04" }, { market_id: "CMFD_USDT", last_price: "0.010524", base_volume: "102718.658" }];
    const upstream = vi.fn().mockImplementation(async () => Response.json(markets));
    vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(new Request("https://explorer.test/api/price"), environment());
    expect(response.status).toBe(200);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=60");
    expect(await response.json()).toEqual({ market: "CMFD_USDT", exchange: "TidoEx", last_price: "0.010524", quote_currency: "USDT" });
    const [url, options] = upstream.mock.calls[0];
    expect(String(url)).toBe("https://tidoex.com/api/v2/markets?market_id=CMFD_USDT");
    expect(options.redirect).toBe("manual");
  });

  it.each([
    ["no CMFD market", () => Response.json([{ market_id: "BTC_USDT", last_price: "82160.04" }])],
    ["a zero price", () => Response.json([{ market_id: "CMFD_USDT", last_price: "0" }])],
    ["a non-decimal price", () => Response.json([{ market_id: "CMFD_USDT", last_price: "1e-2" }])],
    ["an error status", () => new Response("down", { status: 502 })],
    ["a non-JSON body", () => new Response("<html>")],
  ])("reports no price for %s", async (_, reply) => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => reply()));
    const response = await worker.fetch(new Request("https://explorer.test/api/price"), environment());
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "price_unavailable" });
  });

  it("serves no market price off mainnet", async () => {
    const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
    expect((await worker.fetch(new Request("https://explorer.test/api/price"), environment({ EXPLORER_NETWORK: "rc" }))).status).toBe(404);
    expect((await worker.fetch(new Request("https://explorer.test/api/price", { method: "POST" }), environment())).status).toBe(405);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("counts the fees burned as the scheduled mint minus the supply", async () => {
    const snapshot = { accepted_height: 5081, tip: "cd".repeat(32), total_supply_atoms: "253628466998978" };
    vi.stubGlobal("fetch", origin(snapshot));
    const json = await worker.fetch(new Request("https://explorer.test/api/supply"), environment());
    expect(await json.json()).toMatchObject({ height: 5081, burned_fees: "1759.90000000", burned_fees_atoms: "175990000000" });
    // A supply above the scheduled mint is inconsistent; report no burn rather than a negative one.
    vi.stubGlobal("fetch", origin({ ...snapshot, total_supply_atoms: "253804456998979" }));
    const inconsistent = await worker.fetch(new Request("https://explorer.test/api/supply"), environment());
    expect(await inconsistent.json()).toMatchObject({ total_supply_atoms: "253804456998979", burned_fees: null, burned_fees_atoms: null });
  });

  it("sums the plan's emission schedule exactly at every height", () => {
    const plan = JSON.parse(readFileSync(new URL("../../../packaging/mainnet/MAINNET-PLAN.json", import.meta.url), "utf8"));
    const policy = plan.payload.rules.monetary_policy;
    const initial = BigInt(policy.initial_subsidy_atoms);
    const tailHeight = BigInt(policy.tail_height);
    const emissionBlocks = tailHeight - 1n;
    const checkpoints = new Set([1n, 2n, 3n, 4880n, 5081n, 1_000_003n, emissionBlocks - 1n, emissionBlocks, tailHeight, tailHeight + 9n]);
    expect(mintedAtoms(0n)).toBe(0n);
    let minted = 0n;
    for (let height = 1n; height <= tailHeight + 9n; height += 1n) {
      minted += height >= tailHeight ? BigInt(policy.tail_subsidy_atoms) : initial * (emissionBlocks - (height - 1n)) / emissionBlocks;
      if (checkpoints.has(height)) expect(mintedAtoms(height)).toBe(minted);
    }
    expect(mintedAtoms(4880n)).toBe(243_773_501_519_624n);
    expect(mintedAtoms(5081n)).toBe(253_804_456_998_978n);
  });

  it("refuses supply from an unidentified or older node", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json({ accepted_height: 1, tip: "ab".repeat(32) }, {
      headers: { [NETWORK_HEADER]: MAINNET_NETWORK_ID },
    })));
    const missing = await worker.fetch(new Request("https://explorer.test/api/supply/total"), environment());
    expect(missing.status).toBe(503);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json({ total_supply_atoms: "1" })));
    expect((await worker.fetch(new Request("https://explorer.test/api/supply"), environment())).status).toBe(503);
    expect((await worker.fetch(new Request("https://explorer.test/api/supply", { method: "POST" }), environment())).status).toBe(405);
  });

  it("does not proxy static routes to the node", async () => {
    const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(new Request("https://explorer.test/"), environment());
    expect(await response.text()).toBe("static explorer");
    expect(upstream).not.toHaveBeenCalled();
  });
});
