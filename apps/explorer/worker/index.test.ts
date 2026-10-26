// @vitest-environment node
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker, { formatCmfd, FUND_ADDRESSES, isExplorerApiPath, mintedAtoms, parseRichList, SECURITY_HEADERS } from "./index";
import { MAINNET_NETWORK_ID, NETWORK_HEADER } from "../shared/network";

function environment(overrides: Partial<Env> = {}): Env {
  return {
    ASSETS: { fetch: async () => new Response("static explorer"), connect: () => { throw new Error("unused asset connect"); } },
    EXPLORER_ORIGIN: "https://mainnet-explorer-origin.commonfoundry.ai",
    EXPLORER_PROOF_ORIGIN: "https://mainnet-proof-origin.commonfoundry.ai",
    EXPLORER_PROOF_BACKUP_ORIGIN: "https://mainnet-proof-backup-origin.commonfoundry.ai",
    EXPLORER_UTXO_LIMIT: { limit: async () => ({ success: true }) } as unknown as Env["EXPLORER_UTXO_LIMIT"],
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
    expect(yaml).toContain("service: http://127.0.0.1:29456");
    const proofRule = /hostname: mainnet-proof-origin\.commonfoundry\.ai\s+path: '([^']+)'\s+service: http:\/\/127\.0\.0\.1:29457/m.exec(yaml);
    expect(proofRule).not.toBeNull();
    const proofPath = new RegExp(proofRule![1]);
    expect(proofPath.test(`/v1/explorer/utxo/${"ab".repeat(32)}/0`)).toBe(true);
    expect(proofPath.test(`/v1/explorer/utxo/${"ab".repeat(32)}/01`)).toBe(false);
    expect(proofPath.test("/v1/status")).toBe(false);
    const backupRule = /hostname: mainnet-proof-backup-origin\.commonfoundry\.ai\s+path: '([^']+)'\s+service: http:\/\/127\.0\.0\.1:29458/m.exec(yaml);
    expect(backupRule).not.toBeNull();
    expect(new RegExp(backupRule![1]).test("/v1/explorer/utxo/" + "ab".repeat(32) + "/0")).toBe(true);
    expect(yaml.trimEnd().endsWith("- service: http_status:404")).toBe(true);
  });

  it("allows only the bounded read-only explorer routes", () => {
    expect(isExplorerApiPath("/v1/explorer")).toBe(true);
    expect(isExplorerApiPath("/v1/explorer/utxo-backup/" + "01".repeat(32) + "/0")).toBe(true);
    expect(isExplorerApiPath("/v1/explorer/block/42")).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/block/${"ab".repeat(32)}`)).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/transaction/${"01".repeat(32)}`)).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/utxo/${"01".repeat(32)}/0`)).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/utxo/${"01".repeat(32)}/4294967295`)).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/address/${"a1".repeat(32)}`)).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/address/${"a1".repeat(32)}/${"d1".repeat(32)}.81.1`)).toBe(true);
  });

  it("does not expose general node RPC routes", () => {
    expect(isExplorerApiPath("/v1/status")).toBe(false);
    expect(isExplorerApiPath("/v1/explorer/utxo-backup/" + "01".repeat(32) + "/00")).toBe(false);
    expect(isExplorerApiPath("/v1/explorer/block/latest/extra")).toBe(false);
    expect(isExplorerApiPath("/v1/explorer/transaction/not-a-transaction")).toBe(false);
    expect(isExplorerApiPath(`/v1/explorer/utxo/${"01".repeat(32)}/01`)).toBe(false);
    expect(isExplorerApiPath(`/v1/explorer/utxo/${"01".repeat(32)}/4294967296`)).toBe(false);
    expect(isExplorerApiPath(`/v1/explorer/utxo/${"01".repeat(32)}/0/extra`)).toBe(false);
  });
});

describe("mainnet explorer identity gate", () => {
  it("pins configuration to the approved plan and gives the public domain only to mainnet", () => {
    const plan = JSON.parse(readFileSync(new URL("../../../packaging/mainnet/MAINNET-PLAN.json", import.meta.url), "utf8"));
    const config = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
    expect(MAINNET_NETWORK_ID).toBe(plan.network_id);
    expect(config.env.mainnet.vars.EXPLORER_EXPECTED_NETWORK_ID).toBe(MAINNET_NETWORK_ID);
    expect(config.env.mainnet.vars.EXPLORER_PROOF_ORIGIN).toBe("https://mainnet-proof-origin.commonfoundry.ai");
    expect(config.env.mainnet.vars.EXPLORER_PROOF_BACKUP_ORIGIN).toBe("https://mainnet-proof-backup-origin.commonfoundry.ai");
    expect(config.env.mainnet.ratelimits).toEqual([{
      name: "EXPLORER_UTXO_LIMIT", namespace_id: "4104", simple: { limit: 240, period: 60 },
    }]);
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

  it("routes one exact UTXO read only to the independent proof origin", async () => {
    const path = `/v1/explorer/utxo/${"ab".repeat(32)}/0`;
    const data = { network_id: MAINNET_NETWORK_ID, value_atoms: "7", available: true };
    const upstream = vi.fn().mockResolvedValue(Response.json(data, {
      headers: { [NETWORK_HEADER]: MAINNET_NETWORK_ID },
    }));
    vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(new Request("https://explorer.test" + path, {
      headers: { Authorization: "must-not-forward", Cookie: "must-not-forward" },
    }), environment());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(data);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    const [url, options] = upstream.mock.calls[0];
    expect(String(url)).toBe("https://mainnet-proof-origin.commonfoundry.ai" + path);
    expect(options.headers).toEqual({ Accept: "application/json" });
  });

  it("maps the Germany backup route only to its pinned proof origin", async () => {
    const path = "/v1/explorer/utxo-backup/" + "ab".repeat(32) + "/0";
    const canonical = path.replace("/utxo-backup/", "/utxo/");
    const upstream = vi.fn().mockResolvedValue(Response.json({ available: true }, {
      headers: { [NETWORK_HEADER]: MAINNET_NETWORK_ID },
    }));
    vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(new Request("https://explorer.test" + path), environment());
    expect(response.status).toBe(200);
    expect(String(upstream.mock.calls[0][0])).toBe(
      "https://mainnet-proof-backup-origin.commonfoundry.ai" + canonical,
    );
    expect(upstream.mock.calls[0][1].headers).toEqual({ Accept: "application/json" });
  });

  it("passes a network-identified missing outpoint through for the Android readiness probe", async () => {
    const path = `/v1/explorer/utxo/${"00".repeat(32)}/0`;
    const upstream = vi.fn().mockResolvedValue(Response.json({ error: "UTXO not found" }, {
      status: 404,
      headers: { [NETWORK_HEADER]: MAINNET_NETWORK_ID },
    }));
    vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(new Request("https://explorer.test" + path), environment());
    expect(response.status).toBe(404);
    expect(response.headers.get(NETWORK_HEADER)).toBe(MAINNET_NETWORK_ID);
    expect(String(upstream.mock.calls[0][0])).toBe("https://mainnet-proof-origin.commonfoundry.ai" + path);
  });

  it.each(["http://untrusted.example", "https://mainnet-explorer-origin.commonfoundry.ai"])(
    "rejects an unsafe or non-independent proof origin %s before any UTXO request", async (proofOrigin) => {
    const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
    const path = `/v1/explorer/utxo/${"ab".repeat(32)}/0`;
    const response = await worker.fetch(new Request("https://explorer.test" + path),
      environment({ EXPLORER_PROOF_ORIGIN: proofOrigin }));
    expect(response.status).toBe(503);
    expect(upstream).not.toHaveBeenCalled();
    },
  );

  it("rejects a backup proof origin that points at the Singapore-backed router", async () => {
    const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
    const path = "/v1/explorer/utxo-backup/" + "ab".repeat(32) + "/0";
    const response = await worker.fetch(new Request("https://explorer.test" + path),
      environment({ EXPLORER_PROOF_BACKUP_ORIGIN: "https://mainnet-explorer-origin.commonfoundry.ai" }));
    expect(response.status).toBe(503);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("rate-limits UTXO reads before contacting the proof origin", async () => {
    const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
    const path = `/v1/explorer/utxo/${"ab".repeat(32)}/0`;
    const response = await worker.fetch(new Request("https://explorer.test" + path),
      environment({ EXPLORER_UTXO_LIMIT: { limit: async () => ({ success: false }) } as unknown as Env["EXPLORER_UTXO_LIMIT"] }));
    expect(response.status).toBe(429);
    expect(await response.json()).toEqual({ error: "rate_limited" });
    expect(upstream).not.toHaveBeenCalled();
  });

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
      const address = /\/v1\/explorer\/address\/([0-9a-f]{64})\//.exec(String(url))?.[1];
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
      // Cursors at block 1's coinbase: no history page, so the node reads no blocks.
      `https://mainnet-explorer-origin.commonfoundry.ai/v1/explorer/address/${FUND_ADDRESSES[0].address}/${tip}.1.0`,
      `https://mainnet-explorer-origin.commonfoundry.ai/v1/explorer/address/${FUND_ADDRESSES[1].address}/${tip}.1.0`,
    ]);
  });

  it("restarts from the snapshot when a block lands before the fund reads", async () => {
    const stale = { code: "explorer_cursor_stale", error: "the chain tip changed", retryable: true };
    const tips = ["ab".repeat(32), "cd".repeat(32)];
    let round = 0;
    const upstream = vi.fn().mockImplementation(async (url: URL) => {
      const headers = { [NETWORK_HEADER]: MAINNET_NETWORK_ID };
      if (String(url).endsWith("/v1/explorer")) {
        round += 1;
        return Response.json({ accepted_height: 4720 + round, tip: tips[round - 1], total_supply_atoms: "300" }, { headers });
      }
      // The first snapshot's tip is already stale when the fund views arrive.
      return round === 1 ? Response.json(stale, { status: 409, headers }) : Response.json({ tip: tips[1], confirmed_atoms: "100" }, { headers });
    });
    vi.stubGlobal("fetch", upstream);
    const circulating = await worker.fetch(new Request("https://explorer.test/api/supply/circulating"), environment());
    expect(await circulating.text()).toBe("0.00000100");
    expect(upstream).toHaveBeenCalledTimes(6);
    expect(String(upstream.mock.calls[5][0])).toBe(`https://mainnet-explorer-origin.commonfoundry.ai/v1/explorer/address/${FUND_ADDRESSES[1].address}/${tips[1]}.1.0`);
    // A tip that keeps moving, or a fund view at another tip, is not published.
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (url: URL) => String(url).endsWith("/v1/explorer")
      ? Response.json({ accepted_height: 4721, tip: tips[0], total_supply_atoms: "300" }, { headers: { [NETWORK_HEADER]: MAINNET_NETWORK_ID } })
      : Response.json(stale, { status: 409, headers: { [NETWORK_HEADER]: MAINNET_NETWORK_ID } })));
    const moving = await worker.fetch(new Request("https://explorer.test/api/supply"), environment());
    expect(moving.status).toBe(503);
    expect(await moving.json()).toEqual({ error: "supply_unavailable" });
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (url: URL) => Response.json(
      String(url).endsWith("/v1/explorer")
        ? { accepted_height: 4721, tip: tips[0], total_supply_atoms: "300" }
        : { tip: tips[1], confirmed_atoms: "100" },
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

describe("rich list", () => {
  const other = "ab".repeat(32);
  const list = (overrides: Record<string, unknown> = {}) => ({
    schema: "CMFD_RICHLIST_V1", height: 14800, block_hash: "cd".repeat(32), generated_at: 1791900000,
    total_supply_atoms: "737100000000000", unspent_outputs: 70300, addresses_with_balance: 4321, unkeyed_atoms: "0",
    verified_against_node: true,
    top: [
      { rank: 1, address: FUND_ADDRESSES[0].address, balance_atoms: "150000000000000", outputs: 14800 },
      { rank: 2, address: other, balance_atoms: "900000000", outputs: 3 },
    ],
    ...overrides,
  });

  it("serves the checked list with the fund labels", async () => {
    const upstream = vi.fn().mockImplementation(async () => Response.json(list()));
    vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(new Request("https://explorer.test/api/richlist"), environment());
    expect(response.status).toBe(200);
    expect(response.headers.get(NETWORK_HEADER)).toBe(MAINNET_NETWORK_ID);
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=60");
    const body = await response.json() as { top: Record<string, unknown>[]; height: number; total_supply: string };
    expect(body.height).toBe(14800);
    expect(body.total_supply).toBe("7371000.00000000");
    expect(body.top[0]).toEqual({ rank: 1, address: FUND_ADDRESSES[0].address, balance_atoms: "150000000000000", outputs: 14800,
      label: "steward fund", balance: "1500000.00000000" });
    expect(body.top[1].label).toBeNull();
    const [url, options] = upstream.mock.calls[0];
    expect(String(url)).toBe("https://sg-rpc.commonfoundry.ai/stats/richlist.json");
    expect(options.redirect).toBe("manual");
  });

  it("refuses lists that were not checked against the node or are malformed", () => {
    expect(parseRichList(list())).not.toBeNull();
    expect(parseRichList(list({ verified_against_node: false }))).toBeNull();
    expect(parseRichList(list({ schema: "CMFD_RICHLIST_V2" }))).toBeNull();
    expect(parseRichList(list({ top: [{ rank: 2, address: other, balance_atoms: "1", outputs: 1 }] }))).toBeNull();
    expect(parseRichList(list({ top: [{ rank: 1, address: other.toUpperCase(), balance_atoms: "1", outputs: 1 }] }))).toBeNull();
    expect(parseRichList(list({ top: [{ rank: 1, address: other, balance_atoms: "01", outputs: 1 }] }))).toBeNull();
    expect(parseRichList(list({ top: [{ rank: 1, address: other, balance_atoms: "1", outputs: 0 }] }))).toBeNull();
    expect(parseRichList(list({ total_supply_atoms: 5 }))).toBeNull();
    expect(parseRichList([])).toBeNull();
  });

  it("answers 503 for a bad or missing list, and only on mainnet", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async () => Response.json(list({ verified_against_node: false }))));
    const unchecked = await worker.fetch(new Request("https://explorer.test/api/richlist"), environment());
    expect(unchecked.status).toBe(503);
    expect(unchecked.headers.get(NETWORK_HEADER)).toBe(MAINNET_NETWORK_ID);
    expect(await unchecked.json()).toEqual({ error: "richlist_unavailable" });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("not found", { status: 404 })));
    expect((await worker.fetch(new Request("https://explorer.test/api/richlist"), environment())).status).toBe(503);
    const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
    const rc = await worker.fetch(new Request("https://explorer.test/api/richlist"), environment({ EXPLORER_NETWORK: "rc", EXPLORER_EXPECTED_NETWORK_ID: "" }));
    expect(rc.status).toBe(404);
    expect((await worker.fetch(new Request("https://explorer.test/api/richlist", { method: "POST" }), environment())).status).toBe(405);
    expect(upstream).not.toHaveBeenCalled();
  });
});
