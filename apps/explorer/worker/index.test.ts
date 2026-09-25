// @vitest-environment node
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker, { isExplorerApiPath } from "./index";
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

describe("explorer edge API allowlist", () => {
  it("allows only the bounded read-only explorer routes", () => {
    expect(isExplorerApiPath("/v1/explorer")).toBe(true);
    expect(isExplorerApiPath("/v1/explorer/block/42")).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/block/${"ab".repeat(32)}`)).toBe(true);
    expect(isExplorerApiPath(`/v1/explorer/transaction/${"01".repeat(32)}`)).toBe(true);
  });

  it("does not expose general node RPC routes", () => {
    expect(isExplorerApiPath("/v1/status")).toBe(false);
    expect(isExplorerApiPath("/v1/explorer/block/latest/extra")).toBe(false);
    expect(isExplorerApiPath("/v1/explorer/transaction/not-a-transaction")).toBe(false);
  });
});

describe("mainnet explorer identity gate", () => {
  it("pins configuration to the approved plan without taking the live domain", () => {
    const plan = JSON.parse(readFileSync(new URL("../../../packaging/mainnet/MAINNET-PLAN.json", import.meta.url), "utf8"));
    const config = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
    expect(MAINNET_NETWORK_ID).toBe(plan.network_id);
    expect(config.env.mainnet.vars.EXPLORER_EXPECTED_NETWORK_ID).toBe(MAINNET_NETWORK_ID);
    expect(config.env.mainnet.routes).toEqual([]);
    expect(config.env.mainnet.workers_dev).toBe(false);
    expect(config.env.mainnet.preview_urls).toBe(false);
    expect(config.routes[0].pattern).toBe("explorer.commonfoundry.ai");
  });

  it.each(["/v1/explorer", "/v1/explorer/block/42", `/v1/explorer/transaction/${"ab".repeat(32)}`])(
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

  it("does not proxy static routes to the node", async () => {
    const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(new Request("https://explorer.test/"), environment());
    expect(await response.text()).toBe("static explorer");
    expect(upstream).not.toHaveBeenCalled();
  });
});
