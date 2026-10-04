// @vitest-environment node
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker, { isExplorerApiPath, SECURITY_HEADERS } from "./index";
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

  it("invokes the Worker only for API paths and serves static security headers without it", () => {
    const config = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
    expect(config.assets.run_worker_first).toEqual(["/v1/*"]);
    expect(config.env.mainnet.assets.run_worker_first).toEqual(["/v1/*"]);
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

  it("does not proxy static routes to the node", async () => {
    const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(new Request("https://explorer.test/"), environment());
    expect(await response.text()).toBe("static explorer");
    expect(upstream).not.toHaveBeenCalled();
  });
});
