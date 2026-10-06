import { MAINNET_NETWORK_ID, NETWORK_HEADER } from "../shared/network";
import { isAddressApiPath } from "../shared/address";

const SNAPSHOT_PATH = "/v1/explorer";
const SUPPLY_PATH = "/api/supply";
const SUPPLY_TOTAL_PATH = "/api/supply/total";
const SUPPLY_CIRCULATING_PATH = "/api/supply/circulating";
const ATOMS_PER_CMFD = 100_000_000n;
const BLOCK_PATH = /^\/v1\/explorer\/block\/(?:[0-9]+|[0-9a-fA-F]{64})$/;
const TRANSACTION_PATH = /^\/v1\/explorer\/transaction\/[0-9a-fA-F]{64}$/;

export function isExplorerApiPath(pathname: string): boolean {
  return pathname === SNAPSHOT_PATH || BLOCK_PATH.test(pathname) || TRANSACTION_PATH.test(pathname) || isAddressApiPath(pathname);
}

// Cloudflare Web Analytics loads from static.cloudflareinsights.com and reports to cloudflareinsights.com.
function contentSecurityPolicy(nonce?: string): string {
  const scripts = ["'self'", ...(nonce ? [`'nonce-${nonce}'`] : []), "https://static.cloudflareinsights.com"].join(" ");
  return `default-src 'self'; connect-src 'self' https://cloudflareinsights.com; font-src 'self' data:; img-src 'self' data:; object-src 'none'; script-src ${scripts}; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
}

// /assets/* bypasses the Worker (see run_worker_first), so public/_headers repeats these.
export const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": contentSecurityPolicy(),
  "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

function withSecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  if (headers.get("Content-Type")?.startsWith("text/html")) {
    // Cloudflare copies this per-request nonce onto the bot-detection and analytics scripts it injects.
    headers.set("Content-Security-Policy", contentSecurityPolicy(crypto.randomUUID().replace(/-/g, "")));
    headers.set("Cache-Control", "no-store");
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function proxyExplorerRequest(request: Request, env: Env): Promise<Response> {
  const requestUrl = new URL(request.url);
  if (request.method !== "GET") {
    return Response.json({ error: "method_not_allowed" }, { status: 405, headers: { Allow: "GET" } });
  }
  if (requestUrl.search || !isExplorerApiPath(requestUrl.pathname)) {
    return Response.json({ error: "not_found" }, { status: 404 });
  }

  const mainnet = env.EXPLORER_NETWORK === "mainnet";
  if ((env.EXPLORER_NETWORK !== "rc" && !mainnet)
      || (mainnet && env.EXPLORER_EXPECTED_NETWORK_ID !== MAINNET_NETWORK_ID)) {
    return Response.json({ error: "explorer_configuration_invalid" }, {
      status: 503, headers: { "Cache-Control": "no-store" },
    });
  }
  try {
    const origin = new URL(env.EXPLORER_ORIGIN);
    const localHttp = origin.protocol === "http:"
      && ["127.0.0.1", "localhost", "[::1]"].includes(origin.hostname);
    if ((!localHttp && origin.protocol !== "https:") || origin.username || origin.password
        || origin.pathname !== "/" || origin.search || origin.hash) {
      return Response.json({ error: "explorer_configuration_invalid" }, {
        status: 503, headers: { "Cache-Control": "no-store" },
      });
    }
    const upstreamUrl = new URL(requestUrl.pathname, origin);
    const upstream = await fetch(upstreamUrl, {
      headers: { Accept: "application/json" },
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
    if (upstream.status >= 300 && upstream.status < 400) {
      await upstream.body?.cancel();
      return Response.json(
        { error: "explorer_origin_redirect_rejected" },
        { status: 502, headers: { "Cache-Control": "no-store" } },
      );
    }
    if (mainnet && upstream.headers.get(NETWORK_HEADER) !== MAINNET_NETWORK_ID) {
      await upstream.body?.cancel();
      return Response.json({ error: "explorer_network_identity_rejected" }, {
        status: 503, headers: { "Cache-Control": "no-store" },
      });
    }
    if (upstream.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
      await upstream.body?.cancel();
      return Response.json({ error: "explorer_origin_invalid_response" }, {
        status: 502, headers: { "Cache-Control": "no-store" },
      });
    }
    const headers = new Headers();
    headers.set("Cache-Control", "no-store");
    headers.set("Content-Type", upstream.headers.get("Content-Type") ?? "application/json");
    const networkId = upstream.headers.get(NETWORK_HEADER);
    if (networkId) headers.set(NETWORK_HEADER, networkId);
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers,
    });
  } catch (error) {
    console.error(JSON.stringify({
      error: error instanceof Error ? error.name : "UnknownError",
      message: "explorer_origin_unavailable",
      path: requestUrl.pathname,
    }));
    return Response.json(
      { error: "explorer_origin_unavailable" },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }
}

/** Atoms as a CMFD decimal with exactly eight places. */
export function formatCmfd(atoms: string): string {
  const value = BigInt(atoms);
  return `${value / ATOMS_PER_CMFD}.${(value % ATOMS_PER_CMFD).toString().padStart(8, "0")}`;
}

/**
 * Public supply endpoints for exchanges and listing sites, read from the
 * node's checked explorer snapshot: `/api/supply` (JSON),
 * `/api/supply/total` and `/api/supply/circulating` (plain numbers).
 * Circulating supply equals total supply: the steward and community fund
 * allocations circulate like any other coins.
 */
async function supplyResponse(request: Request, env: Env, pathname: string): Promise<Response> {
  if (request.method !== "GET") {
    return Response.json({ error: "method_not_allowed" }, { status: 405, headers: { Allow: "GET" } });
  }
  const upstream = await proxyExplorerRequest(new Request(new URL(SNAPSHOT_PATH, request.url)), env);
  if (!upstream.ok) return upstream;
  const snapshot: unknown = await upstream.json().catch(() => null);
  const fields = typeof snapshot === "object" && snapshot !== null ? snapshot as Record<string, unknown> : {};
  const atoms = fields.total_supply_atoms;
  if (typeof atoms !== "string" || !/^(0|[1-9][0-9]{0,30})$/.test(atoms)
      || !Number.isSafeInteger(fields.accepted_height) || typeof fields.tip !== "string") {
    return Response.json({ error: "supply_unavailable" }, { status: 503, headers: { "Cache-Control": "no-store" } });
  }
  const headers = { "Cache-Control": "public, max-age=30", "Access-Control-Allow-Origin": "*" };
  if (pathname === SUPPLY_TOTAL_PATH || pathname === SUPPLY_CIRCULATING_PATH) {
    return new Response(formatCmfd(atoms), { headers: { ...headers, "Content-Type": "text/plain; charset=utf-8" } });
  }
  return Response.json({
    network: env.EXPLORER_NETWORK,
    height: fields.accepted_height,
    tip: fields.tip,
    total_supply: formatCmfd(atoms),
    total_supply_atoms: atoms,
    circulating_supply: formatCmfd(atoms),
    circulating_supply_atoms: atoms,
    max_supply: null,
    definition: "Value of every unspent output: all CMFD minted so far minus burned fees. Circulating supply equals total supply, including the steward and community fund allocations. Emission ends in a permanent tail, so there is no maximum supply.",
  }, { headers });
}

// Always fetch the full page: a 304 would pair a cached page with a fresh nonce.
function fetchAsset(request: Request, env: Env): Promise<Response> {
  const headers = new Headers(request.headers);
  headers.delete("If-None-Match");
  headers.delete("If-Modified-Since");
  return env.ASSETS.fetch(new Request(request, { headers }));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const response = url.pathname.startsWith("/v1/")
      ? await proxyExplorerRequest(request, env)
      : url.pathname === SUPPLY_PATH || url.pathname === SUPPLY_TOTAL_PATH || url.pathname === SUPPLY_CIRCULATING_PATH
        ? await supplyResponse(request, env, url.pathname)
        : await fetchAsset(request, env);
    return withSecurityHeaders(response);
  },
} satisfies ExportedHandler<Env>;
