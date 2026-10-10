import { MAINNET_NETWORK_ID, NETWORK_HEADER } from "../shared/network";
import { isAddressApiPath } from "../shared/address";

const SNAPSHOT_PATH = "/v1/explorer";
const SUPPLY_PATH = "/api/supply";
const SUPPLY_TOTAL_PATH = "/api/supply/total";
const SUPPLY_CIRCULATING_PATH = "/api/supply/circulating";
const PRICE_PATH = "/api/price";
const PRICE_FEED_URL = "https://tidoex.com/api/v2/markets?market_id=CMFD_USDT";
const ATOMS_PER_CMFD = 100_000_000n;
const ATOMS_PATTERN = /^(0|[1-9][0-9]{0,30})$/;
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

// Mainnet monetary policy; tests pin these to packaging/mainnet/MAINNET-PLAN.json.
const INITIAL_SUBSIDY_ATOMS = 50_000_000_000n;
const TAIL_HEIGHT = 2_628_001n;
const TAIL_SUBSIDY_ATOMS = 500_000_000n;

/** Sum of floor((a * i + b) / m) for i in [0, n), exact (the standard floor-sum reduction). */
function floorSum(n: bigint, m: bigint, a: bigint, b: bigint): bigint {
  let total = 0n;
  for (;;) {
    if (a >= m) {
      total += (n * (n - 1n) / 2n) * (a / m);
      a %= m;
    }
    if (b >= m) {
      total += n * (b / m);
      b %= m;
    }
    const yMax = a * n + b;
    if (yMax < m) return total;
    [n, b, m, a] = [yMax / m, yMax % m, a, m];
  }
}

/**
 * Atoms the consensus emission schedule has created in blocks 1..height.
 * Block h pays floor(initial * (E - h + 1) / E) for h <= E, then the tail.
 */
export function mintedAtoms(height: bigint): bigint {
  const emissionBlocks = TAIL_HEIGHT - 1n;
  const declining = height < emissionBlocks ? height : emissionBlocks;
  const decliningSum = floorSum(declining, emissionBlocks, INITIAL_SUBSIDY_ATOMS,
    INITIAL_SUBSIDY_ATOMS * (emissionBlocks - declining + 1n));
  return decliningSum + (height > emissionBlocks ? (height - emissionBlocks) * TAIL_SUBSIDY_ATOMS : 0n);
}

// Mainnet reward destinations (25% and 5% of every block); tests pin these to packaging/mainnet/MAINNET-PLAN.json.
export const FUND_ADDRESSES = [
  { label: "steward", address: "5321229f3d3e3fccb900f95c7baee2b27a929afe70f95a0bde0394dba79c9684" },
  { label: "community", address: "fbe36f76cad922c1c911d8cecc2eed21c853d10fb99e450fc14ac7e54bf59a3f" },
] as const;

async function explorerView(path: string, request: Request, env: Env): Promise<Record<string, unknown> | Response> {
  const upstream = await proxyExplorerRequest(new Request(new URL(path, request.url)), env);
  if (!upstream.ok) return upstream;
  const body: unknown = await upstream.json().catch(() => null);
  return typeof body === "object" && body !== null ? body as Record<string, unknown> : {};
}

/**
 * Public supply endpoints for exchanges and listing sites, read from the
 * node's checked explorer snapshot: `/api/supply` (JSON),
 * `/api/supply/total` and `/api/supply/circulating` (plain numbers).
 * Circulating supply is the total minus what the steward and community fund
 * addresses hold, read at the same tip as the snapshot. Coinbases claim
 * exactly the scheduled subsidy and every transaction fee is destroyed, so
 * the fees burned so far are the minted total minus the current supply.
 */
async function supplyResponse(request: Request, env: Env, pathname: string): Promise<Response> {
  if (request.method !== "GET") {
    return Response.json({ error: "method_not_allowed" }, { status: 405, headers: { Allow: "GET" } });
  }
  const unavailable = () => Response.json({ error: "supply_unavailable" }, { status: 503, headers: { "Cache-Control": "no-store" } });
  for (let attempt = 1; ; attempt += 1) {
    const fields = await explorerView(SNAPSHOT_PATH, request, env);
    if (fields instanceof Response) return fields;
    const atoms = fields.total_supply_atoms;
    if (typeof atoms !== "string" || !ATOMS_PATTERN.test(atoms)
        || !Number.isSafeInteger(fields.accepted_height) || typeof fields.tip !== "string" || !/^[0-9a-f]{64}$/.test(fields.tip)) {
      return unavailable();
    }
    // The funds are paid in every block, so a first history page would read 20 full blocks.
    // A cursor at their first payment (block 1's coinbase) leaves the page empty, and its
    // tip makes the node answer at the snapshot's tip or reject the cursor as stale.
    const views = pathname === SUPPLY_TOTAL_PATH ? [] : await Promise.all(FUND_ADDRESSES.map((fund) =>
      explorerView(`/v1/explorer/address/${fund.address}/${fields.tip}.1.0`, request, env)));
    const failed = views.find((view) => view instanceof Response);
    if (failed?.status === 409) {
      if (attempt < 3) continue;
      return unavailable();
    }
    if (failed) return failed;
    const funds = views as Record<string, unknown>[];
    if (funds.some((fund) => fund.tip !== fields.tip
        || typeof fund.confirmed_atoms !== "string" || !ATOMS_PATTERN.test(fund.confirmed_atoms))) {
      return unavailable();
    }
    const fundAtoms = funds.map((fund) => fund.confirmed_atoms as string);
    const circulating = (BigInt(atoms) - fundAtoms.reduce((sum, value) => sum + BigInt(value), 0n)).toString();
    const headers = { "Cache-Control": "public, max-age=30", "Access-Control-Allow-Origin": "*" };
    if (pathname === SUPPLY_TOTAL_PATH || pathname === SUPPLY_CIRCULATING_PATH) {
      const value = pathname === SUPPLY_TOTAL_PATH ? atoms : circulating;
      return new Response(formatCmfd(value), { headers: { ...headers, "Content-Type": "text/plain; charset=utf-8" } });
    }
    const burned = mintedAtoms(BigInt(fields.accepted_height as number)) - BigInt(atoms);
    return Response.json({
      network: env.EXPLORER_NETWORK,
      height: fields.accepted_height,
      tip: fields.tip,
      total_supply: formatCmfd(atoms),
      total_supply_atoms: atoms,
      circulating_supply: formatCmfd(circulating),
      circulating_supply_atoms: circulating,
      excluded_from_circulating: FUND_ADDRESSES.map((fund, index) => ({
        label: fund.label,
        address: fund.address,
        balance: formatCmfd(fundAtoms[index]),
        balance_atoms: fundAtoms[index],
      })),
      max_supply: null,
      burned_fees: burned >= 0n ? formatCmfd(burned.toString()) : null,
      burned_fees_atoms: burned >= 0n ? burned.toString() : null,
      definition: "Total supply is the value of every unspent output: all CMFD minted so far minus burned fees. Circulating supply is the total supply minus the current balances of the steward and community fund addresses, which receive 25% and 5% of every block reward; both are listed in excluded_from_circulating. Emission ends in a permanent tail, so there is no maximum supply. Burned fees are every transaction fee destroyed so far: the CMFD the emission schedule has minted minus the total supply.",
    }, { headers });
  }
}

/** The last CMFD/USDT trade on TidoEx, the only market so far. */
async function priceResponse(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return Response.json({ error: "method_not_allowed" }, { status: 405, headers: { Allow: "GET" } });
  }
  if (env.EXPLORER_NETWORK !== "mainnet") return Response.json({ error: "not_found" }, { status: 404 });
  const unavailable = () => Response.json({ error: "price_unavailable" }, { status: 503, headers: { "Cache-Control": "no-store" } });
  try {
    const upstream = await fetch(PRICE_FEED_URL, {
      headers: { Accept: "application/json" },
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
      cf: { cacheTtl: 60, cacheEverything: true },
    });
    if (!upstream.ok) {
      await upstream.body?.cancel();
      return unavailable();
    }
    const markets: unknown = await upstream.json();
    const market = Array.isArray(markets)
      ? markets.find((entry): entry is Record<string, unknown> =>
        typeof entry === "object" && entry !== null && (entry as Record<string, unknown>).market_id === "CMFD_USDT")
      : undefined;
    const price = market?.last_price;
    if (typeof price !== "string" || !/^(0|[1-9][0-9]{0,15})(\.[0-9]{1,18})?$/.test(price) || !(Number(price) > 0)) {
      return unavailable();
    }
    return Response.json({ market: "CMFD_USDT", exchange: "TidoEx", last_price: price, quote_currency: "USDT" }, {
      headers: { "Cache-Control": "public, max-age=60", "Access-Control-Allow-Origin": "*" },
    });
  } catch {
    return unavailable();
  }
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
        : url.pathname === PRICE_PATH
          ? await priceResponse(request, env)
          : await fetchAsset(request, env);
    return withSecurityHeaders(response);
  },
} satisfies ExportedHandler<Env>;
