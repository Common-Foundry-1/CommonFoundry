import { MAINNET_NETWORK_ID, NETWORK_HEADER } from "../shared/network";
import { isAddressApiPath } from "../shared/address";

const SNAPSHOT_PATH = "/v1/explorer";
const BLOCK_PATH = /^\/v1\/explorer\/block\/(?:[0-9]+|[0-9a-fA-F]{64})$/;
const TRANSACTION_PATH = /^\/v1\/explorer\/transaction\/[0-9a-fA-F]{64}$/;

export function isExplorerApiPath(pathname: string): boolean {
  return pathname === SNAPSHOT_PATH || BLOCK_PATH.test(pathname) || TRANSACTION_PATH.test(pathname) || isAddressApiPath(pathname);
}

// Static assets bypass the Worker (run_worker_first is /v1/* only), so public/_headers repeats these.
export const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy":
    "default-src 'self'; connect-src 'self'; font-src 'self' data:; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

function withSecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);

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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const response = url.pathname.startsWith("/v1/")
      ? await proxyExplorerRequest(request, env)
      : await env.ASSETS.fetch(request);
    return withSecurityHeaders(response);
  },
} satisfies ExportedHandler<Env>;
