const SNAPSHOT_PATH = "/v1/explorer";
const BLOCK_PATH = /^\/v1\/explorer\/block\/(?:[0-9]+|[0-9a-fA-F]{64})$/;
const TRANSACTION_PATH = /^\/v1\/explorer\/transaction\/[0-9a-fA-F]{64}$/;

export function isExplorerApiPath(pathname: string): boolean {
  return pathname === SNAPSHOT_PATH || BLOCK_PATH.test(pathname) || TRANSACTION_PATH.test(pathname);
}

function withSecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set(
    "Content-Security-Policy",
    "default-src 'self'; connect-src 'self'; font-src 'self' data:; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  );
  headers.set("Permissions-Policy", "camera=(), geolocation=(), microphone=()");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");

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

  const upstreamUrl = new URL(requestUrl.pathname, env.EXPLORER_ORIGIN);
  try {
    const upstream = await fetch(upstreamUrl, {
      headers: { Accept: "application/json" },
      method: "GET",
      redirect: "manual",
    });
    if (upstream.status >= 300 && upstream.status < 400) {
      return Response.json(
        { error: "explorer_origin_redirect_rejected" },
        { status: 502, headers: { "Cache-Control": "no-store" } },
      );
    }
    const headers = new Headers();
    headers.set("Cache-Control", "no-store");
    headers.set("Content-Type", upstream.headers.get("Content-Type") ?? "application/json");
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers,
    });
  } catch (error) {
    console.error({
      error: error instanceof Error ? error.message : String(error),
      message: "explorer_origin_unavailable",
      path: requestUrl.pathname,
    });
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
