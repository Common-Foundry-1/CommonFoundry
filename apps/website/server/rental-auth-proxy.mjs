const METADATA = new Set([
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-protected-resource",
  "/.well-known/oauth-protected-resource/rent/mcp",
]);
function unavailable(status, error) {
  return Response.json({ error }, { status, headers: {
    "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
  } });
}
export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  if (!context.env.RENTAL_AUTH) return unavailable(503, "marketplace_auth_unavailable");
  if (url.origin !== "https://commonfoundry.ai" || request.headers.get("Host") !== url.host) return unavailable(400, "invalid_host");
  if (!(url.pathname === "/rent/mcp" || url.pathname.startsWith("/rent/auth/") || METADATA.has(url.pathname))) {
    return unavailable(404, "not_found");
  }
  if (!["GET", "HEAD", "POST", "OPTIONS"].includes(request.method)) return unavailable(405, "unsupported_method");
  const headers = new Headers(request.headers);
  headers.set("Host", url.host);
  if (url.pathname === "/.well-known/oauth-protected-resource") url.pathname += "/rent/mcp";
  const metadataHead = request.method === "HEAD" && METADATA.has(new URL(request.url).pathname);
  const forwarded = new Request(url, { method: metadataHead ? "GET" : request.method, headers,
    body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body, redirect: "manual", duplex: "half" });
  try {
    const response = await context.env.RENTAL_AUTH.fetch(forwarded);
    const protectedHeaders = new Headers(response.headers);
    protectedHeaders.set("Cache-Control", "no-store");
    protectedHeaders.set("X-Content-Type-Options", "nosniff");
    protectedHeaders.set("Referrer-Policy", "no-referrer");
    return new Response(request.method === "HEAD" ? null : response.body, { status: response.status, headers: protectedHeaders });
  } catch { return unavailable(503, "marketplace_auth_unavailable"); }
}
