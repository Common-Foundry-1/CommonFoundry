export const markdownRoutes = Object.freeze({
  "/": "home.md",
  "/learn/": "learn.md",
  "/learn/mining/": "mining.md",
  "/learn/forgematrix/": "forgematrix.md",
  "/learn/gpu-renting/": "gpu-renting.md",
  "/docs/api/": "api.md",
  "/docs/whitepaper/": "whitepaper.md",
  "/docs/mcp/": "mcp.md",
});

export function prefersMarkdown(accept = "") {
  const choices = new Map();
  for (const entry of accept.toLowerCase().split(",")) {
    const [type, ...parameters] = entry.trim().split(";");
    const quality = parameters.find((p) => p.trim().startsWith("q="));
    const q = quality === undefined ? 1 : Number(quality.trim().slice(2));
    choices.set(type.trim(), Number.isFinite(q) && q >= 0 && q <= 1 ? q : 0);
  }
  const markdown = choices.get("text/markdown") ?? 0;
  const html = choices.get("text/html") ?? choices.get("text/*") ?? choices.get("*/*") ?? 0;
  return markdown > 0 && markdown >= html;
}

function withVary(response, method) {
  const headers = new Headers(response.headers);
  const vary = headers.get("Vary");
  if (!vary) headers.set("Vary", "Accept");
  else if (vary !== "*" && !vary.split(",").some((v) => v.trim().toLowerCase() === "accept")) {
    headers.set("Vary", `${vary}, Accept`);
  }
  return new Response(method === "HEAD" ? null : response.body, { status: response.status, statusText: response.statusText, headers });
}

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  if (!Object.hasOwn(markdownRoutes, url.pathname) || !["GET", "HEAD"].includes(request.method)) {
    return context.next();
  }
  if (prefersMarkdown(request.headers.get("Accept") ?? "")) {
    const assetUrl = new URL(`/agent-text/${markdownRoutes[url.pathname]}`, url.origin);
    const asset = await context.env.ASSETS.fetch(new Request(assetUrl, { method: request.method }));
    if (asset.status === 200) {
      const headers = new Headers(asset.headers);
      headers.set("Content-Type", "text/markdown; charset=utf-8");
      headers.set("Content-Location", assetUrl.pathname);
      return withVary(new Response(asset.body, { status: 200, headers }), request.method);
    }
  }
  return withVary(await context.next(), request.method);
}
