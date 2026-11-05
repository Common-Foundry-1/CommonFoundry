import assert from "node:assert/strict";
import test from "node:test";
import { onRequest } from "../server/rental-auth-proxy.mjs";

function context(path, { method = "GET", enabled = true, host = "commonfoundry.ai", fail = false } = {}) {
  const calls = [];
  return { calls, request: new Request("https://commonfoundry.ai" + path, { method,
    headers: { Host: host, Authorization: "Bearer test-only" }, body: method === "POST" ? "{}" : undefined }),
    env: enabled ? { RENTAL_AUTH: { async fetch(request) {
      calls.push({ url: request.url, method: request.method, authorization: request.headers.get("Authorization") });
      if (fail) throw new Error("unavailable");
      return Response.json({ ok: true }, { headers: { "WWW-Authenticate": 'Bearer resource_metadata="https://commonfoundry.ai/.well-known/oauth-protected-resource/rent/mcp"' } });
    } } } : {} };
}
test("the gateway uses only its private service binding and preserves OAuth requests", async () => {
  const c = context("/rent/auth/oauth/token", { method: "POST" });
  const response = await onRequest(c);
  assert.equal(response.status, 200);
  assert.deepEqual(c.calls, [{ url: "https://commonfoundry.ai/rent/auth/oauth/token", method: "POST", authorization: "Bearer test-only" }]);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
});
test("the root metadata alias names the specific protected rental resource", async () => {
  const c = context("/.well-known/oauth-protected-resource", { method: "HEAD" });
  const response = await onRequest(c);
  assert.equal(c.calls[0].url, "https://commonfoundry.ai/.well-known/oauth-protected-resource/rent/mcp");
  assert.equal(c.calls[0].method, "GET");
  assert.equal(await response.text(), "");
  assert.match(response.headers.get("WWW-Authenticate"), /rent\/mcp/);
});
test("missing bindings, disallowed routes and hosts fail closed", async () => {
  for (const [c, status] of [
    [context("/rent/mcp", { enabled: false }), 503],
    [context("/mcp"), 404], [context("/rent/catalog.js"), 404],
    [context("/rent/mcp", { host: "untrusted.example" }), 400],
    [context("/rent/mcp", { method: "DELETE" }), 405],
  ]) {
    assert.equal((await onRequest(c)).status, status);
    assert.equal(c.calls.length, 0);
  }
});
test("a service failure exposes no credentials or internal exception details", async () => {
  const response = await onRequest(context("/rent/mcp", { fail: true }));
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "marketplace_auth_unavailable" });
});
