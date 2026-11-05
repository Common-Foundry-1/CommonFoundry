import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createHash } from "node:crypto";
import { SKILL_NAMES } from "../server/skill-info.mjs";
import { markdownRoutes, onRequest, prefersMarkdown } from "../functions/_middleware.js";

function context({ accept, method = "GET", path = "/", missing = false } = {}) {
  const calls = [];
  return {
    calls,
    request: new Request(`https://preview.example${path}`, { method, headers: accept ? { Accept: accept } : {} }),
    env: { ASSETS: { async fetch(request) {
      calls.push(request.url);
      return new Response(method === "HEAD" ? null : "# Common Foundry\n", {
        status: missing ? 404 : 200,
        headers: { "Content-Type": "text/plain", "Content-Security-Policy": "default-src 'self'", "Vary": "Origin" },
      });
    } } },
    async next() { return new Response(method === "HEAD" ? null : "<h1>Common Foundry</h1>", {
      headers: { "Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'" },
    }); },
  };
}

test("content negotiation honors explicit opt-out, HTML preference, and ordinary browser Accept values", () => {
  for (const [accept, expected] of [
    ["", false], ["*/*", false], ["text/html,application/xhtml+xml,*/*;q=0.8", false],
    ["text/markdown", true], ["text/markdown;q=0", false],
    ["text/html;q=1,text/markdown;q=0.5", false],
    ["text/html;q=0.5,text/markdown;q=1", true],
    ["text/markdown;q=invalid", false], ["text/markdown;q=2", false],
  ]) assert.equal(prefersMarkdown(accept), expected, accept);
});

test("browser HTML retains security headers and varies on Accept", async () => {
  const c = context({ accept: "text/html" });
  const response = await onRequest(c);
  assert.match(await response.text(), /<h1>/);
  assert.equal(response.headers.get("Content-Type"), "text/html");
  assert.equal(response.headers.get("Content-Security-Policy"), "default-src 'self'");
  assert.equal(response.headers.get("Vary"), "Accept");
  assert.deepEqual(c.calls, []);
});

test("Markdown uses only its fixed local asset and preserves response protections", async () => {
  const c = context({ accept: "text/markdown", path: "/learn/mining/?redirect=https://untrusted.example" });
  const response = await onRequest(c);
  assert.deepEqual(c.calls, ["https://preview.example/agent-text/mining.md"]);
  assert.match(await response.text(), /^# Common Foundry/);
  assert.equal(response.headers.get("Content-Type"), "text/markdown; charset=utf-8");
  assert.equal(response.headers.get("Content-Location"), "/agent-text/mining.md");
  assert.equal(response.headers.get("Content-Security-Policy"), "default-src 'self'");
  assert.equal(response.headers.get("Vary"), "Origin, Accept");
});

test("HEAD negotiates Markdown without a response body", async () => {
  const response = await onRequest(context({ accept: "text/markdown", method: "HEAD" }));
  assert.equal(await response.text(), "");
  assert.match(response.headers.get("Content-Type"), /^text\/markdown/);
  assert.equal(response.headers.get("Vary"), "Origin, Accept");
});

test("non-page routes and write methods are passed through without asset requests", async () => {
  for (const options of [{ path: "/.well-known/api-catalog" }, { path: "/openapi.json" }, { method: "POST" }]) {
    const c = context({ accept: "text/markdown", ...options });
    const response = await onRequest(c);
    assert.equal(response.headers.get("Content-Type"), "text/html");
    assert.deepEqual(c.calls, []);
  }
});

test("missing Markdown asset falls back to correctly labelled HTML", async () => {
  const response = await onRequest(context({ accept: "text/markdown", missing: true }));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Content-Type"), "text/html");
});

test("every negotiated route has a built Markdown representation with no HTML shell", async () => {
  for (const filename of Object.values(markdownRoutes)) {
    const text = await readFile(`dist/agent-text/${filename}`, "utf8");
    assert.match(text, /^#|\n# /, filename);
    assert.doesNotMatch(text, /<html|<script|<div/i, filename);
    assert.match(text, /https:\/\//, filename);
  }
});

test("catalog description links resolve to built files and advertise only credential-free reads", async () => {
  const catalog = JSON.parse(await readFile("dist/.well-known/api-catalog", "utf8"));
  for (const entry of catalog.linkset) {
    assert.equal(new URL(entry.anchor).protocol, "https:");
    for (const relation of ["service-desc", "service-doc", "service-meta"]) {
      for (const link of entry[relation] ?? []) {
        const path = new URL(link.href).pathname;
        assert.ok((await readFile(`dist${path}${path.endsWith("/") ? "index.html" : ""}`)).length > 0);
      }
    }
  }
  const api = JSON.parse(await readFile("dist/openapi.json", "utf8"));
  assert.equal(api.openapi, "3.1.0");
  assert.deepEqual(api.security, []);
  for (const path of Object.values(api.paths)) assert.deepEqual(Object.keys(path), ["get"]);
});

test("skill discovery describes the exact served artifacts and their metadata", async () => {
  const index = JSON.parse(await readFile("dist/.well-known/agent-skills/index.json", "utf8"));
  assert.equal(index.$schema, "https://schemas.agentskills.io/discovery/0.2.0/schema.json");
  assert.deepEqual(index.skills.map((skill) => skill.name), SKILL_NAMES);
  for (const skill of index.skills) {
    assert.equal(skill.type, "skill-md");
    const bytes = await readFile(`dist${skill.url}`);
    assert.equal(skill.digest, `sha256:${createHash("sha256").update(bytes).digest("hex")}`);
    const text = bytes.toString("utf8");
    assert.ok(text.startsWith(`---\nname: ${skill.name}\ndescription: ${skill.description}\n---\n`) ||
      text.startsWith(`---\r\nname: ${skill.name}\r\ndescription: ${skill.description}\r\n---\r\n`));
    assert.doesNotMatch(text, /\[TODO:|<script|<html/i);
  }
});

test("missing skill files return genuine 404s instead of the site HTML shell", async () => {
  for (const path of ["/.well-known/agent-skills/unknown/SKILL.md", "/.well-known/agent-skills/cmfd-mining-setup/missing.md"]) {
    const response = await onRequest(context({ path }));
    assert.equal(response.status, 404);
    assert.match(response.headers.get("Content-Type"), /^text\/plain/);
    assert.doesNotMatch(await response.text(), /<h1>/);
  }
  const response = await onRequest(context({ path: "/.well-known/agent-skills/unknown/SKILL.md", method: "HEAD" }));
  assert.equal(response.status, 404);
  assert.equal(await response.text(), "");
});
