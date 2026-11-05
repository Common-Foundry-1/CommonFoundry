import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { SKILL_NAMES } from "../server/skill-info.mjs";

const base = new URL(process.argv[2] ?? "https://commonfoundry.ai");
if (base.protocol !== "https:" || !(base.hostname === "commonfoundry.ai" || base.hostname.endsWith(".commonfoundry.pages.dev"))) {
  throw new Error("Use a Common Foundry production or preview origin.");
}
const read = (path, options) => fetch(new URL(path, base), { ...options, redirect: "error", signal: AbortSignal.timeout(12000) });
const response = await read("/.well-known/agent-skills/index.json");
assert.equal(response.status, 200);
assert.match(response.headers.get("Content-Type"), /^application\/json(?:;|$)/);
const index = await response.json();
assert.equal(index.$schema, "https://schemas.agentskills.io/discovery/0.2.0/schema.json");
assert.deepEqual(index.skills.map((skill) => skill.name), SKILL_NAMES);
const skills = [];
for (const skill of index.skills) {
  assert.equal(skill.url, `/.well-known/agent-skills/${skill.name}/SKILL.md`);
  const file = await read(skill.url);
  assert.equal(file.status, 200);
  assert.match(file.headers.get("Content-Type"), /^text\/(markdown|plain)(?:;|$)/);
  assert.equal(file.headers.get("X-Content-Type-Options"), "nosniff");
  const bytes = Buffer.from(await file.arrayBuffer());
  const digest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  assert.equal(digest, skill.digest);
  assert.match(bytes.toString("utf8"), new RegExp(`^---\\r?\\nname: ${skill.name}\\r?\\ndescription: `));
  const head = await read(skill.url, { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), "");
  skills.push({ name: skill.name, digest, bytes: bytes.length });
}
for (const method of ["GET", "HEAD"]) {
  const missing = await read("/.well-known/agent-skills/not-a-published-skill/SKILL.md", { method });
  assert.equal(missing.status, 404);
  assert.match(missing.headers.get("Content-Type"), /^text\/plain/);
}
const docs = await read("/docs/skills/", { headers: { Accept: "text/markdown" } });
assert.equal(docs.status, 200);
assert.match(docs.headers.get("Content-Type"), /^text\/markdown/);
assert.match(await docs.text(), /# Help your assistant/);
const report = { origin: base.origin, checkedUtc: new Date().toISOString(), passed: true, skills, missingFilesReturn404: true, markdownGuide: true };
if (process.argv[3]) await writeFile(process.argv[3], `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report, null, 2));
