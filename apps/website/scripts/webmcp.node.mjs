import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { JSDOM } from "jsdom";
import { createPageTools, registerPageTools } from "../public/agent-tools/webmcp-core.js";

const guides = [{ title: "Mining", url: "https://commonfoundry.ai/learn/mining/" },
  { title: "Verify a release", url: "https://commonfoundry.ai/docs/skills/" }];

test("unsupported browsers do not need a polyfill or change the guide", async () => {
  const { window } = new JSDOM("<main><h1>Mining</h1></main>");
  try { assert.equal(await registerPageTools(window.document, guides, new AbortController().signal), false); }
  finally { window.close(); }
});

test("browser tools are read-only, bounded, validate input, and use the current public page", () => {
  const { window } = new JSDOM('<title>CMFD</title><link rel="canonical" href="https://commonfoundry.ai/learn/mining/"><main><h1>Mining</h1><p>Public guide</p></main>');
  try {
    const [read, search] = createPageTools(window.document, guides);
    assert.equal(read.annotations.readOnlyHint, true);
    assert.equal(search.annotations.readOnlyHint, true);
    assert.equal(read.execute({}).source, "https://commonfoundry.ai/learn/mining/");
    assert.deepEqual(read.execute({}).headings, ["Mining"]);
    assert.equal(read.execute({ url: "https://untrusted.example" }).error, "Pass an empty object.");
    assert.deepEqual(search.execute({ query: "mining" }).matches, [guides[0]]);
    for (const input of [null, [], { query: "" }, { query: "a".repeat(121) }, { query: "mining", url: "anything" }]) {
      assert.ok(search.execute(input).error);
    }
    window.document.querySelector("p").textContent = "a".repeat(30000);
    assert.equal(read.execute({}).text.length, 24000);
    assert.equal(read.execute({}).truncated, true);
  } finally { window.close(); }
});

test("registration follows the current document API and is cancellable on navigation", async () => {
  const { window } = new JSDOM("<main><h1>Guide</h1></main>");
  const calls = [];
  window.document.modelContext = { async registerTool(tool, options) { calls.push({ tool, options }); } };
  const controller = new AbortController();
  try {
    assert.equal(await registerPageTools(window.document, guides, controller.signal), true);
    assert.deepEqual(calls.map(({ tool }) => tool.name), ["cmfd_read_page", "cmfd_find_guide"]);
    assert.ok(calls.every(({ options }) => options.signal === controller.signal && !options.exposedTo));
    controller.abort();
    assert.ok(calls.every(({ options }) => options.signal.aborted));
    await assert.rejects(registerPageTools(window.document, guides, controller.signal), /abort/i);
  } finally { window.close(); }
});

test("built public guide pages load the pilot module and all indexed links have built artifacts", async () => {
  const { guides: builtGuides } = await import("../dist/agent-tools/guide-index.js");
  for (const guide of builtGuides) {
    const path = new URL(guide.url).pathname;
    const bytes = await readFile(`dist${path}${path.endsWith("/") ? "index.html" : ""}`);
    assert.ok(bytes.length);
    if (path.endsWith("/")) assert.match(bytes.toString("utf8"), /type="module" src="\/agent-tools\/webmcp.js"/);
  }
});
