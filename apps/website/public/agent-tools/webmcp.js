import { registerPageTools } from "./webmcp-core.js";
import { guides } from "./guide-index.js";

let controller;
async function activate() {
  controller?.abort();
  const active = new AbortController();
  controller = active;
  const status = document.querySelector("[data-webmcp-status]");
  try {
    const registered = await registerPageTools(document, guides, active.signal);
    if (status && controller === active) status.textContent = registered
      ? "This browser registered two read-only guide tools. A compatible browser assistant can discover them."
      : "This browser does not expose the current WebMCP API. The guides and remote MCP service are available normally.";
  } catch {
    active.abort();
    if (status && controller === active) status.textContent = "WebMCP tools could not be registered in this browser. Use the guides or remote MCP service.";
  }
}
window.addEventListener("pagehide", () => controller?.abort());
window.addEventListener("pageshow", (event) => { if (event.persisted) void activate(); });
void activate();
