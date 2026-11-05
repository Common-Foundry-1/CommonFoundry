const validObject = (input) => input && typeof input === "object" && !Array.isArray(input);

export function createPageTools(doc, guides) {
  return [{
    name: "cmfd_read_page",
    description: "Read the current public Common Foundry guide with its title, source URL, headings, and text.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    execute(input) {
      if (!validObject(input) || Object.keys(input).length) return { error: "Pass an empty object." };
      const main = doc.querySelector("main");
      if (!main) return { error: "No public guide is available on this page." };
      const text = (main.innerText ?? main.textContent).trim();
      return { title: doc.title, source: doc.querySelector('link[rel="canonical"]')?.href ?? doc.URL,
        headings: Array.from(main.querySelectorAll("h1,h2,h3"), (heading) => heading.textContent.trim()),
        text: text.slice(0, 24000), truncated: text.length > 24000 };
    },
    annotations: { readOnlyHint: true, untrustedContentHint: true },
  }, {
    name: "cmfd_find_guide",
    description: "Find maintained Common Foundry guides and setup skills by topic.",
    inputSchema: { type: "object", properties: { query: { type: "string", minLength: 1, maxLength: 120 } }, required: ["query"], additionalProperties: false },
    execute(input) {
      if (!validObject(input) || Object.keys(input).some((key) => key !== "query") || typeof input.query !== "string" ||
          !input.query.trim() || input.query.length > 120) return { error: "Pass a nonempty query of at most 120 characters." };
      const terms = input.query.normalize("NFKC").toLowerCase().trim().split(/\s+/);
      return { source: "https://commonfoundry.ai/learn/", matches: guides.filter((guide) => {
        const text = `${guide.title} ${guide.description ?? ""}`.normalize("NFKC").toLowerCase();
        return terms.every((term) => text.includes(term));
      }) };
    },
    annotations: { readOnlyHint: true },
  }];
}

export async function registerPageTools(doc, guides, signal) {
  if (typeof doc.modelContext?.registerTool !== "function") return false;
  for (const tool of createPageTools(doc, guides)) {
    signal.throwIfAborted();
    await doc.modelContext.registerTool(tool, { signal });
  }
  return true;
}
