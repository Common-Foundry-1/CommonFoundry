import { readFile, mkdir, writeFile } from "node:fs/promises";
import { JSDOM } from "jsdom";
import { markdownRoutes } from "../functions/_middleware.js";

function markdown(node, pageUrl) {
  if (node.nodeType === 3) return node.textContent.replace(/\s+/g, " ");
  if (node.nodeType !== 1) return "";
  const tag = node.tagName.toLowerCase();
  if (["script", "style", "nav"].includes(tag)) return "";
  const text = () => [...node.childNodes].map((child) => markdown(child, pageUrl)).join("");
  if (/^h[1-6]$/.test(tag)) return `\n\n${"#".repeat(Number(tag[1]))} ${text().trim()}\n\n`;
  if (tag === "a") {
    const link = `[${text().trim()}](${new URL(node.getAttribute("href"), pageUrl).href})`;
    return node.classList.contains("card") || node.classList.contains("button") ? `\n- ${link}\n` : link;
  }
  if (tag === "strong" || tag === "b") return `**${text().trim()}**`;
  if (tag === "em" || tag === "i") return `*${text().trim()}*`;
  if (tag === "pre") return `\n\n\`\`\`text\n${node.textContent.trim()}\n\`\`\`\n\n`;
  if (tag === "code") return `\`${node.textContent.trim()}\``;
  if (tag === "li") return `\n${node.parentElement.tagName === "OL" ? "1." : "-"} ${text().trim()}\n`;
  if (["p", "div", "ul", "ol", "section"].includes(tag)) return `\n\n${text().trim()}\n\n`;
  if (tag === "br") return "\n";
  return ` ${text()} `;
}

await mkdir("dist/agent-text", { recursive: true });
for (const [route, filename] of Object.entries(markdownRoutes)) {
  if (route === "/") continue; // Curated homepage summary is copied by Vite from public/.
  const html = await readFile(`public${route}index.html`, "utf8");
  const dom = new JSDOM(html);
  const main = dom.window.document.querySelector("main");
  if (!main?.querySelector("h1")) throw new Error(`Missing guide content: ${route}`);
  const output = markdown(main, new URL(route, "https://commonfoundry.ai"))
    .replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
  await writeFile(`dist/agent-text/${filename}`, `${output}\n`);
  dom.window.close();
}
