import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { SERVER_CARD } from "../server/service-info.mjs";
import { SKILL_NAMES } from "../server/skill-info.mjs";

await mkdir("dist/.well-known/mcp", { recursive: true });
await writeFile("dist/.well-known/mcp/server-card.json", `${JSON.stringify(SERVER_CARD, null, 2)}\n`);

const skills = [];
for (const name of SKILL_NAMES) {
  const url = `/.well-known/agent-skills/${name}/SKILL.md`;
  // Hash exactly the bytes Vite copied and the deployment will serve.
  const bytes = await readFile(`dist${url}`);
  const match = /^---\r?\nname: ([a-z0-9-]+)\r?\ndescription: ([^\r\n]+)\r?\n---\r?\n/.exec(bytes.toString("utf8"));
  if (!match || match[1] !== name || name.length > 64 || name.includes("--") || match[2].length > 1024) {
    throw new Error(`Invalid single-file skill metadata: ${name}`);
  }
  skills.push({ name, description: match[2], type: "skill-md", url,
    digest: `sha256:${createHash("sha256").update(bytes).digest("hex")}` });
}
await mkdir("dist/.well-known/agent-skills", { recursive: true });
await writeFile("dist/.well-known/agent-skills/index.json", `${JSON.stringify({
  $schema: "https://schemas.agentskills.io/discovery/0.2.0/schema.json", skills,
}, null, 2)}\n`);
