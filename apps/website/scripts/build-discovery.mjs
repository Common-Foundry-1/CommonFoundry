import { mkdir, writeFile } from "node:fs/promises";
import { SERVER_CARD } from "../server/service-info.mjs";

await mkdir("dist/.well-known/mcp", { recursive: true });
await writeFile("dist/.well-known/mcp/server-card.json", `${JSON.stringify(SERVER_CARD, null, 2)}\n`);
