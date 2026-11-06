import { readFileSync, writeFileSync } from "node:fs";

if (process.argv.length < 3) throw new Error("Pass one or more generated notice pages");
for (const path of process.argv.slice(2)) {
  const original = readFileSync(path, "utf8");
  const normalized = original.replace(/\r\n?/g, "\n").replace(/[\t ]+$/gm, "");
  if (normalized !== original) writeFileSync(path, normalized, "utf8");
}
