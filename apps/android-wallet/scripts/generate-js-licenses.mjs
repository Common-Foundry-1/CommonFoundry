import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const inventory = JSON.parse(readFileSync(0, "utf8"));
const packages = Object.values(inventory).flat().sort((a, b) => a.name.localeCompare(b.name));
const tauriApi = packages.find((entry) => entry.name === "@tauri-apps/api");
const tauriMit = tauriApi
  ? readFileSync(join(tauriApi.paths[0], "LICENSE_MIT"), "utf8")
  : "";

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function licenseText(entry) {
  const root = entry.paths[0];
  const files = readdirSync(root);
  const preferred = entry.license.includes("MIT")
    ? ["LICENSE_MIT", "LICENSE-MIT", "LICENSE", "LICENSE.spdx"]
    : ["LICENSE", "LICENSE_ISC", "LICENSE.spdx"];
  const name = preferred.find((candidate) => files.includes(candidate));
  if (!name) throw new Error(`No license file for ${entry.name}@${entry.versions[0]}`);
  const text = readFileSync(join(root, name), "utf8");
  if (entry.name === "@tauri-apps/plugin-barcode-scanner") {
    if (!tauriMit) throw new Error("Tauri MIT license text is missing");
    return `${text}\n\nMIT license text for the Tauri plugin:\n\n${tauriMit}`;
  }
  return text;
}

const cards = packages.map((entry) => `
  <details class="card">
    <summary>${escapeHtml(entry.name)} ${escapeHtml(entry.versions.join(", "))}</summary>
    <p>Declared license: ${escapeHtml(entry.license)}</p>
    <pre>${escapeHtml(licenseText(entry))}</pre>
  </details>`).join("\n");

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>JavaScript licenses · Common Foundry Wallet</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; background: #121717; color: #ebe9e3; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    main { max-width: 960px; margin: auto; padding: 24px 18px 72px; }
    a, summary { color: #e7b961; }
    .eyebrow { color: #e7b961; font-size: .75rem; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; }
    header { border-bottom: 1px solid #47423a; margin-bottom: 24px; }
    .card { background: #1b2020; border: 1px solid #47423a; border-radius: 10px; margin: 12px 0; padding: 14px; }
    summary { cursor: pointer; font-weight: 700; }
    pre { background: #111515; border-radius: 8px; overflow-wrap: anywhere; padding: 16px; white-space: pre-wrap; font-size: .8rem; line-height: 1.5; }
  </style>
</head>
<body><main>
  <header>
    <p class="eyebrow">Common Foundry Wallet</p>
    <h1>JavaScript open-source licenses</h1>
    <p>Runtime packages bundled with the Android wallet. <a href="/">Back to wallet</a>.</p>
    <p>See also <a href="/rust-licenses.html">Rust notices</a> and <a href="/android-library-notices.html">Android library notices</a>.</p>
  </header>
  ${cards}
</main></body></html>
`;

writeFileSync(resolve("public/javascript-licenses.html"), html, "utf8");
console.log(`Wrote JavaScript licenses for ${packages.length} runtime packages`);
