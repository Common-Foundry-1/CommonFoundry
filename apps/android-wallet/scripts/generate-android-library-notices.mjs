import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const rows = JSON.parse(readFileSync(join(root, "license-inventory/gradle-arm-release.json"), "utf8"));
if (!Array.isArray(rows) || rows.length === 0 || rows.some((row) => !row.license_names?.length)) {
  throw new Error("Android library license inventory is incomplete");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function safeLink(rawUrl, label) {
  if (!rawUrl) return escapeHtml(label);
  const normalized = rawUrl.replace(/^http:\/\/www\.apache\.org\//, "https://www.apache.org/");
  const url = new URL(normalized);
  if (url.protocol !== "https:") return escapeHtml(label);
  return `<a href="${escapeHtml(url.href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`;
}

const packages = rows.map((row) => `<tr><td>${escapeHtml(row.coordinate)}</td><td>${row.license_names
  .map((name, index) => safeLink(row.license_urls[index], name)).join("; ")}</td></tr>`).join("\n");
const apache = escapeHtml(readFileSync(join(root, "license-inventory/APACHE-2.0.txt"), "utf8"));
const libyuv = escapeHtml(readFileSync(join(root, "license-inventory/LIBYUV-BSD.txt"), "utf8"));

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Android library notices · Common Foundry Wallet</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; background: #121717; color: #ebe9e3; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    main { max-width: 1100px; margin: auto; padding: 24px 18px 72px; }
    a, summary { color: #e7b961; }
    .eyebrow { color: #e7b961; font-size: .75rem; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; }
    header { border-bottom: 1px solid #47423a; margin-bottom: 24px; }
    .notice, details { background: #1b2020; border: 1px solid #47423a; border-radius: 10px; padding: 16px; margin: 14px 0; }
    .table-wrap { overflow-x: auto; }
    table { border-collapse: collapse; width: 100%; font-size: .83rem; }
    th, td { border-bottom: 1px solid #47423a; padding: 9px; text-align: left; vertical-align: top; }
    td:first-child { overflow-wrap: anywhere; }
    summary { cursor: pointer; font-weight: 700; }
    pre { background: #111515; border-radius: 8px; overflow-wrap: anywhere; padding: 16px; white-space: pre-wrap; font-size: .8rem; line-height: 1.5; }
  </style>
</head>
<body><main>
  <header>
    <p class="eyebrow">Common Foundry Wallet</p>
    <h1>Android library notices</h1>
    <p>Resolved ARM release libraries. <a href="/">Back to wallet</a>.</p>
    <p>See also <a href="/rust-licenses.html">Rust notices</a> and <a href="/javascript-licenses.html">JavaScript notices</a>.</p>
  </header>
  <section class="notice">
    <h2>QR scanning and Google ML Kit</h2>
    <p>QR scanning uses Google ML Kit. Google says images and scan results are processed on the device, while ML Kit may contact Google for updates and sends performance and usage metrics. See Google's <a href="https://developers.google.com/ml-kit/terms" target="_blank" rel="noopener noreferrer">ML Kit terms and privacy information</a>.</p>
    <p>Some Google libraries below are distributed under the Android SDK License or ML Kit Terms of Service. Their terms are linked in the inventory.</p>
  </section>
  <div class="table-wrap"><table>
    <thead><tr><th>Library and version</th><th>Declared license or terms</th></tr></thead>
    <tbody>${packages}</tbody>
  </table></div>
  <details><summary>Apache License 2.0 text</summary><pre>${apache}</pre></details>
  <details><summary>libyuv BSD license text used by CameraX</summary><pre>${libyuv}</pre></details>
</main></body></html>
`;

writeFileSync(join(root, "app/public/android-library-notices.html"), html, "utf8");
console.log(`Wrote Android library notices for ${rows.length} runtime artifacts`);
