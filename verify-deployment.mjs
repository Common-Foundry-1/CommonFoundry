import { readFileSync } from "node:fs";

const metadata = JSON.parse(readFileSync("BUILD-METADATA.json", "utf8"));
const [phase, deploymentFile] = process.argv.slice(2);
if (!["before", "after"].includes(phase) || !deploymentFile) throw new Error("Expected verification phase and deployment file");
if (metadata.source_commit !== "815b003e3166948bc98b959450089b66346e2da6") throw new Error("Unexpected source commit");
const deployments = JSON.parse(readFileSync(deploymentFile, "utf8"));
const latest = [...deployments].sort((left, right) => Date.parse(right.created_on) - Date.parse(left.created_on))[0];
if (!latest || latest.versions.length !== 1 || latest.versions[0].percentage !== 100) throw new Error("Expected a single fully deployed Worker version");
const version = latest.versions[0].version_id;
if (phase === "before" && version !== metadata.expected_previous_version) throw new Error(`Production version changed: ${version}`);
if (phase === "after" && version === metadata.expected_previous_version) throw new Error("Production version did not change");

async function get(path) {
  let failure;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const response = await fetch(`https://${metadata.domain}${path}`, { cache: "no-store", signal: AbortSignal.timeout(20000) });
      if (!response.ok) throw new Error(`${path} returned HTTP ${response.status}`);
      return await response.text();
    } catch (error) { failure = error; }
  }
  throw failure;
}

const html = await get("/");
const asset = html.match(/\/assets\/index-[A-Za-z0-9_-]+\.js/)?.[0];
const expected = phase === "before" ? metadata.expected_previous_asset : metadata.expected_asset;
if (asset !== expected) throw new Error(`Unexpected public wallet asset: ${asset}`);
if (phase === "after") {
  const bundle = await get(asset);
  if (!bundle.includes("Wallets and security")) throw new Error("Wallet manager fix missing from public bundle");
}
const explorer = JSON.parse(await get("/v1/explorer"));
if (explorer.network_id !== metadata.network_id) throw new Error("Unexpected explorer network");
console.log(JSON.stringify({ phase, version, asset, height: explorer.accepted_height, connected_peers: explorer.connected_peers }));
