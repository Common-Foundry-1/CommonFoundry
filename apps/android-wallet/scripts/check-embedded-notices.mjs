import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, extname } from "node:path";
import { brotliDecompressSync } from "node:zlib";

const buildRoot = resolve("app/src-tauri/target/aarch64-linux-android/release/build");
const candidates = readdirSync(buildRoot)
  .filter((name) => name.startsWith("common-foundry-android-wallet-"))
  .map((name) => join(buildRoot, name, "out", "tauri-codegen-assets"))
  .filter(existsSync)
  .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
if (!candidates.length) throw new Error("Tauri Android asset bundle is missing");

const assets = readdirSync(candidates[0]).map((name) => ({
  extension: extname(name),
  text: brotliDecompressSync(readFileSync(join(candidates[0], name))).toString("utf8"),
}));
const required = [
  [".html", "Rust open-source licenses"],
  [".html", "JavaScript open-source licenses"],
  [".html", "Android library notices"],
  [".txt", "Copyright (c) 2026 CommonFoundry contributors"],
];
for (const [extension, marker] of required) {
  if (!assets.some((asset) => asset.extension === extension && asset.text.includes(marker))) {
    throw new Error(`Missing bundled notice: ${marker}`);
  }
}
console.log(`Verified four notices in ${candidates[0]}`);
