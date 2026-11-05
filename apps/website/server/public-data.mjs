export const MAINNET_ID = "88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62";
export const DATA_TTL_SECONDS = 15;
const MAX_RESPONSE_BYTES = 131072;
const SOURCES = Object.freeze({
  status: "https://explorer.commonfoundry.ai/v1/explorer",
  supply: "https://explorer.commonfoundry.ai/api/supply",
});
const HEX = /^[0-9a-f]{64}$/;
const ATOMS = /^[0-9]+$/;
const AMOUNT = /^[0-9]+\.[0-9]{8}$/;
const count = (v) => Number.isSafeInteger(v) && v >= 0;

export class PublicDataError extends Error {
  constructor(code) { super(code); this.code = code; }
}

export async function boundedText(response, maximum = MAX_RESPONSE_BYTES) {
  if (Number(response.headers.get("Content-Length")) > maximum) throw new PublicDataError("response_too_large");
  if (!response.body) throw new PublicDataError("empty_response");
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum) {
        await reader.cancel();
        throw new PublicDataError("response_too_large");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new PublicDataError("invalid_response"); }
}

export function selectPublicData(kind, raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new PublicDataError("invalid_response");
  if (kind === "status") {
    if (raw.network_id !== MAINNET_ID || raw.proof_profile !== "ProductionV4" ||
        !count(raw.accepted_height) || !count(raw.validated_height) ||
        raw.validated_height > raw.accepted_height || !HEX.test(raw.tip)) throw new PublicDataError("unexpected_network_data");
    const data = { network: "CommonFoundry Mainnet", network_id: MAINNET_ID, proof_profile: "ProductionV4",
      accepted_height: raw.accepted_height, validated_height: raw.validated_height, tip: raw.tip };
    for (const field of ["connected_peers", "mempool_transactions", "mempool_bytes", "utxo_count"]) {
      if (!count(raw[field])) throw new PublicDataError("invalid_response");
      data[field] = raw[field];
    }
    if (typeof raw.total_supply_atoms !== "string" || !ATOMS.test(raw.total_supply_atoms)) throw new PublicDataError("invalid_response");
    data.total_supply_atoms = raw.total_supply_atoms;
    return data;
  }
  if (kind === "supply") {
    if (raw.network !== "mainnet" || !count(raw.height) || !HEX.test(raw.tip) || raw.max_supply !== null) {
      throw new PublicDataError("unexpected_network_data");
    }
    const data = { network: "mainnet", height: raw.height, tip: raw.tip, max_supply: null };
    for (const field of ["total_supply", "circulating_supply", "burned_fees"]) {
      if (typeof raw[field] !== "string" || !AMOUNT.test(raw[field]) || typeof raw[`${field}_atoms`] !== "string" || !ATOMS.test(raw[`${field}_atoms`])) throw new PublicDataError("invalid_response");
      data[field] = raw[field];
      data[`${field}_atoms`] = raw[`${field}_atoms`];
    }
    data.circulating_supply_definition = "Total supply minus current steward and community fund balances.";
    return data;
  }
  throw new PublicDataError("unknown_data_kind");
}

export function createPublicDataReader({ fetcher = globalThis.fetch, now = Date.now,
  cacheProvider = async () => typeof caches === "undefined" ? null : caches.open("cmfd-public-mcp-v1") } = {}) {
  const memory = new Map();
  const pending = new Map();
  const failures = new Map();
  const fresh = (v) => v && now() - Date.parse(v.fetchedAt) >= 0 && now() - Date.parse(v.fetchedAt) < DATA_TTL_SECONDS * 1000;
  return async function read(kind) {
    if (!Object.hasOwn(SOURCES, kind)) throw new PublicDataError("unknown_data_kind");
    const remembered = memory.get(kind);
    if (fresh(remembered)) return remembered;
    const failed = failures.get(kind);
    if (failed && now() < failed.until) throw new PublicDataError(failed.code);
    if (pending.has(kind)) return pending.get(kind);
    const work = (async () => {
      let cache = null;
      try { cache = await cacheProvider(); } catch { /* Cache availability must not decide data validity. */ }
      const key = new Request(`https://commonfoundry.ai/__mcp_cache/v1/${kind}`);
      if (cache) {
        try {
          const cached = await cache.match(key);
          if (cached) {
            const value = JSON.parse(await boundedText(cached));
            if (fresh(value) && value.source === SOURCES[kind]) {
              // Validate cached scalars too; the cache is not an authority.
              value.data = selectPublicData(kind, value.data);
              memory.set(kind, value);
              return value;
            }
          }
        } catch { /* Fetch and validate anew if a cache entry is unusable. */ }
      }
      let response;
      try { response = await fetcher(SOURCES[kind], { headers: { Accept: "application/json" }, redirect: "manual", signal: AbortSignal.timeout(6000) }); }
      catch (error) {
        console.warn("cmfd_public_upstream_fetch_failed", kind, error?.name, error?.message);
        throw new PublicDataError("upstream_unavailable");
      }
      if (!response.ok) {
        console.warn("cmfd_public_upstream_http_failed", kind, response.status);
        throw new PublicDataError("upstream_unavailable");
      }
      if (!response.headers.get("Content-Type")?.toLowerCase().includes("application/json")) throw new PublicDataError("invalid_response");
      let raw;
      try { raw = JSON.parse(await boundedText(response)); }
      catch (error) { throw error instanceof PublicDataError ? error : new PublicDataError("invalid_response"); }
      const value = { source: SOURCES[kind], fetchedAt: new Date(now()).toISOString(), cacheMaxAgeSeconds: DATA_TTL_SECONDS,
        verification: "Reported by the public explorer; this adapter does not independently validate consensus proofs.", data: selectPublicData(kind, raw) };
      memory.set(kind, value);
      if (cache) {
        try { await cache.put(key, new Response(JSON.stringify(value), { headers: { "Content-Type": "application/json", "Cache-Control": `public, max-age=${DATA_TTL_SECONDS}` } })); }
        catch { /* A failed cache write does not invalidate a verified response shape. */ }
      }
      return value;
    })();
    pending.set(kind, work);
    try {
      const value = await work;
      failures.delete(kind);
      return value;
    } catch (error) {
      const code = error instanceof PublicDataError ? error.code : "upstream_unavailable";
      failures.set(kind, { code, until: now() + 3000 });
      throw new PublicDataError(code);
    } finally { pending.delete(kind); }
  };
}
