var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker/policy.ts
var NETWORK_HEADER = "X-CMFD-Network-Id";
var MAINNET_FRAME_PREFIX = "434d46446702973f";
var HASH = /^[0-9a-f]{64}$/;
var MAX_TRANSACTION_BYTES = 64 * 1024;
var MAX_BODY_BYTES = 2 * MAX_TRANSACTION_BYTES + 1024;
var SNAPSHOT_PATH = "/v1/explorer";
var TRANSACTION_PATH = /^\/v1\/explorer\/transaction\/[0-9a-f]{64}$/;
var ADDRESS_PATH = /^\/v1\/explorer\/address\/[0-9a-f]{64}$/;
function isExplorerPath(pathname) {
  return pathname === SNAPSHOT_PATH || TRANSACTION_PATH.test(pathname) || ADDRESS_PATH.test(pathname);
}
__name(isExplorerPath, "isExplorerPath");
var SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY"
};

// worker/twoFactorCrypto.ts
var hex = /* @__PURE__ */ __name((bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(""), "hex");
var randomHex = /* @__PURE__ */ __name((size = 32) => hex(crypto.getRandomValues(new Uint8Array(size))), "randomHex");
function unhex(value) {
  if (!/^(?:[a-f0-9]{2})+$/.test(value)) throw new Error("Invalid hex");
  return Uint8Array.from(value.match(/../g), (b) => parseInt(b, 16));
}
__name(unhex, "unhex");
var text = /* @__PURE__ */ __name((value) => new TextEncoder().encode(value), "text");
var digest = /* @__PURE__ */ __name(async (value) => hex(new Uint8Array(await crypto.subtle.digest("SHA-256", text(value)))), "digest");
function equal(a, b) {
  let difference = a.length ^ b.length;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ (b.charCodeAt(i) || 0);
  return difference === 0;
}
__name(equal, "equal");
function base32(bytes) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let value = 0, bits = 0, result = "";
  for (const byte of bytes) {
    value = value << 8 | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += alphabet[value >>> bits & 31];
    }
  }
  if (bits) result += alphabet[value << 5 - bits & 31];
  return result;
}
__name(base32, "base32");
async function totp(secretHex, step, digits = 6) {
  const counter = new Uint8Array(8);
  new DataView(counter.buffer).setBigUint64(0, BigInt(step));
  const key = await crypto.subtle.importKey("raw", unhex(secretHex), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = mac[mac.length - 1] & 15;
  const truncated = new DataView(mac.buffer).getUint32(offset) & 2147483647;
  return (truncated % 10 ** digits).toString().padStart(digits, "0");
}
__name(totp, "totp");
async function matchTotp(secret, code, now, lastStep) {
  if (!/^\d{6}$/.test(code)) return null;
  const step = Math.floor(now / 3e4);
  let matched = null;
  for (const candidate of [step - 1, step, step + 1]) {
    const matches = equal(await totp(secret, candidate), code);
    if (matches && candidate > lastStep) matched = candidate;
  }
  return matched;
}
__name(matchTotp, "matchTotp");
async function seal(value, master, aad) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", unhex(master), "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: text(aad) }, key, text(JSON.stringify(value)));
  return `${hex(nonce)}.${hex(new Uint8Array(ciphertext))}`;
}
__name(seal, "seal");
async function unseal(value, master, aad) {
  const [nonce, ciphertext] = value.split(".");
  const key = await crypto.subtle.importKey("raw", unhex(master), "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unhex(nonce), additionalData: text(aad) }, key, unhex(ciphertext));
  return JSON.parse(new TextDecoder().decode(plaintext));
}
__name(unseal, "unseal");

// worker/twoFactor.ts
var json = /* @__PURE__ */ __name((body, status = 200) => Response.json(body, { status, headers: { "Cache-Control": "no-store" } }), "json");
var denied = /* @__PURE__ */ __name(() => json({ error: "two_factor_rejected", message: "The authenticator or recovery code is invalid, expired, or already used. Try a fresh code." }, 401), "denied");
var unavailable = /* @__PURE__ */ __name(() => json({ error: "two_factor_unavailable", message: "The two-factor service is unavailable. Your wallet remains locked. Try again later." }, 503), "unavailable");
var WalletTwoFactor = class {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }
  state;
  env;
  static {
    __name(this, "WalletTwoFactor");
  }
  async fetch(request) {
    return this.state.blockConcurrencyWhile(async () => {
      if (!/^[a-f0-9]{64}$/.test(this.env.TWO_FACTOR_MASTER_KEY_V1 ?? "")) return unavailable();
      const path = new URL(request.url).pathname;
      if (path === "/internal/snapshot" || path === "/internal/restore") {
        if (!backupAuthorized(request, this.env)) return json({ error: "unauthorized" }, 401);
        if (path === "/internal/snapshot") return json({ record: await this.state.storage.get("record") ?? null });
        if (await this.state.storage.get("record")) return json({ error: "restore_requires_empty_record" }, 409);
        const record2 = await request.json();
        if (!record2 || !/^[a-f0-9]{64}$/.test(record2.id) || !/^[a-f0-9]{64}$/.test(record2.authHash) || record2.active !== true || typeof record2.sealed !== "string" || !["expires", "lastStep", "failures", "rounds", "blockedUntil"].every(
          (key) => Number.isSafeInteger(record2[key]) && Number(record2[key]) >= 0
        )) return json({ error: "invalid_backup_record" }, 400);
        const secrets2 = await unseal(record2.sealed, this.env.TWO_FACTOR_MASTER_KEY_V1, record2.id);
        if (!/^[a-f0-9]{40}$/.test(secrets2.totp) || !/^[a-f0-9]{64}$/.test(secrets2.share) || !Array.isArray(secrets2.recovery) || secrets2.recovery.length > 10 || !secrets2.recovery.every((hash2) => typeof hash2 === "string" && /^[a-f0-9]{64}$/.test(hash2))) {
          return json({ error: "invalid_backup_record" }, 400);
        }
        await registerRecord(this.env, record2.id);
        record2.lastStep = Math.max(record2.lastStep, Math.floor(Date.now() / 3e4));
        await this.state.storage.put("record", record2);
        return json({ restored: true });
      }
      const body = await request.json();
      const route = new URL(request.url).pathname.split("/").pop();
      const id = body.id;
      const token = body.token;
      if (!/^[a-f0-9]{64}$/.test(id ?? "") || !/^[a-f0-9]{64}$/.test(token ?? "")) return denied();
      const authHash = await digest(`cmfd-2fa-auth-v1:${id}:${token}`);
      let record = await this.state.storage.get("record");
      const now = Date.now();
      if (route === "enroll") {
        if (record) return json({ error: "enrollment_exists", message: "Start a new authenticator setup." }, 409);
        const recoveryCodes = Array.from({ length: 10 }, () => randomHex(16));
        const secrets2 = {
          totp: randomHex(20),
          share: randomHex(),
          recovery: await Promise.all(recoveryCodes.map((code2) => digest(`cmfd-2fa-recovery-v1:${id}:${code2}`)))
        };
        record = {
          id,
          authHash,
          sealed: await seal(secrets2, this.env.TWO_FACTOR_MASTER_KEY_V1, id),
          active: false,
          expires: now + 15 * 6e4,
          lastStep: -1,
          failures: 0,
          rounds: 0,
          blockedUntil: 0
        };
        await this.state.storage.put("record", record);
        await this.state.storage.setAlarm(record.expires);
        const secret = base32(unhex(secrets2.totp));
        const label = encodeURIComponent(`Common Foundry:Wallet ${id.slice(0, 8)}`);
        return json({
          secret,
          uri: `otpauth://totp/${label}?secret=${secret}&issuer=Common%20Foundry&algorithm=SHA1&digits=6&period=30`,
          recoveryCodes,
          // Used only to prepare the encrypted replacement before activation.
          share: secrets2.share
        });
      }
      if (!record || record.id !== id) return denied();
      if (now < record.blockedUntil) {
        return json({ error: "two_factor_rate_limited", message: "Too many failed attempts. Try again after the security cooldown." }, 429);
      }
      if (!record.active && now >= record.expires) {
        await this.state.storage.deleteAll();
        return json({ error: "enrollment_expired", message: "Authenticator setup expired. Start again." }, 410);
      }
      if (route !== "confirm" && route !== "unlock") return json({ error: "not_found" }, 404);
      const secrets = await unseal(record.sealed, this.env.TWO_FACTOR_MASTER_KEY_V1, id);
      let step = null;
      let recoveryIndex = -1;
      const code = typeof body.code === "string" ? body.code.trim().toLowerCase().replace(/[- ]/g, "") : "";
      if (equal(record.authHash, authHash)) {
        step = await matchTotp(secrets.totp, code, now, record.lastStep);
        if (record.active && route === "unlock" && /^[a-f0-9]{32}$/.test(code)) {
          const hash2 = await digest(`cmfd-2fa-recovery-v1:${id}:${code}`);
          recoveryIndex = secrets.recovery.findIndex((saved) => equal(saved, hash2));
        }
      }
      if (route === "unlock" && !record.active || step === null && recoveryIndex < 0) {
        record.failures++;
        if (record.failures >= 5) {
          record.failures = 0;
          record.rounds = Math.min(record.rounds + 1, 8);
          record.blockedUntil = now + Math.min(24 * 60, 15 * 2 ** (record.rounds - 1)) * 6e4;
        }
        await this.state.storage.put("record", record);
        return denied();
      }
      if (step !== null) record.lastStep = step;
      if (recoveryIndex >= 0) {
        secrets.recovery.splice(recoveryIndex, 1);
        record.sealed = await seal(secrets, this.env.TWO_FACTOR_MASTER_KEY_V1, id);
      }
      if (!record.active) await registerRecord(this.env, id);
      record.active = true;
      record.failures = record.rounds = record.blockedUntil = 0;
      await this.state.storage.put("record", record);
      await this.state.storage.deleteAlarm();
      return json({ share: secrets.share, recoveryRemaining: secrets.recovery.length });
    });
  }
  async alarm() {
    await this.state.blockConcurrencyWhile(async () => {
      const record = await this.state.storage.get("record");
      if (record && !record.active && record.expires <= Date.now()) await this.state.storage.deleteAll();
    });
  }
};
function backupAuthorized(request, env) {
  const expected = env.TWO_FACTOR_BACKUP_TOKEN;
  const authorization = request.headers.get("Authorization") ?? "";
  return /^[a-f0-9]{64}$/.test(expected ?? "") && equal(authorization, `Bearer ${expected}`);
}
__name(backupAuthorized, "backupAuthorized");
async function registerRecord(env, id) {
  if (!env.WALLET_TWO_FACTOR_CATALOG || !/^[a-f0-9]{64}$/.test(env.TWO_FACTOR_BACKUP_TOKEN ?? "")) throw new Error("Backup catalog unavailable");
  const catalog = env.WALLET_TWO_FACTOR_CATALOG.get(env.WALLET_TWO_FACTOR_CATALOG.idFromName("catalog-v1"));
  const response = await catalog.fetch(new Request("https://internal/register", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.TWO_FACTOR_BACKUP_TOKEN}` },
    body: JSON.stringify({ id })
  }));
  if (!response.ok) throw new Error("Backup catalog unavailable");
}
__name(registerRecord, "registerRecord");
var WalletTwoFactorCatalog = class {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }
  state;
  env;
  static {
    __name(this, "WalletTwoFactorCatalog");
  }
  async fetch(request) {
    if (!backupAuthorized(request, this.env)) return json({ error: "unauthorized" }, 401);
    const url = new URL(request.url);
    if (url.pathname === "/register" && request.method === "POST") {
      const { id } = await request.json();
      if (!/^[a-f0-9]{64}$/.test(id ?? "")) return json({ error: "invalid_id" }, 400);
      await this.state.storage.put(id, true);
      return json({ registered: true });
    }
    if (url.pathname === "/list") {
      const cursor = url.searchParams.get("cursor") ?? "";
      if (cursor && !/^[a-f0-9]{64}$/.test(cursor)) return json({ error: "invalid_cursor" }, 400);
      const entries = await this.state.storage.list({ startAfter: cursor || void 0, limit: 100 });
      const ids = [...entries.keys()];
      return json({ ids, cursor: ids.length === 100 ? ids[ids.length - 1] : null });
    }
    return json({ error: "not_found" }, 404);
  }
};
async function handleTwoFactorBackup(request, env) {
  if (!backupAuthorized(request, env)) return json({ error: "unauthorized" }, 401);
  const url = new URL(request.url);
  const headers = { Authorization: `Bearer ${env.TWO_FACTOR_BACKUP_TOKEN}` };
  try {
    if (url.pathname === "/internal/two-factor/export" && request.method === "GET") {
      const cursor = url.searchParams.get("cursor") ?? "";
      if (cursor && !/^[a-f0-9]{64}$/.test(cursor)) return json({ error: "invalid_cursor" }, 400);
      const catalog = env.WALLET_TWO_FACTOR_CATALOG.get(env.WALLET_TWO_FACTOR_CATALOG.idFromName("catalog-v1"));
      const response = await catalog.fetch(new Request(`https://internal/list?cursor=${cursor}`, { headers }));
      if (!response.ok) return unavailable();
      const page = await response.json();
      const records = [];
      for (const id of page.ids) {
        const object = env.WALLET_TWO_FACTOR.get(env.WALLET_TWO_FACTOR.idFromName(id));
        const result = await object.fetch(new Request("https://internal/internal/snapshot", { headers }));
        if (!result.ok) return unavailable();
        const { record } = await result.json();
        if (record?.active) records.push(record);
      }
      return json({ format: "CMFD-2FA-SERVER-1", exportedAt: (/* @__PURE__ */ new Date()).toISOString(), cursor: page.cursor, records });
    }
    if (url.pathname === "/internal/two-factor/restore" && request.method === "POST") {
      const bytes = await request.arrayBuffer();
      if (bytes.byteLength > 8192) return json({ error: "body_too_large" }, 413);
      const record = JSON.parse(new TextDecoder().decode(bytes));
      if (!record || typeof record.id !== "string" || !/^[a-f0-9]{64}$/.test(record.id)) return json({ error: "invalid_backup_record" }, 400);
      const object = env.WALLET_TWO_FACTOR.get(env.WALLET_TWO_FACTOR.idFromName(record.id));
      return await object.fetch(new Request("https://internal/internal/restore", { method: "POST", headers, body: JSON.stringify(record) }));
    }
    return json({ error: "not_found" }, 404);
  } catch {
    return unavailable();
  }
}
__name(handleTwoFactorBackup, "handleTwoFactorBackup");
async function handleTwoFactor(request, env) {
  const url = new URL(request.url);
  const route = /^\/v1\/2fa\/(enroll|confirm|unlock)$/.exec(url.pathname)?.[1];
  if (!route || url.search) return json({ error: "not_found" }, 404);
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  if (request.headers.get("Origin") !== url.origin) return json({ error: "forbidden_origin" }, 403);
  if (request.headers.get("Content-Type")?.split(";")[0].trim() !== "application/json") return json({ error: "json_required" }, 415);
  if (!env.WALLET_TWO_FACTOR || !env.TWO_FACTOR_LIMIT) return unavailable();
  if (route === "enroll" && env.TWO_FACTOR_ENROLLMENT_DISABLED === "true") {
    return json({ error: "enrollment_paused", message: "New authenticator setup is temporarily unavailable. Existing protected wallets can still unlock." }, 503);
  }
  const { success } = await env.TWO_FACTOR_LIMIT.limit({ key: request.headers.get("CF-Connecting-IP") ?? "unknown" });
  if (!success) return json({ error: "rate_limited", message: "Too many authentication requests. Wait a minute and try again." }, 429);
  const reader = request.body?.getReader();
  if (!reader) return json({ error: "invalid_request" }, 400);
  let length = 0;
  const chunks = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > 2048) {
        await reader.cancel();
        return json({ error: "body_too_large" }, 413);
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    const body = JSON.parse(new TextDecoder().decode(bytes));
    if (!body || typeof body !== "object" || Array.isArray(body) || typeof body.id !== "string" || !/^[a-f0-9]{64}$/.test(body.id) || typeof body.token !== "string" || !/^[a-f0-9]{64}$/.test(body.token) || route !== "enroll" && (typeof body.code !== "string" || body.code.length > 64)) {
      return json({ error: "invalid_request" }, 400);
    }
    const object = env.WALLET_TWO_FACTOR.get(env.WALLET_TWO_FACTOR.idFromName(body.id));
    return await object.fetch(new Request(request.url, { method: "POST", body: JSON.stringify(body) }));
  } catch (error) {
    if (error instanceof SyntaxError) return json({ error: "invalid_json" }, 400);
    return unavailable();
  }
}
__name(handleTwoFactor, "handleTwoFactor");

// worker/index.ts
var EdgeError = class extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
  status;
  code;
  static {
    __name(this, "EdgeError");
  }
};
function json2(body, status = 200) {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}
__name(json2, "json");
function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  if (headers.get("Content-Type")?.startsWith("text/html")) headers.set("Cache-Control", "no-store");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
__name(withSecurityHeaders, "withSecurityHeaders");
async function proxyExplorer(request, env) {
  const url = new URL(request.url);
  if (request.method !== "GET") return json2({ error: "method_not_allowed" }, 405);
  if (url.search || !isExplorerPath(url.pathname)) return json2({ error: "not_found" }, 404);
  const { success } = await env.WALLET_READ_LIMIT.limit({ key: request.headers.get("CF-Connecting-IP") ?? "unknown" });
  if (!success) return json2({ error: "rate_limited", message: "Too many requests from this connection. Wait a minute and try again." }, 429);
  const upstreamUrl = new URL(url.pathname, env.EXPLORER_ORIGIN);
  for (let attempt = 0; ; attempt += 1) {
    let upstream;
    try {
      upstream = await fetch(upstreamUrl, {
        headers: { Accept: "application/json" },
        redirect: "manual",
        signal: AbortSignal.timeout(1e4)
      });
    } catch {
      if (attempt === 0) continue;
      return json2({ error: "explorer_unavailable", message: "The network explorer is unreachable. Try again shortly." }, 503);
    }
    if (upstream.status === 502 && attempt === 0) {
      await upstream.body?.cancel();
      continue;
    }
    const type = upstream.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();
    if (upstream.headers.get(NETWORK_HEADER) !== env.EXPECTED_NETWORK_ID || type !== "application/json") {
      await upstream.body?.cancel();
      return json2({ error: "explorer_identity_rejected", message: "The network explorer did not identify as mainnet." }, 503);
    }
    return new Response(upstream.body, {
      status: upstream.status,
      headers: { "Cache-Control": "no-store", "Content-Type": "application/json", [NETWORK_HEADER]: env.EXPECTED_NETWORK_ID }
    });
  }
}
__name(proxyExplorer, "proxyExplorer");
async function readJsonBody(request) {
  if (request.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    throw new EdgeError(415, "json_required", "Send application/json.");
  }
  const declared = Number(request.headers.get("Content-Length") ?? "0");
  if (!Number.isFinite(declared) || declared > MAX_BODY_BYTES) throw new EdgeError(413, "body_too_large", "The request is too large.");
  const text2 = await request.text();
  if (text2.length > MAX_BODY_BYTES) throw new EdgeError(413, "body_too_large", "The request is too large.");
  try {
    const body = JSON.parse(text2);
    if (body && typeof body === "object" && !Array.isArray(body)) return body;
  } catch {
  }
  throw new EdgeError(400, "invalid_json", "The request body must be a JSON object.");
}
__name(readJsonBody, "readJsonBody");
var isHash = /* @__PURE__ */ __name((value) => typeof value === "string" && HASH.test(value), "isHash");
var isHeight = /* @__PURE__ */ __name((value) => Number.isSafeInteger(value) && value >= 0, "isHeight");
var isIndex = /* @__PURE__ */ __name((value) => Number.isInteger(value) && value >= 0 && value <= 4294967295, "isIndex");
var isAtoms = /* @__PURE__ */ __name((value) => typeof value === "string" && /^(?:0|[1-9][0-9]{0,19})$/.test(value), "isAtoms");
var invalidGatewayResponse = /* @__PURE__ */ __name(() => new EdgeError(502, "gateway_invalid_response", "The network gateway sent an unexpected response."), "invalidGatewayResponse");
function hash(value, field) {
  if (typeof value !== "string" || !HASH.test(value)) throw new EdgeError(400, "invalid_params", `${field} must be 64 lowercase hex characters.`);
  return value;
}
__name(hash, "hash");
async function gateway(env, method, params) {
  let upstream;
  try {
    upstream = await fetch(env.GATEWAY_URL, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Basic ${btoa(`${env.GATEWAY_USERNAME}:${env.GATEWAY_PASSWORD}`)}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      redirect: "manual",
      signal: AbortSignal.timeout(method === "sendrawtransaction" ? 3e4 : 2e4)
    });
  } catch {
    throw new EdgeError(502, "gateway_unavailable", "The network gateway did not answer. If you were sending, check your activity before trying again.");
  }
  if (upstream.status === 429 || upstream.status === 503) {
    await upstream.body?.cancel();
    throw new EdgeError(429, "gateway_busy", "The network gateway is busy. Wait a moment and try again.");
  }
  if (upstream.status !== 200) {
    await upstream.body?.cancel();
    console.error(JSON.stringify({ message: "gateway_status", method, status: upstream.status }));
    throw new EdgeError(502, "gateway_unavailable", "The network gateway is unavailable. If you were sending, check your activity before trying again.");
  }
  const body = await upstream.json().catch(() => null);
  if (body?.error) {
    const code = typeof body.error.data?.code === "string" ? body.error.data.code : "rpc_error";
    const message = typeof body.error.message === "string" ? body.error.message : "The network rejected the request.";
    if (code === "upstream_failure") throw new EdgeError(502, code, message);
    throw new EdgeError(422, code, message);
  }
  if (!body || typeof body.result !== "object" && typeof body.result !== "string") {
    throw new EdgeError(502, "gateway_invalid_response", "The network gateway sent an unexpected response.");
  }
  return typeof body.result === "string" ? { value: body.result } : body.result;
}
__name(gateway, "gateway");
async function walletRoute(request, env, route) {
  const body = await readJsonBody(request);
  if (route === "utxos") {
    const address = hash(body.address, "address");
    const cursor = body.cursor ?? null;
    if (cursor !== null) {
      const value = cursor;
      if (typeof cursor !== "object" || Array.isArray(cursor) || Object.keys(value).sort().join() !== "snapshot,txid,vout") {
        throw new EdgeError(400, "invalid_params", "Invalid cursor.");
      }
      hash(value.snapshot, "cursor.snapshot");
      hash(value.txid, "cursor.txid");
      if (!Number.isInteger(value.vout) || value.vout < 0 || value.vout > 4294967295) {
        throw new EdgeError(400, "invalid_params", "Invalid cursor.");
      }
    }
    const result = await gateway(env, "getaddressutxos", [address, 1e3, cursor]);
    if (result.network_id !== env.EXPECTED_NETWORK_ID || result.destination_hex !== address || !Array.isArray(result.utxos) || !isHeight(result.height)) {
      throw invalidGatewayResponse();
    }
    const utxos = [];
    for (const raw of result.utxos) {
      const utxo = raw ?? {};
      if (utxo.lock_type !== "key" || utxo.destination_hex !== address) continue;
      if (!isHash(utxo.txid) || !isIndex(utxo.vout) || !isAtoms(utxo.value_atoms) || !isHeight(utxo.spendable_height)) {
        throw invalidGatewayResponse();
      }
      utxos.push({ txid: utxo.txid, vout: utxo.vout, value_atoms: utxo.value_atoms, spendable_height: utxo.spendable_height });
    }
    return json2({
      height: result.height,
      utxos,
      has_more: result.has_more === true,
      next_cursor: result.next_cursor ?? null
    });
  }
  if (route === "transaction") {
    const txid = hash(body.txid, "txid");
    const blockId = hash(body.block_id, "block_id");
    const result = await gateway(env, "getrawtransaction", [txid, true, blockId]);
    if (result.txid !== txid || result.network_id !== env.EXPECTED_NETWORK_ID || !Array.isArray(result.vout)) {
      throw invalidGatewayResponse();
    }
    const vout = result.vout.map((raw) => {
      const output = raw ?? {};
      if (!isAtoms(output.value_atoms) || !(output.destination_hex === null || isHash(output.destination_hex))) {
        throw invalidGatewayResponse();
      }
      return { value_atoms: output.value_atoms, destination_hex: output.destination_hex };
    });
    return json2({ vout });
  }
  if (route === "broadcast") {
    const frame = body.transaction_hex;
    if (typeof frame !== "string" || !/^(?:[0-9a-f]{2})+$/.test(frame) || frame.length > 2 * MAX_TRANSACTION_BYTES) {
      throw new EdgeError(400, "invalid_transaction", "The transaction encoding is invalid.");
    }
    if (!frame.startsWith(`${MAINNET_FRAME_PREFIX}01000100`)) {
      throw new EdgeError(400, "wrong_network", "Only Common Foundry mainnet transactions can be sent here.");
    }
    const result = await gateway(env, "sendrawtransaction", [frame]);
    if (typeof result.value !== "string" || !HASH.test(result.value)) {
      throw new EdgeError(502, "gateway_invalid_response", "The network gateway sent an unexpected response.");
    }
    return json2({ txid: result.value });
  }
  return json2({ error: "not_found" }, 404);
}
__name(walletRoute, "walletRoute");
async function handleWallet(request, env) {
  const url = new URL(request.url);
  const route = /^\/v1\/wallet\/(utxos|transaction|broadcast)$/.exec(url.pathname)?.[1];
  if (!route || url.search) return json2({ error: "not_found" }, 404);
  if (request.method !== "POST") return json2({ error: "method_not_allowed" }, 405);
  const origin = request.headers.get("Origin");
  if (origin !== null && origin !== url.origin) return json2({ error: "forbidden_origin" }, 403);
  const client = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const { success } = await env.WALLET_RPC_LIMIT.limit({ key: client });
  if (!success) return json2({ error: "rate_limited", message: "Too many requests from this connection. Wait a minute and try again." }, 429);
  try {
    return await walletRoute(request, env, route);
  } catch (cause) {
    if (cause instanceof EdgeError) return json2({ error: cause.code, message: cause.message }, cause.status);
    console.error(JSON.stringify({ message: "wallet_route_failed", route, error: cause instanceof Error ? cause.name : "unknown" }));
    return json2({ error: "internal_error", message: "The wallet service failed unexpectedly." }, 500);
  }
}
__name(handleWallet, "handleWallet");
var index_default = {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const response = pathname.startsWith("/internal/two-factor/") ? await handleTwoFactorBackup(request, env) : pathname.startsWith("/v1/2fa/") ? await handleTwoFactor(request, env) : pathname.startsWith("/v1/wallet/") ? await handleWallet(request, env) : pathname.startsWith("/v1/") ? await proxyExplorer(request, env) : await env.ASSETS.fetch(request);
    return withSecurityHeaders(response);
  }
};
export {
  WalletTwoFactor,
  WalletTwoFactorCatalog,
  index_default as default
};
