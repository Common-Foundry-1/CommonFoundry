// Request policy shared by the Worker and its tests. Kept out of index.ts because workerd
// treats every export of the main module as an entrypoint.

export const NETWORK_HEADER = "X-CMFD-Network-Id";
/** First four bytes of BLAKE3-derive-key("CMFD/WIRE/NETWORK-MAGIC/V1", mainnet id); pinned by tests. */
export const MAINNET_FRAME_PREFIX = "434d46446702973f";
export const HASH = /^[0-9a-f]{64}$/;
export const MAX_TRANSACTION_BYTES = 64 * 1024;
export const MAX_BODY_BYTES = 2 * MAX_TRANSACTION_BYTES + 1024;

const SNAPSHOT_PATH = "/v1/explorer";
const TRANSACTION_PATH = /^\/v1\/explorer\/transaction\/[0-9a-f]{64}$/;
const ADDRESS_PATH = /^\/v1\/explorer\/address\/[0-9a-f]{64}$/;

export function isExplorerPath(pathname: string): boolean {
  return pathname === SNAPSHOT_PATH || TRANSACTION_PATH.test(pathname) || ADDRESS_PATH.test(pathname);
}

// No third-party script, frame, or connection is ever allowed: this page holds signing keys.
export const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};
