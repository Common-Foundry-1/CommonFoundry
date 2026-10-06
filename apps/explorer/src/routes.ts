import { ADDRESS_HASH } from "../shared/address";
import type { ExplorerView } from "./types";

/** A page the explorer can open directly from its URL path. */
export type ExplorerRoute =
  | { kind: "overview" }
  | { kind: "block"; query: string }
  | { kind: "transaction"; txid: string }
  | { kind: "address"; address: string };

const HEIGHT = /^\d{1,20}$/;
const MAX_HEIGHT = 18_446_744_073_709_551_615n;

/** Maps a location path to a route, or `null` when the path names nothing the explorer serves. */
export function parseRoute(pathname: string): ExplorerRoute | null {
  const segments = pathname.split("/").filter((segment) => segment.length > 0);
  if (segments.length === 0) return { kind: "overview" };
  if (segments.length !== 2) return null;
  let value: string;
  try { value = decodeURIComponent(segments[1]); } catch { return null; }
  switch (segments[0]) {
    case "block":
      if (HEIGHT.test(value) && BigInt(value) <= MAX_HEIGHT) return { kind: "block", query: value };
      return ADDRESS_HASH.test(value) ? { kind: "block", query: value.toLowerCase() } : null;
    case "tx":
    case "transaction":
      return ADDRESS_HASH.test(value) ? { kind: "transaction", txid: value.toLowerCase() } : null;
    case "address":
      return ADDRESS_HASH.test(value) ? { kind: "address", address: value.toLowerCase() } : null;
    default:
      return null;
  }
}

/** The canonical path for a loaded view, used for the address bar and shareable links. */
export function viewPath(view: ExplorerView): string {
  switch (view.kind) {
    case "overview": return "/";
    case "block": return `/block/${view.block.block_id}`;
    case "transaction": return `/tx/${view.transaction.txid}`;
    case "address": return `/address/${view.address.address.toLowerCase()}`;
  }
}
