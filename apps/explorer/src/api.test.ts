// @vitest-environment node
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { MAINNET_NETWORK_ID, NETWORK_HEADER } from "../shared/network";
import { demoBlock, demoSnapshot, demoTransactions } from "./demoData";

const mainnetSnapshot = { ...demoSnapshot, network: "CommonFoundry Mainnet", network_short_name: "Mainnet", network_id: MAINNET_NETWORK_ID };
const identified = (data: unknown, pin = MAINNET_NETWORK_ID) => Response.json(data, { headers: { [NETWORK_HEADER]: pin } });

beforeEach(() => {
  vi.resetModules();
  vi.stubEnv("VITE_EXPLORER_NETWORK", "mainnet");
  vi.stubEnv("DEV", true);
});
afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

test("accepts only matching mainnet header and snapshot identity", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(identified(mainnetSnapshot)));
  const api = await import("./api");
  expect(await api.loadExplorer()).toEqual({ data: mainnetSnapshot, preview: false });
});

test.each([undefined, "63".repeat(32)])("mainnet rejects absent or RC headers even in development", async (pin) => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(pin ? identified(mainnetSnapshot, pin) : Response.json(mainnetSnapshot)));
  const api = await import("./api");
  await expect(api.loadExplorer()).rejects.toThrow("No verified mainnet connection");
});

test("rejects RC snapshot data even when its header falsely claims mainnet", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(identified(demoSnapshot)));
  const api = await import("./api");
  await expect(api.loadExplorer()).rejects.toThrow("different network");
});

test.each([{}, { ...mainnetSnapshot, accepted_height: -1 }, { ...mainnetSnapshot, latest_blocks: null }])(
  "rejects malformed data before rendering", async (data) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(identified(data)));
    const api = await import("./api");
    await expect(api.loadExplorer()).rejects.toThrow("invalid data");
  },
);

test("mainnet never falls back to sample blocks or transactions", async () => {
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
  const api = await import("./api");
  await expect(api.loadExplorer()).rejects.toThrow("No verified mainnet connection");
  await expect(api.loadBlock("42", true)).rejects.toThrow("never uses preview");
  await expect(api.loadTransaction("ab".repeat(32), true)).rejects.toThrow("never uses preview");
});

test("checks detail response identity and validates block/transaction shapes", async () => {
  const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
  const api = await import("./api");
  const block = demoBlock(demoSnapshot.latest_blocks[0]);
  upstream.mockResolvedValueOnce(identified(block));
  expect(await api.loadBlock(block.block_id, false)).toEqual(block);
  upstream.mockResolvedValueOnce(identified(demoTransactions[0], "63".repeat(32)));
  await expect(api.loadTransaction(demoTransactions[0].txid, false)).rejects.toThrow("different network");
  upstream.mockResolvedValueOnce(identified({ ...demoTransactions[0], output_atoms: "not-a-number" }));
  await expect(api.loadTransaction(demoTransactions[0].txid, false)).rejects.toThrow("invalid data");
});

test("retains labelled preview only for ordinary development", async () => {
  vi.stubEnv("VITE_EXPLORER_NETWORK", "rc");
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
  const api = await import("./api");
  expect((await api.loadExplorer()).preview).toBe(true);
  vi.stubEnv("DEV", false);
  await expect(api.loadExplorer()).rejects.toThrow("unavailable");
});
