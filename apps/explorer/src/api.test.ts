// @vitest-environment node
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { MAINNET_NETWORK_ID, NETWORK_HEADER } from "../shared/network";
import { demoBlock, demoSnapshot, demoTransactions } from "./demoData";
import { addressFixture, fixtureAddress } from "./test/addressFixture";

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

test("validates address identity and uses the exact cursor route", async () => {
  const page = addressFixture();
  const next = addressFixture({ start: 80, count: 3 });
  const upstream = vi.fn().mockResolvedValueOnce(identified(page)).mockResolvedValueOnce(identified(next));
  vi.stubGlobal("fetch", upstream);
  const api = await import("./api");
  expect(await api.loadAddress(fixtureAddress.toUpperCase())).toEqual(page);
  expect(await api.loadAddress(fixtureAddress, page.next_cursor)).toEqual(next);
  expect(upstream.mock.calls.map(([path]) => path)).toEqual([
    `/v1/explorer/address/${fixtureAddress}`, `/v1/explorer/address/${fixtureAddress}/${page.next_cursor}`,
  ]);
});

test("preserves authenticated address stale-cursor errors", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json({ error: "Restart pagination", code: "explorer_cursor_stale", retryable: true }, {
    status: 409, headers: { [NETWORK_HEADER]: MAINNET_NETWORK_ID },
  })));
  const api = await import("./api");
  await expect(api.loadAddress(fixtureAddress)).rejects.toMatchObject({ status: 409, code: "explorer_cursor_stale", message: "Restart pagination" });
});

test.each([200, 409])("rejects different-network address responses even with status %s", async (status) => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json(addressFixture(), { status, headers: { [NETWORK_HEADER]: "63".repeat(32) } })));
  const api = await import("./api");
  await expect(api.loadAddress(fixtureAddress)).rejects.toThrow("different network");
});

test("never substitutes another address, tip or preview balance", async () => {
  const upstream = vi.fn().mockResolvedValueOnce(identified(addressFixture({ address: "b2".repeat(32) })))
    .mockResolvedValueOnce(identified(addressFixture({ tip: "e2".repeat(32) })));
  vi.stubGlobal("fetch", upstream);
  const api = await import("./api");
  await expect(api.loadAddress(fixtureAddress)).rejects.toThrow("requested address or chain tip");
  await expect(api.loadAddress(fixtureAddress, addressFixture().next_cursor)).rejects.toThrow("requested address or chain tip");
  await expect(api.loadAddress(fixtureAddress, null, true)).rejects.toThrow("preview balances are never generated");
  await expect(api.loadAddress("invalid")).rejects.toThrow("valid address");
  await expect(api.loadAddress(fixtureAddress, `${"d1".repeat(32)}.1.1025`)).rejects.toThrow("valid address");
  expect(upstream).toHaveBeenCalledTimes(2);
});

test.each([
  { confirmed_atoms: "1" }, { confirmed_atoms: "-1" }, { confirmed_atoms: "9".repeat(40) },
  { includes_mempool: true }, { balance_scope: "all_assets" }, { page_limit: 1000000 },
  { next_cursor: null }, { next_cursor: `${"e1".repeat(32)}.81.1` },
  { history: [addressFixture().history[0], addressFixture().history[0]] },
  { history: [{ ...addressFixture().history[0], confirmations: 0 }] },
])("rejects inconsistent address response %j", async (mutation) => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(identified({ ...addressFixture(), ...mutation })));
  const api = await import("./api");
  await expect(api.loadAddress(fixtureAddress)).rejects.toThrow("invalid data");
});

test("supports exact u128 totals without converting them through Number", async () => {
  const large = 1n << 80n;
  const data = { ...addressFixture(), confirmed_atoms: (large + 1n).toString(), spendable_atoms: large.toString(), immature_atoms: "1" };
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(identified(data)));
  const api = await import("./api");
  expect((await api.loadAddress(fixtureAddress)).confirmed_atoms).toBe((large + 1n).toString());
});
