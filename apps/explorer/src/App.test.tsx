import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import App from "./App";
import { ExplorerRequestError, loadAddress, loadBlock, loadExplorer, loadTransaction, type ExplorerLoad } from "./api";
import { demoBlock, demoSnapshot } from "./demoData";
import { MAINNET_HRP, TEST_NETWORK_HRP, encode } from "./lib/addressCodec";
import { addressFixture, fixtureAddress } from "./test/addressFixture";
import type { ExplorerAddress } from "./types";

vi.mock("./api", async (original) => {
  const { demoSnapshot } = await import("./demoData");
  return { ...await original<typeof import("./api")>(), MAINNET_MODE: false, loadExplorer: vi.fn().mockResolvedValue({ data: demoSnapshot, preview: true }), loadBlock: vi.fn(), loadTransaction: vi.fn(), loadAddress: vi.fn() };
});

beforeEach(() => {
  vi.mocked(loadExplorer).mockReset().mockResolvedValue({ data: demoSnapshot, preview: true });
  vi.mocked(loadAddress).mockReset().mockResolvedValue(addressFixture());
  vi.mocked(loadBlock).mockReset(); vi.mocked(loadTransaction).mockReset();
  vi.spyOn(window, "scrollTo").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

function capturePoll() {
  let poll: (() => void) | undefined;
  const original = window.setInterval.bind(window);
  vi.spyOn(window, "setInterval").mockImplementation((handler, delay) => {
    if (delay === 10_000 && typeof handler === "function") { poll = () => handler(); return -1; }
    return original(handler, delay);
  });
  return () => { if (!poll) throw new Error("Refresh interval missing"); poll(); };
}

test("renders the branded explorer overview", async () => {
  render(<App />);
  expect(await screen.findByRole("heading", { name: "The chain, as it happens." })).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Latest blocks" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /pause/i })).toBeInTheDocument();
});

test("pauses and resumes the forge cycle", async () => {
  const user = userEvent.setup();
  const view = render(<App />);
  const explorer = within(view.container);

  const pause = await explorer.findByRole("button", { name: "Pause" });
  await user.click(pause);
  expect(explorer.getByRole("button", { name: "Resume" })).toHaveAttribute("aria-pressed", "true");
  expect(explorer.getByRole("region", { name: "Live transaction forging visualization" })).toHaveClass("is-paused");

  await user.click(explorer.getByRole("button", { name: "Resume" }));
  expect(explorer.getByRole("button", { name: "Pause" })).toHaveAttribute("aria-pressed", "false");
});

test("removes stale live data on a failed refresh and recovers through Retry", async () => {
  const poll = capturePoll();
  vi.mocked(loadExplorer).mockResolvedValueOnce({ data: demoSnapshot, preview: false })
    .mockRejectedValueOnce(new Error("network identity rejected"));
  render(<App />);
  expect(await screen.findByRole("heading", { name: "The chain, as it happens." })).toBeInTheDocument();
  await act(async () => { poll(); });
  expect(await screen.findByText("Explorer unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Latest blocks" })).not.toBeInTheDocument();
  await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
  expect(await screen.findByRole("heading", { name: "Latest blocks" })).toBeInTheDocument();
});

test("an older response cannot overwrite a newer connection failure", async () => {
  const poll = capturePoll();
  let resolveEarlier: ((value: ExplorerLoad) => void) | undefined;
  const earlier = new Promise<ExplorerLoad>((resolve) => { resolveEarlier = resolve; });
  vi.mocked(loadExplorer).mockRejectedValueOnce(new Error("initially offline"))
    .mockReturnValueOnce(earlier).mockRejectedValueOnce(new Error("offline"));
  render(<App />);
  await screen.findByText("Explorer unavailable");
  await act(async () => { poll(); });
  await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
  expect(await screen.findByText("Explorer unavailable")).toBeInTheDocument();
  await act(async () => { resolveEarlier?.({ data: demoSnapshot, preview: false }); });
  expect(screen.getByText("Explorer unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Latest blocks" })).not.toBeInTheDocument();
});

test("automatic polling does not starve a slow successful response", async () => {
  const poll = capturePoll();
  let complete: ((value: ExplorerLoad) => void) | undefined;
  vi.mocked(loadExplorer).mockReturnValueOnce(new Promise<ExplorerLoad>((resolve) => { complete = resolve; }));
  render(<App />);
  await act(async () => { poll(); poll(); });
  expect(loadExplorer).toHaveBeenCalledTimes(1);
  await act(async () => { complete?.({ data: demoSnapshot, preview: false }); });
  expect(await screen.findByRole("heading", { name: "Latest blocks" })).toBeInTheDocument();
});

test("navigation closes after choosing a section", async () => {
  render(<App />);
  await screen.findByRole("heading", { name: "Latest blocks" });
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Toggle navigation" }));
  expect(screen.getByRole("navigation", { name: "Explorer navigation" })).toHaveClass("is-open");
  await user.click(screen.getByRole("link", { name: "Network" }));
  expect(screen.getByRole("navigation", { name: "Explorer navigation" })).not.toHaveClass("is-open");
});

test("explicit Address search avoids block/transaction hash ambiguity", async () => {
  vi.mocked(loadExplorer).mockResolvedValue({ data: demoSnapshot, preview: false });
  render(<App />);
  await screen.findByRole("heading", { name: "Latest blocks" });
  const user = userEvent.setup();
  await user.selectOptions(screen.getByRole("combobox", { name: "Search type" }), "address");
  await user.type(screen.getByRole("textbox", { name: "Search wallet address" }), fixtureAddress);
  await user.click(screen.getByRole("button", { name: "Search" }));
  expect(await screen.findByRole("heading", { name: "Address" })).toBeInTheDocument();
  expect(loadAddress).toHaveBeenCalledWith(fixtureAddress, null, false);
  expect(loadBlock).not.toHaveBeenCalled(); expect(loadTransaction).not.toHaveBeenCalled();
});

test("a delayed address search cannot return after the user goes home", async () => {
  let finish: ((value: ExplorerAddress) => void) | undefined;
  vi.mocked(loadExplorer).mockResolvedValue({ data: demoSnapshot, preview: false });
  vi.mocked(loadAddress).mockReturnValue(new Promise((resolve) => { finish = resolve; }));
  render(<App />);
  await screen.findByRole("heading", { name: "Latest blocks" });
  const user = userEvent.setup();
  await user.selectOptions(screen.getByRole("combobox", { name: "Search type" }), "address");
  await user.type(screen.getByRole("textbox", { name: "Search wallet address" }), fixtureAddress + "{Enter}");
  expect(await screen.findByText("Looking up chain data…")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Explorer overview" }));
  await act(async () => finish?.(addressFixture()));
  expect(screen.getByRole("heading", { name: "Latest blocks" })).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Address" })).not.toBeInTheDocument();
});

test("a connection failure invalidates a pending address result", async () => {
  const poll = capturePoll();
  let finish: ((value: ExplorerAddress) => void) | undefined;
  vi.mocked(loadExplorer).mockResolvedValueOnce({ data: demoSnapshot, preview: false }).mockRejectedValueOnce(new Error("offline"));
  vi.mocked(loadAddress).mockReturnValue(new Promise((resolve) => { finish = resolve; }));
  render(<App />);
  await screen.findByRole("heading", { name: "Latest blocks" });
  const user = userEvent.setup();
  await user.selectOptions(screen.getByRole("combobox", { name: "Search type" }), "address");
  await user.type(screen.getByRole("textbox", { name: "Search wallet address" }), fixtureAddress + "{Enter}");
  await act(async () => poll());
  await act(async () => finish?.(addressFixture()));
  expect(screen.getByText("Explorer unavailable")).toBeInTheDocument();
  expect(screen.queryByText("Confirmed balance")).not.toBeInTheDocument();
});

test("hash search falls back only for not-found, never for an identity failure", async () => {
  vi.mocked(loadExplorer).mockResolvedValue({ data: demoSnapshot, preview: false });
  vi.mocked(loadBlock).mockRejectedValueOnce(new Error("different network"))
    .mockRejectedValueOnce(new ExplorerRequestError("not found", 404));
  vi.mocked(loadTransaction).mockRejectedValueOnce(new ExplorerRequestError("transaction not found", 404));
  render(<App />);
  await screen.findByRole("heading", { name: "Latest blocks" });
  const user = userEvent.setup();
  await user.type(screen.getByRole("textbox", { name: /Search block height/ }), fixtureAddress + "{Enter}");
  expect(await screen.findByRole("alert")).toHaveTextContent("different network");
  expect(loadTransaction).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Search" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("transaction not found");
  expect(loadTransaction).toHaveBeenCalledWith(fixtureAddress, false);
});

async function searchAs(kind: "chain" | "address", query: string) {
  vi.mocked(loadExplorer).mockResolvedValue({ data: demoSnapshot, preview: false });
  render(<App />);
  await screen.findByRole("heading", { name: "Latest blocks" });
  const user = userEvent.setup();
  if (kind === "address") await user.selectOptions(screen.getByRole("combobox", { name: "Search type" }), "address");
  await user.type(screen.getByRole("textbox", { name: kind === "address" ? "Search wallet address" : /Search block height/ }), query + "{Enter}");
}

test.each([
  ["address", encode(TEST_NETWORK_HRP, fixtureAddress)],
  ["address", encode(TEST_NETWORK_HRP, fixtureAddress).toUpperCase()],
  ["chain", encode(TEST_NETWORK_HRP, fixtureAddress)],
  ["address", fixtureAddress.toUpperCase()],
] as const)("a checksummed address (%s search) is looked up by its hex key", async (kind, query) => {
  await searchAs(kind, query);
  expect(await screen.findByRole("heading", { name: "Address" })).toBeInTheDocument();
  expect(loadAddress).toHaveBeenCalledWith(fixtureAddress, null, false);
  expect(loadBlock).not.toHaveBeenCalled(); expect(loadTransaction).not.toHaveBeenCalled();
  expect(screen.getByLabelText("Checksummed address")).toHaveTextContent(encode(TEST_NETWORK_HRP, fixtureAddress));
});

test.each([
  ["address", encode(TEST_NETWORK_HRP, fixtureAddress).slice(0, -1) + "q", "Address checksum does not match: the address is mistyped or incomplete."],
  ["chain", encode(MAINNET_HRP, fixtureAddress), "Address is for another network: expected tcmfd1..., found cmfd1..."],
  ["address", fixtureAddress.slice(0, 40), "Expected a tcmfd1... address or 64 lowercase hexadecimal characters encoding an x-only public key."],
] as const)("a bad address (%s search %s) is explained without a lookup", async (kind, query, message) => {
  await searchAs(kind, query);
  expect(await screen.findByRole("alert")).toHaveTextContent(message);
  expect(loadAddress).not.toHaveBeenCalled(); expect(loadBlock).not.toHaveBeenCalled();
});

test("labels blocks and activity above the validated height as Verifying", async () => {
  const user = userEvent.setup();
  // Statuses stay "confirmed"; the label comes from the validated height alone.
  const checking = { ...demoSnapshot, validated_height: 158 };
  vi.mocked(loadExplorer).mockResolvedValue({ data: checking, preview: false });
  const view = render(<App />);
  expect(await screen.findByText(/This node is still checking blocks above #158\./)).toBeInTheDocument();
  const rows = within(view.container.querySelector("#blocks") as HTMLElement).getAllByRole("row").slice(1);
  expect(rows.map((row) => within(row).queryByText("Verifying") !== null)).toEqual([true, true, false, false, false]);
  const rail = within(view.container.querySelector("#transactions") as HTMLElement);
  expect(rail.getAllByText("Verifying")).toHaveLength(2);

  // A transaction opened from the list keeps the snapshot's validated height.
  const above = checking.recent_transactions.find((tx) => tx.block_height === 160);
  await user.click(rail.getAllByRole("button").find((button) => button.textContent?.includes(above!.txid.slice(0, 11)))!);
  expect(await screen.findByText("In a block still being checked")).toBeInTheDocument();
  expect(screen.queryByText(/Canonical/)).not.toBeInTheDocument();
  await user.click(view.container.querySelector(".back-button") as HTMLElement);

  const held = { ...demoBlock(checking.latest_blocks[0]), validated_height: 158 };
  vi.mocked(loadBlock).mockResolvedValueOnce(held);
  await user.click(within(view.container.querySelector("#blocks") as HTMLElement).getAllByRole("row")[1]);
  expect(await screen.findByRole("heading", { name: "Block #160" })).toBeInTheDocument();
  expect(screen.getByText("Verifying")).toBeInTheDocument();
  expect(screen.getByText(/this node is still re-executing its work/)).toBeInTheDocument();
  expect(screen.queryByText(/Verified by consensus/)).not.toBeInTheDocument();
});

test("labels a transaction found by id from the validated height it carries", async () => {
  const confirmed = demoSnapshot.recent_transactions.find((tx) => tx.block_height === 160)!;
  for (const [validated_height, label] of [[159, "In a block still being checked"], [160, "Confirmed transaction"], [undefined, "Confirmed transaction"]] as const) {
    vi.mocked(loadExplorer).mockResolvedValue({ data: demoSnapshot, preview: false });
    vi.mocked(loadBlock).mockRejectedValueOnce(new ExplorerRequestError("block not found", 404));
    vi.mocked(loadTransaction).mockResolvedValueOnce({ ...confirmed, validated_height });
    const view = render(<App />);
    await screen.findByRole("heading", { name: "Latest blocks" });
    await userEvent.setup().type(screen.getByRole("textbox", { name: /Search block height/ }), confirmed.txid + "{Enter}");
    expect(await screen.findByText(label)).toBeInTheDocument();
    view.unmount();
  }
});

test("shows no Verifying label once the validated height reaches the tip, or without it", async () => {
  for (const validated of [160, null, undefined]) {
    vi.mocked(loadExplorer).mockResolvedValue({ data: { ...demoSnapshot, validated_height: validated }, preview: false });
    const view = render(<App />);
    expect(await within(view.container).findByRole("heading", { name: "Latest blocks" })).toBeInTheDocument();
    expect(within(view.container).queryByText("Verifying")).not.toBeInTheDocument();
    expect(within(view.container).queryByText(/still checking/)).not.toBeInTheDocument();
    view.unmount();
  }
});
