import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { AddressDetail } from "./AddressDetail";
import { ExplorerRequestError, loadAddress } from "../api";
import { addressFixture, fixtureAddress, fixtureTip } from "../test/addressFixture";
import type { ExplorerAddress } from "../types";

vi.mock("../api", async (original) => ({ ...await original<typeof import("../api")>(), loadAddress: vi.fn() }));
beforeEach(() => vi.mocked(loadAddress).mockReset());
const props = () => ({ initial: addressFixture(), liveTip: fixtureTip, onBack: vi.fn(), onBlock: vi.fn(), onTransaction: vi.fn() });

test("shows exact balances and explains change and pending-transfer scope", () => {
  render(<AddressDetail {...props()} />);
  expect(screen.getByRole("heading", { name: "Address" })).toBeInTheDocument();
  expect(screen.getByText("12,345.67 CMFD")).toBeInTheDocument();
  expect(screen.getByText(/Pending transfers and channel escrow are excluded/)).toBeInTheDocument();
  expect(screen.getByText(/including change—not net payment amounts/)).toBeInTheDocument();
});

test("older and newer pages replace history without duplicates", async () => {
  vi.mocked(loadAddress).mockResolvedValueOnce(addressFixture({ start: 80, count: 3 })).mockResolvedValueOnce(addressFixture());
  render(<AddressDetail {...props()} />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Older activity" }));
  expect(await screen.findByText("Page 2 · newest first")).toBeInTheDocument();
  expect(screen.getAllByRole("article")).toHaveLength(3);
  expect(screen.getByRole("button", { name: "Older activity" })).toBeDisabled();
  expect(loadAddress).toHaveBeenNthCalledWith(1, fixtureAddress, addressFixture().next_cursor);
  await user.click(screen.getByRole("button", { name: "Newer activity" }));
  expect(await screen.findByText("Page 1 · newest first")).toBeInTheDocument();
  expect(screen.getAllByRole("article")).toHaveLength(20);
  expect(loadAddress).toHaveBeenNthCalledWith(2, fixtureAddress, null);
});

test("stale cursors clear the old page and recover with a fresh first page", async () => {
  const newest = addressFixture({ tip: "e2".repeat(32), height: 101 });
  vi.mocked(loadAddress).mockRejectedValueOnce(new ExplorerRequestError("Restart", 409, "explorer_cursor_stale")).mockResolvedValueOnce(newest);
  render(<AddressDetail {...props()} />);
  await userEvent.setup().click(screen.getByRole("button", { name: "Older activity" }));
  expect(await screen.findByText(/As of block #101\./)).toBeInTheDocument();
  expect(screen.getByText("Page 1 · newest first")).toBeInTheDocument();
  expect(screen.getByText("The chain changed. Showing the newest activity.")).toBeInTheDocument();
  expect(loadAddress).toHaveBeenNthCalledWith(2, fixtureAddress);
});

test("a slow older page cannot overwrite a newer tip refresh", async () => {
  let finishOld: ((value: ExplorerAddress) => void) | undefined;
  vi.mocked(loadAddress).mockReturnValueOnce(new Promise((resolve) => { finishOld = resolve; }))
    .mockResolvedValueOnce(addressFixture({ tip: "e2".repeat(32), height: 101 }));
  const initialProps = props();
  const view = render(<AddressDetail {...initialProps} />);
  await userEvent.setup().click(screen.getByRole("button", { name: "Older activity" }));
  expect(screen.getByRole("button", { name: "Older activity" })).toBeDisabled();
  view.rerender(<AddressDetail {...initialProps} liveTip={"e2".repeat(32)} />);
  await screen.findByText(/As of block #101\./);
  await act(async () => finishOld?.(addressFixture({ start: 80, count: 3 })));
  expect(screen.getByText(/As of block #101\./)).toBeInTheDocument();
  expect(screen.queryByText("Page 2 · newest first")).not.toBeInTheDocument();
});

test("connection errors remove stale balances and Retry loads the newest page", async () => {
  vi.mocked(loadAddress).mockRejectedValueOnce(new Error("different network")).mockResolvedValueOnce(addressFixture());
  render(<AddressDetail {...props()} />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Older activity" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("different network");
  expect(screen.queryByText("Confirmed balance")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Retry latest activity" }));
  expect(await screen.findByText("Confirmed balance")).toBeInTheDocument();
  expect(screen.getByText("Page 1 · newest first")).toBeInTheDocument();
});

test("empty addresses show no activity and cannot page past the end", () => {
  const empty = { ...addressFixture({ count: 0 }), confirmed_atoms: "0", spendable_atoms: "0", immature_atoms: "0", utxo_count: 0 };
  render(<AddressDetail {...props()} initial={empty} />);
  expect(screen.getByText("No confirmed activity for this address.")).toBeInTheDocument();
  expect(screen.getAllByText("0 CMFD")).toHaveLength(3);
  expect(screen.getByRole("button", { name: "Older activity" })).toBeDisabled();
});

test("reward records link to their blocks, while transfers link to transactions", async () => {
  const initialProps = props();
  initialProps.initial.history[0].kind = "coinbase";
  render(<AddressDetail {...initialProps} />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /^Open reward block/ }));
  expect(initialProps.onBlock).toHaveBeenCalledWith(initialProps.initial.history[0].block_id);
  expect(initialProps.onTransaction).not.toHaveBeenCalled();
  await user.click(screen.getAllByRole("button", { name: /^Open transaction/ })[0]);
  expect(initialProps.onTransaction).toHaveBeenCalledWith(initialProps.initial.history[1].txid);
});
