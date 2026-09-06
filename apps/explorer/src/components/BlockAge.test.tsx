import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { demoBlock, demoSnapshot } from "../demoData";
import { BlockDetail } from "./DetailViews";
import { Overview } from "./Overview";

const now = Date.UTC(2026, 8, 6, 20);
const block = { ...demoSnapshot.latest_blocks[0], timestamp: 1788800406, accepted_at: now / 1000 - 125 };
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

test("block age uses recorded acceptance even when the consensus timestamp is tomorrow", () => {
  vi.spyOn(Date, "now").mockReturnValue(now);
  render(<Overview snapshot={{ ...demoSnapshot, latest_blocks: [block], recent_transactions: [] }} preview={false} onBlock={vi.fn()} onTransaction={vi.fn()} />);
  const row = screen.getByRole("row", { name: /#160/ });
  expect(within(row).getByText("2m ago")).toHaveAttribute("title", "Time since this explorer node accepted the block.");
  expect(within(row).queryByText("0s ago")).not.toBeInTheDocument();
});

test("block detail distinguishes local acceptance from the unchanged block timestamp", () => {
  vi.spyOn(Date, "now").mockReturnValue(now);
  render(<BlockDetail block={demoBlock(block)} onBack={vi.fn()} onTransaction={vi.fn()} />);
  expect(screen.getByText(/Accepted by explorer 2m ago/)).toBeInTheDocument();
  expect(screen.getByText(new Date(block.timestamp * 1000).toLocaleString())).toBeInTheDocument();
  expect(screen.getByText(new Date(block.accepted_at * 1000).toLocaleString())).toBeInTheDocument();
});

test("older nodes show their future block time without inventing an acceptance age", () => {
  vi.spyOn(Date, "now").mockReturnValue(now);
  render(<BlockDetail block={demoBlock({ ...block, accepted_at: undefined })} onBack={vi.fn()} onTransaction={vi.fn()} />);
  expect(screen.getByText(/Block time in 21h/)).toBeInTheDocument();
  expect(screen.queryByText("Explorer accepted")).not.toBeInTheDocument();
});
