import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { RichList, supplyShare } from "./RichList";
import type { RichList as RichListData } from "../types";

const steward = "5321229f3d3e3fccb900f95c7baee2b27a929afe70f95a0bde0394dba79c9684";
const holder = "ab".repeat(32);
const list: RichListData = {
  height: 14800, block_hash: "cd".repeat(32), generated_at: 1791900000, total_supply_atoms: "737100000000000",
  addresses_with_balance: 4321,
  top: [
    { rank: 1, address: steward, label: "steward fund", balance_atoms: "150000000000000", outputs: 14800 },
    { rank: 2, address: holder, label: null, balance_atoms: "900000000", outputs: 1 },
  ],
};

test("a balance's share of the supply is rounded to two decimals", () => {
  expect(supplyShare("150000000000000", "737100000000000")).toBe("20.35%");
  expect(supplyShare("1", "737100000000000")).toBe("0.00%");
  expect(supplyShare("737100000000000", "737100000000000")).toBe("100.00%");
  expect(supplyShare("1", "0")).toBe("—");
});

test("lists the largest balances with the fund labels and opens an address", async () => {
  const onAddress = vi.fn();
  render(<RichList list={list} onBack={vi.fn()} onAddress={onAddress} />);
  expect(screen.getByRole("heading", { name: "Rich list" })).toBeInTheDocument();
  expect(screen.getByText(/as of block #14,800 · 4,321 addresses hold CMFD/)).toBeInTheDocument();
  expect(screen.getByText("Steward fund")).toBeInTheDocument();
  expect(screen.getByText("1,500,000 CMFD")).toBeInTheDocument();
  expect(screen.getByText("9 CMFD")).toBeInTheDocument();
  expect(screen.getByText("1 output")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: `Open address ${holder}` }));
  expect(onAddress).toHaveBeenCalledWith(holder);
});
