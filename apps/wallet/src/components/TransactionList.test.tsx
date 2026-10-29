import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NodeApiError } from "../api/nodeClient";
import type { WalletHistoryEntry } from "../types";
import { TransactionList } from "./TransactionList";

const explorerApi = vi.hoisted(() => ({ open: vi.fn() }));

vi.mock("../api/nodeClient", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/nodeClient")>()),
  openTransactionInExplorer: explorerApi.open,
}));

afterEach(() => cleanup());

function sentEntry(overrides: Partial<WalletHistoryEntry> = {}): WalletHistoryEntry {
  return {
    kind: "sent",
    txid: "ab".repeat(32),
    height: 17,
    timestamp: 1_775_000_000,
    confirmations: 3,
    status: "confirmed",
    net_amount_atoms: "-1000",
    fee_burned_atoms: "1000",
    counterparty: null,
    ...overrides,
  };
}

describe("TransactionList", () => {
  beforeEach(() => {
    explorerApi.open.mockReset().mockResolvedValue(undefined);
  });

  it("opens a transaction on the block explorer by click or keyboard", async () => {
    const user = userEvent.setup();
    const txid = "cd".repeat(32);
    render(<TransactionList entries={[sentEntry({ txid, counterparty: "ef".repeat(32), net_amount_atoms: "-2000" })]} />);

    const row = screen.getByRole("button", { name: /Sent CMFD/ });
    expect(row).toHaveAttribute("title", "View on the block explorer");
    await user.click(row);
    expect(explorerApi.open).toHaveBeenCalledWith(txid);

    row.focus();
    await user.keyboard("{Enter}");
    await user.keyboard(" ");
    expect(explorerApi.open).toHaveBeenCalledTimes(3);
    expect(explorerApi.open).toHaveBeenLastCalledWith(txid);
  });

  it("says why the explorer could not be opened", async () => {
    const user = userEvent.setup();
    explorerApi.open.mockRejectedValueOnce(new NodeApiError("The block explorer shows Mainnet transactions only.", 501, "explorer_unavailable"));
    render(<TransactionList entries={[sentEntry()]} />);

    await user.click(screen.getByRole("button", { name: /Wallet maintenance/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("The block explorer shows Mainnet transactions only.");

    await user.click(screen.getByRole("button", { name: /Wallet maintenance/ }));
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
  });

  it("renders self-only fee history as neutral wallet maintenance", () => {
    render(<TransactionList entries={[sentEntry()]} />);

    const row = screen.getByText("Wallet maintenance").closest("article");
    const icon = row?.querySelector(".transaction-icon");
    expect(row).toBeInTheDocument();
    expect(icon).toHaveClass("kind-maintenance", "kind-consolidated");
    expect(icon).not.toHaveClass("kind-sent");
    expect(icon?.querySelector(".lucide-wrench")).toBeInTheDocument();
    expect(screen.queryByText("Consolidated outputs")).not.toBeInTheDocument();
  });

  it("keeps other outgoing history styled and labeled as a sent payment", () => {
    render(<TransactionList entries={[sentEntry({
      net_amount_atoms: "-2000",
      counterparty: "cd".repeat(32),
    })]} />);

    const row = screen.getByText("Sent CMFD").closest("article");
    const icon = row?.querySelector(".transaction-icon");
    expect(icon).toHaveClass("kind-sent");
    expect(icon).not.toHaveClass("kind-maintenance");
    expect(icon?.querySelector(".lucide-arrow-up-right")).toBeInTheDocument();
  });

  it("marks an entry whose block is not checked yet", () => {
    render(<TransactionList entries={[sentEntry({
      kind: "received",
      status: "verifying",
      confirmations: 1,
      net_amount_atoms: "2000",
      fee_burned_atoms: "0",
      counterparty: "cd".repeat(32),
    })]} />);

    const status = screen.getByText("1 confirmation · block check pending");
    expect(status).toHaveClass("status-verifying");
    expect(status.closest("article")?.querySelector(".lucide-hourglass")).toBeInTheDocument();
  });
});
