import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { WalletHistoryEntry } from "../types";
import { TransactionList } from "./TransactionList";

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
