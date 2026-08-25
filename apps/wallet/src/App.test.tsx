import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

const status = {
  network: "CommonFoundry Profile Test",
  network_id: "11".repeat(32),
  consensus_fingerprint: "22".repeat(32),
  proof_of_work: "ForgeMatrix-v2 tiny full-recompute reference",
  tip: "33".repeat(32),
  cumulative_work: "0".repeat(127) + "1",
  accepted_height: 128,
  next_height: 129,
  expected_target: "00ffffff" + "ff".repeat(28),
  utxo_count: 384,
  mempool_transactions: 1,
  mempool_bytes: 256,
  storage_healthy: true,
};

const wallet = {
  network: "CommonFoundry Profile Test",
  devnet_only: true,
  insecure_demo_wallet: true,
  warning: "Shared insecure Devnet wallet key. Never use for real value.",
  destination: "1d16453b3ab3132acb0a5bc16cc49690d819a585267a15cd5a064e2a0ad40599",
  accepted_height: 128,
  next_height: 129,
  balances: {
    spendable_atoms: "12500000123",
    immature_atoms: "5000000000",
    pending_atoms: "249999877",
  },
  spendable_utxo_count: 12,
  immature_utxo_count: 4,
  reserved_utxo_count: 1,
  mempool: { transactions: 1, bytes: 256 },
  history_limit: 256,
  history: [
    {
      kind: "mined",
      txid: "44".repeat(32),
      height: 128,
      timestamp: 1_775_000_000,
      confirmations: 1,
      status: "immature",
      net_amount_atoms: "5000000000",
      fee_burned_atoms: "0",
      counterparty: null,
    },
  ],
};

const mempool = {
  transactions: 1,
  bytes: 256,
  entries: [
    {
      txid: "55".repeat(32),
      encoded_bytes: 256,
      fee_burned: 1000,
      fee_burned_atoms: "1000",
    },
  ],
};

function jsonResponse(value: unknown, statusCode = 200) {
  return Promise.resolve(new Response(JSON.stringify(value), {
    status: statusCode,
    headers: { "Content-Type": "application/json" },
  }));
}

describe("Common Foundry wallet", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith("/v1/status")) return jsonResponse(status);
      if (url.endsWith("/v1/wallet")) return jsonResponse(wallet);
      if (url.endsWith("/v1/mempool")) return jsonResponse(mempool);
      return jsonResponse({ error: "not found" }, 404);
    }));
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("renders live wallet and node values without inventing market data", async () => {
    render(<App />);

    expect(await screen.findByText("177.50")).toBeInTheDocument();
    expect(screen.getByText("CommonFoundry Profile Test")).toBeInTheDocument();
    expect(screen.getByText("Block height").nextElementSibling).toHaveTextContent("128");
    expect(screen.getByText("Mined reward")).toBeInTheDocument();
    expect(screen.getByText(/Testing network/)).toBeInTheDocument();
    expect(screen.queryByText(/USD|market price|sync percentage/i)).not.toBeInTheDocument();
  });

  it("exposes consolidation from Transactions with mature-output safeguards", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("177.50");

    await user.click(screen.getAllByRole("button", { name: "Transactions" })[0]);
    expect(screen.getByRole("heading", { name: "Consolidate mining outputs" })).toBeInTheDocument();
    expect(screen.getByText("12", { selector: "dd" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Consolidate outputs" }));
    expect(screen.getByRole("dialog", { name: "Consolidate mining outputs" })).toBeInTheDocument();
    expect(screen.getByText(/4 immature and 1 reserved excluded/)).toBeInTheDocument();
    expect(screen.getByRole("spinbutton", { name: "Maximum inputs" })).toHaveValue(12);
  });

  it("opens the receive address without exposing private key material", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("177.50");

    await user.click(screen.getAllByRole("button", { name: "Receive" })[0]);
    expect(screen.getByRole("dialog", { name: "Receive CMFD" })).toBeInTheDocument();
    expect(screen.getByText(wallet.destination)).toBeInTheDocument();
    expect(screen.queryByLabelText(/private key/i)).not.toBeInTheDocument();
  });

  it("surfaces node errors and can retry", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockRejectedValueOnce(new Error("connection refused"));
    render(<App />);
    expect(await screen.findByText("Local node unavailable")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(screen.getByText("177.50")).toBeInTheDocument());
  });

  it("opens the dedicated Mining page from wallet navigation", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("177.50");

    await user.click(screen.getAllByRole("button", { name: "Mining" })[0]);
    expect(screen.getByRole("heading", { name: "Mining", level: 1 })).toBeInTheDocument();
    expect(screen.getByText("ForgeMatrix mining")).toBeInTheDocument();
    expect(screen.getByText("matrix attempts/s")).toBeInTheDocument();

    const mobileNavigation = screen.getAllByRole("navigation", { name: "Wallet navigation" })[1];
    expect(within(mobileNavigation).getByRole("button", { name: "Mining" })).toBeInTheDocument();
    expect(within(mobileNavigation).queryByRole("button", { name: "Network" })).not.toBeInTheDocument();
  });
});
