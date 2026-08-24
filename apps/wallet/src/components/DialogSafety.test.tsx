import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "../App";

const destination = "1d16453b3ab3132acb0a5bc16cc49690d819a585267a15cd5a064e2a0ad40599";

const status = {
  network: "CommonFoundry Devnet-0",
  network_id: "11".repeat(32),
  consensus_fingerprint: "22".repeat(32),
  proof_of_work: "ForgeMatrix-v2 tiny full-recompute reference",
  tip: "33".repeat(32),
  cumulative_work: "0".repeat(127) + "1",
  accepted_height: 128,
  next_height: 129,
  expected_target: "00ffffff" + "ff".repeat(28),
  utxo_count: 384,
  mempool_transactions: 0,
  mempool_bytes: 0,
  storage_healthy: true,
};

const wallet = {
  network: "CommonFoundry Devnet-0",
  devnet_only: true,
  insecure_demo_wallet: true,
  warning: "Shared insecure Devnet wallet key. Never use for real value.",
  destination,
  accepted_height: 128,
  next_height: 129,
  balances: {
    spendable_atoms: "12500000123",
    immature_atoms: "5000000000",
    pending_atoms: "0",
  },
  spendable_utxo_count: 12,
  immature_utxo_count: 4,
  reserved_utxo_count: 1,
  mempool: { transactions: 0, bytes: 0 },
  history_limit: 100,
  history: [],
};

const mempool = { transactions: 0, bytes: 0, entries: [] };

function jsonResponse(value: unknown, statusCode = 200): Response {
  return new Response(JSON.stringify(value), {
    status: statusCode,
    headers: { "Content-Type": "application/json" },
  });
}

function defaultFetch(input: RequestInfo | URL): Promise<Response> {
  const url = input.toString();
  if (url.endsWith("/v1/status")) return Promise.resolve(jsonResponse(status));
  if (url.endsWith("/v1/wallet")) return Promise.resolve(jsonResponse(wallet));
  if (url.endsWith("/v1/mempool")) return Promise.resolve(jsonResponse(mempool));
  return Promise.resolve(jsonResponse({ error: "not found" }, 404));
}

function deferredResponse() {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

describe("wallet dialog safety", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(defaultFetch));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("keeps the active send field focused across parent polling renders", async () => {
    const user = userEvent.setup();
    const view = render(<App />);
    await screen.findByText("125.00");

    await user.click(screen.getAllByRole("button", { name: "Send" })[0]);
    await waitFor(() => expect(screen.getByRole("dialog", { name: "Send CMFD" })).toHaveFocus());
    const amount = screen.getByRole("textbox", { name: "Amount" });
    await user.click(amount);
    expect(amount).toHaveFocus();

    view.rerender(<App />);
    await act(async () => {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    });

    expect(amount).toHaveFocus();
  });

  it("shows the full recipient and locks send until its single request settles", async () => {
    const pending = deferredResponse();
    const fetchMock = vi.mocked(fetch);
    let sendRequests = 0;
    fetchMock.mockImplementation((input) => {
      if (input.toString().endsWith("/v1/wallet/send")) {
        sendRequests += 1;
        return pending.promise;
      }
      return defaultFetch(input);
    });

    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("125.00");
    await user.click(screen.getAllByRole("button", { name: "Send" })[0]);
    await waitFor(() => expect(screen.getByRole("dialog", { name: "Send CMFD" })).toHaveFocus());
    await user.type(screen.getByRole("textbox", { name: "Recipient" }), destination);
    await user.type(screen.getByRole("textbox", { name: "Amount" }), "1");
    await user.click(screen.getByRole("button", { name: "Review transaction" }));

    const recipient = screen.getByLabelText("Full recipient public key");
    expect(recipient).toHaveTextContent(destination);
    expect(recipient).toHaveClass("review-value-address");

    const dialog = screen.getByRole("dialog", { name: "Review transaction" });
    const submit = within(dialog).getByRole("button", { name: "Send transaction" });
    const close = within(dialog).getByRole("button", { name: "Close send dialog" });
    act(() => {
      submit.click();
      submit.click();
      close.click();
    });

    await waitFor(() => expect(sendRequests).toBe(1));
    expect(close).toBeDisabled();
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog", { name: "Review transaction" })).toBeInTheDocument();

    pending.resolve(jsonResponse({
      network: "CommonFoundry Devnet-0",
      devnet_only: true,
      insecure_demo_wallet: true,
      warning: wallet.warning,
      txid: "66".repeat(32),
      amount_atoms: "100000000",
      fee_burned_atoms: "1000",
      change_atoms: "12400000123",
      mempool_transactions: 1,
      mempool_bytes: 256,
    }));
    expect(await screen.findByRole("dialog", { name: "Transaction submitted" })).toBeInTheDocument();
  });

  it("locks consolidation until its single request settles", async () => {
    const pending = deferredResponse();
    const fetchMock = vi.mocked(fetch);
    let consolidationRequests = 0;
    fetchMock.mockImplementation((input) => {
      if (input.toString().endsWith("/v1/wallet/consolidate")) {
        consolidationRequests += 1;
        return pending.promise;
      }
      return defaultFetch(input);
    });

    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("125.00");
    await user.click(screen.getAllByRole("button", { name: "Transactions" })[0]);
    await user.click(screen.getByRole("button", { name: "Consolidate outputs" }));
    await user.click(screen.getByRole("button", { name: "Review consolidation" }));

    const dialog = screen.getByRole("dialog", { name: "Review consolidation" });
    const submit = within(dialog).getByRole("button", { name: "Consolidate outputs" });
    const close = within(dialog).getByRole("button", { name: "Close consolidation dialog" });
    act(() => {
      submit.click();
      submit.click();
      close.click();
    });

    await waitFor(() => expect(consolidationRequests).toBe(1));
    expect(close).toBeDisabled();
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog", { name: "Review consolidation" })).toBeInTheDocument();

    pending.resolve(jsonResponse({
      network: "CommonFoundry Devnet-0",
      devnet_only: true,
      insecure_demo_wallet: true,
      warning: wallet.warning,
      txid: "77".repeat(32),
      inputs_consolidated: 12,
      input_atoms: wallet.balances.spendable_atoms,
      output_atoms: "12499999123",
      fee_burned_atoms: "1000",
      mempool_transactions: 1,
      mempool_bytes: 512,
    }));
    expect(await screen.findByRole("dialog", { name: "Consolidation submitted" })).toBeInTheDocument();
  });
});
