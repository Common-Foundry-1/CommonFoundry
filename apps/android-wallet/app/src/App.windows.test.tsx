import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { App } from "./App";
import { LANGUAGE_STORAGE_KEY } from "./i18n";

const commands = vi.hoisted(() => {
  vi.stubEnv("TAURI_ENV_PLATFORM", "windows");
  return {
    getWalletStatus: vi.fn(),
    getWalletOverview: vi.fn(),
    getSendAvailability: vi.fn(),
    getPendingPayments: vi.fn(),
    preparePayment: vi.fn(),
    confirmAndBroadcastPayment: vi.fn(),
  };
});

vi.mock("./native", () => commands);

const destinationHex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const address = "cmfd10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq4yhywr";

beforeEach(() => {
  vi.resetAllMocks();
  localStorage.setItem(LANGUAGE_STORAGE_KEY, "en");
  commands.getWalletStatus.mockResolvedValue({
    configured: true, unlocked: true, recoveryRequired: false,
    networkName: "Common Foundry Mainnet", destinationHex, address,
  });
  commands.getWalletOverview.mockResolvedValue({
    confirmedAtoms: "100000000", spendableAtoms: "100000000", immatureAtoms: "0",
    acceptedHeight: 71000, validatedHeight: 71000, includesMempool: false, history: [],
  });
  commands.getPendingPayments.mockResolvedValue([]);
});

afterEach(() => {
  cleanup();
  localStorage.clear();
});

test("keeps the Windows balance and review focused without skipping consent", async () => {
  commands.getSendAvailability.mockResolvedValue({
    available: true, message: "Redundant gateway notice", utxoCount: 1,
    spendableAtoms: "100000000", feeAtoms: "10000000", maximumAtoms: "90000000",
  });
  commands.preparePayment.mockResolvedValue({
    intent: "test-review", recipientHex: destinationHex, recipientBech32m: address,
    amountAtoms: "90000000", feeAtoms: "10000000", changeAtoms: "0", selectedInputs: 1,
  });
  render(<App />);
  expect(await screen.findByText(/Accepted height 71000/)).toBeVisible();
  expect(screen.queryByText(/Keep the backup off this PC/)).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Send" }));
  const review = screen.getByRole("button", { name: "Review payment" });
  await waitFor(() => expect(review).toBeEnabled());
  expect(screen.queryByText(/UTXO API returned|Redundant gateway notice/)).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Recipient address"), { target: { value: address } });
  fireEvent.change(screen.getByLabelText("CMFD amount"), { target: { value: "0.9" } });
  fireEvent.click(review);

  const heading = await screen.findByRole("heading", { name: "Review payment" });
  expect(heading).toHaveFocus();
  expect(review).not.toBeVisible();
  expect(screen.getByText(address)).toBeVisible();
  expect(screen.queryByText(destinationHex)).not.toBeInTheDocument();
  const send = screen.getByRole("button", { name: "Sign and send" });
  expect(send).toBeDisabled();
  expect(commands.confirmAndBroadcastPayment).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("checkbox", { name: /This payment is final/ }));
  expect(send).toBeEnabled();

  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(review).toHaveFocus();
  expect(screen.getByLabelText("CMFD amount")).toHaveValue("0.9");
});

test("keeps an actionable error when Windows spend verification fails", async () => {
  commands.getSendAvailability.mockRejectedValue("wallet_service_timeout");
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Send" }));
  expect(await screen.findByText(/took too long to respond/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Review payment" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Check spendable funds again" })).toBeEnabled();
});

test("retries a cold-start balance timeout without displaying a zero balance", async () => {
  commands.getWalletOverview.mockRejectedValueOnce("wallet_service_timeout");
  vi.useFakeTimers();
  try {
    await act(async () => { render(<App />); });
    expect(screen.getByRole("status")).toHaveTextContent("Reconnecting to the balance service");
    expect(screen.queryByText("Available")).not.toBeInTheDocument();

    await act(async () => { await vi.advanceTimersByTimeAsync(4000); });
    expect(commands.getWalletOverview).toHaveBeenCalledTimes(2);
    expect(screen.getByText(/Accepted height 71000/)).toBeVisible();
    expect(screen.getByRole("status")).toBeEmptyDOMElement();
  } finally {
    vi.useRealTimers();
  }
});
