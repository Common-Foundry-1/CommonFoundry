import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./App";
import { LANGUAGE_STORAGE_KEY, THEME_STORAGE_KEY } from "./i18n";
import {
  confirmAndBroadcastPayment,
  getPendingPayments,
  getSendAvailability,
  getWalletOverview,
  getWalletStatus,
  lockWallet,
  preparePayment,
  reconcilePendingPayments,
  type SendAvailability,
  type WalletOverview,
  unlockWallet,
} from "./native";

import {
  Format,
  checkPermissions,
  requestPermissions,
  scan,
} from "@tauri-apps/plugin-barcode-scanner";

vi.mock("./native", () => ({
  createWallet: vi.fn(),
  exportWallet: vi.fn(),
  getSendAvailability: vi.fn(),
  getWalletOverview: vi.fn(),
  getWalletStatus: vi.fn(),
  getPendingPayments: vi.fn(),
  lockWallet: vi.fn(),
  preparePayment: vi.fn(),
  confirmAndBroadcastPayment: vi.fn(),
  reconcilePendingPayments: vi.fn(),
  restoreWallet: vi.fn(),
  unlockWallet: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-barcode-scanner", () => ({
  Format: { QRCode: "QRCode" },
  checkPermissions: vi.fn(),
  requestPermissions: vi.fn(),
  scan: vi.fn(),
}));

vi.mock("qrcode.react", () => ({
  QRCodeSVG: ({ value }: { value: string }) => (
    <svg aria-label="qr-test" data-encoded-value={value} />
  ),
}));

const mockedStatus = vi.mocked(getWalletStatus);
const mockedOverview = vi.mocked(getWalletOverview);
const mockedAvailability = vi.mocked(getSendAvailability);
const mockedPending = vi.mocked(getPendingPayments);
const mockedReconcile = vi.mocked(reconcilePendingPayments);

const ADDRESS = "cmfd10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq4yhywr";
const HEX_ADDRESS = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  localStorage.setItem(LANGUAGE_STORAGE_KEY, "fr");
});

afterEach(() => {
  cleanup();
  Object.defineProperty(document, "visibilityState", {
    configurable: true,
    value: "visible",
  });
  delete document.documentElement.dataset.theme;
  document.documentElement.removeAttribute("lang");
});

function renderUnlockedWallet(
  availability: SendAvailability = {
    available: true,
    message: null,
    nextHeight: 101,
    utxoCount: 0,
    spendableAtoms: null,
    feeAtoms: null,
    maximumAtoms: null,
  },
  overview: WalletOverview = {
    confirmedAtoms: "0",
    spendableAtoms: "0",
    immatureAtoms: "0",
    acceptedHeight: 100,
    validatedHeight: 99,
    includesMempool: false,
    hasMoreHistory: false,
    history: [],
  },
) {
  mockedStatus.mockResolvedValue({
    configured: true,
    unlocked: true,
    recoveryRequired: false,
    networkName: "CommonFoundry Mainnet",
    networkIdHex: "00".repeat(32),
    destinationHex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    address: ADDRESS,
  });
  mockedOverview.mockResolvedValue(overview);
  mockedAvailability.mockResolvedValue(availability);
  mockedPending.mockResolvedValue([]);
  render(<App />);
}

test("shows functional onboarding without fabricated wallet data", async () => {
  mockedStatus.mockResolvedValue({
    configured: false,
    unlocked: false,
    recoveryRequired: false,
    networkName: "CommonFoundry Mainnet",
    networkIdHex: "00".repeat(32),
    destinationHex: null,
    address: null,
  });
  render(<App />);
  expect(await screen.findByText("Votre portefeuille, sur votre téléphone.")).toBeVisible();
  const create = screen.getByRole("button", { name: "Créer un portefeuille" });
  expect(create).toBeEnabled();
  expect(screen.queryByText(/solde disponible/i)).not.toBeInTheDocument();
  fireEvent.click(create);
  expect(screen.getByRole("button", { name: "Choisir l’emplacement de sauvegarde" })).toBeEnabled();
  expect(screen.getAllByLabelText(/phrase/i)).toHaveLength(2);
});

test("offers authenticated restoration when Android Keystore is inaccessible", async () => {
  mockedStatus.mockResolvedValue({
    configured: true,
    unlocked: false,
    recoveryRequired: true,
    networkName: "CommonFoundry Mainnet",
    networkIdHex: "00".repeat(32),
    destinationHex: null,
    address: null,
  });
  render(<App />);
  expect(await screen.findByText("Clé Android Keystore inaccessible")).toBeVisible();
  expect(
    screen.getByRole("button", { name: "Choisir et authentifier la sauvegarde" }),
  ).toBeEnabled();
  expect(screen.getByText(/ne sera ni effacée ni remplacée/i)).toBeVisible();
});

test("does not expose technical error details", async () => {
  mockedStatus.mockRejectedValue(new Error("/private/path/wallet.cmfd-key"));
  render(<App />);
  expect(
    await screen.findByText("Le service sécurisé du portefeuille est indisponible."),
  ).toBeVisible();
  expect(screen.queryByText(/private\/path/)).not.toBeInTheDocument();
});

test("clears the passphrase field before reporting an unlock failure", async () => {
  mockedStatus.mockResolvedValue({
    configured: true,
    unlocked: false,
    recoveryRequired: false,
    networkName: "CommonFoundry Mainnet",
    networkIdHex: "00".repeat(32),
    destinationHex: null,
    address: null,
  });
  vi.mocked(unlockWallet).mockRejectedValue("Phrase secrète invalide.");
  render(<App />);

  const input = await screen.findByLabelText("Phrase secrète");
  fireEvent.change(input, { target: { value: "synthetic secret phrase" } });
  fireEvent.click(screen.getByRole("button", { name: "Déverrouiller" }));

  expect(await screen.findByRole("alert")).toHaveTextContent("Phrase secrète invalide.");
  expect(input).toHaveValue("");
  expect(screen.queryByDisplayValue("synthetic secret phrase")).not.toBeInTheDocument();
});

test("renders a zero mainnet balance and encodes the exact receive address", async () => {
  renderUnlockedWallet();
  expect(await screen.findByText("Solde réel")).toBeVisible();
  expect(await screen.findAllByText("0")).toHaveLength(3);

  fireEvent.click(screen.getByRole("button", { name: "Recevoir" }));
  expect(screen.getByText(ADDRESS)).toBeVisible();
  expect(screen.getByLabelText("qr-test")).toHaveAttribute("data-encoded-value", ADDRESS);
});

test("handles denied camera permission without changing the recipient", async () => {
  vi.mocked(checkPermissions).mockResolvedValue("denied");
  vi.mocked(requestPermissions).mockResolvedValue("denied");
  renderUnlockedWallet();
  await screen.findByText("Solde réel");
  fireEvent.click(screen.getByRole("button", { name: "Envoyer" }));
  fireEvent.click(screen.getByRole("button", { name: "Scanner" }));

  expect(await screen.findByText(/permission caméra est nécessaire/i)).toBeVisible();
  expect(screen.getByLabelText("Adresse du destinataire")).toHaveValue("");
});

test("accepts a strict lowercase hexadecimal mainnet address from a QR scan", async () => {
  vi.mocked(checkPermissions).mockResolvedValue("granted");
  vi.mocked(scan).mockResolvedValue({
    content: HEX_ADDRESS,
    format: Format.QRCode,
    bounds: {},
  });
  renderUnlockedWallet();
  await screen.findByText("Solde réel");
  fireEvent.click(screen.getByRole("button", { name: "Envoyer" }));
  fireEvent.click(screen.getByRole("button", { name: "Scanner" }));

  expect(await screen.findByLabelText("Adresse du destinataire")).toHaveValue(HEX_ADDRESS);
  expect(screen.queryByText(/ne contient pas une adresse/i)).not.toBeInTheDocument();
});

test("rejects an uppercase hexadecimal QR address before payment preparation", async () => {
  vi.mocked(checkPermissions).mockResolvedValue("granted");
  vi.mocked(scan).mockResolvedValue({
    content: HEX_ADDRESS.toUpperCase(),
    format: Format.QRCode,
    bounds: {},
  });
  renderUnlockedWallet();
  await screen.findByText("Solde réel");
  fireEvent.click(screen.getByRole("button", { name: "Envoyer" }));
  fireEvent.click(screen.getByRole("button", { name: "Scanner" }));

  expect(await screen.findByText(/ne contient pas une adresse/i)).toBeVisible();
  expect(screen.getByLabelText("Adresse du destinataire")).toHaveValue("");
  expect(preparePayment).not.toHaveBeenCalled();
});

test("never renders received change as positive income for outgoing history", async () => {
  renderUnlockedWallet(undefined, {
    confirmedAtoms: "100000000",
    spendableAtoms: "100000000",
    immatureAtoms: "0",
    acceptedHeight: 100,
    validatedHeight: 99,
    includesMempool: false,
    hasMoreHistory: false,
    history: [
      {
        kind: "received",
        txid: "11".repeat(32),
        blockHeight: 90,
        blockId: "22".repeat(32),
        timestamp: 1_700_000_000,
        confirmations: 10,
        receivedAtoms: "100000000",
      },
      {
        kind: "sent",
        txid: "33".repeat(32),
        blockHeight: 95,
        blockId: "44".repeat(32),
        timestamp: 1_700_000_100,
        confirmations: 5,
        receivedAtoms: "60000000",
      },
    ],
  });

  expect(await screen.findByText("+ 1 CMFD")).toBeVisible();
  expect(screen.getByText("Transaction sortante")).toBeVisible();
  expect(screen.queryByText("+ 0.6 CMFD")).not.toBeInTheDocument();
  expect(screen.getByText(/monnaie rendue reçue n’est pas affichée/i)).toBeVisible();
});

test("keeps signing unavailable when the gateway contract is unavailable", async () => {
  renderUnlockedWallet({
    available: false,
    message: "L’envoi reste verrouillé : preuve UTXO indépendante indisponible.",
    nextHeight: 101,
    utxoCount: 1,
    spendableAtoms: null,
    feeAtoms: null,
    maximumAtoms: null,
  });
  await screen.findByText("Solde réel");
  fireEvent.click(screen.getByRole("button", { name: "Envoyer" }));

  expect(await screen.findByText(/preuve UTXO indépendante indisponible/i)).toBeVisible();
  expect(screen.getAllByText("indisponible")).toHaveLength(3);
  expect(screen.getByRole("button", { name: /Vérifier les UTXO/i })).toBeDisabled();
  expect(preparePayment).not.toHaveBeenCalled();
});

test("discloses the official-gateway trust model when sending is available", async () => {
  renderUnlockedWallet({
    available: true,
    message: "Les UTXO proviennent de la passerelle officielle; aucune preuve indépendante n’est fournie.",
    nextHeight: 101,
    utxoCount: 2,
    spendableAtoms: "70000000",
    feeAtoms: "10000000",
    maximumAtoms: "60000000",
  });
  await screen.findByText("Solde réel");
  fireEvent.click(screen.getByRole("button", { name: "Envoyer" }));

  expect(await screen.findByText(/passerelle officielle/i)).toBeVisible();
  expect(screen.getByText("Solde disponible")).toBeVisible();
  expect(screen.getByText("0.7 CMFD")).toBeVisible();
  expect(screen.getByText("Frais réseau prévus")).toBeVisible();
  expect(screen.getByText("0.1 CMFD")).toBeVisible();
  expect(screen.getByText("Maximum envoyable après les frais")).toBeVisible();
  expect(screen.getByText("0.6 CMFD")).toBeVisible();
  expect(screen.getByRole("button", { name: /Vérifier les UTXO/i })).toBeEnabled();
});

test("renders the native spending limits in English", async () => {
  localStorage.setItem(LANGUAGE_STORAGE_KEY, "en");
  renderUnlockedWallet({
    available: true,
    message: null,
    nextHeight: 101,
    utxoCount: 1,
    spendableAtoms: "70000000",
    feeAtoms: "10000000",
    maximumAtoms: "60000000",
  });
  await screen.findByText("Live balance");
  fireEvent.click(screen.getByRole("button", { name: "Send" }));

  expect(screen.getByText("Available balance")).toBeVisible();
  expect(screen.getByText("Expected network fee")).toBeVisible();
  expect(screen.getByText("Maximum sendable after fees")).toBeVisible();
});

test("requires explicit confirmation and submits a prepared payment only once", async () => {
  vi.mocked(preparePayment).mockResolvedValue({
    intent: "11".repeat(32),
    recipient: ADDRESS,
    recipientHex: HEX_ADDRESS,
    recipientBech32m: ADDRESS,
    amountAtoms: "100000000",
    feeAtoms: "10000000",
    changeAtoms: "50000000",
    inputAtoms: "160000000",
    selectedInputs: 1,
  });
  vi.mocked(confirmAndBroadcastPayment).mockResolvedValue({
    submitted: false,
    message: "La réponse réseau est ambiguë.",
    payment: {
      intent: "11".repeat(32),
      txid: "22".repeat(32),
      recipient: ADDRESS,
      amountAtoms: "100000000",
      feeAtoms: "10000000",
      changeAtoms: "50000000",
      state: "broadcast_unknown",
      confirmations: 0,
      createdAt: 1_700_000_000,
    },
  });
  renderUnlockedWallet();
  await screen.findByText("Solde réel");
  fireEvent.click(screen.getByRole("button", { name: "Envoyer" }));
  fireEvent.change(screen.getByLabelText("Adresse du destinataire"), {
    target: { value: ADDRESS },
  });
  fireEvent.change(screen.getByLabelText("Montant CMFD"), {
    target: { value: "1" },
  });
  fireEvent.click(screen.getByRole("button", { name: /Vérifier les UTXO/i }));

  expect(await screen.findByText("Confirmation irréversible")).toBeVisible();
  expect(screen.getByText("Destinataire (hexadécimal)")).toBeVisible();
  expect(screen.getByText(HEX_ADDRESS)).toBeVisible();
  expect(screen.getByText("Adresse fournie (cmfd1…)")).toBeVisible();
  expect(screen.getByText(ADDRESS)).toBeVisible();
  const submit = screen.getByRole("button", { name: "Signer et diffuser une fois" });
  expect(submit).toBeDisabled();
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(submit);

  await waitFor(() => expect(confirmAndBroadcastPayment).toHaveBeenCalledTimes(1));
  expect(await screen.findByText("La réponse réseau est ambiguë.")).toBeVisible();
});

test("shows an exact hexadecimal recipient without adding a bech32m presentation", async () => {
  vi.mocked(preparePayment).mockResolvedValue({
    intent: "33".repeat(32),
    recipient: ADDRESS,
    recipientHex: HEX_ADDRESS,
    recipientBech32m: null,
    amountAtoms: "10000000",
    feeAtoms: "10000000",
    changeAtoms: "10000000",
    inputAtoms: "30000000",
    selectedInputs: 1,
  });
  renderUnlockedWallet();
  await screen.findByText("Solde réel");
  fireEvent.click(screen.getByRole("button", { name: "Envoyer" }));
  fireEvent.change(screen.getByLabelText("Adresse du destinataire"), {
    target: { value: HEX_ADDRESS },
  });
  fireEvent.change(screen.getByLabelText("Montant CMFD"), {
    target: { value: "0.1" },
  });
  fireEvent.click(screen.getByRole("button", { name: /Vérifier les UTXO/i }));

  expect(await screen.findByText("Confirmation irréversible")).toBeVisible();
  expect(screen.getByText(HEX_ADDRESS)).toBeVisible();
  expect(screen.queryByText("Adresse fournie (cmfd1…)")).not.toBeInTheDocument();
  expect(screen.queryByText(ADDRESS)).not.toBeInTheDocument();
});

test("clears a stale broadcast notice after successful confirmation reconciliation", async () => {
  vi.mocked(preparePayment).mockResolvedValue({
    intent: "11".repeat(32),
    recipient: ADDRESS,
    recipientHex: HEX_ADDRESS,
    recipientBech32m: ADDRESS,
    amountAtoms: "10000000",
    feeAtoms: "10000000",
    changeAtoms: "10000000",
    inputAtoms: "30000000",
    selectedInputs: 1,
  });
  vi.mocked(confirmAndBroadcastPayment).mockResolvedValue({
    submitted: true,
    message: "Transaction acceptée par le service Common Foundry; elle n’est pas encore confirmée.",
    payment: {
      intent: "11".repeat(32),
      txid: "22".repeat(32),
      recipient: ADDRESS,
      amountAtoms: "10000000",
      feeAtoms: "10000000",
      changeAtoms: "10000000",
      state: "accepted",
      confirmations: 0,
      createdAt: 1_700_000_000,
    },
  });
  mockedReconcile.mockResolvedValue([{
    intent: "11".repeat(32),
    txid: "22".repeat(32),
    recipient: ADDRESS,
    amountAtoms: "10000000",
    feeAtoms: "10000000",
    changeAtoms: "10000000",
    state: "confirmed",
    confirmations: 1,
    createdAt: 1_700_000_000,
  }]);
  renderUnlockedWallet();
  await screen.findByText("Solde réel");
  fireEvent.click(screen.getByRole("button", { name: "Envoyer" }));
  fireEvent.change(screen.getByLabelText("Adresse du destinataire"), {
    target: { value: ADDRESS },
  });
  fireEvent.change(screen.getByLabelText("Montant CMFD"), {
    target: { value: "0.1" },
  });
  fireEvent.click(screen.getByRole("button", { name: /Vérifier les UTXO/i }));
  await screen.findByText("Confirmation irréversible");
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Signer et diffuser une fois" }));

  expect(await screen.findByText(/elle n’est pas encore confirmée/i)).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Vérifier les confirmations" }));

  expect(await screen.findByText("1 confirmation")).toBeVisible();
  expect(screen.queryByText(/elle n’est pas encore confirmée/i)).not.toBeInTheDocument();
});

test("locks the native vault when the unlocked wallet is backgrounded", async () => {
  vi.mocked(lockWallet).mockResolvedValue({
    configured: true,
    unlocked: false,
    recoveryRequired: false,
    networkName: "CommonFoundry Mainnet",
    networkIdHex: "00".repeat(32),
    destinationHex: null,
    address: null,
  });
  renderUnlockedWallet();
  expect(await screen.findByText("Portefeuille CMFD")).toBeVisible();

  Object.defineProperty(document, "visibilityState", {
    configurable: true,
    value: "hidden",
  });
  fireEvent(document, new Event("visibilitychange"));

  await waitFor(() => expect(lockWallet).toHaveBeenCalledTimes(1));
  expect(await screen.findByText("Déverrouillage requis")).toBeVisible();
});

test("opens settings from the CF brand before wallet creation and shows the real version", async () => {
  mockedStatus.mockResolvedValue({
    configured: false,
    unlocked: false,
    recoveryRequired: false,
    networkName: "CommonFoundry Mainnet",
    networkIdHex: "00".repeat(32),
    destinationHex: null,
    address: null,
  });
  render(<App />);
  await screen.findByText("Votre portefeuille, sur votre téléphone.");

  fireEvent.click(screen.getByRole("button", { name: "Paramètres" }));
  expect(await screen.findByRole("dialog", { name: "Paramètres" })).toBeVisible();
  expect(screen.getByText("Version 0.1.0")).toBeVisible();
  expect(screen.getByRole("radio", { name: /Clair/ })).toBeChecked();
  expect(screen.getByRole("button", { name: "Ouvrir la sauvegarde du portefeuille" })).toBeDisabled();

  fireEvent.click(screen.getByRole("button", { name: "Fermer les paramètres" }));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

test("changes language and theme immediately and persists both preferences", async () => {
  mockedStatus.mockResolvedValue({
    configured: false,
    unlocked: false,
    recoveryRequired: false,
    networkName: "CommonFoundry Mainnet",
    networkIdHex: "00".repeat(32),
    destinationHex: null,
    address: null,
  });
  const view = render(<App />);
  await screen.findByText("Votre portefeuille, sur votre téléphone.");
  fireEvent.click(screen.getByRole("button", { name: "Paramètres" }));

  fireEvent.click(screen.getByRole("radio", { name: /Sombre/ }));
  expect(document.documentElement.dataset.theme).toBe("dark");
  expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");

  fireEvent.click(screen.getByRole("radio", { name: "English" }));
  expect(await screen.findByRole("dialog", { name: "Settings" })).toBeVisible();
  expect(screen.getByText("Your wallet, on your phone.")).toBeVisible();
  expect(localStorage.getItem(LANGUAGE_STORAGE_KEY)).toBe("en");
  expect(document.documentElement.lang).toBe("en");

  view.unmount();
  render(<App />);
  expect(await screen.findByText("Your wallet, on your phone.")).toBeVisible();
  expect(screen.getByRole("button", { name: "Settings" })).toBeEnabled();
  expect(document.documentElement.dataset.theme).toBe("dark");
});

test("keeps an in-progress send form intact while language and theme change", async () => {
  renderUnlockedWallet();
  await screen.findByText("Solde réel");
  fireEvent.click(screen.getByRole("button", { name: "Envoyer" }));
  const recipient = screen.getByLabelText("Adresse du destinataire");
  const amount = screen.getByLabelText("Montant CMFD");
  fireEvent.change(recipient, { target: { value: ADDRESS } });
  fireEvent.change(amount, { target: { value: "1.25" } });

  fireEvent.click(screen.getByRole("button", { name: "Paramètres" }));
  fireEvent.click(screen.getByRole("radio", { name: /Sombre/ }));
  fireEvent.click(screen.getByRole("radio", { name: "English" }));
  fireEvent.click(screen.getByRole("button", { name: "Close settings" }));

  expect(screen.getByLabelText("Recipient address")).toHaveValue(ADDRESS);
  expect(screen.getByLabelText("CMFD amount")).toHaveValue("1.25");
  expect(document.documentElement.dataset.theme).toBe("dark");
  expect(preparePayment).not.toHaveBeenCalled();
});

test("opens the existing backup screen from settings without locking the wallet", async () => {
  renderUnlockedWallet();
  await screen.findByText("Solde réel");
  fireEvent.click(screen.getByRole("button", { name: "Paramètres" }));
  fireEvent.click(screen.getByRole("button", { name: "Ouvrir la sauvegarde du portefeuille" }));

  expect(await screen.findByText("Exporter une sauvegarde officielle chiffrée")).toBeVisible();
  expect(lockWallet).not.toHaveBeenCalled();
});

test("keeps an unlocked wallet on screen if it cannot lock before notices", async () => {
  vi.mocked(lockWallet).mockRejectedValue(new Error("private vault error"));
  renderUnlockedWallet();
  await screen.findByText("Solde réel");

  fireEvent.click(screen.getByRole("button", { name: "Paramètres" }));
  fireEvent.click(screen.getByRole("button", {
    name: "Licences tierces et confidentialité du scan QR",
  }));

  await waitFor(() => expect(lockWallet).toHaveBeenCalledTimes(1));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Le portefeuille n’a pas pu être verrouillé",
  );
  expect(window.location.pathname).toBe("/");
});

test("localizes a stable native error when English is selected", async () => {
  localStorage.setItem(LANGUAGE_STORAGE_KEY, "en");
  mockedStatus.mockResolvedValue({
    configured: true,
    unlocked: false,
    recoveryRequired: false,
    networkName: "CommonFoundry Mainnet",
    networkIdHex: "00".repeat(32),
    destinationHex: null,
    address: null,
  });
  vi.mocked(unlockWallet).mockRejectedValue("Phrase secrète invalide.");
  render(<App />);

  const input = await screen.findByLabelText("Passphrase");
  fireEvent.change(input, { target: { value: "synthetic secret phrase" } });
  fireEvent.click(screen.getByRole("button", { name: "Unlock" }));

  expect(await screen.findByRole("alert")).toHaveTextContent("Invalid passphrase.");
  expect(input).toHaveValue("");
});
