import { invoke } from "@tauri-apps/api/core";

export interface WalletStatus {
  configured: boolean;
  unlocked: boolean;
  recoveryRequired: boolean;
  networkName: string;
  networkIdHex: string;
  destinationHex: string | null;
  address: string | null;
}

export interface HistoryEntry {
  kind: string;
  txid: string;
  blockHeight: number;
  blockId: string;
  timestamp: number | null;
  confirmations: number;
  receivedAtoms: string;
}

export interface WalletOverview {
  confirmedAtoms: string;
  spendableAtoms: string;
  immatureAtoms: string;
  acceptedHeight: number;
  validatedHeight: number | null;
  includesMempool: boolean;
  hasMoreHistory: boolean;
  history: HistoryEntry[];
}

export interface SendAvailability {
  available: boolean;
  message: string | null;
  nextHeight: number | null;
  utxoCount: number;
  spendableAtoms: string | null;
  feeAtoms: string | null;
  maximumAtoms: string | null;
}

export interface PaymentSummary {
  intent: string;
  recipient: string;
  recipientHex: string;
  recipientBech32m: string | null;
  amountAtoms: string;
  feeAtoms: string;
  changeAtoms: string;
  inputAtoms: string;
  selectedInputs: number;
}

export type PendingPaymentState =
  | "broadcast_unknown"
  | "accepted"
  | "confirmed"
  | "conflicted"
  | "dropped";

export interface PendingPayment {
  intent: string;
  txid: string;
  recipient: string;
  amountAtoms: string;
  feeAtoms: string;
  changeAtoms: string;
  state: PendingPaymentState;
  confirmations: number;
  createdAt: number;
}

export interface BroadcastOutcome {
  payment: PendingPayment;
  submitted: boolean;
  message: string;
}

export function getWalletStatus(): Promise<WalletStatus> {
  return invoke<WalletStatus>("wallet_status");
}

export function createWallet(passphrase: string): Promise<WalletStatus> {
  return invoke<WalletStatus>("create_wallet", { passphrase });
}

export function restoreWallet(passphrase: string): Promise<WalletStatus> {
  return invoke<WalletStatus>("restore_wallet", { passphrase });
}

export function unlockWallet(passphrase: string): Promise<WalletStatus> {
  return invoke<WalletStatus>("unlock_wallet", { passphrase });
}

export function lockWallet(): Promise<WalletStatus> {
  return invoke<WalletStatus>("lock_wallet");
}

export function exportWallet(passphrase: string): Promise<void> {
  return invoke<void>("export_wallet", { passphrase });
}

export function getWalletOverview(): Promise<WalletOverview> {
  return invoke<WalletOverview>("wallet_overview");
}

export function getSendAvailability(): Promise<SendAvailability> {
  return invoke<SendAvailability>("send_availability");
}

export function preparePayment(recipient: string, amount: string): Promise<PaymentSummary> {
  return invoke<PaymentSummary>("prepare_payment", { recipient, amount });
}

export function confirmAndBroadcastPayment(intent: string): Promise<BroadcastOutcome> {
  return invoke<BroadcastOutcome>("confirm_and_broadcast_payment", { intent });
}

export function getPendingPayments(): Promise<PendingPayment[]> {
  return invoke<PendingPayment[]>("pending_payments");
}

export function reconcilePendingPayments(): Promise<PendingPayment[]> {
  return invoke<PendingPayment[]>("reconcile_pending_payments");
}
