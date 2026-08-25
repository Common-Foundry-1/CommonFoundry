import { useEffect, useRef, useState, type FormEvent } from "react";

import { sendWalletTransaction } from "../api/nodeClient";
import { formatAtoms, parseCmfd, shortenHash } from "../lib/amount";
import type { WalletSendResult, WalletSnapshot } from "../types";

interface SendDialogProps {
  open: boolean;
  wallet: WalletSnapshot | null;
  onClose: () => void;
  onCompleted: (message: string) => void;
  onRefresh: () => Promise<void> | void;
}

interface SendErrors {
  recipient?: string;
  amount?: string;
  fee?: string;
  form?: string;
}

type SendPhase = "edit" | "review" | "complete";

const DEFAULT_FEE = "0.00001000";
const PUBLIC_KEY_PATTERN = /^[0-9a-fA-F]{64}$/;

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "The transaction could not be submitted.";
}

function walletSpendableAtoms(wallet: WalletSnapshot | null): bigint | null {
  if (!wallet) return null;
  try {
    return BigInt(wallet.balances.spendable_atoms);
  } catch {
    return null;
  }
}

export function SendDialog({
  open,
  wallet,
  onClose,
  onCompleted,
  onRefresh,
}: SendDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const [phase, setPhase] = useState<SendPhase>("edit");
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [fee, setFee] = useState(DEFAULT_FEE);
  const [errors, setErrors] = useState<SendErrors>({});
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<WalletSendResult | null>(null);
  const submittingRef = useRef(false);

  useEffect(() => {
    if (!open || submittingRef.current) return;
    setPhase("edit");
    setRecipient("");
    setAmount("");
    setFee(DEFAULT_FEE);
    setErrors({});
    setBusy(false);
    setResult(null);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const previousFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const frame = requestAnimationFrame(() => dialogRef.current?.focus());
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        if (!submittingRef.current) onClose();
        return;
      }
      if (event.key === "Tab" && dialogRef.current) {
        const controls = Array.from(
          dialogRef.current.querySelectorAll<HTMLElement>(
            "button:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex='-1'])",
          ),
        );
        const first = controls[0];
        const last = controls.at(-1);
        if (!first || !last) return;
        if (event.shiftKey && (document.activeElement === first || document.activeElement === dialogRef.current)) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      cancelAnimationFrame(frame);
      document.removeEventListener("keydown", onKeyDown);
      previousFocus?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;

  const amountAtoms = parseCmfd(amount);
  const feeAtoms = parseCmfd(fee);
  const totalAtoms = amountAtoms !== null && feeAtoms !== null
    ? amountAtoms + feeAtoms
    : null;
  const spendableAtoms = walletSpendableAtoms(wallet);
  const closeIfIdle = () => {
    if (!submittingRef.current) onClose();
  };

  const validate = (): boolean => {
    const nextErrors: SendErrors = {};
    const normalizedRecipient = recipient.trim();
    const parsedAmount = parseCmfd(amount);
    const parsedFee = parseCmfd(fee);
    const available = walletSpendableAtoms(wallet);

    if (!wallet || available === null) {
      nextErrors.form = "Wallet data is unavailable. Reconnect to the node and try again.";
    }
    if (!PUBLIC_KEY_PATTERN.test(normalizedRecipient)) {
      nextErrors.recipient = "Enter a 64-character hexadecimal public key.";
    }
    if (parsedAmount === null || parsedAmount <= 0n) {
      nextErrors.amount = "Enter an amount greater than zero with no more than 8 decimals.";
    }
    if (parsedFee === null || parsedFee <= 0n) {
      nextErrors.fee = "Enter a fee greater than zero with no more than 8 decimals.";
    }
    if (
      available !== null
      && parsedAmount !== null
      && parsedFee !== null
      && parsedAmount + parsedFee > available
    ) {
      nextErrors.form = "The amount and burned fee exceed the spendable balance.";
    }

    setErrors(nextErrors);
    return Object.keys(nextErrors).length === 0;
  };

  const reviewTransaction = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!validate()) return;
    setErrors({});
    setPhase("review");
  };

  const submitTransaction = async () => {
    if (submittingRef.current) return;
    if (!validate()) {
      setPhase("edit");
      return;
    }

    submittingRef.current = true;
    setBusy(true);
    setErrors({});
    try {
      const submitted = await sendWalletTransaction({
        recipient: recipient.trim(),
        amount: amount.trim(),
        fee: fee.trim(),
      });
      setResult(submitted);
      setPhase("complete");
      onCompleted(
        `Sent ${formatAtoms(submitted.amount_atoms)} CMFD; ${formatAtoms(submitted.fee_burned_atoms)} CMFD burned.`,
      );
      await Promise.resolve(onRefresh()).catch(() => undefined);
    } catch (error) {
      setErrors({ form: getErrorMessage(error) });
    } finally {
      submittingRef.current = false;
      setBusy(false);
    }
  };

  const title = phase === "edit"
    ? "Send CMFD"
    : phase === "review"
      ? "Review transaction"
      : "Transaction submitted";

  return (
    <div className="dialog-backdrop">
      <div
        ref={dialogRef}
        className="dialog-panel dialog-panel-send"
        role="dialog"
        aria-modal="true"
        aria-labelledby="send-dialog-title"
        aria-describedby="send-dialog-description"
        aria-busy={busy}
        tabIndex={-1}
      >
        <div className="dialog-header">
          <div className="dialog-heading">
            <p className="dialog-eyebrow">{wallet?.network ?? "Network"} wallet</p>
            <h2 className="dialog-title" id="send-dialog-title">{title}</h2>
          </div>
          <button className="button-icon" type="button" onClick={closeIfIdle} aria-label="Close send dialog" disabled={busy}>
            <span aria-hidden="true">×</span>
          </button>
        </div>

        {phase === "edit" && (
          <form className="form-stack" onSubmit={reviewTransaction} noValidate>
            <p className="dialog-description" id="send-dialog-description">
              Create a signed transaction using this node's compiled-network wallet.
            </p>

            <div className="form-field">
              <label className="form-label" htmlFor="send-recipient">Recipient</label>
              <input
                className="form-input form-input-mono"
                id="send-recipient"
                value={recipient}
                onChange={(event) => {
                  setRecipient(event.target.value);
                  setErrors((current) => ({ ...current, recipient: undefined, form: undefined }));
                }}
                aria-invalid={Boolean(errors.recipient)}
                aria-describedby={errors.recipient ? "send-recipient-error" : undefined}
                placeholder="64-character x-only public key"
                autoComplete="off"
                spellCheck={false}
              />
              {errors.recipient && (
                <p className="form-error" id="send-recipient-error">{errors.recipient}</p>
              )}
            </div>

            <div className="form-field">
              <label className="form-label" htmlFor="send-amount">Amount</label>
              <div className="form-input-group">
                <input
                  className="form-input form-input-amount"
                  id="send-amount"
                  value={amount}
                  onChange={(event) => {
                    setAmount(event.target.value);
                    setErrors((current) => ({ ...current, amount: undefined, form: undefined }));
                  }}
                  aria-invalid={Boolean(errors.amount)}
                  aria-describedby={errors.amount ? "send-amount-error" : "send-available"}
                  placeholder="0.00000000"
                  inputMode="decimal"
                  autoComplete="off"
                />
                <span className="form-input-suffix">CMFD</span>
              </div>
              {errors.amount ? (
                <p className="form-error" id="send-amount-error">{errors.amount}</p>
              ) : (
                <p className="form-help" id="send-available">
                  Available: {spendableAtoms === null ? "Unavailable" : `${formatAtoms(spendableAtoms)} CMFD`}
                </p>
              )}
            </div>

            <div className="form-field">
              <label className="form-label" htmlFor="send-fee">Fee to burn</label>
              <div className="form-input-group">
                <input
                  className="form-input form-input-amount"
                  id="send-fee"
                  value={fee}
                  onChange={(event) => {
                    setFee(event.target.value);
                    setErrors((current) => ({ ...current, fee: undefined, form: undefined }));
                  }}
                  aria-invalid={Boolean(errors.fee)}
                  aria-describedby={errors.fee ? "send-fee-error" : "send-fee-help"}
                  inputMode="decimal"
                  autoComplete="off"
                />
                <span className="form-input-suffix">CMFD</span>
              </div>
              {errors.fee ? (
                <p className="form-error" id="send-fee-error">{errors.fee}</p>
              ) : (
                <p className="form-help" id="send-fee-help">Transaction fees are permanently burned.</p>
              )}
            </div>

            <div className="review-summary" aria-label="Transaction preview">
              <div className="review-row">
                <span className="review-label">Recipient receives</span>
                <strong className="review-value">
                  {amountAtoms !== null && amountAtoms > 0n ? formatAtoms(amountAtoms) : "0.00000000"} CMFD
                </strong>
              </div>
              <div className="review-row">
                <span className="review-label">Fee burned</span>
                <strong className="review-value">
                  {feeAtoms !== null && feeAtoms > 0n ? formatAtoms(feeAtoms) : "0.00000000"} CMFD
                </strong>
              </div>
              <div className="review-row review-row-total">
                <span className="review-label">Total</span>
                <strong className="review-value">
                  {totalAtoms !== null && totalAtoms > 0n ? formatAtoms(totalAtoms) : "0.00000000"} CMFD
                </strong>
              </div>
            </div>

            {errors.form && <p className="form-error form-error-summary" role="alert">{errors.form}</p>}
            <p className="warning-inline" role="note">
              {wallet?.warning ?? "Network wallet unavailable."}
            </p>

            <div className="dialog-actions">
              <button className="button-secondary" type="button" onClick={onClose}>Cancel</button>
              <button className="button-primary" type="submit" disabled={!wallet}>Review transaction</button>
            </div>
          </form>
        )}

        {phase === "review" && (
          <div className="review-stack">
            <p className="dialog-description" id="send-dialog-description">
              Verify every detail. The fee is destroyed when the transaction is mined.
            </p>
            <div className="review-summary">
              <div className="review-row review-row-block">
                <span className="review-label">Recipient</span>
                <output className="review-value review-value-address" aria-label="Full recipient public key">
                  {recipient.trim()}
                </output>
              </div>
              <div className="review-row">
                <span className="review-label">Recipient receives</span>
                <strong className="review-value">{formatAtoms(amountAtoms ?? 0n)} CMFD</strong>
              </div>
              <div className="review-row">
                <span className="review-label">Fee burned</span>
                <strong className="review-value">{formatAtoms(feeAtoms ?? 0n)} CMFD</strong>
              </div>
              <div className="review-row review-row-total">
                <span className="review-label">Total</span>
                <strong className="review-value">{formatAtoms(totalAtoms ?? 0n)} CMFD</strong>
              </div>
            </div>
            {errors.form && <p className="form-error form-error-summary" role="alert">{errors.form}</p>}
            <p className="warning-inline" role="note">
              {wallet?.network ?? "Network"} transaction · Verify the recipient and amount before sending.
            </p>
            <div className="dialog-actions">
              <button
                className="button-secondary"
                type="button"
                onClick={() => {
                  setErrors({});
                  setPhase("edit");
                }}
                disabled={busy}
              >
                Back
              </button>
              <button className="button-primary" type="button" onClick={submitTransaction} disabled={busy}>
                {busy ? "Submitting…" : "Send transaction"}
              </button>
            </div>
          </div>
        )}

        {phase === "complete" && result && (
          <div className="review-stack">
            <p className="dialog-description" id="send-dialog-description">
              The node accepted this transaction into its local mempool.
            </p>
            <div className="review-summary">
              <div className="review-row review-row-block">
                <span className="review-label">Transaction ID</span>
                <strong className="review-value review-value-hash" title={result.txid}>
                  {shortenHash(result.txid, 12, 12)}
                </strong>
              </div>
              <div className="review-row">
                <span className="review-label">Amount sent</span>
                <strong className="review-value">{formatAtoms(result.amount_atoms)} CMFD</strong>
              </div>
              <div className="review-row">
                <span className="review-label">Fee burned</span>
                <strong className="review-value">{formatAtoms(result.fee_burned_atoms)} CMFD</strong>
              </div>
              <div className="review-row">
                <span className="review-label">Change</span>
                <strong className="review-value">{formatAtoms(result.change_atoms)} CMFD</strong>
              </div>
            </div>
            <p className="warning-inline" role="note">This transaction is not final until mined.</p>
            <div className="dialog-actions dialog-actions-single">
              <button className="button-primary" type="button" onClick={onClose}>Done</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
