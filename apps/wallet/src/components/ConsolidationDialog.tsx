import { useEffect, useRef, useState, type FormEvent } from "react";

import { consolidateWallet } from "../api/nodeClient";
import { formatAtoms, parseCmfd, shortenHash } from "../lib/amount";
import { DEFAULT_TRANSACTION_FEE, MIN_TRANSACTION_FEE_ATOMS, MINIMUM_FEE_MESSAGE } from "../lib/fees";
import type { ConsolidationResult, WalletSnapshot } from "../types";

interface ConsolidationDialogProps {
  open: boolean;
  wallet: WalletSnapshot | null;
  onClose: () => void;
  onCompleted: (message: string) => void;
  onRefresh: () => Promise<void> | void;
}

interface ConsolidationErrors {
  maxInputs?: string;
  fee?: string;
  form?: string;
}

type ConsolidationPhase = "edit" | "review" | "complete";

const DEFAULT_FEE = DEFAULT_TRANSACTION_FEE;

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "The consolidation could not be submitted.";
}

function defaultMaximumInputs(wallet: WalletSnapshot | null): string {
  return Math.max(2, Math.min(128, wallet?.spendable_utxo_count ?? 2)).toString();
}

function safeAtoms(value: string | undefined): bigint | null {
  if (value === undefined) return null;
  try {
    return BigInt(value);
  } catch {
    return null;
  }
}

export function ConsolidationDialog({
  open,
  wallet,
  onClose,
  onCompleted,
  onRefresh,
}: ConsolidationDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const wasOpenRef = useRef(false);
  const [phase, setPhase] = useState<ConsolidationPhase>("edit");
  const [maxInputs, setMaxInputs] = useState("2");
  const [fee, setFee] = useState(DEFAULT_FEE);
  const [errors, setErrors] = useState<ConsolidationErrors>({});
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ConsolidationResult | null>(null);
  const submittingRef = useRef(false);

  useEffect(() => {
    if (open && !wasOpenRef.current && !submittingRef.current) {
      setPhase("edit");
      setMaxInputs(defaultMaximumInputs(wallet));
      setFee(DEFAULT_FEE);
      setErrors({});
      setBusy(false);
      setResult(null);
    }
    wasOpenRef.current = open;
  }, [open, wallet]);

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

  const parsedMaximum = Number(maxInputs);
  const maximumIsValid = Number.isInteger(parsedMaximum) && parsedMaximum >= 2 && parsedMaximum <= 128;
  const eligibleCount = wallet?.spendable_utxo_count ?? 0;
  const estimatedCount = maximumIsValid ? Math.min(eligibleCount, parsedMaximum) : 0;
  const feeAtoms = parseCmfd(fee);
  const spendableAtoms = safeAtoms(wallet?.balances.spendable_atoms);
  const selectsEveryEligibleOutput = eligibleCount > 0 && estimatedCount === eligibleCount;
  const estimatedOutput = selectsEveryEligibleOutput
    && spendableAtoms !== null
    && feeAtoms !== null
    && spendableAtoms > feeAtoms
      ? spendableAtoms - feeAtoms
      : null;
  const closeIfIdle = () => {
    if (!submittingRef.current) onClose();
  };

  const validate = (): boolean => {
    const nextErrors: ConsolidationErrors = {};
    const parsedFee = parseCmfd(fee);
    const availableAtoms = safeAtoms(wallet?.balances.spendable_atoms);

    if (!wallet || availableAtoms === null) {
      nextErrors.form = "Wallet data is unavailable. Reconnect to the node and try again.";
    } else if (wallet.spendable_utxo_count < 2) {
      nextErrors.form = "At least two mature, unreserved outputs are required to consolidate.";
    }
    if (!maximumIsValid) {
      nextErrors.maxInputs = "Choose a whole number from 2 through 128.";
    }
    if (parsedFee === null || parsedFee < MIN_TRANSACTION_FEE_ATOMS) {
      nextErrors.fee = MINIMUM_FEE_MESSAGE;
    } else if (availableAtoms !== null && parsedFee >= availableAtoms) {
      nextErrors.fee = "The burned fee must be smaller than the available input value.";
    }

    setErrors(nextErrors);
    return Object.keys(nextErrors).length === 0;
  };

  const reviewConsolidation = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!validate()) return;
    setErrors({});
    setPhase("review");
  };

  const submitConsolidation = async () => {
    if (submittingRef.current) return;
    if (!validate()) {
      setPhase("edit");
      return;
    }

    submittingRef.current = true;
    setBusy(true);
    setErrors({});
    try {
      const submitted = await consolidateWallet({
        fee: fee.trim(),
        max_inputs: parsedMaximum,
      });
      setResult(submitted);
      setPhase("complete");
      onCompleted(
        `Consolidated ${submitted.inputs_consolidated} mining outputs; ${formatAtoms(submitted.fee_burned_atoms)} CMFD burned.`,
      );
      await Promise.resolve(onRefresh()).catch(() => undefined);
    } catch (error) {
      setErrors({ form: getErrorMessage(error) });
    } finally {
      submittingRef.current = false;
      setBusy(false);
    }
  };

  const estimatedTotalLabel = selectsEveryEligibleOutput && spendableAtoms !== null
    ? `${formatAtoms(spendableAtoms)} CMFD`
    : "Calculated by node";
  const estimatedOutputLabel = estimatedOutput !== null
    ? `${formatAtoms(estimatedOutput)} CMFD`
    : "Calculated by node";
  const title = phase === "edit"
    ? "Consolidate mining outputs"
    : phase === "review"
      ? "Review consolidation"
      : "Consolidation submitted";

  return (
    <div className="dialog-backdrop">
      <div
        ref={dialogRef}
        className="dialog-panel dialog-panel-consolidation"
        role="dialog"
        aria-modal="true"
        aria-labelledby="consolidation-dialog-title"
        aria-describedby="consolidation-dialog-description"
        aria-busy={busy}
        tabIndex={-1}
      >
        <div className="dialog-header">
          <div className="dialog-heading">
            <p className="dialog-eyebrow">UTXO hygiene</p>
            <h2 className="dialog-title" id="consolidation-dialog-title">{title}</h2>
          </div>
          <button
            className="button-icon"
            type="button"
            onClick={closeIfIdle}
            aria-label="Close consolidation dialog"
            disabled={busy}
          >
            <span aria-hidden="true">×</span>
          </button>
        </div>

        {phase === "edit" && (
          <form className="form-stack" onSubmit={reviewConsolidation} noValidate>
            <p className="dialog-description" id="consolidation-dialog-description">
              Combine mature mining outputs into one wallet output.
            </p>

            <div className="review-metrics" aria-label="Consolidation limits">
              <div className="review-metric">
                <span className="review-label">Spendable outputs</span>
                <strong className="review-value">{eligibleCount}</strong>
              </div>
              <div className="review-metric">
                <span className="review-label">Estimated this batch</span>
                <strong className="review-value">{estimatedCount}</strong>
              </div>
              <div className="review-metric">
                <span className="review-label">Maximum per transaction</span>
                <strong className="review-value">128</strong>
              </div>
            </div>

            <div className="form-field">
              <label className="form-label" htmlFor="consolidation-inputs">Maximum inputs</label>
              <input
                className="form-input"
                id="consolidation-inputs"
                type="number"
                min="2"
                max="128"
                step="1"
                value={maxInputs}
                onChange={(event) => {
                  setMaxInputs(event.target.value);
                  setErrors((current) => ({ ...current, maxInputs: undefined, form: undefined }));
                }}
                aria-invalid={Boolean(errors.maxInputs)}
                aria-describedby={errors.maxInputs ? "consolidation-inputs-error" : "consolidation-inputs-help"}
              />
              {errors.maxInputs ? (
                <p className="form-error" id="consolidation-inputs-error">{errors.maxInputs}</p>
              ) : (
                <p className="form-help" id="consolidation-inputs-help">
                  Only mature, unreserved outputs are eligible. {wallet?.immature_utxo_count ?? 0} immature and {wallet?.reserved_utxo_count ?? 0} reserved excluded.
                </p>
              )}
            </div>

            <div className="form-field">
              <label className="form-label" htmlFor="consolidation-fee">Fee to burn</label>
              <div className="form-input-group">
                <input
                  className="form-input form-input-amount"
                  id="consolidation-fee"
                  value={fee}
                  onChange={(event) => {
                    setFee(event.target.value);
                    setErrors((current) => ({ ...current, fee: undefined, form: undefined }));
                  }}
                  aria-invalid={Boolean(errors.fee)}
                  aria-describedby={errors.fee ? "consolidation-fee-error" : "consolidation-fee-help"}
                  inputMode="decimal"
                  autoComplete="off"
                />
                <span className="form-input-suffix">CMFD</span>
              </div>
              {errors.fee ? (
                <p className="form-error" id="consolidation-fee-error">{errors.fee}</p>
              ) : (
                <p className="form-help" id="consolidation-fee-help">Minimum 0.1 CMFD. This fee is permanently burned.</p>
              )}
            </div>

            <div className="review-summary" aria-label="Estimated consolidation preview">
              <div className="review-row">
                <span className="review-label">Estimated input total</span>
                <strong className="review-value">{estimatedTotalLabel}</strong>
              </div>
              <div className="review-row">
                <span className="review-label">Fee burned</span>
                <strong className="review-value">
                  {feeAtoms !== null && feeAtoms > 0n ? formatAtoms(feeAtoms) : "0.00000000"} CMFD
                </strong>
              </div>
              <div className="review-row review-row-total">
                <span className="review-label">Estimated new wallet output</span>
                <strong className="review-value">{estimatedOutputLabel}</strong>
              </div>
            </div>

            <p className="form-help form-help-estimate">
              Estimate only: individual UTXO values are not exposed here. The node selects mature, unreserved outputs smallest-first and returns exact totals after submission.
            </p>
            {errors.form && <p className="form-error form-error-summary" role="alert">{errors.form}</p>}

            <div className="dialog-actions">
              <button className="button-secondary" type="button" onClick={onClose}>Cancel</button>
              <button className="button-primary" type="submit" disabled={!wallet}>Review consolidation</button>
            </div>
          </form>
        )}

        {phase === "review" && (
          <div className="review-stack">
            <p className="dialog-description" id="consolidation-dialog-description">
              The node will choose up to {parsedMaximum} mature, unreserved outputs, smallest-first.
            </p>
            <div className="review-summary">
              <div className="review-row">
                <span className="review-label">Estimated inputs selected</span>
                <strong className="review-value">{estimatedCount}</strong>
              </div>
              <div className="review-row">
                <span className="review-label">Estimated input total</span>
                <strong className="review-value">{estimatedTotalLabel}</strong>
              </div>
              <div className="review-row">
                <span className="review-label">Fee burned</span>
                <strong className="review-value">{formatAtoms(feeAtoms ?? 0n)} CMFD</strong>
              </div>
              <div className="review-row review-row-total">
                <span className="review-label">Estimated new wallet output</span>
                <strong className="review-value">{estimatedOutputLabel}</strong>
              </div>
            </div>
            <p className="form-help form-help-estimate">
              This is an estimate. Exact input and output totals are shown after the node accepts the transaction.
            </p>
            <p className="info-inline" role="note">
              Mine this transaction before consolidating the next batch.
            </p>
            {errors.form && <p className="form-error form-error-summary" role="alert">{errors.form}</p>}
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
              <button className="button-primary" type="button" onClick={submitConsolidation} disabled={busy}>
                {busy ? "Submitting…" : "Consolidate outputs"}
              </button>
            </div>
          </div>
        )}

        {phase === "complete" && result && (
          <div className="review-stack">
            <p className="dialog-description" id="consolidation-dialog-description">
              The node accepted the consolidation and returned these exact totals.
            </p>
            <div className="review-summary">
              <div className="review-row review-row-block">
                <span className="review-label">Transaction ID</span>
                <strong className="review-value review-value-hash" title={result.txid}>
                  {shortenHash(result.txid, 12, 12)}
                </strong>
              </div>
              <div className="review-row">
                <span className="review-label">Inputs consolidated</span>
                <strong className="review-value">{result.inputs_consolidated}</strong>
              </div>
              <div className="review-row">
                <span className="review-label">Exact input total</span>
                <strong className="review-value">{formatAtoms(result.input_atoms)} CMFD</strong>
              </div>
              <div className="review-row">
                <span className="review-label">Fee burned</span>
                <strong className="review-value">{formatAtoms(result.fee_burned_atoms)} CMFD</strong>
              </div>
              <div className="review-row review-row-total">
                <span className="review-label">New wallet output</span>
                <strong className="review-value">{formatAtoms(result.output_atoms)} CMFD</strong>
              </div>
            </div>
            <p className="info-inline" role="note">
              Mine this transaction before consolidating the next batch.
            </p>
            <div className="dialog-actions dialog-actions-single">
              <button className="button-primary" type="button" onClick={onClose}>Done</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
