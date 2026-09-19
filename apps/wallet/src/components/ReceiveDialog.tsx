import { useEffect, useRef, useState } from "react";
import { QRCodeSVG } from "qrcode.react";

import type { WalletSnapshot } from "../types";

interface ReceiveDialogProps {
  open: boolean;
  wallet: Pick<WalletSnapshot, "destination" | "network" | "insecure_demo_wallet" | "warning"> | null;
  onClose: () => void;
}

export function ReceiveDialog({ open, wallet, onClose }: ReceiveDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const [copyState, setCopyState] = useState<"idle" | "copying" | "copied" | "error">("idle");

  useEffect(() => {
    if (!open) return;
    setCopyState("idle");
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
        onClose();
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

  const address = wallet?.destination ?? "";

  const copyAddress = async () => {
    if (!address) return;
    setCopyState("copying");
    try {
      await navigator.clipboard.writeText(address);
      setCopyState("copied");
    } catch {
      setCopyState("error");
    }
  };

  const copyLabel = copyState === "copying"
    ? "Copying…"
    : copyState === "copied"
      ? "Address copied"
      : "Copy address";

  return (
    <div className="dialog-backdrop">
      <div
        ref={dialogRef}
        className="dialog-panel dialog-panel-receive"
        role="dialog"
        aria-modal="true"
        aria-labelledby="receive-dialog-title"
        aria-describedby="receive-dialog-description"
        tabIndex={-1}
      >
        <div className="dialog-header">
          <div className="dialog-heading">
            <p className="dialog-eyebrow">{wallet?.network ?? "Network"} wallet</p>
            <h2 className="dialog-title" id="receive-dialog-title">Receive CMFD</h2>
          </div>
          <button className="button-icon" type="button" onClick={onClose} aria-label="Close receive dialog">
            <span aria-hidden="true">×</span>
          </button>
        </div>

        <p className="dialog-description" id="receive-dialog-description">
          Mine or receive CMFD at this compiled-network x-only public key.
        </p>

        {address ? (
          <>
            <div className="dialog-qr" aria-label="QR code for the wallet address">
              <QRCodeSVG value={address} size={216} level="M" marginSize={2} />
            </div>
            <p className="dialog-address-label">Your {wallet?.network ?? "network"} address</p>
            <output className="dialog-address" aria-label="Wallet address">{address}</output>
            <button
              className="button-secondary button-copy"
              type="button"
              onClick={copyAddress}
              disabled={copyState === "copying"}
            >
              {copyLabel}
            </button>
            <p className="form-status" aria-live="polite">
              {copyState === "error" ? "Clipboard access failed. Select and copy the address manually." : ""}
            </p>
          </>
        ) : (
          <p className="form-error form-error-summary" role="alert">
            The wallet address is unavailable. Reconnect to the local node and try again.
          </p>
        )}

        {wallet?.insecure_demo_wallet ? (
          <div className="security-panel" role="alert">
            <strong className="security-title">{wallet.network} wallet</strong>
            <span className="security-copy">{wallet.warning}</span>
          </div>
        ) : wallet ? (
          <div className="wallet-context" role="note">
            <strong>{wallet.network} wallet</strong>
            <span>{wallet.warning}</span>
          </div>
        ) : null}

        <div className="dialog-actions dialog-actions-single">
          <button className="button-primary" type="button" onClick={onClose}>Done</button>
        </div>
      </div>
    </div>
  );
}
