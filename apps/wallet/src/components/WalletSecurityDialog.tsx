import { HardDriveDownload, KeyRound, LockKeyhole, RefreshCw, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";

import {
  backupWallet,
  chooseWalletBackupPath,
  lockWallet,
  migrateWalletEncryption,
  restoreWallet,
  unlockWallet,
} from "../api/nodeClient";
import type { WalletCustodyStatus } from "../types";

type CustodyAction = "create" | "unlock" | "backup" | "migrate" | "restore";

interface WalletSecurityDialogProps {
  open: boolean;
  required: boolean;
  status: WalletCustodyStatus | null;
  statusError: string | null;
  onClose: () => void;
  onStatusChange: (status: WalletCustodyStatus) => void;
  onCompleted: (message: string) => void;
  onRefresh: () => Promise<void> | void;
}

function defaultAction(status: WalletCustodyStatus | null): CustodyAction {
  if (!status || status.storage === "missing") return "create";
  if (status.storage === "plaintext") return "migrate";
  return status.unlocked ? "backup" : "unlock";
}

function passphraseBytes(value: string) {
  return new TextEncoder().encode(value).length;
}

function passphraseCharacters(value: string) {
  return Array.from(value).length;
}

export function WalletSecurityDialog({
  open,
  required,
  status,
  statusError,
  onClose,
  onStatusChange,
  onCompleted,
  onRefresh,
}: WalletSecurityDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const [action, setAction] = useState<CustodyAction>(() => defaultAction(status));
  const [path, setPath] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setAction(defaultAction(status));
    setPath("");
    setPassphrase("");
    setConfirmation("");
    setError(null);
  }, [open, status?.storage, status?.unlocked]);

  useEffect(() => {
    if (!open) return;
    const previousFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const frame = requestAnimationFrame(() => dialogRef.current?.focus());
    return () => {
      cancelAnimationFrame(frame);
      previousFocus?.focus();
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        if (!busy && !required) onClose();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [busy, onClose, open, required]);

  if (!open) return null;

  const needsPath = action === "backup" || action === "migrate" || action === "restore";
  const needsConfirmation = action === "create" || action === "migrate";
  const passphraseLabel = action === "unlock" || action === "restore" || action === "backup"
    ? "Wallet passphrase"
    : "New wallet passphrase";

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    setError(null);
    if (passphraseCharacters(passphrase) < 12) {
      setError("Use a passphrase containing at least 12 characters.");
      return;
    }
    if (passphraseBytes(passphrase) > 1_024) {
      setError("That passphrase is too long. Use fewer characters.");
      return;
    }
    if (needsConfirmation && confirmation !== passphrase) {
      setError("The passphrase confirmation does not match.");
      return;
    }
    if (needsPath && !path.trim()) {
      setError(action === "restore" ? "Choose the backup file to restore." : "Choose where to save your backup.");
      return;
    }

    const submittedPassphrase = passphrase;
    setPassphrase("");
    setConfirmation("");
    setBusy(true);
    try {
      const next = action === "unlock" || action === "create"
        ? await unlockWallet(submittedPassphrase)
        : action === "backup"
          ? await backupWallet(path, submittedPassphrase)
          : action === "migrate"
            ? await migrateWalletEncryption(path, submittedPassphrase)
            : await restoreWallet(path, submittedPassphrase);
      onStatusChange(next);
      onCompleted(action === "backup"
        ? "Encrypted wallet backup created. The wallet is locked."
        : action === "migrate"
          ? "Wallet encrypted and backup created. Unlock it to resume the node."
          : action === "restore"
            ? "Encrypted wallet restored. Unlock it to resume the node."
            : "Wallet unlocked and the embedded node started.");
      await Promise.resolve(onRefresh()).catch(() => undefined);
      setPath("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The wallet security operation failed.");
    } finally {
      setBusy(false);
    }
  };

  const choosePath = async () => {
    if (busy) return;
    setError(null);
    setBusy(true);
    try {
      const selected = await chooseWalletBackupPath(action === "restore");
      if (selected !== null) setPath(selected);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The file picker could not open.");
    } finally {
      setBusy(false);
    }
  };

  const lockNow = async () => {
    setError(null);
    setBusy(true);
    try {
      const next = await lockWallet();
      onStatusChange(next);
      onCompleted("Wallet locked and its decrypted signing key was released from memory.");
      await Promise.resolve(onRefresh()).catch(() => undefined);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The wallet could not be locked.");
    } finally {
      setBusy(false);
    }
  };

  const title = action === "create"
    ? "Create an encrypted wallet"
    : action === "unlock"
      ? "Unlock wallet"
      : action === "backup"
        ? "Back up wallet"
        : action === "migrate"
          ? "Encrypt existing wallet"
          : "Restore wallet";

  return (
    <div className="dialog-backdrop">
      <div
        ref={dialogRef}
        className="dialog-panel dialog-wide wallet-security-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="wallet-security-title"
        aria-busy={busy}
        tabIndex={-1}
      >
        <div className="dialog-header">
          <div>
            <p className="dialog-eyebrow">Local key custody</p>
            <h2 className="dialog-title" id="wallet-security-title">{title}</h2>
          </div>
          {!required ? (
            <button className="button-icon" type="button" onClick={onClose} disabled={busy} aria-label="Close wallet security">
              <span aria-hidden="true">×</span>
            </button>
          ) : null}
        </div>

        <div className="custody-summary">
          <span className={`custody-icon custody-${status?.storage ?? "unknown"}`}>
            {status?.storage === "encrypted" ? <ShieldCheck aria-hidden="true" size={22} /> : <KeyRound aria-hidden="true" size={22} />}
          </span>
          <div>
            <strong>{status?.storage === "encrypted"
              ? `Encrypted wallet · ${status.unlocked ? "unlocked" : "locked"}`
              : status?.storage === "plaintext"
                ? "Encryption upgrade available"
                : status?.storage === "missing"
                  ? "No local wallet key"
                  : "Checking wallet storage"}</strong>
            <span>{status?.network ?? "Common Foundry network"}</span>
          </div>
        </div>

        {statusError ? <p className="form-error custody-error" role="alert">{statusError}</p> : null}

        {status?.storage === "missing" ? (
          <div className="custody-action-switch" role="group" aria-label="Wallet setup choice">
            <button className={action === "create" ? "is-active" : ""} type="button" onClick={() => setAction("create")} disabled={busy}>Create new</button>
            <button className={action === "restore" ? "is-active" : ""} type="button" onClick={() => setAction("restore")} disabled={busy}>Restore backup</button>
          </div>
        ) : null}

        {status?.storage === "encrypted" && status.unlocked ? (
          <div className="custody-action-switch" role="group" aria-label="Wallet security choice">
            <button className={action === "backup" ? "is-active" : ""} type="button" onClick={() => setAction("backup")} disabled={busy}>Create backup</button>
            <button type="button" onClick={() => void lockNow()} disabled={busy}>
              <LockKeyhole aria-hidden="true" size={14} /> Lock now
            </button>
          </div>
        ) : null}

        <form className="form-stack" onSubmit={(event) => void submit(event)} noValidate>
          <p className="dialog-description">
            {action === "migrate"
              ? "This creates a separate authenticated backup first, then atomically replaces the local plaintext key with an encrypted copy."
              : action === "backup"
                ? "The backup is independently encrypted and created with no-overwrite protection. The wallet locks while the backup is made."
                : action === "restore"
                  ? "Restore accepts an authenticated Common Foundry backup only when no local wallet key exists."
                  : "Your passphrase is sent only to the local desktop process and is never saved by the wallet interface."}
          </p>

          {needsPath ? (
            <div className="form-field">
              <label htmlFor="custody-path">{action === "restore" ? "Backup file to restore" : "New backup file"}</label>
              <input
                id="custody-path"
                className="form-input form-input-mono"
                value={path}
                readOnly
                placeholder="No file selected"
                autoComplete="off"
                spellCheck={false}
                disabled={busy}
              />
              <button className="button-secondary" type="button" onClick={() => void choosePath()} disabled={busy}>
                {action === "restore" ? "Choose backup file…" : "Choose save location…"}
              </button>
              <small>{action === "restore" ? "Choose your encrypted Common Foundry backup." : "Select a folder and filename. Existing files are never overwritten."}</small>
            </div>
          ) : null}

          <div className="form-field">
            <label htmlFor="custody-passphrase">{passphraseLabel}</label>
            <input
              id="custody-passphrase"
              type="password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              autoComplete={needsConfirmation ? "new-password" : "current-password"}
              disabled={busy}
            />
            <small>At least 12 characters. Store it separately from the encrypted backup.</small>
          </div>

          {needsConfirmation ? (
            <div className="form-field">
              <label htmlFor="custody-confirmation">Confirm passphrase</label>
              <input
                id="custody-confirmation"
                type="password"
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
                autoComplete="new-password"
                disabled={busy}
              />
            </div>
          ) : null}

          {error ? <p className="form-error form-error-summary" role="alert">{error}</p> : null}

          <div className="dialog-actions">
            {!required ? <button className="button-secondary" type="button" onClick={onClose} disabled={busy}>Cancel</button> : null}
            <button className="button-primary" type="submit" disabled={busy || !status}>
              {busy ? <RefreshCw className="spin" aria-hidden="true" size={16} /> : action === "restore" || action === "backup" || action === "migrate" ? <HardDriveDownload aria-hidden="true" size={16} /> : <KeyRound aria-hidden="true" size={16} />}
              {busy ? "Working…" : title}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
