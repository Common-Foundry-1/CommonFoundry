import { useEffect, useRef, useState } from "react";

import { resyncChain } from "../api/nodeClient";
import type { ChainResyncReport, WalletCustodyStatus } from "../types";

interface ResyncDialogProps {
  open: boolean;
  onClose: () => void;
  onStatusChange: (status: WalletCustodyStatus) => void;
  onCompleted: (message: string) => void;
  onRefresh: () => Promise<void> | void;
}

/** A size on disk, in the units a file manager shows. */
export function formatStorageSize(bytes: number): string {
  const units = ["bytes", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return unit === 0 ? `${value} ${units[0]}` : `${value.toFixed(1)} ${units[unit]}`;
}

/** What the wallet tells the user once the stored chain is set aside. */
export function resyncCompletedMessage(report: ChainResyncReport): string {
  const moved = `The stored chain (${formatStorageSize(report.moved_bytes)}) was moved to ${report.moved_to}. `
    + "You can delete that folder once the wallet has synced again.";
  return report.custody.unlocked
    ? `${moved} The wallet is downloading the chain again.`
    : `${moved} Unlock the wallet to download the chain again.`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error && error.message
    ? error.message
    : "The chain could not be resynced. Close and reopen the wallet, then try again.";
}

/** Confirms moving the stored chain aside so the wallet downloads it again. */
export function ResyncDialog({ open, onClose, onStatusChange, onCompleted, onRefresh }: ResyncDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const runningRef = useRef(false);

  useEffect(() => {
    if (open) setError(null);
  }, [open]);

  const closeIfIdle = () => {
    if (!runningRef.current) onClose();
  };

  useEffect(() => {
    if (!open) return;
    const previousFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const frame = requestAnimationFrame(() => dialogRef.current?.focus());
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        if (!runningRef.current) onClose();
        return;
      }
      if (event.key === "Tab" && dialogRef.current) {
        const controls = Array.from(
          dialogRef.current.querySelectorAll<HTMLElement>("button:not([disabled])"),
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

  const resync = async () => {
    if (runningRef.current) return;
    runningRef.current = true;
    setRunning(true);
    setError(null);
    try {
      const report = await resyncChain();
      onStatusChange(report.custody);
      onCompleted(resyncCompletedMessage(report));
      onClose();
      await Promise.resolve(onRefresh()).catch(() => undefined);
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      runningRef.current = false;
      setRunning(false);
    }
  };

  return (
    <div className="dialog-backdrop">
      <div
        ref={dialogRef}
        className="dialog-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="resync-dialog-title"
        aria-describedby="resync-dialog-description"
        tabIndex={-1}
      >
        <div className="dialog-header">
          <div className="dialog-heading">
            <p className="dialog-eyebrow">Stored chain</p>
            <h2 className="dialog-title" id="resync-dialog-title">Resync the chain</h2>
          </div>
          <button
            className="button-icon"
            type="button"
            onClick={closeIfIdle}
            disabled={running}
            aria-label="Close resync dialog"
          >
            <span aria-hidden="true">×</span>
          </button>
        </div>

        <p className="dialog-description" id="resync-dialog-description">
          The wallet moves the blocks it has stored into a new folder inside its data directory and
          downloads the whole chain again from other nodes. Nothing is deleted, and your wallet key and
          backups stay where they are.
        </p>
        <p className="form-help">
          Until you delete the moved folder, the chain takes about twice its disk space. The download
          and the block check can take a long time; coins show as Verifying until the blocks that hold
          them are checked. If the wallet is encrypted, unlock it again afterwards.
        </p>

        {error ? <p className="form-error form-error-summary" role="alert">{error}</p> : null}
        <p className="form-status" aria-live="polite">
          {running ? "Moving the stored chain aside…" : ""}
        </p>

        <div className="dialog-actions">
          <button className="button-secondary" type="button" onClick={closeIfIdle} disabled={running}>
            Cancel
          </button>
          <button className="button-primary" type="button" onClick={() => void resync()} disabled={running}>
            Resync chain
          </button>
        </div>
      </div>
    </div>
  );
}
