import { useEffect, useRef, useState, type ReactNode } from "react";

import {
  publishUpdateStatus,
  restartWithConfirmations,
  RUN_ANYWAY_TEXT,
  updateErrorMessage,
  updateTransport,
  useUpdateStatus,
  type RestartConfirm,
  type UpdateStatus,
  type UpdateTransport,
} from "../api/updateClient";
import { formatStorageSize } from "./ResyncDialog";

interface Question {
  message: string;
  action: string;
  answer: (yes: boolean) => void;
}

/**
 * "Restart to update" and "Retry", shared by the banner and the Updates
 * card. The wallet itself refuses a restart during a send, backup or
 * restore; its message is shown as it is. A question still open when
 * `notice` changes is answered "no", since its notice is gone.
 */
export function useRestartFlow(transport: UpdateTransport, notice?: string) {
  const [running, setRunning] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [question, setQuestion] = useState<Question | null>(null);
  const runningRef = useRef(false);
  const pending = useRef<((yes: boolean) => void) | null>(null);

  const confirm: RestartConfirm = (message, action) => new Promise((resolve) => {
    const answer = (yes: boolean) => {
      pending.current = null;
      setQuestion(null);
      resolve(yes);
    };
    pending.current = answer;
    setQuestion({ message, action, answer });
  });

  // A question or an error about a notice that is gone goes with it.
  useEffect(() => {
    pending.current?.(false);
    setError(null);
  }, [notice]);

  /** `retryVersion`: "Retry" of a version that failed to start. */
  const run = async (retryVersion?: string) => {
    if (runningRef.current) return;
    runningRef.current = true;
    setRunning(true);
    setError(null);
    try {
      const started = await restartWithConfirmations(
        (options) => (retryVersion === undefined
          ? transport.restartToUpdate(options)
          : transport.retryUpdate(retryVersion, options)),
        confirm,
      );
      if (started) setRestarting(true);
    } catch (cause) {
      setError(updateErrorMessage(cause));
    } finally {
      runningRef.current = false;
      setRunning(false);
    }
  };

  const notes = (
    <>
      {question ? (
        <div className="update-question" role="alertdialog" aria-label="Confirm restart">
          <span>{question.message}</span>
          <div className="update-actions">
            <button className="button-secondary compact" type="button" onClick={() => question.answer(true)}>
              {question.action}
            </button>
            <button className="button-quiet" type="button" onClick={() => question.answer(false)}>
              Cancel
            </button>
          </div>
        </div>
      ) : null}
      {restarting ? <span role="status">Restarting the wallet…</span> : null}
      {error ? <span className="update-refusal" role="alert">{error}</span> : null}
    </>
  );

  return { run, running: running || restarting, notes };
}

/** Why an update needs consent to copy the model bank (banner and card). */
export function copyConsentText(version: string, bytes: number): string {
  return `Version ${version} cannot share the model bank file with this version here `
    + "(another drive, OneDrive, or a USB or exFAT drive). "
    + `Installing it copies the file, which uses ${formatStorageSize(bytes)} more disk space.`;
}

type BannerView =
  | { kind: "held"; version: string; reason: string }
  | { kind: "restart_failed"; reason: string }
  | { kind: "failed"; version: string; reason: string }
  | { kind: "fell_back"; version: string; reason: string; afterData: boolean }
  | { kind: "ready"; version: string }
  | { kind: "needs_copy_consent"; version: string; bytes: number }
  | { kind: "install_failed"; version: string; reason: string; retryAutomatically: boolean }
  | { kind: "manual"; version: string; reason: string }
  | { kind: "not_verified"; version: string; reason: string }
  | { kind: "damaged"; version: string; reason: string }
  | { kind: "available"; version: string }
  | { kind: "downloading"; version: string }
  | { kind: "check_stale"; since: number };

/** What "Later" hides for the session; another version or reason shows again. */
export function bannerKey(view: BannerView): string {
  switch (view.kind) {
    case "held":
    case "failed":
    case "fell_back":
    case "install_failed":
    case "manual":
    case "not_verified":
    case "damaged":
      return `${view.kind}:${view.version}:${view.reason}`;
    case "restart_failed":
      return `${view.kind}:${view.reason}`;
    case "check_stale":
      return `${view.kind}:${view.since}`;
    case "ready":
    case "needs_copy_consent":
    case "available":
    case "downloading":
      return `${view.kind}:${view.version}`;
  }
}

/** Checks have failed for this long, or this many times in a row, before the banner says so. */
export const STALE_CHECK_SECONDS = 48 * 60 * 60;
export const STALE_CHECK_FAILURES = 4;

/** When checks have kept failing long enough to tell the user, since when; else null. */
export function staleCheckSince(status: UpdateStatus, nowSeconds: number): number | null {
  const since = status.check_failed_since;
  if (status.check_failures < 1 || since === null) return null;
  return status.check_failures >= STALE_CHECK_FAILURES || nowSeconds - since >= STALE_CHECK_SECONDS
    ? since
    : null;
}

/**
 * The most urgent notice that "Later" has not hidden. `downloading` shows
 * only for the version the user asked the banner to download.
 */
export function bannerView(
  status: UpdateStatus | null,
  dismissed: ReadonlySet<string> = new Set(),
  requested: string | null = null,
  nowSeconds: number = Date.now() / 1000,
): BannerView | null {
  if (!status) return null;
  const { fallback, status: state } = status;
  // Held has no Later: the wallet waits for Retry or Run anyway.
  if (fallback?.held) return { kind: "held", version: fallback.version, reason: fallback.reason };
  const views: BannerView[] = [];
  if (status.restart_failed) views.push({ kind: "restart_failed", reason: status.restart_failed });
  if (state.state === "failed_to_start") views.push({ kind: "failed", version: state.version, reason: state.reason });
  if (fallback) {
    views.push({ kind: "fell_back", version: fallback.version, reason: fallback.reason, afterData: fallback.after_data });
  }
  switch (state.state) {
    case "ready":
      views.push({ kind: "ready", version: state.version });
      break;
    case "needs_copy_consent":
      views.push({ kind: "needs_copy_consent", version: state.version, bytes: state.bytes });
      break;
    case "install_failed":
      views.push({
        kind: "install_failed",
        version: state.version,
        reason: state.reason,
        retryAutomatically: state.retry_automatically,
      });
      break;
    case "manual":
      views.push({ kind: "manual", version: state.version, reason: state.reason });
      break;
    case "not_verified":
      views.push({ kind: "not_verified", version: state.version, reason: state.reason });
      break;
    case "damaged":
      views.push({ kind: "damaged", version: state.version, reason: state.reason });
      break;
    case "available":
      if (!status.automatic) views.push({ kind: "available", version: state.version });
      break;
    case "downloading":
      if (state.version === requested) views.push({ kind: "downloading", version: state.version });
      break;
    default:
      break;
  }
  // Last: a quiet line once checks keep failing, so a wallet that cannot
  // reach the releases does not look up to date.
  const since = staleCheckSince(status, nowSeconds);
  if (since !== null) views.push({ kind: "check_stale", since });
  return views.find((view) => !dismissed.has(bannerKey(view))) ?? null;
}

/** The date a stale check line names. */
export function formatCheckDate(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

/** Why an installed update would not start, and how to get it back. */
export function damagedText(reason: string): string {
  return `${reasonText(reason)}. Antivirus software may have removed one of its files. Reinstall downloads it again.`;
}

/** A staged update starts on the next launch (TRIMMED-SCOPE: no soak). */
export const READY_DETAIL = "It starts the next time you open the wallet, or now with Restart to update.";

function reasonText(reason: string): string {
  return reason ? reason : "no reason given";
}

/**
 * How the forwarder words a hold for a version whose installed files are
 * damaged (updater/forward.rs `damaged_after_data`). Nothing records Run
 * anyway for such a hold, so it comes back at the next launch.
 */
export const DAMAGED_HOLD_PREFIX = "its installed files are damaged";

interface UpdateBannerProps {
  /**
   * The node's refusal while a newer version's failure holds this wallet.
   * Shown when the update status cannot be read, so the wallet is never
   * left without a message.
   */
  heldMessage?: string | null;
  /** After "Run anyway" started the node. */
  onRunAnyway?: () => void;
  transport?: UpdateTransport;
}

/** Update notices above the workspace: ready, failed, or waiting for a choice. */
export function UpdateBanner({ heldMessage = null, onRunAnyway, transport = updateTransport }: UpdateBannerProps) {
  const { status, error: statusError, refresh } = useUpdateStatus(transport);
  // "Later" hides a notice for the session; another version or reason
  // shows again.
  const [dismissed, setDismissed] = useState<ReadonlySet<string>>(() => new Set());
  // The version the banner was asked to download, so its progress shows.
  const [requested, setRequested] = useState<string | null>(null);
  const [runAnywayOpen, setRunAnywayOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const view = bannerView(status, dismissed, requested);
  const viewKey = view ? bannerKey(view) : undefined;
  const restart = useRestartFlow(transport, viewKey);
  // An error about a notice that is gone goes with it.
  useEffect(() => {
    setError(null);
  }, [viewKey]);
  if (!status && heldMessage) {
    return (
      <div className="offline-banner update-banner" role="alert">
        <div>
          <strong>This wallet waits for your choice</strong>
          <span>{heldMessage}</span>
          {statusError ? <span>The update status could not be read: {statusError}</span> : null}
        </div>
        <div className="update-actions">
          <button className="button-secondary compact" type="button" onClick={() => void refresh()}>
            Check again
          </button>
        </div>
      </div>
    );
  }
  if (!view || !status) return null;

  const act = async (call: () => Promise<UpdateStatus>, after?: () => void) => {
    setWorking(true);
    setError(null);
    try {
      publishUpdateStatus(await call());
      after?.();
    } catch (cause) {
      setError(updateErrorMessage(cause));
    } finally {
      setWorking(false);
    }
  };

  const busy = working || restart.running;
  const current = status.current_version;
  const download = (version: string, allowCopy: boolean) => {
    setRequested(version);
    void act(() => transport.downloadUpdate(allowCopy));
  };
  const later = (
    <button
      className="button-quiet"
      type="button"
      disabled={busy}
      onClick={() => setDismissed((previous) => new Set(previous).add(bannerKey(view)))}
    >
      Later
    </button>
  );
  let title: string;
  let detail: string | null = null;
  let actions: ReactNode;
  let alert = true;

  switch (view.kind) {
    case "held": {
      const damaged = view.reason.startsWith(DAMAGED_HOLD_PREFIX);
      title = damaged
        ? `Version ${view.version}'s installed files are damaged`
        : `Version ${view.version} stopped after it opened your wallet data`;
      detail = damaged
        ? `Reason: ${view.reason}. Version ${view.version} had opened your wallet data; this version (${current}) has not yet. `
          + `Reinstall version ${view.version} (antivirus software may have removed one of its files), then Retry it, or run ${current} anyway. `
          + `Run anyway lasts until this wallet closes: the question comes back at the next launch until version ${view.version} is reinstalled or its folder is removed. `
          + "An older version may not read data that a newer one changed."
        : `Reason: ${reasonText(view.reason)}. This version (${current}) has not opened your wallet data yet. `
          + `Retry version ${view.version}, or run ${current} anyway. An older version may not read data that a newer one changed.`;
      actions = (
        <>
          {damaged ? (
            <button className="button-secondary compact" type="button" disabled={busy} onClick={() => download(view.version, false)}>
              Reinstall {view.version}
            </button>
          ) : null}
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => void restart.run(view.version)}>
            Retry {view.version}
          </button>
          <button className="button-quiet" type="button" disabled={busy} onClick={() => setRunAnywayOpen(true)}>
            Run {current} anyway
          </button>
        </>
      );
      break;
    }
    case "restart_failed":
      title = "The update could not be started";
      detail = `Reason: ${reasonText(view.reason)}. This version (${current}) is running instead.`;
      actions = (
        <>
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => void restart.run()}>
            Try again
          </button>
          {later}
        </>
      );
      break;
    case "failed":
      title = `Version ${view.version} failed to start`;
      detail = `Reason: ${reasonText(view.reason)}. This version (${current}) is running instead.`;
      actions = (
        <>
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => void restart.run(view.version)}>
            Retry {view.version}
          </button>
          {later}
        </>
      );
      break;
    case "fell_back":
      title = view.afterData
        ? `Version ${view.version} stopped after it opened your wallet data`
        : `Version ${view.version} could not start`;
      detail = view.afterData
        ? `Reason: ${reasonText(view.reason)}. You chose to run ${current} anyway.`
        : `Reason: ${reasonText(view.reason)}. This version (${current}) is running instead.`;
      actions = (
        <>
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => void restart.run(view.version)}>
            Retry {view.version}
          </button>
          {later}
        </>
      );
      break;
    case "ready":
      alert = false;
      title = `Version ${view.version} is ready.`;
      detail = READY_DETAIL;
      actions = (
        <>
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => void restart.run()}>
            Restart to update
          </button>
          {later}
        </>
      );
      break;
    case "needs_copy_consent":
      alert = false;
      title = `Version ${view.version} waits for your consent to install`;
      detail = copyConsentText(view.version, view.bytes);
      actions = (
        <>
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => download(view.version, true)}>
            Copy and install
          </button>
          {later}
        </>
      );
      break;
    case "install_failed":
      title = `Version ${view.version} could not be installed`;
      detail = `Reason: ${reasonText(view.reason)}. `
        + (view.retryAutomatically
          ? "The next check tries again."
          : "It is not tried again on its own. Antivirus software may have removed one of its files.");
      actions = (
        <>
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => download(view.version, false)}>
            Try again
          </button>
          {later}
        </>
      );
      break;
    case "manual":
      title = `Version ${view.version} must be installed by hand`;
      detail = `Reason: ${reasonText(view.reason)}. This version (${current}) keeps running.`;
      actions = later;
      break;
    case "not_verified":
      title = `Version ${view.version} did not pass its checks, so it was not installed`;
      detail = `Reason: ${reasonText(view.reason)}. This version (${current}) keeps running.`;
      actions = later;
      break;
    case "damaged":
      title = `Version ${view.version} is installed, but some of its files are missing or changed`;
      detail = `Reason: ${damagedText(view.reason)}`;
      actions = (
        <>
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => download(view.version, false)}>
            Reinstall
          </button>
          {later}
        </>
      );
      break;
    case "check_stale":
      alert = false;
      title = `Updates could not be checked since ${formatCheckDate(view.since)}.`;
      detail = "Network → Updates has details.";
      actions = later;
      break;
    case "available":
      alert = false;
      title = `Version ${view.version} is available.`;
      actions = (
        <>
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => download(view.version, false)}>
            Download
          </button>
          {later}
        </>
      );
      break;
    case "downloading":
      alert = false;
      title = `Downloading version ${view.version}…`;
      actions = null;
      break;
  }

  const runAnyway = () => act(() => transport.runOlderAnyway(typed), () => {
    setRunAnywayOpen(false);
    setTyped("");
    onRunAnyway?.();
  });

  return (
    <div
      className={alert ? "offline-banner update-banner" : "work-check-progress update-banner"}
      role={alert ? "alert" : "status"}
    >
      <div>
        <strong>{title}</strong>
        {detail ? <span>{detail}</span> : null}
        {runAnywayOpen && view.kind === "held" ? (
          <form className="update-run-anyway" onSubmit={(event) => { event.preventDefault(); void runAnyway(); }}>
            <label htmlFor="update-run-anyway-text">
              To run {current} on this wallet&apos;s data, type &quot;{RUN_ANYWAY_TEXT}&quot;.
            </label>
            <input
              id="update-run-anyway-text"
              className="form-input"
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            <div className="update-actions">
              <button className="button-secondary compact" type="submit" disabled={busy || !typed.trim()}>
                Run anyway
              </button>
              <button className="button-quiet" type="button" disabled={busy} onClick={() => { setRunAnywayOpen(false); setTyped(""); }}>
                Cancel
              </button>
            </div>
          </form>
        ) : null}
        {restart.notes}
        {error ? <span className="update-refusal" role="alert">{error}</span> : null}
      </div>
      <div className="update-actions">{actions}</div>
    </div>
  );
}
