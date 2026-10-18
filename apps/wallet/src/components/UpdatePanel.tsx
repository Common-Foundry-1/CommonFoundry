import { Download, RefreshCw, Trash2 } from "lucide-react";
import { useState, type ReactNode } from "react";

import {
  formatCheckedAt,
  publishUpdateStatus,
  updateErrorMessage,
  updateTransport,
  useUpdateStatus,
  type UpdateStatus,
  type UpdateTransport,
} from "../api/updateClient";
import { formatStorageSize } from "./ResyncDialog";
import { copyConsentText, damagedText, READY_DETAIL, useRestartFlow } from "./UpdateBanner";

interface UpdatePanelProps {
  transport?: UpdateTransport;
}

/** Settings → Network → Updates. */
export function UpdatePanel({ transport = updateTransport }: UpdatePanelProps) {
  const { status, error, refresh } = useUpdateStatus(transport);
  const restart = useRestartFlow(transport);
  const [working, setWorking] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState(false);

  const act = async (call: () => Promise<UpdateStatus>) => {
    setWorking(true);
    setActionError(null);
    try {
      publishUpdateStatus(await call());
    } catch (cause) {
      setActionError(updateErrorMessage(cause));
      // A refused or partly done action (a removal blocked by a file lock)
      // may still have changed what the wallet reports.
      await refresh();
    } finally {
      setWorking(false);
    }
  };

  const busy = working || restart.running;
  const state = status?.status;
  const usable = status !== null && state?.state !== "unsupported" && state?.state !== "disabled";
  const checking = state?.state === "checking" || state?.state === "downloading";

  let line: string;
  let action: ReactNode = null;
  if (!status || !state) {
    line = error ?? "Loading update status…";
  } else {
    switch (state.state) {
      case "unsupported":
        line = `This wallet does not update itself: ${state.reason}.`;
        break;
      case "disabled":
        line = "Updates are turned off for this run by a launch option (--no-auto-update or CMFD_NO_AUTO_UPDATE=1).";
        break;
      case "idle":
        line = "Not checked yet.";
        break;
      case "checking":
        line = "Checking for updates…";
        break;
      case "up_to_date":
        line = status.last_checked_at === null
          ? "Up to date."
          : `Up to date (checked ${formatCheckedAt(status.last_checked_at)}).`;
        break;
      case "available":
        line = `Version ${state.version} is available.`;
        action = (
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => void act(() => transport.downloadUpdate(false))}>
            <Download aria-hidden="true" size={15} />
            Download
          </button>
        );
        break;
      case "downloading":
        line = `Downloading version ${state.version}…`;
        break;
      case "ready":
        line = `Version ${state.version} is ready. ${READY_DETAIL}`;
        action = status.fallback?.held ? null : (
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => void restart.run()}>
            Restart to update
          </button>
        );
        break;
      case "not_verified":
        line = `Version ${state.version} did not pass its checks, so it was not installed: ${state.reason}`;
        break;
      case "check_failed":
        line = `The last check failed: ${state.reason}`;
        break;
      case "damaged":
        line = `Version ${state.version} is installed but damaged: ${damagedText(state.reason)}`;
        action = (
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => void act(() => transport.downloadUpdate(false))}>
            <Download aria-hidden="true" size={15} />
            Reinstall
          </button>
        );
        break;
      case "needs_copy_consent":
        line = copyConsentText(state.version, state.bytes);
        action = (
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => void act(() => transport.downloadUpdate(true))}>
            <Download aria-hidden="true" size={15} />
            Copy and install
          </button>
        );
        break;
      case "manual":
        line = `Version ${state.version} must be installed by hand: ${state.reason}`;
        break;
      case "install_failed":
        line = `Version ${state.version} could not be installed: ${state.reason}`
          + (state.retry_automatically ? " The next check tries again." : "");
        action = (
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => void act(() => transport.downloadUpdate(false))}>
            Try again
          </button>
        );
        break;
      case "failed_to_start":
        line = `Version ${state.version} failed to start: ${state.reason}`;
        action = (
          <button className="button-secondary compact" type="button" disabled={busy} onClick={() => void restart.run(state.version)}>
            Retry {state.version}
          </button>
        );
        break;
    }
  }

  // A launch option turns updates off for this run, whatever is saved.
  const offForThisRun = status?.disabled_by_launch_option === true;
  const automatic = !offForThisRun && (status?.automatic ?? true);
  const oldVersions = status?.old_versions ?? [];

  return (
    <div className="peer-settings update-panel" aria-labelledby="updates-heading">
      <div className="peer-panel-heading">
        <div>
          <span>Version {status?.current_version ?? "—"}</span>
          <h3 id="updates-heading">Updates</h3>
        </div>
        <button
          className="button-quiet"
          type="button"
          disabled={!usable || busy || checking}
          onClick={() => void act(() => transport.checkForUpdates())}
        >
          <RefreshCw className={checking ? "spin" : undefined} aria-hidden="true" size={14} />
          Check now
        </button>
      </div>
      <label className="update-switch">
        <input
          type="checkbox"
          role="switch"
          checked={automatic}
          disabled={!usable || busy}
          onChange={(event) => void act(() => transport.setUpdateAutomatic(event.target.checked))}
        />
        <span>Update automatically</span>
      </label>
      <p className="peer-panel-help">
        {offForThisRun
          ? "Turned off for this run by a launch option. Without it, the saved setting applies again."
          : automatic
            ? "The wallet checks for signed updates about every 6 hours, downloads them and installs them next to this version. An update starts when you restart the wallet."
            : "The wallet tells you when a new version is available. Nothing is downloaded until you choose Download."}
      </p>
      <div className="update-status-line">
        <span aria-live="polite">{line}</span>
        {action}
      </div>
      {restart.notes}
      {actionError ? <p className="form-error" role="alert">{actionError}</p> : null}
      {oldVersions.length > 0 ? (
        <div className="update-old-versions">
          <h4>Old versions</h4>
          <p className="peer-panel-help">
            These older versions are no longer needed. Files shared with the running version stay where they are.
          </p>
          <ul className="configured-peer-list">
            {oldVersions.map((old) => (
              <li key={old.path}>
                <code title={old.path}>{old.path}</code>
                <span>{formatStorageSize(old.bytes)} of files in folder</span>
              </li>
            ))}
          </ul>
          {confirmRemove ? (
            <div className="update-question" role="alertdialog" aria-label="Confirm removal">
              <span>Delete {oldVersions.length === 1 ? "this folder" : `these ${oldVersions.length} folders`}? This cannot be undone.</span>
              <div className="update-actions">
                <button
                  className="button-secondary compact"
                  type="button"
                  disabled={busy}
                  onClick={() => void act(() => transport.removeOldVersions()).then(() => setConfirmRemove(false))}
                >
                  Delete
                </button>
                <button className="button-quiet" type="button" disabled={busy} onClick={() => setConfirmRemove(false)}>
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <button className="button-quiet" type="button" disabled={busy} onClick={() => setConfirmRemove(true)}>
              <Trash2 aria-hidden="true" size={14} />
              Remove old versions
            </button>
          )}
        </div>
      ) : null}
    </div>
  );
}
