import {
  Activity,
  AlertTriangle,
  Boxes,
  Check,
  ChevronRight,
  CircleDollarSign,
  Copy,
  Database,
  FileClock,
  FileText,
  Gauge,
  HardDrive,
  LockKeyhole,
  Pause,
  Play,
  RefreshCw,
  RotateCcw,
  Save,
  Server,
  Settings2,
  ShieldCheck,
  Square,
  TerminalSquare,
  Users,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  createOperatorSession,
  fetchOperatorLog,
  fetchOperatorStatus,
  runPoolAction,
  savePoolSettings,
} from "./api";
import logo from "../../pool-dashboard/src/assets/common-foundry-mark.png";
import type { OperatorLog, OperatorStatus } from "./types";

type ControlAction = "start" | "stop" | "restart";
type Confirmation = ControlAction | "save-restart" | null;

function formatNumber(value: number | null | undefined): string {
  return value == null ? "—" : new Intl.NumberFormat().format(value);
}

function formatAtoms(value: number | null | undefined): string {
  if (value == null) return "—";
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 8 }).format(value / 100_000_000);
}

function formatDuration(seconds: number | null): string {
  if (seconds == null) return "—";
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  const remainder = seconds % 60;
  if (days) return `${days}d ${hours}h ${minutes}m`;
  if (hours) return `${hours}h ${minutes}m ${remainder}s`;
  return `${minutes}m ${remainder}s`;
}

function formatTime(seconds: number): string {
  return new Date(seconds * 1_000).toLocaleTimeString([], {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
  });
}

function truncate(value: string | null | undefined, head = 12, tail = 10): string {
  if (!value) return "Unavailable";
  return value.length > head + tail + 3 ? `${value.slice(0, head)}…${value.slice(-tail)}` : value;
}

function Metric({ icon, label, value, note }: { icon: React.ReactNode; label: string; value: string; note: string }) {
  return (
    <div className="metric">
      <div className="metric-icon">{icon}</div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{note}</small>
      </div>
    </div>
  );
}

function HealthRow({
  icon,
  service,
  state,
  detail,
  tone = "healthy",
}: {
  icon: React.ReactNode;
  service: string;
  state: string;
  detail: string;
  tone?: "healthy" | "configured" | "offline";
}) {
  return (
    <div className="health-row">
      <div className="health-service">{icon}<strong>{service}</strong></div>
      <span className={`health-state ${tone}`}><i />{state}</span>
      <span className="health-detail">{detail}</span>
    </div>
  );
}

function LoadingScreen() {
  return (
    <main className="loading-screen">
      <img src={logo} alt="" />
      <p>Opening the local operator console</p>
      <div className="loading-rule"><span /></div>
    </main>
  );
}

export function App() {
  const [csrfToken, setCsrfToken] = useState("");
  const [status, setStatus] = useState<OperatorStatus | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmation, setConfirmation] = useState<Confirmation>(null);
  const [notice, setNotice] = useState("");
  const [feePercent, setFeePercent] = useState("3.00");
  const [windowShares, setWindowShares] = useState("0");
  const [settingsDirty, setSettingsDirty] = useState(false);
  const [log, setLog] = useState<OperatorLog | null>(null);
  const [logOpen, setLogOpen] = useState(false);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    try {
      const next = await fetchOperatorStatus(signal);
      setStatus(next);
      setError("");
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) {
        setError(caught instanceof Error ? caught.message : "Operator status is unavailable");
      }
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void createOperatorSession()
      .then((token) => {
        setCsrfToken(token);
        return refresh(controller.signal);
      })
      .catch((caught) => setError(caught instanceof Error ? caught.message : "Operator console is unavailable"));
    const timer = window.setInterval(() => void refresh(controller.signal), 5_000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [refresh]);

  useEffect(() => {
    if (status?.settings && !settingsDirty) {
      setFeePercent((status.settings.operator_fee_bps / 100).toFixed(2));
      setWindowShares(String(status.settings.pplns_window_shares));
    }
  }, [settingsDirty, status]);

  const snapshot = status?.snapshot;
  const pool = snapshot?.pool;
  const ledger = pool?.ledger;
  const running = status?.pool.running ?? false;
  const actionDisabled = busy || status?.action_busy || !csrfToken;
  const operatorFeeBps = Math.round(Number(feePercent) * 100);
  const parsedWindow = Number(windowShares);
  const settingsValid = Number.isFinite(operatorFeeBps)
    && operatorFeeBps >= 0
    && operatorFeeBps <= 10_000
    && Number.isInteger(parsedWindow)
    && parsedWindow >= 0
    && parsedWindow <= 65_536;

  const serviceRows = useMemo(() => {
    if (!status) return [];
    return [
      {
        icon: <Server size={17} />,
        service: "Pool process",
        state: running ? "Running" : "Stopped",
        detail: running ? `PID ${status.pool.pid} · uptime ${formatDuration(status.pool.uptime_seconds)}` : "Ready for a saved-settings start",
        tone: running ? "healthy" as const : "offline" as const,
      },
      {
        icon: <Gauge size={17} />,
        service: "Public dashboard",
        state: status.pool.dashboard_healthy ? "Healthy" : running ? "Starting" : "Offline",
        detail: status.pool.dashboard_healthy ? `Chain tip at height ${formatNumber(pool?.accepted_height)}` : status.pool.dashboard_error || "Starts with the pool",
        tone: status.pool.dashboard_healthy ? "healthy" as const : running ? "configured" as const : "offline" as const,
      },
      {
        icon: <Activity size={17} />,
        service: "P2P",
        state: status.settings ? "Configured" : "Unavailable",
        detail: status.settings ? `Listening on ${status.settings.p2p_bind}` : "Run the pool launcher once to create settings",
        tone: status.settings ? "configured" as const : "offline" as const,
      },
      {
        icon: <LockKeyhole size={17} />,
        service: "Pool TLS",
        state: snapshot?.certificate_sha256 ? "Pinned" : running ? "Starting" : "Offline",
        detail: snapshot?.certificate_sha256 ? `SHA-256 ${truncate(snapshot.certificate_sha256)}` : "Certificate identity is retained between starts",
        tone: snapshot?.certificate_sha256 ? "healthy" as const : running ? "configured" as const : "offline" as const,
      },
      {
        icon: <Boxes size={17} />,
        service: "Proof workers",
        state: running ? "Managed" : "Stopped",
        detail: running ? `${formatNumber(pool?.active_share_verifications)} active · ${formatNumber(pool?.queued_share_verifications)} queued` : "Persistent replay and proof workers start with the pool",
        tone: running ? "configured" as const : "offline" as const,
      },
    ];
  }, [pool, running, snapshot, status]);

  const copy = async (value: string) => {
    await navigator.clipboard.writeText(value);
    setNotice("Copied to clipboard");
    window.setTimeout(() => setNotice(""), 2_000);
  };

  const performControl = async (action: ControlAction) => {
    setBusy(true);
    setError("");
    setConfirmation(null);
    try {
      await runPoolAction(action, csrfToken);
      setNotice(action === "start" ? "Pool launch requested" : action === "stop" ? "Pool stopped cleanly" : "Pool restart requested");
      window.setTimeout(() => void refresh(), action === "start" || action === "restart" ? 1_000 : 100);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : `Could not ${action} the pool`);
    } finally {
      setBusy(false);
    }
  };

  const saveSettings = async (restart: boolean) => {
    if (!settingsValid) {
      setError("Operator fee must be 0–100%; PPLNS window must be 0–65,536 shares.");
      return;
    }
    setBusy(true);
    setError("");
    setConfirmation(null);
    try {
      await savePoolSettings(
        { operator_fee_bps: operatorFeeBps, pplns_window_shares: parsedWindow },
        csrfToken,
      );
      setSettingsDirty(false);
      if (restart) {
        await runPoolAction(running ? "restart" : "start", csrfToken);
        setNotice(running ? "Settings saved; pool restart requested" : "Settings saved; pool launch requested");
      } else {
        setNotice("Settings saved for the next pool start");
      }
      window.setTimeout(() => void refresh(), restart ? 1_000 : 100);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not save pool settings");
    } finally {
      setBusy(false);
    }
  };

  const openLog = async () => {
    setLogOpen(true);
    try {
      setLog(await fetchOperatorLog());
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not read the pool log");
    }
  };

  if (!status && !error) return <LoadingScreen />;

  if (!status) {
    return (
      <main className="fatal-error">
        <AlertTriangle />
        <div>
          <span className="eyebrow">LOCAL OPERATOR CONSOLE</span>
          <h1>Pool controls are unavailable.</h1>
          <p>{error}</p>
          <button className="primary-button" onClick={() => void refresh()}><RefreshCw size={16} /> Retry</button>
        </div>
      </main>
    );
  }

  return (
    <div className="operator-app">
      <header className="topbar">
        <div className="brand">
          <img src={logo} alt="Common Foundry" />
          <span>COMMON FOUNDRY</span>
        </div>
        <div className="title-lockup">
          <h1>Pool Operator Console</h1>
          <span className="local-only"><ShieldCheck size={13} /> LOCAL ONLY</span>
        </div>
        <div className="header-status">
          <span className={`running-dot ${running ? "is-running" : ""}`} />
          <strong>{running ? "Pool running" : "Pool stopped"}</strong>
          <span>{pool ? `Height ${formatNumber(pool.accepted_height)}` : "No live snapshot"}</span>
          <span>Updated {formatTime(status.generated_at_unix_seconds)}</span>
          <button aria-label="Refresh operator status" onClick={() => void refresh()}><RefreshCw size={16} /></button>
        </div>
      </header>

      {(notice || error) && (
        <div className={`notice-bar ${error ? "notice-error" : ""}`} role="status">
          {error ? <AlertTriangle size={16} /> : <Check size={16} />}
          <span>{error || notice}</span>
          <button aria-label="Dismiss message" onClick={() => { setError(""); setNotice(""); }}><X size={15} /></button>
        </div>
      )}

      <main className="console-grid">
        <aside className="control-rail">
          <div className="rail-heading">
            <h2>Pool control</h2>
            <Settings2 size={18} />
          </div>
          <section className="process-panel">
            <div className="process-title"><span className={`running-dot ${running ? "is-running" : ""}`} /><strong>{running ? "Pool running" : "Pool stopped"}</strong></div>
            <dl>
              <div><dt>Process ID</dt><dd>{status.pool.pid ?? "—"}</dd></div>
              <div><dt>Uptime</dt><dd>{formatDuration(status.pool.uptime_seconds)}</dd></div>
              <div><dt>Dashboard</dt><dd>{status.pool.dashboard_url || "Offline"}</dd></div>
            </dl>
          </section>

          <div className="control-buttons">
            <button className="control-button" disabled={running || actionDisabled} onClick={() => void performControl("start")}><Play size={18} /> Start</button>
            <button className="control-button danger" disabled={!running || actionDisabled} onClick={() => setConfirmation("stop")}><Square size={17} /> Stop gracefully</button>
            <button className="control-button restart" disabled={!running || actionDisabled} onClick={() => setConfirmation("restart")}><RotateCcw size={18} /> Restart</button>
          </div>

          {confirmation && confirmation !== "save-restart" && (
            <div className="confirmation" role="alert">
              <strong>{confirmation === "stop" ? "Stop the pool?" : "Restart the pool?"}</strong>
              <p>Ledger state is preserved through a graceful shutdown.</p>
              <div><button onClick={() => setConfirmation(null)}>Cancel</button><button className="confirm-action" onClick={() => void performControl(confirmation)}>Confirm</button></div>
            </div>
          )}

          <div className="log-block">
            <span>ACTIVE LOG</span>
            <code title={status.pool.log_file || ""}>{truncate(status.pool.log_file, 20, 22)}</code>
            <button onClick={() => void openLog()}><FileText size={16} /> View latest log <ChevronRight size={14} /></button>
          </div>
          <div className="local-note"><ShieldCheck size={19} /><span>These controls affect only the pool process on this machine.</span></div>
        </aside>

        <div className="main-workspace">
          <section className="metrics-rail" aria-label="Pool accounting summary">
            <Metric icon={<Users />} label="Connected workers" value={formatNumber(pool?.active_connections)} note={`${formatNumber(pool?.workers.filter((worker) => worker.connected).length)} active identities`} />
            <Metric icon={<Check />} label="Accepted shares" value={formatNumber(ledger?.accepted_shares)} note="Durable PPLNS work" />
            <Metric icon={<X />} label="Rejected shares" value={formatNumber(ledger?.rejected_shares)} note="Total validation rejects" />
            <Metric icon={<FileClock />} label="Pending PPLNS blocks" value={formatNumber(ledger?.pplns_pending_blocks)} note="Waiting for maturity" />
            <Metric icon={<Boxes />} label="Distributed blocks" value={formatNumber(ledger?.pplns_distributed_blocks)} note={`${formatNumber(ledger?.pool_blocks)} found total`} />
            <Metric icon={<CircleDollarSign />} label="Operator earnings" value={formatAtoms(ledger?.operator_fee_atoms)} note="CMFD matured" />
          </section>

          <section className="health-section">
            <div className="section-heading">
              <div><span className="eyebrow">LIVE SERVICES</span><h2>Pool health</h2></div>
              <span className={`summary-state ${running && status.pool.dashboard_healthy ? "healthy" : ""}`}><i />{running && status.pool.dashboard_healthy ? "Core services responding" : running ? "Pool is starting" : "Pool is stopped"}</span>
            </div>
            <div className="health-table">
              {serviceRows.map((row) => <HealthRow key={row.service} {...row} />)}
            </div>
          </section>

          <section className="activity-section">
            <div className="section-heading">
              <div><span className="eyebrow">LOCAL AUDIT TRAIL</span><h2>Recent operator activity</h2></div>
              <span>{status.events.length} event{status.events.length === 1 ? "" : "s"} this session</span>
            </div>
            <div className="activity-table" role="table" aria-label="Recent operator activity">
              <div className="activity-row activity-head" role="row"><span>Time</span><span>Event</span><span>Details</span><span>Source</span></div>
              {status.events.map((event, index) => (
                <div className="activity-row" role="row" key={`${event.time_unix_seconds}-${index}`}>
                  <time>{formatTime(event.time_unix_seconds)}</time>
                  <strong>{event.event}</strong>
                  <span>{event.details}</span>
                  <span>{event.source}</span>
                </div>
              ))}
            </div>
          </section>

          {logOpen && (
            <section className="log-viewer">
              <div className="section-heading">
                <div><span className="eyebrow">LATEST POOL LOG</span><h2>Runtime output</h2></div>
                <div className="log-actions"><button onClick={() => void openLog()}><RefreshCw size={15} /> Refresh</button><button onClick={() => setLogOpen(false)}><X size={16} /> Close</button></div>
              </div>
              <code>{log?.text || "Loading log…"}</code>
            </section>
          )}
        </div>

        <aside className="settings-rail">
          <section className="settings-panel">
            <span className="eyebrow">PPLNS CONFIGURATION</span>
            <h2>Future block economics</h2>
            <label htmlFor="operator-fee">Operator fee</label>
            <div className="input-affix"><input id="operator-fee" inputMode="decimal" value={feePercent} onChange={(event) => { setFeePercent(event.target.value); setSettingsDirty(true); }} /><span>%</span></div>
            <small>0.00% through 100.00%</small>

            <label htmlFor="pplns-window">PPLNS share window</label>
            <div className="window-input">
              <input id="pplns-window" inputMode="numeric" value={windowShares} onChange={(event) => { setWindowShares(event.target.value); setSettingsDirty(true); }} />
              <span>{parsedWindow === 0 ? "Automatic (one expected block)" : "Exact accepted shares"}</span>
            </div>
            <small>Use 0 for the automatic one-expected-block window, or 1–65,536.</small>
            <p className="settings-note"><FileClock size={16} /> Changes apply after restart and affect future discovered blocks only.</p>
            <button className="secondary-button full" disabled={!settingsDirty || !settingsValid || actionDisabled} onClick={() => void saveSettings(false)}><Save size={16} /> Save settings</button>
            <button className="primary-button full" disabled={!settingsValid || actionDisabled} onClick={() => running ? setConfirmation("save-restart") : void saveSettings(true)}><RotateCcw size={16} /> {running ? "Save & restart" : "Save & start"}</button>

            {confirmation === "save-restart" && (
              <div className="confirmation settings-confirm" role="alert">
                <strong>Save and restart?</strong>
                <p>The pool will stop gracefully, then reopen with these future-block settings.</p>
                <div><button onClick={() => setConfirmation(null)}>Cancel</button><button className="confirm-action" onClick={() => void saveSettings(true)}>Confirm</button></div>
              </div>
            )}
          </section>

          <section className="identity-panel">
            <span className="eyebrow">PUBLIC POOL IDENTITY</span>
            <h3>TLS-pinned endpoint</h3>
            <p>Miners authenticate this exact certificate fingerprint.</p>
            <div className="copy-line"><code>{truncate(snapshot?.certificate_sha256, 18, 14)}</code><button aria-label="Copy certificate fingerprint" disabled={!snapshot?.certificate_sha256} onClick={() => snapshot && void copy(snapshot.certificate_sha256)}><Copy size={15} /></button></div>
            <dl>
              <div><dt>Pool URL</dt><dd>{truncate(snapshot?.public_pool_url, 18, 16)}</dd></div>
              <div><dt>Bind</dt><dd>{status.settings ? `${status.settings.private_bind_address}:${status.settings.pool_port}` : "Unavailable"}</dd></div>
              <div><dt>Share window</dt><dd>{pool?.effective_pplns_window_shares ? `${formatNumber(pool.effective_pplns_window_shares)} shares` : "Automatic"}</dd></div>
            </dl>
          </section>
        </aside>
      </main>

      <footer className="audit-strip">
        <div><FileText /><span><strong>Settings file</strong><code>{status.paths.settings_file}</code></span></div>
        <div><HardDrive /><span><strong>Data directory</strong><code>{status.paths.data_directory}</code></span></div>
        <div><TerminalSquare /><span><strong>Operator console</strong><code>{status.operator_bind}</code></span></div>
        <div><Database /><span><strong>Public dashboard</strong><code>{status.settings?.dashboard_bind || "127.0.0.1:22446"}</code></span></div>
      </footer>
      <div className="machine-boundary"><ShieldCheck size={15} /> Operator access never leaves this machine.</div>
    </div>
  );
}
