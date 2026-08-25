import {
  AlertTriangle,
  Blocks,
  Cpu,
  Gauge,
  Pickaxe,
  RefreshCw,
  ShieldAlert,
  Square,
  WalletCards,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useMiningData } from "../hooks/useMiningData";
import { shortenHash } from "../lib/amount";
import type { MiningLifecycle, MiningMode } from "../mining/types";
import {
  poolUrlError,
  POOL_URL_REQUIREMENT,
  workerNameError,
  WORKER_NAME_REQUIREMENT,
} from "../mining/validation";
import type { NodeStatus, WalletSnapshot } from "../types";

interface MiningViewProps {
  wallet: WalletSnapshot | null;
  nodeStatus: NodeStatus | null;
}

const integerFormatter = new Intl.NumberFormat(undefined, {
  maximumFractionDigits: 0,
});

const rateFormatter = new Intl.NumberFormat(undefined, {
  minimumFractionDigits: 0,
  maximumFractionDigits: 2,
});

const lifecycleCopy: Record<MiningLifecycle, string> = {
  stopped: "Ready",
  starting: "Starting reference miner",
  running: "Mining solo",
  stopping: "Stopping miner",
  error: "Miner needs attention",
};

function formatAtomCount(value: string | undefined): string {
  if (!value || !/^\d+$/.test(value)) return "—";
  try {
    return BigInt(value).toLocaleString();
  } catch {
    return "—";
  }
}

export function MiningView({ wallet, nodeStatus }: MiningViewProps) {
  const mining = useMiningData();
  const [mode, setMode] = useState<MiningMode>("solo");
  const [sessionMode, setSessionMode] = useState<MiningMode | null>(null);
  const [poolUrl, setPoolUrl] = useState("");
  const [workerName, setWorkerName] = useState("");

  const lifecycle = mining.status?.lifecycle ?? "stopped";
  const isActive = lifecycle === "starting" || lifecycle === "running";
  const isBusy = mining.action !== null || lifecycle === "stopping";
  const configLocked = isActive || isBusy;
  const metricsStatus = (mining.status?.mode ?? sessionMode) === mode
    ? mining.status
    : null;
  const currentHeight = metricsStatus?.current_height ?? nodeStatus?.accepted_height ?? null;
  const poolSelected = mode === "pool";
  const cudaActive = metricsStatus?.engine === "cuda";
  const poolUrlIssue = poolUrlError(poolUrl);
  const workerNameIssue = workerNameError(workerName);
  const referenceMiningAvailable = nodeStatus?.bounded_reference_mining ?? false;
  const networkName = nodeStatus?.network_short_name ?? "Network";
  const proofProfile = nodeStatus?.proof_profile ?? "Unknown proof profile";
  const canStartBase = !mining.loading
    && mining.status !== null
    && wallet !== null
    && nodeStatus !== null
    && referenceMiningAvailable
    && !isActive
    && !isBusy;
  const canStartSolo = mode === "solo" && canStartBase;
  const canStartPool = mode === "pool"
    && canStartBase
    && poolUrlIssue === null
    && workerNameIssue === null;

  useEffect(() => {
    const status = mining.status;
    if (!status?.mode) return;

    setSessionMode(status.mode);
    setMode(status.mode);
    if (status.mode === "pool") {
      if (status.pool_url) setPoolUrl(status.pool_url);
      if (status.worker_name) setWorkerName(status.worker_name);
    }
  }, [mining.status]);

  const displayedLifecycle: MiningLifecycle = mining.action === "starting"
    ? "starting"
    : mining.action === "stopping"
      ? "stopping"
      : lifecycle;
  const lifecycleLabel = displayedLifecycle === "running" && mining.status?.mode === "pool"
    ? "Mining with pool"
    : lifecycleCopy[displayedLifecycle];

  const handlePrimaryAction = async () => {
    if (isActive) {
      await mining.stop();
      return;
    }
    if ((!canStartSolo && !canStartPool) || !wallet) return;

    if (mode === "pool") {
      await mining.start({
        mode: "pool",
        payout: wallet.destination,
        pool_url: poolUrl,
        worker_name: workerName,
      });
      return;
    }

    await mining.start({
      mode: "solo",
      payout: wallet.destination,
    });
  };

  const buttonText = mining.action === "starting"
    ? "Starting reference miner…"
    : mining.action === "stopping" || lifecycle === "stopping"
      ? "Stopping miner…"
      : isActive
        ? "Stop Mining"
        : poolSelected
          ? "Start Pool Mining"
          : "Start Solo Mining";

  const primaryDisabled = isBusy || (!isActive && !canStartSolo && !canStartPool);
  const statusClass = displayedLifecycle === "running"
    ? " is-running"
    : displayedLifecycle === "error"
      ? " is-error"
      : "";

  return (
    <div className="mining-layout">
      <div className="mining-main-column">
        <section className="mining-status-card" aria-live="polite">
          <div className="section-heading mining-heading">
            <div>
              <span>{cudaActive ? "CUDA engine" : "Reference engine"}</span>
              <h2>ForgeMatrix mining</h2>
            </div>
            <span className={`mining-state${statusClass}`}>
              <i />
              {mining.loading ? "Reading miner status" : lifecycleLabel}
            </span>
          </div>

          <div className="mining-rate">
            <span>Current work rate</span>
            <div>
              <strong>{rateFormatter.format(metricsStatus?.matrix_attempts_per_second ?? 0)}</strong>
              <em>matrix attempts/s</em>
            </div>
          </div>

          {poolSelected ? (
            <dl className="mining-metrics">
              <div>
                <dt>Accepted shares</dt>
                <dd>{integerFormatter.format(metricsStatus?.shares_accepted ?? 0)}</dd>
              </div>
              <div>
                <dt>Rejected shares</dt>
                <dd>{integerFormatter.format(metricsStatus?.shares_rejected ?? 0)}</dd>
              </div>
              <div>
                <dt>Pool blocks</dt>
                <dd>{integerFormatter.format(metricsStatus?.blocks_found ?? 0)}</dd>
              </div>
              <div>
                <dt>Credited {networkName} atoms</dt>
                <dd>{formatAtomCount(metricsStatus?.credited_atoms)}</dd>
              </div>
            </dl>
          ) : (
            <dl className="mining-metrics">
              <div>
                <dt>Session attempts</dt>
                <dd>{integerFormatter.format(metricsStatus?.session_attempts ?? 0)}</dd>
              </div>
              <div>
                <dt>Blocks found</dt>
                <dd>{integerFormatter.format(metricsStatus?.blocks_found ?? 0)}</dd>
              </div>
              <div>
                <dt>Current height</dt>
                <dd>{currentHeight === null ? "—" : integerFormatter.format(currentHeight)}</dd>
              </div>
              <div>
                <dt>Mining route</dt>
                <dd>{mining.status?.mode === "solo" ? "Solo" : "Not mining"}</dd>
              </div>
            </dl>
          )}

          {poolSelected ? (
            <>
              <div className="mining-last-block pool-connection-row">
                <span className="mining-detail-icon"><Gauge aria-hidden="true" size={18} /></span>
                <div>
                  <span>Pool connection</span>
                  <strong className={metricsStatus?.pool_connected ? "is-connected" : ""}>
                    {metricsStatus?.pool_connected ? "Connected" : "Not connected"}
                  </strong>
                </div>
                <dl className="pool-context-metrics">
                  <div>
                    <dt>Session attempts</dt>
                    <dd>{integerFormatter.format(metricsStatus?.session_attempts ?? 0)}</dd>
                  </div>
                  <div>
                    <dt>Pool height</dt>
                    <dd>{currentHeight === null ? "—" : integerFormatter.format(currentHeight)}</dd>
                  </div>
                </dl>
              </div>
              <div className="warning-inline pool-credit-note" role="note">
                <ShieldAlert aria-hidden="true" size={17} />
                <span>Pool credits are session statistics for testing; payouts are not enabled yet.</span>
              </div>
            </>
          ) : (
            <div className="mining-last-block">
              <span className="mining-detail-icon"><Blocks aria-hidden="true" size={18} /></span>
              <div>
                <span>Last block found</span>
                <strong>{metricsStatus?.last_block
                  ? `Height ${metricsStatus.last_block.height} · ${shortenHash(metricsStatus.last_block.block_id, 9, 9)}`
                  : "No blocks found this session"}</strong>
              </div>
            </div>
          )}
        </section>

        <section className="mining-disclosure-card">
          <div className="section-heading">
            <div>
              <span>{proofProfile} engine</span>
              <h2>What this miner does</h2>
            </div>
          </div>
          <div className="mining-disclosure-grid">
            <div>
              <span className="mining-detail-icon"><Cpu aria-hidden="true" size={18} /></span>
              <div>
                <strong>{cudaActive ? "CUDA INT8 matrix engine" : "CPU reference engine"}</strong>
                <p>{referenceMiningAvailable
                  ? (cudaActive
                    ? `Runs the ${nodeStatus?.proof_of_work ?? proofProfile} matrix stage on ${metricsStatus?.device ?? "the selected NVIDIA GPU"}; Rust recomputes every candidate before submission.`
                    : `Runs the ${nodeStatus?.proof_of_work ?? proofProfile} profile for ${networkName} testing.`)
                  : "ProductionV3 is selected. This wallet will not substitute the bounded DevnetV2 reference miner."}</p>
              </div>
            </div>
            <div>
              <span className="mining-detail-icon"><WalletCards aria-hidden="true" size={18} /></span>
              <div>
                <strong>100-block maturity</strong>
                <p>Solo rewards remain immature until they receive 100 confirmations.</p>
              </div>
            </div>
            <div>
              <span className="mining-detail-icon"><ShieldAlert aria-hidden="true" size={18} /></span>
              <div>
                <strong>Transaction fees are burned</strong>
                <p>Included fees do not increase the miner reward.</p>
              </div>
            </div>
          </div>
          <div className="warning-inline mining-proof-warning">
            <AlertTriangle aria-hidden="true" size={17} />
            <span>{cudaActive
              ? "This wallet is using CUDA locally, but consensus validates only the committed result; it cannot prove physical GPU or VRAM residency."
              : "This reference engine makes no GPU-use or VRAM-residency claim. Those physical properties are not proven by consensus."}</span>
          </div>
        </section>
      </div>

      <aside className="mining-control-card">
        <span className="forge-icon"><Pickaxe aria-hidden="true" size={23} /></span>
        <span className="card-eyebrow">Mining control</span>
        <h2>{poolSelected ? "Pool mining" : "Solo mining"}</h2>
        <p>{poolSelected
          ? `Submit ForgeMatrix shares to a pinned CMFD pool endpoint for ${networkName} session accounting.`
          : "Mine directly against the embedded node and send accepted block rewards to this wallet."}</p>

        {!referenceMiningAvailable ? (
          <div className="warning-inline" role="status">
            <ShieldAlert aria-hidden="true" size={17} />
            <span>{proofProfile} is selected. Wallet mining remains disabled until its production work protocol is available.</span>
          </div>
        ) : null}

        <div className="mining-mode-switch" role="group" aria-label="Mining mode">
          <button
            className={!poolSelected ? "is-active" : ""}
            type="button"
            aria-pressed={!poolSelected}
            disabled={configLocked}
            onClick={() => setMode("solo")}
          >
            Solo
          </button>
          <button
            className={poolSelected ? "is-active" : ""}
            type="button"
            aria-pressed={poolSelected}
            disabled={configLocked}
            onClick={() => setMode("pool")}
          >
            Pool
          </button>
        </div>

        {poolSelected ? (
          <div className="pool-configuration">
            <div className="pool-protocol" role="note">
              <ShieldAlert aria-hidden="true" size={17} />
              <div>
                <strong>Pinned private endpoint</strong>
                <span>A CMFD-specific TLS job/share protocol is required. Stratum endpoints are not compatible.</span>
              </div>
            </div>
            <label htmlFor="pool-url">
              Pool URL
              <input
                id="pool-url"
                type="text"
                value={poolUrl}
                required
                disabled={configLocked}
                aria-invalid={poolUrl.length > 0 && poolUrlIssue !== null}
                aria-describedby="pool-url-help"
                autoComplete="off"
                spellCheck={false}
                placeholder="cmfd+tls://192.168.1.20:443?pin=64_HEX"
                onChange={(event) => setPoolUrl(event.target.value)}
              />
              <span
                id="pool-url-help"
                className={poolUrl.length > 0 && poolUrlIssue ? "pool-field-error" : "pool-field-help"}
              >
                {poolUrl.length > 0 && poolUrlIssue ? poolUrlIssue : POOL_URL_REQUIREMENT}
              </span>
            </label>
            <label htmlFor="pool-worker-name">
              Worker name
              <input
                id="pool-worker-name"
                type="text"
                value={workerName}
                required
                maxLength={32}
                disabled={configLocked}
                aria-invalid={workerName.length > 0 && workerNameIssue !== null}
                aria-describedby="pool-worker-help"
                autoComplete="off"
                spellCheck={false}
                placeholder="foundry-worker"
                onChange={(event) => setWorkerName(event.target.value)}
              />
              <span
                id="pool-worker-help"
                className={workerName.length > 0 && workerNameIssue ? "pool-field-error" : "pool-field-help"}
              >
                {workerName.length > 0 && workerNameIssue ? workerNameIssue : WORKER_NAME_REQUIREMENT}
              </span>
            </label>
            <div className="miner-destination pool-credit-destination">
              <span>Demo credit destination</span>
              <code title={wallet?.destination}>{wallet
                ? shortenHash(wallet.destination, 10, 10)
                : "Waiting for wallet"}</code>
            </div>
          </div>
        ) : (
          <>
            <div className="miner-destination">
              <span>Reward destination</span>
              <code title={wallet?.destination}>{wallet
                ? shortenHash(wallet.destination, 10, 10)
                : "Waiting for wallet"}</code>
            </div>
            <div className="reference-engine-row">
              <span className="mining-detail-icon"><Gauge aria-hidden="true" size={17} /></span>
              <div>
                <span>Engine</span>
                <strong>{cudaActive
                  ? metricsStatus?.device ?? "CUDA accelerator"
                  : "CPU reference evaluator"}</strong>
              </div>
            </div>
          </>
        )}

        {mining.error ? (
          <div className="form-error mining-error" role="alert">
            <span>{mining.error}</span>
            <button type="button" onClick={() => void mining.refresh()} aria-label="Retry miner status">
              <RefreshCw aria-hidden="true" size={14} />
            </button>
          </div>
        ) : null}
        {mining.status?.last_error && mining.status.last_error !== mining.error ? (
          <p className="form-error" role="alert">{mining.status.last_error}</p>
        ) : null}

        <button
          className={`button-primary wide mining-primary${isActive ? " is-stop" : ""}`}
          type="button"
          disabled={primaryDisabled}
          onClick={() => void handlePrimaryAction()}
        >
          {isActive ? <Square aria-hidden="true" size={16} /> : <Pickaxe aria-hidden="true" size={18} />}
          {buttonText}
        </button>
        <small>{poolSelected
          ? `${networkName} · pool session statistics · ${cudaActive ? "CUDA matrix stage" : "CPU reference"}`
          : `${networkName} · solo mining · ${cudaActive ? "CUDA matrix stage" : "CPU reference"}`}</small>
      </aside>
    </div>
  );
}
