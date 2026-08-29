import {
  Activity,
  Blocks,
  Check,
  ChevronDown,
  CircleAlert,
  CircleCheck,
  Copy,
  Cpu,
  ExternalLink,
  Pickaxe,
  RefreshCw,
  ShieldCheck,
  Users,
  WalletCards,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { fetchPoolDashboard } from "./api";
import mark from "./assets/common-foundry-mark.png";
import type { DashboardDocument, PoolWorker } from "./types";

type WorkerSort = "worker" | "accepted_shares" | "rejected_shares" | "pool_blocks";
type Platform = "windows" | "linux";

const REFRESH_FALLBACK_SECONDS = 10;
const ATOMS_PER_CMFD = 100_000_000;

function formatCount(value: number) {
  return new Intl.NumberFormat("en-US").format(value);
}

function formatAtoms(value: number) {
  const amount = value / ATOMS_PER_CMFD;
  return `${new Intl.NumberFormat("en-US", {
    minimumFractionDigits: amount < 1 && value > 0 ? 4 : 2,
    maximumFractionDigits: 8,
  }).format(amount)} CMFD`;
}

function shortHex(value: string, lead = 10, tail = 8) {
  if (value.length <= lead + tail + 1) return value;
  return `${value.slice(0, lead)}…${value.slice(-tail)}`;
}

function humanState(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function useClipboard() {
  const [copied, setCopied] = useState("");

  const copy = useCallback(async (label: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setCopied(label);
    window.setTimeout(() => setCopied(""), 1600);
  }, []);

  return { copied, copy };
}

function CopyButton({
  label,
  value,
  copied,
  onCopy,
}: {
  label: string;
  value: string;
  copied: string;
  onCopy: (label: string, value: string) => Promise<void>;
}) {
  const done = copied === label;
  return (
    <button
      className="icon-button"
      type="button"
      aria-label={`Copy ${label}`}
      title={`Copy ${label}`}
      onClick={() => void onCopy(label, value)}
    >
      {done ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}
    </button>
  );
}

function EmptyTable({ children }: { children: string }) {
  return (
    <div className="empty-table">
      <Activity size={19} aria-hidden="true" />
      <span>{children}</span>
    </div>
  );
}

function AppSkeleton() {
  return (
    <main className="dashboard-main" aria-busy="true" aria-label="Loading pool status">
      <div className="skeleton skeleton-kicker" />
      <div className="skeleton skeleton-title" />
      <div className="skeleton skeleton-subtitle" />
      <div className="skeleton skeleton-stats" />
      <div className="content-grid">
        <div className="skeleton skeleton-table" />
        <div className="skeleton skeleton-panel" />
      </div>
    </main>
  );
}

export function App() {
  const [document, setDocument] = useState<DashboardDocument | null>(null);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [workerSort, setWorkerSort] = useState<WorkerSort>("accepted_shares");
  const [sortAscending, setSortAscending] = useState(false);
  const [platform, setPlatform] = useState<Platform>("windows");
  const [workerName, setWorkerName] = useState("rig-01");
  const [payoutAddress, setPayoutAddress] = useState("");
  const { copied, copy } = useClipboard();

  const load = useCallback(async (signal?: AbortSignal) => {
    setRefreshing(true);
    try {
      const next = await fetchPoolDashboard(signal);
      setDocument(next);
      setError("");
    } catch (loadError) {
      if (loadError instanceof DOMException && loadError.name === "AbortError") return;
      setError(loadError instanceof Error ? loadError.message : "Pool status is unavailable");
    } finally {
      if (!signal?.aborted) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    const seconds = document?.refresh_interval_seconds ?? REFRESH_FALLBACK_SECONDS;
    const timer = window.setInterval(() => void load(controller.signal), seconds * 1000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [document?.refresh_interval_seconds, load]);

  const workers = useMemo(() => {
    if (!document) return [];
    const sorted = [...document.pool.workers];
    sorted.sort((left, right) => {
      let comparison = 0;
      if (workerSort === "worker") comparison = left.worker.localeCompare(right.worker);
      else comparison = left[workerSort] - right[workerSort];
      return sortAscending ? comparison : -comparison;
    });
    return sorted;
  }, [document, sortAscending, workerSort]);

  const selectSort = (key: WorkerSort) => {
    if (workerSort === key) setSortAscending((value) => !value);
    else {
      setWorkerSort(key);
      setSortAscending(key === "worker");
    }
  };

  if (!document && !error) {
    return (
      <div className="app-shell">
        <Header connected={false} refreshing={refreshing} onRefresh={() => void load()} />
        <AppSkeleton />
      </div>
    );
  }

  if (!document) {
    return (
      <div className="app-shell">
        <Header connected={false} refreshing={refreshing} onRefresh={() => void load()} />
        <main className="dashboard-main">
          <section className="load-error" role="alert">
            <CircleAlert size={24} aria-hidden="true" />
            <div>
              <h1>Pool status is temporarily unavailable</h1>
              <p>{error}</p>
            </div>
            <button className="primary-button" type="button" onClick={() => void load()}>
              <RefreshCw size={16} aria-hidden="true" /> Retry
            </button>
          </section>
        </main>
      </div>
    );
  }

  const pool = document.pool;
  const ledger = pool.ledger;
  const confirmedPayouts = ledger.payout_transactions.reduce(
    (sum, payout) => sum + (payout.confirmations > 0 ? payout.amount_atoms : 0),
    0,
  );
  const pin = document.certificate_sha256;
  const connectConfig = [
    `Pool URL: ${document.public_pool_url}`,
    `Certificate pin: ${pin}`,
    `Worker: ${workerName.trim() || "rig-01"}`,
    `Payout address: ${payoutAddress.trim() || "PASTE_YOUR_64_CHARACTER_WALLET_ADDRESS"}`,
  ].join("\n");

  return (
    <div className="app-shell">
      <Header connected refreshing={refreshing} onRefresh={() => void load()} />
      <main className="dashboard-main">
        {error && (
          <div className="stale-banner" role="status">
            <CircleAlert size={16} aria-hidden="true" /> Live refresh failed. Showing the most recent
            pool snapshot.
          </div>
        )}

        <section className="hero" aria-labelledby="pool-title">
          <div>
            <p className="eyebrow">Common Foundry · {pool.network_short_name}</p>
            <h1 id="pool-title">ForgeMatrix Pool</h1>
            <p className="hero-copy">
              ProductionV4 mining with authenticated shares and automatic Devnet payouts.
            </p>
          </div>
          <div className="hero-status">
            <span className="live-badge">
              <span className="live-dot" /> Live
            </span>
            <span>Height {formatCount(pool.accepted_height)}</span>
            <span title={pool.current_job_id}>Job {shortHex(pool.current_job_id, 8, 6)}</span>
          </div>
        </section>

        <section className="endpoint-strip" aria-label="Pool connection endpoint">
          <div className="endpoint-label">
            <ShieldCheck size={18} aria-hidden="true" /> TLS-pinned pool endpoint
          </div>
          <code>{document.public_pool_url}</code>
          <CopyButton
            label="pool URL"
            value={document.public_pool_url}
            copied={copied}
            onCopy={copy}
          />
        </section>

        <section className="stat-rail" aria-label="Pool totals">
          <Stat icon={<Users />} label="Active workers" value={formatCount(pool.active_connections)} detail={`of ${formatCount(pool.connection_capacity)} connections`} />
          <Stat icon={<CircleCheck />} label="Accepted shares" value={formatCount(ledger.accepted_shares)} detail="durably accounted" />
          <Stat icon={<CircleAlert />} label="Rejected shares" value={formatCount(ledger.rejected_shares)} detail="visible to operators" tone={ledger.rejected_shares > 0 ? "warn" : undefined} />
          <Stat icon={<Blocks />} label="Pool blocks" value={formatCount(ledger.canonical_pool_blocks)} detail={`${formatCount(ledger.orphaned_pool_blocks)} orphaned`} />
          <Stat icon={<WalletCards />} label="Confirmed payouts" value={formatAtoms(confirmedPayouts)} detail={pool.automatic_testnet_payouts ? "automatic settlement on" : "settlement paused"} />
        </section>

        <div className="content-grid">
          <section className="data-section" id="workers" aria-labelledby="workers-title">
            <SectionHeading
              eyebrow="Live participation"
              title="Workers"
              detail={`${formatCount(pool.active_share_verifications)} verifying · ${formatCount(pool.queued_share_verifications)} queued`}
            />
            {workers.length === 0 ? (
              <EmptyTable>No workers have connected yet. Use the connection panel to start one.</EmptyTable>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <SortableHead label="Worker" sortKey="worker" active={workerSort} ascending={sortAscending} onSort={selectSort} />
                      <th>Status</th>
                      <SortableHead label="Accepted" sortKey="accepted_shares" active={workerSort} ascending={sortAscending} onSort={selectSort} numeric />
                      <SortableHead label="Rejected" sortKey="rejected_shares" active={workerSort} ascending={sortAscending} onSort={selectSort} numeric />
                      <SortableHead label="Blocks" sortKey="pool_blocks" active={workerSort} ascending={sortAscending} onSort={selectSort} numeric />
                      <th className="numeric">Credit</th>
                    </tr>
                  </thead>
                  <tbody>
                    {workers.map((worker) => (
                      <WorkerRow key={`${worker.payout}:${worker.worker}`} worker={worker} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <aside className="connect-panel" id="connect" aria-labelledby="connect-title">
            <p className="eyebrow">Start mining</p>
            <h2 id="connect-title">Connect a worker</h2>
            <div className="platform-tabs" role="tablist" aria-label="Miner platform">
              {(["windows", "linux"] as Platform[]).map((value) => (
                <button
                  key={value}
                  type="button"
                  role="tab"
                  aria-selected={platform === value}
                  className={platform === value ? "is-active" : ""}
                  onClick={() => setPlatform(value)}
                >
                  {value === "windows" ? "Windows" : "Linux"}
                </button>
              ))}
            </div>
            <ol className="connect-steps">
              <li>Open {platform === "windows" ? "START-MINER.bat" : "START-MINER.sh"} from the Devnet-16 miner package.</li>
              <li>Choose pool mode and paste the pool URL below.</li>
              <li>Enter your wallet receive address and a unique worker name.</li>
            </ol>
            <label>
              Pool endpoint
              <span className="copy-field">
                <code>{shortHex(document.public_pool_url, 28, 12)}</code>
                <CopyButton label="pool URL" value={document.public_pool_url} copied={copied} onCopy={copy} />
              </span>
            </label>
            <label>
              Certificate pin
              <span className="copy-field">
                <code>{shortHex(pin, 16, 12)}</code>
                <CopyButton label="certificate pin" value={pin} copied={copied} onCopy={copy} />
              </span>
            </label>
            <label>
              Worker name
              <input value={workerName} maxLength={64} onChange={(event) => setWorkerName(event.target.value)} />
            </label>
            <label>
              Payout address
              <input
                value={payoutAddress}
                maxLength={64}
                spellCheck={false}
                placeholder="64-character wallet receive address"
                onChange={(event) => setPayoutAddress(event.target.value.trim())}
              />
            </label>
            <button className="primary-button full-width" type="button" onClick={() => void copy("connection config", connectConfig)}>
              {copied === "connection config" ? <Check size={17} aria-hidden="true" /> : <Copy size={17} aria-hidden="true" />}
              {copied === "connection config" ? "Configuration copied" : "Copy connection details"}
            </button>
            <p className="connect-note">
              The miner verifies this exact TLS certificate pin before sending authenticated shares.
            </p>
          </aside>
        </div>

        <section className="data-section lower-section" id="blocks" aria-labelledby="blocks-title">
          <SectionHeading eyebrow="Canonical chain" title="Pool blocks" detail={`Tip ${shortHex(pool.tip)}`} />
          {ledger.blocks.length === 0 ? (
            <EmptyTable>The pool has not found a block yet.</EmptyTable>
          ) : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Height</th><th>Block</th><th>State</th><th className="numeric">Confirmations</th></tr></thead>
                <tbody>
                  {ledger.blocks.map((block) => (
                    <tr key={block.block_id}>
                      <td className="strong-cell">{formatCount(block.height)}</td>
                      <td><code title={block.block_id}>{shortHex(block.block_id)}</code></td>
                      <td><span className={`state-badge state-${block.state}`}>{humanState(block.state)}</span></td>
                      <td className="numeric">{formatCount(block.confirmations)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="data-section lower-section" id="payouts" aria-labelledby="payouts-title">
          <SectionHeading
            eyebrow="On-chain settlement"
            title="Payouts"
            detail={pool.automatic_testnet_payouts ? `Minimum ${formatAtoms(pool.minimum_payout_atoms ?? 0)}` : "Currently paused"}
          />
          {ledger.payout_transactions.length === 0 ? (
            <EmptyTable>No payout transactions have been broadcast yet.</EmptyTable>
          ) : (
            <div className="table-scroll">
              <table>
                <thead><tr><th>Transaction</th><th>Recipient</th><th className="numeric">Amount</th><th>State</th><th className="numeric">Confirmations</th></tr></thead>
                <tbody>
                  {ledger.payout_transactions.map((payout) => (
                    <tr key={payout.txid}>
                      <td><code title={payout.txid}>{shortHex(payout.txid)}</code></td>
                      <td><code title={payout.payout}>{shortHex(payout.payout)}</code></td>
                      <td className="numeric strong-cell">{formatAtoms(payout.amount_atoms)}</td>
                      <td><span className={`state-badge state-${payout.state}`}>{humanState(payout.state)}</span></td>
                      <td className="numeric">{formatCount(payout.confirmations)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <footer>
          <span>{pool.network_name}</span>
          <span>Proof profile {pool.proof_profile}</span>
          <span>Updated {new Date(pool.generated_at_unix_seconds * 1000).toLocaleTimeString()}</span>
          <a href="https://commonfoundry.org" target="_blank" rel="noreferrer">
            commonfoundry.org <ExternalLink size={13} aria-hidden="true" />
          </a>
        </footer>
      </main>
    </div>
  );
}

function Header({ connected, refreshing, onRefresh }: { connected: boolean; refreshing: boolean; onRefresh: () => void }) {
  return (
    <header className="topbar">
      <a className="brand" href="#pool-title" aria-label="Common Foundry pool overview">
        <img src={mark} alt="" />
        <span><strong>Common Foundry</strong><small>Pool</small></span>
      </a>
      <nav aria-label="Pool navigation">
        <a href="#pool-title">Overview</a>
        <a href="#workers">Workers</a>
        <a href="#blocks">Blocks</a>
        <a href="#payouts">Payouts</a>
        <a href="#connect">Connect</a>
      </nav>
      <div className="topbar-actions">
        <span className={`connection-pill ${connected ? "connected" : ""}`}>
          <span /> {connected ? "Pool online" : "Connecting"}
        </span>
        <button className="refresh-button" type="button" aria-label="Refresh pool status" onClick={onRefresh} disabled={refreshing}>
          <RefreshCw size={16} className={refreshing ? "is-spinning" : ""} aria-hidden="true" />
          <span>Refresh</span>
        </button>
      </div>
    </header>
  );
}

function Stat({ icon, label, value, detail, tone }: { icon: React.ReactElement; label: string; value: string; detail: string; tone?: "warn" }) {
  return (
    <div className={`stat${tone ? ` stat-${tone}` : ""}`}>
      <div className="stat-icon">{icon}</div>
      <div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
    </div>
  );
}

function SectionHeading({ eyebrow, title, detail }: { eyebrow: string; title: string; detail: string }) {
  return (
    <div className="section-heading">
      <div><p className="eyebrow">{eyebrow}</p><h2>{title}</h2></div>
      <span>{detail}</span>
    </div>
  );
}

function SortableHead({ label, sortKey, active, ascending, onSort, numeric = false }: { label: string; sortKey: WorkerSort; active: WorkerSort; ascending: boolean; onSort: (key: WorkerSort) => void; numeric?: boolean }) {
  const selected = active === sortKey;
  return (
    <th className={numeric ? "numeric" : undefined} aria-sort={selected ? (ascending ? "ascending" : "descending") : "none"}>
      <button type="button" onClick={() => onSort(sortKey)}>
        {label}<ChevronDown size={13} className={selected && ascending ? "sort-up" : ""} aria-hidden="true" />
      </button>
    </th>
  );
}

function WorkerRow({ worker }: { worker: PoolWorker }) {
  return (
    <tr>
      <td><span className="worker-name"><Cpu size={15} aria-hidden="true" />{worker.worker}</span><code title={worker.payout}>{shortHex(worker.payout, 8, 6)}</code></td>
      <td><span className={`worker-status ${worker.connected ? "online" : ""}`}><span />{worker.connected ? "Online" : "Offline"}</span></td>
      <td className="numeric strong-cell">{formatCount(worker.accepted_shares)}</td>
      <td className="numeric">{formatCount(worker.rejected_shares)}</td>
      <td className="numeric">{formatCount(worker.pool_blocks)}</td>
      <td className="numeric strong-cell">{formatAtoms(worker.credited_devnet_atoms)}</td>
    </tr>
  );
}
