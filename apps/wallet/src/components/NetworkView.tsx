import { ArrowDownToLine, ArrowUpFromLine, Blocks, Check, Clipboard, Hammer, Plus, RefreshCw, RotateCcw, ServerCog, ShieldAlert, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { getPeerSettings, mineDevnetBlock, updatePeerSettings, usesEmbeddedNode } from "../api/nodeClient";
import { formatBytes, shortenHash } from "../lib/amount";
import type { MempoolSnapshot, NodeStatus, PeerSettings, WalletSnapshot } from "../types";

interface NetworkViewProps {
  status: NodeStatus | null;
  wallet: WalletSnapshot | null;
  mempool: MempoolSnapshot | null;
  refreshing: boolean;
  onRefresh: () => Promise<void> | void;
  onNotice: (message: string) => void;
}

export function NetworkView({ status, wallet, mempool, refreshing, onRefresh, onNotice }: NetworkViewProps) {
  const [mining, setMining] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [peerSettings, setPeerSettings] = useState<PeerSettings | null>(null);
  const [peerInput, setPeerInput] = useState("");
  const [peerSaving, setPeerSaving] = useState(false);
  const [peerError, setPeerError] = useState<string | null>(null);
  const peers = status?.peers ?? [];

  useEffect(() => {
    if (!usesEmbeddedNode) return;
    let active = true;
    void getPeerSettings().then(
      (settings) => {
        if (active) setPeerSettings(settings);
      },
      (cause) => {
        if (active) setPeerError(cause instanceof Error ? cause.message : "Peer settings could not be loaded");
      },
    );
    return () => {
      active = false;
    };
  }, []);

  const savePeers = async (nextPeers: string[], notice: string) => {
    setPeerSaving(true);
    setPeerError(null);
    try {
      const saved = await updatePeerSettings(nextPeers);
      setPeerSettings(saved);
      onNotice(notice);
      try {
        await onRefresh();
      } catch {
        // Peer settings remain applied even if the best-effort status refresh fails.
      }
      return true;
    } catch (cause) {
      setPeerError(cause instanceof Error ? cause.message : "Peer settings could not be saved");
      return false;
    } finally {
      setPeerSaving(false);
    }
  };

  const addPeer = async () => {
    if (!peerSettings || !peerInput.trim()) return;
    const entered = peerInput.trim();
    if (await savePeers([...peerSettings.peers, entered], `Peer ${entered} added. Connection attempts begin automatically.`)) {
      setPeerInput("");
    }
  };

  const copyDiagnostics = async () => {
    if (!status) return;
    await navigator.clipboard.writeText(JSON.stringify(status, null, 2));
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1_600);
  };

  const mine = async () => {
    if (!wallet) return;
    setMining(true);
    setError(null);
    try {
      const result = await mineDevnetBlock(wallet.destination);
      onNotice(`Block ${result.height} forged and accepted.`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Mining attempt failed");
      setMining(false);
      return;
    }
    try {
      await onRefresh();
    } catch {
      // The accepted block remains successful even if the best-effort refresh fails.
    } finally {
      setMining(false);
    }
  };

  return (
    <div className="network-layout">
      <section className="node-details-card">
        <div className="section-heading">
          <div>
            <span>Local service</span>
            <h2>Node diagnostics</h2>
          </div>
          <div className="heading-actions">
            <button className="button-quiet" type="button" onClick={copyDiagnostics} disabled={!status}>
              {copied ? <Check aria-hidden="true" size={16} /> : <Clipboard aria-hidden="true" size={16} />}
              {copied ? "Copied" : "Copy diagnostics"}
            </button>
            <button className="icon-button bordered" type="button" onClick={() => void onRefresh()} aria-label="Refresh diagnostics">
              <RefreshCw aria-hidden="true" size={16} className={refreshing ? "spin" : ""} />
            </button>
          </div>
        </div>

        <div className="service-banner">
          <span className="service-icon"><ServerCog aria-hidden="true" size={21} /></span>
          <div>
            <strong>{status ? "Node connected" : "Node unavailable"}</strong>
            <span>{status
              ? (usesEmbeddedNode ? "Embedded Rust node is responding" : "Loopback RPC is responding")
              : (usesEmbeddedNode ? "Embedded node failed to start; retry or reopen the wallet" : "Start the local network node, then refresh")}</span>
          </div>
          <span className={`service-state${status ? " is-online" : ""}`}>{status ? "Online" : "Offline"}</span>
        </div>

        {status?.public_peer_mode ? (
          <div className="info-inline" role="status">
            <ShieldAlert aria-hidden="true" size={17} />
            <span>Public {status.network_short_name} P2P is enabled. Node RPC remains local to this computer.</span>
          </div>
        ) : null}

        <dl className="diagnostics-grid">
          <Diagnostic label="Network" value={status?.network ?? "—"} />
          <Diagnostic label="Proof profile" value={status?.proof_profile ?? "—"} />
          <Diagnostic label="Proof of work" value={status?.proof_of_work ?? "—"} />
          <Diagnostic label="Service ports" value={status ? `${status.rpc_port} RPC · ${status.p2p_port} P2P · ${status.pool_port} pool` : "—"} />
          <Diagnostic label="Block height" value={status?.accepted_height.toLocaleString() ?? "—"} />
          <Diagnostic label="Next height" value={status?.next_height.toLocaleString() ?? "—"} />
          <Diagnostic label="Chain tip" value={status ? shortenHash(status.tip, 10, 10) : "—"} mono title={status?.tip} />
          <Diagnostic label="Cumulative work" value={status ? shortenHash(status.cumulative_work, 10, 10) : "—"} mono title={status?.cumulative_work} />
          <Diagnostic label="Expected target" value={status ? shortenHash(status.expected_target, 10, 10) : "—"} mono title={status?.expected_target} />
          <Diagnostic label="UTXO count" value={status?.utxo_count.toLocaleString() ?? "—"} />
          <Diagnostic label="Mempool" value={mempool ? `${mempool.transactions} tx · ${formatBytes(mempool.bytes)}` : "—"} />
          <Diagnostic label="Storage" value={status ? (status.storage_healthy ? "Healthy" : "Faulted") : "—"} good={status?.storage_healthy} />
          <Diagnostic label="Network ID" value={status ? shortenHash(status.network_id, 10, 10) : "—"} mono title={status?.network_id} />
          <Diagnostic label="Consensus fingerprint" value={status ? shortenHash(status.consensus_fingerprint, 10, 10) : "—"} mono title={status?.consensus_fingerprint} />
        </dl>

        <section className="peer-panel" aria-labelledby="recent-peers-heading">
          {usesEmbeddedNode ? (
            <div className="peer-settings" aria-labelledby="configured-peers-heading">
              <div className="peer-panel-heading">
                <div>
                  <span>Connection settings</span>
                  <h3 id="configured-peers-heading">Configured peers</h3>
                </div>
                <button
                  className="button-quiet"
                  type="button"
                  disabled={!peerSettings || peerSaving || peerSettings.peers.length === 1 && peerSettings.peers[0] === peerSettings.bootstrap_peer}
                  onClick={() => peerSettings && void savePeers([peerSettings.bootstrap_peer], "Community bootstrap peer restored.")}
                >
                  <RotateCcw aria-hidden="true" size={14} />
                  Reset
                </button>
              </div>
              <p className="peer-panel-help">
                Add a numeric IP address. Port {peerSettings?.default_peer_port ?? "—"} is used automatically when no port is entered.
              </p>
              <form className="peer-add-form" onSubmit={(event) => { event.preventDefault(); void addPeer(); }}>
                <label className="sr-only" htmlFor="peer-address">Peer IP address</label>
                <input
                  id="peer-address"
                  className="form-input form-input-mono"
                  value={peerInput}
                  onChange={(event) => setPeerInput(event.target.value)}
                  placeholder={`203.0.113.20 or 203.0.113.20:${peerSettings?.default_peer_port ?? "port"}`}
                  autoComplete="off"
                  spellCheck={false}
                  disabled={!peerSettings || peerSaving}
                />
                <button className="button-secondary compact" type="submit" disabled={!peerSettings || !peerInput.trim() || peerSaving || peerSettings.peers.length >= peerSettings.max_peers}>
                  {peerSaving ? <RefreshCw className="spin" aria-hidden="true" size={15} /> : <Plus aria-hidden="true" size={15} />}
                  Add peer
                </button>
              </form>
              {peerError ? <p className="form-error" role="alert">{peerError}</p> : null}
              {peerSettings ? (
                <ul className="configured-peer-list">
                  {peerSettings.peers.map((peer) => (
                    <li key={peer}>
                      <code>{peer}</code>
                      {peer === peerSettings.bootstrap_peer ? <span>Community bootstrap</span> : <span>Manual peer</span>}
                      <button
                        className="icon-button bordered"
                        type="button"
                        aria-label={`Remove peer ${peer}`}
                        title={peerSettings.peers.length === 1 ? "Keep at least one peer configured" : "Remove peer"}
                        disabled={peerSaving || peerSettings.peers.length === 1}
                        onClick={() => void savePeers(peerSettings.peers.filter((candidate) => candidate !== peer), `Peer ${peer} removed.`)}
                      >
                        <Trash2 aria-hidden="true" size={14} />
                      </button>
                    </li>
                  ))}
                </ul>
              ) : peerError ? null : <p className="peer-settings-loading">Loading peer settings…</p>}
            </div>
          ) : null}

          <div className="peer-panel-heading">
            <div>
              <span>Peer activity</span>
              <h3 id="recent-peers-heading">Recent peers</h3>
            </div>
            <span className="peer-count">{peers.length}</span>
          </div>
          <p className="peer-panel-help">
            Short P2P sessions are retained here and update with node diagnostics.
          </p>
          {peers.length === 0 ? (
            <div className="peer-empty">
              <ServerCog aria-hidden="true" size={20} />
              <div>
                <strong>No peer sessions observed yet</strong>
                <span>Configured and inbound peers appear after their first connection attempt.</span>
              </div>
            </div>
          ) : (
            <ul className="peer-list">
              {peers.map((peer) => (
                <li className="peer-row" key={`${peer.direction}:${peer.address}`}>
                  <span className={`peer-direction peer-direction-${peer.direction}`} aria-hidden="true">
                    {peer.direction === "inbound" ? <ArrowDownToLine size={16} /> : <ArrowUpFromLine size={16} />}
                  </span>
                  <div className="peer-identity">
                    <code>{peer.address}</code>
                    <span>{capitalize(peer.direction)} · first seen {formatPeerAge(peer.first_seen)}</span>
                  </div>
                  <div className="peer-chain">
                    <strong>{peer.remote_height === null ? "Height unknown" : `Height ${peer.remote_height.toLocaleString()}`}</strong>
                    <span title={peer.remote_tip ?? undefined}>{peer.remote_tip ? shortenHash(peer.remote_tip, 7, 7) : "No compatible handshake yet"}</span>
                  </div>
                  <div className="peer-sessions">
                    <strong>{peer.successful_sessions.toLocaleString()} successful</strong>
                    <span>{peer.failed_sessions.toLocaleString()} failed</span>
                  </div>
                  <div className="peer-status-cell">
                    <span className={`peer-state peer-state-${peer.state}`}>{peerStateLabel(peer.state)}</span>
                    <small>{peer.active_connections > 0 ? `${peer.active_connections} active` : formatPeerAge(peer.last_seen)}</small>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      </section>

      <aside className="forge-card">
        <span className="forge-icon"><Hammer aria-hidden="true" size={23} /></span>
        {status?.bounded_reference_mining ? (
          <>
            <span className="card-eyebrow">{status.proof_profile} mining</span>
            <h2>Forge a {status.network_short_name} block</h2>
            <p>Run one bounded mining attempt with the {status.proof_of_work} profile.</p>
            <div className="miner-destination">
              <span>Reward destination</span>
              <code title={wallet?.destination}>{wallet ? shortenHash(wallet.destination, 9, 9) : "Waiting for wallet"}</code>
            </div>
            {error ? <p className="form-error" role="alert">{error}</p> : null}
            <button className="button-primary wide" type="button" disabled={!wallet || mining} onClick={() => void mine()}>
              {mining ? <RefreshCw className="spin" aria-hidden="true" size={18} /> : <Blocks aria-hidden="true" size={18} />}
              {mining ? "Forging block…" : "Forge one block"}
            </button>
            <small>Fees in included transactions are burned, not paid to the miner.</small>
          </>
        ) : (
          <>
            <span className="card-eyebrow">{status?.proof_profile ?? "Production"} mining</span>
            <h2>Production proof path selected</h2>
            <p>The bounded DevnetV2 forge action is disabled. This build will not substitute the Devnet proof for ProductionV3 work.</p>
            <div className="info-inline">
              <ShieldAlert aria-hidden="true" size={17} />
              <span>Use a ProductionV3-capable external miner when the production work protocol is enabled.</span>
            </div>
          </>
        )}
      </aside>
    </div>
  );
}

function peerStateLabel(state: "connected" | "reachable" | "failed") {
  if (state === "connected") return "Connected";
  if (state === "reachable") return "Reachable";
  return "Failed";
}

function capitalize(value: "inbound" | "outbound") {
  return value === "inbound" ? "Inbound" : "Outbound";
}

function formatPeerAge(timestamp: number) {
  const elapsed = Math.max(0, Math.floor(Date.now() / 1_000) - timestamp);
  if (elapsed < 5) return "just now";
  if (elapsed < 60) return `${elapsed}s ago`;
  const minutes = Math.floor(elapsed / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function Diagnostic({ label, value, mono = false, good = false, title }: { label: string; value: string; mono?: boolean; good?: boolean; title?: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd className={`${mono ? "mono" : ""}${good ? " healthy" : ""}`} title={title}>{value}</dd>
    </div>
  );
}
