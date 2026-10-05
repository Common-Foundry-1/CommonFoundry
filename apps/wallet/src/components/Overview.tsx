import {
  ArrowDownToLine,
  ArrowRight,
  ArrowUpFromLine,
  CheckCircle2,
  Database,
  RefreshCw,
  WalletCards,
} from "lucide-react";
import { usesBrowserKeys } from "../api/transportMode";
import { formatBalanceAtoms, formatBytes, shortenHash, sumAtoms } from "../lib/amount";
import type { NodeStatus, WalletSnapshot } from "../types";
import { TransactionList } from "./TransactionList";

interface OverviewProps {
  wallet: WalletSnapshot | null;
  status: NodeStatus | null;
  refreshing: boolean;
  onSend: () => void;
  onReceive: () => void;
  onViewTransactions: () => void;
  onViewNetwork: () => void;
  onRefresh: () => void;
}

export function Overview({
  wallet,
  status,
  refreshing,
  onSend,
  onReceive,
  onViewTransactions,
  onViewNetwork,
  onRefresh,
}: OverviewProps) {
  const balances = wallet?.balances;
  const total = balances
    ? sumAtoms(balances.spendable_atoms, balances.pending_atoms, balances.immature_atoms)
    : 0n;

  return (
    <div className="overview-grid">
      <section className="balance-card">
        <div className="card-eyebrow">
          <WalletCards aria-hidden="true" size={17} />
          Wallet balance
        </div>
        <div className="total-balance">
          <span>Total balance</span>
          <strong>{wallet ? formatBalanceAtoms(total) : "—"}</strong>
          <em>CMFD</em>
        </div>
        <div className="balance-breakdown">
          <div>
            <span>Available</span>
            <strong>{balances ? formatBalanceAtoms(balances.spendable_atoms) : "—"}</strong>
          </div>
          <div>
            <span>Pending</span>
            <strong>{balances ? formatBalanceAtoms(balances.pending_atoms) : "—"}</strong>
          </div>
          <div>
            <span>Immature</span>
            <strong>{balances ? formatBalanceAtoms(balances.immature_atoms) : "—"}</strong>
          </div>
        </div>
        <div className="balance-actions">
          <button className="button-primary" type="button" onClick={onSend} disabled={!wallet}>
            <ArrowUpFromLine aria-hidden="true" size={18} />
            Send
          </button>
          <button className="button-secondary" type="button" onClick={onReceive} disabled={!wallet}>
            <ArrowDownToLine aria-hidden="true" size={18} />
            Receive
          </button>
        </div>
      </section>

      <aside className="node-rail">
        <div className="node-rail-heading">
          <div>
            <span className="health-dot" />
            <strong>{usesBrowserKeys ? "Network connected" : "Node connected"}</strong>
          </div>
          <button className="icon-button" type="button" onClick={onRefresh} aria-label="Refresh wallet data">
            <RefreshCw aria-hidden="true" size={16} className={refreshing ? "spin" : ""} />
          </button>
        </div>
        <p>{usesBrowserKeys ? "Public explorer responding" : "Local node responding"}</p>
        <div className="node-stat-list">
          <div>
            <span>Block height</span>
            <strong>{status?.accepted_height ?? "—"}</strong>
          </div>
          <div>
            <span>Mempool</span>
            <strong>{status ? `${status.mempool_transactions} tx` : "—"}</strong>
          </div>
          <div>
            <span>Storage</span>
            <strong className={status?.storage_healthy ? "healthy" : ""}>
              {status ? (status.storage_healthy ? "Healthy" : "Faulted") : "—"}
            </strong>
          </div>
          <div>
            <span>UTXO set</span>
            <strong>{status?.utxo_count.toLocaleString() ?? "—"}</strong>
          </div>
        </div>
        <div className="node-tip">
          <Database aria-hidden="true" size={16} />
          <span>{status ? `${formatBytes(status.mempool_bytes)} in mempool` : "Waiting for node"}</span>
        </div>
        {usesBrowserKeys ? null : (
          <button className="text-button" type="button" onClick={onViewNetwork}>
            View node <ArrowRight aria-hidden="true" size={15} />
          </button>
        )}
      </aside>

      <section className="activity-card">
        <div className="section-heading">
          <div>
            <span>Wallet ledger</span>
            <h2>Recent transactions</h2>
          </div>
          <button className="text-button" type="button" onClick={onViewTransactions}>
            View all <ArrowRight aria-hidden="true" size={15} />
          </button>
        </div>
        <TransactionList entries={wallet?.history ?? []} compact />
      </section>

      <section className="wallet-health-card">
        <div className="wallet-health-icon">
          <CheckCircle2 aria-hidden="true" size={22} />
        </div>
        <div>
          <span>Wallet hygiene</span>
          <strong>{wallet ? `${wallet.spendable_utxo_count} spendable output${wallet.spendable_utxo_count === 1 ? "" : "s"}` : "Waiting for wallet"}</strong>
          <p>Consolidate mature mining outputs from the Transactions page.</p>
        </div>
      </section>
    </div>
  );
}
