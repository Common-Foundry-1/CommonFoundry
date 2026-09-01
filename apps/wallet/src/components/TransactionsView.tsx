import { ArrowRightLeft, Layers3 } from "lucide-react";
import { formatAtoms, formatBytes, shortenHash } from "../lib/amount";
import type { MempoolSnapshot, WalletSnapshot } from "../types";
import { TransactionList } from "./TransactionList";

interface TransactionsViewProps {
  wallet: WalletSnapshot | null;
  mempool: MempoolSnapshot | null;
  onConsolidate: () => void;
}

export function TransactionsView({ wallet, mempool, onConsolidate }: TransactionsViewProps) {
  const canConsolidate = (wallet?.spendable_utxo_count ?? 0) >= 2;

  return (
    <div className="transactions-layout">
      <section className="activity-card full-history-card">
        <div className="section-heading">
          <div>
            <span>Active-chain history</span>
            <h2>Wallet transactions</h2>
          </div>
          <span className="record-count">{wallet?.history.length ?? 0} records</span>
        </div>
        <TransactionList entries={wallet?.history ?? []} />
      </section>

      <aside className="hygiene-card">
        <div className="hygiene-mark">
          <Layers3 aria-hidden="true" size={23} />
        </div>
        <span className="card-eyebrow">Miner wallet hygiene</span>
        <h2>Consolidate mining outputs</h2>
        <p>
          Combine many mature rewards into one wallet output. This keeps future
          transactions smaller and easier to manage.
        </p>
        <dl className="utxo-counts">
          <div>
            <dt>Spendable</dt>
            <dd>{wallet?.spendable_utxo_count ?? "—"}</dd>
          </div>
          <div>
            <dt>Immature</dt>
            <dd>{wallet?.immature_utxo_count ?? "—"}</dd>
          </div>
          <div>
            <dt>Reserved</dt>
            <dd>{wallet?.reserved_utxo_count ?? "—"}</dd>
          </div>
        </dl>
        <button className="button-primary wide" type="button" onClick={onConsolidate} disabled={!canConsolidate}>
          <ArrowRightLeft aria-hidden="true" size={18} />
          Consolidate outputs
        </button>
        {!canConsolidate && wallet ? (
          <small>At least two spendable outputs are required.</small>
        ) : null}
      </aside>

      <section className="mempool-card">
        <div className="section-heading">
          <div>
            <span>Unconfirmed activity</span>
            <h2>Mempool</h2>
          </div>
          <span className="record-count">
            {mempool ? `${mempool.transactions} tx · ${formatBytes(mempool.bytes)}` : "—"}
          </span>
        </div>
        {mempool && mempool.entries.length > 0 ? (
          <div className="mempool-table" role="table" aria-label="Mempool transactions">
            <div className="mempool-table-head" role="row">
              <span role="columnheader">Transaction</span>
              <span role="columnheader">Size</span>
              <span role="columnheader">Fee burned</span>
              <span role="columnheader">Status</span>
            </div>
            {mempool.entries.map((entry) => (
              <div className="mempool-table-row" role="row" key={entry.txid}>
                <code role="cell" title={entry.txid}>{shortenHash(entry.txid, 9, 9)}</code>
                <span role="cell">{formatBytes(entry.encoded_bytes)}</span>
                <span role="cell">{formatAtoms(entry.fee_burned_atoms ?? String(entry.fee_burned))} CMFD</span>
                <span role="cell" className="status-pill">Unconfirmed</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state compact">
            <strong>Mempool is clear</strong>
            <p>Unconfirmed wallet transactions will appear here.</p>
          </div>
        )}
      </section>
    </div>
  );
}
