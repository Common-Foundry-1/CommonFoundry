import { ArrowDownLeft, ArrowRightLeft, ArrowUpRight, Hammer, Hourglass, Wrench } from "lucide-react";
import { formatAtoms, formatTimestamp, shortenHash } from "../lib/amount";
import type { WalletHistoryEntry } from "../types";

interface TransactionListProps {
  entries: WalletHistoryEntry[];
  compact?: boolean;
}

function isWalletMaintenance(entry: WalletHistoryEntry) {
  return entry.kind === "sent"
    && entry.counterparty === null
    && BigInt(entry.net_amount_atoms) === -BigInt(entry.fee_burned_atoms);
}

function transactionLabel(entry: WalletHistoryEntry) {
  if (isWalletMaintenance(entry)) return "Wallet maintenance";

  switch (entry.kind) {
    case "mined":
      return "Mined reward";
    case "sent":
      return "Sent CMFD";
    case "received":
      return "Received CMFD";
    case "consolidated":
      return "Consolidated outputs";
  }
}

function TransactionIcon({ entry }: { entry: WalletHistoryEntry }) {
  if (isWalletMaintenance(entry)) return <Wrench aria-hidden="true" size={18} />;
  if (entry.status === "immature") return <Hourglass aria-hidden="true" size={18} />;
  if (entry.kind === "mined") return <Hammer aria-hidden="true" size={18} />;
  if (entry.kind === "sent") return <ArrowUpRight aria-hidden="true" size={18} />;
  if (entry.kind === "received") return <ArrowDownLeft aria-hidden="true" size={18} />;
  return <ArrowRightLeft aria-hidden="true" size={18} />;
}

export function TransactionList({ entries, compact = false }: TransactionListProps) {
  const visible = compact ? entries.slice(0, 5) : entries;
  if (visible.length === 0) {
    return (
      <div className="empty-state">
        <ActivityMark />
        <strong>No wallet activity yet</strong>
        <p>Mined rewards and wallet payments will appear here.</p>
      </div>
    );
  }

  return (
    <div className="transaction-list">
      {visible.map((entry) => {
        const value = BigInt(entry.net_amount_atoms);
        const maintenance = isWalletMaintenance(entry);
        return (
          <article className="transaction-row" key={`${entry.txid}-${entry.kind}-${entry.height ?? "pending"}`}>
            <span
              className={`transaction-icon ${maintenance ? "kind-consolidated kind-maintenance" : `kind-${entry.kind}`}`}
              data-transaction-kind={maintenance ? "maintenance" : entry.kind}
            >
              <TransactionIcon entry={entry} />
            </span>
            <div className="transaction-main">
              <div className="transaction-title-line">
                <strong>{transactionLabel(entry)}</strong>
                <span className={`transaction-status status-${entry.status}`}>
                  {entry.status === "pending"
                    ? "Pending"
                    : entry.status === "immature"
                      ? `${entry.confirmations}/100 confirmations`
                      : `${entry.confirmations} confirmation${entry.confirmations === 1 ? "" : "s"}`}
                </span>
              </div>
              <span className="transaction-meta">
                {formatTimestamp(entry.timestamp)} · {shortenHash(entry.txid, 7, 7)}
              </span>
            </div>
            <div className="transaction-value">
              <strong className={value < 0n ? "is-negative" : "is-positive"}>
                {formatAtoms(value, true)} CMFD
              </strong>
              {BigInt(entry.fee_burned_atoms) > 0n ? (
                <span>{formatAtoms(entry.fee_burned_atoms)} burned</span>
              ) : (
                <span>{entry.kind === "mined" ? "Block reward" : "No fee"}</span>
              )}
            </div>
          </article>
        );
      })}
    </div>
  );
}

function ActivityMark() {
  return (
    <svg className="empty-state-mark" viewBox="0 0 48 48" aria-hidden="true">
      <path d="M12 16h24M12 24h16M12 32h10" />
    </svg>
  );
}
