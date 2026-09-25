import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, ArrowRight, Copy, LoaderCircle, RefreshCw, Wallet } from "lucide-react";
import { ExplorerRequestError, loadAddress } from "../api";
import { formatAge, formatAtoms, shortHash } from "../format";
import type { ExplorerAddress, ExplorerAddressActivity } from "../types";

const activityLabels: Record<ExplorerAddressActivity["kind"], string> = {
  coinbase: "Block reward", received: "Received", sent: "Sent", self: "Self transfer",
};

type Props = {
  initial: ExplorerAddress;
  liveTip: string;
  onBack: () => void;
  onBlock: (id: string) => void;
  onTransaction: (id: string) => void;
};

export function AddressDetail({ initial, liveTip, onBack, onBlock, onTransaction }: Props) {
  const address = initial.address;
  const [page, setPage] = useState<ExplorerAddress | null>(initial);
  const [cursor, setCursor] = useState<string | null>(null);
  const [trail, setTrail] = useState<(string | null)[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copyStatus, setCopyStatus] = useState("");
  const requestVersion = useRef(0);
  const observedTip = useRef(liveTip);
  const pageTip = useRef(initial.tip);

  const requestPage = useCallback(async (next: string | null, previous: (string | null)[], notice: string | null = null) => {
    const version = ++requestVersion.current;
    setBusy(true); setError(null); setMessage(notice);
    if (notice) setPage(null);
    try {
      let loaded: ExplorerAddress;
      let resolvedCursor = next;
      let resolvedTrail = previous;
      try {
        loaded = await loadAddress(address, next);
      } catch (reason) {
        if (version !== requestVersion.current) return;
        if (!(reason instanceof ExplorerRequestError) || reason.status !== 409 || reason.code !== "explorer_cursor_stale" || !next) throw reason;
        setPage(null);
        setMessage("The chain changed. Showing the newest activity.");
        loaded = await loadAddress(address);
        resolvedCursor = null; resolvedTrail = [];
      }
      if (version !== requestVersion.current) return;
      pageTip.current = loaded.tip;
      setPage(loaded); setCursor(resolvedCursor); setTrail(resolvedTrail);
    } catch (reason) {
      if (version !== requestVersion.current) return;
      setPage(null);
      setError(reason instanceof Error ? reason.message : "Address lookup is unavailable.");
    } finally {
      if (version === requestVersion.current) setBusy(false);
    }
  }, [address]);

  useEffect(() => () => { requestVersion.current += 1; }, []);
  useEffect(() => {
    if (liveTip === observedTip.current) return;
    observedTip.current = liveTip;
    if (liveTip !== pageTip.current) void requestPage(null, [], "The chain changed. Showing the newest activity.");
  }, [liveTip, requestPage]);

  const copyAddress = async () => {
    try { await navigator.clipboard.writeText(address); setCopyStatus("Address copied."); }
    catch { setCopyStatus("Copy unavailable. Select the address text to copy it."); }
  };

  return <main className="detail-main address-main">
    <button className="back-button" type="button" onClick={onBack}><ArrowLeft size={15} /> Explorer overview</button>
    <section className="detail-hero"><div><p className="eyebrow">Public chain lookup</p><h1>Address</h1><p>Confirmed balances and canonical activity.</p></div><span className="verified"><Wallet size={16} /> Read-only</span></section>
    <div className="address-identity"><code>{address}</code><button type="button" onClick={() => void copyAddress()} aria-label="Copy address"><Copy size={17} /> Copy</button></div>
    <div className="address-notices" aria-live="polite">{copyStatus && <p>{copyStatus}</p>}{message && <p>{message}</p>}{busy && <p><LoaderCircle size={15} className="spin" /> Loading address activity…</p>}</div>
    {error && <section className="address-unavailable" role="alert"><h2>Address lookup unavailable</h2><p>{error}</p><button type="button" disabled={busy} onClick={() => void requestPage(null, [])}>Retry latest activity</button></section>}
    {page && <>
      <div className="address-balance-grid">
        <Balance label="Confirmed balance" amount={page.confirmed_atoms} note="Includes immature outputs" />
        <Balance label="Spendable next block" amount={page.spendable_atoms} note="Before pending-transfer reservations" />
        <Balance label="Immature balance" amount={page.immature_atoms} note="Waiting for protocol maturity" />
      </div>
      <p className="address-scope">{page.utxo_count.toLocaleString()} unspent key output{page.utxo_count === 1 ? "" : "s"} · As of block #{page.accepted_height.toLocaleString()}. Pending transfers and channel escrow are excluded.</p>
      <section className="data-section address-history" aria-label="Address activity">
        <div className="section-heading"><div><p className="eyebrow">Canonical history</p><h2>Address activity</h2></div><span>Page {trail.length + 1} · newest first</span></div>
        <div className="address-activity-list">{page.history.length ? page.history.map((entry) => <article key={`${entry.block_id}:${entry.txid}`}>
          <div><strong>{activityLabels[entry.kind]}</strong><small><button type="button" onClick={() => onBlock(entry.block_id)}>Block #{entry.block_height.toLocaleString()}</button> · {formatAge(entry.timestamp)}</small></div>
          <div><button type="button" className="address-record-link" onClick={() => entry.kind === "coinbase" ? onBlock(entry.block_id) : onTransaction(entry.txid)} aria-label={`${entry.kind === "coinbase" ? "Open reward block" : "Open transaction"} ${entry.txid}`}><code>{shortHash(entry.txid, 14, 10)}</code></button><small>{entry.confirmations.toLocaleString()} confirmation{entry.confirmations === 1 ? "" : "s"}{entry.spent_inputs ? ` · ${entry.spent_inputs} input${entry.spent_inputs === 1 ? "" : "s"} spent` : ""}</small></div>
          <div className="address-credited"><strong>{entry.received_outputs ? formatAtoms(entry.received_atoms) : "—"}</strong><small>Outputs to this address</small></div>
        </article>) : <p className="empty-state">No confirmed activity for this address.</p>}</div>
        <div className="address-pagination">
          <button type="button" disabled={busy || trail.length === 0} onClick={() => void requestPage(trail[trail.length - 1] ?? null, trail.slice(0, -1))}><ArrowLeft size={15} /> Newer activity</button>
          <button type="button" disabled={busy} onClick={() => void requestPage(null, [])}><RefreshCw size={15} /> Newest</button>
          <button type="button" disabled={busy || !page.has_more} onClick={() => void requestPage(page.next_cursor, [...trail, cursor])}>Older activity <ArrowRight size={15} /></button>
        </div>
      </section>
      <p className="address-scope">Amounts shown are outputs to this address, including change—not net payment amounts. History is tied to one chain tip and restarts when that tip changes.</p>
    </>}
  </main>;
}

function Balance({ label, amount, note }: { label: string; amount: string; note: string }) {
  return <section><p className="eyebrow">{label}</p><strong>{formatAtoms(amount)}</strong><small>{note}</small></section>;
}
