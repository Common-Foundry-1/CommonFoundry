import { useCallback, useEffect, useRef, useState } from "react";
import { AlertTriangle, LoaderCircle } from "lucide-react";
import { loadBlock, loadExplorer, loadTransaction, MAINNET_MODE } from "./api";
import { demoBlock } from "./demoData";
import type { ExplorerBlock, ExplorerSnapshot, ExplorerTransaction, ExplorerView } from "./types";
import { BlockDetail, TransactionDetail } from "./components/DetailViews";
import { Header } from "./components/Header";
import { Overview } from "./components/Overview";

export default function App() {
  const [snapshot, setSnapshot] = useState<ExplorerSnapshot | null>(null);
  const [preview, setPreview] = useState(false);
  const [view, setView] = useState<ExplorerView>({ kind: "overview" });
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const refreshVersion = useRef(0);
  const refreshInFlight = useRef(false);

  const refresh = useCallback(async (force = false) => {
    if (refreshInFlight.current && !force) return;
    refreshInFlight.current = true;
    const version = ++refreshVersion.current;
    try {
      const loaded = await loadExplorer();
      if (version !== refreshVersion.current) return;
      setSnapshot(loaded.data);
      setPreview(loaded.preview);
      setError(null);
    } catch (reason) {
      if (version !== refreshVersion.current) return;
      setSnapshot(null);
      setPreview(false);
      setView({ kind: "overview" });
      setError(reason instanceof Error ? reason.message : "The explorer node is unavailable.");
    } finally {
      if (version === refreshVersion.current) {
        refreshInFlight.current = false;
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 10_000);
    return () => { window.clearInterval(timer); refreshVersion.current += 1; refreshInFlight.current = false; };
  }, [refresh]);

  const openBlock = async (block: ExplorerBlock | string) => {
    try {
      setError(null);
      const detail = preview && typeof block !== "string" ? demoBlock(block) : await loadBlock(typeof block === "string" ? block : block.block_id, preview);
      setView({ kind: "block", block: detail });
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Block not found.");
    }
  };

  const openTransaction = async (transaction: ExplorerTransaction | string) => {
    try {
      setError(null);
      const detail = typeof transaction === "string" ? await loadTransaction(transaction, preview) : transaction;
      setView({ kind: "transaction", transaction: detail });
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Transaction not found.");
    }
  };

  const search = async (query: string) => {
    if (/^\d+$/.test(query)) {
      await openBlock(query);
      return;
    }
    if (/^[0-9a-fA-F]{64}$/.test(query)) {
      const normalized = query.toLowerCase();
      try {
        const block = await loadBlock(normalized, preview);
        setView({ kind: "block", block });
        setError(null);
        window.scrollTo({ top: 0, behavior: "smooth" });
        return;
      } catch {
        await openTransaction(normalized);
        return;
      }
    }
    setError("Enter a block height or a 64-character block/transaction hash.");
  };

  const home = () => {
    setView({ kind: "overview" });
    setError(null);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  if (loading) return <div className="load-state"><LoaderCircle className="spin" /><span>Opening the chain…</span></div>;
  if (!snapshot) return <div className="load-state error"><AlertTriangle /><strong>{MAINNET_MODE ? "Mainnet explorer awaiting connection" : "Explorer unavailable"}</strong><span>{error}</span><button type="button" onClick={() => void refresh(true)}>Retry</button></div>;

  return <div className="app-shell"><Header network={snapshot.network_short_name} connected={!preview} onHome={home} onSearch={(query) => void search(query)} />{error && <div className="error-banner"><AlertTriangle size={15} />{error}<button type="button" onClick={() => setError(null)}>Dismiss</button></div>}{view.kind === "overview" && <Overview snapshot={snapshot} preview={preview} onBlock={(block) => void openBlock(block)} onTransaction={(tx) => void openTransaction(tx)} />}{view.kind === "block" && <BlockDetail block={view.block} onBack={home} onTransaction={(tx) => void openTransaction(tx)} />}{view.kind === "transaction" && <TransactionDetail transaction={view.transaction} onBack={home} />}<footer><span>Common Foundry Explorer</span><code>{snapshot.network_id.slice(0, 16)}…</code><span>Built for independently verifiable compute.</span></footer></div>;
}
