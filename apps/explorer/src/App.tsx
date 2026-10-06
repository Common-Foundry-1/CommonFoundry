import { useCallback, useEffect, useRef, useState } from "react";
import { AlertTriangle, LoaderCircle } from "lucide-react";
import { ExplorerRequestError, loadAddress, loadBlock, loadExplorer, loadTransaction, MAINNET_MODE } from "./api";
import { ADDRESS_HASH } from "../shared/address";
import { demoBlock } from "./demoData";
import { parseRoute, viewPath, type ExplorerRoute } from "./routes";
import type { ExplorerBlock, ExplorerSearchKind, ExplorerSnapshot, ExplorerTransaction, ExplorerView } from "./types";
import { AddressDetail } from "./components/AddressDetail";
import { BlockDetail, TransactionDetail } from "./components/DetailViews";
import { Header } from "./components/Header";
import { Overview } from "./components/Overview";

type NavigationOptions = { replace?: boolean; path?: string };

export default function App() {
  const [snapshot, setSnapshot] = useState<ExplorerSnapshot | null>(null);
  const [preview, setPreview] = useState(false);
  const [view, setView] = useState<ExplorerView>({ kind: "overview" });
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // A deep link such as /address/<hash> shows the lookup state instead of flashing the overview.
  const [navigating, setNavigating] = useState(() => {
    const route = parseRoute(window.location.pathname);
    return route !== null && route.kind !== "overview";
  });
  const refreshVersion = useRef(0);
  const refreshInFlight = useRef(false);
  const navigationVersion = useRef(0);
  const networkId = useRef<string | null>(null);
  const routedInitialPath = useRef(false);
  const locatedPath = useRef(window.location.pathname);

  /** Moves the address bar to `path` without reloading; `replace` rewrites the current history entry. */
  const syncLocation = useCallback((path: string, replace: boolean) => {
    // The URL is left alone until its deep link has been opened, so a retry after an outage still lands on it.
    if (!routedInitialPath.current) return;
    locatedPath.current = path;
    if (window.location.pathname === path) {
      if (window.location.hash) window.history.replaceState(null, "", path);
      return;
    }
    if (replace) window.history.replaceState(null, "", path);
    else window.history.pushState(null, "", path);
  }, []);

  const showOverview = useCallback(() => {
    navigationVersion.current += 1; setNavigating(false); setView({ kind: "overview" });
    syncLocation("/", true);
  }, [syncLocation]);

  const refresh = useCallback(async (force = false) => {
    if (refreshInFlight.current && !force) return;
    refreshInFlight.current = true;
    const version = ++refreshVersion.current;
    try {
      const loaded = await loadExplorer();
      if (version !== refreshVersion.current) return;
      if (loaded.preview || (networkId.current && networkId.current !== loaded.data.network_id)) showOverview();
      networkId.current = loaded.data.network_id;
      setSnapshot(loaded.data); setPreview(loaded.preview); setError(null);
    } catch (reason) {
      if (version !== refreshVersion.current) return;
      showOverview(); setSnapshot(null); setPreview(false);
      setError(reason instanceof Error ? reason.message : "The explorer node is unavailable.");
    } finally {
      if (version === refreshVersion.current) { refreshInFlight.current = false; setLoading(false); }
    }
  }, [showOverview]);

  useEffect(() => {
    void refresh();
    // Every API poll is a billed Worker invocation; skip hidden tabs and catch up when shown.
    const refreshIfVisible = () => { if (!document.hidden) void refresh(); };
    const timer = window.setInterval(refreshIfVisible, 30_000);
    document.addEventListener("visibilitychange", refreshIfVisible);
    return () => {
      window.clearInterval(timer); document.removeEventListener("visibilitychange", refreshIfVisible);
      refreshVersion.current += 1; navigationVersion.current += 1; refreshInFlight.current = false;
    };
  }, [refresh]);

  const navigate = async (load: () => Promise<ExplorerView>, options: NavigationOptions = {}) => {
    const version = ++navigationVersion.current;
    setError(null); setNavigating(true);
    try {
      const next = await load();
      if (version !== navigationVersion.current) return;
      setView(next); syncLocation(options.path ?? viewPath(next), options.replace ?? false);
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (reason) {
      if (version !== navigationVersion.current) return;
      setView({ kind: "overview" }); syncLocation("/", true);
      setError(reason instanceof Error ? reason.message : "The requested chain data is unavailable.");
    } finally {
      if (version === navigationVersion.current) setNavigating(false);
    }
  };

  const openBlock = (block: ExplorerBlock | string, options: NavigationOptions = {}) => navigate(async () => ({
    kind: "block", block: preview && typeof block !== "string" ? demoBlock(block) : await loadBlock(typeof block === "string" ? block : block.block_id, preview),
  }), { ...options, path: typeof block === "string" && /^\d+$/.test(block) ? `/block/${block}` : options.path });
  const openTransaction = (transaction: ExplorerTransaction | string, options: NavigationOptions = {}) => navigate(async () => ({
    kind: "transaction", transaction: typeof transaction === "string" ? await loadTransaction(transaction, preview) : transaction,
  }), options);
  const openAddress = (address: string, options: NavigationOptions = {}) => navigate(async () => ({
    kind: "address", address: await loadAddress(address, null, preview),
  }), options);

  const openRoute = (route: ExplorerRoute, replace: boolean) => {
    switch (route.kind) {
      case "overview": navigationVersion.current += 1; setNavigating(false); setError(null); setView({ kind: "overview" }); syncLocation("/", replace); return;
      case "block": void openBlock(route.query, { replace }); return;
      case "transaction": void openTransaction(route.txid, { replace }); return;
      case "address": void openAddress(route.address, { replace }); return;
    }
  };
  const openRouteRef = useRef(openRoute);
  openRouteRef.current = openRoute;

  // Open the page named by the URL once live data is available, e.g. a shared /address/<hash> link.
  useEffect(() => {
    if (!snapshot || routedInitialPath.current) return;
    routedInitialPath.current = true;
    const route = parseRoute(window.location.pathname);
    if (route) openRoute(route, true);
    else { setNavigating(false); syncLocation("/", true); }
  }, [snapshot]);

  // Browser back/forward: reopen the page for the restored path; hash-only changes keep the current page.
  useEffect(() => {
    const onPopState = () => {
      // Hash-only changes, such as the overview section links, keep the current page.
      if (!routedInitialPath.current || window.location.pathname === locatedPath.current) return;
      const route = parseRoute(window.location.pathname);
      if (route) openRouteRef.current(route, true);
      else { navigationVersion.current += 1; setNavigating(false); setView({ kind: "overview" }); syncLocation("/", true); }
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const search = async (query: string, kind: ExplorerSearchKind) => {
    if (kind === "address" && ADDRESS_HASH.test(query)) {
      await openAddress(query);
      return;
    }
    if (kind === "chain" && /^\d{1,20}$/.test(query) && BigInt(query) <= 18_446_744_073_709_551_615n) {
      await openBlock(query); return;
    }
    if (kind === "chain" && ADDRESS_HASH.test(query)) {
      const normalized = query.toLowerCase();
      await navigate(async () => {
        try { return { kind: "block", block: await loadBlock(normalized, preview) }; }
        catch (reason) {
          if (!preview && (!(reason instanceof ExplorerRequestError) || reason.status !== 404)) throw reason;
          return { kind: "transaction", transaction: await loadTransaction(normalized, preview) };
        }
      });
      return;
    }
    showOverview();
    setError(kind === "address" ? "Enter a 64-character wallet address." : "Enter a block height or a 64-character block/transaction hash. Choose Address to look up a wallet.");
  };

  const home = () => {
    navigationVersion.current += 1; setNavigating(false); setView({ kind: "overview" }); setError(null);
    syncLocation("/", false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  if (loading) return <div className="load-state"><LoaderCircle className="spin" /><span>Opening the chain…</span></div>;
  if (!snapshot) return <div className="load-state error"><AlertTriangle /><strong>{MAINNET_MODE ? "Mainnet explorer awaiting connection" : "Explorer unavailable"}</strong><span>{error}</span><button type="button" onClick={() => void refresh(true)}>Retry</button></div>;

  return <div className="app-shell">
    <Header network={snapshot.network_short_name} connected={!preview} onHome={home} onSearch={(query, kind) => void search(query, kind)} />
    {error && <div className="error-banner" role="alert"><AlertTriangle size={15} />{error}<button type="button" onClick={() => setError(null)}>Dismiss</button></div>}
    {navigating ? <main className="detail-loading" role="status"><LoaderCircle className="spin" /> Looking up chain data…</main> : <>
      {view.kind === "overview" && <Overview snapshot={snapshot} preview={preview} onBlock={(block) => void openBlock(block)} onTransaction={(tx) => void openTransaction(tx)} />}
      {view.kind === "block" && <BlockDetail block={view.block} onBack={home} onTransaction={(tx) => void openTransaction(tx)} />}
      {view.kind === "transaction" && <TransactionDetail transaction={view.transaction} onBack={home} />}
      {view.kind === "address" && <AddressDetail initial={view.address} liveTip={snapshot.tip} onBack={home} onBlock={(id) => void openBlock(id)} onTransaction={(id) => void openTransaction(id)} />}
    </>}
    <footer><span>Common Foundry Explorer</span><code>{snapshot.network_id.slice(0, 16)}…</code><span>Built for independently verifiable compute.</span></footer>
  </div>;
}
