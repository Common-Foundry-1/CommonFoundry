import { AlertTriangle, RefreshCw, Settings2, X } from "lucide-react";
import { useCallback, useState } from "react";
import { usesEmbeddedNode } from "./api/nodeClient";
import { ConsolidationDialog } from "./components/ConsolidationDialog";
import { MobileNav } from "./components/MobileNav";
import { MiningView } from "./components/MiningView";
import { NetworkView } from "./components/NetworkView";
import { Overview } from "./components/Overview";
import { ReceiveDialog } from "./components/ReceiveDialog";
import { SendDialog } from "./components/SendDialog";
import { Sidebar, type ViewName } from "./components/Sidebar";
import { TransactionsView } from "./components/TransactionsView";
import { useWalletData } from "./hooks/useWalletData";

const TITLES: Record<ViewName, { eyebrow: string; title: string }> = {
  overview: { eyebrow: "Common Foundry Wallet", title: "Overview" },
  transactions: { eyebrow: "Wallet ledger", title: "Transactions" },
  mining: { eyebrow: "ForgeMatrix reference engine", title: "Mining" },
  network: { eyebrow: "Network operations", title: "Network" },
};

export function App() {
  const [view, setView] = useState<ViewName>("overview");
  const [sendOpen, setSendOpen] = useState(false);
  const [receiveOpen, setReceiveOpen] = useState(false);
  const [consolidateOpen, setConsolidateOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const data = useWalletData();
  const networkShortName = data.status?.network_short_name ?? "Network";
  const heading = view === "network"
    ? { eyebrow: `${networkShortName} operations`, title: "Network" }
    : TITLES[view];

  const openSend = useCallback(() => setSendOpen(true), []);
  const closeSend = useCallback(() => setSendOpen(false), []);
  const openReceive = useCallback(() => setReceiveOpen(true), []);
  const closeReceive = useCallback(() => setReceiveOpen(false), []);
  const openConsolidation = useCallback(() => setConsolidateOpen(true), []);
  const closeConsolidation = useCallback(() => setConsolidateOpen(false), []);

  const showNotice = useCallback((message: string) => {
    setNotice(message);
    window.setTimeout(() => setNotice((current) => (current === message ? null : current)), 4_500);
  }, []);

  return (
    <div className="app-shell">
      <Sidebar
        active={view}
        onNavigate={setView}
        onSend={openSend}
        onReceive={openReceive}
        networkName={networkShortName}
        networkPurpose={data.status?.network_purpose ?? "Network unavailable"}
      />

      <main className="workspace">
        <header className="topbar">
          <div>
            <span>{heading.eyebrow}</span>
            <h1>{heading.title}</h1>
          </div>
          <div className="topbar-actions">
            <div className={`connection-pill${data.error ? " is-offline" : ""}`}>
              <span />
              {data.error ? "Node offline" : `${networkShortName} Connected`}
            </div>
            <button className="icon-button topbar-settings" type="button" onClick={() => setView("network")} aria-label="Open node settings">
              <Settings2 aria-hidden="true" size={18} />
            </button>
          </div>
        </header>

        <div className="devnet-warning" role="note">
          <AlertTriangle aria-hidden="true" size={16} />
          <span>
            <strong>{data.status?.network ?? "Common Foundry network"}</strong>
            {` · ${data.status?.network_notice ?? "Network status unavailable"}`}
          </span>
        </div>

        {data.error ? (
          <div className="offline-banner" role="alert">
            <div>
              <strong>Local node unavailable</strong>
              <span>{data.error}</span>
            </div>
            <button className="button-secondary compact" type="button" onClick={() => void data.refresh()}>
              <RefreshCw aria-hidden="true" size={16} />
              Retry
            </button>
          </div>
        ) : null}

        <div className={`workspace-content${data.loading ? " is-loading" : ""}`} aria-busy={data.loading}>
          {view === "overview" ? (
            <Overview
              wallet={data.wallet}
              status={data.status}
              refreshing={data.refreshing}
              onSend={openSend}
              onReceive={openReceive}
              onViewTransactions={() => setView("transactions")}
              onViewNetwork={() => setView("network")}
              onRefresh={() => void data.refresh()}
            />
          ) : null}
          {view === "transactions" ? (
            <TransactionsView
              wallet={data.wallet}
              mempool={data.mempool}
              onConsolidate={openConsolidation}
            />
          ) : null}
          {view === "mining" ? (
            <MiningView wallet={data.wallet} nodeStatus={data.status} />
          ) : null}
          {view === "network" ? (
            <NetworkView
              status={data.status}
              wallet={data.wallet}
              mempool={data.mempool}
              refreshing={data.refreshing}
              onRefresh={data.refresh}
              onNotice={showNotice}
            />
          ) : null}
        </div>

        <footer className="statusbar">
          <span><i className={data.error ? "offline" : ""} />{
            data.error
              ? (usesEmbeddedNode ? "Embedded node offline" : "RPC offline")
              : (usesEmbeddedNode ? "Embedded node connected" : "RPC connected")
          }</span>
          <span>{data.status?.network ?? "Network unavailable"}</span>
          <span>Height {data.status?.accepted_height ?? "—"}</span>
          <span>{data.status?.storage_healthy ? "Storage healthy" : "Storage unavailable"}</span>
          <span className="statusbar-update">{data.lastUpdated ? `Updated ${data.lastUpdated.toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" })}` : "Waiting for node"}</span>
        </footer>
      </main>

      <MobileNav
        active={view}
        onNavigate={setView}
        onSend={openSend}
        onReceive={openReceive}
      />

      <SendDialog
        open={sendOpen}
        wallet={data.wallet}
        onClose={closeSend}
        onCompleted={showNotice}
        onRefresh={data.refresh}
      />
      <ReceiveDialog open={receiveOpen} wallet={data.wallet} onClose={closeReceive} />
      <ConsolidationDialog
        open={consolidateOpen}
        wallet={data.wallet}
        onClose={closeConsolidation}
        onCompleted={showNotice}
        onRefresh={data.refresh}
      />

      {notice ? (
        <div className="toast" role="status">
          <span>{notice}</span>
          <button type="button" onClick={() => setNotice(null)} aria-label="Dismiss notification"><X aria-hidden="true" size={16} /></button>
        </div>
      ) : null}
    </div>
  );
}
