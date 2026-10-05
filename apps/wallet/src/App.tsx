import { RefreshCw, Settings2, ShieldCheck, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { getWalletCustodyStatus, lockWallet, usesEmbeddedNode } from "./api/nodeClient";
import { usesBrowserKeys } from "./api/transportMode";
import { ConsolidationDialog } from "./components/ConsolidationDialog";
import { MobileNav } from "./components/MobileNav";
import { MiningView } from "./components/MiningView";
import { NetworkView } from "./components/NetworkView";
import { Overview } from "./components/Overview";
import { PrelaunchWallet } from "./components/PrelaunchWallet";
import { ReceiveDialog } from "./components/ReceiveDialog";
import { SendDialog } from "./components/SendDialog";
import { Sidebar, type ViewName } from "./components/Sidebar";
import { StartupScreen } from "./components/StartupScreen";
import { TransactionsView } from "./components/TransactionsView";
import { WalletSecurityDialog } from "./components/WalletSecurityDialog";
import { useInactivityLock } from "./hooks/useInactivityLock";
import { useWalletData } from "./hooks/useWalletData";
import type { WalletCustodyStatus } from "./types";

// Browser keys and desktop custody share the security dialog; only the desktop runs a node.
const hasKeyCustody = usesEmbeddedNode || usesBrowserKeys;

const TITLES: Record<ViewName, { eyebrow: string; title: string }> = {
  overview: { eyebrow: "Common Foundry Wallet", title: "Overview" },
  transactions: { eyebrow: "Wallet ledger", title: "Transactions" },
  mining: { eyebrow: "ForgeMatrix mining engine", title: "Mining" },
  network: { eyebrow: "Network operations", title: "Network" },
};

export function App() {
  const [view, setView] = useState<ViewName>("overview");
  const [sendOpen, setSendOpen] = useState(false);
  const [receiveOpen, setReceiveOpen] = useState(false);
  const [consolidateOpen, setConsolidateOpen] = useState(false);
  const [securityOpen, setSecurityOpen] = useState(false);
  const [custody, setCustody] = useState<WalletCustodyStatus | null>(null);
  const [custodyError, setCustodyError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const data = useWalletData(usesBrowserKeys ? 20_000 : undefined);
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

  // Web wallet: forget the decrypted key when nobody has touched the page for a while.
  useInactivityLock(usesBrowserKeys && Boolean(custody?.unlocked), async () => {
    setCustody(await lockWallet());
    showNotice("Wallet locked after 15 minutes without activity.");
  });

  const refreshCustody = useCallback(async () => {
    if (!hasKeyCustody) return;
    try {
      const next = await getWalletCustodyStatus();
      setCustody(next);
      setCustodyError(null);
    } catch (cause) {
      setCustodyError(cause instanceof Error ? cause.message : "Wallet security status is unavailable.");
    }
  }, []);

  useEffect(() => {
    if (!data.starting) void refreshCustody();
  }, [data.starting, refreshCustody]);

  const preparingLaunch = Boolean(custody?.launch && !custody.unlocked);
  useEffect(() => {
    if (!preparingLaunch) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      await refreshCustody();
      if (!cancelled) timer = setTimeout(() => void poll(), 5_000);
    };
    timer = setTimeout(() => void poll(), 5_000);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [preparingLaunch, refreshCustody]);

  const custodyRequired = hasKeyCustody && custody !== null && !custody.unlocked;
  const custodyNeedsAttention = hasKeyCustody && (custody?.requires_migration || custodyRequired);

  if (preparingLaunch && custody) {
    return <PrelaunchWallet status={custody} statusError={custodyError} onStatusChange={setCustody}
      onRefresh={async () => { await Promise.allSettled([data.refresh(), refreshCustody()]); }} />;
  }

  if (data.starting || (data.loading && data.status === null && data.error === null)) {
    return <StartupScreen />;
  }

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
              {data.error ? (usesBrowserKeys ? "Offline" : "Node offline") : `${networkShortName} Connected`}
            </div>
            {hasKeyCustody ? (
              <button
                className={`icon-button topbar-settings${custodyNeedsAttention ? " needs-attention" : ""}`}
                type="button"
                onClick={() => setSecurityOpen(true)}
                aria-label="Open wallet security"
                title="Wallet security"
              >
                <ShieldCheck aria-hidden="true" size={18} />
              </button>
            ) : null}
            {usesBrowserKeys ? null : (
              <button className="icon-button topbar-settings topbar-node-settings" type="button" onClick={() => setView("network")} aria-label="Open node settings">
                <Settings2 aria-hidden="true" size={18} />
              </button>
            )}
          </div>
        </header>

        <div className="network-context" role="note">
          <span>
            <strong>{data.status?.network ?? "Common Foundry network"}</strong>
            {` · ${data.status?.network_notice ?? "Network status unavailable"}`}
          </span>
        </div>

        {custody?.requires_migration ? (
          <button className="custody-banner" type="button" onClick={() => setSecurityOpen(true)}>
            <ShieldCheck aria-hidden="true" size={17} />
            <span><strong>Protect this wallet</strong> · Create an authenticated backup and encrypt the local signing key.</span>
          </button>
        ) : null}

        {data.error ? (
          <div className="offline-banner" role="alert">
            <div>
              <strong>{usesBrowserKeys ? "Network service unavailable" : "Local node unavailable"}</strong>
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
              ? (usesEmbeddedNode ? "Embedded node offline" : usesBrowserKeys ? "Explorer offline" : "RPC offline")
              : (usesEmbeddedNode ? "Embedded node connected" : usesBrowserKeys ? "Explorer connected" : "RPC connected")
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
      <WalletSecurityDialog
        open={securityOpen || custodyRequired}
        required={custodyRequired}
        status={custody}
        statusError={custodyError}
        onClose={() => setSecurityOpen(false)}
        onStatusChange={(next) => {
          setCustody(next);
          setCustodyError(null);
        }}
        onCompleted={showNotice}
        onRefresh={async () => {
          await Promise.allSettled([data.refresh(), refreshCustody()]);
        }}
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
