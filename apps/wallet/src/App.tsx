import { RefreshCw, Settings2, ShieldCheck, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { getWalletCustodyStatus, usesEmbeddedNode } from "./api/nodeClient";
import { ConsolidationDialog } from "./components/ConsolidationDialog";
import { MobileNav } from "./components/MobileNav";
import { MiningView } from "./components/MiningView";
import { NetworkView } from "./components/NetworkView";
import { Overview } from "./components/Overview";
import { PrelaunchWallet } from "./components/PrelaunchWallet";
import { ReceiveDialog } from "./components/ReceiveDialog";
import { ResyncDialog } from "./components/ResyncDialog";
import { SendDialog } from "./components/SendDialog";
import { Sidebar, type ViewName } from "./components/Sidebar";
import { StartupScreen } from "./components/StartupScreen";
import { TransactionsView } from "./components/TransactionsView";
import { UpdateBanner } from "./components/UpdateBanner";
import { WalletSecurityDialog } from "./components/WalletSecurityDialog";
import { WorkCheckNotice } from "./components/WorkCheckNotice";
import { useWalletData } from "./hooks/useWalletData";
import type { WalletCustodyStatus } from "./types";

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
  const [resyncOpen, setResyncOpen] = useState(false);
  const [custody, setCustody] = useState<WalletCustodyStatus | null>(null);
  const [custodyError, setCustodyError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // Where a resync put the old chain. A resync leaves an encrypted wallet
  // locked, so this must still show on the launch screen that follows.
  const [resyncNotice, setResyncNotice] = useState<string | null>(null);
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

  const refreshCustody = useCallback(async () => {
    if (!usesEmbeddedNode) return;
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

  // A newer version failed after it opened the wallet data: the update
  // banner asks Retry or Run anyway, and unlocking waits for that choice.
  // A mainnet wallet always reports its launch, so a held wallet must not get
  // the launch unlock screen, which has no update banner.
  const updateHeld = data.errorCode === "update_fallback_held";
  // A stored chain the node refused is resynced first; unlocking cannot start
  // the node until then. The launch screen has no resync either, so a
  // mainnet wallet that needs one gets the main layout too.
  const resyncRequired = data.errorCode === "chain_resync_required";
  const preparingLaunch = Boolean(custody?.launch && !custody.unlocked) && !updateHeld && !resyncRequired;
  // Once the wallet runs again, the resync notice has done its job.
  useEffect(() => {
    if (custody?.unlocked) setResyncNotice(null);
  }, [custody?.unlocked]);

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

  const custodyRequired = usesEmbeddedNode && custody !== null && !custody.unlocked && !resyncRequired && !updateHeld;
  const custodyNeedsAttention = usesEmbeddedNode && (custody?.requires_migration || custodyRequired);

  // The launch screen shows update notices too: a mainnet wallet always
  // starts locked, and why a newer version could not start belongs on the
  // first screen.
  if (preparingLaunch && custody) {
    return <PrelaunchWallet status={custody} statusError={custodyError} onStatusChange={setCustody}
      onRefresh={async () => { await Promise.allSettled([data.refresh(), refreshCustody()]); }}
      updateNotice={<UpdateBanner />} notice={resyncNotice} />;
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
              {data.error ? "Node offline" : `${networkShortName} Connected`}
            </div>
            {usesEmbeddedNode ? (
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
            <button className="icon-button topbar-settings topbar-node-settings" type="button" onClick={() => setView("network")} aria-label="Open node settings">
              <Settings2 aria-hidden="true" size={18} />
            </button>
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

        {usesEmbeddedNode ? (
          <UpdateBanner heldMessage={updateHeld ? data.error : null} onRunAnyway={() => void data.refresh()} />
        ) : null}

        {updateHeld ? null : data.error ? (
          <div className="offline-banner" role="alert">
            <div>
              <strong>{resyncRequired ? "Stored chain needs a resync" : "Local node unavailable"}</strong>
              <span>{data.error}</span>
            </div>
            {resyncRequired ? (
              <button className="button-secondary compact" type="button" onClick={() => setResyncOpen(true)}>
                <RefreshCw aria-hidden="true" size={16} />
                Resync chain
              </button>
            ) : (
              <button className="button-secondary compact" type="button" onClick={() => void data.refresh()}>
                <RefreshCw aria-hidden="true" size={16} />
                Retry
              </button>
            )}
          </div>
        ) : (
          <WorkCheckNotice status={data.status} onResync={() => setResyncOpen(true)} />
        )}

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
      <ResyncDialog
        open={resyncOpen}
        onClose={() => setResyncOpen(false)}
        onStatusChange={(next) => {
          setCustody(next);
          setCustodyError(null);
        }}
        onCompleted={(message) => {
          setResyncNotice(message);
          showNotice(message);
        }}
        onRefresh={async () => {
          await Promise.allSettled([data.refresh(), refreshCustody()]);
        }}
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
