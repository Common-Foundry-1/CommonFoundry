import { useCallback, useState } from "react";
import { ReceiveDialog } from "./ReceiveDialog";
import { WalletSecurityDialog } from "./WalletSecurityDialog";
import type { WalletCustodyStatus } from "../types";

interface Props {
  status: WalletCustodyStatus;
  statusError: string | null;
  onStatusChange: (status: WalletCustodyStatus) => void;
  onRefresh: () => Promise<void>;
}

export function PrelaunchWallet({ status, statusError, onStatusChange, onRefresh }: Props) {
  const [securityOpen, setSecurityOpen] = useState(false);
  const [receiveOpen, setReceiveOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const closeSecurity = useCallback(() => setSecurityOpen(false), []);
  const closeReceive = useCallback(() => setReceiveOpen(false), []);
  const launch = status.launch!;
  const start = new Intl.DateTimeFormat("en-US", {
    timeZone: "America/Chicago", month: "long", day: "numeric", year: "numeric",
    hour: "numeric", minute: "2-digit", timeZoneName: "short",
  }).format(new Date(launch.mining_start_utc));

  return (
    <main className="prelaunch-wallet">
      <section className="prelaunch-panel" aria-labelledby="prelaunch-title" inert={securityOpen || receiveOpen}>
        <p className="dialog-eyebrow">{status.network}</p>
        <h1 className="dialog-title" id="prelaunch-title">{launch.ready ? "Mainnet is ready to connect" : "Get ready for mainnet"}</h1>
        <p className="dialog-description">Mining starts {start}.</p>
        <div className="custody-summary">
          <div>
            <strong>{launch.ready ? "Launch certificate verified" : "Waiting for the launch certificate"}</strong>
            <span>{launch.ready ? "Unlock your wallet to start the node." : "You can prepare your wallet now. The node and miner will not start before activation."}</span>
          </div>
        </div>
        <p className="dialog-description">Create an encrypted wallet and backup, or restore an existing backup. You can copy your receiving address for miner setup without keeping your signing key unlocked.</p>
        {status.destination ? <>
          <p className="dialog-address-label">Your mainnet receiving address</p>
          <output className="dialog-address" aria-label="Prepared wallet address">{status.destination}</output>
          <button className="button-secondary" type="button" onClick={() => setReceiveOpen(true)}>Copy address / QR code</button>
        </> : null}
        <div className="dialog-actions">
          <button className="button-primary" type="button" onClick={() => setSecurityOpen(true)}>
            {status.storage === "missing" ? "Set up wallet" : launch.ready ? "Unlock and connect" : status.destination ? "Wallet backup and security" : "Show receiving address"}
          </button>
          <button className="button-secondary" type="button" onClick={() => void onRefresh()}>Refresh launch status</button>
        </div>
        {launch.error || statusError ? <p className="form-error" role="alert">{statusError ?? launch.error} Reopen the wallet after correcting the problem.</p> : null}
        {notice ? <p className="form-status" role="status">{notice}</p> : null}
      </section>
      <WalletSecurityDialog open={securityOpen} required={false} status={status} statusError={statusError}
        onClose={closeSecurity} onStatusChange={onStatusChange}
        onCompleted={setNotice} onRefresh={onRefresh} />
      <ReceiveDialog open={receiveOpen} onClose={closeReceive} wallet={status.destination ? {
        destination: status.destination, network: status.network, insecure_demo_wallet: false,
        warning: "Prepared address only. Sending, receiving confirmations, and mining require the activated network.",
      } : null} />
    </main>
  );
}
