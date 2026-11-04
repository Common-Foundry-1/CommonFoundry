import {useEffect, useState} from 'react';
import {getWalletStartupStatus} from '../api/nodeClient';
import type {WalletStartupStatus} from '../types';

const stages: Record<WalletStartupStatus['phase'], [string, string]> = {
  checking_inputs: ['Checking wallet files', 'Authenticating the files needed to check the blockchain.'],
  opening_data: ['Opening saved wallet data', 'Waiting for access to your existing wallet data.'],
  loading_snapshot: ['Loading saved startup state', 'Checking whether the wallet can use its saved quick-start state.'],
  scanning_history: ['Reading saved blockchain history', 'Reading the history already on this computer before checking it.'],
  checking_proofs: ['Checking stored blocks', 'The saved quick-start state could not be used. The wallet is checking stored blockchain proofs again. This can take several minutes or longer.'],
  preparing_balances: ['Preparing your wallet', 'Rebuilding balances and transaction history from the checked blockchain.'],
  connecting: ['Connecting to the network', 'Starting network services. The wallet may still need to catch up after it opens.'],
  ready: ['Wallet startup complete', 'Opening your wallet overview.'],
  waiting_for_unlock: ['Waiting for wallet startup', 'Checking your passphrase and preparing to open the wallet.'],
  failed: ['Wallet needs attention', 'Startup could not finish. Keep your wallet data and backups while correcting the problem below.'],
};
function elapsed(seconds: number) {
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}
function gib(bytes: number) {return (bytes / 2 ** 30).toLocaleString(undefined, {maximumFractionDigits: 2});}

export function WalletStartupProgress({failure = null}: {failure?: string | null} = {}) {
  const [status, setStatus] = useState<WalletStartupStatus | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [seconds, setSeconds] = useState(0);
  const [copied, setCopied] = useState('');
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const began = Date.now();
    async function poll() {
      try {
        const next = await getWalletStartupStatus();
        if (!cancelled) {setStatus(next); setUnavailable(next === null);}
      } catch {if (!cancelled) setUnavailable(true);}
      if (!cancelled) {
        setSeconds(Math.floor((Date.now() - began) / 1000));
        timer = setTimeout(() => void poll(), 1000);
      }
    }
    void poll();
    return () => {cancelled = true; clearTimeout(timer);};
  }, []);
  const phase = failure ? 'failed' : status?.phase;
  const [title, detail] = phase ? stages[phase] : ['Starting your wallet', 'Preparing wallet files and saved blockchain history. Startup details will appear here.'];
  const measured = !!status && (phase === 'scanning_history' || phase === 'checking_proofs') && status.total !== null && status.total > 0;
  const percent = measured ? Math.min(100, Math.max(0, Math.floor(status.completed / status.total! * 100))) : undefined;
  const count = measured && status ? phase === 'scanning_history'
    ? `${gib(status.completed)} of ${gib(status.total!)} GiB read`
    : `${status.completed.toLocaleString()} of ${status.total!.toLocaleString()} stored blocks checked` : null;
  async function copyDetails() {
    try {
      await navigator.clipboard.writeText(JSON.stringify({wallet_startup: status, reported_error: failure, status_updates_unavailable: unavailable}, null, 2));
      setCopied('Startup details copied');
    } catch {setCopied('Could not copy startup details. Your wallet log contains more information.');}
  }
  return <section className="wallet-startup-status" aria-label="Wallet startup status">
    <h3 aria-live="polite">{title}</h3>
    <p>{detail}</p>
    {phase !== 'failed' && <div className={`startup-progress${measured ? ' is-measured' : ''}${phase === 'ready' ? ' is-complete' : ''}`} role="progressbar" aria-label="Wallet startup progress"
      aria-valuemin={measured ? 0 : undefined} aria-valuemax={measured ? 100 : undefined} aria-valuenow={percent} aria-valuetext={count || title}>
      <span style={measured ? {width: `${percent}%`} : undefined}/>
    </div>}
    {count && <strong className="startup-count">{count}</strong>}
    <p className="startup-elapsed">Elapsed: {elapsed(status?.elapsed_seconds || seconds)}{measured ? ` · ${percent}% of this step` : ''}</p>
    {phase === 'checking_proofs' && <p className="startup-guidance">Checking history does not send funds. Keep this window open so the checks can finish.</p>}
    {status?.active && status.seconds_since_progress >= 60 && <p className="startup-guidance">No new progress count for {elapsed(status.seconds_since_progress)}. A single check can take time. Copy the startup details if this continues.</p>}
    {unavailable && phase !== 'failed' && <p className="startup-warning" role="status">Live startup details are temporarily unavailable. The wallet may still be working; no completion estimate is available.</p>}
    {status?.available_disk_bytes !== null && status?.available_disk_bytes !== undefined && status.available_disk_bytes < 5 * 2 ** 30 && <p className="startup-warning" role="alert">Low disk space: {gib(status.available_disk_bytes)} GiB free on the wallet drive. Free space to let the wallet save its data. Deleted files may still occupy space in the Recycle Bin or Trash.</p>}
    {(failure || status?.error) && <p className="startup-warning" role="alert">{failure || status?.error?.message}</p>}
    <button className="startup-copy" type="button" onClick={() => void copyDetails()}>Copy startup details</button>
    {copied && <p className="startup-copy-result" role="status">{copied}</p>}
  </section>;
}
