import { RefreshCw, ShieldCheck } from "lucide-react";

import { PAUSED_ON_BATTERY_COPY, type WorkCheckView, workCheckView } from "../lib/workCheck";
import type { NodeStatus } from "../types";

interface WorkCheckNoticeProps {
  status: NodeStatus | null;
  onResync: () => void;
}

function ResyncButton({ onResync }: { onResync: () => void }) {
  return (
    <button className="button-secondary compact" type="button" onClick={onResync}>
      <RefreshCw aria-hidden="true" size={16} />
      Resync chain
    </button>
  );
}

type CatchUpView = Extract<
  WorkCheckView,
  { kind: "release_stale" | "single_source" | "catching_up" | "checking_newest" | "waiting_for_check" }
>;

/** The line for a catch-up state; N is always the node's own count. */
function catchUpLine(view: CatchUpView): string {
  switch (view.kind) {
    case "catching_up":
      return "Catching up with the network. Recent coins show as Verifying until the newest blocks are checked.";
    case "checking_newest":
      return `Checking the newest blocks on this computer: ${view.newestChecked.toLocaleString()} of ${view.newestNeeded.toLocaleString()}.`;
    case "single_source":
      return "Fast catch-up needs two Common Foundry relays, and fewer can be reached now. Every block is checked here, which is slower.";
    case "release_stale":
      return "Update the wallet for fast catch-up. Every block is checked here, which is slower.";
    case "waiting_for_check": {
      const line = view.reason === "earlier_blocks"
        ? `Earlier stored blocks are checked first: ${view.blocksLeft.toLocaleString()} left.`
        : `Recent blocks need a full check before coins are available: ${view.blocksLeft.toLocaleString()} left.`;
      return view.paused ? `${line} ${PAUSED_ON_BATTERY_COPY}` : line;
    }
  }
}

/**
 * What the wallet's block check is doing, while it is not simply caught up:
 * the node re-executes each block's work before it accepts the block.
 */
export function WorkCheckNotice({ status, onResync }: WorkCheckNoticeProps) {
  const view = workCheckView(status);

  if (view.kind === "halted") {
    return (
      <div className="offline-banner work-check-banner" role="alert">
        <div>
          <strong>Block checks are stopped</strong>
          <span>
            The wallet found a block on its chain whose work does not match, and it accepts no new blocks.
            Your keys stay safe; coins in blocks not checked yet may change once the chain is synced again.
            Resync the chain to download it again from other nodes.
          </span>
        </div>
        <ResyncButton onResync={onResync} />
      </div>
    );
  }
  if (view.kind === "held") {
    const height = view.height.toLocaleString();
    const after = view.blocksAfter === 0
      ? ""
      : view.blocksAfter === 1
        ? " and in the block after it"
        : ` and in the ${view.blocksAfter.toLocaleString()} blocks after it`;
    return (
      <div className="offline-banner work-check-banner" role="alert">
        <div>
          <strong>A stored block did not pass the check</strong>
          <span>
            The work of block {height} did not match when this computer checked it, so coins in it{after} stay
            Verifying. The wallet checks it again later.
          </span>
          <span>
            Resync the chain to set the stored blocks aside and download them again from other nodes; the
            wallet key stays. If the wallet stops at the same block again, keep it open, report block {height}
            {view.blockId ? <>, whose id begins <code>{view.blockId.slice(0, 16)}</code>,</> : null} and update
            the wallet when a new version is out.
          </span>
        </div>
        <ResyncButton onResync={onResync} />
      </div>
    );
  }
  if (view.kind === "failed") {
    return (
      <div className="offline-banner work-check-banner" role="alert">
        <div>
          <strong>Block checks are unavailable</strong>
          <span>
            The wallet could not run its block check on this computer, so it accepts no new blocks for now.
            It tries again on its own; if this stays, reopen the wallet or reinstall the wallet package.
          </span>
        </div>
      </div>
    );
  }
  if (view.kind === "none") return null;
  if (
    view.kind === "release_stale"
    || view.kind === "single_source"
    || view.kind === "catching_up"
    || view.kind === "checking_newest"
    || view.kind === "waiting_for_check"
  ) {
    return (
      <div className="work-check-banner work-check-progress" role="status">
        <ShieldCheck aria-hidden="true" size={17} />
        <div>
          <strong>{catchUpLine(view)}</strong>
        </div>
      </div>
    );
  }

  // Catching up (Standard mode), coins do not wait for this count, so the
  // line says only that older blocks are still checked.
  const heading = view.kind === "preparing"
    ? "Preparing the block check"
    : view.catchUp
      ? `Older blocks are checked in the background: ${view.blocksLeft.toLocaleString()} left`
      : view.paused
        ? `Block check paused on battery · ${view.blocksLeft.toLocaleString()} left`
        : `Checking blocks · ${view.blocksLeft.toLocaleString()} left`;
  const detail = view.kind === "preparing"
    ? "The wallet tests its block check before it accepts new blocks. This usually takes under a minute."
    : view.catchUp
      ? (view.paused ? PAUSED_ON_BATTERY_COPY : null)
      : view.paused
        ? "The wallet checks the blocks it stored once this computer is plugged in. New blocks are still checked as they arrive. Coins in blocks not checked yet show as Verifying."
        : "The wallet re-executes the work of each block it stored. Coins in blocks not checked yet show as Verifying and can be sent once those blocks are checked.";
  return (
    <div className="work-check-banner work-check-progress" role="status">
      <ShieldCheck aria-hidden="true" size={17} />
      <div>
        <strong>{heading}</strong>
        {detail ? <span>{detail}</span> : null}
      </div>
    </div>
  );
}
