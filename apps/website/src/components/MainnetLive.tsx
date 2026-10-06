import { EXPLORER_URL, MAINNET_FIRST_BLOCK_AT, MAINNET_LAUNCH_AT, WALLET_URL } from "../content";
import { BurnCounter } from "./BurnCounter";

export function MainnetLive() {
  return (
    <div className="mainnet-countdown" aria-labelledby="mainnet-live-heading">
      <div className="mainnet-countdown__intro">
        <span className="mainnet-countdown__eyebrow">Mainnet is live</span>
        <h2 id="mainnet-live-heading">Mining since <time dateTime={MAINNET_LAUNCH_AT}>October 3, 2026</time></h2>
        <p>
          Started on schedule at 17:00 UTC · first block <time dateTime={MAINNET_FIRST_BLOCK_AT}>17:06 UTC</time>
        </p>
        <p className="mainnet-countdown__source">
          <a href={EXPLORER_URL} target="_blank" rel="noopener noreferrer">Block explorer</a>
          {" · "}
          <a href={WALLET_URL} target="_blank" rel="noopener noreferrer">Web wallet</a>
        </p>
      </div>
      <BurnCounter />
    </div>
  );
}
