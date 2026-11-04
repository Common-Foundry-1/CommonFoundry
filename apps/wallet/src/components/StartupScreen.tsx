import brandMark from "../assets/common-foundry-mark.png";
import {WalletStartupProgress} from './WalletStartupProgress';

export function StartupScreen() {
  return (
    <main className="startup-screen" aria-labelledby="startup-title">
      <section className="startup-card">
        <img className="startup-mark" src={brandMark} alt="" />
        <span className="startup-eyebrow">Common Foundry Wallet</span>
        <h1 id="startup-title">Opening your wallet</h1>
        <WalletStartupProgress />
      </section>
    </main>
  );
}
