import brandMark from "../assets/common-foundry-mark.png";

export function StartupScreen() {
  return (
    <main className="startup-screen" aria-labelledby="startup-title">
      <section className="startup-card" role="status" aria-live="polite">
        <img className="startup-mark" src={brandMark} alt="" />
        <span className="startup-eyebrow">Common Foundry Wallet</span>
        <h1 id="startup-title">Opening your wallet</h1>
        <p className="startup-message">
          Authenticating proof inputs and replaying local chain history.
        </p>
        <div
          className="startup-progress"
          role="progressbar"
          aria-label="Wallet startup progress"
          aria-valuetext="Authenticating and loading"
        >
          <span />
        </div>
        <p className="startup-note">
          Your wallet is working. A larger testnet history can take a few minutes on its first load.
        </p>
      </section>
    </main>
  );
}
