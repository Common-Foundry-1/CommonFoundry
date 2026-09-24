import { ButtonLink } from "../components/ButtonLink";
import { DISCORD_URL, MAINNET_LAUNCH_AT, SOURCE_RELEASE_AT } from "../content";

export function Launch() {
  return (
    <section id="launch" className="launch section-shell" aria-labelledby="launch-heading">
      <div className="section-heading">
        <p className="launch__eyebrow">Join before launch · Mainnet coming soon</p>
        <h2 id="launch-heading">Two dates. One shared start.</h2>
        <p>Get ready together. Source and launch packages are planned 24 hours before mining begins, giving everyone the same preparation window.</p>
      </div>
      <div className="launch__dates">
        <article>
          <span className="launch__step">01 / PREPARE</span>
          <h3>Source &amp; launch packages</h3>
          <time dateTime={SOURCE_RELEASE_AT}>October 2, 2026</time>
          <p>Noon Central · 12:00 PM CDT · 17:00 UTC</p>
          <p>Planned public source and matching Windows/Linux packages, with release notes, checksums and setup instructions.</p>
        </article>
        <article>
          <span className="launch__step">02 / LAUNCH</span>
          <h3>Mainnet mining begins</h3>
          <time dateTime={MAINNET_LAUNCH_AT}>October 3, 2026</time>
          <p>Noon Central · 12:00 PM CDT · 17:00 UTC</p>
          <p>The planned start of the Common Foundry mainnet. Prepare your wallet, node and supported mining hardware ahead of the shared start.</p>
        </article>
      </div>
      <div className="launch__status">
        <p><strong>Preparing for launch.</strong> Mainnet is not live yet. Final package and deployment checks are in progress; current downloads connect to RCNet. Discord is the place for release instructions, setup help and any schedule changes.</p>
        <ButtonLink href={DISCORD_URL} target="_blank" rel="noopener noreferrer">Get launch-ready in Discord</ButtonLink>
      </div>
    </section>
  );
}
