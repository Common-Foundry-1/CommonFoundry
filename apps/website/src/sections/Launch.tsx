import { ButtonLink } from "../components/ButtonLink";
import { MAINNET_LAUNCH_AT, SOURCE_RELEASE_AT, X_URL } from "../content";

export function Launch() {
  return (
    <section id="launch" className="launch section-shell" aria-labelledby="launch-heading">
      <div className="section-heading">
        <p className="launch__eyebrow">The next chapter · Mainnet coming soon</p>
        <h2 id="launch-heading">Two dates. One shared start.</h2>
        <p>Mark your calendar. The announced launch schedule gives everyone 24 hours to inspect the source and prepare before mainnet mining begins.</p>
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
          <h3>Mainnet launch target</h3>
          <time dateTime={MAINNET_LAUNCH_AT}>October 3, 2026</time>
          <p>Noon Central · 12:00 PM CDT · 17:00 UTC</p>
          <p>The planned start of the Common Foundry mainnet. Prepare your wallet, node and supported mining hardware ahead of the shared start.</p>
        </article>
      </div>
      <div className="launch__status">
        <p><strong>Preparing for launch.</strong> Final release checks, independent review and the launch rehearsal remain in progress. Mainnet is not live yet; current RC5 downloads connect to RCNet. This page and our official channels will carry release instructions and any schedule changes.</p>
        <ButtonLink href={X_URL} target="_blank" rel="noopener noreferrer" variant="secondary">Follow launch updates</ButtonLink>
      </div>
    </section>
  );
}
