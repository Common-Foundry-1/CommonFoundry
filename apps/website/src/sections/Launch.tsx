import { ButtonLink } from "../components/ButtonLink";
import { DISCORD_URL, MAINNET_LAUNCH_AT, MAINNET_POOL_URL, MAINNET_RELEASE_KEY_FINGERPRINT, MAINNET_RELEASE_KEY_URL, MAINNET_RELEASE_URL, MAINNET_SEED_PEER, MINING_GUIDE_URL, SOURCE_RELEASE_AT } from "../content";

export function Launch() {
  return (
    <section id="launch" className="launch section-shell" aria-labelledby="launch-heading">
      <div className="section-heading">
        <p className="launch__eyebrow">Join before launch · Mainnet coming soon</p>
        <h2 id="launch-heading">Two dates. One shared start.</h2>
        <p>Get ready together. Source and launch packages were released 24 hours before the scheduled mining start.</p>
      </div>
      <div className="launch__dates">
        <article>
          <span className="launch__step">01 / PREPARE</span>
          <h3>Source &amp; launch packages</h3>
          <time dateTime={SOURCE_RELEASE_AT}>October 2, 2026</time>
          <p>Noon Central · 12:00 PM CDT · 17:00 UTC</p>
          <p>Public source and matching launch packages, with release notes, checksums and setup instructions.</p>
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
        <p><strong>Prelaunch setup is open.</strong> Mainnet is not live yet. The signed mainnet packages are available; the pool port is staged to open after the verified launch beacon. The existing pool dashboard still shows RCNet. Check Discord for operational updates and any schedule changes.</p>
        <ButtonLink href={MAINNET_RELEASE_URL} target="_blank" rel="noopener noreferrer">Get mainnet v1.0.0 packages</ButtonLink>
        <ButtonLink href={DISCORD_URL} target="_blank" rel="noopener noreferrer">Get launch-ready in Discord</ButtonLink>
      </div>
      <aside id="pool-setup" className="launch__pool-setup" aria-labelledby="pool-setup-heading">
        <p className="launch__eyebrow">Mainnet · Configure before launch</p>
        <h3 id="pool-setup-heading">Official pool connection</h3>
        <p>Enter the complete certificate-pinned URL in your mainnet pool miner, along with your mainnet wallet address and worker name:</p>
        <code className="launch__pool-url">{MAINNET_POOL_URL}</code>
        <p>The pool address and certificate pin match the pool host's configured values. The mainnet pool is not accepting connections before activation; a live miner connection will be checked after it opens.</p>
        <p>Running your own node? The released node uses <code>{MAINNET_SEED_PEER}</code> as its default bootstrap peer. This is separate from the mining pool.</p>
        <p className="launch__guide-note">The current pool.commonfoundry.ai dashboard shows RCNet. Do not use its RCNet pool URL for mainnet.</p>
      </aside>
      <article id="mining-guide" className="launch__guide" aria-labelledby="mining-guide-heading">
        <aside className="launch__pool-update" aria-labelledby="pool-update-heading">
          <p className="launch__eyebrow">Pool operators · Setup update</p>
          <h3 id="pool-update-heading">Running your own pool? Fresh-install setup fix</h3>
          <p>Setting up a new mainnet pool on a host that never ran an RC pool? Use the updated launcher so you do not need hashes of old key or wallet files that do not exist.</p>
          <ButtonLink href="https://github.com/Common-Foundry-1/CommonFoundry/blob/366054828601557e7f53becff508db83d6af2a34/packaging/mainnet/linux/POOL-LAUNCHER-UPDATE.md" target="_blank" rel="noopener noreferrer">Pool setup fix &amp; installation steps</ButtonLink>
          <p className="launch__guide-note">For pool operators only—not ordinary solo miners or miners connecting to a pool. Separate source patch; signed v1.0.0 packages and the launch schedule are unchanged. Existing RC migrations retain their safeguards.</p>
        </aside>
        <p className="launch__eyebrow">Beginner guide · Available now</p>
        <h3 id="mining-guide-heading">Windows &amp; Linux mining guide</h3>
        <p>One easy-to-follow guide for both operating systems, including terminal-only Linux and rented GPUs. Learn wallet setup, safe downloads, pool mining, keeping an SSH session running, and troubleshooting.</p>
        <p className="launch__guide-meta">10 pages · PDF · 113 KB · Mainnet v1.0.0</p>
        <div className="launch__guide-actions">
          <ButtonLink href={MINING_GUIDE_URL} target="_blank" rel="noopener noreferrer">Read mining guide (PDF)</ButtonLink>
          <ButtonLink href={MINING_GUIDE_URL} download variant="secondary">Download PDF</ButtonLink>
        </div>
        <p className="launch__guide-note">Read the guide and prepare with the released mainnet software now. Mining is scheduled for October 3 at noon Central. Need a hand? <a href={DISCORD_URL} target="_blank" rel="noopener noreferrer">Ask in Discord.</a></p>
      </article>
      <div className="launch__trust">
        <h3>Mainnet release verification key</h3>
        <p>Compare this fingerprint with the policy in the published source before trusting a mainnet download. The release includes verification instructions, signatures and checksums.</p>
        <code>{MAINNET_RELEASE_KEY_FINGERPRINT}</code>
        <a href={MAINNET_RELEASE_KEY_URL}>View the public release key</a>
      </div>
    </section>
  );
}
