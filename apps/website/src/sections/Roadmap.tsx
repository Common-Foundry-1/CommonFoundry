import { useState } from "react";
import roadmapBackground from "../assets/roadmap-background.png";
import { ButtonLink } from "../components/ButtonLink";
import { ArrowIcon, DocumentIcon, ShieldIcon, XIcon } from "../components/Icons";
import {
  DISCORD_URL,
  EXPLORER_URL,
  GITHUB_URL,
  MAINNET_RELEASE_URL,
  roadmapGates,
  SECURITY_URL,
  WALLET_URL,
  WHITEPAPER_URL,
  X_URL,
} from "../content";

export function Roadmap() {
  const [expandedGate, setExpandedGate] = useState<string | null>(null);

  return (
    <section id="roadmap" className="roadmap" aria-labelledby="roadmap-heading">
      <img
        className="roadmap__background"
        src={roadmapBackground}
        alt=""
        width="1672"
        height="941"
        loading="lazy"
      />
      <div className="roadmap__content section-shell">
        <div className="section-heading">
          <h2 id="roadmap-heading">Be part of the next chapter.</h2>
          <p>A live mainnet today. A longer-term mission to bring more people into open GPU compute.</p>
        </div>

        <ol className="roadmap__rail">
          {roadmapGates.map((gate) => {
            const isExpanded = expandedGate === gate.number;
            return (
              <li key={gate.number} className={`is-${gate.phase}`}>
                <button
                  type="button"
                  aria-expanded={isExpanded}
                  aria-controls={`gate-${gate.number}`}
                  onClick={() => setExpandedGate(isExpanded ? null : gate.number)}
                >
                  <span className="roadmap__number">{gate.number}</span>
                  <span className="roadmap__node" aria-hidden="true" />
                  <strong>{gate.title}</strong>
                </button>
                <p id={`gate-${gate.number}`} hidden={!isExpanded}>{gate.detail}</p>
              </li>
            );
          })}
        </ol>

        <div className="conversion-band">
          <div>
            <h3>Start in Discord.<br />We’ll help from there.</h3>
            <p>
              You don’t need a rig or a finished setup to join. Tell us whether
              you want to mine, build or learn. Get guidance from the team and
              community, and follow the official release announcements.
            </p>
          </div>
          <div className="conversion-band__actions">
            <div>
              <ButtonLink
                href={DISCORD_URL}
                target="_blank"
                rel="noopener noreferrer"
              >
                Join Discord
              </ButtonLink>
              <ButtonLink
                href={WHITEPAPER_URL}
                target="_blank"
                rel="noopener noreferrer"
                variant="secondary"
              >
                Read the white paper
              </ButtonLink>
            </div>
            <p className="trust-note">
              <ShieldIcon />
              <span>Setup help · Hardware guidance · Release updates</span>
            </p>
          </div>
        </div>

        <footer className="site-footer">
          <div className="brand brand--footer">
            <img src="/assets/common-foundry-mark.png" alt="" width="44" height="44" />
            <span>Common Foundry</span>
          </div>
          <nav aria-label="Footer navigation">
            <a href={DISCORD_URL} target="_blank" rel="noopener noreferrer"><span>Discord</span><ArrowIcon /></a>
            <a href={MAINNET_RELEASE_URL} target="_blank" rel="noopener noreferrer"><span>Mainnet downloads</span><ArrowIcon /></a>
            <a href={EXPLORER_URL} target="_blank" rel="noopener noreferrer"><span>Explorer</span><ArrowIcon /></a>
            <a href={WALLET_URL} target="_blank" rel="noopener noreferrer"><span>Web wallet</span><ArrowIcon /></a>
            <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer"><span>GitHub</span><ArrowIcon /></a>
            <a href={WHITEPAPER_URL} target="_blank" rel="noopener noreferrer"><DocumentIcon /><span>White paper</span></a>
            <a href={SECURITY_URL} target="_blank" rel="noopener noreferrer"><ShieldIcon /><span>Security</span></a>
            <a href={X_URL} target="_blank" rel="noopener noreferrer"><XIcon /><span>X @CommonFoundry1</span></a>
          </nav>
          <p>Open compute. Verifiable work. A maker-built GPU economy.</p>
        </footer>
      </div>
    </section>
  );
}
