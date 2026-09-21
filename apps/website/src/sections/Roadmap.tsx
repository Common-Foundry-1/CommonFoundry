import { useState } from "react";
import roadmapBackground from "../assets/roadmap-background.png";
import { ButtonLink } from "../components/ButtonLink";
import { ArrowIcon, DocumentIcon, ShieldIcon, XIcon } from "../components/Icons";
import {
  DISCORD_URL,
  GITHUB_URL,
  RELEASE_URL,
  roadmapGates,
  SECURITY_URL,
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
          <h2 id="roadmap-heading">The foundation is built. The opportunity is ahead.</h2>
          <p>RC5 today. Preparing for the October 3 mainnet launch target, with final qualification and independent review still ahead.</p>
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
            <h3>Get ready.<br />Build with the Foundry.</h3>
            <p>
              Miners, developers and long-term supporters: explore the release,
              examine the monetary design and help shape what comes next.
            </p>
          </div>
          <div className="conversion-band__actions">
            <div>
              <ButtonLink
                href={DISCORD_URL}
                target="_blank"
                rel="noopener noreferrer"
              >
                Join the community
              </ButtonLink>
              <ButtonLink
                href={RELEASE_URL}
                target="_blank"
                rel="noopener noreferrer"
                variant="secondary"
              >
                Explore RC5
              </ButtonLink>
            </div>
            <p className="trust-note">
              <ShieldIcon />
              <span>RCNet is a test network, not mainnet. Mainnet launch updates are published above.</span>
            </p>
          </div>
        </div>

        <footer className="site-footer">
          <div className="brand brand--footer">
            <img src="/assets/common-foundry-mark.png" alt="" width="44" height="44" />
            <span>Common Foundry</span>
          </div>
          <nav aria-label="Footer navigation">
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
