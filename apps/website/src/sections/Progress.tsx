import { useState, type CSSProperties } from "react";
import { ArrowIcon, ProgressGlyph } from "../components/Icons";
import {
  implementedItems,
  nextItems,
  DISCORD_URL,
  MAINNET_RELEASE_VERSION,
  type ProgressItem,
} from "../content";

function ProgressList({
  items,
  tone,
}: {
  items: readonly ProgressItem[];
  tone: "implemented" | "next";
}) {
  return (
    <ul className={`progress-list progress-list--${tone}`}>
      {items.map((item) => (
        <li key={item.label}>
          <span className="progress-list__icon">
            <ProgressGlyph kind={item.icon} />
          </span>
          <span>{item.label}</span>
          <i aria-hidden="true" />
        </li>
      ))}
    </ul>
  );
}

export function Progress() {
  const [emphasis, setEmphasis] = useState(50);
  const leftOpacity = 0.48 + ((100 - emphasis) / 100) * 0.52;
  const rightOpacity = 0.48 + (emphasis / 100) * 0.52;

  return (
    <section id="progress" className="progress section-shell" aria-labelledby="progress-heading">
      <div className="section-heading progress__heading">
        <div>
          <h2 id="progress-heading">Built to run. Running on mainnet.</h2>
          <p>
            Wallets, transfers, GPU mining and node synchronization run on
            mainnet today, with the public explorer and the web wallet
            alongside. Join Discord for the current status and the right setup
            for your machine.
          </p>
        </div>
        <p className="release-line">
          <strong>Mainnet release</strong>
          <span>·</span>
          <code>{MAINNET_RELEASE_VERSION}</code>
        </p>
      </div>

      <div
        className="progress__instrument"
        style={{
          "--implemented-opacity": leftOpacity,
          "--next-opacity": rightOpacity,
          "--divider-position": `${emphasis}%`,
        } as CSSProperties}
      >
        <div className="progress__group progress__group--implemented">
          <h3>Built and tested</h3>
          <ProgressList items={implementedItems} tone="implemented" />
        </div>

        <label className="progress__divider">
          <span className="sr-only">Emphasize achievements or next milestones</span>
          <input
            type="range"
            min="0"
            max="100"
            value={emphasis}
            onChange={(event) => setEmphasis(Number(event.target.value))}
            aria-valuetext={
              emphasis < 40
                ? "Tested capabilities emphasized"
                : emphasis > 60
                  ? "Next milestones emphasized"
                  : "Both groups equally emphasized"
            }
          />
          <i aria-hidden="true"><span>‹</span><span>›</span></i>
        </label>

        <div className="progress__group progress__group--next">
          <h3>Coming next</h3>
          <ProgressList items={nextItems} tone="next" />
        </div>
      </div>

      <div className="progress__close">
        <p>Not sure where to start? We’ll help you find the next step.</p>
        <a href={DISCORD_URL} target="_blank" rel="noopener noreferrer">
          <span>Get setup help in Discord</span>
          <ArrowIcon />
        </a>
      </div>
    </section>
  );
}
