import { useState, type CSSProperties } from "react";
import { ArrowIcon, ProgressGlyph } from "../components/Icons";
import {
  gatedItems,
  implementedItems,
  WHITEPAPER_URL,
  type ProgressItem,
} from "../content";

function ProgressList({
  items,
  tone,
}: {
  items: readonly ProgressItem[];
  tone: "implemented" | "gated";
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
          <h2 id="progress-heading">Research you can run today.</h2>
          <p>
            Devnet-0 turns the protocol thesis into executable software while
            keeping production claims behind explicit gates.
          </p>
        </div>
        <p className="release-line">
          <strong>Current research release</strong>
          <span>·</span>
          <code>v0.1.0-devnet.11</code>
        </p>
      </div>

      <div
        className="progress__instrument"
        style={{
          "--implemented-opacity": leftOpacity,
          "--gated-opacity": rightOpacity,
          "--divider-position": `${emphasis}%`,
        } as CSSProperties}
      >
        <div className="progress__group progress__group--implemented">
          <h3>Implemented now</h3>
          <ProgressList items={implementedItems} tone="implemented" />
        </div>

        <label className="progress__divider">
          <span className="sr-only">Emphasize implemented or gated work</span>
          <input
            type="range"
            min="0"
            max="100"
            value={emphasis}
            onChange={(event) => setEmphasis(Number(event.target.value))}
            aria-valuetext={
              emphasis < 40
                ? "Implemented work emphasized"
                : emphasis > 60
                  ? "Gated work emphasized"
                  : "Both groups equally emphasized"
            }
          />
          <i aria-hidden="true"><span>‹</span><span>›</span></i>
        </label>

        <div className="progress__group progress__group--gated">
          <h3>Still gated</h3>
          <ProgressList items={gatedItems} tone="gated" />
        </div>
      </div>

      <div className="progress__close">
        <p>Proof over promises.</p>
        <a href={WHITEPAPER_URL} target="_blank" rel="noopener noreferrer">
          <span>Read the white paper</span>
          <ArrowIcon />
        </a>
      </div>
    </section>
  );
}
