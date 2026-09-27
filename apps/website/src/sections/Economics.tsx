import { useState } from "react";
import { ArrowIcon, FlameIcon, ShieldIcon } from "../components/Icons";
import { EMISSION_URL } from "../content";
import {
  emissionAtHeight,
  formatCmfd,
  heightToYear,
  INITIAL_EMISSION_BLOCKS,
  TAIL_HEIGHT,
} from "../economics";

const allocationDetails = {
  miners: "Secures the network by aligning rewards with verifiable work.",
  steward: "Funds protocol stewardship, review, and long-term maintenance.",
  community: "Supports public goods, grants, and ecosystem growth.",
} as const;

type Allocation = keyof typeof allocationDetails;

export function Economics() {
  const [height, setHeight] = useState(1_314_000);
  const [allocation, setAllocation] = useState<Allocation>("miners");
  const atomicSubsidy = emissionAtHeight(height);
  const year = heightToYear(height);
  const isTail = BigInt(height) >= TAIL_HEIGHT;
  const decliningRatio = Math.min(
    1,
    Math.max(0, (height - 1) / Number(INITIAL_EMISSION_BLOCKS)),
  );
  const markerX = isTail ? 790 : 70 + decliningRatio * 650;
  const markerY = isTail ? 237 : 35 + decliningRatio * 205;

  return (
    <section id="economics" className="economics section-shell" aria-labelledby="economics-heading">
      <div className="section-heading">
        <h2 id="economics-heading">CMFD. Earned through work.</h2>
        <p>
          No premine. No token sale. CMFD is issued through mining under an
          explicit reward schedule, with declining issuance, burned transaction
          fees and a permanent miner-only tail. A monetary model built to
          support the network for the long term.
        </p>
      </div>

      <div className="economics__instrument">
        <div className="emission-chart">
          <h3>Scheduled block subsidy</h3>
          <svg viewBox="0 0 1000 310" role="img" aria-labelledby="chart-title chart-desc">
            <title id="chart-title">Common Foundry scheduled block subsidy</title>
            <desc id="chart-desc">
              A decline over 2,628,000 blocks, about five years at the target block spacing, from 500 CMFD per block, followed by a permanent 5 CMFD miner tail.
            </desc>
            <g className="chart-grid">
              <path d="M70 35H950M70 138H950M70 240H950" />
              {[0, 1, 2, 3, 4, 5].map((yearNumber) => {
                const x = 70 + yearNumber * 130;
                return <path key={yearNumber} d={`M${x} 35V240`} />;
              })}
            </g>
            <path className="chart-decline" d="M70 35 720 240" />
            <path className="chart-tail" d="M720 240V238H950" />
            <g className="chart-axis-labels">
              <text x="5" y="41">500 CMFD</text>
              <text x="5" y="144">250 CMFD</text>
              <text x="25" y="246">0 CMFD</text>
              {[0, 1, 2, 3, 4, 5].map((yearNumber) => (
                <text key={yearNumber} x={70 + yearNumber * 130} y="275" textAnchor="middle">
                  Year {yearNumber}
                </text>
              ))}
              <text x="900" y="275" textAnchor="middle">Tail</text>
            </g>
            <g className="chart-annotations">
              <text x="70" y="298">Block 1 · 500 CMFD</text>
              <text x="720" y="18" textAnchor="middle">Block 2,628,001 · Year 5</text>
              <text x="850" y="221">5 CMFD miner tail</text>
            </g>
            <circle className="chart-marker" cx={markerX} cy={markerY} r="8" />
          </svg>

          <div className="emission-control">
            <output htmlFor="emission-height">
              <strong>{isTail ? "Tail" : `Year ${year.toFixed(1)}`}</strong>
              <span>
                Block {height.toLocaleString("en-US")} · {formatCmfd(atomicSubsidy)} CMFD per block
              </span>
            </output>
            <input
              id="emission-height"
              type="range"
              min="1"
              max={Number(TAIL_HEIGHT)}
              value={height}
              onChange={(event) => setHeight(Number(event.target.value))}
              aria-label="Block height"
              aria-valuetext={`Block ${height.toLocaleString("en-US")}, ${formatCmfd(atomicSubsidy)} CMFD per block`}
            />
            <div className="emission-control__labels" aria-hidden="true">
              <span>Year 0</span>
              <span>Year 5</span>
              <span>Tail</span>
            </div>
          </div>
        </div>

        <div className="allocation">
          <h3>Bootstrap allocation</h3>
          <div className="allocation__bar">
            <button
              className={allocation === "miners" ? "is-active" : ""}
              type="button"
              style={{ flexBasis: "70%" }}
              aria-pressed={allocation === "miners"}
              onClick={() => setAllocation("miners")}
            >
              <strong>70%</strong><span>miners</span>
            </button>
            <button
              className={allocation === "steward" ? "is-active" : ""}
              type="button"
              style={{ flexBasis: "25%" }}
              aria-pressed={allocation === "steward"}
              onClick={() => setAllocation("steward")}
            >
              <strong>25%</strong><span>steward</span>
            </button>
            <button
              className={allocation === "community" ? "is-active" : ""}
              type="button"
              style={{ flexBasis: "5%" }}
              aria-pressed={allocation === "community"}
              onClick={() => setAllocation("community")}
            >
              <strong>5%</strong><span>community</span>
            </button>
          </div>
          <p className="allocation__detail" aria-live="polite">
            {allocationDetails[allocation]}
          </p>
        </div>

        <aside className="economics__disclosures" aria-label="Economic disclosures">
          <p><FlameIcon /><span>Transaction fees are burned, not paid to miners. The planned mainnet minimum is 0.1 CMFD per transaction.</span></p>
          <p><ShieldIcon /><span>The 25% stewardship and 5% community allocations end with the bootstrap; the permanent 5 CMFD tail goes only to miners.</span></p>
          <p className="economics__plain"><span>The schedule is defined by block height. Years are approximate at the target block spacing.</span></p>
          <p className="economics__plain"><span>The tail is perpetual, not a hard supply cap. Net supply depends on issuance and actual fee burning.</span></p>
          <a href={EMISSION_URL} target="_blank" rel="noopener noreferrer">
            <span>Inspect the emission rules</span>
            <ArrowIcon />
          </a>
        </aside>
      </div>
    </section>
  );
}
