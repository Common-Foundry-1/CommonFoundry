import { useState } from "react";
import gpuOperator from "../assets/gpu-operator.png";
import { ArrowIcon } from "../components/Icons";
import { DISCORD_URL } from "../content";

type Pathway = "ledger" | "inference";

export function Thesis() {
  const [activePath, setActivePath] = useState<Pathway>("inference");

  return (
    <section id="thesis" className="thesis section-shell" aria-labelledby="thesis-heading">
      <div className="section-heading section-heading--split">
        <div>
          <h2 id="thesis-heading">Open compute. Built by people like you.</h2>
          <p>
            For miners who want to put their hardware to work. For developers
            who want to build open infrastructure. For everyone who believes
            AI compute should have more participants, not fewer gatekeepers.
            There’s a place for you here.
          </p>
        </div>
      </div>

      <div id="technology" className={`thesis__diagram is-${activePath}`}>
        <button
          className="thesis-path thesis-path--ledger"
          type="button"
          aria-pressed={activePath === "ledger"}
          onMouseEnter={() => setActivePath("ledger")}
          onFocus={() => setActivePath("ledger")}
          onClick={() => setActivePath("ledger")}
        >
          <span className="thesis-path__signal" aria-hidden="true">
            {[0, 1, 2, 3, 4].map((item) => <i key={item} />)}
          </span>
          <span className="thesis-path__copy">
            <strong>A GPU-powered foundation</strong>
            <span>
              ForgeMatrix turns GPU matrix computation into verifiable proof
              of work. Nodes check the proof on the CPU: running a node,
              sending and receiving do not require a GPU.
            </span>
          </span>
        </button>

        <div className="operator" aria-label="GPU operator">
          <img
            src={gpuOperator}
            alt="Forged graphite GPU operator apparatus"
            width="1536"
            height="1024"
            loading="lazy"
          />
          <span>GPU operator</span>
        </div>

        <button
          className="thesis-path thesis-path--inference"
          type="button"
          aria-pressed={activePath === "inference"}
          onMouseEnter={() => setActivePath("inference")}
          onFocus={() => setActivePath("inference")}
          onClick={() => setActivePath("inference")}
        >
          <span className="thesis-path__signal thesis-path__signal--stages" aria-hidden="true">
            {[0, 1, 2, 3].map((item) => <i key={item} />)}
          </span>
          <span className="thesis-path__copy">
            <strong>Inference is the direction</strong>
            <span>
              Customer-paid AI inference is the service layer we’re building
              toward. It remains in development and is not part of the initial
              mainnet launch. Help shape it with the community.
            </span>
          </span>
        </button>
      </div>

      <div className="thesis__close">
        <p>Mining secures the chain. Customer inference is a separate service layer.</p>
        <a href={DISCORD_URL} target="_blank" rel="noopener noreferrer">
          <span>Meet the builders in Discord</span>
          <ArrowIcon />
        </a>
      </div>
    </section>
  );
}
