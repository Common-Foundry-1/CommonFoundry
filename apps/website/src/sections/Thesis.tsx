import { useState } from "react";
import gpuOperator from "../assets/gpu-operator.png";
import { ArrowIcon } from "../components/Icons";

type Pathway = "ledger" | "inference";

export function Thesis() {
  const [activePath, setActivePath] = useState<Pathway>("ledger");

  return (
    <section id="thesis" className="thesis section-shell" aria-labelledby="thesis-heading">
      <div className="section-heading section-heading--split">
        <div>
          <h2 id="thesis-heading">The case for Common Foundry.</h2>
          <p>
            A distinctive proof system. Monetary rules you can inspect. A
            community built around consumer GPUs. The long-term thesis combines
            verifiable network security with an open-compute ecosystem, starting
            with a working release candidate.
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
            <strong>Secure the ledger</strong>
            <span>
              ForgeMatrix proves a 384-layer matrix computation. Its transparent
              BaseFold-based proof needs no trusted setup; nodes verify the
              committed work independently instead of trusting the miner.
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
            <strong>Build toward open inference</strong>
            <span>
              The next economic layer is customer-paid GPU inference with
              prepaid settlement channels. This is a separate development path,
              not a claim that mining already serves customer AI jobs.
            </span>
          </span>
        </button>
      </div>

      <div className="thesis__close">
        <p>One hardware base. Distinct roles for consensus and customer compute.</p>
        <a href="#technology">
          <span>Explore the architecture</span>
          <ArrowIcon />
        </a>
      </div>
    </section>
  );
}
