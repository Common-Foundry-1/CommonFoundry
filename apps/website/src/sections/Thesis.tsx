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
          <h2 id="thesis-heading">One hardware base. Two economic roles.</h2>
          <p>
            Common Foundry separates consensus work from customer inference so
            each can do one job well.
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
              ForgeMatrix uses deterministic, matrix-heavy work to order blocks
              and secure UTXO settlement.
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
            <strong>Serve inference</strong>
            <span>
              GPU providers can separately accept customer jobs and settle
              progressive payments through prepaid channels.
            </span>
          </span>
        </button>
      </div>

      <div className="thesis__close">
        <p>Consensus stays deterministic. Inference stays market-driven.</p>
        <a href="#technology">
          <span>Explore the architecture</span>
          <ArrowIcon />
        </a>
      </div>
    </section>
  );
}
