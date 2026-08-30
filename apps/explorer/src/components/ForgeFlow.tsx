import { memo, useState } from "react";
import { Box, Pause, Play } from "lucide-react";
import hammer from "../assets/forge-hammer.png";
import anvil from "../assets/forge-anvil.png";
import { shortHash } from "../format";
import type { ExplorerBlock, ExplorerTransaction } from "../types";

type ForgeFlowProps = {
  mempool: ExplorerTransaction[];
  blocks: ExplorerBlock[];
};

export const ForgeFlow = memo(function ForgeFlow({ mempool, blocks }: ForgeFlowProps) {
  const [paused, setPaused] = useState(false);
  const newest = blocks[0];
  const queue = mempool.length ? mempool : [
    { txid: "Awaiting the next transaction", output_atoms: "0", status: "mempool" as const },
  ];

  return (
    <section className={`forge-flow ${paused ? "is-paused" : ""}`} aria-label="Live transaction forging visualization">
      <div className="forge-head">
        <div><span className="eyebrow">Live protocol view</span><h2>From intent to immutable history.</h2></div>
        <button type="button" className="pause-button" onClick={() => setPaused((value) => !value)}>
          {paused ? <Play size={15} /> : <Pause size={15} />} {paused ? "Resume" : "Pause"}
        </button>
      </div>

      <div className="forge-stage">
        <div className="flow-zone mempool-zone">
          <div className="zone-label"><span>Mempool</span><small>{mempool.length} waiting</small></div>
          <div className="transaction-stack">
            {queue.slice(0, 3).map((transaction, index) => (
              <div className={`transaction-chip chip-${index + 1}`} key={transaction.txid}>
                <span className="flow-node" />
                <div><small>Transaction</small><code>{shortHash(transaction.txid, 8, 6)}</code></div>
              </div>
            ))}
          </div>
          <div className="flow-rail"><span /><span /><span /></div>
        </div>

        <div className="flow-zone forge-zone">
          <div className="zone-label"><span>Forge</span><small>Proof-bound</small></div>
          <div className="forge-machine" aria-hidden="true">
            <div className="hammer-wrap"><img className="hammer" src={hammer} alt="" /></div>
            <div className="impact"><i /><i /><i /><i /></div>
            <div className="block-blank"><Box size={22} /><span>{newest ? `#${newest.height}` : "Next"}</span></div>
            <img className="anvil" src={anvil} alt="" />
          </div>
          <div className="forge-caption"><strong>Challenge + proof</strong><span>Consensus makes every accepted block independently verifiable.</span></div>
        </div>

        <div className="flow-zone chain-zone">
          <div className="zone-label"><span>Canonical chain</span><small>{blocks.length ? "Live" : "Waiting"}</small></div>
          <div className="block-chain">
            {blocks.slice(0, 3).map((block, index) => (
              <div className={`chain-block block-${index + 1}`} key={block.block_id}>
                <Box size={18} />
                <div><strong>Block #{block.height}</strong><code>{shortHash(block.block_id, 7, 5)}</code></div>
                <span>{block.transactions} tx</span>
              </div>
            ))}
          </div>
          <div className="chain-line" />
        </div>
      </div>
    </section>
  );
});
