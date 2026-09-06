import { Activity, Box, Boxes, Clock3, Database, Network, Pickaxe, Users } from "lucide-react";
import { formatAge, formatAtoms, formatBytes, shortHash } from "../format";
import type { ExplorerBlock, ExplorerSnapshot, ExplorerTransaction } from "../types";
import { ForgeFlow } from "./ForgeFlow";

type OverviewProps = {
  snapshot: ExplorerSnapshot;
  preview: boolean;
  onBlock: (block: ExplorerBlock) => void;
  onTransaction: (transaction: ExplorerTransaction) => void;
};

export function Overview({ snapshot, preview, onBlock, onTransaction }: OverviewProps) {
  const mempool = snapshot.recent_transactions.filter((tx) => tx.status === "mempool");
  return (
    <main>
      {preview && <div className="preview-banner">Preview data · connect a ProductionV4 node for live chain activity</div>}
      <section className="hero">
        <div><p className="eyebrow">ForgeMatrix network intelligence</p><h1>The chain, as it happens.</h1><p>Follow transactions from the mempool to the next forged block.</p></div>
        <div className="hero-mark" aria-hidden="true"><Pickaxe /><span>Proof<br />becomes<br />history.</span></div>
      </section>

      <ForgeFlow mempool={mempool} blocks={snapshot.latest_blocks} />

      <section className="stat-rail" id="network" aria-label="Network statistics">
        <Stat icon={<Box />} label="Chain height" value={snapshot.accepted_height.toLocaleString()} detail={shortHash(snapshot.tip)} />
        <Stat icon={<Activity />} label="Mempool" value={snapshot.mempool_transactions.toLocaleString()} detail={formatBytes(snapshot.mempool_bytes)} />
        <Stat icon={<Users />} label="Connected peers" value={snapshot.connected_peers.toLocaleString()} detail="Live sessions" />
        <Stat icon={<Database />} label="UTXO set" value={snapshot.utxo_count.toLocaleString()} detail="Spendable records" />
        <Stat icon={<Network />} label="Proof profile" value="V4" detail={snapshot.proof_profile} />
      </section>

      <div className="explorer-grid">
        <section className="data-section" id="blocks">
          <div className="section-heading"><div><p className="eyebrow">Canonical history</p><h2>Latest blocks</h2></div><Boxes size={21} /></div>
          <div className="table-scroll"><table><thead><tr><th>Height</th><th>Block</th><th>Age</th><th className="numeric">Transactions</th><th className="numeric">Size</th></tr></thead>
            <tbody>{snapshot.latest_blocks.map((block) => <tr key={block.block_id} onClick={() => onBlock(block)} tabIndex={0} onKeyDown={(event) => event.key === "Enter" && onBlock(block)}>
              <td className="height-cell">#{block.height}</td><td><code>{shortHash(block.block_id, 12, 8)}</code></td><td title={block.accepted_at === undefined ? "Block timestamp; explorer acceptance time is unavailable." : "Time since this explorer node accepted the block."}><Clock3 size={13} /> {formatAge(block.accepted_at ?? block.timestamp)}</td><td className="numeric">{block.transactions}</td><td className="numeric">{formatBytes(block.encoded_bytes)}</td>
            </tr>)}</tbody></table></div>
        </section>

        <section className="data-section transaction-rail" id="transactions">
          <div className="section-heading"><div><p className="eyebrow">Network movement</p><h2>Recent transactions</h2></div><Activity size={21} /></div>
          <div className="transaction-list">{snapshot.recent_transactions.map((transaction) => <button type="button" key={transaction.txid} onClick={() => onTransaction(transaction)}>
            <span className={`status-mark ${transaction.status}`} /><div><code>{shortHash(transaction.txid, 11, 8)}</code><small>{transaction.inputs} inputs → {transaction.outputs} outputs</small></div><span><strong>{formatAtoms(transaction.output_atoms)}</strong><small>{transaction.status === "mempool" ? "In mempool" : transaction.timestamp ? formatAge(transaction.timestamp) : "Confirmed"}</small></span>
          </button>)}</div>
        </section>
      </div>
    </main>
  );
}

function Stat({ icon, label, value, detail }: { icon: React.ReactNode; label: string; value: string; detail: string }) {
  return <div className="stat"><span className="stat-icon">{icon}</span><div><small>{label}</small><strong>{value}</strong><code>{detail}</code></div></div>;
}
