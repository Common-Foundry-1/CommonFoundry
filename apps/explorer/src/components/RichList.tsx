import { ArrowLeft, CheckCircle2 } from "lucide-react";
import { formatAtoms, shortHash } from "../format";
import type { RichList as RichListData } from "../types";

/** A balance's share of the total supply, to two decimals. */
export function supplyShare(balanceAtoms: string, totalAtoms: string): string {
  const total = BigInt(totalAtoms);
  if (total === 0n) return "—";
  const basisPoints = (BigInt(balanceAtoms) * 10_000n + total / 2n) / total;
  return `${basisPoints / 100n}.${(basisPoints % 100n).toString().padStart(2, "0")}%`;
}

const LABELS: Record<string, string> = { "steward fund": "Steward fund", "community fund": "Community fund" };

export function RichList({ list, onBack, onAddress }: { list: RichListData; onBack: () => void; onAddress: (address: string) => void }) {
  return <main className="detail-main richlist-main">
    <button className="back-button" type="button" onClick={onBack}><ArrowLeft size={15} /> Explorer overview</button>
    <section className="detail-hero"><div><p className="eyebrow">Mainnet holders</p><h1>Rich list</h1><p>Largest balances as of block #{list.height.toLocaleString()} · {list.addresses_with_balance.toLocaleString()} addresses hold CMFD</p></div><span className="verified"><CheckCircle2 /> Matches the node's supply</span></section>
    <section className="data-section richlist-section" aria-label="Largest balances">
      <div className="section-heading"><div><p className="eyebrow">Top {list.top.length}</p><h2>Balances</h2></div><span>Total supply {formatAtoms(list.total_supply_atoms)}</span></div>
      <div className="richlist-scroll"><table className="richlist-table">
        <thead><tr><th scope="col">#</th><th scope="col">Address</th><th scope="col">Balance</th><th scope="col">Share</th></tr></thead>
        <tbody>{list.top.map((entry) => <tr key={entry.address}>
          <td>{entry.rank}</td>
          <td><button type="button" className="address-record-link" onClick={() => onAddress(entry.address)} aria-label={`Open address ${entry.address}`}><code>{shortHash(entry.address, 14, 10)}</code></button>{entry.label && <span className="richlist-label">{LABELS[entry.label] ?? entry.label}</span>}</td>
          <td><strong>{formatAtoms(entry.balance_atoms)}</strong><small>{entry.outputs.toLocaleString()} output{entry.outputs === 1 ? "" : "s"}</small></td>
          <td>{supplyShare(entry.balance_atoms, list.total_supply_atoms)}</td>
        </tr>)}</tbody>
      </table></div>
    </section>
    <p className="address-scope">A balance is the value of an address's unspent outputs, including coinbase rewards that are not spendable yet. The list is rebuilt from every block and published only when it matches the node's own output-set total; it can trail the tip by a minute or two.</p>
  </main>;
}
