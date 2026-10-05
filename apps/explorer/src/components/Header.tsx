import { Activity, Menu, Search, X } from "lucide-react";
import { useState, type FormEvent } from "react";
import mark from "../assets/common-foundry-mark.png";
import type { ExplorerSearchKind } from "../types";

type HeaderProps = {
  network: string;
  connected: boolean;
  onHome: () => void;
  onSearch: (query: string, kind: ExplorerSearchKind) => void;
};

export function Header({ network, connected, onHome, onSearch }: HeaderProps) {
  const [query, setQuery] = useState("");
  const [searchKind, setSearchKind] = useState<ExplorerSearchKind>("chain");
  const [mobileOpen, setMobileOpen] = useState(false);
  const home = () => { setMobileOpen(false); onHome(); };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const value = query.trim();
    if (value) { setMobileOpen(false); onSearch(value, searchKind); }
  };

  return (
    <header className="topbar">
      <button className="brand" type="button" onClick={home} aria-label="Explorer overview">
        <img src={mark} alt="" />
        <span><strong>Common Foundry</strong><small>Explorer</small></span>
      </button>

      <button className="mobile-menu" type="button" onClick={() => setMobileOpen((open) => !open)} aria-label="Toggle navigation">
        {mobileOpen ? <X size={19} /> : <Menu size={19} />}
      </button>
      <nav className={mobileOpen ? "is-open" : ""} aria-label="Explorer navigation">
        <button type="button" onClick={home}>Overview</button>
        <a href="#blocks" onClick={() => setMobileOpen(false)}>Blocks</a>
        <a href="#transactions" onClick={() => setMobileOpen(false)}>Transactions</a>
        <a href="#network" onClick={() => setMobileOpen(false)}>Network</a>
        <a href="https://wallet.commonfoundry.ai" target="_blank" rel="noopener noreferrer">Wallet</a>
      </nav>

      <form className="search-form" role="search" onSubmit={submit}>
        <select aria-label="Search type" value={searchKind} onChange={(event) => setSearchKind(event.target.value === "address" ? "address" : "chain")}>
          <option value="chain">Block / TX</option><option value="address">Address</option>
        </select>
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={searchKind === "address" ? "Wallet address" : "Height or hash"} aria-label={searchKind === "address" ? "Search wallet address" : "Search block height, block hash, or transaction ID"} />
        <button type="submit" aria-label="Search"><Search size={17} aria-hidden="true" /></button>
      </form>

      <div className={`network-state ${connected ? "connected" : ""}`} title={network}>
        <Activity size={15} aria-hidden="true" />
        <span>{network}</span>
      </div>
    </header>
  );
}
