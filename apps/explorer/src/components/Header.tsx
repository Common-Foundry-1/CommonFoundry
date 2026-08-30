import { Activity, Menu, Search, X } from "lucide-react";
import { useState, type FormEvent } from "react";
import mark from "../assets/common-foundry-mark.png";

type HeaderProps = {
  network: string;
  connected: boolean;
  onHome: () => void;
  onSearch: (query: string) => void;
};

export function Header({ network, connected, onHome, onSearch }: HeaderProps) {
  const [query, setQuery] = useState("");
  const [mobileOpen, setMobileOpen] = useState(false);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const value = query.trim();
    if (value) onSearch(value);
  };

  return (
    <header className="topbar">
      <button className="brand" type="button" onClick={onHome} aria-label="Explorer overview">
        <img src={mark} alt="" />
        <span><strong>Common Foundry</strong><small>Explorer</small></span>
      </button>

      <button className="mobile-menu" type="button" onClick={() => setMobileOpen((open) => !open)} aria-label="Toggle navigation">
        {mobileOpen ? <X size={19} /> : <Menu size={19} />}
      </button>
      <nav className={mobileOpen ? "is-open" : ""} aria-label="Explorer navigation">
        <button type="button" onClick={onHome}>Overview</button>
        <a href="#blocks">Blocks</a>
        <a href="#transactions">Transactions</a>
        <a href="#network">Network</a>
      </nav>

      <form className="search-form" role="search" onSubmit={submit}>
        <Search size={16} aria-hidden="true" />
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search block or transaction" aria-label="Search block height, block hash, or transaction ID" />
        <kbd>↵</kbd>
      </form>

      <div className={`network-state ${connected ? "connected" : ""}`} title={network}>
        <Activity size={15} aria-hidden="true" />
        <span>{network}</span>
      </div>
    </header>
  );
}
