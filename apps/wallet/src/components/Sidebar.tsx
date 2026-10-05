import {
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  Blocks,
  LayoutDashboard,
  Pickaxe,
  Settings,
} from "lucide-react";
import { usesBrowserKeys } from "../api/transportMode";
import mark from "../assets/common-foundry-mark.png";

export type ViewName = "overview" | "transactions" | "mining" | "network";

interface SidebarProps {
  active: ViewName;
  onNavigate: (view: ViewName) => void;
  onSend: () => void;
  onReceive: () => void;
  networkName: string;
  networkPurpose: string;
}

const NAV_ITEMS = [
  { id: "overview" as const, label: "Overview", icon: LayoutDashboard },
  { id: "send" as const, label: "Send", icon: ArrowUpFromLine },
  { id: "receive" as const, label: "Receive", icon: ArrowDownToLine },
  { id: "transactions" as const, label: "Transactions", icon: Activity },
  { id: "mining" as const, label: "Mining", icon: Pickaxe },
  { id: "network" as const, label: "Network", icon: Blocks },
].filter(({ id }) => !usesBrowserKeys || (id !== "mining" && id !== "network"));

export function Sidebar({
  active,
  onNavigate,
  onSend,
  onReceive,
  networkName,
  networkPurpose,
}: SidebarProps) {
  const activate = (id: (typeof NAV_ITEMS)[number]["id"]) => {
    if (id === "send") onSend();
    else if (id === "receive") onReceive();
    else onNavigate(id);
  };

  return (
    <aside className="sidebar">
      <div className="brand-lockup">
        <img className="brand-mark" src={mark} alt="" />
        <div>
          <span className="brand-name">Common Foundry</span>
          <span className="brand-product">Wallet</span>
        </div>
      </div>

      <nav className="side-nav" aria-label="Wallet navigation">
        {NAV_ITEMS.map(({ id, label, icon: Icon }) => {
          const selected = id === active;
          return (
            <button
              className={`nav-item${selected ? " is-active" : ""}`}
              type="button"
              key={id}
              aria-current={selected ? "page" : undefined}
              onClick={() => activate(id)}
            >
              <Icon aria-hidden="true" size={18} strokeWidth={1.8} />
              <span>{label}</span>
            </button>
          );
        })}
      </nav>

      {usesBrowserKeys ? null : (
        <button className="sidebar-settings" type="button" onClick={() => onNavigate("network")}>
          <Settings aria-hidden="true" size={17} />
          Settings
        </button>
      )}
      <div className="sidebar-network">
        <span className="network-dot" />
        <div>
          <strong>{networkName}</strong>
          <span>{networkPurpose}</span>
        </div>
      </div>
    </aside>
  );
}
