import {
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  LayoutDashboard,
  Pickaxe,
} from "lucide-react";
import { usesBrowserKeys } from "../api/transportMode";
import type { ViewName } from "./Sidebar";

interface MobileNavProps {
  active: ViewName;
  onNavigate: (view: ViewName) => void;
  onSend: () => void;
  onReceive: () => void;
}

export function MobileNav({ active, onNavigate, onSend, onReceive }: MobileNavProps) {
  return (
    <nav className="mobile-nav" aria-label="Wallet navigation">
      <button className={active === "overview" ? "is-active" : ""} onClick={() => onNavigate("overview")} type="button">
        <LayoutDashboard aria-hidden="true" size={20} />
        <span>Overview</span>
      </button>
      <button onClick={onSend} type="button">
        <ArrowUpFromLine aria-hidden="true" size={20} />
        <span>Send</span>
      </button>
      <button onClick={onReceive} type="button">
        <ArrowDownToLine aria-hidden="true" size={20} />
        <span>Receive</span>
      </button>
      <button className={active === "transactions" ? "is-active" : ""} onClick={() => onNavigate("transactions")} type="button">
        <Activity aria-hidden="true" size={20} />
        <span>Activity</span>
      </button>
      {usesBrowserKeys ? null : (
        <button className={active === "mining" ? "is-active" : ""} onClick={() => onNavigate("mining")} type="button">
          <Pickaxe aria-hidden="true" size={20} />
          <span>Mining</span>
        </button>
      )}
    </nav>
  );
}
