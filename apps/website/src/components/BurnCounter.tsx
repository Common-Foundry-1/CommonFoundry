import { useEffect, useState } from "react";
import { CMFD_USD_PRICE, SUPPLY_API_URL } from "../content";
import { ATOMIC_UNITS_PER_CMFD, formatCmfd } from "../economics";

const REFRESH_MS = 60_000;

interface Burn {
  atoms: bigint;
  height: number;
}

export function burnedUsd(atoms: bigint, price: number = CMFD_USD_PRICE): string {
  return ((Number(atoms) / Number(ATOMIC_UNITS_PER_CMFD)) * price)
    .toLocaleString("en-US", { style: "currency", currency: "USD" });
}

async function loadBurn(signal: AbortSignal): Promise<Burn | null> {
  const response = await fetch(SUPPLY_API_URL, { signal });
  if (!response.ok) return null;
  const body: unknown = await response.json();
  const fields = typeof body === "object" && body !== null ? body as Record<string, unknown> : {};
  const atoms = fields.burned_fees_atoms;
  if (typeof atoms !== "string" || !/^(0|[1-9][0-9]{0,30})$/.test(atoms) || !Number.isSafeInteger(fields.height)) {
    return null;
  }
  return { atoms: BigInt(atoms), height: fields.height as number };
}

/** Every transaction fee is destroyed; this shows the running total from the explorer. */
export function BurnCounter() {
  const [burn, setBurn] = useState<Burn | null>(null);

  useEffect(() => {
    let controller = new AbortController();
    const refresh = () => {
      controller.abort();
      controller = new AbortController();
      loadBurn(controller.signal).then((next) => { if (next) setBurn(next); }).catch(() => undefined);
    };
    refresh();
    const timer = window.setInterval(refresh, REFRESH_MS);
    return () => {
      window.clearInterval(timer);
      controller.abort();
    };
  }, []);

  return (
    <div className="burn-counter" aria-labelledby="burn-counter-heading">
      <p id="burn-counter-heading" className="mainnet-countdown__eyebrow">Fees burned</p>
      <div className="burn-counter__figures">
        <div className="mainnet-countdown__unit">
          <strong>{burn ? formatCmfd(burn.atoms) : "—"}</strong>
          <span>CMFD burned</span>
        </div>
        <div className="mainnet-countdown__unit">
          <strong>{burn ? burnedUsd(burn.atoms) : "—"}</strong>
          <span>USD value</span>
        </div>
      </div>
      <p className="burn-counter__note">
        Every transaction fee is destroyed, not paid to miners. Valued at ${CMFD_USD_PRICE} per CMFD
        {burn ? ` · block ${burn.height.toLocaleString("en-US")}` : ""}.
      </p>
    </div>
  );
}
