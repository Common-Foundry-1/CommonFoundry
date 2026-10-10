import { useEffect, useState } from "react";
import { PRICE_API_URL, SUPPLY_API_URL } from "../content";
import { ATOMIC_UNITS_PER_CMFD, formatCmfd } from "../economics";

const REFRESH_MS = 60_000;

interface Burn {
  atoms: bigint;
  height: number;
}

export function burnedUsd(atoms: bigint, price: number): string {
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

/** The last CMFD/USDT trade on TidoEx as a positive decimal, or null. */
async function loadPrice(signal: AbortSignal): Promise<string | null> {
  const response = await fetch(PRICE_API_URL, { signal });
  if (!response.ok) return null;
  const body: unknown = await response.json();
  const price = typeof body === "object" && body !== null ? (body as Record<string, unknown>).last_price : undefined;
  return typeof price === "string" && /^[0-9]{1,16}(\.[0-9]{1,18})?$/.test(price) && Number(price) > 0 ? price : null;
}

/** Every transaction fee is destroyed; this shows the running total from the explorer. */
export function BurnCounter() {
  const [burn, setBurn] = useState<Burn | null>(null);
  const [price, setPrice] = useState<string | null>(null);

  useEffect(() => {
    let controller = new AbortController();
    const refresh = () => {
      controller.abort();
      controller = new AbortController();
      loadBurn(controller.signal).then((next) => { if (next) setBurn(next); }).catch(() => undefined);
      loadPrice(controller.signal).then((next) => { if (next) setPrice(next); }).catch(() => undefined);
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
          <strong>{burn && price ? burnedUsd(burn.atoms, Number(price)) : "—"}</strong>
          <span>USD value</span>
        </div>
      </div>
      <p className="burn-counter__note">
        Every transaction fee is destroyed, not paid to miners.
        {price ? ` Valued at $${price} per CMFD, the last CMFD/USDT trade on TidoEx.` : ""}
        {burn ? ` As of block ${burn.height.toLocaleString("en-US")}.` : ""}
      </p>
    </div>
  );
}
