import { useCallback, useState } from "react";
import { openTransactionInExplorer } from "../api/nodeClient";

/** Opens a transaction on the block explorer in the system browser, and keeps the reason when that fails. */
export function useExplorerLink() {
  const [error, setError] = useState<string | null>(null);
  const open = useCallback((txid: string) => {
    setError(null);
    openTransactionInExplorer(txid).catch((cause: unknown) => {
      setError(cause instanceof Error ? cause.message : "The block explorer could not be opened");
    });
  }, []);
  return { open, error };
}
