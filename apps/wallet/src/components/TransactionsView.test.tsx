import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { useAutoConsolidation } from "../hooks/useAutoConsolidation";
import type { WalletSnapshot } from "../types";
import { TransactionsView } from "./TransactionsView";

describe("Transactions automatic consolidation control", () => {
  it("shows the fee policy and saves the selected threshold", async () => {
    const setSettings = vi.fn();
    const autoConsolidation = {
      available: true,
      settings: { enabled: false, threshold: 64 },
      setSettings,
      busy: false,
      error: null,
      reason: "Waiting for 64 spendable outputs.",
      coolingDown: false,
      waitingForBlock: false,
    } as ReturnType<typeof useAutoConsolidation>;
    const wallet = { spendable_utxo_count: 12, immature_utxo_count: 4,
      reserved_utxo_count: 0, history: [] } as unknown as WalletSnapshot;
    const user = userEvent.setup();

    const view = render(<TransactionsView wallet={wallet} mempool={null} onConsolidate={vi.fn()}
      autoConsolidation={autoConsolidation} />);
    expect(screen.getByText(/Each batch burns 0.1 CMFD/)).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "Automatic consolidation" }));
    expect(setSettings).toHaveBeenCalledWith({ enabled: true, threshold: 64 });

    view.rerender(<TransactionsView wallet={wallet} mempool={null} onConsolidate={vi.fn()}
      autoConsolidation={{ ...autoConsolidation, settings: { enabled: true, threshold: 64 } }} />);
    await user.selectOptions(screen.getByRole("combobox", { name: "Start at" }), "128");
    expect(setSettings).toHaveBeenLastCalledWith({ enabled: true, threshold: 128 });
  });
});
