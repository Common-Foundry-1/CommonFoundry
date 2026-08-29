import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import type { DashboardDocument } from "./types";

const fixture: DashboardDocument = {
  public_pool_url: `cmfd+tls://107.214.187.2:22445?pin=${"ab".repeat(32)}`,
  certificate_sha256: "ab".repeat(32),
  refresh_interval_seconds: 60,
  pool: {
    generated_at_unix_seconds: 1_788_000_000,
    network_name: "ProductionV4 Testnet-1",
    network_short_name: "Devnet-16",
    network_notice: "Test network",
    proof_profile: "production-v4",
    accepted_height: 212,
    tip: "12".repeat(32),
    current_job_id: "34".repeat(32),
    share_target: "ff".repeat(32),
    active_connections: 2,
    connection_capacity: 64,
    max_connections_per_source: 4,
    active_share_verifications: 1,
    queued_share_verifications: 0,
    share_verification_capacity: 2,
    share_verification_queue_capacity: 8,
    automatic_testnet_payouts: true,
    minimum_payout_atoms: 100_000_000,
    payout_fee_atoms: 1_000,
    workers: [
      {
        worker: "rig-02",
        payout: "56".repeat(32),
        connected: true,
        accepted_shares: 4,
        rejected_shares: 0,
        pool_blocks: 0,
        credited_devnet_atoms: 40_000_000,
      },
      {
        worker: "rig-01",
        payout: "78".repeat(32),
        connected: true,
        accepted_shares: 9,
        rejected_shares: 1,
        pool_blocks: 1,
        credited_devnet_atoms: 90_000_000,
      },
    ],
    ledger: {
      accounting_semantics: "durable accepted shares",
      persistence: "durable",
      accepted_shares: 13,
      rejected_shares: 1,
      pool_blocks: 1,
      credited_devnet_atoms: 130_000_000,
      canonical_pool_blocks: 1,
      orphaned_pool_blocks: 0,
      sessions: [],
      payouts: [],
      blocks: [
        {
          block_id: "90".repeat(32),
          parent: "80".repeat(32),
          height: 211,
          payout: "78".repeat(32),
          state: "canonical",
          confirmations: 2,
        },
      ],
      payout_transactions: [],
    },
  },
};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("pool dashboard", () => {
  it("renders live pool totals and worker data", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(fixture), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    render(<App />);

    expect(await screen.findByRole("heading", { name: "ForgeMatrix Pool" })).toBeVisible();
    expect(screen.getByText("13")).toBeVisible();
    expect(screen.getByText("rig-01")).toBeVisible();
    expect(screen.getByText("rig-02")).toBeVisible();
    expect(screen.getByText("Height 212")).toBeVisible();
  });

  it("sorts the worker table by name", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(JSON.stringify(fixture), { status: 200 })),
    );
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("rig-01");

    await user.click(screen.getByRole("button", { name: "Worker" }));

    const workersSection = screen.getByRole("heading", { name: "Workers" }).closest("section");
    expect(workersSection).not.toBeNull();
    const rows = within(workersSection!).getAllByRole("row");
    expect(rows[1]).toHaveTextContent("rig-01");
    expect(rows[2]).toHaveTextContent("rig-02");
  });

  it("offers a retry when the pool API is unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("offline", { status: 503 })));
    render(<App />);

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Pool status is temporarily unavailable" })).toBeVisible();
    });
    expect(screen.getByRole("button", { name: /retry/i })).toBeEnabled();
  });
});
