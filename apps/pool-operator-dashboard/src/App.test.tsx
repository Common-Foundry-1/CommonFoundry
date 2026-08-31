import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import type { OperatorStatus } from "./types";

const status: OperatorStatus = {
  ok: true,
  generated_at_unix_seconds: 1_788_000_000,
  platform: "windows",
  operator_bind: "127.0.0.1:22448",
  action_busy: false,
  pool: {
    running: true,
    pid: 14268,
    uptime_seconds: 5_122,
    dashboard_url: "http://127.0.0.1:22446/",
    dashboard_healthy: true,
    dashboard_error: null,
    log_file: "C:\\pool\\pool-data\\logs\\pool.log",
  },
  settings: {
    public_numeric_address: "107.214.187.2",
    private_bind_address: "192.168.68.32",
    pool_port: 22445,
    p2p_bind: "0.0.0.0:22444",
    dashboard_bind: "127.0.0.1:22446",
    operator_fee_bps: 300,
    pplns_window_shares: 0,
  },
  snapshot: {
    public_pool_url: `cmfd+tls://107.214.187.2:22445?pin=${"ab".repeat(32)}`,
    certificate_sha256: "ab".repeat(32),
    pool: {
      generated_at_unix_seconds: 1_788_000_000,
      network_name: "CommonFoundry ProductionV4 Testnet-1",
      network_short_name: "ProductionV4 Testnet-1",
      accepted_height: 561,
      active_connections: 2,
      active_share_verifications: 1,
      queued_share_verifications: 0,
      operator_fee_bps: 300,
      configured_pplns_window_shares: null,
      effective_pplns_window_shares: 128,
      reported_work_rate_fw_per_second: 3.25,
      reported_average_work_rate_fw_per_second: 3.1,
      credited_atoms_last_24h: 130_000_000,
      estimated_24h_credited_atoms: 260_000_000,
      earnings_observation_seconds: 43_200,
      workers: [
        { worker: "forge-5090", connected: true, accepted_shares: 120, rejected_shares: 1, stale_shares: 1, reported_work_rate_fw_per_second: 2, reported_average_work_rate_fw_per_second: 1.9, earned_atoms_last_24h: 90_000_000, estimated_24h_earnings_atoms: 160_000_000 },
        { worker: "rig-5070ti", connected: true, accepted_shares: 90, rejected_shares: 0, stale_shares: 0, reported_work_rate_fw_per_second: 1.25, reported_average_work_rate_fw_per_second: 1.2, earned_atoms_last_24h: 40_000_000, estimated_24h_earnings_atoms: 100_000_000 },
      ],
      ledger: {
        accepted_shares: 210,
        rejected_shares: 1,
        stale_shares: 1,
        pool_blocks: 4,
        operator_fee_atoms: 4020618,
        pplns_pending_blocks: 1,
        pplns_distributed_blocks: 3,
        blocks: [],
        payout_transactions: [],
      },
    },
  },
  paths: {
    data_directory: "C:\\pool\\pool-data",
    settings_file: "C:\\pool\\pool-data\\pool-control\\pool-settings.json",
  },
  events: [
    { time_unix_seconds: 1_788_000_000, event: "Operator console started", details: "Listening on 127.0.0.1:22448", source: "Console" },
  ],
};

function installFetchMock() {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path.endsWith("/session")) {
      return new Response(JSON.stringify({ ok: true, csrf_token: "test-token" }), { status: 200 });
    }
    if (path.endsWith("/status")) {
      return new Response(JSON.stringify(status), { status: 200 });
    }
    if (path.endsWith("/log")) {
      return new Response(JSON.stringify({ ok: true, path: "C:\\pool\\pool.log", text: "pool ready" }), { status: 200 });
    }
    if (init?.method === "POST") {
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    return new Response(JSON.stringify({ ok: false, error: "not found" }), { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("pool operator console", () => {
  it("renders live process, accounting, and local-boundary data", async () => {
    installFetchMock();
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Pool Operator Console" })).toBeVisible();
    expect(screen.getByText("PID 14268 · uptime 1h 25m 22s")).toBeVisible();
    expect(screen.getByText("210")).toBeVisible();
    expect(screen.getByText("Operator access never leaves this machine.")).toBeVisible();
    expect(screen.getByDisplayValue("3.00")).toBeVisible();
  });

  it("requires confirmation before a graceful stop", async () => {
    const fetchMock = installFetchMock();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("heading", { name: "Pool Operator Console" });

    await user.click(screen.getByRole("button", { name: "Stop gracefully" }));
    expect(screen.getByText("Stop the pool?")).toBeVisible();
    expect(fetchMock.mock.calls.some(([path]) => String(path).endsWith("/action/stop"))).toBe(false);

    await user.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([path]) => String(path).endsWith("/action/stop"))).toBe(true));
  });

  it("saves future economics with the CSRF token", async () => {
    const fetchMock = installFetchMock();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("heading", { name: "Pool Operator Console" });

    const fee = screen.getByLabelText("Operator fee");
    await user.clear(fee);
    await user.type(fee, "2.50");
    await user.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() => {
      const request = fetchMock.mock.calls.find(([path]) => String(path).endsWith("/settings"));
      expect(request).toBeDefined();
      expect(request?.[1]?.headers).toMatchObject({ "X-CMFD-Operator-CSRF": "test-token" });
      expect(JSON.parse(String(request?.[1]?.body))).toEqual({ operator_fee_bps: 250, pplns_window_shares: 0 });
    });
  });

  it("opens the latest runtime log inside the console", async () => {
    installFetchMock();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("heading", { name: "Pool Operator Console" });

    await user.click(screen.getByRole("button", { name: /view latest log/i }));
    expect(await screen.findByText("pool ready")).toBeVisible();
  });
});
