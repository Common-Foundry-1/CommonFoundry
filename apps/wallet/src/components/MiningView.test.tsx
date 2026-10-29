import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MiningStatus } from "../mining/types";
import type { NodeStatus, WalletSnapshot } from "../types";
import { MiningView } from "./MiningView";

const apiMocks = vi.hoisted(() => ({
  getMiningStatus: vi.fn(),
  startMining: vi.fn(),
  stopMining: vi.fn(),
}));

vi.mock("../api/miningClient", () => apiMocks);

const payout = "1d16453b3ab3132acb0a5bc16cc49690d819a585267a15cd5a064e2a0ad40599";
const stoppedStatus: MiningStatus = {
  lifecycle: "stopped",
  mode: null,
  payout: null,
  pool_url: null,
  worker_name: null,
  engine: "cpu",
  device: null,
  matrix_attempts_per_second: 0,
  session_attempts: 0,
  blocks_found: 0,
  shares_accepted: 0,
  shares_rejected: 0,
  credited_atoms: "0",
  pool_connected: false,
  current_height: 128,
  last_block: null,
  last_error: null,
};
const poolUrl = `cmfd+tls://192.168.50.20:443?pin=${"ab".repeat(32)}`;
const runningPoolStatus: MiningStatus = {
  ...stoppedStatus,
  lifecycle: "running",
  mode: "pool",
  payout,
  pool_url: poolUrl,
  worker_name: "foundry.worker-1",
  engine: "cuda",
  device: "NVIDIA GeForce RTX 4090 (CUDA 8.9)",
  matrix_attempts_per_second: 19.375,
  session_attempts: 4_321,
  blocks_found: 2,
  shares_accepted: 73,
  shares_rejected: 4,
  credited_atoms: "1234567",
  pool_connected: true,
  current_height: 130,
};
const wallet = { destination: payout } as WalletSnapshot;
const nodeStatus = {
  accepted_height: 128,
  network_short_name: "Devnet-0",
  proof_profile: "DevnetV2",
  proof_of_work: "ForgeMatrix-v2 tiny full-recompute reference",
  bounded_reference_mining: true,
} as NodeStatus;
const productionV4NodeStatus = {
  ...nodeStatus,
  network_short_name: "ProductionV4 Testnet-1",
  proof_profile: "ProductionV4",
  proof_of_work: "ForgeMatrix-v4 transparent BaseFold",
  bounded_reference_mining: false,
} as NodeStatus;

describe("MiningView", () => {
  beforeEach(() => {
    apiMocks.getMiningStatus.mockReset().mockResolvedValue(stoppedStatus);
    apiMocks.startMining.mockReset().mockResolvedValue(runningPoolStatus);
    apiMocks.stopMining.mockReset().mockResolvedValue(stoppedStatus);
  });

  afterEach(() => cleanup());

  it("offers Pool mining only", async () => {
    render(<MiningView wallet={wallet} nodeStatus={nodeStatus} />);

    expect(await screen.findByRole("button", { name: "Start Pool Mining" })).toBeDisabled();
    expect(screen.getByRole("heading", { name: "Pool mining" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Solo" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pool" })).not.toBeInTheDocument();
    expect(screen.queryByText(/solo/i)).not.toBeInTheDocument();
  });

  it("validates Pool configuration before enabling start", async () => {
    const user = userEvent.setup();
    render(<MiningView wallet={wallet} nodeStatus={nodeStatus} />);
    const startButton = await screen.findByRole("button", { name: "Start Pool Mining" });

    const urlInput = screen.getByRole("textbox", { name: /Pool URL/i });
    const workerInput = screen.getByRole("textbox", { name: /Worker name/i });
    expect(screen.getByText(/CMFD-specific TLS job\/share protocol/)).toBeInTheDocument();
    expect(startButton).toBeDisabled();

    await user.type(urlInput, `cmfd+tls://pool.example:443?pin=${"ab".repeat(32)}`);
    await user.type(workerInput, "worker name");
    expect(urlInput).toHaveAttribute("aria-invalid", "true");
    expect(workerInput).toHaveAttribute("aria-invalid", "true");
    expect(startButton).toBeDisabled();
    expect(apiMocks.startMining).not.toHaveBeenCalled();
  });

  it("starts Pool mining with the exact config and renders session accounting", async () => {
    const user = userEvent.setup();
    render(<MiningView wallet={wallet} nodeStatus={nodeStatus} />);
    await screen.findByRole("button", { name: "Start Pool Mining" });

    const urlInput = screen.getByRole("textbox", { name: /Pool URL/i });
    const workerInput = screen.getByRole("textbox", { name: /Worker name/i });
    await user.type(urlInput, poolUrl);
    await user.type(workerInput, "foundry.worker-1");

    const startButton = screen.getByRole("button", { name: "Start Pool Mining" });
    expect(startButton).toBeEnabled();
    await user.click(startButton);
    expect(apiMocks.startMining).toHaveBeenCalledWith({
      mode: "pool",
      payout,
      pool_url: poolUrl,
      worker_name: "foundry.worker-1",
    });

    expect(await screen.findByRole("button", { name: "Stop Mining" })).toBeEnabled();
    expect(screen.getByText("19.38")).toBeInTheDocument();
    expect(screen.getByText("Accepted shares")).toBeInTheDocument();
    expect(screen.getByText("73")).toBeInTheDocument();
    expect(screen.getByText("Rejected shares")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
    expect(screen.getByText("Pool blocks")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("Credited Devnet-0 atoms")).toBeInTheDocument();
    expect(screen.getByText("1,234,567")).toBeInTheDocument();
    expect(screen.getByText("Connected")).toBeInTheDocument();
    expect(screen.getByText("Session attempts")).toBeInTheDocument();
    expect(screen.getByText("4,321")).toBeInTheDocument();
    expect(screen.getByText("Pool height")).toBeInTheDocument();
    expect(screen.getByText("130")).toBeInTheDocument();
    expect(screen.getByText("Mining with pool")).toBeInTheDocument();
    expect(urlInput).toBeDisabled();
    expect(workerInput).toBeDisabled();
  });

  it("enables the server-verified ProductionV4 pool path", async () => {
    const user = userEvent.setup();
    render(<MiningView wallet={wallet} nodeStatus={productionV4NodeStatus} />);
    await screen.findByRole("button", { name: "Start Pool Mining" });

    await user.type(screen.getByRole("textbox", { name: /Pool URL/i }), poolUrl);
    await user.type(screen.getByRole("textbox", { name: /Worker name/i }), "v4-worker");

    expect(screen.getByRole("button", { name: "Start Pool Mining" })).toBeEnabled();
    expect(screen.getByText("CUDA ProductionV4 pool search")).toBeInTheDocument();
    expect(screen.getByText(/persistent batched CUDA/)).toBeInTheDocument();
  });

  it("can stop while an unreachable Pool remains in the starting lifecycle", async () => {
    const user = userEvent.setup();
    apiMocks.getMiningStatus.mockResolvedValue({
      ...runningPoolStatus,
      lifecycle: "starting",
      pool_connected: false,
      last_error: "Pool connection lost; retrying",
    });
    render(<MiningView wallet={wallet} nodeStatus={nodeStatus} />);

    const stopButton = await screen.findByRole("button", { name: "Stop Mining" });
    expect(stopButton).toBeEnabled();
    expect(screen.getByRole("textbox", { name: /Pool URL/i })).toBeDisabled();

    await user.click(stopButton);
    await waitFor(() => expect(apiMocks.stopMining).toHaveBeenCalledTimes(1));
  });

  it("states the reference-engine, maturity, and fee-burn behavior", async () => {
    render(<MiningView wallet={wallet} nodeStatus={nodeStatus} />);
    expect(await screen.findByText("CPU reference engine")).toBeInTheDocument();
    expect(screen.getByText("100-block maturity")).toBeInTheDocument();
    expect(screen.getByText("Transaction fees are burned")).toBeInTheDocument();
  });
});
