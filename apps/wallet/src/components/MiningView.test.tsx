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
const runningStatus: MiningStatus = {
  ...stoppedStatus,
  lifecycle: "running",
  mode: "solo",
  payout,
  engine: "cuda",
  device: "NVIDIA GeForce RTX 4090 (CUDA 8.9)",
  matrix_attempts_per_second: 42.25,
  session_attempts: 2_500,
  blocks_found: 1,
  current_height: 129,
  last_block: { height: 129, block_id: "44".repeat(32) },
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

describe("MiningView", () => {
  beforeEach(() => {
    apiMocks.getMiningStatus.mockReset().mockResolvedValue(stoppedStatus);
    apiMocks.startMining.mockReset().mockResolvedValue(runningStatus);
    apiMocks.stopMining.mockReset().mockResolvedValue(stoppedStatus);
  });

  afterEach(() => cleanup());

  it("starts and stops the continuous solo reference miner", async () => {
    const user = userEvent.setup();
    render(<MiningView wallet={wallet} nodeStatus={nodeStatus} />);

    expect(await screen.findByText("matrix attempts/s")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Start Solo Mining" }));
    expect(apiMocks.startMining).toHaveBeenCalledWith({ mode: "solo", payout });
    expect(await screen.findByRole("button", { name: "Stop Mining" })).toBeEnabled();
    expect(screen.getByText("42.25")).toBeInTheDocument();
    expect(screen.getByText("CUDA INT8 matrix engine")).toBeInTheDocument();
    expect(screen.getAllByText("NVIDIA GeForce RTX 4090 (CUDA 8.9)").length).toBeGreaterThan(0);
    expect(screen.getByText(/Rust recomputes every candidate before submission/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Stop Mining" }));
    await waitFor(() => expect(apiMocks.stopMining).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole("button", { name: "Start Solo Mining" })).toBeEnabled();
  });

  it("validates Pool configuration before enabling start", async () => {
    const user = userEvent.setup();
    render(<MiningView wallet={wallet} nodeStatus={nodeStatus} />);
    await screen.findByRole("button", { name: "Start Solo Mining" });

    await user.click(screen.getByRole("button", { name: "Pool" }));
    const urlInput = screen.getByRole("textbox", { name: /Pool URL/i });
    const workerInput = screen.getByRole("textbox", { name: /Worker name/i });
    const startButton = screen.getByRole("button", { name: "Start Pool Mining" });
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
    apiMocks.startMining.mockResolvedValueOnce(runningPoolStatus);
    render(<MiningView wallet={wallet} nodeStatus={nodeStatus} />);
    await screen.findByRole("button", { name: "Start Solo Mining" });

    await user.click(screen.getByRole("button", { name: "Pool" }));
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
    expect(screen.getByText(/Pool credits are session statistics for testing/i)).toBeInTheDocument();
    expect(screen.getByText(/payouts are not enabled yet/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Solo" })).toBeDisabled();
    expect(urlInput).toBeDisabled();
    expect(workerInput).toBeDisabled();
  });

  it("does not present a completed Pool session as Solo work", async () => {
    const user = userEvent.setup();
    apiMocks.startMining.mockResolvedValueOnce(runningPoolStatus);
    apiMocks.stopMining.mockResolvedValueOnce({
      ...runningPoolStatus,
      lifecycle: "stopped",
      mode: null,
      pool_connected: false,
    });
    render(<MiningView wallet={wallet} nodeStatus={nodeStatus} />);
    await screen.findByRole("button", { name: "Start Solo Mining" });

    await user.click(screen.getByRole("button", { name: "Pool" }));
    await user.type(screen.getByRole("textbox", { name: /Pool URL/i }), poolUrl);
    await user.type(screen.getByRole("textbox", { name: /Worker name/i }), "foundry.worker-1");
    await user.click(screen.getByRole("button", { name: "Start Pool Mining" }));
    await user.click(await screen.findByRole("button", { name: "Stop Mining" }));
    await screen.findByRole("button", { name: "Start Pool Mining" });

    await user.click(screen.getByRole("button", { name: "Solo" }));

    expect(screen.getByText("Session attempts").parentElement).toHaveTextContent("0");
    expect(screen.getByText("Blocks found").parentElement).toHaveTextContent("0");
    expect(screen.getByText("Current height").parentElement).toHaveTextContent("128");
    expect(screen.queryByText("4,321")).not.toBeInTheDocument();
    expect(screen.queryByText("130")).not.toBeInTheDocument();
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
    expect(screen.getByRole("button", { name: "Solo" })).toBeDisabled();

    await user.click(stopButton);
    await waitFor(() => expect(apiMocks.stopMining).toHaveBeenCalledTimes(1));
  });

  it("states the reference-engine, maturity, fee-burn, and hardware boundaries", async () => {
    render(<MiningView wallet={wallet} nodeStatus={nodeStatus} />);
    expect(await screen.findByText("CPU reference engine")).toBeInTheDocument();
    expect(screen.getByText("100-block maturity")).toBeInTheDocument();
    expect(screen.getByText("Transaction fees are burned")).toBeInTheDocument();
    expect(screen.getByText(/no GPU-use or VRAM-residency claim/)).toBeInTheDocument();
  });
});
