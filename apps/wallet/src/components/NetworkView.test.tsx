import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { NodeStatus } from "../types";
import { NetworkView } from "./NetworkView";

const peerApi = vi.hoisted(() => ({
  get: vi.fn(),
  update: vi.fn(),
}));

vi.mock("../api/nodeClient", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/nodeClient")>()),
  usesEmbeddedNode: true,
  getPeerSettings: peerApi.get,
  updatePeerSettings: peerApi.update,
}));

const status: NodeStatus = {
  network: "CommonFoundry Devnet-0",
  network_short_name: "Devnet-0",
  network_notice: "Testing network · No monetary value",
  network_purpose: "Community testing",
  network_id: "11".repeat(32),
  consensus_fingerprint: "22".repeat(32),
  proof_profile: "DevnetV2",
  proof_of_work: "ForgeMatrix-v2 tiny full-recompute reference",
  rpc_port: 18443,
  p2p_port: 18444,
  pool_port: 18445,
  node_data_dir_identity: "commonfoundry-devnet0",
  wallet_data_dir_identity: "devnet-0",
  miner_data_dir_identity: "commonfoundry-miner-devnet0",
  bounded_reference_mining: true,
  tip: "33".repeat(32),
  cumulative_work: "00".repeat(64),
  accepted_height: 0,
  next_height: 1,
  expected_target: "00".repeat(32),
  utxo_count: 0,
  mempool_transactions: 0,
  mempool_bytes: 0,
  storage_healthy: true,
  public_peer_mode: true,
  peers: [],
};

afterEach(() => cleanup());

describe("NetworkView", () => {
  const bootstrap = "107.214.187.2:18444";

  beforeEach(() => {
    cleanup();
    peerApi.get.mockReset().mockResolvedValue({
      peers: [bootstrap],
      bootstrap_peer: bootstrap,
      default_peer_port: 18444,
      max_peers: 16,
    });
    peerApi.update.mockReset().mockImplementation(async (peers: string[]) => ({
      peers: peers.map((peer) => peer.includes(":") ? peer : `${peer}:18444`),
      bootstrap_peer: bootstrap,
      default_peer_port: 18444,
      max_peers: 16,
    }));
  });

  it("shows public P2P status without obscuring diagnostics", () => {
    render(
      <NetworkView
        status={status}
        wallet={null}
        mempool={null}
        refreshing={false}
        onRefresh={vi.fn()}
        onNotice={vi.fn()}
      />,
    );

    expect(screen.getByRole("status")).toHaveTextContent(
      "Public Devnet-0 P2P is enabled",
    );
    expect(screen.getByText("No peer sessions observed yet")).toBeInTheDocument();
  });

  it("presents RCNet ProductionV3 ports without exposing the Devnet forge action", () => {
    render(
      <NetworkView
        status={{
          ...status,
          network: "CommonFoundry RCNet-1",
          network_short_name: "RCNet-1",
          network_notice: "Release-candidate rehearsal network · Not mainnet",
          network_purpose: "Launch rehearsal",
          proof_profile: "ProductionV3",
          proof_of_work: "ForgeMatrix-v3 production Dory",
          rpc_port: 19443,
          p2p_port: 19444,
          pool_port: 19445,
          node_data_dir_identity: "commonfoundry-rcnet1",
          wallet_data_dir_identity: "rcnet-1",
          miner_data_dir_identity: "commonfoundry-miner-rcnet1",
          bounded_reference_mining: false,
          public_peer_mode: false,
        }}
        wallet={null}
        mempool={null}
        refreshing={false}
        onRefresh={vi.fn()}
        onNotice={vi.fn()}
      />,
    );

    expect(screen.getAllByText("ProductionV3").length).toBeGreaterThan(0);
    expect(screen.getByText("19443 RPC · 19444 P2P · 19445 pool")).toBeInTheDocument();
    expect(screen.getByText("Production proof path selected")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Forge one block" })).not.toBeInTheDocument();
  });

  it("shows recent peer direction, chain state, session counts, and reachability", () => {
    const now = Math.floor(Date.now() / 1_000);
    render(
      <NetworkView
        status={{
          ...status,
          peers: [
            {
              address: "203.0.113.7",
              direction: "inbound",
              state: "reachable",
              first_seen: now - 120,
              last_seen: now - 8,
              last_success: now - 8,
              successful_sessions: 4,
              failed_sessions: 1,
              active_connections: 0,
              remote_height: 18,
              remote_tip: "44".repeat(32),
            },
          ],
        }}
        wallet={null}
        mempool={null}
        refreshing={false}
        onRefresh={vi.fn()}
        onNotice={vi.fn()}
      />,
    );

    expect(screen.getByText("203.0.113.7")).toBeInTheDocument();
    expect(screen.getByText(/Inbound · first seen/)).toBeInTheDocument();
    expect(screen.getByText("Height 18")).toBeInTheDocument();
    expect(screen.getByText("4 successful")).toBeInTheDocument();
    expect(screen.getByText("1 failed")).toBeInTheDocument();
    expect(screen.getByText("Reachable")).toBeInTheDocument();
  });

  it("adds a peer from a plain IP address and applies it immediately", async () => {
    const user = userEvent.setup();
    const onRefresh = vi.fn();
    const view = render(
      <NetworkView
        status={status}
        wallet={null}
        mempool={null}
        refreshing={false}
        onRefresh={onRefresh}
        onNotice={vi.fn()}
      />,
    );

    const input = await view.findByPlaceholderText("203.0.113.20 or 203.0.113.20:18444");
    await waitFor(() => expect(input).toBeEnabled());
    await user.type(input, "192.168.1.20");
    await user.click(view.getByRole("button", { name: "Add peer" }));

    expect(peerApi.update).toHaveBeenCalledWith([bootstrap, "192.168.1.20"]);
    expect(await view.findByText("192.168.1.20:18444")).toBeInTheDocument();
    expect(onRefresh).toHaveBeenCalledOnce();
  });
});
