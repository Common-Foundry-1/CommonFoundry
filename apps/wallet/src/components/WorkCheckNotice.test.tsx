import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { NodeStatus, WalletCatchUpStatus, WorkRuleStatus } from "../types";
import { WorkCheckNotice } from "./WorkCheckNotice";

function status(overrides: Partial<WorkRuleStatus>, acceptedHeight = 128): NodeStatus {
  const rule: WorkRuleStatus = {
    enforced: true,
    engines: "cpu",
    bank: "streamed",
    engine_state: "ready",
    engine_ready: true,
    independent_engines: false,
    halted: false,
    checkpoint_height: 100,
    checkpoint_hash: "aa".repeat(32),
    activation_height: 101,
    validated_height: acceptedHeight,
    pending_side_blocks: 0,
    unsettled_height: null,
    unsettled_block_id: null,
    backlog_paused: false,
    alarms: {
      engine_divergence: 0,
      own_engine_mismatches: 0,
      engine_failures: 0,
      store_conflicts: 0,
      peers_on_invalid_chain: 0,
    },
    ...overrides,
  };
  return { accepted_height: acceptedHeight, work_rule: rule } as NodeStatus;
}

describe("WorkCheckNotice", () => {
  afterEach(cleanup);

  it("stays out of the way once every block is checked", () => {
    const { container } = render(<WorkCheckNotice status={status({})} onResync={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
    render(<WorkCheckNotice status={null} onResync={vi.fn()} />);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("explains the preparation and the blocks left", () => {
    render(<WorkCheckNotice status={status({ engine_state: "qualifying", validated_height: 100 })} onResync={vi.fn()} />);
    expect(screen.getByRole("status")).toHaveTextContent("Preparing the block check");
    cleanup();
    render(<WorkCheckNotice status={status({ validated_height: 100 })} onResync={vi.fn()} />);
    expect(screen.getByRole("status")).toHaveTextContent("Checking blocks · 28 left");
    expect(screen.getByRole("status")).toHaveTextContent("show as Verifying");
    cleanup();
    render(<WorkCheckNotice status={status({ validated_height: 100, backlog_paused: true })} onResync={vi.fn()} />);
    expect(screen.getByRole("status")).toHaveTextContent("Block check paused on battery · 28 left");
  });

  it("reports an unavailable check without a resync", () => {
    render(<WorkCheckNotice status={status({ engine_state: "failed" })} onResync={vi.fn()} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Block checks are unavailable");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("offers a resync when block checks are stopped or a stored block holds them", async () => {
    const onResync = vi.fn();
    render(<WorkCheckNotice status={status({ halted: true })} onResync={onResync} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Block checks are stopped");
    await userEvent.click(screen.getByRole("button", { name: "Resync chain" }));
    expect(onResync).toHaveBeenCalledTimes(1);
    cleanup();
    const blockId = "0123456789abcdef".repeat(4);
    render(
      <WorkCheckNotice
        status={status({ validated_height: 120, unsettled_height: 121, unsettled_block_id: blockId })}
        onResync={onResync}
      />,
    );
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("A stored block did not pass the check");
    expect(alert).toHaveTextContent("block 121 did not match");
    // Blocks 122 to 128 follow it.
    expect(alert).toHaveTextContent("coins in it and in the 7 blocks after it stay Verifying");
    // The resync is offered either way: the banner never says to stay on the block.
    expect(alert).toHaveTextContent("Resync the chain to set the stored blocks aside and download them again from other nodes; the wallet key stays.");
    expect(alert).toHaveTextContent("report block 121, whose id begins 0123456789abcdef, and update the wallet when a new version is out.");
    expect(alert).not.toHaveTextContent(/explorer/i);
    expect(alert).not.toHaveTextContent(/do not resync/i);
    await userEvent.click(screen.getByRole("button", { name: "Resync chain" }));
    expect(onResync).toHaveBeenCalledTimes(2);
    cleanup();
    // The held block at the tip: nothing follows it.
    render(<WorkCheckNotice status={status({ validated_height: 127, unsettled_height: 128 })} onResync={onResync} />);
    expect(screen.getByRole("alert")).toHaveTextContent("coins in it stay Verifying");
    expect(screen.getByRole("alert")).toHaveTextContent("report block 128 and update the wallet");
  });

  it("says where a catching-up wallet stands, with the node's own count", () => {
    const catchUp = (overrides: Partial<WalletCatchUpStatus>): WalletCatchUpStatus => ({
      state: "caught_up",
      reason: null,
      available_height: 100,
      blocks_left: 0,
      newest_checked: 0,
      newest_needed: 60,
      sources_answering: 2,
      granted_above_available: false,
      ...overrides,
    });
    const line = (overrides: Partial<WalletCatchUpStatus>, paused = false) => {
      cleanup();
      render(
        <WorkCheckNotice
          status={status({ validated_height: 100, backlog_paused: paused, wallet_catch_up: catchUp(overrides) })}
          onResync={vi.fn()}
        />,
      );
      expect(screen.queryByRole("button")).not.toBeInTheDocument();
      return screen.getByRole("status").textContent;
    };
    expect(line({ state: "catching_up" }))
      .toBe("Catching up with the network. Recent coins show as Verifying until the newest blocks are checked.");
    expect(line({ state: "checking_newest", newest_checked: 17, blocks_left: 43 }))
      .toBe("Checking the newest blocks on this computer: 17 of 60.");
    expect(line({ state: "single_source", blocks_left: 900 }))
      .toBe("Fast catch-up needs two Common Foundry relays, and fewer can be reached now. Every block is checked here, which is slower.");
    expect(line({ state: "release_stale", blocks_left: 900 }))
      .toBe("Update the wallet for fast catch-up. Every block is checked here, which is slower.");
    expect(line({ state: "waiting_for_check", reason: "earlier_blocks", blocks_left: 9 }))
      .toBe("Earlier stored blocks are checked first: 9 left.");
    expect(line({ state: "waiting_for_check", reason: "difficulty", blocks_left: 28 }))
      .toBe("Recent blocks need a full check before coins are available: 28 left.");
    expect(line({ state: "waiting_for_check", reason: "other", blocks_left: 3 }))
      .toBe("Recent blocks need a full check before coins are available: 3 left.");
    // On battery the count waits, and the line says so.
    expect(line({ state: "waiting_for_check", reason: "earlier_blocks", blocks_left: 9 }, true))
      .toBe("Earlier stored blocks are checked first: 9 left. Paused on battery; continues when plugged in.");
    expect(line({ state: "waiting_for_check", reason: "difficulty", blocks_left: 28 }, true))
      .toBe("Recent blocks need a full check before coins are available: 28 left. Paused on battery; continues when plugged in.");
    // Caught up: coins do not wait for the older blocks, so the line makes
    // no claim about Verifying.
    expect(line({ state: "caught_up", blocks_left: 5 })).toBe("Older blocks are checked in the background: 5 left");
    expect(line({ state: "caught_up", blocks_left: 5 }, true))
      .toBe("Older blocks are checked in the background: 5 leftPaused on battery; continues when plugged in.");
  });
});
