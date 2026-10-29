import { describe, expect, it } from "vitest";
import type { NodeStatus, WalletCatchUpStatus, WorkRuleStatus } from "../types";
import { workCheckView } from "./workCheck";

function rule(overrides: Partial<WorkRuleStatus> = {}): WorkRuleStatus {
  return {
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
    validated_height: 128,
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
}

function status(workRule: WorkRuleStatus | null | undefined, acceptedHeight = 128): NodeStatus {
  return { accepted_height: acceptedHeight, work_rule: workRule } as NodeStatus;
}

describe("workCheckView", () => {
  it("says nothing without the rule or once every block is checked", () => {
    expect(workCheckView(null)).toEqual({ kind: "none" });
    expect(workCheckView(status(undefined))).toEqual({ kind: "none" });
    expect(workCheckView(status(null))).toEqual({ kind: "none" });
    expect(workCheckView(status(rule()))).toEqual({ kind: "none" });
  });

  it("counts the blocks left to check, and says when the check is paused", () => {
    expect(workCheckView(status(rule({ validated_height: 120 }))))
      .toEqual({ kind: "checking", blocksLeft: 8, paused: false, catchUp: false });
    expect(workCheckView(status(rule({ validated_height: 120, backlog_paused: true }))))
      .toEqual({ kind: "checking", blocksLeft: 8, paused: true, catchUp: false });
    // Nothing is left to check: a pause does not matter.
    expect(workCheckView(status(rule({ backlog_paused: true })))).toEqual({ kind: "none" });
  });

  it("puts a halt first, then a failed engine, then the preparation", () => {
    const behind = { validated_height: 120 };
    expect(workCheckView(status(rule({ ...behind, halted: true, engine_state: "failed" }))))
      .toEqual({ kind: "halted" });
    expect(workCheckView(status(rule({ ...behind, engine_state: "failed" }))))
      .toEqual({ kind: "failed" });
    expect(workCheckView(status(rule({ ...behind, engine_state: "qualifying" }))))
      .toEqual({ kind: "preparing" });
    expect(workCheckView(status(rule({ engine_state: "pending" }))))
      .toEqual({ kind: "preparing" });
  });

  it("reports a stored block one check found not matching while it holds the check", () => {
    const held = { validated_height: 120, unsettled_height: 121, unsettled_block_id: "0f".repeat(32) };
    expect(workCheckView(status(rule(held))))
      .toEqual({ kind: "held", height: 121, blockId: "0f".repeat(32), blocksAfter: 7 });
    // A refusal counted since start, with nothing held, is not shown.
    const alarms = { ...rule().alarms, own_engine_mismatches: 1 };
    expect(workCheckView(status(rule({ alarms })))).toEqual({ kind: "none" });
  });
});

function catchUp(overrides: Partial<WalletCatchUpStatus> = {}): WalletCatchUpStatus {
  return {
    state: "caught_up",
    reason: null,
    available_height: 120,
    blocks_left: 0,
    newest_checked: 0,
    newest_needed: 60,
    sources_answering: 2,
    granted_above_available: false,
    ...overrides,
  };
}

describe("workCheckView while the wallet catches up", () => {
  // The tip is 128 and the validated height 100 throughout: the node's own count is what shows.
  const behind = { validated_height: 100 };

  it("maps each catch-up state to its own kind", () => {
    const view = (overrides: Partial<WalletCatchUpStatus>) =>
      workCheckView(status(rule({ ...behind, wallet_catch_up: catchUp(overrides) })));
    expect(view({ state: "release_stale", blocks_left: 500 })).toEqual({ kind: "release_stale" });
    expect(view({ state: "single_source", blocks_left: 500 })).toEqual({ kind: "single_source" });
    expect(view({ state: "catching_up", blocks_left: 0 })).toEqual({ kind: "catching_up" });
    expect(view({ state: "checking_newest", newest_checked: 12, blocks_left: 48 }))
      .toEqual({ kind: "checking_newest", newestChecked: 12, newestNeeded: 60 });
    expect(view({ state: "waiting_for_check", reason: "earlier_blocks", blocks_left: 9 }))
      .toEqual({ kind: "waiting_for_check", reason: "earlier_blocks", blocksLeft: 9, paused: false });
    expect(view({ state: "waiting_for_check", reason: "difficulty", blocks_left: 28 }))
      .toEqual({ kind: "waiting_for_check", reason: "difficulty", blocksLeft: 28, paused: false });
    expect(view({ state: "waiting_for_check", reason: "other", blocks_left: 28 }))
      .toEqual({ kind: "waiting_for_check", reason: "other", blocksLeft: 28, paused: false });
    expect(view({ state: "waiting_for_check", reason: null, blocks_left: 28 }))
      .toEqual({ kind: "waiting_for_check", reason: "other", blocksLeft: 28, paused: false });
  });

  it("shows caught_up as the background check, counted by the node", () => {
    expect(workCheckView(status(rule({ ...behind, wallet_catch_up: catchUp({ blocks_left: 3 }) }))))
      .toEqual({ kind: "checking", blocksLeft: 3, paused: false, catchUp: true });
    expect(workCheckView(status(rule({
      ...behind,
      backlog_paused: true,
      wallet_catch_up: catchUp({ blocks_left: 3 }),
    })))).toEqual({ kind: "checking", blocksLeft: 3, paused: true, catchUp: true });
    expect(workCheckView(status(rule({ ...behind, wallet_catch_up: catchUp({ blocks_left: 0 }) }))))
      .toEqual({ kind: "none" });
    // A state this wallet does not know falls back to the background line.
    const unknown = catchUp({ state: "later" as WalletCatchUpStatus["state"], blocks_left: 4 });
    expect(workCheckView(status(rule({ ...behind, wallet_catch_up: unknown }))))
      .toEqual({ kind: "checking", blocksLeft: 4, paused: false, catchUp: true });
  });

  it("says when the count waits for mains power", () => {
    const waiting = catchUp({ state: "waiting_for_check", reason: "earlier_blocks", blocks_left: 9 });
    expect(workCheckView(status(rule({ ...behind, backlog_paused: true, wallet_catch_up: waiting }))))
      .toEqual({ kind: "waiting_for_check", reason: "earlier_blocks", blocksLeft: 9, paused: true });
  });

  it("puts halted, failed, preparing and held before every catch-up state", () => {
    const waiting = catchUp({ state: "waiting_for_check", reason: "other", blocks_left: 28 });
    const withCatchUp = (overrides: Partial<WorkRuleStatus>) =>
      workCheckView(status(rule({ ...behind, wallet_catch_up: waiting, ...overrides })));
    expect(withCatchUp({ halted: true, engine_state: "failed", unsettled_height: 101 })).toEqual({ kind: "halted" });
    expect(withCatchUp({ engine_state: "failed", unsettled_height: 101 })).toEqual({ kind: "failed" });
    expect(withCatchUp({ engine_state: "qualifying", unsettled_height: 101 })).toEqual({ kind: "preparing" });
    expect(withCatchUp({ engine_state: "pending" })).toEqual({ kind: "preparing" });
    expect(withCatchUp({ unsettled_height: 110, unsettled_block_id: "0f".repeat(32) }))
      .toEqual({ kind: "held", height: 110, blockId: "0f".repeat(32), blocksAfter: 18 });
    expect(withCatchUp({})).toEqual({ kind: "waiting_for_check", reason: "other", blocksLeft: 28, paused: false });
  });
});
