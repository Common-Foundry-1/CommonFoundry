import type { NodeStatus, WalletCatchUpStatus } from "../types";

/** Why a catching-up wallet's recent coins still wait for the check. */
export type WaitingReason = "earlier_blocks" | "difficulty" | "other";

/** What the wallet tells the user about its block check. */
export type WorkCheckView =
  | { kind: "none" }
  | { kind: "halted" }
  | { kind: "failed" }
  | { kind: "preparing" }
  /**
   * A stored block's work did not match on this computer's check, and nothing here can settle it.
   * `blocksAfter` counts the active blocks above it.
   */
  | { kind: "held"; height: number; blockId: string | null; blocksAfter: number }
  /** The catch-up states the node reports, one kind each; `caught_up` shows as `checking`. */
  | { kind: "release_stale" }
  | { kind: "single_source" }
  | { kind: "catching_up" }
  | { kind: "checking_newest"; newestChecked: number; newestNeeded: number }
  /** `paused`: the background check waits for mains power, and N waits with it. */
  | { kind: "waiting_for_check"; reason: WaitingReason; blocksLeft: number; paused: boolean }
  /** `catchUp`: the wallet catches up (Standard mode), so coins do not wait for this count. */
  | { kind: "checking"; blocksLeft: number; paused: boolean; catchUp: boolean };

function waitingReason(catchUp: WalletCatchUpStatus): WaitingReason {
  return catchUp.reason === "earlier_blocks" || catchUp.reason === "difficulty" ? catchUp.reason : "other";
}

/** The kind for a catch-up state, or `null` for `caught_up` and states this wallet does not know. */
function catchUpView(catchUp: WalletCatchUpStatus, paused: boolean): WorkCheckView | null {
  switch (catchUp.state) {
    case "release_stale":
    case "single_source":
    case "catching_up":
      return { kind: catchUp.state };
    case "checking_newest":
      return {
        kind: "checking_newest",
        newestChecked: catchUp.newest_checked,
        newestNeeded: catchUp.newest_needed,
      };
    case "waiting_for_check":
      return { kind: "waiting_for_check", reason: waitingReason(catchUp), blocksLeft: catchUp.blocks_left, paused };
    default:
      return null;
  }
}

/**
 * Precedence: halted > failed > preparing > held > the catch-up state > checking > none. While the
 * catch-up is on, a count of blocks always comes from the node's `blocks_left`.
 */
export function workCheckView(status: NodeStatus | null): WorkCheckView {
  const rule = status?.work_rule;
  if (!status || !rule) return { kind: "none" };
  if (rule.halted) return { kind: "halted" };
  if (rule.engine_state === "failed") return { kind: "failed" };
  if (rule.engine_state === "pending" || rule.engine_state === "qualifying") return { kind: "preparing" };
  if (rule.unsettled_height !== null && rule.unsettled_height !== undefined) {
    return {
      kind: "held",
      height: rule.unsettled_height,
      blockId: rule.unsettled_block_id ?? null,
      blocksAfter: Math.max(0, status.accepted_height - rule.unsettled_height),
    };
  }
  const paused = rule.backlog_paused === true;
  const catchUp = rule.wallet_catch_up;
  if (catchUp) {
    const view = catchUpView(catchUp, paused);
    if (view) return view;
  }
  const blocksLeft = catchUp
    ? Math.max(0, catchUp.blocks_left)
    : Math.max(0, status.accepted_height - rule.validated_height);
  if (blocksLeft > 0) return { kind: "checking", blocksLeft, paused, catchUp: Boolean(catchUp) };
  return { kind: "none" };
}

/** Said after a count that waits while the computer runs on its battery. */
export const PAUSED_ON_BATTERY_COPY = "Paused on battery; continues when plugged in.";
