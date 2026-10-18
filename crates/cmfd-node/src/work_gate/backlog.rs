//! The background work check.
//!
//! Some blocks above the release checkpoint reach this node without a check
//! on the admission path: blocks an earlier release stored, blocks the
//! relevance gate noted but did not index, and pool blocks recorded
//! provisionally. The backlog checks them one block per turn of the work
//! lane, in this order:
//!
//! 1. Indexed blocks on side branches, lowest first, each only once it is
//!    known to descend from the checkpoint block. There are few: once the rule
//!    is enforced nothing above the checkpoint is indexed unchecked.
//! 2. Active blocks, lowest first: those still stored in full before those
//!    already pruned, so that pruning can resume early.
//! 3. Provisional blocks, which this node's own engines run again.
//! 4. Blocks the relevance gate noted. They are not indexed, so only the
//!    memo keeps their result, and a re-send is then answered from it.
//!
//! A match is recorded verified. A mismatch two independent engines agree on
//! is recorded invalid, and if the block is on the active chain the node
//! halts and writes the halt marker. A single engine's mismatch on a stored
//! block is recorded unsettled (the checker raises its alarm): the block
//! counts as unchecked, a provisional one too. It is computed again once an
//! independent engine can settle it; with one kind of engine, once after each
//! start and then every [`RETRY_UNSETTLED_ONE_ENGINE`], so that a passing
//! fault heals while a lasting disagreement costs little. An operator can
//! also clear the record with the node stopped (`cmfd-node work-reconsider`),
//! which only has it checked again: a block that one kind of engine keeps
//! refusing, but that matches elsewhere, needs a release that moves the
//! checkpoint past it.
//! A block the engines could not answer for, or whose record could not be
//! read, is tried again later.
//!
//! On a desktop wallet catching up, active blocks are checked in one
//! ascending list from the validated height, up to and including the lowest
//! one recorded unsettled; a side block only once its parent is active or
//! verified; and neither while the blocks re-executed at the tip are about to
//! make the blocks below them available.
//!
//! A noted block that two independent engines agree does not match has its
//! peer reported to P2P ([`super::WorkBlame`]), which treats that peer as a
//! confirmed refusal at admission would have. Only a noted block knows its
//! peer, and a single engine's mismatch reports nobody.
//!
//! A pool's backlog has the lane to itself at startup, before the node opens
//! its network services, and checks active blocks only, since they alone
//! move the validated height: until it is within [`WORK_RELEVANCE_DEPTH`] of
//! the tip, nothing more can be checked, or the engines are not ready
//! ([`run_work_backlog_exclusive`]). A background thread then keeps running
//! it in the order above ([`spawn_work_backlog`]). A node that serves no pool
//! opens its services at once, and its background thread first checks the
//! active blocks in that startup order, then goes on in the order above
//! ([`spawn_startup_work_backlog`]). Each of its turns waits in the lane's
//! priority class, so a flood of remote blocks in the normal class cannot
//! starve it, and between turns it gives way to other waiting admissions for
//! at most [`WORK_BACKLOG_MAX_YIELD`]. A noted block is the exception: anyone
//! can send one, so it is checked only while the lane is idle, in the normal
//! class, and its job stops for any block waiting for the lane. A provisional
//! block's job stops for a block waiting as priority (a pool's own block, for
//! one), and the block is checked again on a later turn.
//!
//! While more than [`PROGRESS_MIN_LEFT`] stored active blocks are left above
//! the validated height, either run logs its progress at warn every
//! [`PROGRESS_INTERVAL`]: the blocks left, those checked, the rate over the
//! last interval and when it should end at that rate.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cmfd_consensus::{
    BlockChallenge, PRODUCTION_V4_MODEL_MANIFEST_DIGEST, forgematrix_v4_challenge_digest,
};

use super::{BlockSender, PendingSideWork, WORK_HALT_FILE, WORK_RELEVANCE_DEPTH, WorkGate, lock};
use crate::honest_work::store::{WorkStatus, WorkStatusStore, write_work_halt};
use crate::honest_work::{
    ConfirmedWorkMismatch, HonestWorkChecker, WorkCancel, WorkClaim, WorkEngineState,
    WorkProvenance, WorkUnavailable, WorkVerdict,
};
use crate::pruning::StoredProof;
use crate::{
    BLOCK_LOG_FILE, Node, NodeError, ProofProfile, RemoteProofRequest, read_indexed_block,
};

/// The longest the background check gives way to other waiting admissions
/// between two of its turns.
pub const WORK_BACKLOG_MAX_YIELD: Duration = Duration::from_secs(60);
/// A block the engines could not answer for is tried again after this.
const RETRY_UNAVAILABLE: Duration = Duration::from_secs(60);
/// A single engine's mismatch is tried again after this, when the other kind
/// of engine may be ready to settle it.
const RETRY_UNSETTLED: Duration = Duration::from_secs(15 * 60);
/// On a node with one kind of engine, a block recorded unsettled is computed
/// again on that engine after this (and once after each start).
pub const RETRY_UNSETTLED_ONE_ENGINE: Duration = Duration::from_secs(6 * 60 * 60);
/// A block whose record could not be read is tried again after this.
const RETRY_UNREADABLE: Duration = Duration::from_secs(15 * 60);
/// The startup run gives up after this many turns in a row in which the
/// engines could not answer, and leaves the rest to the background thread.
const STARTUP_UNAVAILABLE_TURNS: u32 = 6;
/// A block that cannot be checked here (no claim can be read from its
/// record, or it does not descend from the checkpoint block) is looked at
/// again only after this.
const RETRY_UNCHECKABLE: Duration = Duration::from_secs(24 * 60 * 60);
/// The longest a noted block waits for the lane it found idle.
const NOTED_LANE_WAIT: Duration = Duration::from_secs(1);
/// How often the background thread looks for new work when it found none.
const IDLE_POLL: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(250);
/// How often a backlog with many stored blocks left logs its progress.
pub const PROGRESS_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Progress is logged only while more stored active blocks than this are
/// left above the validated height.
pub const PROGRESS_MIN_LEFT: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    Side,
    Active,
    Provisional,
    Pending,
}

#[derive(Clone, Copy, Debug)]
struct Item {
    block_id: [u8; 32],
    height: u64,
    claim: WorkClaim,
    source: Source,
    /// For a noted block, the peer it came from.
    sender: Option<BlockSender>,
}

/// What one checked block came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkBacklogOutcome {
    /// It matched and is recorded verified (a noted block: its result is in
    /// the memo).
    Verified,
    /// Two independent engines found it does not match.
    Invalid,
    /// No final verdict yet (a single engine's mismatch); it is tried again
    /// later.
    Unsettled,
}

/// What one turn of the backlog did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkBacklogTurn {
    /// Nothing is left that can be checked now (a noted block may be waiting
    /// for the lane to be idle).
    Idle,
    /// One block was checked.
    Checked(WorkBacklogOutcome),
    /// The engines could not answer; the block is left for later.
    Unavailable,
    /// The node is halted, or this turn halted it.
    Halted,
    /// The caller cancelled the turn.
    Cancelled,
}

/// The backlog's own state between turns: blocks it will not pick again
/// before a given time.
#[derive(Debug, Default)]
pub struct WorkBacklog {
    deferred: HashMap<[u8; 32], Instant>,
    /// The startup run, which checks active blocks only.
    startup: bool,
}

/// Where the exclusive startup run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkBacklogReport {
    /// Blocks checked.
    pub checked: u64,
    pub validated_height: Option<u64>,
    pub tip_height: u64,
    pub halted: bool,
}

fn poisoned<T>(_: T) -> NodeError {
    NodeError::SharedNodePoisoned
}

impl WorkBacklog {
    pub fn new() -> Self {
        Self::default()
    }

    /// The backlog for the startup run, which checks active blocks only.
    fn for_startup() -> Self {
        Self {
            startup: true,
            ..Self::default()
        }
    }

    fn defer(&mut self, block_id: [u8; 32], wait: Duration) {
        self.deferred.insert(block_id, Instant::now() + wait);
    }

    /// Puts a block back for a later turn.
    fn put_back(&mut self, gate: &WorkGate, item: Item, wait: Duration) {
        if item.source == Source::Pending {
            gate.note_side_work(PendingSideWork {
                block_id: item.block_id,
                height: item.height,
                claim: item.claim,
                sender: item.sender,
            });
        } else {
            self.defer(item.block_id, wait);
        }
    }

    /// Checks the next block, and first runs the known answers if they are
    /// due, inside the work lane. `cancel` stops a running job.
    pub fn run_turn(
        &mut self,
        shared: &Mutex<Node>,
        cancel: &WorkCancel<'_>,
    ) -> Result<WorkBacklogTurn, NodeError> {
        let now = Instant::now();
        self.deferred.retain(|_, until| *until > now);
        let (gate, item) = {
            let node = shared.lock().map_err(poisoned)?;
            let Some(gate) = node.work_gate.clone() else {
                return Ok(WorkBacklogTurn::Idle);
            };
            if gate.halted() {
                return Ok(WorkBacklogTurn::Halted);
            }
            let (Some(checker), Some(_)) = (gate.checker.as_ref(), gate.store.as_ref()) else {
                return Ok(WorkBacklogTurn::Unavailable);
            };
            // While no worker is ready and no qualification round is due,
            // no block is read: nothing could check it.
            let ready = checker.engine_state() == WorkEngineState::Ready;
            if !ready && !checker.known_answer_tests_due(now) {
                return Ok(WorkBacklogTurn::Unavailable);
            }
            let item = node.next_work_backlog_item(&gate, &mut self.deferred, now, self.startup);
            (gate, item)
        };
        let checker = gate.checker.clone().expect("checked above");
        let store = gate.store.clone().expect("checked above");
        let known_answers_due = checker.known_answer_tests_due(now);
        if item.is_none() && !known_answers_due {
            return Ok(WorkBacklogTurn::Idle);
        }
        // A noted block advances nothing this node relies on, and anyone can
        // send one: it is checked only while the lane is otherwise idle, in
        // the normal class, and gives way to any block waiting for the lane.
        // Waiting for an idle lane is not an engine failure, so the turn is
        // idle and the background thread does not back off.
        let noted = item.is_some_and(|item| item.source == Source::Pending);
        if noted && !lane_idle(&gate) {
            if let Some(item) = item {
                self.put_back(&gate, item, RETRY_UNAVAILABLE);
            }
            return Ok(WorkBacklogTurn::Idle);
        }
        let acquired = if noted {
            // Briefly: a block that took the lane since it was found idle
            // goes first.
            gate.lane
                .acquire_cancellable(RemoteProofRequest::new(Instant::now() + NOTED_LANE_WAIT))
        } else {
            gate.lane.acquire_priority()
        };
        let lane = match acquired {
            Ok(lane) => lane,
            Err(error) => {
                tracing::debug!(target: "work_rule", %error, "the background work check waits for the lane");
                if let Some(item) = item {
                    self.put_back(&gate, item, RETRY_UNAVAILABLE);
                }
                return Ok(if noted {
                    WorkBacklogTurn::Idle
                } else {
                    WorkBacklogTurn::Unavailable
                });
            }
        };
        if known_answers_due {
            // Cancelled, the round leaves each worker's health as it was,
            // and the cancel below puts the block back.
            let report = checker.run_known_answer_tests_cancellable(cancel);
            if !cancel() {
                tracing::info!(target: "work_rule", ?report, "work engines qualified against the known answers");
            }
        }
        let Some(item) = item else {
            return Ok(WorkBacklogTurn::Idle);
        };
        if cancel() {
            self.put_back(&gate, item, Duration::ZERO);
            return Ok(WorkBacklogTurn::Cancelled);
        }
        // A noted block counts against its peer's address like an admitted
        // one (see MAX_LONE_REFUSALS_PER_SENDER), unless the peer is trusted.
        // One from an address with no refusals left is dropped; a re-send
        // notes it again.
        let counted_sender = item
            .sender
            .filter(|sender| noted && !sender.trusted)
            .map(|sender| sender.address);
        if !gate.lone_refusals_allow(counted_sender, &item.block_id) {
            return Ok(WorkBacklogTurn::Idle);
        }
        {
            // Admission may have checked it since it was picked.
            let store = lock(&store);
            let outcome = |status| match status {
                Some(WorkStatus::Verified) => Some(WorkBacklogOutcome::Verified),
                Some(WorkStatus::Invalid) => Some(WorkBacklogOutcome::Invalid),
                None => None,
            };
            let done = match item.source {
                Source::Pending => None,
                Source::Provisional if store.is_provisional(&item.block_id) => None,
                Source::Provisional => Some(
                    outcome(store.status(&item.block_id)).unwrap_or(WorkBacklogOutcome::Unsettled),
                ),
                Source::Side | Source::Active => outcome(store.status(&item.block_id)),
            };
            if let Some(outcome) = done {
                return Ok(WorkBacklogTurn::Checked(outcome));
            }
        }
        // The memo may still hold the pool's own result, or this engine's
        // earlier mismatch: this node's engines must compute it.
        let one_engine_retry =
            !checker.has_independent_engines() && lock(&store).is_unsettled(&item.block_id);
        if item.source == Source::Provisional || one_engine_retry {
            checker.forget(item.claim.challenge_digest);
        }
        let provisional = item.source == Source::Provisional;
        let gives_way = || {
            (noted || provisional)
                && gate.lane.telemetry().is_ok_and(|telemetry| {
                    telemetry.priority.queued > 0 || (noted && telemetry.normal.queued > 0)
                })
        };
        let verdict = checker.check_cancellable(item.claim, &|| cancel() || gives_way());
        if let WorkVerdict::Mismatch(mismatch) = &verdict
            && mismatch.confirmed().is_none()
        {
            gate.charge_lone_refusal(counted_sender, item.block_id, item.claim.challenge_digest);
        }
        drop(lane);
        match verdict {
            WorkVerdict::Match(provenance) => {
                if item.source == Source::Pending {
                    return Ok(WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified));
                }
                let recorded =
                    gate.record_match(&mut lock(&store), provenance, item.height, item.block_id);
                match recorded {
                    Ok(()) if provenance == WorkProvenance::RecordHonest => {
                        self.defer(item.block_id, RETRY_UNSETTLED);
                        Ok(WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled))
                    }
                    Ok(()) => Ok(WorkBacklogTurn::Checked(WorkBacklogOutcome::Verified)),
                    Err(error) => {
                        note_store_error(&gate, item, &error, "verified");
                        self.defer(item.block_id, retry_after_store_error(&error));
                        Ok(WorkBacklogTurn::Unavailable)
                    }
                }
            }
            WorkVerdict::Mismatch(mismatch) => {
                let Some(confirmed) = mismatch.confirmed() else {
                    // A noted block is not put back: the memo holds the
                    // result, and a re-send either answers from it or runs
                    // the other engine.
                    if item.source != Source::Pending {
                        self.note_unsettled(&gate, &checker, item);
                    }
                    return Ok(WorkBacklogTurn::Checked(WorkBacklogOutcome::Unsettled));
                };
                if item.source == Source::Pending {
                    // A re-send is refused from the memo as confirmed; the
                    // peer it first came from is reported here.
                    if let Some(sender) = item.sender {
                        tracing::info!(
                            target: "work_rule",
                            height = item.height,
                            block_id = %hex::encode(item.block_id),
                            peer = %sender.address,
                            fetched = sender.fetched,
                            "two engines agree a noted block does not match its work; its peer is treated as for a refused block"
                        );
                        // The outcome is settled; a poisoned node lock only
                        // skips reporting the peer.
                        let sinks = match shared.lock() {
                            Ok(node) => node.work_blame_sinks(),
                            Err(_) => {
                                tracing::warn!(
                                    target: "work_rule",
                                    peer = %sender.address,
                                    "the node lock is poisoned; the peer of a noted block is not reported"
                                );
                                Vec::new()
                            }
                        };
                        for sink in sinks {
                            sink.blame(sender);
                        }
                    }
                    return Ok(WorkBacklogTurn::Checked(WorkBacklogOutcome::Invalid));
                }
                let recorded = lock(&store).mark_invalid(
                    &confirmed,
                    item.height,
                    item.block_id,
                    item.claim.challenge_digest,
                );
                let unrecorded = if let Err(error) = recorded {
                    note_store_error(&gate, item, &error, "invalid");
                    if error.kind() == io::ErrorKind::InvalidInput {
                        // The store says this node's engines verified it:
                        // that disagreement is for an operator, not a halt.
                        self.defer(item.block_id, RETRY_UNSETTLED);
                        return Ok(WorkBacklogTurn::Unavailable);
                    }
                    true
                } else {
                    false
                };
                let node = shared.lock().map_err(poisoned)?;
                if node.active_block_id_at_height(item.height) == Some(item.block_id) {
                    gate.halt(&node, item.height, item.block_id, &confirmed);
                    return Ok(WorkBacklogTurn::Halted);
                }
                if unrecorded {
                    // Tried again later, not at every turn while the store
                    // cannot be written.
                    self.defer(item.block_id, RETRY_UNAVAILABLE);
                    return Ok(WorkBacklogTurn::Unavailable);
                }
                Ok(WorkBacklogTurn::Checked(WorkBacklogOutcome::Invalid))
            }
            WorkVerdict::Unavailable(WorkUnavailable::Cancelled) if !cancel() => {
                // A noted or provisional block gave way to a block waiting
                // for the lane.
                self.put_back(&gate, item, Duration::ZERO);
                Ok(WorkBacklogTurn::Idle)
            }
            WorkVerdict::Unavailable(WorkUnavailable::Cancelled) => {
                self.put_back(&gate, item, Duration::ZERO);
                Ok(WorkBacklogTurn::Cancelled)
            }
            WorkVerdict::Unavailable(reason) => {
                tracing::warn!(
                    target: "work_rule",
                    height = item.height,
                    block_id = %hex::encode(item.block_id),
                    %reason,
                    "a stored block's work could not be checked; it is tried again later"
                );
                self.put_back(&gate, item, RETRY_UNAVAILABLE);
                Ok(WorkBacklogTurn::Unavailable)
            }
        }
    }

    /// Records a stored block's single-engine mismatch as unsettled, so it
    /// no longer counts as verified (if it was provisional). It is computed
    /// again once an independent engine can settle it, or, with one kind of
    /// engine, after [`RETRY_UNSETTLED_ONE_ENGINE`] or the next start.
    fn note_unsettled(&mut self, gate: &WorkGate, checker: &HonestWorkChecker, item: Item) {
        tracing::warn!(
            target: "work_rule",
            height = item.height,
            block_id = %hex::encode(item.block_id),
            "a stored block does not match its work on one engine; no independent engine settled it. \
             It is computed again later: after each start, and every 6 hours on a node with one \
             kind of engine. `cmfd-node work-reconsider <block id>` only makes this node check \
             it again. If the block matches on another node or on the explorer, this node needs \
             a release that moves the checkpoint past it: report it to the release maintainers"
        );
        if item.source == Source::Provisional {
            // The pool's replay and this node's engine disagree.
            tracing::error!(
                target: "work_rule",
                height = item.height,
                block_id = %hex::encode(item.block_id),
                "this node's engine does not reproduce the pool's own result for a block; it no longer counts as verified"
            );
            checker.raise_divergence(item.claim.challenge_digest);
        }
        let store = gate.store.as_ref().expect("a backlog item has a store");
        if let Err(error) = lock(store).mark_unsettled(item.height, item.block_id) {
            note_store_error(gate, item, &error, "unsettled");
            // The block would otherwise still count as granted, if it was.
            if let Some(catch_up) = gate.wallet_catch_up.as_ref() {
                catch_up.set_store_failed();
            }
        }
        if !checker.has_independent_engines() {
            lock(&gate.one_engine_retry)
                .insert(item.block_id, Instant::now() + RETRY_UNSETTLED_ONE_ENGINE);
        }
        self.defer(item.block_id, RETRY_UNSETTLED);
    }
}

/// Whether no block is being checked in the work lane or waiting for it.
fn lane_idle(gate: &WorkGate) -> bool {
    gate.lane.telemetry().is_ok_and(|telemetry| {
        telemetry.normal.active
            + telemetry.normal.queued
            + telemetry.priority.active
            + telemetry.priority.queued
            == 0
    })
}

/// A store that refuses a result keeps refusing it until an operator acts;
/// a write that failed may succeed soon.
fn retry_after_store_error(error: &io::Error) -> Duration {
    if error.kind() == io::ErrorKind::InvalidInput {
        RETRY_UNSETTLED
    } else {
        RETRY_UNAVAILABLE
    }
}

/// The claim of a pruned ProductionV4 record, which keeps the header, nonce
/// and work digest but not the proof: the challenge digest is recomputed
/// from the header and nonce as preflight binds it, under the release's
/// model manifest.
fn pruned_v4_claim(challenge: &BlockChallenge, nonce: u64, work_digest: [u8; 32]) -> WorkClaim {
    WorkClaim {
        challenge_digest: forgematrix_v4_challenge_digest(
            challenge,
            nonce,
            PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
        ),
        work_digest,
    }
}

fn note_store_error(gate: &WorkGate, item: Item, error: &io::Error, what: &str) {
    if error.kind() == io::ErrorKind::InvalidInput {
        gate.note_store_conflict(item.block_id, item.claim.challenge_digest, error);
    } else {
        tracing::warn!(
            target: "work_rule",
            block_id = %hex::encode(item.block_id),
            %error,
            "could not record a block as {what}"
        );
    }
}

impl WorkGate {
    /// Halts admission because two independent engines found that the active
    /// block `block_id` does not match its work, and writes the halt marker.
    /// The node stays halted even if the marker cannot be written.
    fn halt(
        &self,
        node: &Node,
        height: u64,
        block_id: [u8; 32],
        confirmed: &ConfirmedWorkMismatch,
    ) {
        self.halted.store(true, Ordering::Release);
        let path = node.data_dir.join(WORK_HALT_FILE);
        let written = write_work_halt(
            &path,
            node.params.network_id,
            height,
            block_id,
            confirmed.challenge_digest(),
            confirmed,
        );
        match written {
            Ok(halt) => tracing::error!(
                target: "work_rule",
                height = halt.height,
                block_id = %hex::encode(halt.block_id),
                "an active block does not match its work on two independent engines; block admission is halted until an operator quarantines it"
            ),
            Err(error) => tracing::error!(
                target: "work_rule",
                height,
                block_id = %hex::encode(block_id),
                %error,
                "an active block does not match its work on two independent engines; block admission is halted, but the halt marker could not be written"
            ),
        }
    }
}

impl Node {
    /// The work claim of an indexed block, read from its stored record: from
    /// the proof of a full record, or recomputed from the header and the kept
    /// nonce and work digest of a pruned ProductionV4 record. `None` if the
    /// record carries nothing the rule can check.
    fn stored_work_claim(
        &self,
        gate: &WorkGate,
        block_id: [u8; 32],
    ) -> Result<Option<WorkClaim>, NodeError> {
        let indexed = self.index.blocks.get(&block_id).cloned().ok_or_else(|| {
            NodeError::CorruptLog("a backlog block is absent from the fork index".to_owned())
        })?;
        let block = read_indexed_block(
            &self.log,
            &self.data_dir.join(BLOCK_LOG_FILE),
            &indexed,
            block_id,
            self.params.network_id,
            matches!(self.profile.proof, ProofProfile::ProductionV3),
        )?;
        Ok(match &block.proof {
            StoredProof::Full(proof) => gate.claim_of_proof(proof),
            StoredProof::Pruned { summary, .. }
                if summary.is_v4_candidate() && !gate.reference_claims =>
            {
                Some(pruned_v4_claim(
                    &block.challenge,
                    summary.nonce,
                    summary.work_digest,
                ))
            }
            StoredProof::Pruned { .. } => None,
        })
    }

    /// Whether the indexed block `block_id` at `height`, above the
    /// checkpoint, descends from the checkpoint block.
    fn descends_from_work_checkpoint(
        &self,
        gate: &WorkGate,
        block_id: [u8; 32],
    ) -> Result<bool, NodeError> {
        let checkpoint = gate.rule.checkpoint_height();
        let ancestor = self.index.ancestor_at_height(block_id, checkpoint)?;
        Ok(ancestor == gate.rule.checkpoint_block_id())
    }

    /// The next block for the backlog; see the module documentation for the
    /// order. The startup run takes active blocks only. Blocks that cannot be
    /// checked here are deferred, and so is one whose record cannot be read,
    /// so that it holds up no other.
    fn next_work_backlog_item(
        &self,
        gate: &WorkGate,
        deferred: &mut HashMap<[u8; 32], Instant>,
        now: Instant,
        startup: bool,
    ) -> Option<Item> {
        let store = gate.store.as_ref()?;
        let checkpoint = gate.rule.checkpoint_height();
        let tip = self.state.next_height().saturating_sub(1);
        let wallet = gate.wallet_catch_up.is_some();
        // Read before the store is locked below, which it locks too.
        let burial_pending = wallet && self.wallet_burial_pending(now);
        let validated = self.work_validated_height().unwrap_or(checkpoint);
        let active_at = |height: u64| self.active_block_id_at_height(height);
        // A single engine's mismatch is computed again where an independent
        // engine can settle it, and otherwise only when its retry is due.
        let settle = gate
            .checker
            .as_ref()
            .is_some_and(|checker| checker.has_independent_engines());
        let one_engine_retry = lock(&gate.one_engine_retry).clone();
        let (side, active_full, active_pruned, provisional) = {
            let mut store = lock(store);
            let waiting =
                |block_id: &[u8; 32]| deferred.get(block_id).is_none_or(|until| *until <= now);
            let unchecked = |store: &WorkStatusStore, block_id: &[u8; 32]| {
                store.status(block_id).is_none()
                    && (settle
                        || !store.is_unsettled(block_id)
                        || one_engine_retry
                            .get(block_id)
                            .is_none_or(|until| *until <= now))
            };
            // On a wallet, a side block whose parent is neither active nor
            // verified waits for its parent.
            let peeled = |store: &WorkStatusStore, height: u64, parent: [u8; 32]| {
                !wallet
                    || active_at(height.saturating_sub(1)) == Some(parent)
                    || store.status(&parent) == Some(WorkStatus::Verified)
            };
            let mut side: Vec<(u64, [u8; 32])> = if startup || burial_pending {
                Vec::new()
            } else {
                self.index
                    .blocks
                    .values()
                    .filter(|entry| {
                        entry.height() > checkpoint
                            && active_at(entry.height()) != Some(entry.block_id())
                            && unchecked(&store, &entry.block_id())
                            && waiting(&entry.block_id())
                            && peeled(&store, entry.height(), entry.parent())
                    })
                    .map(|entry| (entry.height(), entry.block_id()))
                    .collect()
            };
            side.sort_unstable();
            let (mut full, mut pruned) = (Vec::new(), Vec::new());
            let active_from = if burial_pending {
                tip.saturating_add(1)
            } else {
                validated.max(checkpoint).saturating_add(1)
            };
            for height in active_from..=tip {
                let Some(block_id) = active_at(height) else {
                    break;
                };
                if wallet {
                    // One ascending list, full and pruned blocks together, up
                    // to the lowest unsettled block, offered when its retry is
                    // due.
                    let unsettled = store.is_unsettled(&block_id);
                    if unchecked(&store, &block_id) && waiting(&block_id) {
                        full.push((height, block_id));
                    }
                    if unsettled {
                        break;
                    }
                    continue;
                }
                if !unchecked(&store, &block_id) || !waiting(&block_id) {
                    continue;
                }
                if self.block_is_pruned(block_id) {
                    pruned.push((height, block_id));
                } else {
                    full.push((height, block_id));
                }
            }
            let (mut provisional, mut gone) = (Vec::new(), Vec::new());
            if !startup {
                // A provisional block pruning dropped from the index will not
                // be checked here; its record goes, so that if it is offered
                // again it is checked like any other block.
                let pruned_through = self.prune_height().unwrap_or(0);
                for (height, block_id) in store.provisional_blocks() {
                    if self.index.contains(block_id) {
                        if waiting(&block_id) {
                            provisional.push((height, block_id));
                        }
                    } else if height <= pruned_through {
                        gone.push(block_id);
                    }
                }
            }
            if !gone.is_empty()
                && let Err(error) = store.forget_provisional(&gone)
            {
                tracing::warn!(target: "work_rule", %error, "could not forget provisional records of blocks no longer stored");
            }
            (side, full, pruned, provisional)
        };
        let lists = [
            (Source::Side, side),
            (Source::Active, active_full),
            (Source::Active, active_pruned),
            (Source::Provisional, provisional),
        ];
        for (source, blocks) in lists {
            for (height, block_id) in blocks {
                let unreadable = |error: NodeError| {
                    tracing::warn!(
                        target: "work_rule",
                        height,
                        block_id = %hex::encode(block_id),
                        %error,
                        "a stored block cannot be read for the work check; it is tried again later"
                    );
                };
                // A side block is checked only if it descends from the
                // checkpoint block and from no block recorded invalid.
                if source == Source::Side {
                    let descends = match self.descends_from_work_checkpoint(gate, block_id) {
                        Ok(descends) => descends,
                        Err(error) => {
                            unreadable(error);
                            deferred.insert(block_id, now + RETRY_UNREADABLE);
                            continue;
                        }
                    };
                    if !descends
                        || matches!(
                            self.check_side_ancestors(gate, block_id, checkpoint),
                            Err(NodeError::InvalidAncestor(_))
                        )
                    {
                        deferred.insert(block_id, now + RETRY_UNCHECKABLE);
                        continue;
                    }
                }
                match self.stored_work_claim(gate, block_id) {
                    Ok(Some(claim)) => {
                        return Some(Item {
                            block_id,
                            height,
                            claim,
                            source,
                            sender: None,
                        });
                    }
                    Ok(None) => {
                        deferred.insert(block_id, now + RETRY_UNCHECKABLE);
                    }
                    Err(error) => {
                        unreadable(error);
                        deferred.insert(block_id, now + RETRY_UNREADABLE);
                    }
                }
            }
        }
        if startup {
            return None;
        }
        loop {
            let work = lock(&gate.pending_side).pop()?;
            // Admitted (or refused for good) since it was noted, or already
            // settled in the memo, which answers a re-send; or from an
            // untrusted address with no one-engine refusals left.
            let counted_sender = work
                .sender
                .filter(|sender| !sender.trusted)
                .map(|sender| sender.address);
            if !gate.lone_refusals_allow(counted_sender, &work.block_id)
                || self.index.contains(work.block_id)
                || lock(store).status(&work.block_id).is_some()
                || gate
                    .checker
                    .as_ref()
                    .is_some_and(|checker| checker.memo_settled(work.claim.challenge_digest))
            {
                continue;
            }
            return Some(Item {
                block_id: work.block_id,
                height: work.height,
                claim: work.claim,
                source: Source::Pending,
                sender: work.sender,
            });
        }
    }

    /// The next block the background check would take at `now`, with none
    /// deferred.
    #[cfg(test)]
    pub(in crate::work_gate) fn next_work_backlog_block(
        &self,
        now: Instant,
    ) -> Option<(u64, [u8; 32])> {
        let gate = self.work_gate.clone()?;
        self.next_work_backlog_item(&gate, &mut HashMap::new(), now, false)
            .map(|item| (item.height, item.block_id))
    }

    /// Whether admissions are waiting for the work lane.
    fn work_lane_has_waiters(&self) -> bool {
        self.work_gate.as_ref().is_some_and(|gate| {
            gate.lane
                .telemetry()
                .is_ok_and(|telemetry| telemetry.normal.queued + telemetry.priority.queued > 0)
        })
    }
}

/// The validated height and the tip height of a node with a work rule.
pub fn work_backlog_heights(node: &Node) -> Option<(u64, u64)> {
    let validated = node.work_validated_height()?;
    Some((validated, node.state.next_height().saturating_sub(1)))
}

/// A backlog run's progress, logged at warn every [`PROGRESS_INTERVAL`]
/// while more than [`PROGRESS_MIN_LEFT`] stored active blocks are left.
struct BacklogProgress {
    checked: u64,
    /// When the current interval started, with the blocks checked and left
    /// then.
    since: Option<(Instant, u64, u64)>,
}

impl BacklogProgress {
    fn new() -> Self {
        Self {
            checked: 0,
            since: None,
        }
    }

    fn checked_one(&mut self) {
        self.checked += 1;
    }

    fn report(&mut self, shared: &Mutex<Node>, now: Instant) {
        let Some((validated, tip)) = shared
            .lock()
            .ok()
            .and_then(|node| work_backlog_heights(&node))
        else {
            return;
        };
        if let Some(line) = self.next_line(validated, tip, now) {
            tracing::warn!(
                target: "work_rule",
                blocks_left = line.blocks_left,
                checked = line.checked,
                checked_per_hour = line.checked_per_hour,
                eta = %line.eta,
                validated_height = validated,
                tip_height = tip,
                "checking the stored blocks above the validated height; chain reads that need checked blocks wait until it ends"
            );
        }
    }

    /// The progress line due at `now`, if one is.
    fn next_line(&mut self, validated: u64, tip: u64, now: Instant) -> Option<ProgressLine> {
        let left = tip.saturating_sub(validated);
        let Some((since, checked_then, left_then)) = self.since else {
            self.since = Some((now, self.checked, left));
            return None;
        };
        let elapsed = now.saturating_duration_since(since);
        if elapsed < PROGRESS_INTERVAL {
            return None;
        }
        self.since = Some((now, self.checked, left));
        if left <= PROGRESS_MIN_LEFT {
            return None;
        }
        let hours = elapsed.as_secs_f64() / 3_600.0;
        // Blocks keep arriving meanwhile: the end comes at the rate the count
        // of blocks left falls.
        let falling = (left_then as f64 - left as f64) / hours;
        Some(ProgressLine {
            blocks_left: left,
            checked: self.checked,
            checked_per_hour: ((self.checked - checked_then) as f64 / hours).round() as u64,
            eta: if falling > 0.0 {
                format!("{:.1} h", left as f64 / falling)
            } else {
                "none at this rate".to_owned()
            },
        })
    }
}

#[derive(Debug, PartialEq)]
struct ProgressLine {
    blocks_left: u64,
    checked: u64,
    checked_per_hour: u64,
    eta: String,
}

/// Runs the backlog over the active chain with the work lane to itself, for
/// use before the node opens its network services: until the validated
/// height is within [`WORK_RELEVANCE_DEPTH`] of the tip, nothing more can be
/// checked now, the engines are not ready (or could not answer
/// [`STARTUP_UNAVAILABLE_TURNS`] times in a row), the node halts, or `stop` is
/// set. What is left is for [`spawn_work_backlog`].
pub fn run_work_backlog_exclusive(
    shared: &Mutex<Node>,
    stop: &AtomicBool,
) -> Result<WorkBacklogReport, NodeError> {
    let mut backlog = WorkBacklog::for_startup();
    let mut progress = BacklogProgress::new();
    let mut checked = 0_u64;
    let mut unavailable = 0_u32;
    let mut wait = Duration::from_secs(1);
    let mut last_report = Instant::now();
    let cancel = || stop.load(Ordering::Acquire);
    let finish = |checked| -> Result<WorkBacklogReport, NodeError> {
        let node = shared.lock().map_err(poisoned)?;
        Ok(WorkBacklogReport {
            checked,
            validated_height: node.work_validated_height(),
            tip_height: node.state.next_height().saturating_sub(1),
            halted: node.work_gate.as_ref().is_some_and(WorkGate::halted),
        })
    };
    loop {
        if cancel() {
            return finish(checked);
        }
        {
            let node = shared.lock().map_err(poisoned)?;
            let tip = node.state.next_height().saturating_sub(1);
            let Some(validated) = node.work_validated_height() else {
                drop(node);
                return finish(checked);
            };
            if validated.saturating_add(WORK_RELEVANCE_DEPTH) >= tip {
                drop(node);
                return finish(checked);
            }
            if last_report.elapsed() >= Duration::from_secs(30) {
                last_report = Instant::now();
                tracing::info!(
                    target: "work_rule",
                    checked,
                    validated_height = validated,
                    tip_height = tip,
                    "checking stored blocks"
                );
            }
        }
        progress.report(shared, Instant::now());
        match backlog.run_turn(shared, &cancel)? {
            WorkBacklogTurn::Checked(_) => {
                checked += 1;
                progress.checked_one();
                unavailable = 0;
                wait = Duration::from_secs(1);
            }
            WorkBacklogTurn::Unavailable => {
                unavailable += 1;
                let state = {
                    let node = shared.lock().map_err(poisoned)?;
                    node.work_gate
                        .as_ref()
                        .and_then(|gate| gate.checker.as_ref())
                        .map(|checker| checker.engine_state())
                };
                if state != Some(WorkEngineState::Ready) || unavailable >= STARTUP_UNAVAILABLE_TURNS
                {
                    tracing::warn!(
                        target: "work_rule",
                        ?state,
                        checked,
                        "the work engines cannot check stored blocks now; the node opens its services and blocks above the validated height wait for the background check"
                    );
                    return finish(checked);
                }
                sleep_unless(stop, wait);
                wait = (wait * 2).min(Duration::from_secs(30));
            }
            WorkBacklogTurn::Idle | WorkBacklogTurn::Halted | WorkBacklogTurn::Cancelled => {
                return finish(checked);
            }
        }
    }
}

fn sleep_unless(stop: &AtomicBool, duration: Duration) {
    let until = Instant::now() + duration;
    while !stop.load(Ordering::Acquire) {
        let now = Instant::now();
        if now >= until {
            return;
        }
        std::thread::sleep(TICK.min(until - now));
    }
}

/// Stops the background work check when stopped or dropped; a running job
/// is cancelled.
pub struct WorkBacklogHandle {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WorkBacklogHandle {
    pub fn stop(mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for WorkBacklogHandle {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// Starts the background work check; see the module documentation.
pub fn spawn_work_backlog(shared: Arc<Mutex<Node>>) -> io::Result<WorkBacklogHandle> {
    spawn_work_backlog_with_pause(shared, || false)
}

/// Starts the background work check for a node that opens its services
/// without waiting for it: it first checks the active blocks above the
/// validated height, lowest first, as the startup run does, until the
/// validated height is within [`WORK_RELEVANCE_DEPTH`] of the tip or no
/// active block can be checked now; then it goes on as
/// [`spawn_work_backlog`] does.
pub fn spawn_startup_work_backlog(shared: Arc<Mutex<Node>>) -> io::Result<WorkBacklogHandle> {
    spawn_backlog_thread(shared, || false, true)
}

/// Whether the startup order has nothing more to do: the validated height is
/// within [`WORK_RELEVANCE_DEPTH`] of the tip, or there is none.
fn startup_order_done(shared: &Mutex<Node>) -> bool {
    shared.lock().is_ok_and(|node| {
        work_backlog_heights(&node)
            .is_none_or(|(validated, tip)| validated.saturating_add(WORK_RELEVANCE_DEPTH) >= tip)
    })
}

/// Whether the work engines' known answers are due, which a paused
/// background check still runs.
fn known_answers_due(shared: &Mutex<Node>) -> bool {
    shared.lock().is_ok_and(|node| {
        node.work_gate
            .as_ref()
            .and_then(|gate| gate.checker.as_ref())
            .is_some_and(|checker| checker.known_answer_tests_due(Instant::now()))
    })
}

/// Like [`spawn_work_backlog`], but no turn starts while `paused` answers
/// true (a laptop on battery, say), except one that runs the known answers
/// when they are due, so that the engines still qualify and new blocks can
/// still be admitted. That turn also checks one block. Blocks that arrive
/// meanwhile are still checked as they are admitted; only the validated
/// height waits.
pub fn spawn_work_backlog_with_pause(
    shared: Arc<Mutex<Node>>,
    paused: impl Fn() -> bool + Send + 'static,
) -> io::Result<WorkBacklogHandle> {
    spawn_backlog_thread(shared, paused, false)
}

fn spawn_backlog_thread(
    shared: Arc<Mutex<Node>>,
    paused: impl Fn() -> bool + Send + 'static,
    startup_first: bool,
) -> io::Result<WorkBacklogHandle> {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let paused_flag = lock(&shared).work_backlog_paused_flag();
    let thread = std::thread::Builder::new()
        .name("cmfd-work-backlog".to_owned())
        .spawn(move || {
            let mut backlog = if startup_first {
                WorkBacklog::for_startup()
            } else {
                WorkBacklog::new()
            };
            let mut progress = BacklogProgress::new();
            let mut wait = Duration::from_secs(1);
            let cancel = || flag.load(Ordering::Acquire);
            let show_paused = |value: bool| {
                if let Some(paused_flag) = &paused_flag {
                    paused_flag.store(value, Ordering::Release);
                }
            };
            while !cancel() {
                if backlog.startup && startup_order_done(&shared) {
                    backlog.startup = false;
                    tracing::info!(target: "work_rule", "the stored active blocks are checked to near the tip; the background check goes on with the other stored blocks");
                }
                progress.report(&shared, Instant::now());
                let is_paused = paused();
                show_paused(is_paused);
                if is_paused && !known_answers_due(&shared) {
                    sleep_unless(&flag, IDLE_POLL);
                    continue;
                }
                match backlog.run_turn(&shared, &cancel) {
                    Ok(WorkBacklogTurn::Checked(_)) => {
                        progress.checked_one();
                        wait = Duration::from_secs(1);
                        // Give way to admissions waiting for the lane, but
                        // never for longer than the reserved interval.
                        let until = Instant::now() + WORK_BACKLOG_MAX_YIELD;
                        while !cancel()
                            && Instant::now() < until
                            && shared
                                .lock()
                                .is_ok_and(|node| node.work_lane_has_waiters())
                        {
                            std::thread::sleep(TICK);
                        }
                    }
                    // No active block can be checked now in the startup
                    // order; the other stored blocks may be.
                    Ok(WorkBacklogTurn::Idle) if backlog.startup => {
                        backlog.startup = false;
                    }
                    Ok(WorkBacklogTurn::Idle | WorkBacklogTurn::Halted) => {
                        sleep_unless(&flag, IDLE_POLL);
                    }
                    Ok(WorkBacklogTurn::Unavailable) => {
                        sleep_unless(&flag, wait);
                        wait = (wait * 2).min(RETRY_UNAVAILABLE);
                    }
                    Ok(WorkBacklogTurn::Cancelled) => break,
                    Err(error) => {
                        tracing::warn!(target: "work_rule", %error, "the background work check will retry later");
                        sleep_unless(&flag, RETRY_UNAVAILABLE);
                    }
                }
            }
            show_paused(false);
        })?;
    Ok(WorkBacklogHandle {
        stop,
        thread: Some(thread),
    })
}

#[cfg(test)]
#[path = "backlog_tests.rs"]
mod tests;
