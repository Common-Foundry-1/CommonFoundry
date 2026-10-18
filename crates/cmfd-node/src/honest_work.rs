//! Re-execution of ProductionV4 work for the release work rule.
//!
//! Above the release checkpoint, nodes independently re-execute each block's
//! work from its header and nonce and compare the result with the block's
//! work digest. This module holds the parts that do not depend on the
//! admission path:
//!
//! - [`WorkEngine`]: one implementation of the forward pass, with one or more
//!   workers. The CPU engine runs the consensus executor over the
//!   authenticated model bank; the GPU engine borrows an idle persistent
//!   replay worker and never waits for one.
//! - [`HonestWorkChecker`]: runs the engines, keeps a capped memo of results,
//!   qualifies each worker against known answers and decides how far a
//!   mismatch can be trusted.
//! - [`store`]: the persisted verified/invalid set and the halt marker.
//!
//! How far a result can be trusted is its [`WorkProvenance`]. A mismatch that
//! one engine reports on its own is `OwnEngine`: the caller may refuse the
//! block, but must not record it as invalid for good, because a defect in that
//! engine would reproduce exactly. Only a mismatch that a second, structurally
//! different engine reproduces (CPU and GPU) is `Confirmed`, and only that
//! yields a [`ConfirmedWorkMismatch`], which anything durable requires. While
//! the other engine is ready, an `OwnEngine` mismatch is never final: the next
//! check of that block runs the other engine. An engine failure is never a
//! verdict about the block: it is always reported as
//! [`WorkVerdict::Unavailable`].
//!
//! What the caller may do with a verdict:
//!
//! - Any mismatch may refuse this admission, whether or not it is final.
//! - Only a confirmed mismatch may cost the sender a penalty or a cooldown.
//!   A single engine's mismatch costs it nothing: that engine may be the one
//!   at fault, and the block is refused all the same.
//! - A block id may be remembered as rejected, so that a re-send is refused
//!   without reaching [`HonestWorkChecker::check`], only when
//!   [`WorkMismatch::cacheable`] says so: a confirmed mismatch, or a single
//!   engine's mismatch on a node with no ready worker of the other kind.
//!   Any other mismatch must reach `check` again when the block is re-sent,
//!   so that the other engine can settle it. A remembered single engine's
//!   mismatch stands only while [`HonestWorkChecker::holds_lone_final_mismatch`]
//!   does: once a worker of the other kind is ready, the worker that found
//!   it is retired or has not reproduced a known answer within
//!   [`WORK_MISMATCH_KAT_WINDOW`], its result is displaced, or two engines
//!   have since agreed on that challenge, a running node checks the block
//!   again when it is re-sent (one known answer per worker per window, not
//!   one engine run per block, when nothing else changed; none at all when
//!   two engines agreed). Nothing remembered for it is persisted, so the next start
//!   (after `cmfd-node work-reconsider`, say, which runs with the node
//!   stopped) checks the block again too.
//! - Only a [`ConfirmedWorkMismatch`] may be persisted, propagated to
//!   descendants or halt the node.
//! - [`WorkVerdict::Unavailable`] is retryable and is never cached, persisted
//!   or held against the sender. Its text is for the node's log only; a peer
//!   is sent a fixed message.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use cmfd_consensus::{PRODUCTION_V4_MODEL_MANIFEST_DIGEST, forgematrix_v4_work_digest};
use thiserror::Error;

pub mod store;

/// Results kept in the memo; the oldest is dropped first.
pub const WORK_MEMO_CAPACITY: usize = 4_096;
/// How often workers are qualified again against the known answers while
/// every worker is ready.
pub const WORK_KAT_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// While a worker is not ready, the known answers are due again this long
/// after the last round; the wait doubles with each round that leaves a
/// worker not ready, up to [`WORK_KAT_RETRY_MAX`].
pub const WORK_KAT_RETRY_MIN: Duration = Duration::from_secs(60);
/// The longest wait between rounds while a worker is not ready.
pub const WORK_KAT_RETRY_MAX: Duration = Duration::from_secs(15 * 60);
/// How long a challenge the two engines disagreed on is answered as
/// unavailable without running either engine again. Retiring either of the
/// two workers ends it early.
pub const WORK_DISAGREEMENT_HOLD: Duration = Duration::from_secs(10 * 60);
/// A mismatch only one engine found is this node's answer for a block only
/// if the worker that found it reproduced a known answer this recently;
/// otherwise that worker runs one first. One known answer per worker per
/// window, however many blocks differ.
pub const WORK_MISMATCH_KAT_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Challenges held after a disagreement; the oldest is dropped first.
const WORK_DISAGREEMENT_CAPACITY: usize = 256;
/// Known answers a CPU worker must reproduce to be qualified.
pub const CPU_KAT_VECTORS: usize = 1;
/// Known answers a GPU worker must reproduce to be qualified.
pub const GPU_KAT_VECTORS: usize = 2;

/// A public mainnet block whose work was re-executed by independent engines:
/// its challenge digest and the final-activation digest that work produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkKnownAnswer {
    pub height: u64,
    pub challenge_digest: [u8; 32],
    pub final_activation_digest: [u8; 32],
}

/// Known answers, newest first. They are entries of
/// `cmfd-consensus/data/forgematrix_v4_execution_vectors_v1.json`.
pub const WORK_KNOWN_ANSWERS: [WorkKnownAnswer; 2] = [
    WorkKnownAnswer {
        height: 17_859,
        challenge_digest: hex32("ffb278868d7cf0d7af7b02552b4143b8513d6d0d8e9ede83773b85d4a4591e6b"),
        final_activation_digest: hex32(
            "301a6b5bca49657ede1be86b219a946fc0ebfa63d45ce6aeb6480498ff523589",
        ),
    },
    WorkKnownAnswer {
        height: 4_082,
        challenge_digest: hex32("02658192604e1933fbbf7e19d8034fd480e7facdda5cb840550fe84403af4e38"),
        final_activation_digest: hex32(
            "71c631ef54e1b9dd863ae64a520e2368ebdbb45e1695d99146d8eaf0493d9d9d",
        ),
    },
];

const _: () = assert!(CPU_KAT_VECTORS <= WORK_KNOWN_ANSWERS.len());
const _: () = assert!(GPU_KAT_VECTORS <= WORK_KNOWN_ANSWERS.len());

const fn hex32(text: &str) -> [u8; 32] {
    const fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("lowercase hex expected"),
        }
    }
    let bytes = text.as_bytes();
    assert!(bytes.len() == 64);
    let mut out = [0_u8; 32];
    let mut index = 0;
    while index < 32 {
        out[index] = (nibble(bytes[2 * index]) << 4) | nibble(bytes[2 * index + 1]);
        index += 1;
    }
    out
}

/// The work digest a final-activation digest yields for `challenge_digest`.
pub fn honest_work_digest(
    challenge_digest: [u8; 32],
    final_activation_digest: [u8; 32],
) -> [u8; 32] {
    forgematrix_v4_work_digest(
        PRODUCTION_V4_MODEL_MANIFEST_DIGEST,
        challenge_digest,
        final_activation_digest,
    )
}

/// The kind of an engine. Two engines are independent only when their kinds
/// differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WorkEngineKind {
    Cpu,
    Gpu,
}

impl WorkEngineKind {
    /// The kind that can confirm this one.
    pub fn other(self) -> Self {
        match self {
            Self::Cpu => Self::Gpu,
            Self::Gpu => Self::Cpu,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Cpu => 0,
            Self::Gpu => 1,
        }
    }
}

/// Why an engine did not produce a result. None of these says anything about
/// the block being checked.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WorkEngineError {
    /// The worker could not take the job now (it is in use). Nothing is known
    /// to be wrong with it.
    #[error("work engine is busy")]
    Busy,
    /// The worker is not running: it failed earlier and has not been started
    /// again. It is not used until it reproduces the known answers.
    #[error("work engine worker is not running: {0}")]
    Stopped(String),
    /// The worker failed this job: a crash, timeout or read error.
    #[error("work engine failed: {0}")]
    Failed(String),
    /// Model data or output failed an integrity check. The worker is not
    /// trusted again until it reproduces the known answers.
    #[error("work engine integrity check failed: {0}")]
    Integrity(String),
    /// The caller stopped the job before it finished. Nothing is known about
    /// the worker or the block.
    #[error("work engine job was cancelled")]
    Cancelled,
}

/// Asked during a job; once it returns true the job stops and reports
/// [`WorkEngineError::Cancelled`].
pub type WorkCancel<'a> = dyn Fn() -> bool + Sync + 'a;

/// One implementation of the ProductionV4 forward pass.
pub trait WorkEngine: Send + Sync {
    fn kind(&self) -> WorkEngineKind;

    /// The workers jobs can run on, numbered from 0. Each one is qualified
    /// and retired on its own, and the checker names the worker for every
    /// job. The count does not change while the engine is in use.
    fn workers(&self) -> usize {
        1
    }

    /// The final-activation digest of the work for `challenge_digest`,
    /// computed on `worker`. With `authenticate`, the engine also checks
    /// model data against its authenticated roots where it can.
    fn final_activation_digest(
        &self,
        challenge_digest: [u8; 32],
        worker: usize,
        authenticate: bool,
    ) -> Result<[u8; 32], WorkEngineError>;

    /// [`final_activation_digest`](Self::final_activation_digest) that stops
    /// with [`WorkEngineError::Cancelled`] once `cancel` returns true. An
    /// engine whose jobs are short checks only before it starts: the GPU
    /// engine does, since each replay is bounded by its own timeout, and a
    /// result it finishes after a cancel is kept like any other.
    fn final_activation_digest_cancellable(
        &self,
        challenge_digest: [u8; 32],
        worker: usize,
        authenticate: bool,
        cancel: &WorkCancel<'_>,
    ) -> Result<[u8; 32], WorkEngineError> {
        if cancel() {
            return Err(WorkEngineError::Cancelled);
        }
        self.final_activation_digest(challenge_digest, worker, authenticate)
    }
}

/// How far a work result can be trusted, least first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkProvenance {
    /// Supplied by the pool that produced the block, not computed here.
    RecordHonest,
    /// Computed by one of this node's engines, with no independent check.
    OwnEngine,
    /// Two independent engines produced the same result.
    Confirmed,
}

/// A found block's final-activation digest as this pool's own replay worker
/// produced it: the only input [`HonestWorkChecker::record_honest`] takes.
/// Only this crate builds one, from its replay worker's output for the
/// block's challenge (or, on a network without replay workers, from the
/// pool's own computation of the block); never from a digest that a share,
/// a block or a miner supplied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolReplayResult {
    challenge_digest: [u8; 32],
    final_activation_digest: [u8; 32],
    worker: usize,
    /// The final-activation digest the same worker process produced for the
    /// first of [`WORK_KNOWN_ANSWERS`], while the pool still held it after
    /// the block's replay.
    known_answer: Option<[u8; 32]>,
}

impl PoolReplayResult {
    /// The result of GPU replay `worker` (the GPU engine's numbering) for
    /// `challenge_digest`.
    pub(crate) fn new(
        challenge_digest: [u8; 32],
        final_activation_digest: [u8; 32],
        worker: usize,
    ) -> Self {
        Self {
            challenge_digest,
            final_activation_digest,
            worker,
            known_answer: None,
        }
    }

    /// Adds what the same worker process produced for the first known
    /// answer, replayed under the same hold as the block's result.
    #[cfg_attr(not(feature = "production-v4"), allow(dead_code))]
    pub(crate) fn with_known_answer(mut self, known_answer: Option<[u8; 32]>) -> Self {
        self.known_answer = known_answer;
        self
    }

    pub fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }

    pub fn final_activation_digest(&self) -> [u8; 32] {
        self.final_activation_digest
    }

    pub fn worker(&self) -> usize {
        self.worker
    }

    pub fn known_answer(&self) -> Option<[u8; 32]> {
        self.known_answer
    }
}

/// What a block claims about its work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkClaim {
    pub challenge_digest: [u8; 32],
    pub work_digest: [u8; 32],
}

/// A block whose claimed work digest differs from the re-executed work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkMismatch {
    challenge_digest: [u8; 32],
    claimed_work_digest: [u8; 32],
    honest_final_activation_digest: [u8; 32],
    provenance: WorkProvenance,
    cacheable: bool,
}

impl WorkMismatch {
    pub fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }

    pub fn claimed_work_digest(&self) -> [u8; 32] {
        self.claimed_work_digest
    }

    pub fn honest_final_activation_digest(&self) -> [u8; 32] {
        self.honest_final_activation_digest
    }

    pub fn honest_work_digest(&self) -> [u8; 32] {
        honest_work_digest(self.challenge_digest, self.honest_final_activation_digest)
    }

    pub fn provenance(&self) -> WorkProvenance {
        self.provenance
    }

    /// Whether the caller may remember this block as rejected and refuse a
    /// re-send without checking it again. True for a confirmed mismatch, and
    /// for a single engine's mismatch when no worker of the other kind was
    /// ready to check it; false while the other kind could still settle it.
    pub fn cacheable(&self) -> bool {
        self.cacheable
    }

    /// The independently confirmed form of this mismatch, if it is one. Only
    /// this may be persisted as invalid, propagated to descendants or halt the
    /// node.
    pub fn confirmed(&self) -> Option<ConfirmedWorkMismatch> {
        (self.provenance == WorkProvenance::Confirmed).then_some(ConfirmedWorkMismatch {
            challenge_digest: self.challenge_digest,
            claimed_work_digest: self.claimed_work_digest,
        })
    }
}

/// A mismatch that two independent engines reproduced. It can only be
/// obtained from [`WorkMismatch::confirmed`], and the store refuses it for a
/// block with another challenge digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmedWorkMismatch {
    challenge_digest: [u8; 32],
    claimed_work_digest: [u8; 32],
}

impl ConfirmedWorkMismatch {
    pub fn challenge_digest(&self) -> [u8; 32] {
        self.challenge_digest
    }

    pub fn claimed_work_digest(&self) -> [u8; 32] {
        self.claimed_work_digest
    }

    #[cfg(test)]
    pub(crate) fn for_test(challenge_digest: [u8; 32], claimed_work_digest: [u8; 32]) -> Self {
        Self {
            challenge_digest,
            claimed_work_digest,
        }
    }
}

/// Why no verdict could be reached. Always retryable; never cached, persisted
/// or held against the sender.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WorkUnavailable {
    /// No worker has reproduced the known answers yet.
    #[error("work engines are still qualifying")]
    Qualifying,
    /// Every worker has failed its known answers, an integrity check or a
    /// job.
    #[error("work engines have failed")]
    EnginesFailed,
    /// The workers that were tried could not run the job. The error text can
    /// name worker files; it is for the node's log only.
    #[error("work engine unavailable: {0}")]
    Engine(WorkEngineError),
    /// The two engines disagreed with each other and with the block.
    #[error("work engines disagree")]
    EnginesDisagree,
    /// A worker failed its known answer while a block was checked: the GPU
    /// after it agreed with the CPU, or the only engine that ran the block.
    #[error("work engine failed its known answer")]
    KnownAnswerFailed,
    /// The caller cancelled the check before it reached a verdict.
    #[error("work check was cancelled")]
    Cancelled,
}

/// The outcome of checking one block's work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkVerdict {
    /// The re-executed work equals the claim.
    Match(WorkProvenance),
    /// The re-executed work differs from the claim.
    Mismatch(WorkMismatch),
    /// No verdict; retry later.
    Unavailable(WorkUnavailable),
}

/// The checker's view of one worker. For a whole engine: ready if any of its
/// workers is, otherwise qualifying if any is, otherwise failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkEngineHealth {
    /// Has not reproduced the known answers yet.
    Qualifying,
    /// Reproduced the known answers and has not failed since.
    Ready,
    /// Failed its known answers, an integrity check, or (GPU) a job.
    Failed,
}

/// The checker as a whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkEngineState {
    /// No worker is ready and at least one is still qualifying.
    Qualifying,
    /// At least one worker is ready.
    Ready,
    /// Every worker has failed.
    Failed,
}

/// Counts of events an operator should look at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkAlarmCounts {
    /// The two engines produced different results for one challenge.
    pub engine_divergence: u64,
    /// A single engine reported a mismatch that no independent engine
    /// checked.
    pub own_engine_mismatches: u64,
    /// A worker failed its known answers, an integrity check or a job, was
    /// found not running, or could not read a known answer.
    pub engine_failures: u64,
}

/// The result of one round of known-answer tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkKatReport {
    /// `None` when there is no engine of that kind; otherwise its health
    /// after the round.
    pub cpu: Option<WorkEngineHealth>,
    pub gpu: Option<WorkEngineHealth>,
}

/// The checker could not be built from the engines given.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum WorkCheckerConfigError {
    #[error("the work checker needs at least one engine")]
    NoEngine,
    #[error("a work engine was given in the wrong slot for its kind")]
    WrongKind,
}

/// One worker of one engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Producer {
    kind: WorkEngineKind,
    worker: usize,
}

/// A result one worker produced, with that worker's retirement count when it
/// started, so a result from a worker retired meanwhile is never kept.
#[derive(Clone, Copy, Debug)]
struct Run {
    producer: Producer,
    generation: u64,
    final_activation_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct MemoEntry {
    final_activation_digest: [u8; 32],
    provenance: WorkProvenance,
    /// The worker that computed it; for `RecordHonest`, the pool's replay
    /// worker.
    producer: Producer,
    /// For `RecordHonest`: that worker has since reproduced a known answer.
    worker_checked: bool,
    /// For an `OwnEngine` result that differs from a block: the alarm for it
    /// was raised.
    mismatch_reported: bool,
}

/// Results by challenge digest, capped at `capacity`; the oldest goes first.
#[derive(Debug)]
struct WorkMemo {
    entries: HashMap<[u8; 32], MemoEntry>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl WorkMemo {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn get(&self, challenge_digest: &[u8; 32]) -> Option<MemoEntry> {
        self.entries.get(challenge_digest).copied()
    }

    /// Stores `entry` unless a more trusted result is already held. The same
    /// result stored again keeps the note that its alarm was raised.
    fn insert(&mut self, challenge_digest: [u8; 32], entry: MemoEntry) {
        match self.entries.get_mut(&challenge_digest) {
            Some(existing) if existing.provenance > entry.provenance => {}
            Some(existing) => {
                let reported = existing.mismatch_reported
                    && existing.producer == entry.producer
                    && existing.final_activation_digest == entry.final_activation_digest;
                *existing = entry;
                existing.mismatch_reported |= reported;
            }
            None => {
                self.entries.insert(challenge_digest, entry);
                self.order.push_back(challenge_digest);
                while self.order.len() > self.capacity {
                    if let Some(oldest) = self.order.pop_front() {
                        self.entries.remove(&oldest);
                    }
                }
            }
        }
    }

    fn remove(&mut self, challenge_digest: &[u8; 32]) -> bool {
        let removed = self.entries.remove(challenge_digest).is_some();
        if removed {
            self.order.retain(|held| held != challenge_digest);
        }
        removed
    }

    /// Drops every result `producer` computed or supplied that was not
    /// independently confirmed.
    fn retain_not_from(&mut self, producer: Producer) {
        self.entries.retain(|_, entry| {
            entry.provenance == WorkProvenance::Confirmed || entry.producer != producer
        });
        let entries = &self.entries;
        self.order
            .retain(|challenge_digest| entries.contains_key(challenge_digest));
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Clone, Copy, Debug)]
struct WorkerSlot {
    health: WorkEngineHealth,
    /// How often this worker was retired.
    generation: u64,
    /// When this worker last reproduced its known answers, in a round or
    /// before a mismatch only it found.
    passed_at: Option<Instant>,
    /// Its last job or known answer failed to read model data. Cleared by
    /// the next result it produces.
    erroring: bool,
}

impl WorkerSlot {
    /// Ready, with no read failure since its last result.
    fn settled(&self) -> bool {
        self.health == WorkEngineHealth::Ready && !self.erroring
    }

    /// Whether a round of known answers tests this worker at `now`.
    fn kat_due(&self, now: Instant) -> bool {
        !self.settled()
            || self
                .passed_at
                .is_none_or(|at| now.saturating_duration_since(at) >= WORK_KAT_INTERVAL)
    }

    /// Settled, and reproduced a known answer within
    /// [`WORK_MISMATCH_KAT_WINDOW`] of `now`.
    fn passed_recently(&self, now: Instant) -> bool {
        self.settled()
            && self
                .passed_at
                .is_some_and(|at| now.saturating_duration_since(at) < WORK_MISMATCH_KAT_WINDOW)
    }
}

#[derive(Debug)]
struct CheckerState {
    memo: WorkMemo,
    /// Workers by engine kind; empty for an absent engine.
    slots: [Vec<WorkerSlot>; 2],
    last_kat: Option<Instant>,
    /// Rounds in a row that ended with a worker not settled.
    kat_retries: u32,
    /// Challenges the two engines disagreed on, oldest first.
    disagreements: VecDeque<Disagreement>,
    /// By engine kind: how long the last block job that produced a result
    /// took, and the last passing known answers on one worker.
    run_time: [Option<Duration>; 2],
    known_answer_time: [Option<Duration>; 2],
    /// The last challenge checked on the CPU because the GPU workers were
    /// busy, so that is logged once per block.
    cpu_fallback: Option<[u8; 32]>,
}

/// Two workers that produced different results for one challenge.
#[derive(Clone, Copy, Debug)]
struct Disagreement {
    challenge_digest: [u8; 32],
    workers: [Producer; 2],
    at: Instant,
}

impl CheckerState {
    fn slot(&self, producer: Producer) -> Option<&WorkerSlot> {
        self.slots[producer.kind.index()].get(producer.worker)
    }

    fn slot_mut(&mut self, producer: Producer) -> Option<&mut WorkerSlot> {
        self.slots[producer.kind.index()].get_mut(producer.worker)
    }

    /// Whether a mismatch `producer` alone found is final: no worker of the
    /// other kind is ready, and `producer` reproduced a known answer
    /// recently.
    fn lone_mismatch_final(&self, producer: Producer, now: Instant) -> bool {
        !self.any_ready(producer.kind.other())
            && self
                .slot(producer)
                .is_some_and(|slot| slot.passed_recently(now))
    }

    fn any_ready(&self, kind: WorkEngineKind) -> bool {
        self.slots[kind.index()]
            .iter()
            .any(|slot| slot.health == WorkEngineHealth::Ready)
    }

    fn all_settled(&self) -> bool {
        self.slots.iter().flatten().all(WorkerSlot::settled)
    }

    /// Whether the engines disagreed on `challenge_digest` within
    /// [`WORK_DISAGREEMENT_HOLD`] of `now`. Older entries are dropped.
    fn held(&mut self, challenge_digest: &[u8; 32], now: Instant) -> bool {
        self.disagreements
            .retain(|held| now.saturating_duration_since(held.at) < WORK_DISAGREEMENT_HOLD);
        self.disagreements
            .iter()
            .any(|held| held.challenge_digest == *challenge_digest)
    }

    fn hold(&mut self, disagreement: Disagreement) {
        self.forget_disagreement(&disagreement.challenge_digest);
        self.disagreements.push_back(disagreement);
        while self.disagreements.len() > WORK_DISAGREEMENT_CAPACITY {
            self.disagreements.pop_front();
        }
    }

    fn forget_disagreement(&mut self, challenge_digest: &[u8; 32]) {
        self.disagreements
            .retain(|held| held.challenge_digest != *challenge_digest);
    }

    /// Whether `run`'s worker is still ready and was not retired since.
    fn current(&self, run: &Run) -> bool {
        self.slot(run.producer).is_some_and(|slot| {
            slot.health == WorkEngineHealth::Ready && slot.generation == run.generation
        })
    }

    fn health(&self, kind: WorkEngineKind) -> Option<WorkEngineHealth> {
        aggregate_health(self.slots[kind.index()].iter())
    }
}

fn aggregate_health<'a>(slots: impl Iterator<Item = &'a WorkerSlot>) -> Option<WorkEngineHealth> {
    let healths = slots.map(|slot| slot.health).collect::<Vec<_>>();
    if healths.is_empty() {
        None
    } else if healths.contains(&WorkEngineHealth::Ready) {
        Some(WorkEngineHealth::Ready)
    } else if healths.contains(&WorkEngineHealth::Qualifying) {
        Some(WorkEngineHealth::Qualifying)
    } else {
        Some(WorkEngineHealth::Failed)
    }
}

/// Worker order for jobs: workers 1.. first, then worker 0, which on a pool
/// also serves single shares and proofs.
fn worker_order(count: usize) -> impl Iterator<Item = usize> {
    (1..count).chain(0..count.min(1))
}

fn kat_retry_wait(retries: u32) -> Duration {
    let doublings = retries.saturating_sub(1).min(16);
    WORK_KAT_RETRY_MIN
        .saturating_mul(1 << doublings)
        .min(WORK_KAT_RETRY_MAX)
}

#[derive(Debug, Default)]
struct WorkAlarms {
    engine_divergence: AtomicU64,
    own_engine_mismatches: AtomicU64,
    engine_failures: AtomicU64,
}

/// Outcome of a single known-answer run on one worker.
enum KatOutcome {
    Pass,
    /// The worker could not take the job (busy or not running).
    Busy,
    /// A CPU read failed twice; nothing is known about the worker.
    Error(String),
    /// A wrong answer, an integrity failure or a failed GPU job.
    Fail(String),
}

/// Runs the work engines for blocks above the release checkpoint.
///
/// It never takes a node lock and holds its own lock only around the memo and
/// worker state, never while an engine runs. Workers start out qualifying:
/// until [`run_known_answer_tests`](Self::run_known_answer_tests) qualifies
/// one, every check that is not answered by the memo is unavailable. The
/// caller runs that whenever [`known_answer_tests_due`](Self::known_answer_tests_due)
/// says so, which is soon after a worker was retired.
pub struct HonestWorkChecker {
    cpu: Option<Arc<dyn WorkEngine>>,
    gpu: Option<Arc<dyn WorkEngine>>,
    authenticate: bool,
    state: Mutex<CheckerState>,
    alarms: WorkAlarms,
}

impl HonestWorkChecker {
    /// `authenticate` is passed to every block check; known-answer tests
    /// always ask for it, which the CPU engine honours (the GPU engine has no
    /// model data of its own to check).
    pub fn new(
        cpu: Option<Arc<dyn WorkEngine>>,
        gpu: Option<Arc<dyn WorkEngine>>,
        authenticate: bool,
    ) -> Result<Self, WorkCheckerConfigError> {
        Self::with_memo_capacity(cpu, gpu, authenticate, WORK_MEMO_CAPACITY)
    }

    fn with_memo_capacity(
        cpu: Option<Arc<dyn WorkEngine>>,
        gpu: Option<Arc<dyn WorkEngine>>,
        authenticate: bool,
        memo_capacity: usize,
    ) -> Result<Self, WorkCheckerConfigError> {
        if cpu.is_none() && gpu.is_none() {
            return Err(WorkCheckerConfigError::NoEngine);
        }
        if cpu
            .as_ref()
            .is_some_and(|engine| engine.kind() != WorkEngineKind::Cpu)
            || gpu
                .as_ref()
                .is_some_and(|engine| engine.kind() != WorkEngineKind::Gpu)
        {
            return Err(WorkCheckerConfigError::WrongKind);
        }
        let slots_for = |engine: &Option<Arc<dyn WorkEngine>>| {
            let workers = engine.as_ref().map_or(0, |engine| engine.workers().max(1));
            vec![
                WorkerSlot {
                    health: WorkEngineHealth::Qualifying,
                    generation: 0,
                    passed_at: None,
                    erroring: false,
                };
                workers
            ]
        };
        let slots = [slots_for(&cpu), slots_for(&gpu)];
        Ok(Self {
            cpu,
            gpu,
            authenticate,
            state: Mutex::new(CheckerState {
                memo: WorkMemo::new(memo_capacity),
                slots,
                last_kat: None,
                kat_retries: 0,
                disagreements: VecDeque::new(),
                run_time: [None; 2],
                known_answer_time: [None; 2],
                cpu_fallback: None,
            }),
            alarms: WorkAlarms::default(),
        })
    }

    fn state(&self) -> MutexGuard<'_, CheckerState> {
        // The state is a few plain fields, each always left consistent.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn engine(&self, kind: WorkEngineKind) -> Option<&Arc<dyn WorkEngine>> {
        match kind {
            WorkEngineKind::Cpu => self.cpu.as_ref(),
            WorkEngineKind::Gpu => self.gpu.as_ref(),
        }
    }

    /// The health of the engine of `kind`, or `None` if there is none.
    pub fn engine_health(&self, kind: WorkEngineKind) -> Option<WorkEngineHealth> {
        self.state().health(kind)
    }

    /// The health of one worker, or `None` if there is no such worker.
    pub fn worker_health(&self, kind: WorkEngineKind, worker: usize) -> Option<WorkEngineHealth> {
        self.state()
            .slot(Producer { kind, worker })
            .map(|slot| slot.health)
    }

    /// Whether one worker's last job or known answer could not read model
    /// data (a missing or unreadable bank, for example), or `None` if there
    /// is no such worker. It keeps its health, but the known answers are
    /// tried again soon instead of after [`WORK_KAT_INTERVAL`].
    pub fn worker_erroring(&self, kind: WorkEngineKind, worker: usize) -> Option<bool> {
        self.state()
            .slot(Producer { kind, worker })
            .map(|slot| slot.erroring)
    }

    /// The state of the checker as a whole.
    pub fn engine_state(&self) -> WorkEngineState {
        match aggregate_health(self.state().slots.iter().flatten()) {
            Some(WorkEngineHealth::Ready) => WorkEngineState::Ready,
            Some(WorkEngineHealth::Qualifying) => WorkEngineState::Qualifying,
            _ => WorkEngineState::Failed,
        }
    }

    /// Whether a mismatch can be confirmed here: a CPU and a GPU worker are
    /// both ready.
    pub fn has_independent_engines(&self) -> bool {
        let state = self.state();
        state.any_ready(WorkEngineKind::Cpu) && state.any_ready(WorkEngineKind::Gpu)
    }

    /// How long a check that computes at `now` is expected to take, from the
    /// last measured job on the first kind of engine with a ready worker
    /// (GPU first), plus its last known answers when a mismatch that engine
    /// alone found would have to run them first: no worker of the other kind
    /// is ready, and that worker did not pass them within
    /// [`WORK_MISMATCH_KAT_WINDOW`]. `None` before that engine produced a
    /// result.
    pub fn expected_check_time(&self, now: Instant) -> Option<Duration> {
        let state = self.state();
        let kind = [WorkEngineKind::Gpu, WorkEngineKind::Cpu]
            .into_iter()
            .find(|kind| state.any_ready(*kind))?;
        let run = state.run_time[kind.index()]?;
        let slots = &state.slots[kind.index()];
        let first = worker_order(slots.len())
            .find(|worker| slots[*worker].health == WorkEngineHealth::Ready)?;
        let known_answers_due =
            !state.any_ready(kind.other()) && !slots[first].passed_recently(now);
        Some(if known_answers_due {
            run.saturating_add(state.known_answer_time[kind.index()].unwrap_or_default())
        } else {
            run
        })
    }

    /// Sets the measured job and known-answer times of `kind`, as checks
    /// that took that long would.
    #[cfg(test)]
    pub(crate) fn set_check_times(
        &self,
        kind: WorkEngineKind,
        run: Duration,
        known_answers: Option<Duration>,
    ) {
        let mut state = self.state();
        state.run_time[kind.index()] = Some(run);
        state.known_answer_time[kind.index()] = known_answers;
    }

    pub fn alarms(&self) -> WorkAlarmCounts {
        WorkAlarmCounts {
            engine_divergence: self.alarms.engine_divergence.load(Ordering::Relaxed),
            own_engine_mismatches: self.alarms.own_engine_mismatches.load(Ordering::Relaxed),
            engine_failures: self.alarms.engine_failures.load(Ordering::Relaxed),
        }
    }

    /// Whether this node's own engines already hold a result for
    /// `challenge_digest`, so its check answers from the memo (or, for a
    /// single engine's mismatch, runs only the confirming job or one known
    /// answer). A pool-supplied result does not count.
    pub fn memo_settled(&self, challenge_digest: [u8; 32]) -> bool {
        self.state()
            .memo
            .get(&challenge_digest)
            .is_some_and(|entry| entry.provenance >= WorkProvenance::OwnEngine)
    }

    /// Results currently held in the memo.
    pub fn memo_len(&self) -> usize {
        self.state().memo.len()
    }

    /// Forgets the memoized result for `challenge_digest`, confirmed or not,
    /// and any disagreement held for it, so its next check computes again
    /// (for an operator's reconsider). Returns whether a result was held.
    pub fn forget(&self, challenge_digest: [u8; 32]) -> bool {
        let mut state = self.state();
        state.forget_disagreement(&challenge_digest);
        state.memo.remove(&challenge_digest)
    }

    /// Whether a round of known answers is due at `now`: never run; or a
    /// ready worker last passed [`WORK_KAT_INTERVAL`] ago; or, while a worker
    /// is not ready (qualifying, retired or busy) or its reads are failing,
    /// [`WORK_KAT_RETRY_MIN`] after the last round, doubling with each round
    /// that leaves one so, up to [`WORK_KAT_RETRY_MAX`].
    pub fn known_answer_tests_due(&self, now: Instant) -> bool {
        let state = self.state();
        let Some(last) = state.last_kat else {
            return true;
        };
        if !state.all_settled()
            && now.saturating_duration_since(last) >= kat_retry_wait(state.kat_retries)
        {
            return true;
        }
        state
            .slots
            .iter()
            .flatten()
            .any(|slot| slot.settled() && slot.kat_due(now))
    }

    /// Runs the known answers (CPU: [`CPU_KAT_VECTORS`], GPU:
    /// [`GPU_KAT_VECTORS`]) on every worker that is not ready, whose reads
    /// are failing, or that last passed [`WORK_KAT_INTERVAL`] ago; a ready
    /// worker that passed more recently is left alone. A worker that
    /// reproduces them all becomes ready, including one that had failed,
    /// unless it was retired again while the round ran; one that does not
    /// becomes failed. A busy worker, or a CPU whose read failed twice, keeps
    /// its health and is tried again soon.
    pub fn run_known_answer_tests(&self) -> WorkKatReport {
        self.run_known_answer_tests_at(Instant::now(), &|| false)
    }

    /// [`run_known_answer_tests`](Self::run_known_answer_tests) that stops
    /// once `cancel` returns true: a worker whose round is cut short keeps
    /// its health, as a busy one does.
    pub fn run_known_answer_tests_cancellable(&self, cancel: &WorkCancel<'_>) -> WorkKatReport {
        self.run_known_answer_tests_at(Instant::now(), cancel)
    }

    fn run_known_answer_tests_at(&self, now: Instant, cancel: &WorkCancel<'_>) -> WorkKatReport {
        for kind in [WorkEngineKind::Cpu, WorkEngineKind::Gpu] {
            let Some(engine) = self.engine(kind) else {
                continue;
            };
            let vectors = match kind {
                WorkEngineKind::Cpu => CPU_KAT_VECTORS,
                WorkEngineKind::Gpu => GPU_KAT_VECTORS,
            };
            let due = {
                let state = self.state();
                state.slots[kind.index()]
                    .iter()
                    .enumerate()
                    .filter(|(_, slot)| slot.kat_due(now))
                    .map(|(worker, slot)| (worker, slot.generation))
                    .collect::<Vec<_>>()
            };
            for (worker, generation) in due {
                let producer = Producer { kind, worker };
                let started = Instant::now();
                match run_known_answers(engine.as_ref(), worker, vectors, cancel) {
                    KatOutcome::Pass => {
                        let mut state = self.state();
                        state.known_answer_time[kind.index()] = Some(started.elapsed());
                        if let Some(slot) = state.slot_mut(producer)
                            && slot.generation == generation
                        {
                            slot.health = WorkEngineHealth::Ready;
                            slot.passed_at = Some(now);
                            slot.erroring = false;
                        }
                    }
                    KatOutcome::Busy => {}
                    KatOutcome::Error(reason) => self.note_kat_error(producer, &reason),
                    KatOutcome::Fail(reason) => self.mark_failed(producer, &reason),
                }
            }
        }
        let mut state = self.state();
        // A round cut short is not a round: the next one is not put off.
        if cancel() {
            return WorkKatReport {
                cpu: state.health(WorkEngineKind::Cpu),
                gpu: state.health(WorkEngineKind::Gpu),
            };
        }
        state.last_kat = Some(now);
        state.kat_retries = if state.all_settled() {
            0
        } else {
            state.kat_retries.saturating_add(1)
        };
        WorkKatReport {
            cpu: state.health(WorkEngineKind::Cpu),
            gpu: state.health(WorkEngineKind::Gpu),
        }
    }

    /// Records the final-activation digest that this pool's own GPU replay
    /// produced for a block it found. It never rejects a block on its own,
    /// and is trusted as a match only after that worker reproduces a known
    /// answer, and only while the GPU engine has that worker and it is
    /// ready.
    ///
    /// When the result carries the known answer that the same worker process
    /// replayed right after the block, under the same hold, a correct one
    /// counts as that known answer and nothing runs again; a wrong one means
    /// the result is not recorded at all, that worker is retired until its
    /// known answers pass again, and the node's other engines run the block.
    /// Without one, a known answer runs on that worker when the block is
    /// checked.
    ///
    /// It takes a [`PoolReplayResult`], which only the pool's own replay
    /// produces, never a value taken from a share, a block or a miner: a
    /// known answer on the worker shows that the worker computes correctly,
    /// not where the digest came from.
    pub fn record_honest(&self, replay: PoolReplayResult) {
        let worker_checked = match replay.known_answer {
            None => false,
            Some(digest) if digest == WORK_KNOWN_ANSWERS[0].final_activation_digest => true,
            Some(_) => {
                tracing::warn!(
                    target: "work_rule",
                    worker = replay.worker,
                    "the pool replay worker did not reproduce its known answer; its result for a found block is not used"
                );
                let producer = Producer {
                    kind: WorkEngineKind::Gpu,
                    worker: replay.worker,
                };
                if self.state().slot(producer).is_some() {
                    self.mark_failed(producer, "known answer not reproduced after a found block");
                }
                return;
            }
        };
        self.state().memo.insert(
            replay.challenge_digest,
            MemoEntry {
                final_activation_digest: replay.final_activation_digest,
                provenance: WorkProvenance::RecordHonest,
                producer: Producer {
                    kind: WorkEngineKind::Gpu,
                    worker: replay.worker,
                },
                worker_checked,
                mismatch_reported: false,
            },
        );
    }

    /// A mismatch already known from this node's own engines, without running
    /// any engine. A pool-supplied result never rejects a block, and neither
    /// does a single engine's mismatch while the other kind of engine is
    /// ready, or while its worker has not reproduced a known answer within
    /// [`WORK_MISMATCH_KAT_WINDOW`]: that block must go through
    /// [`check`](Self::check), which then confirms, overturns or re-tests
    /// it. Every mismatch returned here is
    /// [`cacheable`](WorkMismatch::cacheable). A single engine's mismatch
    /// whose alarm was not raised yet raises it here.
    pub fn memo_mismatch(&self, claim: WorkClaim) -> Option<WorkMismatch> {
        let entry = self.final_memo_entry(claim)?;
        match verdict_from_entry(claim, entry) {
            WorkVerdict::Mismatch(mismatch) => {
                if entry.provenance == WorkProvenance::OwnEngine && !entry.mismatch_reported {
                    self.report_own_engine_mismatch(claim.challenge_digest, entry.producer.kind);
                }
                Some(mismatch)
            }
            _ => None,
        }
    }

    /// Whether [`memo_mismatch`](Self::memo_mismatch) would refuse `claim` on
    /// one engine's word alone, without raising any alarm. A mismatch two
    /// engines have since agreed on does not count.
    pub fn holds_lone_final_mismatch(&self, claim: WorkClaim) -> bool {
        self.final_memo_entry(claim).is_some_and(|entry| {
            entry.provenance == WorkProvenance::OwnEngine
                && !work_matches(claim, entry.final_activation_digest)
        })
    }

    /// Makes every worker's last known answer older than
    /// [`WORK_MISMATCH_KAT_WINDOW`], so a mismatch only one engine finds
    /// next re-tests its worker first.
    #[cfg(test)]
    pub(crate) fn age_known_answers(&self) {
        let at = Instant::now().checked_sub(WORK_MISMATCH_KAT_WINDOW + Duration::from_secs(1));
        let mut state = self.state();
        for slot in state.slots.iter_mut().flatten() {
            slot.passed_at = at;
        }
    }

    /// The memoized result for `claim`'s challenge, if it is this node's
    /// final answer without running any engine; see
    /// [`memo_mismatch`](Self::memo_mismatch).
    fn final_memo_entry(&self, claim: WorkClaim) -> Option<MemoEntry> {
        let state = self.state();
        let entry = state.memo.get(&claim.challenge_digest)?;
        let final_here = match entry.provenance {
            WorkProvenance::RecordHonest => false,
            WorkProvenance::OwnEngine => state.lone_mismatch_final(entry.producer, Instant::now()),
            WorkProvenance::Confirmed => true,
        };
        final_here.then_some(entry)
    }

    /// Whether this node's own engines already hold a result that matches
    /// `claim`, and how far it is trusted: [`check`](Self::check) would
    /// answer such a claim from the memo without running any engine.
    pub fn memo_match(&self, claim: WorkClaim) -> Option<WorkProvenance> {
        let entry = self.state().memo.get(&claim.challenge_digest)?;
        (entry.provenance >= WorkProvenance::OwnEngine
            && work_matches(claim, entry.final_activation_digest))
        .then_some(entry.provenance)
    }

    /// Whether the memo holds a result for `claim`'s challenge that differs
    /// from the claim, however far that result is trusted. Raises no alarm.
    pub fn memo_differs(&self, claim: WorkClaim) -> bool {
        self.state()
            .memo
            .get(&claim.challenge_digest)
            .is_some_and(|entry| !work_matches(claim, entry.final_activation_digest))
    }

    /// Computes the work for `challenge_digest` ahead of a check, so that the
    /// check later answers from the memo. No verdict and no confirmation: if
    /// the result differs from the block, the check runs the other engine,
    /// or a known answer on the same worker when no other engine is ready.
    pub fn prewarm(&self, challenge_digest: [u8; 32]) -> Result<(), WorkUnavailable> {
        self.prewarm_cancellable(challenge_digest, &|| false)
    }

    /// [`prewarm`](Self::prewarm) for a caller that may give up: once
    /// `cancel` returns true, a running job stops and nothing is kept.
    pub fn prewarm_cancellable(
        &self,
        challenge_digest: [u8; 32],
        cancel: &WorkCancel<'_>,
    ) -> Result<(), WorkUnavailable> {
        if self
            .state()
            .memo
            .get(&challenge_digest)
            .is_some_and(|entry| entry.provenance >= WorkProvenance::OwnEngine)
        {
            return Ok(());
        }
        if self.state().held(&challenge_digest, Instant::now()) {
            return Err(WorkUnavailable::EnginesDisagree);
        }
        let run = self.run_first_available(challenge_digest, cancel)?;
        self.memoize(challenge_digest, run, WorkProvenance::OwnEngine);
        Ok(())
    }

    /// Checks one block's claimed work.
    ///
    /// - A confirmed result, or a match this node computed before, answers
    ///   from the memo with no engine run, so a repeated block costs nothing.
    /// - A single engine's earlier mismatch also answers from the memo, but
    ///   only while no worker of the other kind is ready; otherwise the other
    ///   engine runs now (as below). Its worker must also have reproduced a
    ///   known answer within [`WORK_MISMATCH_KAT_WINDOW`], or it runs one now.
    /// - Otherwise a GPU worker runs first if one is ready, falling back to
    ///   the CPU when every GPU worker is busy or fails.
    /// - A match from any engine is final.
    /// - A mismatch is re-run on the other engine when it has a ready worker:
    ///   if it agrees (and the GPU worker involved still reproduces a known
    ///   answer) the mismatch is `Confirmed`; if it matches the claim the
    ///   block is accepted, an alarm raised and the disagreeing worker tested
    ///   again; if it disagrees with both, no verdict and both are tested
    ///   again. With no other engine available the mismatch stays
    ///   `OwnEngine`, once its worker has reproduced a known answer within
    ///   [`WORK_MISMATCH_KAT_WINDOW`] (running one now if it has not).
    /// - A challenge the engines disagreed on is answered as unavailable,
    ///   without running either engine, for [`WORK_DISAGREEMENT_HOLD`] or
    ///   until one of the two workers is retired. This is never stored or turned into a
    ///   verdict.
    pub fn check(&self, claim: WorkClaim) -> WorkVerdict {
        self.check_cancellable(claim, &|| false)
    }

    /// [`check`](Self::check) for a caller that may give up: once `cancel`
    /// returns true, a running job stops and the check is
    /// [`WorkUnavailable::Cancelled`]. A cancelled job keeps nothing, raises
    /// no alarm and says nothing about its worker.
    pub fn check_cancellable(&self, claim: WorkClaim, cancel: &WorkCancel<'_>) -> WorkVerdict {
        let memo = {
            let state = self.state();
            state.memo.get(&claim.challenge_digest).map(|entry| {
                let run = Run {
                    producer: entry.producer,
                    generation: state.slot(entry.producer).map_or(0, |slot| slot.generation),
                    final_activation_digest: entry.final_activation_digest,
                };
                let confirmable = entry.provenance == WorkProvenance::OwnEngine
                    && state.any_ready(entry.producer.kind.other());
                (entry, run, confirmable)
            })
        };
        if let Some((entry, run, confirmable)) = memo {
            let verdict = verdict_from_entry(claim, entry);
            match entry.provenance {
                WorkProvenance::Confirmed => return verdict,
                WorkProvenance::OwnEngine => {
                    let mismatch = matches!(verdict, WorkVerdict::Mismatch(_));
                    if confirmable && mismatch {
                        if self.state().held(&claim.challenge_digest, Instant::now()) {
                            return WorkVerdict::Unavailable(WorkUnavailable::EnginesDisagree);
                        }
                        return self.confirm(claim, run, !entry.mismatch_reported, cancel);
                    }
                    if mismatch {
                        let fresh = !entry.mismatch_reported;
                        if !self
                            .state()
                            .lone_mismatch_final(entry.producer, Instant::now())
                        {
                            return self.lone_engine_mismatch(claim, run, fresh, cancel);
                        }
                        if fresh {
                            self.report_own_engine_mismatch(
                                claim.challenge_digest,
                                entry.producer.kind,
                            );
                        }
                    }
                    return verdict;
                }
                WorkProvenance::RecordHonest => {
                    if matches!(verdict, WorkVerdict::Match(_))
                        && self.pool_result_trusted(claim.challenge_digest, entry)
                    {
                        return WorkVerdict::Match(WorkProvenance::RecordHonest);
                    }
                }
            }
        }
        self.compute(claim, cancel)
    }

    fn compute(&self, claim: WorkClaim, cancel: &WorkCancel<'_>) -> WorkVerdict {
        if self.state().held(&claim.challenge_digest, Instant::now()) {
            return WorkVerdict::Unavailable(WorkUnavailable::EnginesDisagree);
        }
        let first = match self.run_first_available(claim.challenge_digest, cancel) {
            Ok(run) => run,
            Err(unavailable) => return WorkVerdict::Unavailable(unavailable),
        };
        if work_matches(claim, first.final_activation_digest) {
            self.memoize(claim.challenge_digest, first, WorkProvenance::OwnEngine);
            return WorkVerdict::Match(WorkProvenance::OwnEngine);
        }
        self.confirm(claim, first, true, cancel)
    }

    /// Re-runs a mismatch that `first` found on the other kind of engine.
    /// `fresh` is false when the alarm for `first`'s mismatch was already
    /// raised.
    fn confirm(
        &self,
        claim: WorkClaim,
        first: Run,
        fresh: bool,
        cancel: &WorkCancel<'_>,
    ) -> WorkVerdict {
        let mut last_error = None;
        let Some(second) = self.run_kind(
            first.producer.kind.other(),
            claim.challenge_digest,
            &mut last_error,
            cancel,
        ) else {
            if last_error == Some(WorkEngineError::Cancelled) {
                // Keep the first engine's own result, so a re-send goes
                // straight to confirmation, but reach no verdict.
                self.memoize(claim.challenge_digest, first, WorkProvenance::OwnEngine);
                return WorkVerdict::Unavailable(WorkUnavailable::Cancelled);
            }
            return self.lone_engine_mismatch(claim, first, fresh, cancel);
        };
        if second.final_activation_digest == first.final_activation_digest {
            let (gpu, cpu) = if first.producer.kind == WorkEngineKind::Gpu {
                (first.producer, second)
            } else {
                (second.producer, first)
            };
            return match self.known_answer(gpu) {
                KatOutcome::Pass
                    if self.memoize_confirmed(claim.challenge_digest, first, second) =>
                {
                    WorkVerdict::Mismatch(WorkMismatch {
                        challenge_digest: claim.challenge_digest,
                        claimed_work_digest: claim.work_digest,
                        honest_final_activation_digest: first.final_activation_digest,
                        provenance: WorkProvenance::Confirmed,
                        cacheable: true,
                    })
                }
                // A worker was retired while this ran, or the GPU could not
                // run its known answer: not confirmed. Keep the CPU's result,
                // so the next check confirms it on the GPU, which is the
                // cheaper engine to run again.
                KatOutcome::Pass | KatOutcome::Busy | KatOutcome::Error(_) => {
                    self.own_engine_mismatch(claim, cpu, fresh)
                }
                KatOutcome::Fail(reason) => {
                    self.mark_failed(gpu, &reason);
                    self.memoize(claim.challenge_digest, cpu, WorkProvenance::OwnEngine);
                    WorkVerdict::Unavailable(WorkUnavailable::KnownAnswerFailed)
                }
            };
        }
        self.raise_divergence(claim.challenge_digest);
        if work_matches(claim, second.final_activation_digest) {
            self.memoize(claim.challenge_digest, second, WorkProvenance::OwnEngine);
            self.requalify(first.producer);
            return WorkVerdict::Match(WorkProvenance::OwnEngine);
        }
        self.requalify(first.producer);
        self.requalify(second.producer);
        {
            // Unless the known answers retired one of them, the same two
            // workers would disagree again: do not run them again for a
            // while.
            let mut state = self.state();
            if state.current(&first) && state.current(&second) {
                state.hold(Disagreement {
                    challenge_digest: claim.challenge_digest,
                    workers: [first.producer, second.producer],
                    at: Instant::now(),
                });
            }
        }
        WorkVerdict::Unavailable(WorkUnavailable::EnginesDisagree)
    }

    /// Runs the ready engines in order (GPU first) until one produces a
    /// result. A block that the CPU checks because the GPU workers were busy
    /// is logged at info, once per block.
    fn run_first_available(
        &self,
        challenge_digest: [u8; 32],
        cancel: &WorkCancel<'_>,
    ) -> Result<Run, WorkUnavailable> {
        let mut last_error = None;
        let mut gpu_busy = false;
        for kind in [WorkEngineKind::Gpu, WorkEngineKind::Cpu] {
            if let Some(run) = self.run_kind(kind, challenge_digest, &mut last_error, cancel) {
                if gpu_busy && kind == WorkEngineKind::Cpu {
                    self.note_cpu_fallback(challenge_digest);
                }
                return Ok(run);
            }
            gpu_busy = kind == WorkEngineKind::Gpu && last_error == Some(WorkEngineError::Busy);
            if last_error == Some(WorkEngineError::Cancelled) {
                return Err(WorkUnavailable::Cancelled);
            }
        }
        Err(match last_error {
            Some(error) => WorkUnavailable::Engine(error),
            None => match self.engine_state() {
                WorkEngineState::Qualifying => WorkUnavailable::Qualifying,
                _ => WorkUnavailable::EnginesFailed,
            },
        })
    }

    /// Runs the ready workers of `kind` in [`worker_order`] until one
    /// produces a result. A cancellation stops it at once.
    fn run_kind(
        &self,
        kind: WorkEngineKind,
        challenge_digest: [u8; 32],
        last_error: &mut Option<WorkEngineError>,
        cancel: &WorkCancel<'_>,
    ) -> Option<Run> {
        let engine = self.engine(kind)?;
        let ready = {
            let state = self.state();
            let slots = &state.slots[kind.index()];
            worker_order(slots.len())
                .filter(|worker| slots[*worker].health == WorkEngineHealth::Ready)
                .map(|worker| (worker, slots[worker].generation))
                .collect::<Vec<_>>()
        };
        for (worker, generation) in ready {
            let producer = Producer { kind, worker };
            let started = Instant::now();
            match engine.final_activation_digest_cancellable(
                challenge_digest,
                worker,
                self.authenticate,
                cancel,
            ) {
                Ok(final_activation_digest) => {
                    let mut state = self.state();
                    state.run_time[kind.index()] = Some(started.elapsed());
                    if let Some(slot) = state.slot_mut(producer) {
                        slot.erroring = false;
                    }
                    drop(state);
                    return Some(Run {
                        producer,
                        generation,
                        final_activation_digest,
                    });
                }
                Err(WorkEngineError::Cancelled) => {
                    *last_error = Some(WorkEngineError::Cancelled);
                    return None;
                }
                Err(error) => {
                    self.note_engine_error(producer, &error);
                    *last_error = Some(error);
                }
            }
        }
        None
    }

    fn note_cpu_fallback(&self, challenge_digest: [u8; 32]) {
        {
            let mut state = self.state();
            if state.cpu_fallback == Some(challenge_digest) {
                return;
            }
            state.cpu_fallback = Some(challenge_digest);
        }
        tracing::info!(
            target: "work_rule",
            challenge = %hex::encode(challenge_digest),
            "gpu replay workers busy; checked on the cpu"
        );
    }

    /// One known answer on `producer`.
    fn known_answer(&self, producer: Producer) -> KatOutcome {
        match self.engine(producer.kind) {
            Some(engine) => run_known_answers(engine.as_ref(), producer.worker, 1, &|| false),
            None => KatOutcome::Busy,
        }
    }

    /// Tests a worker that disagreed with another engine; retires it if it no
    /// longer reproduces a known answer.
    fn requalify(&self, producer: Producer) {
        match self.known_answer(producer) {
            KatOutcome::Pass | KatOutcome::Busy => {}
            KatOutcome::Error(reason) => self.note_kat_error(producer, &reason),
            KatOutcome::Fail(reason) => self.mark_failed(producer, &reason),
        }
    }

    /// Whether the replay worker that produced a pool-supplied result is
    /// ready and has reproduced a known answer since it was recorded. Without
    /// that the result is not used.
    fn pool_result_trusted(&self, challenge_digest: [u8; 32], entry: MemoEntry) -> bool {
        let producer = entry.producer;
        let generation = {
            let state = self.state();
            match state.slot(producer) {
                Some(slot) if slot.health == WorkEngineHealth::Ready => slot.generation,
                _ => return false,
            }
        };
        if entry.worker_checked {
            return true;
        }
        match self.known_answer(producer) {
            KatOutcome::Pass => {
                let mut state = self.state();
                let current = state.current(&Run {
                    producer,
                    generation,
                    final_activation_digest: entry.final_activation_digest,
                });
                if let Some(held) = state.memo.entries.get_mut(&challenge_digest)
                    && current
                    && held.provenance == WorkProvenance::RecordHonest
                    && held.final_activation_digest == entry.final_activation_digest
                    && held.producer == producer
                {
                    held.worker_checked = true;
                }
                true
            }
            KatOutcome::Busy | KatOutcome::Error(_) => false,
            KatOutcome::Fail(reason) => {
                self.mark_failed(producer, &reason);
                false
            }
        }
    }

    /// A mismatch only `run`'s engine found: no engine of the other kind ran
    /// the block. While the other kind has no ready worker, the mismatch is
    /// this node's final answer, so that worker must have reproduced a known
    /// answer, which reads and authenticates every layer of the model,
    /// within [`WORK_MISMATCH_KAT_WINDOW`]. If it has not, it runs its
    /// round's known answers now:
    /// a worker or a model file that changed since it qualified then makes
    /// the check unavailable, keeping nothing, instead of reaching a verdict
    /// on the block. `run` is kept first, so a check that ends without a
    /// verdict (cancelled, busy, a read error) is retried with the known
    /// answer alone.
    fn lone_engine_mismatch(
        &self,
        claim: WorkClaim,
        run: Run,
        fresh: bool,
        cancel: &WorkCancel<'_>,
    ) -> WorkVerdict {
        let now = Instant::now();
        {
            let state = self.state();
            if state.any_ready(run.producer.kind.other())
                || state.lone_mismatch_final(run.producer, now)
            {
                drop(state);
                return self.own_engine_mismatch(claim, run, fresh);
            }
        }
        let Some(engine) = self.engine(run.producer.kind) else {
            return WorkVerdict::Unavailable(WorkUnavailable::EnginesFailed);
        };
        self.memoize(claim.challenge_digest, run, WorkProvenance::OwnEngine);
        // The same vectors as a round, since a pass restarts the round's
        // interval too.
        let vectors = match run.producer.kind {
            WorkEngineKind::Cpu => CPU_KAT_VECTORS,
            WorkEngineKind::Gpu => GPU_KAT_VECTORS,
        };
        let started = Instant::now();
        match run_known_answers(engine.as_ref(), run.producer.worker, vectors, cancel) {
            KatOutcome::Pass => {
                let mut state = self.state();
                state.known_answer_time[run.producer.kind.index()] = Some(started.elapsed());
                if let Some(slot) = state.slot_mut(run.producer)
                    && slot.generation == run.generation
                {
                    slot.passed_at = Some(Instant::now());
                    slot.erroring = false;
                }
                drop(state);
                self.own_engine_mismatch(claim, run, fresh)
            }
            KatOutcome::Fail(reason) => {
                self.mark_failed(run.producer, &reason);
                WorkVerdict::Unavailable(WorkUnavailable::KnownAnswerFailed)
            }
            KatOutcome::Error(reason) => {
                self.note_kat_error(run.producer, &reason);
                WorkVerdict::Unavailable(WorkUnavailable::Engine(WorkEngineError::Failed(reason)))
            }
            KatOutcome::Busy if cancel() => WorkVerdict::Unavailable(WorkUnavailable::Cancelled),
            KatOutcome::Busy => {
                WorkVerdict::Unavailable(WorkUnavailable::Engine(WorkEngineError::Busy))
            }
        }
    }

    fn own_engine_mismatch(&self, claim: WorkClaim, run: Run, fresh: bool) -> WorkVerdict {
        self.memoize(claim.challenge_digest, run, WorkProvenance::OwnEngine);
        let cacheable = !self.state().any_ready(run.producer.kind.other());
        if fresh {
            self.report_own_engine_mismatch(claim.challenge_digest, run.producer.kind);
        }
        WorkVerdict::Mismatch(WorkMismatch {
            challenge_digest: claim.challenge_digest,
            claimed_work_digest: claim.work_digest,
            honest_final_activation_digest: run.final_activation_digest,
            provenance: WorkProvenance::OwnEngine,
            cacheable,
        })
    }

    /// Raises the alarm for a single engine's result that differs from a
    /// block, once per memoized result, however many checks reach it at once.
    fn report_own_engine_mismatch(&self, challenge_digest: [u8; 32], kind: WorkEngineKind) {
        if let Some(entry) = self.state().memo.entries.get_mut(&challenge_digest) {
            if entry.mismatch_reported {
                return;
            }
            entry.mismatch_reported = true;
        }
        self.alarms
            .own_engine_mismatches
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            target: "work_rule",
            challenge = %hex::encode(challenge_digest),
            engine = ?kind,
            "re-executed work differs from the block and no independent engine checked it"
        );
    }

    pub(crate) fn raise_divergence(&self, challenge_digest: [u8; 32]) {
        self.alarms
            .engine_divergence
            .fetch_add(1, Ordering::Relaxed);
        tracing::error!(
            target: "work_rule",
            challenge = %hex::encode(challenge_digest),
            "work engines produced different results for one challenge"
        );
    }

    /// Keeps `run`'s result unless its worker was retired since it started.
    fn memoize(&self, challenge_digest: [u8; 32], run: Run, provenance: WorkProvenance) {
        let mut state = self.state();
        if state.current(&run) {
            state.memo.insert(
                challenge_digest,
                MemoEntry {
                    final_activation_digest: run.final_activation_digest,
                    provenance,
                    producer: run.producer,
                    worker_checked: false,
                    mismatch_reported: false,
                },
            );
        }
    }

    /// Keeps a confirmed result unless either worker was retired since its
    /// run started; returns whether it was kept.
    fn memoize_confirmed(&self, challenge_digest: [u8; 32], first: Run, second: Run) -> bool {
        let mut state = self.state();
        let current = state.current(&first) && state.current(&second);
        if current {
            state.memo.insert(
                challenge_digest,
                MemoEntry {
                    final_activation_digest: first.final_activation_digest,
                    provenance: WorkProvenance::Confirmed,
                    producer: first.producer,
                    worker_checked: false,
                    mismatch_reported: false,
                },
            );
        }
        current
    }

    /// A busy worker is simply skipped. A failed CPU job only makes this
    /// check unavailable, and marks the worker as erroring so the known
    /// answers are tried again soon. A failed GPU job, a worker that is not
    /// running, or an integrity failure on either engine retires that worker
    /// until its known answers pass again; the other workers carry on.
    fn note_engine_error(&self, producer: Producer, error: &WorkEngineError) {
        match error {
            WorkEngineError::Busy | WorkEngineError::Cancelled => {}
            WorkEngineError::Failed(reason) if producer.kind == WorkEngineKind::Cpu => {
                if let Some(slot) = self.state().slot_mut(producer) {
                    slot.erroring = true;
                }
                self.alarms.engine_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(target: "work_rule", %reason, "CPU work engine job failed");
            }
            WorkEngineError::Failed(reason)
            | WorkEngineError::Stopped(reason)
            | WorkEngineError::Integrity(reason) => {
                self.mark_failed(producer, reason);
            }
        }
    }

    fn note_kat_error(&self, producer: Producer, reason: &str) {
        if let Some(slot) = self.state().slot_mut(producer) {
            slot.erroring = true;
        }
        self.alarms.engine_failures.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            target: "work_rule",
            engine = ?producer.kind,
            worker = producer.worker,
            %reason,
            "a known answer could not be read; the worker keeps its state and is tested again soon"
        );
    }

    /// Retires one worker until its known answers pass again, forgets every
    /// result it computed that was not independently confirmed, and ends
    /// every disagreement hold it was one side of.
    fn mark_failed(&self, producer: Producer, reason: &str) {
        {
            let mut state = self.state();
            if let Some(slot) = state.slot_mut(producer) {
                slot.health = WorkEngineHealth::Failed;
                slot.generation += 1;
            }
            state.memo.retain_not_from(producer);
            state
                .disagreements
                .retain(|held| !held.workers.contains(&producer));
        }
        self.alarms.engine_failures.fetch_add(1, Ordering::Relaxed);
        tracing::error!(
            target: "work_rule",
            engine = ?producer.kind,
            worker = producer.worker,
            %reason,
            "work engine worker retired"
        );
    }
}

fn work_matches(claim: WorkClaim, final_activation_digest: [u8; 32]) -> bool {
    honest_work_digest(claim.challenge_digest, final_activation_digest) == claim.work_digest
}

fn verdict_from_entry(claim: WorkClaim, entry: MemoEntry) -> WorkVerdict {
    if work_matches(claim, entry.final_activation_digest) {
        WorkVerdict::Match(entry.provenance)
    } else {
        WorkVerdict::Mismatch(WorkMismatch {
            challenge_digest: claim.challenge_digest,
            claimed_work_digest: claim.work_digest,
            honest_final_activation_digest: entry.final_activation_digest,
            provenance: entry.provenance,
            // Only a confirmed entry, or one the other kind of engine cannot
            // check now, is ever returned as a mismatch.
            cacheable: entry.provenance != WorkProvenance::RecordHonest,
        })
    }
}

/// Runs the first `vectors` known answers on `worker`, asking the engine to
/// authenticate model data (the CPU engine does). A failed CPU read is tried
/// once more before it counts as an error.
fn run_known_answers(
    engine: &dyn WorkEngine,
    worker: usize,
    vectors: usize,
    cancel: &WorkCancel<'_>,
) -> KatOutcome {
    for answer in &WORK_KNOWN_ANSWERS[..vectors] {
        let mut retried = false;
        loop {
            match engine.final_activation_digest_cancellable(
                answer.challenge_digest,
                worker,
                true,
                cancel,
            ) {
                Ok(digest) if digest == answer.final_activation_digest => break,
                Ok(_) => {
                    return KatOutcome::Fail(format!(
                        "known answer for height {} not reproduced",
                        answer.height
                    ));
                }
                Err(
                    WorkEngineError::Busy
                    | WorkEngineError::Stopped(_)
                    | WorkEngineError::Cancelled,
                ) => {
                    return KatOutcome::Busy;
                }
                Err(WorkEngineError::Failed(reason)) if engine.kind() == WorkEngineKind::Cpu => {
                    if retried {
                        return KatOutcome::Error(reason);
                    }
                    retried = true;
                }
                Err(error) => return KatOutcome::Fail(error.to_string()),
            }
        }
    }
    KatOutcome::Pass
}

/// Longest a block work check waits for one GPU replay.
pub const GPU_WORK_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// The outcome of one GPU replay for a block work check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GpuReplay {
    /// The final activation, canonical little-endian `u32` values.
    Done(Vec<u8>),
    /// The worker is in use; try another or fall back.
    Busy,
    /// The worker is not running (it failed earlier and was not started
    /// again).
    Stopped(String),
    /// The worker failed or timed out.
    Failed(String),
}

/// Replay workers a GPU engine can borrow for block work checks.
pub trait GpuReplayWorkers: Send + Sync {
    fn replay_workers(&self) -> usize;

    /// Replays `challenge_digest` on `worker` (`RUNBATCH 1`). Must not wait
    /// for a busy worker, and must not start or restart one.
    fn try_replay(&self, worker: usize, challenge_digest: [u8; 32], timeout: Duration)
    -> GpuReplay;
}

#[cfg(feature = "production-v4")]
pub use engines::{CpuWorkEngine, GpuWorkEngine};

/// How the operating system schedules the CPU work engine's threads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WorkThreadPriority {
    /// The normal priority.
    #[default]
    Normal,
    /// Below normal, so the computer's other work goes first. A desktop
    /// wallet runs its engine this way.
    BelowNormal,
}

impl WorkThreadPriority {
    /// Applies this priority to the calling thread. `Normal` leaves the
    /// thread as it is. Best effort: the priority changes no result, so a
    /// refusal is ignored. On Linux below normal is a nice value of 10 for
    /// the thread; elsewhere outside Windows it does nothing.
    pub fn apply_to_current_thread(self) {
        if self == Self::Normal {
            return;
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Threading::{
                GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL,
            };
            // SAFETY: the pseudo handle of the calling thread is always
            // valid and needs no closing.
            unsafe {
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
            }
        }
        #[cfg(target_os = "linux")]
        {
            // SAFETY: gettid and setpriority take no pointers; on Linux the
            // nice value belongs to the thread a thread id names.
            unsafe {
                let thread = libc::syscall(libc::SYS_gettid) as libc::id_t;
                libc::setpriority(libc::PRIO_PROCESS, thread, 10);
            }
        }
    }
}

#[cfg(feature = "production-v4")]
mod engines {
    use super::*;
    use crate::pool::ProductionV4PoolShareVerifier;
    use crate::production_v4_pool::ProductionV4PersistentPoolVerifier;
    use cmfd_consensus::{
        ForgeMatrixV4ExecutionError, ForgeMatrixV4ExecutionShape, ForgeMatrixV4LayerSource,
        forgematrix_v4_execute_challenge, forgematrix_v4_final_activation_digest_from_le_bytes,
    };
    use std::sync::TryLockError;
    use std::sync::atomic::AtomicBool;

    /// The consensus CPU executor over a model layer source. It has one
    /// worker, which runs one job at a time: a job asked for while another
    /// runs (a block check, a prewarm or a known answer) is refused as busy,
    /// so the engine never uses more than `threads` compute threads.
    pub struct CpuWorkEngine {
        source: Arc<dyn ForgeMatrixV4LayerSource>,
        threads: usize,
        priority: WorkThreadPriority,
        job: Mutex<()>,
    }

    impl CpuWorkEngine {
        /// `threads` compute workers per block (at least one).
        pub fn new(source: Arc<dyn ForgeMatrixV4LayerSource>, threads: usize) -> Self {
            Self {
                source,
                threads: threads.max(1),
                priority: WorkThreadPriority::Normal,
                job: Mutex::new(()),
            }
        }

        /// Runs every thread a job starts at `priority`.
        pub fn with_thread_priority(mut self, priority: WorkThreadPriority) -> Self {
            self.priority = priority;
            self
        }
    }

    impl CpuWorkEngine {
        fn run(
            &self,
            challenge_digest: [u8; 32],
            authenticate: bool,
            cancel: &WorkCancel<'_>,
        ) -> Result<[u8; 32], WorkEngineError> {
            let _job = match self.job.try_lock() {
                Ok(job) => job,
                // The guard holds no data, so a panicked job left nothing
                // inconsistent.
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => return Err(WorkEngineError::Busy),
            };
            if cancel() {
                return Err(WorkEngineError::Cancelled);
            }
            let source = CancellableLayers {
                inner: self.source.as_ref(),
                cancel,
                cancelled: AtomicBool::new(false),
                priority: self.priority,
            };
            let result = forgematrix_v4_execute_challenge(
                challenge_digest,
                &source,
                self.threads,
                authenticate,
            );
            if source.cancelled.load(Ordering::Acquire) {
                return Err(WorkEngineError::Cancelled);
            }
            result
                .map(|execution| execution.final_activation_digest)
                .map_err(|error| match error {
                    ForgeMatrixV4ExecutionError::LayerAuthentication { .. }
                    | ForgeMatrixV4ExecutionError::NonCanonicalFinalActivation => {
                        WorkEngineError::Integrity(error.to_string())
                    }
                    other => WorkEngineError::Failed(other.to_string()),
                })
        }
    }

    /// A layer source that stops the forward pass at the next layer read
    /// once the job is cancelled. Layers are read one ahead of the compute,
    /// so a cancelled job ends within about one layer. Each thread the job
    /// starts runs at the engine's priority.
    struct CancellableLayers<'a> {
        inner: &'a dyn ForgeMatrixV4LayerSource,
        cancel: &'a WorkCancel<'a>,
        cancelled: AtomicBool,
        priority: WorkThreadPriority,
    }

    impl ForgeMatrixV4LayerSource for CancellableLayers<'_> {
        fn shape(&self) -> ForgeMatrixV4ExecutionShape {
            self.inner.shape()
        }

        fn base_input(&self) -> &[u8] {
            self.inner.base_input()
        }

        fn read_layer(
            &self,
            layer: usize,
            out: &mut [u8],
            authenticate: bool,
        ) -> Result<(), ForgeMatrixV4ExecutionError> {
            if (self.cancel)() {
                self.cancelled.store(true, Ordering::Release);
                return Err(ForgeMatrixV4ExecutionError::LayerRead {
                    layer,
                    source: std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "work job cancelled",
                    ),
                });
            }
            self.inner.read_layer(layer, out, authenticate)
        }

        fn on_thread_start(&self) {
            self.priority.apply_to_current_thread();
            self.inner.on_thread_start();
        }
    }

    impl WorkEngine for CpuWorkEngine {
        fn kind(&self) -> WorkEngineKind {
            WorkEngineKind::Cpu
        }

        fn final_activation_digest(
            &self,
            challenge_digest: [u8; 32],
            _worker: usize,
            authenticate: bool,
        ) -> Result<[u8; 32], WorkEngineError> {
            self.run(challenge_digest, authenticate, &|| false)
        }

        fn final_activation_digest_cancellable(
            &self,
            challenge_digest: [u8; 32],
            _worker: usize,
            authenticate: bool,
            cancel: &WorkCancel<'_>,
        ) -> Result<[u8; 32], WorkEngineError> {
            self.run(challenge_digest, authenticate, cancel)
        }
    }

    /// Persistent GPU replay workers, one engine worker each, used only when
    /// idle. The checker tries workers 1.. before worker 0, which also serves
    /// single shares and proofs.
    pub struct GpuWorkEngine {
        workers: Arc<dyn GpuReplayWorkers>,
        timeout: Duration,
    }

    impl GpuWorkEngine {
        pub fn new(workers: Arc<dyn GpuReplayWorkers>, timeout: Duration) -> Self {
            Self { workers, timeout }
        }
    }

    impl WorkEngine for GpuWorkEngine {
        fn kind(&self) -> WorkEngineKind {
            WorkEngineKind::Gpu
        }

        fn workers(&self) -> usize {
            self.workers.replay_workers()
        }

        fn final_activation_digest(
            &self,
            challenge_digest: [u8; 32],
            worker: usize,
            _authenticate: bool,
        ) -> Result<[u8; 32], WorkEngineError> {
            match self
                .workers
                .try_replay(worker, challenge_digest, self.timeout)
            {
                GpuReplay::Done(final_activation) => {
                    forgematrix_v4_final_activation_digest_from_le_bytes(
                        challenge_digest,
                        &final_activation,
                    )
                    .map_err(|error| WorkEngineError::Integrity(error.to_string()))
                }
                GpuReplay::Busy => Err(WorkEngineError::Busy),
                GpuReplay::Stopped(reason) => Err(WorkEngineError::Stopped(reason)),
                GpuReplay::Failed(reason) => Err(WorkEngineError::Failed(reason)),
            }
        }
    }

    impl GpuReplayWorkers for ProductionV4PersistentPoolVerifier {
        fn replay_workers(&self) -> usize {
            ProductionV4PoolShareVerifier::replay_workers(self)
        }

        fn try_replay(
            &self,
            worker: usize,
            challenge_digest: [u8; 32],
            timeout: Duration,
        ) -> GpuReplay {
            self.try_replay_for_work_check(worker, challenge_digest, timeout)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use cmfd_consensus::{
            FORGEMATRIX_V4_FIELD_MODULUS, FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES,
        };
        use std::sync::atomic::AtomicUsize;

        /// Scripted replay workers: each answers with its queued replies, then
        /// with a valid final activation; every call is logged.
        struct FakeWorkers {
            count: usize,
            replies: Mutex<HashMap<usize, VecDeque<GpuReplay>>>,
            calls: Mutex<Vec<(usize, Duration)>>,
        }

        impl FakeWorkers {
            fn new(count: usize) -> Arc<Self> {
                Arc::new(Self {
                    count,
                    replies: Mutex::new(HashMap::new()),
                    calls: Mutex::new(Vec::new()),
                })
            }

            fn reply(&self, worker: usize, reply: GpuReplay) {
                self.replies
                    .lock()
                    .unwrap()
                    .entry(worker)
                    .or_default()
                    .push_back(reply);
            }

            fn called(&self) -> Vec<usize> {
                self.calls
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|call| call.0)
                    .collect()
            }
        }

        impl GpuReplayWorkers for FakeWorkers {
            fn replay_workers(&self) -> usize {
                self.count
            }

            fn try_replay(
                &self,
                worker: usize,
                _challenge_digest: [u8; 32],
                timeout: Duration,
            ) -> GpuReplay {
                self.calls.lock().unwrap().push((worker, timeout));
                self.replies
                    .lock()
                    .unwrap()
                    .get_mut(&worker)
                    .and_then(VecDeque::pop_front)
                    .unwrap_or_else(|| GpuReplay::Done(final_activation(worker as u32 + 1)))
            }
        }

        fn final_activation(value: u32) -> Vec<u8> {
            value
                .to_le_bytes()
                .repeat(FORGEMATRIX_V4_PUBLIC_FINAL_ACTIVATION_BYTES / 4)
        }

        fn digest_of(challenge_digest: [u8; 32], value: u32) -> [u8; 32] {
            forgematrix_v4_final_activation_digest_from_le_bytes(
                challenge_digest,
                &final_activation(value),
            )
            .unwrap()
        }

        fn engine(workers: &Arc<FakeWorkers>) -> GpuWorkEngine {
            GpuWorkEngine::new(workers.clone(), GPU_WORK_CHECK_TIMEOUT)
        }

        #[test]
        fn the_cpu_engine_refuses_a_second_job_while_one_runs() {
            struct Untouched;
            impl ForgeMatrixV4LayerSource for Untouched {
                fn shape(&self) -> cmfd_consensus::ForgeMatrixV4ExecutionShape {
                    unreachable!("a refused job reads nothing")
                }
                fn base_input(&self) -> &[u8] {
                    unreachable!("a refused job reads nothing")
                }
                fn read_layer(
                    &self,
                    _layer: usize,
                    _out: &mut [u8],
                    _authenticate: bool,
                ) -> Result<(), ForgeMatrixV4ExecutionError> {
                    unreachable!("a refused job reads nothing")
                }
            }
            let engine = CpuWorkEngine::new(Arc::new(Untouched), 2);
            let running = engine.job.lock().unwrap();
            assert_eq!(
                engine.final_activation_digest([1; 32], 0, false),
                Err(WorkEngineError::Busy)
            );
            drop(running);
            assert_eq!(
                engine.final_activation_digest_cancellable([1; 32], 0, false, &|| true),
                Err(WorkEngineError::Cancelled),
                "a job cancelled before it starts reads nothing"
            );
        }

        #[test]
        fn a_cancelled_cpu_job_stops_at_the_next_layer() {
            /// A zero model that counts the layers read.
            struct ZeroLayers {
                base: Vec<u8>,
                reads: AtomicUsize,
            }
            impl ForgeMatrixV4LayerSource for ZeroLayers {
                fn shape(&self) -> ForgeMatrixV4ExecutionShape {
                    ForgeMatrixV4ExecutionShape::PRODUCTION
                }
                fn base_input(&self) -> &[u8] {
                    &self.base
                }
                fn read_layer(
                    &self,
                    _layer: usize,
                    out: &mut [u8],
                    _authenticate: bool,
                ) -> Result<(), ForgeMatrixV4ExecutionError> {
                    self.reads.fetch_add(1, Ordering::SeqCst);
                    out.fill(0);
                    Ok(())
                }
            }
            let source = Arc::new(ZeroLayers {
                base: vec![0; ForgeMatrixV4ExecutionShape::PRODUCTION.cells()],
                reads: AtomicUsize::new(0),
            });
            let engine = CpuWorkEngine::new(source.clone(), 2);
            // Cancelled once the first layer has been read: the pass stops
            // when it asks for the second.
            let cancel = || source.reads.load(Ordering::SeqCst) >= 1;
            assert_eq!(
                engine.final_activation_digest_cancellable([1; 32], 0, false, &cancel),
                Err(WorkEngineError::Cancelled)
            );
            assert_eq!(source.reads.load(Ordering::SeqCst), 1);
            assert!(engine.job.try_lock().is_ok(), "the job slot is free again");
        }

        /// The calling thread's scheduling priority: Windows' relative
        /// priority, or Linux's nice value.
        #[cfg(any(windows, target_os = "linux"))]
        fn current_thread_priority() -> i32 {
            #[cfg(windows)]
            // SAFETY: the pseudo handle of the calling thread is always valid.
            unsafe {
                windows_sys::Win32::System::Threading::GetThreadPriority(
                    windows_sys::Win32::System::Threading::GetCurrentThread(),
                )
            }
            #[cfg(target_os = "linux")]
            // SAFETY: gettid and getpriority take no pointers.
            unsafe {
                let thread = libc::syscall(libc::SYS_gettid) as libc::id_t;
                libc::getpriority(libc::PRIO_PROCESS, thread)
            }
        }

        #[cfg(any(windows, target_os = "linux"))]
        #[test]
        fn a_below_normal_cpu_engine_runs_its_threads_below_normal() {
            /// A zero model that records the priority of each thread that
            /// reads a layer after the first (the job's reader threads).
            struct Priorities {
                base: Vec<u8>,
                seen: Mutex<Vec<i32>>,
            }
            impl ForgeMatrixV4LayerSource for Priorities {
                fn shape(&self) -> ForgeMatrixV4ExecutionShape {
                    ForgeMatrixV4ExecutionShape::PRODUCTION
                }
                fn base_input(&self) -> &[u8] {
                    &self.base
                }
                fn read_layer(
                    &self,
                    layer: usize,
                    out: &mut [u8],
                    _authenticate: bool,
                ) -> Result<(), ForgeMatrixV4ExecutionError> {
                    if layer > 0 {
                        self.seen.lock().unwrap().push(current_thread_priority());
                    }
                    out.fill(0);
                    Ok(())
                }
            }
            let caller = current_thread_priority();
            let run = |priority| {
                let source = Arc::new(Priorities {
                    base: vec![0; ForgeMatrixV4ExecutionShape::PRODUCTION.cells()],
                    seen: Mutex::new(Vec::new()),
                });
                let engine = CpuWorkEngine::new(source.clone(), 1).with_thread_priority(priority);
                // Two reader threads, then the job stops.
                let cancel = || source.seen.lock().unwrap().len() >= 2;
                assert_eq!(
                    engine.final_activation_digest_cancellable([1; 32], 0, false, &cancel),
                    Err(WorkEngineError::Cancelled)
                );
                source.seen.lock().unwrap().clone()
            };
            // Windows threads start at normal priority; Linux threads start
            // at their creator's nice value, which they can raise but not
            // lower.
            #[cfg(windows)]
            let (normal, below) = (
                windows_sys::Win32::System::Threading::THREAD_PRIORITY_NORMAL,
                windows_sys::Win32::System::Threading::THREAD_PRIORITY_BELOW_NORMAL,
            );
            #[cfg(target_os = "linux")]
            let (normal, below) = (caller, caller.max(10));
            assert_eq!(run(WorkThreadPriority::BelowNormal), [below, below]);
            assert_eq!(run(WorkThreadPriority::Normal), [normal, normal]);
            assert_eq!(
                current_thread_priority(),
                caller,
                "the caller is left alone"
            );
        }

        #[test]
        fn the_gpu_engine_runs_the_named_worker_and_maps_its_replies() {
            let workers = FakeWorkers::new(3);
            let gpu = engine(&workers);
            assert_eq!(gpu.workers(), 3);
            assert_eq!(
                gpu.final_activation_digest([1; 32], 2, false),
                Ok(digest_of([1; 32], 3))
            );
            assert_eq!(workers.called(), [2]);
            assert_eq!(workers.calls.lock().unwrap()[0].1, GPU_WORK_CHECK_TIMEOUT);

            workers.reply(1, GpuReplay::Busy);
            assert_eq!(
                gpu.final_activation_digest([1; 32], 1, false),
                Err(WorkEngineError::Busy)
            );
            workers.reply(1, GpuReplay::Stopped("not running".to_owned()));
            assert_eq!(
                gpu.final_activation_digest([1; 32], 1, false),
                Err(WorkEngineError::Stopped("not running".to_owned()))
            );
            workers.reply(1, GpuReplay::Failed("timed out".to_owned()));
            assert_eq!(
                gpu.final_activation_digest([1; 32], 1, false),
                Err(WorkEngineError::Failed("timed out".to_owned()))
            );
            assert_eq!(workers.called(), [2, 1, 1, 1], "only the named worker");

            workers.reply(
                1,
                GpuReplay::Done(final_activation(FORGEMATRIX_V4_FIELD_MODULUS)),
            );
            assert!(matches!(
                gpu.final_activation_digest([1; 32], 1, false),
                Err(WorkEngineError::Integrity(_))
            ));
            workers.reply(1, GpuReplay::Done(vec![0; 8]));
            assert!(matches!(
                gpu.final_activation_digest([1; 32], 1, false),
                Err(WorkEngineError::Integrity(_))
            ));
        }

        #[test]
        fn a_checker_prefers_extra_gpu_workers_and_falls_back_to_the_cpu() {
            struct Cpu;
            impl WorkEngine for Cpu {
                fn kind(&self) -> WorkEngineKind {
                    WorkEngineKind::Cpu
                }

                fn final_activation_digest(
                    &self,
                    challenge_digest: [u8; 32],
                    _worker: usize,
                    _authenticate: bool,
                ) -> Result<[u8; 32], WorkEngineError> {
                    Ok(digest_of(challenge_digest, 1))
                }
            }
            let workers = FakeWorkers::new(3);
            let checker = HonestWorkChecker::new(
                Some(Arc::new(Cpu)),
                Some(Arc::new(engine(&workers))),
                false,
            )
            .unwrap();
            // Neither stand-in reproduces the known answers.
            let report = checker.run_known_answer_tests();
            assert_eq!(report.cpu, Some(WorkEngineHealth::Failed));
            assert_eq!(report.gpu, Some(WorkEngineHealth::Failed));
            assert_eq!(workers.called(), [0, 1, 2], "every worker is qualified");
            for slots in &mut checker.state().slots {
                for slot in slots {
                    slot.health = WorkEngineHealth::Ready;
                }
            }
            // Worker 0 yields what the CPU yields.
            let claim = WorkClaim {
                challenge_digest: [3; 32],
                work_digest: honest_work_digest([3; 32], digest_of([3; 32], 1)),
            };
            workers.reply(1, GpuReplay::Busy);
            workers.reply(2, GpuReplay::Busy);
            assert_eq!(
                checker.check(claim),
                WorkVerdict::Match(WorkProvenance::OwnEngine)
            );
            assert_eq!(workers.called()[3..], [1, 2, 0]);

            let claim = WorkClaim {
                challenge_digest: [4; 32],
                work_digest: honest_work_digest([4; 32], digest_of([4; 32], 1)),
            };
            for worker in 0..3 {
                workers.reply(worker, GpuReplay::Busy);
            }
            assert_eq!(
                checker.check(claim),
                WorkVerdict::Match(WorkProvenance::OwnEngine),
                "every GPU worker busy: the CPU decides"
            );
            assert_eq!(
                checker.engine_health(WorkEngineKind::Gpu),
                Some(WorkEngineHealth::Ready),
                "a busy GPU is not retired"
            );
        }

        /// Qualifies the CPU engine on the production model bank and checks
        /// one changed claim for the newest known answer. It needs the bank
        /// (about 6.4 GB) and an optimized build; run it alone:
        ///
        /// ```text
        /// CMFD_HW_MODEL_BANK=/path/MODEL-V2.bank \
        /// CMFD_HW_FIXED_RECORD=/path/FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json \
        /// CMFD_WORK_THREADS=6 \
        /// cargo test --release -p cmfd-node --features production-v4 --lib \
        ///     cpu_engine_reproduces_the_known_answer_with_the_model_bank \
        ///     -- --ignored --test-threads=1 --nocapture
        /// ```
        #[test]
        #[ignore = "needs the production model bank; see the doc comment"]
        fn cpu_engine_reproduces_the_known_answer_with_the_model_bank() {
            use cmfd_consensus::{
                ConsensusPowVerifier, ForgeMatrixV4FileLayerSource,
                ForgeMatrixV4FixedArtifactRecordV1,
            };
            use std::fs::File;

            const MAINNET_NETWORK_ID: [u8; 32] =
                hex32("88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62");
            const PUBLISHED_WORK_DIGEST: [u8; 32] =
                hex32("00000a02f22dfed910411a52bb3aabbca035b592c4986cb3297d5c28684297c9");

            let bank_path = std::env::var_os("CMFD_HW_MODEL_BANK").expect("CMFD_HW_MODEL_BANK");
            let record_path =
                std::env::var_os("CMFD_HW_FIXED_RECORD").expect("CMFD_HW_FIXED_RECORD");
            let threads = std::env::var("CMFD_WORK_THREADS")
                .map(|value| value.parse().expect("CMFD_WORK_THREADS is a number"))
                .unwrap_or(6);
            let record: ForgeMatrixV4FixedArtifactRecordV1 =
                serde_json::from_slice(&std::fs::read(record_path).unwrap()).unwrap();
            let started = Instant::now();
            let (_, identity) = ConsensusPowVerifier::v4_candidate_for_network_with_layer_roots(
                MAINNET_NETWORK_ID,
                record,
                std::io::BufReader::with_capacity(1024 * 1024, File::open(&bank_path).unwrap()),
            )
            .unwrap();
            eprintln!(
                "bank authenticated in {:.1}s",
                started.elapsed().as_secs_f64()
            );
            let source = ForgeMatrixV4FileLayerSource::new(
                File::open(&bank_path).unwrap(),
                &identity.manifest,
                identity.base_input,
                identity.layer_roots,
            )
            .unwrap();
            let checker = HonestWorkChecker::new(
                Some(Arc::new(CpuWorkEngine::new(Arc::new(source), threads))),
                None,
                false,
            )
            .unwrap();

            let started = Instant::now();
            assert_eq!(
                checker.run_known_answer_tests().cpu,
                Some(WorkEngineHealth::Ready)
            );
            eprintln!(
                "known answer (height {}, authenticated) in {:.2}s on {threads} threads",
                WORK_KNOWN_ANSWERS[0].height,
                started.elapsed().as_secs_f64()
            );

            let answer = WORK_KNOWN_ANSWERS[0];
            assert_eq!(
                honest_work_digest(answer.challenge_digest, answer.final_activation_digest),
                PUBLISHED_WORK_DIGEST
            );
            let started = Instant::now();
            let WorkVerdict::Mismatch(mismatch) = checker.check(WorkClaim {
                challenge_digest: answer.challenge_digest,
                work_digest: [0xee; 32],
            }) else {
                panic!("a changed work digest must not match");
            };
            eprintln!(
                "changed claim checked in {:.2}s",
                started.elapsed().as_secs_f64()
            );
            assert_eq!(mismatch.provenance(), WorkProvenance::OwnEngine);
            assert_eq!(mismatch.confirmed(), None);
            assert_eq!(
                mismatch.honest_final_activation_digest(),
                answer.final_activation_digest
            );
            assert_eq!(mismatch.honest_work_digest(), PUBLISHED_WORK_DIGEST);
            let started = Instant::now();
            assert_eq!(
                checker.check(WorkClaim {
                    challenge_digest: answer.challenge_digest,
                    work_digest: PUBLISHED_WORK_DIGEST,
                }),
                WorkVerdict::Match(WorkProvenance::OwnEngine)
            );
            assert!(
                started.elapsed() < Duration::from_millis(100),
                "answered from the memo"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Barrier;
    use std::sync::atomic::AtomicUsize;

    /// A scripted engine: known answers are reproduced unless the worker is
    /// marked bad, and any other challenge yields `digest(challenge)` with
    /// `salt` mixed in, or the queued error.
    struct FakeEngine {
        kind: WorkEngineKind,
        workers: usize,
        salt: Mutex<u8>,
        bad_kat: Mutex<HashSet<usize>>,
        /// Scripted outcomes for the next calls: an error, or `None` for a
        /// normal answer.
        errors: Mutex<VecDeque<Option<WorkEngineError>>>,
        calls: AtomicUsize,
        log: Mutex<Vec<(usize, [u8; 32])>>,
        /// The next known answer waits on the first barrier, then the second.
        gate: Mutex<Option<Arc<(Barrier, Barrier)>>>,
    }

    impl FakeEngine {
        fn new(kind: WorkEngineKind) -> Arc<Self> {
            Self::with_workers(kind, 1)
        }

        fn with_workers(kind: WorkEngineKind, workers: usize) -> Arc<Self> {
            Arc::new(Self {
                kind,
                workers,
                salt: Mutex::new(0),
                bad_kat: Mutex::new(HashSet::new()),
                errors: Mutex::new(VecDeque::new()),
                calls: AtomicUsize::new(0),
                log: Mutex::new(Vec::new()),
                gate: Mutex::new(None),
            })
        }

        /// Makes the next known answer wait until the test has passed both
        /// barriers, so the test can act while it runs.
        fn gate_next_known_answer(&self) -> Arc<(Barrier, Barrier)> {
            let gate = Arc::new((Barrier::new(2), Barrier::new(2)));
            *self.gate.lock().unwrap() = Some(gate.clone());
            gate
        }

        fn set_salt(&self, salt: u8) {
            *self.salt.lock().unwrap() = salt;
        }

        fn set_bad_kat(&self, bad: bool) {
            for worker in 0..self.workers {
                self.set_bad_kat_on(worker, bad);
            }
        }

        fn set_bad_kat_on(&self, worker: usize, bad: bool) {
            let mut set = self.bad_kat.lock().unwrap();
            if bad {
                set.insert(worker);
            } else {
                set.remove(&worker);
            }
        }

        fn fail_next(&self, error: WorkEngineError) {
            self.errors.lock().unwrap().push_back(Some(error));
        }

        fn answer_next(&self) {
            self.errors.lock().unwrap().push_back(None);
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        /// Workers of the calls after the first `skip`.
        fn workers_called(&self, skip: usize) -> Vec<usize> {
            self.log.lock().unwrap()[skip..]
                .iter()
                .map(|call| call.0)
                .collect()
        }

        /// Whether the calls after the first `skip` include a known answer.
        fn ran_known_answer(&self, skip: usize) -> bool {
            self.log.lock().unwrap()[skip..].iter().any(|call| {
                WORK_KNOWN_ANSWERS
                    .iter()
                    .any(|answer| answer.challenge_digest == call.1)
            })
        }
    }

    impl WorkEngine for FakeEngine {
        fn kind(&self) -> WorkEngineKind {
            self.kind
        }

        fn workers(&self) -> usize {
            self.workers
        }

        fn final_activation_digest(
            &self,
            challenge_digest: [u8; 32],
            worker: usize,
            _authenticate: bool,
        ) -> Result<[u8; 32], WorkEngineError> {
            assert!(worker < self.workers, "the checker names a real worker");
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.log.lock().unwrap().push((worker, challenge_digest));
            if let Some(Some(error)) = self.errors.lock().unwrap().pop_front() {
                return Err(error);
            }
            if let Some(answer) = WORK_KNOWN_ANSWERS
                .iter()
                .find(|answer| answer.challenge_digest == challenge_digest)
            {
                let gate = self.gate.lock().unwrap().take();
                if let Some(gate) = gate {
                    gate.0.wait();
                    gate.1.wait();
                }
                let mut digest = answer.final_activation_digest;
                if self.bad_kat.lock().unwrap().contains(&worker) {
                    digest[0] ^= 1;
                }
                return Ok(digest);
            }
            Ok(honest_fad(challenge_digest, *self.salt.lock().unwrap()))
        }
    }

    fn honest_fad(challenge_digest: [u8; 32], salt: u8) -> [u8; 32] {
        let mut digest = *blake3::hash(&challenge_digest).as_bytes();
        digest[31] ^= salt;
        digest
    }

    fn challenge(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn honest_claim(byte: u8) -> WorkClaim {
        WorkClaim {
            challenge_digest: challenge(byte),
            work_digest: honest_work_digest(challenge(byte), honest_fad(challenge(byte), 0)),
        }
    }

    fn wrong_claim(byte: u8) -> WorkClaim {
        WorkClaim {
            challenge_digest: challenge(byte),
            work_digest: [0xee; 32],
        }
    }

    fn cpu_only() -> (HonestWorkChecker, Arc<FakeEngine>) {
        let cpu = FakeEngine::new(WorkEngineKind::Cpu);
        let checker = HonestWorkChecker::new(Some(cpu.clone()), None, false).unwrap();
        (checker, cpu)
    }

    fn both() -> (HonestWorkChecker, Arc<FakeEngine>, Arc<FakeEngine>) {
        both_with_gpu_workers(1)
    }

    fn both_with_gpu_workers(
        workers: usize,
    ) -> (HonestWorkChecker, Arc<FakeEngine>, Arc<FakeEngine>) {
        let cpu = FakeEngine::new(WorkEngineKind::Cpu);
        let gpu = FakeEngine::with_workers(WorkEngineKind::Gpu, workers);
        let checker = HonestWorkChecker::new(Some(cpu.clone()), Some(gpu.clone()), false).unwrap();
        (checker, cpu, gpu)
    }

    fn qualified(checker: &HonestWorkChecker) {
        let report = checker.run_known_answer_tests();
        assert_ne!(report.cpu, Some(WorkEngineHealth::Failed));
        assert_ne!(report.gpu, Some(WorkEngineHealth::Failed));
        assert_eq!(checker.engine_state(), WorkEngineState::Ready);
    }

    /// Makes every worker's last known answer older than
    /// [`WORK_MISMATCH_KAT_WINDOW`], so a mismatch only one engine finds
    /// next re-tests its worker first.
    fn age_known_answers(checker: &HonestWorkChecker) {
        checker.age_known_answers();
    }

    #[test]
    fn known_answers_are_the_committed_execution_vectors() {
        let document: serde_json::Value = serde_json::from_str(include_str!(
            "../../cmfd-consensus/data/forgematrix_v4_execution_vectors_v1.json"
        ))
        .unwrap();
        for answer in WORK_KNOWN_ANSWERS {
            let vector = document["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|vector| vector["height"].as_u64() == Some(answer.height))
                .unwrap();
            assert_eq!(
                vector["challenge_digest"].as_str().unwrap(),
                hex::encode(answer.challenge_digest)
            );
            assert_eq!(
                vector["final_activation_digest"].as_str().unwrap(),
                hex::encode(answer.final_activation_digest)
            );
            assert_eq!(
                vector["work_digest"].as_str().unwrap(),
                hex::encode(honest_work_digest(
                    answer.challenge_digest,
                    answer.final_activation_digest
                ))
            );
        }
    }

    #[test]
    fn checker_needs_an_engine_of_the_right_kind() {
        assert_eq!(
            HonestWorkChecker::new(None, None, false).err(),
            Some(WorkCheckerConfigError::NoEngine)
        );
        let cpu: Arc<dyn WorkEngine> = FakeEngine::new(WorkEngineKind::Cpu);
        assert_eq!(
            HonestWorkChecker::new(None, Some(cpu), false).err(),
            Some(WorkCheckerConfigError::WrongKind)
        );
    }

    #[test]
    fn checks_are_unavailable_until_an_engine_reproduces_the_known_answers() {
        let (checker, cpu) = cpu_only();
        assert_eq!(checker.engine_state(), WorkEngineState::Qualifying);
        assert!(checker.known_answer_tests_due(Instant::now()));
        assert_eq!(
            checker.check(honest_claim(1)),
            WorkVerdict::Unavailable(WorkUnavailable::Qualifying)
        );
        assert_eq!(cpu.calls(), 0);

        let report = checker.run_known_answer_tests();
        assert_eq!(report.cpu, Some(WorkEngineHealth::Ready));
        assert_eq!(report.gpu, None);
        assert_eq!(cpu.calls(), CPU_KAT_VECTORS);
        assert!(!checker.known_answer_tests_due(Instant::now() + WORK_KAT_RETRY_MAX));
        assert!(checker.known_answer_tests_due(Instant::now() + WORK_KAT_INTERVAL));
        assert_eq!(
            checker.check(honest_claim(1)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
    }

    #[test]
    fn a_cancelled_known_answer_round_stops_and_leaves_the_engine_qualifying() {
        let (checker, cpu) = cpu_only();
        // Cancelled: no answer runs.
        let report = checker.run_known_answer_tests_cancellable(&|| true);
        assert_eq!(report.cpu, Some(WorkEngineHealth::Qualifying));
        assert_eq!(cpu.calls(), 0);
        assert_eq!(checker.engine_state(), WorkEngineState::Qualifying);
        // It does not count as a retry, so the next round is due at once.
        assert_eq!(checker.state().last_kat, None);
        assert_eq!(checker.state().kat_retries, 0);
        assert!(checker.known_answer_tests_due(Instant::now()));
        // That round qualifies it.
        let report = checker.run_known_answer_tests();
        assert_eq!(report.cpu, Some(WorkEngineHealth::Ready));
    }

    #[test]
    fn a_failed_known_answer_makes_every_check_unavailable_until_it_passes() {
        let (checker, cpu) = cpu_only();
        cpu.set_bad_kat(true);
        assert_eq!(
            checker.run_known_answer_tests().cpu,
            Some(WorkEngineHealth::Failed)
        );
        assert_eq!(checker.engine_state(), WorkEngineState::Failed);
        assert_eq!(checker.alarms().engine_failures, 1);
        assert_eq!(
            checker.check(honest_claim(1)),
            WorkVerdict::Unavailable(WorkUnavailable::EnginesFailed)
        );
        assert_eq!(
            checker.check(wrong_claim(1)),
            WorkVerdict::Unavailable(WorkUnavailable::EnginesFailed)
        );
        // A failed engine is tested again within minutes, not hours.
        assert!(!checker.known_answer_tests_due(Instant::now()));
        assert!(checker.known_answer_tests_due(Instant::now() + WORK_KAT_RETRY_MIN));

        cpu.set_bad_kat(false);
        assert_eq!(
            checker.run_known_answer_tests().cpu,
            Some(WorkEngineHealth::Ready)
        );
        assert_eq!(
            checker.check(honest_claim(1)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
    }

    #[test]
    fn retries_back_off_while_a_worker_stays_failed() {
        let (checker, cpu) = cpu_only();
        cpu.set_bad_kat(true);
        let mut waits = Vec::new();
        for _ in 0..6 {
            checker.run_known_answer_tests();
            let state = checker.state();
            waits.push(kat_retry_wait(state.kat_retries).as_secs());
        }
        assert_eq!(waits, [60, 120, 240, 480, 900, 900]);
        let last = checker.state().last_kat.unwrap();
        assert!(!checker.known_answer_tests_due(last + Duration::from_secs(899)));
        assert!(checker.known_answer_tests_due(last + WORK_KAT_RETRY_MAX));
    }

    #[test]
    fn a_transient_cpu_read_error_during_the_known_answers_does_not_retire_it() {
        // One read error: retried at once and qualified.
        let (checker, cpu) = cpu_only();
        cpu.fail_next(WorkEngineError::Failed("read error".to_owned()));
        assert_eq!(
            checker.run_known_answer_tests().cpu,
            Some(WorkEngineHealth::Ready)
        );
        assert_eq!(cpu.calls(), 2);
        assert!(!checker.known_answer_tests_due(Instant::now() + WORK_KAT_RETRY_MAX));

        // Two in a row at the six-hourly round: it keeps its health, is
        // shown as erroring and is tested again soon.
        let (checker, cpu) = cpu_only();
        qualified(&checker);
        cpu.fail_next(WorkEngineError::Failed("read error".to_owned()));
        cpu.fail_next(WorkEngineError::Failed("read error".to_owned()));
        let round = Instant::now() + WORK_KAT_INTERVAL;
        assert_eq!(
            checker.run_known_answer_tests_at(round, &|| false).cpu,
            Some(WorkEngineHealth::Ready)
        );
        assert_eq!(checker.alarms().engine_failures, 1);
        assert_eq!(checker.worker_erroring(WorkEngineKind::Cpu, 0), Some(true));
        assert!(!checker.known_answer_tests_due(round));
        assert!(checker.known_answer_tests_due(round + WORK_KAT_RETRY_MIN));
        assert_eq!(
            checker.check(honest_claim(1)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(checker.worker_erroring(WorkEngineKind::Cpu, 0), Some(false));

        // Never qualified yet: it stays qualifying, not failed.
        let (checker, cpu) = cpu_only();
        cpu.fail_next(WorkEngineError::Failed("read error".to_owned()));
        cpu.fail_next(WorkEngineError::Failed("read error".to_owned()));
        assert_eq!(
            checker.run_known_answer_tests().cpu,
            Some(WorkEngineHealth::Qualifying)
        );
        assert!(checker.known_answer_tests_due(Instant::now() + WORK_KAT_RETRY_MIN));
        assert_eq!(
            checker.run_known_answer_tests().cpu,
            Some(WorkEngineHealth::Ready)
        );
    }

    #[test]
    fn gpu_qualification_runs_two_known_answers_and_a_busy_gpu_keeps_its_health() {
        let (checker, cpu, gpu) = both();
        gpu.fail_next(WorkEngineError::Busy);
        let report = checker.run_known_answer_tests();
        assert_eq!(report.cpu, Some(WorkEngineHealth::Ready));
        assert_eq!(report.gpu, Some(WorkEngineHealth::Qualifying));
        assert_eq!(cpu.calls(), CPU_KAT_VECTORS);
        // A busy round is retried soon, not after the full interval.
        assert!(checker.known_answer_tests_due(Instant::now() + WORK_KAT_RETRY_MIN));
        let report = checker.run_known_answer_tests();
        assert_eq!(report.gpu, Some(WorkEngineHealth::Ready));
        assert_eq!(gpu.calls(), 1 + GPU_KAT_VECTORS);
        assert_eq!(cpu.calls(), CPU_KAT_VECTORS, "the ready CPU is left alone");
        assert!(checker.has_independent_engines());
        assert!(!checker.known_answer_tests_due(Instant::now() + WORK_KAT_RETRY_MAX));
    }

    #[test]
    fn a_retry_round_tests_only_the_workers_that_are_not_ready() {
        let (checker, cpu, gpu) = both_with_gpu_workers(2);
        // GPU worker 0 is busy at every round, as on a busy pool.
        gpu.fail_next(WorkEngineError::Busy);
        let start = Instant::now();
        checker.run_known_answer_tests_at(start, &|| false);
        assert_eq!(
            checker.worker_health(WorkEngineKind::Gpu, 0),
            Some(WorkEngineHealth::Qualifying)
        );
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        for round in 1..=4 {
            let at = start + WORK_KAT_RETRY_MAX * round;
            assert!(checker.known_answer_tests_due(at));
            gpu.fail_next(WorkEngineError::Busy);
            checker.run_known_answer_tests_at(at, &|| false);
        }
        assert_eq!(cpu.calls(), cpu_before, "the ready CPU is not tested again");
        assert_eq!(
            gpu.workers_called(gpu_before),
            [0, 0, 0, 0],
            "only the busy worker is tried, once a round"
        );

        // Six hours after it passed, a ready worker is due again on its own.
        let later = start + WORK_KAT_INTERVAL;
        assert!(checker.known_answer_tests_due(later));
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        checker.run_known_answer_tests_at(later, &|| false);
        assert_eq!(cpu.calls(), cpu_before + CPU_KAT_VECTORS);
        assert_eq!(gpu.workers_called(gpu_before), [0, 0, 1, 1]);
        assert_eq!(checker.engine_state(), WorkEngineState::Ready);
        assert!(!checker.known_answer_tests_due(later + WORK_KAT_RETRY_MAX));
        assert!(checker.known_answer_tests_due(later + WORK_KAT_INTERVAL));
    }

    #[test]
    fn a_cpu_job_that_cannot_read_marks_the_cpu_erroring_until_it_reads_again() {
        let (checker, cpu) = cpu_only();
        qualified(&checker);
        cpu.fail_next(WorkEngineError::Failed("bank file missing".to_owned()));
        assert!(matches!(
            checker.check(honest_claim(1)),
            WorkVerdict::Unavailable(WorkUnavailable::Engine(WorkEngineError::Failed(_)))
        ));
        assert_eq!(checker.worker_erroring(WorkEngineKind::Cpu, 0), Some(true));
        assert_eq!(
            checker.engine_health(WorkEngineKind::Cpu),
            Some(WorkEngineHealth::Ready)
        );
        assert!(checker.known_answer_tests_due(Instant::now() + WORK_KAT_RETRY_MIN));
        let before = cpu.calls();
        checker.run_known_answer_tests();
        assert_eq!(cpu.calls(), before + CPU_KAT_VECTORS, "tested again");
        assert_eq!(checker.worker_erroring(WorkEngineKind::Cpu, 0), Some(false));
        assert!(!checker.known_answer_tests_due(Instant::now() + WORK_KAT_RETRY_MAX));
    }

    #[test]
    fn a_round_does_not_bring_back_a_worker_retired_while_it_ran() {
        let (checker, _cpu, gpu) = both();
        let checker = Arc::new(checker);
        let gate = gpu.gate_next_known_answer();
        let round = {
            let checker = checker.clone();
            std::thread::spawn(move || checker.run_known_answer_tests())
        };
        gate.0.wait();
        let gpu_worker = Producer {
            kind: WorkEngineKind::Gpu,
            worker: 0,
        };
        checker.mark_failed(gpu_worker, "retired by another check");
        gate.1.wait();
        round.join().unwrap();
        assert_eq!(
            checker.worker_health(WorkEngineKind::Gpu, 0),
            Some(WorkEngineHealth::Failed)
        );
        // The next round qualifies it again.
        checker.run_known_answer_tests();
        assert_eq!(
            checker.worker_health(WorkEngineKind::Gpu, 0),
            Some(WorkEngineHealth::Ready)
        );
    }

    #[test]
    fn a_mismatch_is_not_confirmed_if_a_worker_is_retired_meanwhile() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        let checker = Arc::new(checker);
        // The GPU computes the block, the CPU agrees, and the CPU is retired
        // while the GPU runs its confirming known answer.
        let gate = gpu.gate_next_known_answer();
        let check = {
            let checker = checker.clone();
            std::thread::spawn(move || checker.check(wrong_claim(31)))
        };
        gate.0.wait();
        let cpu_worker = Producer {
            kind: WorkEngineKind::Cpu,
            worker: 0,
        };
        checker.mark_failed(cpu_worker, "retired by another check");
        gate.1.wait();
        let WorkVerdict::Mismatch(mismatch) = check.join().unwrap() else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::OwnEngine);
        assert_eq!(mismatch.confirmed(), None);
        assert_eq!(
            checker.memo_len(),
            0,
            "the retired CPU's result is not kept"
        );
        assert!(cpu.calls() > 0);
    }

    #[test]
    fn gpu_workers_are_qualified_and_retired_one_by_one() {
        let (checker, _cpu, gpu) = both_with_gpu_workers(3);
        gpu.set_bad_kat_on(2, true);
        let report = checker.run_known_answer_tests();
        assert_eq!(report.gpu, Some(WorkEngineHealth::Ready));
        assert_eq!(gpu.workers_called(0), [0, 0, 1, 1, 2]);
        assert_eq!(
            checker.worker_health(WorkEngineKind::Gpu, 2),
            Some(WorkEngineHealth::Failed)
        );
        assert_eq!(checker.worker_health(WorkEngineKind::Gpu, 3), None);
        assert!(checker.known_answer_tests_due(Instant::now() + WORK_KAT_RETRY_MIN));

        // Jobs prefer worker 1, never use the failed worker 2, and the
        // confirmation's known answer runs on the worker that computed.
        let before = gpu.calls();
        assert_eq!(
            checker.check(honest_claim(2)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        gpu.fail_next(WorkEngineError::Busy);
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(3)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::Confirmed);
        assert_eq!(gpu.workers_called(before), [1, 1, 0, 0]);

        // A failed job on worker 0 retires only worker 0.
        gpu.fail_next(WorkEngineError::Busy);
        gpu.fail_next(WorkEngineError::Failed("timed out".to_owned()));
        assert_eq!(
            checker.check(honest_claim(4)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(
            checker.worker_health(WorkEngineKind::Gpu, 0),
            Some(WorkEngineHealth::Failed)
        );
        assert_eq!(
            checker.worker_health(WorkEngineKind::Gpu, 1),
            Some(WorkEngineHealth::Ready)
        );
        assert!(checker.has_independent_engines());
        gpu.set_bad_kat_on(2, false);
        checker.run_known_answer_tests();
        assert_eq!(
            checker.worker_health(WorkEngineKind::Gpu, 2),
            Some(WorkEngineHealth::Ready)
        );
    }

    #[test]
    fn a_stopped_gpu_worker_is_retired_and_the_cpu_takes_over() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        gpu.fail_next(WorkEngineError::Stopped("not running".to_owned()));
        let before = cpu.calls();
        assert_eq!(
            checker.check(honest_claim(5)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(cpu.calls(), before + 1);
        assert_eq!(
            checker.engine_health(WorkEngineKind::Gpu),
            Some(WorkEngineHealth::Failed)
        );
        assert!(!checker.has_independent_engines());
        assert_eq!(checker.alarms().engine_failures, 1);
        // Still not running at the next round: it stays retired.
        gpu.fail_next(WorkEngineError::Stopped("not running".to_owned()));
        assert_eq!(
            checker.run_known_answer_tests().gpu,
            Some(WorkEngineHealth::Failed)
        );
        assert_eq!(
            checker.run_known_answer_tests().gpu,
            Some(WorkEngineHealth::Ready)
        );
    }

    #[test]
    fn a_match_from_the_first_engine_is_final_and_memoized() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        assert_eq!(
            checker.check(honest_claim(2)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(gpu.calls(), gpu_before + 1, "the GPU runs first");
        assert_eq!(cpu.calls(), cpu_before, "a match is not confirmed");
        assert_eq!(
            checker.check(honest_claim(2)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(
            gpu.calls(),
            gpu_before + 1,
            "a repeat answers from the memo"
        );
    }

    /// The info lines on target `work_rule` that `action` logs on this
    /// thread.
    fn work_rule_lines(action: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Lines(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Lines {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let lines = Lines::default();
        let writer = lines.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, action);
        let bytes = lines.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn a_block_the_cpu_checks_because_the_gpu_workers_are_busy_is_logged_once() {
        let (checker, _cpu, gpu) = both();
        qualified(&checker);
        let fallback = "gpu replay workers busy; checked on the cpu";
        let challenge = hex::encode(honest_claim(4).challenge_digest);
        let lines = work_rule_lines(|| {
            gpu.fail_next(WorkEngineError::Busy);
            assert_eq!(
                checker.check(honest_claim(4)),
                WorkVerdict::Match(WorkProvenance::OwnEngine)
            );
            // The same block checked again that way is not logged again.
            checker.forget(honest_claim(4).challenge_digest);
            gpu.fail_next(WorkEngineError::Busy);
            checker.check(honest_claim(4));
            // Nor is one the GPU checks, or one it could not run for another
            // reason.
            checker.check(honest_claim(5));
            gpu.fail_next(WorkEngineError::Failed("read".to_owned()));
            checker.check(honest_claim(6));
        });
        assert_eq!(lines.matches(fallback).count(), 1, "{lines}");
        assert!(lines.contains(&challenge), "{lines}");
    }

    #[test]
    fn the_expected_check_time_is_the_first_ready_engines_last_job() {
        let (checker, _cpu, _gpu) = both();
        assert_eq!(checker.expected_check_time(Instant::now()), None);
        qualified(&checker);
        assert_eq!(
            checker.expected_check_time(Instant::now()),
            None,
            "nothing is expected before a job ran"
        );
        checker.check(honest_claim(3));
        let measured = checker.expected_check_time(Instant::now()).unwrap();
        assert!(measured < Duration::from_secs(5));

        // The GPU goes first; its known answers count only while no CPU
        // worker could confirm a mismatch.
        checker.set_check_times(
            WorkEngineKind::Gpu,
            Duration::from_secs(3),
            Some(Duration::from_secs(7)),
        );
        checker.set_check_times(WorkEngineKind::Cpu, Duration::from_secs(30), None);
        age_known_answers(&checker);
        assert_eq!(
            checker.expected_check_time(Instant::now()),
            Some(Duration::from_secs(3))
        );

        // With the GPU retired the CPU goes first, alone.
        let (checker, _cpu, gpu) = both();
        gpu.set_bad_kat(true);
        assert_eq!(
            checker.run_known_answer_tests().gpu,
            Some(WorkEngineHealth::Failed)
        );
        checker.set_check_times(
            WorkEngineKind::Cpu,
            Duration::from_secs(30),
            Some(Duration::from_secs(5)),
        );
        assert_eq!(
            checker.expected_check_time(Instant::now()),
            Some(Duration::from_secs(30))
        );
        age_known_answers(&checker);
        assert_eq!(
            checker.expected_check_time(Instant::now()),
            Some(Duration::from_secs(35))
        );

        // On one engine, known answers that are due are added.
        let (checker, _cpu) = cpu_only();
        qualified(&checker);
        checker.set_check_times(
            WorkEngineKind::Cpu,
            Duration::from_secs(20),
            Some(Duration::from_secs(25)),
        );
        assert_eq!(
            checker.expected_check_time(Instant::now()),
            Some(Duration::from_secs(20))
        );
        age_known_answers(&checker);
        assert_eq!(
            checker.expected_check_time(Instant::now()),
            Some(Duration::from_secs(45))
        );
    }

    #[test]
    fn a_cpu_only_mismatch_stays_own_engine_and_a_repeat_runs_nothing() {
        let (checker, cpu) = cpu_only();
        qualified(&checker);
        age_known_answers(&checker);
        let before = cpu.calls();
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(3)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::OwnEngine);
        assert_eq!(mismatch.confirmed(), None);
        assert!(mismatch.cacheable(), "no other engine can settle it");
        assert_eq!(
            mismatch.honest_final_activation_digest(),
            honest_fad(challenge(3), 0)
        );
        assert_eq!(mismatch.honest_work_digest(), honest_claim(3).work_digest);
        assert_eq!(mismatch.claimed_work_digest(), [0xee; 32]);
        assert_eq!(
            cpu.calls(),
            before + 2,
            "the block, then one known answer on the same worker"
        );
        assert!(cpu.ran_known_answer(before + 1));
        assert_eq!(checker.alarms().own_engine_mismatches, 1);

        assert_eq!(
            checker.check(wrong_claim(3)),
            WorkVerdict::Mismatch(mismatch)
        );
        assert_eq!(checker.memo_mismatch(wrong_claim(3)), Some(mismatch));
        assert_eq!(checker.memo_mismatch(honest_claim(3)), None);
        assert!(checker.holds_lone_final_mismatch(wrong_claim(3)));
        assert!(!checker.holds_lone_final_mismatch(honest_claim(3)));
        assert_eq!(cpu.calls(), before + 2, "a repeat is a memo hit");
        assert_eq!(checker.alarms().own_engine_mismatches, 1);
        assert_eq!(
            checker.check(honest_claim(3)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(cpu.calls(), before + 2);

        // Within the window, another block that differs runs only itself.
        assert!(matches!(
            checker.check(wrong_claim(5)),
            WorkVerdict::Mismatch(mismatch) if mismatch.cacheable()
        ));
        assert_eq!(cpu.calls(), before + 3, "one known answer per window");
        assert_eq!(checker.alarms().own_engine_mismatches, 2);

        // Once the window has passed, a repeat re-tests the worker with one
        // known answer, and the block is not run again.
        age_known_answers(&checker);
        assert_eq!(checker.memo_mismatch(wrong_claim(3)), None);
        assert!(!checker.holds_lone_final_mismatch(wrong_claim(3)));
        assert_eq!(
            checker.check(wrong_claim(3)),
            WorkVerdict::Mismatch(mismatch)
        );
        assert_eq!(cpu.calls(), before + 4);
        assert!(cpu.ran_known_answer(before + 3));
        assert!(
            checker.holds_lone_final_mismatch(wrong_claim(3)),
            "final again once the worker passed"
        );
        assert_eq!(
            checker.alarms().own_engine_mismatches,
            2,
            "not raised again"
        );
    }

    #[test]
    fn a_cpu_only_mismatch_is_unavailable_if_the_worker_then_fails_its_known_answer() {
        let (checker, cpu) = cpu_only();
        qualified(&checker);
        age_known_answers(&checker);

        // The model data changed since it was authenticated: the block runs,
        // then its known answer fails the layer check.
        cpu.answer_next();
        cpu.fail_next(WorkEngineError::Integrity("layer 7".to_owned()));
        assert_eq!(
            checker.check(wrong_claim(3)),
            WorkVerdict::Unavailable(WorkUnavailable::KnownAnswerFailed)
        );
        assert_eq!(checker.memo_mismatch(wrong_claim(3)), None);
        assert_eq!(checker.alarms().own_engine_mismatches, 0);
        assert_eq!(
            checker.engine_health(WorkEngineKind::Cpu),
            Some(WorkEngineHealth::Failed)
        );
        assert_eq!(
            checker.check(honest_claim(3)),
            WorkVerdict::Unavailable(WorkUnavailable::EnginesFailed)
        );

        // A worker that computes wrong answers fails the same way.
        qualified(&checker);
        age_known_answers(&checker);
        cpu.set_bad_kat(true);
        assert_eq!(
            checker.check(wrong_claim(4)),
            WorkVerdict::Unavailable(WorkUnavailable::KnownAnswerFailed)
        );
        assert_eq!(checker.memo_mismatch(wrong_claim(4)), None);
        assert_eq!(checker.alarms().own_engine_mismatches, 0);

        // Once it reproduces its known answers again, the block is checked
        // again from the start.
        cpu.set_bad_kat(false);
        qualified(&checker);
        age_known_answers(&checker);
        let before = cpu.calls();
        assert!(matches!(
            checker.check(wrong_claim(4)),
            WorkVerdict::Mismatch(mismatch) if mismatch.provenance() == WorkProvenance::OwnEngine
        ));
        assert_eq!(cpu.calls(), before + 2);
        assert_eq!(checker.alarms().own_engine_mismatches, 1);
    }

    #[test]
    fn a_mismatch_both_engines_reproduce_is_confirmed_after_a_gpu_known_answer() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(4)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::Confirmed);
        assert!(mismatch.cacheable());
        let confirmed = mismatch.confirmed().unwrap();
        assert_eq!(confirmed.challenge_digest(), challenge(4));
        assert_eq!(confirmed.claimed_work_digest(), [0xee; 32]);
        assert_eq!(cpu.calls(), cpu_before + 1);
        assert_eq!(
            gpu.calls(),
            gpu_before + 2,
            "the block, then one known answer"
        );
        assert_eq!(checker.alarms(), WorkAlarmCounts::default());
        assert_eq!(checker.memo_mismatch(wrong_claim(4)), Some(mismatch));
    }

    #[test]
    fn a_mismatch_is_never_confirmed_by_the_engine_that_found_it() {
        // GPU busy: the CPU runs first; the GPU is then the confirmer.
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        gpu.fail_next(WorkEngineError::Busy);
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(5)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::Confirmed);
        assert_eq!(cpu.calls(), cpu_before + 1);
        assert_eq!(
            gpu.calls(),
            gpu_before + 3,
            "busy, the block, a known answer"
        );

        // GPU busy for both its turns: the CPU's mismatch stays its own.
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        gpu.fail_next(WorkEngineError::Busy);
        gpu.fail_next(WorkEngineError::Busy);
        let cpu_before = cpu.calls();
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(5)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::OwnEngine);
        assert!(!mismatch.cacheable(), "the GPU can still settle it");
        assert_eq!(cpu.calls(), cpu_before + 1, "the CPU never confirms itself");
        assert_eq!(checker.alarms().own_engine_mismatches, 1);

        // While the GPU is ready that mismatch is not final: no fast reject,
        // and the next check runs the GPU and confirms it from the memo.
        assert_eq!(checker.memo_mismatch(wrong_claim(5)), None);
        gpu.fail_next(WorkEngineError::Busy);
        let WorkVerdict::Mismatch(still) = checker.check(wrong_claim(5)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(still.provenance(), WorkProvenance::OwnEngine);
        assert!(!still.cacheable());
        assert_eq!(
            checker.alarms().own_engine_mismatches,
            1,
            "not raised again"
        );
        let gpu_before = gpu.calls();
        let WorkVerdict::Mismatch(confirmed) = checker.check(wrong_claim(5)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(confirmed.provenance(), WorkProvenance::Confirmed);
        assert_eq!(cpu.calls(), cpu_before + 1, "the CPU result was reused");
        assert_eq!(gpu.calls(), gpu_before + 2, "the block, a known answer");
        assert_eq!(checker.memo_mismatch(wrong_claim(5)), Some(confirmed));
    }

    #[test]
    fn a_busy_confirming_known_answer_keeps_the_cpu_result_for_a_cheap_retry() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        // The GPU computes the block, the CPU agrees, the GPU's known answer
        // is busy: not confirmed, and the CPU's result is the one kept.
        gpu.answer_next();
        gpu.fail_next(WorkEngineError::Busy);
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(27)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::OwnEngine);
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(27)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::Confirmed);
        assert_eq!(cpu.calls(), cpu_before, "the CPU is not run again");
        assert_eq!(gpu.calls(), gpu_before + 2, "the block, a known answer");
    }

    #[test]
    fn a_cpu_mismatch_the_gpu_overturns_later_is_accepted_and_the_cpu_tested() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        cpu.set_salt(9);
        gpu.fail_next(WorkEngineError::Busy);
        gpu.fail_next(WorkEngineError::Busy);
        assert!(matches!(
            checker.check(honest_claim(6)),
            WorkVerdict::Mismatch(mismatch) if mismatch.provenance() == WorkProvenance::OwnEngine
        ));
        let cpu_before = cpu.calls();
        assert_eq!(
            checker.check(honest_claim(6)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(checker.alarms().engine_divergence, 1);
        assert!(cpu.ran_known_answer(cpu_before), "the CPU is tested again");
        assert_eq!(
            checker.engine_health(WorkEngineKind::Cpu),
            Some(WorkEngineHealth::Ready)
        );
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        assert_eq!(
            checker.check(honest_claim(6)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!((cpu.calls(), gpu.calls()), (cpu_before, gpu_before));

        // The same with a CPU that no longer reproduces its known answer.
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        cpu.set_salt(9);
        cpu.set_bad_kat(true);
        gpu.fail_next(WorkEngineError::Busy);
        assert_eq!(
            checker.check(honest_claim(6)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(
            checker.engine_health(WorkEngineKind::Cpu),
            Some(WorkEngineHealth::Failed)
        );
    }

    #[test]
    fn a_gpu_prewarm_that_differs_from_the_block_is_checked_on_the_cpu() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        gpu.set_salt(9);
        checker.prewarm(challenge(7)).unwrap();
        assert_eq!(checker.memo_mismatch(honest_claim(7)), None);
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        assert_eq!(
            checker.check(honest_claim(7)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(cpu.calls(), cpu_before + 1);
        assert_eq!(checker.alarms().engine_divergence, 1);
        assert!(gpu.ran_known_answer(gpu_before), "the GPU is tested again");
        assert_eq!(gpu.workers_called(gpu_before), [0]);
    }

    #[test]
    fn a_gpu_that_agrees_but_fails_its_known_answer_gives_no_verdict() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        gpu.set_bad_kat(true);
        assert_eq!(
            checker.check(wrong_claim(6)),
            WorkVerdict::Unavailable(WorkUnavailable::KnownAnswerFailed)
        );
        assert_eq!(
            checker.engine_health(WorkEngineKind::Gpu),
            Some(WorkEngineHealth::Failed)
        );
        assert!(!checker.has_independent_engines());
        // The CPU's result is kept. With no confirmer left it is the CPU's
        // own mismatch, answered from the memo without running the CPU.
        let cpu_before = cpu.calls();
        let held = checker.memo_mismatch(wrong_claim(6)).unwrap();
        assert_eq!(held.provenance(), WorkProvenance::OwnEngine);
        assert!(held.cacheable());
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(6)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch, held);
        assert_eq!(cpu.calls(), cpu_before);
    }

    #[test]
    fn a_confirmer_that_matches_the_block_accepts_it_and_raises_an_alarm() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        gpu.set_salt(9);
        assert_eq!(
            checker.check(honest_claim(7)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(checker.alarms().engine_divergence, 1);
        // The GPU still reproduces its known answer, so it stays ready.
        assert_eq!(
            checker.engine_health(WorkEngineKind::Gpu),
            Some(WorkEngineHealth::Ready)
        );
        let before = cpu.calls();
        assert_eq!(
            checker.check(honest_claim(7)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(cpu.calls(), before, "the CPU result is memoized");

        // The same with a GPU that also fails its known answer: retired.
        let (checker, _cpu, gpu) = both();
        qualified(&checker);
        gpu.set_salt(9);
        gpu.set_bad_kat(true);
        assert_eq!(
            checker.check(honest_claim(7)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(
            checker.engine_health(WorkEngineKind::Gpu),
            Some(WorkEngineHealth::Failed)
        );
        assert_eq!(checker.memo_len(), 1, "the CPU's result is kept");
    }

    #[test]
    fn engines_that_disagree_with_each_other_and_the_block_give_no_verdict() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        gpu.set_salt(9);
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        assert_eq!(
            checker.check(wrong_claim(8)),
            WorkVerdict::Unavailable(WorkUnavailable::EnginesDisagree)
        );
        assert_eq!(checker.alarms().engine_divergence, 1);
        assert_eq!(checker.memo_mismatch(wrong_claim(8)), None);
        assert_eq!(checker.memo_len(), 0);
        assert!(gpu.ran_known_answer(gpu_before) && cpu.ran_known_answer(cpu_before));
        assert!(checker.has_independent_engines(), "both still pass");

        // A re-send within the hold runs neither engine, nor does a prewarm.
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        assert_eq!(
            checker.check(wrong_claim(8)),
            WorkVerdict::Unavailable(WorkUnavailable::EnginesDisagree)
        );
        assert_eq!(
            checker.prewarm(challenge(8)),
            Err(WorkUnavailable::EnginesDisagree)
        );
        assert_eq!((cpu.calls(), gpu.calls()), (cpu_before, gpu_before));
        assert_eq!(checker.alarms().engine_divergence, 1, "not raised again");

        // After the hold the engines run again.
        {
            let mut state = checker.state();
            let earlier = Instant::now().checked_sub(WORK_DISAGREEMENT_HOLD).unwrap();
            for held in &mut state.disagreements {
                held.at = earlier;
            }
        }
        assert_eq!(
            checker.check(wrong_claim(8)),
            WorkVerdict::Unavailable(WorkUnavailable::EnginesDisagree)
        );
        assert!(gpu.calls() > gpu_before && cpu.calls() > cpu_before);
        assert_eq!(checker.alarms().engine_divergence, 2);

        // Forgetting the challenge ends the hold too.
        assert!(!checker.forget(challenge(8)));
        let gpu_before = gpu.calls();
        checker.check(wrong_claim(8));
        assert!(gpu.calls() > gpu_before);

        // So does retiring a worker: the next check runs the CPU alone.
        gpu.set_bad_kat(true);
        checker.run_known_answer_tests_at(Instant::now() + WORK_KAT_INTERVAL, &|| false);
        assert!(!checker.has_independent_engines());
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(8)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::OwnEngine);
        assert!(mismatch.cacheable());
    }

    #[test]
    fn retiring_a_worker_outside_a_disagreement_keeps_the_hold() {
        let (checker, cpu, gpu) = both_with_gpu_workers(2);
        qualified(&checker);
        gpu.set_salt(9);
        // GPU worker 1 and the CPU disagree with each other and the block.
        assert_eq!(
            checker.check(wrong_claim(32)),
            WorkVerdict::Unavailable(WorkUnavailable::EnginesDisagree)
        );
        let gpu_worker = |worker| Producer {
            kind: WorkEngineKind::Gpu,
            worker,
        };
        checker.mark_failed(gpu_worker(0), "timed out on another job");
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        assert_eq!(
            checker.check(wrong_claim(32)),
            WorkVerdict::Unavailable(WorkUnavailable::EnginesDisagree)
        );
        assert_eq!((cpu.calls(), gpu.calls()), (cpu_before, gpu_before));
        // Retiring one of the two ends it.
        checker.mark_failed(gpu_worker(1), "failed its known answer");
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(32)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::OwnEngine);
        assert_eq!(
            cpu.calls(),
            cpu_before + 1,
            "the block alone: with no GPU worker left, the CPU passed its known answers moments ago"
        );
    }

    #[test]
    fn a_failed_gpu_job_falls_back_to_the_cpu_and_retires_the_gpu() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        gpu.fail_next(WorkEngineError::Failed("timed out".to_owned()));
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        assert_eq!(
            checker.check(honest_claim(9)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(cpu.calls(), cpu_before + 1);
        assert_eq!(gpu.calls(), gpu_before + 1);
        assert_eq!(
            checker.engine_health(WorkEngineKind::Gpu),
            Some(WorkEngineHealth::Failed)
        );
        assert_eq!(checker.engine_state(), WorkEngineState::Ready);
        assert_eq!(
            checker.check(honest_claim(10)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(gpu.calls(), gpu_before + 1, "a retired GPU is not used");
        // Its known answers are due within minutes and bring it back.
        assert!(checker.known_answer_tests_due(Instant::now() + WORK_KAT_RETRY_MIN));
        checker.run_known_answer_tests();
        assert!(checker.has_independent_engines());
    }

    #[test]
    fn a_failed_cpu_job_is_unavailable_without_retiring_the_cpu() {
        let (checker, cpu) = cpu_only();
        qualified(&checker);
        cpu.fail_next(WorkEngineError::Failed("read error".to_owned()));
        assert_eq!(
            checker.check(honest_claim(11)),
            WorkVerdict::Unavailable(WorkUnavailable::Engine(WorkEngineError::Failed(
                "read error".to_owned()
            )))
        );
        assert_eq!(
            checker.engine_health(WorkEngineKind::Cpu),
            Some(WorkEngineHealth::Ready)
        );
        assert_eq!(checker.memo_len(), 0);
        assert_eq!(
            checker.check(honest_claim(11)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
    }

    #[test]
    fn an_integrity_failure_retires_the_engine_and_forgets_its_unconfirmed_results() {
        let (checker, cpu) = cpu_only();
        qualified(&checker);
        assert!(matches!(
            checker.check(wrong_claim(12)),
            WorkVerdict::Mismatch(_)
        ));
        assert_eq!(checker.memo_len(), 1);
        cpu.fail_next(WorkEngineError::Integrity("layer 3".to_owned()));
        assert!(matches!(
            checker.check(honest_claim(13)),
            WorkVerdict::Unavailable(WorkUnavailable::Engine(WorkEngineError::Integrity(_)))
        ));
        assert_eq!(checker.engine_state(), WorkEngineState::Failed);
        assert_eq!(checker.memo_len(), 0);
        assert_eq!(checker.memo_mismatch(wrong_claim(12)), None);
    }

    #[test]
    fn a_confirmed_result_survives_an_engine_failure() {
        let (checker, _cpu, gpu) = both();
        qualified(&checker);
        assert!(matches!(
            checker.check(wrong_claim(14)),
            WorkVerdict::Mismatch(mismatch) if mismatch.confirmed().is_some()
        ));
        assert_eq!(
            checker.check(honest_claim(15)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        gpu.fail_next(WorkEngineError::Integrity("bad output".to_owned()));
        checker.check(honest_claim(16));
        assert_eq!(
            checker.memo_len(),
            2,
            "the confirmed entry and the CPU's new one"
        );
        assert!(checker.memo_mismatch(wrong_claim(14)).is_some());
    }

    #[test]
    fn retiring_a_gpu_worker_keeps_the_cpu_results() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        gpu.fail_next(WorkEngineError::Busy);
        checker.check(honest_claim(21));
        checker.check(honest_claim(22));
        assert_eq!(checker.memo_len(), 2, "one from each engine");
        gpu.fail_next(WorkEngineError::Integrity("bad output".to_owned()));
        checker.check(honest_claim(23));
        assert_eq!(checker.memo_len(), 2, "the GPU's entry is gone");
        let before = cpu.calls();
        assert_eq!(
            checker.check(honest_claim(21)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(cpu.calls(), before, "the CPU's result is still held");
    }

    #[test]
    fn a_result_from_a_worker_retired_meanwhile_is_not_kept() {
        let (checker, _cpu, _gpu) = both();
        qualified(&checker);
        let producer = Producer {
            kind: WorkEngineKind::Gpu,
            worker: 0,
        };
        let run = Run {
            producer,
            generation: checker.state().slot(producer).unwrap().generation,
            final_activation_digest: honest_fad(challenge(24), 0),
        };
        checker.mark_failed(producer, "retired while the job ran");
        checker.memoize(challenge(24), run, WorkProvenance::OwnEngine);
        assert_eq!(checker.memo_len(), 0);
        // Qualified again, the stale run still does not count.
        checker.run_known_answer_tests();
        checker.memoize(challenge(24), run, WorkProvenance::OwnEngine);
        assert_eq!(checker.memo_len(), 0);
    }

    #[test]
    fn a_pool_supplied_result_never_rejects_a_block() {
        let (checker, cpu) = cpu_only();
        qualified(&checker);
        // A wiring error hands over the wrong digest for an honest block.
        checker.record_honest(crate::honest_work::PoolReplayResult::new(
            challenge(17),
            [0x55; 32],
            0,
        ));
        assert_eq!(checker.memo_mismatch(honest_claim(17)), None);
        let before = cpu.calls();
        assert_eq!(
            checker.check(honest_claim(17)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(cpu.calls(), before + 1, "the node's own engine decides");
        // The own result now outranks any later pool-supplied one.
        checker.record_honest(crate::honest_work::PoolReplayResult::new(
            challenge(17),
            [0x55; 32],
            0,
        ));
        assert_eq!(
            checker.check(honest_claim(17)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(cpu.calls(), before + 1);
    }

    #[test]
    fn a_pool_supplied_match_is_trusted_only_after_its_worker_reproduces_a_known_answer() {
        // CPU-only: no worker to check, so the CPU computes.
        let (checker, cpu) = cpu_only();
        qualified(&checker);
        checker.record_honest(crate::honest_work::PoolReplayResult::new(
            challenge(18),
            honest_fad(challenge(18), 0),
            0,
        ));
        let before = cpu.calls();
        assert_eq!(
            checker.check(honest_claim(18)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(cpu.calls(), before + 1);

        // GPU node: one known answer on the producing worker, no block run,
        // and a repeat runs nothing.
        let (checker, cpu, gpu) = both_with_gpu_workers(3);
        qualified(&checker);
        checker.record_honest(crate::honest_work::PoolReplayResult::new(
            challenge(18),
            honest_fad(challenge(18), 0),
            2,
        ));
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        assert_eq!(
            checker.check(honest_claim(18)),
            WorkVerdict::Match(WorkProvenance::RecordHonest)
        );
        assert_eq!(cpu.calls(), cpu_before);
        assert_eq!(gpu.workers_called(gpu_before), [2]);
        assert!(gpu.ran_known_answer(gpu_before));
        assert_eq!(
            checker.check(honest_claim(18)),
            WorkVerdict::Match(WorkProvenance::RecordHonest)
        );
        assert_eq!(gpu.calls(), gpu_before + 1);

        // That worker busy: not trusted, the node computes.
        checker.record_honest(crate::honest_work::PoolReplayResult::new(
            challenge(20),
            honest_fad(challenge(20), 0),
            2,
        ));
        gpu.fail_next(WorkEngineError::Busy);
        assert_eq!(
            checker.check(honest_claim(20)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );

        // A worker that fails its known answer is retired and the node
        // computes instead.
        checker.record_honest(crate::honest_work::PoolReplayResult::new(
            challenge(19),
            honest_fad(challenge(19), 0),
            1,
        ));
        gpu.set_bad_kat_on(1, true);
        let gpu_before = gpu.calls();
        assert_eq!(
            checker.check(honest_claim(19)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!(gpu.workers_called(gpu_before), [1, 2]);
        assert_eq!(
            checker.worker_health(WorkEngineKind::Gpu, 1),
            Some(WorkEngineHealth::Failed)
        );
        // A worker the GPU engine does not have is never trusted.
        checker.record_honest(crate::honest_work::PoolReplayResult::new(
            challenge(25),
            honest_fad(challenge(25), 0),
            7,
        ));
        assert_eq!(
            checker.check(honest_claim(25)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
    }

    #[test]
    fn a_pool_result_carrying_its_workers_known_answer_needs_no_further_run() {
        let carried = |challenge_digest, worker, known_answer| {
            crate::honest_work::PoolReplayResult::new(
                challenge_digest,
                honest_fad(challenge_digest, 0),
                worker,
            )
            .with_known_answer(Some(known_answer))
        };
        let (checker, cpu, gpu) = both_with_gpu_workers(3);
        qualified(&checker);
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        // The worker that produced the result answered correctly under the
        // same hold: no engine runs, even though worker 2 would be busy now.
        checker.record_honest(carried(
            challenge(21),
            2,
            WORK_KNOWN_ANSWERS[0].final_activation_digest,
        ));
        assert_eq!(
            checker.check(honest_claim(21)),
            WorkVerdict::Match(WorkProvenance::RecordHonest)
        );
        assert_eq!((cpu.calls(), gpu.calls()), (cpu_before, gpu_before));

        // A wrong known answer: the result is not used, the worker that
        // produced it is retired, and the node runs the block on another one.
        let held = checker.memo_len();
        let failures = checker.alarms().engine_failures;
        checker.record_honest(carried(challenge(22), 2, [0x66; 32]));
        // Nothing is recorded for challenge 22, and the retired worker's
        // unconfirmed result for challenge 21 is forgotten with it.
        assert_eq!(checker.memo_len(), held - 1);
        assert_eq!(
            checker.worker_health(WorkEngineKind::Gpu, 2),
            Some(WorkEngineHealth::Failed)
        );
        assert_eq!(checker.alarms().engine_failures, failures + 1);
        let gpu_skip = gpu.calls();
        assert_eq!(
            checker.check(honest_claim(22)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert!(!gpu.workers_called(gpu_skip).contains(&2));

        // A carried known answer does not stand in for a ready worker.
        checker.record_honest(carried(
            challenge(23),
            7,
            WORK_KNOWN_ANSWERS[0].final_activation_digest,
        ));
        assert_eq!(
            checker.check(honest_claim(23)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        checker.mark_failed(
            Producer {
                kind: WorkEngineKind::Gpu,
                worker: 1,
            },
            "retired",
        );
        checker.record_honest(carried(
            challenge(24),
            1,
            WORK_KNOWN_ANSWERS[0].final_activation_digest,
        ));
        assert_eq!(
            checker.check(honest_claim(24)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );

        // With one GPU worker, retiring it leaves the block to the CPU.
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        checker.record_honest(carried(challenge(25), 0, [0x66; 32]));
        assert_eq!(
            checker.worker_health(WorkEngineKind::Gpu, 0),
            Some(WorkEngineHealth::Failed)
        );
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        assert_eq!(
            checker.check(honest_claim(25)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert_eq!((cpu.calls(), gpu.calls()), (cpu_before + 1, gpu_before));
    }

    #[test]
    fn prewarm_computes_once_and_the_check_answers_from_the_memo() {
        let (checker, cpu) = cpu_only();
        assert_eq!(
            checker.prewarm(challenge(20)),
            Err(WorkUnavailable::Qualifying)
        );
        qualified(&checker);
        let before = cpu.calls();
        checker.prewarm(challenge(20)).unwrap();
        checker.prewarm(challenge(20)).unwrap();
        assert_eq!(cpu.calls(), before + 1);
        assert_eq!(
            checker.check(honest_claim(20)),
            WorkVerdict::Match(WorkProvenance::OwnEngine)
        );
        assert!(matches!(
            checker.check(wrong_claim(20)),
            WorkVerdict::Mismatch(mismatch) if mismatch.provenance() == WorkProvenance::OwnEngine
        ));
        assert_eq!(cpu.calls(), before + 1);
    }

    #[test]
    fn a_prewarmed_mismatch_is_final_only_after_a_recent_known_answer() {
        let (checker, cpu) = cpu_only();
        qualified(&checker);
        age_known_answers(&checker);
        let before = cpu.calls();
        checker.prewarm(challenge(21)).unwrap();
        assert_eq!(
            checker.memo_mismatch(wrong_claim(21)),
            None,
            "the admission waits for the check"
        );
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(21)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::OwnEngine);
        assert!(mismatch.cacheable());
        assert_eq!(
            cpu.calls(),
            before + 2,
            "the prewarm, then one known answer"
        );
        assert!(cpu.ran_known_answer(before + 1));
        assert_eq!(checker.memo_mismatch(wrong_claim(21)), Some(mismatch));
        assert_eq!(checker.alarms().own_engine_mismatches, 1);

        // The model data changed after the prewarm: the known answer fails,
        // nothing is kept and no verdict is reached.
        age_known_answers(&checker);
        checker.prewarm(challenge(22)).unwrap();
        cpu.fail_next(WorkEngineError::Integrity("layer 7".to_owned()));
        assert_eq!(
            checker.check(wrong_claim(22)),
            WorkVerdict::Unavailable(WorkUnavailable::KnownAnswerFailed)
        );
        assert_eq!(checker.memo_mismatch(wrong_claim(22)), None);
        assert!(!checker.memo_settled(challenge(22)));
        assert!(
            !checker.memo_settled(challenge(21)),
            "the worker's results go too"
        );
        assert_eq!(checker.alarms().own_engine_mismatches, 1);
        assert_eq!(
            checker.engine_health(WorkEngineKind::Cpu),
            Some(WorkEngineHealth::Failed)
        );
    }

    #[test]
    fn a_lone_known_answer_that_ends_without_a_result_keeps_the_block_run() {
        let (checker, cpu) = cpu_only();
        qualified(&checker);
        age_known_answers(&checker);
        let before = cpu.calls();
        // Cancelled once the block has run: the known answer never starts.
        assert_eq!(
            checker.check_cancellable(wrong_claim(23), &|| cpu.calls() > before),
            WorkVerdict::Unavailable(WorkUnavailable::Cancelled)
        );
        assert_eq!(cpu.calls(), before + 1);
        assert_eq!(checker.memo_mismatch(wrong_claim(23)), None);
        assert_eq!(checker.alarms().own_engine_mismatches, 0);

        // The CPU is busy for the known answer: still no verdict.
        cpu.fail_next(WorkEngineError::Busy);
        assert_eq!(
            checker.check(wrong_claim(23)),
            WorkVerdict::Unavailable(WorkUnavailable::Engine(WorkEngineError::Busy))
        );
        assert_eq!(cpu.calls(), before + 2);
        assert_eq!(checker.memo_mismatch(wrong_claim(23)), None);

        // Each retry ran only the known answer; the block ran once.
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(23)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::OwnEngine);
        assert!(mismatch.cacheable());
        assert_eq!(cpu.calls(), before + 3);
        assert_eq!(
            cpu.log.lock().unwrap()[before..]
                .iter()
                .filter(|call| call.1 == challenge(23))
                .count(),
            1
        );
        assert_eq!(checker.alarms().own_engine_mismatches, 1);
    }

    #[test]
    fn a_cpu_mismatch_kept_while_the_gpu_was_ready_is_re_tested_once_it_is_gone() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        // The GPU computes the block, the CPU agrees, the GPU's known answer
        // is busy: the CPU's result is kept, not confirmed.
        gpu.answer_next();
        gpu.fail_next(WorkEngineError::Busy);
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(28)) else {
            panic!("expected a mismatch");
        };
        assert!(!mismatch.cacheable());
        // The GPU worker is retired, and the CPU's last known answer is old.
        checker.mark_failed(
            Producer {
                kind: WorkEngineKind::Gpu,
                worker: 0,
            },
            "timed out on another job",
        );
        age_known_answers(&checker);
        assert_eq!(checker.memo_mismatch(wrong_claim(28)), None);
        let cpu_before = cpu.calls();
        let WorkVerdict::Mismatch(mismatch) = checker.check(wrong_claim(28)) else {
            panic!("expected a mismatch");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::OwnEngine);
        assert!(mismatch.cacheable());
        assert_eq!(
            cpu.calls(),
            cpu_before + 1,
            "one known answer, no block run"
        );
        assert!(cpu.ran_known_answer(cpu_before));
        assert_eq!(checker.memo_mismatch(wrong_claim(28)), Some(mismatch));
    }

    #[test]
    fn forget_drops_a_held_result() {
        let (checker, cpu) = cpu_only();
        qualified(&checker);
        checker.check(wrong_claim(26));
        assert!(checker.forget(challenge(26)));
        assert!(!checker.forget(challenge(26)));
        assert_eq!(checker.memo_mismatch(wrong_claim(26)), None);
        let before = cpu.calls();
        checker.check(wrong_claim(26));
        assert_eq!(cpu.calls(), before + 1, "the block is run again");
    }

    #[test]
    fn the_memo_is_capped_and_drops_its_oldest_entry() {
        let cpu = FakeEngine::new(WorkEngineKind::Cpu);
        let checker =
            HonestWorkChecker::with_memo_capacity(Some(cpu.clone()), None, false, 3).unwrap();
        qualified(&checker);
        for byte in 30..35 {
            checker.check(honest_claim(byte));
        }
        assert_eq!(checker.memo_len(), 3);
        let before = cpu.calls();
        checker.check(honest_claim(34));
        assert_eq!(cpu.calls(), before, "newest kept");
        checker.check(honest_claim(30));
        assert_eq!(cpu.calls(), before + 1, "oldest dropped");
    }

    #[test]
    fn memo_insert_keeps_the_more_trusted_result() {
        let cpu = Producer {
            kind: WorkEngineKind::Cpu,
            worker: 0,
        };
        let gpu = Producer {
            kind: WorkEngineKind::Gpu,
            worker: 0,
        };
        let mut memo = WorkMemo::new(8);
        let entry = |byte: u8, provenance, producer| MemoEntry {
            final_activation_digest: [byte; 32],
            provenance,
            producer,
            worker_checked: false,
            mismatch_reported: false,
        };
        memo.insert(challenge(1), entry(1, WorkProvenance::Confirmed, gpu));
        memo.insert(challenge(1), entry(2, WorkProvenance::OwnEngine, gpu));
        memo.insert(challenge(1), entry(3, WorkProvenance::RecordHonest, gpu));
        assert_eq!(
            memo.get(&challenge(1)).unwrap().final_activation_digest,
            [1; 32]
        );
        memo.insert(challenge(2), entry(4, WorkProvenance::RecordHonest, gpu));
        memo.insert(challenge(2), entry(5, WorkProvenance::OwnEngine, gpu));
        assert_eq!(
            memo.get(&challenge(2)).unwrap().provenance,
            WorkProvenance::OwnEngine
        );
        memo.insert(challenge(3), entry(6, WorkProvenance::OwnEngine, cpu));
        assert_eq!(memo.order.len(), 3);
        memo.retain_not_from(gpu);
        assert_eq!(memo.len(), 2, "the confirmed entry and the CPU's");
        assert_eq!(memo.order.len(), 2);
        assert!(memo.remove(&challenge(3)));
        assert_eq!(memo.order.len(), 1);
    }

    #[test]
    fn a_cancelled_check_runs_nothing_and_keeps_nothing() {
        let (checker, cpu) = cpu_only();
        qualified(&checker);
        let before = cpu.calls();
        assert_eq!(
            checker.check_cancellable(wrong_claim(1), &|| true),
            WorkVerdict::Unavailable(WorkUnavailable::Cancelled)
        );
        assert_eq!(cpu.calls(), before, "the job never started");
        assert_eq!(checker.memo_len(), 0);
        assert_eq!(checker.alarms(), WorkAlarmCounts::default());
        assert_eq!(checker.worker_erroring(WorkEngineKind::Cpu, 0), Some(false));
        assert_eq!(
            checker.worker_health(WorkEngineKind::Cpu, 0),
            Some(WorkEngineHealth::Ready)
        );
        assert_eq!(
            checker.check(honest_claim(1)),
            WorkVerdict::Match(WorkProvenance::OwnEngine),
            "the next check runs normally"
        );
    }

    #[test]
    fn a_check_cancelled_while_confirming_reaches_no_verdict() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        let (cpu_before, gpu_before) = (cpu.calls(), gpu.calls());
        // Cancelled as soon as the GPU has run: the CPU never starts.
        let cancel = || gpu.calls() > gpu_before;
        assert_eq!(
            checker.check_cancellable(wrong_claim(1), &cancel),
            WorkVerdict::Unavailable(WorkUnavailable::Cancelled)
        );
        assert_eq!(cpu.calls(), cpu_before);
        assert_eq!(gpu.calls(), gpu_before + 1);
        assert_eq!(checker.alarms(), WorkAlarmCounts::default());
        assert!(checker.memo_mismatch(wrong_claim(1)).is_none());

        // The GPU's result was kept: the next check only runs the CPU.
        let verdict = checker.check(wrong_claim(1));
        let WorkVerdict::Mismatch(mismatch) = verdict else {
            panic!("expected a mismatch, got {verdict:?}");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::Confirmed);
        assert_eq!(cpu.calls(), cpu_before + 1);
        assert_eq!(
            gpu.calls(),
            gpu_before + 2,
            "the GPU ran only its confirming known answer"
        );

        // A GPU busy at every try and a cancelled CPU: no fallback after the
        // cancellation either.
        let cpu_before = cpu.calls();
        gpu.fail_next(WorkEngineError::Busy);
        assert_eq!(
            checker.check_cancellable(wrong_claim(2), &|| gpu.calls() > gpu_before + 2),
            WorkVerdict::Unavailable(WorkUnavailable::Cancelled)
        );
        assert_eq!(cpu.calls(), cpu_before);
    }

    #[test]
    fn a_mismatch_a_cancelled_check_left_unconfirmed_is_reported_once() {
        let (checker, cpu, gpu) = both();
        qualified(&checker);
        let gpu_before = gpu.calls();
        assert_eq!(
            checker.check_cancellable(wrong_claim(3), &|| gpu.calls() > gpu_before),
            WorkVerdict::Unavailable(WorkUnavailable::Cancelled)
        );
        assert_eq!(checker.alarms().own_engine_mismatches, 0);

        // The CPU then cannot run it: the GPU's mismatch stands alone and its
        // alarm is raised now.
        cpu.fail_next(WorkEngineError::Failed("read error".to_owned()));
        let verdict = checker.check(wrong_claim(3));
        let WorkVerdict::Mismatch(mismatch) = verdict else {
            panic!("expected a mismatch, got {verdict:?}");
        };
        assert_eq!(mismatch.provenance(), WorkProvenance::OwnEngine);
        assert_eq!(checker.alarms().own_engine_mismatches, 1);

        // Answered again from the memo, it is not counted twice.
        cpu.fail_next(WorkEngineError::Failed("read error".to_owned()));
        assert!(matches!(
            checker.check(wrong_claim(3)),
            WorkVerdict::Mismatch(_)
        ));
        assert_eq!(checker.alarms().own_engine_mismatches, 1);

        // Nor after another cancelled confirmation stores the GPU's result
        // again, and the memo then answers alone once the CPU is retired.
        assert_eq!(
            checker.check_cancellable(wrong_claim(3), &|| true),
            WorkVerdict::Unavailable(WorkUnavailable::Cancelled)
        );
        let cpu_worker = Producer {
            kind: WorkEngineKind::Cpu,
            worker: 0,
        };
        checker.mark_failed(cpu_worker, "retired by another check");
        assert!(checker.memo_mismatch(wrong_claim(3)).is_some());
        assert!(matches!(
            checker.check(wrong_claim(3)),
            WorkVerdict::Mismatch(_)
        ));
        assert_eq!(checker.alarms().own_engine_mismatches, 1);
    }
}
