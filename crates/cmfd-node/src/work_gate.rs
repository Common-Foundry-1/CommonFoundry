//! Block admission under the release work rule.
//!
//! Above the release checkpoint `C`, nodes independently re-execute each
//! block's work before the block is indexed. Admission does it in three
//! places, in this order:
//!
//! 1. Preflight, under the node lock and before any proof is checked: a
//!    halted node admits nothing; a block or parent already recorded invalid
//!    is refused; at or below `C` the block id must be the pinned canonical
//!    id; above `C` the block must descend from the checkpoint block (checked
//!    only after its parent is known, so an unknown parent stays the
//!    retryable `UnknownParent`); a block on a side branch whose earlier
//!    blocks are not checked yet waits; a block that neither extends the
//!    active tip nor is within [`WORK_RELEVANCE_DEPTH`] of it is not indexed
//!    but noted for the background check (unless a sync session fetched it
//!    from a peer that claims more work than this node has, see
//!    [`FetchedFrom`]); and a mismatch this node's engines already settled
//!    is refused at once.
//! 2. The work gate, after the proof check and off the node lock: the block's
//!    work runs on its own single-slot lane. A remote request that is
//!    cancelled stops the job; nothing of it is kept.
//! 3. The commit itself refuses any block above `C` that has no recorded
//!    verdict, so no path can index one unchecked.
//!
//! Every match is recorded as verified before the block is admitted. A
//! mismatch refuses the block; it is recorded invalid, and its sender
//! penalized, only when two independent engines agree. A mismatch one engine
//! found alone ([`NodeError::WorkMismatchUnconfirmed`]) costs the sender
//! nothing, and a re-send is refused from memory without running the engine
//! again, for as long as that engine's result is still this node's final
//! answer (see [`Node::stale_work_rejection`]). An engine that cannot answer
//! makes the block retryable, never rejected.
//!
//! Stored blocks are never re-executed here: startup replay, fork replay and
//! state rebuilds check proofs only.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use cmfd_consensus::{Block, BlockProof, ForgeMatrixV4WorkRule};

use crate::honest_work::store::{
    WorkHalt, WorkStatus, WorkStatusLoad, WorkStatusStore, clear_work_halt, read_work_halt,
};
use crate::honest_work::{
    HonestWorkChecker, PoolReplayResult, WorkCancel, WorkClaim, WorkMismatch, WorkProvenance,
    WorkUnavailable, WorkVerdict,
};
use crate::{BlockOrigin, Node, NodeError, ProofVerificationQueue, RemoteProofRequest};

mod backlog;
pub use backlog::{
    WORK_BACKLOG_MAX_YIELD, WorkBacklog, WorkBacklogHandle, WorkBacklogOutcome, WorkBacklogReport,
    WorkBacklogTurn, run_work_backlog_exclusive, spawn_startup_work_backlog, spawn_work_backlog,
    spawn_work_backlog_with_pause, work_backlog_heights,
};
mod catch_up;
pub use catch_up::{
    CATCH_UP_GRANTS_FILE, CatchUpSource, PROBE_BUDGET, PROBE_CONNECT, PROBE_FAIL_HOLD, PROBE_READ,
    PRUNE_LAG_FACTOR, STALE_AFTER, TOP_RUN_CAP, TOP_RUN_STALL, VIEW_FRESH, WALLET_CATCH_UP_DEPTH,
    WALLET_MAX_EASING,
};
use catch_up::{
    CatchUpFacts, CoverageIndex, CoverageView, GrantFile, GrantRefusal, catch_up_row, run_qualifies,
};
pub(crate) use catch_up::{CatchUpFollow, PROBE_MIN_ATTEMPT, WalletCatchUp};
#[cfg(test)]
mod catch_up_tests;

/// The persisted verified/invalid set, in the node's data directory.
pub const WORK_STATUS_FILE: &str = "work-status.v1";
/// The halt marker, in the node's data directory.
pub const WORK_HALT_FILE: &str = "halt.v1";
/// A block above the checkpoint has its work checked on the admission path
/// only if it extends the active tip or its height is within this many
/// blocks of the tip's. Others wait for the background check.
pub const WORK_RELEVANCE_DEPTH: u64 = 6;
/// Blocks noted for the background check; the oldest is dropped first.
pub const MAX_PENDING_SIDE_WORK: usize = 64;
/// Blocks noted for the background check from any one peer address; its
/// oldest is dropped first.
pub const MAX_PENDING_SIDE_WORK_PER_SENDER: usize = 8;
/// Blocks from one peer address that this node may refuse on one engine's
/// word ([`NodeError::WorkMismatchUnconfirmed`]) within
/// [`LONE_REFUSAL_WINDOW`]. Once an address has that many, its other blocks
/// that would need a work check are answered with the retryable
/// [`NodeError::WorkCheckDeferred`], and run nothing, until the oldest
/// leaves the window. This is not a penalty: nothing is charged to the
/// address's reputation, and the same block from any other address is
/// checked as usual. A block's work counts against the first address whose
/// block had it computed, not against every peer that relays it.
/// Operator-configured, bootstrap and loopback peers are not counted.
pub const MAX_LONE_REFUSALS_PER_SENDER: usize = 2;
/// The window [`MAX_LONE_REFUSALS_PER_SENDER`] counts over.
pub const LONE_REFUSAL_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Admissions that may wait for the work lane.
const WORK_LANE_QUEUED: usize = 4;
/// How long a local admission waits for the work lane.
const WORK_LANE_TIMEOUT: Duration = Duration::from_secs(120);

/// The model bank file and what the verifier's single authenticated pass
/// over it captured, kept for the CPU work engine.
#[cfg(feature = "production-v4")]
pub(crate) struct WorkBank {
    pub(crate) file: std::fs::File,
    /// Where the bank was opened from, for error messages.
    pub(crate) path: std::path::PathBuf,
    pub(crate) identity: cmfd_consensus::ForgeMatrixV4BankIdentity,
}

/// Only ProductionV4 builds read a model bank.
#[cfg(not(feature = "production-v4"))]
pub(crate) enum WorkBank {}

/// Compute threads per block for the CPU work engine when none are
/// configured: half the logical processors, at most eight, at least one.
pub fn default_work_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(1, |threads| threads.get() / 2)
        .clamp(1, 8)
}

/// How the CPU work engine reads the model bank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkBankMode {
    /// Resident when the memory available leaves
    /// [`RESIDENT_WORK_BANK_HEADROOM_BYTES`] beside the layers; streamed
    /// otherwise, or if they cannot be allocated.
    Auto,
    /// Every layer is read into memory once at startup and checked against
    /// its authenticated root; a block's check then reads no disk.
    Resident,
    /// Each block's check reads its layers from the bank file.
    Streamed,
}

impl WorkBankMode {
    /// The name node status and the startup report use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Resident => "resident",
            Self::Streamed => "streamed",
        }
    }
}

/// Memory that must remain available beside a resident model bank for
/// [`WorkBankMode::Auto`] to load one.
pub const RESIDENT_WORK_BANK_HEADROOM_BYTES: u64 = 2 << 30;

/// The mode [`WorkBankMode::Auto`] picks for a bank whose layers take
/// `layer_bytes`, given the memory `available` (`None` when it cannot be
/// read): resident only if the layers and the headroom fit.
pub fn auto_work_bank_mode(layer_bytes: u64, available: Option<u64>) -> WorkBankMode {
    match (
        available,
        layer_bytes.checked_add(RESIDENT_WORK_BANK_HEADROOM_BYTES),
    ) {
        (Some(available), Some(needed)) if available >= needed => WorkBankMode::Resident,
        _ => WorkBankMode::Streamed,
    }
}

/// Physical memory available to new allocations without paging, including
/// reclaimable file cache, or `None` where it cannot be read. On Linux this
/// is also capped by the memory limits of the cgroups the node runs in (a
/// container or a systemd `MemoryMax=`).
pub fn available_memory_bytes() -> Option<u64> {
    available_memory_bytes_os()
}

#[cfg(target_os = "linux")]
fn available_memory_bytes_os() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))?;
    let mut fields = line.split_whitespace();
    let kibibytes = fields.next()?.parse::<u64>().ok()?;
    if fields.next() != Some("kB") {
        return None;
    }
    let available = kibibytes.checked_mul(1024)?;
    let cgroups = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let headroom = cgroup_memory_headroom(&cgroups, |path| std::fs::read_to_string(path).ok());
    Some(headroom.map_or(available, |headroom| headroom.min(available)))
}

/// What the memory limits of the cgroups named in `proc_self_cgroup` (the
/// text of `/proc/self/cgroup`) still let this process allocate: the least,
/// over its own cgroup and each ancestor with a limit, of the limit less the
/// memory charged to it, not counting inactive file cache, which the kernel
/// reclaims first. `None` if no cgroup sets a limit. Covers cgroup v2
/// (`memory.max`, `memory.high`) and v1 (`memory.limit_in_bytes`); `read`
/// returns the contents of a file, or `None`.
#[cfg(any(target_os = "linux", test))]
fn cgroup_memory_headroom(
    proc_self_cgroup: &str,
    read: impl Fn(&str) -> Option<String>,
) -> Option<u64> {
    let number = |path: &str| read(path)?.trim().parse::<u64>().ok();
    let stat = |path: &str, key: &str| {
        read(path)?.lines().find_map(|line| {
            line.strip_prefix(key)?
                .strip_prefix(' ')?
                .trim()
                .parse::<u64>()
                .ok()
        })
    };
    let mut headroom: Option<u64> = None;
    for line in proc_self_cgroup.lines() {
        let mut fields = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let (root, limits, usage, inactive): (&str, &[&str], &str, &str) = if controllers.is_empty()
        {
            (
                "/sys/fs/cgroup",
                &["memory.max", "memory.high"],
                "memory.current",
                "inactive_file",
            )
        } else if controllers
            .split(',')
            .any(|controller| controller == "memory")
        {
            (
                "/sys/fs/cgroup/memory",
                &["memory.limit_in_bytes"],
                "memory.usage_in_bytes",
                "total_inactive_file",
            )
        } else {
            continue;
        };
        // The cgroup's own directory, then each ancestor up to the mount
        // root, which inside a container is the container's own cgroup.
        let mut dir = path.trim_end_matches('/');
        loop {
            let at = |file: &str| format!("{root}{dir}/{file}");
            let limit = limits.iter().filter_map(|&file| number(&at(file))).min();
            if let Some(limit) = limit {
                let charged = number(&at(usage))
                    .unwrap_or(0)
                    .saturating_sub(stat(&at("memory.stat"), inactive).unwrap_or(0));
                let left = limit.saturating_sub(charged);
                headroom = Some(headroom.map_or(left, |headroom| headroom.min(left)));
            }
            match dir.rfind('/') {
                Some(parent) => dir = &dir[..parent],
                None => break,
            }
        }
    }
    headroom
}

/// The node error for a model bank that cannot back the CPU work engine:
/// one that does not fit in memory, one that cannot be read, or one whose
/// bytes no longer match what the node authenticated when it opened.
#[cfg(feature = "production-v4")]
fn work_bank_error(
    error: cmfd_consensus::ForgeMatrixV4ExecutionError,
    bank_path: &std::path::Path,
) -> NodeError {
    use cmfd_consensus::ForgeMatrixV4ExecutionError;
    tracing::error!(target: "work_rule", %error, "the model bank cannot back the work engine");
    match error {
        ForgeMatrixV4ExecutionError::ResidentAllocation { bytes } => {
            NodeError::ProductionV4WorkBankMemory { bytes }
        }
        ForgeMatrixV4ExecutionError::BankIo(source)
        | ForgeMatrixV4ExecutionError::LayerRead { source, .. } => NodeError::Io {
            operation: "read the model bank for the work engine",
            path: bank_path.to_path_buf(),
            source,
        },
        _ => NodeError::ProductionV4ArtifactIdentityMismatch("model bank"),
    }
}

#[cfg(windows)]
fn available_memory_bytes_os() -> Option<u64> {
    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_physical: u64,
        available_physical: u64,
        total_page_file: u64,
        available_page_file: u64,
        total_virtual: u64,
        available_virtual: u64,
        available_extended_virtual: u64,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GlobalMemoryStatusEx(status: *mut MemoryStatusEx) -> i32;
    }

    let mut status = MemoryStatusEx {
        length: u32::try_from(std::mem::size_of::<MemoryStatusEx>()).ok()?,
        memory_load: 0,
        total_physical: 0,
        available_physical: 0,
        total_page_file: 0,
        available_page_file: 0,
        total_virtual: 0,
        available_virtual: 0,
        available_extended_virtual: 0,
    };
    // SAFETY: `status` is a writable, correctly sized MEMORYSTATUSEX whose
    // `length` is set as GlobalMemoryStatusEx requires.
    (unsafe { GlobalMemoryStatusEx(&mut status) } != 0).then_some(status.available_physical)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn available_memory_bytes_os() -> Option<u64> {
    None
}

/// The release work rule as node status reports it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WorkRuleStatus {
    /// Engines are installed, so blocks above the checkpoint are admitted
    /// once their work is re-executed here. Without engines no such block is
    /// admitted at all.
    pub enforced: bool,
    /// The engines installed: `cpu`, `gpu` or `cpu+gpu`; `None` until then.
    pub engines: Option<&'static str>,
    /// How the CPU engine reads the model bank: `resident` or `streamed`;
    /// `None` until it is installed.
    pub bank: Option<&'static str>,
    /// `pending` until engines are installed, then `qualifying`, `ready` or
    /// `failed`.
    pub engine_state: &'static str,
    pub engine_ready: bool,
    /// A CPU and a GPU worker are both ready, so a mismatch can be confirmed
    /// here.
    pub independent_engines: bool,
    /// Block admission is halted until an operator acts.
    pub halted: bool,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
    /// The first height whose work is re-executed.
    pub activation_height: u64,
    /// Every active block up to this height has been checked.
    pub validated_height: u64,
    /// Blocks noted for the background check.
    pub pending_side_blocks: usize,
    /// The height of the lowest active block above the validated height, if
    /// it is recorded unsettled: one engine found its work does not match and
    /// no second kind of engine has settled it. The validated height cannot
    /// pass it until it is settled or the stored chain is synced again.
    pub unsettled_height: Option<u64>,
    /// The id of that block, in hex, so it can be compared with the block
    /// other nodes hold at that height.
    pub unsettled_block_id: Option<String>,
    /// The background check of stored blocks is paused (a laptop on battery,
    /// say); blocks that arrive are still checked as they are admitted.
    pub backlog_paused: bool,
    pub alarms: WorkRuleAlarms,
    /// Where a desktop wallet catching up stands; only on a desktop wallet
    /// with the catch-up on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_catch_up: Option<WalletCatchUpStatus>,
}

/// Where a desktop wallet catching up stands.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WalletCatchUpStatus {
    /// `release_stale`, `single_source`, `caught_up`, `catching_up`,
    /// `checking_newest` or `waiting_for_check`.
    pub state: &'static str,
    /// With `waiting_for_check`: `earlier_blocks`, `difficulty` or `other`.
    pub reason: Option<&'static str>,
    /// Coins in blocks up to this height are available.
    pub available_height: u64,
    /// How many blocks the state still waits for.
    pub blocks_left: u64,
    /// The blocks at the tip re-executed here, up to `newest_needed`.
    pub newest_checked: u64,
    pub newest_needed: u64,
    /// Sources with a recent report of their height.
    pub sources_answering: u8,
    /// A block admitted without an engine run lies above the available
    /// height.
    pub granted_above_available: bool,
}

/// Why the exchange RPC answers chain reads with a retryable error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangeReadRefusal {
    /// Block admission is halted until an operator acts.
    Halted,
    /// Every work engine failed, so no block above the validated height
    /// can be checked.
    EngineFailed,
}

/// Events an operator should look at, counted since the node started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct WorkRuleAlarms {
    /// The two kinds of engine produced different results for one block.
    pub engine_divergence: u64,
    /// One engine found a block's work did not match, with no other kind of
    /// engine to confirm it.
    pub own_engine_mismatches: u64,
    /// A worker failed its known answers, an integrity check or a job.
    pub engine_failures: u64,
    /// The engines and the work-status store disagreed about a block.
    pub store_conflicts: u64,
    /// Times a peer's advertised tip was newly found to build on a block
    /// this node knows is invalid.
    pub peers_on_invalid_chain: u64,
}

/// A block noted for the background check: what it claims, without its
/// body. Once the claim is checked, a re-sent block is answered from the
/// memo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingSideWork {
    pub(crate) block_id: [u8; 32],
    pub(crate) height: u64,
    pub(crate) claim: WorkClaim,
    /// The peer it came from, if a peer did.
    pub(crate) sender: Option<BlockSender>,
}

/// The peer a block came from: one that sent it, or one a sync session
/// fetched it from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockSender {
    /// The peer's address. P2P gives one address for each IPv4 address and
    /// each IPv6 /64, so one host cannot take more places among the noted
    /// blocks by changing its address within its /64.
    pub(crate) address: IpAddr,
    /// A sync session asked the peer for the block; it did not send it
    /// unasked.
    pub(crate) fetched: bool,
    /// An operator-configured, bootstrap or loopback peer: its noted blocks
    /// do not count against its address under
    /// [`MAX_LONE_REFUSALS_PER_SENDER`], as its admitted ones do not.
    pub(crate) trusted: bool,
}

#[derive(Debug, Default)]
struct PendingSide {
    order: VecDeque<PendingSideWork>,
    ids: HashSet<[u8; 32]>,
}

impl PendingSide {
    fn push(&mut self, work: PendingSideWork) {
        if !self.ids.insert(work.block_id) {
            return;
        }
        if let Some(sender) = work.sender {
            let mut from_sender = self.order.iter().enumerate().filter(|(_, noted)| {
                noted
                    .sender
                    .is_some_and(|noted| noted.address == sender.address)
            });
            if let Some((oldest, _)) = from_sender.next()
                && from_sender.count() + 1 >= MAX_PENDING_SIDE_WORK_PER_SENDER
                && let Some(dropped) = self.order.remove(oldest)
            {
                self.ids.remove(&dropped.block_id);
            }
        }
        self.order.push_back(work);
        while self.order.len() > MAX_PENDING_SIDE_WORK {
            if let Some(dropped) = self.order.pop_front() {
                self.ids.remove(&dropped.block_id);
            }
        }
    }

    fn pop(&mut self) -> Option<PendingSideWork> {
        let work = self.order.pop_front()?;
        self.ids.remove(&work.block_id);
        Some(work)
    }
}

/// One block refused on one engine's word: when it was counted, its id, and
/// the challenge its work was computed for.
type LoneRefusal = (Instant, [u8; 32], [u8; 32]);

/// The blocks each peer address had refused on one engine's word within
/// [`LONE_REFUSAL_WINDOW`], oldest first. Counted only while the work lane is
/// held, so concurrent sessions from one address cannot all pass the count
/// before any of them is added. A challenge is counted against the first
/// address whose block had it computed and against no other, so peers that
/// relay one block together are not all counted for one work check. Each
/// entry cost one work check, so the map stays as small as the lane is slow.
#[derive(Debug, Default)]
struct LoneRefusals {
    by_sender: HashMap<IpAddr, VecDeque<LoneRefusal>>,
}

impl LoneRefusals {
    fn forget_expired(&mut self, now: Instant) {
        self.by_sender.retain(|_, refusals| {
            while refusals
                .front()
                .is_some_and(|(at, _, _)| now.saturating_duration_since(*at) >= LONE_REFUSAL_WINDOW)
            {
                refusals.pop_front();
            }
            !refusals.is_empty()
        });
    }

    /// Whether `sender` has used up its refusals in the window.
    fn exhausted(&mut self, sender: IpAddr, now: Instant) -> bool {
        self.forget_expired(now);
        self.by_sender
            .get(&sender)
            .is_some_and(|refusals| refusals.len() >= MAX_LONE_REFUSALS_PER_SENDER)
    }

    /// Whether `block_id` from `sender` may have its work checked: the
    /// sender has refusals left, or this block is already one of them.
    fn allows(&mut self, sender: IpAddr, block_id: &[u8; 32], now: Instant) -> bool {
        !self.exhausted(sender, now)
            || self.by_sender[&sender]
                .iter()
                .any(|(_, refused, _)| refused == block_id)
    }

    /// Counts `block_id`, whose work was computed for `challenge_digest`, as
    /// refused for `sender`, unless that challenge is already counted against
    /// any address.
    fn charge(
        &mut self,
        sender: IpAddr,
        block_id: [u8; 32],
        challenge_digest: [u8; 32],
        now: Instant,
    ) {
        self.forget_expired(now);
        if self
            .by_sender
            .values()
            .flatten()
            .any(|(_, _, counted)| *counted == challenge_digest)
        {
            return;
        }
        self.by_sender
            .entry(sender)
            .or_default()
            .push_back((now, block_id, challenge_digest));
    }
}

/// A validated height, the active block at it, and the store's revocation
/// count when it was found.
type ValidatedAt = (u64, [u8; 32], u64);

/// The work rule of a node and what it needs to apply it. Cheap to clone:
/// admissions take a copy under the node lock and use it off the lock.
#[derive(Clone)]
pub(crate) struct WorkGate {
    rule: Arc<ForgeMatrixV4WorkRule>,
    /// `None` until the node's engines are installed; until then every block
    /// above the checkpoint is retryable.
    checker: Option<Arc<HonestWorkChecker>>,
    store: Option<Arc<Mutex<WorkStatusStore>>>,
    halted: Arc<AtomicBool>,
    /// The background check is paused; see [`WorkRuleStatus::backlog_paused`].
    backlog_paused: Arc<AtomicBool>,
    lane: Arc<ProofVerificationQueue>,
    pending_side: Arc<Mutex<PendingSide>>,
    store_conflicts: Arc<AtomicU64>,
    /// The last validated height found and its active block, from which the
    /// next lookup continues while that block is still active.
    validated: Arc<Mutex<Option<ValidatedAt>>>,
    /// When a block recorded unsettled may next be computed again on a node
    /// with one kind of engine. Kept for the life of the process, so each
    /// start computes such a block once more.
    one_engine_retry: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
    /// Each peer address's recent one-engine refusals; see
    /// [`MAX_LONE_REFUSALS_PER_SENDER`].
    lone_refusals: Arc<Mutex<LoneRefusals>>,
    /// How the CPU engine reads the model bank, once it is installed.
    bank: Option<WorkBankMode>,
    /// A desktop wallet's catch-up, once it is turned on; see
    /// [`Node::enable_wallet_catch_up`].
    wallet_catch_up: Option<Arc<WalletCatchUp>>,
    /// Test rules on reference-proof networks read the claim from the
    /// reference proof's final-activation digest.
    reference_claims: bool,
}

#[cfg(test)]
thread_local! {
    /// A rule that opening a node on this thread takes as if it were compiled
    /// in, for tests of a data directory opened under a rule.
    pub(crate) static OPEN_WITH_WORK_RULE: std::cell::RefCell<Option<ForgeMatrixV4WorkRule>> =
        const { std::cell::RefCell::new(None) };
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Each guarded value is left consistent by every operation on it.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl WorkGate {
    fn new(rule: Arc<ForgeMatrixV4WorkRule>, reference_claims: bool) -> Self {
        Self {
            rule,
            checker: None,
            store: None,
            halted: Arc::new(AtomicBool::new(false)),
            backlog_paused: Arc::new(AtomicBool::new(false)),
            lane: Arc::new(ProofVerificationQueue::new(
                1,
                WORK_LANE_QUEUED,
                WORK_LANE_TIMEOUT,
            )),
            pending_side: Arc::new(Mutex::new(PendingSide::default())),
            store_conflicts: Arc::new(AtomicU64::new(0)),
            validated: Arc::new(Mutex::new(None)),
            one_engine_retry: Arc::new(Mutex::new(HashMap::new())),
            lone_refusals: Arc::new(Mutex::new(LoneRefusals::default())),
            bank: None,
            wallet_catch_up: None,
            reference_claims,
        }
    }

    /// The compiled rule of a ProductionV4 network, if it has one.
    pub(crate) fn compiled(production_v4: bool, network_id: [u8; 32]) -> Option<Self> {
        #[cfg(test)]
        if let Some(rule) = OPEN_WITH_WORK_RULE.with(|rule| rule.borrow().clone()) {
            return Some(Self::new(Arc::new(rule), true));
        }
        if !production_v4 {
            return None;
        }
        cmfd_consensus::forgematrix_v4_work_rule(network_id)
            .map(|rule| Self::new(Arc::new(rule.clone()), false))
    }

    /// The release checkpoint, as (height, block id), of the rule
    /// [`compiled`](Self::compiled) gives this network, if it has one.
    pub(crate) fn compiled_checkpoint(
        production_v4: bool,
        network_id: [u8; 32],
    ) -> Option<(u64, [u8; 32])> {
        Self::compiled(production_v4, network_id).map(|gate| {
            (
                gate.rule.checkpoint_height(),
                gate.rule.checkpoint_block_id(),
            )
        })
    }

    fn halted(&self) -> bool {
        self.halted.load(Ordering::Acquire)
    }

    /// Closes the work lane for a node that is shutting down: no check waits
    /// for it any longer, and a running remote admission check stops.
    pub(crate) fn close_lane(&self) {
        self.lane.close();
    }

    fn lane_closed(&self) -> bool {
        self.lane.ensure_open().is_err()
    }

    fn status(&self, block_id: &[u8; 32]) -> Option<WorkStatus> {
        self.store
            .as_ref()
            .and_then(|store| lock(store).status(block_id))
    }

    /// What `block` claims about its work, if it carries a proof the rule
    /// can check.
    fn claim(&self, block: &Block) -> Option<WorkClaim> {
        self.claim_of_proof(&block.proof)
    }

    fn claim_of_proof(&self, proof: &BlockProof) -> Option<WorkClaim> {
        match proof {
            BlockProof::V4Candidate(proof) => Some(WorkClaim {
                challenge_digest: proof.challenge_digest,
                work_digest: proof.work_digest,
            }),
            BlockProof::V2Reference(proof) if self.reference_claims => Some(WorkClaim {
                challenge_digest: proof.challenge_digest,
                work_digest: crate::honest_work::honest_work_digest(
                    proof.challenge_digest,
                    proof.final_activation_digest,
                ),
            }),
            _ => None,
        }
    }

    /// Records a match: verified if this node's engines produced it,
    /// provisional if it is a pool's own replay result, which the background
    /// check later runs again.
    fn record_match(
        &self,
        store: &mut WorkStatusStore,
        provenance: WorkProvenance,
        height: u64,
        block_id: [u8; 32],
    ) -> io::Result<()> {
        match provenance {
            WorkProvenance::RecordHonest => store.mark_provisional(height, block_id),
            WorkProvenance::OwnEngine | WorkProvenance::Confirmed => {
                store.mark_verified(height, block_id)
            }
        }
    }

    /// Whether a block from `sender` may have its work checked under
    /// [`MAX_LONE_REFUSALS_PER_SENDER`]; always, without a counted sender.
    fn lone_refusals_allow(&self, sender: Option<IpAddr>, block_id: &[u8; 32]) -> bool {
        sender
            .is_none_or(|sender| lock(&self.lone_refusals).allows(sender, block_id, Instant::now()))
    }

    /// Counts `block_id` as refused on one engine's word for `sender`, if
    /// there is a counted sender (see [`LoneRefusals::charge`]).
    fn charge_lone_refusal(
        &self,
        sender: Option<IpAddr>,
        block_id: [u8; 32],
        challenge_digest: [u8; 32],
    ) {
        if let Some(sender) = sender {
            lock(&self.lone_refusals).charge(sender, block_id, challenge_digest, Instant::now());
        }
    }

    fn note_side_work(&self, work: PendingSideWork) {
        lock(&self.pending_side).push(work);
    }

    /// The engines reached a result the store refuses for this block, so two
    /// results for one challenge disagree: the engine-divergence alarm.
    fn note_store_conflict(
        &self,
        block_id: [u8; 32],
        challenge_digest: [u8; 32],
        error: &io::Error,
    ) {
        self.store_conflicts.fetch_add(1, Ordering::Relaxed);
        tracing::error!(
            target: "work_rule",
            block_id = %hex::encode(block_id),
            %error,
            "the work engines and the work-status store disagree about a block"
        );
        if let Some(checker) = self.checker.as_ref() {
            checker.raise_divergence(challenge_digest);
        }
    }
}

/// One block's pass through the work gate, prepared under the node lock.
pub(crate) struct WorkAdmission {
    gate: WorkGate,
    block_id: [u8; 32],
    height: u64,
    claim: Option<WorkClaim>,
    /// Waits for the lane as priority (see [`BlockOrigin`]).
    priority: bool,
    /// The peer address it counts against under
    /// [`MAX_LONE_REFUSALS_PER_SENDER`], if any.
    counted_sender: Option<IpAddr>,
}

/// Why the work gate refused a block, and whether its id may be remembered
/// as rejected so a re-send is refused without another check.
#[derive(Debug)]
pub(crate) struct WorkRejection {
    pub(crate) error: NodeError,
    pub(crate) remember: bool,
}

impl WorkRejection {
    fn retryable(error: NodeError) -> Self {
        Self {
            error,
            remember: false,
        }
    }
}

/// How a block remembered as refused for its work was decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkRejectionKind {
    /// Two independent engines agreed, whether or not the invalid record
    /// could be written.
    Confirmed,
    /// One engine alone, on what the block claims: once the engines no
    /// longer hold that as their final answer, the block is checked again.
    Unconfirmed(WorkClaim),
}

/// The error a mismatch refuses its block with: only one that two
/// independent engines agree on costs its sender a penalty and a cooldown.
fn mismatch_error(mismatch: &WorkMismatch, block_id: [u8; 32]) -> NodeError {
    if mismatch.confirmed().is_some() {
        NodeError::WorkRecomputationMismatch(block_id)
    } else {
        NodeError::WorkMismatchUnconfirmed(block_id)
    }
}

impl WorkAdmission {
    /// Runs the block's work and records the verdict. `request` is the remote
    /// request it serves, if any: a remote request waits for the lane within
    /// its own deadline, and runs nothing, giving the retryable
    /// [`NodeError::ProofVerificationQueueFull`], if the time it has left is
    /// shorter than the check is expected to take
    /// ([`HonestWorkChecker::expected_check_time`]). Once started, its job
    /// stops only if its sender withdraws it, giving
    /// [`NodeError::WorkCheckWithdrawn`], or this node stops it or shuts
    /// down; past the deadline it runs to its verdict, which is recorded and
    /// counts as usual. A local admission always completes. A block from a
    /// peer address that has used up its one-engine refusals (see
    /// [`MAX_LONE_REFUSALS_PER_SENDER`]) runs nothing and gives the retryable
    /// [`NodeError::WorkCheckDeferred`].
    pub(crate) fn ensure(self, request: Option<&RemoteProofRequest>) -> Result<(), WorkRejection> {
        let gate = &self.gate;
        let unavailable = || WorkRejection::retryable(NodeError::WorkCheckUnavailable);
        if gate.halted() {
            return Err(WorkRejection::retryable(NodeError::WorkRuleHalted));
        }
        let (Some(checker), Some(store), Some(claim)) =
            (gate.checker.as_ref(), gate.store.as_ref(), self.claim)
        else {
            return Err(unavailable());
        };
        // A match this node already computed (a sync prewarm, for example)
        // runs no engine, so it does not wait for the lane.
        if let Some(provenance) = checker.memo_match(claim) {
            return self.record(store, provenance, claim);
        }
        let deferred = || WorkRejection::retryable(NodeError::WorkCheckDeferred);
        if !gate.lone_refusals_allow(self.counted_sender, &self.block_id) {
            // Another copy may have had it verified since its preflight.
            if lock(store).status(&self.block_id) == Some(WorkStatus::Verified) {
                return Ok(());
            }
            return Err(deferred());
        }
        let _lane = match request {
            Some(request) if self.priority => {
                gate.lane.acquire_priority_cancellable(request.clone())
            }
            Some(request) => gate.lane.acquire_cancellable(request.clone()),
            None if self.priority => gate.lane.acquire_priority(),
            None => gate.lane.acquire(),
        }
        .map_err(WorkRejection::retryable)?;
        if lock(store).status(&self.block_id) == Some(WorkStatus::Verified) {
            return Ok(());
        }
        // Refusals are counted with the lane held, so every earlier one from
        // this sender is counted by now.
        if !gate.lone_refusals_allow(self.counted_sender, &self.block_id) {
            return Err(deferred());
        }
        if let Some(request) = request
            && let Some(expected) = checker.expected_check_time(Instant::now())
            && request.deadline().saturating_duration_since(Instant::now()) < expected
        {
            return Err(WorkRejection::retryable(
                NodeError::ProofVerificationQueueFull,
            ));
        }
        let cancel =
            || request.is_some_and(|request| request.withdrawn_or_stopped() || gate.lane_closed());
        match checker.check_cancellable(claim, &cancel) {
            WorkVerdict::Match(provenance) => self.record(store, provenance, claim),
            WorkVerdict::Mismatch(mismatch) => {
                if mismatch.confirmed().is_none() {
                    gate.charge_lone_refusal(
                        self.counted_sender,
                        self.block_id,
                        claim.challenge_digest,
                    );
                }
                if let Some(confirmed) = mismatch.confirmed()
                    && let Err(error) = lock(store).mark_invalid(
                        &confirmed,
                        self.height,
                        self.block_id,
                        claim.challenge_digest,
                    )
                {
                    if error.kind() == io::ErrorKind::InvalidInput {
                        gate.note_store_conflict(self.block_id, claim.challenge_digest, &error);
                    } else {
                        tracing::warn!(
                            target: "work_rule",
                            block_id = %hex::encode(self.block_id),
                            %error,
                            "could not record an invalid block"
                        );
                    }
                }
                Err(WorkRejection {
                    error: mismatch_error(&mismatch, self.block_id),
                    remember: mismatch.cacheable(),
                })
            }
            // The job had started. A sender that withdraws its block before
            // the verdict is held off as if the block had failed; a job
            // this node stopped, or ended by shutting down, is not the
            // sender's doing.
            WorkVerdict::Unavailable(WorkUnavailable::Cancelled) => {
                let withdrawn = request.is_some_and(RemoteProofRequest::withdrawn);
                Err(WorkRejection::retryable(if withdrawn {
                    NodeError::WorkCheckWithdrawn
                } else {
                    NodeError::ProofVerificationQueueTimeout
                }))
            }
            WorkVerdict::Unavailable(reason) => {
                tracing::warn!(
                    target: "work_rule",
                    block_id = %hex::encode(self.block_id),
                    %reason,
                    "block work could not be checked"
                );
                Err(unavailable())
            }
        }
    }

    /// Records a match before the block is admitted.
    fn record(
        &self,
        store: &Mutex<WorkStatusStore>,
        provenance: WorkProvenance,
        claim: WorkClaim,
    ) -> Result<(), WorkRejection> {
        let gate = &self.gate;
        match gate.record_match(&mut lock(store), provenance, self.height, self.block_id) {
            Ok(()) => Ok(()),
            Err(error) => {
                if error.kind() == io::ErrorKind::InvalidInput {
                    gate.note_store_conflict(self.block_id, claim.challenge_digest, &error);
                } else {
                    tracing::warn!(
                        target: "work_rule",
                        block_id = %hex::encode(self.block_id),
                        %error,
                        "could not record a verified block"
                    );
                }
                Err(WorkRejection::retryable(NodeError::WorkCheckUnavailable))
            }
        }
    }
}

/// The peer a sync session fetched a block from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FetchedFrom {
    /// The peer's address as one sender of blocks noted for the background
    /// check (see [`BlockSender::address`]).
    pub(crate) sender: IpAddr,
    /// An operator-configured or bootstrap peer: the block waits for the work
    /// lane as priority.
    pub(crate) trusted: bool,
    /// The peer claimed more work than this node had when the session began,
    /// so its branch may replace the active one: the prewarm computes the
    /// block however deep it is, and a heavier branch that forked more than
    /// [`WORK_RELEVANCE_DEPTH`] blocks below the tip is followed in one
    /// session. Every other check still applies first.
    pub(crate) heavier: bool,
    /// On a desktop wallet catching up, the session's source and the highest
    /// height it may admit without an engine run; `None` everywhere else.
    pub(crate) catch_up: Option<CatchUpFollow>,
}

/// Where the background check reports the peer a noted block came from,
/// once two independent engines agree that the block's work does not match
/// (see [`Node::register_work_blame`]). A single engine's mismatch is never
/// reported. P2P registers its peer security here, which treats the peer as
/// a confirmed refusal at admission would have.
pub(crate) trait WorkBlame: Send + Sync {
    fn blame(&self, sender: BlockSender);
}

impl FetchedFrom {
    /// The peer as the sender of a block fetched from it.
    pub(crate) fn block_sender(self) -> BlockSender {
        BlockSender {
            address: self.sender,
            fetched: true,
            trusted: self.trusted,
        }
    }
}

/// A fetched block's work, to be computed into the memo just before its
/// ordered submission. Taken under the node lock, run off it.
pub(crate) struct WorkPrewarm {
    gate: WorkGate,
    checker: Arc<HonestWorkChecker>,
    block_id: [u8; 32],
    claim: WorkClaim,
    /// Waits for the lane as priority: the block came from a trusted peer.
    priority: bool,
    /// The peer address it counts against under
    /// [`MAX_LONE_REFUSALS_PER_SENDER`]: none for a trusted peer.
    counted_sender: Option<IpAddr>,
}

impl WorkPrewarm {
    /// The block whose work this computes.
    pub(crate) fn block_id(&self) -> [u8; 32] {
        self.block_id
    }

    /// Waits for the work lane as long as `request` allows, then computes the
    /// block's work into the memo unless `stop` says to give up. No verdict is
    /// reached and nothing is recorded: the ordered submission does that, from
    /// the memo.
    pub(crate) fn run(self, request: RemoteProofRequest, stop: &WorkCancel<'_>) {
        let lane = if self.priority {
            self.gate.lane.acquire_priority_cancellable(request)
        } else {
            self.gate.lane.acquire_cancellable(request)
        };
        let Ok(_lane) = lane else {
            return;
        };
        // A sender with no refusals left runs nothing; its submission is
        // deferred.
        if !self
            .gate
            .lone_refusals_allow(self.counted_sender, &self.block_id)
        {
            return;
        }
        let digest = self.claim.challenge_digest;
        let computed = !self.checker.memo_settled(digest);
        // Nothing runs if the memo has an answer by now. A failure leaves the
        // memo as it was; the submission then checks the block itself.
        let _ = self.checker.prewarm_cancellable(digest, stop);
        // On one kind of engine, a result that does not match is counted
        // against the sender now, with the lane held, as its submission's
        // refusal would be.
        if computed
            && !self.checker.has_independent_engines()
            && self.checker.memo_settled(digest)
            && self.checker.memo_match(self.claim).is_none()
        {
            self.gate
                .charge_lone_refusal(self.counted_sender, self.block_id, digest);
        }
    }
}

impl Node {
    /// The work prewarm for a block whose parent is indexed, fetched `from`
    /// a peer: `None` unless the block is above the checkpoint, not verified,
    /// not answered by the memo yet, and passes every check its admission
    /// makes before its proof is checked (so a halted node, an invalid
    /// parent, a checkpoint conflict, a side block too deep to check now
    /// unless the peer is heavier, a bad target or challenge binding, a
    /// mismatch already found, and a block from a peer that has used up its
    /// one-engine refusals run nothing).
    pub(crate) fn work_prewarm(
        &self,
        block: &Block,
        accepted_at: u64,
        from: FetchedFrom,
    ) -> Option<WorkPrewarm> {
        let gate = self.work_gate.as_ref()?;
        let checker = gate.checker.as_ref()?;
        let height = self.work_height(block)?;
        if !gate.rule.requires_recomputation(height)
            || gate.status(&block.block_id()) == Some(WorkStatus::Verified)
        {
            return None;
        }
        let claim = gate.claim(block)?;
        if checker.memo_match(claim).is_some() {
            return None;
        }
        let block_id = block.block_id();
        let counted_sender = (!from.trusted).then_some(from.sender);
        // A block a desktop wallet catching up might admit without an
        // engine run, if it gets that far.
        let follow = from
            .catch_up
            .filter(|follow| height <= follow.below)
            .zip(gate.wallet_catch_up.as_ref());
        if !gate.lone_refusals_allow(counted_sender, &block_id) {
            if let Some((_, catch_up)) = follow {
                catch_up.note_throttled();
            }
            return None;
        }
        // A stale one-engine refusal passes this preflight but stays
        // remembered until the submission's own preflight forgets it. Its
        // prewarm runs nothing while its result is still memoized.
        self.preflight_external_block_admission_from(
            block,
            accepted_at,
            Some(from.block_sender()),
            from.heavier,
        )
        .ok()?;
        if let Some((follow, catch_up)) = follow {
            match self.grant_wallet_follow(gate, catch_up, block, height, follow) {
                Ok(()) => return None,
                Err(refusal) => catch_up.note_refusal(refusal),
            }
        }
        Some(WorkPrewarm {
            gate: gate.clone(),
            checker: Arc::clone(checker),
            block_id,
            claim,
            priority: from.trusted,
            counted_sender,
        })
    }

    /// The work prewarms of a contiguous window of fetched blocks, oldest
    /// first, so a catch-up session with more than one work job can compute
    /// them side by side before their ordered submission. The first block
    /// takes the full [`work_prewarm`](Self::work_prewarm) preflight; each
    /// later block must be the child of the one before it and takes
    /// [`work_prewarm_descendant`](Self::work_prewarm_descendant). The
    /// window ends at the first block whose parent is not indexed and not
    /// the block before it, or that fails its preflight. Empty with one
    /// work job: the ordered submission then prewarms each block itself.
    pub(crate) fn work_prewarm_window(
        &self,
        blocks: &[Block],
        accepted_at: u64,
        from: FetchedFrom,
    ) -> Vec<WorkPrewarm> {
        let mut prewarms = Vec::new();
        if self.work_jobs() < 2 || blocks.len() < 2 {
            return prewarms;
        }
        let mut previous: Option<(&Block, u64)> = None;
        for block in blocks {
            let (height, prewarm) = match previous {
                Some((parent, parent_height))
                    if block.challenge.previous_block == parent.block_id() =>
                {
                    match self.work_prewarm_descendant(block, parent_height, from) {
                        Ok(prewarm) => (parent_height.saturating_add(1), prewarm),
                        Err(()) => break,
                    }
                }
                Some(_) => break,
                None => {
                    // The first block's parent must be indexed, and the block
                    // must pass the full admission preflight.
                    let Some(height) = self.work_height(block) else {
                        break;
                    };
                    if self
                        .preflight_external_block_admission_from(
                            block,
                            accepted_at,
                            Some(from.block_sender()),
                            from.heavier,
                        )
                        .is_err()
                    {
                        break;
                    }
                    (height, self.work_prewarm(block, accepted_at, from))
                }
            };
            previous = Some((block, height));
            prewarms.extend(prewarm);
        }
        prewarms
    }

    /// The work prewarm for `block`, fetched `from` a peer in the same sync
    /// window as its parent, which is not indexed yet but has passed
    /// [`work_prewarm`](Self::work_prewarm) (or this) at `parent_height`.
    /// Lets a catch-up session with more than one work job compute the
    /// window's blocks side by side. Every check that needs no parent state
    /// is made: a halted node, a block or parent recorded invalid, a
    /// remembered rejection, a stale proof or preamble, a block from a peer
    /// that has used up its one-engine refusals. The target binding, which
    /// needs the parent's chain state, is left to the ordered submission;
    /// a wrong target then costs this node at most one wasted engine run per
    /// window block, which the lone-refusal accounting charges to the
    /// sender. Not used for a desktop wallet catching up.
    ///
    /// `Err(())` means the block would be refused, so the window ends there;
    /// `Ok(None)` means it needs no engine run (already verified, answered
    /// by the memo, or below the rule), and the window goes on past it.
    pub(crate) fn work_prewarm_descendant(
        &self,
        block: &Block,
        parent_height: u64,
        from: FetchedFrom,
    ) -> Result<Option<WorkPrewarm>, ()> {
        let Some(gate) = self.work_gate.as_ref() else {
            return Ok(None);
        };
        let Some(checker) = gate.checker.as_ref() else {
            return Err(());
        };
        if from.catch_up.is_some() {
            return Err(());
        }
        let height = parent_height.checked_add(1).ok_or(())?;
        let block_id = block.block_id();
        if self.index.contains(block_id)
            || self.storage_faulted
            || self.work_rule_lineage(block).is_err()
            || (self.rejected_proof_ids.contains(&block_id)
                && !self.stale_work_rejection(&block_id))
        {
            return Err(());
        }
        cmfd_consensus::validate_block_resources(block).map_err(|_| ())?;
        let body_digest = crate::canonical_block_cache_digest(block).map_err(|_| ())?;
        if self.rejected_body_digests.contains(&body_digest) {
            return Err(());
        }
        cmfd_consensus::validate_block_preamble(block, self.params.network_id).map_err(|_| ())?;
        self.verifier
            .preflight(&block.challenge, &block.proof)
            .map_err(|_| ())?;
        if !gate.rule.requires_recomputation(height)
            || gate.status(&block_id) == Some(WorkStatus::Verified)
        {
            return Ok(None);
        }
        let Some(claim) = gate.claim(block) else {
            return Err(());
        };
        if checker.memo_match(claim).is_some() {
            return Ok(None);
        }
        let counted_sender = (!from.trusted).then_some(from.sender);
        if !gate.lone_refusals_allow(counted_sender, &block_id) {
            return Err(());
        }
        Ok(Some(WorkPrewarm {
            gate: gate.clone(),
            checker: Arc::clone(checker),
            block_id,
            claim,
            priority: from.trusted,
            counted_sender,
        }))
    }
}

/// Whether `rule` pins the block a halt marker names, at its height: the
/// release then settles that block, at or below its checkpoint.
fn release_pins_halted_block(rule: &ForgeMatrixV4WorkRule, halt: &WorkHalt) -> bool {
    halt.height <= rule.checkpoint_height() && rule.canonical_id(halt.height) == Some(halt.block_id)
}

impl Node {
    /// Installs the work engines and opens the work-status store for this
    /// node's rule. Returns `None` if the node has no work rule. Until this
    /// is called, every block above the checkpoint is retryable. A halt
    /// marker in the data directory (or one that cannot be read) halts
    /// admission, and so does an active block recorded invalid, should the
    /// marker never have been written for it. A marker for a block this
    /// release pins at its height, at or below its checkpoint, is removed
    /// instead: the release has settled that block.
    ///
    /// Fails if the stored active chain is not the one the release pins at
    /// or below the checkpoint (see
    /// [`check_work_checkpoint_consistency`](Self::check_work_checkpoint_consistency)).
    /// A desktop wallet catch-up turned on before is turned off; turn it on
    /// after installing ([`enable_wallet_catch_up`](Self::enable_wallet_catch_up)).
    pub fn install_work_checker(
        &mut self,
        checker: Arc<HonestWorkChecker>,
    ) -> Result<Option<WorkStatusLoad>, NodeError> {
        let network_id = self.params.network_id;
        let Some(gate) = self.work_gate.as_mut() else {
            return Ok(None);
        };
        let path = self.data_dir.join(WORK_STATUS_FILE);
        let (store, load) = WorkStatusStore::open(
            &path,
            network_id,
            gate.rule.checkpoint_height(),
            gate.rule.checkpoint_block_id(),
        )
        .map_err(|source| NodeError::Io {
            operation: "open the work-status store",
            path,
            source,
        })?;
        self.check_work_checkpoint_consistency()?;
        let gate = self.work_gate.as_mut().expect("work rule checked above");
        let halt_path = self.data_dir.join(WORK_HALT_FILE);
        let halted = match read_work_halt(&halt_path, network_id) {
            Ok(Some(halt)) if release_pins_halted_block(&gate.rule, &halt) => {
                match clear_work_halt(&halt_path, network_id, halt.block_id) {
                    Ok(_) => {
                        tracing::error!(
                            target: "work_rule",
                            height = halt.height,
                            block_id = %hex::encode(halt.block_id),
                            checkpoint_height = gate.rule.checkpoint_height(),
                            "the work-check halt marker named a block this release pins as canonical at its height; the marker is removed and block admission is not halted"
                        );
                        false
                    }
                    Err(error) => {
                        tracing::error!(
                            target: "work_rule",
                            %error,
                            "the work-check halt marker names a block this release pins, but it cannot be removed"
                        );
                        true
                    }
                }
            }
            Ok(halt) => halt.is_some(),
            Err(error) => {
                tracing::error!(target: "work_rule", %error, "the work-check halt marker cannot be read");
                true
            }
        };
        gate.halted.store(halted, Ordering::Release);
        gate.checker = Some(checker);
        gate.store = Some(Arc::new(Mutex::new(store)));
        // The catch-up belongs to the store it was turned on over.
        gate.wallet_catch_up = None;
        if let Some((height, block_id)) = self.invalid_active_work_block() {
            tracing::error!(
                target: "work_rule",
                height,
                block_id = %hex::encode(block_id),
                "an active block is recorded invalid; block admission is halted until an operator quarantines it"
            );
            self.work_gate
                .as_ref()
                .expect("work rule checked above")
                .halted
                .store(true, Ordering::Release);
        }
        Ok(Some(load))
    }

    /// The lowest active block above the checkpoint recorded invalid, as
    /// (height, block id).
    fn invalid_active_work_block(&self) -> Option<(u64, [u8; 32])> {
        let gate = self.work_gate.as_ref()?;
        let store = lock(gate.store.as_ref()?);
        let first = usize::try_from(gate.rule.checkpoint_height().saturating_add(1)).ok()?;
        self.index
            .active_chain
            .iter()
            .enumerate()
            .skip(first)
            .find(|(_, block_id)| store.status(block_id) == Some(WorkStatus::Invalid))
            .map(|(height, block_id)| (height as u64, *block_id))
    }

    /// The block an operator removes to end a work-rule halt: the one the
    /// halt marker names, or else the lowest active block recorded invalid.
    pub fn work_halted_block(&self) -> Option<[u8; 32]> {
        let gate = self.work_gate.as_ref()?;
        if !gate.halted() {
            return None;
        }
        let marker = read_work_halt(&self.data_dir.join(WORK_HALT_FILE), self.params.network_id);
        match marker {
            Ok(Some(halt)) => Some(halt.block_id),
            _ => self
                .invalid_active_work_block()
                .map(|(_, block_id)| block_id),
        }
    }

    /// The flag that is set once block admission is halted by the work rule,
    /// for a supervisor that must not take the node lock to watch it.
    pub fn work_rule_halt_flag(&self) -> Option<Arc<AtomicBool>> {
        self.work_gate.as_ref().map(|gate| Arc::clone(&gate.halted))
    }

    /// Builds the CPU work engine over this node's authenticated model bank,
    /// with `threads` compute threads per block run at `priority`, reading
    /// the bank as `bank` says, and, given `gpu` replay workers (a pool's), a
    /// GPU work engine that borrows them while they are idle; then installs
    /// them (see [`install_work_checker`](Self::install_work_checker)).
    /// Returns the checker, not yet qualified, or `None` if the node has no
    /// work rule. Each block's check reads the layers without authenticating
    /// them again: the bank was authenticated when the node opened (and a
    /// resident bank's layers are checked against their roots as they are
    /// loaded), and the known-answer rounds authenticate every layer they
    /// read, as does the known answer a worker reproduces before a mismatch
    /// that only it found is kept.
    #[cfg(feature = "production-v4")]
    pub fn install_work_engines(
        &mut self,
        threads: usize,
        priority: crate::honest_work::WorkThreadPriority,
        bank: WorkBankMode,
        gpu: Option<Arc<dyn crate::honest_work::GpuReplayWorkers>>,
    ) -> Result<Option<(Arc<HonestWorkChecker>, WorkStatusLoad)>, NodeError> {
        self.install_work_engines_with_jobs(threads, 1, priority, bank, gpu)
    }

    /// [`install_work_engines`](Self::install_work_engines) with `jobs` CPU
    /// workers (at least one), each with its own `threads` compute threads,
    /// and a work lane as wide, so a catch-up session can check that many
    /// fetched blocks side by side (see [`crate::p2p`]'s fetched window).
    /// With one job, nothing differs from before.
    #[cfg(feature = "production-v4")]
    pub fn install_work_engines_with_jobs(
        &mut self,
        threads: usize,
        jobs: usize,
        priority: crate::honest_work::WorkThreadPriority,
        bank: WorkBankMode,
        gpu: Option<Arc<dyn crate::honest_work::GpuReplayWorkers>>,
    ) -> Result<Option<(Arc<HonestWorkChecker>, WorkStatusLoad)>, NodeError> {
        use crate::honest_work::{
            CpuWorkEngine, GPU_WORK_CHECK_TIMEOUT, GpuWorkEngine, WorkEngine,
        };
        use cmfd_consensus::{
            ForgeMatrixV4ExecutionError, ForgeMatrixV4FileLayerSource, ForgeMatrixV4LayerSource,
            ForgeMatrixV4ResidentLayerSource,
        };
        if self.work_gate.is_none() {
            return Ok(None);
        }
        let work_bank = self
            .work_bank
            .as_ref()
            .ok_or(NodeError::ProductionV4ArtifactsMissing)?;
        let identity = &work_bank.identity;
        let file = || {
            work_bank.file.try_clone().map_err(|source| NodeError::Io {
                operation: "open the model bank for the work engine",
                path: work_bank.path.clone(),
                source,
            })
        };
        let unusable = |error| work_bank_error(error, &work_bank.path);
        let layer_bytes = identity
            .manifest
            .payload_bytes
            .saturating_sub(identity.manifest.base_input_bytes);
        let mut mode = match bank {
            WorkBankMode::Auto => auto_work_bank_mode(layer_bytes, available_memory_bytes()),
            chosen => chosen,
        };
        let mut resident: Option<Arc<dyn ForgeMatrixV4LayerSource>> = None;
        if mode == WorkBankMode::Resident {
            match ForgeMatrixV4ResidentLayerSource::load(
                file()?,
                &identity.manifest,
                Arc::clone(&identity.base_input),
                Arc::clone(&identity.layer_roots),
            ) {
                Ok(loaded) => resident = Some(Arc::new(loaded)),
                Err(error @ ForgeMatrixV4ExecutionError::ResidentAllocation { .. })
                    if bank == WorkBankMode::Auto =>
                {
                    tracing::warn!(target: "work_rule", %error, "the model bank is streamed instead");
                    mode = WorkBankMode::Streamed;
                }
                Err(error) => return Err(unusable(error)),
            }
        }
        let source = match resident {
            Some(source) => source,
            None => Arc::new(
                ForgeMatrixV4FileLayerSource::new(
                    file()?,
                    &identity.manifest,
                    Arc::clone(&identity.base_input),
                    Arc::clone(&identity.layer_roots),
                )
                .map_err(unusable)?,
            ),
        };
        let jobs = jobs.max(1);
        let engine: Arc<dyn WorkEngine> = Arc::new(
            CpuWorkEngine::new(source, threads)
                .with_thread_priority(priority)
                .with_jobs(jobs),
        );
        let gpu = gpu.map(|workers| {
            Arc::new(GpuWorkEngine::new(workers, GPU_WORK_CHECK_TIMEOUT)) as Arc<dyn WorkEngine>
        });
        let checker = Arc::new(
            HonestWorkChecker::new(Some(engine), gpu, false)
                .expect("each engine in the slot for its kind"),
        );
        let load = self.install_work_checker(Arc::clone(&checker))?;
        if let Some(gate) = self.work_gate.as_mut() {
            gate.bank = Some(mode);
            gate.lane.set_max_active(jobs);
        }
        Ok(load.map(|load| (checker, load)))
    }

    /// Blocks whose work this node can check at once: the width of its work
    /// lane (one unless the engines were installed with more jobs).
    pub(crate) fn work_jobs(&self) -> usize {
        self.work_gate
            .as_ref()
            .map_or(1, |gate| gate.lane.max_active())
    }

    /// Hands the checker this pool's own replay result for a block it found
    /// (see [`HonestWorkChecker::record_honest`]), before the block is
    /// submitted. Does nothing before engines are installed.
    pub(crate) fn record_pool_replay(&self, replay: PoolReplayResult) {
        if let Some(checker) = self
            .work_gate
            .as_ref()
            .and_then(|gate| gate.checker.as_ref())
        {
            checker.record_honest(replay);
        }
    }

    /// Whether this node's network has a work rule but no engines are
    /// installed, so every block above the checkpoint would be retryable.
    pub fn work_checker_missing(&self) -> bool {
        self.work_gate
            .as_ref()
            .is_some_and(|gate| gate.checker.is_none())
    }

    /// Whether block admission is halted by the work rule.
    pub fn work_rule_halted(&self) -> bool {
        self.work_gate.as_ref().is_some_and(WorkGate::halted)
    }

    /// Replaces the compiled work rule, or removes it with `None`. Blocks are
    /// then checked against `rule`, reading reference proofs' claims too, so
    /// Devnet can exercise admission. Tests and local qualification only.
    #[cfg(any(test, feature = "work-rule-test-support"))]
    pub fn install_work_rule_for_test(&mut self, rule: Option<ForgeMatrixV4WorkRule>) {
        self.work_gate = rule.map(|rule| WorkGate::new(Arc::new(rule), true));
    }

    /// The work rule as node status reports it, or `None` for a network
    /// without one.
    pub fn work_rule_status(&self) -> Option<WorkRuleStatus> {
        self.work_rule_status_now(Instant::now())
    }

    /// [`work_rule_status`](Self::work_rule_status) at `now`.
    #[cfg(test)]
    pub(crate) fn work_rule_status_at(&self, now: Instant) -> Option<WorkRuleStatus> {
        self.work_rule_status_now(now)
    }

    fn work_rule_status_now(&self, now: Instant) -> Option<WorkRuleStatus> {
        use crate::honest_work::{WorkEngineKind, WorkEngineState};
        let gate = self.work_gate.as_ref()?;
        let checker = gate.checker.as_ref();
        let state = checker.map(|checker| checker.engine_state());
        let alarms = checker.map(|checker| checker.alarms()).unwrap_or_default();
        let has = |kind| checker.is_some_and(|checker| checker.engine_health(kind).is_some());
        let validated_height = self
            .work_validated_height()
            .unwrap_or_else(|| gate.rule.checkpoint_height());
        let unsettled = self.work_unsettled_frontier(validated_height);
        let wallet_catch_up = gate
            .wallet_catch_up
            .as_ref()
            .map(|catch_up| self.wallet_catch_up_status(gate, catch_up, validated_height, now));
        Some(WorkRuleStatus {
            enforced: checker.is_some(),
            engines: match (has(WorkEngineKind::Cpu), has(WorkEngineKind::Gpu)) {
                (true, true) => Some("cpu+gpu"),
                (true, false) => Some("cpu"),
                (false, true) => Some("gpu"),
                (false, false) => None,
            },
            bank: gate.bank.map(WorkBankMode::as_str),
            engine_state: match state {
                None => "pending",
                Some(WorkEngineState::Qualifying) => "qualifying",
                Some(WorkEngineState::Ready) => "ready",
                Some(WorkEngineState::Failed) => "failed",
            },
            engine_ready: state == Some(WorkEngineState::Ready),
            independent_engines: checker.is_some_and(|checker| checker.has_independent_engines()),
            halted: gate.halted(),
            checkpoint_height: gate.rule.checkpoint_height(),
            checkpoint_hash: hex::encode(gate.rule.checkpoint_block_id()),
            activation_height: gate.rule.checkpoint_height().saturating_add(1),
            validated_height,
            pending_side_blocks: lock(&gate.pending_side).order.len(),
            unsettled_height: unsettled.map(|(height, _)| height),
            unsettled_block_id: unsettled.map(|(_, block_id)| hex::encode(block_id)),
            backlog_paused: gate.backlog_paused.load(Ordering::Acquire),
            alarms: WorkRuleAlarms {
                engine_divergence: alarms.engine_divergence,
                own_engine_mismatches: alarms.own_engine_mismatches,
                engine_failures: alarms.engine_failures,
                store_conflicts: gate.store_conflicts.load(Ordering::Relaxed),
                peers_on_invalid_chain: self.invalid_chain_peer_events(),
            },
            wallet_catch_up,
        })
    }

    /// The height and id of the active block just above `validated_height`,
    /// if it is recorded unsettled ([`WorkRuleStatus::unsettled_height`]).
    /// On a desktop wallet catching up, it is the lowest such block anywhere
    /// above the validated height.
    fn work_unsettled_frontier(&self, validated_height: u64) -> Option<(u64, [u8; 32])> {
        let gate = self.work_gate.as_ref()?;
        if gate.wallet_catch_up.is_some() {
            return self.wallet_frontier(gate, validated_height);
        }
        let store = gate.store.as_ref()?;
        let height = validated_height.checked_add(1)?;
        let block_id = usize::try_from(height)
            .ok()
            .and_then(|position| self.index.active_chain.get(position))?;
        lock(store)
            .is_unsettled(block_id)
            .then_some((height, *block_id))
    }

    /// Whether the validated height is held below the tip by an active block
    /// recorded unsettled, which on a node with one kind of engine only a
    /// later check or syncing the stored chain again can clear.
    pub fn work_validated_height_held_by_unsettled_block(&self) -> bool {
        self.work_validated_height()
            .and_then(|validated| self.work_unsettled_frontier(validated))
            .is_some()
    }

    /// The flag the background check sets while it is paused.
    pub(crate) fn work_backlog_paused_flag(&self) -> Option<Arc<AtomicBool>> {
        self.work_gate
            .as_ref()
            .map(|gate| Arc::clone(&gate.backlog_paused))
    }

    /// Times the engines and the work-status store disagreed about a block.
    pub fn work_store_conflicts(&self) -> u64 {
        self.work_gate
            .as_ref()
            .map_or(0, |gate| gate.store_conflicts.load(Ordering::Relaxed))
    }

    /// Checks that every stored active block at or below the release
    /// checkpoint is the one the release pins. This needs no engine: it is
    /// the same comparison admission makes for each new block at or below
    /// the checkpoint, applied to what an earlier release stored. The first
    /// block that differs is reported as a
    /// [`WorkCheckpointConflict`](NodeError::WorkCheckpointConflict), to be
    /// removed with the storage quarantine command; if it is already pruned,
    /// the node must be resynced
    /// ([`WorkRuleResyncRequired`](NodeError::WorkRuleResyncRequired)).
    pub fn check_work_checkpoint_consistency(&self) -> Result<(), NodeError> {
        let Some(gate) = self.work_gate.as_ref() else {
            return Ok(());
        };
        let rule = &gate.rule;
        let tip = self.state.next_height().saturating_sub(1);
        let through = tip.min(rule.checkpoint_height());
        for height in 1..=through {
            let Some(&block_id) = usize::try_from(height)
                .ok()
                .and_then(|position| self.index.active_chain.get(position))
            else {
                break;
            };
            if !rule.conflicts_with_canonical_list(height, block_id) {
                continue;
            }
            tracing::error!(
                target: "work_rule",
                height,
                block_id = %hex::encode(block_id),
                "the stored chain differs from the chain pinned by the release checkpoint"
            );
            return Err(if self.block_is_pruned(block_id) {
                NodeError::WorkRuleResyncRequired(block_id)
            } else {
                NodeError::WorkCheckpointConflict {
                    block_id,
                    height,
                    checkpoint_height: rule.checkpoint_height(),
                }
            });
        }
        Ok(())
    }

    /// The highest height `h` up to the tip such that every active block
    /// above the release checkpoint, up to `h`, is verified here: everything
    /// up to `h` has had its work checked (blocks at or below the checkpoint
    /// are the pinned ones). It is what consumers may treat as settled. It is
    /// the checkpoint height while no engines are installed above it, and
    /// `None` for a network without a work rule.
    pub fn work_validated_height(&self) -> Option<u64> {
        let gate = self.work_gate.as_ref()?;
        let checkpoint = gate.rule.checkpoint_height();
        let tip = self.state.next_height().saturating_sub(1);
        if tip <= checkpoint {
            return Some(tip);
        }
        let Some(store) = gate.store.as_ref() else {
            return Some(checkpoint);
        };
        let store = lock(store);
        let mut cached = lock(&gate.validated);
        let active = &self.index.active_chain;
        let at = |height: u64| {
            usize::try_from(height)
                .ok()
                .and_then(|position| active.get(position))
                .copied()
        };
        // A block still active at the cached height means the chain below it
        // is unchanged; otherwise a reorganization replaced it, and the walk
        // starts again from the checkpoint.
        // So does a revocation: a block below it may no longer be verified.
        let revocations = store.revocations();
        let mut height = match *cached {
            Some((height, block_id, seen))
                if seen == revocations && height <= tip && at(height) == Some(block_id) =>
            {
                height
            }
            _ => checkpoint,
        };
        while height < tip {
            match at(height + 1) {
                Some(block_id) if store.status(&block_id) == Some(WorkStatus::Verified) => {
                    height += 1;
                }
                _ => break,
            }
        }
        *cached = at(height)
            .filter(|_| height > checkpoint)
            .map(|id| (height, id, revocations));
        Some(height)
    }

    /// The highest active height the exchange RPC serves: the validated
    /// height on a network with a work rule, otherwise the tip.
    pub(crate) fn exchange_served_cap(&self) -> u64 {
        let tip = self.state.next_height().saturating_sub(1);
        self.work_validated_height().unwrap_or(tip).min(tip)
    }

    /// Fails with [`NodeError::WorkCheckPending`] while stored blocks above
    /// the validated height exist, so a withdrawal is never planned from
    /// chain state that includes blocks whose work is not yet re-executed.
    pub(crate) fn require_exchange_tip_checked(&self) -> Result<(), NodeError> {
        if self.exchange_served_cap() < self.state.next_height().saturating_sub(1) {
            return Err(NodeError::WorkCheckPending);
        }
        Ok(())
    }

    /// [`exchange_served_cap`](Self::exchange_served_cap), or why chain reads
    /// are refused: block admission is halted or the engines have failed, so
    /// the validated height can no longer advance.
    pub(crate) fn exchange_served_height(&self) -> Result<u64, ExchangeReadRefusal> {
        if let Some(gate) = self.work_gate.as_ref() {
            if gate.halted() {
                return Err(ExchangeReadRefusal::Halted);
            }
            if gate.checker.as_ref().is_some_and(|checker| {
                checker.engine_state() == crate::honest_work::WorkEngineState::Failed
            }) {
                return Err(ExchangeReadRefusal::EngineFailed);
            }
        }
        Ok(self.exchange_served_cap())
    }

    /// The height of the lowest active block above the checkpoint that is
    /// still kept in full and not verified, if any. The pruner keeps it and
    /// everything above it in full until it is verified, while blocks below
    /// it, pruned or verified, do not hold pruning back.
    /// A desktop wallet catching up keeps its usual prune window instead.
    pub(crate) fn lowest_unverified_full_height(&self) -> Option<u64> {
        let gate = self.work_gate.as_ref()?;
        if gate.wallet_catch_up.is_some() {
            return None;
        }
        let tip = self.state.next_height().saturating_sub(1);
        let start = gate
            .rule
            .checkpoint_height()
            .max(self.prune_height().unwrap_or(0))
            .max(self.work_validated_height().unwrap_or(0))
            .saturating_add(1);
        let store = gate.store.as_ref().map(|store| lock(store));
        (start..=tip).find(|height| {
            let Some(&block_id) = usize::try_from(*height)
                .ok()
                .and_then(|position| self.index.active_chain.get(position))
            else {
                return false;
            };
            store
                .as_ref()
                .is_none_or(|store| store.status(&block_id) != Some(WorkStatus::Verified))
                && !self.block_is_pruned(block_id)
        })
    }

    /// Adds `sink` to the places the background check reports a noted
    /// block's peer to (see [`WorkBlame`]), once. A sink that is gone is
    /// dropped.
    pub(crate) fn register_work_blame(&mut self, sink: Weak<dyn WorkBlame>) {
        self.work_blame.retain(|known| known.strong_count() > 0);
        if !self.work_blame.iter().any(|known| known.ptr_eq(&sink)) {
            self.work_blame.push(sink);
        }
    }

    /// The registered [`WorkBlame`] sinks that are still in use.
    pub(crate) fn work_blame_sinks(&self) -> Vec<Arc<dyn WorkBlame>> {
        self.work_blame.iter().filter_map(Weak::upgrade).collect()
    }

    /// Blocks noted for the background work check, oldest first.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn pending_side_work(&self) -> Vec<PendingSideWork> {
        self.work_gate.as_ref().map_or_else(Vec::new, |gate| {
            lock(&gate.pending_side).order.iter().copied().collect()
        })
    }

    /// The height `block` would have here: one above its parent's, or `None`
    /// if the parent is not indexed.
    fn work_height(&self, block: &Block) -> Option<u64> {
        let parent = block.challenge.previous_block;
        if parent == self.index.genesis {
            return Some(1);
        }
        self.index
            .blocks
            .get(&parent)
            .map(|entry| entry.height().saturating_add(1))
    }

    /// Whether this node knows `block_id` cannot be admitted: its proof or
    /// work was rejected and is remembered, or it is recorded invalid. Sync
    /// does not download such a block again: a re-sent copy would be refused
    /// at once, with no check run. A one-engine refusal that has gone
    /// [stale](Self::stale_work_rejection) does not count.
    pub(crate) fn known_invalid_block(&self, block_id: &[u8; 32]) -> bool {
        (self.rejected_proof_ids.contains(block_id) && !self.stale_work_rejection(block_id))
            || self.recorded_invalid(block_id)
    }

    /// Whether a peer serving `block_id` is on a chain this node knows is
    /// invalid, so its height is no sign that this node is behind: the block
    /// is recorded invalid, two independent engines agreed its work does not
    /// match, or its proof was rejected. One engine's mismatch does not
    /// count: that engine may be at fault, and the node must not then look
    /// caught up with peers it cannot follow.
    pub(crate) fn marks_peer_on_invalid_chain(&self, block_id: &[u8; 32]) -> bool {
        self.recorded_invalid(block_id)
            || (self.rejected_proof_ids.contains(block_id)
                && !matches!(
                    self.work_rejection(block_id),
                    Some(WorkRejectionKind::Unconfirmed(_))
                ))
    }

    /// Whether `block_id` is remembered as refused because one engine found
    /// its work does not match, with no record that two engines agreed.
    pub(crate) fn unconfirmed_work_rejection(&self, block_id: &[u8; 32]) -> bool {
        matches!(
            self.work_rejection(block_id),
            Some(WorkRejectionKind::Unconfirmed(_))
        ) && !self.recorded_invalid(block_id)
    }

    /// Whether `block_id` is remembered as refused on one engine's word that
    /// this node's engines no longer hold as one engine's final answer: a
    /// worker of the other kind is now ready, the worker that found it was
    /// retired or has not reproduced a known answer recently, its result was
    /// displaced, or two engines have since agreed on its challenge. Such a
    /// block is checked again on its next arrival, and sync may download it
    /// again; when two engines agreed, that check refuses it as confirmed
    /// without running any engine.
    pub(crate) fn stale_work_rejection(&self, block_id: &[u8; 32]) -> bool {
        let Some(WorkRejectionKind::Unconfirmed(claim)) = self.work_rejection(block_id) else {
            return false;
        };
        !self.recorded_invalid(block_id)
            && !self
                .work_gate
                .as_ref()
                .and_then(|gate| gate.checker.as_ref())
                .is_some_and(|checker| checker.holds_lone_final_mismatch(claim))
    }

    /// How a remembered work rejection of `block_id` was decided, if it is
    /// remembered as one.
    fn work_rejection(&self, block_id: &[u8; 32]) -> Option<WorkRejectionKind> {
        if !self.rejected_proof_ids.contains(block_id) {
            return None;
        }
        self.work_rejections.get(block_id).copied()
    }

    /// Remembers `block` as refused if `error` is a work mismatch, as
    /// confirmed or as one engine's.
    pub(crate) fn remember_work_mismatch(&mut self, block: &Block, error: &NodeError) {
        let (block_id, kind) = match error {
            NodeError::WorkRecomputationMismatch(block_id) => {
                (*block_id, WorkRejectionKind::Confirmed)
            }
            NodeError::WorkMismatchUnconfirmed(block_id) => {
                let Some(claim) = self.work_gate.as_ref().and_then(|gate| gate.claim(block)) else {
                    return;
                };
                (*block_id, WorkRejectionKind::Unconfirmed(claim))
            }
            _ => return,
        };
        self.remember_work_rejection(block_id, kind);
    }

    fn recorded_invalid(&self, block_id: &[u8; 32]) -> bool {
        self.work_gate
            .as_ref()
            .is_some_and(|gate| gate.status(block_id) == Some(WorkStatus::Invalid))
    }

    /// The first work-rule checks, before the parent lookup: a halted node,
    /// and a block or parent recorded invalid.
    pub(crate) fn work_rule_lineage(&self, block: &Block) -> Result<(), NodeError> {
        let Some(gate) = self.work_gate.as_ref() else {
            return Ok(());
        };
        if gate.halted() {
            return Err(NodeError::WorkRuleHalted);
        }
        let block_id = block.block_id();
        if gate.status(&block_id) == Some(WorkStatus::Invalid) {
            return Err(NodeError::CachedInvalidBlock(block_id));
        }
        let parent = block.challenge.previous_block;
        if gate.status(&parent) == Some(WorkStatus::Invalid) {
            return Err(NodeError::InvalidAncestor(parent));
        }
        Ok(())
    }

    /// The remaining work-rule checks before any proof is checked; see the
    /// module documentation. `sender` is the peer the block came from, if a
    /// peer did. With `any_depth` (a sync prewarm for a
    /// heavier peer, see [`FetchedFrom::heavier`]) a block is checked however
    /// deep it is.
    pub(crate) fn work_rule_preflight(
        &self,
        block: &Block,
        sender: Option<BlockSender>,
        any_depth: bool,
    ) -> Result<(), NodeError> {
        let Some(gate) = self.work_gate.as_ref() else {
            return Ok(());
        };
        self.work_rule_lineage(block)?;
        let block_id = block.block_id();
        let parent = block.challenge.previous_block;
        let height = self
            .work_height(block)
            .ok_or(NodeError::UnknownParent(parent))?;
        let rule = &gate.rule;
        let checkpoint = rule.checkpoint_height();
        let conflict = || NodeError::WorkCheckpointConflict {
            block_id,
            height,
            checkpoint_height: checkpoint,
        };
        if height <= checkpoint {
            return if rule.conflicts_with_canonical_list(height, block_id) {
                Err(conflict())
            } else {
                Ok(())
            };
        }
        let checkpoint_ancestor = if height == checkpoint + 1 {
            parent
        } else {
            match self.index.ancestor_at_height(parent, checkpoint) {
                Ok(ancestor) => ancestor,
                Err(error) => {
                    // Every indexed block's ancestors are indexed too, pruned
                    // or not, so this is a damaged index, not a busy node.
                    tracing::error!(target: "work_rule", %error, "checkpoint ancestry is not readable");
                    return Err(NodeError::WorkCheckUnavailable);
                }
            }
        };
        if checkpoint_ancestor != rule.checkpoint_block_id() {
            return Err(conflict());
        }
        // A block recorded verified still needs every side ancestor checked:
        // an ancestor's record may have gone since (an operator's reconsider,
        // a damaged record dropped at load).
        if gate.store.is_some() {
            self.check_side_ancestors(gate, parent, checkpoint)?;
        }
        if gate.status(&block_id) == Some(WorkStatus::Verified) {
            return Ok(());
        }
        let claim = gate.claim(block);
        let tip_height = self.state.next_height().saturating_sub(1);
        // A claim the background check already settled is cheap to admit,
        // however deep: that is how a deep side block gets in once checked.
        let settled = || {
            claim.is_some_and(|claim| {
                gate.checker
                    .as_ref()
                    .is_some_and(|checker| checker.memo_settled(claim.challenge_digest))
            })
        };
        let relevant = any_depth
            || parent == self.state.tip()
            || height + WORK_RELEVANCE_DEPTH > tip_height
            || settled();
        if !relevant {
            if let Some(claim) = claim {
                gate.note_side_work(PendingSideWork {
                    block_id,
                    height,
                    claim,
                    sender,
                });
            }
            return Err(NodeError::WorkCheckPending);
        }
        if let (Some(checker), Some(claim)) = (gate.checker.as_ref(), claim)
            && let Some(mismatch) = checker.memo_mismatch(claim)
        {
            return Err(mismatch_error(&mismatch, block_id));
        }
        Ok(())
    }

    /// Earlier blocks of the side branch `parent` is on, down to the active
    /// chain or the checkpoint: one recorded invalid refuses the block, and
    /// one not checked yet makes it wait for the background check. However
    /// long the branch, blocks already verified do not make it wait, so a
    /// heavier branch can always be followed once its blocks are checked.
    fn check_side_ancestors(
        &self,
        gate: &WorkGate,
        parent: [u8; 32],
        checkpoint: u64,
    ) -> Result<(), NodeError> {
        let mut cursor = parent;
        let mut unchecked = false;
        // Heights fall by one at each step, so the walk ends. Virtual genesis
        // has no index entry; it ends the walk too.
        while let Some(entry) = self.index.blocks.get(&cursor) {
            let height = entry.height();
            let on_active_chain = usize::try_from(height)
                .ok()
                .and_then(|height| self.index.active_chain.get(height))
                == Some(&cursor);
            if height <= checkpoint || on_active_chain {
                break;
            }
            match gate.status(&cursor) {
                Some(WorkStatus::Invalid) => return Err(NodeError::InvalidAncestor(cursor)),
                Some(WorkStatus::Verified) => {}
                None => unchecked = true,
            }
            cursor = entry.parent();
        }
        if unchecked {
            return Err(NodeError::WorkCheckPending);
        }
        Ok(())
    }

    /// The work gate's part of admitting `block`, or `None` if the rule does
    /// not ask for a check (no rule, at or below the checkpoint, already
    /// verified, or granted on a desktop wallet catching up while it still
    /// extends the tip). `local_tip` is true for a local miner's block.
    pub(crate) fn work_admission(
        &self,
        block: &Block,
        local_tip: bool,
        origin: BlockOrigin,
    ) -> Result<Option<WorkAdmission>, NodeError> {
        let Some(gate) = self.work_gate.as_ref() else {
            return Ok(None);
        };
        if gate.halted() {
            return Err(NodeError::WorkRuleHalted);
        }
        let parent = block.challenge.previous_block;
        let height = self
            .work_height(block)
            .ok_or(NodeError::UnknownParent(parent))?;
        let block_id = block.block_id();
        if !gate.rule.requires_recomputation(height)
            || gate.status(&block_id) == Some(WorkStatus::Verified)
        {
            return Ok(None);
        }
        if let Some(catch_up) = gate.wallet_catch_up.as_ref()
            && catch_up.has_grant(&block_id)
            && self.wallet_grant_usable(gate, catch_up, block)
        {
            return Ok(None);
        }
        Ok(Some(WorkAdmission {
            gate: gate.clone(),
            block_id,
            height,
            claim: gate.claim(block),
            priority: local_tip
                || match origin {
                    BlockOrigin::InProcess => parent == self.state.tip(),
                    BlockOrigin::Rpc { loopback } => loopback,
                    BlockOrigin::Peer { trusted, .. } => trusted,
                },
            counted_sender: origin.counted_sender(),
        }))
    }

    /// Refuses with the retryable [`NodeError::WorkCheckDeferred`] a block
    /// from `sender` that would need a work check while the sender has used
    /// up its one-engine refusals (see [`MAX_LONE_REFUSALS_PER_SENDER`]). A
    /// block that needs no check, or that the memo already shows matches, is
    /// let through; so is any block without a counted sender.
    pub(crate) fn require_lone_refusal_budget(
        &self,
        block: &Block,
        sender: Option<IpAddr>,
    ) -> Result<(), NodeError> {
        let (Some(gate), Some(_)) = (self.work_gate.as_ref(), sender) else {
            return Ok(());
        };
        let Some(height) = self.work_height(block) else {
            return Ok(());
        };
        let block_id = block.block_id();
        if !gate.rule.requires_recomputation(height)
            || gate.status(&block_id) == Some(WorkStatus::Verified)
            || gate
                .claim(block)
                .zip(gate.checker.as_ref())
                .is_some_and(|(claim, checker)| checker.memo_match(claim).is_some())
            || gate.lone_refusals_allow(sender, &block_id)
        {
            Ok(())
        } else {
            Err(NodeError::WorkCheckDeferred)
        }
    }

    /// Whether sync should leave the proofs of blocks fetched `from` a peer
    /// unchecked for now: the peer is counted and has used up its one-engine
    /// refusals, so its blocks that need a work check are deferred anyway.
    pub(crate) fn lone_refusals_exhausted(&self, from: FetchedFrom) -> bool {
        !from.trusted
            && self.work_gate.as_ref().is_some_and(|gate| {
                lock(&gate.lone_refusals).exhausted(from.sender, Instant::now())
            })
    }

    /// Whether a sync session should not fetch the block `block_id` from
    /// `from`: the peer has used up its one-engine refusals, and the block,
    /// at `height` if that is known, needs a work check here, is not
    /// recorded verified and is not one of the peer's refusals already
    /// counted, so it would be deferred anyway.
    pub(crate) fn sync_fetch_deferred(
        &self,
        from: FetchedFrom,
        block_id: &[u8; 32],
        height: Option<u64>,
    ) -> bool {
        self.lone_refusals_exhausted(from)
            && self.work_gate.as_ref().is_some_and(|gate| {
                height.is_none_or(|height| gate.rule.requires_recomputation(height))
                    && gate.status(block_id) != Some(WorkStatus::Verified)
                    && !gate.lone_refusals_allow(Some(from.sender), block_id)
            })
    }

    /// The commit's own check: a block above the checkpoint is indexed only
    /// with a recorded verdict, or on a desktop wallet catching up with a
    /// grant while it still extends the tip, and one at or below the
    /// checkpoint only if it is the pinned canonical block. Returns whether it
    /// used a grant.
    pub(crate) fn require_work_verdict(&self, block: &Block) -> Result<bool, NodeError> {
        let Some(gate) = self.work_gate.as_ref() else {
            return Ok(false);
        };
        if gate.halted() {
            return Err(NodeError::WorkRuleHalted);
        }
        let block_id = block.block_id();
        // The height the admission checks used, not the header's claim.
        let parent = block.challenge.previous_block;
        let height = self
            .work_height(block)
            .ok_or(NodeError::UnknownParent(parent))?;
        if !gate.rule.requires_recomputation(height) {
            return if gate.rule.conflicts_with_canonical_list(height, block_id) {
                Err(NodeError::WorkCheckpointConflict {
                    block_id,
                    height,
                    checkpoint_height: gate.rule.checkpoint_height(),
                })
            } else {
                Ok(false)
            };
        }
        if gate.status(&block_id) == Some(WorkStatus::Verified) {
            return Ok(false);
        }
        if let Some(catch_up) = gate.wallet_catch_up.as_ref()
            && self.wallet_grant_usable(gate, catch_up, block)
            && catch_up.take_grant(&block_id)
        {
            return Ok(true);
        }
        Err(NodeError::WorkCheckRequired)
    }
}

impl Node {
    /// Turns on the desktop wallet catch-up over `sources`, the compiled
    /// sources of blocks each tagged with its provider. Returns whether it is
    /// on. It stays off without a work rule and an open work-status store,
    /// with fewer than two distinct sources or all in one group, when the
    /// release checkpoint is virtual genesis, or when the grant file cannot
    /// be opened or created. Only a desktop wallet calls this.
    ///
    /// With it on, a block a sync session fetched from one source is admitted
    /// without an engine run only if a source in another group listed it, it
    /// lies at least [`WALLET_CATCH_UP_DEPTH`] below both sources' reported
    /// heights, it extends the tip, it is at most [`WALLET_MAX_EASING`] times
    /// easier than the reference work, the release is fresh
    /// ([`STALE_AFTER`]) and the pruner keeps up ([`PRUNE_LAG_FACTOR`]). Such
    /// a block gets no work-status record, so the validated height never
    /// passes it until the background check re-executes it.
    pub fn enable_wallet_catch_up(
        &mut self,
        sources: Vec<CatchUpSource>,
    ) -> Result<bool, NodeError> {
        let Some(gate) = self.work_gate.as_ref() else {
            return Ok(false);
        };
        if gate.wallet_catch_up.is_some() {
            return Ok(true);
        }
        let checkpoint = gate.rule.checkpoint_height();
        if gate.store.is_none() || checkpoint == 0 {
            return Ok(false);
        }
        let Some(sources) = catch_up::valid_sources(sources) else {
            return Ok(false);
        };
        let validated = self.work_validated_height().unwrap_or(checkpoint);
        let path = self.data_dir.join(CATCH_UP_GRANTS_FILE);
        let active = &self.index.active_chain;
        let live = |height: u64, block_id: [u8; 32]| {
            height > validated
                && usize::try_from(height)
                    .ok()
                    .and_then(|position| active.get(position))
                    == Some(&block_id)
        };
        let grant_file = match GrantFile::open(
            &path,
            self.params.network_id,
            gate.rule.checkpoint_block_id(),
            live,
        ) {
            Ok(grant_file) => grant_file,
            Err(error) => {
                tracing::warn!(
                    target: "work_rule::catch_up",
                    path = %path.display(),
                    %error,
                    "the catch-up grant file cannot be opened; every block is checked before it is admitted"
                );
                return Ok(false);
            }
        };
        let catch_up = Arc::new(WalletCatchUp::new(sources, grant_file));
        self.refresh_coverage(gate, &catch_up, Instant::now());
        self.work_gate
            .as_mut()
            .expect("work rule checked above")
            .wallet_catch_up = Some(catch_up);
        Ok(true)
    }

    /// The desktop wallet catch-up, if it is on.
    pub(crate) fn wallet_catch_up(&self) -> Option<Arc<WalletCatchUp>> {
        self.work_gate
            .as_ref()
            .and_then(|gate| gate.wallet_catch_up.clone())
    }

    /// Whether a desktop wallet catching up may ask its sources to
    /// corroborate blocks now: the reference work is known (so the
    /// checkpoint block is indexed) and the release is fresh. The other
    /// grant conditions pass or fail block by block.
    pub(crate) fn wallet_corroboration_due(&self) -> bool {
        let Some(gate) = self.work_gate.as_ref() else {
            return false;
        };
        let Some(catch_up) = gate.wallet_catch_up.as_ref() else {
            return false;
        };
        self.refresh_coverage(gate, catch_up, Instant::now())
            .w_ref
            .is_some()
            && catch_up::release_fresh_at(
                crate::unix_time_seconds().ok(),
                catch_up.checkpoint_time(),
            )
    }

    /// The work of the active block at `height`, if it is indexed.
    fn active_block_work(&self, height: u64) -> Option<primitive_types::U512> {
        let block_id = self.active_block_id_at_height(height)?;
        let entry = self.index.blocks.get(&block_id)?;
        cmfd_consensus::block_work(entry.locator.target).ok()
    }

    /// The timestamp of the active block at `height`, read from its stored
    /// record (full or pruned): `None` if it is not indexed, an error if the
    /// record cannot be read.
    fn active_block_time(&self, height: u64) -> Option<Result<u64, NodeError>> {
        let block_id = self.active_block_id_at_height(height)?;
        let entry = self.index.blocks.get(&block_id)?;
        Some(
            crate::read_indexed_block(
                &self.log,
                &self.data_dir.join(crate::BLOCK_LOG_FILE),
                entry,
                block_id,
                self.params.network_id,
                matches!(self.profile.proof, crate::ProofProfile::ProductionV3),
            )
            .map(|block| block.challenge.timestamp),
        )
    }

    /// The reference work a block admitted without an engine run is measured
    /// against: the larger of the work of the active blocks at the validated
    /// height and at the checkpoint, unknown unless both are indexed. Read
    /// again only while no granted block lies above the validated height
    /// (`top_granted`), or with `force`, and held otherwise. Reads the
    /// checkpoint block's time once that block is indexed; after a failed
    /// read, at most once per
    /// [`CHECKPOINT_TIME_RETRY`](catch_up::CHECKPOINT_TIME_RETRY).
    fn wallet_reference(
        &self,
        gate: &WorkGate,
        catch_up: &WalletCatchUp,
        validated: u64,
        top_granted: u64,
        force: bool,
    ) -> Option<primitive_types::U512> {
        let checkpoint = gate.rule.checkpoint_height();
        let now = Instant::now();
        if catch_up.checkpoint_time().is_none() && catch_up.checkpoint_time_read_due(now) {
            match self.active_block_time(checkpoint) {
                Some(Ok(time)) => catch_up.set_checkpoint_time(time),
                Some(Err(error)) => {
                    let first_failure = catch_up.note_checkpoint_time_failed(now);
                    if first_failure {
                        tracing::warn!(
                            target: "work_rule::catch_up",
                            height = checkpoint,
                            %error,
                            "the checkpoint block's time cannot be read; no block is admitted without a check until it can"
                        );
                    }
                }
                None => {}
            }
        }
        if force || top_granted <= validated {
            catch_up.set_reference_work(catch_up::reference(
                self.active_block_work(validated),
                self.active_block_work(checkpoint),
            ));
        }
        catch_up.reference_work()
    }

    /// The held reference work of the desktop wallet catch-up, read again
    /// while no granted block lies above the validated height.
    #[cfg(test)]
    pub(crate) fn wallet_reference_work(&self) -> Option<primitive_types::U512> {
        let gate = self.work_gate.as_ref()?;
        let catch_up = gate.wallet_catch_up.as_ref()?;
        self.refresh_coverage(gate, catch_up, Instant::now()).w_ref
    }

    /// Brings the coverage of the desktop wallet catch-up up to date: the
    /// one place the uncovered floor, the highest granted block, the
    /// reference work and the runs of re-executed blocks are read from. A
    /// tip extension reads only the new blocks; the blocks above the
    /// validated height are scanned again after a reorganisation, a store
    /// revocation or a change of the reference work. The reference is read
    /// after the coverage, so it sees a highest granted block that a
    /// reorganisation lowered.
    fn refresh_coverage(
        &self,
        gate: &WorkGate,
        catch_up: &WalletCatchUp,
        now: Instant,
    ) -> CoverageView {
        let checkpoint = gate.rule.checkpoint_height();
        let validated = self.work_validated_height().unwrap_or(checkpoint);
        let tip = self.state.next_height().saturating_sub(1);
        let Some(store) = gate.store.as_ref() else {
            return CoverageView::default();
        };
        let store = lock(store);
        let index = WalletCoverageIndex {
            node: self,
            store: &store,
            catch_up,
        };
        catch_up.refresh_coverage(
            &index,
            validated,
            tip,
            store.revocations(),
            now,
            |coverage, first| {
                self.wallet_reference(gate, catch_up, validated, coverage.top_granted, first)
            },
        )
    }

    /// The cumulative work of the active chain up to `height`.
    fn active_cumulative_work(&self, height: u64) -> Option<primitive_types::U512> {
        let block_id = self.active_block_id_at_height(height)?;
        if block_id == self.index.genesis {
            return Some(primitive_types::U512::zero());
        }
        Some(self.index.blocks.get(&block_id)?.cumulative_work)
    }

    /// The height up to which a desktop wallet catching up treats coins as
    /// available: the validated height, or the top of the topmost run of at
    /// least [`WALLET_CATCH_UP_DEPTH`] blocks re-executed here, with at least
    /// that many times the reference work, above blocks that were each
    /// granted or re-executed here. It is the validated height while
    /// admission is halted, the engines failed, an unsettled record could
    /// not be written, an active block above the validated height is
    /// unsettled or was neither granted nor re-executed here, or the
    /// reference work is unknown, and always with the catch-up off.
    pub fn wallet_available_height(&self) -> Option<u64> {
        let validated = self.work_validated_height()?;
        let Some(gate) = self.work_gate.as_ref() else {
            return Some(validated);
        };
        let Some(catch_up) = gate.wallet_catch_up.as_ref() else {
            return Some(validated);
        };
        let view = self.refresh_coverage(gate, catch_up, Instant::now());
        Some(self.wallet_available_from(gate, catch_up, validated, &view))
    }

    fn wallet_available_from(
        &self,
        gate: &WorkGate,
        catch_up: &WalletCatchUp,
        validated: u64,
        view: &CoverageView,
    ) -> u64 {
        let tip = self.state.next_height().saturating_sub(1);
        let failed = gate.checker.as_ref().is_some_and(|checker| {
            checker.engine_state() == crate::honest_work::WorkEngineState::Failed
        });
        if validated >= tip
            || gate.halted()
            || failed
            || catch_up.store_failed()
            || self.wallet_frontier(gate, validated).is_some()
            || view.coverage.uncovered_floor > validated
            || view.w_ref.is_none()
        {
            return validated;
        }
        match view.best_run {
            Some((start, top)) if start > validated.saturating_add(1) => validated.max(top),
            _ => validated,
        }
    }

    /// Whether the run of re-executed blocks at the tip has enough blocks
    /// and enough work.
    fn wallet_top_run_qualifies(&self, catch_up: &WalletCatchUp, view: &CoverageView) -> bool {
        let tip = self.state.next_height().saturating_sub(1);
        view.top_run
            .filter(|run| run.top == tip)
            .zip(view.w_ref)
            .is_some_and(|(run, w_ref)| {
                let work = self
                    .active_cumulative_work(run.top)
                    .zip(self.active_cumulative_work(run.start.saturating_sub(1)))
                    .and_then(|(top, below)| top.checked_sub(below));
                run_qualifies(run.len(), work, w_ref, catch_up.depth())
            })
    }

    /// Whether the background check of stored blocks gives way at `now` to
    /// the blocks a desktop wallet catching up re-executes at its tip: the
    /// tip block was re-executed here, the run of such blocks it ends grew
    /// within [`TOP_RUN_STALL`] and started less than [`TOP_RUN_CAP`] ago,
    /// it does not qualify yet but could, and coins are not yet available up
    /// to the tip.
    pub(crate) fn wallet_burial_pending(&self, now: Instant) -> bool {
        let Some(gate) = self.work_gate.as_ref() else {
            return false;
        };
        let (Some(catch_up), Some(validated)) =
            (gate.wallet_catch_up.as_ref(), self.work_validated_height())
        else {
            return false;
        };
        let view = self.refresh_coverage(gate, catch_up, now);
        self.wallet_burial_pending_from(gate, catch_up, validated, &view, now)
    }

    fn wallet_burial_pending_from(
        &self,
        gate: &WorkGate,
        catch_up: &WalletCatchUp,
        validated: u64,
        view: &CoverageView,
        now: Instant,
    ) -> bool {
        let tip = self.state.next_height().saturating_sub(1);
        let ready = gate.checker.as_ref().is_some_and(|checker| {
            checker.engine_state() == crate::honest_work::WorkEngineState::Ready
        });
        let Some(run) = view.top_run.filter(|run| run.top == tip) else {
            return false;
        };
        ready
            && !gate.halted()
            && !catch_up.store_failed()
            && view.w_ref.is_some()
            && self.wallet_frontier(gate, validated).is_none()
            && view.coverage.uncovered_floor <= validated
            && self.wallet_available_from(gate, catch_up, validated, view) < tip
            && !self.wallet_top_run_qualifies(catch_up, view)
            && now.saturating_duration_since(run.last_growth) <= TOP_RUN_STALL
            && now.saturating_duration_since(run.first_seen) < TOP_RUN_CAP
    }

    /// The catch-up part of the status of a desktop wallet with the
    /// catch-up on, at `now`.
    fn wallet_catch_up_status(
        &self,
        gate: &WorkGate,
        catch_up: &WalletCatchUp,
        validated: u64,
        now: Instant,
    ) -> WalletCatchUpStatus {
        let tip = self.state.next_height().saturating_sub(1);
        let view = self.refresh_coverage(gate, catch_up, now);
        let available = self.wallet_available_from(gate, catch_up, validated, &view);
        let (highest_view, sources_answering) = catch_up.fresh_views(now);
        let top_run_len = view
            .top_run
            .filter(|run| run.top == tip)
            .map_or(0, |run| run.len());
        let depth = catch_up.depth();
        let facts = CatchUpFacts {
            tip,
            validated,
            available,
            depth,
            highest_view,
            release_fresh: catch_up.checkpoint_time().map(|time_c| {
                catch_up::release_fresh_at(crate::unix_time_seconds().ok(), Some(time_c))
            }),
            reference_known: view.w_ref.is_some(),
            probe_hit_fresh: catch_up.probe_hit_fresh(now),
            tip_granted: self
                .active_block_id_at_height(tip)
                .is_some_and(|block_id| catch_up.recorded_grant(&block_id)),
            burial_pending: self.wallet_burial_pending_from(gate, catch_up, validated, &view, now),
            top_run_len,
            top_run_work_ok: self.wallet_top_run_qualifies(catch_up, &view),
            uncovered_floor: view.coverage.uncovered_floor,
        };
        let (state, reason, blocks_left) = catch_up_row(&facts);
        WalletCatchUpStatus {
            state,
            reason,
            available_height: available,
            blocks_left,
            newest_checked: top_run_len.min(depth),
            newest_needed: depth,
            sources_answering,
            granted_above_available: view.coverage.top_granted > available,
        }
    }

    /// The lowest active block above `validated` recorded unsettled.
    fn wallet_frontier(&self, gate: &WorkGate, validated: u64) -> Option<(u64, [u8; 32])> {
        let store = lock(gate.store.as_ref()?);
        store
            .unsettled_blocks()
            .filter(|(height, block_id)| {
                *height > validated && self.active_block_id_at_height(*height) == Some(*block_id)
            })
            .min_by_key(|(height, _)| *height)
    }

    /// Whether this node knows anything of `block` that rules out admitting
    /// it without an engine run: a work-status or unsettled record, a
    /// remembered refusal (stale or not), or a memoized result that differs
    /// from its claim.
    fn wallet_block_known(&self, gate: &WorkGate, block: &Block) -> bool {
        let block_id = block.block_id();
        gate.store.as_ref().is_some_and(|store| {
            let store = lock(store);
            store.status(&block_id).is_some() || store.is_unsettled(&block_id)
        }) || self.rejected_proof_ids.contains(&block_id)
            || self.work_rejections.contains_key(&block_id)
            || gate
                .claim(block)
                .zip(gate.checker.as_ref())
                .is_some_and(|(claim, checker)| checker.memo_differs(claim))
    }

    /// Whether a grant of `block` may be used by its admission and commit
    /// now: it still extends the tip, nothing known rules it out, and grants
    /// are ready.
    fn wallet_grant_usable(
        &self,
        gate: &WorkGate,
        catch_up: &WalletCatchUp,
        block: &Block,
    ) -> bool {
        block.challenge.previous_block == self.state.tip()
            && !self.wallet_block_known(gate, block)
            && self.wallet_grant_ready(gate, catch_up)
    }

    /// Whether a grant may be given or used now: admission is not halted,
    /// the engines are ready, no active block above the validated height is
    /// unsettled, no unsettled record failed to be written, and the grant
    /// file still takes records.
    fn wallet_grant_ready(&self, gate: &WorkGate, catch_up: &WalletCatchUp) -> bool {
        !gate.halted()
            && !catch_up.store_failed()
            && !catch_up.grant_file_stopped()
            && gate.checker.as_ref().is_some_and(|checker| {
                checker.engine_state() == crate::honest_work::WorkEngineState::Ready
            })
            && self
                .work_validated_height()
                .is_some_and(|validated| self.wallet_frontier(gate, validated).is_none())
    }

    /// Grants `block` at `height`, fetched in a catch-up session `follow`,
    /// admission without an engine run if it meets every condition, and
    /// records the grant. Otherwise says which condition it failed first.
    fn grant_wallet_follow(
        &self,
        gate: &WorkGate,
        catch_up: &WalletCatchUp,
        block: &Block,
        height: u64,
        follow: CatchUpFollow,
    ) -> Result<(), GrantRefusal> {
        let now = Instant::now();
        let block_id = block.block_id();
        if !catch_up.vouched_by_other(&block_id, follow.source, height, now) {
            return Err(GrantRefusal::NotVouched);
        }
        if block.challenge.previous_block != self.state.tip() {
            return Err(GrantRefusal::NotTipExtension);
        }
        if self.wallet_block_known(gate, block) {
            return Err(GrantRefusal::Known);
        }
        let w_ref = self.refresh_coverage(gate, catch_up, now).w_ref;
        let work = cmfd_consensus::block_work(block.challenge.target).ok();
        if !w_ref
            .zip(work)
            .is_some_and(|(w_ref, work)| catch_up::easing_ok(work, w_ref))
        {
            return Err(GrantRefusal::Easing);
        }
        if !self.wallet_grant_ready(gate, catch_up) {
            return Err(GrantRefusal::NotReady);
        }
        if !catch_up::release_fresh_at(crate::unix_time_seconds().ok(), catch_up.checkpoint_time())
        {
            return Err(GrantRefusal::ReleaseStale);
        }
        let tip = self.state.next_height().saturating_sub(1);
        let (prune_height, keep) = (self.prune_height(), self.prune_keep_blocks());
        if !catch_up::prune_lag_ok(tip, prune_height, keep) {
            if catch_up.first_prune_lag_refusal() {
                tracing::warn!(
                    target: "work_rule::catch_up",
                    tip,
                    prune_height = prune_height.unwrap_or(0),
                    keep = keep.unwrap_or(0),
                    "blocks are checked before they are admitted until the pruner catches up"
                );
            }
            return Err(GrantRefusal::PruneLag);
        }
        catch_up.grant(height, block_id, now).map_err(|error| {
            if catch_up.first_grant_file_failure() {
                tracing::warn!(
                    target: "work_rule::catch_up",
                    height,
                    block_id = %hex::encode(block_id),
                    %error,
                    "a catch-up grant could not be recorded; blocks are checked instead until one can"
                );
            }
            GrantRefusal::GrantFile
        })
    }

    /// Cuts a relay inventory of a desktop wallet catching up before the
    /// first block above the checkpoint that has no verified record, so the
    /// wallet relays only blocks it re-executed. Unchanged otherwise.
    pub(crate) fn limit_wallet_relay_inventory(&self, inventory: &mut Vec<[u8; 32]>) {
        let Some(gate) = self.work_gate.as_ref() else {
            return;
        };
        let (Some(_), Some(store)) = (gate.wallet_catch_up.as_ref(), gate.store.as_ref()) else {
            return;
        };
        let checkpoint = gate.rule.checkpoint_height();
        let store = lock(store);
        if let Some(position) = inventory.iter().position(|block_id| {
            self.index
                .blocks
                .get(block_id)
                .is_none_or(|entry| entry.height() > checkpoint)
                && store.status(block_id) != Some(WorkStatus::Verified)
        }) {
            inventory.truncate(position);
        }
    }
}

/// The coverage of a desktop wallet catching up, read from this node's
/// active chain, its work-status store and the grant records.
struct WalletCoverageIndex<'a> {
    node: &'a Node,
    store: &'a WorkStatusStore,
    catch_up: &'a WalletCatchUp,
}

impl CoverageIndex for WalletCoverageIndex<'_> {
    fn active(&self, height: u64) -> Option<[u8; 32]> {
        self.node.active_block_id_at_height(height)
    }

    fn verified(&self, block_id: &[u8; 32]) -> bool {
        self.store.status(block_id) == Some(WorkStatus::Verified)
    }

    fn provisional(&self, block_id: &[u8; 32]) -> bool {
        self.store.is_provisional(block_id)
    }

    fn granted(&self, block_id: &[u8; 32]) -> bool {
        self.catch_up.recorded_grant(block_id)
    }

    fn cumulative_work(&self, height: u64) -> Option<primitive_types::U512> {
        self.node.active_cumulative_work(height)
    }
}

/// Scripted work engines for admission tests on Devnet.
#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::time::{Duration, Instant};

    use cmfd_consensus::{Block, BlockProof, ForgeMatrixV4WorkRule};

    use crate::Node;
    use crate::honest_work::{
        HonestWorkChecker, WORK_KNOWN_ANSWERS, WorkCancel, WorkEngine, WorkEngineError,
        WorkEngineKind,
    };

    /// An engine that reproduces the known answers and answers each block
    /// challenge as scripted: honest (the block's own final-activation
    /// digest), dishonest (a different one), a queued error, or a job that
    /// waits on a barrier and then runs until it is cancelled.
    pub(crate) struct ScriptedEngine {
        kind: WorkEngineKind,
        answers: Mutex<HashMap<[u8; 32], [u8; 32]>>,
        errors: Mutex<VecDeque<WorkEngineError>>,
        /// The next block job's barrier, and how long it runs before it
        /// answers if it is not cancelled (without a limit it must be).
        hold: Mutex<Option<(Arc<Barrier>, Option<Duration>)>>,
        during_next: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        block_calls: AtomicUsize,
        block_challenges: Mutex<Vec<[u8; 32]>>,
        known_answer_calls: AtomicUsize,
        known_answers_unreadable: AtomicBool,
        known_answers_cancellable: AtomicBool,
    }

    impl ScriptedEngine {
        pub(crate) fn new(kind: WorkEngineKind) -> Arc<Self> {
            Arc::new(Self {
                kind,
                answers: Mutex::new(HashMap::new()),
                errors: Mutex::new(VecDeque::new()),
                hold: Mutex::new(None),
                during_next: Mutex::new(None),
                block_calls: AtomicUsize::new(0),
                block_challenges: Mutex::new(Vec::new()),
                known_answer_calls: AtomicUsize::new(0),
                known_answers_unreadable: AtomicBool::new(false),
                known_answers_cancellable: AtomicBool::new(false),
            })
        }

        /// The reference proof's challenge and final-activation digests.
        pub(crate) fn digests(block: &Block) -> ([u8; 32], [u8; 32]) {
            let BlockProof::V2Reference(proof) = &block.proof else {
                panic!("Devnet blocks carry a reference proof");
            };
            (proof.challenge_digest, proof.final_activation_digest)
        }

        /// Answers `block`'s challenge with its own digest, or a different
        /// one.
        pub(crate) fn answer(&self, block: &Block, honest: bool) {
            let (challenge, mut digest) = Self::digests(block);
            if !honest {
                digest[0] ^= 1;
            }
            self.answers.lock().unwrap().insert(challenge, digest);
        }

        pub(crate) fn answer_challenge(&self, challenge: [u8; 32], digest: [u8; 32]) {
            self.answers.lock().unwrap().insert(challenge, digest);
        }

        /// Known answers fail as a model read that failed would.
        pub(crate) fn fail_known_answers(&self) {
            self.known_answers_unreadable.store(true, Ordering::SeqCst);
        }

        /// Known answers are read again, after
        /// [`fail_known_answers`](Self::fail_known_answers).
        pub(crate) fn restore_known_answers(&self) {
            self.known_answers_unreadable.store(false, Ordering::SeqCst);
        }

        /// A known answer that is asked for once its job is cancelled stops,
        /// as a real engine's does within a layer.
        pub(crate) fn cancellable_known_answers(&self) {
            self.known_answers_cancellable.store(true, Ordering::SeqCst);
        }

        pub(crate) fn fail_next(&self, error: WorkEngineError) {
            self.errors.lock().unwrap().push_back(error);
        }

        /// The next block job waits on the returned barrier, then runs until
        /// it is cancelled.
        pub(crate) fn hold_next(&self) -> Arc<Barrier> {
            let barrier = Arc::new(Barrier::new(2));
            *self.hold.lock().unwrap() = Some((barrier.clone(), None));
            barrier
        }

        /// The next block job waits on the returned barrier, then runs for
        /// `run` and answers, unless it is cancelled first.
        pub(crate) fn hold_next_for(&self, run: Duration) -> Arc<Barrier> {
            let barrier = Arc::new(Barrier::new(2));
            *self.hold.lock().unwrap() = Some((barrier.clone(), Some(run)));
            barrier
        }

        /// Runs `action` inside the next block job, before it answers.
        pub(crate) fn during_next(&self, action: impl FnOnce() + Send + 'static) {
            *self.during_next.lock().unwrap() = Some(Box::new(action));
        }

        /// Jobs run for block challenges (known answers not counted).
        pub(crate) fn block_calls(&self) -> usize {
            self.block_calls.load(Ordering::SeqCst)
        }

        /// The challenges of the jobs run for blocks, in order.
        pub(crate) fn block_challenges(&self) -> Vec<[u8; 32]> {
            self.block_challenges.lock().unwrap().clone()
        }

        /// Known-answer jobs run, whether or not they passed.
        pub(crate) fn known_answer_calls(&self) -> usize {
            self.known_answer_calls.load(Ordering::SeqCst)
        }

        fn run(
            &self,
            challenge: [u8; 32],
            cancel: &WorkCancel<'_>,
        ) -> Result<[u8; 32], WorkEngineError> {
            if let Some(answer) = WORK_KNOWN_ANSWERS
                .iter()
                .find(|answer| answer.challenge_digest == challenge)
            {
                self.known_answer_calls.fetch_add(1, Ordering::SeqCst);
                if self.known_answers_unreadable.load(Ordering::SeqCst) {
                    return Err(WorkEngineError::Failed("model data unreadable".to_owned()));
                }
                if self.known_answers_cancellable.load(Ordering::SeqCst) && cancel() {
                    return Err(WorkEngineError::Cancelled);
                }
                return Ok(answer.final_activation_digest);
            }
            self.block_calls.fetch_add(1, Ordering::SeqCst);
            self.block_challenges.lock().unwrap().push(challenge);
            if let Some(error) = self.errors.lock().unwrap().pop_front() {
                return Err(error);
            }
            let during = self.during_next.lock().unwrap().take();
            if let Some(action) = during {
                action();
            }
            let hold = self.hold.lock().unwrap().take();
            if let Some((barrier, run)) = hold {
                barrier.wait();
                let started = Instant::now();
                let deadline = started + Duration::from_secs(20);
                loop {
                    if cancel() {
                        return Err(WorkEngineError::Cancelled);
                    }
                    if run.is_some_and(|run| started.elapsed() >= run) {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "the held job was never cancelled"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            self.answers
                .lock()
                .unwrap()
                .get(&challenge)
                .copied()
                .ok_or_else(|| WorkEngineError::Failed("no scripted answer".to_owned()))
        }
    }

    impl WorkEngine for ScriptedEngine {
        fn kind(&self) -> WorkEngineKind {
            self.kind
        }

        fn final_activation_digest(
            &self,
            challenge_digest: [u8; 32],
            _worker: usize,
            _authenticate: bool,
        ) -> Result<[u8; 32], WorkEngineError> {
            self.run(challenge_digest, &|| false)
        }

        fn final_activation_digest_cancellable(
            &self,
            challenge_digest: [u8; 32],
            _worker: usize,
            _authenticate: bool,
            cancel: &WorkCancel<'_>,
        ) -> Result<[u8; 32], WorkEngineError> {
            self.run(challenge_digest, cancel)
        }
    }

    /// A rule whose checkpoint is the virtual genesis: every block is checked.
    pub(crate) fn rule_from_genesis(node: &Node) -> ForgeMatrixV4WorkRule {
        ForgeMatrixV4WorkRule::with_pinned_heights(0, node.params.genesis_hash, []).unwrap()
    }

    /// Installs `rule` (by default [`rule_from_genesis`]) and a checker over
    /// the given engines, qualified.
    pub(crate) fn install(
        node: &mut Node,
        rule: Option<ForgeMatrixV4WorkRule>,
        cpu: Option<Arc<ScriptedEngine>>,
        gpu: Option<Arc<ScriptedEngine>>,
    ) -> Arc<HonestWorkChecker> {
        let rule = rule.unwrap_or_else(|| rule_from_genesis(node));
        node.install_work_rule_for_test(Some(rule));
        let checker = Arc::new(
            HonestWorkChecker::new(
                cpu.map(|engine| engine as Arc<dyn WorkEngine>),
                gpu.map(|engine| engine as Arc<dyn WorkEngine>),
                false,
            )
            .unwrap(),
        );
        checker.run_known_answer_tests();
        node.install_work_checker(Arc::clone(&checker)).unwrap();
        checker
    }

    /// Reports `mode` as the CPU engine's bank mode, as installing the real
    /// engines does.
    pub(crate) fn set_bank_mode(node: &mut Node, mode: super::WorkBankMode) {
        node.work_gate
            .as_mut()
            .expect("a work rule is installed")
            .bank = Some(mode);
    }

    /// Puts a node opened with the real model bank under
    /// [`rule_from_genesis`], whatever checkpoint the release pins, so each
    /// block it admits has its work re-executed. Installs `checker` if one is
    /// given (another node's, to reuse its results), or else the CPU engine
    /// over this node's bank, qualified against the known answers, with
    /// `CMFD_WORK_THREADS` threads (6 by default). For the opt-in tests that
    /// admit preserved ProductionV4 blocks.
    #[cfg(feature = "production-v4")]
    pub(crate) fn check_work_from_genesis(
        node: &mut Node,
        checker: Option<&Arc<HonestWorkChecker>>,
    ) -> Arc<HonestWorkChecker> {
        use super::WorkBankMode;
        use crate::honest_work::{WorkEngineHealth, WorkThreadPriority};

        node.install_work_rule_for_test(Some(rule_from_genesis(node)));
        if let Some(checker) = checker {
            node.install_work_checker(Arc::clone(checker)).unwrap();
            return Arc::clone(checker);
        }
        let threads = std::env::var("CMFD_WORK_THREADS")
            .map(|value| value.parse().expect("CMFD_WORK_THREADS is a number"))
            .unwrap_or(6);
        let (checker, _) = node
            .install_work_engines(
                threads,
                WorkThreadPriority::Normal,
                WorkBankMode::Streamed,
                None,
            )
            .unwrap()
            .expect("the node has a work rule");
        assert_eq!(
            checker.run_known_answer_tests().cpu,
            Some(WorkEngineHealth::Ready),
            "the CPU work engine reproduces its known answer"
        );
        checker
    }

    /// Halts admission, or ends a halt, as a halt marker read at startup
    /// would.
    pub(crate) fn set_halted(node: &Node, halted: bool) {
        node.work_gate
            .as_ref()
            .expect("work rule installed")
            .halted
            .store(halted, Ordering::Release);
    }

    /// Admissions waiting for the work lane, as (normal, priority).
    pub(crate) fn lane_waiters(node: &Node) -> (usize, usize) {
        let telemetry = node
            .work_gate
            .as_ref()
            .expect("work rule installed")
            .lane
            .telemetry()
            .unwrap();
        (telemetry.normal.queued, telemetry.priority.queued)
    }

    /// Recorded verified and invalid blocks.
    pub(crate) fn recorded(node: &Node) -> (usize, usize) {
        let store = node
            .work_gate
            .as_ref()
            .and_then(|gate| gate.store.as_ref())
            .expect("work-status store is open");
        let store = store.lock().unwrap();
        (store.verified_count(), store.invalid_count())
    }

    /// Records `block_id` verified, as a matching work check would.
    pub(crate) fn mark_verified(node: &Node, height: u64, block_id: [u8; 32]) {
        let store = node
            .work_gate
            .as_ref()
            .and_then(|gate| gate.store.as_ref())
            .expect("work-status store is open");
        store
            .lock()
            .unwrap()
            .mark_verified(height, block_id)
            .unwrap();
    }

    /// Provisionally verified blocks, as (height, block id), lowest first.
    pub(crate) fn provisional(node: &Node) -> Vec<(u64, [u8; 32])> {
        let store = node
            .work_gate
            .as_ref()
            .and_then(|gate| gate.store.as_ref())
            .expect("work-status store is open");
        store.lock().unwrap().provisional_blocks()
    }

    /// Lets every one-engine refusal counted against a peer address leave
    /// its window, as if [`LONE_REFUSAL_WINDOW`](super::LONE_REFUSAL_WINDOW)
    /// had passed.
    pub(crate) fn end_lone_refusal_window(node: &Node) {
        node.work_gate
            .as_ref()
            .expect("work rule installed")
            .lone_refusals
            .lock()
            .unwrap()
            .by_sender
            .clear();
    }

    /// The one-engine refusals counted against `sender` in the window.
    pub(crate) fn lone_refusals(node: &Node, sender: std::net::IpAddr) -> usize {
        node.work_gate
            .as_ref()
            .expect("work rule installed")
            .lone_refusals
            .lock()
            .unwrap()
            .by_sender
            .get(&sender)
            .map_or(0, VecDeque::len)
    }

    /// Counts `block_id` as refused on one engine's word for `sender`, as if
    /// its challenge were its id.
    pub(crate) fn count_lone_refusal(node: &Node, sender: std::net::IpAddr, block_id: [u8; 32]) {
        node.work_gate
            .as_ref()
            .expect("work rule installed")
            .charge_lone_refusal(Some(sender), block_id, block_id);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::test_support::{ScriptedEngine, install, provisional, recorded, rule_from_genesis};
    use super::*;
    use crate::honest_work::store::write_work_halt;
    use crate::honest_work::{
        ConfirmedWorkMismatch, WorkAlarmCounts, WorkEngineError, WorkEngineHealth, WorkEngineKind,
    };
    use crate::tests::{clean_test_dir, test_dir};
    use crate::{
        DEVNET_PROFILE, RemoteProofPeerId, default_miner_destination, submit_shared_block,
        submit_shared_peer_block_cancellable, submit_shared_tip_block, unix_time_seconds,
    };
    use std::path::PathBuf;
    use std::thread;
    use std::time::Instant;

    pub(crate) fn devnet(label: &str) -> (PathBuf, Node) {
        let path = test_dir(label);
        clean_test_dir(&path);
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        (path, node)
    }

    /// Mines `count` blocks on `source`, one second apart from `start`.
    pub(crate) fn mine(source: &mut Node, count: u64, start: u64) -> Vec<Block> {
        (0..count)
            .map(|offset| {
                source
                    .mine_once(default_miner_destination(), start + offset, 10_000)
                    .unwrap()
            })
            .collect()
    }

    pub(crate) fn shared(node: Node) -> Arc<Mutex<Node>> {
        Arc::new(Mutex::new(node))
    }

    pub(crate) fn cpu() -> Arc<ScriptedEngine> {
        ScriptedEngine::new(WorkEngineKind::Cpu)
    }

    pub(crate) fn gpu() -> Arc<ScriptedEngine> {
        ScriptedEngine::new(WorkEngineKind::Gpu)
    }

    #[test]
    fn auto_holds_the_bank_resident_only_when_it_fits_beside_the_headroom() {
        let layers = 6 << 30;
        let needed = layers + RESIDENT_WORK_BANK_HEADROOM_BYTES;
        assert_eq!(
            auto_work_bank_mode(layers, Some(needed)),
            WorkBankMode::Resident
        );
        assert_eq!(
            auto_work_bank_mode(layers, Some(needed - 1)),
            WorkBankMode::Streamed
        );
        assert_eq!(auto_work_bank_mode(layers, None), WorkBankMode::Streamed);
        assert_eq!(
            auto_work_bank_mode(u64::MAX, Some(u64::MAX)),
            WorkBankMode::Streamed
        );
        if cfg!(any(target_os = "linux", windows)) {
            assert!(available_memory_bytes().is_some_and(|bytes| bytes > 0));
        }
    }

    #[test]
    fn the_memory_probe_honours_each_cgroup_limit_above_the_node() {
        const GIB: u64 = 1 << 30;
        let headroom = |cgroup: &str, files: &[(&str, String)]| {
            let files = files
                .iter()
                .map(|(path, contents)| (path.to_string(), contents.clone()))
                .collect::<std::collections::HashMap<_, _>>();
            cgroup_memory_headroom(cgroup, |path| files.get(path).cloned())
        };
        let bytes = |gib: u64| format!("{}\n", gib * GIB);
        let mut files = vec![
            (
                "/sys/fs/cgroup/system.slice/cmfd.service/memory.max",
                bytes(8),
            ),
            (
                "/sys/fs/cgroup/system.slice/cmfd.service/memory.high",
                "max\n".to_owned(),
            ),
            (
                "/sys/fs/cgroup/system.slice/cmfd.service/memory.current",
                bytes(3),
            ),
            (
                "/sys/fs/cgroup/system.slice/cmfd.service/memory.stat",
                format!("anon {}\nactive_file 5\ninactive_file {}\n", 2 * GIB, GIB),
            ),
            ("/sys/fs/cgroup/system.slice/memory.max", "max\n".to_owned()),
        ];
        let cgroup = "0::/system.slice/cmfd.service\n";
        // The unit's limit less what it holds, not counting inactive cache.
        assert_eq!(headroom(cgroup, &files), Some(6 * GIB));
        // A lower memory.high counts as the limit.
        files[1].1 = bytes(5);
        assert_eq!(headroom(cgroup, &files), Some(3 * GIB));
        // A tighter limit on an ancestor wins.
        files[4].1 = bytes(4);
        files.push(("/sys/fs/cgroup/system.slice/memory.current", bytes(3)));
        assert_eq!(headroom(cgroup, &files), Some(GIB));
        // No limit anywhere.
        assert_eq!(
            headroom(
                "0::/user.slice\n",
                &[("/sys/fs/cgroup/user.slice/memory.max", "max\n".to_owned())]
            ),
            None
        );
        assert_eq!(headroom("", &[]), None);
        // Inside a container the mount root is the container's cgroup.
        assert_eq!(
            headroom(
                "0::/\n",
                &[
                    ("/sys/fs/cgroup/memory.max", bytes(4)),
                    ("/sys/fs/cgroup/memory.current", bytes(1)),
                ]
            ),
            Some(3 * GIB)
        );
        // cgroup v1, where the host path is not visible in the container.
        let v1 = "12:memory:/docker/abc\n3:cpu,cpuacct:/docker/abc\n0::/\n";
        assert_eq!(
            headroom(
                v1,
                &[
                    ("/sys/fs/cgroup/memory/memory.limit_in_bytes", bytes(4)),
                    ("/sys/fs/cgroup/memory/memory.usage_in_bytes", bytes(2)),
                    (
                        "/sys/fs/cgroup/memory/memory.stat",
                        format!("cache 9\ninactive_file 7\ntotal_inactive_file {GIB}\n"),
                    ),
                ]
            ),
            Some(3 * GIB)
        );
        // v1 reports "no limit" as a huge number, which never binds.
        assert!(
            headroom(
                v1,
                &[(
                    "/sys/fs/cgroup/memory/memory.limit_in_bytes",
                    "9223372036854771712\n".to_owned()
                )]
            )
            .is_some_and(|headroom| headroom > 1 << 60)
        );
    }

    #[cfg(feature = "production-v4")]
    #[test]
    fn a_bank_that_does_not_fit_in_memory_is_reported_as_memory_not_identity() {
        use cmfd_consensus::ForgeMatrixV4ExecutionError;
        let dir = std::path::Path::new("bank/MODEL-V2.bank");
        let error = work_bank_error(
            ForgeMatrixV4ExecutionError::ResidentAllocation { bytes: 7 },
            dir,
        );
        assert!(
            matches!(error, NodeError::ProductionV4WorkBankMemory { bytes: 7 }),
            "{error}"
        );
        assert!(error.to_string().contains("--work-bank streamed"));
        for error in [
            ForgeMatrixV4ExecutionError::BankIo(std::io::Error::other("gone")),
            ForgeMatrixV4ExecutionError::LayerRead {
                layer: 2,
                source: std::io::Error::other("gone"),
            },
        ] {
            let error = work_bank_error(error, dir);
            assert!(
                matches!(
                    error,
                    NodeError::Io {
                        operation: "read the model bank for the work engine",
                        ref path,
                        ..
                    } if path == dir
                ),
                "{error}"
            );
        }
        for error in [
            ForgeMatrixV4ExecutionError::LayerAuthentication { layer: 1 },
            ForgeMatrixV4ExecutionError::BankLength {
                actual: 1,
                expected: 2,
            },
        ] {
            let error = work_bank_error(error, dir);
            assert!(
                matches!(
                    error,
                    NodeError::ProductionV4ArtifactIdentityMismatch("model bank")
                ),
                "{error}"
            );
        }
    }

    #[cfg(feature = "production-v4")]
    #[test]
    fn installed_engines_report_the_bank_mode_and_refuse_a_bank_changed_since_it_opened() {
        use crate::honest_work::WorkThreadPriority;
        use cmfd_consensus::{
            ForgeMatrixV4BankIdentity, SmallModelBankFixture, build_small_model_bank,
            verify_model_bank_and_retain_base_input_and_layer_roots,
        };
        use std::io::{Seek, SeekFrom, Write};

        let (batch, dimension, layers) = (4usize, 8usize, 3usize);
        let pattern = |seed: usize, len: usize| {
            (0..len)
                .map(|index| ((index * 31 + seed * 17) % 251) as u8)
                .collect::<Vec<_>>()
        };
        let base = pattern(1, batch * dimension);
        let weights = (0..layers)
            .map(|layer| pattern(layer + 2, dimension * dimension))
            .collect::<Vec<_>>();
        let weight_slices = weights.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let built = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: dimension as u32,
            batch: batch as u32,
            base_input: &base,
            layers: &weight_slices,
            pcs_parameter_digest: [0x51; 32],
            pcs_commitment_root: [0xa7; 32],
        })
        .unwrap();
        let layer_bytes = built.manifest.payload_bytes - built.manifest.base_input_bytes;
        // A devnet node under the work rule, backed by the small bank as a
        // node that authenticated it when it opened would be.
        let open = |label: &str| {
            let (path, mut node) = devnet(label);
            let bank = path.join("small.bank");
            std::fs::write(&bank, &built.bytes).unwrap();
            let (base_input, layer_roots) =
                verify_model_bank_and_retain_base_input_and_layer_roots(
                    std::fs::File::open(&bank).unwrap(),
                    &built.manifest,
                )
                .unwrap();
            node.work_bank = Some(WorkBank {
                file: std::fs::File::open(&bank).unwrap(),
                path: bank.clone(),
                identity: ForgeMatrixV4BankIdentity {
                    manifest: built.manifest,
                    base_input: Arc::from(base_input),
                    layer_roots: Arc::from(layer_roots),
                },
            });
            node.install_work_rule_for_test(Some(rule_from_genesis(&node)));
            (path, bank, node)
        };
        let engines = |node: &mut Node, mode| {
            node.install_work_engines(1, WorkThreadPriority::Normal, mode, None)
        };

        // Auto's choice depends on the memory free when the engines are
        // installed, which can change between two reads, so it may be either.
        for (label, mode, held) in [
            (
                "work-bank-resident",
                WorkBankMode::Resident,
                &["resident"][..],
            ),
            (
                "work-bank-streamed",
                WorkBankMode::Streamed,
                &["streamed"][..],
            ),
            (
                "work-bank-auto",
                WorkBankMode::Auto,
                &["resident", "streamed"][..],
            ),
        ] {
            let (path, _, mut node) = open(label);
            assert_eq!(node.work_rule_status().unwrap().bank, None);
            engines(&mut node, mode)
                .unwrap()
                .expect("the node has a work rule");
            let status = node.work_rule_status().unwrap();
            assert!(status.enforced, "{label}");
            assert_eq!(status.engines, Some("cpu"), "{label}");
            assert!(
                status.bank.is_some_and(|bank| held.contains(&bank)),
                "{label}"
            );
            drop(node);
            clean_test_dir(&path);
        }

        // A layer that changed on disk after the node authenticated the bank
        // refuses a resident load, and no engine is installed.
        let (path, bank, mut node) = open("work-bank-changed");
        let mut file = std::fs::OpenOptions::new().write(true).open(&bank).unwrap();
        let in_first_layer = built.bytes.len() as u64 - layer_bytes + 5;
        file.seek(SeekFrom::Start(in_first_layer)).unwrap();
        file.write_all(&[built.bytes[in_first_layer as usize] ^ 1])
            .unwrap();
        drop(file);
        let error = engines(&mut node, WorkBankMode::Resident)
            .err()
            .expect("a changed layer refuses the resident load");
        assert!(
            matches!(
                error,
                NodeError::ProductionV4ArtifactIdentityMismatch("model bank")
            ),
            "{error}"
        );
        assert!(node.work_checker_missing());
        assert_eq!(node.work_rule_status().unwrap().bank, None);
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn every_match_is_recorded_verified_and_stored_blocks_are_never_re_executed() {
        let (source_path, mut source) = devnet("work-gate-source-a");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 4, now);
        let (path, mut node) = devnet("work-gate-match");
        let engine = cpu();
        for block in &chain {
            engine.answer(block, true);
        }
        install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        for (offset, block) in chain[..3].iter().enumerate() {
            submit_shared_block(&node, block.clone(), now + offset as u64).unwrap();
        }
        assert_eq!(engine.block_calls(), 3);
        assert_eq!(recorded(&node.lock().unwrap()), (3, 0));
        assert_eq!(node.lock().unwrap().work_validated_height(), Some(3));

        // The commit refuses a block above the checkpoint with no verdict,
        // whichever path reaches it.
        assert!(matches!(
            node.lock().unwrap().submit_block(chain[3].clone(), now + 3),
            Err(NodeError::WorkCheckRequired)
        ));
        submit_shared_block(&node, chain[3].clone(), now + 3).unwrap();
        assert_eq!(engine.block_calls(), 4);

        // A heavier branch from genesis: each new block is checked once, and
        // the reorganization replays stored blocks without re-executing any.
        let (fork_path, mut fork) = devnet("work-gate-fork-a");
        let branch = mine(&mut fork, 5, now + 100);
        for block in &branch {
            engine.answer(block, true);
        }
        for (offset, block) in branch.iter().enumerate() {
            submit_shared_block(&node, block.clone(), now + 100 + offset as u64).unwrap();
        }
        assert_eq!(engine.block_calls(), 9);
        assert_eq!(node.lock().unwrap().state.tip(), branch[4].block_id());
        assert_eq!(recorded(&node.lock().unwrap()), (9, 0));
        // Followed from the fork point on the new branch.
        assert_eq!(node.lock().unwrap().work_validated_height(), Some(5));

        // After a restart the verified set is read back; startup replay runs
        // no engine.
        drop(node);
        let mut reopened = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        install(&mut reopened, None, Some(engine.clone()), None);
        assert_eq!(recorded(&reopened), (9, 0));
        assert_eq!(reopened.work_validated_height(), Some(5));
        assert_eq!(engine.block_calls(), 9);
        drop((reopened, source, fork));
        for path in [path, source_path, fork_path] {
            clean_test_dir(&path);
        }
    }

    #[test]
    fn a_data_directory_opened_under_a_rule_replays_without_any_engine() {
        let (path, mut node) = devnet("work-gate-open-under-rule");
        let now = unix_time_seconds().unwrap();
        // Stored before the release: blocks above the checkpoint, no
        // work-status file.
        let stored = mine(&mut node, 4, now);
        let rule = rule_from_genesis(&node);
        drop(node);
        assert!(!path.join(WORK_STATUS_FILE).exists());

        OPEN_WITH_WORK_RULE.with(|slot| *slot.borrow_mut() = Some(rule));
        let opened = Node::open_with_profile(&path, DEVNET_PROFILE);
        OPEN_WITH_WORK_RULE.with(|slot| *slot.borrow_mut() = None);
        let mut node = opened.unwrap();
        assert!(
            node.work_gate
                .as_ref()
                .is_some_and(|gate| gate.checker.is_none() && gate.store.is_none()),
            "the rule applied from the start, with no engine to call"
        );
        assert_eq!(node.state.tip(), stored[3].block_id());

        let engine = cpu();
        let checker = Arc::new(
            HonestWorkChecker::new(
                Some(engine.clone() as Arc<dyn crate::honest_work::WorkEngine>),
                None,
                false,
            )
            .unwrap(),
        );
        checker.run_known_answer_tests();
        node.install_work_checker(checker).unwrap();
        assert_eq!(engine.block_calls(), 0);
        assert_eq!(recorded(&node), (0, 0));
        drop(node);
        clean_test_dir(&path);
    }

    #[test]
    fn a_single_engine_mismatch_is_refused_without_any_durable_record() {
        let (source_path, mut source) = devnet("work-gate-source-b");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 2, now);
        let (path, mut node) = devnet("work-gate-own-engine");
        let engine = cpu();
        engine.answer(&chain[0], false);
        let checker = install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        let block_id = chain[0].block_id();

        let error = submit_shared_block(&node, chain[0].clone(), now).unwrap_err();
        assert!(matches!(error, NodeError::WorkMismatchUnconfirmed(id) if id == block_id));
        let client = error.client_error();
        assert_eq!(
            (client.code, client.status, client.retryable),
            ("work_mismatch_unconfirmed", 422, false)
        );
        assert!(
            !crate::is_remote_peer_proof_failure(&error),
            "starts no cooldown for the sender"
        );
        assert_eq!(engine.block_calls(), 1);
        assert_eq!(checker.alarms().own_engine_mismatches, 1);
        {
            let node = node.lock().unwrap();
            assert!(!node.index.contains(block_id));
            assert!(
                node.rejected_proof_ids.contains(&block_id),
                "no other engine could settle it"
            );
            assert_eq!(recorded(&node), (0, 0), "nothing durable");
        }

        // A re-send runs nothing: the remembered id refuses it, and without
        // that the memo does, before any proof check. Either way it is
        // refused as unconfirmed, so it costs the sender nothing either.
        let resent = submit_shared_block(&node, chain[0].clone(), now).unwrap_err();
        assert!(matches!(resent, NodeError::WorkMismatchUnconfirmed(id) if id == block_id));
        assert!(!crate::is_remote_peer_proof_failure(&resent));
        node.lock().unwrap().forget_rejected_proof(block_id);
        assert!(matches!(
            submit_shared_block(&node, chain[0].clone(), now),
            Err(NodeError::WorkMismatchUnconfirmed(id)) if id == block_id
        ));
        assert_eq!(engine.block_calls(), 1);
        assert!(
            node.lock().unwrap().rejected_proof_ids.contains(&block_id),
            "remembered again"
        );

        // Its child is an orphan, not a descendant of a recorded invalid
        // block.
        assert!(matches!(
            submit_shared_block(&node, chain[1].clone(), now + 1),
            Err(NodeError::UnknownParent(_))
        ));
        drop(node);
        drop(source);
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    /// A distinct block id for filling the rejected-block caches.
    fn filler_id(index: usize) -> [u8; 32] {
        let mut id = [0xa5; 32];
        id[..8].copy_from_slice(&(index as u64).to_le_bytes());
        id
    }

    #[test]
    fn a_one_engine_refusal_keeps_its_kind_until_it_leaves_the_cache() {
        use crate::MAX_REJECTED_BLOCK_IDS;

        let (source_path, mut source) = devnet("work-gate-source-cache-kinds");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 1, now);
        let (path, mut node) = devnet("work-gate-cache-kinds");
        let engine = cpu();
        engine.answer(&chain[0], false);
        install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        let block_id = chain[0].block_id();
        let unconfirmed = |id: [u8; 32]| {
            WorkRejectionKind::Unconfirmed(WorkClaim {
                challenge_digest: id,
                work_digest: id,
            })
        };
        let older = MAX_REJECTED_BLOCK_IDS - 1;
        {
            let mut node = node.lock().unwrap();
            for index in 0..older {
                node.remember_work_rejection(filler_id(index), unconfirmed(filler_id(index)));
            }
        }
        assert!(matches!(
            submit_shared_block(&node, chain[0].clone(), now),
            Err(NodeError::WorkMismatchUnconfirmed(id)) if id == block_id
        ));
        {
            let mut node = node.lock().unwrap();
            // Each older id remembered again, as its re-send does, then one
            // more: the oldest leaves both caches together.
            for index in 0..older {
                node.remember_work_rejection(filler_id(index), unconfirmed(filler_id(index)));
            }
            let confirmed = filler_id(older);
            node.remember_work_rejection(confirmed, WorkRejectionKind::Confirmed);
            assert!(!node.rejected_proof_ids.contains(&filler_id(0)));
            assert!(!node.work_rejections.contains_key(&filler_id(0)));
            assert!(node.unconfirmed_work_rejection(&block_id));
            assert!(!node.marks_peer_on_invalid_chain(&block_id));
            // Two engines agreed on this one, though nothing was recorded.
            assert!(!node.unconfirmed_work_rejection(&confirmed));
            assert!(node.marks_peer_on_invalid_chain(&confirmed));
        }
        for _ in 0..3 {
            assert!(matches!(
                submit_shared_block(&node, chain[0].clone(), now),
                Err(NodeError::WorkMismatchUnconfirmed(id)) if id == block_id
            ));
        }
        assert_eq!(engine.block_calls(), 1);
        {
            let mut node = node.lock().unwrap();
            for index in 0..MAX_REJECTED_BLOCK_IDS {
                let id = filler_id(MAX_REJECTED_BLOCK_IDS + index);
                node.remember_work_rejection(id, WorkRejectionKind::Confirmed);
            }
            assert!(!node.rejected_proof_ids.contains(&block_id));
            assert!(!node.work_rejections.contains_key(&block_id));
            assert!(!node.marks_peer_on_invalid_chain(&block_id));
            assert_eq!(node.work_rejections.len(), MAX_REJECTED_BLOCK_IDS);
        }
        drop((node, source));
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    #[test]
    fn a_one_engine_refusal_is_checked_again_once_the_other_engine_is_ready() {
        let (source_path, mut source) = devnet("work-gate-source-retry-other");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 1, now);
        let (path, mut node) = devnet("work-gate-retry-other");
        let (cpu, gpu) = (cpu(), gpu());
        cpu.answer(&chain[0], false);
        gpu.answer(&chain[0], true);
        gpu.fail_known_answers();
        let checker = install(&mut node, None, Some(cpu.clone()), Some(gpu.clone()));
        assert_ne!(
            checker.engine_health(WorkEngineKind::Gpu),
            Some(WorkEngineHealth::Ready)
        );
        let node = shared(node);
        let block_id = chain[0].block_id();
        for _ in 0..2 {
            assert!(matches!(
                submit_shared_block(&node, chain[0].clone(), now),
                Err(NodeError::WorkMismatchUnconfirmed(id)) if id == block_id
            ));
        }
        assert_eq!((cpu.block_calls(), gpu.block_calls()), (1, 0));
        assert!(node.lock().unwrap().known_invalid_block(&block_id));

        gpu.restore_known_answers();
        checker.run_known_answer_tests();
        assert_eq!(
            checker.engine_health(WorkEngineKind::Gpu),
            Some(WorkEngineHealth::Ready)
        );
        {
            let node = node.lock().unwrap();
            assert!(node.stale_work_rejection(&block_id));
            assert!(
                !node.known_invalid_block(&block_id),
                "sync may fetch it again"
            );
        }
        submit_shared_block(&node, chain[0].clone(), now).unwrap();
        assert_eq!(gpu.block_calls(), 1, "the GPU settled it");
        {
            let node = node.lock().unwrap();
            assert!(node.index.contains(block_id));
            assert!(!node.rejected_proof_ids.contains(&block_id));
            assert!(!node.work_rejections.contains_key(&block_id));
        }
        drop((node, source));
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    #[test]
    fn a_one_engine_refusal_is_checked_again_once_its_worker_is_retired() {
        let (source_path, mut source) = devnet("work-gate-source-retry-retired");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 1, now);
        let (path, mut node) = devnet("work-gate-retry-retired");
        let engine = cpu();
        engine.answer(&chain[0], false);
        let checker = install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        let block_id = chain[0].block_id();
        assert!(matches!(
            submit_shared_block(&node, chain[0].clone(), now),
            Err(NodeError::WorkMismatchUnconfirmed(id)) if id == block_id
        ));
        assert!(!node.lock().unwrap().stale_work_rejection(&block_id));

        // A job that fails its integrity check retires the worker and drops
        // what it computed alone.
        engine.fail_next(WorkEngineError::Integrity("model data changed".to_owned()));
        assert!(checker.prewarm([0x5c; 32]).is_err());
        assert_ne!(
            checker.engine_health(WorkEngineKind::Cpu),
            Some(WorkEngineHealth::Ready)
        );
        assert!(!node.lock().unwrap().known_invalid_block(&block_id));
        let error = submit_shared_block(&node, chain[0].clone(), now).unwrap_err();
        assert!(
            error.client_error().retryable,
            "not refused from memory: {error:?}"
        );

        // Once the engine is fixed and qualified again, the block gets in.
        engine.answer(&chain[0], true);
        checker.run_known_answer_tests();
        submit_shared_block(&node, chain[0].clone(), now).unwrap();
        assert!(node.lock().unwrap().index.contains(block_id));
        drop((node, source));
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    #[test]
    fn a_one_engine_refusal_is_checked_again_once_its_known_answer_is_old() {
        use crate::honest_work::CPU_KAT_VECTORS;

        let (source_path, mut source) = devnet("work-gate-source-retry-aged");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 1, now);
        let (path, mut node) = devnet("work-gate-retry-aged");
        let engine = cpu();
        engine.answer(&chain[0], false);
        let checker = install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        let block_id = chain[0].block_id();
        let refused = |node: &Arc<Mutex<Node>>| {
            let error = submit_shared_block(node, chain[0].clone(), now).unwrap_err();
            assert!(
                matches!(error, NodeError::WorkMismatchUnconfirmed(id) if id == block_id),
                "{error:?}"
            );
            assert!(!crate::is_remote_peer_proof_failure(&error));
        };
        refused(&node);
        let known_answers = engine.known_answer_calls();

        checker.age_known_answers();
        {
            let node = node.lock().unwrap();
            assert!(node.stale_work_rejection(&block_id));
            assert!(
                !node.known_invalid_block(&block_id),
                "sync may fetch it again"
            );
        }
        // The re-send re-tests the worker with one round of known answers,
        // not the block, and is refused and remembered again.
        refused(&node);
        assert_eq!(engine.block_calls(), 1);
        assert_eq!(engine.known_answer_calls(), known_answers + CPU_KAT_VECTORS);
        {
            let node = node.lock().unwrap();
            assert!(node.unconfirmed_work_rejection(&block_id));
            assert!(!node.stale_work_rejection(&block_id));
            assert!(node.known_invalid_block(&block_id));
        }
        // Within the window a re-send runs nothing at all.
        refused(&node);
        assert_eq!(engine.block_calls(), 1);
        assert_eq!(engine.known_answer_calls(), known_answers + CPU_KAT_VECTORS);
        drop((node, source));
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    #[test]
    fn a_one_engine_refusal_becomes_confirmed_once_two_engines_agree_on_its_challenge() {
        let (source_path, mut source) = devnet("work-gate-source-retry-agreed");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 1, now);
        let (path, mut node) = devnet("work-gate-retry-agreed");
        let (cpu, gpu) = (cpu(), gpu());
        cpu.answer(&chain[0], false);
        gpu.answer(&chain[0], false);
        gpu.fail_known_answers();
        let checker = install(&mut node, None, Some(cpu.clone()), Some(gpu.clone()));
        let node = shared(node);
        let block_id = chain[0].block_id();
        assert!(matches!(
            submit_shared_block(&node, chain[0].clone(), now),
            Err(NodeError::WorkMismatchUnconfirmed(id)) if id == block_id
        ));
        let Some(WorkRejectionKind::Unconfirmed(claim)) =
            node.lock().unwrap().work_rejections.get(&block_id).copied()
        else {
            panic!("remembered as one engine's refusal");
        };

        // Once the GPU qualifies, both engines agree on the same challenge,
        // as they would for another block that carries it.
        gpu.restore_known_answers();
        checker.run_known_answer_tests();
        let verdict = checker.check(claim);
        assert!(
            matches!(&verdict, WorkVerdict::Mismatch(mismatch) if mismatch.confirmed().is_some()),
            "{verdict:?}"
        );
        assert_eq!((cpu.block_calls(), gpu.block_calls()), (1, 1));
        {
            let node = node.lock().unwrap();
            assert!(node.stale_work_rejection(&block_id));
            assert!(!node.known_invalid_block(&block_id));
        }

        // The re-send is refused as confirmed, with no engine run, and now
        // counts against its sender.
        let error = submit_shared_block(&node, chain[0].clone(), now).unwrap_err();
        assert!(
            matches!(error, NodeError::WorkRecomputationMismatch(id) if id == block_id),
            "{error:?}"
        );
        assert!(crate::is_remote_peer_proof_failure(&error));
        assert_eq!((cpu.block_calls(), gpu.block_calls()), (1, 1));
        {
            let node = node.lock().unwrap();
            assert_eq!(
                node.work_rejections.get(&block_id),
                Some(&WorkRejectionKind::Confirmed)
            );
            assert!(!node.stale_work_rejection(&block_id));
            assert!(node.known_invalid_block(&block_id));
            assert!(node.marks_peer_on_invalid_chain(&block_id));
        }
        drop((node, source));
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    #[test]
    fn a_mismatch_both_engines_agree_on_is_recorded_invalid_and_refuses_descendants() {
        let (source_path, mut source) = devnet("work-gate-source-c");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 2, now);
        let (path, mut node) = devnet("work-gate-confirmed");
        let (cpu, gpu) = (cpu(), gpu());
        cpu.answer(&chain[0], false);
        gpu.answer(&chain[0], false);
        install(&mut node, None, Some(cpu.clone()), Some(gpu.clone()));
        let node = shared(node);
        let block_id = chain[0].block_id();

        let error = submit_shared_block(&node, chain[0].clone(), now).unwrap_err();
        assert!(matches!(error, NodeError::WorkRecomputationMismatch(id) if id == block_id));
        assert!(
            crate::is_remote_peer_proof_failure(&error),
            "starts the sender's cooldown"
        );
        assert_eq!((cpu.block_calls(), gpu.block_calls()), (1, 1));
        {
            let node = node.lock().unwrap();
            assert!(!node.index.contains(block_id));
            assert!(node.rejected_proof_ids.contains(&block_id));
            assert!(!node.unconfirmed_work_rejection(&block_id));
            assert_eq!(recorded(&node), (0, 1));
        }
        // A re-send is refused at once as a known invalid block.
        assert!(matches!(
            submit_shared_block(&node, chain[0].clone(), now),
            Err(NodeError::CachedInvalidBlock(id)) if id == block_id
        ));
        let error = submit_shared_block(&node, chain[1].clone(), now + 1).unwrap_err();
        assert!(matches!(error, NodeError::InvalidAncestor(id) if id == block_id));
        assert_eq!(error.client_error().status, 422);
        assert_eq!((cpu.block_calls(), gpu.block_calls()), (1, 1));
        drop(node);
        drop(source);
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    #[test]
    fn engine_failures_are_retryable_and_leave_nothing_behind() {
        let (source_path, mut source) = devnet("work-gate-source-d");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 1, now);
        let (path, mut node) = devnet("work-gate-unavailable");

        // A rule with no engines installed yet admits nothing above it.
        let rule = rule_from_genesis(&node);
        node.install_work_rule_for_test(Some(rule));
        let pending = shared(node);
        let error = submit_shared_block(&pending, chain[0].clone(), now).unwrap_err();
        assert!(matches!(error, NodeError::WorkCheckUnavailable));
        let client = error.client_error();
        assert_eq!(
            (client.code, client.status, client.retryable),
            ("work_check_unavailable", 503, true)
        );
        let mut node = Arc::try_unwrap(pending).ok().unwrap().into_inner().unwrap();

        let engine = cpu();
        engine.answer(&chain[0], true);
        let checker = install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        engine.fail_next(WorkEngineError::Failed("model bank unreadable".to_owned()));
        assert!(matches!(
            submit_shared_block(&node, chain[0].clone(), now),
            Err(NodeError::WorkCheckUnavailable)
        ));
        {
            let node = node.lock().unwrap();
            assert!(node.rejected_proof_ids.is_empty());
            assert_eq!(recorded(&node), (0, 0));
        }
        assert_eq!(checker.memo_len(), 0);
        assert_eq!(checker.alarms().own_engine_mismatches, 0);

        // Retried once the engine answers, it is admitted.
        submit_shared_block(&node, chain[0].clone(), now).unwrap();
        assert_eq!(recorded(&node.lock().unwrap()), (1, 0));
        drop(node);
        drop(source);
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    #[test]
    fn a_cancelled_remote_check_stops_its_job_and_keeps_nothing() {
        let (source_path, mut source) = devnet("work-gate-source-e");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 1, now);
        let (path, mut node) = devnet("work-gate-cancel");
        let engine = cpu();
        engine.answer(&chain[0], true);
        let checker = install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        let held = engine.hold_next();
        let request = RemoteProofRequest::new(Instant::now() + Duration::from_secs(30));
        let submission = {
            let node = Arc::clone(&node);
            let block = chain[0].clone();
            let request = request.clone();
            thread::spawn(move || {
                submit_shared_peer_block_cancellable(
                    &node,
                    block,
                    now,
                    RemoteProofPeerId::new(1).unwrap(),
                    request,
                )
            })
        };
        held.wait();
        assert!(request.cancel());
        let error = submission.join().unwrap().unwrap_err();
        assert!(matches!(error, NodeError::WorkCheckWithdrawn));
        let client = error.client_error();
        assert_eq!(
            (client.code, client.status, client.retryable),
            ("work_check_withdrawn", 503, true)
        );
        assert_eq!(checker.memo_len(), 0);
        assert_eq!(checker.alarms(), WorkAlarmCounts::default());
        {
            let node = node.lock().unwrap();
            assert!(node.rejected_proof_ids.is_empty());
            assert_eq!(recorded(&node), (0, 0));
            assert!(!node.index.contains(chain[0].block_id()));
        }

        // Nor is one this node stopped while it still had time.
        let held = engine.hold_next();
        let request = RemoteProofRequest::new(Instant::now() + Duration::from_secs(30));
        let submission = {
            let node = Arc::clone(&node);
            let block = chain[0].clone();
            let request = request.clone();
            thread::spawn(move || {
                submit_shared_peer_block_cancellable(
                    &node,
                    block,
                    now,
                    RemoteProofPeerId::new(3).unwrap(),
                    request,
                )
            })
        };
        held.wait();
        assert!(request.stop());
        assert!(!request.withdrawn());
        assert!(matches!(
            submission.join().unwrap(),
            Err(NodeError::ProofVerificationQueueTimeout)
        ));
        assert_eq!(recorded(&node.lock().unwrap()), (0, 0));

        // A job whose request's deadline passes while it runs is not
        // stopped: its verdict is recorded, though the block is not admitted
        // under that request.
        engine.during_next(|| thread::sleep(Duration::from_millis(400)));
        let request = RemoteProofRequest::new(Instant::now() + Duration::from_millis(200));
        assert!(matches!(
            submit_shared_peer_block_cancellable(
                &node,
                chain[0].clone(),
                now,
                RemoteProofPeerId::new(4).unwrap(),
                request,
            ),
            Err(NodeError::ProofVerificationQueueTimeout)
        ));
        assert_eq!(recorded(&node.lock().unwrap()), (1, 0));
        assert!(!node.lock().unwrap().index.contains(chain[0].block_id()));

        // A re-send is admitted from the record, with no further run.
        submit_shared_block(&node, chain[0].clone(), now).unwrap();
        assert_eq!(engine.block_calls(), 3);
        drop(node);
        drop(source);
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    /// Submits `block` as an untrusted peer at `address` would, under a
    /// request that ends after `deadline`.
    fn submit_from_address(
        node: &Arc<Mutex<Node>>,
        block: &Block,
        now: u64,
        address: [u8; 4],
        deadline: Duration,
    ) -> Result<u64, NodeError> {
        crate::submit_shared_peer_block_from(
            node,
            block.clone(),
            now,
            {
                static NEXT: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(1_000);
                RemoteProofPeerId::new(NEXT.fetch_add(1, Ordering::Relaxed)).unwrap()
            },
            RemoteProofRequest::new(Instant::now() + deadline),
            false,
            Some(BlockSender {
                address: IpAddr::from(address),
                fetched: false,
                trusted: false,
            }),
        )
    }

    #[test]
    fn a_one_engine_refusal_whose_deadline_passes_during_its_known_answer_still_counts() {
        use super::test_support::lone_refusals;

        let now = unix_time_seconds().unwrap();
        let (first_path, mut first_source) = devnet("work-gate-late-first");
        let (second_path, mut second_source) = devnet("work-gate-late-second");
        let first = mine(&mut first_source, 1, now).remove(0);
        let second = mine(&mut second_source, 1, now + 1).remove(0);
        let (path, mut node) = devnet("work-gate-late-verdict");
        let engine = cpu();
        engine.answer(&first, false);
        engine.answer(&second, false);
        engine.cancellable_known_answers();
        let checker = install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        let sender = [192, 0, 2, 7];

        // The block's job runs past its request's deadline, and the known
        // answer that a mismatch on one engine needs first runs after it.
        checker.age_known_answers();
        let known_answers = engine.known_answer_calls();
        engine.during_next(|| thread::sleep(Duration::from_millis(600)));
        let error = submit_from_address(&node, &first, now, sender, Duration::from_millis(300))
            .unwrap_err();
        assert!(
            matches!(error, NodeError::WorkMismatchUnconfirmed(id) if id == first.block_id()),
            "{error}"
        );
        assert_eq!(engine.known_answer_calls(), known_answers + 1);
        assert_eq!(
            lone_refusals(&node.lock().unwrap(), IpAddr::from(sender)),
            1,
            "the refusal counts against its sender"
        );

        // The known answer passed, so another block from that address within
        // the window is refused at once, with no known answer.
        let error = submit_from_address(&node, &second, now + 1, sender, Duration::from_secs(30))
            .unwrap_err();
        assert!(matches!(error, NodeError::WorkMismatchUnconfirmed(id) if id == second.block_id()));
        assert_eq!(engine.known_answer_calls(), known_answers + 1);
        assert_eq!(
            lone_refusals(&node.lock().unwrap(), IpAddr::from(sender)),
            2
        );
        assert_eq!(engine.block_calls(), 2);
        drop((node, first_source, second_source));
        for path in [path, first_path, second_path] {
            clean_test_dir(&path);
        }
    }

    #[test]
    fn a_remote_check_that_cannot_finish_in_time_runs_nothing() {
        let now = unix_time_seconds().unwrap();
        let (source_path, mut source) = devnet("work-gate-no-time-source");
        let block = mine(&mut source, 1, now).remove(0);
        let (path, mut node) = devnet("work-gate-no-time");
        let engine = cpu();
        engine.answer(&block, true);
        let checker = install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);

        // The last job took 20 s; this request has 5 s left.
        checker.set_check_times(WorkEngineKind::Cpu, Duration::from_secs(20), None);
        assert!(matches!(
            submit_from_address(&node, &block, now, [192, 0, 2, 8], Duration::from_secs(5)),
            Err(NodeError::ProofVerificationQueueFull)
        ));
        assert_eq!(engine.block_calls(), 0);
        assert_eq!(recorded(&node.lock().unwrap()), (0, 0));

        // With its known answers due as well, a check needs both times.
        checker.set_check_times(
            WorkEngineKind::Cpu,
            Duration::from_secs(2),
            Some(Duration::from_secs(4)),
        );
        assert_eq!(
            checker.expected_check_time(Instant::now()),
            Some(Duration::from_secs(2))
        );
        checker.age_known_answers();
        assert_eq!(
            checker.expected_check_time(Instant::now()),
            Some(Duration::from_secs(6))
        );
        assert!(matches!(
            submit_from_address(&node, &block, now, [192, 0, 2, 8], Duration::from_secs(5)),
            Err(NodeError::ProofVerificationQueueFull)
        ));
        assert_eq!(engine.block_calls(), 0);

        // With the time, it runs.
        submit_from_address(&node, &block, now, [192, 0, 2, 8], Duration::from_secs(30)).unwrap();
        assert_eq!(engine.block_calls(), 1);
        drop((node, source));
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    #[test]
    fn a_running_remote_check_ends_when_the_node_shuts_down() {
        let now = unix_time_seconds().unwrap();
        let (source_path, mut source) = devnet("work-gate-shutdown-source");
        let block = mine(&mut source, 1, now).remove(0);
        let (path, mut node) = devnet("work-gate-shutdown");
        let engine = cpu();
        engine.answer(&block, true);
        install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        let held = engine.hold_next();
        let submission = {
            let (node, block) = (Arc::clone(&node), block.clone());
            thread::spawn(move || {
                submit_from_address(&node, &block, now, [192, 0, 2, 9], Duration::from_secs(30))
            })
        };
        held.wait();
        node.lock().unwrap().shutdown_proof_verifier();
        assert!(matches!(
            submission.join().unwrap(),
            Err(NodeError::ProofVerificationQueueTimeout)
        ));
        assert_eq!(recorded(&node.lock().unwrap()), (0, 0));
        drop((node, source));
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    #[test]
    fn a_running_local_check_completes_when_the_node_shuts_down() {
        let now = unix_time_seconds().unwrap();
        let (source_path, mut source) = devnet("work-gate-local-shutdown-source");
        let block = mine(&mut source, 1, now).remove(0);
        let (path, mut node) = devnet("work-gate-local-shutdown");
        let engine = cpu();
        engine.answer(&block, true);
        install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        // A block this node found has its work checked as the node stops.
        let held = engine.hold_next_for(Duration::from_millis(500));
        let submission = {
            let (node, block) = (Arc::clone(&node), block.clone());
            thread::spawn(move || submit_shared_tip_block(&node, block, now))
        };
        held.wait();
        node.lock().unwrap().shutdown_proof_verifier();
        submission.join().unwrap().unwrap();
        assert_eq!(recorded(&node.lock().unwrap()), (1, 0));
        drop((node, source));
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    #[test]
    fn checkpoint_rules_run_after_the_parent_lookup() {
        let now = unix_time_seconds().unwrap();
        let (a_path, mut a) = devnet("work-gate-source-f1");
        let main = mine(&mut a, 2, now);
        let (b_path, mut b) = devnet("work-gate-source-f2");
        let other = mine(&mut b, 2, now + 50);
        let (c_path, mut c) = devnet("work-gate-source-f3");
        let third = mine(&mut c, 1, now + 80);

        // Both height-1 blocks were stored before the rule pinned the first.
        let (path, mut node) = devnet("work-gate-checkpoint");
        node.submit_block(main[0].clone(), now).unwrap();
        node.submit_block(other[0].clone(), now + 50).unwrap();
        let engine = cpu();
        engine.answer(&main[1], true);
        let rule = ForgeMatrixV4WorkRule::with_pinned_heights(1, main[0].block_id(), []).unwrap();
        install(&mut node, Some(rule), Some(engine.clone()), None);
        let node = shared(node);

        // At or below the checkpoint: only the pinned block, and the conflict
        // is one an honest peer can relay.
        let error = submit_shared_block(&node, third[0].clone(), now + 80).unwrap_err();
        assert!(matches!(
            error,
            NodeError::WorkCheckpointConflict {
                height: 1,
                checkpoint_height: 1,
                ..
            }
        ));
        assert_eq!(error.client_error().code, "work_checkpoint_conflict");
        // Above it: the block must descend from the checkpoint block.
        assert!(matches!(
            submit_shared_block(&node, other[1].clone(), now + 51),
            Err(NodeError::WorkCheckpointConflict {
                height: 2,
                checkpoint_height: 1,
                ..
            })
        ));
        // An unknown parent stays an unknown parent.
        let mut orphan = main[1].clone();
        orphan.challenge.previous_block = [0x55; 32];
        assert!(matches!(
            submit_shared_block(&node, orphan, now + 1),
            Err(NodeError::UnknownParent(_))
        ));
        assert_eq!(engine.block_calls(), 0, "none of these reached an engine");
        submit_shared_block(&node, main[1].clone(), now + 1).unwrap();
        assert_eq!(engine.block_calls(), 1);
        drop((node, a, b, c));
        for path in [path, a_path, b_path, c_path] {
            clean_test_dir(&path);
        }
    }

    #[test]
    fn deep_side_blocks_wait_for_the_background_check_without_an_engine_run() {
        let now = unix_time_seconds().unwrap();
        let (a_path, mut a) = devnet("work-gate-source-g1");
        let main = mine(&mut a, 8, now);
        // Two side branches off block 1, mined elsewhere.
        let (b_path, mut b) = devnet("work-gate-source-g2");
        b.submit_block(main[0].clone(), now).unwrap();
        let side = mine(&mut b, 2, now + 200);
        let (c_path, mut c) = devnet("work-gate-source-g3");
        c.submit_block(main[0].clone(), now).unwrap();
        c.submit_block(main[1].clone(), now + 1).unwrap();
        let near = mine(&mut c, 1, now + 300);

        let (path, mut node) = devnet("work-gate-relevance");
        for (offset, block) in main.iter().enumerate() {
            node.submit_block(block.clone(), now + offset as u64)
                .unwrap();
        }
        // Stored before the rule: a side block at height 2 nobody checked.
        node.submit_block(side[0].clone(), now + 200).unwrap();
        let engine = cpu();
        engine.answer(&near[0], true);
        let checker = install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);

        // Height 2 against a tip at 8: too deep for the admission path.
        let (d_path, mut d) = devnet("work-gate-source-g4");
        d.submit_block(main[0].clone(), now).unwrap();
        let path_b = mine(&mut d, 1, now + 400).remove(0);
        let error = submit_shared_block(&node, path_b.clone(), now + 400).unwrap_err();
        assert!(matches!(error, NodeError::WorkCheckPending));
        assert!(error.client_error().retryable);
        {
            let node = node.lock().unwrap();
            assert!(!node.index.contains(path_b.block_id()));
            let pending = node.pending_side_work();
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].block_id, path_b.block_id());
            assert_eq!(pending[0].height, 2);
        }
        // Once the background check has settled its claim (prewarm stands in
        // for it here), a re-send is admitted from the memo with no new job.
        let (challenge, _) = ScriptedEngine::digests(&path_b);
        engine.answer(&path_b, true);
        checker.prewarm(challenge).unwrap();
        assert_eq!(engine.block_calls(), 1);
        submit_shared_block(&node, path_b.clone(), now + 400).unwrap();
        assert_eq!(engine.block_calls(), 1);
        assert_eq!(recorded(&node.lock().unwrap()), (1, 0));

        // Height 3 on the unchecked side block: near enough, but it waits
        // for that block.
        assert!(matches!(
            submit_shared_block(&node, side[1].clone(), now + 201),
            Err(NodeError::WorkCheckPending)
        ));
        assert_eq!(engine.block_calls(), 1);
        // Height 3 off the active chain: checked and admitted.
        submit_shared_block(&node, near[0].clone(), now + 300).unwrap();
        assert_eq!(engine.block_calls(), 2);
        assert_eq!(node.lock().unwrap().state.tip(), main[7].block_id());
        drop((node, a, b, c, d));
        for path in [path, a_path, b_path, c_path, d_path] {
            clean_test_dir(&path);
        }
    }

    #[test]
    fn a_long_verified_side_branch_is_followed_and_an_unchecked_block_anywhere_in_it_waits() {
        let now = unix_time_seconds().unwrap();
        let (a_path, mut a) = devnet("work-gate-source-j1");
        let main = mine(&mut a, 12, now);
        let (b_path, mut b) = devnet("work-gate-source-j2");
        b.submit_block(main[0].clone(), now).unwrap();
        // Heights 2 to 14: heavier than the active chain once past 12.
        let side = mine(&mut b, 13, now + 500);

        let (path, mut node) = devnet("work-gate-side-walk");
        for (offset, block) in main.iter().enumerate() {
            node.submit_block(block.clone(), now + offset as u64)
                .unwrap();
        }
        for (offset, block) in side[..9].iter().enumerate() {
            node.submit_block(block.clone(), now + 500 + offset as u64)
                .unwrap();
        }
        assert_eq!(node.state.tip(), main[11].block_id());
        let engine = cpu();
        for block in &side[9..] {
            engine.answer(block, true);
        }
        install(&mut node, None, Some(engine.clone()), None);
        let mark_verified = |node: &Node, blocks: &[Block]| {
            let store = node.work_gate.as_ref().unwrap().store.as_ref().unwrap();
            let mut store = store.lock().unwrap();
            for block in blocks {
                store
                    .mark_verified(block.challenge.height, block.block_id())
                    .unwrap();
            }
        };
        // All but the lowest stored side block are verified.
        mark_verified(&node, &side[1..9]);
        let node = shared(node);

        // One unchecked block nine below still makes the branch wait.
        assert!(matches!(
            submit_shared_block(&node, side[9].clone(), now + 509),
            Err(NodeError::WorkCheckPending)
        ));
        assert_eq!(engine.block_calls(), 0);

        // Once it is verified, the whole branch is, and it is followed: each
        // new block is checked once and the heavier branch becomes active.
        mark_verified(&node.lock().unwrap(), &side[..1]);
        for (offset, block) in side[9..].iter().enumerate() {
            submit_shared_block(&node, block.clone(), now + 509 + offset as u64).unwrap();
        }
        assert_eq!(engine.block_calls(), 4);
        assert_eq!(node.lock().unwrap().state.tip(), side[12].block_id());
        drop((node, a, b));
        for path in [path, a_path, b_path] {
            clean_test_dir(&path);
        }
    }

    #[test]
    fn a_halted_node_admits_nothing() {
        let (source_path, mut source) = devnet("work-gate-source-h");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 1, now);
        let (path, mut node) = devnet("work-gate-halt");
        let network_id = node.params.network_id;
        write_work_halt(
            &path.join(WORK_HALT_FILE),
            network_id,
            9,
            [9; 32],
            [8; 32],
            &ConfirmedWorkMismatch::for_test([8; 32], [7; 32]),
        )
        .unwrap();
        let engine = cpu();
        engine.answer(&chain[0], true);
        install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        let error = submit_shared_block(&node, chain[0].clone(), now).unwrap_err();
        assert!(matches!(error, NodeError::WorkRuleHalted));
        assert!(error.client_error().retryable);
        assert!(matches!(
            node.lock().unwrap().submit_block(chain[0].clone(), now),
            Err(NodeError::WorkRuleHalted)
        ));
        assert_eq!(engine.block_calls(), 0);
        drop(node);
        drop(source);
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    #[test]
    fn one_peer_address_keeps_at_most_its_share_of_noted_blocks() {
        let id = |index: u32| {
            let mut id = [0_u8; 32];
            id[..4].copy_from_slice(&index.to_le_bytes());
            id
        };
        // A peer's blocks count together whether it sent them or a sync
        // session fetched them from it.
        let work = |index: u32, address: Option<IpAddr>| PendingSideWork {
            block_id: id(index),
            height: 10,
            claim: WorkClaim {
                challenge_digest: id(index),
                work_digest: [0; 32],
            },
            sender: address.map(|address| BlockSender {
                address,
                fetched: index.is_multiple_of(2),
                trusted: false,
            }),
        };
        let busy: IpAddr = "203.0.113.1".parse().unwrap();
        let other: IpAddr = "203.0.113.2".parse().unwrap();
        let mut pending = PendingSide::default();
        pending.push(work(0, Some(other)));
        for index in 1..=20 {
            pending.push(work(index, Some(busy)));
        }
        pending.push(work(100, None));
        let from_busy = pending
            .order
            .iter()
            .filter(|noted| noted.sender.is_some_and(|sender| sender.address == busy))
            .map(|noted| noted.block_id)
            .collect::<Vec<_>>();
        // Its newest are kept; nobody else's are dropped for them.
        assert_eq!(
            from_busy,
            (13..=20).map(id).collect::<Vec<_>>(),
            "{MAX_PENDING_SIDE_WORK_PER_SENDER} per address"
        );
        assert!(pending.ids.contains(&id(0)));
        assert!(pending.ids.contains(&id(100)));
        assert_eq!(pending.order.len(), 10);
        assert_eq!(pending.ids.len(), pending.order.len());
    }

    #[test]
    fn lone_refusals_count_each_block_once_per_address_and_leave_their_window() {
        let mut refusals = LoneRefusals::default();
        let busy: IpAddr = "198.51.100.1".parse().unwrap();
        let other: IpAddr = "198.51.100.2".parse().unwrap();
        let start = Instant::now();
        for index in 0..MAX_LONE_REFUSALS_PER_SENDER {
            assert!(refusals.allows(busy, &filler_id(index), start));
            // A block refused twice (a sync prewarm, then its submission)
            // counts once, and another address relaying it is not counted.
            refusals.charge(busy, filler_id(index), filler_id(index), start);
            refusals.charge(busy, filler_id(index), filler_id(index), start);
            refusals.charge(other, filler_id(index), filler_id(index), start);
        }
        assert!(!refusals.by_sender.contains_key(&other));
        assert!(refusals.exhausted(busy, start));
        assert!(!refusals.allows(busy, &filler_id(99), start));
        assert!(
            refusals.allows(busy, &filler_id(0), start),
            "a block already counted is not deferred"
        );
        assert!(refusals.allows(other, &filler_id(99), start));
        assert!(!refusals.exhausted(other, start));

        // Each leaves after the window; then the address is forgotten.
        let later = start + LONE_REFUSAL_WINDOW / 2;
        refusals.charge(other, filler_id(50), filler_id(50), later);
        assert!(refusals.exhausted(busy, start + LONE_REFUSAL_WINDOW - Duration::from_secs(1)));
        assert!(!refusals.exhausted(busy, start + LONE_REFUSAL_WINDOW));
        assert!(!refusals.by_sender.contains_key(&busy));
        assert!(refusals.by_sender.contains_key(&other));
        refusals.forget_expired(later + LONE_REFUSAL_WINDOW);
        assert!(refusals.by_sender.is_empty());
    }

    /// Submits `block` as a block from `address`, sent unasked.
    fn submit_from(
        node: &Arc<Mutex<Node>>,
        block: &Block,
        now: u64,
        address: IpAddr,
        trusted: bool,
    ) -> Result<u64, NodeError> {
        static PEER: AtomicU64 = AtomicU64::new(1_000);
        crate::submit_shared_peer_block_from(
            node,
            block.clone(),
            now,
            RemoteProofPeerId::new(PEER.fetch_add(1, Ordering::Relaxed)).unwrap(),
            RemoteProofRequest::new(Instant::now() + Duration::from_secs(30)),
            trusted,
            Some(BlockSender {
                address,
                fetched: false,
                trusted,
            }),
        )
    }

    /// `count` distinct blocks that each extend genesis, from fresh sources.
    pub(crate) fn competing_blocks(
        label: &str,
        count: usize,
        now: u64,
    ) -> (Vec<PathBuf>, Vec<Block>) {
        (0..count)
            .map(|index| {
                let (source_path, mut source) = devnet(&format!("{label}-{index}"));
                let block = mine(&mut source, 1, now + index as u64).remove(0);
                (source_path, block)
            })
            .unzip()
    }

    #[test]
    fn one_address_has_at_most_its_share_of_lone_refusals_and_its_other_blocks_wait() {
        let now = unix_time_seconds().unwrap();
        let (source_paths, blocks) = competing_blocks(
            "work-gate-lone-source",
            MAX_LONE_REFUSALS_PER_SENDER + 4,
            now,
        );
        let (honest, bad) = blocks.split_first().unwrap();
        let (path, mut node) = devnet("work-gate-lone-refusals");
        let engine = cpu();
        engine.answer(honest, true);
        for block in bad {
            engine.answer(block, false);
        }
        let checker = install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        let busy: IpAddr = "198.51.100.7".parse().unwrap();
        let other: IpAddr = "198.51.100.8".parse().unwrap();
        let refused = |result: Result<u64, NodeError>, block: &Block| {
            assert!(
                matches!(result, Err(NodeError::WorkMismatchUnconfirmed(id)) if id == block.block_id()),
                "{result:?}"
            );
        };
        let deferred = |result: Result<u64, NodeError>| {
            let error = result.unwrap_err();
            assert!(matches!(error, NodeError::WorkCheckDeferred), "{error:?}");
            let client = error.client_error();
            assert_eq!(
                (client.code, client.status, client.retryable),
                ("work_check_deferred", 503, true)
            );
            assert!(!crate::is_remote_peer_proof_failure(&error));
        };

        // Its share of distinct blocks is checked and refused.
        let (checked, rest) = bad.split_at(MAX_LONE_REFUSALS_PER_SENDER);
        for block in checked {
            refused(submit_from(&node, block, now, busy, false), block);
        }
        assert_eq!(engine.block_calls(), MAX_LONE_REFUSALS_PER_SENDER);
        // Its next distinct block runs nothing and is not remembered.
        deferred(submit_from(&node, &rest[0], now, busy, false));
        assert_eq!(engine.block_calls(), MAX_LONE_REFUSALS_PER_SENDER);
        assert_eq!(checker.memo_len(), MAX_LONE_REFUSALS_PER_SENDER);
        assert!(
            !node
                .lock()
                .unwrap()
                .rejected_proof_ids
                .contains(&rest[0].block_id())
        );
        // A re-send of a refused block is still refused from memory.
        refused(
            submit_from(&node, &checked[0], now, busy, false),
            &checked[0],
        );
        // An honest block from it waits too, and the same block from
        // another address is checked and admitted at once.
        deferred(submit_from(&node, honest, now, busy, false));
        assert!(!node.lock().unwrap().index.contains(honest.block_id()));
        submit_from(&node, honest, now, other, false).unwrap();
        assert!(node.lock().unwrap().index.contains(honest.block_id()));
        assert_eq!(engine.block_calls(), MAX_LONE_REFUSALS_PER_SENDER + 1);
        // The deferred block from another address is checked as usual.
        refused(submit_from(&node, &rest[0], now, other, false), &rest[0]);
        assert_eq!(engine.block_calls(), MAX_LONE_REFUSALS_PER_SENDER + 2);
        // A trusted peer on the busy address is not counted.
        refused(submit_from(&node, &rest[1], now, busy, true), &rest[1]);
        assert_eq!(engine.block_calls(), MAX_LONE_REFUSALS_PER_SENDER + 3);
        // Once its refusals leave the window, the address is checked again.
        deferred(submit_from(&node, &rest[2], now, busy, false));
        test_support::end_lone_refusal_window(&node.lock().unwrap());
        refused(submit_from(&node, &rest[2], now, busy, false), &rest[2]);
        assert_eq!(engine.block_calls(), MAX_LONE_REFUSALS_PER_SENDER + 4);
        assert_eq!(recorded(&node.lock().unwrap()), (1, 0), "nothing invalid");
        assert_eq!(checker.alarms().own_engine_mismatches, bad.len() as u64);

        drop(node);
        clean_test_dir(&path);
        for source_path in source_paths {
            clean_test_dir(&source_path);
        }
    }

    /// Computes `block`'s work as a sync session fetching it `from` a peer
    /// would just before submitting it.
    fn prewarm_from(node: &Arc<Mutex<Node>>, block: &Block, now: u64, from: FetchedFrom) {
        let prewarm = node.lock().unwrap().work_prewarm(block, now, from);
        if let Some(prewarm) = prewarm {
            let request = RemoteProofRequest::new(Instant::now() + Duration::from_secs(30));
            prewarm.run(request, &|| false);
        }
    }

    #[test]
    fn checks_from_one_address_waiting_together_share_its_lone_refusals() {
        let now = unix_time_seconds().unwrap();
        let waiting = MAX_LONE_REFUSALS_PER_SENDER + 1;
        let (source_paths, blocks) =
            competing_blocks("work-gate-lone-concurrent-source", waiting + 1, now);
        let (path, mut node) = devnet("work-gate-lone-concurrent");
        let engine = cpu();
        for block in &blocks {
            engine.answer(block, false);
        }
        let checker = install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        let busy: IpAddr = "198.51.100.9".parse().unwrap();
        let from = FetchedFrom {
            sender: busy,
            trusted: false,
            heavier: false,
            catch_up: None,
        };

        // While a sync session computes one block's work, two more sessions
        // and a block sent unasked, all from the address, pass every check
        // made before the lane and wait for it.
        let (first, others) = blocks.split_first().unwrap();
        let sessions = Arc::new(Mutex::new(Vec::new()));
        {
            let node = Arc::clone(&node);
            let others = others.to_vec();
            let sessions = Arc::clone(&sessions);
            engine.during_next(move || {
                for (index, block) in others.into_iter().enumerate() {
                    let node = Arc::clone(&node);
                    sessions.lock().unwrap().push(thread::spawn(move || {
                        if index == 0 {
                            submit_from(&node, &block, now, busy, false).map(|_| ())
                        } else {
                            prewarm_from(&node, &block, now, from);
                            Ok(())
                        }
                    }));
                }
                let deadline = Instant::now() + Duration::from_secs(20);
                while test_support::lane_waiters(&node.lock().unwrap()).0 < waiting {
                    assert!(Instant::now() < deadline, "the checks never queued");
                    thread::sleep(Duration::from_millis(5));
                }
            });
        }
        prewarm_from(&node, first, now, from);
        let results = std::mem::take(&mut *sessions.lock().unwrap())
            .into_iter()
            .map(|session| session.join().unwrap())
            .collect::<Vec<_>>();
        // Each took the lane in turn, and only the address's share ran.
        assert_eq!(
            engine.block_calls(),
            MAX_LONE_REFUSALS_PER_SENDER,
            "{results:?}"
        );
        assert_eq!(checker.memo_len(), MAX_LONE_REFUSALS_PER_SENDER);
        assert!(node.lock().unwrap().lone_refusals_exhausted(from));
        assert!(!node.lock().unwrap().lone_refusals_exhausted(FetchedFrom {
            trusted: true,
            ..from
        }));

        drop(node);
        clean_test_dir(&path);
        for source_path in source_paths {
            clean_test_dir(&source_path);
        }
    }

    #[test]
    fn peers_relaying_one_refused_block_together_are_counted_once_for_its_work() {
        let now = unix_time_seconds().unwrap();
        let (source_paths, blocks) = competing_blocks("work-gate-lone-relay-source", 2, now);
        let (path, mut node) = devnet("work-gate-lone-relay");
        let engine = cpu();
        for block in &blocks {
            engine.answer(block, false);
        }
        install(&mut node, None, Some(engine.clone()), None);
        let node = shared(node);
        let relays: [IpAddr; 2] = [
            "198.51.100.11".parse().unwrap(),
            "198.51.100.12".parse().unwrap(),
        ];

        // While the first relay's copy of one block is checked, the other
        // relay's copy of it and both relays' copies of a second block pass
        // every check made before the lane and wait for it.
        let sessions = Arc::new(Mutex::new(Vec::new()));
        {
            let node = Arc::clone(&node);
            let sends = [
                (blocks[0].clone(), relays[1]),
                (blocks[1].clone(), relays[0]),
                (blocks[1].clone(), relays[1]),
            ];
            let sessions = Arc::clone(&sessions);
            engine.during_next(move || {
                let waiting = sends.len();
                for (block, relay) in sends {
                    let node = Arc::clone(&node);
                    sessions.lock().unwrap().push(thread::spawn(move || {
                        submit_from(&node, &block, now, relay, false)
                    }));
                }
                let deadline = Instant::now() + Duration::from_secs(20);
                while test_support::lane_waiters(&node.lock().unwrap()).0 < waiting {
                    assert!(Instant::now() < deadline, "the copies never queued");
                    thread::sleep(Duration::from_millis(5));
                }
            });
        }
        let first = submit_from(&node, &blocks[0], now, relays[0], false);
        let results = std::iter::once(first)
            .chain(
                std::mem::take(&mut *sessions.lock().unwrap())
                    .into_iter()
                    .map(|session| session.join().unwrap()),
            )
            .collect::<Vec<_>>();
        // Every copy is refused, each block's work ran once, and each counts
        // against one relay only.
        assert!(
            results
                .iter()
                .all(|result| matches!(result, Err(NodeError::WorkMismatchUnconfirmed(_)))),
            "{results:?}"
        );
        assert_eq!(engine.block_calls(), 2);
        let counted = relays.map(|relay| test_support::lone_refusals(&node.lock().unwrap(), relay));
        assert_eq!(counted.iter().sum::<usize>(), 2, "{counted:?}");
        assert!(counted[0] >= 1, "the first relay's copy ran: {counted:?}");

        drop(node);
        clean_test_dir(&path);
        for source_path in source_paths {
            clean_test_dir(&source_path);
        }
    }

    #[test]
    fn only_local_miners_and_trusted_peers_wait_for_the_lane_as_priority() {
        let (source_path, mut source) = devnet("work-gate-source-origin");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 1, now);
        let priority = |node: &Node, local_tip: bool, origin: BlockOrigin| {
            node.work_admission(&chain[0], local_tip, origin)
                .unwrap()
                .unwrap()
                .priority
        };
        let origins = [
            BlockOrigin::Peer {
                trusted: false,
                sender: None,
            },
            BlockOrigin::Peer {
                trusted: true,
                sender: None,
            },
            BlockOrigin::Rpc { loopback: false },
            BlockOrigin::Rpc { loopback: true },
            BlockOrigin::InProcess,
        ];

        // The block extends the tip.
        let (path, mut node) = devnet("work-gate-origin-tip");
        install(&mut node, None, Some(cpu()), None);
        let at_tip = origins.map(|origin| priority(&node, false, origin));
        assert_eq!(at_tip, [false, true, false, true, true]);
        assert!(priority(
            &node,
            true,
            BlockOrigin::Peer {
                trusted: false,
                sender: None,
            }
        ));

        // The block is on a side branch.
        let (side_path, mut side) = devnet("work-gate-origin-side");
        mine(&mut side, 1, now + 1);
        install(&mut side, None, Some(cpu()), None);
        let on_side = origins.map(|origin| priority(&side, false, origin));
        assert_eq!(on_side, [false, true, false, true, false]);

        drop((node, side, source));
        clean_test_dir(&path);
        clean_test_dir(&side_path);
        clean_test_dir(&source_path);
    }

    #[test]
    fn a_pool_block_with_its_own_replay_result_is_admitted_and_recorded_verified() {
        let (source_path, mut source) = devnet("work-gate-source-i");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 2, now);
        let (path, mut node) = devnet("work-gate-pool");
        let replay = gpu();
        let checker = install(&mut node, None, None, Some(replay.clone()));
        let node = shared(node);

        // The pool's replay worker produced this block's work: no engine runs
        // for it beyond a known answer on that worker.
        let (challenge, digest) = ScriptedEngine::digests(&chain[0]);
        checker.record_honest(crate::honest_work::PoolReplayResult::new(
            challenge, digest, 0,
        ));
        submit_shared_tip_block(&node, chain[0].clone(), now).unwrap();
        assert_eq!(replay.block_calls(), 0);
        assert_eq!(recorded(&node.lock().unwrap()), (1, 0));
        // Admitted, but only provisionally verified until this node's own
        // engines run it.
        assert_eq!(
            provisional(&node.lock().unwrap()),
            vec![(1, chain[0].block_id())]
        );

        // A wrong recorded result does not refuse an honest block: its work
        // is run, and it matches.
        let (challenge, mut wrong) = ScriptedEngine::digests(&chain[1]);
        wrong[0] ^= 1;
        checker.record_honest(crate::honest_work::PoolReplayResult::new(
            challenge, wrong, 0,
        ));
        replay.answer(&chain[1], true);
        submit_shared_tip_block(&node, chain[1].clone(), now + 1).unwrap();
        assert_eq!(replay.block_calls(), 1);
        assert_eq!(recorded(&node.lock().unwrap()), (2, 0));
        assert_eq!(
            provisional(&node.lock().unwrap()),
            vec![(1, chain[0].block_id())]
        );
        drop(node);
        drop(source);
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }

    #[test]
    fn a_stored_chain_off_the_pinned_list_is_refused_at_startup() {
        let (source_path, mut source) = devnet("work-gate-source-j");
        let now = unix_time_seconds().unwrap();
        let chain = mine(&mut source, 4, now);
        let (path, node) = devnet("work-gate-consistency");
        let shared_node = shared(node);
        for (offset, block) in chain.iter().enumerate() {
            submit_shared_block(&shared_node, block.clone(), now + offset as u64).unwrap();
        }
        let mut node = shared_node.lock().unwrap();
        let checker = || {
            Arc::new(
                crate::honest_work::HonestWorkChecker::new(
                    Some(cpu() as Arc<dyn crate::honest_work::WorkEngine>),
                    None,
                    false,
                )
                .unwrap(),
            )
        };

        let other = [7; 32];
        let rule = ForgeMatrixV4WorkRule::with_pinned_heights(3, chain[2].block_id(), [(2, other)])
            .unwrap();
        node.install_work_rule_for_test(Some(rule));
        let error = node.install_work_checker(checker()).unwrap_err();
        assert!(matches!(
            error,
            NodeError::WorkCheckpointConflict { block_id, height: 2, checkpoint_height: 3 }
                if block_id == chain[1].block_id()
        ));

        // The pinned chain itself opens, and a checkpoint above the tip only
        // checks what is stored.
        let rule = ForgeMatrixV4WorkRule::with_pinned_heights(
            3,
            chain[2].block_id(),
            [(1, chain[0].block_id()), (2, chain[1].block_id())],
        )
        .unwrap();
        node.install_work_rule_for_test(Some(rule));
        node.install_work_checker(checker()).unwrap();
        let rule =
            ForgeMatrixV4WorkRule::with_pinned_heights(9, [9; 32], [(4, chain[3].block_id())])
                .unwrap();
        node.install_work_rule_for_test(Some(rule));
        node.install_work_checker(checker()).unwrap();
        assert_eq!(node.work_validated_height(), Some(4));
        drop(node);
        drop((shared_node, source));
        clean_test_dir(&path);
        clean_test_dir(&source_path);
    }
}
