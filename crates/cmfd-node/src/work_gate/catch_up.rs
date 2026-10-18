//! Desktop wallet catch-up: what a wallet that is far behind needs to admit
//! a block without running its work engine, and the grant records it keeps.
//!
//! Only a desktop wallet turns this on (see
//! [`Node::enable_wallet_catch_up`](crate::Node::enable_wallet_catch_up)).
//! With it on, a block fetched from one compiled source may be admitted
//! without an engine run only if a source run by another provider lists the
//! same block, both sources report heights at least
//! [`WALLET_CATCH_UP_DEPTH`] above it, it extends this node's tip, and it is
//! not much easier than a reference that cannot fall below the checkpoint
//! block's work. Each such grant is recorded in
//! [`CATCH_UP_GRANTS_FILE`] and synced before the block commits. The records
//! only say which stored blocks were admitted that way; they never admit a
//! block themselves. Nodes independently re-execute each block's work in the
//! background all the same, and nothing a grant admits counts as validated.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use primitive_types::U512;

pub use crate::honest_work::store::CATCH_UP_GRANTS_FILE;
use crate::honest_work::store::sync_parent;

/// A block is admitted without an engine run only this many blocks below the
/// heights both the serving and the vouching source report; the newest ones
/// are always re-executed before they are admitted.
pub const WALLET_CATCH_UP_DEPTH: u64 = 60;
/// A block admitted that way needs at least `1 / WALLET_MAX_EASING` of the
/// reference work.
pub const WALLET_MAX_EASING: u64 = 2;
/// How long a source's reported height, or its recent delivery of blocks,
/// counts.
pub const VIEW_FRESH: Duration = Duration::from_secs(10 * 60);
/// The run of re-executed blocks at the tip counts as forming only while it
/// grew within this long.
pub const TOP_RUN_STALL: Duration = Duration::from_secs(2 * 60);
/// ... and only for this long after it started.
pub const TOP_RUN_CAP: Duration = Duration::from_secs(30 * 60);
/// Connect timeout of one corroborating connection.
pub const PROBE_CONNECT: Duration = Duration::from_secs(2);
/// Read timeout of one corroborating connection.
pub const PROBE_READ: Duration = Duration::from_secs(2);
/// All corroborating connections of one sync session end by this deadline.
pub const PROBE_BUDGET: Duration = Duration::from_secs(6);
/// A source that failed a corroborating connection is not asked again for
/// this long.
pub const PROBE_FAIL_HOLD: Duration = Duration::from_secs(60);
/// No corroborating connection starts with less than this left before the
/// deadline.
pub(crate) const PROBE_MIN_ATTEMPT: Duration = Duration::from_millis(100);
/// The summary of a source's sync sessions is logged at most this often per
/// source.
const SESSION_SUMMARY_INTERVAL: Duration = Duration::from_secs(60);
/// No block is admitted without an engine run once the checkpoint block's
/// timestamp is more than this many seconds before the local clock: a newer
/// release moves the checkpoint.
pub const STALE_AFTER: u64 = 60 * 24 * 60 * 60;
/// No block is admitted without an engine run while the tip is more than this
/// many prune windows above the prune height, so intake cannot outrun the
/// pruner.
pub const PRUNE_LAG_FACTOR: u64 = 2;
/// After a failed read of the checkpoint block's time, it is read again at
/// most this often.
pub const CHECKPOINT_TIME_RETRY: Duration = Duration::from_secs(60);

/// At most this many sources (one bit each in a vouched id's mask).
const MAX_SOURCES: usize = 8;
/// Grants waiting for their block's commit; the oldest is dropped first.
const MAX_GRANTS: usize = 64;
/// Ids listed by corroborating sources that are remembered; the oldest is
/// dropped first.
const MAX_VOUCHED: usize = 4_096;

const GRANT_MAGIC: [u8; 8] = *b"CMFDCUG1";
/// Magic, network id, checkpoint block id, check.
const GRANT_HEADER_BYTES: usize = 8 + 32 + 32 + 32;
/// Height, block id, check.
const GRANT_RECORD_BYTES: usize = 8 + 32 + 8;

/// A compiled source of blocks for the catch-up, and the hosting provider it
/// belongs to: sources in one group count as one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CatchUpSource {
    pub addr: SocketAddr,
    pub group: u8,
}

/// A sync session's part in a grant: the session's source (its index among
/// the sources) and the highest height it may grant, its reported height
/// less [`WALLET_CATCH_UP_DEPTH`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CatchUpFollow {
    pub(crate) below: u64,
    pub(crate) source: u8,
}

/// Why a block was not granted: the first condition it failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrantRefusal {
    /// No fresh source in another group listed it at least the depth below
    /// its own reported height.
    NotVouched,
    /// It does not extend the tip.
    NotTipExtension,
    /// It is recorded, unsettled or remembered as refused.
    Known,
    /// The reference work is unknown, or it is too easy.
    Easing,
    /// Admission is halted, the engines are not ready, a block above the
    /// validated height is unsettled, or the work-status store failed.
    NotReady,
    /// The release is stale, or the checkpoint time or the clock is unknown.
    ReleaseStale,
    /// The tip is too far above the prune height.
    PruneLag,
    /// Its grant record could not be written.
    GrantFile,
}

impl GrantRefusal {
    /// The number of the grant condition this is. A grant-file failure is
    /// not one of the numbered conditions; it reports 9 and is counted on
    /// its own.
    pub(crate) fn condition(self) -> u8 {
        match self {
            Self::NotVouched => 2,
            Self::NotTipExtension => 3,
            Self::Known => 4,
            Self::Easing => 5,
            Self::NotReady => 6,
            Self::ReleaseStale => 7,
            Self::PruneLag => 8,
            Self::GrantFile => 9,
        }
    }
}

/// Whether a block of work `work_b` is close enough to the reference `w_ref`.
pub(crate) fn easing_ok(work_b: U512, w_ref: U512) -> bool {
    work_b
        .checked_mul(U512::from(WALLET_MAX_EASING))
        .is_none_or(|scaled| scaled >= w_ref)
}

/// Whether the release whose checkpoint block has timestamp `time_c` is
/// fresh at `now_unix`. A clock behind the checkpoint counts as fresh: a block
/// may be stamped up to two hours ahead of the clock that accepted it.
pub(crate) fn release_fresh(now_unix: u64, time_c: u64) -> bool {
    now_unix.saturating_sub(time_c) <= STALE_AFTER
}

/// [`release_fresh`] with a clock reading and a checkpoint time that may be
/// missing: not fresh without both.
pub(crate) fn release_fresh_at(now_unix: Option<u64>, time_c: Option<u64>) -> bool {
    now_unix
        .zip(time_c)
        .is_some_and(|(now_unix, time_c)| release_fresh(now_unix, time_c))
}

/// Whether the pruner keeps up: with pruning on (`keep` blocks), the tip is
/// at most [`PRUNE_LAG_FACTOR`] windows above the prune height (0 before the
/// first prune).
pub(crate) fn prune_lag_ok(tip: u64, prune_height: Option<u64>, keep: Option<u64>) -> bool {
    keep.is_none_or(|keep| {
        tip.saturating_sub(prune_height.unwrap_or(0)) <= PRUNE_LAG_FACTOR.saturating_mul(keep)
    })
}

/// The reference work from the block at the validated height and the block
/// at the checkpoint: unknown unless both are known.
pub(crate) fn reference(work_v: Option<U512>, work_c: Option<U512>) -> Option<U512> {
    Some(work_v?.max(work_c?))
}

/// The sources as given, without repeated addresses, if there are 2 to
/// [`MAX_SOURCES`] of them in at least two groups.
pub(crate) fn valid_sources(sources: Vec<CatchUpSource>) -> Option<Vec<CatchUpSource>> {
    let mut distinct: Vec<CatchUpSource> = Vec::with_capacity(sources.len());
    for source in sources {
        if !distinct.iter().any(|known| known.addr == source.addr) {
            distinct.push(source);
        }
    }
    let groups = distinct
        .iter()
        .map(|source| source.group)
        .collect::<HashSet<_>>();
    ((2..=MAX_SOURCES).contains(&distinct.len()) && groups.len() >= 2).then_some(distinct)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Each guarded value is left consistent by every operation on it.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `catch-up-grants.v1`: a header that binds the file to one network and one
/// checkpoint, then one record per grant. Every hash is plain BLAKE3, so the
/// file can be read without this code.
pub(crate) struct GrantFile {
    path: PathBuf,
    /// Ids with a valid record.
    ids: HashSet<[u8; 32]>,
    /// The append handle; `None` once a failed append could not be undone,
    /// after which nothing more is granted in this process.
    file: Option<File>,
    /// The length of the file up to its last complete record.
    length: u64,
    #[cfg(test)]
    syncs: u64,
    #[cfg(test)]
    fail_next_write: bool,
}

fn grant_header(network_id: [u8; 32], checkpoint_id: [u8; 32]) -> [u8; GRANT_HEADER_BYTES] {
    let mut header = [0_u8; GRANT_HEADER_BYTES];
    header[..8].copy_from_slice(&GRANT_MAGIC);
    header[8..40].copy_from_slice(&network_id);
    header[40..72].copy_from_slice(&checkpoint_id);
    let check = blake3::hash(&header[..72]);
    header[72..].copy_from_slice(check.as_bytes());
    header
}

fn grant_record(height: u64, block_id: [u8; 32]) -> [u8; GRANT_RECORD_BYTES] {
    let mut record = [0_u8; GRANT_RECORD_BYTES];
    record[..8].copy_from_slice(&height.to_le_bytes());
    record[8..40].copy_from_slice(&block_id);
    let check = blake3::hash(&record[..40]);
    record[40..].copy_from_slice(&check.as_bytes()[..8]);
    record
}

fn decode_grant(record: &[u8]) -> Option<(u64, [u8; 32])> {
    if record[40..] != blake3::hash(&record[..40]).as_bytes()[..8] {
        return None;
    }
    let height = u64::from_le_bytes(record[..8].try_into().expect("eight bytes"));
    Some((height, record[8..40].try_into().expect("32 bytes")))
}

/// Writes `bytes` to the temporary file, syncs it and renames it to `path`.
fn replace_grant_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fn write(temporary: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = File::create(temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(temporary, path)?;
        sync_parent(path)
    }
    let temporary = path.with_extension("v1.tmp");
    let written = write(&temporary, path, bytes);
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

/// Cuts the file at `path` back to `length` and opens a new append handle.
fn cut_back(path: &Path, length: u64) -> io::Result<File> {
    let file = OpenOptions::new().write(true).open(path)?;
    file.set_len(length)?;
    file.sync_all()?;
    drop(file);
    OpenOptions::new().append(true).open(path)
}

impl GrantFile {
    /// Opens (or creates) the grant file at `path` for `network_id` and the
    /// checkpoint `checkpoint_id`. A missing file, a damaged header, or one
    /// for another network or checkpoint is replaced by an empty one; a torn
    /// last record is cut off, and a damaged record is skipped. If more than
    /// half the records are not `live` (height, block id), the file is first
    /// rewritten with the live ones only; a failed rewrite keeps the old file.
    pub(crate) fn open(
        path: &Path,
        network_id: [u8; 32],
        checkpoint_id: [u8; 32],
        live: impl Fn(u64, [u8; 32]) -> bool,
    ) -> io::Result<Self> {
        let header = grant_header(network_id, checkpoint_id);
        let bytes = match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let mut records = Vec::new();
        let mut whole_records = 0_usize;
        let mut length = GRANT_HEADER_BYTES;
        match bytes {
            Some(bytes)
                if bytes.len() >= GRANT_HEADER_BYTES && bytes[..GRANT_HEADER_BYTES] == header =>
            {
                let body = &bytes[GRANT_HEADER_BYTES..];
                let whole = body.len() - body.len() % GRANT_RECORD_BYTES;
                for record in body[..whole].chunks_exact(GRANT_RECORD_BYTES) {
                    whole_records += 1;
                    if let Some(grant) = decode_grant(record) {
                        records.push(grant);
                    }
                }
                length += whole;
                if whole < body.len() {
                    // An append-only handle cannot truncate on every platform.
                    let file = OpenOptions::new().write(true).open(path)?;
                    file.set_len(length as u64)?;
                    file.sync_all()?;
                }
            }
            _ => replace_grant_file(path, &header)?,
        }
        let kept = records
            .iter()
            .copied()
            .filter(|(height, block_id)| live(*height, *block_id))
            .collect::<Vec<_>>();
        if 2 * (whole_records - kept.len()) > whole_records {
            let mut compacted =
                Vec::with_capacity(GRANT_HEADER_BYTES + kept.len() * GRANT_RECORD_BYTES);
            compacted.extend_from_slice(&header);
            for (height, block_id) in &kept {
                compacted.extend_from_slice(&grant_record(*height, *block_id));
            }
            match replace_grant_file(path, &compacted) {
                Ok(()) => {
                    records = kept;
                    length = compacted.len();
                }
                Err(error) => tracing::warn!(
                    target: "work_rule::catch_up",
                    path = %path.display(),
                    %error,
                    "the catch-up grant file could not be compacted; the old one stays in use"
                ),
            }
        }
        let file = OpenOptions::new().append(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            ids: records.into_iter().map(|(_, block_id)| block_id).collect(),
            file: Some(file),
            length: length as u64,
            #[cfg(test)]
            syncs: 0,
            #[cfg(test)]
            fail_next_write: false,
        })
    }

    /// Whether `block_id` has a grant record.
    pub(crate) fn contains(&self, block_id: &[u8; 32]) -> bool {
        self.ids.contains(block_id)
    }

    /// Whether appends stopped after a failed write that could not be cut
    /// back.
    pub(crate) fn stopped(&self) -> bool {
        self.file.is_none()
    }

    /// Appends and syncs the grant record of `block_id` at `height`. On any
    /// failure the file is cut back to its last complete record and the
    /// append handle reopened; if that fails too, every later append fails.
    pub(crate) fn append(&mut self, height: u64, block_id: [u8; 32]) -> io::Result<()> {
        let Some(file) = self.file.as_mut() else {
            return Err(io::Error::other(
                "catch-up grants stopped after a failed write",
            ));
        };
        let record = grant_record(height, block_id);
        #[cfg(test)]
        let written = if std::mem::take(&mut self.fail_next_write) {
            // Part of the record reaches the file, as a full disk allows.
            file.write_all(&record[..GRANT_RECORD_BYTES / 2])
                .and_then(|()| Err(io::Error::other("write refused for the test")))
        } else {
            file.write_all(&record)
        };
        #[cfg(not(test))]
        let written = file.write_all(&record);
        let synced = written.and_then(|()| {
            #[cfg(test)]
            {
                self.syncs += 1;
            }
            file.sync_data()
        });
        if let Err(error) = synced {
            self.file = None;
            match cut_back(&self.path, self.length) {
                Ok(file) => self.file = Some(file),
                Err(restore) => tracing::warn!(
                    target: "work_rule::catch_up",
                    path = %self.path.display(),
                    error = %restore,
                    "the catch-up grant file could not be restored after a failed write; no more blocks are admitted without a check in this run"
                ),
            }
            return Err(error);
        }
        self.length += GRANT_RECORD_BYTES as u64;
        self.ids.insert(block_id);
        Ok(())
    }
}

/// What the last full scan of the active blocks above the validated height
/// found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Coverage {
    /// The highest active height above the validated height whose block has
    /// neither a verified record nor a grant record, or the validated height.
    pub(crate) uncovered_floor: u64,
    /// The highest active height with a grant record, or 0.
    pub(crate) top_granted: u64,
}

/// A source's reported height and when it was reported.
#[derive(Clone, Copy, Debug)]
struct SourceView {
    height: u64,
    at: Instant,
}

/// The ids corroborating sources listed, each with a mask of those sources.
#[derive(Debug, Default)]
struct Vouched {
    sources: HashMap<[u8; 32], u8>,
    order: VecDeque<[u8; 32]>,
}

impl Vouched {
    fn mark(&mut self, block_id: [u8; 32], source: u8) {
        let mask = self.sources.entry(block_id).or_insert_with(|| {
            self.order.push_back(block_id);
            0
        });
        *mask |= 1 << source;
        while self.order.len() > MAX_VOUCHED {
            if let Some(oldest) = self.order.pop_front() {
                self.sources.remove(&oldest);
            }
        }
    }
}

/// The run of re-executed blocks ending at the tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TopRun {
    pub(crate) start: u64,
    pub(crate) top: u64,
    /// When the run was first seen.
    pub(crate) first_seen: Instant,
    /// When it was last seen to grow.
    pub(crate) last_growth: Instant,
}

impl TopRun {
    pub(crate) fn len(&self) -> u64 {
        self.top - self.start + 1
    }
}

/// Whether a run of `len` blocks re-executed here with `work` in total (if
/// it can be read) is enough for the blocks below it: at least `depth`
/// blocks and at least `depth` times the reference work `w_ref`.
pub(crate) fn run_qualifies(len: u64, work: Option<U512>, w_ref: U512, depth: u64) -> bool {
    len >= depth
        && work.is_some_and(|work| {
            U512::from(depth)
                .checked_mul(w_ref)
                .is_some_and(|needed| work >= needed)
        })
}

/// The work of the active blocks `start..=top`, from the cumulative work at
/// `top` and at `start - 1`.
fn run_work(cumulative_work: impl Fn(u64) -> Option<U512>, start: u64, top: u64) -> Option<U512> {
    cumulative_work(top)?.checked_sub(cumulative_work(start.checked_sub(1)?)?)
}

/// The topmost qualifying run among the active heights above `validated` up
/// to `tip`, as (first height, top height): a maximal run of blocks
/// re-executed here (`checked`) that starts above `validated + 1` and passes
/// [`run_qualifies`], its work read from `cumulative_work`. Heights are read
/// from the tip down; `visit` is called once per height read.
pub(crate) fn topmost_qualifying_run(
    validated: u64,
    tip: u64,
    checked: impl Fn(u64) -> bool,
    cumulative_work: impl Fn(u64) -> Option<U512>,
    w_ref: U512,
    depth: u64,
    mut visit: impl FnMut(),
) -> Option<(u64, u64)> {
    let mut top = None;
    for height in (validated.saturating_add(1)..=tip).rev() {
        visit();
        if checked(height) {
            top.get_or_insert(height);
            continue;
        }
        if let Some(top) = top.take() {
            let start = height + 1;
            if start > validated.saturating_add(1)
                && run_qualifies(
                    top - start + 1,
                    run_work(&cumulative_work, start, top),
                    w_ref,
                    depth,
                )
            {
                return Some((start, top));
            }
        }
    }
    // A run reaching down to `validated + 1` would have moved the validated
    // height past it.
    None
}

/// What the coverage of the active blocks above the validated height is
/// read from.
pub(crate) trait CoverageIndex {
    /// The id of the active block at `height`.
    fn active(&self, height: u64) -> Option<[u8; 32]>;
    /// Whether `block_id` has a verified record.
    fn verified(&self, block_id: &[u8; 32]) -> bool;
    /// Whether that record is a provisional one, which this node did not
    /// re-execute.
    fn provisional(&self, block_id: &[u8; 32]) -> bool;
    /// Whether `block_id` has a grant record.
    fn granted(&self, block_id: &[u8; 32]) -> bool;
    /// The cumulative work of the active chain up to `height`.
    fn cumulative_work(&self, height: u64) -> Option<U512>;
}

/// The state a full scan is valid for: the height of the tip it reached and
/// the id there, the store's revocation count and the reference work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScanKey {
    top: u64,
    top_id: [u8; 32],
    revocations: u64,
    w_ref: Option<U512>,
}

/// The coverage, the reference work, the run at the tip and the topmost
/// qualifying run, as [`CoverageTracker::refresh`] last found them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CoverageView {
    pub(crate) coverage: Coverage,
    pub(crate) w_ref: Option<U512>,
    pub(crate) top_run: Option<TopRun>,
    /// (first height, top height).
    pub(crate) best_run: Option<(u64, u64)>,
}

/// Keeps the coverage of the active blocks above the validated height, the
/// run of re-executed blocks at the tip and the topmost qualifying run up to
/// date. A tip extension reads only the new blocks. The full scan of the
/// blocks above the validated height runs again only when the block at the
/// height last reached is no longer active (a reorganisation), the store
/// revoked a record, or the reference work changed.
#[derive(Debug, Default)]
pub(crate) struct CoverageTracker {
    key: Option<ScanKey>,
    view: CoverageView,
    #[cfg(test)]
    pub(crate) visits: u64,
    #[cfg(test)]
    pub(crate) full_scans: u64,
}

impl CoverageTracker {
    fn visit(&mut self) {
        #[cfg(test)]
        {
            self.visits += 1;
        }
    }

    /// Brings the view up to date for the active chain in `index` up to
    /// `tip`, above `validated`, at `now`. `reference` gives the reference
    /// work from the coverage just found, and whether this is the first
    /// refresh.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn refresh(
        &mut self,
        index: &impl CoverageIndex,
        validated: u64,
        tip: u64,
        revocations: u64,
        depth: u64,
        now: Instant,
        reference: impl FnOnce(&Coverage, bool) -> Option<U512>,
    ) -> CoverageView {
        let first = self.key.is_none();
        self.visit();
        let chain_unchanged = self.key.is_some_and(|key| {
            key.revocations == revocations && index.active(key.top) == Some(key.top_id)
        });
        if !chain_unchanged {
            self.scan_coverage(index, validated, tip);
        }
        let w_ref = reference(&self.view.coverage, first);
        let reference_unchanged = self.key.is_some_and(|key| key.w_ref == w_ref);
        match self.key {
            Some(key) if chain_unchanged && reference_unchanged => {
                self.extend(index, validated, key.top, tip, w_ref, depth, now);
            }
            _ => {
                if chain_unchanged {
                    self.scan_coverage(index, validated, tip);
                }
                self.scan_runs(index, validated, tip, w_ref, depth, now);
            }
        }
        self.view.w_ref = w_ref;
        self.key = index.active(tip).map(|top_id| ScanKey {
            top: tip,
            top_id,
            revocations,
            w_ref,
        });
        self.view
    }

    /// The view as last refreshed.
    #[cfg(test)]
    pub(crate) fn view(&self) -> CoverageView {
        self.view
    }

    /// A granted block at `height` was committed.
    pub(crate) fn raise_top_granted(&mut self, height: u64) {
        let coverage = &mut self.view.coverage;
        coverage.top_granted = coverage.top_granted.max(height);
    }

    fn scan_coverage(&mut self, index: &impl CoverageIndex, validated: u64, tip: u64) {
        let mut coverage = Coverage {
            uncovered_floor: validated,
            top_granted: 0,
        };
        for height in validated.saturating_add(1)..=tip {
            self.visit();
            let Some(block_id) = index.active(height) else {
                break;
            };
            let granted = index.granted(&block_id);
            if granted {
                coverage.top_granted = height;
            } else if !index.verified(&block_id) {
                coverage.uncovered_floor = height;
            }
        }
        self.view.coverage = coverage;
    }

    fn scan_runs(
        &mut self,
        index: &impl CoverageIndex,
        validated: u64,
        tip: u64,
        w_ref: Option<U512>,
        depth: u64,
        now: Instant,
    ) {
        #[cfg(test)]
        {
            self.full_scans += 1;
        }
        let checked = |height: u64| {
            index
                .active(height)
                .is_some_and(|block_id| index.verified(&block_id) && !index.provisional(&block_id))
        };
        let mut visits = 0_u64;
        self.view.best_run = w_ref.and_then(|w_ref| {
            topmost_qualifying_run(
                validated,
                tip,
                checked,
                |height| index.cumulative_work(height),
                w_ref,
                depth,
                || visits += 1,
            )
        });
        let mut start = None;
        for height in (validated.saturating_add(1)..=tip).rev() {
            visits += 1;
            if !checked(height) {
                break;
            }
            start = Some(height);
        }
        #[cfg(test)]
        {
            self.visits += visits;
        }
        #[cfg(not(test))]
        let _ = visits;
        let previous = self.view.top_run;
        self.view.top_run = start.map(|start| match previous {
            // The same run, seen again after a rescan.
            Some(run) if run.start == start && run.top <= tip => TopRun {
                top: tip,
                last_growth: if run.top < tip { now } else { run.last_growth },
                ..run
            },
            _ => TopRun {
                start,
                top: tip,
                first_seen: now,
                last_growth: now,
            },
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn extend(
        &mut self,
        index: &impl CoverageIndex,
        validated: u64,
        from: u64,
        tip: u64,
        w_ref: Option<U512>,
        depth: u64,
        now: Instant,
    ) {
        for height in from.saturating_add(1)..=tip {
            self.visit();
            let Some(block_id) = index.active(height) else {
                break;
            };
            let granted = index.granted(&block_id);
            let verified = index.verified(&block_id);
            let coverage = &mut self.view.coverage;
            if granted {
                coverage.top_granted = coverage.top_granted.max(height);
            } else if !verified {
                coverage.uncovered_floor = coverage.uncovered_floor.max(height);
            }
            if !verified || index.provisional(&block_id) {
                self.view.top_run = None;
                continue;
            }
            let run = match self.view.top_run {
                Some(run) if run.top + 1 == height => TopRun {
                    top: height,
                    last_growth: now,
                    ..run
                },
                _ => TopRun {
                    start: height,
                    top: height,
                    first_seen: now,
                    last_growth: now,
                },
            };
            self.view.top_run = Some(run);
            if let Some(w_ref) = w_ref
                && run.start > validated.saturating_add(1)
                && run_qualifies(
                    run.len(),
                    run_work(|height| index.cumulative_work(height), run.start, run.top),
                    w_ref,
                    depth,
                )
            {
                self.view.best_run = Some((run.start, run.top));
            }
        }
    }
}

/// What the status row of a desktop wallet catching up is chosen from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CatchUpFacts {
    pub(crate) tip: u64,
    pub(crate) validated: u64,
    pub(crate) available: u64,
    pub(crate) depth: u64,
    /// The highest height a source with a fresh view reported.
    pub(crate) highest_view: Option<u64>,
    /// Whether the release is fresh; `None` while the checkpoint block's
    /// time is unread. Not fresh when the clock cannot be read.
    pub(crate) release_fresh: Option<bool>,
    pub(crate) reference_known: bool,
    /// A corroborating source listed a block not stored here within
    /// [`VIEW_FRESH`].
    pub(crate) probe_hit_fresh: bool,
    /// The tip block has a grant record.
    pub(crate) tip_granted: bool,
    pub(crate) burial_pending: bool,
    /// The length of the run of re-executed blocks ending at the tip; 0
    /// when the tip block was not re-executed here.
    pub(crate) top_run_len: u64,
    /// That run has at least the depth's worth of the reference work.
    pub(crate) top_run_work_ok: bool,
    pub(crate) uncovered_floor: u64,
}

/// The status row: state, reason and blocks left. The first row that
/// matches wins, and so does the first reason.
pub(crate) fn catch_up_row(facts: &CatchUpFacts) -> (&'static str, Option<&'static str>, u64) {
    let tip = facts.tip;
    let behind = facts
        .highest_view
        .filter(|highest| *highest >= tip.saturating_add(facts.depth));
    let ahead = facts
        .highest_view
        .map_or(0, |highest| highest.saturating_sub(tip));
    let newest_checked = facts.top_run_len.min(facts.depth);
    let below_tip = tip.saturating_sub(facts.validated);
    if behind.is_some() && facts.release_fresh == Some(false) {
        return ("release_stale", None, ahead);
    }
    if behind.is_some() && facts.reference_known && !facts.probe_hit_fresh {
        return ("single_source", None, ahead);
    }
    if facts.available >= tip {
        return ("caught_up", None, below_tip);
    }
    if facts.tip_granted {
        return ("catching_up", None, ahead);
    }
    if facts.top_run_len > 0 && facts.burial_pending && newest_checked < facts.depth {
        return ("checking_newest", None, facts.depth - newest_checked);
    }
    if facts.uncovered_floor > facts.validated {
        return (
            "waiting_for_check",
            Some("earlier_blocks"),
            facts.uncovered_floor - facts.validated,
        );
    }
    if facts.reference_known && facts.top_run_len >= facts.depth && !facts.top_run_work_ok {
        return ("waiting_for_check", Some("difficulty"), below_tip);
    }
    ("waiting_for_check", Some("other"), below_tip)
}

/// What the catch-up did since it was turned on, as the session summary
/// reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CatchUpCounts {
    /// Blocks admitted without an engine run.
    pub(crate) granted: u64,
    /// Blocks at or below a session's depth limit whose work was computed
    /// instead, by the first grant condition they failed: index 0 is
    /// condition 2, and the last is a grant record that could not be
    /// written.
    pub(crate) refused: [u64; 8],
    /// Blocks at or below a session's depth limit left for later because
    /// their sender used up its one-engine refusals.
    pub(crate) throttled: u64,
    pub(crate) probe_attempts: u64,
    /// Answers that listed no block not stored here.
    pub(crate) probe_misses: u64,
    /// Connections that ended before an answer.
    pub(crate) probe_failures: u64,
    /// How long the last corroboration took, in milliseconds.
    pub(crate) last_probe_ms: u64,
}

impl CatchUpCounts {
    /// Blocks refused under grant condition `condition` (2 to 9).
    pub(crate) fn refused(&self, condition: u8) -> u64 {
        usize::from(condition)
            .checked_sub(2)
            .and_then(|index| self.refused.get(index))
            .copied()
            .unwrap_or(0)
    }
}

/// A desktop wallet's catch-up state. Everything but the grant file is in
/// memory and rebuilt from the index, the store and the grant file at start.
pub(crate) struct WalletCatchUp {
    sources: Vec<CatchUpSource>,
    grant_file: Mutex<GrantFile>,
    tracker: Mutex<CoverageTracker>,
    w_ref: Mutex<Option<U512>>,
    checkpoint_time: Mutex<Option<u64>>,
    /// When reading the checkpoint block's time last failed.
    checkpoint_time_failed: Mutex<Option<Instant>>,
    views: Mutex<Vec<Option<SourceView>>>,
    probe_failed: Mutex<Vec<Option<Instant>>>,
    last_probe_hit: Mutex<Option<Instant>>,
    last_source_progress: Mutex<Option<Instant>>,
    /// A record of an unsettled block could not be written.
    store_failed: AtomicBool,
    vouched: Mutex<Vouched>,
    /// Granted ids waiting for their block's commit, oldest first.
    grants: Mutex<VecDeque<[u8; 32]>>,
    last_grant: Mutex<Option<Instant>>,
    counts: Mutex<CatchUpCounts>,
    /// When each source's session summary was last logged.
    summary_logged: Mutex<Vec<Option<Instant>>>,
    /// The prune-lag refusal has been logged.
    prune_lag_logged: AtomicBool,
    /// A failed grant record has been logged since the last one written.
    grant_file_logged: AtomicBool,
    #[cfg(test)]
    depth: AtomicU64,
    #[cfg(test)]
    view_fresh: Mutex<Option<Duration>>,
    #[cfg(test)]
    probe_fail_hold: Mutex<Option<Duration>>,
}

impl WalletCatchUp {
    /// The state for `sources` (as [`valid_sources`] returns them) over an
    /// open grant file.
    pub(crate) fn new(sources: Vec<CatchUpSource>, grant_file: GrantFile) -> Self {
        let count = sources.len();
        Self {
            sources,
            grant_file: Mutex::new(grant_file),
            tracker: Mutex::new(CoverageTracker::default()),
            w_ref: Mutex::new(None),
            checkpoint_time: Mutex::new(None),
            checkpoint_time_failed: Mutex::new(None),
            views: Mutex::new(vec![None; count]),
            probe_failed: Mutex::new(vec![None; count]),
            last_probe_hit: Mutex::new(None),
            last_source_progress: Mutex::new(None),
            store_failed: AtomicBool::new(false),
            vouched: Mutex::new(Vouched::default()),
            grants: Mutex::new(VecDeque::new()),
            last_grant: Mutex::new(None),
            counts: Mutex::new(CatchUpCounts::default()),
            summary_logged: Mutex::new(vec![None; count]),
            prune_lag_logged: AtomicBool::new(false),
            grant_file_logged: AtomicBool::new(false),
            #[cfg(test)]
            depth: AtomicU64::new(WALLET_CATCH_UP_DEPTH),
            #[cfg(test)]
            view_fresh: Mutex::new(None),
            #[cfg(test)]
            probe_fail_hold: Mutex::new(None),
        }
    }

    /// [`WALLET_CATCH_UP_DEPTH`].
    #[cfg(not(test))]
    pub(crate) fn depth(&self) -> u64 {
        WALLET_CATCH_UP_DEPTH
    }

    /// [`WALLET_CATCH_UP_DEPTH`], or a test's.
    #[cfg(test)]
    pub(crate) fn depth(&self) -> u64 {
        self.depth.load(Ordering::Relaxed)
    }

    fn view_fresh(&self) -> Duration {
        #[cfg(test)]
        if let Some(fresh) = *lock(&self.view_fresh) {
            return fresh;
        }
        VIEW_FRESH
    }

    fn probe_fail_hold(&self) -> Duration {
        #[cfg(test)]
        if let Some(hold) = *lock(&self.probe_fail_hold) {
            return hold;
        }
        PROBE_FAIL_HOLD
    }

    /// Sets a test's depth; the next coverage refresh scans in full.
    #[cfg(test)]
    pub(crate) fn set_depth(&self, depth: u64) {
        self.depth.store(depth, Ordering::Relaxed);
        lock(&self.tracker).key = None;
    }

    #[cfg(test)]
    pub(crate) fn set_view_fresh(&self, fresh: Duration) {
        *lock(&self.view_fresh) = Some(fresh);
    }

    #[cfg(test)]
    pub(crate) fn set_probe_fail_hold(&self, hold: Duration) {
        *lock(&self.probe_fail_hold) = Some(hold);
    }

    /// The index of the source at `addr`, if it is one: the whole address,
    /// port included, must match.
    pub(crate) fn source_index(&self, addr: SocketAddr) -> Option<u8> {
        self.sources
            .iter()
            .position(|source| source.addr == addr)
            .and_then(|index| u8::try_from(index).ok())
    }

    /// The address of `source`.
    pub(crate) fn source_addr(&self, source: u8) -> Option<SocketAddr> {
        self.sources
            .get(usize::from(source))
            .map(|source| source.addr)
    }

    fn group(&self, source: u8) -> Option<u8> {
        self.sources
            .get(usize::from(source))
            .map(|source| source.group)
    }

    /// Records that `source` reported `height` at `now` and listed `ids`.
    pub(crate) fn note_view(&self, source: u8, height: u64, ids: &[[u8; 32]], now: Instant) {
        {
            let mut views = lock(&self.views);
            let Some(view) = views.get_mut(usize::from(source)) else {
                return;
            };
            *view = Some(SourceView { height, at: now });
        }
        let mut vouched = lock(&self.vouched);
        for block_id in ids {
            vouched.mark(*block_id, source);
        }
    }

    /// Records that a source session committed a block at `now`.
    pub(crate) fn note_source_progress(&self, now: Instant) {
        *lock(&self.last_source_progress) = Some(now);
    }

    fn fresh(&self, at: Instant, now: Instant) -> bool {
        now.saturating_duration_since(at) <= self.view_fresh()
    }

    /// `source`'s reported height, if its view is fresh at `now`.
    fn fresh_height(&self, source: u8, now: Instant) -> Option<u64> {
        lock(&self.views)
            .get(usize::from(source))
            .copied()
            .flatten()
            .filter(|view| self.fresh(view.at, now))
            .map(|view| view.height)
    }

    /// Whether sources in at least two groups have fresh views at least the
    /// depth above `local`, and a source session committed a block recently.
    pub(crate) fn sources_ahead(&self, local: u64, now: Instant) -> bool {
        let progress = lock(&self.last_source_progress).is_some_and(|at| self.fresh(at, now));
        let wanted = local.saturating_add(self.depth());
        let groups = (0..self.sources.len())
            .filter_map(|index| u8::try_from(index).ok())
            .filter(|source| {
                self.fresh_height(*source, now)
                    .is_some_and(|height| height >= wanted)
            })
            .filter_map(|source| self.group(source))
            .collect::<HashSet<_>>();
        progress && groups.len() >= 2
    }

    /// Whether a source in a group other than `source`'s listed `block_id`,
    /// its view is fresh at `now`, and `height` is at least the depth below
    /// its reported height.
    pub(crate) fn vouched_by_other(
        &self,
        block_id: &[u8; 32],
        source: u8,
        height: u64,
        now: Instant,
    ) -> bool {
        let Some(group) = self.group(source) else {
            return false;
        };
        let mask = lock(&self.vouched)
            .sources
            .get(block_id)
            .copied()
            .unwrap_or(0);
        (0..self.sources.len())
            .filter_map(|index| u8::try_from(index).ok())
            .filter(|other| mask & (1 << other) != 0 && self.group(*other) != Some(group))
            .any(|other| {
                self.fresh_height(other, now)
                    .and_then(|reported| reported.checked_sub(self.depth()))
                    .is_some_and(|limit| height <= limit)
            })
    }

    /// The sources a session with `source` asks to corroborate its blocks, in
    /// order: those in other groups, in list order after `source` and
    /// wrapping around, each once, without one that failed within
    /// [`PROBE_FAIL_HOLD`] of `now`.
    pub(crate) fn probe_candidates(&self, source: u8, now: Instant) -> Vec<u8> {
        let count = self.sources.len();
        let Some(group) = self.group(source) else {
            return Vec::new();
        };
        let failed = lock(&self.probe_failed);
        (1..count)
            .map(|step| (usize::from(source) + step) % count)
            .filter(|&index| self.sources[index].group != group)
            .filter(|&index| {
                failed[index]
                    .is_none_or(|at| now.saturating_duration_since(at) >= self.probe_fail_hold())
            })
            .filter_map(|index| u8::try_from(index).ok())
            .collect()
    }

    /// Records that a corroborating connection to `source` failed at `now`.
    pub(crate) fn note_probe_failed(&self, source: u8, now: Instant) {
        if let Some(slot) = lock(&self.probe_failed).get_mut(usize::from(source)) {
            *slot = Some(now);
        }
        lock(&self.counts).probe_failures += 1;
    }

    /// Records that a corroborating source listed a block not stored here.
    pub(crate) fn note_probe_hit(&self, now: Instant) {
        *lock(&self.last_probe_hit) = Some(now);
    }

    /// Records that a corroborating connection is being opened.
    pub(crate) fn note_probe_attempt(&self) {
        lock(&self.counts).probe_attempts += 1;
    }

    /// Records that a corroborating source listed no block not stored here.
    pub(crate) fn note_probe_miss(&self) {
        lock(&self.counts).probe_misses += 1;
    }

    /// Records how long a session's corroboration took.
    pub(crate) fn note_probe_elapsed(&self, elapsed: Duration) {
        lock(&self.counts).last_probe_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    }

    /// Records that a block at or below a session's depth limit was not
    /// granted, for `refusal`, and so has its work computed.
    pub(crate) fn note_refusal(&self, refusal: GrantRefusal) {
        let index = usize::from(refusal.condition()).saturating_sub(2);
        if let Some(count) = lock(&self.counts).refused.get_mut(index) {
            *count += 1;
        }
    }

    /// Records that a block at or below a session's depth limit was left for
    /// later: its sender used up its one-engine refusals.
    pub(crate) fn note_throttled(&self) {
        lock(&self.counts).throttled += 1;
    }

    /// What the catch-up did since it was turned on.
    pub(crate) fn counts(&self) -> CatchUpCounts {
        *lock(&self.counts)
    }

    /// Logs the summary of a sync session with `source`, which reported
    /// `reported`, and the source that corroborated its blocks with the
    /// height that one reported, unless `source`'s summary was logged within
    /// a minute of `now`. The counts are those since the catch-up was turned
    /// on, so a summary left out loses nothing. Returns whether it logged.
    pub(crate) fn log_session_summary(
        &self,
        source: u8,
        reported: u64,
        voucher: Option<(u8, u64)>,
        now: Instant,
    ) -> bool {
        {
            let mut logged = lock(&self.summary_logged);
            let Some(slot) = logged.get_mut(usize::from(source)) else {
                return false;
            };
            if slot.is_some_and(|at| now.saturating_duration_since(at) < SESSION_SUMMARY_INTERVAL) {
                return false;
            }
            *slot = Some(now);
        }
        let counts = self.counts();
        let address = |source: u8| {
            self.source_addr(source)
                .map_or_else(|| "none".to_owned(), |addr| addr.to_string())
        };
        let since_last_grant =
            lock(&self.last_grant).map(|at| now.saturating_duration_since(at).as_secs());
        tracing::info!(
            target: "work_rule::catch_up",
            source = %address(source),
            reported,
            voucher = %voucher.map_or_else(|| "none".to_owned(), |(voucher, _)| address(voucher)),
            voucher_reported = voucher.map_or(0, |(_, height)| height),
            granted = counts.granted,
            checked_not_vouched = counts.refused(2),
            checked_not_tip = counts.refused(3),
            checked_known = counts.refused(4),
            checked_easing = counts.refused(5),
            checked_not_ready = counts.refused(6),
            checked_release_stale = counts.refused(7),
            checked_prune_lag = counts.refused(8),
            checked_grant_file = counts.refused(9),
            deferred_sender = counts.throttled,
            probe_attempts = counts.probe_attempts,
            probe_misses = counts.probe_misses,
            probe_failures = counts.probe_failures,
            last_probe_ms = counts.last_probe_ms,
            since_last_grant_secs = ?since_last_grant,
            "catch-up sync session"
        );
        true
    }

    /// A record of an unsettled block could not be written: no more grants
    /// in this process.
    pub(crate) fn set_store_failed(&self) {
        self.store_failed.store(true, Ordering::Release);
    }

    pub(crate) fn store_failed(&self) -> bool {
        self.store_failed.load(Ordering::Acquire)
    }

    /// Whether `block_id` has a grant record.
    pub(crate) fn recorded_grant(&self, block_id: &[u8; 32]) -> bool {
        lock(&self.grant_file).contains(block_id)
    }

    /// Records the grant of `block_id` at `height` in the grant file, synced,
    /// then lets its commit use it.
    pub(crate) fn grant(&self, height: u64, block_id: [u8; 32], now: Instant) -> io::Result<()> {
        lock(&self.grant_file).append(height, block_id)?;
        self.grant_file_logged.store(false, Ordering::Release);
        let mut grants = lock(&self.grants);
        grants.push_back(block_id);
        while grants.len() > MAX_GRANTS {
            grants.pop_front();
        }
        drop(grants);
        *lock(&self.last_grant) = Some(now);
        lock(&self.counts).granted += 1;
        Ok(())
    }

    /// Whether `block_id` was granted and its commit has not used it yet.
    pub(crate) fn has_grant(&self, block_id: &[u8; 32]) -> bool {
        lock(&self.grants).contains(block_id)
    }

    /// Takes the grant of `block_id` for its commit. Returns whether there
    /// was one.
    pub(crate) fn take_grant(&self, block_id: &[u8; 32]) -> bool {
        let mut grants = lock(&self.grants);
        match grants.iter().position(|granted| granted == block_id) {
            Some(position) => {
                grants.remove(position);
                true
            }
            None => false,
        }
    }

    /// The coverage as last refreshed.
    #[cfg(test)]
    pub(crate) fn coverage(&self) -> Coverage {
        lock(&self.tracker).view().coverage
    }

    /// Brings the coverage up to date; see [`CoverageTracker::refresh`].
    pub(crate) fn refresh_coverage(
        &self,
        index: &impl CoverageIndex,
        validated: u64,
        tip: u64,
        revocations: u64,
        now: Instant,
        reference: impl FnOnce(&Coverage, bool) -> Option<U512>,
    ) -> CoverageView {
        lock(&self.tracker).refresh(
            index,
            validated,
            tip,
            revocations,
            self.depth(),
            now,
            reference,
        )
    }

    /// A granted block at `height` was committed.
    pub(crate) fn raise_top_granted(&self, height: u64) {
        lock(&self.tracker).raise_top_granted(height);
    }

    /// The highest height a source with a fresh view at `now` reported, and
    /// how many sources have one.
    pub(crate) fn fresh_views(&self, now: Instant) -> (Option<u64>, u8) {
        let heights = (0..self.sources.len())
            .filter_map(|index| u8::try_from(index).ok())
            .filter_map(|source| self.fresh_height(source, now))
            .collect::<Vec<_>>();
        (
            heights.iter().copied().max(),
            u8::try_from(heights.len()).unwrap_or(u8::MAX),
        )
    }

    /// Whether a corroborating source listed a block not stored here within
    /// [`VIEW_FRESH`] of `now`.
    pub(crate) fn probe_hit_fresh(&self, now: Instant) -> bool {
        lock(&self.last_probe_hit).is_some_and(|at| self.fresh(at, now))
    }

    pub(crate) fn reference_work(&self) -> Option<U512> {
        *lock(&self.w_ref)
    }

    pub(crate) fn set_reference_work(&self, w_ref: Option<U512>) {
        *lock(&self.w_ref) = w_ref;
    }

    pub(crate) fn checkpoint_time(&self) -> Option<u64> {
        *lock(&self.checkpoint_time)
    }

    pub(crate) fn set_checkpoint_time(&self, time: u64) {
        *lock(&self.checkpoint_time) = Some(time);
    }

    /// Whether this is the first prune-lag refusal of the process.
    pub(crate) fn first_prune_lag_refusal(&self) -> bool {
        !self.prune_lag_logged.swap(true, Ordering::AcqRel)
    }

    /// Whether this is the first failed grant record since one was written.
    pub(crate) fn first_grant_file_failure(&self) -> bool {
        !self.grant_file_logged.swap(true, Ordering::AcqRel)
    }

    /// Whether the grant file stopped taking records in this process.
    pub(crate) fn grant_file_stopped(&self) -> bool {
        lock(&self.grant_file).stopped()
    }

    /// Whether the checkpoint block's time may be read at `now`: no read
    /// failed within [`CHECKPOINT_TIME_RETRY`] before it.
    pub(crate) fn checkpoint_time_read_due(&self, now: Instant) -> bool {
        lock(&self.checkpoint_time_failed)
            .is_none_or(|failed| now.saturating_duration_since(failed) >= CHECKPOINT_TIME_RETRY)
    }

    /// Reading the checkpoint block's time failed at `now`. Returns whether
    /// this is the first failure of the process.
    pub(crate) fn note_checkpoint_time_failed(&self, now: Instant) -> bool {
        lock(&self.checkpoint_time_failed).replace(now).is_none()
    }

    #[cfg(test)]
    pub(crate) fn grant_file_syncs(&self) -> u64 {
        lock(&self.grant_file).syncs
    }

    #[cfg(test)]
    pub(crate) fn fail_next_grant_write(&self) {
        lock(&self.grant_file).fail_next_write = true;
    }

    /// Full scans and heights read by the coverage so far.
    #[cfg(test)]
    pub(crate) fn coverage_reads(&self) -> (u64, u64) {
        let tracker = lock(&self.tracker);
        (tracker.full_scans, tracker.visits)
    }

    #[cfg(test)]
    pub(crate) fn pending_grants(&self) -> Vec<[u8; 32]> {
        lock(&self.grants).iter().copied().collect()
    }
}
