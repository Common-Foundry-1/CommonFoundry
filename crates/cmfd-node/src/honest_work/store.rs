//! Persisted work-check results and the halt marker.
//!
//! [`WorkStatusStore`] keeps which blocks above the release checkpoint have
//! been checked (`work-status.v1`). It is append-only: a header that binds the
//! file to one network and one release checkpoint, then fixed-size records,
//! each with its own check value. A torn or damaged record is ignored, so the
//! block it named is simply checked again; nothing is trusted from it. A file
//! for another network or checkpoint is replaced by an empty one.
//!
//! A match this node did not compute itself (a pool's own replay result) is
//! recorded as provisional: it admits the block like a verified one, but the
//! node's own engines check it again, after a restart too, and only then is
//! it recorded verified.
//!
//! A mismatch found by this node's own engine that no independent engine
//! confirmed is recorded as unsettled. That is not a verdict: the block
//! counts as unchecked, as if nothing were recorded, and the node computes it
//! again only on a bounded schedule (see the work backlog). An unsettled
//! record replaces a provisional one.
//!
//! A block is recorded as invalid only with a [`ConfirmedWorkMismatch`] for
//! that block's challenge digest, and the halt marker (`halt.v1`) can only be
//! written with one too. Once a block is recorded, the other status is
//! refused (`InvalidInput`) until an operator reconsiders it: that error means
//! the engines and the store disagree about the block, and the caller raises
//! the engine-divergence alarm rather than treating it as a disk failure.
//!
//! A caller that cannot write the halt marker treats the node as halted all
//! the same.
//!
//! A failed compaction never loses the store: the old file stays in place,
//! appends continue, and compaction is tried again later.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use super::ConfirmedWorkMismatch;

/// File name of the work-status store in a node's data directory.
pub const WORK_STATUS_FILE: &str = "work-status.v1";
/// File name of the halt marker in a node's data directory.
pub const WORK_HALT_FILE: &str = "halt.v1";
/// File name of a desktop wallet's catch-up grant records, beside the store.
/// Any repair of the store, and any reconsidered record, removes it (and its
/// temporary file) first, so no block whose status this store lost is still
/// listed there.
pub const CATCH_UP_GRANTS_FILE: &str = "catch-up-grants.v1";
/// Invalid blocks kept in memory; the oldest is forgotten first and dropped
/// from the file at the next compaction.
pub const MAX_INVALID_BLOCKS: usize = 1_024;
/// The file is compacted once it holds at least this many records and more
/// than twice as many as are live.
const COMPACT_MIN_RECORDS: u64 = 1_024;

const STATUS_MAGIC: [u8; 8] = *b"CMFDWS01";
const HALT_MAGIC: [u8; 8] = *b"CMFDWH01";
const STATUS_CHECK_DOMAIN: &str = "CommonFoundry/WorkStatus/Record/v1";
const HALT_CHECK_DOMAIN: &str = "CommonFoundry/WorkStatus/Halt/v1";
const CHECK_BYTES: usize = 8;
/// Magic, network id, checkpoint height, checkpoint block id, check.
const HEADER_BYTES: usize = 8 + 32 + 8 + 32 + CHECK_BYTES;
/// Tag, height, block id, check.
const RECORD_BYTES: usize = 1 + 8 + 32 + CHECK_BYTES;
/// Magic, network id, height, block id, challenge digest, check.
const HALT_BYTES: usize = 8 + 32 + 8 + 32 + 32 + CHECK_BYTES;

const TAG_VERIFIED: u8 = 1;
const TAG_INVALID: u8 = 2;
const TAG_RECONSIDER: u8 = 3;
const TAG_PROVISIONAL: u8 = 4;
const TAG_UNSETTLED: u8 = 5;

/// What the store knows about a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkStatus {
    /// Its work was re-executed and matched, here or (provisionally) by the
    /// pool that produced it.
    Verified,
    /// Two independent engines found its work does not match.
    Invalid,
}

/// What opening the store found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkStatusLoad {
    /// The file did not exist, or belonged to another network or checkpoint
    /// or had a damaged header, and was replaced by an empty one.
    pub started_empty: bool,
    /// Whole records skipped because their check value or tag was wrong.
    pub damaged_records: u64,
    /// Bytes of an incomplete last record, removed from the file.
    pub torn_bytes: u64,
}

/// The persisted verified/invalid set for one network and release checkpoint.
#[derive(Debug)]
pub struct WorkStatusStore {
    path: PathBuf,
    file: Option<File>,
    network_id: [u8; 32],
    checkpoint_height: u64,
    checkpoint_block_id: [u8; 32],
    status: HashMap<[u8; 32], (WorkStatus, u64)>,
    /// Verified blocks whose match this node's engines have not reproduced.
    provisional: HashSet<[u8; 32]>,
    /// Blocks this node's own engine found do not match, with no independent
    /// confirmation, and their heights. They have no status.
    unsettled: HashMap<[u8; 32], u64>,
    /// Times a verified block stopped being verified.
    revocations: u64,
    /// Invalid blocks, oldest first; may name blocks no longer invalid.
    invalid_order: VecDeque<[u8; 32]>,
    invalid_count: usize,
    records: u64,
    max_invalid: usize,
    compact_min_records: u64,
    /// After a failed compaction, the record count at which it is tried
    /// again.
    compact_retry_at: u64,
    #[cfg(test)]
    fail_next_rename: bool,
    #[cfg(test)]
    fail_next_write: bool,
}

impl WorkStatusStore {
    /// Opens (or creates) the store at `path` for `network_id` and the release
    /// checkpoint (`checkpoint_height`, `checkpoint_block_id`).
    pub fn open(
        path: &Path,
        network_id: [u8; 32],
        checkpoint_height: u64,
        checkpoint_block_id: [u8; 32],
    ) -> io::Result<(Self, WorkStatusLoad)> {
        let mut store = Self {
            path: path.to_path_buf(),
            file: None,
            network_id,
            checkpoint_height,
            checkpoint_block_id,
            status: HashMap::new(),
            provisional: HashSet::new(),
            unsettled: HashMap::new(),
            revocations: 0,
            invalid_order: VecDeque::new(),
            invalid_count: 0,
            records: 0,
            max_invalid: MAX_INVALID_BLOCKS,
            compact_min_records: COMPACT_MIN_RECORDS,
            compact_retry_at: 0,
            #[cfg(test)]
            fail_next_rename: false,
            #[cfg(test)]
            fail_next_write: false,
        };
        let mut load = WorkStatusLoad::default();
        let bytes = match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        match bytes {
            Some(bytes)
                if bytes.len() >= HEADER_BYTES && bytes[..HEADER_BYTES] == store.header() =>
            {
                let body = &bytes[HEADER_BYTES..];
                let whole = body.len() - body.len() % RECORD_BYTES;
                for record in body[..whole].chunks_exact(RECORD_BYTES) {
                    store.records += 1;
                    match store.decode(record) {
                        Some((tag, height, block_id)) => store.apply(tag, height, block_id),
                        None => load.damaged_records += 1,
                    }
                }
                load.torn_bytes = (body.len() - whole) as u64;
                let removed = if load.torn_bytes > 0 || load.damaged_records > 0 {
                    remove_catch_up_grants(path)?
                } else {
                    false
                };
                if load.torn_bytes > 0 {
                    // An append-only handle cannot truncate on every platform.
                    let file = OpenOptions::new().write(true).open(path)?;
                    file.set_len((HEADER_BYTES + whole) as u64)?;
                    file.sync_all()?;
                }
                // Rewritten without the damaged records, so the grant file
                // is not removed again at every start.
                if load.damaged_records > 0 && removed {
                    store.compact();
                }
                if store.file.is_none() {
                    store.file = Some(OpenOptions::new().append(true).open(path)?);
                }
            }
            _ => {
                load.started_empty = true;
                remove_catch_up_grants(path)?;
                store.rewrite()?;
            }
        }
        Ok((store, load))
    }

    /// Opens the store at `path` only if it exists and is for `network_id`
    /// and the release checkpoint, for an operator's change to a stopped
    /// node: unlike [`open`](Self::open), it never replaces the file. `None`
    /// if there is no store; `InvalidData` if it is for another network or
    /// checkpoint.
    pub fn open_existing(
        path: &Path,
        network_id: [u8; 32],
        checkpoint_height: u64,
        checkpoint_block_id: [u8; 32],
    ) -> io::Result<Option<Self>> {
        let mut header = [0_u8; HEADER_BYTES];
        match File::open(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
            Ok(mut file) => {
                let expected = status_header(network_id, checkpoint_height, checkpoint_block_id);
                if file.read_exact(&mut header).is_err() || header != expected {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the work-status store is not for this network and release checkpoint",
                    ));
                }
            }
        }
        Self::open(path, network_id, checkpoint_height, checkpoint_block_id)
            .map(|(store, _)| Some(store))
    }

    /// Blocks recorded as unsettled, as (height, block id), in no order.
    pub fn unsettled_blocks(&self) -> impl Iterator<Item = (u64, [u8; 32])> + '_ {
        self.unsettled
            .iter()
            .map(|(block_id, height)| (*height, *block_id))
    }

    /// The status of `block_id`, if it was checked.
    pub fn status(&self, block_id: &[u8; 32]) -> Option<WorkStatus> {
        self.status.get(block_id).map(|(status, _)| *status)
    }

    /// Blocks recorded as verified, provisional ones included.
    pub fn verified_count(&self) -> usize {
        self.status.len() - self.invalid_count
    }

    /// Whether `block_id` is verified only provisionally.
    pub fn is_provisional(&self, block_id: &[u8; 32]) -> bool {
        self.provisional.contains(block_id)
    }

    /// Provisionally verified blocks, as (height, block id), lowest first.
    pub fn provisional_blocks(&self) -> Vec<(u64, [u8; 32])> {
        let mut blocks: Vec<_> = self
            .provisional
            .iter()
            .map(|block_id| (self.status[block_id].1, *block_id))
            .collect();
        blocks.sort_unstable();
        blocks
    }

    /// Blocks recorded as invalid and still held in memory.
    pub fn invalid_count(&self) -> usize {
        self.invalid_count
    }

    /// Whether this node's own engine found that `block_id` does not match,
    /// with no independent confirmation.
    pub fn is_unsettled(&self, block_id: &[u8; 32]) -> bool {
        self.unsettled.contains_key(block_id)
    }

    /// How many times a block recorded verified (provisionally or not) has
    /// stopped being verified. A caller that remembers what was verified
    /// compares this to know whether its knowledge still holds.
    pub fn revocations(&self) -> u64 {
        self.revocations
    }

    /// Records that this node's engines found that `block_id` at `height`
    /// matched; a provisional record becomes a verified one. Blocks at or
    /// below the checkpoint are not recorded. A block recorded invalid is
    /// refused (`InvalidInput`): only [`reconsider`](Self::reconsider) clears
    /// that.
    pub fn mark_verified(&mut self, height: u64, block_id: [u8; 32]) -> io::Result<()> {
        if height <= self.checkpoint_height {
            return Ok(());
        }
        match self.status(&block_id) {
            Some(WorkStatus::Verified) if self.is_provisional(&block_id) => {
                self.append(TAG_VERIFIED, height, block_id)
            }
            Some(WorkStatus::Verified) => Ok(()),
            Some(WorkStatus::Invalid) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "block is recorded invalid; reconsider it first",
            )),
            None => self.append(TAG_VERIFIED, height, block_id),
        }
    }

    /// Records that `block_id` at `height` matched a result this node did not
    /// compute (a pool's own replay). Nothing is written for a block already
    /// verified. A block recorded invalid, or unsettled because this node's
    /// own engine found it does not match, is refused (`InvalidInput`).
    pub fn mark_provisional(&mut self, height: u64, block_id: [u8; 32]) -> io::Result<()> {
        if height <= self.checkpoint_height {
            return Ok(());
        }
        match self.status(&block_id) {
            Some(WorkStatus::Verified) => Ok(()),
            Some(WorkStatus::Invalid) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "block is recorded invalid; reconsider it first",
            )),
            None if self.is_unsettled(&block_id) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "this node's engine found the block does not match; reconsider it first",
            )),
            None => self.append(TAG_PROVISIONAL, height, block_id),
        }
    }

    /// Records that this node's own engine found that `block_id` at `height`
    /// does not match, and no independent engine confirmed it. A provisional
    /// record is replaced, so the block no longer counts as verified. Nothing
    /// is written for a block recorded invalid or already unsettled. A block
    /// recorded verified by this node's engines is refused (`InvalidInput`).
    pub fn mark_unsettled(&mut self, height: u64, block_id: [u8; 32]) -> io::Result<()> {
        if height <= self.checkpoint_height {
            return Ok(());
        }
        match self.status(&block_id) {
            Some(WorkStatus::Invalid) => Ok(()),
            Some(WorkStatus::Verified) if !self.is_provisional(&block_id) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "block is recorded verified; reconsider it first",
            )),
            None if self.is_unsettled(&block_id) => Ok(()),
            _ => self.append(TAG_UNSETTLED, height, block_id),
        }
    }

    /// Forgets the provisional records of `block_ids` (blocks this node no
    /// longer stores), so they are not admitted on the pool's word if they
    /// are offered again. Other records are left alone.
    pub fn forget_provisional(&mut self, block_ids: &[[u8; 32]]) -> io::Result<()> {
        for block_id in block_ids {
            if self.is_provisional(block_id) {
                let height = self.status[block_id].1;
                self.append(TAG_RECONSIDER, height, *block_id)?;
            }
        }
        Ok(())
    }

    /// Records that `block_id` at `height`, whose challenge digest is
    /// `challenge_digest`, is invalid. Only an independently confirmed
    /// mismatch for that challenge can be recorded; another is refused
    /// (`InvalidInput`). A block recorded verified by this node's engines is
    /// refused too (`InvalidInput`): only [`reconsider`](Self::reconsider)
    /// clears that. A provisional record is replaced.
    pub fn mark_invalid(
        &mut self,
        confirmed: &ConfirmedWorkMismatch,
        height: u64,
        block_id: [u8; 32],
        challenge_digest: [u8; 32],
    ) -> io::Result<()> {
        if confirmed.challenge_digest() != challenge_digest {
            return Err(mismatch_for_another_block());
        }
        if height <= self.checkpoint_height {
            return Ok(());
        }
        match self.status(&block_id) {
            Some(WorkStatus::Invalid) => Ok(()),
            Some(WorkStatus::Verified) if !self.is_provisional(&block_id) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "block is recorded verified; reconsider it first",
            )),
            _ => self.append(TAG_INVALID, height, block_id),
        }
    }

    /// Forgets what is recorded about `block_id`, so it is checked again, and
    /// compacts the file so the old record is gone from it too. Returns
    /// whether anything was recorded.
    pub fn reconsider(&mut self, block_id: [u8; 32]) -> io::Result<bool> {
        let height = match self.status.get(&block_id) {
            Some(&(_, height)) => height,
            None => match self.unsettled.get(&block_id) {
                Some(&height) => height,
                None => return Ok(false),
            },
        };
        remove_catch_up_grants(&self.path)?;
        self.append(TAG_RECONSIDER, height, block_id)?;
        self.compact();
        Ok(true)
    }

    fn header(&self) -> [u8; HEADER_BYTES] {
        status_header(
            self.network_id,
            self.checkpoint_height,
            self.checkpoint_block_id,
        )
    }

    /// Records are bound to the header, so one copied from another network's
    /// or checkpoint's file fails its check.
    fn record(&self, tag: u8, height: u64, block_id: [u8; 32]) -> [u8; RECORD_BYTES] {
        let mut record = [0_u8; RECORD_BYTES];
        record[0] = tag;
        record[1..9].copy_from_slice(&height.to_le_bytes());
        record[9..41].copy_from_slice(&block_id);
        let check = self.record_check(&record[..41]);
        record[41..].copy_from_slice(&check);
        record
    }

    fn record_check(&self, fields: &[u8]) -> [u8; CHECK_BYTES] {
        let mut hasher = blake3::Hasher::new_derive_key(STATUS_CHECK_DOMAIN);
        hasher.update(&self.network_id);
        hasher.update(&self.checkpoint_height.to_le_bytes());
        hasher.update(&self.checkpoint_block_id);
        hasher.update(fields);
        hasher.finalize().as_bytes()[..CHECK_BYTES]
            .try_into()
            .expect("check value length")
    }

    fn decode(&self, record: &[u8]) -> Option<(u8, u64, [u8; 32])> {
        if record[41..] != self.record_check(&record[..41])
            || !matches!(
                record[0],
                TAG_VERIFIED | TAG_INVALID | TAG_RECONSIDER | TAG_PROVISIONAL | TAG_UNSETTLED
            )
        {
            return None;
        }
        let height = u64::from_le_bytes(record[1..9].try_into().expect("eight bytes"));
        let block_id = record[9..41].try_into().expect("32 bytes");
        Some((record[0], height, block_id))
    }

    fn apply(&mut self, tag: u8, height: u64, block_id: [u8; 32]) {
        let before = self.status(&block_id);
        if before == Some(WorkStatus::Invalid) {
            self.invalid_count -= 1;
        }
        self.provisional.remove(&block_id);
        self.unsettled.remove(&block_id);
        match tag {
            TAG_VERIFIED if height > self.checkpoint_height => {
                self.status.insert(block_id, (WorkStatus::Verified, height));
            }
            TAG_PROVISIONAL if height > self.checkpoint_height => {
                self.status.insert(block_id, (WorkStatus::Verified, height));
                self.provisional.insert(block_id);
            }
            TAG_INVALID if height > self.checkpoint_height => {
                self.status.insert(block_id, (WorkStatus::Invalid, height));
                self.invalid_count += 1;
                self.invalid_order.push_back(block_id);
                self.evict_invalid();
            }
            TAG_UNSETTLED if height > self.checkpoint_height => {
                self.status.remove(&block_id);
                self.unsettled.insert(block_id, height);
            }
            _ => {
                self.status.remove(&block_id);
            }
        }
        if before == Some(WorkStatus::Verified) && self.status(&block_id) != before {
            self.revocations += 1;
        }
    }

    /// Records the file holds that are still live.
    fn live_records(&self) -> u64 {
        (self.status.len() + self.unsettled.len()) as u64
    }

    fn evict_invalid(&mut self) {
        while self.invalid_count > self.max_invalid {
            let Some(oldest) = self.invalid_order.pop_front() else {
                break;
            };
            if self.status(&oldest) == Some(WorkStatus::Invalid) {
                self.status.remove(&oldest);
                self.invalid_count -= 1;
            }
        }
    }

    fn append(&mut self, tag: u8, height: u64, block_id: [u8; 32]) -> io::Result<()> {
        let record = self.record(tag, height, block_id);
        let file = match &mut self.file {
            Some(file) => file,
            empty => empty.insert(OpenOptions::new().append(true).open(&self.path)?),
        };
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_write) {
            return Err(io::Error::other("write refused for the test"));
        }
        file.write_all(&record)?;
        file.sync_data()?;
        self.records += 1;
        self.apply(tag, height, block_id);
        if self.records >= self.compact_min_records
            && self.records > 2 * self.live_records()
            && self.records >= self.compact_retry_at
        {
            self.compact();
        }
        Ok(())
    }

    /// Compacts the file. A failure is logged and compaction is tried again
    /// after more appends; the records already written stay valid.
    fn compact(&mut self) {
        if let Err(error) = self.rewrite() {
            self.compact_retry_at = self.records + self.compact_min_records;
            tracing::warn!(
                target: "work_rule",
                path = %self.path.display(),
                %error,
                "work-status compaction failed; it will be tried again"
            );
        }
    }

    /// Writes the header and the live records to a new file, then puts it in
    /// place of the old one. Whatever happens, an append handle is kept on
    /// whichever complete file is then in place.
    fn rewrite(&mut self) -> io::Result<()> {
        let mut bytes =
            Vec::with_capacity(HEADER_BYTES + self.live_records() as usize * RECORD_BYTES);
        bytes.extend_from_slice(&self.header());
        let mut live = 0_u64;
        for (block_id, (status, height)) in &self.status {
            if *status == WorkStatus::Verified {
                let tag = if self.is_provisional(block_id) {
                    TAG_PROVISIONAL
                } else {
                    TAG_VERIFIED
                };
                bytes.extend_from_slice(&self.record(tag, *height, *block_id));
                live += 1;
            }
        }
        for (block_id, height) in &self.unsettled {
            bytes.extend_from_slice(&self.record(TAG_UNSETTLED, *height, *block_id));
            live += 1;
        }
        let mut seen = std::collections::HashSet::new();
        let mut order = VecDeque::new();
        for block_id in &self.invalid_order {
            if self.status(block_id) == Some(WorkStatus::Invalid) && seen.insert(*block_id) {
                let height = self.status[block_id].1;
                bytes.extend_from_slice(&self.record(TAG_INVALID, height, *block_id));
                order.push_back(*block_id);
                live += 1;
            }
        }
        let temporary = self.path.with_extension("v1.tmp");
        let replaced = self.replace_file(&temporary, &bytes);
        if replaced.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        if self.file.is_none() {
            self.file = Some(OpenOptions::new().append(true).open(&self.path)?);
        }
        replaced?;
        self.invalid_order = order;
        self.records = live;
        Ok(())
    }

    /// The next record written fails, as a full disk would.
    #[cfg(test)]
    pub(crate) fn fail_next_write(&mut self) {
        self.fail_next_write = true;
    }

    fn replace_file(&mut self, temporary: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = File::create(temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        // Some platforms cannot replace a file that is open.
        self.file = None;
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_rename) {
            return Err(io::Error::other("rename refused for the test"));
        }
        fs::rename(temporary, &self.path)?;
        sync_parent(&self.path)
    }
}

/// Removes the catch-up grant file beside the store at `store_path`, and its
/// temporary file. Returns whether either existed. A file that is not there is
/// fine; any other error is returned, so the store is not repaired while the
/// grant file may still list blocks the repair drops.
fn remove_catch_up_grants(store_path: &Path) -> io::Result<bool> {
    let mut removed = false;
    for name in [
        CATCH_UP_GRANTS_FILE.to_owned(),
        format!("{CATCH_UP_GRANTS_FILE}.tmp"),
    ] {
        match fs::remove_file(store_path.with_file_name(name)) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    if removed {
        sync_parent(store_path)?;
    }
    Ok(removed)
}

fn mismatch_for_another_block() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "confirmed mismatch is for another challenge",
    )
}

/// The node halted on this block: two independent engines found that a
/// block on its active chain does not match its work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkHalt {
    pub height: u64,
    pub block_id: [u8; 32],
    pub challenge_digest: [u8; 32],
}

/// Writes the halt marker at `path` for `block_id`, whose challenge digest is
/// `challenge_digest`; a confirmed mismatch for another challenge is refused
/// (`InvalidInput`). If a marker already exists it is kept and returned: the
/// first halt stands until an operator clears it.
///
/// The marker is written to `halt.v1.tmp` and then hard-linked into place, so
/// a torn marker is never left at `path`. Where the file system has no hard
/// links, it is written in place instead; a torn marker is then still caught
/// by its check value. An error means no marker was written, and the caller
/// must still treat the node as halted.
pub fn write_work_halt(
    path: &Path,
    network_id: [u8; 32],
    height: u64,
    block_id: [u8; 32],
    challenge_digest: [u8; 32],
    confirmed: &ConfirmedWorkMismatch,
) -> io::Result<WorkHalt> {
    if confirmed.challenge_digest() != challenge_digest {
        return Err(mismatch_for_another_block());
    }
    let halt = WorkHalt {
        height,
        block_id,
        challenge_digest: confirmed.challenge_digest(),
    };
    let mut bytes = Vec::with_capacity(HALT_BYTES);
    bytes.extend_from_slice(&HALT_MAGIC);
    bytes.extend_from_slice(&network_id);
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&block_id);
    bytes.extend_from_slice(&halt.challenge_digest);
    let check = check_value(HALT_CHECK_DOMAIN, &bytes);
    bytes.extend_from_slice(&check);
    // One writer at a time in this process, so the first halt wins and no
    // two writers share the temporary file.
    let _write = HALT_WRITE.lock().unwrap_or_else(PoisonError::into_inner);
    if path.exists() {
        return existing_work_halt(path, network_id);
    }
    let temporary = path.with_extension("v1.tmp");
    // A temporary file left by an interrupted write is removed first, so it
    // is never linked in place of the new marker.
    match fs::remove_file(&temporary) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    // A hard link never replaces an existing file.
    let linked = write_new_file(&temporary, &bytes).and_then(|()| hard_link(&temporary, path));
    let _ = fs::remove_file(&temporary);
    let placed = match linked {
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
            tracing::warn!(
                target: "work_rule",
                path = %path.display(),
                %error,
                "halt marker could not be linked into place; writing it in place"
            );
            write_new_file(path, &bytes)
        }
        other => other,
    };
    match placed {
        Ok(()) => {
            sync_parent(path)?;
            Ok(halt)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            existing_work_halt(path, network_id)
        }
        Err(error) => Err(error),
    }
}

static HALT_WRITE: Mutex<()> = Mutex::new(());

/// Creates `path`, which must not exist yet, holding `bytes`, and syncs it.
/// If the write fails the partial file is removed.
fn write_new_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    if written.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    written
}

#[cfg(test)]
thread_local! {
    static REFUSE_HARD_LINKS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn hard_link(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(test)]
    if REFUSE_HARD_LINKS.with(std::cell::Cell::get) {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    fs::hard_link(from, to)
}

fn existing_work_halt(path: &Path, network_id: [u8; 32]) -> io::Result<WorkHalt> {
    read_work_halt(path, network_id)?
        .ok_or_else(|| io::Error::other("halt marker vanished while being read"))
}

/// Reads the halt marker. A missing marker is `None`; a damaged one, or one
/// for another network, is an error, so a node never starts as if it were
/// not halted.
pub fn read_work_halt(path: &Path, network_id: [u8; 32]) -> io::Result<Option<WorkHalt>> {
    let mut bytes = Vec::with_capacity(HALT_BYTES);
    match File::open(path) {
        Ok(file) => {
            file.take(HALT_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let damaged = || io::Error::new(io::ErrorKind::InvalidData, "halt marker is damaged");
    if bytes.len() != HALT_BYTES
        || bytes[..8] != HALT_MAGIC
        || bytes[HALT_BYTES - CHECK_BYTES..]
            != check_value(HALT_CHECK_DOMAIN, &bytes[..HALT_BYTES - CHECK_BYTES])
    {
        return Err(damaged());
    }
    if bytes[8..40] != network_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "halt marker belongs to another network",
        ));
    }
    Ok(Some(WorkHalt {
        height: u64::from_le_bytes(bytes[40..48].try_into().expect("eight bytes")),
        block_id: bytes[48..80].try_into().expect("32 bytes"),
        challenge_digest: bytes[80..112].try_into().expect("32 bytes"),
    }))
}

/// Removes the halt marker if it names `block_id`. Returns whether it did.
pub fn clear_work_halt(path: &Path, network_id: [u8; 32], block_id: [u8; 32]) -> io::Result<bool> {
    match read_work_halt(path, network_id)? {
        Some(halt) if halt.block_id == block_id => {
            fs::remove_file(path)?;
            sync_parent(path)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn status_header(
    network_id: [u8; 32],
    checkpoint_height: u64,
    checkpoint_block_id: [u8; 32],
) -> [u8; HEADER_BYTES] {
    let mut header = [0_u8; HEADER_BYTES];
    header[..8].copy_from_slice(&STATUS_MAGIC);
    header[8..40].copy_from_slice(&network_id);
    header[40..48].copy_from_slice(&checkpoint_height.to_le_bytes());
    header[48..80].copy_from_slice(&checkpoint_block_id);
    let check = check_value(STATUS_CHECK_DOMAIN, &header[..80]);
    header[80..].copy_from_slice(&check);
    header
}

fn check_value(domain: &str, bytes: &[u8]) -> [u8; CHECK_BYTES] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(bytes);
    hasher.finalize().as_bytes()[..CHECK_BYTES]
        .try_into()
        .expect("check value length")
}

#[cfg(unix)]
pub(crate) fn sync_parent(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => File::open(parent)?.sync_all(),
        _ => Ok(()),
    }
}

#[cfg(not(unix))]
pub(crate) fn sync_parent(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: [u8; 32] = [0x11; 32];
    const CHECKPOINT: u64 = 100;
    const CHECKPOINT_ID: [u8; 32] = [0x22; 32];

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    const CHALLENGE: [u8; 32] = [0x33; 32];

    fn confirmed() -> ConfirmedWorkMismatch {
        ConfirmedWorkMismatch::for_test(CHALLENGE, [0x44; 32])
    }

    fn test_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cmfd-work-status-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn open(path: &Path) -> (WorkStatusStore, WorkStatusLoad) {
        WorkStatusStore::open(path, NETWORK, CHECKPOINT, CHECKPOINT_ID).unwrap()
    }

    #[test]
    fn statuses_survive_a_reopen() {
        let dir = test_dir("round-trip");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, load) = open(&path);
        assert!(load.started_empty);
        store.mark_verified(101, id(1)).unwrap();
        store.mark_verified(102, id(2)).unwrap();
        store
            .mark_invalid(&confirmed(), 103, id(3), CHALLENGE)
            .unwrap();
        store.mark_verified(CHECKPOINT, id(4)).unwrap();
        store.mark_verified(101, id(1)).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            (HEADER_BYTES + 3 * RECORD_BYTES) as u64,
            "at or below the checkpoint and repeats are not written"
        );
        drop(store);

        let (store, load) = open(&path);
        assert_eq!(load, WorkStatusLoad::default());
        assert_eq!(store.status(&id(1)), Some(WorkStatus::Verified));
        assert_eq!(store.status(&id(2)), Some(WorkStatus::Verified));
        assert_eq!(store.status(&id(3)), Some(WorkStatus::Invalid));
        assert_eq!(store.status(&id(4)), None);
        assert_eq!(store.verified_count(), 2);
        assert_eq!(store.invalid_count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reconsider_forgets_a_block_for_good() {
        let dir = test_dir("reconsider");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        store
            .mark_invalid(&confirmed(), 101, id(1), CHALLENGE)
            .unwrap();
        store.mark_verified(102, id(2)).unwrap();
        assert!(store.reconsider(id(1)).unwrap());
        assert!(!store.reconsider(id(9)).unwrap());
        assert_eq!(store.status(&id(1)), None);
        assert_eq!(store.invalid_count(), 0);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            (HEADER_BYTES + RECORD_BYTES) as u64,
            "compacted: the invalid record is gone from the file"
        );
        drop(store);
        let (store, _) = open(&path);
        assert_eq!(store.status(&id(1)), None);
        assert_eq!(store.status(&id(2)), Some(WorkStatus::Verified));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_provisional_match_survives_a_reopen_until_this_node_verifies_it() {
        let dir = test_dir("provisional");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        store.mark_provisional(102, id(2)).unwrap();
        store.mark_provisional(101, id(1)).unwrap();
        store.mark_provisional(103, id(3)).unwrap();
        store.mark_verified(104, id(4)).unwrap();
        store.mark_provisional(104, id(4)).unwrap();
        assert_eq!(store.status(&id(1)), Some(WorkStatus::Verified));
        assert!(
            !store.is_provisional(&id(4)),
            "a verified block stays verified"
        );
        drop(store);

        let (mut store, _) = open(&path);
        assert_eq!(
            store.provisional_blocks(),
            vec![(101, id(1)), (102, id(2)), (103, id(3))]
        );
        store.mark_verified(101, id(1)).unwrap();
        store
            .mark_invalid(&confirmed(), 103, id(3), CHALLENGE)
            .unwrap();
        assert_eq!(store.provisional_blocks(), vec![(102, id(2))]);
        assert_eq!(store.status(&id(3)), Some(WorkStatus::Invalid));
        assert_eq!(
            store.mark_provisional(103, id(3)).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        store.rewrite().unwrap();
        drop(store);

        let (store, _) = open(&path);
        assert_eq!(store.provisional_blocks(), vec![(102, id(2))]);
        assert_eq!(store.status(&id(1)), Some(WorkStatus::Verified));
        assert_eq!(store.status(&id(3)), Some(WorkStatus::Invalid));
        assert_eq!(store.verified_count(), 3);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_unsettled_block_counts_as_unchecked_and_survives_a_reopen() {
        let dir = test_dir("unsettled");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        store.mark_provisional(101, id(1)).unwrap();
        store.mark_unsettled(102, id(2)).unwrap();
        store.mark_verified(103, id(3)).unwrap();
        store.mark_verified(104, id(4)).unwrap();
        store.mark_provisional(105, id(5)).unwrap();
        assert_eq!(store.revocations(), 0);

        // A provisional record is replaced: the block is no longer verified.
        store.mark_unsettled(101, id(1)).unwrap();
        assert_eq!(store.status(&id(1)), None);
        assert!(store.is_unsettled(&id(1)) && !store.is_provisional(&id(1)));
        assert_eq!(store.revocations(), 1);
        // The pool's word does not bring it back; this node's engines can.
        assert_eq!(
            store.mark_provisional(101, id(1)).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            store.mark_unsettled(103, id(3)).unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
            "a block this node verified is not unsettled"
        );
        store.mark_unsettled(102, id(2)).unwrap();
        store.reconsider(id(4)).unwrap();
        assert_eq!(store.revocations(), 2);
        store.forget_provisional(&[id(5), id(3)]).unwrap();
        assert_eq!(store.status(&id(5)), None);
        assert_eq!(store.status(&id(3)), Some(WorkStatus::Verified));
        assert_eq!(store.revocations(), 3);
        drop(store);

        let (mut store, load) = open(&path);
        assert_eq!(load, WorkStatusLoad::default());
        assert!(store.is_unsettled(&id(1)) && store.is_unsettled(&id(2)));
        assert_eq!(store.status(&id(2)), None);
        assert_eq!(store.verified_count(), 1);
        assert!(store.provisional_blocks().is_empty());
        // Compaction keeps unsettled records.
        store.rewrite().unwrap();
        assert_eq!(store.records, 3);
        drop(store);
        let (mut store, _) = open(&path);
        assert!(store.is_unsettled(&id(1)) && store.is_unsettled(&id(2)));
        // A later verdict replaces it, and a reconsider forgets it.
        store.mark_verified(101, id(1)).unwrap();
        assert!(!store.is_unsettled(&id(1)));
        assert_eq!(store.status(&id(1)), Some(WorkStatus::Verified));
        assert!(store.reconsider(id(2)).unwrap());
        assert!(!store.is_unsettled(&id(2)));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_torn_last_record_is_dropped_and_appends_continue() {
        let dir = test_dir("torn");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        store.mark_verified(101, id(1)).unwrap();
        store.mark_verified(102, id(2)).unwrap();
        drop(store);
        let full = fs::metadata(&path).unwrap().len();
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(full - 5).unwrap();
        drop(file);

        let (mut store, load) = open(&path);
        assert_eq!(load.torn_bytes, (RECORD_BYTES - 5) as u64);
        assert_eq!(store.status(&id(1)), Some(WorkStatus::Verified));
        assert_eq!(store.status(&id(2)), None, "checked again");
        store.mark_verified(103, id(3)).unwrap();
        drop(store);
        let (store, load) = open(&path);
        assert_eq!(load, WorkStatusLoad::default());
        assert_eq!(store.status(&id(3)), Some(WorkStatus::Verified));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_flipped_byte_makes_only_that_block_unverified() {
        let dir = test_dir("flipped");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        store.mark_verified(101, id(1)).unwrap();
        store.mark_verified(102, id(2)).unwrap();
        store.mark_verified(103, id(3)).unwrap();
        drop(store);
        let mut bytes = fs::read(&path).unwrap();
        bytes[HEADER_BYTES + RECORD_BYTES + 20] ^= 0x01;
        fs::write(&path, &bytes).unwrap();

        let (store, load) = open(&path);
        assert_eq!(load.damaged_records, 1);
        assert_eq!(store.status(&id(1)), Some(WorkStatus::Verified));
        assert_eq!(store.status(&id(2)), None);
        assert_eq!(store.status(&id(3)), Some(WorkStatus::Verified));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn another_checkpoint_or_a_damaged_header_starts_empty() {
        let dir = test_dir("header");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        store.mark_verified(201, id(1)).unwrap();
        drop(store);
        let (store, load) = WorkStatusStore::open(&path, NETWORK, CHECKPOINT + 100, id(7)).unwrap();
        assert!(load.started_empty);
        assert_eq!(store.status(&id(1)), None);
        drop(store);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            HEADER_BYTES as u64,
            "replaced by an empty store"
        );

        let (mut store, _) = open(&path);
        store.mark_verified(201, id(1)).unwrap();
        drop(store);
        let mut bytes = fs::read(&path).unwrap();
        bytes[9] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        let (store, load) = open(&path);
        assert!(load.started_empty);
        assert_eq!(store.status(&id(1)), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn compaction_keeps_live_records_only() {
        let dir = test_dir("compact");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        store.compact_min_records = 8;
        store.mark_verified(101, id(1)).unwrap();
        store
            .mark_invalid(&confirmed(), 102, id(2), CHALLENGE)
            .unwrap();
        for byte in 10..16 {
            store.mark_verified(110, id(byte)).unwrap();
        }
        // 8 records, 8 live: not compacted.
        assert_eq!(store.records, 8);
        // Each reconsider compacts, leaving the live records only.
        for byte in 10..16 {
            store.reconsider(id(byte)).unwrap();
        }
        assert_eq!(store.records, 2);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            (HEADER_BYTES + 2 * RECORD_BYTES) as u64
        );
        store.mark_verified(103, id(3)).unwrap();
        drop(store);
        let (store, load) = open(&path);
        assert_eq!(load, WorkStatusLoad::default());
        assert_eq!(store.status(&id(1)), Some(WorkStatus::Verified));
        assert_eq!(store.status(&id(2)), Some(WorkStatus::Invalid));
        assert_eq!(store.status(&id(3)), Some(WorkStatus::Verified));
        assert_eq!(store.status(&id(10)), None);
        assert!(!dir.join("work-status.v1.tmp").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_blocks_are_capped_oldest_first() {
        let dir = test_dir("invalid-cap");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        store.max_invalid = 2;
        for byte in 1..=3 {
            store
                .mark_invalid(&confirmed(), 100 + u64::from(byte), id(byte), CHALLENGE)
                .unwrap();
        }
        assert_eq!(store.invalid_count(), 2);
        assert_eq!(store.status(&id(1)), None);
        assert_eq!(store.status(&id(3)), Some(WorkStatus::Invalid));
        // A verified block is never evicted by the invalid cap.
        store.mark_verified(110, id(9)).unwrap();
        store
            .mark_invalid(&confirmed(), 104, id(4), CHALLENGE)
            .unwrap();
        assert_eq!(store.status(&id(9)), Some(WorkStatus::Verified));
        assert_eq!(store.status(&id(2)), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_first_halt_stands_until_its_block_is_cleared() {
        let dir = test_dir("halt");
        let path = dir.join(WORK_HALT_FILE);
        assert_eq!(read_work_halt(&path, NETWORK).unwrap(), None);
        let halt = write_work_halt(&path, NETWORK, 150, id(5), CHALLENGE, &confirmed()).unwrap();
        assert_eq!(
            halt,
            WorkHalt {
                height: 150,
                block_id: id(5),
                challenge_digest: [0x33; 32],
            }
        );
        assert_eq!(
            write_work_halt(&path, NETWORK, 151, id(6), CHALLENGE, &confirmed()).unwrap(),
            halt
        );
        assert_eq!(read_work_halt(&path, NETWORK).unwrap(), Some(halt));
        assert_eq!(
            read_work_halt(&path, [0x99; 32]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!clear_work_halt(&path, NETWORK, id(6)).unwrap());
        assert!(path.exists());
        assert!(clear_work_halt(&path, NETWORK, id(5)).unwrap());
        assert_eq!(read_work_halt(&path, NETWORK).unwrap(), None);

        write_work_halt(&path, NETWORK, 150, id(5), CHALLENGE, &confirmed()).unwrap();
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            1,
            "no temporary file is left"
        );
        let mut bytes = fs::read(&path).unwrap();
        bytes[50] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            read_work_halt(&path, NETWORK).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn without_hard_links_the_halt_is_written_in_place() {
        let dir = test_dir("halt-no-links");
        let path = dir.join(WORK_HALT_FILE);
        // A temporary file left by an interrupted write is not used.
        fs::write(dir.join("halt.v1.tmp"), b"left over").unwrap();
        REFUSE_HARD_LINKS.with(|refuse| refuse.set(true));
        let halt = write_work_halt(&path, NETWORK, 150, id(5), CHALLENGE, &confirmed());
        let again = write_work_halt(&path, NETWORK, 151, id(6), CHALLENGE, &confirmed());
        REFUSE_HARD_LINKS.with(|refuse| refuse.set(false));
        let halt = halt.unwrap();
        assert_eq!(halt.block_id, id(5));
        assert_eq!(again.unwrap(), halt, "the first halt still stands");
        assert_eq!(read_work_halt(&path, NETWORK).unwrap(), Some(halt));
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            1,
            "no temporary file is left"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_verified_block_is_not_recorded_invalid_until_reconsidered() {
        let dir = test_dir("verified-sticky");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        store.mark_verified(101, id(1)).unwrap();
        assert_eq!(
            store
                .mark_invalid(&confirmed(), 101, id(1), CHALLENGE)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(store.status(&id(1)), Some(WorkStatus::Verified));
        store.reconsider(id(1)).unwrap();
        store
            .mark_invalid(&confirmed(), 101, id(1), CHALLENGE)
            .unwrap();
        assert_eq!(store.status(&id(1)), Some(WorkStatus::Invalid));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_invalid_block_is_not_recorded_verified_until_reconsidered() {
        let dir = test_dir("invalid-sticky");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        store
            .mark_invalid(&confirmed(), 101, id(1), CHALLENGE)
            .unwrap();
        assert_eq!(
            store.mark_verified(101, id(1)).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(store.status(&id(1)), Some(WorkStatus::Invalid));
        store.reconsider(id(1)).unwrap();
        store.mark_verified(101, id(1)).unwrap();
        assert_eq!(store.status(&id(1)), Some(WorkStatus::Verified));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_confirmed_mismatch_for_another_challenge_is_refused() {
        let dir = test_dir("other-challenge");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        assert_eq!(
            store
                .mark_invalid(&confirmed(), 101, id(1), [0x99; 32])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(store.status(&id(1)), None);
        let halt = dir.join(WORK_HALT_FILE);
        assert_eq!(
            write_work_halt(&halt, NETWORK, 101, id(1), [0x99; 32], &confirmed())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!halt.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    fn grants(dir: &Path) -> [PathBuf; 2] {
        [
            dir.join(CATCH_UP_GRANTS_FILE),
            dir.join(format!("{CATCH_UP_GRANTS_FILE}.tmp")),
        ]
    }

    fn place_grants(dir: &Path) {
        for path in grants(dir) {
            fs::write(path, b"grants").unwrap();
        }
    }

    fn grants_present(dir: &Path) -> [bool; 2] {
        grants(dir).map(|path| path.exists())
    }

    #[test]
    fn every_repair_and_reconsider_removes_the_catch_up_grants_first() {
        let dir = test_dir("grants-repair");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        store.mark_verified(101, id(1)).unwrap();
        store.mark_verified(102, id(2)).unwrap();
        drop(store);
        let clean = fs::read(&path).unwrap();

        // A clean open keeps them.
        place_grants(&dir);
        let (store, load) = open(&path);
        assert_eq!(load, WorkStatusLoad::default());
        drop(store);
        assert_eq!(grants_present(&dir), [true, true]);

        // A torn tail, a damaged record and a store that starts empty (a
        // missing file, a damaged header, another checkpoint) each remove them.
        let torn = clean[..clean.len() - 5].to_vec();
        let mut damaged = clean.clone();
        damaged[HEADER_BYTES + 20] ^= 0x01;
        let mut header = clean.clone();
        header[9] ^= 0x01;
        for (label, bytes) in [
            ("torn", Some(torn)),
            ("damaged", Some(damaged)),
            ("header", Some(header)),
            ("missing", None),
        ] {
            match &bytes {
                Some(bytes) => fs::write(&path, bytes).unwrap(),
                None => fs::remove_file(&path).unwrap(),
            }
            place_grants(&dir);
            let (store, load) = open(&path);
            assert!(
                load.torn_bytes > 0 || load.damaged_records > 0 || load.started_empty,
                "{label}"
            );
            drop(store);
            assert_eq!(grants_present(&dir), [false, false], "{label}");
        }
        fs::write(&path, &clean).unwrap();
        let (store, _) = WorkStatusStore::open(&path, NETWORK, CHECKPOINT + 1, id(7)).unwrap();
        drop(store);
        assert_eq!(grants_present(&dir), [false, false], "another checkpoint");

        // A reconsider removes them before it clears a record, and one that
        // clears nothing leaves them.
        fs::write(&path, &clean).unwrap();
        let (mut store, _) = open(&path);
        place_grants(&dir);
        assert!(!store.reconsider(id(9)).unwrap());
        assert_eq!(grants_present(&dir), [true, true]);
        assert!(store.reconsider(id(1)).unwrap());
        assert_eq!(grants_present(&dir), [false, false]);
        drop(store);

        // Removed before the repair: if the grant file cannot be removed, the
        // open fails and the torn tail is still there.
        fs::write(&path, &clean[..clean.len() - 5]).unwrap();
        fs::create_dir(dir.join(CATCH_UP_GRANTS_FILE)).unwrap();
        assert!(WorkStatusStore::open(&path, NETWORK, CHECKPOINT, CHECKPOINT_ID).is_err());
        assert_eq!(fs::metadata(&path).unwrap().len(), clean.len() as u64 - 5);
        fs::remove_dir(dir.join(CATCH_UP_GRANTS_FILE)).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_damaged_record_drops_the_grants_once_and_a_store_without_them_is_left_as_it_was() {
        let dir = test_dir("grants-once");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        for byte in 1..=3 {
            store
                .mark_verified(100 + u64::from(byte), id(byte))
                .unwrap();
        }
        drop(store);
        let mut damaged = fs::read(&path).unwrap();
        damaged[HEADER_BYTES + RECORD_BYTES + 20] ^= 0x01;

        // Without a grant file (a server), nothing is rewritten.
        fs::write(&path, &damaged).unwrap();
        let (store, load) = open(&path);
        assert_eq!(load.damaged_records, 1);
        drop(store);
        assert_eq!(fs::read(&path).unwrap(), damaged);

        // With one, the first open removes it and drops the damaged record.
        place_grants(&dir);
        let (store, load) = open(&path);
        assert_eq!(load.damaged_records, 1);
        drop(store);
        assert_eq!(grants_present(&dir), [false, false]);
        // A grant file made after that survives the next open.
        fs::write(dir.join(CATCH_UP_GRANTS_FILE), b"grants").unwrap();
        let (store, load) = open(&path);
        assert_eq!(load, WorkStatusLoad::default());
        assert_eq!(store.status(&id(1)), Some(WorkStatus::Verified));
        assert_eq!(store.status(&id(2)), None);
        assert_eq!(store.status(&id(3)), Some(WorkStatus::Verified));
        drop(store);
        assert_eq!(grants_present(&dir), [true, false]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unsettled_blocks_are_listed_and_a_failed_write_records_nothing() {
        let dir = test_dir("unsettled-list");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        store.mark_unsettled(102, id(2)).unwrap();
        store.mark_unsettled(105, id(5)).unwrap();
        store.mark_verified(103, id(3)).unwrap();
        let mut listed = store.unsettled_blocks().collect::<Vec<_>>();
        listed.sort_unstable();
        assert_eq!(listed, vec![(102, id(2)), (105, id(5))]);

        let length = fs::metadata(&path).unwrap().len();
        store.fail_next_write();
        assert!(store.mark_unsettled(106, id(6)).is_err());
        assert!(!store.is_unsettled(&id(6)));
        assert_eq!(fs::metadata(&path).unwrap().len(), length);
        store.mark_unsettled(106, id(6)).unwrap();
        assert!(store.is_unsettled(&id(6)));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_failed_compaction_keeps_the_store_open_and_is_tried_again() {
        let dir = test_dir("compact-fails");
        let path = dir.join(WORK_STATUS_FILE);
        let (mut store, _) = open(&path);
        store.compact_min_records = 4;
        store.mark_verified(101, id(1)).unwrap();
        store.mark_verified(102, id(2)).unwrap();
        store.fail_next_rename = true;
        store.reconsider(id(2)).unwrap();
        // The rename was refused: the old file is intact and still appended to.
        assert!(!dir.join("work-status.v1.tmp").exists());
        assert_eq!(store.records, 3);
        assert_eq!(store.compact_retry_at, 3 + 4);
        store.mark_verified(103, id(3)).unwrap();
        drop(store);
        let (mut store, load) = open(&path);
        assert_eq!(load, WorkStatusLoad::default());
        assert_eq!(store.status(&id(1)), Some(WorkStatus::Verified));
        assert_eq!(store.status(&id(2)), None);
        assert_eq!(store.status(&id(3)), Some(WorkStatus::Verified));
        // Compaction works again later.
        store.reconsider(id(3)).unwrap();
        assert_eq!(store.records, 1);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            (HEADER_BYTES + RECORD_BYTES) as u64
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
