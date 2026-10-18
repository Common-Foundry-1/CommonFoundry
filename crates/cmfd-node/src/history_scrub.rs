//! Background re-verification of the retained block log after a fast start.
//!
//! A fast start trusts the startup snapshot's record locators for history the
//! node verified before, and authenticates only the records its index cache
//! does not cover. This scrub then re-reads every older record at a bounded
//! rate and checks it against its locator: header, acceptance time, complete
//! digest, offset and the link to the previous record. The expected offset and
//! link come from the sorted locators, so the scrub checks the newest records
//! first, in batches each read in log order. A mismatch faults
//! storage (the node stops accepting and serving blocks) and moves the startup
//! caches aside, so the next start rebuilds from the log, which stays
//! authoritative. Records appended after startup were authenticated when they
//! were written and are not re-read.
//!
//! Address entries loaded from an older index cache have no activity facts
//! yet. The scrub decodes just the records that hold such hint entries, once
//! they pass the checks above, and fills the entries from them. Going newest
//! first fills the history that busy keys' first pages show within seconds of
//! startup. A hint record that does not decode faults storage like any other
//! mismatch.

use std::fs::File;
use std::io::Cursor;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::explorer_address_index::{AddressEntry, AddressHistoryIndex};
use super::{
    BlockRecordLocator, BlockRecordVersion, EMPTY_RECORD_CHAIN_ROOT, Node, NodeError, RECORD_MAGIC,
    complete_record_digest, decode_stored_block, positioned_read_exact, read_log_record,
};

/// Average read rate while scrubbing, so serving and syncing keep the disk.
const SCRUB_BYTES_PER_SECOND: u64 = 96 << 20;
/// Bytes read per batch. The node lock and a log handle are taken only
/// between batches, so pruning can swap the log in the gaps.
const SCRUB_BATCH_BYTES: u64 = 64 << 20;

/// How much of the retained history the scrub has verified.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Progress {
    pub verified_records: u64,
    pub complete: bool,
}

impl Progress {
    pub(crate) fn verified(records: u64) -> Self {
        Self {
            verified_records: records,
            complete: true,
        }
    }
}

/// A running background scrub; stopping it joins its thread.
pub struct HistoryScrub {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl HistoryScrub {
    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for HistoryScrub {
    fn drop(&mut self) {
        self.halt();
    }
}

/// Starts the scrub. It ends by itself once every record present at startup
/// has been checked, and does nothing when startup already scanned the log.
pub fn spawn_history_scrub(shared: Arc<Mutex<Node>>) -> std::io::Result<HistoryScrub> {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("cmfd-history-scrub".to_owned())
        .spawn(move || {
            if let Err(error) = scrub(&shared, &flag, true) {
                tracing::warn!(%error, "background history scrub stopped");
            }
        })?;
    Ok(HistoryScrub {
        stop,
        thread: Some(thread),
    })
}

enum Pass {
    Done,
    Restart,
}

/// Runs the scrub to the end (or until `stop`). `throttle` bounds the read
/// rate; tests run unthrottled.
pub(crate) fn scrub(
    shared: &Mutex<Node>,
    stop: &AtomicBool,
    throttle: bool,
) -> Result<(), NodeError> {
    scrub_in_batches(shared, stop, throttle, SCRUB_BATCH_BYTES)
}

/// `scrub` with batches of at most `batch_bytes` (a larger record is a batch
/// of its own), so tests can span several batches.
pub(crate) fn scrub_in_batches(
    shared: &Mutex<Node>,
    stop: &AtomicBool,
    throttle: bool,
    batch_bytes: u64,
) -> Result<(), NodeError> {
    while let Pass::Restart = scrub_pass(shared, stop, throttle, batch_bytes)? {}
    Ok(())
}

fn lock(shared: &Mutex<Node>) -> Result<std::sync::MutexGuard<'_, Node>, NodeError> {
    shared.lock().map_err(|_| NodeError::SharedNodePoisoned)
}

fn scrub_pass(
    shared: &Mutex<Node>,
    stop: &AtomicBool,
    throttle: bool,
    batch_bytes: u64,
) -> Result<Pass, NodeError> {
    let (instance, epoch, locators, mut hints, network_id, log_path) = {
        let node = lock(shared)?;
        if node.history_scrub.complete || node.storage_faulted {
            return Ok(Pass::Done);
        }
        let mut locators: Vec<BlockRecordLocator> = node
            .index
            .blocks
            .values()
            .map(|entry| entry.locator)
            .collect();
        locators.sort_unstable_by_key(|locator| locator.ordinal);
        (
            node.instance_id,
            node.log_epoch,
            locators,
            node.index.addresses.hint_blocks(),
            node.params.network_id,
            node.data_dir.join(super::BLOCK_LOG_FILE),
        )
    };
    tracing::info!(
        records = locators.len(),
        address_hint_blocks = hints.len(),
        "verifying retained block history in the background"
    );
    let started = Instant::now();
    let mut read_bytes = 0_u64;
    let mut filled = 0_usize;
    let mut repaired = 0_usize;
    let mut verified = 0_usize;
    // Batches run from the newest record back; each is read in log order.
    let mut end = locators.len();
    while end > 0 {
        if stop.load(Ordering::Acquire) {
            return Ok(Pass::Done);
        }
        let mut start = end;
        let mut batch_read = 0_u64;
        while start > 0 && (start == end || batch_read + locators[start - 1].length <= batch_bytes)
        {
            start -= 1;
            batch_read += locators[start].length;
        }
        let log = {
            let node = lock(shared)?;
            if node.instance_id != instance || node.log_epoch != epoch {
                // Pruning replaced the log; check the new one from the start.
                return Ok(Pass::Restart);
            }
            if node.storage_faulted {
                return Ok(Pass::Done);
            }
            node.clone_log_for_read().map_err(NodeError::RpcIo)?
        };
        let mut failure = None;
        let mut recomputed = Vec::new();
        for (position, locator) in (start..end).zip(&locators[start..end]) {
            let checked = verify_record(&log, &locators, position).and_then(|raw| {
                if hints.contains_key(&locator.block_id) {
                    recomputed.push((
                        locator.block_id,
                        record_entries(&raw, &log_path, locator, network_id)?,
                    ));
                }
                Ok(())
            });
            if let Err(reason) = checked {
                failure = Some((locator.ordinal, reason));
                break;
            }
        }
        drop(log);
        if let Some((ordinal, reason)) = failure {
            let mut node = lock(shared)?;
            if node.instance_id == instance && node.log_epoch == epoch && !node.storage_faulted {
                node.storage_faulted = true;
                super::startup_snapshot::quarantine_startup_caches(&node.data_dir);
                tracing::error!(
                    ordinal,
                    reason,
                    "a retained block record does not match the startup index; storage faulted and startup caches moved aside, so the next start rebuilds from the block log"
                );
            }
            return Ok(Pass::Done);
        }
        read_bytes += batch_read;
        verified += end - start;
        end = start;
        {
            let mut node = lock(shared)?;
            if node.instance_id == instance && node.log_epoch == epoch {
                node.history_scrub.verified_records = verified as u64;
                for (block_id, entries) in recomputed {
                    let stale = hints.remove(&block_id).unwrap_or_default();
                    let report = node.index.addresses.fill_block(&stale, entries);
                    filled += report.filled;
                    if report.repaired > 0 {
                        // A derived display index; never fault storage for it.
                        tracing::error!(
                            block_id = %hex::encode(block_id),
                            repaired = report.repaired,
                            "explorer address index disagreed with an authenticated block; corrected it from the block"
                        );
                        repaired += report.repaired;
                    }
                }
            }
        }
        if throttle {
            let due = Duration::from_secs_f64(read_bytes as f64 / SCRUB_BYTES_PER_SECOND as f64);
            while started.elapsed() < due && !stop.load(Ordering::Acquire) {
                thread::sleep((due - started.elapsed()).min(Duration::from_millis(100)));
            }
        }
    }
    let mut node = lock(shared)?;
    if node.instance_id == instance && node.log_epoch == epoch {
        node.history_scrub = Progress::verified(locators.len() as u64);
        tracing::info!(
            records = locators.len(),
            bytes = read_bytes,
            seconds = started.elapsed().as_secs(),
            filled_address_entries = filled,
            repaired_address_entries = repaired,
            "retained block history verified"
        );
        if (filled > 0 || repaired > 0)
            && let Err(error) = node.persist_index_cache()
        {
            tracing::warn!(%error, "explorer index cache not saved after the history scrub");
        }
    }
    Ok(Pass::Done)
}

/// Decodes a record whose bytes `verify_record` just checked and derives its
/// address entries. A record that does not decode is a log fault.
fn record_entries(
    raw: &[u8],
    path: &Path,
    locator: &BlockRecordLocator,
    network_id: [u8; 32],
) -> Result<Vec<AddressEntry>, &'static str> {
    let record = read_log_record(&mut Cursor::new(raw), path, locator.ordinal, network_id)
        .ok()
        .flatten()
        .filter(|record| record.complete_digest == locator.complete_digest)
        .ok_or("record cannot be decoded")?;
    let block = decode_stored_block(&record, locator.ordinal, network_id)
        .map_err(|_| "record cannot be decoded")?;
    if block.block_id() != locator.block_id || block.challenge.height != locator.height {
        return Err("record block differs from its index entry");
    }
    Ok(AddressHistoryIndex::stored_block_entries(&block))
}

/// Checks the bytes of `locators[position]` against its locator and its
/// predecessor's locator, and returns them. Every record's own digest is
/// checked against its locator, so checking the link against the
/// predecessor's locator equals checking it against the predecessor record,
/// in whatever order the records are read.
fn verify_record(
    log: &File,
    locators: &[BlockRecordLocator],
    position: usize,
) -> Result<Vec<u8>, &'static str> {
    let locator = &locators[position];
    let (previous, expected_offset) = match position.checked_sub(1).map(|index| &locators[index]) {
        Some(predecessor) => (
            predecessor.complete_digest,
            predecessor.offset.checked_add(predecessor.length),
        ),
        None => (EMPTY_RECORD_CHAIN_ROOT, Some(0)),
    };
    if Some(locator.offset) != expected_offset {
        return Err("record offsets are not contiguous");
    }
    let length = usize::try_from(locator.length).map_err(|_| "record length overflows")?;
    let mut raw = vec![0_u8; length];
    positioned_read_exact(log, &mut raw, locator.offset).map_err(|_| "record cannot be read")?;
    let version = match locator.version {
        BlockRecordVersion::LegacyV1 => 1_u16,
        BlockRecordVersion::V2 => 2,
        BlockRecordVersion::V3 => 3,
        BlockRecordVersion::Pruned => 4,
    };
    if raw.len() < 16
        || raw[..4] != RECORD_MAGIC
        || u16::from_le_bytes([raw[4], raw[5]]) != version
        || u64::from_le_bytes(raw[8..16].try_into().expect("fixed slice")) != locator.accepted_at
    {
        return Err("record header differs from its index entry");
    }
    if complete_record_digest(&raw) != locator.complete_digest {
        return Err("record digest differs from its index entry");
    }
    if locator.version != BlockRecordVersion::LegacyV1 && raw.get(24..56) != Some(&previous[..]) {
        return Err("record does not link to its predecessor");
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{clean_test_dir, test_dir};
    use crate::{DEFAULT_MINING_ATTEMPTS, DEVNET_GENESIS_TIMESTAMP, default_miner_destination};

    /// A three-record log and its locators in log order.
    fn three_records(name: &str) -> (std::path::PathBuf, File, Vec<BlockRecordLocator>) {
        let path = test_dir(name);
        let mut node = Node::open(&path).unwrap();
        while node.state.next_height() <= 3 {
            let now = DEVNET_GENESIS_TIMESTAMP + node.state.next_height() * 60;
            node.mine_once(default_miner_destination(), now, DEFAULT_MINING_ATTEMPTS)
                .unwrap();
        }
        let mut locators: Vec<BlockRecordLocator> = node
            .index
            .blocks
            .values()
            .map(|entry| entry.locator)
            .collect();
        locators.sort_unstable_by_key(|locator| locator.ordinal);
        drop(node);
        assert_eq!(locators.len(), 3);
        assert!(
            locators
                .iter()
                .all(|locator| locator.version != BlockRecordVersion::LegacyV1)
        );
        let log = File::open(path.join(crate::BLOCK_LOG_FILE)).unwrap();
        (path, log, locators)
    }

    #[test]
    fn verify_record_checks_offsets_against_the_predecessor_locator() {
        let (path, log, locators) = three_records("scrub-verify-offsets");
        for position in 0..locators.len() {
            let raw = verify_record(&log, &locators, position).unwrap();
            assert_eq!(raw.len() as u64, locators[position].length);
        }
        // Record 2's own locator is intact, so only the contiguity check can
        // refuse it: its predecessor now claims to end one byte later.
        let mut longer = locators.clone();
        longer[1].length += 1;
        assert_eq!(
            verify_record(&log, &longer, 2),
            Err("record offsets are not contiguous")
        );
        // The first record must start the log.
        let mut moved = locators.clone();
        moved[0].offset = 1;
        assert_eq!(
            verify_record(&log, &moved, 0),
            Err("record offsets are not contiguous")
        );
        drop(log);
        clean_test_dir(&path);
    }

    #[test]
    fn verify_record_checks_the_link_against_the_predecessor_locator() {
        let (path, log, locators) = three_records("scrub-verify-link");
        // Record 2's bytes, offset and digest all match its own locator; only
        // the link to its predecessor's digest can refuse it.
        let mut relinked = locators.clone();
        relinked[1].complete_digest[0] ^= 1;
        assert_eq!(
            verify_record(&log, &relinked, 2),
            Err("record does not link to its predecessor")
        );
        assert!(verify_record(&log, &relinked, 0).is_ok());
        drop(log);
        clean_test_dir(&path);
    }
}
