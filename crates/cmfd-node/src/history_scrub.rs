//! Background re-verification of the retained block log after a fast start.
//!
//! A fast start trusts the startup snapshot's record locators for history the
//! node verified before, and authenticates only the records its index cache
//! does not cover. This scrub then re-reads every older record at a bounded
//! rate and checks it against its locator: header, acceptance time, complete
//! digest, offset and the link to the previous record. A mismatch faults
//! storage (the node stops accepting and serving blocks) and moves the startup
//! caches aside, so the next start rebuilds from the log, which stays
//! authoritative. Records appended after startup were authenticated when they
//! were written and are not re-read.

use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{
    BlockRecordLocator, BlockRecordVersion, EMPTY_RECORD_CHAIN_ROOT, Node, NodeError, RECORD_MAGIC,
    complete_record_digest, positioned_read_exact,
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
    while let Pass::Restart = scrub_pass(shared, stop, throttle)? {}
    Ok(())
}

fn lock(shared: &Mutex<Node>) -> Result<std::sync::MutexGuard<'_, Node>, NodeError> {
    shared.lock().map_err(|_| NodeError::SharedNodePoisoned)
}

fn scrub_pass(shared: &Mutex<Node>, stop: &AtomicBool, throttle: bool) -> Result<Pass, NodeError> {
    let (instance, epoch, locators) = {
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
        (node.instance_id, node.log_epoch, locators)
    };
    tracing::info!(
        records = locators.len(),
        "verifying retained block history in the background"
    );
    let started = Instant::now();
    let mut previous = EMPTY_RECORD_CHAIN_ROOT;
    let mut expected_offset = 0_u64;
    let mut read_bytes = 0_u64;
    let mut position = 0;
    while position < locators.len() {
        if stop.load(Ordering::Acquire) {
            return Ok(Pass::Done);
        }
        let mut end = position;
        let mut batch_bytes = 0_u64;
        while end < locators.len()
            && (end == position || batch_bytes + locators[end].length <= SCRUB_BATCH_BYTES)
        {
            batch_bytes += locators[end].length;
            end += 1;
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
        let failure = locators[position..end].iter().find_map(|locator| {
            verify_record(&log, locator, &mut previous, &mut expected_offset)
                .err()
                .map(|reason| (locator.ordinal, reason))
        });
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
        read_bytes += batch_bytes;
        position = end;
        {
            let mut node = lock(shared)?;
            if node.instance_id == instance && node.log_epoch == epoch {
                node.history_scrub.verified_records = position as u64;
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
            "retained block history verified"
        );
    }
    Ok(Pass::Done)
}

/// Checks one record's bytes against its locator and its predecessor.
fn verify_record(
    log: &File,
    locator: &BlockRecordLocator,
    previous: &mut [u8; 32],
    expected_offset: &mut u64,
) -> Result<(), &'static str> {
    if locator.offset != *expected_offset {
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
    *previous = locator.complete_digest;
    *expected_offset += locator.length;
    Ok(())
}
