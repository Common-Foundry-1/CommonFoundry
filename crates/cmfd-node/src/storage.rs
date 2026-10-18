//! Offline block-log inspection, evidence-preserving partial-tail repair, and
//! evidence-preserving removal of a stored block and everything stored after
//! it.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{
    BLOCK_LOG_FILE, DataDirLock, EMPTY_RECORD_CHAIN_ROOT, NetworkProfile, NodeError,
    ParsedRecordPayload, decode_stored_block, io_error, read_log_record,
    verify_retained_block_log_path,
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StorageInspection {
    pub network: &'static str,
    pub records: u64,
    pub legacy_v1_records: u64,
    pub v2_records: u64,
    pub last_valid_offset: u64,
    pub total_bytes: u64,
    pub recoverable_partial_tail_bytes: u64,
    pub record_chain_root: String,
}

impl StorageInspection {
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.recoverable_partial_tail_bytes == 0
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StorageRepairReport {
    pub inspection: StorageInspection,
    pub quarantine: PathBuf,
    pub quarantined_bytes: u64,
    pub repaired_log_bytes: u64,
}

fn authenticated_storage_profile(profile: NetworkProfile) -> Result<NetworkProfile, NodeError> {
    // Mainnet's compiled profile contains an unactivated zero genesis. Use
    // exactly the same verified plan/beacon authority as node startup before
    // taking a data lock or deciding which log prefix may be retained.
    let (profile, launch) = super::mainnet_runtime::resolve_compiled_profile(profile)?;
    super::mainnet_runtime::require_authenticated_profile(profile, launch)?;
    Ok(profile)
}

pub fn inspect_block_log(
    data_dir: &Path,
    profile: NetworkProfile,
) -> Result<StorageInspection, NodeError> {
    let profile = authenticated_storage_profile(profile)?;
    require_existing_data_directory(data_dir)?;
    let _lock = DataDirLock::acquire(data_dir)?;
    let path = data_dir.join(BLOCK_LOG_FILE);
    let mut file = match OpenOptions::new().read(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(empty_inspection(profile));
        }
        Err(error) => return Err(io_error("open block log for inspection", &path, error)),
    };
    scan_block_log(&mut file, &path, profile)
}

pub fn repair_partial_block_log_tail(
    data_dir: &Path,
    profile: NetworkProfile,
    quarantine: &Path,
) -> Result<Option<StorageRepairReport>, NodeError> {
    let profile = authenticated_storage_profile(profile)?;
    require_existing_data_directory(data_dir)?;
    let _lock = DataDirLock::acquire(data_dir)?;
    let path = data_dir.join(BLOCK_LOG_FILE);
    let mut file = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("open block log for tail repair", &path, error)),
    };
    let inspection = scan_block_log(&mut file, &path, profile)?;
    let tail_bytes = inspection.recoverable_partial_tail_bytes;
    if tail_bytes == 0 {
        return Ok(None);
    }

    file.seek(SeekFrom::Start(inspection.last_valid_offset))
        .map_err(|error| io_error("seek recoverable block-log tail", &path, error))?;
    let mut evidence = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(quarantine)
        .map_err(|error| io_error("create block-log tail quarantine", quarantine, error))?;
    let copied = io::copy(&mut (&mut file).take(tail_bytes), &mut evidence)
        .map_err(|error| io_error("quarantine block-log tail", quarantine, error))?;
    if copied != tail_bytes {
        return Err(NodeError::CorruptLog(
            "block-log tail changed while it was being quarantined".to_owned(),
        ));
    }
    evidence
        .flush()
        .and_then(|()| evidence.sync_all())
        .map_err(|error| io_error("sync block-log tail quarantine", quarantine, error))?;
    super::sync_parent_directory(quarantine)?;

    if file
        .metadata()
        .map_err(|error| io_error("reinspect block log before tail repair", &path, error))?
        .len()
        != inspection.total_bytes
    {
        return Err(NodeError::CorruptLog(
            "block log changed before partial-tail repair".to_owned(),
        ));
    }
    verify_retained_block_log_path(&file, &path)?;
    file.set_len(inspection.last_valid_offset)
        .map_err(|error| io_error("truncate quarantined block-log tail", &path, error))?;
    file.sync_all()
        .map_err(|error| io_error("sync repaired block log", &path, error))?;
    super::sync_parent_directory(&path)?;

    Ok(Some(StorageRepairReport {
        repaired_log_bytes: inspection.last_valid_offset,
        inspection,
        quarantine: quarantine.to_path_buf(),
        quarantined_bytes: tail_bytes,
    }))
}

/// What [`quarantine_block_log_from_block`] removed.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StorageQuarantineReport {
    /// The first removed block, in hex.
    pub block_id: String,
    /// Its record ordinal; every record from it on was removed.
    pub from_record: u64,
    pub removed_records: u64,
    pub quarantine: PathBuf,
    pub quarantined_bytes: u64,
    pub retained_log_bytes: u64,
    /// Whether the halt marker was cleared: it named a removed block, or one
    /// this log no longer stores.
    pub halt_cleared: bool,
}

/// Removes the stored block `block_id`, and every record stored after it,
/// from the block log of a stopped node. With no `block_id`, the block named
/// by the work-check halt marker is removed.
///
/// The removed bytes are first copied to `quarantine`, which must not exist,
/// and kept as evidence. The startup caches are moved aside, so the next
/// start replays the log and opens at the removed block's parent. Records
/// stored after it on other branches are removed too; peers serve them
/// again. A halt marker naming any removed block is cleared, but a block
/// recorded invalid stays recorded, so it is not admitted again.
///
/// With no `block_id`, a halt marker that names a block the log no longer
/// stores (an earlier quarantine stopped before it cleared the marker) is
/// cleared, and nothing is removed.
///
/// A pruned block cannot be removed this way, because the chain state below
/// the prune anchor is gone: that is
/// [`WorkRuleResyncRequired`](NodeError::WorkRuleResyncRequired), and the node
/// must be resynced from an empty data directory.
pub fn quarantine_block_log_from_block(
    data_dir: &Path,
    profile: NetworkProfile,
    block_id: Option<[u8; 32]>,
    quarantine: &Path,
) -> Result<StorageQuarantineReport, NodeError> {
    let profile = authenticated_storage_profile(profile)?;
    require_existing_data_directory(data_dir)?;
    let _lock = DataDirLock::acquire(data_dir)?;
    let halt_path = data_dir.join(super::work_gate::WORK_HALT_FILE);
    let halt = super::honest_work::store::read_work_halt(&halt_path, profile.network_id)
        .map_err(|error| io_error("read the work-check halt marker", &halt_path, error))?;
    let from_halt = block_id.is_none();
    let halted_block = halt.as_ref().map(|halt| halt.block_id);
    let block_id = match (block_id, halt) {
        (Some(block_id), _) => block_id,
        (None, Some(halt)) => halt.block_id,
        (None, None) => {
            return Err(io_error(
                "choose the block to quarantine",
                &halt_path,
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no block was given and no halt marker names one",
                ),
            ));
        }
    };
    let path = data_dir.join(BLOCK_LOG_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|error| io_error("open block log for quarantine", &path, error))?;
    let targets: Vec<[u8; 32]> = std::iter::once(block_id).chain(halted_block).collect();
    let (inspection, found) = scan_block_log_for(&mut file, &path, profile, &targets)?;
    if inspection.recoverable_partial_tail_bytes != 0 {
        return Err(NodeError::CorruptLog(
            "the block log has an incomplete final record; repair the tail first".to_owned(),
        ));
    }
    let halted_record = found.get(1).copied().flatten();
    let clear_halt = |removed_from: u64| -> Result<bool, NodeError> {
        let Some(halted_block) = halted_block else {
            return Ok(false);
        };
        if halted_record.is_some_and(|record| record.ordinal < removed_from) {
            return Ok(false);
        }
        super::honest_work::store::clear_work_halt(&halt_path, profile.network_id, halted_block)
            .map_err(|error| io_error("clear the work-check halt marker", &halt_path, error))
    };
    let Some(found) = found[0] else {
        if from_halt {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(quarantine)
                .and_then(|evidence| evidence.sync_all())
                .map_err(|error| io_error("create block-log quarantine", quarantine, error))?;
            return Ok(StorageQuarantineReport {
                block_id: hex::encode(block_id),
                from_record: inspection.records,
                removed_records: 0,
                quarantine: quarantine.to_path_buf(),
                quarantined_bytes: 0,
                retained_log_bytes: inspection.total_bytes,
                halt_cleared: clear_halt(inspection.records)?,
            });
        }
        return Err(io_error(
            "find the block to quarantine",
            &path,
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("block {} is not stored", hex::encode(block_id)),
            ),
        ));
    };
    if found.pruned {
        return Err(NodeError::WorkRuleResyncRequired(block_id));
    }
    let removed_bytes = inspection.total_bytes - found.offset;

    file.seek(SeekFrom::Start(found.offset))
        .map_err(|error| io_error("seek quarantined block-log records", &path, error))?;
    let mut evidence = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(quarantine)
        .map_err(|error| io_error("create block-log quarantine", quarantine, error))?;
    let copied = io::copy(&mut (&mut file).take(removed_bytes), &mut evidence)
        .map_err(|error| io_error("quarantine block-log records", quarantine, error))?;
    if copied != removed_bytes {
        return Err(NodeError::CorruptLog(
            "block log changed while its records were being quarantined".to_owned(),
        ));
    }
    evidence
        .flush()
        .and_then(|()| evidence.sync_all())
        .map_err(|error| io_error("sync block-log quarantine", quarantine, error))?;
    super::sync_parent_directory(quarantine)?;

    if file
        .metadata()
        .map_err(|error| io_error("reinspect block log before quarantine", &path, error))?
        .len()
        != inspection.total_bytes
    {
        return Err(NodeError::CorruptLog(
            "block log changed before its records were quarantined".to_owned(),
        ));
    }
    // The caches describe the longer log; the next start replays it instead.
    super::startup_snapshot::quarantine_startup_caches(data_dir);
    verify_retained_block_log_path(&file, &path)?;
    file.set_len(found.offset)
        .map_err(|error| io_error("truncate quarantined block-log records", &path, error))?;
    file.sync_all()
        .map_err(|error| io_error("sync quarantined block log", &path, error))?;
    super::sync_parent_directory(&path)?;
    let halt_cleared = clear_halt(found.ordinal)?;

    Ok(StorageQuarantineReport {
        block_id: hex::encode(block_id),
        from_record: found.ordinal,
        removed_records: inspection.records - found.ordinal,
        quarantine: quarantine.to_path_buf(),
        quarantined_bytes: removed_bytes,
        retained_log_bytes: found.offset,
        halt_cleared,
    })
}

/// What [`reconsider_work_block`] cleared.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorkReconsiderReport {
    pub block_id: String,
    /// Whether the work-status store held a record for the block.
    pub record_cleared: bool,
    pub halt_cleared: bool,
    /// The work-status store is for another network or release checkpoint:
    /// it was left as it is, and the next start replaces it.
    pub store_for_another_checkpoint: bool,
}

/// Forgets what the work check recorded about `block_id` (verified, invalid
/// or unsettled) on a stopped node, so the next start checks the block again
/// like any unchecked block, and clears a halt marker that names it. Nothing
/// else changes: if the engines find the same result again, the node records
/// it again.
///
/// The store is changed only if it is for this network and its release
/// checkpoint; it is never replaced. One for another checkpoint is left as
/// it is, and the halt marker is still cleared.
pub fn reconsider_work_block(
    data_dir: &Path,
    profile: NetworkProfile,
    block_id: [u8; 32],
) -> Result<WorkReconsiderReport, NodeError> {
    let profile = authenticated_storage_profile(profile)?;
    require_existing_data_directory(data_dir)?;
    let _lock = DataDirLock::acquire(data_dir)?;
    let path = data_dir.join(super::work_gate::WORK_STATUS_FILE);
    let production_v4 = matches!(profile.proof, super::ProofProfile::ProductionV4);
    let Some((checkpoint_height, checkpoint_block_id)) =
        super::work_gate::WorkGate::compiled_checkpoint(production_v4, profile.network_id)
    else {
        return Err(io_error(
            "open the work-status store",
            &path,
            io::Error::new(
                io::ErrorKind::Unsupported,
                "this network has no release work rule",
            ),
        ));
    };
    let store = super::honest_work::store::WorkStatusStore::open_existing(
        &path,
        profile.network_id,
        checkpoint_height,
        checkpoint_block_id,
    );
    let (record_cleared, store_for_another_checkpoint) = match store {
        Ok(Some(mut store)) => (
            store
                .reconsider(block_id)
                .map_err(|error| io_error("reconsider a work-status record", &path, error))?,
            false,
        ),
        Ok(None) => (false, false),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => (false, true),
        Err(error) => return Err(io_error("open the work-status store", &path, error)),
    };
    let halt_path = data_dir.join(super::work_gate::WORK_HALT_FILE);
    let halt_cleared =
        super::honest_work::store::clear_work_halt(&halt_path, profile.network_id, block_id)
            .map_err(|error| io_error("clear the work-check halt marker", &halt_path, error))?;
    Ok(WorkReconsiderReport {
        block_id: hex::encode(block_id),
        record_cleared,
        halt_cleared,
        store_for_another_checkpoint,
    })
}

/// What [`set_chain_data_aside`] moved.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ChainSetAsideReport {
    /// The new folder inside the data directory that holds the moved files.
    pub folder: PathBuf,
    /// The names of the files and folders moved there.
    pub moved: Vec<String>,
    /// Their total size in bytes.
    pub moved_bytes: u64,
}

/// Moves a stopped node's stored chain out of the way so that its next start
/// syncs the chain again from peers: the block log, the fast-start caches,
/// the saved pruning states, and the work-check records and halt marker.
/// They go into a new folder
/// `resync-<unix seconds>` inside the data directory; nothing is deleted.
/// The wallet key, the network identity file, peer lists and everything else
/// stay where they are. For a desktop wallet's data directory: indexes that
/// an exchange or explorer node keeps are not moved.
///
/// Takes the data-directory lock, so it fails while a node has the directory
/// open. If a file cannot be moved, the ones already moved are put back.
pub fn set_chain_data_aside(data_dir: &Path) -> Result<ChainSetAsideReport, NodeError> {
    require_existing_data_directory(data_dir)?;
    let _lock = DataDirLock::acquire(data_dir)?;
    let stamp = super::unix_time_seconds().unwrap_or_default();
    let folder = (0..100)
        .map(|attempt| match attempt {
            0 => data_dir.join(format!("resync-{stamp}")),
            _ => data_dir.join(format!("resync-{stamp}-{attempt}")),
        })
        .find(|folder| !folder.exists())
        .ok_or_else(|| {
            io_error(
                "create the resync folder",
                data_dir,
                io::Error::new(io::ErrorKind::AlreadyExists, "no free folder name"),
            )
        })?;
    fs::create_dir(&folder)
        .map_err(|source| io_error("create the resync folder", &folder, source))?;
    let names = super::startup_snapshot::startup_cache_file_names()
        .into_iter()
        .chain([
            super::work_gate::WORK_HALT_FILE.to_owned(),
            format!("{}.tmp", super::work_gate::WORK_HALT_FILE),
            super::work_gate::WORK_STATUS_FILE.to_owned(),
            super::work_gate::CATCH_UP_GRANTS_FILE.to_owned(),
            format!("{}.tmp", super::work_gate::CATCH_UP_GRANTS_FILE),
            super::pruning::TEMPORARY_LOG_FILE.to_owned(),
        ])
        .chain(
            super::pruning::prune_state_names(data_dir)
                .map_err(|source| io_error("list the saved pruning states", data_dir, source))?,
        )
        // Last: should anything fail before it, the log still matches the
        // caches that were put back.
        .chain([BLOCK_LOG_FILE.to_owned()]);
    let mut moved = Vec::new();
    let mut moved_bytes = 0_u64;
    for name in names {
        let from = data_dir.join(&name);
        if !from.exists() {
            continue;
        }
        moved_bytes = moved_bytes.saturating_add(stored_size(&from));
        if let Err(source) = fs::rename(&from, folder.join(&name)) {
            for name in moved.iter().rev() {
                let _ = fs::rename(folder.join(name), data_dir.join(name));
            }
            let _ = fs::remove_dir(&folder);
            return Err(io_error("move stored chain data aside", &from, source));
        }
        moved.push(name);
    }
    super::sync_parent_directory(&data_dir.join(BLOCK_LOG_FILE))?;
    Ok(ChainSetAsideReport {
        folder,
        moved,
        moved_bytes,
    })
}

/// The size of a file, or of the files in a folder; what cannot be read
/// counts as nothing.
fn stored_size(path: &Path) -> u64 {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::read_dir(path)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| stored_size(&entry.path()))
                    .fold(0_u64, u64::saturating_add)
            })
            .unwrap_or(0),
        Ok(metadata) => metadata.len(),
        Err(_) => 0,
    }
}

fn require_existing_data_directory(data_dir: &Path) -> Result<(), NodeError> {
    match fs::metadata(data_dir) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(io_error(
            "inspect data directory",
            data_dir,
            io::Error::new(io::ErrorKind::InvalidInput, "path is not a directory"),
        )),
        Err(error) => Err(io_error("inspect data directory", data_dir, error)),
    }
}

fn empty_inspection(profile: NetworkProfile) -> StorageInspection {
    StorageInspection {
        network: profile.short_name(),
        records: 0,
        legacy_v1_records: 0,
        v2_records: 0,
        last_valid_offset: 0,
        total_bytes: 0,
        recoverable_partial_tail_bytes: 0,
        record_chain_root: hex::encode(EMPTY_RECORD_CHAIN_ROOT),
    }
}

fn scan_block_log(
    file: &mut File,
    path: &Path,
    profile: NetworkProfile,
) -> Result<StorageInspection, NodeError> {
    scan_block_log_for(file, path, profile, &[]).map(|(inspection, _)| inspection)
}

/// Where a block's record starts in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FoundRecord {
    ordinal: u64,
    offset: u64,
    pruned: bool,
}

/// Scans the whole log as [`scan_block_log`] does, and also reports where
/// the record of each of `targets` starts, if it is stored.
fn scan_block_log_for(
    file: &mut File,
    path: &Path,
    profile: NetworkProfile,
    targets: &[[u8; 32]],
) -> Result<(StorageInspection, Vec<Option<FoundRecord>>), NodeError> {
    let mut found = vec![None; targets.len()];
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("seek block log for inspection", path, error))?;
    let total_bytes = file
        .metadata()
        .map_err(|error| io_error("inspect block log length", path, error))?
        .len();
    let mut reader = BufReader::new(file);
    let mut record_index = 0_u64;
    let mut legacy_v1_records = 0_u64;
    let mut v2_records = 0_u64;
    let mut last_record_digest = EMPTY_RECORD_CHAIN_ROOT;
    let mut last_valid_offset = 0_u64;
    let mut saw_v2 = false;
    let mut known_blocks = HashSet::from([profile.virtual_genesis_hash]);

    loop {
        let record_offset = reader
            .stream_position()
            .map_err(|error| io_error("locate block-log record", path, error))?;
        let record = match read_log_record(&mut reader, path, record_index, profile.network_id) {
            Ok(Some(record)) => record,
            Ok(None) => {
                return Ok((
                    StorageInspection {
                        network: profile.short_name(),
                        records: record_index,
                        legacy_v1_records,
                        v2_records,
                        last_valid_offset,
                        total_bytes,
                        recoverable_partial_tail_bytes: 0,
                        record_chain_root: hex::encode(last_record_digest),
                    },
                    found,
                ));
            }
            Err(NodeError::CorruptLog(message)) if message.contains(" has a truncated ") => {
                return Ok((
                    StorageInspection {
                        network: profile.short_name(),
                        records: record_index,
                        legacy_v1_records,
                        v2_records,
                        last_valid_offset,
                        total_bytes,
                        recoverable_partial_tail_bytes: total_bytes
                            .checked_sub(record_offset)
                            .ok_or_else(|| {
                                NodeError::CorruptLog(
                                    "block-log tail offset exceeds file length".to_owned(),
                                )
                            })?,
                        record_chain_root: hex::encode(last_record_digest),
                    },
                    found,
                ));
            }
            Err(error) => return Err(error),
        };
        let record_end = reader
            .stream_position()
            .map_err(|error| io_error("locate block-log record end", path, error))?;
        match &record.payload {
            ParsedRecordPayload::LegacyV1 if saw_v2 => {
                return Err(NodeError::CorruptLog(format!(
                    "record {record_index} is legacy V1 after the V2 chain began"
                )));
            }
            ParsedRecordPayload::LegacyV1
                if !matches!(profile.proof, super::ProofProfile::DevnetV2Reference) =>
            {
                return Err(NodeError::ProductionLegacyBlockLog(record_index));
            }
            ParsedRecordPayload::LegacyV1 => {
                legacy_v1_records = legacy_v1_records.checked_add(1).ok_or_else(|| {
                    NodeError::CorruptLog("legacy record count overflowed".to_owned())
                })?;
            }
            ParsedRecordPayload::V2 {
                previous_record_digest,
                ..
            } => {
                if *previous_record_digest != last_record_digest {
                    return Err(NodeError::CorruptLog(format!(
                        "record {record_index} previous-record digest mismatch"
                    )));
                }
                saw_v2 = true;
                v2_records = v2_records.checked_add(1).ok_or_else(|| {
                    NodeError::CorruptLog("V2 record count overflowed".to_owned())
                })?;
            }
        }
        // Pruned records keep everything but the proof and are checked
        // against their stored header instead of re-encoded.
        let block = decode_stored_block(&record, record_index, profile.network_id)?;
        let block_id = block.block_id();
        if !known_blocks.contains(&block.challenge.previous_block) {
            return Err(NodeError::CorruptLog(format!(
                "record {record_index} names a parent that was not accepted earlier"
            )));
        }
        if !known_blocks.insert(block_id) {
            return Err(NodeError::CorruptLog(format!(
                "record {record_index} duplicates an earlier block"
            )));
        }
        for (target, found) in targets.iter().zip(&mut found) {
            if *target == block_id {
                *found = Some(FoundRecord {
                    ordinal: record_index,
                    offset: record_offset,
                    pruned: record.version == super::BlockRecordVersion::Pruned,
                });
            }
        }
        match record.payload {
            ParsedRecordPayload::LegacyV1 => {
                debug_assert_eq!(legacy_v1_records + v2_records, record_index + 1);
            }
            ParsedRecordPayload::V2 { .. } => {
                debug_assert!(saw_v2);
            }
        }
        last_record_digest = record.complete_digest;
        last_valid_offset = record_end;
        record_index = record_index
            .checked_add(1)
            .ok_or_else(|| NodeError::CorruptLog("block record count overflowed".to_owned()))?;
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::{DEFAULT_MINING_ATTEMPTS, DEVNET_GENESIS_TIMESTAMP, DEVNET_PROFILE, Node};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct OwnedTestDirectory(PathBuf);

    impl OwnedTestDirectory {
        fn new() -> Self {
            let mut identity = [0; 16];
            getrandom::fill(&mut identity).unwrap();
            let path =
                std::env::temp_dir().join(format!("cmfd-storage-launch-{}", hex::encode(identity)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for OwnedTestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn unactivated_mainnet_profile() -> NetworkProfile {
        NetworkProfile {
            kind: crate::NetworkProfileKind::Mainnet,
            virtual_genesis_hash: [0; 32],
            name: "CommonFoundry Mainnet",
            ..crate::RCNET1_PROFILE
        }
    }

    #[test]
    fn mainnet_storage_inspection_requires_launch_before_opening_data() {
        let root = OwnedTestDirectory::new();
        let result = inspect_block_log(&root.0, unactivated_mainnet_profile());
        assert!(
            matches!(result, Err(NodeError::MainnetLaunchRequired)),
            "an unauthenticated mainnet profile must not inspect storage: {result:?}"
        );
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
    }

    #[test]
    fn mainnet_storage_repair_requires_launch_before_mutating_files() {
        let root = OwnedTestDirectory::new();
        let path = root.0.join(BLOCK_LOG_FILE);
        let quarantine = root.0.join("must-not-create.quarantine");
        fs::write(&path, b"CMF").unwrap();
        let result =
            repair_partial_block_log_tail(&root.0, unactivated_mainnet_profile(), &quarantine);
        assert!(
            matches!(result, Err(NodeError::MainnetLaunchRequired)),
            "an unauthenticated mainnet profile must not repair storage: {result:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"CMF");
        assert!(!quarantine.exists());
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 1);
    }

    #[test]
    fn storage_scan_requires_the_resolved_genesis_not_an_unactivated_placeholder() {
        let root = OwnedTestDirectory::new();
        let expected_length = create_one_block_log(&root.0);
        let path = root.0.join(BLOCK_LOG_FILE);
        let mut file = File::open(&path).unwrap();
        let placeholder = NetworkProfile {
            virtual_genesis_hash: [0; 32],
            ..DEVNET_PROFILE
        };
        assert!(matches!(
            scan_block_log(&mut file, &path, placeholder),
            Err(NodeError::CorruptLog(message)) if message.contains("parent")
        ));
        let inspection = scan_block_log(&mut file, &path, DEVNET_PROFILE).unwrap();
        assert!(inspection.is_healthy());
        assert_eq!(inspection.records, 1);
        assert_eq!(inspection.last_valid_offset, expected_length);
    }

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cmfd-storage-{label}-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn create_one_block_log(path: &Path) -> u64 {
        fs::create_dir_all(path).unwrap();
        let mut node = Node::open_with_profile_artifacts_and_worker(
            path,
            DEVNET_PROFILE,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        node.mine_once(
            node.wallet_destination(),
            DEVNET_GENESIS_TIMESTAMP + 60,
            DEFAULT_MINING_ATTEMPTS,
        )
        .unwrap();
        drop(node);
        fs::metadata(path.join(BLOCK_LOG_FILE)).unwrap().len()
    }

    #[test]
    fn healthy_log_reports_its_authenticated_boundary() {
        let path = test_dir("healthy");
        let length = create_one_block_log(&path);
        let inspection = inspect_block_log(&path, DEVNET_PROFILE).unwrap();

        assert!(inspection.is_healthy());
        assert_eq!(inspection.records, 1);
        assert_eq!(inspection.v2_records, 1);
        assert_eq!(inspection.last_valid_offset, length);
        assert_eq!(inspection.total_bytes, length);
        assert_eq!(
            repair_partial_block_log_tail(&path, DEVNET_PROFILE, &path.join("unused")).unwrap(),
            None
        );
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn repair_quarantines_exact_partial_tail_and_restores_startup() {
        let path = test_dir("partial-tail");
        let valid_length = create_one_block_log(&path);
        let log_path = path.join(BLOCK_LOG_FILE);
        let tail = b"CMF";
        OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap()
            .write_all(tail)
            .unwrap();
        let inspection = inspect_block_log(&path, DEVNET_PROFILE).unwrap();
        assert_eq!(inspection.last_valid_offset, valid_length);
        assert_eq!(inspection.recoverable_partial_tail_bytes, tail.len() as u64);

        let quarantine = path.join("partial-tail.quarantine");
        fs::write(&quarantine, b"existing evidence").unwrap();
        assert!(matches!(
            repair_partial_block_log_tail(&path, DEVNET_PROFILE, &quarantine),
            Err(NodeError::Io { .. })
        ));
        assert_eq!(
            fs::metadata(&log_path).unwrap().len(),
            valid_length + tail.len() as u64
        );
        assert_eq!(fs::read(&quarantine).unwrap(), b"existing evidence");
        fs::remove_file(&quarantine).unwrap();
        let repaired = repair_partial_block_log_tail(&path, DEVNET_PROFILE, &quarantine)
            .unwrap()
            .unwrap();
        assert_eq!(repaired.quarantined_bytes, tail.len() as u64);
        assert_eq!(fs::read(&quarantine).unwrap(), tail);
        assert_eq!(fs::metadata(&log_path).unwrap().len(), valid_length);
        drop(
            Node::open_with_profile_artifacts_and_worker(
                &path,
                DEVNET_PROFILE,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap(),
        );
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn setting_the_chain_aside_keeps_the_wallet_and_a_restart_syncs_again() {
        let path = test_dir("chain-aside");
        create_one_block_log(&path);
        fs::write(path.join(super::super::work_gate::WORK_HALT_FILE), b"halt").unwrap();
        fs::write(
            path.join(super::super::work_gate::WORK_STATUS_FILE),
            b"status",
        )
        .unwrap();
        let anchor = super::super::pruning::anchor_path(&path, 7);
        fs::write(&anchor, b"anchor").unwrap();
        let candidate = super::super::pruning::candidate_path(&path, 7);
        fs::create_dir_all(candidate.parent().unwrap()).unwrap();
        fs::write(&candidate, b"candidate").unwrap();
        let open = || Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let destination = {
            let node = open();
            assert_eq!(node.state.next_height(), 2);
            node.wallet_destination()
        };
        let kept = ["network.meta", "wallet.key"];
        for name in kept {
            assert!(path.join(name).exists(), "{name}");
        }

        // Not while a node has the directory open; nothing moves.
        let running = open();
        assert!(matches!(
            set_chain_data_aside(&path),
            Err(NodeError::DataDirLocked(_))
        ));
        drop(running);
        assert!(path.join(BLOCK_LOG_FILE).exists());

        let report = set_chain_data_aside(&path).unwrap();
        assert!(report.folder.starts_with(&path));
        assert_eq!(
            report.moved.last().map(String::as_str),
            Some(BLOCK_LOG_FILE)
        );
        let anchor_name = anchor.file_name().unwrap().to_str().unwrap();
        for name in [
            "halt.v1",
            "work-status.v1",
            "prune-candidates",
            anchor_name,
            BLOCK_LOG_FILE,
        ] {
            assert!(report.moved.iter().any(|moved| moved == name), "{name}");
        }
        let log_bytes = fs::metadata(report.folder.join(BLOCK_LOG_FILE))
            .unwrap()
            .len();
        assert!(report.moved_bytes >= log_bytes + 4 + 6 + 6 + 9);
        for name in &report.moved {
            assert!(!path.join(name).exists(), "{name}");
            assert!(report.folder.join(name).exists(), "{name}");
        }
        for name in kept {
            assert!(path.join(name).exists(), "{name}");
        }
        // The next start has no chain and the same wallet.
        let node = open();
        assert_eq!(node.state.next_height(), 1);
        assert_eq!(node.wallet_destination(), destination);
        drop(node);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn repair_refuses_checksum_corruption_without_writing_quarantine() {
        let path = test_dir("checksum-corruption");
        let length = create_one_block_log(&path);
        let log_path = path.join(BLOCK_LOG_FILE);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&log_path)
            .unwrap();
        file.seek(SeekFrom::Start(length - 1)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        file.seek(SeekFrom::Start(length - 1)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let quarantine = path.join("must-not-exist.quarantine");
        assert!(matches!(
            repair_partial_block_log_tail(&path, DEVNET_PROFILE, &quarantine),
            Err(NodeError::CorruptLog(message)) if message.contains("checksum mismatch")
        ));
        assert!(!quarantine.exists());
        assert_eq!(fs::metadata(log_path).unwrap().len(), length);
        let _ = fs::remove_dir_all(path);
    }
}
