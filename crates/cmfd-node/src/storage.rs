//! Offline block-log inspection and evidence-preserving partial-tail repair.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{
    BLOCK_LOG_FILE, DataDirLock, EMPTY_RECORD_CHAIN_ROOT, NetworkProfile, NodeError,
    ParsedRecordPayload, decode_block, encode_block, io_error, read_log_record,
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

pub fn inspect_block_log(
    data_dir: &Path,
    profile: NetworkProfile,
) -> Result<StorageInspection, NodeError> {
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
    sync_parent(quarantine)?;

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
    sync_parent(&path)?;

    Ok(Some(StorageRepairReport {
        repaired_log_bytes: inspection.last_valid_offset,
        inspection,
        quarantine: quarantine.to_path_buf(),
        quarantined_bytes: tail_bytes,
    }))
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
                return Ok(StorageInspection {
                    network: profile.short_name(),
                    records: record_index,
                    legacy_v1_records,
                    v2_records,
                    last_valid_offset,
                    total_bytes,
                    recoverable_partial_tail_bytes: 0,
                    record_chain_root: hex::encode(last_record_digest),
                });
            }
            Err(NodeError::CorruptLog(message)) if message.contains(" has a truncated ") => {
                return Ok(StorageInspection {
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
                });
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
        let block = decode_block(&record.block_bytes, profile.network_id).map_err(|error| {
            NodeError::CorruptLog(format!("record {record_index} cannot decode: {error}"))
        })?;
        if encode_block(&block).map_err(|error| {
            NodeError::CorruptLog(format!("record {record_index} cannot re-encode: {error}"))
        })? != record.block_bytes
        {
            return Err(NodeError::CorruptLog(format!(
                "record {record_index} is not canonical"
            )));
        }
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

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), NodeError> {
    let parent = path.parent().ok_or_else(|| {
        io_error(
            "locate durable file parent",
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"),
        )
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error("sync durable file directory", parent, error))
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), NodeError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::{DEFAULT_MINING_ATTEMPTS, DEVNET_GENESIS_TIMESTAMP, DEVNET_PROFILE, Node};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

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
