use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use blake3::Hasher;
use primitive_types::U512;

use cmfd_consensus::{
    MAX_BLOCK_TRANSACTIONS, MAX_COINBASE_OUTPUTS, MAX_TRANSACTION_INPUTS, MAX_TRANSACTION_OUTPUTS,
    Transaction, coinbase_outpoint_id,
};

use super::explorer_address_index::{
    ActivityKind, AddressActivity, AddressHistoryIndex, AddressLocation,
};
use super::explorer_index::{TransactionIndex, TransactionLocation};
use super::{
    BlockIndex, BlockRecordLocator, BlockRecordVersion, ChainState, ConsensusPowVerifier,
    EMPTY_RECORD_CHAIN_ROOT, IndexedBlock, MAX_CHAIN_STATE_SNAPSHOT_BYTES, NetworkParams, Node,
    NodeError, ReplayLogState, SuccessorHeaderPreflight, add_chain_work, io_error,
    read_located_record, scan_replay_log, sync_parent_directory, verify_retained_block_log_path,
};

pub(super) const STARTUP_SNAPSHOT_FILE_PREFIX: &str = "startup-state";
const SNAPSHOT_MAGIC: [u8; 8] = *b"CMFDNSN\0";
const SNAPSHOT_VERSION: u32 = 1;
const SNAPSHOT_INTEGRITY_DOMAIN: &str = "CMFD/NODE/STARTUP-SNAPSHOT/LOCAL-INTEGRITY/V1";
const SNAPSHOT_HEADER_BYTES: usize = 8 + 4 + 32 + 8 + 32 + 8 + 8;
const SNAPSHOT_ENTRY_BYTES: usize =
    8 + 8 + 8 + 1 + 32 + 8 + 32 + 32 + 8 + 32 + SuccessorHeaderPreflight::LOCAL_SNAPSHOT_BYTES;
const SNAPSHOT_DIGEST_BYTES: usize = 32;
const MAX_STARTUP_SNAPSHOT_BYTES: usize = MAX_CHAIN_STATE_SNAPSHOT_BYTES + 512 * 1024 * 1024;
const INDEX_FILE: &str = "startup-index.bin";
const INDEX_MAGIC: [u8; 8] = *b"CMFDNIX\0";
/// Format 2 adds each address entry's activity facts, so pages read no blocks.
const INDEX_VERSION: u32 = 2;
/// Format 1 (1.0.15 and older) holds bare address locations; they load as
/// hints, which the background history scrub fills.
const INDEX_VERSION_LOCATIONS_ONLY: u32 = 1;
const INDEX_INTEGRITY_DOMAIN: &str = "CMFD/NODE/STARTUP-INDEX/LOCAL-INTEGRITY/V1";
const INDEX_HEADER_BYTES: usize = 8 + 4 + 32 + 8 + 8 + 32 + 8 + 8;
const INDEX_TRANSACTION_BYTES: usize = 32 + 32 + 8;
/// Address, block, height and position.
const INDEX_ADDRESS_BYTES_V1: usize = 32 + 32 + 8 + 8;
/// Txid, timestamp, received atoms, received outputs, spent inputs and kind.
const INDEX_ADDRESS_FACTS_BYTES: usize = 32 + 8 + 16 + 2 + 2 + 1;
/// The format 1 row, a flags byte (bit 0: facts present; when clear every
/// facts byte is zero) and the facts.
const INDEX_ADDRESS_BYTES_V2: usize = INDEX_ADDRESS_BYTES_V1 + 1 + INDEX_ADDRESS_FACTS_BYTES;
/// Records appended between index-cache refreshes. A fast start indexes at
/// most about this many records itself.
pub(super) const INDEX_CACHE_INTERVAL: u64 = 64;

pub(super) struct LoadedStartupSnapshot {
    pub state: ChainState,
    pub index: BlockIndex,
    pub replay: ReplayLogState,
    /// True when startup scanned the complete retained log; false for a fast
    /// start that left older records to the background history scrub.
    pub history_verified: bool,
}

pub(super) fn load_startup_snapshot(
    data_dir: &Path,
    log: &File,
    log_path: &Path,
    params: NetworkParams,
    verifier: &ConsensusPowVerifier,
) -> Result<Option<LoadedStartupSnapshot>, NodeError> {
    let log_length = log
        .metadata()
        .map_err(|source| io_error("inspect block log for startup snapshot", log_path, source))?
        .len();
    let mut best = None;
    for slot in 0..=1_u8 {
        let path = snapshot_path(data_dir, slot);
        let candidate =
            match load_slot(&path, data_dir, log, log_path, params, verifier, log_length) {
                Ok(candidate) => candidate,
                Err(error) => {
                    tracing::info!(slot, %error, "startup: snapshot slot refused");
                    None
                }
            };
        if candidate.as_ref().is_some_and(|candidate| {
            best.as_ref().is_none_or(|best: &LoadedStartupSnapshot| {
                candidate.replay.record_count > best.replay.record_count
            })
        }) {
            best = candidate;
        }
    }
    Ok(best)
}

pub(super) fn persist_startup_snapshot(node: &Node) -> Result<(), NodeError> {
    if node.storage_faulted {
        return Err(NodeError::StorageFaulted);
    }
    let log_path = node.data_dir.join(super::BLOCK_LOG_FILE);
    verify_retained_block_log_path(&node.log, &log_path)?;
    let observed_length = node
        .log
        .metadata()
        .map_err(|source| io_error("inspect block log for startup snapshot", &log_path, source))?
        .len();
    if observed_length != node.block_log_length {
        return Err(NodeError::CorruptLog(
            "startup snapshot does not match the retained log length".to_owned(),
        ));
    }
    validate_active_state(&node.state, &node.index)?;
    let state_bytes = node
        .state
        .encode_local_snapshot()
        .map_err(|error| NodeError::CorruptLog(format!("cannot encode startup state: {error}")))?;
    let mut entries: Vec<_> = node.index.blocks.values().collect();
    entries.sort_unstable_by_key(|entry| entry.locator.ordinal);
    let expected_len = SNAPSHOT_HEADER_BYTES
        .checked_add(state_bytes.len())
        .and_then(|length| length.checked_add(entries.len().checked_mul(SNAPSHOT_ENTRY_BYTES)?))
        .and_then(|length| length.checked_add(SNAPSHOT_DIGEST_BYTES))
        .ok_or_else(|| NodeError::CorruptLog("startup snapshot size overflowed".to_owned()))?;
    if expected_len > MAX_STARTUP_SNAPSHOT_BYTES {
        return Err(NodeError::CorruptLog(
            "startup snapshot exceeds its local size limit".to_owned(),
        ));
    }

    let mut bytes = Vec::with_capacity(expected_len);
    bytes.extend_from_slice(&SNAPSHOT_MAGIC);
    bytes.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&node.fingerprint);
    bytes.extend_from_slice(&node.block_log_length.to_le_bytes());
    bytes.extend_from_slice(&node.last_record_digest);
    write_count(&mut bytes, entries.len())?;
    write_count(&mut bytes, state_bytes.len())?;
    bytes.extend_from_slice(&state_bytes);
    for entry in entries {
        let locator = entry.locator;
        bytes.extend_from_slice(&locator.ordinal.to_le_bytes());
        bytes.extend_from_slice(&locator.offset.to_le_bytes());
        bytes.extend_from_slice(&locator.length.to_le_bytes());
        bytes.push(match locator.version {
            BlockRecordVersion::LegacyV1 => 1,
            BlockRecordVersion::V2 => 2,
            BlockRecordVersion::V3 => 3,
            BlockRecordVersion::Pruned => 4,
        });
        bytes.extend_from_slice(&locator.complete_digest);
        bytes.extend_from_slice(&locator.accepted_at.to_le_bytes());
        bytes.extend_from_slice(&locator.block_id);
        bytes.extend_from_slice(&locator.parent);
        bytes.extend_from_slice(&locator.height.to_le_bytes());
        bytes.extend_from_slice(&locator.target);
        bytes.extend_from_slice(&entry.successor_header.encode_local_snapshot().map_err(
            |error| NodeError::CorruptLog(format!("cannot encode startup header cache: {error}")),
        )?);
    }
    let digest = snapshot_digest(&bytes);
    bytes.extend_from_slice(&digest);
    debug_assert_eq!(bytes.len(), expected_len);

    let slot = u8::try_from(node.index.blocks.len() & 1)
        .map_err(|_| NodeError::CorruptLog("startup snapshot slot overflowed".to_owned()))?;
    persist_slot(&snapshot_path(&node.data_dir, slot), &bytes)
}

fn load_slot(
    path: &Path,
    data_dir: &Path,
    log: &File,
    log_path: &Path,
    params: NetworkParams,
    verifier: &ConsensusPowVerifier,
    log_length: u64,
) -> Result<Option<LoadedStartupSnapshot>, NodeError> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let mut file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            tracing::info!(snapshot = %name, "startup: snapshot slot absent");
            return Ok(None);
        }
        Err(source) => return Err(io_error("open startup snapshot", path, source)),
    };
    let length = file
        .metadata()
        .map_err(|source| io_error("inspect startup snapshot", path, source))?
        .len();
    let length = usize::try_from(length)
        .ok()
        .filter(|length| {
            *length >= SNAPSHOT_HEADER_BYTES + SNAPSHOT_DIGEST_BYTES
                && *length <= MAX_STARTUP_SNAPSHOT_BYTES
        })
        .ok_or_else(|| NodeError::CorruptLog("startup snapshot has an invalid size".to_owned()))?;
    let mut bytes = vec![0_u8; length];
    file.read_exact(&mut bytes)
        .map_err(|source| io_error("read startup snapshot", path, source))?;
    let (payload, expected_digest) = bytes.split_at(bytes.len() - SNAPSHOT_DIGEST_BYTES);
    if snapshot_digest(payload) != expected_digest {
        return Err(NodeError::CorruptLog(
            "startup snapshot integrity mismatch".to_owned(),
        ));
    }
    let mut decoder = Decoder::new(payload);
    if decoder.array::<8>()? != SNAPSHOT_MAGIC {
        return Err(NodeError::CorruptLog(
            "startup snapshot magic mismatch".to_owned(),
        ));
    }
    if decoder.u32()? != SNAPSHOT_VERSION {
        return Err(NodeError::CorruptLog(
            "startup snapshot version is unsupported".to_owned(),
        ));
    }
    if decoder.array::<32>()? != params.fingerprint()? {
        return Err(NodeError::CorruptLog(
            "startup snapshot belongs to another network".to_owned(),
        ));
    }
    let snapshot_log_length = decoder.u64()?;
    let last_record_digest = decoder.array::<32>()?;
    let record_count = decoder.count()?;
    let state_length = decoder.count()?;
    if snapshot_log_length != log_length {
        tracing::info!(
            snapshot = %name,
            snapshot_log_bytes = snapshot_log_length,
            log_bytes = log_length,
            "startup: snapshot slot is for another block log length"
        );
        return Ok(None);
    }
    if state_length > MAX_CHAIN_STATE_SNAPSHOT_BYTES {
        return Ok(None);
    }
    let expected_length = SNAPSHOT_HEADER_BYTES
        .checked_add(state_length)
        .and_then(|length| length.checked_add(record_count.checked_mul(SNAPSHOT_ENTRY_BYTES)?))
        .ok_or_else(|| NodeError::CorruptLog("startup snapshot size overflowed".to_owned()))?;
    if expected_length != payload.len() {
        return Err(NodeError::CorruptLog(
            "startup snapshot length mismatch".to_owned(),
        ));
    }
    let state =
        ChainState::decode_local_snapshot(decoder.take(state_length)?, params, verifier.clone())
            .map_err(|error| NodeError::CorruptLog(format!("startup state is invalid: {error}")))?;

    let mut index = BlockIndex::new(params.genesis_hash);
    let mut known = HashSet::from([params.genesis_hash]);
    let mut expected_offset = 0_u64;
    let mut saw_v2 = false;
    let mut winning_tip = params.genesis_hash;
    let mut winning_work = U512::zero();
    let mut winning_ordinal = u64::MAX;
    let mut last_locator = None;
    for ordinal in 0..record_count {
        let locator = BlockRecordLocator {
            ordinal: decoder.u64()?,
            offset: decoder.u64()?,
            length: decoder.u64()?,
            version: match decoder.byte()? {
                1 if !saw_v2 => BlockRecordVersion::LegacyV1,
                2 => {
                    saw_v2 = true;
                    BlockRecordVersion::V2
                }
                3 => {
                    saw_v2 = true;
                    BlockRecordVersion::V3
                }
                4 => {
                    saw_v2 = true;
                    BlockRecordVersion::Pruned
                }
                _ => {
                    return Err(NodeError::CorruptLog(
                        "startup snapshot record version is invalid".to_owned(),
                    ));
                }
            },
            complete_digest: decoder.array::<32>()?,
            accepted_at: decoder.u64()?,
            block_id: decoder.array::<32>()?,
            parent: decoder.array::<32>()?,
            height: decoder.u64()?,
            target: decoder.array::<32>()?,
        };
        let successor_bytes =
            decoder.array::<{ SuccessorHeaderPreflight::LOCAL_SNAPSHOT_BYTES }>()?;
        let successor_header =
            SuccessorHeaderPreflight::decode_local_snapshot(&successor_bytes, params).map_err(
                |error| NodeError::CorruptLog(format!("startup header cache is invalid: {error}")),
            )?;
        if locator.ordinal != u64::try_from(ordinal).unwrap_or(u64::MAX)
            || locator.offset != expected_offset
            || locator.length == 0
            || !known.contains(&locator.parent)
            || !known.insert(locator.block_id)
        {
            return Err(NodeError::CorruptLog(
                "startup snapshot record index is inconsistent".to_owned(),
            ));
        }
        let parent_height = if locator.parent == index.genesis {
            0
        } else {
            index
                .blocks
                .get(&locator.parent)
                .ok_or_else(|| NodeError::CorruptLog("snapshot parent is absent".to_owned()))?
                .height()
        };
        if locator.height != parent_height.saturating_add(1) {
            return Err(NodeError::CorruptLog(
                "startup snapshot height is inconsistent".to_owned(),
            ));
        }
        let parent_work = index.work_at(locator.parent).ok_or_else(|| {
            NodeError::CorruptLog("startup snapshot parent work is absent".to_owned())
        })?;
        let cumulative_work = add_chain_work(parent_work, locator.target).map_err(|error| {
            NodeError::CorruptLog(format!("startup snapshot work is invalid: {error}"))
        })?;
        let ancestors = index.ancestor_table(locator.parent)?;
        let entry = Arc::new(IndexedBlock {
            locator,
            cumulative_work,
            successor_header,
            ancestors,
        });
        let encoded_successor =
            entry
                .successor_header
                .encode_local_snapshot()
                .map_err(|error| {
                    NodeError::CorruptLog(format!("startup header cache is invalid: {error}"))
                })?;
        if encoded_successor[32..64] != locator.block_id
            || encoded_successor[64..72] != locator.height.saturating_add(1).to_le_bytes()
        {
            return Err(NodeError::CorruptLog(
                "startup header cache does not match its block".to_owned(),
            ));
        }
        if cumulative_work > winning_work
            || (cumulative_work == winning_work && locator.ordinal < winning_ordinal)
        {
            winning_tip = locator.block_id;
            winning_work = cumulative_work;
            winning_ordinal = locator.ordinal;
        }
        expected_offset = expected_offset
            .checked_add(locator.length)
            .ok_or_else(|| NodeError::CorruptLog("startup locator overflowed".to_owned()))?;
        last_locator = Some(locator);
        index.blocks.insert(locator.block_id, entry);
    }
    if !decoder.is_empty()
        || expected_offset != snapshot_log_length
        || index.blocks.len() != record_count
    {
        return Err(NodeError::CorruptLog(
            "startup snapshot index has trailing or missing data".to_owned(),
        ));
    }
    // A local snapshot is a replay accelerator, not an authority over the
    // append-only block log. With a valid index cache, startup reads only the
    // records the cache does not cover; the background history scrub then
    // checks every older record against these locators, and a mismatch faults
    // storage and moves the caches aside so the next start rebuilds from the
    // log. Without the cache, scan the complete retained record chain now.
    let cached = load_index_cache(data_dir, params, &index, record_count, log, log_path);
    let history_verified = cached.is_none();
    let (transactions, addresses) = match cached {
        Some(indexes) => indexes,
        None => {
            let scan_started_at = std::time::Instant::now();
            tracing::info!(
                records = record_count,
                log_bytes = snapshot_log_length,
                "startup: scanning the whole block log to rebuild its indexes"
            );
            let mut scan_file = log.try_clone().map_err(|source| {
                io_error("clone block log for startup validation", log_path, source)
            })?;
            scan_file.seek(SeekFrom::Start(0)).map_err(|source| {
                io_error("seek block log for startup validation", log_path, source)
            })?;
            let scanned = scan_replay_log(scan_file, log_path, params, params.network_id)?;
            if scanned.log_length != snapshot_log_length
                || scanned.last_record_digest != last_record_digest
                || scanned.records.len() != record_count
                || scanned.records.iter().any(|locator| {
                    index
                        .blocks
                        .get(&locator.block_id)
                        .is_none_or(|entry| entry.locator != *locator)
                })
            {
                return Err(NodeError::CorruptLog(
                    "startup snapshot block-log chain binding mismatch".to_owned(),
                ));
            }
            tracing::info!(
                records = record_count,
                seconds = scan_started_at.elapsed().as_secs_f64(),
                "startup: block log scanned"
            );
            (scanned.transactions, scanned.addresses)
        }
    };
    match last_locator {
        Some(locator) => {
            if locator.complete_digest != last_record_digest {
                return Err(NodeError::CorruptLog(
                    "startup snapshot terminal digest mismatch".to_owned(),
                ));
            }
            read_located_record(log, log_path, &locator, params.network_id, false)?;
        }
        None if last_record_digest == EMPTY_RECORD_CHAIN_ROOT && snapshot_log_length == 0 => {}
        None => {
            return Err(NodeError::CorruptLog(
                "empty startup snapshot has nonempty log bindings".to_owned(),
            ));
        }
    }
    if state.tip() != winning_tip {
        return Err(NodeError::CorruptLog(
            "startup snapshot state does not match fork choice".to_owned(),
        ));
    }
    index.active_chain = vec![index.genesis];
    index.active_chain.extend(index.path_to(winning_tip)?);
    index.active_work = winning_work;
    validate_active_state(&state, &index)?;
    // Cached transaction locations are hints: every lookup reads and
    // authenticates the block it names. Cached address facts carry the same
    // local trust as this snapshot's UTXO set (integrity digest, record
    // binding and the loader's consistency checks); a hint address entry
    // (one without facts) is authenticated on every lookup that reaches it.
    index.transactions = transactions;
    index.addresses = addresses;
    verify_retained_block_log_path(log, log_path)?;
    tracing::info!(
        snapshot = %name,
        records = record_count,
        history_verified,
        "startup: snapshot slot matches the block log"
    );
    Ok(Some(LoadedStartupSnapshot {
        state,
        index,
        replay: ReplayLogState {
            last_record_digest,
            log_length: snapshot_log_length,
            record_count: u64::try_from(record_count).map_err(|_| {
                NodeError::CorruptLog("startup snapshot record count overflowed".to_owned())
            })?,
        },
        history_verified,
    }))
}

/// The cached state belongs to the selected chain, not necessarily the last
/// appended record. Nonwinning branches remain in the index and are still
/// checked against every record in the complete retained-log scan on load.
fn validate_active_state(state: &ChainState, index: &BlockIndex) -> Result<(), NodeError> {
    // Equal-work arrivals do not displace the first retained winner. Match
    // live strict-greater activation and the full-replay ordinal tie-break.
    let winner = index.blocks.values().max_by(|left, right| {
        left.cumulative_work
            .cmp(&right.cumulative_work)
            .then_with(|| right.locator.ordinal.cmp(&left.locator.ordinal))
    });
    let winning_tip = winner.map_or(index.genesis, |entry| entry.block_id());
    let winning_work = winner.map_or(U512::zero(), |entry| entry.cumulative_work);
    let expected_len = usize::try_from(state.next_height()).map_err(|_| {
        NodeError::CorruptLog("startup state height does not fit this platform".to_owned())
    })?;
    let mut active_chain = vec![index.genesis];
    active_chain.extend(index.path_to(winning_tip)?);
    if state.tip() != winning_tip
        || active_chain.len() != expected_len
        || index.active_chain != active_chain
        || index.active_work != winning_work
    {
        return Err(NodeError::CorruptLog(
            "startup state and active fork metadata disagree".to_owned(),
        ));
    }
    if let Some(winner) = winner
        && winner.successor_header != state.successor_header_preflight()?
    {
        return Err(NodeError::CorruptLog(
            "startup active header does not match cached chain state".to_owned(),
        ));
    }
    Ok(())
}

fn persist_slot(path: &Path, bytes: &[u8]) -> Result<(), NodeError> {
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).map_err(|source| {
        io_error(
            "generate startup snapshot path",
            path,
            io::Error::other(source.to_string()),
        )
    })?;
    let parent = path.parent().ok_or_else(|| {
        io_error(
            "locate startup snapshot directory",
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "snapshot path has no parent"),
        )
    })?;
    let temporary = parent.join(format!(
        ".{STARTUP_SNAPSHOT_FILE_PREFIX}.tmp-{}",
        hex::encode(suffix)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| io_error("create startup snapshot", &temporary, source))?;
        file.write_all(bytes)
            .map_err(|source| io_error("write startup snapshot", &temporary, source))?;
        file.sync_all()
            .map_err(|source| io_error("sync startup snapshot", &temporary, source))?;
        publish_slot(&file, &temporary, path)?;
        sync_parent_directory(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

/// Windows has no directory sync, so a remove and a rename of the slot could
/// both be lost in a power cut, which leaves the slot missing or older than
/// the synced block log and forces a full replay. Rename over the slot in one
/// step instead (std renames over a file another handle holds open, which
/// `MoveFileExW` refuses), then flush the renamed file through its open
/// handle, which asks NTFS to commit the file and its new name before this
/// returns.
#[cfg(windows)]
fn publish_slot(file: &File, temporary: &Path, path: &Path) -> Result<(), NodeError> {
    fs::rename(temporary, path)
        .map_err(|source| io_error("publish startup snapshot", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync published startup snapshot", path, source))
}

#[cfg(not(windows))]
fn publish_slot(_file: &File, temporary: &Path, path: &Path) -> Result<(), NodeError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(io_error("replace startup snapshot", path, source)),
    }
    fs::rename(temporary, path).map_err(|source| io_error("publish startup snapshot", path, source))
}

fn snapshot_path(data_dir: &Path, slot: u8) -> PathBuf {
    data_dir.join(format!("{STARTUP_SNAPSHOT_FILE_PREFIX}.{slot}.bin"))
}

/// Saves the explorer transaction and address indexes, address activity facts
/// included, bound to the newest retained record by its complete digest, so a
/// fast start need not decode the whole log to rebuild them.
pub(super) fn persist_index_cache(node: &Node) -> Result<(), NodeError> {
    if node.storage_faulted {
        return Err(NodeError::StorageFaulted);
    }
    let newest = node
        .index
        .blocks
        .values()
        .map(|entry| entry.locator)
        .max_by_key(|locator| locator.ordinal);
    let (covered_records, covered_length, covered_digest) = match newest {
        Some(locator) => (
            locator.ordinal.saturating_add(1),
            locator.offset.saturating_add(locator.length),
            locator.complete_digest,
        ),
        None => (0, 0, EMPTY_RECORD_CHAIN_ROOT),
    };
    if covered_records != node.record_count
        || covered_length != node.block_log_length
        || covered_digest != node.last_record_digest
    {
        return Err(NodeError::CorruptLog(
            "index cache does not match the retained log".to_owned(),
        ));
    }
    // The loader refuses the whole cache for an entry whose block the fork
    // index does not hold, and such an entry is never served: leave it out.
    let blocks = &node.index.blocks;
    let transaction_entries = || {
        node.index
            .transactions
            .entries()
            .filter(move |(_, location)| blocks.contains_key(&location.block_id))
    };
    let address_entries = || {
        node.index
            .addresses
            .entries()
            .filter(move |(_, location, _)| blocks.contains_key(&location.block_id))
    };
    let transactions = transaction_entries().count();
    let addresses = address_entries().count();
    // After a prune, none should be left out; one that is shows here rather
    // than nowhere.
    let left_out_transactions = node.index.transactions.entries().count() - transactions;
    let left_out_addresses = node.index.addresses.entries().count() - addresses;
    if left_out_transactions > 0 || left_out_addresses > 0 {
        tracing::info!(
            transactions = left_out_transactions,
            addresses = left_out_addresses,
            "startup: index cache left out entries for blocks the fork index does not hold"
        );
    }
    let mut bytes = Vec::with_capacity(
        INDEX_HEADER_BYTES
            + transactions * INDEX_TRANSACTION_BYTES
            + addresses * INDEX_ADDRESS_BYTES_V2
            + SNAPSHOT_DIGEST_BYTES,
    );
    bytes.extend_from_slice(&INDEX_MAGIC);
    bytes.extend_from_slice(&INDEX_VERSION.to_le_bytes());
    bytes.extend_from_slice(&node.fingerprint);
    bytes.extend_from_slice(&covered_records.to_le_bytes());
    bytes.extend_from_slice(&covered_length.to_le_bytes());
    bytes.extend_from_slice(&covered_digest);
    write_count(&mut bytes, transactions)?;
    write_count(&mut bytes, addresses)?;
    for (txid, location) in transaction_entries() {
        bytes.extend_from_slice(&txid);
        bytes.extend_from_slice(&location.block_id);
        bytes.extend_from_slice(&(location.transaction_position as u64).to_le_bytes());
    }
    for (address, location, facts) in address_entries() {
        bytes.extend_from_slice(&address);
        bytes.extend_from_slice(&location.block_id);
        bytes.extend_from_slice(&location.height.to_le_bytes());
        bytes.extend_from_slice(&(location.position as u64).to_le_bytes());
        match facts {
            Some(facts) => {
                bytes.push(1);
                bytes.extend_from_slice(&facts.txid);
                bytes.extend_from_slice(&facts.timestamp.to_le_bytes());
                bytes.extend_from_slice(&facts.received_atoms.to_le_bytes());
                bytes.extend_from_slice(&facts.received_outputs.to_le_bytes());
                bytes.extend_from_slice(&facts.spent_inputs.to_le_bytes());
                bytes.push(facts.kind.to_byte());
            }
            None => bytes.resize(bytes.len() + 1 + INDEX_ADDRESS_FACTS_BYTES, 0),
        }
    }
    let digest = index_digest(&bytes);
    bytes.extend_from_slice(&digest);
    persist_slot(&node.data_dir.join(INDEX_FILE), &bytes)
}

/// Restores the location indexes for a snapshot-restored fork index, then
/// indexes the records the cache does not cover by reading them through the
/// authenticated record path. Any cache that is absent, foreign, damaged, not
/// bound to this log or internally inconsistent yields `None`, and startup
/// scans the whole log.
fn load_index_cache(
    data_dir: &Path,
    params: NetworkParams,
    index: &BlockIndex,
    record_count: usize,
    log: &File,
    log_path: &Path,
) -> Option<(TransactionIndex, AddressHistoryIndex)> {
    match read_index_cache(data_dir, params, index, record_count, log, log_path) {
        Ok(indexes) => Some(indexes),
        Err(reason) => {
            tracing::info!(reason, "startup: index cache not used");
            None
        }
    }
}

/// [`load_index_cache`], with the reason a cache is refused.
fn read_index_cache(
    data_dir: &Path,
    params: NetworkParams,
    index: &BlockIndex,
    record_count: usize,
    log: &File,
    log_path: &Path,
) -> Result<(TransactionIndex, AddressHistoryIndex), &'static str> {
    const MALFORMED: &str = "malformed";
    let bytes = fs::read(data_dir.join(INDEX_FILE)).map_err(|_| "absent or unreadable")?;
    if bytes.len() < INDEX_HEADER_BYTES + SNAPSHOT_DIGEST_BYTES {
        return Err("too short");
    }
    let (payload, digest) = bytes.split_at(bytes.len() - SNAPSHOT_DIGEST_BYTES);
    if index_digest(payload) != digest {
        return Err("integrity digest mismatch");
    }
    let mut decoder = Decoder::new(payload);
    if decoder.array::<8>().map_err(|_| MALFORMED)? != INDEX_MAGIC {
        return Err("not an index cache");
    }
    let version = decoder.u32().map_err(|_| MALFORMED)?;
    let address_bytes = match version {
        INDEX_VERSION => INDEX_ADDRESS_BYTES_V2,
        INDEX_VERSION_LOCATIONS_ONLY => INDEX_ADDRESS_BYTES_V1,
        _ => return Err("unsupported format"),
    };
    if decoder.array::<32>().map_err(|_| MALFORMED)?
        != params
            .fingerprint()
            .map_err(|_| "network fingerprint unavailable")?
    {
        return Err("another network");
    }
    let covered = usize::try_from(decoder.u64().map_err(|_| MALFORMED)?).map_err(|_| MALFORMED)?;
    let covered_length = decoder.u64().map_err(|_| MALFORMED)?;
    let covered_digest = decoder.array::<32>().map_err(|_| MALFORMED)?;
    let transactions = decoder.count().map_err(|_| MALFORMED)?;
    let addresses = decoder.count().map_err(|_| MALFORMED)?;
    let expected = transactions
        .checked_mul(INDEX_TRANSACTION_BYTES)
        .and_then(|bytes| INDEX_HEADER_BYTES.checked_add(bytes))
        .and_then(|length| {
            addresses
                .checked_mul(address_bytes)
                .and_then(|bytes| length.checked_add(bytes))
        })
        .ok_or(MALFORMED)?;
    if expected != payload.len() {
        return Err("size does not match its counts");
    }
    if covered > record_count {
        return Err("covers more records than the snapshot");
    }
    let mut locators: Vec<BlockRecordLocator> =
        index.blocks.values().map(|entry| entry.locator).collect();
    locators.sort_unstable_by_key(|locator| locator.ordinal);
    if locators.len() != record_count {
        return Err("snapshot record count disagrees with its index");
    }
    let bound = match covered.checked_sub(1).map(|position| locators[position]) {
        Some(locator) => {
            locator.complete_digest == covered_digest
                && locator.offset.checked_add(locator.length) == Some(covered_length)
        }
        None => covered_length == 0 && covered_digest == EMPTY_RECORD_CHAIN_ROOT,
    };
    if !bound {
        return Err("not bound to this block log");
    }
    let mut transaction_index = TransactionIndex::default();
    for _ in 0..transactions {
        let txid = decoder.array::<32>().map_err(|_| MALFORMED)?;
        let block_id = decoder.array::<32>().map_err(|_| MALFORMED)?;
        let transaction_position =
            usize::try_from(decoder.u64().map_err(|_| MALFORMED)?).map_err(|_| MALFORMED)?;
        if !index.blocks.contains_key(&block_id) {
            return Err("a transaction entry names a block the snapshot does not hold");
        }
        transaction_index.insert_location(
            txid,
            TransactionLocation {
                block_id,
                transaction_position,
            },
        );
    }
    let mut address_index = AddressHistoryIndex::default();
    let mut hint_entries = 0_usize;
    let mut hint_blocks = HashSet::new();
    for _ in 0..addresses {
        let address = decoder.array::<32>().map_err(|_| MALFORMED)?;
        let block_id = decoder.array::<32>().map_err(|_| MALFORMED)?;
        let height = decoder.u64().map_err(|_| MALFORMED)?;
        let position =
            usize::try_from(decoder.u64().map_err(|_| MALFORMED)?).map_err(|_| MALFORMED)?;
        if index
            .blocks
            .get(&block_id)
            .ok_or("an address entry names a block the snapshot does not hold")?
            .height()
            != height
        {
            return Err("an address entry's height does not match its block");
        }
        let location = AddressLocation {
            height,
            position,
            block_id,
        };
        let facts = match version {
            INDEX_VERSION => {
                decode_address_facts(&mut decoder, location, params, &transaction_index)
                    .ok_or("an address entry's activity facts are inconsistent")?
            }
            _ => None,
        };
        match facts {
            Some(facts) => address_index.insert_block_entries([(address, location, facts)]),
            None => {
                address_index.insert_entries([(address, location)]);
                hint_entries += 1;
                hint_blocks.insert(block_id);
            }
        }
    }
    for locator in &locators[covered..] {
        let (_, block) = read_located_record(log, log_path, locator, params.network_id, false)
            .map_err(|_| "a record the cache does not cover could not be read")?;
        transaction_index.insert_block(
            block.block_id(),
            block.transactions.iter().map(Transaction::txid),
        );
        address_index.insert_block_entries(AddressHistoryIndex::stored_block_entries(&block));
    }
    let uncovered = record_count - covered;
    if version == INDEX_VERSION_LOCATIONS_ONLY {
        tracing::info!(
            format = version,
            entries = address_index.entry_count(),
            hint_entries,
            hint_blocks = hint_blocks.len(),
            uncovered,
            "explorer index cache loaded; the background history scrub fills activity facts; until then, pages that reach those blocks read them once"
        );
    } else {
        tracing::info!(
            format = version,
            entries = address_index.entry_count(),
            hint_entries,
            hint_blocks = hint_blocks.len(),
            uncovered,
            "explorer index cache loaded"
        );
    }
    Ok((transaction_index, address_index))
}

/// Reads one format 2 row's flags and facts and checks them against the row's
/// location and the transaction section. `None` rejects the cache;
/// `Some(None)` is a hint row.
fn decode_address_facts(
    decoder: &mut Decoder<'_>,
    location: AddressLocation,
    params: NetworkParams,
    transactions: &TransactionIndex,
) -> Option<Option<AddressActivity>> {
    let flags = decoder.byte().ok()?;
    let bytes = decoder.take(INDEX_ADDRESS_FACTS_BYTES).ok()?;
    match flags {
        0 => return bytes.iter().all(|byte| *byte == 0).then_some(None),
        1 => {}
        _ => return None,
    }
    let mut facts = Decoder::new(bytes);
    let txid = facts.array::<32>().ok()?;
    let timestamp = facts.u64().ok()?;
    let received_atoms = facts.u128().ok()?;
    let received_outputs = facts.u16().ok()?;
    let spent_inputs = facts.u16().ok()?;
    let kind = ActivityKind::from_byte(facts.byte().ok()?)?;
    let received = usize::from(received_outputs);
    let spent = usize::from(spent_inputs);
    // Outputs to the key, or only spent inputs and no atoms.
    let consistent = (received > 0 || (spent > 0 && received_atoms == 0))
        && location.position <= MAX_BLOCK_TRANSACTIONS
        && if location.position == 0 {
            kind == ActivityKind::Coinbase
                && spent == 0
                && received <= MAX_COINBASE_OUTPUTS
                && txid == coinbase_outpoint_id(params.network_id, location.block_id)
        } else {
            received <= MAX_TRANSACTION_OUTPUTS
                && spent <= MAX_TRANSACTION_INPUTS
                && match kind {
                    ActivityKind::Coinbase => false,
                    ActivityKind::Received => spent == 0,
                    ActivityKind::Sent => spent > 0,
                    ActivityKind::SelfTransfer => spent > 0 && received > 0,
                }
                && transactions.has_location(
                    &txid,
                    TransactionLocation {
                        block_id: location.block_id,
                        transaction_position: location.position - 1,
                    },
                )
        };
    consistent.then_some(Some(AddressActivity {
        txid,
        received_atoms,
        timestamp,
        received_outputs,
        spent_inputs,
        kind,
    }))
}

/// Moves the startup caches aside after the history scrub found the log and
/// the caches disagreeing. The next start then scans or replays the log, which
/// stays authoritative.
pub(super) fn quarantine_startup_caches(data_dir: &Path) {
    let stamp = super::unix_time_seconds().unwrap_or_default();
    for name in startup_cache_file_names() {
        let path = data_dir.join(&name);
        if path.exists() {
            let _ = fs::rename(&path, data_dir.join(format!("{name}.invalid-{stamp}")));
        }
    }
    let _ = sync_parent_directory(&data_dir.join(INDEX_FILE));
}

/// The files a fast start reads instead of replaying the block log.
pub(super) fn startup_cache_file_names() -> [String; 3] {
    [
        format!("{STARTUP_SNAPSHOT_FILE_PREFIX}.0.bin"),
        format!("{STARTUP_SNAPSHOT_FILE_PREFIX}.1.bin"),
        INDEX_FILE.to_owned(),
    ]
}

fn index_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(INDEX_INTEGRITY_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
pub(super) fn invalidate_fixture_snapshots(data_dir: &Path) {
    assert!(data_dir.starts_with(std::env::temp_dir()));
    let mut damaged = 0;
    for slot in 0..=1 {
        let path = snapshot_path(data_dir, slot);
        if path.exists() {
            let mut bytes = fs::read(&path).unwrap();
            *bytes.last_mut().unwrap() ^= 1;
            fs::write(path, bytes).unwrap();
            damaged += 1;
        }
    }
    assert!(damaged > 0, "fixture must exercise an existing cache");
}

/// Byte offsets of the address rows in an index cache, and the row size.
#[cfg(test)]
fn index_address_rows(bytes: &[u8]) -> (usize, usize, usize) {
    let count = |offset: usize| {
        usize::try_from(u64::from_le_bytes(
            bytes[offset..offset + 8].try_into().unwrap(),
        ))
        .unwrap()
    };
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let row = match version {
        INDEX_VERSION => INDEX_ADDRESS_BYTES_V2,
        INDEX_VERSION_LOCATIONS_ONLY => INDEX_ADDRESS_BYTES_V1,
        _ => panic!("unknown index cache format"),
    };
    let transactions = count(INDEX_HEADER_BYTES - 16);
    let addresses = count(INDEX_HEADER_BYTES - 8);
    (
        INDEX_HEADER_BYTES + transactions * INDEX_TRANSACTION_BYTES,
        addresses,
        row,
    )
}

#[cfg(test)]
fn redigest_index_cache(bytes: &mut [u8]) {
    let digest_offset = bytes.len() - SNAPSHOT_DIGEST_BYTES;
    let digest = index_digest(&bytes[..digest_offset]);
    bytes[digest_offset..].copy_from_slice(&digest);
}

/// The format of the index cache on disk and its hint (flag 0) rows.
#[cfg(test)]
pub(super) fn index_cache_format(data_dir: &Path) -> (u32, usize) {
    let bytes = fs::read(data_dir.join(INDEX_FILE)).unwrap();
    let (start, addresses, row) = index_address_rows(&bytes);
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let hints = (0..addresses)
        .filter(|index| {
            version == INDEX_VERSION_LOCATIONS_ONLY
                || bytes[start + index * row + INDEX_ADDRESS_BYTES_V1] == 0
        })
        .count();
    (version, hints)
}

/// Re-encodes the index cache as format 1, as 1.0.15 wrote it, with `extra`
/// address rows appended.
#[cfg(test)]
pub(super) fn rewrite_index_cache_as_v1(data_dir: &Path, extra: &[([u8; 32], AddressLocation)]) {
    let path = data_dir.join(INDEX_FILE);
    let bytes = fs::read(&path).unwrap();
    let (start, addresses, row) = index_address_rows(&bytes);
    assert_eq!(row, INDEX_ADDRESS_BYTES_V2);
    let mut rewritten = bytes[..start].to_vec();
    rewritten[8..12].copy_from_slice(&INDEX_VERSION_LOCATIONS_ONLY.to_le_bytes());
    rewritten[INDEX_HEADER_BYTES - 8..INDEX_HEADER_BYTES]
        .copy_from_slice(&((addresses + extra.len()) as u64).to_le_bytes());
    for index in 0..addresses {
        let offset = start + index * row;
        rewritten.extend_from_slice(&bytes[offset..offset + INDEX_ADDRESS_BYTES_V1]);
    }
    for (address, location) in extra {
        rewritten.extend_from_slice(address);
        rewritten.extend_from_slice(&location.block_id);
        rewritten.extend_from_slice(&location.height.to_le_bytes());
        rewritten.extend_from_slice(&(location.position as u64).to_le_bytes());
    }
    rewritten.extend_from_slice(&[0; SNAPSHOT_DIGEST_BYTES]);
    redigest_index_cache(&mut rewritten);
    fs::write(path, rewritten).unwrap();
}

/// Edits the first format 2 address row `pick` selects, then re-digests the
/// cache so only the loader's consistency checks can refuse it.
#[cfg(test)]
pub(super) fn tamper_index_address_row(
    data_dir: &Path,
    pick: impl Fn(&[u8]) -> bool,
    edit: impl FnOnce(&mut [u8]),
) {
    let path = data_dir.join(INDEX_FILE);
    let mut bytes = fs::read(&path).unwrap();
    let (start, addresses, row) = index_address_rows(&bytes);
    assert_eq!(row, INDEX_ADDRESS_BYTES_V2);
    let offset = (0..addresses)
        .map(|index| start + index * row)
        .find(|offset| pick(&bytes[*offset..*offset + row]))
        .expect("no address row matches");
    edit(&mut bytes[offset..offset + row]);
    redigest_index_cache(&mut bytes);
    fs::write(path, bytes).unwrap();
}

#[cfg(test)]
#[path = "startup_snapshot_fork_tests.rs"]
mod fork_tests;

fn write_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), NodeError> {
    bytes.extend_from_slice(
        &u64::try_from(count)
            .map_err(|_| NodeError::CorruptLog("startup snapshot count overflowed".to_owned()))?
            .to_le_bytes(),
    );
    Ok(())
}

fn snapshot_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(SNAPSHOT_INTEGRITY_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], NodeError> {
        if self.remaining.len() < length {
            return Err(NodeError::CorruptLog(
                "startup snapshot is truncated".to_owned(),
            ));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], NodeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| NodeError::CorruptLog("startup snapshot is truncated".to_owned()))
    }

    fn byte(&mut self) -> Result<u8, NodeError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, NodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, NodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, NodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn u128(&mut self) -> Result<u128, NodeError> {
        Ok(u128::from_le_bytes(self.array()?))
    }

    fn count(&mut self) -> Result<usize, NodeError> {
        usize::try_from(self.u64()?)
            .map_err(|_| NodeError::CorruptLog("startup snapshot count overflowed".to_owned()))
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::{DEFAULT_MINING_ATTEMPTS, DEVNET_PROFILE, Node, unix_time_seconds};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cmfd-startup-snapshot-{label}-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn accepted_linear_block_refreshes_snapshot_without_shutdown() {
        let path = test_dir("restore");
        let now = unix_time_seconds().unwrap();
        let expected_tip = {
            let mut node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
            assert!(!node.status().unwrap().startup_snapshot_used);
            let block = node
                .mine_once(node.wallet_destination(), now, DEFAULT_MINING_ATTEMPTS)
                .unwrap();
            block.block_id()
        };

        let reopened = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let status = reopened.status().unwrap();
        assert!(status.startup_snapshot_used);
        assert_eq!(reopened.state.tip(), expected_tip);
        assert_eq!(status.accepted_height, 1);
        drop(reopened);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn corrupt_snapshot_falls_back_to_full_replay() {
        let path = test_dir("fallback");
        {
            let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
            node.persist_startup_snapshot().unwrap();
        }
        let snapshot = snapshot_path(&path, 0);
        let mut bytes = fs::read(&snapshot).unwrap();
        bytes[SNAPSHOT_HEADER_BYTES] ^= 1;
        fs::write(&snapshot, bytes).unwrap();

        let reopened = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        assert!(!reopened.status().unwrap().startup_snapshot_used);
        drop(reopened);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn semantically_inconsistent_snapshot_falls_back_to_full_replay() {
        let path = test_dir("semantic-fallback");
        let now = unix_time_seconds().unwrap();
        {
            let mut node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
            node.mine_once(node.wallet_destination(), now, DEFAULT_MINING_ATTEMPTS)
                .unwrap();
            node.persist_startup_snapshot().unwrap();
        }
        let snapshot = snapshot_path(&path, 1);
        let mut bytes = fs::read(&snapshot).unwrap();
        let state_length = usize::try_from(u64::from_le_bytes(
            bytes[SNAPSHOT_HEADER_BYTES - 8..SNAPSHOT_HEADER_BYTES]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        let first_entry = SNAPSHOT_HEADER_BYTES + state_length;
        let height_offset = first_entry + 8 + 8 + 8 + 1 + 32 + 8 + 32 + 32;
        bytes[height_offset..height_offset + 8].copy_from_slice(&2_u64.to_le_bytes());
        let digest_offset = bytes.len() - SNAPSHOT_DIGEST_BYTES;
        let digest = snapshot_digest(&bytes[..digest_offset]);
        bytes[digest_offset..].copy_from_slice(&digest);
        fs::write(&snapshot, bytes).unwrap();

        let reopened = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        assert!(!reopened.status().unwrap().startup_snapshot_used);
        assert_eq!(reopened.status().unwrap().accepted_height, 1);
        drop(reopened);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn nonterminal_snapshot_locator_must_match_the_scanned_record() {
        let path = test_dir("nonterminal-locator");
        let now = unix_time_seconds().unwrap();
        {
            let mut node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
            node.mine_once(node.wallet_destination(), now, DEFAULT_MINING_ATTEMPTS)
                .unwrap();
            node.mine_once(node.wallet_destination(), now + 60, DEFAULT_MINING_ATTEMPTS)
                .unwrap();
        }
        let snapshot = snapshot_path(&path, 0);
        let mut bytes = fs::read(&snapshot).unwrap();
        let state_length = usize::try_from(u64::from_le_bytes(
            bytes[SNAPSHOT_HEADER_BYTES - 8..SNAPSHOT_HEADER_BYTES]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        let accepted_at_offset = SNAPSHOT_HEADER_BYTES + state_length + 8 + 8 + 8 + 1 + 32;
        bytes[accepted_at_offset..accepted_at_offset + 8].copy_from_slice(&(now + 1).to_le_bytes());
        let digest_offset = bytes.len() - SNAPSHOT_DIGEST_BYTES;
        let digest = snapshot_digest(&bytes[..digest_offset]);
        bytes[digest_offset..].copy_from_slice(&digest);
        fs::write(&snapshot, bytes).unwrap();
        let reopened = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        assert!(!reopened.startup_snapshot_used);
        assert_eq!(reopened.state.next_height(), 3);
        drop(reopened);
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn a_slot_publish_replaces_the_slot_in_one_step_and_leaves_no_temporary() {
        let path = test_dir("publish");
        fs::create_dir_all(&path).unwrap();
        let slot = snapshot_path(&path, 0);
        persist_slot(&slot, b"first").unwrap();
        // Another handle on the old slot (a virus scan, a backup) does not
        // stop the replacement, as it did not stop the old remove and rename.
        let reader = File::open(&slot).unwrap();
        persist_slot(&slot, b"second").unwrap();
        drop(reader);
        assert_eq!(fs::read(&slot).unwrap(), b"second");
        let names = || {
            let mut names: Vec<_> = fs::read_dir(&path)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        };
        assert_eq!(names(), ["startup-state.0.bin"]);
        // A publish that cannot replace its target removes its temporary.
        let blocked = path.join("startup-state.1.bin");
        fs::create_dir(&blocked).unwrap();
        assert!(persist_slot(&blocked, b"third").is_err());
        assert!(blocked.is_dir());
        assert_eq!(names(), ["startup-state.0.bin", "startup-state.1.bin"]);
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn checkpoint_does_not_bypass_authoritative_log_corruption() {
        let path = test_dir("log-corruption");
        let now = unix_time_seconds().unwrap();
        {
            let mut node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
            node.mine_once(node.wallet_destination(), now, DEFAULT_MINING_ATTEMPTS)
                .unwrap();
            node.persist_startup_snapshot().unwrap();
        }
        let log = path.join(crate::BLOCK_LOG_FILE);
        let mut bytes = fs::read(&log).unwrap();
        let final_byte = bytes.last_mut().unwrap();
        *final_byte ^= 1;
        fs::write(&log, bytes).unwrap();

        assert!(Node::open_with_profile(&path, DEVNET_PROFILE).is_err());
        let _ = fs::remove_dir_all(path);
    }

    /// What `persist_index_cache` logs, at the default (info) level.
    fn persist_logging(node: &Node) -> String {
        #[derive(Clone, Default)]
        struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Captured {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || persist_index_cache(node)).unwrap();
        String::from_utf8(captured.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn the_index_cache_writer_logs_the_entries_it_leaves_out() {
        let path = test_dir("left-out");
        let now = unix_time_seconds().unwrap();
        let mut node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        node.mine_once(node.wallet_destination(), now, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        assert!(!persist_logging(&node).contains("left out"));
        // An entry for a block the fork index does not hold.
        node.index.transactions.insert_location(
            [7; 32],
            crate::explorer_index::TransactionLocation {
                block_id: [9; 32],
                transaction_position: 0,
            },
        );
        let logged = persist_logging(&node);
        assert!(
            logged.contains("index cache left out entries")
                && logged.contains("transactions=1")
                && logged.contains("addresses=0"),
            "{logged}"
        );
        drop(node);
        // The cache it wrote still loads.
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        assert!(node.startup_snapshot_used);
        drop(node);
        let _ = fs::remove_dir_all(path);
    }
}
