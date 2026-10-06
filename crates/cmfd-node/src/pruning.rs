//! Opt-in proof pruning (`run --prune-keep-blocks <N>`).
//!
//! Nearly all of a block's bytes are its proof. A pruned node keeps full
//! blocks only for the newest `N` active blocks. Older active blocks are
//! rewritten as pruned records that keep the header, coinbase, transactions,
//! block identifier and a proof summary (type, nonce, work digest): everything
//! wallets, explorers and exchange queries read, but not the proof itself.
//!
//! A block identifier hashes the full proof, so pruned records store it and it
//! can no longer be recomputed. Pruned blocks are never replayed through
//! consensus. Instead the node keeps the chain state at the newest pruned
//! block (the anchor) and replays only the full blocks above it. The anchor
//! state comes from snapshots the running node writes every
//! [`candidate_interval`] active blocks; a snapshot becomes usable once it is
//! at least `N` blocks below the tip. Pruned nodes do not serve pruned
//! blocks to peers and cannot follow a reorganization below the anchor.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use blake3::Hasher;
use cmfd_consensus::wire::{decode_transaction, encode_transaction};
use cmfd_consensus::{
    Block, BlockChallenge, BlockProof, ChainState, Coinbase, ConsensusPowVerifier, NetworkParams,
    SuccessorHeaderPreflight, Transaction,
};

use super::{NodeError, io_error, sync_parent_directory};

/// Smallest accepted keep window (about 4.8 hours of blocks).
pub const MIN_PRUNE_KEEP_BLOCKS: u64 = 288;
/// Smallest number of active blocks between saved chain-state candidates.
const MIN_CANDIDATE_INTERVAL: u64 = 64;
const CANDIDATE_DIRECTORY: &str = "prune-candidates";
const ANCHOR_PREFIX: &str = "prune-anchor-";
const STATE_FILE_SUFFIX: &str = ".bin";
const STATE_FILE_MAGIC: [u8; 8] = *b"CMFDPST\0";
const STATE_FILE_VERSION: u32 = 1;
const STATE_FILE_DOMAIN: &str = "CMFD/NODE/PRUNE-STATE/LOCAL-INTEGRITY/V1";
const STATE_FILE_HEADER_BYTES: usize =
    8 + 4 + 32 + 32 + 8 + SuccessorHeaderPreflight::LOCAL_SNAPSHOT_BYTES + 8;
const STATE_FILE_DIGEST_BYTES: usize = 32;
const PRUNED_BODY_MAGIC: [u8; 4] = *b"CMFP";
const PRUNED_BODY_VERSION: u16 = 1;
/// Upper bound on one pruned body before compression (headers, coinbase and
/// at most a block's worth of transactions).
pub const MAX_PRUNED_BODY_BYTES: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Stored blocks

/// The proof fields readers report, kept by pruned records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofSummary {
    kind: u8,
    pub nonce: u64,
    pub work_digest: [u8; 32],
}

impl ProofSummary {
    pub fn of(proof: &BlockProof) -> Self {
        let (kind, nonce, work_digest) = match proof {
            BlockProof::V1Legacy(proof) => (1, proof.nonce, proof.work_digest),
            BlockProof::V2Reference(proof) => (2, proof.nonce, proof.work_digest),
            BlockProof::V3Candidate(proof) => (3, proof.nonce, proof.work_digest),
            BlockProof::V4Candidate(proof) => (4, proof.nonce, proof.work_digest),
        };
        Self {
            kind,
            nonce,
            work_digest,
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            1 => "v1_legacy",
            2 => "v2_reference",
            3 => "v3_candidate",
            _ => "v4_candidate",
        }
    }
}

#[derive(Debug, Clone)]
pub enum StoredProof {
    Full(BlockProof),
    Pruned {
        summary: ProofSummary,
        /// Encoded successor header state after this block, kept so the fork
        /// index can be rebuilt without the proof.
        successor: [u8; SuccessorHeaderPreflight::LOCAL_SNAPSHOT_BYTES],
        original_bytes: usize,
    },
}

/// A block as read from the local block log: either the full canonical block
/// or a pruned record. Field names match [`Block`] so readers stay uniform.
#[derive(Debug, Clone)]
pub struct StoredBlock {
    pub version: u32,
    pub challenge: BlockChallenge,
    pub coinbase: Coinbase,
    pub transactions: Vec<Transaction>,
    pub proof: StoredProof,
    block_id: [u8; 32],
}

impl StoredBlock {
    /// Decoded successor header state of a pruned record.
    pub fn pruned_successor(
        &self,
        params: NetworkParams,
    ) -> Result<Option<SuccessorHeaderPreflight>, NodeError> {
        match &self.proof {
            StoredProof::Full(_) => Ok(None),
            StoredProof::Pruned { successor, .. } => {
                SuccessorHeaderPreflight::decode_local_snapshot(successor, params)
                    .map(Some)
                    .map_err(|error| {
                        corrupt(format!("pruned block header state is invalid: {error}"))
                    })
            }
        }
    }

    pub fn from_full(block: Block) -> Self {
        let block_id = block.block_id();
        Self::from_full_with_id(block, block_id)
    }

    /// Callers must have computed `block_id` from this exact block.
    pub fn from_full_with_id(block: Block, block_id: [u8; 32]) -> Self {
        let Block {
            version,
            challenge,
            proof,
            coinbase,
            transactions,
        } = block;
        Self {
            version,
            challenge,
            coinbase,
            transactions,
            proof: StoredProof::Full(proof),
            block_id,
        }
    }

    pub fn block_id(&self) -> [u8; 32] {
        self.block_id
    }

    pub fn coinbase_outpoint_id(&self) -> [u8; 32] {
        cmfd_consensus::coinbase_outpoint_id(self.challenge.network_id, self.block_id)
    }

    pub fn is_pruned(&self) -> bool {
        matches!(self.proof, StoredProof::Pruned { .. })
    }

    pub fn proof_summary(&self) -> ProofSummary {
        match &self.proof {
            StoredProof::Full(proof) => ProofSummary::of(proof),
            StoredProof::Pruned { summary, .. } => *summary,
        }
    }

    /// The full block, or `None` for a pruned record.
    pub fn into_full(self) -> Option<Block> {
        match self.proof {
            StoredProof::Full(proof) => Some(Block {
                version: self.version,
                challenge: self.challenge,
                proof,
                coinbase: self.coinbase,
                transactions: self.transactions,
            }),
            StoredProof::Pruned { .. } => None,
        }
    }

    #[cfg(test)]
    pub fn full(&self) -> Option<Block> {
        self.clone().into_full()
    }

    pub fn transaction_root(&self) -> [u8; 32] {
        let mut ids = Vec::with_capacity(self.transactions.len() + 1);
        ids.push(self.coinbase.commitment(self.challenge.network_id));
        ids.extend(self.transactions.iter().map(Transaction::txid));
        cmfd_consensus::merkle_root(&ids)
    }
}

// ---------------------------------------------------------------------------
// Pruned record bodies

fn corrupt(message: impl Into<String>) -> NodeError {
    NodeError::CorruptLog(message.into())
}

/// Encodes the pruned body of a full block (before record compression).
pub fn encode_pruned_body(
    block: &Block,
    block_id: [u8; 32],
    successor: SuccessorHeaderPreflight,
    original_bytes: usize,
) -> Result<Vec<u8>, NodeError> {
    let summary = ProofSummary::of(&block.proof);
    let successor = successor
        .encode_local_snapshot()
        .map_err(|error| corrupt(format!("cannot encode pruned header state: {error}")))?;
    let coinbase = serde_json::to_vec(&block.coinbase)
        .map_err(|error| corrupt(format!("cannot encode pruned coinbase: {error}")))?;
    let original_bytes = u32::try_from(original_bytes)
        .map_err(|_| corrupt("pruned block original size exceeds u32"))?;
    let mut body = Vec::with_capacity(512 + coinbase.len());
    body.extend_from_slice(&PRUNED_BODY_MAGIC);
    body.extend_from_slice(&PRUNED_BODY_VERSION.to_le_bytes());
    body.extend_from_slice(&block_id);
    body.extend_from_slice(&original_bytes.to_le_bytes());
    body.extend_from_slice(&successor);
    body.extend_from_slice(&block.version.to_le_bytes());
    body.push(summary.kind);
    body.extend_from_slice(&summary.nonce.to_le_bytes());
    body.extend_from_slice(&summary.work_digest);
    let challenge = &block.challenge;
    body.extend_from_slice(&challenge.network_id);
    body.extend_from_slice(&challenge.previous_block);
    body.extend_from_slice(&challenge.transaction_root);
    body.extend_from_slice(&challenge.height.to_le_bytes());
    body.extend_from_slice(&challenge.timestamp.to_le_bytes());
    body.extend_from_slice(&challenge.target);
    push_sized(&mut body, &coinbase)?;
    let count = u32::try_from(block.transactions.len())
        .map_err(|_| corrupt("pruned block transaction count exceeds u32"))?;
    body.extend_from_slice(&count.to_le_bytes());
    for transaction in &block.transactions {
        let encoded = encode_transaction(transaction)
            .map_err(|error| corrupt(format!("cannot encode pruned transaction: {error}")))?;
        push_sized(&mut body, &encoded)?;
    }
    if body.len() > MAX_PRUNED_BODY_BYTES {
        return Err(corrupt("pruned block body exceeds its size limit"));
    }
    Ok(body)
}

fn push_sized(body: &mut Vec<u8>, bytes: &[u8]) -> Result<(), NodeError> {
    let length = u32::try_from(bytes.len()).map_err(|_| corrupt("pruned field exceeds u32"))?;
    body.extend_from_slice(&length.to_le_bytes());
    body.extend_from_slice(bytes);
    Ok(())
}

struct BodyReader<'a> {
    bytes: &'a [u8],
}

impl<'a> BodyReader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], NodeError> {
        if self.bytes.len() < length {
            return Err(corrupt("pruned block body is truncated"));
        }
        let (head, rest) = self.bytes.split_at(length);
        self.bytes = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], NodeError> {
        Ok(self.take(N)?.try_into().expect("exact length"))
    }

    fn u32(&mut self) -> Result<u32, NodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, NodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn sized(&mut self, limit: usize) -> Result<&'a [u8], NodeError> {
        let length = self.u32()? as usize;
        if length > limit {
            return Err(corrupt("pruned block field exceeds its size limit"));
        }
        self.take(length)
    }
}

/// Decodes and checks a pruned body: network, coinbase height and the
/// transaction root must agree with the stored header.
pub fn decode_pruned_body(body: &[u8], network_id: [u8; 32]) -> Result<StoredBlock, NodeError> {
    let mut reader = BodyReader { bytes: body };
    if reader.array::<4>()? != PRUNED_BODY_MAGIC
        || u16::from_le_bytes(reader.array()?) != PRUNED_BODY_VERSION
    {
        return Err(corrupt("pruned block body has an unsupported format"));
    }
    let block_id = reader.array::<32>()?;
    let original_bytes = reader.u32()? as usize;
    let successor = reader.array::<{ SuccessorHeaderPreflight::LOCAL_SNAPSHOT_BYTES }>()?;
    if successor[32..64] != block_id {
        return Err(corrupt("pruned block header state names another block"));
    }
    let version = reader.u32()?;
    let kind = reader.array::<1>()?[0];
    if !(1..=4).contains(&kind) {
        return Err(corrupt("pruned block proof type is invalid"));
    }
    let summary = ProofSummary {
        kind,
        nonce: reader.u64()?,
        work_digest: reader.array()?,
    };
    let challenge = BlockChallenge {
        network_id: reader.array()?,
        previous_block: reader.array()?,
        transaction_root: reader.array()?,
        height: reader.u64()?,
        timestamp: reader.u64()?,
        target: reader.array()?,
    };
    if challenge.network_id != network_id {
        return Err(corrupt("pruned block belongs to another network"));
    }
    let coinbase: Coinbase = serde_json::from_slice(reader.sized(MAX_PRUNED_BODY_BYTES)?)
        .map_err(|error| corrupt(format!("pruned block coinbase is invalid: {error}")))?;
    let count = reader.u32()? as usize;
    if count > cmfd_consensus::MAX_BLOCK_TRANSACTIONS {
        return Err(corrupt("pruned block has too many transactions"));
    }
    let mut transactions = Vec::with_capacity(count);
    for _ in 0..count {
        let encoded = reader.sized(cmfd_consensus::wire::MAX_TRANSACTION_BYTES)?;
        let transaction = decode_transaction(encoded, network_id)
            .map_err(|error| corrupt(format!("pruned block transaction is invalid: {error}")))?;
        if encode_transaction(&transaction).ok().as_deref() != Some(encoded) {
            return Err(corrupt("pruned block transaction is not canonical"));
        }
        transactions.push(transaction);
    }
    if !reader.bytes.is_empty() {
        return Err(corrupt("pruned block body has trailing bytes"));
    }
    let stored = StoredBlock {
        version,
        challenge,
        coinbase,
        transactions,
        proof: StoredProof::Pruned {
            summary,
            successor,
            original_bytes,
        },
        block_id,
    };
    if stored.coinbase.height != stored.challenge.height
        || stored.transaction_root() != stored.challenge.transaction_root
    {
        return Err(corrupt(
            "pruned block contents do not match its stored header",
        ));
    }
    Ok(stored)
}

// ---------------------------------------------------------------------------
// Saved chain states (candidates and the anchor)

/// Active blocks between saved candidates: 64, or a quarter of the keep window
/// (in multiples of 64) when that is larger. This bounds the saved states to a
/// handful for any window. A prune also waits until it can advance the anchor
/// this far, so each rewrite of the kept blocks covers a quarter window.
pub fn candidate_interval(keep: u64) -> u64 {
    (keep / 4 / MIN_CANDIDATE_INTERVAL * MIN_CANDIDATE_INTERVAL).max(MIN_CANDIDATE_INTERVAL)
}

/// Chain state at one active block, saved for use as a prune anchor.
pub struct SavedState {
    pub block_id: [u8; 32],
    pub height: u64,
    pub successor: SuccessorHeaderPreflight,
    pub state: ChainState,
}

pub fn candidate_directory(data_dir: &Path) -> PathBuf {
    data_dir.join(CANDIDATE_DIRECTORY)
}

pub fn candidate_path(data_dir: &Path, height: u64) -> PathBuf {
    candidate_directory(data_dir).join(format!("{height:012}{STATE_FILE_SUFFIX}"))
}

pub fn anchor_path(data_dir: &Path, height: u64) -> PathBuf {
    data_dir.join(format!("{ANCHOR_PREFIX}{height:012}{STATE_FILE_SUFFIX}"))
}

fn state_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(STATE_FILE_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// Writes a saved state through a temporary file and an atomic rename.
pub fn write_state_file(
    path: &Path,
    fingerprint: [u8; 32],
    block_id: [u8; 32],
    height: u64,
    successor: SuccessorHeaderPreflight,
    state: &ChainState,
) -> Result<(), NodeError> {
    let state_bytes = state
        .encode_local_snapshot()
        .map_err(|error| corrupt(format!("cannot encode saved chain state: {error}")))?;
    let successor = successor
        .encode_local_snapshot()
        .map_err(|error| corrupt(format!("cannot encode saved header state: {error}")))?;
    let mut bytes = Vec::with_capacity(STATE_FILE_HEADER_BYTES + state_bytes.len() + 32);
    bytes.extend_from_slice(&STATE_FILE_MAGIC);
    bytes.extend_from_slice(&STATE_FILE_VERSION.to_le_bytes());
    bytes.extend_from_slice(&fingerprint);
    bytes.extend_from_slice(&block_id);
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&successor);
    bytes.extend_from_slice(&(state_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&state_bytes);
    let digest = state_digest(&bytes);
    bytes.extend_from_slice(&digest);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|source| io_error("create prune state directory", parent, source))?;
    }
    let temporary = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|source| io_error("create prune state", &temporary, source))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error("write prune state", &temporary, source))?;
    drop(file);
    fs::rename(&temporary, path).map_err(|source| io_error("install prune state", path, source))?;
    sync_parent_directory(path)
}

/// Reads and authenticates a saved state for this network.
pub fn read_state_file(
    path: &Path,
    params: NetworkParams,
    verifier: &ConsensusPowVerifier,
) -> Result<SavedState, NodeError> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|source| io_error("read prune state", path, source))?;
    if bytes.len() < STATE_FILE_HEADER_BYTES + STATE_FILE_DIGEST_BYTES {
        return Err(corrupt("prune state is truncated"));
    }
    let (payload, digest) = bytes.split_at(bytes.len() - STATE_FILE_DIGEST_BYTES);
    if state_digest(payload) != digest {
        return Err(corrupt("prune state integrity mismatch"));
    }
    let mut reader = BodyReader { bytes: payload };
    if reader.array::<8>()? != STATE_FILE_MAGIC || reader.u32()? != STATE_FILE_VERSION {
        return Err(corrupt("prune state has an unsupported format"));
    }
    let fingerprint = params
        .fingerprint()
        .map_err(|error| corrupt(format!("network parameters are invalid: {error}")))?;
    if reader.array::<32>()? != fingerprint {
        return Err(corrupt("prune state belongs to another network"));
    }
    let block_id = reader.array::<32>()?;
    let height = reader.u64()?;
    let successor_bytes = reader.array::<{ SuccessorHeaderPreflight::LOCAL_SNAPSHOT_BYTES }>()?;
    let successor = SuccessorHeaderPreflight::decode_local_snapshot(&successor_bytes, params)
        .map_err(|error| corrupt(format!("prune state header is invalid: {error}")))?;
    let state_length = usize::try_from(reader.u64()?)
        .map_err(|_| corrupt("prune state length does not fit this platform"))?;
    if state_length != reader.bytes.len() {
        return Err(corrupt("prune state length mismatch"));
    }
    let state = ChainState::decode_local_snapshot(reader.bytes, params, verifier.clone())
        .map_err(|error| corrupt(format!("prune state is invalid: {error}")))?;
    let state_successor = state
        .successor_header_preflight()
        .map_err(|error| corrupt(format!("prune state header is invalid: {error}")))?;
    if state.tip() != block_id
        || state.next_height() != height.saturating_add(1)
        || state_successor != successor
    {
        return Err(corrupt("prune state does not match its block"));
    }
    Ok(SavedState {
        block_id,
        height,
        successor,
        state,
    })
}

/// Heights of saved candidates, ascending.
pub fn list_candidates(data_dir: &Path) -> Vec<u64> {
    list_heights(&candidate_directory(data_dir), "")
}

/// Heights of anchor files present, ascending.
pub fn list_anchors(data_dir: &Path) -> Vec<u64> {
    list_heights(data_dir, ANCHOR_PREFIX)
}

fn list_heights(directory: &Path, prefix: &str) -> Vec<u64> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut heights = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let digits = name.strip_prefix(prefix)?.strip_suffix(STATE_FILE_SUFFIX)?;
            (digits.len() == 12 && digits.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| digits.parse().ok())
                .flatten()
        })
        .collect::<Vec<u64>>();
    heights.sort_unstable();
    heights
}

/// Removes a file if present, ignoring a missing one.
pub fn remove_if_present(path: &Path) -> Result<(), NodeError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove prune state", path, source)),
    }
}

// ---------------------------------------------------------------------------
// Pruning a live node

const TEMPORARY_LOG_FILE: &str = "blocks.log.prune-tmp";
/// Saved candidates kept beyond what the keep window needs.
const SPARE_CANDIDATES: u64 = 4;

/// What one prune did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneReport {
    pub anchor_height: u64,
    pub newly_pruned_blocks: u64,
    pub dropped_side_blocks: u64,
    pub log_bytes_before: u64,
    pub log_bytes_after: u64,
}

/// A prune chosen under the node lock and built without it.
pub struct PrunePlan {
    anchor: SavedState,
    pruned: Vec<Arc<super::IndexedBlock>>,
    kept: Vec<Arc<super::IndexedBlock>>,
    newly_pruned: u64,
    log: File,
    log_path: PathBuf,
    temporary: PathBuf,
    network_id: [u8; 32],
    instance_id: u64,
    base_log_length: u64,
    base_anchor_height: Option<u64>,
}

/// A pruned log written up to the planned extent, still open for the
/// records appended while it was built.
pub struct BuiltPrune {
    anchor: SavedState,
    newly_pruned: u64,
    instance_id: u64,
    base_log_length: u64,
    base_anchor_height: Option<u64>,
    writer: LogWriter,
}

/// How long a running prune waits for a moment with no off-lock log reader
/// before it gives up until the next check. Reads are short, so a gap comes
/// quickly even under steady RPC load; the wait only holds the lock briefly.
const READER_WAIT: Duration = Duration::from_secs(300);

/// How often a background pruner checks whether a prune is due.
pub const PRUNE_CHECK_INTERVAL: Duration = Duration::from_secs(600);

/// Free space a prune keeps in reserve beyond its own temporary log, so the
/// blocks appended while it runs never hit a full disk.
const PRUNE_FREE_SPACE_MARGIN_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Generous per-block allowance for a pruned record in the temporary log.
const PRUNED_RECORD_ALLOWANCE_BYTES: u64 = 64 * 1024;

/// Free space a prune needs before it starts writing its temporary log: room
/// for twice the full blocks it keeps, an allowance per pruned record, and a
/// margin. Below that the prune waits for a later check instead of filling
/// the disk under the node's own block appends.
fn prune_free_space_required(kept_bytes: u64, pruned_records: u64) -> u64 {
    kept_bytes
        .saturating_mul(2)
        .saturating_add(pruned_records.saturating_mul(PRUNED_RECORD_ALLOWANCE_BYTES))
        .saturating_add(PRUNE_FREE_SPACE_MARGIN_BYTES)
}

#[cfg(test)]
thread_local! {
    static FREE_SPACE_FOR_TEST: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Makes `plan_prune` on this test thread see `bytes` of free space.
#[cfg(test)]
pub(crate) fn set_free_space_for_test(bytes: Option<u64>) {
    FREE_SPACE_FOR_TEST.with(|cell| cell.set(bytes));
}

fn available_space(directory: &Path) -> io::Result<u64> {
    #[cfg(test)]
    if let Some(bytes) = FREE_SPACE_FOR_TEST.with(std::cell::Cell::get) {
        return Ok(bytes);
    }
    fs2::available_space(directory)
}

fn stop_requested(stop: Option<&AtomicBool>) -> bool {
    stop.is_some_and(|flag| flag.load(Ordering::Acquire))
}

/// Plans, builds and installs one prune on a shared node. The rewrite runs
/// without the node lock; only planning and the final swap hold it.
pub fn prune_shared_node(
    shared: &std::sync::Mutex<super::Node>,
) -> Result<Option<PruneReport>, NodeError> {
    prune_shared_node_until_stopped(shared, None)
}

/// [`prune_shared_node`] that gives up as soon as `stop` is raised: the
/// temporary log is removed and the current log is left untouched, so a
/// closing wallet or node never waits for a long first prune.
pub fn prune_shared_node_until_stopped(
    shared: &std::sync::Mutex<super::Node>,
    stop: Option<&AtomicBool>,
) -> Result<Option<PruneReport>, NodeError> {
    let plan = {
        let mut node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
        node.plan_prune()?
    };
    let Some(plan) = plan else {
        return Ok(None);
    };
    let Some(built) = build_pruned_log_until_stopped(plan, stop)? else {
        return Ok(None);
    };
    // Readers working without the lock hold the current log open. Let them
    // finish rather than replace the file under them.
    let deadline = Instant::now() + READER_WAIT;
    loop {
        if stop_requested(stop) {
            built.discard();
            return Ok(None);
        }
        let node = shared.lock().map_err(|_| NodeError::SharedNodePoisoned)?;
        if !node.log_readers_outstanding() || Instant::now() >= deadline {
            let mut node = node;
            return node.finish_prune(built);
        }
        drop(node);
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A background thread that prunes a shared node: first after `first_check`,
/// then every [`PRUNE_CHECK_INTERVAL`]. Stopping it (or dropping the handle)
/// cancels a prune in progress and waits only for the record being written.
pub struct PrunerHandle {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl PrunerHandle {
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

impl Drop for PrunerHandle {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// Starts a [`PrunerHandle`]. Each prune logs its own report; a prune that
/// cannot finish (readers keep the log busy, too little free space, no saved
/// state outside the keep window yet) is retried at the next check.
pub fn spawn_pruner(
    shared: Arc<std::sync::Mutex<super::Node>>,
    first_check: Duration,
) -> io::Result<PrunerHandle> {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let thread = std::thread::Builder::new()
        .name("cmfd-pruner".to_owned())
        .spawn(move || {
            let tick = Duration::from_millis(250);
            let mut next_check = first_check;
            let mut waited = Duration::ZERO;
            while !flag.load(Ordering::Acquire) {
                std::thread::sleep(tick);
                waited += tick;
                if waited < next_check {
                    continue;
                }
                waited = Duration::ZERO;
                next_check = PRUNE_CHECK_INTERVAL;
                if let Err(error) = prune_shared_node_until_stopped(&shared, Some(&flag)) {
                    tracing::warn!(%error, "proof pruning will retry later");
                }
            }
        })?;
    Ok(PrunerHandle {
        stop,
        thread: Some(thread),
    })
}

impl super::Node {
    /// Enables or disables opt-in proof pruning. `keep` is the number of
    /// newest active blocks that stay full.
    pub fn configure_pruning(&mut self, keep: Option<u64>) -> Result<(), NodeError> {
        if let Some(keep) = keep
            && keep < MIN_PRUNE_KEEP_BLOCKS
        {
            return Err(NodeError::InvalidPruneSetting(format!(
                "keep at least {MIN_PRUNE_KEEP_BLOCKS} full blocks (got {keep})"
            )));
        }
        self.prune_keep_blocks = keep;
        if keep.is_some() {
            self.save_prune_candidate(true);
        }
        Ok(())
    }

    pub fn prune_keep_blocks(&self) -> Option<u64> {
        self.prune_keep_blocks
    }

    /// Height of the newest pruned block, if the log is pruned.
    pub fn prune_height(&self) -> Option<u64> {
        self.index.anchor.as_ref().map(|anchor| anchor.height)
    }

    /// True when the block is stored without its proof.
    pub fn block_is_pruned(&self, block_id: [u8; 32]) -> bool {
        self.index
            .blocks
            .get(&block_id)
            .is_some_and(|entry| entry.locator.version == super::BlockRecordVersion::Pruned)
    }

    /// Saves the active chain state as a future anchor when the tip reaches a
    /// candidate height (or always, with `force`). Failures only delay pruning.
    pub(crate) fn save_prune_candidate(&mut self, force: bool) {
        let Some(keep) = self.prune_keep_blocks else {
            return;
        };
        let height = self.state.next_height().saturating_sub(1);
        if self.storage_faulted
            || height == 0
            || (!force && !height.is_multiple_of(candidate_interval(keep)))
            || self.prune_height().is_some_and(|anchor| height <= anchor)
        {
            return;
        }
        let Ok(successor) = self.state.successor_header_preflight() else {
            return;
        };
        let path = candidate_path(&self.data_dir, height);
        if let Err(error) = write_state_file(
            &path,
            self.fingerprint,
            self.state.tip(),
            height,
            successor,
            &self.state,
        ) {
            tracing::warn!(%error, height, "could not save a prune candidate; pruning will wait for the next one");
            return;
        }
        // Keep the candidates the keep window can still use, plus a few spare.
        let retained = keep / candidate_interval(keep) + SPARE_CANDIDATES;
        let candidates = list_candidates(&self.data_dir);
        let floor = self.prune_height().unwrap_or(0);
        let excess = candidates
            .len()
            .saturating_sub(usize::try_from(retained).unwrap_or(usize::MAX));
        for (position, candidate) in candidates.iter().enumerate() {
            if *candidate <= floor || position < excess {
                let _ = remove_if_present(&candidate_path(&self.data_dir, *candidate));
            }
        }
    }

    /// Prunes proofs below the keep window when a saved candidate allows it,
    /// holding this node for the whole rewrite. Running nodes use
    /// [`prune_shared_node`] instead. Returns `None` when there is nothing to
    /// do yet.
    pub fn prune_block_log(&mut self) -> Result<Option<PruneReport>, NodeError> {
        let Some(plan) = self.plan_prune()? else {
            return Ok(None);
        };
        let built = build_pruned_log(plan)?;
        self.finish_prune(built)
    }

    /// Chooses the newest usable candidate and the records to rewrite.
    pub fn plan_prune(&mut self) -> Result<Option<PrunePlan>, NodeError> {
        let Some(keep) = self.prune_keep_blocks else {
            return Ok(None);
        };
        if self.storage_faulted {
            return Err(NodeError::StorageFaulted);
        }
        let tip_height = self.state.next_height().saturating_sub(1);
        let limit = tip_height.saturating_sub(keep);
        let floor = self.prune_height().unwrap_or(0);
        let mut chosen = None;
        for height in list_candidates(&self.data_dir).into_iter().rev() {
            if height > limit || height < floor.saturating_add(candidate_interval(keep)) {
                continue;
            }
            let Ok(saved) = read_state_file(
                &candidate_path(&self.data_dir, height),
                self.params,
                &self.verifier,
            ) else {
                continue;
            };
            let on_active_chain = usize::try_from(height)
                .ok()
                .and_then(|position| self.index.active_chain.get(position))
                == Some(&saved.block_id);
            let header_matches = self
                .index
                .blocks
                .get(&saved.block_id)
                .is_some_and(|entry| entry.successor_header == saved.successor);
            if on_active_chain && header_matches {
                chosen = Some(saved);
                break;
            }
        }
        let Some(anchor) = chosen else {
            return Ok(None);
        };
        let anchor_height = anchor.height;
        let anchor_position = usize::try_from(anchor_height)
            .map_err(|_| corrupt("prune height does not fit this platform"))?;
        let pruned = self.index.active_chain[1..=anchor_position]
            .iter()
            .map(|block_id| {
                self.index
                    .blocks
                    .get(block_id)
                    .cloned()
                    .ok_or_else(|| corrupt("an active block is absent from the fork index"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut kept: Vec<Arc<super::IndexedBlock>> = self
            .index
            .blocks
            .values()
            .filter(|entry| self.descends_from_anchor(entry, &anchor))
            .cloned()
            .collect();
        kept.sort_unstable_by_key(|entry| entry.locator.ordinal);
        let newly_pruned = pruned
            .iter()
            .filter(|entry| entry.locator.version != super::BlockRecordVersion::Pruned)
            .count() as u64;
        let kept_bytes = kept
            .iter()
            .map(|entry| entry.locator.length)
            .fold(0_u64, u64::saturating_add);
        let required = prune_free_space_required(kept_bytes, pruned.len() as u64);
        match available_space(&self.data_dir) {
            Ok(available) if available >= required => {}
            Ok(available) => {
                tracing::warn!(
                    available_bytes = available,
                    required_bytes = required,
                    anchor_height,
                    "not enough free space to prune safely; pruning waits for the next check"
                );
                return Ok(None);
            }
            Err(error) => {
                tracing::warn!(%error, "could not read free space; pruning waits for the next check");
                return Ok(None);
            }
        }
        let log_path = self.data_dir.join(super::BLOCK_LOG_FILE);
        let log = self
            .log
            .try_clone()
            .map_err(|source| io_error("clone the block log for pruning", &log_path, source))?;
        tracing::info!(
            anchor_height,
            newly_pruned,
            kept = kept.len(),
            "pruning block proofs"
        );
        Ok(Some(PrunePlan {
            anchor,
            pruned,
            kept,
            newly_pruned,
            log,
            temporary: self.data_dir.join(TEMPORARY_LOG_FILE),
            log_path,
            network_id: self.params.network_id,
            instance_id: self.instance_id,
            base_log_length: self.block_log_length,
            base_anchor_height: self.prune_height(),
        }))
    }

    fn descends_from_anchor(&self, entry: &super::IndexedBlock, anchor: &SavedState) -> bool {
        entry.height() > anchor.height
            && self
                .index
                .ancestor_at_height(entry.block_id(), anchor.height)
                .is_ok_and(|ancestor| ancestor == anchor.block_id)
    }

    /// Appends the records added while the prune was built, then installs the
    /// pruned log and its anchor. Returns `None` when the chain moved in a way
    /// that invalidates the plan, or an off-lock reader still holds the log;
    /// the next check plans again.
    pub fn finish_prune(&mut self, built: BuiltPrune) -> Result<Option<PruneReport>, NodeError> {
        let BuiltPrune {
            anchor,
            newly_pruned,
            instance_id,
            base_log_length,
            base_anchor_height,
            mut writer,
        } = built;
        let temporary = writer.path.clone();
        let log_path = self.data_dir.join(super::BLOCK_LOG_FILE);
        let still_valid = instance_id == self.instance_id
            && !self.storage_faulted
            && self.block_log_length >= base_log_length
            && self.prune_height() == base_anchor_height
            && usize::try_from(anchor.height)
                .ok()
                .and_then(|position| self.index.active_chain.get(position))
                == Some(&anchor.block_id)
            && !self.log_readers_outstanding();
        if !still_valid {
            drop(writer);
            let _ = remove_if_present(&temporary);
            return Ok(None);
        }
        let appended = (|| -> Result<(), NodeError> {
            let mut tail: Vec<Arc<super::IndexedBlock>> = self
                .index
                .blocks
                .values()
                .filter(|entry| {
                    entry.locator.offset >= base_log_length
                        && self.descends_from_anchor(entry, &anchor)
                })
                .cloned()
                .collect();
            tail.sort_unstable_by_key(|entry| entry.locator.ordinal);
            for entry in tail {
                let raw = read_raw_record(&self.log, &entry.locator, &log_path)?;
                let record = super::rechain_record(&raw, writer.previous)?;
                writer.append(&entry, &record, entry.locator.version)?;
            }
            Ok(())
        })();
        if let Err(error) = appended {
            drop(writer);
            let _ = remove_if_present(&temporary);
            return Err(error);
        }
        let (locators, last_digest, length) = match writer.finish() {
            Ok(finished) => finished,
            Err(error) => {
                let _ = remove_if_present(&temporary);
                return Err(error);
            }
        };

        // The anchor must exist before the pruned log replaces the old one.
        write_state_file(
            &anchor_path(&self.data_dir, anchor.height),
            self.fingerprint,
            anchor.block_id,
            anchor.height,
            anchor.successor,
            &anchor.state,
        )?;
        let bytes_before = self.block_log_length;
        let dropped = self.index.blocks.len().saturating_sub(locators.len()) as u64;
        // A running history scan holds its own handle on the log; dropping it
        // stops the scan and closes that handle before the swap.
        self.wallet_history_scan = None;
        let durable = self.swap_block_log(
            &temporary,
            &log_path,
            &anchor_path(&self.data_dir, anchor.height),
        )?;

        // Retarget every retained block to its new record; drop the rest.
        let mut blocks = std::collections::HashMap::with_capacity(locators.len());
        for (block_id, locator) in locators {
            let entry = self
                .index
                .blocks
                .get(&block_id)
                .ok_or_else(|| corrupt("a rewritten block is absent from the fork index"))?;
            blocks.insert(
                block_id,
                Arc::new(super::IndexedBlock {
                    locator,
                    cumulative_work: entry.cumulative_work,
                    successor_header: entry.successor_header,
                    ancestors: entry.ancestors.clone(),
                }),
            );
        }
        let anchor_height = anchor.height;
        self.index.blocks = blocks;
        self.index.anchor = Some(Arc::new(super::PruneAnchor {
            block_id: anchor.block_id,
            height: anchor_height,
            state: anchor.state,
        }));
        self.last_record_digest = last_digest;
        self.block_log_length = length;
        self.record_count = self.index.blocks.len() as u64;
        // Bump the revision so every off-lock plan holding old record
        // locations restarts.
        self.chain_revision = self.chain_revision.saturating_add(1);
        self.branch_checkpoints = super::BranchCheckpointCache::default();
        self.transaction_scan_marks.clear();
        self.remember_active_branch_checkpoint(true);
        let _ = self.persist_startup_snapshot();
        for height in list_anchors(&self.data_dir) {
            if durable && height != anchor_height {
                let _ = remove_if_present(&anchor_path(&self.data_dir, height));
            }
        }
        for height in list_candidates(&self.data_dir) {
            if height <= anchor_height {
                let _ = remove_if_present(&candidate_path(&self.data_dir, height));
            }
        }
        let report = PruneReport {
            anchor_height,
            newly_pruned_blocks: newly_pruned,
            dropped_side_blocks: dropped,
            log_bytes_before: bytes_before,
            log_bytes_after: length,
        };
        tracing::info!(?report, "pruned block proofs");
        Ok(Some(report))
    }

    /// Replaces the block log with `temporary`. Windows refuses to rename a
    /// file with open handles, so the retained handle is closed first and the
    /// old log reopened if the rename fails. Returns whether the rename is
    /// known to be durable.
    fn swap_block_log(
        &mut self,
        temporary: &Path,
        log_path: &Path,
        placeholder: &Path,
    ) -> Result<bool, NodeError> {
        // Any other open file stands in while the log handle is closed.
        let placeholder = File::open(placeholder).map_err(|source| {
            io_error(
                "open a placeholder during the log swap",
                placeholder,
                source,
            )
        })?;
        drop(std::mem::replace(&mut self.log, placeholder));
        let renamed = fs::rename(temporary, log_path);
        let reopened = super::open_block_log(log_path);
        match (renamed, reopened) {
            (Ok(()), Ok(file)) => {
                self.log = file;
                // The new log is in place either way. An unsynced rename may
                // bring the old log back after a crash, so its anchor stays.
                match sync_parent_directory(log_path) {
                    Ok(()) => Ok(true),
                    Err(error) => {
                        tracing::warn!(%error, "could not sync the pruned block log rename");
                        Ok(false)
                    }
                }
            }
            (Err(source), Ok(file)) => {
                self.log = file;
                let _ = remove_if_present(temporary);
                Err(io_error(
                    "replace the block log with its pruned copy",
                    log_path,
                    source,
                ))
            }
            (_, Err(error)) => {
                self.storage_faulted = true;
                Err(error)
            }
        }
    }
}

/// Writes the pruned prefix and the kept full records without the node lock.
pub fn build_pruned_log(plan: PrunePlan) -> Result<BuiltPrune, NodeError> {
    build_pruned_log_until_stopped(plan, None)?
        .ok_or_else(|| corrupt("a prune without a stop flag reported being stopped"))
}

/// [`build_pruned_log`] that checks `stop` before each record. When it is
/// raised the temporary log is removed and `None` is returned.
fn build_pruned_log_until_stopped(
    plan: PrunePlan,
    stop: Option<&AtomicBool>,
) -> Result<Option<BuiltPrune>, NodeError> {
    let PrunePlan {
        anchor,
        pruned,
        kept,
        newly_pruned,
        log,
        log_path,
        temporary,
        network_id,
        instance_id,
        base_log_length,
        base_anchor_height,
    } = plan;
    let written = (|| -> Result<Option<LogWriter>, NodeError> {
        let mut writer = LogWriter::create(&temporary)?;
        let total = pruned.len();
        for (position, entry) in pruned.iter().enumerate() {
            if stop_requested(stop) {
                return Ok(None);
            }
            let record = if entry.locator.version == super::BlockRecordVersion::Pruned {
                let raw = read_raw_record(&log, &entry.locator, &log_path)?;
                super::rechain_record(&raw, writer.previous)?
            } else {
                let (record, block) =
                    super::read_located_record(&log, &log_path, &entry.locator, network_id, false)?;
                let size = record.block_bytes.len();
                let block = block
                    .into_full()
                    .ok_or_else(|| corrupt("a full record decoded as pruned"))?;
                let body =
                    encode_pruned_body(&block, entry.block_id(), entry.successor_header, size)?;
                super::encode_record_pruned(entry.locator.accepted_at, &body, writer.previous)?
            };
            writer.append(entry, &record, super::BlockRecordVersion::Pruned)?;
            if position % 500 == 499 {
                tracing::info!(done = position + 1, total, "pruning block proofs");
            }
        }
        for entry in &kept {
            if stop_requested(stop) {
                return Ok(None);
            }
            let raw = read_raw_record(&log, &entry.locator, &log_path)?;
            let record = super::rechain_record(&raw, writer.previous)?;
            writer.append(entry, &record, entry.locator.version)?;
        }
        Ok(Some(writer))
    })();
    drop(log);
    match written {
        Ok(Some(writer)) => Ok(Some(BuiltPrune {
            anchor,
            newly_pruned,
            instance_id,
            base_log_length,
            base_anchor_height,
            writer,
        })),
        Ok(None) => {
            let _ = remove_if_present(&temporary);
            tracing::info!("proof pruning stopped before it finished; the block log is unchanged");
            Ok(None)
        }
        Err(error) => {
            let _ = remove_if_present(&temporary);
            Err(error)
        }
    }
}

impl BuiltPrune {
    /// Drops a finished but uninstalled prune and its temporary log.
    fn discard(self) {
        let temporary = self.writer.path.clone();
        drop(self);
        let _ = remove_if_present(&temporary);
    }
}

/// Reads one complete record and checks it against its locator digest.
fn read_raw_record(
    log: &File,
    locator: &super::BlockRecordLocator,
    log_path: &Path,
) -> Result<Vec<u8>, NodeError> {
    let length = usize::try_from(locator.length)
        .map_err(|_| corrupt("record length does not fit this platform"))?;
    let mut raw = vec![0_u8; length];
    super::positioned_read_exact(log, &mut raw, locator.offset)
        .map_err(|source| io_error("read block record for pruning", log_path, source))?;
    if super::complete_record_digest(&raw) != locator.complete_digest {
        return Err(corrupt(format!(
            "record {} changed before pruning",
            locator.ordinal
        )));
    }
    Ok(raw)
}

/// Appends rewritten records to the temporary log and tracks their locators.
pub struct LogWriter {
    file: io::BufWriter<File>,
    path: PathBuf,
    previous: [u8; 32],
    offset: u64,
    ordinal: u64,
    locators: Vec<([u8; 32], super::BlockRecordLocator)>,
}

impl LogWriter {
    fn create(path: &Path) -> Result<Self, NodeError> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|source| io_error("create pruned block log", path, source))?;
        Ok(Self {
            file: io::BufWriter::with_capacity(4 * 1024 * 1024, file),
            path: path.to_path_buf(),
            previous: super::EMPTY_RECORD_CHAIN_ROOT,
            offset: 0,
            ordinal: 0,
            locators: Vec::new(),
        })
    }

    fn append(
        &mut self,
        entry: &super::IndexedBlock,
        record: &[u8],
        version: super::BlockRecordVersion,
    ) -> Result<(), NodeError> {
        self.file
            .write_all(record)
            .map_err(|source| io_error("write pruned block log", &self.path, source))?;
        let digest = super::complete_record_digest(record);
        let length = record.len() as u64;
        let mut locator = entry.locator;
        locator.ordinal = self.ordinal;
        locator.offset = self.offset;
        locator.length = length;
        locator.version = version;
        locator.complete_digest = digest;
        self.locators.push((entry.block_id(), locator));
        self.previous = digest;
        self.offset += length;
        self.ordinal += 1;
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn finish(
        self,
    ) -> Result<(Vec<([u8; 32], super::BlockRecordLocator)>, [u8; 32], u64), NodeError> {
        let file = self
            .file
            .into_inner()
            .map_err(|error| io_error("flush pruned block log", &self.path, error.into_error()))?;
        file.sync_all()
            .map_err(|source| io_error("sync pruned block log", &self.path, source))?;
        drop(file);
        Ok((self.locators, self.previous, self.offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_space_rule_reserves_twice_the_kept_blocks_and_a_margin() {
        assert_eq!(
            prune_free_space_required(0, 0),
            PRUNE_FREE_SPACE_MARGIN_BYTES
        );
        let kept = 720 * 12_000_000_u64;
        assert_eq!(
            prune_free_space_required(kept, 5_000),
            2 * kept + 5_000 * PRUNED_RECORD_ALLOWANCE_BYTES + PRUNE_FREE_SPACE_MARGIN_BYTES
        );
        assert_eq!(prune_free_space_required(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn candidates_stay_few_for_any_window() {
        assert_eq!(candidate_interval(10), 64);
        assert_eq!(candidate_interval(MIN_PRUNE_KEEP_BLOCKS), 64);
        assert_eq!(candidate_interval(1_000), 192);
        assert_eq!(candidate_interval(100_000), 24_960);
        for keep in [MIN_PRUNE_KEEP_BLOCKS, 1_000, 10_000, 100_000, 1_000_000] {
            assert!(keep / candidate_interval(keep) + SPARE_CANDIDATES <= 9);
        }
    }

    #[test]
    fn proof_summary_names_cover_every_kind() {
        for (kind, name) in [
            (1, "v1_legacy"),
            (2, "v2_reference"),
            (3, "v3_candidate"),
            (4, "v4_candidate"),
        ] {
            let summary = ProofSummary {
                kind,
                nonce: 0,
                work_digest: [0; 32],
            };
            assert_eq!(summary.kind_name(), name);
        }
    }
}
