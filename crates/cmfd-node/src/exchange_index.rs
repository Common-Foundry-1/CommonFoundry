//! Durable, watch-only deposit indexing for authenticated exchange integrations.
//!
//! Registrations are immutable and the index never holds keys, signs, or
//! consults the mempool.  Chain bodies are authenticated and decoded outside
//! the node mutex, then applied only after rechecking the captured node
//! instance and chain revision.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use blake3::Hasher;
use cmfd_consensus::OutputLock;
use k256::schnorr::VerifyingKey;
use thiserror::Error;

use super::{
    BLOCK_LOG_FILE, BlockRecordLocator, Node, NodeError, ProofProfile,
    is_authenticated_storage_failure, read_located_record, sync_parent_directory,
    verify_retained_block_log_path,
};

pub(crate) const EXCHANGE_INDEX_FILE_PREFIX: &str = "exchange-deposits";
const EXCHANGE_INDEX_MARKER_FILE: &str = "exchange-deposits.initialized";
pub(crate) const MAX_WATCH_DESTINATIONS: usize = 100_000;
pub(crate) const MAX_ACTIVE_DEPOSITS: usize = 1_000_000;
pub(crate) const MAX_DEPOSIT_EVENTS: usize = 1_000_000;
pub(crate) const MAX_DEPOSIT_EVENT_PAGE: usize = 1_000;
pub(crate) const MAX_WATCH_LABEL_BYTES: usize = 128;
pub(crate) const MAX_WATCH_REGISTRATION_BATCH: usize = 1_000;

const MAX_INDEXED_CHAIN_BLOCKS: usize = 4_000_000;
/// Registration reads only the blocks the node's address history lists for
/// the new keys, so a block arriving mid-read is rare and simply retried.
const REGISTRATION_ATTEMPTS: usize = 3;
/// Blocks read per incremental synchronize pass. Each pass persists before
/// the next starts, so an index that fell far behind (a slow restart, a client
/// that stopped polling) catches up across calls instead of re-reading the
/// whole gap on every call and losing it to the next block.
const MAX_BLOCKS_PER_SYNCHRONIZE: usize = 64;
const MAX_EXCHANGE_INDEX_BYTES: usize = 512 * 1024 * 1024;
const SNAPSHOT_MAGIC: [u8; 8] = *b"CMFDEXI\0";
const MARKER_MAGIC: [u8; 8] = *b"CMFDEXM\0";
const SNAPSHOT_VERSION: u32 = 1;
const SNAPSHOT_DIGEST_BYTES: usize = 32;
const SNAPSHOT_INTEGRITY_DOMAIN: &str = "CMFD/NODE/EXCHANGE-DEPOSIT-INDEX/V1";
const MARKER_INTEGRITY_DOMAIN: &str = "CMFD/NODE/EXCHANGE-DEPOSIT-MARKER/V1";

#[derive(Debug, Error)]
pub(crate) enum ExchangeIndexError {
    #[error("exchange deposit index I/O failed during {operation}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("exchange deposit index is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("exchange deposit index belongs to another network or consensus fingerprint")]
    BindingMismatch,
    #[error("exchange deposit index is faulted and requires a node restart")]
    Faulted,
    #[error("watch label is invalid")]
    InvalidLabel,
    #[error("watch destination is not a valid key destination")]
    InvalidDestination,
    #[error("watch label is already registered to another destination")]
    LabelConflict,
    #[error("watch destination is already registered under another label")]
    DestinationConflict,
    #[error(
        "watch registration batch must contain between 1 and {MAX_WATCH_REGISTRATION_BATCH} entries"
    )]
    InvalidRegistrationBatch,
    #[error("watch registration batch contains a duplicate label")]
    DuplicateBatchLabel,
    #[error("watch registration batch contains a duplicate destination")]
    DuplicateBatchDestination,
    #[error("exchange deposit index capacity was reached: {0}")]
    Capacity(&'static str),
    #[error("deposit event cursor is above the current high watermark")]
    InvalidCursor,
    #[error("deposit event page limit must be between 1 and {MAX_DEPOSIT_EVENT_PAGE}")]
    InvalidPageLimit,
    #[error("the active chain changed while the exchange index was scanning")]
    ChainChanged,
    #[error(transparent)]
    Node(#[from] NodeError),
}

impl ExchangeIndexError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "exchange_index_io",
            Self::Corrupt(_) => "exchange_index_corrupt",
            Self::BindingMismatch => "exchange_index_binding_mismatch",
            Self::Faulted => "exchange_index_faulted",
            Self::InvalidLabel => "invalid_watch_label",
            Self::InvalidDestination => "invalid_watch_destination",
            Self::LabelConflict => "watch_label_conflict",
            Self::DestinationConflict => "watch_destination_conflict",
            Self::InvalidRegistrationBatch => "invalid_watch_registration_batch",
            Self::DuplicateBatchLabel => "duplicate_watch_batch_label",
            Self::DuplicateBatchDestination => "duplicate_watch_batch_destination",
            Self::Capacity(_) => "exchange_index_capacity",
            Self::InvalidCursor => "deposit_cursor_ahead",
            Self::InvalidPageLimit => "invalid_deposit_event_page_limit",
            Self::ChainChanged => "exchange_index_chain_changed",
            Self::Node(error) => error.client_error().code,
        }
    }

    pub(crate) fn retryable(&self) -> bool {
        match self {
            Self::ChainChanged => true,
            Self::Node(error) => error.client_error().retryable,
            _ => false,
        }
    }

    pub(crate) fn client_message(&self) -> String {
        match self {
            Self::Io { .. } => {
                "exchange deposit index storage failed; inspect the node logs".to_owned()
            }
            Self::Corrupt(_) => {
                "exchange deposit index is corrupt; restore it or rebuild it explicitly".to_owned()
            }
            Self::BindingMismatch => {
                "exchange deposit index network or consensus binding does not match".to_owned()
            }
            Self::Faulted => {
                "exchange deposit index is faulted; restart the node before retrying".to_owned()
            }
            Self::InvalidLabel => {
                format!("watch label must contain 1 to {MAX_WATCH_LABEL_BYTES} visible ASCII bytes")
            }
            Self::InvalidDestination => {
                "watch destination must be a valid 32-byte key destination".to_owned()
            }
            Self::LabelConflict => {
                "watch label is already registered to another destination".to_owned()
            }
            Self::DestinationConflict => {
                "watch destination is already registered under another label".to_owned()
            }
            Self::InvalidRegistrationBatch => format!(
                "watch registration batch must contain between 1 and {MAX_WATCH_REGISTRATION_BATCH} entries"
            ),
            Self::DuplicateBatchLabel => {
                "watch registration batch contains a duplicate label".to_owned()
            }
            Self::DuplicateBatchDestination => {
                "watch registration batch contains a duplicate destination".to_owned()
            }
            Self::Capacity(kind) => format!("exchange deposit index {kind} capacity was reached"),
            Self::InvalidCursor => {
                "deposit event cursor is above the current high watermark".to_owned()
            }
            Self::InvalidPageLimit => {
                format!("deposit event page limit must be between 1 and {MAX_DEPOSIT_EVENT_PAGE}")
            }
            Self::ChainChanged => {
                "active chain changed during the deposit scan; retry the request".to_owned()
            }
            Self::Node(error) => error.client_error().message,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DepositOutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActiveDeposit {
    pub outpoint: DepositOutPoint,
    pub label: String,
    pub destination: [u8; 32],
    pub amount_atoms: u64,
    pub spendable_height: u64,
    pub coinbase: bool,
    pub block_hash: [u8; 32],
    pub block_height: u64,
    pub block_timestamp: u64,
    pub added_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DepositEventKind {
    Added,
    Removed,
}

impl DepositEventKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Added => "deposit_added",
            Self::Removed => "deposit_removed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DepositEvent {
    pub sequence: u64,
    pub added_sequence: u64,
    pub kind: DepositEventKind,
    pub deposit: ActiveDeposit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WatchDestinationView {
    pub label: String,
    pub destination: [u8; 32],
    pub registered_at_height: u64,
    pub registered_at_tip: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegisterWatchDestinationResult {
    pub watch: WatchDestinationView,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WatchDestinationRegistration {
    pub label: String,
    pub destination: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegisterWatchDestinationsResult {
    pub watches: Vec<WatchDestinationView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DepositEventPage {
    pub network_id: [u8; 32],
    pub consensus_fingerprint: [u8; 32],
    pub indexed_tip_height: u64,
    pub indexed_tip: [u8; 32],
    pub high_watermark: u64,
    pub next_cursor: u64,
    pub has_more: bool,
    pub events: Vec<DepositEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExchangeIndexStatus {
    pub network_id: [u8; 32],
    pub consensus_fingerprint: [u8; 32],
    pub indexed_tip_height: u64,
    pub indexed_tip: [u8; 32],
    pub high_watermark: u64,
    pub watch_destination_count: usize,
    pub active_deposit_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegisteredDestination {
    destination: [u8; 32],
    registered_at_height: u64,
    registered_at_tip: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexState {
    generation: u64,
    high_watermark: u64,
    indexed_chain: Vec<[u8; 32]>,
    watches: BTreeMap<String, RegisteredDestination>,
    active_deposits: BTreeMap<DepositOutPoint, ActiveDeposit>,
    events: Vec<DepositEvent>,
}

pub(crate) struct ExchangeDepositIndex {
    // Ephemeral and rebuilt from authenticated history; never persisted in the
    // deposit event journal or treated as a consensus capability.
    pub(crate) transaction_lookup: crate::exchange_queries::TransactionLookupIndex,
    data_dir: PathBuf,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
    state: IndexState,
    faulted: bool,
}

impl ExchangeDepositIndex {
    pub(crate) fn open_and_sync(shared: &Arc<Mutex<Node>>) -> Result<Self, ExchangeIndexError> {
        let binding = node_binding(shared)?;
        let loaded = load_state(
            &binding.data_dir,
            binding.network_id,
            binding.consensus_fingerprint,
            binding.genesis,
        )?;
        let (state, needs_redundancy, needs_marker) = loaded.map_or_else(
            || {
                (
                    IndexState {
                        generation: 0,
                        high_watermark: 0,
                        indexed_chain: vec![binding.genesis],
                        watches: BTreeMap::new(),
                        active_deposits: BTreeMap::new(),
                        events: Vec::new(),
                    },
                    false,
                    false,
                )
            },
            |loaded| (loaded.state, loaded.needs_redundancy, loaded.needs_marker),
        );
        let mut index = Self {
            transaction_lookup: Default::default(),
            data_dir: binding.data_dir,
            network_id: binding.network_id,
            consensus_fingerprint: binding.consensus_fingerprint,
            genesis: binding.genesis,
            state,
            faulted: false,
        };
        if needs_redundancy {
            index.persist_candidate(index.state.clone())?;
        }
        if needs_marker {
            index.persist_marker()?;
        }
        index.synchronize(shared)?;
        Ok(index)
    }

    pub(crate) fn synchronize(
        &mut self,
        shared: &Arc<Mutex<Node>>,
    ) -> Result<ExchangeIndexStatus, ExchangeIndexError> {
        self.require_healthy()?;
        let plan = self.capture_incremental_plan(shared)?;
        if plan.active_chain == self.state.indexed_chain {
            return Ok(self.status());
        }
        let watches = self
            .state
            .watches
            .iter()
            .map(|(label, watch)| (watch.destination, label.clone()))
            .collect::<BTreeMap<_, _>>();
        let deposits = execute_deposit_scan(&plan, shared, &watches)?;
        let mut candidate = self.state.clone();
        reconcile_state(&mut candidate, &plan.active_chain, deposits)?;
        self.recheck_shared_plan(shared, &plan)?;
        self.persist_candidate(candidate)?;
        self.recheck_shared_plan(shared, &plan)?;
        Ok(self.status())
    }

    /// Registers one immutable key destination after scanning active history
    /// from height one. Labels are persisted in plaintext; callers should use
    /// pseudonymous internal identifiers rather than customer information.
    pub(crate) fn register_watch_destination(
        &mut self,
        shared: &Arc<Mutex<Node>>,
        label: &str,
        destination: [u8; 32],
    ) -> Result<RegisterWatchDestinationResult, ExchangeIndexError> {
        let result = self.register_watch_destinations(
            shared,
            &[WatchDestinationRegistration {
                label: label.to_owned(),
                destination,
            }],
        )?;
        Ok(RegisterWatchDestinationResult {
            watch: result
                .watches
                .into_iter()
                .next()
                .expect("one registration must return one watch"),
        })
    }

    /// Atomically registers a bounded set of immutable key destinations after
    /// one active-history scan. Exact retries are idempotent. Any invalid or
    /// conflicting entry rejects the complete batch before persistence.
    pub(crate) fn register_watch_destinations(
        &mut self,
        shared: &Arc<Mutex<Node>>,
        registrations: &[WatchDestinationRegistration],
    ) -> Result<RegisterWatchDestinationsResult, ExchangeIndexError> {
        if registrations.is_empty() || registrations.len() > MAX_WATCH_REGISTRATION_BATCH {
            return Err(ExchangeIndexError::InvalidRegistrationBatch);
        }
        let mut labels = BTreeSet::new();
        let mut destinations = BTreeSet::new();
        for registration in registrations {
            validate_label(&registration.label)?;
            validate_destination(registration.destination)?;
            if !labels.insert(registration.label.as_str()) {
                return Err(ExchangeIndexError::DuplicateBatchLabel);
            }
            if !destinations.insert(registration.destination) {
                return Err(ExchangeIndexError::DuplicateBatchDestination);
            }
        }
        // A block arriving during the short indexed read is retried here;
        // an attempt that already persisted leaves nothing pending.
        let mut attempt = 1;
        loop {
            match self.register_pending(shared, registrations) {
                Err(ExchangeIndexError::ChainChanged) if attempt < REGISTRATION_ATTEMPTS => {
                    attempt += 1;
                }
                result => break result?,
            }
        }

        let watches = registrations
            .iter()
            .map(|registration| {
                let stored = self
                    .state
                    .watches
                    .get(&registration.label)
                    .expect("validated batch registration must be present");
                self.watch_view(&registration.label, stored)
            })
            .collect();
        Ok(RegisterWatchDestinationsResult { watches })
    }

    fn register_pending(
        &mut self,
        shared: &Arc<Mutex<Node>>,
        registrations: &[WatchDestinationRegistration],
    ) -> Result<(), ExchangeIndexError> {
        self.synchronize(shared)?;

        let existing_destinations = self
            .state
            .watches
            .iter()
            .map(|(label, watch)| (watch.destination, label.as_str()))
            .collect::<BTreeMap<_, _>>();
        let mut pending = Vec::new();
        for registration in registrations {
            if let Some(existing) = self.state.watches.get(&registration.label) {
                if existing.destination != registration.destination {
                    return Err(ExchangeIndexError::LabelConflict);
                }
                continue;
            }
            if existing_destinations.contains_key(&registration.destination) {
                return Err(ExchangeIndexError::DestinationConflict);
            }
            pending.push(registration);
        }
        if self.state.watches.len().saturating_add(pending.len()) > MAX_WATCH_DESTINATIONS {
            return Err(ExchangeIndexError::Capacity("watch destination"));
        }

        if !pending.is_empty() {
            let watches = pending
                .iter()
                .map(|registration| (registration.destination, registration.label.clone()))
                .collect::<BTreeMap<_, _>>();
            let plan = self.capture_registration_plan(shared, watches.keys())?;
            let deposits = execute_deposit_scan(&plan, shared, &watches)?;
            let mut candidate = self.state.clone();
            let tip_height = indexed_tip_height(&plan.active_chain)?;
            let tip = *plan
                .active_chain
                .last()
                .ok_or(ExchangeIndexError::Corrupt("captured chain is empty"))?;
            for registration in pending {
                candidate.watches.insert(
                    registration.label.clone(),
                    RegisteredDestination {
                        destination: registration.destination,
                        registered_at_height: tip_height,
                        registered_at_tip: tip,
                    },
                );
            }
            for deposit in deposits {
                append_added_deposit(&mut candidate, deposit)?;
            }

            self.recheck_shared_plan(shared, &plan)?;
            self.persist_candidate(candidate)?;
            self.recheck_shared_plan(shared, &plan)?;
        }
        Ok(())
    }

    pub(crate) fn get_watch_destination(
        &self,
        label: &str,
    ) -> Result<Option<WatchDestinationView>, ExchangeIndexError> {
        self.require_healthy()?;
        validate_label(label)?;
        Ok(self
            .state
            .watches
            .get(label)
            .map(|watch| self.watch_view(label, watch)))
    }

    pub(crate) fn get_deposit_events(
        &self,
        after_sequence: u64,
        limit: usize,
    ) -> Result<DepositEventPage, ExchangeIndexError> {
        self.require_healthy()?;
        if limit == 0 || limit > MAX_DEPOSIT_EVENT_PAGE {
            return Err(ExchangeIndexError::InvalidPageLimit);
        }
        if after_sequence > self.state.high_watermark {
            return Err(ExchangeIndexError::InvalidCursor);
        }
        let start =
            usize::try_from(after_sequence).map_err(|_| ExchangeIndexError::InvalidCursor)?;
        let end = start.saturating_add(limit).min(self.state.events.len());
        let events = self.state.events[start..end].to_vec();
        let next_cursor = events.last().map_or(after_sequence, |event| event.sequence);
        let (indexed_tip_height, indexed_tip) = self.indexed_tip();
        Ok(DepositEventPage {
            network_id: self.network_id,
            consensus_fingerprint: self.consensus_fingerprint,
            indexed_tip_height,
            indexed_tip,
            high_watermark: self.state.high_watermark,
            next_cursor,
            has_more: next_cursor < self.state.high_watermark,
            events,
        })
    }

    pub(crate) fn status(&self) -> ExchangeIndexStatus {
        let (indexed_tip_height, indexed_tip) = self.indexed_tip();
        ExchangeIndexStatus {
            network_id: self.network_id,
            consensus_fingerprint: self.consensus_fingerprint,
            indexed_tip_height,
            indexed_tip,
            high_watermark: self.state.high_watermark,
            watch_destination_count: self.state.watches.len(),
            active_deposit_count: self.state.active_deposits.len(),
        }
    }

    fn capture_incremental_plan(
        &self,
        shared: &Arc<Mutex<Node>>,
    ) -> Result<ChainReadPlan, ExchangeIndexError> {
        let node = lock_node(shared)?;
        self.check_node_binding(&node)?;
        let mut active_chain = checked_active_chain(&node)?;
        let common = common_prefix_len(&self.state.indexed_chain, &active_chain);
        let read_blocks = !self.state.watches.is_empty();
        if read_blocks && active_chain.len() - common > MAX_BLOCKS_PER_SYNCHRONIZE {
            active_chain.truncate(common + MAX_BLOCKS_PER_SYNCHRONIZE);
        }
        capture_chain_plan(&node, active_chain, common, read_blocks)
    }

    /// Plans the active-history read for new watches. The node's full-history
    /// address index lists every retained block with a key output to (or key
    /// spend by) each destination, so only those blocks are read; a fresh key
    /// reads none.
    fn capture_registration_plan<'a>(
        &self,
        shared: &Arc<Mutex<Node>>,
        destinations: impl Iterator<Item = &'a [u8; 32]>,
    ) -> Result<ChainReadPlan, ExchangeIndexError> {
        let node = lock_node(shared)?;
        self.check_node_binding(&node)?;
        let active_chain = checked_active_chain(&node)?;
        if active_chain != self.state.indexed_chain {
            return Err(ExchangeIndexError::ChainChanged);
        }
        let mut positions = BTreeSet::new();
        for destination in destinations {
            for height in node
                .index
                .addresses
                .active_heights(destination, &node.index)
            {
                positions.insert(
                    usize::try_from(height)
                        .map_err(|_| ExchangeIndexError::Capacity("indexed chain"))?,
                );
            }
        }
        capture_chain_plan_at(&node, active_chain, positions)
    }

    fn check_node_binding(&self, node: &Node) -> Result<(), ExchangeIndexError> {
        if node.data_dir != self.data_dir
            || node.params.network_id != self.network_id
            || node.fingerprint != self.consensus_fingerprint
            || node.params.genesis_hash != self.genesis
        {
            return Err(ExchangeIndexError::BindingMismatch);
        }
        if node.storage_faulted {
            return Err(ExchangeIndexError::Node(NodeError::StorageFaulted));
        }
        Ok(())
    }

    /// The planned chain must still be a prefix of the active chain: blocks
    /// appended behind it while the plan was read do not change what was
    /// read, a reorganization of any planned block does.
    fn recheck_plan(&self, node: &Node, plan: &ChainReadPlan) -> Result<(), ExchangeIndexError> {
        self.check_node_binding(node)?;
        if node.instance_id != plan.node_instance_id
            || !node.index.active_chain.starts_with(&plan.active_chain)
        {
            return Err(ExchangeIndexError::ChainChanged);
        }
        Ok(())
    }

    fn recheck_shared_plan(
        &self,
        shared: &Arc<Mutex<Node>>,
        plan: &ChainReadPlan,
    ) -> Result<(), ExchangeIndexError> {
        let node = lock_node(shared)?;
        self.recheck_plan(&node, plan)
    }

    fn persist_candidate(&mut self, mut candidate: IndexState) -> Result<(), ExchangeIndexError> {
        let result = (|| {
            let first_generation = self
                .state
                .generation
                .checked_add(1)
                .ok_or(ExchangeIndexError::Capacity("snapshot generation"))?;
            candidate.generation = first_generation;
            validate_state(&candidate, self.genesis)?;
            let bytes = encode_snapshot(&candidate, self.network_id, self.consensus_fingerprint)?;
            let slot = (candidate.generation & 1) as u8;
            persist_slot(&snapshot_path(&self.data_dir, slot), &bytes)?;

            if self.state.generation == 0 {
                candidate.generation = first_generation
                    .checked_add(1)
                    .ok_or(ExchangeIndexError::Capacity("snapshot generation"))?;
                let bytes =
                    encode_snapshot(&candidate, self.network_id, self.consensus_fingerprint)?;
                let slot = (candidate.generation & 1) as u8;
                persist_slot(&snapshot_path(&self.data_dir, slot), &bytes)?;
                persist_marker(
                    &self.data_dir,
                    self.network_id,
                    self.consensus_fingerprint,
                    self.genesis,
                )?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.faulted = true;
            return Err(error);
        }
        self.state = candidate;
        Ok(())
    }

    fn persist_marker(&mut self) -> Result<(), ExchangeIndexError> {
        if let Err(error) = persist_marker(
            &self.data_dir,
            self.network_id,
            self.consensus_fingerprint,
            self.genesis,
        ) {
            self.faulted = true;
            return Err(error);
        }
        Ok(())
    }

    fn watch_view(&self, label: &str, watch: &RegisteredDestination) -> WatchDestinationView {
        WatchDestinationView {
            label: label.to_owned(),
            destination: watch.destination,
            registered_at_height: watch.registered_at_height,
            registered_at_tip: watch.registered_at_tip,
        }
    }

    fn indexed_tip(&self) -> (u64, [u8; 32]) {
        (
            u64::try_from(self.state.indexed_chain.len().saturating_sub(1)).unwrap_or(u64::MAX),
            *self
                .state
                .indexed_chain
                .last()
                .expect("validated exchange index chain is nonempty"),
        )
    }

    fn require_healthy(&self) -> Result<(), ExchangeIndexError> {
        if self.faulted {
            Err(ExchangeIndexError::Faulted)
        } else {
            Ok(())
        }
    }
}

struct NodeBinding {
    data_dir: PathBuf,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
}

fn node_binding(shared: &Arc<Mutex<Node>>) -> Result<NodeBinding, ExchangeIndexError> {
    let node = lock_node(shared)?;
    if node.storage_faulted {
        return Err(ExchangeIndexError::Node(NodeError::StorageFaulted));
    }
    Ok(NodeBinding {
        data_dir: node.data_dir.clone(),
        network_id: node.params.network_id,
        consensus_fingerprint: node.fingerprint,
        genesis: node.params.genesis_hash,
    })
}

fn lock_node(shared: &Arc<Mutex<Node>>) -> Result<MutexGuard<'_, Node>, ExchangeIndexError> {
    shared
        .lock()
        .map_err(|_| ExchangeIndexError::Node(NodeError::SharedNodePoisoned))
}

struct PlannedBlock {
    height: u64,
    block_id: [u8; 32],
    locator: BlockRecordLocator,
}

struct ChainReadPlan {
    node_instance_id: u64,
    active_chain: Vec<[u8; 32]>,
    blocks: Vec<PlannedBlock>,
    log: Option<crate::LogReadHandle>,
    log_path: PathBuf,
    network_id: [u8; 32],
    require_v2: bool,
}

fn checked_active_chain(node: &Node) -> Result<Vec<[u8; 32]>, ExchangeIndexError> {
    if node.index.active_chain.is_empty() || node.index.active_chain[0] != node.params.genesis_hash
    {
        return Err(ExchangeIndexError::Node(NodeError::CorruptLog(
            "active chain is missing its virtual genesis".to_owned(),
        )));
    }
    if node.index.active_chain.len() > MAX_INDEXED_CHAIN_BLOCKS {
        return Err(ExchangeIndexError::Capacity("indexed chain"));
    }
    Ok(node.index.active_chain.clone())
}

fn capture_chain_plan(
    node: &Node,
    active_chain: Vec<[u8; 32]>,
    start: usize,
    read_blocks: bool,
) -> Result<ChainReadPlan, ExchangeIndexError> {
    if start > active_chain.len() {
        return Err(ExchangeIndexError::Corrupt(
            "chain scan starts above the captured tip",
        ));
    }
    let end = if read_blocks {
        active_chain.len()
    } else {
        start
    };
    capture_chain_plan_at(node, active_chain, start..end)
}

/// Plans authenticated reads of the given active-chain positions, ascending.
fn capture_chain_plan_at(
    node: &Node,
    active_chain: Vec<[u8; 32]>,
    positions: impl IntoIterator<Item = usize>,
) -> Result<ChainReadPlan, ExchangeIndexError> {
    let mut blocks = Vec::new();
    for position in positions {
        if position == 0 {
            continue;
        }
        let block_id = *active_chain
            .get(position)
            .ok_or(ExchangeIndexError::Corrupt(
                "chain scan position is above the captured tip",
            ))?;
        let indexed = node.index.blocks.get(&block_id).ok_or_else(|| {
            ExchangeIndexError::Node(NodeError::CorruptLog(
                "active exchange scan refers to an absent block".to_owned(),
            ))
        })?;
        let height =
            u64::try_from(position).map_err(|_| ExchangeIndexError::Capacity("indexed chain"))?;
        if indexed.block_id() != block_id || indexed.height() != height {
            return Err(ExchangeIndexError::Node(NodeError::CorruptLog(
                "active exchange scan block metadata is inconsistent".to_owned(),
            )));
        }
        blocks.push(PlannedBlock {
            height,
            block_id,
            locator: indexed.locator,
        });
    }
    let log_path = node.data_dir.join(BLOCK_LOG_FILE);
    let log = if blocks.is_empty() {
        None
    } else {
        Some(node.clone_log_for_read().map_err(|source| {
            ExchangeIndexError::Node(super::io_error(
                "clone retained block log for exchange deposit scan",
                &log_path,
                source,
            ))
        })?)
    };
    Ok(ChainReadPlan {
        node_instance_id: node.instance_id,
        active_chain,
        blocks,
        log,
        log_path,
        network_id: node.params.network_id,
        require_v2: matches!(node.profile.proof, ProofProfile::ProductionV3),
    })
}

fn execute_deposit_scan(
    plan: &ChainReadPlan,
    shared: &Arc<Mutex<Node>>,
    watches: &BTreeMap<[u8; 32], String>,
) -> Result<Vec<ActiveDeposit>, ExchangeIndexError> {
    let result = (|| -> Result<Vec<ActiveDeposit>, ExchangeIndexError> {
        let Some(log) = plan.log.as_ref() else {
            return Ok(Vec::new());
        };
        verify_retained_block_log_path(log, &plan.log_path)?;
        let mut deposits = Vec::new();
        for planned in &plan.blocks {
            let (_, block) = read_located_record(
                log,
                &plan.log_path,
                &planned.locator,
                plan.network_id,
                plan.require_v2,
            )?;
            if block.block_id() != planned.block_id || block.challenge.height != planned.height {
                return Err(ExchangeIndexError::Node(NodeError::CorruptLog(
                    "exchange deposit scan read a mismatched block".to_owned(),
                )));
            }
            collect_block_deposits(&mut deposits, watches, &block)?;
        }
        verify_retained_block_log_path(log, &plan.log_path)?;
        Ok(deposits)
    })();
    match result {
        Ok(blocks) => Ok(blocks),
        Err(error) => {
            if let ExchangeIndexError::Node(node_error) = &error
                && is_authenticated_storage_failure(node_error)
            {
                let mut node = lock_node(shared)?;
                if node.instance_id == plan.node_instance_id {
                    node.storage_faulted = true;
                }
            }
            Err(error)
        }
    }
}

fn reconcile_state(
    state: &mut IndexState,
    active_chain: &[[u8; 32]],
    deposits: Vec<ActiveDeposit>,
) -> Result<(), ExchangeIndexError> {
    let common = common_prefix_len(&state.indexed_chain, active_chain);
    let common_height =
        u64::try_from(common).map_err(|_| ExchangeIndexError::Capacity("indexed chain"))?;
    let mut removed: Vec<_> = state
        .active_deposits
        .values()
        .filter(|deposit| deposit.block_height >= common_height)
        .cloned()
        .collect();
    removed.sort_by(|left, right| {
        right
            .block_height
            .cmp(&left.block_height)
            .then_with(|| right.added_sequence.cmp(&left.added_sequence))
            .then_with(|| left.outpoint.cmp(&right.outpoint))
    });
    for deposit in removed {
        append_removed_deposit(state, deposit)?;
    }

    for deposit in deposits {
        append_added_deposit(state, deposit)?;
    }
    state.indexed_chain = active_chain.to_vec();
    Ok(())
}

fn collect_block_deposits(
    deposits: &mut Vec<ActiveDeposit>,
    watches: &BTreeMap<[u8; 32], String>,
    block: &crate::StoredBlock,
) -> Result<(), ExchangeIndexError> {
    let block_hash = block.block_id();
    let block_height = block.challenge.height;
    let block_timestamp = block.challenge.timestamp;
    let coinbase_txid = block.coinbase_outpoint_id();
    collect_outputs(
        deposits,
        watches,
        coinbase_txid,
        &block.coinbase.outputs,
        true,
        block_hash,
        block_height,
        block_timestamp,
    )?;
    for transaction in &block.transactions {
        collect_outputs(
            deposits,
            watches,
            transaction.txid(),
            &transaction.outputs,
            false,
            block_hash,
            block_height,
            block_timestamp,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect_outputs(
    deposits: &mut Vec<ActiveDeposit>,
    watches: &BTreeMap<[u8; 32], String>,
    txid: [u8; 32],
    outputs: &[cmfd_consensus::TxOutput],
    coinbase: bool,
    block_hash: [u8; 32],
    block_height: u64,
    block_timestamp: u64,
) -> Result<(), ExchangeIndexError> {
    for (position, output) in outputs.iter().enumerate() {
        let OutputLock::Key(destination) = output.lock else {
            continue;
        };
        let Some(label) = watches.get(&destination) else {
            continue;
        };
        if deposits.len() >= MAX_ACTIVE_DEPOSITS {
            return Err(ExchangeIndexError::Capacity("active deposit"));
        }
        let vout = u32::try_from(position)
            .map_err(|_| ExchangeIndexError::Corrupt("transaction output index overflowed"))?;
        deposits.push(ActiveDeposit {
            outpoint: DepositOutPoint { txid, vout },
            label: label.clone(),
            destination,
            amount_atoms: output.value,
            spendable_height: output.spendable_height,
            coinbase,
            block_hash,
            block_height,
            block_timestamp,
            added_sequence: 0,
        });
    }
    Ok(())
}

fn append_added_deposit(
    state: &mut IndexState,
    mut deposit: ActiveDeposit,
) -> Result<(), ExchangeIndexError> {
    if state.active_deposits.len() >= MAX_ACTIVE_DEPOSITS {
        return Err(ExchangeIndexError::Capacity("active deposit"));
    }
    if state.active_deposits.contains_key(&deposit.outpoint) {
        return Err(ExchangeIndexError::Corrupt(
            "active chain contains a duplicate watched outpoint",
        ));
    }
    let sequence = next_event_sequence(state)?;
    deposit.added_sequence = sequence;
    append_event(
        state,
        sequence,
        sequence,
        DepositEventKind::Added,
        deposit.clone(),
    )?;
    state.active_deposits.insert(deposit.outpoint, deposit);
    Ok(())
}

fn append_removed_deposit(
    state: &mut IndexState,
    deposit: ActiveDeposit,
) -> Result<(), ExchangeIndexError> {
    if state.active_deposits.get(&deposit.outpoint) != Some(&deposit) {
        return Err(ExchangeIndexError::Corrupt(
            "deposit removal does not match active state",
        ));
    }
    let sequence = next_event_sequence(state)?;
    append_event(
        state,
        sequence,
        deposit.added_sequence,
        DepositEventKind::Removed,
        deposit.clone(),
    )?;
    state.active_deposits.remove(&deposit.outpoint);
    Ok(())
}

fn append_event(
    state: &mut IndexState,
    sequence: u64,
    added_sequence: u64,
    kind: DepositEventKind,
    deposit: ActiveDeposit,
) -> Result<(), ExchangeIndexError> {
    if state.events.len() >= MAX_DEPOSIT_EVENTS {
        return Err(ExchangeIndexError::Capacity("deposit event"));
    }
    state.events.push(DepositEvent {
        sequence,
        added_sequence,
        kind,
        deposit,
    });
    state.high_watermark = sequence;
    Ok(())
}

fn next_event_sequence(state: &IndexState) -> Result<u64, ExchangeIndexError> {
    state
        .high_watermark
        .checked_add(1)
        .ok_or(ExchangeIndexError::Capacity("event sequence"))
}

fn common_prefix_len(left: &[[u8; 32]], right: &[[u8; 32]]) -> usize {
    left.iter()
        .zip(right)
        .take_while(|(left, right)| left == right)
        .count()
}

fn indexed_tip_height(chain: &[[u8; 32]]) -> Result<u64, ExchangeIndexError> {
    u64::try_from(
        chain
            .len()
            .checked_sub(1)
            .ok_or(ExchangeIndexError::Corrupt("indexed chain is empty"))?,
    )
    .map_err(|_| ExchangeIndexError::Capacity("indexed chain"))
}

fn validate_label(label: &str) -> Result<(), ExchangeIndexError> {
    if label.is_empty()
        || label.len() > MAX_WATCH_LABEL_BYTES
        || !label.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ExchangeIndexError::InvalidLabel);
    }
    Ok(())
}

fn validate_destination(destination: [u8; 32]) -> Result<(), ExchangeIndexError> {
    VerifyingKey::from_bytes(&destination)
        .map(|_| ())
        .map_err(|_| ExchangeIndexError::InvalidDestination)
}

enum LoadedSlot {
    Missing,
    Valid(IndexState),
}

struct LoadedState {
    state: IndexState,
    needs_redundancy: bool,
    needs_marker: bool,
}

fn load_marker(
    data_dir: &Path,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
) -> Result<bool, ExchangeIndexError> {
    let path = marker_path(data_dir);
    let mut file = match OpenOptions::new().read(true).open(&path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(index_io("open exchange deposit marker", &path, source)),
    };
    let metadata = file
        .metadata()
        .map_err(|source| index_io("inspect exchange deposit marker", &path, source))?;
    if !metadata.file_type().is_file() {
        return Err(ExchangeIndexError::Corrupt(
            "exchange deposit marker is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ExchangeIndexError::Corrupt(
                "exchange deposit marker permissions are not owner-only",
            ));
        }
    }
    const MARKER_PAYLOAD_BYTES: usize = 8 + 4 + 32 + 32 + 32;
    const MARKER_BYTES: usize = MARKER_PAYLOAD_BYTES + SNAPSHOT_DIGEST_BYTES;
    if metadata.len() != MARKER_BYTES as u64 {
        return Err(ExchangeIndexError::Corrupt(
            "exchange deposit marker size is invalid",
        ));
    }
    let mut bytes = [0_u8; MARKER_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|source| index_io("read exchange deposit marker", &path, source))?;
    let (payload, expected_digest) = bytes.split_at(MARKER_PAYLOAD_BYTES);
    if marker_digest(payload) != expected_digest {
        return Err(ExchangeIndexError::Corrupt(
            "exchange deposit marker checksum mismatch",
        ));
    }
    let mut decoder = Decoder::new(payload);
    if decoder.array::<8>()? != MARKER_MAGIC || decoder.u32()? != SNAPSHOT_VERSION {
        return Err(ExchangeIndexError::Corrupt(
            "exchange deposit marker magic or version is unsupported",
        ));
    }
    if decoder.array::<32>()? != network_id
        || decoder.array::<32>()? != consensus_fingerprint
        || decoder.array::<32>()? != genesis
    {
        return Err(ExchangeIndexError::BindingMismatch);
    }
    if !decoder.is_empty() {
        return Err(ExchangeIndexError::Corrupt(
            "exchange deposit marker contains trailing bytes",
        ));
    }
    Ok(true)
}

fn persist_marker(
    data_dir: &Path,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
) -> Result<(), ExchangeIndexError> {
    let mut bytes = Vec::with_capacity(140);
    bytes.extend_from_slice(&MARKER_MAGIC);
    bytes.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&network_id);
    bytes.extend_from_slice(&consensus_fingerprint);
    bytes.extend_from_slice(&genesis);
    let digest = marker_digest(&bytes);
    bytes.extend_from_slice(&digest);
    persist_slot(&marker_path(data_dir), &bytes)
}

fn load_state(
    data_dir: &Path,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
) -> Result<Option<LoadedState>, ExchangeIndexError> {
    let marker_present = load_marker(data_dir, network_id, consensus_fingerprint, genesis)?;
    let first = load_slot(
        &snapshot_path(data_dir, 0),
        0,
        network_id,
        consensus_fingerprint,
        genesis,
    )?;
    let second = load_slot(
        &snapshot_path(data_dir, 1),
        1,
        network_id,
        consensus_fingerprint,
        genesis,
    )?;
    match (first, second) {
        (LoadedSlot::Missing, LoadedSlot::Missing) => {
            if marker_present {
                Err(ExchangeIndexError::Corrupt(
                    "initialized exchange deposit snapshots are missing",
                ))
            } else {
                Ok(None)
            }
        }
        (LoadedSlot::Valid(state), LoadedSlot::Missing)
        | (LoadedSlot::Missing, LoadedSlot::Valid(state)) => {
            if marker_present || state.generation != 1 {
                return Err(ExchangeIndexError::Corrupt(
                    "snapshot redundancy is missing after initialization",
                ));
            }
            Ok(Some(LoadedState {
                state,
                needs_redundancy: true,
                needs_marker: true,
            }))
        }
        (LoadedSlot::Valid(first), LoadedSlot::Valid(second)) => {
            let difference = first.generation.abs_diff(second.generation);
            if difference != 1 {
                return Err(ExchangeIndexError::Corrupt(
                    "snapshot slot generations are inconsistent",
                ));
            }
            let (older, newer) = if first.generation < second.generation {
                (&first, &second)
            } else {
                (&second, &first)
            };
            if !older
                .watches
                .iter()
                .all(|(label, watch)| newer.watches.get(label) == Some(watch))
                || !newer.events.starts_with(&older.events)
            {
                return Err(ExchangeIndexError::Corrupt(
                    "snapshot slots do not form one append-only history",
                ));
            }
            Ok(Some(LoadedState {
                state: if first.generation > second.generation {
                    first
                } else {
                    second
                },
                needs_redundancy: false,
                needs_marker: !marker_present,
            }))
        }
    }
}

fn load_slot(
    path: &Path,
    expected_slot: u8,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
) -> Result<LoadedSlot, ExchangeIndexError> {
    let mut file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(LoadedSlot::Missing),
        Err(source) => return Err(index_io("open exchange deposit index", path, source)),
    };
    let metadata = file
        .metadata()
        .map_err(|source| index_io("inspect exchange deposit index", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(ExchangeIndexError::Corrupt(
            "snapshot slot is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ExchangeIndexError::Corrupt(
                "snapshot slot permissions are not owner-only",
            ));
        }
    }
    let length = usize::try_from(metadata.len())
        .ok()
        .filter(|length| {
            *length >= 8 + 4 + 32 + 32 + SNAPSHOT_DIGEST_BYTES
                && *length <= MAX_EXCHANGE_INDEX_BYTES
        })
        .ok_or(ExchangeIndexError::Corrupt("snapshot slot size is invalid"))?;
    let mut bytes = vec![0_u8; length];
    file.read_exact(&mut bytes)
        .map_err(|source| index_io("read exchange deposit index", path, source))?;
    let (payload, expected_digest) = bytes.split_at(bytes.len() - SNAPSHOT_DIGEST_BYTES);
    if snapshot_digest(payload) != expected_digest {
        return Err(ExchangeIndexError::Corrupt(
            "snapshot slot checksum mismatch",
        ));
    }
    let state = decode_snapshot(payload, network_id, consensus_fingerprint, genesis)?;
    if state.generation & 1 != u64::from(expected_slot) {
        return Err(ExchangeIndexError::Corrupt(
            "snapshot generation does not match its slot",
        ));
    }
    Ok(LoadedSlot::Valid(state))
}

fn encode_snapshot(
    state: &IndexState,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
) -> Result<Vec<u8>, ExchangeIndexError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&SNAPSHOT_MAGIC);
    bytes.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&network_id);
    bytes.extend_from_slice(&consensus_fingerprint);
    bytes.extend_from_slice(&state.generation.to_le_bytes());
    bytes.extend_from_slice(&state.high_watermark.to_le_bytes());
    write_count(&mut bytes, state.indexed_chain.len())?;
    write_count(&mut bytes, state.watches.len())?;
    write_count(&mut bytes, state.active_deposits.len())?;
    write_count(&mut bytes, state.events.len())?;
    for block_id in &state.indexed_chain {
        bytes.extend_from_slice(block_id);
    }
    for (label, watch) in &state.watches {
        write_label(&mut bytes, label)?;
        bytes.extend_from_slice(&watch.destination);
        bytes.extend_from_slice(&watch.registered_at_height.to_le_bytes());
        bytes.extend_from_slice(&watch.registered_at_tip);
    }
    for deposit in state.active_deposits.values() {
        write_deposit(&mut bytes, deposit)?;
    }
    for event in &state.events {
        bytes.extend_from_slice(&event.sequence.to_le_bytes());
        bytes.extend_from_slice(&event.added_sequence.to_le_bytes());
        bytes.push(match event.kind {
            DepositEventKind::Added => 1,
            DepositEventKind::Removed => 2,
        });
        write_deposit(&mut bytes, &event.deposit)?;
    }
    if bytes.len().saturating_add(SNAPSHOT_DIGEST_BYTES) > MAX_EXCHANGE_INDEX_BYTES {
        return Err(ExchangeIndexError::Capacity("snapshot byte"));
    }
    let digest = snapshot_digest(&bytes);
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn decode_snapshot(
    bytes: &[u8],
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
) -> Result<IndexState, ExchangeIndexError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.array::<8>()? != SNAPSHOT_MAGIC || decoder.u32()? != SNAPSHOT_VERSION {
        return Err(ExchangeIndexError::Corrupt(
            "snapshot magic or version is unsupported",
        ));
    }
    if decoder.array::<32>()? != network_id || decoder.array::<32>()? != consensus_fingerprint {
        return Err(ExchangeIndexError::BindingMismatch);
    }
    let generation = decoder.u64()?;
    let high_watermark = decoder.u64()?;
    if generation == 0 {
        return Err(ExchangeIndexError::Corrupt(
            "persisted snapshot generation is zero",
        ));
    }
    let chain_count = decoder.bounded_count(MAX_INDEXED_CHAIN_BLOCKS, "indexed chain")?;
    let watch_count = decoder.bounded_count(MAX_WATCH_DESTINATIONS, "watch destination")?;
    let deposit_count = decoder.bounded_count(MAX_ACTIVE_DEPOSITS, "active deposit")?;
    let event_count = decoder.bounded_count(MAX_DEPOSIT_EVENTS, "deposit event")?;
    let mut indexed_chain = Vec::with_capacity(chain_count);
    for _ in 0..chain_count {
        indexed_chain.push(decoder.array()?);
    }
    let mut watches = BTreeMap::new();
    for _ in 0..watch_count {
        let label = decoder.label()?;
        let watch = RegisteredDestination {
            destination: decoder.array()?,
            registered_at_height: decoder.u64()?,
            registered_at_tip: decoder.array()?,
        };
        validate_destination(watch.destination)
            .map_err(|_| ExchangeIndexError::Corrupt("registered destination is invalid"))?;
        if watches.insert(label, watch).is_some() {
            return Err(ExchangeIndexError::Corrupt(
                "snapshot contains a duplicate watch label",
            ));
        }
    }
    let mut active_deposits = BTreeMap::new();
    for _ in 0..deposit_count {
        let deposit = decoder.deposit()?;
        if active_deposits.insert(deposit.outpoint, deposit).is_some() {
            return Err(ExchangeIndexError::Corrupt(
                "snapshot contains a duplicate active deposit",
            ));
        }
    }
    let mut events = Vec::with_capacity(event_count);
    for _ in 0..event_count {
        let sequence = decoder.u64()?;
        let added_sequence = decoder.u64()?;
        let kind = match decoder.byte()? {
            1 => DepositEventKind::Added,
            2 => DepositEventKind::Removed,
            _ => {
                return Err(ExchangeIndexError::Corrupt(
                    "snapshot contains an invalid event kind",
                ));
            }
        };
        events.push(DepositEvent {
            sequence,
            added_sequence,
            kind,
            deposit: decoder.deposit()?,
        });
    }
    if !decoder.is_empty() {
        return Err(ExchangeIndexError::Corrupt(
            "snapshot contains trailing bytes",
        ));
    }
    let state = IndexState {
        generation,
        high_watermark,
        indexed_chain,
        watches,
        active_deposits,
        events,
    };
    validate_state(&state, genesis)?;
    Ok(state)
}

fn validate_state(state: &IndexState, genesis: [u8; 32]) -> Result<(), ExchangeIndexError> {
    if state.indexed_chain.is_empty()
        || state.indexed_chain.len() > MAX_INDEXED_CHAIN_BLOCKS
        || state.indexed_chain[0] != genesis
    {
        return Err(ExchangeIndexError::Corrupt(
            "indexed chain is empty, oversized, or has the wrong genesis",
        ));
    }
    if state.watches.len() > MAX_WATCH_DESTINATIONS
        || state.active_deposits.len() > MAX_ACTIVE_DEPOSITS
        || state.events.len() > MAX_DEPOSIT_EVENTS
    {
        return Err(ExchangeIndexError::Corrupt(
            "snapshot collection exceeds its capacity",
        ));
    }
    let mut destinations = BTreeSet::new();
    for (label, watch) in &state.watches {
        validate_label(label)
            .map_err(|_| ExchangeIndexError::Corrupt("snapshot watch label is invalid"))?;
        validate_destination(watch.destination)
            .map_err(|_| ExchangeIndexError::Corrupt("snapshot watch destination is invalid"))?;
        if !destinations.insert(watch.destination) {
            return Err(ExchangeIndexError::Corrupt(
                "snapshot contains a duplicate watch destination",
            ));
        }
    }
    let mut replayed = BTreeMap::new();
    for (position, event) in state.events.iter().enumerate() {
        let expected_sequence = u64::try_from(position)
            .ok()
            .and_then(|position| position.checked_add(1))
            .ok_or(ExchangeIndexError::Corrupt(
                "event sequence does not fit u64",
            ))?;
        if event.sequence != expected_sequence {
            return Err(ExchangeIndexError::Corrupt(
                "deposit event sequences are not contiguous",
            ));
        }
        if event.added_sequence != event.deposit.added_sequence
            || match event.kind {
                DepositEventKind::Added => event.added_sequence != event.sequence,
                DepositEventKind::Removed => {
                    event.added_sequence == 0 || event.added_sequence >= event.sequence
                }
            }
        {
            return Err(ExchangeIndexError::Corrupt(
                "deposit event added-sequence link is invalid",
            ));
        }
        validate_deposit(&event.deposit, &state.watches, &state.indexed_chain, false)?;
        match event.kind {
            DepositEventKind::Added => {
                if replayed
                    .insert(event.deposit.outpoint, event.deposit.clone())
                    .is_some()
                {
                    return Err(ExchangeIndexError::Corrupt(
                        "deposit event adds an already-active outpoint",
                    ));
                }
            }
            DepositEventKind::Removed => {
                if replayed.get(&event.deposit.outpoint) != Some(&event.deposit) {
                    return Err(ExchangeIndexError::Corrupt(
                        "deposit event removes a mismatched outpoint",
                    ));
                }
                replayed.remove(&event.deposit.outpoint);
            }
        }
    }
    if state.high_watermark != u64::try_from(state.events.len()).unwrap_or(u64::MAX) {
        return Err(ExchangeIndexError::Corrupt(
            "event high watermark does not match the event log",
        ));
    }
    for deposit in state.active_deposits.values() {
        validate_deposit(deposit, &state.watches, &state.indexed_chain, true)?;
    }
    if replayed != state.active_deposits {
        return Err(ExchangeIndexError::Corrupt(
            "event replay does not match active deposits",
        ));
    }
    Ok(())
}

fn validate_deposit(
    deposit: &ActiveDeposit,
    watches: &BTreeMap<String, RegisteredDestination>,
    indexed_chain: &[[u8; 32]],
    require_active_block: bool,
) -> Result<(), ExchangeIndexError> {
    let Some(watch) = watches.get(&deposit.label) else {
        return Err(ExchangeIndexError::Corrupt(
            "deposit refers to an unknown watch label",
        ));
    };
    if watch.destination != deposit.destination {
        return Err(ExchangeIndexError::Corrupt(
            "deposit destination does not match its watch label",
        ));
    }
    if deposit.added_sequence == 0 {
        return Err(ExchangeIndexError::Corrupt(
            "deposit has no originating added sequence",
        ));
    }
    if require_active_block {
        let height = usize::try_from(deposit.block_height).map_err(|_| {
            ExchangeIndexError::Corrupt("active deposit block height does not fit this platform")
        })?;
        if height == 0 || indexed_chain.get(height) != Some(&deposit.block_hash) {
            return Err(ExchangeIndexError::Corrupt(
                "active deposit does not belong to the indexed active chain",
            ));
        }
    }
    Ok(())
}

fn write_deposit(bytes: &mut Vec<u8>, deposit: &ActiveDeposit) -> Result<(), ExchangeIndexError> {
    bytes.extend_from_slice(&deposit.outpoint.txid);
    bytes.extend_from_slice(&deposit.outpoint.vout.to_le_bytes());
    write_label(bytes, &deposit.label)?;
    bytes.extend_from_slice(&deposit.destination);
    bytes.extend_from_slice(&deposit.amount_atoms.to_le_bytes());
    bytes.extend_from_slice(&deposit.spendable_height.to_le_bytes());
    bytes.push(u8::from(deposit.coinbase));
    bytes.extend_from_slice(&deposit.block_hash);
    bytes.extend_from_slice(&deposit.block_height.to_le_bytes());
    bytes.extend_from_slice(&deposit.block_timestamp.to_le_bytes());
    bytes.extend_from_slice(&deposit.added_sequence.to_le_bytes());
    Ok(())
}

fn write_label(bytes: &mut Vec<u8>, label: &str) -> Result<(), ExchangeIndexError> {
    validate_label(label)?;
    let length =
        u16::try_from(label.len()).map_err(|_| ExchangeIndexError::Capacity("watch label byte"))?;
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(label.as_bytes());
    Ok(())
}

fn write_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), ExchangeIndexError> {
    bytes.extend_from_slice(
        &u64::try_from(count)
            .map_err(|_| ExchangeIndexError::Capacity("snapshot collection"))?
            .to_le_bytes(),
    );
    Ok(())
}

fn snapshot_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(SNAPSHOT_INTEGRITY_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn marker_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(MARKER_INTEGRITY_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn persist_slot(path: &Path, bytes: &[u8]) -> Result<(), ExchangeIndexError> {
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).map_err(|source| {
        index_io(
            "generate exchange deposit index path",
            path,
            io::Error::other(source.to_string()),
        )
    })?;
    let parent = path.parent().ok_or_else(|| {
        index_io(
            "locate exchange deposit index directory",
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "index path has no parent"),
        )
    })?;
    let temporary = parent.join(format!(
        ".{EXCHANGE_INDEX_FILE_PREFIX}.tmp-{}",
        hex::encode(suffix)
    ));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|source| index_io("create exchange deposit index", &temporary, source))?;
        file.write_all(bytes)
            .map_err(|source| index_io("write exchange deposit index", &temporary, source))?;
        file.sync_all()
            .map_err(|source| index_io("sync exchange deposit index", &temporary, source))?;
        publish_snapshot(&temporary, path)
            .map_err(|source| index_io("publish exchange deposit index", path, source))?;
        sync_parent_directory(path)
            .map_err(|error| node_io_as_index(error, "sync exchange deposit index directory", path))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(windows)]
fn publish_snapshot(temporary: &Path, path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let temporary = temporary
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: both arguments are valid, NUL-terminated UTF-16 paths for the
    // duration of the call. The flags request atomic replacement plus a
    // write-through publication before success is reported.
    if unsafe {
        MoveFileExW(
            temporary.as_ptr(),
            path.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn publish_snapshot(temporary: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temporary, path)
}

fn node_io_as_index(error: NodeError, operation: &'static str, path: &Path) -> ExchangeIndexError {
    match error {
        NodeError::Io { source, .. } => index_io(operation, path, source),
        other => ExchangeIndexError::Node(other),
    }
}

fn snapshot_path(data_dir: &Path, slot: u8) -> PathBuf {
    data_dir.join(format!("{EXCHANGE_INDEX_FILE_PREFIX}.{slot}.bin"))
}

fn marker_path(data_dir: &Path) -> PathBuf {
    data_dir.join(EXCHANGE_INDEX_MARKER_FILE)
}

fn index_io(
    operation: &'static str,
    path: impl AsRef<Path>,
    source: io::Error,
) -> ExchangeIndexError {
    ExchangeIndexError::Io {
        operation,
        path: path.as_ref().to_path_buf(),
        source,
    }
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ExchangeIndexError> {
        if self.remaining.len() < length {
            return Err(ExchangeIndexError::Corrupt("snapshot is truncated"));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ExchangeIndexError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ExchangeIndexError::Corrupt("snapshot is truncated"))
    }

    fn byte(&mut self) -> Result<u8, ExchangeIndexError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ExchangeIndexError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ExchangeIndexError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ExchangeIndexError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn bounded_count(
        &mut self,
        maximum: usize,
        kind: &'static str,
    ) -> Result<usize, ExchangeIndexError> {
        usize::try_from(self.u64()?)
            .ok()
            .filter(|count| *count <= maximum)
            .ok_or(ExchangeIndexError::Corrupt(match kind {
                "indexed chain" => "indexed chain count exceeds its capacity",
                "watch destination" => "watch destination count exceeds its capacity",
                "active deposit" => "active deposit count exceeds its capacity",
                "deposit event" => "deposit event count exceeds its capacity",
                _ => "snapshot count exceeds its capacity",
            }))
    }

    fn label(&mut self) -> Result<String, ExchangeIndexError> {
        let length = usize::from(self.u16()?);
        let label = std::str::from_utf8(self.take(length)?)
            .map_err(|_| ExchangeIndexError::Corrupt("snapshot label is not UTF-8"))?;
        validate_label(label)
            .map_err(|_| ExchangeIndexError::Corrupt("snapshot label is invalid"))?;
        Ok(label.to_owned())
    }

    fn deposit(&mut self) -> Result<ActiveDeposit, ExchangeIndexError> {
        Ok(ActiveDeposit {
            outpoint: DepositOutPoint {
                txid: self.array()?,
                vout: self.u32()?,
            },
            label: self.label()?,
            destination: self.array()?,
            amount_atoms: self.u64()?,
            spendable_height: self.u64()?,
            coinbase: match self.byte()? {
                0 => false,
                1 => true,
                _ => {
                    return Err(ExchangeIndexError::Corrupt(
                        "snapshot deposit coinbase flag is invalid",
                    ));
                }
            },
            block_hash: self.array()?,
            block_height: self.u64()?,
            block_timestamp: self.u64()?,
            added_sequence: self.u64()?,
        })
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::{DEFAULT_MINING_ATTEMPTS, DEVNET_PROFILE, unix_time_seconds};
    use cmfd_consensus::Block;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cmfd-exchange-index-{label}-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn random_destination() -> [u8; 32] {
        k256::schnorr::SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng)
            .verifying_key()
            .to_bytes()
            .into()
    }

    fn test_deposit(
        marker: u8,
        label: &str,
        destination: [u8; 32],
        block_hash: [u8; 32],
        block_height: u64,
    ) -> ActiveDeposit {
        ActiveDeposit {
            outpoint: DepositOutPoint {
                txid: [marker; 32],
                vout: u32::from(marker),
            },
            label: label.to_owned(),
            destination,
            amount_atoms: u64::from(marker),
            spendable_height: block_height,
            coinbase: false,
            block_hash,
            block_height,
            block_timestamp: 1_700_000_000 + block_height,
            added_sequence: 0,
        }
    }

    fn mined_child_to(
        node: &Node,
        parent: [u8; 32],
        timestamp: u64,
        destination: [u8; 32],
    ) -> Block {
        let log_path = node.data_dir.join(BLOCK_LOG_FILE);
        let state = crate::rebuild_state_to(
            &node.log,
            &log_path,
            &node.index,
            node.params,
            &node.verifier,
            parent,
            None,
        )
        .unwrap();
        let height = state.next_height();
        let allocation = node.params.monetary_policy.allocation(height, 0).unwrap();
        let coinbase = crate::Coinbase::new(height, allocation, destination, node.params.rewards);
        let challenge = crate::BlockChallenge {
            network_id: node.params.network_id,
            previous_block: parent,
            transaction_root: crate::merkle_root(&[coinbase.commitment(node.params.network_id)]),
            height,
            timestamp,
            target: state.expected_target().unwrap(),
        };
        let proof = node
            .verifier
            .mine(&challenge, 0, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        Block {
            version: crate::BLOCK_VERSION,
            challenge,
            proof,
            coinbase,
            transactions: Vec::new(),
        }
    }

    #[test]
    fn registration_reads_only_blocks_that_touch_the_new_keys() {
        let path = test_dir("indexed-history");
        let now = unix_time_seconds().unwrap();
        let mut node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let paid = random_destination();
        let other = node.wallet_destination();
        for (offset, destination) in [other, paid, other, paid].into_iter().enumerate() {
            node.mine_once(destination, now + offset as u64, DEFAULT_MINING_ATTEMPTS)
                .unwrap();
        }
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();

        let fresh = random_destination();
        let plan = index
            .capture_registration_plan(&shared, [fresh].iter())
            .unwrap();
        assert!(plan.blocks.is_empty(), "a fresh key must not read history");
        let plan = index
            .capture_registration_plan(&shared, [paid, fresh].iter())
            .unwrap();
        assert_eq!(
            plan.blocks
                .iter()
                .map(|block| block.height)
                .collect::<Vec<_>>(),
            vec![2, 4]
        );

        index
            .register_watch_destinations(
                &shared,
                &[
                    WatchDestinationRegistration {
                        label: "paid".to_owned(),
                        destination: paid,
                    },
                    WatchDestinationRegistration {
                        label: "fresh".to_owned(),
                        destination: fresh,
                    },
                ],
            )
            .unwrap();
        let page = index.get_deposit_events(0, 100).unwrap();
        assert_eq!(
            page.events
                .iter()
                .map(|event| (event.deposit.label.as_str(), event.deposit.block_height))
                .collect::<Vec<_>>(),
            vec![("paid", 2), ("paid", 4)]
        );
        drop(index);
        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn registration_scans_history_and_survives_reopen() {
        let path = test_dir("history");
        let now = unix_time_seconds().unwrap();
        let mut node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let destination = node.wallet_destination();
        node.mine_once(destination, now, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        let shared = Arc::new(Mutex::new(node));

        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        let registered = index
            .register_watch_destination(&shared, "account-001", destination)
            .unwrap();
        assert_eq!(registered.watch.label, "account-001");
        let page = index.get_deposit_events(0, 10).unwrap();
        assert_eq!(page.high_watermark, 1);
        assert_eq!(page.events[0].kind, DepositEventKind::Added);
        assert_eq!(page.events[0].deposit.block_height, 1);

        drop(index);
        let reopened = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        assert_eq!(reopened.get_deposit_events(0, 10).unwrap(), page);
        drop(reopened);
        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn registration_is_exactly_idempotent_and_conflicts_fail_closed() {
        let path = test_dir("idempotency");
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let first = node.wallet_destination();
        let other = random_destination();
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();

        let first_response = index
            .register_watch_destination(&shared, "account-001", first)
            .unwrap();
        let retry_response = index
            .register_watch_destination(&shared, "account-001", first)
            .unwrap();
        assert_eq!(retry_response, first_response);
        assert!(matches!(
            index.register_watch_destination(&shared, "account-001", other),
            Err(ExchangeIndexError::LabelConflict)
        ));
        assert!(matches!(
            index.register_watch_destination(&shared, "account-002", first),
            Err(ExchangeIndexError::DestinationConflict)
        ));

        drop(index);
        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn batch_registration_is_atomic_ordered_and_retry_safe() {
        let path = test_dir("batch-registration");
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let first = node.wallet_destination();
        let second = random_destination();
        let third = random_destination();
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        let batch = vec![
            WatchDestinationRegistration {
                label: "account-001".to_owned(),
                destination: first,
            },
            WatchDestinationRegistration {
                label: "account-002".to_owned(),
                destination: second,
            },
        ];

        let registered = index.register_watch_destinations(&shared, &batch).unwrap();
        assert_eq!(registered.watches.len(), 2);
        assert_eq!(registered.watches[0].label, "account-001");
        assert_eq!(registered.watches[1].label, "account-002");
        assert_eq!(index.status().watch_destination_count, 2);
        assert_eq!(
            index.register_watch_destinations(&shared, &batch).unwrap(),
            registered
        );

        let conflicting = vec![
            WatchDestinationRegistration {
                label: "account-003".to_owned(),
                destination: third,
            },
            WatchDestinationRegistration {
                label: "account-001".to_owned(),
                destination: second,
            },
        ];
        assert!(matches!(
            index.register_watch_destinations(&shared, &conflicting),
            Err(ExchangeIndexError::LabelConflict)
        ));
        assert!(
            index
                .get_watch_destination("account-003")
                .unwrap()
                .is_none()
        );
        assert_eq!(index.status().watch_destination_count, 2);

        drop(index);
        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn batch_registration_rejects_ambiguous_or_unbounded_input() {
        let path = test_dir("batch-validation");
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let destination = node.wallet_destination();
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();

        assert!(matches!(
            index.register_watch_destinations(&shared, &[]),
            Err(ExchangeIndexError::InvalidRegistrationBatch)
        ));
        let duplicate_label = vec![
            WatchDestinationRegistration {
                label: "account-001".to_owned(),
                destination,
            },
            WatchDestinationRegistration {
                label: "account-001".to_owned(),
                destination: random_destination(),
            },
        ];
        assert!(matches!(
            index.register_watch_destinations(&shared, &duplicate_label),
            Err(ExchangeIndexError::DuplicateBatchLabel)
        ));
        let duplicate_destination = vec![
            WatchDestinationRegistration {
                label: "account-001".to_owned(),
                destination,
            },
            WatchDestinationRegistration {
                label: "account-002".to_owned(),
                destination,
            },
        ];
        assert!(matches!(
            index.register_watch_destinations(&shared, &duplicate_destination),
            Err(ExchangeIndexError::DuplicateBatchDestination)
        ));
        assert_eq!(index.status().watch_destination_count, 0);

        drop(index);
        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn first_acknowledged_registration_has_two_durable_slots() {
        let path = test_dir("initial-redundancy");
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        index
            .register_watch_destination(&shared, "account-001", random_destination())
            .unwrap();

        assert_eq!(index.state.generation, 2);
        assert!(snapshot_path(&path, 0).is_file());
        assert!(snapshot_path(&path, 1).is_file());
        assert!(marker_path(&path).is_file());

        drop(index);
        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn interrupted_initial_publication_is_healed_before_readiness() {
        let path = test_dir("heal-initial");
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let shared = Arc::new(Mutex::new(node));
        let destination = random_destination();
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        index
            .register_watch_destination(&shared, "account-001", destination)
            .unwrap();
        drop(index);

        fs::remove_file(snapshot_path(&path, 0)).unwrap();
        fs::remove_file(marker_path(&path)).unwrap();
        let healed = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        assert_eq!(healed.state.generation, 2);
        assert!(snapshot_path(&path, 0).is_file());
        assert!(snapshot_path(&path, 1).is_file());
        assert!(marker_path(&path).is_file());
        assert_eq!(
            healed
                .get_watch_destination("account-001")
                .unwrap()
                .unwrap()
                .destination,
            destination
        );

        drop(healed);
        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn initialized_marker_makes_complete_snapshot_loss_fail_closed() {
        let path = test_dir("missing-both-slots");
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        index
            .register_watch_destination(&shared, "account-001", random_destination())
            .unwrap();
        drop(index);

        fs::remove_file(snapshot_path(&path, 0)).unwrap();
        fs::remove_file(snapshot_path(&path, 1)).unwrap();
        assert!(marker_path(&path).is_file());
        assert!(matches!(
            ExchangeDepositIndex::open_and_sync(&shared),
            Err(ExchangeIndexError::Corrupt(
                "initialized exchange deposit snapshots are missing"
            ))
        ));

        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn snapshot_generation_must_match_its_slot() {
        let path = test_dir("slot-parity");
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        index
            .register_watch_destination(&shared, "account-001", random_destination())
            .unwrap();
        drop(index);

        let zero_path = snapshot_path(&path, 0);
        let one_path = snapshot_path(&path, 1);
        let zero = fs::read(&zero_path).unwrap();
        let one = fs::read(&one_path).unwrap();
        fs::write(&zero_path, one).unwrap();
        fs::write(&one_path, zero).unwrap();
        assert!(matches!(
            ExchangeDepositIndex::open_and_sync(&shared),
            Err(ExchangeIndexError::Corrupt(
                "snapshot generation does not match its slot"
            ))
        ));

        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn adjacent_slots_must_form_one_append_only_history() {
        let path = test_dir("slot-history");
        fs::create_dir_all(&path).unwrap();
        let network_id = [3_u8; 32];
        let consensus_fingerprint = [4_u8; 32];
        let genesis = [5_u8; 32];
        let first_destination = random_destination();
        let second_destination = random_destination();
        let older = IndexState {
            generation: 2,
            high_watermark: 0,
            indexed_chain: vec![genesis],
            watches: BTreeMap::from([(
                "account-001".to_owned(),
                RegisteredDestination {
                    destination: first_destination,
                    registered_at_height: 0,
                    registered_at_tip: genesis,
                },
            )]),
            active_deposits: BTreeMap::new(),
            events: Vec::new(),
        };
        let mut newer = older.clone();
        newer.generation = 3;
        newer.watches.clear();
        newer.watches.insert(
            "account-002".to_owned(),
            RegisteredDestination {
                destination: second_destination,
                registered_at_height: 0,
                registered_at_tip: genesis,
            },
        );
        persist_slot(
            &snapshot_path(&path, 0),
            &encode_snapshot(&older, network_id, consensus_fingerprint).unwrap(),
        )
        .unwrap();
        persist_slot(
            &snapshot_path(&path, 1),
            &encode_snapshot(&newer, network_id, consensus_fingerprint).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            load_state(&path, network_id, consensus_fingerprint, genesis),
            Err(ExchangeIndexError::Corrupt(
                "snapshot slots do not form one append-only history"
            ))
        ));

        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn missing_slot_after_initialization_cannot_roll_back_acknowledged_state() {
        let path = test_dir("missing-slot");
        let now = unix_time_seconds().unwrap();
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let destination = node.wallet_destination();
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        index
            .register_watch_destination(&shared, "account-001", destination)
            .unwrap();
        {
            let mut node = shared.lock().unwrap();
            node.mine_once(destination, now, DEFAULT_MINING_ATTEMPTS)
                .unwrap();
        }
        index.synchronize(&shared).unwrap();
        assert_eq!(index.state.generation, 3);
        drop(index);

        fs::remove_file(snapshot_path(&path, 1)).unwrap();
        assert!(matches!(
            ExchangeDepositIndex::open_and_sync(&shared),
            Err(ExchangeIndexError::Corrupt(
                "snapshot redundancy is missing after initialization"
            ))
        ));

        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn reorg_removals_reverse_original_add_order_and_link_added_sequence() {
        let genesis = [1_u8; 32];
        let common = [2_u8; 32];
        let orphaned = [3_u8; 32];
        let replacement = [4_u8; 32];
        let destination = random_destination();
        let mut state = IndexState {
            generation: 0,
            high_watermark: 0,
            indexed_chain: vec![genesis, common, orphaned],
            watches: BTreeMap::from([(
                "account-001".to_owned(),
                RegisteredDestination {
                    destination,
                    registered_at_height: 0,
                    registered_at_tip: genesis,
                },
            )]),
            active_deposits: BTreeMap::new(),
            events: Vec::new(),
        };
        append_added_deposit(
            &mut state,
            test_deposit(1, "account-001", destination, orphaned, 2),
        )
        .unwrap();
        append_added_deposit(
            &mut state,
            test_deposit(2, "account-001", destination, orphaned, 2),
        )
        .unwrap();

        reconcile_state(
            &mut state,
            &[genesis, common, replacement],
            vec![test_deposit(3, "account-001", destination, replacement, 2)],
        )
        .unwrap();

        assert_eq!(state.events.len(), 5);
        assert_eq!(state.events[2].kind, DepositEventKind::Removed);
        assert_eq!(state.events[2].added_sequence, 2);
        assert_eq!(state.events[3].kind, DepositEventKind::Removed);
        assert_eq!(state.events[3].added_sequence, 1);
        assert_eq!(state.events[4].kind, DepositEventKind::Added);
        assert_eq!(state.events[4].added_sequence, 5);
        assert_eq!(state.active_deposits.len(), 1);
        validate_state(&state, genesis).unwrap();
    }

    #[test]
    fn node_reorg_emits_removals_then_replacements_and_restart_does_not_duplicate() {
        let path = test_dir("node-reorg");
        let watched = random_destination();
        let other = random_destination();
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let genesis = node.params.genesis_hash;
        let t1 = DEVNET_PROFILE.virtual_genesis_timestamp + 60;
        let t2 = t1 + 60;
        let t3 = t2 + 60;
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        index
            .register_watch_destination(&shared, "account-001", watched)
            .unwrap();

        let (a1, a2) = {
            let mut node = shared.lock().unwrap();
            let a1 = mined_child_to(&node, genesis, t1, watched);
            node.submit_block(a1.clone(), t1).unwrap();
            let a2 = mined_child_to(&node, a1.block_id(), t2, watched);
            node.submit_block(a2.clone(), t2).unwrap();
            (a1, a2)
        };
        index.synchronize(&shared).unwrap();
        assert_eq!(index.get_deposit_events(0, 10).unwrap().high_watermark, 2);

        let b2 = {
            let mut node = shared.lock().unwrap();
            let b1 = mined_child_to(&node, genesis, t1, other);
            node.submit_block(b1.clone(), t1).unwrap();
            let b2 = mined_child_to(&node, b1.block_id(), t2, watched);
            node.submit_block(b2.clone(), t2).unwrap();
            b2
        };
        index.synchronize(&shared).unwrap();
        assert_eq!(index.get_deposit_events(0, 10).unwrap().high_watermark, 2);

        let b3 = {
            let mut node = shared.lock().unwrap();
            let b3 = mined_child_to(&node, b2.block_id(), t3, watched);
            node.submit_block(b3.clone(), t3).unwrap();
            b3
        };
        index.synchronize(&shared).unwrap();
        let page = index.get_deposit_events(0, 10).unwrap();
        assert_eq!(page.high_watermark, 6);
        assert_eq!(
            page.events
                .iter()
                .map(|event| (event.kind, event.added_sequence, event.deposit.block_hash))
                .collect::<Vec<_>>(),
            vec![
                (DepositEventKind::Added, 1, a1.block_id()),
                (DepositEventKind::Added, 2, a2.block_id()),
                (DepositEventKind::Removed, 2, a2.block_id()),
                (DepositEventKind::Removed, 1, a1.block_id()),
                (DepositEventKind::Added, 5, b2.block_id()),
                (DepositEventKind::Added, 6, b3.block_id()),
            ]
        );
        assert_eq!(page.indexed_tip, b3.block_id());

        drop(index);
        drop(shared);
        let reopened_node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let reopened_shared = Arc::new(Mutex::new(reopened_node));
        let reopened_index = ExchangeDepositIndex::open_and_sync(&reopened_shared).unwrap();
        assert_eq!(reopened_index.get_deposit_events(0, 10).unwrap(), page);

        drop(reopened_index);
        drop(reopened_shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn synchronize_catches_up_in_bounded_persisted_passes() {
        let path = test_dir("bounded-catch-up");
        let watched = random_destination();
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        index
            .register_watch_destination(&shared, "account-001", watched)
            .unwrap();
        let generation = index.state.generation;
        // Nobody polls while the chain grows well past one pass.
        let behind = 2 * MAX_BLOCKS_PER_SYNCHRONIZE + 5;
        let now = unix_time_seconds().unwrap();
        {
            let mut node = shared.lock().unwrap();
            for offset in 0..behind as u64 {
                node.mine_once(watched, now + offset, DEFAULT_MINING_ATTEMPTS)
                    .unwrap();
            }
        }
        let pass = MAX_BLOCKS_PER_SYNCHRONIZE as u64;

        // Each call indexes at most one pass and persists it before returning.
        let first = index.synchronize(&shared).unwrap();
        assert_eq!(first.indexed_tip_height, pass);
        assert_eq!(first.high_watermark, pass);
        assert_eq!(index.state.generation, generation + 1);
        let second = index.synchronize(&shared).unwrap();
        assert_eq!(second.indexed_tip_height, 2 * pass);
        assert_eq!(index.state.generation, generation + 2);
        let third = index.synchronize(&shared).unwrap();
        assert_eq!(third.indexed_tip_height, behind as u64);
        assert_eq!(third.high_watermark, behind as u64);
        assert_eq!(index.state.generation, generation + 3);
        // Caught up: a further call reads nothing and persists nothing.
        assert_eq!(
            index.synchronize(&shared).unwrap().indexed_tip_height,
            behind as u64
        );
        assert_eq!(index.state.generation, generation + 3);
        let page = index.get_deposit_events(0, MAX_DEPOSIT_EVENT_PAGE).unwrap();
        assert_eq!(
            page.events
                .iter()
                .map(|event| event.deposit.block_height)
                .collect::<Vec<_>>(),
            (1..=behind as u64).collect::<Vec<_>>()
        );

        drop(index);
        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn recheck_accepts_blocks_appended_behind_the_plan_but_not_a_reorganization() {
        let path = test_dir("recheck-prefix");
        let watched = random_destination();
        let other = random_destination();
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let genesis = node.params.genesis_hash;
        let t1 = DEVNET_PROFILE.virtual_genesis_timestamp + 60;
        let t2 = t1 + 60;
        let t3 = t2 + 60;
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        index
            .register_watch_destination(&shared, "account-001", watched)
            .unwrap();
        let a1 = {
            let mut node = shared.lock().unwrap();
            let a1 = mined_child_to(&node, genesis, t1, watched);
            node.submit_block(a1.clone(), t1).unwrap();
            a1
        };

        // Plan the read of a1, then let the chain grow behind it.
        let plan = index.capture_incremental_plan(&shared).unwrap();
        assert_eq!(plan.active_chain, vec![genesis, a1.block_id()]);
        {
            let mut node = shared.lock().unwrap();
            let a2 = mined_child_to(&node, a1.block_id(), t2, other);
            node.submit_block(a2, t2).unwrap();
        }
        index.recheck_shared_plan(&shared, &plan).unwrap();

        // A reorganization that replaces a planned block invalidates the plan.
        {
            let mut node = shared.lock().unwrap();
            let b1 = mined_child_to(&node, genesis, t1, other);
            node.submit_block(b1.clone(), t1).unwrap();
            let b2 = mined_child_to(&node, b1.block_id(), t2, other);
            node.submit_block(b2.clone(), t2).unwrap();
            let b3 = mined_child_to(&node, b2.block_id(), t3, other);
            node.submit_block(b3, t3).unwrap();
        }
        assert!(matches!(
            index.recheck_shared_plan(&shared, &plan),
            Err(ExchangeIndexError::ChainChanged)
        ));
        // The next synchronize follows the reorganization normally.
        assert_eq!(index.synchronize(&shared).unwrap().indexed_tip_height, 3);

        drop(index);
        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn event_pages_are_stable_exclusive_and_bounded_by_the_high_watermark() {
        let genesis = [1_u8; 32];
        let block = [2_u8; 32];
        let destination = random_destination();
        let mut state = IndexState {
            generation: 0,
            high_watermark: 0,
            indexed_chain: vec![genesis, block],
            watches: BTreeMap::from([(
                "account-001".to_owned(),
                RegisteredDestination {
                    destination,
                    registered_at_height: 0,
                    registered_at_tip: genesis,
                },
            )]),
            active_deposits: BTreeMap::new(),
            events: Vec::new(),
        };
        for marker in 1..=3 {
            append_added_deposit(
                &mut state,
                test_deposit(marker, "account-001", destination, block, 1),
            )
            .unwrap();
        }
        let index = ExchangeDepositIndex {
            transaction_lookup: Default::default(),
            data_dir: PathBuf::new(),
            network_id: [3_u8; 32],
            consensus_fingerprint: [4_u8; 32],
            genesis,
            state,
            faulted: false,
        };

        let first = index.get_deposit_events(0, 1).unwrap();
        assert_eq!(first, index.get_deposit_events(0, 1).unwrap());
        assert_eq!(first.events[0].sequence, 1);
        assert_eq!(first.next_cursor, 1);
        assert_eq!(first.high_watermark, 3);
        assert!(first.has_more);
        let final_page = index.get_deposit_events(1, 10).unwrap();
        assert_eq!(
            final_page
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(final_page.next_cursor, 3);
        assert!(!final_page.has_more);
        assert!(matches!(
            index.get_deposit_events(4, 1),
            Err(ExchangeIndexError::InvalidCursor)
        ));
    }

    #[test]
    fn synchronization_never_indexes_mempool_outputs() {
        let path = test_dir("no-mempool");
        let now = unix_time_seconds().unwrap();
        let recipient = random_destination();
        let mut node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let miner = node.wallet_destination();
        for offset in 0..100_u64 {
            node.mine_once(miner, now + offset, DEFAULT_MINING_ATTEMPTS)
                .unwrap();
        }
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        index
            .register_watch_destination(&shared, "account-001", recipient)
            .unwrap();
        let txid = {
            let mut node = shared.lock().unwrap();
            let (transaction, _) = node.prepare_dev_wallet_payment(recipient, 1, 1).unwrap();
            let txid = transaction.txid();
            node.submit_transaction(transaction).unwrap();
            txid
        };

        index.synchronize(&shared).unwrap();
        assert_eq!(index.get_deposit_events(0, 10).unwrap().high_watermark, 0);

        {
            let mut node = shared.lock().unwrap();
            node.mine_once(miner, now + 100, DEFAULT_MINING_ATTEMPTS)
                .unwrap();
        }
        index.synchronize(&shared).unwrap();
        let page = index.get_deposit_events(0, 10).unwrap();
        assert_eq!(page.high_watermark, 1);
        assert_eq!(page.events[0].deposit.outpoint.txid, txid);
        assert!(!page.events[0].deposit.coinbase);

        drop(index);
        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn persisted_state_is_bound_to_network_and_consensus_fingerprint() {
        let path = test_dir("binding");
        let node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let network_id = node.params.network_id;
        let consensus_fingerprint = node.fingerprint;
        let genesis = node.params.genesis_hash;
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        index
            .register_watch_destination(&shared, "account-001", random_destination())
            .unwrap();
        drop(index);

        assert!(matches!(
            load_state(&path, [9_u8; 32], consensus_fingerprint, genesis),
            Err(ExchangeIndexError::BindingMismatch)
        ));
        assert!(matches!(
            load_state(&path, network_id, [8_u8; 32], genesis),
            Err(ExchangeIndexError::BindingMismatch)
        ));

        drop(shared);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn any_corrupt_committed_slot_fails_closed() {
        let path = test_dir("corruption");
        let now = unix_time_seconds().unwrap();
        let mut node = Node::open_with_profile(&path, DEVNET_PROFILE).unwrap();
        let destination = node.wallet_destination();
        node.mine_once(destination, now, DEFAULT_MINING_ATTEMPTS)
            .unwrap();
        let shared = Arc::new(Mutex::new(node));
        let mut index = ExchangeDepositIndex::open_and_sync(&shared).unwrap();
        index
            .register_watch_destination(&shared, "account-001", destination)
            .unwrap();
        drop(index);

        let slot = snapshot_path(&path, 0);
        let mut bytes = fs::read(&slot).unwrap();
        bytes[16] ^= 1;
        fs::write(&slot, bytes).unwrap();
        assert!(matches!(
            ExchangeDepositIndex::open_and_sync(&shared),
            Err(ExchangeIndexError::Corrupt(_))
        ));

        drop(shared);
        let _ = fs::remove_dir_all(path);
    }
}
