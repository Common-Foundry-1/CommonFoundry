//! Crash-safe, idempotent withdrawal journaling for exchange integrations.
//!
//! Every new request advances through a reserved unsigned Intent, an unsigned
//! Prepared phase pinned by the exchange, and a signed Released phase. Signing
//! occurs only after the external Prepared anchor matches, and the exact signed
//! frame is durably Released before it can be returned or broadcast.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use blake3::Hasher;
use cmfd_consensus::{
    InputWitness, MAX_TRANSACTION_BYTES, MAX_TRANSACTION_INPUTS, OutPoint, OutputLock,
    TRANSACTION_VERSION, Transaction, TxInput, TxOutput, decode_transaction, encode_transaction,
};
use k256::schnorr::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    ExchangeWithdrawalSecurityConfig, Node, NodeError, WalletPaymentPlan,
    signed_wallet_payment_size, sync_parent_directory,
};

pub(crate) const EXCHANGE_WITHDRAWAL_FILE_PREFIX: &str = "exchange-withdrawals";
const EXCHANGE_WITHDRAWAL_MARKER_FILE: &str = "exchange-withdrawals.initialized";
pub(crate) const MAX_WITHDRAWAL_RECORDS: usize = 65_536;
pub(crate) const MAX_WITHDRAWAL_REQUEST_ID_BYTES: usize = 128;
const MAX_WITHDRAWAL_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const SNAPSHOT_MAGIC: [u8; 8] = *b"CMFDEXW\0";
const MARKER_MAGIC: [u8; 8] = *b"CMFDEXN\0";
const LEGACY_SNAPSHOT_VERSION: u32 = 1;
const SNAPSHOT_VERSION: u32 = 2;
const DIGEST_BYTES: usize = 32;
const SNAPSHOT_AUTH_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-JOURNAL/AUTH/V2";
const MARKER_AUTH_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-MARKER/AUTH/V2";
const COMMITMENT_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-COMMITMENT/V2";
const KEY_ID_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-KEY-ID/V2";
const MAX_COMMITMENTS: usize = MAX_WITHDRAWAL_RECORDS * 3 + 2;

#[derive(Debug, Error)]
pub(crate) enum ExchangeWithdrawalError {
    #[error("exchange withdrawal journal I/O failed during {operation}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("exchange withdrawal journal is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("exchange withdrawal journal belongs to another network or consensus fingerprint")]
    BindingMismatch,
    #[error("exchange withdrawal journal belongs to another wallet key")]
    WalletBindingMismatch,
    #[error("exchange withdrawal journal is faulted and requires a node restart")]
    Faulted,
    #[error("authenticated exchange withdrawal journal security is required")]
    SecurityRequired,
    #[error("exchange withdrawal journal key must be an owner-only regular 32-byte file")]
    InvalidJournalKey,
    #[error("exchange withdrawal journal key permissions must be 0600 or stricter")]
    #[cfg_attr(not(unix), allow(dead_code))]
    InsecureJournalKeyPermissions,
    #[error("exchange withdrawal anchor must be outside the node data directory")]
    AnchorInsideDataDirectory,
    #[error("exchange withdrawal external anchor is invalid")]
    InvalidAnchor,
    #[error("exchange withdrawal external anchor does not match journal history")]
    AnchorMismatch,
    #[error("exchange withdrawal journal v1 requires an explicit offline migration")]
    LegacyV1Unsupported,
    #[error("withdrawal request identifier is invalid")]
    InvalidRequestId,
    #[error("withdrawal destination is not a valid key destination")]
    InvalidDestination,
    #[error("withdrawal amount must be nonzero")]
    InvalidAmount,
    #[error("withdrawal amount arithmetic overflow")]
    AmountOverflow,
    #[error("withdrawal request identifier was already used for different request fields")]
    RequestConflict,
    #[error("withdrawal has not been prepared")]
    NotPrepared,
    #[error("withdrawal prepared anchor does not match the durable prepared phase")]
    PreparedAnchorMismatch,
    #[error("another withdrawal is pending and must be released before preparing a new request")]
    PreparedWithdrawalPending,
    #[error("withdrawal journal capacity was reached: {0}")]
    Capacity(&'static str),
    #[error(transparent)]
    Node(#[from] NodeError),
}

impl ExchangeWithdrawalError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "exchange_withdrawal_io",
            Self::Corrupt(_) => "exchange_withdrawal_corrupt",
            Self::BindingMismatch => "exchange_withdrawal_binding_mismatch",
            Self::WalletBindingMismatch => "exchange_withdrawal_wallet_mismatch",
            Self::Faulted => "exchange_withdrawal_faulted",
            Self::SecurityRequired => "exchange_withdrawal_security_required",
            Self::InvalidJournalKey => "invalid_exchange_withdrawal_journal_key",
            Self::InsecureJournalKeyPermissions => {
                "insecure_exchange_withdrawal_journal_key_permissions"
            }
            Self::AnchorInsideDataDirectory => "exchange_withdrawal_anchor_inside_data_dir",
            Self::InvalidAnchor => "invalid_exchange_withdrawal_anchor",
            Self::AnchorMismatch => "exchange_withdrawal_anchor_mismatch",
            Self::LegacyV1Unsupported => "exchange_withdrawal_v1_migration_required",
            Self::InvalidRequestId => "invalid_withdrawal_request_id",
            Self::InvalidDestination => "invalid_withdrawal_destination",
            Self::InvalidAmount => "invalid_withdrawal_amount",
            Self::AmountOverflow => "withdrawal_amount_overflow",
            Self::RequestConflict => "withdrawal_request_conflict",
            Self::NotPrepared => "withdrawal_not_prepared",
            Self::PreparedAnchorMismatch => "withdrawal_prepared_anchor_mismatch",
            Self::PreparedWithdrawalPending => "withdrawal_prepared_pending",
            Self::Capacity(_) => "exchange_withdrawal_capacity",
            Self::Node(error) => error.client_error().code,
        }
    }

    pub(crate) fn retryable(&self) -> bool {
        match self {
            Self::Node(error) => error.client_error().retryable,
            _ => false,
        }
    }

    pub(crate) fn client_message(&self) -> String {
        match self {
            Self::Io { .. } => {
                "exchange withdrawal storage failed; inspect the node logs".to_owned()
            }
            Self::Corrupt(_) => {
                "exchange withdrawal journal is corrupt; restore it before restarting".to_owned()
            }
            Self::BindingMismatch => {
                "exchange withdrawal network or consensus binding does not match".to_owned()
            }
            Self::WalletBindingMismatch => {
                "exchange withdrawal journal was created by another wallet key".to_owned()
            }
            Self::Faulted => {
                "exchange withdrawal journal is faulted; restart before retrying".to_owned()
            }
            Self::SecurityRequired => {
                "authenticated exchange withdrawal journal key and anchor configuration are required"
                    .to_owned()
            }
            Self::InvalidJournalKey => {
                "exchange withdrawal journal key must be a regular 32-byte file".to_owned()
            }
            Self::InsecureJournalKeyPermissions => {
                "exchange withdrawal journal key permissions are not owner-only".to_owned()
            }
            Self::AnchorInsideDataDirectory => {
                "exchange withdrawal anchor must be outside the node data directory".to_owned()
            }
            Self::InvalidAnchor => {
                "exchange withdrawal external anchor is invalid; inspect the anchor store"
                    .to_owned()
            }
            Self::AnchorMismatch => {
                "exchange withdrawal journal was rolled back or diverged from its external anchor"
                    .to_owned()
            }
            Self::LegacyV1Unsupported => {
                "exchange withdrawal journal v1 requires explicit offline migration".to_owned()
            }
            Self::InvalidRequestId => format!(
                "request_id must contain 1 to {MAX_WITHDRAWAL_REQUEST_ID_BYTES} visible ASCII bytes"
            ),
            Self::InvalidDestination => {
                "destination must be a valid 32-byte Schnorr public key".to_owned()
            }
            Self::InvalidAmount => "amount_atoms must be nonzero".to_owned(),
            Self::AmountOverflow => "withdrawal amount plus fee overflows u64".to_owned(),
            Self::RequestConflict => {
                "request_id is already bound to different withdrawal fields".to_owned()
            }
            Self::NotPrepared => "withdrawal must be prepared before release".to_owned(),
            Self::PreparedAnchorMismatch => {
                "prepared anchor does not authorize this withdrawal release".to_owned()
            }
            Self::PreparedWithdrawalPending => {
                "release the currently pending withdrawal before preparing another".to_owned()
            }
            Self::Capacity(kind) => format!("exchange withdrawal {kind} capacity was reached"),
            Self::Node(error) => error.client_error().message,
        }
    }
}

/// Loaded independently from the wallet and HTTP authentication material.
/// The secret is retained only because every journal transition must be
/// authenticated before it can become externally anchored.
pub(crate) struct LoadedWithdrawalSecurity {
    key: Zeroizing<[u8; 32]>,
    key_id: [u8; 32],
    anchor_path: PathBuf,
}

impl std::fmt::Debug for LoadedWithdrawalSecurity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoadedWithdrawalSecurity")
            .field("key", &"<redacted>")
            .field("key_id", &hex::encode(self.key_id))
            .field("anchor_path", &self.anchor_path)
            .finish()
    }
}

impl Clone for LoadedWithdrawalSecurity {
    fn clone(&self) -> Self {
        Self {
            key: Zeroizing::new(*self.key),
            key_id: self.key_id,
            anchor_path: self.anchor_path.clone(),
        }
    }
}

impl LoadedWithdrawalSecurity {
    pub(crate) fn load(
        config: &ExchangeWithdrawalSecurityConfig,
        data_dir: &Path,
    ) -> Result<Self, ExchangeWithdrawalError> {
        let key_path = external_path(config.journal_key_file(), data_dir, true)?;
        let anchor_path = external_path(config.anchor_file(), data_dir, false)?;
        let mut file = open_security_file(&key_path)
            .map_err(|source| withdrawal_io("open withdrawal journal key", &key_path, source))?;
        validate_secret_file(&file, &key_path)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(33));
        Read::by_ref(&mut file)
            .take(33)
            .read_to_end(&mut bytes)
            .map_err(|source| withdrawal_io("read withdrawal journal key", &key_path, source))?;
        if bytes.len() != 32 {
            return Err(ExchangeWithdrawalError::InvalidJournalKey);
        }
        let mut key = Zeroizing::new([0_u8; 32]);
        key.copy_from_slice(&bytes);
        if *key == [0; 32] {
            return Err(ExchangeWithdrawalError::InvalidJournalKey);
        }
        let key_id = keyed_digest(&key, KEY_ID_DOMAIN, b"journal-key-id");
        Ok(Self {
            key,
            key_id,
            anchor_path,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WithdrawalRequest {
    pub request_id: String,
    pub destination: [u8; 32],
    pub amount_atoms: u64,
    pub fee_atoms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WithdrawalStatus {
    Intent,
    Prepared,
    BroadcastPending,
    InMempool,
    Confirmed,
    Conflicted,
}

impl WithdrawalStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Prepared => "prepared",
            Self::BroadcastPending => "broadcast_pending",
            Self::InMempool => "in_mempool",
            Self::Confirmed => "confirmed",
            Self::Conflicted => "conflicted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WithdrawalPhase {
    Intent,
    Prepared,
    Released,
}

impl WithdrawalPhase {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Prepared => "prepared",
            Self::Released => "released",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WithdrawalJournalAnchor {
    pub key_id: [u8; 32],
    pub journal_instance_id: [u8; 32],
    pub generation: u64,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WithdrawalJournalInfo {
    pub current_anchor: WithdrawalJournalAnchor,
    pub external_anchor: Option<WithdrawalJournalAnchor>,
    pub relationship: WithdrawalAnchorRelationship,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WithdrawalAnchorRelationship {
    Bootstrap,
    Current,
    Descendant,
}

impl WithdrawalAnchorRelationship {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Current => "current",
            Self::Descendant => "descendant",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WithdrawalReservedInput {
    pub outpoint: OutPoint,
    pub value_atoms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WithdrawalView {
    pub journal_key_id: [u8; 32],
    pub journal_instance_id: [u8; 32],
    pub journal_generation: u64,
    pub journal_commitment: [u8; 32],
    pub phase: WithdrawalPhase,
    pub prepared_anchor: Option<WithdrawalJournalAnchor>,
    pub request_digest: [u8; 32],
    pub request_id: String,
    pub destination: [u8; 32],
    pub amount_atoms: u64,
    pub fee_atoms: u64,
    pub change_atoms: u64,
    pub reserved_inputs: Vec<WithdrawalReservedInput>,
    pub signing_digest: [u8; 32],
    pub txid: Option<[u8; 32]>,
    pub transaction_bytes: Option<Vec<u8>>,
    pub status: WithdrawalStatus,
    pub confirmations: Option<u64>,
}

/// Read-only, fully authenticated v2 source material for the explicit v3
/// migration planner. This type intentionally contains no v3 policy, keyring,
/// time, or approval decisions; those authorities must be supplied and
/// verified independently by the migration command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedV2MigrationExport {
    pub source_anchor: WithdrawalJournalAnchor,
    pub exact_snapshot_bytes: Vec<u8>,
    pub wallet_destination: [u8; 32],
    pub released_records: Vec<ValidatedV2ReleasedRecordExport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedV2ReleasedRecordExport {
    pub request: WithdrawalRequest,
    pub request_digest: [u8; 32],
    pub change_atoms: u64,
    pub output_spendable_height: u64,
    pub signing_digest: [u8; 32],
    pub reserved_inputs: Vec<WithdrawalReservedInput>,
    pub prepared_generation: u64,
    pub txid: [u8; 32],
    pub exact_transaction_bytes: Vec<u8>,
    pub source_record_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedInput {
    outpoint: OutPoint,
    value_atoms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PersistedPlan {
    change_atoms: u64,
    output_spendable_height: u64,
    signing_digest: [u8; 32],
    inputs: Vec<PlannedInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SignedWithdrawal {
    txid: [u8; 32],
    transaction_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WithdrawalRecord {
    request: WithdrawalRequest,
    plan: PersistedPlan,
    signed: Option<SignedWithdrawal>,
    prepared_generation: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JournalState {
    generation: u64,
    journal_instance_id: [u8; 32],
    commitments: Vec<[u8; 32]>,
    records: BTreeMap<String, WithdrawalRecord>,
}

pub(crate) struct ExchangeWithdrawalJournal {
    data_dir: PathBuf,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
    wallet_destination: [u8; 32],
    security: LoadedWithdrawalSecurity,
    state: JournalState,
    bootstrap_anchor_missing: bool,
    faulted: bool,
}

impl ExchangeWithdrawalJournal {
    /// Authenticates and exports the exact current v2 snapshot without writing
    /// journal files, reconciling transactions, signing, or broadcasting.
    /// Migration is refused unless both durable slots and the marker are
    /// healthy, the external anchor exactly pins current state, and every
    /// record is already Released.
    pub(crate) fn export_validated_v2_for_v3_migration(
        node: &Node,
    ) -> Result<ValidatedV2MigrationExport, ExchangeWithdrawalError> {
        let binding = NodeBinding::from_node(node)?;
        let loaded = load_state(&binding)?.ok_or(ExchangeWithdrawalError::Corrupt(
            "v2 migration requires an initialized withdrawal journal",
        ))?;
        if loaded.needs_redundancy || loaded.needs_marker || loaded.bootstrap_anchor_missing {
            return Err(ExchangeWithdrawalError::Corrupt(
                "v2 migration requires two healthy slots, a marker, and an external anchor",
            ));
        }
        let security = binding
            .security
            .as_ref()
            .ok_or(ExchangeWithdrawalError::SecurityRequired)?;
        let source_anchor = anchor_for_state(&loaded.state, security);
        let exact_snapshot_bytes = encode_snapshot(
            &loaded.state,
            binding.network_id,
            binding.consensus_fingerprint,
            binding.genesis,
            binding.wallet_destination,
            security,
        )?;
        export_validated_v2_state_for_v3_migration(
            &binding,
            loaded.state,
            exact_snapshot_bytes,
            source_anchor,
        )
    }

    /// Reconstructs the migration export from the immutable exact snapshot
    /// created by the planner. This recovery path is used only after a v3 slot
    /// proves that cutover already started and the live v2 two-slot loader can
    /// no longer choose a state. The copied bytes must still authenticate under
    /// the configured v2 journal key and reproduce the independently pinned
    /// source anchor from the confirmed migration plan.
    pub(crate) fn export_exact_v2_for_v3_migration_resume(
        node: &Node,
        exact_snapshot_bytes: &[u8],
        expected_source_anchor: WithdrawalJournalAnchor,
    ) -> Result<ValidatedV2MigrationExport, ExchangeWithdrawalError> {
        let binding = NodeBinding::from_node(node)?;
        let state = decode_authenticated_exact_snapshot(exact_snapshot_bytes, &binding)?;
        export_validated_v2_state_for_v3_migration(
            &binding,
            state,
            exact_snapshot_bytes.to_vec(),
            expected_source_anchor,
        )
    }

    /// Loads and authenticates the journal, restores every reservation, then
    /// reconciles only transactions whose Released phase was already durable.
    /// Intent and Prepared records are deliberately inert during startup.
    pub(crate) fn open_and_reconcile(
        shared: &Arc<Mutex<Node>>,
    ) -> Result<Self, ExchangeWithdrawalError> {
        let binding = node_binding(shared)?;
        if binding.security.is_none() {
            return Err(ExchangeWithdrawalError::SecurityRequired);
        }
        let loaded = match load_state(&binding)? {
            Some(loaded) => loaded,
            None => enroll_empty_journal(&binding)?,
        };
        let (state, needs_redundancy, needs_marker, bootstrap_anchor_missing) = (
            loaded.state,
            loaded.needs_redundancy,
            loaded.needs_marker,
            loaded.bootstrap_anchor_missing,
        );
        let mut journal = Self::from_binding(binding, state, bootstrap_anchor_missing);
        if needs_redundancy {
            journal.persist_candidate(journal.state.clone())?;
        }
        if needs_marker {
            journal.persist_marker()?;
        }
        journal.install_reservations(shared)?;
        journal.reconcile_released(shared)?;
        Ok(journal)
    }

    /// Startup-only reservation recovery. This path performs no journal writes,
    /// signing, or broadcast and must run even when exchange RPC is disabled.
    pub(crate) fn install_persisted_reservations(
        node: &mut Node,
    ) -> Result<(), ExchangeWithdrawalError> {
        let binding = NodeBinding::from_node(node)?;
        let reservations = load_state(&binding)?
            .map(|loaded| reservation_map(&loaded.state))
            .transpose()?
            .unwrap_or_default();
        node.set_exchange_withdrawal_reservations(reservations);
        Ok(())
    }

    /// Creates and anchors an Intent when necessary, then durably marks the
    /// unsigned request Prepared. It never signs or submits a transaction.
    pub(crate) fn prepare(
        &mut self,
        shared: &Arc<Mutex<Node>>,
        request: &WithdrawalRequest,
    ) -> Result<WithdrawalView, ExchangeWithdrawalError> {
        self.require_healthy()?;
        validate_request(request)?;
        if let Some(existing) = self.state.records.get(&request.request_id)
            && existing.request != *request
        {
            return Err(ExchangeWithdrawalError::RequestConflict);
        }

        let is_new = !self.state.records.contains_key(&request.request_id);
        if is_new {
            if self
                .state
                .records
                .values()
                .any(|record| withdrawal_phase(record) != WithdrawalPhase::Released)
            {
                return Err(ExchangeWithdrawalError::PreparedWithdrawalPending);
            }
            let external = self.load_and_validate_external_anchor()?;
            if external != current_anchor(self) {
                return Err(ExchangeWithdrawalError::AnchorMismatch);
            }
            if self.state.records.len() >= MAX_WITHDRAWAL_RECORDS {
                return Err(ExchangeWithdrawalError::Capacity("record"));
            }
        } else if self
            .state
            .records
            .get(&request.request_id)
            .is_some_and(|record| withdrawal_phase(record) == WithdrawalPhase::Intent)
        {
            self.load_and_validate_external_anchor()?;
        }

        let mut node = lock_node(shared)?;
        self.check_node_binding(&node)?;
        if is_new {
            let plan = node.plan_dev_wallet_payment(
                request.destination,
                request.amount_atoms,
                request.fee_atoms,
            )?;
            let signed_transaction_bytes =
                signed_wallet_payment_size(&plan.transaction, self.wallet_destination)?;
            let persisted_plan = persisted_plan_from_wallet_plan(
                &plan,
                request,
                self.network_id,
                self.wallet_destination,
            )?;
            let record = WithdrawalRecord {
                request: request.clone(),
                plan: persisted_plan,
                signed: None,
                prepared_generation: None,
            };
            let mut candidate = self.state.clone();
            candidate.records.insert(request.request_id.clone(), record);
            ensure_signed_snapshot_capacity(
                &candidate,
                self.network_id,
                self.consensus_fingerprint,
                self.genesis,
                self.wallet_destination,
                signed_transaction_bytes,
                &self.security,
            )?;
            // Freeze every candidate input in the live node before the first
            // durable publication attempt. A first-slot success followed by a
            // second-slot or marker failure is an ambiguous commit until
            // restart; retaining these reservations prevents an ordinary
            // wallet path from spending an Intent that recovery may load.
            let candidate_reservations = reservation_map(&candidate)?;
            node.set_exchange_withdrawal_reservations(candidate_reservations);
            self.persist_candidate(candidate)?;
        }

        self.prepare_if_needed(&request.request_id)?;
        self.observe_locked(&mut node, &request.request_id)
    }

    /// Pure observation: no signing, journal write, or broadcast occurs.
    pub(crate) fn get(
        &self,
        shared: &Arc<Mutex<Node>>,
        request_id: &str,
    ) -> Result<Option<WithdrawalView>, ExchangeWithdrawalError> {
        self.require_healthy()?;
        validate_request_id(request_id)?;
        if !self.state.records.contains_key(request_id) {
            return Ok(None);
        }
        let mut node = lock_node(shared)?;
        self.check_node_binding(&node)?;
        self.observe_locked(&mut node, request_id).map(Some)
    }

    /// Requires the exchange-owned anchor to authorize this exact Prepared
    /// phase, then persists Released before attempting the first broadcast.
    /// The node never writes the external anchor.
    pub(crate) fn release(
        &mut self,
        shared: &Arc<Mutex<Node>>,
        request_id: &str,
    ) -> Result<WithdrawalView, ExchangeWithdrawalError> {
        self.require_healthy()?;
        validate_request_id(request_id)?;
        let record = self
            .state
            .records
            .get(request_id)
            .ok_or(ExchangeWithdrawalError::NotPrepared)?;
        let expected = prepared_anchor_for(self, record)?;
        let already_released = withdrawal_phase(record) == WithdrawalPhase::Released;
        let external = self.load_and_validate_external_anchor()?;
        let current = current_anchor(self);
        if expected != external && (!already_released || external != current) {
            return Err(ExchangeWithdrawalError::PreparedAnchorMismatch);
        }
        let mut node = lock_node(shared)?;
        self.check_node_binding(&node)?;
        if !already_released {
            let wallet_plan =
                wallet_plan_from_record(record, self.network_id, self.wallet_destination)?;
            let transaction = node.sign_dev_wallet_payment(&wallet_plan)?;
            validate_signed_transaction(
                record,
                &transaction,
                self.network_id,
                self.wallet_destination,
            )?;
            let transaction_bytes = encode_transaction(&transaction).map_err(NodeError::from)?;
            let signed = SignedWithdrawal {
                txid: transaction.txid(),
                transaction_bytes,
            };
            let mut candidate = self.state.clone();
            candidate
                .records
                .get_mut(request_id)
                .expect("record cloned from current journal")
                .signed = Some(signed);
            self.persist_candidate(candidate)?;
        }
        self.reconcile_released_locked(&mut node, request_id)
    }

    pub(crate) fn journal_info(&self) -> Result<WithdrawalJournalInfo, ExchangeWithdrawalError> {
        let current = current_anchor(self);
        match load_external_anchor(&self.security)? {
            Some(external) => {
                let relationship = anchor_relationship(&self.state, &self.security, external)?;
                Ok(WithdrawalJournalInfo {
                    current_anchor: current,
                    external_anchor: Some(external),
                    relationship,
                })
            }
            None if self.bootstrap_anchor_missing && self.state.records.is_empty() => {
                Ok(WithdrawalJournalInfo {
                    current_anchor: current,
                    external_anchor: None,
                    relationship: WithdrawalAnchorRelationship::Bootstrap,
                })
            }
            None => Err(ExchangeWithdrawalError::InvalidAnchor),
        }
    }

    /// Reconciles and may rebroadcast only records already durably Released.
    pub(crate) fn reconcile_released(
        &self,
        shared: &Arc<Mutex<Node>>,
    ) -> Result<Vec<WithdrawalView>, ExchangeWithdrawalError> {
        self.require_healthy()?;
        let mut node = lock_node(shared)?;
        self.check_node_binding(&node)?;
        let txids = self
            .state
            .records
            .values()
            .filter(|record| withdrawal_phase(record) == WithdrawalPhase::Released)
            .filter_map(|record| record.signed.as_ref().map(|signed| signed.txid))
            .collect::<HashSet<_>>();
        let confirmations = node.active_transaction_confirmations_for(&txids)?;
        let mut views = Vec::with_capacity(self.state.records.len());
        for request_id in self.state.records.keys() {
            let record = &self.state.records[request_id];
            views.push(if withdrawal_phase(record) == WithdrawalPhase::Released {
                self.reconcile_released_locked_with_confirmations(
                    &mut node,
                    request_id,
                    &confirmations,
                )?
            } else {
                self.observe_locked_with_confirmations(request_id, &confirmations)?
            });
        }
        Ok(views)
    }

    fn from_binding(
        binding: NodeBinding,
        state: JournalState,
        bootstrap_anchor_missing: bool,
    ) -> Self {
        let security = binding
            .security
            .expect("authenticated withdrawal journal requires loaded security");
        Self {
            data_dir: binding.data_dir,
            network_id: binding.network_id,
            consensus_fingerprint: binding.consensus_fingerprint,
            genesis: binding.genesis,
            wallet_destination: binding.wallet_destination,
            security,
            state,
            bootstrap_anchor_missing,
            faulted: false,
        }
    }

    fn prepare_if_needed(&mut self, request_id: &str) -> Result<(), ExchangeWithdrawalError> {
        let record = self
            .state
            .records
            .get(request_id)
            .ok_or(ExchangeWithdrawalError::Corrupt(
                "requested withdrawal record disappeared",
            ))?;
        if record.prepared_generation.is_some() {
            return Ok(());
        }
        let mut candidate = self.state.clone();
        let prepared_generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or(ExchangeWithdrawalError::Capacity("snapshot generation"))?;
        let prepared = candidate
            .records
            .get_mut(request_id)
            .expect("record cloned from current journal");
        prepared.prepared_generation = Some(prepared_generation);
        self.persist_candidate(candidate)
    }

    fn observe_locked(
        &self,
        node: &mut Node,
        request_id: &str,
    ) -> Result<WithdrawalView, ExchangeWithdrawalError> {
        let record = self
            .state
            .records
            .get(request_id)
            .ok_or(ExchangeWithdrawalError::Corrupt(
                "requested withdrawal record disappeared",
            ))?;
        let Some(signed) = &record.signed else {
            let status = if record.prepared_generation.is_some() {
                WithdrawalStatus::Prepared
            } else {
                WithdrawalStatus::Intent
            };
            return Ok(view_for(self, record, status, None));
        };
        let txids = HashSet::from([signed.txid]);
        let confirmations = node.active_transaction_confirmations_for(&txids)?;
        if let Some(confirmations) = confirmations.get(&signed.txid).copied() {
            return Ok(view_for(
                self,
                record,
                WithdrawalStatus::Confirmed,
                Some(confirmations),
            ));
        }
        if node.mempool_contains_transaction(signed.txid) {
            return Ok(view_for(self, record, WithdrawalStatus::InMempool, None));
        }
        self.observe_locked_with_confirmations(request_id, &confirmations)
    }

    fn observe_locked_with_confirmations(
        &self,
        request_id: &str,
        confirmations_by_txid: &HashMap<[u8; 32], u64>,
    ) -> Result<WithdrawalView, ExchangeWithdrawalError> {
        let record = self
            .state
            .records
            .get(request_id)
            .ok_or(ExchangeWithdrawalError::Corrupt(
                "requested withdrawal record disappeared",
            ))?;
        let Some(signed) = &record.signed else {
            let status = if record.prepared_generation.is_some() {
                WithdrawalStatus::Prepared
            } else {
                WithdrawalStatus::Intent
            };
            return Ok(view_for(self, record, status, None));
        };
        if let Some(confirmations) = confirmations_by_txid.get(&signed.txid).copied() {
            return Ok(view_for(
                self,
                record,
                WithdrawalStatus::Confirmed,
                Some(confirmations),
            ));
        }
        Ok(view_for(
            self,
            record,
            WithdrawalStatus::BroadcastPending,
            None,
        ))
    }

    fn reconcile_released_locked(
        &self,
        node: &mut Node,
        request_id: &str,
    ) -> Result<WithdrawalView, ExchangeWithdrawalError> {
        let record = self
            .state
            .records
            .get(request_id)
            .ok_or(ExchangeWithdrawalError::Corrupt(
                "requested withdrawal record disappeared",
            ))?;
        if withdrawal_phase(record) != WithdrawalPhase::Released {
            return Err(ExchangeWithdrawalError::NotPrepared);
        }
        let signed = record
            .signed
            .as_ref()
            .ok_or(ExchangeWithdrawalError::Corrupt(
                "released withdrawal has no signed transaction",
            ))?;
        let txids = HashSet::from([signed.txid]);
        let confirmations = node.active_transaction_confirmations_for(&txids)?;
        self.reconcile_released_locked_with_confirmations(node, request_id, &confirmations)
    }

    fn reconcile_released_locked_with_confirmations(
        &self,
        node: &mut Node,
        request_id: &str,
        confirmations_by_txid: &HashMap<[u8; 32], u64>,
    ) -> Result<WithdrawalView, ExchangeWithdrawalError> {
        let record = self
            .state
            .records
            .get(request_id)
            .ok_or(ExchangeWithdrawalError::Corrupt(
                "requested withdrawal record disappeared",
            ))?;
        if withdrawal_phase(record) != WithdrawalPhase::Released {
            return Err(ExchangeWithdrawalError::Corrupt(
                "non-released withdrawal reached broadcast reconciliation",
            ));
        }
        let signed = record
            .signed
            .as_ref()
            .ok_or(ExchangeWithdrawalError::Corrupt(
                "released withdrawal has no signed transaction",
            ))?;
        if let Some(confirmations) = confirmations_by_txid.get(&signed.txid).copied() {
            return Ok(view_for(
                self,
                record,
                WithdrawalStatus::Confirmed,
                Some(confirmations),
            ));
        }
        if node.mempool_contains_transaction(signed.txid) {
            return Ok(view_for(self, record, WithdrawalStatus::InMempool, None));
        }
        let transaction = decode_signed_record(record, self.network_id, self.wallet_destination)?;
        let status = match node.submit_exchange_withdrawal_transaction(transaction) {
            Ok(_) | Err(NodeError::DuplicateMempoolTransaction(_)) => WithdrawalStatus::InMempool,
            Err(NodeError::MempoolTransactionLimit | NodeError::MempoolByteLimit) => {
                WithdrawalStatus::BroadcastPending
            }
            Err(NodeError::MempoolInputConflict(_) | NodeError::MempoolUnconfirmedInput(_)) => {
                WithdrawalStatus::Conflicted
            }
            Err(error) => return Err(ExchangeWithdrawalError::Node(error)),
        };
        Ok(view_for(self, record, status, None))
    }

    fn install_reservations(
        &self,
        shared: &Arc<Mutex<Node>>,
    ) -> Result<(), ExchangeWithdrawalError> {
        let reservations = reservation_map(&self.state)?;
        let mut node = lock_node(shared)?;
        self.check_node_binding(&node)?;
        node.set_exchange_withdrawal_reservations(reservations);
        Ok(())
    }

    fn check_node_binding(&self, node: &Node) -> Result<(), ExchangeWithdrawalError> {
        if node.data_dir != self.data_dir
            || node.params.network_id != self.network_id
            || node.fingerprint != self.consensus_fingerprint
            || node.params.genesis_hash != self.genesis
        {
            return Err(ExchangeWithdrawalError::BindingMismatch);
        }
        if node.wallet_destination() != self.wallet_destination {
            return Err(ExchangeWithdrawalError::WalletBindingMismatch);
        }
        if node.storage_faulted {
            return Err(ExchangeWithdrawalError::Node(NodeError::StorageFaulted));
        }
        Ok(())
    }

    fn load_and_validate_external_anchor(
        &self,
    ) -> Result<WithdrawalJournalAnchor, ExchangeWithdrawalError> {
        let anchor =
            load_external_anchor(&self.security)?.ok_or(ExchangeWithdrawalError::InvalidAnchor)?;
        anchor_relationship(&self.state, &self.security, anchor)?;
        Ok(anchor)
    }

    fn persist_candidate(
        &mut self,
        mut candidate: JournalState,
    ) -> Result<(), ExchangeWithdrawalError> {
        let result = (|| {
            let first_generation = self
                .state
                .generation
                .checked_add(1)
                .ok_or(ExchangeWithdrawalError::Capacity("snapshot generation"))?;
            candidate.generation = first_generation;
            if !history_extends(&self.state, &candidate)? {
                return Err(ExchangeWithdrawalError::Corrupt(
                    "candidate does not extend withdrawal history",
                ));
            }
            if candidate.commitments != self.state.commitments {
                return Err(ExchangeWithdrawalError::Corrupt(
                    "candidate commitment history changed",
                ));
            }
            append_state_commitment(
                &mut candidate,
                self.network_id,
                self.consensus_fingerprint,
                self.genesis,
                self.wallet_destination,
                &self.security,
            )?;
            validate_state(
                &candidate,
                self.network_id,
                self.consensus_fingerprint,
                self.genesis,
                self.wallet_destination,
                &self.security,
            )?;
            let bytes = encode_snapshot(
                &candidate,
                self.network_id,
                self.consensus_fingerprint,
                self.genesis,
                self.wallet_destination,
                &self.security,
            )?;
            persist_slot(
                &snapshot_path(&self.data_dir, (candidate.generation & 1) as u8),
                &bytes,
            )?;
            Ok(())
        })();
        if let Err(error) = result {
            self.faulted = true;
            return Err(error);
        }
        self.state = candidate;
        Ok(())
    }

    fn persist_marker(&mut self) -> Result<(), ExchangeWithdrawalError> {
        let binding = NodeBinding {
            data_dir: self.data_dir.clone(),
            network_id: self.network_id,
            consensus_fingerprint: self.consensus_fingerprint,
            genesis: self.genesis,
            wallet_destination: self.wallet_destination,
            security: Some(self.security.clone()),
        };
        if let Err(error) = persist_marker(&binding, self.state.journal_instance_id) {
            self.faulted = true;
            return Err(error);
        }
        Ok(())
    }

    fn require_healthy(&self) -> Result<(), ExchangeWithdrawalError> {
        if self.faulted {
            Err(ExchangeWithdrawalError::Faulted)
        } else {
            Ok(())
        }
    }
}

fn decode_authenticated_exact_snapshot(
    exact_snapshot_bytes: &[u8],
    binding: &NodeBinding,
) -> Result<JournalState, ExchangeWithdrawalError> {
    if exact_snapshot_bytes.len() < minimum_snapshot_bytes()
        || exact_snapshot_bytes.len() > MAX_WITHDRAWAL_SNAPSHOT_BYTES
    {
        return Err(ExchangeWithdrawalError::Corrupt(
            "validated v2 migration snapshot size is invalid",
        ));
    }
    let security = binding
        .security
        .as_ref()
        .ok_or(ExchangeWithdrawalError::SecurityRequired)?;
    let payload_length = exact_snapshot_bytes.len() - DIGEST_BYTES;
    let (payload, authentication_tag) = exact_snapshot_bytes.split_at(payload_length);
    if snapshot_authentication_tag(&security.key, payload) != authentication_tag {
        return Err(ExchangeWithdrawalError::Corrupt(
            "validated v2 migration snapshot authentication failed",
        ));
    }
    decode_snapshot(payload, binding)
}

fn export_validated_v2_state_for_v3_migration(
    binding: &NodeBinding,
    state: JournalState,
    exact_snapshot_bytes: Vec<u8>,
    expected_source_anchor: WithdrawalJournalAnchor,
) -> Result<ValidatedV2MigrationExport, ExchangeWithdrawalError> {
    let security = binding
        .security
        .as_ref()
        .ok_or(ExchangeWithdrawalError::SecurityRequired)?;
    let source_anchor = anchor_for_state(&state, security);
    let external = load_external_anchor(security)?.ok_or(ExchangeWithdrawalError::InvalidAnchor)?;
    if source_anchor != expected_source_anchor || external != expected_source_anchor {
        return Err(ExchangeWithdrawalError::AnchorMismatch);
    }
    if encode_snapshot(
        &state,
        binding.network_id,
        binding.consensus_fingerprint,
        binding.genesis,
        binding.wallet_destination,
        security,
    )? != exact_snapshot_bytes
    {
        return Err(ExchangeWithdrawalError::Corrupt(
            "validated v2 migration snapshot is not canonical",
        ));
    }
    if state
        .records
        .values()
        .any(|record| withdrawal_phase(record) != WithdrawalPhase::Released)
    {
        return Err(ExchangeWithdrawalError::PreparedWithdrawalPending);
    }

    let mut released_records = Vec::with_capacity(state.records.len());
    for record in state.records.values() {
        let transaction =
            decode_signed_record(record, binding.network_id, binding.wallet_destination)?;
        let signed = record
            .signed
            .as_ref()
            .ok_or(ExchangeWithdrawalError::Corrupt(
                "released migration record has no signed transaction",
            ))?;
        let prepared_generation =
            record
                .prepared_generation
                .ok_or(ExchangeWithdrawalError::Corrupt(
                    "released migration record has no prepared generation",
                ))?;
        let record_request_digest = request_digest(
            &record.request,
            binding.network_id,
            binding.consensus_fingerprint,
            binding.genesis,
            binding.wallet_destination,
        );
        released_records.push(ValidatedV2ReleasedRecordExport {
            request: record.request.clone(),
            request_digest: record_request_digest,
            change_atoms: record.plan.change_atoms,
            output_spendable_height: record.plan.output_spendable_height,
            signing_digest: record.plan.signing_digest,
            reserved_inputs: record
                .plan
                .inputs
                .iter()
                .map(|input| WithdrawalReservedInput {
                    outpoint: input.outpoint,
                    value_atoms: input.value_atoms,
                })
                .collect(),
            prepared_generation,
            txid: transaction.txid(),
            exact_transaction_bytes: signed.transaction_bytes.clone(),
            source_record_digest: v2_migration_record_digest(record)?,
        });
    }
    Ok(ValidatedV2MigrationExport {
        source_anchor,
        exact_snapshot_bytes,
        wallet_destination: binding.wallet_destination,
        released_records,
    })
}

#[derive(Debug, Clone)]
struct NodeBinding {
    data_dir: PathBuf,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
    wallet_destination: [u8; 32],
    security: Option<LoadedWithdrawalSecurity>,
}

impl NodeBinding {
    fn from_node(node: &Node) -> Result<Self, ExchangeWithdrawalError> {
        if node.storage_faulted {
            return Err(ExchangeWithdrawalError::Node(NodeError::StorageFaulted));
        }
        Ok(Self {
            data_dir: node.data_dir.clone(),
            network_id: node.params.network_id,
            consensus_fingerprint: node.fingerprint,
            genesis: node.params.genesis_hash,
            wallet_destination: node.wallet_destination(),
            security: node.exchange_withdrawal_security.clone(),
        })
    }
}

fn node_binding(shared: &Arc<Mutex<Node>>) -> Result<NodeBinding, ExchangeWithdrawalError> {
    let node = lock_node(shared)?;
    NodeBinding::from_node(&node)
}

fn lock_node(shared: &Arc<Mutex<Node>>) -> Result<MutexGuard<'_, Node>, ExchangeWithdrawalError> {
    shared
        .lock()
        .map_err(|_| ExchangeWithdrawalError::Node(NodeError::SharedNodePoisoned))
}

fn validate_request(request: &WithdrawalRequest) -> Result<(), ExchangeWithdrawalError> {
    validate_request_id(&request.request_id)?;
    VerifyingKey::from_bytes(&request.destination)
        .map_err(|_| ExchangeWithdrawalError::InvalidDestination)?;
    if request.amount_atoms == 0 {
        return Err(ExchangeWithdrawalError::InvalidAmount);
    }
    request
        .amount_atoms
        .checked_add(request.fee_atoms)
        .ok_or(ExchangeWithdrawalError::AmountOverflow)?;
    Ok(())
}

fn validate_request_id(request_id: &str) -> Result<(), ExchangeWithdrawalError> {
    if request_id.is_empty()
        || request_id.len() > MAX_WITHDRAWAL_REQUEST_ID_BYTES
        || !request_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ExchangeWithdrawalError::InvalidRequestId);
    }
    Ok(())
}

fn persisted_plan_from_wallet_plan(
    plan: &WalletPaymentPlan,
    request: &WithdrawalRequest,
    network_id: [u8; 32],
    wallet_destination: [u8; 32],
) -> Result<PersistedPlan, ExchangeWithdrawalError> {
    if plan.recipient != request.destination
        || plan.amount_atoms != request.amount_atoms
        || plan.fee_burned_atoms != request.fee_atoms
        || plan.transaction.network_id != network_id
        || plan.transaction.version != TRANSACTION_VERSION
        || plan.transaction.inputs.len() != plan.selected_input_values.len()
    {
        return Err(ExchangeWithdrawalError::Corrupt(
            "node returned a mismatched withdrawal plan",
        ));
    }
    let inputs = plan
        .transaction
        .inputs
        .iter()
        .zip(&plan.selected_input_values)
        .map(|(input, value_atoms)| PlannedInput {
            outpoint: input.previous,
            value_atoms: *value_atoms,
        })
        .collect();
    let persisted = PersistedPlan {
        change_atoms: plan.change_atoms,
        output_spendable_height: plan.output_spendable_height,
        signing_digest: plan.transaction.signing_digest(),
        inputs,
    };
    let record = WithdrawalRecord {
        request: request.clone(),
        plan: persisted.clone(),
        signed: None,
        prepared_generation: None,
    };
    let reconstructed = wallet_plan_from_record(&record, network_id, wallet_destination)?;
    if reconstructed != *plan {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal plan cannot be reconstructed exactly",
        ));
    }
    Ok(persisted)
}

fn wallet_plan_from_record(
    record: &WithdrawalRecord,
    network_id: [u8; 32],
    wallet_destination: [u8; 32],
) -> Result<WalletPaymentPlan, ExchangeWithdrawalError> {
    validate_request(&record.request)
        .map_err(|_| ExchangeWithdrawalError::Corrupt("stored request is invalid"))?;
    if record.plan.inputs.is_empty() || record.plan.inputs.len() > MAX_TRANSACTION_INPUTS {
        return Err(ExchangeWithdrawalError::Corrupt(
            "stored withdrawal input count is invalid",
        ));
    }
    let mut seen = HashSet::with_capacity(record.plan.inputs.len());
    let mut selected_total = 0_u64;
    for input in &record.plan.inputs {
        if input.value_atoms == 0 || !seen.insert(input.outpoint) {
            return Err(ExchangeWithdrawalError::Corrupt(
                "stored withdrawal inputs are invalid",
            ));
        }
        selected_total = selected_total.checked_add(input.value_atoms).ok_or(
            ExchangeWithdrawalError::Corrupt("stored withdrawal input total overflows"),
        )?;
    }
    let required = record
        .request
        .amount_atoms
        .checked_add(record.request.fee_atoms)
        .and_then(|value| value.checked_add(record.plan.change_atoms))
        .ok_or(ExchangeWithdrawalError::Corrupt(
            "stored withdrawal totals overflow",
        ))?;
    if selected_total != required {
        return Err(ExchangeWithdrawalError::Corrupt(
            "stored withdrawal totals do not balance",
        ));
    }

    let mut outputs = vec![TxOutput {
        value: record.request.amount_atoms,
        lock: OutputLock::Key(record.request.destination),
        spendable_height: record.plan.output_spendable_height,
    }];
    if record.plan.change_atoms > 0 {
        outputs.push(TxOutput {
            value: record.plan.change_atoms,
            lock: OutputLock::Key(wallet_destination),
            spendable_height: record.plan.output_spendable_height,
        });
    }
    let transaction = Transaction {
        network_id,
        version: TRANSACTION_VERSION,
        inputs: record
            .plan
            .inputs
            .iter()
            .map(|input| TxInput {
                previous: input.outpoint,
                witness: InputWitness::Key {
                    public_key: wallet_destination,
                    signature: Vec::new(),
                },
            })
            .collect(),
        outputs,
    };
    if transaction.signing_digest() != record.plan.signing_digest {
        return Err(ExchangeWithdrawalError::Corrupt(
            "stored withdrawal signing digest does not match its plan",
        ));
    }
    Ok(WalletPaymentPlan {
        transaction,
        recipient: record.request.destination,
        amount_atoms: record.request.amount_atoms,
        fee_burned_atoms: record.request.fee_atoms,
        change_atoms: record.plan.change_atoms,
        selected_input_values: record
            .plan
            .inputs
            .iter()
            .map(|input| input.value_atoms)
            .collect(),
        output_spendable_height: record.plan.output_spendable_height,
    })
}

fn validate_signed_transaction(
    record: &WithdrawalRecord,
    transaction: &Transaction,
    network_id: [u8; 32],
    wallet_destination: [u8; 32],
) -> Result<(), ExchangeWithdrawalError> {
    let plan = wallet_plan_from_record(record, network_id, wallet_destination)?;
    if transaction.network_id != plan.transaction.network_id
        || transaction.version != plan.transaction.version
        || transaction.outputs != plan.transaction.outputs
        || transaction.inputs.len() != plan.transaction.inputs.len()
        || transaction
            .inputs
            .iter()
            .zip(&plan.transaction.inputs)
            .any(|(signed, unsigned)| signed.previous != unsigned.previous)
        || transaction.signing_digest() != record.plan.signing_digest
    {
        return Err(ExchangeWithdrawalError::Corrupt(
            "signed withdrawal does not match its durable intent",
        ));
    }
    let key = VerifyingKey::from_bytes(&wallet_destination)
        .map_err(|_| ExchangeWithdrawalError::Corrupt("stored wallet destination is invalid"))?;
    for input in &transaction.inputs {
        let InputWitness::Key {
            public_key,
            signature,
        } = &input.witness
        else {
            return Err(ExchangeWithdrawalError::Corrupt(
                "signed withdrawal contains a non-key witness",
            ));
        };
        if *public_key != wallet_destination {
            return Err(ExchangeWithdrawalError::Corrupt(
                "signed withdrawal uses another public key",
            ));
        }
        let signature = Signature::try_from(signature.as_slice()).map_err(|_| {
            ExchangeWithdrawalError::Corrupt("signed withdrawal signature is malformed")
        })?;
        key.verify(&record.plan.signing_digest, &signature)
            .map_err(|_| {
                ExchangeWithdrawalError::Corrupt("signed withdrawal signature is invalid")
            })?;
    }
    Ok(())
}

fn decode_signed_record(
    record: &WithdrawalRecord,
    network_id: [u8; 32],
    wallet_destination: [u8; 32],
) -> Result<Transaction, ExchangeWithdrawalError> {
    let signed = record
        .signed
        .as_ref()
        .ok_or(ExchangeWithdrawalError::Corrupt(
            "signed withdrawal phase has no transaction",
        ))?;
    let transaction = decode_transaction(&signed.transaction_bytes, network_id)
        .map_err(|_| ExchangeWithdrawalError::Corrupt("signed transaction frame is invalid"))?;
    let canonical = encode_transaction(&transaction)
        .map_err(|_| ExchangeWithdrawalError::Corrupt("signed transaction is not encodable"))?;
    if canonical != signed.transaction_bytes || transaction.txid() != signed.txid {
        return Err(ExchangeWithdrawalError::Corrupt(
            "signed transaction bytes or identifier are not canonical",
        ));
    }
    validate_signed_transaction(record, &transaction, network_id, wallet_destination)?;
    Ok(transaction)
}

fn reservation_map(
    state: &JournalState,
) -> Result<HashMap<OutPoint, [u8; 32]>, ExchangeWithdrawalError> {
    let mut reservations = HashMap::new();
    for record in state.records.values() {
        for input in &record.plan.inputs {
            if reservations
                .insert(input.outpoint, record.plan.signing_digest)
                .is_some()
            {
                return Err(ExchangeWithdrawalError::Corrupt(
                    "multiple withdrawals reserve the same input",
                ));
            }
        }
    }
    Ok(reservations)
}

fn view_for(
    journal: &ExchangeWithdrawalJournal,
    record: &WithdrawalRecord,
    status: WithdrawalStatus,
    confirmations: Option<u64>,
) -> WithdrawalView {
    let phase = withdrawal_phase(record);
    WithdrawalView {
        journal_key_id: journal.security.key_id,
        journal_instance_id: journal.state.journal_instance_id,
        journal_generation: journal.state.generation,
        journal_commitment: current_commitment(&journal.state),
        phase,
        prepared_anchor: prepared_anchor_for(journal, record).ok(),
        request_digest: request_digest(
            &record.request,
            journal.network_id,
            journal.consensus_fingerprint,
            journal.genesis,
            journal.wallet_destination,
        ),
        request_id: record.request.request_id.clone(),
        destination: record.request.destination,
        amount_atoms: record.request.amount_atoms,
        fee_atoms: record.request.fee_atoms,
        change_atoms: record.plan.change_atoms,
        reserved_inputs: record
            .plan
            .inputs
            .iter()
            .map(|input| WithdrawalReservedInput {
                outpoint: input.outpoint,
                value_atoms: input.value_atoms,
            })
            .collect(),
        signing_digest: record.plan.signing_digest,
        txid: record.signed.as_ref().map(|signed| signed.txid),
        transaction_bytes: record
            .signed
            .as_ref()
            .map(|signed| signed.transaction_bytes.clone()),
        status,
        confirmations,
    }
}

fn withdrawal_phase(record: &WithdrawalRecord) -> WithdrawalPhase {
    if record.signed.is_some() {
        WithdrawalPhase::Released
    } else if record.prepared_generation.is_some() {
        WithdrawalPhase::Prepared
    } else {
        WithdrawalPhase::Intent
    }
}

fn current_commitment(state: &JournalState) -> [u8; 32] {
    state.commitments.last().copied().unwrap_or([0; 32])
}

fn anchor_for_state(
    state: &JournalState,
    security: &LoadedWithdrawalSecurity,
) -> WithdrawalJournalAnchor {
    WithdrawalJournalAnchor {
        key_id: security.key_id,
        journal_instance_id: state.journal_instance_id,
        generation: state.generation,
        commitment: current_commitment(state),
    }
}

fn current_anchor(journal: &ExchangeWithdrawalJournal) -> WithdrawalJournalAnchor {
    anchor_for_state(&journal.state, &journal.security)
}

fn prepared_anchor_for(
    journal: &ExchangeWithdrawalJournal,
    record: &WithdrawalRecord,
) -> Result<WithdrawalJournalAnchor, ExchangeWithdrawalError> {
    let generation = record
        .prepared_generation
        .ok_or(ExchangeWithdrawalError::NotPrepared)?;
    let position = usize::try_from(generation.saturating_sub(1))
        .map_err(|_| ExchangeWithdrawalError::Corrupt("prepared generation is invalid"))?;
    let commitment = journal.state.commitments.get(position).copied().ok_or(
        ExchangeWithdrawalError::Corrupt("prepared generation has no authenticated commitment"),
    )?;
    Ok(WithdrawalJournalAnchor {
        key_id: journal.security.key_id,
        journal_instance_id: journal.state.journal_instance_id,
        generation,
        commitment,
    })
}

fn request_digest(
    request: &WithdrawalRequest,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
    wallet_destination: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key("CMFD/NODE/EXCHANGE-WITHDRAWAL-REQUEST/V1");
    hasher.update(&network_id);
    hasher.update(&consensus_fingerprint);
    hasher.update(&genesis);
    hasher.update(&wallet_destination);
    hasher.update(&(request.request_id.len() as u64).to_le_bytes());
    hasher.update(request.request_id.as_bytes());
    hasher.update(&request.destination);
    hasher.update(&request.amount_atoms.to_le_bytes());
    hasher.update(&request.fee_atoms.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn v2_migration_record_digest(
    record: &WithdrawalRecord,
) -> Result<[u8; 32], ExchangeWithdrawalError> {
    let mut records = BTreeMap::new();
    records.insert(record.request.request_id.clone(), record.clone());
    let mut canonical = Vec::new();
    write_records(&mut canonical, &records)?;
    let mut hasher = Hasher::new_derive_key("CMFD/NODE/EXCHANGE-WITHDRAWAL/V2-MIGRATION-RECORD/V1");
    hasher.update(&canonical);
    let digest = *hasher.finalize().as_bytes();
    if digest == [0; 32] {
        return Err(ExchangeWithdrawalError::Corrupt(
            "v2 migration record digest is zero",
        ));
    }
    Ok(digest)
}

fn random_identifier(operation: &'static str) -> Result<[u8; 32], ExchangeWithdrawalError> {
    let mut value = [0_u8; 32];
    getrandom::fill(&mut value).map_err(|source| {
        withdrawal_io(
            operation,
            Path::new(EXCHANGE_WITHDRAWAL_FILE_PREFIX),
            io::Error::other(source.to_string()),
        )
    })?;
    Ok(value)
}

fn history_extends(
    older: &JournalState,
    newer: &JournalState,
) -> Result<bool, ExchangeWithdrawalError> {
    if older.journal_instance_id != newer.journal_instance_id
        || older.records.len() > newer.records.len()
        || newer.records.len().saturating_sub(older.records.len()) > 1
        || !newer.commitments.starts_with(&older.commitments)
    {
        return Ok(false);
    }
    for (request_id, prior) in &older.records {
        let Some(next) = newer.records.get(request_id) else {
            return Ok(false);
        };
        if prior == next {
            continue;
        }
        if prior.request != next.request || prior.plan != next.plan {
            return Ok(false);
        }
        let valid_transition = match (withdrawal_phase(prior), withdrawal_phase(next)) {
            (WithdrawalPhase::Intent, WithdrawalPhase::Prepared) => {
                prior.signed.is_none()
                    && next.signed.is_none()
                    && next.prepared_generation == Some(newer.generation)
            }
            (WithdrawalPhase::Prepared, WithdrawalPhase::Released) => {
                prior.signed.is_none()
                    && next.signed.is_some()
                    && prior.prepared_generation == next.prepared_generation
            }
            _ => false,
        };
        if !valid_transition {
            return Ok(false);
        }
    }
    for (request_id, record) in &newer.records {
        if !older.records.contains_key(request_id)
            && (withdrawal_phase(record) != WithdrawalPhase::Intent
                || record.prepared_generation.is_some())
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_state(
    state: &JournalState,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
    wallet_destination: [u8; 32],
    security: &LoadedWithdrawalSecurity,
) -> Result<(), ExchangeWithdrawalError> {
    if state.generation == 0 || state.journal_instance_id == [0; 32] {
        return Err(ExchangeWithdrawalError::Corrupt(
            "persisted generation or journal identity is invalid",
        ));
    }
    if state.records.len() > MAX_WITHDRAWAL_RECORDS {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal record count exceeds its capacity",
        ));
    }
    if state.commitments.len() != usize::try_from(state.generation).unwrap_or(usize::MAX)
        || state.commitments.len() > MAX_COMMITMENTS
    {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal commitment history length is invalid",
        ));
    }
    if state
        .records
        .values()
        .filter(|record| withdrawal_phase(record) != WithdrawalPhase::Released)
        .count()
        > 1
    {
        return Err(ExchangeWithdrawalError::Corrupt(
            "multiple non-released withdrawals are present",
        ));
    }
    for (request_id, record) in &state.records {
        if request_id != &record.request.request_id {
            return Err(ExchangeWithdrawalError::Corrupt(
                "withdrawal record key does not match request_id",
            ));
        }
        let plan = wallet_plan_from_record(record, network_id, wallet_destination)?;
        if plan.transaction.signing_digest() != record.plan.signing_digest {
            return Err(ExchangeWithdrawalError::Corrupt(
                "withdrawal record signing digest is inconsistent",
            ));
        }
        if record.signed.is_some() {
            decode_signed_record(record, network_id, wallet_destination)?;
        }
        match withdrawal_phase(record) {
            WithdrawalPhase::Intent if record.prepared_generation.is_some() => {
                return Err(ExchangeWithdrawalError::Corrupt(
                    "intent has a prepared generation",
                ));
            }
            WithdrawalPhase::Intent => {}
            WithdrawalPhase::Prepared | WithdrawalPhase::Released => {
                let generation =
                    record
                        .prepared_generation
                        .ok_or(ExchangeWithdrawalError::Corrupt(
                            "prepared withdrawal has no prepared generation",
                        ))?;
                if generation == 0 || generation > state.generation {
                    return Err(ExchangeWithdrawalError::Corrupt(
                        "prepared withdrawal generation is invalid",
                    ));
                }
                if withdrawal_phase(record) == WithdrawalPhase::Prepared
                    && generation != state.generation
                {
                    return Err(ExchangeWithdrawalError::Corrupt(
                        "prepared withdrawal is not the current journal phase",
                    ));
                }
                if withdrawal_phase(record) == WithdrawalPhase::Released
                    && generation >= state.generation
                {
                    return Err(ExchangeWithdrawalError::Corrupt(
                        "released withdrawal does not descend from its prepared phase",
                    ));
                }
            }
        }
    }
    let expected = compute_state_commitment(
        state,
        network_id,
        consensus_fingerprint,
        genesis,
        wallet_destination,
        security,
    )?;
    if current_commitment(state) != expected {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal state commitment mismatch",
        ));
    }
    reservation_map(state)?;
    Ok(())
}

enum LoadedSlot {
    Missing,
    Valid(JournalState),
}

struct LoadedState {
    state: JournalState,
    needs_redundancy: bool,
    needs_marker: bool,
    bootstrap_anchor_missing: bool,
}

fn load_state(binding: &NodeBinding) -> Result<Option<LoadedState>, ExchangeWithdrawalError> {
    if binding.security.is_none() {
        if !journal_files_present(&binding.data_dir)? {
            return Ok(None);
        }
        if journal_has_legacy_v1_file(&binding.data_dir)? {
            return Err(ExchangeWithdrawalError::LegacyV1Unsupported);
        }
        return Err(ExchangeWithdrawalError::SecurityRequired);
    }
    let security = binding
        .security
        .as_ref()
        .ok_or(ExchangeWithdrawalError::SecurityRequired)?;
    let marker = load_marker(binding)?;
    let first = load_slot(&snapshot_path(&binding.data_dir, 0), 0, binding)?;
    let second = load_slot(&snapshot_path(&binding.data_dir, 1), 1, binding)?;
    match (first, second) {
        (LoadedSlot::Missing, LoadedSlot::Missing) => {
            if marker.is_some() {
                Err(ExchangeWithdrawalError::Corrupt(
                    "initialized withdrawal snapshots are missing",
                ))
            } else if load_external_anchor(security)?.is_some() {
                Err(ExchangeWithdrawalError::AnchorMismatch)
            } else {
                Ok(None)
            }
        }
        (LoadedSlot::Valid(state), LoadedSlot::Missing)
        | (LoadedSlot::Missing, LoadedSlot::Valid(state)) => {
            if marker.is_none()
                && state.generation == 1
                && state.records.is_empty()
                && load_external_anchor(security)?.is_none()
            {
                Ok(Some(LoadedState {
                    state,
                    needs_redundancy: true,
                    needs_marker: true,
                    bootstrap_anchor_missing: true,
                }))
            } else {
                Err(ExchangeWithdrawalError::Corrupt(
                    "withdrawal snapshot redundancy is missing after initialization",
                ))
            }
        }
        (LoadedSlot::Valid(first), LoadedSlot::Valid(second)) => {
            if first.generation.abs_diff(second.generation) != 1 {
                return Err(ExchangeWithdrawalError::Corrupt(
                    "withdrawal snapshot generations are inconsistent",
                ));
            }
            let (older, newer) = if first.generation < second.generation {
                (&first, &second)
            } else {
                (&second, &first)
            };
            if !history_extends(older, newer)? {
                return Err(ExchangeWithdrawalError::Corrupt(
                    "withdrawal snapshots do not form one append-only history",
                ));
            }
            if let Some(marker_instance_id) = marker
                && marker_instance_id != newer.journal_instance_id
            {
                return Err(ExchangeWithdrawalError::Corrupt(
                    "withdrawal marker and snapshots have different identities",
                ));
            }
            let external = load_external_anchor(security)?;
            let bootstrap_anchor_missing = match external {
                Some(external) => {
                    if marker.is_none() {
                        return Err(ExchangeWithdrawalError::Corrupt(
                            "withdrawal marker is missing after initialization",
                        ));
                    }
                    anchor_relationship(newer, security, external)?;
                    false
                }
                None if newer.records.is_empty() => true,
                None => return Err(ExchangeWithdrawalError::InvalidAnchor),
            };
            Ok(Some(LoadedState {
                state: if first.generation > second.generation {
                    first
                } else {
                    second
                },
                needs_redundancy: false,
                needs_marker: marker.is_none(),
                bootstrap_anchor_missing,
            }))
        }
    }
}

fn enroll_empty_journal(binding: &NodeBinding) -> Result<LoadedState, ExchangeWithdrawalError> {
    if journal_files_present(&binding.data_dir)? {
        return Err(ExchangeWithdrawalError::Corrupt(
            "fresh withdrawal enrollment found existing journal files",
        ));
    }
    let security = binding
        .security
        .as_ref()
        .ok_or(ExchangeWithdrawalError::SecurityRequired)?;
    if load_external_anchor(security)?.is_some() {
        return Err(ExchangeWithdrawalError::AnchorMismatch);
    }
    let mut state = JournalState {
        generation: 1,
        journal_instance_id: random_identifier("generate withdrawal journal identity")?,
        commitments: Vec::new(),
        records: BTreeMap::new(),
    };
    append_state_commitment(
        &mut state,
        binding.network_id,
        binding.consensus_fingerprint,
        binding.genesis,
        binding.wallet_destination,
        security,
    )?;
    let first = encode_snapshot(
        &state,
        binding.network_id,
        binding.consensus_fingerprint,
        binding.genesis,
        binding.wallet_destination,
        security,
    )?;
    persist_slot(&snapshot_path(&binding.data_dir, 1), &first)?;

    state.generation = 2;
    append_state_commitment(
        &mut state,
        binding.network_id,
        binding.consensus_fingerprint,
        binding.genesis,
        binding.wallet_destination,
        security,
    )?;
    let second = encode_snapshot(
        &state,
        binding.network_id,
        binding.consensus_fingerprint,
        binding.genesis,
        binding.wallet_destination,
        security,
    )?;
    persist_slot(&snapshot_path(&binding.data_dir, 0), &second)?;
    persist_marker(binding, state.journal_instance_id)?;
    Ok(LoadedState {
        state,
        needs_redundancy: false,
        needs_marker: false,
        bootstrap_anchor_missing: true,
    })
}

fn load_slot(
    path: &Path,
    expected_slot: u8,
    binding: &NodeBinding,
) -> Result<LoadedSlot, ExchangeWithdrawalError> {
    let mut file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(LoadedSlot::Missing);
        }
        Err(source) => return Err(withdrawal_io("open withdrawal snapshot", path, source)),
    };
    validate_durable_file(&file, path, "withdrawal snapshot")?;
    let length = usize::try_from(
        file.metadata()
            .map_err(|source| withdrawal_io("inspect withdrawal snapshot", path, source))?
            .len(),
    )
    .ok()
    .filter(|length| {
        *length >= minimum_snapshot_bytes() && *length <= MAX_WITHDRAWAL_SNAPSHOT_BYTES
    })
    .ok_or(ExchangeWithdrawalError::Corrupt(
        "withdrawal snapshot size is invalid",
    ))?;
    let mut bytes = vec![0_u8; length];
    file.read_exact(&mut bytes)
        .map_err(|source| withdrawal_io("read withdrawal snapshot", path, source))?;
    if bytes.get(8..12) == Some(&LEGACY_SNAPSHOT_VERSION.to_le_bytes()) {
        return Err(ExchangeWithdrawalError::LegacyV1Unsupported);
    }
    let security = binding
        .security
        .as_ref()
        .ok_or(ExchangeWithdrawalError::SecurityRequired)?;
    let (payload, expected_digest) = bytes.split_at(bytes.len() - DIGEST_BYTES);
    if snapshot_authentication_tag(&security.key, payload) != expected_digest {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal snapshot authentication failed",
        ));
    }
    let state = decode_snapshot(payload, binding)?;
    if state.generation & 1 != u64::from(expected_slot) {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal generation does not match its slot",
        ));
    }
    Ok(LoadedSlot::Valid(state))
}

fn minimum_snapshot_bytes() -> usize {
    8 + 4 + 32 * 6 + 8 + 8 + 32 + 8 + DIGEST_BYTES
}

fn load_marker(binding: &NodeBinding) -> Result<Option<[u8; 32]>, ExchangeWithdrawalError> {
    let path = marker_path(&binding.data_dir);
    let mut file = match OpenOptions::new().read(true).open(&path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(withdrawal_io("open withdrawal marker", &path, source)),
    };
    validate_durable_file(&file, &path, "withdrawal marker")?;
    const MARKER_PAYLOAD_BYTES: usize = 8 + 4 + 32 * 6;
    const MARKER_BYTES: usize = MARKER_PAYLOAD_BYTES + DIGEST_BYTES;
    if file
        .metadata()
        .map_err(|source| withdrawal_io("inspect withdrawal marker", &path, source))?
        .len()
        != MARKER_BYTES as u64
    {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal marker size is invalid",
        ));
    }
    let mut bytes = [0_u8; MARKER_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|source| withdrawal_io("read withdrawal marker", &path, source))?;
    if bytes.get(8..12) == Some(&LEGACY_SNAPSHOT_VERSION.to_le_bytes()) {
        return Err(ExchangeWithdrawalError::LegacyV1Unsupported);
    }
    let security = binding
        .security
        .as_ref()
        .ok_or(ExchangeWithdrawalError::SecurityRequired)?;
    let (payload, expected_digest) = bytes.split_at(MARKER_PAYLOAD_BYTES);
    if marker_authentication_tag(&security.key, payload) != expected_digest {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal marker authentication failed",
        ));
    }
    let mut decoder = Decoder::new(payload);
    if decoder.array::<8>()? != MARKER_MAGIC || decoder.u32()? != SNAPSHOT_VERSION {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal marker magic or version is unsupported",
        ));
    }
    if decoder.array::<32>()? != security.key_id {
        return Err(ExchangeWithdrawalError::InvalidJournalKey);
    }
    check_binding(&mut decoder, binding)?;
    let instance_id = decoder.array()?;
    if instance_id == [0; 32] || !decoder.is_empty() {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal marker identity or length is invalid",
        ));
    }
    Ok(Some(instance_id))
}

fn persist_marker(
    binding: &NodeBinding,
    instance_id: [u8; 32],
) -> Result<(), ExchangeWithdrawalError> {
    if instance_id == [0; 32] {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal journal identity is zero",
        ));
    }
    let security = binding
        .security
        .as_ref()
        .ok_or(ExchangeWithdrawalError::SecurityRequired)?;
    let mut bytes = Vec::with_capacity(8 + 4 + 32 * 6 + DIGEST_BYTES);
    bytes.extend_from_slice(&MARKER_MAGIC);
    bytes.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&security.key_id);
    write_binding(&mut bytes, binding);
    bytes.extend_from_slice(&instance_id);
    let digest = marker_authentication_tag(&security.key, &bytes);
    bytes.extend_from_slice(&digest);
    persist_slot(&marker_path(&binding.data_dir), &bytes)
}

fn encode_snapshot(
    state: &JournalState,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
    wallet_destination: [u8; 32],
    security: &LoadedWithdrawalSecurity,
) -> Result<Vec<u8>, ExchangeWithdrawalError> {
    validate_state(
        state,
        network_id,
        consensus_fingerprint,
        genesis,
        wallet_destination,
        security,
    )?;
    let binding = NodeBinding {
        data_dir: PathBuf::new(),
        network_id,
        consensus_fingerprint,
        genesis,
        wallet_destination,
        security: Some(security.clone()),
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&SNAPSHOT_MAGIC);
    bytes.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&security.key_id);
    write_binding(&mut bytes, &binding);
    bytes.extend_from_slice(&state.journal_instance_id);
    bytes.extend_from_slice(&state.generation.to_le_bytes());
    write_count(&mut bytes, state.commitments.len())?;
    for commitment in &state.commitments {
        bytes.extend_from_slice(commitment);
    }
    write_records(&mut bytes, &state.records)?;
    if bytes.len().saturating_add(DIGEST_BYTES) > MAX_WITHDRAWAL_SNAPSHOT_BYTES {
        return Err(ExchangeWithdrawalError::Capacity("snapshot byte"));
    }
    let digest = snapshot_authentication_tag(&security.key, &bytes);
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn ensure_signed_snapshot_capacity(
    intent_state: &JournalState,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
    wallet_destination: [u8; 32],
    transaction_bytes: usize,
    security: &LoadedWithdrawalSecurity,
) -> Result<(), ExchangeWithdrawalError> {
    u32::try_from(transaction_bytes)
        .map_err(|_| ExchangeWithdrawalError::Capacity("transaction byte"))?;
    let mut projected_intent = intent_state.clone();
    projected_intent.generation = projected_intent
        .generation
        .checked_add(1)
        .ok_or(ExchangeWithdrawalError::Capacity("snapshot generation"))?;
    append_state_commitment(
        &mut projected_intent,
        network_id,
        consensus_fingerprint,
        genesis,
        wallet_destination,
        security,
    )?;
    let intent_bytes = encode_snapshot(
        &projected_intent,
        network_id,
        consensus_fingerprint,
        genesis,
        wallet_destination,
        security,
    )?
    .len();
    // Reserve both future transitions. Prepared adds its generation and one
    // commitment. Released adds another commitment, the txid, a u32 length,
    // and the exact canonical signed frame.
    let signed_growth = DIGEST_BYTES
        .checked_mul(3)
        .and_then(|value| value.checked_add(std::mem::size_of::<u64>()))
        .and_then(|value| value.checked_add(std::mem::size_of::<u32>()))
        .and_then(|value| value.checked_add(transaction_bytes))
        .ok_or(ExchangeWithdrawalError::Capacity("snapshot byte"))?;
    if intent_bytes
        .checked_add(signed_growth)
        .is_none_or(|length| length > MAX_WITHDRAWAL_SNAPSHOT_BYTES)
    {
        return Err(ExchangeWithdrawalError::Capacity("snapshot byte"));
    }
    Ok(())
}

fn decode_snapshot(
    bytes: &[u8],
    binding: &NodeBinding,
) -> Result<JournalState, ExchangeWithdrawalError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.array::<8>()? != SNAPSHOT_MAGIC || decoder.u32()? != SNAPSHOT_VERSION {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal snapshot magic or version is unsupported",
        ));
    }
    let security = binding
        .security
        .as_ref()
        .ok_or(ExchangeWithdrawalError::SecurityRequired)?;
    if decoder.array::<32>()? != security.key_id {
        return Err(ExchangeWithdrawalError::InvalidJournalKey);
    }
    check_binding(&mut decoder, binding)?;
    let journal_instance_id = decoder.array()?;
    let generation = decoder.u64()?;
    let commitment_count = decoder.bounded_count(MAX_COMMITMENTS, "commitment")?;
    let mut commitments = Vec::with_capacity(commitment_count);
    for _ in 0..commitment_count {
        commitments.push(decoder.array()?);
    }
    let record_count = decoder.bounded_count(MAX_WITHDRAWAL_RECORDS, "withdrawal record")?;
    let mut records = BTreeMap::new();
    for _ in 0..record_count {
        let request_id = decoder.request_id()?;
        let request = WithdrawalRequest {
            request_id: request_id.clone(),
            destination: decoder.array()?,
            amount_atoms: decoder.u64()?,
            fee_atoms: decoder.u64()?,
        };
        let change_atoms = decoder.u64()?;
        let output_spendable_height = decoder.u64()?;
        let signing_digest = decoder.array()?;
        let input_count = decoder.bounded_count(MAX_TRANSACTION_INPUTS, "withdrawal input")?;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            inputs.push(PlannedInput {
                outpoint: OutPoint {
                    txid: decoder.array()?,
                    index: decoder.u32()?,
                },
                value_atoms: decoder.u64()?,
            });
        }
        let phase = decoder.byte()?;
        let (signed, prepared_generation) = match phase {
            1 => (None, None),
            2 => (None, Some(decoder.u64()?)),
            3 => {
                let prepared_generation = decoder.u64()?;
                let txid = decoder.array()?;
                let length = decoder.bounded_u32(MAX_TRANSACTION_BYTES, "transaction")?;
                (
                    Some(SignedWithdrawal {
                        txid,
                        transaction_bytes: decoder.take(length)?.to_vec(),
                    }),
                    Some(prepared_generation),
                )
            }
            _ => {
                return Err(ExchangeWithdrawalError::Corrupt(
                    "withdrawal record phase is invalid",
                ));
            }
        };
        let record = WithdrawalRecord {
            request,
            plan: PersistedPlan {
                change_atoms,
                output_spendable_height,
                signing_digest,
                inputs,
            },
            signed,
            prepared_generation,
        };
        if records.insert(request_id, record).is_some() {
            return Err(ExchangeWithdrawalError::Corrupt(
                "withdrawal snapshot contains duplicate request_id",
            ));
        }
    }
    if !decoder.is_empty() {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal snapshot contains trailing bytes",
        ));
    }
    let state = JournalState {
        generation,
        journal_instance_id,
        commitments,
        records,
    };
    validate_state(
        &state,
        binding.network_id,
        binding.consensus_fingerprint,
        binding.genesis,
        binding.wallet_destination,
        security,
    )?;
    Ok(state)
}

fn write_binding(bytes: &mut Vec<u8>, binding: &NodeBinding) {
    bytes.extend_from_slice(&binding.network_id);
    bytes.extend_from_slice(&binding.consensus_fingerprint);
    bytes.extend_from_slice(&binding.genesis);
    bytes.extend_from_slice(&binding.wallet_destination);
}

fn check_binding(
    decoder: &mut Decoder<'_>,
    binding: &NodeBinding,
) -> Result<(), ExchangeWithdrawalError> {
    if decoder.array::<32>()? != binding.network_id
        || decoder.array::<32>()? != binding.consensus_fingerprint
        || decoder.array::<32>()? != binding.genesis
    {
        return Err(ExchangeWithdrawalError::BindingMismatch);
    }
    if decoder.array::<32>()? != binding.wallet_destination {
        return Err(ExchangeWithdrawalError::WalletBindingMismatch);
    }
    Ok(())
}

fn write_request_id(bytes: &mut Vec<u8>, request_id: &str) -> Result<(), ExchangeWithdrawalError> {
    validate_request_id(request_id)?;
    let length = u16::try_from(request_id.len())
        .map_err(|_| ExchangeWithdrawalError::Capacity("request_id byte"))?;
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(request_id.as_bytes());
    Ok(())
}

fn write_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), ExchangeWithdrawalError> {
    bytes.extend_from_slice(
        &u64::try_from(count)
            .map_err(|_| ExchangeWithdrawalError::Capacity("snapshot collection"))?
            .to_le_bytes(),
    );
    Ok(())
}

fn write_records(
    bytes: &mut Vec<u8>,
    records: &BTreeMap<String, WithdrawalRecord>,
) -> Result<(), ExchangeWithdrawalError> {
    write_count(bytes, records.len())?;
    for (request_id, record) in records {
        if request_id != &record.request.request_id {
            return Err(ExchangeWithdrawalError::Corrupt(
                "withdrawal record key does not match request_id",
            ));
        }
        write_request_id(bytes, request_id)?;
        bytes.extend_from_slice(&record.request.destination);
        bytes.extend_from_slice(&record.request.amount_atoms.to_le_bytes());
        bytes.extend_from_slice(&record.request.fee_atoms.to_le_bytes());
        bytes.extend_from_slice(&record.plan.change_atoms.to_le_bytes());
        bytes.extend_from_slice(&record.plan.output_spendable_height.to_le_bytes());
        bytes.extend_from_slice(&record.plan.signing_digest);
        write_count(bytes, record.plan.inputs.len())?;
        for input in &record.plan.inputs {
            bytes.extend_from_slice(&input.outpoint.txid);
            bytes.extend_from_slice(&input.outpoint.index.to_le_bytes());
            bytes.extend_from_slice(&input.value_atoms.to_le_bytes());
        }
        match withdrawal_phase(record) {
            WithdrawalPhase::Intent => bytes.push(1),
            WithdrawalPhase::Prepared => {
                bytes.push(2);
                let prepared_generation =
                    record
                        .prepared_generation
                        .ok_or(ExchangeWithdrawalError::Corrupt(
                            "prepared withdrawal has no prepared generation",
                        ))?;
                bytes.extend_from_slice(&prepared_generation.to_le_bytes());
            }
            WithdrawalPhase::Released => {
                bytes.push(3);
                let prepared_generation =
                    record
                        .prepared_generation
                        .ok_or(ExchangeWithdrawalError::Corrupt(
                            "released withdrawal has no prepared generation",
                        ))?;
                let signed = record
                    .signed
                    .as_ref()
                    .ok_or(ExchangeWithdrawalError::Corrupt(
                        "released withdrawal has no signed transaction",
                    ))?;
                bytes.extend_from_slice(&prepared_generation.to_le_bytes());
                bytes.extend_from_slice(&signed.txid);
                let transaction_length = u32::try_from(signed.transaction_bytes.len())
                    .map_err(|_| ExchangeWithdrawalError::Capacity("transaction byte"))?;
                bytes.extend_from_slice(&transaction_length.to_le_bytes());
                bytes.extend_from_slice(&signed.transaction_bytes);
            }
        }
    }
    Ok(())
}

fn keyed_digest(key: &[u8; 32], domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn snapshot_authentication_tag(key: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    keyed_digest(key, SNAPSHOT_AUTH_DOMAIN, bytes)
}

fn marker_authentication_tag(key: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    keyed_digest(key, MARKER_AUTH_DOMAIN, bytes)
}

fn compute_state_commitment(
    state: &JournalState,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
    wallet_destination: [u8; 32],
    security: &LoadedWithdrawalSecurity,
) -> Result<[u8; 32], ExchangeWithdrawalError> {
    let generation = usize::try_from(state.generation)
        .map_err(|_| ExchangeWithdrawalError::Capacity("snapshot generation"))?;
    if generation == 0
        || (state.commitments.len() != generation
            && state.commitments.len().checked_add(1) != Some(generation))
    {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal commitment history does not precede its generation",
        ));
    }
    let previous = if generation == 1 {
        [0_u8; 32]
    } else {
        state.commitments[generation - 2]
    };
    let binding = NodeBinding {
        data_dir: PathBuf::new(),
        network_id,
        consensus_fingerprint,
        genesis,
        wallet_destination,
        security: Some(security.clone()),
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&SNAPSHOT_MAGIC);
    bytes.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&security.key_id);
    write_binding(&mut bytes, &binding);
    bytes.extend_from_slice(&state.journal_instance_id);
    bytes.extend_from_slice(&state.generation.to_le_bytes());
    bytes.extend_from_slice(&previous);
    write_records(&mut bytes, &state.records)?;
    Ok(keyed_digest(&security.key, COMMITMENT_DOMAIN, &bytes))
}

fn append_state_commitment(
    state: &mut JournalState,
    network_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis: [u8; 32],
    wallet_destination: [u8; 32],
    security: &LoadedWithdrawalSecurity,
) -> Result<(), ExchangeWithdrawalError> {
    let generation = usize::try_from(state.generation)
        .map_err(|_| ExchangeWithdrawalError::Capacity("snapshot generation"))?;
    if generation == 0
        || generation > MAX_COMMITMENTS
        || state.commitments.len().checked_add(1) != Some(generation)
    {
        return Err(ExchangeWithdrawalError::Corrupt(
            "withdrawal commitment append is out of sequence",
        ));
    }
    let commitment = compute_state_commitment(
        state,
        network_id,
        consensus_fingerprint,
        genesis,
        wallet_destination,
        security,
    )?;
    state.commitments.push(commitment);
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalAnchorDocument {
    key_id: String,
    journal_instance_id: String,
    generation: String,
    commitment: String,
}

#[cfg(test)]
pub(crate) fn encode_external_anchor(
    anchor: &WithdrawalJournalAnchor,
) -> Result<Vec<u8>, ExchangeWithdrawalError> {
    if anchor.key_id == [0; 32]
        || anchor.journal_instance_id == [0; 32]
        || anchor.generation == 0
        || anchor.commitment == [0; 32]
    {
        return Err(ExchangeWithdrawalError::InvalidAnchor);
    }
    serde_json::to_vec(&ExternalAnchorDocument {
        key_id: hex::encode(anchor.key_id),
        journal_instance_id: hex::encode(anchor.journal_instance_id),
        generation: anchor.generation.to_string(),
        commitment: hex::encode(anchor.commitment),
    })
    .map_err(|_| ExchangeWithdrawalError::InvalidAnchor)
}

fn load_external_anchor(
    security: &LoadedWithdrawalSecurity,
) -> Result<Option<WithdrawalJournalAnchor>, ExchangeWithdrawalError> {
    match fs::symlink_metadata(&security.anchor_path) {
        Ok(metadata)
            if !metadata.file_type().is_file() || metadata_is_symlink_or_reparse(&metadata) =>
        {
            return Err(ExchangeWithdrawalError::InvalidAnchor);
        }
        Ok(_) => {}
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(withdrawal_io(
                "inspect external withdrawal anchor path",
                &security.anchor_path,
                source,
            ));
        }
    }
    let mut file = match open_security_file(&security.anchor_path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(withdrawal_io(
                "open external withdrawal anchor",
                &security.anchor_path,
                source,
            ));
        }
    };
    validate_external_anchor_file(&file, &security.anchor_path)?;
    const MAX_ANCHOR_BYTES: u64 = 4 * 1024;
    let length = file
        .metadata()
        .map_err(|source| {
            withdrawal_io(
                "inspect external withdrawal anchor",
                &security.anchor_path,
                source,
            )
        })?
        .len();
    if length == 0 || length > MAX_ANCHOR_BYTES {
        return Err(ExchangeWithdrawalError::InvalidAnchor);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    Read::by_ref(&mut file)
        .take(MAX_ANCHOR_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            withdrawal_io(
                "read external withdrawal anchor",
                &security.anchor_path,
                source,
            )
        })?;
    if bytes.len() as u64 != length {
        return Err(ExchangeWithdrawalError::InvalidAnchor);
    }
    let document: ExternalAnchorDocument =
        serde_json::from_slice(&bytes).map_err(|_| ExchangeWithdrawalError::InvalidAnchor)?;
    let generation = document
        .generation
        .parse::<u64>()
        .ok()
        .filter(|generation| *generation != 0 && document.generation == generation.to_string())
        .ok_or(ExchangeWithdrawalError::InvalidAnchor)?;
    let anchor = WithdrawalJournalAnchor {
        key_id: decode_anchor_hex(&document.key_id)?,
        journal_instance_id: decode_anchor_hex(&document.journal_instance_id)?,
        generation,
        commitment: decode_anchor_hex(&document.commitment)?,
    };
    if anchor.key_id != security.key_id
        || anchor.journal_instance_id == [0; 32]
        || anchor.commitment == [0; 32]
    {
        return Err(ExchangeWithdrawalError::AnchorMismatch);
    }
    Ok(Some(anchor))
}

fn open_security_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn decode_anchor_hex(value: &str) -> Result<[u8; 32], ExchangeWithdrawalError> {
    if value.len() != 64 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(ExchangeWithdrawalError::InvalidAnchor);
    }
    let mut decoded = [0_u8; 32];
    hex::decode_to_slice(value, &mut decoded)
        .map_err(|_| ExchangeWithdrawalError::InvalidAnchor)?;
    Ok(decoded)
}

fn anchor_relationship(
    state: &JournalState,
    security: &LoadedWithdrawalSecurity,
    anchor: WithdrawalJournalAnchor,
) -> Result<WithdrawalAnchorRelationship, ExchangeWithdrawalError> {
    if anchor.key_id != security.key_id
        || anchor.journal_instance_id != state.journal_instance_id
        || anchor.generation == 0
        || anchor.generation > state.generation
    {
        return Err(ExchangeWithdrawalError::AnchorMismatch);
    }
    let position = usize::try_from(anchor.generation - 1)
        .map_err(|_| ExchangeWithdrawalError::AnchorMismatch)?;
    if state.commitments.get(position).copied() != Some(anchor.commitment) {
        return Err(ExchangeWithdrawalError::AnchorMismatch);
    }
    Ok(if anchor.generation == state.generation {
        WithdrawalAnchorRelationship::Current
    } else {
        WithdrawalAnchorRelationship::Descendant
    })
}

fn external_path(
    configured: &Path,
    data_dir: &Path,
    journal_key: bool,
) -> Result<PathBuf, ExchangeWithdrawalError> {
    if !configured.is_absolute() {
        return Err(if journal_key {
            ExchangeWithdrawalError::InvalidJournalKey
        } else {
            ExchangeWithdrawalError::InvalidAnchor
        });
    }
    match fs::symlink_metadata(configured) {
        Ok(metadata) if metadata_is_symlink_or_reparse(&metadata) => {
            return Err(if journal_key {
                ExchangeWithdrawalError::InvalidJournalKey
            } else {
                ExchangeWithdrawalError::InvalidAnchor
            });
        }
        Ok(_) => {}
        Err(source) if source.kind() == io::ErrorKind::NotFound && !journal_key => {}
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(withdrawal_io(
                "inspect withdrawal journal key path",
                configured,
                source,
            ));
        }
        Err(source) => {
            return Err(withdrawal_io(
                if journal_key {
                    "inspect withdrawal journal key path"
                } else {
                    "inspect external withdrawal anchor path"
                },
                configured,
                source,
            ));
        }
    }
    let resolved = if journal_key || configured.exists() {
        fs::canonicalize(configured).map_err(|source| {
            withdrawal_io(
                if journal_key {
                    "resolve withdrawal journal key"
                } else {
                    "resolve external withdrawal anchor"
                },
                configured,
                source,
            )
        })?
    } else {
        let parent = configured.parent().ok_or(if journal_key {
            ExchangeWithdrawalError::InvalidJournalKey
        } else {
            ExchangeWithdrawalError::InvalidAnchor
        })?;
        let name = configured.file_name().ok_or(if journal_key {
            ExchangeWithdrawalError::InvalidJournalKey
        } else {
            ExchangeWithdrawalError::InvalidAnchor
        })?;
        fs::canonicalize(parent)
            .map_err(|source| {
                withdrawal_io(
                    "resolve external withdrawal anchor directory",
                    parent,
                    source,
                )
            })?
            .join(name)
    };
    if !journal_key {
        let data_root = fs::canonicalize(data_dir)
            .map_err(|source| withdrawal_io("resolve node data directory", data_dir, source))?;
        if resolved.starts_with(&data_root) || configured.starts_with(&data_root) {
            return Err(ExchangeWithdrawalError::AnchorInsideDataDirectory);
        }
    }
    Ok(resolved)
}

fn metadata_is_symlink_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

fn validate_secret_file(file: &File, path: &Path) -> Result<(), ExchangeWithdrawalError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| withdrawal_io("inspect withdrawal journal key path", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| withdrawal_io("inspect withdrawal journal key", path, source))?;
    if !path_metadata.file_type().is_file() || !metadata.file_type().is_file() {
        return Err(ExchangeWithdrawalError::InvalidJournalKey);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ExchangeWithdrawalError::InsecureJournalKeyPermissions);
        }
    }
    Ok(())
}

fn validate_external_anchor_file(file: &File, path: &Path) -> Result<(), ExchangeWithdrawalError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| withdrawal_io("inspect external withdrawal anchor path", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| withdrawal_io("inspect external withdrawal anchor", path, source))?;
    if !path_metadata.file_type().is_file() || !metadata.file_type().is_file() {
        return Err(ExchangeWithdrawalError::InvalidAnchor);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(ExchangeWithdrawalError::InvalidAnchor);
        }
    }
    Ok(())
}

fn journal_files_present(data_dir: &Path) -> Result<bool, ExchangeWithdrawalError> {
    for path in [
        snapshot_path(data_dir, 0),
        snapshot_path(data_dir, 1),
        marker_path(data_dir),
    ] {
        match fs::symlink_metadata(&path) {
            Ok(_) => return Ok(true),
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(withdrawal_io(
                    "inspect withdrawal journal presence",
                    path,
                    source,
                ));
            }
        }
    }
    Ok(false)
}

fn journal_has_legacy_v1_file(data_dir: &Path) -> Result<bool, ExchangeWithdrawalError> {
    for path in [
        snapshot_path(data_dir, 0),
        snapshot_path(data_dir, 1),
        marker_path(data_dir),
    ] {
        let mut file = match OpenOptions::new().read(true).open(&path) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(withdrawal_io(
                    "inspect withdrawal journal version",
                    path,
                    source,
                ));
            }
        };
        let mut header = [0_u8; 12];
        match file.read_exact(&mut header) {
            Ok(()) if header[8..12] == LEGACY_SNAPSHOT_VERSION.to_le_bytes() => return Ok(true),
            Ok(()) => {}
            Err(source) if source.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(source) => {
                return Err(withdrawal_io(
                    "read withdrawal journal version",
                    path,
                    source,
                ));
            }
        }
    }
    Ok(false)
}

fn validate_durable_file(
    file: &File,
    path: &Path,
    kind: &'static str,
) -> Result<(), ExchangeWithdrawalError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| withdrawal_io("inspect withdrawal durable path", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| withdrawal_io("inspect withdrawal durable file", path, source))?;
    if !path_metadata.file_type().is_file() || !metadata.file_type().is_file() {
        return Err(ExchangeWithdrawalError::Corrupt(match kind {
            "withdrawal marker" => "withdrawal marker is not a regular file",
            _ => "withdrawal snapshot is not a regular file",
        }));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ExchangeWithdrawalError::Corrupt(match kind {
                "withdrawal marker" => "withdrawal marker permissions are not owner-only",
                _ => "withdrawal snapshot permissions are not owner-only",
            }));
        }
    }
    Ok(())
}

fn persist_slot(path: &Path, bytes: &[u8]) -> Result<(), ExchangeWithdrawalError> {
    if bytes.len() > MAX_WITHDRAWAL_SNAPSHOT_BYTES {
        return Err(ExchangeWithdrawalError::Capacity("snapshot byte"));
    }
    let mut suffix = [0_u8; 16];
    getrandom::fill(&mut suffix).map_err(|source| {
        withdrawal_io(
            "generate withdrawal temporary path",
            path,
            io::Error::other(source.to_string()),
        )
    })?;
    let parent = path.parent().ok_or_else(|| {
        withdrawal_io(
            "locate withdrawal journal directory",
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "journal path has no parent"),
        )
    })?;
    let temporary = parent.join(format!(
        ".{EXCHANGE_WITHDRAWAL_FILE_PREFIX}.tmp-{}",
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
            .map_err(|source| withdrawal_io("create withdrawal journal", &temporary, source))?;
        file.write_all(bytes)
            .map_err(|source| withdrawal_io("write withdrawal journal", &temporary, source))?;
        file.sync_all()
            .map_err(|source| withdrawal_io("sync withdrawal journal", &temporary, source))?;
        publish_snapshot(&temporary, path)
            .map_err(|source| withdrawal_io("publish withdrawal journal", path, source))?;
        sync_parent_directory(path)
            .map_err(|error| node_io_as_withdrawal(error, "sync withdrawal directory", path))
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
    // SAFETY: both buffers are valid NUL-terminated UTF-16 paths for this call.
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

fn snapshot_path(data_dir: &Path, slot: u8) -> PathBuf {
    data_dir.join(format!("{EXCHANGE_WITHDRAWAL_FILE_PREFIX}.{slot}.bin"))
}

fn marker_path(data_dir: &Path) -> PathBuf {
    data_dir.join(EXCHANGE_WITHDRAWAL_MARKER_FILE)
}

fn withdrawal_io(
    operation: &'static str,
    path: impl AsRef<Path>,
    source: io::Error,
) -> ExchangeWithdrawalError {
    ExchangeWithdrawalError::Io {
        operation,
        path: path.as_ref().to_path_buf(),
        source,
    }
}

fn node_io_as_withdrawal(
    error: NodeError,
    operation: &'static str,
    path: &Path,
) -> ExchangeWithdrawalError {
    match error {
        NodeError::Io { source, .. } => withdrawal_io(operation, path, source),
        other => ExchangeWithdrawalError::Node(other),
    }
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ExchangeWithdrawalError> {
        if self.remaining.len() < length {
            return Err(ExchangeWithdrawalError::Corrupt(
                "withdrawal snapshot is truncated",
            ));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ExchangeWithdrawalError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ExchangeWithdrawalError::Corrupt("withdrawal snapshot is truncated"))
    }

    fn byte(&mut self) -> Result<u8, ExchangeWithdrawalError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ExchangeWithdrawalError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ExchangeWithdrawalError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ExchangeWithdrawalError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn bounded_count(
        &mut self,
        maximum: usize,
        kind: &'static str,
    ) -> Result<usize, ExchangeWithdrawalError> {
        usize::try_from(self.u64()?)
            .ok()
            .filter(|count| *count <= maximum)
            .ok_or(ExchangeWithdrawalError::Corrupt(match kind {
                "withdrawal record" => "withdrawal record count exceeds its capacity",
                "withdrawal input" => "withdrawal input count exceeds its capacity",
                _ => "withdrawal snapshot count exceeds its capacity",
            }))
    }

    fn bounded_u32(
        &mut self,
        maximum: usize,
        kind: &'static str,
    ) -> Result<usize, ExchangeWithdrawalError> {
        usize::try_from(self.u32()?)
            .ok()
            .filter(|length| *length <= maximum)
            .ok_or(ExchangeWithdrawalError::Corrupt(match kind {
                "transaction" => "signed transaction exceeds its capacity",
                _ => "withdrawal byte field exceeds its capacity",
            }))
    }

    fn request_id(&mut self) -> Result<String, ExchangeWithdrawalError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > MAX_WITHDRAWAL_REQUEST_ID_BYTES {
            return Err(ExchangeWithdrawalError::Corrupt(
                "stored request_id length is invalid",
            ));
        }
        let request_id = std::str::from_utf8(self.take(length)?)
            .map_err(|_| ExchangeWithdrawalError::Corrupt("request_id is not UTF-8"))?;
        validate_request_id(request_id)
            .map_err(|_| ExchangeWithdrawalError::Corrupt("stored request_id is invalid"))?;
        Ok(request_id.to_owned())
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use k256::schnorr::SigningKey;

    use super::*;
    use crate::{DEFAULT_MINING_ATTEMPTS, DEVNET_PROFILE};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cmfd-exchange-withdrawal-{label}-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn clean_test_paths(data_dir: &Path, security_dir: &Path) {
        let _ = fs::remove_dir_all(data_dir);
        let _ = fs::remove_dir_all(security_dir);
    }

    fn key(marker: u8) -> SigningKey {
        SigningKey::from_bytes(&[marker; 32]).expect("test scalar is nonzero")
    }

    fn destination(marker: u8) -> [u8; 32] {
        key(marker).verifying_key().to_bytes().into()
    }

    fn loaded_security(anchor_path: PathBuf, marker: u8) -> LoadedWithdrawalSecurity {
        let key = Zeroizing::new([marker; 32]);
        let key_id = keyed_digest(&key, KEY_ID_DOMAIN, b"journal-key-id");
        LoadedWithdrawalSecurity {
            key,
            key_id,
            anchor_path,
        }
    }

    fn test_binding(data_dir: PathBuf, security: LoadedWithdrawalSecurity) -> NodeBinding {
        NodeBinding {
            data_dir,
            network_id: [0x11; 32],
            consensus_fingerprint: [0x22; 32],
            genesis: [0x33; 32],
            wallet_destination: destination(7),
            security: Some(security),
        }
    }

    fn empty_state(
        security: &LoadedWithdrawalSecurity,
    ) -> Result<JournalState, ExchangeWithdrawalError> {
        let mut state = JournalState {
            generation: 1,
            journal_instance_id: [0x55; 32],
            commitments: Vec::new(),
            records: BTreeMap::new(),
        };
        append_state_commitment(
            &mut state,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            destination(7),
            security,
        )?;
        state.generation = 2;
        append_state_commitment(
            &mut state,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            destination(7),
            security,
        )?;
        Ok(state)
    }

    fn intent_record(request_id: &str, input_marker: u8) -> WithdrawalRecord {
        let wallet_destination = destination(7);
        let request = WithdrawalRequest {
            request_id: request_id.to_owned(),
            destination: destination(9),
            amount_atoms: 100,
            fee_atoms: 1,
        };
        let unsigned = Transaction {
            network_id: [0x11; 32],
            version: TRANSACTION_VERSION,
            inputs: vec![TxInput {
                previous: OutPoint {
                    txid: [input_marker; 32],
                    index: 3,
                },
                witness: InputWitness::Key {
                    public_key: wallet_destination,
                    signature: Vec::new(),
                },
            }],
            outputs: vec![
                TxOutput {
                    value: 100,
                    lock: OutputLock::Key(request.destination),
                    spendable_height: 42,
                },
                TxOutput {
                    value: 49,
                    lock: OutputLock::Key(wallet_destination),
                    spendable_height: 42,
                },
            ],
        };
        WithdrawalRecord {
            request,
            plan: PersistedPlan {
                change_atoms: 49,
                output_spendable_height: 42,
                signing_digest: unsigned.signing_digest(),
                inputs: vec![PlannedInput {
                    outpoint: unsigned.inputs[0].previous,
                    value_atoms: 150,
                }],
            },
            signed: None,
            prepared_generation: None,
        }
    }

    fn write_external_anchor(path: &Path, anchor: &WithdrawalJournalAnchor) {
        fs::write(path, encode_external_anchor(anchor).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn secured_node(label: &str) -> (PathBuf, PathBuf, ExchangeWithdrawalSecurityConfig, Node) {
        let data_dir = test_dir(label);
        let security_dir = data_dir.with_extension("withdrawal-security");
        clean_test_paths(&data_dir, &security_dir);
        fs::create_dir_all(&security_dir).unwrap();
        let key_path = security_dir.join("journal.key");
        fs::write(&key_path, [0x5a_u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config =
            ExchangeWithdrawalSecurityConfig::new(&key_path, security_dir.join("journal.anchor"));
        let node = Node::open_with_profile_and_exchange_withdrawal_security(
            &data_dir,
            DEVNET_PROFILE,
            &config,
        )
        .unwrap();
        (data_dir, security_dir, config, node)
    }

    fn mine_spendable_wallet(node: &mut Node) {
        let wallet_destination = node.wallet_destination();
        for height in 1..=100 {
            node.mine_once(
                wallet_destination,
                DEVNET_PROFILE.virtual_genesis_timestamp + height * 60,
                DEFAULT_MINING_ATTEMPTS,
            )
            .unwrap();
        }
    }

    fn persist_intent_for_test(
        journal: &mut ExchangeWithdrawalJournal,
        node: &mut Node,
        request: &WithdrawalRequest,
    ) {
        let plan = node
            .plan_dev_wallet_payment(request.destination, request.amount_atoms, request.fee_atoms)
            .unwrap();
        let persisted = persisted_plan_from_wallet_plan(
            &plan,
            request,
            journal.network_id,
            journal.wallet_destination,
        )
        .unwrap();
        let mut candidate = journal.state.clone();
        candidate.records.insert(
            request.request_id.clone(),
            WithdrawalRecord {
                request: request.clone(),
                plan: persisted,
                signed: None,
                prepared_generation: None,
            },
        );
        node.set_exchange_withdrawal_reservations(reservation_map(&candidate).unwrap());
        journal.persist_candidate(candidate).unwrap();
    }

    #[test]
    fn external_anchor_is_exact_canonical_four_field_json() {
        let directory = test_dir("anchor-json");
        fs::create_dir_all(&directory).unwrap();
        let anchor_path = directory.join("anchor.json");
        let security = loaded_security(anchor_path.clone(), 0x44);
        let anchor = WithdrawalJournalAnchor {
            key_id: security.key_id,
            journal_instance_id: [0x55; 32],
            generation: 7,
            commitment: [0x66; 32],
        };
        let bytes = encode_external_anchor(&anchor).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 4);
        assert_eq!(object["generation"], "7");
        assert!(!object.contains_key("schema"));

        write_external_anchor(&anchor_path, &anchor);
        assert_eq!(load_external_anchor(&security).unwrap(), Some(anchor));

        let mut invalid = object.clone();
        invalid.insert(
            "schema".to_owned(),
            serde_json::Value::String("v2".to_owned()),
        );
        fs::write(&anchor_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(matches!(
            load_external_anchor(&security),
            Err(ExchangeWithdrawalError::InvalidAnchor)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn external_anchor_fifo_is_rejected_without_blocking_on_open() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let directory = test_dir("anchor-fifo");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let anchor_path = directory.join("anchor.json");
        let c_path = CString::new(anchor_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let security = loaded_security(anchor_path, 0x44);
        assert!(matches!(
            load_external_anchor(&security),
            Err(ExchangeWithdrawalError::InvalidAnchor)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn authenticated_snapshot_and_commitment_chain_reject_tampering_and_wrong_key() {
        let security = loaded_security(PathBuf::from("unused-anchor"), 0x44);
        let binding = test_binding(PathBuf::new(), security.clone());
        let state = empty_state(&security).unwrap();
        let encoded = encode_snapshot(
            &state,
            binding.network_id,
            binding.consensus_fingerprint,
            binding.genesis,
            binding.wallet_destination,
            &security,
        )
        .unwrap();
        let payload = &encoded[..encoded.len() - DIGEST_BYTES];
        assert_eq!(decode_snapshot(payload, &binding).unwrap(), state);

        let mut tampered = encoded.clone();
        tampered[minimum_snapshot_bytes() - DIGEST_BYTES - 1] ^= 1;
        let payload_length = tampered.len() - DIGEST_BYTES;
        let public_checksum = *blake3::hash(&tampered[..payload_length]).as_bytes();
        tampered[payload_length..].copy_from_slice(&public_checksum);
        let (tampered_payload, tag) = tampered.split_at(payload_length);
        assert_ne!(
            snapshot_authentication_tag(&security.key, tampered_payload),
            tag
        );

        let wrong_security = loaded_security(PathBuf::from("unused-anchor"), 0x45);
        let wrong_binding = test_binding(PathBuf::new(), wrong_security);
        assert!(matches!(
            decode_snapshot(payload, &wrong_binding),
            Err(ExchangeWithdrawalError::InvalidJournalKey)
        ));

        let mut broken_history = state.clone();
        broken_history.commitments[0][0] ^= 1;
        assert!(matches!(
            validate_state(
                &broken_history,
                binding.network_id,
                binding.consensus_fingerprint,
                binding.genesis,
                binding.wallet_destination,
                &security,
            ),
            Err(ExchangeWithdrawalError::Corrupt(_))
        ));
    }

    #[test]
    fn capacity_reserves_prepared_and_released_commitments_at_the_exact_boundary() {
        let security = loaded_security(PathBuf::from("unused-anchor"), 0x44);
        let mut intent = empty_state(&security).unwrap();
        let record = intent_record("capacity", 3);
        intent
            .records
            .insert(record.request.request_id.clone(), record);

        let mut projected_intent = intent.clone();
        projected_intent.generation += 1;
        append_state_commitment(
            &mut projected_intent,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            destination(7),
            &security,
        )
        .unwrap();
        let intent_length = encode_snapshot(
            &projected_intent,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            destination(7),
            &security,
        )
        .unwrap()
        .len();
        let fixed_growth =
            DIGEST_BYTES * 3 + std::mem::size_of::<u64>() + std::mem::size_of::<u32>();
        let exact_transaction_capacity = MAX_WITHDRAWAL_SNAPSHOT_BYTES
            .checked_sub(intent_length + fixed_growth)
            .unwrap();

        ensure_signed_snapshot_capacity(
            &intent,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            destination(7),
            exact_transaction_capacity,
            &security,
        )
        .unwrap();
        assert!(matches!(
            ensure_signed_snapshot_capacity(
                &intent,
                [0x11; 32],
                [0x22; 32],
                [0x33; 32],
                destination(7),
                exact_transaction_capacity + 1,
                &security,
            ),
            Err(ExchangeWithdrawalError::Capacity("snapshot byte"))
        ));
    }

    #[test]
    fn bootstrap_restart_intent_prepared_and_release_are_exchange_anchored() {
        let (data_dir, security_dir, config, node) = secured_node("anchored-lifecycle");
        let shared = Arc::new(Mutex::new(node));
        let journal = ExchangeWithdrawalJournal::open_and_reconcile(&shared).unwrap();
        let bootstrap_info = journal.journal_info().unwrap();
        assert_eq!(
            bootstrap_info.relationship,
            WithdrawalAnchorRelationship::Bootstrap
        );
        assert!(bootstrap_info.external_anchor.is_none());
        let bootstrap_anchor = bootstrap_info.current_anchor;
        drop(journal);
        drop(shared);

        // An empty authenticated enrollment remains recoverable if the process
        // crashed before the exchange persisted its baseline pin.
        let mut node = Node::open_with_profile_and_exchange_withdrawal_security(
            &data_dir,
            DEVNET_PROFILE,
            &config,
        )
        .unwrap();
        let shared = Arc::new(Mutex::new(node));
        let mut journal = ExchangeWithdrawalJournal::open_and_reconcile(&shared).unwrap();
        assert_eq!(
            journal.journal_info().unwrap().relationship,
            WithdrawalAnchorRelationship::Bootstrap
        );
        mine_spendable_wallet(&mut shared.lock().unwrap());

        let request = WithdrawalRequest {
            request_id: "exchange-order-1".to_owned(),
            destination: destination(9),
            amount_atoms: 1,
            fee_atoms: 1,
        };
        assert!(matches!(
            journal.prepare(&shared, &request),
            Err(ExchangeWithdrawalError::InvalidAnchor)
        ));
        assert!(shared.lock().unwrap().mempool.is_empty());

        write_external_anchor(config.anchor_file(), &bootstrap_anchor);
        {
            let mut node = shared.lock().unwrap();
            persist_intent_for_test(&mut journal, &mut node, &request);
        }
        assert_eq!(
            journal
                .get(&shared, &request.request_id)
                .unwrap()
                .unwrap()
                .phase,
            WithdrawalPhase::Intent
        );
        drop(journal);
        drop(shared);

        // Startup restores reservations but neither signs nor broadcasts Intent.
        node = Node::open_with_profile_and_exchange_withdrawal_security(
            &data_dir,
            DEVNET_PROFILE,
            &config,
        )
        .unwrap();
        assert!(!node.exchange_withdrawal_reservations.is_empty());
        assert!(node.mempool.is_empty());
        let shared = Arc::new(Mutex::new(node));
        let mut journal = ExchangeWithdrawalJournal::open_and_reconcile(&shared).unwrap();
        assert_eq!(
            journal
                .get(&shared, &request.request_id)
                .unwrap()
                .unwrap()
                .phase,
            WithdrawalPhase::Intent
        );
        assert!(shared.lock().unwrap().mempool.is_empty());

        let prepared = journal.prepare(&shared, &request).unwrap();
        assert_eq!(prepared.phase, WithdrawalPhase::Prepared);
        assert_eq!(prepared.status, WithdrawalStatus::Prepared);
        assert!(prepared.txid.is_none());
        assert!(prepared.transaction_bytes.is_none());
        assert!(shared.lock().unwrap().mempool.is_empty());
        let prepared_anchor = prepared.prepared_anchor.unwrap();
        assert_eq!(prepared_anchor, current_anchor(&journal));
        assert_eq!(
            fs::read(config.anchor_file()).unwrap(),
            encode_external_anchor(&bootstrap_anchor).unwrap()
        );
        assert!(matches!(
            journal.prepare(
                &shared,
                &WithdrawalRequest {
                    request_id: "exchange-order-2".to_owned(),
                    destination: destination(8),
                    amount_atoms: 1,
                    fee_atoms: 1,
                },
            ),
            Err(ExchangeWithdrawalError::PreparedWithdrawalPending)
        ));
        drop(journal);
        drop(shared);

        // Prepared is also inert across restart even while the exchange pin is
        // still the earlier authenticated ancestor.
        node = Node::open_with_profile_and_exchange_withdrawal_security(
            &data_dir,
            DEVNET_PROFILE,
            &config,
        )
        .unwrap();
        assert!(node.mempool.is_empty());
        let shared = Arc::new(Mutex::new(node));
        let mut journal = ExchangeWithdrawalJournal::open_and_reconcile(&shared).unwrap();
        let observed = journal.get(&shared, &request.request_id).unwrap().unwrap();
        assert_eq!(observed.phase, WithdrawalPhase::Prepared);
        assert!(shared.lock().unwrap().mempool.is_empty());
        assert_eq!(journal.prepare(&shared, &request).unwrap(), observed);

        assert!(matches!(
            journal.release(&shared, &request.request_id),
            Err(ExchangeWithdrawalError::PreparedAnchorMismatch)
        ));
        assert!(shared.lock().unwrap().mempool.is_empty());

        write_external_anchor(config.anchor_file(), &prepared_anchor);
        let prepared_pin_bytes = fs::read(config.anchor_file()).unwrap();
        assert!(matches!(
            ExchangeWithdrawalJournal::export_validated_v2_for_v3_migration(
                &shared.lock().unwrap()
            ),
            Err(ExchangeWithdrawalError::PreparedWithdrawalPending)
        ));
        let released = journal.release(&shared, &request.request_id).unwrap();
        assert_eq!(released.phase, WithdrawalPhase::Released);
        assert_eq!(released.status, WithdrawalStatus::InMempool);
        assert!(released.txid.is_some());
        assert!(released.transaction_bytes.is_some());
        assert_eq!(shared.lock().unwrap().mempool.len(), 1);
        assert_eq!(
            journal
                .get(&shared, &request.request_id)
                .unwrap()
                .unwrap()
                .status,
            WithdrawalStatus::InMempool
        );
        assert_eq!(fs::read(config.anchor_file()).unwrap(), prepared_pin_bytes);
        assert!(matches!(
            ExchangeWithdrawalJournal::export_validated_v2_for_v3_migration(
                &shared.lock().unwrap()
            ),
            Err(ExchangeWithdrawalError::AnchorMismatch)
        ));

        // Lost-response retry works while the exchange still has the Prepared
        // pin, and again after it advances to the current Released pin.
        assert_eq!(
            journal.release(&shared, &request.request_id).unwrap(),
            released
        );
        let released_anchor = current_anchor(&journal);
        write_external_anchor(config.anchor_file(), &released_anchor);
        let migration_export = ExchangeWithdrawalJournal::export_validated_v2_for_v3_migration(
            &shared.lock().unwrap(),
        )
        .unwrap();
        assert_eq!(migration_export.source_anchor, released_anchor);
        assert_eq!(
            migration_export.wallet_destination,
            shared.lock().unwrap().wallet_destination()
        );
        assert_eq!(migration_export.released_records.len(), 1);
        assert_eq!(
            migration_export.released_records[0].txid,
            released.txid.unwrap()
        );
        assert_eq!(
            migration_export.released_records[0].exact_transaction_bytes,
            released.transaction_bytes.clone().unwrap()
        );
        assert_ne!(
            migration_export.released_records[0].source_record_digest,
            [0; 32]
        );
        assert_eq!(
            ExchangeWithdrawalJournal::export_exact_v2_for_v3_migration_resume(
                &shared.lock().unwrap(),
                &migration_export.exact_snapshot_bytes,
                released_anchor,
            )
            .unwrap(),
            migration_export
        );
        let mut wrong_source_anchor = released_anchor;
        wrong_source_anchor.commitment[0] ^= 1;
        assert!(matches!(
            ExchangeWithdrawalJournal::export_exact_v2_for_v3_migration_resume(
                &shared.lock().unwrap(),
                &migration_export.exact_snapshot_bytes,
                wrong_source_anchor,
            ),
            Err(ExchangeWithdrawalError::AnchorMismatch)
        ));
        let mut tampered_snapshot = migration_export.exact_snapshot_bytes.clone();
        tampered_snapshot[minimum_snapshot_bytes() - DIGEST_BYTES - 1] ^= 1;
        assert!(matches!(
            ExchangeWithdrawalJournal::export_exact_v2_for_v3_migration_resume(
                &shared.lock().unwrap(),
                &tampered_snapshot,
                released_anchor,
            ),
            Err(ExchangeWithdrawalError::Corrupt(_))
        ));
        let binding = NodeBinding::from_node(&shared.lock().unwrap()).unwrap();
        let payload_length = migration_export.exact_snapshot_bytes.len() - DIGEST_BYTES;
        assert_eq!(
            decode_snapshot(
                &migration_export.exact_snapshot_bytes[..payload_length],
                &binding,
            )
            .unwrap()
            .generation,
            released_anchor.generation
        );
        assert_eq!(
            journal.release(&shared, &request.request_id).unwrap(),
            released
        );

        write_external_anchor(config.anchor_file(), &prepared_anchor);
        assert!(matches!(
            journal.prepare(
                &shared,
                &WithdrawalRequest {
                    request_id: "exchange-order-2".to_owned(),
                    destination: destination(8),
                    amount_atoms: 1,
                    fee_atoms: 1,
                },
            ),
            Err(ExchangeWithdrawalError::AnchorMismatch)
        ));

        drop(journal);
        drop(shared);

        // If Released committed but both the response and first in-memory
        // broadcast were lost, startup may rebroadcast only those same durable
        // bytes. The still-pinned Prepared anchor authorizes no new request.
        node = Node::open_with_profile_and_exchange_withdrawal_security(
            &data_dir,
            DEVNET_PROFILE,
            &config,
        )
        .unwrap();
        assert!(node.mempool.is_empty());
        let shared = Arc::new(Mutex::new(node));
        let journal = ExchangeWithdrawalJournal::open_and_reconcile(&shared).unwrap();
        let recovered = journal.get(&shared, &request.request_id).unwrap().unwrap();
        assert_eq!(recovered.phase, WithdrawalPhase::Released);
        assert_eq!(recovered.status, WithdrawalStatus::InMempool);
        assert_eq!(recovered.txid, released.txid);
        assert_eq!(recovered.transaction_bytes, released.transaction_bytes);
        assert_eq!(shared.lock().unwrap().mempool.len(), 1);

        drop(journal);
        drop(shared);
        clean_test_paths(&data_dir, &security_dir);
    }

    #[test]
    fn failed_released_publication_never_exposes_or_broadcasts_signed_bytes() {
        let (data_dir, security_dir, config, mut node) = secured_node("release-persist-failure");
        mine_spendable_wallet(&mut node);
        let shared = Arc::new(Mutex::new(node));
        let mut journal = ExchangeWithdrawalJournal::open_and_reconcile(&shared).unwrap();
        let bootstrap_anchor = journal.journal_info().unwrap().current_anchor;
        write_external_anchor(config.anchor_file(), &bootstrap_anchor);
        let request = WithdrawalRequest {
            request_id: "release-persist-failure".to_owned(),
            destination: destination(9),
            amount_atoms: 1,
            fee_atoms: 1,
        };
        let prepared = journal.prepare(&shared, &request).unwrap();
        assert_eq!(prepared.phase, WithdrawalPhase::Prepared);
        assert!(prepared.txid.is_none());
        assert!(prepared.transaction_bytes.is_none());
        write_external_anchor(config.anchor_file(), &prepared.prepared_anchor.unwrap());

        let released_generation = journal.state.generation + 1;
        let blocked_slot = snapshot_path(&data_dir, (released_generation & 1) as u8);
        fs::remove_file(&blocked_slot).unwrap();
        fs::create_dir(&blocked_slot).unwrap();

        assert!(matches!(
            journal.release(&shared, &request.request_id),
            Err(ExchangeWithdrawalError::Io { .. })
        ));
        assert!(journal.faulted);
        let retained = journal.state.records.get(&request.request_id).unwrap();
        assert_eq!(withdrawal_phase(retained), WithdrawalPhase::Prepared);
        assert!(retained.signed.is_none());
        let node = shared.lock().unwrap();
        assert!(node.mempool.is_empty());
        assert!(!node.exchange_withdrawal_reservations.is_empty());
        drop(node);

        drop(journal);
        drop(shared);
        clean_test_paths(&data_dir, &security_dir);
    }

    #[test]
    fn wrong_anchor_key_instance_or_commitment_fails_closed() {
        let (data_dir, security_dir, config, node) = secured_node("wrong-anchor");
        let shared = Arc::new(Mutex::new(node));
        let journal = ExchangeWithdrawalJournal::open_and_reconcile(&shared).unwrap();
        let current = journal.journal_info().unwrap().current_anchor;

        for invalid in [
            WithdrawalJournalAnchor {
                key_id: [0x91; 32],
                ..current
            },
            WithdrawalJournalAnchor {
                journal_instance_id: [0x92; 32],
                ..current
            },
            WithdrawalJournalAnchor {
                commitment: [0x93; 32],
                ..current
            },
        ] {
            write_external_anchor(config.anchor_file(), &invalid);
            assert!(matches!(
                journal.journal_info(),
                Err(ExchangeWithdrawalError::AnchorMismatch)
            ));
        }

        drop(journal);
        drop(shared);
        clean_test_paths(&data_dir, &security_dir);
    }

    #[test]
    fn nonempty_journal_requires_its_surviving_external_anchor_and_rejects_rollback() {
        let (data_dir, security_dir, config, mut node) = secured_node("rollback");
        mine_spendable_wallet(&mut node);
        let shared = Arc::new(Mutex::new(node));
        let mut journal = ExchangeWithdrawalJournal::open_and_reconcile(&shared).unwrap();
        let bootstrap_anchor = journal.journal_info().unwrap().current_anchor;
        let baseline_slots = [
            fs::read(snapshot_path(&data_dir, 0)).unwrap(),
            fs::read(snapshot_path(&data_dir, 1)).unwrap(),
        ];
        write_external_anchor(config.anchor_file(), &bootstrap_anchor);
        let request = WithdrawalRequest {
            request_id: "rollback-order".to_owned(),
            destination: destination(9),
            amount_atoms: 1,
            fee_atoms: 1,
        };
        let prepared = journal.prepare(&shared, &request).unwrap();
        let prepared_anchor = prepared.prepared_anchor.unwrap();
        write_external_anchor(config.anchor_file(), &prepared_anchor);
        drop(journal);
        drop(shared);

        fs::remove_file(config.anchor_file()).unwrap();
        assert!(matches!(
            Node::open_with_profile_and_exchange_withdrawal_security(
                &data_dir,
                DEVNET_PROFILE,
                &config,
            ),
            Err(NodeError::ExchangeWithdrawalJournal {
                code: "invalid_exchange_withdrawal_anchor",
                ..
            })
        ));

        write_external_anchor(config.anchor_file(), &prepared_anchor);
        for (slot, bytes) in baseline_slots.into_iter().enumerate() {
            fs::write(snapshot_path(&data_dir, slot as u8), bytes).unwrap();
        }
        assert!(matches!(
            Node::open_with_profile_and_exchange_withdrawal_security(
                &data_dir,
                DEVNET_PROFILE,
                &config,
            ),
            Err(NodeError::ExchangeWithdrawalJournal {
                code: "exchange_withdrawal_anchor_mismatch",
                ..
            })
        ));
        clean_test_paths(&data_dir, &security_dir);
    }

    #[test]
    fn legacy_v1_journal_is_never_silently_migrated() {
        let data_dir = test_dir("legacy-v1");
        let security_dir = data_dir.with_extension("unused-security");
        clean_test_paths(&data_dir, &security_dir);
        fs::create_dir_all(&data_dir).unwrap();
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&SNAPSHOT_MAGIC);
        legacy.extend_from_slice(&LEGACY_SNAPSHOT_VERSION.to_le_bytes());
        fs::write(snapshot_path(&data_dir, 0), legacy).unwrap();

        assert!(matches!(
            Node::open_with_profile(&data_dir, DEVNET_PROFILE),
            Err(NodeError::ExchangeWithdrawalJournal {
                code: "exchange_withdrawal_v1_migration_required",
                ..
            })
        ));
        clean_test_paths(&data_dir, &security_dir);
    }

    #[test]
    fn external_anchor_path_inside_data_directory_is_rejected() {
        let data_dir = test_dir("anchor-inside");
        let security_dir = data_dir.with_extension("security");
        clean_test_paths(&data_dir, &security_dir);
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&security_dir).unwrap();
        let key_path = security_dir.join("journal.key");
        fs::write(&key_path, [0x61; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config = ExchangeWithdrawalSecurityConfig::new(key_path, data_dir.join("anchor.json"));
        assert!(matches!(
            Node::open_with_profile_and_exchange_withdrawal_security(
                &data_dir,
                DEVNET_PROFILE,
                &config,
            ),
            Err(NodeError::ExchangeWithdrawalJournal {
                code: "exchange_withdrawal_anchor_inside_data_dir",
                ..
            })
        ));
        clean_test_paths(&data_dir, &security_dir);
    }
}
