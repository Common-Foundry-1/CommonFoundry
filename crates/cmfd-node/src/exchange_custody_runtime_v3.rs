//! Operational composition for exchange custody journal v3.
//!
//! Callers must lock this runtime before the shared node. Every mutating path
//! keeps that order, persists the journal candidate before reporting success,
//! and never submits a transaction until its exact signed bytes are durable.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use cmfd_consensus::{
    InputWitness, OutPoint, OutputLock, TRANSACTION_VERSION, Transaction, TxInput, TxOutput,
    decode_transaction, encode_transaction,
};
use thiserror::Error;

use crate::exchange_custody_engine::{
    AuthorizedReleaseCompletionEngineV3, CustodyPaymentPlanV3, CustodyTerminalActionV3,
    ExchangeCustodyEngineError, ExchangeCustodyEngineV3, UnsignedApprovalDocumentV3,
    verify_persisted_terminal_approval,
};
use crate::exchange_custody_v3::{
    ExchangeCustodyV3Error, ExchangeCustodyV3OpenConfig, ExchangeCustodyV3Store,
    ExternalAnchorRelationshipV3, keyring_anchor_v3_from_v1, load_external_anchor_v3,
    load_keyring_anchor_v3, load_keyring_envelope_v3, load_keyring_passphrase_v3,
    load_policy_document_v3,
};
use crate::exchange_policy::{ExchangePolicyError, WithdrawalPolicy, WithdrawalPolicyBinding};
use crate::exchange_withdrawal::WithdrawalRequest;
use crate::exchange_withdrawal_v3::{
    DecisionScopeV3, JournalAnchorV3, JournalBindingV3, KeyringAnchorV3, MAX_V3_COMMITMENTS,
    MAX_V3_TOMBSTONES, MAX_V3_WITHDRAWAL_RECORDS, RecordOriginV3, SignerPackageEvidenceV3,
    WithdrawalPhaseV3, WithdrawalRecordV3,
};
use crate::wallet_keyring::{
    KeyLifecycle, KeyStorageBinding, KeyringRuntimeBinding, WalletKeyring, WalletKeyringError,
};
use crate::wallet_signing_protocol::{SigningPackageV1, SigningProtocolError};
use crate::{Node, NodeError, WalletPaymentPlan};

/// Path-only activation inputs. The keyring passphrase is intentionally
/// supplied separately so it is never retained in this clonable config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeCustodyV3Config {
    journal_key_file: PathBuf,
    external_anchor_file: PathBuf,
    policy_file: PathBuf,
    keyring_file: PathBuf,
    keyring_anchor_file: PathBuf,
}

impl ExchangeCustodyV3Config {
    pub fn new(
        journal_key_file: impl Into<PathBuf>,
        external_anchor_file: impl Into<PathBuf>,
        policy_file: impl Into<PathBuf>,
        keyring_file: impl Into<PathBuf>,
        keyring_anchor_file: impl Into<PathBuf>,
    ) -> Self {
        Self {
            journal_key_file: journal_key_file.into(),
            external_anchor_file: external_anchor_file.into(),
            policy_file: policy_file.into(),
            keyring_file: keyring_file.into(),
            keyring_anchor_file: keyring_anchor_file.into(),
        }
    }

    pub fn journal_key_file(&self) -> &Path {
        &self.journal_key_file
    }
    pub fn external_anchor_file(&self) -> &Path {
        &self.external_anchor_file
    }
    pub fn policy_file(&self) -> &Path {
        &self.policy_file
    }
    pub fn keyring_file(&self) -> &Path {
        &self.keyring_file
    }
    pub fn keyring_anchor_file(&self) -> &Path {
        &self.keyring_anchor_file
    }
}

#[derive(Debug, Error)]
pub(crate) enum ExchangeCustodyRuntimeV3Error {
    #[error(transparent)]
    Store(#[from] ExchangeCustodyV3Error),
    #[error(transparent)]
    Engine(#[from] ExchangeCustodyEngineError),
    #[error(transparent)]
    Policy(#[from] ExchangePolicyError),
    #[error(transparent)]
    Keyring(#[from] WalletKeyringError),
    #[error(transparent)]
    SigningProtocol(#[from] SigningProtocolError),
    #[error(transparent)]
    Node(#[from] NodeError),
    #[error("shared node mutex is poisoned")]
    NodePoisoned,
    #[error("exchange custody v3 runtime does not match the live node")]
    NodeBindingMismatch,
    #[error("exchange custody v3 keyring and policy wallet bindings do not match")]
    WalletBindingMismatch,
    #[error("withdrawal request conflicts with its durable record")]
    RequestConflict,
    #[error("withdrawal request is unknown")]
    UnknownRequest,
    #[error("withdrawal has no durable signer package")]
    MissingSignerPackage,
    #[error(
        "withdrawal signing package is not available until ReleaseAuthorized is externally pinned"
    )]
    SigningNotAuthorized,
    #[error("durable released transaction is invalid")]
    InvalidReleasedTransaction,
    #[error("withdrawal is canceled")]
    Canceled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeWithdrawalPhaseV3 {
    Intent,
    Prepared,
    ReleaseAuthorized,
    Released,
    Canceled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeWithdrawalStatusV3 {
    Intent,
    Prepared,
    ReleaseAuthorized,
    BroadcastPending,
    InMempool,
    Confirmed,
    Conflicted,
    Canceled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeWithdrawalViewV3 {
    pub current_anchor: JournalAnchorV3,
    pub phase: RuntimeWithdrawalPhaseV3,
    pub status: RuntimeWithdrawalStatusV3,
    pub request_id: String,
    pub request_digest: [u8; 32],
    pub destination: [u8; 32],
    pub amount_atoms: u64,
    pub fee_atoms: u64,
    pub change_atoms: u64,
    pub signing_digest: [u8; 32],
    pub signer_package_digest: Option<[u8; 32]>,
    pub signer_package_bytes: Option<Vec<u8>>,
    pub prepared_anchor: Option<JournalAnchorV3>,
    pub reserved_inputs: Vec<(OutPoint, u64)>,
    pub decision_id: Option<[u8; 32]>,
    pub approval_digest: Option<[u8; 32]>,
    pub action_anchor: Option<JournalAnchorV3>,
    pub authorized_at_unix_seconds: Option<u64>,
    pub accounted_at_unix_seconds: Option<u64>,
    pub txid: Option<[u8; 32]>,
    pub transaction_bytes: Option<Vec<u8>>,
    pub confirmations: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeJournalInfoV3 {
    pub current_anchor: JournalAnchorV3,
    pub external_anchor: JournalAnchorV3,
    pub relationship: ExternalAnchorRelationshipV3,
    pub policy_id: [u8; 32],
    pub active_keyring: KeyringAnchorV3,
    pub policy_time_watermark_unix_seconds: u64,
    pub policy_release_event_count: usize,
    pub live_record_count: usize,
    pub live_record_limit: usize,
    pub tombstone_count: usize,
    pub tombstone_limit: usize,
    pub commitment_count: usize,
    pub commitment_limit: usize,
    /// Conservative estimate assuming five journal transitions for a new
    /// prepare/authorize/complete release.
    pub estimated_full_release_capacity_remaining: usize,
    pub capacity_warning: bool,
    pub redundancy_degraded: bool,
    pub faulted: bool,
}

pub(crate) struct ExchangeCustodyRuntimeV3 {
    store: ExchangeCustodyV3Store,
    policy: WithdrawalPolicy,
    keyring: WalletKeyring,
    data_dir: PathBuf,
    external_anchor_file: PathBuf,
    _node_lease: RetainedRuntimeLease<Mutex<Node>>,
}

/// Lifetime marker for a claimed custody wallet. Dropping an RPC/runtime
/// owner intentionally drops only its weak reference: it must never mutate a
/// still-live Node's claim or reservation set. Process shutdown drops the Node
/// itself; listener-only shutdown remains fail-closed.
struct RetainedRuntimeLease<T> {
    _owner: Weak<T>,
}

impl<T> RetainedRuntimeLease<T> {
    fn new(owner: &Arc<T>) -> Self {
        Self {
            _owner: Arc::downgrade(owner),
        }
    }
}

impl ExchangeCustodyRuntimeV3 {
    pub(crate) fn open_from_passphrase_file(
        shared: &Arc<Mutex<Node>>,
        config: &ExchangeCustodyV3Config,
        keyring_passphrase_file: &Path,
    ) -> Result<Self, ExchangeCustodyRuntimeV3Error> {
        let data_dir = shared
            .lock()
            .map_err(|_| ExchangeCustodyRuntimeV3Error::NodePoisoned)?
            .data_dir
            .clone();
        let passphrase = load_keyring_passphrase_v3(&data_dir, keyring_passphrase_file)?;
        Self::open(shared, config, &passphrase)
    }

    pub(crate) fn open(
        shared: &Arc<Mutex<Node>>,
        config: &ExchangeCustodyV3Config,
        keyring_passphrase: &[u8],
    ) -> Result<Self, ExchangeCustodyRuntimeV3Error> {
        let (data_dir, binding) = {
            let node = shared
                .lock()
                .map_err(|_| ExchangeCustodyRuntimeV3Error::NodePoisoned)?;
            (
                node.data_dir.clone(),
                JournalBindingV3 {
                    network_id: node.params.network_id,
                    consensus_fingerprint: node.fingerprint,
                    genesis: node.params.genesis_hash,
                },
            )
        };
        let keyring_binding = KeyringRuntimeBinding {
            network_id: binding.network_id,
            consensus_fingerprint: binding.consensus_fingerprint,
            genesis_hash: binding.genesis,
        };
        let trusted_keyring_anchor =
            load_keyring_anchor_v3(&data_dir, config.keyring_anchor_file())?;
        let envelope = load_keyring_envelope_v3(config.keyring_file())?;
        let keyring = WalletKeyring::decode_live(
            &envelope,
            keyring_binding,
            keyring_passphrase,
            trusted_keyring_anchor,
        )?;
        let active_change_key = keyring.active_change_key();
        if active_change_key.storage == KeyStorageBinding::WatchOnly {
            return Err(ExchangeCustodyRuntimeV3Error::WalletBindingMismatch);
        }
        let policy_bytes = load_policy_document_v3(&data_dir, config.policy_file())?;
        let policy = WithdrawalPolicy::parse(
            &policy_bytes,
            WithdrawalPolicyBinding {
                network_id: binding.network_id,
                consensus_fingerprint: binding.consensus_fingerprint,
                genesis_hash: binding.genesis,
                wallet_destination: active_change_key.public_key,
            },
        )?;
        let active_keyring = keyring_anchor_v3_from_v1(keyring.anchor(), binding)?;
        let store = ExchangeCustodyV3Store::open(&ExchangeCustodyV3OpenConfig {
            data_dir: data_dir.clone(),
            journal_key_file: config.journal_key_file().to_path_buf(),
            external_anchor_file: config.external_anchor_file().to_path_buf(),
            expected_binding: binding,
            expected_policy_id: policy.policy_id(),
            expected_active_keyring: active_keyring,
        })?;
        let mut runtime = Self {
            store,
            policy,
            keyring,
            data_dir,
            external_anchor_file: config.external_anchor_file().to_path_buf(),
            _node_lease: RetainedRuntimeLease::new(shared),
        };
        let mut node = shared
            .lock()
            .map_err(|_| ExchangeCustodyRuntimeV3Error::NodePoisoned)?;
        runtime.check_node_binding(&node)?;
        node.claim_exchange_custody_v3_wallet()?;
        // Claim acquisition is itself a one-way runtime boundary. Once
        // startup has claimed the wallet, any restoration/replay failure
        // leaves the live Node claimed with the strongest reservations
        // installed so far. Reopening native wallet mutation here would turn
        // a startup fault into a double-spend window.
        runtime.restore_and_reconcile_locked(&mut node)?;
        runtime.install_active_reservations_locked(&mut node);
        drop(node);
        Ok(runtime)
    }

    pub(crate) fn prepare(
        &mut self,
        shared: &Arc<Mutex<Node>>,
        request: &WithdrawalRequest,
    ) -> Result<RuntimeWithdrawalViewV3, ExchangeCustodyRuntimeV3Error> {
        let mut node = self.lock_bound_node(shared)?;
        let expected = self.store.require_external_anchor_current()?;
        let plan = match self.store.journal().records.get(&request.request_id) {
            Some(record) => {
                require_request_match(record, request)?;
                if matches!(
                    record.phase,
                    WithdrawalPhaseV3::ReleaseAuthorized(_)
                        | WithdrawalPhaseV3::Released(_)
                        | WithdrawalPhaseV3::Canceled(_)
                ) {
                    return Err(ExchangeCustodyEngineError::TerminalConflict.into());
                }
                reconstruct_plan(record, self.store.journal().binding, &self.keyring)?
            }
            None => custody_plan_from_wallet(
                &request.request_id,
                node.plan_exchange_custody_payment(
                    request.destination,
                    request.amount_atoms,
                    request.fee_atoms,
                    &signable_keyring_destinations(&self.keyring),
                    self.keyring.active_change_key().public_key,
                )?,
            ),
        };
        let candidate = {
            let engine = ExchangeCustodyEngineV3::new(
                self.store.journal(),
                self.store.journal_key(),
                expected,
                &self.policy,
                &self.keyring,
            )?;
            engine.prepare(expected, &plan)?
        };
        if candidate.changed {
            after_durable_commit(
                self.store
                    .commit_candidate(expected, candidate.journal)
                    .map_err(ExchangeCustodyRuntimeV3Error::from),
                |_| {
                    self.install_active_reservations_locked(&mut node);
                    Ok(())
                },
            )?;
        }
        self.view_locked(&mut node, &request.request_id, None)
    }

    pub(crate) fn approval_payload(
        &self,
        shared: &Arc<Mutex<Node>>,
        action: CustodyTerminalActionV3,
        request_id: &str,
        decision_id: [u8; 32],
        authorized_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<UnsignedApprovalDocumentV3, ExchangeCustodyRuntimeV3Error> {
        let node = self.lock_bound_node(shared)?;
        let expected = self.store.require_external_anchor_current()?;
        let engine = ExchangeCustodyEngineV3::new(
            self.store.journal(),
            self.store.journal_key(),
            expected,
            &self.policy,
            &self.keyring,
        )?;
        let result = engine.unsigned_approval_document(
            expected,
            action,
            request_id,
            decision_id,
            authorized_at_unix_seconds,
            expires_at_unix_seconds,
        )?;
        drop(node);
        Ok(result)
    }

    /// Production entrypoint: captures the trusted clock only after both the
    /// custody-runtime mutex (held by the caller) and live-node mutex are held.
    pub(crate) fn release_with_current_time(
        &mut self,
        shared: &Arc<Mutex<Node>>,
        request_id: &str,
        signed_approval_document: &[u8],
        external_response_bytes: &[Vec<u8>],
    ) -> Result<RuntimeWithdrawalViewV3, ExchangeCustodyRuntimeV3Error> {
        let mut node = self.lock_bound_node(shared)?;
        let local_now_unix_seconds = crate::unix_time_seconds()?;
        self.release_with_external_responses_locked(
            &mut node,
            request_id,
            signed_approval_document,
            local_now_unix_seconds,
            external_response_bytes,
        )
    }

    fn release_with_external_responses_locked(
        &mut self,
        node: &mut Node,
        request_id: &str,
        signed_approval_document: &[u8],
        local_now_unix_seconds: u64,
        external_response_bytes: &[Vec<u8>],
    ) -> Result<RuntimeWithdrawalViewV3, ExchangeCustodyRuntimeV3Error> {
        match self
            .store
            .journal()
            .records
            .get(request_id)
            .map(|record| &record.phase)
        {
            Some(WithdrawalPhaseV3::Prepared(_)) => {
                if !external_response_bytes.is_empty() {
                    return Err(ExchangeCustodyRuntimeV3Error::SigningNotAuthorized);
                }
                let expected = self.store.require_external_anchor_current()?;
                let candidate = {
                    let engine = ExchangeCustodyEngineV3::new(
                        self.store.journal(),
                        self.store.journal_key(),
                        expected,
                        &self.policy,
                        &self.keyring,
                    )?;
                    engine.authorize_release(
                        request_id,
                        signed_approval_document,
                        local_now_unix_seconds,
                    )?
                };
                if candidate.changed {
                    self.store.commit_candidate(expected, candidate.journal)?;
                }
                // Authorization and signing are deliberately separate durable
                // operations. The operator must first pin this newly
                // persisted ReleaseAuthorized anchor before an exact retry may
                // enter the signing/completion path.
                return self.view_locked(node, request_id, None);
            }
            Some(WithdrawalPhaseV3::ReleaseAuthorized(_)) => {
                verify_persisted_terminal_approval(
                    self.store.journal(),
                    &self.policy,
                    request_id,
                    CustodyTerminalActionV3::Release,
                    signed_approval_document,
                )?;
            }
            Some(WithdrawalPhaseV3::Released(_)) => {
                verify_persisted_terminal_approval(
                    self.store.journal(),
                    &self.policy,
                    request_id,
                    CustodyTerminalActionV3::Release,
                    signed_approval_document,
                )?;
            }
            Some(WithdrawalPhaseV3::Canceled(_)) => {
                return Err(ExchangeCustodyRuntimeV3Error::Canceled);
            }
            Some(WithdrawalPhaseV3::Intent) => {
                return Err(ExchangeCustodyEngineError::InvalidPhase.into());
            }
            None => return Err(ExchangeCustodyRuntimeV3Error::UnknownRequest),
        }
        self.complete_locked(node, request_id, external_response_bytes)
    }

    /// Production cancellation entrypoint with the same post-lock trusted
    /// clock boundary as release authorization.
    pub(crate) fn cancel_with_current_time(
        &mut self,
        shared: &Arc<Mutex<Node>>,
        request_id: &str,
        signed_approval_document: &[u8],
    ) -> Result<RuntimeWithdrawalViewV3, ExchangeCustodyRuntimeV3Error> {
        let mut node = self.lock_bound_node(shared)?;
        let local_now_unix_seconds = crate::unix_time_seconds()?;
        self.cancel_locked(
            &mut node,
            request_id,
            signed_approval_document,
            local_now_unix_seconds,
        )
    }

    fn cancel_locked(
        &mut self,
        node: &mut Node,
        request_id: &str,
        signed_approval_document: &[u8],
        local_now_unix_seconds: u64,
    ) -> Result<RuntimeWithdrawalViewV3, ExchangeCustodyRuntimeV3Error> {
        if let Some(record) = self.store.journal().records.get(request_id)
            && let WithdrawalPhaseV3::Canceled(_) = &record.phase
        {
            verify_persisted_terminal_approval(
                self.store.journal(),
                &self.policy,
                request_id,
                CustodyTerminalActionV3::Cancel,
                signed_approval_document,
            )?;
            return self.view_locked(node, request_id, None);
        }
        let expected = self.store.require_external_anchor_current()?;
        let candidate = {
            let engine = ExchangeCustodyEngineV3::new(
                self.store.journal(),
                self.store.journal_key(),
                expected,
                &self.policy,
                &self.keyring,
            )?;
            engine.cancel(request_id, signed_approval_document, local_now_unix_seconds)?
        };
        if candidate.changed {
            after_durable_commit(
                self.store
                    .commit_candidate(expected, candidate.journal)
                    .map_err(ExchangeCustodyRuntimeV3Error::from),
                |_| {
                    self.install_active_reservations_locked(node);
                    Ok(())
                },
            )?;
        }
        self.view_locked(node, request_id, None)
    }

    pub(crate) fn get(
        &self,
        shared: &Arc<Mutex<Node>>,
        request_id: &str,
    ) -> Result<Option<RuntimeWithdrawalViewV3>, ExchangeCustodyRuntimeV3Error> {
        if !self.store.journal().records.contains_key(request_id) {
            return Ok(None);
        }
        let mut node = self.lock_bound_node(shared)?;
        self.view_locked(&mut node, request_id, None).map(Some)
    }

    /// Returns signer material only after the ReleaseAuthorized state and its
    /// independent external anchor are identical. This prevents an RPC caller
    /// from obtaining a signable package before the durable authorization
    /// boundary has been pinned.
    pub(crate) fn authorized_signing_package(
        &self,
        shared: &Arc<Mutex<Node>>,
        request_id: &str,
        signed_approval_document: &[u8],
    ) -> Result<RuntimeWithdrawalViewV3, ExchangeCustodyRuntimeV3Error> {
        let mut node = self.lock_bound_node(shared)?;
        self.store.require_external_anchor_current()?;
        let record = self
            .store
            .journal()
            .records
            .get(request_id)
            .ok_or(ExchangeCustodyRuntimeV3Error::UnknownRequest)?;
        if !matches!(record.phase, WithdrawalPhaseV3::ReleaseAuthorized(_)) {
            return Err(ExchangeCustodyRuntimeV3Error::SigningNotAuthorized);
        }
        verify_persisted_terminal_approval(
            self.store.journal(),
            &self.policy,
            request_id,
            CustodyTerminalActionV3::Release,
            signed_approval_document,
        )?;
        self.view_locked(&mut node, request_id, None)
    }

    pub(crate) fn info(
        &self,
        shared: &Arc<Mutex<Node>>,
    ) -> Result<RuntimeJournalInfoV3, ExchangeCustodyRuntimeV3Error> {
        let node = self.lock_bound_node(shared)?;
        let current_anchor = self.store.current_anchor()?;
        let external_anchor = load_external_anchor_v3(&self.data_dir, &self.external_anchor_file)?;
        let relationship = self.store.external_anchor_relationship()?;
        let live_record_count = self.store.journal().records.len();
        let tombstone_count = self.store.journal().tombstones.len();
        let commitment_count = self.store.journal().prior_commitments.len();
        let estimated_full_release_capacity_remaining = MAX_V3_WITHDRAWAL_RECORDS
            .saturating_sub(live_record_count)
            .min(MAX_V3_COMMITMENTS.saturating_sub(commitment_count) / 5);
        drop(node);
        Ok(RuntimeJournalInfoV3 {
            current_anchor,
            external_anchor,
            relationship,
            policy_id: self.store.journal().policy_id,
            active_keyring: self.store.journal().active_keyring,
            policy_time_watermark_unix_seconds: self
                .store
                .journal()
                .policy_window
                .time_watermark_unix_seconds,
            policy_release_event_count: self.store.journal().policy_window.release_events.len(),
            live_record_count,
            live_record_limit: MAX_V3_WITHDRAWAL_RECORDS,
            tombstone_count,
            tombstone_limit: MAX_V3_TOMBSTONES,
            commitment_count,
            commitment_limit: MAX_V3_COMMITMENTS,
            estimated_full_release_capacity_remaining,
            capacity_warning: estimated_full_release_capacity_remaining < 1_024,
            redundancy_degraded: self.store.redundancy_degraded(),
            faulted: self.store.is_faulted(),
        })
    }

    fn complete_locked(
        &mut self,
        node: &mut Node,
        request_id: &str,
        external_response_bytes: &[Vec<u8>],
    ) -> Result<RuntimeWithdrawalViewV3, ExchangeCustodyRuntimeV3Error> {
        if matches!(
            self.store
                .journal()
                .records
                .get(request_id)
                .map(|record| &record.phase),
            Some(WithdrawalPhaseV3::Released(_))
        ) {
            self.install_replay_reservations_locked(node);
            let reconciled = self.reconcile_one_locked(node, request_id);
            self.install_active_reservations_locked(node);
            let status = reconciled?;
            return self.view_locked(node, request_id, Some(status));
        }
        let record = self
            .store
            .journal()
            .records
            .get(request_id)
            .ok_or(ExchangeCustodyRuntimeV3Error::UnknownRequest)?;
        let plan = reconstruct_plan(record, self.store.journal().binding, &self.keyring)?;
        let authorized_anchor = self.store.current_anchor()?;
        let external = self.store.require_external_anchor_current()?;
        let candidate = {
            let engine = AuthorizedReleaseCompletionEngineV3::new(
                self.store.journal(),
                self.store.journal_key(),
                external,
                &self.policy,
                &self.keyring,
                request_id,
            )?;
            if external_response_bytes.is_empty() {
                engine.complete(&plan, |plan| revalidate_plan(node, &self.keyring, plan))?
            } else {
                engine.complete_with_external_responses(&plan, external_response_bytes, |plan| {
                    revalidate_plan(node, &self.keyring, plan)
                })?
            }
        };
        let status = if candidate.changed {
            after_durable_commit(
                self.store
                    .commit_authorized_completion(authorized_anchor, candidate.journal)
                    .map_err(ExchangeCustodyRuntimeV3Error::from),
                |_| self.reconcile_one_locked(node, request_id),
            )?
        } else {
            self.reconcile_one_locked(node, request_id)?
        };
        self.install_active_reservations_locked(node);
        self.view_locked(node, request_id, Some(status))
    }

    fn restore_and_reconcile_locked(
        &mut self,
        node: &mut Node,
    ) -> Result<(), ExchangeCustodyRuntimeV3Error> {
        self.install_replay_reservations_locked(node);
        let released: Vec<String> = self
            .store
            .journal()
            .records
            .iter()
            .filter_map(|(id, record)| {
                matches!(record.phase, WithdrawalPhaseV3::Released(_)).then_some(id.clone())
            })
            .collect();
        for request_id in released {
            let _ = self.reconcile_one_locked(node, &request_id)?;
        }
        Ok(())
    }

    fn reconcile_one_locked(
        &self,
        node: &mut Node,
        request_id: &str,
    ) -> Result<RuntimeWithdrawalStatusV3, ExchangeCustodyRuntimeV3Error> {
        let record = self
            .store
            .journal()
            .records
            .get(request_id)
            .ok_or(ExchangeCustodyRuntimeV3Error::UnknownRequest)?;
        let WithdrawalPhaseV3::Released(released) = &record.phase else {
            return Err(ExchangeCustodyEngineError::InvalidPhase.into());
        };
        let external = load_external_anchor_v3(&self.data_dir, &self.external_anchor_file)?;
        require_exact_released_replay_anchor(
            self.store.journal(),
            self.store.journal_key(),
            record,
            external,
        )?;
        let txids = HashSet::from([released.txid]);
        if node
            .active_transaction_confirmations_for(&txids)?
            .contains_key(&released.txid)
        {
            return Ok(RuntimeWithdrawalStatusV3::Confirmed);
        }
        if node.mempool_contains_transaction(released.txid) {
            return Ok(RuntimeWithdrawalStatusV3::InMempool);
        }
        let transaction = validate_released_transaction(record, self.store.journal().binding)?;
        match node.submit_exchange_withdrawal_transaction(transaction) {
            Ok(_) | Err(NodeError::DuplicateMempoolTransaction(_)) => {
                Ok(RuntimeWithdrawalStatusV3::InMempool)
            }
            Err(NodeError::MempoolTransactionLimit | NodeError::MempoolByteLimit) => {
                Ok(RuntimeWithdrawalStatusV3::BroadcastPending)
            }
            Err(NodeError::MempoolInputConflict(_) | NodeError::MempoolUnconfirmedInput(_)) => {
                Ok(RuntimeWithdrawalStatusV3::Conflicted)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn view_locked(
        &self,
        node: &mut Node,
        request_id: &str,
        status_override: Option<RuntimeWithdrawalStatusV3>,
    ) -> Result<RuntimeWithdrawalViewV3, ExchangeCustodyRuntimeV3Error> {
        let record = self
            .store
            .journal()
            .records
            .get(request_id)
            .ok_or(ExchangeCustodyRuntimeV3Error::UnknownRequest)?;
        let (phase, default_status, evidence, terminal, txid, transaction_bytes) =
            match &record.phase {
                WithdrawalPhaseV3::Intent => (
                    RuntimeWithdrawalPhaseV3::Intent,
                    RuntimeWithdrawalStatusV3::Intent,
                    None,
                    None,
                    None,
                    None,
                ),
                WithdrawalPhaseV3::Prepared(prepared) => (
                    RuntimeWithdrawalPhaseV3::Prepared,
                    RuntimeWithdrawalStatusV3::Prepared,
                    prepared.signer_package.as_ref(),
                    None,
                    None,
                    None,
                ),
                WithdrawalPhaseV3::ReleaseAuthorized(authorized) => (
                    RuntimeWithdrawalPhaseV3::ReleaseAuthorized,
                    RuntimeWithdrawalStatusV3::ReleaseAuthorized,
                    authorized.prepared.signer_package.as_ref(),
                    Some(&authorized.terminal),
                    None,
                    None,
                ),
                WithdrawalPhaseV3::Released(released) => (
                    RuntimeWithdrawalPhaseV3::Released,
                    RuntimeWithdrawalStatusV3::BroadcastPending,
                    released.prepared.signer_package.as_ref(),
                    Some(&released.terminal),
                    Some(released.txid),
                    Some(released.exact_transaction.bytes.clone()),
                ),
                WithdrawalPhaseV3::Canceled(canceled) => (
                    RuntimeWithdrawalPhaseV3::Canceled,
                    RuntimeWithdrawalStatusV3::Canceled,
                    canceled
                        .prepared
                        .as_ref()
                        .and_then(|prepared| prepared.signer_package.as_ref()),
                    Some(&canceled.terminal),
                    None,
                    None,
                ),
            };
        let chain_confirmations = if let Some(txid) = txid {
            let confirmations =
                node.active_transaction_confirmations_for(&HashSet::from([txid]))?;
            confirmations.get(&txid).copied()
        } else {
            None
        };
        let (status, confirmations) = if let Some(value) = chain_confirmations {
            (RuntimeWithdrawalStatusV3::Confirmed, Some(value))
        } else if let Some(status) = status_override {
            (status, None)
        } else if txid.is_some_and(|txid| node.mempool_contains_transaction(txid)) {
            (RuntimeWithdrawalStatusV3::InMempool, None)
        } else {
            (default_status, None)
        };
        Ok(RuntimeWithdrawalViewV3 {
            current_anchor: self.store.current_anchor()?,
            phase,
            status,
            request_id: record.core.request_id.clone(),
            request_digest: record.core.request_digest,
            destination: record.core.destination,
            amount_atoms: record.core.amount_atoms,
            fee_atoms: record.core.fee_atoms,
            change_atoms: record.core.change_atoms,
            signing_digest: record.core.signing_digest,
            signer_package_digest: evidence.map(|value| value.exact_package.digest),
            signer_package_bytes: evidence.map(|value| value.exact_package.bytes.clone()),
            prepared_anchor: evidence.map(|value| value.prepared_anchor),
            reserved_inputs: record
                .core
                .reservations
                .iter()
                .map(|input| {
                    (
                        OutPoint {
                            txid: input.outpoint.txid,
                            index: input.outpoint.index,
                        },
                        input.value_atoms,
                    )
                })
                .collect(),
            decision_id: terminal.map(|value| value.decision_id),
            approval_digest: terminal.map(|value| value.approval_digest),
            action_anchor: terminal.map(|value| value.action_anchor),
            authorized_at_unix_seconds: terminal.map(|value| value.decided_at_unix_seconds),
            accounted_at_unix_seconds: terminal.map(|value| value.accounted_at_unix_seconds),
            txid,
            transaction_bytes,
            confirmations,
        })
    }

    fn install_active_reservations_locked(&self, node: &mut Node) {
        // Released inputs remain reserved for exact replay until an explicit
        // authenticated finality transition exists. If the transaction is
        // confirmed those outpoints are absent from the active UTXO set, so
        // retaining the stale reservation is harmless; dropping it while a
        // broadcast is pending or conflicted would permit a second plan to
        // select the same live input.
        self.install_reservations_locked(node);
    }

    fn install_replay_reservations_locked(&self, node: &mut Node) {
        self.install_reservations_locked(node);
    }

    fn install_reservations_locked(&self, node: &mut Node) {
        let reservations = self
            .store
            .startup_reservations()
            .into_iter()
            .map(|reserved| {
                (
                    OutPoint {
                        txid: reserved.outpoint.txid,
                        index: reserved.outpoint.index,
                    },
                    reserved.signing_digest,
                )
            })
            .collect();
        node.set_exchange_withdrawal_reservations(reservations);
    }

    fn lock_bound_node<'a>(
        &self,
        shared: &'a Arc<Mutex<Node>>,
    ) -> Result<std::sync::MutexGuard<'a, Node>, ExchangeCustodyRuntimeV3Error> {
        let node = shared
            .lock()
            .map_err(|_| ExchangeCustodyRuntimeV3Error::NodePoisoned)?;
        self.check_node_binding(&node)?;
        if !node.exchange_custody_v3_wallet_is_active() {
            return Err(ExchangeCustodyRuntimeV3Error::NodeBindingMismatch);
        }
        Ok(node)
    }

    fn check_node_binding(&self, node: &Node) -> Result<(), ExchangeCustodyRuntimeV3Error> {
        let binding = self.store.journal().binding;
        if node.data_dir != self.data_dir
            || node.params.network_id != binding.network_id
            || node.fingerprint != binding.consensus_fingerprint
            || node.params.genesis_hash != binding.genesis
        {
            return Err(ExchangeCustodyRuntimeV3Error::NodeBindingMismatch);
        }
        if self.policy.binding.wallet_destination != self.keyring.active_change_key().public_key {
            return Err(ExchangeCustodyRuntimeV3Error::WalletBindingMismatch);
        }
        if node.storage_faulted {
            return Err(NodeError::StorageFaulted.into());
        }
        Ok(())
    }
}

/// Runs a reservation update, reconciliation, or broadcast attempt only after
/// the durability boundary has returned success. Keeping this tiny sequencing
/// primitive explicit makes the two security-sensitive call sites testable
/// without a production-ACL store fixture.
fn after_durable_commit<T, U, E>(
    commit_result: Result<T, E>,
    after_commit: impl FnOnce(T) -> Result<U, E>,
) -> Result<U, E> {
    after_commit(commit_result?)
}

fn require_request_match(
    record: &WithdrawalRecordV3,
    request: &WithdrawalRequest,
) -> Result<(), ExchangeCustodyRuntimeV3Error> {
    if record.core.request_id != request.request_id
        || record.core.destination != request.destination
        || record.core.amount_atoms != request.amount_atoms
        || record.core.fee_atoms != request.fee_atoms
    {
        return Err(ExchangeCustodyRuntimeV3Error::RequestConflict);
    }
    Ok(())
}

fn custody_plan_from_wallet(request_id: &str, plan: WalletPaymentPlan) -> CustodyPaymentPlanV3 {
    CustodyPaymentPlanV3 {
        request_id: request_id.to_owned(),
        transaction: plan.transaction,
        recipient: plan.recipient,
        amount_atoms: plan.amount_atoms,
        fee_atoms: plan.fee_burned_atoms,
        change_atoms: plan.change_atoms,
        selected_input_values: plan.selected_input_values,
        output_spendable_height: plan.output_spendable_height,
    }
}

fn reconstruct_plan(
    record: &WithdrawalRecordV3,
    binding: JournalBindingV3,
    keyring: &WalletKeyring,
) -> Result<CustodyPaymentPlanV3, ExchangeCustodyRuntimeV3Error> {
    let (transaction, selected_input_values) = if let Some(evidence) = signer_evidence(record) {
        let package = SigningPackageV1::decode(&evidence.exact_package.bytes)?;
        let transaction = package.transaction()?;
        if package.request_id != record.core.request_id
            || package.request_digest != record.core.request_digest
            || package.signing_digest != record.core.signing_digest
            || transaction.signing_digest() != record.core.signing_digest
            || package.network_id != binding.network_id
            || package.consensus_fingerprint != binding.consensus_fingerprint
            || package.genesis != binding.genesis
            || package.keyring_anchor != keyring.anchor().signing_protocol_anchor()
            || package.inputs.len() != transaction.inputs.len()
        {
            return Err(ExchangeCustodyRuntimeV3Error::MissingSignerPackage);
        }
        let selected = package
            .inputs
            .iter()
            .map(|input| input.value_atoms)
            .collect();
        (transaction, selected)
    } else {
        let inputs = record
            .core
            .reservations
            .iter()
            .map(|reserved| TxInput {
                previous: OutPoint {
                    txid: reserved.outpoint.txid,
                    index: reserved.outpoint.index,
                },
                witness: InputWitness::Key {
                    public_key: reserved.public_key,
                    signature: Vec::new(),
                },
            })
            .collect();
        let mut outputs = vec![TxOutput {
            value: record.core.amount_atoms,
            lock: OutputLock::Key(record.core.destination),
            spendable_height: record.core.output_spendable_height,
        }];
        if record.core.change_atoms > 0 {
            outputs.push(TxOutput {
                value: record.core.change_atoms,
                lock: OutputLock::Key(keyring.active_change_key().public_key),
                spendable_height: record.core.output_spendable_height,
            });
        }
        let transaction = Transaction {
            network_id: binding.network_id,
            version: TRANSACTION_VERSION,
            inputs,
            outputs,
        };
        if transaction.signing_digest() != record.core.signing_digest {
            return Err(ExchangeCustodyRuntimeV3Error::MissingSignerPackage);
        }
        let selected = record
            .core
            .reservations
            .iter()
            .map(|input| input.value_atoms)
            .collect();
        (transaction, selected)
    };
    Ok(CustodyPaymentPlanV3 {
        request_id: record.core.request_id.clone(),
        transaction,
        recipient: record.core.destination,
        amount_atoms: record.core.amount_atoms,
        fee_atoms: record.core.fee_atoms,
        change_atoms: record.core.change_atoms,
        selected_input_values,
        output_spendable_height: record.core.output_spendable_height,
    })
}

fn signer_evidence(record: &WithdrawalRecordV3) -> Option<&SignerPackageEvidenceV3> {
    match &record.phase {
        WithdrawalPhaseV3::Prepared(prepared) => prepared.signer_package.as_ref(),
        WithdrawalPhaseV3::ReleaseAuthorized(authorized) => {
            authorized.prepared.signer_package.as_ref()
        }
        WithdrawalPhaseV3::Released(released) => released.prepared.signer_package.as_ref(),
        WithdrawalPhaseV3::Canceled(canceled) => {
            canceled.prepared.as_ref()?.signer_package.as_ref()
        }
        WithdrawalPhaseV3::Intent => None,
    }
}

fn signable_keyring_destinations(keyring: &WalletKeyring) -> Vec<[u8; 32]> {
    keyring
        .summaries()
        .into_iter()
        .filter(|key| {
            key.lifecycle != KeyLifecycle::Disabled && key.storage != KeyStorageBinding::WatchOnly
        })
        .map(|key| key.public_key)
        .collect()
}

fn revalidate_plan(node: &Node, keyring: &WalletKeyring, plan: &CustodyPaymentPlanV3) -> bool {
    let mut transaction = plan.transaction.clone();
    for input in &mut transaction.inputs {
        let InputWitness::Key { signature, .. } = &mut input.witness else {
            return false;
        };
        // The durable signing package canonically stores fixed-width zero
        // placeholders. Node wallet validation expects the equivalent
        // in-memory unsigned representation.
        if signature.iter().any(|byte| *byte != 0) {
            return false;
        }
        signature.clear();
    }
    let wallet_plan = WalletPaymentPlan {
        transaction,
        recipient: plan.recipient,
        amount_atoms: plan.amount_atoms,
        fee_burned_atoms: plan.fee_atoms,
        change_atoms: plan.change_atoms,
        selected_input_values: plan.selected_input_values.clone(),
        output_spendable_height: plan.output_spendable_height,
    };
    node.validate_exchange_custody_payment_plan(
        &wallet_plan,
        &signable_keyring_destinations(keyring),
        keyring.active_change_key().public_key,
    )
    .is_ok()
        && plan.transaction.inputs.iter().all(|input| {
            node.exchange_withdrawal_reservations.get(&input.previous)
                == Some(&plan.transaction.signing_digest())
        })
}

fn validate_released_transaction(
    record: &WithdrawalRecordV3,
    binding: JournalBindingV3,
) -> Result<Transaction, ExchangeCustodyRuntimeV3Error> {
    let WithdrawalPhaseV3::Released(released) = &record.phase else {
        return Err(ExchangeCustodyRuntimeV3Error::InvalidReleasedTransaction);
    };
    let transaction = decode_transaction(&released.exact_transaction.bytes, binding.network_id)
        .map_err(NodeError::from)?;
    if encode_transaction(&transaction).map_err(NodeError::from)?
        != released.exact_transaction.bytes
        || transaction.txid() != released.txid
        || transaction.signing_digest() != record.core.signing_digest
        || transaction.network_id != binding.network_id
        || transaction.version != TRANSACTION_VERSION
        || transaction.inputs.len() != record.core.reservations.len()
    {
        return Err(ExchangeCustodyRuntimeV3Error::InvalidReleasedTransaction);
    }
    let reserved: HashSet<_> = record
        .core
        .reservations
        .iter()
        .map(|input| OutPoint {
            txid: input.outpoint.txid,
            index: input.outpoint.index,
        })
        .collect();
    if transaction
        .inputs
        .iter()
        .any(|input| !reserved.contains(&input.previous))
    {
        return Err(ExchangeCustodyRuntimeV3Error::InvalidReleasedTransaction);
    }
    Ok(transaction)
}

fn require_exact_released_replay_anchor(
    journal: &crate::exchange_withdrawal_v3::ExchangeWithdrawalJournalV3,
    journal_key: &[u8; 32],
    record: &WithdrawalRecordV3,
    external: JournalAnchorV3,
) -> Result<(), ExchangeCustodyRuntimeV3Error> {
    let WithdrawalPhaseV3::Released(released) = &record.phase else {
        return Err(ExchangeCustodyRuntimeV3Error::InvalidReleasedTransaction);
    };
    // Native releases first became replayable at their ReleaseAuthorized v3
    // generation. Migrated records were imported already Released, so their
    // foreign v2 action-anchor generation must never be compared to the v3
    // generation space; the authenticated v3 migration snapshot is generation 1.
    let first_authenticated_replay_generation = match (&record.origin, released.terminal.scope) {
        (RecordOriginV3::NativeV3, DecisionScopeV3::NativeV3) => released
            .terminal
            .action_anchor
            .generation
            .checked_add(1)
            .ok_or(ExchangeCustodyRuntimeV3Error::InvalidReleasedTransaction)?,
        (RecordOriginV3::ValidatedV2 { .. }, DecisionScopeV3::ValidatedV2Migration) => 1,
        _ => return Err(ExchangeCustodyRuntimeV3Error::InvalidReleasedTransaction),
    };
    if external.generation < first_authenticated_replay_generation {
        return Err(ExchangeCustodyV3Error::ExternalAnchorMismatch.into());
    }
    let authenticated_external = journal
        .anchor_at(journal_key, external.generation)
        .map_err(|_| ExchangeCustodyV3Error::ExternalAnchorMismatch)?;
    if external != authenticated_external {
        return Err(ExchangeCustodyV3Error::ExternalAnchorMismatch.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    use k256::schnorr::{Signature, SigningKey, signature::Signer};
    use serde_json::{Value, json};
    use zeroize::Zeroizing;

    use super::*;
    use crate::exchange_policy::{ApprovalRule, WithdrawalPolicyBinding};
    use crate::exchange_withdrawal_v3::{
        ExchangeWithdrawalJournalV3, PolicyReleaseEventV3, PolicyWindowStateV3, TerminalDecisionV3,
        ValidatedV2MigrationInputV3, ValidatedV2ReleasedRecordV3, WithdrawalActionV3,
        migrate_validated_v2,
    };
    use crate::wallet_keyring::{KeyLifecycle, KeyRoles, WalletKeyEntry};

    const JOURNAL_KEY: [u8; 32] = [0xa5; 32];
    const RELEASE_APPROVER: u8 = 0x11;
    const CANCEL_APPROVER: u8 = 0x22;

    fn marker(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn signing_key(value: u8) -> SigningKey {
        SigningKey::from_bytes(&marker(value)).expect("test scalar is valid")
    }

    fn public_key(value: u8) -> [u8; 32] {
        signing_key(value).verifying_key().to_bytes().into()
    }

    fn runtime_binding() -> KeyringRuntimeBinding {
        KeyringRuntimeBinding {
            network_id: marker(1),
            consensus_fingerprint: marker(2),
            genesis_hash: marker(3),
        }
    }

    fn journal_binding() -> JournalBindingV3 {
        let binding = runtime_binding();
        JournalBindingV3 {
            network_id: binding.network_id,
            consensus_fingerprint: binding.consensus_fingerprint,
            genesis: binding.genesis_hash,
        }
    }

    fn keyring() -> WalletKeyring {
        WalletKeyring::new_genesis(
            runtime_binding(),
            marker(0x40),
            vec![
                WalletKeyEntry::local(
                    Zeroizing::new(marker(7)),
                    KeyRoles::DEPOSIT.union(KeyRoles::CHANGE),
                    KeyLifecycle::Active,
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    fn policy(keyring: &WalletKeyring) -> WithdrawalPolicy {
        WithdrawalPolicy {
            binding: WithdrawalPolicyBinding {
                network_id: runtime_binding().network_id,
                consensus_fingerprint: runtime_binding().consensus_fingerprint,
                genesis_hash: runtime_binding().genesis_hash,
                wallet_destination: keyring.active_change_key().public_key,
            },
            max_single_amount_atoms: 1_000,
            max_single_fee_atoms: 25,
            max_single_debit_atoms: 1_025,
            max_rolling_24h_debit_atoms: 5_000,
            max_rolling_24h_release_count: 8,
            release_approval: ApprovalRule {
                threshold: 1,
                public_keys: vec![public_key(RELEASE_APPROVER)],
            },
            cancel_approval: ApprovalRule {
                threshold: 1,
                public_keys: vec![public_key(CANCEL_APPROVER)],
            },
        }
    }

    fn initial_journal(
        keyring: &WalletKeyring,
        policy: &WithdrawalPolicy,
    ) -> ExchangeWithdrawalJournalV3 {
        let source_anchor = JournalAnchorV3 {
            key_id: marker(0x31),
            journal_instance_id: marker(0x32),
            generation: 7,
            commitment: marker(0x33),
        };
        let keyring_anchor = keyring.anchor();
        migrate_validated_v2(
            ValidatedV2MigrationInputV3 {
                source_schema_version: 2,
                source_snapshot_digest: marker(0x34),
                source_current_anchor: source_anchor,
                source_external_anchor: source_anchor,
                migration_id: marker(0x35),
                migration_decision_id: marker(0x36),
                migration_approval_digest: marker(0x37),
                binding: journal_binding(),
                new_journal_instance_id: marker(0x38),
                policy_id: policy.policy_id(),
                initial_policy_window: PolicyWindowStateV3 {
                    time_watermark_unix_seconds: 10,
                    release_events: Vec::new(),
                },
                active_keyring: KeyringAnchorV3 {
                    instance_id: keyring_anchor.instance_id,
                    generation: keyring_anchor.generation,
                    commitment: keyring_anchor.commitment,
                },
                released_records: Vec::new(),
            },
            &JOURNAL_KEY,
        )
        .unwrap()
        .journal
    }

    fn engine<'a>(
        journal: &'a ExchangeWithdrawalJournalV3,
        policy: &'a WithdrawalPolicy,
        keyring: &'a WalletKeyring,
    ) -> ExchangeCustodyEngineV3<'a> {
        ExchangeCustodyEngineV3::new(
            journal,
            &JOURNAL_KEY,
            journal.anchor(&JOURNAL_KEY).unwrap(),
            policy,
            keyring,
        )
        .unwrap()
    }

    fn payment_plan(keyring: &WalletKeyring, request_id: &str) -> CustodyPaymentPlanV3 {
        let amount_atoms = 700;
        let fee_atoms = 20;
        let change_atoms = 280;
        let recipient = public_key(0x23);
        CustodyPaymentPlanV3 {
            request_id: request_id.to_owned(),
            transaction: Transaction {
                network_id: runtime_binding().network_id,
                version: TRANSACTION_VERSION,
                inputs: vec![TxInput {
                    previous: OutPoint {
                        txid: marker(0x50),
                        index: 0,
                    },
                    witness: InputWitness::Key {
                        public_key: keyring.active_change_key().public_key,
                        signature: Vec::new(),
                    },
                }],
                outputs: vec![
                    TxOutput {
                        value: amount_atoms,
                        lock: OutputLock::Key(recipient),
                        spendable_height: 44,
                    },
                    TxOutput {
                        value: change_atoms,
                        lock: OutputLock::Key(keyring.active_change_key().public_key),
                        spendable_height: 44,
                    },
                ],
            },
            recipient,
            amount_atoms,
            fee_atoms,
            change_atoms,
            selected_input_values: vec![1_000],
            output_spendable_height: 44,
        }
    }

    fn signed_approval(
        engine: &ExchangeCustodyEngineV3<'_>,
        action: CustodyTerminalActionV3,
        request_id: &str,
        decision_marker: u8,
        authorized_at: u64,
        expires_at: u64,
        signer_marker: u8,
    ) -> Vec<u8> {
        let unsigned = engine
            .unsigned_approval_document(
                engine.current_anchor().unwrap(),
                action,
                request_id,
                marker(decision_marker),
                authorized_at,
                expires_at,
            )
            .unwrap();
        let signature: Signature = signing_key(signer_marker).sign(&unsigned.signing_digest);
        let mut document: Value = serde_json::from_slice(&unsigned.document).unwrap();
        document["signatures"] = json!([{
            "public_key": hex::encode(public_key(signer_marker)),
            "signature": hex::encode(signature.to_bytes()),
        }]);
        serde_json::to_vec(&document).unwrap()
    }

    fn prepared(
        journal: &ExchangeWithdrawalJournalV3,
        policy: &WithdrawalPolicy,
        keyring: &WalletKeyring,
        plan: &CustodyPaymentPlanV3,
    ) -> crate::exchange_custody_engine::PreparedCustodyCandidateV3 {
        let engine = engine(journal, policy, keyring);
        engine
            .prepare(engine.current_anchor().unwrap(), plan)
            .unwrap()
    }

    fn authorize(
        prepared: &ExchangeWithdrawalJournalV3,
        policy: &WithdrawalPolicy,
        keyring: &WalletKeyring,
        request_id: &str,
        approval: &[u8],
    ) -> crate::exchange_custody_engine::AuthorizedReleaseCustodyCandidateV3 {
        engine(prepared, policy, keyring)
            .authorize_release(request_id, approval, 100)
            .unwrap()
    }

    #[test]
    fn prepared_is_not_submittable_and_restart_reconstructs_the_exact_plan() {
        let keyring = keyring();
        let policy = policy(&keyring);
        let journal = initial_journal(&keyring, &policy);
        let plan = payment_plan(&keyring, "withdrawal-runtime-0001");
        let prepared = prepared(&journal, &policy, &keyring, &plan);
        let record = &prepared.journal.records[&plan.request_id];

        assert!(matches!(record.phase, WithdrawalPhaseV3::Prepared(_)));
        assert!(matches!(
            validate_released_transaction(record, journal_binding()),
            Err(ExchangeCustodyRuntimeV3Error::InvalidReleasedTransaction)
        ));
        let reconstructed = reconstruct_plan(record, journal_binding(), &keyring).unwrap();
        assert_eq!(reconstructed.request_id, plan.request_id);
        assert_eq!(reconstructed.recipient, plan.recipient);
        assert_eq!(reconstructed.amount_atoms, plan.amount_atoms);
        assert_eq!(reconstructed.fee_atoms, plan.fee_atoms);
        assert_eq!(reconstructed.change_atoms, plan.change_atoms);
        assert_eq!(
            reconstructed.transaction.signing_digest(),
            plan.transaction.signing_digest()
        );
        assert!(reconstructed.transaction.inputs.iter().all(|input| {
            matches!(
                &input.witness,
                InputWitness::Key { signature, .. }
                    if signature.len() == 64 && signature.iter().all(|byte| *byte == 0)
            )
        }));
        assert!(!journal.records.contains_key(&plan.request_id));
    }

    #[test]
    fn cancel_crosses_durability_boundary_before_reservations_can_be_released() {
        let keyring = keyring();
        let policy = policy(&keyring);
        let journal = initial_journal(&keyring, &policy);
        let plan = payment_plan(&keyring, "withdrawal-runtime-0002");
        let prepared_candidate = prepared(&journal, &policy, &keyring, &plan);
        let prepared_engine = engine(&prepared_candidate.journal, &policy, &keyring);
        let approval = signed_approval(
            &prepared_engine,
            CustodyTerminalActionV3::Cancel,
            &plan.request_id,
            0x51,
            100,
            200,
            CANCEL_APPROVER,
        );
        let canceled = prepared_engine
            .cancel(&plan.request_id, &approval, 150)
            .unwrap();

        assert!(matches!(
            prepared_candidate.journal.records[&plan.request_id].phase,
            WithdrawalPhaseV3::Prepared(_)
        ));
        assert!(matches!(
            canceled.journal.records[&plan.request_id].phase,
            WithdrawalPhaseV3::Canceled(_)
        ));

        let trace = RefCell::new(Vec::new());
        let refreshed = Cell::new(false);
        after_durable_commit::<_, _, &'static str>(
            {
                trace.borrow_mut().push("persist-canceled");
                Ok(canceled.journal.anchor(&JOURNAL_KEY).unwrap())
            },
            |_| {
                trace.borrow_mut().push("release-reservations");
                refreshed.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            trace.into_inner(),
            vec!["persist-canceled", "release-reservations"]
        );
        assert!(refreshed.get());

        let refreshed = Cell::new(false);
        let result = after_durable_commit::<(), (), _>(Err("disk-failure"), |_| {
            refreshed.set(true);
            Ok(())
        });
        assert_eq!(result, Err("disk-failure"));
        assert!(!refreshed.get());

        let replacement_plan = payment_plan(&keyring, "withdrawal-runtime-0002-replacement");
        let replacement = prepared(&canceled.journal, &policy, &keyring, &replacement_plan);
        assert_eq!(
            replacement.journal.records[&replacement_plan.request_id]
                .core
                .reservations[0]
                .outpoint,
            canceled.journal.records[&plan.request_id].core.reservations[0].outpoint
        );
        assert!(matches!(
            replacement.journal.records[&replacement_plan.request_id].phase,
            WithdrawalPhaseV3::Prepared(_)
        ));
    }

    #[test]
    fn release_is_two_step_and_exact_bytes_are_durable_before_submission() {
        let keyring = keyring();
        let policy = policy(&keyring);
        let journal = initial_journal(&keyring, &policy);
        let plan = payment_plan(&keyring, "withdrawal-runtime-0003");
        let prepared_candidate = prepared(&journal, &policy, &keyring, &plan);
        let prepared_engine = engine(&prepared_candidate.journal, &policy, &keyring);
        let approval = signed_approval(
            &prepared_engine,
            CustodyTerminalActionV3::Release,
            &plan.request_id,
            0x52,
            100,
            200,
            RELEASE_APPROVER,
        );
        let authorized = authorize(
            &prepared_candidate.journal,
            &policy,
            &keyring,
            &plan.request_id,
            &approval,
        );

        let authorized_record = &authorized.journal.records[&plan.request_id];
        let WithdrawalPhaseV3::ReleaseAuthorized(authorized_phase) = &authorized_record.phase
        else {
            panic!("expected ReleaseAuthorized")
        };
        assert_eq!(
            prepared_candidate.candidate_anchor.generation,
            prepared_candidate.prepared_anchor.generation + 1
        );
        assert_eq!(
            authorized_phase.terminal.action_anchor,
            prepared_candidate.candidate_anchor
        );
        assert!(matches!(
            validate_released_transaction(authorized_record, journal_binding()),
            Err(ExchangeCustodyRuntimeV3Error::InvalidReleasedTransaction)
        ));

        let authorized_anchor = authorized.journal.anchor(&JOURNAL_KEY).unwrap();
        assert_eq!(
            authorized_anchor.generation,
            authorized_phase.terminal.action_anchor.generation + 1
        );
        let completion = AuthorizedReleaseCompletionEngineV3::new(
            &authorized.journal,
            &JOURNAL_KEY,
            authorized_anchor,
            &policy,
            &keyring,
            &plan.request_id,
        )
        .unwrap()
        .complete(&plan, |_| true)
        .unwrap();
        let released_record = &completion.journal.records[&plan.request_id];
        let WithdrawalPhaseV3::Released(released_phase) = &released_record.phase else {
            panic!("expected Released")
        };
        assert!(matches!(
            require_exact_released_replay_anchor(
                &completion.journal,
                &JOURNAL_KEY,
                released_record,
                released_phase.terminal.action_anchor,
            ),
            Err(ExchangeCustodyRuntimeV3Error::Store(
                ExchangeCustodyV3Error::ExternalAnchorMismatch
            ))
        ));
        require_exact_released_replay_anchor(
            &completion.journal,
            &JOURNAL_KEY,
            released_record,
            authorized_anchor,
        )
        .unwrap();
        require_exact_released_replay_anchor(
            &completion.journal,
            &JOURNAL_KEY,
            released_record,
            completion.journal.anchor(&JOURNAL_KEY).unwrap(),
        )
        .unwrap();

        let mut later_plan = payment_plan(&keyring, "withdrawal-runtime-0003-later");
        later_plan.transaction.inputs[0].previous.txid = marker(0x55);
        let later = prepared(&completion.journal, &policy, &keyring, &later_plan);
        let original_record = &later.journal.records[&plan.request_id];
        require_exact_released_replay_anchor(
            &later.journal,
            &JOURNAL_KEY,
            original_record,
            later.journal.anchor(&JOURNAL_KEY).unwrap(),
        )
        .unwrap();

        let durable = RefCell::new(None::<ExchangeWithdrawalJournalV3>);
        let submitted = Cell::new(false);
        let trace = RefCell::new(Vec::new());

        let submitted_txid = after_durable_commit::<_, _, &'static str>(
            {
                trace.borrow_mut().push("persist-released");
                durable.replace(Some(completion.journal.clone()));
                Ok(completion.txid)
            },
            |txid| {
                trace.borrow_mut().push("submit-exact");
                let durable = durable.borrow();
                let record = &durable.as_ref().unwrap().records[&plan.request_id];
                let transaction = validate_released_transaction(record, journal_binding())
                    .map_err(|_| "invalid-durable-transaction")?;
                let WithdrawalPhaseV3::Released(released) = &record.phase else {
                    return Err("not-released");
                };
                assert_eq!(
                    released.exact_transaction.bytes,
                    completion.exact_transaction_bytes
                );
                assert_eq!(transaction.txid(), txid);
                submitted.set(true);
                Ok(txid)
            },
        )
        .unwrap();

        assert_eq!(submitted_txid, completion.txid);
        assert!(submitted.get());
        assert_eq!(trace.into_inner(), vec!["persist-released", "submit-exact"]);

        let submitted = Cell::new(false);
        let result = after_durable_commit::<(), (), _>(Err("disk-failure"), |_| {
            submitted.set(true);
            Ok(())
        });
        assert_eq!(result, Err("disk-failure"));
        assert!(!submitted.get());

        let duplicate_plan = payment_plan(&keyring, "withdrawal-runtime-0003-duplicate");
        let released_engine = engine(&completion.journal, &policy, &keyring);
        assert!(matches!(
            released_engine.prepare(released_engine.current_anchor().unwrap(), &duplicate_plan,),
            Err(ExchangeCustodyEngineError::Journal(_))
        ));
    }

    #[test]
    fn migrated_v2_released_record_replays_from_its_v3_anchor_with_exact_bytes() {
        let keyring = keyring();
        let policy = policy(&keyring);
        let base = initial_journal(&keyring, &policy);
        let plan = payment_plan(&keyring, "withdrawal-runtime-migrated");
        let prepared_candidate = prepared(&base, &policy, &keyring, &plan);
        let prepared_engine = engine(&prepared_candidate.journal, &policy, &keyring);
        let approval = signed_approval(
            &prepared_engine,
            CustodyTerminalActionV3::Release,
            &plan.request_id,
            0x56,
            100,
            200,
            RELEASE_APPROVER,
        );
        let authorized = authorize(
            &prepared_candidate.journal,
            &policy,
            &keyring,
            &plan.request_id,
            &approval,
        );
        let authorized_anchor = authorized.journal.anchor(&JOURNAL_KEY).unwrap();
        let native = AuthorizedReleaseCompletionEngineV3::new(
            &authorized.journal,
            &JOURNAL_KEY,
            authorized_anchor,
            &policy,
            &keyring,
            &plan.request_id,
        )
        .unwrap()
        .complete(&plan, |_| true)
        .unwrap();
        let native_record = &native.journal.records[&plan.request_id];
        let WithdrawalPhaseV3::Released(native_released) = &native_record.phase else {
            panic!("expected native Released record")
        };
        let source_anchor = base.migration.source_anchor;
        let migrated = migrate_validated_v2(
            ValidatedV2MigrationInputV3 {
                source_schema_version: 2,
                source_snapshot_digest: marker(0x57),
                source_current_anchor: source_anchor,
                source_external_anchor: source_anchor,
                migration_id: marker(0x58),
                migration_decision_id: marker(0x59),
                migration_approval_digest: marker(0x5a),
                binding: journal_binding(),
                new_journal_instance_id: marker(0x5b),
                policy_id: policy.policy_id(),
                initial_policy_window: PolicyWindowStateV3 {
                    time_watermark_unix_seconds: 100,
                    release_events: vec![PolicyReleaseEventV3 {
                        request_digest: native_record.core.request_digest,
                        released_at_unix_seconds: 100,
                        debit_atoms: native_released.debit_atoms,
                    }],
                },
                active_keyring: KeyringAnchorV3 {
                    instance_id: keyring.anchor().instance_id,
                    generation: keyring.anchor().generation,
                    commitment: keyring.anchor().commitment,
                },
                released_records: vec![ValidatedV2ReleasedRecordV3 {
                    core: native_record.core.clone(),
                    source_prepared_generation: source_anchor.generation,
                    source_record_digest: marker(0x5c),
                    terminal: TerminalDecisionV3 {
                        scope: DecisionScopeV3::ValidatedV2Migration,
                        action: WithdrawalActionV3::Release,
                        decision_id: marker(0x5d),
                        approval_digest: marker(0x5e),
                        policy_id: policy.policy_id(),
                        action_anchor: source_anchor,
                        request_digest: native_record.core.request_digest,
                        transaction_signing_digest: native_record.core.signing_digest,
                        decided_at_unix_seconds: 100,
                        accounted_at_unix_seconds: 100,
                    },
                    txid: native_released.txid,
                    exact_transaction_bytes: native_released.exact_transaction.bytes.clone(),
                    debit_atoms: native_released.debit_atoms,
                }],
            },
            &JOURNAL_KEY,
        )
        .unwrap()
        .journal;
        let migrated_record = &migrated.records[&plan.request_id];
        let v3_anchor = migrated.anchor(&JOURNAL_KEY).unwrap();

        require_exact_released_replay_anchor(&migrated, &JOURNAL_KEY, migrated_record, v3_anchor)
            .unwrap();
        assert!(matches!(
            require_exact_released_replay_anchor(
                &migrated,
                &JOURNAL_KEY,
                migrated_record,
                source_anchor,
            ),
            Err(ExchangeCustodyRuntimeV3Error::Store(
                ExchangeCustodyV3Error::ExternalAnchorMismatch
            ))
        ));
        let replay = validate_released_transaction(migrated_record, journal_binding()).unwrap();
        assert_eq!(replay.txid(), native_released.txid);
        assert_eq!(
            encode_transaction(&replay).unwrap(),
            native_released.exact_transaction.bytes
        );
        assert_eq!(replay.signing_digest(), migrated_record.core.signing_digest);

        let mut later_plan = payment_plan(&keyring, "withdrawal-runtime-after-migration");
        later_plan.transaction.inputs[0].previous.txid = marker(0x5f);
        let later = prepared(&migrated, &policy, &keyring, &later_plan);
        let later_migrated_record = &later.journal.records[&plan.request_id];
        require_exact_released_replay_anchor(
            &later.journal,
            &JOURNAL_KEY,
            later_migrated_record,
            later.journal.anchor(&JOURNAL_KEY).unwrap(),
        )
        .unwrap();
        let later_replay =
            validate_released_transaction(later_migrated_record, journal_binding()).unwrap();
        assert_eq!(
            encode_transaction(&later_replay).unwrap(),
            native_released.exact_transaction.bytes
        );
    }

    #[test]
    fn dropping_runtime_lease_retains_claim_and_replay_reservations() {
        #[derive(Debug, PartialEq, Eq)]
        struct NodeLeaseProbe {
            claimed: bool,
            phase: RuntimeWithdrawalPhaseV3,
            reservations: HashMap<OutPoint, [u8; 32]>,
        }

        let outpoint = OutPoint {
            txid: marker(0x77),
            index: 3,
        };
        let owner = Arc::new(Mutex::new(NodeLeaseProbe {
            claimed: true,
            phase: RuntimeWithdrawalPhaseV3::Released,
            reservations: HashMap::from([(outpoint, marker(0x78))]),
        }));
        {
            let lease = RetainedRuntimeLease::new(&owner);
            drop(lease);
        }

        let retained = owner.lock().unwrap();
        assert!(retained.claimed);
        assert_eq!(retained.phase, RuntimeWithdrawalPhaseV3::Released);
        assert_eq!(retained.reservations.get(&outpoint), Some(&marker(0x78)));
    }

    #[test]
    fn startup_failure_after_claim_remains_fail_closed() {
        #[derive(Debug)]
        struct StartupProbe {
            claimed: bool,
            reservations: HashMap<OutPoint, [u8; 32]>,
        }

        let outpoint = OutPoint {
            txid: marker(0x79),
            index: 4,
        };
        let owner = Arc::new(Mutex::new(StartupProbe {
            claimed: false,
            reservations: HashMap::new(),
        }));
        let startup: Result<(), &'static str> = {
            let _runtime_lease = RetainedRuntimeLease::new(&owner);
            let mut node = owner.lock().unwrap();
            node.claimed = true;
            node.reservations.insert(outpoint, marker(0x7a));
            drop(node);
            Err("reconcile-failed")
        };

        assert_eq!(startup, Err("reconcile-failed"));
        let retained = owner.lock().unwrap();
        assert!(retained.claimed);
        assert_eq!(retained.reservations.get(&outpoint), Some(&marker(0x7a)));
    }

    #[test]
    fn persisted_release_approval_retries_after_expiry_but_rejects_any_other_approval() {
        let keyring = keyring();
        let policy = policy(&keyring);
        let journal = initial_journal(&keyring, &policy);
        let plan = payment_plan(&keyring, "withdrawal-runtime-0004");
        let prepared = prepared(&journal, &policy, &keyring, &plan);
        let prepared_engine = engine(&prepared.journal, &policy, &keyring);
        let exact = signed_approval(
            &prepared_engine,
            CustodyTerminalActionV3::Release,
            &plan.request_id,
            0x53,
            100,
            101,
            RELEASE_APPROVER,
        );
        let different = signed_approval(
            &prepared_engine,
            CustodyTerminalActionV3::Release,
            &plan.request_id,
            0x54,
            100,
            101,
            RELEASE_APPROVER,
        );
        let authorized = authorize(
            &prepared.journal,
            &policy,
            &keyring,
            &plan.request_id,
            &exact,
        );

        // The expiry was 101 and authorization happened at local time 100.
        // Persisted-terminal verification deliberately reuses the durable
        // decision rather than reapplying an already-consumed expiry gate.
        let parsed = crate::exchange_policy::WithdrawalApproval::parse(&exact).unwrap();
        assert_eq!(parsed.expires_at_unix_seconds, 101);
        let expired_retry = engine(&authorized.journal, &policy, &keyring)
            .authorize_release(&plan.request_id, &exact, 10_000)
            .unwrap();
        assert!(!expired_retry.changed);
        verify_persisted_terminal_approval(
            &authorized.journal,
            &policy,
            &plan.request_id,
            CustodyTerminalActionV3::Release,
            &exact,
        )
        .unwrap();
        assert!(matches!(
            verify_persisted_terminal_approval(
                &authorized.journal,
                &policy,
                &plan.request_id,
                CustodyTerminalActionV3::Release,
                &different,
            ),
            Err(ExchangeCustodyEngineError::TerminalConflict)
        ));

        let authorized_anchor = authorized.journal.anchor(&JOURNAL_KEY).unwrap();
        let released = AuthorizedReleaseCompletionEngineV3::new(
            &authorized.journal,
            &JOURNAL_KEY,
            authorized_anchor,
            &policy,
            &keyring,
            &plan.request_id,
        )
        .unwrap()
        .complete(&plan, |_| true)
        .unwrap();
        verify_persisted_terminal_approval(
            &released.journal,
            &policy,
            &plan.request_id,
            CustodyTerminalActionV3::Release,
            &exact,
        )
        .unwrap();
        assert!(matches!(
            verify_persisted_terminal_approval(
                &released.journal,
                &policy,
                &plan.request_id,
                CustodyTerminalActionV3::Release,
                &different,
            ),
            Err(ExchangeCustodyEngineError::TerminalConflict)
        ));
    }
}
