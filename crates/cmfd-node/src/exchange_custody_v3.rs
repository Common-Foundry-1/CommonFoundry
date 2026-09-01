//! File-backed activation boundary for the exchange-withdrawal v3 state machine.
//!
//! The pure journal module returns authenticated candidate states. This module
//! is the only place that publishes those candidates into the two active
//! `exchange-withdrawals.{0,1}.bin` slots. A candidate is never installed in
//! memory until its slot replacement and parent-directory synchronization have
//! succeeded. Any uncertain persistence result permanently faults the opened
//! store until restart.
//!
//! Policy, rollback-anchor, keyring-envelope, and keyring-anchor files are
//! read-only inputs here. In particular, this module never advances an external
//! rollback anchor: an operator-controlled process must pin the returned anchor
//! before another transition can commit.

#[cfg(unix)]
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use blake3::Hasher;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::exchange_policy::MAX_POLICY_DOCUMENT_BYTES;
use crate::exchange_withdrawal::{EXCHANGE_WITHDRAWAL_FILE_PREFIX, WithdrawalJournalAnchor};
#[cfg(test)]
use crate::exchange_withdrawal_v3::JournalTransitionV3;
use crate::exchange_withdrawal_v3::{
    ExchangeWithdrawalJournalV3, ExchangeWithdrawalV3Error, JournalAnchorV3, JournalBindingV3,
    KeyringAnchorV3, MAX_V3_SNAPSHOT_BYTES, MigrationOutputV3, ReservedOutpointV3,
    ValidatedV2MigrationInputV3, WithdrawalPhaseV3, derive_authorized_completion,
    migrate_validated_v2, validate_authorized_completion, validated_v2_snapshot_digest,
};
use crate::wallet_backup::{MAXIMUM_PASSPHRASE_BYTES, MINIMUM_PASSPHRASE_BYTES};
use crate::wallet_keyring::{
    KEYRING_ANCHOR_BYTES, KeyringAnchorV1, MAX_KEYRING_ENVELOPE_BYTES, WalletKeyringError,
};

const V3_MARKER_FILE: &str = "exchange-withdrawals.v3.initialized";
const V3_LOCK_FILE: &str = "exchange-withdrawals.v3.lock";
const LEGACY_V2_MARKER_FILE: &str = "exchange-withdrawals.initialized";
const SNAPSHOT_MAGIC: [u8; 8] = *b"CMFDEXW\0";
const V3_MARKER_MAGIC: [u8; 8] = *b"CMFDEX3\0";
const V3_VERSION: u32 = 3;
const LEGACY_V1_VERSION: u32 = 1;
const LEGACY_V2_VERSION: u32 = 2;
const MARKER_AUTH_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-MARKER/AUTH/V3";
const MARKER_PAYLOAD_BYTES: usize = 8 + 4 + (32 * 3) + 32 + 32 + 32 + (32 + 32 + 8 + 32);
const MARKER_BYTES: usize = MARKER_PAYLOAD_BYTES + 32;
const MINIMUM_SNAPSHOT_BYTES: usize = 8 + 4 + 8 + 32;
const MAX_EXTERNAL_ANCHOR_BYTES: usize = 4 * 1024;
const MAX_LEGACY_MARKER_BYTES: usize = 4 * 1024;
const MAX_ATOMIC_TRANSITIONS: usize = 3;

/// Returns true once this data directory contains the v3 activation commit
/// point. Any inspection error other than absence is treated as enrolled so an
/// unreadable or substituted marker cannot silently reopen the native wallet.
pub(crate) fn persisted_v3_wallet_claim_required(data_dir: &Path) -> bool {
    match fs::symlink_metadata(data_dir.join(V3_MARKER_FILE)) {
        Ok(_) => return true,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return true,
    }
    (0..=1).any(|slot| persisted_slot_requires_v3_claim(&snapshot_path(data_dir, slot)))
}

fn persisted_slot_requires_v3_claim(path: &Path) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    if !metadata.file_type().is_file() || metadata_is_symlink_or_reparse(&metadata) {
        return true;
    }
    let mut file = match open_read_only(path) {
        Ok(file) => file,
        Err(_) => return true,
    };
    let mut header = [0_u8; 12];
    if file.read_exact(&mut header).is_err() || header[..8] != SNAPSHOT_MAGIC {
        return true;
    }
    !matches!(
        u32::from_le_bytes(header[8..12].try_into().expect("fixed snapshot header")),
        LEGACY_V1_VERSION | LEGACY_V2_VERSION
    )
}

#[derive(Debug, Error)]
pub(crate) enum ExchangeCustodyV3Error {
    #[error("exchange custody v3 I/O failed during {operation} for `{path}`")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("exchange custody v3 requires an existing regular data directory")]
    InvalidDataDirectory,
    #[error("{0} must be an absolute regular file")]
    InvalidControlPath(&'static str),
    #[error("{0} must be outside the node data directory")]
    ControlInsideDataDirectory(&'static str),
    #[error("{0} exceeds its byte limit or has an invalid length")]
    InvalidControlLength(&'static str),
    #[error("the exchange custody v3 journal key is invalid")]
    InvalidJournalKey,
    #[error("the exchange custody v3 journal key is not owner-only")]
    #[cfg_attr(windows, allow(dead_code))]
    InsecureJournalKeyPermissions,
    #[error("the external exchange custody v3 anchor is invalid")]
    InvalidExternalAnchor,
    #[error("the external exchange custody v3 anchor is not in the loaded journal history")]
    ExternalAnchorMismatch,
    #[error("the external exchange custody v3 anchor is ahead of the loaded journal")]
    ExternalAnchorAhead,
    #[error(
        "the external exchange custody v3 anchor must exactly equal the current journal anchor"
    )]
    ExternalAnchorNotCurrent,
    #[error("exchange custody v3 belongs to another runtime binding")]
    BindingMismatch,
    #[error("exchange custody v3 belongs to another policy")]
    PolicyMismatch,
    #[error("exchange custody v3 belongs to another active keyring")]
    KeyringMismatch,
    #[error("exchange custody v3 is not initialized")]
    NotInitialized,
    #[error("exchange custody v3 activation is incomplete because its marker is missing")]
    ActivationIncomplete,
    #[error("a v1/v2 withdrawal journal requires explicit offline v3 migration")]
    ExplicitMigrationRequired,
    #[error("legacy and v3 withdrawal snapshots are mixed")]
    MixedSnapshotVersions,
    #[error("exchange custody v3 durable state is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("another process holds the exchange custody v3 storage lock")]
    Busy,
    #[error("exchange custody v3 storage is faulted and requires restart")]
    Faulted,
    #[error("an atomic exchange custody v3 transition batch must contain between 1 and 3 items")]
    #[cfg(test)]
    InvalidTransitionBatch,
    #[error("the exchange custody v3 candidate does not extend current state: {0}")]
    InvalidCandidateExtension(&'static str),
    #[error("the v2-to-v3 migration contract is invalid: {0}")]
    InvalidMigration(&'static str),
    #[error("the v2-to-v3 migration layout changed or cannot be resumed safely")]
    MigrationLayoutChanged,
    #[error("exchange custody v3 is already initialized with another migration")]
    AlreadyInitialized,
    #[error(transparent)]
    Journal(#[from] ExchangeWithdrawalV3Error),
    #[error(transparent)]
    Keyring(#[from] WalletKeyringError),
    #[cfg(windows)]
    #[error(transparent)]
    WindowsAcl(#[from] crate::exchange_acl::WindowsCustodyAclError),
    #[cfg(test)]
    #[error("injected exchange custody v3 persistence failure")]
    InjectedPersistenceFailure,
}

pub(crate) struct LoadedJournalKeyV3(Zeroizing<[u8; 32]>);

impl fmt::Debug for LoadedJournalKeyV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoadedJournalKeyV3(<redacted>)")
    }
}

impl LoadedJournalKeyV3 {
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExchangeCustodyV3OpenConfig {
    pub data_dir: PathBuf,
    pub journal_key_file: PathBuf,
    pub external_anchor_file: PathBuf,
    pub expected_binding: JournalBindingV3,
    pub expected_policy_id: [u8; 32],
    pub expected_active_keyring: KeyringAnchorV3,
}

#[derive(Debug, Clone)]
pub(crate) struct MigrationPlanV3Config {
    pub data_dir: PathBuf,
    pub journal_key_file: PathBuf,
    /// Exact v2 bytes that the caller has already authenticated and validated
    /// with the v2 decoder. This file must be immutable to the node process.
    pub validated_v2_snapshot_file: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalAnchorRelationshipV3 {
    Current,
    Descendant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupReservationPhaseV3 {
    Intent,
    Prepared,
    ReleaseAuthorized,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupReservationV3 {
    pub request_id: String,
    pub request_digest: [u8; 32],
    pub signing_digest: [u8; 32],
    pub outpoint: ReservedOutpointV3,
    pub phase: StartupReservationPhaseV3,
}

pub(crate) struct ExchangeCustodyV3Store {
    data_dir: PathBuf,
    external_anchor_file: PathBuf,
    journal_key: LoadedJournalKeyV3,
    state: ExchangeWithdrawalJournalV3,
    _storage_lock: File,
    redundancy_degraded: bool,
    faulted: bool,
    security: FileSecurity,
    #[cfg(test)]
    fail_next_persistence: bool,
}

impl fmt::Debug for ExchangeCustodyV3Store {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExchangeCustodyV3Store")
            .field("data_dir", &self.data_dir)
            .field("external_anchor_file", &self.external_anchor_file)
            .field("journal_key", &"<redacted>")
            .field("generation", &self.state.generation)
            .field("redundancy_degraded", &self.redundancy_degraded)
            .field("faulted", &self.faulted)
            .finish()
    }
}

impl ExchangeCustodyV3Store {
    pub(crate) fn open(
        config: &ExchangeCustodyV3OpenConfig,
    ) -> Result<Self, ExchangeCustodyV3Error> {
        let data_dir = resolve_data_directory(&config.data_dir)?;
        let journal_key = load_journal_key_v3(&config.journal_key_file)?;
        let external_anchor_file = resolve_external_control_path(
            &data_dir,
            &config.external_anchor_file,
            "external anchor",
        )?;
        Self::open_with_material(
            data_dir,
            external_anchor_file,
            journal_key,
            config.expected_binding,
            config.expected_policy_id,
            config.expected_active_keyring,
            FileSecurity::Production,
        )
    }

    fn open_with_material(
        data_dir: PathBuf,
        external_anchor_file: PathBuf,
        journal_key: LoadedJournalKeyV3,
        expected_binding: JournalBindingV3,
        expected_policy_id: [u8; 32],
        expected_active_keyring: KeyringAnchorV3,
        security: FileSecurity,
    ) -> Result<Self, ExchangeCustodyV3Error> {
        let storage_lock = acquire_storage_lock(&data_dir, security)?;
        let marker = load_v3_marker(&data_dir, journal_key.bytes(), security)?;
        let first = load_v3_slot(&data_dir, 0, journal_key.bytes(), security)?;
        let second = load_v3_slot(&data_dir, 1, journal_key.bytes(), security)?;
        let (state, redundancy_degraded) =
            choose_active_state(first, second, marker.as_ref(), journal_key.bytes())?;
        let marker = marker.ok_or(ExchangeCustodyV3Error::ActivationIncomplete)?;
        marker.verify_state(&state, journal_key.bytes())?;
        if state.binding != expected_binding {
            return Err(ExchangeCustodyV3Error::BindingMismatch);
        }
        if state.policy_id != expected_policy_id {
            return Err(ExchangeCustodyV3Error::PolicyMismatch);
        }
        if state.active_keyring != expected_active_keyring {
            return Err(ExchangeCustodyV3Error::KeyringMismatch);
        }
        let external = load_external_anchor_from_resolved(&external_anchor_file, security)?;
        anchor_relationship(&state, journal_key.bytes(), external)?;
        Ok(Self {
            data_dir,
            external_anchor_file,
            journal_key,
            state,
            _storage_lock: storage_lock,
            redundancy_degraded,
            faulted: false,
            security,
            #[cfg(test)]
            fail_next_persistence: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn open_for_rehearsal(
        data_dir: &Path,
        external_anchor_file: &Path,
        journal_key: [u8; 32],
        expected_binding: JournalBindingV3,
        expected_policy_id: [u8; 32],
        expected_active_keyring: KeyringAnchorV3,
    ) -> Result<Self, ExchangeCustodyV3Error> {
        Self::open_with_material(
            resolve_data_directory(data_dir)?,
            resolve_existing_regular_path(external_anchor_file, "external anchor")?,
            LoadedJournalKeyV3(Zeroizing::new(journal_key)),
            expected_binding,
            expected_policy_id,
            expected_active_keyring,
            FileSecurity::PortableTest,
        )
    }

    pub(crate) fn journal(&self) -> &ExchangeWithdrawalJournalV3 {
        &self.state
    }

    /// Exposes the authenticated journal key only to the in-process custody
    /// orchestrator. It is never serialized into an RPC response or log.
    pub(crate) fn journal_key(&self) -> &[u8; 32] {
        self.journal_key.bytes()
    }

    pub(crate) fn current_anchor(&self) -> Result<JournalAnchorV3, ExchangeCustodyV3Error> {
        Ok(self.state.anchor(self.journal_key.bytes())?)
    }

    pub(crate) fn is_faulted(&self) -> bool {
        self.faulted
    }

    pub(crate) fn redundancy_degraded(&self) -> bool {
        self.redundancy_degraded
    }

    /// Reloads the operator-controlled anchor on every call. `Descendant`
    /// means this journal descends from the external anchor; it does not grant
    /// permission to mutate the journal.
    pub(crate) fn external_anchor_relationship(
        &self,
    ) -> Result<ExternalAnchorRelationshipV3, ExchangeCustodyV3Error> {
        let external =
            load_external_anchor_from_resolved(&self.external_anchor_file, self.security)?;
        anchor_relationship(&self.state, self.journal_key.bytes(), external)
    }

    pub(crate) fn require_external_anchor_current(
        &self,
    ) -> Result<JournalAnchorV3, ExchangeCustodyV3Error> {
        let external =
            load_external_anchor_from_resolved(&self.external_anchor_file, self.security)?;
        if anchor_relationship(&self.state, self.journal_key.bytes(), external)?
            != ExternalAnchorRelationshipV3::Current
        {
            return Err(ExchangeCustodyV3Error::ExternalAnchorNotCurrent);
        }
        Ok(external)
    }

    /// Applies a pure transition, publishes its authenticated candidate, and
    /// only then swaps the in-memory state. The caller must not sign, broadcast,
    /// release reservations, acknowledge success, or delete archive input until
    /// this method returns `Ok`.
    #[cfg(test)]
    pub(crate) fn commit_transition(
        &mut self,
        transition: JournalTransitionV3,
    ) -> Result<JournalAnchorV3, ExchangeCustodyV3Error> {
        self.commit_transitions(vec![transition])
    }

    /// Commits a bounded logical operation (for example
    /// AddIntent+Prepare+AttachSignerPackage) with one external-anchor check and
    /// one final durable publication. A failed middle transition has no disk or
    /// in-memory effect.
    #[cfg(test)]
    pub(crate) fn commit_transitions(
        &mut self,
        transitions: Vec<JournalTransitionV3>,
    ) -> Result<JournalAnchorV3, ExchangeCustodyV3Error> {
        if self.faulted {
            return Err(ExchangeCustodyV3Error::Faulted);
        }
        if transitions.is_empty() || transitions.len() > MAX_ATOMIC_TRANSITIONS {
            return Err(ExchangeCustodyV3Error::InvalidTransitionBatch);
        }
        let expected_current_anchor = self.current_anchor()?;
        let mut candidate = self.state.clone();
        for transition in transitions {
            candidate = candidate.apply_transition(self.journal_key.bytes(), transition)?;
        }
        self.commit_candidate(expected_current_anchor, candidate)
    }

    /// Publishes a fully validated engine candidate. This is the primary
    /// storage primitive for an orchestration layer that performs several pure
    /// journal transitions before one crash-atomic disk commit.
    pub(crate) fn commit_candidate(
        &mut self,
        expected_current_anchor: JournalAnchorV3,
        candidate: ExchangeWithdrawalJournalV3,
    ) -> Result<JournalAnchorV3, ExchangeCustodyV3Error> {
        if self.faulted {
            return Err(ExchangeCustodyV3Error::Faulted);
        }
        self.require_external_anchor_current()?;
        let current_anchor = self.current_anchor()?;
        if current_anchor != expected_current_anchor {
            return Err(ExchangeCustodyV3Error::Journal(
                ExchangeWithdrawalV3Error::AnchorMismatch,
            ));
        }
        candidate.validate(self.journal_key.bytes())?;
        validate_candidate_extension(&self.state, &candidate, current_anchor)?;
        self.publish_candidate(candidate)
    }

    /// Commits only the exact one-generation ReleaseAuthorized -> Released
    /// successor after the operator-controlled external anchor has pinned the
    /// ReleaseAuthorized generation.
    pub(crate) fn commit_authorized_completion(
        &mut self,
        expected_authorized_anchor: JournalAnchorV3,
        candidate: ExchangeWithdrawalJournalV3,
    ) -> Result<JournalAnchorV3, ExchangeCustodyV3Error> {
        if self.faulted {
            return Err(ExchangeCustodyV3Error::Faulted);
        }
        let current_anchor = self.current_anchor()?;
        if current_anchor != expected_authorized_anchor {
            return Err(ExchangeCustodyV3Error::Journal(
                ExchangeWithdrawalV3Error::AnchorMismatch,
            ));
        }
        let completion = derive_authorized_completion(&self.state, &candidate, current_anchor)?;
        validate_authorized_completion(
            &self.state,
            &candidate,
            self.journal_key.bytes(),
            &completion,
        )?;
        let external =
            load_external_anchor_from_resolved(&self.external_anchor_file, self.security)?;
        if external != current_anchor {
            return Err(ExchangeCustodyV3Error::ExternalAnchorMismatch);
        }
        anchor_relationship(&self.state, self.journal_key.bytes(), external)?;
        self.publish_candidate(candidate)
    }

    fn publish_candidate(
        &mut self,
        candidate: ExchangeWithdrawalJournalV3,
    ) -> Result<JournalAnchorV3, ExchangeCustodyV3Error> {
        let bytes = candidate.encode_authenticated(self.journal_key.bytes())?;
        let path = snapshot_path(&self.data_dir, (candidate.generation & 1) as u8);
        #[cfg(test)]
        let fail_before_publish = std::mem::take(&mut self.fail_next_persistence);
        #[cfg(not(test))]
        let fail_before_publish = false;
        if let Err(error) =
            atomic_publish_node_file(&path, &bytes, true, self.security, fail_before_publish)
        {
            self.faulted = true;
            return Err(error);
        }
        self.state = candidate;
        self.redundancy_degraded = false;
        self.current_anchor()
    }

    /// Exports wallet-planner reservations in canonical record/outpoint order.
    /// Canceled records are excluded. Released inputs remain reserved for
    /// exact replay until a future authenticated finality transition can prove
    /// that releasing them is safe.
    pub(crate) fn startup_reservations(&self) -> Vec<StartupReservationV3> {
        let mut output = Vec::new();
        for record in self.state.records.values() {
            let phase = match record.phase {
                WithdrawalPhaseV3::Intent => StartupReservationPhaseV3::Intent,
                WithdrawalPhaseV3::Prepared(_) => StartupReservationPhaseV3::Prepared,
                WithdrawalPhaseV3::ReleaseAuthorized(_) => {
                    StartupReservationPhaseV3::ReleaseAuthorized
                }
                WithdrawalPhaseV3::Released(_) => StartupReservationPhaseV3::Released,
                WithdrawalPhaseV3::Canceled(_) => continue,
            };
            output.extend(record.core.reservations.iter().map(|reservation| {
                StartupReservationV3 {
                    request_id: record.core.request_id.clone(),
                    request_digest: record.core.request_digest,
                    signing_digest: record.core.signing_digest,
                    outpoint: reservation.outpoint,
                    phase,
                }
            }));
        }
        output
    }

    #[cfg(test)]
    pub(crate) fn inject_next_persistence_failure(&mut self) {
        self.fail_next_persistence = true;
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MigrationPlanV3 {
    config: MigrationPlanV3Config,
    data_dir: PathBuf,
    validated_source_file: PathBuf,
    output: MigrationOutputV3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppliedMigrationV3 {
    pub initial_anchor: JournalAnchorV3,
    pub migration_id: [u8; 32],
    pub backup_files: Vec<PathBuf>,
    pub resumed: bool,
}

impl MigrationPlanV3 {
    #[cfg(test)]
    pub(crate) fn from_rehearsal_fixture(
        config: MigrationPlanV3Config,
        output: MigrationOutputV3,
    ) -> Result<Self, ExchangeCustodyV3Error> {
        let data_dir = resolve_data_directory(&config.data_dir)?;
        let validated_source_file = resolve_existing_regular_path(
            &config.validated_v2_snapshot_file,
            "validated v2 snapshot",
        )?;
        Ok(Self {
            config,
            data_dir,
            validated_source_file,
            output,
        })
    }

    /// Builds a read-only plan. The caller is responsible for proving that the
    /// exact source file was authenticated and semantically validated by the v2
    /// decoder before constructing `ValidatedV2MigrationInputV3`.
    pub(crate) fn build(
        config: MigrationPlanV3Config,
        input: ValidatedV2MigrationInputV3,
    ) -> Result<Self, ExchangeCustodyV3Error> {
        let data_dir = resolve_data_directory(&config.data_dir)?;
        let source = resolve_external_control_path(
            &data_dir,
            &config.validated_v2_snapshot_file,
            "validated v2 snapshot",
        )?;
        let source_bytes = read_external_control(
            &source,
            MAX_V3_SNAPSHOT_BYTES,
            "validated v2 snapshot",
            FileSecurity::Production,
        )?;
        validate_legacy_v2_snapshot_header(&source_bytes)?;
        if validated_v2_snapshot_digest(&source_bytes) != input.source_snapshot_digest {
            return Err(ExchangeCustodyV3Error::InvalidMigration(
                "validated source bytes do not match source_snapshot_digest",
            ));
        }
        let key = load_journal_key_v3(&config.journal_key_file)?;
        let output = migrate_validated_v2(input, key.bytes())?;
        verify_migration_layout_read_only(
            &data_dir,
            &output,
            &source_bytes,
            key.bytes(),
            FileSecurity::Production,
        )?;
        Ok(Self {
            config,
            data_dir,
            validated_source_file: source,
            output,
        })
    }

    pub(crate) fn initial_anchor(&self) -> JournalAnchorV3 {
        self.output.initial_anchor
    }

    pub(crate) fn receipt(&self) -> &crate::exchange_withdrawal_v3::MigrationReceiptV3 {
        &self.output.receipt
    }

    /// Applies or safely resumes the offline migration. Both active v2 slots
    /// and the legacy marker must be retained as create-new backups before the
    /// first v3 slot replacement. The authenticated v3 marker is the final
    /// activation commit point.
    pub(crate) fn apply(&self) -> Result<AppliedMigrationV3, ExchangeCustodyV3Error> {
        self.apply_with_security(FileSecurity::Production)
    }

    #[cfg(test)]
    pub(crate) fn apply_for_rehearsal(&self) -> Result<AppliedMigrationV3, ExchangeCustodyV3Error> {
        self.apply_with_security(FileSecurity::PortableTest)
    }

    fn apply_with_security(
        &self,
        security: FileSecurity,
    ) -> Result<AppliedMigrationV3, ExchangeCustodyV3Error> {
        let key = load_journal_key_v3_with_security(&self.config.journal_key_file, security)?;
        let decoded = ExchangeWithdrawalJournalV3::decode_authenticated(
            &self.output.authenticated_snapshot,
            key.bytes(),
        )?;
        if decoded != self.output.journal
            || decoded.anchor(key.bytes())? != self.output.initial_anchor
        {
            return Err(ExchangeCustodyV3Error::InvalidMigration(
                "planned v3 snapshot no longer matches its initial anchor",
            ));
        }
        let source_bytes = read_external_control(
            &self.validated_source_file,
            MAX_V3_SNAPSHOT_BYTES,
            "validated v2 snapshot",
            security,
        )?;
        validate_legacy_v2_snapshot_header(&source_bytes)?;
        if validated_v2_snapshot_digest(&source_bytes) != self.output.receipt.source_snapshot_digest
        {
            return Err(ExchangeCustodyV3Error::MigrationLayoutChanged);
        }

        let _lock = acquire_storage_lock(&self.data_dir, security)?;
        let marker = load_v3_marker(&self.data_dir, key.bytes(), security)?;
        let backup_files = migration_backup_paths(&self.data_dir, self.output.receipt.migration_id);
        if let Some(marker) = marker {
            marker.verify_output(&self.output)?;
            require_installed_initial_slots(
                &self.data_dir,
                &self.output.authenticated_snapshot,
                security,
            )?;
            return Ok(AppliedMigrationV3 {
                initial_anchor: self.output.initial_anchor,
                migration_id: self.output.receipt.migration_id,
                backup_files,
                resumed: true,
            });
        }

        let mut active = Vec::with_capacity(2);
        let mut source_seen = false;
        for slot in 0..=1 {
            let path = snapshot_path(&self.data_dir, slot);
            let bytes = read_required_node_file(
                &path,
                MAX_V3_SNAPSHOT_BYTES,
                "migration source snapshot",
                security,
            )?;
            let backup = &backup_files[usize::from(slot)];
            if is_legacy_v2_snapshot(&bytes) {
                source_seen |= validated_v2_snapshot_digest(&bytes)
                    == self.output.receipt.source_snapshot_digest;
                create_or_verify_backup(backup, &bytes, security)?;
            } else if bytes == self.output.authenticated_snapshot {
                let retained = read_required_node_file(
                    backup,
                    MAX_V3_SNAPSHOT_BYTES,
                    "retained v2 migration backup",
                    security,
                )?;
                validate_legacy_v2_snapshot_header(&retained)?;
                source_seen |= validated_v2_snapshot_digest(&retained)
                    == self.output.receipt.source_snapshot_digest;
            } else {
                return Err(ExchangeCustodyV3Error::MigrationLayoutChanged);
            }
            active.push((path, bytes));
        }

        let legacy_marker = self.data_dir.join(LEGACY_V2_MARKER_FILE);
        let legacy_marker_bytes = read_required_node_file(
            &legacy_marker,
            MAX_LEGACY_MARKER_BYTES,
            "legacy v2 marker",
            security,
        )?;
        if !has_version(&legacy_marker_bytes, LEGACY_V2_VERSION) {
            return Err(ExchangeCustodyV3Error::MigrationLayoutChanged);
        }
        create_or_verify_backup(&backup_files[2], &legacy_marker_bytes, security)?;
        if !source_seen {
            return Err(ExchangeCustodyV3Error::InvalidMigration(
                "no active or retained v2 slot matches the validated source snapshot",
            ));
        }

        let resumed = active
            .iter()
            .any(|(_, bytes)| bytes == &self.output.authenticated_snapshot);
        for (path, bytes) in active {
            if bytes != self.output.authenticated_snapshot {
                atomic_replace_node_file(&path, &self.output.authenticated_snapshot, security)?;
            }
        }
        let marker = ActivationMarkerV3::from_output(&self.output);
        atomic_create_node_file(
            &v3_marker_path(&self.data_dir),
            &marker.encode(key.bytes()),
            security,
        )?;
        Ok(AppliedMigrationV3 {
            initial_anchor: self.output.initial_anchor,
            migration_id: self.output.receipt.migration_id,
            backup_files,
            resumed,
        })
    }
}

pub(crate) fn load_journal_key_v3(
    path: &Path,
) -> Result<LoadedJournalKeyV3, ExchangeCustodyV3Error> {
    load_journal_key_v3_with_security(path, FileSecurity::Production)
}

fn load_journal_key_v3_with_security(
    path: &Path,
    security: FileSecurity,
) -> Result<LoadedJournalKeyV3, ExchangeCustodyV3Error> {
    if !path.is_absolute() {
        return Err(ExchangeCustodyV3Error::InvalidControlPath("journal key"));
    }
    let resolved = resolve_existing_regular_path(path, "journal key")?;
    let bytes = read_node_owned_secret(&resolved, 32, "journal key", security)?;
    if bytes.len() != 32 {
        return Err(ExchangeCustodyV3Error::InvalidJournalKey);
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&bytes);
    if key.iter().all(|byte| *byte == 0) {
        return Err(ExchangeCustodyV3Error::InvalidJournalKey);
    }
    Ok(LoadedJournalKeyV3(key))
}

pub(crate) fn load_external_anchor_v3(
    data_dir: &Path,
    path: &Path,
) -> Result<JournalAnchorV3, ExchangeCustodyV3Error> {
    let data_dir = resolve_data_directory(data_dir)?;
    let path = resolve_external_control_path(&data_dir, path, "external anchor")?;
    load_external_anchor_from_resolved(&path, FileSecurity::Production)
}

pub(crate) fn load_policy_document_v3(
    data_dir: &Path,
    path: &Path,
) -> Result<Vec<u8>, ExchangeCustodyV3Error> {
    load_external_control_document_v3(
        data_dir,
        path,
        MAX_POLICY_DOCUMENT_BYTES,
        "withdrawal policy",
    )
}

pub(crate) fn load_external_control_document_v3(
    data_dir: &Path,
    path: &Path,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<u8>, ExchangeCustodyV3Error> {
    let data_dir = resolve_data_directory(data_dir)?;
    let path = resolve_external_control_path(&data_dir, path, kind)?;
    read_external_control(&path, maximum, kind, FileSecurity::Production)
}

pub(crate) fn load_external_secret_document_v3(
    data_dir: &Path,
    path: &Path,
    maximum: usize,
    kind: &'static str,
) -> Result<Zeroizing<Vec<u8>>, ExchangeCustodyV3Error> {
    let data_dir = resolve_data_directory(data_dir)?;
    let path = resolve_external_control_path(&data_dir, path, kind)?;
    let mut file = open_read_only(&path)
        .map_err(|source| io_error("open external exchange custody secret", &path, source))?;
    validate_external_secret_file(&file, &path, kind, FileSecurity::Production)?;
    read_bounded_secret(&mut file, &path, maximum, kind)
}

pub(crate) fn load_keyring_envelope_v3(
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, ExchangeCustodyV3Error> {
    if !path.is_absolute() {
        return Err(ExchangeCustodyV3Error::InvalidControlPath("wallet keyring"));
    }
    let path = resolve_existing_regular_path(path, "wallet keyring")?;
    read_node_owned_secret(
        &path,
        MAX_KEYRING_ENVELOPE_BYTES,
        "wallet keyring",
        FileSecurity::Production,
    )
}

pub(crate) fn load_keyring_anchor_v3(
    data_dir: &Path,
    path: &Path,
) -> Result<KeyringAnchorV1, ExchangeCustodyV3Error> {
    let data_dir = resolve_data_directory(data_dir)?;
    let path = resolve_external_control_path(&data_dir, path, "wallet keyring anchor")?;
    let bytes = read_external_control(
        &path,
        KEYRING_ANCHOR_BYTES,
        "wallet keyring anchor",
        FileSecurity::Production,
    )?;
    if bytes.len() != KEYRING_ANCHOR_BYTES {
        return Err(ExchangeCustodyV3Error::InvalidControlLength(
            "wallet keyring anchor",
        ));
    }
    Ok(KeyringAnchorV1::decode(&bytes)?)
}

pub(crate) fn load_keyring_passphrase_v3(
    data_dir: &Path,
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, ExchangeCustodyV3Error> {
    load_external_passphrase_v3(data_dir, path, "wallet keyring passphrase")
}

pub(crate) fn load_wallet_passphrase_v3(
    data_dir: &Path,
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, ExchangeCustodyV3Error> {
    load_external_passphrase_v3(data_dir, path, "wallet passphrase")
}

/// Reads a create-time passphrase owned by the offline provisioning identity.
/// Unlike a live external control, this file may be writable by the current
/// identity, but it must still be confidential, non-reparse, regular, and read
/// through the same retained handle that was validated.
pub(crate) fn load_provisioning_passphrase_v3(
    data_dir: &Path,
    path: &Path,
    kind: &'static str,
) -> Result<Zeroizing<Vec<u8>>, ExchangeCustodyV3Error> {
    let data_dir = resolve_data_directory(data_dir)?;
    let path = resolve_external_control_path(&data_dir, path, kind)?;
    let mut file = open_read_only(&path)
        .map_err(|source| io_error("open provisioning passphrase", &path, source))?;
    validate_secret_file(&file, &path, kind, FileSecurity::Production)?;
    read_passphrase(&mut file, &path, kind)
}

fn load_external_passphrase_v3(
    data_dir: &Path,
    path: &Path,
    kind: &'static str,
) -> Result<Zeroizing<Vec<u8>>, ExchangeCustodyV3Error> {
    let data_dir = resolve_data_directory(data_dir)?;
    let path = resolve_external_control_path(&data_dir, path, kind)?;
    let mut file = open_read_only(&path)
        .map_err(|source| io_error("open external wallet passphrase", &path, source))?;
    validate_external_secret_file(&file, &path, kind, FileSecurity::Production)?;
    read_passphrase(&mut file, &path, kind)
}

fn read_passphrase(
    file: &mut File,
    path: &Path,
    kind: &'static str,
) -> Result<Zeroizing<Vec<u8>>, ExchangeCustodyV3Error> {
    let length = file
        .metadata()
        .map_err(|source| io_error("inspect passphrase", path, source))?
        .len();
    let maximum_file_bytes = MAXIMUM_PASSPHRASE_BYTES + 2;
    if length == 0 || length > maximum_file_bytes as u64 {
        return Err(ExchangeCustodyV3Error::InvalidControlLength(kind));
    }
    let mut passphrase = Zeroizing::new(Vec::with_capacity(length as usize));
    Read::by_ref(file)
        .take(maximum_file_bytes as u64 + 1)
        .read_to_end(&mut passphrase)
        .map_err(|source| io_error("read passphrase", path, source))?;
    if passphrase.len() as u64 != length || passphrase.len() > maximum_file_bytes {
        return Err(ExchangeCustodyV3Error::InvalidControlLength(kind));
    }
    if passphrase.last() == Some(&b'\n') {
        passphrase.pop();
        if passphrase.last() == Some(&b'\r') {
            passphrase.pop();
        }
    }
    if !(MINIMUM_PASSPHRASE_BYTES..=MAXIMUM_PASSPHRASE_BYTES).contains(&passphrase.len()) {
        return Err(ExchangeCustodyV3Error::InvalidControlLength(kind));
    }
    Ok(passphrase)
}

pub(crate) fn journal_anchor_v3_from_v2(anchor: WithdrawalJournalAnchor) -> JournalAnchorV3 {
    JournalAnchorV3 {
        key_id: anchor.key_id,
        journal_instance_id: anchor.journal_instance_id,
        generation: anchor.generation,
        commitment: anchor.commitment,
    }
}

pub(crate) fn keyring_anchor_v3_from_v1(
    anchor: KeyringAnchorV1,
    binding: JournalBindingV3,
) -> Result<KeyringAnchorV3, ExchangeCustodyV3Error> {
    anchor.encode()?;
    if anchor.binding.network_id != binding.network_id
        || anchor.binding.consensus_fingerprint != binding.consensus_fingerprint
        || anchor.binding.genesis_hash != binding.genesis
    {
        return Err(ExchangeCustodyV3Error::BindingMismatch);
    }
    Ok(KeyringAnchorV3 {
        instance_id: anchor.instance_id,
        generation: anchor.generation,
        commitment: anchor.commitment,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileSecurity {
    Production,
    #[cfg(test)]
    PortableTest,
}

/// Security classes exposed only to the packaged-host ACL qualification
/// command. Qualification calls the same retained-handle validators as runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AclQualificationClassV3 {
    NodeDataDirectory,
    NodeSecret,
    ExternalControl,
    ExternalSecret,
}

/// Validates one configured custody path with the production runtime policy and
/// returns its platform-stable owner identity (UID on Unix, SID on Windows).
pub(crate) fn qualify_acl_path_v3(
    data_dir: &Path,
    path: &Path,
    class: AclQualificationClassV3,
    expected_authorities: &[String],
) -> Result<String, ExchangeCustodyV3Error> {
    #[cfg(unix)]
    let unix_authorities = UnixQualificationAuthorities::parse(expected_authorities)?;
    #[cfg(unix)]
    validate_unix_input_path_authority(path, class, &unix_authorities)?;
    let data_dir = resolve_data_directory(data_dir)?;
    match class {
        AclQualificationClassV3::NodeDataDirectory => {
            let resolved = resolve_data_directory(path)?;
            if resolved != data_dir {
                return Err(ExchangeCustodyV3Error::InvalidDataDirectory);
            }
            let owner = qualify_node_data_directory(&resolved, expected_authorities)?;
            #[cfg(unix)]
            validate_unix_qualification_directory_path(&resolved, &unix_authorities)?;
            for state_path in [
                snapshot_path(&resolved, 0),
                snapshot_path(&resolved, 1),
                v3_marker_path(&resolved),
                resolved.join(V3_LOCK_FILE),
            ] {
                let mut file = match open_read_only(&state_path) {
                    Ok(file) => file,
                    Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
                    Err(source) => {
                        return Err(io_error(
                            "open existing v3 custody state for ACL qualification",
                            &state_path,
                            source,
                        ));
                    }
                };
                validate_node_owned_file(
                    &file,
                    &state_path,
                    "existing v3 custody state",
                    FileSecurity::Production,
                )?;
                #[cfg(windows)]
                crate::exchange_acl::validate_windows_custody_path_acl_with_authorities(
                    &file,
                    &state_path,
                    crate::exchange_acl::WindowsCustodyFilePolicy::DurableJournal,
                    expected_authorities,
                )?;
                if qualification_file_owner(&file, &state_path)? != owner {
                    return Err(ExchangeCustodyV3Error::Corrupt(
                        "existing v3 custody state owner differs from the data directory",
                    ));
                }
                #[cfg(unix)]
                validate_unix_qualification_file_path(
                    &file,
                    &state_path,
                    AclQualificationClassV3::NodeSecret,
                    &unix_authorities,
                )?;
                // Prove the retained file is readable without consuming its
                // contents or changing the journal lock/state.
                let mut probe = [0_u8; 1];
                let _ = file.read(&mut probe).map_err(|source| {
                    io_error("read existing v3 custody state", &state_path, source)
                })?;
            }
            Ok(owner)
        }
        AclQualificationClassV3::NodeSecret => {
            if !path.is_absolute() {
                return Err(ExchangeCustodyV3Error::InvalidControlPath(
                    "node-owned custody secret",
                ));
            }
            let resolved = resolve_existing_regular_path(path, "node-owned custody secret")?;
            let file = open_read_only(&resolved)
                .map_err(|source| io_error("open node-owned custody secret", &resolved, source))?;
            validate_secret_file(
                &file,
                &resolved,
                "node-owned custody secret",
                FileSecurity::Production,
            )?;
            #[cfg(windows)]
            crate::exchange_acl::validate_windows_custody_path_acl_with_authorities(
                &file,
                &resolved,
                crate::exchange_acl::WindowsCustodyFilePolicy::JournalKey,
                expected_authorities,
            )?;
            #[cfg(unix)]
            validate_unix_qualification_file_path(&file, &resolved, class, &unix_authorities)?;
            qualification_file_owner(&file, &resolved)
        }
        AclQualificationClassV3::ExternalControl | AclQualificationClassV3::ExternalSecret => {
            let kind = match class {
                AclQualificationClassV3::ExternalControl => "external custody control",
                AclQualificationClassV3::ExternalSecret => "external custody secret",
                _ => unreachable!(),
            };
            let resolved = resolve_external_control_path(&data_dir, path, kind)?;
            let file = open_read_only(&resolved).map_err(|source| {
                io_error("open custody ACL qualification input", &resolved, source)
            })?;
            match class {
                AclQualificationClassV3::ExternalControl => {
                    validate_external_file(&file, &resolved, kind, FileSecurity::Production)?;
                    #[cfg(windows)]
                    crate::exchange_acl::validate_windows_custody_path_acl_with_authorities(
                        &file,
                        &resolved,
                        crate::exchange_acl::WindowsCustodyFilePolicy::ExternalReadOnly,
                        expected_authorities,
                    )?;
                }
                AclQualificationClassV3::ExternalSecret => {
                    validate_external_secret_file(
                        &file,
                        &resolved,
                        kind,
                        FileSecurity::Production,
                    )?;
                    #[cfg(windows)]
                    crate::exchange_acl::validate_windows_custody_path_acl_with_authorities(
                        &file,
                        &resolved,
                        crate::exchange_acl::WindowsCustodyFilePolicy::ExternalSecretReadOnly,
                        expected_authorities,
                    )?;
                }
                _ => unreachable!(),
            }
            #[cfg(unix)]
            validate_unix_qualification_file_path(&file, &resolved, class, &unix_authorities)?;
            qualification_file_owner(&file, &resolved)
        }
    }
}

fn qualify_node_data_directory(
    path: &Path,
    expected_authorities: &[String],
) -> Result<String, ExchangeCustodyV3Error> {
    #[cfg(unix)]
    {
        let _ = expected_authorities;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let metadata = fs::metadata(path)
            .map_err(|source| io_error("inspect custody data-directory ACL", path, source))?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ExchangeCustodyV3Error::Corrupt(
                "custody data directory is not owner-only",
            ));
        }
        Ok(unix_uid_authority(metadata.uid()))
    }
    #[cfg(windows)]
    {
        crate::exchange_acl::validate_windows_custody_directory_path_acl(
            path,
            crate::exchange_acl::WindowsCustodyFilePolicy::DurableJournal,
            expected_authorities,
        )
        .map_err(Into::into)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, expected_authorities);
        Err(ExchangeCustodyV3Error::Corrupt(
            "custody ACL qualification is unsupported on this platform",
        ))
    }
}

fn qualification_file_owner(file: &File, path: &Path) -> Result<String, ExchangeCustodyV3Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        file.metadata()
            .map(|metadata| unix_uid_authority(metadata.uid()))
            .map_err(|source| io_error("inspect custody-file owner", path, source))
    }
    #[cfg(windows)]
    {
        crate::exchange_acl::windows_custody_file_owner_sid(file, path).map_err(Into::into)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, path);
        Err(ExchangeCustodyV3Error::Corrupt(
            "custody ACL qualification is unsupported on this platform",
        ))
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct UnixQualificationAuthorities {
    uids: BTreeSet<libc::uid_t>,
    gids: BTreeSet<libc::gid_t>,
}

#[cfg(unix)]
impl UnixQualificationAuthorities {
    fn parse(values: &[String]) -> Result<Self, ExchangeCustodyV3Error> {
        let mut uids = BTreeSet::new();
        let mut gids = BTreeSet::new();
        for value in values {
            if let Some(uid) = parse_unix_authority(value, "uid:") {
                if unix_uid_authority(uid) != *value || !uids.insert(uid) {
                    return Err(ExchangeCustodyV3Error::Corrupt(
                        "Unix custody authority IDs are non-canonical or duplicated",
                    ));
                }
            } else if let Some(gid) = parse_unix_authority(value, "gid:") {
                if unix_gid_authority(gid) != *value || !gids.insert(gid) {
                    return Err(ExchangeCustodyV3Error::Corrupt(
                        "Unix custody authority IDs are non-canonical or duplicated",
                    ));
                }
            } else {
                return Err(ExchangeCustodyV3Error::Corrupt(
                    "Unix custody authority ID is invalid",
                ));
            }
        }
        if uids.is_empty() {
            return Err(ExchangeCustodyV3Error::Corrupt(
                "Unix custody UID allowlist is empty",
            ));
        }
        Ok(Self { uids, gids })
    }
}

#[cfg(unix)]
fn parse_unix_authority(value: &str, prefix: &str) -> Option<u32> {
    let digits = value.strip_prefix(prefix)?;
    if digits.is_empty() || digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    digits.parse().ok()
}

#[cfg(unix)]
fn unix_uid_authority(uid: libc::uid_t) -> String {
    format!("uid:{uid}")
}

#[cfg(unix)]
fn unix_gid_authority(gid: libc::gid_t) -> String {
    format!("gid:{gid}")
}

#[cfg(unix)]
fn validate_unix_input_path_authority(
    path: &Path,
    class: AclQualificationClassV3,
    authorities: &UnixQualificationAuthorities,
) -> Result<(), ExchangeCustodyV3Error> {
    if !path.is_absolute() {
        return Err(ExchangeCustodyV3Error::InvalidControlPath(
            "Unix ACL qualification path",
        ));
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(ExchangeCustodyV3Error::InvalidControlPath(
            "Unix ACL qualification path contains a relative component",
        ));
    }
    let directory = if class == AclQualificationClassV3::NodeDataDirectory {
        path
    } else {
        path.parent()
            .ok_or(ExchangeCustodyV3Error::InvalidControlPath(
                "Unix ACL qualification path has no parent",
            ))?
    };
    validate_unix_qualification_ancestors(directory, authorities)
}

#[cfg(unix)]
fn validate_unix_qualification_directory_path(
    path: &Path,
    authorities: &UnixQualificationAuthorities,
) -> Result<(), ExchangeCustodyV3Error> {
    validate_unix_qualification_ancestors(path, authorities)
}

#[cfg(unix)]
fn validate_unix_qualification_file_path(
    file: &File,
    path: &Path,
    class: AclQualificationClassV3,
    authorities: &UnixQualificationAuthorities,
) -> Result<(), ExchangeCustodyV3Error> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect Unix custody authority", path, source))?;
    validate_unix_owner_authority(metadata.uid(), authorities)?;
    if class == AclQualificationClassV3::ExternalSecret
        && metadata.mode() & 0o070 != 0
        && !authorities.gids.contains(&metadata.gid())
    {
        return Err(ExchangeCustodyV3Error::Corrupt(
            "Unix external-secret group access is outside the configured GID allowlist",
        ));
    }
    reject_unix_posix_acl(file, path, false)?;
    let parent = path.parent().ok_or_else(|| {
        io_error(
            "locate Unix custody authority parent",
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"),
        )
    })?;
    validate_unix_qualification_ancestors(parent, authorities)?;
    let final_metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reinspect Unix custody authority", path, source))?;
    if final_metadata.dev() != metadata.dev() || final_metadata.ino() != metadata.ino() {
        return Err(ExchangeCustodyV3Error::Corrupt(
            "Unix custody object changed during authority qualification",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_qualification_ancestors(
    path: &Path,
    authorities: &UnixQualificationAuthorities,
) -> Result<(), ExchangeCustodyV3Error> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;

    let mut retained = Vec::new();
    for directory in path.ancestors() {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
        let file = options.open(directory).map_err(|source| {
            io_error("open Unix custody authority ancestor", directory, source)
        })?;
        let metadata = file.metadata().map_err(|source| {
            io_error("inspect Unix custody authority ancestor", directory, source)
        })?;
        if !metadata.is_dir() {
            return Err(ExchangeCustodyV3Error::Corrupt(
                "Unix custody authority ancestor is not a directory",
            ));
        }
        validate_unix_directory_authority(
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
            authorities,
        )?;
        reject_unix_posix_acl(&file, directory, true)?;
        retained.push((
            directory.to_path_buf(),
            file,
            metadata.dev(),
            metadata.ino(),
        ));
    }
    for (directory, _file, device, inode) in retained {
        let current = fs::symlink_metadata(&directory).map_err(|source| {
            io_error(
                "reinspect Unix custody authority ancestor",
                &directory,
                source,
            )
        })?;
        if current.dev() != device || current.ino() != inode {
            return Err(ExchangeCustodyV3Error::Corrupt(
                "Unix custody authority ancestor changed during qualification",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_directory_authority(
    owner: libc::uid_t,
    group: libc::gid_t,
    mode: libc::mode_t,
    authorities: &UnixQualificationAuthorities,
) -> Result<(), ExchangeCustodyV3Error> {
    validate_unix_owner_authority(owner, authorities)?;
    if mode & 0o002 != 0 {
        return Err(ExchangeCustodyV3Error::Corrupt(
            "Unix custody authority ancestor is other-writable",
        ));
    }
    if mode & 0o020 != 0 && !authorities.gids.contains(&group) {
        return Err(ExchangeCustodyV3Error::Corrupt(
            "Unix custody authority ancestor has an unlisted group writer",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_owner_authority(
    owner: libc::uid_t,
    authorities: &UnixQualificationAuthorities,
) -> Result<(), ExchangeCustodyV3Error> {
    if authorities.uids.contains(&owner) {
        Ok(())
    } else {
        Err(ExchangeCustodyV3Error::Corrupt(
            "Unix custody object owner is outside the configured UID allowlist",
        ))
    }
}

#[cfg(target_os = "linux")]
fn reject_unix_posix_acl(
    file: &File,
    path: &Path,
    directory: bool,
) -> Result<(), ExchangeCustodyV3Error> {
    use std::os::fd::AsRawFd;

    for name in [
        b"system.posix_acl_access\0".as_slice(),
        b"system.posix_acl_default\0".as_slice(),
    ] {
        if !directory && name == b"system.posix_acl_default\0" {
            continue;
        }
        // SAFETY: name is NUL-terminated, the descriptor is retained for the
        // call, and a null value with size zero only queries xattr presence.
        let result = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                name.as_ptr().cast(),
                std::ptr::null_mut(),
                0,
            )
        };
        if result >= 0 {
            return Err(ExchangeCustodyV3Error::Corrupt(
                "extended POSIX ACLs are not accepted for custody qualification",
            ));
        }
        let source = io::Error::last_os_error();
        let error = source.raw_os_error();
        if error != Some(libc::ENODATA) {
            return Err(io_error("inspect Unix custody POSIX ACL", path, source));
        }
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn reject_unix_posix_acl(
    _file: &File,
    _path: &Path,
    _directory: bool,
) -> Result<(), ExchangeCustodyV3Error> {
    Err(ExchangeCustodyV3Error::Corrupt(
        "Unix custody ACL qualification is implemented only for Linux",
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActivationMarkerV3 {
    binding: JournalBindingV3,
    policy_id: [u8; 32],
    migration_id: [u8; 32],
    migration_input_digest: [u8; 32],
    initial_anchor: JournalAnchorV3,
}

impl ActivationMarkerV3 {
    fn from_output(output: &MigrationOutputV3) -> Self {
        Self {
            binding: output.journal.binding,
            policy_id: output.journal.policy_id,
            migration_id: output.receipt.migration_id,
            migration_input_digest: output.receipt.migration_input_digest,
            initial_anchor: output.initial_anchor,
        }
    }

    fn encode(&self, key: &[u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MARKER_BYTES);
        bytes.extend_from_slice(&V3_MARKER_MAGIC);
        bytes.extend_from_slice(&V3_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.binding.network_id);
        bytes.extend_from_slice(&self.binding.consensus_fingerprint);
        bytes.extend_from_slice(&self.binding.genesis);
        bytes.extend_from_slice(&self.policy_id);
        bytes.extend_from_slice(&self.migration_id);
        bytes.extend_from_slice(&self.migration_input_digest);
        write_anchor(&mut bytes, self.initial_anchor);
        debug_assert_eq!(bytes.len(), MARKER_PAYLOAD_BYTES);
        let tag = keyed_digest(key, MARKER_AUTH_DOMAIN, &bytes);
        bytes.extend_from_slice(&tag);
        bytes
    }

    fn decode(bytes: &[u8], key: &[u8; 32]) -> Result<Self, ExchangeCustodyV3Error> {
        if bytes.len() != MARKER_BYTES {
            return Err(ExchangeCustodyV3Error::Corrupt("v3 marker size is invalid"));
        }
        let (payload, tag) = bytes.split_at(MARKER_PAYLOAD_BYTES);
        let expected = keyed_digest(key, MARKER_AUTH_DOMAIN, payload);
        if !constant_time_equal(&expected, tag) {
            return Err(ExchangeCustodyV3Error::Corrupt(
                "v3 marker authentication failed",
            ));
        }
        let mut offset = 0;
        if take_array::<8>(payload, &mut offset)? != V3_MARKER_MAGIC
            || take_u32(payload, &mut offset)? != V3_VERSION
        {
            return Err(ExchangeCustodyV3Error::Corrupt(
                "v3 marker magic or version is invalid",
            ));
        }
        let marker = Self {
            binding: JournalBindingV3 {
                network_id: take_array(payload, &mut offset)?,
                consensus_fingerprint: take_array(payload, &mut offset)?,
                genesis: take_array(payload, &mut offset)?,
            },
            policy_id: take_array(payload, &mut offset)?,
            migration_id: take_array(payload, &mut offset)?,
            migration_input_digest: take_array(payload, &mut offset)?,
            initial_anchor: JournalAnchorV3 {
                key_id: take_array(payload, &mut offset)?,
                journal_instance_id: take_array(payload, &mut offset)?,
                generation: take_u64(payload, &mut offset)?,
                commitment: take_array(payload, &mut offset)?,
            },
        };
        if offset != payload.len()
            || marker.encode(key).as_slice() != bytes
            || marker.policy_id == [0; 32]
            || marker.migration_id == [0; 32]
            || marker.migration_input_digest == [0; 32]
        {
            return Err(ExchangeCustodyV3Error::Corrupt(
                "v3 marker is non-canonical",
            ));
        }
        Ok(marker)
    }

    fn verify_state(
        &self,
        state: &ExchangeWithdrawalJournalV3,
        key: &[u8; 32],
    ) -> Result<(), ExchangeCustodyV3Error> {
        if state.binding != self.binding
            || state.policy_id != self.policy_id
            || state.migration.migration_id != self.migration_id
            || state.migration.migration_input_digest != self.migration_input_digest
            || state.anchor_at(key, self.initial_anchor.generation)? != self.initial_anchor
        {
            return Err(ExchangeCustodyV3Error::Corrupt(
                "v3 marker does not bind the loaded journal history",
            ));
        }
        Ok(())
    }

    fn verify_output(&self, output: &MigrationOutputV3) -> Result<(), ExchangeCustodyV3Error> {
        if self != &Self::from_output(output) {
            return Err(ExchangeCustodyV3Error::AlreadyInitialized);
        }
        Ok(())
    }
}

enum LoadedSlotV3 {
    Missing,
    Legacy,
    Corrupt,
    Valid(Box<ExchangeWithdrawalJournalV3>),
}

fn choose_active_state(
    first: LoadedSlotV3,
    second: LoadedSlotV3,
    marker: Option<&ActivationMarkerV3>,
    key: &[u8; 32],
) -> Result<(ExchangeWithdrawalJournalV3, bool), ExchangeCustodyV3Error> {
    let legacy = matches!(first, LoadedSlotV3::Legacy) || matches!(second, LoadedSlotV3::Legacy);
    let valid = matches!(first, LoadedSlotV3::Valid(_)) || matches!(second, LoadedSlotV3::Valid(_));
    if legacy {
        return Err(if valid || marker.is_some() {
            ExchangeCustodyV3Error::MixedSnapshotVersions
        } else {
            ExchangeCustodyV3Error::ExplicitMigrationRequired
        });
    }
    if marker.is_none() {
        return match (&first, &second) {
            (LoadedSlotV3::Missing, LoadedSlotV3::Missing) => {
                Err(ExchangeCustodyV3Error::NotInitialized)
            }
            (LoadedSlotV3::Valid(_), _) | (_, LoadedSlotV3::Valid(_)) => {
                Err(ExchangeCustodyV3Error::ActivationIncomplete)
            }
            _ => Err(ExchangeCustodyV3Error::Corrupt(
                "unmarked withdrawal snapshots are corrupt",
            )),
        };
    }
    match (first, second) {
        (LoadedSlotV3::Valid(first), LoadedSlotV3::Valid(second)) => {
            let first_anchor = first.anchor(key)?;
            let second_anchor = second.anchor(key)?;
            if first_anchor == second_anchor {
                if first != second {
                    return Err(ExchangeCustodyV3Error::Corrupt(
                        "equal anchors encode different v3 states",
                    ));
                }
                return Ok((*first, false));
            }
            let (older, newer, older_anchor) = if first.generation < second.generation {
                (first, second, first_anchor)
            } else {
                (second, first, second_anchor)
            };
            if newer.generation <= older.generation
                || newer.anchor_at(key, older.generation)? != older_anchor
            {
                return Err(ExchangeCustodyV3Error::Corrupt(
                    "v3 slots do not form one append-only history",
                ));
            }
            Ok((*newer, false))
        }
        (LoadedSlotV3::Valid(state), LoadedSlotV3::Missing | LoadedSlotV3::Corrupt)
        | (LoadedSlotV3::Missing | LoadedSlotV3::Corrupt, LoadedSlotV3::Valid(state)) => {
            Ok((*state, true))
        }
        _ => Err(ExchangeCustodyV3Error::Corrupt(
            "no authenticated v3 snapshot remains",
        )),
    }
}

fn load_v3_slot(
    data_dir: &Path,
    slot: u8,
    key: &[u8; 32],
    security: FileSecurity,
) -> Result<LoadedSlotV3, ExchangeCustodyV3Error> {
    let path = snapshot_path(data_dir, slot);
    let mut file = match open_read_only(&path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(LoadedSlotV3::Missing);
        }
        Err(source) => return Err(io_error("open v3 withdrawal slot", &path, source)),
    };
    validate_node_owned_file(&file, &path, "v3 withdrawal slot", security)?;
    let length = file
        .metadata()
        .map_err(|source| io_error("inspect v3 withdrawal slot", &path, source))?
        .len();
    if length < 12 || length > MAX_V3_SNAPSHOT_BYTES as u64 {
        return Ok(LoadedSlotV3::Corrupt);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    Read::by_ref(&mut file)
        .take(MAX_V3_SNAPSHOT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read v3 withdrawal slot", &path, source))?;
    if bytes.len() as u64 != length || bytes.len() > MAX_V3_SNAPSHOT_BYTES {
        return Ok(LoadedSlotV3::Corrupt);
    }
    if is_legacy_snapshot(&bytes) {
        return Ok(LoadedSlotV3::Legacy);
    }
    if bytes.len() < MINIMUM_SNAPSHOT_BYTES {
        return Ok(LoadedSlotV3::Corrupt);
    }
    match ExchangeWithdrawalJournalV3::decode_authenticated(&bytes, key) {
        Ok(state) if state.generation == 1 || (state.generation & 1) as u8 == slot => {
            Ok(LoadedSlotV3::Valid(Box::new(state)))
        }
        Ok(_) => Ok(LoadedSlotV3::Corrupt),
        Err(ExchangeWithdrawalV3Error::ExplicitMigrationRequired) => Ok(LoadedSlotV3::Legacy),
        Err(_) => Ok(LoadedSlotV3::Corrupt),
    }
}

fn load_v3_marker(
    data_dir: &Path,
    key: &[u8; 32],
    security: FileSecurity,
) -> Result<Option<ActivationMarkerV3>, ExchangeCustodyV3Error> {
    let path = v3_marker_path(data_dir);
    let mut file = match open_read_only(&path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("open v3 activation marker", &path, source)),
    };
    validate_node_owned_file(&file, &path, "v3 activation marker", security)?;
    let length = file
        .metadata()
        .map_err(|source| io_error("inspect v3 activation marker", &path, source))?
        .len();
    if length != MARKER_BYTES as u64 {
        return Err(ExchangeCustodyV3Error::Corrupt(
            "v3 activation marker size is invalid",
        ));
    }
    let mut bytes = vec![0; MARKER_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|source| io_error("read v3 activation marker", &path, source))?;
    Ok(Some(ActivationMarkerV3::decode(&bytes, key)?))
}

fn anchor_relationship(
    state: &ExchangeWithdrawalJournalV3,
    key: &[u8; 32],
    external: JournalAnchorV3,
) -> Result<ExternalAnchorRelationshipV3, ExchangeCustodyV3Error> {
    if external.key_id != state.journal_key_id
        || external.journal_instance_id != state.journal_instance_id
        || external.generation == 0
        || external.commitment == [0; 32]
    {
        return Err(ExchangeCustodyV3Error::ExternalAnchorMismatch);
    }
    if external.generation > state.generation {
        return Err(ExchangeCustodyV3Error::ExternalAnchorAhead);
    }
    if state.anchor_at(key, external.generation)? != external {
        return Err(ExchangeCustodyV3Error::ExternalAnchorMismatch);
    }
    Ok(if external.generation == state.generation {
        ExternalAnchorRelationshipV3::Current
    } else {
        ExternalAnchorRelationshipV3::Descendant
    })
}

fn validate_candidate_extension(
    current: &ExchangeWithdrawalJournalV3,
    candidate: &ExchangeWithdrawalJournalV3,
    current_anchor: JournalAnchorV3,
) -> Result<(), ExchangeCustodyV3Error> {
    let generation_delta = candidate
        .generation
        .checked_sub(current.generation)
        .filter(|delta| (1..=MAX_ATOMIC_TRANSITIONS as u64).contains(delta))
        .ok_or(ExchangeCustodyV3Error::InvalidCandidateExtension(
            "generation must advance by one to three",
        ))?;
    if candidate.binding != current.binding
        || candidate.journal_key_id != current.journal_key_id
        || candidate.journal_instance_id != current.journal_instance_id
        || candidate.migration != current.migration
        || candidate.policy_id != current.policy_id
    {
        return Err(ExchangeCustodyV3Error::InvalidCandidateExtension(
            "journal identity, binding, migration receipt, or policy changed",
        ));
    }
    if !candidate
        .prior_commitments
        .starts_with(&current.prior_commitments)
    {
        return Err(ExchangeCustodyV3Error::InvalidCandidateExtension(
            "prior commitment history was rewritten",
        ));
    }
    let current_position = usize::try_from(current.generation - 1).map_err(|_| {
        ExchangeCustodyV3Error::InvalidCandidateExtension("current generation is too large")
    })?;
    if candidate.prior_commitments.get(current_position).copied() != Some(current_anchor.commitment)
    {
        return Err(ExchangeCustodyV3Error::InvalidCandidateExtension(
            "candidate does not append the exact current commitment",
        ));
    }
    if !candidate
        .prior_keyrings
        .starts_with(&current.prior_keyrings)
    {
        return Err(ExchangeCustodyV3Error::InvalidCandidateExtension(
            "keyring history was rewritten",
        ));
    }
    let appended_keyrings = &candidate.prior_keyrings[current.prior_keyrings.len()..];
    if appended_keyrings.len() > generation_delta as usize
        || (appended_keyrings.is_empty() && candidate.active_keyring != current.active_keyring)
        || (appended_keyrings
            .first()
            .is_some_and(|entry| entry.anchor != current.active_keyring))
    {
        return Err(ExchangeCustodyV3Error::InvalidCandidateExtension(
            "active keyring does not extend current keyring lineage",
        ));
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalAnchorDocumentV3 {
    key_id: String,
    journal_instance_id: String,
    generation: String,
    commitment: String,
}

fn load_external_anchor_from_resolved(
    path: &Path,
    security: FileSecurity,
) -> Result<JournalAnchorV3, ExchangeCustodyV3Error> {
    let bytes =
        read_external_control(path, MAX_EXTERNAL_ANCHOR_BYTES, "external anchor", security)?;
    let document: ExternalAnchorDocumentV3 = serde_json::from_slice(&bytes)
        .map_err(|_| ExchangeCustodyV3Error::InvalidExternalAnchor)?;
    let generation = document
        .generation
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0 && document.generation == value.to_string())
        .ok_or(ExchangeCustodyV3Error::InvalidExternalAnchor)?;
    let anchor = JournalAnchorV3 {
        key_id: decode_lower_hex(&document.key_id)?,
        journal_instance_id: decode_lower_hex(&document.journal_instance_id)?,
        generation,
        commitment: decode_lower_hex(&document.commitment)?,
    };
    if anchor.key_id == [0; 32]
        || anchor.journal_instance_id == [0; 32]
        || anchor.commitment == [0; 32]
    {
        return Err(ExchangeCustodyV3Error::InvalidExternalAnchor);
    }
    Ok(anchor)
}

fn decode_lower_hex(value: &str) -> Result<[u8; 32], ExchangeCustodyV3Error> {
    if value.len() != 64 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(ExchangeCustodyV3Error::InvalidExternalAnchor);
    }
    let mut output = [0; 32];
    hex::decode_to_slice(value, &mut output)
        .map_err(|_| ExchangeCustodyV3Error::InvalidExternalAnchor)?;
    Ok(output)
}

fn verify_migration_layout_read_only(
    data_dir: &Path,
    output: &MigrationOutputV3,
    source_bytes: &[u8],
    key: &[u8; 32],
    security: FileSecurity,
) -> Result<(), ExchangeCustodyV3Error> {
    if let Some(marker) = load_v3_marker(data_dir, key, security)? {
        marker.verify_output(output)?;
        require_installed_initial_slots(data_dir, &output.authenticated_snapshot, security)?;
        return Ok(());
    }
    let backup_files = migration_backup_paths(data_dir, output.receipt.migration_id);
    let source_digest = validated_v2_snapshot_digest(source_bytes);
    let mut source_seen = false;
    for slot in 0..=1 {
        let path = snapshot_path(data_dir, slot);
        let bytes = read_required_node_file(
            &path,
            MAX_V3_SNAPSHOT_BYTES,
            "migration source snapshot",
            security,
        )?;
        if is_legacy_v2_snapshot(&bytes) {
            source_seen |= validated_v2_snapshot_digest(&bytes) == source_digest;
        } else if bytes == output.authenticated_snapshot {
            let retained = read_required_node_file(
                &backup_files[usize::from(slot)],
                MAX_V3_SNAPSHOT_BYTES,
                "retained v2 migration backup",
                security,
            )?;
            validate_legacy_v2_snapshot_header(&retained)?;
            source_seen |= validated_v2_snapshot_digest(&retained) == source_digest;
        } else {
            return Err(ExchangeCustodyV3Error::MigrationLayoutChanged);
        }
    }
    if !source_seen {
        return Err(ExchangeCustodyV3Error::InvalidMigration(
            "validated source bytes are not the current or retained v2 snapshot",
        ));
    }
    let legacy_marker = read_required_node_file(
        &data_dir.join(LEGACY_V2_MARKER_FILE),
        MAX_LEGACY_MARKER_BYTES,
        "legacy v2 marker",
        security,
    )?;
    if !has_version(&legacy_marker, LEGACY_V2_VERSION) {
        return Err(ExchangeCustodyV3Error::MigrationLayoutChanged);
    }
    Ok(())
}

fn require_installed_initial_slots(
    data_dir: &Path,
    expected: &[u8],
    security: FileSecurity,
) -> Result<(), ExchangeCustodyV3Error> {
    for slot in 0..=1 {
        let bytes = read_required_node_file(
            &snapshot_path(data_dir, slot),
            MAX_V3_SNAPSHOT_BYTES,
            "installed v3 snapshot",
            security,
        )?;
        if bytes != expected {
            return Err(ExchangeCustodyV3Error::MigrationLayoutChanged);
        }
    }
    Ok(())
}

fn create_or_verify_backup(
    path: &Path,
    expected: &[u8],
    security: FileSecurity,
) -> Result<(), ExchangeCustodyV3Error> {
    match read_optional_node_file(path, expected.len().max(1), "migration backup", security)? {
        Some(bytes) if bytes == expected => Ok(()),
        Some(_) => Err(ExchangeCustodyV3Error::MigrationLayoutChanged),
        None => atomic_create_node_file(path, expected, security),
    }
}

pub(crate) fn migration_backup_paths(data_dir: &Path, migration_id: [u8; 32]) -> Vec<PathBuf> {
    let tag = hex::encode(migration_id);
    vec![
        data_dir.join(format!("exchange-withdrawals.v2-backup-{tag}.0.bin")),
        data_dir.join(format!("exchange-withdrawals.v2-backup-{tag}.1.bin")),
        data_dir.join(format!("exchange-withdrawals.v2-backup-{tag}.initialized")),
    ]
}

fn validate_legacy_v2_snapshot_header(bytes: &[u8]) -> Result<(), ExchangeCustodyV3Error> {
    if !is_legacy_v2_snapshot(bytes) {
        return Err(ExchangeCustodyV3Error::InvalidMigration(
            "validated source file is not a v2 snapshot",
        ));
    }
    Ok(())
}

fn is_legacy_snapshot(bytes: &[u8]) -> bool {
    bytes.get(..8) == Some(&SNAPSHOT_MAGIC)
        && bytes
            .get(8..12)
            .and_then(|version| <[u8; 4]>::try_from(version).ok())
            .map(u32::from_le_bytes)
            .is_some_and(|version| matches!(version, LEGACY_V1_VERSION | LEGACY_V2_VERSION))
}

fn is_legacy_v2_snapshot(bytes: &[u8]) -> bool {
    bytes.get(..8) == Some(&SNAPSHOT_MAGIC) && has_version(bytes, LEGACY_V2_VERSION)
}

fn has_version(bytes: &[u8], expected: u32) -> bool {
    bytes.get(8..12) == Some(&expected.to_le_bytes())
}

fn resolve_data_directory(path: &Path) -> Result<PathBuf, ExchangeCustodyV3Error> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect exchange custody v3 data directory", path, source))?;
    if !metadata.file_type().is_dir() || metadata_is_symlink_or_reparse(&metadata) {
        return Err(ExchangeCustodyV3Error::InvalidDataDirectory);
    }
    fs::canonicalize(path)
        .map_err(|source| io_error("resolve exchange custody v3 data directory", path, source))
}

fn resolve_external_control_path(
    data_dir: &Path,
    path: &Path,
    kind: &'static str,
) -> Result<PathBuf, ExchangeCustodyV3Error> {
    if !path.is_absolute() {
        return Err(ExchangeCustodyV3Error::InvalidControlPath(kind));
    }
    let resolved = resolve_existing_regular_path(path, kind)?;
    if resolved.starts_with(data_dir) || path.starts_with(data_dir) {
        return Err(ExchangeCustodyV3Error::ControlInsideDataDirectory(kind));
    }
    Ok(resolved)
}

fn resolve_existing_regular_path(
    path: &Path,
    kind: &'static str,
) -> Result<PathBuf, ExchangeCustodyV3Error> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect exchange custody control path", path, source))?;
    if !metadata.file_type().is_file() || metadata_is_symlink_or_reparse(&metadata) {
        return Err(ExchangeCustodyV3Error::InvalidControlPath(kind));
    }
    fs::canonicalize(path)
        .map_err(|source| io_error("resolve exchange custody control path", path, source))
}

fn read_external_control(
    path: &Path,
    maximum: usize,
    kind: &'static str,
    security: FileSecurity,
) -> Result<Vec<u8>, ExchangeCustodyV3Error> {
    let mut file = open_read_only(path)
        .map_err(|source| io_error("open external exchange custody control", path, source))?;
    validate_external_file(&file, path, kind, security)?;
    read_bounded(&mut file, path, maximum, kind)
}

fn read_node_owned_secret(
    path: &Path,
    maximum: usize,
    kind: &'static str,
    security: FileSecurity,
) -> Result<Zeroizing<Vec<u8>>, ExchangeCustodyV3Error> {
    let mut file = open_read_only(path)
        .map_err(|source| io_error("open exchange custody secret", path, source))?;
    validate_secret_file(&file, path, kind, security)?;
    read_bounded_secret(&mut file, path, maximum, kind)
}

fn read_required_node_file(
    path: &Path,
    maximum: usize,
    kind: &'static str,
    security: FileSecurity,
) -> Result<Vec<u8>, ExchangeCustodyV3Error> {
    read_optional_node_file(path, maximum, kind, security)?
        .ok_or(ExchangeCustodyV3Error::MigrationLayoutChanged)
}

fn read_optional_node_file(
    path: &Path,
    maximum: usize,
    kind: &'static str,
    security: FileSecurity,
) -> Result<Option<Vec<u8>>, ExchangeCustodyV3Error> {
    let mut file = match open_read_only(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("open exchange custody durable file", path, source)),
    };
    validate_node_owned_file(&file, path, kind, security)?;
    Ok(Some(read_bounded(&mut file, path, maximum, kind)?))
}

fn read_bounded(
    file: &mut File,
    path: &Path,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<u8>, ExchangeCustodyV3Error> {
    let length = file
        .metadata()
        .map_err(|source| io_error("inspect bounded exchange custody file", path, source))?
        .len();
    if length == 0 || length > maximum as u64 {
        return Err(ExchangeCustodyV3Error::InvalidControlLength(kind));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    Read::by_ref(file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read bounded exchange custody file", path, source))?;
    if bytes.len() as u64 != length || bytes.len() > maximum {
        return Err(ExchangeCustodyV3Error::InvalidControlLength(kind));
    }
    Ok(bytes)
}

fn read_bounded_secret(
    file: &mut File,
    path: &Path,
    maximum: usize,
    kind: &'static str,
) -> Result<Zeroizing<Vec<u8>>, ExchangeCustodyV3Error> {
    let length = file
        .metadata()
        .map_err(|source| io_error("inspect bounded exchange custody secret", path, source))?
        .len();
    if length == 0 || length > maximum as u64 {
        return Err(ExchangeCustodyV3Error::InvalidControlLength(kind));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(length as usize));
    Read::by_ref(file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read bounded exchange custody secret", path, source))?;
    if bytes.len() as u64 != length || bytes.len() > maximum {
        return Err(ExchangeCustodyV3Error::InvalidControlLength(kind));
    }
    Ok(bytes)
}

fn open_read_only(path: &Path) -> io::Result<File> {
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

fn validate_secret_file(
    file: &File,
    path: &Path,
    kind: &'static str,
    security: FileSecurity,
) -> Result<(), ExchangeCustodyV3Error> {
    #[cfg(not(windows))]
    let _ = security;
    validate_regular_file(file, path, kind)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file
            .metadata()
            .map_err(|source| {
                io_error("inspect exchange custody secret permissions", path, source)
            })?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err(ExchangeCustodyV3Error::InsecureJournalKeyPermissions);
        }
    }
    #[cfg(windows)]
    if security == FileSecurity::Production {
        crate::exchange_acl::validate_windows_custody_path_acl(
            file,
            path,
            crate::exchange_acl::WindowsCustodyFilePolicy::JournalKey,
        )?;
    }
    Ok(())
}

fn validate_external_file(
    file: &File,
    path: &Path,
    kind: &'static str,
    security: FileSecurity,
) -> Result<(), ExchangeCustodyV3Error> {
    validate_regular_file(file, path, kind)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file
            .metadata()
            .map_err(|source| io_error("inspect external control permissions", path, source))?
            .permissions()
            .mode()
            & 0o022
            != 0
        {
            return Err(ExchangeCustodyV3Error::InvalidControlPath(kind));
        }
        if security == FileSecurity::Production {
            validate_unix_external_control_independence(file, path, kind)?;
        }
    }
    #[cfg(windows)]
    if security == FileSecurity::Production {
        crate::exchange_acl::validate_windows_custody_path_acl(
            file,
            path,
            crate::exchange_acl::WindowsCustodyFilePolicy::ExternalReadOnly,
        )?;
    }
    Ok(())
}

fn validate_external_secret_file(
    file: &File,
    path: &Path,
    kind: &'static str,
    security: FileSecurity,
) -> Result<(), ExchangeCustodyV3Error> {
    validate_regular_file(file, path, kind)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file
            .metadata()
            .map_err(|source| io_error("inspect external secret permissions", path, source))?
            .permissions()
            .mode();
        // A dedicated group may grant the node read access to an
        // operator-owned secret. Other-user access and all group/other write
        // access are rejected.
        if mode & 0o007 != 0 || mode & 0o022 != 0 {
            return Err(ExchangeCustodyV3Error::InvalidControlPath(kind));
        }
        if security == FileSecurity::Production {
            validate_unix_external_control_independence(file, path, kind)?;
        }
    }
    #[cfg(windows)]
    if security == FileSecurity::Production {
        crate::exchange_acl::validate_windows_custody_path_acl(
            file,
            path,
            crate::exchange_acl::WindowsCustodyFilePolicy::ExternalSecretReadOnly,
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_external_control_independence(
    file: &File,
    path: &Path,
    kind: &'static str,
) -> Result<(), ExchangeCustodyV3Error> {
    use std::os::unix::fs::MetadataExt;

    // A root process can override Unix ownership and mode protections, so it
    // cannot claim that an on-host file is an independent authorization
    // boundary.
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid == 0 {
        return Err(ExchangeCustodyV3Error::InvalidControlPath(kind));
    }

    let opened_metadata = file
        .metadata()
        .map_err(|source| io_error("inspect opened external control identity", path, source))?;
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect external control identity", path, source))?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.uid() == effective_uid
        || unix_effectively_writable(path)?
    {
        return Err(ExchangeCustodyV3Error::InvalidControlPath(kind));
    }

    for directory in path.ancestors().skip(1) {
        let metadata = fs::metadata(directory).map_err(|source| {
            io_error(
                "inspect external control ancestor directory",
                directory,
                source,
            )
        })?;
        if !metadata.is_dir()
            || metadata.uid() == effective_uid
            || unix_effectively_writable(directory)?
        {
            return Err(ExchangeCustodyV3Error::InvalidControlPath(kind));
        }
    }

    // Detect replacement by the external authority while validation was in
    // progress. The node cannot cause this race once the checks above pass,
    // but startup still fails closed rather than consuming ambiguous bytes.
    let final_metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reinspect external control identity", path, source))?;
    if opened_metadata.dev() != final_metadata.dev()
        || opened_metadata.ino() != final_metadata.ino()
    {
        return Err(ExchangeCustodyV3Error::InvalidControlPath(kind));
    }
    Ok(())
}

#[cfg(unix)]
fn unix_effectively_writable(path: &Path) -> Result<bool, ExchangeCustodyV3Error> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let encoded = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io_error(
            "encode external control path for access check",
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"),
        )
    })?;
    let result = unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            encoded.as_ptr(),
            libc::W_OK,
            libc::AT_EACCESS,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let source = io::Error::last_os_error();
    match source.raw_os_error() {
        Some(code) if code == libc::EACCES || code == libc::EPERM || code == libc::EROFS => {
            Ok(false)
        }
        _ => Err(io_error(
            "check effective write access to external control path",
            path,
            source,
        )),
    }
}

fn validate_node_owned_file(
    file: &File,
    path: &Path,
    kind: &'static str,
    security: FileSecurity,
) -> Result<(), ExchangeCustodyV3Error> {
    #[cfg(not(windows))]
    let _ = security;
    validate_regular_file(file, path, kind)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file
            .metadata()
            .map_err(|source| io_error("inspect durable custody permissions", path, source))?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err(ExchangeCustodyV3Error::Corrupt(
                "durable custody file is not owner-only",
            ));
        }
    }
    #[cfg(windows)]
    if security == FileSecurity::Production {
        crate::exchange_acl::validate_windows_custody_path_acl(
            file,
            path,
            crate::exchange_acl::WindowsCustodyFilePolicy::DurableJournal,
        )?;
    }
    Ok(())
}

fn validate_regular_file(
    file: &File,
    path: &Path,
    kind: &'static str,
) -> Result<(), ExchangeCustodyV3Error> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect exchange custody file path", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect exchange custody file", path, source))?;
    if !path_metadata.file_type().is_file()
        || !metadata.file_type().is_file()
        || metadata_is_symlink_or_reparse(&path_metadata)
    {
        return Err(ExchangeCustodyV3Error::InvalidControlPath(kind));
    }
    Ok(())
}

fn acquire_storage_lock(
    data_dir: &Path,
    security: FileSecurity,
) -> Result<File, ExchangeCustodyV3Error> {
    let path = data_dir.join(V3_LOCK_FILE);
    let file = match create_node_file(&path, security) {
        Ok(file) => {
            file.sync_all()
                .map_err(|source| io_error("sync new v3 storage lock", &path, source))?;
            sync_parent_directory(&path)?;
            file
        }
        Err(ExchangeCustodyV3Error::Io { source, .. })
            if source.kind() == io::ErrorKind::AlreadyExists =>
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|source| io_error("open v3 storage lock", &path, source))?;
            validate_node_owned_file(&file, &path, "v3 storage lock", security)?;
            if file
                .metadata()
                .map_err(|source| io_error("inspect v3 storage lock", &path, source))?
                .len()
                != 0
            {
                return Err(ExchangeCustodyV3Error::Corrupt(
                    "v3 storage lock file is not empty",
                ));
            }
            file
        }
        Err(error) => return Err(error),
    };
    file.try_lock_exclusive().map_err(|source| {
        if source.kind() == io::ErrorKind::WouldBlock {
            ExchangeCustodyV3Error::Busy
        } else {
            io_error("lock exchange custody v3 storage", &path, source)
        }
    })?;
    Ok(file)
}

fn atomic_replace_node_file(
    path: &Path,
    bytes: &[u8],
    security: FileSecurity,
) -> Result<(), ExchangeCustodyV3Error> {
    atomic_publish_node_file(path, bytes, true, security, false)
}

fn atomic_create_node_file(
    path: &Path,
    bytes: &[u8],
    security: FileSecurity,
) -> Result<(), ExchangeCustodyV3Error> {
    atomic_publish_node_file(path, bytes, false, security, false)
}

fn atomic_publish_node_file(
    path: &Path,
    bytes: &[u8],
    replace: bool,
    security: FileSecurity,
    fail_before_publish: bool,
) -> Result<(), ExchangeCustodyV3Error> {
    if bytes.is_empty() || bytes.len() > MAX_V3_SNAPSHOT_BYTES {
        return Err(ExchangeCustodyV3Error::Corrupt(
            "durable custody payload length is invalid",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io_error(
            "locate exchange custody durable parent",
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"),
        )
    })?;
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|source| {
        io_error(
            "generate exchange custody temporary path",
            path,
            io::Error::other(source.to_string()),
        )
    })?;
    let temporary = parent.join(format!(
        ".{EXCHANGE_WITHDRAWAL_FILE_PREFIX}.v3-tmp-{}",
        hex::encode(random)
    ));
    let result = (|| {
        let mut file = create_node_file(&temporary, security)?;
        file.write_all(bytes).map_err(|source| {
            io_error("write exchange custody temporary file", &temporary, source)
        })?;
        file.sync_all().map_err(|source| {
            io_error("sync exchange custody temporary file", &temporary, source)
        })?;
        drop(file);
        #[cfg(test)]
        if fail_before_publish {
            return Err(ExchangeCustodyV3Error::InjectedPersistenceFailure);
        }
        #[cfg(not(test))]
        let _ = fail_before_publish;
        if replace {
            publish_replace(&temporary, path)
        } else {
            publish_create_new(&temporary, path)
        }
        .map_err(|source| io_error("publish exchange custody durable file", path, source))?;
        sync_parent_directory(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn create_node_file(path: &Path, security: FileSecurity) -> Result<File, ExchangeCustodyV3Error> {
    #[cfg(not(windows))]
    let _ = security;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    if security == FileSecurity::Production {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, WRITE_DAC,
        };
        options.access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
    }
    let file = options
        .open(path)
        .map_err(|source| io_error("create exchange custody node-owned file", path, source))?;
    #[cfg(windows)]
    if security == FileSecurity::Production {
        crate::exchange_acl::initialize_windows_node_owned_custody_file_acl(
            &file,
            path,
            crate::exchange_acl::WindowsCustodyFilePolicy::DurableJournal,
        )?;
    }
    Ok(file)
}

#[cfg(windows)]
fn publish_replace(temporary: &Path, destination: &Path) -> io::Result<()> {
    publish_windows(temporary, destination, true)
}

#[cfg(windows)]
fn publish_create_new(temporary: &Path, destination: &Path) -> io::Result<()> {
    publish_windows(temporary, destination, false)
}

#[cfg(windows)]
fn publish_windows(temporary: &Path, destination: &Path, replace: bool) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let temporary = temporary
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut flags = MOVEFILE_WRITE_THROUGH;
    if replace {
        flags |= MOVEFILE_REPLACE_EXISTING;
    }
    // SAFETY: both paths are NUL-terminated UTF-16 buffers retained for the call.
    if unsafe { MoveFileExW(temporary.as_ptr(), destination.as_ptr(), flags) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn publish_replace(temporary: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temporary, destination)
}

#[cfg(unix)]
fn publish_create_new(temporary: &Path, destination: &Path) -> io::Result<()> {
    fs::hard_link(temporary, destination)?;
    fs::remove_file(temporary)
}

#[cfg(not(any(unix, windows)))]
fn publish_replace(temporary: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temporary, destination)
}

#[cfg(not(any(unix, windows)))]
fn publish_create_new(temporary: &Path, destination: &Path) -> io::Result<()> {
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "destination already exists",
        ));
    }
    fs::rename(temporary, destination)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), ExchangeCustodyV3Error> {
    let parent = path.parent().ok_or_else(|| {
        io_error(
            "locate exchange custody parent directory",
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"),
        )
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync exchange custody parent directory", parent, source))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), ExchangeCustodyV3Error> {
    // Windows publication uses MOVEFILE_WRITE_THROUGH. Rust does not expose a
    // portable directory fsync handle on this platform.
    Ok(())
}

fn snapshot_path(data_dir: &Path, slot: u8) -> PathBuf {
    data_dir.join(format!("{EXCHANGE_WITHDRAWAL_FILE_PREFIX}.{slot}.bin"))
}

fn v3_marker_path(data_dir: &Path) -> PathBuf {
    data_dir.join(V3_MARKER_FILE)
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

fn write_anchor(bytes: &mut Vec<u8>, anchor: JournalAnchorV3) {
    bytes.extend_from_slice(&anchor.key_id);
    bytes.extend_from_slice(&anchor.journal_instance_id);
    bytes.extend_from_slice(&anchor.generation.to_le_bytes());
    bytes.extend_from_slice(&anchor.commitment);
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], ExchangeCustodyV3Error> {
    let end = offset
        .checked_add(N)
        .ok_or(ExchangeCustodyV3Error::Corrupt("v3 marker length overflow"))?;
    let value = bytes
        .get(*offset..end)
        .ok_or(ExchangeCustodyV3Error::Corrupt("v3 marker is truncated"))?;
    *offset = end;
    Ok(value.try_into().expect("fixed marker slice"))
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, ExchangeCustodyV3Error> {
    Ok(u32::from_le_bytes(take_array(bytes, offset)?))
}

fn take_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, ExchangeCustodyV3Error> {
    Ok(u64::from_le_bytes(take_array(bytes, offset)?))
}

fn keyed_digest(key: &[u8; 32], domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn constant_time_equal(expected: &[u8; 32], actual: &[u8]) -> bool {
    actual.len() == expected.len()
        && expected
            .iter()
            .zip(actual)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn io_error(
    operation: &'static str,
    path: impl AsRef<Path>,
    source: io::Error,
) -> ExchangeCustodyV3Error {
    ExchangeCustodyV3Error::Io {
        operation,
        path: path.as_ref().to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::exchange_withdrawal_v3::{
        AddIntentV3, AttachSignerPackageV3, AuthorizeReleaseV3, CompleteReleaseV3, DecisionScopeV3,
        ExactBytesV3, PolicyWindowStateV3, PrepareWithdrawalV3, ReservedInputV3,
        SignerPackageEvidenceV3, TerminalDecisionV3, ValidatedV2MigrationInputV3,
        WithdrawalActionV3, WithdrawalCoreV3,
    };
    #[cfg(all(feature = "production-v4", not(feature = "production-v4-testnet")))]
    use crate::{ExchangeCustodyV3WalletState, Node};

    const KEY: [u8; 32] = [0x41; 32];
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        root: PathBuf,
        data: PathBuf,
        anchor: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "cmfd-exchange-custody-v3-{}-{sequence}",
                std::process::id()
            ));
            let data = root.join("data");
            fs::create_dir_all(&data).unwrap();
            Self {
                anchor: root.join("external-anchor.json"),
                root,
                data,
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn migration_output() -> MigrationOutputV3 {
        let source_bytes = legacy_v2_bytes(0x71);
        let source_anchor = JournalAnchorV3 {
            key_id: [0x11; 32],
            journal_instance_id: [0x12; 32],
            generation: 7,
            commitment: [0x13; 32],
        };
        migrate_validated_v2(
            ValidatedV2MigrationInputV3 {
                source_schema_version: LEGACY_V2_VERSION,
                source_snapshot_digest: validated_v2_snapshot_digest(&source_bytes),
                source_current_anchor: source_anchor,
                source_external_anchor: source_anchor,
                migration_id: [0x21; 32],
                migration_decision_id: [0x22; 32],
                migration_approval_digest: [0x23; 32],
                binding: JournalBindingV3 {
                    network_id: [0x31; 32],
                    consensus_fingerprint: [0x32; 32],
                    genesis: [0x33; 32],
                },
                new_journal_instance_id: [0x34; 32],
                policy_id: [0x35; 32],
                initial_policy_window: PolicyWindowStateV3::default(),
                active_keyring: KeyringAnchorV3 {
                    instance_id: [0x36; 32],
                    generation: 1,
                    commitment: [0x37; 32],
                },
                released_records: Vec::new(),
            },
            &KEY,
        )
        .unwrap()
    }

    fn legacy_v2_bytes(fill: u8) -> Vec<u8> {
        let mut bytes = Vec::from(SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&LEGACY_V2_VERSION.to_le_bytes());
        bytes.extend_from_slice(&[fill; 64]);
        bytes
    }

    #[test]
    fn persisted_wallet_latch_detects_incomplete_v3_migration_slots() {
        let directory = TestDirectory::new();
        assert!(!persisted_v3_wallet_claim_required(&directory.data));

        fs::write(snapshot_path(&directory.data, 0), legacy_v2_bytes(0x71)).unwrap();
        fs::write(snapshot_path(&directory.data, 1), legacy_v2_bytes(0x72)).unwrap();
        assert!(!persisted_v3_wallet_claim_required(&directory.data));

        fs::write(
            snapshot_path(&directory.data, 1),
            migration_output().authenticated_snapshot,
        )
        .unwrap();
        assert!(persisted_v3_wallet_claim_required(&directory.data));

        fs::write(snapshot_path(&directory.data, 1), legacy_v2_bytes(0x72)).unwrap();
        fs::write(v3_marker_path(&directory.data), b"corrupt-marker").unwrap();
        assert!(persisted_v3_wallet_claim_required(&directory.data));
    }

    fn write_external_anchor(path: &Path, anchor: JournalAnchorV3) {
        let bytes = serde_json::to_vec(&ExternalAnchorDocumentV3 {
            key_id: hex::encode(anchor.key_id),
            journal_instance_id: hex::encode(anchor.journal_instance_id),
            generation: anchor.generation.to_string(),
            commitment: hex::encode(anchor.commitment),
        })
        .unwrap();
        fs::write(path, bytes).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn production_external_control_rejects_node_owned_authority_path() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        write_external_anchor(&directory.anchor, migration_output().initial_anchor);
        fs::set_permissions(&directory.anchor, fs::Permissions::from_mode(0o444)).unwrap();
        let file = open_read_only(&directory.anchor).unwrap();

        assert!(matches!(
            validate_external_file(
                &file,
                &directory.anchor,
                "external anchor",
                FileSecurity::Production,
            ),
            Err(ExchangeCustodyV3Error::InvalidControlPath(
                "external anchor"
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_authority_rejects_attacker_owned_ancestor() {
        let authorities = UnixQualificationAuthorities::parse(&[
            "uid:0".to_owned(),
            "uid:1001".to_owned(),
            "uid:1002".to_owned(),
            "gid:2001".to_owned(),
        ])
        .unwrap();

        assert!(validate_unix_directory_authority(1002, 2001, 0o770, &authorities).is_ok());
        assert!(matches!(
            validate_unix_directory_authority(9001, 2001, 0o750, &authorities),
            Err(ExchangeCustodyV3Error::Corrupt(
                "Unix custody object owner is outside the configured UID allowlist"
            ))
        ));
        assert!(matches!(
            validate_unix_directory_authority(1002, 9001, 0o770, &authorities),
            Err(ExchangeCustodyV3Error::Corrupt(
                "Unix custody authority ancestor has an unlisted group writer"
            ))
        ));
    }

    #[test]
    fn production_keyring_passphrase_rejects_node_controlled_path() {
        let directory = TestDirectory::new();
        let passphrase = directory.root.join("keyring.passphrase");
        fs::write(&passphrase, b"correct horse battery staple").unwrap();

        assert!(load_keyring_passphrase_v3(&directory.data, &passphrase).is_err());
    }

    fn install_initial(directory: &TestDirectory, output: &MigrationOutputV3) {
        for slot in 0..=1 {
            atomic_replace_node_file(
                &snapshot_path(&directory.data, slot),
                &output.authenticated_snapshot,
                FileSecurity::PortableTest,
            )
            .unwrap();
        }
        let marker = ActivationMarkerV3::from_output(output);
        atomic_create_node_file(
            &v3_marker_path(&directory.data),
            &marker.encode(&KEY),
            FileSecurity::PortableTest,
        )
        .unwrap();
        write_external_anchor(&directory.anchor, output.initial_anchor);
    }

    #[cfg(all(feature = "production-v4", not(feature = "production-v4-testnet")))]
    #[test]
    fn node_restart_with_valid_v3_slots_reaches_required_wallet_latch() {
        let directory = TestDirectory::new();
        install_initial(&directory, &migration_output());

        let node = Node::open(&directory.data).unwrap();
        assert_eq!(
            node.exchange_custody_v3_wallet_state,
            ExchangeCustodyV3WalletState::Required
        );
    }

    fn open_test_store(
        directory: &TestDirectory,
        output: &MigrationOutputV3,
    ) -> Result<ExchangeCustodyV3Store, ExchangeCustodyV3Error> {
        ExchangeCustodyV3Store::open_with_material(
            fs::canonicalize(&directory.data).unwrap(),
            fs::canonicalize(&directory.anchor).unwrap(),
            LoadedJournalKeyV3(Zeroizing::new(KEY)),
            output.journal.binding,
            output.journal.policy_id,
            output.journal.active_keyring,
            FileSecurity::PortableTest,
        )
    }

    fn add_intent(expected_anchor: JournalAnchorV3) -> JournalTransitionV3 {
        JournalTransitionV3::AddIntent(AddIntentV3 {
            expected_anchor,
            core: WithdrawalCoreV3 {
                request_id: "withdrawal-1".to_owned(),
                request_digest: [0x51; 32],
                destination: [0x52; 32],
                amount_atoms: 10,
                fee_atoms: 2,
                change_atoms: 3,
                output_spendable_height: 9,
                signing_digest: [0x53; 32],
                reservations: vec![ReservedInputV3 {
                    outpoint: ReservedOutpointV3 {
                        txid: [0x54; 32],
                        index: 0,
                    },
                    value_atoms: 15,
                    wallet_key_id: [0x55; 32],
                    public_key: [0x56; 32],
                    signer_id: [0x57; 32],
                }],
            },
        })
    }

    #[test]
    fn corrupt_slot_recovers_authenticated_peer_and_reports_degraded_redundancy() {
        let directory = TestDirectory::new();
        let output = migration_output();
        install_initial(&directory, &output);
        fs::write(snapshot_path(&directory.data, 0), b"corrupt").unwrap();

        let store = open_test_store(&directory, &output).unwrap();
        assert_eq!(store.current_anchor().unwrap(), output.initial_anchor);
        assert!(store.redundancy_degraded());
    }

    #[test]
    fn externally_pinned_newer_state_rejects_rollback_to_surviving_old_slot() {
        let directory = TestDirectory::new();
        let output = migration_output();
        install_initial(&directory, &output);
        let mut store = open_test_store(&directory, &output).unwrap();
        let next = store
            .commit_transition(add_intent(output.initial_anchor))
            .unwrap();
        write_external_anchor(&directory.anchor, next);
        drop(store);
        fs::write(snapshot_path(&directory.data, 0), b"corrupt-current").unwrap();

        assert!(matches!(
            open_test_store(&directory, &output),
            Err(ExchangeCustodyV3Error::ExternalAnchorAhead)
        ));
    }

    #[test]
    fn failed_candidate_publication_faults_store_without_swapping_state_or_disk() {
        let directory = TestDirectory::new();
        let output = migration_output();
        install_initial(&directory, &output);
        let original_slot = fs::read(snapshot_path(&directory.data, 0)).unwrap();
        let mut store = open_test_store(&directory, &output).unwrap();
        store.inject_next_persistence_failure();

        assert!(matches!(
            store.commit_transition(add_intent(output.initial_anchor)),
            Err(ExchangeCustodyV3Error::InjectedPersistenceFailure)
        ));
        assert!(store.is_faulted());
        assert_eq!(store.current_anchor().unwrap(), output.initial_anchor);
        assert_eq!(
            fs::read(snapshot_path(&directory.data, 0)).unwrap(),
            original_slot
        );
        assert!(matches!(
            store.commit_transition(add_intent(output.initial_anchor)),
            Err(ExchangeCustodyV3Error::Faulted)
        ));
    }

    #[test]
    fn legacy_v2_slots_are_rejected_without_automatic_upgrade() {
        let directory = TestDirectory::new();
        let output = migration_output();
        for slot in 0..=1 {
            atomic_replace_node_file(
                &snapshot_path(&directory.data, slot),
                &legacy_v2_bytes(0x70 + slot),
                FileSecurity::PortableTest,
            )
            .unwrap();
        }

        assert!(matches!(
            ExchangeCustodyV3Store::open_with_material(
                fs::canonicalize(&directory.data).unwrap(),
                directory.anchor.clone(),
                LoadedJournalKeyV3(Zeroizing::new(KEY)),
                output.journal.binding,
                output.journal.policy_id,
                output.journal.active_keyring,
                FileSecurity::PortableTest,
            ),
            Err(ExchangeCustodyV3Error::ExplicitMigrationRequired)
        ));
    }

    #[test]
    fn middle_batch_failure_leaves_memory_and_both_slots_unchanged() {
        let directory = TestDirectory::new();
        let output = migration_output();
        install_initial(&directory, &output);
        let first_before = fs::read(snapshot_path(&directory.data, 0)).unwrap();
        let second_before = fs::read(snapshot_path(&directory.data, 1)).unwrap();
        let mut store = open_test_store(&directory, &output).unwrap();
        let stale_prepare = JournalTransitionV3::Prepare(PrepareWithdrawalV3 {
            expected_anchor: output.initial_anchor,
            request_id: "withdrawal-1".to_owned(),
            request_digest: [0x51; 32],
        });

        assert!(matches!(
            store.commit_transitions(vec![add_intent(output.initial_anchor), stale_prepare]),
            Err(ExchangeCustodyV3Error::Journal(
                ExchangeWithdrawalV3Error::AnchorMismatch
            ))
        ));
        assert!(!store.is_faulted());
        assert_eq!(store.current_anchor().unwrap(), output.initial_anchor);
        assert_eq!(
            fs::read(snapshot_path(&directory.data, 0)).unwrap(),
            first_before
        );
        assert_eq!(
            fs::read(snapshot_path(&directory.data, 1)).unwrap(),
            second_before
        );
    }

    #[test]
    fn batch_publishes_only_final_candidate_and_loader_accepts_history_gap() {
        let directory = TestDirectory::new();
        let output = migration_output();
        install_initial(&directory, &output);
        let initial_bytes = output.authenticated_snapshot.clone();
        let intermediate = output
            .journal
            .apply_transition(&KEY, add_intent(output.initial_anchor))
            .unwrap();
        let intermediate_anchor = intermediate.anchor(&KEY).unwrap();
        let prepare = JournalTransitionV3::Prepare(PrepareWithdrawalV3 {
            expected_anchor: intermediate_anchor,
            request_id: "withdrawal-1".to_owned(),
            request_digest: [0x51; 32],
        });
        let mut store = open_test_store(&directory, &output).unwrap();

        let final_anchor = store
            .commit_transitions(vec![add_intent(output.initial_anchor), prepare])
            .unwrap();
        assert_eq!(
            final_anchor.generation,
            output.initial_anchor.generation + 2
        );
        assert_eq!(
            fs::read(snapshot_path(&directory.data, 0)).unwrap(),
            initial_bytes
        );
        write_external_anchor(&directory.anchor, final_anchor);
        drop(store);

        let reopened = open_test_store(&directory, &output).unwrap();
        assert_eq!(reopened.current_anchor().unwrap(), final_anchor);
        assert!(!reopened.redundancy_degraded());
    }

    #[test]
    fn authorized_completion_requires_authorized_anchor_and_recovers_after_publish_failure() {
        let directory = TestDirectory::new();
        let output = migration_output();
        install_initial(&directory, &output);

        let intent = add_intent(output.initial_anchor);
        let intent_state = output
            .journal
            .apply_transition(&KEY, intent.clone())
            .unwrap();
        let intent_anchor = intent_state.anchor(&KEY).unwrap();
        let prepare = JournalTransitionV3::Prepare(PrepareWithdrawalV3 {
            expected_anchor: intent_anchor,
            request_id: "withdrawal-1".to_owned(),
            request_digest: [0x51; 32],
        });
        let prepared_state = intent_state
            .apply_transition(&KEY, prepare.clone())
            .unwrap();
        let prepared_anchor = prepared_state.anchor(&KEY).unwrap();
        let package = SignerPackageEvidenceV3 {
            prepared_anchor,
            keyring_anchor: output.journal.active_keyring,
            transaction_signing_digest: [0x53; 32],
            exact_package: ExactBytesV3::signer_package(vec![0x61; 32]).unwrap(),
        };
        let attach = JournalTransitionV3::AttachSignerPackage(AttachSignerPackageV3 {
            expected_anchor: prepared_anchor,
            request_id: "withdrawal-1".to_owned(),
            request_digest: [0x51; 32],
            signer_package: package.clone(),
        });
        let attached_state = prepared_state
            .apply_transition(&KEY, attach.clone())
            .unwrap();
        let attached_anchor = attached_state.anchor(&KEY).unwrap();

        let mut store = open_test_store(&directory, &output).unwrap();
        assert_eq!(
            store
                .commit_candidate(output.initial_anchor, attached_state)
                .unwrap(),
            attached_anchor
        );
        write_external_anchor(&directory.anchor, attached_anchor);

        let terminal = TerminalDecisionV3 {
            scope: DecisionScopeV3::NativeV3,
            action: WithdrawalActionV3::Release,
            decision_id: [0x62; 32],
            approval_digest: [0x63; 32],
            policy_id: output.journal.policy_id,
            action_anchor: attached_anchor,
            request_digest: [0x51; 32],
            transaction_signing_digest: [0x53; 32],
            decided_at_unix_seconds: 100,
            accounted_at_unix_seconds: 100,
        };
        let authorize = JournalTransitionV3::AuthorizeRelease(AuthorizeReleaseV3 {
            expected_anchor: attached_anchor,
            request_id: "withdrawal-1".to_owned(),
            request_digest: [0x51; 32],
            terminal,
        });
        let authorized_state = store
            .journal()
            .apply_transition(&KEY, authorize.clone())
            .unwrap();
        let authorized_anchor = authorized_state.anchor(&KEY).unwrap();
        assert_eq!(
            store.commit_transition(authorize).unwrap(),
            authorized_anchor
        );

        let completion = CompleteReleaseV3 {
            expected_anchor: authorized_anchor,
            request_id: "withdrawal-1".to_owned(),
            request_digest: [0x51; 32],
            decision_id: terminal.decision_id,
            approval_digest: terminal.approval_digest,
            signer_package_digest: package.exact_package.digest,
            transaction_signing_digest: [0x53; 32],
            txid: [0x64; 32],
            exact_transaction_bytes: vec![0x65; 48],
        };
        let released_state = store
            .journal()
            .apply_transition(&KEY, JournalTransitionV3::CompleteRelease(completion))
            .unwrap();
        let released_anchor = released_state.anchor(&KEY).unwrap();
        assert!(matches!(
            store.commit_authorized_completion(authorized_anchor, released_state.clone()),
            Err(ExchangeCustodyV3Error::ExternalAnchorMismatch)
        ));
        write_external_anchor(&directory.anchor, authorized_anchor);
        store.inject_next_persistence_failure();
        assert!(matches!(
            store.commit_authorized_completion(authorized_anchor, released_state.clone()),
            Err(ExchangeCustodyV3Error::InjectedPersistenceFailure)
        ));
        assert_eq!(store.current_anchor().unwrap(), authorized_anchor);
        assert!(fs::read_dir(&directory.data).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("v3-tmp")
        }));
        drop(store);

        let mut recovered = open_test_store(&directory, &output).unwrap();
        assert_eq!(
            recovered.external_anchor_relationship().unwrap(),
            ExternalAnchorRelationshipV3::Current
        );
        assert_eq!(
            recovered
                .commit_authorized_completion(authorized_anchor, released_state)
                .unwrap(),
            released_anchor
        );
        let reservations = recovered.startup_reservations();
        assert!(!reservations.is_empty());
        assert!(
            reservations
                .iter()
                .all(|reservation| reservation.phase == StartupReservationPhaseV3::Released)
        );
    }
}
