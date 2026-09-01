//! Pure authenticated state machine for exchange-withdrawal journal v3.
//!
//! This module deliberately performs no file I/O, policy-signature checking,
//! transaction parsing, or signer transport. Callers must verify those inputs
//! before constructing a transition, then durably replace the old snapshot
//! with `encode_authenticated` before acting on the returned state. The state
//! machine makes the journal update atomic: a release cannot become terminal
//! without its exact transaction, policy-window debit, and approval evidence;
//! a cancellation cannot acquire transaction bytes; and compaction cannot
//! remove a terminal record without installing its permanent reuse tombstone.
//!
//! v1/v2 snapshots are never decoded here. Migration is available only through
//! `migrate_validated_v2`, whose input requires an exactly externally pinned v2
//! anchor and explicit migration evidence. This prevents a runtime upgrade from
//! silently reinterpreting or rewriting the v0.4 journal.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use blake3::Hasher;
use thiserror::Error;

use crate::exchange_policy::MAX_APPROVAL_VALIDITY_SECONDS;

const SNAPSHOT_MAGIC: [u8; 8] = *b"CMFDEXW\0";
const SNAPSHOT_VERSION: u32 = 3;
const LEGACY_V1_VERSION: u32 = 1;
const LEGACY_V2_VERSION: u32 = 2;
const HEADER_BYTES: usize = 8 + 4 + 8;
const AUTH_TAG_BYTES: usize = 32;

pub(crate) const MAX_V3_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_V3_WITHDRAWAL_RECORDS: usize = 65_536;
pub(crate) const MAX_V3_REQUEST_ID_BYTES: usize = 128;
pub(crate) const MAX_V3_RESERVED_INPUTS: usize = 4_096;
pub(crate) const MAX_V3_POLICY_EVENTS: usize = 65_536;
pub(crate) const MAX_V3_TOMBSTONES: usize = 262_144;
pub(crate) const MAX_V3_COMMITMENTS: usize = 327_682;
pub(crate) const MAX_V3_SIGNER_PACKAGE_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_V3_TRANSACTION_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const POLICY_WINDOW_SECONDS: u64 = 86_400;

const KEY_ID_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-KEY-ID/V3";
const AUTH_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-JOURNAL/AUTH/V3";
const CONTENT_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-CONTENT/V3";
const COMMITMENT_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-COMMITMENT/V3";
const REQUEST_TAG_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-ARCHIVE/REQUEST-TAG/V1";
const ARCHIVE_PAYLOAD_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-ARCHIVE/PAYLOAD/V1";
const SIGNER_PACKAGE_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-SIGNER-PACKAGE/V3";
const TRANSACTION_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-TRANSACTION/V3";
const MIGRATION_INPUT_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-MIGRATION-INPUT/V2-TO-V3";
const MIGRATION_SOURCE_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-MIGRATION-SOURCE/V2";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum ExchangeWithdrawalV3Error {
    #[error("the v3 journal key is invalid")]
    InvalidJournalKey,
    #[error("a v1/v2 withdrawal journal requires explicit validated migration")]
    ExplicitMigrationRequired,
    #[error("the withdrawal snapshot version is unsupported")]
    UnsupportedVersion,
    #[error("the authenticated withdrawal snapshot is truncated")]
    Truncated,
    #[error("the authenticated withdrawal snapshot is too large")]
    SnapshotTooLarge,
    #[error("the authenticated withdrawal snapshot length is invalid")]
    InvalidSnapshotLength,
    #[error("the authenticated withdrawal snapshot tag is invalid")]
    AuthenticationFailed,
    #[error("the withdrawal snapshot is not canonically encoded")]
    NonCanonical,
    #[error("the withdrawal state binding is invalid")]
    InvalidBinding,
    #[error("the withdrawal state is invalid: {0}")]
    InvalidState(&'static str),
    #[error("the withdrawal transition is invalid: {0}")]
    InvalidTransition(&'static str),
    #[error("the transition expected a different current journal anchor")]
    AnchorMismatch,
    #[error("the withdrawal request is unknown")]
    UnknownRequest,
    #[error("the withdrawal request identifier or digest already exists")]
    DuplicateRequest,
    #[error("the withdrawal request was permanently tombstoned")]
    ReusedArchivedRequest,
    #[error("the collection exceeds the v3 journal's authenticated bound: {0}")]
    Capacity(&'static str),
    #[error("an integer operation overflowed")]
    ArithmeticOverflow,
    #[error("the v2 migration contract is invalid: {0}")]
    InvalidMigration(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct JournalAnchorV3 {
    pub key_id: [u8; 32],
    pub journal_instance_id: [u8; 32],
    pub generation: u64,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct KeyringAnchorV3 {
    pub instance_id: [u8; 32],
    pub generation: u64,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JournalBindingV3 {
    pub network_id: [u8; 32],
    pub consensus_fingerprint: [u8; 32],
    pub genesis: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ReservedOutpointV3 {
    pub txid: [u8; 32],
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReservedInputV3 {
    pub outpoint: ReservedOutpointV3,
    pub value_atoms: u64,
    pub wallet_key_id: [u8; 32],
    pub public_key: [u8; 32],
    pub signer_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WithdrawalCoreV3 {
    pub request_id: String,
    pub request_digest: [u8; 32],
    pub destination: [u8; 32],
    pub amount_atoms: u64,
    pub fee_atoms: u64,
    pub change_atoms: u64,
    pub output_spendable_height: u64,
    pub signing_digest: [u8; 32],
    pub reservations: Vec<ReservedInputV3>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactBytesV3 {
    pub digest: [u8; 32],
    pub bytes: Vec<u8>,
}

impl ExactBytesV3 {
    pub(crate) fn signer_package(bytes: Vec<u8>) -> Result<Self, ExchangeWithdrawalV3Error> {
        Self::new(bytes, MAX_V3_SIGNER_PACKAGE_BYTES, SIGNER_PACKAGE_DOMAIN)
    }

    pub(crate) fn transaction(bytes: Vec<u8>) -> Result<Self, ExchangeWithdrawalV3Error> {
        Self::new(bytes, MAX_V3_TRANSACTION_BYTES, TRANSACTION_DOMAIN)
    }

    fn new(
        bytes: Vec<u8>,
        limit: usize,
        domain: &'static str,
    ) -> Result<Self, ExchangeWithdrawalV3Error> {
        if bytes.is_empty() || bytes.len() > limit {
            return Err(ExchangeWithdrawalV3Error::Capacity("exact byte payload"));
        }
        let digest = unkeyed_digest(domain, &bytes);
        Ok(Self { digest, bytes })
    }

    fn validate(
        &self,
        limit: usize,
        domain: &'static str,
    ) -> Result<(), ExchangeWithdrawalV3Error> {
        if self.bytes.is_empty()
            || self.bytes.len() > limit
            || self.digest != unkeyed_digest(domain, &self.bytes)
        {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "exact payload bytes or digest are invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WithdrawalActionV3 {
    Release,
    Cancel,
}

impl WithdrawalActionV3 {
    fn tag(self) -> u8 {
        match self {
            Self::Release => 1,
            Self::Cancel => 2,
        }
    }

    fn decode(tag: u8) -> Result<Self, ExchangeWithdrawalV3Error> {
        match tag {
            1 => Ok(Self::Release),
            2 => Ok(Self::Cancel),
            _ => Err(ExchangeWithdrawalV3Error::NonCanonical),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecisionScopeV3 {
    NativeV3,
    ValidatedV2Migration,
}

impl DecisionScopeV3 {
    fn tag(self) -> u8 {
        match self {
            Self::NativeV3 => 1,
            Self::ValidatedV2Migration => 2,
        }
    }

    fn decode(tag: u8) -> Result<Self, ExchangeWithdrawalV3Error> {
        match tag {
            1 => Ok(Self::NativeV3),
            2 => Ok(Self::ValidatedV2Migration),
            _ => Err(ExchangeWithdrawalV3Error::NonCanonical),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalDecisionV3 {
    pub scope: DecisionScopeV3,
    pub action: WithdrawalActionV3,
    pub decision_id: [u8; 32],
    pub approval_digest: [u8; 32],
    pub policy_id: [u8; 32],
    pub action_anchor: JournalAnchorV3,
    pub request_digest: [u8; 32],
    pub transaction_signing_digest: [u8; 32],
    pub decided_at_unix_seconds: u64,
    pub accounted_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignerPackageEvidenceV3 {
    pub prepared_anchor: JournalAnchorV3,
    pub keyring_anchor: KeyringAnchorV3,
    pub transaction_signing_digest: [u8; 32],
    pub exact_package: ExactBytesV3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecordOriginV3 {
    NativeV3,
    ValidatedV2 { source_record_digest: [u8; 32] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedPhaseV3 {
    pub prepared_generation: u64,
    pub signer_package: Option<SignerPackageEvidenceV3>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleasedPhaseV3 {
    pub prepared: PreparedPhaseV3,
    pub terminal: TerminalDecisionV3,
    pub txid: [u8; 32],
    pub exact_transaction: ExactBytesV3,
    pub debit_atoms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseAuthorizedPhaseV3 {
    pub prepared: PreparedPhaseV3,
    pub terminal: TerminalDecisionV3,
    pub debit_atoms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanceledPhaseV3 {
    pub prepared: Option<PreparedPhaseV3>,
    pub terminal: TerminalDecisionV3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WithdrawalPhaseV3 {
    Intent,
    Prepared(PreparedPhaseV3),
    ReleaseAuthorized(ReleaseAuthorizedPhaseV3),
    Released(ReleasedPhaseV3),
    Canceled(CanceledPhaseV3),
}

impl WithdrawalPhaseV3 {
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(self, Self::Released(_) | Self::Canceled(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WithdrawalRecordV3 {
    pub origin: RecordOriginV3,
    pub core: WithdrawalCoreV3,
    pub phase: WithdrawalPhaseV3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyReleaseEventV3 {
    pub request_digest: [u8; 32],
    pub released_at_unix_seconds: u64,
    pub debit_atoms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PolicyWindowStateV3 {
    pub time_watermark_unix_seconds: u64,
    pub release_events: Vec<PolicyReleaseEventV3>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminalPhaseV3 {
    Released,
    Canceled,
}

impl TerminalPhaseV3 {
    fn tag(self) -> u8 {
        match self {
            Self::Released => 1,
            Self::Canceled => 2,
        }
    }

    fn decode(tag: u8) -> Result<Self, ExchangeWithdrawalV3Error> {
        match tag {
            1 => Ok(Self::Released),
            2 => Ok(Self::Canceled),
            _ => Err(ExchangeWithdrawalV3Error::NonCanonical),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchiveTombstoneV3 {
    pub request_id_tag: [u8; 32],
    pub request_digest: [u8; 32],
    pub phase: TerminalPhaseV3,
    pub terminal_decision_id: [u8; 32],
    pub approval_digest: [u8; 32],
    pub archive_id: [u8; 32],
    pub record_index: u64,
    pub txid: Option<[u8; 32]>,
    pub debit_atoms: u64,
    pub record_payload_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyringHistoryEntryV3 {
    pub anchor: KeyringAnchorV3,
    pub rotation_decision_id: [u8; 32],
    pub approval_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MigrationReceiptV3 {
    pub migration_id: [u8; 32],
    pub source_snapshot_digest: [u8; 32],
    pub source_anchor: JournalAnchorV3,
    pub migration_decision_id: [u8; 32],
    pub migration_approval_digest: [u8; 32],
    pub migration_input_digest: [u8; 32],
    pub migrated_record_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExchangeWithdrawalJournalV3 {
    pub binding: JournalBindingV3,
    pub journal_key_id: [u8; 32],
    pub journal_instance_id: [u8; 32],
    pub generation: u64,
    /// Commitments for generations `1..generation`; the current commitment is
    /// derived from the current state and never trusted as an encoded field.
    pub prior_commitments: Vec<[u8; 32]>,
    pub migration: MigrationReceiptV3,
    pub policy_id: [u8; 32],
    pub policy_window: PolicyWindowStateV3,
    pub active_keyring: KeyringAnchorV3,
    pub prior_keyrings: Vec<KeyringHistoryEntryV3>,
    pub records: BTreeMap<String, WithdrawalRecordV3>,
    pub tombstones: BTreeMap<[u8; 32], ArchiveTombstoneV3>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedV2ReleasedRecordV3 {
    pub core: WithdrawalCoreV3,
    pub source_prepared_generation: u64,
    pub source_record_digest: [u8; 32],
    pub terminal: TerminalDecisionV3,
    pub txid: [u8; 32],
    pub exact_transaction_bytes: Vec<u8>,
    pub debit_atoms: u64,
}

/// Input to the only supported v2-to-v3 conversion path. The caller must first
/// authenticate and fully validate the v2 snapshot with the v2 implementation.
/// Exact equality of `source_current_anchor` and `source_external_anchor` is a
/// deliberate offline migration gate, not a general v2 anchor relationship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedV2MigrationInputV3 {
    pub source_schema_version: u32,
    pub source_snapshot_digest: [u8; 32],
    pub source_current_anchor: JournalAnchorV3,
    pub source_external_anchor: JournalAnchorV3,
    pub migration_id: [u8; 32],
    pub migration_decision_id: [u8; 32],
    pub migration_approval_digest: [u8; 32],
    pub binding: JournalBindingV3,
    pub new_journal_instance_id: [u8; 32],
    pub policy_id: [u8; 32],
    pub initial_policy_window: PolicyWindowStateV3,
    pub active_keyring: KeyringAnchorV3,
    /// Pending v2 Intent/Prepared records are intentionally unrepresentable.
    /// Migration callers must cancel or otherwise resolve them under v2 rules.
    pub released_records: Vec<ValidatedV2ReleasedRecordV3>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MigrationOutputV3 {
    pub journal: ExchangeWithdrawalJournalV3,
    pub receipt: MigrationReceiptV3,
    pub initial_anchor: JournalAnchorV3,
    pub authenticated_snapshot: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddIntentV3 {
    pub expected_anchor: JournalAnchorV3,
    pub core: WithdrawalCoreV3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrepareWithdrawalV3 {
    pub expected_anchor: JournalAnchorV3,
    pub request_id: String,
    pub request_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachSignerPackageV3 {
    pub expected_anchor: JournalAnchorV3,
    pub request_id: String,
    pub request_digest: [u8; 32],
    /// Integration must first parse and verify these exact bytes with the
    /// wallet signing protocol. The journal verifies their retained digest and
    /// all independently supplied bindings but does not reinterpret them.
    pub signer_package: SignerPackageEvidenceV3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizeReleaseV3 {
    pub expected_anchor: JournalAnchorV3,
    pub request_id: String,
    pub request_digest: [u8; 32],
    /// Must already have passed release policy limits and threshold approval.
    pub terminal: TerminalDecisionV3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompleteReleaseV3 {
    pub expected_anchor: JournalAnchorV3,
    pub request_id: String,
    pub request_digest: [u8; 32],
    pub decision_id: [u8; 32],
    pub approval_digest: [u8; 32],
    pub signer_package_digest: [u8; 32],
    pub transaction_signing_digest: [u8; 32],
    /// Must already have passed canonical consensus decode, signature checks,
    /// transaction-ID derivation, and exact signer-response assembly.
    pub txid: [u8; 32],
    pub exact_transaction_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CancelWithdrawalV3 {
    pub expected_anchor: JournalAnchorV3,
    pub request_id: String,
    pub request_digest: [u8; 32],
    /// Must already have passed the distinct cancel-policy threshold.
    pub terminal: TerminalDecisionV3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RotateKeyringV3 {
    pub expected_anchor: JournalAnchorV3,
    pub new_keyring: KeyringAnchorV3,
    pub rotation_decision_id: [u8; 32],
    pub approval_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchivePruneRecordV3 {
    pub request_id: String,
    pub request_digest: [u8; 32],
    pub record_index: u64,
    pub record_payload_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompactTerminalRecordsV3 {
    pub expected_anchor: JournalAnchorV3,
    /// The archive builder must bind its payload to this exact live source.
    pub archive_source_anchor: JournalAnchorV3,
    pub archive_id: [u8; 32],
    pub records: Vec<ArchivePruneRecordV3>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JournalTransitionV3 {
    AddIntent(AddIntentV3),
    Prepare(PrepareWithdrawalV3),
    AttachSignerPackage(AttachSignerPackageV3),
    AuthorizeRelease(AuthorizeReleaseV3),
    CompleteRelease(CompleteReleaseV3),
    Cancel(CancelWithdrawalV3),
    #[allow(dead_code)] // Rotation is offline-only until its explicit operator command lands.
    RotateKeyring(RotateKeyringV3),
    Compact(CompactTerminalRecordsV3),
}

impl JournalTransitionV3 {
    fn expected_anchor(&self) -> JournalAnchorV3 {
        match self {
            Self::AddIntent(value) => value.expected_anchor,
            Self::Prepare(value) => value.expected_anchor,
            Self::AttachSignerPackage(value) => value.expected_anchor,
            Self::AuthorizeRelease(value) => value.expected_anchor,
            Self::CompleteRelease(value) => value.expected_anchor,
            Self::Cancel(value) => value.expected_anchor,
            Self::RotateKeyring(value) => value.expected_anchor,
            Self::Compact(value) => value.expected_anchor,
        }
    }
}

impl ExchangeWithdrawalJournalV3 {
    pub(crate) fn anchor(
        &self,
        journal_key: &[u8; 32],
    ) -> Result<JournalAnchorV3, ExchangeWithdrawalV3Error> {
        validate_key(journal_key)?;
        if self.journal_key_id != journal_key_id(journal_key) {
            return Err(ExchangeWithdrawalV3Error::AuthenticationFailed);
        }
        Ok(JournalAnchorV3 {
            key_id: self.journal_key_id,
            journal_instance_id: self.journal_instance_id,
            generation: self.generation,
            commitment: compute_current_commitment(self, journal_key)?,
        })
    }

    pub(crate) fn anchor_at(
        &self,
        journal_key: &[u8; 32],
        generation: u64,
    ) -> Result<JournalAnchorV3, ExchangeWithdrawalV3Error> {
        if generation == 0 || generation > self.generation {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "journal anchor generation is unavailable",
            ));
        }
        let commitment = if generation == self.generation {
            compute_current_commitment(self, journal_key)?
        } else {
            let index = usize::try_from(generation - 1)
                .map_err(|_| ExchangeWithdrawalV3Error::ArithmeticOverflow)?;
            *self
                .prior_commitments
                .get(index)
                .ok_or(ExchangeWithdrawalV3Error::InvalidState(
                    "journal commitment history is incomplete",
                ))?
        };
        Ok(JournalAnchorV3 {
            key_id: self.journal_key_id,
            journal_instance_id: self.journal_instance_id,
            generation,
            commitment,
        })
    }

    /// Produces the exact compaction item for a live canceled record. The
    /// archive builder must retain the same canonical record bytes and source
    /// anchor before this item is accepted by `Compact`.
    pub(crate) fn archive_prune_record(
        &self,
        journal_key: &[u8; 32],
        request_id: &str,
        record_index: u64,
    ) -> Result<ArchivePruneRecordV3, ExchangeWithdrawalV3Error> {
        self.validate(journal_key)?;
        let record = self
            .records
            .get(request_id)
            .ok_or(ExchangeWithdrawalV3Error::UnknownRequest)?;
        if !matches!(&record.phase, WithdrawalPhaseV3::Canceled(_)) {
            return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                "only a canceled record can be archived",
            ));
        }
        let payload = encode_record(record)?;
        Ok(ArchivePruneRecordV3 {
            request_id: request_id.to_owned(),
            request_digest: record.core.request_digest,
            record_index,
            record_payload_digest: keyed_digest(journal_key, ARCHIVE_PAYLOAD_DOMAIN, &payload),
        })
    }

    pub(crate) fn canonical_record_bytes(
        &self,
        request_id: &str,
    ) -> Result<Vec<u8>, ExchangeWithdrawalV3Error> {
        let record = self
            .records
            .get(request_id)
            .ok_or(ExchangeWithdrawalV3Error::UnknownRequest)?;
        encode_record(record)
    }

    pub(crate) fn encode_authenticated(
        &self,
        journal_key: &[u8; 32],
    ) -> Result<Vec<u8>, ExchangeWithdrawalV3Error> {
        self.validate(journal_key)?;
        let payload = encode_state_payload(self)?;
        let payload_len = u64::try_from(payload.len())
            .map_err(|_| ExchangeWithdrawalV3Error::SnapshotTooLarge)?;
        let total = HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|value| value.checked_add(AUTH_TAG_BYTES))
            .ok_or(ExchangeWithdrawalV3Error::SnapshotTooLarge)?;
        if total > MAX_V3_SNAPSHOT_BYTES {
            return Err(ExchangeWithdrawalV3Error::SnapshotTooLarge);
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&payload);
        let tag = keyed_digest(journal_key, AUTH_DOMAIN, &bytes);
        bytes.extend_from_slice(&tag);
        Ok(bytes)
    }

    pub(crate) fn decode_authenticated(
        bytes: &[u8],
        journal_key: &[u8; 32],
    ) -> Result<Self, ExchangeWithdrawalV3Error> {
        validate_key(journal_key)?;
        if bytes.len() > MAX_V3_SNAPSHOT_BYTES {
            return Err(ExchangeWithdrawalV3Error::SnapshotTooLarge);
        }
        if bytes.len() < HEADER_BYTES + AUTH_TAG_BYTES {
            return Err(ExchangeWithdrawalV3Error::Truncated);
        }
        if bytes[..8] != SNAPSHOT_MAGIC {
            return Err(ExchangeWithdrawalV3Error::UnsupportedVersion);
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().expect("fixed slice"));
        if matches!(version, LEGACY_V1_VERSION | LEGACY_V2_VERSION) {
            return Err(ExchangeWithdrawalV3Error::ExplicitMigrationRequired);
        }
        if version != SNAPSHOT_VERSION {
            return Err(ExchangeWithdrawalV3Error::UnsupportedVersion);
        }
        let payload_len = u64::from_le_bytes(bytes[12..20].try_into().expect("fixed slice"));
        let payload_len = usize::try_from(payload_len)
            .map_err(|_| ExchangeWithdrawalV3Error::InvalidSnapshotLength)?;
        let expected_len = HEADER_BYTES
            .checked_add(payload_len)
            .and_then(|value| value.checked_add(AUTH_TAG_BYTES))
            .ok_or(ExchangeWithdrawalV3Error::InvalidSnapshotLength)?;
        if expected_len != bytes.len() {
            return Err(ExchangeWithdrawalV3Error::InvalidSnapshotLength);
        }
        let tag_offset = bytes.len() - AUTH_TAG_BYTES;
        let expected_tag = keyed_digest(journal_key, AUTH_DOMAIN, &bytes[..tag_offset]);
        if !constant_time_equal(&expected_tag, &bytes[tag_offset..]) {
            return Err(ExchangeWithdrawalV3Error::AuthenticationFailed);
        }
        let mut decoder = Decoder::new(&bytes[HEADER_BYTES..tag_offset]);
        let state = decode_state_payload(&mut decoder)?;
        if !decoder.is_empty() {
            return Err(ExchangeWithdrawalV3Error::NonCanonical);
        }
        state.validate(journal_key)?;
        if state.encode_authenticated(journal_key)? != bytes {
            return Err(ExchangeWithdrawalV3Error::NonCanonical);
        }
        Ok(state)
    }

    /// Returns a fully validated candidate state. The caller must durably
    /// replace the prior authenticated snapshot before signing, broadcasting,
    /// returning success, releasing reservations, or deleting archive input.
    pub(crate) fn apply_transition(
        &self,
        journal_key: &[u8; 32],
        transition: JournalTransitionV3,
    ) -> Result<Self, ExchangeWithdrawalV3Error> {
        self.validate(journal_key)?;
        let current_anchor = self.anchor(journal_key)?;
        if transition.expected_anchor() != current_anchor {
            return Err(ExchangeWithdrawalV3Error::AnchorMismatch);
        }
        if self.prior_commitments.len() >= MAX_V3_COMMITMENTS {
            return Err(ExchangeWithdrawalV3Error::Capacity(
                "journal commitment history",
            ));
        }
        let mut candidate = self.clone();
        candidate.prior_commitments.push(current_anchor.commitment);
        candidate.generation = candidate
            .generation
            .checked_add(1)
            .ok_or(ExchangeWithdrawalV3Error::ArithmeticOverflow)?;

        match transition {
            JournalTransitionV3::AddIntent(value) => {
                apply_add_intent(&mut candidate, journal_key, value)?
            }
            JournalTransitionV3::Prepare(value) => apply_prepare(&mut candidate, value)?,
            JournalTransitionV3::AttachSignerPackage(value) => {
                apply_attach_package(&mut candidate, journal_key, value)?
            }
            JournalTransitionV3::AuthorizeRelease(value) => {
                apply_authorize_release(&mut candidate, value)?
            }
            JournalTransitionV3::CompleteRelease(value) => {
                apply_complete_release(&mut candidate, value)?
            }
            JournalTransitionV3::Cancel(value) => apply_cancel(&mut candidate, value)?,
            JournalTransitionV3::RotateKeyring(value) => {
                apply_rotate_keyring(&mut candidate, value)?
            }
            JournalTransitionV3::Compact(value) => {
                apply_compaction(&mut candidate, journal_key, value)?
            }
        }
        candidate.validate(journal_key)?;
        // Force size validation before the candidate can be handed to storage.
        let _ = candidate.encode_authenticated(journal_key)?;
        Ok(candidate)
    }

    pub(crate) fn validate(&self, journal_key: &[u8; 32]) -> Result<(), ExchangeWithdrawalV3Error> {
        validate_key(journal_key)?;
        validate_binding(self.binding)?;
        if self.journal_key_id != journal_key_id(journal_key) {
            return Err(ExchangeWithdrawalV3Error::AuthenticationFailed);
        }
        if is_zero(&self.journal_instance_id) || self.generation == 0 || self.policy_id == [0; 32] {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "journal identity, generation, or policy is invalid",
            ));
        }
        let expected_history = usize::try_from(self.generation - 1)
            .map_err(|_| ExchangeWithdrawalV3Error::Capacity("journal generation"))?;
        if expected_history != self.prior_commitments.len()
            || self.prior_commitments.len() > MAX_V3_COMMITMENTS
            || self.prior_commitments.iter().any(is_zero)
        {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "commitment history does not match generation",
            ));
        }
        validate_migration_receipt(&self.migration)?;
        validate_keyring_anchor(self.active_keyring)?;
        validate_policy_window(&self.policy_window)?;
        validate_keyring_history(self)?;
        validate_records_and_tombstones(self, journal_key)?;
        let migrated_count = self
            .records
            .values()
            .filter(|record| matches!(record.origin, RecordOriginV3::ValidatedV2 { .. }))
            .count();
        if u64::try_from(migrated_count).ok() != Some(self.migration.migrated_record_count) {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "migration receipt record count does not match live legacy records",
            ));
        }
        Ok(())
    }
}

pub(crate) fn migrate_validated_v2(
    input: ValidatedV2MigrationInputV3,
    journal_key: &[u8; 32],
) -> Result<MigrationOutputV3, ExchangeWithdrawalV3Error> {
    validate_key(journal_key)?;
    if input.source_schema_version != LEGACY_V2_VERSION {
        return Err(ExchangeWithdrawalV3Error::InvalidMigration(
            "source schema must be exactly v2",
        ));
    }
    if input.source_current_anchor != input.source_external_anchor {
        return Err(ExchangeWithdrawalV3Error::InvalidMigration(
            "the external v2 anchor must exactly pin the current v2 state",
        ));
    }
    validate_foreign_anchor(input.source_current_anchor)?;
    validate_binding(input.binding)?;
    validate_keyring_anchor(input.active_keyring)?;
    validate_policy_window(&input.initial_policy_window)?;
    if is_zero(&input.source_snapshot_digest)
        || is_zero(&input.migration_id)
        || is_zero(&input.migration_decision_id)
        || is_zero(&input.migration_approval_digest)
        || is_zero(&input.new_journal_instance_id)
        || input.policy_id == [0; 32]
    {
        return Err(ExchangeWithdrawalV3Error::InvalidMigration(
            "migration evidence contains a zero identifier",
        ));
    }
    if input.new_journal_instance_id == input.source_current_anchor.journal_instance_id {
        return Err(ExchangeWithdrawalV3Error::InvalidMigration(
            "v3 must use a fresh journal instance identifier",
        ));
    }
    if input.released_records.len() > MAX_V3_WITHDRAWAL_RECORDS {
        return Err(ExchangeWithdrawalV3Error::Capacity(
            "migrated withdrawal records",
        ));
    }

    let migration_input_digest = migration_input_digest(&input)?;
    let migrated_record_count = u64::try_from(input.released_records.len())
        .map_err(|_| ExchangeWithdrawalV3Error::Capacity("migrated withdrawal records"))?;
    let receipt = MigrationReceiptV3 {
        migration_id: input.migration_id,
        source_snapshot_digest: input.source_snapshot_digest,
        source_anchor: input.source_current_anchor,
        migration_decision_id: input.migration_decision_id,
        migration_approval_digest: input.migration_approval_digest,
        migration_input_digest,
        migrated_record_count,
    };
    let mut records = BTreeMap::new();
    for source in input.released_records {
        if source.source_prepared_generation == 0
            || source.source_prepared_generation > receipt.source_anchor.generation
            || is_zero(&source.source_record_digest)
            || is_zero(&source.txid)
        {
            return Err(ExchangeWithdrawalV3Error::InvalidMigration(
                "a migrated v2 released record is invalid",
            ));
        }
        if source.terminal.scope != DecisionScopeV3::ValidatedV2Migration
            || source.terminal.action != WithdrawalActionV3::Release
            || source.terminal.action_anchor != receipt.source_anchor
        {
            return Err(ExchangeWithdrawalV3Error::InvalidMigration(
                "migrated terminal evidence is not bound to the pinned v2 source",
            ));
        }
        let request_id = source.core.request_id.clone();
        let exact_transaction = ExactBytesV3::transaction(source.exact_transaction_bytes)?;
        let prepared = PreparedPhaseV3 {
            prepared_generation: source.source_prepared_generation,
            signer_package: None,
        };
        let record = WithdrawalRecordV3 {
            origin: RecordOriginV3::ValidatedV2 {
                source_record_digest: source.source_record_digest,
            },
            core: source.core,
            phase: WithdrawalPhaseV3::Released(ReleasedPhaseV3 {
                prepared,
                terminal: source.terminal,
                txid: source.txid,
                exact_transaction,
                debit_atoms: source.debit_atoms,
            }),
        };
        if records.insert(request_id, record).is_some() {
            return Err(ExchangeWithdrawalV3Error::DuplicateRequest);
        }
    }

    let journal = ExchangeWithdrawalJournalV3 {
        binding: input.binding,
        journal_key_id: journal_key_id(journal_key),
        journal_instance_id: input.new_journal_instance_id,
        generation: 1,
        prior_commitments: Vec::new(),
        migration: receipt.clone(),
        policy_id: input.policy_id,
        policy_window: input.initial_policy_window,
        active_keyring: input.active_keyring,
        prior_keyrings: Vec::new(),
        records,
        tombstones: BTreeMap::new(),
    };
    journal.validate(journal_key)?;
    let initial_anchor = journal.anchor(journal_key)?;
    let authenticated_snapshot = journal.encode_authenticated(journal_key)?;
    Ok(MigrationOutputV3 {
        journal,
        receipt,
        initial_anchor,
        authenticated_snapshot,
    })
}

/// Digests the exact authenticated v2 snapshot bytes after the v2 decoder has
/// validated them. This digest does not itself authenticate or parse v2.
pub(crate) fn validated_v2_snapshot_digest(authenticated_v2_snapshot: &[u8]) -> [u8; 32] {
    unkeyed_digest(MIGRATION_SOURCE_DOMAIN, authenticated_v2_snapshot)
}

/// Proves that `candidate` is exactly the one-step result of completing the
/// supplied, already durable ReleaseAuthorized state. Storage facades can use
/// this before committing a candidate received from a higher-level engine.
pub(crate) fn validate_authorized_completion(
    current: &ExchangeWithdrawalJournalV3,
    candidate: &ExchangeWithdrawalJournalV3,
    journal_key: &[u8; 32],
    completion: &CompleteReleaseV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    let expected = current.apply_transition(
        journal_key,
        JournalTransitionV3::CompleteRelease(completion.clone()),
    )?;
    if &expected != candidate {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "candidate is not the exact authorized-release completion",
        ));
    }
    Ok(())
}

/// Derives the exact completion transition represented by a candidate. This
/// performs structural extraction only; callers must immediately pass the
/// result to `validate_authorized_completion` with the journal key.
pub(crate) fn derive_authorized_completion(
    current: &ExchangeWithdrawalJournalV3,
    candidate: &ExchangeWithdrawalJournalV3,
    expected_anchor: JournalAnchorV3,
) -> Result<CompleteReleaseV3, ExchangeWithdrawalV3Error> {
    if current.records.len() != candidate.records.len() {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "completion candidate changed the record set",
        ));
    }
    let mut derived = None;
    for (request_id, before) in &current.records {
        let after = candidate.records.get(request_id).ok_or(
            ExchangeWithdrawalV3Error::InvalidTransition(
                "completion candidate removed a withdrawal",
            ),
        )?;
        if before == after {
            continue;
        }
        if derived.is_some() {
            return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                "completion candidate changed multiple withdrawals",
            ));
        }
        let WithdrawalPhaseV3::ReleaseAuthorized(authorized) = &before.phase else {
            return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                "completion source is not ReleaseAuthorized",
            ));
        };
        let WithdrawalPhaseV3::Released(released) = &after.phase else {
            return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                "completion candidate is not Released",
            ));
        };
        let package_digest = authorized
            .prepared
            .signer_package
            .as_ref()
            .ok_or(ExchangeWithdrawalV3Error::InvalidTransition(
                "authorized completion has no signer package",
            ))?
            .exact_package
            .digest;
        derived = Some(CompleteReleaseV3 {
            expected_anchor,
            request_id: request_id.clone(),
            request_digest: before.core.request_digest,
            decision_id: authorized.terminal.decision_id,
            approval_digest: authorized.terminal.approval_digest,
            signer_package_digest: package_digest,
            transaction_signing_digest: before.core.signing_digest,
            txid: released.txid,
            exact_transaction_bytes: released.exact_transaction.bytes.clone(),
        });
    }
    derived.ok_or(ExchangeWithdrawalV3Error::InvalidTransition(
        "completion candidate did not change a withdrawal",
    ))
}

fn apply_add_intent(
    state: &mut ExchangeWithdrawalJournalV3,
    journal_key: &[u8; 32],
    value: AddIntentV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    if state.records.len() >= MAX_V3_WITHDRAWAL_RECORDS {
        return Err(ExchangeWithdrawalV3Error::Capacity("withdrawal records"));
    }
    validate_core(&value.core)?;
    if state.records.contains_key(&value.core.request_id)
        || state
            .records
            .values()
            .any(|record| record.core.request_digest == value.core.request_digest)
    {
        return Err(ExchangeWithdrawalV3Error::DuplicateRequest);
    }
    let tag = request_id_tag(journal_key, &value.core.request_id)?;
    if state.tombstones.contains_key(&tag)
        || state
            .tombstones
            .values()
            .any(|tombstone| tombstone.request_digest == value.core.request_digest)
    {
        return Err(ExchangeWithdrawalV3Error::ReusedArchivedRequest);
    }
    state.records.insert(
        value.core.request_id.clone(),
        WithdrawalRecordV3 {
            origin: RecordOriginV3::NativeV3,
            core: value.core,
            phase: WithdrawalPhaseV3::Intent,
        },
    );
    Ok(())
}

fn apply_prepare(
    state: &mut ExchangeWithdrawalJournalV3,
    value: PrepareWithdrawalV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    let prepared_generation = state.generation;
    let record = exact_record_mut(state, &value.request_id, value.request_digest)?;
    if !matches!(record.origin, RecordOriginV3::NativeV3)
        || !matches!(record.phase, WithdrawalPhaseV3::Intent)
    {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "only a native Intent can become Prepared",
        ));
    }
    record.phase = WithdrawalPhaseV3::Prepared(PreparedPhaseV3 {
        prepared_generation,
        signer_package: None,
    });
    Ok(())
}

fn apply_attach_package(
    state: &mut ExchangeWithdrawalJournalV3,
    journal_key: &[u8; 32],
    value: AttachSignerPackageV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    value
        .signer_package
        .exact_package
        .validate(MAX_V3_SIGNER_PACKAGE_BYTES, SIGNER_PACKAGE_DOMAIN)?;
    if value.signer_package.keyring_anchor != state.active_keyring {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "signer package is not bound to the active keyring",
        ));
    }
    let prepared_generation = {
        let record = exact_record(state, &value.request_id, value.request_digest)?;
        match &record.phase {
            WithdrawalPhaseV3::Prepared(prepared) if prepared.signer_package.is_none() => {
                if value.signer_package.transaction_signing_digest != record.core.signing_digest {
                    return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                        "signer package signing digest changed",
                    ));
                }
                prepared.prepared_generation
            }
            _ => {
                return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                    "signer package can be attached exactly once to Prepared",
                ));
            }
        }
    };
    let prepared_anchor = state.anchor_at(journal_key, prepared_generation)?;
    if value.signer_package.prepared_anchor != prepared_anchor {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "signer package is not bound to the exact Prepared anchor",
        ));
    }
    let record = exact_record_mut(state, &value.request_id, value.request_digest)?;
    match &mut record.phase {
        WithdrawalPhaseV3::Prepared(prepared) => {
            prepared.signer_package = Some(value.signer_package);
            Ok(())
        }
        _ => Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "withdrawal is not Prepared",
        )),
    }
}

fn apply_authorize_release(
    state: &mut ExchangeWithdrawalJournalV3,
    value: AuthorizeReleaseV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    let prepared = {
        let record = exact_record(state, &value.request_id, value.request_digest)?;
        validate_native_terminal(
            state,
            record,
            &value.terminal,
            WithdrawalActionV3::Release,
            value.expected_anchor,
        )?;
        match &record.phase {
            WithdrawalPhaseV3::Prepared(prepared) if prepared.signer_package.is_some() => {
                prepared.clone()
            }
            _ => {
                return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                    "release authorization requires Prepared with an exact signer package",
                ));
            }
        }
    };
    let debit_atoms = {
        let record = exact_record(state, &value.request_id, value.request_digest)?;
        record
            .core
            .amount_atoms
            .checked_add(record.core.fee_atoms)
            .ok_or(ExchangeWithdrawalV3Error::ArithmeticOverflow)?
    };
    advance_policy_window(
        &mut state.policy_window,
        value.request_digest,
        value.terminal.accounted_at_unix_seconds,
        debit_atoms,
    )?;
    let record = exact_record_mut(state, &value.request_id, value.request_digest)?;
    record.phase = WithdrawalPhaseV3::ReleaseAuthorized(ReleaseAuthorizedPhaseV3 {
        prepared,
        terminal: value.terminal,
        debit_atoms,
    });
    Ok(())
}

fn apply_complete_release(
    state: &mut ExchangeWithdrawalJournalV3,
    value: CompleteReleaseV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    let exact_transaction = ExactBytesV3::transaction(value.exact_transaction_bytes)?;
    if is_zero(&value.txid) {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "released transaction identifier is zero",
        ));
    }
    let authorized = {
        let record = exact_record(state, &value.request_id, value.request_digest)?;
        let WithdrawalPhaseV3::ReleaseAuthorized(authorized) = &record.phase else {
            return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                "completion requires an exact ReleaseAuthorized record",
            ));
        };
        let package = authorized.prepared.signer_package.as_ref().ok_or(
            ExchangeWithdrawalV3Error::InvalidTransition(
                "authorized release has no signer package",
            ),
        )?;
        if value.decision_id != authorized.terminal.decision_id
            || value.approval_digest != authorized.terminal.approval_digest
            || value.signer_package_digest != package.exact_package.digest
            || value.transaction_signing_digest != record.core.signing_digest
            || package.transaction_signing_digest != value.transaction_signing_digest
        {
            return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                "completion does not match frozen authorization evidence",
            ));
        }
        authorized.clone()
    };
    let record = exact_record_mut(state, &value.request_id, value.request_digest)?;
    record.phase = WithdrawalPhaseV3::Released(ReleasedPhaseV3 {
        prepared: authorized.prepared,
        terminal: authorized.terminal,
        txid: value.txid,
        exact_transaction,
        debit_atoms: authorized.debit_atoms,
    });
    Ok(())
}

fn apply_cancel(
    state: &mut ExchangeWithdrawalJournalV3,
    value: CancelWithdrawalV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    let prepared = {
        let record = exact_record(state, &value.request_id, value.request_digest)?;
        validate_native_terminal(
            state,
            record,
            &value.terminal,
            WithdrawalActionV3::Cancel,
            value.expected_anchor,
        )?;
        match &record.phase {
            WithdrawalPhaseV3::Intent => None,
            WithdrawalPhaseV3::Prepared(prepared) => Some(prepared.clone()),
            _ => {
                return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                    "only Intent or Prepared can be canceled",
                ));
            }
        }
    };
    advance_policy_time_watermark(
        &mut state.policy_window,
        value.terminal.accounted_at_unix_seconds,
    )?;
    let record = exact_record_mut(state, &value.request_id, value.request_digest)?;
    record.phase = WithdrawalPhaseV3::Canceled(CanceledPhaseV3 {
        prepared,
        terminal: value.terminal,
    });
    Ok(())
}

fn apply_rotate_keyring(
    state: &mut ExchangeWithdrawalJournalV3,
    value: RotateKeyringV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    validate_keyring_anchor(value.new_keyring)?;
    if is_zero(&value.rotation_decision_id)
        || is_zero(&value.approval_digest)
        || value.new_keyring == state.active_keyring
    {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "keyring rotation evidence is invalid",
        ));
    }
    if state
        .records
        .values()
        .any(|record| !record.phase.is_terminal())
    {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "keyring rotation requires no pending withdrawals",
        ));
    }
    if value.new_keyring.instance_id == state.active_keyring.instance_id
        && value.new_keyring.generation <= state.active_keyring.generation
    {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "keyring generation must advance within an instance",
        ));
    }
    state.prior_keyrings.push(KeyringHistoryEntryV3 {
        anchor: state.active_keyring,
        rotation_decision_id: value.rotation_decision_id,
        approval_digest: value.approval_digest,
    });
    state.active_keyring = value.new_keyring;
    Ok(())
}

fn apply_compaction(
    state: &mut ExchangeWithdrawalJournalV3,
    journal_key: &[u8; 32],
    value: CompactTerminalRecordsV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    if value.archive_source_anchor != value.expected_anchor
        || is_zero(&value.archive_id)
        || value.records.is_empty()
    {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "archive source, identifier, or record set is invalid",
        ));
    }
    if value.records.len() > MAX_V3_WITHDRAWAL_RECORDS
        || state
            .tombstones
            .len()
            .checked_add(value.records.len())
            .is_none_or(|count| count > MAX_V3_TOMBSTONES)
    {
        return Err(ExchangeWithdrawalV3Error::Capacity("archive tombstones"));
    }
    let mut expected_index = 0_u64;
    let mut previous_tag = None;
    let mut pending = Vec::with_capacity(value.records.len());
    for item in &value.records {
        if item.record_index != expected_index {
            return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                "archive record indices are not contiguous",
            ));
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(ExchangeWithdrawalV3Error::ArithmeticOverflow)?;
        let record = exact_record(state, &item.request_id, item.request_digest)?;
        if !matches!(&record.phase, WithdrawalPhaseV3::Canceled(_)) {
            return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                "only canceled records can be compacted",
            ));
        }
        let tag = request_id_tag(journal_key, &item.request_id)?;
        if previous_tag.is_some_and(|previous| previous >= tag) {
            return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                "archive records are not strictly request-tag ordered",
            ));
        }
        previous_tag = Some(tag);
        if state.tombstones.contains_key(&tag) {
            return Err(ExchangeWithdrawalV3Error::ReusedArchivedRequest);
        }
        let canonical_record = encode_record(record)?;
        let payload_digest = keyed_digest(journal_key, ARCHIVE_PAYLOAD_DOMAIN, &canonical_record);
        if payload_digest != item.record_payload_digest {
            return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                "archive payload digest does not match the live terminal record",
            ));
        }
        let parts = terminal_parts(record)?;
        pending.push((
            tag,
            ArchiveTombstoneV3 {
                request_id_tag: tag,
                request_digest: record.core.request_digest,
                phase: parts.phase,
                terminal_decision_id: parts.terminal.decision_id,
                approval_digest: parts.terminal.approval_digest,
                archive_id: value.archive_id,
                record_index: item.record_index,
                txid: parts.txid,
                debit_atoms: parts.debit_atoms,
                record_payload_digest: payload_digest,
            },
            item.request_id.clone(),
        ));
    }
    for (tag, tombstone, request_id) in pending {
        if state.records.remove(&request_id).is_none()
            || state.tombstones.insert(tag, tombstone).is_some()
        {
            return Err(ExchangeWithdrawalV3Error::InvalidTransition(
                "archive pruning set changed during transition",
            ));
        }
    }
    Ok(())
}

fn exact_record<'a>(
    state: &'a ExchangeWithdrawalJournalV3,
    request_id: &str,
    request_digest: [u8; 32],
) -> Result<&'a WithdrawalRecordV3, ExchangeWithdrawalV3Error> {
    let record = state
        .records
        .get(request_id)
        .ok_or(ExchangeWithdrawalV3Error::UnknownRequest)?;
    if record.core.request_digest != request_digest {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "request digest does not match request identifier",
        ));
    }
    Ok(record)
}

fn exact_record_mut<'a>(
    state: &'a mut ExchangeWithdrawalJournalV3,
    request_id: &str,
    request_digest: [u8; 32],
) -> Result<&'a mut WithdrawalRecordV3, ExchangeWithdrawalV3Error> {
    let record = state
        .records
        .get_mut(request_id)
        .ok_or(ExchangeWithdrawalV3Error::UnknownRequest)?;
    if record.core.request_digest != request_digest {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "request digest does not match request identifier",
        ));
    }
    Ok(record)
}

fn validate_native_terminal(
    state: &ExchangeWithdrawalJournalV3,
    record: &WithdrawalRecordV3,
    terminal: &TerminalDecisionV3,
    expected_action: WithdrawalActionV3,
    expected_anchor: JournalAnchorV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    if !matches!(record.origin, RecordOriginV3::NativeV3)
        || terminal.scope != DecisionScopeV3::NativeV3
        || terminal.action != expected_action
        || terminal.policy_id != state.policy_id
        || terminal.action_anchor != expected_anchor
        || terminal.request_digest != record.core.request_digest
        || terminal.transaction_signing_digest != record.core.signing_digest
        || is_zero(&terminal.decision_id)
        || is_zero(&terminal.approval_digest)
    {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "terminal action evidence does not match journal state",
        ));
    }
    if state.records.values().any(|other| {
        record_terminal(other).is_some_and(|existing| {
            existing.decision_id == terminal.decision_id
                || existing.approval_digest == terminal.approval_digest
        })
    }) || state.tombstones.values().any(|existing| {
        existing.terminal_decision_id == terminal.decision_id
            || existing.approval_digest == terminal.approval_digest
    }) {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "terminal decision or approval was already consumed",
        ));
    }
    Ok(())
}

fn advance_policy_window(
    state: &mut PolicyWindowStateV3,
    request_digest: [u8; 32],
    evaluated_at_unix_seconds: u64,
    debit_atoms: u64,
) -> Result<(), ExchangeWithdrawalV3Error> {
    if evaluated_at_unix_seconds < state.time_watermark_unix_seconds {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "policy clock moved behind its durable watermark",
        ));
    }
    if debit_atoms == 0
        || state
            .release_events
            .iter()
            .any(|event| event.request_digest == request_digest)
    {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "policy release event is zero or duplicated",
        ));
    }
    state.release_events.retain(|event| {
        evaluated_at_unix_seconds.saturating_sub(event.released_at_unix_seconds)
            < POLICY_WINDOW_SECONDS
    });
    if state.release_events.len() >= MAX_V3_POLICY_EVENTS {
        return Err(ExchangeWithdrawalV3Error::Capacity("policy release events"));
    }
    state.release_events.push(PolicyReleaseEventV3 {
        request_digest,
        released_at_unix_seconds: evaluated_at_unix_seconds,
        debit_atoms,
    });
    state.time_watermark_unix_seconds = evaluated_at_unix_seconds;
    Ok(())
}

fn advance_policy_time_watermark(
    state: &mut PolicyWindowStateV3,
    evaluated_at_unix_seconds: u64,
) -> Result<(), ExchangeWithdrawalV3Error> {
    if evaluated_at_unix_seconds < state.time_watermark_unix_seconds {
        return Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "policy clock moved behind its durable watermark",
        ));
    }
    state.release_events.retain(|event| {
        evaluated_at_unix_seconds.saturating_sub(event.released_at_unix_seconds)
            < POLICY_WINDOW_SECONDS
    });
    state.time_watermark_unix_seconds = evaluated_at_unix_seconds;
    Ok(())
}

struct TerminalParts<'a> {
    phase: TerminalPhaseV3,
    terminal: &'a TerminalDecisionV3,
    txid: Option<[u8; 32]>,
    debit_atoms: u64,
}

fn terminal_parts(
    record: &WithdrawalRecordV3,
) -> Result<TerminalParts<'_>, ExchangeWithdrawalV3Error> {
    match &record.phase {
        WithdrawalPhaseV3::Released(released) => Ok(TerminalParts {
            phase: TerminalPhaseV3::Released,
            terminal: &released.terminal,
            txid: Some(released.txid),
            debit_atoms: released.debit_atoms,
        }),
        WithdrawalPhaseV3::Canceled(canceled) => Ok(TerminalParts {
            phase: TerminalPhaseV3::Canceled,
            terminal: &canceled.terminal,
            txid: None,
            debit_atoms: 0,
        }),
        _ => Err(ExchangeWithdrawalV3Error::InvalidTransition(
            "withdrawal is not terminal",
        )),
    }
}

fn record_terminal(record: &WithdrawalRecordV3) -> Option<&TerminalDecisionV3> {
    match &record.phase {
        WithdrawalPhaseV3::ReleaseAuthorized(authorized) => Some(&authorized.terminal),
        WithdrawalPhaseV3::Released(released) => Some(&released.terminal),
        WithdrawalPhaseV3::Canceled(canceled) => Some(&canceled.terminal),
        _ => None,
    }
}

fn validate_records_and_tombstones(
    state: &ExchangeWithdrawalJournalV3,
    journal_key: &[u8; 32],
) -> Result<(), ExchangeWithdrawalV3Error> {
    if state.records.len() > MAX_V3_WITHDRAWAL_RECORDS {
        return Err(ExchangeWithdrawalV3Error::Capacity("withdrawal records"));
    }
    if state.tombstones.len() > MAX_V3_TOMBSTONES {
        return Err(ExchangeWithdrawalV3Error::Capacity("archive tombstones"));
    }
    let mut request_digests = HashSet::new();
    let mut outpoints = BTreeSet::new();
    let mut decision_ids = HashSet::new();
    let mut approval_digests = HashSet::new();
    let mut txids = HashSet::new();
    for (request_id, record) in &state.records {
        if request_id != &record.core.request_id {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "record map key differs from request identifier",
            ));
        }
        if !request_digests.insert(record.core.request_digest) {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "duplicate request digest",
            ));
        }
        validate_record(state, journal_key, record)?;
        // Cancellation is the authenticated release of an input reservation.
        // All spending-capable phases, including Released for exact replay,
        // continue to participate in global outpoint uniqueness.
        if !matches!(&record.phase, WithdrawalPhaseV3::Canceled(_)) {
            for input in &record.core.reservations {
                if !outpoints.insert(input.outpoint) {
                    return Err(ExchangeWithdrawalV3Error::InvalidState(
                        "reserved input is duplicated",
                    ));
                }
            }
        }
        if let Some(terminal) = record_terminal(record)
            && (!decision_ids.insert(terminal.decision_id)
                || !approval_digests.insert(terminal.approval_digest))
        {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "terminal decision or approval is duplicated",
            ));
        }
        if let WithdrawalPhaseV3::Released(released) = &record.phase
            && !txids.insert(released.txid)
        {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "released transaction identifier is duplicated",
            ));
        }
        let release = match &record.phase {
            WithdrawalPhaseV3::ReleaseAuthorized(authorized) => {
                Some((&authorized.terminal, authorized.debit_atoms))
            }
            WithdrawalPhaseV3::Released(released) => {
                Some((&released.terminal, released.debit_atoms))
            }
            _ => None,
        };
        if let Some((terminal, debit_atoms)) = release {
            let event_is_active = state
                .policy_window
                .time_watermark_unix_seconds
                .saturating_sub(terminal.accounted_at_unix_seconds)
                < POLICY_WINDOW_SECONDS;
            let has_exact_event = state.policy_window.release_events.iter().any(|event| {
                event.request_digest == record.core.request_digest
                    && event.released_at_unix_seconds == terminal.accounted_at_unix_seconds
                    && event.debit_atoms == debit_atoms
            });
            if event_is_active != has_exact_event {
                return Err(ExchangeWithdrawalV3Error::InvalidState(
                    "active release terminal and policy event differ",
                ));
            }
        }
    }
    for (tag, tombstone) in &state.tombstones {
        if tag != &tombstone.request_id_tag
            || is_zero(tag)
            || is_zero(&tombstone.request_digest)
            || is_zero(&tombstone.terminal_decision_id)
            || is_zero(&tombstone.approval_digest)
            || is_zero(&tombstone.archive_id)
            || is_zero(&tombstone.record_payload_digest)
            || tombstone.phase != TerminalPhaseV3::Canceled
            || tombstone.txid.is_some()
            || tombstone.debit_atoms != 0
            || !request_digests.insert(tombstone.request_digest)
            || !decision_ids.insert(tombstone.terminal_decision_id)
            || !approval_digests.insert(tombstone.approval_digest)
            || tombstone.txid.is_some_and(|txid| !txids.insert(txid))
        {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "archive tombstone is invalid or duplicated",
            ));
        }
    }
    for event in &state.policy_window.release_events {
        let live_match = state.records.values().any(|record| {
            record.core.request_digest == event.request_digest
                && match &record.phase {
                    WithdrawalPhaseV3::ReleaseAuthorized(authorized) => {
                        authorized.debit_atoms == event.debit_atoms
                            && authorized.terminal.accounted_at_unix_seconds
                                == event.released_at_unix_seconds
                    }
                    WithdrawalPhaseV3::Released(released) => {
                        released.debit_atoms == event.debit_atoms
                            && released.terminal.accounted_at_unix_seconds
                                == event.released_at_unix_seconds
                    }
                    _ => false,
                }
        });
        let tombstone_match = state.tombstones.values().any(|tombstone| {
            tombstone.request_digest == event.request_digest
                && tombstone.phase == TerminalPhaseV3::Released
                && tombstone.debit_atoms == event.debit_atoms
        });
        if !live_match && !tombstone_match {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "policy event has no released record or tombstone",
            ));
        }
    }
    Ok(())
}

fn validate_record(
    state: &ExchangeWithdrawalJournalV3,
    _journal_key: &[u8; 32],
    record: &WithdrawalRecordV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    validate_core(&record.core)?;
    match (&record.origin, &record.phase) {
        (RecordOriginV3::NativeV3, WithdrawalPhaseV3::Intent) => {}
        (RecordOriginV3::NativeV3, WithdrawalPhaseV3::Prepared(prepared)) => {
            validate_native_prepared(state, record, prepared)?;
        }
        (RecordOriginV3::NativeV3, WithdrawalPhaseV3::ReleaseAuthorized(authorized)) => {
            validate_native_authorization(state, record, authorized)?;
        }
        (RecordOriginV3::NativeV3, WithdrawalPhaseV3::Released(released)) => {
            validate_native_prepared(state, record, &released.prepared)?;
            if released.prepared.signer_package.is_none() {
                return Err(ExchangeWithdrawalV3Error::InvalidState(
                    "native Released record has no exact signer package",
                ));
            }
            validate_released(state, record, released)?;
        }
        (RecordOriginV3::NativeV3, WithdrawalPhaseV3::Canceled(canceled)) => {
            if let Some(prepared) = &canceled.prepared {
                validate_native_prepared(state, record, prepared)?;
            }
            validate_terminal(
                state,
                record,
                &canceled.terminal,
                WithdrawalActionV3::Cancel,
            )?;
        }
        (
            RecordOriginV3::ValidatedV2 {
                source_record_digest,
            },
            WithdrawalPhaseV3::Released(released),
        ) => {
            if is_zero(source_record_digest)
                || released.prepared.signer_package.is_some()
                || released.prepared.prepared_generation == 0
                || released.prepared.prepared_generation > state.migration.source_anchor.generation
                || released.terminal.scope != DecisionScopeV3::ValidatedV2Migration
                || released.terminal.action_anchor != state.migration.source_anchor
            {
                return Err(ExchangeWithdrawalV3Error::InvalidState(
                    "validated-v2 Released record evidence is invalid",
                ));
            }
            validate_released(state, record, released)?;
        }
        _ => {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "record origin cannot have this phase",
            ));
        }
    }
    Ok(())
}

fn validate_core(core: &WithdrawalCoreV3) -> Result<(), ExchangeWithdrawalV3Error> {
    validate_request_id(&core.request_id)?;
    if is_zero(&core.request_digest)
        || is_zero(&core.destination)
        || core.amount_atoms == 0
        || is_zero(&core.signing_digest)
        || core.reservations.is_empty()
        || core.reservations.len() > MAX_V3_RESERVED_INPUTS
    {
        return Err(ExchangeWithdrawalV3Error::InvalidState(
            "withdrawal request or plan is invalid",
        ));
    }
    let expected = core
        .amount_atoms
        .checked_add(core.fee_atoms)
        .and_then(|value| value.checked_add(core.change_atoms))
        .ok_or(ExchangeWithdrawalV3Error::ArithmeticOverflow)?;
    let mut total = 0_u64;
    let mut previous = None;
    for input in &core.reservations {
        if is_zero(&input.outpoint.txid)
            || input.value_atoms == 0
            || is_zero(&input.wallet_key_id)
            || is_zero(&input.public_key)
            || is_zero(&input.signer_id)
            || previous.is_some_and(|prior| prior >= input.outpoint)
        {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "withdrawal reservations are invalid or not strictly ordered",
            ));
        }
        previous = Some(input.outpoint);
        total = total
            .checked_add(input.value_atoms)
            .ok_or(ExchangeWithdrawalV3Error::ArithmeticOverflow)?;
    }
    if total != expected {
        return Err(ExchangeWithdrawalV3Error::InvalidState(
            "reserved value does not equal amount, fee, and change",
        ));
    }
    Ok(())
}

fn validate_native_prepared(
    state: &ExchangeWithdrawalJournalV3,
    record: &WithdrawalRecordV3,
    prepared: &PreparedPhaseV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    if prepared.prepared_generation == 0 || prepared.prepared_generation > state.generation {
        return Err(ExchangeWithdrawalV3Error::InvalidState(
            "Prepared generation is outside journal history",
        ));
    }
    if let Some(package) = &prepared.signer_package {
        package
            .exact_package
            .validate(MAX_V3_SIGNER_PACKAGE_BYTES, SIGNER_PACKAGE_DOMAIN)?;
        if package.transaction_signing_digest != record.core.signing_digest
            || !state_has_anchor(state, package.prepared_anchor)
            || package.prepared_anchor.generation != prepared.prepared_generation
            || !state_has_keyring(state, package.keyring_anchor)
        {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "signer package evidence is not bound to journal history",
            ));
        }
    }
    Ok(())
}

fn validate_released(
    state: &ExchangeWithdrawalJournalV3,
    record: &WithdrawalRecordV3,
    released: &ReleasedPhaseV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    released
        .exact_transaction
        .validate(MAX_V3_TRANSACTION_BYTES, TRANSACTION_DOMAIN)?;
    let expected_debit = record
        .core
        .amount_atoms
        .checked_add(record.core.fee_atoms)
        .ok_or(ExchangeWithdrawalV3Error::ArithmeticOverflow)?;
    if is_zero(&released.txid) || released.debit_atoms != expected_debit {
        return Err(ExchangeWithdrawalV3Error::InvalidState(
            "released transaction or debit is invalid",
        ));
    }
    validate_terminal(
        state,
        record,
        &released.terminal,
        WithdrawalActionV3::Release,
    )
}

fn validate_native_authorization(
    state: &ExchangeWithdrawalJournalV3,
    record: &WithdrawalRecordV3,
    authorized: &ReleaseAuthorizedPhaseV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    validate_native_prepared(state, record, &authorized.prepared)?;
    let expected_debit = record
        .core
        .amount_atoms
        .checked_add(record.core.fee_atoms)
        .ok_or(ExchangeWithdrawalV3Error::ArithmeticOverflow)?;
    if authorized.prepared.signer_package.is_none() || authorized.debit_atoms != expected_debit {
        return Err(ExchangeWithdrawalV3Error::InvalidState(
            "release authorization package or debit is invalid",
        ));
    }
    validate_terminal(
        state,
        record,
        &authorized.terminal,
        WithdrawalActionV3::Release,
    )
}

fn validate_terminal(
    state: &ExchangeWithdrawalJournalV3,
    record: &WithdrawalRecordV3,
    terminal: &TerminalDecisionV3,
    action: WithdrawalActionV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    if terminal.action != action
        || is_zero(&terminal.decision_id)
        || is_zero(&terminal.approval_digest)
        || terminal.policy_id != state.policy_id
        || terminal.request_digest != record.core.request_digest
        || terminal.transaction_signing_digest != record.core.signing_digest
        || terminal.accounted_at_unix_seconds < terminal.decided_at_unix_seconds
        || terminal.accounted_at_unix_seconds > state.policy_window.time_watermark_unix_seconds
    {
        return Err(ExchangeWithdrawalV3Error::InvalidState(
            "terminal decision fields do not match the withdrawal",
        ));
    }
    match terminal.scope {
        DecisionScopeV3::NativeV3 => {
            if terminal
                .accounted_at_unix_seconds
                .saturating_sub(terminal.decided_at_unix_seconds)
                >= MAX_APPROVAL_VALIDITY_SECONDS
                || !state_has_anchor(state, terminal.action_anchor)
                || terminal.action_anchor.generation >= state.generation
            {
                return Err(ExchangeWithdrawalV3Error::InvalidState(
                    "native terminal decision is not bound to a prior v3 anchor",
                ));
            }
        }
        DecisionScopeV3::ValidatedV2Migration => {
            if terminal.action_anchor != state.migration.source_anchor
                || !matches!(record.origin, RecordOriginV3::ValidatedV2 { .. })
            {
                return Err(ExchangeWithdrawalV3Error::InvalidState(
                    "migration terminal decision is not bound to the v2 receipt",
                ));
            }
        }
    }
    Ok(())
}

fn validate_policy_window(state: &PolicyWindowStateV3) -> Result<(), ExchangeWithdrawalV3Error> {
    if state.release_events.len() > MAX_V3_POLICY_EVENTS {
        return Err(ExchangeWithdrawalV3Error::Capacity("policy release events"));
    }
    let mut previous_time = None;
    let mut digests = HashSet::new();
    for event in &state.release_events {
        if is_zero(&event.request_digest)
            || event.debit_atoms == 0
            || event.released_at_unix_seconds > state.time_watermark_unix_seconds
            || previous_time.is_some_and(|previous| previous > event.released_at_unix_seconds)
            || !digests.insert(event.request_digest)
        {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "policy window is invalid or non-canonical",
            ));
        }
        if state
            .time_watermark_unix_seconds
            .saturating_sub(event.released_at_unix_seconds)
            >= POLICY_WINDOW_SECONDS
        {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "policy window contains an expired release event",
            ));
        }
        previous_time = Some(event.released_at_unix_seconds);
    }
    Ok(())
}

fn validate_keyring_history(
    state: &ExchangeWithdrawalJournalV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    if state.prior_keyrings.len() > MAX_V3_WITHDRAWAL_RECORDS {
        return Err(ExchangeWithdrawalV3Error::Capacity("keyring history"));
    }
    let mut anchors = BTreeSet::new();
    let mut decisions = HashSet::new();
    let mut approvals = HashSet::new();
    for entry in &state.prior_keyrings {
        validate_keyring_anchor(entry.anchor)?;
        if is_zero(&entry.rotation_decision_id)
            || is_zero(&entry.approval_digest)
            || !anchors.insert(entry.anchor)
            || !decisions.insert(entry.rotation_decision_id)
            || !approvals.insert(entry.approval_digest)
        {
            return Err(ExchangeWithdrawalV3Error::InvalidState(
                "keyring history is invalid or duplicated",
            ));
        }
    }
    if anchors.contains(&state.active_keyring) {
        return Err(ExchangeWithdrawalV3Error::InvalidState(
            "active keyring also appears in keyring history",
        ));
    }
    Ok(())
}

fn validate_migration_receipt(
    receipt: &MigrationReceiptV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    if is_zero(&receipt.migration_id)
        || is_zero(&receipt.source_snapshot_digest)
        || is_zero(&receipt.migration_decision_id)
        || is_zero(&receipt.migration_approval_digest)
        || is_zero(&receipt.migration_input_digest)
    {
        return Err(ExchangeWithdrawalV3Error::InvalidState(
            "migration receipt is incomplete",
        ));
    }
    validate_foreign_anchor(receipt.source_anchor)
}

fn validate_binding(binding: JournalBindingV3) -> Result<(), ExchangeWithdrawalV3Error> {
    if is_zero(&binding.network_id)
        || is_zero(&binding.consensus_fingerprint)
        || is_zero(&binding.genesis)
    {
        return Err(ExchangeWithdrawalV3Error::InvalidBinding);
    }
    Ok(())
}

fn validate_keyring_anchor(anchor: KeyringAnchorV3) -> Result<(), ExchangeWithdrawalV3Error> {
    if is_zero(&anchor.instance_id) || anchor.generation == 0 || is_zero(&anchor.commitment) {
        return Err(ExchangeWithdrawalV3Error::InvalidState(
            "keyring anchor is invalid",
        ));
    }
    Ok(())
}

fn validate_foreign_anchor(anchor: JournalAnchorV3) -> Result<(), ExchangeWithdrawalV3Error> {
    if is_zero(&anchor.key_id)
        || is_zero(&anchor.journal_instance_id)
        || anchor.generation == 0
        || is_zero(&anchor.commitment)
    {
        return Err(ExchangeWithdrawalV3Error::InvalidState(
            "journal anchor is invalid",
        ));
    }
    Ok(())
}

fn state_has_anchor(state: &ExchangeWithdrawalJournalV3, anchor: JournalAnchorV3) -> bool {
    if anchor.key_id != state.journal_key_id
        || anchor.journal_instance_id != state.journal_instance_id
        || anchor.generation == 0
        || anchor.generation >= state.generation
    {
        return false;
    }
    usize::try_from(anchor.generation - 1)
        .ok()
        .and_then(|index| state.prior_commitments.get(index))
        .is_some_and(|commitment| commitment == &anchor.commitment)
}

fn state_has_keyring(state: &ExchangeWithdrawalJournalV3, anchor: KeyringAnchorV3) -> bool {
    state.active_keyring == anchor
        || state
            .prior_keyrings
            .iter()
            .any(|entry| entry.anchor == anchor)
}

fn validate_request_id(request_id: &str) -> Result<(), ExchangeWithdrawalV3Error> {
    if request_id.is_empty()
        || request_id.len() > MAX_V3_REQUEST_ID_BYTES
        || !request_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ExchangeWithdrawalV3Error::InvalidState(
            "request identifier is invalid",
        ));
    }
    Ok(())
}

fn validate_key(key: &[u8; 32]) -> Result<(), ExchangeWithdrawalV3Error> {
    if is_zero(key) {
        return Err(ExchangeWithdrawalV3Error::InvalidJournalKey);
    }
    Ok(())
}

fn journal_key_id(key: &[u8; 32]) -> [u8; 32] {
    keyed_digest(key, KEY_ID_DOMAIN, b"journal-key-id")
}

fn request_id_tag(key: &[u8; 32], request_id: &str) -> Result<[u8; 32], ExchangeWithdrawalV3Error> {
    validate_request_id(request_id)?;
    Ok(keyed_digest(key, REQUEST_TAG_DOMAIN, request_id.as_bytes()))
}

fn is_zero<const N: usize>(value: &[u8; N]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn compute_current_commitment(
    state: &ExchangeWithdrawalJournalV3,
    journal_key: &[u8; 32],
) -> Result<[u8; 32], ExchangeWithdrawalV3Error> {
    let content = encode_commitment_content(state)?;
    let content_digest = keyed_digest(journal_key, CONTENT_DOMAIN, &content);
    let previous = state.prior_commitments.last().copied().unwrap_or([0; 32]);
    let mut frame = Vec::with_capacity(72);
    frame.extend_from_slice(&previous);
    frame.extend_from_slice(&state.generation.to_le_bytes());
    frame.extend_from_slice(&content_digest);
    Ok(keyed_digest(journal_key, COMMITMENT_DOMAIN, &frame))
}

fn encode_state_payload(
    state: &ExchangeWithdrawalJournalV3,
) -> Result<Vec<u8>, ExchangeWithdrawalV3Error> {
    let mut bytes = Vec::new();
    write_state_prefix(&mut bytes, state);
    write_count(
        &mut bytes,
        state.prior_commitments.len(),
        "journal commitment history",
    )?;
    for commitment in &state.prior_commitments {
        bytes.extend_from_slice(commitment);
    }
    write_state_body(&mut bytes, state)?;
    Ok(bytes)
}

fn encode_commitment_content(
    state: &ExchangeWithdrawalJournalV3,
) -> Result<Vec<u8>, ExchangeWithdrawalV3Error> {
    let mut bytes = Vec::new();
    write_state_prefix(&mut bytes, state);
    // The chain authenticates its immediate predecessor; embedding the entire
    // history here would make the commitment depend twice on the same data.
    write_state_body(&mut bytes, state)?;
    Ok(bytes)
}

fn write_state_prefix(bytes: &mut Vec<u8>, state: &ExchangeWithdrawalJournalV3) {
    write_binding(bytes, state.binding);
    bytes.extend_from_slice(&state.journal_key_id);
    bytes.extend_from_slice(&state.journal_instance_id);
    bytes.extend_from_slice(&state.generation.to_le_bytes());
}

fn write_state_body(
    bytes: &mut Vec<u8>,
    state: &ExchangeWithdrawalJournalV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    write_migration_receipt(bytes, &state.migration);
    bytes.extend_from_slice(&state.policy_id);
    write_policy_window(bytes, &state.policy_window)?;
    write_keyring_anchor(bytes, state.active_keyring);
    write_count(bytes, state.prior_keyrings.len(), "keyring history")?;
    for entry in &state.prior_keyrings {
        write_keyring_anchor(bytes, entry.anchor);
        bytes.extend_from_slice(&entry.rotation_decision_id);
        bytes.extend_from_slice(&entry.approval_digest);
    }
    write_count(bytes, state.records.len(), "withdrawal records")?;
    for (request_id, record) in &state.records {
        write_string(bytes, request_id, MAX_V3_REQUEST_ID_BYTES, "request_id")?;
        let record_bytes = encode_record(record)?;
        write_blob(bytes, &record_bytes, MAX_V3_SNAPSHOT_BYTES, "record")?;
    }
    write_count(bytes, state.tombstones.len(), "archive tombstones")?;
    for (tag, tombstone) in &state.tombstones {
        bytes.extend_from_slice(tag);
        write_tombstone(bytes, tombstone);
    }
    Ok(())
}

fn encode_record(record: &WithdrawalRecordV3) -> Result<Vec<u8>, ExchangeWithdrawalV3Error> {
    let mut bytes = Vec::new();
    match record.origin {
        RecordOriginV3::NativeV3 => bytes.push(1),
        RecordOriginV3::ValidatedV2 {
            source_record_digest,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&source_record_digest);
        }
    }
    write_core(&mut bytes, &record.core)?;
    match &record.phase {
        WithdrawalPhaseV3::Intent => bytes.push(1),
        WithdrawalPhaseV3::Prepared(prepared) => {
            bytes.push(2);
            write_prepared(&mut bytes, prepared)?;
        }
        WithdrawalPhaseV3::ReleaseAuthorized(authorized) => {
            bytes.push(3);
            write_prepared(&mut bytes, &authorized.prepared)?;
            write_terminal(&mut bytes, authorized.terminal);
            bytes.extend_from_slice(&authorized.debit_atoms.to_le_bytes());
        }
        WithdrawalPhaseV3::Released(released) => {
            bytes.push(4);
            write_prepared(&mut bytes, &released.prepared)?;
            write_terminal(&mut bytes, released.terminal);
            bytes.extend_from_slice(&released.txid);
            write_exact(
                &mut bytes,
                &released.exact_transaction,
                MAX_V3_TRANSACTION_BYTES,
            )?;
            bytes.extend_from_slice(&released.debit_atoms.to_le_bytes());
        }
        WithdrawalPhaseV3::Canceled(canceled) => {
            bytes.push(5);
            match &canceled.prepared {
                None => bytes.push(0),
                Some(prepared) => {
                    bytes.push(1);
                    write_prepared(&mut bytes, prepared)?;
                }
            }
            write_terminal(&mut bytes, canceled.terminal);
        }
    }
    Ok(bytes)
}

fn write_core(
    bytes: &mut Vec<u8>,
    core: &WithdrawalCoreV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    write_string(
        bytes,
        &core.request_id,
        MAX_V3_REQUEST_ID_BYTES,
        "request_id",
    )?;
    bytes.extend_from_slice(&core.request_digest);
    bytes.extend_from_slice(&core.destination);
    bytes.extend_from_slice(&core.amount_atoms.to_le_bytes());
    bytes.extend_from_slice(&core.fee_atoms.to_le_bytes());
    bytes.extend_from_slice(&core.change_atoms.to_le_bytes());
    bytes.extend_from_slice(&core.output_spendable_height.to_le_bytes());
    bytes.extend_from_slice(&core.signing_digest);
    write_count(bytes, core.reservations.len(), "reserved inputs")?;
    for input in &core.reservations {
        bytes.extend_from_slice(&input.outpoint.txid);
        bytes.extend_from_slice(&input.outpoint.index.to_le_bytes());
        bytes.extend_from_slice(&input.value_atoms.to_le_bytes());
        bytes.extend_from_slice(&input.wallet_key_id);
        bytes.extend_from_slice(&input.public_key);
        bytes.extend_from_slice(&input.signer_id);
    }
    Ok(())
}

fn write_prepared(
    bytes: &mut Vec<u8>,
    prepared: &PreparedPhaseV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    bytes.extend_from_slice(&prepared.prepared_generation.to_le_bytes());
    match &prepared.signer_package {
        None => bytes.push(0),
        Some(package) => {
            bytes.push(1);
            write_journal_anchor(bytes, package.prepared_anchor);
            write_keyring_anchor(bytes, package.keyring_anchor);
            bytes.extend_from_slice(&package.transaction_signing_digest);
            write_exact(bytes, &package.exact_package, MAX_V3_SIGNER_PACKAGE_BYTES)?;
        }
    }
    Ok(())
}

fn write_terminal(bytes: &mut Vec<u8>, terminal: TerminalDecisionV3) {
    bytes.push(terminal.scope.tag());
    bytes.push(terminal.action.tag());
    bytes.extend_from_slice(&terminal.decision_id);
    bytes.extend_from_slice(&terminal.approval_digest);
    bytes.extend_from_slice(&terminal.policy_id);
    write_journal_anchor(bytes, terminal.action_anchor);
    bytes.extend_from_slice(&terminal.request_digest);
    bytes.extend_from_slice(&terminal.transaction_signing_digest);
    bytes.extend_from_slice(&terminal.decided_at_unix_seconds.to_le_bytes());
    bytes.extend_from_slice(&terminal.accounted_at_unix_seconds.to_le_bytes());
}

fn write_exact(
    bytes: &mut Vec<u8>,
    exact: &ExactBytesV3,
    limit: usize,
) -> Result<(), ExchangeWithdrawalV3Error> {
    bytes.extend_from_slice(&exact.digest);
    write_blob(bytes, &exact.bytes, limit, "exact payload")
}

fn write_policy_window(
    bytes: &mut Vec<u8>,
    state: &PolicyWindowStateV3,
) -> Result<(), ExchangeWithdrawalV3Error> {
    bytes.extend_from_slice(&state.time_watermark_unix_seconds.to_le_bytes());
    write_count(bytes, state.release_events.len(), "policy release events")?;
    for event in &state.release_events {
        bytes.extend_from_slice(&event.request_digest);
        bytes.extend_from_slice(&event.released_at_unix_seconds.to_le_bytes());
        bytes.extend_from_slice(&event.debit_atoms.to_le_bytes());
    }
    Ok(())
}

fn write_tombstone(bytes: &mut Vec<u8>, tombstone: &ArchiveTombstoneV3) {
    bytes.extend_from_slice(&tombstone.request_id_tag);
    bytes.extend_from_slice(&tombstone.request_digest);
    bytes.push(tombstone.phase.tag());
    bytes.extend_from_slice(&tombstone.terminal_decision_id);
    bytes.extend_from_slice(&tombstone.approval_digest);
    bytes.extend_from_slice(&tombstone.archive_id);
    bytes.extend_from_slice(&tombstone.record_index.to_le_bytes());
    match tombstone.txid {
        None => bytes.push(0),
        Some(txid) => {
            bytes.push(1);
            bytes.extend_from_slice(&txid);
        }
    }
    bytes.extend_from_slice(&tombstone.debit_atoms.to_le_bytes());
    bytes.extend_from_slice(&tombstone.record_payload_digest);
}

fn write_migration_receipt(bytes: &mut Vec<u8>, receipt: &MigrationReceiptV3) {
    bytes.extend_from_slice(&receipt.migration_id);
    bytes.extend_from_slice(&receipt.source_snapshot_digest);
    write_journal_anchor(bytes, receipt.source_anchor);
    bytes.extend_from_slice(&receipt.migration_decision_id);
    bytes.extend_from_slice(&receipt.migration_approval_digest);
    bytes.extend_from_slice(&receipt.migration_input_digest);
    bytes.extend_from_slice(&receipt.migrated_record_count.to_le_bytes());
}

fn write_binding(bytes: &mut Vec<u8>, binding: JournalBindingV3) {
    bytes.extend_from_slice(&binding.network_id);
    bytes.extend_from_slice(&binding.consensus_fingerprint);
    bytes.extend_from_slice(&binding.genesis);
}

fn write_journal_anchor(bytes: &mut Vec<u8>, anchor: JournalAnchorV3) {
    bytes.extend_from_slice(&anchor.key_id);
    bytes.extend_from_slice(&anchor.journal_instance_id);
    bytes.extend_from_slice(&anchor.generation.to_le_bytes());
    bytes.extend_from_slice(&anchor.commitment);
}

fn write_keyring_anchor(bytes: &mut Vec<u8>, anchor: KeyringAnchorV3) {
    bytes.extend_from_slice(&anchor.instance_id);
    bytes.extend_from_slice(&anchor.generation.to_le_bytes());
    bytes.extend_from_slice(&anchor.commitment);
}

fn write_count(
    bytes: &mut Vec<u8>,
    count: usize,
    name: &'static str,
) -> Result<(), ExchangeWithdrawalV3Error> {
    let count = u32::try_from(count).map_err(|_| ExchangeWithdrawalV3Error::Capacity(name))?;
    bytes.extend_from_slice(&count.to_le_bytes());
    Ok(())
}

fn write_string(
    bytes: &mut Vec<u8>,
    value: &str,
    limit: usize,
    name: &'static str,
) -> Result<(), ExchangeWithdrawalV3Error> {
    write_blob(bytes, value.as_bytes(), limit, name)
}

fn write_blob(
    bytes: &mut Vec<u8>,
    value: &[u8],
    limit: usize,
    name: &'static str,
) -> Result<(), ExchangeWithdrawalV3Error> {
    if value.len() > limit {
        return Err(ExchangeWithdrawalV3Error::Capacity(name));
    }
    let length =
        u32::try_from(value.len()).map_err(|_| ExchangeWithdrawalV3Error::Capacity(name))?;
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn migration_input_digest(
    input: &ValidatedV2MigrationInputV3,
) -> Result<[u8; 32], ExchangeWithdrawalV3Error> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&input.source_schema_version.to_le_bytes());
    bytes.extend_from_slice(&input.source_snapshot_digest);
    write_journal_anchor(&mut bytes, input.source_current_anchor);
    write_journal_anchor(&mut bytes, input.source_external_anchor);
    bytes.extend_from_slice(&input.migration_id);
    bytes.extend_from_slice(&input.migration_decision_id);
    bytes.extend_from_slice(&input.migration_approval_digest);
    write_binding(&mut bytes, input.binding);
    bytes.extend_from_slice(&input.new_journal_instance_id);
    bytes.extend_from_slice(&input.policy_id);
    write_policy_window(&mut bytes, &input.initial_policy_window)?;
    write_keyring_anchor(&mut bytes, input.active_keyring);
    write_count(
        &mut bytes,
        input.released_records.len(),
        "migrated withdrawal records",
    )?;
    let mut previous_request_id: Option<&str> = None;
    for record in &input.released_records {
        if previous_request_id.is_some_and(|previous| previous >= record.core.request_id.as_str()) {
            return Err(ExchangeWithdrawalV3Error::InvalidMigration(
                "migrated records must be strictly request-id ordered",
            ));
        }
        previous_request_id = Some(&record.core.request_id);
        write_core(&mut bytes, &record.core)?;
        bytes.extend_from_slice(&record.source_prepared_generation.to_le_bytes());
        bytes.extend_from_slice(&record.source_record_digest);
        write_terminal(&mut bytes, record.terminal);
        bytes.extend_from_slice(&record.txid);
        write_blob(
            &mut bytes,
            &record.exact_transaction_bytes,
            MAX_V3_TRANSACTION_BYTES,
            "migrated transaction",
        )?;
        bytes.extend_from_slice(&record.debit_atoms.to_le_bytes());
    }
    if bytes.len() > MAX_V3_SNAPSHOT_BYTES {
        return Err(ExchangeWithdrawalV3Error::SnapshotTooLarge);
    }
    Ok(unkeyed_digest(MIGRATION_INPUT_DOMAIN, &bytes))
}

fn decode_state_payload(
    decoder: &mut Decoder<'_>,
) -> Result<ExchangeWithdrawalJournalV3, ExchangeWithdrawalV3Error> {
    let binding = read_binding(decoder)?;
    let journal_key_id = decoder.array()?;
    let journal_instance_id = decoder.array()?;
    let generation = decoder.u64()?;
    let commitment_count = decoder.count(MAX_V3_COMMITMENTS, "journal commitment history")?;
    let mut prior_commitments = Vec::with_capacity(commitment_count);
    for _ in 0..commitment_count {
        prior_commitments.push(decoder.array()?);
    }
    let migration = read_migration_receipt(decoder)?;
    let policy_id = decoder.array()?;
    let policy_window = read_policy_window(decoder)?;
    let active_keyring = read_keyring_anchor(decoder)?;
    let keyring_count = decoder.count(MAX_V3_WITHDRAWAL_RECORDS, "keyring history")?;
    let mut prior_keyrings = Vec::with_capacity(keyring_count);
    for _ in 0..keyring_count {
        prior_keyrings.push(KeyringHistoryEntryV3 {
            anchor: read_keyring_anchor(decoder)?,
            rotation_decision_id: decoder.array()?,
            approval_digest: decoder.array()?,
        });
    }
    let record_count = decoder.count(MAX_V3_WITHDRAWAL_RECORDS, "withdrawal records")?;
    let mut records = BTreeMap::new();
    let mut previous_request_id: Option<String> = None;
    for _ in 0..record_count {
        let request_id = decoder.string(MAX_V3_REQUEST_ID_BYTES, "request_id")?;
        if previous_request_id
            .as_ref()
            .is_some_and(|previous| previous >= &request_id)
        {
            return Err(ExchangeWithdrawalV3Error::NonCanonical);
        }
        previous_request_id = Some(request_id.clone());
        let record_bytes = decoder.blob(MAX_V3_SNAPSHOT_BYTES, "record")?;
        let mut record_decoder = Decoder::new(record_bytes);
        let record = read_record(&mut record_decoder)?;
        if !record_decoder.is_empty() || record.core.request_id != request_id {
            return Err(ExchangeWithdrawalV3Error::NonCanonical);
        }
        if records.insert(request_id, record).is_some() {
            return Err(ExchangeWithdrawalV3Error::NonCanonical);
        }
    }
    let tombstone_count = decoder.count(MAX_V3_TOMBSTONES, "archive tombstones")?;
    let mut tombstones = BTreeMap::new();
    let mut previous_tag = None;
    for _ in 0..tombstone_count {
        let tag = decoder.array()?;
        if previous_tag.is_some_and(|previous| previous >= tag) {
            return Err(ExchangeWithdrawalV3Error::NonCanonical);
        }
        previous_tag = Some(tag);
        let tombstone = read_tombstone(decoder)?;
        if tombstone.request_id_tag != tag || tombstones.insert(tag, tombstone).is_some() {
            return Err(ExchangeWithdrawalV3Error::NonCanonical);
        }
    }
    Ok(ExchangeWithdrawalJournalV3 {
        binding,
        journal_key_id,
        journal_instance_id,
        generation,
        prior_commitments,
        migration,
        policy_id,
        policy_window,
        active_keyring,
        prior_keyrings,
        records,
        tombstones,
    })
}

fn read_record(decoder: &mut Decoder<'_>) -> Result<WithdrawalRecordV3, ExchangeWithdrawalV3Error> {
    let origin = match decoder.byte()? {
        1 => RecordOriginV3::NativeV3,
        2 => RecordOriginV3::ValidatedV2 {
            source_record_digest: decoder.array()?,
        },
        _ => return Err(ExchangeWithdrawalV3Error::NonCanonical),
    };
    let core = read_core(decoder)?;
    let phase = match decoder.byte()? {
        1 => WithdrawalPhaseV3::Intent,
        2 => WithdrawalPhaseV3::Prepared(read_prepared(decoder)?),
        3 => WithdrawalPhaseV3::ReleaseAuthorized(ReleaseAuthorizedPhaseV3 {
            prepared: read_prepared(decoder)?,
            terminal: read_terminal(decoder)?,
            debit_atoms: decoder.u64()?,
        }),
        4 => WithdrawalPhaseV3::Released(ReleasedPhaseV3 {
            prepared: read_prepared(decoder)?,
            terminal: read_terminal(decoder)?,
            txid: decoder.array()?,
            exact_transaction: read_exact(decoder, MAX_V3_TRANSACTION_BYTES)?,
            debit_atoms: decoder.u64()?,
        }),
        5 => {
            let prepared = match decoder.byte()? {
                0 => None,
                1 => Some(read_prepared(decoder)?),
                _ => return Err(ExchangeWithdrawalV3Error::NonCanonical),
            };
            WithdrawalPhaseV3::Canceled(CanceledPhaseV3 {
                prepared,
                terminal: read_terminal(decoder)?,
            })
        }
        _ => return Err(ExchangeWithdrawalV3Error::NonCanonical),
    };
    Ok(WithdrawalRecordV3 {
        origin,
        core,
        phase,
    })
}

fn read_core(decoder: &mut Decoder<'_>) -> Result<WithdrawalCoreV3, ExchangeWithdrawalV3Error> {
    let request_id = decoder.string(MAX_V3_REQUEST_ID_BYTES, "request_id")?;
    let request_digest = decoder.array()?;
    let destination = decoder.array()?;
    let amount_atoms = decoder.u64()?;
    let fee_atoms = decoder.u64()?;
    let change_atoms = decoder.u64()?;
    let output_spendable_height = decoder.u64()?;
    let signing_digest = decoder.array()?;
    let count = decoder.count(MAX_V3_RESERVED_INPUTS, "reserved inputs")?;
    let mut reservations = Vec::with_capacity(count);
    for _ in 0..count {
        reservations.push(ReservedInputV3 {
            outpoint: ReservedOutpointV3 {
                txid: decoder.array()?,
                index: decoder.u32()?,
            },
            value_atoms: decoder.u64()?,
            wallet_key_id: decoder.array()?,
            public_key: decoder.array()?,
            signer_id: decoder.array()?,
        });
    }
    Ok(WithdrawalCoreV3 {
        request_id,
        request_digest,
        destination,
        amount_atoms,
        fee_atoms,
        change_atoms,
        output_spendable_height,
        signing_digest,
        reservations,
    })
}

fn read_prepared(decoder: &mut Decoder<'_>) -> Result<PreparedPhaseV3, ExchangeWithdrawalV3Error> {
    let prepared_generation = decoder.u64()?;
    let signer_package = match decoder.byte()? {
        0 => None,
        1 => Some(SignerPackageEvidenceV3 {
            prepared_anchor: read_journal_anchor(decoder)?,
            keyring_anchor: read_keyring_anchor(decoder)?,
            transaction_signing_digest: decoder.array()?,
            exact_package: read_exact(decoder, MAX_V3_SIGNER_PACKAGE_BYTES)?,
        }),
        _ => return Err(ExchangeWithdrawalV3Error::NonCanonical),
    };
    Ok(PreparedPhaseV3 {
        prepared_generation,
        signer_package,
    })
}

fn read_terminal(
    decoder: &mut Decoder<'_>,
) -> Result<TerminalDecisionV3, ExchangeWithdrawalV3Error> {
    Ok(TerminalDecisionV3 {
        scope: DecisionScopeV3::decode(decoder.byte()?)?,
        action: WithdrawalActionV3::decode(decoder.byte()?)?,
        decision_id: decoder.array()?,
        approval_digest: decoder.array()?,
        policy_id: decoder.array()?,
        action_anchor: read_journal_anchor(decoder)?,
        request_digest: decoder.array()?,
        transaction_signing_digest: decoder.array()?,
        decided_at_unix_seconds: decoder.u64()?,
        accounted_at_unix_seconds: decoder.u64()?,
    })
}

fn read_exact(
    decoder: &mut Decoder<'_>,
    limit: usize,
) -> Result<ExactBytesV3, ExchangeWithdrawalV3Error> {
    Ok(ExactBytesV3 {
        digest: decoder.array()?,
        bytes: decoder.blob(limit, "exact payload")?.to_vec(),
    })
}

fn read_policy_window(
    decoder: &mut Decoder<'_>,
) -> Result<PolicyWindowStateV3, ExchangeWithdrawalV3Error> {
    let time_watermark_unix_seconds = decoder.u64()?;
    let count = decoder.count(MAX_V3_POLICY_EVENTS, "policy release events")?;
    let mut release_events = Vec::with_capacity(count);
    for _ in 0..count {
        release_events.push(PolicyReleaseEventV3 {
            request_digest: decoder.array()?,
            released_at_unix_seconds: decoder.u64()?,
            debit_atoms: decoder.u64()?,
        });
    }
    Ok(PolicyWindowStateV3 {
        time_watermark_unix_seconds,
        release_events,
    })
}

fn read_tombstone(
    decoder: &mut Decoder<'_>,
) -> Result<ArchiveTombstoneV3, ExchangeWithdrawalV3Error> {
    let request_id_tag = decoder.array()?;
    let request_digest = decoder.array()?;
    let phase = TerminalPhaseV3::decode(decoder.byte()?)?;
    let terminal_decision_id = decoder.array()?;
    let approval_digest = decoder.array()?;
    let archive_id = decoder.array()?;
    let record_index = decoder.u64()?;
    let txid = match decoder.byte()? {
        0 => None,
        1 => Some(decoder.array()?),
        _ => return Err(ExchangeWithdrawalV3Error::NonCanonical),
    };
    let debit_atoms = decoder.u64()?;
    let record_payload_digest = decoder.array()?;
    Ok(ArchiveTombstoneV3 {
        request_id_tag,
        request_digest,
        phase,
        terminal_decision_id,
        approval_digest,
        archive_id,
        record_index,
        txid,
        debit_atoms,
        record_payload_digest,
    })
}

fn read_migration_receipt(
    decoder: &mut Decoder<'_>,
) -> Result<MigrationReceiptV3, ExchangeWithdrawalV3Error> {
    Ok(MigrationReceiptV3 {
        migration_id: decoder.array()?,
        source_snapshot_digest: decoder.array()?,
        source_anchor: read_journal_anchor(decoder)?,
        migration_decision_id: decoder.array()?,
        migration_approval_digest: decoder.array()?,
        migration_input_digest: decoder.array()?,
        migrated_record_count: decoder.u64()?,
    })
}

fn read_binding(decoder: &mut Decoder<'_>) -> Result<JournalBindingV3, ExchangeWithdrawalV3Error> {
    Ok(JournalBindingV3 {
        network_id: decoder.array()?,
        consensus_fingerprint: decoder.array()?,
        genesis: decoder.array()?,
    })
}

fn read_journal_anchor(
    decoder: &mut Decoder<'_>,
) -> Result<JournalAnchorV3, ExchangeWithdrawalV3Error> {
    Ok(JournalAnchorV3 {
        key_id: decoder.array()?,
        journal_instance_id: decoder.array()?,
        generation: decoder.u64()?,
        commitment: decoder.array()?,
    })
}

fn read_keyring_anchor(
    decoder: &mut Decoder<'_>,
) -> Result<KeyringAnchorV3, ExchangeWithdrawalV3Error> {
    Ok(KeyringAnchorV3 {
        instance_id: decoder.array()?,
        generation: decoder.u64()?,
        commitment: decoder.array()?,
    })
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ExchangeWithdrawalV3Error> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ExchangeWithdrawalV3Error::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ExchangeWithdrawalV3Error::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, ExchangeWithdrawalV3Error> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, ExchangeWithdrawalV3Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("fixed slice"),
        ))
    }

    fn u64(&mut self) -> Result<u64, ExchangeWithdrawalV3Error> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("fixed slice"),
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ExchangeWithdrawalV3Error> {
        Ok(self.take(N)?.try_into().expect("fixed slice"))
    }

    fn count(
        &mut self,
        limit: usize,
        name: &'static str,
    ) -> Result<usize, ExchangeWithdrawalV3Error> {
        let count =
            usize::try_from(self.u32()?).map_err(|_| ExchangeWithdrawalV3Error::Capacity(name))?;
        if count > limit {
            return Err(ExchangeWithdrawalV3Error::Capacity(name));
        }
        Ok(count)
    }

    fn blob(
        &mut self,
        limit: usize,
        name: &'static str,
    ) -> Result<&'a [u8], ExchangeWithdrawalV3Error> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| ExchangeWithdrawalV3Error::Capacity(name))?;
        if length > limit {
            return Err(ExchangeWithdrawalV3Error::Capacity(name));
        }
        self.take(length)
    }

    fn string(
        &mut self,
        limit: usize,
        name: &'static str,
    ) -> Result<String, ExchangeWithdrawalV3Error> {
        let bytes = self.blob(limit, name)?;
        let value =
            std::str::from_utf8(bytes).map_err(|_| ExchangeWithdrawalV3Error::NonCanonical)?;
        Ok(value.to_owned())
    }
}

fn keyed_digest(key: &[u8; 32], domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn unkeyed_digest(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn constant_time_equal(expected: &[u8; 32], actual: &[u8]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    expected
        .iter()
        .zip(actual)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOURNAL_KEY: [u8; 32] = [0xA5; 32];

    fn marker(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn source_anchor() -> JournalAnchorV3 {
        JournalAnchorV3 {
            key_id: marker(1),
            journal_instance_id: marker(2),
            generation: 9,
            commitment: marker(3),
        }
    }

    fn keyring(generation: u64, marker_value: u8) -> KeyringAnchorV3 {
        KeyringAnchorV3 {
            instance_id: marker(marker_value),
            generation,
            commitment: marker(marker_value.wrapping_add(1)),
        }
    }

    fn migration_input() -> ValidatedV2MigrationInputV3 {
        ValidatedV2MigrationInputV3 {
            source_schema_version: 2,
            source_snapshot_digest: marker(4),
            source_current_anchor: source_anchor(),
            source_external_anchor: source_anchor(),
            migration_id: marker(5),
            migration_decision_id: marker(6),
            migration_approval_digest: marker(7),
            binding: JournalBindingV3 {
                network_id: marker(8),
                consensus_fingerprint: marker(9),
                genesis: marker(10),
            },
            new_journal_instance_id: marker(11),
            policy_id: marker(12),
            initial_policy_window: PolicyWindowStateV3 {
                time_watermark_unix_seconds: 1_700_000_000,
                release_events: Vec::new(),
            },
            active_keyring: keyring(1, 13),
            released_records: Vec::new(),
        }
    }

    fn initial() -> ExchangeWithdrawalJournalV3 {
        migrate_validated_v2(migration_input(), &JOURNAL_KEY)
            .unwrap()
            .journal
    }

    fn core(request_id: &str, digest_marker: u8, outpoint_marker: u8) -> WithdrawalCoreV3 {
        WithdrawalCoreV3 {
            request_id: request_id.to_owned(),
            request_digest: marker(digest_marker),
            destination: marker(digest_marker.wrapping_add(1)),
            amount_atoms: 700,
            fee_atoms: 20,
            change_atoms: 280,
            output_spendable_height: 44,
            signing_digest: marker(digest_marker.wrapping_add(2)),
            reservations: vec![ReservedInputV3 {
                outpoint: ReservedOutpointV3 {
                    txid: marker(outpoint_marker),
                    index: 0,
                },
                value_atoms: 1_000,
                wallet_key_id: marker(outpoint_marker.wrapping_add(1)),
                public_key: marker(outpoint_marker.wrapping_add(2)),
                signer_id: marker(outpoint_marker.wrapping_add(3)),
            }],
        }
    }

    fn add_intent(
        state: &ExchangeWithdrawalJournalV3,
        core: WithdrawalCoreV3,
    ) -> ExchangeWithdrawalJournalV3 {
        state
            .apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::AddIntent(AddIntentV3 {
                    expected_anchor: state.anchor(&JOURNAL_KEY).unwrap(),
                    core,
                }),
            )
            .unwrap()
    }

    fn prepare_and_attach(
        state: &ExchangeWithdrawalJournalV3,
        request_id: &str,
        request_digest: [u8; 32],
        signing_digest: [u8; 32],
    ) -> ExchangeWithdrawalJournalV3 {
        let state = state
            .apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::Prepare(PrepareWithdrawalV3 {
                    expected_anchor: state.anchor(&JOURNAL_KEY).unwrap(),
                    request_id: request_id.to_owned(),
                    request_digest,
                }),
            )
            .unwrap();
        let prepared_anchor = state.anchor(&JOURNAL_KEY).unwrap();
        state
            .apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::AttachSignerPackage(AttachSignerPackageV3 {
                    expected_anchor: prepared_anchor,
                    request_id: request_id.to_owned(),
                    request_digest,
                    signer_package: SignerPackageEvidenceV3 {
                        prepared_anchor,
                        keyring_anchor: state.active_keyring,
                        transaction_signing_digest: signing_digest,
                        exact_package: ExactBytesV3::signer_package(vec![21, 22, 23]).unwrap(),
                    },
                }),
            )
            .unwrap()
    }

    fn terminal(
        state: &ExchangeWithdrawalJournalV3,
        core: &WithdrawalCoreV3,
        action: WithdrawalActionV3,
        decision_marker: u8,
        decided_at: u64,
    ) -> TerminalDecisionV3 {
        TerminalDecisionV3 {
            scope: DecisionScopeV3::NativeV3,
            action,
            decision_id: marker(decision_marker),
            approval_digest: marker(decision_marker.wrapping_add(1)),
            policy_id: state.policy_id,
            action_anchor: state.anchor(&JOURNAL_KEY).unwrap(),
            request_digest: core.request_digest,
            transaction_signing_digest: core.signing_digest,
            decided_at_unix_seconds: decided_at,
            accounted_at_unix_seconds: decided_at,
        }
    }

    fn authorize_release(
        state: &ExchangeWithdrawalJournalV3,
        core: &WithdrawalCoreV3,
        decision_marker: u8,
        decided_at: u64,
    ) -> ExchangeWithdrawalJournalV3 {
        let terminal = terminal(
            state,
            core,
            WithdrawalActionV3::Release,
            decision_marker,
            decided_at,
        );
        state
            .apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::AuthorizeRelease(AuthorizeReleaseV3 {
                    expected_anchor: terminal.action_anchor,
                    request_id: core.request_id.clone(),
                    request_digest: core.request_digest,
                    terminal,
                }),
            )
            .unwrap()
    }

    fn complete_release(
        state: &ExchangeWithdrawalJournalV3,
        core: &WithdrawalCoreV3,
        txid: [u8; 32],
        transaction_bytes: Vec<u8>,
    ) -> ExchangeWithdrawalJournalV3 {
        let WithdrawalPhaseV3::ReleaseAuthorized(authorized) =
            &state.records[&core.request_id].phase
        else {
            panic!("expected ReleaseAuthorized")
        };
        let package_digest = authorized
            .prepared
            .signer_package
            .as_ref()
            .unwrap()
            .exact_package
            .digest;
        state
            .apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::CompleteRelease(CompleteReleaseV3 {
                    expected_anchor: state.anchor(&JOURNAL_KEY).unwrap(),
                    request_id: core.request_id.clone(),
                    request_digest: core.request_digest,
                    decision_id: authorized.terminal.decision_id,
                    approval_digest: authorized.terminal.approval_digest,
                    signer_package_digest: package_digest,
                    transaction_signing_digest: core.signing_digest,
                    txid,
                    exact_transaction_bytes: transaction_bytes,
                }),
            )
            .unwrap()
    }

    fn released_state() -> ExchangeWithdrawalJournalV3 {
        let core = core("wd-001", 30, 40);
        let state = add_intent(&initial(), core.clone());
        let state = prepare_and_attach(
            &state,
            &core.request_id,
            core.request_digest,
            core.signing_digest,
        );
        let state = authorize_release(&state, &core, 50, 1_700_000_100);
        complete_release(&state, &core, marker(60), vec![31, 32, 33, 34])
    }

    fn canceled_state() -> ExchangeWithdrawalJournalV3 {
        let core = core("wd-001", 30, 40);
        let state = add_intent(&initial(), core.clone());
        let terminal = terminal(&state, &core, WithdrawalActionV3::Cancel, 50, 1_700_000_100);
        state
            .apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::Cancel(CancelWithdrawalV3 {
                    expected_anchor: terminal.action_anchor,
                    request_id: core.request_id,
                    request_digest: core.request_digest,
                    terminal,
                }),
            )
            .unwrap()
    }

    #[test]
    fn explicit_migration_round_trips_and_has_stable_golden_values() {
        let output = migrate_validated_v2(migration_input(), &JOURNAL_KEY).unwrap();
        assert_eq!(output.initial_anchor.generation, 1);
        assert_eq!(
            output.journal,
            ExchangeWithdrawalJournalV3::decode_authenticated(
                &output.authenticated_snapshot,
                &JOURNAL_KEY,
            )
            .unwrap()
        );
        let snapshot_digest = unkeyed_digest("test/snapshot", &output.authenticated_snapshot);
        assert_eq!(
            hex(&output.initial_anchor.commitment),
            "ba70a6c74b33c2265e159c9b032769f120bf00dd476f661670b3205adc0bdf55"
        );
        assert_eq!(
            hex(&snapshot_digest),
            "377ad09c67d7ab6ffc66d1b03e2119c045063e4b6a7bdbe6a11938c45d50bc58"
        );
        assert_eq!(
            hex(&validated_v2_snapshot_digest(b"validated v2 snapshot")),
            "89c1c306e5a7ade1eb27e624e88795230fb2f7f8548971cd5a82d9b37cda987f"
        );
    }

    #[test]
    fn legacy_snapshots_are_rejected_instead_of_silently_migrated() {
        for version in [1_u32, 2] {
            let mut bytes = vec![0_u8; HEADER_BYTES + AUTH_TAG_BYTES];
            bytes[..8].copy_from_slice(&SNAPSHOT_MAGIC);
            bytes[8..12].copy_from_slice(&version.to_le_bytes());
            assert_eq!(
                ExchangeWithdrawalJournalV3::decode_authenticated(&bytes, &JOURNAL_KEY),
                Err(ExchangeWithdrawalV3Error::ExplicitMigrationRequired)
            );
        }
    }

    #[test]
    fn migration_requires_exact_external_pin_fresh_instance_and_v2() {
        let mut input = migration_input();
        input.source_external_anchor.commitment[0] ^= 1;
        assert!(matches!(
            migrate_validated_v2(input, &JOURNAL_KEY),
            Err(ExchangeWithdrawalV3Error::InvalidMigration(_))
        ));
        let mut input = migration_input();
        input.new_journal_instance_id = input.source_current_anchor.journal_instance_id;
        assert!(matches!(
            migrate_validated_v2(input, &JOURNAL_KEY),
            Err(ExchangeWithdrawalV3Error::InvalidMigration(_))
        ));
        let mut input = migration_input();
        input.source_schema_version = 1;
        assert!(matches!(
            migrate_validated_v2(input, &JOURNAL_KEY),
            Err(ExchangeWithdrawalV3Error::InvalidMigration(_))
        ));
    }

    #[test]
    fn migrated_released_record_is_honest_about_legacy_signer_evidence() {
        let mut input = migration_input();
        let migrated_core = core("legacy-release", 24, 25);
        input.released_records.push(ValidatedV2ReleasedRecordV3 {
            core: migrated_core.clone(),
            source_prepared_generation: 8,
            source_record_digest: marker(26),
            terminal: TerminalDecisionV3 {
                scope: DecisionScopeV3::ValidatedV2Migration,
                action: WithdrawalActionV3::Release,
                decision_id: marker(27),
                approval_digest: marker(28),
                policy_id: input.policy_id,
                action_anchor: input.source_current_anchor,
                request_digest: migrated_core.request_digest,
                transaction_signing_digest: migrated_core.signing_digest,
                decided_at_unix_seconds: 1_700_000_000,
                accounted_at_unix_seconds: 1_700_000_000,
            },
            txid: marker(29),
            exact_transaction_bytes: vec![5, 6, 7],
            debit_atoms: 720,
        });
        input
            .initial_policy_window
            .release_events
            .push(PolicyReleaseEventV3 {
                request_digest: migrated_core.request_digest,
                released_at_unix_seconds: 1_700_000_000,
                debit_atoms: 720,
            });
        let output = migrate_validated_v2(input, &JOURNAL_KEY).unwrap();
        let WithdrawalPhaseV3::Released(released) = &output.journal.records["legacy-release"].phase
        else {
            panic!("expected Released")
        };
        assert!(released.prepared.signer_package.is_none());
        assert_eq!(released.exact_transaction.bytes, vec![5, 6, 7]);
        assert_eq!(
            released.terminal.scope,
            DecisionScopeV3::ValidatedV2Migration
        );
        assert_eq!(output.receipt.migrated_record_count, 1);
        assert_eq!(
            ExchangeWithdrawalJournalV3::decode_authenticated(
                &output.authenticated_snapshot,
                &JOURNAL_KEY
            )
            .unwrap(),
            output.journal
        );
    }

    #[test]
    fn release_atomically_retains_package_transaction_approval_and_policy_debit() {
        let state = released_state();
        let record = state.records.get("wd-001").unwrap();
        let WithdrawalPhaseV3::Released(released) = &record.phase else {
            panic!("expected Released")
        };
        assert_eq!(released.debit_atoms, 720);
        assert_eq!(released.exact_transaction.bytes, vec![31, 32, 33, 34]);
        assert_eq!(
            released
                .prepared
                .signer_package
                .as_ref()
                .unwrap()
                .exact_package
                .bytes,
            vec![21, 22, 23]
        );
        assert_eq!(released.terminal.decision_id, marker(50));
        assert_eq!(released.terminal.approval_digest, marker(51));
        assert_eq!(state.policy_window.release_events.len(), 1);
        assert_eq!(state.policy_window.release_events[0].debit_atoms, 720);
        assert!(!state.canonical_record_bytes("wd-001").unwrap().is_empty());
        let encoded = state.encode_authenticated(&JOURNAL_KEY).unwrap();
        assert_eq!(
            ExchangeWithdrawalJournalV3::decode_authenticated(&encoded, &JOURNAL_KEY).unwrap(),
            state
        );
    }

    #[test]
    fn active_release_terminal_cannot_omit_or_retime_its_policy_event() {
        let state = released_state();
        let mut missing = state.clone();
        missing.policy_window.release_events.clear();
        assert!(matches!(
            missing.validate(&JOURNAL_KEY),
            Err(ExchangeWithdrawalV3Error::InvalidState(
                "active release terminal and policy event differ"
            ))
        ));

        let mut retimed = state;
        retimed.policy_window.release_events[0].released_at_unix_seconds += 1;
        retimed.policy_window.time_watermark_unix_seconds += 1;
        assert!(matches!(
            retimed.validate(&JOURNAL_KEY),
            Err(ExchangeWithdrawalV3Error::InvalidState(_))
        ));

        let mut delayed = released_state();
        let WithdrawalPhaseV3::Released(released) =
            &mut delayed.records.get_mut("wd-001").unwrap().phase
        else {
            panic!("expected Released")
        };
        let delayed_time =
            released.terminal.decided_at_unix_seconds + MAX_APPROVAL_VALIDITY_SECONDS;
        released.terminal.accounted_at_unix_seconds = delayed_time;
        delayed.policy_window.release_events[0].released_at_unix_seconds = delayed_time;
        delayed.policy_window.time_watermark_unix_seconds = delayed_time;
        assert!(matches!(
            delayed.validate(&JOURNAL_KEY),
            Err(ExchangeWithdrawalV3Error::InvalidState(_))
        ));
    }

    #[test]
    fn authorization_is_durable_before_key_use_and_completion_never_recharges() {
        let release_core = core("wd-authorized-crash", 39, 49);
        let state = add_intent(&initial(), release_core.clone());
        let state = prepare_and_attach(
            &state,
            &release_core.request_id,
            release_core.request_digest,
            release_core.signing_digest,
        );
        let authorized = authorize_release(&state, &release_core, 86, 1_700_000_100);
        let WithdrawalPhaseV3::ReleaseAuthorized(authorization) =
            &authorized.records[&release_core.request_id].phase
        else {
            panic!("expected ReleaseAuthorized")
        };
        assert_eq!(authorization.debit_atoms, 720);
        assert_eq!(authorized.policy_window.release_events.len(), 1);
        assert!(
            !authorized.records[&release_core.request_id]
                .phase
                .is_terminal()
        );

        let persisted = authorized.encode_authenticated(&JOURNAL_KEY).unwrap();
        let restarted =
            ExchangeWithdrawalJournalV3::decode_authenticated(&persisted, &JOURNAL_KEY).unwrap();
        assert_eq!(restarted, authorized);
        assert!(matches!(
            restarted.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::Cancel(CancelWithdrawalV3 {
                    expected_anchor: restarted.anchor(&JOURNAL_KEY).unwrap(),
                    request_id: release_core.request_id.clone(),
                    request_digest: release_core.request_digest,
                    terminal: TerminalDecisionV3 {
                        scope: DecisionScopeV3::NativeV3,
                        action: WithdrawalActionV3::Cancel,
                        decision_id: marker(88),
                        approval_digest: marker(89),
                        policy_id: restarted.policy_id,
                        action_anchor: restarted.anchor(&JOURNAL_KEY).unwrap(),
                        request_digest: release_core.request_digest,
                        transaction_signing_digest: release_core.signing_digest,
                        decided_at_unix_seconds: 1_700_000_101,
                        accounted_at_unix_seconds: 1_700_000_101,
                    },
                })
            ),
            Err(ExchangeWithdrawalV3Error::InvalidTransition(_))
        ));

        let other_core = core("wd-decision-reuse", 100, 120);
        let other = add_intent(&restarted, other_core.clone());
        let other = prepare_and_attach(
            &other,
            &other_core.request_id,
            other_core.request_digest,
            other_core.signing_digest,
        );
        let reused_decision = terminal(
            &other,
            &other_core,
            WithdrawalActionV3::Release,
            86,
            1_700_000_101,
        );
        assert!(matches!(
            other.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::AuthorizeRelease(AuthorizeReleaseV3 {
                    expected_anchor: reused_decision.action_anchor,
                    request_id: other_core.request_id,
                    request_digest: other_core.request_digest,
                    terminal: reused_decision,
                })
            ),
            Err(ExchangeWithdrawalV3Error::InvalidTransition(_))
        ));
        assert_eq!(other.policy_window.release_events.len(), 1);

        let package_digest = authorization
            .prepared
            .signer_package
            .as_ref()
            .unwrap()
            .exact_package
            .digest;
        let completion = CompleteReleaseV3 {
            expected_anchor: restarted.anchor(&JOURNAL_KEY).unwrap(),
            request_id: release_core.request_id.clone(),
            request_digest: release_core.request_digest,
            decision_id: authorization.terminal.decision_id,
            approval_digest: authorization.terminal.approval_digest,
            signer_package_digest: package_digest,
            transaction_signing_digest: release_core.signing_digest,
            txid: marker(90),
            exact_transaction_bytes: vec![9, 10, 11],
        };
        let mut wrong_completion = completion.clone();
        wrong_completion.signer_package_digest[0] ^= 1;
        assert!(matches!(
            restarted.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::CompleteRelease(wrong_completion)
            ),
            Err(ExchangeWithdrawalV3Error::InvalidTransition(_))
        ));
        let completed = restarted
            .apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::CompleteRelease(completion.clone()),
            )
            .unwrap();
        validate_authorized_completion(&restarted, &completed, &JOURNAL_KEY, &completion).unwrap();
        assert_eq!(completed.policy_window, restarted.policy_window);
        assert_eq!(completed.policy_window.release_events.len(), 1);
        assert!(matches!(
            completed.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::CompleteRelease(CompleteReleaseV3 {
                    expected_anchor: completed.anchor(&JOURNAL_KEY).unwrap(),
                    ..completion
                })
            ),
            Err(ExchangeWithdrawalV3Error::InvalidTransition(_))
        ));
    }

    #[test]
    fn release_without_attached_package_is_rejected_without_mutation() {
        let core = core("wd-no-package", 31, 41);
        let state = add_intent(&initial(), core.clone());
        let state = state
            .apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::Prepare(PrepareWithdrawalV3 {
                    expected_anchor: state.anchor(&JOURNAL_KEY).unwrap(),
                    request_id: core.request_id.clone(),
                    request_digest: core.request_digest,
                }),
            )
            .unwrap();
        let before = state.clone();
        let terminal = terminal(
            &state,
            &core,
            WithdrawalActionV3::Release,
            52,
            1_700_000_100,
        );
        assert!(matches!(
            state.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::AuthorizeRelease(AuthorizeReleaseV3 {
                    expected_anchor: terminal.action_anchor,
                    request_id: core.request_id,
                    request_digest: core.request_digest,
                    terminal,
                })
            ),
            Err(ExchangeWithdrawalV3Error::InvalidTransition(_))
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn cancel_is_terminal_has_no_transaction_and_uses_distinct_action() {
        let core = core("wd-cancel", 32, 42);
        let state = add_intent(&initial(), core.clone());
        let terminal = terminal(&state, &core, WithdrawalActionV3::Cancel, 54, 1_700_000_100);
        let state = state
            .apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::Cancel(CancelWithdrawalV3 {
                    expected_anchor: terminal.action_anchor,
                    request_id: core.request_id.clone(),
                    request_digest: core.request_digest,
                    terminal,
                }),
            )
            .unwrap();
        let WithdrawalPhaseV3::Canceled(canceled) = &state.records[&core.request_id].phase else {
            panic!("expected Canceled")
        };
        assert!(canceled.prepared.is_none());
        assert!(state.policy_window.release_events.is_empty());
        let action_anchor = state.anchor(&JOURNAL_KEY).unwrap();
        let release_attempt = TerminalDecisionV3 {
            scope: DecisionScopeV3::NativeV3,
            action: WithdrawalActionV3::Release,
            decision_id: marker(56),
            approval_digest: marker(57),
            policy_id: state.policy_id,
            action_anchor,
            request_digest: core.request_digest,
            transaction_signing_digest: core.signing_digest,
            decided_at_unix_seconds: 1_700_000_101,
            accounted_at_unix_seconds: 1_700_000_101,
        };
        assert!(matches!(
            state.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::AuthorizeRelease(AuthorizeReleaseV3 {
                    expected_anchor: action_anchor,
                    request_id: core.request_id,
                    request_digest: core.request_digest,
                    terminal: release_attempt,
                })
            ),
            Err(ExchangeWithdrawalV3Error::InvalidTransition(_))
        ));
    }

    #[test]
    fn action_and_anchor_substitution_are_rejected() {
        let core = core("wd-substitution", 33, 43);
        let state = add_intent(&initial(), core.clone());
        let expected_anchor = state.anchor(&JOURNAL_KEY).unwrap();
        let mut wrong_action = terminal(
            &state,
            &core,
            WithdrawalActionV3::Release,
            58,
            1_700_000_100,
        );
        assert!(matches!(
            state.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::Cancel(CancelWithdrawalV3 {
                    expected_anchor,
                    request_id: core.request_id.clone(),
                    request_digest: core.request_digest,
                    terminal: wrong_action,
                })
            ),
            Err(ExchangeWithdrawalV3Error::InvalidTransition(_))
        ));
        wrong_action.action = WithdrawalActionV3::Cancel;
        wrong_action.action_anchor.commitment[0] ^= 1;
        assert!(matches!(
            state.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::Cancel(CancelWithdrawalV3 {
                    expected_anchor,
                    request_id: core.request_id,
                    request_digest: core.request_digest,
                    terminal: wrong_action,
                })
            ),
            Err(ExchangeWithdrawalV3Error::InvalidTransition(_))
        ));
    }

    #[test]
    fn policy_clock_rollback_is_fail_closed() {
        let first = released_state();
        let core = core("wd-late", 34, 44);
        let state = add_intent(&first, core.clone());
        let state = prepare_and_attach(
            &state,
            &core.request_id,
            core.request_digest,
            core.signing_digest,
        );
        let terminal = terminal(
            &state,
            &core,
            WithdrawalActionV3::Release,
            70,
            1_699_999_999,
        );
        assert!(matches!(
            state.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::AuthorizeRelease(AuthorizeReleaseV3 {
                    expected_anchor: terminal.action_anchor,
                    request_id: core.request_id,
                    request_digest: core.request_digest,
                    terminal,
                })
            ),
            Err(ExchangeWithdrawalV3Error::InvalidTransition(_))
        ));
        assert_eq!(state.policy_window.release_events.len(), 1);
    }

    #[test]
    fn compaction_installs_permanent_tombstone_and_rejects_reuse() {
        let state = canceled_state();
        let source = state.anchor(&JOURNAL_KEY).unwrap();
        let item = state
            .archive_prune_record(&JOURNAL_KEY, "wd-001", 0)
            .unwrap();
        let state = state
            .apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::Compact(CompactTerminalRecordsV3 {
                    expected_anchor: source,
                    archive_source_anchor: source,
                    archive_id: marker(80),
                    records: vec![item],
                }),
            )
            .unwrap();
        assert!(state.records.is_empty());
        assert_eq!(state.tombstones.len(), 1);
        assert!(state.policy_window.release_events.is_empty());
        let reused = core("wd-001", 90, 91);
        assert_eq!(
            state.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::AddIntent(AddIntentV3 {
                    expected_anchor: state.anchor(&JOURNAL_KEY).unwrap(),
                    core: reused,
                })
            ),
            Err(ExchangeWithdrawalV3Error::ReusedArchivedRequest)
        );
    }

    #[test]
    fn bad_archive_digest_does_not_prune_live_record() {
        let state = canceled_state();
        let source = state.anchor(&JOURNAL_KEY).unwrap();
        let mut item = state
            .archive_prune_record(&JOURNAL_KEY, "wd-001", 0)
            .unwrap();
        item.record_payload_digest[0] ^= 1;
        assert!(matches!(
            state.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::Compact(CompactTerminalRecordsV3 {
                    expected_anchor: source,
                    archive_source_anchor: source,
                    archive_id: marker(81),
                    records: vec![item],
                })
            ),
            Err(ExchangeWithdrawalV3Error::InvalidTransition(_))
        ));
        assert!(state.records.contains_key("wd-001"));
        assert!(state.tombstones.is_empty());
    }

    #[test]
    fn released_records_cannot_be_archived_without_a_finality_policy() {
        let state = released_state();
        assert!(matches!(
            state.archive_prune_record(&JOURNAL_KEY, "wd-001", 0),
            Err(ExchangeWithdrawalV3Error::InvalidTransition(
                "only a canceled record can be archived"
            ))
        ));
    }

    #[test]
    fn canceled_compaction_cannot_mask_a_missing_migrated_released_record() {
        let mut input = migration_input();
        let migrated_core = core("legacy-release", 24, 25);
        input.initial_policy_window.release_events = vec![PolicyReleaseEventV3 {
            request_digest: migrated_core.request_digest,
            released_at_unix_seconds: 1_700_000_000,
            debit_atoms: 720,
        }];
        input.released_records.push(ValidatedV2ReleasedRecordV3 {
            core: migrated_core.clone(),
            source_prepared_generation: 8,
            source_record_digest: marker(26),
            terminal: TerminalDecisionV3 {
                scope: DecisionScopeV3::ValidatedV2Migration,
                action: WithdrawalActionV3::Release,
                decision_id: marker(27),
                approval_digest: marker(28),
                policy_id: input.policy_id,
                action_anchor: input.source_current_anchor,
                request_digest: migrated_core.request_digest,
                transaction_signing_digest: migrated_core.signing_digest,
                decided_at_unix_seconds: 1_700_000_000,
                accounted_at_unix_seconds: 1_700_000_000,
            },
            txid: marker(29),
            exact_transaction_bytes: vec![5, 6, 7],
            debit_atoms: 720,
        });
        let state = migrate_validated_v2(input, &JOURNAL_KEY).unwrap().journal;

        let canceled_core = core("native-cancel", 90, 91);
        let state = add_intent(&state, canceled_core.clone());
        let terminal = terminal(
            &state,
            &canceled_core,
            WithdrawalActionV3::Cancel,
            100,
            1_700_000_100,
        );
        let state = state
            .apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::Cancel(CancelWithdrawalV3 {
                    expected_anchor: terminal.action_anchor,
                    request_id: canceled_core.request_id.clone(),
                    request_digest: canceled_core.request_digest,
                    terminal,
                }),
            )
            .unwrap();
        let source = state.anchor(&JOURNAL_KEY).unwrap();
        let item = state
            .archive_prune_record(&JOURNAL_KEY, &canceled_core.request_id, 0)
            .unwrap();
        let compacted = state
            .apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::Compact(CompactTerminalRecordsV3 {
                    expected_anchor: source,
                    archive_source_anchor: source,
                    archive_id: marker(110),
                    records: vec![item],
                }),
            )
            .unwrap();
        assert!(compacted.records.contains_key(&migrated_core.request_id));
        assert!(
            compacted
                .tombstones
                .values()
                .all(|tombstone| tombstone.phase == TerminalPhaseV3::Canceled)
        );

        let mut removed = compacted.clone();
        removed.records.remove(&migrated_core.request_id);
        removed.policy_window.release_events.clear();
        assert!(matches!(
            removed.validate(&JOURNAL_KEY),
            Err(ExchangeWithdrawalV3Error::InvalidState(
                "migration receipt record count does not match live legacy records"
            ))
        ));

        let mut changed = compacted;
        changed
            .records
            .get_mut(&migrated_core.request_id)
            .unwrap()
            .origin = RecordOriginV3::NativeV3;
        assert!(matches!(
            changed.validate(&JOURNAL_KEY),
            Err(ExchangeWithdrawalV3Error::InvalidState(_))
        ));
    }

    #[test]
    fn injected_released_tombstone_is_rejected() {
        let mut state = initial();
        let tag = marker(120);
        state.tombstones.insert(
            tag,
            ArchiveTombstoneV3 {
                request_id_tag: tag,
                request_digest: marker(121),
                phase: TerminalPhaseV3::Released,
                terminal_decision_id: marker(122),
                approval_digest: marker(123),
                archive_id: marker(124),
                record_index: 0,
                txid: Some(marker(125)),
                debit_atoms: 720,
                record_payload_digest: marker(126),
            },
        );
        assert!(matches!(
            state.validate(&JOURNAL_KEY),
            Err(ExchangeWithdrawalV3Error::InvalidState(
                "archive tombstone is invalid or duplicated"
            ))
        ));
    }

    #[test]
    fn tampering_wrong_key_and_trailing_bytes_are_rejected() {
        let state = released_state();
        let encoded = state.encode_authenticated(&JOURNAL_KEY).unwrap();
        let mut tampered = encoded.clone();
        tampered[HEADER_BYTES + 12] ^= 1;
        assert_eq!(
            ExchangeWithdrawalJournalV3::decode_authenticated(&tampered, &JOURNAL_KEY),
            Err(ExchangeWithdrawalV3Error::AuthenticationFailed)
        );
        assert_eq!(
            ExchangeWithdrawalJournalV3::decode_authenticated(&encoded, &[0xA6; 32]),
            Err(ExchangeWithdrawalV3Error::AuthenticationFailed)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            ExchangeWithdrawalJournalV3::decode_authenticated(&trailing, &JOURNAL_KEY),
            Err(ExchangeWithdrawalV3Error::InvalidSnapshotLength)
        );
    }

    #[test]
    fn in_memory_exact_payload_tampering_fails_validation() {
        let mut state = released_state();
        let WithdrawalPhaseV3::Released(released) =
            &mut state.records.get_mut("wd-001").unwrap().phase
        else {
            panic!("expected Released")
        };
        released.exact_transaction.bytes[0] ^= 1;
        assert!(matches!(
            state.validate(&JOURNAL_KEY),
            Err(ExchangeWithdrawalV3Error::InvalidState(_))
        ));
    }

    #[test]
    fn keyring_rotation_requires_quiescence_and_preserves_old_package_binding() {
        let core = core("wd-keyring", 35, 45);
        let pending = add_intent(&initial(), core);
        assert!(matches!(
            pending.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::RotateKeyring(RotateKeyringV3 {
                    expected_anchor: pending.anchor(&JOURNAL_KEY).unwrap(),
                    new_keyring: keyring(2, 13),
                    rotation_decision_id: marker(82),
                    approval_digest: marker(83),
                })
            ),
            Err(ExchangeWithdrawalV3Error::InvalidTransition(_))
        ));
        let state = released_state();
        let old_keyring = state.active_keyring;
        let state = state
            .apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::RotateKeyring(RotateKeyringV3 {
                    expected_anchor: state.anchor(&JOURNAL_KEY).unwrap(),
                    new_keyring: keyring(2, 13),
                    rotation_decision_id: marker(84),
                    approval_digest: marker(85),
                }),
            )
            .unwrap();
        assert_eq!(state.prior_keyrings[0].anchor, old_keyring);
        state.validate(&JOURNAL_KEY).unwrap();
    }

    #[test]
    fn duplicate_request_digest_and_outpoint_are_rejected() {
        let first_core = core("wd-first", 36, 46);
        let state = add_intent(&initial(), first_core.clone());
        let mut duplicate_digest = core("wd-second", 37, 47);
        duplicate_digest.request_digest = first_core.request_digest;
        assert_eq!(
            state.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::AddIntent(AddIntentV3 {
                    expected_anchor: state.anchor(&JOURNAL_KEY).unwrap(),
                    core: duplicate_digest,
                })
            ),
            Err(ExchangeWithdrawalV3Error::DuplicateRequest)
        );
        let mut duplicate_outpoint = core("wd-third", 38, 48);
        duplicate_outpoint.reservations[0].outpoint = first_core.reservations[0].outpoint;
        assert!(matches!(
            state.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::AddIntent(AddIntentV3 {
                    expected_anchor: state.anchor(&JOURNAL_KEY).unwrap(),
                    core: duplicate_outpoint,
                })
            ),
            Err(ExchangeWithdrawalV3Error::InvalidState(_))
        ));
    }

    #[test]
    fn canceled_outpoint_is_reusable_but_released_outpoint_remains_reserved() {
        let canceled = canceled_state();
        let replacement = core("wd-after-cancel", 90, 40);
        let reused = add_intent(&canceled, replacement.clone());
        assert_eq!(
            reused.records["wd-after-cancel"].core.reservations[0].outpoint,
            canceled.records["wd-001"].core.reservations[0].outpoint
        );
        reused.validate(&JOURNAL_KEY).unwrap();

        let released = released_state();
        assert!(matches!(
            released.apply_transition(
                &JOURNAL_KEY,
                JournalTransitionV3::AddIntent(AddIntentV3 {
                    expected_anchor: released.anchor(&JOURNAL_KEY).unwrap(),
                    core: replacement,
                })
            ),
            Err(ExchangeWithdrawalV3Error::InvalidState(
                "reserved input is duplicated"
            ))
        ));
    }

    fn hex(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(TABLE[usize::from(byte >> 4)] as char);
            output.push(TABLE[usize::from(byte & 0x0f)] as char);
        }
        output
    }
}
