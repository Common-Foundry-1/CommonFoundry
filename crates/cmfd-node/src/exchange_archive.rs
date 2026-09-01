//! Canonical authenticated archive envelopes for withdrawal-journal v3.
//!
//! Archives are pure values: this module performs no file I/O and never prunes
//! journal state. A caller first builds an envelope from exact canonical bytes
//! read from a live v3 source, durably stores both the authenticated envelope
//! and its external manifest pin, then revalidates source membership to obtain
//! `ArchivePruneRecordV3` values for one atomic `Compact` transition.
//!
//! The first operational profile accepts only Canceled withdrawals. Released
//! transactions remain live until an explicit confirmation/finality policy is
//! defined and enforced by the runtime.

use std::collections::HashSet;

use blake3::Hasher;
use thiserror::Error;

use super::exchange_withdrawal_v3::{
    ArchivePruneRecordV3, ExchangeWithdrawalJournalV3, JournalAnchorV3, WithdrawalPhaseV3,
};

const ARCHIVE_MAGIC: [u8; 8] = *b"CMFDARC\0";
const PIN_MAGIC: [u8; 8] = *b"CMFDAPN\0";
const ARCHIVE_VERSION: u32 = 3;
const HEADER_BYTES: usize = 8 + 4 + 8;
const AUTH_TAG_BYTES: usize = 32;
const PIN_BYTES: usize = 8 + 4 + 32 + 32 + 8 + 32 + 32 + 8 + 32 + 32;

const REQUEST_TAG_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-ARCHIVE/REQUEST-TAG/V1";
const RECORD_LEAF_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-ARCHIVE/RECORD/V1";
const RECORD_CHAIN_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-ARCHIVE/CHAIN/V1";
const ARCHIVE_ID_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-ARCHIVE/ID/V1";
const RECORD_PAYLOAD_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-ARCHIVE/PAYLOAD/V1";
const ARCHIVE_AUTH_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-ARCHIVE/AUTH/V3";
const JOURNAL_KEY_ID_DOMAIN: &str = "CMFD/NODE/EXCHANGE-WITHDRAWAL-KEY-ID/V3";

const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_ARCHIVE_RECORDS: usize = 65_536;
// A canceled Prepared record may contain a 2 MiB signer package plus its
// bounded reservation set and metadata.
const MAX_ARCHIVE_RECORD_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchivedTerminalPhase {
    Released,
    Canceled,
}

impl ArchivedTerminalPhase {
    fn code(self) -> u8 {
        match self {
            Self::Released => 1,
            Self::Canceled => 2,
        }
    }

    fn decode(code: u8) -> Result<Self, ExchangeArchiveError> {
        match code {
            1 => Ok(Self::Released),
            2 => Ok(Self::Canceled),
            _ => Err(ExchangeArchiveError::NonCanonical),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArchiveSource {
    pub key_id: [u8; 32],
    pub journal_instance_id: [u8; 32],
    pub generation: u64,
    pub commitment: [u8; 32],
    pub policy_id: [u8; 32],
}

impl ArchiveSource {
    fn from_journal(anchor: JournalAnchorV3, policy_id: [u8; 32]) -> Self {
        Self {
            key_id: anchor.key_id,
            journal_instance_id: anchor.journal_instance_id,
            generation: anchor.generation,
            commitment: anchor.commitment,
            policy_id,
        }
    }

    fn journal_anchor(self) -> JournalAnchorV3 {
        JournalAnchorV3 {
            key_id: self.key_id,
            journal_instance_id: self.journal_instance_id,
            generation: self.generation,
            commitment: self.commitment,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchivedTerminalRecord {
    pub request_id: String,
    pub request_id_tag: [u8; 32],
    pub request_digest: [u8; 32],
    pub phase: ArchivedTerminalPhase,
    pub terminal_decision_id: [u8; 32],
    pub approval_digest: [u8; 32],
    pub debit_atoms: u64,
    pub txid: Option<[u8; 32]>,
    pub record_payload_digest: [u8; 32],
    /// Exact bytes returned by `ExchangeWithdrawalJournalV3::canonical_record_bytes`.
    pub canonical_record_payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WithdrawalArchiveManifest {
    pub source: ArchiveSource,
    pub record_count: u64,
    pub records_root: [u8; 32],
    pub archive_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WithdrawalArchiveEnvelopeV3 {
    pub manifest: WithdrawalArchiveManifest,
    records: Vec<ArchivedTerminalRecord>,
}

impl WithdrawalArchiveEnvelopeV3 {
    pub(crate) fn records(&self) -> &[ArchivedTerminalRecord] {
        &self.records
    }

    pub(crate) fn encode_authenticated(
        &self,
        journal_key: &[u8; 32],
    ) -> Result<Vec<u8>, ExchangeArchiveError> {
        validate_envelope(self, journal_key)?;
        let payload = encode_payload(self)?;
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| ExchangeArchiveError::Capacity)?;
        let total = HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|value| value.checked_add(AUTH_TAG_BYTES))
            .ok_or(ExchangeArchiveError::PayloadTooLarge)?;
        if total > MAX_ARCHIVE_BYTES {
            return Err(ExchangeArchiveError::PayloadTooLarge);
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&ARCHIVE_MAGIC);
        bytes.extend_from_slice(&ARCHIVE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&payload);
        let authentication_tag = keyed_digest(journal_key, ARCHIVE_AUTH_DOMAIN, &bytes);
        bytes.extend_from_slice(&authentication_tag);
        Ok(bytes)
    }

    pub(crate) fn decode_authenticated(
        bytes: &[u8],
        journal_key: &[u8; 32],
        expected_source: JournalAnchorV3,
    ) -> Result<Self, ExchangeArchiveError> {
        validate_key(journal_key)?;
        if bytes.len() > MAX_ARCHIVE_BYTES {
            return Err(ExchangeArchiveError::PayloadTooLarge);
        }
        if bytes.len() < HEADER_BYTES + AUTH_TAG_BYTES {
            return Err(ExchangeArchiveError::Truncated);
        }
        if bytes[..8] != ARCHIVE_MAGIC {
            return Err(ExchangeArchiveError::InvalidEnvelope);
        }
        if u32::from_le_bytes(bytes[8..12].try_into().expect("fixed slice")) != ARCHIVE_VERSION {
            return Err(ExchangeArchiveError::UnsupportedVersion);
        }
        let payload_len = u64::from_le_bytes(bytes[12..20].try_into().expect("fixed slice"));
        let payload_len =
            usize::try_from(payload_len).map_err(|_| ExchangeArchiveError::Capacity)?;
        let expected_len = HEADER_BYTES
            .checked_add(payload_len)
            .and_then(|value| value.checked_add(AUTH_TAG_BYTES))
            .ok_or(ExchangeArchiveError::PayloadTooLarge)?;
        if expected_len != bytes.len() {
            return Err(ExchangeArchiveError::InvalidEnvelope);
        }
        let tag_offset = bytes.len() - AUTH_TAG_BYTES;
        let expected_tag = keyed_digest(journal_key, ARCHIVE_AUTH_DOMAIN, &bytes[..tag_offset]);
        if !constant_time_equal(&expected_tag, &bytes[tag_offset..]) {
            return Err(ExchangeArchiveError::AuthenticationFailed);
        }
        let mut decoder = Decoder::new(&bytes[HEADER_BYTES..tag_offset]);
        let envelope = decode_payload(&mut decoder)?;
        if !decoder.is_empty() {
            return Err(ExchangeArchiveError::NonCanonical);
        }
        if envelope.manifest.source.journal_anchor() != expected_source {
            return Err(ExchangeArchiveError::SourceMismatch);
        }
        validate_envelope(&envelope, journal_key)?;
        if envelope.encode_authenticated(journal_key)? != bytes {
            return Err(ExchangeArchiveError::NonCanonical);
        }
        Ok(envelope)
    }

    pub(crate) fn manifest_pin(&self) -> WithdrawalArchiveManifestPinV3 {
        WithdrawalArchiveManifestPinV3 {
            manifest: self.manifest,
        }
    }

    /// Rechecks every exact record against the still-live source and returns
    /// the only values accepted by the v3 Compact transition. Call this after
    /// the authenticated archive and external pin are durably stored.
    pub(crate) fn verify_source_membership_and_prepare_prune(
        &self,
        journal: &ExchangeWithdrawalJournalV3,
        journal_key: &[u8; 32],
        expected_source: JournalAnchorV3,
    ) -> Result<Vec<ArchivePruneRecordV3>, ExchangeArchiveError> {
        validate_envelope(self, journal_key)?;
        let actual_source = journal
            .anchor(journal_key)
            .map_err(|_| ExchangeArchiveError::SourceMismatch)?;
        if expected_source != actual_source
            || self.manifest.source.journal_anchor() != expected_source
            || self.manifest.source.policy_id != journal.policy_id
        {
            return Err(ExchangeArchiveError::SourceMismatch);
        }
        let mut prune_records = Vec::with_capacity(self.records.len());
        for (index, archived) in self.records.iter().enumerate() {
            let live = journal
                .records
                .get(&archived.request_id)
                .ok_or(ExchangeArchiveError::MembershipMismatch)?;
            let WithdrawalPhaseV3::Canceled(canceled) = &live.phase else {
                return Err(ExchangeArchiveError::ReleasedFinalityPolicyRequired);
            };
            if live.core.request_digest != archived.request_digest
                || canceled.terminal.decision_id != archived.terminal_decision_id
                || canceled.terminal.approval_digest != archived.approval_digest
                || journal
                    .canonical_record_bytes(&archived.request_id)
                    .map_err(|_| ExchangeArchiveError::MembershipMismatch)?
                    != archived.canonical_record_payload
            {
                return Err(ExchangeArchiveError::MembershipMismatch);
            }
            let record_index = u64::try_from(index).map_err(|_| ExchangeArchiveError::Capacity)?;
            let prune = journal
                .archive_prune_record(journal_key, &archived.request_id, record_index)
                .map_err(|_| ExchangeArchiveError::MembershipMismatch)?;
            if prune.record_payload_digest != archived.record_payload_digest {
                return Err(ExchangeArchiveError::MembershipMismatch);
            }
            prune_records.push(prune);
        }
        Ok(prune_records)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WithdrawalArchiveManifestPinV3 {
    pub manifest: WithdrawalArchiveManifest,
}

impl WithdrawalArchiveManifestPinV3 {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, ExchangeArchiveError> {
        validate_manifest(self.manifest)?;
        let mut bytes = Vec::with_capacity(PIN_BYTES);
        bytes.extend_from_slice(&PIN_MAGIC);
        bytes.extend_from_slice(&ARCHIVE_VERSION.to_le_bytes());
        write_manifest(&mut bytes, self.manifest);
        debug_assert_eq!(bytes.len(), PIN_BYTES);
        Ok(bytes)
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ExchangeArchiveError> {
        if bytes.len() != PIN_BYTES || bytes[..8] != PIN_MAGIC {
            return Err(ExchangeArchiveError::InvalidManifestPin);
        }
        if u32::from_le_bytes(bytes[8..12].try_into().expect("fixed slice")) != ARCHIVE_VERSION {
            return Err(ExchangeArchiveError::UnsupportedVersion);
        }
        let mut decoder = Decoder::new(&bytes[12..]);
        let manifest = read_manifest(&mut decoder)?;
        if !decoder.is_empty() {
            return Err(ExchangeArchiveError::InvalidManifestPin);
        }
        validate_manifest(manifest)?;
        let pin = Self { manifest };
        if pin.encode()? != bytes {
            return Err(ExchangeArchiveError::NonCanonical);
        }
        Ok(pin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedArchiveRestoreV3 {
    pub manifest: WithdrawalArchiveManifest,
    pub records: Vec<ArchivedTerminalRecord>,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangeArchiveError {
    #[error("archive journal key is invalid")]
    InvalidJournalKey,
    #[error("archive source is invalid")]
    InvalidSource,
    #[error("archive source does not match the independently expected journal anchor")]
    SourceMismatch,
    #[error("an archive must contain at least one terminal withdrawal record")]
    EmptyArchive,
    #[error("archive record count exceeds its configured limit")]
    TooManyRecords,
    #[error("archive payload exceeds its configured limit")]
    PayloadTooLarge,
    #[error("the archive envelope is truncated")]
    Truncated,
    #[error("the archive envelope version is unsupported")]
    UnsupportedVersion,
    #[error("the archive envelope is invalid")]
    InvalidEnvelope,
    #[error("the archive authentication tag is invalid")]
    AuthenticationFailed,
    #[error("the archive envelope is not canonically encoded")]
    NonCanonical,
    #[error("archived withdrawal record is invalid")]
    InvalidRecord,
    #[error("archived withdrawal request identifiers are not strictly ordered")]
    RequestOrder,
    #[error("archived withdrawal record is duplicated")]
    DuplicateRecord,
    #[error("released withdrawals require an explicit finality policy before archival")]
    ReleasedFinalityPolicyRequired,
    #[error("archived record no longer exactly belongs to the pinned live source")]
    MembershipMismatch,
    #[error("the external archive manifest pin is invalid")]
    InvalidManifestPin,
    #[error("archive record count exceeds its representation")]
    Capacity,
}

pub(crate) fn build_canceled_archive(
    journal: &ExchangeWithdrawalJournalV3,
    journal_key: &[u8; 32],
    expected_source: JournalAnchorV3,
    request_ids: &[String],
) -> Result<WithdrawalArchiveEnvelopeV3, ExchangeArchiveError> {
    validate_key(journal_key)?;
    let actual_source = journal
        .anchor(journal_key)
        .map_err(|_| ExchangeArchiveError::SourceMismatch)?;
    if actual_source != expected_source {
        return Err(ExchangeArchiveError::SourceMismatch);
    }
    if request_ids.is_empty() {
        return Err(ExchangeArchiveError::EmptyArchive);
    }
    if request_ids.len() > MAX_ARCHIVE_RECORDS {
        return Err(ExchangeArchiveError::TooManyRecords);
    }
    let source = ArchiveSource::from_journal(actual_source, journal.policy_id);
    let mut records = Vec::with_capacity(request_ids.len());
    let mut previous_tag = None;
    let mut seen_ids = HashSet::with_capacity(request_ids.len());
    for request_id in request_ids {
        if !seen_ids.insert(request_id) {
            return Err(ExchangeArchiveError::DuplicateRecord);
        }
        let live = journal
            .records
            .get(request_id)
            .ok_or(ExchangeArchiveError::MembershipMismatch)?;
        let WithdrawalPhaseV3::Canceled(canceled) = &live.phase else {
            return Err(ExchangeArchiveError::ReleasedFinalityPolicyRequired);
        };
        let request_id_tag = archive_request_id_tag(journal_key, request_id)?;
        if previous_tag.is_some_and(|previous| previous >= request_id_tag) {
            return Err(ExchangeArchiveError::RequestOrder);
        }
        previous_tag = Some(request_id_tag);
        let canonical_record_payload = journal
            .canonical_record_bytes(request_id)
            .map_err(|_| ExchangeArchiveError::MembershipMismatch)?;
        let record_payload_digest = keyed_digest(
            journal_key,
            RECORD_PAYLOAD_DOMAIN,
            &canonical_record_payload,
        );
        records.push(ArchivedTerminalRecord {
            request_id: request_id.clone(),
            request_id_tag,
            request_digest: live.core.request_digest,
            phase: ArchivedTerminalPhase::Canceled,
            terminal_decision_id: canceled.terminal.decision_id,
            approval_digest: canceled.terminal.approval_digest,
            debit_atoms: 0,
            txid: None,
            record_payload_digest,
            canonical_record_payload,
        });
    }
    let manifest = compute_manifest(journal_key, source, &records)?;
    let envelope = WithdrawalArchiveEnvelopeV3 { manifest, records };
    validate_envelope(&envelope, journal_key)?;
    Ok(envelope)
}

/// Authenticates an archive against an independently retained manifest pin and
/// returns exact canonical record bytes for a future explicit restore tool.
/// It does not mutate or reconstruct a live journal.
pub(crate) fn verify_archive_for_restore(
    authenticated_archive: &[u8],
    journal_key: &[u8; 32],
    manifest_pin_bytes: &[u8],
) -> Result<VerifiedArchiveRestoreV3, ExchangeArchiveError> {
    let pin = WithdrawalArchiveManifestPinV3::parse(manifest_pin_bytes)?;
    let envelope = WithdrawalArchiveEnvelopeV3::decode_authenticated(
        authenticated_archive,
        journal_key,
        pin.manifest.source.journal_anchor(),
    )?;
    if envelope.manifest != pin.manifest {
        return Err(ExchangeArchiveError::InvalidManifestPin);
    }
    Ok(VerifiedArchiveRestoreV3 {
        manifest: envelope.manifest,
        records: envelope.records,
    })
}

pub(crate) fn archive_request_id_tag(
    journal_key: &[u8; 32],
    request_id: &str,
) -> Result<[u8; 32], ExchangeArchiveError> {
    validate_key(journal_key)?;
    if request_id.is_empty()
        || request_id.len() > MAX_REQUEST_ID_BYTES
        || !request_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ExchangeArchiveError::InvalidRecord);
    }
    Ok(keyed_digest(
        journal_key,
        REQUEST_TAG_DOMAIN,
        request_id.as_bytes(),
    ))
}

fn compute_manifest(
    journal_key: &[u8; 32],
    source: ArchiveSource,
    records: &[ArchivedTerminalRecord],
) -> Result<WithdrawalArchiveManifest, ExchangeArchiveError> {
    validate_source(journal_key, source)?;
    if records.is_empty() {
        return Err(ExchangeArchiveError::EmptyArchive);
    }
    if records.len() > MAX_ARCHIVE_RECORDS {
        return Err(ExchangeArchiveError::TooManyRecords);
    }
    let mut total_payload_bytes = 0_usize;
    let mut previous_tag = None;
    let mut request_ids = HashSet::with_capacity(records.len());
    let mut request_digests = HashSet::with_capacity(records.len());
    let mut decision_ids = HashSet::with_capacity(records.len());
    let mut approval_digests = HashSet::with_capacity(records.len());
    let mut payload_digests = HashSet::with_capacity(records.len());
    let mut records_root = [0_u8; 32];
    for (index, record) in records.iter().enumerate() {
        validate_record(journal_key, record)?;
        total_payload_bytes = total_payload_bytes
            .checked_add(record.canonical_record_payload.len())
            .ok_or(ExchangeArchiveError::PayloadTooLarge)?;
        if total_payload_bytes > MAX_ARCHIVE_BYTES {
            return Err(ExchangeArchiveError::PayloadTooLarge);
        }
        if previous_tag.is_some_and(|previous| previous >= record.request_id_tag) {
            return Err(ExchangeArchiveError::RequestOrder);
        }
        previous_tag = Some(record.request_id_tag);
        if !request_ids.insert(&record.request_id)
            || !request_digests.insert(record.request_digest)
            || !decision_ids.insert(record.terminal_decision_id)
            || !approval_digests.insert(record.approval_digest)
            || !payload_digests.insert(record.record_payload_digest)
        {
            return Err(ExchangeArchiveError::DuplicateRecord);
        }
        let leaf = record_leaf(journal_key, record);
        let mut frame = Vec::with_capacity(72);
        frame.extend_from_slice(&records_root);
        frame.extend_from_slice(
            &u64::try_from(index)
                .map_err(|_| ExchangeArchiveError::Capacity)?
                .to_le_bytes(),
        );
        frame.extend_from_slice(&leaf);
        records_root = keyed_digest(journal_key, RECORD_CHAIN_DOMAIN, &frame);
    }
    let record_count = u64::try_from(records.len()).map_err(|_| ExchangeArchiveError::Capacity)?;
    let archive_id = archive_identifier(journal_key, source, record_count, records_root);
    Ok(WithdrawalArchiveManifest {
        source,
        record_count,
        records_root,
        archive_id,
    })
}

fn validate_envelope(
    envelope: &WithdrawalArchiveEnvelopeV3,
    journal_key: &[u8; 32],
) -> Result<(), ExchangeArchiveError> {
    let expected = compute_manifest(journal_key, envelope.manifest.source, &envelope.records)?;
    if expected != envelope.manifest {
        return Err(ExchangeArchiveError::InvalidEnvelope);
    }
    Ok(())
}

fn validate_manifest(manifest: WithdrawalArchiveManifest) -> Result<(), ExchangeArchiveError> {
    if manifest.source.key_id == [0; 32]
        || manifest.source.journal_instance_id == [0; 32]
        || manifest.source.generation == 0
        || manifest.source.commitment == [0; 32]
        || manifest.source.policy_id == [0; 32]
        || manifest.record_count == 0
        || usize::try_from(manifest.record_count)
            .ok()
            .is_none_or(|count| count > MAX_ARCHIVE_RECORDS)
        || manifest.records_root == [0; 32]
        || manifest.archive_id == [0; 32]
    {
        return Err(ExchangeArchiveError::InvalidManifestPin);
    }
    Ok(())
}

fn validate_source(
    journal_key: &[u8; 32],
    source: ArchiveSource,
) -> Result<(), ExchangeArchiveError> {
    validate_key(journal_key)?;
    if source.key_id != keyed_digest(journal_key, JOURNAL_KEY_ID_DOMAIN, b"journal-key-id")
        || source.journal_instance_id == [0; 32]
        || source.generation == 0
        || source.commitment == [0; 32]
        || source.policy_id == [0; 32]
    {
        return Err(ExchangeArchiveError::InvalidSource);
    }
    Ok(())
}

fn validate_record(
    journal_key: &[u8; 32],
    record: &ArchivedTerminalRecord,
) -> Result<(), ExchangeArchiveError> {
    if record.request_id_tag != archive_request_id_tag(journal_key, &record.request_id)?
        || record.request_digest == [0; 32]
        || record.terminal_decision_id == [0; 32]
        || record.approval_digest == [0; 32]
        || record.phase != ArchivedTerminalPhase::Canceled
        || record.debit_atoms != 0
        || record.txid.is_some()
        || record.canonical_record_payload.is_empty()
        || record.canonical_record_payload.len() > MAX_ARCHIVE_RECORD_PAYLOAD_BYTES
        || record.record_payload_digest
            != keyed_digest(
                journal_key,
                RECORD_PAYLOAD_DOMAIN,
                &record.canonical_record_payload,
            )
    {
        return Err(if record.phase == ArchivedTerminalPhase::Released {
            ExchangeArchiveError::ReleasedFinalityPolicyRequired
        } else {
            ExchangeArchiveError::InvalidRecord
        });
    }
    Ok(())
}

fn encode_payload(envelope: &WithdrawalArchiveEnvelopeV3) -> Result<Vec<u8>, ExchangeArchiveError> {
    let mut bytes = Vec::new();
    write_manifest(&mut bytes, envelope.manifest);
    write_count(&mut bytes, envelope.records.len())?;
    for record in &envelope.records {
        write_string(&mut bytes, &record.request_id)?;
        bytes.extend_from_slice(&record.request_id_tag);
        bytes.extend_from_slice(&record.request_digest);
        bytes.push(record.phase.code());
        bytes.extend_from_slice(&record.terminal_decision_id);
        bytes.extend_from_slice(&record.approval_digest);
        bytes.extend_from_slice(&record.debit_atoms.to_le_bytes());
        match record.txid {
            None => bytes.push(0),
            Some(txid) => {
                bytes.push(1);
                bytes.extend_from_slice(&txid);
            }
        }
        bytes.extend_from_slice(&record.record_payload_digest);
        write_blob(&mut bytes, &record.canonical_record_payload)?;
    }
    if bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(ExchangeArchiveError::PayloadTooLarge);
    }
    Ok(bytes)
}

fn decode_payload(
    decoder: &mut Decoder<'_>,
) -> Result<WithdrawalArchiveEnvelopeV3, ExchangeArchiveError> {
    let manifest = read_manifest(decoder)?;
    let count = decoder.count(MAX_ARCHIVE_RECORDS)?;
    let mut records = Vec::with_capacity(count);
    let mut previous_tag = None;
    for _ in 0..count {
        let request_id = decoder.string(MAX_REQUEST_ID_BYTES)?;
        let request_id_tag = decoder.array()?;
        if previous_tag.is_some_and(|previous| previous >= request_id_tag) {
            return Err(ExchangeArchiveError::RequestOrder);
        }
        previous_tag = Some(request_id_tag);
        let request_digest = decoder.array()?;
        let phase = ArchivedTerminalPhase::decode(decoder.byte()?)?;
        let terminal_decision_id = decoder.array()?;
        let approval_digest = decoder.array()?;
        let debit_atoms = decoder.u64()?;
        let txid = match decoder.byte()? {
            0 => None,
            1 => Some(decoder.array()?),
            _ => return Err(ExchangeArchiveError::NonCanonical),
        };
        let record_payload_digest = decoder.array()?;
        let canonical_record_payload = decoder.blob(MAX_ARCHIVE_RECORD_PAYLOAD_BYTES)?.to_vec();
        records.push(ArchivedTerminalRecord {
            request_id,
            request_id_tag,
            request_digest,
            phase,
            terminal_decision_id,
            approval_digest,
            debit_atoms,
            txid,
            record_payload_digest,
            canonical_record_payload,
        });
    }
    Ok(WithdrawalArchiveEnvelopeV3 { manifest, records })
}

fn write_manifest(bytes: &mut Vec<u8>, manifest: WithdrawalArchiveManifest) {
    bytes.extend_from_slice(&manifest.source.key_id);
    bytes.extend_from_slice(&manifest.source.journal_instance_id);
    bytes.extend_from_slice(&manifest.source.generation.to_le_bytes());
    bytes.extend_from_slice(&manifest.source.commitment);
    bytes.extend_from_slice(&manifest.source.policy_id);
    bytes.extend_from_slice(&manifest.record_count.to_le_bytes());
    bytes.extend_from_slice(&manifest.records_root);
    bytes.extend_from_slice(&manifest.archive_id);
}

fn read_manifest(
    decoder: &mut Decoder<'_>,
) -> Result<WithdrawalArchiveManifest, ExchangeArchiveError> {
    Ok(WithdrawalArchiveManifest {
        source: ArchiveSource {
            key_id: decoder.array()?,
            journal_instance_id: decoder.array()?,
            generation: decoder.u64()?,
            commitment: decoder.array()?,
            policy_id: decoder.array()?,
        },
        record_count: decoder.u64()?,
        records_root: decoder.array()?,
        archive_id: decoder.array()?,
    })
}

fn write_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), ExchangeArchiveError> {
    let count = u32::try_from(count).map_err(|_| ExchangeArchiveError::Capacity)?;
    bytes.extend_from_slice(&count.to_le_bytes());
    Ok(())
}

fn write_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), ExchangeArchiveError> {
    if value.is_empty()
        || value.len() > MAX_REQUEST_ID_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ExchangeArchiveError::InvalidRecord);
    }
    let length = u16::try_from(value.len()).map_err(|_| ExchangeArchiveError::Capacity)?;
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn write_blob(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), ExchangeArchiveError> {
    if value.is_empty() || value.len() > MAX_ARCHIVE_RECORD_PAYLOAD_BYTES {
        return Err(ExchangeArchiveError::PayloadTooLarge);
    }
    let length = u32::try_from(value.len()).map_err(|_| ExchangeArchiveError::Capacity)?;
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn record_leaf(journal_key: &[u8; 32], record: &ArchivedTerminalRecord) -> [u8; 32] {
    let mut frame = Vec::with_capacity(32 * 6 + 10);
    frame.extend_from_slice(&record.request_id_tag);
    frame.extend_from_slice(&record.request_digest);
    frame.push(record.phase.code());
    frame.extend_from_slice(&record.terminal_decision_id);
    frame.extend_from_slice(&record.approval_digest);
    frame.extend_from_slice(&record.debit_atoms.to_le_bytes());
    match record.txid {
        Some(txid) => {
            frame.push(1);
            frame.extend_from_slice(&txid);
        }
        None => frame.push(0),
    }
    frame.extend_from_slice(&record.record_payload_digest);
    keyed_digest(journal_key, RECORD_LEAF_DOMAIN, &frame)
}

fn archive_identifier(
    journal_key: &[u8; 32],
    source: ArchiveSource,
    record_count: u64,
    records_root: [u8; 32],
) -> [u8; 32] {
    let mut frame = Vec::with_capacity(32 * 6 + 16);
    frame.extend_from_slice(&source.key_id);
    frame.extend_from_slice(&source.journal_instance_id);
    frame.extend_from_slice(&source.generation.to_le_bytes());
    frame.extend_from_slice(&source.commitment);
    frame.extend_from_slice(&source.policy_id);
    frame.extend_from_slice(&record_count.to_le_bytes());
    frame.extend_from_slice(&records_root);
    keyed_digest(journal_key, ARCHIVE_ID_DOMAIN, &frame)
}

fn validate_key(journal_key: &[u8; 32]) -> Result<(), ExchangeArchiveError> {
    if *journal_key == [0; 32] {
        return Err(ExchangeArchiveError::InvalidJournalKey);
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], ExchangeArchiveError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ExchangeArchiveError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ExchangeArchiveError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, ExchangeArchiveError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ExchangeArchiveError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("fixed slice"),
        ))
    }

    fn u32(&mut self) -> Result<u32, ExchangeArchiveError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("fixed slice"),
        ))
    }

    fn u64(&mut self) -> Result<u64, ExchangeArchiveError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("fixed slice"),
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ExchangeArchiveError> {
        Ok(self.take(N)?.try_into().expect("fixed slice"))
    }

    fn count(&mut self, limit: usize) -> Result<usize, ExchangeArchiveError> {
        let count = usize::try_from(self.u32()?).map_err(|_| ExchangeArchiveError::Capacity)?;
        if count > limit {
            return Err(ExchangeArchiveError::TooManyRecords);
        }
        Ok(count)
    }

    fn blob(&mut self, limit: usize) -> Result<&'a [u8], ExchangeArchiveError> {
        let length = usize::try_from(self.u32()?).map_err(|_| ExchangeArchiveError::Capacity)?;
        if length == 0 || length > limit {
            return Err(ExchangeArchiveError::PayloadTooLarge);
        }
        self.take(length)
    }

    fn string(&mut self, limit: usize) -> Result<String, ExchangeArchiveError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > limit {
            return Err(ExchangeArchiveError::InvalidRecord);
        }
        let bytes = self.take(length)?;
        let value = std::str::from_utf8(bytes).map_err(|_| ExchangeArchiveError::NonCanonical)?;
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(ExchangeArchiveError::InvalidRecord);
        }
        Ok(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange_withdrawal_v3::{
        AddIntentV3, CancelWithdrawalV3, DecisionScopeV3, JournalBindingV3, JournalTransitionV3,
        KeyringAnchorV3, PolicyReleaseEventV3, PolicyWindowStateV3, ReservedInputV3,
        ReservedOutpointV3, TerminalDecisionV3, ValidatedV2MigrationInputV3,
        ValidatedV2ReleasedRecordV3, WithdrawalActionV3, WithdrawalCoreV3, migrate_validated_v2,
    };

    const KEY: [u8; 32] = [9; 32];

    fn marker(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn source_anchor() -> JournalAnchorV3 {
        JournalAnchorV3 {
            key_id: marker(1),
            journal_instance_id: marker(2),
            generation: 7,
            commitment: marker(3),
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
                consensus_fingerprint: marker(10),
                genesis: marker(11),
            },
            new_journal_instance_id: marker(12),
            policy_id: marker(13),
            initial_policy_window: PolicyWindowStateV3 {
                time_watermark_unix_seconds: 1_700_000_000,
                release_events: Vec::new(),
            },
            active_keyring: KeyringAnchorV3 {
                instance_id: marker(14),
                generation: 1,
                commitment: marker(15),
            },
            released_records: Vec::new(),
        }
    }

    fn core(request_id: &str, value: u8) -> WithdrawalCoreV3 {
        WithdrawalCoreV3 {
            request_id: request_id.to_owned(),
            request_digest: marker(value),
            destination: marker(value.wrapping_add(1)),
            amount_atoms: 700,
            fee_atoms: 20,
            change_atoms: 280,
            output_spendable_height: 55,
            signing_digest: marker(value.wrapping_add(2)),
            reservations: vec![ReservedInputV3 {
                outpoint: ReservedOutpointV3 {
                    txid: marker(value.wrapping_add(3)),
                    index: 0,
                },
                value_atoms: 1_000,
                wallet_key_id: marker(value.wrapping_add(4)),
                public_key: marker(value.wrapping_add(5)),
                signer_id: marker(value.wrapping_add(6)),
            }],
        }
    }

    fn cancel(
        state: &ExchangeWithdrawalJournalV3,
        core: WithdrawalCoreV3,
        decision_marker: u8,
    ) -> ExchangeWithdrawalJournalV3 {
        let state = state
            .apply_transition(
                &KEY,
                JournalTransitionV3::AddIntent(AddIntentV3 {
                    expected_anchor: state.anchor(&KEY).unwrap(),
                    core: core.clone(),
                }),
            )
            .unwrap();
        let action_anchor = state.anchor(&KEY).unwrap();
        state
            .apply_transition(
                &KEY,
                JournalTransitionV3::Cancel(CancelWithdrawalV3 {
                    expected_anchor: action_anchor,
                    request_id: core.request_id,
                    request_digest: core.request_digest,
                    terminal: TerminalDecisionV3 {
                        scope: DecisionScopeV3::NativeV3,
                        action: WithdrawalActionV3::Cancel,
                        decision_id: marker(decision_marker),
                        approval_digest: marker(decision_marker.wrapping_add(1)),
                        policy_id: state.policy_id,
                        action_anchor,
                        request_digest: core.request_digest,
                        transaction_signing_digest: core.signing_digest,
                        decided_at_unix_seconds: 1_700_000_010,
                        accounted_at_unix_seconds: 1_700_000_010,
                    },
                }),
            )
            .unwrap()
    }

    fn canceled_journal() -> ExchangeWithdrawalJournalV3 {
        let state = migrate_validated_v2(migration_input(), &KEY)
            .unwrap()
            .journal;
        let state = cancel(&state, core("cancel-a", 30), 60);
        cancel(&state, core("cancel-b", 40), 70)
    }

    fn ordered_ids() -> Vec<String> {
        let mut ids = vec!["cancel-a".to_owned(), "cancel-b".to_owned()];
        ids.sort_by_key(|request_id| archive_request_id_tag(&KEY, request_id).unwrap());
        ids
    }

    fn envelope() -> (ExchangeWithdrawalJournalV3, WithdrawalArchiveEnvelopeV3) {
        let journal = canceled_journal();
        let source = journal.anchor(&KEY).unwrap();
        let envelope = build_canceled_archive(&journal, &KEY, source, &ordered_ids()).unwrap();
        (journal, envelope)
    }

    #[test]
    fn authenticated_envelope_pin_membership_and_restore_round_trip() {
        let (journal, envelope) = envelope();
        let source = journal.anchor(&KEY).unwrap();
        let archive_bytes = envelope.encode_authenticated(&KEY).unwrap();
        let decoded =
            WithdrawalArchiveEnvelopeV3::decode_authenticated(&archive_bytes, &KEY, source)
                .unwrap();
        assert_eq!(decoded, envelope);
        let prune = decoded
            .verify_source_membership_and_prepare_prune(&journal, &KEY, source)
            .unwrap();
        assert_eq!(prune.len(), 2);
        for (index, item) in prune.iter().enumerate() {
            assert_eq!(item.record_index, u64::try_from(index).unwrap());
            assert_eq!(
                item.record_payload_digest,
                decoded.records[index].record_payload_digest
            );
        }

        let pin_bytes = decoded.manifest_pin().encode().unwrap();
        let parsed_pin = WithdrawalArchiveManifestPinV3::parse(&pin_bytes).unwrap();
        assert_eq!(parsed_pin.manifest, decoded.manifest);
        let restore = verify_archive_for_restore(&archive_bytes, &KEY, &pin_bytes).unwrap();
        assert_eq!(restore.manifest, decoded.manifest);
        assert_eq!(restore.records, decoded.records);
        for restored in &restore.records {
            assert_eq!(
                restored.canonical_record_payload,
                journal
                    .canonical_record_bytes(&restored.request_id)
                    .unwrap()
            );
        }
    }

    #[test]
    fn archive_tamper_wrong_key_and_wrong_source_fail_closed() {
        let (journal, envelope) = envelope();
        let source = journal.anchor(&KEY).unwrap();
        let archive_bytes = envelope.encode_authenticated(&KEY).unwrap();
        let mut tampered = archive_bytes.clone();
        tampered[HEADER_BYTES + 5] ^= 1;
        assert_eq!(
            WithdrawalArchiveEnvelopeV3::decode_authenticated(&tampered, &KEY, source),
            Err(ExchangeArchiveError::AuthenticationFailed)
        );
        assert_eq!(
            WithdrawalArchiveEnvelopeV3::decode_authenticated(&archive_bytes, &[8; 32], source),
            Err(ExchangeArchiveError::AuthenticationFailed)
        );
        let mut wrong_source = source;
        wrong_source.commitment[0] ^= 1;
        assert_eq!(
            WithdrawalArchiveEnvelopeV3::decode_authenticated(&archive_bytes, &KEY, wrong_source),
            Err(ExchangeArchiveError::SourceMismatch)
        );
    }

    #[test]
    fn duplicate_and_noncanonical_request_order_are_rejected() {
        let journal = canceled_journal();
        let source = journal.anchor(&KEY).unwrap();
        let ids = ordered_ids();
        assert_eq!(
            build_canceled_archive(&journal, &KEY, source, &[ids[0].clone(), ids[0].clone()]),
            Err(ExchangeArchiveError::DuplicateRecord)
        );
        let mut reversed = ids;
        reversed.reverse();
        assert_eq!(
            build_canceled_archive(&journal, &KEY, source, &reversed),
            Err(ExchangeArchiveError::RequestOrder)
        );
    }

    #[test]
    fn released_records_remain_blocked_without_finality_policy() {
        let mut input = migration_input();
        let released_core = core("released", 80);
        input
            .initial_policy_window
            .release_events
            .push(PolicyReleaseEventV3 {
                request_digest: released_core.request_digest,
                released_at_unix_seconds: 1_700_000_000,
                debit_atoms: 720,
            });
        input.released_records.push(ValidatedV2ReleasedRecordV3 {
            core: released_core.clone(),
            source_prepared_generation: 6,
            source_record_digest: marker(81),
            terminal: TerminalDecisionV3 {
                scope: DecisionScopeV3::ValidatedV2Migration,
                action: WithdrawalActionV3::Release,
                decision_id: marker(82),
                approval_digest: marker(83),
                policy_id: input.policy_id,
                action_anchor: input.source_current_anchor,
                request_digest: released_core.request_digest,
                transaction_signing_digest: released_core.signing_digest,
                decided_at_unix_seconds: 1_700_000_000,
                accounted_at_unix_seconds: 1_700_000_000,
            },
            txid: marker(84),
            exact_transaction_bytes: vec![1, 2, 3],
            debit_atoms: 720,
        });
        let journal = migrate_validated_v2(input, &KEY).unwrap().journal;
        let source = journal.anchor(&KEY).unwrap();
        assert_eq!(
            build_canceled_archive(&journal, &KEY, source, &["released".to_owned()]),
            Err(ExchangeArchiveError::ReleasedFinalityPolicyRequired)
        );
    }

    #[test]
    fn membership_is_revalidated_against_exact_source_and_payload() {
        let (journal, mut altered_envelope) = envelope();
        let source = journal.anchor(&KEY).unwrap();
        altered_envelope.records[0].canonical_record_payload[0] ^= 1;
        altered_envelope.records[0].record_payload_digest = keyed_digest(
            &KEY,
            RECORD_PAYLOAD_DOMAIN,
            &altered_envelope.records[0].canonical_record_payload,
        );
        altered_envelope.manifest = compute_manifest(
            &KEY,
            altered_envelope.manifest.source,
            &altered_envelope.records,
        )
        .unwrap();
        assert_eq!(
            altered_envelope.verify_source_membership_and_prepare_prune(&journal, &KEY, source),
            Err(ExchangeArchiveError::MembershipMismatch)
        );

        let (journal, envelope) = envelope();
        let source = journal.anchor(&KEY).unwrap();
        let changed = cancel(&journal, core("cancel-c", 90), 100);
        assert_eq!(
            envelope.verify_source_membership_and_prepare_prune(&changed, &KEY, source),
            Err(ExchangeArchiveError::SourceMismatch)
        );
    }

    #[test]
    fn external_manifest_pin_is_exact_and_independently_compared() {
        let (_journal, envelope) = envelope();
        let archive_bytes = envelope.encode_authenticated(&KEY).unwrap();
        let pin = envelope.manifest_pin();
        let pin_bytes = pin.encode().unwrap();
        assert_eq!(pin_bytes.len(), PIN_BYTES);
        assert_eq!(
            WithdrawalArchiveManifestPinV3::parse(&pin_bytes).unwrap(),
            pin
        );
        let mut truncated = pin_bytes.clone();
        truncated.pop();
        assert_eq!(
            WithdrawalArchiveManifestPinV3::parse(&truncated),
            Err(ExchangeArchiveError::InvalidManifestPin)
        );
        let mut wrong_pin = pin;
        wrong_pin.manifest.archive_id[0] ^= 1;
        assert_eq!(
            verify_archive_for_restore(&archive_bytes, &KEY, &wrong_pin.encode().unwrap()),
            Err(ExchangeArchiveError::InvalidManifestPin)
        );
    }
}
