//! Strict codec and verifier for the frozen Dory V3 model-generation ceremony.
//!
//! This module deliberately exposes verification and canonical encoding only.
//! It has no signing, secret-key, publication, or activation entry point.

use std::collections::BTreeSet;

use k256::schnorr::{Signature, VerifyingKey};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    ModelBankManifest,
    dory_v3_model::{CanonicalBlsDoryGtHex, ordered_dory_v3_model_commitment_root},
    dory_v3_suite::{
        DORY_V3_MODEL_IDENTITY_DOMAIN, DORY_V3_MODEL_IDENTITY_VERSION, DORY_V3_MODEL_RECORD_DOMAIN,
        DORY_V3_MODEL_RECORD_VERSION,
    },
};

pub const CEREMONY_TRANSCRIPT_MAGIC: [u8; 8] = *b"CMFDMGC1";
pub const CEREMONY_ATTESTATION_MAGIC: [u8; 8] = *b"CMFDMTA1";
pub const CEREMONY_PROTOCOL_VERSION: u16 = 1;
pub const CEREMONY_TRANSCRIPT_HEADER_BYTES: u16 = 24;
pub const MIN_CEREMONY_OPERATORS: usize = 3;
pub const MAX_CEREMONY_OPERATORS: usize = 16;
pub const MIN_CEREMONY_REPRODUCERS: usize = 2;
pub const MAX_CEREMONY_REPRODUCERS: usize = 16;
pub const MAX_CEREMONY_SIGNERS: usize = MAX_CEREMONY_OPERATORS + MAX_CEREMONY_REPRODUCERS;
pub const MAX_CEREMONY_RECORDS: usize = 2 * MAX_CEREMONY_OPERATORS + 4;
pub const MAX_CEREMONY_RECORD_BODY_BYTES: usize = 16 * 1024;
pub const MAX_CEREMONY_TRANSCRIPT_BYTES: usize = 1024 * 1024;
pub const MAX_CEREMONY_ATTESTATION_BYTES: usize =
    8 + 2 + 32 + 8 + 32 + 32 + 32 + 2 + MAX_CEREMONY_SIGNERS * (1 + 2 + 64);

pub const PRODUCTION_MODEL_VERSION: u32 = 2;
pub const PRODUCTION_BANK_FORMAT_VERSION: u32 = 2;
pub const PRODUCTION_BANK_HEADER_BYTES: u32 = 184;
pub const PRODUCTION_BATCH: u32 = 128;
pub const PRODUCTION_DIMENSION: u32 = 4096;
pub const PRODUCTION_LAYERS: u32 = 384;
pub const PRODUCTION_BANKS: u32 = 3;
pub const PRODUCTION_LAYERS_PER_BANK: u32 = 128;
pub const PRODUCTION_PADDED_VARIABLES: u32 = 33;
pub const PRODUCTION_MAX_MODEL_BYTE: u8 = 250;
pub const PRODUCTION_BASE_INPUT_BYTES: u64 = 524_288;
pub const PRODUCTION_BYTES_PER_LAYER: u64 = 16_777_216;
pub const PRODUCTION_PAYLOAD_BYTES: u64 = 6_442_975_232;
pub const PRODUCTION_BANK_BYTES: u64 = 6_442_975_416;

const RECORD_DOMAINS: [&str; 7] = [
    "CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/GENESIS/V1",
    "CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/CONTRIBUTION-COMMITMENT/V1",
    "CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/COMMITMENT-SET/V1",
    "CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/CONTRIBUTION-REVEAL/V1",
    "CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/REVEAL-SET/V1",
    "CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/FINAL-RECEIPT/V1",
    "CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/ABORT/V1",
];
const SIGNED_RECORD_DOMAIN: &str = "CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/SIGNED-RECORD/V1";
const SIGNATURE_DOMAIN: &str = "CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/SIGNATURE/V1";
const TRANSCRIPT_DOMAIN: &str = "CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/TRANSCRIPT/V1";
const TRANSCRIPT_ATTESTATION_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/MODEL-GENERATION-CEREMONY/TRANSCRIPT-ATTESTATION/V1";

const PRODUCTION_SUITE_DIGEST: [u8; 32] = [
    0x6c, 0x09, 0x50, 0xd4, 0xb5, 0xdc, 0xff, 0xef, 0x9f, 0x32, 0x96, 0xf9, 0xc0, 0x71, 0x8a, 0x8d,
    0x51, 0x24, 0x87, 0x77, 0x19, 0xb3, 0xaf, 0x76, 0xb2, 0xf6, 0x8b, 0x3f, 0xcb, 0x64, 0x76, 0x4a,
];
const DORY_SETUP_IDENTITY: [u8; 32] = [
    0x75, 0xfd, 0x3d, 0xac, 0xdd, 0xba, 0x30, 0x68, 0x2d, 0x1e, 0xab, 0xd5, 0xd8, 0xd2, 0x92, 0x44,
    0x66, 0xd7, 0x21, 0x4b, 0x01, 0x1a, 0x7e, 0xcc, 0x48, 0xba, 0x27, 0x82, 0x1c, 0xbb, 0xf6, 0x12,
];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CeremonyTranscriptError {
    #[error("truncated ceremony encoding while reading {0}")]
    Truncated(&'static str),
    #[error("invalid ceremony encoding: {0}")]
    Invalid(&'static str),
    #[error("ceremony size or count exceeds its protocol cap: {0}")]
    Limit(&'static str),
    #[error("invalid BIP340 public key")]
    InvalidPublicKey,
    #[error("malformed canonical BIP340 signature")]
    MalformedSignature,
    #[error("BIP340 signature verification failed")]
    InvalidSignature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub bytes: u64,
    pub blake3: [u8; 32],
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceBinary {
    pub target_id: u16,
    pub rustc_vv: FileIdentity,
    pub build_environment: FileIdentity,
    pub binary_blake3: [u8; 32],
    pub binary_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterMember {
    pub index: u16,
    pub public_key: [u8; 32],
    pub identity_document: FileIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisBody {
    pub ceremony_protocol_version: u16,
    pub model_version: u32,
    pub bank_format_version: u32,
    pub bank_header_bytes: u32,
    pub batch: u32,
    pub dimension: u32,
    pub layers: u32,
    pub banks: u32,
    pub layers_per_bank: u32,
    pub padded_variables: u32,
    pub max_model_byte: u8,
    pub base_input_bytes: u64,
    pub bytes_per_layer: u64,
    pub payload_bytes: u64,
    pub commit_deadline_unix_seconds: u64,
    pub reveal_deadline_unix_seconds: u64,
    pub source_commit_sha1: [u8; 20],
    pub source_bundle: FileIdentity,
    pub source_bundle_policy: FileIdentity,
    pub cargo_lock_blake3: [u8; 32],
    pub cargo_lock_sha256: [u8; 32],
    pub protocol_spec_blake3: [u8; 32],
    pub protocol_spec_sha256: [u8; 32],
    pub bulletin_policy: FileIdentity,
    pub reference_binaries: Vec<ReferenceBinary>,
    pub structural_analyzer_target_id: u16,
    pub structural_analyzer_blake3: [u8; 32],
    pub structural_analyzer_sha256: [u8; 32],
    pub production_suite_digest: [u8; 32],
    pub dory_setup_identity: [u8; 32],
    pub operators: Vec<RosterMember>,
    pub reproducers: Vec<RosterMember>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContributionCommitmentBody {
    pub ceremony_id: [u8; 32],
    pub genesis_signed_record_digest: [u8; 32],
    pub operator_index: u16,
    pub operator_public_key: [u8; 32],
    pub contribution_bytes: u64,
    pub contribution_blake3: [u8; 32],
    pub contribution_sha256: [u8; 32],
    pub source_bytes_consumed: u64,
    pub rejected_source_bytes: u64,
    pub generation_finished_unix_seconds: u64,
    pub generator_binary_blake3: [u8; 32],
    pub generator_binary_sha256: [u8; 32],
    pub entropy_attestation: FileIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedRecordDigest {
    pub index: u16,
    pub signed_record_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentSetBody {
    pub ceremony_id: [u8; 32],
    pub genesis_signed_record_digest: [u8; 32],
    pub commitments: Vec<IndexedRecordDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContributionRevealBody {
    pub ceremony_id: [u8; 32],
    pub operator_index: u16,
    pub contribution_commitment_signed_record_digest: [u8; 32],
    pub contribution_bytes: u64,
    pub contribution_blake3: [u8; 32],
    pub contribution_sha256: [u8; 32],
    pub reveal_finished_unix_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevealSetBody {
    pub ceremony_id: [u8; 32],
    pub commitment_set_signed_record_digest: [u8; 32],
    pub reveals: Vec<IndexedRecordDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReproducerReceipt {
    pub index: u16,
    pub combiner_binary_blake3: [u8; 32],
    pub combiner_binary_sha256: [u8; 32],
    pub bootstrap_report: FileIdentity,
    pub record_ceremony_report: FileIdentity,
    pub reproduction_report: FileIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalReceiptBody {
    pub ceremony_id: [u8; 32],
    pub commitment_set_signed_record_digest: [u8; 32],
    pub reveal_set_signed_record_digest: [u8; 32],
    pub payload_bytes: u64,
    pub raw_payload_blake3: [u8; 32],
    pub raw_payload_sha256: [u8; 32],
    pub base_input_blake3_root: [u8; 32],
    pub layer_roots_aggregate: [u8; 32],
    pub roots_file: FileIdentity,
    pub structural_report: FileIdentity,
    pub bank_bytes: u64,
    pub bank_file_blake3: [u8; 32],
    pub bank_file_sha256: [u8; 32],
    pub manifest_file: FileIdentity,
    pub manifest_digest: [u8; 32],
    pub production_suite_digest: [u8; 32],
    pub pcs_parameter_digest: [u8; 32],
    pub base_commitment: [u8; 576],
    pub weight_bank_0_commitment: [u8; 576],
    pub weight_bank_1_commitment: [u8; 576],
    pub weight_bank_2_commitment: [u8; 576],
    pub pcs_commitment_root: [u8; 32],
    pub model_identity_digest: [u8; 32],
    pub setup_identity: [u8; 32],
    pub padded_variables: u32,
    pub record_v2_file: FileIdentity,
    pub record_v2_digest: [u8; 32],
    pub publisher_reproducer_index: u16,
    pub reproducers: Vec<ReproducerReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbortBody {
    pub ceremony_id: [u8; 32],
    pub last_valid_signed_record_digest: [u8; 32],
    pub phase: u16,
    pub reason_code: u16,
    pub evidence_file: FileIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CeremonyRecordBody {
    Genesis(Box<GenesisBody>),
    ContributionCommitment(ContributionCommitmentBody),
    CommitmentSet(CommitmentSetBody),
    ContributionReveal(ContributionRevealBody),
    RevealSet(RevealSetBody),
    FinalReceipt(Box<FinalReceiptBody>),
    Abort(AbortBody),
}

impl CeremonyRecordBody {
    pub fn record_type(&self) -> u16 {
        match self {
            Self::Genesis(_) => 1,
            Self::ContributionCommitment(_) => 2,
            Self::CommitmentSet(_) => 3,
            Self::ContributionReveal(_) => 4,
            Self::RevealSet(_) => 5,
            Self::FinalReceipt(_) => 6,
            Self::Abort(_) => 7,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignerClass {
    Operator,
    Reproducer,
}

impl SignerClass {
    fn as_u8(self) -> u8 {
        match self {
            Self::Operator => 0,
            Self::Reproducer => 1,
        }
    }

    fn from_u8(value: u8) -> Result<Self, CeremonyTranscriptError> {
        match value {
            0 => Ok(Self::Operator),
            1 => Ok(Self::Reproducer),
            _ => Err(CeremonyTranscriptError::Invalid("reserved signer class")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSignature {
    pub signer_class: SignerClass,
    pub signer_index: u16,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCeremonyRecord {
    pub body: CeremonyRecordBody,
    pub signatures: Vec<RecordSignature>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyTranscriptStatus {
    /// Exact verified prefix through the signed type-5 closure.
    RevealSetClosed,
    Completed,
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedCombinerContributionBinding {
    operator_index: u16,
    operator_public_key: [u8; 32],
    contribution_bytes: u64,
    contribution_blake3: [u8; 32],
    contribution_sha256: [u8; 32],
    contribution_commitment_signed_record_digest: [u8; 32],
    contribution_reveal_signed_record_digest: [u8; 32],
}

// These crate-private accessors are the capability handoff to the production
// combiner; no public caller can construct or mutate the signed bindings.
#[cfg_attr(not(test), allow(dead_code))]
impl VerifiedCombinerContributionBinding {
    pub(crate) const fn operator_index(&self) -> u16 {
        self.operator_index
    }

    pub(crate) const fn operator_public_key(&self) -> [u8; 32] {
        self.operator_public_key
    }

    pub(crate) const fn contribution_bytes(&self) -> u64 {
        self.contribution_bytes
    }

    pub(crate) const fn contribution_blake3(&self) -> [u8; 32] {
        self.contribution_blake3
    }

    pub(crate) const fn contribution_sha256(&self) -> [u8; 32] {
        self.contribution_sha256
    }

    pub(crate) const fn contribution_commitment_signed_record_digest(&self) -> [u8; 32] {
        self.contribution_commitment_signed_record_digest
    }

    pub(crate) const fn contribution_reveal_signed_record_digest(&self) -> [u8; 32] {
        self.contribution_reveal_signed_record_digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedCombinerBindings {
    ceremony_id: [u8; 32],
    commitment_set_signed_record_digest: [u8; 32],
    reveal_set_signed_record_digest: [u8; 32],
    contributions: Vec<VerifiedCombinerContributionBinding>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl VerifiedCombinerBindings {
    pub(crate) const fn ceremony_id(&self) -> [u8; 32] {
        self.ceremony_id
    }

    pub(crate) const fn commitment_set_signed_record_digest(&self) -> [u8; 32] {
        self.commitment_set_signed_record_digest
    }

    pub(crate) const fn reveal_set_signed_record_digest(&self) -> [u8; 32] {
        self.reveal_set_signed_record_digest
    }

    pub(crate) fn contributions(&self) -> &[VerifiedCombinerContributionBinding] {
        &self.contributions
    }
}

/// Opaque result produced only by the strict transcript verifiers.
///
/// Private fields prevent callers from forging a status, roster, digest, or
/// combiner capability and then presenting it as parser-verified state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCeremonyTranscript {
    records: Vec<SignedCeremonyRecord>,
    status: CeremonyTranscriptStatus,
    ceremony_id: [u8; 32],
    transcript_derive_key_digest: [u8; 32],
    transcript_blake3: [u8; 32],
    transcript_sha256: [u8; 32],
    transcript_bytes: u64,
    operators: Vec<[u8; 32]>,
    reproducers: Vec<[u8; 32]>,
    combiner_bindings: Option<VerifiedCombinerBindings>,
}

impl VerifiedCeremonyTranscript {
    #[must_use]
    pub fn records(&self) -> &[SignedCeremonyRecord] {
        &self.records
    }

    #[must_use]
    pub const fn status(&self) -> CeremonyTranscriptStatus {
        self.status
    }

    #[must_use]
    pub const fn ceremony_id(&self) -> [u8; 32] {
        self.ceremony_id
    }

    #[must_use]
    pub const fn transcript_derive_key_digest(&self) -> [u8; 32] {
        self.transcript_derive_key_digest
    }

    #[must_use]
    pub const fn transcript_blake3(&self) -> [u8; 32] {
        self.transcript_blake3
    }

    #[must_use]
    pub const fn transcript_sha256(&self) -> [u8; 32] {
        self.transcript_sha256
    }

    #[must_use]
    pub const fn transcript_bytes(&self) -> u64 {
        self.transcript_bytes
    }

    #[must_use]
    pub fn operators(&self) -> &[[u8; 32]] {
        &self.operators
    }

    #[must_use]
    pub fn reproducers(&self) -> &[[u8; 32]] {
        &self.reproducers
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn require_combiner_bindings(
        &self,
    ) -> Result<&VerifiedCombinerBindings, CeremonyTranscriptError> {
        if self.status != CeremonyTranscriptStatus::RevealSetClosed {
            return Err(CeremonyTranscriptError::Invalid(
                "combiner bindings require an anchored reveal-set-closed prefix",
            ));
        }
        self.combiner_bindings
            .as_ref()
            .ok_or(CeremonyTranscriptError::Invalid(
                "missing verified combiner bindings",
            ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetachedTranscriptAttestation {
    pub ceremony_id: [u8; 32],
    pub transcript_bytes: u64,
    pub transcript_derive_key_digest: [u8; 32],
    pub transcript_blake3: [u8; 32],
    pub transcript_sha256: [u8; 32],
    pub signatures: Vec<RecordSignature>,
}

#[derive(Default)]
struct Encoder(Vec<u8>);

impl Encoder {
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], CeremonyTranscriptError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(CeremonyTranscriptError::Limit("decoder offset"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CeremonyTranscriptError::Truncated(field))?;
        self.offset = end;
        value
            .try_into()
            .map_err(|_| CeremonyTranscriptError::Truncated(field))
    }

    fn take_slice(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], CeremonyTranscriptError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CeremonyTranscriptError::Limit("decoder offset"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CeremonyTranscriptError::Truncated(field))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, CeremonyTranscriptError> {
        Ok(self.take::<1>(field)?[0])
    }
    fn u16(&mut self, field: &'static str) -> Result<u16, CeremonyTranscriptError> {
        Ok(u16::from_le_bytes(self.take(field)?))
    }
    fn u32(&mut self, field: &'static str) -> Result<u32, CeremonyTranscriptError> {
        Ok(u32::from_le_bytes(self.take(field)?))
    }
    fn u64(&mut self, field: &'static str) -> Result<u64, CeremonyTranscriptError> {
        Ok(u64::from_le_bytes(self.take(field)?))
    }
    fn finish(self) -> Result<(), CeremonyTranscriptError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CeremonyTranscriptError::Invalid("trailing bytes"))
        }
    }
}

fn encode_file_identity(encoder: &mut Encoder, value: &FileIdentity) {
    encoder.u64(value.bytes);
    encoder.bytes(&value.blake3);
    encoder.bytes(&value.sha256);
}

fn decode_file_identity(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<FileIdentity, CeremonyTranscriptError> {
    Ok(FileIdentity {
        bytes: decoder.u64(field)?,
        blake3: decoder.take(field)?,
        sha256: decoder.take(field)?,
    })
}

fn checked_u16(length: usize, field: &'static str) -> Result<u16, CeremonyTranscriptError> {
    u16::try_from(length).map_err(|_| CeremonyTranscriptError::Limit(field))
}

fn checked_u32(length: usize, field: &'static str) -> Result<u32, CeremonyTranscriptError> {
    u32::try_from(length).map_err(|_| CeremonyTranscriptError::Limit(field))
}

fn validate_indexed_digests(
    values: &[IndexedRecordDigest],
    minimum: usize,
    maximum: usize,
) -> Result<(), CeremonyTranscriptError> {
    if !(minimum..=maximum).contains(&values.len()) {
        return Err(CeremonyTranscriptError::Invalid(
            "invalid indexed digest count",
        ));
    }
    for (expected, value) in values.iter().enumerate() {
        if usize::from(value.index) != expected {
            return Err(CeremonyTranscriptError::Invalid(
                "nonconsecutive indexed digest",
            ));
        }
    }
    Ok(())
}

fn validate_genesis(value: &GenesisBody) -> Result<(), CeremonyTranscriptError> {
    if value.ceremony_protocol_version != CEREMONY_PROTOCOL_VERSION
        || value.model_version != PRODUCTION_MODEL_VERSION
        || value.bank_format_version != PRODUCTION_BANK_FORMAT_VERSION
        || value.bank_header_bytes != PRODUCTION_BANK_HEADER_BYTES
        || value.batch != PRODUCTION_BATCH
        || value.dimension != PRODUCTION_DIMENSION
        || value.layers != PRODUCTION_LAYERS
        || value.banks != PRODUCTION_BANKS
        || value.layers_per_bank != PRODUCTION_LAYERS_PER_BANK
        || value.padded_variables != PRODUCTION_PADDED_VARIABLES
        || value.max_model_byte != PRODUCTION_MAX_MODEL_BYTE
        || value.base_input_bytes != PRODUCTION_BASE_INPUT_BYTES
        || value.bytes_per_layer != PRODUCTION_BYTES_PER_LAYER
        || value.payload_bytes != PRODUCTION_PAYLOAD_BYTES
    {
        return Err(CeremonyTranscriptError::Invalid(
            "genesis production geometry",
        ));
    }
    if value.commit_deadline_unix_seconds == 0
        || value.commit_deadline_unix_seconds >= value.reveal_deadline_unix_seconds
    {
        return Err(CeremonyTranscriptError::Invalid("genesis deadlines"));
    }
    if !(1..=2).contains(&value.reference_binaries.len()) {
        return Err(CeremonyTranscriptError::Invalid("reference binary count"));
    }
    let mut previous_target = 0u16;
    for binary in &value.reference_binaries {
        if !(1..=2).contains(&binary.target_id) || binary.target_id <= previous_target {
            return Err(CeremonyTranscriptError::Invalid(
                "reference binary target order",
            ));
        }
        previous_target = binary.target_id;
    }
    if !(1..=2).contains(&value.structural_analyzer_target_id) {
        return Err(CeremonyTranscriptError::Invalid(
            "structural analyzer target",
        ));
    }
    if value.production_suite_digest != PRODUCTION_SUITE_DIGEST
        || value.dory_setup_identity != DORY_SETUP_IDENTITY
    {
        return Err(CeremonyTranscriptError::Invalid(
            "pinned production identity",
        ));
    }
    if !(MIN_CEREMONY_OPERATORS..=MAX_CEREMONY_OPERATORS).contains(&value.operators.len())
        || !(MIN_CEREMONY_REPRODUCERS..=MAX_CEREMONY_REPRODUCERS).contains(&value.reproducers.len())
    {
        return Err(CeremonyTranscriptError::Invalid("roster cardinality"));
    }
    let mut keys = BTreeSet::new();
    for (expected, member) in value
        .operators
        .iter()
        .chain(value.reproducers.iter())
        .enumerate()
    {
        let local_expected = if expected < value.operators.len() {
            expected
        } else {
            expected - value.operators.len()
        };
        if usize::from(member.index) != local_expected {
            return Err(CeremonyTranscriptError::Invalid(
                "nonconsecutive roster index",
            ));
        }
        VerifyingKey::from_bytes(&member.public_key)
            .map_err(|_| CeremonyTranscriptError::InvalidPublicKey)?;
        if !keys.insert(member.public_key) {
            return Err(CeremonyTranscriptError::Invalid("duplicate roster key"));
        }
    }
    Ok(())
}

fn validate_body(body: &CeremonyRecordBody) -> Result<(), CeremonyTranscriptError> {
    match body {
        CeremonyRecordBody::Genesis(value) => validate_genesis(value),
        CeremonyRecordBody::ContributionCommitment(value) => {
            if value.contribution_bytes != PRODUCTION_PAYLOAD_BYTES {
                return Err(CeremonyTranscriptError::Invalid(
                    "contribution commitment length",
                ));
            }
            if value.source_bytes_consumed
                != value
                    .contribution_bytes
                    .checked_add(value.rejected_source_bytes)
                    .ok_or(CeremonyTranscriptError::Invalid(
                        "source byte count overflow",
                    ))?
            {
                return Err(CeremonyTranscriptError::Invalid("source byte accounting"));
            }
            VerifyingKey::from_bytes(&value.operator_public_key)
                .map_err(|_| CeremonyTranscriptError::InvalidPublicKey)?;
            Ok(())
        }
        CeremonyRecordBody::CommitmentSet(value) => validate_indexed_digests(
            &value.commitments,
            MIN_CEREMONY_OPERATORS,
            MAX_CEREMONY_OPERATORS,
        ),
        CeremonyRecordBody::ContributionReveal(value) => {
            if value.contribution_bytes != PRODUCTION_PAYLOAD_BYTES {
                return Err(CeremonyTranscriptError::Invalid(
                    "contribution reveal length",
                ));
            }
            Ok(())
        }
        CeremonyRecordBody::RevealSet(value) => validate_indexed_digests(
            &value.reveals,
            MIN_CEREMONY_OPERATORS,
            MAX_CEREMONY_OPERATORS,
        ),
        CeremonyRecordBody::FinalReceipt(value) => {
            if value.payload_bytes != PRODUCTION_PAYLOAD_BYTES
                || value.bank_bytes != PRODUCTION_BANK_BYTES
                || value.padded_variables != PRODUCTION_PADDED_VARIABLES
                || value.publisher_reproducer_index != 0
                || value.production_suite_digest != PRODUCTION_SUITE_DIGEST
                || value.pcs_parameter_digest != PRODUCTION_SUITE_DIGEST
                || value.setup_identity != DORY_SETUP_IDENTITY
            {
                return Err(CeremonyTranscriptError::Invalid(
                    "final receipt production constants",
                ));
            }
            if !(MIN_CEREMONY_REPRODUCERS..=MAX_CEREMONY_REPRODUCERS)
                .contains(&value.reproducers.len())
            {
                return Err(CeremonyTranscriptError::Invalid(
                    "final receipt reproducer count",
                ));
            }
            for (expected, receipt) in value.reproducers.iter().enumerate() {
                if usize::from(receipt.index) != expected {
                    return Err(CeremonyTranscriptError::Invalid(
                        "nonconsecutive final receipt reproducer",
                    ));
                }
            }
            let commitments = [
                &value.base_commitment,
                &value.weight_bank_0_commitment,
                &value.weight_bank_1_commitment,
                &value.weight_bank_2_commitment,
            ];
            for left in 0..commitments.len() {
                for right in left + 1..commitments.len() {
                    if commitments[left] == commitments[right] {
                        return Err(CeremonyTranscriptError::Invalid(
                            "duplicate final receipt commitment",
                        ));
                    }
                }
            }
            validate_final_receipt_derivations(value)?;
            Ok(())
        }
        CeremonyRecordBody::Abort(value) => {
            // The phase is signed incident metadata. A failed operation need
            // not have emitted a valid record, so its phase cannot be inferred
            // from the retained valid transcript prefix.
            if !(1..=8).contains(&value.phase)
                || !(1..=12).contains(&value.reason_code)
                || value.ceremony_id == [0; 32]
                || value.last_valid_signed_record_digest == [0; 32]
            {
                return Err(CeremonyTranscriptError::Invalid("abort fields"));
            }
            Ok(())
        }
    }
}

fn parse_canonical_commitment(
    bytes: &[u8; 576],
) -> Result<CanonicalBlsDoryGtHex, CeremonyTranscriptError> {
    CanonicalBlsDoryGtHex::from_hex(&hex::encode(bytes))
        .map_err(|_| CeremonyTranscriptError::Invalid("canonical Dory commitment"))
}

struct DerivedFinalReceiptFields {
    commitment_root: [u8; 32],
    manifest_digest: [u8; 32],
    model_identity_digest: [u8; 32],
    record_v2_digest: [u8; 32],
}

fn derive_final_receipt_fields(
    value: &FinalReceiptBody,
) -> Result<DerivedFinalReceiptFields, CeremonyTranscriptError> {
    let base = parse_canonical_commitment(&value.base_commitment)?;
    let weights = vec![
        parse_canonical_commitment(&value.weight_bank_0_commitment)?,
        parse_canonical_commitment(&value.weight_bank_1_commitment)?,
        parse_canonical_commitment(&value.weight_bank_2_commitment)?,
    ];
    let commitment_root = ordered_dory_v3_model_commitment_root(
        DORY_V3_MODEL_IDENTITY_VERSION,
        value.production_suite_digest,
        value.setup_identity,
        value.padded_variables,
        &base,
        &weights,
    )
    .map_err(|_| CeremonyTranscriptError::Invalid("Dory commitment root"))?;
    let manifest = ModelBankManifest {
        model_version: PRODUCTION_MODEL_VERSION,
        dimension: PRODUCTION_DIMENSION,
        batch: PRODUCTION_BATCH,
        layers: PRODUCTION_LAYERS,
        base_input_bytes: PRODUCTION_BASE_INPUT_BYTES,
        bytes_per_layer: PRODUCTION_BYTES_PER_LAYER,
        payload_bytes: PRODUCTION_PAYLOAD_BYTES,
        raw_blake3_root: value.raw_payload_blake3,
        layer_roots_aggregate: value.layer_roots_aggregate,
        pcs_parameter_digest: value.pcs_parameter_digest,
        pcs_commitment_root: commitment_root,
    };
    let manifest_digest = manifest
        .digest()
        .map_err(|_| CeremonyTranscriptError::Invalid("model manifest digest"))?;

    let mut identity = Encoder::default();
    identity.u16(DORY_V3_MODEL_IDENTITY_VERSION);
    identity.bytes(&value.production_suite_digest);
    identity.u32(PRODUCTION_MODEL_VERSION);
    identity.u32(PRODUCTION_BATCH);
    identity.u32(PRODUCTION_DIMENSION);
    identity.u32(PRODUCTION_LAYERS_PER_BANK);
    identity.u32(PRODUCTION_BANKS);
    identity.bytes(&value.raw_payload_blake3);
    identity.bytes(&value.layer_roots_aggregate);
    identity.bytes(&value.setup_identity);
    identity.u32(value.padded_variables);
    identity.bytes(&commitment_root);
    let model_identity_digest = blake3_derive(DORY_V3_MODEL_IDENTITY_DOMAIN, &identity.0);

    let mut canonical_record = Encoder::default();
    canonical_record.u16(DORY_V3_MODEL_RECORD_VERSION);
    canonical_record.bytes(&value.production_suite_digest);
    canonical_record.bytes(&manifest_digest);
    canonical_record.bytes(&model_identity_digest);
    canonical_record.bytes(&value.setup_identity);
    canonical_record.u32(value.padded_variables);
    canonical_record.bytes(&commitment_root);
    if canonical_record.0.len() != 166 {
        return Err(CeremonyTranscriptError::Invalid(
            "canonical Record V2 length",
        ));
    }
    let record_v2_digest = blake3_derive(DORY_V3_MODEL_RECORD_DOMAIN, &canonical_record.0);
    Ok(DerivedFinalReceiptFields {
        commitment_root,
        manifest_digest,
        model_identity_digest,
        record_v2_digest,
    })
}

fn validate_final_receipt_derivations(
    value: &FinalReceiptBody,
) -> Result<(), CeremonyTranscriptError> {
    let derived = derive_final_receipt_fields(value)?;
    if value.pcs_commitment_root != derived.commitment_root
        || value.manifest_digest != derived.manifest_digest
        || value.model_identity_digest != derived.model_identity_digest
        || value.record_v2_digest != derived.record_v2_digest
    {
        return Err(CeremonyTranscriptError::Invalid(
            "final receipt derived identity",
        ));
    }
    Ok(())
}

fn encode_genesis(
    encoder: &mut Encoder,
    value: &GenesisBody,
) -> Result<(), CeremonyTranscriptError> {
    encoder.u16(value.ceremony_protocol_version);
    encoder.u32(value.model_version);
    encoder.u32(value.bank_format_version);
    encoder.u32(value.bank_header_bytes);
    encoder.u32(value.batch);
    encoder.u32(value.dimension);
    encoder.u32(value.layers);
    encoder.u32(value.banks);
    encoder.u32(value.layers_per_bank);
    encoder.u32(value.padded_variables);
    encoder.u8(value.max_model_byte);
    encoder.u64(value.base_input_bytes);
    encoder.u64(value.bytes_per_layer);
    encoder.u64(value.payload_bytes);
    encoder.u64(value.commit_deadline_unix_seconds);
    encoder.u64(value.reveal_deadline_unix_seconds);
    encoder.bytes(&value.source_commit_sha1);
    encode_file_identity(encoder, &value.source_bundle);
    encode_file_identity(encoder, &value.source_bundle_policy);
    encoder.bytes(&value.cargo_lock_blake3);
    encoder.bytes(&value.cargo_lock_sha256);
    encoder.bytes(&value.protocol_spec_blake3);
    encoder.bytes(&value.protocol_spec_sha256);
    encode_file_identity(encoder, &value.bulletin_policy);
    encoder.u16(checked_u16(
        value.reference_binaries.len(),
        "reference binary count",
    )?);
    for binary in &value.reference_binaries {
        encoder.u16(binary.target_id);
        encode_file_identity(encoder, &binary.rustc_vv);
        encode_file_identity(encoder, &binary.build_environment);
        encoder.bytes(&binary.binary_blake3);
        encoder.bytes(&binary.binary_sha256);
    }
    encoder.u16(value.structural_analyzer_target_id);
    encoder.bytes(&value.structural_analyzer_blake3);
    encoder.bytes(&value.structural_analyzer_sha256);
    encoder.bytes(&value.production_suite_digest);
    encoder.bytes(&value.dory_setup_identity);
    encoder.u16(checked_u16(value.operators.len(), "operator count")?);
    for member in &value.operators {
        encode_roster_member(encoder, member);
    }
    encoder.u16(checked_u16(value.reproducers.len(), "reproducer count")?);
    for member in &value.reproducers {
        encode_roster_member(encoder, member);
    }
    Ok(())
}

fn encode_roster_member(encoder: &mut Encoder, value: &RosterMember) {
    encoder.u16(value.index);
    encoder.bytes(&value.public_key);
    encode_file_identity(encoder, &value.identity_document);
}

fn decode_roster_member(
    decoder: &mut Decoder<'_>,
) -> Result<RosterMember, CeremonyTranscriptError> {
    Ok(RosterMember {
        index: decoder.u16("roster index")?,
        public_key: decoder.take("roster public key")?,
        identity_document: decode_file_identity(decoder, "identity document")?,
    })
}

fn decode_genesis(decoder: &mut Decoder<'_>) -> Result<GenesisBody, CeremonyTranscriptError> {
    let ceremony_protocol_version = decoder.u16("ceremony protocol version")?;
    let model_version = decoder.u32("model version")?;
    let bank_format_version = decoder.u32("bank format version")?;
    let bank_header_bytes = decoder.u32("bank header bytes")?;
    let batch = decoder.u32("batch")?;
    let dimension = decoder.u32("dimension")?;
    let layers = decoder.u32("layers")?;
    let banks = decoder.u32("banks")?;
    let layers_per_bank = decoder.u32("layers per bank")?;
    let padded_variables = decoder.u32("padded variables")?;
    let max_model_byte = decoder.u8("maximum model byte")?;
    let base_input_bytes = decoder.u64("base input bytes")?;
    let bytes_per_layer = decoder.u64("bytes per layer")?;
    let payload_bytes = decoder.u64("payload bytes")?;
    let commit_deadline_unix_seconds = decoder.u64("commit deadline")?;
    let reveal_deadline_unix_seconds = decoder.u64("reveal deadline")?;
    let source_commit_sha1 = decoder.take("source commit sha1")?;
    let source_bundle = decode_file_identity(decoder, "source bundle")?;
    let source_bundle_policy = decode_file_identity(decoder, "source bundle policy")?;
    let cargo_lock_blake3 = decoder.take("cargo lock blake3")?;
    let cargo_lock_sha256 = decoder.take("cargo lock sha256")?;
    let protocol_spec_blake3 = decoder.take("protocol spec blake3")?;
    let protocol_spec_sha256 = decoder.take("protocol spec sha256")?;
    let bulletin_policy = decode_file_identity(decoder, "bulletin policy")?;
    let reference_binary_count = usize::from(decoder.u16("reference binary count")?);
    if !(1..=2).contains(&reference_binary_count) {
        return Err(CeremonyTranscriptError::Invalid("reference binary count"));
    }
    let mut reference_binaries = Vec::with_capacity(reference_binary_count);
    for _ in 0..reference_binary_count {
        reference_binaries.push(ReferenceBinary {
            target_id: decoder.u16("reference target")?,
            rustc_vv: decode_file_identity(decoder, "rustc version file")?,
            build_environment: decode_file_identity(decoder, "build environment file")?,
            binary_blake3: decoder.take("reference binary blake3")?,
            binary_sha256: decoder.take("reference binary sha256")?,
        });
    }
    let structural_analyzer_target_id = decoder.u16("structural analyzer target")?;
    let structural_analyzer_blake3 = decoder.take("structural analyzer blake3")?;
    let structural_analyzer_sha256 = decoder.take("structural analyzer sha256")?;
    let production_suite_digest = decoder.take("production suite digest")?;
    let dory_setup_identity = decoder.take("dory setup identity")?;
    let operator_count = usize::from(decoder.u16("operator count")?);
    if !(MIN_CEREMONY_OPERATORS..=MAX_CEREMONY_OPERATORS).contains(&operator_count) {
        return Err(CeremonyTranscriptError::Invalid("operator count"));
    }
    let mut operators = Vec::with_capacity(operator_count);
    for _ in 0..operator_count {
        operators.push(decode_roster_member(decoder)?);
    }
    let reproducer_count = usize::from(decoder.u16("reproducer count")?);
    if !(MIN_CEREMONY_REPRODUCERS..=MAX_CEREMONY_REPRODUCERS).contains(&reproducer_count) {
        return Err(CeremonyTranscriptError::Invalid("reproducer count"));
    }
    let mut reproducers = Vec::with_capacity(reproducer_count);
    for _ in 0..reproducer_count {
        reproducers.push(decode_roster_member(decoder)?);
    }
    Ok(GenesisBody {
        ceremony_protocol_version,
        model_version,
        bank_format_version,
        bank_header_bytes,
        batch,
        dimension,
        layers,
        banks,
        layers_per_bank,
        padded_variables,
        max_model_byte,
        base_input_bytes,
        bytes_per_layer,
        payload_bytes,
        commit_deadline_unix_seconds,
        reveal_deadline_unix_seconds,
        source_commit_sha1,
        source_bundle,
        source_bundle_policy,
        cargo_lock_blake3,
        cargo_lock_sha256,
        protocol_spec_blake3,
        protocol_spec_sha256,
        bulletin_policy,
        reference_binaries,
        structural_analyzer_target_id,
        structural_analyzer_blake3,
        structural_analyzer_sha256,
        production_suite_digest,
        dory_setup_identity,
        operators,
        reproducers,
    })
}

fn encode_indexed_digests(
    encoder: &mut Encoder,
    values: &[IndexedRecordDigest],
) -> Result<(), CeremonyTranscriptError> {
    encoder.u16(checked_u16(values.len(), "indexed digest count")?);
    for value in values {
        encoder.u16(value.index);
        encoder.bytes(&value.signed_record_digest);
    }
    Ok(())
}

fn decode_indexed_digests(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<IndexedRecordDigest>, CeremonyTranscriptError> {
    let count = usize::from(decoder.u16("indexed digest count")?);
    if !(MIN_CEREMONY_OPERATORS..=MAX_CEREMONY_OPERATORS).contains(&count) {
        return Err(CeremonyTranscriptError::Invalid("indexed digest count"));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(IndexedRecordDigest {
            index: decoder.u16("indexed digest index")?,
            signed_record_digest: decoder.take("indexed signed record digest")?,
        });
    }
    Ok(values)
}

fn encode_reproducer_receipt(encoder: &mut Encoder, value: &ReproducerReceipt) {
    encoder.u16(value.index);
    encoder.bytes(&value.combiner_binary_blake3);
    encoder.bytes(&value.combiner_binary_sha256);
    encode_file_identity(encoder, &value.bootstrap_report);
    encode_file_identity(encoder, &value.record_ceremony_report);
    encode_file_identity(encoder, &value.reproduction_report);
}

fn decode_reproducer_receipt(
    decoder: &mut Decoder<'_>,
) -> Result<ReproducerReceipt, CeremonyTranscriptError> {
    Ok(ReproducerReceipt {
        index: decoder.u16("reproducer receipt index")?,
        combiner_binary_blake3: decoder.take("combiner binary blake3")?,
        combiner_binary_sha256: decoder.take("combiner binary sha256")?,
        bootstrap_report: decode_file_identity(decoder, "bootstrap report")?,
        record_ceremony_report: decode_file_identity(decoder, "record ceremony report")?,
        reproduction_report: decode_file_identity(decoder, "reproduction report")?,
    })
}

fn encode_body(body: &CeremonyRecordBody) -> Result<Vec<u8>, CeremonyTranscriptError> {
    validate_body(body)?;
    let mut encoder = Encoder::default();
    match body {
        CeremonyRecordBody::Genesis(value) => encode_genesis(&mut encoder, value)?,
        CeremonyRecordBody::ContributionCommitment(value) => {
            encoder.bytes(&value.ceremony_id);
            encoder.bytes(&value.genesis_signed_record_digest);
            encoder.u16(value.operator_index);
            encoder.bytes(&value.operator_public_key);
            encoder.u64(value.contribution_bytes);
            encoder.bytes(&value.contribution_blake3);
            encoder.bytes(&value.contribution_sha256);
            encoder.u64(value.source_bytes_consumed);
            encoder.u64(value.rejected_source_bytes);
            encoder.u64(value.generation_finished_unix_seconds);
            encoder.bytes(&value.generator_binary_blake3);
            encoder.bytes(&value.generator_binary_sha256);
            encode_file_identity(&mut encoder, &value.entropy_attestation);
        }
        CeremonyRecordBody::CommitmentSet(value) => {
            encoder.bytes(&value.ceremony_id);
            encoder.bytes(&value.genesis_signed_record_digest);
            encode_indexed_digests(&mut encoder, &value.commitments)?;
        }
        CeremonyRecordBody::ContributionReveal(value) => {
            encoder.bytes(&value.ceremony_id);
            encoder.u16(value.operator_index);
            encoder.bytes(&value.contribution_commitment_signed_record_digest);
            encoder.u64(value.contribution_bytes);
            encoder.bytes(&value.contribution_blake3);
            encoder.bytes(&value.contribution_sha256);
            encoder.u64(value.reveal_finished_unix_seconds);
        }
        CeremonyRecordBody::RevealSet(value) => {
            encoder.bytes(&value.ceremony_id);
            encoder.bytes(&value.commitment_set_signed_record_digest);
            encode_indexed_digests(&mut encoder, &value.reveals)?;
        }
        CeremonyRecordBody::FinalReceipt(value) => {
            encoder.bytes(&value.ceremony_id);
            encoder.bytes(&value.commitment_set_signed_record_digest);
            encoder.bytes(&value.reveal_set_signed_record_digest);
            encoder.u64(value.payload_bytes);
            encoder.bytes(&value.raw_payload_blake3);
            encoder.bytes(&value.raw_payload_sha256);
            encoder.bytes(&value.base_input_blake3_root);
            encoder.bytes(&value.layer_roots_aggregate);
            encode_file_identity(&mut encoder, &value.roots_file);
            encode_file_identity(&mut encoder, &value.structural_report);
            encoder.u64(value.bank_bytes);
            encoder.bytes(&value.bank_file_blake3);
            encoder.bytes(&value.bank_file_sha256);
            encode_file_identity(&mut encoder, &value.manifest_file);
            encoder.bytes(&value.manifest_digest);
            encoder.bytes(&value.production_suite_digest);
            encoder.bytes(&value.pcs_parameter_digest);
            encoder.bytes(&value.base_commitment);
            encoder.bytes(&value.weight_bank_0_commitment);
            encoder.bytes(&value.weight_bank_1_commitment);
            encoder.bytes(&value.weight_bank_2_commitment);
            encoder.bytes(&value.pcs_commitment_root);
            encoder.bytes(&value.model_identity_digest);
            encoder.bytes(&value.setup_identity);
            encoder.u32(value.padded_variables);
            encode_file_identity(&mut encoder, &value.record_v2_file);
            encoder.bytes(&value.record_v2_digest);
            encoder.u16(value.publisher_reproducer_index);
            encoder.u16(checked_u16(
                value.reproducers.len(),
                "final receipt reproducer count",
            )?);
            for receipt in &value.reproducers {
                encode_reproducer_receipt(&mut encoder, receipt);
            }
        }
        CeremonyRecordBody::Abort(value) => {
            encoder.bytes(&value.ceremony_id);
            encoder.bytes(&value.last_valid_signed_record_digest);
            encoder.u16(value.phase);
            encoder.u16(value.reason_code);
            encode_file_identity(&mut encoder, &value.evidence_file);
        }
    }
    if encoder.0.len() > MAX_CEREMONY_RECORD_BODY_BYTES {
        return Err(CeremonyTranscriptError::Limit("record body bytes"));
    }
    Ok(encoder.0)
}

fn decode_body(
    record_type: u16,
    bytes: &[u8],
) -> Result<CeremonyRecordBody, CeremonyTranscriptError> {
    if bytes.len() > MAX_CEREMONY_RECORD_BODY_BYTES {
        return Err(CeremonyTranscriptError::Limit("record body bytes"));
    }
    let mut decoder = Decoder::new(bytes);
    let body = match record_type {
        1 => CeremonyRecordBody::Genesis(Box::new(decode_genesis(&mut decoder)?)),
        2 => CeremonyRecordBody::ContributionCommitment(ContributionCommitmentBody {
            ceremony_id: decoder.take("ceremony id")?,
            genesis_signed_record_digest: decoder.take("genesis signed record digest")?,
            operator_index: decoder.u16("operator index")?,
            operator_public_key: decoder.take("operator public key")?,
            contribution_bytes: decoder.u64("contribution bytes")?,
            contribution_blake3: decoder.take("contribution blake3")?,
            contribution_sha256: decoder.take("contribution sha256")?,
            source_bytes_consumed: decoder.u64("source bytes consumed")?,
            rejected_source_bytes: decoder.u64("rejected source bytes")?,
            generation_finished_unix_seconds: decoder.u64("generation finished")?,
            generator_binary_blake3: decoder.take("generator binary blake3")?,
            generator_binary_sha256: decoder.take("generator binary sha256")?,
            entropy_attestation: decode_file_identity(&mut decoder, "entropy attestation")?,
        }),
        3 => CeremonyRecordBody::CommitmentSet(CommitmentSetBody {
            ceremony_id: decoder.take("ceremony id")?,
            genesis_signed_record_digest: decoder.take("genesis signed record digest")?,
            commitments: decode_indexed_digests(&mut decoder)?,
        }),
        4 => CeremonyRecordBody::ContributionReveal(ContributionRevealBody {
            ceremony_id: decoder.take("ceremony id")?,
            operator_index: decoder.u16("operator index")?,
            contribution_commitment_signed_record_digest: decoder
                .take("contribution commitment signed record digest")?,
            contribution_bytes: decoder.u64("contribution bytes")?,
            contribution_blake3: decoder.take("contribution blake3")?,
            contribution_sha256: decoder.take("contribution sha256")?,
            reveal_finished_unix_seconds: decoder.u64("reveal finished")?,
        }),
        5 => CeremonyRecordBody::RevealSet(RevealSetBody {
            ceremony_id: decoder.take("ceremony id")?,
            commitment_set_signed_record_digest: decoder
                .take("commitment set signed record digest")?,
            reveals: decode_indexed_digests(&mut decoder)?,
        }),
        6 => CeremonyRecordBody::FinalReceipt(Box::new(FinalReceiptBody {
            ceremony_id: decoder.take("ceremony id")?,
            commitment_set_signed_record_digest: decoder
                .take("commitment set signed record digest")?,
            reveal_set_signed_record_digest: decoder.take("reveal set signed record digest")?,
            payload_bytes: decoder.u64("payload bytes")?,
            raw_payload_blake3: decoder.take("raw payload blake3")?,
            raw_payload_sha256: decoder.take("raw payload sha256")?,
            base_input_blake3_root: decoder.take("base input root")?,
            layer_roots_aggregate: decoder.take("layer roots aggregate")?,
            roots_file: decode_file_identity(&mut decoder, "roots file")?,
            structural_report: decode_file_identity(&mut decoder, "structural report")?,
            bank_bytes: decoder.u64("bank bytes")?,
            bank_file_blake3: decoder.take("bank blake3")?,
            bank_file_sha256: decoder.take("bank sha256")?,
            manifest_file: decode_file_identity(&mut decoder, "manifest file")?,
            manifest_digest: decoder.take("manifest digest")?,
            production_suite_digest: decoder.take("production suite digest")?,
            pcs_parameter_digest: decoder.take("pcs parameter digest")?,
            base_commitment: decoder.take("base commitment")?,
            weight_bank_0_commitment: decoder.take("weight bank 0 commitment")?,
            weight_bank_1_commitment: decoder.take("weight bank 1 commitment")?,
            weight_bank_2_commitment: decoder.take("weight bank 2 commitment")?,
            pcs_commitment_root: decoder.take("pcs commitment root")?,
            model_identity_digest: decoder.take("model identity digest")?,
            setup_identity: decoder.take("setup identity")?,
            padded_variables: decoder.u32("padded variables")?,
            record_v2_file: decode_file_identity(&mut decoder, "record v2 file")?,
            record_v2_digest: decoder.take("record v2 digest")?,
            publisher_reproducer_index: decoder.u16("publisher reproducer index")?,
            reproducers: {
                let count = usize::from(decoder.u16("final receipt reproducer count")?);
                if !(MIN_CEREMONY_REPRODUCERS..=MAX_CEREMONY_REPRODUCERS).contains(&count) {
                    return Err(CeremonyTranscriptError::Invalid(
                        "final receipt reproducer count",
                    ));
                }
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(decode_reproducer_receipt(&mut decoder)?);
                }
                values
            },
        })),
        7 => CeremonyRecordBody::Abort(AbortBody {
            ceremony_id: decoder.take("ceremony id")?,
            last_valid_signed_record_digest: decoder.take("last valid signed record digest")?,
            phase: decoder.u16("abort phase")?,
            reason_code: decoder.u16("abort reason")?,
            evidence_file: decode_file_identity(&mut decoder, "abort evidence")?,
        }),
        _ => return Err(CeremonyTranscriptError::Invalid("unknown record type")),
    };
    decoder.finish()?;
    validate_body(&body)?;
    Ok(body)
}

fn validate_signature_order(signatures: &[RecordSignature]) -> Result<(), CeremonyTranscriptError> {
    if signatures.len() > MAX_CEREMONY_SIGNERS {
        return Err(CeremonyTranscriptError::Limit("signature count"));
    }
    let mut previous = None;
    for signature in signatures {
        let key = (signature.signer_class, signature.signer_index);
        if previous.is_some_and(|value| value >= key) {
            return Err(CeremonyTranscriptError::Invalid(
                "duplicate or out-of-order signer entry",
            ));
        }
        Signature::try_from(signature.signature.as_slice())
            .map_err(|_| CeremonyTranscriptError::MalformedSignature)?;
        previous = Some(key);
    }
    Ok(())
}

fn append_signature(encoder: &mut Encoder, signature: &RecordSignature) {
    encoder.u8(signature.signer_class.as_u8());
    encoder.u16(signature.signer_index);
    encoder.bytes(&signature.signature);
}

fn decode_signatures(
    decoder: &mut Decoder<'_>,
    count: usize,
) -> Result<Vec<RecordSignature>, CeremonyTranscriptError> {
    if count > MAX_CEREMONY_SIGNERS {
        return Err(CeremonyTranscriptError::Limit("signature count"));
    }
    let mut signatures = Vec::with_capacity(count);
    for _ in 0..count {
        signatures.push(RecordSignature {
            signer_class: SignerClass::from_u8(decoder.u8("signer class")?)?,
            signer_index: decoder.u16("signer index")?,
            signature: decoder.take("BIP340 signature")?,
        });
    }
    validate_signature_order(&signatures)?;
    Ok(signatures)
}

pub fn encode_ceremony_record(
    record: &SignedCeremonyRecord,
) -> Result<Vec<u8>, CeremonyTranscriptError> {
    validate_signature_order(&record.signatures)?;
    let body = encode_body(&record.body)?;
    let mut encoder = Encoder::default();
    encoder.u16(record.body.record_type());
    encoder.u16(CEREMONY_PROTOCOL_VERSION);
    encoder.u32(checked_u32(body.len(), "record body bytes")?);
    encoder.bytes(&body);
    encoder.u16(checked_u16(record.signatures.len(), "signature count")?);
    for signature in &record.signatures {
        append_signature(&mut encoder, signature);
    }
    Ok(encoder.0)
}

fn decode_ceremony_record_from(
    decoder: &mut Decoder<'_>,
) -> Result<SignedCeremonyRecord, CeremonyTranscriptError> {
    let record_type = decoder.u16("record type")?;
    if !(1..=7).contains(&record_type) {
        return Err(CeremonyTranscriptError::Invalid("unknown record type"));
    }
    if decoder.u16("record version")? != CEREMONY_PROTOCOL_VERSION {
        return Err(CeremonyTranscriptError::Invalid("record version"));
    }
    let body_bytes = usize::try_from(decoder.u32("record body bytes")?)
        .map_err(|_| CeremonyTranscriptError::Limit("record body bytes"))?;
    if body_bytes > MAX_CEREMONY_RECORD_BODY_BYTES {
        return Err(CeremonyTranscriptError::Limit("record body bytes"));
    }
    let body = decode_body(record_type, decoder.take_slice(body_bytes, "record body")?)?;
    let signature_count = usize::from(decoder.u16("signature count")?);
    let signatures = decode_signatures(decoder, signature_count)?;
    Ok(SignedCeremonyRecord { body, signatures })
}

pub fn decode_ceremony_record(
    bytes: &[u8],
) -> Result<SignedCeremonyRecord, CeremonyTranscriptError> {
    let mut decoder = Decoder::new(bytes);
    let record = decode_ceremony_record_from(&mut decoder)?;
    decoder.finish()?;
    Ok(record)
}

fn blake3_derive(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

pub fn ceremony_record_content_digest(
    body: &CeremonyRecordBody,
) -> Result<[u8; 32], CeremonyTranscriptError> {
    let body_bytes = encode_body(body)?;
    let record_type = body.record_type();
    let domain = RECORD_DOMAINS
        .get(usize::from(record_type - 1))
        .ok_or(CeremonyTranscriptError::Invalid("unknown record type"))?;
    let mut encoded = Encoder::default();
    encoded.u16(record_type);
    encoded.u16(CEREMONY_PROTOCOL_VERSION);
    encoded.u32(checked_u32(body_bytes.len(), "record body bytes")?);
    encoded.bytes(&body_bytes);
    Ok(blake3_derive(domain, &encoded.0))
}

pub fn ceremony_record_signature_message(
    body: &CeremonyRecordBody,
) -> Result<[u8; 32], CeremonyTranscriptError> {
    let body_bytes = encode_body(body)?;
    let content_digest = ceremony_record_content_digest(body)?;
    let mut encoded = Encoder::default();
    encoded.u16(body.record_type());
    encoded.u16(CEREMONY_PROTOCOL_VERSION);
    encoded.u32(checked_u32(body_bytes.len(), "record body bytes")?);
    encoded.bytes(&content_digest);
    Ok(blake3_derive(SIGNATURE_DOMAIN, &encoded.0))
}

pub fn ceremony_signed_record_digest(
    record: &SignedCeremonyRecord,
) -> Result<[u8; 32], CeremonyTranscriptError> {
    Ok(blake3_derive(
        SIGNED_RECORD_DOMAIN,
        &encode_ceremony_record(record)?,
    ))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn ordinary_blake3(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

struct Roster<'a> {
    operators: &'a [RosterMember],
    reproducers: &'a [RosterMember],
}

impl Roster<'_> {
    fn public_key(
        &self,
        class: SignerClass,
        index: u16,
    ) -> Result<&[u8; 32], CeremonyTranscriptError> {
        let roster = match class {
            SignerClass::Operator => self.operators,
            SignerClass::Reproducer => self.reproducers,
        };
        roster
            .get(usize::from(index))
            .filter(|member| member.index == index)
            .map(|member| &member.public_key)
            .ok_or(CeremonyTranscriptError::Invalid(
                "signer outside frozen roster",
            ))
    }
}

fn verify_bip340(
    public_key: &[u8; 32],
    message: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> Result<(), CeremonyTranscriptError> {
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| CeremonyTranscriptError::InvalidPublicKey)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| CeremonyTranscriptError::MalformedSignature)?;
    key.verify_raw(message, &signature)
        .map_err(|_| CeremonyTranscriptError::InvalidSignature)
}

fn expected_all_signers(roster: &Roster<'_>) -> Vec<(SignerClass, u16)> {
    roster
        .operators
        .iter()
        .map(|member| (SignerClass::Operator, member.index))
        .chain(
            roster
                .reproducers
                .iter()
                .map(|member| (SignerClass::Reproducer, member.index)),
        )
        .collect()
}

fn expected_operator_signers(roster: &Roster<'_>) -> Vec<(SignerClass, u16)> {
    roster
        .operators
        .iter()
        .map(|member| (SignerClass::Operator, member.index))
        .collect()
}

fn signature_slots(signatures: &[RecordSignature]) -> Vec<(SignerClass, u16)> {
    signatures
        .iter()
        .map(|value| (value.signer_class, value.signer_index))
        .collect()
}

fn verify_record_signatures(
    record: &SignedCeremonyRecord,
    roster: &Roster<'_>,
) -> Result<(), CeremonyTranscriptError> {
    let expected = match &record.body {
        CeremonyRecordBody::Genesis(_) | CeremonyRecordBody::FinalReceipt(_) => {
            expected_all_signers(roster)
        }
        CeremonyRecordBody::ContributionCommitment(value) => {
            vec![(SignerClass::Operator, value.operator_index)]
        }
        CeremonyRecordBody::CommitmentSet(_) | CeremonyRecordBody::RevealSet(_) => {
            expected_operator_signers(roster)
        }
        CeremonyRecordBody::ContributionReveal(value) => {
            vec![(SignerClass::Operator, value.operator_index)]
        }
        CeremonyRecordBody::Abort(_) => {
            if record.signatures.is_empty() {
                return Err(CeremonyTranscriptError::Invalid(
                    "abort signature cardinality",
                ));
            }
            signature_slots(&record.signatures)
        }
    };
    if signature_slots(&record.signatures) != expected {
        return Err(CeremonyTranscriptError::Invalid(
            "record signer cardinality or order",
        ));
    }
    let message = ceremony_record_signature_message(&record.body)?;
    for signature in &record.signatures {
        verify_bip340(
            roster.public_key(signature.signer_class, signature.signer_index)?,
            &message,
            &signature.signature,
        )?;
    }
    Ok(())
}

fn encode_transcript_records(
    records: &[SignedCeremonyRecord],
) -> Result<Vec<u8>, CeremonyTranscriptError> {
    if !(2..=MAX_CEREMONY_RECORDS).contains(&records.len()) {
        return Err(CeremonyTranscriptError::Invalid("transcript record count"));
    }
    let mut framed = Vec::with_capacity(records.len());
    let mut total = usize::from(CEREMONY_TRANSCRIPT_HEADER_BYTES);
    for record in records {
        let bytes = encode_ceremony_record(record)?;
        total = total
            .checked_add(bytes.len())
            .ok_or(CeremonyTranscriptError::Limit("transcript bytes"))?;
        if total > MAX_CEREMONY_TRANSCRIPT_BYTES {
            return Err(CeremonyTranscriptError::Limit("transcript bytes"));
        }
        framed.push(bytes);
    }
    let mut encoder = Encoder::default();
    encoder.bytes(&CEREMONY_TRANSCRIPT_MAGIC);
    encoder.u16(CEREMONY_PROTOCOL_VERSION);
    encoder.u16(CEREMONY_TRANSCRIPT_HEADER_BYTES);
    encoder.u32(checked_u32(records.len(), "transcript record count")?);
    encoder
        .u64(u64::try_from(total).map_err(|_| CeremonyTranscriptError::Limit("transcript bytes"))?);
    for bytes in framed {
        encoder.bytes(&bytes);
    }
    Ok(encoder.0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SequenceState {
    Commitments(usize),
    CommitmentClosure,
    Reveals(usize),
    RevealClosure,
    FinalReceipt,
    Completed,
    Aborted,
}

#[derive(Clone, Copy)]
enum RequiredTerminal {
    CompletedOrAborted,
    RevealSetClosed,
}

struct ValidatedSequence {
    status: CeremonyTranscriptStatus,
    ceremony_id: [u8; 32],
    combiner_bindings: Option<VerifiedCombinerBindings>,
}

fn validate_record_references_and_sequence(
    records: &[SignedCeremonyRecord],
    required_terminal: RequiredTerminal,
) -> Result<ValidatedSequence, CeremonyTranscriptError> {
    let Some(SignedCeremonyRecord {
        body: CeremonyRecordBody::Genesis(genesis),
        ..
    }) = records.first()
    else {
        return Err(CeremonyTranscriptError::Invalid(
            "transcript must begin with genesis",
        ));
    };
    validate_genesis(genesis)?;
    let roster = Roster {
        operators: &genesis.operators,
        reproducers: &genesis.reproducers,
    };
    verify_record_signatures(&records[0], &roster)?;
    let ceremony_id = ceremony_record_content_digest(&records[0].body)?;
    let genesis_signed_digest = ceremony_signed_record_digest(&records[0])?;
    let operator_count = genesis.operators.len();
    let reproducer_count = genesis.reproducers.len();
    let mut commitment_records = Vec::with_capacity(operator_count);
    let mut commitment_digests = Vec::with_capacity(operator_count);
    let mut reveal_digests = Vec::with_capacity(operator_count);
    let mut commitment_set_digest = None;
    let mut reveal_set_digest = None;
    let mut previous_digest = genesis_signed_digest;
    let mut state = SequenceState::Commitments(0);

    for record in &records[1..] {
        verify_record_signatures(record, &roster)?;
        match (&state, &record.body) {
            (
                SequenceState::Commitments(expected),
                CeremonyRecordBody::ContributionCommitment(body),
            ) => {
                if body.ceremony_id != ceremony_id
                    || body.genesis_signed_record_digest != genesis_signed_digest
                    || usize::from(body.operator_index) != *expected
                    || genesis.operators[*expected].public_key != body.operator_public_key
                {
                    return Err(CeremonyTranscriptError::Invalid(
                        "contribution commitment sequence or reference",
                    ));
                }
                commitment_records.push(body.clone());
                commitment_digests.push(ceremony_signed_record_digest(record)?);
                state = if *expected + 1 == operator_count {
                    SequenceState::CommitmentClosure
                } else {
                    SequenceState::Commitments(*expected + 1)
                };
            }
            (SequenceState::CommitmentClosure, CeremonyRecordBody::CommitmentSet(body)) => {
                if body.ceremony_id != ceremony_id
                    || body.genesis_signed_record_digest != genesis_signed_digest
                    || body.commitments.len() != operator_count
                    || body
                        .commitments
                        .iter()
                        .zip(&commitment_digests)
                        .any(|(entry, digest)| entry.signed_record_digest != *digest)
                {
                    return Err(CeremonyTranscriptError::Invalid(
                        "commitment set sequence or reference",
                    ));
                }
                let digest = ceremony_signed_record_digest(record)?;
                commitment_set_digest = Some(digest);
                state = SequenceState::Reveals(0);
            }
            (SequenceState::Reveals(expected), CeremonyRecordBody::ContributionReveal(body)) => {
                let commitment =
                    commitment_records
                        .get(*expected)
                        .ok_or(CeremonyTranscriptError::Invalid(
                            "missing commitment reference",
                        ))?;
                if body.ceremony_id != ceremony_id
                    || usize::from(body.operator_index) != *expected
                    || body.contribution_commitment_signed_record_digest
                        != commitment_digests[*expected]
                    || body.contribution_bytes != commitment.contribution_bytes
                    || body.contribution_blake3 != commitment.contribution_blake3
                    || body.contribution_sha256 != commitment.contribution_sha256
                {
                    return Err(CeremonyTranscriptError::Invalid(
                        "contribution reveal sequence or reference",
                    ));
                }
                reveal_digests.push(ceremony_signed_record_digest(record)?);
                state = if *expected + 1 == operator_count {
                    SequenceState::RevealClosure
                } else {
                    SequenceState::Reveals(*expected + 1)
                };
            }
            (SequenceState::RevealClosure, CeremonyRecordBody::RevealSet(body)) => {
                if body.ceremony_id != ceremony_id
                    || Some(body.commitment_set_signed_record_digest) != commitment_set_digest
                    || body.reveals.len() != operator_count
                    || body
                        .reveals
                        .iter()
                        .zip(&reveal_digests)
                        .any(|(entry, digest)| entry.signed_record_digest != *digest)
                {
                    return Err(CeremonyTranscriptError::Invalid(
                        "reveal set sequence or reference",
                    ));
                }
                reveal_set_digest = Some(ceremony_signed_record_digest(record)?);
                state = SequenceState::FinalReceipt;
            }
            (SequenceState::FinalReceipt, CeremonyRecordBody::FinalReceipt(body)) => {
                if body.ceremony_id != ceremony_id
                    || Some(body.commitment_set_signed_record_digest) != commitment_set_digest
                    || Some(body.reveal_set_signed_record_digest) != reveal_set_digest
                    || body.reproducers.len() != reproducer_count
                {
                    return Err(CeremonyTranscriptError::Invalid(
                        "final receipt sequence or reference",
                    ));
                }
                state = SequenceState::Completed;
            }
            (
                SequenceState::Commitments(_)
                | SequenceState::CommitmentClosure
                | SequenceState::Reveals(_)
                | SequenceState::RevealClosure
                | SequenceState::FinalReceipt,
                CeremonyRecordBody::Abort(body),
            ) => {
                if body.ceremony_id != ceremony_id
                    || body.last_valid_signed_record_digest != previous_digest
                {
                    return Err(CeremonyTranscriptError::Invalid(
                        "abort sequence or reference",
                    ));
                }
                state = SequenceState::Aborted;
            }
            _ => {
                return Err(CeremonyTranscriptError::Invalid(
                    "record type outside required sequence",
                ));
            }
        }
        previous_digest = ceremony_signed_record_digest(record)?;
    }
    let status = match (required_terminal, state) {
        (RequiredTerminal::CompletedOrAborted, SequenceState::Completed) => {
            CeremonyTranscriptStatus::Completed
        }
        (RequiredTerminal::CompletedOrAborted, SequenceState::Aborted) => {
            CeremonyTranscriptStatus::Aborted
        }
        (RequiredTerminal::RevealSetClosed, SequenceState::FinalReceipt) => {
            CeremonyTranscriptStatus::RevealSetClosed
        }
        (RequiredTerminal::RevealSetClosed, _) => {
            return Err(CeremonyTranscriptError::Invalid(
                "transcript is not an exact reveal-set-closed prefix",
            ));
        }
        (RequiredTerminal::CompletedOrAborted, _) => {
            return Err(CeremonyTranscriptError::Invalid(
                "incomplete transcript without abort",
            ));
        }
    };
    let combiner_bindings = if status == CeremonyTranscriptStatus::RevealSetClosed {
        let commitment_set_signed_record_digest = commitment_set_digest.ok_or(
            CeremonyTranscriptError::Invalid("missing commitment-set closure digest"),
        )?;
        let reveal_set_signed_record_digest = reveal_set_digest.ok_or(
            CeremonyTranscriptError::Invalid("missing reveal-set closure digest"),
        )?;
        if commitment_records.len() != operator_count
            || commitment_digests.len() != operator_count
            || reveal_digests.len() != operator_count
        {
            return Err(CeremonyTranscriptError::Invalid(
                "incomplete verified combiner bindings",
            ));
        }
        let contributions = commitment_records
            .into_iter()
            .zip(commitment_digests)
            .zip(reveal_digests)
            .map(
                |((commitment, commitment_signed_record_digest), reveal_signed_record_digest)| {
                    VerifiedCombinerContributionBinding {
                        operator_index: commitment.operator_index,
                        operator_public_key: commitment.operator_public_key,
                        contribution_bytes: commitment.contribution_bytes,
                        contribution_blake3: commitment.contribution_blake3,
                        contribution_sha256: commitment.contribution_sha256,
                        contribution_commitment_signed_record_digest:
                            commitment_signed_record_digest,
                        contribution_reveal_signed_record_digest: reveal_signed_record_digest,
                    }
                },
            )
            .collect();
        Some(VerifiedCombinerBindings {
            ceremony_id,
            commitment_set_signed_record_digest,
            reveal_set_signed_record_digest,
            contributions,
        })
    } else {
        None
    };
    Ok(ValidatedSequence {
        status,
        ceremony_id,
        combiner_bindings,
    })
}

pub fn encode_and_verify_ceremony_transcript(
    records: &[SignedCeremonyRecord],
) -> Result<Vec<u8>, CeremonyTranscriptError> {
    validate_record_references_and_sequence(records, RequiredTerminal::CompletedOrAborted)?;
    encode_transcript_records(records)
}

/// Canonically encode the exact signed prefix ending at the type-5 reveal-set
/// closure and verify it against an independently authenticated ceremony ID.
///
/// The resulting bytes are reparsed through
/// [`parse_and_verify_reveal_set_prefix`], which remains the only path that
/// constructs the opaque combiner bindings. This encoder returns bytes only.
pub fn encode_and_verify_reveal_set_prefix(
    records: &[SignedCeremonyRecord],
    expected_ceremony_id: [u8; 32],
) -> Result<Vec<u8>, CeremonyTranscriptError> {
    let bytes = encode_transcript_records(records)?;
    let _verified = parse_and_verify_reveal_set_prefix(&bytes, expected_ceremony_id)?;
    Ok(bytes)
}

/// Parse the authoritative bytes, verify every signature and reference, and
/// require a complete or explicitly aborted sequence.
///
/// This generic inspection path is not anchored to an independently trusted
/// ceremony identifier and therefore never returns a combiner capability.
/// Combination must use [`parse_and_verify_reveal_set_prefix`] instead.
///
/// This verifies the transcript itself and the internally derivable final
/// receipt fields. It does not open the external contribution, report, bank,
/// manifest, or Record V2 files, and it cannot prove bulletin timing or the
/// absence of private leakage. Ceremony acceptance must perform those separate
/// checks before treating a completed receipt as true.
pub fn parse_and_verify_ceremony_transcript(
    bytes: &[u8],
) -> Result<VerifiedCeremonyTranscript, CeremonyTranscriptError> {
    parse_and_verify_ceremony_transcript_with_terminal(bytes, RequiredTerminal::CompletedOrAborted)
}

/// Verify the exact signed prefix ending immediately after the type-5
/// reveal-set closure, before combination or any type-6 final receipt.
///
/// `expected_ceremony_id` must come from an independently authenticated and
/// mirrored genesis record. Deriving it from `bytes` and passing it back would
/// remove the organizer-intent trust anchor required by the production
/// combiner path.
pub fn parse_and_verify_reveal_set_prefix(
    bytes: &[u8],
    expected_ceremony_id: [u8; 32],
) -> Result<VerifiedCeremonyTranscript, CeremonyTranscriptError> {
    let transcript = parse_and_verify_ceremony_transcript_with_terminal(
        bytes,
        RequiredTerminal::RevealSetClosed,
    )?;
    if transcript.ceremony_id != expected_ceremony_id {
        return Err(CeremonyTranscriptError::Invalid(
            "reveal-set prefix ceremony id does not match trusted anchor",
        ));
    }
    Ok(transcript)
}

fn parse_and_verify_ceremony_transcript_with_terminal(
    bytes: &[u8],
    required_terminal: RequiredTerminal,
) -> Result<VerifiedCeremonyTranscript, CeremonyTranscriptError> {
    if bytes.len() > MAX_CEREMONY_TRANSCRIPT_BYTES {
        return Err(CeremonyTranscriptError::Limit("transcript bytes"));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take::<8>("transcript magic")? != CEREMONY_TRANSCRIPT_MAGIC {
        return Err(CeremonyTranscriptError::Invalid("transcript magic"));
    }
    if decoder.u16("transcript version")? != CEREMONY_PROTOCOL_VERSION {
        return Err(CeremonyTranscriptError::Invalid("transcript version"));
    }
    if decoder.u16("transcript header bytes")? != CEREMONY_TRANSCRIPT_HEADER_BYTES {
        return Err(CeremonyTranscriptError::Invalid("transcript header bytes"));
    }
    let record_count = usize::try_from(decoder.u32("transcript record count")?)
        .map_err(|_| CeremonyTranscriptError::Limit("transcript record count"))?;
    if !(2..=MAX_CEREMONY_RECORDS).contains(&record_count) {
        return Err(CeremonyTranscriptError::Invalid("transcript record count"));
    }
    let total_file_bytes = usize::try_from(decoder.u64("total transcript bytes")?)
        .map_err(|_| CeremonyTranscriptError::Limit("transcript bytes"))?;
    if total_file_bytes != bytes.len()
        || total_file_bytes < usize::from(CEREMONY_TRANSCRIPT_HEADER_BYTES)
        || total_file_bytes > MAX_CEREMONY_TRANSCRIPT_BYTES
    {
        return Err(CeremonyTranscriptError::Invalid("total transcript bytes"));
    }
    let mut records = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        records.push(decode_ceremony_record_from(&mut decoder)?);
    }
    decoder.finish()?;
    let validated = validate_record_references_and_sequence(&records, required_terminal)?;
    let CeremonyRecordBody::Genesis(genesis) = &records[0].body else {
        return Err(CeremonyTranscriptError::Invalid("missing genesis"));
    };
    let operators = genesis
        .operators
        .iter()
        .map(|member| member.public_key)
        .collect();
    let reproducers = genesis
        .reproducers
        .iter()
        .map(|member| member.public_key)
        .collect();
    Ok(VerifiedCeremonyTranscript {
        records,
        status: validated.status,
        ceremony_id: validated.ceremony_id,
        transcript_derive_key_digest: blake3_derive(TRANSCRIPT_DOMAIN, bytes),
        transcript_blake3: ordinary_blake3(bytes),
        transcript_sha256: sha256(bytes),
        transcript_bytes: u64::try_from(bytes.len())
            .map_err(|_| CeremonyTranscriptError::Limit("transcript bytes"))?,
        operators,
        reproducers,
        combiner_bindings: validated.combiner_bindings,
    })
}

fn attestation_prefix(
    attestation: &DetachedTranscriptAttestation,
) -> Result<Vec<u8>, CeremonyTranscriptError> {
    if attestation.signatures.len() > MAX_CEREMONY_SIGNERS {
        return Err(CeremonyTranscriptError::Limit(
            "attestation signature count",
        ));
    }
    let mut encoder = Encoder::default();
    encoder.bytes(&CEREMONY_ATTESTATION_MAGIC);
    encoder.u16(CEREMONY_PROTOCOL_VERSION);
    encoder.bytes(&attestation.ceremony_id);
    encoder.u64(attestation.transcript_bytes);
    encoder.bytes(&attestation.transcript_derive_key_digest);
    encoder.bytes(&attestation.transcript_blake3);
    encoder.bytes(&attestation.transcript_sha256);
    encoder.u16(checked_u16(
        attestation.signatures.len(),
        "attestation signature count",
    )?);
    Ok(encoder.0)
}

pub fn ceremony_attestation_signature_message(
    attestation: &DetachedTranscriptAttestation,
) -> Result<[u8; 32], CeremonyTranscriptError> {
    Ok(blake3_derive(
        TRANSCRIPT_ATTESTATION_DOMAIN,
        &attestation_prefix(attestation)?,
    ))
}

pub fn encode_detached_transcript_attestation(
    attestation: &DetachedTranscriptAttestation,
) -> Result<Vec<u8>, CeremonyTranscriptError> {
    validate_signature_order(&attestation.signatures)?;
    let mut bytes = attestation_prefix(attestation)?;
    let mut signatures = Encoder::default();
    for signature in &attestation.signatures {
        append_signature(&mut signatures, signature);
    }
    bytes.extend_from_slice(&signatures.0);
    if bytes.len() > MAX_CEREMONY_ATTESTATION_BYTES {
        return Err(CeremonyTranscriptError::Limit("attestation bytes"));
    }
    Ok(bytes)
}

pub fn decode_detached_transcript_attestation(
    bytes: &[u8],
) -> Result<DetachedTranscriptAttestation, CeremonyTranscriptError> {
    if bytes.len() > MAX_CEREMONY_ATTESTATION_BYTES {
        return Err(CeremonyTranscriptError::Limit("attestation bytes"));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take::<8>("attestation magic")? != CEREMONY_ATTESTATION_MAGIC {
        return Err(CeremonyTranscriptError::Invalid("attestation magic"));
    }
    if decoder.u16("attestation version")? != CEREMONY_PROTOCOL_VERSION {
        return Err(CeremonyTranscriptError::Invalid("attestation version"));
    }
    let ceremony_id = decoder.take("attestation ceremony id")?;
    let transcript_bytes = decoder.u64("attested transcript bytes")?;
    let transcript_derive_key_digest = decoder.take("transcript derive-key digest")?;
    let transcript_blake3 = decoder.take("transcript blake3")?;
    let transcript_sha256 = decoder.take("transcript sha256")?;
    let signature_count = usize::from(decoder.u16("attestation signature count")?);
    let signatures = decode_signatures(&mut decoder, signature_count)?;
    decoder.finish()?;
    Ok(DetachedTranscriptAttestation {
        ceremony_id,
        transcript_bytes,
        transcript_derive_key_digest,
        transcript_blake3,
        transcript_sha256,
        signatures,
    })
}

/// Verify a detached closure against one already verified exact transcript.
///
/// This function verifies one attestation. Detecting a roster member signing a
/// second attestation for the same ceremony requires comparing independently
/// mirrored attestations outside this codec.
pub fn verify_detached_transcript_attestation(
    bytes: &[u8],
    transcript: &VerifiedCeremonyTranscript,
) -> Result<DetachedTranscriptAttestation, CeremonyTranscriptError> {
    let attestation = decode_detached_transcript_attestation(bytes)?;
    if attestation.ceremony_id != transcript.ceremony_id
        || attestation.transcript_bytes != transcript.transcript_bytes
        || attestation.transcript_derive_key_digest != transcript.transcript_derive_key_digest
        || attestation.transcript_blake3 != transcript.transcript_blake3
        || attestation.transcript_sha256 != transcript.transcript_sha256
    {
        return Err(CeremonyTranscriptError::Invalid(
            "attestation transcript identity",
        ));
    }
    let expected_all: Vec<_> = transcript
        .operators
        .iter()
        .enumerate()
        .map(|(index, _)| {
            (
                SignerClass::Operator,
                u16::try_from(index).expect("operator roster is capped at u16"),
            )
        })
        .chain(transcript.reproducers.iter().enumerate().map(|(index, _)| {
            (
                SignerClass::Reproducer,
                u16::try_from(index).expect("reproducer roster is capped at u16"),
            )
        }))
        .collect();
    let actual = signature_slots(&attestation.signatures);
    match transcript.status {
        CeremonyTranscriptStatus::Completed if actual != expected_all => {
            return Err(CeremonyTranscriptError::Invalid(
                "completed attestation signer cardinality",
            ));
        }
        CeremonyTranscriptStatus::Aborted if actual.is_empty() => {
            return Err(CeremonyTranscriptError::Invalid(
                "aborted attestation signer cardinality",
            ));
        }
        CeremonyTranscriptStatus::RevealSetClosed => {
            return Err(CeremonyTranscriptError::Invalid(
                "detached attestation requires a completed or aborted transcript",
            ));
        }
        _ => {}
    }
    let message = ceremony_attestation_signature_message(&attestation)?;
    for signature in &attestation.signatures {
        let keys = match signature.signer_class {
            SignerClass::Operator => &transcript.operators,
            SignerClass::Reproducer => &transcript.reproducers,
        };
        let key = keys.get(usize::from(signature.signer_index)).ok_or(
            CeremonyTranscriptError::Invalid("attestation signer outside frozen roster"),
        )?;
        verify_bip340(key, &message, &signature.signature)?;
    }
    Ok(attestation)
}

#[cfg(test)]
mod tests {
    use dory_pcs::primitives::{
        DorySerialize,
        arithmetic::{Field, Group},
    };
    use k256::schnorr::{Signature, SigningKey};

    use super::*;
    use crate::{
        dory_bls12_381_prototype::{
            BlsDoryFr, BlsDoryGt, DeterministicBlsDorySetup, deterministic_bls_dory_setup,
        },
        dory_v3_model::DoryV3ModelIdentityV1,
        dory_v3_model_record::DoryV3ModelCommitmentRecordV2,
        dory_v3_suite::DORY_V3_MODEL_IDENTITY_VERSION,
    };

    fn file(byte: u8) -> FileIdentity {
        FileIdentity {
            bytes: u64::from(byte) + 1,
            blake3: [byte; 32],
            sha256: [byte.wrapping_add(1); 32],
        }
    }

    fn keys(count: usize, offset: u8) -> Vec<SigningKey> {
        (0..count)
            .map(|index| SigningKey::from_bytes(&[offset.wrapping_add(index as u8); 32]).unwrap())
            .collect()
    }

    fn member(index: usize, key: &SigningKey) -> RosterMember {
        RosterMember {
            index: index as u16,
            public_key: key.verifying_key().to_bytes().into(),
            identity_document: file(index as u8 + 10),
        }
    }

    fn genesis(operator_keys: &[SigningKey], reproducer_keys: &[SigningKey]) -> GenesisBody {
        GenesisBody {
            ceremony_protocol_version: CEREMONY_PROTOCOL_VERSION,
            model_version: PRODUCTION_MODEL_VERSION,
            bank_format_version: PRODUCTION_BANK_FORMAT_VERSION,
            bank_header_bytes: PRODUCTION_BANK_HEADER_BYTES,
            batch: PRODUCTION_BATCH,
            dimension: PRODUCTION_DIMENSION,
            layers: PRODUCTION_LAYERS,
            banks: PRODUCTION_BANKS,
            layers_per_bank: PRODUCTION_LAYERS_PER_BANK,
            padded_variables: PRODUCTION_PADDED_VARIABLES,
            max_model_byte: PRODUCTION_MAX_MODEL_BYTE,
            base_input_bytes: PRODUCTION_BASE_INPUT_BYTES,
            bytes_per_layer: PRODUCTION_BYTES_PER_LAYER,
            payload_bytes: PRODUCTION_PAYLOAD_BYTES,
            commit_deadline_unix_seconds: 1,
            reveal_deadline_unix_seconds: 2,
            source_commit_sha1: [3; 20],
            source_bundle: file(4),
            source_bundle_policy: file(5),
            cargo_lock_blake3: [6; 32],
            cargo_lock_sha256: [7; 32],
            protocol_spec_blake3: [8; 32],
            protocol_spec_sha256: [9; 32],
            bulletin_policy: file(10),
            reference_binaries: vec![ReferenceBinary {
                target_id: 1,
                rustc_vv: file(11),
                build_environment: file(12),
                binary_blake3: [13; 32],
                binary_sha256: [14; 32],
            }],
            structural_analyzer_target_id: 1,
            structural_analyzer_blake3: [15; 32],
            structural_analyzer_sha256: [16; 32],
            production_suite_digest: PRODUCTION_SUITE_DIGEST,
            dory_setup_identity: DORY_SETUP_IDENTITY,
            operators: operator_keys
                .iter()
                .enumerate()
                .map(|(index, key)| member(index, key))
                .collect(),
            reproducers: reproducer_keys
                .iter()
                .enumerate()
                .map(|(index, key)| member(index, key))
                .collect(),
        }
    }

    fn sign_record(
        body: CeremonyRecordBody,
        signers: &[(SignerClass, u16, &SigningKey)],
    ) -> SignedCeremonyRecord {
        let message = ceremony_record_signature_message(&body).unwrap();
        SignedCeremonyRecord {
            body,
            signatures: signers
                .iter()
                .map(|(class, index, key)| {
                    let signature: Signature = key.sign_raw(&message, &[0; 32]).unwrap();
                    RecordSignature {
                        signer_class: *class,
                        signer_index: *index,
                        signature: signature.to_bytes(),
                    }
                })
                .collect(),
        }
    }

    fn all_signers<'a>(
        operators: &'a [SigningKey],
        reproducers: &'a [SigningKey],
    ) -> Vec<(SignerClass, u16, &'a SigningKey)> {
        operators
            .iter()
            .enumerate()
            .map(|(index, key)| (SignerClass::Operator, index as u16, key))
            .chain(
                reproducers
                    .iter()
                    .enumerate()
                    .map(|(index, key)| (SignerClass::Reproducer, index as u16, key)),
            )
            .collect()
    }

    fn canonical_commitment(
        setup: &DeterministicBlsDorySetup,
        scalar: i64,
        row: usize,
    ) -> [u8; 576] {
        let committed_row = setup
            .commit_row_segment(0, &[BlsDoryFr::from_i64(scalar)])
            .unwrap();
        let commitment = setup.pair_committed_row(row, &committed_row).unwrap();
        let mut encoded = Vec::new();
        commitment.serialize_compressed(&mut encoded).unwrap();
        encoded.try_into().unwrap()
    }

    fn aborted_fixture() -> (Vec<u8>, Vec<SigningKey>, Vec<SigningKey>) {
        let operators = keys(3, 1);
        let reproducers = keys(2, 20);
        let genesis = sign_record(
            CeremonyRecordBody::Genesis(Box::new(genesis(&operators, &reproducers))),
            &all_signers(&operators, &reproducers),
        );
        let ceremony_id = ceremony_record_content_digest(&genesis.body).unwrap();
        let previous = ceremony_signed_record_digest(&genesis).unwrap();
        let abort = sign_record(
            CeremonyRecordBody::Abort(AbortBody {
                ceremony_id,
                last_valid_signed_record_digest: previous,
                phase: 1,
                reason_code: 12,
                evidence_file: file(30),
            }),
            &[(SignerClass::Operator, 0, &operators[0])],
        );
        (
            encode_and_verify_ceremony_transcript(&[genesis, abort]).unwrap(),
            operators,
            reproducers,
        )
    }

    fn completed_fixture() -> (Vec<u8>, Vec<SigningKey>, Vec<SigningKey>) {
        let operators = keys(3, 1);
        let reproducers = keys(2, 20);
        let operator_signers: Vec<_> = operators
            .iter()
            .enumerate()
            .map(|(index, key)| (SignerClass::Operator, index as u16, key))
            .collect();
        let all = all_signers(&operators, &reproducers);
        let genesis = sign_record(
            CeremonyRecordBody::Genesis(Box::new(genesis(&operators, &reproducers))),
            &all,
        );
        let ceremony_id = ceremony_record_content_digest(&genesis.body).unwrap();
        let genesis_digest = ceremony_signed_record_digest(&genesis).unwrap();
        let mut records = vec![genesis];
        let mut commitments = Vec::new();
        let mut commitment_bodies = Vec::new();
        for (index, key) in operators.iter().enumerate() {
            let body = ContributionCommitmentBody {
                ceremony_id,
                genesis_signed_record_digest: genesis_digest,
                operator_index: index as u16,
                operator_public_key: key.verifying_key().to_bytes().into(),
                contribution_bytes: PRODUCTION_PAYLOAD_BYTES,
                contribution_blake3: [40 + index as u8; 32],
                contribution_sha256: [50 + index as u8; 32],
                source_bytes_consumed: PRODUCTION_PAYLOAD_BYTES + 5,
                rejected_source_bytes: 5,
                generation_finished_unix_seconds: 100 + index as u64,
                generator_binary_blake3: [60 + index as u8; 32],
                generator_binary_sha256: [70 + index as u8; 32],
                entropy_attestation: file(80 + index as u8),
            };
            let record = sign_record(
                CeremonyRecordBody::ContributionCommitment(body.clone()),
                &[(SignerClass::Operator, index as u16, key)],
            );
            commitments.push(IndexedRecordDigest {
                index: index as u16,
                signed_record_digest: ceremony_signed_record_digest(&record).unwrap(),
            });
            commitment_bodies.push(body);
            records.push(record);
        }
        let commitment_set = sign_record(
            CeremonyRecordBody::CommitmentSet(CommitmentSetBody {
                ceremony_id,
                genesis_signed_record_digest: genesis_digest,
                commitments: commitments.clone(),
            }),
            &operator_signers,
        );
        let commitment_set_digest = ceremony_signed_record_digest(&commitment_set).unwrap();
        records.push(commitment_set);
        let mut reveals = Vec::new();
        for (index, key) in operators.iter().enumerate() {
            let commitment = &commitment_bodies[index];
            let record = sign_record(
                CeremonyRecordBody::ContributionReveal(ContributionRevealBody {
                    ceremony_id,
                    operator_index: index as u16,
                    contribution_commitment_signed_record_digest: commitments[index]
                        .signed_record_digest,
                    contribution_bytes: commitment.contribution_bytes,
                    contribution_blake3: commitment.contribution_blake3,
                    contribution_sha256: commitment.contribution_sha256,
                    reveal_finished_unix_seconds: 200 + index as u64,
                }),
                &[(SignerClass::Operator, index as u16, key)],
            );
            reveals.push(IndexedRecordDigest {
                index: index as u16,
                signed_record_digest: ceremony_signed_record_digest(&record).unwrap(),
            });
            records.push(record);
        }
        let reveal_set = sign_record(
            CeremonyRecordBody::RevealSet(RevealSetBody {
                ceremony_id,
                commitment_set_signed_record_digest: commitment_set_digest,
                reveals,
            }),
            &operator_signers,
        );
        let reveal_set_digest = ceremony_signed_record_digest(&reveal_set).unwrap();
        records.push(reveal_set);

        let setup = deterministic_bls_dory_setup(3).unwrap();
        let mut final_body = FinalReceiptBody {
            ceremony_id,
            commitment_set_signed_record_digest: commitment_set_digest,
            reveal_set_signed_record_digest: reveal_set_digest,
            payload_bytes: PRODUCTION_PAYLOAD_BYTES,
            raw_payload_blake3: [90; 32],
            raw_payload_sha256: [91; 32],
            base_input_blake3_root: [92; 32],
            layer_roots_aggregate: [93; 32],
            roots_file: file(94),
            structural_report: file(95),
            bank_bytes: PRODUCTION_BANK_BYTES,
            bank_file_blake3: [96; 32],
            bank_file_sha256: [97; 32],
            manifest_file: file(98),
            manifest_digest: [0; 32],
            production_suite_digest: PRODUCTION_SUITE_DIGEST,
            pcs_parameter_digest: PRODUCTION_SUITE_DIGEST,
            base_commitment: canonical_commitment(&setup, 3, 0),
            weight_bank_0_commitment: canonical_commitment(&setup, 5, 1),
            weight_bank_1_commitment: canonical_commitment(&setup, 7, 2),
            weight_bank_2_commitment: canonical_commitment(&setup, 11, 3),
            pcs_commitment_root: [0; 32],
            model_identity_digest: [0; 32],
            setup_identity: DORY_SETUP_IDENTITY,
            padded_variables: PRODUCTION_PADDED_VARIABLES,
            record_v2_file: file(102),
            record_v2_digest: [0; 32],
            publisher_reproducer_index: 0,
            reproducers: (0..reproducers.len())
                .map(|index| ReproducerReceipt {
                    index: index as u16,
                    combiner_binary_blake3: [110 + index as u8; 32],
                    combiner_binary_sha256: [112 + index as u8; 32],
                    bootstrap_report: file(114 + index as u8),
                    record_ceremony_report: file(116 + index as u8),
                    reproduction_report: file(118 + index as u8),
                })
                .collect(),
        };
        let derived = derive_final_receipt_fields(&final_body).unwrap();
        final_body.pcs_commitment_root = derived.commitment_root;
        final_body.manifest_digest = derived.manifest_digest;
        final_body.model_identity_digest = derived.model_identity_digest;
        final_body.record_v2_digest = derived.record_v2_digest;
        let final_receipt =
            sign_record(CeremonyRecordBody::FinalReceipt(Box::new(final_body)), &all);
        records.push(final_receipt);
        (
            encode_and_verify_ceremony_transcript(&records).unwrap(),
            operators,
            reproducers,
        )
    }

    #[test]
    fn aborted_transcript_and_attestation_round_trip() {
        let (bytes, operators, _) = aborted_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&bytes).unwrap();
        assert_eq!(transcript.status(), CeremonyTranscriptStatus::Aborted);
        let mut attestation = DetachedTranscriptAttestation {
            ceremony_id: transcript.ceremony_id(),
            transcript_bytes: transcript.transcript_bytes(),
            transcript_derive_key_digest: transcript.transcript_derive_key_digest(),
            transcript_blake3: transcript.transcript_blake3(),
            transcript_sha256: transcript.transcript_sha256(),
            signatures: vec![RecordSignature {
                signer_class: SignerClass::Operator,
                signer_index: 0,
                signature: [0; 64],
            }],
        };
        let message = ceremony_attestation_signature_message(&attestation).unwrap();
        let signature: Signature = operators[0].sign_raw(&message, &[0; 32]).unwrap();
        attestation.signatures[0].signature = signature.to_bytes();
        let encoded = encode_detached_transcript_attestation(&attestation).unwrap();
        assert_eq!(
            verify_detached_transcript_attestation(&encoded, &transcript).unwrap(),
            attestation
        );
    }

    #[test]
    fn completed_transcript_round_trip_covers_all_record_types() {
        let (bytes, _, _) = completed_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&bytes).unwrap();
        assert_eq!(transcript.status(), CeremonyTranscriptStatus::Completed);
        assert_eq!(transcript.records().len(), 10);
        assert_eq!(
            encode_and_verify_ceremony_transcript(transcript.records()).unwrap(),
            bytes
        );
        assert_eq!(
            transcript
                .records()
                .iter()
                .map(|record| record.body.record_type())
                .collect::<Vec<_>>(),
            vec![1, 2, 2, 2, 3, 4, 4, 4, 5, 6]
        );
        assert_eq!(
            hex::encode(transcript.ceremony_id()),
            "03b483fa6626cd9e8e12ff8a1bd7f18fd1d034a5038f8cb53b109d836ad8d7e8"
        );
        assert_eq!(
            hex::encode(ceremony_signed_record_digest(&transcript.records()[0]).unwrap()),
            "cb35343a764b88e1d3267328a47df5698681dad359894e45a583d3abf21b918b"
        );
        assert_eq!(
            hex::encode(transcript.transcript_derive_key_digest()),
            "71d07b4bd81729777ead91e9807eee8e6275d09a8ebb170345f38515f35dc8b0"
        );
        assert_eq!(
            hex::encode(transcript.transcript_blake3()),
            "23293f47e57372556b96456de1eb94e5d630e3defd4eb51639ec8f6d7a1ccb03"
        );
        assert_eq!(
            hex::encode(transcript.transcript_sha256()),
            "e4d38fb2953e7f226bcefbb52ea1be342f0768bfe19073c426e69db30b276a3d"
        );

        let mut reordered = transcript.records().to_vec();
        reordered.swap(1, 2);
        assert!(encode_and_verify_ceremony_transcript(&reordered).is_err());

        let mut inconsistent = transcript.records().to_vec();
        let CeremonyRecordBody::FinalReceipt(receipt) = &mut inconsistent[9].body else {
            panic!("fixture must finish with a receipt");
        };
        receipt.model_identity_digest[0] ^= 1;
        assert!(encode_and_verify_ceremony_transcript(&inconsistent).is_err());
    }

    #[test]
    fn verifies_bip340_message_directly_without_extra_sha256() {
        let public_key: [u8; 32] =
            hex::decode("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
                .unwrap()
                .try_into()
                .unwrap();
        let signature: [u8; 64] = hex::decode(concat!(
            "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215",
            "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
        ))
        .unwrap()
        .try_into()
        .unwrap();
        verify_bip340(&public_key, &[0; 32], &signature).unwrap();
    }

    #[test]
    fn completed_attestation_requires_every_roster_member() {
        let (bytes, operators, reproducers) = completed_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&bytes).unwrap();
        let mut attestation = DetachedTranscriptAttestation {
            ceremony_id: transcript.ceremony_id(),
            transcript_bytes: transcript.transcript_bytes(),
            transcript_derive_key_digest: transcript.transcript_derive_key_digest(),
            transcript_blake3: transcript.transcript_blake3(),
            transcript_sha256: transcript.transcript_sha256(),
            signatures: all_signers(&operators, &reproducers)
                .iter()
                .map(|(class, index, _)| RecordSignature {
                    signer_class: *class,
                    signer_index: *index,
                    signature: [0; 64],
                })
                .collect(),
        };
        let message = ceremony_attestation_signature_message(&attestation).unwrap();
        for (entry, (_, _, key)) in attestation
            .signatures
            .iter_mut()
            .zip(all_signers(&operators, &reproducers))
        {
            let signature: Signature = key.sign_raw(&message, &[0; 32]).unwrap();
            entry.signature = signature.to_bytes();
        }
        let encoded = encode_detached_transcript_attestation(&attestation).unwrap();
        verify_detached_transcript_attestation(&encoded, &transcript).unwrap();

        attestation.signatures.pop();
        let encoded = encode_detached_transcript_attestation(&attestation).unwrap();
        assert!(verify_detached_transcript_attestation(&encoded, &transcript).is_err());
    }

    #[test]
    fn rejects_header_length_trailing_and_unknown_signer_class() {
        let (bytes, _, _) = aborted_fixture();
        let mut bad_total = bytes.clone();
        bad_total[16] ^= 1;
        assert!(parse_and_verify_ceremony_transcript(&bad_total).is_err());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(parse_and_verify_ceremony_transcript(&trailing).is_err());

        let mut reserved = bytes.clone();
        let genesis_body_bytes = u32::from_le_bytes(reserved[28..32].try_into().unwrap()) as usize;
        let first_signer_class = 24 + 8 + genesis_body_bytes + 2;
        reserved[first_signer_class] = 2;
        assert!(parse_and_verify_ceremony_transcript(&reserved).is_err());

        let mut unknown_type = bytes;
        unknown_type[24..26].copy_from_slice(&8_u16.to_le_bytes());
        assert!(parse_and_verify_ceremony_transcript(&unknown_type).is_err());
    }

    #[test]
    fn rejects_wrong_reference_and_signature() {
        let (bytes, _, _) = aborted_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&bytes).unwrap();
        let mut records = transcript.records().to_vec();
        let CeremonyRecordBody::Abort(abort) = &mut records[1].body else {
            panic!("fixture must abort");
        };
        abort.last_valid_signed_record_digest[0] ^= 1;
        assert!(encode_and_verify_ceremony_transcript(&records).is_err());

        let (bytes, _, _) = aborted_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&bytes).unwrap();
        let mut records = transcript.records().to_vec();
        records[1].signatures[0].signature[10] ^= 1;
        assert!(encode_and_verify_ceremony_transcript(&records).is_err());
    }

    #[test]
    fn record_codec_rejects_trailing_and_bad_geometry() {
        let operators = keys(3, 1);
        let reproducers = keys(2, 20);
        let record = sign_record(
            CeremonyRecordBody::Genesis(Box::new(genesis(&operators, &reproducers))),
            &all_signers(&operators, &reproducers),
        );
        let encoded = encode_ceremony_record(&record).unwrap();
        assert_eq!(decode_ceremony_record(&encoded).unwrap(), record);
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_ceremony_record(&trailing).is_err());

        let mut invalid = genesis(&operators, &reproducers);
        invalid.dimension -= 1;
        assert!(encode_body(&CeremonyRecordBody::Genesis(Box::new(invalid))).is_err());

        let mut nonconsecutive = genesis(&operators, &reproducers);
        nonconsecutive.operators[1].index = 2;
        assert!(encode_body(&CeremonyRecordBody::Genesis(Box::new(nonconsecutive))).is_err());

        let mut duplicate_key = genesis(&operators, &reproducers);
        duplicate_key.reproducers[0].public_key = duplicate_key.operators[0].public_key;
        assert!(encode_body(&CeremonyRecordBody::Genesis(Box::new(duplicate_key))).is_err());

        let mut out_of_order_signatures = record;
        out_of_order_signatures.signatures.swap(0, 1);
        assert!(encode_ceremony_record(&out_of_order_signatures).is_err());
    }

    #[test]
    fn abort_phase_is_signed_incident_metadata_and_type_7_is_stable() {
        let (bytes, operators, _) = aborted_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&bytes).unwrap();
        let abort_record = &transcript.records()[1];
        assert_eq!(
            hex::encode(ceremony_record_content_digest(&abort_record.body).unwrap()),
            "a598b88a044c587d01f986b915b395ca2dc2b3ed96e5bdc9d2b9c576297bf326"
        );
        assert_eq!(
            hex::encode(ceremony_record_signature_message(&abort_record.body).unwrap()),
            "5477908050c24378ecfd5395ae9092cdbf90dd2554353738a0f3403345d6517c"
        );
        assert_eq!(
            hex::encode(ceremony_signed_record_digest(abort_record).unwrap()),
            "aaeb753b3e36e5c12afd375111d81874ea0a1e7fc141f73d52ac294782223c3c"
        );
        assert_eq!(
            hex::encode(transcript.transcript_derive_key_digest()),
            "8ad3c702f3cc3dc5b4df9a3f078da2173c22b46c23581c86bb5a9a637fcc689d"
        );

        let CeremonyRecordBody::Abort(original_abort) = &abort_record.body else {
            panic!("fixture must abort");
        };
        let mut phase_two = transcript.records().to_vec();
        let CeremonyRecordBody::Abort(body) = &mut phase_two[1].body else {
            panic!("fixture must abort");
        };
        body.phase = 2;
        phase_two[1] = sign_record(
            phase_two[1].body.clone(),
            &[(SignerClass::Operator, 0, &operators[0])],
        );
        let phase_two_bytes = encode_and_verify_ceremony_transcript(&phase_two).unwrap();
        assert_eq!(
            parse_and_verify_ceremony_transcript(&phase_two_bytes)
                .unwrap()
                .status(),
            CeremonyTranscriptStatus::Aborted
        );

        for phase in [0, 9] {
            let mut invalid = original_abort.clone();
            invalid.phase = phase;
            assert!(
                ceremony_record_signature_message(&CeremonyRecordBody::Abort(invalid)).is_err()
            );
        }
    }

    #[test]
    fn detached_attestation_has_stable_domain_and_rejects_invalid_closures() {
        let (bytes, operators, _) = aborted_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&bytes).unwrap();
        let mut attestation = DetachedTranscriptAttestation {
            ceremony_id: transcript.ceremony_id(),
            transcript_bytes: transcript.transcript_bytes(),
            transcript_derive_key_digest: transcript.transcript_derive_key_digest(),
            transcript_blake3: transcript.transcript_blake3(),
            transcript_sha256: transcript.transcript_sha256(),
            signatures: vec![RecordSignature {
                signer_class: SignerClass::Operator,
                signer_index: 0,
                signature: [0; 64],
            }],
        };
        let message = ceremony_attestation_signature_message(&attestation).unwrap();
        let signature: Signature = operators[0].sign_raw(&message, &[0; 32]).unwrap();
        attestation.signatures[0].signature = signature.to_bytes();
        let encoded = encode_detached_transcript_attestation(&attestation).unwrap();
        assert_eq!(
            hex::encode(message),
            "ab9de9c7b76ee321a679d07f0db16375ec42c18f83ac4e8301256756ef332941"
        );
        assert_eq!(
            hex::encode(ordinary_blake3(&encoded)),
            "1a92ed8d538584082a62efb5b21788e20afa6bbea21f151f0f014a6291d13b6b"
        );
        assert_eq!(
            hex::encode(sha256(&encoded)),
            "d34fd3dbae5803179703f832b6a93eac28833f79528225268183029dabab26fe"
        );
        verify_detached_transcript_attestation(&encoded, &transcript).unwrap();

        let mut no_signatures = attestation.clone();
        no_signatures.signatures.clear();
        let encoded_no_signatures = encode_detached_transcript_attestation(&no_signatures).unwrap();
        assert!(
            verify_detached_transcript_attestation(&encoded_no_signatures, &transcript).is_err()
        );

        let mut outside_roster = attestation.clone();
        outside_roster.signatures[0].signer_index = 9;
        let outside_message = ceremony_attestation_signature_message(&outside_roster).unwrap();
        outside_roster.signatures[0].signature = operators[0]
            .sign_raw(&outside_message, &[0; 32])
            .unwrap()
            .to_bytes();
        let encoded_outside = encode_detached_transcript_attestation(&outside_roster).unwrap();
        assert!(verify_detached_transcript_attestation(&encoded_outside, &transcript).is_err());

        let mut wrong_identity = attestation.clone();
        wrong_identity.transcript_sha256[0] ^= 1;
        let wrong_message = ceremony_attestation_signature_message(&wrong_identity).unwrap();
        wrong_identity.signatures[0].signature = operators[0]
            .sign_raw(&wrong_message, &[0; 32])
            .unwrap()
            .to_bytes();
        let encoded_wrong = encode_detached_transcript_attestation(&wrong_identity).unwrap();
        assert!(verify_detached_transcript_attestation(&encoded_wrong, &transcript).is_err());

        let mut duplicate_signer = attestation.clone();
        let duplicate = duplicate_signer.signatures[0].clone();
        duplicate_signer.signatures.push(duplicate);
        assert!(encode_detached_transcript_attestation(&duplicate_signer).is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_detached_transcript_attestation(&trailing).is_err());
    }

    #[test]
    fn codec_caps_fail_before_unbounded_allocation() {
        let (bytes, _, _) = aborted_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&bytes).unwrap();
        let mut too_many_signatures = transcript.records()[0].clone();
        too_many_signatures.signatures = vec![
            RecordSignature {
                signer_class: SignerClass::Operator,
                signer_index: 0,
                signature: [0; 64],
            };
            MAX_CEREMONY_SIGNERS + 1
        ];
        assert!(matches!(
            encode_ceremony_record(&too_many_signatures),
            Err(CeremonyTranscriptError::Limit("signature count"))
        ));

        let mut oversized_body = Encoder::default();
        oversized_body.u16(1);
        oversized_body.u16(CEREMONY_PROTOCOL_VERSION);
        oversized_body.u32((MAX_CEREMONY_RECORD_BODY_BYTES as u32) + 1);
        assert!(matches!(
            decode_ceremony_record(&oversized_body.0),
            Err(CeremonyTranscriptError::Limit("record body bytes"))
        ));

        assert!(matches!(
            parse_and_verify_ceremony_transcript(&vec![0; MAX_CEREMONY_TRANSCRIPT_BYTES + 1]),
            Err(CeremonyTranscriptError::Limit("transcript bytes"))
        ));
        assert!(matches!(
            decode_detached_transcript_attestation(&vec![0; MAX_CEREMONY_ATTESTATION_BYTES + 1]),
            Err(CeremonyTranscriptError::Limit("attestation bytes"))
        ));

        let mut too_many_records = Encoder::default();
        too_many_records.bytes(&CEREMONY_TRANSCRIPT_MAGIC);
        too_many_records.u16(CEREMONY_PROTOCOL_VERSION);
        too_many_records.u16(CEREMONY_TRANSCRIPT_HEADER_BYTES);
        too_many_records.u32((MAX_CEREMONY_RECORDS as u32) + 1);
        too_many_records.u64(u64::from(CEREMONY_TRANSCRIPT_HEADER_BYTES));
        assert!(matches!(
            parse_and_verify_ceremony_transcript(&too_many_records.0),
            Err(CeremonyTranscriptError::Invalid("transcript record count"))
        ));
    }

    #[test]
    fn every_record_class_enforces_signer_cardinality_and_order() {
        let (bytes, _, _) = completed_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&bytes).unwrap();
        let records = transcript.records();

        let mut missing_genesis_signer = records.to_vec();
        missing_genesis_signer[0].signatures.pop();
        assert!(encode_and_verify_ceremony_transcript(&missing_genesis_signer).is_err());

        let mut duplicate_genesis_signer = records.to_vec();
        let duplicate = duplicate_genesis_signer[0].signatures[0].clone();
        duplicate_genesis_signer[0].signatures.insert(1, duplicate);
        assert!(encode_and_verify_ceremony_transcript(&duplicate_genesis_signer).is_err());

        let mut wrong_single_signer = records.to_vec();
        wrong_single_signer[1].signatures[0].signer_class = SignerClass::Reproducer;
        assert!(encode_and_verify_ceremony_transcript(&wrong_single_signer).is_err());

        for index in [4, 8, 9] {
            let mut missing_required_signer = records.to_vec();
            missing_required_signer[index].signatures.pop();
            assert!(encode_and_verify_ceremony_transcript(&missing_required_signer).is_err());
        }

        let (abort_bytes, _, _) = aborted_fixture();
        let abort = parse_and_verify_ceremony_transcript(&abort_bytes).unwrap();
        let mut unsigned_abort = abort.records().to_vec();
        unsigned_abort[1].signatures.clear();
        assert!(encode_and_verify_ceremony_transcript(&unsigned_abort).is_err());
    }

    #[test]
    fn every_later_record_rejects_a_wrong_signed_record_reference() {
        let (bytes, operators, reproducers) = completed_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&bytes).unwrap();
        let records = transcript.records();
        let operator_signers: Vec<_> = operators
            .iter()
            .enumerate()
            .map(|(index, key)| (SignerClass::Operator, index as u16, key))
            .collect();
        let all = all_signers(&operators, &reproducers);

        let mut bad_type_2 = records.to_vec();
        let CeremonyRecordBody::ContributionCommitment(body) = &mut bad_type_2[1].body else {
            panic!("fixture record 1 must be type 2");
        };
        body.genesis_signed_record_digest[0] ^= 1;
        bad_type_2[1] = sign_record(
            bad_type_2[1].body.clone(),
            &[(SignerClass::Operator, 0, &operators[0])],
        );
        assert!(encode_and_verify_ceremony_transcript(&bad_type_2).is_err());

        let mut bad_type_3 = records.to_vec();
        let CeremonyRecordBody::CommitmentSet(body) = &mut bad_type_3[4].body else {
            panic!("fixture record 4 must be type 3");
        };
        body.commitments[0].signed_record_digest[0] ^= 1;
        bad_type_3[4] = sign_record(bad_type_3[4].body.clone(), &operator_signers);
        assert!(encode_and_verify_ceremony_transcript(&bad_type_3).is_err());

        let mut bad_type_4 = records.to_vec();
        let CeremonyRecordBody::ContributionReveal(body) = &mut bad_type_4[5].body else {
            panic!("fixture record 5 must be type 4");
        };
        body.contribution_commitment_signed_record_digest[0] ^= 1;
        bad_type_4[5] = sign_record(
            bad_type_4[5].body.clone(),
            &[(SignerClass::Operator, 0, &operators[0])],
        );
        assert!(encode_and_verify_ceremony_transcript(&bad_type_4).is_err());

        let mut bad_type_5 = records.to_vec();
        let CeremonyRecordBody::RevealSet(body) = &mut bad_type_5[8].body else {
            panic!("fixture record 8 must be type 5");
        };
        body.reveals[0].signed_record_digest[0] ^= 1;
        bad_type_5[8] = sign_record(bad_type_5[8].body.clone(), &operator_signers);
        assert!(encode_and_verify_ceremony_transcript(&bad_type_5).is_err());

        let mut bad_type_6 = records.to_vec();
        let CeremonyRecordBody::FinalReceipt(body) = &mut bad_type_6[9].body else {
            panic!("fixture record 9 must be type 6");
        };
        body.reveal_set_signed_record_digest[0] ^= 1;
        bad_type_6[9] = sign_record(bad_type_6[9].body.clone(), &all);
        assert!(encode_and_verify_ceremony_transcript(&bad_type_6).is_err());
    }

    #[test]
    fn reveal_set_prefix_encoder_round_trips_exact_n3_r2_stage() {
        let (completed_bytes, _, _) = completed_fixture();
        let completed = parse_and_verify_ceremony_transcript(&completed_bytes).unwrap();
        let prefix_records = &completed.records()[..9];
        assert_eq!(completed.operators().len(), 3);
        assert_eq!(completed.reproducers().len(), 2);
        assert_eq!(
            prefix_records
                .iter()
                .map(|record| record.body.record_type())
                .collect::<Vec<_>>(),
            vec![1, 2, 2, 2, 3, 4, 4, 4, 5]
        );

        let encoded =
            encode_and_verify_reveal_set_prefix(prefix_records, completed.ceremony_id()).unwrap();
        assert_eq!(encoded, encode_transcript_records(prefix_records).unwrap());
        let reparsed =
            parse_and_verify_reveal_set_prefix(&encoded, completed.ceremony_id()).unwrap();
        assert_eq!(reparsed.status(), CeremonyTranscriptStatus::RevealSetClosed);
        assert_eq!(reparsed.records(), prefix_records);
    }

    #[test]
    fn reveal_set_prefix_encoder_rejects_malformed_incomplete_order_and_anchor() {
        let (completed_bytes, operators, _) = completed_fixture();
        let completed = parse_and_verify_ceremony_transcript(&completed_bytes).unwrap();
        let prefix_records = completed.records()[..9].to_vec();
        let operator_signers: Vec<_> = operators
            .iter()
            .enumerate()
            .map(|(index, key)| (SignerClass::Operator, index as u16, key))
            .collect();

        assert!(
            encode_and_verify_reveal_set_prefix(completed.records(), completed.ceremony_id())
                .is_err()
        );

        let mut malformed_closure = prefix_records.clone();
        let CeremonyRecordBody::RevealSet(body) = &mut malformed_closure[8].body else {
            panic!("fixture record 8 must be type 5");
        };
        body.reveals[0].signed_record_digest[0] ^= 1;
        malformed_closure[8] = sign_record(malformed_closure[8].body.clone(), &operator_signers);
        assert!(matches!(
            encode_and_verify_reveal_set_prefix(&malformed_closure, completed.ceremony_id()),
            Err(CeremonyTranscriptError::Invalid(
                "reveal set sequence or reference"
            ))
        ));

        assert!(
            encode_and_verify_reveal_set_prefix(&prefix_records[..8], completed.ceremony_id())
                .is_err()
        );

        let mut out_of_order = prefix_records.clone();
        out_of_order.swap(1, 2);
        assert!(
            encode_and_verify_reveal_set_prefix(&out_of_order, completed.ceremony_id()).is_err()
        );

        let mut wrong_anchor = completed.ceremony_id();
        wrong_anchor[0] ^= 1;
        assert!(matches!(
            encode_and_verify_reveal_set_prefix(&prefix_records, wrong_anchor),
            Err(CeremonyTranscriptError::Invalid(
                "reveal-set prefix ceremony id does not match trusted anchor"
            ))
        ));
    }

    #[test]
    fn reveal_set_prefix_is_exact_anchored_and_combiner_bound() {
        let (completed_bytes, operators, _) = completed_fixture();
        let completed = parse_and_verify_ceremony_transcript(&completed_bytes).unwrap();
        let prefix_bytes = encode_transcript_records(&completed.records()[..9]).unwrap();
        assert!(parse_and_verify_ceremony_transcript(&prefix_bytes).is_err());
        assert!(
            parse_and_verify_reveal_set_prefix(&completed_bytes, completed.ceremony_id()).is_err()
        );
        let early_prefix = encode_transcript_records(&completed.records()[..8]).unwrap();
        assert!(
            parse_and_verify_reveal_set_prefix(&early_prefix, completed.ceremony_id()).is_err()
        );
        let mut wrong_anchor = completed.ceremony_id();
        wrong_anchor[0] ^= 1;
        assert!(parse_and_verify_reveal_set_prefix(&prefix_bytes, wrong_anchor).is_err());

        let prefix =
            parse_and_verify_reveal_set_prefix(&prefix_bytes, completed.ceremony_id()).unwrap();
        assert_eq!(prefix.status(), CeremonyTranscriptStatus::RevealSetClosed);
        let bindings = prefix.require_combiner_bindings().unwrap();
        assert_eq!(bindings.ceremony_id(), completed.ceremony_id());
        assert_eq!(
            bindings.commitment_set_signed_record_digest(),
            ceremony_signed_record_digest(&completed.records()[4]).unwrap()
        );
        assert_eq!(
            bindings.reveal_set_signed_record_digest(),
            ceremony_signed_record_digest(&completed.records()[8]).unwrap()
        );
        assert_eq!(bindings.contributions().len(), operators.len());
        for (index, binding) in bindings.contributions().iter().enumerate() {
            let CeremonyRecordBody::ContributionCommitment(commitment) =
                &completed.records()[1 + index].body
            else {
                panic!("fixture commitment slot must contain type 2");
            };
            let expected_public_key: [u8; 32] = operators[index].verifying_key().to_bytes().into();
            assert_eq!(binding.operator_index(), index as u16);
            assert_eq!(binding.operator_public_key(), expected_public_key);
            assert_eq!(binding.contribution_bytes(), commitment.contribution_bytes);
            assert_eq!(
                binding.contribution_blake3(),
                commitment.contribution_blake3
            );
            assert_eq!(
                binding.contribution_sha256(),
                commitment.contribution_sha256
            );
            assert_eq!(
                binding.contribution_commitment_signed_record_digest(),
                ceremony_signed_record_digest(&completed.records()[1 + index]).unwrap()
            );
            assert_eq!(
                binding.contribution_reveal_signed_record_digest(),
                ceremony_signed_record_digest(&completed.records()[5 + index]).unwrap()
            );
        }
        assert!(completed.combiner_bindings.is_none());
        assert!(completed.require_combiner_bindings().is_err());
        assert!(matches!(
            crate::dory_v3_model_combiner::combine_production_dory_v3_model_contributions(
                &completed,
                &[],
                std::path::Path::new("unused-completed-combiner-output")
            ),
            Err(
                crate::dory_v3_model_combiner::ProductionDoryV3ModelCombinerError::TranscriptAuthority {
                    ..
                }
            )
        ));
        assert!(matches!(
            crate::dory_v3_model_combiner::validate_existing_production_dory_v3_model_combined_payload(
                &completed,
                &[],
                std::path::Path::new("unused-completed-validator-output")
            ),
            Err(
                crate::dory_v3_model_combiner::ProductionDoryV3ModelCombinerError::TranscriptAuthority {
                    ..
                }
            )
        ));

        let mut abort_after_closure = completed.records()[..9].to_vec();
        let abort = sign_record(
            CeremonyRecordBody::Abort(AbortBody {
                ceremony_id: completed.ceremony_id(),
                last_valid_signed_record_digest: ceremony_signed_record_digest(
                    &abort_after_closure[8],
                )
                .unwrap(),
                phase: 4,
                reason_code: 12,
                evidence_file: file(130),
            }),
            &[(SignerClass::Operator, 0, &operators[0])],
        );
        abort_after_closure.push(abort);
        let aborted_bytes = encode_and_verify_ceremony_transcript(&abort_after_closure).unwrap();
        let aborted = parse_and_verify_ceremony_transcript(&aborted_bytes).unwrap();
        assert_eq!(aborted.status(), CeremonyTranscriptStatus::Aborted);
        assert!(aborted.require_combiner_bindings().is_err());
        assert!(matches!(
            crate::dory_v3_model_combiner::combine_production_dory_v3_model_contributions(
                &aborted,
                &[],
                std::path::Path::new("unused-aborted-combiner-output")
            ),
            Err(
                crate::dory_v3_model_combiner::ProductionDoryV3ModelCombinerError::TranscriptAuthority {
                    ..
                }
            )
        ));
        assert!(matches!(
            crate::dory_v3_model_combiner::validate_existing_production_dory_v3_model_combined_payload(
                &aborted,
                &[],
                std::path::Path::new("unused-aborted-validator-output")
            ),
            Err(
                crate::dory_v3_model_combiner::ProductionDoryV3ModelCombinerError::TranscriptAuthority {
                    ..
                }
            )
        ));
        assert!(parse_and_verify_reveal_set_prefix(&aborted_bytes, aborted.ceremony_id()).is_err());

        let mut attestation = DetachedTranscriptAttestation {
            ceremony_id: prefix.ceremony_id(),
            transcript_bytes: prefix.transcript_bytes(),
            transcript_derive_key_digest: prefix.transcript_derive_key_digest(),
            transcript_blake3: prefix.transcript_blake3(),
            transcript_sha256: prefix.transcript_sha256(),
            signatures: vec![RecordSignature {
                signer_class: SignerClass::Operator,
                signer_index: 0,
                signature: [0; 64],
            }],
        };
        let message = ceremony_attestation_signature_message(&attestation).unwrap();
        attestation.signatures[0].signature = operators[0]
            .sign_raw(&message, &[0; 32])
            .unwrap()
            .to_bytes();
        let attestation_bytes = encode_detached_transcript_attestation(&attestation).unwrap();
        assert!(verify_detached_transcript_attestation(&attestation_bytes, &prefix).is_err());
    }

    #[test]
    fn final_receipt_rejects_invalid_identity_and_duplicate_commitments() {
        let (bytes, _, _) = completed_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&bytes).unwrap();

        let mut invalid = transcript.records().to_vec();
        let CeremonyRecordBody::FinalReceipt(body) = &mut invalid[9].body else {
            panic!("fixture must finish with type 6");
        };
        body.base_commitment = [0xff; 576];
        assert!(encode_and_verify_ceremony_transcript(&invalid).is_err());

        let mut identity_bytes = Vec::new();
        BlsDoryGt::identity()
            .serialize_compressed(&mut identity_bytes)
            .unwrap();
        let mut identity = transcript.records().to_vec();
        let CeremonyRecordBody::FinalReceipt(body) = &mut identity[9].body else {
            panic!("fixture must finish with type 6");
        };
        body.base_commitment = identity_bytes.try_into().unwrap();
        assert!(encode_and_verify_ceremony_transcript(&identity).is_err());

        let mut duplicate = transcript.records().to_vec();
        let CeremonyRecordBody::FinalReceipt(body) = &mut duplicate[9].body else {
            panic!("fixture must finish with type 6");
        };
        body.weight_bank_0_commitment = body.base_commitment;
        assert!(encode_and_verify_ceremony_transcript(&duplicate).is_err());
    }

    #[test]
    fn final_receipt_derivations_match_independent_production_types() {
        let (bytes, _, _) = completed_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&bytes).unwrap();
        let CeremonyRecordBody::FinalReceipt(receipt) = &transcript.records()[9].body else {
            panic!("fixture must finish with type 6");
        };
        let identity: DoryV3ModelIdentityV1 = serde_json::from_value(serde_json::json!({
            "identity_version": DORY_V3_MODEL_IDENTITY_VERSION,
            "model_version": PRODUCTION_MODEL_VERSION,
            "batch": PRODUCTION_BATCH,
            "dimension": PRODUCTION_DIMENSION,
            "layers_per_bank": PRODUCTION_LAYERS_PER_BANK,
            "model_byte_root": receipt.raw_payload_blake3,
            "layer_roots_aggregate": receipt.layer_roots_aggregate,
            "suite_parameter_digest": receipt.production_suite_digest,
            "setup_identity": receipt.setup_identity,
            "padded_variables": PRODUCTION_PADDED_VARIABLES,
            "base_input_commitment": hex::encode(receipt.base_commitment),
            "weight_bank_commitments": [
                hex::encode(receipt.weight_bank_0_commitment),
                hex::encode(receipt.weight_bank_1_commitment),
                hex::encode(receipt.weight_bank_2_commitment),
            ],
        }))
        .unwrap();
        let manifest = ModelBankManifest {
            model_version: PRODUCTION_MODEL_VERSION,
            dimension: PRODUCTION_DIMENSION,
            batch: PRODUCTION_BATCH,
            layers: PRODUCTION_LAYERS,
            base_input_bytes: PRODUCTION_BASE_INPUT_BYTES,
            bytes_per_layer: PRODUCTION_BYTES_PER_LAYER,
            payload_bytes: PRODUCTION_PAYLOAD_BYTES,
            raw_blake3_root: receipt.raw_payload_blake3,
            layer_roots_aggregate: receipt.layer_roots_aggregate,
            pcs_parameter_digest: receipt.pcs_parameter_digest,
            pcs_commitment_root: identity.commitment_root().unwrap(),
        };
        let record = DoryV3ModelCommitmentRecordV2::new(manifest, identity).unwrap();
        assert_eq!(
            record.commitment_root().into_bytes(),
            receipt.pcs_commitment_root
        );
        assert_eq!(
            record.manifest_digest().into_bytes(),
            receipt.manifest_digest
        );
        assert_eq!(
            record.model_identity_digest().into_bytes(),
            receipt.model_identity_digest
        );
        assert_eq!(
            record.record_digest().into_bytes(),
            receipt.record_v2_digest
        );
        assert_eq!(record.canonical_bytes().len(), 166);
    }
}
