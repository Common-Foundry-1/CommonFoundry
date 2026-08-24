//! Keyless record and detached-attestation authoring for the production Dory V3 ceremony.
//!
//! A strict tagged JSON plan names trusted, immutable inputs. Preparation
//! authenticates those inputs and every prior signed record, derives the one
//! canonical record body, and returns only public signing material. Staging
//! repeats preparation, accepts externally produced BIP340 signatures, enforces
//! the frozen signer policy, and create-new persists immutable records and
//! terminal-transcript attestations for later append-only bulletin publication.
//!
//! This module has no secret-key, seed, signing, transcript-publication, or
//! activation API. A locally staged record always remains publication-pending.

#![cfg(feature = "dory-bls12-381-prototype")]

use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read as _, Seek as _, SeekFrom},
    path::{Path, PathBuf},
};

use k256::schnorr::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    dory_v3_model_ceremony_fs::{
        AuthenticatedInput, CeremonyFsError, ParentSyncOutcome, PendingOutput,
        TrustedCeremonyParent,
    },
    dory_v3_model_ceremony_transcript::{
        CEREMONY_PROTOCOL_VERSION, CeremonyRecordBody, CeremonyTranscriptError,
        CeremonyTranscriptStatus, CommitmentSetBody, ContributionCommitmentBody,
        ContributionRevealBody, DetachedTranscriptAttestation, FileIdentity, FinalReceiptBody,
        GenesisBody, IndexedRecordDigest, MAX_CEREMONY_OPERATORS, MAX_CEREMONY_RECORD_BODY_BYTES,
        MAX_CEREMONY_SIGNERS, MAX_CEREMONY_TRANSCRIPT_BYTES, PRODUCTION_BANK_FORMAT_VERSION,
        PRODUCTION_BANK_HEADER_BYTES, PRODUCTION_BANKS, PRODUCTION_BASE_INPUT_BYTES,
        PRODUCTION_BATCH, PRODUCTION_BYTES_PER_LAYER, PRODUCTION_DIMENSION, PRODUCTION_LAYERS,
        PRODUCTION_LAYERS_PER_BANK, PRODUCTION_MAX_MODEL_BYTE, PRODUCTION_MODEL_VERSION,
        PRODUCTION_PADDED_VARIABLES, PRODUCTION_PAYLOAD_BYTES, RecordSignature, ReferenceBinary,
        RevealSetBody, RosterMember, SignedCeremonyRecord, SignerClass, VerifiedCeremonyTranscript,
        ceremony_attestation_signature_message, ceremony_record_content_digest,
        ceremony_record_signature_message, ceremony_signed_record_digest, decode_ceremony_record,
        encode_and_verify_ceremony_transcript, encode_and_verify_reveal_set_prefix,
        encode_ceremony_record, encode_detached_transcript_attestation,
        parse_and_verify_ceremony_transcript, parse_and_verify_completed_ceremony_transcript,
        parse_and_verify_reveal_set_prefix, verify_detached_transcript_attestation,
    },
    dory_v3_model_final_candidate_validation::{
        ProductionDoryV3ModelFinalCandidateValidationError,
        ValidatedProductionDoryV3ModelFinalCandidate,
    },
    dory_v3_suite::{DORY_V3_SETUP_IDENTITY, production_dory_v3_suite_digest},
};

pub const PRODUCTION_DORY_V3_CEREMONY_PLAN_MAX_BYTES: usize = 256 * 1024;

const MAX_SIGNED_CEREMONY_RECORD_BYTES: usize =
    2 + 2 + 4 + MAX_CEREMONY_RECORD_BODY_BYTES + 2 + MAX_CEREMONY_SIGNERS * (1 + 2 + 64);
const IO_BUFFER_BYTES: usize = 1024 * 1024;

/// Strict, explicitly tagged JSON plan. The wire shape is
/// `{ "record_type": "type_N_name", "plan": { ... } }`.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "record_type", content = "plan", deny_unknown_fields)]
pub enum ProductionDoryV3CeremonyRecordPlan {
    #[serde(rename = "type_1_genesis")]
    Genesis(Box<GenesisPlan>),
    #[serde(rename = "type_2_contribution_commitment")]
    ContributionCommitment(Box<ContributionCommitmentPlan>),
    #[serde(rename = "type_3_commitment_set")]
    CommitmentSet(Box<PriorRecordsPlan>),
    #[serde(rename = "type_4_contribution_reveal")]
    ContributionReveal(Box<ContributionRevealPlan>),
    #[serde(rename = "type_5_reveal_set")]
    RevealSet(Box<RevealSetPlan>),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisPlan {
    pub commit_deadline_unix_seconds: u64,
    pub reveal_deadline_unix_seconds: u64,
    pub source_commit_sha1: String,
    pub source_bundle: PathBuf,
    pub source_bundle_policy: PathBuf,
    pub cargo_lock: PathBuf,
    pub protocol_spec: PathBuf,
    pub bulletin_policy: PathBuf,
    pub reference_binaries: Vec<ReferenceBinaryPlan>,
    pub structural_analyzer_target_id: u16,
    pub structural_analyzer_binary: PathBuf,
    pub operators: Vec<RosterMemberPlan>,
    pub reproducers: Vec<RosterMemberPlan>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceBinaryPlan {
    pub target_id: u16,
    pub rustc_vv: PathBuf,
    pub build_environment: PathBuf,
    pub binary: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterMemberPlan {
    pub index: u16,
    pub public_key: String,
    pub identity_document: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionCommitmentPlan {
    pub prior_records: Vec<PathBuf>,
    pub operator_index: u16,
    pub contribution_file: PathBuf,
    pub source_bytes_consumed: u64,
    pub rejected_source_bytes: u64,
    pub generation_finished_unix_seconds: u64,
    pub generator_target_id: u16,
    pub generator_binary: PathBuf,
    pub entropy_attestation: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionRevealPlan {
    pub prior_records: Vec<PathBuf>,
    pub operator_index: u16,
    pub contribution_file: PathBuf,
    pub reveal_finished_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorRecordsPlan {
    pub prior_records: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevealSetPlan {
    pub prior_records: Vec<PathBuf>,
    /// Ordered by operator index. Every full contribution is authenticated
    /// again before a type-5 closure can be prepared.
    pub contribution_files: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequiredCeremonySigner {
    signer_class: SignerClass,
    signer_index: u16,
    public_key: [u8; 32],
}

impl RequiredCeremonySigner {
    pub const fn signer_class(&self) -> SignerClass {
        self.signer_class
    }

    pub const fn signer_index(&self) -> u16 {
        self.signer_index
    }

    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

/// One canonical signer slot selected for an aborted-transcript attestation.
/// Completed transcripts never accept caller-selected slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProductionDoryV3CeremonyAttestationSigner {
    signer_class: SignerClass,
    signer_index: u16,
}

impl ProductionDoryV3CeremonyAttestationSigner {
    pub const fn new(signer_class: SignerClass, signer_index: u16) -> Self {
        Self {
            signer_class,
            signer_index,
        }
    }

    pub const fn signer_class(&self) -> SignerClass {
        self.signer_class
    }

    pub const fn signer_index(&self) -> u16 {
        self.signer_index
    }
}

/// Public, keyless output of a preparation pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedProductionDoryV3CeremonyRecord {
    plan_file: FileIdentity,
    body: CeremonyRecordBody,
    record_content_digest: [u8; 32],
    signature_message: [u8; 32],
    required_signers: Vec<RequiredCeremonySigner>,
}

impl PreparedProductionDoryV3CeremonyRecord {
    pub const fn plan_file(&self) -> &FileIdentity {
        &self.plan_file
    }

    pub const fn body(&self) -> &CeremonyRecordBody {
        &self.body
    }

    pub const fn record_content_digest(&self) -> [u8; 32] {
        self.record_content_digest
    }

    pub const fn signature_message(&self) -> [u8; 32] {
        self.signature_message
    }

    pub fn required_signers(&self) -> &[RequiredCeremonySigner] {
        &self.required_signers
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionDoryV3CeremonyRecordStageDurability {
    FileAndParentDirectorySynced,
    FileSyncedParentDirectorySyncAccessDeniedOnWindows,
    FileSyncedParentDirectorySyncUnsupportedOnWindows,
    FileSyncedParentDirectorySyncUnsupportedOnPlatform,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3CeremonyRecordStageReport {
    output: PathBuf,
    plan_file: FileIdentity,
    record_file: FileIdentity,
    record_type: u16,
    record_content_digest: [u8; 32],
    signed_record_digest: [u8; 32],
    signature_message: [u8; 32],
    signer_count: u16,
    durability: ProductionDoryV3CeremonyRecordStageDurability,
    publication_pending: bool,
}

/// Opaque keyless signing request derived only from an anchored type-5 prefix
/// and a retained, exact-roster final-candidate capability.
///
/// The capability deliberately owns both inputs across external signature
/// collection. It is non-cloneable and non-serializable, and staging consumes
/// it so retained artifact guards remain live through the final output check.
#[must_use]
pub struct PreparedProductionDoryV3FinalReceipt {
    transcript: VerifiedCeremonyTranscript,
    candidate: ValidatedProductionDoryV3ModelFinalCandidate,
    body: FinalReceiptBody,
    record_content_digest: [u8; 32],
    signature_message: [u8; 32],
    required_signers: Vec<RequiredCeremonySigner>,
}

impl PreparedProductionDoryV3FinalReceipt {
    pub const fn body(&self) -> &FinalReceiptBody {
        &self.body
    }

    pub const fn ceremony_id(&self) -> [u8; 32] {
        self.transcript.ceremony_id()
    }

    pub const fn record_content_digest(&self) -> [u8; 32] {
        self.record_content_digest
    }

    pub const fn signature_message(&self) -> [u8; 32] {
        self.signature_message
    }

    pub fn required_signers(&self) -> &[RequiredCeremonySigner] {
        &self.required_signers
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3FinalReceiptStageReport {
    output: PathBuf,
    record_file: FileIdentity,
    record_content_digest: [u8; 32],
    signed_record_digest: [u8; 32],
    signature_message: [u8; 32],
    signer_count: u16,
    durability: ProductionDoryV3CeremonyRecordStageDurability,
    publication_pending: bool,
}

struct StagedFinalReceiptRecord {
    record_file: FileIdentity,
    signed_record_digest: [u8; 32],
    signer_count: u16,
    durability: ProductionDoryV3CeremonyRecordStageDurability,
}

impl ProductionDoryV3FinalReceiptStageReport {
    pub fn output(&self) -> &Path {
        &self.output
    }

    pub const fn record_file(&self) -> &FileIdentity {
        &self.record_file
    }

    pub const fn record_content_digest(&self) -> [u8; 32] {
        self.record_content_digest
    }

    pub const fn signed_record_digest(&self) -> [u8; 32] {
        self.signed_record_digest
    }

    pub const fn signature_message(&self) -> [u8; 32] {
        self.signature_message
    }

    pub const fn signer_count(&self) -> u16 {
        self.signer_count
    }

    pub const fn durability(&self) -> ProductionDoryV3CeremonyRecordStageDurability {
        self.durability
    }

    pub const fn publication_pending(&self) -> bool {
        self.publication_pending
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3CeremonyPrefixStageReport {
    output: PathBuf,
    transcript_file: FileIdentity,
    ceremony_id: [u8; 32],
    transcript_derive_key_digest: [u8; 32],
    record_count: u16,
    durability: ProductionDoryV3CeremonyRecordStageDurability,
    publication_pending: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3CompletedTranscriptStageReport {
    output: PathBuf,
    reveal_set_prefix_file: FileIdentity,
    final_receipt_record_file: FileIdentity,
    transcript_file: FileIdentity,
    ceremony_id: [u8; 32],
    transcript_derive_key_digest: [u8; 32],
    record_count: u16,
    durability: ProductionDoryV3CeremonyRecordStageDurability,
    publication_pending: bool,
}

/// Public signing request reconstructed from one exact, terminal transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedProductionDoryV3CeremonyAttestation {
    transcript_path: PathBuf,
    transcript_bytes_exact: Vec<u8>,
    transcript_file: FileIdentity,
    transcript: VerifiedCeremonyTranscript,
    signature_message: [u8; 32],
    required_signers: Vec<RequiredCeremonySigner>,
}

impl PreparedProductionDoryV3CeremonyAttestation {
    pub fn transcript_path(&self) -> &Path {
        &self.transcript_path
    }

    pub const fn transcript_file(&self) -> &FileIdentity {
        &self.transcript_file
    }

    pub const fn status(&self) -> CeremonyTranscriptStatus {
        self.transcript.status()
    }

    pub const fn ceremony_id(&self) -> [u8; 32] {
        self.transcript.ceremony_id()
    }

    pub const fn transcript_derive_key_digest(&self) -> [u8; 32] {
        self.transcript.transcript_derive_key_digest()
    }

    pub const fn signature_message(&self) -> [u8; 32] {
        self.signature_message
    }

    pub fn required_signers(&self) -> &[RequiredCeremonySigner] {
        &self.required_signers
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3CeremonyAttestationStageReport {
    output: PathBuf,
    transcript_file: FileIdentity,
    attestation_file: FileIdentity,
    status: CeremonyTranscriptStatus,
    ceremony_id: [u8; 32],
    transcript_derive_key_digest: [u8; 32],
    signature_message: [u8; 32],
    staged_signers: Vec<RequiredCeremonySigner>,
    signer_count: u16,
    durability: ProductionDoryV3CeremonyRecordStageDurability,
    publication_pending: bool,
}

impl ProductionDoryV3CeremonyAttestationStageReport {
    pub fn output(&self) -> &Path {
        &self.output
    }

    pub const fn transcript_file(&self) -> &FileIdentity {
        &self.transcript_file
    }

    pub const fn attestation_file(&self) -> &FileIdentity {
        &self.attestation_file
    }

    pub const fn status(&self) -> CeremonyTranscriptStatus {
        self.status
    }

    pub const fn ceremony_id(&self) -> [u8; 32] {
        self.ceremony_id
    }

    pub const fn transcript_derive_key_digest(&self) -> [u8; 32] {
        self.transcript_derive_key_digest
    }

    pub const fn signature_message(&self) -> [u8; 32] {
        self.signature_message
    }

    pub fn staged_signers(&self) -> &[RequiredCeremonySigner] {
        &self.staged_signers
    }

    pub const fn signer_count(&self) -> u16 {
        self.signer_count
    }

    pub const fn durability(&self) -> ProductionDoryV3CeremonyRecordStageDurability {
        self.durability
    }

    pub const fn publication_pending(&self) -> bool {
        self.publication_pending
    }
}

impl ProductionDoryV3CeremonyPrefixStageReport {
    pub fn output(&self) -> &Path {
        &self.output
    }

    pub const fn transcript_file(&self) -> &FileIdentity {
        &self.transcript_file
    }

    pub const fn ceremony_id(&self) -> [u8; 32] {
        self.ceremony_id
    }

    pub const fn transcript_derive_key_digest(&self) -> [u8; 32] {
        self.transcript_derive_key_digest
    }

    pub const fn record_count(&self) -> u16 {
        self.record_count
    }

    pub const fn durability(&self) -> ProductionDoryV3CeremonyRecordStageDurability {
        self.durability
    }

    pub const fn publication_pending(&self) -> bool {
        self.publication_pending
    }
}

impl ProductionDoryV3CompletedTranscriptStageReport {
    pub fn output(&self) -> &Path {
        &self.output
    }

    pub const fn reveal_set_prefix_file(&self) -> &FileIdentity {
        &self.reveal_set_prefix_file
    }

    pub const fn final_receipt_record_file(&self) -> &FileIdentity {
        &self.final_receipt_record_file
    }

    pub const fn transcript_file(&self) -> &FileIdentity {
        &self.transcript_file
    }

    pub const fn ceremony_id(&self) -> [u8; 32] {
        self.ceremony_id
    }

    pub const fn transcript_derive_key_digest(&self) -> [u8; 32] {
        self.transcript_derive_key_digest
    }

    pub const fn record_count(&self) -> u16 {
        self.record_count
    }

    pub const fn durability(&self) -> ProductionDoryV3CeremonyRecordStageDurability {
        self.durability
    }

    pub const fn publication_pending(&self) -> bool {
        self.publication_pending
    }
}

impl ProductionDoryV3CeremonyRecordStageReport {
    pub fn output(&self) -> &Path {
        &self.output
    }

    pub const fn plan_file(&self) -> &FileIdentity {
        &self.plan_file
    }

    pub const fn record_file(&self) -> &FileIdentity {
        &self.record_file
    }

    pub const fn record_type(&self) -> u16 {
        self.record_type
    }

    pub const fn record_content_digest(&self) -> [u8; 32] {
        self.record_content_digest
    }

    pub const fn signed_record_digest(&self) -> [u8; 32] {
        self.signed_record_digest
    }

    pub const fn signature_message(&self) -> [u8; 32] {
        self.signature_message
    }

    pub const fn signer_count(&self) -> u16 {
        self.signer_count
    }

    pub const fn durability(&self) -> ProductionDoryV3CeremonyRecordStageDurability {
        self.durability
    }

    pub const fn publication_pending(&self) -> bool {
        self.publication_pending
    }
}

#[derive(Debug, Error)]
pub enum ProductionDoryV3CeremonyAuthoringError {
    #[error("trusted ceremony filesystem rejected an artifact: {0}")]
    Filesystem(String),
    #[error("strict ceremony plan JSON is invalid: {0}")]
    PlanJson(#[from] serde_json::Error),
    #[error("ceremony transcript codec or signature verification failed: {0}")]
    Transcript(#[from] CeremonyTranscriptError),
    #[error("production Dory V3 final-candidate validation failed: {0}")]
    FinalCandidate(#[from] ProductionDoryV3ModelFinalCandidateValidationError),
    #[error("failed to read trusted input {path}: {source}")]
    ReadInput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("trusted input changed between authentication passes: {0}")]
    InputChanged(PathBuf),
    #[error("trusted input exceeds its size cap: {0}")]
    InputTooLarge(PathBuf),
    #[error("duplicate trusted input path: {0}")]
    DuplicateInput(PathBuf),
    #[error("invalid lowercase hexadecimal field {0}")]
    InvalidHex(&'static str),
    #[error("prior record sequence is invalid: {0}")]
    InvalidPriorSequence(&'static str),
    #[error("plan does not describe the next canonical ceremony record")]
    WrongNextRecord,
    #[error("Genesis preparation must not receive an expected ceremony-id anchor")]
    UnexpectedCeremonyIdAnchor,
    #[error("post-Genesis preparation requires an independently supplied ceremony-id anchor")]
    MissingCeremonyIdAnchor,
    #[error("the prior Genesis content digest does not match the trusted ceremony-id anchor")]
    CeremonyIdAnchorMismatch,
    #[error("trusted contribution contains a byte outside the production range")]
    ContributionByteRange,
    #[error("trusted contribution does not match its signed commitment")]
    ContributionIdentityMismatch,
    #[error("generator binary does not match the selected Genesis reference target")]
    GeneratorBinaryMismatch,
    #[error("declared ceremony time is zero or outside its frozen deadline")]
    Deadline,
    #[error("external signatures do not occupy the exact required signer slots")]
    SignerPolicy,
    #[error("reopened staged output differs from the prepared canonical bytes")]
    StagedOutputChanged,
    #[error("retained final-candidate projection differs from the prepared type-6 body")]
    FinalCandidateProjectionChanged,
    #[error("an external retained-input guard failed before final-candidate reauthentication: {0}")]
    RetainedInputGuard(String),
    #[error("failed to clean an unconfirmed output; original: {original}; cleanup: {cleanup}")]
    OutputCleanup { original: String, cleanup: String },
}

impl From<CeremonyFsError> for ProductionDoryV3CeremonyAuthoringError {
    fn from(error: CeremonyFsError) -> Self {
        Self::Filesystem(error.to_string())
    }
}

/// Authenticate a strict plan and all files and prior records it names, then
/// derive the exact canonical body and public BIP340 signing request.
pub fn prepare_production_dory_v3_ceremony_record(
    plan_path: &Path,
    expected_ceremony_id: Option<[u8; 32]>,
) -> Result<PreparedProductionDoryV3CeremonyRecord, ProductionDoryV3CeremonyAuthoringError> {
    let (plan_bytes, plan_file) =
        authenticate_small_file(plan_path, PRODUCTION_DORY_V3_CEREMONY_PLAN_MAX_BYTES)?;
    let plan: ProductionDoryV3CeremonyRecordPlan = serde_json::from_slice(&plan_bytes)?;
    prepare_decoded_plan(plan, plan_file, expected_ceremony_id)
}

/// Repeat preparation, verify only externally supplied BIP340 signatures, and
/// create-new stage the canonical signed record. Publication is deliberately a
/// separate operation outside this module.
pub fn stage_production_dory_v3_ceremony_record(
    plan_path: &Path,
    expected_ceremony_id: Option<[u8; 32]>,
    mut signatures: Vec<RecordSignature>,
    output_path: &Path,
) -> Result<ProductionDoryV3CeremonyRecordStageReport, ProductionDoryV3CeremonyAuthoringError> {
    let prepared = prepare_production_dory_v3_ceremony_record(plan_path, expected_ceremony_id)?;
    signatures.sort_by_key(|signature| (signature.signer_class, signature.signer_index));
    verify_external_signatures(&prepared, &signatures)?;

    let record = SignedCeremonyRecord {
        body: prepared.body.clone(),
        signatures,
    };
    let encoded = encode_ceremony_record(&record)?;
    let signed_record_digest = ceremony_signed_record_digest(&record)?;
    let signer_count = u16::try_from(record.signatures.len())
        .map_err(|_| CeremonyTranscriptError::Limit("signature count"))?;
    let record_file = file_identity_for_bytes(&encoded);
    let expected = record.clone();
    let durability = persist_record(output_path, &encoded, |reopened| {
        let decoded = decode_ceremony_record(reopened)?;
        if decoded != expected || encode_ceremony_record(&decoded)? != reopened {
            return Err(ProductionDoryV3CeremonyAuthoringError::StagedOutputChanged);
        }
        Ok(())
    })?;

    Ok(ProductionDoryV3CeremonyRecordStageReport {
        output: output_path.to_path_buf(),
        plan_file: prepared.plan_file,
        record_file,
        record_type: prepared.body.record_type(),
        record_content_digest: prepared.record_content_digest,
        signed_record_digest,
        signature_message: prepared.signature_message,
        signer_count,
        durability,
        publication_pending: true,
    })
}

/// Consume an anchored type-5 prefix and one exact-roster retained candidate,
/// then derive the complete canonical type-6 body and public signing request.
/// No caller supplies receipt hashes, file identities, or signer slots.
pub fn prepare_production_dory_v3_final_receipt(
    transcript: VerifiedCeremonyTranscript,
    mut candidate: ValidatedProductionDoryV3ModelFinalCandidate,
) -> Result<PreparedProductionDoryV3FinalReceipt, ProductionDoryV3CeremonyAuthoringError> {
    let body = candidate.derive_final_receipt_body(&transcript)?;
    let record_body = CeremonyRecordBody::FinalReceipt(Box::new(body.clone()));
    let genesis = transcript
        .records()
        .first()
        .and_then(|record| match &record.body {
            CeremonyRecordBody::Genesis(genesis) => Some(genesis.as_ref()),
            _ => None,
        })
        .ok_or(
            ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence("missing Genesis roster"),
        )?;
    let required_signers = required_signers_for_body(&record_body, Some(genesis))?;
    let record_content_digest = ceremony_record_content_digest(&record_body)?;
    let signature_message = ceremony_record_signature_message(&record_body)?;

    Ok(PreparedProductionDoryV3FinalReceipt {
        transcript,
        candidate,
        body,
        record_content_digest,
        signature_message,
        required_signers,
    })
}

/// Verify the exact externally supplied full-roster signatures and create-new
/// stage the canonical type-6 record. The retained final candidate is checked
/// once before signing material is accepted and again after the output is
/// reopened; its bank guard remains the last retained-artifact check.
pub fn stage_production_dory_v3_final_receipt(
    prepared: PreparedProductionDoryV3FinalReceipt,
    signatures: Vec<RecordSignature>,
    output_path: &Path,
) -> Result<ProductionDoryV3FinalReceiptStageReport, ProductionDoryV3CeremonyAuthoringError> {
    stage_production_dory_v3_final_receipt_with_retained_input_guard(
        prepared,
        signatures,
        output_path,
        || Ok(()),
    )
}

pub(crate) fn stage_production_dory_v3_final_receipt_with_retained_input_guard(
    mut prepared: PreparedProductionDoryV3FinalReceipt,
    signatures: Vec<RecordSignature>,
    output_path: &Path,
    mut retained_input_guard: impl FnMut() -> Result<(), ProductionDoryV3CeremonyAuthoringError>,
) -> Result<ProductionDoryV3FinalReceiptStageReport, ProductionDoryV3CeremonyAuthoringError> {
    retained_input_guard()?;
    let refreshed = prepared
        .candidate
        .derive_final_receipt_body(&prepared.transcript)?;
    if refreshed != prepared.body {
        return Err(ProductionDoryV3CeremonyAuthoringError::FinalCandidateProjectionChanged);
    }

    let staged = persist_production_dory_v3_final_receipt(
        &prepared.body,
        &prepared.required_signers,
        signatures,
        output_path,
        retained_input_guard,
        || {
            prepared
                .candidate
                .derive_final_receipt_body(&prepared.transcript)
                .map_err(Into::into)
        },
    )?;

    Ok(ProductionDoryV3FinalReceiptStageReport {
        output: output_path.to_path_buf(),
        record_file: staged.record_file,
        record_content_digest: prepared.record_content_digest,
        signed_record_digest: staged.signed_record_digest,
        signature_message: prepared.signature_message,
        signer_count: staged.signer_count,
        durability: staged.durability,
        publication_pending: true,
    })
}

fn persist_production_dory_v3_final_receipt(
    body: &FinalReceiptBody,
    required_signers: &[RequiredCeremonySigner],
    signatures: Vec<RecordSignature>,
    output_path: &Path,
    retained_input_guard: impl FnOnce() -> Result<(), ProductionDoryV3CeremonyAuthoringError>,
    final_guard: impl FnOnce() -> Result<FinalReceiptBody, ProductionDoryV3CeremonyAuthoringError>,
) -> Result<StagedFinalReceiptRecord, ProductionDoryV3CeremonyAuthoringError> {
    let record = SignedCeremonyRecord {
        body: CeremonyRecordBody::FinalReceipt(Box::new(body.clone())),
        signatures,
    };
    verify_signatures_against(&record, required_signers)?;

    let encoded = encode_ceremony_record(&record)?;
    let record_file = file_identity_for_bytes(&encoded);
    let signed_record_digest = ceremony_signed_record_digest(&record)?;
    let signer_count = u16::try_from(record.signatures.len())
        .map_err(|_| CeremonyTranscriptError::Limit("signature count"))?;
    let expected = record.clone();
    let durability = persist_record(output_path, &encoded, |reopened| {
        let decoded = decode_ceremony_record(reopened)?;
        if decoded != expected || encode_ceremony_record(&decoded)? != reopened {
            return Err(ProductionDoryV3CeremonyAuthoringError::StagedOutputChanged);
        }
        retained_input_guard()?;
        if final_guard()? != *body {
            return Err(ProductionDoryV3CeremonyAuthoringError::FinalCandidateProjectionChanged);
        }
        Ok(())
    })?;
    Ok(StagedFinalReceiptRecord {
        record_file,
        signed_record_digest,
        signer_count,
        durability,
    })
}

/// Authenticate immutable type-1-through-type-5 record files and create-new
/// stage their exact canonical reveal-set-closed transcript prefix. The
/// independently supplied ceremony ID remains mandatory, and publication is a
/// separate append-only bulletin operation.
pub fn stage_production_dory_v3_ceremony_reveal_set_prefix(
    record_paths: &[PathBuf],
    expected_ceremony_id: [u8; 32],
    output_path: &Path,
) -> Result<ProductionDoryV3CeremonyPrefixStageReport, ProductionDoryV3CeremonyAuthoringError> {
    let records = authenticate_prior_record_files(record_paths)?;
    let prefix = verify_authoring_prefix(&records)?;
    if prefix.ceremony_id != expected_ceremony_id {
        return Err(ProductionDoryV3CeremonyAuthoringError::CeremonyIdAnchorMismatch);
    }
    if prefix.state != PrefixState::Closed {
        return Err(ProductionDoryV3CeremonyAuthoringError::WrongNextRecord);
    }

    let encoded = encode_and_verify_reveal_set_prefix(&records, expected_ceremony_id)?;
    let verified = parse_and_verify_reveal_set_prefix(&encoded, expected_ceremony_id)?;
    let transcript_file = file_identity_for_bytes(&encoded);
    let transcript_derive_key_digest = verified.transcript_derive_key_digest();
    let record_count = u16::try_from(records.len())
        .map_err(|_| CeremonyTranscriptError::Limit("transcript record count"))?;
    let expected_records = records.clone();
    let durability = persist_record(output_path, &encoded, |reopened| {
        let reparsed = parse_and_verify_reveal_set_prefix(reopened, expected_ceremony_id)?;
        if reparsed.records() != expected_records
            || reparsed.transcript_derive_key_digest() != transcript_derive_key_digest
            || file_identity_for_bytes(reopened) != transcript_file
        {
            return Err(ProductionDoryV3CeremonyAuthoringError::StagedOutputChanged);
        }
        Ok(())
    })?;

    Ok(ProductionDoryV3CeremonyPrefixStageReport {
        output: output_path.to_path_buf(),
        transcript_file,
        ceremony_id: expected_ceremony_id,
        transcript_derive_key_digest,
        record_count,
        durability,
        publication_pending: true,
    })
}

/// Authenticate one exact staged type-5 prefix and one exact signed type-6
/// record, rebuild the canonical completed transcript, and create-new stage it.
/// Both input handles remain retained until the reopened output is verified,
/// both inputs are authenticated one final time, the parent is synchronized,
/// and the output is confirmed. Publication remains a separate append-only
/// bulletin operation.
pub fn stage_production_dory_v3_completed_ceremony_transcript(
    reveal_set_prefix_path: &Path,
    final_receipt_record_path: &Path,
    expected_ceremony_id: [u8; 32],
    output_path: &Path,
) -> Result<ProductionDoryV3CompletedTranscriptStageReport, ProductionDoryV3CeremonyAuthoringError>
{
    stage_production_dory_v3_completed_ceremony_transcript_with_final_reauthentication_hook(
        reveal_set_prefix_path,
        final_receipt_record_path,
        expected_ceremony_id,
        output_path,
        || Ok(()),
    )
}

fn stage_production_dory_v3_completed_ceremony_transcript_with_final_reauthentication_hook(
    reveal_set_prefix_path: &Path,
    final_receipt_record_path: &Path,
    expected_ceremony_id: [u8; 32],
    output_path: &Path,
    before_final_reauthentication: impl FnOnce() -> Result<(), ProductionDoryV3CeremonyAuthoringError>,
) -> Result<ProductionDoryV3CompletedTranscriptStageReport, ProductionDoryV3CeremonyAuthoringError>
{
    if reveal_set_prefix_path == final_receipt_record_path {
        return Err(ProductionDoryV3CeremonyAuthoringError::DuplicateInput(
            final_receipt_record_path.to_path_buf(),
        ));
    }

    let mut prefix = RetainedAuthenticatedSmallFile::open(
        reveal_set_prefix_path,
        MAX_CEREMONY_TRANSCRIPT_BYTES,
    )?;
    let mut final_receipt = RetainedAuthenticatedSmallFile::open(
        final_receipt_record_path,
        MAX_SIGNED_CEREMONY_RECORD_BYTES,
    )?;
    if prefix.input.identity() == final_receipt.input.identity() {
        return Err(ProductionDoryV3CeremonyAuthoringError::DuplicateInput(
            final_receipt_record_path.to_path_buf(),
        ));
    }

    let verified_prefix = parse_and_verify_reveal_set_prefix(&prefix.bytes, expected_ceremony_id)?;
    let final_receipt_record = decode_ceremony_record(&final_receipt.bytes)?;
    if encode_ceremony_record(&final_receipt_record)? != final_receipt.bytes {
        return Err(
            ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence(
                "noncanonical final receipt record encoding",
            ),
        );
    }
    if !matches!(
        &final_receipt_record.body,
        CeremonyRecordBody::FinalReceipt(_)
    ) {
        return Err(ProductionDoryV3CeremonyAuthoringError::WrongNextRecord);
    }
    let genesis = verified_prefix
        .records()
        .first()
        .and_then(|record| match &record.body {
            CeremonyRecordBody::Genesis(genesis) => Some(genesis.as_ref()),
            _ => None,
        })
        .ok_or(
            ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence("missing Genesis roster"),
        )?;
    let required_signers = required_signers_for_body(&final_receipt_record.body, Some(genesis))?;
    verify_signatures_against(&final_receipt_record, &required_signers)?;

    let mut records = verified_prefix.records().to_vec();
    records.push(final_receipt_record);
    let encoded = encode_and_verify_ceremony_transcript(&records)?;
    let completed = parse_and_verify_completed_ceremony_transcript(&encoded, expected_ceremony_id)?;
    if completed.records() != records {
        return Err(ProductionDoryV3CeremonyAuthoringError::StagedOutputChanged);
    }

    let reveal_set_prefix_file = prefix.file_identity.clone();
    let final_receipt_record_file = final_receipt.file_identity.clone();
    let transcript_file = file_identity_for_bytes(&encoded);
    let transcript_derive_key_digest = completed.transcript_derive_key_digest();
    let record_count = u16::try_from(completed.records().len())
        .map_err(|_| CeremonyTranscriptError::Limit("transcript record count"))?;

    let output_parent = TrustedCeremonyParent::for_artifact(output_path)?;
    let mut output = PendingOutput::create(&output_parent, output_path)?;
    let completion = (|| {
        output.write_all(&encoded)?;
        output.sync_file()?;
        let reopened = output.reopen_exact(&output_parent, &encoded)?;
        let reparsed =
            parse_and_verify_completed_ceremony_transcript(&reopened, expected_ceremony_id)?;
        if reparsed != completed
            || encode_and_verify_ceremony_transcript(reparsed.records())? != reopened
            || file_identity_for_bytes(&reopened) != transcript_file
        {
            return Err(ProductionDoryV3CeremonyAuthoringError::StagedOutputChanged);
        }
        before_final_reauthentication()?;
        prefix.reauthenticate_exact()?;
        final_receipt.reauthenticate_exact()?;
        let durability = map_durability(output.sync_parent(&output_parent)?);
        Ok(durability)
    })();
    let confirmed = finish_pending_output(output, &output_parent, completion);

    // Keep both authenticated inputs and their trusted parent handles alive
    // through `PendingOutput::confirm`, including its final identity checks.
    drop(final_receipt);
    drop(prefix);
    let durability = confirmed?;

    Ok(ProductionDoryV3CompletedTranscriptStageReport {
        output: output_path.to_path_buf(),
        reveal_set_prefix_file,
        final_receipt_record_file,
        transcript_file,
        ceremony_id: completed.ceremony_id(),
        transcript_derive_key_digest,
        record_count,
        durability,
        publication_pending: true,
    })
}

/// Authenticate one exact terminal transcript twice, require an independent
/// ceremony-ID anchor, and return only public detached-attestation signing
/// material. Completed transcripts always require the full frozen roster.
/// Aborted transcripts require an explicit nonempty roster subset. Its order
/// is canonicalized, while duplicate slots are rejected.
pub fn prepare_production_dory_v3_ceremony_attestation(
    transcript_path: &Path,
    expected_ceremony_id: [u8; 32],
    aborted_signers: &[ProductionDoryV3CeremonyAttestationSigner],
) -> Result<PreparedProductionDoryV3CeremonyAttestation, ProductionDoryV3CeremonyAuthoringError> {
    let (transcript_bytes_exact, transcript_file) =
        authenticate_small_file(transcript_path, MAX_CEREMONY_TRANSCRIPT_BYTES)?;
    let transcript = parse_and_verify_ceremony_transcript(&transcript_bytes_exact)?;
    if transcript.ceremony_id() != expected_ceremony_id {
        return Err(ProductionDoryV3CeremonyAuthoringError::CeremonyIdAnchorMismatch);
    }
    let required_signers = required_attestation_signers_for_status(
        transcript.status(),
        transcript.operators(),
        transcript.reproducers(),
        aborted_signers,
    )?;
    let unsigned = detached_attestation_from_transcript(
        &transcript,
        required_signers
            .iter()
            .map(|signer| RecordSignature {
                signer_class: signer.signer_class,
                signer_index: signer.signer_index,
                signature: [0; 64],
            })
            .collect(),
    );
    let signature_message = ceremony_attestation_signature_message(&unsigned)?;
    Ok(PreparedProductionDoryV3CeremonyAttestation {
        transcript_path: transcript_path.to_path_buf(),
        transcript_bytes_exact,
        transcript_file,
        transcript,
        signature_message,
        required_signers,
    })
}

/// Repeat terminal-transcript preparation, verify externally produced BIP340
/// signatures, and create-new stage one detached attestation. The exact
/// aborted signer subset must be repeated from preparation. No secret-key,
/// signing, seed, publication, or activation capability is present here.
pub fn stage_production_dory_v3_ceremony_attestation(
    transcript_path: &Path,
    expected_ceremony_id: [u8; 32],
    aborted_signers: &[ProductionDoryV3CeremonyAttestationSigner],
    mut signatures: Vec<RecordSignature>,
    output_path: &Path,
) -> Result<ProductionDoryV3CeremonyAttestationStageReport, ProductionDoryV3CeremonyAuthoringError>
{
    // This gate deliberately precedes every transcript filesystem operation.
    if signatures.is_empty() {
        return Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy);
    }
    let prepared = prepare_production_dory_v3_ceremony_attestation(
        transcript_path,
        expected_ceremony_id,
        aborted_signers,
    )?;
    signatures.sort_by_key(|signature| (signature.signer_class, signature.signer_index));
    if signatures.len() != prepared.required_signers.len()
        || signatures
            .iter()
            .zip(&prepared.required_signers)
            .any(|(actual, expected)| {
                actual.signer_class != expected.signer_class
                    || actual.signer_index != expected.signer_index
            })
    {
        return Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy);
    }

    let attestation = detached_attestation_from_transcript(&prepared.transcript, signatures);
    let signature_message = ceremony_attestation_signature_message(&attestation)?;
    if signature_message != prepared.signature_message {
        return Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy);
    }
    let encoded = encode_detached_transcript_attestation(&attestation)?;
    let verified = verify_detached_transcript_attestation(&encoded, &prepared.transcript)?;
    if verified != attestation {
        return Err(ProductionDoryV3CeremonyAuthoringError::StagedOutputChanged);
    }
    let attestation_file = file_identity_for_bytes(&encoded);
    let expected_attestation = attestation.clone();
    let durability = persist_record(output_path, &encoded, |reopened| {
        let reopened_attestation =
            verify_detached_transcript_attestation(reopened, &prepared.transcript)?;
        if reopened_attestation != expected_attestation
            || encode_detached_transcript_attestation(&reopened_attestation)? != reopened
            || file_identity_for_bytes(reopened) != attestation_file
        {
            return Err(ProductionDoryV3CeremonyAuthoringError::StagedOutputChanged);
        }

        // Reauthenticate the immutable input only after the staged output has
        // been reopened and verified, closing the input/output TOCTOU window.
        let (final_transcript_bytes, final_transcript_file) =
            authenticate_small_file(transcript_path, MAX_CEREMONY_TRANSCRIPT_BYTES)?;
        if final_transcript_bytes != prepared.transcript_bytes_exact
            || final_transcript_file != prepared.transcript_file
        {
            return Err(ProductionDoryV3CeremonyAuthoringError::InputChanged(
                transcript_path.to_path_buf(),
            ));
        }
        let final_transcript = parse_and_verify_ceremony_transcript(&final_transcript_bytes)?;
        if final_transcript != prepared.transcript
            || final_transcript.ceremony_id() != expected_ceremony_id
        {
            return Err(ProductionDoryV3CeremonyAuthoringError::InputChanged(
                transcript_path.to_path_buf(),
            ));
        }
        Ok(())
    })?;
    let signer_count = u16::try_from(attestation.signatures.len())
        .map_err(|_| CeremonyTranscriptError::Limit("attestation signature count"))?;

    Ok(ProductionDoryV3CeremonyAttestationStageReport {
        output: output_path.to_path_buf(),
        transcript_file: prepared.transcript_file,
        attestation_file,
        status: prepared.transcript.status(),
        ceremony_id: prepared.transcript.ceremony_id(),
        transcript_derive_key_digest: prepared.transcript.transcript_derive_key_digest(),
        signature_message,
        staged_signers: prepared.required_signers,
        signer_count,
        durability,
        publication_pending: true,
    })
}

fn detached_attestation_from_transcript(
    transcript: &VerifiedCeremonyTranscript,
    signatures: Vec<RecordSignature>,
) -> DetachedTranscriptAttestation {
    DetachedTranscriptAttestation {
        ceremony_id: transcript.ceremony_id(),
        transcript_bytes: transcript.transcript_bytes(),
        transcript_derive_key_digest: transcript.transcript_derive_key_digest(),
        transcript_blake3: transcript.transcript_blake3(),
        transcript_sha256: transcript.transcript_sha256(),
        signatures,
    }
}

fn required_attestation_signers_for_status(
    status: CeremonyTranscriptStatus,
    operators: &[[u8; 32]],
    reproducers: &[[u8; 32]],
    aborted_signers: &[ProductionDoryV3CeremonyAttestationSigner],
) -> Result<Vec<RequiredCeremonySigner>, ProductionDoryV3CeremonyAuthoringError> {
    if status == CeremonyTranscriptStatus::Completed {
        if !aborted_signers.is_empty() {
            return Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy);
        }
        return Ok(operators
            .iter()
            .enumerate()
            .map(|(index, public_key)| RequiredCeremonySigner {
                signer_class: SignerClass::Operator,
                signer_index: u16::try_from(index).expect("operator roster is capped at u16"),
                public_key: *public_key,
            })
            .chain(reproducers.iter().enumerate().map(|(index, public_key)| {
                RequiredCeremonySigner {
                    signer_class: SignerClass::Reproducer,
                    signer_index: u16::try_from(index).expect("reproducer roster is capped at u16"),
                    public_key: *public_key,
                }
            }))
            .collect());
    }
    if status != CeremonyTranscriptStatus::Aborted || aborted_signers.is_empty() {
        return Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy);
    }

    let mut canonical_signers = aborted_signers.to_vec();
    canonical_signers.sort_by_key(|signer| (signer.signer_class, signer.signer_index));
    if canonical_signers.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy);
    }

    let mut required = Vec::with_capacity(canonical_signers.len());
    for signer in canonical_signers {
        let roster = match signer.signer_class {
            SignerClass::Operator => operators,
            SignerClass::Reproducer => reproducers,
        };
        let Some(public_key) = roster.get(usize::from(signer.signer_index)) else {
            return Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy);
        };
        required.push(RequiredCeremonySigner {
            signer_class: signer.signer_class,
            signer_index: signer.signer_index,
            public_key: *public_key,
        });
    }
    Ok(required)
}

fn prepare_decoded_plan(
    plan: ProductionDoryV3CeremonyRecordPlan,
    plan_file: FileIdentity,
    expected_ceremony_id: Option<[u8; 32]>,
) -> Result<PreparedProductionDoryV3CeremonyRecord, ProductionDoryV3CeremonyAuthoringError> {
    let (body, required_signers) = match plan {
        ProductionDoryV3CeremonyRecordPlan::Genesis(plan) => {
            if expected_ceremony_id.is_some() {
                return Err(ProductionDoryV3CeremonyAuthoringError::UnexpectedCeremonyIdAnchor);
            }
            prepare_genesis(*plan)?
        }
        ProductionDoryV3CeremonyRecordPlan::ContributionCommitment(plan) => {
            prepare_contribution_commitment(*plan, require_ceremony_anchor(expected_ceremony_id)?)?
        }
        ProductionDoryV3CeremonyRecordPlan::CommitmentSet(plan) => {
            prepare_commitment_set(*plan, require_ceremony_anchor(expected_ceremony_id)?)?
        }
        ProductionDoryV3CeremonyRecordPlan::ContributionReveal(plan) => {
            prepare_contribution_reveal(*plan, require_ceremony_anchor(expected_ceremony_id)?)?
        }
        ProductionDoryV3CeremonyRecordPlan::RevealSet(plan) => {
            prepare_reveal_set(*plan, require_ceremony_anchor(expected_ceremony_id)?)?
        }
    };
    let record_content_digest = ceremony_record_content_digest(&body)?;
    let signature_message = ceremony_record_signature_message(&body)?;
    Ok(PreparedProductionDoryV3CeremonyRecord {
        plan_file,
        body,
        record_content_digest,
        signature_message,
        required_signers,
    })
}

fn require_ceremony_anchor(
    expected_ceremony_id: Option<[u8; 32]>,
) -> Result<[u8; 32], ProductionDoryV3CeremonyAuthoringError> {
    expected_ceremony_id.ok_or(ProductionDoryV3CeremonyAuthoringError::MissingCeremonyIdAnchor)
}

fn prepare_genesis(
    plan: GenesisPlan,
) -> Result<(CeremonyRecordBody, Vec<RequiredCeremonySigner>), ProductionDoryV3CeremonyAuthoringError>
{
    let source_commit_sha1 = parse_lower_hex::<20>(&plan.source_commit_sha1, "source_commit_sha1")?;
    let source_bundle = authenticate_file_identity(&plan.source_bundle, None, false)?;
    let source_bundle_policy = authenticate_file_identity(&plan.source_bundle_policy, None, false)?;
    let cargo_lock = authenticate_file_identity(&plan.cargo_lock, None, false)?;
    let protocol_spec = authenticate_file_identity(&plan.protocol_spec, None, false)?;
    let bulletin_policy = authenticate_file_identity(&plan.bulletin_policy, None, false)?;

    let mut reference_binaries = Vec::with_capacity(plan.reference_binaries.len());
    for input in plan.reference_binaries {
        let rustc_vv = authenticate_file_identity(&input.rustc_vv, None, false)?;
        let build_environment = authenticate_file_identity(&input.build_environment, None, false)?;
        let binary = authenticate_file_identity(&input.binary, None, false)?;
        reference_binaries.push(ReferenceBinary {
            target_id: input.target_id,
            rustc_vv,
            build_environment,
            binary_blake3: binary.blake3,
            binary_sha256: binary.sha256,
        });
    }

    let structural_analyzer =
        authenticate_file_identity(&plan.structural_analyzer_binary, None, false)?;
    let operators = prepare_roster(plan.operators)?;
    let reproducers = prepare_roster(plan.reproducers)?;
    let body = CeremonyRecordBody::Genesis(Box::new(GenesisBody {
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
        commit_deadline_unix_seconds: plan.commit_deadline_unix_seconds,
        reveal_deadline_unix_seconds: plan.reveal_deadline_unix_seconds,
        source_commit_sha1,
        source_bundle,
        source_bundle_policy,
        cargo_lock_blake3: cargo_lock.blake3,
        cargo_lock_sha256: cargo_lock.sha256,
        protocol_spec_blake3: protocol_spec.blake3,
        protocol_spec_sha256: protocol_spec.sha256,
        bulletin_policy,
        reference_binaries,
        structural_analyzer_target_id: plan.structural_analyzer_target_id,
        structural_analyzer_blake3: structural_analyzer.blake3,
        structural_analyzer_sha256: structural_analyzer.sha256,
        production_suite_digest: production_dory_v3_suite_digest().into_bytes(),
        dory_setup_identity: DORY_V3_SETUP_IDENTITY.into_bytes(),
        operators,
        reproducers,
    }));
    let signers = required_signers_for_body(&body, None)?;
    Ok((body, signers))
}

fn prepare_roster(
    plans: Vec<RosterMemberPlan>,
) -> Result<Vec<RosterMember>, ProductionDoryV3CeremonyAuthoringError> {
    let mut members = Vec::with_capacity(plans.len());
    for plan in plans {
        members.push(RosterMember {
            index: plan.index,
            public_key: parse_lower_hex::<32>(&plan.public_key, "roster public_key")?,
            identity_document: authenticate_file_identity(&plan.identity_document, None, false)?,
        });
    }
    Ok(members)
}

fn prepare_contribution_commitment(
    plan: ContributionCommitmentPlan,
    expected_ceremony_id: [u8; 32],
) -> Result<(CeremonyRecordBody, Vec<RequiredCeremonySigner>), ProductionDoryV3CeremonyAuthoringError>
{
    let prefix = authenticate_prior_records(&plan.prior_records, expected_ceremony_id)?;
    let PrefixState::Commitments { next_operator } = prefix.state else {
        return Err(ProductionDoryV3CeremonyAuthoringError::WrongNextRecord);
    };
    if plan.operator_index != next_operator {
        return Err(ProductionDoryV3CeremonyAuthoringError::WrongNextRecord);
    }
    if plan.generation_finished_unix_seconds == 0
        || plan.generation_finished_unix_seconds > prefix.genesis.commit_deadline_unix_seconds
    {
        return Err(ProductionDoryV3CeremonyAuthoringError::Deadline);
    }
    let expected_source = PRODUCTION_PAYLOAD_BYTES
        .checked_add(plan.rejected_source_bytes)
        .ok_or(
            ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence(
                "source byte accounting overflow",
            ),
        )?;
    if plan.source_bytes_consumed != expected_source {
        return Err(
            ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence("source byte accounting"),
        );
    }
    let contribution = authenticate_file_identity(
        &plan.contribution_file,
        Some(PRODUCTION_PAYLOAD_BYTES),
        true,
    )?;
    let generator = authenticate_file_identity(&plan.generator_binary, None, false)?;
    let reference = prefix
        .genesis
        .reference_binaries
        .iter()
        .find(|reference| reference.target_id == plan.generator_target_id)
        .ok_or(ProductionDoryV3CeremonyAuthoringError::GeneratorBinaryMismatch)?;
    if reference.binary_blake3 != generator.blake3 || reference.binary_sha256 != generator.sha256 {
        return Err(ProductionDoryV3CeremonyAuthoringError::GeneratorBinaryMismatch);
    }
    let entropy_attestation = authenticate_file_identity(&plan.entropy_attestation, None, false)?;
    let operator = prefix
        .genesis
        .operators
        .get(usize::from(plan.operator_index))
        .filter(|operator| operator.index == plan.operator_index)
        .ok_or(ProductionDoryV3CeremonyAuthoringError::WrongNextRecord)?;
    let body = CeremonyRecordBody::ContributionCommitment(ContributionCommitmentBody {
        ceremony_id: prefix.ceremony_id,
        genesis_signed_record_digest: prefix.genesis_signed_record_digest,
        operator_index: plan.operator_index,
        operator_public_key: operator.public_key,
        contribution_bytes: contribution.bytes,
        contribution_blake3: contribution.blake3,
        contribution_sha256: contribution.sha256,
        source_bytes_consumed: plan.source_bytes_consumed,
        rejected_source_bytes: plan.rejected_source_bytes,
        generation_finished_unix_seconds: plan.generation_finished_unix_seconds,
        generator_binary_blake3: generator.blake3,
        generator_binary_sha256: generator.sha256,
        entropy_attestation,
    });
    let signers = required_signers_for_body(&body, Some(&prefix.genesis))?;
    Ok((body, signers))
}

fn prepare_commitment_set(
    plan: PriorRecordsPlan,
    expected_ceremony_id: [u8; 32],
) -> Result<(CeremonyRecordBody, Vec<RequiredCeremonySigner>), ProductionDoryV3CeremonyAuthoringError>
{
    let prefix = authenticate_prior_records(&plan.prior_records, expected_ceremony_id)?;
    if prefix.state != PrefixState::CommitmentSet {
        return Err(ProductionDoryV3CeremonyAuthoringError::WrongNextRecord);
    }
    let commitments = prefix
        .commitment_digests
        .iter()
        .enumerate()
        .map(|(index, digest)| IndexedRecordDigest {
            index: u16::try_from(index).expect("ceremony operator cap fits u16"),
            signed_record_digest: *digest,
        })
        .collect();
    let body = CeremonyRecordBody::CommitmentSet(CommitmentSetBody {
        ceremony_id: prefix.ceremony_id,
        genesis_signed_record_digest: prefix.genesis_signed_record_digest,
        commitments,
    });
    let signers = required_signers_for_body(&body, Some(&prefix.genesis))?;
    Ok((body, signers))
}

fn prepare_contribution_reveal(
    plan: ContributionRevealPlan,
    expected_ceremony_id: [u8; 32],
) -> Result<(CeremonyRecordBody, Vec<RequiredCeremonySigner>), ProductionDoryV3CeremonyAuthoringError>
{
    let prefix = authenticate_prior_records(&plan.prior_records, expected_ceremony_id)?;
    let PrefixState::Reveals { next_operator } = prefix.state else {
        return Err(ProductionDoryV3CeremonyAuthoringError::WrongNextRecord);
    };
    if plan.operator_index != next_operator {
        return Err(ProductionDoryV3CeremonyAuthoringError::WrongNextRecord);
    }
    if plan.reveal_finished_unix_seconds == 0
        || plan.reveal_finished_unix_seconds > prefix.genesis.reveal_deadline_unix_seconds
    {
        return Err(ProductionDoryV3CeremonyAuthoringError::Deadline);
    }
    let commitment = prefix
        .commitments
        .get(usize::from(plan.operator_index))
        .ok_or(ProductionDoryV3CeremonyAuthoringError::WrongNextRecord)?;
    let contribution = authenticate_file_identity(
        &plan.contribution_file,
        Some(PRODUCTION_PAYLOAD_BYTES),
        true,
    )?;
    if contribution.bytes != commitment.contribution_bytes
        || contribution.blake3 != commitment.contribution_blake3
        || contribution.sha256 != commitment.contribution_sha256
    {
        return Err(ProductionDoryV3CeremonyAuthoringError::ContributionIdentityMismatch);
    }
    let body = CeremonyRecordBody::ContributionReveal(ContributionRevealBody {
        ceremony_id: prefix.ceremony_id,
        operator_index: plan.operator_index,
        contribution_commitment_signed_record_digest: prefix.commitment_digests
            [usize::from(plan.operator_index)],
        contribution_bytes: contribution.bytes,
        contribution_blake3: contribution.blake3,
        contribution_sha256: contribution.sha256,
        reveal_finished_unix_seconds: plan.reveal_finished_unix_seconds,
    });
    let signers = required_signers_for_body(&body, Some(&prefix.genesis))?;
    Ok((body, signers))
}

fn prepare_reveal_set(
    plan: RevealSetPlan,
    expected_ceremony_id: [u8; 32],
) -> Result<(CeremonyRecordBody, Vec<RequiredCeremonySigner>), ProductionDoryV3CeremonyAuthoringError>
{
    let prefix = authenticate_prior_records(&plan.prior_records, expected_ceremony_id)?;
    if prefix.state != PrefixState::RevealSet {
        return Err(ProductionDoryV3CeremonyAuthoringError::WrongNextRecord);
    }
    authenticate_all_revealed_contributions(&plan.contribution_files, &prefix.commitments)?;
    let reveals = prefix
        .reveal_digests
        .iter()
        .enumerate()
        .map(|(index, digest)| IndexedRecordDigest {
            index: u16::try_from(index).expect("ceremony operator cap fits u16"),
            signed_record_digest: *digest,
        })
        .collect();
    let body = CeremonyRecordBody::RevealSet(RevealSetBody {
        ceremony_id: prefix.ceremony_id,
        commitment_set_signed_record_digest: prefix.commitment_set_signed_record_digest.ok_or(
            ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence(
                "missing commitment-set digest",
            ),
        )?,
        reveals,
    });
    let signers = required_signers_for_body(&body, Some(&prefix.genesis))?;
    Ok((body, signers))
}

fn authenticate_all_revealed_contributions(
    paths: &[PathBuf],
    commitments: &[ContributionCommitmentBody],
) -> Result<(), ProductionDoryV3CeremonyAuthoringError> {
    if paths.len() != commitments.len() {
        return Err(
            ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence(
                "type-5 contribution file count",
            ),
        );
    }
    let mut unique = BTreeSet::new();
    for (path, commitment) in paths.iter().zip(commitments) {
        if !unique.insert(path.clone()) {
            return Err(ProductionDoryV3CeremonyAuthoringError::DuplicateInput(
                path.clone(),
            ));
        }
        let identity = authenticate_file_identity(path, Some(PRODUCTION_PAYLOAD_BYTES), true)?;
        if identity.bytes != commitment.contribution_bytes
            || identity.blake3 != commitment.contribution_blake3
            || identity.sha256 != commitment.contribution_sha256
        {
            return Err(ProductionDoryV3CeremonyAuthoringError::ContributionIdentityMismatch);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrefixState {
    Commitments { next_operator: u16 },
    CommitmentSet,
    Reveals { next_operator: u16 },
    RevealSet,
    Closed,
}

struct VerifiedAuthoringPrefix {
    genesis: GenesisBody,
    ceremony_id: [u8; 32],
    genesis_signed_record_digest: [u8; 32],
    commitments: Vec<ContributionCommitmentBody>,
    commitment_digests: Vec<[u8; 32]>,
    commitment_set_signed_record_digest: Option<[u8; 32]>,
    reveal_digests: Vec<[u8; 32]>,
    state: PrefixState,
}

fn authenticate_prior_records(
    paths: &[PathBuf],
    expected_ceremony_id: [u8; 32],
) -> Result<VerifiedAuthoringPrefix, ProductionDoryV3CeremonyAuthoringError> {
    let records = authenticate_prior_record_files(paths)?;
    let prefix = verify_authoring_prefix(&records)?;
    if prefix.ceremony_id != expected_ceremony_id {
        return Err(ProductionDoryV3CeremonyAuthoringError::CeremonyIdAnchorMismatch);
    }
    Ok(prefix)
}

fn authenticate_prior_record_files(
    paths: &[PathBuf],
) -> Result<Vec<SignedCeremonyRecord>, ProductionDoryV3CeremonyAuthoringError> {
    if paths.is_empty() || paths.len() > 2 * MAX_CEREMONY_OPERATORS + 3 {
        return Err(
            ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence("prior record count"),
        );
    }
    let mut unique = BTreeSet::new();
    let mut records = Vec::with_capacity(paths.len());
    for path in paths {
        if !unique.insert(path.clone()) {
            return Err(ProductionDoryV3CeremonyAuthoringError::DuplicateInput(
                path.clone(),
            ));
        }
        let (bytes, _) = authenticate_small_file(path, MAX_SIGNED_CEREMONY_RECORD_BYTES)?;
        let record = decode_ceremony_record(&bytes)?;
        if encode_ceremony_record(&record)? != bytes {
            return Err(
                ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence(
                    "noncanonical prior record encoding",
                ),
            );
        }
        records.push(record);
    }
    Ok(records)
}

fn verify_authoring_prefix(
    records: &[SignedCeremonyRecord],
) -> Result<VerifiedAuthoringPrefix, ProductionDoryV3CeremonyAuthoringError> {
    let CeremonyRecordBody::Genesis(genesis) = &records[0].body else {
        return Err(
            ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence(
                "first record is not Genesis",
            ),
        );
    };
    let genesis = genesis.as_ref().clone();
    ceremony_record_content_digest(&records[0].body)?;
    verify_prior_record_signatures(&records[0], &genesis)?;
    let ceremony_id = ceremony_record_content_digest(&records[0].body)?;
    let genesis_signed_record_digest = ceremony_signed_record_digest(&records[0])?;
    let operator_count = genesis.operators.len();
    let mut state = PrefixState::Commitments { next_operator: 0 };
    let mut commitments = Vec::with_capacity(operator_count);
    let mut commitment_digests = Vec::with_capacity(operator_count);
    let mut commitment_set_signed_record_digest = None;
    let mut reveal_digests = Vec::with_capacity(operator_count);

    for record in &records[1..] {
        ceremony_record_content_digest(&record.body)?;
        verify_prior_record_signatures(record, &genesis)?;
        match (state, &record.body) {
            (
                PrefixState::Commitments { next_operator },
                CeremonyRecordBody::ContributionCommitment(body),
            ) => {
                let operator = genesis.operators.get(usize::from(next_operator)).ok_or(
                    ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence(
                        "too many commitments",
                    ),
                )?;
                if body.ceremony_id != ceremony_id
                    || body.genesis_signed_record_digest != genesis_signed_record_digest
                    || body.operator_index != next_operator
                    || body.operator_public_key != operator.public_key
                    || body.generation_finished_unix_seconds == 0
                    || body.generation_finished_unix_seconds > genesis.commit_deadline_unix_seconds
                    || !genesis.reference_binaries.iter().any(|reference| {
                        reference.binary_blake3 == body.generator_binary_blake3
                            && reference.binary_sha256 == body.generator_binary_sha256
                    })
                {
                    return Err(
                        ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence(
                            "commitment reference",
                        ),
                    );
                }
                commitments.push(body.clone());
                commitment_digests.push(ceremony_signed_record_digest(record)?);
                state = if commitments.len() == operator_count {
                    PrefixState::CommitmentSet
                } else {
                    PrefixState::Commitments {
                        next_operator: next_operator + 1,
                    }
                };
            }
            (PrefixState::CommitmentSet, CeremonyRecordBody::CommitmentSet(body)) => {
                if body.ceremony_id != ceremony_id
                    || body.genesis_signed_record_digest != genesis_signed_record_digest
                    || body.commitments.len() != operator_count
                    || body.commitments.iter().enumerate().any(|(index, value)| {
                        usize::from(value.index) != index
                            || value.signed_record_digest != commitment_digests[index]
                    })
                {
                    return Err(
                        ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence(
                            "commitment-set closure",
                        ),
                    );
                }
                commitment_set_signed_record_digest = Some(ceremony_signed_record_digest(record)?);
                state = PrefixState::Reveals { next_operator: 0 };
            }
            (
                PrefixState::Reveals { next_operator },
                CeremonyRecordBody::ContributionReveal(body),
            ) => {
                let commitment = commitments.get(usize::from(next_operator)).ok_or(
                    ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence(
                        "missing commitment",
                    ),
                )?;
                if body.ceremony_id != ceremony_id
                    || body.operator_index != next_operator
                    || body.contribution_commitment_signed_record_digest
                        != commitment_digests[usize::from(next_operator)]
                    || body.contribution_bytes != commitment.contribution_bytes
                    || body.contribution_blake3 != commitment.contribution_blake3
                    || body.contribution_sha256 != commitment.contribution_sha256
                    || body.reveal_finished_unix_seconds == 0
                    || body.reveal_finished_unix_seconds > genesis.reveal_deadline_unix_seconds
                {
                    return Err(
                        ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence(
                            "reveal reference",
                        ),
                    );
                }
                reveal_digests.push(ceremony_signed_record_digest(record)?);
                state = if reveal_digests.len() == operator_count {
                    PrefixState::RevealSet
                } else {
                    PrefixState::Reveals {
                        next_operator: next_operator + 1,
                    }
                };
            }
            (PrefixState::RevealSet, CeremonyRecordBody::RevealSet(body)) => {
                if body.ceremony_id != ceremony_id
                    || Some(body.commitment_set_signed_record_digest)
                        != commitment_set_signed_record_digest
                    || body.reveals.len() != operator_count
                    || body.reveals.iter().enumerate().any(|(index, value)| {
                        usize::from(value.index) != index
                            || value.signed_record_digest != reveal_digests[index]
                    })
                {
                    return Err(
                        ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence(
                            "reveal-set closure",
                        ),
                    );
                }
                state = PrefixState::Closed;
            }
            _ => {
                return Err(
                    ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence(
                        "record outside canonical type-1-through-type-5 sequence",
                    ),
                );
            }
        }
    }

    Ok(VerifiedAuthoringPrefix {
        genesis,
        ceremony_id,
        genesis_signed_record_digest,
        commitments,
        commitment_digests,
        commitment_set_signed_record_digest,
        reveal_digests,
        state,
    })
}

fn required_signers_for_body(
    body: &CeremonyRecordBody,
    prior_genesis: Option<&GenesisBody>,
) -> Result<Vec<RequiredCeremonySigner>, ProductionDoryV3CeremonyAuthoringError> {
    let genesis = match body {
        CeremonyRecordBody::Genesis(genesis) => genesis.as_ref(),
        _ => prior_genesis.ok_or(
            ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence("missing Genesis roster"),
        )?,
    };
    let all = || {
        genesis
            .operators
            .iter()
            .map(|member| RequiredCeremonySigner {
                signer_class: SignerClass::Operator,
                signer_index: member.index,
                public_key: member.public_key,
            })
            .chain(
                genesis
                    .reproducers
                    .iter()
                    .map(|member| RequiredCeremonySigner {
                        signer_class: SignerClass::Reproducer,
                        signer_index: member.index,
                        public_key: member.public_key,
                    }),
            )
            .collect()
    };
    let operators = || {
        genesis
            .operators
            .iter()
            .map(|member| RequiredCeremonySigner {
                signer_class: SignerClass::Operator,
                signer_index: member.index,
                public_key: member.public_key,
            })
            .collect()
    };
    match body {
        CeremonyRecordBody::Genesis(_) => Ok(all()),
        CeremonyRecordBody::ContributionCommitment(value) => {
            Ok(vec![operator_signer(genesis, value.operator_index)?])
        }
        CeremonyRecordBody::CommitmentSet(_) => Ok(operators()),
        CeremonyRecordBody::ContributionReveal(value) => {
            Ok(vec![operator_signer(genesis, value.operator_index)?])
        }
        CeremonyRecordBody::RevealSet(_) => Ok(operators()),
        CeremonyRecordBody::FinalReceipt(_) => Ok(all()),
        CeremonyRecordBody::Abort(_) => {
            Err(ProductionDoryV3CeremonyAuthoringError::WrongNextRecord)
        }
    }
}

fn operator_signer(
    genesis: &GenesisBody,
    index: u16,
) -> Result<RequiredCeremonySigner, ProductionDoryV3CeremonyAuthoringError> {
    let member = genesis
        .operators
        .get(usize::from(index))
        .filter(|member| member.index == index)
        .ok_or(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)?;
    Ok(RequiredCeremonySigner {
        signer_class: SignerClass::Operator,
        signer_index: index,
        public_key: member.public_key,
    })
}

fn verify_prior_record_signatures(
    record: &SignedCeremonyRecord,
    genesis: &GenesisBody,
) -> Result<(), ProductionDoryV3CeremonyAuthoringError> {
    let expected = required_signers_for_body(&record.body, Some(genesis))?;
    verify_signatures_against(record, &expected)
}

fn verify_external_signatures(
    prepared: &PreparedProductionDoryV3CeremonyRecord,
    signatures: &[RecordSignature],
) -> Result<(), ProductionDoryV3CeremonyAuthoringError> {
    let record = SignedCeremonyRecord {
        body: prepared.body.clone(),
        signatures: signatures.to_vec(),
    };
    verify_signatures_against(&record, &prepared.required_signers)
}

fn verify_signatures_against(
    record: &SignedCeremonyRecord,
    expected: &[RequiredCeremonySigner],
) -> Result<(), ProductionDoryV3CeremonyAuthoringError> {
    if record.signatures.len() != expected.len()
        || record
            .signatures
            .iter()
            .zip(expected)
            .any(|(actual, expected)| {
                actual.signer_class != expected.signer_class
                    || actual.signer_index != expected.signer_index
            })
    {
        return Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy);
    }
    let message = ceremony_record_signature_message(&record.body)?;
    for (signature, signer) in record.signatures.iter().zip(expected) {
        let key = VerifyingKey::from_bytes(&signer.public_key)
            .map_err(|_| CeremonyTranscriptError::InvalidPublicKey)?;
        let signature = Signature::try_from(signature.signature.as_slice())
            .map_err(|_| CeremonyTranscriptError::MalformedSignature)?;
        key.verify_raw(&message, &signature)
            .map_err(|_| CeremonyTranscriptError::InvalidSignature)?;
    }
    Ok(())
}

/// One bounded input whose authenticated file and parent handles remain live
/// until the caller explicitly finishes confirming its output.
struct RetainedAuthenticatedSmallFile {
    path: PathBuf,
    maximum_bytes: usize,
    parent: TrustedCeremonyParent,
    input: AuthenticatedInput,
    bytes: Vec<u8>,
    file_identity: FileIdentity,
}

impl RetainedAuthenticatedSmallFile {
    fn open(
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Self, ProductionDoryV3CeremonyAuthoringError> {
        let parent = TrustedCeremonyParent::for_artifact(path)?;
        let mut input = AuthenticatedInput::open(&parent, path, None)?;
        let first = input.read_bounded(maximum_bytes)?;
        if first.len() > maximum_bytes {
            return Err(ProductionDoryV3CeremonyAuthoringError::InputTooLarge(
                path.to_path_buf(),
            ));
        }
        input.recheck(&parent, Some(first.len() as u64))?;
        let second = input.read_bounded(maximum_bytes)?;
        input.recheck(&parent, Some(first.len() as u64))?;
        if first != second {
            return Err(ProductionDoryV3CeremonyAuthoringError::InputChanged(
                path.to_path_buf(),
            ));
        }
        let file_identity = file_identity_for_bytes(&first);
        Ok(Self {
            path: path.to_path_buf(),
            maximum_bytes,
            parent,
            input,
            bytes: first,
            file_identity,
        })
    }

    fn reauthenticate_exact(&mut self) -> Result<(), ProductionDoryV3CeremonyAuthoringError> {
        self.input
            .recheck(&self.parent, Some(self.bytes.len() as u64))?;
        let first = self.input.read_bounded(self.maximum_bytes)?;
        self.input
            .recheck(&self.parent, Some(self.bytes.len() as u64))?;
        let second = self.input.read_bounded(self.maximum_bytes)?;
        self.input
            .recheck(&self.parent, Some(self.bytes.len() as u64))?;
        if first != self.bytes
            || second != self.bytes
            || file_identity_for_bytes(&first) != self.file_identity
        {
            return Err(ProductionDoryV3CeremonyAuthoringError::InputChanged(
                self.path.clone(),
            ));
        }
        Ok(())
    }
}

fn authenticate_small_file(
    path: &Path,
    maximum_bytes: usize,
) -> Result<(Vec<u8>, FileIdentity), ProductionDoryV3CeremonyAuthoringError> {
    let parent = TrustedCeremonyParent::for_artifact(path)?;
    let mut input = AuthenticatedInput::open(&parent, path, None)?;
    let first = input.read_bounded(maximum_bytes)?;
    if first.len() > maximum_bytes {
        return Err(ProductionDoryV3CeremonyAuthoringError::InputTooLarge(
            path.to_path_buf(),
        ));
    }
    input.recheck(&parent, Some(first.len() as u64))?;
    let second = input.read_bounded(maximum_bytes)?;
    input.recheck(&parent, Some(first.len() as u64))?;
    if first != second {
        return Err(ProductionDoryV3CeremonyAuthoringError::InputChanged(
            path.to_path_buf(),
        ));
    }
    let identity = file_identity_for_bytes(&first);
    Ok((first, identity))
}

fn authenticate_file_identity(
    path: &Path,
    expected_bytes: Option<u64>,
    enforce_model_byte_range: bool,
) -> Result<FileIdentity, ProductionDoryV3CeremonyAuthoringError> {
    let parent = TrustedCeremonyParent::for_artifact(path)?;
    let mut input = AuthenticatedInput::open(&parent, path, expected_bytes)?;
    let first = hash_file_pass(input.file_mut(), path, enforce_model_byte_range)?;
    input.recheck(&parent, Some(first.bytes))?;
    let second = hash_file_pass(input.file_mut(), path, enforce_model_byte_range)?;
    input.recheck(&parent, Some(first.bytes))?;
    if first != second {
        return Err(ProductionDoryV3CeremonyAuthoringError::InputChanged(
            path.to_path_buf(),
        ));
    }
    Ok(first)
}

fn hash_file_pass(
    file: &mut File,
    path: &Path,
    enforce_model_byte_range: bool,
) -> Result<FileIdentity, ProductionDoryV3CeremonyAuthoringError> {
    file.seek(SeekFrom::Start(0)).map_err(|source| {
        ProductionDoryV3CeremonyAuthoringError::ReadInput {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let mut blake3 = blake3::Hasher::new();
    let mut sha256 = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = vec![0u8; IO_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer).map_err(|source| {
            ProductionDoryV3CeremonyAuthoringError::ReadInput {
                path: path.to_path_buf(),
                source,
            }
        })?;
        if read == 0 {
            break;
        }
        if enforce_model_byte_range
            && buffer[..read]
                .iter()
                .any(|byte| *byte > PRODUCTION_MAX_MODEL_BYTE)
        {
            return Err(ProductionDoryV3CeremonyAuthoringError::ContributionByteRange);
        }
        bytes = bytes.checked_add(read as u64).ok_or(
            ProductionDoryV3CeremonyAuthoringError::InvalidPriorSequence("input length overflow"),
        )?;
        blake3.update(&buffer[..read]);
        sha256.update(&buffer[..read]);
    }
    Ok(FileIdentity {
        bytes,
        blake3: *blake3.finalize().as_bytes(),
        sha256: sha256.finalize().into(),
    })
}

fn file_identity_for_bytes(bytes: &[u8]) -> FileIdentity {
    FileIdentity {
        bytes: bytes.len() as u64,
        blake3: *blake3::hash(bytes).as_bytes(),
        sha256: Sha256::digest(bytes).into(),
    }
}

fn parse_lower_hex<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], ProductionDoryV3CeremonyAuthoringError> {
    if value.len() != 2 * N
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ProductionDoryV3CeremonyAuthoringError::InvalidHex(field));
    }
    let mut result = [0u8; N];
    hex::decode_to_slice(value, &mut result)
        .map_err(|_| ProductionDoryV3CeremonyAuthoringError::InvalidHex(field))?;
    Ok(result)
}

fn persist_record(
    output_path: &Path,
    bytes: &[u8],
    validate: impl FnOnce(&[u8]) -> Result<(), ProductionDoryV3CeremonyAuthoringError>,
) -> Result<ProductionDoryV3CeremonyRecordStageDurability, ProductionDoryV3CeremonyAuthoringError> {
    let parent = TrustedCeremonyParent::for_artifact(output_path)?;
    let mut output = PendingOutput::create(&parent, output_path)?;
    let completion = (|| {
        output.write_all(bytes)?;
        output.sync_file()?;
        let reopened = output.reopen_exact(&parent, bytes)?;
        validate(&reopened)?;
        let durability = map_durability(output.sync_parent(&parent)?);
        Ok(durability)
    })();
    finish_pending_output(output, &parent, completion)
}

fn finish_pending_output<T>(
    mut output: PendingOutput,
    parent: &TrustedCeremonyParent,
    completion: Result<T, ProductionDoryV3CeremonyAuthoringError>,
) -> Result<T, ProductionDoryV3CeremonyAuthoringError> {
    match completion {
        Ok(value) => match output.confirm(parent) {
            Ok(()) => Ok(value),
            Err(original) => cleanup_pending_output(&mut output, parent, original.into()),
        },
        Err(original) => cleanup_pending_output(&mut output, parent, original),
    }
}

fn cleanup_pending_output<T>(
    output: &mut PendingOutput,
    parent: &TrustedCeremonyParent,
    original: ProductionDoryV3CeremonyAuthoringError,
) -> Result<T, ProductionDoryV3CeremonyAuthoringError> {
    match output.remove_explicit(parent) {
        Ok(()) => Err(original),
        Err(cleanup) => Err(ProductionDoryV3CeremonyAuthoringError::OutputCleanup {
            original: original.to_string(),
            cleanup: cleanup.to_string(),
        }),
    }
}

fn map_durability(outcome: ParentSyncOutcome) -> ProductionDoryV3CeremonyRecordStageDurability {
    match outcome {
        ParentSyncOutcome::Synced => {
            ProductionDoryV3CeremonyRecordStageDurability::FileAndParentDirectorySynced
        }
        #[cfg(windows)]
        ParentSyncOutcome::WindowsAccessDenied => ProductionDoryV3CeremonyRecordStageDurability::
            FileSyncedParentDirectorySyncAccessDeniedOnWindows,
        #[cfg(windows)]
        ParentSyncOutcome::WindowsUnsupported => ProductionDoryV3CeremonyRecordStageDurability::
            FileSyncedParentDirectorySyncUnsupportedOnWindows,
        #[cfg(not(any(unix, windows)))]
        ParentSyncOutcome::PlatformUnsupported => ProductionDoryV3CeremonyRecordStageDurability::
            FileSyncedParentDirectorySyncUnsupportedOnPlatform,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use dory_pcs::primitives::{DorySerialize, arithmetic::Field};
    use k256::schnorr::SigningKey;

    use super::*;
    use crate::{
        ModelBankManifest,
        dory_bls12_381_prototype::{
            BlsDoryFr, DeterministicBlsDorySetup, deterministic_bls_dory_setup,
        },
        dory_v3_model::{CanonicalBlsDoryGtHex, ordered_dory_v3_model_commitment_root},
        dory_v3_model_ceremony_fs::prepare_test_parent,
        dory_v3_model_ceremony_transcript::{AbortBody, PRODUCTION_BANK_BYTES, ReproducerReceipt},
        dory_v3_model_reproduction::PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES,
        dory_v3_suite::{
            DORY_V3_MODEL_IDENTITY_DOMAIN, DORY_V3_MODEL_IDENTITY_VERSION,
            DORY_V3_MODEL_RECORD_DOMAIN, DORY_V3_MODEL_RECORD_VERSION,
        },
    };

    static TEST_DIRECTORY_NONCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "cmfd-ceremony-authoring-test-{}-{}",
                std::process::id(),
                TEST_DIRECTORY_NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            prepare_test_parent(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct TypeFiveFixture {
        records: Vec<SignedCeremonyRecord>,
        ceremony_id: [u8; 32],
        operators: Vec<SigningKey>,
        reproducers: Vec<SigningKey>,
    }

    struct TerminalTranscriptFixture {
        bytes: Vec<u8>,
        ceremony_id: [u8; 32],
        operators: Vec<SigningKey>,
        reproducers: Vec<SigningKey>,
    }

    fn test_file(byte: u8) -> FileIdentity {
        FileIdentity {
            bytes: u64::from(byte) + 1,
            blake3: [byte; 32],
            sha256: [byte.wrapping_add(1); 32],
        }
    }

    fn test_reproduction_file(byte: u8) -> FileIdentity {
        FileIdentity {
            bytes: PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES as u64,
            ..test_file(byte)
        }
    }

    fn test_keys(count: usize, offset: u8) -> Vec<SigningKey> {
        (0..count)
            .map(|index| SigningKey::from_bytes(&[offset.wrapping_add(index as u8); 32]).unwrap())
            .collect()
    }

    fn test_member(index: usize, key: &SigningKey) -> RosterMember {
        RosterMember {
            index: index as u16,
            public_key: key.verifying_key().to_bytes().into(),
            identity_document: test_file(index as u8 + 10),
        }
    }

    fn test_genesis(operator_keys: &[SigningKey], reproducer_keys: &[SigningKey]) -> GenesisBody {
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
            commit_deadline_unix_seconds: 1_000,
            reveal_deadline_unix_seconds: 2_000,
            source_commit_sha1: [3; 20],
            source_bundle: test_file(4),
            source_bundle_policy: test_file(5),
            cargo_lock_blake3: [6; 32],
            cargo_lock_sha256: [7; 32],
            protocol_spec_blake3: [8; 32],
            protocol_spec_sha256: [9; 32],
            bulletin_policy: test_file(10),
            reference_binaries: vec![ReferenceBinary {
                target_id: 1,
                rustc_vv: test_file(11),
                build_environment: test_file(12),
                binary_blake3: [13; 32],
                binary_sha256: [14; 32],
            }],
            structural_analyzer_target_id: 1,
            structural_analyzer_blake3: [15; 32],
            structural_analyzer_sha256: [16; 32],
            production_suite_digest: production_dory_v3_suite_digest().into_bytes(),
            dory_setup_identity: DORY_V3_SETUP_IDENTITY.into_bytes(),
            operators: operator_keys
                .iter()
                .enumerate()
                .map(|(index, key)| test_member(index, key))
                .collect(),
            reproducers: reproducer_keys
                .iter()
                .enumerate()
                .map(|(index, key)| test_member(index, key))
                .collect(),
        }
    }

    fn sign_test_record(
        body: CeremonyRecordBody,
        signers: &[(SignerClass, u16, &SigningKey)],
    ) -> SignedCeremonyRecord {
        let message = ceremony_record_signature_message(&body).unwrap();
        SignedCeremonyRecord {
            body,
            signatures: signers
                .iter()
                .map(|(signer_class, signer_index, key)| {
                    let signature: Signature = key.sign_raw(&message, &[0; 32]).unwrap();
                    RecordSignature {
                        signer_class: *signer_class,
                        signer_index: *signer_index,
                        signature: signature.to_bytes(),
                    }
                })
                .collect(),
        }
    }

    fn all_test_signers<'a>(
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

    fn type_five_fixture() -> TypeFiveFixture {
        let operators = test_keys(3, 1);
        let reproducers = test_keys(2, 20);
        let operator_signers: Vec<_> = operators
            .iter()
            .enumerate()
            .map(|(index, key)| (SignerClass::Operator, index as u16, key))
            .collect();
        let genesis = sign_test_record(
            CeremonyRecordBody::Genesis(Box::new(test_genesis(&operators, &reproducers))),
            &all_test_signers(&operators, &reproducers),
        );
        let ceremony_id = ceremony_record_content_digest(&genesis.body).unwrap();
        let genesis_signed_record_digest = ceremony_signed_record_digest(&genesis).unwrap();
        let mut records = vec![genesis];
        let mut commitment_bodies = Vec::with_capacity(operators.len());
        let mut commitment_digests = Vec::with_capacity(operators.len());

        for (index, key) in operators.iter().enumerate() {
            let body = ContributionCommitmentBody {
                ceremony_id,
                genesis_signed_record_digest,
                operator_index: index as u16,
                operator_public_key: key.verifying_key().to_bytes().into(),
                contribution_bytes: PRODUCTION_PAYLOAD_BYTES,
                contribution_blake3: [40 + index as u8; 32],
                contribution_sha256: [50 + index as u8; 32],
                source_bytes_consumed: PRODUCTION_PAYLOAD_BYTES + 5,
                rejected_source_bytes: 5,
                generation_finished_unix_seconds: 100 + index as u64,
                generator_binary_blake3: [13; 32],
                generator_binary_sha256: [14; 32],
                entropy_attestation: test_file(80 + index as u8),
            };
            let record = sign_test_record(
                CeremonyRecordBody::ContributionCommitment(body.clone()),
                &[(SignerClass::Operator, index as u16, key)],
            );
            commitment_digests.push(IndexedRecordDigest {
                index: index as u16,
                signed_record_digest: ceremony_signed_record_digest(&record).unwrap(),
            });
            commitment_bodies.push(body);
            records.push(record);
        }

        let commitment_set = sign_test_record(
            CeremonyRecordBody::CommitmentSet(CommitmentSetBody {
                ceremony_id,
                genesis_signed_record_digest,
                commitments: commitment_digests.clone(),
            }),
            &operator_signers,
        );
        let commitment_set_signed_record_digest =
            ceremony_signed_record_digest(&commitment_set).unwrap();
        records.push(commitment_set);

        let mut reveal_digests = Vec::with_capacity(operators.len());
        for (index, key) in operators.iter().enumerate() {
            let commitment = &commitment_bodies[index];
            let record = sign_test_record(
                CeremonyRecordBody::ContributionReveal(ContributionRevealBody {
                    ceremony_id,
                    operator_index: index as u16,
                    contribution_commitment_signed_record_digest: commitment_digests[index]
                        .signed_record_digest,
                    contribution_bytes: commitment.contribution_bytes,
                    contribution_blake3: commitment.contribution_blake3,
                    contribution_sha256: commitment.contribution_sha256,
                    reveal_finished_unix_seconds: 1_100 + index as u64,
                }),
                &[(SignerClass::Operator, index as u16, key)],
            );
            reveal_digests.push(IndexedRecordDigest {
                index: index as u16,
                signed_record_digest: ceremony_signed_record_digest(&record).unwrap(),
            });
            records.push(record);
        }

        records.push(sign_test_record(
            CeremonyRecordBody::RevealSet(RevealSetBody {
                ceremony_id,
                commitment_set_signed_record_digest,
                reveals: reveal_digests,
            }),
            &operator_signers,
        ));
        TypeFiveFixture {
            records,
            ceremony_id,
            operators,
            reproducers,
        }
    }

    fn canonical_test_commitment(
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

    fn completed_transcript_fixture() -> TerminalTranscriptFixture {
        let mut fixture = type_five_fixture();
        let commitment_set_signed_record_digest =
            ceremony_signed_record_digest(&fixture.records[4]).unwrap();
        let reveal_set_signed_record_digest =
            ceremony_signed_record_digest(fixture.records.last().unwrap()).unwrap();
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let base_commitment = canonical_test_commitment(&setup, 3, 0);
        let weight_bank_0_commitment = canonical_test_commitment(&setup, 5, 1);
        let weight_bank_1_commitment = canonical_test_commitment(&setup, 7, 2);
        let weight_bank_2_commitment = canonical_test_commitment(&setup, 11, 3);
        let base = CanonicalBlsDoryGtHex::from_hex(&hex::encode(base_commitment)).unwrap();
        let weights = [
            CanonicalBlsDoryGtHex::from_hex(&hex::encode(weight_bank_0_commitment)).unwrap(),
            CanonicalBlsDoryGtHex::from_hex(&hex::encode(weight_bank_1_commitment)).unwrap(),
            CanonicalBlsDoryGtHex::from_hex(&hex::encode(weight_bank_2_commitment)).unwrap(),
        ];
        let suite_digest = production_dory_v3_suite_digest().into_bytes();
        let setup_identity = DORY_V3_SETUP_IDENTITY.into_bytes();
        let commitment_root = ordered_dory_v3_model_commitment_root(
            DORY_V3_MODEL_IDENTITY_VERSION,
            suite_digest,
            setup_identity,
            PRODUCTION_PADDED_VARIABLES,
            &base,
            &weights,
        )
        .unwrap();
        let raw_payload_blake3 = [90; 32];
        let layer_roots_aggregate = [93; 32];
        let manifest_digest = ModelBankManifest {
            model_version: PRODUCTION_MODEL_VERSION,
            dimension: PRODUCTION_DIMENSION,
            batch: PRODUCTION_BATCH,
            layers: PRODUCTION_LAYERS,
            base_input_bytes: PRODUCTION_BASE_INPUT_BYTES,
            bytes_per_layer: PRODUCTION_BYTES_PER_LAYER,
            payload_bytes: PRODUCTION_PAYLOAD_BYTES,
            raw_blake3_root: raw_payload_blake3,
            layer_roots_aggregate,
            pcs_parameter_digest: suite_digest,
            pcs_commitment_root: commitment_root,
        }
        .digest()
        .unwrap();

        let mut identity = blake3::Hasher::new_derive_key(DORY_V3_MODEL_IDENTITY_DOMAIN);
        identity.update(&DORY_V3_MODEL_IDENTITY_VERSION.to_le_bytes());
        identity.update(&suite_digest);
        identity.update(&PRODUCTION_MODEL_VERSION.to_le_bytes());
        identity.update(&PRODUCTION_BATCH.to_le_bytes());
        identity.update(&PRODUCTION_DIMENSION.to_le_bytes());
        identity.update(&PRODUCTION_LAYERS_PER_BANK.to_le_bytes());
        identity.update(&PRODUCTION_BANKS.to_le_bytes());
        identity.update(&raw_payload_blake3);
        identity.update(&layer_roots_aggregate);
        identity.update(&setup_identity);
        identity.update(&PRODUCTION_PADDED_VARIABLES.to_le_bytes());
        identity.update(&commitment_root);
        let model_identity_digest = *identity.finalize().as_bytes();

        let mut canonical_record = Vec::with_capacity(166);
        canonical_record.extend_from_slice(&DORY_V3_MODEL_RECORD_VERSION.to_le_bytes());
        canonical_record.extend_from_slice(&suite_digest);
        canonical_record.extend_from_slice(&manifest_digest);
        canonical_record.extend_from_slice(&model_identity_digest);
        canonical_record.extend_from_slice(&setup_identity);
        canonical_record.extend_from_slice(&PRODUCTION_PADDED_VARIABLES.to_le_bytes());
        canonical_record.extend_from_slice(&commitment_root);
        assert_eq!(canonical_record.len(), 166);
        let mut record = blake3::Hasher::new_derive_key(DORY_V3_MODEL_RECORD_DOMAIN);
        record.update(&canonical_record);
        let record_v2_digest = *record.finalize().as_bytes();

        let final_receipt = sign_test_record(
            CeremonyRecordBody::FinalReceipt(Box::new(FinalReceiptBody {
                ceremony_id: fixture.ceremony_id,
                commitment_set_signed_record_digest,
                reveal_set_signed_record_digest,
                payload_bytes: PRODUCTION_PAYLOAD_BYTES,
                raw_payload_blake3,
                raw_payload_sha256: [91; 32],
                base_input_blake3_root: [92; 32],
                layer_roots_aggregate,
                roots_file: test_file(94),
                structural_report: test_file(95),
                bank_bytes: PRODUCTION_BANK_BYTES,
                bank_file_blake3: [96; 32],
                bank_file_sha256: [97; 32],
                manifest_file: test_file(98),
                manifest_digest,
                production_suite_digest: suite_digest,
                pcs_parameter_digest: suite_digest,
                base_commitment,
                weight_bank_0_commitment,
                weight_bank_1_commitment,
                weight_bank_2_commitment,
                pcs_commitment_root: commitment_root,
                model_identity_digest,
                setup_identity,
                padded_variables: PRODUCTION_PADDED_VARIABLES,
                record_v2_file: test_file(102),
                record_v2_digest,
                publisher_reproducer_index: 0,
                reproducers: (0..fixture.reproducers.len())
                    .map(|index| ReproducerReceipt {
                        index: index as u16,
                        combiner_binary_blake3: [110 + index as u8; 32],
                        combiner_binary_sha256: [112 + index as u8; 32],
                        bootstrap_report: test_file(114 + index as u8),
                        record_ceremony_report: test_file(116 + index as u8),
                        reproduction_report: test_reproduction_file(118 + index as u8),
                    })
                    .collect(),
            })),
            &all_test_signers(&fixture.operators, &fixture.reproducers),
        );
        fixture.records.push(final_receipt);
        TerminalTranscriptFixture {
            bytes: encode_and_verify_ceremony_transcript(&fixture.records).unwrap(),
            ceremony_id: fixture.ceremony_id,
            operators: fixture.operators,
            reproducers: fixture.reproducers,
        }
    }

    fn aborted_transcript_fixture(reason_code: u16) -> TerminalTranscriptFixture {
        let operators = test_keys(3, 1);
        let reproducers = test_keys(2, 20);
        let genesis = sign_test_record(
            CeremonyRecordBody::Genesis(Box::new(test_genesis(&operators, &reproducers))),
            &all_test_signers(&operators, &reproducers),
        );
        let ceremony_id = ceremony_record_content_digest(&genesis.body).unwrap();
        let last_valid_signed_record_digest = ceremony_signed_record_digest(&genesis).unwrap();
        let abort = sign_test_record(
            CeremonyRecordBody::Abort(AbortBody {
                ceremony_id,
                last_valid_signed_record_digest,
                phase: 1,
                reason_code,
                evidence_file: test_file(30 + reason_code as u8),
            }),
            &[(SignerClass::Operator, 0, &operators[0])],
        );
        TerminalTranscriptFixture {
            bytes: encode_and_verify_ceremony_transcript(&[genesis, abort]).unwrap(),
            ceremony_id,
            operators,
            reproducers,
        }
    }

    fn persist_fixture_records(
        directory: &TestDirectory,
        records: &[SignedCeremonyRecord],
    ) -> Vec<PathBuf> {
        records
            .iter()
            .enumerate()
            .map(|(index, record)| {
                let path = directory.0.join(format!("record-{index}.cmfdcr01"));
                let encoded = encode_ceremony_record(record).unwrap();
                let expected = record.clone();
                persist_record(&path, &encoded, |reopened| {
                    let decoded = decode_ceremony_record(reopened)?;
                    if decoded != expected || encode_ceremony_record(&decoded)? != reopened {
                        return Err(ProductionDoryV3CeremonyAuthoringError::StagedOutputChanged);
                    }
                    Ok(())
                })
                .unwrap();
                path
            })
            .collect()
    }

    fn write_test_input(directory: &TestDirectory, name: &str, bytes: &[u8]) -> PathBuf {
        let path = directory.0.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    fn persist_completed_transcript_inputs(
        directory: &TestDirectory,
        fixture: &TerminalTranscriptFixture,
    ) -> (PathBuf, Vec<u8>, PathBuf, Vec<u8>) {
        let completed =
            parse_and_verify_completed_ceremony_transcript(&fixture.bytes, fixture.ceremony_id)
                .unwrap();
        let prefix_bytes = encode_and_verify_reveal_set_prefix(
            &completed.records()[..completed.records().len() - 1],
            fixture.ceremony_id,
        )
        .unwrap();
        let final_receipt_bytes =
            encode_ceremony_record(completed.records().last().unwrap()).unwrap();
        let prefix_path = write_test_input(directory, "reveal-set-prefix.cmfdct01", &prefix_bytes);
        let final_receipt_path =
            write_test_input(directory, "final-receipt.cmfdcr01", &final_receipt_bytes);
        (
            prefix_path,
            prefix_bytes,
            final_receipt_path,
            final_receipt_bytes,
        )
    }

    fn genesis_plan_bytes(
        directory: &TestDirectory,
        operators: &[SigningKey],
        reproducers: &[SigningKey],
    ) -> Vec<u8> {
        let source_bundle = write_test_input(directory, "source.bundle", b"source");
        let source_bundle_policy =
            write_test_input(directory, "source-policy.txt", b"source policy");
        let cargo_lock = write_test_input(directory, "Cargo.lock", b"lock");
        let protocol_spec = write_test_input(directory, "protocol.md", b"protocol");
        let bulletin_policy = write_test_input(directory, "bulletin.md", b"bulletin");
        let rustc_vv = write_test_input(directory, "rustc-vv.txt", b"rustc");
        let build_environment = write_test_input(directory, "build-env.txt", b"build");
        let binary = write_test_input(directory, "reference.bin", b"binary");
        let analyzer = write_test_input(directory, "analyzer.bin", b"analyzer");
        let roster = |keys: &[SigningKey], prefix: &str| {
            keys.iter()
                .enumerate()
                .map(|(index, key)| {
                    let identity = write_test_input(
                        directory,
                        &format!("{prefix}-{index}-identity.txt"),
                        &[index as u8],
                    );
                    serde_json::json!({
                        "index": index,
                        "public_key": hex::encode(key.verifying_key().to_bytes()),
                        "identity_document": identity,
                    })
                })
                .collect::<Vec<_>>()
        };
        serde_json::to_vec(&serde_json::json!({
            "record_type": "type_1_genesis",
            "plan": {
                "commit_deadline_unix_seconds": 1_000,
                "reveal_deadline_unix_seconds": 2_000,
                "source_commit_sha1": "1111111111111111111111111111111111111111",
                "source_bundle": source_bundle,
                "source_bundle_policy": source_bundle_policy,
                "cargo_lock": cargo_lock,
                "protocol_spec": protocol_spec,
                "bulletin_policy": bulletin_policy,
                "reference_binaries": [{
                    "target_id": 1,
                    "rustc_vv": rustc_vv,
                    "build_environment": build_environment,
                    "binary": binary,
                }],
                "structural_analyzer_target_id": 1,
                "structural_analyzer_binary": analyzer,
                "operators": roster(operators, "operator"),
                "reproducers": roster(reproducers, "reproducer"),
            }
        }))
        .unwrap()
    }

    fn sign_prepared_record(
        prepared: &PreparedProductionDoryV3CeremonyRecord,
        operators: &[SigningKey],
        reproducers: &[SigningKey],
    ) -> Vec<RecordSignature> {
        prepared
            .required_signers()
            .iter()
            .map(|required| {
                let key = match required.signer_class() {
                    SignerClass::Operator => &operators[usize::from(required.signer_index())],
                    SignerClass::Reproducer => &reproducers[usize::from(required.signer_index())],
                };
                let public_key: [u8; 32] = key.verifying_key().to_bytes().into();
                assert_eq!(required.public_key(), public_key);
                let signature: Signature = key
                    .sign_raw(&prepared.signature_message(), &[0; 32])
                    .unwrap();
                RecordSignature {
                    signer_class: required.signer_class(),
                    signer_index: required.signer_index(),
                    signature: signature.to_bytes(),
                }
            })
            .collect()
    }

    fn sign_prepared_attestation(
        prepared: &PreparedProductionDoryV3CeremonyAttestation,
        operators: &[SigningKey],
        reproducers: &[SigningKey],
    ) -> Vec<RecordSignature> {
        prepared
            .required_signers()
            .iter()
            .map(|required| {
                let key = match required.signer_class() {
                    SignerClass::Operator => &operators[usize::from(required.signer_index())],
                    SignerClass::Reproducer => &reproducers[usize::from(required.signer_index())],
                };
                let signature: Signature = key
                    .sign_raw(&prepared.signature_message(), &[0; 32])
                    .unwrap();
                RecordSignature {
                    signer_class: required.signer_class(),
                    signer_index: required.signer_index(),
                    signature: signature.to_bytes(),
                }
            })
            .collect()
    }

    #[test]
    fn strict_tag_rejects_unknown_plan_fields() {
        let json = br#"{
            "record_type":"type_3_commitment_set",
            "plan":{"prior_records":[],"unexpected":true}
        }"#;
        assert!(serde_json::from_slice::<ProductionDoryV3CeremonyRecordPlan>(json).is_err());
    }

    #[test]
    fn type_five_plan_requires_strict_ordered_contribution_files() {
        let missing = br#"{
            "record_type":"type_5_reveal_set",
            "plan":{"prior_records":[]}
        }"#;
        assert!(serde_json::from_slice::<ProductionDoryV3CeremonyRecordPlan>(missing).is_err());
        let wrong_element_type = br#"{
            "record_type":"type_5_reveal_set",
            "plan":{"prior_records":[],"contribution_files":[7]}
        }"#;
        assert!(
            serde_json::from_slice::<ProductionDoryV3CeremonyRecordPlan>(wrong_element_type)
                .is_err()
        );
        let unknown = br#"{
            "record_type":"type_5_reveal_set",
            "plan":{"prior_records":[],"contribution_files":[],"unexpected":true}
        }"#;
        assert!(serde_json::from_slice::<ProductionDoryV3CeremonyRecordPlan>(unknown).is_err());
        let complete = br#"{
            "record_type":"type_5_reveal_set",
            "plan":{
                "prior_records":["record-0","record-1"],
                "contribution_files":["contribution-0","contribution-1","contribution-2"]
            }
        }"#;
        let decoded =
            serde_json::from_slice::<ProductionDoryV3CeremonyRecordPlan>(complete).unwrap();
        let ProductionDoryV3CeremonyRecordPlan::RevealSet(plan) = decoded else {
            panic!("type-5 tag must decode only as a reveal-set plan");
        };
        assert_eq!(
            plan.prior_records,
            [PathBuf::from("record-0"), PathBuf::from("record-1")]
        );
        assert_eq!(
            plan.contribution_files,
            [
                PathBuf::from("contribution-0"),
                PathBuf::from("contribution-1"),
                PathBuf::from("contribution-2")
            ]
        );
    }

    #[test]
    fn post_genesis_plan_requires_out_of_plan_anchor() {
        let plan = ProductionDoryV3CeremonyRecordPlan::CommitmentSet(Box::new(PriorRecordsPlan {
            prior_records: Vec::new(),
        }));
        assert!(matches!(
            prepare_decoded_plan(plan, file_identity_for_bytes(b"plan"), None),
            Err(ProductionDoryV3CeremonyAuthoringError::MissingCeremonyIdAnchor)
        ));
    }

    #[test]
    fn genesis_plan_prepares_externally_signs_stages_and_reopens_canonically() {
        let directory = TestDirectory::new();
        let operators = test_keys(3, 1);
        let reproducers = test_keys(2, 20);
        let plan_bytes = genesis_plan_bytes(&directory, &operators, &reproducers);
        let plan_path = write_test_input(&directory, "genesis-plan.json", &plan_bytes);
        let output = directory.0.join("genesis.cmfdcr01");

        let prepared = prepare_production_dory_v3_ceremony_record(&plan_path, None).unwrap();
        assert_eq!(prepared.plan_file(), &file_identity_for_bytes(&plan_bytes));
        assert_eq!(prepared.required_signers().len(), 5);
        let signatures = sign_prepared_record(&prepared, &operators, &reproducers);
        let expected_signatures = signatures.clone();
        let report =
            stage_production_dory_v3_ceremony_record(&plan_path, None, signatures, &output)
                .unwrap();

        let reopened = fs::read(&output).unwrap();
        let record = decode_ceremony_record(&reopened).unwrap();
        assert_eq!(record.body, *prepared.body());
        assert_eq!(record.signatures, expected_signatures);
        assert_eq!(encode_ceremony_record(&record).unwrap(), reopened);
        assert_eq!(report.plan_file(), prepared.plan_file());
        assert_eq!(report.record_file(), &file_identity_for_bytes(&reopened));
        assert_eq!(
            report.record_content_digest(),
            prepared.record_content_digest()
        );
        assert_eq!(report.signature_message(), prepared.signature_message());
        assert_eq!(report.signer_count(), 5);
        assert!(report.publication_pending());

        let post_genesis_plan = serde_json::to_vec(&serde_json::json!({
            "record_type": "type_3_commitment_set",
            "plan": {"prior_records": [&output]},
        }))
        .unwrap();
        let post_genesis_plan_path =
            write_test_input(&directory, "commitment-set-plan.json", &post_genesis_plan);
        assert!(matches!(
            prepare_production_dory_v3_ceremony_record(&post_genesis_plan_path, None),
            Err(ProductionDoryV3CeremonyAuthoringError::MissingCeremonyIdAnchor)
        ));
        let mut wrong_anchor = prepared.record_content_digest();
        wrong_anchor[0] ^= 1;
        assert!(matches!(
            prepare_production_dory_v3_ceremony_record(&post_genesis_plan_path, Some(wrong_anchor)),
            Err(ProductionDoryV3CeremonyAuthoringError::CeremonyIdAnchorMismatch)
        ));
    }

    #[test]
    fn external_signature_verifier_enforces_exact_slots_and_valid_signatures() {
        let operators = test_keys(3, 1);
        let reproducers = test_keys(2, 20);
        let record = sign_test_record(
            CeremonyRecordBody::Genesis(Box::new(test_genesis(&operators, &reproducers))),
            &all_test_signers(&operators, &reproducers),
        );
        let expected = required_signers_for_body(&record.body, None).unwrap();
        verify_signatures_against(&record, &expected).unwrap();

        let mut missing = record.clone();
        missing.signatures.pop();
        assert!(matches!(
            verify_signatures_against(&missing, &expected),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));

        let mut extra = record.clone();
        extra.signatures.push(record.signatures[0].clone());
        assert!(matches!(
            verify_signatures_against(&extra, &expected),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));

        let mut wrong_class = record.clone();
        wrong_class.signatures[0].signer_class = SignerClass::Reproducer;
        assert!(matches!(
            verify_signatures_against(&wrong_class, &expected),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));

        let mut duplicate = record.clone();
        duplicate.signatures[1].signer_class = duplicate.signatures[0].signer_class;
        duplicate.signatures[1].signer_index = duplicate.signatures[0].signer_index;
        assert!(matches!(
            verify_signatures_against(&duplicate, &expected),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));

        let wrong_key = SigningKey::from_bytes(&[99; 32]).unwrap();
        let message = ceremony_record_signature_message(&record.body).unwrap();
        let invalid_signature: Signature = wrong_key.sign_raw(&message, &[0; 32]).unwrap();
        let mut invalid = record;
        invalid.signatures[0].signature = invalid_signature.to_bytes();
        assert!(matches!(
            verify_signatures_against(&invalid, &expected),
            Err(ProductionDoryV3CeremonyAuthoringError::Transcript(
                CeremonyTranscriptError::InvalidSignature
            ))
        ));
    }

    #[test]
    fn type_six_signer_policy_requires_exact_full_roster_order() {
        let fixture = completed_transcript_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&fixture.bytes).unwrap();
        let final_record = transcript.records().last().unwrap();
        let genesis = match &transcript.records()[0].body {
            CeremonyRecordBody::Genesis(genesis) => genesis.as_ref(),
            _ => unreachable!(),
        };
        let required = required_signers_for_body(&final_record.body, Some(genesis)).unwrap();
        assert_eq!(
            required.len(),
            fixture.operators.len() + fixture.reproducers.len()
        );
        assert_eq!(required[0].signer_class(), SignerClass::Operator);
        assert_eq!(required[2].signer_index(), 2);
        assert_eq!(required[3].signer_class(), SignerClass::Reproducer);
        assert_eq!(required[4].signer_index(), 1);
        verify_signatures_against(final_record, &required).unwrap();

        let mut reordered = final_record.clone();
        reordered.signatures.swap(0, 1);
        assert!(matches!(
            verify_signatures_against(&reordered, &required),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));
    }

    #[test]
    fn type_six_stage_reopens_create_new_output_and_runs_final_guard() {
        let directory = TestDirectory::new();
        let fixture = completed_transcript_fixture();
        let transcript = parse_and_verify_ceremony_transcript(&fixture.bytes).unwrap();
        let final_record = transcript.records().last().unwrap().clone();
        let body = match &final_record.body {
            CeremonyRecordBody::FinalReceipt(body) => body.as_ref().clone(),
            _ => unreachable!(),
        };
        let genesis = match &transcript.records()[0].body {
            CeremonyRecordBody::Genesis(genesis) => genesis.as_ref(),
            _ => unreachable!(),
        };
        let required = required_signers_for_body(&final_record.body, Some(genesis)).unwrap();
        let output = directory.0.join("final-receipt.cmfdcr01");
        let mut guard_calls = 0;
        let guard_order = RefCell::new(Vec::new());
        let staged = persist_production_dory_v3_final_receipt(
            &body,
            &required,
            final_record.signatures.clone(),
            &output,
            || {
                guard_order.borrow_mut().push("retained inputs");
                Ok(())
            },
            || {
                guard_order.borrow_mut().push("final candidate");
                guard_calls += 1;
                Ok(body.clone())
            },
        )
        .unwrap();
        let reopened = fs::read(&output).unwrap();
        assert_eq!(decode_ceremony_record(&reopened).unwrap(), final_record);
        assert_eq!(encode_ceremony_record(&final_record).unwrap(), reopened);
        assert_eq!(staged.record_file, file_identity_for_bytes(&reopened));
        assert_eq!(guard_calls, 1);
        assert_eq!(
            guard_order.into_inner(),
            ["retained inputs", "final candidate"]
        );

        assert!(matches!(
            persist_production_dory_v3_final_receipt(
                &body,
                &required,
                final_record.signatures.clone(),
                &output,
                || Ok(()),
                || Ok(body.clone())
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::Filesystem(message))
                if message.contains("refusing to overwrite existing output")
        ));

        let retained_rejected_output = directory.0.join("retained-rejected-final-receipt.cmfdcr01");
        assert!(matches!(
            persist_production_dory_v3_final_receipt(
                &body,
                &required,
                final_record.signatures.clone(),
                &retained_rejected_output,
                || {
                    Err(ProductionDoryV3CeremonyAuthoringError::RetainedInputGuard(
                        "changed plan".to_owned(),
                    ))
                },
                || Ok(body.clone())
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::RetainedInputGuard(message))
                if message == "changed plan"
        ));
        assert!(!retained_rejected_output.exists());

        let rejected_output = directory.0.join("rejected-final-receipt.cmfdcr01");
        let mut changed = body.clone();
        changed.raw_payload_blake3[0] ^= 1;
        assert!(matches!(
            persist_production_dory_v3_final_receipt(
                &body,
                &required,
                final_record.signatures,
                &rejected_output,
                || Ok(()),
                || Ok(changed)
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::FinalCandidateProjectionChanged)
        ));
        assert!(!rejected_output.exists());
    }

    #[test]
    fn anchored_type_five_prefix_stages_create_new_and_reparses() {
        let directory = TestDirectory::new();
        let fixture = type_five_fixture();
        let record_paths = persist_fixture_records(&directory, &fixture.records);
        let output = directory.0.join("reveal-set-prefix.cmfdct01");

        let report = stage_production_dory_v3_ceremony_reveal_set_prefix(
            &record_paths,
            fixture.ceremony_id,
            &output,
        )
        .unwrap();
        let bytes = fs::read(&output).unwrap();
        let reparsed = parse_and_verify_reveal_set_prefix(&bytes, fixture.ceremony_id).unwrap();

        assert_eq!(report.output(), output);
        assert_eq!(report.transcript_file(), &file_identity_for_bytes(&bytes));
        assert_eq!(report.ceremony_id(), fixture.ceremony_id);
        assert_eq!(report.record_count(), fixture.records.len() as u16);
        assert_eq!(reparsed.records(), fixture.records);
        assert_eq!(
            report.transcript_derive_key_digest(),
            reparsed.transcript_derive_key_digest()
        );
        assert!(report.publication_pending());

        let original = bytes;
        assert!(matches!(
            stage_production_dory_v3_ceremony_reveal_set_prefix(
                &record_paths,
                fixture.ceremony_id,
                &output
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::Filesystem(message))
                if message.contains("refusing to overwrite existing output")
        ));
        assert_eq!(fs::read(output).unwrap(), original);
    }

    #[test]
    fn prefix_stage_rejects_wrong_independent_ceremony_anchor() {
        let directory = TestDirectory::new();
        let fixture = type_five_fixture();
        let record_paths = persist_fixture_records(&directory, &fixture.records);
        let output = directory.0.join("wrong-anchor-prefix.cmfdct01");
        let mut wrong_anchor = fixture.ceremony_id;
        wrong_anchor[0] ^= 1;

        assert!(matches!(
            stage_production_dory_v3_ceremony_reveal_set_prefix(
                &record_paths,
                wrong_anchor,
                &output
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::CeremonyIdAnchorMismatch)
        ));
        assert!(!output.exists());
    }

    #[test]
    fn completed_transcript_stage_rebuilds_n3_r2_and_is_create_new() {
        let directory = TestDirectory::new();
        let fixture = completed_transcript_fixture();
        assert_eq!(fixture.operators.len(), 3);
        assert_eq!(fixture.reproducers.len(), 2);
        let (prefix_path, prefix_bytes, final_receipt_path, final_receipt_bytes) =
            persist_completed_transcript_inputs(&directory, &fixture);
        let output = directory.0.join("completed-transcript.cmfdct01");

        let report = stage_production_dory_v3_completed_ceremony_transcript(
            &prefix_path,
            &final_receipt_path,
            fixture.ceremony_id,
            &output,
        )
        .unwrap();
        let reopened = fs::read(&output).unwrap();
        let completed =
            parse_and_verify_completed_ceremony_transcript(&reopened, fixture.ceremony_id).unwrap();

        assert_eq!(reopened, fixture.bytes);
        assert_eq!(completed.operators().len(), 3);
        assert_eq!(completed.reproducers().len(), 2);
        assert_eq!(report.output(), output);
        assert_eq!(
            report.reveal_set_prefix_file(),
            &file_identity_for_bytes(&prefix_bytes)
        );
        assert_eq!(
            report.final_receipt_record_file(),
            &file_identity_for_bytes(&final_receipt_bytes)
        );
        assert_eq!(
            report.transcript_file(),
            &file_identity_for_bytes(&reopened)
        );
        assert_eq!(report.ceremony_id(), fixture.ceremony_id);
        assert_eq!(report.record_count(), 10);
        assert_eq!(
            report.transcript_derive_key_digest(),
            completed.transcript_derive_key_digest()
        );
        assert!(report.publication_pending());

        assert!(matches!(
            stage_production_dory_v3_completed_ceremony_transcript(
                &prefix_path,
                &final_receipt_path,
                fixture.ceremony_id,
                &output
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::Filesystem(message))
                if message.contains("refusing to overwrite existing output")
        ));
        assert_eq!(fs::read(output).unwrap(), reopened);
    }

    #[test]
    fn completed_transcript_stage_rejects_wrong_anchor_type_trailing_and_duplicate_inputs() {
        let directory = TestDirectory::new();
        let fixture = completed_transcript_fixture();
        let (prefix_path, prefix_bytes, final_receipt_path, final_receipt_bytes) =
            persist_completed_transcript_inputs(&directory, &fixture);

        let mut wrong_anchor = fixture.ceremony_id;
        wrong_anchor[0] ^= 1;
        let wrong_anchor_output = directory.0.join("wrong-anchor-completed.cmfdct01");
        assert!(
            stage_production_dory_v3_completed_ceremony_transcript(
                &prefix_path,
                &final_receipt_path,
                wrong_anchor,
                &wrong_anchor_output
            )
            .is_err()
        );
        assert!(!wrong_anchor_output.exists());

        let prefix =
            parse_and_verify_reveal_set_prefix(&prefix_bytes, fixture.ceremony_id).unwrap();
        let wrong_type_bytes = encode_ceremony_record(prefix.records().last().unwrap()).unwrap();
        let wrong_type_path =
            write_test_input(&directory, "wrong-type.cmfdcr01", &wrong_type_bytes);
        let wrong_type_output = directory.0.join("wrong-type-completed.cmfdct01");
        assert!(matches!(
            stage_production_dory_v3_completed_ceremony_transcript(
                &prefix_path,
                &wrong_type_path,
                fixture.ceremony_id,
                &wrong_type_output
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::WrongNextRecord)
        ));
        assert!(!wrong_type_output.exists());

        let mut trailing_bytes = final_receipt_bytes;
        trailing_bytes.push(0);
        let trailing_path =
            write_test_input(&directory, "trailing-final.cmfdcr01", &trailing_bytes);
        let trailing_output = directory.0.join("trailing-completed.cmfdct01");
        assert!(matches!(
            stage_production_dory_v3_completed_ceremony_transcript(
                &prefix_path,
                &trailing_path,
                fixture.ceremony_id,
                &trailing_output
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::Transcript(_))
        ));
        assert!(!trailing_output.exists());

        let duplicate_output = directory.0.join("duplicate-completed.cmfdct01");
        assert!(matches!(
            stage_production_dory_v3_completed_ceremony_transcript(
                &prefix_path,
                &prefix_path,
                fixture.ceremony_id,
                &duplicate_output
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::DuplicateInput(path))
                if path == prefix_path
        ));
        assert!(!duplicate_output.exists());
    }

    #[test]
    fn completed_transcript_stage_rejects_same_ceremony_cross_fork_receipt() {
        let directory = TestDirectory::new();
        let fixture = completed_transcript_fixture();
        let completed =
            parse_and_verify_completed_ceremony_transcript(&fixture.bytes, fixture.ceremony_id)
                .unwrap();
        let mut fork_records = completed.records()[..completed.records().len() - 1].to_vec();
        let operator_signers: Vec<_> = fixture
            .operators
            .iter()
            .enumerate()
            .map(|(index, key)| (SignerClass::Operator, index as u16, key))
            .collect();

        let CeremonyRecordBody::ContributionCommitment(commitment) = &mut fork_records[1].body
        else {
            panic!("fixture record 1 must be type 2");
        };
        commitment.generation_finished_unix_seconds += 1;
        fork_records[1] = sign_test_record(
            fork_records[1].body.clone(),
            &[(SignerClass::Operator, 0, &fixture.operators[0])],
        );
        let fork_commitment_digest = ceremony_signed_record_digest(&fork_records[1]).unwrap();

        let CeremonyRecordBody::CommitmentSet(commitment_set) = &mut fork_records[4].body else {
            panic!("fixture record 4 must be type 3");
        };
        commitment_set.commitments[0].signed_record_digest = fork_commitment_digest;
        fork_records[4] = sign_test_record(fork_records[4].body.clone(), &operator_signers);
        let fork_commitment_set_digest = ceremony_signed_record_digest(&fork_records[4]).unwrap();

        let CeremonyRecordBody::ContributionReveal(reveal) = &mut fork_records[5].body else {
            panic!("fixture record 5 must be type 4");
        };
        reveal.contribution_commitment_signed_record_digest = fork_commitment_digest;
        fork_records[5] = sign_test_record(
            fork_records[5].body.clone(),
            &[(SignerClass::Operator, 0, &fixture.operators[0])],
        );
        let fork_reveal_digest = ceremony_signed_record_digest(&fork_records[5]).unwrap();

        let CeremonyRecordBody::RevealSet(reveal_set) = &mut fork_records[8].body else {
            panic!("fixture record 8 must be type 5");
        };
        reveal_set.commitment_set_signed_record_digest = fork_commitment_set_digest;
        reveal_set.reveals[0].signed_record_digest = fork_reveal_digest;
        fork_records[8] = sign_test_record(fork_records[8].body.clone(), &operator_signers);

        let fork_prefix_bytes =
            encode_and_verify_reveal_set_prefix(&fork_records, fixture.ceremony_id).unwrap();
        let fork_prefix_path =
            write_test_input(&directory, "fork-prefix.cmfdct01", &fork_prefix_bytes);
        let original_final_receipt =
            encode_ceremony_record(completed.records().last().unwrap()).unwrap();
        let final_receipt_path = write_test_input(
            &directory,
            "other-fork-final-receipt.cmfdcr01",
            &original_final_receipt,
        );
        let output = directory.0.join("cross-fork-completed.cmfdct01");

        assert!(
            stage_production_dory_v3_completed_ceremony_transcript(
                &fork_prefix_path,
                &final_receipt_path,
                fixture.ceremony_id,
                &output
            )
            .is_err()
        );
        assert!(!output.exists());
    }

    #[test]
    fn completed_transcript_stage_rejects_missing_bad_and_swapped_type_six_signatures() {
        let directory = TestDirectory::new();
        let fixture = completed_transcript_fixture();
        let (prefix_path, _, _, final_receipt_bytes) =
            persist_completed_transcript_inputs(&directory, &fixture);
        let final_receipt = decode_ceremony_record(&final_receipt_bytes).unwrap();

        let mut missing = final_receipt.clone();
        missing.signatures.pop();
        let missing_path = write_test_input(
            &directory,
            "missing-signature.cmfdcr01",
            &encode_ceremony_record(&missing).unwrap(),
        );
        let missing_output = directory.0.join("missing-signature.cmfdct01");
        assert!(matches!(
            stage_production_dory_v3_completed_ceremony_transcript(
                &prefix_path,
                &missing_path,
                fixture.ceremony_id,
                &missing_output
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));
        assert!(!missing_output.exists());

        let mut bad = final_receipt.clone();
        bad.signatures[0].signature[0] ^= 1;
        let bad_path = write_test_input(
            &directory,
            "bad-signature.cmfdcr01",
            &encode_ceremony_record(&bad).unwrap(),
        );
        let bad_output = directory.0.join("bad-signature.cmfdct01");
        assert!(matches!(
            stage_production_dory_v3_completed_ceremony_transcript(
                &prefix_path,
                &bad_path,
                fixture.ceremony_id,
                &bad_output
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::Transcript(
                CeremonyTranscriptError::MalformedSignature
                    | CeremonyTranscriptError::InvalidSignature
            ))
        ));
        assert!(!bad_output.exists());

        let mut swapped = final_receipt;
        let first_signature = swapped.signatures[0].signature;
        swapped.signatures[0].signature = swapped.signatures[1].signature;
        swapped.signatures[1].signature = first_signature;
        let swapped_path = write_test_input(
            &directory,
            "swapped-signatures.cmfdcr01",
            &encode_ceremony_record(&swapped).unwrap(),
        );
        let swapped_output = directory.0.join("swapped-signatures.cmfdct01");
        assert!(matches!(
            stage_production_dory_v3_completed_ceremony_transcript(
                &prefix_path,
                &swapped_path,
                fixture.ceremony_id,
                &swapped_output
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::Transcript(
                CeremonyTranscriptError::InvalidSignature
            ))
        ));
        assert!(!swapped_output.exists());
    }

    #[test]
    fn completed_transcript_stage_rejects_terminal_transcript_as_prefix() {
        let directory = TestDirectory::new();
        let completed_fixture = completed_transcript_fixture();
        let completed_path = write_test_input(
            &directory,
            "already-completed.cmfdct01",
            &completed_fixture.bytes,
        );
        let completed = parse_and_verify_completed_ceremony_transcript(
            &completed_fixture.bytes,
            completed_fixture.ceremony_id,
        )
        .unwrap();
        let final_receipt_bytes =
            encode_ceremony_record(completed.records().last().unwrap()).unwrap();
        let final_receipt_path = write_test_input(
            &directory,
            "terminal-prefix-final.cmfdcr01",
            &final_receipt_bytes,
        );
        let completed_output = directory.0.join("completed-as-prefix-output.cmfdct01");
        assert!(
            stage_production_dory_v3_completed_ceremony_transcript(
                &completed_path,
                &final_receipt_path,
                completed_fixture.ceremony_id,
                &completed_output
            )
            .is_err()
        );
        assert!(!completed_output.exists());

        let aborted_fixture = aborted_transcript_fixture(12);
        let aborted_path = write_test_input(
            &directory,
            "aborted-as-prefix.cmfdct01",
            &aborted_fixture.bytes,
        );
        let aborted_output = directory.0.join("aborted-as-prefix-output.cmfdct01");
        assert!(
            stage_production_dory_v3_completed_ceremony_transcript(
                &aborted_path,
                &final_receipt_path,
                aborted_fixture.ceremony_id,
                &aborted_output
            )
            .is_err()
        );
        assert!(!aborted_output.exists());
    }

    #[test]
    fn completed_transcript_stage_cleans_output_on_final_reauthentication_failure() {
        let directory = TestDirectory::new();
        let fixture = completed_transcript_fixture();
        let (prefix_path, _, final_receipt_path, _) =
            persist_completed_transcript_inputs(&directory, &fixture);
        let output = directory.0.join("failed-final-reauth-completed.cmfdct01");
        let expected_failure_path = prefix_path.clone();

        assert!(matches!(
            stage_production_dory_v3_completed_ceremony_transcript_with_final_reauthentication_hook(
                &prefix_path,
                &final_receipt_path,
                fixture.ceremony_id,
                &output,
                || Err(ProductionDoryV3CeremonyAuthoringError::InputChanged(
                    expected_failure_path
                ))
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::InputChanged(path))
                if path == prefix_path
        ));
        assert!(!output.exists());
    }

    #[cfg(windows)]
    #[test]
    fn completed_transcript_stage_retains_windows_input_share_denials_until_confirmation() {
        let directory = TestDirectory::new();
        let fixture = completed_transcript_fixture();
        let (prefix_path, _, final_receipt_path, _) =
            persist_completed_transcript_inputs(&directory, &fixture);
        let output = directory.0.join("windows-retained-inputs.cmfdct01");
        let prefix_for_write = prefix_path.clone();
        let receipt_for_delete = final_receipt_path.clone();
        let mut write_denied = false;
        let mut delete_denied = false;

        let report =
            stage_production_dory_v3_completed_ceremony_transcript_with_final_reauthentication_hook(
                &prefix_path,
                &final_receipt_path,
                fixture.ceremony_id,
                &output,
                || {
                    write_denied = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&prefix_for_write)
                        .is_err();
                    delete_denied = fs::remove_file(&receipt_for_delete).is_err();
                    Ok(())
                },
            )
            .unwrap();
        assert!(write_denied);
        assert!(delete_denied);
        assert!(report.publication_pending());
        assert!(output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn completed_transcript_stage_rejects_replaced_input_before_confirmation() {
        let directory = TestDirectory::new();
        let fixture = completed_transcript_fixture();
        let (prefix_path, _, final_receipt_path, _) =
            persist_completed_transcript_inputs(&directory, &fixture);
        let output = directory.0.join("replaced-input-completed.cmfdct01");
        let replacement_path = prefix_path.clone();
        let retained_path = directory.0.join("retained-old-prefix.cmfdct01");

        let result =
            stage_production_dory_v3_completed_ceremony_transcript_with_final_reauthentication_hook(
                &prefix_path,
                &final_receipt_path,
                fixture.ceremony_id,
                &output,
                || {
                    fs::rename(&replacement_path, &retained_path).unwrap();
                    fs::write(&replacement_path, b"replacement").unwrap();
                    Ok(())
                },
            );
        assert!(result.is_err());
        assert!(!output.exists());
    }

    #[test]
    fn attestation_signer_policy_distinguishes_completed_and_aborted_transcripts() {
        let operators = [[1; 32], [2; 32], [3; 32]];
        let reproducers = [[4; 32], [5; 32]];
        let completed = required_attestation_signers_for_status(
            CeremonyTranscriptStatus::Completed,
            &operators,
            &reproducers,
            &[],
        )
        .unwrap();
        assert_eq!(completed.len(), 5);
        assert_eq!(completed[0].signer_class(), SignerClass::Operator);
        assert_eq!(completed[2].signer_index(), 2);
        assert_eq!(completed[3].signer_class(), SignerClass::Reproducer);
        assert_eq!(completed[4].signer_index(), 1);

        let selected = [ProductionDoryV3CeremonyAttestationSigner::new(
            SignerClass::Reproducer,
            1,
        )];
        assert!(matches!(
            required_attestation_signers_for_status(
                CeremonyTranscriptStatus::Completed,
                &operators,
                &reproducers,
                &selected
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));
        assert!(matches!(
            required_attestation_signers_for_status(
                CeremonyTranscriptStatus::Aborted,
                &operators,
                &reproducers,
                &[]
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));
        let aborted = required_attestation_signers_for_status(
            CeremonyTranscriptStatus::Aborted,
            &operators,
            &reproducers,
            &selected,
        )
        .unwrap();
        assert_eq!(aborted.len(), 1);
        assert_eq!(aborted[0].signer_class(), SignerClass::Reproducer);
        assert_eq!(aborted[0].signer_index(), 1);
        assert_eq!(aborted[0].public_key(), [5; 32]);

        let unordered = [
            ProductionDoryV3CeremonyAttestationSigner::new(SignerClass::Reproducer, 1),
            ProductionDoryV3CeremonyAttestationSigner::new(SignerClass::Operator, 2),
        ];
        let canonical = required_attestation_signers_for_status(
            CeremonyTranscriptStatus::Aborted,
            &operators,
            &reproducers,
            &unordered,
        )
        .unwrap();
        assert_eq!(canonical.len(), 2);
        assert_eq!(canonical[0].signer_class(), SignerClass::Operator);
        assert_eq!(canonical[0].signer_index(), 2);
        assert_eq!(canonical[1].signer_class(), SignerClass::Reproducer);
        assert_eq!(canonical[1].signer_index(), 1);
    }

    #[test]
    fn completed_attestation_prepares_all_signers_stages_and_reopens() {
        let directory = TestDirectory::new();
        let fixture = completed_transcript_fixture();
        let transcript_path = write_test_input(&directory, "completed.cmfdct01", &fixture.bytes);
        let output = directory.0.join("completed.cmfdta01");
        let forbidden_selector = [ProductionDoryV3CeremonyAttestationSigner::new(
            SignerClass::Operator,
            0,
        )];
        assert!(matches!(
            prepare_production_dory_v3_ceremony_attestation(
                &transcript_path,
                fixture.ceremony_id,
                &forbidden_selector
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));

        let prepared = prepare_production_dory_v3_ceremony_attestation(
            &transcript_path,
            fixture.ceremony_id,
            &[],
        )
        .unwrap();
        assert_eq!(prepared.status(), CeremonyTranscriptStatus::Completed);
        assert_eq!(prepared.required_signers().len(), 5);
        let signatures =
            sign_prepared_attestation(&prepared, &fixture.operators, &fixture.reproducers);
        let report = stage_production_dory_v3_ceremony_attestation(
            &transcript_path,
            fixture.ceremony_id,
            &[],
            signatures,
            &output,
        )
        .unwrap();

        let transcript = parse_and_verify_ceremony_transcript(&fixture.bytes).unwrap();
        assert_eq!(transcript.status(), CeremonyTranscriptStatus::Completed);
        let attestation_bytes = fs::read(&output).unwrap();
        let attestation =
            verify_detached_transcript_attestation(&attestation_bytes, &transcript).unwrap();
        assert_eq!(attestation.signatures.len(), 5);
        assert_eq!(report.status(), CeremonyTranscriptStatus::Completed);
        assert_eq!(report.signer_count(), 5);
        assert_eq!(report.staged_signers(), prepared.required_signers());
        assert_eq!(
            report.staged_signers()[0].signer_class(),
            SignerClass::Operator
        );
        assert_eq!(report.staged_signers()[2].signer_index(), 2);
        assert_eq!(
            report.staged_signers()[3].signer_class(),
            SignerClass::Reproducer
        );
        let expected_reproducer_key: [u8; 32] =
            fixture.reproducers[1].verifying_key().to_bytes().into();
        assert_eq!(
            report.staged_signers()[4].public_key(),
            expected_reproducer_key
        );
        assert_eq!(
            report.attestation_file(),
            &file_identity_for_bytes(&attestation_bytes)
        );
        assert!(report.publication_pending());
    }

    #[test]
    fn aborted_attestation_prepares_and_stages_reproducer_only_with_equal_message() {
        let directory = TestDirectory::new();
        let fixture = aborted_transcript_fixture(12);
        let transcript_path = write_test_input(&directory, "aborted.cmfdct01", &fixture.bytes);
        let output = directory.0.join("aborted.cmfdta01");
        let selected = [ProductionDoryV3CeremonyAttestationSigner::new(
            SignerClass::Reproducer,
            1,
        )];

        let prepared = prepare_production_dory_v3_ceremony_attestation(
            &transcript_path,
            fixture.ceremony_id,
            &selected,
        )
        .unwrap();
        assert_eq!(prepared.status(), CeremonyTranscriptStatus::Aborted);
        assert_eq!(
            prepared.transcript_file(),
            &file_identity_for_bytes(&fixture.bytes)
        );
        assert_eq!(prepared.required_signers().len(), 1);
        assert_eq!(
            prepared.required_signers()[0].signer_class(),
            SignerClass::Reproducer
        );
        let signatures =
            sign_prepared_attestation(&prepared, &fixture.operators, &fixture.reproducers);
        let report = stage_production_dory_v3_ceremony_attestation(
            &transcript_path,
            fixture.ceremony_id,
            &selected,
            signatures,
            &output,
        )
        .unwrap();

        let transcript = parse_and_verify_ceremony_transcript(&fixture.bytes).unwrap();
        let attestation_bytes = fs::read(&output).unwrap();
        let attestation =
            verify_detached_transcript_attestation(&attestation_bytes, &transcript).unwrap();
        assert_eq!(
            ceremony_attestation_signature_message(&attestation).unwrap(),
            prepared.signature_message()
        );
        assert_eq!(report.signature_message(), prepared.signature_message());
        assert_eq!(report.transcript_file(), prepared.transcript_file());
        assert_eq!(
            report.attestation_file(),
            &file_identity_for_bytes(&attestation_bytes)
        );
        assert_eq!(report.signer_count(), 1);
        assert_eq!(report.staged_signers(), prepared.required_signers());
        let expected_reproducer_key: [u8; 32] =
            fixture.reproducers[1].verifying_key().to_bytes().into();
        assert_eq!(
            report.staged_signers()[0].public_key(),
            expected_reproducer_key
        );
        assert!(report.publication_pending());

        let original = attestation_bytes;
        let signatures =
            sign_prepared_attestation(&prepared, &fixture.operators, &fixture.reproducers);
        assert!(matches!(
            stage_production_dory_v3_ceremony_attestation(
                &transcript_path,
                fixture.ceremony_id,
                &selected,
                signatures,
                &output
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::Filesystem(message))
                if message.contains("refusing to overwrite existing output")
        ));
        assert_eq!(fs::read(output).unwrap(), original);
    }

    #[test]
    fn attestation_prepare_rejects_wrong_anchor_prefix_and_bad_aborted_subsets() {
        let directory = TestDirectory::new();
        let aborted = aborted_transcript_fixture(12);
        let aborted_path = write_test_input(&directory, "aborted.cmfdct01", &aborted.bytes);
        let selected = [ProductionDoryV3CeremonyAttestationSigner::new(
            SignerClass::Operator,
            0,
        )];
        let mut wrong_anchor = aborted.ceremony_id;
        wrong_anchor[0] ^= 1;
        assert!(matches!(
            prepare_production_dory_v3_ceremony_attestation(&aborted_path, wrong_anchor, &selected),
            Err(ProductionDoryV3CeremonyAuthoringError::CeremonyIdAnchorMismatch)
        ));

        let prefix_fixture = type_five_fixture();
        let prefix_bytes = encode_and_verify_reveal_set_prefix(
            &prefix_fixture.records,
            prefix_fixture.ceremony_id,
        )
        .unwrap();
        let prefix_path = write_test_input(&directory, "prefix.cmfdct01", &prefix_bytes);
        assert!(
            prepare_production_dory_v3_ceremony_attestation(
                &prefix_path,
                prefix_fixture.ceremony_id,
                &selected
            )
            .is_err()
        );

        let duplicate = [selected[0], selected[0]];
        assert!(matches!(
            prepare_production_dory_v3_ceremony_attestation(
                &aborted_path,
                aborted.ceremony_id,
                &duplicate
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));
        let outside = [ProductionDoryV3CeremonyAttestationSigner::new(
            SignerClass::Reproducer,
            2,
        )];
        assert!(matches!(
            prepare_production_dory_v3_ceremony_attestation(
                &aborted_path,
                aborted.ceremony_id,
                &outside
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));
    }

    #[test]
    fn attestation_stage_rejects_zero_duplicate_outside_invalid_and_stale_signatures() {
        let directory = TestDirectory::new();
        let fixture = aborted_transcript_fixture(12);
        let transcript_path = write_test_input(&directory, "aborted.cmfdct01", &fixture.bytes);
        let selected = [ProductionDoryV3CeremonyAttestationSigner::new(
            SignerClass::Reproducer,
            1,
        )];
        let prepared = prepare_production_dory_v3_ceremony_attestation(
            &transcript_path,
            fixture.ceremony_id,
            &selected,
        )
        .unwrap();
        let valid = sign_prepared_attestation(&prepared, &fixture.operators, &fixture.reproducers);

        let missing_path = directory.0.join("missing.cmfdct01");
        assert!(matches!(
            stage_production_dory_v3_ceremony_attestation(
                &missing_path,
                fixture.ceremony_id,
                &selected,
                Vec::new(),
                &directory.0.join("zero.cmfdta01")
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));

        let duplicate = vec![valid[0].clone(), valid[0].clone()];
        assert!(matches!(
            stage_production_dory_v3_ceremony_attestation(
                &transcript_path,
                fixture.ceremony_id,
                &selected,
                duplicate,
                &directory.0.join("duplicate.cmfdta01")
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));

        let mut outside = valid.clone();
        outside[0].signer_index = 2;
        assert!(matches!(
            stage_production_dory_v3_ceremony_attestation(
                &transcript_path,
                fixture.ceremony_id,
                &selected,
                outside,
                &directory.0.join("outside.cmfdta01")
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::SignerPolicy)
        ));

        let wrong_key = SigningKey::from_bytes(&[99; 32]).unwrap();
        let wrong_signature: Signature = wrong_key
            .sign_raw(&prepared.signature_message(), &[0; 32])
            .unwrap();
        let mut invalid = valid.clone();
        invalid[0].signature = wrong_signature.to_bytes();
        assert!(matches!(
            stage_production_dory_v3_ceremony_attestation(
                &transcript_path,
                fixture.ceremony_id,
                &selected,
                invalid,
                &directory.0.join("invalid.cmfdta01")
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::Transcript(
                CeremonyTranscriptError::InvalidSignature
            ))
        ));

        let replacement = aborted_transcript_fixture(11);
        assert_eq!(replacement.ceremony_id, fixture.ceremony_id);
        fs::write(&transcript_path, replacement.bytes).unwrap();
        assert!(matches!(
            stage_production_dory_v3_ceremony_attestation(
                &transcript_path,
                fixture.ceremony_id,
                &selected,
                valid,
                &directory.0.join("stale.cmfdta01")
            ),
            Err(ProductionDoryV3CeremonyAuthoringError::Transcript(
                CeremonyTranscriptError::InvalidSignature
            ))
        ));
    }

    #[test]
    fn lowercase_hex_is_exact() {
        assert_eq!(parse_lower_hex::<2>("00af", "test").unwrap(), [0, 0xaf]);
        assert!(parse_lower_hex::<2>("00AF", "test").is_err());
        assert!(parse_lower_hex::<2>("af", "test").is_err());
    }

    #[test]
    fn every_successful_stage_is_publication_pending() {
        // The field is not caller-controlled and the constructor is private.
        let report = ProductionDoryV3CeremonyRecordStageReport {
            output: PathBuf::from("unused"),
            plan_file: file_identity_for_bytes(b"plan"),
            record_file: file_identity_for_bytes(b"record"),
            record_type: 1,
            record_content_digest: [1; 32],
            signed_record_digest: [2; 32],
            signature_message: [3; 32],
            signer_count: 5,
            durability: ProductionDoryV3CeremonyRecordStageDurability::FileAndParentDirectorySynced,
            publication_pending: true,
        };
        assert!(report.publication_pending());
    }
}
