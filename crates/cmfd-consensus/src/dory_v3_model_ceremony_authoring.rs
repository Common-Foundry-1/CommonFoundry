//! Keyless record authoring for production Dory V3 ceremony records 1 through 5.
//!
//! A strict tagged JSON plan names trusted, immutable inputs. Preparation
//! authenticates those inputs and every prior signed record, derives the one
//! canonical record body, and returns only public signing material. Staging
//! repeats preparation, accepts externally produced BIP340 signatures, enforces
//! the frozen signer policy, and create-new persists one immutable record for
//! later append-only bulletin publication.
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
        CEREMONY_PROTOCOL_VERSION, CeremonyRecordBody, CeremonyTranscriptError, CommitmentSetBody,
        ContributionCommitmentBody, ContributionRevealBody, FileIdentity, GenesisBody,
        IndexedRecordDigest, MAX_CEREMONY_OPERATORS, MAX_CEREMONY_RECORD_BODY_BYTES,
        MAX_CEREMONY_SIGNERS, PRODUCTION_BANK_FORMAT_VERSION, PRODUCTION_BANK_HEADER_BYTES,
        PRODUCTION_BANKS, PRODUCTION_BASE_INPUT_BYTES, PRODUCTION_BATCH,
        PRODUCTION_BYTES_PER_LAYER, PRODUCTION_DIMENSION, PRODUCTION_LAYERS,
        PRODUCTION_LAYERS_PER_BANK, PRODUCTION_MAX_MODEL_BYTE, PRODUCTION_MODEL_VERSION,
        PRODUCTION_PADDED_VARIABLES, PRODUCTION_PAYLOAD_BYTES, RecordSignature, ReferenceBinary,
        RevealSetBody, RosterMember, SignedCeremonyRecord, SignerClass,
        ceremony_record_content_digest, ceremony_record_signature_message,
        ceremony_signed_record_digest, decode_ceremony_record, encode_and_verify_reveal_set_prefix,
        encode_ceremony_record, parse_and_verify_reveal_set_prefix,
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
        CeremonyRecordBody::FinalReceipt(_) | CeremonyRecordBody::Abort(_) => {
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
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use k256::schnorr::SigningKey;

    use super::*;
    use crate::dory_v3_model_ceremony_fs::prepare_test_parent;

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
    }

    fn test_file(byte: u8) -> FileIdentity {
        FileIdentity {
            bytes: u64::from(byte) + 1,
            blake3: [byte; 32],
            sha256: [byte.wrapping_add(1); 32],
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
