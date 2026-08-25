//! Fail-closed orchestration for one unchanged production Dory V3 qualification run.
//!
//! This module is deliberately dormant and feature-gated. It does not activate
//! V3 consensus. It joins the already-reviewed opaque capabilities into one
//! operator entry point that can measure an exact n=33 run without exposing a
//! second, configurable proof construction path.
//! The report is written after the proof and is the graceful-completion marker.
//! The required hash-chained journal records durable progress diagnostics, not
//! completion or resumability. The separate outputs cannot be made crash-atomic
//! as one filesystem commit.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use same_file::Handle as SameFileHandle;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::{
    BlockChallenge, BlockProof, ForgeMatrixV3CandidateProof, MODEL_BANK_HEADER_BYTES,
    dory_bls12_381_aggregate::BLS_DORY_COMPOSED_AGGREGATE_CLAIMS,
    dory_bls12_381_blake3::{
        BlsDoryBlake3ProductionPreflightError, projected_bls_dory_blake3_production_resources,
    },
    dory_bls12_381_candidate::{
        BlsDoryV3CandidateError, BlsDoryV3CandidatePayload, CANDIDATE_PAYLOAD_HEADER_BYTES,
        CANDIDATE_PAYLOAD_MAGIC, preflight_candidate_scratch,
        projected_candidate_required_free_scratch_bytes, verify_bls_dory_v3_layout_v5_candidate,
    },
    dory_bls12_381_execution_provider::{
        BlsDoryV3WinningNonceClaim, BlsDoryV3WinningNonceReplayError,
        derive_dory_v3_winning_nonce_claim_from_bank_authenticated_record,
        finish_prepared_bls_dory_v3_layout_v5_execution_with_composition,
        prepare_bls_dory_shared_layout_v5_from_verified_dory_v3_execution_with_scratch,
        replay_dory_v3_winning_nonce_from_bank_authenticated_record,
        seal_composed_bls_dory_v3_layout_v5_candidate,
    },
    dory_bls12_381_layout::{
        BLS_DORY_SHARED_PRODUCTION_VARIABLES, SHARED_PROOF_MAGIC,
        prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_with_scratch,
    },
    dory_bls12_381_prototype::{BlsDoryPrototypeError, deterministic_bls_dory_setup},
    dory_scratch_telemetry::ExactScratchReservationSession,
    dory_v3_model::DoryV3ModelIdentityError,
    dory_v3_model_record::{
        DoryV3ModelCommitmentRecordError, DoryV3ModelCommitmentRecordV2,
        derive_bank_authenticated_dory_v3_model_commitment_record_v2,
    },
    dory_v3_suite::{
        DORY_V3_ALGORITHM_VERSION, DORY_V3_PADDED_VARIABLES, DORY_V3_PROOF_VERSION,
        DORY_V3_SETUP_IDENTITY, DORY_V3_SHARED_LAYOUT_VERSION, Digest32,
    },
    dory_v3_transcript::DoryV3TranscriptContext,
    wire::{MAX_PROOF_BYTES, WireError, decode_forgematrix_proof, encode_forgematrix_proof},
};

const QUALIFICATION_REPORT_VERSION: u16 = 4;
const QUALIFICATION_JOURNAL_VERSION: u16 = 1;
const QUALIFICATION_REQUEST_GENERATION_REPORT_VERSION: u16 = 1;
const VERIFIER_REPORT_VERSION: u16 = 2;
const MAX_QUALIFICATION_REQUEST_JSON_BYTES: usize = 16 * 1024;
const MAX_QUALIFICATION_REPORT_JSON_BYTES: usize = 128 * 1024;
const MAX_QUALIFICATION_JOURNAL_BYTES: usize = 64 * 1024;
const MAX_RECORD_V2_JSON_BYTES: usize = 64 * 1024;
const SCRATCH_SAMPLE_INTERVAL: Duration = Duration::from_millis(100);
const QUALIFICATION_REQUEST_DIGEST_DOMAIN: &str = "CMFD/FORGEMATRIX/V3/QUALIFICATION-REQUEST/V1";
const QUALIFICATION_RUN_IDENTITY_DOMAIN: &str = "CMFD/FORGEMATRIX/V3/QUALIFICATION-RUN-IDENTITY/V1";
const QUALIFICATION_JOURNAL_RECORD_DIGEST_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/QUALIFICATION-JOURNAL-RECORD/V1";
const QUALIFICATION_JOURNAL_FILE_DIGEST_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/QUALIFICATION-JOURNAL-COMPLETE-FILE/V1";
const SAMPLED_SCRATCH_OBSERVATION_SCOPE: &str = "informational non-atomic periodic whole-directory observation; one traversal can combine files that never coexisted, so it is neither a lower nor upper bound and is not comparable to exact_peak_instrumented_scratch_*; exact instrumentation is authoritative";
const EXACT_SCRATCH_PEAK_SCOPE: &str = "exact per-session high-water mark of metadata.len logical bytes and live entries across all seven Dory scratch writer classes (the six runner-reachable classes plus dormant BlsDoryIndex); a per-session mutation lock spans tracked create, write, write_vectored, set_len, and same-file unlink with their ledger updates; excludes allocation blocks, filesystem metadata, RAM, and external mutation through handles outside TrackedScratchFile";
const WHOLE_PROCESS_PEAK_RSS_SCOPE: &str =
    "OS process-lifetime high-water mark; run the CLI in a fresh process for qualification";
const COOPERATIVE_CANCELLATION_SCOPE: &str = "the CLI maps Ctrl-C to the supplied flag; winning-claim replay polls it, other long stages observe it only after returning to a runner boundary";

const QUALIFICATION_JOURNAL_STAGES: [&str; 16] = [
    "preflight_completed",
    "resource_preflight_completed",
    "setup_validation_completed",
    "record_validation_completed",
    "bank_authentication_completed",
    "fixed_model_preparation_completed",
    "winning_claim_replay_completed",
    "candidate_resource_preflight_completed",
    "layout_v5_preparation_completed",
    "native_and_aggregate_composition_completed",
    "cp02_seal_completed",
    "scratch_cleanup_completed",
    "first_verification_completed",
    "wire_round_trip_completed",
    "second_verification_completed",
    "prepublication_verification_recorded",
];

const _: [(); 33] = [(); DORY_V3_PADDED_VARIABLES as usize];
const _: [(); DORY_V3_PADDED_VARIABLES as usize] = [(); BLS_DORY_SHARED_PRODUCTION_VARIABLES];
const _: [(); 134] = [(); BLS_DORY_COMPOSED_AGGREGATE_CLAIMS];

/// Exact public input for one production qualification run.
///
/// The two claimed digests are accelerator output only. The runner performs a
/// complete CPU replay and rejects them before publishing any proof bytes if
/// they do not match that replay or the block target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionDoryV3QualificationRequest {
    #[serde(deserialize_with = "deserialize_strict_block_challenge")]
    pub block: BlockChallenge,
    pub nonce: u64,
    pub final_activation_digest: Digest32,
    pub work_digest: Digest32,
}

/// Exact caller-selected block and nonce for one production-faithful request evaluation.
///
/// The final-activation and work digests are deliberately absent. They are
/// derived by a complete authenticated CPU execution and cannot be supplied by
/// the caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionDoryV3QualificationSeed {
    #[serde(deserialize_with = "deserialize_strict_block_challenge")]
    pub block: BlockChallenge,
    pub nonce: u64,
}

/// Measurements and identities retained after one request is derived and published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionDoryV3QualificationRequestGenerationReport {
    pub report_version: u16,
    pub network_id: Digest32,
    pub block_height: u64,
    pub nonce: u64,
    pub request_digest: Digest32,
    pub record_digest: Digest32,
    pub model_identity_digest: Digest32,
    pub setup_identity: Digest32,
    pub final_activation_digest: Digest32,
    pub work_digest: Digest32,
    pub request_bytes: u64,
    pub setup_nanoseconds: u64,
    pub record_load_and_validation_nanoseconds: u64,
    pub bank_reauthentication_nanoseconds: u64,
    pub nonce_evaluation_nanoseconds: u64,
    pub scratch_cleanup_nanoseconds: u64,
    pub request_publication_nanoseconds: u64,
    pub total_nanoseconds: u64,
    pub request_output_is_completion_marker: bool,
    pub publication_crash_atomic: bool,
    pub parent_directory_sync_performed: bool,
}

/// Exact measurements retained after one successful qualification run.
///
/// Artifact byte counts are exact and timings are wall-clock nanoseconds around
/// the named stage. Peak RSS is the OS process-lifetime high-water mark. The
/// periodically sampled whole-directory scratch fields are informational,
/// non-atomic observations: one traversal can combine files that never existed
/// concurrently, so they are neither a lower nor upper bound and are not
/// comparable to the authoritative exact scratch fields. Those exact fields
/// account for live tracked entries and their `metadata.len()` logical lengths
/// across every Dory scratch writer class. They are not physical disk
/// allocation, filesystem metadata, or RAM measurements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionDoryV3QualificationReport {
    pub report_version: u16,
    pub padded_variables: u32,
    pub composed_claims: u16,
    pub verifier_passes: u8,
    pub maximum_native_block_rows: u64,
    pub network_id: Digest32,
    pub block_height: u64,
    pub nonce: u64,
    pub request_digest: Digest32,
    pub record_digest: Digest32,
    pub model_identity_digest: Digest32,
    pub setup_identity: Digest32,
    pub challenge_digest: Digest32,
    pub final_activation_digest: Digest32,
    pub work_digest: Digest32,
    pub cp02_blake3_digest: Digest32,
    pub dory_proof_blake3_digest: Digest32,
    pub native_proof_blake3_digest: Digest32,
    pub wire_blake3_digest: Digest32,
    pub record_canonical_bytes: u64,
    pub cp02_bytes: u64,
    pub cp02_header_bytes: u64,
    pub dory_proof_bytes: u64,
    pub native_proof_bytes: u64,
    pub wire_bytes: u64,
    pub provisional_scratch_floor_bytes: u64,
    pub initial_available_scratch_bytes: u64,
    pub candidate_required_free_scratch_bytes: u64,
    pub candidate_available_free_scratch_bytes: u64,
    pub provisional_available_memory_floor_bytes: u64,
    pub observed_available_memory_before_bytes: u64,
    pub native_resource_projection_complete: bool,
    pub sampled_peak_scratch_entries_observation: u64,
    pub sampled_peak_scratch_logical_bytes_observation: u64,
    pub scratch_sample_interval_milliseconds: u64,
    pub sampled_peak_scratch_observation_scope: String,
    pub exact_peak_instrumented_scratch_logical_bytes: u64,
    pub exact_peak_instrumented_scratch_live_entries: u64,
    pub instrumented_scratch_file_creation_events: u64,
    pub instrumented_scratch_size_mutation_events: u64,
    pub exact_peak_scratch_instrumented: bool,
    pub exact_peak_scratch_scope: String,
    pub retained_scratch_entries: u64,
    pub retained_scratch_logical_bytes: u64,
    pub whole_process_peak_rss_bytes: u64,
    pub whole_process_peak_rss_scope: String,
    pub cooperative_cancellation_scope: String,
    pub qualification_journal: ProductionDoryV3QualificationJournalSummary,
    pub report_output_is_completion_marker: bool,
    pub publication_crash_atomic: bool,
    pub parent_directory_sync_performed: bool,
    pub setup_nanoseconds: u64,
    pub record_load_and_validation_nanoseconds: u64,
    pub bank_reauthentication_nanoseconds: u64,
    pub fixed_model_preparation_nanoseconds: u64,
    pub winning_claim_replay_nanoseconds: u64,
    pub candidate_resource_preflight_nanoseconds: u64,
    pub layout_v5_preparation_nanoseconds: u64,
    pub native_and_aggregate_composition_nanoseconds: u64,
    pub cp02_seal_nanoseconds: u64,
    pub scratch_cleanup_nanoseconds: u64,
    pub first_verification_nanoseconds: u64,
    pub wire_round_trip_nanoseconds: u64,
    pub second_verification_nanoseconds: u64,
    pub prepublication_qualification_nanoseconds: u64,
}

/// Hash-chain identity retained by a successful producer report.
///
/// The journal is durable progress diagnostics only. It neither proves a
/// successful qualification nor supports restart or resumption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionDoryV3QualificationJournalSummary {
    pub journal_version: u16,
    pub run_identity: Digest32,
    pub final_record_digest: Digest32,
    pub event_count: u64,
    pub journal_bytes: u64,
    pub complete_file_digest: Digest32,
    pub diagnostic_only: bool,
    pub completion_marker: bool,
    pub resumable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationEffectiveConfiguration {
    qualification_report_version: u16,
    padded_variables: u32,
    composed_claims: u16,
    verifier_passes: u8,
    maximum_native_block_rows: u64,
    algorithm_version: u32,
    proof_version: u32,
    shared_layout_version: u16,
    scratch_sample_interval_milliseconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationAuthenticatedIdentities {
    record_digest: Digest32,
    model_identity_digest: Digest32,
    setup_identity: Digest32,
}

#[derive(Serialize)]
struct QualificationJournalRecord<'a> {
    journal_version: u16,
    sequence: u64,
    previous_record_digest: Digest32,
    run_identity: Digest32,
    request_digest: Digest32,
    stage: &'a str,
    diagnostic_only: bool,
    completion_marker: bool,
    resumable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_configuration: Option<&'a QualificationEffectiveConfiguration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authenticated_identities: Option<QualificationAuthenticatedIdentities>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictQualificationJournalRecord {
    journal_version: u16,
    sequence: u64,
    previous_record_digest: Digest32,
    run_identity: Digest32,
    request_digest: Digest32,
    stage: String,
    diagnostic_only: bool,
    completion_marker: bool,
    resumable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_configuration: Option<QualificationEffectiveConfiguration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authenticated_identities: Option<QualificationAuthenticatedIdentities>,
}

/// Measurements from independently loading and verifying one persisted proof.
///
/// This runner never proves, mines, publishes, or creates a chain-admission
/// capability. Layout V5 decoding includes its canonical re-encoding check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionDoryV3VerifierReport {
    pub report_version: u16,
    pub network_id: Digest32,
    pub block_height: u64,
    pub nonce: u64,
    pub request_digest: Digest32,
    pub record_digest: Digest32,
    pub model_identity_digest: Digest32,
    pub setup_identity: Digest32,
    pub bank_content_blake3_digest: Digest32,
    pub bank_content_bytes: u64,
    pub producer_report_blake3_digest: Digest32,
    pub qualification_journal: ProductionDoryV3QualificationJournalSummary,
    pub wire_blake3_digest: Digest32,
    pub wire_bytes: u64,
    pub cp02_bytes: u64,
    pub algorithm_version: u32,
    pub proof_version: u32,
    pub shared_layout_version: u16,
    pub parse_and_canonicalization_nanoseconds: u64,
    pub record_and_bank_authentication_nanoseconds: u64,
    pub verification_nanoseconds: u64,
    pub bank_final_stability_scan_nanoseconds: u64,
    pub total_nanoseconds: u64,
    pub whole_process_peak_rss_bytes: u64,
    pub whole_process_peak_rss_scope: String,
    pub verifier_only: bool,
    pub producer_report_checked: bool,
    pub qualification_journal_checked: bool,
}

/// Fail-closed errors from the production qualification orchestrator.
#[derive(Debug, Error)]
pub enum ProductionDoryV3QualificationError {
    #[error("qualification cancellation was requested")]
    Cancelled,
    #[error("invalid qualification configuration: {0}")]
    Configuration(&'static str),
    #[error("failed to resolve qualification path {path}: {source}")]
    ResolvePath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("qualification path already exists: {0}")]
    PathExists(PathBuf),
    #[error("failed to inspect qualification path {path}: {source}")]
    InspectPath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create runner-owned scratch directory {path}: {source}")]
    CreateScratch {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to inspect runner-owned scratch directory {path}: {source}")]
    InspectScratch {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("runner-owned scratch retained {entries} entries and {logical_bytes} logical bytes")]
    RetainedScratch { entries: u64, logical_bytes: u64 },
    #[error("failed to remove empty runner-owned scratch directory {path}: {source}")]
    RemoveScratch {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to query scratch space at {path}: {source}")]
    ScratchSpaceQuery {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("insufficient scratch space: need {required} bytes, have {available} bytes")]
    InsufficientScratch { required: u64, available: u64 },
    #[error("failed to query available system memory: {0}")]
    MemoryQuery(#[source] io::Error),
    #[error("insufficient available memory: need {required} bytes, have {available} bytes")]
    InsufficientMemory { required: u64, available: u64 },
    #[error("production resource projection failed: {0}")]
    ResourceProjection(#[from] BlsDoryBlake3ProductionPreflightError),
    #[error("failed to open input {path}: {source}")]
    OpenInput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read input {path}: {source}")]
    ReadInput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("persisted proof wire exceeds the {max}-byte limit")]
    ProofWireTooLarge { max: usize },
    #[error("qualification request JSON exceeds the {max}-byte limit")]
    QualificationRequestJsonTooLarge { max: usize },
    #[error("qualification producer report JSON exceeds the {max}-byte limit")]
    QualificationReportJsonTooLarge { max: usize },
    #[error("qualification journal exceeds the {max}-byte limit")]
    QualificationJournalTooLarge { max: usize },
    #[error("Record V2 JSON exceeds the {max}-byte limit")]
    RecordV2JsonTooLarge { max: usize },
    #[error("qualification journal is invalid: {0}")]
    InvalidJournal(&'static str),
    #[error("qualification producer report is noncanonical")]
    NonCanonicalProducerReport,
    #[error("qualification evidence does not match: {0}")]
    EvidenceMismatch(&'static str),
    #[error("qualification input is not a regular non-reparse file: {0}")]
    InputNotRegular(PathBuf),
    #[error("qualification input has {links} hard links instead of exactly one: {path}")]
    InputHardLinks { path: PathBuf, links: u64 },
    #[error("qualification input path was replaced while it was being read: {0}")]
    InputReplaced(PathBuf),
    #[error("qualification input bytes changed while they were being read: {0}")]
    InputChanged(PathBuf),
    #[error("qualification JSON encoding or decoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("deterministic n=33 setup failed: {0}")]
    Setup(#[from] BlsDoryPrototypeError),
    #[error("Record V2 validation or bank authentication failed: {0}")]
    Record(#[from] DoryV3ModelCommitmentRecordError),
    #[error("Record V2 production identity validation failed: {0}")]
    ModelIdentity(#[from] DoryV3ModelIdentityError),
    #[error("the bank-authenticated Record V2 does not equal the supplied audit record")]
    RecordReproductionMismatch,
    #[error("qualification pipeline stage {stage} failed: {message}")]
    Pipeline {
        stage: &'static str,
        message: String,
    },
    #[error("candidate validation failed: {0}")]
    Candidate(#[from] BlsDoryV3CandidateError),
    #[error("canonical wire processing failed: {0}")]
    Wire(#[from] WireError),
    #[error("the sealed candidate is not a canonical CP02 envelope")]
    NonCanonicalCp02,
    #[error("the canonical proof wire did not round-trip byte-identically")]
    NonCanonicalWire,
    #[error("the persisted proof wire does not contain a V3 candidate")]
    ExpectedV3Candidate,
    #[error("the persisted candidate is not a Layout V5 proof")]
    ExpectedLayoutV5,
    #[error("the persisted candidate does not match the qualification request: {0}")]
    ProofRequestMismatch(&'static str),
    #[error("qualification duration overflowed its u64 nanosecond field")]
    DurationOverflow,
    #[error("qualification size overflowed its u64 byte field")]
    SizeOverflow,
    #[error("scratch high-water observer thread panicked")]
    ScratchObserverPanicked,
    #[error("exact scratch logical-length instrumentation failed: {0}")]
    ScratchInstrumentation(#[source] io::Error),
    #[error("failed to create new output {path}: {source}")]
    CreateOutput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write output {path}: {source}")]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to sync output {path}: {source}")]
    SyncOutput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to sync output parent directory {path}: {source}")]
    SyncOutputParent {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to reopen output {path}: {source}")]
    ReopenOutput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("reopened output differs from the bytes written: {0}")]
    OutputMismatch(PathBuf),
    #[error("failed to establish output identity for {path}: {source}")]
    OutputIdentity {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("output path was replaced while qualification was publishing it: {0}")]
    OutputReplaced(PathBuf),
}

/// Derive one qualification request by executing the exact authenticated
/// production model for the caller-selected nonce.
///
/// This is deliberately a one-nonce evaluator, not a CPU miner. A useful
/// qualification seed uses the maximum target. The independent qualification
/// runner still reauthenticates the bank and replays the emitted claim before
/// constructing any proof.
#[allow(clippy::too_many_arguments)]
pub fn generate_production_dory_v3_qualification_request(
    bank_path: &Path,
    record_path: &Path,
    seed: &ProductionDoryV3QualificationSeed,
    scratch_path: &Path,
    request_output: &Path,
    cancel: &AtomicBool,
) -> Result<ProductionDoryV3QualificationRequestGenerationReport, ProductionDoryV3QualificationError>
{
    let generation_started = Instant::now();
    check_cancel(cancel)?;
    ensure_absolute_paths(
        &[bank_path, record_path],
        "qualification request bank and Record V2 paths must be absolute",
    )?;
    let paths = QualificationRequestPaths::preflight(scratch_path, request_output)?;
    let mut scratch = OwnedScratchDirectory::create(paths.scratch.clone())?;

    let setup_started = Instant::now();
    let setup = deterministic_bls_dory_setup(DORY_V3_PADDED_VARIABLES as usize)?;
    setup.validate()?;
    let setup_nanoseconds = elapsed_nanoseconds(setup_started)?;
    check_cancel(cancel)?;

    let record_started = Instant::now();
    let record_reader = open_input(record_path)?;
    let audit_record: DoryV3ModelCommitmentRecordV2 = serde_json::from_reader(record_reader)?;
    audit_record.validate_production(&setup)?;
    let structural = audit_record
        .model_identity()
        .validate_production_structure(audit_record.manifest(), &setup)?;
    let record_load_and_validation_nanoseconds = elapsed_nanoseconds(record_started)?;
    check_cancel(cancel)?;

    let bank_reauthentication_started = Instant::now();
    let authenticated = derive_bank_authenticated_dory_v3_model_commitment_record_v2(
        open_input(bank_path)?,
        &structural,
        &setup,
    )?;
    if authenticated.record() != &audit_record {
        return Err(ProductionDoryV3QualificationError::RecordReproductionMismatch);
    }
    let bank_reauthentication_nanoseconds = elapsed_nanoseconds(bank_reauthentication_started)?;
    check_cancel(cancel)?;

    let evaluation_started = Instant::now();
    let transcript = DoryV3TranscriptContext::from_bank_authenticated_record(
        seed.block.network_id,
        &authenticated,
    )
    .map_err(|error| pipeline_error("transcript construction", error))?;
    let claim = derive_dory_v3_winning_nonce_claim_from_bank_authenticated_record(
        &authenticated,
        transcript,
        &seed.block,
        seed.nonce,
        &setup,
        open_input(bank_path)?,
        scratch.path(),
        cancel,
    )
    .map_err(|error| match error {
        BlsDoryV3WinningNonceReplayError::Cancelled => {
            ProductionDoryV3QualificationError::Cancelled
        }
        error => pipeline_error("winning-claim CPU evaluation", error),
    })?;
    let nonce_evaluation_nanoseconds = elapsed_nanoseconds(evaluation_started)?;
    check_cancel(cancel)?;

    let scratch_cleanup_started = Instant::now();
    let (retained_scratch_entries, retained_scratch_logical_bytes) = scratch.measure_retained()?;
    if retained_scratch_entries != 0 || retained_scratch_logical_bytes != 0 {
        return Err(ProductionDoryV3QualificationError::RetainedScratch {
            entries: retained_scratch_entries,
            logical_bytes: retained_scratch_logical_bytes,
        });
    }
    scratch.remove_empty()?;
    let scratch_cleanup_nanoseconds = elapsed_nanoseconds(scratch_cleanup_started)?;
    check_cancel(cancel)?;

    let request = ProductionDoryV3QualificationRequest {
        block: seed.block,
        nonce: claim.nonce,
        final_activation_digest: Digest32::new(claim.final_activation_digest),
        work_digest: Digest32::new(claim.work_digest),
    };
    let mut request_bytes = serde_json::to_vec_pretty(&request)?;
    request_bytes.push(b'\n');
    if serde_json::from_slice::<ProductionDoryV3QualificationRequest>(&request_bytes)? != request {
        return Err(ProductionDoryV3QualificationError::Configuration(
            "qualification request did not round-trip canonically",
        ));
    }

    let publication_started = Instant::now();
    write_verified_output(&paths.request_output, &request_bytes)?;
    let request_publication_nanoseconds = elapsed_nanoseconds(publication_started)?;

    Ok(ProductionDoryV3QualificationRequestGenerationReport {
        report_version: QUALIFICATION_REQUEST_GENERATION_REPORT_VERSION,
        network_id: Digest32::new(request.block.network_id),
        block_height: request.block.height,
        nonce: request.nonce,
        request_digest: qualification_request_digest(&request),
        record_digest: audit_record.record_digest(),
        model_identity_digest: audit_record.model_identity_digest(),
        setup_identity: audit_record.setup_identity(),
        final_activation_digest: request.final_activation_digest,
        work_digest: request.work_digest,
        request_bytes: byte_len(&request_bytes)?,
        setup_nanoseconds,
        record_load_and_validation_nanoseconds,
        bank_reauthentication_nanoseconds,
        nonce_evaluation_nanoseconds,
        scratch_cleanup_nanoseconds,
        request_publication_nanoseconds,
        total_nanoseconds: elapsed_nanoseconds(generation_started)?,
        request_output_is_completion_marker: true,
        publication_crash_atomic: false,
        parent_directory_sync_performed: cfg!(unix),
    })
}

/// Run one exact n=33, 134-claim qualification and publish only fully checked outputs.
#[allow(clippy::too_many_arguments)]
pub fn run_production_dory_v3_qualification(
    bank_path: &Path,
    record_path: &Path,
    request: &ProductionDoryV3QualificationRequest,
    scratch_path: &Path,
    proof_output: &Path,
    report_output: &Path,
    journal_output: &Path,
    maximum_native_block_rows: usize,
    cancel: &AtomicBool,
) -> Result<ProductionDoryV3QualificationReport, ProductionDoryV3QualificationError> {
    let qualification_started = Instant::now();
    if cancel.load(Ordering::Relaxed) {
        return Err(ProductionDoryV3QualificationError::Cancelled);
    }
    ensure_absolute_paths(
        &[bank_path, record_path],
        "qualification bank and Record V2 paths must be absolute",
    )?;
    if maximum_native_block_rows == 0 {
        return Err(ProductionDoryV3QualificationError::Configuration(
            "maximum_native_block_rows must be nonzero",
        ));
    }
    let effective_configuration = qualification_effective_configuration(maximum_native_block_rows)?;
    let request_digest = qualification_request_digest(request);
    let paths =
        QualificationPaths::preflight(scratch_path, proof_output, report_output, journal_output)?;
    let mut journal = QualificationJournal::create(
        paths.journal_output.clone(),
        request_digest,
        effective_configuration,
    )?;

    let native_projection = projected_bls_dory_blake3_production_resources()?;
    let scratch_parent =
        paths
            .scratch
            .parent()
            .ok_or(ProductionDoryV3QualificationError::Configuration(
                "scratch directory must have an existing parent",
            ))?;
    let initial_available_scratch_bytes =
        fs2::available_space(scratch_parent).map_err(|source| {
            ProductionDoryV3QualificationError::ScratchSpaceQuery {
                path: scratch_parent.to_path_buf(),
                source,
            }
        })?;
    ensure_scratch_floor(
        native_projection.provisional_scratch_gate_bytes,
        initial_available_scratch_bytes,
    )?;
    let observed_available_memory_before_bytes =
        available_memory_bytes().map_err(ProductionDoryV3QualificationError::MemoryQuery)?;
    ensure_memory_floor(
        native_projection.provisional_available_memory_gate_bytes,
        observed_available_memory_before_bytes,
    )?;
    journal.append_stage("resource_preflight_completed", None)?;

    let mut scratch = OwnedScratchDirectory::create(paths.scratch.clone())?;
    let mut exact_scratch = ExactScratchReservationSession::start(scratch.path())
        .map_err(ProductionDoryV3QualificationError::ScratchInstrumentation)?;
    let mut scratch_observer = ScratchHighWaterObserver::start(scratch.path().to_path_buf());

    let setup_started = Instant::now();
    let setup = deterministic_bls_dory_setup(DORY_V3_PADDED_VARIABLES as usize)?;
    setup.validate()?;
    let setup_nanoseconds = elapsed_nanoseconds(setup_started)?;
    journal.append_stage("setup_validation_completed", None)?;
    check_cancel(cancel)?;

    let record_started = Instant::now();
    let record_reader = open_input(record_path)?;
    let audit_record: DoryV3ModelCommitmentRecordV2 = serde_json::from_reader(record_reader)?;
    audit_record.validate_production(&setup)?;
    let structural = audit_record
        .model_identity()
        .validate_production_structure(audit_record.manifest(), &setup)?;
    let record_load_and_validation_nanoseconds = elapsed_nanoseconds(record_started)?;
    journal.append_stage("record_validation_completed", None)?;
    check_cancel(cancel)?;

    let bank_reauthentication_started = Instant::now();
    let authenticated = derive_bank_authenticated_dory_v3_model_commitment_record_v2(
        open_input(bank_path)?,
        &structural,
        &setup,
    )?;
    if authenticated.record() != &audit_record {
        return Err(ProductionDoryV3QualificationError::RecordReproductionMismatch);
    }
    let bank_reauthentication_nanoseconds = elapsed_nanoseconds(bank_reauthentication_started)?;
    let authenticated_identities = QualificationAuthenticatedIdentities {
        record_digest: audit_record.record_digest(),
        model_identity_digest: audit_record.model_identity_digest(),
        setup_identity: audit_record.setup_identity(),
    };
    journal.append_stage(
        "bank_authentication_completed",
        Some(authenticated_identities),
    )?;
    check_cancel(cancel)?;

    let fixed_model_started = Instant::now();
    let prepared_model =
        prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_with_scratch(
            open_input(bank_path)?,
            &authenticated,
            &setup,
            scratch.path(),
        )
        .map_err(|error| pipeline_error("fixed-model preparation", error))?;
    let fixed_model_preparation_nanoseconds = elapsed_nanoseconds(fixed_model_started)?;
    journal.append_stage("fixed_model_preparation_completed", None)?;
    check_cancel(cancel)?;

    let replay_started = Instant::now();
    let transcript = DoryV3TranscriptContext::from_bank_authenticated_record(
        request.block.network_id,
        &authenticated,
    )
    .map_err(|error| pipeline_error("transcript construction", error))?;
    let claim = BlsDoryV3WinningNonceClaim {
        nonce: request.nonce,
        final_activation_digest: request.final_activation_digest.into_bytes(),
        work_digest: request.work_digest.into_bytes(),
    };
    let execution = replay_dory_v3_winning_nonce_from_bank_authenticated_record(
        &authenticated,
        transcript,
        &request.block,
        claim,
        &setup,
        open_input(bank_path)?,
        scratch.path(),
        cancel,
    )
    .map_err(|error| match error {
        BlsDoryV3WinningNonceReplayError::Cancelled => {
            ProductionDoryV3QualificationError::Cancelled
        }
        error => pipeline_error("winning-claim CPU replay", error),
    })?;
    let winning_claim_replay_nanoseconds = elapsed_nanoseconds(replay_started)?;
    journal.append_stage("winning_claim_replay_completed", None)?;
    check_cancel(cancel)?;

    let candidate_resource_started = Instant::now();
    let (candidate_required_free_scratch_bytes, candidate_available_free_scratch_bytes) =
        preflight_candidate_scratch(scratch.path())?;
    let candidate_resource_preflight_nanoseconds = elapsed_nanoseconds(candidate_resource_started)?;
    journal.append_stage("candidate_resource_preflight_completed", None)?;
    check_cancel(cancel)?;

    let layout_started = Instant::now();
    let prepared = prepare_bls_dory_shared_layout_v5_from_verified_dory_v3_execution_with_scratch(
        execution,
        &authenticated,
        &prepared_model,
        &request.block,
        &setup,
        scratch.path(),
    )
    .map_err(|error| pipeline_error("Layout V5 preparation", error))?;
    let layout_v5_preparation_nanoseconds = elapsed_nanoseconds(layout_started)?;
    journal.append_stage("layout_v5_preparation_completed", None)?;
    check_cancel(cancel)?;

    let composition_started = Instant::now();
    let composed = finish_prepared_bls_dory_v3_layout_v5_execution_with_composition(
        prepared,
        &setup,
        scratch.path(),
        maximum_native_block_rows,
    )
    .map_err(|error| pipeline_error("native and 134-claim composition", error))?;
    let native_and_aggregate_composition_nanoseconds = elapsed_nanoseconds(composition_started)?;
    journal.append_stage("native_and_aggregate_composition_completed", None)?;
    check_cancel(cancel)?;

    let seal_started = Instant::now();
    let candidate = seal_composed_bls_dory_v3_layout_v5_candidate(
        composed,
        &authenticated,
        &request.block,
        &setup,
    )?;
    let payload = validate_cp02(&candidate)?;
    let cp02_seal_nanoseconds = elapsed_nanoseconds(seal_started)?;
    journal.append_stage("cp02_seal_completed", None)?;
    check_cancel(cancel)?;

    let scratch_cleanup_started = Instant::now();
    drop(prepared_model);
    let scratch_high_water = scratch_observer.stop()?;
    let exact_scratch_snapshot = exact_scratch
        .finish_and_remove_root()
        .map_err(ProductionDoryV3QualificationError::ScratchInstrumentation)?;
    scratch.mark_removed();
    if exact_scratch_snapshot.file_creation_events == 0
        || exact_scratch_snapshot.size_mutation_events == 0
    {
        return Err(ProductionDoryV3QualificationError::ScratchInstrumentation(
            io::Error::other(
                "scratch logical-length instrumentation recorded no file or size-changing operations",
            ),
        ));
    }
    let (retained_scratch_entries, retained_scratch_logical_bytes) = (0, 0);
    let scratch_cleanup_nanoseconds = elapsed_nanoseconds(scratch_cleanup_started)?;
    journal.append_stage("scratch_cleanup_completed", None)?;
    check_cancel(cancel)?;

    let first_verification_started = Instant::now();
    let _first = verify_bls_dory_v3_layout_v5_candidate(
        request.block.network_id,
        &authenticated,
        &request.block,
        &candidate,
        &setup,
    )?;
    let first_verification_nanoseconds = elapsed_nanoseconds(first_verification_started)?;
    journal.append_stage("first_verification_completed", None)?;
    check_cancel(cancel)?;

    let wire_started = Instant::now();
    let block_proof = BlockProof::V3Candidate(Box::new(candidate.clone()));
    let wire = encode_forgematrix_proof(&block_proof, request.block.network_id)?;
    let decoded = decode_forgematrix_proof(&wire, request.block.network_id)?;
    let BlockProof::V3Candidate(decoded_candidate) = decoded else {
        return Err(ProductionDoryV3QualificationError::NonCanonicalWire);
    };
    if *decoded_candidate != candidate {
        return Err(ProductionDoryV3QualificationError::NonCanonicalWire);
    }
    let reencoded = encode_forgematrix_proof(
        &BlockProof::V3Candidate(decoded_candidate.clone()),
        request.block.network_id,
    )?;
    if reencoded != wire {
        return Err(ProductionDoryV3QualificationError::NonCanonicalWire);
    }
    let wire_round_trip_nanoseconds = elapsed_nanoseconds(wire_started)?;
    journal.append_stage("wire_round_trip_completed", None)?;
    check_cancel(cancel)?;

    let second_verification_started = Instant::now();
    let _second = verify_bls_dory_v3_layout_v5_candidate(
        request.block.network_id,
        &authenticated,
        &request.block,
        &decoded_candidate,
        &setup,
    )?;
    let second_verification_nanoseconds = elapsed_nanoseconds(second_verification_started)?;
    journal.append_stage("second_verification_completed", None)?;
    check_cancel(cancel)?;
    let whole_process_peak_rss_bytes =
        peak_whole_process_rss_bytes().map_err(ProductionDoryV3QualificationError::MemoryQuery)?;
    let qualification_journal = journal.finish("prepublication_verification_recorded")?;

    let report = ProductionDoryV3QualificationReport {
        report_version: QUALIFICATION_REPORT_VERSION,
        padded_variables: effective_configuration.padded_variables,
        composed_claims: effective_configuration.composed_claims,
        verifier_passes: effective_configuration.verifier_passes,
        maximum_native_block_rows: effective_configuration.maximum_native_block_rows,
        network_id: Digest32::new(request.block.network_id),
        block_height: request.block.height,
        nonce: request.nonce,
        request_digest,
        record_digest: authenticated_identities.record_digest,
        model_identity_digest: authenticated_identities.model_identity_digest,
        setup_identity: authenticated_identities.setup_identity,
        challenge_digest: Digest32::new(candidate.challenge_digest),
        final_activation_digest: Digest32::new(candidate.final_activation_digest),
        work_digest: Digest32::new(candidate.work_digest),
        cp02_blake3_digest: blake3_digest(&candidate.structured_proof),
        dory_proof_blake3_digest: blake3_digest(&payload.dory_proof),
        native_proof_blake3_digest: blake3_digest(&payload.native_blake3_proof),
        wire_blake3_digest: blake3_digest(&wire),
        record_canonical_bytes: u64::try_from(audit_record.canonical_bytes().len())
            .map_err(|_| ProductionDoryV3QualificationError::SizeOverflow)?,
        cp02_bytes: byte_len(&candidate.structured_proof)?,
        cp02_header_bytes: u64::try_from(CANDIDATE_PAYLOAD_HEADER_BYTES)
            .map_err(|_| ProductionDoryV3QualificationError::SizeOverflow)?,
        dory_proof_bytes: byte_len(&payload.dory_proof)?,
        native_proof_bytes: byte_len(&payload.native_blake3_proof)?,
        wire_bytes: byte_len(&wire)?,
        provisional_scratch_floor_bytes: native_projection.provisional_scratch_gate_bytes,
        initial_available_scratch_bytes,
        candidate_required_free_scratch_bytes,
        candidate_available_free_scratch_bytes,
        provisional_available_memory_floor_bytes: native_projection
            .provisional_available_memory_gate_bytes,
        observed_available_memory_before_bytes,
        native_resource_projection_complete: native_projection.is_complete(),
        sampled_peak_scratch_entries_observation: scratch_high_water.entries,
        sampled_peak_scratch_logical_bytes_observation: scratch_high_water.logical_bytes,
        scratch_sample_interval_milliseconds: u64::try_from(SCRATCH_SAMPLE_INTERVAL.as_millis())
            .map_err(|_| ProductionDoryV3QualificationError::DurationOverflow)?,
        sampled_peak_scratch_observation_scope: SAMPLED_SCRATCH_OBSERVATION_SCOPE.into(),
        exact_peak_instrumented_scratch_logical_bytes: exact_scratch_snapshot.peak_logical_bytes,
        exact_peak_instrumented_scratch_live_entries: exact_scratch_snapshot.peak_live_entries,
        instrumented_scratch_file_creation_events: exact_scratch_snapshot.file_creation_events,
        instrumented_scratch_size_mutation_events: exact_scratch_snapshot.size_mutation_events,
        exact_peak_scratch_instrumented: true,
        exact_peak_scratch_scope: EXACT_SCRATCH_PEAK_SCOPE.into(),
        retained_scratch_entries,
        retained_scratch_logical_bytes,
        whole_process_peak_rss_bytes,
        whole_process_peak_rss_scope: WHOLE_PROCESS_PEAK_RSS_SCOPE.into(),
        cooperative_cancellation_scope: COOPERATIVE_CANCELLATION_SCOPE.into(),
        qualification_journal,
        report_output_is_completion_marker: true,
        publication_crash_atomic: false,
        parent_directory_sync_performed: cfg!(unix),
        setup_nanoseconds,
        record_load_and_validation_nanoseconds,
        bank_reauthentication_nanoseconds,
        fixed_model_preparation_nanoseconds,
        winning_claim_replay_nanoseconds,
        candidate_resource_preflight_nanoseconds,
        layout_v5_preparation_nanoseconds,
        native_and_aggregate_composition_nanoseconds,
        cp02_seal_nanoseconds,
        scratch_cleanup_nanoseconds,
        first_verification_nanoseconds,
        wire_round_trip_nanoseconds,
        second_verification_nanoseconds,
        prepublication_qualification_nanoseconds: elapsed_nanoseconds(qualification_started)?,
    };
    validate_producer_report_invariants(&report, effective_configuration)?;

    let mut report_bytes = serde_json::to_vec_pretty(&report)?;
    report_bytes.push(b'\n');
    write_verified_outputs(
        &paths.proof_output,
        &wire,
        &paths.report_output,
        &report_bytes,
    )?;
    Ok(report)
}

/// Independently load and verify one persisted production Dory V3 Layout V5 proof.
///
/// The proof wire and its nested CP02 envelope are decoded and canonically
/// re-encoded before the production Record V2 and bank are authenticated. The
/// existing Layout V5 verifier then performs the context-bound inner decode,
/// canonical re-encoding, and cryptographic verification. This function has no
/// proving, publication, or consensus-activation side effects.
pub fn run_production_dory_v3_verifier(
    bank_path: &Path,
    record_path: &Path,
    request_path: &Path,
    proof_path: &Path,
    producer_report_path: &Path,
    journal_path: &Path,
    report_output: &Path,
) -> Result<ProductionDoryV3VerifierReport, ProductionDoryV3QualificationError> {
    ensure_absolute_paths(
        &[
            bank_path,
            record_path,
            request_path,
            proof_path,
            producer_report_path,
            journal_path,
        ],
        "verifier bank, Record V2, request, proof, producer report, and journal paths must be absolute",
    )?;
    let verifier_inputs = [
        bank_path,
        record_path,
        request_path,
        proof_path,
        producer_report_path,
        journal_path,
    ];
    for (index, left) in verifier_inputs.iter().enumerate() {
        for right in &verifier_inputs[index + 1..] {
            if paths_equal_for_platform(left, right) {
                return Err(ProductionDoryV3QualificationError::Configuration(
                    "verifier input paths must be pairwise distinct",
                ));
            }
        }
    }
    let report_output = preflight_verifier_report_output(report_output)?;
    for input in verifier_inputs {
        if paths_equal_for_platform(input, &report_output) {
            return Err(ProductionDoryV3QualificationError::Configuration(
                "verifier report output must be distinct from every verifier input",
            ));
        }
    }
    let verifier_started = Instant::now();

    // Retain every parsed input handle until the verifier report is published.
    // Windows denies write/delete sharing; Unix uses no-follow opens, retained
    // identity, exact byte rereads for bounded inputs, and change-time checks.
    let mut request_input = RetainedStrictInput::open(request_path)?;
    let mut proof_input = RetainedStrictInput::open(proof_path)?;

    let parse_started = Instant::now();
    let request_bytes = request_input.read_bounded(
        MAX_QUALIFICATION_REQUEST_JSON_BYTES,
        ProductionDoryV3QualificationError::QualificationRequestJsonTooLarge {
            max: MAX_QUALIFICATION_REQUEST_JSON_BYTES,
        },
    )?;
    let request: ProductionDoryV3QualificationRequest = serde_json::from_slice(&request_bytes)?;
    let wire = proof_input.read_bounded(
        MAX_PROOF_BYTES,
        ProductionDoryV3QualificationError::ProofWireTooLarge {
            max: MAX_PROOF_BYTES,
        },
    )?;
    let (candidate, payload) = decode_canonical_v3_layout_v5_wire(&wire, &request)?;
    let mut producer_report_input = RetainedStrictInput::open(producer_report_path)?;
    let mut journal_input = RetainedStrictInput::open(journal_path)?;
    let producer_report_bytes = producer_report_input.read_bounded(
        MAX_QUALIFICATION_REPORT_JSON_BYTES,
        ProductionDoryV3QualificationError::QualificationReportJsonTooLarge {
            max: MAX_QUALIFICATION_REPORT_JSON_BYTES,
        },
    )?;
    let producer_report = parse_canonical_qualification_report(&producer_report_bytes)?;
    let expected_configuration = validate_producer_report_request_and_proof(
        &producer_report,
        &request,
        &wire,
        &candidate,
        &payload,
    )?;
    let journal_bytes = journal_input.read_bounded(
        MAX_QUALIFICATION_JOURNAL_BYTES,
        ProductionDoryV3QualificationError::QualificationJournalTooLarge {
            max: MAX_QUALIFICATION_JOURNAL_BYTES,
        },
    )?;
    let audited_journal = audit_qualification_journal(
        &journal_bytes,
        qualification_request_digest(&request),
        expected_configuration,
        QualificationAuthenticatedIdentities {
            record_digest: producer_report.record_digest,
            model_identity_digest: producer_report.model_identity_digest,
            setup_identity: producer_report.setup_identity,
        },
    )?;
    require_matching_journal_summary(&audited_journal, &producer_report.qualification_journal)?;
    let parse_and_canonicalization_nanoseconds = elapsed_nanoseconds(parse_started)?;

    let authentication_started = Instant::now();
    let mut record_input = RetainedStrictInput::open(record_path)?;
    let mut bank_input = RetainedStrictInput::open(bank_path)?;
    let record_bytes = record_input.read_bounded(
        MAX_RECORD_V2_JSON_BYTES,
        ProductionDoryV3QualificationError::RecordV2JsonTooLarge {
            max: MAX_RECORD_V2_JSON_BYTES,
        },
    )?;
    let audit_record: DoryV3ModelCommitmentRecordV2 = serde_json::from_slice(&record_bytes)?;
    validate_verifier_record_static_identity(&audit_record)?;
    let setup = deterministic_bls_dory_setup(DORY_V3_PADDED_VARIABLES as usize)?;
    setup.validate()?;
    audit_record.validate_production(&setup)?;
    let structural = audit_record
        .model_identity()
        .validate_production_structure(audit_record.manifest(), &setup)?;
    let expected_bank_bytes = audit_record
        .manifest()
        .payload_bytes
        .checked_add(MODEL_BANK_HEADER_BYTES as u64)
        .ok_or(ProductionDoryV3QualificationError::SizeOverflow)?;
    if bank_input.bytes() != expected_bank_bytes {
        return Err(ProductionDoryV3QualificationError::EvidenceMismatch(
            "bank length and Record V2 manifest",
        ));
    }
    bank_input.recheck()?;
    bank_input.seek_start()?;
    let mut bank_reader = Blake3CountingReader::new(&mut bank_input.file);
    let authenticated = derive_bank_authenticated_dory_v3_model_commitment_record_v2(
        &mut bank_reader,
        &structural,
        &setup,
    )?;
    io::copy(&mut bank_reader, &mut io::sink()).map_err(|source| {
        ProductionDoryV3QualificationError::ReadInput {
            path: bank_path.to_path_buf(),
            source,
        }
    })?;
    let authenticated_bank_content = bank_reader.finish();
    if authenticated_bank_content.bytes != expected_bank_bytes {
        return Err(ProductionDoryV3QualificationError::EvidenceMismatch(
            "authenticated bank byte length",
        ));
    }
    bank_input.recheck()?;
    if authenticated.record() != &audit_record {
        return Err(ProductionDoryV3QualificationError::RecordReproductionMismatch);
    }
    if audit_record.record_digest() != producer_report.record_digest
        || audit_record.model_identity_digest() != producer_report.model_identity_digest
        || audit_record.setup_identity() != producer_report.setup_identity
        || byte_len(&audit_record.canonical_bytes())? != producer_report.record_canonical_bytes
    {
        return Err(ProductionDoryV3QualificationError::EvidenceMismatch(
            "producer report authenticated identities",
        ));
    }
    validate_verifier_candidate_binding(&candidate, &request, audit_record.manifest_digest())?;
    let record_and_bank_authentication_nanoseconds = elapsed_nanoseconds(authentication_started)?;

    let verification_started = Instant::now();
    let _verified = verify_bls_dory_v3_layout_v5_candidate(
        request.block.network_id,
        &authenticated,
        &request.block,
        &candidate,
        &setup,
    )?;
    let verification_nanoseconds = elapsed_nanoseconds(verification_started)?;
    let whole_process_peak_rss_bytes =
        peak_whole_process_rss_bytes().map_err(ProductionDoryV3QualificationError::MemoryQuery)?;

    // A second complete sequential read is the bounded-memory content-stability
    // check. It detects in-place mutation after authentication; the retained
    // no-follow handle and final named-path recheck detect replacement.
    let bank_final_stability_scan_started = Instant::now();
    bank_input.confirm_content_identity(authenticated_bank_content)?;
    let bank_final_stability_scan_nanoseconds =
        elapsed_nanoseconds(bank_final_stability_scan_started)?;
    request_input.confirm_exact_bytes(&request_bytes)?;
    proof_input.confirm_exact_bytes(&wire)?;
    record_input.confirm_exact_bytes(&record_bytes)?;
    producer_report_input.confirm_exact_bytes(&producer_report_bytes)?;
    journal_input.confirm_exact_bytes(&journal_bytes)?;
    // Bank last: a same-inode write after the final scan changes its retained
    // state, while replacement changes the named-path identity.
    bank_input.recheck()?;

    let report = ProductionDoryV3VerifierReport {
        report_version: VERIFIER_REPORT_VERSION,
        network_id: Digest32::new(request.block.network_id),
        block_height: request.block.height,
        nonce: candidate.nonce,
        request_digest: qualification_request_digest(&request),
        record_digest: audit_record.record_digest(),
        model_identity_digest: audit_record.model_identity_digest(),
        setup_identity: audit_record.setup_identity(),
        bank_content_blake3_digest: authenticated_bank_content.blake3,
        bank_content_bytes: authenticated_bank_content.bytes,
        producer_report_blake3_digest: blake3_digest(&producer_report_bytes),
        qualification_journal: audited_journal,
        wire_blake3_digest: blake3_digest(&wire),
        wire_bytes: byte_len(&wire)?,
        cp02_bytes: byte_len(&candidate.structured_proof)?,
        algorithm_version: candidate.algorithm_version,
        proof_version: candidate.proof_version,
        shared_layout_version: DORY_V3_SHARED_LAYOUT_VERSION,
        parse_and_canonicalization_nanoseconds,
        record_and_bank_authentication_nanoseconds,
        verification_nanoseconds,
        bank_final_stability_scan_nanoseconds,
        total_nanoseconds: elapsed_nanoseconds(verifier_started)?,
        whole_process_peak_rss_bytes,
        whole_process_peak_rss_scope: "OS process-lifetime high-water mark; run the verifier CLI in a fresh process for an isolated measurement".into(),
        verifier_only: true,
        producer_report_checked: true,
        qualification_journal_checked: true,
    };
    let mut report_bytes = serde_json::to_vec_pretty(&report)?;
    report_bytes.push(b'\n');
    write_verified_output(&report_output, &report_bytes)?;
    Ok(report)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictBlockChallenge {
    network_id: [u8; 32],
    previous_block: [u8; 32],
    transaction_root: [u8; 32],
    height: u64,
    timestamp: u64,
    target: [u8; 32],
}

fn deserialize_strict_block_challenge<'de, D>(deserializer: D) -> Result<BlockChallenge, D::Error>
where
    D: Deserializer<'de>,
{
    let block = StrictBlockChallenge::deserialize(deserializer)?;
    Ok(BlockChallenge {
        network_id: block.network_id,
        previous_block: block.previous_block,
        transaction_root: block.transaction_root,
        height: block.height,
        timestamp: block.timestamp,
        target: block.target,
    })
}

struct QualificationPaths {
    scratch: PathBuf,
    proof_output: PathBuf,
    report_output: PathBuf,
    journal_output: PathBuf,
}

struct QualificationRequestPaths {
    scratch: PathBuf,
    request_output: PathBuf,
}

impl QualificationRequestPaths {
    fn preflight(
        scratch: &Path,
        request_output: &Path,
    ) -> Result<Self, ProductionDoryV3QualificationError> {
        if !scratch.is_absolute() || !request_output.is_absolute() {
            return Err(ProductionDoryV3QualificationError::Configuration(
                "request scratch and output paths must be absolute",
            ));
        }
        if path_starts_with_for_platform(request_output, scratch) {
            return Err(ProductionDoryV3QualificationError::Configuration(
                "request output must not be inside runner-owned scratch",
            ));
        }
        let scratch = resolve_new_path(scratch)?;
        let request_output = resolve_new_path(request_output)?;
        if path_starts_with_for_platform(&request_output, &scratch) {
            return Err(ProductionDoryV3QualificationError::Configuration(
                "request output must not be inside runner-owned scratch",
            ));
        }
        ensure_path_absent(&scratch)?;
        ensure_path_absent(&request_output)?;
        Ok(Self {
            scratch,
            request_output,
        })
    }
}

impl QualificationPaths {
    fn preflight(
        scratch: &Path,
        proof_output: &Path,
        report_output: &Path,
        journal_output: &Path,
    ) -> Result<Self, ProductionDoryV3QualificationError> {
        if !scratch.is_absolute()
            || !proof_output.is_absolute()
            || !report_output.is_absolute()
            || !journal_output.is_absolute()
        {
            return Err(ProductionDoryV3QualificationError::Configuration(
                "qualification scratch, proof, report, and journal paths must be absolute",
            ));
        }
        if paths_equal_for_platform(proof_output, report_output)
            || paths_equal_for_platform(journal_output, proof_output)
            || paths_equal_for_platform(journal_output, report_output)
        {
            return Err(ProductionDoryV3QualificationError::Configuration(
                "proof, report, and journal outputs must be distinct",
            ));
        }
        if path_starts_with_for_platform(proof_output, scratch)
            || path_starts_with_for_platform(report_output, scratch)
            || path_starts_with_for_platform(journal_output, scratch)
            || path_starts_with_for_platform(scratch, journal_output)
        {
            return Err(ProductionDoryV3QualificationError::Configuration(
                "proof, report, and journal outputs must not overlap runner-owned scratch",
            ));
        }
        let scratch = resolve_new_path(scratch)?;
        let proof_output = resolve_new_path(proof_output)?;
        let report_output = resolve_new_path(report_output)?;
        let journal_output = resolve_new_path(journal_output)?;
        if paths_equal_for_platform(&proof_output, &report_output)
            || paths_equal_for_platform(&journal_output, &proof_output)
            || paths_equal_for_platform(&journal_output, &report_output)
        {
            return Err(ProductionDoryV3QualificationError::Configuration(
                "proof, report, and journal outputs must be distinct",
            ));
        }
        if path_starts_with_for_platform(&proof_output, &scratch)
            || path_starts_with_for_platform(&report_output, &scratch)
            || path_starts_with_for_platform(&journal_output, &scratch)
            || path_starts_with_for_platform(&scratch, &journal_output)
        {
            return Err(ProductionDoryV3QualificationError::Configuration(
                "proof, report, and journal outputs must not overlap runner-owned scratch",
            ));
        }
        ensure_path_absent(&scratch)?;
        ensure_path_absent(&proof_output)?;
        ensure_path_absent(&report_output)?;
        ensure_path_absent(&journal_output)?;
        Ok(Self {
            scratch,
            proof_output,
            report_output,
            journal_output,
        })
    }
}

fn qualification_effective_configuration(
    maximum_native_block_rows: usize,
) -> Result<QualificationEffectiveConfiguration, ProductionDoryV3QualificationError> {
    Ok(QualificationEffectiveConfiguration {
        qualification_report_version: QUALIFICATION_REPORT_VERSION,
        padded_variables: DORY_V3_PADDED_VARIABLES,
        composed_claims: u16::try_from(BLS_DORY_COMPOSED_AGGREGATE_CLAIMS)
            .map_err(|_| ProductionDoryV3QualificationError::SizeOverflow)?,
        verifier_passes: 2,
        maximum_native_block_rows: u64::try_from(maximum_native_block_rows)
            .map_err(|_| ProductionDoryV3QualificationError::SizeOverflow)?,
        algorithm_version: DORY_V3_ALGORITHM_VERSION,
        proof_version: DORY_V3_PROOF_VERSION,
        shared_layout_version: DORY_V3_SHARED_LAYOUT_VERSION,
        scratch_sample_interval_milliseconds: u64::try_from(SCRATCH_SAMPLE_INTERVAL.as_millis())
            .map_err(|_| ProductionDoryV3QualificationError::DurationOverflow)?,
    })
}

fn qualification_run_identity(
    request_digest: Digest32,
    configuration: &QualificationEffectiveConfiguration,
) -> Digest32 {
    let mut hasher = blake3::Hasher::new_derive_key(QUALIFICATION_RUN_IDENTITY_DOMAIN);
    hasher.update(request_digest.as_bytes());
    hasher.update(&configuration.qualification_report_version.to_le_bytes());
    hasher.update(&configuration.padded_variables.to_le_bytes());
    hasher.update(&configuration.composed_claims.to_le_bytes());
    hasher.update(&[configuration.verifier_passes]);
    hasher.update(&configuration.maximum_native_block_rows.to_le_bytes());
    hasher.update(&configuration.algorithm_version.to_le_bytes());
    hasher.update(&configuration.proof_version.to_le_bytes());
    hasher.update(&configuration.shared_layout_version.to_le_bytes());
    hasher.update(
        &configuration
            .scratch_sample_interval_milliseconds
            .to_le_bytes(),
    );
    Digest32::new(*hasher.finalize().as_bytes())
}

fn qualification_journal_record_digest(record_bytes: &[u8]) -> Digest32 {
    let mut hasher = blake3::Hasher::new_derive_key(QUALIFICATION_JOURNAL_RECORD_DIGEST_DOMAIN);
    hasher.update(record_bytes);
    Digest32::new(*hasher.finalize().as_bytes())
}

fn qualification_journal_complete_file_digest(
    journal_bytes: &[u8],
) -> Result<Digest32, ProductionDoryV3QualificationError> {
    let length = u64::try_from(journal_bytes.len())
        .map_err(|_| ProductionDoryV3QualificationError::SizeOverflow)?;
    let mut hasher = blake3::Hasher::new_derive_key(QUALIFICATION_JOURNAL_FILE_DIGEST_DOMAIN);
    hasher.update(&length.to_le_bytes());
    hasher.update(journal_bytes);
    Ok(Digest32::new(*hasher.finalize().as_bytes()))
}

fn audit_qualification_journal(
    journal_bytes: &[u8],
    request_digest: Digest32,
    configuration: QualificationEffectiveConfiguration,
    identities: QualificationAuthenticatedIdentities,
) -> Result<ProductionDoryV3QualificationJournalSummary, ProductionDoryV3QualificationError> {
    if journal_bytes.is_empty() {
        return Err(ProductionDoryV3QualificationError::InvalidJournal(
            "journal is empty",
        ));
    }
    if journal_bytes.last() != Some(&b'\n') {
        return Err(ProductionDoryV3QualificationError::InvalidJournal(
            "journal is missing its final LF",
        ));
    }

    let raw_records = journal_bytes[..journal_bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    if raw_records.len() != QUALIFICATION_JOURNAL_STAGES.len() {
        return Err(ProductionDoryV3QualificationError::InvalidJournal(
            "journal event count or stage sequence length is wrong",
        ));
    }

    let run_identity = qualification_run_identity(request_digest, &configuration);
    let mut previous_record_digest = Digest32::ZERO;
    for (index, (raw_record, expected_stage)) in raw_records
        .iter()
        .zip(QUALIFICATION_JOURNAL_STAGES)
        .enumerate()
    {
        if raw_record.is_empty() {
            return Err(ProductionDoryV3QualificationError::InvalidJournal(
                "journal contains an empty record",
            ));
        }
        let record: StrictQualificationJournalRecord = serde_json::from_slice(raw_record)?;
        if serde_json::to_vec(&record)? != *raw_record {
            return Err(ProductionDoryV3QualificationError::InvalidJournal(
                "journal record is not canonical JSON",
            ));
        }
        let sequence =
            u64::try_from(index).map_err(|_| ProductionDoryV3QualificationError::SizeOverflow)?;
        if record.journal_version != QUALIFICATION_JOURNAL_VERSION
            || record.sequence != sequence
            || record.previous_record_digest != previous_record_digest
            || record.run_identity != run_identity
            || record.request_digest != request_digest
            || record.stage != expected_stage
            || !record.diagnostic_only
            || record.completion_marker
            || record.resumable
        {
            return Err(ProductionDoryV3QualificationError::InvalidJournal(
                "journal record header, chain, identity, stage, or diagnostic flags are wrong",
            ));
        }

        let expected_configuration = (index == 0).then_some(configuration);
        if record.effective_configuration != expected_configuration {
            return Err(ProductionDoryV3QualificationError::InvalidJournal(
                "journal effective configuration is missing, duplicated, or wrong",
            ));
        }
        let expected_identities =
            (expected_stage == "bank_authentication_completed").then_some(identities);
        if record.authenticated_identities != expected_identities {
            return Err(ProductionDoryV3QualificationError::InvalidJournal(
                "journal authenticated identities are missing, duplicated, or wrong",
            ));
        }
        previous_record_digest = qualification_journal_record_digest(raw_record);
    }

    Ok(ProductionDoryV3QualificationJournalSummary {
        journal_version: QUALIFICATION_JOURNAL_VERSION,
        run_identity,
        final_record_digest: previous_record_digest,
        event_count: u64::try_from(raw_records.len())
            .map_err(|_| ProductionDoryV3QualificationError::SizeOverflow)?,
        journal_bytes: byte_len(journal_bytes)?,
        complete_file_digest: qualification_journal_complete_file_digest(journal_bytes)?,
        diagnostic_only: true,
        completion_marker: false,
        resumable: false,
    })
}

fn require_matching_journal_summary(
    audited: &ProductionDoryV3QualificationJournalSummary,
    reported: &ProductionDoryV3QualificationJournalSummary,
) -> Result<(), ProductionDoryV3QualificationError> {
    if audited != reported {
        return Err(ProductionDoryV3QualificationError::EvidenceMismatch(
            "producer report journal summary",
        ));
    }
    Ok(())
}

fn validate_producer_report_invariants(
    report: &ProductionDoryV3QualificationReport,
    configuration: QualificationEffectiveConfiguration,
) -> Result<(), ProductionDoryV3QualificationError> {
    if report.maximum_native_block_rows == 0 {
        return Err(ProductionDoryV3QualificationError::EvidenceMismatch(
            "producer report maximum native block rows",
        ));
    }
    let native_projection = projected_bls_dory_blake3_production_resources()?;
    let candidate_required = projected_candidate_required_free_scratch_bytes()?;
    let expected_events = u64::try_from(QUALIFICATION_JOURNAL_STAGES.len())
        .map_err(|_| ProductionDoryV3QualificationError::SizeOverflow)?;
    let stage_timing_sum = [
        report.setup_nanoseconds,
        report.record_load_and_validation_nanoseconds,
        report.bank_reauthentication_nanoseconds,
        report.fixed_model_preparation_nanoseconds,
        report.winning_claim_replay_nanoseconds,
        report.candidate_resource_preflight_nanoseconds,
        report.layout_v5_preparation_nanoseconds,
        report.native_and_aggregate_composition_nanoseconds,
        report.cp02_seal_nanoseconds,
        report.scratch_cleanup_nanoseconds,
        report.first_verification_nanoseconds,
        report.wire_round_trip_nanoseconds,
        report.second_verification_nanoseconds,
    ]
    .into_iter()
    .try_fold(0_u64, u64::checked_add)
    .ok_or(ProductionDoryV3QualificationError::EvidenceMismatch(
        "producer report stage timing overflow",
    ))?;
    if report.report_version != configuration.qualification_report_version
        || report.padded_variables != configuration.padded_variables
        || report.composed_claims != configuration.composed_claims
        || report.verifier_passes != configuration.verifier_passes
        || report.maximum_native_block_rows != configuration.maximum_native_block_rows
        || report.scratch_sample_interval_milliseconds
            != configuration.scratch_sample_interval_milliseconds
        || report.setup_identity != DORY_V3_SETUP_IDENTITY
        || report.provisional_scratch_floor_bytes
            != native_projection.provisional_scratch_gate_bytes
        || report.initial_available_scratch_bytes < report.provisional_scratch_floor_bytes
        || report.candidate_required_free_scratch_bytes != candidate_required
        || report.candidate_available_free_scratch_bytes
            < report.candidate_required_free_scratch_bytes
        || report.provisional_available_memory_floor_bytes
            != native_projection.provisional_available_memory_gate_bytes
        || report.observed_available_memory_before_bytes
            < report.provisional_available_memory_floor_bytes
        || report.native_resource_projection_complete != native_projection.is_complete()
        || report.sampled_peak_scratch_observation_scope != SAMPLED_SCRATCH_OBSERVATION_SCOPE
        || report.exact_peak_instrumented_scratch_logical_bytes == 0
        || report.exact_peak_instrumented_scratch_live_entries == 0
        || report.instrumented_scratch_file_creation_events == 0
        || report.instrumented_scratch_size_mutation_events == 0
        || report.exact_peak_instrumented_scratch_live_entries
            > report.instrumented_scratch_file_creation_events
        || !report.exact_peak_scratch_instrumented
        || report.exact_peak_scratch_scope != EXACT_SCRATCH_PEAK_SCOPE
        || report.retained_scratch_entries != 0
        || report.retained_scratch_logical_bytes != 0
        || report.whole_process_peak_rss_scope != WHOLE_PROCESS_PEAK_RSS_SCOPE
        || report.cooperative_cancellation_scope != COOPERATIVE_CANCELLATION_SCOPE
        || stage_timing_sum > report.prepublication_qualification_nanoseconds
        || (cfg!(any(target_os = "windows", target_os = "linux"))
            && report.whole_process_peak_rss_bytes == 0)
        || report.qualification_journal.journal_version != QUALIFICATION_JOURNAL_VERSION
        || report.qualification_journal.event_count != expected_events
        || report.qualification_journal.journal_bytes == 0
        || !report.qualification_journal.diagnostic_only
        || report.qualification_journal.completion_marker
        || report.qualification_journal.resumable
        || !report.report_output_is_completion_marker
        || report.publication_crash_atomic
        || report.parent_directory_sync_performed != cfg!(unix)
    {
        return Err(ProductionDoryV3QualificationError::EvidenceMismatch(
            "producer report qualification invariants",
        ));
    }
    Ok(())
}

fn validate_producer_report_request_and_proof(
    report: &ProductionDoryV3QualificationReport,
    request: &ProductionDoryV3QualificationRequest,
    wire: &[u8],
    candidate: &ForgeMatrixV3CandidateProof,
    payload: &BlsDoryV3CandidatePayload,
) -> Result<QualificationEffectiveConfiguration, ProductionDoryV3QualificationError> {
    if report.maximum_native_block_rows == 0 {
        return Err(ProductionDoryV3QualificationError::EvidenceMismatch(
            "producer report maximum native block rows",
        ));
    }
    let maximum_native_block_rows = usize::try_from(report.maximum_native_block_rows)
        .map_err(|_| ProductionDoryV3QualificationError::SizeOverflow)?;
    let configuration = qualification_effective_configuration(maximum_native_block_rows)?;
    validate_producer_report_invariants(report, configuration)?;
    if report.network_id != Digest32::new(request.block.network_id)
        || report.block_height != request.block.height
        || report.nonce != request.nonce
        || report.request_digest != qualification_request_digest(request)
        || report.final_activation_digest != request.final_activation_digest
        || report.work_digest != request.work_digest
    {
        return Err(ProductionDoryV3QualificationError::EvidenceMismatch(
            "producer report qualification request",
        ));
    }
    if report.challenge_digest != Digest32::new(candidate.challenge_digest)
        || report.final_activation_digest != Digest32::new(candidate.final_activation_digest)
        || report.work_digest != Digest32::new(candidate.work_digest)
        || report.cp02_blake3_digest != blake3_digest(&candidate.structured_proof)
        || report.dory_proof_blake3_digest != blake3_digest(&payload.dory_proof)
        || report.native_proof_blake3_digest != blake3_digest(&payload.native_blake3_proof)
        || report.wire_blake3_digest != blake3_digest(wire)
        || report.cp02_bytes != byte_len(&candidate.structured_proof)?
        || report.cp02_header_bytes
            != u64::try_from(CANDIDATE_PAYLOAD_HEADER_BYTES)
                .map_err(|_| ProductionDoryV3QualificationError::SizeOverflow)?
        || report.dory_proof_bytes != byte_len(&payload.dory_proof)?
        || report.native_proof_bytes != byte_len(&payload.native_blake3_proof)?
        || report.wire_bytes != byte_len(wire)?
    {
        return Err(ProductionDoryV3QualificationError::EvidenceMismatch(
            "producer report persisted proof",
        ));
    }
    Ok(configuration)
}

#[cfg(test)]
fn load_canonical_qualification_report(
    path: &Path,
) -> Result<(ProductionDoryV3QualificationReport, Vec<u8>), ProductionDoryV3QualificationError> {
    let bytes = read_bounded_strict_input(
        path,
        MAX_QUALIFICATION_REPORT_JSON_BYTES,
        ProductionDoryV3QualificationError::QualificationReportJsonTooLarge {
            max: MAX_QUALIFICATION_REPORT_JSON_BYTES,
        },
    )?;
    let report = parse_canonical_qualification_report(&bytes)?;
    Ok((report, bytes))
}

fn parse_canonical_qualification_report(
    bytes: &[u8],
) -> Result<ProductionDoryV3QualificationReport, ProductionDoryV3QualificationError> {
    let report: ProductionDoryV3QualificationReport = serde_json::from_slice(bytes)?;
    let mut canonical = serde_json::to_vec_pretty(&report)?;
    canonical.push(b'\n');
    if canonical != *bytes {
        return Err(ProductionDoryV3QualificationError::NonCanonicalProducerReport);
    }
    Ok(report)
}

struct QualificationJournal {
    path: PathBuf,
    parent: PathBuf,
    file: File,
    identity: SameFileHandle,
    expected_bytes: Vec<u8>,
    next_sequence: u64,
    previous_record_digest: Digest32,
    run_identity: Digest32,
    request_digest: Digest32,
}

impl QualificationJournal {
    fn create(
        path: PathBuf,
        request_digest: Digest32,
        configuration: QualificationEffectiveConfiguration,
    ) -> Result<Self, ProductionDoryV3QualificationError> {
        let parent = path
            .parent()
            .ok_or(ProductionDoryV3QualificationError::Configuration(
                "journal output must have a parent directory",
            ))?
            .to_path_buf();
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(&path)
            .map_err(|source| ProductionDoryV3QualificationError::CreateOutput {
                path: path.clone(),
                source,
            })?;
        let identity = file
            .try_clone()
            .and_then(SameFileHandle::from_file)
            .map_err(
                |source| ProductionDoryV3QualificationError::OutputIdentity {
                    path: path.clone(),
                    source,
                },
            )?;
        let run_identity = qualification_run_identity(request_digest, &configuration);
        let mut journal = Self {
            path,
            parent,
            file,
            identity,
            expected_bytes: Vec::new(),
            next_sequence: 0,
            previous_record_digest: Digest32::new([0; 32]),
            run_identity,
            request_digest,
        };
        journal.append("preflight_completed", Some(&configuration), None)?;
        Ok(journal)
    }

    fn append_stage(
        &mut self,
        stage: &'static str,
        authenticated_identities: Option<QualificationAuthenticatedIdentities>,
    ) -> Result<(), ProductionDoryV3QualificationError> {
        self.append(stage, None, authenticated_identities)
    }

    fn finish(
        &mut self,
        final_stage: &'static str,
    ) -> Result<ProductionDoryV3QualificationJournalSummary, ProductionDoryV3QualificationError>
    {
        self.append_stage(final_stage, None)?;
        Ok(ProductionDoryV3QualificationJournalSummary {
            journal_version: QUALIFICATION_JOURNAL_VERSION,
            run_identity: self.run_identity,
            final_record_digest: self.previous_record_digest,
            event_count: self.next_sequence,
            journal_bytes: byte_len(&self.expected_bytes)?,
            complete_file_digest: qualification_journal_complete_file_digest(&self.expected_bytes)?,
            diagnostic_only: true,
            completion_marker: false,
            resumable: false,
        })
    }

    fn append(
        &mut self,
        stage: &'static str,
        effective_configuration: Option<&QualificationEffectiveConfiguration>,
        authenticated_identities: Option<QualificationAuthenticatedIdentities>,
    ) -> Result<(), ProductionDoryV3QualificationError> {
        let record = QualificationJournalRecord {
            journal_version: QUALIFICATION_JOURNAL_VERSION,
            sequence: self.next_sequence,
            previous_record_digest: self.previous_record_digest,
            run_identity: self.run_identity,
            request_digest: self.request_digest,
            stage,
            diagnostic_only: true,
            completion_marker: false,
            resumable: false,
            effective_configuration,
            authenticated_identities,
        };
        let record_bytes = serde_json::to_vec(&record)?;
        let record_digest = qualification_journal_record_digest(&record_bytes);
        let mut framed_record = record_bytes;
        framed_record.push(b'\n');

        self.file.write_all(&framed_record).map_err(|source| {
            ProductionDoryV3QualificationError::WriteOutput {
                path: self.path.clone(),
                source,
            }
        })?;
        self.file
            .flush()
            .map_err(|source| ProductionDoryV3QualificationError::WriteOutput {
                path: self.path.clone(),
                source,
            })?;
        self.file
            .sync_all()
            .map_err(|source| ProductionDoryV3QualificationError::SyncOutput {
                path: self.path.clone(),
                source,
            })?;
        sync_output_parent_directory(&self.parent)?;

        let mut expected = self.expected_bytes.clone();
        expected.extend_from_slice(&framed_record);
        let mut reopened = File::open(&self.path).map_err(|source| {
            ProductionDoryV3QualificationError::ReopenOutput {
                path: self.path.clone(),
                source,
            }
        })?;
        let reopened_identity = reopened
            .try_clone()
            .and_then(SameFileHandle::from_file)
            .map_err(
                |source| ProductionDoryV3QualificationError::OutputIdentity {
                    path: self.path.clone(),
                    source,
                },
            )?;
        if reopened_identity != self.identity {
            return Err(ProductionDoryV3QualificationError::OutputReplaced(
                self.path.clone(),
            ));
        }
        let mut actual = Vec::new();
        reopened.read_to_end(&mut actual).map_err(|source| {
            ProductionDoryV3QualificationError::ReopenOutput {
                path: self.path.clone(),
                source,
            }
        })?;
        if actual != expected {
            return Err(ProductionDoryV3QualificationError::OutputMismatch(
                self.path.clone(),
            ));
        }

        self.expected_bytes = expected;
        self.previous_record_digest = record_digest;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ProductionDoryV3QualificationError::SizeOverflow)?;
        Ok(())
    }
}

fn preflight_verifier_report_output(
    report_output: &Path,
) -> Result<PathBuf, ProductionDoryV3QualificationError> {
    if !report_output.is_absolute() {
        return Err(ProductionDoryV3QualificationError::Configuration(
            "verifier report output path must be absolute",
        ));
    }
    let report_output = resolve_new_path(report_output)?;
    ensure_path_absent(&report_output)?;
    Ok(report_output)
}

fn ensure_absolute_paths(
    paths: &[&Path],
    message: &'static str,
) -> Result<(), ProductionDoryV3QualificationError> {
    if paths.iter().any(|path| !path.is_absolute()) {
        return Err(ProductionDoryV3QualificationError::Configuration(message));
    }
    Ok(())
}

#[cfg(windows)]
fn path_component_eq_for_platform(
    left: &std::path::Component<'_>,
    right: &std::path::Component<'_>,
) -> bool {
    left.as_os_str().to_string_lossy().to_lowercase()
        == right.as_os_str().to_string_lossy().to_lowercase()
}

#[cfg(not(windows))]
fn path_component_eq_for_platform(
    left: &std::path::Component<'_>,
    right: &std::path::Component<'_>,
) -> bool {
    left == right
}

fn paths_equal_for_platform(left: &Path, right: &Path) -> bool {
    let mut left_components = left.components();
    let mut right_components = right.components();
    loop {
        match (left_components.next(), right_components.next()) {
            (Some(left), Some(right)) if path_component_eq_for_platform(&left, &right) => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn path_starts_with_for_platform(path: &Path, base: &Path) -> bool {
    let mut path_components = path.components();
    for base_component in base.components() {
        let Some(path_component) = path_components.next() else {
            return false;
        };
        if !path_component_eq_for_platform(&path_component, &base_component) {
            return false;
        }
    }
    true
}

fn resolve_new_path(path: &Path) -> Result<PathBuf, ProductionDoryV3QualificationError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| ProductionDoryV3QualificationError::ResolvePath {
                path: path.to_path_buf(),
                source,
            })?
            .join(path)
    };
    let file_name =
        absolute
            .file_name()
            .ok_or(ProductionDoryV3QualificationError::Configuration(
                "scratch and output paths must name a child of an existing directory",
            ))?;
    let parent = absolute
        .parent()
        .ok_or(ProductionDoryV3QualificationError::Configuration(
            "scratch and output paths must have an existing parent",
        ))?;
    let parent = parent.canonicalize().map_err(|source| {
        ProductionDoryV3QualificationError::ResolvePath {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(parent.join(file_name))
}

fn ensure_path_absent(path: &Path) -> Result<(), ProductionDoryV3QualificationError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ProductionDoryV3QualificationError::PathExists(
            path.to_path_buf(),
        )),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ProductionDoryV3QualificationError::InspectPath {
            path: path.to_path_buf(),
            source,
        }),
    }
}

struct OwnedScratchDirectory {
    path: PathBuf,
    removed: bool,
}

impl OwnedScratchDirectory {
    fn create(path: PathBuf) -> Result<Self, ProductionDoryV3QualificationError> {
        fs::create_dir(&path).map_err(|source| {
            ProductionDoryV3QualificationError::CreateScratch {
                path: path.clone(),
                source,
            }
        })?;
        Ok(Self {
            path,
            removed: false,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn measure_retained(&self) -> Result<(u64, u64), ProductionDoryV3QualificationError> {
        measure_retained_scratch(&self.path).map_err(|source| {
            ProductionDoryV3QualificationError::InspectScratch {
                path: self.path.clone(),
                source,
            }
        })
    }

    fn remove_empty(&mut self) -> Result<(), ProductionDoryV3QualificationError> {
        fs::remove_dir(&self.path).map_err(|source| {
            ProductionDoryV3QualificationError::RemoveScratch {
                path: self.path.clone(),
                source,
            }
        })?;
        self.removed = true;
        Ok(())
    }

    fn mark_removed(&mut self) {
        self.removed = true;
    }
}

impl Drop for OwnedScratchDirectory {
    fn drop(&mut self) {
        if !self.removed {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

fn measure_retained_scratch(root: &Path) -> io::Result<(u64, u64)> {
    let mut entries = 0_u64;
    let mut logical_bytes = 0_u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            entries = entries
                .checked_add(1)
                .ok_or_else(|| io::Error::other("scratch entry count overflow"))?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_dir() {
                pending.push(entry.path());
            } else if metadata.file_type().is_file() {
                logical_bytes = logical_bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| io::Error::other("scratch logical-byte count overflow"))?;
            }
        }
    }
    Ok((entries, logical_bytes))
}

fn open_input(path: &Path) -> Result<File, ProductionDoryV3QualificationError> {
    File::open(path).map_err(|source| ProductionDoryV3QualificationError::OpenInput {
        path: path.to_path_buf(),
        source,
    })
}

fn pipeline_error(
    stage: &'static str,
    error: impl std::fmt::Display,
) -> ProductionDoryV3QualificationError {
    ProductionDoryV3QualificationError::Pipeline {
        stage,
        message: error.to_string(),
    }
}

fn check_cancel(cancel: &AtomicBool) -> Result<(), ProductionDoryV3QualificationError> {
    if cancel.load(Ordering::Relaxed) {
        return Err(ProductionDoryV3QualificationError::Cancelled);
    }
    Ok(())
}

fn qualification_request_digest(request: &ProductionDoryV3QualificationRequest) -> Digest32 {
    let mut hasher = blake3::Hasher::new_derive_key(QUALIFICATION_REQUEST_DIGEST_DOMAIN);
    hasher.update(&request.block.network_id);
    hasher.update(&request.block.previous_block);
    hasher.update(&request.block.transaction_root);
    hasher.update(&request.block.height.to_le_bytes());
    hasher.update(&request.block.timestamp.to_le_bytes());
    hasher.update(&request.block.target);
    hasher.update(&request.nonce.to_le_bytes());
    hasher.update(request.final_activation_digest.as_bytes());
    hasher.update(request.work_digest.as_bytes());
    Digest32::new(*hasher.finalize().as_bytes())
}

#[cfg(test)]
fn load_bounded_qualification_request(
    path: &Path,
) -> Result<ProductionDoryV3QualificationRequest, ProductionDoryV3QualificationError> {
    let bytes = read_bounded_strict_input(
        path,
        MAX_QUALIFICATION_REQUEST_JSON_BYTES,
        ProductionDoryV3QualificationError::QualificationRequestJsonTooLarge {
            max: MAX_QUALIFICATION_REQUEST_JSON_BYTES,
        },
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
fn load_bounded_record_v2(
    path: &Path,
) -> Result<DoryV3ModelCommitmentRecordV2, ProductionDoryV3QualificationError> {
    let bytes = read_bounded_strict_input(
        path,
        MAX_RECORD_V2_JSON_BYTES,
        ProductionDoryV3QualificationError::RecordV2JsonTooLarge {
            max: MAX_RECORD_V2_JSON_BYTES,
        },
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
fn read_bounded_proof_wire(path: &Path) -> Result<Vec<u8>, ProductionDoryV3QualificationError> {
    read_bounded_strict_input(
        path,
        MAX_PROOF_BYTES,
        ProductionDoryV3QualificationError::ProofWireTooLarge {
            max: MAX_PROOF_BYTES,
        },
    )
}

#[cfg(test)]
fn read_bounded_strict_input(
    path: &Path,
    maximum_bytes: usize,
    oversized: ProductionDoryV3QualificationError,
) -> Result<Vec<u8>, ProductionDoryV3QualificationError> {
    let mut input = RetainedStrictInput::open(path)?;
    let bytes = input.read_bounded(maximum_bytes, oversized)?;
    input.confirm_exact_bytes(&bytes)?;
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StrictInputState {
    bytes: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(windows)]
    last_write_time: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StrictContentIdentity {
    bytes: u64,
    blake3: Digest32,
}

struct RetainedStrictInput {
    path: PathBuf,
    file: File,
    identity: SameFileHandle,
    state: StrictInputState,
}

impl RetainedStrictInput {
    fn open(path: &Path) -> Result<Self, ProductionDoryV3QualificationError> {
        let file = open_strict_input_no_follow(path).map_err(|source| {
            ProductionDoryV3QualificationError::OpenInput {
                path: path.to_path_buf(),
                source,
            }
        })?;
        let (identity, state) = strict_input_identity_and_state(path, &file)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity,
            state,
        })
    }

    fn read_bounded(
        &mut self,
        maximum_bytes: usize,
        oversized: ProductionDoryV3QualificationError,
    ) -> Result<Vec<u8>, ProductionDoryV3QualificationError> {
        self.seek_start()?;
        let mut bytes = Vec::new();
        Read::take(&mut self.file, (maximum_bytes + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| ProductionDoryV3QualificationError::ReadInput {
                path: self.path.clone(),
                source,
            })?;
        if bytes.len() > maximum_bytes {
            return Err(oversized);
        }
        self.recheck()?;
        Ok(bytes)
    }

    fn confirm_exact_bytes(
        &mut self,
        expected: &[u8],
    ) -> Result<(), ProductionDoryV3QualificationError> {
        self.recheck()?;
        let mut named = self.open_named()?;
        let mut confirmed = Vec::with_capacity(expected.len().saturating_add(1));
        Read::take(&mut named, (expected.len().saturating_add(1)) as u64)
            .read_to_end(&mut confirmed)
            .map_err(|source| ProductionDoryV3QualificationError::ReadInput {
                path: self.path.clone(),
                source,
            })?;
        if confirmed != expected {
            return Err(ProductionDoryV3QualificationError::InputChanged(
                self.path.clone(),
            ));
        }
        self.recheck()
    }

    fn complete_content_identity(
        &mut self,
    ) -> Result<StrictContentIdentity, ProductionDoryV3QualificationError> {
        self.recheck()?;
        self.seek_start()?;
        let mut reader = Blake3CountingReader::new(&mut self.file);
        io::copy(&mut reader, &mut io::sink()).map_err(|source| {
            ProductionDoryV3QualificationError::ReadInput {
                path: self.path.clone(),
                source,
            }
        })?;
        let identity = reader.finish();
        self.recheck()?;
        Ok(identity)
    }

    fn confirm_content_identity(
        &mut self,
        expected: StrictContentIdentity,
    ) -> Result<(), ProductionDoryV3QualificationError> {
        if self.complete_content_identity()? != expected {
            return Err(ProductionDoryV3QualificationError::InputChanged(
                self.path.clone(),
            ));
        }
        Ok(())
    }

    fn recheck(&self) -> Result<(), ProductionDoryV3QualificationError> {
        drop(self.open_named()?);
        let (retained_identity, retained_state) =
            strict_input_identity_and_state(&self.path, &self.file)?;
        if retained_identity != self.identity {
            return Err(ProductionDoryV3QualificationError::InputReplaced(
                self.path.clone(),
            ));
        }
        if retained_state != self.state {
            return Err(ProductionDoryV3QualificationError::InputChanged(
                self.path.clone(),
            ));
        }
        Ok(())
    }

    fn open_named(&self) -> Result<File, ProductionDoryV3QualificationError> {
        let named = open_strict_input_no_follow(&self.path).map_err(|source| {
            ProductionDoryV3QualificationError::OpenInput {
                path: self.path.clone(),
                source,
            }
        })?;
        let (identity, state) = strict_input_identity_and_state(&self.path, &named)?;
        if identity != self.identity {
            return Err(ProductionDoryV3QualificationError::InputReplaced(
                self.path.clone(),
            ));
        }
        if state != self.state {
            return Err(ProductionDoryV3QualificationError::InputChanged(
                self.path.clone(),
            ));
        }
        Ok(named)
    }

    fn seek_start(&mut self) -> Result<(), ProductionDoryV3QualificationError> {
        self.file.seek(SeekFrom::Start(0)).map_err(|source| {
            ProductionDoryV3QualificationError::ReadInput {
                path: self.path.clone(),
                source,
            }
        })?;
        Ok(())
    }

    const fn bytes(&self) -> u64 {
        self.state.bytes
    }
}

fn strict_input_identity_and_state(
    path: &Path,
    file: &File,
) -> Result<(SameFileHandle, StrictInputState), ProductionDoryV3QualificationError> {
    let metadata =
        file.metadata()
            .map_err(|source| ProductionDoryV3QualificationError::OpenInput {
                path: path.to_path_buf(),
                source,
            })?;
    if !metadata.file_type().is_file() || metadata_is_reparse_point(&metadata) {
        return Err(ProductionDoryV3QualificationError::InputNotRegular(
            path.to_path_buf(),
        ));
    }
    let links = hard_link_count(file, &metadata).map_err(|source| {
        ProductionDoryV3QualificationError::OpenInput {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if links != 1 {
        return Err(ProductionDoryV3QualificationError::InputHardLinks {
            path: path.to_path_buf(),
            links,
        });
    }
    let identity = SameFileHandle::from_file(file.try_clone().map_err(|source| {
        ProductionDoryV3QualificationError::OpenInput {
            path: path.to_path_buf(),
            source,
        }
    })?)
    .map_err(|source| ProductionDoryV3QualificationError::OpenInput {
        path: path.to_path_buf(),
        source,
    })?;
    Ok((identity, strict_input_state(&metadata)))
}

fn strict_input_state(metadata: &fs::Metadata) -> StrictInputState {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        StrictInputState {
            bytes: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        StrictInputState {
            bytes: metadata.len(),
            last_write_time: metadata.last_write_time(),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        unreachable!("strict qualification inputs are supported only on Unix and Windows")
    }
}

fn open_strict_input_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = options;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "strict no-follow qualification inputs are supported only on Unix and Windows",
        ));
    }
    options.open(path)
}

struct Blake3CountingReader<R> {
    inner: R,
    hasher: blake3::Hasher,
    bytes: u64,
}

impl<R> Blake3CountingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
            bytes: 0,
        }
    }

    fn finish(self) -> StrictContentIdentity {
        StrictContentIdentity {
            bytes: self.bytes,
            blake3: Digest32::new(*self.hasher.finalize().as_bytes()),
        }
    }
}

impl<R: Read> Read for Blake3CountingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.bytes = self
            .bytes
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("qualification input byte count overflow"))?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn hard_link_count(file: &File, metadata: &fs::Metadata) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let _ = file;
        Ok(metadata.nlink())
    }
    #[cfg(windows)]
    {
        use std::{mem::MaybeUninit, os::windows::io::AsRawHandle as _};
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };

        let _ = metadata;
        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: `file` owns a live handle and the output points to the exact
        // structure initialized by GetFileInformationByHandle.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a nonzero return initialized the entire structure.
        Ok(u64::from(
            unsafe { information.assume_init() }.nNumberOfLinks,
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, metadata);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hard-link count is unavailable on this platform",
        ))
    }
}

fn decode_canonical_v3_layout_v5_wire(
    wire: &[u8],
    request: &ProductionDoryV3QualificationRequest,
) -> Result<
    (ForgeMatrixV3CandidateProof, BlsDoryV3CandidatePayload),
    ProductionDoryV3QualificationError,
> {
    let decoded = decode_forgematrix_proof(wire, request.block.network_id)?;
    let BlockProof::V3Candidate(candidate) = decoded else {
        return Err(ProductionDoryV3QualificationError::ExpectedV3Candidate);
    };
    let reencoded = encode_forgematrix_proof(
        &BlockProof::V3Candidate(candidate.clone()),
        request.block.network_id,
    )?;
    if reencoded != wire {
        return Err(ProductionDoryV3QualificationError::NonCanonicalWire);
    }
    let payload = validate_cp02(&candidate)?;
    require_layout_v5_header(&payload.dory_proof)?;
    validate_candidate_request_binding(&candidate, request)?;
    Ok((*candidate, payload))
}

fn require_layout_v5_header(dory_proof: &[u8]) -> Result<(), ProductionDoryV3QualificationError> {
    let Some(version_bytes) = dory_proof.get(8..10) else {
        return Err(ProductionDoryV3QualificationError::ExpectedLayoutV5);
    };
    if dory_proof.get(..SHARED_PROOF_MAGIC.len()) != Some(SHARED_PROOF_MAGIC.as_slice())
        || u16::from_le_bytes([version_bytes[0], version_bytes[1]]) != DORY_V3_SHARED_LAYOUT_VERSION
    {
        return Err(ProductionDoryV3QualificationError::ExpectedLayoutV5);
    }
    Ok(())
}

fn validate_candidate_request_binding(
    candidate: &ForgeMatrixV3CandidateProof,
    request: &ProductionDoryV3QualificationRequest,
) -> Result<(), ProductionDoryV3QualificationError> {
    if candidate.algorithm_version != DORY_V3_ALGORITHM_VERSION {
        return Err(BlsDoryV3CandidateError::AlgorithmVersion.into());
    }
    if candidate.proof_version != DORY_V3_PROOF_VERSION {
        return Err(BlsDoryV3CandidateError::ProofVersion.into());
    }
    if candidate.nonce != request.nonce {
        return Err(ProductionDoryV3QualificationError::ProofRequestMismatch(
            "nonce",
        ));
    }
    if candidate.final_activation_digest != request.final_activation_digest.into_bytes() {
        return Err(ProductionDoryV3QualificationError::ProofRequestMismatch(
            "final activation digest",
        ));
    }
    if candidate.work_digest != request.work_digest.into_bytes() {
        return Err(ProductionDoryV3QualificationError::ProofRequestMismatch(
            "work digest",
        ));
    }
    Ok(())
}

fn validate_verifier_candidate_binding(
    candidate: &ForgeMatrixV3CandidateProof,
    request: &ProductionDoryV3QualificationRequest,
    manifest_digest: Digest32,
) -> Result<(), ProductionDoryV3QualificationError> {
    validate_candidate_request_binding(candidate, request)?;
    if candidate.model_manifest_digest != manifest_digest.into_bytes() {
        return Err(BlsDoryV3CandidateError::ModelManifestDigest.into());
    }
    Ok(())
}

fn validate_verifier_record_static_identity(
    record: &DoryV3ModelCommitmentRecordV2,
) -> Result<(), ProductionDoryV3QualificationError> {
    if record.padded_variables() != DORY_V3_PADDED_VARIABLES {
        return Err(DoryV3ModelIdentityError::ProductionGeometry.into());
    }
    if record.setup_identity() != DORY_V3_SETUP_IDENTITY {
        return Err(DoryV3ModelIdentityError::SetupMismatch.into());
    }
    Ok(())
}

fn validate_cp02(
    candidate: &ForgeMatrixV3CandidateProof,
) -> Result<BlsDoryV3CandidatePayload, ProductionDoryV3QualificationError> {
    if candidate
        .structured_proof
        .get(..CANDIDATE_PAYLOAD_MAGIC.len())
        != Some(CANDIDATE_PAYLOAD_MAGIC.as_slice())
    {
        return Err(ProductionDoryV3QualificationError::NonCanonicalCp02);
    }
    let payload = BlsDoryV3CandidatePayload::decode(&candidate.structured_proof)?;
    if payload.encode()? != candidate.structured_proof {
        return Err(ProductionDoryV3QualificationError::NonCanonicalCp02);
    }
    Ok(payload)
}

fn blake3_digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*blake3::hash(bytes).as_bytes())
}

fn byte_len(bytes: &[u8]) -> Result<u64, ProductionDoryV3QualificationError> {
    u64::try_from(bytes.len()).map_err(|_| ProductionDoryV3QualificationError::SizeOverflow)
}

fn elapsed_nanoseconds(started: Instant) -> Result<u64, ProductionDoryV3QualificationError> {
    u64::try_from(started.elapsed().as_nanos())
        .map_err(|_| ProductionDoryV3QualificationError::DurationOverflow)
}

fn ensure_scratch_floor(
    required: u64,
    available: u64,
) -> Result<(), ProductionDoryV3QualificationError> {
    if available < required {
        return Err(ProductionDoryV3QualificationError::InsufficientScratch {
            required,
            available,
        });
    }
    Ok(())
}

fn ensure_memory_floor(
    required: u64,
    available: u64,
) -> Result<(), ProductionDoryV3QualificationError> {
    if available < required {
        return Err(ProductionDoryV3QualificationError::InsufficientMemory {
            required,
            available,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ScratchHighWaterSample {
    entries: u64,
    logical_bytes: u64,
}

struct ScratchHighWaterObserver {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<io::Result<ScratchHighWaterSample>>>,
}

impl ScratchHighWaterObserver {
    fn start(path: PathBuf) -> Self {
        let observer_path = path.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let join = thread::spawn(move || {
            let mut peak = ScratchHighWaterSample::default();
            while !thread_stop.load(Ordering::Relaxed) {
                let sample = sample_scratch_observation(&path)?;
                peak.entries = peak.entries.max(sample.entries);
                peak.logical_bytes = peak.logical_bytes.max(sample.logical_bytes);
                thread::sleep(SCRATCH_SAMPLE_INTERVAL);
            }
            let sample = sample_scratch_observation(&path)?;
            peak.entries = peak.entries.max(sample.entries);
            peak.logical_bytes = peak.logical_bytes.max(sample.logical_bytes);
            Ok(peak)
        });
        Self {
            path: observer_path,
            stop,
            join: Some(join),
        }
    }

    fn stop(&mut self) -> Result<ScratchHighWaterSample, ProductionDoryV3QualificationError> {
        self.stop.store(true, Ordering::Relaxed);
        self.join
            .take()
            .expect("scratch observer may only be stopped once")
            .join()
            .map_err(|_| ProductionDoryV3QualificationError::ScratchObserverPanicked)?
            .map_err(
                |source| ProductionDoryV3QualificationError::InspectScratch {
                    path: self.path.clone(),
                    source,
                },
            )
    }
}

impl Drop for ScratchHighWaterObserver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn sample_scratch_observation(root: &Path) -> io::Result<ScratchHighWaterSample> {
    let mut sample = ScratchHighWaterSample::default();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let reader = match fs::read_dir(directory) {
            Ok(reader) => reader,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in reader {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            sample.entries = sample
                .entries
                .checked_add(1)
                .ok_or_else(|| io::Error::other("scratch sample entry count overflow"))?;
            if metadata.file_type().is_dir() {
                pending.push(entry.path());
            } else if metadata.file_type().is_file() {
                sample.logical_bytes = sample
                    .logical_bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| io::Error::other("scratch sample logical-byte overflow"))?;
            }
        }
    }
    Ok(sample)
}

#[cfg(target_os = "linux")]
fn available_memory_bytes() -> io::Result<u64> {
    let contents = fs::read_to_string("/proc/meminfo")?;
    let host_available = parse_linux_kibibyte_field(&contents, "MemAvailable:")?;
    Ok(match linux_cgroup_available_memory_bytes()? {
        Some(cgroup_available) => host_available.min(cgroup_available),
        None => host_available,
    })
}

#[cfg(target_os = "linux")]
fn parse_linux_kibibyte_field(contents: &str, field: &str) -> io::Result<u64> {
    let line = contents
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .ok_or_else(|| io::Error::other(format!("Linux memory status has no {field} field")))?;
    let mut fields = line.split_whitespace();
    let kibibytes = fields
        .next()
        .ok_or_else(|| io::Error::other(format!("{field} has no value")))?
        .parse::<u64>()
        .map_err(|_| io::Error::other(format!("{field} is not a u64")))?;
    if fields.next() != Some("kB") || fields.next().is_some() {
        return Err(io::Error::other(format!("{field} has an unexpected unit")));
    }
    kibibytes
        .checked_mul(1_024)
        .ok_or_else(|| io::Error::other(format!("{field} byte count overflow")))
}

#[cfg(target_os = "linux")]
fn linux_cgroup_available_memory_bytes() -> io::Result<Option<u64>> {
    let cgroups = fs::read_to_string("/proc/self/cgroup")?;
    let mut v2_path = None;
    let mut v1_path = None;
    for line in cgroups.lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next().unwrap_or_default();
        let controllers = fields.next().unwrap_or_default();
        let path = fields.next().unwrap_or_default();
        if hierarchy == "0" && controllers.is_empty() && !path.is_empty() {
            v2_path = Some(PathBuf::from(path));
        } else if controllers
            .split(',')
            .any(|controller| controller == "memory")
            && !path.is_empty()
        {
            v1_path = Some(PathBuf::from(path));
        }
    }
    let Some((version, cgroup_path)) = v2_path
        .map(|path| (2_u8, path))
        .or_else(|| v1_path.map(|path| (1_u8, path)))
    else {
        return Ok(None);
    };

    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let mut control_location = None;
    for line in mountinfo.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let Some(separator) = fields.iter().position(|field| *field == "-") else {
            continue;
        };
        if separator < 5 || fields.len() <= separator + 3 {
            continue;
        }
        let file_system = fields[separator + 1];
        let super_options = fields[separator + 3];
        let matching_mount = if version == 2 {
            file_system == "cgroup2"
        } else {
            file_system == "cgroup" && super_options.split(',').any(|option| option == "memory")
        };
        if !matching_mount {
            continue;
        }
        let mount_root = decode_linux_mountinfo_path(fields[3]);
        let mount_point = decode_linux_mountinfo_path(fields[4]);
        let Ok(relative) = cgroup_path.strip_prefix(&mount_root) else {
            continue;
        };
        let control_directory = mount_point.join(relative);
        control_location = Some((mount_point, control_directory));
        break;
    }
    let (control_mount, control_directory) = control_location.ok_or_else(|| {
        io::Error::other("memory cgroup exists but its control mount was not found")
    })?;
    let (limit_name, current_name) = if version == 2 {
        ("memory.max", "memory.current")
    } else {
        ("memory.limit_in_bytes", "memory.usage_in_bytes")
    };
    cgroup_ancestor_available_memory_bytes(
        &control_directory,
        &control_mount,
        limit_name,
        current_name,
    )
}

#[cfg(target_os = "linux")]
fn decode_linux_mountinfo_path(encoded: &str) -> PathBuf {
    PathBuf::from(
        encoded
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\"),
    )
}

#[cfg(any(test, target_os = "linux"))]
fn cgroup_ancestor_available_memory_bytes(
    control_directory: &Path,
    control_mount: &Path,
    limit_name: &str,
    current_name: &str,
) -> io::Result<Option<u64>> {
    if !control_directory.starts_with(control_mount) {
        return Err(io::Error::other(
            "memory cgroup control directory is outside its mount",
        ));
    }
    let mut minimum_available = None;
    let mut current_directory = control_directory.to_path_buf();
    loop {
        let limit = fs::read_to_string(current_directory.join(limit_name))?;
        if limit.trim() != "max" {
            let limit = limit
                .trim()
                .parse::<u64>()
                .map_err(|_| io::Error::other("memory cgroup limit is not a u64"))?;
            let current = fs::read_to_string(current_directory.join(current_name))?
                .trim()
                .parse::<u64>()
                .map_err(|_| io::Error::other("memory cgroup usage is not a u64"))?;
            let available = limit.saturating_sub(current);
            minimum_available =
                Some(minimum_available.map_or(available, |minimum: u64| minimum.min(available)));
        }
        if current_directory == control_mount {
            break;
        }
        current_directory = current_directory
            .parent()
            .filter(|parent| parent.starts_with(control_mount))
            .ok_or_else(|| io::Error::other("memory cgroup ancestor traversal escaped mount"))?
            .to_path_buf();
    }
    Ok(minimum_available)
}

#[cfg(target_os = "windows")]
fn available_memory_bytes() -> io::Result<u64> {
    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_physical: u64,
        available_physical: u64,
        total_page_file: u64,
        available_page_file: u64,
        total_virtual: u64,
        available_virtual: u64,
        available_extended_virtual: u64,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GlobalMemoryStatusEx(status: *mut MemoryStatusEx) -> i32;
    }

    let mut status = MemoryStatusEx {
        length: u32::try_from(std::mem::size_of::<MemoryStatusEx>())
            .map_err(|_| io::Error::other("MEMORYSTATUSEX size overflow"))?,
        memory_load: 0,
        total_physical: 0,
        available_physical: 0,
        total_page_file: 0,
        available_page_file: 0,
        total_virtual: 0,
        available_virtual: 0,
        available_extended_virtual: 0,
    };
    // SAFETY: `status` is a writable, correctly sized MEMORYSTATUSEX value
    // whose `length` field is initialized as required by GlobalMemoryStatusEx.
    if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(status.available_physical)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn available_memory_bytes() -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "available-memory qualification is implemented only for Linux and Windows",
    ))
}

#[cfg(target_os = "linux")]
fn peak_whole_process_rss_bytes() -> io::Result<u64> {
    let contents = fs::read_to_string("/proc/self/status")?;
    parse_linux_kibibyte_field(&contents, "VmHWM:")
}

#[cfg(target_os = "windows")]
fn peak_whole_process_rss_bytes() -> io::Result<u64> {
    #[repr(C)]
    struct ProcessMemoryCounters {
        size: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
    }
    #[link(name = "psapi")]
    unsafe extern "system" {
        fn GetProcessMemoryInfo(
            process: isize,
            counters: *mut ProcessMemoryCounters,
            size: u32,
        ) -> i32;
    }

    let size = u32::try_from(std::mem::size_of::<ProcessMemoryCounters>())
        .map_err(|_| io::Error::other("PROCESS_MEMORY_COUNTERS size overflow"))?;
    let mut counters = ProcessMemoryCounters {
        size,
        page_fault_count: 0,
        peak_working_set_size: 0,
        working_set_size: 0,
        quota_peak_paged_pool_usage: 0,
        quota_paged_pool_usage: 0,
        quota_peak_non_paged_pool_usage: 0,
        quota_non_paged_pool_usage: 0,
        pagefile_usage: 0,
        peak_pagefile_usage: 0,
    };
    // SAFETY: GetCurrentProcess returns a process-local pseudo-handle that is
    // always valid for queries in the current process.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: `counters` is writable and its size field and explicit size
    // argument match the C PROCESS_MEMORY_COUNTERS layout above.
    if unsafe { GetProcessMemoryInfo(process, &mut counters, size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(counters.peak_working_set_size)
        .map_err(|_| io::Error::other("whole-process peak RSS does not fit u64"))
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn peak_whole_process_rss_bytes() -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "whole-process peak RSS is implemented only for Linux and Windows",
    ))
}

struct UnconfirmedOutputs {
    outputs: Vec<(PathBuf, SameFileHandle)>,
    confirmed: bool,
}

impl UnconfirmedOutputs {
    fn new() -> Self {
        Self {
            outputs: Vec::with_capacity(2),
            confirmed: false,
        }
    }

    fn write_and_verify(
        &mut self,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), ProductionDoryV3QualificationError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|source| ProductionDoryV3QualificationError::CreateOutput {
                path: path.to_path_buf(),
                source,
            })?;
        let identity = match file.try_clone().and_then(SameFileHandle::from_file) {
            Ok(identity) => identity,
            Err(source) => {
                drop(file);
                let _ = fs::remove_file(path);
                return Err(ProductionDoryV3QualificationError::OutputIdentity {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        self.outputs.push((path.to_path_buf(), identity));
        file.write_all(bytes).map_err(|source| {
            ProductionDoryV3QualificationError::WriteOutput {
                path: path.to_path_buf(),
                source,
            }
        })?;
        file.sync_all()
            .map_err(|source| ProductionDoryV3QualificationError::SyncOutput {
                path: path.to_path_buf(),
                source,
            })?;
        drop(file);
        let mut reopened = Vec::new();
        let mut reopened_file = File::open(path).map_err(|source| {
            ProductionDoryV3QualificationError::ReopenOutput {
                path: path.to_path_buf(),
                source,
            }
        })?;
        let reopened_identity =
            SameFileHandle::from_file(reopened_file.try_clone().map_err(|source| {
                ProductionDoryV3QualificationError::OutputIdentity {
                    path: path.to_path_buf(),
                    source,
                }
            })?)
            .map_err(|source| {
                ProductionDoryV3QualificationError::OutputIdentity {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
        if reopened_identity != self.outputs.last().expect("output identity was retained").1 {
            return Err(ProductionDoryV3QualificationError::OutputReplaced(
                path.to_path_buf(),
            ));
        }
        reopened_file.read_to_end(&mut reopened).map_err(|source| {
            ProductionDoryV3QualificationError::ReopenOutput {
                path: path.to_path_buf(),
                source,
            }
        })?;
        if reopened != bytes {
            return Err(ProductionDoryV3QualificationError::OutputMismatch(
                path.to_path_buf(),
            ));
        }
        Ok(())
    }

    fn confirm(mut self) {
        self.confirmed = true;
    }
}

impl Drop for UnconfirmedOutputs {
    fn drop(&mut self) {
        if !self.confirmed {
            for (path, identity) in self.outputs.iter().rev() {
                if SameFileHandle::from_path(path).is_ok_and(|current| &current == identity) {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }
}

fn write_verified_outputs(
    proof_path: &Path,
    proof_bytes: &[u8],
    report_path: &Path,
    report_bytes: &[u8],
) -> Result<(), ProductionDoryV3QualificationError> {
    let mut outputs = UnconfirmedOutputs::new();
    outputs.write_and_verify(proof_path, proof_bytes)?;
    outputs.write_and_verify(report_path, report_bytes)?;
    sync_output_parent_directories(proof_path, report_path)?;
    outputs.confirm();
    Ok(())
}

fn write_verified_output(
    output_path: &Path,
    output_bytes: &[u8],
) -> Result<(), ProductionDoryV3QualificationError> {
    let mut outputs = UnconfirmedOutputs::new();
    outputs.write_and_verify(output_path, output_bytes)?;
    let parent = output_path
        .parent()
        .ok_or(ProductionDoryV3QualificationError::Configuration(
            "output must have a parent directory",
        ))?;
    sync_output_parent_directory(parent)?;
    outputs.confirm();
    Ok(())
}

#[cfg(unix)]
fn sync_output_parent_directories(
    proof_path: &Path,
    report_path: &Path,
) -> Result<(), ProductionDoryV3QualificationError> {
    let proof_parent =
        proof_path
            .parent()
            .ok_or(ProductionDoryV3QualificationError::Configuration(
                "proof output must have a parent directory",
            ))?;
    sync_output_parent_directory(proof_parent)?;
    let report_parent =
        report_path
            .parent()
            .ok_or(ProductionDoryV3QualificationError::Configuration(
                "report output must have a parent directory",
            ))?;
    if report_parent != proof_parent {
        sync_output_parent_directory(report_parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_output_parent_directory(path: &Path) -> Result<(), ProductionDoryV3QualificationError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(
            |source| ProductionDoryV3QualificationError::SyncOutputParent {
                path: path.to_path_buf(),
                source,
            },
        )
}

#[cfg(not(unix))]
fn sync_output_parent_directory(_path: &Path) -> Result<(), ProductionDoryV3QualificationError> {
    Ok(())
}

#[cfg(not(unix))]
fn sync_output_parent_directories(
    _proof_path: &Path,
    _report_path: &Path,
) -> Result<(), ProductionDoryV3QualificationError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        sync::atomic::{AtomicU64, Ordering},
    };

    use dory_pcs::primitives::arithmetic::Field;
    use serde_json::json;

    use crate::{
        ForgeMatrixV2CompactProof, ModelBankManifest, SmallModelBankFixture,
        dory_bls12_381_aggregate::commit_bls_dory_polynomial,
        dory_bls12_381_candidate::decode_dory_v3_layout_v5_candidate_payload,
        dory_bls12_381_layout::bls_dory_shared_layout_v5_candidate_codec_fixture_for_test,
        dory_bls12_381_prototype::{BlsDoryFr, DeterministicBlsDorySetup},
        dory_v3_model::{CanonicalBlsDoryGtHex, DoryV3ModelIdentityV1},
        dory_v3_model_record::derive_bank_authenticated_dory_v3_model_commitment_record_v2_for_test,
        dory_v3_suite::DORY_V3_MODEL_IDENTITY_VERSION,
        model_bank::build_small_model_bank,
        structured_proof::StructuredForgeMatrixResearchShape,
    };

    use super::*;

    static TEST_DIRECTORY_NONCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    struct SmallBankFixture {
        bytes: Vec<u8>,
        manifest: ModelBankManifest,
        identity: DoryV3ModelIdentityV1,
        setup: DeterministicBlsDorySetup,
    }

    impl TestDirectory {
        fn create() -> Self {
            let nonce = TEST_DIRECTORY_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cmfd-dory-v3-qualification-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn request() -> ProductionDoryV3QualificationRequest {
        ProductionDoryV3QualificationRequest {
            block: seed().block,
            nonce: 6,
            final_activation_digest: Digest32::new([7; 32]),
            work_digest: Digest32::new([8; 32]),
        }
    }

    fn complete_journal_fixture() -> (
        TestDirectory,
        PathBuf,
        QualificationEffectiveConfiguration,
        Digest32,
        QualificationAuthenticatedIdentities,
        ProductionDoryV3QualificationJournalSummary,
        Vec<u8>,
    ) {
        let directory = TestDirectory::create();
        let path = directory.0.join("complete-journal.jsonl");
        let configuration = qualification_effective_configuration(131_072).unwrap();
        let request_digest = Digest32::new([0x11; 32]);
        let identities = QualificationAuthenticatedIdentities {
            record_digest: Digest32::new([0x22; 32]),
            model_identity_digest: Digest32::new([0x33; 32]),
            setup_identity: Digest32::new([0x44; 32]),
        };
        let mut journal =
            QualificationJournal::create(path.clone(), request_digest, configuration).unwrap();
        for stage in &QUALIFICATION_JOURNAL_STAGES[1..QUALIFICATION_JOURNAL_STAGES.len() - 1] {
            journal
                .append_stage(
                    stage,
                    (*stage == "bank_authentication_completed").then_some(identities),
                )
                .unwrap();
        }
        let summary = journal
            .finish(QUALIFICATION_JOURNAL_STAGES[QUALIFICATION_JOURNAL_STAGES.len() - 1])
            .unwrap();
        drop(journal);
        let bytes = fs::read(&path).unwrap();
        (
            directory,
            path,
            configuration,
            request_digest,
            identities,
            summary,
            bytes,
        )
    }

    fn decode_strict_journal_records(bytes: &[u8]) -> Vec<StrictQualificationJournalRecord> {
        bytes[..bytes.len() - 1]
            .split(|byte| *byte == b'\n')
            .map(|record| serde_json::from_slice(record).unwrap())
            .collect()
    }

    fn encode_strict_journal_records(records: &[StrictQualificationJournalRecord]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for record in records {
            bytes.extend_from_slice(&serde_json::to_vec(record).unwrap());
            bytes.push(b'\n');
        }
        bytes
    }

    fn producer_report_fixture(
        summary: ProductionDoryV3QualificationJournalSummary,
    ) -> (
        ProductionDoryV3QualificationReport,
        ProductionDoryV3QualificationRequest,
        Vec<u8>,
        ForgeMatrixV3CandidateProof,
        BlsDoryV3CandidatePayload,
    ) {
        let request = request();
        let candidate = verifier_candidate(&request, [0x55; 32]);
        let payload = validate_cp02(&candidate).unwrap();
        let native_projection = projected_bls_dory_blake3_production_resources().unwrap();
        let candidate_required = projected_candidate_required_free_scratch_bytes().unwrap();
        let wire = encode_forgematrix_proof(
            &BlockProof::V3Candidate(Box::new(candidate.clone())),
            request.block.network_id,
        )
        .unwrap();
        let report = ProductionDoryV3QualificationReport {
            report_version: QUALIFICATION_REPORT_VERSION,
            padded_variables: DORY_V3_PADDED_VARIABLES,
            composed_claims: u16::try_from(BLS_DORY_COMPOSED_AGGREGATE_CLAIMS).unwrap(),
            verifier_passes: 2,
            maximum_native_block_rows: 131_072,
            network_id: Digest32::new(request.block.network_id),
            block_height: request.block.height,
            nonce: request.nonce,
            request_digest: qualification_request_digest(&request),
            record_digest: Digest32::new([0x22; 32]),
            model_identity_digest: Digest32::new([0x33; 32]),
            setup_identity: DORY_V3_SETUP_IDENTITY,
            challenge_digest: Digest32::new(candidate.challenge_digest),
            final_activation_digest: request.final_activation_digest,
            work_digest: request.work_digest,
            cp02_blake3_digest: blake3_digest(&candidate.structured_proof),
            dory_proof_blake3_digest: blake3_digest(&payload.dory_proof),
            native_proof_blake3_digest: blake3_digest(&payload.native_blake3_proof),
            wire_blake3_digest: blake3_digest(&wire),
            record_canonical_bytes: 166,
            cp02_bytes: byte_len(&candidate.structured_proof).unwrap(),
            cp02_header_bytes: u64::try_from(CANDIDATE_PAYLOAD_HEADER_BYTES).unwrap(),
            dory_proof_bytes: byte_len(&payload.dory_proof).unwrap(),
            native_proof_bytes: byte_len(&payload.native_blake3_proof).unwrap(),
            wire_bytes: byte_len(&wire).unwrap(),
            provisional_scratch_floor_bytes: native_projection.provisional_scratch_gate_bytes,
            initial_available_scratch_bytes: native_projection.provisional_scratch_gate_bytes,
            candidate_required_free_scratch_bytes: candidate_required,
            candidate_available_free_scratch_bytes: candidate_required,
            provisional_available_memory_floor_bytes: native_projection
                .provisional_available_memory_gate_bytes,
            observed_available_memory_before_bytes: native_projection
                .provisional_available_memory_gate_bytes,
            native_resource_projection_complete: native_projection.is_complete(),
            sampled_peak_scratch_entries_observation: 1,
            sampled_peak_scratch_logical_bytes_observation: 1,
            scratch_sample_interval_milliseconds: 100,
            sampled_peak_scratch_observation_scope: SAMPLED_SCRATCH_OBSERVATION_SCOPE.into(),
            exact_peak_instrumented_scratch_logical_bytes: 1,
            exact_peak_instrumented_scratch_live_entries: 1,
            instrumented_scratch_file_creation_events: 1,
            instrumented_scratch_size_mutation_events: 1,
            exact_peak_scratch_instrumented: true,
            exact_peak_scratch_scope: EXACT_SCRATCH_PEAK_SCOPE.into(),
            retained_scratch_entries: 0,
            retained_scratch_logical_bytes: 0,
            whole_process_peak_rss_bytes: 1,
            whole_process_peak_rss_scope: WHOLE_PROCESS_PEAK_RSS_SCOPE.into(),
            cooperative_cancellation_scope: COOPERATIVE_CANCELLATION_SCOPE.into(),
            qualification_journal: summary,
            report_output_is_completion_marker: true,
            publication_crash_atomic: false,
            parent_directory_sync_performed: cfg!(unix),
            setup_nanoseconds: 1,
            record_load_and_validation_nanoseconds: 1,
            bank_reauthentication_nanoseconds: 1,
            fixed_model_preparation_nanoseconds: 1,
            winning_claim_replay_nanoseconds: 1,
            candidate_resource_preflight_nanoseconds: 1,
            layout_v5_preparation_nanoseconds: 1,
            native_and_aggregate_composition_nanoseconds: 1,
            cp02_seal_nanoseconds: 1,
            scratch_cleanup_nanoseconds: 1,
            first_verification_nanoseconds: 1,
            wire_round_trip_nanoseconds: 1,
            second_verification_nanoseconds: 1,
            prepublication_qualification_nanoseconds: 13,
        };
        (report, request, wire, candidate, payload)
    }

    fn seed() -> ProductionDoryV3QualificationSeed {
        ProductionDoryV3QualificationSeed {
            block: BlockChallenge {
                network_id: [1; 32],
                previous_block: [2; 32],
                transaction_root: [3; 32],
                height: 4,
                timestamp: 5,
                target: [0xff; 32],
            },
            nonce: 6,
        }
    }

    fn verifier_candidate(
        request: &ProductionDoryV3QualificationRequest,
        manifest_digest: [u8; 32],
    ) -> ForgeMatrixV3CandidateProof {
        let mut dory_proof = SHARED_PROOF_MAGIC.to_vec();
        dory_proof.extend_from_slice(&DORY_V3_SHARED_LAYOUT_VERSION.to_le_bytes());
        dory_proof.extend_from_slice(&(DORY_V3_PADDED_VARIABLES as u16).to_le_bytes());
        dory_proof.extend_from_slice(&3_u16.to_le_bytes());
        dory_proof.extend_from_slice(&4_u16.to_le_bytes());
        ForgeMatrixV3CandidateProof {
            algorithm_version: DORY_V3_ALGORITHM_VERSION,
            proof_version: DORY_V3_PROOF_VERSION,
            nonce: request.nonce,
            model_manifest_digest: manifest_digest,
            challenge_digest: [9; 32],
            final_activation_digest: request.final_activation_digest.into_bytes(),
            work_digest: request.work_digest.into_bytes(),
            structured_proof: BlsDoryV3CandidatePayload {
                dory_proof,
                native_blake3_proof: vec![4, 5, 6],
            }
            .encode()
            .unwrap(),
        }
    }

    fn small_bank_fixture() -> SmallBankFixture {
        const VARIABLES: usize = 4;
        const BASE: [u8; 4] = [125, 126, 124, 130];
        const LAYER: [u8; 4] = [125, 127, 129, 131];
        const SUITE_DIGEST: [u8; 32] = [0x51; 32];

        let setup = deterministic_bls_dory_setup(VARIABLES).unwrap();
        let commit = |bytes: &[u8]| {
            let mut coefficients = bytes
                .iter()
                .map(|value| BlsDoryFr::from_i64(i64::from(*value) - 125))
                .collect::<Vec<_>>();
            coefficients.resize(1_usize << VARIABLES, BlsDoryFr::from_i64(0));
            commit_bls_dory_polynomial(
                coefficients,
                VARIABLES / 2,
                VARIABLES - VARIABLES / 2,
                &setup,
            )
            .unwrap()
            .commitment()
        };
        let base_commitment = commit(&BASE);
        let weight_commitment = commit(&LAYER);
        let layers = [LAYER.as_slice()];
        let provisional = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &BASE,
            layers: &layers,
            pcs_parameter_digest: SUITE_DIGEST,
            pcs_commitment_root: [0x52; 32],
        })
        .unwrap();
        let identity: DoryV3ModelIdentityV1 = serde_json::from_value(json!({
            "identity_version": DORY_V3_MODEL_IDENTITY_VERSION,
            "model_version": 2,
            "batch": 2,
            "dimension": 2,
            "layers_per_bank": 1,
            "model_byte_root": provisional.manifest.raw_blake3_root,
            "layer_roots_aggregate": provisional.manifest.layer_roots_aggregate,
            "suite_parameter_digest": SUITE_DIGEST,
            "setup_identity": setup.identity(),
            "padded_variables": VARIABLES,
            "base_input_commitment": CanonicalBlsDoryGtHex::from_commitment(base_commitment)
                .unwrap()
                .to_hex()
                .unwrap(),
            "weight_bank_commitments": [
                CanonicalBlsDoryGtHex::from_commitment(weight_commitment)
                    .unwrap()
                    .to_hex()
                    .unwrap()
            ],
        }))
        .unwrap();
        let built = build_small_model_bank(SmallModelBankFixture {
            model_version: 2,
            dimension: 2,
            batch: 2,
            base_input: &BASE,
            layers: &layers,
            pcs_parameter_digest: SUITE_DIGEST,
            pcs_commitment_root: identity.commitment_root().unwrap(),
        })
        .unwrap();
        identity.verify_manifest(&built.manifest).unwrap();
        SmallBankFixture {
            bytes: built.bytes,
            manifest: built.manifest,
            identity,
            setup,
        }
    }

    #[test]
    fn qualification_seed_json_is_strict_and_has_no_claim_fields() {
        let encoded = serde_json::to_value(seed()).unwrap();
        assert_eq!(
            serde_json::from_value::<ProductionDoryV3QualificationSeed>(encoded.clone()).unwrap(),
            seed()
        );
        assert!(encoded.get("final_activation_digest").is_none());
        assert!(encoded.get("work_digest").is_none());

        let mut unknown_outer = encoded.clone();
        unknown_outer["work_digest"] = json!("00".repeat(32));
        assert!(
            serde_json::from_value::<ProductionDoryV3QualificationSeed>(unknown_outer).is_err()
        );

        let mut unknown_block = encoded;
        unknown_block["block"]["algorithm_version"] = json!(3);
        assert!(
            serde_json::from_value::<ProductionDoryV3QualificationSeed>(unknown_block).is_err()
        );
    }

    #[test]
    fn qualification_request_json_is_strict_at_both_levels() {
        let encoded = serde_json::to_value(request()).unwrap();
        assert_eq!(
            serde_json::from_value::<ProductionDoryV3QualificationRequest>(encoded.clone())
                .unwrap(),
            request()
        );

        let mut unknown_outer = encoded.clone();
        unknown_outer["geometry"] = json!(33);
        assert!(
            serde_json::from_value::<ProductionDoryV3QualificationRequest>(unknown_outer).is_err()
        );

        let mut unknown_block = encoded.clone();
        unknown_block["block"]["algorithm_version"] = json!(2);
        assert!(
            serde_json::from_value::<ProductionDoryV3QualificationRequest>(unknown_block).is_err()
        );

        let mut uppercase_digest = encoded;
        uppercase_digest["work_digest"] = json!("AA".repeat(32));
        assert!(
            serde_json::from_value::<ProductionDoryV3QualificationRequest>(uppercase_digest)
                .is_err()
        );
    }

    #[test]
    fn qualification_paths_require_new_distinct_runner_owned_locations() {
        let directory = TestDirectory::create();
        let scratch = directory.0.join("scratch");
        let proof = directory.0.join("proof.bin");
        let report = directory.0.join("report.json");
        let journal = directory.0.join("journal.jsonl");
        let paths = QualificationPaths::preflight(&scratch, &proof, &report, &journal).unwrap();
        assert_eq!(paths.scratch, scratch);
        assert_eq!(paths.journal_output, journal);

        assert!(matches!(
            QualificationPaths::preflight(Path::new("relative"), &proof, &report, &journal),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));
        assert!(matches!(
            QualificationPaths::preflight(&scratch, Path::new("relative-proof"), &report, &journal),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));
        assert!(matches!(
            QualificationPaths::preflight(&scratch, &proof, Path::new("relative-report"), &journal),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));
        assert!(matches!(
            QualificationPaths::preflight(&scratch, &proof, &report, Path::new("relative-journal")),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));
        assert!(matches!(
            QualificationPaths::preflight(&scratch, &proof, &proof, &journal),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));
        assert!(matches!(
            QualificationPaths::preflight(&scratch, &proof, &report, &proof),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));
        let alias_directory = directory.0.join("alias");
        fs::create_dir(&alias_directory).unwrap();
        let aliased_proof = alias_directory.join("..").join("proof.bin");
        assert!(matches!(
            QualificationPaths::preflight(&scratch, &proof, &report, &aliased_proof),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));
        assert!(matches!(
            QualificationPaths::preflight(
                &scratch,
                &proof,
                &report,
                &scratch.join("journal.jsonl")
            ),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));

        fs::create_dir(&scratch).unwrap();
        assert!(matches!(
            QualificationPaths::preflight(&scratch, &proof, &report, &journal),
            Err(ProductionDoryV3QualificationError::PathExists(path)) if path == scratch
        ));
        fs::remove_dir(&scratch).unwrap();

        fs::write(&proof, b"existing").unwrap();
        assert!(matches!(
            QualificationPaths::preflight(&scratch, &proof, &report, &journal),
            Err(ProductionDoryV3QualificationError::PathExists(path)) if path == proof
        ));
        fs::remove_file(&proof).unwrap();

        fs::write(&journal, b"existing").unwrap();
        assert!(matches!(
            QualificationPaths::preflight(&scratch, &proof, &report, &journal),
            Err(ProductionDoryV3QualificationError::PathExists(path)) if path == journal
        ));
    }

    #[test]
    fn qualification_library_inputs_require_absolute_paths() {
        let directory = TestDirectory::create();
        let absolute = directory.0.join("input");
        ensure_absolute_paths(&[&absolute], "test paths must be absolute").unwrap();
        assert!(matches!(
            ensure_absolute_paths(
                &[Path::new("relative-input")],
                "test paths must be absolute"
            ),
            Err(ProductionDoryV3QualificationError::Configuration(
                "test paths must be absolute"
            ))
        ));
    }

    #[test]
    fn qualification_request_paths_require_new_absolute_separate_locations() {
        let directory = TestDirectory::create();
        let scratch = directory.0.join("request-scratch");
        let output = directory.0.join("request.json");
        let paths = QualificationRequestPaths::preflight(&scratch, &output).unwrap();
        assert_eq!(paths.scratch, scratch);
        assert_eq!(paths.request_output, output);

        assert!(matches!(
            QualificationRequestPaths::preflight(Path::new("relative"), &output),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));
        assert!(matches!(
            QualificationRequestPaths::preflight(&scratch, Path::new("relative.json")),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));
        assert!(matches!(
            QualificationRequestPaths::preflight(&scratch, &scratch.join("request.json")),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));

        fs::write(&output, b"existing").unwrap();
        assert!(matches!(
            QualificationRequestPaths::preflight(&scratch, &output),
            Err(ProductionDoryV3QualificationError::PathExists(path)) if path == output
        ));
    }

    #[test]
    fn verifier_report_output_requires_a_new_absolute_path() {
        let directory = TestDirectory::create();
        let report = directory.0.join("fresh-verifier-report.json");
        assert_eq!(preflight_verifier_report_output(&report).unwrap(), report);
        assert!(matches!(
            preflight_verifier_report_output(Path::new("relative-report.json")),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));

        fs::write(&report, b"existing").unwrap();
        assert!(matches!(
            preflight_verifier_report_output(&report),
            Err(ProductionDoryV3QualificationError::PathExists(path)) if path == report
        ));
    }

    #[test]
    fn qualification_resource_floors_reject_one_byte_short() {
        ensure_scratch_floor(10, 10).unwrap();
        assert!(matches!(
            ensure_scratch_floor(10, 9),
            Err(ProductionDoryV3QualificationError::InsufficientScratch {
                required: 10,
                available: 9
            })
        ));
        ensure_memory_floor(20, 20).unwrap();
        assert!(matches!(
            ensure_memory_floor(20, 19),
            Err(ProductionDoryV3QualificationError::InsufficientMemory {
                required: 20,
                available: 19
            })
        ));
    }

    #[test]
    fn qualification_honors_prestart_cancellation_before_path_or_resource_io() {
        let cancel = AtomicBool::new(true);
        let result = run_production_dory_v3_qualification(
            Path::new("missing-bank"),
            Path::new("missing-record"),
            &request(),
            Path::new("relative-scratch"),
            Path::new("proof"),
            Path::new("report"),
            Path::new("journal"),
            1,
            &cancel,
        );
        assert!(matches!(
            result,
            Err(ProductionDoryV3QualificationError::Cancelled)
        ));
    }

    #[test]
    fn request_generation_honors_prestart_cancellation_before_path_io() {
        let result = generate_production_dory_v3_qualification_request(
            Path::new("missing-bank"),
            Path::new("missing-record"),
            &seed(),
            Path::new("relative-scratch"),
            Path::new("relative-request"),
            &AtomicBool::new(true),
        );
        assert!(matches!(
            result,
            Err(ProductionDoryV3QualificationError::Cancelled)
        ));
    }

    #[test]
    fn qualification_request_digest_binds_block_and_claim() {
        let original = request();
        let digest = qualification_request_digest(&original);
        assert_eq!(
            digest.to_hex(),
            "7efd98c684fe92e2c2490cbdcf5fbb4cfdfb701a8cadd8b596d96fc075f0b6fa"
        );
        let mut changed_nonce = original.clone();
        changed_nonce.nonce += 1;
        assert_ne!(qualification_request_digest(&changed_nonce), digest);
        let mut changed_block = original;
        changed_block.block.timestamp += 1;
        assert_ne!(qualification_request_digest(&changed_block), digest);
    }

    #[test]
    fn qualification_journal_is_canonical_hash_chained_and_diagnostic_only() {
        let directory = TestDirectory::create();
        let path = directory.0.join("qualification.jsonl");
        let configuration = qualification_effective_configuration(131_072).unwrap();
        let request_digest = Digest32::new([0x11; 32]);
        let identities = QualificationAuthenticatedIdentities {
            record_digest: Digest32::new([0x22; 32]),
            model_identity_digest: Digest32::new([0x33; 32]),
            setup_identity: Digest32::new([0x44; 32]),
        };
        let mut journal =
            QualificationJournal::create(path.clone(), request_digest, configuration).unwrap();
        journal
            .append_stage("bank_authentication_completed", Some(identities))
            .unwrap();
        let summary = journal
            .finish("prepublication_verification_recorded")
            .unwrap();
        drop(journal);

        assert_eq!(QUALIFICATION_REPORT_VERSION, 4);
        assert_eq!(VERIFIER_REPORT_VERSION, 2);
        assert_eq!(QUALIFICATION_REQUEST_GENERATION_REPORT_VERSION, 1);
        assert_eq!(QUALIFICATION_JOURNAL_VERSION, 1);
        assert_eq!(summary.journal_version, QUALIFICATION_JOURNAL_VERSION);
        assert_eq!(
            summary.run_identity.to_hex(),
            "779177cafbf61172bb9f3281afa58ba46782c18c7cf3219afadae6d0a0a18906"
        );
        assert_eq!(summary.event_count, 3);
        assert!(summary.diagnostic_only);
        assert!(!summary.completion_marker);
        assert!(!summary.resumable);

        let journal_bytes = fs::read(&path).unwrap();
        assert_eq!(journal_bytes.last(), Some(&b'\n'));
        let records = journal_bytes
            .split(|byte| *byte == b'\n')
            .filter(|record| !record.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 3);
        let decoded = records
            .iter()
            .map(|record| serde_json::from_slice::<serde_json::Value>(record).unwrap())
            .collect::<Vec<_>>();
        for (sequence, value) in decoded.iter().enumerate() {
            assert_eq!(value["sequence"], json!(sequence));
            assert_eq!(value["run_identity"], json!(summary.run_identity.to_hex()));
            assert_eq!(value["request_digest"], json!(request_digest.to_hex()));
            assert_eq!(value["diagnostic_only"], json!(true));
            assert_eq!(value["completion_marker"], json!(false));
            assert_eq!(value["resumable"], json!(false));
        }
        assert_eq!(
            std::str::from_utf8(records[0]).unwrap(),
            format!(
                "{{\"journal_version\":1,\"sequence\":0,\"previous_record_digest\":\"{}\",\"run_identity\":\"{}\",\"request_digest\":\"{}\",\"stage\":\"preflight_completed\",\"diagnostic_only\":true,\"completion_marker\":false,\"resumable\":false,\"effective_configuration\":{{\"qualification_report_version\":4,\"padded_variables\":33,\"composed_claims\":134,\"verifier_passes\":2,\"maximum_native_block_rows\":131072,\"algorithm_version\":2,\"proof_version\":1,\"shared_layout_version\":5,\"scratch_sample_interval_milliseconds\":100}}}}",
                "00".repeat(32),
                summary.run_identity.to_hex(),
                request_digest.to_hex()
            )
        );
        assert_eq!(decoded[0]["previous_record_digest"], json!("00".repeat(32)));
        assert_eq!(decoded[0]["stage"], json!("preflight_completed"));
        assert_ne!(
            qualification_journal_record_digest(records[0]),
            Digest32::ZERO
        );
        assert_eq!(
            decoded[0]["effective_configuration"]["maximum_native_block_rows"],
            json!(131_072)
        );
        assert_eq!(
            decoded[1]["previous_record_digest"],
            json!(qualification_journal_record_digest(records[0]).to_hex())
        );
        assert_eq!(
            decoded[1]["authenticated_identities"]["record_digest"],
            json!(identities.record_digest.to_hex())
        );
        assert_eq!(
            decoded[2]["previous_record_digest"],
            json!(qualification_journal_record_digest(records[1]).to_hex())
        );
        assert_eq!(
            summary.final_record_digest,
            qualification_journal_record_digest(records[2])
        );
        assert_eq!(summary.journal_bytes, byte_len(&journal_bytes).unwrap());
        assert_eq!(
            summary.complete_file_digest,
            qualification_journal_complete_file_digest(&journal_bytes).unwrap()
        );
        assert_eq!(
            decoded[2]["stage"],
            json!("prepublication_verification_recorded")
        );

        let encoded_summary = serde_json::to_string(&summary).unwrap();
        assert_eq!(
            encoded_summary,
            format!(
                "{{\"journal_version\":1,\"run_identity\":\"{}\",\"final_record_digest\":\"{}\",\"event_count\":3,\"journal_bytes\":{},\"complete_file_digest\":\"{}\",\"diagnostic_only\":true,\"completion_marker\":false,\"resumable\":false}}",
                summary.run_identity.to_hex(),
                summary.final_record_digest.to_hex(),
                summary.journal_bytes,
                summary.complete_file_digest.to_hex()
            )
        );

        assert!(matches!(
            QualificationJournal::create(path, request_digest, configuration),
            Err(ProductionDoryV3QualificationError::CreateOutput { .. })
        ));
    }

    #[test]
    fn qualification_journal_detects_unexpected_appended_bytes() {
        let directory = TestDirectory::create();
        let path = directory.0.join("qualification.jsonl");
        let configuration = qualification_effective_configuration(1).unwrap();
        let mut journal =
            QualificationJournal::create(path.clone(), Digest32::new([0x55; 32]), configuration)
                .unwrap();
        journal.file.write_all(b"{}\n").unwrap();
        journal.file.flush().unwrap();
        journal.file.sync_all().unwrap();

        assert!(matches!(
            journal.append_stage("setup_validation_completed", None),
            Err(ProductionDoryV3QualificationError::OutputMismatch(found)) if found == path
        ));
    }

    #[test]
    fn independent_journal_auditor_accepts_only_the_complete_exact_stage_grammar() {
        let (_directory, _path, configuration, request_digest, identities, summary, bytes) =
            complete_journal_fixture();
        let audited =
            audit_qualification_journal(&bytes, request_digest, configuration, identities).unwrap();
        assert_eq!(audited, summary);
        require_matching_journal_summary(&audited, &summary).unwrap();
        assert_eq!(audited.event_count, 16);
        assert_eq!(audited.journal_bytes, byte_len(&bytes).unwrap());
        assert_eq!(
            audited.complete_file_digest,
            qualification_journal_complete_file_digest(&bytes).unwrap()
        );

        let records = decode_strict_journal_records(&bytes);
        for (record, stage) in records.iter().zip(QUALIFICATION_JOURNAL_STAGES) {
            assert_eq!(record.stage, stage);
            assert!(record.diagnostic_only);
            assert!(!record.completion_marker);
            assert!(!record.resumable);
        }
    }

    #[test]
    fn independent_journal_auditor_rejects_mutated_headers_chain_and_bindings() {
        let (_directory, _path, configuration, request_digest, identities, _summary, bytes) =
            complete_journal_fixture();
        let original = decode_strict_journal_records(&bytes);
        let rejects = |records: Vec<StrictQualificationJournalRecord>| {
            let mutated = encode_strict_journal_records(&records);
            assert!(
                audit_qualification_journal(&mutated, request_digest, configuration, identities)
                    .is_err()
            );
        };

        let mut records = original.clone();
        records[2].sequence += 1;
        rejects(records);

        let mut records = original.clone();
        records[1].previous_record_digest = Digest32::new([0x90; 32]);
        rejects(records);

        let mut records = original.clone();
        records[1].run_identity = Digest32::new([0x91; 32]);
        rejects(records);

        let mut records = original.clone();
        records[1].request_digest = Digest32::new([0x92; 32]);
        rejects(records);

        let mut records = original.clone();
        records[1].stage = "record_validation_completed".into();
        rejects(records);

        let mut records = original.clone();
        records[0]
            .effective_configuration
            .as_mut()
            .unwrap()
            .maximum_native_block_rows += 1;
        rejects(records);

        let mut records = original.clone();
        records[4]
            .authenticated_identities
            .as_mut()
            .unwrap()
            .record_digest = Digest32::new([0x93; 32]);
        rejects(records);

        let mut records = original.clone();
        records[3].authenticated_identities = Some(identities);
        rejects(records);

        let mut records = original.clone();
        records[5].diagnostic_only = false;
        rejects(records);

        let mut records = original.clone();
        records[5].completion_marker = true;
        rejects(records);

        let mut records = original;
        records[5].resumable = true;
        rejects(records);
    }

    #[test]
    fn independent_journal_auditor_rejects_noncanonical_missing_unknown_and_suffix_bytes() {
        let (_directory, _path, configuration, request_digest, identities, _summary, bytes) =
            complete_journal_fixture();
        let assert_rejected = |mutated: &[u8]| {
            assert!(
                audit_qualification_journal(mutated, request_digest, configuration, identities)
                    .is_err()
            );
        };

        let mut missing_final_lf = bytes.clone();
        missing_final_lf.pop();
        assert_rejected(&missing_final_lf);

        let first_lf = bytes.iter().position(|byte| *byte == b'\n').unwrap();
        let journal_only_interruption = &bytes[..=first_lf];
        assert_rejected(journal_only_interruption);

        let mut suffix_record = bytes.clone();
        suffix_record.extend_from_slice(&bytes[..=first_lf]);
        assert_rejected(&suffix_record);

        let mut suffix_bytes = bytes.clone();
        suffix_bytes.extend_from_slice(b"suffix\n");
        assert_rejected(&suffix_bytes);

        let mut noncanonical = bytes.clone();
        noncanonical.insert(first_lf, b' ');
        assert_rejected(&noncanonical);

        let mut values = bytes[..bytes.len() - 1]
            .split(|byte| *byte == b'\n')
            .map(|record| serde_json::from_slice::<serde_json::Value>(record).unwrap())
            .collect::<Vec<_>>();
        values[0]
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(true));
        let mut unknown_field = serde_json::to_vec(&values[0]).unwrap();
        unknown_field.push(b'\n');
        for value in &values[1..] {
            unknown_field.extend_from_slice(&serde_json::to_vec(value).unwrap());
            unknown_field.push(b'\n');
        }
        assert_rejected(&unknown_field);

        values[0].as_object_mut().unwrap().remove("diagnostic_only");
        values[0].as_object_mut().unwrap().remove("unknown");
        let mut missing_field = serde_json::to_vec(&values[0]).unwrap();
        missing_field.push(b'\n');
        for value in &values[1..] {
            missing_field.extend_from_slice(&serde_json::to_vec(value).unwrap());
            missing_field.push(b'\n');
        }
        assert_rejected(&missing_field);
    }

    #[test]
    fn producer_report_summary_must_match_count_last_digest_length_and_complete_file_digest() {
        let (_directory, _path, configuration, request_digest, identities, summary, bytes) =
            complete_journal_fixture();
        let audited =
            audit_qualification_journal(&bytes, request_digest, configuration, identities).unwrap();

        let mut wrong = summary.clone();
        wrong.event_count -= 1;
        assert!(require_matching_journal_summary(&audited, &wrong).is_err());

        let mut wrong = summary.clone();
        wrong.final_record_digest = Digest32::new([0xa1; 32]);
        assert!(require_matching_journal_summary(&audited, &wrong).is_err());

        let mut wrong = summary.clone();
        wrong.journal_bytes += 1;
        assert!(require_matching_journal_summary(&audited, &wrong).is_err());

        let mut wrong = summary;
        wrong.complete_file_digest = Digest32::new([0xa2; 32]);
        assert!(require_matching_journal_summary(&audited, &wrong).is_err());
    }

    #[test]
    fn producer_report_loader_requires_strict_complete_canonical_json() {
        let (directory, _journal_path, _configuration, _request_digest, _identities, summary, _) =
            complete_journal_fixture();
        let (report, _request, _wire, _candidate, _payload) = producer_report_fixture(summary);
        let canonical_path = directory.0.join("canonical-producer-report.json");
        let mut canonical = serde_json::to_vec_pretty(&report).unwrap();
        canonical.push(b'\n');
        fs::write(&canonical_path, &canonical).unwrap();
        let (decoded, decoded_bytes) =
            load_canonical_qualification_report(&canonical_path).unwrap();
        assert_eq!(decoded, report);
        assert_eq!(decoded_bytes, canonical);

        let compact_path = directory.0.join("compact-producer-report.json");
        fs::write(&compact_path, serde_json::to_vec(&report).unwrap()).unwrap();
        assert!(matches!(
            load_canonical_qualification_report(&compact_path),
            Err(ProductionDoryV3QualificationError::NonCanonicalProducerReport)
        ));

        let mut value = serde_json::to_value(&report).unwrap();
        value["unknown"] = json!(true);
        let unknown_path = directory.0.join("unknown-producer-report.json");
        fs::write(&unknown_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert!(matches!(
            load_canonical_qualification_report(&unknown_path),
            Err(ProductionDoryV3QualificationError::Json(_))
        ));

        value.as_object_mut().unwrap().remove("unknown");
        value.as_object_mut().unwrap().remove("wire_bytes");
        let missing_path = directory.0.join("missing-producer-report.json");
        fs::write(&missing_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert!(matches!(
            load_canonical_qualification_report(&missing_path),
            Err(ProductionDoryV3QualificationError::Json(_))
        ));
    }

    #[test]
    fn producer_report_must_match_request_and_exact_proof_bytes() {
        let (_directory, _journal_path, _configuration, _request_digest, _identities, summary, _) =
            complete_journal_fixture();
        let (report, request, wire, candidate, payload) = producer_report_fixture(summary);
        validate_producer_report_request_and_proof(&report, &request, &wire, &candidate, &payload)
            .unwrap();

        let mut wrong = report.clone();
        wrong.wire_blake3_digest = Digest32::new([0xb1; 32]);
        assert!(
            validate_producer_report_request_and_proof(
                &wrong, &request, &wire, &candidate, &payload
            )
            .is_err()
        );

        let mut wrong = report.clone();
        wrong.request_digest = Digest32::new([0xb2; 32]);
        assert!(
            validate_producer_report_request_and_proof(
                &wrong, &request, &wire, &candidate, &payload
            )
            .is_err()
        );

        let mut wrong = report;
        wrong.padded_variables += 1;
        assert!(
            validate_producer_report_request_and_proof(
                &wrong, &request, &wire, &candidate, &payload
            )
            .is_err()
        );
    }

    #[test]
    fn fresh_verifier_accepts_only_v4_and_does_not_compare_sampled_to_exact_scratch() {
        let (_directory, _journal_path, _configuration, _request_digest, _identities, summary, _) =
            complete_journal_fixture();
        let (mut report, request, wire, candidate, payload) = producer_report_fixture(summary);

        report.sampled_peak_scratch_entries_observation = u64::MAX;
        report.sampled_peak_scratch_logical_bytes_observation = u64::MAX;
        validate_producer_report_request_and_proof(&report, &request, &wire, &candidate, &payload)
            .unwrap();

        report.report_version = 3;
        assert!(matches!(
            validate_producer_report_request_and_proof(
                &report, &request, &wire, &candidate, &payload
            ),
            Err(ProductionDoryV3QualificationError::EvidenceMismatch(
                "producer report qualification invariants"
            ))
        ));
    }

    #[test]
    fn producer_report_rejects_one_field_invariant_mutations() {
        let (_directory, _journal_path, _configuration, _request_digest, _identities, summary, _) =
            complete_journal_fixture();
        let (report, request, wire, candidate, payload) = producer_report_fixture(summary);
        let rejects = |mutated: ProductionDoryV3QualificationReport| {
            assert!(
                validate_producer_report_request_and_proof(
                    &mutated, &request, &wire, &candidate, &payload
                )
                .is_err()
            );
        };

        let mut mutated = report.clone();
        mutated.maximum_native_block_rows = 0;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.provisional_scratch_floor_bytes += 1;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.initial_available_scratch_bytes = mutated.provisional_scratch_floor_bytes - 1;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.candidate_required_free_scratch_bytes += 1;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.candidate_available_free_scratch_bytes =
            mutated.candidate_required_free_scratch_bytes - 1;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.provisional_available_memory_floor_bytes += 1;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.observed_available_memory_before_bytes =
            mutated.provisional_available_memory_floor_bytes - 1;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.native_resource_projection_complete = !mutated.native_resource_projection_complete;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.instrumented_scratch_file_creation_events = 0;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.instrumented_scratch_size_mutation_events = 0;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.exact_peak_instrumented_scratch_logical_bytes = 0;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.exact_peak_instrumented_scratch_live_entries = 0;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.exact_peak_instrumented_scratch_live_entries =
            mutated.instrumented_scratch_file_creation_events + 1;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.exact_peak_scratch_instrumented = false;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.sampled_peak_scratch_observation_scope.push('!');
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.exact_peak_scratch_scope.push('!');
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.whole_process_peak_rss_scope.push('!');
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.cooperative_cancellation_scope.push('!');
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.prepublication_qualification_nanoseconds -= 1;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.setup_nanoseconds = u64::MAX;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.whole_process_peak_rss_bytes = 0;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.qualification_journal.event_count -= 1;
        rejects(mutated);

        let mut mutated = report.clone();
        mutated.report_output_is_completion_marker = false;
        rejects(mutated);

        let mut mutated = report;
        mutated.parent_directory_sync_performed = !mutated.parent_directory_sync_performed;
        rejects(mutated);
    }

    #[test]
    fn strict_evidence_reader_rejects_hardlinks_and_symlinks() {
        let directory = TestDirectory::create();
        let original = directory.0.join("evidence.jsonl");
        fs::write(&original, b"evidence\n").unwrap();
        let hardlink = directory.0.join("hardlink.jsonl");
        fs::hard_link(&original, &hardlink).unwrap();
        assert!(matches!(
            read_bounded_strict_input(
                &original,
                64,
                ProductionDoryV3QualificationError::QualificationJournalTooLarge { max: 64 }
            ),
            Err(ProductionDoryV3QualificationError::InputHardLinks { links: 2, .. })
        ));
        fs::remove_file(&hardlink).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let mut retained = RetainedStrictInput::open(&original).unwrap();
            let exact = retained
                .read_bounded(
                    64,
                    ProductionDoryV3QualificationError::QualificationJournalTooLarge { max: 64 },
                )
                .unwrap();
            fs::remove_file(&original).unwrap();
            fs::write(&original, b"replacement\n").unwrap();
            assert!(matches!(
                retained.confirm_exact_bytes(&exact),
                Err(ProductionDoryV3QualificationError::InputReplaced(path))
                    if path == original
            ));

            let symlink_path = directory.0.join("symlink.jsonl");
            symlink(&original, &symlink_path).unwrap();
            assert!(
                read_bounded_strict_input(
                    &symlink_path,
                    64,
                    ProductionDoryV3QualificationError::QualificationJournalTooLarge { max: 64 }
                )
                .is_err()
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::symlink_file;

            let symlink_path = directory.0.join("symlink.jsonl");
            if symlink_file(&original, &symlink_path).is_ok() {
                assert!(RetainedStrictInput::open(&symlink_path).is_err());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn retained_strict_input_rejects_same_inode_content_mutation() {
        let directory = TestDirectory::create();
        let path = directory.0.join("stable.bin");
        fs::write(&path, b"original").unwrap();
        let mut input = RetainedStrictInput::open(&path).unwrap();
        let first = input.complete_content_identity().unwrap();
        fs::write(&path, b"mutated!").unwrap();
        let changed = input.confirm_content_identity(first);
        assert!(
            matches!(
                &changed,
                Err(ProductionDoryV3QualificationError::InputChanged(found)) if found == &path
            ),
            "unexpected retained-input result: {changed:?}"
        );
        assert_eq!(first.bytes, 8);
    }

    #[cfg(windows)]
    #[test]
    fn retained_strict_input_denies_concurrent_windows_writes() {
        let directory = TestDirectory::create();
        let path = directory.0.join("stable.bin");
        fs::write(&path, b"original").unwrap();
        let mut input = RetainedStrictInput::open(&path).unwrap();
        let first = input.complete_content_identity().unwrap();
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert_eq!(input.complete_content_identity().unwrap(), first);
    }

    #[cfg(windows)]
    #[test]
    fn qualification_preflight_rejects_windows_case_only_output_aliases() {
        let directory = TestDirectory::create();
        let scratch = directory.0.join("scratch");
        let proof = directory.0.join("Proof.cmfd");
        let report = directory.0.join("proof.CMFD");
        let journal = directory.0.join("journal.jsonl");
        assert!(matches!(
            QualificationPaths::preflight(&scratch, &proof, &report, &journal),
            Err(ProductionDoryV3QualificationError::Configuration(
                "proof, report, and journal outputs must be distinct"
            ))
        ));
    }

    #[test]
    fn qualification_outputs_are_create_new_synced_and_reopened() {
        let directory = TestDirectory::create();
        let proof = directory.0.join("proof.bin");
        let report = directory.0.join("report.json");
        write_verified_outputs(&proof, b"proof", &report, b"report\n").unwrap();
        assert_eq!(fs::read(&proof).unwrap(), b"proof");
        assert_eq!(fs::read(&report).unwrap(), b"report\n");
        assert!(matches!(
            write_verified_outputs(&proof, b"new", &directory.0.join("other"), b"new"),
            Err(ProductionDoryV3QualificationError::CreateOutput { .. })
        ));
        assert!(!directory.0.join("other").exists());

        let unconfirmed_proof = directory.0.join("unconfirmed.bin");
        assert!(matches!(
            write_verified_outputs(&unconfirmed_proof, b"new", &report, b"new"),
            Err(ProductionDoryV3QualificationError::CreateOutput { .. })
        ));
        assert!(!unconfirmed_proof.exists());

        let request = directory.0.join("request.json");
        write_verified_output(&request, b"request\n").unwrap();
        assert_eq!(fs::read(&request).unwrap(), b"request\n");
        assert!(matches!(
            write_verified_output(&request, b"replacement\n"),
            Err(ProductionDoryV3QualificationError::CreateOutput { .. })
        ));
    }

    #[test]
    fn retained_scratch_measurement_counts_files_and_directories() {
        let directory = TestDirectory::create();
        let nested = directory.0.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("artifact"), b"1234").unwrap();
        assert_eq!(measure_retained_scratch(&directory.0).unwrap(), (2, 4));
    }

    #[test]
    fn scratch_observer_reports_an_informational_non_atomic_observation() {
        let directory = TestDirectory::create();
        let mut observer = ScratchHighWaterObserver::start(directory.0.clone());
        fs::write(directory.0.join("artifact"), vec![0_u8; 4_096]).unwrap();
        thread::sleep(SCRATCH_SAMPLE_INTERVAL + SCRATCH_SAMPLE_INTERVAL);
        let sample = observer.stop().unwrap();
        assert!(sample.entries >= 1);
        assert!(sample.logical_bytes >= 4_096);
    }

    #[test]
    fn qualification_scratch_fixture_keeps_sampled_and_exact_metrics_independent() {
        let directory = TestDirectory::create();
        let scratch = directory.0.join("scratch-fixture");
        fs::create_dir(&scratch).unwrap();
        let mut exact = ExactScratchReservationSession::start(&scratch).unwrap();
        let mut observer = ScratchHighWaterObserver::start(scratch.clone());
        let mut file = crate::dory_scratch_telemetry::TrackedScratchFile::create_new(
            &scratch.join("artifact"),
        )
        .unwrap();
        file.set_len(4_096).unwrap();
        thread::sleep(SCRATCH_SAMPLE_INTERVAL + SCRATCH_SAMPLE_INTERVAL);
        let sampled = observer.stop().unwrap();
        file.remove_if_owned().unwrap();
        let exact = exact.finish_and_remove_root().unwrap();

        assert!(sampled.entries >= 1);
        assert!(sampled.logical_bytes >= 4_096);
        assert_eq!(exact.peak_live_entries, 1);
        assert_eq!(exact.peak_logical_bytes, 4_096);
        assert!(!scratch.exists());
    }

    #[test]
    fn whole_process_peak_rss_is_os_reported() {
        assert!(peak_whole_process_rss_bytes().unwrap() > 0);
    }

    #[test]
    fn cgroup_resource_floor_uses_tightest_ancestor_limit() {
        let directory = TestDirectory::create();
        let parent = directory.0.join("parent");
        let leaf = parent.join("leaf");
        fs::create_dir_all(&leaf).unwrap();
        for (path, limit, current) in [
            (&directory.0, "2000", "100"),
            (&parent, "900", "100"),
            (&leaf, "max", "700"),
        ] {
            fs::write(path.join("memory.max"), limit).unwrap();
            fs::write(path.join("memory.current"), current).unwrap();
        }
        assert_eq!(
            cgroup_ancestor_available_memory_bytes(
                &leaf,
                &directory.0,
                "memory.max",
                "memory.current"
            )
            .unwrap(),
            Some(800)
        );

        fs::write(leaf.join("memory.max"), "500").unwrap();
        fs::write(leaf.join("memory.current"), "200").unwrap();
        assert_eq!(
            cgroup_ancestor_available_memory_bytes(
                &leaf,
                &directory.0,
                "memory.max",
                "memory.current"
            )
            .unwrap(),
            Some(300)
        );
    }

    #[test]
    fn cp02_and_wire_helpers_accept_only_canonical_frames() {
        let network_id = [0x44; 32];
        let structured_proof = BlsDoryV3CandidatePayload {
            dory_proof: vec![1, 2, 3],
            native_blake3_proof: vec![4, 5, 6],
        }
        .encode()
        .unwrap();
        let candidate = ForgeMatrixV3CandidateProof {
            algorithm_version: 2,
            proof_version: 1,
            nonce: 7,
            model_manifest_digest: [8; 32],
            challenge_digest: [9; 32],
            final_activation_digest: [10; 32],
            work_digest: [11; 32],
            structured_proof,
        };
        let decoded_payload = validate_cp02(&candidate).unwrap();
        assert_eq!(decoded_payload.dory_proof, vec![1, 2, 3]);

        let wire = encode_forgematrix_proof(
            &BlockProof::V3Candidate(Box::new(candidate.clone())),
            network_id,
        )
        .unwrap();
        let decoded = decode_forgematrix_proof(&wire, network_id).unwrap();
        assert_eq!(
            encode_forgematrix_proof(&decoded, network_id).unwrap(),
            wire
        );
        assert_eq!(
            decoded,
            BlockProof::V3Candidate(Box::new(candidate.clone()))
        );

        let mut wrong_magic = candidate;
        wrong_magic.structured_proof[0] ^= 1;
        assert!(matches!(
            validate_cp02(&wrong_magic),
            Err(ProductionDoryV3QualificationError::NonCanonicalCp02)
        ));
    }

    #[test]
    fn verifier_wire_loader_accepts_only_canonical_v3_layout_v5() {
        let request = request();
        let candidate = verifier_candidate(&request, [8; 32]);
        let wire = encode_forgematrix_proof(
            &BlockProof::V3Candidate(Box::new(candidate.clone())),
            request.block.network_id,
        )
        .unwrap();
        let (decoded, payload) = decode_canonical_v3_layout_v5_wire(&wire, &request).unwrap();
        assert_eq!(decoded, candidate);
        require_layout_v5_header(&payload.dory_proof).unwrap();

        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(decode_canonical_v3_layout_v5_wire(&trailing, &request).is_err());

        let v2 = BlockProof::V2Reference(ForgeMatrixV2CompactProof {
            algorithm_version: 2,
            proof_version: 1,
            nonce: request.nonce,
            model_manifest_digest: [8; 32],
            challenge_digest: [9; 32],
            final_activation_digest: request.final_activation_digest.into_bytes(),
            work_digest: request.work_digest.into_bytes(),
        });
        let v2_wire = encode_forgematrix_proof(&v2, request.block.network_id).unwrap();
        assert!(matches!(
            decode_canonical_v3_layout_v5_wire(&v2_wire, &request),
            Err(ProductionDoryV3QualificationError::ExpectedV3Candidate)
        ));
    }

    #[test]
    fn verifier_wire_loader_rejects_layout_v4_and_wrong_bindings() {
        let request = request();
        let manifest_digest = Digest32::new([8; 32]);
        let candidate = verifier_candidate(&request, manifest_digest.into_bytes());
        validate_verifier_candidate_binding(&candidate, &request, manifest_digest).unwrap();

        let mut wrong_manifest = candidate.clone();
        wrong_manifest.model_manifest_digest[0] ^= 1;
        assert!(matches!(
            validate_verifier_candidate_binding(&wrong_manifest, &request, manifest_digest),
            Err(ProductionDoryV3QualificationError::Candidate(
                BlsDoryV3CandidateError::ModelManifestDigest
            ))
        ));

        let mut wrong_nonce = candidate.clone();
        wrong_nonce.nonce += 1;
        assert!(matches!(
            validate_candidate_request_binding(&wrong_nonce, &request),
            Err(ProductionDoryV3QualificationError::ProofRequestMismatch(
                "nonce"
            ))
        ));

        let mut payload = BlsDoryV3CandidatePayload::decode(&candidate.structured_proof).unwrap();
        payload.dory_proof[8..10].copy_from_slice(&4_u16.to_le_bytes());
        let mut v4 = candidate;
        v4.structured_proof = payload.encode().unwrap();
        let v4_wire = encode_forgematrix_proof(
            &BlockProof::V3Candidate(Box::new(v4)),
            request.block.network_id,
        )
        .unwrap();
        assert!(matches!(
            decode_canonical_v3_layout_v5_wire(&v4_wire, &request),
            Err(ProductionDoryV3QualificationError::ExpectedLayoutV5)
        ));
    }

    #[test]
    fn verifier_proof_reader_rejects_oversize_before_decoding() {
        let directory = TestDirectory::create();
        let proof = directory.0.join("oversize-proof.bin");
        fs::write(&proof, vec![0_u8; MAX_PROOF_BYTES + 1]).unwrap();
        assert!(matches!(
            read_bounded_proof_wire(&proof),
            Err(ProductionDoryV3QualificationError::ProofWireTooLarge {
                max: MAX_PROOF_BYTES
            })
        ));
    }

    #[test]
    fn verifier_json_loaders_reject_oversize_before_parsing() {
        let directory = TestDirectory::create();
        let request_path = directory.0.join("oversize-request.json");
        fs::write(
            &request_path,
            vec![b' '; MAX_QUALIFICATION_REQUEST_JSON_BYTES + 1],
        )
        .unwrap();
        assert!(matches!(
            load_bounded_qualification_request(&request_path),
            Err(
                ProductionDoryV3QualificationError::QualificationRequestJsonTooLarge {
                    max: MAX_QUALIFICATION_REQUEST_JSON_BYTES
                }
            )
        ));

        let record_path = directory.0.join("oversize-record-v2.json");
        let oversized_record = serde_json::to_vec(&json!({
            "model_identity": {
                "weight_bank_commitments": ["a".repeat(MAX_RECORD_V2_JSON_BYTES)]
            }
        }))
        .unwrap();
        assert!(oversized_record.len() > MAX_RECORD_V2_JSON_BYTES);
        fs::write(&record_path, oversized_record).unwrap();
        assert!(matches!(
            load_bounded_record_v2(&record_path),
            Err(ProductionDoryV3QualificationError::RecordV2JsonTooLarge {
                max: MAX_RECORD_V2_JSON_BYTES
            })
        ));

        let report_path = directory.0.join("oversize-producer-report.json");
        fs::write(
            &report_path,
            vec![b' '; MAX_QUALIFICATION_REPORT_JSON_BYTES + 1],
        )
        .unwrap();
        assert!(matches!(
            load_canonical_qualification_report(&report_path),
            Err(
                ProductionDoryV3QualificationError::QualificationReportJsonTooLarge {
                    max: MAX_QUALIFICATION_REPORT_JSON_BYTES
                }
            )
        ));

        let journal_path = directory.0.join("oversize-journal.jsonl");
        fs::write(
            &journal_path,
            vec![b' '; MAX_QUALIFICATION_JOURNAL_BYTES + 1],
        )
        .unwrap();
        assert!(matches!(
            read_bounded_strict_input(
                &journal_path,
                MAX_QUALIFICATION_JOURNAL_BYTES,
                ProductionDoryV3QualificationError::QualificationJournalTooLarge {
                    max: MAX_QUALIFICATION_JOURNAL_BYTES
                }
            ),
            Err(
                ProductionDoryV3QualificationError::QualificationJournalTooLarge {
                    max: MAX_QUALIFICATION_JOURNAL_BYTES
                }
            )
        ));
    }

    #[test]
    fn verifier_rejects_wrong_request_before_record_or_bank_authentication() {
        let directory = TestDirectory::create();
        let original_request = request();
        let candidate = verifier_candidate(&original_request, [8; 32]);
        let proof_path = directory.0.join("proof.cmfd");
        fs::write(
            &proof_path,
            encode_forgematrix_proof(
                &BlockProof::V3Candidate(Box::new(candidate)),
                original_request.block.network_id,
            )
            .unwrap(),
        )
        .unwrap();

        let mut wrong_request = original_request;
        wrong_request.nonce += 1;
        let request_path = directory.0.join("wrong-request.json");
        let report_path = directory.0.join("fresh-verifier-report.json");
        fs::write(&request_path, serde_json::to_vec(&wrong_request).unwrap()).unwrap();
        let error = run_production_dory_v3_verifier(
            &directory.0.join("unused-bank.cmfdmb02"),
            &directory.0.join("unused-record-v2.json"),
            &request_path,
            &proof_path,
            &directory.0.join("unused-producer-report.json"),
            &directory.0.join("unused-journal.jsonl"),
            &report_path,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ProductionDoryV3QualificationError::ProofRequestMismatch("nonce")
        ));
        assert!(!report_path.exists());
    }

    #[test]
    fn fresh_verifier_rejects_journal_only_interruption_before_bank_authentication() {
        let (
            directory,
            _journal_path,
            _configuration,
            _request_digest,
            _identities,
            summary,
            bytes,
        ) = complete_journal_fixture();
        let (report, request, wire, _candidate, _payload) = producer_report_fixture(summary);
        let request_path = directory.0.join("qualification-request.json");
        let proof_path = directory.0.join("proof.cmfd");
        let producer_report_path = directory.0.join("producer-report.json");
        let interrupted_journal_path = directory.0.join("interrupted-journal.jsonl");
        let verifier_report_path = directory.0.join("fresh-verifier-report.json");
        let first_lf = bytes.iter().position(|byte| *byte == b'\n').unwrap();
        fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
        fs::write(&proof_path, wire).unwrap();
        let mut producer_report_bytes = serde_json::to_vec_pretty(&report).unwrap();
        producer_report_bytes.push(b'\n');
        fs::write(&producer_report_path, producer_report_bytes).unwrap();
        fs::write(&interrupted_journal_path, &bytes[..=first_lf]).unwrap();

        let error = run_production_dory_v3_verifier(
            &directory.0.join("unused-bank.cmfdmb02"),
            &directory.0.join("unused-record-v2.json"),
            &request_path,
            &proof_path,
            &producer_report_path,
            &interrupted_journal_path,
            &verifier_report_path,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ProductionDoryV3QualificationError::InvalidJournal(
                "journal event count or stage sequence length is wrong"
            )
        ));
        assert!(!verifier_report_path.exists());
    }

    #[test]
    fn verifier_record_loader_rejects_wrong_document_type() {
        let directory = TestDirectory::create();
        let record_path = directory.0.join("wrong-record-v2.json");
        fs::write(&record_path, serde_json::to_vec(&request()).unwrap()).unwrap();
        assert!(matches!(
            load_bounded_record_v2(&record_path),
            Err(ProductionDoryV3QualificationError::Json(_))
        ));
    }

    #[test]
    fn verifier_rejects_nonproduction_record_identity() {
        let directory = TestDirectory::create();
        let fixture = small_bank_fixture();
        let authenticated = derive_bank_authenticated_dory_v3_model_commitment_record_v2_for_test(
            Cursor::new(&fixture.bytes),
            &fixture.manifest,
            &fixture.identity,
            &fixture.setup,
        )
        .unwrap();
        let record_path = directory.0.join("wrong-production-record-v2.json");
        fs::write(
            &record_path,
            serde_json::to_vec(authenticated.record()).unwrap(),
        )
        .unwrap();
        let loaded = load_bounded_record_v2(&record_path).unwrap();
        assert!(matches!(
            validate_verifier_record_static_identity(&loaded),
            Err(ProductionDoryV3QualificationError::ModelIdentity(
                DoryV3ModelIdentityError::ProductionGeometry
            ))
        ));
    }

    #[test]
    fn verifier_bank_authentication_rejects_changed_bytes() {
        let fixture = small_bank_fixture();
        let _authenticated = derive_bank_authenticated_dory_v3_model_commitment_record_v2_for_test(
            Cursor::new(&fixture.bytes),
            &fixture.manifest,
            &fixture.identity,
            &fixture.setup,
        )
        .unwrap();

        let mut changed_bank = fixture.bytes.clone();
        *changed_bank.last_mut().unwrap() ^= 1;
        assert!(
            derive_bank_authenticated_dory_v3_model_commitment_record_v2_for_test(
                Cursor::new(changed_bank),
                &fixture.manifest,
                &fixture.identity,
                &fixture.setup,
            )
            .is_err()
        );
    }

    #[test]
    fn verifier_layout_v5_decoder_rejects_mutated_inner_frame() {
        let (context, proof) = bls_dory_shared_layout_v5_candidate_codec_fixture_for_test(0x71);
        let shape = StructuredForgeMatrixResearchShape::production_candidate();
        let transition_statements = [
            shape.initialization_statement,
            shape.transition_statements[0],
            shape.transition_statements[1],
            shape.transition_statements[2],
        ];
        let encoded = proof
            .encode(
                &shape.matrix_statements,
                &transition_statements,
                shape.wiring_statement,
            )
            .unwrap();
        let payload = BlsDoryV3CandidatePayload {
            dory_proof: encoded.clone(),
            native_blake3_proof: vec![1],
        }
        .encode()
        .unwrap();
        let (_decoded, _decoded_payload) =
            decode_dory_v3_layout_v5_candidate_payload(&payload, &context).unwrap();

        let mut mutated = encoded;
        mutated[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        let mutated_payload = BlsDoryV3CandidatePayload {
            dory_proof: mutated,
            native_blake3_proof: vec![1],
        }
        .encode()
        .unwrap();
        assert!(decode_dory_v3_layout_v5_candidate_payload(&mutated_payload, &context).is_err());
    }
}
