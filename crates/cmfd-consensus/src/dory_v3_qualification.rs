//! Fail-closed orchestration for one unchanged production Dory V3 qualification run.
//!
//! This module is deliberately dormant and feature-gated. It does not activate
//! V3 consensus. It joins the already-reviewed opaque capabilities into one
//! operator entry point that can measure an exact n=33 run without exposing a
//! second, configurable proof construction path.
//! The report is written second and is the graceful-completion marker. The two
//! separate output paths cannot be made crash-atomic as one filesystem commit.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
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
    BlockChallenge, BlockProof, ForgeMatrixV3CandidateProof,
    dory_bls12_381_aggregate::BLS_DORY_COMPOSED_AGGREGATE_CLAIMS,
    dory_bls12_381_blake3::{
        BlsDoryBlake3ProductionPreflightError, projected_bls_dory_blake3_production_resources,
    },
    dory_bls12_381_candidate::{
        BlsDoryV3CandidateError, BlsDoryV3CandidatePayload, CANDIDATE_PAYLOAD_HEADER_BYTES,
        CANDIDATE_PAYLOAD_MAGIC, preflight_candidate_scratch,
        verify_bls_dory_v3_layout_v5_candidate,
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
        BLS_DORY_SHARED_PRODUCTION_VARIABLES,
        prepare_bls_dory_v3_fixed_model_from_bank_authenticated_record_with_scratch,
    },
    dory_bls12_381_prototype::{BlsDoryPrototypeError, deterministic_bls_dory_setup},
    dory_scratch_telemetry::ExactScratchReservationSession,
    dory_v3_model::DoryV3ModelIdentityError,
    dory_v3_model_record::{
        DoryV3ModelCommitmentRecordError, DoryV3ModelCommitmentRecordV2,
        derive_bank_authenticated_dory_v3_model_commitment_record_v2,
    },
    dory_v3_suite::{DORY_V3_PADDED_VARIABLES, Digest32},
    dory_v3_transcript::DoryV3TranscriptContext,
    wire::{WireError, decode_forgematrix_proof, encode_forgematrix_proof},
};

const QUALIFICATION_REPORT_VERSION: u16 = 2;
const QUALIFICATION_REQUEST_GENERATION_REPORT_VERSION: u16 = 1;
const SCRATCH_SAMPLE_INTERVAL: Duration = Duration::from_millis(100);
const QUALIFICATION_REQUEST_DIGEST_DOMAIN: &str = "CMFD/FORGEMATRIX/V3/QUALIFICATION-REQUEST/V1";

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
/// sampled scratch fields remain a whole-directory lower bound. The exact
/// reservation fields account for declared final logical-byte reservations
/// across the six instrumented Dory artifact writer classes used by this
/// runner. They do not establish an exact whole-directory peak and are not
/// physical disk allocation, filesystem metadata, or RAM measurements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
    pub sampled_peak_scratch_entries_lower_bound: u64,
    pub sampled_peak_scratch_logical_bytes_lower_bound: u64,
    pub scratch_sample_interval_milliseconds: u64,
    pub exact_peak_instrumented_scratch_reserved_logical_bytes: u64,
    pub exact_peak_instrumented_scratch_live_artifacts: u64,
    pub instrumented_scratch_reservation_events: u64,
    pub exact_peak_scratch_instrumented: bool,
    pub exact_reservation_peak_instrumented: bool,
    pub exact_reservation_peak_scope: &'static str,
    pub retained_scratch_entries: u64,
    pub retained_scratch_logical_bytes: u64,
    pub whole_process_peak_rss_bytes: u64,
    pub whole_process_peak_rss_scope: &'static str,
    pub cooperative_cancellation_scope: &'static str,
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
    #[error("qualification duration overflowed its u64 nanosecond field")]
    DurationOverflow,
    #[error("qualification size overflowed its u64 byte field")]
    SizeOverflow,
    #[error("scratch high-water observer thread panicked")]
    ScratchObserverPanicked,
    #[error("exact scratch reservation instrumentation failed: {0}")]
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
    maximum_native_block_rows: usize,
    cancel: &AtomicBool,
) -> Result<ProductionDoryV3QualificationReport, ProductionDoryV3QualificationError> {
    let qualification_started = Instant::now();
    if cancel.load(Ordering::Relaxed) {
        return Err(ProductionDoryV3QualificationError::Cancelled);
    }
    if maximum_native_block_rows == 0 {
        return Err(ProductionDoryV3QualificationError::Configuration(
            "maximum_native_block_rows must be nonzero",
        ));
    }
    let paths = QualificationPaths::preflight(scratch_path, proof_output, report_output)?;

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

    let mut scratch = OwnedScratchDirectory::create(paths.scratch.clone())?;
    let mut exact_scratch = ExactScratchReservationSession::start(scratch.path())
        .map_err(ProductionDoryV3QualificationError::ScratchInstrumentation)?;
    let mut scratch_observer = ScratchHighWaterObserver::start(scratch.path().to_path_buf());

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
    check_cancel(cancel)?;

    let candidate_resource_started = Instant::now();
    let (candidate_required_free_scratch_bytes, candidate_available_free_scratch_bytes) =
        preflight_candidate_scratch(scratch.path())?;
    let candidate_resource_preflight_nanoseconds = elapsed_nanoseconds(candidate_resource_started)?;
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
    check_cancel(cancel)?;

    let scratch_cleanup_started = Instant::now();
    drop(prepared_model);
    let scratch_high_water = scratch_observer.stop()?;
    let (retained_scratch_entries, retained_scratch_logical_bytes) = scratch.measure_retained()?;
    if retained_scratch_entries != 0 || retained_scratch_logical_bytes != 0 {
        return Err(ProductionDoryV3QualificationError::RetainedScratch {
            entries: retained_scratch_entries,
            logical_bytes: retained_scratch_logical_bytes,
        });
    }
    let exact_scratch_reservations = exact_scratch
        .finish()
        .map_err(ProductionDoryV3QualificationError::ScratchInstrumentation)?;
    if exact_scratch_reservations.reservation_events == 0
        || scratch_high_water.entries > exact_scratch_reservations.peak_live_artifacts
        || scratch_high_water.logical_bytes > exact_scratch_reservations.peak_reserved_logical_bytes
    {
        return Err(ProductionDoryV3QualificationError::ScratchInstrumentation(
            io::Error::other(
                "scratch reservation instrumentation was empty or its peak was below a sampled scratch observation",
            ),
        ));
    }
    scratch.remove_empty()?;
    let scratch_cleanup_nanoseconds = elapsed_nanoseconds(scratch_cleanup_started)?;
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
    check_cancel(cancel)?;
    let whole_process_peak_rss_bytes =
        peak_whole_process_rss_bytes().map_err(ProductionDoryV3QualificationError::MemoryQuery)?;

    let report = ProductionDoryV3QualificationReport {
        report_version: QUALIFICATION_REPORT_VERSION,
        padded_variables: DORY_V3_PADDED_VARIABLES,
        composed_claims: u16::try_from(BLS_DORY_COMPOSED_AGGREGATE_CLAIMS)
            .map_err(|_| ProductionDoryV3QualificationError::SizeOverflow)?,
        verifier_passes: 2,
        maximum_native_block_rows: u64::try_from(maximum_native_block_rows)
            .map_err(|_| ProductionDoryV3QualificationError::SizeOverflow)?,
        network_id: Digest32::new(request.block.network_id),
        block_height: request.block.height,
        nonce: request.nonce,
        request_digest: qualification_request_digest(request),
        record_digest: audit_record.record_digest(),
        model_identity_digest: audit_record.model_identity_digest(),
        setup_identity: audit_record.setup_identity(),
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
        sampled_peak_scratch_entries_lower_bound: scratch_high_water.entries,
        sampled_peak_scratch_logical_bytes_lower_bound: scratch_high_water.logical_bytes,
        scratch_sample_interval_milliseconds: u64::try_from(SCRATCH_SAMPLE_INTERVAL.as_millis())
            .map_err(|_| ProductionDoryV3QualificationError::DurationOverflow)?,
        exact_peak_instrumented_scratch_reserved_logical_bytes: exact_scratch_reservations
            .peak_reserved_logical_bytes,
        exact_peak_instrumented_scratch_live_artifacts: exact_scratch_reservations
            .peak_live_artifacts,
        instrumented_scratch_reservation_events: exact_scratch_reservations.reservation_events,
        exact_peak_scratch_instrumented: false,
        exact_reservation_peak_instrumented: true,
        exact_reservation_peak_scope: "exact high-water mark of declared final logical-byte reservations for the six instrumented Dory scratch artifact writer classes used by this runner; the sampled comparison is only a consistency check and does not prove an exact whole-directory peak or exclude uninstrumented transient files; excludes filesystem allocation granularity, metadata, physical bytes, and RAM",
        retained_scratch_entries,
        retained_scratch_logical_bytes,
        whole_process_peak_rss_bytes,
        whole_process_peak_rss_scope: "OS process-lifetime high-water mark; run the CLI in a fresh process for qualification",
        cooperative_cancellation_scope: "the CLI maps Ctrl-C to the supplied flag; winning-claim replay polls it, other long stages observe it only after returning to a runner boundary",
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
        if request_output.starts_with(scratch) {
            return Err(ProductionDoryV3QualificationError::Configuration(
                "request output must not be inside runner-owned scratch",
            ));
        }
        let scratch = resolve_new_path(scratch)?;
        let request_output = resolve_new_path(request_output)?;
        if request_output.starts_with(&scratch) {
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
    ) -> Result<Self, ProductionDoryV3QualificationError> {
        if !scratch.is_absolute() {
            return Err(ProductionDoryV3QualificationError::Configuration(
                "scratch path must be absolute",
            ));
        }
        let scratch = resolve_new_path(scratch)?;
        let proof_output = resolve_new_path(proof_output)?;
        let report_output = resolve_new_path(report_output)?;
        if proof_output == report_output {
            return Err(ProductionDoryV3QualificationError::Configuration(
                "proof and report outputs must be distinct",
            ));
        }
        if proof_output.starts_with(&scratch) || report_output.starts_with(&scratch) {
            return Err(ProductionDoryV3QualificationError::Configuration(
                "outputs must not be inside runner-owned scratch",
            ));
        }
        ensure_path_absent(&scratch)?;
        ensure_path_absent(&proof_output)?;
        ensure_path_absent(&report_output)?;
        Ok(Self {
            scratch,
            proof_output,
            report_output,
        })
    }
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
                let sample = sample_scratch_lower_bound(&path)?;
                peak.entries = peak.entries.max(sample.entries);
                peak.logical_bytes = peak.logical_bytes.max(sample.logical_bytes);
                thread::sleep(SCRATCH_SAMPLE_INTERVAL);
            }
            let sample = sample_scratch_lower_bound(&path)?;
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

fn sample_scratch_lower_bound(root: &Path) -> io::Result<ScratchHighWaterSample> {
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
            "request output must have a parent directory",
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
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::json;

    use super::*;

    static TEST_DIRECTORY_NONCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

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
        let paths = QualificationPaths::preflight(&scratch, &proof, &report).unwrap();
        assert_eq!(paths.scratch, scratch);

        assert!(matches!(
            QualificationPaths::preflight(Path::new("relative"), &proof, &report),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));
        assert!(matches!(
            QualificationPaths::preflight(&scratch, &proof, &proof),
            Err(ProductionDoryV3QualificationError::Configuration(_))
        ));

        fs::create_dir(&scratch).unwrap();
        assert!(matches!(
            QualificationPaths::preflight(&scratch, &proof, &report),
            Err(ProductionDoryV3QualificationError::PathExists(path)) if path == scratch
        ));
        fs::remove_dir(&scratch).unwrap();

        fs::write(&proof, b"existing").unwrap();
        assert!(matches!(
            QualificationPaths::preflight(&scratch, &proof, &report),
            Err(ProductionDoryV3QualificationError::PathExists(path)) if path == proof
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
    fn scratch_observer_reports_only_a_sampled_lower_bound() {
        let directory = TestDirectory::create();
        let mut observer = ScratchHighWaterObserver::start(directory.0.clone());
        fs::write(directory.0.join("artifact"), vec![0_u8; 4_096]).unwrap();
        thread::sleep(SCRATCH_SAMPLE_INTERVAL + SCRATCH_SAMPLE_INTERVAL);
        let sample = observer.stop().unwrap();
        assert!(sample.entries >= 1);
        assert!(sample.logical_bytes >= 4_096);
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
}
