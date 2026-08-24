//! Retained plan-to-Type-6 orchestration for production Dory V3 final receipts.
//!
//! The loader boundary authenticates only the strict JSON plan and its exact,
//! independently anchored reveal-set-closed prefix; plan path claims never
//! become content or candidate authority. The higher-level prepare and stage
//! APIs then route those paths through the existing combined-payload, CMFDRP,
//! CMFDIL, final-candidate, and keyless Type-6 validators while retaining every
//! resulting capability through the final create-new output guard.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    dory_v3_model_ceremony_authoring::{
        PreparedProductionDoryV3FinalReceipt, ProductionDoryV3CeremonyAuthoringError,
        ProductionDoryV3CeremonyRecordStageDurability, ProductionDoryV3FinalReceiptStageReport,
        RequiredCeremonySigner, prepare_production_dory_v3_final_receipt,
        stage_production_dory_v3_final_receipt_with_retained_input_guard,
    },
    dory_v3_model_ceremony_fs::{
        AuthenticatedInput, CeremonyFsError, FileIdentity as CeremonyFilesystemIdentity,
        TrustedCeremonyParent,
    },
    dory_v3_model_ceremony_transcript::{
        CeremonyTranscriptError, FileIdentity, MAX_CEREMONY_TRANSCRIPT_BYTES, RecordSignature,
        VerifiedCeremonyTranscript, parse_and_verify_reveal_set_prefix,
    },
    dory_v3_model_combiner::{
        ProductionDoryV3ModelCombinerError,
        validate_existing_production_dory_v3_model_combined_payload,
    },
    dory_v3_model_final_candidate_validation::{
        ProductionDoryV3ModelFinalCandidatePaths,
        ProductionDoryV3ModelFinalCandidateValidationError,
        ProductionDoryV3ModelReproducerCandidatePaths,
        ValidatedProductionDoryV3ModelFinalCandidate, VerifiedProductionDoryV3ReproducerLineages,
        validate_existing_production_dory_v3_model_final_candidate,
    },
    dory_v3_model_independent_lineage::{
        ProductionDoryV3IndependentLineageError, ProductionDoryV3IndependentLineageEvidencePaths,
        validate_existing_production_dory_v3_independent_lineage,
    },
    dory_v3_model_reproduction::{
        PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES,
        ProductionDoryV3ModelReproductionReportError,
        ProductionDoryV3ReproductionImplementationKind,
        verify_production_dory_v3_model_reproduction_report,
    },
};

pub const PRODUCTION_DORY_V3_FINAL_RECEIPT_PLAN_MAX_BYTES: usize = 256 * 1024;

// Every authenticated artifact retains both its file and trusted-parent
// handles. The fixed set is plan + prefix + eight shared candidate artifacts
// + the bank chain's three independently retained artifacts. Contributions,
// reproducer bundles, and Independent lineages add the remaining terms.
const FIXED_RETAINED_HANDLES: usize = 2 * (2 + 8 + 3);
const RETAINED_HANDLES_PER_CONTRIBUTION: usize = 2;
const RETAINED_HANDLES_PER_REPRODUCER: usize = 2 * 9;
const RETAINED_HANDLES_PER_INDEPENDENT_LINEAGE: usize = 2 * 12;
// Leave room for the process runtime and the create-new/reopen staging path.
const OPEN_FILE_DESCRIPTOR_RESERVE: usize = 64;
// Production operators use one explicit, reviewable floor. This also covers
// transient combiner handles and process descriptors that are not part of the
// retained-capability count above.
const MINIMUM_OPEN_FILE_DESCRIPTOR_SOFT_LIMIT: usize = 1024;

#[derive(Debug, Deserialize)]
#[serde(tag = "plan_type", content = "artifacts", deny_unknown_fields)]
enum ProductionDoryV3FinalReceiptOrchestrationPlan {
    #[serde(rename = "production_dory_v3_final_receipt_v1")]
    V1(ProductionDoryV3FinalReceiptArtifactsV1),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionDoryV3FinalReceiptArtifactsV1 {
    reveal_set_prefix: PathBuf,
    ordered_contributions: Vec<PathBuf>,
    shared_candidate: SharedCandidatePaths,
    ordered_reproducers: Vec<ReproducerCandidatePaths>,
    // Dense order corresponding to the filtered Independent report order that
    // later semantic validation derives; no kind or index claim lives here.
    ordered_independent_evidence: Vec<IndependentEvidencePaths>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedCandidatePaths {
    source_bundle: PathBuf,
    source_bundle_policy: PathBuf,
    raw_payload: PathBuf,
    roots_file: PathBuf,
    structural_report: PathBuf,
    bank_file: PathBuf,
    manifest_file: PathBuf,
    record_v2_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReproducerCandidatePaths {
    reproduction_report: PathBuf,
    combiner_binary: PathBuf,
    combiner_report: PathBuf,
    bootstrap_report: PathBuf,
    record_ceremony_report: PathBuf,
    host_environment_report: PathBuf,
    source_extraction_report: PathBuf,
    command_log: PathBuf,
    implementation_lineage_report: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndependentEvidencePaths {
    // The corresponding reproducer bundle supplies the lineage artifact,
    // combiner binary, host report, extraction report, and command log later.
    combiner_source_bundle: PathBuf,
    combiner_build_provenance: PathBuf,
    roots_calculator_source_bundle: PathBuf,
    roots_calculator_build_provenance: PathBuf,
    roots_calculator_binary: PathBuf,
    independent_lineage_review_report: PathBuf,
    conformance_test_report: PathBuf,
}

/// Opaque retained routing input for later final-receipt orchestration.
///
/// This value authenticates the exact plan bytes and anchored type-5 prefix
/// only. It does not authenticate any artifact merely named by the plan, does
/// not validate a final candidate, and cannot authorize a type-6 receipt.
#[must_use]
pub struct RetainedProductionDoryV3FinalReceiptOrchestrationInputs {
    plan: RetainedAuthenticatedSmallFile,
    reveal_set_prefix: RetainedAuthenticatedSmallFile,
    transcript: VerifiedCeremonyTranscript,
    _artifacts: ProductionDoryV3FinalReceiptArtifactsV1,
}

/// Opaque keyless Type-6 signing request whose strict plan, anchored type-5
/// prefix, final candidate, and Independent lineage evidence all remain live.
///
/// This capability is deliberately non-cloneable and non-serializable. It
/// exposes only public signing material and can be consumed only by the
/// guarded Type-6 staging entry point below.
#[must_use]
pub struct PreparedProductionDoryV3FinalReceiptOrchestration {
    inputs: RetainedProductionDoryV3FinalReceiptOrchestrationInputs,
    prepared: PreparedProductionDoryV3FinalReceipt,
}

impl PreparedProductionDoryV3FinalReceiptOrchestration {
    pub fn plan_path(&self) -> &Path {
        self.inputs.plan_path()
    }

    pub const fn plan_file(&self) -> &FileIdentity {
        self.inputs.plan_file()
    }

    pub fn reveal_set_prefix_path(&self) -> &Path {
        self.inputs.reveal_set_prefix_path()
    }

    pub const fn reveal_set_prefix_file(&self) -> &FileIdentity {
        self.inputs.reveal_set_prefix_file()
    }

    pub const fn ceremony_id(&self) -> [u8; 32] {
        self.prepared.ceremony_id()
    }

    pub const fn transcript_derive_key_digest(&self) -> [u8; 32] {
        self.inputs.transcript.transcript_derive_key_digest()
    }

    pub const fn record_content_digest(&self) -> [u8; 32] {
        self.prepared.record_content_digest()
    }

    pub const fn signature_message(&self) -> [u8; 32] {
        self.prepared.signature_message()
    }

    pub fn required_signers(&self) -> &[RequiredCeremonySigner] {
        self.prepared.required_signers()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3FinalReceiptOrchestrationStageReport {
    plan_path: PathBuf,
    plan_file: FileIdentity,
    reveal_set_prefix_path: PathBuf,
    reveal_set_prefix_file: FileIdentity,
    ceremony_id: [u8; 32],
    staged: ProductionDoryV3FinalReceiptStageReport,
}

impl ProductionDoryV3FinalReceiptOrchestrationStageReport {
    pub fn plan_path(&self) -> &Path {
        &self.plan_path
    }

    pub const fn plan_file(&self) -> &FileIdentity {
        &self.plan_file
    }

    pub fn reveal_set_prefix_path(&self) -> &Path {
        &self.reveal_set_prefix_path
    }

    pub const fn reveal_set_prefix_file(&self) -> &FileIdentity {
        &self.reveal_set_prefix_file
    }

    pub const fn ceremony_id(&self) -> [u8; 32] {
        self.ceremony_id
    }

    pub fn output(&self) -> &Path {
        self.staged.output()
    }

    pub const fn record_file(&self) -> &FileIdentity {
        self.staged.record_file()
    }

    pub const fn record_content_digest(&self) -> [u8; 32] {
        self.staged.record_content_digest()
    }

    pub const fn signed_record_digest(&self) -> [u8; 32] {
        self.staged.signed_record_digest()
    }

    pub const fn signature_message(&self) -> [u8; 32] {
        self.staged.signature_message()
    }

    pub const fn signer_count(&self) -> u16 {
        self.staged.signer_count()
    }

    pub const fn durability(&self) -> ProductionDoryV3CeremonyRecordStageDurability {
        self.staged.durability()
    }

    pub const fn publication_pending(&self) -> bool {
        self.staged.publication_pending()
    }
}

impl RetainedProductionDoryV3FinalReceiptOrchestrationInputs {
    pub fn plan_path(&self) -> &Path {
        &self.plan.path
    }

    pub const fn plan_file(&self) -> &FileIdentity {
        &self.plan.content_identity
    }

    pub fn reveal_set_prefix_path(&self) -> &Path {
        &self.reveal_set_prefix.path
    }

    pub const fn reveal_set_prefix_file(&self) -> &FileIdentity {
        &self.reveal_set_prefix.content_identity
    }

    pub const fn ceremony_id(&self) -> [u8; 32] {
        self.transcript.ceremony_id()
    }

    pub fn operator_count(&self) -> usize {
        self.transcript.operators().len()
    }

    pub fn reproducer_count(&self) -> usize {
        self.transcript.reproducers().len()
    }

    /// Reauthenticate both retained inputs against their original exact bytes.
    /// Later orchestration must call this inside its final output guard before
    /// the final-candidate capability performs its bank-last recheck.
    pub fn reauthenticate_retained_inputs(
        &mut self,
    ) -> Result<(), ProductionDoryV3FinalReceiptOrchestrationError> {
        self.plan.reauthenticate_exact()?;
        self.reveal_set_prefix.reauthenticate_exact()?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ProductionDoryV3FinalReceiptOrchestrationError {
    #[error("trusted ceremony filesystem rejected an orchestration input: {0}")]
    Filesystem(String),
    #[error("strict final-receipt orchestration plan JSON is invalid: {0}")]
    PlanJson(#[from] serde_json::Error),
    #[error("anchored reveal-set prefix verification failed: {0}")]
    Transcript(#[from] CeremonyTranscriptError),
    #[error("trusted orchestration input exceeds its size cap: {0}")]
    InputTooLarge(PathBuf),
    #[error("trusted orchestration input changed during authentication: {0}")]
    InputChanged(PathBuf),
    #[error("orchestration paths for {first} and {second} must be distinct")]
    DuplicatePath { first: String, second: String },
    #[error("the plan and reveal-set prefix resolve to the same retained file")]
    DuplicateRetainedInput,
    #[error("expected exactly {expected} ordered contribution paths, observed {actual}")]
    ContributionCount { expected: usize, actual: usize },
    #[error("expected exactly {expected} ordered reproducer path bundles, observed {actual}")]
    ReproducerCount { expected: usize, actual: usize },
    #[error(
        "expected between one and {maximum} ordered independent-evidence bundles, observed {actual}"
    )]
    IndependentEvidenceCount { maximum: usize, actual: usize },
    #[error("declared artifacts for {first} and {second} resolve to the same retained file")]
    AliasedArtifacts { first: String, second: String },
    #[error("no validated retained capability covers declared artifact {0}")]
    MissingRetainedArtifact(String),
    #[error("validated capabilities disagree on the retained filesystem identity for {0}")]
    RetainedArtifactIdentityMismatch(String),
    #[error("a validated capability retained an artifact absent from the strict plan: {0}")]
    UnexpectedRetainedArtifact(PathBuf),
    #[error(
        "reproduction report {index} has {actual} bytes; expected exactly {expected} canonical bytes"
    )]
    ReproductionReportLength {
        index: usize,
        expected: usize,
        actual: usize,
    },
    #[error("reproduction report {index} changed between authenticated reads")]
    ReproductionReportChanged { index: usize },
    #[error("reproduction report {index} failed context verification: {source}")]
    ReproductionReport {
        index: usize,
        #[source]
        source: ProductionDoryV3ModelReproductionReportError,
    },
    #[error("reproduction report at ordered position {position} declares index {actual}")]
    ReproducerOrder { position: usize, actual: u16 },
    #[error(
        "verified reports require exactly {expected} Independent evidence bundles, observed {actual}"
    )]
    ExactIndependentEvidenceCount { expected: usize, actual: usize },
    #[error("Independent lineage validation failed for reproducer {index}: {source}")]
    IndependentLineage {
        index: usize,
        #[source]
        source: ProductionDoryV3IndependentLineageError,
    },
    #[error("fresh combined-payload validation failed: {0}")]
    Combined(#[source] ProductionDoryV3ModelCombinerError),
    #[error("exact-roster final-candidate validation failed: {0}")]
    FinalCandidate(#[from] ProductionDoryV3ModelFinalCandidateValidationError),
    #[error("keyless Type-6 preparation or staging failed: {0}")]
    Authoring(#[from] ProductionDoryV3CeremonyAuthoringError),
    #[error("failed to inspect the process open-file descriptor limit: {0}")]
    OpenFileDescriptorLimit(#[source] std::io::Error),
    #[error(
        "production Type-6 orchestration requires an open-file descriptor soft limit of at least {required}, observed {actual}"
    )]
    InsufficientOpenFileDescriptorLimit { required: usize, actual: u64 },
}

impl From<CeremonyFsError> for ProductionDoryV3FinalReceiptOrchestrationError {
    fn from(error: CeremonyFsError) -> Self {
        Self::Filesystem(error.to_string())
    }
}

/// Load and retain one strict paths-only plan and its independently anchored
/// reveal-set-closed prefix. No external candidate artifact is opened here.
pub fn load_production_dory_v3_final_receipt_orchestration_plan(
    plan_path: &Path,
    expected_ceremony_id: [u8; 32],
) -> Result<
    RetainedProductionDoryV3FinalReceiptOrchestrationInputs,
    ProductionDoryV3FinalReceiptOrchestrationError,
> {
    load_production_dory_v3_final_receipt_orchestration_plan_with_final_reauthentication_hook(
        plan_path,
        expected_ceremony_id,
        || Ok(()),
    )
}

fn load_production_dory_v3_final_receipt_orchestration_plan_with_final_reauthentication_hook(
    plan_path: &Path,
    expected_ceremony_id: [u8; 32],
    before_final_reauthentication: impl FnOnce() -> Result<
        (),
        ProductionDoryV3FinalReceiptOrchestrationError,
    >,
) -> Result<
    RetainedProductionDoryV3FinalReceiptOrchestrationInputs,
    ProductionDoryV3FinalReceiptOrchestrationError,
> {
    let mut plan = RetainedAuthenticatedSmallFile::open(
        plan_path,
        PRODUCTION_DORY_V3_FINAL_RECEIPT_PLAN_MAX_BYTES,
    )?;
    let ProductionDoryV3FinalReceiptOrchestrationPlan::V1(artifacts) =
        serde_json::from_slice(&plan.bytes)?;

    if plan.path == artifacts.reveal_set_prefix {
        return Err(
            ProductionDoryV3FinalReceiptOrchestrationError::DuplicatePath {
                first: "plan".to_owned(),
                second: "reveal_set_prefix".to_owned(),
            },
        );
    }
    let mut reveal_set_prefix = RetainedAuthenticatedSmallFile::open(
        &artifacts.reveal_set_prefix,
        MAX_CEREMONY_TRANSCRIPT_BYTES,
    )?;
    if plan.input.identity() == reveal_set_prefix.input.identity() {
        return Err(ProductionDoryV3FinalReceiptOrchestrationError::DuplicateRetainedInput);
    }
    let transcript =
        parse_and_verify_reveal_set_prefix(&reveal_set_prefix.bytes, expected_ceremony_id)?;

    let expected_contributions = transcript.operators().len();
    if artifacts.ordered_contributions.len() != expected_contributions {
        return Err(
            ProductionDoryV3FinalReceiptOrchestrationError::ContributionCount {
                expected: expected_contributions,
                actual: artifacts.ordered_contributions.len(),
            },
        );
    }
    let expected_reproducers = transcript.reproducers().len();
    if artifacts.ordered_reproducers.len() != expected_reproducers {
        return Err(
            ProductionDoryV3FinalReceiptOrchestrationError::ReproducerCount {
                expected: expected_reproducers,
                actual: artifacts.ordered_reproducers.len(),
            },
        );
    }
    if artifacts.ordered_independent_evidence.is_empty()
        || artifacts.ordered_independent_evidence.len() > expected_reproducers
    {
        return Err(
            ProductionDoryV3FinalReceiptOrchestrationError::IndependentEvidenceCount {
                maximum: expected_reproducers,
                actual: artifacts.ordered_independent_evidence.len(),
            },
        );
    }

    validate_declared_paths(plan_path, &artifacts)?;
    before_final_reauthentication()?;
    plan.reauthenticate_exact()?;
    reveal_set_prefix.reauthenticate_exact()?;

    Ok(RetainedProductionDoryV3FinalReceiptOrchestrationInputs {
        plan,
        reveal_set_prefix,
        transcript,
        _artifacts: artifacts,
    })
}

/// Authenticate every path named by a strict plan, validate the complete
/// A-through-G semantic chain, and return only public Type-6 signing material
/// plus the retained capabilities needed for guarded staging.
pub fn prepare_production_dory_v3_final_receipt_from_orchestration_plan(
    plan_path: &Path,
    expected_ceremony_id: [u8; 32],
) -> Result<
    PreparedProductionDoryV3FinalReceiptOrchestration,
    ProductionDoryV3FinalReceiptOrchestrationError,
> {
    let inputs =
        load_production_dory_v3_final_receipt_orchestration_plan(plan_path, expected_ceremony_id)?;
    prepare_loaded_production_dory_v3_final_receipt_orchestration(inputs)
}

fn prepare_loaded_production_dory_v3_final_receipt_orchestration(
    mut inputs: RetainedProductionDoryV3FinalReceiptOrchestrationInputs,
) -> Result<
    PreparedProductionDoryV3FinalReceiptOrchestration,
    ProductionDoryV3FinalReceiptOrchestrationError,
> {
    let artifacts = &inputs._artifacts;
    let transcript = &inputs.transcript;
    preflight_open_file_descriptor_capacity(
        transcript.operators().len(),
        transcript.reproducers().len(),
        artifacts.ordered_independent_evidence.len(),
    )?;

    // A-B: the exact contribution roster freshly reconstructs and validates
    // the shared raw payload against the independently anchored Type-5 prefix.
    let combined = validate_existing_production_dory_v3_model_combined_payload(
        transcript,
        &artifacts.ordered_contributions,
        &artifacts.shared_candidate.raw_payload,
    )
    .map_err(ProductionDoryV3FinalReceiptOrchestrationError::Combined)?;

    // C: each fixed-width canonical CMFDRP is read twice through its retained
    // handle and context-verified in frozen roster order.
    let mut reports = Vec::with_capacity(artifacts.ordered_reproducers.len());
    for (index, reproducer) in artifacts.ordered_reproducers.iter().enumerate() {
        let bytes = read_authenticated_reproduction_report(&reproducer.reproduction_report, index)?;
        let report =
            verify_production_dory_v3_model_reproduction_report(&bytes, transcript, &combined)
                .map_err(|source| {
                    ProductionDoryV3FinalReceiptOrchestrationError::ReproductionReport {
                        index,
                        source,
                    }
                })?;
        reports.push(report);
    }

    // D-E: dense evidence is consumed only for the filtered Independent
    // report order. Exact count is checked before opening any CMFDIL evidence.
    let descriptors: Vec<_> = reports
        .iter()
        .map(|report| {
            (
                report.report().reproducer_index(),
                report.report().implementation_kind(),
            )
        })
        .collect();
    let independent_positions = require_ordered_reports_and_independent_evidence(
        &descriptors,
        artifacts.ordered_independent_evidence.len(),
    )?;
    let mut independent_lineages = Vec::with_capacity(independent_positions.len());
    for (independent, index) in artifacts
        .ordered_independent_evidence
        .iter()
        .zip(independent_positions)
    {
        let report = &reports[index];
        let reproducer = &artifacts.ordered_reproducers[index];
        let paths = independent_lineage_evidence_paths(reproducer, independent);
        independent_lineages.push(
            validate_existing_production_dory_v3_independent_lineage(
                &reproducer.implementation_lineage_report,
                paths,
                transcript,
                report,
            )
            .map_err(|source| {
                ProductionDoryV3FinalReceiptOrchestrationError::IndependentLineage { index, source }
            })?,
        );
    }
    let lineages = VerifiedProductionDoryV3ReproducerLineages::verify_exact_ordered(
        transcript,
        &reports,
        independent_lineages,
    )?;

    // F: repeat fresh combined/report validation inside the existing retained
    // exact-candidate validator, including roots, structure, bank and Record V2.
    let shared = ProductionDoryV3ModelFinalCandidatePaths {
        source_bundle: &artifacts.shared_candidate.source_bundle,
        source_bundle_policy: &artifacts.shared_candidate.source_bundle_policy,
        raw_payload: &artifacts.shared_candidate.raw_payload,
        roots_file: &artifacts.shared_candidate.roots_file,
        structural_report: &artifacts.shared_candidate.structural_report,
        bank_file: &artifacts.shared_candidate.bank_file,
        manifest_file: &artifacts.shared_candidate.manifest_file,
        record_v2_file: &artifacts.shared_candidate.record_v2_file,
    };
    let reproducer_paths: Vec<_> = artifacts
        .ordered_reproducers
        .iter()
        .map(|reproducer| ProductionDoryV3ModelReproducerCandidatePaths {
            reproduction_report: &reproducer.reproduction_report,
            combiner_binary: &reproducer.combiner_binary,
            combiner_report: &reproducer.combiner_report,
            bootstrap_report: &reproducer.bootstrap_report,
            record_ceremony_report: &reproducer.record_ceremony_report,
            host_environment_report: &reproducer.host_environment_report,
            source_extraction_report: &reproducer.source_extraction_report,
            command_log: &reproducer.command_log,
            implementation_lineage_report: &reproducer.implementation_lineage_report,
        })
        .collect();
    let candidate = validate_existing_production_dory_v3_model_final_candidate(
        transcript,
        lineages,
        &artifacts.ordered_contributions,
        shared,
        &reproducer_paths,
    )?;

    // G: compare filesystem identities across the already-retained plan,
    // prefix, candidate, and CMFDIL capabilities. Same-path overlap between
    // validators is coalesced; different declared paths may never hardlink.
    validate_global_retained_artifact_identities(&inputs, &candidate)?;
    let authoring_transcript = inputs.transcript.clone();
    inputs.reauthenticate_retained_inputs()?;
    let prepared = prepare_production_dory_v3_final_receipt(authoring_transcript, candidate)?;
    Ok(PreparedProductionDoryV3FinalReceiptOrchestration { inputs, prepared })
}

fn retained_handle_count(
    operator_count: usize,
    reproducer_count: usize,
    independent_count: usize,
) -> usize {
    FIXED_RETAINED_HANDLES
        + RETAINED_HANDLES_PER_CONTRIBUTION * operator_count
        + RETAINED_HANDLES_PER_REPRODUCER * reproducer_count
        + RETAINED_HANDLES_PER_INDEPENDENT_LINEAGE * independent_count
}

fn required_open_file_descriptor_soft_limit(
    operator_count: usize,
    reproducer_count: usize,
    independent_count: usize,
) -> usize {
    (retained_handle_count(operator_count, reproducer_count, independent_count)
        + OPEN_FILE_DESCRIPTOR_RESERVE)
        .max(MINIMUM_OPEN_FILE_DESCRIPTOR_SOFT_LIMIT)
}

#[cfg(unix)]
fn preflight_open_file_descriptor_capacity(
    operator_count: usize,
    reproducer_count: usize,
    independent_count: usize,
) -> Result<(), ProductionDoryV3FinalReceiptOrchestrationError> {
    let required = required_open_file_descriptor_soft_limit(
        operator_count,
        reproducer_count,
        independent_count,
    );
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: `limit` points to writable storage for one `rlimit`, and the
    // result is read only after `getrlimit` reports success.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return Err(
            ProductionDoryV3FinalReceiptOrchestrationError::OpenFileDescriptorLimit(
                std::io::Error::last_os_error(),
            ),
        );
    }
    // SAFETY: the successful call above initialized the complete value.
    let limit = unsafe { limit.assume_init() };
    let actual = (limit.rlim_cur != libc::RLIM_INFINITY).then_some(limit.rlim_cur as u64);
    require_open_file_descriptor_soft_limit(required, actual)
}

#[cfg(not(unix))]
fn preflight_open_file_descriptor_capacity(
    operator_count: usize,
    reproducer_count: usize,
    independent_count: usize,
) -> Result<(), ProductionDoryV3FinalReceiptOrchestrationError> {
    // Windows kernel handles do not have an RLIMIT_NOFILE-style process soft
    // limit. Still compute the documented bound, while every retained open
    // remains fail-closed through ceremony_fs.
    let required = required_open_file_descriptor_soft_limit(
        operator_count,
        reproducer_count,
        independent_count,
    );
    require_open_file_descriptor_soft_limit(required, None)
}

fn require_open_file_descriptor_soft_limit(
    required: usize,
    actual: Option<u64>,
) -> Result<(), ProductionDoryV3FinalReceiptOrchestrationError> {
    match actual {
        Some(actual) if actual < required as u64 => Err(
            ProductionDoryV3FinalReceiptOrchestrationError::InsufficientOpenFileDescriptorLimit {
                required,
                actual,
            },
        ),
        _ => Ok(()),
    }
}

/// Consume one live plan-to-Type-6 capability, verify external full-roster
/// signatures, and create-new stage the canonical Type-6 record. The plan and
/// Type-5 prefix are reauthenticated immediately before both candidate guards,
/// including the final bank-last guard after the output is reopened.
pub fn stage_production_dory_v3_final_receipt_orchestration(
    prepared: PreparedProductionDoryV3FinalReceiptOrchestration,
    signatures: Vec<RecordSignature>,
    output_path: &Path,
) -> Result<
    ProductionDoryV3FinalReceiptOrchestrationStageReport,
    ProductionDoryV3FinalReceiptOrchestrationError,
> {
    let PreparedProductionDoryV3FinalReceiptOrchestration {
        mut inputs,
        prepared,
    } = prepared;
    let plan_path = inputs.plan_path().to_path_buf();
    let plan_file = inputs.plan_file().clone();
    let reveal_set_prefix_path = inputs.reveal_set_prefix_path().to_path_buf();
    let reveal_set_prefix_file = inputs.reveal_set_prefix_file().clone();
    let ceremony_id = inputs.ceremony_id();
    let staged = stage_production_dory_v3_final_receipt_with_retained_input_guard(
        prepared,
        signatures,
        output_path,
        || {
            inputs.reauthenticate_retained_inputs().map_err(|error| {
                ProductionDoryV3CeremonyAuthoringError::RetainedInputGuard(error.to_string())
            })
        },
    )?;
    Ok(ProductionDoryV3FinalReceiptOrchestrationStageReport {
        plan_path,
        plan_file,
        reveal_set_prefix_path,
        reveal_set_prefix_file,
        ceremony_id,
        staged,
    })
}

pub fn stage_production_dory_v3_final_receipt_from_orchestration_plan(
    plan_path: &Path,
    expected_ceremony_id: [u8; 32],
    signatures: Vec<RecordSignature>,
    output_path: &Path,
) -> Result<
    ProductionDoryV3FinalReceiptOrchestrationStageReport,
    ProductionDoryV3FinalReceiptOrchestrationError,
> {
    let prepared = prepare_production_dory_v3_final_receipt_from_orchestration_plan(
        plan_path,
        expected_ceremony_id,
    )?;
    stage_production_dory_v3_final_receipt_orchestration(prepared, signatures, output_path)
}

fn require_ordered_reports_and_independent_evidence(
    reports: &[(u16, ProductionDoryV3ReproductionImplementationKind)],
    evidence_count: usize,
) -> Result<Vec<usize>, ProductionDoryV3FinalReceiptOrchestrationError> {
    let mut independent = Vec::new();
    for (position, (actual, kind)) in reports.iter().copied().enumerate() {
        if usize::from(actual) != position {
            return Err(
                ProductionDoryV3FinalReceiptOrchestrationError::ReproducerOrder {
                    position,
                    actual,
                },
            );
        }
        if kind == ProductionDoryV3ReproductionImplementationKind::Independent {
            independent.push(position);
        }
    }
    if evidence_count != independent.len() {
        return Err(
            ProductionDoryV3FinalReceiptOrchestrationError::ExactIndependentEvidenceCount {
                expected: independent.len(),
                actual: evidence_count,
            },
        );
    }
    Ok(independent)
}

fn independent_lineage_evidence_paths<'a>(
    reproducer: &'a ReproducerCandidatePaths,
    independent: &'a IndependentEvidencePaths,
) -> ProductionDoryV3IndependentLineageEvidencePaths<'a> {
    ProductionDoryV3IndependentLineageEvidencePaths {
        combiner_source_bundle: &independent.combiner_source_bundle,
        combiner_build_provenance: &independent.combiner_build_provenance,
        combiner_binary: &reproducer.combiner_binary,
        roots_calculator_source_bundle: &independent.roots_calculator_source_bundle,
        roots_calculator_build_provenance: &independent.roots_calculator_build_provenance,
        roots_calculator_binary: &independent.roots_calculator_binary,
        independent_lineage_review_report: &independent.independent_lineage_review_report,
        conformance_test_report: &independent.conformance_test_report,
        host_environment_report: &reproducer.host_environment_report,
        source_extraction_report: &reproducer.source_extraction_report,
        command_log: &reproducer.command_log,
    }
}

fn validate_declared_paths(
    plan_path: &Path,
    artifacts: &ProductionDoryV3FinalReceiptArtifactsV1,
) -> Result<(), ProductionDoryV3FinalReceiptOrchestrationError> {
    // This routing layer deliberately requires every declared pathname to be
    // textually distinct. Later semantic validators additionally open the real
    // files and reject filesystem-identity aliases within their authority sets.
    let paths = declared_paths(plan_path, artifacts);

    for first in 0..paths.len() {
        for second in first + 1..paths.len() {
            if paths[first].1 == paths[second].1 {
                return Err(
                    ProductionDoryV3FinalReceiptOrchestrationError::DuplicatePath {
                        first: paths[first].0.clone(),
                        second: paths[second].0.clone(),
                    },
                );
            }
        }
    }
    for (_, path) in paths.into_iter().skip(2) {
        drop(TrustedCeremonyParent::for_artifact(path)?);
    }
    Ok(())
}

fn declared_paths<'a>(
    plan_path: &'a Path,
    artifacts: &'a ProductionDoryV3FinalReceiptArtifactsV1,
) -> Vec<(String, &'a Path)> {
    let mut paths = vec![
        ("plan".to_owned(), plan_path),
        (
            "reveal_set_prefix".to_owned(),
            artifacts.reveal_set_prefix.as_path(),
        ),
    ];
    for (index, path) in artifacts.ordered_contributions.iter().enumerate() {
        paths.push((format!("ordered_contributions[{index}]"), path));
    }
    push_shared_candidate_paths(&mut paths, &artifacts.shared_candidate);
    for (index, reproducer) in artifacts.ordered_reproducers.iter().enumerate() {
        push_reproducer_paths(&mut paths, index, reproducer);
    }
    for (index, evidence) in artifacts.ordered_independent_evidence.iter().enumerate() {
        push_independent_evidence_paths(&mut paths, index, evidence);
    }
    paths
}

fn push_shared_candidate_paths<'a>(
    paths: &mut Vec<(String, &'a Path)>,
    shared: &'a SharedCandidatePaths,
) {
    paths.extend([
        (
            "shared_candidate.source_bundle".to_owned(),
            shared.source_bundle.as_path(),
        ),
        (
            "shared_candidate.source_bundle_policy".to_owned(),
            shared.source_bundle_policy.as_path(),
        ),
        (
            "shared_candidate.raw_payload".to_owned(),
            shared.raw_payload.as_path(),
        ),
        (
            "shared_candidate.roots_file".to_owned(),
            shared.roots_file.as_path(),
        ),
        (
            "shared_candidate.structural_report".to_owned(),
            shared.structural_report.as_path(),
        ),
        (
            "shared_candidate.bank_file".to_owned(),
            shared.bank_file.as_path(),
        ),
        (
            "shared_candidate.manifest_file".to_owned(),
            shared.manifest_file.as_path(),
        ),
        (
            "shared_candidate.record_v2_file".to_owned(),
            shared.record_v2_file.as_path(),
        ),
    ]);
}

fn push_reproducer_paths<'a>(
    paths: &mut Vec<(String, &'a Path)>,
    index: usize,
    reproducer: &'a ReproducerCandidatePaths,
) {
    let prefix = format!("ordered_reproducers[{index}]");
    paths.extend([
        (
            format!("{prefix}.reproduction_report"),
            reproducer.reproduction_report.as_path(),
        ),
        (
            format!("{prefix}.combiner_binary"),
            reproducer.combiner_binary.as_path(),
        ),
        (
            format!("{prefix}.combiner_report"),
            reproducer.combiner_report.as_path(),
        ),
        (
            format!("{prefix}.bootstrap_report"),
            reproducer.bootstrap_report.as_path(),
        ),
        (
            format!("{prefix}.record_ceremony_report"),
            reproducer.record_ceremony_report.as_path(),
        ),
        (
            format!("{prefix}.host_environment_report"),
            reproducer.host_environment_report.as_path(),
        ),
        (
            format!("{prefix}.source_extraction_report"),
            reproducer.source_extraction_report.as_path(),
        ),
        (
            format!("{prefix}.command_log"),
            reproducer.command_log.as_path(),
        ),
        (
            format!("{prefix}.implementation_lineage_report"),
            reproducer.implementation_lineage_report.as_path(),
        ),
    ]);
}

fn push_independent_evidence_paths<'a>(
    paths: &mut Vec<(String, &'a Path)>,
    index: usize,
    evidence: &'a IndependentEvidencePaths,
) {
    let prefix = format!("ordered_independent_evidence[{index}]");
    paths.extend([
        (
            format!("{prefix}.combiner_source_bundle"),
            evidence.combiner_source_bundle.as_path(),
        ),
        (
            format!("{prefix}.combiner_build_provenance"),
            evidence.combiner_build_provenance.as_path(),
        ),
        (
            format!("{prefix}.roots_calculator_source_bundle"),
            evidence.roots_calculator_source_bundle.as_path(),
        ),
        (
            format!("{prefix}.roots_calculator_build_provenance"),
            evidence.roots_calculator_build_provenance.as_path(),
        ),
        (
            format!("{prefix}.roots_calculator_binary"),
            evidence.roots_calculator_binary.as_path(),
        ),
        (
            format!("{prefix}.independent_lineage_review_report"),
            evidence.independent_lineage_review_report.as_path(),
        ),
        (
            format!("{prefix}.conformance_test_report"),
            evidence.conformance_test_report.as_path(),
        ),
    ]);
}

fn read_authenticated_reproduction_report(
    path: &Path,
    index: usize,
) -> Result<Vec<u8>, ProductionDoryV3FinalReceiptOrchestrationError> {
    let parent = TrustedCeremonyParent::for_artifact(path)?;
    let expected = PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES;
    let mut input = AuthenticatedInput::open(&parent, path, Some(expected as u64))?;
    let first = input.read_bounded(expected)?;
    if first.len() != expected {
        return Err(
            ProductionDoryV3FinalReceiptOrchestrationError::ReproductionReportLength {
                index,
                expected,
                actual: first.len(),
            },
        );
    }
    input.recheck(&parent, Some(expected as u64))?;
    let second = input.read_bounded(expected)?;
    input.recheck(&parent, Some(expected as u64))?;
    if second != first {
        return Err(
            ProductionDoryV3FinalReceiptOrchestrationError::ReproductionReportChanged { index },
        );
    }
    Ok(first)
}

fn validate_global_retained_artifact_identities(
    inputs: &RetainedProductionDoryV3FinalReceiptOrchestrationInputs,
    candidate: &ValidatedProductionDoryV3ModelFinalCandidate,
) -> Result<(), ProductionDoryV3FinalReceiptOrchestrationError> {
    let mut retained = candidate.retained_filesystem_entries();
    retained.push((
        inputs.plan_path().to_path_buf(),
        inputs.plan.input.identity(),
    ));
    retained.push((
        inputs.reveal_set_prefix_path().to_path_buf(),
        inputs.reveal_set_prefix.input.identity(),
    ));

    let declared = declared_paths(inputs.plan_path(), &inputs._artifacts);
    validate_global_retained_artifact_identity_entries(&declared, &retained)
}

fn validate_global_retained_artifact_identity_entries(
    declared: &[(String, &Path)],
    retained: &[(PathBuf, CeremonyFilesystemIdentity)],
) -> Result<(), ProductionDoryV3FinalReceiptOrchestrationError> {
    for (path, _) in retained {
        if !declared
            .iter()
            .any(|(_, declared_path)| *declared_path == path)
        {
            return Err(
                ProductionDoryV3FinalReceiptOrchestrationError::UnexpectedRetainedArtifact(
                    path.clone(),
                ),
            );
        }
    }

    let mut unique: Vec<(String, &Path, CeremonyFilesystemIdentity)> =
        Vec::with_capacity(declared.len());
    for (role, path) in declared {
        let mut matches = retained
            .iter()
            .filter(|(retained_path, _)| retained_path == path);
        let Some((_, identity)) = matches.next() else {
            return Err(
                ProductionDoryV3FinalReceiptOrchestrationError::MissingRetainedArtifact(
                    role.clone(),
                ),
            );
        };
        if matches.any(|(_, observed)| observed != identity) {
            return Err(
                ProductionDoryV3FinalReceiptOrchestrationError::RetainedArtifactIdentityMismatch(
                    role.clone(),
                ),
            );
        }
        unique.push((role.clone(), *path, *identity));
    }

    for second in 0..unique.len() {
        for first in 0..second {
            if unique[first].2 == unique[second].2 {
                return Err(
                    ProductionDoryV3FinalReceiptOrchestrationError::AliasedArtifacts {
                        first: unique[first].0.clone(),
                        second: unique[second].0.clone(),
                    },
                );
            }
        }
    }
    Ok(())
}

struct RetainedAuthenticatedSmallFile {
    path: PathBuf,
    maximum_bytes: usize,
    parent: TrustedCeremonyParent,
    input: AuthenticatedInput,
    bytes: Vec<u8>,
    content_identity: FileIdentity,
}

impl RetainedAuthenticatedSmallFile {
    fn open(
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Self, ProductionDoryV3FinalReceiptOrchestrationError> {
        let parent = TrustedCeremonyParent::for_artifact(path)?;
        let mut input = AuthenticatedInput::open(&parent, path, None)?;
        let first = input.read_bounded(maximum_bytes)?;
        if first.len() > maximum_bytes {
            return Err(
                ProductionDoryV3FinalReceiptOrchestrationError::InputTooLarge(path.to_path_buf()),
            );
        }
        input.recheck(&parent, Some(first.len() as u64))?;
        let second = input.read_bounded(maximum_bytes)?;
        input.recheck(&parent, Some(first.len() as u64))?;
        if first != second {
            return Err(
                ProductionDoryV3FinalReceiptOrchestrationError::InputChanged(path.to_path_buf()),
            );
        }
        let content_identity = content_identity(&first);
        Ok(Self {
            path: path.to_path_buf(),
            maximum_bytes,
            parent,
            input,
            bytes: first,
            content_identity,
        })
    }

    fn reauthenticate_exact(
        &mut self,
    ) -> Result<(), ProductionDoryV3FinalReceiptOrchestrationError> {
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
            || content_identity(&first) != self.content_identity
        {
            return Err(
                ProductionDoryV3FinalReceiptOrchestrationError::InputChanged(self.path.clone()),
            );
        }
        Ok(())
    }
}

fn content_identity(bytes: &[u8]) -> FileIdentity {
    let mut sha256 = Sha256::new();
    sha256.update(bytes);
    FileIdentity {
        bytes: bytes.len() as u64,
        blake3: *blake3::hash(bytes).as_bytes(),
        sha256: sha256.finalize().into(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use k256::schnorr::{Signature, SigningKey};
    use serde_json::{Value, json};

    use super::*;
    use crate::{
        dory_v3_model_ceremony_fs::prepare_test_parent,
        dory_v3_model_ceremony_transcript::{
            AbortBody, CEREMONY_PROTOCOL_VERSION, CeremonyRecordBody, CommitmentSetBody,
            ContributionCommitmentBody, ContributionRevealBody, GenesisBody, IndexedRecordDigest,
            PRODUCTION_BANK_FORMAT_VERSION, PRODUCTION_BANK_HEADER_BYTES, PRODUCTION_BANKS,
            PRODUCTION_BASE_INPUT_BYTES, PRODUCTION_BATCH, PRODUCTION_BYTES_PER_LAYER,
            PRODUCTION_DIMENSION, PRODUCTION_LAYERS, PRODUCTION_LAYERS_PER_BANK,
            PRODUCTION_MAX_MODEL_BYTE, PRODUCTION_MODEL_VERSION, PRODUCTION_PADDED_VARIABLES,
            PRODUCTION_PAYLOAD_BYTES, RecordSignature, ReferenceBinary, RevealSetBody,
            RosterMember, SignedCeremonyRecord, SignerClass, ceremony_record_content_digest,
            ceremony_record_signature_message, ceremony_signed_record_digest,
            encode_and_verify_ceremony_transcript, encode_and_verify_reveal_set_prefix,
        },
        dory_v3_suite::{DORY_V3_SETUP_IDENTITY, production_dory_v3_suite_digest},
    };

    static TEST_DIRECTORY_NONCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "cmfd-final-receipt-orchestration-test-{}-{}",
                std::process::id(),
                TEST_DIRECTORY_NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            prepare_test_parent(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
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

    fn reveal_set_prefix_fixture() -> (Vec<u8>, [u8; 32]) {
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

        (
            encode_and_verify_reveal_set_prefix(&records, ceremony_id).unwrap(),
            ceremony_id,
        )
    }

    fn aborted_transcript_fixture() -> (Vec<u8>, [u8; 32]) {
        let operators = test_keys(3, 1);
        let reproducers = test_keys(2, 20);
        let genesis = sign_test_record(
            CeremonyRecordBody::Genesis(Box::new(test_genesis(&operators, &reproducers))),
            &all_test_signers(&operators, &reproducers),
        );
        let ceremony_id = ceremony_record_content_digest(&genesis.body).unwrap();
        let abort = sign_test_record(
            CeremonyRecordBody::Abort(AbortBody {
                ceremony_id,
                last_valid_signed_record_digest: ceremony_signed_record_digest(&genesis).unwrap(),
                phase: 1,
                reason_code: 12,
                evidence_file: test_file(30),
            }),
            &[(SignerClass::Operator, 0, &operators[0])],
        );
        (
            encode_and_verify_ceremony_transcript(&[genesis, abort]).unwrap(),
            ceremony_id,
        )
    }

    fn valid_plan(directory: &TestDirectory, reveal_set_prefix: &Path) -> Value {
        let path = |name: &str| directory.path(name);
        json!({
            "plan_type": "production_dory_v3_final_receipt_v1",
            "artifacts": {
                "reveal_set_prefix": reveal_set_prefix,
                "ordered_contributions": [
                    path("contribution-0.bin"),
                    path("contribution-1.bin"),
                    path("contribution-2.bin")
                ],
                "shared_candidate": {
                    "source_bundle": path("source-bundle.bin"),
                    "source_bundle_policy": path("source-bundle-policy.json"),
                    "raw_payload": path("raw-payload.bin"),
                    "roots_file": path("roots.cmfdmr01"),
                    "structural_report": path("structure.cmfdsr01"),
                    "bank_file": path("bank.bin"),
                    "manifest_file": path("manifest.json"),
                    "record_v2_file": path("record-v2.json")
                },
                "ordered_reproducers": [
                    reproducer_plan(directory, 0),
                    reproducer_plan(directory, 1)
                ],
                "ordered_independent_evidence": [independent_evidence_plan(directory, 0)]
            }
        })
    }

    fn reproducer_plan(directory: &TestDirectory, index: usize) -> Value {
        let path = |role: &str| directory.path(&format!("reproducer-{index}-{role}"));
        json!({
            "reproduction_report": path("reproduction-report.cmfdrp01"),
            "combiner_binary": path("combiner.bin"),
            "combiner_report": path("combiner-report.bin"),
            "bootstrap_report": path("bootstrap-report.json"),
            "record_ceremony_report": path("record-ceremony-report.json"),
            "host_environment_report": path("host-environment.json"),
            "source_extraction_report": path("source-extraction.json"),
            "command_log": path("command.log"),
            "implementation_lineage_report": path("lineage.cmfdil01")
        })
    }

    fn independent_evidence_plan(directory: &TestDirectory, index: usize) -> Value {
        let path = |role: &str| directory.path(&format!("independent-{index}-{role}"));
        json!({
            "combiner_source_bundle": path("combiner-source.tar"),
            "combiner_build_provenance": path("combiner-build.json"),
            "roots_calculator_source_bundle": path("roots-source.tar"),
            "roots_calculator_build_provenance": path("roots-build.json"),
            "roots_calculator_binary": path("roots-calculator.bin"),
            "independent_lineage_review_report": path("lineage-review.json"),
            "conformance_test_report": path("conformance.json")
        })
    }

    fn write_json(directory: &TestDirectory, name: &str, value: &Value) -> PathBuf {
        let path = directory.path(name);
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    }

    fn filesystem_identity(path: &Path) -> CeremonyFilesystemIdentity {
        let parent = TrustedCeremonyParent::for_artifact(path).unwrap();
        AuthenticatedInput::open(&parent, path, None)
            .unwrap()
            .identity()
    }

    #[test]
    fn canonical_paths_only_plan_loads_and_retains_exact_inputs() {
        let directory = TestDirectory::new();
        let (prefix_bytes, ceremony_id) = reveal_set_prefix_fixture();
        let prefix_path = directory.path("reveal-set-closed.cmfd");
        fs::write(&prefix_path, &prefix_bytes).unwrap();
        let plan_value = valid_plan(&directory, &prefix_path);
        assert_eq!(
            plan_value["artifacts"]["ordered_independent_evidence"][0]
                .as_object()
                .unwrap()
                .len(),
            7
        );
        let plan_path = write_json(&directory, "plan.json", &plan_value);
        let plan_bytes = fs::read(&plan_path).unwrap();
        assert!(!directory.path("raw-payload.bin").exists());

        let mut loaded =
            load_production_dory_v3_final_receipt_orchestration_plan(&plan_path, ceremony_id)
                .unwrap();
        assert_eq!(loaded.plan_path(), plan_path);
        assert_eq!(loaded.reveal_set_prefix_path(), prefix_path);
        assert_eq!(loaded.plan_file(), &content_identity(&plan_bytes));
        assert_eq!(
            loaded.reveal_set_prefix_file(),
            &content_identity(&prefix_bytes)
        );
        assert_eq!(loaded.ceremony_id(), ceremony_id);
        assert_eq!(loaded.operator_count(), 3);
        assert_eq!(loaded.reproducer_count(), 2);
        loaded.reauthenticate_retained_inputs().unwrap();
    }

    #[test]
    fn report_order_and_dense_independent_evidence_are_fail_closed() {
        use ProductionDoryV3ReproductionImplementationKind::{Independent, Reference};

        let honest = [
            (0, Reference),
            (1, Independent),
            (2, Reference),
            (3, Independent),
        ];
        assert_eq!(
            require_ordered_reports_and_independent_evidence(&honest, 2).unwrap(),
            [1, 3]
        );

        let swapped = [(1, Independent), (0, Reference)];
        assert!(matches!(
            require_ordered_reports_and_independent_evidence(&swapped, 1),
            Err(
                ProductionDoryV3FinalReceiptOrchestrationError::ReproducerOrder {
                    position: 0,
                    actual: 1
                }
            )
        ));
        for actual in [1, 3] {
            assert!(matches!(
                require_ordered_reports_and_independent_evidence(&honest, actual),
                Err(ProductionDoryV3FinalReceiptOrchestrationError::
                    ExactIndependentEvidenceCount {
                        expected: 2,
                        actual: observed
                    }) if observed == actual
            ));
        }
    }

    #[test]
    fn retained_handle_budget_is_bounded_before_heavy_validation() {
        assert_eq!(retained_handle_count(3, 2, 1), 92);
        assert_eq!(required_open_file_descriptor_soft_limit(3, 2, 1), 1024);
        assert_eq!(retained_handle_count(16, 16, 16), 730);
        assert_eq!(required_open_file_descriptor_soft_limit(16, 16, 16), 1024);
        assert!(matches!(
            require_open_file_descriptor_soft_limit(1024, Some(1023)),
            Err(ProductionDoryV3FinalReceiptOrchestrationError::
                InsufficientOpenFileDescriptorLimit {
                    required: 1024,
                    actual: 1023
                })
        ));
        require_open_file_descriptor_soft_limit(1024, Some(1024)).unwrap();
        require_open_file_descriptor_soft_limit(1024, None).unwrap();
        preflight_open_file_descriptor_capacity(3, 2, 1).unwrap();
    }

    #[test]
    fn independent_lineage_path_mapping_uses_only_the_verified_dense_slot() {
        let directory = TestDirectory::new();
        let reproducer = ReproducerCandidatePaths {
            reproduction_report: directory.path("report"),
            combiner_binary: directory.path("combiner-binary"),
            combiner_report: directory.path("combiner-report"),
            bootstrap_report: directory.path("bootstrap-report"),
            record_ceremony_report: directory.path("record-report"),
            host_environment_report: directory.path("host"),
            source_extraction_report: directory.path("extraction"),
            command_log: directory.path("command"),
            implementation_lineage_report: directory.path("lineage"),
        };
        let independent = IndependentEvidencePaths {
            combiner_source_bundle: directory.path("combiner-source"),
            combiner_build_provenance: directory.path("combiner-build"),
            roots_calculator_source_bundle: directory.path("roots-source"),
            roots_calculator_build_provenance: directory.path("roots-build"),
            roots_calculator_binary: directory.path("roots-binary"),
            independent_lineage_review_report: directory.path("review"),
            conformance_test_report: directory.path("conformance"),
        };
        let mapped = independent_lineage_evidence_paths(&reproducer, &independent);
        assert_eq!(
            mapped.combiner_source_bundle,
            independent.combiner_source_bundle
        );
        assert_eq!(
            mapped.combiner_build_provenance,
            independent.combiner_build_provenance
        );
        assert_eq!(mapped.combiner_binary, reproducer.combiner_binary);
        assert_eq!(
            mapped.roots_calculator_source_bundle,
            independent.roots_calculator_source_bundle
        );
        assert_eq!(
            mapped.roots_calculator_build_provenance,
            independent.roots_calculator_build_provenance
        );
        assert_eq!(
            mapped.roots_calculator_binary,
            independent.roots_calculator_binary
        );
        assert_eq!(
            mapped.independent_lineage_review_report,
            independent.independent_lineage_review_report
        );
        assert_eq!(
            mapped.conformance_test_report,
            independent.conformance_test_report
        );
        assert_eq!(
            mapped.host_environment_report,
            reproducer.host_environment_report
        );
        assert_eq!(
            mapped.source_extraction_report,
            reproducer.source_extraction_report
        );
        assert_eq!(mapped.command_log, reproducer.command_log);
    }

    #[test]
    fn global_retained_identity_registry_coalesces_overlap_and_rejects_aliases() {
        let directory = TestDirectory::new();
        let first = directory.path("first");
        let second = directory.path("second");
        let third = directory.path("third");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        fs::write(&third, b"third").unwrap();
        let first_identity = filesystem_identity(&first);
        let second_identity = filesystem_identity(&second);
        let third_identity = filesystem_identity(&third);
        let declared = vec![
            ("first".to_owned(), first.as_path()),
            ("second".to_owned(), second.as_path()),
        ];

        validate_global_retained_artifact_identity_entries(
            &declared,
            &[
                (first.clone(), first_identity),
                (second.clone(), second_identity),
                (second.clone(), second_identity),
            ],
        )
        .unwrap();

        assert!(matches!(
            validate_global_retained_artifact_identity_entries(
                &declared,
                &[(first.clone(), first_identity), (second.clone(), first_identity)]
            ),
            Err(ProductionDoryV3FinalReceiptOrchestrationError::AliasedArtifacts {
                first: first_role,
                second: second_role
            }) if first_role == "first" && second_role == "second"
        ));
        assert!(matches!(
            validate_global_retained_artifact_identity_entries(
                &declared,
                &[
                    (first.clone(), first_identity),
                    (second.clone(), second_identity),
                    (second.clone(), third_identity),
                ]
            ),
            Err(ProductionDoryV3FinalReceiptOrchestrationError::
                RetainedArtifactIdentityMismatch(role)) if role == "second"
        ));
        assert!(matches!(
            validate_global_retained_artifact_identity_entries(
                &declared,
                &[(first.clone(), first_identity)]
            ),
            Err(ProductionDoryV3FinalReceiptOrchestrationError::MissingRetainedArtifact(role))
                if role == "second"
        ));
        assert!(matches!(
            validate_global_retained_artifact_identity_entries(
                &declared,
                &[
                    (first.clone(), first_identity),
                    (second.clone(), second_identity),
                    (third.clone(), third_identity),
                ]
            ),
            Err(ProductionDoryV3FinalReceiptOrchestrationError::UnexpectedRetainedArtifact(path))
                if path == third
        ));
    }

    #[test]
    fn bank_chain_duplicate_manifest_and_record_identities_must_match() {
        let directory = TestDirectory::new();
        let manifest = directory.path("manifest.json");
        let record_v2 = directory.path("record-v2.json");
        let replacement = directory.path("replacement");
        fs::write(&manifest, b"manifest").unwrap();
        fs::write(&record_v2, b"record-v2").unwrap();
        fs::write(&replacement, b"replacement").unwrap();
        let manifest_identity = filesystem_identity(&manifest);
        let record_v2_identity = filesystem_identity(&record_v2);
        let replacement_identity = filesystem_identity(&replacement);
        let declared = vec![
            (
                "shared_candidate.manifest_file".to_owned(),
                manifest.as_path(),
            ),
            (
                "shared_candidate.record_v2_file".to_owned(),
                record_v2.as_path(),
            ),
        ];

        for (path, second, expected_role) in [
            (
                manifest.clone(),
                replacement_identity,
                "shared_candidate.manifest_file",
            ),
            (
                record_v2.clone(),
                replacement_identity,
                "shared_candidate.record_v2_file",
            ),
        ] {
            assert!(matches!(
                validate_global_retained_artifact_identity_entries(
                    &declared,
                    &[
                        (manifest.clone(), manifest_identity),
                        (record_v2.clone(), record_v2_identity),
                        (path, second),
                    ]
                ),
                Err(ProductionDoryV3FinalReceiptOrchestrationError::
                    RetainedArtifactIdentityMismatch(role)) if role == expected_role
            ));
        }
    }

    #[test]
    fn strict_schema_rejects_unknown_missing_and_wrong_version_fields() {
        let directory = TestDirectory::new();
        let (prefix_bytes, ceremony_id) = reveal_set_prefix_fixture();
        let prefix_path = directory.path("reveal-set-closed.cmfd");
        fs::write(&prefix_path, prefix_bytes).unwrap();
        let valid = valid_plan(&directory, &prefix_path);
        let mut cases = Vec::new();

        let mut outer_unknown = valid.clone();
        outer_unknown["unexpected"] = json!(true);
        cases.push(outer_unknown);
        let mut artifacts_unknown = valid.clone();
        artifacts_unknown["artifacts"]["unexpected"] = json!(true);
        cases.push(artifacts_unknown);
        let mut shared_unknown = valid.clone();
        shared_unknown["artifacts"]["shared_candidate"]["unexpected"] = json!(true);
        cases.push(shared_unknown);
        let mut reproducer_unknown = valid.clone();
        reproducer_unknown["artifacts"]["ordered_reproducers"][0]["unexpected"] = json!(true);
        cases.push(reproducer_unknown);
        let mut evidence_unknown = valid.clone();
        evidence_unknown["artifacts"]["ordered_independent_evidence"][0]["unexpected"] =
            json!(true);
        cases.push(evidence_unknown);
        let mut missing = valid.clone();
        missing["artifacts"]["shared_candidate"]
            .as_object_mut()
            .unwrap()
            .remove("raw_payload");
        cases.push(missing);
        let mut wrong_version = valid;
        wrong_version["plan_type"] = json!("production_dory_v3_final_receipt_v2");
        cases.push(wrong_version);

        for (index, value) in cases.iter().enumerate() {
            let plan_path = write_json(&directory, &format!("invalid-{index}.json"), value);
            assert!(matches!(
                load_production_dory_v3_final_receipt_orchestration_plan(&plan_path, ceremony_id),
                Err(ProductionDoryV3FinalReceiptOrchestrationError::PlanJson(_))
            ));
        }
    }

    #[test]
    fn rejects_wrong_roster_counts_anchor_and_terminal_transcript() {
        let directory = TestDirectory::new();
        let (prefix_bytes, ceremony_id) = reveal_set_prefix_fixture();
        let prefix_path = directory.path("reveal-set-closed.cmfd");
        fs::write(&prefix_path, prefix_bytes).unwrap();
        let valid = valid_plan(&directory, &prefix_path);

        let mut wrong_contributions = valid.clone();
        wrong_contributions["artifacts"]["ordered_contributions"]
            .as_array_mut()
            .unwrap()
            .pop();
        let plan_path = write_json(&directory, "wrong-contributions.json", &wrong_contributions);
        assert!(matches!(
            load_production_dory_v3_final_receipt_orchestration_plan(&plan_path, ceremony_id),
            Err(
                ProductionDoryV3FinalReceiptOrchestrationError::ContributionCount {
                    expected: 3,
                    actual: 2
                }
            )
        ));

        let mut wrong_reproducers = valid.clone();
        wrong_reproducers["artifacts"]["ordered_reproducers"]
            .as_array_mut()
            .unwrap()
            .pop();
        let plan_path = write_json(&directory, "wrong-reproducers.json", &wrong_reproducers);
        assert!(matches!(
            load_production_dory_v3_final_receipt_orchestration_plan(&plan_path, ceremony_id),
            Err(
                ProductionDoryV3FinalReceiptOrchestrationError::ReproducerCount {
                    expected: 2,
                    actual: 1
                }
            )
        ));

        let mut no_independent = valid.clone();
        no_independent["artifacts"]["ordered_independent_evidence"] = json!([]);
        let plan_path = write_json(&directory, "no-independent.json", &no_independent);
        assert!(matches!(
            load_production_dory_v3_final_receipt_orchestration_plan(&plan_path, ceremony_id),
            Err(
                ProductionDoryV3FinalReceiptOrchestrationError::IndependentEvidenceCount {
                    maximum: 2,
                    actual: 0
                }
            )
        ));

        let mut too_many_independent = valid.clone();
        too_many_independent["artifacts"]["ordered_independent_evidence"] = json!([
            independent_evidence_plan(&directory, 0),
            independent_evidence_plan(&directory, 1),
            independent_evidence_plan(&directory, 2)
        ]);
        let plan_path = write_json(
            &directory,
            "too-many-independent.json",
            &too_many_independent,
        );
        assert!(matches!(
            load_production_dory_v3_final_receipt_orchestration_plan(&plan_path, ceremony_id),
            Err(
                ProductionDoryV3FinalReceiptOrchestrationError::IndependentEvidenceCount {
                    maximum: 2,
                    actual: 3
                }
            )
        ));

        let plan_path = write_json(&directory, "wrong-anchor.json", &valid);
        let mut wrong_anchor = ceremony_id;
        wrong_anchor[0] ^= 1;
        assert!(matches!(
            load_production_dory_v3_final_receipt_orchestration_plan(&plan_path, wrong_anchor),
            Err(ProductionDoryV3FinalReceiptOrchestrationError::Transcript(
                _
            ))
        ));

        let (aborted_bytes, aborted_ceremony_id) = aborted_transcript_fixture();
        let aborted_path = directory.path("aborted.cmfd");
        fs::write(&aborted_path, aborted_bytes).unwrap();
        let aborted_plan = valid_plan(&directory, &aborted_path);
        let aborted_plan_path = write_json(&directory, "aborted-plan.json", &aborted_plan);
        assert!(matches!(
            load_production_dory_v3_final_receipt_orchestration_plan(
                &aborted_plan_path,
                aborted_ceremony_id
            ),
            Err(ProductionDoryV3FinalReceiptOrchestrationError::Transcript(
                _
            ))
        ));
    }

    #[test]
    fn rejects_relative_nonprivate_and_obviously_duplicate_paths() {
        let directory = TestDirectory::new();
        let (prefix_bytes, ceremony_id) = reveal_set_prefix_fixture();
        let prefix_path = directory.path("reveal-set-closed.cmfd");
        fs::write(&prefix_path, prefix_bytes).unwrap();
        let valid = valid_plan(&directory, &prefix_path);

        let mut relative = valid.clone();
        relative["artifacts"]["shared_candidate"]["source_bundle"] = json!("relative.bin");
        let plan_path = write_json(&directory, "relative.json", &relative);
        assert!(matches!(
            load_production_dory_v3_final_receipt_orchestration_plan(&plan_path, ceremony_id),
            Err(ProductionDoryV3FinalReceiptOrchestrationError::Filesystem(
                _
            ))
        ));

        let mut duplicate = valid.clone();
        duplicate["artifacts"]["ordered_contributions"][1] =
            duplicate["artifacts"]["ordered_contributions"][0].clone();
        let plan_path = write_json(&directory, "duplicate.json", &duplicate);
        assert!(matches!(
            load_production_dory_v3_final_receipt_orchestration_plan(&plan_path, ceremony_id),
            Err(ProductionDoryV3FinalReceiptOrchestrationError::DuplicatePath { .. })
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let unsafe_parent = std::env::temp_dir().join(format!(
                "cmfd-final-receipt-unsafe-test-{}-{}",
                std::process::id(),
                TEST_DIRECTORY_NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&unsafe_parent).unwrap();
            fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o755)).unwrap();
            let mut nonprivate = valid;
            nonprivate["artifacts"]["shared_candidate"]["source_bundle"] =
                json!(unsafe_parent.join("source-bundle.bin"));
            let plan_path = write_json(&directory, "nonprivate.json", &nonprivate);
            assert!(matches!(
                load_production_dory_v3_final_receipt_orchestration_plan(&plan_path, ceremony_id),
                Err(ProductionDoryV3FinalReceiptOrchestrationError::Filesystem(
                    _
                ))
            ));
            fs::remove_dir_all(unsafe_parent).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn final_reauthentication_rejects_in_place_prefix_mutation() {
        let directory = TestDirectory::new();
        let (prefix_bytes, ceremony_id) = reveal_set_prefix_fixture();
        let prefix_path = directory.path("reveal-set-closed.cmfd");
        fs::write(&prefix_path, &prefix_bytes).unwrap();
        let plan_path = write_json(
            &directory,
            "plan.json",
            &valid_plan(&directory, &prefix_path),
        );
        let mut changed = prefix_bytes;
        let last = changed.last_mut().unwrap();
        *last ^= 1;

        assert!(matches!(
            load_production_dory_v3_final_receipt_orchestration_plan_with_final_reauthentication_hook(
                &plan_path,
                ceremony_id,
                || {
                    fs::write(&prefix_path, changed).unwrap();
                    Ok(())
                }
            ),
            Err(ProductionDoryV3FinalReceiptOrchestrationError::InputChanged(path))
                if path == prefix_path
        ));
    }

    #[cfg(unix)]
    #[test]
    fn final_reauthentication_rejects_in_place_plan_mutation() {
        let directory = TestDirectory::new();
        let (prefix_bytes, ceremony_id) = reveal_set_prefix_fixture();
        let prefix_path = directory.path("reveal-set-closed.cmfd");
        fs::write(&prefix_path, prefix_bytes).unwrap();
        let plan_path = write_json(
            &directory,
            "plan.json",
            &valid_plan(&directory, &prefix_path),
        );
        let mut changed = fs::read(&plan_path).unwrap();
        *changed.last_mut().unwrap() = b' ';

        assert!(matches!(
            load_production_dory_v3_final_receipt_orchestration_plan_with_final_reauthentication_hook(
                &plan_path,
                ceremony_id,
                || {
                    fs::write(&plan_path, changed).unwrap();
                    Ok(())
                }
            ),
            Err(ProductionDoryV3FinalReceiptOrchestrationError::InputChanged(path))
                if path == plan_path
        ));
    }

    #[cfg(windows)]
    #[test]
    fn retained_windows_plan_and_prefix_handles_deny_write_until_load_finishes() {
        let directory = TestDirectory::new();
        let (prefix_bytes, ceremony_id) = reveal_set_prefix_fixture();
        let prefix_path = directory.path("reveal-set-closed.cmfd");
        fs::write(&prefix_path, prefix_bytes).unwrap();
        let plan_path = write_json(
            &directory,
            "plan.json",
            &valid_plan(&directory, &prefix_path),
        );
        let mut plan_write_denied = false;
        let mut prefix_write_denied = false;

        let loaded =
            load_production_dory_v3_final_receipt_orchestration_plan_with_final_reauthentication_hook(
                &plan_path,
                ceremony_id,
                || {
                    plan_write_denied = fs::OpenOptions::new()
                        .write(true)
                        .open(&plan_path)
                        .is_err();
                    prefix_write_denied = fs::OpenOptions::new()
                        .write(true)
                        .open(&prefix_path)
                        .is_err();
                    Ok(())
                },
            )
            .unwrap();
        assert!(plan_write_denied);
        assert!(prefix_write_denied);
        assert_eq!(loaded.ceremony_id(), ceremony_id);
    }
}
