//! Exact-roster retained validation for one production Dory V3 final candidate.
//!
//! This module deliberately stops before type-6 authoring. A self-declared
//! `Independent` report is never sufficient to mint this aggregate or
//! activation authority: every such report must carry its exact retained
//! CMFDIL capability.

use std::{
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ModelBankManifest,
    dory_v3_model_bank_record_validation::{
        ProductionDoryV3ModelBankRecordValidationError,
        ValidatedProductionDoryV3ModelBankRecordChain,
        validate_existing_production_dory_v3_model_bank_record_chain,
    },
    dory_v3_model_ceremony_fs::{AuthenticatedInput, CeremonyFsError, TrustedCeremonyParent},
    dory_v3_model_ceremony_transcript::{
        CeremonyTranscriptError, FileIdentity, PRODUCTION_BANK_BYTES, VerifiedCeremonyTranscript,
    },
    dory_v3_model_combiner::{
        ProductionDoryV3ModelCombinerError, ValidatedProductionDoryV3ModelCombinedPayload,
        validate_existing_production_dory_v3_model_combined_payload,
    },
    dory_v3_model_independent_lineage::{
        ProductionDoryV3IndependentLineageError, VerifiedIndependentLineage,
    },
    dory_v3_model_reproduction::{
        ContextVerifiedProductionDoryV3ModelReproductionReport,
        PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES, ProductionDoryV3ModelFinalCandidate,
        ProductionDoryV3ModelReproductionReportError,
        ProductionDoryV3ReproductionImplementationKind,
        parse_production_dory_v3_model_reproduction_report,
        verify_production_dory_v3_model_reproduction_report,
    },
    dory_v3_model_roots::{
        PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES, ProductionDoryV3ModelRoots,
        ProductionDoryV3ModelRootsError, validate_production_dory_v3_model_roots_against_payload,
    },
    dory_v3_model_structure::{
        PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES, ProductionDoryV3ModelStructuralReport,
        ProductionDoryV3ModelStructureError, analyze_production_dory_v3_model_structure,
        verify_production_dory_v3_model_structural_report,
    },
    dory_v3_suite::Digest32,
};

const STREAM_BUFFER_BYTES: usize = 64 * 1024;

/// Shared artifact paths for one candidate. Every path must be an absolute,
/// normalized direct child of a trusted ceremony directory.
#[derive(Clone, Copy, Debug)]
pub struct ProductionDoryV3ModelFinalCandidatePaths<'a> {
    pub source_bundle: &'a Path,
    pub source_bundle_policy: &'a Path,
    pub raw_payload: &'a Path,
    pub roots_file: &'a Path,
    pub structural_report: &'a Path,
    pub bank_file: &'a Path,
    pub manifest_file: &'a Path,
    pub record_v2_file: &'a Path,
}

/// Reproducer-specific files named by one `CMFDRP01` report.
#[derive(Clone, Copy, Debug)]
pub struct ProductionDoryV3ModelReproducerCandidatePaths<'a> {
    pub reproduction_report: &'a Path,
    pub combiner_binary: &'a Path,
    pub combiner_report: &'a Path,
    pub bootstrap_report: &'a Path,
    pub record_ceremony_report: &'a Path,
    pub host_environment_report: &'a Path,
    pub source_extraction_report: &'a Path,
    pub command_log: &'a Path,
    pub implementation_lineage_report: &'a Path,
}

struct VerifiedIndependentLineageBinding {
    reproduction_report: FileIdentity,
    lineage: VerifiedIndependentLineage,
}

/// Opaque evidence that strict CMFDIL verification authenticated every
/// independently implemented reproducer and found at least one such lineage.
///
/// Construction consumes the exact ordered Independent subset of one complete,
/// ordered reproducer roster. The aggregate retains the real CMFDIL
/// capabilities and exposes no per-report activation authority.
#[must_use]
pub struct VerifiedProductionDoryV3ReproducerLineages {
    ceremony_id: [u8; 32],
    independent: Vec<VerifiedIndependentLineageBinding>,
}

/// Opaque, non-cloneable, non-serializable result of validating one exact-roster
/// candidate. It is not a type-6 receipt and exposes no per-reproducer authority.
#[must_use]
pub struct ValidatedProductionDoryV3ModelFinalCandidate {
    inner: ValidatedFinalCandidateCore<ProductionHeavyRetention>,
}

impl ValidatedProductionDoryV3ModelFinalCandidate {
    pub const fn ceremony_id(&self) -> [u8; 32] {
        self.inner.ceremony_id
    }

    pub fn reproducer_count(&self) -> usize {
        self.inner.reports.len()
    }

    /// Recheck all retained names and trusted parents without repeating the
    /// full multi-gigabyte semantic validation. The bank is checked last.
    pub fn recheck_retained_files(
        &mut self,
    ) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        self.inner.recheck_retained_files()
    }
}

/// Fail-closed errors from exact-roster final-candidate validation.
#[derive(Debug, Error)]
pub enum ProductionDoryV3ModelFinalCandidateValidationError {
    #[error("expected exactly {expected} ordered reproducer bundles, observed {actual}")]
    ReproducerCount { expected: usize, actual: usize },
    #[error("expected exactly {expected} ordered contribution paths, observed {actual}")]
    ContributionCount { expected: usize, actual: usize },
    #[error("reproduction report inputs {first} and {second} resolve to the same retained file")]
    DuplicateReproductionReport { first: usize, second: usize },
    #[error("artifact paths for {first} and {second} must be distinct")]
    ArtifactPathsNotDistinct { first: String, second: String },
    #[error("artifacts {first} and {second} resolve to the same retained file")]
    AliasedArtifacts { first: String, second: String },
    #[error("trusted filesystem validation failed for {role}: {detail}")]
    TrustedFilesystem { role: String, detail: String },
    #[error("failed to read retained artifact {role}: {source}")]
    ArtifactRead {
        role: String,
        #[source]
        source: std::io::Error,
    },
    #[error("retained artifact {role} does not match its exact claimed content identity")]
    ArtifactIdentity { role: String },
    #[error("reproduction report {index} is invalid: {source}")]
    ReproductionReport {
        index: usize,
        #[source]
        source: ProductionDoryV3ModelReproductionReportError,
    },
    #[error("reproduction report at ordered position {position} declares index {actual}")]
    ReproducerOrder { position: usize, actual: u16 },
    #[error(
        "the verified lineage capability does not cover the exact ordered independent reports: {0}"
    )]
    IndependentLineage(&'static str),
    #[error(
        "retained independent-lineage evidence for reproducer {reproducer_index} failed reauthentication: {source}"
    )]
    IndependentLineageEvidence {
        reproducer_index: u16,
        #[source]
        source: ProductionDoryV3IndependentLineageError,
    },
    #[error("invalid reveal-set-closed transcript while verifying reproducer lineages: {0}")]
    LineageTranscript(#[source] CeremonyTranscriptError),
    #[error("fresh combined-payload validation failed: {0}")]
    Combined(#[source] ProductionDoryV3ModelCombinerError),
    #[error("production roots validation failed: {0}")]
    Roots(#[source] ProductionDoryV3ModelRootsError),
    #[error("production structural validation failed: {0}")]
    Structure(#[source] ProductionDoryV3ModelStructureError),
    #[error("production bank/manifest/Record V2 validation failed: {0}")]
    BankRecord(#[source] ProductionDoryV3ModelBankRecordValidationError),
    #[error("the retained reproduction reports do not name one identical final candidate")]
    CandidateMismatch,
    #[error("validated candidate cross-binding failed: {0}")]
    CrossBinding(&'static str),
}

/// Validate every exact-roster report and all shared candidate artifacts once.
///
/// This function does not author, sign, stage, or publish a type-6 record. All
/// report, source, audit, and shared artifact handles are opened before any
/// reproduction report is parsed.
pub fn validate_existing_production_dory_v3_model_final_candidate(
    transcript: &VerifiedCeremonyTranscript,
    lineages: VerifiedProductionDoryV3ReproducerLineages,
    ordered_contribution_paths: &[PathBuf],
    paths: ProductionDoryV3ModelFinalCandidatePaths<'_>,
    reproducers: &[ProductionDoryV3ModelReproducerCandidatePaths<'_>],
) -> Result<
    ValidatedProductionDoryV3ModelFinalCandidate,
    ProductionDoryV3ModelFinalCandidateValidationError,
> {
    let inner = validate_with_backend(
        transcript,
        lineages,
        ordered_contribution_paths,
        paths,
        reproducers,
        &mut ProductionValidationBackend,
    )?;
    Ok(ValidatedProductionDoryV3ModelFinalCandidate { inner })
}

struct RetainedArtifact {
    role: String,
    input: AuthenticatedInput,
    parent: TrustedCeremonyParent,
    expected_bytes: Option<u64>,
    expected_identity: Option<FileIdentity>,
}

impl RetainedArtifact {
    fn open(
        role: impl Into<String>,
        path: &Path,
        expected_bytes: Option<u64>,
    ) -> Result<Self, ProductionDoryV3ModelFinalCandidateValidationError> {
        let role = role.into();
        let parent =
            TrustedCeremonyParent::for_artifact(path).map_err(|error| map_fs(&role, error))?;
        let input = AuthenticatedInput::open(&parent, path, expected_bytes)
            .map_err(|error| map_fs(&role, error))?;
        Ok(Self {
            role,
            input,
            parent,
            expected_bytes,
            expected_identity: None,
        })
    }

    fn read_exact(
        &mut self,
        expected_bytes: usize,
    ) -> Result<Vec<u8>, ProductionDoryV3ModelFinalCandidateValidationError> {
        let bytes = self
            .input
            .read_bounded(expected_bytes)
            .map_err(|error| map_fs(&self.role, error))?;
        self.recheck(Some(expected_bytes as u64))?;
        if bytes.len() != expected_bytes {
            return Err(
                ProductionDoryV3ModelFinalCandidateValidationError::ArtifactIdentity {
                    role: self.role.clone(),
                },
            );
        }
        Ok(bytes)
    }

    fn authenticate(
        &mut self,
        expected: &FileIdentity,
    ) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        let observed = hash_exact_retained(&mut self.input, &self.role, expected.bytes)?;
        self.recheck(Some(expected.bytes))?;
        if &observed != expected {
            return Err(
                ProductionDoryV3ModelFinalCandidateValidationError::ArtifactIdentity {
                    role: self.role.clone(),
                },
            );
        }
        self.expected_bytes = Some(expected.bytes);
        self.expected_identity = Some(expected.clone());
        Ok(())
    }

    fn bind_identity(&mut self, expected: &FileIdentity) {
        self.expected_bytes = Some(expected.bytes);
        self.expected_identity = Some(expected.clone());
    }

    fn recheck(
        &self,
        expected_bytes: Option<u64>,
    ) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        self.input
            .recheck(&self.parent, expected_bytes)
            .map_err(|error| map_fs(&self.role, error))
    }

    fn recheck_expected(&self) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        self.recheck(self.expected_bytes)
    }

    fn reauthenticate_or_recheck(
        &mut self,
    ) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        if let Some(expected) = self.expected_identity.clone() {
            self.authenticate(&expected)
        } else {
            self.recheck_expected()
        }
    }
}

struct RetainedSharedArtifacts {
    source_bundle: RetainedArtifact,
    source_bundle_policy: RetainedArtifact,
    raw_payload: RetainedArtifact,
    roots_file: RetainedArtifact,
    structural_report: RetainedArtifact,
    bank_file: RetainedArtifact,
    manifest_file: RetainedArtifact,
    record_v2_file: RetainedArtifact,
}

struct RetainedReproducerArtifacts {
    reproduction_report: RetainedArtifact,
    combiner_binary: RetainedArtifact,
    combiner_report: RetainedArtifact,
    bootstrap_report: RetainedArtifact,
    record_ceremony_report: RetainedArtifact,
    host_environment_report: RetainedArtifact,
    source_extraction_report: RetainedArtifact,
    command_log: RetainedArtifact,
    implementation_lineage_report: RetainedArtifact,
}

struct RetainedCandidateArtifacts {
    shared: RetainedSharedArtifacts,
    contributions: Vec<RetainedArtifact>,
    reproducers: Vec<RetainedReproducerArtifacts>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuardRecheckTarget {
    SourceBundle,
    SourceBundlePolicy,
    Contribution(usize),
    ReproductionReport(usize),
    CombinerBinary(usize),
    CombinerReport(usize),
    BootstrapReport(usize),
    RecordCeremonyReport(usize),
    HostEnvironmentReport(usize),
    SourceExtractionReport(usize),
    CommandLog(usize),
    ImplementationLineageReport(usize),
    RawPayload,
    RootsFile,
    StructuralReport,
    ManifestFile,
    RecordV2File,
    BankFile,
}

fn final_guard_recheck_order(
    contribution_count: usize,
    reproducer_count: usize,
) -> Vec<GuardRecheckTarget> {
    let mut order = Vec::with_capacity(8 + contribution_count + reproducer_count.saturating_mul(9));
    order.push(GuardRecheckTarget::SourceBundle);
    order.push(GuardRecheckTarget::SourceBundlePolicy);
    for index in 0..contribution_count {
        order.push(GuardRecheckTarget::Contribution(index));
    }
    for index in 0..reproducer_count {
        order.push(GuardRecheckTarget::ReproductionReport(index));
        order.push(GuardRecheckTarget::CombinerBinary(index));
        order.push(GuardRecheckTarget::CombinerReport(index));
        order.push(GuardRecheckTarget::BootstrapReport(index));
        order.push(GuardRecheckTarget::RecordCeremonyReport(index));
        order.push(GuardRecheckTarget::HostEnvironmentReport(index));
        order.push(GuardRecheckTarget::SourceExtractionReport(index));
        order.push(GuardRecheckTarget::CommandLog(index));
        order.push(GuardRecheckTarget::ImplementationLineageReport(index));
    }
    order.push(GuardRecheckTarget::RawPayload);
    order.push(GuardRecheckTarget::RootsFile);
    order.push(GuardRecheckTarget::StructuralReport);
    order.push(GuardRecheckTarget::ManifestFile);
    order.push(GuardRecheckTarget::RecordV2File);
    order.push(GuardRecheckTarget::BankFile);
    order
}

fn ensure_distinct_supplied_paths(
    shared: ProductionDoryV3ModelFinalCandidatePaths<'_>,
    ordered_contribution_paths: &[PathBuf],
    reproducers: &[ProductionDoryV3ModelReproducerCandidatePaths<'_>],
) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
    let mut entries = vec![
        ("source bundle".to_owned(), shared.source_bundle),
        (
            "source bundle policy".to_owned(),
            shared.source_bundle_policy,
        ),
        ("raw payload".to_owned(), shared.raw_payload),
        ("roots file".to_owned(), shared.roots_file),
        ("structural report".to_owned(), shared.structural_report),
        ("model bank".to_owned(), shared.bank_file),
        ("manifest".to_owned(), shared.manifest_file),
        ("Record V2".to_owned(), shared.record_v2_file),
    ];
    for (index, path) in ordered_contribution_paths.iter().enumerate() {
        entries.push((format!("ordered contribution {index}"), path));
    }
    for (index, paths) in reproducers.iter().enumerate() {
        entries.extend([
            (
                format!("reproducer {index} reproduction report"),
                paths.reproduction_report,
            ),
            (
                format!("reproducer {index} combiner binary"),
                paths.combiner_binary,
            ),
            (
                format!("reproducer {index} combiner report"),
                paths.combiner_report,
            ),
            (
                format!("reproducer {index} bootstrap report"),
                paths.bootstrap_report,
            ),
            (
                format!("reproducer {index} record ceremony report"),
                paths.record_ceremony_report,
            ),
            (
                format!("reproducer {index} host environment report"),
                paths.host_environment_report,
            ),
            (
                format!("reproducer {index} source extraction report"),
                paths.source_extraction_report,
            ),
            (format!("reproducer {index} command log"), paths.command_log),
            (
                format!("reproducer {index} implementation lineage report"),
                paths.implementation_lineage_report,
            ),
        ]);
    }
    for second in 0..entries.len() {
        for first in 0..second {
            if entries[first].1 == entries[second].1 {
                return Err(
                    ProductionDoryV3ModelFinalCandidateValidationError::ArtifactPathsNotDistinct {
                        first: entries[first].0.clone(),
                        second: entries[second].0.clone(),
                    },
                );
            }
        }
    }
    Ok(())
}

impl RetainedCandidateArtifacts {
    fn open_all(
        paths: ProductionDoryV3ModelFinalCandidatePaths<'_>,
        ordered_contribution_paths: &[PathBuf],
        reproducers: &[ProductionDoryV3ModelReproducerCandidatePaths<'_>],
    ) -> Result<Self, ProductionDoryV3ModelFinalCandidateValidationError> {
        ensure_distinct_supplied_paths(paths, ordered_contribution_paths, reproducers)?;
        let shared = RetainedSharedArtifacts {
            source_bundle: RetainedArtifact::open("source bundle", paths.source_bundle, None)?,
            source_bundle_policy: RetainedArtifact::open(
                "source bundle policy",
                paths.source_bundle_policy,
                None,
            )?,
            raw_payload: RetainedArtifact::open(
                "raw payload",
                paths.raw_payload,
                Some(crate::dory_v3_model_roots::PRODUCTION_DORY_V3_PAYLOAD_BYTES),
            )?,
            roots_file: RetainedArtifact::open(
                "roots file",
                paths.roots_file,
                Some(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES as u64),
            )?,
            structural_report: RetainedArtifact::open(
                "structural report",
                paths.structural_report,
                Some(PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES as u64),
            )?,
            bank_file: RetainedArtifact::open(
                "model bank",
                paths.bank_file,
                Some(PRODUCTION_BANK_BYTES),
            )?,
            manifest_file: RetainedArtifact::open("manifest", paths.manifest_file, None)?,
            record_v2_file: RetainedArtifact::open("Record V2", paths.record_v2_file, None)?,
        };

        let mut contributions = Vec::with_capacity(ordered_contribution_paths.len());
        for (index, path) in ordered_contribution_paths.iter().enumerate() {
            contributions.push(RetainedArtifact::open(
                format!("ordered contribution {index}"),
                path,
                Some(crate::dory_v3_model_roots::PRODUCTION_DORY_V3_PAYLOAD_BYTES),
            )?);
        }

        let mut retained_reproducers = Vec::with_capacity(reproducers.len());
        for (index, paths) in reproducers.iter().enumerate() {
            retained_reproducers.push(RetainedReproducerArtifacts {
                reproduction_report: RetainedArtifact::open(
                    format!("reproducer {index} reproduction report"),
                    paths.reproduction_report,
                    Some(PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES as u64),
                )?,
                combiner_binary: RetainedArtifact::open(
                    format!("reproducer {index} combiner binary"),
                    paths.combiner_binary,
                    None,
                )?,
                combiner_report: RetainedArtifact::open(
                    format!("reproducer {index} combiner report"),
                    paths.combiner_report,
                    None,
                )?,
                bootstrap_report: RetainedArtifact::open(
                    format!("reproducer {index} bootstrap report"),
                    paths.bootstrap_report,
                    None,
                )?,
                record_ceremony_report: RetainedArtifact::open(
                    format!("reproducer {index} record ceremony report"),
                    paths.record_ceremony_report,
                    None,
                )?,
                host_environment_report: RetainedArtifact::open(
                    format!("reproducer {index} host environment report"),
                    paths.host_environment_report,
                    None,
                )?,
                source_extraction_report: RetainedArtifact::open(
                    format!("reproducer {index} source extraction report"),
                    paths.source_extraction_report,
                    None,
                )?,
                command_log: RetainedArtifact::open(
                    format!("reproducer {index} command log"),
                    paths.command_log,
                    None,
                )?,
                implementation_lineage_report: RetainedArtifact::open(
                    format!("reproducer {index} implementation lineage report"),
                    paths.implementation_lineage_report,
                    None,
                )?,
            });
        }

        for second in 0..retained_reproducers.len() {
            for first in 0..second {
                if retained_reproducers[first]
                    .reproduction_report
                    .input
                    .identity()
                    == retained_reproducers[second]
                        .reproduction_report
                        .input
                        .identity()
                {
                    return Err(ProductionDoryV3ModelFinalCandidateValidationError::
                        DuplicateReproductionReport { first, second });
                }
            }
        }

        let retained = Self {
            shared,
            contributions,
            reproducers: retained_reproducers,
        };
        retained.ensure_distinct_inputs()?;
        Ok(retained)
    }

    fn ensure_distinct_inputs(
        &self,
    ) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        let mut seen: Vec<(String, crate::dory_v3_model_ceremony_fs::FileIdentity)> = Vec::new();
        let mut observe = |artifact: &RetainedArtifact| {
            let identity = artifact.input.identity();
            if let Some((first, _)) = seen.iter().find(|(_, existing)| *existing == identity) {
                return Err(
                    ProductionDoryV3ModelFinalCandidateValidationError::AliasedArtifacts {
                        first: first.clone(),
                        second: artifact.role.clone(),
                    },
                );
            }
            seen.push((artifact.role.clone(), identity));
            Ok(())
        };

        observe(&self.shared.source_bundle)?;
        observe(&self.shared.source_bundle_policy)?;
        observe(&self.shared.raw_payload)?;
        observe(&self.shared.roots_file)?;
        observe(&self.shared.structural_report)?;
        observe(&self.shared.bank_file)?;
        observe(&self.shared.manifest_file)?;
        observe(&self.shared.record_v2_file)?;
        for contribution in &self.contributions {
            observe(contribution)?;
        }
        for reproducer in &self.reproducers {
            observe(&reproducer.reproduction_report)?;
            observe(&reproducer.combiner_binary)?;
            observe(&reproducer.combiner_report)?;
            observe(&reproducer.bootstrap_report)?;
            observe(&reproducer.record_ceremony_report)?;
            observe(&reproducer.host_environment_report)?;
            observe(&reproducer.source_extraction_report)?;
            observe(&reproducer.command_log)?;
            observe(&reproducer.implementation_lineage_report)?;
        }
        Ok(())
    }

    fn recheck_except_bank(
        &mut self,
    ) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        for target in final_guard_recheck_order(self.contributions.len(), self.reproducers.len()) {
            if target == GuardRecheckTarget::BankFile {
                break;
            }
            self.recheck_target(target)?;
        }
        Ok(())
    }

    fn recheck_target(
        &mut self,
        target: GuardRecheckTarget,
    ) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        let artifact = match target {
            GuardRecheckTarget::SourceBundle => &mut self.shared.source_bundle,
            GuardRecheckTarget::SourceBundlePolicy => &mut self.shared.source_bundle_policy,
            GuardRecheckTarget::Contribution(index) => &mut self.contributions[index],
            GuardRecheckTarget::ReproductionReport(index) => {
                &mut self.reproducers[index].reproduction_report
            }
            GuardRecheckTarget::CombinerBinary(index) => {
                &mut self.reproducers[index].combiner_binary
            }
            GuardRecheckTarget::CombinerReport(index) => {
                &mut self.reproducers[index].combiner_report
            }
            GuardRecheckTarget::BootstrapReport(index) => {
                &mut self.reproducers[index].bootstrap_report
            }
            GuardRecheckTarget::RecordCeremonyReport(index) => {
                &mut self.reproducers[index].record_ceremony_report
            }
            GuardRecheckTarget::HostEnvironmentReport(index) => {
                &mut self.reproducers[index].host_environment_report
            }
            GuardRecheckTarget::SourceExtractionReport(index) => {
                &mut self.reproducers[index].source_extraction_report
            }
            GuardRecheckTarget::CommandLog(index) => &mut self.reproducers[index].command_log,
            GuardRecheckTarget::ImplementationLineageReport(index) => {
                &mut self.reproducers[index].implementation_lineage_report
            }
            GuardRecheckTarget::RawPayload => &mut self.shared.raw_payload,
            GuardRecheckTarget::RootsFile => &mut self.shared.roots_file,
            GuardRecheckTarget::StructuralReport => &mut self.shared.structural_report,
            GuardRecheckTarget::ManifestFile => &mut self.shared.manifest_file,
            GuardRecheckTarget::RecordV2File => &mut self.shared.record_v2_file,
            GuardRecheckTarget::BankFile => &mut self.shared.bank_file,
        };
        if target == GuardRecheckTarget::BankFile {
            artifact.recheck_expected()
        } else {
            artifact.reauthenticate_or_recheck()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CandidateIdentity {
    raw_payload: FileIdentity,
    base_input_blake3_root: [u8; 32],
    layer_roots_aggregate: [u8; 32],
    roots_file: FileIdentity,
    structural_report: FileIdentity,
    bank_file: FileIdentity,
    manifest_file: FileIdentity,
    manifest_digest: [u8; 32],
    production_suite_digest: [u8; 32],
    pcs_parameter_digest: [u8; 32],
    commitments: [[u8; 576]; 4],
    pcs_commitment_root: [u8; 32],
    model_identity_digest: [u8; 32],
    setup_identity: [u8; 32],
    padded_variables: u32,
    record_v2_file: FileIdentity,
    record_v2_digest: [u8; 32],
}

impl From<ProductionDoryV3ModelFinalCandidate<'_>> for CandidateIdentity {
    fn from(value: ProductionDoryV3ModelFinalCandidate<'_>) -> Self {
        Self {
            raw_payload: value.raw_payload.clone(),
            base_input_blake3_root: value.base_input_blake3_root,
            layer_roots_aggregate: value.layer_roots_aggregate,
            roots_file: value.roots_file.clone(),
            structural_report: value.structural_report.clone(),
            bank_file: value.bank_file.clone(),
            manifest_file: value.manifest_file.clone(),
            manifest_digest: value.manifest_digest,
            production_suite_digest: value.production_suite_digest,
            pcs_parameter_digest: value.pcs_parameter_digest,
            commitments: [
                *value.base_commitment,
                *value.weight_bank_0_commitment,
                *value.weight_bank_1_commitment,
                *value.weight_bank_2_commitment,
            ],
            pcs_commitment_root: value.pcs_commitment_root,
            model_identity_digest: value.model_identity_digest,
            setup_identity: value.setup_identity,
            padded_variables: value.padded_variables,
            record_v2_file: value.record_v2_file.clone(),
            record_v2_digest: value.record_v2_digest,
        }
    }
}

#[derive(Clone, Debug)]
struct HeavyCandidateObservation {
    roots_ceremony_id: [u8; 32],
    roots_payload_bytes: u64,
    roots_raw_blake3: [u8; 32],
    roots_raw_sha256: [u8; 32],
    roots_base_input_blake3_root: [u8; 32],
    roots_layer_roots_aggregate: [u8; 32],
    structure_ceremony_id: [u8; 32],
    structure_payload_bytes: u64,
    structure_raw_blake3: [u8; 32],
    structure_raw_sha256: [u8; 32],
    bank_file: FileIdentity,
    manifest_file: FileIdentity,
    record_v2_file: FileIdentity,
    manifest: ModelBankManifest,
    record_suite_digest: [u8; 32],
    record_manifest_digest: [u8; 32],
    record_model_identity_digest: [u8; 32],
    record_setup_identity: [u8; 32],
    record_padded_variables: u32,
    record_commitment_root: [u8; 32],
    record_digest: [u8; 32],
    record_model_byte_root: [u8; 32],
    record_layer_roots_aggregate: [u8; 32],
    record_suite_parameter_digest: [u8; 32],
    record_commitments: [[u8; 576]; 4],
}

struct ProductionHeavyRetention {
    _roots: ProductionDoryV3ModelRoots,
    _structure: ProductionDoryV3ModelStructuralReport,
    bank_chain: ValidatedProductionDoryV3ModelBankRecordChain,
}

struct HeavyValidation<R> {
    observation: HeavyCandidateObservation,
    retention: R,
}

trait FinalCandidateValidationBackend {
    type Retention;

    fn validate_combined(
        &mut self,
        transcript: &VerifiedCeremonyTranscript,
        ordered_contribution_paths: &[PathBuf],
        raw_payload_path: &Path,
    ) -> Result<
        ValidatedProductionDoryV3ModelCombinedPayload,
        ProductionDoryV3ModelFinalCandidateValidationError,
    >;

    fn validate_heavy_candidate(
        &mut self,
        ceremony_id: [u8; 32],
        paths: ProductionDoryV3ModelFinalCandidatePaths<'_>,
        retained: &mut RetainedSharedArtifacts,
        roots_bytes: &[u8],
        structural_report_bytes: &[u8],
    ) -> Result<HeavyValidation<Self::Retention>, ProductionDoryV3ModelFinalCandidateValidationError>;
}

struct ProductionValidationBackend;

impl FinalCandidateValidationBackend for ProductionValidationBackend {
    type Retention = ProductionHeavyRetention;

    fn validate_combined(
        &mut self,
        transcript: &VerifiedCeremonyTranscript,
        ordered_contribution_paths: &[PathBuf],
        raw_payload_path: &Path,
    ) -> Result<
        ValidatedProductionDoryV3ModelCombinedPayload,
        ProductionDoryV3ModelFinalCandidateValidationError,
    > {
        validate_existing_production_dory_v3_model_combined_payload(
            transcript,
            ordered_contribution_paths,
            raw_payload_path,
        )
        .map_err(ProductionDoryV3ModelFinalCandidateValidationError::Combined)
    }

    fn validate_heavy_candidate(
        &mut self,
        ceremony_id: [u8; 32],
        paths: ProductionDoryV3ModelFinalCandidatePaths<'_>,
        retained: &mut RetainedSharedArtifacts,
        roots_bytes: &[u8],
        structural_report_bytes: &[u8],
    ) -> Result<HeavyValidation<Self::Retention>, ProductionDoryV3ModelFinalCandidateValidationError>
    {
        let roots = validate_production_dory_v3_model_roots_against_payload(
            roots_bytes,
            retained.raw_payload.input.file_mut(),
            Digest32::new(ceremony_id),
        )
        .map_err(ProductionDoryV3ModelFinalCandidateValidationError::Roots)?;
        let structure = verify_production_dory_v3_model_structural_report(
            retained.raw_payload.input.file_mut(),
            structural_report_bytes,
            &roots,
        )
        .map_err(ProductionDoryV3ModelFinalCandidateValidationError::Structure)?;
        let second_structure = analyze_production_dory_v3_model_structure(
            retained.raw_payload.input.file_mut(),
            &roots,
        )
        .map_err(ProductionDoryV3ModelFinalCandidateValidationError::Structure)?;
        if second_structure != structure
            || second_structure.canonical_bytes() != structural_report_bytes
        {
            return Err(
                ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                    "second independent structural analysis",
                ),
            );
        }

        let bank_chain = validate_existing_production_dory_v3_model_bank_record_chain(
            paths.bank_file,
            paths.manifest_file,
            paths.record_v2_file,
        )
        .map_err(ProductionDoryV3ModelFinalCandidateValidationError::BankRecord)?;
        if bank_chain.retained_bank_filesystem_identity() != retained.bank_file.input.identity() {
            return Err(
                ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                    "bank retained filesystem identity",
                ),
            );
        }
        let observation = production_observation(&roots, &structure, &bank_chain)?;
        Ok(HeavyValidation {
            observation,
            retention: ProductionHeavyRetention {
                _roots: roots,
                _structure: structure,
                bank_chain,
            },
        })
    }
}

struct ValidatedFinalCandidateCore<R> {
    ceremony_id: [u8; 32],
    lineages: VerifiedProductionDoryV3ReproducerLineages,
    _combined: ValidatedProductionDoryV3ModelCombinedPayload,
    reports: Vec<ContextVerifiedProductionDoryV3ModelReproductionReport>,
    retained: RetainedCandidateArtifacts,
    heavy: R,
}

impl ValidatedFinalCandidateCore<ProductionHeavyRetention> {
    fn recheck_retained_files(
        &mut self,
    ) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        self.retained.recheck_except_bank()?;
        self.lineages.recheck_retained_files()?;
        self.heavy
            .bank_chain
            .recheck_retained_files()
            .map_err(ProductionDoryV3ModelFinalCandidateValidationError::BankRecord)?;
        self.retained.recheck_target(GuardRecheckTarget::BankFile)
    }
}

fn validate_with_backend<B: FinalCandidateValidationBackend>(
    transcript: &VerifiedCeremonyTranscript,
    mut lineages: VerifiedProductionDoryV3ReproducerLineages,
    ordered_contribution_paths: &[PathBuf],
    paths: ProductionDoryV3ModelFinalCandidatePaths<'_>,
    reproducer_paths: &[ProductionDoryV3ModelReproducerCandidatePaths<'_>],
    backend: &mut B,
) -> Result<
    ValidatedFinalCandidateCore<B::Retention>,
    ProductionDoryV3ModelFinalCandidateValidationError,
> {
    let expected_reproducers = transcript.reproducers().len();
    require_exact_reproducer_count(expected_reproducers, reproducer_paths.len())?;
    let expected_contributions = transcript.operators().len();
    require_exact_contribution_count(expected_contributions, ordered_contribution_paths.len())?;

    let mut retained =
        RetainedCandidateArtifacts::open_all(paths, ordered_contribution_paths, reproducer_paths)?;
    let mut report_bytes = Vec::with_capacity(expected_reproducers);
    for reproducer in &mut retained.reproducers {
        report_bytes.push(
            reproducer
                .reproduction_report
                .read_exact(PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES)?,
        );
    }

    let mut parsed_indices = Vec::with_capacity(report_bytes.len());
    for (position, bytes) in report_bytes.iter().enumerate() {
        let parsed =
            parse_production_dory_v3_model_reproduction_report(bytes).map_err(|source| {
                ProductionDoryV3ModelFinalCandidateValidationError::ReproductionReport {
                    index: position,
                    source,
                }
            })?;
        parsed_indices.push(parsed.reproducer_index());
    }
    require_ordered_reproducer_indices(&parsed_indices)?;

    // Reauthenticate every retained CMFDIL artifact and its eleven evidence
    // files immediately before the first expensive payload validation.
    lineages.recheck_retained_files()?;
    let combined =
        backend.validate_combined(transcript, ordered_contribution_paths, paths.raw_payload)?;
    require_exact_contribution_count(
        expected_contributions,
        combined.report().ordered_inputs.len(),
    )?;
    for (retained_input, combined_input) in retained
        .contributions
        .iter_mut()
        .zip(&combined.report().ordered_inputs)
    {
        retained_input.recheck(Some(combined_input.contribution_bytes))?;
        retained_input.expected_bytes = Some(combined_input.contribution_bytes);
    }
    let mut reports = Vec::with_capacity(expected_reproducers);
    for (index, bytes) in report_bytes.iter().enumerate() {
        reports.push(
            verify_production_dory_v3_model_reproduction_report(bytes, transcript, &combined)
                .map_err(|source| {
                    ProductionDoryV3ModelFinalCandidateValidationError::ReproductionReport {
                        index,
                        source,
                    }
                })?,
        );
    }

    let Some(_) = reports.first() else {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::ReproducerCount {
                expected: expected_reproducers,
                actual: 0,
            },
        );
    };
    let candidate_identities: Vec<_> = reports
        .iter()
        .map(|report| CandidateIdentity::from(report.final_candidate()))
        .collect();
    require_same_candidates(&candidate_identities)?;
    lineages.validate(transcript.ceremony_id(), &reports)?;
    let candidate = candidate_identities[0].clone();

    authenticate_report_artifacts(&mut retained, &reports)?;
    let roots_bytes = retained
        .shared
        .roots_file
        .read_exact(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES)?;
    require_content_identity("roots file", &roots_bytes, &candidate.roots_file)?;
    retained
        .shared
        .roots_file
        .bind_identity(&candidate.roots_file);
    let structural_report_bytes = retained
        .shared
        .structural_report
        .read_exact(PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES)?;
    require_content_identity(
        "structural report",
        &structural_report_bytes,
        &candidate.structural_report,
    )?;
    retained
        .shared
        .structural_report
        .bind_identity(&candidate.structural_report);

    retained
        .shared
        .raw_payload
        .recheck(Some(candidate.raw_payload.bytes))?;
    retained.shared.raw_payload.expected_bytes = Some(candidate.raw_payload.bytes);
    let heavy = backend.validate_heavy_candidate(
        transcript.ceremony_id(),
        paths,
        &mut retained.shared,
        &roots_bytes,
        &structural_report_bytes,
    )?;
    cross_bind_candidate(
        transcript.ceremony_id(),
        paths.raw_payload,
        &candidate,
        combined.report(),
        &heavy.observation,
    )?;

    retained
        .shared
        .manifest_file
        .bind_identity(&candidate.manifest_file);
    retained
        .shared
        .record_v2_file
        .bind_identity(&candidate.record_v2_file);
    retained.shared.bank_file.expected_bytes = Some(candidate.bank_file.bytes);
    retained.recheck_except_bank()?;
    // The lineage evidence is part of the final guard and must precede the
    // last bank-name/identity check.
    lineages.recheck_retained_files()?;
    retained.recheck_target(GuardRecheckTarget::BankFile)?;

    Ok(ValidatedFinalCandidateCore {
        ceremony_id: transcript.ceremony_id(),
        lineages,
        _combined: combined,
        reports,
        retained,
        heavy: heavy.retention,
    })
}

fn require_exact_reproducer_count(
    expected: usize,
    actual: usize,
) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
    if actual != expected {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::ReproducerCount {
                expected,
                actual,
            },
        );
    }
    Ok(())
}

fn require_exact_contribution_count(
    expected: usize,
    actual: usize,
) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
    if actual != expected {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::ContributionCount {
                expected,
                actual,
            },
        );
    }
    Ok(())
}

fn require_ordered_reproducer_indices(
    indices: &[u16],
) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
    for (position, actual) in indices.iter().copied().enumerate() {
        if usize::from(actual) != position {
            return Err(
                ProductionDoryV3ModelFinalCandidateValidationError::ReproducerOrder {
                    position,
                    actual,
                },
            );
        }
    }
    Ok(())
}

fn require_same_candidates(
    candidates: &[CandidateIdentity],
) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
    let Some(first) = candidates.first() else {
        return Err(ProductionDoryV3ModelFinalCandidateValidationError::CandidateMismatch);
    };
    if candidates
        .iter()
        .skip(1)
        .any(|candidate| candidate != first)
    {
        return Err(ProductionDoryV3ModelFinalCandidateValidationError::CandidateMismatch);
    }
    Ok(())
}

impl VerifiedProductionDoryV3ReproducerLineages {
    /// Verify and retain the exact Independent subset from one complete,
    /// ordered reproducer roster.
    ///
    /// `reports` must contain every context-verified CMFDRP in frozen roster
    /// order. `independent_lineages` is consumed in the corresponding filtered
    /// order and must contain one live CMFDIL capability for each and only each
    /// report whose implementation kind is `Independent`.
    pub fn verify_exact_ordered(
        transcript: &VerifiedCeremonyTranscript,
        reports: &[ContextVerifiedProductionDoryV3ModelReproductionReport],
        independent_lineages: Vec<VerifiedIndependentLineage>,
    ) -> Result<Self, ProductionDoryV3ModelFinalCandidateValidationError> {
        require_exact_reproducer_count(transcript.reproducers().len(), reports.len())?;
        let bindings = transcript
            .require_combiner_bindings()
            .map_err(ProductionDoryV3ModelFinalCandidateValidationError::LineageTranscript)?;
        let expected_prefix = FileIdentity {
            bytes: transcript.transcript_bytes(),
            blake3: transcript.transcript_blake3(),
            sha256: transcript.transcript_sha256(),
        };
        for (position, report) in reports.iter().enumerate() {
            let body = report.report();
            let actual = body.reproducer_index();
            if usize::from(actual) != position {
                return Err(
                    ProductionDoryV3ModelFinalCandidateValidationError::ReproducerOrder {
                        position,
                        actual,
                    },
                );
            }
            if body.ceremony_id() != transcript.ceremony_id()
                || body.reproducer_public_key() != transcript.reproducers()[position]
                || body.reveal_set_prefix_identity() != expected_prefix
                || body.reveal_set_prefix_derive_key_digest()
                    != transcript.transcript_derive_key_digest()
                || body.commitment_set_signed_record_digest()
                    != bindings.commitment_set_signed_record_digest()
                || body.reveal_set_signed_record_digest()
                    != bindings.reveal_set_signed_record_digest()
            {
                return Err(
                    ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                        "CMFDRP transcript or roster binding",
                    ),
                );
            }
        }

        let expected_independent = reports
            .iter()
            .filter(|report| {
                report.report().implementation_kind()
                    == ProductionDoryV3ReproductionImplementationKind::Independent
            })
            .count();
        if expected_independent == 0 {
            return Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                    "no Independent report",
                ),
            );
        }
        if independent_lineages.len() != expected_independent {
            return Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                    "Independent capability count",
                ),
            );
        }

        let ceremony_id = transcript.ceremony_id();
        let mut supplied = independent_lineages.into_iter();
        let mut independent = Vec::with_capacity(expected_independent);
        for report in reports.iter().filter(|report| {
            report.report().implementation_kind()
                == ProductionDoryV3ReproductionImplementationKind::Independent
        }) {
            let mut lineage = supplied
                .next()
                .expect("the exact Independent capability count was checked");
            validate_independent_lineage_binding(ceremony_id, report, &lineage)?;
            validate_independent_lineage_type5_binding(
                &lineage,
                &expected_prefix,
                transcript.transcript_derive_key_digest(),
                bindings.commitment_set_signed_record_digest(),
                bindings.reveal_set_signed_record_digest(),
            )?;
            lineage.recheck_retained_files().map_err(|source| {
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineageEvidence {
                    reproducer_index: report.report().reproducer_index(),
                    source,
                }
            })?;
            independent.push(VerifiedIndependentLineageBinding {
                reproduction_report: report.report().content_identity(),
                lineage,
            });
        }
        debug_assert!(supplied.next().is_none());

        Ok(Self {
            ceremony_id,
            independent,
        })
    }

    fn validate(
        &self,
        ceremony_id: [u8; 32],
        reports: &[ContextVerifiedProductionDoryV3ModelReproductionReport],
    ) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        if self.ceremony_id != ceremony_id {
            return Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                    "ceremony id",
                ),
            );
        }
        let mut independent = self.independent.iter();
        let mut observed = 0_usize;
        for report in reports.iter().filter(|report| {
            report.report().implementation_kind()
                == ProductionDoryV3ReproductionImplementationKind::Independent
        }) {
            observed += 1;
            let binding = independent.next().ok_or(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                    "missing Independent capability",
                ),
            )?;
            if binding.reproduction_report != report.report().content_identity() {
                return Err(
                    ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                        "CMFDRP content identity",
                    ),
                );
            }
            validate_independent_lineage_binding(ceremony_id, report, &binding.lineage)?;
        }
        if observed == 0 || independent.next().is_some() {
            return Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                    "Independent set or order",
                ),
            );
        }
        Ok(())
    }

    fn recheck_retained_files(
        &mut self,
    ) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        for binding in &mut self.independent {
            let reproducer_index = binding.lineage.reproducer_index();
            binding.lineage.recheck_retained_files().map_err(|source| {
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineageEvidence {
                    reproducer_index,
                    source,
                }
            })?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn validate_for_test(
        &self,
        ceremony_id: [u8; 32],
        reports: &[ContextVerifiedProductionDoryV3ModelReproductionReport],
    ) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        self.validate(ceremony_id, reports)
    }

    #[cfg(test)]
    pub(crate) fn recheck_for_test(
        &mut self,
    ) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        self.recheck_retained_files()
    }
}

fn validate_independent_lineage_binding(
    ceremony_id: [u8; 32],
    report: &ContextVerifiedProductionDoryV3ModelReproductionReport,
    lineage: &VerifiedIndependentLineage,
) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
    let report_body = report.report();
    let report_artifacts = report.artifacts();
    let candidate = report.final_candidate();
    let lineage_artifacts = lineage.artifacts();
    if report_body.implementation_kind()
        != ProductionDoryV3ReproductionImplementationKind::Independent
    {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                "Reference report supplied a CMFDIL capability",
            ),
        );
    }
    if report_body.ceremony_id() != ceremony_id || lineage.ceremony_id() != ceremony_id {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage("ceremony id"),
        );
    }
    let report_prefix = report_body.reveal_set_prefix_identity();
    validate_independent_lineage_type5_binding(
        lineage,
        &report_prefix,
        report_body.reveal_set_prefix_derive_key_digest(),
        report_body.commitment_set_signed_record_digest(),
        report_body.reveal_set_signed_record_digest(),
    )?;
    if lineage.reproducer_index() != report_body.reproducer_index()
        || lineage.reproducer_public_key() != report_body.reproducer_public_key()
        || lineage.target_id() != report_body.target_id()
    {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                "reproducer, key, or target",
            ),
        );
    }
    if lineage.artifact_identity() != report_artifacts.implementation_lineage_report {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                "CMFDIL artifact identity",
            ),
        );
    }
    if lineage_artifacts.combiner_binary != report_artifacts.combiner_binary
        || lineage_artifacts.raw_payload != candidate.raw_payload
        || lineage_artifacts.roots_file != candidate.roots_file
        || lineage.base_input_blake3_root() != candidate.base_input_blake3_root
        || lineage.layer_roots_aggregate() != candidate.layer_roots_aggregate
    {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                "combiner or final candidate",
            ),
        );
    }
    if lineage_artifacts.host_environment_report != report_artifacts.host_environment_report
        || lineage_artifacts.source_extraction_report != report_artifacts.source_extraction_report
        || lineage_artifacts.command_log != report_artifacts.command_log
    {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                "host, extraction, or command audit",
            ),
        );
    }
    Ok(())
}

fn validate_independent_lineage_type5_binding(
    lineage: &VerifiedIndependentLineage,
    reveal_set_prefix: &FileIdentity,
    reveal_set_prefix_derive_key_digest: [u8; 32],
    commitment_set_signed_record_digest: [u8; 32],
    reveal_set_signed_record_digest: [u8; 32],
) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
    if lineage.artifacts().reveal_set_prefix != reveal_set_prefix
        || lineage.reveal_set_prefix_derive_key_digest() != reveal_set_prefix_derive_key_digest
        || lineage.commitment_set_signed_record_digest() != commitment_set_signed_record_digest
        || lineage.reveal_set_signed_record_digest() != reveal_set_signed_record_digest
    {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                "type-5 prefix or closure",
            ),
        );
    }
    Ok(())
}

fn authenticate_report_artifacts(
    retained: &mut RetainedCandidateArtifacts,
    reports: &[ContextVerifiedProductionDoryV3ModelReproductionReport],
) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
    let first = reports
        .first()
        .ok_or(ProductionDoryV3ModelFinalCandidateValidationError::CandidateMismatch)?;
    retained
        .shared
        .source_bundle
        .authenticate(first.artifacts().source_bundle)?;
    retained
        .shared
        .source_bundle_policy
        .authenticate(first.artifacts().source_bundle_policy)?;

    for (retained, report) in retained.reproducers.iter_mut().zip(reports) {
        retained
            .reproduction_report
            .authenticate(&report.report().content_identity())?;
        let artifacts = report.artifacts();
        retained
            .combiner_binary
            .authenticate(artifacts.combiner_binary)?;
        retained
            .combiner_report
            .authenticate(artifacts.combiner_report)?;
        retained
            .bootstrap_report
            .authenticate(artifacts.bootstrap_report)?;
        retained
            .record_ceremony_report
            .authenticate(artifacts.record_ceremony_report)?;
        retained
            .host_environment_report
            .authenticate(artifacts.host_environment_report)?;
        retained
            .source_extraction_report
            .authenticate(artifacts.source_extraction_report)?;
        retained.command_log.authenticate(artifacts.command_log)?;
        retained
            .implementation_lineage_report
            .authenticate(artifacts.implementation_lineage_report)?;
    }
    Ok(())
}

fn production_observation(
    roots: &ProductionDoryV3ModelRoots,
    structure: &ProductionDoryV3ModelStructuralReport,
    bank_chain: &ValidatedProductionDoryV3ModelBankRecordChain,
) -> Result<HeavyCandidateObservation, ProductionDoryV3ModelFinalCandidateValidationError> {
    let record = bank_chain.record();
    let identity = record.model_identity();
    let encoded_weights = identity.encoded_weight_bank_commitments();
    if encoded_weights.len() != 3 {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                "Record V2 weight-bank commitment count",
            ),
        );
    }
    let mut commitments = [[0_u8; 576]; 4];
    commitments[0] = commitment_bytes(identity.encoded_base_input_commitment())?;
    for (slot, commitment) in commitments[1..].iter_mut().zip(encoded_weights) {
        *slot = commitment_bytes(commitment)?;
    }
    Ok(HeavyCandidateObservation {
        roots_ceremony_id: roots.ceremony_id().into_bytes(),
        roots_payload_bytes: roots.payload_bytes(),
        roots_raw_blake3: roots.raw_blake3().into_bytes(),
        roots_raw_sha256: roots.raw_sha256().into_bytes(),
        roots_base_input_blake3_root: roots.base_input_blake3_root().into_bytes(),
        roots_layer_roots_aggregate: roots.layer_roots_aggregate().into_bytes(),
        structure_ceremony_id: structure.ceremony_id().into_bytes(),
        structure_payload_bytes: structure.payload_bytes(),
        structure_raw_blake3: structure.raw_payload_blake3().into_bytes(),
        structure_raw_sha256: structure.raw_payload_sha256().into_bytes(),
        bank_file: bank_chain.bank_file().clone(),
        manifest_file: bank_chain.manifest_file().clone(),
        record_v2_file: bank_chain.record_v2_file().clone(),
        manifest: *bank_chain.manifest(),
        record_suite_digest: record.suite_digest().into_bytes(),
        record_manifest_digest: record.manifest_digest().into_bytes(),
        record_model_identity_digest: record.model_identity_digest().into_bytes(),
        record_setup_identity: record.setup_identity().into_bytes(),
        record_padded_variables: record.padded_variables(),
        record_commitment_root: record.commitment_root().into_bytes(),
        record_digest: record.record_digest().into_bytes(),
        record_model_byte_root: identity.model_byte_root(),
        record_layer_roots_aggregate: identity.layer_roots_aggregate(),
        record_suite_parameter_digest: identity.suite_parameter_digest(),
        record_commitments: commitments,
    })
}

fn commitment_bytes(
    commitment: &crate::dory_v3_model::CanonicalBlsDoryGtHex,
) -> Result<[u8; 576], ProductionDoryV3ModelFinalCandidateValidationError> {
    commitment
        .canonical_bytes()
        .map_err(|_| {
            ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                "Record V2 canonical commitment",
            )
        })?
        .try_into()
        .map_err(|_| {
            ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                "Record V2 commitment width",
            )
        })
}

fn cross_bind_candidate(
    ceremony_id: [u8; 32],
    raw_payload_path: &Path,
    candidate: &CandidateIdentity,
    combined: &crate::dory_v3_model_combiner::ProductionDoryV3ModelCombinedPayloadValidationReport,
    observed: &HeavyCandidateObservation,
) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
    let combined_identity = FileIdentity {
        bytes: combined.output_bytes,
        blake3: combined.output_blake3.into_bytes(),
        sha256: combined.output_sha256.into_bytes(),
    };
    if combined.ceremony_id.into_bytes() != ceremony_id
        || combined.output != raw_payload_path
        || combined_identity != candidate.raw_payload
        || combined.bytes_processed != candidate.raw_payload.bytes
    {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                "fresh combined payload",
            ),
        );
    }
    if observed.roots_ceremony_id != ceremony_id
        || observed.roots_payload_bytes != candidate.raw_payload.bytes
        || observed.roots_raw_blake3 != candidate.raw_payload.blake3
        || observed.roots_raw_sha256 != candidate.raw_payload.sha256
        || observed.roots_base_input_blake3_root != candidate.base_input_blake3_root
        || observed.roots_layer_roots_aggregate != candidate.layer_roots_aggregate
    {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                "payload-verified roots",
            ),
        );
    }
    if observed.structure_ceremony_id != ceremony_id
        || observed.structure_payload_bytes != candidate.raw_payload.bytes
        || observed.structure_raw_blake3 != candidate.raw_payload.blake3
        || observed.structure_raw_sha256 != candidate.raw_payload.sha256
    {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                "independently reproduced structural report",
            ),
        );
    }
    if observed.bank_file != candidate.bank_file
        || observed.manifest_file != candidate.manifest_file
        || observed.record_v2_file != candidate.record_v2_file
    {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                "bank-chain file identities",
            ),
        );
    }
    let manifest = &observed.manifest;
    if manifest.payload_bytes != candidate.raw_payload.bytes
        || manifest.raw_blake3_root != candidate.raw_payload.blake3
        || manifest.layer_roots_aggregate != candidate.layer_roots_aggregate
        || manifest.pcs_parameter_digest != candidate.pcs_parameter_digest
        || manifest.pcs_commitment_root != candidate.pcs_commitment_root
        || manifest.digest().ok() != Some(candidate.manifest_digest)
    {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding("canonical manifest"),
        );
    }
    if observed.record_suite_digest != candidate.production_suite_digest
        || observed.record_manifest_digest != candidate.manifest_digest
        || observed.record_model_identity_digest != candidate.model_identity_digest
        || observed.record_setup_identity != candidate.setup_identity
        || observed.record_padded_variables != candidate.padded_variables
        || observed.record_commitment_root != candidate.pcs_commitment_root
        || observed.record_digest != candidate.record_v2_digest
        || observed.record_model_byte_root != candidate.raw_payload.blake3
        || observed.record_layer_roots_aggregate != candidate.layer_roots_aggregate
        || observed.record_suite_parameter_digest != candidate.pcs_parameter_digest
        || observed.record_commitments != candidate.commitments
    {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                "bank-authenticated Record V2",
            ),
        );
    }
    Ok(())
}

fn hash_exact_retained(
    input: &mut AuthenticatedInput,
    role: &str,
    expected_bytes: u64,
) -> Result<FileIdentity, ProductionDoryV3ModelFinalCandidateValidationError> {
    let reader = input.file_mut();
    reader.seek(SeekFrom::Start(0)).map_err(|source| {
        ProductionDoryV3ModelFinalCandidateValidationError::ArtifactRead {
            role: role.to_owned(),
            source,
        }
    })?;
    let mut blake3 = blake3::Hasher::new();
    let mut sha256 = Sha256::new();
    let mut buffer = [0_u8; STREAM_BUFFER_BYTES];
    let mut total = 0_u64;
    while total < expected_bytes {
        let remaining = expected_bytes - total;
        let limit = usize::try_from(remaining.min(STREAM_BUFFER_BYTES as u64))
            .expect("bounded stream chunk fits usize");
        let read = reader.read(&mut buffer[..limit]).map_err(|source| {
            ProductionDoryV3ModelFinalCandidateValidationError::ArtifactRead {
                role: role.to_owned(),
                source,
            }
        })?;
        if read == 0 {
            return Err(
                ProductionDoryV3ModelFinalCandidateValidationError::ArtifactIdentity {
                    role: role.to_owned(),
                },
            );
        }
        blake3.update(&buffer[..read]);
        sha256.update(&buffer[..read]);
        total += read as u64;
    }
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing).map_err(|source| {
        ProductionDoryV3ModelFinalCandidateValidationError::ArtifactRead {
            role: role.to_owned(),
            source,
        }
    })? != 0
    {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::ArtifactIdentity {
                role: role.to_owned(),
            },
        );
    }
    Ok(FileIdentity {
        bytes: total,
        blake3: *blake3.finalize().as_bytes(),
        sha256: sha256.finalize().into(),
    })
}

fn require_content_identity(
    role: &str,
    bytes: &[u8],
    expected: &FileIdentity,
) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
    if content_identity(bytes) != *expected {
        return Err(
            ProductionDoryV3ModelFinalCandidateValidationError::ArtifactIdentity {
                role: role.to_owned(),
            },
        );
    }
    Ok(())
}

fn content_identity(bytes: &[u8]) -> FileIdentity {
    FileIdentity {
        bytes: bytes.len() as u64,
        blake3: *blake3::hash(bytes).as_bytes(),
        sha256: Sha256::digest(bytes).into(),
    }
}

fn map_fs(
    role: &str,
    error: CeremonyFsError,
) -> ProductionDoryV3ModelFinalCandidateValidationError {
    ProductionDoryV3ModelFinalCandidateValidationError::TrustedFilesystem {
        role: role.to_owned(),
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::{fs::OpenOptions, io::Write as _};
    use std::{
        fs::{self, File},
        sync::atomic::{AtomicU64, Ordering},
    };

    use dory_pcs::primitives::{DorySerialize, arithmetic::Field};
    use k256::schnorr::{Signature, SigningKey};

    use super::*;
    use crate::{
        dory_bls12_381_prototype::{
            BlsDoryFr, DeterministicBlsDorySetup, deterministic_bls_dory_setup,
        },
        dory_v3_model_ceremony_fs::prepare_test_parent,
        dory_v3_model_ceremony_transcript::{
            CEREMONY_PROTOCOL_VERSION, CeremonyRecordBody, CommitmentSetBody,
            ContributionCommitmentBody, ContributionRevealBody, GenesisBody, IndexedRecordDigest,
            PRODUCTION_BANK_FORMAT_VERSION, PRODUCTION_BANK_HEADER_BYTES, PRODUCTION_BANKS,
            PRODUCTION_BASE_INPUT_BYTES, PRODUCTION_BATCH, PRODUCTION_BYTES_PER_LAYER,
            PRODUCTION_DIMENSION, PRODUCTION_LAYERS, PRODUCTION_LAYERS_PER_BANK,
            PRODUCTION_MAX_MODEL_BYTE, PRODUCTION_MODEL_VERSION, PRODUCTION_PADDED_VARIABLES,
            PRODUCTION_PAYLOAD_BYTES, RecordSignature, ReferenceBinary, RevealSetBody,
            RosterMember, SignedCeremonyRecord, SignerClass, ceremony_record_content_digest,
            ceremony_record_signature_message, ceremony_signed_record_digest,
            encode_and_verify_reveal_set_prefix, parse_and_verify_reveal_set_prefix,
        },
        dory_v3_model_combiner::{
            ProductionDoryV3ModelCombinedPayloadValidationReport,
            ProductionDoryV3ModelCombinerInputReport,
        },
        dory_v3_model_independent_lineage::{
            ProductionDoryV3IndependentLineageEvidencePaths, tests::signed_artifact_for_claims,
            validate_existing_production_dory_v3_independent_lineage,
        },
        dory_v3_model_reproduction::{
            ProductionDoryV3ModelReproductionClaims,
            author_and_verify_production_dory_v3_model_reproduction_report,
        },
        dory_v3_suite::{DORY_V3_SETUP_IDENTITY, production_dory_v3_suite_digest},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "cmfd-final-candidate-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            prepare_test_parent(&path).unwrap();
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn file(bytes: u64, seed: u8) -> FileIdentity {
        FileIdentity {
            bytes,
            blake3: [seed; 32],
            sha256: [seed.wrapping_add(1); 32],
        }
    }

    fn write_artifact(path: &Path, bytes: &[u8]) -> FileIdentity {
        fs::write(path, bytes).unwrap();
        content_identity(bytes)
    }

    fn write_sparse_artifact(path: &Path, bytes: u64) {
        let file = File::create(path).unwrap();
        file.set_len(bytes).unwrap();
    }

    fn signing_keys(count: usize, offset: u8) -> Vec<SigningKey> {
        (0..count)
            .map(|index| SigningKey::from_bytes(&[offset.wrapping_add(index as u8); 32]).unwrap())
            .collect()
    }

    fn roster_member(index: usize, key: &SigningKey) -> RosterMember {
        RosterMember {
            index: index as u16,
            public_key: key.verifying_key().to_bytes().into(),
            identity_document: file(index as u64 + 1, index as u8 + 40),
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

    struct OwnedReproducerPaths {
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

    impl OwnedReproducerPaths {
        fn borrowed(&self) -> ProductionDoryV3ModelReproducerCandidatePaths<'_> {
            ProductionDoryV3ModelReproducerCandidatePaths {
                reproduction_report: &self.reproduction_report,
                combiner_binary: &self.combiner_binary,
                combiner_report: &self.combiner_report,
                bootstrap_report: &self.bootstrap_report,
                record_ceremony_report: &self.record_ceremony_report,
                host_environment_report: &self.host_environment_report,
                source_extraction_report: &self.source_extraction_report,
                command_log: &self.command_log,
                implementation_lineage_report: &self.implementation_lineage_report,
            }
        }
    }

    fn borrowed_lineage_evidence_paths(
        paths: &[PathBuf; 11],
    ) -> ProductionDoryV3IndependentLineageEvidencePaths<'_> {
        ProductionDoryV3IndependentLineageEvidencePaths {
            combiner_source_bundle: &paths[0],
            combiner_build_provenance: &paths[1],
            combiner_binary: &paths[2],
            roots_calculator_source_bundle: &paths[3],
            roots_calculator_build_provenance: &paths[4],
            roots_calculator_binary: &paths[5],
            independent_lineage_review_report: &paths[6],
            conformance_test_report: &paths[7],
            host_environment_report: &paths[8],
            source_extraction_report: &paths[9],
            command_log: &paths[10],
        }
    }

    struct ReproducerArtifactIdentities {
        combiner_binary: FileIdentity,
        combiner_report: FileIdentity,
        bootstrap_report: FileIdentity,
        record_ceremony_report: FileIdentity,
        host_environment_report: FileIdentity,
        source_extraction_report: FileIdentity,
        command_log: FileIdentity,
        implementation_lineage_report: FileIdentity,
    }

    fn create_reproducer_artifacts(
        directory: &TestDirectory,
        index: usize,
    ) -> (OwnedReproducerPaths, ReproducerArtifactIdentities) {
        let path = |role: &str| directory.join(&format!("reproducer-{index}-{role}.bin"));
        let paths = OwnedReproducerPaths {
            reproduction_report: path("report"),
            combiner_binary: path("combiner"),
            combiner_report: path("combiner-report"),
            bootstrap_report: path("bootstrap-report"),
            record_ceremony_report: path("record-report"),
            host_environment_report: path("host-report"),
            source_extraction_report: path("source-report"),
            command_log: path("command-log"),
            implementation_lineage_report: path("lineage-report"),
        };
        let contents = |slot: u8| [index as u8 + 1, slot];
        let identities = ReproducerArtifactIdentities {
            combiner_binary: write_artifact(&paths.combiner_binary, &contents(1)),
            combiner_report: write_artifact(&paths.combiner_report, &contents(2)),
            bootstrap_report: write_artifact(&paths.bootstrap_report, &contents(3)),
            record_ceremony_report: write_artifact(&paths.record_ceremony_report, &contents(4)),
            host_environment_report: write_artifact(&paths.host_environment_report, &contents(5)),
            source_extraction_report: write_artifact(&paths.source_extraction_report, &contents(6)),
            command_log: write_artifact(&paths.command_log, &contents(7)),
            implementation_lineage_report: write_artifact(
                &paths.implementation_lineage_report,
                &contents(8),
            ),
        };
        (paths, identities)
    }

    struct BoundedBackend {
        combined: Option<ValidatedProductionDoryV3ModelCombinedPayload>,
        observation: HeavyCandidateObservation,
        combined_calls: usize,
        heavy_calls: usize,
        mutate_during_heavy: Option<(PathBuf, Vec<u8>)>,
    }

    impl FinalCandidateValidationBackend for BoundedBackend {
        type Retention = ();

        fn validate_combined(
            &mut self,
            _transcript: &VerifiedCeremonyTranscript,
            _ordered_contribution_paths: &[PathBuf],
            _raw_payload_path: &Path,
        ) -> Result<
            ValidatedProductionDoryV3ModelCombinedPayload,
            ProductionDoryV3ModelFinalCandidateValidationError,
        > {
            self.combined_calls += 1;
            Ok(self.combined.take().unwrap())
        }

        fn validate_heavy_candidate(
            &mut self,
            _ceremony_id: [u8; 32],
            _paths: ProductionDoryV3ModelFinalCandidatePaths<'_>,
            _retained: &mut RetainedSharedArtifacts,
            _roots_bytes: &[u8],
            _structural_report_bytes: &[u8],
        ) -> Result<
            HeavyValidation<Self::Retention>,
            ProductionDoryV3ModelFinalCandidateValidationError,
        > {
            self.heavy_calls += 1;
            if let Some((path, bytes)) = self.mutate_during_heavy.take() {
                fs::write(path, bytes).unwrap();
            }
            Ok(HeavyValidation {
                observation: self.observation.clone(),
                retention: (),
            })
        }
    }

    fn borrowed_shared_paths(paths: &[PathBuf; 8]) -> ProductionDoryV3ModelFinalCandidatePaths<'_> {
        ProductionDoryV3ModelFinalCandidatePaths {
            source_bundle: &paths[0],
            source_bundle_policy: &paths[1],
            raw_payload: &paths[2],
            roots_file: &paths[3],
            structural_report: &paths[4],
            bank_file: &paths[5],
            manifest_file: &paths[6],
            record_v2_file: &paths[7],
        }
    }

    struct BoundedFinalCandidateFixture {
        _directory: TestDirectory,
        transcript: VerifiedCeremonyTranscript,
        lineages: Option<VerifiedProductionDoryV3ReproducerLineages>,
        contribution_paths: Vec<PathBuf>,
        shared_paths: [PathBuf; 8],
        reproducer_paths: [OwnedReproducerPaths; 2],
        #[cfg(unix)]
        lineage_evidence_paths: [PathBuf; 11],
        backend: BoundedBackend,
    }

    impl BoundedFinalCandidateFixture {
        fn validate(
            &mut self,
        ) -> Result<
            ValidatedFinalCandidateCore<()>,
            ProductionDoryV3ModelFinalCandidateValidationError,
        > {
            let reproducer_paths: Vec<_> = self
                .reproducer_paths
                .iter()
                .map(OwnedReproducerPaths::borrowed)
                .collect();
            validate_with_backend(
                &self.transcript,
                self.lineages
                    .take()
                    .expect("bounded fixture validates once"),
                &self.contribution_paths,
                borrowed_shared_paths(&self.shared_paths),
                &reproducer_paths,
                &mut self.backend,
            )
        }
    }

    fn bounded_transcript_and_combined(
        source_bundle: FileIdentity,
        source_bundle_policy: FileIdentity,
        reference_combiner: &FileIdentity,
        contribution_paths: &[PathBuf],
        raw_payload_path: &Path,
    ) -> (
        VerifiedCeremonyTranscript,
        ProductionDoryV3ModelCombinedPayloadValidationReport,
    ) {
        let operators = signing_keys(3, 1);
        let reproducers = signing_keys(2, 20);
        let operator_signers: Vec<_> = operators
            .iter()
            .enumerate()
            .map(|(index, key)| (SignerClass::Operator, index as u16, key))
            .collect();
        let genesis = GenesisBody {
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
            source_bundle,
            source_bundle_policy,
            cargo_lock_blake3: [6; 32],
            cargo_lock_sha256: [7; 32],
            protocol_spec_blake3: [8; 32],
            protocol_spec_sha256: [9; 32],
            bulletin_policy: file(11, 10),
            reference_binaries: vec![ReferenceBinary {
                target_id: 1,
                rustc_vv: file(12, 11),
                build_environment: file(13, 12),
                binary_blake3: reference_combiner.blake3,
                binary_sha256: reference_combiner.sha256,
            }],
            structural_analyzer_target_id: 1,
            structural_analyzer_blake3: [15; 32],
            structural_analyzer_sha256: [16; 32],
            production_suite_digest: production_dory_v3_suite_digest().into_bytes(),
            dory_setup_identity: DORY_V3_SETUP_IDENTITY.into_bytes(),
            operators: operators
                .iter()
                .enumerate()
                .map(|(index, key)| roster_member(index, key))
                .collect(),
            reproducers: reproducers
                .iter()
                .enumerate()
                .map(|(index, key)| roster_member(index, key))
                .collect(),
        };
        let genesis_record = sign_record(
            CeremonyRecordBody::Genesis(Box::new(genesis)),
            &all_signers(&operators, &reproducers),
        );
        let ceremony_id = ceremony_record_content_digest(&genesis_record.body).unwrap();
        let genesis_digest = ceremony_signed_record_digest(&genesis_record).unwrap();
        let mut records = vec![genesis_record];
        let mut commitment_bodies = Vec::new();
        let mut commitment_digests = Vec::new();
        for (index, key) in operators.iter().enumerate() {
            let body = ContributionCommitmentBody {
                ceremony_id,
                genesis_signed_record_digest: genesis_digest,
                operator_index: index as u16,
                operator_public_key: key.verifying_key().to_bytes().into(),
                contribution_bytes: PRODUCTION_PAYLOAD_BYTES,
                contribution_blake3: [60 + index as u8; 32],
                contribution_sha256: [70 + index as u8; 32],
                source_bytes_consumed: PRODUCTION_PAYLOAD_BYTES + 5,
                rejected_source_bytes: 5,
                generation_finished_unix_seconds: 100 + index as u64,
                generator_binary_blake3: [80 + index as u8; 32],
                generator_binary_sha256: [90 + index as u8; 32],
                entropy_attestation: file(101 + index as u64, 100 + index as u8),
            };
            let record = sign_record(
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
        let commitment_set = sign_record(
            CeremonyRecordBody::CommitmentSet(CommitmentSetBody {
                ceremony_id,
                genesis_signed_record_digest: genesis_digest,
                commitments: commitment_digests.clone(),
            }),
            &operator_signers,
        );
        let commitment_set_digest = ceremony_signed_record_digest(&commitment_set).unwrap();
        records.push(commitment_set);
        let mut reveal_digests = Vec::new();
        for (index, key) in operators.iter().enumerate() {
            let commitment = &commitment_bodies[index];
            let record = sign_record(
                CeremonyRecordBody::ContributionReveal(ContributionRevealBody {
                    ceremony_id,
                    operator_index: index as u16,
                    contribution_commitment_signed_record_digest: commitment_digests[index]
                        .signed_record_digest,
                    contribution_bytes: commitment.contribution_bytes,
                    contribution_blake3: commitment.contribution_blake3,
                    contribution_sha256: commitment.contribution_sha256,
                    reveal_finished_unix_seconds: 200 + index as u64,
                }),
                &[(SignerClass::Operator, index as u16, key)],
            );
            reveal_digests.push(IndexedRecordDigest {
                index: index as u16,
                signed_record_digest: ceremony_signed_record_digest(&record).unwrap(),
            });
            records.push(record);
        }
        let reveal_set = sign_record(
            CeremonyRecordBody::RevealSet(RevealSetBody {
                ceremony_id,
                commitment_set_signed_record_digest: commitment_set_digest,
                reveals: reveal_digests.clone(),
            }),
            &operator_signers,
        );
        let reveal_set_digest = ceremony_signed_record_digest(&reveal_set).unwrap();
        records.push(reveal_set);
        let transcript_bytes = encode_and_verify_reveal_set_prefix(&records, ceremony_id).unwrap();
        let transcript =
            parse_and_verify_reveal_set_prefix(&transcript_bytes, ceremony_id).unwrap();
        let ordered_inputs = commitment_bodies
            .iter()
            .enumerate()
            .map(
                |(index, commitment)| ProductionDoryV3ModelCombinerInputReport {
                    path: contribution_paths[index].clone(),
                    operator_index: index as u16,
                    operator_public_key: Digest32::new(commitment.operator_public_key),
                    contribution_bytes: commitment.contribution_bytes,
                    contribution_blake3: Digest32::new(commitment.contribution_blake3),
                    contribution_sha256: Digest32::new(commitment.contribution_sha256),
                    contribution_commitment_signed_record_digest: Digest32::new(
                        commitment_digests[index].signed_record_digest,
                    ),
                    contribution_reveal_signed_record_digest: Digest32::new(
                        reveal_digests[index].signed_record_digest,
                    ),
                },
            )
            .collect();
        let combined = ProductionDoryV3ModelCombinedPayloadValidationReport {
            ceremony_id: Digest32::new(ceremony_id),
            reveal_set_prefix_bytes: transcript.transcript_bytes(),
            reveal_set_prefix_derive_key_digest: Digest32::new(
                transcript.transcript_derive_key_digest(),
            ),
            reveal_set_prefix_blake3: Digest32::new(transcript.transcript_blake3()),
            reveal_set_prefix_sha256: Digest32::new(transcript.transcript_sha256()),
            commitment_set_signed_record_digest: Digest32::new(commitment_set_digest),
            reveal_set_signed_record_digest: Digest32::new(reveal_set_digest),
            ordered_inputs,
            output: raw_payload_path.to_path_buf(),
            output_bytes: PRODUCTION_PAYLOAD_BYTES,
            output_blake3: Digest32::new([110; 32]),
            output_sha256: Digest32::new([111; 32]),
            bytes_processed: PRODUCTION_PAYLOAD_BYTES,
            elapsed_micros: 101,
        };
        (transcript, combined)
    }

    fn bounded_production_observation(
        ceremony_id: [u8; 32],
        candidate: &CandidateIdentity,
    ) -> HeavyCandidateObservation {
        let manifest = ModelBankManifest {
            model_version: PRODUCTION_MODEL_VERSION,
            dimension: PRODUCTION_DIMENSION,
            batch: PRODUCTION_BATCH,
            layers: PRODUCTION_LAYERS,
            base_input_bytes: PRODUCTION_BASE_INPUT_BYTES,
            bytes_per_layer: PRODUCTION_BYTES_PER_LAYER,
            payload_bytes: PRODUCTION_PAYLOAD_BYTES,
            raw_blake3_root: candidate.raw_payload.blake3,
            layer_roots_aggregate: candidate.layer_roots_aggregate,
            pcs_parameter_digest: candidate.pcs_parameter_digest,
            pcs_commitment_root: candidate.pcs_commitment_root,
        };
        assert_eq!(manifest.digest().unwrap(), candidate.manifest_digest);
        HeavyCandidateObservation {
            roots_ceremony_id: ceremony_id,
            roots_payload_bytes: candidate.raw_payload.bytes,
            roots_raw_blake3: candidate.raw_payload.blake3,
            roots_raw_sha256: candidate.raw_payload.sha256,
            roots_base_input_blake3_root: candidate.base_input_blake3_root,
            roots_layer_roots_aggregate: candidate.layer_roots_aggregate,
            structure_ceremony_id: ceremony_id,
            structure_payload_bytes: candidate.raw_payload.bytes,
            structure_raw_blake3: candidate.raw_payload.blake3,
            structure_raw_sha256: candidate.raw_payload.sha256,
            bank_file: candidate.bank_file.clone(),
            manifest_file: candidate.manifest_file.clone(),
            record_v2_file: candidate.record_v2_file.clone(),
            manifest,
            record_suite_digest: candidate.production_suite_digest,
            record_manifest_digest: candidate.manifest_digest,
            record_model_identity_digest: candidate.model_identity_digest,
            record_setup_identity: candidate.setup_identity,
            record_padded_variables: candidate.padded_variables,
            record_commitment_root: candidate.pcs_commitment_root,
            record_digest: candidate.record_v2_digest,
            record_model_byte_root: candidate.raw_payload.blake3,
            record_layer_roots_aggregate: candidate.layer_roots_aggregate,
            record_suite_parameter_digest: candidate.pcs_parameter_digest,
            record_commitments: candidate.commitments,
        }
    }

    fn candidate_fixture() -> (
        [u8; 32],
        PathBuf,
        CandidateIdentity,
        ProductionDoryV3ModelCombinedPayloadValidationReport,
        HeavyCandidateObservation,
    ) {
        let ceremony_id = [1; 32];
        let raw_payload_path = PathBuf::from("bounded-raw-payload.bin");
        let raw_payload = file(12, 2);
        let roots_file = file(14_006, 4);
        let structural_report = file(799_795, 6);
        let bank_file = file(196, 8);
        let manifest_file = file(300, 10);
        let record_v2_file = file(500, 12);
        let commitments = [[13; 576], [14; 576], [15; 576], [16; 576]];
        let manifest = ModelBankManifest {
            model_version: 1,
            dimension: 2,
            batch: 2,
            layers: 2,
            base_input_bytes: 4,
            bytes_per_layer: 4,
            payload_bytes: raw_payload.bytes,
            raw_blake3_root: raw_payload.blake3,
            layer_roots_aggregate: [17; 32],
            pcs_parameter_digest: [18; 32],
            pcs_commitment_root: [19; 32],
        };
        let manifest_digest = manifest.digest().unwrap();
        let candidate = CandidateIdentity {
            raw_payload: raw_payload.clone(),
            base_input_blake3_root: [20; 32],
            layer_roots_aggregate: manifest.layer_roots_aggregate,
            roots_file,
            structural_report,
            bank_file: bank_file.clone(),
            manifest_file: manifest_file.clone(),
            manifest_digest,
            production_suite_digest: [21; 32],
            pcs_parameter_digest: manifest.pcs_parameter_digest,
            commitments,
            pcs_commitment_root: manifest.pcs_commitment_root,
            model_identity_digest: [22; 32],
            setup_identity: [23; 32],
            padded_variables: 4,
            record_v2_file: record_v2_file.clone(),
            record_v2_digest: [24; 32],
        };
        let combined = ProductionDoryV3ModelCombinedPayloadValidationReport {
            ceremony_id: Digest32::new(ceremony_id),
            reveal_set_prefix_bytes: 1,
            reveal_set_prefix_derive_key_digest: Digest32::new([25; 32]),
            reveal_set_prefix_blake3: Digest32::new([26; 32]),
            reveal_set_prefix_sha256: Digest32::new([27; 32]),
            commitment_set_signed_record_digest: Digest32::new([28; 32]),
            reveal_set_signed_record_digest: Digest32::new([29; 32]),
            ordered_inputs: Vec::new(),
            output: raw_payload_path.clone(),
            output_bytes: raw_payload.bytes,
            output_blake3: Digest32::new(raw_payload.blake3),
            output_sha256: Digest32::new(raw_payload.sha256),
            bytes_processed: raw_payload.bytes,
            elapsed_micros: 1,
        };
        let observed = HeavyCandidateObservation {
            roots_ceremony_id: ceremony_id,
            roots_payload_bytes: raw_payload.bytes,
            roots_raw_blake3: raw_payload.blake3,
            roots_raw_sha256: raw_payload.sha256,
            roots_base_input_blake3_root: candidate.base_input_blake3_root,
            roots_layer_roots_aggregate: candidate.layer_roots_aggregate,
            structure_ceremony_id: ceremony_id,
            structure_payload_bytes: raw_payload.bytes,
            structure_raw_blake3: raw_payload.blake3,
            structure_raw_sha256: raw_payload.sha256,
            bank_file,
            manifest_file,
            record_v2_file,
            manifest,
            record_suite_digest: candidate.production_suite_digest,
            record_manifest_digest: candidate.manifest_digest,
            record_model_identity_digest: candidate.model_identity_digest,
            record_setup_identity: candidate.setup_identity,
            record_padded_variables: candidate.padded_variables,
            record_commitment_root: candidate.pcs_commitment_root,
            record_digest: candidate.record_v2_digest,
            record_model_byte_root: raw_payload.blake3,
            record_layer_roots_aggregate: candidate.layer_roots_aggregate,
            record_suite_parameter_digest: candidate.pcs_parameter_digest,
            record_commitments: candidate.commitments,
        };
        (ceremony_id, raw_payload_path, candidate, combined, observed)
    }

    // Private bounded seam: production roots, structure, and bank validators
    // project into this same cross-binding check, while this fixture stays tiny.
    fn validate_bounded_projection(
        candidate: &CandidateIdentity,
        combined: &ProductionDoryV3ModelCombinedPayloadValidationReport,
        observed: &HeavyCandidateObservation,
    ) -> Result<(), ProductionDoryV3ModelFinalCandidateValidationError> {
        cross_bind_candidate(
            [1; 32],
            Path::new("bounded-raw-payload.bin"),
            candidate,
            combined,
            observed,
        )
    }

    fn bounded_final_candidate_fixture() -> BoundedFinalCandidateFixture {
        let directory = TestDirectory::new();
        let source_bundle_path = directory.join("source-bundle.tar");
        let source_policy_path = directory.join("source-policy.txt");
        let source_bundle = write_artifact(&source_bundle_path, b"bounded source bundle");
        let source_bundle_policy = write_artifact(&source_policy_path, b"bounded source policy");

        let contribution_paths: Vec<_> = (0..3)
            .map(|index| directory.join(&format!("contribution-{index}.bin")))
            .collect();
        for path in &contribution_paths {
            write_sparse_artifact(path, PRODUCTION_PAYLOAD_BYTES);
        }
        let raw_payload_path = directory.join("raw-payload.bin");
        let bank_path = directory.join("model-bank.bin");
        write_sparse_artifact(&raw_payload_path, PRODUCTION_PAYLOAD_BYTES);
        write_sparse_artifact(&bank_path, PRODUCTION_BANK_BYTES);
        let roots_path = directory.join("roots.cmfd-roots");
        let structure_path = directory.join("structure.cmfd-structure");
        let manifest_path = directory.join("manifest.json");
        let record_path = directory.join("record-v2.json");
        let roots_file =
            write_artifact(&roots_path, &vec![31; PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES]);
        let structural_report = write_artifact(
            &structure_path,
            &vec![32; PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES],
        );
        let manifest_file = write_artifact(&manifest_path, b"bounded manifest bytes");
        let record_v2_file = write_artifact(&record_path, b"bounded Record V2 bytes");
        let bank_file = file(PRODUCTION_BANK_BYTES, 33);

        let (reproducer_zero_paths, reproducer_zero_artifacts) =
            create_reproducer_artifacts(&directory, 0);
        let (reproducer_one_paths, reproducer_one_artifacts) =
            create_reproducer_artifacts(&directory, 1);
        let (transcript, combined_report) = bounded_transcript_and_combined(
            source_bundle,
            source_bundle_policy,
            &reproducer_zero_artifacts.combiner_binary,
            &contribution_paths,
            &raw_payload_path,
        );
        let combined_for_authoring =
            ValidatedProductionDoryV3ModelCombinedPayload::from_report_for_test(
                combined_report.clone(),
            );
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let commitments = [
            canonical_commitment(&setup, 3, 0),
            canonical_commitment(&setup, 5, 1),
            canonical_commitment(&setup, 7, 2),
            canonical_commitment(&setup, 11, 3),
        ];
        let reproducer_artifacts = [&reproducer_zero_artifacts, &reproducer_one_artifacts];
        let implementation_kinds = [
            ProductionDoryV3ReproductionImplementationKind::Reference,
            ProductionDoryV3ReproductionImplementationKind::Independent,
        ];
        let mut claims: Vec<_> = (0..2)
            .map(|index| {
                let artifacts = reproducer_artifacts[index];
                ProductionDoryV3ModelReproductionClaims {
                    reproducer_index: index as u16,
                    implementation_kind: implementation_kinds[index],
                    target_id: 1,
                    combiner_binary: artifacts.combiner_binary.clone(),
                    combiner_report: artifacts.combiner_report.clone(),
                    bootstrap_report: artifacts.bootstrap_report.clone(),
                    record_ceremony_report: artifacts.record_ceremony_report.clone(),
                    host_environment_report: artifacts.host_environment_report.clone(),
                    source_extraction_report: artifacts.source_extraction_report.clone(),
                    command_log: artifacts.command_log.clone(),
                    implementation_lineage_report: artifacts.implementation_lineage_report.clone(),
                    roots_file: roots_file.clone(),
                    structural_report: structural_report.clone(),
                    bank_file: bank_file.clone(),
                    manifest_file: manifest_file.clone(),
                    record_v2_file: record_v2_file.clone(),
                    base_input_blake3_root: [112; 32],
                    layer_roots_aggregate: [113; 32],
                    base_commitment: commitments[0],
                    weight_bank_0_commitment: commitments[1],
                    weight_bank_1_commitment: commitments[2],
                    weight_bank_2_commitment: commitments[3],
                    roots_elapsed_micros: 102,
                    structure_elapsed_micros: 103,
                    bootstrap_elapsed_micros: 104,
                    record_elapsed_micros: 105,
                    total_elapsed_micros: 1_000,
                    peak_rss_bytes: 1_048_576,
                    peak_disk_bytes: PRODUCTION_PAYLOAD_BYTES + PRODUCTION_BANK_BYTES,
                }
            })
            .collect();

        let lineage_evidence_paths = [
            directory.join("independent-combiner-source.tar"),
            directory.join("independent-combiner-build.txt"),
            reproducer_one_paths.combiner_binary.clone(),
            directory.join("independent-roots-source.tar"),
            directory.join("independent-roots-build.txt"),
            directory.join("independent-roots-binary"),
            directory.join("independent-lineage-review.txt"),
            directory.join("independent-conformance.txt"),
            reproducer_one_paths.host_environment_report.clone(),
            reproducer_one_paths.source_extraction_report.clone(),
            reproducer_one_paths.command_log.clone(),
        ];
        let lineage_evidence = [
            write_artifact(&lineage_evidence_paths[0], b"independent combiner source"),
            write_artifact(&lineage_evidence_paths[1], b"independent combiner build"),
            reproducer_one_artifacts.combiner_binary.clone(),
            write_artifact(&lineage_evidence_paths[3], b"independent roots source"),
            write_artifact(&lineage_evidence_paths[4], b"independent roots build"),
            write_artifact(&lineage_evidence_paths[5], b"independent roots binary"),
            write_artifact(&lineage_evidence_paths[6], b"independent lineage review"),
            write_artifact(&lineage_evidence_paths[7], b"independent conformance"),
            reproducer_one_artifacts.host_environment_report.clone(),
            reproducer_one_artifacts.source_extraction_report.clone(),
            reproducer_one_artifacts.command_log.clone(),
        ];
        let raw_payload = FileIdentity {
            bytes: combined_report.output_bytes,
            blake3: combined_report.output_blake3.into_bytes(),
            sha256: combined_report.output_sha256.into_bytes(),
        };
        let operator_keys = signing_keys(3, 1);
        let reproducer_keys = signing_keys(2, 20);
        let lineage_artifact = signed_artifact_for_claims(
            &transcript,
            raw_payload,
            &claims[1],
            lineage_evidence,
            &operator_keys,
            &reproducer_keys,
        );
        claims[1].implementation_lineage_report = write_artifact(
            &reproducer_one_paths.implementation_lineage_report,
            &lineage_artifact,
        );

        let verified_reports: Vec<_> = claims
            .into_iter()
            .map(|claims| {
                author_and_verify_production_dory_v3_model_reproduction_report(
                    &transcript,
                    &combined_for_authoring,
                    claims,
                )
                .unwrap()
            })
            .collect();
        let report_paths = [
            &reproducer_zero_paths.reproduction_report,
            &reproducer_one_paths.reproduction_report,
        ];
        for (path, report) in report_paths.into_iter().zip(&verified_reports) {
            fs::write(path, report.report().canonical_bytes()).unwrap();
        }
        let independent_lineage = validate_existing_production_dory_v3_independent_lineage(
            &reproducer_one_paths.implementation_lineage_report,
            borrowed_lineage_evidence_paths(&lineage_evidence_paths),
            &transcript,
            &verified_reports[1],
        )
        .unwrap();
        let lineages = VerifiedProductionDoryV3ReproducerLineages::verify_exact_ordered(
            &transcript,
            &verified_reports,
            vec![independent_lineage],
        )
        .unwrap();
        let candidate = CandidateIdentity::from(verified_reports[0].final_candidate());
        let backend = BoundedBackend {
            combined: Some(
                ValidatedProductionDoryV3ModelCombinedPayload::from_report_for_test(
                    combined_report,
                ),
            ),
            observation: bounded_production_observation(transcript.ceremony_id(), &candidate),
            combined_calls: 0,
            heavy_calls: 0,
            mutate_during_heavy: None,
        };
        BoundedFinalCandidateFixture {
            _directory: directory,
            transcript,
            lineages: Some(lineages),
            contribution_paths,
            shared_paths: [
                source_bundle_path,
                source_policy_path,
                raw_payload_path,
                roots_path,
                structure_path,
                bank_path,
                manifest_path,
                record_path,
            ],
            reproducer_paths: [reproducer_zero_paths, reproducer_one_paths],
            #[cfg(unix)]
            lineage_evidence_paths,
            backend,
        }
    }

    #[test]
    fn bounded_backend_exercises_exact_roster_final_candidate_orchestration() {
        let mut fixture = bounded_final_candidate_fixture();
        let ceremony_id = fixture.transcript.ceremony_id();
        let validated = fixture.validate().unwrap();
        assert_eq!(validated.ceremony_id, ceremony_id);
        assert_eq!(validated.reports.len(), 2);
        assert_eq!(fixture.backend.combined_calls, 1);
        assert_eq!(fixture.backend.heavy_calls, 1);
    }

    #[cfg(unix)]
    #[test]
    fn lineage_mutation_or_replacement_fails_before_expensive_validation() {
        let mut mutated = bounded_final_candidate_fixture();
        let evidence = mutated.lineage_evidence_paths[0].clone();
        fs::write(&evidence, b"XXXXXXXXXXXXXXXXXXXXXXXXXXX").unwrap();
        assert!(matches!(
            mutated.validate(),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineageEvidence {
                    reproducer_index: 1,
                    source: ProductionDoryV3IndependentLineageError::EvidenceIdentity(
                        "combiner source bundle"
                    )
                }
            )
        ));
        assert_eq!(mutated.backend.combined_calls, 0);
        assert_eq!(mutated.backend.heavy_calls, 0);

        let mut replaced = bounded_final_candidate_fixture();
        let lineage_path = replaced.reproducer_paths[1]
            .implementation_lineage_report
            .clone();
        let artifact = fs::read(&lineage_path).unwrap();
        fs::rename(&lineage_path, lineage_path.with_extension("old")).unwrap();
        fs::write(&lineage_path, artifact).unwrap();
        assert!(matches!(
            replaced.validate(),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineageEvidence {
                    reproducer_index: 1,
                    ..
                }
            )
        ));
        assert_eq!(replaced.backend.combined_calls, 0);
        assert_eq!(replaced.backend.heavy_calls, 0);
    }

    #[cfg(unix)]
    #[test]
    fn lineage_mutation_during_heavy_validation_fails_final_guard() {
        let mut fixture = bounded_final_candidate_fixture();
        fixture.backend.mutate_during_heavy = Some((
            fixture.lineage_evidence_paths[0].clone(),
            b"XXXXXXXXXXXXXXXXXXXXXXXXXXX".to_vec(),
        ));
        assert!(matches!(
            fixture.validate(),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineageEvidence {
                    reproducer_index: 1,
                    source: ProductionDoryV3IndependentLineageError::EvidenceIdentity(
                        "combiner source bundle"
                    )
                }
            )
        ));
        assert_eq!(fixture.backend.combined_calls, 1);
        assert_eq!(fixture.backend.heavy_calls, 1);
    }

    #[test]
    fn bounded_projection_accepts_complete_cross_binding() {
        let (_, _, candidate, combined, observed) = candidate_fixture();
        validate_bounded_projection(&candidate, &combined, &observed).unwrap();
    }

    #[test]
    fn duplicate_artifact_roles_are_rejected_before_open() {
        let shared = PathBuf::from("shared");
        let raw = PathBuf::from("raw");
        let roots = PathBuf::from("roots");
        let structure = PathBuf::from("structure");
        let bank = PathBuf::from("bank");
        let manifest = PathBuf::from("manifest");
        let record = PathBuf::from("record");
        let paths = ProductionDoryV3ModelFinalCandidatePaths {
            source_bundle: &shared,
            source_bundle_policy: &shared,
            raw_payload: &raw,
            roots_file: &roots,
            structural_report: &structure,
            bank_file: &bank,
            manifest_file: &manifest,
            record_v2_file: &record,
        };
        assert!(matches!(
            ensure_distinct_supplied_paths(paths, &[], &[]),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::ArtifactPathsNotDistinct {
                    first,
                    second
                }
            ) if first == "source bundle" && second == "source bundle policy"
        ));
    }

    #[test]
    fn exact_roster_count_and_report_order_are_fail_closed() {
        require_exact_reproducer_count(3, 3).unwrap();
        assert!(matches!(
            require_exact_reproducer_count(3, 2),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::ReproducerCount {
                    expected: 3,
                    actual: 2
                }
            )
        ));
        require_ordered_reproducer_indices(&[0, 1, 2]).unwrap();
        assert!(matches!(
            require_ordered_reproducer_indices(&[0, 2, 1]),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::ReproducerOrder {
                    position: 1,
                    actual: 2
                }
            )
        ));
        require_exact_contribution_count(3, 3).unwrap();
        assert!(matches!(
            require_exact_contribution_count(3, 4),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::ContributionCount {
                    expected: 3,
                    actual: 4
                }
            )
        ));
    }

    #[test]
    fn different_candidate_report_is_rejected() {
        let (_, _, candidate, _, _) = candidate_fixture();
        let mut changed = candidate.clone();
        changed.record_v2_digest[0] ^= 1;
        assert!(matches!(
            require_same_candidates(&[candidate, changed]),
            Err(ProductionDoryV3ModelFinalCandidateValidationError::CandidateMismatch)
        ));
    }

    #[test]
    fn bounded_projection_rejects_each_heavy_boundary() {
        let (_, _, candidate, combined, observed) = candidate_fixture();

        let mut wrong_combined = combined.clone();
        wrong_combined.output_sha256 = Digest32::new([30; 32]);
        assert!(matches!(
            validate_bounded_projection(&candidate, &wrong_combined, &observed),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                    "fresh combined payload"
                )
            )
        ));

        let mut wrong_roots = observed.clone();
        wrong_roots.roots_base_input_blake3_root[0] ^= 1;
        assert!(matches!(
            validate_bounded_projection(&candidate, &combined, &wrong_roots),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                    "payload-verified roots"
                )
            )
        ));

        let mut wrong_structure = observed.clone();
        wrong_structure.structure_raw_sha256[0] ^= 1;
        assert!(matches!(
            validate_bounded_projection(&candidate, &combined, &wrong_structure),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                    "independently reproduced structural report"
                )
            )
        ));

        let mut wrong_bank = observed.clone();
        wrong_bank.bank_file.sha256[0] ^= 1;
        assert!(matches!(
            validate_bounded_projection(&candidate, &combined, &wrong_bank),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                    "bank-chain file identities"
                )
            )
        ));

        let mut wrong_manifest = observed.clone();
        wrong_manifest.manifest.pcs_parameter_digest[0] ^= 1;
        assert!(matches!(
            validate_bounded_projection(&candidate, &combined, &wrong_manifest),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                    "canonical manifest"
                )
            )
        ));

        let mut wrong_record = observed;
        wrong_record.record_commitments[3][0] ^= 1;
        assert!(matches!(
            validate_bounded_projection(&candidate, &combined, &wrong_record),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::CrossBinding(
                    "bank-authenticated Record V2"
                )
            )
        ));
    }

    #[test]
    fn final_guard_recheck_order_is_deterministic_and_bank_last() {
        let order = final_guard_recheck_order(2, 2);
        assert_eq!(order[0], GuardRecheckTarget::SourceBundle);
        assert_eq!(order[1], GuardRecheckTarget::SourceBundlePolicy);
        assert_eq!(order[2], GuardRecheckTarget::Contribution(0));
        assert_eq!(order[3], GuardRecheckTarget::Contribution(1));
        assert_eq!(order[4], GuardRecheckTarget::ReproductionReport(0));
        assert_eq!(order[13], GuardRecheckTarget::ReproductionReport(1));
        assert_eq!(order.last(), Some(&GuardRecheckTarget::BankFile));
        assert_eq!(
            order
                .iter()
                .filter(|target| **target == GuardRecheckTarget::BankFile)
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_artifact_mutation_fails_content_identity() {
        let directory = TestDirectory::new();
        let path = directory.join("shared-artifact.bin");
        fs::write(&path, b"original").unwrap();
        let expected = content_identity(b"original");
        let mut retained = RetainedArtifact::open("shared artifact", &path, None).unwrap();
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap()
            .write_all(b"mutated!")
            .unwrap();
        assert!(matches!(
            retained.authenticate(&expected),
            Err(ProductionDoryV3ModelFinalCandidateValidationError::ArtifactIdentity { role })
                if role == "shared artifact"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn retained_replacement_error_precedes_content_acceptance() {
        let directory = TestDirectory::new();
        let path = directory.join("report.cmfd-rp");
        let displaced = directory.join("displaced.cmfd-rp");
        fs::write(
            &path,
            vec![7_u8; PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES],
        )
        .unwrap();
        let mut retained = RetainedArtifact::open(
            "reproduction report",
            &path,
            Some(PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES as u64),
        )
        .unwrap();
        fs::rename(&path, &displaced).unwrap();
        fs::write(
            &path,
            vec![7_u8; PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES],
        )
        .unwrap();
        assert!(matches!(
            retained.read_exact(PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES),
            Err(ProductionDoryV3ModelFinalCandidateValidationError::TrustedFilesystem { role, .. })
                if role == "reproduction report"
        ));
    }

    #[test]
    fn content_identity_binds_length_and_both_hashes() {
        let bytes = b"bounded candidate artifact";
        let identity = content_identity(bytes);
        assert_eq!(identity.bytes, bytes.len() as u64);
        assert_eq!(identity.blake3, *blake3::hash(bytes).as_bytes());
        let expected_sha256: [u8; 32] = Sha256::digest(bytes).into();
        assert_eq!(identity.sha256, expected_sha256);
        assert!(matches!(
            require_content_identity("fixture", b"changed", &identity),
            Err(ProductionDoryV3ModelFinalCandidateValidationError::ArtifactIdentity { .. })
        ));
    }
}
