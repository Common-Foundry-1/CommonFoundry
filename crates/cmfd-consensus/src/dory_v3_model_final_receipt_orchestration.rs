//! Retained path-plan loading for production Dory V3 final-receipt orchestration.
//!
//! This first boundary authenticates only the strict JSON plan and its exact,
//! independently anchored reveal-set-closed prefix. Paths declared by the plan
//! are routing inputs for later validators, never content or candidate authority.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    dory_v3_model_ceremony_fs::{AuthenticatedInput, CeremonyFsError, TrustedCeremonyParent},
    dory_v3_model_ceremony_transcript::{
        CeremonyTranscriptError, FileIdentity, MAX_CEREMONY_TRANSCRIPT_BYTES,
        VerifiedCeremonyTranscript, parse_and_verify_reveal_set_prefix,
    },
};

pub const PRODUCTION_DORY_V3_FINAL_RECEIPT_PLAN_MAX_BYTES: usize = 256 * 1024;

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

fn validate_declared_paths(
    plan_path: &Path,
    artifacts: &ProductionDoryV3FinalReceiptArtifactsV1,
) -> Result<(), ProductionDoryV3FinalReceiptOrchestrationError> {
    // This routing layer deliberately requires every declared pathname to be
    // textually distinct. Later semantic validators additionally open the real
    // files and reject filesystem-identity aliases within their authority sets.
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
