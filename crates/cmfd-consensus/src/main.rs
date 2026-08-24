use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
#[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
use cmfd_consensus::dory_bls12_381_blake3::derive_bls_dory_blake3_preprocessing_record;
#[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
use cmfd_consensus::dory_v3_qualification::{
    ProductionDoryV3QualificationRequest, ProductionDoryV3QualificationSeed,
    generate_production_dory_v3_qualification_request, run_production_dory_v3_qualification,
};
use cmfd_consensus::forgematrix::CANDIDATE_16GB_PROFILE;
use cmfd_consensus::forgematrix::target_with_leading_zero_bits;
use cmfd_consensus::{
    BlockChallenge, DEFAULT_MONETARY_POLICY, ForgeMatrixVerifier, TEST_PROFILE, v2_test_reference,
};
#[cfg(feature = "dory-bls12-381-prototype")]
use cmfd_consensus::{
    ModelBankManifest, ModelPcsIdentity,
    dory_bls12_381_model_commitment::derive_bls_dory_model_commitment_record,
    dory_bls12_381_prototype::deterministic_bls_dory_setup,
    dory_v3_model_bank_bootstrap::run_production_dory_v3_model_bank_bootstrap,
    dory_v3_model_ceremony::run_production_dory_v3_model_record_v2_ceremony,
    dory_v3_model_ceremony_transcript::{
        CeremonyRecordBody, MAX_CEREMONY_TRANSCRIPT_BYTES, RecordSignature, SignerClass,
        ceremony_record_content_digest, parse_and_verify_reveal_set_prefix,
    },
    dory_v3_model_combiner::combine_production_dory_v3_model_contributions,
    dory_v3_model_contribution::generate_production_dory_v3_model_contribution,
    dory_v3_model_roots::{
        ProductionDoryV3ModelRoots, generate_production_dory_v3_model_roots_file,
        validate_production_dory_v3_model_roots_files,
    },
    dory_v3_model_structure::{
        ProductionDoryV3ModelStructuralReport, run_production_dory_v3_model_structural_report,
        validate_production_dory_v3_model_structural_report_files,
    },
    dory_v3_model_structure_evidence::{
        AuthenticatedProductionDoryV3StructuralErrorEvidence,
        ProductionDoryV3StructuralAbortSubjectBinding, ProductionDoryV3StructuralAnalyzerOutcome,
        prepare_anchored_production_dory_v3_structural_abort_from_files,
        run_anchored_production_dory_v3_model_structural_report,
        stage_anchored_production_dory_v3_structural_abort_record,
        stage_anchored_production_dory_v3_structural_abort_transcript,
        verify_anchored_production_dory_v3_structural_abort,
    },
    dory_v3_suite::Digest32,
};
#[cfg(feature = "dory-bls12-381-prototype")]
use std::io::Read as _;

#[derive(Debug, Parser)]
#[command(
    name = "cmfd-consensus",
    version,
    about = "CommonFoundry consensus reference tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[cfg(feature = "dory-bls12-381-prototype")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ExternalRecordSignature {
    signer_index: u16,
    signature: [u8; 64],
}

#[cfg(feature = "dory-bls12-381-prototype")]
impl ExternalRecordSignature {
    fn into_record_signature(self, signer_class: SignerClass) -> RecordSignature {
        RecordSignature {
            signer_class,
            signer_index: self.signer_index,
            signature: self.signature,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Emit a deterministic ForgeMatrix test vector.
    Vector,
    /// Mine the small CPU test profile.
    Mine {
        #[arg(long, default_value_t = 12)]
        leading_zero_bits: u16,
        #[arg(long, default_value_t = 100_000)]
        attempts: u64,
    },
    /// Show the subsidy, allocation, and burned fees at a height.
    Economics {
        #[arg(long)]
        height: u64,
        #[arg(long, default_value_t = 0)]
        fees: u64,
    },
    /// Write a binary fixture for the independent CUDA differential test.
    GpuFixture {
        #[arg(long)]
        output: std::path::PathBuf,
        #[arg(long, default_value_t = 7)]
        nonce: u64,
    },
    /// Write the explicit-byte, mod-251 v2 CUDA differential fixture.
    GpuFixtureV2 {
        #[arg(long)]
        output: std::path::PathBuf,
        #[arg(long, default_value_t = 7)]
        nonce: u64,
    },
    /// Report exact memory and work for the unactivated 16 GB candidate.
    Profile16gb,
    /// Authenticate a model bank and emit its reproducible fixed-model BLS commitment record.
    #[cfg(feature = "dory-bls12-381-prototype")]
    BlsModelCommitment {
        /// Canonical binary model bank to authenticate.
        #[arg(long)]
        bank: std::path::PathBuf,
        /// Separately trusted model-bank manifest JSON.
        #[arg(long)]
        manifest: std::path::PathBuf,
        /// Separately trusted ModelPcsIdentity JSON.
        #[arg(long)]
        model_identity: std::path::PathBuf,
        /// Fixed-table geometry and deterministic setup size.
        #[arg(long, default_value_t = 33)]
        padded_variables: usize,
        /// New JSON record path; omit for stdout. Existing files are never overwritten.
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    /// Build the canonical production V2 model bank from a pre-generated raw payload.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelBankBootstrap {
        /// Exact raw payload: base input followed by 384 layers; every byte must be 0..=250.
        #[arg(long)]
        payload: std::path::PathBuf,
        /// New canonical 184-byte-header V2 bank. Existing paths are never overwritten.
        #[arg(long)]
        bank_output: std::path::PathBuf,
        /// New strict manifest JSON. Existing paths are never overwritten.
        #[arg(long)]
        manifest_output: std::path::PathBuf,
    },
    /// Run the two-pass production Dory V3 Model Record V2 ceremony.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelRecordCeremony {
        /// Canonical production model bank to authenticate independently twice.
        #[arg(long)]
        bank: std::path::PathBuf,
        /// Separately trusted canonical production model-bank manifest JSON.
        #[arg(long)]
        manifest: std::path::PathBuf,
        /// New canonical Record V2 JSON path. Existing files are never overwritten.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Generate one full-length production ceremony contribution from the operating-system CSPRNG.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelContributionGenerate {
        /// New 6,442,975,232-byte contribution path. Existing paths are never overwritten.
        /// Use an operator-owned local directory; Windows requires an operator-only parent DACL.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Combine ordered production ceremony contributions bytewise modulo 251.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelCombine {
        /// Exact signed transcript prefix ending at type 5 and EOF (at most 1 MiB).
        #[arg(long)]
        reveal_set_prefix: std::path::PathBuf,
        /// Independently authenticated ceremony ID as exactly 64 lowercase hexadecimal characters.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_ceremony_id: [u8; 32],
        /// Ordered local contribution paths in operator-owned parents, repeated in operator-index order (3 through 16).
        #[arg(long = "contribution", required = true)]
        contributions: Vec<std::path::PathBuf>,
        /// New raw payload in an operator-owned local directory. On Windows the parent must have an operator-only DACL.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Generate and authenticate the frozen production model-roots artifact.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelRootsGenerate {
        /// Existing absolute path to the exact raw production payload.
        #[arg(long, value_parser = parse_absolute_path)]
        payload: std::path::PathBuf,
        /// New absolute path for the CMFDMR01 roots artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        roots_output: std::path::PathBuf,
        /// Ceremony ID as exactly 64 lowercase hexadecimal characters.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_ceremony_id: [u8; 32],
    },
    /// Authenticate an existing production model-roots artifact against its full payload.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelRootsValidate {
        /// Existing absolute path to the exact raw production payload.
        #[arg(long, value_parser = parse_absolute_path)]
        payload: std::path::PathBuf,
        /// Existing absolute path to the CMFDMR01 roots artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        roots: std::path::PathBuf,
        /// Independently trusted ceremony ID as exactly 64 lowercase hexadecimal characters.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_ceremony_id: [u8; 32],
    },
    /// Generate and authenticate the frozen production structural-report artifact.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelStructureGenerate {
        /// Existing absolute path to the exact raw production payload.
        #[arg(long, value_parser = parse_absolute_path)]
        payload: std::path::PathBuf,
        /// Existing absolute path to the CMFDMR01 roots artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        roots: std::path::PathBuf,
        /// New absolute path for the CMFDSR01 structural-report artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        structure_output: std::path::PathBuf,
        /// Independently trusted ceremony ID as exactly 64 lowercase hexadecimal characters.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_ceremony_id: [u8; 32],
    },
    /// Authenticate an existing structural report against its roots and full payload.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelStructureValidate {
        /// Existing absolute path to the exact raw production payload.
        #[arg(long, value_parser = parse_absolute_path)]
        payload: std::path::PathBuf,
        /// Existing absolute path to the CMFDMR01 roots artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        roots: std::path::PathBuf,
        /// Existing absolute path to the CMFDSR01 structural-report artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        structure: std::path::PathBuf,
        /// Independently trusted ceremony ID as exactly 64 lowercase hexadecimal characters.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_ceremony_id: [u8; 32],
    },
    /// Run the structural analyzer under the exact signed type-5 ceremony authority.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelStructureGenerateAnchored {
        /// Exact signed transcript prefix ending at type 5 and EOF (at most 1 MiB).
        #[arg(long, value_parser = parse_absolute_path)]
        reveal_set_prefix: std::path::PathBuf,
        /// Independently authenticated ceremony ID as exactly 64 lowercase hexadecimal characters.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_ceremony_id: [u8; 32],
        /// Independently authenticated digest of the final signed type-5 record.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_last_valid_signed_record_digest: [u8; 32],
        /// Existing absolute path to the exact raw production payload.
        #[arg(long, value_parser = parse_absolute_path)]
        payload: std::path::PathBuf,
        /// Existing absolute path to the CMFDMR01 roots artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        roots: std::path::PathBuf,
        /// New absolute path for the CMFDSR01 structural-report artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        structure_output: std::path::PathBuf,
        /// New absolute path reserved for CMFDSE01 evidence if analysis fails closed.
        #[arg(long, value_parser = parse_absolute_path)]
        error_evidence_output: std::path::PathBuf,
    },
    /// Verify a signed type-7 analyzer abort and its exact external CMFDSE01 evidence.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelStructureAbortVerify {
        /// Exact signed transcript ending at type 7 and EOF (at most 1 MiB).
        #[arg(long, value_parser = parse_absolute_path)]
        aborted_transcript: std::path::PathBuf,
        /// Independently authenticated ceremony ID as exactly 64 lowercase hexadecimal characters.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_ceremony_id: [u8; 32],
        /// Independently authenticated digest of the penultimate signed type-5 record.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_last_valid_signed_record_digest: [u8; 32],
        /// Existing absolute path to the exact raw production payload.
        #[arg(long, value_parser = parse_absolute_path)]
        payload: std::path::PathBuf,
        /// Existing absolute path to the CMFDMR01 roots artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        roots: std::path::PathBuf,
        /// Existing absolute path to the CMFDSE01 evidence artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        error_evidence: std::path::PathBuf,
    },
    /// Reconstruct the unsigned type-7 request for an external signer or HSM.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelStructureAbortPrepare {
        /// Exact signed transcript prefix ending at type 5 and EOF (at most 1 MiB).
        #[arg(long, value_parser = parse_absolute_path)]
        reveal_set_prefix: std::path::PathBuf,
        /// Independently authenticated ceremony ID as exactly 64 lowercase hexadecimal characters.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_ceremony_id: [u8; 32],
        /// Independently authenticated digest of the final signed type-5 record.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_last_valid_signed_record_digest: [u8; 32],
        /// Existing absolute path to the retained failed production payload.
        #[arg(long, value_parser = parse_absolute_path)]
        payload: std::path::PathBuf,
        /// Existing absolute path to the CMFDMR01 roots artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        roots: std::path::PathBuf,
        /// Existing absolute path to the CMFDSE01 evidence artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        error_evidence: std::path::PathBuf,
    },
    /// Verify external BIP340 signatures and stage one exact signed type-7 record.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelStructureAbortRecordStage {
        /// Exact signed transcript prefix ending at type 5 and EOF (at most 1 MiB).
        #[arg(long, value_parser = parse_absolute_path)]
        reveal_set_prefix: std::path::PathBuf,
        /// Independently authenticated ceremony ID as exactly 64 lowercase hexadecimal characters.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_ceremony_id: [u8; 32],
        /// Independently authenticated digest of the final signed type-5 record.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_last_valid_signed_record_digest: [u8; 32],
        /// Existing absolute path to the retained failed production payload.
        #[arg(long, value_parser = parse_absolute_path)]
        payload: std::path::PathBuf,
        /// Existing absolute path to the CMFDMR01 roots artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        roots: std::path::PathBuf,
        /// Existing absolute path to the CMFDSE01 evidence artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        error_evidence: std::path::PathBuf,
        /// External operator signature as INDEX:128-lowercase-hex. Repeat as needed.
        #[arg(long, value_parser = parse_external_signature)]
        operator_signature: Vec<ExternalRecordSignature>,
        /// External reproducer signature as INDEX:128-lowercase-hex. Repeat as needed.
        #[arg(long, value_parser = parse_external_signature)]
        reproducer_signature: Vec<ExternalRecordSignature>,
        /// New absolute path for the exact signed type-7 record.
        #[arg(long, value_parser = parse_absolute_path)]
        record_output: std::path::PathBuf,
    },
    /// Stage a new terminal transcript snapshot from an immutable signed type-7 record.
    #[cfg(feature = "dory-bls12-381-prototype")]
    DoryV3ModelStructureAbortTranscriptStage {
        /// Exact signed transcript prefix ending at type 5 and EOF (at most 1 MiB).
        #[arg(long, value_parser = parse_absolute_path)]
        reveal_set_prefix: std::path::PathBuf,
        /// Independently authenticated ceremony ID as exactly 64 lowercase hexadecimal characters.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_ceremony_id: [u8; 32],
        /// Independently authenticated digest of the final signed type-5 record.
        #[arg(long, value_parser = parse_lower_hex_32)]
        expected_last_valid_signed_record_digest: [u8; 32],
        /// Existing absolute path to the retained failed production payload.
        #[arg(long, value_parser = parse_absolute_path)]
        payload: std::path::PathBuf,
        /// Existing absolute path to the CMFDMR01 roots artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        roots: std::path::PathBuf,
        /// Existing absolute path to the CMFDSE01 evidence artifact.
        #[arg(long, value_parser = parse_absolute_path)]
        error_evidence: std::path::PathBuf,
        /// Existing absolute path to the staged exact signed type-7 record.
        #[arg(long, value_parser = parse_absolute_path)]
        signed_abort_record: std::path::PathBuf,
        /// New absolute path for the complete aborted-transcript snapshot.
        #[arg(long, value_parser = parse_absolute_path)]
        transcript_output: std::path::PathBuf,
    },
    /// Derive the reproducible production BLAKE3 preprocessing-only BLS record.
    #[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
    BlsBlake3PreprocessingCommitment {
        /// Existing absolute directory for owned temporary artifacts.
        #[arg(long)]
        scratch: std::path::PathBuf,
        /// New JSON record path; omit for stdout. Existing files are never overwritten.
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    /// Execute one nonce and create a strict production Dory V3 qualification request.
    #[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
    DoryV3QualifyRequest {
        /// Existing absolute canonical production model bank.
        #[arg(long, value_parser = parse_absolute_path)]
        bank: std::path::PathBuf,
        /// Existing absolute canonical production Record V2 JSON.
        #[arg(long, value_parser = parse_absolute_path)]
        record: std::path::PathBuf,
        /// Existing absolute strict JSON containing only the block and selected nonce.
        #[arg(long, value_parser = parse_absolute_path)]
        seed: std::path::PathBuf,
        /// New absolute runner-owned scratch directory.
        #[arg(long, value_parser = parse_absolute_path)]
        scratch: std::path::PathBuf,
        /// New absolute strict qualification-request JSON output.
        #[arg(long, value_parser = parse_absolute_path)]
        request_output: std::path::PathBuf,
    },
    /// Run one unchanged n=33 Dory V3 production qualification.
    #[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
    DoryV3Qualify {
        /// Canonical production model bank.
        #[arg(long)]
        bank: std::path::PathBuf,
        /// Canonical production Record V2 JSON.
        #[arg(long)]
        record: std::path::PathBuf,
        /// Strict qualification request JSON containing the block and winning claim.
        #[arg(long)]
        request: std::path::PathBuf,
        /// New absolute runner-owned scratch directory.
        #[arg(long)]
        scratch: std::path::PathBuf,
        /// New canonical proof-wire output path.
        #[arg(long)]
        proof_output: std::path::PathBuf,
        /// New report written last as the completion marker; publication is not crash-atomic.
        #[arg(long)]
        report_output: std::path::PathBuf,
        /// Maximum native BLAKE3 rows materialized in one block.
        #[arg(long)]
        maximum_native_block_rows: usize,
    },
}

#[cfg(feature = "dory-bls12-381-prototype")]
fn parse_lower_hex_32(encoded: &str) -> std::result::Result<[u8; 32], String> {
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("expected exactly 64 lowercase hexadecimal characters".to_owned());
    }
    let decoded = hex::decode(encoded)
        .map_err(|_| "expected exactly 64 lowercase hexadecimal characters".to_owned())?;
    decoded
        .try_into()
        .map_err(|_| "expected exactly 32 decoded bytes".to_owned())
}

#[cfg(feature = "dory-bls12-381-prototype")]
fn parse_external_signature(encoded: &str) -> std::result::Result<ExternalRecordSignature, String> {
    let (index, signature) = encoded
        .split_once(':')
        .ok_or_else(|| "expected INDEX:128-lowercase-hex external BIP340 signature".to_owned())?;
    if index.is_empty()
        || (index.len() > 1 && index.starts_with('0'))
        || !index.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("expected a canonical decimal signer index".to_owned());
    }
    let signer_index = index
        .parse::<u16>()
        .map_err(|_| "signer index must fit unsigned 16 bits".to_owned())?;
    if signature.len() != 128
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("expected exactly 128 lowercase hexadecimal signature characters".to_owned());
    }
    let signature = hex::decode(signature)
        .map_err(|_| "expected exactly 128 lowercase hexadecimal signature characters".to_owned())?
        .try_into()
        .map_err(|_| "expected exactly 64 decoded signature bytes".to_owned())?;
    Ok(ExternalRecordSignature {
        signer_index,
        signature,
    })
}

#[cfg(feature = "dory-bls12-381-prototype")]
fn parse_absolute_path(encoded: &str) -> std::result::Result<std::path::PathBuf, String> {
    let path = std::path::PathBuf::from(encoded);
    if !path.is_absolute() {
        return Err("expected an absolute artifact path".to_owned());
    }
    Ok(path)
}

#[cfg(feature = "dory-bls12-381-prototype")]
fn print_model_roots(roots: &ProductionDoryV3ModelRoots) {
    println!("ceremony_id {}", roots.ceremony_id());
    println!("payload_bytes {}", roots.payload_bytes());
    println!("raw_blake3 {}", roots.raw_blake3());
    println!("raw_sha256 {}", roots.raw_sha256());
    println!("base_input_blake3_root {}", roots.base_input_blake3_root());
    println!("layer_roots {}", roots.layer_roots().len());
    println!("layer_roots_aggregate {}", roots.layer_roots_aggregate());
}

#[cfg(feature = "dory-bls12-381-prototype")]
fn print_structural_report(report: &ProductionDoryV3ModelStructuralReport) {
    println!("ceremony_id {}", report.ceremony_id());
    println!("payload_bytes {}", report.payload_bytes());
    println!("raw_blake3 {}", report.raw_payload_blake3());
    println!("raw_sha256 {}", report.raw_payload_sha256());
    println!("sections {}", report.sections().len());
    println!("duplicate_row_pairs {}", report.duplicate_row_pairs());
    println!("duplicate_column_pairs {}", report.duplicate_column_pairs());
    println!("duplicate_layer_pairs {}", report.duplicate_layer_pairs());
    println!("diagnostic_mask 0x{:08x}", report.diagnostic_mask());
    println!("fatal_mask 0x{:08x}", report.fatal_mask());
}

#[cfg(feature = "dory-bls12-381-prototype")]
fn read_ceremony_transcript(path: &std::path::Path, description: &str) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open {description} {}", path.display()))?;
    let limit = u64::try_from(MAX_CEREMONY_TRANSCRIPT_BYTES)
        .expect("the 1 MiB transcript cap fits u64")
        + 1;
    let mut reader = file.take(limit);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {description} {}", path.display()))?;
    if bytes.len() > MAX_CEREMONY_TRANSCRIPT_BYTES {
        anyhow::bail!(
            "{description} {} exceeds the {}-byte protocol cap",
            path.display(),
            MAX_CEREMONY_TRANSCRIPT_BYTES
        );
    }
    Ok(bytes)
}

#[cfg(feature = "dory-bls12-381-prototype")]
fn print_structural_error_evidence(
    evidence: &AuthenticatedProductionDoryV3StructuralErrorEvidence,
) {
    let claims = evidence.claims();
    let identity = evidence.file_identity();
    println!("evidence_bytes {}", identity.bytes);
    println!("evidence_blake3 {}", hex::encode(identity.blake3));
    println!("evidence_sha256 {}", hex::encode(identity.sha256));
    println!("ceremony_id {}", hex::encode(claims.ceremony_id()));
    println!(
        "last_valid_signed_record_digest {}",
        hex::encode(claims.last_valid_signed_record_digest())
    );
    println!("analyzer_target_id {}", claims.analyzer_target_id());
    println!("analyzer_blake3 {}", hex::encode(claims.analyzer_blake3()));
    println!("analyzer_sha256 {}", hex::encode(claims.analyzer_sha256()));
    println!("roots_bytes {}", claims.roots_file().bytes);
    println!("roots_blake3 {}", hex::encode(claims.roots_file().blake3));
    println!("roots_sha256 {}", hex::encode(claims.roots_file().sha256));
    println!("expected_payload_bytes {}", claims.expected_payload_bytes());
    println!("opened_payload_bytes {}", claims.opened_payload_bytes());
    println!("payload_prefix_bytes {}", claims.payload_prefix_bytes());
    println!(
        "payload_prefix_blake3 {}",
        hex::encode(claims.payload_prefix_blake3())
    );
    println!(
        "payload_prefix_sha256 {}",
        hex::encode(claims.payload_prefix_sha256())
    );
    println!("failure_operation {}", claims.operation() as u16);
    println!("failure_stage {}", claims.stage() as u16);
    println!("failure_class {}", claims.failure_class() as u16);
    println!("failure_code {}", claims.failure_code() as u16);
    println!("failure_detail {}", claims.detail());
}

#[cfg(feature = "dory-bls12-381-prototype")]
const fn structural_abort_subject_binding_label(
    binding: ProductionDoryV3StructuralAbortSubjectBinding,
) -> &'static str {
    match binding {
        ProductionDoryV3StructuralAbortSubjectBinding::AttestationOnly => "attestation_only",
        ProductionDoryV3StructuralAbortSubjectBinding::RetainedPayloadObservationVerified => {
            "retained_payload_observation_verified"
        }
    }
}

fn sample_block(network_id: [u8; 32], target: [u8; 32]) -> BlockChallenge {
    BlockChallenge {
        network_id,
        previous_block: [0x11; 32],
        transaction_root: [0x22; 32],
        height: 42,
        timestamp: 1_777_777_777,
        target,
    }
}

fn run_cli() -> Result<()> {
    match Cli::parse().command {
        Command::Vector => {
            let verifier = ForgeMatrixVerifier::new(TEST_PROFILE)?;
            let block = sample_block([0x33; 32], [0xff; 32]);
            let proof = verifier.prove(&block, 7);
            verifier.verify(&block, &proof)?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
        }
        Command::Mine {
            leading_zero_bits,
            attempts,
        } => {
            let verifier = ForgeMatrixVerifier::new(TEST_PROFILE)?;
            let block = sample_block([0x33; 32], target_with_leading_zero_bits(leading_zero_bits));
            let proof = verifier
                .mine(&block, 0, attempts)
                .with_context(|| format!("no solution in {attempts} attempts"))?;
            verifier.verify(&block, &proof)?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
        }
        Command::Economics { height, fees } => {
            let allocation = DEFAULT_MONETARY_POLICY.allocation(height, fees)?;
            println!("{}", serde_json::to_string_pretty(&allocation)?);
        }
        Command::GpuFixture { output, nonce } => {
            let verifier = ForgeMatrixVerifier::new(TEST_PROFILE)?;
            let fixture = verifier.gpu_fixture(&sample_block([0x33; 32], [0xff; 32]), nonce);
            std::fs::write(&output, fixture)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!("wrote {}", output.display());
        }
        Command::GpuFixtureV2 { output, nonce } => {
            let oracle = v2_test_reference()?;
            let fixture = oracle.gpu_fixture(
                &sample_block(oracle.descriptor().network_id, [0xff; 32]),
                nonce,
            )?;
            std::fs::write(&output, fixture)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!("wrote {}", output.display());
        }
        Command::Profile16gb => {
            println!(
                "{}",
                serde_json::to_string_pretty(&CANDIDATE_16GB_PROFILE.metrics())?
            );
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::BlsModelCommitment {
            bank,
            manifest,
            model_identity,
            padded_variables,
            output,
        } => {
            let manifest_reader = std::fs::File::open(&manifest)
                .with_context(|| format!("failed to open {}", manifest.display()))?;
            let trusted_manifest: ModelBankManifest = serde_json::from_reader(manifest_reader)
                .with_context(|| format!("failed to parse {}", manifest.display()))?;
            let identity_reader = std::fs::File::open(&model_identity)
                .with_context(|| format!("failed to open {}", model_identity.display()))?;
            let trusted_identity: ModelPcsIdentity = serde_json::from_reader(identity_reader)
                .with_context(|| format!("failed to parse {}", model_identity.display()))?;
            let bank_reader = std::fs::File::open(&bank)
                .with_context(|| format!("failed to open {}", bank.display()))?;
            let setup = deterministic_bls_dory_setup(padded_variables)
                .context("failed to derive deterministic BLS setup")?;
            let record = derive_bls_dory_model_commitment_record(
                bank_reader,
                &trusted_manifest,
                &trusted_identity,
                padded_variables,
                &setup,
            )
            .context("failed to derive authenticated fixed-model commitments")?;
            let mut encoded = serde_json::to_vec_pretty(&record)?;
            encoded.push(b'\n');
            if let Some(output) = output {
                use std::io::Write as _;

                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&output)
                    .with_context(|| {
                        format!("failed to create new output file {}", output.display())
                    })?;
                file.write_all(&encoded)
                    .with_context(|| format!("failed to write {}", output.display()))?;
                file.sync_all()
                    .with_context(|| format!("failed to sync {}", output.display()))?;
                println!("wrote {}", output.display());
                println!("record digest {}", record.record_digest);
            } else {
                print!("{}", String::from_utf8(encoded)?);
            }
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelBankBootstrap {
            payload,
            bank_output,
            manifest_output,
        } => {
            let report = run_production_dory_v3_model_bank_bootstrap(
                &payload,
                &bank_output,
                &manifest_output,
            )
            .context("production Dory V3 model-bank bootstrap failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelRecordCeremony {
            bank,
            manifest,
            output,
        } => {
            let manifest_reader = std::fs::File::open(&manifest)
                .with_context(|| format!("failed to open {}", manifest.display()))?;
            let trusted_manifest: ModelBankManifest = serde_json::from_reader(manifest_reader)
                .with_context(|| format!("failed to parse {}", manifest.display()))?;
            let report =
                run_production_dory_v3_model_record_v2_ceremony(&bank, &trusted_manifest, &output)
                    .context("production Dory V3 Model Record V2 ceremony failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelContributionGenerate { output } => {
            let report = generate_production_dory_v3_model_contribution(&output)
                .context("production Dory V3 model contribution generation failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelCombine {
            reveal_set_prefix,
            expected_ceremony_id,
            contributions,
            output,
        } => {
            let prefix_bytes = read_ceremony_transcript(&reveal_set_prefix, "reveal-set prefix")?;
            let transcript =
                parse_and_verify_reveal_set_prefix(&prefix_bytes, expected_ceremony_id)
                    .with_context(|| {
                        format!(
                            "failed to verify anchored reveal-set prefix {}",
                            reveal_set_prefix.display()
                        )
                    })?;
            let report = combine_production_dory_v3_model_contributions(
                &transcript,
                &contributions,
                &output,
            )
            .context("production Dory V3 contribution combination failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelRootsGenerate {
            payload,
            roots_output,
            expected_ceremony_id,
        } => {
            let file_report = generate_production_dory_v3_model_roots_file(
                &payload,
                &roots_output,
                Digest32::new(expected_ceremony_id),
            )
            .context("production Dory V3 model-roots generation failed")?;
            println!("roots_generated {}", roots_output.display());
            print_model_roots(file_report.roots());
            println!("durability {:?}", file_report.durability());
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelRootsValidate {
            payload,
            roots,
            expected_ceremony_id,
        } => {
            let validated = validate_production_dory_v3_model_roots_files(
                &roots,
                &payload,
                Digest32::new(expected_ceremony_id),
            )
            .context("production Dory V3 model-roots validation failed")?;
            println!("roots_validated {}", roots.display());
            print_model_roots(&validated);
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelStructureGenerate {
            payload,
            roots,
            structure_output,
            expected_ceremony_id,
        } => {
            let validated_roots = validate_production_dory_v3_model_roots_files(
                &roots,
                &payload,
                Digest32::new(expected_ceremony_id),
            )
            .context("production Dory V3 model-roots validation failed")?;
            let run = run_production_dory_v3_model_structural_report(
                &payload,
                &validated_roots,
                &structure_output,
            )
            .context("production Dory V3 structural-report generation failed")?;
            println!("structure_generated {}", run.output.display());
            println!("report_bytes {}", run.report_bytes);
            println!("report_blake3 {}", run.report_blake3);
            println!("report_sha256 {}", run.report_sha256);
            print_structural_report(&run.report);
            println!("durability {:?}", run.durability);
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelStructureValidate {
            payload,
            roots,
            structure,
            expected_ceremony_id,
        } => {
            let validated_roots = validate_production_dory_v3_model_roots_files(
                &roots,
                &payload,
                Digest32::new(expected_ceremony_id),
            )
            .context("production Dory V3 model-roots validation failed")?;
            let report = validate_production_dory_v3_model_structural_report_files(
                &payload,
                &structure,
                &validated_roots,
            )
            .context("production Dory V3 structural-report validation failed")?;
            println!("structure_validated {}", structure.display());
            print_structural_report(&report);
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelStructureGenerateAnchored {
            reveal_set_prefix,
            expected_ceremony_id,
            expected_last_valid_signed_record_digest,
            payload,
            roots,
            structure_output,
            error_evidence_output,
        } => {
            let prefix = read_ceremony_transcript(&reveal_set_prefix, "reveal-set prefix")?;
            match run_anchored_production_dory_v3_model_structural_report(
                &prefix,
                expected_ceremony_id,
                expected_last_valid_signed_record_digest,
                &payload,
                &roots,
                &structure_output,
                &error_evidence_output,
            )
            .context("anchored production Dory V3 structural analysis failed")?
            {
                ProductionDoryV3StructuralAnalyzerOutcome::Report(run) => {
                    println!("outcome completed");
                    println!("structure_generated {}", run.output.display());
                    println!("report_bytes {}", run.report_bytes);
                    println!("report_blake3 {}", run.report_blake3);
                    println!("report_sha256 {}", run.report_sha256);
                    print_structural_report(&run.report);
                    println!("durability {:?}", run.durability);
                }
                ProductionDoryV3StructuralAnalyzerOutcome::AbortEvidence(report) => {
                    println!("outcome abort_evidence_prepared");
                    println!("error_evidence {}", report.output().display());
                    print_structural_error_evidence(report.evidence());
                    let abort = report.prepared_abort();
                    let body = abort.body();
                    let content_digest =
                        ceremony_record_content_digest(&CeremonyRecordBody::Abort(body.clone()))?;
                    println!("abort_record_type 7");
                    println!("abort_ceremony_id {}", hex::encode(body.ceremony_id));
                    println!(
                        "abort_last_valid_signed_record_digest {}",
                        hex::encode(body.last_valid_signed_record_digest)
                    );
                    println!("abort_phase {}", body.phase);
                    println!("abort_reason_code {}", body.reason_code);
                    println!(
                        "abort_record_content_digest {}",
                        hex::encode(content_digest)
                    );
                    println!(
                        "abort_signature_message {}",
                        hex::encode(abort.signature_message())
                    );
                    println!("signature_policy one-or-more-frozen-roster-members");
                    println!("durability {:?}", report.durability());
                    anyhow::bail!(
                        "structural analysis failed closed; durable evidence and an unsigned type-7 abort were prepared"
                    );
                }
            }
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelStructureAbortVerify {
            aborted_transcript,
            expected_ceremony_id,
            expected_last_valid_signed_record_digest,
            payload,
            roots,
            error_evidence,
        } => {
            let transcript = read_ceremony_transcript(&aborted_transcript, "aborted transcript")?;
            let verified = verify_anchored_production_dory_v3_structural_abort(
                &transcript,
                expected_ceremony_id,
                expected_last_valid_signed_record_digest,
                &payload,
                &roots,
                &error_evidence,
            )
            .context("signed production Dory V3 structural abort verification failed")?;
            println!("outcome abort_verified");
            println!("transcript {}", aborted_transcript.display());
            println!("error_evidence {}", error_evidence.display());
            println!(
                "subject_binding {}",
                structural_abort_subject_binding_label(verified.subject_binding())
            );
            print_structural_error_evidence(verified.evidence());
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelStructureAbortPrepare {
            reveal_set_prefix,
            expected_ceremony_id,
            expected_last_valid_signed_record_digest,
            payload,
            roots,
            error_evidence,
        } => {
            let prefix = read_ceremony_transcript(&reveal_set_prefix, "reveal-set prefix")?;
            let reprepared = prepare_anchored_production_dory_v3_structural_abort_from_files(
                &prefix,
                expected_ceremony_id,
                expected_last_valid_signed_record_digest,
                &payload,
                &roots,
                &error_evidence,
            )
            .context("failed to reconstruct the anchored structural-abort signing request")?;
            let abort = reprepared.prepared_abort();
            let body = abort.body();
            println!("outcome abort_prepared");
            println!("reveal_set_prefix {}", reveal_set_prefix.display());
            println!("error_evidence {}", error_evidence.display());
            print_structural_error_evidence(reprepared.evidence());
            println!("abort_record_type 7");
            println!("abort_ceremony_id {}", hex::encode(body.ceremony_id));
            println!(
                "abort_last_valid_signed_record_digest {}",
                hex::encode(body.last_valid_signed_record_digest)
            );
            println!("abort_phase {}", body.phase);
            println!("abort_reason_code {}", body.reason_code);
            println!(
                "abort_record_content_digest {}",
                hex::encode(ceremony_record_content_digest(&CeremonyRecordBody::Abort(
                    body.clone()
                ))?)
            );
            println!(
                "abort_signature_message {}",
                hex::encode(abort.signature_message())
            );
            println!(
                "subject_binding {}",
                structural_abort_subject_binding_label(reprepared.subject_binding())
            );
            println!("signature_algorithm bip340_raw_32_byte_message");
            println!("private_key_handling external_only");
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelStructureAbortRecordStage {
            reveal_set_prefix,
            expected_ceremony_id,
            expected_last_valid_signed_record_digest,
            payload,
            roots,
            error_evidence,
            operator_signature,
            reproducer_signature,
            record_output,
        } => {
            let prefix = read_ceremony_transcript(&reveal_set_prefix, "reveal-set prefix")?;
            let mut signatures: Vec<_> = operator_signature
                .into_iter()
                .map(|signature| signature.into_record_signature(SignerClass::Operator))
                .collect();
            signatures.extend(
                reproducer_signature
                    .into_iter()
                    .map(|signature| signature.into_record_signature(SignerClass::Reproducer)),
            );
            let report = stage_anchored_production_dory_v3_structural_abort_record(
                &prefix,
                expected_ceremony_id,
                expected_last_valid_signed_record_digest,
                &payload,
                &roots,
                &error_evidence,
                signatures,
                &record_output,
            )
            .context("failed to verify and stage the signed structural-abort record")?;
            let identity = report.record_file();
            println!("outcome record_staged");
            println!("signed_abort_record {}", report.output().display());
            println!("record_bytes {}", identity.bytes);
            println!("record_blake3 {}", hex::encode(identity.blake3));
            println!("record_sha256 {}", hex::encode(identity.sha256));
            println!(
                "record_content_digest {}",
                hex::encode(report.record_content_digest())
            );
            println!(
                "signed_record_digest {}",
                hex::encode(report.signed_record_digest())
            );
            println!(
                "abort_signature_message {}",
                hex::encode(report.signature_message())
            );
            println!("signer_count {}", report.signer_count());
            println!(
                "subject_binding {}",
                structural_abort_subject_binding_label(report.subject_binding())
            );
            println!("durability {:?}", report.durability());
            println!("mirror_publication_pending true");
        }
        #[cfg(feature = "dory-bls12-381-prototype")]
        Command::DoryV3ModelStructureAbortTranscriptStage {
            reveal_set_prefix,
            expected_ceremony_id,
            expected_last_valid_signed_record_digest,
            payload,
            roots,
            error_evidence,
            signed_abort_record,
            transcript_output,
        } => {
            let prefix = read_ceremony_transcript(&reveal_set_prefix, "reveal-set prefix")?;
            let report = stage_anchored_production_dory_v3_structural_abort_transcript(
                &prefix,
                expected_ceremony_id,
                expected_last_valid_signed_record_digest,
                &payload,
                &roots,
                &error_evidence,
                &signed_abort_record,
                &transcript_output,
            )
            .context("failed to stage the terminal structural-abort transcript")?;
            let transcript = report.transcript_file();
            let record = report.record_file();
            println!("outcome transcript_staged");
            println!("aborted_transcript {}", report.output().display());
            println!("transcript_bytes {}", transcript.bytes);
            println!("transcript_blake3 {}", hex::encode(transcript.blake3));
            println!("transcript_sha256 {}", hex::encode(transcript.sha256));
            println!(
                "transcript_derive_key_digest {}",
                hex::encode(report.transcript_derive_key_digest())
            );
            println!("record_bytes {}", record.bytes);
            println!("record_blake3 {}", hex::encode(record.blake3));
            println!("record_sha256 {}", hex::encode(record.sha256));
            println!(
                "subject_binding {}",
                structural_abort_subject_binding_label(report.subject_binding())
            );
            println!("durability {:?}", report.durability());
            println!("mirror_publication_pending true");
        }
        #[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
        Command::BlsBlake3PreprocessingCommitment { scratch, output } => {
            if let Some(output) = &output {
                match std::fs::symlink_metadata(output) {
                    Ok(_) => anyhow::bail!(
                        "refusing to run the ceremony because output already exists: {}",
                        output.display()
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to inspect output path {}", output.display())
                        });
                    }
                }
            }
            let record = derive_bls_dory_blake3_preprocessing_record(&scratch)
                .context("failed to derive production BLAKE3 preprocessing commitment")?;
            let mut encoded = serde_json::to_vec_pretty(&record)?;
            encoded.push(b'\n');
            if let Some(output) = output {
                use std::io::Write as _;

                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&output)
                    .with_context(|| {
                        format!("failed to create new output file {}", output.display())
                    })?;
                file.write_all(&encoded).with_context(|| {
                    format!(
                        "failed to write {}; the newly created output may be incomplete",
                        output.display()
                    )
                })?;
                file.sync_all().with_context(|| {
                    format!(
                        "failed to sync {}; the newly created output may be incomplete",
                        output.display()
                    )
                })?;
                println!("wrote {}", output.display());
                println!("record digest {}", record.record_digest);
            } else {
                print!("{}", String::from_utf8(encoded)?);
            }
        }
        #[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
        Command::DoryV3QualifyRequest {
            bank,
            record,
            seed,
            scratch,
            request_output,
        } => {
            let seed_reader = std::fs::File::open(&seed)
                .with_context(|| format!("failed to open {}", seed.display()))?;
            let qualification_seed: ProductionDoryV3QualificationSeed =
                serde_json::from_reader(seed_reader)
                    .with_context(|| format!("failed to parse {}", seed.display()))?;
            let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let signal_cancel = std::sync::Arc::clone(&cancel);
            ctrlc::set_handler(move || {
                signal_cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            })
            .context("failed to install qualification-request Ctrl-C handler")?;
            let report = generate_production_dory_v3_qualification_request(
                &bank,
                &record,
                &qualification_seed,
                &scratch,
                &request_output,
                cancel.as_ref(),
            )
            .context("production Dory V3 qualification-request generation failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        #[cfg(all(feature = "dory-bls12-381-prototype", feature = "whir-prototype"))]
        Command::DoryV3Qualify {
            bank,
            record,
            request,
            scratch,
            proof_output,
            report_output,
            maximum_native_block_rows,
        } => {
            let request_reader = std::fs::File::open(&request)
                .with_context(|| format!("failed to open {}", request.display()))?;
            let qualification_request: ProductionDoryV3QualificationRequest =
                serde_json::from_reader(request_reader)
                    .with_context(|| format!("failed to parse {}", request.display()))?;
            let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let signal_cancel = std::sync::Arc::clone(&cancel);
            ctrlc::set_handler(move || {
                signal_cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            })
            .context("failed to install qualification Ctrl-C handler")?;
            let report = run_production_dory_v3_qualification(
                &bank,
                &record,
                &qualification_request,
                &scratch,
                &proof_output,
                &report_output,
                maximum_native_block_rows,
                cancel.as_ref(),
            )
            .context("production Dory V3 qualification failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn main() -> Result<()> {
    // Clap's debug command graph exceeds the Windows main thread's 1 MiB stack.
    std::thread::Builder::new()
        .name("cmfd-consensus-cli".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(run_cli)
        .context("failed to start the Windows CLI worker")?
        .join()
        .map_err(|_| anyhow::anyhow!("the Windows CLI worker panicked"))?
}

#[cfg(not(windows))]
fn main() -> Result<()> {
    run_cli()
}

#[cfg(all(test, feature = "dory-bls12-381-prototype"))]
mod tests {
    use super::*;

    #[test]
    fn external_signature_parser_accepts_only_canonical_bip340_tuples() {
        let signature_hex = "ab".repeat(64);
        let parsed = parse_external_signature(&format!("17:{signature_hex}")).unwrap();
        assert_eq!(parsed.signer_index, 17);
        assert_eq!(parsed.signature, [0xab; 64]);
        assert_eq!(
            parse_external_signature(&format!("0:{signature_hex}"))
                .unwrap()
                .signer_index,
            0
        );
        assert_eq!(
            parse_external_signature(&format!("65535:{signature_hex}"))
                .unwrap()
                .signer_index,
            u16::MAX
        );

        let invalid = [
            signature_hex.clone(),
            format!(":{signature_hex}"),
            format!("01:{signature_hex}"),
            format!("+1:{signature_hex}"),
            format!("65536:{signature_hex}"),
            format!("1:{}", "ab".repeat(63)),
            format!("1:{}", "ab".repeat(65)),
            format!("1:{}", "AB".repeat(64)),
            format!("1:{signature_hex}:00"),
        ];
        for encoded in invalid {
            assert!(
                parse_external_signature(&encoded).is_err(),
                "accepted noncanonical external signature tuple: {encoded}"
            );
        }
    }
}
