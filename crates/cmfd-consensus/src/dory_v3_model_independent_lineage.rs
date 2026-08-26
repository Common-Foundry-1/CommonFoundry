//! Signed independent-implementation lineage approval for one Dory V3 reproduction.
//!
//! `CMFDIL01` is an accountable human approval, not a cryptographic proof of
//! independent authorship. Its exact roster signatures make false or careless
//! approval attributable. They cannot prove that the named source, build, or
//! review process was genuinely independent.

use std::{
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use k256::schnorr::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    dory_v3_model_ceremony_fs::{
        AuthenticatedInput, CeremonyFsError, FileIdentity as CeremonyFilesystemIdentity,
        TrustedCeremonyParent,
    },
    dory_v3_model_ceremony_transcript::{
        CeremonyRecordBody, CeremonyTranscriptError, FileIdentity, GenesisBody,
        MAX_CEREMONY_SIGNERS, RecordSignature, SignerClass, VerifiedCeremonyTranscript,
        ceremony_signed_record_digest,
    },
    dory_v3_model_reproduction::{
        ContextVerifiedProductionDoryV3ModelReproductionReport,
        ProductionDoryV3ReproductionImplementationKind,
    },
};

pub const PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_MAGIC: [u8; 8] = *b"CMFDIL01";
pub const PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_VERSION: u16 = 1;
pub const PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES: usize = 1_284;
pub const PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_SIGNATURE_BYTES: usize = 67;
pub const MAX_PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_BYTES: usize =
    PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES
        + MAX_CEREMONY_SIGNERS * PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_SIGNATURE_BYTES;

const CONTENT_END: usize = PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES - 2;
const CONTENT_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/MODEL-REPRODUCTION/INDEPENDENT-LINEAGE-ATTESTATION/V1";
const SIGNATURE_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/MODEL-REPRODUCTION/INDEPENDENT-LINEAGE-ATTESTATION/SIGNATURE/V1";
const EVIDENCE_FIELD_NAMES: [&str; 11] = [
    "combiner source bundle",
    "combiner build provenance",
    "combiner binary",
    "roots-calculator source bundle",
    "roots-calculator build provenance",
    "roots-calculator binary",
    "independent-lineage review report",
    "conformance-test report",
    "host-environment report",
    "source-extraction report",
    "command log",
];

const _: [(); PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES] = [(); 8
    + 2
    + 4
    + 4 * 32
    + (8 + 32 + 32)
    + 32
    + 2
    + 32
    + 2
    + 2 * (8 + 32 + 32)
    + 2 * 32
    + 11 * (8 + 32 + 32)
    + 2];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProductionDoryV3IndependentLineageError {
    #[error("independent-lineage artifact length mismatch: expected {expected}, observed {actual}")]
    ArtifactLength { expected: usize, actual: usize },
    #[error("invalid independent-lineage artifact magic")]
    InvalidMagic,
    #[error("unsupported independent-lineage artifact version {0}")]
    UnsupportedVersion(u16),
    #[error("truncated independent-lineage artifact while reading {0}")]
    Truncated(&'static str),
    #[error("invalid independent-lineage artifact: {0}")]
    Invalid(&'static str),
    #[error("independent-lineage artifact does not match its verified context: {0}")]
    Context(&'static str),
    #[error("invalid ceremony transcript while checking independent lineage: {0}")]
    Transcript(#[from] CeremonyTranscriptError),
    #[error("independent-lineage and evidence paths must be pairwise distinct")]
    PathsNotDistinct,
    #[error("independent-lineage and evidence inputs resolve to the same retained file")]
    AliasedInputs,
    #[error("trusted filesystem validation failed: {0}")]
    TrustedFilesystem(String),
    #[error("retained evidence does not match its signed content identity: {0}")]
    EvidenceIdentity(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IndependentLineageStatement {
    ceremony_id: [u8; 32],
    genesis_signed_record_digest: [u8; 32],
    commitment_set_signed_record_digest: [u8; 32],
    reveal_set_signed_record_digest: [u8; 32],
    reveal_set_prefix: FileIdentity,
    reveal_set_prefix_derive_key_digest: [u8; 32],
    reproducer_index: u16,
    reproducer_public_key: [u8; 32],
    target_id: u16,
    raw_payload: FileIdentity,
    roots_file: FileIdentity,
    base_input_blake3_root: [u8; 32],
    layer_roots_aggregate: [u8; 32],
    combiner_source_bundle: FileIdentity,
    combiner_build_provenance: FileIdentity,
    combiner_binary: FileIdentity,
    roots_calculator_source_bundle: FileIdentity,
    roots_calculator_build_provenance: FileIdentity,
    roots_calculator_binary: FileIdentity,
    independent_lineage_review_report: FileIdentity,
    conformance_test_report: FileIdentity,
    host_environment_report: FileIdentity,
    source_extraction_report: FileIdentity,
    command_log: FileIdentity,
}

/// Read-only external-artifact projection from a verified lineage approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3IndependentLineageArtifacts<'a> {
    pub reveal_set_prefix: &'a FileIdentity,
    pub raw_payload: &'a FileIdentity,
    pub roots_file: &'a FileIdentity,
    pub combiner_source_bundle: &'a FileIdentity,
    pub combiner_build_provenance: &'a FileIdentity,
    pub combiner_binary: &'a FileIdentity,
    pub roots_calculator_source_bundle: &'a FileIdentity,
    pub roots_calculator_build_provenance: &'a FileIdentity,
    pub roots_calculator_binary: &'a FileIdentity,
    pub independent_lineage_review_report: &'a FileIdentity,
    pub conformance_test_report: &'a FileIdentity,
    pub host_environment_report: &'a FileIdentity,
    pub source_extraction_report: &'a FileIdentity,
    pub command_log: &'a FileIdentity,
}

/// Exact paths to the eleven post-root evidence files named by CMFDIL01.
///
/// The lineage artifact itself is passed separately to the verifier. Every
/// path must be an absolute normalized direct child of a trusted private local
/// directory, and all twelve paths and retained file identities must differ.
#[derive(Clone, Copy, Debug)]
pub struct ProductionDoryV3IndependentLineageEvidencePaths<'a> {
    pub combiner_source_bundle: &'a Path,
    pub combiner_build_provenance: &'a Path,
    pub combiner_binary: &'a Path,
    pub roots_calculator_source_bundle: &'a Path,
    pub roots_calculator_build_provenance: &'a Path,
    pub roots_calculator_binary: &'a Path,
    pub independent_lineage_review_report: &'a Path,
    pub conformance_test_report: &'a Path,
    pub host_environment_report: &'a Path,
    pub source_extraction_report: &'a Path,
    pub command_log: &'a Path,
}

impl<'a> ProductionDoryV3IndependentLineageEvidencePaths<'a> {
    const fn ordered(self) -> [&'a Path; 11] {
        [
            self.combiner_source_bundle,
            self.combiner_build_provenance,
            self.combiner_binary,
            self.roots_calculator_source_bundle,
            self.roots_calculator_build_provenance,
            self.roots_calculator_binary,
            self.independent_lineage_review_report,
            self.conformance_test_report,
            self.host_environment_report,
            self.source_extraction_report,
            self.command_log,
        ]
    }
}

struct RetainedLineageInput {
    input: AuthenticatedInput,
    parent: TrustedCeremonyParent,
    expected_content: FileIdentity,
}

impl RetainedLineageInput {
    fn open(
        path: &Path,
        expected_bytes: Option<u64>,
    ) -> Result<Self, ProductionDoryV3IndependentLineageError> {
        let parent = TrustedCeremonyParent::for_artifact(path).map_err(map_fs)?;
        let input = AuthenticatedInput::open(&parent, path, expected_bytes).map_err(map_fs)?;
        Ok(Self {
            input,
            parent,
            expected_content: FileIdentity {
                bytes: 0,
                blake3: [0; 32],
                sha256: [0; 32],
            },
        })
    }

    fn authenticate_content(
        &mut self,
        expected: &FileIdentity,
        field: &'static str,
    ) -> Result<(), ProductionDoryV3IndependentLineageError> {
        self.input
            .recheck(&self.parent, Some(expected.bytes))
            .map_err(map_fs)?;
        let observed = hash_retained_input(&mut self.input, expected.bytes)?;
        self.input
            .recheck(&self.parent, Some(expected.bytes))
            .map_err(map_fs)?;
        if &observed != expected {
            return Err(ProductionDoryV3IndependentLineageError::EvidenceIdentity(
                field,
            ));
        }
        self.expected_content = expected.clone();
        Ok(())
    }

    fn reauthenticate_content(
        &mut self,
        field: &'static str,
    ) -> Result<(), ProductionDoryV3IndependentLineageError> {
        let expected = self.expected_content.clone();
        self.authenticate_content(&expected, field)
    }
}

/// Opaque capability returned only after the artifact, context, and every
/// genesis-roster signature have been verified.
///
/// This type intentionally implements neither `Clone` nor serialization. It
/// proves an accountable signed approval and the exact CMFDRP file-identity
/// binding; it does not prove that the approved implementation was authored
/// independently.
pub struct VerifiedIndependentLineage {
    statement: IndependentLineageStatement,
    artifact_identity: FileIdentity,
    content_digest: [u8; 32],
    signature_message: [u8; 32],
    lineage_input: RetainedLineageInput,
    evidence_inputs: Vec<RetainedLineageInput>,
}

impl VerifiedIndependentLineage {
    #[must_use]
    pub const fn ceremony_id(&self) -> [u8; 32] {
        self.statement.ceremony_id
    }

    #[must_use]
    pub const fn reproducer_index(&self) -> u16 {
        self.statement.reproducer_index
    }

    #[must_use]
    pub const fn reproducer_public_key(&self) -> [u8; 32] {
        self.statement.reproducer_public_key
    }

    #[must_use]
    pub const fn target_id(&self) -> u16 {
        self.statement.target_id
    }

    pub(crate) const fn reveal_set_prefix_derive_key_digest(&self) -> [u8; 32] {
        self.statement.reveal_set_prefix_derive_key_digest
    }

    pub(crate) const fn commitment_set_signed_record_digest(&self) -> [u8; 32] {
        self.statement.commitment_set_signed_record_digest
    }

    pub(crate) const fn reveal_set_signed_record_digest(&self) -> [u8; 32] {
        self.statement.reveal_set_signed_record_digest
    }

    #[must_use]
    pub const fn base_input_blake3_root(&self) -> [u8; 32] {
        self.statement.base_input_blake3_root
    }

    #[must_use]
    pub const fn layer_roots_aggregate(&self) -> [u8; 32] {
        self.statement.layer_roots_aggregate
    }

    #[must_use]
    pub const fn artifact_identity(&self) -> &FileIdentity {
        &self.artifact_identity
    }

    #[must_use]
    pub const fn content_digest(&self) -> [u8; 32] {
        self.content_digest
    }

    #[must_use]
    pub const fn signature_message(&self) -> [u8; 32] {
        self.signature_message
    }

    #[must_use]
    pub const fn artifacts(&self) -> ProductionDoryV3IndependentLineageArtifacts<'_> {
        ProductionDoryV3IndependentLineageArtifacts {
            reveal_set_prefix: &self.statement.reveal_set_prefix,
            raw_payload: &self.statement.raw_payload,
            roots_file: &self.statement.roots_file,
            combiner_source_bundle: &self.statement.combiner_source_bundle,
            combiner_build_provenance: &self.statement.combiner_build_provenance,
            combiner_binary: &self.statement.combiner_binary,
            roots_calculator_source_bundle: &self.statement.roots_calculator_source_bundle,
            roots_calculator_build_provenance: &self.statement.roots_calculator_build_provenance,
            roots_calculator_binary: &self.statement.roots_calculator_binary,
            independent_lineage_review_report: &self.statement.independent_lineage_review_report,
            conformance_test_report: &self.statement.conformance_test_report,
            host_environment_report: &self.statement.host_environment_report,
            source_extraction_report: &self.statement.source_extraction_report,
            command_log: &self.statement.command_log,
        }
    }

    /// Reauthenticate all eleven evidence files and then the lineage artifact.
    ///
    /// The lineage artifact is deliberately last, so no later evidence-file
    /// operation can hide replacement of the signed authority.
    pub fn recheck_retained_files(
        &mut self,
    ) -> Result<(), ProductionDoryV3IndependentLineageError> {
        for (input, field) in self.evidence_inputs.iter_mut().zip(EVIDENCE_FIELD_NAMES) {
            input.reauthenticate_content(field)?;
        }
        self.lineage_input
            .reauthenticate_content("independent-lineage artifact")
    }

    pub(crate) fn retained_filesystem_entries(&self) -> Vec<(PathBuf, CeremonyFilesystemIdentity)> {
        let mut entries = Vec::with_capacity(1 + self.evidence_inputs.len());
        entries.extend(
            self.evidence_inputs
                .iter()
                .map(|input| (input.input.path().to_path_buf(), input.input.identity())),
        );
        entries.push((
            self.lineage_input.input.path().to_path_buf(),
            self.lineage_input.input.identity(),
        ));
        entries
    }
}

struct CoreVerifiedIndependentLineage {
    statement: IndependentLineageStatement,
    artifact_identity: FileIdentity,
    content_digest: [u8; 32],
    signature_message: [u8; 32],
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
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], ProductionDoryV3IndependentLineageError> {
        let end =
            self.offset
                .checked_add(N)
                .ok_or(ProductionDoryV3IndependentLineageError::Invalid(
                    "decoder offset overflow",
                ))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProductionDoryV3IndependentLineageError::Truncated(field))?;
        self.offset = end;
        value
            .try_into()
            .map_err(|_| ProductionDoryV3IndependentLineageError::Truncated(field))
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, ProductionDoryV3IndependentLineageError> {
        Ok(self.take::<1>(field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, ProductionDoryV3IndependentLineageError> {
        Ok(u16::from_le_bytes(self.take(field)?))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, ProductionDoryV3IndependentLineageError> {
        Ok(u32::from_le_bytes(self.take(field)?))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, ProductionDoryV3IndependentLineageError> {
        Ok(u64::from_le_bytes(self.take(field)?))
    }

    fn finish(self) -> Result<(), ProductionDoryV3IndependentLineageError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ProductionDoryV3IndependentLineageError::Invalid(
                "trailing bytes",
            ))
        }
    }
}

fn encode_file_identity(encoder: &mut Encoder, identity: &FileIdentity) {
    encoder.u64(identity.bytes);
    encoder.bytes(&identity.blake3);
    encoder.bytes(&identity.sha256);
}

fn decode_file_identity(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<FileIdentity, ProductionDoryV3IndependentLineageError> {
    Ok(FileIdentity {
        bytes: decoder.u64(field)?,
        blake3: decoder.take(field)?,
        sha256: decoder.take(field)?,
    })
}

fn encode_statement(
    statement: &IndependentLineageStatement,
    total_bytes: u32,
    signer_count: u16,
) -> [u8; PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES] {
    let mut encoder = Encoder::default();
    encoder.bytes(&PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_MAGIC);
    encoder.u16(PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_VERSION);
    encoder.u32(total_bytes);
    encoder.bytes(&statement.ceremony_id);
    encoder.bytes(&statement.genesis_signed_record_digest);
    encoder.bytes(&statement.commitment_set_signed_record_digest);
    encoder.bytes(&statement.reveal_set_signed_record_digest);
    encode_file_identity(&mut encoder, &statement.reveal_set_prefix);
    encoder.bytes(&statement.reveal_set_prefix_derive_key_digest);
    encoder.u16(statement.reproducer_index);
    encoder.bytes(&statement.reproducer_public_key);
    encoder.u16(statement.target_id);
    encode_file_identity(&mut encoder, &statement.raw_payload);
    encode_file_identity(&mut encoder, &statement.roots_file);
    encoder.bytes(&statement.base_input_blake3_root);
    encoder.bytes(&statement.layer_roots_aggregate);
    encode_file_identity(&mut encoder, &statement.combiner_source_bundle);
    encode_file_identity(&mut encoder, &statement.combiner_build_provenance);
    encode_file_identity(&mut encoder, &statement.combiner_binary);
    encode_file_identity(&mut encoder, &statement.roots_calculator_source_bundle);
    encode_file_identity(&mut encoder, &statement.roots_calculator_build_provenance);
    encode_file_identity(&mut encoder, &statement.roots_calculator_binary);
    encode_file_identity(&mut encoder, &statement.independent_lineage_review_report);
    encode_file_identity(&mut encoder, &statement.conformance_test_report);
    encode_file_identity(&mut encoder, &statement.host_environment_report);
    encode_file_identity(&mut encoder, &statement.source_extraction_report);
    encode_file_identity(&mut encoder, &statement.command_log);
    encoder.u16(signer_count);
    debug_assert_eq!(
        encoder.0.len(),
        PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES
    );
    encoder
        .0
        .try_into()
        .expect("the fixed lineage prefix encoder emits its declared length")
}

fn append_signature(encoder: &mut Encoder, signature: &RecordSignature) {
    encoder.u8(match signature.signer_class {
        SignerClass::Operator => 0,
        SignerClass::Reproducer => 1,
    });
    encoder.u16(signature.signer_index);
    encoder.bytes(&signature.signature);
}

fn encode_artifact(
    statement: &IndependentLineageStatement,
    signatures: &[RecordSignature],
) -> Result<Vec<u8>, ProductionDoryV3IndependentLineageError> {
    let signer_count = u16::try_from(signatures.len()).map_err(|_| {
        ProductionDoryV3IndependentLineageError::Invalid("signature count exceeds u16")
    })?;
    let total_bytes = PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES
        .checked_add(
            signatures
                .len()
                .checked_mul(PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_SIGNATURE_BYTES)
                .ok_or(ProductionDoryV3IndependentLineageError::Invalid(
                    "artifact length overflow",
                ))?,
        )
        .ok_or(ProductionDoryV3IndependentLineageError::Invalid(
            "artifact length overflow",
        ))?;
    let total_bytes = u32::try_from(total_bytes).map_err(|_| {
        ProductionDoryV3IndependentLineageError::Invalid("artifact length exceeds u32")
    })?;
    let mut bytes = encode_statement(statement, total_bytes, signer_count).to_vec();
    let mut encoded_signatures = Encoder::default();
    for signature in signatures {
        append_signature(&mut encoded_signatures, signature);
    }
    bytes.extend_from_slice(&encoded_signatures.0);
    Ok(bytes)
}

fn blake3_derive(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn signature_message(
    version: u16,
    total_bytes: u32,
    content_digest: [u8; 32],
    signer_count: u16,
) -> [u8; 32] {
    let mut encoded = Encoder::default();
    encoded.u16(version);
    encoded.u32(total_bytes);
    encoded.bytes(&content_digest);
    encoded.u16(signer_count);
    blake3_derive(SIGNATURE_DOMAIN, &encoded.0)
}

fn file_identity(bytes: &[u8]) -> FileIdentity {
    FileIdentity {
        bytes: u64::try_from(bytes.len()).expect("lineage artifact length fits in u64"),
        blake3: *blake3::hash(bytes).as_bytes(),
        sha256: Sha256::digest(bytes).into(),
    }
}

fn hash_retained_input(
    input: &mut AuthenticatedInput,
    expected_bytes: u64,
) -> Result<FileIdentity, ProductionDoryV3IndependentLineageError> {
    let file = input.file_mut();
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        ProductionDoryV3IndependentLineageError::TrustedFilesystem(error.to_string())
    })?;
    let mut reader = file.take(expected_bytes.saturating_add(1));
    let mut blake3 = blake3::Hasher::new();
    let mut sha256 = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            ProductionDoryV3IndependentLineageError::TrustedFilesystem(error.to_string())
        })?;
        if read == 0 {
            break;
        }
        bytes = bytes.checked_add(read as u64).ok_or(
            ProductionDoryV3IndependentLineageError::Invalid("evidence byte count overflow"),
        )?;
        blake3.update(&buffer[..read]);
        sha256.update(&buffer[..read]);
    }
    if bytes != expected_bytes {
        return Err(ProductionDoryV3IndependentLineageError::Invalid(
            "retained evidence length or EOF",
        ));
    }
    Ok(FileIdentity {
        bytes,
        blake3: *blake3.finalize().as_bytes(),
        sha256: sha256.finalize().into(),
    })
}

fn map_fs(error: CeremonyFsError) -> ProductionDoryV3IndependentLineageError {
    ProductionDoryV3IndependentLineageError::TrustedFilesystem(error.to_string())
}

fn ensure_pairwise_distinct_paths(
    paths: &[&Path],
) -> Result<(), ProductionDoryV3IndependentLineageError> {
    for (index, path) in paths.iter().enumerate() {
        if paths[..index].contains(path) {
            return Err(ProductionDoryV3IndependentLineageError::PathsNotDistinct);
        }
    }
    Ok(())
}

fn ensure_pairwise_distinct_inputs(
    inputs: &[RetainedLineageInput],
) -> Result<(), ProductionDoryV3IndependentLineageError> {
    for (index, input) in inputs.iter().enumerate() {
        if inputs[..index]
            .iter()
            .any(|previous| previous.input.identity() == input.input.identity())
        {
            return Err(ProductionDoryV3IndependentLineageError::AliasedInputs);
        }
    }
    Ok(())
}

fn validate_file_identity(
    identity: &FileIdentity,
    field: &'static str,
) -> Result<(), ProductionDoryV3IndependentLineageError> {
    if identity.bytes == 0 || identity.blake3 == [0; 32] || identity.sha256 == [0; 32] {
        return Err(ProductionDoryV3IndependentLineageError::Invalid(field));
    }
    Ok(())
}

fn validate_statement(
    statement: &IndependentLineageStatement,
) -> Result<(), ProductionDoryV3IndependentLineageError> {
    if statement.ceremony_id == [0; 32]
        || statement.genesis_signed_record_digest == [0; 32]
        || statement.commitment_set_signed_record_digest == [0; 32]
        || statement.reveal_set_signed_record_digest == [0; 32]
        || statement.reveal_set_prefix_derive_key_digest == [0; 32]
        || statement.reproducer_public_key == [0; 32]
        || statement.base_input_blake3_root == [0; 32]
        || statement.layer_roots_aggregate == [0; 32]
    {
        return Err(ProductionDoryV3IndependentLineageError::Invalid(
            "required anchor, key, or digest is zero",
        ));
    }
    VerifyingKey::from_bytes(&statement.reproducer_public_key)
        .map_err(|_| ProductionDoryV3IndependentLineageError::Invalid("reproducer public key"))?;
    if !(1..=2).contains(&statement.target_id) {
        return Err(ProductionDoryV3IndependentLineageError::Invalid(
            "target id",
        ));
    }
    for (identity, field) in [
        (&statement.reveal_set_prefix, "reveal-set prefix identity"),
        (&statement.raw_payload, "raw-payload identity"),
        (&statement.roots_file, "roots-file identity"),
        (
            &statement.combiner_source_bundle,
            "combiner source-bundle identity",
        ),
        (
            &statement.combiner_build_provenance,
            "combiner build-provenance identity",
        ),
        (&statement.combiner_binary, "combiner-binary identity"),
        (
            &statement.roots_calculator_source_bundle,
            "roots-calculator source-bundle identity",
        ),
        (
            &statement.roots_calculator_build_provenance,
            "roots-calculator build-provenance identity",
        ),
        (
            &statement.roots_calculator_binary,
            "roots-calculator binary identity",
        ),
        (
            &statement.independent_lineage_review_report,
            "independent-lineage review-report identity",
        ),
        (
            &statement.conformance_test_report,
            "conformance-test report identity",
        ),
        (
            &statement.host_environment_report,
            "host-environment report identity",
        ),
        (
            &statement.source_extraction_report,
            "source-extraction report identity",
        ),
        (&statement.command_log, "command-log identity"),
    ] {
        validate_file_identity(identity, field)?;
    }
    Ok(())
}

fn binary_reuses_pinned_identity(
    binary: &FileIdentity,
    blake3: [u8; 32],
    sha256: [u8; 32],
) -> bool {
    binary.blake3 == blake3 || binary.sha256 == sha256
}

fn validate_independence_claims(
    statement: &IndependentLineageStatement,
    genesis: &GenesisBody,
) -> Result<(), ProductionDoryV3IndependentLineageError> {
    if statement.combiner_source_bundle == genesis.source_bundle
        || statement.roots_calculator_source_bundle == genesis.source_bundle
    {
        return Err(ProductionDoryV3IndependentLineageError::Context(
            "independent implementation reuses the genesis reference source bundle",
        ));
    }
    for binary in [
        &statement.combiner_binary,
        &statement.roots_calculator_binary,
    ] {
        if genesis.reference_binaries.iter().any(|reference| {
            binary_reuses_pinned_identity(binary, reference.binary_blake3, reference.binary_sha256)
        }) || binary_reuses_pinned_identity(
            binary,
            genesis.structural_analyzer_blake3,
            genesis.structural_analyzer_sha256,
        ) {
            return Err(ProductionDoryV3IndependentLineageError::Context(
                "independent implementation reuses a pinned reference or analyzer binary",
            ));
        }
    }
    Ok(())
}

fn validate_context(
    statement: &IndependentLineageStatement,
    transcript: &VerifiedCeremonyTranscript,
    report: &ContextVerifiedProductionDoryV3ModelReproductionReport,
) -> Result<(), ProductionDoryV3IndependentLineageError> {
    let bindings = transcript.require_combiner_bindings()?;
    let Some(first) = transcript.records().first() else {
        return Err(ProductionDoryV3IndependentLineageError::Context(
            "missing genesis record",
        ));
    };
    let CeremonyRecordBody::Genesis(genesis) = &first.body else {
        return Err(ProductionDoryV3IndependentLineageError::Context(
            "first record is not genesis",
        ));
    };
    let expected_prefix = FileIdentity {
        bytes: transcript.transcript_bytes(),
        blake3: transcript.transcript_blake3(),
        sha256: transcript.transcript_sha256(),
    };
    if statement.ceremony_id != transcript.ceremony_id()
        || statement.genesis_signed_record_digest != ceremony_signed_record_digest(first)?
        || statement.commitment_set_signed_record_digest
            != bindings.commitment_set_signed_record_digest()
        || statement.reveal_set_signed_record_digest != bindings.reveal_set_signed_record_digest()
        || statement.reveal_set_prefix != expected_prefix
        || statement.reveal_set_prefix_derive_key_digest
            != transcript.transcript_derive_key_digest()
    {
        return Err(ProductionDoryV3IndependentLineageError::Context(
            "type-5 transcript binding",
        ));
    }

    let report_body = report.report();
    if report_body.implementation_kind()
        != ProductionDoryV3ReproductionImplementationKind::Independent
    {
        return Err(ProductionDoryV3IndependentLineageError::Context(
            "CMFDRP implementation kind is not independent",
        ));
    }
    if report_body.ceremony_id() != transcript.ceremony_id()
        || report_body.genesis_signed_record_digest() != statement.genesis_signed_record_digest
        || report_body.reveal_set_prefix_identity() != statement.reveal_set_prefix
        || report_body.reveal_set_prefix_derive_key_digest()
            != statement.reveal_set_prefix_derive_key_digest
        || report_body.commitment_set_signed_record_digest()
            != statement.commitment_set_signed_record_digest
        || report_body.reveal_set_signed_record_digest()
            != statement.reveal_set_signed_record_digest
    {
        return Err(ProductionDoryV3IndependentLineageError::Context(
            "CMFDRP was not verified against the same type-5 transcript",
        ));
    }
    if statement.reproducer_index != report_body.reproducer_index()
        || statement.reproducer_public_key != report_body.reproducer_public_key()
        || statement.target_id != report_body.target_id()
    {
        return Err(ProductionDoryV3IndependentLineageError::Context(
            "CMFDRP reproducer or target binding",
        ));
    }
    let candidate = report.final_candidate();
    if &statement.raw_payload != candidate.raw_payload
        || &statement.roots_file != candidate.roots_file
        || statement.base_input_blake3_root != candidate.base_input_blake3_root
        || statement.layer_roots_aggregate != candidate.layer_roots_aggregate
    {
        return Err(ProductionDoryV3IndependentLineageError::Context(
            "CMFDRP candidate binding",
        ));
    }
    let artifacts = report.artifacts();
    if &statement.combiner_binary != artifacts.combiner_binary
        || &statement.host_environment_report != artifacts.host_environment_report
        || &statement.source_extraction_report != artifacts.source_extraction_report
        || &statement.command_log != artifacts.command_log
    {
        return Err(ProductionDoryV3IndependentLineageError::Context(
            "CMFDRP implementation-audit binding",
        ));
    }
    validate_independence_claims(statement, genesis)
}

fn verify_signatures(
    signatures: &[RecordSignature],
    message: &[u8; 32],
    transcript: &VerifiedCeremonyTranscript,
) -> Result<(), ProductionDoryV3IndependentLineageError> {
    let expected_count = transcript
        .operators()
        .len()
        .checked_add(transcript.reproducers().len())
        .ok_or(ProductionDoryV3IndependentLineageError::Invalid(
            "signature count overflow",
        ))?;
    if signatures.len() != expected_count {
        return Err(ProductionDoryV3IndependentLineageError::Context(
            "signature count does not cover the genesis roster",
        ));
    }
    for (position, signature) in signatures.iter().enumerate() {
        let (expected_class, expected_index, public_key) =
            if position < transcript.operators().len() {
                (
                    SignerClass::Operator,
                    u16::try_from(position).expect("operator roster is capped at u16"),
                    &transcript.operators()[position],
                )
            } else {
                let index = position - transcript.operators().len();
                (
                    SignerClass::Reproducer,
                    u16::try_from(index).expect("reproducer roster is capped at u16"),
                    &transcript.reproducers()[index],
                )
            };
        if signature.signer_class != expected_class || signature.signer_index != expected_index {
            return Err(ProductionDoryV3IndependentLineageError::Context(
                "signatures are not in exact genesis-roster order",
            ));
        }
        let key = VerifyingKey::from_bytes(public_key).map_err(|_| {
            ProductionDoryV3IndependentLineageError::Invalid("genesis roster public key")
        })?;
        let parsed = Signature::try_from(signature.signature.as_slice()).map_err(|_| {
            ProductionDoryV3IndependentLineageError::Invalid("canonical BIP340 signature")
        })?;
        key.verify_raw(message, &parsed).map_err(|_| {
            ProductionDoryV3IndependentLineageError::Context("BIP340 signature verification")
        })?;
    }
    Ok(())
}

fn verify_independent_lineage_bytes(
    bytes: &[u8],
    transcript: &VerifiedCeremonyTranscript,
    report: &ContextVerifiedProductionDoryV3ModelReproductionReport,
) -> Result<CoreVerifiedIndependentLineage, ProductionDoryV3IndependentLineageError> {
    if bytes.len() < PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES {
        return Err(ProductionDoryV3IndependentLineageError::ArtifactLength {
            expected: PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES,
            actual: bytes.len(),
        });
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take::<8>("magic")? != PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_MAGIC {
        return Err(ProductionDoryV3IndependentLineageError::InvalidMagic);
    }
    let version = decoder.u16("version")?;
    if version != PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_VERSION {
        return Err(ProductionDoryV3IndependentLineageError::UnsupportedVersion(
            version,
        ));
    }
    let declared_total = decoder.u32("declared artifact bytes")?;
    let statement = IndependentLineageStatement {
        ceremony_id: decoder.take("ceremony id")?,
        genesis_signed_record_digest: decoder.take("genesis signed-record digest")?,
        commitment_set_signed_record_digest: decoder.take("commitment-set signed-record digest")?,
        reveal_set_signed_record_digest: decoder.take("reveal-set signed-record digest")?,
        reveal_set_prefix: decode_file_identity(&mut decoder, "reveal-set prefix identity")?,
        reveal_set_prefix_derive_key_digest: decoder.take("reveal-set prefix derive-key digest")?,
        reproducer_index: decoder.u16("reproducer index")?,
        reproducer_public_key: decoder.take("reproducer public key")?,
        target_id: decoder.u16("target id")?,
        raw_payload: decode_file_identity(&mut decoder, "raw-payload identity")?,
        roots_file: decode_file_identity(&mut decoder, "roots-file identity")?,
        base_input_blake3_root: decoder.take("base-input BLAKE3 root")?,
        layer_roots_aggregate: decoder.take("layer-roots aggregate")?,
        combiner_source_bundle: decode_file_identity(
            &mut decoder,
            "combiner source-bundle identity",
        )?,
        combiner_build_provenance: decode_file_identity(
            &mut decoder,
            "combiner build-provenance identity",
        )?,
        combiner_binary: decode_file_identity(&mut decoder, "combiner-binary identity")?,
        roots_calculator_source_bundle: decode_file_identity(
            &mut decoder,
            "roots-calculator source-bundle identity",
        )?,
        roots_calculator_build_provenance: decode_file_identity(
            &mut decoder,
            "roots-calculator build-provenance identity",
        )?,
        roots_calculator_binary: decode_file_identity(
            &mut decoder,
            "roots-calculator binary identity",
        )?,
        independent_lineage_review_report: decode_file_identity(
            &mut decoder,
            "independent-lineage review-report identity",
        )?,
        conformance_test_report: decode_file_identity(
            &mut decoder,
            "conformance-test report identity",
        )?,
        host_environment_report: decode_file_identity(
            &mut decoder,
            "host-environment report identity",
        )?,
        source_extraction_report: decode_file_identity(
            &mut decoder,
            "source-extraction report identity",
        )?,
        command_log: decode_file_identity(&mut decoder, "command-log identity")?,
    };
    let signer_count = usize::from(decoder.u16("signer count")?);
    if signer_count > MAX_CEREMONY_SIGNERS {
        return Err(ProductionDoryV3IndependentLineageError::Invalid(
            "signature count exceeds ceremony cap",
        ));
    }
    let expected_total = PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES
        .checked_add(
            signer_count
                .checked_mul(PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_SIGNATURE_BYTES)
                .ok_or(ProductionDoryV3IndependentLineageError::Invalid(
                    "artifact length overflow",
                ))?,
        )
        .ok_or(ProductionDoryV3IndependentLineageError::Invalid(
            "artifact length overflow",
        ))?;
    let declared_total = usize::try_from(declared_total)
        .map_err(|_| ProductionDoryV3IndependentLineageError::Invalid("declared artifact bytes"))?;
    if declared_total != expected_total || bytes.len() != expected_total {
        return Err(ProductionDoryV3IndependentLineageError::ArtifactLength {
            expected: expected_total,
            actual: bytes.len(),
        });
    }
    let mut signatures = Vec::with_capacity(signer_count);
    for _ in 0..signer_count {
        let signer_class = match decoder.u8("signer class")? {
            0 => SignerClass::Operator,
            1 => SignerClass::Reproducer,
            _ => {
                return Err(ProductionDoryV3IndependentLineageError::Invalid(
                    "reserved signer class",
                ));
            }
        };
        signatures.push(RecordSignature {
            signer_class,
            signer_index: decoder.u16("signer index")?,
            signature: decoder.take("BIP340 signature")?,
        });
    }
    decoder.finish()?;
    validate_statement(&statement)?;
    validate_context(&statement, transcript, report)?;

    let canonical = encode_artifact(&statement, &signatures)?;
    if canonical != bytes {
        return Err(ProductionDoryV3IndependentLineageError::Invalid(
            "noncanonical independent-lineage artifact",
        ));
    }
    let content_digest = blake3_derive(CONTENT_DOMAIN, &bytes[..CONTENT_END]);
    let signature_message = signature_message(
        version,
        u32::try_from(expected_total).expect("bounded lineage artifact fits in u32"),
        content_digest,
        u16::try_from(signer_count).expect("bounded signer count fits in u16"),
    );
    verify_signatures(&signatures, &signature_message, transcript)?;
    let artifact_identity = file_identity(bytes);
    if &artifact_identity != report.artifacts().implementation_lineage_report {
        return Err(ProductionDoryV3IndependentLineageError::Context(
            "CMFDRP implementation-lineage file identity",
        ));
    }
    Ok(CoreVerifiedIndependentLineage {
        statement,
        artifact_identity,
        content_digest,
        signature_message,
    })
}

/// Authenticate and verify one exact CMFDIL01 artifact and all eleven signed
/// post-root evidence files using retained trusted-file handles.
///
/// Every input is opened before any caller-controlled bytes are parsed. The
/// lineage artifact and evidence paths must be normalized absolute,
/// pairwise-distinct direct children of trusted private local directories, and
/// their retained filesystem identities must also be pairwise distinct. Every
/// evidence file is read to its exact signed byte count and EOF under both
/// BLAKE3 and SHA-256. The lineage artifact is reparsed and rechecked last.
///
/// Verification requires the same independently anchored, reveal-set-closed
/// type-5 transcript used by the context-verified CMFDRP report. The CMFDIL01
/// file identity must equal that report's `implementation_lineage_report`
/// identity. No completed type-6 transcript is accepted at this boundary.
pub fn validate_existing_production_dory_v3_independent_lineage(
    lineage_path: &Path,
    evidence_paths: ProductionDoryV3IndependentLineageEvidencePaths<'_>,
    transcript: &VerifiedCeremonyTranscript,
    report: &ContextVerifiedProductionDoryV3ModelReproductionReport,
) -> Result<VerifiedIndependentLineage, ProductionDoryV3IndependentLineageError> {
    let ordered_evidence_paths = evidence_paths.ordered();
    let mut all_paths = Vec::with_capacity(1 + ordered_evidence_paths.len());
    all_paths.push(lineage_path);
    all_paths.extend(ordered_evidence_paths);
    ensure_pairwise_distinct_paths(&all_paths)?;

    // Open every input before parsing any caller-controlled bytes.
    let expected_lineage_bytes = report.artifacts().implementation_lineage_report.bytes;
    let mut retained = Vec::with_capacity(all_paths.len());
    for (index, path) in all_paths.iter().enumerate() {
        retained.push(RetainedLineageInput::open(
            path,
            (index == 0).then_some(expected_lineage_bytes),
        )?);
    }
    ensure_pairwise_distinct_inputs(&retained)?;
    let mut lineage_input = retained.remove(0);
    let mut evidence_inputs = retained;

    let lineage_bytes = lineage_input
        .input
        .read_bounded(MAX_PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_BYTES)
        .map_err(map_fs)?;
    let first = verify_independent_lineage_bytes(&lineage_bytes, transcript, report)?;
    lineage_input.authenticate_content(&first.artifact_identity, "independent-lineage artifact")?;

    let expected_evidence = [
        &first.statement.combiner_source_bundle,
        &first.statement.combiner_build_provenance,
        &first.statement.combiner_binary,
        &first.statement.roots_calculator_source_bundle,
        &first.statement.roots_calculator_build_provenance,
        &first.statement.roots_calculator_binary,
        &first.statement.independent_lineage_review_report,
        &first.statement.conformance_test_report,
        &first.statement.host_environment_report,
        &first.statement.source_extraction_report,
        &first.statement.command_log,
    ];
    for ((input, expected), field) in evidence_inputs
        .iter_mut()
        .zip(expected_evidence)
        .zip(EVIDENCE_FIELD_NAMES)
    {
        input.authenticate_content(expected, field)?;
    }

    // Final full evidence rechecks, then CMFDIL last.
    for (input, field) in evidence_inputs.iter_mut().zip(EVIDENCE_FIELD_NAMES) {
        input.reauthenticate_content(field)?;
    }
    lineage_input
        .input
        .recheck(&lineage_input.parent, Some(first.artifact_identity.bytes))
        .map_err(map_fs)?;
    let final_lineage_bytes = lineage_input
        .input
        .read_bounded(MAX_PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_BYTES)
        .map_err(map_fs)?;
    lineage_input
        .input
        .recheck(&lineage_input.parent, Some(first.artifact_identity.bytes))
        .map_err(map_fs)?;
    let final_verified =
        verify_independent_lineage_bytes(&final_lineage_bytes, transcript, report)?;
    if final_lineage_bytes != lineage_bytes
        || final_verified.statement != first.statement
        || final_verified.artifact_identity != first.artifact_identity
        || final_verified.content_digest != first.content_digest
        || final_verified.signature_message != first.signature_message
    {
        return Err(ProductionDoryV3IndependentLineageError::EvidenceIdentity(
            "independent-lineage artifact",
        ));
    }
    lineage_input.expected_content = final_verified.artifact_identity.clone();

    Ok(VerifiedIndependentLineage {
        statement: final_verified.statement,
        artifact_identity: final_verified.artifact_identity,
        content_digest: final_verified.content_digest,
        signature_message: final_verified.signature_message,
        lineage_input,
        evidence_inputs,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{fs, io, path::PathBuf, thread, time::Duration};

    use dory_pcs::primitives::{DorySerialize, arithmetic::Field};
    use k256::schnorr::{Signature, SigningKey};

    use super::*;
    use crate::{
        dory_bls12_381_prototype::{
            BlsDoryFr, DeterministicBlsDorySetup, deterministic_bls_dory_setup,
        },
        dory_v3_model_ceremony_fs::prepare_test_parent,
        dory_v3_model_ceremony_transcript::{
            CEREMONY_PROTOCOL_VERSION, CommitmentSetBody, ContributionCommitmentBody,
            ContributionRevealBody, IndexedRecordDigest, PRODUCTION_BANK_BYTES,
            PRODUCTION_BANK_FORMAT_VERSION, PRODUCTION_BANK_HEADER_BYTES, PRODUCTION_BANKS,
            PRODUCTION_BASE_INPUT_BYTES, PRODUCTION_BATCH, PRODUCTION_BYTES_PER_LAYER,
            PRODUCTION_DIMENSION, PRODUCTION_LAYERS, PRODUCTION_LAYERS_PER_BANK,
            PRODUCTION_MAX_MODEL_BYTE, PRODUCTION_MODEL_VERSION, PRODUCTION_PADDED_VARIABLES,
            PRODUCTION_PAYLOAD_BYTES, ReferenceBinary, RevealSetBody, RosterMember,
            SignedCeremonyRecord, ceremony_record_content_digest,
            ceremony_record_signature_message, encode_and_verify_reveal_set_prefix,
            parse_and_verify_reveal_set_prefix,
        },
        dory_v3_model_combiner::{
            ProductionDoryV3ModelCombinedPayloadValidationReport,
            ProductionDoryV3ModelCombinerInputReport,
            ValidatedProductionDoryV3ModelCombinedPayload,
        },
        dory_v3_model_final_candidate_validation::{
            ProductionDoryV3ModelFinalCandidateValidationError,
            VerifiedProductionDoryV3ReproducerLineages,
        },
        dory_v3_model_reproduction::{
            ProductionDoryV3ModelReproductionClaims,
            author_and_verify_production_dory_v3_model_reproduction_report,
        },
        dory_v3_model_roots::PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES,
        dory_v3_model_structure::PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES,
        dory_v3_suite::{DORY_V3_SETUP_IDENTITY, Digest32, production_dory_v3_suite_digest},
    };

    const EVIDENCE_BYTES: [&[u8]; 11] = [
        b"independent combiner source bundle\n",
        b"independent combiner build provenance\n",
        b"independent combiner executable\n",
        b"independent roots source bundle\n",
        b"independent roots build provenance\n",
        b"independent roots executable\n",
        b"independent lineage review report\n",
        b"independent conformance test report\n",
        b"independent host environment report\n",
        b"independent source extraction report\n",
        b"independent command log\n",
    ];

    struct Fixture {
        transcript: VerifiedCeremonyTranscript,
        combined: ValidatedProductionDoryV3ModelCombinedPayload,
        statement: IndependentLineageStatement,
        claims: ProductionDoryV3ModelReproductionClaims,
        operators: Vec<SigningKey>,
        reproducers: Vec<SigningKey>,
    }

    impl Fixture {
        fn artifact(&self, statement: &IndependentLineageStatement) -> Vec<u8> {
            signed_artifact(statement, &self.operators, &self.reproducers)
        }

        fn report(
            &self,
            artifact: &[u8],
        ) -> ContextVerifiedProductionDoryV3ModelReproductionReport {
            let mut claims = self.claims.clone();
            claims.implementation_lineage_report = file_identity(artifact);
            author_and_verify_production_dory_v3_model_reproduction_report(
                &self.transcript,
                &self.combined,
                claims,
            )
            .unwrap()
        }

        fn independent_report_for(
            &self,
            artifact: &[u8],
            reproducer_index: u16,
        ) -> ContextVerifiedProductionDoryV3ModelReproductionReport {
            let mut claims = self.claims.clone();
            claims.reproducer_index = reproducer_index;
            claims.implementation_lineage_report = file_identity(artifact);
            author_and_verify_production_dory_v3_model_reproduction_report(
                &self.transcript,
                &self.combined,
                claims,
            )
            .unwrap()
        }

        fn reference_report_for(
            &self,
            reproducer_index: u16,
        ) -> ContextVerifiedProductionDoryV3ModelReproductionReport {
            let CeremonyRecordBody::Genesis(genesis) = &self.transcript.records()[0].body else {
                panic!("fixture starts with genesis");
            };
            let reference = &genesis.reference_binaries[0];
            let mut claims = self.claims.clone();
            claims.reproducer_index = reproducer_index;
            claims.implementation_kind = ProductionDoryV3ReproductionImplementationKind::Reference;
            claims.combiner_binary = FileIdentity {
                bytes: 1,
                blake3: reference.binary_blake3,
                sha256: reference.binary_sha256,
            };
            author_and_verify_production_dory_v3_model_reproduction_report(
                &self.transcript,
                &self.combined,
                claims,
            )
            .unwrap()
        }

        fn verify_statement(
            &self,
            statement: &IndependentLineageStatement,
        ) -> Result<CoreVerifiedIndependentLineage, ProductionDoryV3IndependentLineageError>
        {
            let artifact = self.artifact(statement);
            let report = self.report(&artifact);
            verify_independent_lineage_bytes(&artifact, &self.transcript, &report)
        }
    }

    fn file(seed: u8) -> FileIdentity {
        sized_file(u64::from(seed) + 1, seed)
    }

    fn sized_file(bytes: u64, seed: u8) -> FileIdentity {
        FileIdentity {
            bytes,
            blake3: [seed; 32],
            sha256: [seed.wrapping_add(1); 32],
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
            identity_document: file(index as u8 + 40),
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
            production_suite_digest: production_dory_v3_suite_digest().into_bytes(),
            dory_setup_identity: DORY_V3_SETUP_IDENTITY.into_bytes(),
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

    fn signed_artifact(
        statement: &IndependentLineageStatement,
        operators: &[SigningKey],
        reproducers: &[SigningKey],
    ) -> Vec<u8> {
        let signer_count = operators.len() + reproducers.len();
        let total = PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES
            + signer_count * PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_SIGNATURE_BYTES;
        let prefix = encode_statement(statement, total as u32, signer_count as u16);
        let content_digest = blake3_derive(CONTENT_DOMAIN, &prefix[..CONTENT_END]);
        let message = signature_message(
            PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_VERSION,
            total as u32,
            content_digest,
            signer_count as u16,
        );
        let signatures = all_signers(operators, reproducers)
            .into_iter()
            .map(|(signer_class, signer_index, key)| {
                let signature: Signature = key.sign_raw(&message, &[0; 32]).unwrap();
                RecordSignature {
                    signer_class,
                    signer_index,
                    signature: signature.to_bytes(),
                }
            })
            .collect::<Vec<_>>();
        encode_artifact(statement, &signatures).unwrap()
    }

    pub(crate) fn signed_artifact_for_claims(
        transcript: &VerifiedCeremonyTranscript,
        raw_payload: FileIdentity,
        claims: &ProductionDoryV3ModelReproductionClaims,
        evidence: [FileIdentity; 11],
        operators: &[SigningKey],
        reproducers: &[SigningKey],
    ) -> Vec<u8> {
        assert_eq!(
            claims.implementation_kind,
            ProductionDoryV3ReproductionImplementationKind::Independent
        );
        let bindings = transcript.require_combiner_bindings().unwrap();
        let first = transcript.records().first().unwrap();
        let reproducer_public_key = transcript.reproducers()[usize::from(claims.reproducer_index)];
        let [
            combiner_source_bundle,
            combiner_build_provenance,
            combiner_binary,
            roots_calculator_source_bundle,
            roots_calculator_build_provenance,
            roots_calculator_binary,
            independent_lineage_review_report,
            conformance_test_report,
            host_environment_report,
            source_extraction_report,
            command_log,
        ] = evidence;
        assert_eq!(combiner_binary, claims.combiner_binary);
        assert_eq!(host_environment_report, claims.host_environment_report);
        assert_eq!(source_extraction_report, claims.source_extraction_report);
        assert_eq!(command_log, claims.command_log);
        signed_artifact(
            &IndependentLineageStatement {
                ceremony_id: transcript.ceremony_id(),
                genesis_signed_record_digest: ceremony_signed_record_digest(first).unwrap(),
                commitment_set_signed_record_digest: bindings.commitment_set_signed_record_digest(),
                reveal_set_signed_record_digest: bindings.reveal_set_signed_record_digest(),
                reveal_set_prefix: FileIdentity {
                    bytes: transcript.transcript_bytes(),
                    blake3: transcript.transcript_blake3(),
                    sha256: transcript.transcript_sha256(),
                },
                reveal_set_prefix_derive_key_digest: transcript.transcript_derive_key_digest(),
                reproducer_index: claims.reproducer_index,
                reproducer_public_key,
                target_id: claims.target_id,
                raw_payload,
                roots_file: claims.roots_file.clone(),
                base_input_blake3_root: claims.base_input_blake3_root,
                layer_roots_aggregate: claims.layer_roots_aggregate,
                combiner_source_bundle,
                combiner_build_provenance,
                combiner_binary,
                roots_calculator_source_bundle,
                roots_calculator_build_provenance,
                roots_calculator_binary,
                independent_lineage_review_report,
                conformance_test_report,
                host_environment_report,
                source_extraction_report,
                command_log,
            },
            operators,
            reproducers,
        )
    }

    fn fixture() -> Fixture {
        fixture_with_key_offsets(1, 20)
    }

    fn fixture_with_key_offsets(operator_offset: u8, reproducer_offset: u8) -> Fixture {
        fixture_with_key_offsets_and_type5_variant(operator_offset, reproducer_offset, 0)
    }

    fn fixture_with_key_offsets_and_type5_variant(
        operator_offset: u8,
        reproducer_offset: u8,
        type5_variant: u8,
    ) -> Fixture {
        let operators = keys(3, operator_offset);
        let reproducers = keys(2, reproducer_offset);
        let operator_signers = operators
            .iter()
            .enumerate()
            .map(|(index, key)| (SignerClass::Operator, index as u16, key))
            .collect::<Vec<_>>();
        let genesis_record = sign_record(
            CeremonyRecordBody::Genesis(Box::new(genesis(&operators, &reproducers))),
            &all_signers(&operators, &reproducers),
        );
        let ceremony_id = ceremony_record_content_digest(&genesis_record.body).unwrap();
        let genesis_digest = ceremony_signed_record_digest(&genesis_record).unwrap();
        let mut prefix_records = vec![genesis_record];
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
                generation_finished_unix_seconds: 100 + index as u64 + u64::from(type5_variant),
                generator_binary_blake3: [80 + index as u8; 32],
                generator_binary_sha256: [90 + index as u8; 32],
                entropy_attestation: file(100 + index as u8),
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
            prefix_records.push(record);
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
        prefix_records.push(commitment_set);
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
            prefix_records.push(record);
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
        prefix_records.push(reveal_set);
        let prefix_bytes =
            encode_and_verify_reveal_set_prefix(&prefix_records, ceremony_id).unwrap();
        let transcript = parse_and_verify_reveal_set_prefix(&prefix_bytes, ceremony_id).unwrap();

        let ordered_inputs = commitment_bodies
            .iter()
            .enumerate()
            .map(
                |(index, commitment)| ProductionDoryV3ModelCombinerInputReport {
                    path: PathBuf::from(format!("operator-{index}.bin")),
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
        let raw_payload = sized_file(PRODUCTION_PAYLOAD_BYTES, 110);
        let combined = ValidatedProductionDoryV3ModelCombinedPayload::from_report_for_test(
            ProductionDoryV3ModelCombinedPayloadValidationReport {
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
                output: PathBuf::from("combined-payload.bin"),
                output_bytes: raw_payload.bytes,
                output_blake3: Digest32::new(raw_payload.blake3),
                output_sha256: Digest32::new(raw_payload.sha256),
                bytes_processed: raw_payload.bytes,
                elapsed_micros: 101,
            },
        );

        let roots_file = sized_file(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES as u64, 111);
        let base_input_blake3_root = [112; 32];
        let layer_roots_aggregate = [113; 32];
        let evidence = EVIDENCE_BYTES.map(file_identity);
        let statement = IndependentLineageStatement {
            ceremony_id,
            genesis_signed_record_digest: genesis_digest,
            commitment_set_signed_record_digest: commitment_set_digest,
            reveal_set_signed_record_digest: reveal_set_digest,
            reveal_set_prefix: FileIdentity {
                bytes: transcript.transcript_bytes(),
                blake3: transcript.transcript_blake3(),
                sha256: transcript.transcript_sha256(),
            },
            reveal_set_prefix_derive_key_digest: transcript.transcript_derive_key_digest(),
            reproducer_index: 0,
            reproducer_public_key: reproducers[0].verifying_key().to_bytes().into(),
            target_id: 1,
            raw_payload: raw_payload.clone(),
            roots_file: roots_file.clone(),
            base_input_blake3_root,
            layer_roots_aggregate,
            combiner_source_bundle: evidence[0].clone(),
            combiner_build_provenance: evidence[1].clone(),
            combiner_binary: evidence[2].clone(),
            roots_calculator_source_bundle: evidence[3].clone(),
            roots_calculator_build_provenance: evidence[4].clone(),
            roots_calculator_binary: evidence[5].clone(),
            independent_lineage_review_report: evidence[6].clone(),
            conformance_test_report: evidence[7].clone(),
            host_environment_report: evidence[8].clone(),
            source_extraction_report: evidence[9].clone(),
            command_log: evidence[10].clone(),
        };
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let claims = ProductionDoryV3ModelReproductionClaims {
            reproducer_index: 0,
            implementation_kind: ProductionDoryV3ReproductionImplementationKind::Independent,
            target_id: 1,
            combiner_binary: statement.combiner_binary.clone(),
            combiner_report: file(120),
            bootstrap_report: file(121),
            record_ceremony_report: file(122),
            host_environment_report: statement.host_environment_report.clone(),
            source_extraction_report: statement.source_extraction_report.clone(),
            command_log: statement.command_log.clone(),
            implementation_lineage_report: file(123),
            roots_file,
            structural_report: sized_file(
                PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES as u64,
                124,
            ),
            bank_file: sized_file(PRODUCTION_BANK_BYTES, 125),
            manifest_file: file(126),
            record_v2_file: file(127),
            base_input_blake3_root,
            layer_roots_aggregate,
            base_commitment: canonical_commitment(&setup, 3, 0),
            weight_bank_0_commitment: canonical_commitment(&setup, 5, 1),
            weight_bank_1_commitment: canonical_commitment(&setup, 7, 2),
            weight_bank_2_commitment: canonical_commitment(&setup, 11, 3),
            roots_elapsed_micros: 102,
            structure_elapsed_micros: 103,
            bootstrap_elapsed_micros: 104,
            record_elapsed_micros: 105,
            total_elapsed_micros: 1_000,
            peak_rss_bytes: 1_048_576,
            peak_disk_bytes: PRODUCTION_PAYLOAD_BYTES + PRODUCTION_BANK_BYTES,
        };
        Fixture {
            transcript,
            combined,
            statement,
            claims,
            operators,
            reproducers,
        }
    }

    #[test]
    fn fixed_layout_known_answers_and_context_round_trip() {
        let fixture = fixture();
        let artifact = fixture.artifact(&fixture.statement);
        let report = fixture.report(&artifact);
        let verified =
            verify_independent_lineage_bytes(&artifact, &fixture.transcript, &report).unwrap();
        assert_eq!(artifact.len(), 1_619);
        assert_eq!(&artifact[..8], b"CMFDIL01");
        assert_eq!(&artifact[8..10], &1_u16.to_le_bytes());
        assert_eq!(&artifact[10..14], &1_619_u32.to_le_bytes());
        assert_eq!(&artifact[1_282..1_284], &5_u16.to_le_bytes());
        assert_eq!(
            hex::encode(verified.content_digest),
            "754afe29bfa7d54fa21074466ced9c3f7df54cfc74c284372ee55694dd7efeda"
        );
        assert_eq!(
            hex::encode(verified.signature_message),
            "daea29d3f0e73ecf019e927679477ef37519ed3ba5ccac7a48520b6120c7270f"
        );
        assert_eq!(
            hex::encode(verified.artifact_identity.blake3),
            "1f27daf3112b4c750b3562eed234e54ca1689307dd87baa102b8bb422bc38470"
        );
        assert_eq!(
            hex::encode(verified.artifact_identity.sha256),
            "80df8ebfc83858c516b6c31ab43e22a469d566428ebac409bf57d5162496c7dd"
        );
    }

    #[test]
    fn maximum_roster_framing_is_exactly_3428_bytes() {
        let fixture = fixture();
        let signatures = vec![
            RecordSignature {
                signer_class: SignerClass::Operator,
                signer_index: 0,
                signature: [1; 64],
            };
            MAX_CEREMONY_SIGNERS
        ];
        let artifact = encode_artifact(&fixture.statement, &signatures).unwrap();
        assert_eq!(MAX_CEREMONY_SIGNERS, 32);
        assert_eq!(MAX_PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_BYTES, 3_428);
        assert_eq!(artifact.len(), 3_428);
        assert_eq!(&artifact[10..14], &3_428_u32.to_le_bytes());
        assert_eq!(&artifact[1_282..1_284], &32_u16.to_le_bytes());
    }

    #[test]
    fn context_bound_field_mutations_are_rejected_after_resigning() {
        let fixture = fixture();
        let mutations: [fn(&mut IndependentLineageStatement); 17] = [
            |value| value.ceremony_id[0] ^= 1,
            |value| value.genesis_signed_record_digest[0] ^= 1,
            |value| value.commitment_set_signed_record_digest[0] ^= 1,
            |value| value.reveal_set_signed_record_digest[0] ^= 1,
            |value| value.reveal_set_prefix.blake3[0] ^= 1,
            |value| value.reveal_set_prefix_derive_key_digest[0] ^= 1,
            |value| value.reproducer_index = 1,
            |value| value.reproducer_public_key[0] ^= 1,
            |value| value.target_id = 2,
            |value| value.raw_payload.sha256[0] ^= 1,
            |value| value.roots_file.blake3[0] ^= 1,
            |value| value.base_input_blake3_root[0] ^= 1,
            |value| value.layer_roots_aggregate[0] ^= 1,
            |value| value.combiner_binary.sha256[0] ^= 1,
            |value| value.host_environment_report.blake3[0] ^= 1,
            |value| value.source_extraction_report.sha256[0] ^= 1,
            |value| value.command_log.blake3[0] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = fixture.statement.clone();
            mutate(&mut changed);
            assert!(fixture.verify_statement(&changed).is_err());
        }
    }

    #[test]
    fn zero_identities_and_reference_reuse_are_rejected() {
        let fixture = fixture();
        let zero_identity_mutations: [fn(&mut IndependentLineageStatement); 11] = [
            |value| value.combiner_source_bundle.bytes = 0,
            |value| value.combiner_build_provenance.bytes = 0,
            |value| value.combiner_binary.bytes = 0,
            |value| value.roots_calculator_source_bundle.bytes = 0,
            |value| value.roots_calculator_build_provenance.bytes = 0,
            |value| value.roots_calculator_binary.bytes = 0,
            |value| value.independent_lineage_review_report.bytes = 0,
            |value| value.conformance_test_report.bytes = 0,
            |value| value.host_environment_report.bytes = 0,
            |value| value.source_extraction_report.bytes = 0,
            |value| value.command_log.bytes = 0,
        ];
        for mutate in zero_identity_mutations {
            let mut changed = fixture.statement.clone();
            mutate(&mut changed);
            assert!(fixture.verify_statement(&changed).is_err());
        }

        let CeremonyRecordBody::Genesis(genesis) = &fixture.transcript.records()[0].body else {
            panic!("fixture starts with genesis");
        };
        let mut reused_source = fixture.statement.clone();
        reused_source.roots_calculator_source_bundle = genesis.source_bundle.clone();
        assert!(fixture.verify_statement(&reused_source).is_err());

        let mut reused_reference = fixture.statement.clone();
        reused_reference.roots_calculator_binary.blake3 =
            genesis.reference_binaries[0].binary_blake3;
        assert!(fixture.verify_statement(&reused_reference).is_err());

        let mut reused_analyzer = fixture.statement.clone();
        reused_analyzer.roots_calculator_binary.sha256 = genesis.structural_analyzer_sha256;
        assert!(fixture.verify_statement(&reused_analyzer).is_err());
    }

    #[test]
    fn signature_and_framing_mutations_are_rejected() {
        let fixture = fixture();
        let artifact = fixture.artifact(&fixture.statement);

        let mut bad_signature = artifact.clone();
        bad_signature[PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES + 3] ^= 1;
        let report = fixture.report(&bad_signature);
        assert!(
            verify_independent_lineage_bytes(&bad_signature, &fixture.transcript, &report).is_err()
        );

        let mut wrong_class = artifact.clone();
        wrong_class[PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES] = 1;
        let report = fixture.report(&wrong_class);
        assert!(
            verify_independent_lineage_bytes(&wrong_class, &fixture.transcript, &report).is_err()
        );

        let mut reserved_class = artifact.clone();
        reserved_class[PRODUCTION_DORY_V3_INDEPENDENT_LINEAGE_PREFIX_BYTES] = 2;
        let report = fixture.report(&reserved_class);
        assert!(matches!(
            verify_independent_lineage_bytes(&reserved_class, &fixture.transcript, &report,),
            Err(ProductionDoryV3IndependentLineageError::Invalid(
                "reserved signer class"
            ))
        ));

        let truncated = &artifact[..artifact.len() - 1];
        let report = fixture.report(truncated);
        assert!(verify_independent_lineage_bytes(truncated, &fixture.transcript, &report).is_err());

        let mut trailing = artifact.clone();
        trailing.push(0);
        let report = fixture.report(&trailing);
        assert!(verify_independent_lineage_bytes(&trailing, &fixture.transcript, &report).is_err());

        let mut bad_magic = artifact.clone();
        bad_magic[0] ^= 1;
        let report = fixture.report(&bad_magic);
        assert!(matches!(
            verify_independent_lineage_bytes(&bad_magic, &fixture.transcript, &report),
            Err(ProductionDoryV3IndependentLineageError::InvalidMagic)
        ));
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            for _ in 0..128 {
                let mut id = [0_u8; 16];
                getrandom::fill(&mut id).expect("obtain random lineage test-root identity");
                let path = std::env::temp_dir().join(format!("cmfd-lineage-{}", hex::encode(id)));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        let directory = Self(path);
                        prepare_test_parent(&directory.0).unwrap();
                        return directory;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create isolated lineage test root {path:?}: {error}"),
                }
            }
            panic!("could not allocate a unique lineage test root after 128 random candidates")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            for _ in 0..100 {
                match fs::remove_dir_all(&self.0) {
                    Ok(()) => return,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return,
                    Err(_) => thread::sleep(Duration::from_millis(10)),
                }
            }
            eprintln!("could not remove isolated lineage test root {:?}", self.0);
        }
    }

    fn evidence_path_view(
        paths: &[PathBuf],
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

    fn materialize_path_fixture(
        fixture: &Fixture,
    ) -> (
        TestDirectory,
        PathBuf,
        Vec<PathBuf>,
        Vec<u8>,
        ContextVerifiedProductionDoryV3ModelReproductionReport,
    ) {
        let artifact = fixture.artifact(&fixture.statement);
        let report = fixture.report(&artifact);
        let directory = TestDirectory::new();
        let lineage_path = directory.0.join("lineage.cmfdil");
        fs::write(&lineage_path, &artifact).unwrap();
        let evidence_paths = (0..EVIDENCE_BYTES.len())
            .map(|index| directory.0.join(format!("evidence-{index}.bin")))
            .collect::<Vec<_>>();
        for (path, bytes) in evidence_paths.iter().zip(EVIDENCE_BYTES) {
            fs::write(path, bytes).unwrap();
        }
        (directory, lineage_path, evidence_paths, artifact, report)
    }

    struct MaterializedVerifiedLineage {
        lineage_path: PathBuf,
        evidence_paths: Vec<PathBuf>,
        report: ContextVerifiedProductionDoryV3ModelReproductionReport,
        lineage: VerifiedIndependentLineage,
        // Retained lineage handles must close before the directory guard removes the tree.
        _directory: TestDirectory,
    }

    fn materialize_verified_lineage(
        fixture: &Fixture,
        reproducer_index: u16,
    ) -> MaterializedVerifiedLineage {
        let mut statement = fixture.statement.clone();
        statement.reproducer_index = reproducer_index;
        statement.reproducer_public_key =
            fixture.transcript.reproducers()[usize::from(reproducer_index)];
        let artifact = fixture.artifact(&statement);
        let report = fixture.independent_report_for(&artifact, reproducer_index);
        let directory = TestDirectory::new();
        let lineage_path = directory
            .0
            .join(format!("lineage-{reproducer_index}.cmfdil"));
        fs::write(&lineage_path, artifact).unwrap();
        let evidence_paths = (0..EVIDENCE_BYTES.len())
            .map(|index| {
                directory
                    .0
                    .join(format!("evidence-{reproducer_index}-{index}.bin"))
            })
            .collect::<Vec<_>>();
        for (path, bytes) in evidence_paths.iter().zip(EVIDENCE_BYTES) {
            fs::write(path, bytes).unwrap();
        }
        let lineage = validate_existing_production_dory_v3_independent_lineage(
            &lineage_path,
            evidence_path_view(&evidence_paths),
            &fixture.transcript,
            &report,
        )
        .unwrap();
        MaterializedVerifiedLineage {
            lineage_path,
            evidence_paths,
            report,
            lineage,
            _directory: directory,
        }
    }

    #[test]
    fn path_validator_authenticates_and_retains_every_named_file() {
        let fixture = fixture();
        let (_directory, lineage_path, evidence_paths, artifact, report) =
            materialize_path_fixture(&fixture);
        let mut verified = validate_existing_production_dory_v3_independent_lineage(
            &lineage_path,
            evidence_path_view(&evidence_paths),
            &fixture.transcript,
            &report,
        )
        .unwrap();
        assert_eq!(verified.artifact_identity(), &file_identity(&artifact));
        assert_eq!(
            verified.artifacts().command_log,
            &file_identity(EVIDENCE_BYTES[10])
        );
        verified.recheck_retained_files().unwrap();
    }

    #[test]
    fn exact_ordered_aggregate_constructor_consumes_real_lineage_capability() {
        let fixture = fixture();
        let materialized = materialize_verified_lineage(&fixture, 0);
        let reference = fixture.reference_report_for(1);
        let reports = [materialized.report, reference];
        let mut aggregate = VerifiedProductionDoryV3ReproducerLineages::verify_exact_ordered(
            &fixture.transcript,
            &reports,
            vec![materialized.lineage],
        )
        .unwrap();
        aggregate
            .validate_for_test(fixture.transcript.ceremony_id(), &reports)
            .unwrap();
        aggregate.recheck_for_test().unwrap();

        let artifact = fs::read(&materialized.lineage_path).unwrap();
        let mut changed_claims = fixture.claims.clone();
        changed_claims.implementation_lineage_report = file_identity(&artifact);
        changed_claims.total_elapsed_micros += 1;
        let changed = author_and_verify_production_dory_v3_model_reproduction_report(
            &fixture.transcript,
            &fixture.combined,
            changed_claims,
        )
        .unwrap();
        let changed_reports = [changed, fixture.reference_report_for(1)];
        assert!(matches!(
            aggregate.validate_for_test(fixture.transcript.ceremony_id(), &changed_reports),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                    "CMFDRP content identity"
                )
            )
        ));
    }

    #[test]
    fn exact_ordered_aggregate_constructor_rejects_incomplete_or_wrong_context() {
        let fixture = fixture();

        let missing = materialize_verified_lineage(&fixture, 0);
        let missing_reports = [missing.report, fixture.reference_report_for(1)];
        assert!(matches!(
            VerifiedProductionDoryV3ReproducerLineages::verify_exact_ordered(
                &fixture.transcript,
                &missing_reports,
                vec![],
            ),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                    "Independent capability count"
                )
            )
        ));

        let short = materialize_verified_lineage(&fixture, 0);
        assert!(matches!(
            VerifiedProductionDoryV3ReproducerLineages::verify_exact_ordered(
                &fixture.transcript,
                std::slice::from_ref(&short.report),
                vec![short.lineage],
            ),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::ReproducerCount {
                    expected: 2,
                    actual: 1
                }
            )
        ));

        let swapped = materialize_verified_lineage(&fixture, 0);
        let swapped_reports = [fixture.reference_report_for(1), swapped.report];
        assert!(matches!(
            VerifiedProductionDoryV3ReproducerLineages::verify_exact_ordered(
                &fixture.transcript,
                &swapped_reports,
                vec![swapped.lineage],
            ),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::ReproducerOrder {
                    position: 0,
                    actual: 1
                }
            )
        ));

        let reference_reports = [
            fixture.reference_report_for(0),
            fixture.reference_report_for(1),
        ];
        assert!(matches!(
            VerifiedProductionDoryV3ReproducerLineages::verify_exact_ordered(
                &fixture.transcript,
                &reference_reports,
                vec![],
            ),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                    "no Independent report"
                )
            )
        ));

        let wrong_transcript_lineage = materialize_verified_lineage(&fixture, 0);
        let wrong_transcript_reports = [
            wrong_transcript_lineage.report,
            fixture.reference_report_for(1),
        ];
        let other = fixture_with_key_offsets(2, 30);
        assert!(matches!(
            VerifiedProductionDoryV3ReproducerLineages::verify_exact_ordered(
                &other.transcript,
                &wrong_transcript_reports,
                vec![wrong_transcript_lineage.lineage],
            ),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                    "CMFDRP transcript or roster binding"
                )
            )
        ));
    }

    #[test]
    fn exact_ordered_aggregate_constructor_rejects_swapped_real_lineages() {
        let fixture = fixture();
        let first = materialize_verified_lineage(&fixture, 0);
        let second = materialize_verified_lineage(&fixture, 1);
        let reports = [first.report, second.report];
        assert!(matches!(
            VerifiedProductionDoryV3ReproducerLineages::verify_exact_ordered(
                &fixture.transcript,
                &reports,
                vec![second.lineage, first.lineage],
            ),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                    "reproducer, key, or target"
                )
            )
        ));
    }

    #[test]
    fn exact_ordered_aggregate_rejects_old_lineage_from_same_ceremony_type5_fork() {
        let old = fixture_with_key_offsets_and_type5_variant(1, 20, 0);
        let old_lineage = materialize_verified_lineage(&old, 0);
        let current = fixture_with_key_offsets_and_type5_variant(1, 20, 1);
        assert_eq!(
            old.transcript.ceremony_id(),
            current.transcript.ceremony_id()
        );
        assert_ne!(
            old.transcript.transcript_blake3(),
            current.transcript.transcript_blake3()
        );

        let mut current_claims = current.claims.clone();
        current_claims.implementation_lineage_report =
            old_lineage.lineage.artifact_identity().clone();
        let current_report = author_and_verify_production_dory_v3_model_reproduction_report(
            &current.transcript,
            &current.combined,
            current_claims,
        )
        .unwrap();
        let current_reports = [current_report, current.reference_report_for(1)];
        assert!(matches!(
            VerifiedProductionDoryV3ReproducerLineages::verify_exact_ordered(
                &current.transcript,
                &current_reports,
                vec![old_lineage.lineage],
            ),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineage(
                    "type-5 prefix or closure"
                )
            )
        ));
    }

    #[cfg(unix)]
    #[test]
    fn aggregate_recheck_catches_later_evidence_mutation() {
        let fixture = fixture();
        let materialized = materialize_verified_lineage(&fixture, 0);
        let evidence_path = materialized.evidence_paths[0].clone();
        let reports = [materialized.report, fixture.reference_report_for(1)];
        let mut aggregate = VerifiedProductionDoryV3ReproducerLineages::verify_exact_ordered(
            &fixture.transcript,
            &reports,
            vec![materialized.lineage],
        )
        .unwrap();
        fs::write(&evidence_path, vec![b'X'; EVIDENCE_BYTES[0].len()]).unwrap();
        assert!(matches!(
            aggregate.recheck_for_test(),
            Err(
                ProductionDoryV3ModelFinalCandidateValidationError::IndependentLineageEvidence {
                    reproducer_index: 0,
                    source: ProductionDoryV3IndependentLineageError::EvidenceIdentity(
                        "combiner source bundle"
                    )
                }
            )
        ));
    }

    #[cfg(windows)]
    #[test]
    fn aggregate_retained_handles_deny_later_evidence_replacement() {
        let fixture = fixture();
        let materialized = materialize_verified_lineage(&fixture, 0);
        let evidence_path = materialized.evidence_paths[0].clone();
        let reports = [materialized.report, fixture.reference_report_for(1)];
        let mut aggregate = VerifiedProductionDoryV3ReproducerLineages::verify_exact_ordered(
            &fixture.transcript,
            &reports,
            vec![materialized.lineage],
        )
        .unwrap();
        assert!(fs::write(&evidence_path, EVIDENCE_BYTES[0]).is_err());
        assert!(fs::rename(&evidence_path, evidence_path.with_extension("old")).is_err());
        aggregate.recheck_for_test().unwrap();
    }

    #[test]
    fn path_validator_rejects_mutated_evidence_and_duplicate_paths() {
        let fixture = fixture();
        let (_directory, lineage_path, evidence_paths, _artifact, report) =
            materialize_path_fixture(&fixture);
        let corrupt = vec![b'X'; EVIDENCE_BYTES[4].len()];
        fs::write(&evidence_paths[4], corrupt).unwrap();
        assert!(matches!(
            validate_existing_production_dory_v3_independent_lineage(
                &lineage_path,
                evidence_path_view(&evidence_paths),
                &fixture.transcript,
                &report,
            ),
            Err(ProductionDoryV3IndependentLineageError::EvidenceIdentity(
                "roots-calculator build provenance"
            ))
        ));

        fs::write(&evidence_paths[4], EVIDENCE_BYTES[4]).unwrap();
        let duplicate = ProductionDoryV3IndependentLineageEvidencePaths {
            command_log: &evidence_paths[9],
            ..evidence_path_view(&evidence_paths)
        };
        assert!(matches!(
            validate_existing_production_dory_v3_independent_lineage(
                &lineage_path,
                duplicate,
                &fixture.transcript,
                &report,
            ),
            Err(ProductionDoryV3IndependentLineageError::PathsNotDistinct)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn retained_windows_handles_deny_live_mutation_and_replacement() {
        let fixture = fixture();
        let (directory, lineage_path, evidence_paths, _artifact, report) =
            materialize_path_fixture(&fixture);
        let mut verified = validate_existing_production_dory_v3_independent_lineage(
            &lineage_path,
            evidence_path_view(&evidence_paths),
            &fixture.transcript,
            &report,
        )
        .unwrap();
        assert!(fs::write(&evidence_paths[0], EVIDENCE_BYTES[0]).is_err());
        assert!(fs::rename(&lineage_path, directory.0.join("replacement.cmfdil")).is_err());
        verified.recheck_retained_files().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn retained_unix_rechecks_detect_live_mutation_and_named_replacement() {
        let fixture = fixture();
        let (directory, lineage_path, evidence_paths, artifact, report) =
            materialize_path_fixture(&fixture);
        let mut verified = validate_existing_production_dory_v3_independent_lineage(
            &lineage_path,
            evidence_path_view(&evidence_paths),
            &fixture.transcript,
            &report,
        )
        .unwrap();
        fs::write(&evidence_paths[0], vec![b'X'; EVIDENCE_BYTES[0].len()]).unwrap();
        assert!(matches!(
            verified.recheck_retained_files(),
            Err(ProductionDoryV3IndependentLineageError::EvidenceIdentity(
                "combiner source bundle"
            ))
        ));
        drop(verified);

        fs::write(&evidence_paths[0], EVIDENCE_BYTES[0]).unwrap();
        let mut verified = validate_existing_production_dory_v3_independent_lineage(
            &lineage_path,
            evidence_path_view(&evidence_paths),
            &fixture.transcript,
            &report,
        )
        .unwrap();
        let replaced = directory.0.join("old-lineage.cmfdil");
        fs::rename(&lineage_path, &replaced).unwrap();
        fs::write(&lineage_path, artifact).unwrap();
        assert!(matches!(
            verified.recheck_retained_files(),
            Err(ProductionDoryV3IndependentLineageError::TrustedFilesystem(
                _
            ))
        ));
    }
}
