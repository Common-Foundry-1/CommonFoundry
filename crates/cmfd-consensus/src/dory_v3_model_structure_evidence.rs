//! Canonical error evidence for the production Dory V3 structural analyzer.
//!
//! `CMFDSE01` is an external ceremony artifact. It does not change the signed
//! type-7 transcript codec: the existing type-7 `evidence_file` identity binds
//! the exact bytes written here. Generation requires the opaque result of the
//! independently ceremony-ID-anchored exact type-5 prefix parser. Verification
//! requires a signed aborted transcript whose penultimate record is that type-5
//! closure, plus independent ceremony-ID and signed-record-digest anchors.

use std::{
    fs::File,
    io::{Read as _, Seek as _, SeekFrom},
    path::{Path, PathBuf},
};

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    dory_v3_model_ceremony_fs::{
        AuthenticatedInput, CeremonyFsError, ParentSyncOutcome, PendingOutput,
        TrustedCeremonyParent,
    },
    dory_v3_model_ceremony_transcript::{
        AbortBody, CeremonyRecordBody, CeremonyTranscriptError, CeremonyTranscriptStatus,
        FileIdentity as TranscriptFileIdentity, GenesisBody, MAX_CEREMONY_RECORD_BODY_BYTES,
        MAX_CEREMONY_SIGNERS, RecordSignature, SignedCeremonyRecord, VerifiedCeremonyTranscript,
        ceremony_record_content_digest, ceremony_record_signature_message,
        ceremony_signed_record_digest, decode_ceremony_record,
        encode_and_verify_ceremony_transcript, encode_ceremony_record,
        parse_and_verify_ceremony_transcript, parse_and_verify_reveal_set_prefix,
    },
    dory_v3_model_roots::{
        PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES, ProductionDoryV3ModelRoots,
        ProductionDoryV3ModelRootsClaims,
    },
    dory_v3_model_structure::{
        PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES, ProductionDoryV3ModelStructuralReportRun,
        ProductionDoryV3ModelStructureError, StructuralAnalyzerPayloadPrefix,
        StructuralAnalyzerProgress,
        run_production_dory_v3_model_structural_report_observed_from_claims,
    },
};

pub const PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_MAGIC: [u8; 8] = *b"CMFDSE01";
pub const PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_VERSION: u16 = 1;
pub const PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_FIXED_BYTES: usize = 384;
pub const PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_MAX_DETAIL_BYTES: usize = 64;
pub const PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_MAX_BYTES: usize =
    PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_FIXED_BYTES
        + PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_MAX_DETAIL_BYTES;

const STRUCTURAL_ANALYZER_ABORT_PHASE: u16 = 5;
const EXPECTED_PRODUCTION_PAYLOAD_BYTES: u64 =
    crate::dory_v3_model_roots::PRODUCTION_DORY_V3_PAYLOAD_BYTES;

const _: [(); PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_FIXED_BYTES] = [(); 8
    + 2
    + 32
    + 32
    + 2
    + 32
    + 32
    + 8
    + 32
    + 32
    + 8
    + 8
    + 8
    + 32
    + 32
    + 8
    + 32
    + 32
    + 2
    + 2
    + 2
    + 2
    + 2
    + 2];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ProductionDoryV3StructuralEvidenceOperation {
    GenerateReport = 1,
    ValidateReport = 2,
}

impl ProductionDoryV3StructuralEvidenceOperation {
    fn decode(value: u16) -> Result<Self, ProductionDoryV3StructuralEvidenceError> {
        match value {
            1 => Ok(Self::GenerateReport),
            2 => Ok(Self::ValidateReport),
            _ => Err(ProductionDoryV3StructuralEvidenceError::InvalidOperation(
                value,
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ProductionDoryV3StructuralEvidenceStage {
    InputAuthentication = 1,
    FirstAnalysis = 2,
    SecondAnalysis = 3,
    ReportEncoding = 4,
    ReportPersistence = 5,
    FinalRecheck = 6,
}

impl ProductionDoryV3StructuralEvidenceStage {
    fn decode(value: u16) -> Result<Self, ProductionDoryV3StructuralEvidenceError> {
        match value {
            1 => Ok(Self::InputAuthentication),
            2 => Ok(Self::FirstAnalysis),
            3 => Ok(Self::SecondAnalysis),
            4 => Ok(Self::ReportEncoding),
            5 => Ok(Self::ReportPersistence),
            6 => Ok(Self::FinalRecheck),
            _ => Err(ProductionDoryV3StructuralEvidenceError::InvalidStage(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ProductionDoryV3StructuralEvidenceFailureClass {
    FileLength = 1,
    FileDigest = 2,
    ForbiddenByte = 3,
    ToolOrSpecification = 4,
    StructuralComputationOrEncoding = 5,
    FilesystemIdentity = 6,
    IoOrResource = 7,
    OtherFailClosed = 8,
}

impl ProductionDoryV3StructuralEvidenceFailureClass {
    fn decode(value: u16) -> Result<Self, ProductionDoryV3StructuralEvidenceError> {
        match value {
            1 => Ok(Self::FileLength),
            2 => Ok(Self::FileDigest),
            3 => Ok(Self::ForbiddenByte),
            4 => Ok(Self::ToolOrSpecification),
            5 => Ok(Self::StructuralComputationOrEncoding),
            6 => Ok(Self::FilesystemIdentity),
            7 => Ok(Self::IoOrResource),
            8 => Ok(Self::OtherFailClosed),
            _ => Err(ProductionDoryV3StructuralEvidenceError::InvalidFailureClass(value)),
        }
    }

    const fn abort_reason_code(self) -> u16 {
        match self {
            Self::FileLength => 4,
            Self::FileDigest => 5,
            Self::ForbiddenByte => 6,
            Self::ToolOrSpecification => 7,
            Self::StructuralComputationOrEncoding => 8,
            Self::FilesystemIdentity => 10,
            Self::IoOrResource => 11,
            Self::OtherFailClosed => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ProductionDoryV3StructuralEvidenceFailureCode {
    PayloadLengthMismatch = 1,
    EarlyEof = 2,
    TrailingBytes = 3,
    RootOrDigestMismatch = 4,
    PayloadByteAbove250 = 5,
    GeometryOrToolMismatch = 6,
    CounterOverflow = 7,
    FatalStructuralComputation = 8,
    StructuralReportEncoding = 9,
    StructuralReportReproductionMismatch = 10,
    FilesystemIdentityOrReplacement = 11,
    PermissionDrift = 12,
    IoFailure = 13,
    ResourceFailure = 14,
    OtherFailClosed = 15,
}

impl ProductionDoryV3StructuralEvidenceFailureCode {
    fn decode(value: u16) -> Result<Self, ProductionDoryV3StructuralEvidenceError> {
        match value {
            1 => Ok(Self::PayloadLengthMismatch),
            2 => Ok(Self::EarlyEof),
            3 => Ok(Self::TrailingBytes),
            4 => Ok(Self::RootOrDigestMismatch),
            5 => Ok(Self::PayloadByteAbove250),
            6 => Ok(Self::GeometryOrToolMismatch),
            7 => Ok(Self::CounterOverflow),
            8 => Ok(Self::FatalStructuralComputation),
            9 => Ok(Self::StructuralReportEncoding),
            10 => Ok(Self::StructuralReportReproductionMismatch),
            11 => Ok(Self::FilesystemIdentityOrReplacement),
            12 => Ok(Self::PermissionDrift),
            13 => Ok(Self::IoFailure),
            14 => Ok(Self::ResourceFailure),
            15 => Ok(Self::OtherFailClosed),
            _ => Err(ProductionDoryV3StructuralEvidenceError::InvalidFailureCode(
                value,
            )),
        }
    }

    pub const fn failure_class(self) -> ProductionDoryV3StructuralEvidenceFailureClass {
        match self {
            Self::PayloadLengthMismatch | Self::EarlyEof | Self::TrailingBytes => {
                ProductionDoryV3StructuralEvidenceFailureClass::FileLength
            }
            Self::RootOrDigestMismatch => {
                ProductionDoryV3StructuralEvidenceFailureClass::FileDigest
            }
            Self::PayloadByteAbove250 => {
                ProductionDoryV3StructuralEvidenceFailureClass::ForbiddenByte
            }
            Self::GeometryOrToolMismatch => {
                ProductionDoryV3StructuralEvidenceFailureClass::ToolOrSpecification
            }
            Self::CounterOverflow
            | Self::FatalStructuralComputation
            | Self::StructuralReportEncoding
            | Self::StructuralReportReproductionMismatch => {
                ProductionDoryV3StructuralEvidenceFailureClass::StructuralComputationOrEncoding
            }
            Self::FilesystemIdentityOrReplacement | Self::PermissionDrift => {
                ProductionDoryV3StructuralEvidenceFailureClass::FilesystemIdentity
            }
            Self::IoFailure | Self::ResourceFailure => {
                ProductionDoryV3StructuralEvidenceFailureClass::IoOrResource
            }
            Self::OtherFailClosed => {
                ProductionDoryV3StructuralEvidenceFailureClass::OtherFailClosed
            }
        }
    }

    pub const fn abort_reason_code(self) -> u16 {
        self.failure_class().abort_reason_code()
    }
}

/// Syntax-validated claims decoded from one exact `CMFDSE01` artifact.
///
/// This is deliberately not authority. Only the authenticated file generator
/// and the signed-abort verifier below mint the authenticated evidence type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3StructuralErrorEvidenceClaims {
    ceremony_id: [u8; 32],
    last_valid_signed_record_digest: [u8; 32],
    analyzer_target_id: u16,
    analyzer_blake3: [u8; 32],
    analyzer_sha256: [u8; 32],
    roots_file: TranscriptFileIdentity,
    expected_payload_bytes: u64,
    opened_payload_bytes: u64,
    payload_prefix_bytes: u64,
    payload_prefix_blake3: [u8; 32],
    payload_prefix_sha256: [u8; 32],
    subject_file: Option<TranscriptFileIdentity>,
    operation: ProductionDoryV3StructuralEvidenceOperation,
    stage: ProductionDoryV3StructuralEvidenceStage,
    failure_class: ProductionDoryV3StructuralEvidenceFailureClass,
    failure_code: ProductionDoryV3StructuralEvidenceFailureCode,
    detail: Vec<u8>,
}

impl ProductionDoryV3StructuralErrorEvidenceClaims {
    pub const fn ceremony_id(&self) -> [u8; 32] {
        self.ceremony_id
    }

    pub const fn last_valid_signed_record_digest(&self) -> [u8; 32] {
        self.last_valid_signed_record_digest
    }

    pub const fn analyzer_target_id(&self) -> u16 {
        self.analyzer_target_id
    }

    pub const fn analyzer_blake3(&self) -> [u8; 32] {
        self.analyzer_blake3
    }

    pub const fn analyzer_sha256(&self) -> [u8; 32] {
        self.analyzer_sha256
    }

    pub const fn roots_file(&self) -> &TranscriptFileIdentity {
        &self.roots_file
    }

    pub const fn expected_payload_bytes(&self) -> u64 {
        self.expected_payload_bytes
    }

    pub const fn opened_payload_bytes(&self) -> u64 {
        self.opened_payload_bytes
    }

    pub const fn payload_prefix_bytes(&self) -> u64 {
        self.payload_prefix_bytes
    }

    pub const fn payload_prefix_blake3(&self) -> [u8; 32] {
        self.payload_prefix_blake3
    }

    pub const fn payload_prefix_sha256(&self) -> [u8; 32] {
        self.payload_prefix_sha256
    }

    pub const fn subject_file(&self) -> Option<&TranscriptFileIdentity> {
        self.subject_file.as_ref()
    }

    pub const fn operation(&self) -> ProductionDoryV3StructuralEvidenceOperation {
        self.operation
    }

    pub const fn stage(&self) -> ProductionDoryV3StructuralEvidenceStage {
        self.stage
    }

    pub const fn failure_class(&self) -> ProductionDoryV3StructuralEvidenceFailureClass {
        self.failure_class
    }

    pub const fn failure_code(&self) -> ProductionDoryV3StructuralEvidenceFailureCode {
        self.failure_code
    }

    pub const fn abort_reason_code(&self) -> u16 {
        self.failure_class.abort_reason_code()
    }

    pub fn detail(&self) -> &str {
        // Parsing and construction both require printable ASCII.
        std::str::from_utf8(&self.detail).expect("validated printable ASCII is UTF-8")
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_FIXED_BYTES + self.detail.len(),
        );
        bytes.extend_from_slice(&PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_MAGIC);
        bytes
            .extend_from_slice(&PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.ceremony_id);
        bytes.extend_from_slice(&self.last_valid_signed_record_digest);
        bytes.extend_from_slice(&self.analyzer_target_id.to_le_bytes());
        bytes.extend_from_slice(&self.analyzer_blake3);
        bytes.extend_from_slice(&self.analyzer_sha256);
        encode_file_identity(&mut bytes, &self.roots_file);
        bytes.extend_from_slice(&self.expected_payload_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.opened_payload_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.payload_prefix_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.payload_prefix_blake3);
        bytes.extend_from_slice(&self.payload_prefix_sha256);
        encode_optional_file_identity(&mut bytes, self.subject_file.as_ref());
        bytes.extend_from_slice(&(self.operation as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.stage as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.failure_class as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.failure_code as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.detail.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        debug_assert_eq!(
            bytes.len(),
            PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_FIXED_BYTES
        );
        bytes.extend_from_slice(&self.detail);
        bytes
    }

    pub fn parse_and_validate(
        bytes: &[u8],
    ) -> Result<Self, ProductionDoryV3StructuralEvidenceError> {
        if !(PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_FIXED_BYTES
            ..=PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_MAX_BYTES)
            .contains(&bytes.len())
        {
            return Err(ProductionDoryV3StructuralEvidenceError::EncodedLength {
                actual: bytes.len(),
            });
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take::<8>()? != PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_MAGIC {
            return Err(ProductionDoryV3StructuralEvidenceError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_VERSION {
            return Err(ProductionDoryV3StructuralEvidenceError::UnsupportedVersion(
                version,
            ));
        }
        let ceremony_id = decoder.take::<32>()?;
        let last_valid_signed_record_digest = decoder.take::<32>()?;
        if ceremony_id == [0; 32] || last_valid_signed_record_digest == [0; 32] {
            return Err(ProductionDoryV3StructuralEvidenceError::ZeroTranscriptAnchor);
        }
        let analyzer_target_id = decoder.u16()?;
        if !(1..=2).contains(&analyzer_target_id) {
            return Err(
                ProductionDoryV3StructuralEvidenceError::InvalidAnalyzerTarget(analyzer_target_id),
            );
        }
        let analyzer_blake3 = decoder.take::<32>()?;
        let analyzer_sha256 = decoder.take::<32>()?;
        let roots_file = decode_file_identity(&mut decoder)?;
        if roots_file.bytes != PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES as u64 {
            return Err(ProductionDoryV3StructuralEvidenceError::InvalidRootsLength(
                roots_file.bytes,
            ));
        }
        let expected_payload_bytes = decoder.u64()?;
        if expected_payload_bytes != EXPECTED_PRODUCTION_PAYLOAD_BYTES {
            return Err(
                ProductionDoryV3StructuralEvidenceError::InvalidExpectedPayloadLength(
                    expected_payload_bytes,
                ),
            );
        }
        let opened_payload_bytes = decoder.u64()?;
        let payload_prefix_bytes = decoder.u64()?;
        let payload_prefix_blake3 = decoder.take::<32>()?;
        let payload_prefix_sha256 = decoder.take::<32>()?;
        let subject_file = decode_optional_file_identity(&mut decoder)?;
        let operation = ProductionDoryV3StructuralEvidenceOperation::decode(decoder.u16()?)?;
        let stage = ProductionDoryV3StructuralEvidenceStage::decode(decoder.u16()?)?;
        let failure_class = ProductionDoryV3StructuralEvidenceFailureClass::decode(decoder.u16()?)?;
        let failure_code = ProductionDoryV3StructuralEvidenceFailureCode::decode(decoder.u16()?)?;
        let detail_bytes = usize::from(decoder.u16()?);
        if decoder.u16()? != 0 {
            return Err(ProductionDoryV3StructuralEvidenceError::ReservedField);
        }
        if decoder.offset != PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_FIXED_BYTES
            || detail_bytes > PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_MAX_DETAIL_BYTES
            || bytes.len()
                != PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_FIXED_BYTES + detail_bytes
        {
            return Err(ProductionDoryV3StructuralEvidenceError::InvalidDetailLength);
        }
        let detail = decoder.remaining().to_vec();
        if detail.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
            return Err(ProductionDoryV3StructuralEvidenceError::NonPrintableDetail);
        }
        if failure_code.failure_class() != failure_class {
            return Err(ProductionDoryV3StructuralEvidenceError::FailureClassMismatch);
        }
        validate_progress(
            opened_payload_bytes,
            payload_prefix_bytes,
            payload_prefix_blake3,
            payload_prefix_sha256,
            stage,
            failure_code,
        )?;
        validate_stage_code(stage, failure_code)?;
        match (operation, subject_file.is_some()) {
            (ProductionDoryV3StructuralEvidenceOperation::GenerateReport, true) => {
                return Err(ProductionDoryV3StructuralEvidenceError::UnexpectedSubjectFile);
            }
            (ProductionDoryV3StructuralEvidenceOperation::ValidateReport, false) => {
                return Err(ProductionDoryV3StructuralEvidenceError::MissingSubjectFile);
            }
            _ => {}
        }
        Ok(Self {
            ceremony_id,
            last_valid_signed_record_digest,
            analyzer_target_id,
            analyzer_blake3,
            analyzer_sha256,
            roots_file,
            expected_payload_bytes,
            opened_payload_bytes,
            payload_prefix_bytes,
            payload_prefix_blake3,
            payload_prefix_sha256,
            subject_file,
            operation,
            stage,
            failure_class,
            failure_code,
            detail,
        })
    }
}

/// Evidence authenticated against both an immutable external file identity and
/// the signed, independently anchored ceremony transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedProductionDoryV3StructuralErrorEvidence {
    claims: ProductionDoryV3StructuralErrorEvidenceClaims,
    file_identity: TranscriptFileIdentity,
}

impl AuthenticatedProductionDoryV3StructuralErrorEvidence {
    pub const fn claims(&self) -> &ProductionDoryV3StructuralErrorEvidenceClaims {
        &self.claims
    }

    pub const fn file_identity(&self) -> &TranscriptFileIdentity {
        &self.file_identity
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionDoryV3StructuralErrorEvidenceDurability {
    FileAndParentDirectorySynced,
    FileSyncedParentDirectorySyncAccessDeniedOnWindows,
    FileSyncedParentDirectorySyncUnsupportedOnWindows,
    FileSyncedParentDirectorySyncUnsupportedOnPlatform,
}

/// Unsigned type-7 body and the existing transcript signature message.
///
/// Signing and key custody deliberately remain outside this module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedProductionDoryV3StructuralAnalyzerAbort {
    body: AbortBody,
    signature_message: [u8; 32],
}

impl PreparedProductionDoryV3StructuralAnalyzerAbort {
    pub const fn body(&self) -> &AbortBody {
        &self.body
    }

    pub const fn signature_message(&self) -> [u8; 32] {
        self.signature_message
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3StructuralErrorEvidenceFileReport {
    output: PathBuf,
    durability: ProductionDoryV3StructuralErrorEvidenceDurability,
    evidence: AuthenticatedProductionDoryV3StructuralErrorEvidence,
    prepared_abort: PreparedProductionDoryV3StructuralAnalyzerAbort,
}

impl ProductionDoryV3StructuralErrorEvidenceFileReport {
    pub fn output(&self) -> &Path {
        &self.output
    }

    pub const fn durability(&self) -> ProductionDoryV3StructuralErrorEvidenceDurability {
        self.durability
    }

    pub const fn evidence(&self) -> &AuthenticatedProductionDoryV3StructuralErrorEvidence {
        &self.evidence
    }

    pub const fn prepared_abort(&self) -> &PreparedProductionDoryV3StructuralAnalyzerAbort {
        &self.prepared_abort
    }
}

/// Result of the independently anchored structural-analyzer ceremony step.
#[derive(Debug)]
pub enum ProductionDoryV3StructuralAnalyzerOutcome {
    /// Both independent analyzer passes agreed and the canonical report was
    /// create-new persisted and authenticated.
    Report(Box<ProductionDoryV3ModelStructuralReportRun>),
    /// Analysis failed closed and a canonical external evidence artifact was
    /// persisted. The contained type-7 body is intentionally unsigned.
    AbortEvidence(Box<ProductionDoryV3StructuralErrorEvidenceFileReport>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionDoryV3StructuralAbortSubjectBinding {
    /// The signed type-7 record and its evidence are authenticated, but no
    /// retained payload observation was independently rebound. This includes
    /// failures before any successful read and transient failures whose
    /// recorded payload observation is no longer reproducible.
    AttestationOnly,
    /// The retained payload's stable length and successfully read prefix were
    /// authenticated against the signed external evidence. This does not imply
    /// that bytes beyond the recorded prefix were authenticated.
    RetainedPayloadObservationVerified,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProductionDoryV3StructuralAnalyzerAbort {
    evidence: AuthenticatedProductionDoryV3StructuralErrorEvidence,
    subject_binding: ProductionDoryV3StructuralAbortSubjectBinding,
}

/// Durability reached by one create-new signed-abort staging step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionDoryV3StructuralAbortStageDurability {
    FileAndParentDirectorySynced,
    FileSyncedParentDirectorySyncAccessDeniedOnWindows,
    FileSyncedParentDirectorySyncUnsupportedOnWindows,
    FileSyncedParentDirectorySyncUnsupportedOnPlatform,
}

/// Exact signed type-7 record staged for append-only bulletin publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3StructuralAbortRecordStageReport {
    output: PathBuf,
    record_file: TranscriptFileIdentity,
    record_content_digest: [u8; 32],
    signed_record_digest: [u8; 32],
    signature_message: [u8; 32],
    signer_count: u16,
    subject_binding: ProductionDoryV3StructuralAbortSubjectBinding,
    durability: ProductionDoryV3StructuralAbortStageDurability,
}

impl ProductionDoryV3StructuralAbortRecordStageReport {
    pub fn output(&self) -> &Path {
        &self.output
    }

    pub const fn record_file(&self) -> &TranscriptFileIdentity {
        &self.record_file
    }

    pub const fn signature_message(&self) -> [u8; 32] {
        self.signature_message
    }

    pub const fn record_content_digest(&self) -> [u8; 32] {
        self.record_content_digest
    }

    pub const fn signed_record_digest(&self) -> [u8; 32] {
        self.signed_record_digest
    }

    pub const fn signer_count(&self) -> u16 {
        self.signer_count
    }

    pub const fn subject_binding(&self) -> ProductionDoryV3StructuralAbortSubjectBinding {
        self.subject_binding
    }

    pub const fn durability(&self) -> ProductionDoryV3StructuralAbortStageDurability {
        self.durability
    }
}

/// Reconstructed unsigned type-7 request authenticated from the exact type-5
/// prefix, roots, error evidence, and retained payload observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepreparedProductionDoryV3StructuralAnalyzerAbort {
    prepared_abort: PreparedProductionDoryV3StructuralAnalyzerAbort,
    evidence: AuthenticatedProductionDoryV3StructuralErrorEvidence,
    subject_binding: ProductionDoryV3StructuralAbortSubjectBinding,
}

impl RepreparedProductionDoryV3StructuralAnalyzerAbort {
    pub const fn prepared_abort(&self) -> &PreparedProductionDoryV3StructuralAnalyzerAbort {
        &self.prepared_abort
    }

    pub const fn evidence(&self) -> &AuthenticatedProductionDoryV3StructuralErrorEvidence {
        &self.evidence
    }

    pub const fn subject_binding(&self) -> ProductionDoryV3StructuralAbortSubjectBinding {
        self.subject_binding
    }
}

/// Exact terminal aborted-transcript snapshot staged after its signed type-7
/// record. The original type-5 prefix remains untouched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3StructuralAbortTranscriptStageReport {
    output: PathBuf,
    transcript_file: TranscriptFileIdentity,
    transcript_derive_key_digest: [u8; 32],
    record_file: TranscriptFileIdentity,
    subject_binding: ProductionDoryV3StructuralAbortSubjectBinding,
    durability: ProductionDoryV3StructuralAbortStageDurability,
}

impl ProductionDoryV3StructuralAbortTranscriptStageReport {
    pub fn output(&self) -> &Path {
        &self.output
    }

    pub const fn transcript_file(&self) -> &TranscriptFileIdentity {
        &self.transcript_file
    }

    pub const fn transcript_derive_key_digest(&self) -> [u8; 32] {
        self.transcript_derive_key_digest
    }

    pub const fn record_file(&self) -> &TranscriptFileIdentity {
        &self.record_file
    }

    pub const fn subject_binding(&self) -> ProductionDoryV3StructuralAbortSubjectBinding {
        self.subject_binding
    }

    pub const fn durability(&self) -> ProductionDoryV3StructuralAbortStageDurability {
        self.durability
    }
}

impl VerifiedProductionDoryV3StructuralAnalyzerAbort {
    pub const fn evidence(&self) -> &AuthenticatedProductionDoryV3StructuralErrorEvidence {
        &self.evidence
    }

    pub const fn subject_binding(&self) -> ProductionDoryV3StructuralAbortSubjectBinding {
        self.subject_binding
    }
}

/// Stable, path-free failure metadata mapped by the structural analyzer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProductionDoryV3StructuralEvidenceFailure {
    pub(crate) operation: ProductionDoryV3StructuralEvidenceOperation,
    pub(crate) stage: ProductionDoryV3StructuralEvidenceStage,
    pub(crate) code: ProductionDoryV3StructuralEvidenceFailureCode,
    pub(crate) subject_file: Option<TranscriptFileIdentity>,
    pub(crate) detail: String,
}

#[derive(Debug, Error)]
pub enum ProductionDoryV3StructuralEvidenceError {
    #[error("CMFDSE01 length must be 384 through 448 bytes, found {actual}")]
    EncodedLength { actual: usize },
    #[error("invalid CMFDSE01 magic")]
    InvalidMagic,
    #[error("unsupported CMFDSE01 version {0}")]
    UnsupportedVersion(u16),
    #[error("CMFDSE01 ceremony and last-valid-record anchors must be nonzero")]
    ZeroTranscriptAnchor,
    #[error("invalid CMFDSE01 analyzer target {0}")]
    InvalidAnalyzerTarget(u16),
    #[error("CMFDSE01 roots identity has noncanonical length {0}")]
    InvalidRootsLength(u64),
    #[error("CMFDSE01 expected payload length is noncanonical: {0}")]
    InvalidExpectedPayloadLength(u64),
    #[error("CMFDSE01 subject identity is neither absent nor a full structural report")]
    InvalidSubjectFile,
    #[error("CMFDSE01 validation evidence requires a subject structural report")]
    MissingSubjectFile,
    #[error("CMFDSE01 generation evidence must not name a subject structural report")]
    UnexpectedSubjectFile,
    #[error("invalid CMFDSE01 operation {0}")]
    InvalidOperation(u16),
    #[error("invalid CMFDSE01 stage {0}")]
    InvalidStage(u16),
    #[error("invalid CMFDSE01 failure class {0}")]
    InvalidFailureClass(u16),
    #[error("invalid CMFDSE01 failure code {0}")]
    InvalidFailureCode(u16),
    #[error("CMFDSE01 failure class does not match its registered failure code")]
    FailureClassMismatch,
    #[error("CMFDSE01 failure code is invalid for the recorded stage")]
    StageCodeMismatch,
    #[error("CMFDSE01 payload-prefix accounting is invalid")]
    InvalidProgress,
    #[error("CMFDSE01 empty prefix does not use the canonical empty digests")]
    InvalidEmptyPrefixDigests,
    #[error("CMFDSE01 detail length or exact EOF is invalid")]
    InvalidDetailLength,
    #[error("CMFDSE01 detail contains a byte outside printable ASCII")]
    NonPrintableDetail,
    #[error("CMFDSE01 reserved field is nonzero")]
    ReservedField,
    #[error("CMFDSE01 codec cursor overflow or truncation")]
    Truncated,
    #[error("transcript does not provide the required anchored structural-analyzer authority: {0}")]
    TranscriptAuthority(&'static str),
    #[error("transcript codec or signature verification failed: {0}")]
    Transcript(#[from] CeremonyTranscriptError),
    #[error("CMFDSE01 roots authority does not match the transcript")]
    RootsAuthority,
    #[error("CMFDSE01 artifact does not match the signed transcript anchors")]
    EvidenceAnchorMismatch,
    #[error("signed type-7 abort does not bind the authenticated CMFDSE01 file")]
    AbortEvidenceIdentityMismatch,
    #[error("signed type-7 abort phase or reason does not match CMFDSE01")]
    AbortMetadataMismatch,
    #[error("CMFDSE01 changed while it was being authenticated")]
    EvidenceChanged,
    #[error("structural report and error-evidence outputs must be distinct")]
    OutputPathConflict,
    #[error("failed to authenticate the production roots artifact: {0}")]
    RootsValidation(String),
    #[error("the authenticated production roots artifact changed during use")]
    RootsChanged,
    #[error("the retained failed payload does not match CMFDSE01: {0}")]
    FailedPayloadBinding(&'static str),
    #[error("failed to locate the running structural-analyzer executable: {0}")]
    CurrentExecutablePath(String),
    #[error("failed to dual-hash the running structural-analyzer executable: {0}")]
    CurrentExecutableRead(String),
    #[error("the running structural-analyzer executable does not match the Genesis pin")]
    AnalyzerBinaryMismatch,
    #[error(
        "structural analysis failed ({analyzer}); preserving its canonical evidence failed ({evidence})"
    )]
    EvidencePersistenceAfterAnalyzerFailure { analyzer: String, evidence: String },
    #[error("trusted ceremony filesystem operation failed: {0}")]
    Filesystem(String),
    #[error(
        "unconfirmed ceremony output could not be removed; original failure: {original}; cleanup failure: {cleanup}"
    )]
    OutputCleanup { original: String, cleanup: String },
    #[error("signed structural-abort record is not a terminal type-7 record")]
    NotStructuralAbortRecord,
    #[error("staged structural-abort artifact changed during authentication")]
    StagedArtifactChanged,
}

struct Type5AnalyzerAuthority {
    ceremony_id: [u8; 32],
    last_valid_signed_record_digest: [u8; 32],
    analyzer_target_id: u16,
    analyzer_blake3: [u8; 32],
    analyzer_sha256: [u8; 32],
}

struct RootsBinding {
    ceremony_id: [u8; 32],
    file_identity: TranscriptFileIdentity,
}

/// Run the production structural analyzer under the exact signed type-5
/// authority. The currently executing binary must match the analyzer hashes
/// pinned by Genesis.
///
/// A successful analysis returns the canonical structural report. A mapped
/// analyzer failure returns a durable evidence artifact and an unsigned type-7
/// body/signature message for an external operator or HSM. This function never
/// signs, appends, or publishes a transcript.
#[allow(clippy::too_many_arguments)]
pub fn run_anchored_production_dory_v3_model_structural_report(
    reveal_set_prefix: &[u8],
    expected_ceremony_id: [u8; 32],
    expected_last_signed_record_digest: [u8; 32],
    payload_path: &Path,
    roots_path: &Path,
    report_output_path: &Path,
    evidence_output_path: &Path,
) -> Result<ProductionDoryV3StructuralAnalyzerOutcome, ProductionDoryV3StructuralEvidenceError> {
    let transcript = parse_and_verify_reveal_set_prefix(reveal_set_prefix, expected_ceremony_id)?;
    let authority =
        require_type5_analyzer_authority(&transcript, expected_last_signed_record_digest)?;
    let (running_blake3, running_sha256) = current_executable_hashes()?;
    if running_blake3 != authority.analyzer_blake3 || running_sha256 != authority.analyzer_sha256 {
        return Err(ProductionDoryV3StructuralEvidenceError::AnalyzerBinaryMismatch);
    }
    run_anchored_with_verified_binary(
        &transcript,
        expected_last_signed_record_digest,
        payload_path,
        roots_path,
        report_output_path,
        evidence_output_path,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_anchored_with_verified_binary(
    transcript: &VerifiedCeremonyTranscript,
    expected_last_signed_record_digest: [u8; 32],
    payload_path: &Path,
    roots_path: &Path,
    report_output_path: &Path,
    evidence_output_path: &Path,
) -> Result<ProductionDoryV3StructuralAnalyzerOutcome, ProductionDoryV3StructuralEvidenceError> {
    if report_output_path == evidence_output_path {
        return Err(ProductionDoryV3StructuralEvidenceError::OutputPathConflict);
    }
    let report_parent = TrustedCeremonyParent::for_artifact(report_output_path).map_err(map_fs)?;
    report_parent
        .preflight_output(report_output_path)
        .map_err(map_fs)?;
    let evidence_parent =
        TrustedCeremonyParent::for_artifact(evidence_output_path).map_err(map_fs)?;
    evidence_parent
        .preflight_output(evidence_output_path)
        .map_err(map_fs)?;

    let (roots, roots_binding) = authenticate_roots_artifact(roots_path, transcript.ceremony_id())?;

    let mut progress = StructuralAnalyzerProgress::new();
    match run_production_dory_v3_model_structural_report_observed_from_claims(
        payload_path,
        &roots,
        report_output_path,
        &mut progress,
    ) {
        Ok(report) => Ok(ProductionDoryV3StructuralAnalyzerOutcome::Report(Box::new(
            report,
        ))),
        Err(analyzer_error) => {
            let observed_prefix = progress.snapshot();
            let opened_payload_bytes = opened_payload_bytes(
                &analyzer_error,
                progress.scan_index(),
                observed_prefix.bytes(),
            );
            let failure = map_structural_failure(&analyzer_error, progress.scan_index());
            let analyzer = analyzer_error.to_string();
            let evidence = persist_production_dory_v3_structural_error_evidence(
                transcript,
                expected_last_signed_record_digest,
                &roots_binding,
                opened_payload_bytes,
                observed_prefix,
                failure,
                evidence_output_path,
            )
            .map_err(|evidence| {
                ProductionDoryV3StructuralEvidenceError::EvidencePersistenceAfterAnalyzerFailure {
                    analyzer,
                    evidence: evidence.to_string(),
                }
            })?;
            Ok(ProductionDoryV3StructuralAnalyzerOutcome::AbortEvidence(
                Box::new(evidence),
            ))
        }
    }
}

/// Parse and verify a signed terminal type-7 transcript, authenticate the exact
/// roots and `CMFDSE01` artifacts, then bind a reproducible retained failed
/// payload to the evidence's recorded length and successfully read prefix.
#[allow(clippy::too_many_arguments)]
pub fn verify_anchored_production_dory_v3_structural_abort(
    aborted_transcript: &[u8],
    expected_ceremony_id: [u8; 32],
    expected_last_signed_record_digest: [u8; 32],
    payload_path: &Path,
    roots_path: &Path,
    evidence_path: &Path,
) -> Result<VerifiedProductionDoryV3StructuralAnalyzerAbort, ProductionDoryV3StructuralEvidenceError>
{
    let transcript = parse_and_verify_ceremony_transcript(aborted_transcript)?;
    let _ = require_type7_analyzer_abort(
        &transcript,
        expected_ceremony_id,
        expected_last_signed_record_digest,
    )?;
    let (_, roots) = authenticate_roots_artifact(roots_path, expected_ceremony_id)?;
    let evidence = validate_production_dory_v3_structural_error_evidence_file_with_roots(
        &transcript,
        evidence_path,
        expected_ceremony_id,
        expected_last_signed_record_digest,
        &roots,
    )?;
    let subject_binding = authenticate_failed_payload(payload_path, evidence.claims())?;
    Ok(VerifiedProductionDoryV3StructuralAnalyzerAbort {
        evidence,
        subject_binding,
    })
}

/// Reconstruct the exact unsigned type-7 body and BIP340 raw-signing message
/// from authenticated ceremony artifacts. This read-only step is suitable for
/// exporting the 32-byte message to an external signer or HSM.
#[allow(clippy::too_many_arguments)]
pub fn prepare_anchored_production_dory_v3_structural_abort_from_files(
    reveal_set_prefix: &[u8],
    expected_ceremony_id: [u8; 32],
    expected_last_signed_record_digest: [u8; 32],
    payload_path: &Path,
    roots_path: &Path,
    evidence_path: &Path,
) -> Result<
    RepreparedProductionDoryV3StructuralAnalyzerAbort,
    ProductionDoryV3StructuralEvidenceError,
> {
    let prepared = reprepare_structural_abort(
        reveal_set_prefix,
        expected_ceremony_id,
        expected_last_signed_record_digest,
        payload_path,
        roots_path,
        evidence_path,
    )?;
    Ok(RepreparedProductionDoryV3StructuralAnalyzerAbort {
        prepared_abort: prepared.prepared_abort,
        evidence: prepared.evidence,
        subject_binding: prepared.subject_binding,
    })
}

/// Verify externally produced roster signatures and stage the exact signed
/// type-7 record as one create-new file. This never reads or stores a private
/// signing key and never modifies the type-5 prefix.
#[allow(clippy::too_many_arguments)]
pub fn stage_anchored_production_dory_v3_structural_abort_record(
    reveal_set_prefix: &[u8],
    expected_ceremony_id: [u8; 32],
    expected_last_signed_record_digest: [u8; 32],
    payload_path: &Path,
    roots_path: &Path,
    evidence_path: &Path,
    signatures: Vec<RecordSignature>,
    output_path: &Path,
) -> Result<ProductionDoryV3StructuralAbortRecordStageReport, ProductionDoryV3StructuralEvidenceError>
{
    let prepared = prepare_signed_structural_abort(
        reveal_set_prefix,
        expected_ceremony_id,
        expected_last_signed_record_digest,
        payload_path,
        roots_path,
        evidence_path,
        signatures,
    )?;
    let signature_message = ceremony_record_signature_message(&prepared.record.body)?;
    let record_content_digest = ceremony_record_content_digest(&prepared.record.body)?;
    let signed_record_digest = ceremony_signed_record_digest(&prepared.record)?;
    let signer_count = u16::try_from(prepared.record.signatures.len())
        .map_err(|_| CeremonyTranscriptError::Limit("abort signature count"))?;
    let record_bytes = encode_ceremony_record(&prepared.record)?;
    let expected_record = prepared.record.clone();
    let (_, record_file, durability) =
        persist_staged_abort_bytes(output_path, &record_bytes, |reopened| {
            let record = decode_ceremony_record(reopened)?;
            if record != expected_record || !matches!(record.body, CeremonyRecordBody::Abort(_)) {
                return Err(ProductionDoryV3StructuralEvidenceError::StagedArtifactChanged);
            }
            Ok(())
        })?;
    Ok(ProductionDoryV3StructuralAbortRecordStageReport {
        output: output_path.to_path_buf(),
        record_file,
        record_content_digest,
        signed_record_digest,
        signature_message,
        signer_count,
        subject_binding: prepared.subject_binding,
        durability,
    })
}

/// Consume one immutable staged type-7 record and stage the exact terminal
/// aborted-transcript snapshot as a second create-new file. The canonical
/// transcript header is rebuilt; the input type-5 prefix is never overwritten
/// or byte-appended in place.
#[allow(clippy::too_many_arguments)]
pub fn stage_anchored_production_dory_v3_structural_abort_transcript(
    reveal_set_prefix: &[u8],
    expected_ceremony_id: [u8; 32],
    expected_last_signed_record_digest: [u8; 32],
    payload_path: &Path,
    roots_path: &Path,
    evidence_path: &Path,
    signed_abort_record_path: &Path,
    output_path: &Path,
) -> Result<
    ProductionDoryV3StructuralAbortTranscriptStageReport,
    ProductionDoryV3StructuralEvidenceError,
> {
    let (staged_record, record_file) = authenticate_signed_abort_record(signed_abort_record_path)?;
    let prepared = prepare_signed_structural_abort(
        reveal_set_prefix,
        expected_ceremony_id,
        expected_last_signed_record_digest,
        payload_path,
        roots_path,
        evidence_path,
        staged_record.signatures.clone(),
    )?;
    if prepared.record != staged_record {
        return Err(ProductionDoryV3StructuralEvidenceError::StagedArtifactChanged);
    }
    let staged_record_bytes = encode_ceremony_record(&staged_record)?;
    let expected_evidence = prepared.evidence.clone();
    let expected_subject_binding = prepared.subject_binding;
    let transcript_bytes = prepared.transcript_bytes;
    verify_abort_successor_snapshot(reveal_set_prefix, &staged_record_bytes, &transcript_bytes)?;
    let ((verified, transcript_derive_key_digest), transcript_file, durability) =
        persist_staged_abort_bytes(output_path, &transcript_bytes, |reopened| {
            verify_abort_successor_snapshot(reveal_set_prefix, &staged_record_bytes, reopened)?;
            let verified = verify_anchored_production_dory_v3_structural_abort(
                reopened,
                expected_ceremony_id,
                expected_last_signed_record_digest,
                payload_path,
                roots_path,
                evidence_path,
            )?;
            if verified.evidence() != &expected_evidence
                || verified.subject_binding() != expected_subject_binding
            {
                return Err(ProductionDoryV3StructuralEvidenceError::StagedArtifactChanged);
            }
            let parsed = parse_and_verify_ceremony_transcript(reopened)?;
            if parsed.status() != CeremonyTranscriptStatus::Aborted {
                return Err(ProductionDoryV3StructuralEvidenceError::StagedArtifactChanged);
            }
            let (final_record, final_record_file) =
                authenticate_signed_abort_record(signed_abort_record_path)?;
            if final_record != staged_record || final_record_file != record_file {
                return Err(ProductionDoryV3StructuralEvidenceError::StagedArtifactChanged);
            }
            Ok((verified, parsed.transcript_derive_key_digest()))
        })?;
    Ok(ProductionDoryV3StructuralAbortTranscriptStageReport {
        output: output_path.to_path_buf(),
        transcript_file,
        transcript_derive_key_digest,
        record_file,
        subject_binding: verified.subject_binding(),
        durability,
    })
}

struct PreparedSignedStructuralAbort {
    record: SignedCeremonyRecord,
    transcript_bytes: Vec<u8>,
    evidence: AuthenticatedProductionDoryV3StructuralErrorEvidence,
    subject_binding: ProductionDoryV3StructuralAbortSubjectBinding,
}

struct RepreparedStructuralAbort {
    prefix: VerifiedCeremonyTranscript,
    prepared_abort: PreparedProductionDoryV3StructuralAnalyzerAbort,
    evidence: AuthenticatedProductionDoryV3StructuralErrorEvidence,
    subject_binding: ProductionDoryV3StructuralAbortSubjectBinding,
}

#[allow(clippy::too_many_arguments)]
fn prepare_signed_structural_abort(
    reveal_set_prefix: &[u8],
    expected_ceremony_id: [u8; 32],
    expected_last_signed_record_digest: [u8; 32],
    payload_path: &Path,
    roots_path: &Path,
    evidence_path: &Path,
    mut signatures: Vec<RecordSignature>,
) -> Result<PreparedSignedStructuralAbort, ProductionDoryV3StructuralEvidenceError> {
    let prepared = reprepare_structural_abort(
        reveal_set_prefix,
        expected_ceremony_id,
        expected_last_signed_record_digest,
        payload_path,
        roots_path,
        evidence_path,
    )?;
    signatures.sort_by_key(|signature| (signature.signer_class, signature.signer_index));
    let record = SignedCeremonyRecord {
        body: CeremonyRecordBody::Abort(prepared.prepared_abort.body.clone()),
        signatures,
    };
    let mut records = prepared.prefix.records().to_vec();
    records.push(record.clone());
    let transcript_bytes = encode_and_verify_ceremony_transcript(&records)?;
    Ok(PreparedSignedStructuralAbort {
        record,
        transcript_bytes,
        evidence: prepared.evidence,
        subject_binding: prepared.subject_binding,
    })
}

#[allow(clippy::too_many_arguments)]
fn reprepare_structural_abort(
    reveal_set_prefix: &[u8],
    expected_ceremony_id: [u8; 32],
    expected_last_signed_record_digest: [u8; 32],
    payload_path: &Path,
    roots_path: &Path,
    evidence_path: &Path,
) -> Result<RepreparedStructuralAbort, ProductionDoryV3StructuralEvidenceError> {
    let prefix = parse_and_verify_reveal_set_prefix(reveal_set_prefix, expected_ceremony_id)?;
    let authority = require_type5_analyzer_authority(&prefix, expected_last_signed_record_digest)?;
    let (_, roots) = authenticate_roots_artifact(roots_path, expected_ceremony_id)?;
    let (claims, evidence_file) = authenticate_evidence_file(evidence_path)?;
    verify_claims_against_authority(&claims, &authority, &roots)?;
    let subject_binding = authenticate_failed_payload(payload_path, &claims)?;
    let body = AbortBody {
        ceremony_id: authority.ceremony_id,
        last_valid_signed_record_digest: authority.last_valid_signed_record_digest,
        phase: STRUCTURAL_ANALYZER_ABORT_PHASE,
        reason_code: claims.abort_reason_code(),
        evidence_file: evidence_file.clone(),
    };
    let signature_message =
        ceremony_record_signature_message(&CeremonyRecordBody::Abort(body.clone()))?;
    Ok(RepreparedStructuralAbort {
        prefix,
        prepared_abort: PreparedProductionDoryV3StructuralAnalyzerAbort {
            body,
            signature_message,
        },
        evidence: AuthenticatedProductionDoryV3StructuralErrorEvidence {
            claims,
            file_identity: evidence_file,
        },
        subject_binding,
    })
}

const MAX_SIGNED_CEREMONY_RECORD_BYTES: usize =
    2 + 2 + 4 + MAX_CEREMONY_RECORD_BODY_BYTES + 2 + MAX_CEREMONY_SIGNERS * (1 + 2 + 64);

fn authenticate_signed_abort_record(
    path: &Path,
) -> Result<(SignedCeremonyRecord, TranscriptFileIdentity), ProductionDoryV3StructuralEvidenceError>
{
    let parent = TrustedCeremonyParent::for_artifact(path).map_err(map_fs)?;
    let mut input = AuthenticatedInput::open(&parent, path, None).map_err(map_fs)?;
    let initial = input
        .read_bounded(MAX_SIGNED_CEREMONY_RECORD_BYTES)
        .map_err(map_fs)?;
    let exact_len = u64::try_from(initial.len())
        .map_err(|_| CeremonyTranscriptError::Limit("signed abort record bytes"))?;
    input.recheck(&parent, Some(exact_len)).map_err(map_fs)?;
    let record = decode_ceremony_record(&initial)?;
    if !matches!(record.body, CeremonyRecordBody::Abort(_)) {
        return Err(ProductionDoryV3StructuralEvidenceError::NotStructuralAbortRecord);
    }
    let file_identity = content_identity(&initial)?;
    let final_bytes = input
        .read_bounded(MAX_SIGNED_CEREMONY_RECORD_BYTES)
        .map_err(map_fs)?;
    input.recheck(&parent, Some(exact_len)).map_err(map_fs)?;
    parent.recheck().map_err(map_fs)?;
    if final_bytes != initial
        || decode_ceremony_record(&final_bytes)? != record
        || content_identity(&final_bytes)? != file_identity
    {
        return Err(ProductionDoryV3StructuralEvidenceError::StagedArtifactChanged);
    }
    Ok((record, file_identity))
}

fn verify_abort_successor_snapshot(
    reveal_set_prefix: &[u8],
    staged_record: &[u8],
    successor: &[u8],
) -> Result<(), ProductionDoryV3StructuralEvidenceError> {
    let header_bytes =
        usize::from(crate::dory_v3_model_ceremony_transcript::CEREMONY_TRANSCRIPT_HEADER_BYTES);
    let unchanged_header_bytes = 12;
    let expected_successor_bytes = reveal_set_prefix
        .len()
        .checked_add(staged_record.len())
        .ok_or(CeremonyTranscriptError::Limit("aborted transcript bytes"))?;
    if reveal_set_prefix.len() < header_bytes
        || successor.len() != expected_successor_bytes
        || successor.get(..unchanged_header_bytes)
            != reveal_set_prefix.get(..unchanged_header_bytes)
        || successor.get(header_bytes..reveal_set_prefix.len())
            != reveal_set_prefix.get(header_bytes..)
        || successor.get(reveal_set_prefix.len()..) != Some(staged_record)
    {
        return Err(ProductionDoryV3StructuralEvidenceError::StagedArtifactChanged);
    }
    Ok(())
}

fn persist_staged_abort_bytes<T>(
    output_path: &Path,
    bytes: &[u8],
    validate: impl FnOnce(&[u8]) -> Result<T, ProductionDoryV3StructuralEvidenceError>,
) -> Result<
    (
        T,
        TranscriptFileIdentity,
        ProductionDoryV3StructuralAbortStageDurability,
    ),
    ProductionDoryV3StructuralEvidenceError,
> {
    let parent = TrustedCeremonyParent::for_artifact(output_path).map_err(map_fs)?;
    let mut output = PendingOutput::create(&parent, output_path).map_err(map_fs)?;
    let completion = (|| {
        output.write_all(bytes).map_err(map_fs)?;
        output.sync_file().map_err(map_fs)?;
        let reopened = output.reopen_exact(&parent, bytes).map_err(map_fs)?;
        let value = validate(&reopened)?;
        let file_identity = content_identity(&reopened)?;
        let durability = map_abort_stage_durability(output.sync_parent(&parent).map_err(map_fs)?);
        Ok((value, file_identity, durability))
    })();
    finish_pending_output(output, &parent, completion)
}

fn authenticate_roots_artifact(
    path: &Path,
    expected_ceremony_id: [u8; 32],
) -> Result<(ProductionDoryV3ModelRootsClaims, RootsBinding), ProductionDoryV3StructuralEvidenceError>
{
    let parent = TrustedCeremonyParent::for_artifact(path).map_err(map_fs)?;
    let expected_bytes = PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES as u64;
    let mut input =
        AuthenticatedInput::open(&parent, path, Some(expected_bytes)).map_err(map_fs)?;
    let initial = input
        .read_bounded(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES)
        .map_err(map_fs)?;
    input
        .recheck(&parent, Some(expected_bytes))
        .map_err(map_fs)?;
    let expected_ceremony_id = crate::dory_v3_suite::Digest32::new(expected_ceremony_id);
    let claims =
        ProductionDoryV3ModelRootsClaims::parse_and_validate(&initial, expected_ceremony_id)
            .map_err(|error| {
                ProductionDoryV3StructuralEvidenceError::RootsValidation(error.to_string())
            })?;
    if claims.canonical_bytes().as_slice() != initial.as_slice() {
        return Err(ProductionDoryV3StructuralEvidenceError::RootsChanged);
    }

    let final_bytes = input
        .read_bounded(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES)
        .map_err(map_fs)?;
    input
        .recheck(&parent, Some(expected_bytes))
        .map_err(map_fs)?;
    parent.recheck().map_err(map_fs)?;
    if final_bytes != initial {
        return Err(ProductionDoryV3StructuralEvidenceError::RootsChanged);
    }
    let final_claims =
        ProductionDoryV3ModelRootsClaims::parse_and_validate(&final_bytes, expected_ceremony_id)
            .map_err(|error| {
                ProductionDoryV3StructuralEvidenceError::RootsValidation(error.to_string())
            })?;
    if final_claims != claims {
        return Err(ProductionDoryV3StructuralEvidenceError::RootsChanged);
    }
    let binding = RootsBinding {
        ceremony_id: claims.ceremony_id().into_bytes(),
        file_identity: content_identity(&final_bytes)?,
    };
    Ok((claims, binding))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FailedPayloadPrefixObservation {
    blake3: [u8; 32],
    sha256: [u8; 32],
    contains_forbidden_byte: bool,
}

fn authenticate_failed_payload(
    path: &Path,
    claims: &ProductionDoryV3StructuralErrorEvidenceClaims,
) -> Result<ProductionDoryV3StructuralAbortSubjectBinding, ProductionDoryV3StructuralEvidenceError>
{
    use ProductionDoryV3StructuralEvidenceFailureCode as Code;

    if claims.opened_payload_bytes() == 0
        && claims.payload_prefix_bytes() == 0
        && claims.failure_code() != Code::PayloadLengthMismatch
    {
        // The analyzer did not authenticate or successfully read a subject
        // payload. The signed abort remains an attestation to that pre-read
        // failure; there are no subject bytes for this verifier to bind.
        return Ok(ProductionDoryV3StructuralAbortSubjectBinding::AttestationOnly);
    }

    match authenticate_failed_payload_observation(path, claims) {
        Ok(()) => {
            Ok(ProductionDoryV3StructuralAbortSubjectBinding::RetainedPayloadObservationVerified)
        }
        Err(_) if permits_attestation_only(claims.failure_code()) => {
            Ok(ProductionDoryV3StructuralAbortSubjectBinding::AttestationOnly)
        }
        Err(error) => Err(error),
    }
}

fn authenticate_failed_payload_observation(
    path: &Path,
    claims: &ProductionDoryV3StructuralErrorEvidenceClaims,
) -> Result<(), ProductionDoryV3StructuralEvidenceError> {
    use ProductionDoryV3StructuralEvidenceFailureCode as Code;

    let parent = TrustedCeremonyParent::for_artifact(path).map_err(map_fs)?;
    let mut input = AuthenticatedInput::open(&parent, path, None).map_err(map_fs)?;
    let current_bytes = input
        .file_mut()
        .metadata()
        .map_err(|_| {
            ProductionDoryV3StructuralEvidenceError::FailedPayloadBinding(
                "failed to inspect the retained payload",
            )
        })?
        .len();
    validate_retained_payload_length(current_bytes, claims)?;

    let first = hash_failed_payload_prefix(input.file_mut(), claims.payload_prefix_bytes())?;
    input
        .recheck(&parent, Some(current_bytes))
        .map_err(map_fs)?;
    let second = hash_failed_payload_prefix(input.file_mut(), claims.payload_prefix_bytes())?;
    input
        .recheck(&parent, Some(current_bytes))
        .map_err(map_fs)?;
    parent.recheck().map_err(map_fs)?;
    if first != second
        || first.blake3 != claims.payload_prefix_blake3()
        || first.sha256 != claims.payload_prefix_sha256()
    {
        return Err(
            ProductionDoryV3StructuralEvidenceError::FailedPayloadBinding(
                "the retained payload prefix does not match the evidence",
            ),
        );
    }
    if claims.failure_code() == Code::PayloadByteAbove250 && !first.contains_forbidden_byte {
        return Err(
            ProductionDoryV3StructuralEvidenceError::FailedPayloadBinding(
                "the retained payload prefix contains no forbidden byte",
            ),
        );
    }
    Ok(())
}

const fn permits_attestation_only(code: ProductionDoryV3StructuralEvidenceFailureCode) -> bool {
    use ProductionDoryV3StructuralEvidenceFailureCode as Code;

    matches!(
        code,
        Code::FilesystemIdentityOrReplacement
            | Code::PermissionDrift
            | Code::IoFailure
            | Code::ResourceFailure
            | Code::OtherFailClosed
    )
}

fn validate_retained_payload_length(
    current_bytes: u64,
    claims: &ProductionDoryV3StructuralErrorEvidenceClaims,
) -> Result<(), ProductionDoryV3StructuralEvidenceError> {
    use ProductionDoryV3StructuralEvidenceFailureCode as Code;

    let opened = claims.opened_payload_bytes();
    let prefix = claims.payload_prefix_bytes();
    let matches = match claims.failure_code() {
        Code::PayloadLengthMismatch | Code::EarlyEof => current_bytes == opened,
        Code::TrailingBytes => current_bytes >= prefix,
        _ => current_bytes == opened && current_bytes >= prefix,
    };
    if matches {
        Ok(())
    } else {
        Err(
            ProductionDoryV3StructuralEvidenceError::FailedPayloadBinding(
                "the retained payload length does not match the evidence",
            ),
        )
    }
}

fn hash_failed_payload_prefix(
    file: &mut File,
    prefix_bytes: u64,
) -> Result<FailedPayloadPrefixObservation, ProductionDoryV3StructuralEvidenceError> {
    file.seek(SeekFrom::Start(0)).map_err(|_| {
        ProductionDoryV3StructuralEvidenceError::FailedPayloadBinding(
            "failed to seek the retained payload",
        )
    })?;
    let mut blake3 = blake3::Hasher::new();
    let mut sha256 = Sha256::new();
    let mut contains_forbidden_byte = false;
    let mut remaining = prefix_bytes;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("the bounded payload read size fits usize");
        let read = match file.read(&mut buffer[..requested]) {
            Ok(0) => {
                return Err(
                    ProductionDoryV3StructuralEvidenceError::FailedPayloadBinding(
                        "the retained payload ends before the recorded prefix",
                    ),
                );
            }
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                return Err(
                    ProductionDoryV3StructuralEvidenceError::FailedPayloadBinding(
                        "failed to read the retained payload prefix",
                    ),
                );
            }
        };
        let observed = &buffer[..read];
        contains_forbidden_byte |= observed.iter().any(|byte| *byte > crate::MAX_MODEL_BYTE);
        blake3.update(observed);
        sha256.update(observed);
        remaining -= u64::try_from(read).expect("the bounded payload read size fits u64");
    }
    Ok(FailedPayloadPrefixObservation {
        blake3: *blake3.finalize().as_bytes(),
        sha256: sha256.finalize().into(),
        contains_forbidden_byte,
    })
}

fn current_executable_hashes()
-> Result<([u8; 32], [u8; 32]), ProductionDoryV3StructuralEvidenceError> {
    #[cfg(target_os = "linux")]
    let mut file = File::open("/proc/self/exe").map_err(|error| {
        ProductionDoryV3StructuralEvidenceError::CurrentExecutableRead(error.to_string())
    })?;
    #[cfg(not(target_os = "linux"))]
    let mut file = {
        let path = std::env::current_exe().map_err(|error| {
            ProductionDoryV3StructuralEvidenceError::CurrentExecutablePath(error.to_string())
        })?;
        File::open(&path).map_err(|error| {
            ProductionDoryV3StructuralEvidenceError::CurrentExecutableRead(error.to_string())
        })?
    };
    let mut blake3 = blake3::Hasher::new();
    let mut sha256 = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(
                    ProductionDoryV3StructuralEvidenceError::CurrentExecutableRead(
                        error.to_string(),
                    ),
                );
            }
        };
        if read == 0 {
            break;
        }
        blake3.update(&buffer[..read]);
        sha256.update(&buffer[..read]);
    }
    Ok((*blake3.finalize().as_bytes(), sha256.finalize().into()))
}

fn opened_payload_bytes(
    error: &ProductionDoryV3ModelStructureError,
    scan_index: u8,
    observed_prefix_bytes: u64,
) -> u64 {
    use ProductionDoryV3ModelStructureError as Error;
    match error {
        Error::PayloadLength { actual, .. } if scan_index == 0 => *actual,
        Error::PayloadLength { .. } => observed_prefix_bytes,
        Error::EarlyEof { .. } | Error::TrailingBytes(_) => observed_prefix_bytes,
        _ if scan_index == 0 => 0,
        _ => EXPECTED_PRODUCTION_PAYLOAD_BYTES,
    }
}

fn analyzer_stage(scan_index: u8) -> ProductionDoryV3StructuralEvidenceStage {
    if scan_index >= 2 {
        ProductionDoryV3StructuralEvidenceStage::SecondAnalysis
    } else if scan_index == 1 {
        ProductionDoryV3StructuralEvidenceStage::FirstAnalysis
    } else {
        ProductionDoryV3StructuralEvidenceStage::InputAuthentication
    }
}

fn map_structural_failure(
    error: &ProductionDoryV3ModelStructureError,
    scan_index: u8,
) -> ProductionDoryV3StructuralEvidenceFailure {
    use ProductionDoryV3ModelStructureError as Error;
    use ProductionDoryV3StructuralEvidenceFailureCode as Code;
    use ProductionDoryV3StructuralEvidenceStage as Stage;

    let (stage, code, detail) = match error {
        Error::PayloadLength { .. } if scan_index == 0 => (
            Stage::InputAuthentication,
            Code::PayloadLengthMismatch,
            "payload length mismatch",
        ),
        Error::PayloadLength { .. } => (
            Stage::FinalRecheck,
            Code::FilesystemIdentityOrReplacement,
            "payload length changed after analysis",
        ),
        Error::EarlyEof { .. } => (
            analyzer_stage(scan_index),
            Code::EarlyEof,
            "payload ended early",
        ),
        Error::TrailingBytes(_) => (
            analyzer_stage(scan_index),
            Code::TrailingBytes,
            "payload has trailing bytes",
        ),
        Error::OutOfRange { .. } => (
            analyzer_stage(scan_index),
            Code::PayloadByteAbove250,
            "payload byte exceeds 250",
        ),
        Error::FatalAnalysis(mask) if mask & (1 << 1) != 0 => (
            analyzer_stage(scan_index),
            Code::RootOrDigestMismatch,
            "payload roots differ",
        ),
        Error::FatalAnalysis(_) => (
            analyzer_stage(scan_index),
            Code::FatalStructuralComputation,
            "structural fatal mask is nonzero",
        ),
        Error::RootMismatch => (
            analyzer_stage(scan_index),
            Code::RootOrDigestMismatch,
            "payload roots differ",
        ),
        Error::GeometryOverflow
        | Error::ProductionGeometryMismatch
        | Error::RootsGeometryMismatch => (
            Stage::InputAuthentication,
            Code::GeometryOrToolMismatch,
            "frozen geometry mismatch",
        ),
        Error::CounterOverflow => (
            analyzer_stage(scan_index),
            Code::CounterOverflow,
            "structural counter overflow",
        ),
        Error::ReportLength { .. }
        | Error::InvalidMagic
        | Error::UnsupportedVersion(_)
        | Error::CeremonyIdMismatch
        | Error::InvalidReportPayloadLength
        | Error::InvalidSectionCount
        | Error::InvalidSectionKind(_)
        | Error::InvalidSectionGeometry { .. }
        | Error::InvalidSectionCounter { .. }
        | Error::ReservedDiagnosticBits
        | Error::DiagnosticMaskMismatch
        | Error::ReservedFatalBits
        | Error::FatalMaskMismatch
        | Error::NonzeroFatalMask => (
            Stage::ReportEncoding,
            Code::StructuralReportEncoding,
            "structural report encoding failed",
        ),
        Error::PayloadReportMismatch => (
            Stage::SecondAnalysis,
            Code::StructuralReportReproductionMismatch,
            "independent analyzer passes differ",
        ),
        Error::PayloadIdentityMismatch(_)
        | Error::PayloadNotRegular(_)
        | Error::InvalidPayloadPath(_)
        | Error::PayloadReparsePoint(_)
        | Error::PayloadHardLinks { .. }
        | Error::PayloadReportSameFile
        | Error::OutputIdentityMismatch(_)
        | Error::OutputReparsePoint(_)
        | Error::OutputHardLinks { .. }
        | Error::QuarantinedOutput { .. } => (
            if scan_index == 0 {
                Stage::InputAuthentication
            } else {
                Stage::FinalRecheck
            },
            Code::FilesystemIdentityOrReplacement,
            "filesystem identity changed",
        ),
        Error::SetOutputPermissions { .. } => (
            Stage::ReportPersistence,
            Code::PermissionDrift,
            "private output permissions failed",
        ),
        Error::InspectPayload { .. }
        | Error::OpenPayload { .. }
        | Error::ReadPayload(_)
        | Error::InspectOutput { .. }
        | Error::CreateOutput { .. }
        | Error::WriteOutput { .. }
        | Error::ReopenOutput { .. }
        | Error::SyncParent { .. }
        | Error::CleanupOutput { .. } => (
            if scan_index == 0 {
                Stage::InputAuthentication
            } else if matches!(error, Error::ReadPayload(_)) {
                analyzer_stage(scan_index)
            } else {
                Stage::ReportPersistence
            },
            Code::IoFailure,
            "structural analyzer I/O failed",
        ),
        Error::ReopenedReportMismatch => (
            Stage::FinalRecheck,
            Code::StructuralReportReproductionMismatch,
            "reopened report differs",
        ),
        Error::OutputExists(_) | Error::InvalidOutputPath(_) | Error::OutputParent(_) => (
            if scan_index == 0 {
                Stage::InputAuthentication
            } else {
                Stage::ReportPersistence
            },
            Code::FilesystemIdentityOrReplacement,
            "report output is unavailable",
        ),
    };
    ProductionDoryV3StructuralEvidenceFailure {
        operation: ProductionDoryV3StructuralEvidenceOperation::GenerateReport,
        stage,
        code,
        subject_file: None,
        detail: detail.to_owned(),
    }
}

/// Persist one canonical artifact after a mapped analyzer failure.
///
/// The transcript must be the opaque result of
/// `parse_and_verify_reveal_set_prefix`, and `expected_last_signed_record_digest`
/// must be independently retained by the caller before analysis begins.
fn persist_production_dory_v3_structural_error_evidence(
    transcript: &VerifiedCeremonyTranscript,
    expected_last_signed_record_digest: [u8; 32],
    roots: &RootsBinding,
    opened_payload_bytes: u64,
    progress: StructuralAnalyzerPayloadPrefix,
    failure: ProductionDoryV3StructuralEvidenceFailure,
    output_path: &Path,
) -> Result<
    ProductionDoryV3StructuralErrorEvidenceFileReport,
    ProductionDoryV3StructuralEvidenceError,
> {
    let authority =
        require_type5_analyzer_authority(transcript, expected_last_signed_record_digest)?;
    if roots.ceremony_id != authority.ceremony_id {
        return Err(ProductionDoryV3StructuralEvidenceError::RootsAuthority);
    }
    let claims = build_claims(&authority, roots, opened_payload_bytes, progress, failure)?;
    persist_claims(claims, output_path)
}

/// Authenticate one authoritative evidence file against a signed type-7 abort.
///
/// Both expected anchors must be obtained independently; deriving them from the
/// transcript under validation removes the organizer-intent trust anchor.
pub fn validate_production_dory_v3_structural_error_evidence_file(
    transcript: &VerifiedCeremonyTranscript,
    evidence_path: &Path,
    expected_ceremony_id: [u8; 32],
    expected_last_signed_record_digest: [u8; 32],
    roots: &ProductionDoryV3ModelRoots,
) -> Result<
    AuthenticatedProductionDoryV3StructuralErrorEvidence,
    ProductionDoryV3StructuralEvidenceError,
> {
    let roots = RootsBinding::from_verified(roots);
    validate_production_dory_v3_structural_error_evidence_file_with_roots(
        transcript,
        evidence_path,
        expected_ceremony_id,
        expected_last_signed_record_digest,
        &roots,
    )
}

fn validate_production_dory_v3_structural_error_evidence_file_with_roots(
    transcript: &VerifiedCeremonyTranscript,
    evidence_path: &Path,
    expected_ceremony_id: [u8; 32],
    expected_last_signed_record_digest: [u8; 32],
    roots: &RootsBinding,
) -> Result<
    AuthenticatedProductionDoryV3StructuralErrorEvidence,
    ProductionDoryV3StructuralEvidenceError,
> {
    let (authority, abort) = require_type7_analyzer_abort(
        transcript,
        expected_ceremony_id,
        expected_last_signed_record_digest,
    )?;
    if roots.ceremony_id != authority.ceremony_id {
        return Err(ProductionDoryV3StructuralEvidenceError::RootsAuthority);
    }
    let (claims, file_identity) = authenticate_evidence_file(evidence_path)?;
    verify_authenticated_abort_bindings(&claims, &file_identity, &authority, &abort, roots)?;
    Ok(AuthenticatedProductionDoryV3StructuralErrorEvidence {
        claims,
        file_identity,
    })
}

fn build_claims(
    authority: &Type5AnalyzerAuthority,
    roots: &RootsBinding,
    opened_payload_bytes: u64,
    progress: StructuralAnalyzerPayloadPrefix,
    failure: ProductionDoryV3StructuralEvidenceFailure,
) -> Result<ProductionDoryV3StructuralErrorEvidenceClaims, ProductionDoryV3StructuralEvidenceError>
{
    let detail = failure.detail.into_bytes();
    let claims = ProductionDoryV3StructuralErrorEvidenceClaims {
        ceremony_id: authority.ceremony_id,
        last_valid_signed_record_digest: authority.last_valid_signed_record_digest,
        analyzer_target_id: authority.analyzer_target_id,
        analyzer_blake3: authority.analyzer_blake3,
        analyzer_sha256: authority.analyzer_sha256,
        roots_file: roots.file_identity.clone(),
        expected_payload_bytes: EXPECTED_PRODUCTION_PAYLOAD_BYTES,
        opened_payload_bytes,
        payload_prefix_bytes: progress.bytes(),
        payload_prefix_blake3: progress.blake3().into_bytes(),
        payload_prefix_sha256: progress.sha256().into_bytes(),
        subject_file: failure.subject_file,
        operation: failure.operation,
        stage: failure.stage,
        failure_class: failure.code.failure_class(),
        failure_code: failure.code,
        detail,
    };
    // One codec path defines all construction invariants.
    ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&claims.canonical_bytes())
}

fn persist_claims(
    claims: ProductionDoryV3StructuralErrorEvidenceClaims,
    output_path: &Path,
) -> Result<
    ProductionDoryV3StructuralErrorEvidenceFileReport,
    ProductionDoryV3StructuralEvidenceError,
> {
    let parent = TrustedCeremonyParent::for_artifact(output_path).map_err(map_fs)?;
    let bytes = claims.canonical_bytes();
    let mut output = PendingOutput::create(&parent, output_path).map_err(map_fs)?;
    let completion = (|| {
        output.write_all(&bytes).map_err(map_fs)?;
        output.sync_file().map_err(map_fs)?;
        let reopened = output.reopen_exact(&parent, &bytes).map_err(map_fs)?;
        let reopened_claims =
            ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&reopened)?;
        if reopened_claims != claims {
            return Err(ProductionDoryV3StructuralEvidenceError::EvidenceChanged);
        }
        let durability = map_durability(output.sync_parent(&parent).map_err(map_fs)?);
        let file_identity = content_identity(&reopened)?;
        let abort_body = AbortBody {
            ceremony_id: claims.ceremony_id,
            last_valid_signed_record_digest: claims.last_valid_signed_record_digest,
            phase: STRUCTURAL_ANALYZER_ABORT_PHASE,
            reason_code: claims.abort_reason_code(),
            evidence_file: file_identity.clone(),
        };
        let signature_message =
            ceremony_record_signature_message(&CeremonyRecordBody::Abort(abort_body.clone()))?;
        Ok(ProductionDoryV3StructuralErrorEvidenceFileReport {
            output: output_path.to_path_buf(),
            durability,
            evidence: AuthenticatedProductionDoryV3StructuralErrorEvidence {
                claims: reopened_claims,
                file_identity,
            },
            prepared_abort: PreparedProductionDoryV3StructuralAnalyzerAbort {
                body: abort_body,
                signature_message,
            },
        })
    })();
    finish_pending_output(output, &parent, completion)
}

fn finish_pending_output<T>(
    mut output: PendingOutput,
    parent: &TrustedCeremonyParent,
    completion: Result<T, ProductionDoryV3StructuralEvidenceError>,
) -> Result<T, ProductionDoryV3StructuralEvidenceError> {
    match completion {
        Ok(value) => match output.confirm(parent) {
            Ok(()) => Ok(value),
            Err(original) => {
                let original = map_fs(original);
                cleanup_pending_output(&mut output, parent, original)
            }
        },
        Err(original) => cleanup_pending_output(&mut output, parent, original),
    }
}

fn cleanup_pending_output<T>(
    output: &mut PendingOutput,
    parent: &TrustedCeremonyParent,
    original: ProductionDoryV3StructuralEvidenceError,
) -> Result<T, ProductionDoryV3StructuralEvidenceError> {
    match output.remove_explicit(parent) {
        Ok(()) => Err(original),
        Err(cleanup) => Err(ProductionDoryV3StructuralEvidenceError::OutputCleanup {
            original: original.to_string(),
            cleanup: cleanup.to_string(),
        }),
    }
}

fn authenticate_evidence_file(
    path: &Path,
) -> Result<
    (
        ProductionDoryV3StructuralErrorEvidenceClaims,
        TranscriptFileIdentity,
    ),
    ProductionDoryV3StructuralEvidenceError,
> {
    let parent = TrustedCeremonyParent::for_artifact(path).map_err(map_fs)?;
    let mut input = AuthenticatedInput::open(&parent, path, None).map_err(map_fs)?;
    let initial = input
        .read_bounded(PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_MAX_BYTES)
        .map_err(map_fs)?;
    let exact_len = u64::try_from(initial.len()).map_err(|_| {
        ProductionDoryV3StructuralEvidenceError::EncodedLength {
            actual: initial.len(),
        }
    })?;
    input.recheck(&parent, Some(exact_len)).map_err(map_fs)?;
    let claims = ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&initial)?;
    let file_identity = content_identity(&initial)?;
    let final_bytes = input
        .read_bounded(PRODUCTION_DORY_V3_STRUCTURAL_ERROR_EVIDENCE_MAX_BYTES)
        .map_err(map_fs)?;
    input.recheck(&parent, Some(exact_len)).map_err(map_fs)?;
    parent.recheck().map_err(map_fs)?;
    if final_bytes != initial {
        return Err(ProductionDoryV3StructuralEvidenceError::EvidenceChanged);
    }
    let final_claims =
        ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&final_bytes)?;
    if final_claims != claims || content_identity(&final_bytes)? != file_identity {
        return Err(ProductionDoryV3StructuralEvidenceError::EvidenceChanged);
    }
    Ok((claims, file_identity))
}

fn require_type5_analyzer_authority(
    transcript: &VerifiedCeremonyTranscript,
    expected_last_signed_record_digest: [u8; 32],
) -> Result<Type5AnalyzerAuthority, ProductionDoryV3StructuralEvidenceError> {
    if transcript.status() != CeremonyTranscriptStatus::RevealSetClosed {
        return Err(
            ProductionDoryV3StructuralEvidenceError::TranscriptAuthority(
                "generation requires an exact anchored type-5 prefix",
            ),
        );
    }
    let records = transcript.records();
    let CeremonyRecordBody::Genesis(genesis) = &records
        .first()
        .ok_or(ProductionDoryV3StructuralEvidenceError::TranscriptAuthority("missing genesis"))?
        .body
    else {
        return Err(
            ProductionDoryV3StructuralEvidenceError::TranscriptAuthority("missing genesis"),
        );
    };
    let last = records.last().ok_or(
        ProductionDoryV3StructuralEvidenceError::TranscriptAuthority("missing type-5 closure"),
    )?;
    if !matches!(last.body, CeremonyRecordBody::RevealSet(_)) {
        return Err(
            ProductionDoryV3StructuralEvidenceError::TranscriptAuthority(
                "prefix does not end at type 5",
            ),
        );
    }
    let actual_last = ceremony_signed_record_digest(last)?;
    if actual_last != expected_last_signed_record_digest {
        return Err(
            ProductionDoryV3StructuralEvidenceError::TranscriptAuthority(
                "type-5 signed-record digest differs from the independent anchor",
            ),
        );
    }
    Ok(authority_from_genesis(
        transcript.ceremony_id(),
        actual_last,
        genesis,
    ))
}

fn require_type7_analyzer_abort(
    transcript: &VerifiedCeremonyTranscript,
    expected_ceremony_id: [u8; 32],
    expected_last_signed_record_digest: [u8; 32],
) -> Result<(Type5AnalyzerAuthority, AbortBody), ProductionDoryV3StructuralEvidenceError> {
    if transcript.status() != CeremonyTranscriptStatus::Aborted
        || transcript.ceremony_id() != expected_ceremony_id
    {
        return Err(
            ProductionDoryV3StructuralEvidenceError::TranscriptAuthority(
                "verification requires an independently anchored aborted transcript",
            ),
        );
    }
    let records = transcript.records();
    if records.len() < 3 {
        return Err(
            ProductionDoryV3StructuralEvidenceError::TranscriptAuthority(
                "analyzer abort must follow type 5",
            ),
        );
    }
    let CeremonyRecordBody::Genesis(genesis) = &records[0].body else {
        return Err(
            ProductionDoryV3StructuralEvidenceError::TranscriptAuthority("missing genesis"),
        );
    };
    let penultimate = &records[records.len() - 2];
    if !matches!(penultimate.body, CeremonyRecordBody::RevealSet(_)) {
        return Err(
            ProductionDoryV3StructuralEvidenceError::TranscriptAuthority(
                "type-7 analyzer abort is not immediately after type 5",
            ),
        );
    }
    let actual_last = ceremony_signed_record_digest(penultimate)?;
    if actual_last != expected_last_signed_record_digest {
        return Err(
            ProductionDoryV3StructuralEvidenceError::TranscriptAuthority(
                "type-5 signed-record digest differs from the independent anchor",
            ),
        );
    }
    let CeremonyRecordBody::Abort(abort) = &records[records.len() - 1].body else {
        return Err(
            ProductionDoryV3StructuralEvidenceError::TranscriptAuthority(
                "missing terminal type-7 abort",
            ),
        );
    };
    if abort.ceremony_id != expected_ceremony_id
        || abort.last_valid_signed_record_digest != actual_last
    {
        return Err(ProductionDoryV3StructuralEvidenceError::EvidenceAnchorMismatch);
    }
    Ok((
        authority_from_genesis(expected_ceremony_id, actual_last, genesis),
        abort.clone(),
    ))
}

fn authority_from_genesis(
    ceremony_id: [u8; 32],
    last_valid_signed_record_digest: [u8; 32],
    genesis: &GenesisBody,
) -> Type5AnalyzerAuthority {
    Type5AnalyzerAuthority {
        ceremony_id,
        last_valid_signed_record_digest,
        analyzer_target_id: genesis.structural_analyzer_target_id,
        analyzer_blake3: genesis.structural_analyzer_blake3,
        analyzer_sha256: genesis.structural_analyzer_sha256,
    }
}

fn verify_claims_against_authority(
    claims: &ProductionDoryV3StructuralErrorEvidenceClaims,
    authority: &Type5AnalyzerAuthority,
    roots: &RootsBinding,
) -> Result<(), ProductionDoryV3StructuralEvidenceError> {
    if claims.ceremony_id != authority.ceremony_id
        || claims.last_valid_signed_record_digest != authority.last_valid_signed_record_digest
        || claims.analyzer_target_id != authority.analyzer_target_id
        || claims.analyzer_blake3 != authority.analyzer_blake3
        || claims.analyzer_sha256 != authority.analyzer_sha256
        || claims.roots_file != roots.file_identity
        || roots.ceremony_id != authority.ceremony_id
    {
        return Err(ProductionDoryV3StructuralEvidenceError::EvidenceAnchorMismatch);
    }
    Ok(())
}

fn verify_authenticated_abort_bindings(
    claims: &ProductionDoryV3StructuralErrorEvidenceClaims,
    file_identity: &TranscriptFileIdentity,
    authority: &Type5AnalyzerAuthority,
    abort: &AbortBody,
    roots: &RootsBinding,
) -> Result<(), ProductionDoryV3StructuralEvidenceError> {
    if abort.evidence_file != *file_identity {
        return Err(ProductionDoryV3StructuralEvidenceError::AbortEvidenceIdentityMismatch);
    }
    verify_claims_against_authority(claims, authority, roots)?;
    if abort.ceremony_id != authority.ceremony_id
        || abort.last_valid_signed_record_digest != authority.last_valid_signed_record_digest
    {
        return Err(ProductionDoryV3StructuralEvidenceError::EvidenceAnchorMismatch);
    }
    if abort.phase != STRUCTURAL_ANALYZER_ABORT_PHASE
        || abort.reason_code != claims.abort_reason_code()
    {
        return Err(ProductionDoryV3StructuralEvidenceError::AbortMetadataMismatch);
    }
    Ok(())
}

impl RootsBinding {
    fn from_verified(roots: &ProductionDoryV3ModelRoots) -> Self {
        let bytes = roots.canonical_bytes();
        Self {
            ceremony_id: roots.ceremony_id().into_bytes(),
            file_identity: content_identity_infallible(&bytes),
        }
    }
}

fn validate_progress(
    opened_payload_bytes: u64,
    payload_prefix_bytes: u64,
    payload_prefix_blake3: [u8; 32],
    payload_prefix_sha256: [u8; 32],
    stage: ProductionDoryV3StructuralEvidenceStage,
    failure_code: ProductionDoryV3StructuralEvidenceFailureCode,
) -> Result<(), ProductionDoryV3StructuralEvidenceError> {
    use ProductionDoryV3StructuralEvidenceFailureCode as Code;
    let zero_byte_attestation = opened_payload_bytes == 0
        && payload_prefix_bytes == 0
        && ((stage == ProductionDoryV3StructuralEvidenceStage::FinalRecheck
            && matches!(
                failure_code,
                Code::FilesystemIdentityOrReplacement
                    | Code::IoFailure
                    | Code::ResourceFailure
                    | Code::OtherFailClosed
            ))
            || (matches!(
                stage,
                ProductionDoryV3StructuralEvidenceStage::FirstAnalysis
                    | ProductionDoryV3StructuralEvidenceStage::SecondAnalysis
            ) && failure_code == Code::EarlyEof));
    if payload_prefix_bytes > EXPECTED_PRODUCTION_PAYLOAD_BYTES.saturating_add(1)
        || (opened_payload_bytes == 0 && payload_prefix_bytes != 0)
        || (opened_payload_bytes != 0 && payload_prefix_bytes > opened_payload_bytes)
        || (opened_payload_bytes == 0
            && stage != ProductionDoryV3StructuralEvidenceStage::InputAuthentication
            && !zero_byte_attestation)
    {
        return Err(ProductionDoryV3StructuralEvidenceError::InvalidProgress);
    }
    if payload_prefix_bytes == 0 {
        let empty = content_identity_infallible(&[]);
        if payload_prefix_blake3 != empty.blake3 || payload_prefix_sha256 != empty.sha256 {
            return Err(ProductionDoryV3StructuralEvidenceError::InvalidEmptyPrefixDigests);
        }
    }
    let code_progress_is_valid = match failure_code {
        Code::PayloadLengthMismatch => {
            opened_payload_bytes != EXPECTED_PRODUCTION_PAYLOAD_BYTES && payload_prefix_bytes == 0
        }
        Code::EarlyEof => {
            opened_payload_bytes == payload_prefix_bytes
                && payload_prefix_bytes < EXPECTED_PRODUCTION_PAYLOAD_BYTES
        }
        Code::TrailingBytes => {
            opened_payload_bytes == EXPECTED_PRODUCTION_PAYLOAD_BYTES + 1
                && payload_prefix_bytes == EXPECTED_PRODUCTION_PAYLOAD_BYTES + 1
        }
        Code::PayloadByteAbove250 => {
            opened_payload_bytes == EXPECTED_PRODUCTION_PAYLOAD_BYTES
                && (1..=EXPECTED_PRODUCTION_PAYLOAD_BYTES).contains(&payload_prefix_bytes)
        }
        Code::RootOrDigestMismatch
        | Code::FatalStructuralComputation
        | Code::StructuralReportEncoding
        | Code::StructuralReportReproductionMismatch => {
            opened_payload_bytes == EXPECTED_PRODUCTION_PAYLOAD_BYTES
                && payload_prefix_bytes == EXPECTED_PRODUCTION_PAYLOAD_BYTES
        }
        Code::GeometryOrToolMismatch => opened_payload_bytes == 0 && payload_prefix_bytes == 0,
        Code::CounterOverflow
        | Code::FilesystemIdentityOrReplacement
        | Code::PermissionDrift
        | Code::IoFailure
        | Code::ResourceFailure
        | Code::OtherFailClosed => true,
    };
    if !code_progress_is_valid {
        return Err(ProductionDoryV3StructuralEvidenceError::InvalidProgress);
    }
    Ok(())
}

fn validate_stage_code(
    stage: ProductionDoryV3StructuralEvidenceStage,
    code: ProductionDoryV3StructuralEvidenceFailureCode,
) -> Result<(), ProductionDoryV3StructuralEvidenceError> {
    use ProductionDoryV3StructuralEvidenceFailureCode as Code;
    use ProductionDoryV3StructuralEvidenceStage as Stage;
    let valid = match stage {
        Stage::InputAuthentication => matches!(
            code,
            Code::PayloadLengthMismatch
                | Code::GeometryOrToolMismatch
                | Code::FilesystemIdentityOrReplacement
                | Code::PermissionDrift
                | Code::IoFailure
                | Code::ResourceFailure
                | Code::OtherFailClosed
        ),
        Stage::FirstAnalysis | Stage::SecondAnalysis => matches!(
            code,
            Code::EarlyEof
                | Code::TrailingBytes
                | Code::RootOrDigestMismatch
                | Code::PayloadByteAbove250
                | Code::CounterOverflow
                | Code::FatalStructuralComputation
                | Code::StructuralReportReproductionMismatch
                | Code::FilesystemIdentityOrReplacement
                | Code::PermissionDrift
                | Code::IoFailure
                | Code::ResourceFailure
                | Code::OtherFailClosed
        ),
        Stage::ReportEncoding => matches!(
            code,
            Code::CounterOverflow
                | Code::StructuralReportEncoding
                | Code::IoFailure
                | Code::ResourceFailure
                | Code::OtherFailClosed
        ),
        Stage::ReportPersistence => matches!(
            code,
            Code::StructuralReportReproductionMismatch
                | Code::FilesystemIdentityOrReplacement
                | Code::PermissionDrift
                | Code::IoFailure
                | Code::ResourceFailure
                | Code::OtherFailClosed
        ),
        Stage::FinalRecheck => matches!(
            code,
            Code::StructuralReportReproductionMismatch
                | Code::FilesystemIdentityOrReplacement
                | Code::PermissionDrift
                | Code::IoFailure
                | Code::OtherFailClosed
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(ProductionDoryV3StructuralEvidenceError::StageCodeMismatch)
    }
}

fn encode_file_identity(bytes: &mut Vec<u8>, identity: &TranscriptFileIdentity) {
    bytes.extend_from_slice(&identity.bytes.to_le_bytes());
    bytes.extend_from_slice(&identity.blake3);
    bytes.extend_from_slice(&identity.sha256);
}

fn encode_optional_file_identity(bytes: &mut Vec<u8>, identity: Option<&TranscriptFileIdentity>) {
    if let Some(identity) = identity {
        encode_file_identity(bytes, identity);
    } else {
        encode_file_identity(
            bytes,
            &TranscriptFileIdentity {
                bytes: 0,
                blake3: [0; 32],
                sha256: [0; 32],
            },
        );
    }
}

fn decode_file_identity(
    decoder: &mut Decoder<'_>,
) -> Result<TranscriptFileIdentity, ProductionDoryV3StructuralEvidenceError> {
    Ok(TranscriptFileIdentity {
        bytes: decoder.u64()?,
        blake3: decoder.take::<32>()?,
        sha256: decoder.take::<32>()?,
    })
}

fn decode_optional_file_identity(
    decoder: &mut Decoder<'_>,
) -> Result<Option<TranscriptFileIdentity>, ProductionDoryV3StructuralEvidenceError> {
    let identity = decode_file_identity(decoder)?;
    let all_zero = identity.bytes == 0 && identity.blake3 == [0; 32] && identity.sha256 == [0; 32];
    if all_zero {
        return Ok(None);
    }
    if identity.bytes != PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES as u64 {
        return Err(ProductionDoryV3StructuralEvidenceError::InvalidSubjectFile);
    }
    Ok(Some(identity))
}

fn content_identity(
    bytes: &[u8],
) -> Result<TranscriptFileIdentity, ProductionDoryV3StructuralEvidenceError> {
    let length = u64::try_from(bytes.len()).map_err(|_| {
        ProductionDoryV3StructuralEvidenceError::EncodedLength {
            actual: bytes.len(),
        }
    })?;
    let mut sha256 = Sha256::new();
    sha256.update(bytes);
    Ok(TranscriptFileIdentity {
        bytes: length,
        blake3: *blake3::hash(bytes).as_bytes(),
        sha256: sha256.finalize().into(),
    })
}

fn content_identity_infallible(bytes: &[u8]) -> TranscriptFileIdentity {
    content_identity(bytes).expect("bounded ceremony artifacts fit u64")
}

fn map_fs(error: CeremonyFsError) -> ProductionDoryV3StructuralEvidenceError {
    ProductionDoryV3StructuralEvidenceError::Filesystem(error.to_string())
}

fn map_durability(outcome: ParentSyncOutcome) -> ProductionDoryV3StructuralErrorEvidenceDurability {
    match outcome {
        ParentSyncOutcome::Synced => {
            ProductionDoryV3StructuralErrorEvidenceDurability::FileAndParentDirectorySynced
        }
        #[cfg(windows)]
        ParentSyncOutcome::WindowsAccessDenied => {
            ProductionDoryV3StructuralErrorEvidenceDurability::FileSyncedParentDirectorySyncAccessDeniedOnWindows
        }
        #[cfg(windows)]
        ParentSyncOutcome::WindowsUnsupported => {
            ProductionDoryV3StructuralErrorEvidenceDurability::FileSyncedParentDirectorySyncUnsupportedOnWindows
        }
        #[cfg(not(any(unix, windows)))]
        ParentSyncOutcome::PlatformUnsupported => {
            ProductionDoryV3StructuralErrorEvidenceDurability::FileSyncedParentDirectorySyncUnsupportedOnPlatform
        }
    }
}

fn map_abort_stage_durability(
    outcome: ParentSyncOutcome,
) -> ProductionDoryV3StructuralAbortStageDurability {
    match outcome {
        ParentSyncOutcome::Synced => {
            ProductionDoryV3StructuralAbortStageDurability::FileAndParentDirectorySynced
        }
        #[cfg(windows)]
        ParentSyncOutcome::WindowsAccessDenied => {
            ProductionDoryV3StructuralAbortStageDurability::FileSyncedParentDirectorySyncAccessDeniedOnWindows
        }
        #[cfg(windows)]
        ParentSyncOutcome::WindowsUnsupported => {
            ProductionDoryV3StructuralAbortStageDurability::FileSyncedParentDirectorySyncUnsupportedOnWindows
        }
        #[cfg(not(any(unix, windows)))]
        ParentSyncOutcome::PlatformUnsupported => {
            ProductionDoryV3StructuralAbortStageDurability::FileSyncedParentDirectorySyncUnsupportedOnPlatform
        }
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

    fn take<const N: usize>(&mut self) -> Result<[u8; N], ProductionDoryV3StructuralEvidenceError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(ProductionDoryV3StructuralEvidenceError::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProductionDoryV3StructuralEvidenceError::Truncated)?;
        self.offset = end;
        slice
            .try_into()
            .map_err(|_| ProductionDoryV3StructuralEvidenceError::Truncated)
    }

    fn u16(&mut self) -> Result<u16, ProductionDoryV3StructuralEvidenceError> {
        Ok(u16::from_le_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, ProductionDoryV3StructuralEvidenceError> {
        Ok(u64::from_le_bytes(self.take()?))
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::{Seek, SeekFrom, Write},
        time::{SystemTime, UNIX_EPOCH},
    };

    use k256::schnorr::{Signature, SigningKey};

    use super::*;
    use crate::dory_v3_model_ceremony_transcript::{
        CEREMONY_PROTOCOL_VERSION, CEREMONY_TRANSCRIPT_HEADER_BYTES, CEREMONY_TRANSCRIPT_MAGIC,
        CommitmentSetBody, ContributionCommitmentBody, ContributionRevealBody, IndexedRecordDigest,
        PRODUCTION_BANK_FORMAT_VERSION, PRODUCTION_BANK_HEADER_BYTES, PRODUCTION_BANKS,
        PRODUCTION_BASE_INPUT_BYTES, PRODUCTION_BATCH, PRODUCTION_BYTES_PER_LAYER,
        PRODUCTION_DIMENSION, PRODUCTION_LAYERS, PRODUCTION_LAYERS_PER_BANK,
        PRODUCTION_MAX_MODEL_BYTE, PRODUCTION_MODEL_VERSION, PRODUCTION_PADDED_VARIABLES,
        PRODUCTION_PAYLOAD_BYTES, RecordSignature, ReferenceBinary, RevealSetBody, RosterMember,
        SignedCeremonyRecord, SignerClass, ceremony_record_content_digest,
        encode_and_verify_ceremony_transcript, parse_and_verify_ceremony_transcript,
        parse_and_verify_reveal_set_prefix,
    };

    const TEST_PRODUCTION_SUITE_DIGEST: [u8; 32] = [
        0x6c, 0x09, 0x50, 0xd4, 0xb5, 0xdc, 0xff, 0xef, 0x9f, 0x32, 0x96, 0xf9, 0xc0, 0x71, 0x8a,
        0x8d, 0x51, 0x24, 0x87, 0x77, 0x19, 0xb3, 0xaf, 0x76, 0xb2, 0xf6, 0x8b, 0x3f, 0xcb, 0x64,
        0x76, 0x4a,
    ];
    const TEST_DORY_SETUP_IDENTITY: [u8; 32] = [
        0x75, 0xfd, 0x3d, 0xac, 0xdd, 0xba, 0x30, 0x68, 0x2d, 0x1e, 0xab, 0xd5, 0xd8, 0xd2, 0x92,
        0x44, 0x66, 0xd7, 0x21, 0x4b, 0x01, 0x1a, 0x7e, 0xcc, 0x48, 0xba, 0x27, 0x82, 0x1c, 0xbb,
        0xf6, 0x12,
    ];

    fn identity(byte: u8, bytes: u64) -> TranscriptFileIdentity {
        TranscriptFileIdentity {
            bytes,
            blake3: [byte; 32],
            sha256: [byte.wrapping_add(1); 32],
        }
    }

    fn sample_claims(detail: &[u8]) -> ProductionDoryV3StructuralErrorEvidenceClaims {
        let prefix = content_identity_infallible(b"prefix");
        ProductionDoryV3StructuralErrorEvidenceClaims {
            ceremony_id: [1; 32],
            last_valid_signed_record_digest: [2; 32],
            analyzer_target_id: 1,
            analyzer_blake3: [3; 32],
            analyzer_sha256: [4; 32],
            roots_file: identity(5, PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES as u64),
            expected_payload_bytes: EXPECTED_PRODUCTION_PAYLOAD_BYTES,
            opened_payload_bytes: EXPECTED_PRODUCTION_PAYLOAD_BYTES,
            payload_prefix_bytes: 6,
            payload_prefix_blake3: prefix.blake3,
            payload_prefix_sha256: prefix.sha256,
            subject_file: None,
            operation: ProductionDoryV3StructuralEvidenceOperation::GenerateReport,
            stage: ProductionDoryV3StructuralEvidenceStage::FirstAnalysis,
            failure_class: ProductionDoryV3StructuralEvidenceFailureClass::ForbiddenByte,
            failure_code: ProductionDoryV3StructuralEvidenceFailureCode::PayloadByteAbove250,
            detail: detail.to_vec(),
        }
    }

    fn length_mismatch_claims(
        opened_payload_bytes: u64,
    ) -> ProductionDoryV3StructuralErrorEvidenceClaims {
        let mut claims = sample_claims(b"payload length mismatch");
        let empty = content_identity_infallible(&[]);
        claims.opened_payload_bytes = opened_payload_bytes;
        claims.payload_prefix_bytes = 0;
        claims.payload_prefix_blake3 = empty.blake3;
        claims.payload_prefix_sha256 = empty.sha256;
        claims.stage = ProductionDoryV3StructuralEvidenceStage::InputAuthentication;
        claims.failure_class = ProductionDoryV3StructuralEvidenceFailureClass::FileLength;
        claims.failure_code = ProductionDoryV3StructuralEvidenceFailureCode::PayloadLengthMismatch;
        ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&claims.canonical_bytes())
            .unwrap()
    }

    fn roots_artifact(ceremony_id: [u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES);
        bytes.extend_from_slice(b"CMFDMR01");
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&ceremony_id);
        bytes.extend_from_slice(&EXPECTED_PRODUCTION_PAYLOAD_BYTES.to_le_bytes());
        bytes.extend_from_slice(&[7; 32]);
        bytes.extend_from_slice(&[8; 32]);
        bytes.extend_from_slice(&[9; 32]);
        bytes.extend_from_slice(&crate::dory_v3_suite::DORY_V3_LAYERS.to_le_bytes());
        let mut aggregate =
            crate::model_bank::start_layer_aggregate(crate::dory_v3_suite::DORY_V3_LAYERS);
        for index in 0..crate::dory_v3_suite::DORY_V3_LAYERS {
            let root = blake3::hash(&index.to_le_bytes());
            bytes.extend_from_slice(&index.to_le_bytes());
            bytes.extend_from_slice(root.as_bytes());
            crate::model_bank::add_layer_root(&mut aggregate, index, root);
        }
        bytes.extend_from_slice(aggregate.finalize().as_bytes());
        assert_eq!(bytes.len(), PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES);
        bytes
    }

    #[test]
    fn retained_payload_binding_covers_stable_lengths_prefix_and_forbidden_byte() {
        let directory = test_directory("failed-payload");
        fs::create_dir(&directory).unwrap();
        crate::dory_v3_model_ceremony_fs::prepare_test_parent(&directory).unwrap();
        let payload = directory.join("failed.bin");

        fs::write(&payload, [1_u8, 2, 3]).unwrap();
        authenticate_failed_payload(&payload, &length_mismatch_claims(3)).unwrap();
        let wrong_length = length_mismatch_claims(4);
        assert!(authenticate_failed_payload(&payload, &wrong_length).is_err());

        let mut file = OpenOptions::new().write(true).open(&payload).unwrap();
        file.set_len(EXPECTED_PRODUCTION_PAYLOAD_BYTES).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&[1, 2, 251, 4]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut forbidden = sample_claims(b"forbidden byte");
        let observed = content_identity_infallible(&[1, 2, 251, 4]);
        forbidden.payload_prefix_bytes = 4;
        forbidden.payload_prefix_blake3 = observed.blake3;
        forbidden.payload_prefix_sha256 = observed.sha256;
        let forbidden = ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(
            &forbidden.canonical_bytes(),
        )
        .unwrap();
        authenticate_failed_payload(&payload, &forbidden).unwrap();

        let mut wrong_digest = forbidden.clone();
        wrong_digest.payload_prefix_blake3[0] ^= 1;
        assert!(authenticate_failed_payload(&payload, &wrong_digest).is_err());

        let mut file = OpenOptions::new().write(true).open(&payload).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&[1, 2, 3, 4]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let safe = content_identity_infallible(&[1, 2, 3, 4]);
        let mut no_forbidden = forbidden;
        no_forbidden.payload_prefix_blake3 = safe.blake3;
        no_forbidden.payload_prefix_sha256 = safe.sha256;
        assert!(authenticate_failed_payload(&payload, &no_forbidden).is_err());

        fs::remove_file(payload).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn zero_byte_early_eof_is_a_canonical_attestation() {
        let empty = content_identity_infallible(&[]);
        let mut claims = sample_claims(b"payload ended before byte zero");
        claims.opened_payload_bytes = 0;
        claims.payload_prefix_bytes = 0;
        claims.payload_prefix_blake3 = empty.blake3;
        claims.payload_prefix_sha256 = empty.sha256;
        claims.stage = ProductionDoryV3StructuralEvidenceStage::FirstAnalysis;
        claims.failure_class = ProductionDoryV3StructuralEvidenceFailureClass::FileLength;
        claims.failure_code = ProductionDoryV3StructuralEvidenceFailureCode::EarlyEof;
        let claims = ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(
            &claims.canonical_bytes(),
        )
        .unwrap();

        assert_eq!(
            authenticate_failed_payload(Path::new("unused-for-zero-byte-attestation"), &claims)
                .unwrap(),
            ProductionDoryV3StructuralAbortSubjectBinding::AttestationOnly
        );
    }

    #[test]
    fn transient_replacement_downgrades_to_attestation_but_deterministic_failure_does_not() {
        let directory = test_directory("transient-replacement");
        fs::create_dir(&directory).unwrap();
        crate::dory_v3_model_ceremony_fs::prepare_test_parent(&directory).unwrap();
        let payload = directory.join("failed.bin");
        fs::write(&payload, b"short").unwrap();

        let observed = b"prefix observed before replacement";
        let observed_identity = content_identity_infallible(observed);
        let mut transient = sample_claims(b"payload identity changed");
        transient.opened_payload_bytes = observed.len() as u64;
        transient.payload_prefix_bytes = observed.len() as u64;
        transient.payload_prefix_blake3 = observed_identity.blake3;
        transient.payload_prefix_sha256 = observed_identity.sha256;
        transient.stage = ProductionDoryV3StructuralEvidenceStage::FinalRecheck;
        transient.failure_class =
            ProductionDoryV3StructuralEvidenceFailureClass::FilesystemIdentity;
        transient.failure_code =
            ProductionDoryV3StructuralEvidenceFailureCode::FilesystemIdentityOrReplacement;
        let transient = ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(
            &transient.canonical_bytes(),
        )
        .unwrap();
        assert_eq!(
            authenticate_failed_payload(&payload, &transient).unwrap(),
            ProductionDoryV3StructuralAbortSubjectBinding::AttestationOnly
        );

        let mut deterministic = transient;
        deterministic.stage = ProductionDoryV3StructuralEvidenceStage::FirstAnalysis;
        deterministic.failure_class = ProductionDoryV3StructuralEvidenceFailureClass::FileLength;
        deterministic.failure_code = ProductionDoryV3StructuralEvidenceFailureCode::EarlyEof;
        let deterministic = ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(
            &deterministic.canonical_bytes(),
        )
        .unwrap();
        assert!(matches!(
            authenticate_failed_payload(&payload, &deterministic),
            Err(ProductionDoryV3StructuralEvidenceError::FailedPayloadBinding(_))
        ));

        fs::remove_file(payload).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn roots_artifact_authentication_is_exact_and_ceremony_bound() {
        let directory = test_directory("roots");
        fs::create_dir(&directory).unwrap();
        crate::dory_v3_model_ceremony_fs::prepare_test_parent(&directory).unwrap();
        let path = directory.join("roots.cmfdr");
        let ceremony_id = [42; 32];
        let bytes = roots_artifact(ceremony_id);
        fs::write(&path, &bytes).unwrap();

        let (claims, binding) = authenticate_roots_artifact(&path, ceremony_id).unwrap();
        assert_eq!(claims.ceremony_id().into_bytes(), ceremony_id);
        assert_eq!(binding.file_identity, content_identity_infallible(&bytes));
        assert!(authenticate_roots_artifact(&path, [41; 32]).is_err());

        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn generated_abort_is_signed_and_verified_end_to_end() {
        let (mut records, operators) = reveal_set_prefix();
        let prefix_bytes = encode_transcript_prefix(&records);
        let ceremony_id = ceremony_record_content_digest(&records[0].body).unwrap();
        let last = ceremony_signed_record_digest(records.last().unwrap()).unwrap();
        let transcript = parse_and_verify_reveal_set_prefix(&prefix_bytes, ceremony_id).unwrap();

        let directory = test_directory("abort-round-trip");
        fs::create_dir(&directory).unwrap();
        crate::dory_v3_model_ceremony_fs::prepare_test_parent(&directory).unwrap();
        let payload = directory.join("short-payload.bin");
        let roots = directory.join("roots.cmfdr");
        let structure = directory.join("structure.cmfdsr");
        let evidence = directory.join("failure.cmfdse");
        let signed_abort_record = directory.join("abort-record.cmfdrec");
        let aborted_transcript = directory.join("aborted.cmfd");
        let rejected_record = directory.join("rejected-abort-record.cmfdrec");
        fs::write(&payload, [1_u8, 2, 3]).unwrap();
        fs::write(&roots, roots_artifact(ceremony_id)).unwrap();

        let report = match run_anchored_with_verified_binary(
            &transcript,
            last,
            &payload,
            &roots,
            &structure,
            &evidence,
        )
        .unwrap()
        {
            ProductionDoryV3StructuralAnalyzerOutcome::AbortEvidence(report) => report,
            ProductionDoryV3StructuralAnalyzerOutcome::Report(_) => {
                panic!("a short payload must not produce a structural report")
            }
        };
        assert_eq!(
            report.evidence().claims().failure_code(),
            ProductionDoryV3StructuralEvidenceFailureCode::PayloadLengthMismatch
        );
        let reprepared = prepare_anchored_production_dory_v3_structural_abort_from_files(
            &prefix_bytes,
            ceremony_id,
            last,
            &payload,
            &roots,
            &evidence,
        )
        .unwrap();
        assert_eq!(reprepared.prepared_abort(), report.prepared_abort());
        assert_eq!(reprepared.evidence(), report.evidence());
        assert_eq!(
            reprepared.subject_binding(),
            ProductionDoryV3StructuralAbortSubjectBinding::RetainedPayloadObservationVerified
        );
        let signed_abort = sign_record(
            CeremonyRecordBody::Abort(report.prepared_abort().body().clone()),
            &[
                (SignerClass::Operator, 0, &operators[0]),
                (SignerClass::Operator, 1, &operators[1]),
            ],
        );
        let mut bad_signatures = signed_abort.signatures.clone();
        bad_signatures[0].signature[0] ^= 1;
        assert!(
            stage_anchored_production_dory_v3_structural_abort_record(
                &prefix_bytes,
                ceremony_id,
                last,
                &payload,
                &roots,
                &evidence,
                bad_signatures,
                &rejected_record,
            )
            .is_err()
        );
        assert!(!rejected_record.exists());
        let mut wrong_message_body = report.prepared_abort().body().clone();
        wrong_message_body.reason_code = wrong_message_body.reason_code.saturating_add(1);
        let wrong_message_record = sign_record(
            CeremonyRecordBody::Abort(wrong_message_body),
            &[
                (SignerClass::Operator, 0, &operators[0]),
                (SignerClass::Operator, 1, &operators[1]),
            ],
        );
        assert!(
            stage_anchored_production_dory_v3_structural_abort_record(
                &prefix_bytes,
                ceremony_id,
                last,
                &payload,
                &roots,
                &evidence,
                wrong_message_record.signatures,
                &rejected_record,
            )
            .is_err()
        );
        assert!(!rejected_record.exists());
        assert!(
            stage_anchored_production_dory_v3_structural_abort_record(
                &prefix_bytes,
                ceremony_id,
                last,
                &payload,
                &roots,
                &evidence,
                Vec::new(),
                &rejected_record,
            )
            .is_err()
        );
        assert!(!rejected_record.exists());
        assert!(
            stage_anchored_production_dory_v3_structural_abort_record(
                &prefix_bytes,
                ceremony_id,
                last,
                &payload,
                &roots,
                &evidence,
                vec![
                    signed_abort.signatures[0].clone(),
                    signed_abort.signatures[0].clone(),
                ],
                &rejected_record,
            )
            .is_err()
        );
        assert!(!rejected_record.exists());
        let mut out_of_roster = signed_abort.signatures.clone();
        out_of_roster[0].signer_index = u16::MAX;
        assert!(
            stage_anchored_production_dory_v3_structural_abort_record(
                &prefix_bytes,
                ceremony_id,
                last,
                &payload,
                &roots,
                &evidence,
                out_of_roster,
                &rejected_record,
            )
            .is_err()
        );
        assert!(!rejected_record.exists());

        let mut reversed_signatures = signed_abort.signatures.clone();
        reversed_signatures.reverse();
        let record_report = stage_anchored_production_dory_v3_structural_abort_record(
            &prefix_bytes,
            ceremony_id,
            last,
            &payload,
            &roots,
            &evidence,
            reversed_signatures,
            &signed_abort_record,
        )
        .unwrap();
        assert_eq!(record_report.output(), signed_abort_record);
        assert_eq!(record_report.signer_count(), 2);
        assert_eq!(
            record_report.signature_message(),
            report.prepared_abort().signature_message()
        );
        assert_eq!(
            record_report.record_content_digest(),
            ceremony_record_content_digest(&signed_abort.body).unwrap()
        );
        assert_eq!(
            record_report.signed_record_digest(),
            ceremony_signed_record_digest(&signed_abort).unwrap()
        );
        assert_eq!(
            record_report.subject_binding(),
            ProductionDoryV3StructuralAbortSubjectBinding::RetainedPayloadObservationVerified
        );
        let record_bytes = fs::read(&signed_abort_record).unwrap();
        assert_eq!(record_bytes, encode_ceremony_record(&signed_abort).unwrap());
        assert_eq!(
            record_report.record_file(),
            &content_identity_infallible(&record_bytes)
        );
        assert!(
            stage_anchored_production_dory_v3_structural_abort_record(
                &prefix_bytes,
                ceremony_id,
                last,
                &payload,
                &roots,
                &evidence,
                signed_abort.signatures.clone(),
                &signed_abort_record,
            )
            .is_err()
        );
        assert_eq!(fs::read(&signed_abort_record).unwrap(), record_bytes);

        let transcript_report = stage_anchored_production_dory_v3_structural_abort_transcript(
            &prefix_bytes,
            ceremony_id,
            last,
            &payload,
            &roots,
            &evidence,
            &signed_abort_record,
            &aborted_transcript,
        )
        .unwrap();
        assert_eq!(transcript_report.output(), aborted_transcript);
        assert_eq!(transcript_report.record_file(), record_report.record_file());
        assert_eq!(
            transcript_report.subject_binding(),
            ProductionDoryV3StructuralAbortSubjectBinding::RetainedPayloadObservationVerified
        );
        records.push(signed_abort);
        let aborted = encode_and_verify_ceremony_transcript(&records).unwrap();
        assert_eq!(fs::read(&aborted_transcript).unwrap(), aborted);
        assert!(
            stage_anchored_production_dory_v3_structural_abort_transcript(
                &prefix_bytes,
                ceremony_id,
                last,
                &payload,
                &roots,
                &evidence,
                &signed_abort_record,
                &aborted_transcript,
            )
            .is_err()
        );
        assert_eq!(fs::read(&aborted_transcript).unwrap(), aborted);
        assert_eq!(
            transcript_report.transcript_file(),
            &content_identity_infallible(&aborted)
        );
        assert_eq!(
            transcript_report.transcript_derive_key_digest(),
            parse_and_verify_ceremony_transcript(&aborted)
                .unwrap()
                .transcript_derive_key_digest()
        );
        let verified = verify_anchored_production_dory_v3_structural_abort(
            &aborted,
            ceremony_id,
            last,
            &payload,
            &roots,
            &evidence,
        )
        .unwrap();
        assert_eq!(
            verified.subject_binding(),
            ProductionDoryV3StructuralAbortSubjectBinding::RetainedPayloadObservationVerified
        );
        assert_eq!(verified.evidence(), report.evidence());

        fs::remove_file(payload).unwrap();
        fs::remove_file(roots).unwrap();
        fs::remove_file(evidence).unwrap();
        fs::remove_file(signed_abort_record).unwrap();
        fs::remove_file(aborted_transcript).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn abort_verifier_rejects_transcript_before_touching_artifact_paths() {
        let missing = Path::new("this-relative-path-is-intentionally-invalid");
        assert!(matches!(
            verify_anchored_production_dory_v3_structural_abort(
                b"not a transcript",
                [1; 32],
                [2; 32],
                missing,
                missing,
                missing,
            ),
            Err(ProductionDoryV3StructuralEvidenceError::Transcript(_))
        ));
    }

    #[test]
    fn post_read_length_drift_maps_to_final_recheck_without_impossible_progress() {
        let error = ProductionDoryV3ModelStructureError::PayloadLength {
            expected: EXPECTED_PRODUCTION_PAYLOAD_BYTES,
            actual: 2,
        };
        let observed = 4;
        assert_eq!(opened_payload_bytes(&error, 1, observed), observed);
        let failure = map_structural_failure(&error, 1);
        assert_eq!(
            failure.stage,
            ProductionDoryV3StructuralEvidenceStage::FinalRecheck
        );
        assert_eq!(
            failure.code,
            ProductionDoryV3StructuralEvidenceFailureCode::FilesystemIdentityOrReplacement
        );

        assert_eq!(opened_payload_bytes(&error, 1, 0), 0);
        let empty = content_identity_infallible(&[]);
        let mut zero = sample_claims(b"payload length changed after analysis");
        zero.opened_payload_bytes = 0;
        zero.payload_prefix_bytes = 0;
        zero.payload_prefix_blake3 = empty.blake3;
        zero.payload_prefix_sha256 = empty.sha256;
        zero.stage = failure.stage;
        zero.failure_class = failure.code.failure_class();
        zero.failure_code = failure.code;
        assert!(
            ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(
                &zero.canonical_bytes()
            )
            .is_ok()
        );
    }

    #[test]
    fn codec_has_exact_384_and_448_byte_boundaries_and_round_trips() {
        let minimum = sample_claims(b"");
        let minimum_bytes = minimum.canonical_bytes();
        assert_eq!(minimum_bytes.len(), 384);
        assert_eq!(&minimum_bytes[..8], b"CMFDSE01");
        assert_eq!(
            ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&minimum_bytes)
                .unwrap(),
            minimum
        );

        let maximum = sample_claims(&[b'X'; 64]);
        let maximum_bytes = maximum.canonical_bytes();
        assert_eq!(maximum_bytes.len(), 448);
        assert_eq!(
            u16::from_le_bytes(maximum_bytes[380..382].try_into().unwrap()),
            64
        );
        assert_eq!(
            ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&maximum_bytes)
                .unwrap(),
            maximum
        );
    }

    #[test]
    fn codec_rejects_every_length_boundary_and_fixed_field_mutation() {
        let bytes = sample_claims(b"failure").canonical_bytes();
        for length in [0, 383, 449] {
            let candidate = vec![0_u8; length];
            assert!(matches!(
                ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&candidate),
                Err(ProductionDoryV3StructuralEvidenceError::EncodedLength { .. })
            ));
        }
        for length in 384..bytes.len() {
            assert!(
                ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&bytes[..length])
                    .is_err()
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(b'X');
        assert!(
            ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&trailing).is_err()
        );

        for (offset, replacement) in [
            (0, 0_u8),
            (8, 2),
            (10, 0),
            (42, 0),
            (74, 3),
            (140, 0),
            (212, 1),
            (372, 9),
            (374, 9),
            (376, 9),
            (378, 0),
            (382, 1),
        ] {
            let mut changed = bytes.clone();
            if offset == 10 || offset == 42 {
                changed[offset..offset + 32].fill(0);
            } else {
                changed[offset] = replacement;
            }
            assert!(
                ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&changed)
                    .is_err(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn codec_rejects_noncanonical_subject_progress_detail_and_class() {
        let mut bytes = sample_claims(b"failure").canonical_bytes();
        bytes[300] = 1;
        assert!(matches!(
            ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&bytes),
            Err(ProductionDoryV3StructuralEvidenceError::InvalidSubjectFile)
        ));

        let mut generation_with_subject = sample_claims(b"failure");
        generation_with_subject.subject_file = Some(identity(
            9,
            PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES as u64,
        ));
        assert!(matches!(
            ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(
                &generation_with_subject.canonical_bytes()
            ),
            Err(ProductionDoryV3StructuralEvidenceError::UnexpectedSubjectFile)
        ));

        let mut validation_without_subject = sample_claims(b"failure");
        validation_without_subject.operation =
            ProductionDoryV3StructuralEvidenceOperation::ValidateReport;
        assert!(matches!(
            ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(
                &validation_without_subject.canonical_bytes()
            ),
            Err(ProductionDoryV3StructuralEvidenceError::MissingSubjectFile)
        ));

        let mut bytes = sample_claims(b"failure").canonical_bytes();
        bytes[376..378].copy_from_slice(
            &(ProductionDoryV3StructuralEvidenceFailureClass::FileLength as u16).to_le_bytes(),
        );
        assert!(matches!(
            ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&bytes),
            Err(ProductionDoryV3StructuralEvidenceError::FailureClassMismatch)
        ));

        let mut bytes = sample_claims(b"failure").canonical_bytes();
        bytes[384] = b'\n';
        assert!(matches!(
            ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(&bytes),
            Err(ProductionDoryV3StructuralEvidenceError::NonPrintableDetail)
        ));

        let mut empty = sample_claims(b"");
        empty.opened_payload_bytes = 0;
        empty.payload_prefix_bytes = 0;
        empty.payload_prefix_blake3 = [0; 32];
        empty.payload_prefix_sha256 = [0; 32];
        empty.stage = ProductionDoryV3StructuralEvidenceStage::InputAuthentication;
        empty.failure_class = ProductionDoryV3StructuralEvidenceFailureClass::FileLength;
        empty.failure_code = ProductionDoryV3StructuralEvidenceFailureCode::PayloadLengthMismatch;
        assert!(matches!(
            ProductionDoryV3StructuralErrorEvidenceClaims::parse_and_validate(
                &empty.canonical_bytes()
            ),
            Err(ProductionDoryV3StructuralEvidenceError::InvalidEmptyPrefixDigests)
        ));
    }

    fn file(byte: u8) -> TranscriptFileIdentity {
        identity(byte, u64::from(byte) + 1)
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
            production_suite_digest: TEST_PRODUCTION_SUITE_DIGEST,
            dory_setup_identity: TEST_DORY_SETUP_IDENTITY,
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

    fn reveal_set_prefix() -> (Vec<SignedCeremonyRecord>, Vec<SigningKey>) {
        let operators = keys(3, 1);
        let reproducers = keys(2, 20);
        let all: Vec<_> = operators
            .iter()
            .enumerate()
            .map(|(index, key)| (SignerClass::Operator, index as u16, key))
            .chain(
                reproducers
                    .iter()
                    .enumerate()
                    .map(|(index, key)| (SignerClass::Reproducer, index as u16, key)),
            )
            .collect();
        let operator_signers: Vec<_> = all
            .iter()
            .copied()
            .filter(|(class, _, _)| *class == SignerClass::Operator)
            .collect();
        let genesis = sign_record(
            CeremonyRecordBody::Genesis(Box::new(genesis(&operators, &reproducers))),
            &all,
        );
        let ceremony_id = ceremony_record_content_digest(&genesis.body).unwrap();
        let genesis_digest = ceremony_signed_record_digest(&genesis).unwrap();
        let mut records = vec![genesis];
        let mut commitments = Vec::new();
        let mut bodies = Vec::new();
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
            bodies.push(body);
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
            let body = &bodies[index];
            let record = sign_record(
                CeremonyRecordBody::ContributionReveal(ContributionRevealBody {
                    ceremony_id,
                    operator_index: index as u16,
                    contribution_commitment_signed_record_digest: commitments[index]
                        .signed_record_digest,
                    contribution_bytes: body.contribution_bytes,
                    contribution_blake3: body.contribution_blake3,
                    contribution_sha256: body.contribution_sha256,
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
        records.push(sign_record(
            CeremonyRecordBody::RevealSet(RevealSetBody {
                ceremony_id,
                commitment_set_signed_record_digest: commitment_set_digest,
                reveals,
            }),
            &operator_signers,
        ));
        (records, operators)
    }

    #[test]
    fn only_exact_anchored_type5_prefix_mints_generation_authority() {
        let (records, operators) = reveal_set_prefix();
        let bytes = encode_transcript_prefix(&records);
        let ceremony_id = ceremony_record_content_digest(&records[0].body).unwrap();
        let last = ceremony_signed_record_digest(records.last().unwrap()).unwrap();
        let verified = parse_and_verify_reveal_set_prefix(&bytes, ceremony_id).unwrap();
        let authority = require_type5_analyzer_authority(&verified, last).unwrap();
        assert_eq!(authority.ceremony_id, ceremony_id);
        assert_eq!(authority.last_valid_signed_record_digest, last);
        assert_eq!(authority.analyzer_blake3, [15; 32]);

        assert!(require_type5_analyzer_authority(&verified, [99; 32]).is_err());
        assert!(parse_and_verify_reveal_set_prefix(&bytes, [98; 32]).is_err());

        let evidence_file =
            content_identity_infallible(&sample_claims(b"failure").canonical_bytes());
        let mut aborted = records;
        aborted.push(sign_record(
            CeremonyRecordBody::Abort(AbortBody {
                ceremony_id,
                last_valid_signed_record_digest: last,
                phase: STRUCTURAL_ANALYZER_ABORT_PHASE,
                reason_code: 6,
                evidence_file,
            }),
            &[(SignerClass::Operator, 0, &operators[0])],
        ));
        let aborted_bytes = encode_and_verify_ceremony_transcript(&aborted).unwrap();
        let inspected = parse_and_verify_ceremony_transcript(&aborted_bytes).unwrap();
        assert!(require_type5_analyzer_authority(&inspected, last).is_err());
    }

    #[test]
    fn type7_authority_requires_independent_anchors_and_immediate_type5() {
        let (mut records, operators) = reveal_set_prefix();
        let ceremony_id = ceremony_record_content_digest(&records[0].body).unwrap();
        let last = ceremony_signed_record_digest(records.last().unwrap()).unwrap();
        let evidence_file =
            content_identity_infallible(&sample_claims(b"failure").canonical_bytes());
        records.push(sign_record(
            CeremonyRecordBody::Abort(AbortBody {
                ceremony_id,
                last_valid_signed_record_digest: last,
                phase: STRUCTURAL_ANALYZER_ABORT_PHASE,
                reason_code: 6,
                evidence_file,
            }),
            &[(SignerClass::Operator, 0, &operators[0])],
        ));
        let bytes = encode_and_verify_ceremony_transcript(&records).unwrap();
        let transcript = parse_and_verify_ceremony_transcript(&bytes).unwrap();
        assert!(require_type7_analyzer_abort(&transcript, ceremony_id, last).is_ok());
        assert!(require_type7_analyzer_abort(&transcript, [1; 32], last).is_err());
        assert!(require_type7_analyzer_abort(&transcript, ceremony_id, [2; 32]).is_err());
    }

    #[test]
    fn claims_anchor_verification_rejects_every_wrong_binding() {
        let claims = sample_claims(b"failure");
        let authority = Type5AnalyzerAuthority {
            ceremony_id: claims.ceremony_id,
            last_valid_signed_record_digest: claims.last_valid_signed_record_digest,
            analyzer_target_id: claims.analyzer_target_id,
            analyzer_blake3: claims.analyzer_blake3,
            analyzer_sha256: claims.analyzer_sha256,
        };
        let roots = RootsBinding {
            ceremony_id: claims.ceremony_id,
            file_identity: claims.roots_file.clone(),
        };
        assert!(verify_claims_against_authority(&claims, &authority, &roots).is_ok());

        for field in 0..7 {
            let mut changed = claims.clone();
            match field {
                0 => changed.ceremony_id[0] ^= 1,
                1 => changed.last_valid_signed_record_digest[0] ^= 1,
                2 => changed.analyzer_target_id = 2,
                3 => changed.analyzer_blake3[0] ^= 1,
                4 => changed.analyzer_sha256[0] ^= 1,
                5 => changed.roots_file.blake3[0] ^= 1,
                6 => changed.roots_file.sha256[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(verify_claims_against_authority(&changed, &authority, &roots).is_err());
        }
    }

    #[test]
    fn authenticated_abort_bindings_reject_wrong_file_phase_reason_and_anchor() {
        let claims = sample_claims(b"failure");
        let authority = Type5AnalyzerAuthority {
            ceremony_id: claims.ceremony_id,
            last_valid_signed_record_digest: claims.last_valid_signed_record_digest,
            analyzer_target_id: claims.analyzer_target_id,
            analyzer_blake3: claims.analyzer_blake3,
            analyzer_sha256: claims.analyzer_sha256,
        };
        let roots = RootsBinding {
            ceremony_id: claims.ceremony_id,
            file_identity: claims.roots_file.clone(),
        };
        let file_identity = content_identity_infallible(&claims.canonical_bytes());
        let abort = AbortBody {
            ceremony_id: claims.ceremony_id,
            last_valid_signed_record_digest: claims.last_valid_signed_record_digest,
            phase: STRUCTURAL_ANALYZER_ABORT_PHASE,
            reason_code: claims.abort_reason_code(),
            evidence_file: file_identity.clone(),
        };
        assert!(
            verify_authenticated_abort_bindings(
                &claims,
                &file_identity,
                &authority,
                &abort,
                &roots
            )
            .is_ok()
        );

        let mut changed = abort.clone();
        changed.evidence_file.bytes += 1;
        assert!(matches!(
            verify_authenticated_abort_bindings(
                &claims,
                &file_identity,
                &authority,
                &changed,
                &roots
            ),
            Err(ProductionDoryV3StructuralEvidenceError::AbortEvidenceIdentityMismatch)
        ));
        let mut changed = abort.clone();
        changed.phase = 4;
        assert!(matches!(
            verify_authenticated_abort_bindings(
                &claims,
                &file_identity,
                &authority,
                &changed,
                &roots
            ),
            Err(ProductionDoryV3StructuralEvidenceError::AbortMetadataMismatch)
        ));
        let mut changed = abort.clone();
        changed.reason_code = 12;
        assert!(matches!(
            verify_authenticated_abort_bindings(
                &claims,
                &file_identity,
                &authority,
                &changed,
                &roots
            ),
            Err(ProductionDoryV3StructuralEvidenceError::AbortMetadataMismatch)
        ));
        let mut changed = abort;
        changed.ceremony_id[0] ^= 1;
        assert!(matches!(
            verify_authenticated_abort_bindings(
                &claims,
                &file_identity,
                &authority,
                &changed,
                &roots
            ),
            Err(ProductionDoryV3StructuralEvidenceError::EvidenceAnchorMismatch)
        ));
    }

    #[test]
    fn persisted_file_is_private_reopened_and_bound_to_prepared_abort() {
        let directory = test_directory("persist");
        fs::create_dir(&directory).unwrap();
        crate::dory_v3_model_ceremony_fs::prepare_test_parent(&directory).unwrap();
        let output = directory.join("failure.cmfdse");
        let claims = sample_claims(b"forbidden byte");
        let report = persist_claims(claims.clone(), &output).unwrap();
        assert_eq!(fs::read(&output).unwrap(), claims.canonical_bytes());
        assert_eq!(report.evidence().claims(), &claims);
        assert_eq!(
            report.prepared_abort().body().evidence_file,
            *report.evidence().file_identity()
        );
        assert_eq!(report.prepared_abort().body().phase, 5);
        assert_eq!(report.prepared_abort().body().reason_code, 6);
        assert_eq!(
            report.prepared_abort().signature_message(),
            ceremony_record_signature_message(&CeremonyRecordBody::Abort(
                report.prepared_abort().body().clone()
            ))
            .unwrap()
        );
        fs::remove_file(output).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn authenticated_file_reader_rejects_extra_bytes_and_wrong_content_identity() {
        let directory = test_directory("authenticate");
        fs::create_dir(&directory).unwrap();
        crate::dory_v3_model_ceremony_fs::prepare_test_parent(&directory).unwrap();
        let output = directory.join("failure.cmfdse");
        let claims = sample_claims(b"failure");
        fs::write(&output, claims.canonical_bytes()).unwrap();
        let (parsed, file_identity) = authenticate_evidence_file(&output).unwrap();
        assert_eq!(parsed, claims);
        assert_eq!(
            file_identity,
            content_identity_infallible(&fs::read(&output).unwrap())
        );

        let mut changed = fs::read(&output).unwrap();
        changed.push(b'X');
        fs::write(&output, changed).unwrap();
        assert!(authenticate_evidence_file(&output).is_err());
        fs::remove_file(output).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    fn encode_transcript_prefix(records: &[SignedCeremonyRecord]) -> Vec<u8> {
        // The public completed/aborted encoder intentionally rejects a type-5
        // prefix. Reuse its exact framing by appending a signed abort, encode,
        // then reconstruct the header for the retained prefix records.
        let framed: Vec<_> = records
            .iter()
            .map(crate::dory_v3_model_ceremony_transcript::encode_ceremony_record)
            .collect::<Result<_, _>>()
            .unwrap();
        let total = usize::from(CEREMONY_TRANSCRIPT_HEADER_BYTES)
            + framed.iter().map(Vec::len).sum::<usize>();
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&CEREMONY_TRANSCRIPT_MAGIC);
        bytes.extend_from_slice(&CEREMONY_PROTOCOL_VERSION.to_le_bytes());
        bytes.extend_from_slice(&CEREMONY_TRANSCRIPT_HEADER_BYTES.to_le_bytes());
        bytes.extend_from_slice(&(records.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(total as u64).to_le_bytes());
        for record in framed {
            bytes.extend_from_slice(&record);
        }
        bytes
    }

    fn test_directory(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cmfd-structure-evidence-{label}-{}-{unique}",
            std::process::id()
        ))
    }
}
