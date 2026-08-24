//! Strict, path-independent reproduction report for the production Dory V3 ceremony.
//!
//! `CMFDRP01` is a fixed-width audit artifact. Parsing checks its canonical
//! syntax and all locally derivable production identities. Contextual
//! verification additionally binds it to an independently anchored exact
//! type-5 transcript and a live combined-payload validation result. The
//! combiner's path-bearing JSON remains opaque: this report commits to that
//! file's exact length and dual hashes but never deserializes or trusts it.

use k256::schnorr::VerifyingKey;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ModelBankManifest,
    dory_v3_model::{CanonicalBlsDoryGtHex, ordered_dory_v3_model_commitment_root},
    dory_v3_model_ceremony_transcript::{
        CeremonyRecordBody, CeremonyTranscriptError, FileIdentity, GenesisBody,
        PRODUCTION_BANK_BYTES, PRODUCTION_BANKS, PRODUCTION_BASE_INPUT_BYTES, PRODUCTION_BATCH,
        PRODUCTION_BYTES_PER_LAYER, PRODUCTION_DIMENSION, PRODUCTION_LAYERS,
        PRODUCTION_LAYERS_PER_BANK, PRODUCTION_MODEL_VERSION, PRODUCTION_PADDED_VARIABLES,
        PRODUCTION_PAYLOAD_BYTES, VerifiedCeremonyTranscript, VerifiedCombinerBindings,
        ceremony_signed_record_digest,
    },
    dory_v3_model_combiner::{
        ProductionDoryV3ModelCombinerInputReport, ValidatedProductionDoryV3ModelCombinedPayload,
    },
    dory_v3_model_roots::PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES,
    dory_v3_model_structure::PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES,
    dory_v3_suite::{
        DORY_V3_MODEL_IDENTITY_DOMAIN, DORY_V3_MODEL_IDENTITY_VERSION, DORY_V3_MODEL_RECORD_DOMAIN,
        DORY_V3_MODEL_RECORD_VERSION, DORY_V3_SETUP_IDENTITY, production_dory_v3_suite_digest,
    },
};

pub const PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_MAGIC: [u8; 8] = *b"CMFDRP01";
pub const PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_VERSION: u16 = 1;
pub const PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES: usize = 4_283;

const FILE_IDENTITY_BYTES: usize = 8 + 32 + 32;
const COMBINER_INPUTS_DOMAIN: &str = "CMFD/FORGEMATRIX/V3/MODEL-REPRODUCTION/COMBINER-INPUTS/V1";

const _: [(); PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES] = [(); 8
    + 2
    + 4
    + 32
    + 32
    + 2
    + 32
    + 1
    + 2
    + 20
    + 2 * FILE_IDENTITY_BYTES
    + 4 * 32
    + 8
    + 3 * 32
    + 2 * 32
    + 32
    + 4 * FILE_IDENTITY_BYTES
    + 4 * FILE_IDENTITY_BYTES
    + 6 * FILE_IDENTITY_BYTES
    + 4 * 32
    + 4 * 576
    + 4 * 32
    + 4
    + 32
    + 8
    + 6 * 8
    + 2 * 8];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProductionDoryV3ReproductionImplementationKind {
    Reference = 0,
    Independent = 1,
}

impl ProductionDoryV3ReproductionImplementationKind {
    fn decode(value: u8) -> Result<Self, ProductionDoryV3ModelReproductionReportError> {
        match value {
            0 => Ok(Self::Reference),
            1 => Ok(Self::Independent),
            _ => Err(ProductionDoryV3ModelReproductionReportError::Invalid(
                "reserved implementation kind",
            )),
        }
    }
}

/// Syntax-verified, internally consistent V1 reproduction report.
///
/// Private fields prevent callers from constructing a report that merely looks
/// parser-verified. This type is not contextual ceremony authority; use
/// [`verify_production_dory_v3_model_reproduction_report`] for that boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3ModelReproductionReport {
    ceremony_id: [u8; 32],
    genesis_signed_record_digest: [u8; 32],
    reproducer_index: u16,
    reproducer_public_key: [u8; 32],
    implementation_kind: ProductionDoryV3ReproductionImplementationKind,
    target_id: u16,
    source_commit_sha1: [u8; 20],
    source_bundle: FileIdentity,
    source_bundle_policy: FileIdentity,
    cargo_lock_blake3: [u8; 32],
    cargo_lock_sha256: [u8; 32],
    protocol_spec_blake3: [u8; 32],
    protocol_spec_sha256: [u8; 32],
    reveal_set_prefix_bytes: u64,
    reveal_set_prefix_derive_key_digest: [u8; 32],
    reveal_set_prefix_blake3: [u8; 32],
    reveal_set_prefix_sha256: [u8; 32],
    commitment_set_signed_record_digest: [u8; 32],
    reveal_set_signed_record_digest: [u8; 32],
    combiner_ordered_inputs_digest: [u8; 32],
    combiner_binary: FileIdentity,
    combiner_report: FileIdentity,
    bootstrap_report: FileIdentity,
    record_ceremony_report: FileIdentity,
    host_environment_report: FileIdentity,
    source_extraction_report: FileIdentity,
    command_log: FileIdentity,
    implementation_lineage_report: FileIdentity,
    raw_payload: FileIdentity,
    roots_file: FileIdentity,
    structural_report: FileIdentity,
    bank_file: FileIdentity,
    manifest_file: FileIdentity,
    record_v2_file: FileIdentity,
    base_input_blake3_root: [u8; 32],
    layer_roots_aggregate: [u8; 32],
    production_suite_digest: [u8; 32],
    pcs_parameter_digest: [u8; 32],
    base_commitment: [u8; 576],
    weight_bank_0_commitment: [u8; 576],
    weight_bank_1_commitment: [u8; 576],
    weight_bank_2_commitment: [u8; 576],
    pcs_commitment_root: [u8; 32],
    manifest_digest: [u8; 32],
    model_identity_digest: [u8; 32],
    setup_identity: [u8; 32],
    padded_variables: u32,
    record_v2_digest: [u8; 32],
    combine_bytes_processed: u64,
    combine_elapsed_micros: u64,
    roots_elapsed_micros: u64,
    structure_elapsed_micros: u64,
    bootstrap_elapsed_micros: u64,
    record_elapsed_micros: u64,
    total_elapsed_micros: u64,
    peak_rss_bytes: u64,
    peak_disk_bytes: u64,
}

/// Reproducer-owned claims that cannot be derived from the signed ceremony
/// prefix or the live combined-payload validation result.
///
/// The authoring API derives all ceremony, source, closure, ordered-input,
/// output, and frozen production identities itself. These claims contain only
/// the implementation choice, external audit artifacts, downstream candidate
/// artifacts, commitments, and measured resource use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3ModelReproductionClaims {
    pub reproducer_index: u16,
    pub implementation_kind: ProductionDoryV3ReproductionImplementationKind,
    pub target_id: u16,
    pub combiner_binary: FileIdentity,
    pub combiner_report: FileIdentity,
    pub bootstrap_report: FileIdentity,
    pub record_ceremony_report: FileIdentity,
    pub host_environment_report: FileIdentity,
    pub source_extraction_report: FileIdentity,
    pub command_log: FileIdentity,
    pub implementation_lineage_report: FileIdentity,
    pub roots_file: FileIdentity,
    pub structural_report: FileIdentity,
    pub bank_file: FileIdentity,
    pub manifest_file: FileIdentity,
    pub record_v2_file: FileIdentity,
    pub base_input_blake3_root: [u8; 32],
    pub layer_roots_aggregate: [u8; 32],
    pub base_commitment: [u8; 576],
    pub weight_bank_0_commitment: [u8; 576],
    pub weight_bank_1_commitment: [u8; 576],
    pub weight_bank_2_commitment: [u8; 576],
    pub roots_elapsed_micros: u64,
    pub structure_elapsed_micros: u64,
    pub bootstrap_elapsed_micros: u64,
    pub record_elapsed_micros: u64,
    pub total_elapsed_micros: u64,
    pub peak_rss_bytes: u64,
    pub peak_disk_bytes: u64,
}

/// Immutable view of every external file identity bound by one report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3ModelReproductionArtifacts<'a> {
    pub source_bundle: &'a FileIdentity,
    pub source_bundle_policy: &'a FileIdentity,
    pub combiner_binary: &'a FileIdentity,
    pub combiner_report: &'a FileIdentity,
    pub bootstrap_report: &'a FileIdentity,
    pub record_ceremony_report: &'a FileIdentity,
    pub host_environment_report: &'a FileIdentity,
    pub source_extraction_report: &'a FileIdentity,
    pub command_log: &'a FileIdentity,
    pub implementation_lineage_report: &'a FileIdentity,
    pub raw_payload: &'a FileIdentity,
    pub roots_file: &'a FileIdentity,
    pub structural_report: &'a FileIdentity,
    pub bank_file: &'a FileIdentity,
    pub manifest_file: &'a FileIdentity,
    pub record_v2_file: &'a FileIdentity,
}

/// Immutable type-6 candidate projection. Reproducer-specific audit and
/// timing fields are intentionally excluded so independently produced reports
/// can be compared for one identical final candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionDoryV3ModelFinalCandidate<'a> {
    pub raw_payload: &'a FileIdentity,
    pub base_input_blake3_root: [u8; 32],
    pub layer_roots_aggregate: [u8; 32],
    pub roots_file: &'a FileIdentity,
    pub structural_report: &'a FileIdentity,
    pub bank_file: &'a FileIdentity,
    pub manifest_file: &'a FileIdentity,
    pub manifest_digest: [u8; 32],
    pub production_suite_digest: [u8; 32],
    pub pcs_parameter_digest: [u8; 32],
    pub base_commitment: &'a [u8; 576],
    pub weight_bank_0_commitment: &'a [u8; 576],
    pub weight_bank_1_commitment: &'a [u8; 576],
    pub weight_bank_2_commitment: &'a [u8; 576],
    pub pcs_commitment_root: [u8; 32],
    pub model_identity_digest: [u8; 32],
    pub setup_identity: [u8; 32],
    pub padded_variables: u32,
    pub record_v2_file: &'a FileIdentity,
    pub record_v2_digest: [u8; 32],
}

impl ProductionDoryV3ModelReproductionReport {
    pub const fn ceremony_id(&self) -> [u8; 32] {
        self.ceremony_id
    }

    pub const fn reproducer_index(&self) -> u16 {
        self.reproducer_index
    }

    pub const fn reproducer_public_key(&self) -> [u8; 32] {
        self.reproducer_public_key
    }

    pub const fn implementation_kind(&self) -> ProductionDoryV3ReproductionImplementationKind {
        self.implementation_kind
    }

    pub const fn target_id(&self) -> u16 {
        self.target_id
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES] {
        encode_report(self)
    }

    #[must_use]
    pub fn content_identity(&self) -> FileIdentity {
        file_identity(&self.canonical_bytes())
    }
}

/// Opaque capability returned only after transcript and live-combiner context
/// have both matched the strict report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextVerifiedProductionDoryV3ModelReproductionReport {
    report: ProductionDoryV3ModelReproductionReport,
}

impl ContextVerifiedProductionDoryV3ModelReproductionReport {
    pub const fn report(&self) -> &ProductionDoryV3ModelReproductionReport {
        &self.report
    }

    #[must_use]
    pub const fn artifacts(&self) -> ProductionDoryV3ModelReproductionArtifacts<'_> {
        ProductionDoryV3ModelReproductionArtifacts {
            source_bundle: &self.report.source_bundle,
            source_bundle_policy: &self.report.source_bundle_policy,
            combiner_binary: &self.report.combiner_binary,
            combiner_report: &self.report.combiner_report,
            bootstrap_report: &self.report.bootstrap_report,
            record_ceremony_report: &self.report.record_ceremony_report,
            host_environment_report: &self.report.host_environment_report,
            source_extraction_report: &self.report.source_extraction_report,
            command_log: &self.report.command_log,
            implementation_lineage_report: &self.report.implementation_lineage_report,
            raw_payload: &self.report.raw_payload,
            roots_file: &self.report.roots_file,
            structural_report: &self.report.structural_report,
            bank_file: &self.report.bank_file,
            manifest_file: &self.report.manifest_file,
            record_v2_file: &self.report.record_v2_file,
        }
    }

    #[must_use]
    pub const fn final_candidate(&self) -> ProductionDoryV3ModelFinalCandidate<'_> {
        ProductionDoryV3ModelFinalCandidate {
            raw_payload: &self.report.raw_payload,
            base_input_blake3_root: self.report.base_input_blake3_root,
            layer_roots_aggregate: self.report.layer_roots_aggregate,
            roots_file: &self.report.roots_file,
            structural_report: &self.report.structural_report,
            bank_file: &self.report.bank_file,
            manifest_file: &self.report.manifest_file,
            manifest_digest: self.report.manifest_digest,
            production_suite_digest: self.report.production_suite_digest,
            pcs_parameter_digest: self.report.pcs_parameter_digest,
            base_commitment: &self.report.base_commitment,
            weight_bank_0_commitment: &self.report.weight_bank_0_commitment,
            weight_bank_1_commitment: &self.report.weight_bank_1_commitment,
            weight_bank_2_commitment: &self.report.weight_bank_2_commitment,
            pcs_commitment_root: self.report.pcs_commitment_root,
            model_identity_digest: self.report.model_identity_digest,
            setup_identity: self.report.setup_identity,
            padded_variables: self.report.padded_variables,
            record_v2_file: &self.report.record_v2_file,
            record_v2_digest: self.report.record_v2_digest,
        }
    }

    #[must_use]
    pub fn same_final_candidate(&self, other: &Self) -> bool {
        self.final_candidate() == other.final_candidate()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProductionDoryV3ModelReproductionReportError {
    #[error("reproduction report length mismatch: expected {expected}, observed {actual}")]
    ReportLength { expected: usize, actual: usize },
    #[error("invalid reproduction report magic")]
    InvalidMagic,
    #[error("unsupported reproduction report version {0}")]
    UnsupportedVersion(u16),
    #[error("truncated reproduction report while reading {0}")]
    Truncated(&'static str),
    #[error("invalid reproduction report: {0}")]
    Invalid(&'static str),
    #[error("reproduction report does not match its ceremony context: {0}")]
    Context(&'static str),
    #[error("invalid ceremony transcript while checking the reproduction report: {0}")]
    Transcript(#[from] CeremonyTranscriptError),
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
    ) -> Result<[u8; N], ProductionDoryV3ModelReproductionReportError> {
        let end = self.offset.checked_add(N).ok_or(
            ProductionDoryV3ModelReproductionReportError::Invalid("decoder offset overflow"),
        )?;
        let value = self.bytes.get(self.offset..end).ok_or(
            ProductionDoryV3ModelReproductionReportError::Truncated(field),
        )?;
        self.offset = end;
        value
            .try_into()
            .map_err(|_| ProductionDoryV3ModelReproductionReportError::Truncated(field))
    }

    fn u8(
        &mut self,
        field: &'static str,
    ) -> Result<u8, ProductionDoryV3ModelReproductionReportError> {
        Ok(self.take::<1>(field)?[0])
    }

    fn u16(
        &mut self,
        field: &'static str,
    ) -> Result<u16, ProductionDoryV3ModelReproductionReportError> {
        Ok(u16::from_le_bytes(self.take(field)?))
    }

    fn u32(
        &mut self,
        field: &'static str,
    ) -> Result<u32, ProductionDoryV3ModelReproductionReportError> {
        Ok(u32::from_le_bytes(self.take(field)?))
    }

    fn u64(
        &mut self,
        field: &'static str,
    ) -> Result<u64, ProductionDoryV3ModelReproductionReportError> {
        Ok(u64::from_le_bytes(self.take(field)?))
    }

    fn finish(self) -> Result<(), ProductionDoryV3ModelReproductionReportError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ProductionDoryV3ModelReproductionReportError::Invalid(
                "trailing bytes",
            ))
        }
    }
}

fn encode_file_identity(encoder: &mut Encoder, value: &FileIdentity) {
    encoder.u64(value.bytes);
    encoder.bytes(&value.blake3);
    encoder.bytes(&value.sha256);
}

fn decode_file_identity(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<FileIdentity, ProductionDoryV3ModelReproductionReportError> {
    let identity = FileIdentity {
        bytes: decoder.u64(field)?,
        blake3: decoder.take(field)?,
        sha256: decoder.take(field)?,
    };
    validate_file_identity(&identity)?;
    Ok(identity)
}

fn validate_file_identity(
    identity: &FileIdentity,
) -> Result<(), ProductionDoryV3ModelReproductionReportError> {
    if identity.bytes == 0 {
        return Err(ProductionDoryV3ModelReproductionReportError::Invalid(
            "zero-length file identity",
        ));
    }
    if identity.blake3 == [0; 32] || identity.sha256 == [0; 32] {
        return Err(ProductionDoryV3ModelReproductionReportError::Invalid(
            "zero digest in file identity",
        ));
    }
    Ok(())
}

fn encode_report(
    report: &ProductionDoryV3ModelReproductionReport,
) -> [u8; PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES] {
    let mut encoder = Encoder::default();
    encoder.bytes(&PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_MAGIC);
    encoder.u16(PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_VERSION);
    encoder.u32(
        u32::try_from(PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES)
            .expect("the fixed report length fits in u32"),
    );
    encoder.bytes(&report.ceremony_id);
    encoder.bytes(&report.genesis_signed_record_digest);
    encoder.u16(report.reproducer_index);
    encoder.bytes(&report.reproducer_public_key);
    encoder.u8(report.implementation_kind as u8);
    encoder.u16(report.target_id);
    encoder.bytes(&report.source_commit_sha1);
    encode_file_identity(&mut encoder, &report.source_bundle);
    encode_file_identity(&mut encoder, &report.source_bundle_policy);
    encoder.bytes(&report.cargo_lock_blake3);
    encoder.bytes(&report.cargo_lock_sha256);
    encoder.bytes(&report.protocol_spec_blake3);
    encoder.bytes(&report.protocol_spec_sha256);
    encoder.u64(report.reveal_set_prefix_bytes);
    encoder.bytes(&report.reveal_set_prefix_derive_key_digest);
    encoder.bytes(&report.reveal_set_prefix_blake3);
    encoder.bytes(&report.reveal_set_prefix_sha256);
    encoder.bytes(&report.commitment_set_signed_record_digest);
    encoder.bytes(&report.reveal_set_signed_record_digest);
    encoder.bytes(&report.combiner_ordered_inputs_digest);
    encode_file_identity(&mut encoder, &report.combiner_binary);
    encode_file_identity(&mut encoder, &report.combiner_report);
    encode_file_identity(&mut encoder, &report.bootstrap_report);
    encode_file_identity(&mut encoder, &report.record_ceremony_report);
    encode_file_identity(&mut encoder, &report.host_environment_report);
    encode_file_identity(&mut encoder, &report.source_extraction_report);
    encode_file_identity(&mut encoder, &report.command_log);
    encode_file_identity(&mut encoder, &report.implementation_lineage_report);
    encode_file_identity(&mut encoder, &report.raw_payload);
    encode_file_identity(&mut encoder, &report.roots_file);
    encode_file_identity(&mut encoder, &report.structural_report);
    encode_file_identity(&mut encoder, &report.bank_file);
    encode_file_identity(&mut encoder, &report.manifest_file);
    encode_file_identity(&mut encoder, &report.record_v2_file);
    encoder.bytes(&report.base_input_blake3_root);
    encoder.bytes(&report.layer_roots_aggregate);
    encoder.bytes(&report.production_suite_digest);
    encoder.bytes(&report.pcs_parameter_digest);
    encoder.bytes(&report.base_commitment);
    encoder.bytes(&report.weight_bank_0_commitment);
    encoder.bytes(&report.weight_bank_1_commitment);
    encoder.bytes(&report.weight_bank_2_commitment);
    encoder.bytes(&report.pcs_commitment_root);
    encoder.bytes(&report.manifest_digest);
    encoder.bytes(&report.model_identity_digest);
    encoder.bytes(&report.setup_identity);
    encoder.u32(report.padded_variables);
    encoder.bytes(&report.record_v2_digest);
    encoder.u64(report.combine_bytes_processed);
    encoder.u64(report.combine_elapsed_micros);
    encoder.u64(report.roots_elapsed_micros);
    encoder.u64(report.structure_elapsed_micros);
    encoder.u64(report.bootstrap_elapsed_micros);
    encoder.u64(report.record_elapsed_micros);
    encoder.u64(report.total_elapsed_micros);
    encoder.u64(report.peak_rss_bytes);
    encoder.u64(report.peak_disk_bytes);
    debug_assert_eq!(
        encoder.0.len(),
        PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES
    );
    encoder
        .0
        .try_into()
        .expect("the fixed report encoder emits its declared length")
}

/// Parse the exact fixed-width V1 codec and validate all locally derivable
/// production constants and identities.
pub fn parse_production_dory_v3_model_reproduction_report(
    bytes: &[u8],
) -> Result<ProductionDoryV3ModelReproductionReport, ProductionDoryV3ModelReproductionReportError> {
    if bytes.len() != PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES {
        return Err(ProductionDoryV3ModelReproductionReportError::ReportLength {
            expected: PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES,
            actual: bytes.len(),
        });
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take::<8>("magic")? != PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_MAGIC {
        return Err(ProductionDoryV3ModelReproductionReportError::InvalidMagic);
    }
    let version = decoder.u16("version")?;
    if version != PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_VERSION {
        return Err(ProductionDoryV3ModelReproductionReportError::UnsupportedVersion(version));
    }
    let declared_bytes = usize::try_from(decoder.u32("report bytes")?)
        .map_err(|_| ProductionDoryV3ModelReproductionReportError::Invalid("report bytes"))?;
    if declared_bytes != PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES {
        return Err(ProductionDoryV3ModelReproductionReportError::Invalid(
            "declared report length",
        ));
    }
    let report = ProductionDoryV3ModelReproductionReport {
        ceremony_id: decoder.take("ceremony id")?,
        genesis_signed_record_digest: decoder.take("genesis signed record digest")?,
        reproducer_index: decoder.u16("reproducer index")?,
        reproducer_public_key: decoder.take("reproducer public key")?,
        implementation_kind: ProductionDoryV3ReproductionImplementationKind::decode(
            decoder.u8("implementation kind")?,
        )?,
        target_id: decoder.u16("target id")?,
        source_commit_sha1: decoder.take("source commit")?,
        source_bundle: decode_file_identity(&mut decoder, "source bundle")?,
        source_bundle_policy: decode_file_identity(&mut decoder, "source bundle policy")?,
        cargo_lock_blake3: decoder.take("Cargo.lock blake3")?,
        cargo_lock_sha256: decoder.take("Cargo.lock sha256")?,
        protocol_spec_blake3: decoder.take("protocol spec blake3")?,
        protocol_spec_sha256: decoder.take("protocol spec sha256")?,
        reveal_set_prefix_bytes: decoder.u64("reveal-set prefix bytes")?,
        reveal_set_prefix_derive_key_digest: decoder.take("reveal-set prefix derive digest")?,
        reveal_set_prefix_blake3: decoder.take("reveal-set prefix blake3")?,
        reveal_set_prefix_sha256: decoder.take("reveal-set prefix sha256")?,
        commitment_set_signed_record_digest: decoder.take("commitment-set record digest")?,
        reveal_set_signed_record_digest: decoder.take("reveal-set record digest")?,
        combiner_ordered_inputs_digest: decoder.take("combiner ordered-input digest")?,
        combiner_binary: decode_file_identity(&mut decoder, "combiner binary")?,
        combiner_report: decode_file_identity(&mut decoder, "combiner report")?,
        bootstrap_report: decode_file_identity(&mut decoder, "bootstrap report")?,
        record_ceremony_report: decode_file_identity(&mut decoder, "record ceremony report")?,
        host_environment_report: decode_file_identity(&mut decoder, "host environment report")?,
        source_extraction_report: decode_file_identity(&mut decoder, "source extraction report")?,
        command_log: decode_file_identity(&mut decoder, "command log")?,
        implementation_lineage_report: decode_file_identity(
            &mut decoder,
            "implementation lineage report",
        )?,
        raw_payload: decode_file_identity(&mut decoder, "raw payload")?,
        roots_file: decode_file_identity(&mut decoder, "roots file")?,
        structural_report: decode_file_identity(&mut decoder, "structural report")?,
        bank_file: decode_file_identity(&mut decoder, "bank file")?,
        manifest_file: decode_file_identity(&mut decoder, "manifest file")?,
        record_v2_file: decode_file_identity(&mut decoder, "Record V2 file")?,
        base_input_blake3_root: decoder.take("base-input root")?,
        layer_roots_aggregate: decoder.take("layer-roots aggregate")?,
        production_suite_digest: decoder.take("production suite digest")?,
        pcs_parameter_digest: decoder.take("PCS parameter digest")?,
        base_commitment: decoder.take("base commitment")?,
        weight_bank_0_commitment: decoder.take("weight-bank 0 commitment")?,
        weight_bank_1_commitment: decoder.take("weight-bank 1 commitment")?,
        weight_bank_2_commitment: decoder.take("weight-bank 2 commitment")?,
        pcs_commitment_root: decoder.take("PCS commitment root")?,
        manifest_digest: decoder.take("manifest digest")?,
        model_identity_digest: decoder.take("model identity digest")?,
        setup_identity: decoder.take("setup identity")?,
        padded_variables: decoder.u32("padded variables")?,
        record_v2_digest: decoder.take("Record V2 digest")?,
        combine_bytes_processed: decoder.u64("combine bytes processed")?,
        combine_elapsed_micros: decoder.u64("combine elapsed micros")?,
        roots_elapsed_micros: decoder.u64("roots elapsed micros")?,
        structure_elapsed_micros: decoder.u64("structure elapsed micros")?,
        bootstrap_elapsed_micros: decoder.u64("bootstrap elapsed micros")?,
        record_elapsed_micros: decoder.u64("record elapsed micros")?,
        total_elapsed_micros: decoder.u64("total elapsed micros")?,
        peak_rss_bytes: decoder.u64("peak RSS bytes")?,
        peak_disk_bytes: decoder.u64("peak disk bytes")?,
    };
    decoder.finish()?;
    validate_report(&report)?;
    if encode_report(&report) != bytes {
        return Err(ProductionDoryV3ModelReproductionReportError::Invalid(
            "noncanonical reproduction report",
        ));
    }
    Ok(report)
}

struct DerivedCandidateFields {
    commitment_root: [u8; 32],
    manifest_digest: [u8; 32],
    model_identity_digest: [u8; 32],
    record_v2_digest: [u8; 32],
}

fn validate_report(
    report: &ProductionDoryV3ModelReproductionReport,
) -> Result<(), ProductionDoryV3ModelReproductionReportError> {
    if report.ceremony_id == [0; 32]
        || report.genesis_signed_record_digest == [0; 32]
        || report.source_commit_sha1 == [0; 20]
        || report.cargo_lock_blake3 == [0; 32]
        || report.cargo_lock_sha256 == [0; 32]
        || report.protocol_spec_blake3 == [0; 32]
        || report.protocol_spec_sha256 == [0; 32]
        || report.reveal_set_prefix_bytes == 0
        || report.reveal_set_prefix_derive_key_digest == [0; 32]
        || report.reveal_set_prefix_blake3 == [0; 32]
        || report.reveal_set_prefix_sha256 == [0; 32]
        || report.commitment_set_signed_record_digest == [0; 32]
        || report.reveal_set_signed_record_digest == [0; 32]
        || report.combiner_ordered_inputs_digest == [0; 32]
        || report.base_input_blake3_root == [0; 32]
        || report.layer_roots_aggregate == [0; 32]
    {
        return Err(ProductionDoryV3ModelReproductionReportError::Invalid(
            "required anchor or digest is zero",
        ));
    }
    VerifyingKey::from_bytes(&report.reproducer_public_key).map_err(|_| {
        ProductionDoryV3ModelReproductionReportError::Invalid("reproducer public key")
    })?;
    if !(1..=2).contains(&report.target_id) {
        return Err(ProductionDoryV3ModelReproductionReportError::Invalid(
            "target id",
        ));
    }
    for identity in [
        &report.source_bundle,
        &report.source_bundle_policy,
        &report.combiner_binary,
        &report.combiner_report,
        &report.bootstrap_report,
        &report.record_ceremony_report,
        &report.host_environment_report,
        &report.source_extraction_report,
        &report.command_log,
        &report.implementation_lineage_report,
        &report.raw_payload,
        &report.roots_file,
        &report.structural_report,
        &report.bank_file,
        &report.manifest_file,
        &report.record_v2_file,
    ] {
        validate_file_identity(identity)?;
    }
    if report.raw_payload.bytes != PRODUCTION_PAYLOAD_BYTES
        || report.roots_file.bytes
            != u64::try_from(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES)
                .expect("the frozen roots length fits in u64")
        || report.structural_report.bytes
            != u64::try_from(PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES)
                .expect("the frozen structural-report length fits in u64")
        || report.bank_file.bytes != PRODUCTION_BANK_BYTES
        || report.combine_bytes_processed != PRODUCTION_PAYLOAD_BYTES
    {
        return Err(ProductionDoryV3ModelReproductionReportError::Invalid(
            "nonproduction artifact size or byte count",
        ));
    }
    let production_suite_digest = production_dory_v3_suite_digest().into_bytes();
    if report.production_suite_digest != production_suite_digest
        || report.pcs_parameter_digest != production_suite_digest
        || report.setup_identity != DORY_V3_SETUP_IDENTITY.into_bytes()
        || report.padded_variables != PRODUCTION_PADDED_VARIABLES
    {
        return Err(ProductionDoryV3ModelReproductionReportError::Invalid(
            "production suite identity",
        ));
    }
    let derived = derive_candidate_fields(report)?;
    if report.pcs_commitment_root != derived.commitment_root
        || report.manifest_digest != derived.manifest_digest
        || report.model_identity_digest != derived.model_identity_digest
        || report.record_v2_digest != derived.record_v2_digest
    {
        return Err(ProductionDoryV3ModelReproductionReportError::Invalid(
            "derived candidate identity",
        ));
    }
    let phase_times = [
        report.combine_elapsed_micros,
        report.roots_elapsed_micros,
        report.structure_elapsed_micros,
        report.bootstrap_elapsed_micros,
        report.record_elapsed_micros,
    ];
    if phase_times.contains(&0)
        || report.total_elapsed_micros == 0
        || phase_times
            .iter()
            .any(|elapsed| *elapsed > report.total_elapsed_micros)
        || report.peak_rss_bytes == 0
        || report.peak_disk_bytes == 0
    {
        return Err(ProductionDoryV3ModelReproductionReportError::Invalid(
            "resource or timing measurement",
        ));
    }
    Ok(())
}

fn parse_commitment(
    bytes: &[u8; 576],
) -> Result<CanonicalBlsDoryGtHex, ProductionDoryV3ModelReproductionReportError> {
    CanonicalBlsDoryGtHex::from_hex(&hex::encode(bytes)).map_err(|_| {
        ProductionDoryV3ModelReproductionReportError::Invalid("canonical Dory commitment")
    })
}

fn derive_candidate_fields(
    report: &ProductionDoryV3ModelReproductionReport,
) -> Result<DerivedCandidateFields, ProductionDoryV3ModelReproductionReportError> {
    let commitments = [
        &report.base_commitment,
        &report.weight_bank_0_commitment,
        &report.weight_bank_1_commitment,
        &report.weight_bank_2_commitment,
    ];
    for left in 0..commitments.len() {
        for right in left + 1..commitments.len() {
            if commitments[left] == commitments[right] {
                return Err(ProductionDoryV3ModelReproductionReportError::Invalid(
                    "duplicate Dory commitment",
                ));
            }
        }
    }
    let base = parse_commitment(&report.base_commitment)?;
    let weights = vec![
        parse_commitment(&report.weight_bank_0_commitment)?,
        parse_commitment(&report.weight_bank_1_commitment)?,
        parse_commitment(&report.weight_bank_2_commitment)?,
    ];
    let commitment_root = ordered_dory_v3_model_commitment_root(
        DORY_V3_MODEL_IDENTITY_VERSION,
        report.production_suite_digest,
        report.setup_identity,
        report.padded_variables,
        &base,
        &weights,
    )
    .map_err(|_| ProductionDoryV3ModelReproductionReportError::Invalid("Dory commitment root"))?;
    let manifest = ModelBankManifest {
        model_version: PRODUCTION_MODEL_VERSION,
        dimension: PRODUCTION_DIMENSION,
        batch: PRODUCTION_BATCH,
        layers: PRODUCTION_LAYERS,
        base_input_bytes: PRODUCTION_BASE_INPUT_BYTES,
        bytes_per_layer: PRODUCTION_BYTES_PER_LAYER,
        payload_bytes: PRODUCTION_PAYLOAD_BYTES,
        raw_blake3_root: report.raw_payload.blake3,
        layer_roots_aggregate: report.layer_roots_aggregate,
        pcs_parameter_digest: report.pcs_parameter_digest,
        pcs_commitment_root: commitment_root,
    };
    let manifest_digest = manifest.digest().map_err(|_| {
        ProductionDoryV3ModelReproductionReportError::Invalid("model manifest digest")
    })?;

    let mut identity = Encoder::default();
    identity.u16(DORY_V3_MODEL_IDENTITY_VERSION);
    identity.bytes(&report.production_suite_digest);
    identity.u32(PRODUCTION_MODEL_VERSION);
    identity.u32(PRODUCTION_BATCH);
    identity.u32(PRODUCTION_DIMENSION);
    identity.u32(PRODUCTION_LAYERS_PER_BANK);
    identity.u32(PRODUCTION_BANKS);
    identity.bytes(&report.raw_payload.blake3);
    identity.bytes(&report.layer_roots_aggregate);
    identity.bytes(&report.setup_identity);
    identity.u32(report.padded_variables);
    identity.bytes(&commitment_root);
    let model_identity_digest = blake3_derive(DORY_V3_MODEL_IDENTITY_DOMAIN, &identity.0);

    let mut record = Encoder::default();
    record.u16(DORY_V3_MODEL_RECORD_VERSION);
    record.bytes(&report.production_suite_digest);
    record.bytes(&manifest_digest);
    record.bytes(&model_identity_digest);
    record.bytes(&report.setup_identity);
    record.u32(report.padded_variables);
    record.bytes(&commitment_root);
    if record.0.len() != 166 {
        return Err(ProductionDoryV3ModelReproductionReportError::Invalid(
            "canonical Record V2 length",
        ));
    }
    let record_v2_digest = blake3_derive(DORY_V3_MODEL_RECORD_DOMAIN, &record.0);
    Ok(DerivedCandidateFields {
        commitment_root,
        manifest_digest,
        model_identity_digest,
        record_v2_digest,
    })
}

fn blake3_derive(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn file_identity(bytes: &[u8]) -> FileIdentity {
    FileIdentity {
        bytes: u64::try_from(bytes.len()).expect("the fixed report length fits in u64"),
        blake3: *blake3::hash(bytes).as_bytes(),
        sha256: Sha256::digest(bytes).into(),
    }
}

fn combiner_ordered_inputs_digest(
    inputs: &[ProductionDoryV3ModelCombinerInputReport],
) -> Result<[u8; 32], ProductionDoryV3ModelReproductionReportError> {
    let count = u16::try_from(inputs.len()).map_err(|_| {
        ProductionDoryV3ModelReproductionReportError::Context("combiner input count")
    })?;
    let mut encoder = Encoder::default();
    encoder.u16(count);
    for input in inputs {
        encoder.u16(input.operator_index);
        encoder.bytes(input.operator_public_key.as_bytes());
        encoder.u64(input.contribution_bytes);
        encoder.bytes(input.contribution_blake3.as_bytes());
        encoder.bytes(input.contribution_sha256.as_bytes());
        encoder.bytes(
            input
                .contribution_commitment_signed_record_digest
                .as_bytes(),
        );
        encoder.bytes(input.contribution_reveal_signed_record_digest.as_bytes());
    }
    Ok(blake3_derive(COMBINER_INPUTS_DOMAIN, &encoder.0))
}

/// Author one canonical report from a sealed type-5 authority, a live
/// combined-payload validation result, and the reproducer-owned claims that
/// cannot be derived from either input.
///
/// This operation is keyless: signatures remain the responsibility of the
/// frozen ceremony transcript. Before returning, the exact canonical bytes
/// are reparsed and contextually verified through the same public verifier
/// used for reports received from another reproducer.
pub fn author_and_verify_production_dory_v3_model_reproduction_report(
    transcript: &VerifiedCeremonyTranscript,
    combined: &ValidatedProductionDoryV3ModelCombinedPayload,
    claims: ProductionDoryV3ModelReproductionClaims,
) -> Result<
    ContextVerifiedProductionDoryV3ModelReproductionReport,
    ProductionDoryV3ModelReproductionReportError,
> {
    let combined_report = combined.report();
    let bindings = transcript.require_combiner_bindings()?;
    let Some(first) = transcript.records().first() else {
        return Err(ProductionDoryV3ModelReproductionReportError::Context(
            "missing genesis record",
        ));
    };
    let CeremonyRecordBody::Genesis(genesis) = &first.body else {
        return Err(ProductionDoryV3ModelReproductionReportError::Context(
            "first record is not genesis",
        ));
    };
    let reproducer = genesis
        .reproducers
        .get(usize::from(claims.reproducer_index))
        .filter(|member| member.index == claims.reproducer_index)
        .ok_or(ProductionDoryV3ModelReproductionReportError::Context(
            "reproducer index",
        ))?;
    let production_suite_digest = production_dory_v3_suite_digest().into_bytes();
    let mut report = ProductionDoryV3ModelReproductionReport {
        ceremony_id: transcript.ceremony_id(),
        genesis_signed_record_digest: ceremony_signed_record_digest(first)?,
        reproducer_index: claims.reproducer_index,
        reproducer_public_key: reproducer.public_key,
        implementation_kind: claims.implementation_kind,
        target_id: claims.target_id,
        source_commit_sha1: genesis.source_commit_sha1,
        source_bundle: genesis.source_bundle.clone(),
        source_bundle_policy: genesis.source_bundle_policy.clone(),
        cargo_lock_blake3: genesis.cargo_lock_blake3,
        cargo_lock_sha256: genesis.cargo_lock_sha256,
        protocol_spec_blake3: genesis.protocol_spec_blake3,
        protocol_spec_sha256: genesis.protocol_spec_sha256,
        reveal_set_prefix_bytes: transcript.transcript_bytes(),
        reveal_set_prefix_derive_key_digest: transcript.transcript_derive_key_digest(),
        reveal_set_prefix_blake3: transcript.transcript_blake3(),
        reveal_set_prefix_sha256: transcript.transcript_sha256(),
        commitment_set_signed_record_digest: bindings.commitment_set_signed_record_digest(),
        reveal_set_signed_record_digest: bindings.reveal_set_signed_record_digest(),
        combiner_ordered_inputs_digest: combiner_ordered_inputs_digest(
            &combined_report.ordered_inputs,
        )?,
        combiner_binary: claims.combiner_binary,
        combiner_report: claims.combiner_report,
        bootstrap_report: claims.bootstrap_report,
        record_ceremony_report: claims.record_ceremony_report,
        host_environment_report: claims.host_environment_report,
        source_extraction_report: claims.source_extraction_report,
        command_log: claims.command_log,
        implementation_lineage_report: claims.implementation_lineage_report,
        raw_payload: FileIdentity {
            bytes: combined_report.output_bytes,
            blake3: combined_report.output_blake3.into_bytes(),
            sha256: combined_report.output_sha256.into_bytes(),
        },
        roots_file: claims.roots_file,
        structural_report: claims.structural_report,
        bank_file: claims.bank_file,
        manifest_file: claims.manifest_file,
        record_v2_file: claims.record_v2_file,
        base_input_blake3_root: claims.base_input_blake3_root,
        layer_roots_aggregate: claims.layer_roots_aggregate,
        production_suite_digest,
        pcs_parameter_digest: production_suite_digest,
        base_commitment: claims.base_commitment,
        weight_bank_0_commitment: claims.weight_bank_0_commitment,
        weight_bank_1_commitment: claims.weight_bank_1_commitment,
        weight_bank_2_commitment: claims.weight_bank_2_commitment,
        pcs_commitment_root: [0; 32],
        manifest_digest: [0; 32],
        model_identity_digest: [0; 32],
        setup_identity: DORY_V3_SETUP_IDENTITY.into_bytes(),
        padded_variables: PRODUCTION_PADDED_VARIABLES,
        record_v2_digest: [0; 32],
        combine_bytes_processed: combined_report.bytes_processed,
        combine_elapsed_micros: combined_report.elapsed_micros,
        roots_elapsed_micros: claims.roots_elapsed_micros,
        structure_elapsed_micros: claims.structure_elapsed_micros,
        bootstrap_elapsed_micros: claims.bootstrap_elapsed_micros,
        record_elapsed_micros: claims.record_elapsed_micros,
        total_elapsed_micros: claims.total_elapsed_micros,
        peak_rss_bytes: claims.peak_rss_bytes,
        peak_disk_bytes: claims.peak_disk_bytes,
    };
    let derived = derive_candidate_fields(&report)?;
    report.pcs_commitment_root = derived.commitment_root;
    report.manifest_digest = derived.manifest_digest;
    report.model_identity_digest = derived.model_identity_digest;
    report.record_v2_digest = derived.record_v2_digest;
    let canonical = encode_report(&report);
    verify_production_dory_v3_model_reproduction_report(&canonical, transcript, combined)
}

/// Parse and contextually verify one report against an independently anchored
/// exact type-5 transcript and a freshly produced validated-existing-payload
/// capability. Paths and elapsed time are intentionally excluded from the
/// canonical combiner semantics; all other reported combiner fields match.
pub fn verify_production_dory_v3_model_reproduction_report(
    bytes: &[u8],
    transcript: &VerifiedCeremonyTranscript,
    combined: &ValidatedProductionDoryV3ModelCombinedPayload,
) -> Result<
    ContextVerifiedProductionDoryV3ModelReproductionReport,
    ProductionDoryV3ModelReproductionReportError,
> {
    let bindings = transcript.require_combiner_bindings()?;
    let report = parse_production_dory_v3_model_reproduction_report(bytes)?;
    let records = transcript.records();
    let Some(first) = records.first() else {
        return Err(ProductionDoryV3ModelReproductionReportError::Context(
            "missing genesis record",
        ));
    };
    let CeremonyRecordBody::Genesis(genesis) = &first.body else {
        return Err(ProductionDoryV3ModelReproductionReportError::Context(
            "first record is not genesis",
        ));
    };
    verify_genesis_context(&report, transcript, genesis, first)?;
    verify_combiner_context(&report, transcript, combined, bindings)?;
    Ok(ContextVerifiedProductionDoryV3ModelReproductionReport { report })
}

fn verify_genesis_context(
    report: &ProductionDoryV3ModelReproductionReport,
    transcript: &VerifiedCeremonyTranscript,
    genesis: &GenesisBody,
    first: &crate::dory_v3_model_ceremony_transcript::SignedCeremonyRecord,
) -> Result<(), ProductionDoryV3ModelReproductionReportError> {
    if report.ceremony_id != transcript.ceremony_id()
        || report.genesis_signed_record_digest != ceremony_signed_record_digest(first)?
        || report.source_commit_sha1 != genesis.source_commit_sha1
        || report.source_bundle != genesis.source_bundle
        || report.source_bundle_policy != genesis.source_bundle_policy
        || report.cargo_lock_blake3 != genesis.cargo_lock_blake3
        || report.cargo_lock_sha256 != genesis.cargo_lock_sha256
        || report.protocol_spec_blake3 != genesis.protocol_spec_blake3
        || report.protocol_spec_sha256 != genesis.protocol_spec_sha256
    {
        return Err(ProductionDoryV3ModelReproductionReportError::Context(
            "genesis or source binding",
        ));
    }
    let member = genesis
        .reproducers
        .get(usize::from(report.reproducer_index))
        .filter(|member| member.index == report.reproducer_index)
        .ok_or(ProductionDoryV3ModelReproductionReportError::Context(
            "reproducer index",
        ))?;
    if report.reproducer_public_key != member.public_key {
        return Err(ProductionDoryV3ModelReproductionReportError::Context(
            "reproducer public key",
        ));
    }
    let reference = genesis
        .reference_binaries
        .iter()
        .find(|binary| binary.target_id == report.target_id)
        .ok_or(ProductionDoryV3ModelReproductionReportError::Context(
            "target is not pinned by genesis",
        ))?;
    if report.implementation_kind == ProductionDoryV3ReproductionImplementationKind::Reference
        && (report.combiner_binary.blake3 != reference.binary_blake3
            || report.combiner_binary.sha256 != reference.binary_sha256)
    {
        return Err(ProductionDoryV3ModelReproductionReportError::Context(
            "reference combiner binary",
        ));
    }
    Ok(())
}

fn verify_combiner_context(
    report: &ProductionDoryV3ModelReproductionReport,
    transcript: &VerifiedCeremonyTranscript,
    combined: &ValidatedProductionDoryV3ModelCombinedPayload,
    bindings: &VerifiedCombinerBindings,
) -> Result<(), ProductionDoryV3ModelReproductionReportError> {
    let combined = combined.report();
    if report.reveal_set_prefix_bytes != transcript.transcript_bytes()
        || report.reveal_set_prefix_derive_key_digest != transcript.transcript_derive_key_digest()
        || report.reveal_set_prefix_blake3 != transcript.transcript_blake3()
        || report.reveal_set_prefix_sha256 != transcript.transcript_sha256()
        || combined.ceremony_id.into_bytes() != report.ceremony_id
        || combined.reveal_set_prefix_bytes != report.reveal_set_prefix_bytes
        || combined.reveal_set_prefix_derive_key_digest.into_bytes()
            != report.reveal_set_prefix_derive_key_digest
        || combined.reveal_set_prefix_blake3.into_bytes() != report.reveal_set_prefix_blake3
        || combined.reveal_set_prefix_sha256.into_bytes() != report.reveal_set_prefix_sha256
        || combined.commitment_set_signed_record_digest.into_bytes()
            != report.commitment_set_signed_record_digest
        || combined.reveal_set_signed_record_digest.into_bytes()
            != report.reveal_set_signed_record_digest
        || bindings.ceremony_id() != report.ceremony_id
        || bindings.commitment_set_signed_record_digest()
            != report.commitment_set_signed_record_digest
        || bindings.reveal_set_signed_record_digest() != report.reveal_set_signed_record_digest
    {
        return Err(ProductionDoryV3ModelReproductionReportError::Context(
            "transcript or closure binding",
        ));
    }
    verify_combiner_inputs_against_bindings(&combined.ordered_inputs, bindings)?;
    if combiner_ordered_inputs_digest(&combined.ordered_inputs)?
        != report.combiner_ordered_inputs_digest
    {
        return Err(ProductionDoryV3ModelReproductionReportError::Context(
            "ordered combiner inputs",
        ));
    }
    if combined.output_bytes != report.raw_payload.bytes
        || combined.output_blake3.into_bytes() != report.raw_payload.blake3
        || combined.output_sha256.into_bytes() != report.raw_payload.sha256
        || combined.bytes_processed != report.combine_bytes_processed
        || combined.bytes_processed != combined.output_bytes
    {
        return Err(ProductionDoryV3ModelReproductionReportError::Context(
            "combined payload result",
        ));
    }
    Ok(())
}

fn verify_combiner_inputs_against_bindings(
    inputs: &[ProductionDoryV3ModelCombinerInputReport],
    bindings: &VerifiedCombinerBindings,
) -> Result<(), ProductionDoryV3ModelReproductionReportError> {
    if inputs.len() != bindings.contributions().len() {
        return Err(ProductionDoryV3ModelReproductionReportError::Context(
            "combiner input count",
        ));
    }
    for (index, (input, binding)) in inputs.iter().zip(bindings.contributions()).enumerate() {
        if usize::from(input.operator_index) != index
            || input.operator_index != binding.operator_index()
            || input.operator_public_key.into_bytes() != binding.operator_public_key()
            || input.contribution_bytes != binding.contribution_bytes()
            || input.contribution_blake3.into_bytes() != binding.contribution_blake3()
            || input.contribution_sha256.into_bytes() != binding.contribution_sha256()
            || input
                .contribution_commitment_signed_record_digest
                .into_bytes()
                != binding.contribution_commitment_signed_record_digest()
            || input.contribution_reveal_signed_record_digest.into_bytes()
                != binding.contribution_reveal_signed_record_digest()
        {
            return Err(ProductionDoryV3ModelReproductionReportError::Context(
                "combiner input claim",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use dory_pcs::primitives::{DorySerialize, arithmetic::Field};
    use k256::schnorr::{Signature, SigningKey};

    use super::*;
    use crate::{
        dory_bls12_381_prototype::{
            BlsDoryFr, DeterministicBlsDorySetup, deterministic_bls_dory_setup,
        },
        dory_v3_model_ceremony_transcript::{
            AbortBody, CEREMONY_PROTOCOL_VERSION, CeremonyTranscriptStatus, CommitmentSetBody,
            ContributionCommitmentBody, ContributionRevealBody, IndexedRecordDigest,
            PRODUCTION_BANK_FORMAT_VERSION, PRODUCTION_BANK_HEADER_BYTES,
            PRODUCTION_MAX_MODEL_BYTE, ReferenceBinary, ReproducerReceipt, RevealSetBody,
            RosterMember, SignedCeremonyRecord, SignerClass, ceremony_record_content_digest,
            ceremony_record_signature_message, encode_and_verify_ceremony_transcript,
            encode_and_verify_reveal_set_prefix, parse_and_verify_ceremony_transcript,
            parse_and_verify_reveal_set_prefix,
        },
        dory_v3_model_combiner::ProductionDoryV3ModelCombinedPayloadValidationReport,
        dory_v3_suite::Digest32,
    };

    struct Fixture {
        transcript: VerifiedCeremonyTranscript,
        combined: ValidatedProductionDoryV3ModelCombinedPayload,
        report: ProductionDoryV3ModelReproductionReport,
        claims: ProductionDoryV3ModelReproductionClaims,
        prefix_records: Vec<SignedCeremonyRecord>,
        operators: Vec<SigningKey>,
        reproducers: Vec<SigningKey>,
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
                    crate::dory_v3_model_ceremony_transcript::RecordSignature {
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

    fn fixture() -> Fixture {
        let operators = keys(3, 1);
        let reproducers = keys(2, 20);
        let operator_signers: Vec<_> = operators
            .iter()
            .enumerate()
            .map(|(index, key)| (SignerClass::Operator, index as u16, key))
            .collect();
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
                generation_finished_unix_seconds: 100 + index as u64,
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
        let combined_report = ProductionDoryV3ModelCombinedPayloadValidationReport {
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
            output_bytes: PRODUCTION_PAYLOAD_BYTES,
            output_blake3: Digest32::new([110; 32]),
            output_sha256: Digest32::new([111; 32]),
            bytes_processed: PRODUCTION_PAYLOAD_BYTES,
            elapsed_micros: 101,
        };
        let combined =
            ValidatedProductionDoryV3ModelCombinedPayload::from_report_for_test(combined_report);
        let setup = deterministic_bls_dory_setup(3).unwrap();
        let claims = ProductionDoryV3ModelReproductionClaims {
            reproducer_index: 0,
            implementation_kind: ProductionDoryV3ReproductionImplementationKind::Reference,
            target_id: 1,
            combiner_binary: sized_file(4_096, 13),
            combiner_report: file(20),
            bootstrap_report: file(21),
            record_ceremony_report: file(22),
            host_environment_report: file(23),
            source_extraction_report: file(24),
            command_log: file(25),
            implementation_lineage_report: file(26),
            roots_file: sized_file(PRODUCTION_DORY_V3_MODEL_ROOTS_BYTES as u64, 27),
            structural_report: sized_file(
                PRODUCTION_DORY_V3_MODEL_STRUCTURAL_REPORT_BYTES as u64,
                28,
            ),
            bank_file: sized_file(PRODUCTION_BANK_BYTES, 29),
            manifest_file: file(30),
            record_v2_file: file(31),
            base_input_blake3_root: [112; 32],
            layer_roots_aggregate: [113; 32],
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
        let verified = author_and_verify_production_dory_v3_model_reproduction_report(
            &transcript,
            &combined,
            claims.clone(),
        )
        .unwrap();
        let report = verified.report().clone();
        Fixture {
            transcript,
            combined,
            report,
            claims,
            prefix_records,
            operators,
            reproducers,
        }
    }

    fn completed_transcript(fixture: &Fixture) -> VerifiedCeremonyTranscript {
        let report = &fixture.report;
        let mut records = fixture.prefix_records.clone();
        let final_receipt = crate::dory_v3_model_ceremony_transcript::FinalReceiptBody {
            ceremony_id: report.ceremony_id,
            commitment_set_signed_record_digest: report.commitment_set_signed_record_digest,
            reveal_set_signed_record_digest: report.reveal_set_signed_record_digest,
            payload_bytes: report.raw_payload.bytes,
            raw_payload_blake3: report.raw_payload.blake3,
            raw_payload_sha256: report.raw_payload.sha256,
            base_input_blake3_root: report.base_input_blake3_root,
            layer_roots_aggregate: report.layer_roots_aggregate,
            roots_file: report.roots_file.clone(),
            structural_report: report.structural_report.clone(),
            bank_bytes: report.bank_file.bytes,
            bank_file_blake3: report.bank_file.blake3,
            bank_file_sha256: report.bank_file.sha256,
            manifest_file: report.manifest_file.clone(),
            manifest_digest: report.manifest_digest,
            production_suite_digest: report.production_suite_digest,
            pcs_parameter_digest: report.pcs_parameter_digest,
            base_commitment: report.base_commitment,
            weight_bank_0_commitment: report.weight_bank_0_commitment,
            weight_bank_1_commitment: report.weight_bank_1_commitment,
            weight_bank_2_commitment: report.weight_bank_2_commitment,
            pcs_commitment_root: report.pcs_commitment_root,
            model_identity_digest: report.model_identity_digest,
            setup_identity: report.setup_identity,
            padded_variables: report.padded_variables,
            record_v2_file: report.record_v2_file.clone(),
            record_v2_digest: report.record_v2_digest,
            publisher_reproducer_index: 0,
            reproducers: vec![
                ReproducerReceipt {
                    index: report.reproducer_index,
                    combiner_binary_blake3: report.combiner_binary.blake3,
                    combiner_binary_sha256: report.combiner_binary.sha256,
                    bootstrap_report: report.bootstrap_report.clone(),
                    record_ceremony_report: report.record_ceremony_report.clone(),
                    reproduction_report: report.content_identity(),
                },
                ReproducerReceipt {
                    index: 1,
                    combiner_binary_blake3: [120; 32],
                    combiner_binary_sha256: [121; 32],
                    bootstrap_report: file(122),
                    record_ceremony_report: file(123),
                    reproduction_report: sized_file(
                        PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES as u64,
                        124,
                    ),
                },
            ],
        };
        records.push(sign_record(
            CeremonyRecordBody::FinalReceipt(Box::new(final_receipt)),
            &all_signers(&fixture.operators, &fixture.reproducers),
        ));
        let bytes = encode_and_verify_ceremony_transcript(&records).unwrap();
        parse_and_verify_ceremony_transcript(&bytes).unwrap()
    }

    fn aborted_transcript(fixture: &Fixture) -> VerifiedCeremonyTranscript {
        let mut records = fixture.prefix_records.clone();
        let previous = ceremony_signed_record_digest(records.last().unwrap()).unwrap();
        records.push(sign_record(
            CeremonyRecordBody::Abort(AbortBody {
                ceremony_id: fixture.report.ceremony_id,
                last_valid_signed_record_digest: previous,
                phase: 4,
                reason_code: 12,
                evidence_file: file(125),
            }),
            &[(SignerClass::Operator, 0, &fixture.operators[0])],
        ));
        let bytes = encode_and_verify_ceremony_transcript(&records).unwrap();
        parse_and_verify_ceremony_transcript(&bytes).unwrap()
    }

    fn assert_invalid_report(report: &ProductionDoryV3ModelReproductionReport) {
        assert!(matches!(
            parse_production_dory_v3_model_reproduction_report(&encode_report(report)),
            Err(ProductionDoryV3ModelReproductionReportError::Invalid(_))
        ));
    }

    fn assert_context_mismatch(
        report: &ProductionDoryV3ModelReproductionReport,
        fixture: &Fixture,
    ) {
        assert!(matches!(
            verify_production_dory_v3_model_reproduction_report(
                &encode_report(report),
                &fixture.transcript,
                &fixture.combined,
            ),
            Err(ProductionDoryV3ModelReproductionReportError::Context(_))
        ));
    }

    #[test]
    fn fixed_width_codec_round_trip_and_known_answer() {
        let fixture = fixture();
        let bytes = fixture.report.canonical_bytes();
        assert_eq!(
            bytes.len(),
            PRODUCTION_DORY_V3_MODEL_REPRODUCTION_REPORT_BYTES
        );
        assert_eq!(&bytes[..8], b"CMFDRP01");
        assert_eq!(&bytes[8..10], &1_u16.to_le_bytes());
        assert_eq!(&bytes[10..14], &4_283_u32.to_le_bytes());
        let parsed = parse_production_dory_v3_model_reproduction_report(&bytes).unwrap();
        assert_eq!(parsed, fixture.report);
        assert_eq!(parsed.canonical_bytes(), bytes);
        let identity = parsed.content_identity();
        assert_eq!(identity.bytes, 4_283);
        assert_eq!(
            hex::encode(identity.blake3),
            "02f8dbe453b7f82dd22c760f0eaef1226a7d04207308799277bb4b5e53962783"
        );
        assert_eq!(
            hex::encode(identity.sha256),
            "1c72f02f887149490b5cf2fea05b328202d02461664601171b31e06c91e41fb4"
        );
    }

    #[test]
    fn authoring_derives_authority_and_exposes_immutable_projections() {
        let fixture = fixture();
        let verified = author_and_verify_production_dory_v3_model_reproduction_report(
            &fixture.transcript,
            &fixture.combined,
            fixture.claims.clone(),
        )
        .unwrap();
        let report = verified.report();
        assert_eq!(report.ceremony_id(), fixture.transcript.ceremony_id());
        assert_eq!(report.target_id(), 1);
        assert_eq!(
            verified.artifacts().combiner_report,
            &fixture.claims.combiner_report
        );
        assert_eq!(
            verified.final_candidate().raw_payload.bytes,
            PRODUCTION_PAYLOAD_BYTES
        );
        let fixture_verified = verify_production_dory_v3_model_reproduction_report(
            &fixture.report.canonical_bytes(),
            &fixture.transcript,
            &fixture.combined,
        )
        .unwrap();
        assert!(verified.same_final_candidate(&fixture_verified));

        let mut independent = fixture.claims;
        independent.implementation_kind =
            ProductionDoryV3ReproductionImplementationKind::Independent;
        independent.combiner_binary = file(200);
        assert!(
            author_and_verify_production_dory_v3_model_reproduction_report(
                &fixture.transcript,
                &fixture.combined,
                independent,
            )
            .is_ok()
        );
    }

    #[test]
    fn public_combiner_report_is_not_the_reproduction_authority_type() {
        type VerifyFn = fn(
            &[u8],
            &VerifiedCeremonyTranscript,
            &ValidatedProductionDoryV3ModelCombinedPayload,
        ) -> Result<
            ContextVerifiedProductionDoryV3ModelReproductionReport,
            ProductionDoryV3ModelReproductionReportError,
        >;
        type AuthorFn = fn(
            &VerifiedCeremonyTranscript,
            &ValidatedProductionDoryV3ModelCombinedPayload,
            ProductionDoryV3ModelReproductionClaims,
        ) -> Result<
            ContextVerifiedProductionDoryV3ModelReproductionReport,
            ProductionDoryV3ModelReproductionReportError,
        >;

        let fixture = fixture();
        let raw_operational_report: ProductionDoryV3ModelCombinedPayloadValidationReport =
            fixture.combined.report().clone();
        assert_eq!(
            raw_operational_report.output_blake3,
            fixture.combined.report().output_blake3
        );
        let _: VerifyFn = verify_production_dory_v3_model_reproduction_report;
        let _: AuthorFn = author_and_verify_production_dory_v3_model_reproduction_report;
    }

    #[test]
    fn codec_rejects_bad_framing_discriminants_and_file_identities() {
        let fixture = fixture();
        let bytes = fixture.report.canonical_bytes();

        let mut bad_magic = bytes;
        bad_magic[0] ^= 1;
        assert_eq!(
            parse_production_dory_v3_model_reproduction_report(&bad_magic),
            Err(ProductionDoryV3ModelReproductionReportError::InvalidMagic)
        );
        let mut bad_version = bytes;
        bad_version[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            parse_production_dory_v3_model_reproduction_report(&bad_version),
            Err(ProductionDoryV3ModelReproductionReportError::UnsupportedVersion(2))
        );
        let mut bad_declared_length = bytes;
        bad_declared_length[10..14].copy_from_slice(&4_282_u32.to_le_bytes());
        assert!(matches!(
            parse_production_dory_v3_model_reproduction_report(&bad_declared_length),
            Err(ProductionDoryV3ModelReproductionReportError::Invalid(
                "declared report length"
            ))
        ));
        assert!(matches!(
            parse_production_dory_v3_model_reproduction_report(&bytes[..bytes.len() - 1]),
            Err(ProductionDoryV3ModelReproductionReportError::ReportLength { .. })
        ));
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(matches!(
            parse_production_dory_v3_model_reproduction_report(&trailing),
            Err(ProductionDoryV3ModelReproductionReportError::ReportLength { .. })
        ));

        let mut reserved_kind = bytes;
        reserved_kind[112] = 2;
        assert!(matches!(
            parse_production_dory_v3_model_reproduction_report(&reserved_kind),
            Err(ProductionDoryV3ModelReproductionReportError::Invalid(
                "reserved implementation kind"
            ))
        ));
        let mut bad_target = bytes;
        bad_target[113..115].copy_from_slice(&0_u16.to_le_bytes());
        assert!(matches!(
            parse_production_dory_v3_model_reproduction_report(&bad_target),
            Err(ProductionDoryV3ModelReproductionReportError::Invalid(
                "target id"
            ))
        ));
        let mut zero_length = bytes;
        zero_length[135..143].fill(0);
        assert!(matches!(
            parse_production_dory_v3_model_reproduction_report(&zero_length),
            Err(ProductionDoryV3ModelReproductionReportError::Invalid(
                "zero-length file identity"
            ))
        ));
        let mut zero_blake3 = bytes;
        zero_blake3[143..175].fill(0);
        assert!(matches!(
            parse_production_dory_v3_model_reproduction_report(&zero_blake3),
            Err(ProductionDoryV3ModelReproductionReportError::Invalid(
                "zero digest in file identity"
            ))
        ));
        let mut zero_sha256 = bytes;
        zero_sha256[175..207].fill(0);
        assert!(matches!(
            parse_production_dory_v3_model_reproduction_report(&zero_sha256),
            Err(ProductionDoryV3ModelReproductionReportError::Invalid(
                "zero digest in file identity"
            ))
        ));
    }

    #[test]
    fn codec_rejects_nonproduction_constants_and_inconsistent_derivations() {
        let fixture = fixture();
        let mut report = fixture.report.clone();
        report.raw_payload.bytes += 1;
        assert_invalid_report(&report);
        report = fixture.report.clone();
        report.roots_file.bytes += 1;
        assert_invalid_report(&report);
        report = fixture.report.clone();
        report.structural_report.bytes += 1;
        assert_invalid_report(&report);
        report = fixture.report.clone();
        report.bank_file.bytes += 1;
        assert_invalid_report(&report);
        report = fixture.report.clone();
        report.combine_bytes_processed -= 1;
        assert_invalid_report(&report);
        report = fixture.report.clone();
        report.production_suite_digest[0] ^= 1;
        assert_invalid_report(&report);
        report = fixture.report.clone();
        report.setup_identity[0] ^= 1;
        assert_invalid_report(&report);
        report = fixture.report.clone();
        report.padded_variables -= 1;
        assert_invalid_report(&report);
        report = fixture.report.clone();
        report.manifest_digest[0] ^= 1;
        assert_invalid_report(&report);
        report = fixture.report.clone();
        report.record_v2_digest[0] ^= 1;
        assert_invalid_report(&report);
        report = fixture.report.clone();
        report.weight_bank_0_commitment = report.base_commitment;
        assert_invalid_report(&report);
        report = fixture.report;
        report.roots_elapsed_micros = 0;
        assert_invalid_report(&report);
    }

    #[test]
    fn contextual_verifier_matches_sealed_bindings_and_live_combiner_semantics() {
        let fixture = fixture();
        assert!(
            verify_production_dory_v3_model_reproduction_report(
                &fixture.report.canonical_bytes(),
                &fixture.transcript,
                &fixture.combined,
            )
            .is_ok()
        );

        let mut report = fixture.report.clone();
        report.ceremony_id = [201; 32];
        assert_context_mismatch(&report, &fixture);
        report = fixture.report.clone();
        report.genesis_signed_record_digest = [202; 32];
        assert_context_mismatch(&report, &fixture);
        report = fixture.report.clone();
        report.reproducer_index = 1;
        assert_context_mismatch(&report, &fixture);
        report = fixture.report.clone();
        report.source_bundle.blake3 = [203; 32];
        assert_context_mismatch(&report, &fixture);
        report = fixture.report.clone();
        report.reveal_set_prefix_blake3 = [204; 32];
        assert_context_mismatch(&report, &fixture);
        report = fixture.report.clone();
        report.commitment_set_signed_record_digest = [205; 32];
        assert_context_mismatch(&report, &fixture);
        report = fixture.report.clone();
        report.combiner_ordered_inputs_digest = [206; 32];
        assert_context_mismatch(&report, &fixture);
        report = fixture.report.clone();
        report.combiner_binary.blake3 = [207; 32];
        assert_context_mismatch(&report, &fixture);
        report = fixture.report.clone();
        report.target_id = 2;
        assert_context_mismatch(&report, &fixture);

        let mut combined_report = fixture.combined.report().clone();
        combined_report.ordered_inputs[0].contribution_sha256 = Digest32::new([208; 32]);
        let combined =
            ValidatedProductionDoryV3ModelCombinedPayload::from_report_for_test(combined_report);
        assert!(matches!(
            verify_production_dory_v3_model_reproduction_report(
                &fixture.report.canonical_bytes(),
                &fixture.transcript,
                &combined,
            ),
            Err(ProductionDoryV3ModelReproductionReportError::Context(_))
        ));
        let mut combined_report = fixture.combined.report().clone();
        combined_report.output_sha256 = Digest32::new([209; 32]);
        let combined =
            ValidatedProductionDoryV3ModelCombinedPayload::from_report_for_test(combined_report);
        assert!(matches!(
            verify_production_dory_v3_model_reproduction_report(
                &fixture.report.canonical_bytes(),
                &fixture.transcript,
                &combined,
            ),
            Err(ProductionDoryV3ModelReproductionReportError::Context(_))
        ));
    }

    #[test]
    fn combiner_json_is_opaque_but_its_exact_file_identity_is_bound() {
        let fixture = fixture();
        let mut alternate = fixture.report.clone();
        alternate.combiner_report = file(210);
        let verified = verify_production_dory_v3_model_reproduction_report(
            &alternate.canonical_bytes(),
            &fixture.transcript,
            &fixture.combined,
        )
        .unwrap();
        assert_ne!(
            verified.report().content_identity(),
            fixture.report.content_identity()
        );
        let original = verify_production_dory_v3_model_reproduction_report(
            &fixture.report.canonical_bytes(),
            &fixture.transcript,
            &fixture.combined,
        )
        .unwrap();
        assert!(verified.same_final_candidate(&original));
    }

    #[test]
    fn completed_and_aborted_transcripts_cannot_authorize_reproduction_reports() {
        let fixture = fixture();
        let completed = completed_transcript(&fixture);
        assert_eq!(completed.status(), CeremonyTranscriptStatus::Completed);
        assert!(matches!(
            verify_production_dory_v3_model_reproduction_report(
                &fixture.report.canonical_bytes(),
                &completed,
                &fixture.combined,
            ),
            Err(ProductionDoryV3ModelReproductionReportError::Transcript(_))
        ));
        assert!(matches!(
            author_and_verify_production_dory_v3_model_reproduction_report(
                &completed,
                &fixture.combined,
                fixture.claims.clone(),
            ),
            Err(ProductionDoryV3ModelReproductionReportError::Transcript(_))
        ));

        let aborted = aborted_transcript(&fixture);
        assert_eq!(aborted.status(), CeremonyTranscriptStatus::Aborted);
        assert!(matches!(
            verify_production_dory_v3_model_reproduction_report(
                &fixture.report.canonical_bytes(),
                &aborted,
                &fixture.combined,
            ),
            Err(ProductionDoryV3ModelReproductionReportError::Transcript(_))
        ));
    }
}
