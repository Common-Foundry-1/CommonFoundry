//! Frozen parameter manifest for the proposed Dory-native ForgeMatrix V3 path.
//!
//! This module deliberately has no dependency on the legacy WHIR
//! `ModelPcsIdentity` namespace. The Dory-native model identity starts at its
//! own version 1, while its commitment record starts at version 2 so a V1
//! record can never be reinterpreted.
//!
//! The component parameter digests use explicit labelled descriptors. Values
//! with implemented owners are consumed directly or checked by the owner-map
//! test. Values that describe future V3 transcripts, layout V5, or binding V2
//! remain explicit activation blockers until those owners exist.

use std::{fmt, sync::LazyLock};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor};

pub const DORY_V3_SUITE_MANIFEST_VERSION: u16 = 1;
pub const DORY_V3_POW_TYPE: u16 = 3;
pub const DORY_V3_ALGORITHM_VERSION: u32 = 2;
pub const DORY_V3_PROOF_VERSION: u32 = 1;
pub const DORY_V3_MODEL_BANK_FORMAT_VERSION: u32 = 2;
/// A new namespace; this is not `MODEL_PCS_IDENTITY_VERSION`.
pub const DORY_V3_MODEL_IDENTITY_VERSION: u16 = 1;
/// Version 1 remains the legacy WHIR-input record.
pub const DORY_V3_MODEL_RECORD_VERSION: u16 = 2;
/// Fixed transcript length hashed by the Dory-native model commitment record.
pub const DORY_V3_MODEL_RECORD_CANONICAL_BYTES: u32 = 166;
pub const DORY_V3_MODEL_RECORD_DIGEST_FIELDS: &str = "record_version_u16le,suite_digest[32],manifest_digest[32],model_identity_digest[32],setup_identity[32],padded_variables_u32le,commitment_root[32]";
pub const DORY_V3_MODEL_RECORD_JSON_FIELDS: &str = "record_version,suite_digest,manifest,manifest_digest,model_identity,model_identity_digest,setup_identity,padded_variables,commitment_root,record_digest; JSON audit-only; unknown/duplicate fields reject; top-level digest fields use lowercase hex; nested manifest byte arrays and identity commitment encodings retain their own strict codecs; JSON bytes not consensus hashed";
pub const DORY_V3_SETUP_VERSION: u16 = 1;
pub const DORY_V3_TRANSCRIPT_VERSION: u16 = 2;
pub const DORY_V3_AGGREGATE_VERSION: u16 = 1;
pub const DORY_V3_MATRIX_VERSION: u16 = 1;
pub const DORY_V3_TRANSITION_VERSION: u16 = 2;
pub const DORY_V3_RANGE_LOGUP_VERSION: u16 = 3;
pub const DORY_V3_WIRING_VERSION: u16 = 1;
pub const DORY_V3_OUTPUT_BRIDGE_VERSION: u16 = 1;
/// Version 5 is the first layout that binds the Dory-native model identity.
pub const DORY_V3_SHARED_LAYOUT_VERSION: u16 = 5;
pub const DORY_V3_NATIVE_COMPOSITION_VERSION: u16 = 1;
pub const DORY_V3_BLAKE3_PROJECTION_VERSION: u16 = 2;
pub const DORY_V3_BLAKE3_NATIVE_PROOF_VERSION: u16 = 1;
pub const DORY_V3_BLAKE3_PREPROCESSING_RECORD_VERSION: u16 = 1;
pub const DORY_V3_FIXED_MODEL_BINDING_VERSION: u16 = 2;
pub const DORY_V3_ALGEBRAIC_BINDING_VERSION: u16 = 2;
pub const DORY_V3_CANDIDATE_PAYLOAD_VERSION: u16 =
    crate::dory_bls12_381_candidate::CANDIDATE_PAYLOAD_VERSION;
pub const DORY_V3_CANDIDATE_PAYLOAD_MAGIC: [u8; 8] =
    crate::dory_bls12_381_candidate::CANDIDATE_PAYLOAD_MAGIC;
pub const DORY_V3_CANDIDATE_PAYLOAD_HEADER_BYTES: u32 =
    crate::dory_bls12_381_candidate::CANDIDATE_PAYLOAD_HEADER_BYTES as u32;
pub const DORY_V3_WIRE_TAG: u8 = 3;

pub const DORY_V3_MODEL_VERSION: u32 = 2;
pub const DORY_V3_BATCH: u32 = 128;
pub const DORY_V3_DIMENSION: u32 = 4_096;
pub const DORY_V3_LAYERS: u32 = 384;
pub const DORY_V3_BANKS: u32 = 3;
pub const DORY_V3_LAYERS_PER_BANK: u32 = 128;
pub const DORY_V3_PADDED_VARIABLES: u32 = 33;
pub const DORY_V3_GT_CANONICAL_BYTES: u32 = 576;
pub const DORY_V3_MAX_PROOF_BYTES: u32 = 256 * 1_024;
pub const DORY_V3_MAX_STRUCTURED_PROOF_BYTES: u32 = 261_947;

pub const DORY_V3_SUITE_CANONICAL_BYTES: usize = 345;

pub const DORY_V3_SUITE_DIGEST_DOMAIN: &str = "CMFD/FORGEMATRIX/V3/DORY-CONSENSUS-SUITE/V1";
pub const DORY_V3_RELATION_PARAMETERS_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/SUITE/RELATION-PARAMETERS/V1";
pub const DORY_V3_MODEL_CODEC_PARAMETERS_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/SUITE/MODEL-CODEC-PARAMETERS/V1";
pub const DORY_V3_BACKEND_PARAMETERS_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/SUITE/DORY-BACKEND-PARAMETERS/V1";
pub const DORY_V3_SHARED_ALGEBRA_PARAMETERS_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/SUITE/SHARED-ALGEBRA-PARAMETERS/V1";
pub const DORY_V3_NATIVE_BLAKE3_PARAMETERS_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/SUITE/NATIVE-BLAKE3-PARAMETERS/V1";
pub const DORY_V3_CANDIDATE_CODEC_PARAMETERS_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/SUITE/CANDIDATE-CODEC-PARAMETERS/V1";

pub const DORY_V3_CHALLENGE_DOMAIN: &str = "CMFD/FORGEMATRIX/CHALLENGE/V3-DORY/V1";
pub const DORY_V3_MASK_DOMAIN: &str = "CMFD/FORGEMATRIX/MASKCOEFF/V3-DORY/V1";
pub const DORY_V3_OUTPUT_DOMAIN: &str = "CMFD/FORGEMATRIX/OUTPUT/V3-DORY/V1";
pub const DORY_V3_WORK_DOMAIN: &str = "CMFD/FORGEMATRIX/WORK/V3-DORY/V1";
pub const DORY_V3_MODEL_COMMITMENT_ROOT_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/DORY-MODEL-COMMITMENTS/V1";
pub const DORY_V3_MODEL_IDENTITY_DOMAIN: &str = "CMFD/FORGEMATRIX/V3/DORY-MODEL-IDENTITY/V1";
pub const DORY_V3_MODEL_RECORD_DOMAIN: &str = "CMFD/FORGEMATRIX/V3/DORY-MODEL-COMMITMENT-RECORD/V2";
pub const DORY_V3_FIXED_MODEL_BINDING_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/DORY-FIXED-MODEL-BINDING/V2";
pub const DORY_V3_FIXED_MODEL_BINDING_FIELDS: &str = "binding_version_u16le,shared_layout_version_u16le,suite_digest[32],model_identity_digest[32],setup_identity[32],padded_variables_u32le,outer_binding_length_u32le,outer_binding[outer_binding_length]";
pub const DORY_V3_SHARED_OPENING_BINDING_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/DORY-SHARED-OPENING-BINDING/V5";
pub const DORY_V3_SHARED_OPENING_BINDING_FIELDS: &str = "shared_layout_version_u16le,padded_variables_u32le,setup_identity[32],component_binding[32],matrix_count_u16le,then each matrix_transcript_digest[32],transition_count_u16le,then each arithmetic_transcript_digest[32],range_transcript_digest[32],wiring_transcript_digest[32]";
pub const DORY_V3_NATIVE_COMPOSITION_BINDING_DOMAIN: &str =
    "CMFD/FORGEMATRIX/V3/DORY-NATIVE-COMPOSITION-BINDING/V1";
pub const DORY_V3_NATIVE_COMPOSITION_BINDING_FIELDS: &str = "shared_layout_version_u16le,native_composition_version_u16le,dory_nu_u16le,dory_sigma_u16le,setup_identity[32],shared_opening_binding[32],native_opening_binding[32]";
pub const DORY_V3_ALGEBRAIC_BINDING_DOMAIN: &str = "CMFD/FORGEMATRIX/V3/DORY-ALGEBRAIC-BINDING/V2";

pub const DORY_V3_SETUP_IDENTITY: Digest32 = Digest32::new([
    0x75, 0xfd, 0x3d, 0xac, 0xdd, 0xba, 0x30, 0x68, 0x2d, 0x1e, 0xab, 0xd5, 0xd8, 0xd2, 0x92, 0x44,
    0x66, 0xd7, 0x21, 0x4b, 0x01, 0x1a, 0x7e, 0xcc, 0x48, 0xba, 0x27, 0x82, 0x1c, 0xbb, 0xf6, 0x12,
]);
pub const DORY_V3_BLAKE3_PREPROCESSING_RECORD_DIGEST: Digest32 = Digest32::new([
    0x98, 0x7a, 0xcd, 0x2e, 0xca, 0x3e, 0x41, 0xbb, 0xc2, 0xab, 0xbd, 0xf6, 0xf9, 0x1a, 0x5f, 0x7b,
    0xa9, 0x07, 0x55, 0x52, 0x33, 0x35, 0x3e, 0xda, 0x10, 0x9c, 0x28, 0x11, 0x4b, 0xb4, 0xb8, 0xb1,
]);

/// Integration properties enforced by owner-map, codec, and release-gate tests.
/// Entries naming future V3 owners remain activation blockers until implemented.
pub const DORY_V3_REQUIRED_INTEGRATION_ASSERTIONS: &[&str] = &[
    "wire tag and both proof limits equal the constants in wire.rs",
    "production geometry and integer relation equal forgematrix_v2.rs",
    "n=33 setup identity is rederived by dory_bls12_381_prototype.rs",
    "component versions and claim order equal every Dory proof module",
    "native BLAKE3 geometry and preprocessing pin equal dory_bls12_381_blake3.rs",
    "candidate payload grammar equals dory_bls12_381_candidate.rs after its V2 binding bump",
    "model commitment record V2 uses the exact canonical transcript pinned by the model codec",
];

/// The suite is a pinned migration target, not an activation signal.
pub const DORY_V3_SUITE_ACTIVATION_READY: bool = false;
pub const DORY_V3_SUITE_ACTIVATION_BLOCKERS: &[&str] = &[
    "the canonical production model bank ceremony has not been independently reproduced and its V2 record pinned",
    "the unchanged production n=33 proof has not passed the benchmark and review gates",
];

/// A fixed 32-byte digest with strict lowercase-hex JSON encoding.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(HEX[usize::from(byte >> 4)] as char);
            output.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        output
    }

    fn from_lower_hex(encoded: &str) -> Result<Self, &'static str> {
        if encoded.len() != 64 || !encoded.is_ascii() {
            return Err("digest must contain exactly 64 lowercase hexadecimal characters");
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
            let high = lower_hex_nibble(pair[0])?;
            let low = lower_hex_nibble(pair[1])?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Digest32")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for Digest32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

struct Digest32Visitor;

impl Visitor<'_> for Digest32Visitor {
    type Value = Digest32;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("exactly 64 lowercase hexadecimal characters")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Digest32::from_lower_hex(value).map_err(E::custom)
    }
}

impl<'de> Deserialize<'de> for Digest32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Digest32Visitor)
    }
}

fn lower_hex_nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("digest must use lowercase hexadecimal"),
    }
}

/// Complete network-independent identity of the intended Dory-native V3 suite.
///
/// JSON is an audit representation only. Consensus hashes the fixed-width
/// [`Self::canonical_bytes`] encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoryV3ConsensusSuiteManifestV1 {
    pub manifest_version: u16,
    pub pow_type: u16,
    pub algorithm_version: u32,
    pub proof_version: u32,
    pub model_bank_format_version: u32,
    pub model_identity_version: u16,
    pub model_record_version: u16,
    pub setup_version: u16,
    pub transcript_version: u16,
    pub aggregate_version: u16,
    pub matrix_version: u16,
    pub transition_version: u16,
    pub range_logup_version: u16,
    pub wiring_version: u16,
    pub output_bridge_version: u16,
    pub shared_layout_version: u16,
    pub native_composition_version: u16,
    pub blake3_projection_version: u16,
    pub blake3_native_proof_version: u16,
    pub blake3_preprocessing_record_version: u16,
    pub fixed_model_binding_version: u16,
    pub algebraic_binding_version: u16,
    pub candidate_payload_version: u16,
    pub wire_tag: u8,
    pub model_version: u32,
    pub batch: u32,
    pub dimension: u32,
    pub layers: u32,
    pub banks: u32,
    pub layers_per_bank: u32,
    pub padded_variables: u32,
    pub max_proof_bytes: u32,
    pub max_structured_proof_bytes: u32,
    pub setup_identity: Digest32,
    pub blake3_preprocessing_record_digest: Digest32,
    pub relation_parameters_digest: Digest32,
    pub model_codec_parameters_digest: Digest32,
    pub dory_backend_parameters_digest: Digest32,
    pub shared_algebra_parameters_digest: Digest32,
    pub native_blake3_parameters_digest: Digest32,
    pub candidate_codec_parameters_digest: Digest32,
}

pub static DORY_V3_PRODUCTION_SUITE_MANIFEST: LazyLock<DoryV3ConsensusSuiteManifestV1> =
    LazyLock::new(production_dory_v3_suite_manifest);
/// Consensus identity of [`DORY_V3_PRODUCTION_SUITE_MANIFEST`].
pub static DORY_V3_PRODUCTION_SUITE_DIGEST: LazyLock<Digest32> =
    LazyLock::new(|| DORY_V3_PRODUCTION_SUITE_MANIFEST.digest());
/// Audit handle for the model-commitment parameters absorbed by the suite.
///
/// The model identity and model-bank manifest bind the top-level suite digest,
/// so this component is transitively committed rather than copied into a
/// second manifest field. The model module must not define another codec or
/// PCS-suite derivation.
pub static DORY_V3_PRODUCTION_MODEL_COMMITMENT_PARAMETERS_DIGEST: LazyLock<Digest32> =
    LazyLock::new(|| DORY_V3_PRODUCTION_SUITE_MANIFEST.model_codec_parameters_digest);

pub fn compiled_production_dory_v3_suite() -> &'static DoryV3ConsensusSuiteManifestV1 {
    &DORY_V3_PRODUCTION_SUITE_MANIFEST
}

pub fn production_dory_v3_suite_digest() -> Digest32 {
    *DORY_V3_PRODUCTION_SUITE_DIGEST
}

pub fn production_dory_v3_model_commitment_parameters_digest() -> Digest32 {
    *DORY_V3_PRODUCTION_MODEL_COMMITMENT_PARAMETERS_DIGEST
}

pub fn production_dory_v3_suite_manifest() -> DoryV3ConsensusSuiteManifestV1 {
    DoryV3ConsensusSuiteManifestV1 {
        manifest_version: DORY_V3_SUITE_MANIFEST_VERSION,
        pow_type: DORY_V3_POW_TYPE,
        algorithm_version: DORY_V3_ALGORITHM_VERSION,
        proof_version: DORY_V3_PROOF_VERSION,
        model_bank_format_version: DORY_V3_MODEL_BANK_FORMAT_VERSION,
        model_identity_version: DORY_V3_MODEL_IDENTITY_VERSION,
        model_record_version: DORY_V3_MODEL_RECORD_VERSION,
        setup_version: DORY_V3_SETUP_VERSION,
        transcript_version: DORY_V3_TRANSCRIPT_VERSION,
        aggregate_version: DORY_V3_AGGREGATE_VERSION,
        matrix_version: DORY_V3_MATRIX_VERSION,
        transition_version: DORY_V3_TRANSITION_VERSION,
        range_logup_version: DORY_V3_RANGE_LOGUP_VERSION,
        wiring_version: DORY_V3_WIRING_VERSION,
        output_bridge_version: DORY_V3_OUTPUT_BRIDGE_VERSION,
        shared_layout_version: DORY_V3_SHARED_LAYOUT_VERSION,
        native_composition_version: DORY_V3_NATIVE_COMPOSITION_VERSION,
        blake3_projection_version: DORY_V3_BLAKE3_PROJECTION_VERSION,
        blake3_native_proof_version: DORY_V3_BLAKE3_NATIVE_PROOF_VERSION,
        blake3_preprocessing_record_version: DORY_V3_BLAKE3_PREPROCESSING_RECORD_VERSION,
        fixed_model_binding_version: DORY_V3_FIXED_MODEL_BINDING_VERSION,
        algebraic_binding_version: DORY_V3_ALGEBRAIC_BINDING_VERSION,
        candidate_payload_version: DORY_V3_CANDIDATE_PAYLOAD_VERSION,
        wire_tag: DORY_V3_WIRE_TAG,
        model_version: DORY_V3_MODEL_VERSION,
        batch: DORY_V3_BATCH,
        dimension: DORY_V3_DIMENSION,
        layers: DORY_V3_LAYERS,
        banks: DORY_V3_BANKS,
        layers_per_bank: DORY_V3_LAYERS_PER_BANK,
        padded_variables: DORY_V3_PADDED_VARIABLES,
        max_proof_bytes: DORY_V3_MAX_PROOF_BYTES,
        max_structured_proof_bytes: DORY_V3_MAX_STRUCTURED_PROOF_BYTES,
        setup_identity: DORY_V3_SETUP_IDENTITY,
        blake3_preprocessing_record_digest: DORY_V3_BLAKE3_PREPROCESSING_RECORD_DIGEST,
        relation_parameters_digest: relation_parameters_digest(),
        model_codec_parameters_digest: model_codec_parameters_digest(),
        dory_backend_parameters_digest: dory_backend_parameters_digest(),
        shared_algebra_parameters_digest: shared_algebra_parameters_digest(),
        native_blake3_parameters_digest: native_blake3_parameters_digest(),
        candidate_codec_parameters_digest: candidate_codec_parameters_digest(),
    }
}

impl DoryV3ConsensusSuiteManifestV1 {
    /// Encode the manifest without Serde, padding, or platform-sized values.
    pub fn canonical_bytes(&self) -> [u8; DORY_V3_SUITE_CANONICAL_BYTES] {
        let mut encoder = FixedEncoder::new();
        encoder.u16(self.manifest_version);
        encoder.u16(self.pow_type);
        encoder.u32(self.algorithm_version);
        encoder.u32(self.proof_version);
        encoder.u32(self.model_bank_format_version);
        encoder.u16(self.model_identity_version);
        encoder.u16(self.model_record_version);
        encoder.u16(self.setup_version);
        encoder.u16(self.transcript_version);
        encoder.u16(self.aggregate_version);
        encoder.u16(self.matrix_version);
        encoder.u16(self.transition_version);
        encoder.u16(self.range_logup_version);
        encoder.u16(self.wiring_version);
        encoder.u16(self.output_bridge_version);
        encoder.u16(self.shared_layout_version);
        encoder.u16(self.native_composition_version);
        encoder.u16(self.blake3_projection_version);
        encoder.u16(self.blake3_native_proof_version);
        encoder.u16(self.blake3_preprocessing_record_version);
        encoder.u16(self.fixed_model_binding_version);
        encoder.u16(self.algebraic_binding_version);
        encoder.u16(self.candidate_payload_version);
        encoder.u8(self.wire_tag);
        encoder.u32(self.model_version);
        encoder.u32(self.batch);
        encoder.u32(self.dimension);
        encoder.u32(self.layers);
        encoder.u32(self.banks);
        encoder.u32(self.layers_per_bank);
        encoder.u32(self.padded_variables);
        encoder.u32(self.max_proof_bytes);
        encoder.u32(self.max_structured_proof_bytes);
        encoder.digest(self.setup_identity);
        encoder.digest(self.blake3_preprocessing_record_digest);
        encoder.digest(self.relation_parameters_digest);
        encoder.digest(self.model_codec_parameters_digest);
        encoder.digest(self.dory_backend_parameters_digest);
        encoder.digest(self.shared_algebra_parameters_digest);
        encoder.digest(self.native_blake3_parameters_digest);
        encoder.digest(self.candidate_codec_parameters_digest);
        encoder.finish()
    }

    pub fn digest(&self) -> Digest32 {
        derive_key_digest(DORY_V3_SUITE_DIGEST_DOMAIN, &self.canonical_bytes())
    }

    /// Require the exact compiled production suite and return its identity.
    pub fn validate(&self) -> Result<Digest32, DoryV3SuiteError> {
        check_field(
            "manifest_version",
            self.manifest_version,
            DORY_V3_SUITE_MANIFEST_VERSION,
        )?;
        check_field("pow_type", self.pow_type, DORY_V3_POW_TYPE)?;
        check_field(
            "algorithm_version",
            self.algorithm_version,
            DORY_V3_ALGORITHM_VERSION,
        )?;
        check_field("proof_version", self.proof_version, DORY_V3_PROOF_VERSION)?;
        check_field(
            "model_bank_format_version",
            self.model_bank_format_version,
            DORY_V3_MODEL_BANK_FORMAT_VERSION,
        )?;
        check_field(
            "model_identity_version",
            self.model_identity_version,
            DORY_V3_MODEL_IDENTITY_VERSION,
        )?;
        check_field(
            "model_record_version",
            self.model_record_version,
            DORY_V3_MODEL_RECORD_VERSION,
        )?;
        check_field("setup_version", self.setup_version, DORY_V3_SETUP_VERSION)?;
        check_field(
            "transcript_version",
            self.transcript_version,
            DORY_V3_TRANSCRIPT_VERSION,
        )?;
        check_field(
            "aggregate_version",
            self.aggregate_version,
            DORY_V3_AGGREGATE_VERSION,
        )?;
        check_field(
            "matrix_version",
            self.matrix_version,
            DORY_V3_MATRIX_VERSION,
        )?;
        check_field(
            "transition_version",
            self.transition_version,
            DORY_V3_TRANSITION_VERSION,
        )?;
        check_field(
            "range_logup_version",
            self.range_logup_version,
            DORY_V3_RANGE_LOGUP_VERSION,
        )?;
        check_field(
            "wiring_version",
            self.wiring_version,
            DORY_V3_WIRING_VERSION,
        )?;
        check_field(
            "output_bridge_version",
            self.output_bridge_version,
            DORY_V3_OUTPUT_BRIDGE_VERSION,
        )?;
        check_field(
            "shared_layout_version",
            self.shared_layout_version,
            DORY_V3_SHARED_LAYOUT_VERSION,
        )?;
        check_field(
            "native_composition_version",
            self.native_composition_version,
            DORY_V3_NATIVE_COMPOSITION_VERSION,
        )?;
        check_field(
            "blake3_projection_version",
            self.blake3_projection_version,
            DORY_V3_BLAKE3_PROJECTION_VERSION,
        )?;
        check_field(
            "blake3_native_proof_version",
            self.blake3_native_proof_version,
            DORY_V3_BLAKE3_NATIVE_PROOF_VERSION,
        )?;
        check_field(
            "blake3_preprocessing_record_version",
            self.blake3_preprocessing_record_version,
            DORY_V3_BLAKE3_PREPROCESSING_RECORD_VERSION,
        )?;
        check_field(
            "fixed_model_binding_version",
            self.fixed_model_binding_version,
            DORY_V3_FIXED_MODEL_BINDING_VERSION,
        )?;
        check_field(
            "algebraic_binding_version",
            self.algebraic_binding_version,
            DORY_V3_ALGEBRAIC_BINDING_VERSION,
        )?;
        check_field(
            "candidate_payload_version",
            self.candidate_payload_version,
            DORY_V3_CANDIDATE_PAYLOAD_VERSION,
        )?;
        check_field("wire_tag", self.wire_tag, DORY_V3_WIRE_TAG)?;
        check_field("model_version", self.model_version, DORY_V3_MODEL_VERSION)?;
        check_field("batch", self.batch, DORY_V3_BATCH)?;
        check_field("dimension", self.dimension, DORY_V3_DIMENSION)?;
        check_field("layers", self.layers, DORY_V3_LAYERS)?;
        check_field("banks", self.banks, DORY_V3_BANKS)?;
        check_field(
            "layers_per_bank",
            self.layers_per_bank,
            DORY_V3_LAYERS_PER_BANK,
        )?;
        check_field(
            "padded_variables",
            self.padded_variables,
            DORY_V3_PADDED_VARIABLES,
        )?;
        check_field(
            "max_proof_bytes",
            self.max_proof_bytes,
            DORY_V3_MAX_PROOF_BYTES,
        )?;
        check_field(
            "max_structured_proof_bytes",
            self.max_structured_proof_bytes,
            DORY_V3_MAX_STRUCTURED_PROOF_BYTES,
        )?;
        check_digest(
            "setup_identity",
            self.setup_identity,
            DORY_V3_SETUP_IDENTITY,
        )?;
        check_digest(
            "blake3_preprocessing_record_digest",
            self.blake3_preprocessing_record_digest,
            DORY_V3_BLAKE3_PREPROCESSING_RECORD_DIGEST,
        )?;
        check_component(
            "relation_parameters_digest",
            self.relation_parameters_digest,
            relation_parameters_digest(),
        )?;
        check_component(
            "model_codec_parameters_digest",
            self.model_codec_parameters_digest,
            model_codec_parameters_digest(),
        )?;
        check_component(
            "dory_backend_parameters_digest",
            self.dory_backend_parameters_digest,
            dory_backend_parameters_digest(),
        )?;
        check_component(
            "shared_algebra_parameters_digest",
            self.shared_algebra_parameters_digest,
            shared_algebra_parameters_digest(),
        )?;
        check_component(
            "native_blake3_parameters_digest",
            self.native_blake3_parameters_digest,
            native_blake3_parameters_digest(),
        )?;
        check_component(
            "candidate_codec_parameters_digest",
            self.candidate_codec_parameters_digest,
            candidate_codec_parameters_digest(),
        )?;
        Ok(self.digest())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoryV3SuiteError {
    FieldMismatch(&'static str),
    DigestMismatch(&'static str),
    ComponentDigestMismatch(&'static str),
    ZeroDigest(&'static str),
}

impl fmt::Display for DoryV3SuiteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldMismatch(field) => {
                write!(formatter, "Dory V3 suite field `{field}` is not canonical")
            }
            Self::DigestMismatch(field) => write!(
                formatter,
                "Dory V3 suite digest field `{field}` is not canonical"
            ),
            Self::ComponentDigestMismatch(field) => {
                write!(
                    formatter,
                    "Dory V3 component digest `{field}` does not match compiled parameters"
                )
            }
            Self::ZeroDigest(field) => {
                write!(formatter, "Dory V3 suite digest field `{field}` is zero")
            }
        }
    }
}

impl std::error::Error for DoryV3SuiteError {}

fn check_field<T: PartialEq>(
    name: &'static str,
    actual: T,
    expected: T,
) -> Result<(), DoryV3SuiteError> {
    if actual != expected {
        return Err(DoryV3SuiteError::FieldMismatch(name));
    }
    Ok(())
}

fn check_digest(
    name: &'static str,
    actual: Digest32,
    expected: Digest32,
) -> Result<(), DoryV3SuiteError> {
    if actual == Digest32::ZERO {
        return Err(DoryV3SuiteError::ZeroDigest(name));
    }
    if actual != expected {
        return Err(DoryV3SuiteError::DigestMismatch(name));
    }
    Ok(())
}

fn check_component(
    name: &'static str,
    actual: Digest32,
    expected: Digest32,
) -> Result<(), DoryV3SuiteError> {
    if actual == Digest32::ZERO {
        return Err(DoryV3SuiteError::ZeroDigest(name));
    }
    if actual != expected {
        return Err(DoryV3SuiteError::ComponentDigestMismatch(name));
    }
    Ok(())
}

struct FixedEncoder {
    bytes: [u8; DORY_V3_SUITE_CANONICAL_BYTES],
    offset: usize,
}

impl FixedEncoder {
    fn new() -> Self {
        Self {
            bytes: [0; DORY_V3_SUITE_CANONICAL_BYTES],
            offset: 0,
        }
    }

    fn put(&mut self, bytes: &[u8]) {
        let end = self
            .offset
            .checked_add(bytes.len())
            .expect("fixed suite encoding length cannot overflow");
        self.bytes[self.offset..end].copy_from_slice(bytes);
        self.offset = end;
    }

    fn u8(&mut self, value: u8) {
        self.put(&[value]);
    }

    fn u16(&mut self, value: u16) {
        self.put(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.put(&value.to_le_bytes());
    }

    fn digest(&mut self, value: Digest32) {
        self.put(value.as_bytes());
    }

    fn finish(self) -> [u8; DORY_V3_SUITE_CANONICAL_BYTES] {
        assert_eq!(self.offset, DORY_V3_SUITE_CANONICAL_BYTES);
        self.bytes
    }
}

struct DescriptorHasher {
    hasher: blake3::Hasher,
}

impl DescriptorHasher {
    fn new(domain: &'static str) -> Self {
        let mut descriptor = Self {
            hasher: blake3::Hasher::new_derive_key(domain),
        };
        descriptor.str(
            "descriptor-format",
            "label-u16le-length || label || value-u32le-length || value; fields in call order; v1",
        );
        descriptor
    }

    fn field(&mut self, label: &'static str, value: &[u8]) {
        let label_len = u16::try_from(label.len()).expect("fixed descriptor label fits in u16");
        let value_len = u32::try_from(value.len()).expect("fixed descriptor value fits in u32");
        self.hasher.update(&label_len.to_le_bytes());
        self.hasher.update(label.as_bytes());
        self.hasher.update(&value_len.to_le_bytes());
        self.hasher.update(value);
    }

    fn str(&mut self, label: &'static str, value: &'static str) {
        self.field(label, value.as_bytes());
    }

    fn u8(&mut self, label: &'static str, value: u8) {
        self.field(label, &[value]);
    }

    fn u16(&mut self, label: &'static str, value: u16) {
        self.field(label, &value.to_le_bytes());
    }

    fn u32(&mut self, label: &'static str, value: u32) {
        self.field(label, &value.to_le_bytes());
    }

    fn u64(&mut self, label: &'static str, value: u64) {
        self.field(label, &value.to_le_bytes());
    }

    fn digest(&mut self, label: &'static str, value: Digest32) {
        self.field(label, value.as_bytes());
    }

    fn finish(self) -> Digest32 {
        Digest32::new(*self.hasher.finalize().as_bytes())
    }
}

pub fn relation_parameters_digest() -> Digest32 {
    use crate::{
        dory_bls12_381_blake3::BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES,
        forgematrix_v2::{
            V2_MAX_OUTPUT_QUOTIENT, V2_MODEL_VALUE_CENTER, V2_MODEL_VALUE_ENCODING,
            V2_OUTPUT_MODULUS, V2_TRANSITION_MODULUS,
        },
    };

    let mut descriptor = DescriptorHasher::new(DORY_V3_RELATION_PARAMETERS_DOMAIN);
    descriptor.str(
        "relation",
        "ForgeMatrix integer relation; Dory-native V3 profile v1",
    );
    descriptor.u16("pow-type", DORY_V3_POW_TYPE);
    descriptor.u32("algorithm-version", DORY_V3_ALGORITHM_VERSION);
    descriptor.u32("proof-version", DORY_V3_PROOF_VERSION);
    descriptor.u32("model-version", DORY_V3_MODEL_VERSION);
    descriptor.u32("batch", DORY_V3_BATCH);
    descriptor.u32("dimension", DORY_V3_DIMENSION);
    descriptor.u32("layers", DORY_V3_LAYERS);
    descriptor.u32("banks", DORY_V3_BANKS);
    descriptor.u32("layers-per-bank", DORY_V3_LAYERS_PER_BANK);
    descriptor.u8("model-byte-minimum", u8::MIN);
    descriptor.u8("model-byte-maximum", crate::model_bank::MAX_MODEL_BYTE);
    descriptor.u16(
        "model-value-center",
        u16::try_from(V2_MODEL_VALUE_CENTER).expect("model value center is nonnegative"),
    );
    descriptor.u32("transition-modulus", V2_TRANSITION_MODULUS);
    descriptor.u16(
        "output-modulus",
        u16::try_from(V2_OUTPUT_MODULUS).expect("output modulus fits u16"),
    );
    descriptor.u32("maximum-output-quotient", V2_MAX_OUTPUT_QUOTIENT);
    descriptor.str("model-value-map", V2_MODEL_VALUE_ENCODING);
    descriptor.str("challenge-domain", DORY_V3_CHALLENGE_DOMAIN);
    descriptor.str(
        "challenge-fields",
        "pow_type_u16le,algorithm_version_u32le,proof_version_u32le,network_id[32],suite_digest[32],manifest_digest[32],model_identity_digest[32],previous_block[32],transaction_root[32],height_u64le,timestamp_u64le,target[32],nonce_u64le",
    );
    descriptor.str("mask-domain", DORY_V3_MASK_DOMAIN);
    descriptor.str(
        "mask-sampler",
        "BLAKE3 XOF over challenge_digest[32],layer_u32le; accept each XOF byte <=250 until count=1+log2(rows)+log2(columns)",
    );
    descriptor.str("output-domain", DORY_V3_OUTPUT_DOMAIN);
    descriptor.u64(
        "output-activation-bytes",
        u64::try_from(BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES)
            .expect("production activation length fits u64"),
    );
    descriptor.str(
        "output-fields",
        "challenge_digest[32],activation_length_u64le equal to output-activation-bytes,activation_bytes[activation_length] each 0..=250",
    );
    descriptor.str("work-domain", DORY_V3_WORK_DOMAIN);
    descriptor.str(
        "work-fields",
        "suite_digest[32],challenge_digest[32],model_identity_digest[32],final_activation_digest[32]",
    );
    descriptor.str(
        "target-comparison",
        "unsigned lexicographic comparison of 32 digest bytes; winning work_digest <= block target",
    );
    descriptor.finish()
}

pub fn model_codec_parameters_digest() -> Digest32 {
    use crate::{
        dory_v3_model::{
            DORY_V3_COMMITMENT_ROOT_FIELDS, DORY_V3_FIXED_ROLE_ORDER,
            DORY_V3_GT_CANONICAL_ENCODING, DORY_V3_IDENTITY_FIELDS,
            DORY_V3_MODEL_BANK_HEADER_INTERPRETATION,
        },
        model_bank::{
            LAYER_ROOTS_DOMAIN, MANIFEST_DOMAIN, MAX_MODEL_BYTE, MODEL_BANK_HEADER_BYTES,
            MODEL_BANK_HEADER_FIELDS, MODEL_BANK_INTEGER_ENDIAN, MODEL_BANK_MAGIC,
            MODEL_BANK_RAW_ROOT_RULE, MODEL_PCS_BASE_INPUT_AXIS_ORDER,
            MODEL_PCS_WEIGHT_BANK_AXIS_ORDER,
        },
    };

    let mut descriptor = DescriptorHasher::new(DORY_V3_MODEL_CODEC_PARAMETERS_DOMAIN);
    descriptor.field("model-bank-magic", &MODEL_BANK_MAGIC);
    descriptor.u32(
        "model-bank-format-version",
        DORY_V3_MODEL_BANK_FORMAT_VERSION,
    );
    descriptor.u32(
        "model-bank-header-bytes",
        u32::try_from(MODEL_BANK_HEADER_BYTES).expect("fixed model bank header fits u32"),
    );
    descriptor.u8("maximum-model-byte", MAX_MODEL_BYTE);
    descriptor.str("integer-endian", MODEL_BANK_INTEGER_ENDIAN);
    descriptor.str("header-fields", MODEL_BANK_HEADER_FIELDS);
    descriptor.str(
        "v3-header-field-interpretation",
        DORY_V3_MODEL_BANK_HEADER_INTERPRETATION,
    );
    descriptor.str("raw-root", MODEL_BANK_RAW_ROOT_RULE);
    descriptor.str("layer-roots-domain", LAYER_ROOTS_DOMAIN);
    descriptor.str("manifest-domain", MANIFEST_DOMAIN);
    descriptor.u16(
        "dory-model-identity-version",
        DORY_V3_MODEL_IDENTITY_VERSION,
    );
    descriptor.u16("dory-model-record-version", DORY_V3_MODEL_RECORD_VERSION);
    descriptor.str(
        "commitment-root-domain",
        DORY_V3_MODEL_COMMITMENT_ROOT_DOMAIN,
    );
    descriptor.str("model-identity-domain", DORY_V3_MODEL_IDENTITY_DOMAIN);
    descriptor.str("model-record-domain", DORY_V3_MODEL_RECORD_DOMAIN);
    descriptor.u32(
        "model-record-canonical-bytes",
        DORY_V3_MODEL_RECORD_CANONICAL_BYTES,
    );
    descriptor.str(
        "model-record-digest-fields",
        DORY_V3_MODEL_RECORD_DIGEST_FIELDS,
    );
    descriptor.str("model-record-json-fields", DORY_V3_MODEL_RECORD_JSON_FIELDS);
    descriptor.u32("gt-canonical-bytes", DORY_V3_GT_CANONICAL_BYTES);
    descriptor.str("gt-canonical-encoding", DORY_V3_GT_CANONICAL_ENCODING);
    descriptor.u16(
        "fixed-role-count",
        u16::try_from(DORY_V3_BANKS + 1).expect("fixed role count fits u16"),
    );
    descriptor.str("fixed-role-order", DORY_V3_FIXED_ROLE_ORDER);
    descriptor.str("base-axis-order", MODEL_PCS_BASE_INPUT_AXIS_ORDER);
    descriptor.str("weight-axis-order", MODEL_PCS_WEIGHT_BANK_AXIS_ORDER);
    descriptor.str("commitment-root-fields", DORY_V3_COMMITMENT_ROOT_FIELDS);
    descriptor.str("identity-fields", DORY_V3_IDENTITY_FIELDS);
    descriptor.str(
        "legacy-separation",
        "legacy ModelPcsIdentity V1 and its WHIR domains are not accepted or reinterpreted",
    );
    descriptor.finish()
}

pub fn dory_backend_parameters_digest() -> Digest32 {
    use crate::{
        dory_bls12_381_blake3::{
            BLS_DORY_BLAKE3_SHARED_DORY_NU, BLS_DORY_BLAKE3_SHARED_DORY_SIGMA,
        },
        dory_bls12_381_prototype::{
            BLS_DORY_EXACT_NONZERO_CHALLENGE_SAMPLING, BLS_DORY_GENERATOR_MESSAGE_FIELDS,
            BLS_DORY_SETUP_IDENTITY_FIELDS, G1_DOMAIN, G2_DOMAIN, SETUP_IDENTITY_DOMAIN,
            TRANSCRIPT_DOMAIN, bls_dory_setup_generator_count,
        },
    };

    let mut descriptor = DescriptorHasher::new(DORY_V3_BACKEND_PARAMETERS_DOMAIN);
    descriptor.str("curve", "BLS12-381");
    descriptor.str(
        "scalar-field",
        "BLS12-381 Fr canonical 32-byte scalar encoding",
    );
    descriptor.str(
        "target-group",
        "BLS12-381 pairing output in validated Fq12 subgroup",
    );
    descriptor.u16("setup-version", DORY_V3_SETUP_VERSION);
    descriptor.u16("transcript-version", DORY_V3_TRANSCRIPT_VERSION);
    descriptor.u32("setup-maximum-log-n", DORY_V3_PADDED_VARIABLES);
    descriptor.u32(
        "setup-generator-count-per-group",
        u32::try_from(bls_dory_setup_generator_count(
            DORY_V3_PADDED_VARIABLES as usize,
        ))
        .expect("production setup generator count fits u32"),
    );
    descriptor.u32(
        "shared-dory-nu",
        u32::try_from(BLS_DORY_BLAKE3_SHARED_DORY_NU).expect("shared Dory nu fits u32"),
    );
    descriptor.u32(
        "shared-dory-sigma",
        u32::try_from(BLS_DORY_BLAKE3_SHARED_DORY_SIGMA).expect("shared Dory sigma fits u32"),
    );
    descriptor.u8(
        "exact-nonzero-challenge-sampling",
        u8::from(BLS_DORY_EXACT_NONZERO_CHALLENGE_SAMPLING),
    );
    descriptor.str(
        "hash-to-curve",
        "IETF XMD:SHA-256 SSWU random-oracle mapping",
    );
    descriptor.field("g1-domain", G1_DOMAIN);
    descriptor.field("g2-domain", G2_DOMAIN);
    descriptor.str("setup-identity-domain", SETUP_IDENTITY_DOMAIN);
    descriptor.str("transcript-domain", TRANSCRIPT_DOMAIN);
    descriptor.str("generator-message", BLS_DORY_GENERATOR_MESSAGE_FIELDS);
    descriptor.str("setup-identity-fields", BLS_DORY_SETUP_IDENTITY_FIELDS);
    descriptor.str(
        "dory-profile",
        "transparent multilinear Dory commitment and opening; row-major nu/sigma split; no trusted setup or toxic waste",
    );
    descriptor.u32("scalar-bytes", 32);
    descriptor.u32("gt-bytes", DORY_V3_GT_CANONICAL_BYTES);
    descriptor.digest("setup-identity", DORY_V3_SETUP_IDENTITY);
    descriptor.finish()
}

pub fn shared_algebra_parameters_digest() -> Digest32 {
    use crate::{
        dory_bls12_381_aggregate::WIRE_MAGIC as AGGREGATE_MAGIC,
        dory_bls12_381_blake3::BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS,
        dory_bls12_381_layout::{
            BLS_DORY_SHARED_FINAL_OUTPUT_BRIDGE_CLAIMS, BLS_DORY_SHARED_INITIALIZATION_LINKS,
            BLS_DORY_SHARED_LINKS_PER_BANK, BLS_DORY_SHARED_NATIVE_COMPOSITION_CLAIMS,
            BLS_DORY_SHARED_NATIVE_COMPOSITION_VERSION, BLS_DORY_SHARED_PRODUCTION_CLAIMS,
            BLS_DORY_SHARED_PRODUCTION_EQUALITY_CLAIMS, BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS,
            MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES, MAX_BLS_DORY_SHARED_MATRIX_PROOFS,
            MAX_BLS_DORY_SHARED_TRANSITION_PROOFS, MAX_SHARED_LAYOUT_BINDING_BYTES,
            SHARED_PROOF_MAGIC,
        },
        dory_bls12_381_logup::PROOF_MAGIC as RANGE_LOGUP_MAGIC,
        dory_bls12_381_matrix::PROOF_MAGIC as MATRIX_MAGIC,
        dory_bls12_381_transition::PROOF_MAGIC as TRANSITION_MAGIC,
        dory_bls12_381_wiring::PROOF_MAGIC as WIRING_MAGIC,
    };

    let mut descriptor = DescriptorHasher::new(DORY_V3_SHARED_ALGEBRA_PARAMETERS_DOMAIN);
    descriptor.u16("aggregate-version", DORY_V3_AGGREGATE_VERSION);
    descriptor.field("aggregate-magic", &AGGREGATE_MAGIC);
    descriptor.u16("matrix-version", DORY_V3_MATRIX_VERSION);
    descriptor.field("matrix-magic", &MATRIX_MAGIC);
    descriptor.u16("transition-version", DORY_V3_TRANSITION_VERSION);
    descriptor.field("transition-magic", &TRANSITION_MAGIC);
    descriptor.u16("range-logup-version", DORY_V3_RANGE_LOGUP_VERSION);
    descriptor.field("range-logup-magic", &RANGE_LOGUP_MAGIC);
    descriptor.u16("wiring-version", DORY_V3_WIRING_VERSION);
    descriptor.field("wiring-magic", &WIRING_MAGIC);
    descriptor.u16("output-bridge-version", DORY_V3_OUTPUT_BRIDGE_VERSION);
    descriptor.u16("shared-layout-version", DORY_V3_SHARED_LAYOUT_VERSION);
    descriptor.field("shared-layout-magic", &SHARED_PROOF_MAGIC);
    descriptor.u16(
        "native-composition-version",
        BLS_DORY_SHARED_NATIVE_COMPOSITION_VERSION,
    );
    descriptor.u16(
        "fixed-model-binding-version",
        DORY_V3_FIXED_MODEL_BINDING_VERSION,
    );
    descriptor.str(
        "fixed-model-binding-domain",
        DORY_V3_FIXED_MODEL_BINDING_DOMAIN,
    );
    descriptor.str(
        "fixed-model-binding-fields",
        DORY_V3_FIXED_MODEL_BINDING_FIELDS,
    );
    descriptor.str(
        "shared-opening-binding-domain",
        DORY_V3_SHARED_OPENING_BINDING_DOMAIN,
    );
    descriptor.str(
        "shared-opening-binding-fields",
        DORY_V3_SHARED_OPENING_BINDING_FIELDS,
    );
    descriptor.str(
        "native-composition-binding-domain",
        DORY_V3_NATIVE_COMPOSITION_BINDING_DOMAIN,
    );
    descriptor.str(
        "native-composition-binding-fields",
        DORY_V3_NATIVE_COMPOSITION_BINDING_FIELDS,
    );
    descriptor.u32(
        "maximum-shared-binding-bytes",
        u32::try_from(MAX_SHARED_LAYOUT_BINDING_BYTES).expect("shared binding limit fits u32"),
    );
    descriptor.u32("padded-variables", DORY_V3_PADDED_VARIABLES);
    descriptor.u32(
        "matrix-proof-count",
        u32::try_from(MAX_BLS_DORY_SHARED_MATRIX_PROOFS).expect("matrix proof count fits u32"),
    );
    descriptor.u32(
        "transition-proof-count",
        u32::try_from(MAX_BLS_DORY_SHARED_TRANSITION_PROOFS)
            .expect("transition proof count fits u32"),
    );
    descriptor.u32(
        "shared-opening-claims",
        u32::try_from(BLS_DORY_SHARED_PRODUCTION_CLAIMS).expect("shared opening count fits u32"),
    );
    descriptor.u32(
        "native-suffix-opening-claims",
        u32::try_from(BLS_DORY_SHARED_NATIVE_COMPOSITION_CLAIMS)
            .expect("native opening count fits u32"),
    );
    descriptor.u32(
        "composed-opening-claims",
        u32::try_from(BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS)
            .expect("composed opening count fits u32"),
    );
    descriptor.u32(
        "initialization-equality-links",
        u32::try_from(BLS_DORY_SHARED_INITIALIZATION_LINKS)
            .expect("initialization link count fits u32"),
    );
    descriptor.u32(
        "links-per-bank",
        u32::try_from(BLS_DORY_SHARED_LINKS_PER_BANK).expect("links per bank fits u32"),
    );
    descriptor.u32(
        "total-equality-links",
        u32::try_from(BLS_DORY_SHARED_PRODUCTION_EQUALITY_LINKS)
            .expect("equality link count fits u32"),
    );
    descriptor.u32(
        "total-equality-claims",
        u32::try_from(BLS_DORY_SHARED_PRODUCTION_EQUALITY_CLAIMS)
            .expect("equality claim count fits u32"),
    );
    descriptor.u32(
        "final-output-bridge-claims",
        u32::try_from(BLS_DORY_SHARED_FINAL_OUTPUT_BRIDGE_CLAIMS)
            .expect("final output claim count fits u32"),
    );
    descriptor.u32(
        "maximum-matrix-proofs",
        u32::try_from(MAX_BLS_DORY_SHARED_MATRIX_PROOFS).expect("matrix proof cap fits u32"),
    );
    descriptor.u32(
        "maximum-transition-proofs",
        u32::try_from(MAX_BLS_DORY_SHARED_TRANSITION_PROOFS)
            .expect("transition proof cap fits u32"),
    );
    descriptor.u32(
        "maximum-shared-layout-component-bytes",
        u32::try_from(MAX_BLS_DORY_SHARED_LAYOUT_PROOF_BYTES)
            .expect("shared layout component cap fits u32"),
    );
    descriptor.str(
        "proof-order",
        "three matrix banks; initialization then three arithmetic/range transitions; wiring; equality links; final-output bridge; one 128-claim shared opening followed by six native BLAKE3 claims",
    );
    descriptor.str(
        "model-binding",
        "DoryV3ModelIdentityV1 digest and exact decoded base plus three bank commitments; legacy ModelPcsIdentity digest forbidden",
    );
    descriptor.finish()
}

pub fn native_blake3_parameters_digest() -> Digest32 {
    use crate::{dory_bls12_381_aggregate::scalar_bytes, dory_bls12_381_blake3 as owner};

    let mut descriptor = DescriptorHasher::new(DORY_V3_NATIVE_BLAKE3_PARAMETERS_DOMAIN);
    descriptor.u16("projection-version", DORY_V3_BLAKE3_PROJECTION_VERSION);
    descriptor.u16("native-proof-version", DORY_V3_BLAKE3_NATIVE_PROOF_VERSION);
    descriptor.u16(
        "preprocessing-record-version",
        DORY_V3_BLAKE3_PREPROCESSING_RECORD_VERSION,
    );
    descriptor.u64(
        "activation-bytes",
        u64::try_from(owner::BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES)
            .expect("activation length fits u64"),
    );
    descriptor.u64(
        "trace-rows",
        u64::try_from(owner::BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS)
            .expect("trace row count fits u64"),
    );
    for (label, value) in [
        ("trace-variables", owner::BLS_DORY_BLAKE3_TRACE_VARIABLES),
        ("main-width", owner::BLS_DORY_BLAKE3_MAIN_WIDTH),
        (
            "preprocessed-width",
            owner::BLS_DORY_BLAKE3_PREPROCESSED_WIDTH,
        ),
        (
            "source-selector-variables",
            owner::BLS_DORY_BLAKE3_SOURCE_SELECTOR_VARIABLES,
        ),
        (
            "adjacency-selector-variables",
            owner::BLS_DORY_BLAKE3_ADJACENCY_SELECTOR_VARIABLES,
        ),
        (
            "source-commitment-variables",
            owner::BLS_DORY_BLAKE3_SOURCE_COMMITMENT_VARIABLES,
        ),
        ("source-dory-nu", owner::BLS_DORY_BLAKE3_SOURCE_DORY_NU),
        (
            "source-dory-sigma",
            owner::BLS_DORY_BLAKE3_SOURCE_DORY_SIGMA,
        ),
        ("shared-dory-nu", owner::BLS_DORY_BLAKE3_SHARED_DORY_NU),
        (
            "shared-dory-sigma",
            owner::BLS_DORY_BLAKE3_SHARED_DORY_SIGMA,
        ),
        (
            "signed-word-tables",
            owner::BLS_DORY_BLAKE3_SIGNED_WORD_TABLES,
        ),
        (
            "accumulator-scalar-tables",
            owner::BLS_DORY_BLAKE3_ACCUMULATOR_SCALAR_TABLES,
        ),
        (
            "preprocessed-word-tables",
            owner::BLS_DORY_BLAKE3_PREPROCESSED_WORD_TABLES,
        ),
        (
            "preprocessed-code-tables",
            owner::BLS_DORY_BLAKE3_PREPROCESSED_CODE_TABLES,
        ),
        (
            "inverse-scalar-tables",
            owner::BLS_DORY_BLAKE3_INVERSE_SCALAR_TABLES,
        ),
        (
            "execution-constraint-degree",
            owner::BLS_DORY_BLAKE3_EXECUTION_CONSTRAINT_DEGREE,
        ),
        (
            "execution-constraints",
            owner::BLS_DORY_BLAKE3_EXECUTION_CONSTRAINTS,
        ),
        (
            "execution-sumcheck-degree",
            owner::BLS_DORY_BLAKE3_EXECUTION_SUMCHECK_DEGREE,
        ),
        (
            "adjacency-sumcheck-degree",
            owner::BLS_DORY_BLAKE3_ADJACENCY_SUMCHECK_DEGREE,
        ),
        (
            "execution-terminal-evaluations",
            owner::BLS_DORY_BLAKE3_EXECUTION_TERMINAL_EVALUATIONS,
        ),
        (
            "adjacency-terminal-evaluations",
            owner::BLS_DORY_BLAKE3_ADJACENCY_TERMINAL_EVALUATIONS,
        ),
        (
            "execution-opening-claims",
            owner::BLS_DORY_BLAKE3_EXECUTION_OPENING_CLAIMS,
        ),
        (
            "adjacency-opening-claims",
            owner::BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS,
        ),
        (
            "physical-source-commitments",
            owner::BLS_DORY_BLAKE3_SOURCE_COMMITMENTS,
        ),
        (
            "composed-opening-claims",
            owner::BLS_DORY_BLAKE3_COMPOSED_OPENING_CLAIMS,
        ),
        (
            "proposed-aggregate-claim-cap",
            owner::BLS_DORY_BLAKE3_PROPOSED_MAX_OPENING_CLAIMS,
        ),
    ] {
        descriptor.u32(
            label,
            u32::try_from(value).expect("native BLAKE3 parameter fits u32"),
        );
    }
    descriptor.str("source-order", owner::BLS_DORY_BLAKE3_SOURCE_ORDER);
    descriptor.str(
        "opening-source-order",
        owner::BLS_DORY_BLAKE3_OPENING_SOURCE_ORDER,
    );
    descriptor.field(
        "execution-proof-magic",
        &owner::BLS_DORY_BLAKE3_EXECUTION_PROOF_MAGIC,
    );
    descriptor.field(
        "adjacency-proof-magic",
        &owner::BLS_DORY_BLAKE3_ADJACENCY_PROOF_MAGIC,
    );
    descriptor.u32(
        "component-header-bytes",
        u32::try_from(owner::COMPONENT_HEADER_BYTES).expect("component header fits u32"),
    );
    descriptor.u32(
        "scalar-bytes",
        u32::try_from(scalar_bytes()).expect("scalar encoding length fits u32"),
    );
    descriptor.u32(
        "gt-bytes",
        u32::try_from(owner::GT_BYTES).expect("GT encoding length fits u32"),
    );
    descriptor.str("output-domain", DORY_V3_OUTPUT_DOMAIN);
    descriptor.str(
        "native-binding",
        "challenge digest and final activation digest determine a one-block BLAKE3 tree statement; verifier replays execution and adjacency; six claims join the unchanged 128-claim shared opening",
    );
    descriptor.digest(
        "preprocessing-record-digest",
        DORY_V3_BLAKE3_PREPROCESSING_RECORD_DIGEST,
    );
    descriptor.digest("setup-identity", DORY_V3_SETUP_IDENTITY);
    descriptor.finish()
}

pub fn candidate_codec_parameters_digest() -> Digest32 {
    use crate::{
        dory_bls12_381_candidate::CANDIDATE_PAYLOAD_FIELDS,
        pow::FORGEMATRIX_V3_BLOCK_ID_PROOF_FIELDS,
        wire::{
            FORGEMATRIX_PROOF_KIND, FORGEMATRIX_V3_LENGTH_BYTES,
            FORGEMATRIX_V3_PUBLIC_PREFIX_BYTES, FORGEMATRIX_V3_WIRE_PREFIX_FIELDS,
            FORGEMATRIX_V3_WIRE_TAIL_FIELDS, FRAME_MAGIC, NETWORK_MAGIC_DOMAIN, WIRE_HEADER_BYTES,
            WIRE_HEADER_FIELDS, WIRE_VERSION,
        },
    };

    let mut descriptor = DescriptorHasher::new(DORY_V3_CANDIDATE_CODEC_PARAMETERS_DOMAIN);
    descriptor.field("wire-frame-magic", &FRAME_MAGIC);
    descriptor.u16("wire-version", WIRE_VERSION);
    descriptor.u8("proof-kind", FORGEMATRIX_PROOF_KIND);
    descriptor.u8("v3-wire-tag", DORY_V3_WIRE_TAG);
    descriptor.u32(
        "wire-header-bytes",
        u32::try_from(WIRE_HEADER_BYTES).expect("fixed wire header length fits u32"),
    );
    descriptor.u32(
        "wire-fixed-prefix-bytes",
        u32::try_from(FORGEMATRIX_V3_PUBLIC_PREFIX_BYTES)
            .expect("fixed public prefix length fits u32"),
    );
    descriptor.str("wire-header-fields", WIRE_HEADER_FIELDS);
    descriptor.str("network-magic-domain", NETWORK_MAGIC_DOMAIN);
    descriptor.u32(
        "structured-length-bytes",
        u32::try_from(FORGEMATRIX_V3_LENGTH_BYTES).expect("structured length width fits u32"),
    );
    descriptor.u32("maximum-proof-bytes", DORY_V3_MAX_PROOF_BYTES);
    descriptor.u32(
        "maximum-structured-proof-bytes",
        DORY_V3_MAX_STRUCTURED_PROOF_BYTES,
    );
    descriptor.field("candidate-payload-magic", &DORY_V3_CANDIDATE_PAYLOAD_MAGIC);
    descriptor.u16(
        "candidate-payload-version",
        DORY_V3_CANDIDATE_PAYLOAD_VERSION,
    );
    descriptor.u32(
        "candidate-payload-header-bytes",
        DORY_V3_CANDIDATE_PAYLOAD_HEADER_BYTES,
    );
    descriptor.str("candidate-payload-fields", CANDIDATE_PAYLOAD_FIELDS);
    descriptor.str(
        "proof-public-prefix-fields",
        FORGEMATRIX_V3_WIRE_PREFIX_FIELDS,
    );
    descriptor.str("proof-payload-tail", FORGEMATRIX_V3_WIRE_TAIL_FIELDS);
    descriptor.str(
        "block-id-proof-fields",
        FORGEMATRIX_V3_BLOCK_ID_PROOF_FIELDS,
    );
    descriptor.u16(
        "algebraic-binding-version",
        DORY_V3_ALGEBRAIC_BINDING_VERSION,
    );
    descriptor.str("algebraic-binding-domain", DORY_V3_ALGEBRAIC_BINDING_DOMAIN);
    descriptor.str(
        "algebraic-binding-fields",
        "binding_version_u16le,pow_type_u16le,network_id[32],algorithm_version_u32le,proof_version_u32le,suite_digest[32],model_record_digest[32],manifest_digest[32],model_identity_digest[32],previous_block[32],transaction_root[32],height_u64le,timestamp_u64le,target[32],nonce_u64le,challenge_digest[32],final_activation_digest[32],work_digest[32]",
    );
    descriptor.str(
        "admission",
        "empty,oversized,truncated,trailing,legacy-binding,wrong-suite,wrong-model,wrong-setup and high-hash proofs reject without fallback",
    );
    descriptor.finish()
}

fn derive_key_digest(domain: &'static str, bytes: &[u8]) -> Digest32 {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(bytes);
    Digest32::new(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::collections::BTreeSet;

    #[test]
    fn compiled_manifest_validates_and_has_exact_fixed_width() {
        let manifest = production_dory_v3_suite_manifest();
        assert_eq!(manifest.canonical_bytes().len(), 345);
        assert_eq!(manifest.validate(), Ok(manifest.digest()));
        assert_eq!(*DORY_V3_PRODUCTION_SUITE_MANIFEST, manifest);
        assert_eq!(compiled_production_dory_v3_suite(), &manifest);
        assert_eq!(production_dory_v3_suite_digest(), manifest.digest());
        assert_eq!(
            production_dory_v3_model_commitment_parameters_digest(),
            manifest.model_codec_parameters_digest
        );
    }

    #[test]
    fn golden_parameter_and_suite_digests_are_stable() {
        let manifest = production_dory_v3_suite_manifest();
        assert_eq!(
            manifest.digest().to_hex(),
            "6c0950d4b5dcffef9f3296f9c0718a8d5124877719b3af76b2f68b3fcb64764a"
        );
        assert_eq!(
            manifest.relation_parameters_digest.to_hex(),
            "27f838def695b558663679c556a6e1183fd73a52244d87668d33975a2cabe0b1"
        );
        assert_eq!(
            manifest.model_codec_parameters_digest.to_hex(),
            "548a837d9520fa7159efa76bcd9c11bd485a127d0fd6cfce280e6f5ab857cdef"
        );
        assert_eq!(
            manifest.dory_backend_parameters_digest.to_hex(),
            "cb7b9eb27ce164884ef4c42f9ecb03e96f78533723e6e9640e70119df04fa141"
        );
        assert_eq!(
            manifest.shared_algebra_parameters_digest.to_hex(),
            "3540c35f987e32890a29e22839be03dec0f0cde5aa560d73e96c270e58a7b171"
        );
        assert_eq!(
            manifest.native_blake3_parameters_digest.to_hex(),
            "919b7069237aa3e69c5399c8aeca802e0b965ab2679fac31597a5287c010ae8d"
        );
        assert_eq!(
            manifest.candidate_codec_parameters_digest.to_hex(),
            "e8fbd5463f33e151e37763bfb29b47d266a34465a6b5648218ce5ce97d10092e"
        );
    }

    #[test]
    fn model_record_v2_codec_is_exactly_bound() {
        assert_eq!(DORY_V3_MODEL_RECORD_VERSION, 2);
        assert_eq!(DORY_V3_MODEL_RECORD_CANONICAL_BYTES, 2 + 5 * 32 + 4);
        assert_eq!(
            DORY_V3_MODEL_RECORD_DIGEST_FIELDS,
            "record_version_u16le,suite_digest[32],manifest_digest[32],model_identity_digest[32],setup_identity[32],padded_variables_u32le,commitment_root[32]"
        );
        assert_eq!(
            DORY_V3_MODEL_RECORD_JSON_FIELDS,
            "record_version,suite_digest,manifest,manifest_digest,model_identity,model_identity_digest,setup_identity,padded_variables,commitment_root,record_digest; JSON audit-only; unknown/duplicate fields reject; top-level digest fields use lowercase hex; nested manifest byte arrays and identity commitment encodings retain their own strict codecs; JSON bytes not consensus hashed"
        );
        assert_eq!(
            DORY_V3_MODEL_RECORD_DOMAIN,
            "CMFD/FORGEMATRIX/V3/DORY-MODEL-COMMITMENT-RECORD/V2"
        );
    }

    #[test]
    fn layout_v5_binding_transcript_grammars_are_exactly_frozen() {
        assert_eq!(
            DORY_V3_FIXED_MODEL_BINDING_FIELDS,
            "binding_version_u16le,shared_layout_version_u16le,suite_digest[32],model_identity_digest[32],setup_identity[32],padded_variables_u32le,outer_binding_length_u32le,outer_binding[outer_binding_length]"
        );
        assert_eq!(
            DORY_V3_SHARED_OPENING_BINDING_FIELDS,
            "shared_layout_version_u16le,padded_variables_u32le,setup_identity[32],component_binding[32],matrix_count_u16le,then each matrix_transcript_digest[32],transition_count_u16le,then each arithmetic_transcript_digest[32],range_transcript_digest[32],wiring_transcript_digest[32]"
        );
        assert_eq!(
            DORY_V3_NATIVE_COMPOSITION_BINDING_FIELDS,
            "shared_layout_version_u16le,native_composition_version_u16le,dory_nu_u16le,dory_sigma_u16le,setup_identity[32],shared_opening_binding[32],native_opening_binding[32]"
        );
    }

    #[test]
    fn component_domains_are_distinct_and_nonzero() {
        let manifest = production_dory_v3_suite_manifest();
        let digests = [
            manifest.relation_parameters_digest,
            manifest.model_codec_parameters_digest,
            manifest.dory_backend_parameters_digest,
            manifest.shared_algebra_parameters_digest,
            manifest.native_blake3_parameters_digest,
            manifest.candidate_codec_parameters_digest,
        ];
        assert!(digests.iter().all(|digest| *digest != Digest32::ZERO));
        assert_eq!(digests.into_iter().collect::<BTreeSet<_>>().len(), 6);
    }

    #[test]
    fn json_is_strict_but_never_part_of_the_suite_digest() {
        let manifest = production_dory_v3_suite_manifest();
        let compact = serde_json::to_string(&manifest).unwrap();
        let pretty = serde_json::to_string_pretty(&manifest).unwrap();
        let decoded_compact: DoryV3ConsensusSuiteManifestV1 =
            serde_json::from_str(&compact).unwrap();
        let decoded_pretty: DoryV3ConsensusSuiteManifestV1 = serde_json::from_str(&pretty).unwrap();
        assert_eq!(decoded_compact, manifest);
        assert_eq!(decoded_pretty, manifest);
        assert_eq!(decoded_compact.digest(), decoded_pretty.digest());

        let mut value = serde_json::to_value(manifest).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), json!(1));
        assert!(serde_json::from_value::<DoryV3ConsensusSuiteManifestV1>(value).is_err());
    }

    #[test]
    fn digest_json_rejects_uppercase_short_and_non_string_values() {
        let encoded = serde_json::to_string(&DORY_V3_SETUP_IDENTITY).unwrap();
        assert_eq!(encoded.len(), 66);
        assert_eq!(
            serde_json::from_str::<Digest32>(&encoded).unwrap(),
            DORY_V3_SETUP_IDENTITY
        );
        assert!(serde_json::from_str::<Digest32>(&encoded.to_uppercase()).is_err());
        assert!(serde_json::from_str::<Digest32>("\"00\"").is_err());
        assert!(serde_json::from_str::<Digest32>("[0,1]").is_err());
    }

    #[test]
    fn field_component_and_pin_substitution_fail_closed() {
        let mut changed = production_dory_v3_suite_manifest();
        changed.dimension /= 2;
        assert_eq!(
            changed.validate(),
            Err(DoryV3SuiteError::FieldMismatch("dimension"))
        );

        let mut changed = production_dory_v3_suite_manifest();
        changed.shared_algebra_parameters_digest = Digest32::new([0x55; 32]);
        assert_eq!(
            changed.validate(),
            Err(DoryV3SuiteError::ComponentDigestMismatch(
                "shared_algebra_parameters_digest"
            ))
        );

        let mut changed = production_dory_v3_suite_manifest();
        changed.setup_identity = Digest32::new([0x44; 32]);
        assert_eq!(
            changed.validate(),
            Err(DoryV3SuiteError::DigestMismatch("setup_identity"))
        );

        let mut changed = production_dory_v3_suite_manifest();
        changed.native_blake3_parameters_digest = Digest32::ZERO;
        assert_eq!(
            changed.validate(),
            Err(DoryV3SuiteError::ZeroDigest(
                "native_blake3_parameters_digest"
            ))
        );
    }

    #[test]
    fn every_manifest_field_is_validated() {
        let original = serde_json::to_value(production_dory_v3_suite_manifest()).unwrap();
        let keys = original
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            let mut changed = original.clone();
            let value = changed.as_object_mut().unwrap().get_mut(&key).unwrap();
            match value {
                Value::Number(number) => {
                    *value = json!(number.as_u64().unwrap() + 1);
                }
                Value::String(encoded) => {
                    *encoded = "11".repeat(32);
                }
                _ => panic!("unexpected suite field representation for {key}"),
            }
            let decoded: DoryV3ConsensusSuiteManifestV1 = serde_json::from_value(changed).unwrap();
            assert!(
                decoded.validate().is_err(),
                "suite field `{key}` was not validated"
            );
        }
    }

    #[test]
    fn canonical_encoding_is_little_endian_and_order_sensitive() {
        let manifest = production_dory_v3_suite_manifest();
        let encoded = manifest.canonical_bytes();
        assert_eq!(&encoded[0..2], &1_u16.to_le_bytes());
        assert_eq!(&encoded[2..4], &3_u16.to_le_bytes());
        assert_eq!(&encoded[4..8], &2_u32.to_le_bytes());
        assert_eq!(&encoded[8..12], &1_u32.to_le_bytes());

        let mut changed = manifest;
        changed.proof_version = 2;
        assert_ne!(changed.canonical_bytes(), encoded);
        assert_ne!(changed.digest(), manifest.digest());
    }

    #[test]
    fn serde_key_order_does_not_define_consensus_bytes() {
        let manifest = production_dory_v3_suite_manifest();
        let value = serde_json::to_value(manifest).unwrap();
        let Value::Object(object) = value else {
            panic!("manifest must serialize as an object");
        };
        let reversed = Value::Object(object.into_iter().rev().collect());
        let decoded: DoryV3ConsensusSuiteManifestV1 = serde_json::from_value(reversed).unwrap();
        assert_eq!(decoded.canonical_bytes(), manifest.canonical_bytes());
        assert_eq!(decoded.digest(), manifest.digest());
    }

    #[test]
    fn implemented_owner_constants_match_the_staged_suite() {
        use crate::{
            dory_bls12_381_aggregate::{
                BLS_DORY_AGGREGATE_PRODUCTION_READY, BLS_DORY_AGGREGATE_VERSION,
                MAX_BLS_DORY_AGGREGATE_CLAIMS,
            },
            dory_bls12_381_blake3::{
                BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS, BLS_DORY_BLAKE3_NATIVE_PROOF_VERSION,
                BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES, BLS_DORY_BLAKE3_PRODUCTION_READY,
                BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS, BLS_DORY_BLAKE3_PROJECTION_VERSION,
                BLS_DORY_BLAKE3_SHARED_DORY_NU, BLS_DORY_BLAKE3_SHARED_DORY_SIGMA,
                BLS_DORY_BLAKE3_SOURCE_COMMITMENTS, BLS_DORY_BLAKE3_TRACE_VARIABLES,
            },
            dory_bls12_381_candidate::{ALGEBRAIC_BINDING_DOMAIN, ALGEBRAIC_BINDING_VERSION},
            dory_bls12_381_layout::{
                BLS_DORY_FINAL_OUTPUT_BRIDGE_VERSION, BLS_DORY_FIXED_MODEL_IDENTITY_VERSION,
                BLS_DORY_SHARED_LAYOUT_PRODUCTION_READY, BLS_DORY_SHARED_LAYOUT_VERSION,
                BLS_DORY_SHARED_NATIVE_COMPOSITION_VERSION, BLS_DORY_SHARED_PRODUCTION_CLAIMS,
                BLS_DORY_SHARED_PRODUCTION_VARIABLES,
            },
            dory_bls12_381_logup::BLS_DORY_RANGE_LOGUP_VERSION,
            dory_bls12_381_matrix::BLS_DORY_MATRIX_VERSION,
            dory_bls12_381_output_bridge::BLS_DORY_OUTPUT_BRIDGE_VERSION,
            dory_bls12_381_prototype::{
                BLS_DORY_EXACT_NONZERO_CHALLENGE_SAMPLING, BLS_DORY_SETUP_VERSION,
                BLS_DORY_TRANSCRIPT_VERSION, BlsDoryFr, BlsDoryGt, MAX_BLS_DORY_SETUP_VARIABLES,
                bls_dory_setup_generator_count,
            },
            dory_bls12_381_transition::BLS_DORY_TRANSITION_VERSION,
            dory_bls12_381_wiring::BLS_DORY_WIRING_VERSION,
            forgematrix_v2::{
                CHALLENGE_DOMAIN, FORGEMATRIX_V2_ALGORITHM_VERSION, FORGEMATRIX_V2_PROOF_VERSION,
                MASK_DOMAIN, OUTPUT_DOMAIN, PRODUCTION_V2_BANKS, PRODUCTION_V2_BATCH,
                PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS, PRODUCTION_V2_LAYERS_PER_BANK,
                WORK_DOMAIN,
            },
            model_bank::{
                MAX_MODEL_BYTE, MODEL_BANK_FORMAT_VERSION, MODEL_BANK_HEADER_BYTES,
                MODEL_BANK_MAGIC,
            },
            pow::POW_TYPE_V3_CANDIDATE,
            wire::{
                FORGEMATRIX_V3_CANDIDATE_PROOF_TAG, MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES,
                MAX_PROOF_BYTES,
            },
        };
        use dory_pcs::primitives::{
            DorySerialize,
            arithmetic::{Field, Group},
        };

        assert_eq!(DORY_V3_POW_TYPE, POW_TYPE_V3_CANDIDATE);
        assert_eq!(DORY_V3_WIRE_TAG, FORGEMATRIX_V3_CANDIDATE_PROOF_TAG);
        assert_eq!(DORY_V3_ALGORITHM_VERSION, FORGEMATRIX_V2_ALGORITHM_VERSION);
        assert_eq!(DORY_V3_PROOF_VERSION, FORGEMATRIX_V2_PROOF_VERSION);
        assert_eq!(DORY_V3_MODEL_BANK_FORMAT_VERSION, MODEL_BANK_FORMAT_VERSION);
        assert_eq!(MODEL_BANK_MAGIC, *b"CMFDBNK2");
        assert_eq!(MODEL_BANK_HEADER_BYTES, 184);
        assert_eq!(MAX_MODEL_BYTE, 250);
        assert_eq!(DORY_V3_BATCH, PRODUCTION_V2_BATCH);
        assert_eq!(DORY_V3_DIMENSION, PRODUCTION_V2_DIMENSION);
        assert_eq!(DORY_V3_LAYERS, PRODUCTION_V2_LAYERS);
        assert_eq!(DORY_V3_BANKS, PRODUCTION_V2_BANKS);
        assert_eq!(DORY_V3_LAYERS_PER_BANK, PRODUCTION_V2_LAYERS_PER_BANK);
        assert_eq!(DORY_V3_SETUP_VERSION, BLS_DORY_SETUP_VERSION);
        assert_eq!(DORY_V3_TRANSCRIPT_VERSION, BLS_DORY_TRANSCRIPT_VERSION);
        const {
            assert!(BLS_DORY_EXACT_NONZERO_CHALLENGE_SAMPLING);
        }
        assert_eq!(bls_dory_setup_generator_count(33), 1 << 17);
        assert_eq!(BlsDoryFr::one().compressed_size(), 32);
        assert_eq!(BlsDoryGt::identity().compressed_size(), 576);
        assert_eq!(
            DORY_V3_PADDED_VARIABLES as usize,
            MAX_BLS_DORY_SETUP_VARIABLES
        );
        assert_eq!(
            DORY_V3_PADDED_VARIABLES as usize,
            BLS_DORY_SHARED_PRODUCTION_VARIABLES
        );
        assert_eq!(DORY_V3_AGGREGATE_VERSION, BLS_DORY_AGGREGATE_VERSION);
        assert_eq!(DORY_V3_MATRIX_VERSION, BLS_DORY_MATRIX_VERSION);
        assert_eq!(DORY_V3_TRANSITION_VERSION, BLS_DORY_TRANSITION_VERSION);
        assert_eq!(DORY_V3_RANGE_LOGUP_VERSION, BLS_DORY_RANGE_LOGUP_VERSION);
        assert_eq!(DORY_V3_WIRING_VERSION, BLS_DORY_WIRING_VERSION);
        assert_eq!(
            DORY_V3_NATIVE_COMPOSITION_VERSION,
            BLS_DORY_SHARED_NATIVE_COMPOSITION_VERSION
        );
        assert_eq!(
            DORY_V3_OUTPUT_BRIDGE_VERSION,
            BLS_DORY_OUTPUT_BRIDGE_VERSION
        );
        assert_eq!(
            DORY_V3_OUTPUT_BRIDGE_VERSION,
            BLS_DORY_FINAL_OUTPUT_BRIDGE_VERSION
        );
        assert_eq!(MAX_BLS_DORY_AGGREGATE_CLAIMS, 128);
        assert_eq!(BLS_DORY_SHARED_PRODUCTION_CLAIMS, 128);
        assert_eq!(
            BLS_DORY_BLAKE3_PROJECTION_VERSION,
            DORY_V3_BLAKE3_PROJECTION_VERSION
        );
        assert_eq!(
            BLS_DORY_BLAKE3_NATIVE_PROOF_VERSION,
            DORY_V3_BLAKE3_NATIVE_PROOF_VERSION
        );
        assert_eq!(BLS_DORY_BLAKE3_PRODUCTION_ACTIVATION_BYTES, 1 << 19);
        assert_eq!(BLS_DORY_BLAKE3_PRODUCTION_TRACE_ROWS, 1 << 20);
        assert_eq!(BLS_DORY_BLAKE3_TRACE_VARIABLES, 20);
        assert_eq!(BLS_DORY_BLAKE3_SHARED_DORY_NU, 16);
        assert_eq!(BLS_DORY_BLAKE3_SHARED_DORY_SIGMA, 17);
        assert_eq!(BLS_DORY_BLAKE3_SOURCE_COMMITMENTS, 4);
        assert_eq!(BLS_DORY_BLAKE3_ADJACENCY_OPENING_CLAIMS, 3);
        assert_eq!(DORY_V3_MAX_PROOF_BYTES as usize, MAX_PROOF_BYTES);
        assert_eq!(
            DORY_V3_MAX_STRUCTURED_PROOF_BYTES as usize,
            MAX_FORGEMATRIX_V3_STRUCTURED_PROOF_BYTES
        );

        assert_eq!(BLS_DORY_SHARED_LAYOUT_VERSION, 4);
        assert_eq!(DORY_V3_SHARED_LAYOUT_VERSION, 5);
        assert_eq!(BLS_DORY_FIXED_MODEL_IDENTITY_VERSION, 1);
        assert_eq!(DORY_V3_FIXED_MODEL_BINDING_VERSION, 2);
        assert_eq!(ALGEBRAIC_BINDING_VERSION, 1);
        assert_eq!(DORY_V3_ALGEBRAIC_BINDING_VERSION, 2);
        assert_ne!(ALGEBRAIC_BINDING_DOMAIN, DORY_V3_ALGEBRAIC_BINDING_DOMAIN);
        assert_ne!(CHALLENGE_DOMAIN, DORY_V3_CHALLENGE_DOMAIN);
        assert_ne!(MASK_DOMAIN, DORY_V3_MASK_DOMAIN);
        assert_ne!(OUTPUT_DOMAIN, DORY_V3_OUTPUT_DOMAIN);
        assert_ne!(WORK_DOMAIN, DORY_V3_WORK_DOMAIN);
        const {
            assert!(!BLS_DORY_AGGREGATE_PRODUCTION_READY);
            assert!(!BLS_DORY_SHARED_LAYOUT_PRODUCTION_READY);
            assert!(!BLS_DORY_BLAKE3_PRODUCTION_READY);
            assert!(!DORY_V3_SUITE_ACTIVATION_READY);
        }
        assert_eq!(DORY_V3_SUITE_ACTIVATION_BLOCKERS.len(), 2);
        assert!(
            DORY_V3_SUITE_ACTIVATION_BLOCKERS
                .iter()
                .any(|blocker| blocker.contains("model bank ceremony"))
        );
        assert!(
            DORY_V3_SUITE_ACTIVATION_BLOCKERS
                .iter()
                .any(|blocker| blocker.contains("n=33 proof"))
        );
    }

    #[test]
    fn candidate_payload_offsets_match_the_suite_descriptor() {
        use crate::dory_bls12_381_candidate::BlsDoryV3CandidatePayload;

        let payload = BlsDoryV3CandidatePayload {
            dory_proof: vec![0xaa, 0xbb],
            native_blake3_proof: vec![0xcc, 0xdd, 0xee],
        };
        let encoded = payload.encode().unwrap();
        assert_eq!(DORY_V3_CANDIDATE_PAYLOAD_HEADER_BYTES, 18);
        assert_eq!(&encoded[0..8], &DORY_V3_CANDIDATE_PAYLOAD_MAGIC);
        assert_eq!(
            u16::from_le_bytes(encoded[8..10].try_into().unwrap()),
            DORY_V3_CANDIDATE_PAYLOAD_VERSION
        );
        assert_eq!(u32::from_le_bytes(encoded[10..14].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(encoded[14..18].try_into().unwrap()), 3);
        assert_eq!(&encoded[18..], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        assert_eq!(
            BlsDoryV3CandidatePayload::decode(&encoded).unwrap(),
            payload
        );
    }

    #[cfg(feature = "whir-prototype")]
    #[test]
    fn embedded_preprocessing_pin_matches_the_suite() {
        use crate::dory_bls12_381_blake3::{
            BLS_DORY_BLAKE3_PREPROCESSING_RECORD_VERSION,
            BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD_DIGEST,
        };

        assert_eq!(
            DORY_V3_BLAKE3_PREPROCESSING_RECORD_VERSION,
            BLS_DORY_BLAKE3_PREPROCESSING_RECORD_VERSION
        );
        assert_eq!(
            DORY_V3_BLAKE3_PREPROCESSING_RECORD_DIGEST.into_bytes(),
            BLS_DORY_BLAKE3_PRODUCTION_PREPROCESSING_RECORD_DIGEST
        );
    }

    #[test]
    #[ignore = "release-only n=33 deterministic setup reproduction"]
    fn release_gate_rederives_the_pinned_production_setup_identity() {
        use crate::dory_bls12_381_prototype::deterministic_bls_dory_setup;

        let setup = deterministic_bls_dory_setup(DORY_V3_PADDED_VARIABLES as usize).unwrap();
        setup.validate().unwrap();
        assert_eq!(setup.identity(), DORY_V3_SETUP_IDENTITY.into_bytes());
    }
}
