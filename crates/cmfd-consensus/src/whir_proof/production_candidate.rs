//! Additive production-geometry WHIR candidate.
//!
//! This module defines and measures the exact n19/n31 verifier geometry without
//! widening the legacy V2 adapter. It is deliberately not a block-proof type:
//! the current n31 encoding has a dictionary-free floor above the complete
//! 256 KiB proof frame and therefore fails closed at the network budget boundary.

use blake3::Hasher as Blake3Hasher;
use thiserror::Error;

use super::{
    Challenger, EF, EXPLICIT_WHIR_FOLDING, EXPLICIT_WHIR_POW_BITS, EXPLICIT_WHIR_SECURITY_BITS,
    EXPLICIT_WHIR_STARTING_LOG_INV_RATE, F, build_whir_config_bounded,
    native_codec::{self, NativeProofCodecError, NativeProofCodecProfile, NativeProofGeometry},
    structured_whir_suite_parameter_digest,
};
use crate::{
    MAX_MODEL_PCS_WEIGHT_BANKS, ModelPcsIdentity, ModelPcsRole, PRODUCTION_V2_BANKS,
    PRODUCTION_V2_BATCH, PRODUCTION_V2_DIMENSION, PRODUCTION_V2_LAYERS,
    PRODUCTION_V2_LAYERS_PER_BANK,
};

pub const PRODUCTION_WHIR_CANDIDATE_VERSION: u32 = 1;
pub const PRODUCTION_WHIR_BASE_VARIABLES: usize = 19;
pub const PRODUCTION_WHIR_WEIGHT_VARIABLES: usize = 31;
pub const PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES: usize =
    match crate::wire::MAX_PROOF_BYTES.checked_sub(crate::wire::WIRE_HEADER_BYTES) {
        Some(bytes) => bytes,
        None => panic!("proof frame is smaller than its wire header"),
    };

pub(super) const PRODUCTION_WHIR_NATIVE_MAGIC: &[u8; 8] = b"CMFDPWB1";
pub(super) const PRODUCTION_WHIR_NATIVE_CODEC_VERSION: u32 = 1;
pub(super) const PRODUCTION_WHIR_NATIVE_PROTOCOL_VERSION: u32 = 1;

const PRODUCTION_MODEL_VERSION: u32 = 2;
const CANDIDATE_SUITE_DOMAIN: &str = "CMFD/FORGEMATRIX/WHIR-PRODUCTION-CANDIDATE/V1";
const NATIVE_CODEC_DESCRIPTION: &[u8] =
    b"fixed-width-le-config-derived-shape-first-reference-merkle-dictionary-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionWhirRoleV1 {
    BaseInput,
    WeightBank { index: u8 },
}

impl ProductionWhirRoleV1 {
    const fn num_variables(self) -> usize {
        match self {
            Self::BaseInput => PRODUCTION_WHIR_BASE_VARIABLES,
            Self::WeightBank { .. } => PRODUCTION_WHIR_WEIGHT_VARIABLES,
        }
    }

    #[cfg(feature = "gpu-proof-prover")]
    const fn as_model_role(self) -> ModelPcsRole {
        match self {
            Self::BaseInput => ModelPcsRole::BaseInput,
            Self::WeightBank { index } => ModelPcsRole::WeightBank {
                index: index as u32,
            },
        }
    }
}

pub struct ProductionWhirConfigV1 {
    role: ProductionWhirRoleV1,
    model_digest: [u8; 32],
    expected_commitment: [u8; 32],
    suite_digest: [u8; 32],
    inner: p3_whir::parameters::WhirConfig<EF, F, Challenger>,
}

impl std::fmt::Debug for ProductionWhirConfigV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionWhirConfigV1")
            .field("role", &self.role)
            .field("model_digest", &self.model_digest)
            .field("expected_commitment", &self.expected_commitment)
            .field("suite_digest", &self.suite_digest)
            .field("num_variables", &self.inner.num_variables)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionWhirWireShapeV1 {
    pub intermediate_rounds: usize,
    pub path_depths: Vec<usize>,
    pub body_bytes: usize,
    pub reference_count: usize,
    pub maximum_dictionary_nodes: usize,
    pub dictionary_free_floor_bytes: usize,
    pub maximum_native_bytes: usize,
    pub conservative_payload_fit: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProductionWhirCandidateError {
    #[error("model identity is not the exact ForgeMatrix-v2 production geometry")]
    InvalidModel,
    #[error("model role is not one of the exact production base/weight roles")]
    InvalidRole,
    #[error("production-candidate WHIR configuration derivation failed")]
    Configuration,
    #[error(
        "native proof dictionary-free floor {minimum} exceeds the {available}-byte proof-payload budget"
    )]
    NetworkBudgetExceeded { minimum: usize, available: usize },
    #[error("native proof exceeds the bounded candidate parser budget")]
    NativeProofTooLarge,
    #[error("native proof is not a canonical production-candidate encoding")]
    InvalidEncoding,
    #[error("prepared model role does not match the production-candidate configuration")]
    PreparedRoleMismatch,
    #[error("prepared model role context or artifact geometry is invalid")]
    PreparedContextMismatch,
}

impl ProductionWhirConfigV1 {
    pub fn for_model_role(
        model: &ModelPcsIdentity,
        role: ModelPcsRole,
    ) -> Result<Self, ProductionWhirCandidateError> {
        validate_production_model(model)?;
        let (role, expected_commitment) = production_role(model, role)?;
        let inner =
            build_whir_config_bounded(role.num_variables(), PRODUCTION_WHIR_WEIGHT_VARIABLES)
                .map_err(|_| ProductionWhirCandidateError::Configuration)?;
        Ok(Self {
            role,
            model_digest: model
                .digest()
                .map_err(|_| ProductionWhirCandidateError::InvalidModel)?,
            expected_commitment,
            suite_digest: production_whir_suite_parameter_digest_v1(),
            inner,
        })
    }

    pub const fn role(&self) -> ProductionWhirRoleV1 {
        self.role
    }

    pub const fn num_variables(&self) -> usize {
        self.role.num_variables()
    }

    pub const fn model_digest(&self) -> [u8; 32] {
        self.model_digest
    }

    pub const fn expected_commitment(&self) -> [u8; 32] {
        self.expected_commitment
    }

    pub const fn suite_digest(&self) -> [u8; 32] {
        self.suite_digest
    }

    pub fn wire_shape(&self) -> Result<ProductionWhirWireShapeV1, ProductionWhirCandidateError> {
        let geometry = native_codec::proof_geometry_with_profile(
            &self.inner,
            candidate_codec_profile(usize::MAX),
        )
        .map_err(|_| ProductionWhirCandidateError::Configuration)?;
        Ok(wire_shape(geometry))
    }

    /// Parse and canonicalize one candidate native proof without verifying its
    /// polynomial-opening statement. The n31 role fails before proof decoding
    /// or proof-sized allocation because even its dictionary-free floor exceeds
    /// the proof-payload budget.
    pub fn validate_native_proof_encoding(
        &self,
        encoded: &[u8],
    ) -> Result<(), ProductionWhirCandidateError> {
        let shape = self.wire_shape()?;
        if shape.dictionary_free_floor_bytes > PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES {
            return Err(ProductionWhirCandidateError::NetworkBudgetExceeded {
                minimum: shape.dictionary_free_floor_bytes,
                available: PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES,
            });
        }
        if encoded.len() > PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES {
            return Err(ProductionWhirCandidateError::NativeProofTooLarge);
        }
        let profile = candidate_codec_profile(PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES);
        let proof = native_codec::decode_native_proof_with_profile(encoded, &self.inner, profile)
            .map_err(map_codec_decode_error)?;
        let canonical =
            native_codec::encode_native_proof_with_profile(&proof, &self.inner, profile)
                .map_err(map_codec_encode_error)?;
        if canonical != encoded {
            return Err(ProductionWhirCandidateError::InvalidEncoding);
        }
        Ok(())
    }
}

pub fn production_whir_suite_parameter_digest_v1() -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_derive_key(CANDIDATE_SUITE_DOMAIN);
    update_descriptor(
        &mut hasher,
        b"source-artifact-suite",
        &structured_whir_suite_parameter_digest(),
    );
    update_u64(
        &mut hasher,
        b"candidate-version",
        PRODUCTION_WHIR_CANDIDATE_VERSION as u64,
    );
    update_u64(
        &mut hasher,
        b"production-model-version",
        PRODUCTION_MODEL_VERSION as u64,
    );
    update_u64(&mut hasher, b"production-batch", PRODUCTION_V2_BATCH as u64);
    update_u64(
        &mut hasher,
        b"production-dimension",
        PRODUCTION_V2_DIMENSION as u64,
    );
    update_u64(
        &mut hasher,
        b"production-layers-per-bank",
        PRODUCTION_V2_LAYERS_PER_BANK as u64,
    );
    update_u64(
        &mut hasher,
        b"production-total-layers",
        PRODUCTION_V2_LAYERS as u64,
    );
    update_u64(
        &mut hasher,
        b"base-variables",
        PRODUCTION_WHIR_BASE_VARIABLES as u64,
    );
    update_u64(
        &mut hasher,
        b"weight-variables",
        PRODUCTION_WHIR_WEIGHT_VARIABLES as u64,
    );
    update_u64(&mut hasher, b"weight-banks", PRODUCTION_V2_BANKS as u64);
    update_descriptor(&mut hasher, b"variable-order", b"suffix");
    update_descriptor(&mut hasher, b"security-assumption", b"unique-decoding");
    update_u64(
        &mut hasher,
        b"security-bits",
        EXPLICIT_WHIR_SECURITY_BITS as u64,
    );
    update_u64(&mut hasher, b"folding-factor", EXPLICIT_WHIR_FOLDING as u64);
    update_u64(
        &mut hasher,
        b"starting-log-inverse-rate",
        EXPLICIT_WHIR_STARTING_LOG_INV_RATE as u64,
    );
    update_u64(&mut hasher, b"pow-bits", EXPLICIT_WHIR_POW_BITS as u64);
    update_descriptor(&mut hasher, b"base-field", b"goldilocks");
    update_descriptor(&mut hasher, b"extension-field", b"cubic:u^3=u+1");
    update_descriptor(
        &mut hasher,
        b"field-element-encoding",
        b"canonical-u64-coefficients-extension-basis-1-u-u2",
    );
    update_descriptor(&mut hasher, b"native-codec", NATIVE_CODEC_DESCRIPTION);
    update_descriptor(
        &mut hasher,
        b"native-codec-magic",
        PRODUCTION_WHIR_NATIVE_MAGIC,
    );
    update_u64(
        &mut hasher,
        b"native-codec-version",
        PRODUCTION_WHIR_NATIVE_CODEC_VERSION as u64,
    );
    update_u64(
        &mut hasher,
        b"native-protocol-version",
        PRODUCTION_WHIR_NATIVE_PROTOCOL_VERSION as u64,
    );
    update_u64(
        &mut hasher,
        b"native-codec-flags",
        native_codec::NATIVE_PROOF_CODEC_FLAGS as u64,
    );
    update_u64(
        &mut hasher,
        b"native-header-bytes",
        native_codec::NATIVE_PROOF_CODEC_HEADER_BYTES as u64,
    );
    update_u64(
        &mut hasher,
        b"dictionary-reference-bytes",
        native_codec::NATIVE_PROOF_CODEC_REFERENCE_BYTES as u64,
    );
    update_u64(
        &mut hasher,
        b"maximum-dictionary-nodes",
        native_codec::NATIVE_PROOF_CODEC_MAX_DICTIONARY_NODES as u64,
    );
    update_u64(
        &mut hasher,
        b"complete-frame-bytes",
        crate::wire::MAX_PROOF_BYTES as u64,
    );
    update_u64(
        &mut hasher,
        b"wire-header-bytes",
        crate::wire::WIRE_HEADER_BYTES as u64,
    );
    update_u64(
        &mut hasher,
        b"absolute-native-bytes",
        PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES as u64,
    );
    *hasher.finalize().as_bytes()
}

pub(super) const fn candidate_codec_profile(max_encoded_bytes: usize) -> NativeProofCodecProfile {
    NativeProofCodecProfile::new(
        PRODUCTION_WHIR_NATIVE_MAGIC,
        PRODUCTION_WHIR_NATIVE_CODEC_VERSION,
        PRODUCTION_WHIR_NATIVE_PROTOCOL_VERSION,
        PRODUCTION_WHIR_WEIGHT_VARIABLES,
        max_encoded_bytes,
    )
}

fn wire_shape(geometry: NativeProofGeometry) -> ProductionWhirWireShapeV1 {
    ProductionWhirWireShapeV1 {
        intermediate_rounds: geometry.intermediate_rounds,
        path_depths: geometry.path_depths,
        body_bytes: geometry.body_bytes,
        reference_count: geometry.reference_count,
        maximum_dictionary_nodes: geometry.maximum_dictionary_nodes,
        dictionary_free_floor_bytes: geometry.structural_floor_bytes,
        maximum_native_bytes: geometry.conservative_upper_bound_bytes,
        conservative_payload_fit: geometry.conservative_upper_bound_bytes
            <= PRODUCTION_WHIR_ABSOLUTE_NATIVE_BYTES,
    }
}

fn validate_production_model(model: &ModelPcsIdentity) -> Result<(), ProductionWhirCandidateError> {
    model
        .validate()
        .map_err(|_| ProductionWhirCandidateError::InvalidModel)?;
    if model.model_version != PRODUCTION_MODEL_VERSION
        || model.batch != PRODUCTION_V2_BATCH
        || model.dimension != PRODUCTION_V2_DIMENSION
        || model.layers_per_bank != PRODUCTION_V2_LAYERS_PER_BANK
        || model.weight_bank_commitments.len() != PRODUCTION_V2_BANKS as usize
        || model.weight_bank_commitments.len() != MAX_MODEL_PCS_WEIGHT_BANKS
        || model.layers_per_bank.checked_mul(PRODUCTION_V2_BANKS) != Some(PRODUCTION_V2_LAYERS)
        || model.pcs_suite_parameter_digest != structured_whir_suite_parameter_digest()
    {
        return Err(ProductionWhirCandidateError::InvalidModel);
    }
    Ok(())
}

fn production_role(
    model: &ModelPcsIdentity,
    role: ModelPcsRole,
) -> Result<(ProductionWhirRoleV1, [u8; 32]), ProductionWhirCandidateError> {
    match role {
        ModelPcsRole::BaseInput => {
            Ok((ProductionWhirRoleV1::BaseInput, model.base_input_commitment))
        }
        ModelPcsRole::WeightBank { index } => {
            let index_u8 =
                u8::try_from(index).map_err(|_| ProductionWhirCandidateError::InvalidRole)?;
            let commitment = model
                .weight_bank_commitments
                .get(index as usize)
                .copied()
                .ok_or(ProductionWhirCandidateError::InvalidRole)?;
            Ok((
                ProductionWhirRoleV1::WeightBank { index: index_u8 },
                commitment,
            ))
        }
    }
}

fn map_codec_decode_error(error: NativeProofCodecError) -> ProductionWhirCandidateError {
    match error {
        NativeProofCodecError::TooLarge => ProductionWhirCandidateError::NativeProofTooLarge,
        NativeProofCodecError::Configuration => ProductionWhirCandidateError::Configuration,
        _ => ProductionWhirCandidateError::InvalidEncoding,
    }
}

fn map_codec_encode_error(error: NativeProofCodecError) -> ProductionWhirCandidateError {
    match error {
        NativeProofCodecError::TooLarge => ProductionWhirCandidateError::NativeProofTooLarge,
        NativeProofCodecError::Configuration => ProductionWhirCandidateError::Configuration,
        _ => ProductionWhirCandidateError::InvalidEncoding,
    }
}

fn update_descriptor(hasher: &mut Blake3Hasher, label: &[u8], value: &[u8]) {
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn update_u64(hasher: &mut Blake3Hasher, label: &[u8], value: u64) {
    update_descriptor(hasher, label, &value.to_le_bytes());
}

#[cfg(feature = "gpu-proof-prover")]
pub struct BoundProductionWhirRoleV1 {
    model_digest: [u8; 32],
    production_suite_digest: [u8; 32],
    role: ProductionWhirRoleV1,
    prepared: crate::PreparedModelWhirRoleV2,
}

#[cfg(feature = "gpu-proof-prover")]
impl std::fmt::Debug for BoundProductionWhirRoleV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundProductionWhirRoleV1")
            .field("model_digest", &self.model_digest)
            .field("production_suite_digest", &self.production_suite_digest)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "gpu-proof-prover")]
impl BoundProductionWhirRoleV1 {
    pub const fn model_digest(&self) -> [u8; 32] {
        self.model_digest
    }

    pub const fn production_suite_digest(&self) -> [u8; 32] {
        self.production_suite_digest
    }

    pub const fn role(&self) -> ProductionWhirRoleV1 {
        self.role
    }

    pub const fn prepared(&self) -> &crate::PreparedModelWhirRoleV2 {
        &self.prepared
    }
}

/// A failed candidate bind together with the original prepared role.
///
/// Preparing an n19/n31 role can be expensive, so a rejected bind must not
/// silently destroy the caller's capability.
#[cfg(feature = "gpu-proof-prover")]
#[derive(Debug)]
pub struct ProductionWhirBindFailure {
    error: ProductionWhirCandidateError,
    prepared: Box<crate::PreparedModelWhirRoleV2>,
}

#[cfg(feature = "gpu-proof-prover")]
impl ProductionWhirBindFailure {
    pub const fn error(&self) -> &ProductionWhirCandidateError {
        &self.error
    }

    pub fn prepared(&self) -> &crate::PreparedModelWhirRoleV2 {
        self.prepared.as_ref()
    }

    pub fn into_prepared(self) -> crate::PreparedModelWhirRoleV2 {
        *self.prepared
    }

    pub fn into_parts(self) -> (ProductionWhirCandidateError, crate::PreparedModelWhirRoleV2) {
        (self.error, *self.prepared)
    }
}

#[cfg(feature = "gpu-proof-prover")]
impl std::fmt::Display for ProductionWhirBindFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

#[cfg(feature = "gpu-proof-prover")]
impl std::error::Error for ProductionWhirBindFailure {}

/// Join the authenticated source/oracle capability to the candidate type
/// boundary without changing the existing WHIR transcript.
///
/// This wrapper is prover-local type state only. A future candidate proof must
/// cryptographically bind the production suite digest, model digest, exact
/// role/index, expected commitment, and opening statement into its public
/// statement and Fiat-Shamir transcript before this path can be consensus.
#[cfg(feature = "gpu-proof-prover")]
pub fn bind_prepared_production_whir_role_v1(
    config: &ProductionWhirConfigV1,
    model: &ModelPcsIdentity,
    prepared: crate::PreparedModelWhirRoleV2,
) -> Result<BoundProductionWhirRoleV1, ProductionWhirBindFailure> {
    if let Err(error) = validate_prepared_production_whir_role_v1(config, model, &prepared) {
        return Err(ProductionWhirBindFailure {
            error,
            prepared: Box::new(prepared),
        });
    }

    Ok(BoundProductionWhirRoleV1 {
        model_digest: config.model_digest,
        production_suite_digest: config.suite_digest,
        role: config.role,
        prepared,
    })
}

#[cfg(feature = "gpu-proof-prover")]
fn validate_prepared_production_whir_role_v1(
    config: &ProductionWhirConfigV1,
    model: &ModelPcsIdentity,
    prepared: &crate::PreparedModelWhirRoleV2,
) -> Result<(), ProductionWhirCandidateError> {
    let prover_identity = prepared.prover_identity();
    let source = prover_identity.source_artifact_identity();
    let oracle = prover_identity.oracle_identity();
    let binding = PreparedProductionWhirBindingV1 {
        role: prepared.role(),
        expected_commitment: prepared.expected_commitment(),
        source_num_variables: source.source.num_variables,
        source_element_count: source.element_count,
        context_digest: prepared.context_digest(),
        oracle_context_digest: oracle.context_digest(),
        oracle_source_matches: oracle.codeword_identity().source == source.source,
    };
    validate_prepared_production_whir_binding_v1(config, model, &binding)
}

#[cfg(feature = "gpu-proof-prover")]
struct PreparedProductionWhirBindingV1 {
    role: ModelPcsRole,
    expected_commitment: [u8; 32],
    source_num_variables: u32,
    source_element_count: u64,
    context_digest: [u8; 32],
    oracle_context_digest: [u8; 32],
    oracle_source_matches: bool,
}

#[cfg(feature = "gpu-proof-prover")]
fn validate_prepared_production_whir_binding_v1(
    config: &ProductionWhirConfigV1,
    model: &ModelPcsIdentity,
    binding: &PreparedProductionWhirBindingV1,
) -> Result<(), ProductionWhirCandidateError> {
    let derived = ProductionWhirConfigV1::for_model_role(model, binding.role)?;
    if derived.role != config.role
        || derived.model_digest != config.model_digest
        || derived.expected_commitment != config.expected_commitment
        || derived.suite_digest != config.suite_digest
        || binding.role != config.role.as_model_role()
        || binding.expected_commitment != config.expected_commitment
    {
        return Err(ProductionWhirCandidateError::PreparedRoleMismatch);
    }

    let expected_elements = 1_u64
        .checked_shl(config.num_variables() as u32)
        .ok_or(ProductionWhirCandidateError::PreparedContextMismatch)?;
    let expected_context = crate::model_whir_role_context_digest(model, binding.role)
        .map_err(|_| ProductionWhirCandidateError::PreparedContextMismatch)?;
    if binding.source_num_variables as usize != config.num_variables()
        || binding.source_element_count != expected_elements
        || binding.context_digest != expected_context
        || binding.oracle_context_digest != expected_context
        || !binding.oracle_source_matches
    {
        return Err(ProductionWhirCandidateError::PreparedContextMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn production_model() -> ModelPcsIdentity {
        ModelPcsIdentity {
            model_version: PRODUCTION_MODEL_VERSION,
            batch: PRODUCTION_V2_BATCH,
            dimension: PRODUCTION_V2_DIMENSION,
            layers_per_bank: PRODUCTION_V2_LAYERS_PER_BANK,
            model_byte_root: [0x31; 32],
            pcs_suite_parameter_digest: structured_whir_suite_parameter_digest(),
            base_input_commitment: [0x41; 32],
            weight_bank_commitments: vec![[0x51; 32], [0x52; 32], [0x53; 32]],
        }
    }

    #[test]
    fn exact_production_roles_have_pinned_n19_and_n31_geometry() {
        let model = production_model();
        let base = ProductionWhirConfigV1::for_model_role(&model, ModelPcsRole::BaseInput).unwrap();
        let base_shape = base.wire_shape().unwrap();
        assert_eq!(base.role(), ProductionWhirRoleV1::BaseInput);
        assert_eq!(base.num_variables(), 19);
        assert_eq!(base_shape.intermediate_rounds, 6);
        assert_eq!(base_shape.path_depths, (12..=18).rev().collect::<Vec<_>>());
        assert_eq!(base_shape.body_bytes, 96_240);
        assert_eq!(base_shape.reference_count, 18_509);
        assert_eq!(base_shape.maximum_dictionary_nodes, 11_911);
        assert_eq!(base_shape.dictionary_free_floor_bytes, 133_298);
        assert_eq!(base_shape.maximum_native_bytes, 514_450);
        assert!(!base_shape.conservative_payload_fit);

        for index in 0..PRODUCTION_V2_BANKS {
            let config =
                ProductionWhirConfigV1::for_model_role(&model, ModelPcsRole::WeightBank { index })
                    .unwrap();
            let shape = config.wire_shape().unwrap();
            assert_eq!(
                config.role(),
                ProductionWhirRoleV1::WeightBank { index: index as u8 }
            );
            assert_eq!(config.num_variables(), 31);
            assert_eq!(shape.intermediate_rounds, 12);
            assert_eq!(shape.path_depths, (18..=30).rev().collect::<Vec<_>>());
            assert_eq!(shape.body_bytes, 171_312);
            assert_eq!(shape.reference_count, 48_644);
            assert_eq!(shape.maximum_dictionary_nodes, 38_152);
            assert_eq!(shape.dictionary_free_floor_bytes, 268_640);
            assert_eq!(shape.maximum_native_bytes, 1_489_504);
            assert!(!shape.conservative_payload_fit);
            assert_eq!(
                config.validate_native_proof_encoding(&[]),
                Err(ProductionWhirCandidateError::NetworkBudgetExceeded {
                    minimum: 268_640,
                    available: 262_128,
                })
            );
        }
    }

    #[test]
    fn only_the_exact_source_suite_model_shape_and_roles_are_admitted() {
        let model = production_model();
        assert!(
            ProductionWhirConfigV1::for_model_role(&model, ModelPcsRole::WeightBank { index: 3 })
                .is_err()
        );

        for mutate in [
            |identity: &mut ModelPcsIdentity| identity.model_version = 3,
            |identity: &mut ModelPcsIdentity| identity.batch /= 2,
            |identity: &mut ModelPcsIdentity| identity.dimension /= 2,
            |identity: &mut ModelPcsIdentity| identity.layers_per_bank /= 2,
            |identity: &mut ModelPcsIdentity| identity.pcs_suite_parameter_digest[0] ^= 1,
            |identity: &mut ModelPcsIdentity| {
                identity.weight_bank_commitments.pop();
            },
        ] {
            let mut malformed = model.clone();
            mutate(&mut malformed);
            assert_eq!(
                ProductionWhirConfigV1::for_model_role(&malformed, ModelPcsRole::BaseInput)
                    .unwrap_err(),
                ProductionWhirCandidateError::InvalidModel
            );
        }
    }

    #[test]
    fn candidate_suite_is_separate_from_the_v2_source_artifact_suite() {
        let candidate = production_whir_suite_parameter_digest_v1();
        assert_ne!(candidate, structured_whir_suite_parameter_digest());
        assert_eq!(
            hex::encode(candidate),
            "ac65cb999e987299d87ea6e6c1b2934784b2130d915eb4f1e284bb034b7ab696"
        );
    }

    #[cfg(feature = "gpu-proof-prover")]
    #[test]
    fn prepared_role_binding_rejects_role_and_context_substitution() {
        let model = production_model();
        let config =
            ProductionWhirConfigV1::for_model_role(&model, ModelPcsRole::BaseInput).unwrap();
        let context_digest =
            crate::model_whir_role_context_digest(&model, ModelPcsRole::BaseInput).unwrap();
        let mut binding = PreparedProductionWhirBindingV1 {
            role: ModelPcsRole::BaseInput,
            expected_commitment: model.base_input_commitment,
            source_num_variables: PRODUCTION_WHIR_BASE_VARIABLES as u32,
            source_element_count: 1_u64 << PRODUCTION_WHIR_BASE_VARIABLES,
            context_digest,
            oracle_context_digest: context_digest,
            oracle_source_matches: true,
        };
        assert!(validate_prepared_production_whir_binding_v1(&config, &model, &binding).is_ok());

        binding.role = ModelPcsRole::WeightBank { index: 0 };
        binding.expected_commitment = model.weight_bank_commitments[0];
        assert_eq!(
            validate_prepared_production_whir_binding_v1(&config, &model, &binding),
            Err(ProductionWhirCandidateError::PreparedRoleMismatch)
        );

        binding.role = ModelPcsRole::BaseInput;
        binding.expected_commitment = model.base_input_commitment;
        binding.context_digest[0] ^= 1;
        assert_eq!(
            validate_prepared_production_whir_binding_v1(&config, &model, &binding),
            Err(ProductionWhirCandidateError::PreparedContextMismatch)
        );
    }
}
